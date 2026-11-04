"""airlock worker: runs PyGhidra (and so the JVM) in its own process.

Started by the server as `python -m airlock.worker`. Reads requests on stdin,
writes responses on a private copy of stdout. The real stdout (fd 1) is
pointed at stderr before anything else runs, so output from Ghidra, the JVM
or stray prints can never corrupt the protocol stream. stderr goes to the
worker log file opened by the server.

The worker exits when stdin closes, which happens when the server exits or
crashes; on Windows the Job Object additionally guarantees it (win.jobobject).

Requests run on two lanes so a long job never blocks the cheap ones (DESIGN.md section 8):
- CONCURRENT_OPS (hello, status, cancel_*, decompile, decompile_batch, bulk_decompile,
  external_paths) each get their own thread and answer while anything else runs;
- every other op runs one at a time on the main thread, in arrival order, as before
  (the JVM must be started from the main thread).
Responses carry their request id and may arrive in any order. All protocol writes go
through one lock (`_write`), so lines never interleave. Program access is arbitrated by the
per-program reader/writer lock (ghidra_ops.session), not by this loop.
"""

from __future__ import annotations

import os
import sys
import queue
import threading
import time
import traceback
from typing import Any, BinaryIO, Callable

from airlock import __version__
from airlock.worker.protocol import WorkerError, decode, encode

Handler = Callable[[dict[str, Any]], dict[str, Any]]
OPS: dict[str, Handler] = {}
CONCURRENT_OPS = frozenset({
    "hello", "status", "cancel_analysis", "cancel_bulk", "decompile", "decompile_batch",
    "bulk_decompile", "external_paths",
})


def op(name: str) -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        OPS[name] = fn
        return fn
    return deco


# ── State ──────────────────────────────────────────────────────────────────

class _State:
    launcher: Any = None
    ghidra: dict[str, Any] | None = None
    out: BinaryIO | None = None
    out_lock = threading.Lock()
    processors: int | None = None   # detected once, at worker start (pool.detect_processors)


STATE = _State()


def _write(obj: dict[str, Any]) -> None:
    """Write one protocol line. Safe to call from any thread."""
    if STATE.out is None:  # not running as a worker (unit tests)
        return
    data = encode(obj)
    with STATE.out_lock:
        STATE.out.write(data)


def emit(event: str, **fields: Any) -> None:
    """Send an unsolicited event line: {"event": <event>, ...fields}."""
    _write({"event": event, **fields})


# ── Ops ────────────────────────────────────────────────────────────────────

@op("hello")
def _hello(_args: dict[str, Any]) -> dict[str, Any]:
    return {
        "airlock": __version__,
        "pid": os.getpid(),
        "python": sys.version.split()[0],
        "ghidra_started": STATE.ghidra is not None,
        "processors": STATE.processors,
    }


@op("start_ghidra")
def _start_ghidra(args: dict[str, Any]) -> dict[str, Any]:
    if STATE.ghidra is not None:
        return {**STATE.ghidra, "already_started": True}

    install_dir = args.get("install_dir")
    if not install_dir:
        raise WorkerError("bad_args", "install_dir is required")
    try:
        import pyghidra
        from pyghidra.launcher import HeadlessPyGhidraLauncher
    except ImportError as e:
        raise WorkerError(
            "pyghidra_missing",
            f"pyghidra is not installed in {sys.executable} ({e}). Run `airlock doctor --fix`.",
        ) from e

    t0 = time.monotonic()
    launcher = HeadlessPyGhidraLauncher(verbose=False, install_dir=install_dir)
    if args.get("jdk_dir"):
        # Explicit JDK: skips PyGhidra's PATH/JAVA_HOME + LaunchSupport discovery.
        launcher.java_home = args["jdk_dir"]
    if args.get("jvm_max_memory"):
        launcher.add_vmargs(f"-Xmx{args['jvm_max_memory']}")
    try:
        launcher.start()
    except SystemExit as e:  # PyGhidra reports fatal launch errors via sys.exit
        raise WorkerError("ghidra_start_failed", f"PyGhidra exited during startup ({e})") from e

    from ghidra.framework import Application  # type: ignore  # available after start
    from java.lang import System  # type: ignore

    STATE.launcher = launcher
    STATE.ghidra = {
        "ghidra_version": str(Application.getApplicationVersion()),
        "java_version": str(System.getProperty("java.version")),
        "java_home": str(launcher.java_home),
        "pyghidra_version": getattr(pyghidra, "__version__", None),
        "startup_s": round(time.monotonic() - t0, 2),
    }
    return dict(STATE.ghidra)


@op("shutdown")
def _shutdown(_args: dict[str, Any]) -> dict[str, Any]:
    raise SystemExit(0)


# ── Loop ───────────────────────────────────────────────────────────────────

def _isolate_stdout() -> BinaryIO:
    """Return a private protocol stream and point fd 1 at stderr."""
    proto_fd = os.dup(1)
    os.dup2(2, 1)
    if sys.platform == "win32":
        # Make sure native code that asks for STD_OUTPUT_HANDLE (the JVM) gets stderr too.
        import ctypes
        import msvcrt

        STD_OUTPUT_HANDLE = -11
        ctypes.windll.kernel32.SetStdHandle(STD_OUTPUT_HANDLE, msvcrt.get_osfhandle(2))
        msvcrt.setmode(proto_fd, os.O_BINARY)
        msvcrt.setmode(0, os.O_BINARY)
    sys.stdout = sys.stderr
    return os.fdopen(proto_fd, "wb", buffering=0)


def _isolate_stdin() -> BinaryIO:
    """Return the request stream and point fd 0 at NUL.

    The reader thread sits in a blocking read on the pipe for the life of the process. On
    Windows a pending synchronous read serialises other operations on the same pipe object,
    and the JVM queries the standard handles while it starts: with the pipe still behind fd 0,
    start_ghidra hangs (measured). The JVM and native code get NUL instead."""
    req_fd = os.dup(0)
    nul = os.open(os.devnull, os.O_RDONLY)
    os.dup2(nul, 0)
    os.close(nul)
    if sys.platform == "win32":
        import ctypes
        import msvcrt

        STD_INPUT_HANDLE = -10
        ctypes.windll.kernel32.SetStdHandle(STD_INPUT_HANDLE, msvcrt.get_osfhandle(0))
        msvcrt.setmode(req_fd, os.O_BINARY)
    return os.fdopen(req_fd, "rb")


def _handle(msg: dict[str, Any]) -> dict[str, Any]:
    rid = msg.get("id")
    name = msg.get("op")
    fn = OPS.get(name) if isinstance(name, str) else None
    if fn is None:
        return {"id": rid, "ok": False, "error": {"code": "unknown_op", "message": str(name)}}
    try:
        return {"id": rid, "ok": True, "data": fn(msg.get("args") or {})}
    except WorkerError as e:
        return {"id": rid, "ok": False, "error": {"code": e.code, "message": e.message}}
    except SystemExit:
        raise
    except Exception as e:  # report, keep serving
        traceback.print_exc(file=sys.stderr)
        return {"id": rid, "ok": False,
                "error": {"code": "internal", "message": f"{type(e).__name__}: {e}"}}


def _serve_one(msg: dict[str, Any]) -> None:
    try:
        reply = _handle(msg)
    except SystemExit:
        reply = {"id": msg.get("id"), "ok": True, "data": {"bye": True}}
    _write(reply)


def _serial_lane(jobs: "queue.Queue[dict[str, Any] | None]") -> None:
    while True:
        msg = jobs.get()
        if msg is None:
            return
        _serve_one(msg)


def serve(lines: Any) -> None:
    """Dispatch requests from `lines` (bytes lines) until it ends or a shutdown request.

    A reader thread classifies and dispatches; the serial lane runs on the CALLING thread,
    which for the worker is the main thread: PyGhidra starts the JVM from `start_ghidra`,
    and that must keep happening on the main thread (it hangs elsewhere)."""
    jobs: "queue.Queue[dict[str, Any] | None]" = queue.Queue()

    def reader() -> None:
        for line in lines:  # ends when the server closes the pipe or dies
            if not line.strip():
                continue
            try:
                msg = decode(line)
            except ValueError as e:
                _write({"id": None, "ok": False,
                        "error": {"code": "bad_request", "message": str(e)}})
                continue
            name = msg.get("op")
            if name == "shutdown":
                _write({"id": msg.get("id"), "ok": True, "data": {"bye": True}})
                break
            if name in CONCURRENT_OPS:
                threading.Thread(target=_serve_one, args=(msg,), name=f"airlock-op-{name}",
                                 daemon=True).start()
            else:
                jobs.put(msg)
        jobs.put(None)

    threading.Thread(target=reader, name="airlock-reader", daemon=True).start()
    _serial_lane(jobs)


def main() -> int:
    out = _isolate_stdout()
    STATE.out = out
    requests = _isolate_stdin()
    from airlock.worker import pool
    STATE.processors = pool.detect_processors()
    import airlock.worker.ghidra_ops  # noqa: F401  registers the Ghidra ops (no JVM needed)
    from airlock.worker.ghidra_ops import session
    session.POOL.processors = STATE.processors
    print(f"[worker] airlock {__version__} pid {os.getpid()} python {sys.version.split()[0]} "
          f"processors {STATE.processors}", file=sys.stderr, flush=True)
    serve(requests)
    return 0
