"""airlock worker: runs PyGhidra (and so the JVM) in its own process.

Started by the server as `python -m airlock.worker`. Reads requests on stdin,
writes responses on a private copy of stdout. The real stdout (fd 1) is
pointed at stderr before anything else runs, so output from Ghidra, the JVM
or stray prints can never corrupt the protocol stream. stderr goes to the
worker log file opened by the server.

The worker exits when stdin closes, which happens when the server exits or
crashes; on Windows the Job Object additionally guarantees it (win.jobobject).
"""

from __future__ import annotations

import os
import sys
import time
import traceback
from typing import Any, BinaryIO, Callable

from airlock import __version__
from airlock.worker.protocol import WorkerError, decode, encode

Handler = Callable[[dict[str, Any]], dict[str, Any]]
OPS: dict[str, Handler] = {}


def op(name: str) -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        OPS[name] = fn
        return fn
    return deco


# ── State ──────────────────────────────────────────────────────────────────

class _State:
    launcher: Any = None
    ghidra: dict[str, Any] | None = None


STATE = _State()


# ── Ops ────────────────────────────────────────────────────────────────────

@op("hello")
def _hello(_args: dict[str, Any]) -> dict[str, Any]:
    return {
        "airlock": __version__,
        "pid": os.getpid(),
        "python": sys.version.split()[0],
        "ghidra_started": STATE.ghidra is not None,
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


def main() -> int:
    out = _isolate_stdout()
    stdin = sys.stdin.buffer
    print(f"[worker] airlock {__version__} pid {os.getpid()} python {sys.version.split()[0]}",
          file=sys.stderr, flush=True)
    for line in stdin:  # ends when the server closes the pipe or dies
        if not line.strip():
            continue
        try:
            msg = decode(line)
        except ValueError as e:
            out.write(encode({"id": None, "ok": False,
                              "error": {"code": "bad_request", "message": str(e)}}))
            continue
        try:
            reply = _handle(msg)
        except SystemExit:
            out.write(encode({"id": msg.get("id"), "ok": True, "data": {"bye": True}}))
            break
        out.write(encode(reply))
    return 0
