"""Server-side handle on the worker process."""

from __future__ import annotations

import logging
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

from airlock import logs
from airlock.config import Config
from airlock.win import jobobject
from airlock.worker.protocol import WorkerError, decode, encode


class WorkerClient:
    """Spawns the worker lazily and sends it one request at a time per caller.

    Requests are matched to responses by id, so several threads may call
    request() concurrently; the worker itself processes them in order.
    """

    def __init__(self, config: Config, python: str | None = None):
        self.config = config
        self.python = python or sys.executable
        self.proc: subprocess.Popen[bytes] | None = None
        self.in_job = False
        self._stopping = False      # stop() asked the worker to end: requests lost to it are no crash
        self.ghidra: dict[str, Any] | None = None
        self._next_id = 0
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._pending: dict[int, tuple[threading.Event, list[dict[str, Any]]]] = {}
        self._reader: threading.Thread | None = None
        self._log_file = None
        self._log_pump: threading.Thread | None = None
        # Latest progress event per program ("" when the event names none).
        self._progress: dict[str, dict[str, Any]] = {}
        self._listeners: list[Callable[[dict[str, Any]], None]] = []
        self._event_seq = 0

    # ── events ─────────────────────────────────────────────────────────────

    def progress(self, program: str | None = None) -> dict[str, Any] | None:
        """Latest progress event for a program (None if none received).

        With no argument: the latest event of any program. Fields: event,
        job, program, state (running|done|error|cancelled), pct (int|None),
        message, elapsed_s. State "done"/"error" is terminal.
        """
        if program is None:
            if not self._progress:
                return None
            return max(self._progress.values(), key=lambda e: e.get("_seq", 0))
        return self._progress.get(program)

    def all_progress(self) -> dict[str, dict[str, Any]]:
        return dict(self._progress)

    def on_event(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Call callback(event_dict) for every event, on the reader thread."""
        self._listeners.append(callback)

    def _dispatch_event(self, msg: dict[str, Any]) -> None:
        if msg.get("event") == "progress":
            self._event_seq += 1
            self._progress[str(msg.get("program") or "")] = {**msg, "_seq": self._event_seq}
        for cb in list(self._listeners):
            try:
                cb(msg)
            except Exception:  # a bad listener must not kill the reader
                pass

    # ── lifecycle ──────────────────────────────────────────────────────────

    @property
    def log_path(self) -> Path:
        return self.config.data_dir / "logs" / logs.WORKER_LOG

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self) -> None:
        with self._lock:
            if self.running():
                return
            self._stopping = False
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_file = logs.rotating(self.log_path, "%(message)s")   # size-rotated worker.log
            flags = 0
            if sys.platform == "win32":
                flags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
            self.proc = subprocess.Popen(
                [self.python, "-I", "-m", "airlock.worker"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=flags,
            )
            self._log_pump = threading.Thread(target=self._pump_log, args=(self.proc.stderr, self._log_file),
                                              name="airlock-worker-log", daemon=True)
            self._log_pump.start()
            if sys.platform == "win32":
                self.in_job = jobobject.assign(int(self.proc._handle))  # type: ignore[attr-defined]
            self.ghidra = None
            self._progress.clear()
            self._reader = threading.Thread(target=self._read_loop, name="airlock-worker-reader",
                                            daemon=True)
            self._reader.start()

    @staticmethod
    def _pump_log(stream: Any, handler: Any) -> None:
        """Copy the worker's stderr into the rotating log, line by line."""
        try:
            for raw in iter(stream.readline, b""):
                text = raw.decode("utf-8", "replace").rstrip("\r\n")
                handler.handle(logging.makeLogRecord({"msg": text, "levelno": logging.INFO}))
        except (OSError, ValueError):
            pass

    def _read_loop(self) -> None:
        proc = self.proc
        assert proc is not None and proc.stdout is not None
        for line in proc.stdout:
            try:
                msg = decode(line)
            except ValueError:
                continue
            if "event" in msg and "id" not in msg:
                self._dispatch_event(msg)
                continue
            rid = msg.get("id")
            if rid in self._pending:
                event, box = self._pending[rid]
                box.append(msg)
                event.set()
        # worker gone: log the exit code (a crash has none of its own), then fail everything waiting
        self._note_exit(proc)
        # fail everything still waiting
        for event, box in list(self._pending.values()):
            if not box:
                box.append({"ok": False, "error": (
                    {"code": "worker_stopped", "message": "worker was stopped (server shutdown)"}
                    if self._stopping else
                    {"code": "worker_exited", "message": "worker process exited"})})
            event.set()

    def _note_exit(self, proc: Any) -> None:
        """Write how the worker ended into worker.log; 0xC0000005 and the like name a native crash."""
        handler = self._log_file
        if proc is None or handler is None:
            return
        try:
            code = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            return
        if self._pending and code != 0 and not self._stopping:
            text = (f"[server] worker pid {proc.pid} exited with code {code & 0xFFFFFFFF:#010x} ({code}) "
                    f"while {len(self._pending)} request(s) were pending")
            try:
                handler.handle(logging.makeLogRecord({"msg": text, "levelno": logging.WARNING}))
            except (OSError, ValueError):
                pass

    def stop(self, timeout: float = 5.0) -> None:
        proc = self.proc
        if proc is None:
            return
        self._stopping = True
        if proc.poll() is None:
            try:
                self.request("shutdown", timeout=timeout)
            except WorkerError:
                pass
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=timeout)
        self.proc = None
        self.ghidra = None
        pump = getattr(self, "_log_pump", None)
        if pump is not None:
            pump.join(timeout=5)
            self._log_pump = None
        if self._log_file:
            self._log_file.close()
            self._log_file = None

    # ── requests ───────────────────────────────────────────────────────────

    def request(self, op: str, args: dict[str, Any] | None = None,
                timeout: float = 60.0) -> dict[str, Any]:
        self.start()
        assert self.proc is not None and self.proc.stdin is not None
        with self._lock:
            self._next_id += 1
            rid = self._next_id
        event = threading.Event()
        box: list[dict[str, Any]] = []
        self._pending[rid] = (event, box)
        try:
            with self._write_lock:
                try:
                    self.proc.stdin.write(encode({"id": rid, "op": op, "args": args or {}}))
                    self.proc.stdin.flush()
                except (BrokenPipeError, OSError) as e:
                    raise WorkerError("worker_exited", f"cannot write to worker: {e}") from e
            if not event.wait(timeout):
                self._kill()
                raise WorkerError("timeout", f"'{op}' did not answer within {timeout:.0f}s; "
                                             "worker was restarted")
            msg = box[0]
        finally:
            self._pending.pop(rid, None)
        if not msg.get("ok"):
            err = msg.get("error") or {}
            raise WorkerError(err.get("code", "error"), err.get("message", ""))
        return msg.get("data") or {}

    def _kill(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
        self.proc = None
        self.ghidra = None

    def ensure_ghidra(self, timeout: float = 300.0) -> dict[str, Any]:
        """Start the JVM and Ghidra inside the worker (once)."""
        if self.ghidra is not None and self.running():
            return self.ghidra
        cfg = self.config
        if cfg.ghidra_dir is None:
            raise WorkerError("not_configured", "ghidra_dir is not set in config.jsonc")
        t0 = time.monotonic()
        self.ghidra = self.request("start_ghidra", {
            "install_dir": str(cfg.ghidra_dir),
            "jdk_dir": str(cfg.jdk_dir) if cfg.jdk_dir else None,
            "jvm_max_memory": cfg.defaults.get("jvm_max_memory"),
        }, timeout=timeout)
        self.ghidra.setdefault("startup_s", round(time.monotonic() - t0, 2))
        return self.ghidra
