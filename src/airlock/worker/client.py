"""Server-side handle on the worker process."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

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
        self.ghidra: dict[str, Any] | None = None
        self._next_id = 0
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._pending: dict[int, tuple[threading.Event, list[dict[str, Any]]]] = {}
        self._reader: threading.Thread | None = None
        self._log_file = None

    # ── lifecycle ──────────────────────────────────────────────────────────

    @property
    def log_path(self) -> Path:
        return self.config.data_dir / "logs" / "worker.log"

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self) -> None:
        with self._lock:
            if self.running():
                return
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_file = open(self.log_path, "ab")
            flags = 0
            if sys.platform == "win32":
                flags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
            self.proc = subprocess.Popen(
                [self.python, "-I", "-m", "airlock.worker"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self._log_file,
                creationflags=flags,
            )
            if sys.platform == "win32":
                self.in_job = jobobject.assign(int(self.proc._handle))  # type: ignore[attr-defined]
            self.ghidra = None
            self._reader = threading.Thread(target=self._read_loop, name="airlock-worker-reader",
                                            daemon=True)
            self._reader.start()

    def _read_loop(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for line in self.proc.stdout:
            try:
                msg = decode(line)
            except ValueError:
                continue
            rid = msg.get("id")
            if rid in self._pending:
                event, box = self._pending[rid]
                box.append(msg)
                event.set()
        # worker gone: fail everything still waiting
        for event, box in list(self._pending.values()):
            if not box:
                box.append({"ok": False, "error": {"code": "worker_exited",
                                                   "message": "worker process exited"}})
            event.set()

    def stop(self, timeout: float = 5.0) -> None:
        proc = self.proc
        if proc is None:
            return
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
