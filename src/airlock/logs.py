r"""Log files (DESIGN.md section 10, "Logs").

Machine logs live in ``%LOCALAPPDATA%\airlock\logs`` (``server.log``, ``worker.log``); the
project's own events (analysis queue, missing functions, relink, map refresh errors) also go to
``<project>\dirty\.airlock\logs\project.log``. Every file rotates by size (RotatingFileHandler,
constants below; no config keys). Nothing here writes to stdout: the worker's stdout is the protocol.
"""

from __future__ import annotations

import logging
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_MAX_BYTES = 2_000_000       # per file, before it rolls over
LOG_BACKUPS = 3                 # rolled files kept: <name>.1 .. <name>.3
PROJECT_LOG = "project.log"
SERVER_LOG = "server.log"
WORKER_LOG = "worker.log"
_FMT = "%(asctime)s %(levelname)s %(message)s"
_LOCK = threading.Lock()


def rotating(path: Path, fmt: str = _FMT) -> RotatingFileHandler:
    """Size-rotating UTF-8 handler; the file is opened on the first record."""
    path.parent.mkdir(parents=True, exist_ok=True)
    h = RotatingFileHandler(path, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8",
                            delay=True)
    h.setFormatter(logging.Formatter(fmt))
    return h


def setup_server_logging(data_dir: Path) -> Path:
    """Add the rotating ``server.log`` to the ``airlock`` logger (once). Returns its path."""
    path = data_dir / "logs" / SERVER_LOG
    root = logging.getLogger("airlock")
    with _LOCK:
        if not any(getattr(h, "_airlock_server", False) for h in root.handlers):
            h = rotating(path)
            h._airlock_server = True                                   # type: ignore[attr-defined]
            root.addHandler(h)
            if root.level == logging.NOTSET or root.level > logging.INFO:
                root.setLevel(logging.INFO)
    return path


class _ProjectRouter(logging.Handler):
    """Writes records that carry ``project_log`` (a file path) to that file. Low volume: the file is
    opened, written and closed per record, so nothing stays locked."""

    def emit(self, record: logging.LogRecord) -> None:
        path = getattr(record, "project_log", None)
        if not path:
            return
        try:
            with _LOCK:
                h = rotating(Path(path))
                try:
                    h.emit(record)
                finally:
                    h.close()
        except Exception:  # noqa: BLE001  logging never breaks the work
            pass


def project_log_path(logs_dir: Path) -> Path:
    return Path(logs_dir) / PROJECT_LOG


def project_log(logs_dir: Path) -> logging.LoggerAdapter:
    r"""Logger for one project: records reach the normal handlers (server.log, stderr) and
    ``<logs_dir>\project.log``. ``logs_dir`` is ``ProjectPaths.logs``."""
    root = logging.getLogger("airlock")
    with _LOCK:
        if not any(isinstance(h, _ProjectRouter) for h in root.handlers):
            root.addHandler(_ProjectRouter())
            if root.level == logging.NOTSET or root.level > logging.INFO:
                root.setLevel(logging.INFO)
    return logging.LoggerAdapter(root, {"project_log": str(project_log_path(logs_dir))})
