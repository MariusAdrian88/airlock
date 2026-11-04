"""Worker-side state: the open project and the programs loaded from it.

Locking rules
- `Entry.lock` is a reader/writer lock (worker.rwlock). Readers (decompiling different
  functions on different threads, extract) share it; writers (analysis, link_externals,
  save, closing the project) are exclusive. `with e.lock:` is the write side.
  The analysis thread holds the write side for the whole analysis.
- `Entry.fg` serialises users of the entry's reserved foreground decompiler. Take it
  before the read lock, never after.
- `SESSION.mutex` guards the dicts/state fields only and is never held across
  Ghidra calls, so `hello`/`status` always answer.
- A program whose `state` is not "ready" is refused by `ready_entry()` with the
  WorkerError code `not_analysed`; that check happens before taking `Entry.lock`,
  so requests never queue behind a running analysis.
"""

from __future__ import annotations

import functools
import threading
from typing import Any, Callable

from airlock.worker.main import STATE
from airlock.worker.pool import Pool
from airlock.worker.protocol import WorkerError
from airlock.worker.rwlock import RWLock

# Entry.state values
LOADED = "loaded"        # in the project, not analysed yet
ANALYSING = "analysing"  # analysis thread running
READY = "ready"          # analysed; extract/decompile allowed


class Entry:
    def __init__(self, name: str, program: Any, analysed: bool):
        self.name = name
        self.program = program
        self.lock = RWLock()
        self.fg = threading.Lock()             # reserved foreground decompiler (self.decomp)
        self.cursor_lock = threading.Lock()    # extract cursors
        self.closed = False                    # project closed: refuse further work
        self.bulk: dict[str, Any] | None = None  # latest bulk-decompile snapshot (for status)
        self.state = READY if analysed else LOADED
        self.error: str | None = None          # last analysis failure/cancel
        self.thread: threading.Thread | None = None
        self.monitor: Any = None               # Ghidra TaskMonitor of a running analysis
        self.started_at: float | None = None
        self.progress: dict[str, Any] | None = None
        self.analysis_profile: str | None = None
        self.decomp: Any = None                # reserved foreground DecompInterface (lazy)
        self.cursors: dict[str, Any] = {}      # extract cursors by kind


class _Session:
    def __init__(self) -> None:
        self.mutex = threading.RLock()
        self.gp: Any = None                    # ghidra.base.project.GhidraProject
        self.path: str | None = None
        self.name: str | None = None
        self.programs: dict[str, Entry] = {}


SESSION = _Session()


def _analysis_running() -> bool:
    return any(e.state == ANALYSING for e in list(SESSION.programs.values()))


# Decompiler thread budget: processors are detected here, when the worker starts.
POOL = Pool(analysis_running=_analysis_running)


def require_ghidra() -> None:
    if STATE.ghidra is None:
        raise WorkerError("ghidra_not_started", "Ghidra is not running. Call start_ghidra first.")


def require_project() -> Any:
    require_ghidra()
    if SESSION.gp is None:
        raise WorkerError("no_project", "No project is open. Call open_project first.")
    return SESSION.gp


def is_analysed(program: Any) -> bool:
    from ghidra.program.util import GhidraProgramUtilities  # type: ignore
    return bool(GhidraProgramUtilities.isAnalyzed(program))


def get_entry(name: Any) -> Entry:
    """Entry for a program in the open project, loading it from the project if needed."""
    gp = require_project()
    if not isinstance(name, str) or not name:
        raise WorkerError("bad_args", "program is required")
    with SESSION.mutex:
        e = SESSION.programs.get(name)
        if e is not None:
            return e
        if gp.getRootFolder().getFile(name) is None:
            raise WorkerError("no_program", f"No program '{name}' in the project. "
                                            "Call import_binary first.")
        program = gp.openProgram("/", name, False)
        e = Entry(name, program, is_analysed(program))
        SESSION.programs[name] = e
        return e


def ready_entry(name: Any) -> Entry:
    e = get_entry(name)
    if e.state == ANALYSING:
        raise WorkerError("not_analysed", f"'{e.name}' is still being analysed. "
                                          "Poll status and retry when state is ready.")
    if e.state != READY:
        hint = f" (last attempt: {e.error})" if e.error else ""
        raise WorkerError("not_analysed", f"'{e.name}' has not been analysed{hint}. "
                                          "Call analyze first.")
    if e.analysis_profile is None:  # analysed in an earlier session
        from airlock.worker.ghidra_ops.project import analysis_profile
        with e.lock:
            e.analysis_profile = analysis_profile(e.program)
    return e


def addr_int(address: Any) -> int:
    """Address -> int. Never str(address) (JPype gives Java long -> int via getOffset)."""
    return int(address.getOffset())


def space_of(address: Any) -> str:
    return str(address.getAddressSpace().getName())


def java_error(e: BaseException) -> WorkerError:
    """Map a Java exception (JPype) to a WorkerError code."""
    try:
        cls = str(e.getClass().getName())  # type: ignore[attr-defined]
        msg = str(e.getMessage() or "")    # type: ignore[attr-defined]
    except Exception:
        return WorkerError("ghidra_error", f"{type(e).__name__}: {e}")
    simple = cls.rsplit(".", 1)[-1]
    text = f"{simple}: {msg}" if msg else simple
    if simple == "CancelledException":
        return WorkerError("cancelled", text)
    if simple == "OutOfMemoryError":
        return WorkerError("out_of_memory", f"{text}. Raise defaults.jvm_max_memory and restart.")
    if simple in {"FileNotFoundException", "NoSuchFileException"}:
        return WorkerError("not_found", text)
    if simple == "LockException" or "lock" in msg.lower():
        return WorkerError("project_locked", f"{text}. Close the project in the Ghidra GUI.")
    if simple == "VersionException":
        return WorkerError("version_mismatch", text)
    if simple in {"LoadException", "LanguageNotFoundException", "InvalidInputException"}:
        return WorkerError("import_failed", text)
    if simple == "DuplicateNameException":
        return WorkerError("exists", text)
    if simple.endswith("IOException"):
        return WorkerError("io_error", text)
    return WorkerError("ghidra_error", f"{cls}: {msg}")


def guarded(fn: Callable[[dict[str, Any]], dict[str, Any]]) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Turn Java exceptions raised by an op into WorkerError."""
    @functools.wraps(fn)
    def wrapper(args: dict[str, Any]) -> dict[str, Any]:
        try:
            return fn(args)
        except WorkerError:
            raise
        except Exception as e:
            try:
                import jpype
                if isinstance(e, jpype.JException):
                    raise java_error(e) from e
            except ImportError:
                pass
            raise
    return wrapper
