"""bulk_decompile / cancel_bulk: the background decompile pass of one program.

bulk_decompile(program, order=[entry, ...], timeout=60, cpu_min=None, cpu_max=None) returns at
once and runs on its own thread, using the worker's decompiler budget (worker.pool): the
threads follow the current N between functions, and one decompiler stays reserved for the
foreground `decompile` op. The server hears about it through events, in order:

  {"event":"decompile_results","program","job","ast_columns":[...],"results":[...]}
      up to 50 results (and about 512 KB) per event; a result is
      {"entry","status","s", and for "ok": "c_text","ast"; otherwise "error"}
  {"event":"decompile_progress","program","job","state":"running"|"done"|"cancelled"|"error",
   "done","total","ok","failed","rate","threads","processors","message"?}
      about once a second; the terminal state comes after the last results event.

cancel_bulk(program) is asynchronous (the in-flight functions are aborted through the task
monitor); status shows the latest snapshot as programs[].bulk.
"""

from __future__ import annotations

import itertools
import threading
import time
from typing import Any

from airlock.worker.main import emit, op
from airlock.worker.pool import log
from airlock.worker.protocol import WorkerError

from . import session as S
from .decompile import AST_COLUMNS, DEFAULT_TIMEOUT_S, make_engine
from .session import guarded

MAX_ORDER = 2_000_000


class BulkJob:
    def __init__(self, program: str, job_id: int) -> None:
        self.program, self.id = program, job_id
        self.engine: Any = None
        self.monitor: Any = None
        self.thread: threading.Thread | None = None
        self.state = "running"
        self.started = time.monotonic()


_LOCK = threading.Lock()
_JOBS: dict[str, BulkJob] = {}
_IDS = itertools.count(1)


def _compact(r: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"entry": r["entry"], "status": r["status"], "s": r.get("decompile_s")}
    if r["status"] == "ok":
        out["c_text"], out["ast"] = r["c_text"], r["ast"]
    else:
        out["error"] = r.get("error")
    return out


def _run(e: S.Entry, job: BulkJob, entries: list[int], timeout: int) -> None:
    def on_results(batch: list[dict[str, Any]]) -> None:
        emit("decompile_results", program=e.name, job=job.id, ast_columns=AST_COLUMNS,
             results=[_compact(r) for r in batch])

    def on_progress(snap: dict[str, Any]) -> None:
        e.bulk = {**snap, "job": job.id}
        emit("decompile_progress", program=e.name, job=job.id, **snap)

    try:
        job.engine = make_engine(e, entries, timeout, job.monitor, False, on_results, on_progress)
        if job.monitor.isCancelled():  # cancelled before the engine existed
            job.engine.cancel()
        job.state = job.engine.run()
    except BaseException as ex:  # report, never die silently
        job.state = "error"
        msg = f"{type(ex).__name__}: {ex}"
        log(f"bulk decompile of {e.name} failed: {msg}")
        snap = job.engine.snapshot("error") if job.engine is not None else \
            {"state": "error", "done": 0, "total": len(entries), "ok": 0, "failed": 0,
             "rate": 0.0, "threads": S.POOL.total(), "processors": S.POOL.processors}
        e.bulk = {**snap, "job": job.id, "message": msg}
        emit("decompile_progress", program=e.name, job=job.id, message=msg, **snap)
    else:
        log(f"bulk decompile of {e.name}: {job.state}, {job.engine.done}/{job.engine.total} "
            f"in {time.monotonic() - job.started:.1f}s, peak threads {job.engine.peak_threads}")


@op("bulk_decompile")
@guarded
def bulk_decompile(args: dict[str, Any]) -> dict[str, Any]:
    """bulk_decompile(program, order, timeout=60, cpu_min=None, cpu_max=None): start the
    background pass over `order` (function entry addresses, most wanted first)."""
    e = S.ready_entry(args.get("program"))
    from ghidra.util.task import TaskMonitorAdapter  # type: ignore

    order = args.get("order")
    if not isinstance(order, list) or len(order) > MAX_ORDER:
        raise WorkerError("bad_args", "order must be a list of function entry addresses")
    try:
        entries = [int(x, 0) if isinstance(x, str) else int(x) for x in order]
    except (TypeError, ValueError) as ex:
        raise WorkerError("bad_args", f"order must hold integer addresses ({ex})") from ex
    timeout = int(args.get("timeout") or DEFAULT_TIMEOUT_S)
    if args.get("cpu_min") is not None or args.get("cpu_max") is not None:
        S.POOL.configure(args.get("cpu_min"), args.get("cpu_max"))
    with _LOCK:
        cur = _JOBS.get(e.name)
        if cur is not None and cur.thread is not None and cur.thread.is_alive():
            return {"program": e.name, "job": cur.id, "already_running": True,
                    **S.POOL.describe()}
        job = BulkJob(e.name, next(_IDS))
        job.monitor = TaskMonitorAdapter()
        e.bulk = {"state": "running", "job": job.id, "done": 0, "total": len(entries),
                  "ok": 0, "failed": 0, "rate": 0.0, **S.POOL.describe()}
        job.thread = threading.Thread(target=_run, args=(e, job, entries, timeout),
                                      name=f"airlock-bulk-{e.name}", daemon=True)
        _JOBS[e.name] = job
        job.thread.start()
    return {"program": e.name, "job": job.id, "total": len(entries), "started": True,
            **S.POOL.describe()}


def cancel(program: str, join: bool = False, timeout: float = 120.0) -> bool:
    """Cancel the running pass of `program`. True if there was one."""
    with _LOCK:
        job = _JOBS.get(program)
    if job is None or job.thread is None or not job.thread.is_alive():
        return False
    if job.engine is not None:
        job.engine.cancel()
    if job.monitor is not None:
        job.monitor.cancel()
    if join:
        job.thread.join(timeout=timeout)
    return True


def cancel_all(join: bool = False) -> int:
    with _LOCK:
        names = list(_JOBS)
    return sum(1 for n in names if cancel(n, join=join))


@op("cancel_bulk")
@guarded
def cancel_bulk(args: dict[str, Any]) -> dict[str, Any]:
    """cancel_bulk(program): stop the background pass of a program (async)."""
    name = args.get("program")
    if not isinstance(name, str) or not name:
        raise WorkerError("bad_args", "program is required")
    return {"program": name, "cancelling": cancel(name)}
