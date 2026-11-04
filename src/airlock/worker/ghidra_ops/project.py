"""Project, import, analysis, save, status ops."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

from airlock.worker.main import STATE, emit, op
from airlock.worker.protocol import WorkerError

from . import fixups
from . import session as S
from .session import ANALYSING, LOADED, READY, SESSION, Entry, guarded

COLLECTOR_VERSION = 2  # bump when extract/decompile row semantics change
PROGRESS_INTERVAL_S = 1.0


def _program_info(e: Entry) -> dict[str, Any]:
    p = e.program
    return {
        "program": e.name,
        "state": e.state,
        "analysed": e.state == READY,
        "image_base": S.addr_int(p.getImageBase()),
        "pointer_size": int(p.getDefaultPointerSize()),
    }


@op("open_project")
@guarded
def open_project(args: dict[str, Any]) -> dict[str, Any]:
    """open_project(path, name): open or create the Ghidra project `path`/`name`.gpr."""
    S.require_ghidra()
    path, name = args.get("path"), args.get("name")
    if not path or not name:
        raise WorkerError("bad_args", "path and name are required")
    from ghidra.base.project import GhidraProject  # type: ignore
    from ghidra.framework.model import ProjectLocator  # type: ignore

    path = str(Path(path))
    if SESSION.gp is not None and (SESSION.path, SESSION.name) != (path, name):
        _stop_analyses(force=False)
    with SESSION.mutex:
        if SESSION.gp is not None:
            if (SESSION.path, SESSION.name) == (path, name):
                return _project_info(created=False, already_open=True)
            _close_project()
        Path(path).mkdir(parents=True, exist_ok=True)  # Ghidra requires the directory to exist
        exists = ProjectLocator(path, name).exists()
        if exists:
            gp = GhidraProject.openProject(path, name, True)
        else:
            gp = GhidraProject.createProject(path, name, False)
        SESSION.gp, SESSION.path, SESSION.name = gp, path, name
        return _project_info(created=not exists)


def _project_info(created: bool, already_open: bool = False) -> dict[str, Any]:
    gp = SESSION.gp
    files = sorted(str(f.getName()) for f in gp.getRootFolder().getFiles())
    out: dict[str, Any] = {"path": SESSION.path, "name": SESSION.name,
                           "created": created, "programs": files}
    if already_open:
        out["already_open"] = True
    return out


def _stop_analyses(force: bool) -> None:
    """Refuse (or with force, cancel and join) running analyses. Call WITHOUT SESSION.mutex:
    the analysis thread takes it when it finishes."""
    running = [e for e in list(SESSION.programs.values()) if e.state == ANALYSING]
    if running and not force:
        raise WorkerError("busy", f"analysis is running on {', '.join(e.name for e in running)}. "
                                  "Call cancel_analysis or wait.")
    for e in running:
        if e.monitor is not None:
            e.monitor.cancel()
        if e.thread is not None:
            e.thread.join(timeout=120)


def _close_project() -> None:
    for e in list(SESSION.programs.values()):
        with e.lock:
            dispose_decomp(e)
    if SESSION.gp is not None:
        SESSION.gp.close()  # releases every opened program and the project lock
    SESSION.gp = None
    SESSION.path = SESSION.name = None
    SESSION.programs.clear()


def dispose_decomp(e: Entry) -> None:
    if e.decomp is not None:
        try:
            e.decomp.dispose()
        finally:
            e.decomp = None


@op("close_project")
@guarded
def close_project(args: dict[str, Any]) -> dict[str, Any]:
    """close_project(force=False): close all programs (unsaved changes are dropped), free the lock."""
    S.require_ghidra()
    _stop_analyses(force=bool(args.get("force")))
    with SESSION.mutex:
        if SESSION.gp is None:
            return {"closed": False}
        _close_project()
    return {"closed": True}


@op("import_binary")
@guarded
def import_binary(args: dict[str, Any]) -> dict[str, Any]:
    """import_binary(artifact_path, program_name): import into the project root and save."""
    gp = S.require_project()
    artifact, name = args.get("artifact_path"), args.get("program_name")
    if not artifact or not name:
        raise WorkerError("bad_args", "artifact_path and program_name are required")
    src = Path(artifact)
    if not src.is_file():
        raise WorkerError("not_found", f"{src} does not exist")
    with SESSION.mutex:
        if gp.getRootFolder().getFile(name) is not None:
            e = S.get_entry(name)
            return {**_program_info(e), "already_imported": True}
        t0 = time.monotonic()
        program = gp.importProgram(src)  # pathlib.Path -> java.io.File
        if program is None:
            raise WorkerError("import_failed", f"Ghidra could not import {src}. "
                                               "Unsupported format or no matching language.")
        gp.saveAs(program, "/", name, True)
        e = Entry(name, program, analysed=False)
        SESSION.programs[name] = e
        lang = program.getLanguage()
        return {
            **_program_info(e),
            "import_s": round(time.monotonic() - t0, 2),
            "format": str(program.getExecutableFormat()),
            "language": str(program.getLanguageID()),
            "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
            "processor": str(lang.getProcessor()),
            "big_endian": bool(lang.isBigEndian()),
        }


def analysis_profile(program: Any) -> str:
    """Short sha256 over Ghidra version, collector version and the analyzer option values."""
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # type: ignore
    from ghidra.framework import Application  # type: ignore
    from ghidra.program.model.listing import Program  # type: ignore

    AutoAnalysisManager.getAnalysisManager(program).initializeOptions()
    opts = program.getOptions(Program.ANALYSIS_PROPERTIES)
    values = {str(n): str(opts.getValueAsString(n)) for n in opts.getOptionNames()}
    blob = json.dumps({"ghidra": str(Application.getApplicationVersion()),
                       "collector": COLLECTOR_VERSION, "options": values}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


@op("analyze")
@guarded
def analyze(args: dict[str, Any]) -> dict[str, Any]:
    """analyze(program, timeout_min=None, force=False): start auto-analysis in the background."""
    e = S.get_entry(args.get("program"))
    force = bool(args.get("force"))
    timeout_min = args.get("timeout_min")
    with SESSION.mutex:
        if e.state == ANALYSING:
            return {"program": e.name, "state": ANALYSING, "already_running": True}
        if e.state == READY and not force:
            return {"program": e.name, "state": READY, "already_analysed": True}
        e.state = ANALYSING
        e.error = None
        e.started_at = time.monotonic()
        e.progress = {"job": "analysis", "program": e.name, "state": "running", "pct": None,
                      "message": "starting", "elapsed_s": 0.0}
        t = threading.Thread(target=_analysis_thread, args=(e, timeout_min),
                             name=f"airlock-analysis-{e.name}", daemon=True)
        e.thread = t
        t.start()
    return {"program": e.name, "state": ANALYSING, "started": True}


def _analysis_thread(e: Entry, timeout_min: Any) -> None:
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # type: ignore
    from ghidra.app.script import GhidraScriptUtil  # type: ignore
    from ghidra.program.util import GhidraProgramUtilities  # type: ignore
    from ghidra.util.task import TaskMonitorAdapter  # type: ignore

    monitor = TaskMonitorAdapter()
    e.monitor = monitor
    done = threading.Event()
    final: dict[str, Any] = {}

    def report(state: str, message: str, **extra: Any) -> None:
        elapsed = round(time.monotonic() - (e.started_at or time.monotonic()), 1)
        fields = {"job": "analysis", "program": e.name, "state": state, "pct": None,
                  "message": message, "elapsed_s": elapsed, **extra}
        e.progress = fields
        emit("progress", **fields)

    def ticker() -> None:
        # The analysis manager never feeds the monitor's message/progress, so derive
        # progress from it: analyzers finished so far and functions found so far.
        mgr = AutoAnalysisManager.getAnalysisManager(e.program)
        while not done.wait(PROGRESS_INTERVAL_S):
            try:
                tasks = [str(x) for x in mgr.getTimedTasks()]
                nfun = int(e.program.getFunctionManager().getFunctionCount())
            except Exception:
                continue
            msg = f"{len(tasks)} analyzers done" + (f", last: {tasks[-1]}" if tasks else "")
            report("running", msg, analyzers_done=len(tasks), functions=nfun)

    timer: threading.Timer | None = None
    tick = threading.Thread(target=ticker, name="airlock-progress", daemon=True)
    try:
        with e.lock:
            program = e.program
            if timeout_min:
                timer = threading.Timer(float(timeout_min) * 60, monitor.cancel)
                timer.daemon = True
                timer.start()
            tick.start()
            tx = program.startTransaction("airlock analyze")
            ok = False
            try:
                GhidraScriptUtil.acquireBundleHostReference()
                try:
                    mgr = AutoAnalysisManager.getAnalysisManager(program)
                    mgr.initializeOptions()
                    mgr.reAnalyzeAll(None)
                    mgr.startAnalysis(monitor, True)
                    if not monitor.isCancelled():
                        fixups.apply_call_fixups(program)
                finally:
                    GhidraScriptUtil.releaseBundleHostReference()
                ok = True
            finally:
                program.endTransaction(tx, ok)
            cancelled = bool(monitor.isCancelled())
            if not cancelled:
                GhidraProgramUtilities.markProgramAnalyzed(program)
                e.analysis_profile = analysis_profile(program)
                SESSION.gp.save(program)
            nfun = int(program.getFunctionManager().getFunctionCount())
        final = {"cancelled": cancelled, "functions": nfun}
    except BaseException as ex:  # report, never die silently
        if hasattr(ex, "getClass"):
            err = S.java_error(ex)
            final = {"error": f"{err.code}: {err.message}"}
        else:
            final = {"error": f"{type(ex).__name__}: {ex}"}
    finally:
        done.set()
        if timer is not None:
            timer.cancel()
        if tick.is_alive():
            tick.join(timeout=5)
        e.monitor = None
        with SESSION.mutex:
            if "error" in final:
                e.state, e.error = LOADED, final["error"]
            elif final.get("cancelled"):
                e.state, e.error = LOADED, "analysis cancelled or timed out"
            else:
                e.state = READY
        # terminal event only after the state is final, so status() and the event agree
        if "error" in final:
            report("error", final["error"])
        elif final.get("cancelled"):
            report("cancelled", e.error or "cancelled")
        else:
            report("done", "analysis finished", functions=final["functions"],
                   analysis_profile=e.analysis_profile)


@op("link_externals")
@guarded
def link_externals(args: dict[str, Any]) -> dict[str, Any]:
    """link_externals(links=[{program, libs: {library name (any case): target program}}]):
    point each program's external libraries at programs of this project
    (ExternalManager.setExternalPath), so imports resolve across binaries. Libraries the
    program does not import are ignored. Programs being analysed are skipped."""
    gp = S.require_project()
    done: list[list[str]] = []
    skipped: list[str] = []
    for link in args.get("links") or []:
        e = S.get_entry(link.get("program"))
        want = {str(k).lower(): str(v) for k, v in (link.get("libs") or {}).items()}
        if e.state == ANALYSING:
            skipped.append(e.name)
            continue
        with e.lock:
            em = e.program.getExternalManager()
            todo = []
            for lib in (str(n) for n in em.getExternalLibraryNames()):
                target = want.get(lib.lower())
                if target is None or target == e.name:
                    continue
                if gp.getRootFolder().getFile(target) is None:
                    continue
                path = "/" + target
                if str(em.getExternalLibraryPath(lib) or "") != path:
                    todo.append((lib, path))
            if not todo:
                continue
            tx = e.program.startTransaction("airlock link externals")
            ok = False
            try:
                for lib, path in todo:
                    em.setExternalPath(lib, path, True)
                ok = True
            finally:
                e.program.endTransaction(tx, ok)
            gp.save(e.program)
            done += [[e.name, lib, path] for lib, path in todo]
    return {"linked": done, "skipped": skipped}


@op("external_paths")
@guarded
def external_paths(args: dict[str, Any]) -> dict[str, Any]:
    """external_paths(program): {library name: project path or ''} of the program's externals."""
    e = S.get_entry(args.get("program"))
    with e.lock:
        em = e.program.getExternalManager()
        return {"program": e.name,
                "paths": {str(n): str(em.getExternalLibraryPath(n) or "")
                          for n in em.getExternalLibraryNames()}}


@op("cancel_analysis")
@guarded
def cancel_analysis(args: dict[str, Any]) -> dict[str, Any]:
    """cancel_analysis(program): ask a running analysis to stop (async)."""
    e = S.get_entry(args.get("program"))
    mon = e.monitor
    if e.state != ANALYSING or mon is None:
        return {"program": e.name, "state": e.state, "cancelling": False}
    mon.cancel()
    return {"program": e.name, "state": ANALYSING, "cancelling": True}


@op("save")
@guarded
def save(args: dict[str, Any]) -> dict[str, Any]:
    """save(program=None): save one program, or all loaded ones that are not analysing."""
    gp = S.require_project()
    name = args.get("program")
    entries = [S.get_entry(name)] if name else list(SESSION.programs.values())
    saved = []
    for e in entries:
        if e.state == ANALYSING:
            if name:
                raise WorkerError("not_analysed", f"'{e.name}' is still being analysed.")
            continue
        with e.lock:
            gp.save(e.program)
        saved.append(e.name)
    return {"saved": saved}


def _status_of(e: Entry) -> dict[str, Any]:
    d: dict[str, Any] = {"program": e.name, "state": e.state, "analysed": e.state == READY}
    if e.error:
        d["error"] = e.error
    if e.state == ANALYSING and e.started_at is not None:
        d["elapsed_s"] = round(time.monotonic() - e.started_at, 1)
    if e.progress:
        d["progress"] = dict(e.progress)
    if e.analysis_profile:
        d["analysis_profile"] = e.analysis_profile
    return d


@op("status")
def status(args: dict[str, Any]) -> dict[str, Any]:
    """status(program=None): worker, project and per-program state. Never touches Ghidra."""
    want = args.get("program")
    with SESSION.mutex:
        entries = [SESSION.programs[want]] if want in SESSION.programs \
            else ([] if want else list(SESSION.programs.values()))
        out: dict[str, Any] = {
            "ghidra_started": STATE.ghidra is not None,
            "project": ({"path": SESSION.path, "name": SESSION.name}
                        if SESSION.gp is not None else None),
            "programs": [_status_of(e) for e in entries],
        }
        if SESSION.gp is not None:  # in the project but not opened in this worker yet
            known = {x["program"] for x in out["programs"]}
            for f in SESSION.gp.getRootFolder().getFiles():
                n = str(f.getName())
                if n not in known and (not want or n == want):
                    out["programs"].append({"program": n, "state": "unloaded"})
    return out
