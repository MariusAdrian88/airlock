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
from . import stubs
from .session import ANALYSING, LOADED, READY, SESSION, Entry, guarded

COLLECTOR_VERSION = 13  # 13: 32-bit Pascal functions get the full register prototype, stack arguments in source order (pascalconv, delphistr VERSION 7); 12: the string index lists the Pascal ShortString literals that code points at (shortstr); 11: Delphi x86 indirect calls get the same stubs (delphistr VERSION 6); 10: Free Pascal x86 indirect calls get register-convention stubs (delphistr VERSION 5); 9: decompiled calls to a concat stub name the real routine (delphistr VERSION 4); 8: Free Pascal x64 string literals (24-byte header), stub caps raised; 7: airlock stubs left out of extract/disassemble/decompile rows; 4: Delphi string literals (delphistr); 5: delphistr v2; 6: concat calls get stub signatures. Bump when extract/decompile row semantics or post-analysis fixups change
PROFILE_COLLECTOR = 4  # the collector part of analysis_profile; raise with COLLECTOR_VERSION unless only delphistr changed
STRINGS_ONLY_FROM = {4, 5, 6, 7, 8, 9, 10, 11, 12}  # stored collector versions that need only the Delphi string pass rerun
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
    from . import bulk
    bulk.cancel_all(join=True)  # outside SESSION.mutex, so status keeps answering
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
    from . import bulk
    bulk.cancel_all(join=True)  # background decompiles read the programs we are about to close
    for e in list(SESSION.programs.values()):
        with e.lock:
            e.closed = True
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
        if gp.getRootFolder().getFile(name) is None:
            raise WorkerError("import_failed", f"'{name}' is not in the Ghidra project after the import.")
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
    """Short sha256 over Ghidra version, collector version, the analyzer option values and, for a
    Delphi program, the version of the string pass (so a new pass invalidates only Delphi decompiles)."""
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # type: ignore
    from ghidra.framework import Application  # type: ignore
    from ghidra.program.model.listing import Program  # type: ignore

    AutoAnalysisManager.getAnalysisManager(program).initializeOptions()
    opts = program.getOptions(Program.ANALYSIS_PROPERTIES)
    values = {str(n): str(opts.getValueAsString(n)) for n in opts.getOptionNames()}
    prof: dict[str, Any] = {"ghidra": str(Application.getApplicationVersion()),
                            "collector": PROFILE_COLLECTOR, "options": values}
    own = program.getOptions("airlock")
    if own.contains("delphi_strings"):
        prof["delphi_strings"] = int(own.getInt("delphi_strings", 0))
    blob = json.dumps(prof, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


@op("analyze")
@guarded
def analyze(args: dict[str, Any]) -> dict[str, Any]:
    """analyze(program, timeout_min=None, force=False, parameter_id=True): start auto-analysis in
    the background; `parameter_id` (config decompiler_parameter_id) allows the post-analysis
    Decompiler Parameter ID pass."""
    e = S.get_entry(args.get("program"))
    force = bool(args.get("force"))
    timeout_min = args.get("timeout_min")
    if force or e.state != READY:
        from . import bulk
        bulk.cancel(e.name, join=True)  # analysis takes the write lock; stop readers first
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
        t = threading.Thread(target=_analysis_thread,
                             args=(e, timeout_min, args.get("parameter_id") is not False),
                             name=f"airlock-analysis-{e.name}", daemon=True)
        e.thread = t
        t.start()
    return {"program": e.name, "state": ANALYSING, "started": True}


def _analysis_thread(e: Entry, timeout_min: Any, parameter_id: bool = True) -> None:
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
                nfun = stubs.program_function_count(e.program)
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
            with S.transaction(program, "airlock analyze"):
                GhidraScriptUtil.acquireBundleHostReference()
                try:
                    mgr = AutoAnalysisManager.getAnalysisManager(program)
                    mgr.initializeOptions()
                    mgr.reAnalyzeAll(None)
                    mgr.startAnalysis(monitor, True)
                    if not monitor.isCancelled():
                        fixups.apply_all(program, monitor, parameter_id)
                finally:
                    GhidraScriptUtil.releaseBundleHostReference()
            cancelled = bool(monitor.isCancelled())
            if not cancelled:
                GhidraProgramUtilities.markProgramAnalyzed(program)
                e.analysis_profile = analysis_profile(program)
                SESSION.gp.save(program)
            nfun = stubs.program_function_count(program)
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


@op("apply_fixups")
@guarded
def apply_fixups(args: dict[str, Any]) -> dict[str, Any]:
    """apply_fixups(program, parameter_id=True, have_collector=None): run the post-analysis fixups (prolog helpers,
    calling conventions) on an analysed program without re-analysing it, save, and return the
    new analysis_profile. Takes minutes on large binaries."""
    from ghidra.app.script import GhidraScriptUtil  # type: ignore
    from ghidra.util.task import TaskMonitorAdapter  # type: ignore

    gp = S.require_project()
    if args.get("have_collector") == COLLECTOR_VERSION:  # already current: nothing to load
        return {"program": args.get("program"), "skipped": True, "collector": COLLECTOR_VERSION}
    e = S.get_entry(args.get("program"))
    if e.state == ANALYSING:
        raise WorkerError("busy", f"'{e.name}' is being analysed. Wait for it to finish.")
    if e.state != READY:
        raise WorkerError("not_analysed", f"'{e.name}' has not been analysed. Call analyze first.")
    from . import bulk
    bulk.cancel(e.name, join=True)  # fixups take the write lock; stop the readers first
    t0 = time.monotonic()
    monitor = TaskMonitorAdapter()
    with e.lock:
        program = e.program
        with S.transaction(program, "airlock fixups"):
            GhidraScriptUtil.acquireBundleHostReference()
            try:
                if args.get("have_collector") in STRINGS_ONLY_FROM:   # only the Delphi string pass changed
                    from . import delphistr
                    stats = {"delphi_strings": delphistr.apply_delphi_strings(program, monitor)}
                else:
                    stats = fixups.apply_all(program, monitor, args.get("parameter_id") is not False)
            finally:
                GhidraScriptUtil.releaseBundleHostReference()
        e.analysis_profile = analysis_profile(program)
        gp.save(program)
    return {"program": e.name, "collector": COLLECTOR_VERSION, "fixups_s": round(time.monotonic() - t0, 1),
            "analysis_profile": e.analysis_profile, **stats}


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
            with S.transaction(e.program, "airlock link externals"):
                for lib, path in todo:
                    em.setExternalPath(lib, path, True)
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
    d: dict[str, Any] = {"program": e.name, "state": e.state, "analysed": e.state == READY,
                         "collector": COLLECTOR_VERSION}
    if e.error:
        d["error"] = e.error
    if e.state == ANALYSING and e.started_at is not None:
        d["elapsed_s"] = round(time.monotonic() - e.started_at, 1)
    if e.progress:
        d["progress"] = dict(e.progress)
    if e.analysis_profile:
        d["analysis_profile"] = e.analysis_profile
    if e.bulk:
        d["bulk"] = dict(e.bulk)
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
