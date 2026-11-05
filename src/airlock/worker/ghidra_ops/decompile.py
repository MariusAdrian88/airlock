"""decompile / decompile_batch ops and the shared per-function core.

Result: {"entry", "name", "status": "ok"|"timeout"|"error", "error", "c_text",
         "ast_columns": [...], "ast": [[kind, start_off, end_off, address, target, text], ...],
         "version_inputs": {...}, "decompile_s"}
Offsets are character indexes into c_text (Python str), end exclusive.
"""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Any

from airlock.worker.main import op
from airlock.worker.pool import Engine
from airlock.worker.pool import Engine
from airlock.worker.protocol import WorkerError

from . import session as S
from .project import dispose_decomp
from .session import Entry, guarded

# The native decompile runs outside the GIL, but turning its result into Python rows is many
# small JPype calls. Measured on 473 functions with 11 threads: unserialised, the threads
# fight over the GIL (4.0 s, slower than 4 threads); with this lock around the conversion
# only (2.0 s, 3.5x faster than one thread) and the curve stays flat from 6 threads up.
_POST = threading.Lock()

AST_COLUMNS = ["kind", "start_off", "end_off", "address", "target", "text"]
DEFAULT_TIMEOUT_S = 60
MAX_TOKEN_TEXT = 200


def open_decompiler(program: Any, style: str | None = None, max_instructions: int | None = None,
                    payload_mb: int | None = None) -> Any:
    """A new DecompInterface (one native decompiler process) on `program`. Caller holds
    the program's read or write lock and disposes it. The optional arguments are for the retry of
    a function the default settings could not finish: simplification ``style`` ("normalize",
    "firstpass", ...), the per-function ``max_instructions`` limit (Ghidra default 100000) and the
    ``payload_mb`` limit of one decompiler message (default 50)."""
    from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
    di = DecompInterface()
    opts = DecompileOptions()
    if max_instructions:
        opts.setMaxInstructions(int(max_instructions))
    if payload_mb:
        opts.setMaxPayloadMBytes(int(payload_mb))
    di.setOptions(opts)
    di.toggleCCode(True)
    di.toggleSyntaxTree(True)
    if style:
        di.setSimplificationStyle(style)
    if not di.openProgram(program):
        msg = str(di.getLastMessage())
        di.dispose()
        raise WorkerError("decompiler_failed", f"cannot open decompiler for program: {msg}")
    return di


def _decomp(e: Entry) -> Any:
    """The entry's reserved foreground decompiler (created lazily; caller holds e.fg)."""
    if e.decomp is None:
        e.decomp = open_decompiler(e.program)
    return e.decomp


def _bytes_hash(program: Any, func: Any) -> str:
    mem = program.getMemory()
    h = hashlib.sha256()
    import jpype
    for rng in func.getBody().getAddressRanges():
        n = int(rng.getLength())
        buf = jpype.JArray(jpype.JByte)(n)
        try:
            mem.getBytes(rng.getMinAddress(), buf)
        except Exception:  # uninitialised memory: hash what we can
            continue
        h.update(bytes(memoryview(buf).cast("B")))
    return h.hexdigest()


def _ast_rows(markup: Any, high: Any, c_text: str) -> list[list[Any]]:
    """ast_node rows (call, str_ref, global_ref) from the ClangToken stream. Tokens come in
    output order, so each one is located in c_text from the previous position.
    Measured: iterating with tokenIterator and asking for address/varnode only on the
    token kinds that need them is 2.4x faster than walking the tree (Python holds the GIL
    through this conversion, so it is the part that limits parallel speed-up)."""
    from ghidra.app.decompiler import ClangFuncNameToken, ClangToken  # type: ignore
    from ghidra.program.model.pcode import PcodeOp  # type: ignore

    rows: list[list[Any]] = []
    pos = 0
    const_color, global_color = ClangToken.CONST_COLOR, ClangToken.GLOBAL_COLOR
    it = markup.tokenIterator(True)
    while it.hasNext():
        tok = it.next()
        text = str(tok.getText())
        if not text.strip():
            continue
        idx = c_text.find(text, pos)
        if idx < 0:
            continue
        pos = idx + len(text)
        start, end = idx, pos

        if isinstance(tok, ClangFuncNameToken):
            op_ = tok.getPcodeOp()
            if op_ is not None and int(op_.getOpcode()) == PcodeOp.CALL:
                tgt = op_.getInput(0)
                target = S.addr_int(tgt.getAddress()) if tgt is not None else None
                seq = op_.getSeqnum().getTarget()
                rows.append(["call", start, end, S.addr_int(seq), target, text[:MAX_TOKEN_TEXT]])
            continue
        syntax = int(tok.getSyntaxType())
        if syntax == const_color and text[:1] in ('"', "L", "u", "U") and '"' in text[:3]:
            addr = tok.getMinAddress()
            vn = tok.getVarnode()
            target = int(vn.getOffset()) if vn is not None and vn.isConstant() else None
            rows.append(["str_ref", start, end, S.addr_int(addr) if addr is not None else None,
                         target, text[:MAX_TOKEN_TEXT]])
        elif syntax == global_color:
            addr = tok.getMinAddress()
            target = None
            hs = tok.getHighSymbol(high) if high is not None else None
            if hs is not None:
                try:
                    target = S.addr_int(hs.getStorage().getMinAddress())
                except Exception:
                    target = None
            if target is None:
                vn = tok.getVarnode()
                if vn is not None and vn.isAddress():
                    target = S.addr_int(vn.getAddress())
            rows.append(["global_ref", start, end, S.addr_int(addr) if addr is not None else None,
                         target, text[:MAX_TOKEN_TEXT]])
    return rows


def _resolve_function(program: Any, entry: Any) -> Any:
    try:
        off = int(entry, 0) if isinstance(entry, str) else int(entry)
    except (TypeError, ValueError) as ex:
        raise WorkerError("bad_args", f"entry must be an integer address ({ex})") from ex
    addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(off)
    fm = program.getFunctionManager()
    f = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
    if f is None:
        raise WorkerError("no_function", f"no function at or containing 0x{off:x}")
    return f


def decompile_function(e: Entry, di: Any, func: Any, timeout: int, monitor: Any,
                       with_version: bool = True) -> dict[str, Any]:
    """Decompile one function with `di`. The caller holds e.lock (read or write) and `di`.
    Status data, never an exception for decompiler failures."""
    entry_off = S.addr_int(func.getEntryPoint())
    t0 = time.monotonic()
    res = di.decompileFunction(func, timeout, monitor)
    took = round(time.monotonic() - t0, 3)
    out: dict[str, Any] = {
        "entry": entry_off, "name": str(func.getName()), "decompile_s": took,
        "ast_columns": AST_COLUMNS, "ast": [], "c_text": None, "error": None,
    }
    callee_entries: list[int] = []
    if res.isTimedOut() or res.getDecompiledFunction() is None:
        out["status"] = "timeout" if res.isTimedOut() else "error"
        out["error"] = str(res.getErrorMessage() or "").strip() or out["status"]
    else:
        if not res.decompileCompleted():
            out["partial"] = str(res.getErrorMessage() or "").strip() or "incomplete"
        with _POST:
            c_text = str(res.getDecompiledFunction().getC())
            out["status"] = "ok"
            out["c_text"] = c_text
            out["ast"] = _ast_rows(res.getCCodeMarkup(), res.getHighFunction(), c_text)
        callee_entries = sorted({r[4] for r in out["ast"] if r[0] == "call" and r[4] is not None})
    if with_version:
        from ghidra.framework import Application  # type: ignore
        p = e.program
        out["version_inputs"] = {
            "ghidra_version": str(Application.getApplicationVersion()),
            "analysis_profile": e.analysis_profile,
            # getModificationNumber() is a per-session counter (not stable across reopen),
            # so the project file's last-modified time is the cross-session change marker.
            "program_mod_number": int(p.getModificationNumber()),
            "project_file_modified": int(p.getDomainFile().getLastModifiedTime()),
            "bytes_hash": _bytes_hash(p, func),
            "size": int(func.getBody().getNumAddresses()),
            "signature": str(func.getPrototypeString(False, False)),
            "calling_conv": str(func.getCallingConventionName()),
            "callees": callee_entries,
        }
    return out


def check_open(e: Entry) -> None:
    if e.closed:
        raise WorkerError("no_program", f"'{e.name}' was closed. Call open_project again.")


@op("decompile")
@guarded
def decompile(args: dict[str, Any]) -> dict[str, Any]:
    """decompile(program, entry, timeout=60, style=None, max_instructions=None, payload_mb=None):
    decompile the function at/containing `entry`. Uses the entry's reserved decompiler, so it
    never waits behind the background pass. With `style`, `max_instructions` or `payload_mb` the
    function is decompiled on a throwaway decompiler with those settings (retry of a failure)."""
    e = S.ready_entry(args.get("program"))
    from ghidra.util.task import TaskMonitor  # type: ignore

    timeout = int(args.get("timeout") or DEFAULT_TIMEOUT_S)
    with S.POOL.foreground(), e.fg, e.lock.read():
        check_open(e)
        func = _resolve_function(e.program, args.get("entry"))
        if func.isExternal():
            raise WorkerError("no_function", f"'{func.getName()}' is an external function")
        retry = {k: args[k] for k in ("style", "max_instructions", "payload_mb") if args.get(k)}
        if retry:
            # a retry with other settings: its own throwaway decompiler, never the reserved one
            di = open_decompiler(e.program, retry.get("style"), retry.get("max_instructions"),
                                 retry.get("payload_mb"))
            try:
                out = decompile_function(e, di, func, timeout, TaskMonitor.DUMMY)
            finally:
                di.dispose()
            out["retry"] = retry
            return out
        out = decompile_function(e, _decomp(e), func, timeout, TaskMonitor.DUMMY)
        if out["status"] != "ok":
            dispose_decomp(e)  # a timed-out native decompiler is not trusted again
        return out


MAX_BATCH = 500


def make_engine(e: Entry, entries: list[int], timeout: int, monitor: Any, with_version: bool,
                on_results: Any, on_progress: Any = None) -> Engine:
    """An Engine that decompiles `entries` of program `e`, one decompiler per thread.
    Every result carries "req", the address that was asked for."""

    class Ctx:
        di: Any = None
        epoch = 0

    def make_ctx() -> Ctx:
        c = Ctx()
        with e.lock.read():
            check_open(e)
            c.di = open_decompiler(e.program)
            c.epoch = e.epoch
        return c

    def close_ctx(c: Ctx) -> None:
        if c.di is not None:
            try:
                c.di.dispose()
            finally:
                c.di = None

    def work(c: Ctx, req: int) -> dict[str, Any]:
        if monitor.isCancelled():
            return {"entry": req, "req": req, "status": "cancelled"}
        try:
            with e.lock.read():
                check_open(e)
                try:
                    func = _resolve_function(e.program, req)
                except WorkerError as ex:
                    return {"entry": req, "req": req, "status": "error", "error": ex.message}
                if c.di is not None and c.epoch != e.epoch:   # an annotate write happened: reopen
                    try:
                        c.di.dispose()
                    finally:
                        c.di = None
                if c.di is None:
                    c.di = open_decompiler(e.program)
                    c.epoch = e.epoch
                out = decompile_function(e, c.di, func, timeout, monitor, with_version)
        except WorkerError:
            raise
        except Exception as ex:  # Java exceptions: out of memory is data, the rest is an error
            err = S.java_error(ex) if hasattr(ex, "getClass") else None
            if err is not None and err.code == "out_of_memory":
                return {"entry": req, "req": req, "status": "error", "error": "out_of_memory",
                        "oom": True, "drop_ctx": True}
            raise
        out["req"] = req
        if out["status"] != "ok":
            if monitor.isCancelled():
                return {"entry": req, "req": req, "status": "cancelled"}
            low = (out["error"] or "").lower()
            if "out of memory" in low or "bad_alloc" in low:
                out["oom"] = True
            out["drop_ctx"] = True  # replace the native decompiler after a failure
        return out

    return Engine(entries, work, make_ctx, close_ctx, S.POOL, on_results, on_progress)


@op("decompile_batch")
@guarded
def decompile_batch(args: dict[str, Any]) -> dict[str, Any]:
    """decompile_batch(program, entries, timeout=60): `decompile` for up to 500 entries on the
    background thread budget; one result per entry (status data, not exceptions)."""
    e = S.ready_entry(args.get("program"))
    from ghidra.util.task import TaskMonitorAdapter  # type: ignore

    entries = args.get("entries")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_BATCH:
        raise WorkerError("bad_args", f"entries must be a list of 1 to {MAX_BATCH} addresses")
    try:
        entries = [int(x, 0) if isinstance(x, str) else int(x) for x in entries]
    except (TypeError, ValueError) as ex:
        raise WorkerError("bad_args", f"entries must be integer addresses ({ex})") from ex
    timeout = int(args.get("timeout") or DEFAULT_TIMEOUT_S)
    got: list[dict[str, Any]] = []
    with S.POOL.foreground():
        make_engine(e, entries, timeout, TaskMonitorAdapter(), True, got.extend).run()
    by_req = {r["req"]: r for r in got}
    results = [by_req.get(want) or {"entry": want, "req": want, "status": "error",
                                    "error": "not decompiled"} for want in entries]
    return {"program": e.name, "ast_columns": AST_COLUMNS, "results": results,
            "threads": S.POOL.total(), "processors": S.POOL.processors}
