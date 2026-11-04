"""decompile op: C text plus ast_node rows from the decompiler's ClangNode markup.

Result: {"entry", "name", "status": "ok"|"timeout"|"error", "error", "c_text",
         "ast_columns": [...], "ast": [[kind, start_off, end_off, address, target, text], ...],
         "version_inputs": {...}, "decompile_s"}
Offsets are character indexes into c_text (Python str), end exclusive.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Iterator

from airlock.worker.main import op
from airlock.worker.protocol import WorkerError

from . import session as S
from .project import dispose_decomp
from .session import Entry, guarded

AST_COLUMNS = ["kind", "start_off", "end_off", "address", "target", "text"]
DEFAULT_TIMEOUT_S = 60
MAX_TOKEN_TEXT = 200


def _decomp(e: Entry) -> Any:
    if e.decomp is None:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
        di = DecompInterface()
        opts = DecompileOptions()
        di.setOptions(opts)
        di.toggleCCode(True)
        di.toggleSyntaxTree(True)
        if not di.openProgram(e.program):
            msg = str(di.getLastMessage())
            di.dispose()
            raise WorkerError("decompiler_failed", f"cannot open decompiler for program: {msg}")
        e.decomp = di
    return e.decomp


def _leaf_tokens(node: Any) -> Iterator[Any]:
    """Depth-first leaves (ClangToken) of a ClangNode tree, in document order."""
    stack = [(node, 0)]
    while stack:
        n, i = stack.pop()
        count = int(n.numChildren())
        if count == 0:
            yield n
            continue
        if i < count:
            stack.append((n, i + 1))
            stack.append((n.Child(i), 0))


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
    from ghidra.app.decompiler import ClangFuncNameToken, ClangToken  # type: ignore
    from ghidra.program.model.pcode import PcodeOp  # type: ignore

    rows: list[list[Any]] = []
    pos = 0
    for tok in _leaf_tokens(markup):
        if not ClangToken.class_.isInstance(tok):
            continue
        text = str(tok.getText())
        if not text.strip():
            continue
        idx = c_text.find(text, pos)  # tokens come in output order
        if idx < 0:
            continue
        pos = idx + len(text)
        start, end = idx, idx + len(text)
        syntax = int(tok.getSyntaxType())
        addr = tok.getMinAddress()
        address = S.addr_int(addr) if addr is not None else None

        if ClangFuncNameToken.class_.isInstance(tok):
            op_ = tok.getPcodeOp()
            if op_ is not None and int(op_.getOpcode()) == PcodeOp.CALL:
                tgt = op_.getInput(0)
                target = S.addr_int(tgt.getAddress()) if tgt is not None else None
                seq = op_.getSeqnum().getTarget()
                rows.append(["call", start, end, S.addr_int(seq), target, text[:MAX_TOKEN_TEXT]])
            continue
        if syntax == ClangToken.CONST_COLOR and text[:1] in ('"', "L", "u", "U") and '"' in text[:3]:
            vn = tok.getVarnode()
            target = int(vn.getOffset()) if vn is not None and vn.isConstant() else None
            rows.append(["str_ref", start, end, address, target, text[:MAX_TOKEN_TEXT]])
        elif syntax == ClangToken.GLOBAL_COLOR:
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
            rows.append(["global_ref", start, end, address, target, text[:MAX_TOKEN_TEXT]])
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


@op("decompile")
@guarded
def decompile(args: dict[str, Any]) -> dict[str, Any]:
    """decompile(program, entry, timeout=60): decompile the function at/containing `entry`."""
    e = S.ready_entry(args.get("program"))
    timeout = int(args.get("timeout") or DEFAULT_TIMEOUT_S)
    from ghidra.framework import Application  # type: ignore
    from ghidra.util.task import TaskMonitor  # type: ignore

    with e.lock:
        p = e.program
        func = _resolve_function(p, args.get("entry"))
        if func.isExternal():
            raise WorkerError("no_function", f"'{func.getName()}' is an external function")
        di = _decomp(e)
        t0 = time.monotonic()
        res = di.decompileFunction(func, timeout, TaskMonitor.DUMMY)
        took = round(time.monotonic() - t0, 3)

        entry_off = S.addr_int(func.getEntryPoint())
        callee_entries: list[int] = []
        out: dict[str, Any] = {
            "entry": entry_off, "name": str(func.getName()), "decompile_s": took,
            "ast_columns": AST_COLUMNS, "ast": [], "c_text": None, "error": None,
        }
        if res.isTimedOut() or not res.decompileCompleted() or res.getDecompiledFunction() is None:
            dispose_decomp(e)  # a timed-out native decompiler is not trusted again
            out["status"] = "timeout" if res.isTimedOut() else "error"
            out["error"] = str(res.getErrorMessage() or "").strip() or out["status"]
        else:
            c_text = str(res.getDecompiledFunction().getC())
            out["status"] = "ok"
            out["c_text"] = c_text
            out["ast"] = _ast_rows(res.getCCodeMarkup(), res.getHighFunction(), c_text)
            callee_entries = sorted({r[4] for r in out["ast"] if r[0] == "call" and r[4] is not None})

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
