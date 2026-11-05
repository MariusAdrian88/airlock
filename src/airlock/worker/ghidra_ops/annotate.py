"""Annotate ops (DESIGN.md section 6 "annotate"): the writes into the Ghidra project.

Every op takes the program's write lock (after the reserved foreground decompiler's lock, the
documented order), runs inside one Ghidra transaction, saves the program before it answers, drops
the foreground decompiler and bumps `Entry.epoch` so decompilers that bulk threads opened earlier
are reopened (their symbol and type caches would otherwise show the old names and types). A failed
op rolls its transaction back. The ops run one at a time on the main lane (not in CONCURRENT_OPS).

Ops
- rename_function(program, space, entry, new_name): `A::B::name` moves the function into that namespace;
  a bare name keeps its namespace.
- rename_label(program, space, address | name, new_name): a data or code label; creates one when the
  address has none.
- rename_variable(program, entry, variable, new_name) / retype_variable(program, entry, variable, type):
  a local or parameter, found by the name the decompiler shows.
- set_comment(program, space, address, text, kind): plate/pre/eol; an empty text clears. A plate comment
  keeps the airlock notes block (below).
- annotate_function(program, space, entry, new_name?, notes?): rename plus the notes block of the plate
  comment in one transaction (`notes` = list of lines; [] removes the block).
- define_struct(program, name, fields, size?): create or replace a structure in the root category.

The pure helpers (plate block handling, name splitting, struct layout checks) import nothing from Ghidra.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from airlock.worker.main import op
from airlock.worker.protocol import WorkerError

from . import session as S
from .decompile import check_open, open_decompiler
from .project import dispose_decomp
from .session import Entry, guarded

NOTES_BEGIN = "--- airlock notes ---"
NOTES_END = "--- end airlock notes ---"
_BLOCK = re.compile(r"\n?" + re.escape(NOTES_BEGIN) + r".*?" + re.escape(NOTES_END) + r"\n?", re.S)
COMMENT_KINDS = ("plate", "pre", "eol")
DECOMPILE_TIMEOUT_S = 60
MAX_FIELDS = 512


# -- pure helpers --------------------------------------------------------------------------------

def split_plate(text: str | None) -> tuple[str, str]:
    """(text without the airlock notes block, the block or '')."""
    text = text or ""
    m = _BLOCK.search(text)
    if not m:
        return text, ""
    return (text[:m.start()] + text[m.end():]).strip("\n"), m.group(0).strip("\n")


def join_plate(user: str, block: str) -> str:
    return "\n".join(p for p in (user.strip("\n"), block) if p)


def notes_block(lines: list[str]) -> str:
    return "\n".join([NOTES_BEGIN, *lines, NOTES_END]) if lines else ""


def split_name(name: str) -> tuple[str, str]:
    """('A::B', 'name') for 'A::B::name'; ('', 'name') for a bare name."""
    ns, sep, base = name.rpartition("::")
    return (ns, base) if sep else ("", name)


def check_struct_fields(fields: Any, size: int | None) -> list[tuple[int, str, str]]:
    """Validated [(offset, type text, field name)] sorted by offset. Overlap is checked by the caller,
    which knows the type lengths."""
    if not isinstance(fields, list) or not fields:
        raise WorkerError("bad_args", "fields must be a non-empty list of {offset, type, name}")
    if len(fields) > MAX_FIELDS:
        raise WorkerError("bad_args", f"at most {MAX_FIELDS} fields")
    out: list[tuple[int, str, str]] = []
    names: set[str] = set()
    for i, f in enumerate(fields):
        if not isinstance(f, dict):
            raise WorkerError("bad_args", f"field {i} is not an object {{offset, type, name}}")
        try:
            off = int(f.get("offset"), 0) if isinstance(f.get("offset"), str) else int(f.get("offset"))
        except (TypeError, ValueError) as ex:
            raise WorkerError("bad_args", f"field {i}: offset must be an integer ({ex})") from ex
        typ, nm = str(f.get("type") or "").strip(), str(f.get("name") or "").strip()
        if off < 0 or not typ or not nm:
            raise WorkerError("bad_args", f"field {i}: offset >= 0, type and name are required")
        if nm in names:
            raise WorkerError("bad_args", f"field name '{nm}' is used twice")
        names.add(nm)
        out.append((off, typ, nm))
    return sorted(out)


# -- Ghidra helpers --------------------------------------------------------------------------------

def _mapped(ex: BaseException) -> WorkerError | None:
    """A WorkerError for the Java exceptions an annotate op expects, else None."""
    try:
        simple = str(ex.getClass().getSimpleName())  # type: ignore[attr-defined]
        msg = str(ex.getMessage() or "")             # type: ignore[attr-defined]
    except Exception:
        return None
    text = f"{simple}: {msg}" if msg else simple
    if simple == "InvalidInputException":
        return WorkerError("bad_name", text)
    if simple == "DuplicateNameException":
        return WorkerError("exists", text)
    if simple in {"InvalidDataTypeException", "UsrException"}:
        return WorkerError("bad_type", text)
    if simple in {"IllegalArgumentException", "AddressOutOfBoundsException"}:
        return WorkerError("bad_args", text)
    return None


def _write(args: dict[str, Any], label: str, body: Callable[[Entry, Any], dict[str, Any]]) -> dict[str, Any]:
    """Run `body(entry, program)` in a transaction under the write lock, then save. Rolls back and
    raises on any failure."""
    e = S.ready_entry(args.get("program"))
    with e.fg, e.lock:
        check_open(e)
        program = e.program
        with S.transaction(program, f"airlock {label}"):
            try:
                out = body(e, program)
            except WorkerError:
                raise
            except Exception as ex:
                err = _mapped(ex)
                if err is not None:
                    raise err from ex
                raise
        dispose_decomp(e)
        e.epoch += 1
        S.require_project().save(program)
    return out


def _address(program: Any, space: Any, off: Any) -> Any:
    try:
        value = int(off, 0) if isinstance(off, str) else int(off)
    except (TypeError, ValueError) as ex:
        raise WorkerError("bad_args", f"address must be an integer ({ex})") from ex
    af = program.getAddressFactory()
    sp = af.getDefaultAddressSpace() if space in (None, "", "ram") else af.getAddressSpace(str(space))
    if sp is None:
        raise WorkerError("bad_args", f"unknown address space '{space}'")
    return sp.getAddress(value)


def _function_at(program: Any, space: Any, entry: Any) -> Any:
    addr = _address(program, space, entry)
    f = program.getFunctionManager().getFunctionAt(addr)
    if f is None:
        raise WorkerError("no_function", f"no function starts at {addr}")
    return f


def _fn_info(func: Any) -> dict[str, Any]:
    ns = func.getParentNamespace()
    return {
        "entry": S.addr_int(func.getEntryPoint()), "name": str(func.getName()),
        "namespace": None if ns.isGlobal() else str(ns.getName(True)),
        "signature": str(func.getPrototypeString(False, False)),
        "calling_conv": str(func.getCallingConventionName()),
    }


def _qualified(func: Any) -> str:
    ns = func.getParentNamespace()
    return str(func.getName()) if ns.isGlobal() else f"{ns.getName(True)}::{func.getName()}"


def _rename_function(program: Any, func: Any, new_name: str) -> None:
    from ghidra.app.util import NamespaceUtils  # type: ignore
    from ghidra.program.model.symbol import SourceType  # type: ignore

    ns_path, base = split_name(new_name)
    if not base:
        raise WorkerError("bad_name", f"'{new_name}' has no name after '::'")
    ns = None
    if ns_path:
        ns = NamespaceUtils.createNamespaceHierarchy(
            ns_path, program.getGlobalNamespace(), program, SourceType.USER_DEFINED)
    func.setName(base, SourceType.USER_DEFINED)
    if ns is not None:
        func.setParentNamespace(ns)


def _parse_type(program: Any, text: str) -> Any:
    from ghidra.program.model.data import DataTypeConflictHandler  # type: ignore
    from ghidra.util.data import DataTypeParser  # type: ignore

    dtm = program.getDataTypeManager()
    parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
    try:
        dt = parser.parse(text)
    except Exception as ex:
        err = _mapped(ex)
        raise (err if err is not None else WorkerError("bad_type", f"cannot parse type '{text}': {ex}")) from ex
    if dt is None:
        raise WorkerError("bad_type", f"cannot parse type '{text}'")
    return dtm.resolve(dt, DataTypeConflictHandler.DEFAULT_HANDLER)


def _plate_text(program: Any, addr: Any) -> str:
    from ghidra.program.model.listing import CommentType  # type: ignore
    return str(program.getListing().getComment(CommentType.PLATE, addr) or "")


def _set_comment(program: Any, addr: Any, kind: str, text: str | None) -> None:
    from ghidra.program.model.listing import CommentType  # type: ignore

    ct = {"plate": CommentType.PLATE, "pre": CommentType.PRE, "eol": CommentType.EOL}[kind]
    program.getListing().setComment(addr, ct, text if text else None)


def _high_symbol(program: Any, func: Any, name: str) -> tuple[Any, Any, list[str]]:
    """(HighSymbol, decompiler to dispose, all names) of the local or parameter shown as `name`."""
    from ghidra.util.task import TaskMonitor  # type: ignore

    di = open_decompiler(program)
    try:
        res = di.decompileFunction(func, DECOMPILE_TIMEOUT_S, TaskMonitor.DUMMY)
        hf = res.getHighFunction()
        if hf is None:
            raise WorkerError("decompile_failed", f"cannot decompile {func.getName()}: "
                              f"{str(res.getErrorMessage() or 'no result').strip()}")
        it = hf.getLocalSymbolMap().getSymbols()
        names: list[str] = []
        found = None
        while it.hasNext():
            sym = it.next()
            n = str(sym.getName())
            names.append(n)
            if n == name and found is None:
                found = sym
        if found is None:
            raise WorkerError("no_variable", f"{func.getName()} shows no variable '{name}' "
                              f"(it shows: {', '.join(names[:30]) or 'none'})")
        return found, di, names
    except BaseException:
        di.dispose()
        raise


# -- ops ---------------------------------------------------------------------------------------------

@op("rename_function")
@guarded
def rename_function(args: dict[str, Any]) -> dict[str, Any]:
    """rename_function(program, space, entry, new_name): rename the function starting at `entry`."""
    new = str(args.get("new_name") or "").strip()
    if not new:
        raise WorkerError("bad_args", "new_name is required")

    def body(e: Entry, program: Any) -> dict[str, Any]:
        func = _function_at(program, args.get("space"), args.get("entry"))
        old = _qualified(func)
        _rename_function(program, func, new)
        return {**_fn_info(func), "old": old}
    return _write(args, "rename function", body)


@op("rename_label")
@guarded
def rename_label(args: dict[str, Any]) -> dict[str, Any]:
    """rename_label(program, space, address | name, new_name): rename the label at `address` (or the
    global label called `name`); creates a label when the address has none. Functions are refused."""
    new = str(args.get("new_name") or "").strip()
    if not new:
        raise WorkerError("bad_args", "new_name is required")

    def body(e: Entry, program: Any) -> dict[str, Any]:
        from ghidra.program.model.symbol import SourceType, SymbolType  # type: ignore

        st = program.getSymbolTable()
        sym = None
        if args.get("name"):
            syms = [s for s in st.getGlobalSymbols(str(args["name"]))]
            if not syms:
                raise WorkerError("not_found", f"no global label '{args['name']}'")
            if len(syms) > 1:
                raise WorkerError("ambiguous", f"label '{args['name']}' exists at "
                                  + ", ".join(str(s.getAddress()) for s in syms[:10]))
            sym = syms[0]
            addr = sym.getAddress()
        else:
            addr = _address(program, args.get("space"), args.get("address"))
            sym = st.getPrimarySymbol(addr)
        if sym is not None and sym.getSymbolType() == SymbolType.FUNCTION:
            raise WorkerError("wrong_kind", f"{addr} is the function {sym.getName()}; use kind=function")
        if sym is None:
            if not program.getMemory().contains(addr):
                raise WorkerError("bad_args", f"{addr} is not in the program's memory")
            old = ""
            st.createLabel(addr, new, SourceType.USER_DEFINED)
        else:
            old = str(sym.getName())
            sym.setName(new, SourceType.USER_DEFINED)
        return {"address": S.addr_int(addr), "space": S.space_of(addr), "old": old, "new": new}
    return _write(args, "rename label", body)


def _variable_op(args: dict[str, Any], label: str, new_name: str | None, type_text: str | None) -> dict[str, Any]:
    var = str(args.get("variable") or "")
    if not var:
        raise WorkerError("bad_args", "variable is required")

    def body(e: Entry, program: Any) -> dict[str, Any]:
        from ghidra.program.model.pcode import HighFunctionDBUtil  # type: ignore
        from ghidra.program.model.symbol import SourceType  # type: ignore

        func = _function_at(program, args.get("space"), args.get("entry"))
        sym, di, names = _high_symbol(program, func, var)
        try:
            if new_name is not None and new_name != var and new_name in names:
                raise WorkerError("exists", f"{func.getName()} already has a variable '{new_name}'")
            dt = _parse_type(program, type_text) if type_text is not None else None
            is_param = bool(sym.isParameter())
            HighFunctionDBUtil.updateDBVariable(sym, new_name, dt, SourceType.USER_DEFINED)
        finally:
            di.dispose()
        return {**_fn_info(func), "variable": var, "new_name": new_name, "is_param": is_param,
                "type": str(dt.getDisplayName()) if dt is not None else None}
    return _write(args, label, body)


@op("rename_variable")
@guarded
def rename_variable(args: dict[str, Any]) -> dict[str, Any]:
    """rename_variable(program, space, entry, variable, new_name): rename a local or parameter."""
    new = str(args.get("new_name") or "").strip()
    if not new:
        raise WorkerError("bad_args", "new_name is required")
    return _variable_op(args, "rename variable", new, None)


@op("retype_variable")
@guarded
def retype_variable(args: dict[str, Any]) -> dict[str, Any]:
    """retype_variable(program, space, entry, variable, type): set the data type of a local or parameter."""
    t = str(args.get("type") or "").strip()
    if not t:
        raise WorkerError("bad_args", "type is required")
    return _variable_op(args, "retype variable", None, t)


@op("set_comment")
@guarded
def set_comment(args: dict[str, Any]) -> dict[str, Any]:
    """set_comment(program, space, address, text, kind=plate): empty text clears the comment. A plate
    comment keeps the airlock notes block."""
    kind = str(args.get("kind") or "plate")
    if kind not in COMMENT_KINDS:
        raise WorkerError("bad_args", f"kind must be one of {', '.join(COMMENT_KINDS)}")
    text = str(args.get("text") or "")

    def body(e: Entry, program: Any) -> dict[str, Any]:
        addr = _address(program, args.get("space"), args.get("address"))
        if program.getMemory().getBlock(addr) is None:
            raise WorkerError("bad_args", f"{addr} is not in the program's memory")
        if kind == "plate":
            _user, block = split_plate(_plate_text(program, addr))
            text_ = join_plate(text, block)
        else:
            text_ = text
        _set_comment(program, addr, kind, text_)
        return {"address": S.addr_int(addr), "kind": kind, "cleared": not text}
    return _write(args, "comment", body)


@op("annotate_function")
@guarded
def annotate_function(args: dict[str, Any]) -> dict[str, Any]:
    """annotate_function(program, space, entry, new_name=None, notes=None): the optional rename and the
    notes block of the plate comment (notes: list of lines, [] removes the block) in one transaction."""
    new = str(args.get("new_name") or "").strip()
    notes = args.get("notes")
    if notes is not None and not isinstance(notes, list):
        raise WorkerError("bad_args", "notes must be a list of lines")

    def body(e: Entry, program: Any) -> dict[str, Any]:
        func = _function_at(program, args.get("space"), args.get("entry"))
        old = _qualified(func)
        if new:
            _rename_function(program, func, new)
        if notes is not None:
            addr = func.getEntryPoint()
            user, _old_block = split_plate(_plate_text(program, addr))
            _set_comment(program, addr, "plate", join_plate(user, notes_block([str(x) for x in notes])))
        return {**_fn_info(func), "old": old, "renamed": bool(new)}
    return _write(args, "annotate", body)


@op("define_struct")
@guarded
def define_struct(args: dict[str, Any]) -> dict[str, Any]:
    """define_struct(program, name, fields=[{offset, type, name}], size=None): create or replace the
    structure `name` in the root category. Gaps stay undefined bytes."""
    name = str(args.get("name") or "").strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise WorkerError("bad_name", f"'{name}' is not a C identifier")
    size = args.get("size")
    size = int(size) if size not in (None, "") else None
    fields = check_struct_fields(args.get("fields"), size)

    def body(e: Entry, program: Any) -> dict[str, Any]:
        from ghidra.program.model.data import (  # type: ignore
            CategoryPath, DataTypeConflictHandler, StructureDataType,
        )

        dtm = program.getDataTypeManager()
        typed = []
        end = 0
        for off, typ, fname in fields:
            dt = _parse_type(program, typ)
            ln = int(dt.getLength())
            if ln <= 0:
                raise WorkerError("bad_type", f"field '{fname}': type '{typ}' has no fixed size")
            if typed and off < typed[-1][0] + typed[-1][2]:
                raise WorkerError("bad_args", f"field '{fname}' at {off} overlaps '{typed[-1][3]}'")
            typed.append((off, dt, ln, fname))
            end = max(end, off + ln)
        total = size if size is not None else end
        if total < end:
            raise WorkerError("bad_args", f"size {total} is smaller than the last field's end ({end})")
        existing = dtm.getDataType("/" + name)
        st = StructureDataType(CategoryPath.ROOT, name, total)
        for off, dt, ln, fname in typed:
            st.replaceAtOffset(off, dt, ln, fname, None)
        res = dtm.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER)
        return {"name": name, "path": str(res.getPathName()), "size": int(res.getLength()),
                "fields": len(typed), "replaced": existing is not None}
    return _write(args, "define struct", body)


# -- patch_bytes -----------------------------------------------------------------------------------

MAX_PATCH = 512


def parse_patch_hex(text: Any) -> bytes:
    """Bytes from hex text (spaces, commas and a 0x prefix per byte allowed). Pure."""
    s = re.sub(r"0x|[\s,]", "", str(text or ""), flags=re.I)
    if not s or len(s) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        raise WorkerError("bad_args", "hex must be an even number of hex digits, e.g. 90 90 or 8BFF55")
    data = bytes.fromhex(s)
    if len(data) > MAX_PATCH:
        raise WorkerError("bad_args", f"at most {MAX_PATCH} bytes per patch")
    return data


def _jbytes(data: bytes) -> Any:
    import jpype
    return jpype.JArray(jpype.JByte)([b - 256 if b > 127 else b for b in data])


def _read_bytes(mem: Any, addr: Any, n: int) -> bytes:
    import jpype
    buf = jpype.JArray(jpype.JByte)(n)
    mem.getBytes(addr, buf)
    return bytes(memoryview(buf).cast("B"))


@op("patch_bytes")
@guarded
def patch_bytes(args: dict[str, Any]) -> dict[str, Any]:
    """patch_bytes(program, space, address, hex, force=False, expect=None): write bytes into the
    program memory (never into the original file) in one transaction. Refuses uninitialised memory
    (`uninitialized`), a changed `expect` (`changed`: the bytes are not what the caller expects) and
    a patch whose old or new instruction boundaries differ from the patched range (`boundary`)
    unless `force`. Instructions in the range are cleared and disassembled again.
    Result: {address, length, old, new, cleared: [start, end] | None, instructions, functions: [entry]}."""
    data = parse_patch_hex(args.get("hex"))
    force = bool(args.get("force"))
    expect = parse_patch_hex(args["expect"]) if args.get("expect") else None
    if expect is not None and len(expect) != len(data):
        raise WorkerError("bad_args", "expect and hex must have the same length")

    def body(e: Entry, program: Any) -> dict[str, Any]:
        from ghidra.app.cmd.disassemble import DisassembleCommand  # type: ignore
        from ghidra.program.model.address import AddressSet  # type: ignore
        from ghidra.util.task import TaskMonitor  # type: ignore

        addr = _address(program, args.get("space"), args.get("address"))
        n = len(data)
        try:
            end = addr.add(n - 1)
        except Exception as ex:
            raise WorkerError("bad_args", f"{addr} + {n} bytes is outside the address space") from ex
        mem = program.getMemory()
        a = addr
        while a is not None and a.compareTo(end) <= 0:
            blk = mem.getBlock(a)
            if blk is None or not blk.isInitialized():
                raise WorkerError("uninitialized", f"{a} is not in initialised memory"
                                  + (f" (block {blk.getName()})" if blk is not None else ""))
            a = blk.getEnd().next()
        old = _read_bytes(mem, addr, n)
        if expect is not None and old != expect and not force:
            raise WorkerError("changed", f"the bytes at {addr} are {old.hex()}, not {expect.hex()}")
        listing = program.getListing()
        has_insn = False
        a_start, a_end = addr, end
        it = listing.getCodeUnits(AddressSet(addr, end), True)
        while it.hasNext():
            if listing.getInstructionAt(it.next().getMinAddress()) is not None:
                has_insn = True
        for edge in (addr, end):       # an instruction that starts before or ends after the range
            cu = listing.getCodeUnitContaining(edge)
            if cu is not None and listing.getInstructionAt(cu.getMinAddress()) is not None:
                has_insn = True
            if cu is not None:
                if cu.getMinAddress().compareTo(a_start) < 0:
                    a_start = cu.getMinAddress()
                if cu.getMaxAddress().compareTo(a_end) > 0:
                    a_end = cu.getMaxAddress()
        if has_insn and (a_start.compareTo(addr) != 0 or a_end.compareTo(end) != 0) and not force:
            raise WorkerError("boundary", f"the patch {addr}-{end} cuts an instruction "
                              f"(code covers {a_start}-{a_end})")
        cleared = None
        if has_insn:
            listing.clearCodeUnits(a_start, a_end, False)
            cleared = [S.addr_int(a_start), S.addr_int(a_end)]
        mem.setBytes(addr, _jbytes(data))
        count = 0
        if has_insn:
            restricted = AddressSet(a_start, a_end)
            cur, ok = a_start, True
            while cur is not None and cur.compareTo(a_end) <= 0:
                ins = listing.getInstructionAt(cur)
                if ins is None:
                    DisassembleCommand(cur, restricted, True).applyTo(program, TaskMonitor.DUMMY)
                    ins = listing.getInstructionAt(cur)
                if ins is None:
                    ok = False
                    break
                count += 1
                cur = ins.getMaxAddress().next()
            if not force:   # the new instructions must tile the old range exactly
                last = listing.getInstructionContaining(a_end)
                if not ok or last is None or last.getMaxAddress().compareTo(a_end) != 0:
                    raise WorkerError("boundary", f"the new bytes do not decode to whole instructions "
                                      f"over {a_start}-{a_end}")
        fns = []
        fit = program.getFunctionManager().getFunctions(AddressSet(a_start, a_end), True)
        while fit.hasNext():
            fns.append(S.addr_int(fit.next().getEntryPoint()))
        fc = program.getFunctionManager().getFunctionContaining(addr)
        if fc is not None and S.addr_int(fc.getEntryPoint()) not in fns:
            fns.append(S.addr_int(fc.getEntryPoint()))
        return {"address": S.addr_int(addr), "length": n, "old": old.hex(), "new": data.hex(),
                "cleared": cleared, "instructions": count, "functions": sorted(fns)}
    return _write(args, "patch bytes", body)
