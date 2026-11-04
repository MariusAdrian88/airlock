"""extract op: the cheap full pass, in batches, shaped for the DESIGN.md section 4 tables.

Result: {"kind", "columns": [...], "rows": [[...], ...], "offset", "next_offset" | null,
         "done", "image_base", "pointer_size"}
Rows are lists in `columns` order, so the server can `executemany` them as they are.
Addresses are ints (Address.getOffset()); the space name is a separate column.
"""

from __future__ import annotations

import collections
import itertools
import re
from typing import Any, Callable, Iterator

from airlock.worker.main import op
from airlock.worker.protocol import WorkerError

from . import session as S
from .session import Entry, guarded

DEFAULT_LIMIT = 2000
MAX_LIMIT = 20000
MAX_STRING_CHARS = 4096

# SourceType name -> function.name_state. "source" (raw) is also returned for finer decisions.
NAME_STATE = {"DEFAULT": "auto", "ANALYSIS": "auto", "AI": "auto",
              "IMPORTED": "library", "USER_DEFINED": "user"}

FUNCTION_COLUMNS = ["space", "entry", "name", "name_state", "source", "namespace", "signature",
                    "calling_conv", "size", "is_thunk", "is_external"]
IMPORT_COLUMNS = ["dll", "name", "ordinal", "space", "address"]
STRING_COLUMNS = ["space", "address", "encoding", "length", "value"]
EDGE_COLUMNS = ["src_addr", "src_fn", "dst_space", "dst_addr", "dst_fn", "kind"]


class Cursor:
    """A resumable iterator with one item of lookahead."""

    def __init__(self, it: Iterator[list[Any]], pos: int):
        self.it, self.pos = it, pos
        self._buf: list[list[Any]] = []

    def take(self, n: int) -> list[list[Any]]:
        rows = []
        while len(rows) < n:
            if self._buf:
                rows.append(self._buf.pop())
                continue
            nxt = next(self.it, None)
            if nxt is None:
                break
            rows.append(nxt)
        self.pos += len(rows)
        return rows

    def exhausted(self) -> bool:
        if self._buf:
            return False
        nxt = next(self.it, None)
        if nxt is None:
            return True
        self._buf.append(nxt)
        return False


# ── functions ──────────────────────────────────────────────────────────────

def _functions(p: Any) -> Iterator[list[Any]]:
    fm = p.getFunctionManager()
    for f in itertools.chain(fm.getFunctions(True), fm.getExternalFunctions()):
        entry = f.getEntryPoint()
        src = str(f.getSymbol().getSource().name())
        ns = f.getParentNamespace()
        yield [
            S.space_of(entry), S.addr_int(entry), str(f.getName()),
            NAME_STATE.get(src, "auto"), src,
            None if ns.isGlobal() else str(ns.getName(True)),
            str(f.getPrototypeString(False, False)),
            str(f.getCallingConventionName()),
            int(f.getBody().getNumAddresses()),
            1 if f.isThunk() else 0,
            1 if f.isExternal() else 0,
        ]


# ── imports ────────────────────────────────────────────────────────────────

_ORDINAL = re.compile(r"^Ordinal_(\d+)$")


def _imports(p: Any) -> Iterator[list[Any]]:
    em = p.getExternalManager()
    rm = p.getReferenceManager()
    for lib in sorted(str(n) for n in em.getExternalLibraryNames()):
        locs = em.getExternalLocations(lib)
        while locs.hasNext():
            loc = locs.next()
            name = str(loc.getLabel())
            m = _ORDINAL.match(name)
            ordinal = int(m.group(1)) if m else None
            slot = None  # IAT slot: the first data reference to the external symbol
            ext_addr = loc.getExternalSpaceAddress()
            if ext_addr is not None:
                refs = rm.getReferencesTo(ext_addr)
                for r in refs:
                    slot = r.getFromAddress()
                    break
            if slot is None:
                fn = loc.getFunction()
                if fn is not None:
                    for a in fn.getFunctionThunkAddresses(True) or []:
                        slot = a
                        break
            yield [lib, name, ordinal,
                   S.space_of(slot) if slot is not None else None,
                   S.addr_int(slot) if slot is not None else None]


# ── strings ────────────────────────────────────────────────────────────────

def _encoding(dt_name: str) -> str:
    n = dt_name.lower()
    if "utf8" in n or "utf-8" in n:
        return "utf8"
    if "wchar32" in n or "utf32" in n:
        return "utf32le"
    if "unicode" in n or "wchar" in n or "utf16" in n or "utf-16" in n:
        return "utf16le"
    return "ascii"


def _strings(p: Any) -> Iterator[list[Any]]:
    # Iterator.hasNext/next are consumed by Python through JPype's Iterator support.
    from ghidra.program.model.data import StringDataInstance  # type: ignore
    from ghidra.program.util import DefinedDataIterator  # type: ignore

    for d in DefinedDataIterator.byDataInstance(p, lambda d: StringDataInstance.isString(d)):
        sdi = StringDataInstance.getStringDataInstance(d)
        value = sdi.getStringValue() if sdi is not None else None
        if value is None:
            v = d.getValue()
            value = str(v) if v is not None else None
        if not value:
            continue
        value = str(value)
        a = d.getAddress()
        yield [S.space_of(a), S.addr_int(a), _encoding(str(d.getDataType().getName())),
               len(value), value[:MAX_STRING_CHARS]]


# ── references -> edges ────────────────────────────────────────────────────

def _edge_kinds(rt: Any) -> list[str]:
    """RefType -> edge.kind values (READ_WRITE gives two). Flow-through is not an edge."""
    if rt.isCall():
        return ["call_ind" if (rt.isComputed() or rt.isIndirect()) else "call"]
    if rt.isFallthrough():
        return []
    if rt.isJump():
        return ["jump"]
    kinds = []
    if rt.isRead():
        kinds.append("read")
    if rt.isWrite():
        kinds.append("write")
    if kinds:
        return kinds
    if rt.isData():
        return ["data"]
    return []


def _edges(p: Any) -> Iterator[list[Any]]:
    rm = p.getReferenceManager()
    fm = p.getFunctionManager()
    memory = p.getMemory()

    def fn_entry(addr: Any) -> int | None:
        f = fm.getFunctionContaining(addr)
        return S.addr_int(f.getEntryPoint()) if f is not None else None

    it = rm.getReferenceSourceIterator(memory, True)
    while it.hasNext():
        src = it.next()
        src_off = S.addr_int(src)
        src_fn = fn_entry(src)
        for r in rm.getReferencesFrom(src):
            if not (r.isMemoryReference() or r.isExternalReference()):
                continue  # stack and register references are not edges
            kinds = _edge_kinds(r.getReferenceType())
            if not kinds:
                continue
            dst = r.getToAddress()
            dst_fn = None if r.isExternalReference() else fn_entry(dst)
            for k in kinds:
                yield [src_off, src_fn, S.space_of(dst), S.addr_int(dst), dst_fn, k]


KINDS: dict[str, tuple[list[str], Callable[[Any], Iterator[list[Any]]]]] = {
    "functions": (FUNCTION_COLUMNS, _functions),
    "imports": (IMPORT_COLUMNS, _imports),
    "strings": (STRING_COLUMNS, _strings),
    "edges": (EDGE_COLUMNS, _edges),
}


def _cursor_for(e: Entry, kind: str, offset: int) -> Cursor:
    cur: Cursor | None = e.cursors.get(kind)
    if cur is not None and cur.pos == offset:
        return cur
    it = KINDS[kind][1](e.program)
    if offset:
        collections.deque(itertools.islice(it, offset), maxlen=0)  # skip `offset` rows
    cur = Cursor(it, offset)
    e.cursors[kind] = cur
    return cur


@op("extract")
@guarded
def extract(args: dict[str, Any]) -> dict[str, Any]:
    """extract(program, kind, offset=0, limit=2000): one batch of rows of
    kind functions | imports | strings | edges."""
    e = S.ready_entry(args.get("program"))
    kind = args.get("kind")
    if kind not in KINDS:
        raise WorkerError("bad_args", f"kind must be one of {', '.join(KINDS)}")
    try:
        offset = max(0, int(args.get("offset") or 0))
        limit = min(MAX_LIMIT, max(1, int(args.get("limit") or DEFAULT_LIMIT)))
    except (TypeError, ValueError) as ex:
        raise WorkerError("bad_args", f"offset/limit must be integers ({ex})") from ex
    with e.lock:
        cur = _cursor_for(e, kind, offset)
        rows = cur.take(limit)
        done = cur.exhausted()
        if done:
            e.cursors.pop(kind, None)
        p = e.program
        return {
            "kind": kind,
            "columns": KINDS[kind][0],
            "rows": rows,
            "offset": offset,
            "next_offset": None if done else offset + len(rows),
            "done": done,
            "image_base": S.addr_int(p.getImageBase()),
            "pointer_size": int(p.getDefaultPointerSize()),
        }
