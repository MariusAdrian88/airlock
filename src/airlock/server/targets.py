"""Typed target resolution shared by the tools (DESIGN.md section 7.3). Server side, no Ghidra.

``resolve_target`` turns the text an agent passes (``ReadFile``, ``KERNEL32!ReadFile``,
``bin!Foo``, ``0x00401000``, ``"quoted text"``, a feature key, a cluster id) into a typed target
or a one-line error. Each tool names the kinds it accepts; everything else gets the same
``error bad_target`` wording. The ``path`` tool keeps its own graph-based resolver
(``graph.resolve_endpoint``) with the same import name rules (``norm_import``, A/W variants).
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Iterable

from airlock.index.store import CODE_EDGES, Function, StringHit, Xref
from airlock.server.context import ServerContext
from airlock.server.graph import dll_stem, norm_import
from airlock.server.selectors import MAX_CANDIDATES, parse_address, resolve_function
from airlock.server.tools.common import Bound, Scope, bind_scope

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_CLUSTER_ID = re.compile(r"^(?:[cm]\d+|util)$", re.I)
MAX_STRING_HITS = 200

# kinds a tool accepts
FUNCTION = "function"        # a function, or an address inside one
ADDRESS = "address"          # a raw address that is no function (xrefs)
IMPORT = "import"            # an import, as ImportTarget
IMPORT_FN = "import_fn"      # an import, converted to its function (library, thunk, external row)
STRING = "string"
FEATURE = "feature"
CLUSTER = "cluster"

_KIND_WORDS = {FUNCTION: "a function name or address", IMPORT: "an import", IMPORT_FN: "an import",
               ADDRESS: "an address", STRING: "a string", FEATURE: "a feature key",
               CLUSTER: "a cluster id"}


# -- typed targets -----------------------------------------------------------------------------

@dataclass(frozen=True)
class FunctionTarget:
    bound: Bound
    fn: Function
    note: str | None = None          # "resolved from interior address ..."
    binary_note: str | None = None   # "binary x.dll" when the search over all binaries found it

    @property
    def any_note(self) -> str | None:
        return self.note or self.binary_note


@dataclass(frozen=True)
class AddressTarget:
    """An address that starts no function (a string, a data slot, an import slot)."""

    bound: Bound
    space: str
    value: int
    binary_note: str | None = None


@dataclass(frozen=True)
class ImportBinding:
    """How one binary reaches the import: slots (IAT addresses), thunk functions, EXTERNAL rows."""

    bound: Bound
    slots: tuple[int, ...]
    thunks: tuple[Function, ...]
    externals: tuple[Function, ...]


@dataclass(frozen=True)
class ImportTarget:
    label: str                                       # KERNEL32!ReadFile
    name: str
    bindings: tuple[ImportBinding, ...]
    library: tuple[tuple[Bound, Function], ...] = ()  # statically linked implementations
    binary_note: str | None = None
    explicit: bool = True                            # the binary was named (or is the only one)

    @property
    def nbinaries(self) -> int:
        return len({b.bound.binary.id for b in self.bindings} | {bd.binary.id for bd, _ in self.library})

    @property
    def multi(self) -> bool:
        return self.nbinaries > 1

    @property
    def stubs(self) -> list[tuple[Bound, Function]]:
        return [(b.bound, f) for b in self.bindings for f in (*b.thunks, *b.externals)]


@dataclass(frozen=True)
class StringTarget:
    matches: tuple[tuple[Bound, StringHit], ...]
    how: str                                         # exact or substring


@dataclass(frozen=True)
class FeatureTarget:
    key: str
    row: sqlite3.Row


@dataclass(frozen=True)
class ClusterTarget:
    id: str
    cluster: object


Target = FunctionTarget | AddressTarget | ImportTarget | StringTarget | FeatureTarget | ClusterTarget


# -- errors (one wording for every tool) ---------------------------------------------------------

def err(code: str, what: str, nxt: str) -> str:
    return f"error {code}: {what}. {nxt}."


def _where(sc: Scope) -> str:
    if sc.explicit:
        return ""
    extra = f" ({sc.skipped} not ready)" if sc.skipped else ""
    return f" in {len(sc.bounds)} ready binaries{extra}"


def not_found(sc: Scope, text: str) -> str:
    return err("not_found", f"no function or import named '{text}'{_where(sc)}",
               "Use search to find the name, or pass an address like 0x00401000 (binary!0x... "
               "to pick a binary)")


def ambiguous(text: str, listed: list[str], total: int) -> str:
    shown = listed[:MAX_CANDIDATES]
    more = f" (+{total - len(shown)} more)" if total > len(shown) else ""
    return err("ambiguous", f"'{text}' matches {total} functions: {', '.join(shown)}{more}",
               "Retry with binary!name or binary!address")


def wrong_kind(text: str, got: str, accepted: Iterable[str], nxt: str) -> str:
    words = sorted({_KIND_WORDS[k] for k in accepted if k in _KIND_WORDS})
    return err("bad_target", f"'{text}' is {got}, but this tool takes {' or '.join(words)}", nxt)


def _cand(bd: Bound, fn: Function) -> str:
    return f"{bd.binary.name}!{fn.qualified_name} {bd.addr(fn.entry, fn.space)}"


# -- imports -------------------------------------------------------------------------------------

@dataclass(frozen=True)
class _Cand:
    stem: str
    name: str
    norm: str
    address: int | None


def _candidates(bd: Bound) -> list[_Cand]:
    """Every import row and EXTERNAL function row of the binary, by name."""
    st, bid = bd.store, bd.binary.id
    out: list[_Cand] = []
    for r in st.db.execute("SELECT dll, name, address FROM import WHERE binary_id=? AND name IS NOT NULL",
                           (bid,)):
        n = norm_import(r["name"])
        if n:
            out.append(_Cand(dll_stem(r["dll"]), r["name"], n, r["address"]))
    for r in st.db.execute("SELECT name, namespace FROM function WHERE binary_id=? AND is_external=1",
                           (bid,)):
        n = norm_import(r["name"])
        if n:
            out.append(_Cand(dll_stem(r["namespace"]), r["name"], n, None))
    return out


def _variants(name: str, wide: bool) -> list[str]:
    base = norm_import(name)
    if not base:
        return []
    if not wide:
        return [base]
    out = [base, base + "a", base + "w"]
    if len(base) > 3 and base[-1] in "aw":
        root = base[:-1]
        out += [root, root + "a", root + "w"]
    return out


def _match(cands: dict[int, list[_Cand]], name: str, stem: str, wide: bool) -> dict[int, list[_Cand]]:
    """Per binary id, the import candidates for ``[DLL!]name``: the exact name, else (``wide``)
    the A/W forms together (``CreateFile`` -> ``CreateFileA`` and ``CreateFileW``)."""
    vs = _variants(name, wide)

    def pick(want: list[str]) -> dict[int, list[_Cand]]:
        hit = {bid: [c for c in cs if c.norm in want and (not stem or c.stem in (stem, ""))]
               for bid, cs in cands.items()}
        return {bid: cs for bid, cs in hit.items() if cs}

    return (pick(vs[:1]) or pick(vs[1:])) if vs else {}   # exact first, else all A/W forms together


def _label(hits: dict[int, list[_Cand]]) -> tuple[str, str]:
    keys = sorted({(c.stem, c.name) for cs in hits.values() for c in cs})
    text = ", ".join(f"{s}!{n}" if s else n for s, n in keys[:3]) + (
        f" +{len(keys) - 3}" if len(keys) > 3 else "")
    return text, keys[0][1]


def _binding(bd: Bound, hits: list[_Cand]) -> ImportBinding:
    st, bid = bd.store, bd.binary.id
    names = sorted({c.name for c in hits})
    slots = tuple(sorted({c.address for c in hits if c.address is not None}))
    seen: set[int] = set()
    thunks: list[Function] = []
    exts: list[Function] = []
    for n in names:
        for f in st.functions_by_name(bid, n):
            if f.id in seen:
                continue
            seen.add(f.id)
            if f.is_external:
                exts.append(f)
            elif f.is_thunk:
                thunks.append(f)
    return ImportBinding(bd, slots, tuple(thunks), tuple(exts))


def _import_target(sc: Scope, hits: dict[int, list[_Cand]]) -> ImportTarget:
    label, name = _label(hits)
    names = {c.name for cs in hits.values() for c in cs}
    bindings = tuple(_binding(bd, hits[bd.binary.id]) for bd in sc.bounds if bd.binary.id in hits)
    lib: list[tuple[Bound, Function]] = []
    for bd in sc.bounds:
        for n in sorted(names):
            lib += [(bd, f) for f in bd.store.functions_by_name(bd.binary.id, n)
                    if not f.is_external and not f.is_thunk]
    note = f"binary {bindings[0].bound.binary.name}" if len(bindings) == 1 and not sc.explicit else None
    return ImportTarget(label, name, bindings, tuple(lib), note, sc.explicit)


def _stub_cand(b: ImportBinding, label: str) -> str:
    bd = b.bound
    if b.thunks:
        return _cand(bd, b.thunks[0])
    if b.externals:
        return _cand(bd, b.externals[0])
    if b.slots:
        return f"{bd.binary.name}!{label} {bd.addr(b.slots[0])}"
    return f"{bd.binary.name}!{label}"


def function_of_import(t: ImportTarget) -> FunctionTarget | str:
    """The function a tool that needs code can use for an import: the statically linked library
    function, else the one thunk, else the one EXTERNAL row (the caller reports it as having no
    code). Several of the same rank are ambiguous; an import row alone has no function."""
    for rank in (list(t.library), [(b.bound, f) for b in t.bindings for f in b.thunks],
                 [(b.bound, f) for b in t.bindings for f in b.externals]):
        if len(rank) == 1:
            bd, fn = rank[0]
            return FunctionTarget(bd, fn, None,
                                  t.binary_note or (None if t.explicit else f"binary {bd.binary.name}"))
        if rank:
            return ambiguous(t.label, [_cand(bd, f) for bd, f in rank], len(rank))
    return err("external", f"{t.label} is an imported function with no code",
               "Use xrefs on it to see its callers")


def import_refs(t: ImportTarget, kinds: tuple[str, ...] | None, limit: int) -> list[tuple[Bound, Xref]]:
    """References to the import in every binary that has it, merged: through its slots, to its
    thunks (their own jump to the slot is not a reference) and to library implementations."""
    out: list[tuple[Bound, Xref]] = []
    seen: set[tuple[int, int, int, str]] = set()

    def add(bd: Bound, xs: list[Xref], skip: set[int]) -> None:
        for x in xs:
            if x.src_fn is not None and x.src_fn.id in skip:
                continue
            key = (bd.binary.id, x.src_addr, x.dst_addr, x.kind)
            if key not in seen:
                seen.add(key)
                out.append((bd, x))

    for b in t.bindings:
        st, bid = b.bound.store, b.bound.binary.id
        skip = {f.id for f in b.thunks}
        for a in b.slots:
            add(b.bound, st.xrefs_to_address(bid, a, kinds, limit), skip)
        for f in b.thunks:
            add(b.bound, st.xrefs_to_function(f, kinds, limit), skip)
    for bd, f in t.library:
        add(bd, bd.store.xrefs_to_function(f, kinds, limit), set())
    order = {b.bound.binary.id: i for i, b in enumerate(t.bindings)}
    out.sort(key=lambda p: (order.get(p[0].binary.id, len(order)), p[0].binary.id, p[1].src_addr))
    return out


def import_callers(t: ImportTarget, limit: int) -> list[tuple[Bound, Function]]:
    """Distinct functions that call the import (through a slot, a thunk or a library copy)."""
    out: list[tuple[Bound, Function]] = []
    seen: set[int] = set()
    for bd, x in import_refs(t, CODE_EDGES, limit):
        f = x.src_fn
        if f is not None and f.id not in seen:
            seen.add(f.id)
            out.append((bd, f))
    return out


# -- resolution ----------------------------------------------------------------------------------

def resolve_target(ctx: ServerContext, binary: str, target: str, kinds: Iterable[str]) -> Target | str:
    """Resolve ``target`` to a typed target the tool accepts, or return a one-line error.

    ``binary`` and a ``binary!`` prefix narrow the lookup; otherwise a project with several ready
    binaries searches all of them (DESIGN 7.3 rule 6)."""
    ks = frozenset(kinds)
    sc = bind_scope(ctx, binary, target)
    if isinstance(sc, str):
        return sc
    t = sc.bare
    if not t:
        return err("bad_target", "empty target", "Pass a function name or an address like 0x00401000")
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
        if STRING not in ks:
            return wrong_kind(t, "a quoted string", ks, "Pass a name or an address")
        return _strings(sc, t[1:-1]) or err(
            "not_found", f"no string matching {t}{_where(sc)}", "Use strings(pattern) to find it")
    if parse_address(t) is not None:
        return _by_address(sc, t, ks)
    cands = {bd.binary.id: _candidates(bd) for bd in sc.bounds}
    for name, stem in _attempts(t, cands):
        r = _by_name(sc, name, stem, cands, ks)
        if r is not None:
            return _policy(sc, r, t, ks)
    if _HEX.match(t):
        return _by_address(sc, t, ks)
    if FEATURE in ks:
        try:
            feat = sc.store.get_feature(t.lower())
        except Exception:  # noqa: BLE001  no feature tables
            feat = None
        if feat is not None:
            return FeatureTarget(t.lower(), feat)
    if CLUSTER in ks and _CLUSTER_ID.match(t):
        from airlock.server import clusters as cl   # late: clusters imports graph
        c = cl.get_clusters(ctx, sc.project).get(t)
        if c is not None:
            return ClusterTarget(c.id, c)
    if STRING in ks:
        s = _strings(sc, t)
        if s:
            return s
    return not_found(sc, t)


def _attempts(t: str, cands: dict[int, list[_Cand]]) -> list[tuple[str, str]]:
    """(name, dll stem) readings of the text, most specific first: ``DLL!name`` and
    ``DLL::name`` when the DLL is one the project imports from, then the whole text as a name."""
    stems = {c.stem for cs in cands.values() for c in cs if c.stem}
    out: list[tuple[str, str]] = []
    left, sep, right = t.partition("!")
    if sep and left.strip() and right.strip() and dll_stem(left.strip()) in stems:
        out.append((right.strip(), dll_stem(left.strip())))
    left, sep, right = t.rpartition("::")
    if sep and left.strip() and right.strip() and dll_stem(left.strip()) in stems:
        out.append((right.strip(), dll_stem(left.strip())))
    out.append((t, ""))
    return out


def _by_name(sc: Scope, name: str, stem: str, cands: dict[int, list[_Cand]],
             ks: frozenset[str]) -> Target | str | None:
    """Function(s) and/or import for a name. None when nothing matches."""
    hits = _match(cands, name, stem, wide=False)
    fcands: list[tuple[Bound, Function]] = []
    if not stem:
        for bd in sc.bounds:
            bid = bd.binary.id
            for f in bd.store.functions_by_name(bid, name):
                if f.is_external or (f.is_thunk and bid in hits):
                    continue                              # stubs of an import belong to the import
                fcands.append((bd, f))
        if not fcands and not hits:
            hits = _match(cands, name, stem, wide=True)   # ReadFile -> ReadFileW / ReadFileA
    if len(sc.bounds) == 1:
        bd = sc.bounds[0]
        if fcands:
            return _single(bd, name)
        return _import_target(sc, hits) if hits else None
    if fcands and not hits:
        if len(fcands) == 1:
            bd, f = fcands[0]
            return FunctionTarget(bd, f, None, f"binary {bd.binary.name}")
        return ambiguous(name, [_cand(bd, f) for bd, f in fcands], len(fcands))
    if not fcands and hits:
        return _import_target(sc, hits)
    if fcands:
        imp = _import_target(sc, hits)
        listed = [_cand(bd, f) for bd, f in fcands] + [_stub_cand(b, imp.label) for b in imp.bindings]
        return ambiguous(name, listed, len(listed))
    return None


def _single(bd: Bound, name: str) -> Target | str:
    r = resolve_function(bd.store, bd.binary.id, name)
    return FunctionTarget(bd, r.function, r.note) if r.function is not None else (r.error or "")


def _policy(sc: Scope, r: Target | str, text: str, ks: frozenset[str]) -> Target | str:
    """Apply what the tool accepts to an import result."""
    if not isinstance(r, ImportTarget):
        return r
    if IMPORT in ks:
        return r
    if IMPORT_FN in ks:
        return function_of_import(r)
    return wrong_kind(text, f"an import ({r.label}) with no code of its own", ks,
                      "Use xrefs on it, or pass a function that calls it")


def _by_address(sc: Scope, raw: str, ks: frozenset[str]) -> Target | str:
    """An explicit address (``0x...``, ``SPACE:0x...``) or a bare hex string."""
    parsed = parse_address(raw)
    space, value = parsed if parsed is not None else ("ram", int(raw, 16))
    if len(sc.bounds) == 1:
        bd = sc.bounds[0]
        st, bid = bd.store, bd.binary.id
        fn = st.function_at(bid, value, space)
        if fn is not None:
            return FunctionTarget(bd, fn)
        if ADDRESS in ks:
            has_refs = st.xrefs_to_address(bid, value, None, 1) or st.xrefs_from_address(bid, value, None, 1)
            if not has_refs:   # nothing at the address itself: an interior address means its function
                r = resolve_function(st, bid, raw if parsed is not None else f"0x{value:x}")
                if r.function is not None:
                    return FunctionTarget(bd, r.function, r.note)
            return AddressTarget(bd, space, value)
        r = resolve_function(st, bid, raw if parsed is not None else f"0x{value:x}")
        return FunctionTarget(bd, r.function, r.note) if r.function is not None else (r.error or "")
    found: list[tuple[Bound, Function, str | None]] = []
    for bd in sc.bounds:
        r = resolve_function(bd.store, bd.binary.id, f"{space}:0x{value:x}" if space != "ram" else f"0x{value:x}")
        if r.function is not None:
            found.append((bd, r.function, r.note))
    if len(found) == 1:
        bd, f, note = found[0]
        return FunctionTarget(bd, f, note, f"binary {bd.binary.name}")
    if found:
        return ambiguous(raw, [_cand(bd, f) for bd, f, _n in found], len(found))
    return err("not_found", f"no function at or containing {raw}{_where(sc)}",
               "Check the address, or pass binary!0xaddress")


def _strings(sc: Scope, text: str) -> StringTarget | None:
    like_exact = text
    esc = "".join("\\" + c if c in "%_\\" else c for c in text)
    for how, sql, arg in (("exact", "value=?", like_exact),
                          ("substring", "value LIKE ? ESCAPE '\\'", f"%{esc}%")):
        out: list[tuple[Bound, StringHit]] = []
        for bd in sc.bounds:
            for r in bd.store.db.execute(
                    f"SELECT id, address, encoding, value FROM string WHERE binary_id=? AND {sql} "
                    "ORDER BY address LIMIT ?", (bd.binary.id, arg, MAX_STRING_HITS)):
                out.append((bd, StringHit(r["id"], r["address"], r["encoding"], r["value"])))
        if out:
            return StringTarget(tuple(out[:MAX_STRING_HITS]), how)
    return None
