"""Typed target resolution shared by the tools (DESIGN.md section 7.3). Server side, no Ghidra.

``resolve_target`` turns the text an agent passes (``ReadFile``, ``KERNEL32!ReadFile``,
``bin!Foo``, ``0x00401000``, ``"quoted text"``, a feature key, a cluster id) into a typed target
or a one-line error. Each tool names the kinds it accepts; everything else gets the same
``error bad_target`` wording. ``path`` uses it too (``endpoints.py`` turns the result into graph
nodes) with ``aggregate=True``, so a name that matches several functions is one multi-target
endpoint instead of ``error ambiguous`` (DESIGN 7.3 rule 8).
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, replace
from typing import Iterable

from airlock.index.store import CODE_EDGES, Function, StringHit, Xref
from airlock.server import classfwd
from airlock.server.context import ServerContext
from airlock.server import dotnet_meta
from airlock.server.graph import dll_stem, norm_import
from airlock.server.selectors import (alias_functions, default_name_address, MAX_CANDIDATES, MAX_CLOSE,
                                      close_functions, close_text, parse_address, resolve_function,
                                      by_selector, describe, fmt_addr, is_managed, managed_named, managed_overloads, parse_selector, prefer_token)
from airlock.server.tools.common import Bound, Scope, bind_scope, preview

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
    keys: tuple[tuple[str, str], ...] = ()           # (dll stem, import name) of every matched import

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
class MultiFunctionTarget:
    """Aggregate result (``aggregate=True``, the ``path`` tool): every function of that name, and
    the import of that name when one exists."""

    functions: tuple[tuple[Bound, Function], ...]
    imports: ImportTarget | None = None


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


Target = (FunctionTarget | AddressTarget | ImportTarget | MultiFunctionTarget | StringTarget
          | FeatureTarget | ClusterTarget)


# -- errors (one wording for every tool) ---------------------------------------------------------

def err(code: str, what: str, nxt: str = "") -> str:
    """``error code: what.`` plus the next step only when it is data the agent needs (candidates)
    or a fix only the user can make."""
    return f"error {code}: {what}." + (f" {nxt}." if nxt else "")


def _where(sc: Scope) -> str:
    if sc.explicit:
        return ""
    extra = f" ({sc.skipped} not ready)" if sc.skipped else ""
    return f" in {len(sc.bounds)} ready binaries{extra}"


def close_matches(sc: Scope, text: str) -> tuple[list[tuple[Bound, Function]], bool]:
    """Functions named like ``text`` in the scope: the names equal to it ignoring case when there
    are any (exact=True), else names containing its last segment."""
    exact_hits: list[tuple[Bound, Function]] = []
    near: list[tuple[Bound, Function]] = []
    for bd in sc.bounds:
        fns, exact = close_functions(bd.store, bd.binary.id, text)
        (exact_hits if exact else near).extend((bd, f) for f in fns)
    return (exact_hits, True) if exact_hits else (near, False)


def not_found(sc: Scope, text: str, close: list[tuple[Bound, Function]] | None = None) -> str:
    close = close or []
    names = [f"{'' if sc.explicit else bd.binary.name + '!'}{f.qualified_name} {bd.addr(f.entry, f.space)}"
             for bd, f in close[:MAX_CLOSE]]
    return err("not_found", f"no function or import named '{text}'{_where(sc)}",
               close_text(names, len(close) > MAX_CLOSE))


def ambiguous(text: str, listed: list[str], total: int) -> str:
    shown = listed[:MAX_CANDIDATES]
    more = f" (+{total - len(shown)} more)" if total > len(shown) else ""
    return err("ambiguous", f"'{text}' matches {total} functions: {', '.join(shown)}{more}")


def wrong_kind(text: str, got: str, accepted: Iterable[str], nxt: str = "") -> str:
    words = sorted({_KIND_WORDS[k] for k in accepted if k in _KIND_WORDS})
    return err("bad_target", f"'{text}' is {got}, but this tool takes {' or '.join(words)}", nxt)


def _cand(bd: Bound, fn: Function) -> str:
    return f"{bd.binary.name}!{fn.qualified_name} {bd.addr(fn.entry, fn.space)}"


def _cands(pairs: list[tuple[Bound, Function]]) -> list[str]:
    """Candidates as ready-to-use ``binary!name 0xaddr`` forms. A name that repeats inside one
    binary (overloads) is not a selector there, so that candidate is ``binary!0xaddr name``; managed
    overloads show ``binary!0xtoken Name(sig)`` (a ``Type::Name(params)`` selector picks one)."""
    seen: dict[tuple[int, str], int] = {}
    for bd, f in pairs:
        k = (bd.binary.id, f.qualified_name)
        seen[k] = seen.get(k, 0) + 1
    out = []
    for bd, f in pairs:
        if is_managed(f):
            out.append(f"{bd.binary.name}!" + describe([f], bd.binary.pointer_size, True)[0])
        elif seen[(bd.binary.id, f.qualified_name)] == 1:
            out.append(_cand(bd, f))
        else:
            out.append(f"{bd.binary.name}!{bd.addr(f.entry, f.space)} {f.qualified_name}")
    return out


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
    keys = tuple(sorted({(c.stem, c.name) for cs in hits.values() for c in cs}))
    return ImportTarget(label, name, bindings, tuple(lib), note, sc.explicit, keys)


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
            return ambiguous(t.label, _cands(rank), len(rank))
    return err("external", f"{t.label} is an imported function with no code")


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

def resolve_target(ctx: ServerContext, binary: str, target: str, kinds: Iterable[str],
                   aggregate: bool = False, create: bool = True) -> Target | str:
    """Resolve ``target`` (see ``_resolve``), then apply the session focus (DESIGN 7.3 rule 9):
    a name that is ``error ambiguous`` across the binaries of a project resolves in the binary
    the session looked at last when that binary has exactly one such function, and a function
    resolved in a multi-binary project becomes the new focus."""
    r = _il_forward(ctx, _resolve(ctx, binary, target, kinds, aggregate))
    if isinstance(r, str):
        if r.startswith("error ambiguous"):
            fr = _focused(ctx, binary, target, kinds, aggregate)
            if fr is not None:
                return fr
        if create and r.startswith("error not_found: no function at or containing") and FUNCTION in kinds:
            made = _create_on_demand(ctx, binary, target)
            if isinstance(made, str):
                return made
            if made is not None:
                _set_focus(ctx, made.bound)
                return made
        return r
    if isinstance(r, FunctionTarget):
        _set_focus(ctx, r.bound)
    return r


_NATIVE_THUNK = re.compile(r"^native thunk (0x[0-9a-f]+(?:, 0x[0-9a-f]+)*)$")


def _il_forward(ctx: ServerContext, r: Target | str) -> Target | str:
    """Mixed-mode (C++/CLI) binaries: a Ghidra pseudo-function over the IL body of a managed method is that
    method (one fact line); a method token whose "native thunk" is such an IL body drops the wrong thunk line."""
    if not isinstance(r, FunctionTarget):
        return r
    bd, fn = r.bound, r.fn
    if bd.binary.toolchain != "dotnet" or bd.binary.format == "dotnet" or fn.is_external:
        return r
    try:
        art = ctx.indexer.paths(bd.project).artifacts / bd.binary.sha256
        ps = bd.binary.pointer_size
        if fn.space == "ram" and not is_managed(fn):
            tok = dotnet_meta.il_token_at(bd.store, bd.binary, art, fn.entry)
            f = bd.store.function_at(bd.binary.id, tok) if tok else None
            if f is not None:
                return FunctionTarget(bd, f, f"IL body of {f.qualified_name} ({fmt_addr(f.entry, ps)}) at "
                                      f"{fmt_addr(fn.entry, ps)}", r.binary_note)
        elif is_managed(fn) and r.note:
            m = _NATIVE_THUNK.match(r.note)
            if m:
                addrs = [int(a, 16) for a in m.group(1).split(", ")]
                if all(dotnet_meta.il_token_at(bd.store, bd.binary, art, a) == fn.entry for a in addrs):
                    return FunctionTarget(bd, fn, f"IL body of {fn.qualified_name} ({fmt_addr(fn.entry, ps)}) at "
                                          + ", ".join(fmt_addr(a, ps) for a in addrs), r.binary_note)
    except Exception:  # noqa: BLE001  the forward is an extra
        return r
    return r


def overload_set(ctx: ServerContext, binary: str, target: str) -> tuple[Bound, list[Function]] | None:
    """The managed overloads of one ``Type::Name`` that ``target`` leaves open, all in one binary; None when
    the candidates differ in type, name or binary (that stays ``error ambiguous``)."""
    sc = bind_scope(ctx, binary, target)
    if isinstance(sc, str):
        return None
    found: list[tuple[Bound, list[Function]]] = []
    for bd in sc.bounds:
        name, _p = parse_selector(sc.bare)
        if managed_named(bd.store, bd.binary.id, name):
            ov = managed_overloads(bd.store, bd.binary.id, sc.bare)
            if not ov:
                return None
            found.append((bd, ov))
    return (found[0][0], found[0][1]) if len(found) == 1 else None


def code_address(ctx: ServerContext, binary: str, target: str) -> tuple[Bound, int, Scope] | None:
    """(binary, address, scope) when ``target`` is an address (or a default name such as ``FUN_...``) in an
    executable block of exactly one binary of the scope; None otherwise."""
    from airlock.server.cpp import Image

    sc = bind_scope(ctx, binary, target)
    if isinstance(sc, str):
        return None
    pa = parse_address(sc.bare)
    if pa is not None:
        space, value = pa
    elif default_name_address(sc.bare) is not None:
        space, value = "ram", default_name_address(sc.bare)
    elif _HEX.match(sc.bare):
        space, value = "ram", int(sc.bare, 16)
    elif sc.bare.lower() in _PROGRAM_NAMES:       # ``main`` of a Free Pascal program that has no function there
        mains = {pm for bd in sc.bounds if (pm := _fpc_main_address(ctx, bd)) is not None}
        if len(mains) != 1:
            return None
        space, value = "ram", mains.pop()
    else:
        return None
    if space != "ram" or value is None:
        return None
    ix = ctx.indexer
    code: list[Bound] = []
    for bd in sc.bounds:
        art = ix.paths(bd.project).artifacts / bd.binary.sha256
        img = Image.from_pe(art) if art.is_file() else None
        if img is not None and img.is_code(value):
            code.append(bd)
    if len(code) != 1:
        return None
    return code[0], value, sc


HEADER_MAX = 12     # bytes of a Delphi string header (reference count, length, code page)


def _string_covering(bd: Bound, value: int) -> StringHit | None:
    """The indexed string that covers ``value`` (it starts there or earlier and runs past it)."""
    row = bd.store.db.execute("SELECT id FROM string WHERE binary_id=? AND address<=? ORDER BY address DESC LIMIT 1",
                              (bd.binary.id, value)).fetchone()
    s = bd.store.get_string(row[0]) if row else None
    if s is not None:
        size = len(s.value) * (2 if s.encoding.startswith("utf16") else 1) + 2
        if value < s.address + size:
            return s
    nxt = bd.store.db.execute("SELECT id FROM string WHERE binary_id=? AND address>? AND address<=? "
                              "ORDER BY address LIMIT 1", (bd.binary.id, value, value + HEADER_MAX)).fetchone()
    return bd.store.get_string(nxt[0]) if nxt else None       # the length / reference count header before a Delphi string


def _data_line(bd: Bound, value: int, what: str) -> str:
    """One error line for an address that holds data: what it is and who references it."""
    st, bid = bd.store, bd.binary.id
    refs = list(st.xrefs_to_address(bid, value, None, 3))
    who = ", ".join(f"{x.src_fn.qualified_name if x.src_fn else '-'} {bd.addr(x.src_addr)}" for x in refs)
    return (f"error not_found: no function at {bd.addr(value)}; it is {what}"
            + (f", referenced from {who}" if who else ", with no references"))


def _create_on_demand(ctx: ServerContext, binary: str, target: str) -> FunctionTarget | str | None:
    """An address in an executable block of one binary where Ghidra has no function (a Qt vtable slot, a handler
    no static table names): create the function with the worker op ``create_functions`` (the same op as the
    bulk pass), read back just that function and its edges and return it with a fact line. None when the session may not
    write (clean role, ``allow_writes`` off), the address is no code, or Ghidra refuses."""
    from airlock.server import roles

    if ctx.session.role == roles.CLEAN or not ctx.config.allow_writes:
        return None
    ca = code_address(ctx, binary, target)
    if ca is None:
        return None
    bd, value, sc = ca
    s = _string_covering(bd, value)
    if s is not None:      # Delphi keeps string literals in CODE: a string (or the middle of one) is no function
        return _data_line(bd, value, f"the string {preview(s.value, 40)}" if s.address == value
                          else f"inside or just before the string {preview(s.value, 40)} at {bd.addr(s.address)}")
    ix = ctx.indexer
    program = ix.program_of(bd.store, bd.binary)
    entry = value
    note = f"no Ghidra function at {bd.addr(value)}; created one from the code there"
    try:
        ix.ensure_open(bd.project)
        r = ctx.worker.request("create_functions", {"program": program, "addresses": [value]}, timeout=600)
        det = (r.get("data") or {}).get(hex(value))
        if det is not None:
            return _data_line(bd, value, f"data ({det})")
        if not r.get("created"):
            return None
        outer = (r.get("resolved") or {}).get(hex(value))
        if outer is not None:
            entry = int(outer, 16)
            note = (f"{bd.addr(value)} is inside the code that starts at {bd.addr(entry)}; no Ghidra function "
                    f"there, created one from that start")
        conv = r.get("conventions") or {}
        try:
            if sum(int(n) for n in conv.values()) > 1:   # the pass touched other functions: read them all
                raise ValueError("conventions changed")
            ix.extract_new_functions(bd.store, bd.binary, program, [entry])
        except Exception:  # noqa: BLE001  the whole binary is read instead
            ix.reextract_code(bd.store, bd.binary, program)
        ix.name_new_functions(bd.project, bd.store, bd.binary)
    except Exception:  # noqa: BLE001  the not_found line stands
        return None
    fn = bd.store.function_at(bd.binary.id, entry)
    if fn is None:
        return None
    return FunctionTarget(bd, fn, note, None if sc.explicit else f"binary {bd.binary.name}")


def _set_focus(ctx: ServerContext, bd: Bound) -> None:
    try:
        if len(bd.store.list_binaries()) > 1:
            ctx.focus[bd.project] = bd.binary.id
    except Exception:  # noqa: BLE001  focus is an extra
        pass


def _focused(ctx: ServerContext, binary: str, target: str, kinds: Iterable[str],
             aggregate: bool) -> FunctionTarget | None:
    """Retry an ambiguous, unqualified target in the focus binary; only a single function counts."""
    sc = bind_scope(ctx, binary, target)
    if isinstance(sc, str) or sc.explicit:
        return None
    fid = ctx.focus.get(sc.project)
    bd = next((b for b in sc.bounds if b.binary.id == fid), None)
    if bd is None:
        return None
    r = _resolve(ctx, bd.binary.name, sc.bare, kinds, aggregate)
    if not isinstance(r, FunctionTarget):
        return None
    return FunctionTarget(r.bound, r.fn, r.note, f"binary {bd.binary.name} (current binary)")


def _resolve(ctx: ServerContext, binary: str, target: str, kinds: Iterable[str],
             aggregate: bool = False) -> Target | str:
    """Resolve ``target`` to a typed target the tool accepts, or return a one-line error.

    ``binary`` and a ``binary!`` prefix narrow the lookup; otherwise a project with several ready
    binaries searches all of them (DESIGN 7.3 rule 6). ``aggregate`` (tools that list relations
    over several matches, i.e. ``path``) returns a MultiFunctionTarget for a name that matches
    several functions, or a function and an import, instead of ``error ambiguous``."""
    ks = frozenset(kinds)
    sc = bind_scope(ctx, binary, target)
    if isinstance(sc, str):
        return sc
    t = sc.bare
    if not t:
        return err("bad_target", "empty target")
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
        if STRING not in ks:
            return wrong_kind(t, "a quoted string", ks)
        return _strings(sc, t[1:-1]) or err("not_found", f"no string matching {t}{_where(sc)}")
    if parse_address(t) is not None:
        return _by_address(sc, t, ks)
    cands = {bd.binary.id: _candidates(bd) for bd in sc.bounds}
    for name, stem in _attempts(t, cands):
        r = _by_name(sc, name, stem, cands, aggregate, IMPORT in ks)
        if r is not None:
            return _policy(sc, r, t, ks)
    if FUNCTION in ks or IMPORT_FN in ks:
        ms = _managed_selector(sc, t)
        if ms is not None:
            return ms
    qa = _qt_method_addr(sc, t)
    if qa is not None:
        return _by_address(sc, f"0x{qa:x}", ks)
    if CLUSTER in ks and _CLUSTER_ID.match(t):
        from airlock.server import clusters as cl   # late: clusters imports graph
        c = cl.get_clusters(ctx, sc.project).get(t)
        if c is not None:
            return ClusterTarget(c.id, c)
    if _HEX.match(t):
        return _by_address(sc, t, ks)
    da = default_name_address(t)
    if da is not None:     # a name the decompiler prints for data or a label: the address is in it
        return _by_address(sc, f"0x{da:x}", ks)
    if FUNCTION in ks or IMPORT_FN in ks or ADDRESS in ks:
        mr = _bare_method(sc, t, ks)
        if mr is not None:
            return mr
    if (FUNCTION in ks or IMPORT_FN in ks) and t.lower() in _PROGRAM_NAMES:
        pr = _program_body(ctx, sc, t, ks)
        if pr is not None:
            return pr
    if FEATURE in ks:
        try:
            feat = sc.store.get_feature(t.lower())
        except Exception:  # noqa: BLE001  no feature tables
            feat = None
        if feat is not None:
            return FeatureTarget(t.lower(), feat)
    if STRING in ks:
        s = _strings(sc, t)
        if s:
            return s
    close, exact = close_matches(sc, t)
    if exact and len(close) == 1 and (FUNCTION in ks or IMPORT_FN in ks):   # only the case differs
        bd, f = close[0]
        return FunctionTarget(bd, f, f"resolved '{t}' to {f.qualified_name} (case differs)",
                              None if sc.explicit else f"binary {bd.binary.name}")
    if FUNCTION in ks or IMPORT_FN in ks:
        al = [(bd, f) for bd in sc.bounds for f in alias_functions(bd.store, bd.binary.id, t)]
        if len(al) == 1:       # a name hint a tool printed: rtti, IDR or signature name, `TClass::vslot N`
            bd, f = al[0]
            return FunctionTarget(bd, f, f"resolved '{t}' to {f.qualified_name} {bd.addr(f.entry, f.space)}",
                                  None if sc.explicit else f"binary {bd.binary.name}")
        if al:
            return ambiguous(t, _cands(al), len(al))
    return not_found(sc, t, close)


def _managed_selector(sc: Scope, text: str) -> Target | str | None:
    """``Type::Name(params)`` / ``Type.Name`` of a managed method: the overload the parameter types pick."""
    found: list[tuple[Bound, Function, str | None]] = []
    errors: list[str] = []
    for bd in sc.bounds:
        r = by_selector(bd.store, bd.binary.id, text, bd.binary.pointer_size)
        if r is None:
            continue
        if r.function is not None:
            found.append((bd, r.function, r.note))
        elif r.error:
            errors.append(r.error)
    if len(found) == 1:
        bd, f, note = found[0]
        return FunctionTarget(bd, f, note, None if sc.explicit else f"binary {bd.binary.name}")
    if found:
        return ambiguous(text, _cands([(bd, f) for bd, f, _n in found]), len(found))
    if len(errors) == 1:
        return errors[0]
    return None


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


def _binds_to(imp: ImportTarget, fcands: list[tuple[Bound, Function]]) -> list[tuple[Bound, Function]]:
    """The functions every binding of the import resolves to (xedge from its slots and thunks into
    a function of ``fcands``); empty when some binding does not bind to one of them."""
    want = {(bd.binary.id, f.entry): (bd, f) for bd, f in fcands}
    found: dict[tuple[int, int], tuple[Bound, Function]] = {}
    for b in imp.bindings:
        addrs = [*b.slots, *(f.entry for f in b.thunks)]
        if not addrs:
            return []
        marks = ",".join("?" * len(addrs))
        try:
            rows = b.bound.store.db.execute(
                f"SELECT dst_binary, dst_entry FROM xedge WHERE src_binary=? AND src_addr IN ({marks})",
                (b.bound.binary.id, *addrs)).fetchall()
        except sqlite3.Error:
            return []
        hit = [(r[0], r[1]) for r in rows if (r[0], r[1]) in want]
        if not hit:
            return []
        for k in hit:
            found[k] = want[k]
    return list(found.values())


def _by_name(sc: Scope, name: str, stem: str, cands: dict[int, list[_Cand]],
             aggregate: bool = False, prefer_def: bool = False) -> Target | str | None:
    """Function(s) and/or import for a name. None when nothing matches.

    DESIGN 7.3 rule 8: the single-target tools get exactly one function (several are
    ``error ambiguous``); a function in one binary and an import elsewhere is the function when the
    import binds to it (xedge), else ambiguous. ``aggregate`` keeps every match."""
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
    if aggregate and fcands and (len(fcands) > 1 or hits):
        return MultiFunctionTarget(tuple(fcands), _import_target(sc, hits) if hits else None)
    if len(sc.bounds) == 1:
        bd = sc.bounds[0]
        if fcands:
            return _single(bd, name)
        return _import_target(sc, hits) if hits else None
    if not fcands and hits:
        return _import_target(sc, hits)
    if fcands and hits:
        imp = _import_target(sc, hits)
        bound = _binds_to(imp, fcands)
        if not bound and prefer_def and len(fcands) == 1:
            # tools that list relations: the definition wins, the import is mentioned
            bd, f = fcands[0]
            others = ", ".join(b.bound.binary.name for b in imp.bindings)
            return FunctionTarget(bd, f, None, f"binary {bd.binary.name}; also an import in {others}")
        if not bound:
            listed = _cands(fcands) + [_stub_cand(b, imp.label) for b in imp.bindings]
            return ambiguous(name, listed, len(listed))
        fcands = bound                                    # the import is this definition
    if len(fcands) > 1:
        for bd in {id(b): b for b, _f in fcands}.values():     # a C++/CLI token and its IJW native body
            mine = [f for b, f in fcands if b is bd]
            pt = prefer_token(mine, bd.binary.pointer_size) if len(mine) == len(fcands) else None
            if pt is not None:
                return FunctionTarget(bd, pt[0], pt[1], f"binary {bd.binary.name}")
    if len(fcands) == 1:
        bd, f = fcands[0]
        return FunctionTarget(bd, f, None, f"binary {bd.binary.name}")
    if fcands:
        return ambiguous(name, _cands(fcands), len(fcands))
    return None


def _qt_method_addr(sc: Scope, text: str) -> int | None:
    """Address of a Qt signal, slot or method named ``Class::name``, or of a published Delphi method
    named ``TClass.name`` (``search`` and the form tools print these names for functions that are
    still FUN_ ones). One address only; None when unknown or ambiguous."""
    name = text.split("(", 1)[0].strip()
    qcls, _, qmeth = name.rpartition("::")
    dcls, _, dmeth = name.rpartition(".")
    for bd in sc.bounds:
        found: set[int] = set()
        for sql, args in (
                ("SELECT m.addr FROM qt_method m JOIN qt_class c ON c.binary_id=m.binary_id "
                 "AND c.meta_addr=m.meta_addr WHERE m.binary_id=? AND c.name=? AND m.name=? "
                 "AND m.addr IS NOT NULL", (bd.binary.id, qcls, qmeth) if qcls and qmeth else None),
                ("SELECT m.addr FROM dl_method m JOIN dl_class c ON c.binary_id=m.binary_id "
                 "AND c.vmt=m.vmt WHERE m.binary_id=? AND lower(c.name)=lower(?) "
                 "AND lower(m.name)=lower(?)", (bd.binary.id, dcls, dmeth) if dcls and dmeth else None)):
            if args is None:
                continue
            try:
                found |= {int(r[0]) for r in bd.store.db.execute(sql, args)}
            except Exception:  # noqa: BLE001  no framework tables
                continue
        if not found:
            found = _mfc_handler_addrs(bd, qcls, qmeth or name)
        if len(found) == 1:
            return found.pop()
    return None


_IDENT = re.compile(r"^[A-Za-z_]\w*$")


def _bare_method(sc: Scope, name: str, ks: frozenset[str]) -> Target | str | None:
    """A bare method name (``fileOpen``) that is one Qt method or one published Delphi method of the scope
    resolves to it, with a fact line; several give ``error ambiguous`` with ``Class::name 0xaddr``."""
    if not _IDENT.match(name):
        return None
    found: dict[tuple[int, int], tuple[Bound, str]] = {}
    for bd in sc.bounds:
        for sql, sep in (
                ("SELECT m.addr, c.name AS cn, m.name AS mn FROM qt_method m JOIN qt_class c ON "
                 "c.binary_id=m.binary_id AND c.meta_addr=m.meta_addr WHERE m.binary_id=? AND m.name=? "
                 "AND m.addr IS NOT NULL", "::"),
                ("SELECT m.addr, c.name AS cn, m.name AS mn FROM dl_method m JOIN dl_class c ON "
                 "c.binary_id=m.binary_id AND c.vmt=m.vmt WHERE m.binary_id=? AND lower(m.name)=lower(?) "
                 "AND m.addr IS NOT NULL AND m.addr>0", ".")):
            try:
                rows = bd.store.db.execute(sql, (bd.binary.id, name)).fetchall()
            except Exception:  # noqa: BLE001  no framework tables
                continue
            for r in rows:
                found.setdefault((bd.binary.id, int(r["addr"])), (bd, f"{r['cn']}{sep}{r['mn']}"))
    if not found:
        return None
    if len(found) > 1:
        listed = [f"{'' if sc.explicit else bd.binary.name + '!'}{label} {bd.addr(a)}"
                  for (_b, a), (bd, label) in sorted(found.items(), key=lambda kv: (kv[0][0], kv[0][1]))]
        return ambiguous(name, listed, len(listed))
    (_bid, addr), (bd, label) = next(iter(found.items()))
    r = _by_address(sc, f"0x{addr:x}", ks)
    if isinstance(r, FunctionTarget) and not r.note:
        r = replace(r, note=f"resolved '{name}' to {label}")
    return r


_PROGRAM_NAMES = frozenset({"main", "winmain", "wwinmain", "pascalmain", "program"})
_PASCALMAIN_FIELDS = (5, 3)     # TEntryInformation.PascalMain, in pointers: FPC 3.2.2 field 5, FPC 3.0.4 field 3 (verified)
_ENTRY_MAIN64 = re.compile(rb"\x48\x31\xc9\x48\x8d\x15(....)", re.S)      # xor rcx,rcx; lea rdx,[rip+d]


def fpc_pascalmain(img, ep: int) -> int | None:
    """The address of ``PASCALMAIN`` (the program body) of a Free Pascal program. The entry point passes
    ``@EntryInformation`` (the last ``mov eax, imm32`` / ``lea rcx, [rip+d]`` before the call) to
    ``FPC_EXE_ENTRY``; field 5 of that record is ``PascalMain`` in FPC 3.2.2 (x86 and x64) and field 3 in
    FPC 3.0.4 x86 (**[verified]**). FPC 3.0.4 x64 passes no record: the entry function it calls holds
    ``xor rcx,rcx; lea rdx,[PASCALMAIN]``."""
    code = img.read(ep, 0x60) or b""
    ps = img.psize
    if ps == 4:
        m = list(re.finditer(rb"\xb8(....)\xe8", code, re.S))
        rec = int.from_bytes(m[-1].group(1), "little") if m else None
    else:
        m = list(re.finditer(rb"\x48\x8d\x0d(....)", code, re.S))
        rec = (ep + m[-1].end() + int.from_bytes(m[-1].group(1), "little", signed=True)) if m else None
    if rec is not None:
        for f in _PASCALMAIN_FIELDS:
            pm = img.ptr(rec + f * ps)
            if pm and img.is_code(pm):
                return pm
    if ps == 8:
        for call in reversed(list(re.finditer(rb"\xe8(....)", code, re.S))):
            callee = ep + call.end() + int.from_bytes(call.group(1), "little", signed=True)
            hit = _ENTRY_MAIN64.search(img.read(callee, 0x80) or b"") if img.is_code(callee) else None
            if hit:
                pm = callee + hit.end() + int.from_bytes(hit.group(1), "little", signed=True)
                if img.is_code(pm):
                    return pm
    return None


def _fpc_main_address(ctx: ServerContext, bd: Bound) -> int | None:
    """``PASCALMAIN`` of one Free Pascal binary (None for other binaries or when it is not found)."""
    from airlock.projects import detect
    from airlock.server.cpp import Image

    b = bd.binary
    if b.toolchain != "fpc" or b.image_base is None:
        return None
    artifact = ctx.indexer.paths(bd.project).artifacts / b.sha256
    if not artifact.is_file():
        return None
    try:
        rva = detect(artifact).entry_point
        return fpc_pascalmain(Image.from_pe(artifact), b.image_base + rva) if rva is not None else None
    except Exception:  # noqa: BLE001  not a readable PE
        return None


def _program_body(ctx: ServerContext, sc: Scope, name: str, ks: frozenset[str] = frozenset()) -> Target | str | None:
    """``main`` / ``WinMain`` / ``PASCALMAIN`` / ``program`` of a Delphi or FPC program (no function of that
    name exists): the program body. Delphi inlines it into the PE entry point function; FPC's entry point
    passes ``@EntryInformation`` (the last ``mov eax, imm32`` / ``lea rcx, [rip+d]`` before the call) to
    ``FPC_EXE_ENTRY``, and field 5 of that record is PASCALMAIN."""
    from airlock.projects import detect
    from airlock.server.cpp import Image

    found: list[tuple[Bound, Function, str]] = []
    missing: list[tuple[Bound, int]] = []
    for bd in sc.bounds:
        b = bd.binary
        if b.toolchain not in ("delphi", "fpc") or b.image_base is None:
            continue
        artifact = ctx.indexer.paths(bd.project).artifacts / b.sha256
        if not artifact.is_file():
            continue
        try:
            rva = detect(artifact).entry_point
            img = Image.from_pe(artifact) if b.toolchain == "fpc" else None
        except Exception:  # noqa: BLE001  not a readable PE
            continue
        if rva is None or (b.toolchain == "fpc" and img is None):
            continue
        ep = b.image_base + rva
        fn = bd.store.function_containing(b.id, ep)
        if fn is None:
            continue
        if b.toolchain == "fpc":
            pm = fpc_pascalmain(img, ep)
            main = bd.store.function_at(b.id, pm) if pm else None
            if main is None:
                if pm:                      # Ghidra made no function there: the address resolves like a typed one
                    missing.append((bd, pm))
                continue
            found.append((bd, main, "PASCALMAIN"))
        else:
            found.append((bd, fn, "entry"))
    if len(found) > 1:
        return ambiguous(name, _cands([(bd, f) for bd, f, _w in found]), len(found))
    if not found:
        if len(missing) == 1 and len(sc.bounds) == 1:       # no Ghidra function: `_create_on_demand` makes it
            return err("not_found", f"no function at or containing {missing[0][0].addr(missing[0][1])}{_where(sc)}")
        return None
    bd, fn, what = found[0]
    return FunctionTarget(bd, fn, f"resolved '{name}' to the program body {fn.qualified_name} ({what})",
                          None if sc.explicit else f"binary {bd.binary.name}")


def _mfc_handler_addrs(bd: Bound, cls: str, meth: str) -> set[int]:
    """Handlers of message map entries whose ClassWizard style name (``OnCommand_32786_Options``,
    ``uijoin.UiIndex.suggest``, printed by ``mfc_message_maps`` / ``menus``) is ``meth``; ``cls`` (may
    be empty) narrows to one class."""
    if not meth.lower().startswith("on"):
        return set()
    from airlock.server import uijoin            # late: uijoin imports features
    sql = ("SELECT class, map_addr, message, code, ctrl_id, last_id, handler FROM msgmap_entry "
           "WHERE binary_id=?")
    args: tuple = (bd.binary.id,)
    if cls:
        sql += " AND lower(class)=lower(?)"
        args += (cls,)
    try:
        rows = bd.store.db.execute(sql, args).fetchall()
    except Exception:  # noqa: BLE001  no message map tables
        return set()
    if not rows:
        return set()
    ui = uijoin.UiIndex(bd.store, bd.binary.id)
    want = meth.lower()
    return {int(r[6]) for r in rows
            if ui.suggest(uijoin.Handler(r[0], r[1], r[2], r[3], r[4], r[5], r[6])).lower() == want}


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
    return wrong_kind(text, f"an import ({r.label}) with no code of its own", ks)


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
        return ambiguous(raw, _cands([(bd, f) for bd, f, _n in found]), len(found))
    if ADDRESS in ks:            # a data address (a VMT, a table): the binaries that reference it or hold its class
        data = [bd for bd in sc.bounds if bd.store.xrefs_to_address(bd.binary.id, value, None, 1)
                or bd.store.xrefs_from_address(bd.binary.id, value, None, 1)
                or classfwd.find_classes([bd], value)]
        if not data:             # no binary references it: the binaries that hold a string there
            data = [bd for bd in sc.bounds if bd.store.string_at(bd.binary.id, value) is not None]
        if len(data) == 1:
            return AddressTarget(data[0], space, value, f"binary {data[0].binary.name}")
        if data:
            shown = ", ".join(f"{bd.binary.name}!{bd.addr(value, space)}" for bd in data[:MAX_CANDIDATES])
            return err("ambiguous", f"'{raw}' has references in {len(data)} binaries: {shown}")
    return err("not_found", f"no function at or containing {raw}{_where(sc)}")


def _strings(sc: Scope, text: str) -> StringTarget | None:
    """Strings equal to ``text`` (``*``/``?`` is a glob), else containing it."""
    def esc(x: str) -> str:
        return "".join("\\" + c if c in "%_\\" else c for c in x)

    if "*" in text or "?" in text:
        like = "".join("%" if c == "*" else "_" if c == "?" else esc(c) for c in text)
        plans = (("glob", "value LIKE ? ESCAPE '\\'", like),)
    else:
        plans = (("exact", "value=?", text), ("substring", "value LIKE ? ESCAPE '\\'", f"%{esc(text)}%"))
    for how, sql, arg in plans:
        out: list[tuple[Bound, StringHit]] = []
        for bd in sc.bounds:
            for r in bd.store.db.execute(
                    f"SELECT id, address, encoding, value FROM string WHERE binary_id=? AND {sql} "
                    "ORDER BY address LIMIT ?", (bd.binary.id, arg, MAX_STRING_HITS)):
                out.append((bd, StringHit(r["id"], r["address"], r["encoding"], r["value"])))
        if out:
            return StringTarget(tuple(out[:MAX_STRING_HITS]), how)
    return None
