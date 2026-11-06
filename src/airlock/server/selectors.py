"""Target resolution (DESIGN.md section 7.3). Server side; no Ghidra imports."""

from __future__ import annotations

import re
from dataclasses import dataclass

from airlock.index.store import DN_METHOD_HI, DN_METHOD_LO, US_BASE, Function, Store

_SPACE_ADDR = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):(?:0[xX])?([0-9a-fA-F]+)$")
_BARE_HEX = re.compile(r"^[0-9a-fA-F]+$")
MAX_CANDIDATES = 20
# Ghidra default names carry the address: DAT_14026ebc8, PTR_FUN_00401000, LAB_0040102c, UNK_..., s_Hello_00402000
_DEFAULT_NAME = re.compile(r"^(?:DAT|PTR|LAB|UNK|FUN|SUB|EXT|BYTE|WORD|DWORD|QWORD|s|u)_(?:.*_)?([0-9a-fA-F]{4,16})$")


@dataclass(frozen=True)
class Resolved:
    """Either ``function`` is set (with an optional ``note``) or ``error`` is
    a ready-to-print one-line error."""

    function: Function | None = None
    note: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.function is not None


def fmt_addr(value: int, pointer_size: int | None = 4, space: str = "ram") -> str:
    """``0x`` + lowercase hex zero-padded to pointer size; non-ram spaces get a prefix."""
    if value >= US_BASE:                      # a .NET user string: space ``us``, offset in the #US heap
        return f"us:0x{value - US_BASE:08x}"
    width = (pointer_size or 4) * 2
    s = f"0x{value:0{width}x}"
    return s if space == "ram" else f"{space}:{s}"


def parse_address(target: str) -> tuple[str, int] | None:
    """(space, offset) for ``0x...`` or ``SPACE:0x...``; None if not an
    explicit address. Rule 1 of 7.3."""
    t = target.strip()
    if t[:2].lower() == "0x":
        try:
            return "ram", int(t[2:], 16)
        except ValueError:
            return None
    m = _SPACE_ADDR.match(t)
    if m and (t.split(":", 1)[1][:2].lower() == "0x"):
        space = "EXTERNAL" if m.group(1).lower() == "external" else m.group(1)
        if m.group(1).lower() == "ram":
            space = "ram"
        if m.group(1).lower() == "us":        # .NET user string: an address in its own window
            return "ram", US_BASE | int(m.group(2), 16)
        return space, int(m.group(2), 16)
    return None


def default_name_address(text: str) -> int | None:
    """The address in a Ghidra default data or label name (``DAT_14026ebc8``, ``s_text_00402000``),
    else None. The hex part is the last ``_`` segment (32-bit names have 8 digits, 64-bit 8 to 16)."""
    m = _DEFAULT_NAME.match(text.strip())
    return int(m.group(1), 16) if m else None


def split_binary_target(store: Store, target: str) -> tuple[str, str]:
    """``(binary, bare_target)`` for ``binary!target``, else ``("", target)``.

    Splits on the first ``!`` only when the left part is the exact name (case-insensitive) of
    a binary of the project, so names that contain ``!`` stay intact. Rule 6 of 7.3."""
    t = target.strip()
    left, sep, right = t.partition("!")
    left, right = left.strip(), right.strip()
    if sep and left and right:
        for b in store.list_binaries():
            if b.name.lower() == left.lower():
                return b.name, right
    return "", t


def split_binary_suffix(store: Store, target: str) -> tuple[str, str]:
    """``(binary, bare_target)`` for ``name@binary``, else ``("", target)``. Splits on the last
    ``@`` only when the right part is the exact name of a binary (decorated names like
    ``_foo@8`` stay intact). Rule 9 of 7.3."""
    t = target.strip()
    left, sep, right = t.rpartition("@")
    left, right = left.strip(), right.strip()
    if sep and left and right:
        for b in store.list_binaries():
            if b.name.lower() == right.lower():
                return b.name, left
    return "", t


def _error(code: str, what: str, nxt: str = "") -> Resolved:
    return Resolved(error=f"error {code}: {what}." + (f" {nxt}." if nxt else ""))


MAX_CLOSE = 8   # close names listed in a not_found error


def close_functions(store: Store, binary_id: int, name: str, limit: int = MAX_CLOSE) -> tuple[list[Function], bool]:
    """Functions whose name is close to ``name``: (rows, exact_ignoring_case). First the names
    equal to it ignoring case (also ``ns::name``); else names that contain its last segment
    (after ``::``, ``.`` or ``!``), shortest first. Only the first kind is safe to resolve to."""
    t = name.strip()
    if not t:
        return [], False
    rows = store.db.execute(
        "SELECT entry, space FROM function WHERE binary_id=? AND (lower(name)=lower(?) OR "
        "(namespace IS NOT NULL AND namespace<>'' AND lower(namespace || '::' || name)=lower(?))) "
        "ORDER BY space, entry LIMIT ?", (binary_id, t, t, limit + 1)).fetchall()
    if rows:
        exact = True
    else:
        tail = re.split(r"::|[.!]", t)[-1]
        if len(tail) < 3:
            return [], False
        like = "%" + tail.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        rows = store.db.execute(
            "SELECT entry, space FROM function WHERE binary_id=? AND name LIKE ? ESCAPE '\\' "
            "ORDER BY length(name), entry LIMIT ?", (binary_id, like, limit + 1)).fetchall()
        exact = False
    fns = [f for f in (store.function_at(binary_id, r[0], r[1]) for r in rows) if f is not None]
    local = [f for f in fns if not f.is_external]
    if exact and len(fns) > 1 and len(local) == 1:   # an import's EXTERNAL row and its thunk
        fns = local
    return fns, exact


def close_text(names: list[str], more: bool) -> str:
    """``close names: a 0x.., b 0x..`` for a not_found error, or empty."""
    if not names:
        return ""
    return "close names: " + ", ".join(names) + (" …" if more else "")


_VSLOT = re.compile(r"^(.+?)\s*::\s*vslot\s+(\d+)\b.*$", re.I)


def _class_keys(head: str) -> list[tuple[str, str]]:
    """(unit, class) readings of ``head`` (``apphelpers.TAppSettings``, ``TAppSettings``): the whole text as a
    class name, and the text after the last dot with the rest as the unit."""
    out = [("", head)]
    unit, dot, cls = head.rpartition(".")
    if dot and unit and cls:
        out.append((unit, cls))
    return out


def alias_addrs(store: Store, binary_id: int, target: str) -> list[int]:
    """Entries of the functions that the name hints of the tools call ``target``: ``Unit.Class.Method`` /
    ``Class.Method`` / ``Class::Method`` of Delphi and FPC (published, RTTI, property accessors, named
    virtual methods), ``TClass::vslot N`` (Delphi VMT or C++ vtable slot) and the IDR / signature names
    (``Unit.Proc``, with or without the unit). Case-insensitive; sorted; empty when nothing matches."""
    text = target.strip()
    if not text:
        return []
    q = store.db.execute
    found: set[int] = set()
    try:
        m = _VSLOT.match(text)
        if m:
            want, slot = m.group(1).strip().lower(), int(m.group(2))
            for r in q("SELECT m.addr FROM dl_method m JOIN dl_class c ON c.binary_id=m.binary_id AND c.vmt=m.vmt "
                       "WHERE m.binary_id=? AND m.kind='virtual' AND m.slot=? AND (lower(c.name)=? OR "
                       "lower(c.unit || '.' || c.name)=?)", (binary_id, slot, want, want)):
                found.add(int(r[0]))
            for r in q("SELECT s.target FROM vtable_slot s JOIN rtti_class c ON c.binary_id=s.binary_id AND "
                       "c.vtable_addr=s.vtable_addr WHERE s.binary_id=? AND s.slot=? AND lower(c.name)=?",
                       (binary_id, slot, want)):
                found.add(int(r[0]))
            return sorted(found)
        name = text.split("(", 1)[0].strip()
        low = name.lower()
        from airlock.server.delphi import accessor_name        # late: delphi imports the store
        for sep in ("::", "."):
            head, s, meth = name.rpartition(sep)
            if not (s and head.strip() and meth.strip()):
                continue
            meth = meth.strip().lower()
            for unit, cls in _class_keys(head.strip()):
                sql = ("SELECT m.kind, m.name, m.addr FROM dl_method m JOIN dl_class c ON c.binary_id=m.binary_id "
                       "AND c.vmt=m.vmt WHERE m.binary_id=? AND lower(c.name)=?")
                args: list = [binary_id, cls.lower()]
                if unit:
                    sql += " AND lower(c.unit)=?"
                    args.append(unit.lower())
                for r in q(sql, args):
                    if r[1] and (r[1].lower() == meth or (r[0] in ("prop-get", "prop-set")
                                                          and accessor_name(r[0], r[1]).lower() == meth)):
                        found.add(int(r[2]))
        from airlock.server import idr
        for entry, names in idr.hits(store, binary_id).items():
            for n in names.split(" | "):
                n = re.sub(r"\s*\(\+\d+\)$", "", n).strip().lower()
                if n and (n == low or n.endswith("." + low)):
                    found.add(entry)
                    break
    except Exception:  # noqa: BLE001  an index without the framework tables
        return sorted(found)
    return sorted(found)


def alias_functions(store: Store, binary_id: int, target: str) -> list[Function]:
    """``alias_addrs`` as functions (an address inside a function is skipped)."""
    out: list[Function] = []
    for a in alias_addrs(store, binary_id, target):
        f = store.function_at(binary_id, a)
        if f is not None and f not in out:
            out.append(f)
    return out


# -- managed overloads (P19) ----------------------------------------------------------------------

_TYPE_ALIAS = {"string": "string", "boolean": "bool", "int32": "int", "int64": "long", "uint32": "uint",
               "uint64": "ulong", "int16": "short", "uint16": "ushort", "byte": "byte", "sbyte": "sbyte",
               "single": "float", "double": "double", "object": "object", "char": "char", "void": "void",
               "intptr": "intptr", "uintptr": "uintptr"}
_QUALIFIER = re.compile(r"\b(?:ref|out|in)\s+")
_IDENT_PART = re.compile(r"[A-Za-z_][\w.`+]*")
_SELECTOR = re.compile(r"^([^()]+?)\s*\((.*)\)\s*$", re.S)


def is_managed(f: Function) -> bool:
    """A .NET method row (token entry), not its IJW native body or an import."""
    return f.space == "ram" and DN_METHOD_LO <= f.entry < DN_METHOD_HI


def _norm_type(t: str) -> str:
    """Loose form of a type name: no namespace, no generic arity, no ref/out/in, ``String`` = ``string``."""
    t = _QUALIFIER.sub("", t.strip())

    def one(m: re.Match) -> str:
        w = m.group(0).split("`", 1)[0].rsplit(".", 1)[-1].replace("+", ".")
        return _TYPE_ALIAS.get(w.lower(), w.lower())
    return re.sub(r"\s+", "", _IDENT_PART.sub(one, t.replace("&", "")))


def _split_params(text: str) -> list[str]:
    out: list[str] = []
    depth, cur = 0, ""
    for ch in text:
        if ch in "<[":
            depth += 1
        elif ch in ">]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip() or out:
        out.append(cur)
    return [_norm_type(p) for p in out if p.strip()]


def sig_params(sig: str | None) -> list[str] | None:
    """Normalised parameter types of a stored managed signature ``ret(p1, p2)``; None when unknown."""
    if not sig or "(" not in sig or ")" not in sig:
        return None
    return _split_params(sig[sig.index("(") + 1:sig.index(")")])


def parse_selector(target: str) -> tuple[str, list[str] | None]:
    """``(name, params)`` of ``Type::Name(int, string)``; params is None without parentheses."""
    m = _SELECTOR.match(target.strip())
    if not m:
        return target.strip(), None
    return m.group(1).strip(), _split_params(m.group(2))


def managed_named(store: Store, binary_id: int, name: str) -> list[Function]:
    """Managed methods named ``Type::Name`` or ``Type.Name`` (namespace and type before the last separator)."""
    out = [f for f in store.functions_by_name(binary_id, name) if is_managed(f)]
    if out:
        return out
    head, sep, meth = name.rpartition(".")
    if not (sep and head and meth):
        return []
    rows = store.db.execute(
        "SELECT entry, space FROM function WHERE binary_id=? AND space='ram' AND entry>=? AND entry<? "
        "AND name=? AND namespace=? ORDER BY entry", (binary_id, DN_METHOD_LO, DN_METHOD_HI, meth, head)).fetchall()
    return [f for f in (store.function_at(binary_id, r[0], r[1]) for r in rows) if f is not None]


def describe(fns: list[Function], psize: int | None, qualified: bool = False) -> list[str]:
    """Candidate texts: ``0xaddr`` for native functions, ``0xtoken Name(sig)`` for managed ones (the qualified
    name when the candidates do not all share one)."""
    qual = qualified or len({f.qualified_name for f in fns if is_managed(f)}) > 1
    out = []
    for f in fns:
        a = fmt_addr(f.entry, psize, f.space)
        if is_managed(f):
            sig = f.signature or ""
            ret, _, rest = sig.partition("(")
            out.append(f"{a} {f.qualified_name if qual else f.name}({rest}" if rest else f"{a} {f.qualified_name}")
        else:
            out.append(a)
    return out


def prefer_token(fns: list[Function], psize: int | None) -> tuple[Function, str] | None:
    """One managed token plus native bodies of the same name (C++/CLI IJW thunk): the token and a fact line."""
    managed = [f for f in fns if is_managed(f)]
    native = [f for f in fns if not is_managed(f) and not f.is_external]
    if len(managed) == 1 and native and len(managed) + len(native) == len(fns):
        return managed[0], "native thunk " + ", ".join(fmt_addr(f.entry, psize, f.space) for f in native)
    return None


def _ambiguous(target: str, fns: list[Function], psize: int | None) -> Resolved:
    shown = fns[:MAX_CANDIDATES]
    more = f" (+{len(fns) - len(shown)} more)" if len(fns) > len(shown) else ""
    return _error("ambiguous", f"'{target}' matches {len(fns)} functions: "
                  + ", ".join(describe(shown, psize)) + more)


def by_selector(store: Store, binary_id: int, target: str, psize: int | None) -> Resolved | None:
    """``Type::Name(params)`` and ``Type.Name`` for managed methods; None when it is not one."""
    name, params = parse_selector(target)
    if params is None and "." not in name:
        return None
    cands = managed_named(store, binary_id, name)
    if not cands:
        return None
    picked = cands if params is None else [f for f in cands if sig_params(f.signature) == params]
    if len(picked) == 1:
        f = picked[0]
        return Resolved(function=f, note=f"resolved '{target}' to {describe([f], psize)[0]}")
    if not picked:
        return _error("not_found", f"no overload of '{name}' takes ({', '.join(params or [])}); "
                      f"overloads: " + ", ".join(describe(cands[:MAX_CANDIDATES], psize)))
    return _ambiguous(target, picked, psize)


def resolve_function(store: Store, binary_id: int, target: str) -> Resolved:
    """Resolve ``target`` to a function of the binary.

    Order: explicit address, exact name (incl. namespace), bare hex address.
    Names matching several functions give an error listing every candidate.
    An address inside a function resolves to it, with a note.
    """
    target = target.strip()
    if not target:
        return _error("bad_target", "empty target")
    binary = store.get_binary_by_id(binary_id)
    psize = binary.pointer_size if binary else 4

    addr = parse_address(target)
    if addr is not None:
        return _by_address(store, binary_id, addr[0], addr[1], psize, target)

    fns = store.functions_by_name(binary_id, target)
    if len(fns) == 1:
        return Resolved(function=fns[0])
    if len(fns) > 1:
        # An imported function is an EXTERNAL row plus a ram thunk of the same
        # name; the thunk is the one with callers, so external rows lose the tie.
        local = [f for f in fns if not f.is_external]
        if len(local) == 1:
            return Resolved(function=local[0])
        pt = prefer_token(fns, psize)
        if pt is not None:
            return Resolved(function=pt[0], note=pt[1])
        return _ambiguous(target, fns, psize)
    if not fns:
        sel = by_selector(store, binary_id, target, psize)
        if sel is not None:
            return sel

    if _BARE_HEX.match(target):
        return _by_address(store, binary_id, "ram", int(target, 16), psize, target)

    close, exact = close_functions(store, binary_id, target)
    if exact and len(close) == 1:
        f = close[0]
        return Resolved(function=f, note=f"resolved '{target}' to {f.qualified_name} (case differs)")
    al = alias_functions(store, binary_id, target)
    if len(al) == 1:
        f = al[0]
        return Resolved(function=f, note=f"resolved '{target}' to {f.qualified_name} {fmt_addr(f.entry, psize, f.space)}")
    if al:
        shown = al[:MAX_CANDIDATES]
        more = f" (+{len(al) - len(shown)} more)" if len(al) > len(shown) else ""
        return _error("ambiguous", f"'{target}' matches {len(al)} functions: "
                      + ", ".join(fmt_addr(f.entry, psize, f.space) for f in shown) + more)
    names = [f"{f.qualified_name} {fmt_addr(f.entry, psize, f.space)}" for f in close[:MAX_CLOSE]]
    return _error("not_found", f"no function named '{target}'", close_text(names, len(close) > MAX_CLOSE))


def _by_address(
    store: Store, binary_id: int, space: str, value: int, psize: int | None, raw: str
) -> Resolved:
    fn = store.function_at(binary_id, value, space)
    if fn is not None:
        return Resolved(function=fn)
    fn = store.function_containing(binary_id, value, space)
    if fn is not None:
        a = fmt_addr(value, psize, space)
        e = fmt_addr(fn.entry, psize, space)
        return Resolved(function=fn, note=f"resolved from interior address {a} to {fn.qualified_name} at {e}")
    return _error(
        "not_found",
        f"no function at or containing {fmt_addr(value, psize, space)}",
    )
