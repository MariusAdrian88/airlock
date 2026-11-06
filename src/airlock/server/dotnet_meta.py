""".NET type-system facts from the metadata tables (DESIGN.md section 11): interface implementations and
overrides (InterfaceImpl, MethodImpl, virtual slots), fields with layouts and constants, properties,
events, and the field read/write edges of the IL bodies.

``parse`` builds a ``Meta`` from the dnfile tables; ``write`` stores it in the derived tables
``dn_rel`` / ``dn_override`` / ``dn_field`` / ``dn_layout`` / ``dn_prop`` / ``dn_event`` (schema v16; rebuilt with the rest of the .NET tables when DOTNET_VERSION
changes). The query side (``impl_lines``, ``field_lines``, ``property_lines``, ``event_lines``,
``implementers``, ``bases``) works on those tables only, over all managed binaries of a project, and
matches across assemblies by full type name, as ``link_managed`` does.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from airlock.server import dotnet as dn

log = logging.getLogger(__name__)

FIELD_LO, FIELD_HI = 0x04000000, 0x05000000     # Field tokens (targets of read / write edges)
KINDS = ("impl", "field", "property", "event")

_TABLES = ("dn_rel", "dn_override", "dn_field", "dn_layout", "dn_prop", "dn_event", "dn_native")


@dataclass
class Meta:
    rels: list[tuple[int, str, str, int | None]] = field(default_factory=list)
    # (type token, 'iface' | 'base', target full name, target TypeDef token or None)
    overrides: list[tuple[int, str, int | None, str, str, str]] = field(default_factory=list)
    # (method token, 'impl' | 'override', base MethodDef token or None, base type, base name, base params)
    fields: list[tuple[int, int, str, str, str, int | None, str | None]] = field(default_factory=list)
    layouts: list[tuple[int, str, int | None, int | None]] = field(default_factory=list)
    props: list[tuple[int, int, str, str, int | None, int | None]] = field(default_factory=list)
    events: list[tuple[int, int, str, str, int | None, int | None]] = field(default_factory=list)
    accesses: list[tuple[int, int, str]] = field(default_factory=list)      # method, field token, read|write
    natives: list[tuple[int, int, str, str]] = field(default_factory=list)  # method token, RVA, name, type name


def clear(db: sqlite3.Connection, bid: int) -> None:
    for t in _TABLES:
        db.execute(f"DELETE FROM {t} WHERE binary_id=?", (bid,))
    db.execute("DELETE FROM edge WHERE binary_id=? AND kind IN ('read','write') AND dst_addr>=? AND dst_addr<?",
               (bid, FIELD_LO, FIELD_HI))
    db.execute("DELETE FROM edge WHERE binary_id=? AND kind='native' AND src_addr>=? AND src_addr<?",
               (bid, dn.DN_METHOD_LO, dn.DN_METHOD_HI))


# -- parsing -----------------------------------------------------------------------------------

def _s(v: Any) -> str:
    return "" if v is None else str(v)


def _short(name: str) -> str:
    return name.rsplit(".", 1)[-1].split("`", 1)[0]


def field_owners(md: Any, parsed: Any) -> dict[int, str]:
    """Field row id -> full name of the declaring type (for the ``Type::Field`` IL labels)."""
    out: dict[int, str] = {}
    for i, r in enumerate(md.TypeDef.rows, 1):
        for f in (r.FieldList or []):
            out[f.row_index] = parsed.types[i - 1].name
    return out


def _field_sig(blob: bytes, names: dict[int, str]) -> str:
    try:
        r = dn._Blob(blob)
        if r.byte() & 0x0F != 6:
            return "?"
        return dn._type(r, names)
    except (ValueError, IndexError):
        return "?"


def _const(c: Any) -> str | None:
    try:
        raw = bytes(c.Value.value)
        t = int(c.Type)
        if t == 0x0E:
            s = raw.decode("utf-16-le", "replace").replace("\n", "\\n")
            return '"' + (s[:40] + "…" if len(s) > 40 else s) + '"'
        if t == 0x0C and len(raw) == 4:
            import struct
            return repr(struct.unpack("<f", raw)[0])
        if t == 0x0D and len(raw) == 8:
            import struct
            return repr(struct.unpack("<d", raw)[0])
        if t == 0x12:
            return "null"
        signed = t in (0x04, 0x06, 0x08, 0x0A)
        v = int.from_bytes(raw, "little", signed=signed)
        return ("true" if v else "false") if t == 0x02 else str(v)
    except (ValueError, TypeError, AttributeError):
        return None


def scan_fields(code: bytes) -> list[tuple[str, int]]:
    """(``read`` | ``write``, field token) of the ldfld / ldflda / stfld / ldsfld / ldsflda / stsfld
    instructions of an IL body. Stops at an undefined opcode."""
    out: list[tuple[str, int]] = []
    i, n, sz, sz2 = 0, len(code), dn._SZ, dn._SZ2
    frm = int.from_bytes
    while i < n:
        op = code[i]
        if 0x7B <= op <= 0x80:
            out.append(("write" if op in (0x7D, 0x80) else "read", frm(code[i + 1:i + 5], "little")))
            i += 5
        elif op == 0xFE:
            if i + 1 >= n:
                break
            s = sz2[code[i + 1]]
            if s < 0:
                break
            i += 2 + s
        elif op == 0x45:
            i += 5 + 4 * frm(code[i + 1:i + 5], "little")
        else:
            s = sz[op]
            if s < 0:
                break
            i += 1 + s
    return out


class _Types:
    """Base, interfaces and methods of the TypeDefs, as the override matching needs them."""

    def __init__(self, md: Any, parsed: Any) -> None:
        self.md, self.p = md, parsed
        self.res = parsed.res
        self.n = len(parsed.types)
        self.methods: dict[int, list[Any]] = {}
        for m in parsed.methods:
            self.methods.setdefault(m.type_token, []).append(m)
        self.mflags: dict[int, Any] = {}
        for i, r in enumerate(md.MethodDef.rows, 1):
            f = r.Flags
            self.mflags[dn.METHOD_TOKEN | i] = (
                bool(getattr(f, "mdVirtual", False)), bool(getattr(f, "mdNewSlot", False)),
                bool(getattr(f, "mdStatic", False)), bool(getattr(f, "mdPrivate", False)))

    def target(self, ref: Any) -> tuple[str, int | None] | None:
        """(full name, TypeDef token or None) of a TypeDefOrRef coded index."""
        tn = getattr(getattr(ref, "table", None), "name", "")
        rid = getattr(ref, "row_index", 0)
        if tn == "TypeSpec":
            ts = self.res._typespec(rid)
            if ts is None:
                return None
            tn, rid = ts
        if tn == "TypeDef" and 0 < rid <= self.n:
            return self.p.types[rid - 1].name, dn.TYPE_TOKEN | rid
        if tn == "TypeRef" and 0 < rid <= len(self.res.refs):
            return self.res.tref(rid)[0], None
        return None


def _same_params(a: str, b: str) -> bool:
    if a == b:
        return True
    generic = re.compile(r"\b[TM]\d+\b")
    return (bool(generic.search(a)) or bool(generic.search(b))) and a.count(",") == b.count(",") \
        and (a == "()") == (b == "()")


def _find(ty: _Types, tok: int, name: str, params: str, need_virtual: bool) -> int | None:
    """The method of type ``tok`` named ``name`` with these parameters (a generic parameter list
    matches by count), or None."""
    cands = [m for m in ty.methods.get(tok, []) if m.name == name and not ty.mflags[m.token][2]
             and (not need_virtual or ty.mflags[m.token][0])]
    for m in cands:
        if dn._params(m.sig) == params:
            return m.token
    for m in cands:
        if _same_params(dn._params(m.sig), params):
            return m.token
    return None


def parse(md: Any, parsed: Any, pe: Any = None) -> Meta:
    """Type-system facts of an assembly; ``pe`` (the loaded file) adds the field access edges."""
    out = Meta()
    ty = _Types(md, parsed)
    names = parsed.res.names
    tdefs = md.TypeDef.rows
    # -- base types and interfaces
    base_of: dict[int, tuple[str, int | None]] = {}
    ifaces: dict[int, list[tuple[str, int | None]]] = {}
    for i, r in enumerate(tdefs, 1):
        ex = r.Extends
        if ex is not None and getattr(ex, "row_index", 0):
            t = ty.target(ex)
            if t is not None and t[0] != "System.Object":
                base_of[dn.TYPE_TOKEN | i] = t
                out.rels.append((dn.TYPE_TOKEN | i, "base", t[0], t[1]))
    if md.InterfaceImpl is not None:
        for r in md.InterfaceImpl.rows:
            cls = dn.TYPE_TOKEN | r.Class.row_index
            t = ty.target(r.Interface)
            if t is not None:
                ifaces.setdefault(cls, []).append(t)
                out.rels.append((cls, "iface", t[0], t[1]))
    owner = {m.token: m.type_token for m in parsed.methods}
    seen: set[tuple[int, str, str, str]] = set()

    def add(meth: int, kind: str, base_tok: int | None, btype: str, bname: str, bparams: str) -> None:
        key = (meth, btype, bname, bparams)
        if key not in seen:
            seen.add(key)
            out.overrides.append((meth, kind, base_tok, btype, bname, bparams))

    # -- explicit MethodImpl
    covered: set[tuple[int, int]] = set()          # (implementing method, interface method token)
    if md.MethodImpl is not None:
        for r in md.MethodImpl.rows:
            body, decl = r.MethodBody, r.MethodDeclaration
            if getattr(body.table, "name", "") != "MethodDef":
                continue
            btok = dn.METHOD_TOKEN | body.row_index
            dtab = getattr(decl.table, "name", "")
            cls = dn.TYPE_TOKEN | r.Class.row_index
            if dtab == "MethodDef":
                dtok = dn.METHOD_TOKEN | decl.row_index
                dm = parsed.methods[decl.row_index - 1]
                dt = parsed.types[(dm.type_token & 0xFFFFFF) - 1]
                add(btok, "impl" if dt.kind == "interface" else "override", dtok, dt.name, dm.name,
                    dn._params(dm.sig))
                covered.add((btok, dtok))
                continue
            got = parsed.res.resolve(dn.REF_LO | decl.row_index) if dtab == "MemberRef" else None
            if got is None:
                continue
            if got[0] is not None:
                dm = parsed.methods[(got[0] & 0xFFFFFF) - 1]
                dt = parsed.types[(dm.type_token & 0xFFFFFF) - 1]
                add(btok, "impl" if dt.kind == "interface" else "override", got[0], dt.name, dm.name,
                    dn._params(dm.sig))
                covered.add((btok, got[0]))
            elif got[2] and "::" in got[2]:
                head, _, tail = got[2].partition("::")
                mname, par, rest = tail.partition("(")
                is_if = any(head == t[0] for t in _all_ifaces(cls, ifaces, ty, base_of))
                add(btok, "impl" if is_if else "override", None, head, mname, par + rest if par else "()")

    # -- implicit interface implementations and virtual overrides
    for i, t in enumerate(parsed.types, 1):
        tok = dn.TYPE_TOKEN | i
        if t.kind == "interface":
            continue
        for itype, itok in _all_ifaces(tok, ifaces, ty, base_of):
            if itok is None:
                continue                             # an interface of another assembly: matched by name at query time
            for im in ty.methods.get(itok, []):
                if ty.mflags[im.token][2]:
                    continue
                par = dn._params(im.sig)
                hit = None
                cur: int | None = tok
                for _ in range(16):
                    if cur is None:
                        break
                    hit = _find(ty, cur, im.name, par, False)
                    if hit is not None:
                        break
                    b = base_of.get(cur)
                    cur = b[1] if b else None
                if hit is not None and (hit, im.token) not in covered:
                    add(hit, "impl", im.token, itype, im.name, par)
        for m in ty.methods.get(tok, []):
            virt, newslot, static, _priv = ty.mflags[m.token]
            if not virt or newslot or static:
                continue
            par = dn._params(m.sig)
            b = base_of.get(tok)
            for _ in range(16):
                if b is None:
                    break
                if b[1] is None:                      # the base is in another assembly
                    add(m.token, "override", None, b[0], m.name, par)
                    break
                hit = _find(ty, b[1], m.name, par, True)
                if hit is not None:
                    add(m.token, "override", hit, b[0], m.name, par)
                    break
                b = base_of.get(b[1])

    # -- fields, layouts, constants
    consts: dict[int, str | None] = {}
    if md.Constant is not None:
        for c in md.Constant.rows:
            if getattr(c.Parent.table, "name", "") == "Field":
                consts[c.Parent.row_index] = _const(c)
    offsets: dict[int, int] = {}
    if md.FieldLayout is not None:
        for r in md.FieldLayout.rows:
            offsets[r.Field.row_index] = int(r.Offset)
    frows = md.Field.rows if md.Field is not None else []
    fowner = field_owners(md, parsed)
    tok_of_name = {parsed.types[j].name: dn.TYPE_TOKEN | (j + 1) for j in range(ty.n)}
    for i, r in enumerate(frows, 1):
        f = r.Flags
        fl = []
        for attr, lab in (("fdPublic", "public"), ("fdPrivate", "private"), ("fdFamily", "protected"),
                          ("fdAssembly", "internal"), ("fdStatic", "static"), ("fdLiteral", "const"),
                          ("fdInitOnly", "readonly")):
            if getattr(f, attr, False):
                fl.append(lab)
        raw = r.Signature.value if r.Signature is not None else b""
        owner_name = fowner.get(i)
        out.fields.append((0x04000000 | i, tok_of_name.get(owner_name or "", 0), _s(r.Name),
                           _field_sig(bytes(raw), names), ",".join(fl), offsets.get(i), consts.get(i)))
    cl = {}
    if md.ClassLayout is not None:
        for r in md.ClassLayout.rows:
            cl[r.Parent.row_index] = (int(r.PackingSize) or None, int(r.ClassSize) or None)
    for i, r in enumerate(tdefs, 1):
        f = r.Flags
        explicit = getattr(f, "tdExplicitLayout", False)
        seq = getattr(f, "tdSequentialLayout", False)
        if explicit or i in cl:
            pack, size = cl.get(i, (None, None))
            out.layouts.append((dn.TYPE_TOKEN | i, "explicit" if explicit else ("sequential" if seq else "auto"),
                                pack, size))

    # -- properties and events
    sem_get: dict[tuple[str, int], dict[str, int]] = {}
    if md.MethodSemantics is not None:
        for r in md.MethodSemantics.rows:
            a = r.Association
            s = r.Semantics
            role = ("get" if getattr(s, "msGetter", False) else "set" if getattr(s, "msSetter", False)
                    else "add" if getattr(s, "msAddOn", False) else "remove" if getattr(s, "msRemoveOn", False)
                    else None)
            if role:
                sem_get.setdefault((getattr(a.table, "name", ""), a.row_index), {})[role] = \
                    dn.METHOD_TOKEN | r.Method.row_index
    if md.PropertyMap is not None and md.Property is not None:
        for pm in md.PropertyMap.rows:
            tt = dn.TYPE_TOKEN | pm.Parent.row_index
            for ref in (pm.PropertyList or []):
                pr = md.Property.rows[ref.row_index - 1]
                blob = bytes(pr.Type.value) if pr.Type is not None else b""
                sig = dn.method_sig(blob, names) if blob else "?"
                s = sem_get.get(("Property", ref.row_index), {})
                out.props.append((0x17000000 | ref.row_index, tt, _s(pr.Name), sig, s.get("get"), s.get("set")))
    if md.EventMap is not None and md.Event is not None:
        for em in md.EventMap.rows:
            tt = dn.TYPE_TOKEN | em.Parent.row_index
            for ref in (em.EventList or []):
                er = md.Event.rows[ref.row_index - 1]
                t = ty.target(er.EventType)
                s = sem_get.get(("Event", ref.row_index), {})
                out.events.append((0x14000000 | ref.row_index, tt, _s(er.Name), t[0] if t else "?",
                                   s.get("add"), s.get("remove")))

    # -- C++/CLI methods implemented in native code (miNative / miUnmanaged, an RVA, no ImplMap row)
    pinv = {p.token for p in parsed.pinvokes}
    for i, r in enumerate(md.MethodDef.rows, 1):
        f = r.ImplFlags
        if r.Rva and (getattr(f, "miNative", False) or getattr(f, "miUnmanaged", False))                 and not getattr(f, "miIL", False) and (dn.METHOD_TOKEN | i) not in pinv:
            m = parsed.methods[i - 1]
            out.natives.append((m.token, int(r.Rva), m.name, parsed.types[(m.type_token & 0xFFFFFF) - 1].name
                                if m.type_token else ""))
    if pe is not None:
        _accesses(md, pe, parsed, out, fowner, tok_of_name)
    return out


def _all_ifaces(tok: int, ifaces: dict[int, list[tuple[str, int | None]]], ty: _Types,
                base_of: dict[int, tuple[str, int | None]]) -> list[tuple[str, int | None]]:
    """The interfaces a type declares plus the ones those inherit (local interface types only)."""
    out: list[tuple[str, int | None]] = []
    seen: set[str] = set()
    todo = list(ifaces.get(tok, []))
    while todo and len(out) < 200:
        t = todo.pop()
        if t[0] in seen:
            continue
        seen.add(t[0])
        out.append(t)
        if t[1] is not None:
            todo += ifaces.get(t[1], [])
    return out


def _accesses(md: Any, pe: Any, parsed: Any, out: Meta, fowner: dict[int, str], type_tok: dict[str, int]) -> None:
    data = pe.__data__
    secs = dn._rva_map(pe)
    res = parsed.res
    by_name: dict[tuple[int, str], int] = {}
    for f in out.fields:
        by_name[(f[1], f[2])] = f[0]
    seen: set[tuple[int, int, str]] = set()
    memo: dict[int, int | None] = {}

    def field_tok(tok: int) -> int | None:
        if tok in memo:
            return memo[tok]
        v: int | None = None
        if tok >> 24 == 0x04:
            v = tok if (tok & 0xFFFFFF) in fowner else None
        elif tok >> 24 == 0x0A:
            try:
                r = md.MemberRef.rows[(tok & 0xFFFFFF) - 1]
                c = r.Class
                tn, ri = getattr(c.table, "name", ""), c.row_index
                if tn == "TypeSpec":
                    ts = res._typespec(ri)
                    tn, ri = ts if ts else ("", 0)
                if tn == "TypeDef":
                    v = by_name.get((dn.TYPE_TOKEN | ri, _s(r.Name)))
            except (ValueError, IndexError, AttributeError):
                v = None
        memo[tok] = v
        return v

    for i, r in enumerate(md.MethodDef.rows, 1):
        rva = r.Rva
        if not rva or not getattr(r.ImplFlags, "miIL", False):
            continue
        off = dn._rva_off(secs, rva)
        body = dn.il_body(data, off) if off is not None else None
        if body is None:
            continue
        caller = dn.METHOD_TOKEN | i
        for kind, tok in scan_fields(body[0]):
            ft = field_tok(tok)
            if ft is not None:
                seen.add((caller, ft, kind))
    out.accesses = sorted(seen)


# -- storing -----------------------------------------------------------------------------------

def write(store: Any, bid: int, meta: Meta) -> None:
    """Fill the tables of one binary (after ``clear``) and add the field access edges. Joins an open
    transaction (the caller commits)."""
    db = store.db
    with store.tx():
        db.executemany("INSERT INTO dn_rel VALUES (?,?,?,?,?)", [(bid, *r) for r in meta.rels])
        db.executemany("INSERT INTO dn_override VALUES (?,?,?,?,?,?,?)", [(bid, *r) for r in meta.overrides])
        db.executemany("INSERT INTO dn_field VALUES (?,?,?,?,?,?,?,?)", [(bid, *r) for r in meta.fields])
        db.executemany("INSERT INTO dn_layout VALUES (?,?,?,?,?)", [(bid, *r) for r in meta.layouts])
        db.executemany("INSERT INTO dn_prop VALUES (?,?,?,?,?,?,?)", [(bid, *r) for r in meta.props])
        db.executemany("INSERT INTO dn_event VALUES (?,?,?,?,?,?,?)", [(bid, *r) for r in meta.events])
        db.executemany("INSERT INTO dn_native VALUES (?,?,?,?,?)", [(bid, *r) for r in meta.natives])
        if meta.accesses:
            ids = {r["entry"]: r["id"] for r in db.execute(
                "SELECT id, entry FROM function WHERE binary_id=? AND space='ram' AND entry>=? AND entry<?",
                (bid, dn.DN_METHOD_LO, dn.DN_METHOD_HI))}
            db.executemany(
                "INSERT INTO edge(binary_id, src_fn, src_addr, dst_fn, dst_addr, kind) VALUES (?,?,?,NULL,?,?)",
                [(bid, ids.get(m), m, f, k) for m, f, k in meta.accesses if m in ids])


# -- queries -----------------------------------------------------------------------------------

def _q(store: Any, sql: str, args: tuple | list = ()) -> list[Any]:
    try:
        return store.db.execute(sql, tuple(args)).fetchall()
    except sqlite3.OperationalError:               # tables not created yet (old index)
        return []


def _marks(n: int) -> str:
    return ",".join("?" * n)


def _name_ok(full: str, q: str) -> bool:
    f, q = full.lower().replace("+", "."), q.lower().replace("+", ".")
    base = f.split("`", 1)[0]
    return f == q or base == q or base.endswith("." + q) or base.endswith("+" + q)


@dataclass
class Hit:
    kind: str                  # impl | override
    bid: int
    token: int
    type_name: str
    name: str
    sig: str
    base_type: str = ""
    base_name: str = ""


def _binary_names(store: Any, bids: list[int]) -> dict[int, str]:
    return {r["id"]: r["name"] for r in _q(store, f"SELECT id, name FROM binary WHERE id IN ({_marks(len(bids))})", bids)}


def _descendants(store: Any, bids: list[int], roots: set[str]) -> dict[str, tuple[int, int, str, str, str]]:
    """Types that implement, extend or inherit from any of the ``roots`` (full names), transitively:
    name -> (binary id, token, type kind, relation, parent name)."""
    found: dict[str, tuple[int, int, str, str, str]] = {}
    frontier = set(roots)
    seen = set(roots)
    for _ in range(10):
        if not frontier:
            break
        rows = _q(store, f"SELECT r.binary_id, r.type_token, r.kind, r.target, t.name, t.kind AS tk FROM dn_rel r "
                         f"JOIN dn_type t ON t.binary_id=r.binary_id AND t.token=r.type_token "
                         f"WHERE r.binary_id IN ({_marks(len(bids))}) AND r.target IN ({_marks(len(frontier))})",
                  [*bids, *frontier])
        nxt: set[str] = set()
        for r in rows:
            if r["name"] in seen and r["name"] in found:
                continue
            rel = ("extends" if r["tk"] == "interface" else "implements") if r["kind"] == "iface" else "inherits"
            found.setdefault(r["name"], (r["binary_id"], r["type_token"], r["tk"], rel, r["target"]))
            if r["name"] not in seen:
                seen.add(r["name"])
                nxt.add(r["name"])
        frontier = nxt
    return found


def _target_names(store: Any, bids: list[int], tq: str) -> set[str]:
    names = {r[0] for r in _q(store, f"SELECT name FROM dn_type WHERE binary_id IN ({_marks(len(bids))})", bids)}
    names |= {r[0] for r in _q(store, f"SELECT DISTINCT target FROM dn_rel WHERE binary_id IN ({_marks(len(bids))})", bids)}
    return {n for n in names if _name_ok(n, tq)}


def _params_ok(have: str, want: str | None) -> bool:
    return want is None or _same_params(have, want)


def member_hits(store: Any, bids: list[int], type_names: set[str], member: str,
                params: str | None = None) -> list[Hit]:
    """Implementations and overrides of ``member`` declared in any of ``type_names``, across the
    binaries ``bids``. An override of an override is found by following the declaring type of each
    hit (a ``newslot`` method starts a new chain and is not an override of the first one)."""
    rows = _q(store, f"SELECT o.binary_id, o.method, o.kind, o.base_type, o.base_name, o.base_params, m.name, m.sig, "
                     f"t.name AS tname FROM dn_override o JOIN dn_method m ON m.binary_id=o.binary_id AND m.token=o.method "
                     f"JOIN dn_type t ON t.binary_id=m.binary_id AND t.token=m.type_token "
                     f"WHERE o.binary_id IN ({_marks(len(bids))}) AND lower(o.base_name)=lower(?)", [*bids, member])
    out: list[Hit] = []
    have: set[tuple[int, int]] = set()
    covered: set[tuple[int, str]] = set()
    frontier, seen = set(type_names), set(type_names)
    while frontier:
        nxt: set[str] = set()
        for r in rows:
            if r["base_type"] not in frontier or not _params_ok(r["base_params"], params):
                continue
            if (r["binary_id"], r["method"]) in have:
                continue
            have.add((r["binary_id"], r["method"]))
            out.append(Hit(r["kind"], r["binary_id"], r["method"], r["tname"], r["name"], r["sig"],
                           r["base_type"], r["base_name"]))
            covered.add((r["binary_id"], r["tname"]))
            if r["tname"] not in seen:
                seen.add(r["tname"])
                nxt.add(r["tname"])
        frontier = nxt
    # implementers of an interface of another assembly (no local interface to match against): by name
    for name, (bid, tok, tk, rel, parent) in _descendants(store, bids, set(type_names)).items():
        if rel != "implements" or tk == "interface" or (bid, name) in covered:
            continue
        for m in _q(store, "SELECT token, name, sig FROM dn_method WHERE binary_id=? AND type_token=? "
                           "AND lower(name)=lower(?) AND flags LIKE '%virtual%' AND flags NOT LIKE '%static%'",
                    (bid, tok, member)):
            if (bid, m["token"]) not in have and _params_ok(dn._params(m["sig"]), params):
                out.append(Hit("impl", bid, m["token"], name, m["name"], m["sig"], parent, member))
                have.add((bid, m["token"]))
                if name not in seen:      # overrides of that implementation in other assemblies
                    seen.add(name)
                    out += [h for h in member_hits(store, bids, {name}, member, params)
                            if (h.bid, h.token) not in have]
                    have.update((h.bid, h.token) for h in out)
    return out


def _split(store: Any, bids: list[int], q: str) -> tuple[set[str], str | None]:
    """(type full names, member) for a query ``Type``, ``Type::Member`` or ``Type.Member``."""
    if "::" in q:
        a, _, b = q.partition("::")
        return _target_names(store, bids, a.strip()), b.strip()
    whole = _target_names(store, bids, q)
    if whole:
        return whole, None
    if "." in q:
        a, _, b = q.rpartition(".")
        names = _target_names(store, bids, a)
        if names:
            return names, b
    return set(), None


def impl_lines(store: Any, bids: list[int], query: str) -> list[str]:
    """Lines for ``dotnet_types kind=impl``: the types that implement / extend / inherit the type
    named by ``query``, or the implementations and overrides of ``Type::Member``."""
    q = query.strip()
    multi = len(bids) > 1
    bn = _binary_names(store, bids)
    pfx = lambda bid: f"[{bn.get(bid, '?')}] " if multi else ""      # noqa: E731
    if not q:
        rows = _q(store, f"SELECT t.binary_id, t.name, (SELECT COUNT(*) FROM dn_rel r WHERE r.target=t.name "
                         f"AND r.kind='iface') AS n FROM dn_type t WHERE t.binary_id IN ({_marks(len(bids))}) "
                         f"AND t.kind='interface' AND t.name NOT LIKE '%<%' ORDER BY t.name", bids)
        return [f"{pfx(r['binary_id'])}interface {r['name']} {r['n']} implementers" for r in rows if r["n"]]
    names, member = _split(store, bids, q)
    if not names:
        return []
    if member is None:
        desc = _descendants(store, bids, names)
        lines = []
        for n, (bid, tok, tk, rel, parent) in sorted(desc.items(), key=lambda kv: (kv[1][3], kv[0])):
            lines.append(f"{pfx(bid)}impl {n} {tk} {rel} {parent}")
        return lines
    out = []
    for h in sorted(member_hits(store, bids, names, member), key=lambda h: (h.type_name, h.name, h.token)):
        out.append(f"{pfx(h.bid)}{h.kind} {h.type_name}::{h.name}{dn._params(h.sig)} 0x{h.token:08x}")
    return out


def _method_row(store: Any, bid: int, token: int) -> Any:
    rows = _q(store, "SELECT m.name, m.sig, t.name AS tname FROM dn_method m JOIN dn_type t "
                     "ON t.binary_id=m.binary_id AND t.token=m.type_token WHERE m.binary_id=? AND m.token=?",
              (bid, token))
    return rows[0] if rows else None


def implementers(store: Any, bids: list[int], bid: int, token: int) -> list[Hit]:
    """The implementations and overrides of one method (interface or virtual), all binaries ``bids``."""
    m = _method_row(store, bid, token)
    if m is None:
        return []
    return member_hits(store, bids, {m["tname"]}, m["name"], dn._params(m["sig"]))


def bases(store: Any, bid: int, token: int) -> list[Hit]:
    """What a method implements or overrides: kind, base type and name (token set when local)."""
    out = []
    for r in _q(store, "SELECT kind, base_token, base_type, base_name, base_params FROM dn_override "
                       "WHERE binary_id=? AND method=?", (bid, token)):
        out.append(Hit(r["kind"], bid, r["base_token"] or 0, r["base_type"], r["base_name"], r["base_params"],
                       r["base_type"], r["base_name"]))
    return out


def link_lines(store: Any, bids: list[int], bid: int, token: int) -> list[str]:
    """``impl Type::Method`` / ``override Type::Method`` lines of the implementations of a method and
    ``implements`` / ``overrides`` lines for the declaration it fills (for xrefs and callgraph)."""
    multi = len(bids) > 1
    bn = _binary_names(store, bids) if multi else {}
    out = []
    for h in bases(store, bid, token):
        out.append(f"{'implements' if h.kind == 'impl' else 'overrides'} {h.base_type}::{h.base_name}")
    for h in sorted(implementers(store, bids, bid, token), key=lambda h: (h.type_name, h.token)):
        pre = f"[{bn.get(h.bid, '?')}] " if multi else ""
        out.append(f"{pre}{h.kind} {h.type_name}::{h.name}{dn._params(h.sig)}")
    return out


def field_label(store: Any, bid: int, token: int) -> str | None:
    rows = _q(store, "SELECT f.name, t.name AS tname FROM dn_field f LEFT JOIN dn_type t "
                     "ON t.binary_id=f.binary_id AND t.token=f.type_token WHERE f.binary_id=? AND f.token=?",
              (bid, token))
    return f"{rows[0]['tname'] or '?'}::{rows[0]['name']}" if rows else None


# -- listings ----------------------------------------------------------------------------------

def iface_map(store: Any, bid: int) -> dict[int, list[str]]:
    """Type token -> short names of its interfaces (for the ``: Base, IFace`` part of type lines)."""
    out: dict[int, list[str]] = {}
    for r in _q(store, "SELECT type_token, target FROM dn_rel WHERE binary_id=? AND kind='iface' ORDER BY rowid", (bid,)):
        out.setdefault(r["type_token"], []).append(_short(r["target"]))
    return out


def _types_for(store: Any, bids: list[int], q: str) -> list[Any]:
    rows = _q(store, f"SELECT binary_id, token, name, kind, flags FROM dn_type WHERE binary_id IN ({_marks(len(bids))}) "
                     f"ORDER BY name", bids)
    return [r for r in rows if _name_ok(r["name"], q)]


def _acc(store: Any, bid: int, ftoken: int) -> tuple[list[str], list[str]]:
    rd, wr = [], []
    for r in _q(store, "SELECT DISTINCT e.kind, t.name AS tname, m.name, m.sig FROM edge e "
                       "JOIN dn_method m ON m.binary_id=e.binary_id AND m.token=e.src_addr "
                       "JOIN dn_type t ON t.binary_id=m.binary_id AND t.token=m.type_token "
                       "WHERE e.binary_id=? AND e.dst_addr=? AND e.kind IN ('read','write') ORDER BY t.name, m.token",
                (bid, ftoken)):
        (wr if r["kind"] == "write" else rd).append(f"{r['tname']}::{r['name']}{dn._params(r['sig'])}")
    return rd, wr


def field_lines(store: Any, bids: list[int], query: str) -> list[str]:
    """``dotnet_types kind=field``: the fields of the types matching ``query`` with their layout
    (``Type`` lists the type; ``Type::Field`` adds the methods that read and write it); a query that
    names no type searches field names."""
    q = query.strip()
    multi = len(bids) > 1
    bn = _binary_names(store, bids)
    pfx = lambda bid: f"[{bn.get(bid, '?')}] " if multi else ""      # noqa: E731
    member = None
    types = _types_for(store, bids, q.partition("::")[0]) if q else []
    if "::" in q:
        member = q.partition("::")[2].strip()
    elif not types and q:
        # field name search
        rows = _q(store, f"SELECT f.binary_id, f.token, f.name, f.sig, f.flags, f.offset, f.const, t.name AS tname FROM dn_field f "
                         f"JOIN dn_type t ON t.binary_id=f.binary_id AND t.token=f.type_token "
                         f"WHERE f.binary_id IN ({_marks(len(bids))}) AND f.name LIKE ? ESCAPE '\\' AND f.name NOT LIKE '%<%' "
                         f"ORDER BY t.name, f.token", [*bids, dn._like(q)])
        if not rows:               # not a field of the project: an enum of the framework (e.g. SpecialFolder)
            return reference_enum_lines(q)
        return [_field_line(r, pfx(r["binary_id"]), r["tname"], None) for r in rows]
    elif not q:
        return []
    out: list[str] = []
    if not types and member is None:
        return []
    for t in types:
        lay = _q(store, "SELECT layout, pack, size FROM dn_layout WHERE binary_id=? AND type_token=?", (t["binary_id"], t["token"]))
        head = f"{pfx(t['binary_id'])}{t['kind']} {t['name']}"
        if lay:
            head += f" {lay[0]['layout']}" + (f" size={lay[0]['size']}" if lay[0]["size"] else "") \
                + (f" pack={lay[0]['pack']}" if lay[0]["pack"] else "")
        frows = _q(store, "SELECT * FROM dn_field WHERE binary_id=? AND type_token=? ORDER BY token", (t["binary_id"], t["token"]))
        if member is not None:
            frows = [f for f in frows if f["name"].lower() == member.lower()]
            if not frows:
                continue
        elif t["kind"] == "enum":
            vf = [f for f in frows if f["name"] == "value__"]
            head += f" : {vf[0]['sig']}" if vf else ""
        out.append(head)
        for f in frows:
            if t["kind"] == "enum" and f["name"] == "value__":
                continue
            out.append("  " + _field_line(f, "", None, t["kind"]))
            if member is not None:
                rd, wr = _acc(store, t["binary_id"], f["token"])
                out += [f"    read by {x}" for x in rd] + [f"    written by {x}" for x in wr]
    return out


def _field_line(f: Any, pfx: str, tname: str | None, tkind: str | None) -> str:
    c = f["const"]
    if tkind == "enum" and c is not None:
        return f"{f['name']} = {c}"
    off = f"+0x{f['offset']:02x} " if f["offset"] is not None else ""
    fl = [x for x in f["flags"].split(",") if x]
    shown = " ".join(x for x in fl if x != "const")
    cval = f" = {c}" if c is not None else ""
    name = f"{tname}::{f['name']}" if tname else f["name"]
    return f"{pfx}{off}{f['sig']} {name}{(' ' + shown) if shown else ''}{cval} 0x{f['token']:08x}"


def property_lines(store: Any, bids: list[int], query: str) -> list[str]:
    q = query.strip()
    multi = len(bids) > 1
    bn = _binary_names(store, bids)
    out = []
    for r in _q(store, f"SELECT p.binary_id, p.name, p.sig, p.getter, p.setter, t.name AS tname FROM dn_prop p "
                       f"JOIN dn_type t ON t.binary_id=p.binary_id AND t.token=p.type_token "
                       f"WHERE p.binary_id IN ({_marks(len(bids))}) ORDER BY t.name, p.token", bids):
        full = f"{r['tname']}::{r['name']}"
        if q and not (_name_ok(r["tname"], q.partition("::")[0]) and (not "::" in q or r["name"].lower() == q.partition("::")[2].lower())
                      or q.lower() in r["name"].lower()):
            continue
        if "<" in r["tname"] and "<" not in q:
            continue
        acc = "/".join(x for x, v in (("get", r["getter"]), ("set", r["setter"])) if v)
        par = dn._params(r["sig"])
        out.append(f"{'[' + bn.get(r['binary_id'], '?') + '] ' if multi else ''}property {full} "
                   f"{r['sig'].partition('(')[0]}{'' if par == '()' else par} {acc}")
    return out


def event_lines(store: Any, bids: list[int], query: str) -> list[str]:
    q = query.strip()
    multi = len(bids) > 1
    bn = _binary_names(store, bids)
    out = []
    for r in _q(store, f"SELECT e.binary_id, e.name, e.etype, e.adder, e.remover, t.name AS tname FROM dn_event e "
                       f"JOIN dn_type t ON t.binary_id=e.binary_id AND t.token=e.type_token "
                       f"WHERE e.binary_id IN ({_marks(len(bids))}) ORDER BY t.name, e.token", bids):
        if q and not (_name_ok(r["tname"], q.partition("::")[0]) and (not "::" in q or r["name"].lower() == q.partition("::")[2].lower())
                      or q.lower() in r["name"].lower()):
            continue
        if "<" in r["tname"] and "<" not in q:
            continue
        acc = "/".join(x for x, v in (("add", r["adder"]), ("remove", r["remover"])) if v)
        out.append(f"{'[' + bn.get(r['binary_id'], '?') + '] ' if multi else ''}event {r['tname']}::{r['name']} "
                   f"{_short(r['etype'])} {acc}")
    return out


def list_lines(store: Any, bids: list[int], query: str, kind: str) -> list[str]:
    if kind == "impl":
        return impl_lines(store, bids, query)
    if kind == "field":
        return field_lines(store, bids, query)
    if kind == "property":
        return property_lines(store, bids, query)
    if kind == "event":
        return event_lines(store, bids, query)
    return []


# -- C++/CLI native bodies ---------------------------------------------------------------------

def native_candidates(store: Any, b: Any) -> list[tuple[int, str, str]]:
    """(address, method name, type name) of the managed methods that have native code: image base +
    RVA. Empty for an IL-only assembly."""
    base = int(b.image_base or 0)
    return [(base + r["rva"], r["name"], r["tname"]) for r in
            _q(store, "SELECT rva, name, tname FROM dn_native WHERE binary_id=? ORDER BY rva", (b.id,))]


def link_native(store: Any, b: Any) -> int:
    """Edges of kind ``native`` from each native MethodDef (its token function) to the Ghidra function at
    image base + RVA, where one exists. Returns how many were written."""
    base = int(b.image_base or 0)
    rows = _q(store, "SELECT token, rva FROM dn_native WHERE binary_id=?", (b.id,))
    if not rows:
        return 0
    db = store.db
    fid = {r["entry"]: r["id"] for r in db.execute(
        "SELECT id, entry FROM function WHERE binary_id=? AND space='ram'", (b.id,))}
    out = [(b.id, fid.get(r["token"]), r["token"], fid[base + r["rva"]], base + r["rva"], "native")
           for r in rows if (base + r["rva"]) in fid and r["token"] in fid]
    with db:
        db.execute("DELETE FROM edge WHERE binary_id=? AND kind='native' AND src_addr>=? AND src_addr<?",
                   (b.id, dn.DN_METHOD_LO, dn.DN_METHOD_HI))
        db.executemany("INSERT INTO edge(binary_id, src_fn, src_addr, dst_fn, dst_addr, kind) VALUES (?,?,?,?,?,?)", out)
    return len(out)


def native_target(store: Any, bid: int, token: int) -> int | None:
    """Address of the native function behind a managed method token, or None."""
    rows = _q(store, "SELECT dst_addr FROM edge WHERE binary_id=? AND src_addr=? AND kind='native' LIMIT 1", (bid, token))
    return int(rows[0][0]) if rows else None


def native_function(store: Any, bid: int, fn: Any) -> Any:
    """The Ghidra Function behind a C++/CLI native method (via its ``native`` edge), or None."""
    a = native_target(store, bid, fn.entry)
    return store.function_at(bid, a) if a is not None else None


def dispatch_links(store: Any, bid: int, token: int, down: bool, limit: int) -> list[tuple[int, Any, str]]:
    """(binary id, Function, label) of the dispatch neighbours of a managed method for the call graph:
    ``down``: its implementations and overrides (``impl`` / ``override``); else the declaration it
    fills (``declaration``). Binaries are all managed ones of the store."""
    bids = [r["id"] for r in _q(store, "SELECT id FROM binary WHERE toolchain='dotnet'")]
    if bid not in bids:
        return []
    out: list[tuple[int, Any, str]] = []
    if down:
        na = native_target(store, bid, token)          # C++/CLI: the native body of the method
        nf = store.function_at(bid, na) if na is not None else None
        if nf is not None:
            out.append((bid, nf, "native"))
        hits = sorted(implementers(store, bids, bid, token), key=lambda h: (h.bid, h.token))
    else:
        hits = [h for h in bases(store, bid, token) if h.token]
    for h in hits[:limit]:
        f = store.function_at(h.bid, h.token)
        if f is not None:
            out.append((h.bid, f, h.kind if down else "declaration"))
    return out


def link_notes(store: Any, bid: int, token: int, limit: int = 20) -> list[str]:
    """``implements`` / ``overrides`` / ``impl`` / ``override`` fact lines of a managed method for xrefs."""
    bids = [r["id"] for r in _q(store, "SELECT id FROM binary WHERE toolchain='dotnet'")]
    if bid not in bids:
        return []
    lines = link_lines(store, bids, bid, token)
    if len(lines) > limit:
        lines = lines[:limit] + [f"… {len(lines) - limit} more implementations"]
    return lines


# -- enum values of the framework (reference assemblies on this machine) ---------------------------

_REF_DIRS = (r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319", r"C:\Program Files\dotnet\shared\Microsoft.NETCore.App")
_REF_DLLS = ("mscorlib.dll", "System.dll", "System.Core.dll", "System.Windows.Forms.dll", "System.Drawing.dll",
             "System.Private.CoreLib.dll", "System.Runtime.InteropServices.dll", "System.Diagnostics.Process.dll")
_enum_cache: dict[str, dict[str, list[tuple[str, str]]]] = {}


def _ref_files() -> list[Any]:
    from pathlib import Path
    out = []
    for d in _REF_DIRS:
        root = Path(d)
        if not root.is_dir():
            continue
        if out:            # one runtime is enough
            break
        # .NET (Core) keeps one folder per runtime version: take the newest
        vers = sorted([x for x in root.iterdir() if x.is_dir() and x.name[:1].isdigit()],
                      key=lambda x: [int(n) if n.isdigit() else 0 for n in x.name.split(".")], reverse=True)
        base = vers[0] if vers and (vers[0] / "System.Private.CoreLib.dll").is_file() else root
        for dll in _REF_DLLS:
            f = base / dll
            if f.is_file():
                out.append(f)
    return out


def _enums_of(path: Any) -> dict[str, list[tuple[str, str]]]:
    """Enum full name -> [(member, value)] of one assembly file (cached per process)."""
    key = f"{path}|{path.stat().st_mtime_ns}"
    if key in _enum_cache:
        return _enum_cache[key]
    out: dict[str, list[tuple[str, str]]] = {}
    try:
        pe = dn._open(path)
        try:
            md = pe.net.mdtables
            consts = {c.Parent.row_index: _const(c) for c in (md.Constant.rows if md.Constant is not None else [])
                      if getattr(c.Parent.table, "name", "") == "Field"}
            tdefs = md.TypeDef.rows
            encl = {r.NestedClass.row_index: r.EnclosingClass.row_index for r in
                    (md.NestedClass.rows if md.NestedClass is not None else [])}

            def full(i: int, d: int = 0) -> str:
                r = tdefs[i - 1]
                if i in encl and d < 6:
                    return f"{full(encl[i], d + 1)}+{r.TypeName}"
                return f"{r.TypeNamespace}.{r.TypeName}" if _s(r.TypeNamespace) else _s(r.TypeName)

            for i, r in enumerate(tdefs, 1):
                ex = r.Extends
                tn = getattr(getattr(ex, "table", None), "name", "")
                if tn == "TypeRef":
                    t = md.TypeRef.rows[ex.row_index - 1]
                    if _s(t.TypeName) != "Enum" or _s(t.TypeNamespace) != "System":
                        continue
                elif tn == "TypeDef":                  # System.Private.CoreLib / mscorlib define System.Enum
                    if full(ex.row_index) != "System.Enum":
                        continue
                else:
                    continue
                out[full(i)] = [(_s(md.Field.rows[f.row_index - 1].Name), consts[f.row_index])
                                for f in (r.FieldList or []) if consts.get(f.row_index) is not None]
        finally:
            pe.close()
    except Exception:  # noqa: BLE001  a reference file that cannot be read is skipped
        out = {}
    _enum_cache[key] = out
    return out


def reference_enum_lines(query: str) -> list[str]:
    """The members of framework enums whose name matches ``query`` (so ``Environment.GetFolderPath(26)``
    can be read as ``SpecialFolder.System``): ``enum Full.Name (file)`` and ``  Member = value`` lines."""
    q = query.strip()
    if not q:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for f in _ref_files():
        for name, members in _enums_of(f).items():
            if name in seen or not _name_ok(name, q):
                continue
            seen.add(name)
            out.append(f"enum {name} ({f.name})")
            out += [f"  {m} = {v}" for m, v in members]
        if out:            # first assembly with a match: parsing every framework assembly takes minutes
            break
    return out


def resolve_field(ctx: Any, binary: str, target: str) -> tuple[str, str] | str | None:
    """``Type::Field`` -> (binary name, ``0x04xxxxxx``) when exactly one managed field matches; an
    ``error ambiguous`` line with the candidates when several do; None when no field matches."""
    tname, _, fname = target.strip().rpartition("::")
    if not tname or not fname or "(" in target:
        return None
    try:
        st = ctx.indexer.store(ctx.indexer.resolve_project(None))
    except Exception:  # noqa: BLE001
        return None
    bn = {b.id: b.name for b in dn.dotnet_binaries(st)}
    if binary.strip():
        bn = {i: n for i, n in bn.items() if n.lower() == binary.strip().lower()}
    if not bn:
        return None
    rows = _q(st, f"SELECT f.binary_id, f.token, t.name AS tname FROM dn_field f JOIN dn_type t ON "
                  f"t.binary_id=f.binary_id AND t.token=f.type_token WHERE f.binary_id IN ({_marks(len(bn))}) "
                  f"AND lower(f.name)=lower(?)", [*bn, fname])
    hits = [r for r in rows if _name_ok(r["tname"], tname)]
    if not hits:
        return None
    if len(hits) > 1:
        shown = ", ".join(f"[{bn[r['binary_id']]}] {r['tname']}::{fname} 0x{r['token']:08x}" for r in hits[:6])
        return f"error ambiguous: '{target}' matches {len(hits)} fields: {shown}."
    return bn[hits[0]["binary_id"]], f"0x{hits[0]['token']:08x}"
