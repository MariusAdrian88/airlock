"""Interfaces of Delphi / Free Pascal classes: the ``interface*`` rows of ``dl_method`` (written by
``server/delphi.py``, see the block comment there) as lines for ``vtable`` / ``function``, as address targets
(interface table, interface method table = IMT, the header before a Delphi VMT) and as the index that names
interface calls in decompiled C (``server/vcallnames.py``). Server side, no Ghidra.
"""

from __future__ import annotations

from typing import Any

from airlock.server import delphi
from airlock.server.delphi import INTF_STRIDE, IntfTable

HOW_IMT, HOW_TABLE, HOW_HEADER = "imt", "interface table", "header"
HOWS = (HOW_IMT, HOW_TABLE, HOW_HEADER)      # ClassHit.how values that name an interface structure, not a slot
_PLAIN = ("FUN_", "sub_", "thunk_")


def _q(bd: Any, sql: str, *args: Any) -> list:
    try:
        return bd.store.db.execute(sql, (bd.binary.id, *args)).fetchall()
    except Exception:  # noqa: BLE001  an index without the Delphi tables
        return []


def _owners(bd: Any) -> dict[int, list[tuple[str, str]]]:
    """{code address: [(class, method name)]} of the named methods of the classes."""
    out: dict[int, list[tuple[str, str]]] = {}
    for r in _q(bd, "SELECT m.addr, c.name, m.name FROM dl_method m JOIN dl_class c ON c.binary_id=m.binary_id AND "
                    "c.vmt=m.vmt WHERE m.binary_id=? AND m.name<>'' AND (m.kind IN ('published', 'virtual') OR "
                    "m.kind LIKE 'rtti-%') ORDER BY c.vmt"):
        out.setdefault(r[0], []).append((r[1], r[2]))
    return out


def _impl(bd: Any, owners: dict[int, list[tuple[str, str]]], addr: int, method: str) -> str:
    """Name of the code an interface slot reaches: the Ghidra function, else the class method of that address."""
    fn = bd.store.function_at(bd.binary.id, addr)
    if fn is not None and not fn.name.startswith(_PLAIN):
        return fn.qualified_name
    for cls, name in owners.get(addr, []):
        if name == method:
            return f"{cls}.{name}"
    return ""


def _class_rows(bd: Any, vmt: int) -> tuple[list[tuple[int, IntfTable, int]], dict[int, tuple[str, int]], dict[int, int]]:
    """(tables [(index, parsed name, IMT)], {slot k + index * stride: (row name, thunk)}, {same key: target})."""
    tabs: list[tuple[int, IntfTable, int]] = []
    names: dict[int, tuple[str, int]] = {}
    targets: dict[int, int] = {}
    for r in _q(bd, "SELECT kind, slot, name, addr FROM dl_method WHERE binary_id=? AND vmt=? AND kind IN "
                    "('interface-table', 'interface', 'interface-target') ORDER BY kind, slot", vmt):
        if r[0] == "interface-table":
            t = delphi.parse_intf_table(r[2])
            if t is not None:
                tabs.append((r[1], t, r[3]))
        elif r[0] == "interface-target":
            targets[r[1]] = r[3]
    tabs.sort(key=lambda x: x[0])
    # ``interface`` rows carry the slot only; they follow their table's rows in order, so count them per label
    by_label: dict[str, list[tuple[int, str, int]]] = {}
    for r in _q(bd, "SELECT slot, name, addr FROM dl_method WHERE binary_id=? AND vmt=? AND kind='interface' "
                    "ORDER BY rowid", vmt):
        by_label.setdefault(r[1].split(".", 1)[0], []).append((r[0], r[1], r[2]))
    for idx, t, _imt in tabs:
        rows = by_label.get(t.name, [])
        used = rows[:t.slots]
        by_label[t.name] = rows[t.slots:]
        for slot, name, addr in used:
            names[idx * INTF_STRIDE + slot] = (name, addr)
    return tabs, names, targets


def parent_chain(bd: Any, vmt: int) -> list[int]:
    """VMT addresses of the ancestors of a class, nearest first."""
    out: list[int] = []
    seen = {vmt}
    row = (_q(bd, "SELECT parent_vmt FROM dl_class WHERE binary_id=? AND vmt=?", vmt) or [(0,)])[0]
    nxt = row[0] or 0
    while nxt and nxt not in seen and len(out) < 64:
        seen.add(nxt)
        out.append(nxt)
        row = (_q(bd, "SELECT parent_vmt FROM dl_class WHERE binary_id=? AND vmt=?", nxt) or [(0,)])[0]
        nxt = row[0] or 0
    return out


def virtual_slot(bd: Any, vmt: int, addr: int) -> int | None:
    """The virtual slot of the class whose code is ``addr``, when it is one slot only. A Delphi interface thunk
    that dispatches through the VMT jumps through this slot: the call reaches the code of the object's class, not
    this one. None for Free Pascal (its thunks jump to the method) and for an address that is not a virtual slot."""
    if bd.binary.toolchain == "fpc":
        return None
    rows = _q(bd, "SELECT DISTINCT slot FROM dl_method WHERE binary_id=? AND vmt=? AND kind='virtual' AND addr=?",
              vmt, addr)
    return rows[0][0] if len(rows) == 1 else None


def virtual_impls(bd: Any, vmt: int, slot: int, limit: int = 6,
                  owners: dict[int, list[tuple[str, str]]] | None = None) -> list[str]:
    """Names of the code that virtual slot ``slot`` runs for the class ``vmt`` and for the classes derived from it
    that override it: the class's own first, then the other code addresses, in VMT order (`TBase.Greet`,
    `TDerived.Greet`). A name is the Ghidra function, else a published / RTTI method name of the address, else `Class.Method` of the slot, else the `FUN_` name. At most
    ``limit`` names, then `+N more`."""
    owners = _owners(bd) if owners is None else owners
    kids: dict[int, list[int]] = {}
    for v, pv in _q(bd, "SELECT vmt, parent_vmt FROM dl_class WHERE binary_id=? ORDER BY vmt"):
        kids.setdefault(pv or 0, []).append(v)
    order, todo = [], [vmt]
    while todo and len(order) < 512:
        v = todo.pop(0)
        if v not in order:
            order.append(v)
            todo += kids.get(v, [])
    names: list[str] = []
    seen: set[int] = set()
    for v in order:
        r = _q(bd, "SELECT m.addr, m.name, c.name FROM dl_method m JOIN dl_class c ON c.binary_id=m.binary_id AND "
                   "c.vmt=m.vmt WHERE m.binary_id=? AND m.vmt=? AND m.kind='virtual' AND m.slot=?", v, slot)
        if not r or r[0][0] in seen:
            continue
        addr, mname, cname = r[0]
        seen.add(addr)
        fn = bd.store.function_at(bd.binary.id, addr)
        own = owners.get(addr)
        if fn is not None and not fn.name.startswith(_PLAIN):
            names.append(fn.qualified_name)
        elif own:
            names.append(f"{own[0][0]}.{own[0][1]}")
        elif mname:
            names.append(f"{cname}.{mname}")
        else:
            names.append(fn.name if fn is not None else bd.addr(addr))
    return names[:limit] + ([f"+{len(names) - limit} more"] if len(names) > limit else [])


def iface_lines(bd: Any, vmt: int, mark: tuple[str, int] | None = None) -> list[str]:
    """`interface Name {GUID} imt 0x.. offset N` and per slot `  [k] 0xthunk Method -> 0xtarget Impl` of a class.
    A slot whose thunk dispatches through the VMT reads `  [k] 0xthunk Method -> vslot N (virtual: A.M; B.M)`.
    The interfaces of the ancestors follow with ` inherited from X` on the header line (the class's own table of
    the same interface wins); of those only the slots that dispatch through the VMT are listed, resolved against this class. ``mark``: (interface name, slot) that ends with ` <-`."""
    owners = _owners(bd)
    out: list[str] = []
    done: set[str] = set()
    for owner in [vmt, *parent_chain(bd, vmt)]:
        tabs, names, targets = _class_rows(bd, owner)
        inherited = owner != vmt
        who = ""
        if inherited:
            who = (_q(bd, "SELECT name FROM dl_class WHERE binary_id=? AND vmt=?", owner) or [("",)])[0][0]
        for idx, t, imt in tabs:
            if t.name in done:
                continue
            done.add(t.name)
            head = f"interface {t.name}" + (f" {t.guid}" if t.guid else "") + f" imt {bd.addr(imt)} offset {t.offset}"
            out.append(head + f" slots {t.slots}" + (f" inherited from {who}" if inherited else ""))
            for k in range(t.slots):
                got = names.get(idx * INTF_STRIDE + k)
                if got is None:
                    continue
                method = got[0].split(".", 1)[1] if "." in got[0] else got[0]
                line = f"  [{k}] {bd.addr(got[1])} {method}"
                tg = targets.get(idx * INTF_STRIDE + k)
                vs = virtual_slot(bd, owner, tg) if tg is not None else None
                impls = virtual_impls(bd, vmt, vs, owners=owners) if vs is not None else []
                if inherited and not impls:
                    continue                # the ancestor's listing shows it; only dispatching slots can differ
                if impls:
                    line += f" -> vslot {vs} (virtual: {'; '.join(impls)})"
                elif tg is not None:
                    line += f" -> {bd.addr(tg)}"
                    impl = _impl(bd, owners, tg, method)
                    if impl:
                        line += f" {impl}"
                out.append(line + (" <-" if not inherited and mark == (t.name, k) else ""))
    return out


def find(bd: Any, value: int) -> list[tuple[int, str, int | None, str]]:
    """(class VMT, how, slot, interface name) of the classes whose interface method table, interface table or Delphi
    VMT header holds ``value``."""
    ps = bd.psize
    out: list[tuple[int, str, int | None, str]] = []
    for r in _q(bd, "SELECT vmt, name, addr FROM dl_method WHERE binary_id=? AND kind='interface-table' AND addr<=? "
                    "AND addr>? ORDER BY addr DESC", value, value - ps * delphi.MAX_VIRTUAL):
        t = delphi.parse_intf_table(r[1])
        if t is not None and value < r[2] + ps * t.slots:
            out.append((r[0], HOW_IMT, (value - r[2]) // ps, t.name))
    fpc = bd.binary.toolchain == "fpc"
    for r in _q(bd, "SELECT vmt, slot, addr FROM dl_method WHERE binary_id=? AND kind='interface-tab' AND addr<=? "
                    "AND addr>?", value, value - 0x10000):
        size = ps + r[1] * 5 * ps if fpc else (4 + r[1] * 28 if ps == 4 else 8 + r[1] * 40)
        if value < r[2] + size:
            out.append((r[0], HOW_TABLE, None, ""))
    if not fpc and not out:
        for r in _q(bd, "SELECT h.vmt FROM dl_method h WHERE h.binary_id=? AND h.kind='header' AND h.addr<=? AND "
                        "h.vmt>? AND h.addr>? LIMIT 1", value, value, value - ps * delphi.MAX_SLOTS):
            out.append((r[0], HOW_HEADER, None, ""))
    return out


def index(bd: Any) -> tuple[dict[str, dict[int, tuple[str, list[str]]]], dict[int, str]]:
    """({interface name: {slot: (method, [implementations])}}, {type info address: interface name}) of a
    binary: what an interface call at slot k can be, and which interface a type info belongs to."""
    out: dict[str, dict[int, tuple[str, list[str]]]] = {}
    types: dict[int, str] = {}
    owners = _owners(bd)
    for vmt, in _q(bd, "SELECT DISTINCT vmt FROM dl_method WHERE binary_id=? AND kind='interface-table'"):
        cls = (_q(bd, "SELECT name FROM dl_class WHERE binary_id=? AND vmt=?", vmt) or [("",)])[0][0]
        tabs, names, targets = _class_rows(bd, vmt)
        for idx, t, _imt in tabs:
            if t.typeinfo:
                types[t.typeinfo] = t.name
            slots = out.setdefault(t.name, {})
            for k in range(t.slots):
                got = names.get(idx * INTF_STRIDE + k)
                if got is None:
                    continue
                method = got[0].split(".", 1)[1] if "." in got[0] else got[0]
                tg = targets.get(idx * INTF_STRIDE + k)
                impl = _impl(bd, owners, tg, method) if tg is not None else ""
                cur = slots.setdefault(k, (method, []))
                vs = virtual_slot(bd, vmt, tg) if tg is not None and k >= 3 else None
                if vs is not None:      # the thunk dispatches through the VMT: all the code the slot can run
                    names_ = virtual_impls(bd, vmt, vs)
                    if names_ and names_[0] not in cur[1]:
                        cur[1].extend([f"vslot {vs}: {names_[0]}", *names_[1:]])
                elif impl and impl not in cur[1]:
                    cur[1].append(impl)
                elif not impl and cls and k >= 3 and not method.startswith("#") and f"{cls}.{method}" not in cur[1]:
                    cur[1].append(f"{cls}.{method}")
    return out, types
