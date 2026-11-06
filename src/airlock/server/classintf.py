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


def iface_lines(bd: Any, vmt: int, mark: tuple[str, int] | None = None) -> list[str]:
    """`interface Name {GUID} imt 0x.. offset N` and per slot `  [k] 0xthunk Method -> 0xtarget Impl` of a class.
    ``mark``: (interface name, slot) that ends with ` <-`."""
    tabs, names, targets = _class_rows(bd, vmt)
    if not tabs:
        return []
    owners = _owners(bd)
    out: list[str] = []
    for idx, t, imt in tabs:
        head = f"interface {t.name}" + (f" {t.guid}" if t.guid else "") + f" imt {bd.addr(imt)} offset {t.offset}"
        out.append(head + f" slots {t.slots}")
        for k in range(t.slots):
            got = names.get(idx * INTF_STRIDE + k)
            if got is None:
                continue
            method = got[0].split(".", 1)[1] if "." in got[0] else got[0]
            line = f"  [{k}] {bd.addr(got[1])} {method}"
            tg = targets.get(idx * INTF_STRIDE + k)
            if tg is not None:
                line += f" -> {bd.addr(tg)}"
                impl = _impl(bd, owners, tg, method)
                if impl:
                    line += f" {impl}"
            out.append(line + (" <-" if mark == (t.name, k) else ""))
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
                if impl and impl not in cur[1]:
                    cur[1].append(impl)
                elif not impl and cls and k >= 3 and not method.startswith("#") and f"{cls}.{method}" not in cur[1]:
                    cur[1].append(f"{cls}.{method}")
    return out, types
