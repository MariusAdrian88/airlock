"""Delphi / Free Pascal classes as targets of ``vtable``, ``function`` and ``xrefs`` (tables ``dl_class``,
``dl_method``). Server side, no Ghidra.

A class is found by name (``TBase``, ``vc.TBase``, case-insensitive) or by an address: its VMT (the address of
virtual slot 0), its type info, or an address inside the virtual slots. Virtual slots use the numbering of the
function hints (``TBase::vslot N``): slot N is the pointer at ``vmt + N * pointer size``.
"""

from __future__ import annotations

from dataclasses import dataclass

from airlock.server.tools.common import Bound


@dataclass(frozen=True)
class ClassHit:
    bd: Bound
    vmt: int
    name: str
    parent: str
    parent_vmt: int
    unit: str
    size: int
    nvirtual: int
    typeinfo: int
    how: str = ""               # "vmt", "type info", "slot N": how the address named the class
    slot: int | None = None     # the slot an interior address points at

    @property
    def full(self) -> str:
        return f"{self.unit}.{self.name}" if self.unit else self.name


_COLS = "c.vmt, c.name, c.parent, c.parent_vmt, c.unit, c.size, c.nvirtual, c.typeinfo"


def _hit(bd: Bound, r, how: str = "", slot: int | None = None) -> ClassHit:
    return ClassHit(bd, r[0], r[1], r[2] or "", r[3] or 0, r[4] or "", r[5] or 0, r[6] or 0, r[7] or 0, how, slot)


def _query(bd: Bound, sql: str, args: tuple) -> list:
    try:
        return bd.store.db.execute(f"SELECT {_COLS} FROM dl_class c WHERE c.binary_id=? AND {sql}",
                                   (bd.binary.id, *args)).fetchall()
    except Exception:  # noqa: BLE001  an index without the Delphi tables
        return []


def find_classes(bounds: list[Bound], value: int) -> list[ClassHit]:
    """Classes whose VMT, type info or virtual slot area holds ``value``."""
    out: list[ClassHit] = []
    for bd in bounds:
        ps = bd.psize
        for r in _query(bd, "(c.vmt=? OR c.typeinfo=? OR (c.vmt<? AND c.vmt + ?*c.nvirtual>?)) "
                            "ORDER BY c.vmt", (value, value, value, ps, value)):
            if r[0] == value:
                out.append(_hit(bd, r, "vmt"))
            elif r[7] == value:
                out.append(_hit(bd, r, "type info"))
            else:
                k = (value - r[0]) // ps
                out.append(_hit(bd, r, f"slot {k}", k))
    return out


def by_name(bounds: list[Bound], want: str, exact: bool = True, limit: int = 20) -> list[ClassHit]:
    """Classes named ``want`` (also ``unit.name``), ignoring case; ``exact=False``: names containing it."""
    w = want.strip().lower()
    out: list[ClassHit] = []
    for bd in bounds:
        if exact:
            rows = _query(bd, "(lower(c.name)=? OR lower(c.unit || '.' || c.name)=?) ORDER BY c.vmt", (w, w))
        else:
            like = "%" + w.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            rows = _query(bd, "lower(c.name) LIKE ? ESCAPE '\\' ORDER BY c.name, c.vmt LIMIT ?", (like, limit))
        out += [_hit(bd, r) for r in rows]
    return out


def all_names(bounds: list[Bound]) -> list[str]:
    names: set[str] = set()
    for bd in bounds:
        try:
            names |= {r[0] for r in bd.store.db.execute("SELECT name FROM dl_class WHERE binary_id=?",
                                                       (bd.binary.id,))}
        except Exception:  # noqa: BLE001
            pass
    return sorted(names)


def fact(h: ClassHit, value: int, several: bool = False) -> str:
    """One fact line: what the address is."""
    where = f"{h.bd.addr(value)} is the {h.how}" if h.how in ("vmt", "type info") else \
        f"{h.bd.addr(value)} is virtual {h.how}"
    pre = f"{h.bd.binary.name}!" if several else ""
    return f"{where} of {'Free Pascal' if h.bd.binary.toolchain == 'fpc' else 'Delphi'} class {pre}{h.full}"


def class_line(h: ClassHit, several: bool = False) -> str:
    pre = f"{h.bd.binary.name}!" if several else ""
    line = f"{pre}{h.name}"
    if h.parent:
        line += f" : {h.parent}"
    if h.unit:
        line += f" unit {h.unit}"
    return line + f" vmt {h.bd.addr(h.vmt)} size {h.size} virtual {h.nvirtual}"


def _slots(bd: Bound, vmt: int) -> dict[int, tuple[str, int]]:
    return {r[0]: (r[1], r[2]) for r in bd.store.db.execute(
        "SELECT slot, name, addr FROM dl_method WHERE binary_id=? AND vmt=? AND kind='virtual' ORDER BY slot",
        (bd.binary.id, vmt))}


def _chain(h: ClassHit) -> list[tuple[str, dict[int, tuple[str, int]]]]:
    """(name, slots) of the class and its ancestors, nearest first."""
    bd = h.bd
    out = [(h.name, _slots(bd, h.vmt))]
    seen = {h.vmt}
    nxt = h.parent_vmt
    while nxt and nxt not in seen and len(out) < 64:
        seen.add(nxt)
        r = bd.store.db.execute("SELECT name, parent_vmt FROM dl_class WHERE binary_id=? AND vmt=?",
                                (bd.binary.id, nxt)).fetchone()
        if r is None:
            break
        out.append((r[0], _slots(bd, nxt)))
        nxt = r[1] or 0
    return out


def _origin(chain: list[tuple[str, dict[int, tuple[str, int]]]], slot: int, addr: int) -> str:
    """Who introduced slot ``slot`` and whose code the class has: `new`, `override, introduced by X`,
    `inherited from Y, introduced by X`."""
    owners = [(n, s[slot][1]) for n, s in chain if slot in s]       # nearest first
    if not owners:
        return ""
    intro = owners[-1][0]
    owner, cur = owners[-1][0], owners[-1][1]
    for n, a in reversed(owners[:-1]):                              # from the introducer down to the class
        if a != cur:
            owner, cur = n, a
    me = chain[0][0]
    if owner == me:
        return "new" if intro == me else f"override, introduced by {intro}"
    return f"inherited from {owner}" + ("" if intro == owner else f", introduced by {intro}")


def _names_of(bd: Bound, addr: int) -> str:
    r = bd.store.db.execute(
        "SELECT c.unit, c.name, m.name FROM dl_method m JOIN dl_class c ON c.binary_id=m.binary_id AND "
        "c.vmt=m.vmt WHERE m.binary_id=? AND m.addr=? AND (m.kind='published' OR m.kind LIKE 'rtti-%') "
        "ORDER BY c.vmt LIMIT 1", (bd.binary.id, addr)).fetchone()
    return f"rtti: {r[0] + '.' if r[0] else ''}{r[1]}.{r[2]}" if r else ""


def slot_lines(h: ClassHit) -> list[str]:
    """`[N] 0xaddr function [slot name] [rtti: Unit.Class.Method] origin` per virtual slot; the slot an
    interior address pointed at ends with ` <-`."""
    bd = h.bd
    chain = _chain(h)
    out: list[str] = []
    for slot, (name, addr) in sorted(chain[0][1].items()):
        fn = bd.store.function_at(bd.binary.id, addr)
        parts = [f"[{slot}] {bd.addr(addr)}"]
        if fn is not None:
            parts.append(fn.qualified_name)
        if name:
            parts.append(f"({name})")
        rt = _names_of(bd, addr)
        if rt:
            parts.append(rt)
        org = _origin(chain, slot, addr)
        line = " ".join(parts) + (f"; {org}" if org else "")
        out.append(line + (" <-" if h.slot == slot else ""))
    return out


def method_lines(h: ClassHit) -> list[str]:
    """Published, RTTI and message methods of the class: `kind name 0xaddr function`."""
    bd = h.bd
    out: list[str] = []
    for r in bd.store.db.execute(
            "SELECT kind, name, addr FROM dl_method WHERE binary_id=? AND vmt=? AND kind<>'virtual' "
            "ORDER BY kind, name, addr", (bd.binary.id, h.vmt)):
        fn = bd.store.function_at(bd.binary.id, r[2])
        out.append(f"{r[0]} {r[1]} {bd.addr(r[2])}{' ' + fn.qualified_name if fn else ''}")
    return out


def vtable_lines(h: ClassHit, several: bool) -> list[str]:
    """Header and slot lines of ``vtable`` for a Delphi / FPC class."""
    return [f"{class_line(h, several)}", *slot_lines(h)]
