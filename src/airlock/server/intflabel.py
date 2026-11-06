"""Names for interface calls in decompiled Pascal C (``vmt_c_adc_0(g, ...)`` where ``g`` is an interface pointer).

An interface call looks like a class call (``CALL [reg + disp]`` through a table), but the table is the IMT of an
interface, so ``disp / pointer size`` is the interface slot and not a class slot. ``intf_label`` decides from the
text of one function whether the receiver is an interface variable and gives ``IGreeter.Greet -> TBase.Greet``
when the interface is known and the slot has one method, else ``intf slot 3: IA.m | IB.n`` or ``intf slot 3``.

A variable is an interface variable when the function passes it to the reference counting helpers of the runtime
(``IntfAddRef``, ``IntfClear``, ``IntfCopy``, ``IntfCast``) or when it is finalized with the type info of an
interface (``FinalizeArray(&v, &typeinfo, n)``: that also gives the interface). Aliases (``local_8 = param_1``)
are followed. Display only; nothing is stored.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any

from airlock.server import classintf

COM_SLOTS = ("QueryInterface", "_AddRef", "_Release")
MAX_SHOWN = 3
_ASSIGN = re.compile(r"^[ \t]*(\w+) = ([^;\n]+);[ \t\r]*$", re.M)
_CAST = re.compile(r"^\((?:const\s+)?[A-Za-z_][\w \t\*]*\)\s*")
_HELPER = re.compile(r"(?<![A-Za-z0-9])(?:Intf(?:AddRef|Clear|Copy|Cast|SetVar|Assign)|fpc_intf_\w+)\w*"
                     r"(?:/\*[^*]*\*/)?\(", re.I)
_FINAL = re.compile(r"(?<![A-Za-z0-9])Finalize(?:Array|Record)?(?:/\*[^*]*\*/)?\(", re.I)
_DAT = re.compile(r"&\s*\w*?_?([0-9a-fA-F]{6,16})\b")
_LOCAL = re.compile(r"^local_([0-9a-fA-F]+)$")


def _args(text: str, open_at: int) -> list[str]:
    d, start, out = 0, open_at + 1, []
    for i in range(open_at, len(text)):
        ch = text[i]
        if ch in "([":
            d += 1
        elif ch in ")]":
            d -= 1
            if d == 0:
                if text[start:i].strip():
                    out.append(text[start:i].strip())
                return out
        elif ch == "," and d == 1:
            out.append(text[start:i].strip())
            start = i + 1
    return out


def _strip(e: str) -> str:
    e = e.strip()
    while True:
        if e.startswith("&"):
            e = e[1:].strip()
        elif _CAST.match(e):
            e = _CAST.sub("", e, count=1).strip()
        elif e.startswith("(") and e.endswith(")") and _args("f" + e, 1) == [e[1:-1].strip()]:
            e = e[1:-1].strip()
        else:
            return e


def _roots(text: str) -> dict[str, str]:
    """{variable: the variable it copies} for every variable that one assignment sets to another plain name."""
    seen: dict[str, set[str]] = {}
    for m in _ASSIGN.finditer(text):
        seen.setdefault(m.group(1), set()).add(_strip(m.group(2)))
    return {v: next(iter(rs)) for v, rs in seen.items() if len(rs) == 1 and re.fullmatch(r"\w+", next(iter(rs)))}


def _root(expr: str, roots: dict[str, str]) -> str:
    e = _strip(expr)
    for _ in range(6):
        if e not in roots:
            break
        e = roots[e]
    return e


def interface_vars(c_text: str, types: dict[int, str], psize: int) -> dict[str, str]:
    """{variable root: interface name or ""} of the variables that the function treats as interface pointers."""
    roots = _roots(c_text)
    out: dict[str, str] = {}
    for m in _HELPER.finditer(c_text):
        for a in _args(c_text, m.end() - 1)[:2]:
            r = _root(a, roots)
            if re.fullmatch(r"\w+", r) and not r.isdigit() and not r.startswith("0x"):
                out.setdefault(r, "")
    for m in _FINAL.finditer(c_text):
        args = _args(c_text, m.end() - 1)
        if len(args) < 2:
            continue
        d = _DAT.search(args[1])
        name = types.get(int(d.group(1), 16), "") if d else ""
        if not name:
            continue
        first = _root(args[0], roots)
        n = int(args[2], 0) if len(args) > 2 and re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", args[2]) else 1
        loc = _LOCAL.match(first)
        names = [first]
        if loc and n > 1:         # an array of n interface slots: the locals go up in memory, local_<off> down in name
            off = int(loc.group(1), 16)
            names += [f"local_{off - i * psize:x}" for i in range(1, n) if off - i * psize > 0]
        for v in names:
            out[v] = name
    return out


def _index(cls: Any) -> tuple[dict[str, dict[int, tuple[str, list[str]]]], dict[int, str]] | None:
    got = getattr(cls, "_intf_index", None)
    if got is not None:
        return got or None
    store = getattr(cls, "store", None)
    if store is None:
        return None
    bd = SimpleNamespace(store=store, psize=cls.psize,
                         binary=SimpleNamespace(id=cls.bid, toolchain="fpc" if cls.fpc else "delphi"))
    try:
        idx = classintf.index(bd)
    except Exception:  # noqa: BLE001  an index without the Delphi tables
        idx = ({}, {})
    try:
        cls._intf_index = idx if idx[0] else ()
    except AttributeError:
        pass
    return idx if idx[0] else None


def _impls(impls: list[str]) -> str:
    if not impls:
        return ""
    more = f" (+{len(impls) - MAX_SHOWN})" if len(impls) > MAX_SHOWN else ""
    return " -> " + " | ".join(impls[:MAX_SHOWN]) + more


def intf_label(c_text: str, recv_expr: str, slot: int, cls: Any) -> str:
    """The comment text (without ``/* */``) for a call through ``slot`` of the receiver ``recv_expr``, or "" when
    the receiver is no known interface variable (the caller then labels it as a class call)."""
    got = _index(cls)
    if got is None:
        return ""
    index, types = got
    cache = getattr(cls, "_intf_vars", None)
    if cache is None or cache[0] is not c_text:
        cache = (c_text, interface_vars(c_text, types, cls.psize))
        try:
            cls._intf_vars = cache
        except AttributeError:
            pass
    root = _root(recv_expr, _roots(c_text))
    if root not in cache[1]:
        return ""
    known = cache[1][root]
    if known and slot in index.get(known, {}):
        method, impls = index[known][slot]
        return f"{known}.{method}{_impls(impls)}"
    if slot < len(COM_SLOTS):
        return f"intf slot {slot}: {COM_SLOTS[slot]}"
    cands: list[tuple[str, str, list[str]]] = []
    for iface, slots in index.items():
        if slot in slots and not slots[slot][0].startswith("#"):
            cands.append((iface, slots[slot][0], slots[slot][1]))
    if len(cands) == 1:
        iface, method, impls = cands[0]
        return f"{iface}.{method}{_impls(impls)}"
    if not cands:
        return f"intf slot {slot}"
    shown = " | ".join(f"{i}.{m}" for i, m, _ in cands[:MAX_SHOWN])
    more = f" (+{len(cands) - MAX_SHOWN})" if len(cands) > MAX_SHOWN else ""
    return f"intf slot {slot}: {shown}{more}"
