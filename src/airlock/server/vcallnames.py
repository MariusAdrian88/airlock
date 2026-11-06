"""Names for the virtual-call stubs in decompiled C (``vmt_508_adc_0(self, a, &r)``).

The worker turns ``CALL [reg + disp]`` of 32-bit Pascal code into a call of a stub whose name holds the vmt
offset and the registers. Here the offset becomes the slot number of the class hints (``TBase::vslot N``: Delphi
slot N is the pointer at ``vmt + N * 4``, Free Pascal slot N at ``vmt + (12 + N) * 4``) and, when the class of
the receiver is known, the method: ``vmt_508_adc_0/*TFormMain vslot 310 -> TFormMain.ButtonClick*/(...)``.

The receiver is the first argument. Its class comes from: ``Self`` (the first parameter of a method, an event
handler or a virtual method of one class), a field of that class with a class type, or an object that the same
function made by a constructor call whose class argument is a VMT address. Display only; nothing is stored.
"""

from __future__ import annotations

import re
from typing import Any, Protocol

_STUB = re.compile(r"(?<![A-Za-z0-9_])vmt_([0-9a-f]{1,8})_([a-z]+)_(\d+)(?=\()")
_CAST = re.compile(r"^\((?:const\s+)?[A-Za-z_][\w \t\*]*\)\s*")
_ASSIGN = re.compile(r"^[ \t]*(\w+) = ([^;\n]+);[ \t\r]*$", re.M)
_FIELD = re.compile(r"^\*\(\s*[A-Za-z_][\w \t\*]*\)\s*\((?:\([\w \t\*]*\))?\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)$")
_INDEX = re.compile(r"^(\w+)\[(0x[0-9a-fA-F]+|\d+)\]$")
_CLASSREF = re.compile(r"&\s*\w*?_?([0-9a-fA-F]{6,8})\b")
FPC_METHOD_START = 12      # pointer slots before the first virtual method of a Free Pascal VMT (delphi.py)
DEPTH = 4


class Classes(Protocol):
    """What the resolver asks of the class tables (``DbClasses`` reads the index)."""
    psize: int
    fpc: bool

    def self_class(self) -> int | None: ...
    def field_class(self, vmt: int, offset: int) -> int | None: ...
    def class_at(self, addr: int) -> int | None: ...
    def method(self, vmt: int, slot: int) -> tuple[str, str]: ...      # (class name, target name or "")


def slot_of(disp: int, psize: int, fpc: bool) -> int | None:
    """Virtual slot (the numbering of the function hints) of a vmt offset; None for a header offset."""
    if disp & 0x80000000:
        return None
    n = disp // psize - (FPC_METHOD_START if fpc else 0)
    return n if n >= 0 and disp % psize == 0 else None


def _strip(e: str) -> str:
    e = e.strip()
    while True:
        m = _CAST.match(e)
        if m and m.end() < len(e):
            e = e[m.end():].strip()
        elif e.startswith("(") and e.endswith(")") and _balanced(e[1:-1]):
            e = e[1:-1].strip()
        else:
            return e


def _balanced(t: str) -> bool:
    d = 0
    for ch in t:
        d += (ch == "(") - (ch == ")")
        if d < 0:
            return False
    return d == 0


def first_arg(text: str, open_at: int) -> str:
    """The first argument of the call whose ``(`` is at ``open_at``."""
    d = 0
    for i in range(open_at, len(text)):
        ch = text[i]
        if ch in "([":
            d += 1
        elif ch in ")]":
            d -= 1
            if d == 0:
                return text[open_at + 1:i]
        elif ch == "," and d == 1:
            return text[open_at + 1:i]
    return ""


def _first_param(c_text: str) -> str | None:
    head = c_text.split("{", 1)[0]
    i = head.find("(")
    if i < 0:
        return None
    piece = first_arg(head, i).strip()
    m = re.search(r"(\w+)$", piece)
    return m.group(1) if m and piece != "void" else None


def _aliases(c_text: str) -> dict[str, str | None]:
    """{variable: expression} of the variables that one assignment sets (None when they get several values)."""
    out: dict[str, str | None] = {}
    for m in _ASSIGN.finditer(c_text):
        v, rhs = m.group(1), m.group(2).strip()
        out[v] = rhs if v not in out or out[v] == rhs else None
    return out


def receiver_class(expr: str, c_text: str, cls: Classes, _aliases_: dict | None = None, depth: int = 0) -> int | None:
    """VMT of the class of the object that ``expr`` names; None when unknown."""
    if depth > DEPTH:
        return None
    al = _aliases_ if _aliases_ is not None else _aliases(c_text)
    e = _strip(expr)
    if re.fullmatch(r"\w+", e):
        if e == _first_param(c_text) and al.get(e) is None:
            return cls.self_class()
        rhs = al.get(e)
        return receiver_class(rhs, c_text, cls, al, depth + 1) if rhs else None
    m = _FIELD.match(e)
    if m:
        base = receiver_class(m.group(1), c_text, cls, al, depth + 1)
        return cls.field_class(base, int(m.group(2), 0)) if base is not None else None
    m = _INDEX.match(e)
    if m:
        base = receiver_class(m.group(1), c_text, cls, al, depth + 1)
        return cls.field_class(base, int(m.group(2), 0) * cls.psize) if base is not None else None
    m = re.match(r"^\w+\(", e)
    if m:       # a constructor call: its first argument is the VMT of the class
        arg = _strip(first_arg(e, m.end() - 1))
        c = _CLASSREF.search(arg)
        return cls.class_at(int(c.group(1), 16)) if c else None
    return None


def annotate(c_text: str, cls: Classes) -> str:
    """``c_text`` with a comment after every virtual-call stub name."""
    ins: list[tuple[int, str]] = []
    al: dict | None = None
    for m in _STUB.finditer(c_text):
        slot = slot_of(int(m.group(1), 16), cls.psize, cls.fpc)
        if slot is None:
            continue
        if al is None:
            al = _aliases(c_text)
        vmt = receiver_class(first_arg(c_text, m.end()), c_text, cls, al)
        name, target = cls.method(vmt, slot) if vmt is not None else ("", "")
        label = f"{name} vslot {slot}" if name else f"vslot {slot}"
        ins.append((m.end(), f"/*{label}{' -> ' + target if target else ''}*/"))
    for pos, text in sorted(ins, reverse=True):
        c_text = c_text[:pos] + text + c_text[pos:]
    return c_text


class DbClasses:
    """``Classes`` over the ``dl_*`` tables of one binary for the function ``entry``."""

    def __init__(self, store: Any, binary: Any, entry: int) -> None:
        self.store, self.bid, self.entry = store, binary.id, entry
        self.psize = binary.pointer_size or 4
        self.fpc = binary.toolchain == "fpc"
        self._self: int | None | bool = False

    def _q(self, sql: str, *args: Any) -> list:
        try:
            return self.store.db.execute(sql, (self.bid, *args)).fetchall()
        except Exception:  # noqa: BLE001  an index without the Delphi tables
            return []

    def _parent(self, vmt: int) -> int | None:
        r = self._q("SELECT parent_vmt FROM dl_class WHERE binary_id=? AND vmt=?", vmt)
        return r[0][0] if r and r[0][0] else None

    def _chain(self, vmt: int) -> list[int]:
        out: list[int] = []
        while vmt and vmt not in out and len(out) < 64:
            out.append(vmt)
            vmt = self._parent(vmt) or 0
        return out

    def self_class(self) -> int | None:
        if self._self is not False:
            return self._self    # type: ignore[return-value]
        found = {r[0] for r in self._q(
            "SELECT DISTINCT m.vmt FROM dl_method m WHERE m.binary_id=? AND m.addr=? AND (m.kind IN "
            "('published','virtual','message','message-str','prop-get','prop-set') OR m.kind LIKE 'rtti-%')",
            self.entry)}
        for r in self._q("SELECT DISTINCT c.vmt FROM dl_event e JOIN dl_form f ON f.binary_id=e.binary_id AND "
                         "f.res_name=e.form JOIN dl_class c ON c.binary_id=f.binary_id AND c.name=f.class "
                         "WHERE e.binary_id=? AND e.addr=?", self.entry):
            found.add(r[0])
        pick = [c for c in found if all(c in self._chain(o) for o in found)]     # every other one descends from it
        self._self = pick[0] if len(pick) == 1 else None
        return self._self

    def field_class(self, vmt: int, offset: int) -> int | None:
        for v in self._chain(vmt):
            r = self._q("SELECT f.type FROM dl_field f WHERE f.binary_id=? AND f.vmt=? AND f.offset=? LIMIT 1",
                        v, offset)
            if r:
                t = self._q("SELECT vmt FROM dl_class WHERE binary_id=? AND name=? ORDER BY vmt LIMIT 1", r[0][0])
                return t[0][0] if t else None
        return None

    def class_at(self, addr: int) -> int | None:
        return addr if self._q("SELECT 1 FROM dl_class WHERE binary_id=? AND vmt=?", addr) else None

    def method(self, vmt: int, slot: int) -> tuple[str, str]:
        c = self._q("SELECT name FROM dl_class WHERE binary_id=? AND vmt=?", vmt)
        if not c:
            return "", ""
        m = self._q("SELECT name, addr FROM dl_method WHERE binary_id=? AND vmt=? AND kind='virtual' AND slot=?",
                    vmt, slot)
        if not m:
            return c[0][0], ""
        name, addr = m[0]
        if name:
            return c[0][0], f"{c[0][0]}.{name}"
        fn = self.store.function_at(self.bid, addr)
        return c[0][0], fn.qualified_name if fn is not None else ""
