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
WINDOW = 24            # bytes before a dynamic-method call searched for the index load


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
    p = _params(c_text)
    return p[0] if p else None


def skip_comments(c_text: str) -> int:
    """Offset of the first character after the leading comments (``/* .. */`` blocks, ``//`` lines) and blanks:
    the plate comment and the notes block come before the signature and may hold ``(`` and ``{``."""
    i, n = 0, len(c_text)
    while i < n:
        if c_text[i].isspace():
            i += 1
        elif c_text.startswith("/*", i):
            j = c_text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c_text.startswith("//", i):
            j = c_text.find(chr(10), i)
            i = n if j < 0 else j + 1
        else:
            break
    return i


def mask_head(c_text: str) -> str:
    """``c_text`` with the leading comments (plate comment, notes block) blanked out, same length and line breaks:
    nothing a note says is read as code (a ``(`` in the signature search, a ``name = x;`` line, a stub name)."""
    n = skip_comments(c_text)
    return c_text if n == 0 else "".join(ch if ch == chr(10) else " " for ch in c_text[:n]) + c_text[n:]


def _params(c_text: str) -> list[str]:
    """Names of the parameters in the header of the decompiled function."""
    head = c_text[skip_comments(c_text):].split("{", 1)[0]
    i = head.find("(")
    if i < 0:
        return []
    out = []
    for piece in args_of(head, i):
        m = re.search(r"(\w+)$", piece.strip())
        if m and piece.strip() != "void":
            out.append(m.group(1))
    return out


def close_of(text: str, open_at: int) -> int:
    """Offset of the ``)`` that closes the ``(`` at ``open_at`` (the end of the text when it never closes)."""
    d = 0
    for i in range(open_at, len(text)):
        d += (text[i] in "([") - (text[i] in ")]")
        if d == 0:
            return i
    return len(text) - 1


def args_of(text: str, open_at: int) -> list[str]:
    """All arguments of the call whose ``(`` is at ``open_at`` (top level split on commas)."""
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


def _aliases(c_text: str) -> dict[str, list[tuple[int, int, str]]]:
    """{variable: [(offset, brace depth, expression)]} of every ``variable = expression;`` line, in order."""
    out: dict[str, list[tuple[int, int, str]]] = {}
    depth, last = 0, 0
    for m in _ASSIGN.finditer(c_text):
        depth += c_text.count("{", last, m.start()) - c_text.count("}", last, m.start())
        last = m.start()
        out.setdefault(m.group(1), []).append((m.start(2), depth, m.group(2).strip()))
    return out


def _dedupe(xs: list[int]) -> list[int]:
    return list(dict.fromkeys(xs))


_NULLS = ("0", "0x0", "NULL")
_GLOBAL = re.compile(r"^(?:\w*_)?DAT_([0-9a-fA-F]{6,16})$")
MAX_LEVEL = 2          # nesting of "classes of the callers" / "classes written into a global"


class Resolver:
    """Classes of the objects that expressions name in the text of one decompiled function."""

    def __init__(self, c_text: str, cls: Classes, level: int = 0) -> None:
        self.t, self.cls, self.level = c_text, cls, level
        self.al = _aliases(c_text)
        self.params = _params(c_text)

    def depth_at(self, pos: int) -> int:
        return self.t.count("{", 0, pos) - self.t.count("}", 0, pos)

    def classes(self, expr: str, pos: int, depth: int = 0) -> list[int] | None:
        """VMTs of the classes the object can have (all of them when it can have several); None when unknown."""
        if depth > DEPTH:
            return None
        e = _strip(expr)
        if e in _NULLS:
            return []
        if re.fullmatch(r"\w+", e):
            return self._var(e, pos, depth)
        m = _FIELD.match(e)
        if m:
            return self._field(m.group(1), int(m.group(2), 0), pos, depth)
        m = _INDEX.match(e)
        if m:
            return self._field(m.group(1), int(m.group(2), 0) * self.cls.psize, pos, depth)
        m = re.match(r"^\w+\(", e)
        if m:       # a constructor call: its first argument is the VMT of the class
            arg = _strip(first_arg(e, m.end() - 1))
            c = _CLASSREF.search(arg)
            v = self.cls.class_at(int(c.group(1), 16)) if c else None
            return [v] if v is not None else None
        return None

    def _field(self, base_expr: str, offset: int, pos: int, depth: int) -> list[int] | None:
        base = self.classes(base_expr, pos, depth + 1)
        if not base:
            return None
        out: list[int] = []
        for b in base:
            f = self.cls.field_class(b, offset)
            if f is None:
                return None
            out.append(f)
        return _dedupe(out)

    def _var(self, name: str, pos: int, depth: int) -> list[int] | None:
        prior = [a for a in self.al.get(name, []) if a[0] < pos]
        if not prior:
            return self._free(name)
        here, picked, shallow = self.depth_at(pos), [], False
        for a in reversed(prior):       # the nearest store, and every store in a deeper block after it
            picked.append(a)
            if a[1] <= here:
                shallow = True
                break
        if not shallow and len(picked) < 2:
            return None
        out: list[int] = []
        for off, _d, rhs in reversed(picked):
            r = self.classes(rhs, off, depth + 1)
            if r is None:
                return None
            out += r
        return _dedupe(out) or None

    def _free(self, name: str) -> list[int] | None:
        """A variable no store reaches: a parameter or a global."""
        if name in self.params or (name == "in_EAX" and self.cls.psize == 4):
            # 32-bit ``register`` convention: EAX is the first argument (Self) even where the decompiler
            # declares no parameter and names the register ``in_EAX`` (FPC 3.0.4 and 3.2.2 methods, verified)
            k = self.params.index(name) if name in self.params else 0
            if k == 0:
                s = self.cls.self_class()
                if s is not None:
                    return [s]
            f = getattr(self.cls, "caller_classes", None)
            return f(k) if f and self.level < MAX_LEVEL else None
        m = _GLOBAL.match(name)
        f = getattr(self.cls, "global_classes", None)
        return f(int(m.group(1), 16), name) if m and f and self.level < MAX_LEVEL else None


def receiver_class(expr: str, c_text: str, cls: Classes, _aliases_: Resolver | None = None, depth: int = 0,
                   pos: int | None = None) -> int | None:
    """VMT of the class of the object that ``expr`` names (``pos``: where it is used, default the end of the
    text); None when unknown or when it can have several classes."""
    r = _aliases_ if isinstance(_aliases_, Resolver) else Resolver(c_text, cls)
    got = r.classes(expr, len(c_text) if pos is None else pos, depth)
    return got[0] if got and len(got) == 1 else None


def _vcall_label(slot: int, vmts: list[int], cls: Classes) -> str:
    got = [cls.method(v, slot) for v in vmts]
    if len(got) == 1 and got[0][0]:
        name, target = got[0]
        return f"{name} vslot {slot}" + (f" -> {target}" if target else "")
    parts = list(dict.fromkeys(t or n for n, t in got if t or n))
    if len(parts) == 1:
        return f"vslot {slot} -> {parts[0]}"
    return f"vslot {slot}: {' | '.join(parts)}" if parts else f"vslot {slot}"


_PLAIN_CALL = re.compile(r"\(\*\*\(code \*\*\)(?=[(*])")      # (**(code **)(*recv + 0xOFF))(args): 64-bit, no stub
_PLAIN_BODY = re.compile(r"^\*\s*(.+?)\s*(?:\+\s*(0x[0-9a-fA-F]+|\d+))?$", re.S)


def _plain_calls(c_text: str):
    """(position after the callee expression, receiver expression, vmt offset) of the calls that read their target
    straight out of the VMT: ``(**(code **)(*recv + 0xa10))(recv,..)`` and ``(**(code **)*recv)(recv)``."""
    for m in _PLAIN_CALL.finditer(c_text):
        outer = close_of(c_text, m.start())
        inner = c_text[m.end():outer].strip()
        if inner.startswith("(") and close_of(inner, 0) == len(inner) - 1:
            inner = inner[1:-1].strip()
        b = _PLAIN_BODY.match(inner)
        if b and c_text[outer + 1:outer + 2] == "(":
            yield outer + 1, b.group(1), int(b.group(2), 0) if b.group(2) else 0


_DYNA = re.compile(r"(?<![A-Za-z0-9_])(?:(?:thunk_)?FUN_([0-9a-fA-F]{6,16})|[\w.]*@(?:Call|Find)Dyna(Inst|Class)"
                   r"/\*0x([0-9a-fA-F]+)\*/)(?=\()")
_DYNA_NAME = re.compile(r"@(?:Call|Find)Dyna(?:Inst|Class)$")
_VMTREF = re.compile(r"&\s*\w*?_?([0-9a-fA-F]{6,16})\b(?!/\*)")


def annotate(c_text: str, cls: Classes) -> str:
    """``c_text`` with a comment after every virtual-call stub name, dynamic-call name and VMT address."""
    ins: list[tuple[int, str]] = []
    text0, c_text = c_text, mask_head(c_text)          # analysis on the masked text, the comments go in the original
    rs: Resolver | None = None
    from airlock.server.intflabel import intf_label       # interface calls: IMT slot, not a class slot
    for m in _STUB.finditer(c_text):
        il = intf_label(c_text, first_arg(c_text, m.end()), int(m.group(1), 16) // cls.psize, cls)
        if il:
            ins.append((m.end(), f"/*{il}*/"))
            continue
        slot = slot_of(int(m.group(1), 16), cls.psize, cls.fpc)
        if slot is None:
            continue
        if rs is None:
            rs = Resolver(c_text, cls)
        vmts = rs.classes(first_arg(c_text, m.end()), m.start()) or []
        ins.append((m.end(), f"/*{_vcall_label(slot, vmts, cls)}*/"))
    for pos, recv, disp in _plain_calls(c_text):
        il = intf_label(c_text, recv, disp // cls.psize, cls) if disp % cls.psize == 0 else ""
        if il:
            ins.append((pos, f"/*{il}*/"))
            continue
        slot = slot_of(disp, cls.psize, cls.fpc)
        if slot is None:
            continue
        if rs is None:
            rs = Resolver(c_text, cls)
        ins.append((pos, f"/*{_vcall_label(slot, rs.classes(recv, pos) or [], cls)}*/"))
    dyn = getattr(cls, "dynamic_index", None)
    nth: dict[int, int] = {}
    for m in _DYNA.finditer(c_text) if dyn else ():
        addr = int(m.group(1) or m.group(3), 16)
        n = nth[addr] = nth.get(addr, -1) + 1
        idx = dyn(addr, n)
        if idx is None:
            continue
        if rs is None:
            rs = Resolver(c_text, cls)
        arg = _strip(first_arg(c_text, m.end()))
        c = _CLASSREF.search(arg) if cls.dyna_class_call(addr) else None
        direct = cls.class_at(int(c.group(1), 16)) if c else None
        vmts = [direct] if direct is not None else (rs.classes(arg, m.start()) or [])
        ins.append((close_of(c_text, m.end()) + 1, f"/*{cls.dynamic_label(idx, vmts)}*/"))
    for m in _VMTREF.finditer(c_text):
        v = cls.class_at(int(m.group(1), 16))
        name = cls.method(v, -1)[0] if v is not None else ""
        if name:
            ins.append((m.end(), f"/*{name}*/"))
    for pos, text in sorted(ins, reverse=True):
        text0 = text0[:pos] + text + text0[pos:]
    return text0


class DbClasses:
    """``Classes`` over the ``dl_*`` tables of one binary for the function ``entry``."""

    def __init__(self, store: Any, binary: Any, entry: int, level: int = 0, artifact: Any = None) -> None:
        self.store, self.binary, self.bid, self.entry = store, binary, binary.id, entry
        self.level, self.artifact, self._cache = level, artifact, {}
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
        return c[0][0], self._addr_label(addr)

    # -- classes of globals and parameters, dynamic methods --------------------------------------------------

    def _sub(self, entry: int) -> "DbClasses":
        return DbClasses(self.store, self.binary, entry, self.level + 1, self.artifact)

    def _text(self, function_id: int) -> str | None:
        r = self.store.db.execute("SELECT c_text FROM decomp WHERE function_id=? AND c_text IS NOT NULL "
                                  "ORDER BY fn_version DESC LIMIT 1", (function_id,)).fetchone()
        return r[0] if r else None

    def global_classes(self, addr: int, name: str) -> list[int] | None:
        """Classes that all stores into the global at ``addr`` (in the decompiled functions that use it) put there."""
        key = ("g", addr)
        if key not in self._cache:
            self._cache[key] = self._global_classes(addr, name)
        return self._cache[key]

    def _global_classes(self, addr: int, name: str) -> list[int] | None:
        rows = self._q("SELECT DISTINCT a.function_id, f.entry FROM ast_node a JOIN function f ON f.id=a.function_id "
                       "WHERE f.binary_id=? AND a.kind='global_ref' AND a.target=? LIMIT 41", addr)
        if not rows or len(rows) > 40:
            return None
        out: list[int] = []
        for fid, entry in rows:
            text = self._text(fid)
            if text is None:
                return None
            rs = Resolver(text, self._sub(entry), self.level + 1)
            for off, _d, rhs in rs.al.get(name, []):
                got = rs.classes(rhs, off)
                if got is None:
                    return None
                out += got
        return _dedupe(out) or None

    def caller_classes(self, k: int) -> list[int] | None:
        """Classes of argument ``k`` at all the calls of this function; None when one call is unknown."""
        key = ("p", k)
        if key not in self._cache:
            self._cache[key] = self._caller_classes(k)
        return self._cache[key]

    def _caller_classes(self, k: int) -> list[int] | None:
        rows = self._q("SELECT DISTINCT a.function_id, a.start_off, f.entry FROM ast_node a "
                       "JOIN function f ON f.id=a.function_id WHERE f.binary_id=? AND a.kind='call' AND a.target=? "
                       "LIMIT 11", self.entry)
        if not rows or len(rows) > 10:
            return None
        out: list[int] = []
        for fid, off, entry in rows:
            text = self._text(fid)
            if text is None:
                return None
            at = text.find("(", off)
            if at < 0 or not re.fullmatch(r"[\w.@]+(?:/\*[^*]*\*/)?", text[off:at]):
                return None
            args = args_of(text, at)
            if k >= len(args):
                return None
            got = Resolver(text, self._sub(entry), self.level + 1).classes(args[k], off)
            if not got:
                return None
            out += got
        return _dedupe(out) or None

    def _dyn_target(self, vmt: int, idx: int) -> tuple[int, str] | None:
        """(class that declares the entry, its label) for dynamic index ``idx`` seen from class ``vmt``."""
        for v in self._chain(vmt):
            r = self._q("SELECT addr FROM dl_method WHERE binary_id=? AND vmt=? AND kind='dynamic' AND slot=?",
                        v, idx)
            if r:
                return v, self._addr_label(r[0][0])
        return None

    def _addr_label(self, addr: int) -> str:
        """Name of the code at ``addr``: its function name, else the RTTI name of a method, else the function."""
        fn = self.store.function_at(self.bid, addr)
        if fn is not None and not fn.name.startswith(("FUN_", "thunk_FUN_")):
            return fn.qualified_name
        r = self._q("SELECT c.name, m.name FROM dl_method m JOIN dl_class c ON c.binary_id=m.binary_id AND "
                    "c.vmt=m.vmt WHERE m.binary_id=? AND m.addr=? AND m.name<>'' AND "
                    "(m.kind='published' OR m.kind LIKE 'rtti-%') ORDER BY c.vmt LIMIT 1", addr)
        if r:
            return f"{r[0][0]}.{r[0][1]}"
        return fn.qualified_name if fn is not None else f"0x{addr:x}"

    def dynamic_label(self, idx: int, vmts: list[int]) -> str:
        """`dynamic -1 -> TBase.Dyn` (class known), `dynamic -1: A.M | B.M` (every method with that index)."""
        if vmts:
            found = [self._dyn_target(v, idx) for v in vmts]
            names = list(dict.fromkeys(t[1] for t in found if t))
            if names:
                return f"dynamic {idx} -> {' | '.join(names)}"
            return f"dynamic {idx}"
        rows = self._q("SELECT DISTINCT addr FROM dl_method WHERE binary_id=? AND kind='dynamic' AND slot=? "
                       "ORDER BY addr LIMIT 4", idx)
        names = list(dict.fromkeys(self._addr_label(r[0]) for r in rows))
        return f"dynamic {idx}: {' | '.join(names)}" if 0 < len(names) <= 3 else f"dynamic {idx}"

    def _dispatchers(self) -> dict[int, bool]:
        """{entry: True if it takes a class (`CallDynaClass`, `FindDynaClass`)} of the dynamic-method dispatchers."""
        if "d" not in self._cache:
            from airlock.server import libnames
            names = dict(libnames.labels(self.store, self.bid))
            for r in self._q("SELECT entry, name FROM function WHERE binary_id=? AND name LIKE '%Dyna%'"):
                names.setdefault(r[0], r[1])
            self._cache["d"] = {a: n.endswith("Class") for a, n in names.items() if _DYNA_NAME.search(n)}
        return self._cache["d"]

    def helper_names(self) -> dict[int, str]:
        """{entry: name} of the interface reference-count and finalize helpers of the runtime, by call target
        address: the library name (IDR / sigdb) or the Ghidra name. The stored C still says ``FUN_xxxxxxxx``."""
        if "h" not in self._cache:
            from airlock.server import libnames
            keep = re.compile(r"Intf|Finalize|fpc_intf", re.I)
            names = {a: n for a, n in libnames.labels(self.store, self.bid).items() if keep.search(n)}
            for r in self._q("SELECT entry, name FROM function WHERE binary_id=? AND (name LIKE '%Intf%' OR "
                             "name LIKE '%Finalize%') AND substr(name, 1, 4) <> 'FUN_'"):
                names.setdefault(r[0], r[1])
            self._cache["h"] = names
        return self._cache["h"]

    def dyna_class_call(self, target: int) -> bool:
        return self._dispatchers().get(target, False)

    def dynamic_index(self, target: int, n: int) -> int | None:
        """Dynamic method index that the ``n``-th call (in text order) of the dispatcher at ``target`` loads."""
        if target not in self._dispatchers():
            return None
        r = self._q("SELECT id FROM function WHERE binary_id=? AND entry=?", self.entry)
        if not r:
            return None
        sites = self.store.db.execute(
            "SELECT address FROM ast_node WHERE function_id=? AND kind='call' AND target=? ORDER BY start_off",
            (r[0][0], target)).fetchall()
        if n >= len(sites) or self.artifact is None:
            return None
        return dyn_index_before(self.artifact, int(sites[n][0]))


_IMAGES: dict[str, Any] = {}
_DYN_LOADS = re.compile(rb"\x66\xBE(..)|\xBE(....)|\x48\xC7\xC6(....)|\x66\x41\xBB(..)|\x41\xBB(....)", re.S)


def dyn_index_before(artifact: Any, call: int) -> int | None:
    """The signed 16-bit dynamic index that the code before the call at ``call`` loads into SI / ESI / RSI (the
    Delphi dispatchers take it there) or R11: `MOV SI,imm16`, `MOV ESI,imm32`, `MOV RSI,imm32`."""
    key = str(artifact)
    if key not in _IMAGES:
        from airlock.server.cpp import Image
        if len(_IMAGES) > 2:
            _IMAGES.clear()
        _IMAGES[key] = Image.from_pe(artifact)
    img = _IMAGES[key]
    if img is None:
        return None
    for n in (WINDOW, 16, 8):
        b = img.read(call - n, n)
        if b is not None:
            break
    else:
        return None
    best = None
    for i in range(len(b)):
        m = _DYN_LOADS.match(b, i)
        if m and m.end() <= len(b):
            best = m
    if best is None:
        return None
    raw = next(g for g in best.groups() if g is not None)
    v = int.from_bytes(raw[:4], "little") & 0xFFFF
    return v - 0x10000 if v & 0x8000 else v
