"""Itanium C++ ABI demangler for the exports of Win64 Delphi packages (DESIGN 11 "Delphi", "Signature
databases").

Win64 Delphi exports routines as ``_ZN6System7Classes5TList3AddEPv``: a nested name (unit, class, routine)
followed by the parameter types. Only the name is wanted, shown in the style of the 32-bit demangler in
``delphisigs`` (``System.Classes.TList.Add``). The parameter types are parsed too, because template
arguments and substitutions (``S_``, ``S0_``) inside the name refer to them; the substitution table is kept
as the ABI defines it, so a substitution that opens a nested name expands to the right prefix.

Written from the ABI description (no code copied). Not a general demangler: it covers what Delphi emits and
returns None for anything else.
"""

from __future__ import annotations

import re

_BUILTIN = {
    "v": "void", "w": "wchar_t", "b": "bool", "c": "char", "a": "signed char", "h": "unsigned char",
    "s": "short", "t": "unsigned short", "i": "int", "j": "unsigned int", "l": "long",
    "m": "unsigned long", "x": "long long", "y": "unsigned long long", "n": "__int128",
    "o": "unsigned __int128", "f": "float", "d": "double", "e": "long double", "g": "__float128",
    "z": "...",
}
_STD = {"t": "std", "a": "std::allocator", "b": "std::basic_string", "s": "std::string",
        "i": "std::istream", "o": "std::ostream", "d": "std::iostream"}
_OPS = {
    "nw": "new", "na": "new[]", "dl": "delete", "da": "delete[]", "ps": "+", "ng": "-", "ad": "&",
    "de": "*", "co": "~", "pl": "+", "mi": "-", "ml": "*", "dv": "/", "rm": "%", "an": "&", "or": "|",
    "eo": "^", "aS": "=", "pL": "+=", "mI": "-=", "mL": "*=", "dV": "/=", "rM": "%=", "aN": "&=",
    "oR": "|=", "eO": "^=", "ls": "<<", "rs": ">>", "lS": "<<=", "rS": ">>=", "eq": "==", "ne": "!=",
    "lt": "<", "gt": ">", "le": "<=", "ge": ">=", "nt": "!", "aa": "&&", "oo": "||", "pp": "++",
    "mm": "--", "cm": ",", "pm": "->*", "pt": "->", "cl": "()", "ix": "[]", "qu": "?",
}
_SPECIAL = {"cctr": "ClassCreate", "cdtr": "ClassDestroy"}
_GENERIC = re.compile(r"__\d+$")
MAX_DEPTH = 40


class _Fail(Exception):
    pass


class _Parser:
    def __init__(self, s: str) -> None:
        self.s = s
        self.i = 0
        self.subs: list[tuple[str, tuple[str, ...]]] = []   # (text, display components)
        self.depth = 0

    # -- low level
    def peek(self, n: int = 1) -> str:
        return self.s[self.i:self.i + n]

    def take(self) -> str:
        if self.i >= len(self.s):
            raise _Fail
        c = self.s[self.i]
        self.i += 1
        return c

    def expect(self, c: str) -> None:
        if self.take() != c:
            raise _Fail

    def number(self) -> int:
        j = self.i
        while self.i < len(self.s) and self.s[self.i].isdigit():
            self.i += 1
        if j == self.i:
            raise _Fail
        return int(self.s[j:self.i])

    def source_name(self) -> str:
        n = self.number()
        if n == 0 or self.i + n > len(self.s):
            raise _Fail
        t = self.s[self.i:self.i + n]
        self.i += n
        return t

    def push(self, text: str, comps: tuple[str, ...] = ()) -> None:
        self.subs.append((text, comps))

    # -- substitutions
    def substitution(self) -> tuple[str, tuple[str, ...]]:
        self.expect("S")
        c = self.peek()
        if c in _STD:
            self.i += 1
            return _STD[c], tuple(_STD[c].split("::"))
        if c == "_":
            self.i += 1
            idx = 0
        else:
            j = self.i
            while self.i < len(self.s) and (self.s[self.i].isdigit() or self.s[self.i].isupper()):
                self.i += 1
            if self.peek() != "_" or j == self.i:
                raise _Fail
            idx = int(self.s[j:self.i], 36) + 1
            self.i += 1
        if idx >= len(self.subs):
            raise _Fail
        return self.subs[idx]

    # -- template arguments (text is not needed, the table is)
    def template_args(self) -> str:
        self.expect("I")
        out: list[str] = []
        while self.peek() != "E":
            out.append(self.template_arg())
        self.i += 1
        return "<" + ",".join(out) + ">"

    def template_arg(self) -> str:
        c = self.peek()
        if c == "L":
            self.i += 1
            if self.peek(2) == "_Z":
                raise _Fail
            t = self.type_()
            j = self.s.find("E", self.i)
            if j < 0:
                raise _Fail
            v = self.s[self.i:j]
            self.i = j + 1
            return f"({t}){v}"
        if c == "J":
            self.i += 1
            out = []
            while self.peek() != "E":
                out.append(self.template_arg())
            self.i += 1
            return ",".join(out)
        if c == "X":
            raise _Fail
        return self.type_()

    # -- types
    def type_(self) -> str:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise _Fail
        try:
            return self._type()
        finally:
            self.depth -= 1

    def _type(self) -> str:
        c = self.peek()
        if c in _BUILTIN and c != "":
            self.i += 1
            return _BUILTIN[c]
        if c in "PROKVr":
            self.i += 1
            t = self.type_()
            r = {"P": t + "*", "R": t + "&", "O": t + "&&", "K": "const " + t, "V": "volatile " + t,
                 "r": "restrict " + t}[c]
            self.push(r)
            return r
        if c == "D":
            d = self.peek(2)
            if d in ("Dn", "Dd", "De", "Df", "Dh", "Di", "Ds", "Da", "Dc", "Du"):
                self.i += 2
                return "builtin"
            if d == "Dp":
                self.i += 2
                t = self.type_() + "..."
                self.push(t)
                return t
            raise _Fail
        if c == "u":
            self.i += 1
            t = self.source_name()
            self.push(t)
            return t
        if c == "U":
            self.i += 1
            q = self.source_name()
            if self.peek() == "I":
                self.template_args()
            t = q + " " + self.type_()
            self.push(t)
            return t
        if c == "A":
            self.i += 1
            if self.peek() == "_":
                self.i += 1
            else:
                self.number()
                self.expect("_")
            t = self.type_() + "[]"
            self.push(t)
            return t
        if c == "F":
            self.i += 1
            if self.peek() == "Y":
                self.i += 1
            parts = []
            while self.peek() not in ("E", "RE", "OE") and self.peek(2) not in ("RE", "OE"):
                parts.append(self.type_())
            if self.peek(2) in ("RE", "OE"):
                self.i += 1
            self.expect("E")
            t = "fn(" + ",".join(parts) + ")"
            self.push(t)
            return t
        if c == "M":
            self.i += 1
            a = self.type_()
            b = self.type_()
            t = f"{b} {a}::*"
            self.push(t)
            return t
        if c == "T":
            self.i += 1
            while self.peek() != "_":
                self.take()
            self.i += 1
            t = "T"
            self.push(t)
            if self.peek() == "I":
                t += self.template_args()
                self.push(t)
            return t
        if c == "S":
            if self.peek(2) == "St":
                self.i += 2
                n = "std::" + self.source_name()
                self.push(n)
                if self.peek() == "I":
                    n += self.template_args()
                    self.push(n)
                return n
            t = self.substitution()[0]
            if self.peek() == "I":
                t += self.template_args()
                self.push(t)
            return t
        if c == "N":
            return self.nested(as_type=True)[1]
        if c.isdigit():
            n = self.source_name()
            self.push(n, (n,))
            if self.peek() == "I":
                n += self.template_args()
                self.push(n, (_GENERIC.sub("", n.partition("<")[0]) + "<T>",))
            return n
        raise _Fail

    # -- names
    def nested(self, as_type: bool = False) -> tuple[list[str], str]:
        """``N ... E``. Returns (display components, full text). Display: ``TList<T>`` for template ids."""
        self.expect("N")
        while self.peek() in ("K", "V", "r"):
            self.i += 1
        if self.peek() in ("R", "O"):
            self.i += 1
        comps: list[str] = []
        prefix = ""                       # text of the prefix so far (for the substitution table)
        pending = False                   # prefix not yet pushed to the table
        while self.peek() != "E":
            if pending:
                self.push(prefix, tuple(comps))
                pending = False
            c = self.peek()
            if c.isdigit():
                nm = self.source_name()
                comps.append(nm)
                prefix = f"{prefix}::{nm}" if prefix else nm
                pending = True
            elif c == "S":
                if self.peek(2) == "St":
                    self.i += 2
                    prefix, comps = "std", ["std"]
                else:
                    prefix, cc = self.substitution()
                    if not cc:
                        raise _Fail
                    comps = list(cc)
            elif c == "I":
                if not comps:
                    raise _Fail
                if pending:                   # the template name is a candidate before its arguments
                    self.push(prefix, tuple(comps))
                    pending = False
                args = self.template_args()
                prefix += args
                comps[-1] = _GENERIC.sub("", comps[-1]) + "<T>"
                pending = True
            elif c in "CD":
                kind = self.take()
                d = self.take()
                if not d.isdigit():
                    raise _Fail
                comps.append("Create" if kind == "C" else "Destroy")
                prefix += "::" + comps[-1]
                pending = True
            elif c == "v" and self.peek(2)[1:].isdigit():
                self.i += 2                   # Borland: ``v0`` then the name of a class constructor
                nm = self.source_name()
                if nm in ("explicit", "implicit"):
                    self.type_()              # the conversion operator carries its target type
                    nm = "op_" + nm.capitalize()
                comps.append(_SPECIAL.get(nm, nm))
                prefix += "::" + nm
                pending = True
            elif c == "L":
                self.i += 1                   # internal linkage marker
            elif self.peek(2) == "cv":
                self.i += 2
                self.type_()
                comps.append("op_Implicit")
                prefix += "::op_Implicit"
                pending = True
            elif self.peek(2) in _OPS:
                op = self.peek(2)
                self.i += 2
                comps.append("operator" + _OPS[op])
                prefix += "::" + comps[-1]
                pending = True
            else:
                raise _Fail
        self.i += 1
        if as_type:
            self.push(prefix, tuple(comps))
        if not comps:
            raise _Fail
        return comps, prefix


_TYPE_LIKE = re.compile(r"^[TEIP][A-Z]")


def _clean(comps: list[str]) -> str:
    last = comps[-1]
    if len(comps) >= 2 and re.match(r"_[A-Za-z]", last) and not last.startswith("_op_")             and not _TYPE_LIKE.match(comps[-2]) and not re.match(r"_S[A-Z]", last):
        comps = comps[:-1] + ["@" + last[1:]]               # System._LStrAsg -> System.@LStrAsg
    elif last.startswith("_op_"):
        comps = comps[:-1] + [last[1:]]                     # class operators: _op_Multiply -> op_Multiply
    return ".".join(comps)


def demangle(name: str, need_params: bool = False) -> str | None:
    """Name of an Itanium mangled Delphi export in the style of the 32-bit demangler, or None. With
    ``need_params`` an export without a parameter list (data, type info) gives None."""
    if not name.startswith("_Z") or name.startswith(("_ZT", "_ZG", "_ZGV")):
        return None
    p = _Parser(name)
    p.i = 2
    try:
        c = p.peek()
        if c == "N":
            comps, _t = p.nested()
        elif c.isdigit():
            nm = p.source_name()
            comps = [nm]
            if p.peek() == "I":
                p.template_args()
                comps = [_GENERIC.sub("", nm) + "<T>"]
        else:
            return None
    except (_Fail, IndexError):
        return None
    if need_params and p.i >= len(name):
        return None
    return _clean(comps)
