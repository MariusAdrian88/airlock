""".NET metadata on the server side (dnfile, no Ghidra), DESIGN.md sections 6 and 11.

``parse_file`` reads an assembly into plain rows (types, methods, P/Invoke declarations).
``ensure`` writes them to the derived tables ``dn_type``/``dn_method``/``dn_pinvoke`` (schema v11)
when they are missing or were written by an older ``DOTNET_VERSION``.

Every managed method becomes a function (space ram, entry = the MethodDef token, size 1). A P/Invoke
method is a thunk plus an import row (address = the same token, dll = the declared module with
``.dll`` added when it has no extension). The normal import linking then binds it to the export of a
project binary and writes an xedge of kind ``pinvoke``, so ``xrefs``, ``callgraph`` and ``path``
follow it like a native import. A module no project binary provides (a system DLL) stays an
unresolved import.

IL bodies are scanned for ``call``, ``callvirt``, ``newobj`` and ``jmp`` (edge kind ``call``) and ``ldftn``,
``ldvirtftn`` (edge kind ``fnptr``) and ``ldtoken`` of a method (kind ``data``); each site keeps its IL offset in ``edge.site``.
``ldstr`` writes a string row (address ``US_BASE | #US offset``) and a ``data`` edge from the method. A state machine stub gets a ``body`` edge to its ``MoveNext``. A target in
the same assembly is an edge to its function. A MemberRef/MethodSpec target in another assembly
is an external function (space EXTERNAL, entry = ``0x0A000000 | MemberRef row``) plus an import row
(dll = assembly name + ``.dll``, name = ``Ns.Type::Method(params)``); ``link_managed`` binds it to a
method of a project assembly with an xedge of kind ``mcall``.

``ilspy_type`` runs ``ilspycmd -t`` for one type; the output is a reconstruction, never a fact.
"""

from __future__ import annotations

import functools
import logging
import os
import re
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock.index.store import DN_METHOD_HI, DN_METHOD_LO, US_BASE, Binary, Function, Store

log = logging.getLogger(__name__)

DOTNET_VERSION = 7            # meta key ``dotnet_version:<binary id>``; older rows are parsed again
TYPE_TOKEN = 0x02000000
METHOD_TOKEN = 0x06000000
REF_LO, REF_HI = 0x0A000000, 0x0B000000      # MemberRef tokens: import slots of external callees
EXT_SPACE = "EXTERNAL"
MODULE_EXT = (".dll", ".exe", ".ocx", ".drv", ".cpl", ".sys", ".tlb")
REMINDER = "// RECONSTRUCTION by ilspycmd: decompiled C#, not the original source. Metadata is the fact."


@dataclass
class DnType:
    token: int
    name: str
    kind: str
    base: str | None
    flags: str


@dataclass
class DnMethod:
    token: int
    type_token: int
    name: str
    sig: str
    flags: str


@dataclass
class DnPInvoke:
    token: int
    module: str
    entry: str | None
    ordinal: int | None
    flags: str


@dataclass
class Parsed:
    types: list[DnType] = field(default_factory=list)
    methods: list[DnMethod] = field(default_factory=list)
    pinvokes: list[DnPInvoke] = field(default_factory=list)
    calls: list[tuple[int, int, str]] = field(default_factory=list)   # caller token, callee token, edge kind
    refs: dict[int, tuple[str, str]] = field(default_factory=dict)    # MemberRef token -> (dll, label)
    res: Any = None                                                   # _Resolver (not stored)
    meta: Any = None                                                  # dotnet_meta.Meta (type-system facts)
    sites: list[tuple[int, int, str, int]] = field(default_factory=list)   # caller, callee, kind, IL offset (one per site)
    strings: dict[int, str] = field(default_factory=dict)             # #US offset -> literal text
    str_sites: list[tuple[int, int, int]] = field(default_factory=list)    # caller, #US offset, IL offset


# -- IL opcodes --------------------------------------------------------------------------------
# Operand size by opcode (-1: undefined). Branch, token and switch operands are told apart by sets.

_OPS1 = """00 nop 01 break 02 ldarg.0 03 ldarg.1 04 ldarg.2 05 ldarg.3 06 ldloc.0 07 ldloc.1 08 ldloc.2
09 ldloc.3 0A stloc.0 0B stloc.1 0C stloc.2 0D stloc.3 0E ldarg.s 0F ldarga.s 10 starg.s 11 ldloc.s
12 ldloca.s 13 stloc.s 14 ldnull 15 ldc.i4.m1 16 ldc.i4.0 17 ldc.i4.1 18 ldc.i4.2 19 ldc.i4.3 1A ldc.i4.4
1B ldc.i4.5 1C ldc.i4.6 1D ldc.i4.7 1E ldc.i4.8 1F ldc.i4.s 20 ldc.i4 21 ldc.i8 22 ldc.r4 23 ldc.r8
25 dup 26 pop 27 jmp 28 call 29 calli 2A ret 2B br.s 2C brfalse.s 2D brtrue.s 2E beq.s 2F bge.s 30 bgt.s
31 ble.s 32 blt.s 33 bne.un.s 34 bge.un.s 35 bgt.un.s 36 ble.un.s 37 blt.un.s 38 br 39 brfalse 3A brtrue
3B beq 3C bge 3D bgt 3E ble 3F blt 40 bne.un 41 bge.un 42 bgt.un 43 ble.un 44 blt.un 45 switch
46 ldind.i1 47 ldind.u1 48 ldind.i2 49 ldind.u2 4A ldind.i4 4B ldind.u4 4C ldind.i8 4D ldind.i
4E ldind.r4 4F ldind.r8 50 ldind.ref 51 stind.ref 52 stind.i1 53 stind.i2 54 stind.i4 55 stind.i8
56 stind.r4 57 stind.r8 58 add 59 sub 5A mul 5B div 5C div.un 5D rem 5E rem.un 5F and 60 or 61 xor
62 shl 63 shr 64 shr.un 65 neg 66 not 67 conv.i1 68 conv.i2 69 conv.i4 6A conv.i8 6B conv.r4 6C conv.r8
6D conv.u4 6E conv.u8 6F callvirt 70 cpobj 71 ldobj 72 ldstr 73 newobj 74 castclass 75 isinst
76 conv.r.un 79 unbox 7A throw 7B ldfld 7C ldflda 7D stfld 7E ldsfld 7F ldsflda 80 stsfld 81 stobj
82 conv.ovf.i1.un 83 conv.ovf.i2.un 84 conv.ovf.i4.un 85 conv.ovf.i8.un 86 conv.ovf.u1.un
87 conv.ovf.u2.un 88 conv.ovf.u4.un 89 conv.ovf.u8.un 8A conv.ovf.i.un 8B conv.ovf.u.un 8C box
8D newarr 8E ldlen 8F ldelema 90 ldelem.i1 91 ldelem.u1 92 ldelem.i2 93 ldelem.u2 94 ldelem.i4
95 ldelem.u4 96 ldelem.i8 97 ldelem.i 98 ldelem.r4 99 ldelem.r8 9A ldelem.ref 9B stelem.i 9C stelem.i1
9D stelem.i2 9E stelem.i4 9F stelem.i8 A0 stelem.r4 A1 stelem.r8 A2 stelem.ref A3 ldelem A4 stelem
A5 unbox.any B3 conv.ovf.i1 B4 conv.ovf.u1 B5 conv.ovf.i2 B6 conv.ovf.u2 B7 conv.ovf.i4 B8 conv.ovf.u4
B9 conv.ovf.i8 BA conv.ovf.u8 C2 refanyval C3 ckfinite C6 mkrefany D0 ldtoken D1 conv.u2 D2 conv.u1
D3 conv.i D4 conv.ovf.i D5 conv.ovf.u D6 add.ovf D7 add.ovf.un D8 mul.ovf D9 mul.ovf.un DA sub.ovf
DB sub.ovf.un DC endfinally DD leave DE leave.s DF stind.i E0 conv.u"""
_OPS2 = """00 arglist 01 ceq 02 cgt 03 cgt.un 04 clt 05 clt.un 06 ldftn 07 ldvirtftn 09 ldarg 0A ldarga
0B starg 0C ldloc 0D ldloca 0E stloc 0F localloc 11 endfilter 12 unaligned. 13 volatile. 14 tail.
15 initobj 16 constrained. 17 cpblk 18 initblk 19 no. 1A rethrow 1C sizeof 1D refanytype 1E readonly."""


def _table(spec: str) -> dict[int, str]:
    w = spec.split()
    return {int(w[i], 16): w[i + 1] for i in range(0, len(w), 2)}


OP1, OP2 = _table(_OPS1), _table(_OPS2)
_B1 = frozenset([0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x1F, *range(0x2B, 0x38), 0xDE])
_B4 = frozenset([0x20, 0x22, *range(0x38, 0x45), 0xDD])
_TOK = frozenset([0x27, 0x28, 0x29, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x79, 0x7B, 0x7C, 0x7D,
                  0x7E, 0x7F, 0x80, 0x81, 0x8C, 0x8D, 0x8F, 0xA3, 0xA4, 0xA5, 0xC2, 0xC6, 0xD0])
_SZ = [-1] * 256
for _o in OP1:
    _SZ[_o] = 4 if (_o in _TOK or _o in _B4) else 1 if _o in _B1 else 8 if _o in (0x21, 0x23) else 0
_SZ2 = [-1] * 256
for _o in OP2:
    _SZ2[_o] = (4 if _o in (0x06, 0x07, 0x15, 0x16, 0x1C) else 2 if 0x09 <= _o <= 0x0E
                else 1 if _o in (0x12, 0x19) else 0)


def _scan_calls(code: bytes) -> list[tuple[int, int, int]]:
    """(kind, token, IL offset) of the call-like instructions of an IL body: kind 0 =
    call/callvirt/newobj/jmp, 1 = ldtoken (the caller keeps method tokens only; calli has no
    static target), 2 = ldstr (token 0x70xxxxxx = #US offset), 3 = ldftn/ldvirtftn, 4 = initobj.
    Stops at an undefined opcode (data, damaged body)."""
    out: list[tuple[int, int, int]] = []
    i, n, sz, sz2 = 0, len(code), _SZ, _SZ2
    frm = int.from_bytes
    while i < n:
        op = code[i]
        if op == 0x28 or op == 0x6F or op == 0x73 or op == 0x27:
            out.append((0, frm(code[i + 1:i + 5], "little"), i))
            i += 5
        elif op == 0xD0:
            out.append((1, frm(code[i + 1:i + 5], "little"), i))
            i += 5
        elif op == 0x72:
            out.append((2, frm(code[i + 1:i + 5], "little"), i))
            i += 5
        elif op == 0xFE:
            if i + 1 >= n:
                break
            o2 = code[i + 1]
            if o2 == 6 or o2 == 7:
                out.append((3, frm(code[i + 2:i + 6], "little"), i))
                i += 6
            elif o2 == 0x15:
                out.append((4, frm(code[i + 2:i + 6], "little"), i))
                i += 6
            else:
                s = sz2[o2]
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


def il_body(data: bytes, off: int) -> tuple[bytes, int] | None:
    """(IL code, header size) of the method body at file offset ``off`` (tiny or fat header; exception
    clauses are not read), or None when the header is not valid."""
    if off < 0 or off + 4 > len(data):
        return None
    b0 = data[off]
    if b0 & 3 == 2:
        size, start = b0 >> 2, off + 1
    elif b0 & 3 == 3:
        hdr = (data[off + 1] >> 4) * 4
        if hdr < 12:
            return None
        size, start = int.from_bytes(data[off + 4:off + 8], "little"), off + hdr
    else:
        return None
    if start + size > len(data):
        return None
    return data[start:start + size], start - off


# -- signatures --------------------------------------------------------------------------------

_PRIM = {0x01: "void", 0x02: "bool", 0x03: "char", 0x04: "sbyte", 0x05: "byte", 0x06: "short",
         0x07: "ushort", 0x08: "int", 0x09: "uint", 0x0A: "long", 0x0B: "ulong", 0x0C: "float",
         0x0D: "double", 0x0E: "string", 0x16: "TypedReference", 0x18: "IntPtr", 0x19: "UIntPtr",
         0x1C: "object"}


class _Blob:
    def __init__(self, data: bytes) -> None:
        self.d, self.p = data, 0

    def byte(self) -> int:
        if self.p >= len(self.d):
            raise ValueError("truncated signature")
        b = self.d[self.p]
        self.p += 1
        return b

    def uint(self) -> int:
        b = self.byte()
        if b & 0x80 == 0:
            return b
        if b & 0xC0 == 0x80:
            return ((b & 0x3F) << 8) | self.byte()
        if b & 0xE0 == 0xC0:
            return ((b & 0x1F) << 24) | (self.byte() << 16) | (self.byte() << 8) | self.byte()
        raise ValueError("bad compressed integer")


def _short(name: str) -> str:
    """Simple type name: no namespace, no generic arity (``List`1`` -> ``List``)."""
    return name.rsplit(".", 1)[-1].split("`", 1)[0].replace("+", ".")


def _type(r: _Blob, names: dict[int, str], depth: int = 0) -> str:
    if depth > 12:
        return "?"
    t = r.byte()
    if t in _PRIM:
        return _PRIM[t]
    if t in (0x11, 0x12):                          # VALUETYPE / CLASS + TypeDefOrRef
        enc = r.uint()
        tag, rid = enc & 3, enc >> 2
        return names.get(((0x02, 0x01, 0x1B)[tag] << 24) | rid, "?") if tag < 3 else "?"
    if t == 0x0F:
        return _type(r, names, depth + 1) + "*"
    if t == 0x10:
        return "ref " + _type(r, names, depth + 1)
    if t == 0x1D:
        return _type(r, names, depth + 1) + "[]"
    if t == 0x14:                                  # ARRAY type rank sizes lobounds
        el = _type(r, names, depth + 1)
        rank = r.uint()
        for _ in range(r.uint()):
            r.uint()
        for _ in range(r.uint()):
            r.uint()
        return el + "[" + "," * (rank - 1) + "]"
    if t == 0x13:
        return f"T{r.uint()}"
    if t == 0x1E:
        return f"M{r.uint()}"
    if t == 0x15:                                  # GENERICINST (CLASS|VALUETYPE) tdr n types
        r.byte()
        enc = r.uint()
        tag, rid = enc & 3, enc >> 2
        base = names.get(((0x02, 0x01, 0x1B)[tag] << 24) | rid, "?") if tag < 3 else "?"
        args = [_type(r, names, depth + 1) for _ in range(r.uint())]
        return f"{base}<{', '.join(args)}>"
    if t in (0x1F, 0x20):                          # custom modifier: skip it
        r.uint()
        return _type(r, names, depth + 1)
    raise ValueError(f"unsupported element type 0x{t:02x}")


def method_sig(blob: bytes, names: dict[int, str]) -> str:
    """``ret(p1, p2)`` from a MethodDefSig blob; ``?`` when it cannot be decoded."""
    try:
        r = _Blob(blob)
        conv = r.byte()
        if conv & 0x10:
            r.uint()                               # generic parameter count
        n = r.uint()
        ret = _type(r, names)
        ps = []
        for _ in range(n):
            if r.d[r.p:r.p + 1] == b"\x41":        # SENTINEL (vararg call sites)
                r.p += 1
            ps.append(_type(r, names))
        return f"{ret}({', '.join(ps)})"
    except (ValueError, IndexError):
        return "?"


# -- parsing -----------------------------------------------------------------------------------

def _flag_names(obj: Any, pairs: tuple[tuple[str, str], ...]) -> list[str]:
    return [label for attr, label in pairs if getattr(obj, attr, False)]


_TD_FLAGS = (("tdPublic", "public"), ("tdNestedPublic", "public"), ("tdAbstract", "abstract"),
             ("tdSealed", "sealed"), ("tdImport", "com"))
_MD_FLAGS = (("mdPublic", "public"), ("mdPrivate", "private"), ("mdFamily", "protected"),
             ("mdAssem", "internal"), ("mdStatic", "static"), ("mdVirtual", "virtual"),
             ("mdAbstract", "abstract"), ("mdPinvokeImpl", "pinvoke"))
_PM_FLAGS = (("pmCharSetAnsi", "ansi"), ("pmCharSetUnicode", "unicode"), ("pmCharSetAuto", "auto"),
             ("pmCallConvStdcall", "stdcall"), ("pmCallConvCdecl", "cdecl"),
             ("pmCallConvFastcall", "fastcall"), ("pmCallConvThiscall", "thiscall"),
             ("pmSupportsLastError", "lasterror"))
_KIND_BY_BASE = {"System.Enum": "enum", "System.ValueType": "struct",
                 "System.MulticastDelegate": "delegate", "System.Delegate": "delegate"}


def _s(v: Any) -> str:
    return "" if v is None else str(v)


_SO_NAME_RE = re.compile(r"\.(so|dylib)(\.\d+)*$", re.I)


def normal_module(module: str) -> str:
    """The file name the P/Invoke probes for: base name, ``.dll`` added without a known extension;
    Unix names (``libgcrypt.so.20``, ``libc.dylib``) stay as written."""
    base = re.split(r"[\\/]", module.strip())[-1]
    return base if base.lower().endswith(MODULE_EXT) or _SO_NAME_RE.search(base) else base + ".dll"


def _open(path: Path | None = None, data: bytes | None = None) -> Any:
    import dnfile

    logging.getLogger("dnfile").setLevel(logging.ERROR)
    return dnfile.dnPE(str(path)) if data is None else dnfile.dnPE(data=data)


def parse_file(path: Path, calls: bool = True) -> Parsed | None:
    """Types, methods, P/Invokes and (with ``calls``) the call edges of the IL bodies of a managed
    assembly; None when dnfile finds no metadata."""
    try:
        pe = _open(path)
    except Exception as e:  # noqa: BLE001  not a PE, damaged headers
        log.warning("dnfile cannot read %s: %s", path.name, e)
        return None
    try:
        net = getattr(pe, "net", None)
        md = getattr(net, "mdtables", None)
        if md is None or md.TypeDef is None or not md.TypeDef.rows:
            return None
        return _parse_tables(md, pe if calls else None)
    finally:
        pe.close()


_GUID = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")


def _blob_string(v: Any) -> str | None:
    """The first SerString of a custom attribute blob (prolog 0x0001), or None."""
    try:
        b = bytes(v)
        if b[:2] != b"\x01\x00":
            return None
        r = _Blob(b[2:])
        n = r.uint()
        return r.d[r.p:r.p + n].decode("utf-8", "replace")
    except (ValueError, IndexError, TypeError):
        return None


def _guids(md: Any, tdefs: list[Any]) -> dict[int, str]:
    """TypeDef token -> GUID from a GuidAttribute on the type."""
    ca = md.CustomAttribute
    mr = md.MemberRef
    trefs = md.TypeRef.rows if md.TypeRef is not None else []
    if ca is None or mr is None or not ca.rows:
        return {}
    ctors: set[int] = set()
    for i, r in enumerate(mr.rows, 1):
        c = r.Class
        if c.table is not None and c.table.name == "TypeRef" and r.Name == ".ctor":
            t = trefs[c.row_index - 1]
            if _s(t.TypeName) == "GuidAttribute" and _s(t.TypeNamespace) == "System.Runtime.InteropServices":
                ctors.add(i)
    out: dict[int, str] = {}
    if not ctors:
        return out
    for r in ca.rows:
        p, t = r.Parent, r.Type
        if (p.table is not None and p.table.name == "TypeDef" and t.table is not None
                and t.table.name == "MemberRef" and t.row_index in ctors):
            g = _blob_string(r.Value.value if r.Value is not None else b"")
            if g and _GUID.match(g.strip("{}")):
                out[TYPE_TOKEN | p.row_index] = g.strip("{}").lower()
    return out


def _params(sig: str) -> str:
    i = sig.find("(")
    return sig[i:] if i >= 0 else "(?)"


class _Resolver:
    """What an IL method token stands for: a method of this assembly (MethodDef, or a MemberRef /
    MethodSpec that points at one) or a method of another assembly (dll + label)."""

    def __init__(self, md: Any, parsed: Parsed, names: dict[int, str]) -> None:
        self.md, self.p, self.names = md, parsed, names
        self.local: dict[tuple[int, str], list[tuple[int, str]]] = {}
        for m in parsed.methods:
            self.local.setdefault((m.type_token, m.name), []).append((m.token, _params(m.sig)))
        self.by_name = {t.name: t.token for t in parsed.types}
        self.type_name = {t.token: t.name for t in parsed.types}
        self.refs = md.TypeRef.rows if md.TypeRef is not None else []
        self.asm = [_s(r.Name) for r in md.AssemblyRef.rows] if md.AssemblyRef is not None else []
        self._tref: dict[int, tuple[str, str | None]] = {}
        self._memo: dict[int, tuple[int | None, str | None, str | None] | None] = {}
        self.field_owner: dict[int, str] = {}                  # Field row -> declaring type (dotnet_meta)

    def tref(self, rid: int, depth: int = 0) -> tuple[str, str | None]:
        """(full name with ``+`` nesting, assembly name or None) of a TypeRef row."""
        got = self._tref.get(rid)
        if got is not None:
            return got
        r = self.refs[rid - 1]
        name, ns = _s(r.TypeName), _s(r.TypeNamespace)
        sc = r.ResolutionScope
        tn = sc.table.name if getattr(sc, "table", None) is not None else ""
        if tn == "TypeRef" and depth < 8 and 0 < sc.row_index <= len(self.refs):
            outer, asm = self.tref(sc.row_index, depth + 1)
            out = (f"{outer}+{name}", asm)
        else:
            asm = self.asm[sc.row_index - 1] if tn == "AssemblyRef" and 0 < sc.row_index <= len(self.asm) else None
            out = (f"{ns}.{name}" if ns else name, asm)
        self._tref[rid] = out
        return out

    def _typespec(self, rid: int) -> tuple[str, int] | None:
        """(table, row) of the generic type behind a TypeSpec (``List<int>`` -> List), else None."""
        try:
            r = _Blob(bytes(self.md.TypeSpec.rows[rid - 1].Signature.value))
            t = r.byte()
            if t == 0x15:
                t = r.byte()
            if t not in (0x11, 0x12):
                return None
            enc = r.uint()
            tag = enc & 3
            return (("TypeDef", "TypeRef")[tag], enc >> 2) if tag < 2 else None
        except (ValueError, IndexError, AttributeError):
            return None

    def _inst(self, rid: int) -> str:
        """``<uint>`` / ``<string, int>``: the type arguments of a generic-instance TypeSpec, else empty."""
        try:
            r = _Blob(bytes(self.md.TypeSpec.rows[rid - 1].Signature.value))
            if r.byte() != 0x15:
                return ""
            r.byte()
            r.uint()
            return "<" + ", ".join(_type(r, self.names) for _ in range(r.uint())) + ">"
        except (ValueError, IndexError, AttributeError):
            return ""

    def _method_inst(self, rid: int) -> str:
        """``<int>``: the method type arguments of a MethodSpec, else empty."""
        try:
            r = _Blob(bytes(self.md.MethodSpec.rows[rid - 1].Instantiation.value))
            if r.byte() != 0x0A:
                return ""
            return "<" + ", ".join(_type(r, self.names) for _ in range(r.uint())) + ">"
        except (ValueError, IndexError, AttributeError):
            return ""

    def _local(self, tok: int, name: str, params: str) -> int | None:
        cands = self.local.get((tok, name))
        if not cands:
            return None
        for t, p in cands:
            if p == params:
                return t
        return cands[0][0] if len(cands) == 1 else None

    def resolve(self, tok: int) -> tuple[int | None, str | None, str | None] | None:
        """(MethodDef token or None, dll, label) of a method token; None when it cannot be named."""
        if tok in self._memo:
            return self._memo[tok]
        try:
            out = self._resolve(tok)
        except (ValueError, IndexError, AttributeError):
            out = None
        self._memo[tok] = out
        return out

    def _resolve(self, tok: int) -> tuple[int | None, str | None, str | None] | None:
        table, rid = tok >> 24, tok & 0xFFFFFF
        if table == 0x06:
            return (tok, None, None) if 0 < rid <= len(self.p.methods) else None
        if table == 0x2B:
            ms = self.md.MethodSpec.rows[rid - 1].Method
            inner = (METHOD_TOKEN if ms.table.name == "MethodDef" else 0x0A000000) | ms.row_index
            return self.resolve(inner) if inner >> 24 != 0x2B else None
        if table != 0x0A:
            return None
        r = self.md.MemberRef.rows[rid - 1]
        raw = bytes(r.Signature.value) if r.Signature is not None else b""
        if not raw or raw[0] & 0x0F == 0x06:                   # a field reference
            return None
        cls = r.Class
        tn, ri = (cls.table.name if cls.table is not None else ""), cls.row_index
        name = _s(r.Name)
        params = _params(method_sig(raw, self.names))
        inst = ""
        if tn == "TypeSpec":
            inst = self._inst(ri)
            ts = self._typespec(ri)
            if ts is None:
                return None
            tn, ri = ts
        if tn == "MethodDef":
            return (METHOD_TOKEN | ri, None, None)
        if tn == "TypeDef":
            t = self._local(TYPE_TOKEN | ri, name, params)
            return (t, None, None) if t is not None else None
        if tn != "TypeRef" or not 0 < ri <= len(self.refs):
            return None
        full, asm = self.tref(ri)
        if asm is None:                                        # a type of this very module
            tdef = self.by_name.get(full)
            t = self._local(tdef, name, params) if tdef is not None else None
            return (t, None, None) if t is not None else None
        if inst:                                               # System.Nullable`1 -> System.Nullable<uint>
            full = re.sub(r"`\d+(?=\+|$)", "", full, count=1) + inst
        return (None, normal_module(asm), f"{full}::{name}{params}")

    def stand_alone(self, rid: int) -> str:
        """Readable calli signature: ``[instance ][unmanaged stdcall ]int(int, string)``."""
        blob = bytes(self.md.StandAloneSig.rows[rid - 1].Signature.value)
        conv = blob[0] if blob else 0
        text = method_sig(blob, self.names)
        kind = {1: "cdecl", 2: "stdcall", 3: "thiscall", 4: "fastcall"}.get(conv & 0x0F)
        pre = ("instance " if conv & 0x20 else "") + (f"unmanaged {kind} " if kind else "")
        return pre + text

    def label(self, tok: int) -> str:
        """Readable name of any IL token operand (method, type, field)."""
        table, rid = tok >> 24, tok & 0xFFFFFF
        try:
            if table in (0x06, 0x0A, 0x2B):
                got = self.resolve(tok)
                if got is None and table == 0x0A:              # field of another type, or unnamed
                    r = self.md.MemberRef.rows[rid - 1]
                    c = r.Class
                    if c.table is not None and c.table.name == "TypeRef":
                        return f"{self.tref(c.row_index)[0]}::{_s(r.Name)}"
                    return _s(r.Name) or "?"
                if got is None:
                    return "?"
                spec = self._method_inst(rid) if table == 0x2B else ""
                if got[0] is not None:
                    m = self.p.methods[(got[0] & 0xFFFFFF) - 1]
                    return f"{self.type_name.get(m.type_token, '?')}::{m.name}{spec}{_params(m.sig)}"
                name, sep, par = (got[2] or "?").partition("(")
                return f"{name}{spec}{sep}{par}"
            if table == 0x11:                                  # StandAloneSig (calli)
                return self.stand_alone(rid)
            if table == 0x02:
                return self.p.types[rid - 1].name
            if table == 0x01:
                return self.tref(rid)[0]
            if table == 0x04:
                owner = self.field_owner.get(rid)
                return f"{owner}::{_s(self.md.Field.rows[rid - 1].Name)}" if owner else _s(self.md.Field.rows[rid - 1].Name)
            if table == 0x1B:
                ts = self._typespec(rid)
                if ts is not None:
                    return self.p.types[ts[1] - 1].name if ts[0] == "TypeDef" else self.tref(ts[1])[0]
                return "typespec"
        except (ValueError, IndexError, AttributeError):
            pass
        return f"0x{tok:08x}"


def _rva_map(pe: Any) -> list[tuple[int, int, int]]:
    return sorted((s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData)
                  for s in pe.sections)


def _rva_off(secs: list[tuple[int, int, int]], rva: int) -> int | None:
    for va, size, raw in secs:
        if va <= rva < va + size:
            return rva - va + raw
    return None


_STATE_NAME = re.compile(r"^(.*)\+<([^>]+)>d__\d+$")


def _user_string_text(us: Any, offset: int) -> str | None:
    """Full text of a #US entry, or None when it cannot be read."""
    try:
        s = us.get(offset, errors="replace")
        return None if s is None else str(s.value if hasattr(s, "value") else s)
    except Exception:  # noqa: BLE001
        return None


def _collect_calls(md: Any, pe: Any, out: Parsed, res: _Resolver) -> None:
    data = pe.__data__
    secs = _rva_map(pe)
    us = getattr(pe.net, "user_strings", None)
    seen: set[tuple[int, int, str]] = set()
    sites: list[tuple[int, int, str, int]] = []
    inits: list[tuple[int, int]] = []                  # caller, TypeDef token of an initobj
    for i, r in enumerate(md.MethodDef.rows, 1):
        rva = r.Rva
        if not rva or not getattr(r.ImplFlags, "miIL", False):
            continue
        off = _rva_off(secs, rva)
        body = il_body(data, off) if off is not None else None
        if body is None:
            continue
        caller = METHOD_TOKEN | i
        for kind, tok, at in _scan_calls(body[0]):
            if kind == 2:
                if tok >> 24 == 0x70 and us is not None:
                    uo = tok & 0xFFFFFF
                    if uo not in out.strings:
                        text = _user_string_text(us, uo)
                        out.strings[uo] = text if text is not None else ""
                    if out.strings[uo]:
                        out.str_sites.append((caller, uo, at))
                continue
            if kind == 4:
                if tok >> 24 == 0x02:
                    inits.append((caller, tok))
                continue
            got = res.resolve(tok) if (tok >> 24) in (0x06, 0x0A, 0x2B) else None
            if got is None:
                continue
            if got[0] is not None:
                callee = got[0]
            else:
                callee = REF_LO | (tok & 0xFFFFFF if tok >> 24 == 0x0A else _spec_ref(res, tok))
                out.refs.setdefault(callee, (got[1] or "", got[2] or ""))
            ek = "call" if kind == 0 else "fnptr" if kind == 3 else "data"
            seen.add((caller, callee, ek))
            sites.append((caller, callee, ek, at))
    out.sites = sites
    out.calls = sorted(seen)
    try:
        _state_machine_edges(md, out, inits)
    except Exception as e:  # noqa: BLE001  an extra link
        log.warning("state machine links stopped: %s: %s", type(e).__name__, e)


_MACHINE_ATTRS = frozenset({"AsyncStateMachineAttribute", "IteratorStateMachineAttribute",
                            "AsyncIteratorStateMachineAttribute"})


def _machine_attributes(md: Any) -> list[tuple[int, str]]:
    """(stub MethodDef token, machine type name with ``+`` nesting) from the state machine attributes."""
    ca, mr = md.CustomAttribute, md.MemberRef
    if ca is None or mr is None or not ca.rows:
        return []
    trefs = md.TypeRef.rows if md.TypeRef is not None else []
    ctors: set[int] = set()
    for i, r in enumerate(mr.rows, 1):
        c = r.Class
        if c.table is not None and c.table.name == "TypeRef" and r.Name == ".ctor":
            if _s(trefs[c.row_index - 1].TypeName) in _MACHINE_ATTRS:
                ctors.add(i)
    out: list[tuple[int, str]] = []
    if not ctors:
        return out
    for r in ca.rows:
        p, t = r.Parent, r.Type
        if (p.table is not None and p.table.name == "MethodDef" and t.table is not None
                and t.table.name == "MemberRef" and t.row_index in ctors):
            name = _blob_string(r.Value.value if r.Value is not None else b"")
            if name:
                out.append((METHOD_TOKEN | p.row_index, name.split(",")[0].strip()))
    return out


def _state_machine_edges(md: Any, out: Parsed, inits: list[tuple[int, int]]) -> None:
    """Edge kind ``body`` from the stub of an async or iterator method to ``MoveNext`` of its
    compiler-generated state machine ``Outer+<Name>d__N``: found by the ``newobj`` of the machine's
    constructor or the ``initobj`` of the machine struct inside a method named ``Name`` of ``Outer``."""
    tname = {t.token: t.name for t in out.types}
    mname = {m.token: m for m in out.methods}
    move: dict[int, int] = {}
    for m in out.methods:
        if m.name == "MoveNext" and m.type_token in tname and _STATE_NAME.match(tname[m.type_token]):
            move[m.type_token] = m.token
    if not move:
        return
    cands: list[tuple[int, int]] = []                  # caller, machine type token
    for caller, callee, kind in out.calls:
        m = mname.get(callee)
        if kind == "call" and m is not None and m.name == ".ctor" and m.type_token in move:
            cands.append((caller, m.type_token))
    cands += [(c, t) for c, t in inits if t in move]
    have = {(a, b) for a, b, k in out.calls if k == "body"}
    by_name = {n: t for t, n in tname.items()}
    for stub, mach in _machine_attributes(md):                # [AsyncStateMachine(typeof(X))] on the stub
        tt = by_name.get(mach)
        if stub in mname and tt in move and (stub, move[tt]) not in have:
            out.calls.append((stub, move[tt], "body"))
            out.sites.append((stub, move[tt], "body", -1))
            have.add((stub, move[tt]))
    for caller, tt in sorted(set(cands)):
        stub = mname.get(caller)
        mt = _STATE_NAME.match(tname[tt])
        if stub is None or mt is None or mt.group(1) != tname.get(stub.type_token):
            continue
        name = mt.group(2)
        if name != stub.name and not name.endswith(stub.name):
            continue
        if (caller, move[tt]) not in have:
            out.calls.append((caller, move[tt], "body"))
            out.sites.append((caller, move[tt], "body", -1))
            have.add((caller, move[tt]))


def _spec_ref(res: _Resolver, tok: int) -> int:
    """MemberRef row behind a MethodSpec token."""
    ms = res.md.MethodSpec.rows[(tok & 0xFFFFFF) - 1].Method
    return ms.row_index


def _parse_tables(md: Any, pe: Any = None) -> Parsed:
    tdefs = md.TypeDef.rows
    trefs = md.TypeRef.rows if md.TypeRef is not None else []
    mdefs = md.MethodDef.rows if md.MethodDef is not None else []
    enclosing: dict[int, int] = {}
    if md.NestedClass is not None:
        for r in md.NestedClass.rows:
            enclosing[r.NestedClass.row_index] = r.EnclosingClass.row_index

    full: dict[int, str] = {}

    def full_name(rid: int, depth: int = 0) -> str:
        if rid in full:
            return full[rid]
        r = tdefs[rid - 1]
        name = _s(r.TypeName)
        up = enclosing.get(rid)
        if up and depth < 8:
            out = f"{full_name(up, depth + 1)}+{name}"
        else:
            ns = _s(r.TypeNamespace)
            out = f"{ns}.{name}" if ns else name
        full[rid] = out
        return out

    names: dict[int, str] = {}            # token -> simple name, for signatures
    for i in range(1, len(tdefs) + 1):
        names[TYPE_TOKEN | i] = _short(full_name(i))
    for i, r in enumerate(trefs, 1):
        names[0x01000000 | i] = _short(f"{_s(r.TypeNamespace)}.{_s(r.TypeName)}")
    ref_full = {0x01000000 | i: (f"{_s(r.TypeNamespace)}.{_s(r.TypeName)}" if _s(r.TypeNamespace)
                                 else _s(r.TypeName)) for i, r in enumerate(trefs, 1)}

    out = Parsed()
    owner: dict[int, int] = {}            # method rid -> type token
    try:
        guids = _guids(md, tdefs)
    except (ValueError, IndexError, AttributeError):
        guids = {}
    for i, r in enumerate(tdefs, 1):
        tok = TYPE_TOKEN | i
        base = None
        ex = r.Extends
        if ex is not None and getattr(ex, "row_index", 0):
            tname = getattr(ex.table, "name", "")
            if tname == "TypeRef":
                base = ref_full.get(0x01000000 | ex.row_index)
            elif tname == "TypeDef" and 0 < ex.row_index <= len(tdefs):
                base = full_name(ex.row_index)
            elif tname == "TypeSpec":
                base = "generic"
        fl = r.Flags
        kind = "interface" if getattr(fl, "tdInterface", False) else _KIND_BY_BASE.get(base or "", "class")
        flags = _flag_names(fl, _TD_FLAGS)
        if kind == "class" and getattr(fl, "tdAbstract", False) and getattr(fl, "tdSealed", False):
            flags = [f for f in flags if f not in ("abstract", "sealed")] + ["static"]
        if i in enclosing:
            flags.append("nested")
        if tok in guids:
            flags.append("guid=" + guids[tok])
        out.types.append(DnType(tok, full_name(i), kind, base, ",".join(dict.fromkeys(flags))))
        for mi in (r.MethodList or []):
            owner[mi.row_index] = tok

    pinv_by_method: dict[int, Any] = {}
    if md.ImplMap is not None:
        for r in md.ImplMap.rows:
            mf = r.MemberForwarded
            if getattr(mf.table, "name", "") == "MethodDef":
                pinv_by_method[mf.row_index] = r

    for i, r in enumerate(mdefs, 1):
        tok = METHOD_TOKEN | i
        raw = r.Signature.value if r.Signature is not None else b""
        sig = method_sig(bytes(raw), names) if raw else "?"
        flags = _flag_names(r.Flags, _MD_FLAGS)
        out.methods.append(DnMethod(tok, owner.get(i, 0), _s(r.Name), sig, ",".join(flags)))
        im = pinv_by_method.get(i)
        if im is None:
            continue
        scope = im.ImportScope
        module = _s(getattr(getattr(scope, "row", None), "Name", None))
        entry = _s(im.ImportName)
        ordinal = None
        if entry.startswith("#") and entry[1:].isdigit():
            ordinal, entry = int(entry[1:]), ""
        out.pinvokes.append(DnPInvoke(
            tok, module, entry or (None if ordinal is not None else _s(r.Name)), ordinal,
            ",".join(_flag_names(im.MappingFlags, _PM_FLAGS))))
    out.res = _Resolver(md, out, names)
    from airlock.server import dotnet_meta               # late: dotnet_meta imports this module
    try:
        out.res.field_owner = dotnet_meta.field_owners(md, out)
        if pe is not None:
            out.meta = dotnet_meta.parse(md, out, pe)
    except Exception as e:  # noqa: BLE001  type-system facts are an extra
        log.warning("type-system metadata stopped: %s: %s", type(e).__name__, e)
    if pe is not None and mdefs:
        try:
            _collect_calls(md, pe, out, out.res)
        except Exception as e:  # noqa: BLE001  the call graph is an extra
            log.warning("IL call scan stopped: %s: %s", type(e).__name__, e)
    return out


# -- the index ---------------------------------------------------------------------------------

def _meta_key(bid: int) -> str:
    return f"dotnet_version:{bid}"


def stale(store: Store, bid: int) -> bool:
    return store.get_meta(_meta_key(bid)) != str(DOTNET_VERSION)


def is_managed(b: Binary, fn: Function) -> bool:
    """A managed method (or P/Invoke thunk) of a .NET binary: it has no machine code to decompile."""
    return b.toolchain == "dotnet" and fn.space == "ram" and DN_METHOD_LO <= fn.entry < DN_METHOD_HI


is_stub = is_managed


def is_managed_site(b: Binary, space: str, addr: int) -> bool:
    """A metadata token address of a .NET binary: a method (ram) or an external callee (EXTERNAL).
    No Ghidra function stands there, so no write tool may send it to the worker."""
    return b.toolchain == "dotnet" and (
        (space == "ram" and DN_METHOD_LO <= addr < DN_METHOD_HI)
        or (space == EXT_SPACE and REF_LO <= addr < REF_HI))


def is_managed_only(b: Binary) -> bool:
    """A managed-only assembly: never imported into Ghidra, so it has no program to write to."""
    return b.format == "dotnet"


def managed_error(b: Binary, fn: Function, store: Store) -> str:
    """One-line error for ``function view=c`` on a managed method."""
    if fn.is_thunk:
        return (f"error managed: {fn.qualified_name} is a P/Invoke declaration with no machine "
                f"code{bound_label(store, b.id, fn.entry)}.")
    return f"error managed: {fn.qualified_name} is managed code with no machine code and no IL listing."


def ensure(store: Store, b: Binary, artifact: Path, force: bool = False) -> bool:
    """Fill the .NET tables of ``b`` (and its P/Invoke thunks and import rows) when missing or
    stale. True when it parsed now. A file without metadata gets no rows and is not parsed again.
    Links to the project's other binaries are not rebuilt here (``Store.link_cross_binary``)."""
    if b.toolchain != "dotnet" or not artifact.is_file():
        return False
    if not force and not stale(store, b.id):
        return False
    with _ensure_lock(store, b.id):
        if not force and not stale(store, b.id):   # another thread parsed it while this one waited
            return False
        return _ensure_locked(store, b, artifact)


_ENSURE_LOCKS: dict[tuple[str, int], threading.Lock] = {}
_ENSURE_GUARD = threading.Lock()


def _ensure_lock(store: Store, bid: int) -> threading.Lock:
    """One lock per binary of one database: the parse and its writes of two callers never interleave."""
    row = store.db.execute("PRAGMA database_list").fetchone()
    key = (str(row[2]) if row else "", bid)
    with _ENSURE_GUARD:
        return _ENSURE_LOCKS.setdefault(key, threading.Lock())


def _ensure_locked(store: Store, b: Binary, artifact: Path) -> bool:
    from airlock.server import dotnet_meta
    parsed = parse_file(artifact)
    db = store.db
    sig_of = {m.token: m.sig for m in parsed.methods} if parsed else {}
    with db:   # one transaction: delete, insert, FTS and version key; a failure leaves the old rows
        for t in ("dn_type", "dn_method", "dn_pinvoke"):
            db.execute(f"DELETE FROM {t} WHERE binary_id=?", (b.id,))
        dotnet_meta.clear(db, b.id)
        db.execute("DELETE FROM xedge WHERE src_binary=? AND kind IN ('pinvoke','mcall')", (b.id,))
        db.execute("DELETE FROM edge WHERE binary_id=? AND src_addr>=? AND src_addr<?",
                   (b.id, DN_METHOD_LO, DN_METHOD_HI))
        db.execute("DELETE FROM string WHERE binary_id=? AND address>=? AND address<?",
                   (b.id, US_BASE, US_BASE + (1 << 32)))
        db.execute("DELETE FROM function WHERE binary_id=? AND ((space='ram' AND entry>=? AND entry<?) "
                   "OR (space=? AND entry>=? AND entry<?))",
                   (b.id, DN_METHOD_LO, DN_METHOD_HI, EXT_SPACE, REF_LO, REF_HI))
        db.execute("DELETE FROM import WHERE binary_id=? AND ((address>=? AND address<?) "
                   "OR (address>=? AND address<?))", (b.id, DN_METHOD_LO, DN_METHOD_HI, REF_LO, REF_HI))
        if parsed is not None:
            db.executemany("INSERT INTO dn_type VALUES (?,?,?,?,?,?)",
                           [(b.id, t.token, t.name, t.kind, t.base, t.flags) for t in parsed.types])
            db.executemany("INSERT INTO dn_method VALUES (?,?,?,?,?,?)",
                           [(b.id, m.token, m.type_token, m.name, m.sig, m.flags)
                            for m in parsed.methods])
            db.executemany("INSERT INTO dn_pinvoke VALUES (?,?,?,?,?,?)",
                           [(b.id, p.token, p.module, p.entry, p.ordinal, p.flags)
                            for p in parsed.pinvokes])
            _write_functions(store, b, parsed, sig_of)
            if parsed.meta is not None:
                dotnet_meta.write(store, b.id, parsed.meta)
        store.rebuild_fts(b.id)
        store.set_meta(_meta_key(b.id), str(DOTNET_VERSION))
    return True


def _write_functions(store: Store, b: Binary, parsed: Parsed, sig_of: dict[int, str]) -> None:
    """Function rows of all methods (P/Invokes as thunks), external callee rows, import rows and
    the call edges of the IL bodies."""
    type_name = {t.token: t.name for t in parsed.types}
    pin = {p.token: p for p in parsed.pinvokes}
    fns: list[dict[str, Any]] = []
    for m in parsed.methods:
        p = pin.get(m.token)
        if p is None:
            fns.append({"entry": m.token, "name": m.name, "name_state": "auto",
                        "namespace": type_name.get(m.type_token), "signature": m.sig,
                        "size": 1, "is_thunk": False})
            continue
        conv = next((f for f in p.flags.split(",") if f in ("stdcall", "cdecl", "fastcall", "thiscall")), None)
        fns.append({"entry": p.token, "name": m.name, "name_state": "auto",
                    "namespace": type_name.get(m.type_token),
                    "signature": f"{sig_of.get(p.token, '?')} [{normal_module(p.module)}!"
                                 f"{p.entry if p.entry else '#' + str(p.ordinal)}]",
                    "calling_conv": conv, "size": 1, "is_thunk": True})
    ext = sorted(parsed.refs.items())
    for tok, (dll, label) in ext:
        fns.append({"space": EXT_SPACE, "entry": tok, "name": label, "name_state": "library",
                    "namespace": dll, "size": 1, "is_external": True})
    store.insert_functions(b.id, fns)
    store.insert_imports(b.id, [(normal_module(p.module), p.entry, p.ordinal, p.token)
                                for p in parsed.pinvokes]
                         + [(dll, label, None, tok) for tok, (dll, label) in ext])
    if not parsed.sites:
        return
    ids = {r["entry"]: r["id"] for r in store.db.execute(
        "SELECT id, entry FROM function WHERE binary_id=? AND space='ram' AND entry>=? AND entry<?",
        (b.id, DN_METHOD_LO, DN_METHOD_HI))}
    _write_edges(store, b, parsed, ids)


def _write_edges(store: Store, b: Binary, parsed: Parsed, ids: dict[int, int]) -> None:
    """Edge rows with the IL offset of each call site (``site``; NULL for a ``body`` link), the
    user-string rows (address ``US_BASE | #US offset``) and one ``data`` edge per ``ldstr``."""
    rows = [(b.id, ids[a], a, ids.get(c), c, k, at if at >= 0 else None)
            for a, c, k, at in parsed.sites if a in ids]
    srows = [(b.id, ids[a], a, None, US_BASE | uo, "data", at)
             for a, uo, at in parsed.str_sites if a in ids]
    with store.tx():
        store.db.executemany(
            "INSERT INTO edge(binary_id, src_fn, src_addr, dst_fn, dst_addr, kind, site) "
            "VALUES (?,?,?,?,?,?,?)", rows + srows)
        store.db.executemany(
            "INSERT INTO string(binary_id, address, encoding, value) VALUES (?,?,'utf16le',?)",
            [(b.id, US_BASE | uo, text) for uo, text in sorted(parsed.strings.items()) if text])


def ensure_project(store: Store, artifacts: Path, ready: list[int]) -> int:
    """``ensure`` for every managed binary of the project; relinks the ones parsed now against the
    other ``ready`` binaries. A binary that is not ``ready`` is skipped: its own job (still running)
    writes the tables. Returns how many were parsed."""
    n = 0
    for b in store.list_binaries():
        if store.get_meta(f"status:{b.id}") != "ready":
            continue
        try:
            if ensure(store, b, artifacts / b.sha256):
                n += 1
                store.link_cross_binary(b.id, [i for i in ready if i != b.id])
        except Exception as e:  # noqa: BLE001  metadata is an extra
            log.warning(".NET metadata of %s: %s", b.name, e)
    return n


def dotnet_binaries(store: Store) -> list[Binary]:
    return [b for b in store.list_binaries() if b.toolchain == "dotnet"]


def _stem(name: str | None) -> str:
    n = (name or "").strip().lower()
    return n[:-4] if n.endswith(MODULE_EXT) else n


def _open_name(name: str) -> str:
    """Metadata name of a readable generic instance: ``System.Tuple<string, int>`` -> ``System.Tuple`2``."""
    i = name.find("<")
    if i < 0:
        return name
    depth, n = 0, 1
    for ch in name[i:]:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
            if depth == 0:
                break
        elif ch == "," and depth == 1:
            n += 1
    j = name.rfind(">")
    return f"{name[:i]}`{n}{name[j + 1:]}"


def link_managed(store: Store, src_id: int, dst_id: int) -> int:
    """Bind the external method references of managed binary ``src_id`` that name assembly
    ``dst_id`` to its methods (type + name + parameter list; a single overload may match by name
    alone). Writes xedges of kind ``mcall`` from the reference slot (MemberRef token) to the
    method token. Returns how many references were bound."""
    src, dst = store.get_binary_by_id(src_id), store.get_binary_by_id(dst_id)
    if src is None or dst is None or src_id == dst_id:
        return 0
    with store.db:
        store.db.execute("DELETE FROM xedge WHERE src_binary=? AND dst_binary=? AND kind='mcall'",
                         (src_id, dst_id))
    if src.toolchain != "dotnet" or dst.toolchain != "dotnet":
        return 0
    want = _stem(dst.name)
    refs = [r for r in store.db.execute("SELECT dll, name, address FROM import WHERE binary_id=? "
                                        "AND address>=? AND address<?", (src_id, REF_LO, REF_HI))
            if _stem(r["dll"]) == want]
    if not refs:
        return 0
    types = {r["name"]: r["token"] for r in store.db.execute(
        "SELECT name, token FROM dn_type WHERE binary_id=?", (dst_id,))}
    methods: dict[tuple[int, str], list[tuple[int, str]]] = {}
    for r in store.db.execute("SELECT token, type_token, name, sig FROM dn_method WHERE binary_id=?", (dst_id,)):
        methods.setdefault((r["type_token"], r["name"]), []).append((r["token"], _params(r["sig"])))
    rows = []
    for r in refs:
        head, _, tail = (r["name"] or "").partition("::")
        meth, par, rest = tail.partition("(")
        tok = types.get(_open_name(head))
        cands = methods.get((tok, meth)) if tok is not None else None
        if not cands:
            continue
        params = par + rest
        hit = next((t for t, p in cands if p == params), None)
        if hit is None and len(cands) == 1:
            hit = cands[0][0]
        if hit is not None:
            rows.append((src_id, r["address"], dst_id, hit, "mcall"))
    with store.db:
        store.db.executemany("INSERT INTO xedge(src_binary, src_addr, dst_binary, dst_entry, kind) "
                             "VALUES (?,?,?,?,?)", list(dict.fromkeys(rows)))
    return len(rows)


# -- IL listing --------------------------------------------------------------------------------

_LISTING: dict[str, Any] = {}
_LISTING_LOCK = threading.Lock()
LISTING_KEEP_S = 120


def _drop_listing() -> None:
    with _LISTING_LOCK:
        _LISTING.clear()


def _listing_state(path: Path) -> tuple[Any, Parsed, bytes]:
    """(pe, parsed, file bytes) of an assembly, kept for a short while: parsing a big assembly
    takes seconds and a listing is often followed by another."""
    key = f"{path}|{path.stat().st_mtime_ns}"
    with _LISTING_LOCK:
        got = _LISTING.get("state")
        if got is not None and got[0] == key:
            t = _LISTING.get("timer")
            if t is not None:
                t.cancel()
            _LISTING["timer"] = _start_timer()
            return got[1]
    data = path.read_bytes()
    pe = _open(data=data)
    md = pe.net.mdtables
    parsed = _parse_tables(md, None)
    state = (pe, parsed, data)
    with _LISTING_LOCK:
        t = _LISTING.get("timer")
        if t is not None:
            t.cancel()
        _LISTING["state"] = (key, state)
        _LISTING["timer"] = _start_timer()
    return state


def _start_timer() -> threading.Timer:
    t = threading.Timer(LISTING_KEEP_S, _drop_listing)
    t.daemon = True
    t.start()
    return t


def il_listing(path: Path, token: int) -> tuple[list[str] | None, str | None]:
    """(IL lines, error) of one method: ``IL_0000 opcode operand``, operands named (methods as
    ``Type::name(params)``, strings quoted and cut), branch targets as ``IL_xxxx``."""
    try:
        pe, parsed, data = _listing_state(path)
    except Exception as e:  # noqa: BLE001
        return None, f"cannot read the assembly ({type(e).__name__})"
    md = pe.net.mdtables
    rid = token & 0xFFFFFF
    if not 0 < rid <= len(md.MethodDef.rows):
        return None, "no such method"
    row = md.MethodDef.rows[rid - 1]
    if not row.Rva:
        return None, "the method has no body (abstract, extern or P/Invoke)"
    off = _rva_off(_rva_map(pe), row.Rva)
    body = il_body(data, off) if off is not None else None
    if body is None:
        return None, "the method body is not IL"
    code = body[0]
    res: _Resolver = parsed.res
    us = getattr(pe.net, "user_strings", None)
    out: list[str] = []
    i, n = 0, len(code)
    frm = int.from_bytes
    while i < n:
        at = i
        op = code[i]
        i += 1
        if op == 0xFE:
            if i >= n:
                break
            op = code[i]
            i += 1
            name, size = OP2.get(op), _SZ2[op]
            second = True
        else:
            name, size = OP1.get(op), _SZ[op]
            second = False
        if name is None:
            out.append(f"IL_{at:04x} .byte 0x{code[at]:02x}")
            continue
        arg = ""
        if not second and op == 0x45:                       # switch
            cnt = frm(code[i:i + 4], "little")
            base = i + 4 + 4 * cnt
            tg = [frm(code[i + 4 + 4 * k:i + 8 + 4 * k], "little", signed=True) + base for k in range(cnt)]
            arg = "(" + ", ".join(f"IL_{t:04x}" for t in tg) + ")"
            i = base
        else:
            raw = code[i:i + size]
            i += size
            if not second and op in _B1 and op >= 0x2B:
                arg = f"IL_{i + frm(raw, 'little', signed=True):04x}"
            elif not second and op in _B4 and op >= 0x38:
                arg = f"IL_{i + frm(raw, 'little', signed=True):04x}"
            elif (not second and op in _TOK) or (second and op in (0x06, 0x07, 0x15, 0x16, 0x1C)):
                tok = frm(raw, "little")
                if tok >> 24 == 0x70:
                    arg = _user_string(us, tok & 0xFFFFFF)
                else:
                    arg = res.label(tok)
            elif size:
                v = frm(raw, "little", signed=op not in (0x22, 0x23) or second)
                arg = str(v) if op not in (0x22, 0x23) else raw.hex()
        out.append(f"IL_{at:04x} {name}{' ' + arg if arg else ''}")
    return out, None


LISTING_STRING_CUT = 200


def _user_string(us: Any, offset: int) -> str:
    try:
        s = us.get(offset, errors="replace")
        v = str(s.value if hasattr(s, "value") else s)
    except Exception:  # noqa: BLE001
        return '"?"'
    v = v.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return '"' + (v[:LISTING_STRING_CUT] + f"…({len(v)} chars)" if len(v) > LISTING_STRING_CUT else v) + '"'


# -- listing -----------------------------------------------------------------------------------

KINDS = ("type", "method", "pinvoke", "com", "impl", "field", "property", "event")


def counts(store: Store, bid: int) -> tuple[int, int, int, int]:
    """(types without compiler-generated ones, methods, P/Invokes, COM import types)."""
    q = store.db.execute
    t = q("SELECT COUNT(*) FROM dn_type WHERE binary_id=? AND name NOT LIKE '%<%'", (bid,)).fetchone()[0]
    m = q("SELECT COUNT(*) FROM dn_method WHERE binary_id=?", (bid,)).fetchone()[0]
    p = q("SELECT COUNT(*) FROM dn_pinvoke WHERE binary_id=?", (bid,)).fetchone()[0]
    c = q(f"SELECT COUNT(*) FROM dn_type t WHERE t.binary_id=? AND {_COM_SQL}", (bid,)).fetchone()[0]
    return int(t), int(m), int(p), int(c)


# COM types: ComImport ones, and interfaces that carry a GuidAttribute
_COM_SQL = "(t.flags LIKE '%com%' OR (t.kind='interface' AND t.flags LIKE '%guid=%'))"


def _flags_text(flags: str) -> str:
    """Flags for display: ``guid=abc`` becomes ``{ABC}``."""
    return ",".join("{" + f[5:].upper() + "}" if f.startswith("guid=") else f for f in flags.split(",") if f)


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def bound_label(store: Store, bid: int, token: int) -> str:
    """` => engine.dll!DoWork` when the P/Invoke is bound to a project export, else empty."""
    r = store.db.execute("SELECT dst_binary, dst_entry FROM xedge WHERE src_binary=? AND src_addr=? "
                         "AND kind='pinvoke' LIMIT 1", (bid, token)).fetchone()
    if r is None:
        return ""
    dst = store.get_binary_by_id(r["dst_binary"])
    fn = store.function_at(r["dst_binary"], r["dst_entry"])
    return f" => {dst.name if dst else '?'}!{fn.qualified_name if fn else hex(r['dst_entry'])}"


def list_lines(store: Store, bid: int, query: str = "", kind: str = "") -> list[str]:
    """Item lines of one binary, no header. Without ``kind``: matching types, then P/Invokes and
    methods when a query is given; ``kind`` limits the list to type, method, pinvoke or com."""
    q = query.strip()
    like = _like(q)
    hide = "" if "<" in q else " AND name NOT LIKE '%<%'"
    db = store.db
    out: list[str] = []
    if kind in ("", "type", "com"):
        extra = f" AND {_COM_SQL}" if kind == "com" else ""
        from airlock.server import dotnet_meta
        ifs = dotnet_meta.iface_map(store, bid)
        for r in db.execute(
                "SELECT t.token, t.name, t.kind, t.base, t.flags, (SELECT COUNT(*) FROM dn_method m "
                "WHERE m.binary_id=t.binary_id AND m.type_token=t.token) AS n FROM dn_type t "
                f"WHERE t.binary_id=? AND t.name LIKE ? ESCAPE '\\'{hide.replace('name', 't.name')}"
                f"{extra} ORDER BY t.name", (bid, like)):
            fl = _flags_text(r["flags"])
            heads = ([r["base"]] if r["base"] and r["kind"] in ("class", "struct")
                     and r["base"] != "System.Object" else []) + ifs.get(r["token"], [])
            base = f" : {', '.join(heads)}" if heads else ""
            out.append(f"{'com' if kind == 'com' else 'type'} {r['name']} {r['kind']}"
                       f"{' ' + fl if fl else ''}{base} {r['n']}m")
    if kind in ("", "pinvoke") and (q or kind == "pinvoke"):
        for r in db.execute(
                "SELECT p.token, p.module, p.entry, p.ordinal, p.flags, m.name, m.sig, t.name AS tname "
                "FROM dn_pinvoke p JOIN dn_method m ON m.binary_id=p.binary_id AND m.token=p.token "
                "LEFT JOIN dn_type t ON t.binary_id=m.binary_id AND t.token=m.type_token "
                "WHERE p.binary_id=? AND (m.name LIKE ? ESCAPE '\\' OR p.module LIKE ? ESCAPE '\\' "
                "OR COALESCE(p.entry,'') LIKE ? ESCAPE '\\' OR COALESCE(t.name,'') LIKE ? ESCAPE '\\') "
                "ORDER BY lower(p.module), p.entry, p.ordinal, m.name", (bid, like, like, like, like)):
            ent = r["entry"] if r["entry"] else "#" + str(r["ordinal"])
            fl = f" {r['flags']}" if r["flags"] else ""
            out.append(f"pinvoke {r['tname'] or '?'}::{r['name']} {r['sig']} -> "
                       f"{normal_module(r['module'])}!{ent}{fl}{bound_label(store, bid, r['token'])}")
    if kind in ("", "method") and (q or kind == "method"):
        pin = "" if kind == "method" else " AND m.flags NOT LIKE '%pinvoke%'"
        for r in db.execute(
                "SELECT m.name, m.sig, m.flags, t.name AS tname FROM dn_method m "
                "LEFT JOIN dn_type t ON t.binary_id=m.binary_id AND t.token=m.type_token "
                "WHERE m.binary_id=? AND (m.name LIKE ? ESCAPE '\\' OR COALESCE(t.name,'') || '::' "
                f"|| m.name LIKE ? ESCAPE '\\'){pin}{hide.replace('name', 'm.name')} "
                "ORDER BY t.name, m.token", (bid, like, like)):
            fl = f" {r['flags']}" if r["flags"] else ""
            out.append(f"method {r['tname'] or '?'}::{r['name']} {r['sig']}{fl}")
    return out


def find_type(store: Store, bid: int, name: str) -> list[str]:
    """Full names matching ``name``: exact, then exact ignoring case, then as a suffix after a
    dot or plus (``Api`` for ``Demo.Native.Api``)."""
    n = name.strip()
    db = store.db
    for sql, nargs in (("name=?", 1), ("lower(name)=lower(?)", 1),
                       ("(lower(name) LIKE '%.' || lower(?) OR lower(name) LIKE '%+' || lower(?))", 2)):
        rows = [r["name"] for r in db.execute(
            f"SELECT name FROM dn_type WHERE binary_id=? AND {sql} ORDER BY name", (bid, *([n] * nargs)))]
        if rows:
            return rows
    return []


# -- ilspycmd ----------------------------------------------------------------------------------

def _ilspy_env(exe: str = "") -> dict[str, str]:
    env = dict(os.environ)
    # ilspycmd 8.x is a .NET 6 apphost: roll forward to a newer runtime (child process only).
    # ilspycmd 11 is NativeAOT and ignores it.
    env.setdefault("DOTNET_ROLL_FORWARD", "LatestMajor")
    env.setdefault("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
    return env


@functools.lru_cache(maxsize=8)
def _ilspy_version(exe: str, size: int, mtime: int) -> str:
    try:
        r = subprocess.run([exe, "--version"], capture_output=True, timeout=30, env=_ilspy_env(exe),
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        m = re.search(r"\d+(?:\.\d+)+", r.stdout.decode("utf-8", "replace"))
        if m:
            return m.group(0)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return f"s{size}"                      # no version printed: the file itself tells when it changed


def ilspy_version(exe: Path) -> str:
    """Version of ilspycmd, asked once per process and file (it keys the decompile cache)."""
    try:
        st = exe.stat()
    except OSError:
        return "unknown"
    return _ilspy_version(str(exe), st.st_size, st.st_mtime_ns)


def ilspy_major(exe: Path) -> int:
    """Major version of ilspycmd (0 when unknown). `-m <token>`, `--list-resources` and `--resource`
    need 11 (verified on 11.2.0.10050)."""
    m = re.match(r"(\d+)\.", ilspy_version(exe))
    return int(m.group(1)) if m else 0


def run_ilspy_args(exe: Path, assembly: Path, args: list[str], timeout: int,
                   ref_dir: Path | list[Path] | None = None) -> tuple[bytes | None, str | None]:
    """(stdout bytes, error text) of ``ilspycmd --disable-updatecheck <args> [-r ref_dir] <assembly>``.
    The general helper: ``["--list-resources"]``, ``["--resource", name]``, ``["-m", "0x06000005"]``,
    ``["-t", type]``. Bytes are returned as written, so binary resources stay intact."""
    cmd = [str(exe), "--disable-updatecheck", *args]
    for d in ([] if ref_dir is None else ref_dir if isinstance(ref_dir, list) else [ref_dir]):
        if d.is_dir() and d != Path("."):          # never the server's working directory
            cmd += ["-r", str(d)]
    cmd.append(str(assembly))
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, env=_ilspy_env(str(exe)),
                           cwd=str(assembly.parent), creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"
    except OSError as e:
        return None, f"cannot start ilspycmd ({e.strerror or e})"
    if r.returncode != 0 or not r.stdout.strip():
        err = (r.stderr.decode("utf-8", "replace") or r.stdout.decode("utf-8", "replace")).strip().splitlines()
        return None, (err[0] if err else f"exit code {r.returncode}")[:200]
    return r.stdout, None


def run_ilspy(exe: Path, assembly: Path, type_name: str, timeout: int,
              ref_dir: Path | list[Path] | None = None, token: int | None = None) -> tuple[str | None, str | None]:
    """(C# text, error text) of ``ilspycmd -t <type>`` or, with ``token`` (ilspycmd 11), of
    ``ilspycmd -m 0x<token>``: one method, also a lambda or MoveNext."""
    args = ["-m", f"0x{token:08x}"] if token is not None else ["-t", type_name]
    out, err = run_ilspy_args(exe, assembly, args, timeout, ref_dir)
    if out is None:
        return None, err
    return out.decode("utf-8", "replace").replace("\r\n", "\n"), None


def member_alias(member: str, full_type: str) -> str:
    """The name a member has in the C# text: `.ctor` and `.cctor` are the type's own name, and a
    compiler-generated lambda or iterator name like `<.ctor>b__37_5` or `<Run>d__3` lives inside
    the method it came from (`<Name>` prefix)."""
    m = re.match(r"<([^>]+)>", member)
    name = m.group(1) if m else member
    if re.match(r"(?:get|set|add|remove)_\w+$", name):          # property or event accessor
        name = name.split("_", 1)[1]
    if name in (".ctor", ".cctor"):
        return re.split(r"[./+]", re.sub(r"`\d+.*$", "", full_type))[-1] or name
    return name


def member_text(code: str, member: str) -> str | None:
    """The declaration(s) named ``member`` inside the C# of one type: a line at member depth (one
    tab) that names it, the attributes above it and the body (brace matched), or None. Members of
    nested types sit deeper (two tabs and more): tried when depth one has none."""
    lines = code.split("\n")
    want = re.compile(r"(?<![\w.])" + re.escape(member) + r"\s*(?:<[^>]*>)?\s*(?:\(|\{|=|;|$)")
    for depth_tabs in range(1, 5):
        pre = "\t" * depth_tabs
        out: list[str] = []
        i = 0
        while i < len(lines):
            ln = lines[i]
            if (ln.startswith(pre) and not ln.startswith(pre + "\t") and ln.strip()
                    and not ln.strip().startswith(("[", "//")) and want.search(ln)):
                j = i
                while j > 0 and lines[j - 1].startswith(pre) and lines[j - 1].strip().startswith("["):
                    j -= 1
                depth, k, seen = 0, i, False
                while k < len(lines):
                    depth += lines[k].count("{") - lines[k].count("}")
                    seen = seen or "{" in lines[k]
                    if (seen and depth <= 0) or (not seen and lines[k].rstrip().endswith(";")):
                        break
                    k += 1
                out += lines[j:k + 1] + [""]
                i = k + 1
            else:
                i += 1
        if out:
            return "\n".join(out).rstrip("\n")
    return None
