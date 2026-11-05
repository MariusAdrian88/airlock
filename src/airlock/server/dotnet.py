""".NET metadata on the server side (dnfile, no Ghidra), DESIGN.md sections 6 and 11.

``parse_file`` reads an assembly into plain rows (types, methods, P/Invoke declarations).
``ensure`` writes them to the derived tables ``dn_type``/``dn_method``/``dn_pinvoke`` (schema v11)
when they are missing or were written by an older ``DOTNET_VERSION``.

Every P/Invoke method also becomes a thunk function (entry = the MethodDef token) and an import row
(address = the same token, dll = the declared module with ``.dll`` added when it has no extension).
The normal import linking then binds it to the export of a project binary and writes an xedge of
kind ``pinvoke``, so ``xrefs``, ``callgraph`` and ``path`` follow it like a native import. A module
no project binary provides (a system DLL) stays an unresolved import.

``ilspy_type`` runs ``ilspycmd -t`` for one type; the output is a reconstruction, never a fact.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock.index.store import DN_METHOD_HI, DN_METHOD_LO, Binary, Function, Store

log = logging.getLogger(__name__)

DOTNET_VERSION = 1            # meta key ``dotnet_version:<binary id>``; older rows are parsed again
TYPE_TOKEN = 0x02000000
METHOD_TOKEN = 0x06000000
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


def normal_module(module: str) -> str:
    """The file name the P/Invoke probes for: base name, ``.dll`` added without a known extension."""
    base = re.split(r"[\\/]", module.strip())[-1]
    return base if base.lower().endswith(MODULE_EXT) else base + ".dll"


def parse_file(path: Path) -> Parsed | None:
    """Types, methods and P/Invokes of a managed assembly; None when dnfile finds no metadata."""
    import dnfile

    logging.getLogger("dnfile").setLevel(logging.ERROR)
    try:
        pe = dnfile.dnPE(str(path))
    except Exception as e:  # noqa: BLE001  not a PE, damaged headers
        log.warning("dnfile cannot read %s: %s", path.name, e)
        return None
    try:
        net = getattr(pe, "net", None)
        md = getattr(net, "mdtables", None)
        if md is None or md.TypeDef is None or not md.TypeDef.rows:
            return None
        return _parse_tables(md)
    finally:
        pe.close()


def _parse_tables(md: Any) -> Parsed:
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
    return out


# -- the index ---------------------------------------------------------------------------------

def _meta_key(bid: int) -> str:
    return f"dotnet_version:{bid}"


def stale(store: Store, bid: int) -> bool:
    return store.get_meta(_meta_key(bid)) != str(DOTNET_VERSION)


def is_stub(b: Binary, fn: Function) -> bool:
    """A P/Invoke thunk of a managed binary: it has no machine code to decompile."""
    return b.toolchain == "dotnet" and fn.space == "ram" and DN_METHOD_LO <= fn.entry < DN_METHOD_HI


def ensure(store: Store, b: Binary, artifact: Path, force: bool = False) -> bool:
    """Fill the .NET tables of ``b`` (and its P/Invoke thunks and import rows) when missing or
    stale. True when it parsed now. A file without metadata gets no rows and is not parsed again.
    Links to the project's other binaries are not rebuilt here (``Store.link_cross_binary``)."""
    if b.toolchain != "dotnet" or not artifact.is_file():
        return False
    if not force and not stale(store, b.id):
        return False
    parsed = parse_file(artifact)
    db = store.db
    sig_of = {m.token: m.sig for m in parsed.methods} if parsed else {}
    with db:
        for t in ("dn_type", "dn_method", "dn_pinvoke"):
            db.execute(f"DELETE FROM {t} WHERE binary_id=?", (b.id,))
        db.execute("DELETE FROM xedge WHERE src_binary=? AND kind='pinvoke'", (b.id,))
        db.execute("DELETE FROM function WHERE binary_id=? AND space='ram' AND is_thunk=1 "
                   "AND entry>=? AND entry<?", (b.id, DN_METHOD_LO, DN_METHOD_HI))
        db.execute("DELETE FROM import WHERE binary_id=? AND address>=? AND address<?",
                   (b.id, DN_METHOD_LO, DN_METHOD_HI))
        if parsed is not None:
            db.executemany("INSERT INTO dn_type VALUES (?,?,?,?,?,?)",
                           [(b.id, t.token, t.name, t.kind, t.base, t.flags) for t in parsed.types])
            db.executemany("INSERT INTO dn_method VALUES (?,?,?,?,?,?)",
                           [(b.id, m.token, m.type_token, m.name, m.sig, m.flags)
                            for m in parsed.methods])
            db.executemany("INSERT INTO dn_pinvoke VALUES (?,?,?,?,?,?)",
                           [(b.id, p.token, p.module, p.entry, p.ordinal, p.flags)
                            for p in parsed.pinvokes])
    if parsed is not None and parsed.pinvokes:
        type_name = {t.token: t.name for t in parsed.types}
        owner = {m.token: m.type_token for m in parsed.methods}
        method_name = {m.token: m.name for m in parsed.methods}
        fns = []
        for p in parsed.pinvokes:
            conv = next((f for f in p.flags.split(",") if f in ("stdcall", "cdecl", "fastcall", "thiscall")), None)
            fns.append({"entry": p.token, "name": method_name[p.token], "name_state": "auto",
                        "namespace": type_name.get(owner.get(p.token, 0)),
                        "signature": f"{sig_of.get(p.token, '?')} [{normal_module(p.module)}!"
                                     f"{p.entry if p.entry else '#' + str(p.ordinal)}]",
                        "calling_conv": conv, "size": 1, "is_thunk": True})
        store.insert_functions(b.id, fns)
        store.insert_imports(b.id, [(normal_module(p.module), p.entry, p.ordinal, p.token)
                                    for p in parsed.pinvokes])
    store.rebuild_fts(b.id)
    store.set_meta(_meta_key(b.id), str(DOTNET_VERSION))
    return True


def ensure_project(store: Store, artifacts: Path, ready: list[int]) -> int:
    """``ensure`` for every managed binary of the project; relinks the ones parsed now against the
    other ``ready`` binaries. Returns how many were parsed."""
    n = 0
    for b in store.list_binaries():
        try:
            if ensure(store, b, artifacts / b.sha256):
                n += 1
                store.link_cross_binary(b.id, [i for i in ready if i != b.id])
        except Exception as e:  # noqa: BLE001  metadata is an extra
            log.warning(".NET metadata of %s: %s", b.name, e)
    return n


def dotnet_binaries(store: Store) -> list[Binary]:
    return [b for b in store.list_binaries() if b.toolchain == "dotnet"]


# -- listing -----------------------------------------------------------------------------------

KINDS = ("type", "method", "pinvoke", "com")


def counts(store: Store, bid: int) -> tuple[int, int, int, int]:
    """(types without compiler-generated ones, methods, P/Invokes, COM import types)."""
    q = store.db.execute
    t = q("SELECT COUNT(*) FROM dn_type WHERE binary_id=? AND name NOT LIKE '%<%'", (bid,)).fetchone()[0]
    m = q("SELECT COUNT(*) FROM dn_method WHERE binary_id=?", (bid,)).fetchone()[0]
    p = q("SELECT COUNT(*) FROM dn_pinvoke WHERE binary_id=?", (bid,)).fetchone()[0]
    c = q("SELECT COUNT(*) FROM dn_type WHERE binary_id=? AND flags LIKE '%com%'", (bid,)).fetchone()[0]
    return int(t), int(m), int(p), int(c)


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
        extra = " AND t.flags LIKE '%com%'" if kind == "com" else ""
        for r in db.execute(
                "SELECT t.name, t.kind, t.base, t.flags, (SELECT COUNT(*) FROM dn_method m "
                "WHERE m.binary_id=t.binary_id AND m.type_token=t.token) AS n FROM dn_type t "
                f"WHERE t.binary_id=? AND t.name LIKE ? ESCAPE '\\'{hide.replace('name', 't.name')}"
                f"{extra} ORDER BY t.name", (bid, like)):
            fl = ",".join(f for f in r["flags"].split(",") if f)
            base = (f" : {r['base']}" if r["base"] and r["kind"] in ("class", "struct")
                    and r["base"] != "System.Object" else "")
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

def run_ilspy(exe: Path, assembly: Path, type_name: str, timeout: int,
              ref_dir: Path | None = None) -> tuple[str | None, str | None]:
    """(C# text, error text) of ``ilspycmd -t <type> <assembly>``. ilspycmd 8.x targets .NET 6;
    ``DOTNET_ROLL_FORWARD=LatestMajor`` (child process only) lets it run on a newer runtime."""
    cmd = [str(exe), "--disable-updatecheck", "-t", type_name]
    if ref_dir is not None and ref_dir.is_dir():
        cmd += ["-r", str(ref_dir)]
    cmd.append(str(assembly))
    env = dict(os.environ)
    env.setdefault("DOTNET_ROLL_FORWARD", "LatestMajor")
    env.setdefault("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env, cwd=str(assembly.parent),
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"
    except OSError as e:
        return None, f"cannot start ilspycmd ({e.strerror or e})"
    out = r.stdout.decode("utf-8", "replace").replace("\r\n", "\n")
    if r.returncode != 0 or not out.strip():
        err = (r.stderr.decode("utf-8", "replace") or out).strip().splitlines()
        return None, (err[0] if err else f"exit code {r.returncode}")[:200]
    return out, None


def member_text(code: str, member: str) -> str | None:
    """The declaration(s) named ``member`` inside the C# of one type: a line at member depth (one
    tab) that names it, the attributes above it and the body (brace matched), or None."""
    lines = code.split("\n")
    want = re.compile(r"(?<![\w.])" + re.escape(member) + r"\s*(?:<[^>]*>)?\s*(?:\(|\{|=|;|$)")
    out: list[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        if (ln.startswith("\t") and not ln.startswith("\t\t") and ln.strip()
                and not ln.strip().startswith(("[", "//")) and want.search(ln)):
            j = i
            while j > 0 and lines[j - 1].startswith("\t") and lines[j - 1].strip().startswith("["):
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
    return "\n".join(out).rstrip("\n") if out else None
