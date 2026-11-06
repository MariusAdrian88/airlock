""".NET UI wiring and managed resources (dnfile and ilspycmd, no Ghidra), DESIGN.md section 11.

``dotnet_events`` rows come from two sources, both read from the assembly itself:

- WinForms: the IL of ``InitializeComponent`` and of the other methods of types derived from
  ``System.Windows.Forms`` classes. A delegate wiring is the instruction run
  ``<receiver> ldarg.0 ldftn <handler> newobj <Delegate>::.ctor callvirt add_<Event>``; a caption is
  ``<receiver> ldstr "<text>" callvirt set_Text``. The receiver is ``ldarg.0 ldfld <field>``, ``ldarg.0``
  (the form itself) or a local that a later ``stfld`` stores into a field.
- WPF: the BAML resources, turned into XAML by ``ilspycmd --resource`` (11.x). Event attributes
  (``Click="Handler"``, ``EventSetter``) and ``Command`` values are joined to the ``CommandBinding``
  elements of the same file.

``managed_resources`` lists the ManifestResource rows and the entries inside ``.resources`` containers.
"""

from __future__ import annotations

import re
import threading
import xml.etree.ElementTree as ET
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from airlock.server import dotnet as dn

_UI_ROOTS = ("System.Windows.Forms.",)
_MAX_BODY = 1 << 20


@dataclass
class UiRow:
    kind: str            # "wf" or "wpf"
    form: str            # full type name (WPF: x:Class, else the BAML name)
    control: str         # field name / x:Name, "" for none, "form" for the form itself
    ctype: str
    caption: str
    event: str
    handler: str         # method name (Type::name when it is another type)
    token: int           # MethodDef token of the handler, 0 when it is not in the assembly
    where: str = ""      # method that holds the wiring when it is not InitializeComponent
    command: str = ""    # WPF: Command value that joined the handler
    key: tuple | None = None   # WinForms: receiver key while the caption pass runs
    via: str = ""        # WPF: view-model getter (Type::get_X) that a {Binding X} command resolved to
    alt: tuple = ()      # WPF: other handlers created in that getter (display names)


# -- IL decoding -----------------------------------------------------------------------------

_LD = {f"ldloc.{k}": ("ldloc", k) for k in range(4)}
_ST = {f"stloc.{k}": ("stloc", k) for k in range(4)}
_AR = {f"ldarg.{k}": ("ldarg", k) for k in range(4)}
_TOK2 = (0x06, 0x07, 0x15, 0x16, 0x1C)


def decode(code: bytes) -> list[tuple[str, int]]:
    """(opcode, operand) pairs. Local and argument loads are normalised to ``ldloc n``, ``stloc n``,
    ``ldarg n``; token operands stay integers; branch operands are dropped (0)."""
    out: list[tuple[str, int]] = []
    i, n = 0, len(code)
    frm = int.from_bytes
    while i < n:
        op = code[i]
        i += 1
        second = False
        if op == 0xFE:
            if i >= n:
                break
            op = code[i]
            i += 1
            name, size, second = dn.OP2.get(op), dn._SZ2[op], True
        else:
            name, size = dn.OP1.get(op), dn._SZ[op]
        if name is None or size < 0:
            break
        if not second and op == 0x45:                    # switch
            cnt = frm(code[i:i + 4], "little")
            i += 4 + 4 * cnt
            out.append(("switch", 0))
            continue
        raw = code[i:i + size]
        i += size
        if name in _LD:
            out.append(_LD[name])
        elif name in _ST:
            out.append(_ST[name])
        elif name in _AR:
            out.append(_AR[name])
        elif name in ("ldloc.s", "ldloc"):
            out.append(("ldloc", frm(raw, "little")))
        elif name in ("stloc.s", "stloc"):
            out.append(("stloc", frm(raw, "little")))
        elif name in ("ldarg.s", "ldarg"):
            out.append(("ldarg", frm(raw, "little")))
        elif (not second and op in dn._TOK) or (second and op in _TOK2):
            out.append((name, frm(raw, "little")))
        else:
            out.append((name, 0))
    return out


class _Asm:
    """Names behind the tokens of one assembly."""

    def __init__(self, path: Path) -> None:
        self.pe, self.parsed, self.data = dn._listing_state(path)
        self.md = self.pe.net.mdtables
        self.res = self.parsed.res
        self.us = getattr(self.pe.net, "user_strings", None)
        self.secs = dn._rva_map(self.pe)
        self.type_by_tok = {t.token: t for t in self.parsed.types}
        self.type_by_name = {t.name: t for t in self.parsed.types}
        self.getters: dict[str, list[tuple[Any, Any]]] | None = None
        self.methods_of: dict[int, list[Any]] = {}
        for m in self.parsed.methods:
            self.methods_of.setdefault(m.type_token, []).append(m)

    def getters_named(self, prop: str) -> list[tuple[Any, Any]]:
        """(type, method) of every ``get_<prop>`` in the assembly."""
        if self.getters is None:
            self.getters = {}
            for m in self.parsed.methods:
                if m.name.startswith("get_"):
                    t = self.type_by_tok.get(m.type_token)
                    if t is not None:
                        self.getters.setdefault(m.name[4:], []).append((t, m))
        return self.getters.get(prop, [])

    def string(self, tok: int) -> str:
        if self.us is None:
            return ""
        try:
            s = self.us.get(tok & 0xFFFFFF, errors="replace")
            return str(s.value if hasattr(s, "value") else s)
        except Exception:  # noqa: BLE001
            return ""

    def member_name(self, tok: int) -> str:
        """Plain member name of a MethodDef, MemberRef, Field or MethodSpec token."""
        t, rid = tok >> 24, tok & 0xFFFFFF
        try:
            if t == 0x06:
                return self.parsed.methods[rid - 1].name
            if t == 0x0A:
                return dn._s(self.md.MemberRef.rows[rid - 1].Name)
            if t == 0x04:
                return dn._s(self.md.Field.rows[rid - 1].Name)
            if t == 0x2B:
                m = self.md.MethodSpec.rows[rid - 1].Method
                return self.member_name((0x06 if m.table.name == "MethodDef" else 0x0A) << 24 | m.row_index)
        except (IndexError, ValueError, AttributeError):
            pass
        return ""

    def owner_name(self, tok: int) -> str:
        """Short type name that declares a method, constructor or member token."""
        t, rid = tok >> 24, tok & 0xFFFFFF
        try:
            if t == 0x06:
                tt = self.type_by_tok.get(self.parsed.methods[rid - 1].type_token)
                return dn._short(tt.name) if tt else ""
            if t == 0x0A:
                c = self.md.MemberRef.rows[rid - 1].Class
                tn = c.table.name if c.table is not None else ""
                if tn == "TypeRef":
                    return dn._short(self.res.tref(c.row_index)[0])
                if tn == "TypeDef":
                    return dn._short(self.parsed.types[c.row_index - 1].name)
        except (IndexError, ValueError, AttributeError):
            pass
        return ""

    def field_type(self, tok: int) -> str:
        if tok >> 24 != 0x04:
            return ""
        try:
            blob = bytes(self.md.Field.rows[(tok & 0xFFFFFF) - 1].Signature.value)
            if blob and blob[0] == 0x06:
                return dn._type(dn._Blob(blob[1:]), self.res.names)
        except (IndexError, ValueError, AttributeError):
            pass
        return ""

    def code_of(self, token: int) -> bytes | None:
        rid = token & 0xFFFFFF
        if not 0 < rid <= len(self.md.MethodDef.rows):
            return None
        rva = self.md.MethodDef.rows[rid - 1].Rva
        if not rva:
            return None
        off = dn._rva_off(self.secs, rva)
        body = dn.il_body(self.data, off) if off is not None else None
        if body is None or len(body[0]) > _MAX_BODY:
            return None
        return body[0]


# -- WinForms --------------------------------------------------------------------------------

def _recv(ins: list[tuple[str, int]], k: int, gen: dict[int, int]) -> tuple | None:
    """Receiver key of the load that ends at instruction ``k``."""
    if k < 0:
        return None
    op, a = ins[k]
    if op == "ldarg" and a == 0:
        return ("this",)
    if op == "ldloc":
        return ("l", a, gen.get(a, 0))
    if op == "ldfld" and k >= 1 and ins[k - 1] == ("ldarg", 0):
        return ("f", a)
    return None


def _scan_method(asm: _Asm, code: bytes, mname: str, form: str, rows: list[UiRow],
                 caps: dict, ctypes: dict, resname: dict, resget: dict) -> None:
    ins = decode(code)
    gen: dict[int, int] = {}
    alias: dict[tuple, tuple] = {}
    ev_raw: list[tuple] = []            # (key, event, handler, token)
    for j, (op, a) in enumerate(ins):
        if op == "stloc":
            gen[a] = gen.get(a, 0) + 1
            if j >= 1 and ins[j - 1][0] == "newobj":
                ctypes[("l", a, gen[a])] = asm.owner_name(ins[j - 1][1])
        elif op == "stfld":
            if j >= 2 and ins[j - 2] == ("ldarg", 0):
                prev = ins[j - 1]
                if prev[0] == "ldloc":
                    alias[("l", prev[1], gen.get(prev[1], 0))] = ("f", a)
                elif prev[0] == "newobj":
                    ctypes[("f", a)] = asm.owner_name(prev[1])
        elif op in ("callvirt", "call"):
            name = asm.member_name(a)
            if name.startswith("add_") and j >= 3 and ins[j - 1][0] == "newobj":
                f = j - 2
                if ins[f][0] not in ("ldftn", "ldvirtftn"):
                    continue
                t = f - 1
                if ins[f][0] == "ldvirtftn" and t >= 0 and ins[t][0] == "dup":
                    t -= 1
                key = _recv(ins, t - 1, gen)
                if key is None:
                    continue
                ev_raw.append((key, name[4:], ins[f][1]))
            elif name == "set_Text" and j >= 2:
                prev = ins[j - 1]
                if prev[0] == "ldstr":
                    key = _recv(ins, j - 2, gen)
                    if key is not None:
                        caps[key] = asm.string(prev[1])
                elif prev[0] in ("callvirt", "call") and asm.member_name(prev[1]) == "GetString" and \
                        ins[j - 2][0] == "ldstr":
                    key = _recv(ins, j - 4, gen)       # <recv> <resources> ldstr GetString set_Text
                    if key is not None:
                        resget[key] = asm.string(ins[j - 2][1])
            elif name == "ApplyResources" and j >= 3 and ins[j - 1][0] == "ldstr":
                key = _recv(ins, j - 2, gen)
                if key is not None:
                    resname[key] = asm.string(ins[j - 1][1])
    for key, event, ftok in ev_raw:
        k2 = alias.get(key, key) if key[0] == "l" else key
        if k2[0] == "l":
            ctype = ctypes.get(key, "")
            ctrl = f"local{k2[1]}"
        elif k2[0] == "this":
            ctype, ctrl = "", "form"
        else:
            ctype, ctrl = "", asm.member_name(k2[1])
        if key[0] == "l" and k2 != key:
            ctypes.setdefault(k2, ctypes.get(key, ""))
        h, token = _handler(asm, ftok, form)
        rows.append(UiRow("wf", form, ctrl, ctype, "", event, h, token,
                          "" if mname == "InitializeComponent" else mname))
        rows[-1].key = k2
    for key, k2 in alias.items():                # captions set on the local before the field store
        if key in caps:
            caps.setdefault(k2, caps[key])
        if key in resname:
            resname.setdefault(k2, resname[key])
        if key in resget:
            resget.setdefault(k2, resget[key])


def _real_type(name: str) -> str:
    """Full type name without compiler-generated closure classes (``Ns.VM+<>c`` -> ``Ns.VM``)."""
    parts = [p for p in name.split("+") if not p.startswith("<>c")]
    return "+".join(parts) if parts else name


_LAMBDA = re.compile(r"<([^>]+)>b__\d+(?:_\d+)?$")


def lambda_outer(handler: str) -> str:
    """Name of the method that holds a compiler-generated lambda (``Type::<Outer>b__3`` -> ``Outer``)."""
    m = _LAMBDA.search(handler.rsplit("::", 1)[-1])
    return m.group(1) if m else ""


def _handler(asm: _Asm, ftok: int, form: str) -> tuple[str, int]:
    name = asm.member_name(ftok)
    if ftok >> 24 == 0x06:
        m = asm.parsed.methods[(ftok & 0xFFFFFF) - 1]
        owner = asm.type_by_tok.get(m.type_token)
        if owner is not None and _real_type(owner.name) != form:
            return f"{dn._short(_real_type(owner.name))}::{name}", ftok
        return name, ftok
    owner = asm.owner_name(ftok)
    return (f"{owner}::{name}" if owner else name), 0


def _is_ui(asm: _Asm, t: Any) -> bool:
    cur, seen = t, 0
    while cur is not None and seen < 12:
        base = cur.base or ""
        if base.startswith(_UI_ROOTS):
            return True
        cur = asm.type_by_name.get(base)
        seen += 1
    return False


_WF_CACHE: dict[str, list[UiRow]] = {}
_LOCK = threading.Lock()


def winforms_rows(path: Path) -> list[UiRow]:
    key = f"{path}|{path.stat().st_mtime_ns}"
    with _LOCK:
        got = _WF_CACHE.get(key)
    if got is not None:
        return got
    asm = _Asm(path)
    resources = _form_resources(asm)
    out: list[UiRow] = []
    for t in asm.parsed.types:
        meths = asm.methods_of.get(t.token, [])
        has_init = any(m.name == "InitializeComponent" for m in meths)
        if not has_init and not _is_ui(asm, t):
            continue
        rows: list[UiRow] = []
        caps: dict = {}
        ctypes: dict = {}
        resname: dict = {}
        resget: dict = {}
        for m in meths:
            code = asm.code_of(m.token)
            if code is None or (b"\x6f" not in code and b"\x28" not in code):
                continue
            try:
                _scan_method(asm, code, m.name, t.name, rows, caps, ctypes, resname, resget)
            except (IndexError, ValueError, KeyError):
                continue
        if not rows:
            continue
        res = resources.get(t.name, {})
        for r in rows:
            k = r.key
            r.key = None
            if k and k[0] == "f":
                r.ctype = ctypes.get(k) or asm.field_type(k[1]) or r.ctype
            elif k and k[0] == "l":
                r.ctype = ctypes.get(k, r.ctype)
            cap = caps.get(k, "") if k else ""
            if not cap and k:
                rn = resname.get(k)
                cap = res.get(f"{rn}.Text", "") if rn else ""
                if not cap and k in resget:
                    cap = res.get(resget[k], "")
            r.caption = cap
        out += rows
    with _LOCK:
        _WF_CACHE[key] = out
    return out


def _form_resources(asm: _Asm) -> dict[str, dict[str, str]]:
    """type full name -> {resource key: string} for the form ``.resources`` containers that exist."""
    out: dict[str, dict[str, str]] = {}
    for mr in manifest_resources(asm):
        if not mr.name.endswith(".resources") or mr.name.endswith(".g.resources"):
            continue
        tname = mr.name[:-len(".resources")]
        if tname not in asm.type_by_name or mr.payload is None:
            continue
        ents = read_resources(mr.payload, 0)
        if ents:
            out[tname] = {e.name: e.preview for e in ents if e.is_string}
    return out


# -- managed resources -----------------------------------------------------------------------

@dataclass
class MRes:
    name: str
    size: int
    kind: str                   # "embedded", "linked file X", "linked assembly X"
    public: bool
    payload: bytes | None = None


@dataclass
class REntry:
    name: str
    size: int
    preview: str
    is_string: bool


def manifest_resources(asm: _Asm) -> list[MRes]:
    tbl = getattr(asm.md, "ManifestResource", None)
    if tbl is None:
        return []
    st = asm.pe.net.struct
    base = dn._rva_off(asm.secs, st.ResourcesRva) if getattr(st, "ResourcesRva", 0) else None
    out: list[MRes] = []
    for r in tbl.rows:
        impl = r.Implementation
        tn = impl.table.name if getattr(impl, "table", None) is not None else ""
        if not tn:
            kind = "embedded"
        elif tn == "File":
            kind = f"linked file {_impl_name(asm, 'File', impl)}"
        else:
            kind = f"linked assembly {_impl_name(asm, 'AssemblyRef', impl)}"
        size, payload = 0, None
        if kind == "embedded" and base is not None:
            p = base + int(r.Offset)
            if p + 4 <= len(asm.data):
                size = int.from_bytes(asm.data[p:p + 4], "little")
                if p + 4 + size <= len(asm.data):
                    payload = asm.data[p + 4:p + 4 + size]
                else:
                    size = 0
        out.append(MRes(dn._s(r.Name), size, kind, bool(getattr(r.Flags, "mrPublic", False)), payload))
    return out


def _impl_name(asm: _Asm, table: str, impl: Any) -> str:
    try:
        row = getattr(asm.md, table).rows[impl.row_index - 1]
        return dn._s(row.Name)
    except (AttributeError, IndexError, ValueError):
        return "?"


_PRIM_CODES = {2: "bool", 3: "char", 4: "byte", 5: "sbyte", 6: "short", 7: "ushort", 8: "int", 9: "uint",
               10: "long", 11: "ulong", 12: "float", 13: "double", 14: "decimal", 15: "DateTime",
               16: "TimeSpan", 0x20: "byte[]", 0x21: "stream"}


def _r7(b: bytes, p: int) -> tuple[int, int]:
    v = s = 0
    while p < len(b):
        x = b[p]
        p += 1
        v |= (x & 0x7F) << s
        if not x & 0x80:
            break
        s += 7
        if s > 35:
            raise ValueError("bad 7-bit integer")
    return v, p


def read_resources(b: bytes, cut: int = 60) -> list[REntry] | None:
    """The entries of a .resources stream (name, size, string text or type); None when it is not one."""
    try:
        if len(b) < 24 or int.from_bytes(b[:4], "little") != 0xBEEFCACE:
            return None
        u32 = lambda p: int.from_bytes(b[p:p + 4], "little")  # noqa: E731
        p = 12 + u32(8)
        ver, count, nt = u32(p), u32(p + 4), u32(p + 8)
        if ver not in (1, 2) or count > 1_000_000 or nt > 100_000:
            return None
        p += 12
        types: list[str] = []
        for _ in range(nt):
            n, p = _r7(b, p)
            types.append(b[p:p + n].decode("utf-8", "replace").split(",")[0])
            p += n
        p = (p + 7) & ~7
        p += 4 * count
        name_tbl = p
        p += 4 * count
        data_off = u32(p)
        name_sec = p + 4
        ents: list[tuple[int, str]] = []
        for i in range(count):
            q = name_sec + u32(name_tbl + 4 * i)
            n, q = _r7(b, q)
            ents.append((data_off + u32(q + n), b[q:q + n].decode("utf-16le", "replace")))
        order = sorted(e[0] for e in ents)
        end_of = {o: (order[i + 1] if i + 1 < len(order) else len(b)) for i, o in enumerate(order)}
        out: list[REntry] = []
        for off, name in sorted(ents, key=lambda e: e[1].lower()):
            size = end_of[off] - off
            code, q = _r7(b, off)
            text, is_str = "", False
            if code == 1:
                n, q = _r7(b, q)
                s = b[q:q + n].decode("utf-8", "replace")
                is_str = True
                text = s
                short = s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
                prev = '"' + (short[:cut] + "…" if len(short) > cut else short) + '"'
            elif code == 0:
                prev = "null"
            elif code in _PRIM_CODES:
                prev = _PRIM_CODES[code]
            elif code >= 0x40 and code - 0x40 < len(types):
                prev = types[code - 0x40].rsplit(".", 1)[-1]
            else:
                prev = f"type 0x{code:x}"
            out.append(REntry(name, size, prev, is_str))
            if is_str:
                out[-1].preview = text if cut == 0 else prev
        return out
    except (ValueError, IndexError):
        return None


def managed_resources(path: Path, want: str = "") -> list[str] | None:
    """Lines for pe_resources: one per ManifestResource, plus the entries of ``*.g.resources`` (BAML
    names) and, with ``want`` = "managed" or "resources", of every ``.resources`` container.
    ``want`` "baml" lists only the BAML entries. None when the file has no .NET metadata."""
    try:
        asm = _Asm(path)
    except Exception:  # noqa: BLE001
        return None
    mrs = manifest_resources(asm)
    lines: list[str] = []
    all_entries = want in ("managed", "resources")
    for mr in mrs:
        is_res = mr.name.endswith(".resources")
        entries = read_resources(mr.payload) if (is_res and mr.payload is not None) else None
        gres = mr.name.endswith(".g.resources")
        if want != "baml" and not (want == "resources" and not is_res):
            extra = f" {len(entries)} entries" if entries is not None else ""
            vis = " public" if mr.public else ""
            lines.append(f"managed {mr.name} {mr.size} B {mr.kind}{vis}{extra}")
        if entries and (all_entries or gres or want == "baml"):
            for e in entries:
                if want == "baml" and not e.name.lower().endswith(".baml"):
                    continue
                lines.append(f"  {mr.name}/{e.name} {e.size} B {e.preview}")
    return lines


# -- WPF (BAML through ilspycmd) -------------------------------------------------------------

def baml_names(path: Path) -> list[tuple[str, str]]:
    """(container, entry) of each BAML resource."""
    asm = _Asm(path)
    out: list[tuple[str, str]] = []
    for mr in manifest_resources(asm):
        if mr.name.endswith(".g.resources") and mr.payload is not None:
            for e in read_resources(mr.payload) or []:
                if e.name.lower().endswith(".baml"):
                    out.append((mr.name, e.name))
    return out


_CAPTION_ATTRS = ("Header", "Content", "Text", "Title", "Label", "Caption")
_NOT_EVENT = frozenset(["Name", "Uid", "Tag", "Key", "Style", "Command", "CommandParameter", "Target",
                        "Source", "DataContext", "ToolTip", "Margin", "Padding", "Width", "Height",
                        "Class", "TargetType", "Header", "Content", "Text", "Title", "Label", "Icon"])
_KNOWN_EVENTS = frozenset("""Click DoubleClick Loaded Unloaded Initialized Closed Closing Activated Deactivated
MouseDown MouseUp MouseMove MouseEnter MouseLeave MouseWheel MouseDoubleClick MouseLeftButtonDown
MouseLeftButtonUp MouseRightButtonDown MouseRightButtonUp PreviewMouseDown PreviewMouseUp
PreviewMouseLeftButtonDown PreviewMouseLeftButtonUp PreviewKeyDown PreviewKeyUp KeyDown KeyUp
TextChanged SelectionChanged Checked Unchecked Indeterminate Drop DragEnter DragOver DragLeave
GotFocus LostFocus GotKeyboardFocus LostKeyboardFocus ValueChanged SizeChanged ContextMenuOpening
Executed CanExecute PreviewExecuted PreviewCanExecute SelectedItemChanged SelectedDateChanged
Expanded Collapsed Opened Closed SubmenuOpened Navigated Navigating Tick Sorting AutoGeneratingColumn
CellEditEnding RowEditEnding BeginningEdit PreviewTextInput TextInput StateChanged Checked ScrollChanged
DataContextChanged IsVisibleChanged LayoutUpdated SourceUpdated TargetUpdated Handler""".split())


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _norm_cmd(text: str) -> str:
    t = text.strip()
    m = re.fullmatch(r"\{\s*x:Static\s+([^}]+)\}", t)
    if m:
        t = m.group(1).strip()
    for p in ("ApplicationCommands.", "NavigationCommands.", "EditingCommands.", "ComponentCommands.",
              "MediaCommands."):
        if t.startswith(p):
            t = t[len(p):]
    return t


# characters XML 1.0 does not allow (ilspycmd writes them raw into attribute values), raw or as a reference
_BAD_XML = re.compile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\ufffe\\uffff]|&#(?:[xX]0*(?:[0-8bBcCeEfF]|1[0-9a-fA-F])|"
                      "0*(?:[0-8]|1[12]|1[4-9]|2\\d|3[01]));")
_BINDING = re.compile(r"\{\s*(?:\w+:)?Binding\s+(?:Path\s*=\s*)?((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)\s*[,}]")
_PATH_HOPS = frozenset(["DataContext", "PlacementTarget", "Tag"])     # path steps that still end at a view model
_TYPE_IN = (re.compile(r"Type\s*=\s*(?:\{x:Type\s+)?(?:\w+:)?([\w.]+)"),
            re.compile(r"(?:DesignInstance|x:Type)\s+(?:\w+:)?([\w.]+)"))
_MAX_VM = 6


_STRAY_AMP = re.compile(r"&(?!(?:#\d+|#[xX][0-9a-fA-F]+|amp|lt|gt|quot|apos);)")


def clean_xaml(xaml: str) -> str:
    """The text without XML-illegal characters; a bare ``&`` (ilspycmd leaves some in text) becomes ``&amp;``."""
    return _STRAY_AMP.sub("&amp;", _BAD_XML.sub(" ", xaml))


def _data_type(v: str, reskeys: dict[str, str]) -> str:
    """Short type name a DataContext / x:DataType value names, or ""."""
    v = v.strip()
    m = re.match(r"\{\s*(?:StaticResource|DynamicResource)\s+(?:ResourceKey\s*=\s*)?([\w.]+)\s*\}", v)
    if m:
        return reskeys.get(m.group(1), "")
    if v.startswith("{"):
        m = _TYPE_IN[0].search(v) or _TYPE_IN[1].search(v)
        return m.group(1).rsplit(".", 1)[-1] if m else ""
    return v.split(":")[-1].rsplit(".", 1)[-1] if re.fullmatch(r"[\w:.]+", v) else ""


def _handlers_in(asm: _Asm, ins: list[tuple[str, int]], lo: int, hi: int) -> list[tuple[int, str]]:
    """(MethodDef token, role) of each delegate made from a method in ``ins[lo:hi]``. The role is
    ``execute`` / ``can`` when an object initializer stores the delegate with ``set_*Execute*`` /
    ``set_*CanExecute*``; "" when it is a constructor argument (position decides)."""
    out = []
    for i in range(lo, hi):
        op, a = ins[i]
        if op not in ("ldftn", "ldvirtftn"):
            continue
        role = ""
        if i + 2 < len(ins) and ins[i + 1][0] == "newobj" and ins[i + 2][0] in ("call", "callvirt"):
            nm = asm.member_name(ins[i + 2][1])
            if nm.startswith("set_"):
                low = nm.lower()
                role = "can" if "canexecute" in low or low.startswith("set_can") else "execute" if "execute" in low else ""
        out.append((a, role))
    return out


def _getter_handlers(asm: _Asm, t: Any, g: Any) -> list[tuple[int, str]]:
    """Delegates a command property creates: the ``ldftn`` targets in its getter, else those stored into the
    backing field by the method (constructor) that sets it."""
    code = asm.code_of(g.token)
    if code is None:
        return []
    ins = decode(code)
    hs = _handlers_in(asm, ins, 0, len(ins))
    if hs:
        return hs
    fields = {a for op, a in ins if op in ("ldfld", "ldsfld")}
    for m in asm.methods_of.get(t.token, []):
        if m.token == g.token:
            continue
        mc = asm.code_of(m.token)
        if mc is None or (bytes([0x7D]) not in mc and bytes([0x80]) not in mc):   # stfld / stsfld
            continue
        mi = decode(mc)
        start = 0
        for j, (op, a) in enumerate(mi):
            if op in ("stfld", "stsfld"):
                if a in fields:
                    hs = _handlers_in(asm, mi, start, j)
                    if hs:
                        return hs
                start = j + 1
    return []


def view_model_commands(asm: _Asm, prop: str, prefer: set[str]) -> tuple[list[tuple[str, list[tuple[int, str]]]], int]:
    """([(``Type::get_<prop>``, handler tokens)], types left out). Types named in ``prefer`` (short names) win;
    else every type with the property."""
    found = [(t, g) for t, g in asm.getters_named(prop) if "<>c" not in t.name]
    pref = [(t, g) for t, g in found if dn._short(t.name).rsplit(".", 1)[-1] in prefer]
    use = pref or found
    out = []
    for t, g in use[:_MAX_VM]:
        try:
            hs = _getter_handlers(asm, t, g)
        except (IndexError, ValueError, KeyError):
            hs = []
        out.append((f"{dn._short(t.name)}::{g.name}", hs))
    return out, max(0, len(use) - _MAX_VM)


def xaml_rows(xaml: str, source: str, asm: _Asm | None, bad: list[str] | None = None) -> list[UiRow]:
    """Event and command rows of one XAML document. ``source`` names the document when it has no x:Class;
    ``bad`` collects the source of a document that does not parse."""
    xaml = clean_xaml(xaml)
    try:
        root = ET.fromstring(xaml.encode("utf-8") if xaml.startswith("<?xml") else xaml)
    except ET.ParseError:
        if bad is not None:
            bad.append(source)
        return []
    cls = ""
    for k, v in root.attrib.items():
        if _local(k) == "Class":
            cls = v
    form = cls or source
    methods: dict[str, int] = {}
    if asm is not None and cls in asm.type_by_name:
        for m in asm.methods_of.get(asm.type_by_name[cls].token, []):
            methods.setdefault(m.name, m.token)
    cmdb: dict[str, tuple[str, str]] = {}         # command -> (Executed, CanExecute)
    reskeys: dict[str, str] = {}                  # x:Key -> short type name of the resource element
    for e in root.iter():
        if _local(e.tag) == "CommandBinding":
            c = _norm_cmd(e.attrib.get("Command", ""))
            cmdb[c] = (e.attrib.get("Executed", ""), e.attrib.get("CanExecute", ""))
        for k, v in e.attrib.items():
            if _local(k) == "Key" and "." not in _local(e.tag):
                reskeys[v] = _local(e.tag)
    rows: list[UiRow] = []
    vm_cache: dict[tuple[str, str], tuple] = {}

    def add(ctrl: str, ctype: str, cap: str, ev: str, h: str, cmd: str = "") -> None:
        rows.append(UiRow("wpf", form, ctrl, ctype, cap, ev, h, methods.get(h, 0), "", cmd))

    def add_vm(ctrl: str, ctype: str, cap: str, c: str, prop: str, dc: frozenset) -> bool:
        if asm is None:
            return False
        key = (prop, ",".join(sorted(dc)))
        if key not in vm_cache:
            vm_cache[key] = view_model_commands(asm, prop, set(dc))
        cands, left = vm_cache[key]
        if not cands:
            return False
        for n, (via, hs) in enumerate(cands):
            hs = sorted(hs, key=lambda h: h[1] != "execute")           # a known execute delegate first
            disp = [(_handler(asm, h, ""), role) for h, role in hs]
            main = disp[0][0] if disp else ("", 0)
            r = UiRow("wpf", form, ctrl, ctype, cap, "Command", main[0], main[1], "", c)
            r.via = via + (f" +{left} more types" if left and n == len(cands) - 1 else "")
            r.alt = tuple(("can " if (role == "can" or (not role and len(disp) == 2)) else "also ") + d[0]
                          for d, role in disp[1:])
            rows.append(r)
        return True

    def contexts(e: ET.Element, dc: frozenset) -> frozenset:
        found = set()
        for k, v in e.attrib.items():
            if _local(k) in ("DataContext", "DataType"):
                t = _data_type(v, reskeys)
                if t:
                    found.add(t)
        for c in e:
            if _local(c.tag) == f"{_local(e.tag)}.DataContext" and len(c) and "." not in _local(c[0].tag):
                found.add(_local(c[0].tag))
        return frozenset(found) or dc

    def walk(e: ET.Element, owner: str, dc: frozenset, depth: int = 0) -> None:
        tag = _local(e.tag)
        if "." in tag or depth > 200:               # property element: its children belong to the owner
            for c in e:
                walk(c, owner, dc, depth + 1)
            return
        dc = contexts(e, dc)
        attrs = {_local(k): v for k, v in e.attrib.items()}
        name = attrs.get("Name", "")
        ctrl = name
        cap = ""
        for a in _CAPTION_ATTRS:
            v = attrs.get(a, "")
            if v and not v.startswith("{"):
                cap = v
                break
        if not cap and e.text and e.text.strip():
            cap = e.text.strip()
        if tag == "EventSetter":
            add(owner, "EventSetter", "", attrs.get("Event", ""), attrs.get("Handler", ""))
        elif tag == "CommandBinding":
            c = _norm_cmd(attrs.get("Command", ""))
            for ev in ("Executed", "CanExecute", "PreviewExecuted", "PreviewCanExecute"):
                if attrs.get(ev):
                    add("", "CommandBinding", c, ev, attrs[ev], c)
        else:
            for a, v in attrs.items():
                if a in _NOT_EVENT or a.startswith("xmlns") or not v or v.startswith("{"):
                    continue
                if a in _KNOWN_EVENTS or (v in methods and a[0].isupper() and _looks_event(a)):
                    add(ctrl, tag, cap, a, v)
            cmd = attrs.get("Command", "")
            if cmd:
                c = _norm_cmd(cmd)
                ex = cmdb.get(c)
                bm = _BINDING.search(cmd)
                path = bm.group(1).split(".") if bm else []
                if not all(h in _PATH_HOPS for h in path[:-1]):
                    bm = None
                if ex is not None and ex[0]:
                    add(ctrl, tag, cap, "Command", ex[0], c)
                elif not (bm and add_vm(ctrl, tag, cap, c, path[-1], dc)):
                    add(ctrl, tag, cap, "Command", "", c)
        nxt = name or owner
        for c in e:
            walk(c, nxt, dc, depth + 1)

    walk(root, "", frozenset())
    return rows


def _looks_event(attr: str) -> bool:
    """An attribute whose value names a method of the code-behind class is an event when it is not a
    plain property: events are verbs or end in a participle (Changed, Clicked, Opened, ...)."""
    return bool(re.search(r"(Click|Clicked|Changed|Changing|Opened|Opening|Closed|Closing|Loaded|Executed|"
                          r"Checked|Drop|Down|Up|Move|Enter|Leave|Focus|Press|Edit|Edited|Validate|"
                          r"Selected|Expanded|Collapsed|Navigated|Tick|Sort\w*|Event|Handler)$", attr))


def wpf_rows(path: Path, run: Callable[[str], tuple[bytes | None, str | None]], cache: Path,
             form_hint: str = "") -> tuple[list[UiRow], str]:
    """(rows, fact line or ""). ``run(name)`` gives the bytes of ``ilspycmd --resource name``. XAML texts are cached under ``cache``. ``form_hint`` names a form: only the
    BAML files whose name contains it are read first (all of them when none matches)."""
    names = baml_names(path)
    if not names:
        return [], ""
    asm = _Asm(path)
    cache.mkdir(parents=True, exist_ok=True)
    hint = form_hint.rsplit(".", 1)[-1].lower()
    todo = names
    if hint:
        sel = [n for n in names if hint in n[1].lower()]
        todo = sel or names
    failed: list[str] = []
    unreadable: list[str] = []

    def fetch(item: tuple[str, str]) -> tuple[tuple[str, str], str | None]:
        cont, ent = item
        f = cache / (re.sub(r"[^A-Za-z0-9_.-]", "_", f"{cont}__{ent}") + ".xaml")
        try:
            return item, f.read_text(encoding="utf-8")
        except OSError:
            pass
        raw, err = run(f"{cont}/{ent}")
        text = raw.decode("utf-8", "replace").replace(chr(13) + chr(10), chr(10)) if raw is not None else None
        if text is None:
            failed.append(f"{ent}: {err}")
            return item, None
        try:
            f.write_text(text, encoding="utf-8")
        except OSError:
            pass
        return item, text

    rows: list[UiRow] = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        for (cont, ent), text in ex.map(fetch, todo):
            if text:
                rows += xaml_rows(text, ent, asm, unreadable)
    notes = [f"wpf: {len(failed)} of {len(todo)} BAML resources not read ({failed[0]})"] if failed else []
    if unreadable:
        names = ", ".join(n.rsplit("/", 1)[-1] for n in unreadable[:5])
        more = f", +{len(unreadable) - 5} more" if len(unreadable) > 5 else ""
        notes.append(f"({len(unreadable)} XAML documents unreadable: {names}{more})")
    return rows, "\n".join(notes)


# -- selection and output --------------------------------------------------------------------

def _plain(text: str) -> str:
    return text.replace("&", "").replace("_", "").rstrip(".").strip().lower()


def _tiers(rows: list[UiRow], keys: Callable[[UiRow], list[str]], want: str) -> tuple[list[UiRow], str]:
    """Rows with a key equal to ``want``; else with a key that starts with it; else containing it
    (case ignored). Returns (rows, "exact" | "prefix" | "partial") or ([], "")."""
    w = _plain(want)
    if not w:
        return rows, "exact"
    for how, test in (("exact", lambda k: k == w), ("prefix", lambda k: k.startswith(w)),
                      ("partial", lambda k: w in k)):
        sel = [r for r in rows if any(test(_plain(k)) for k in keys(r) if k)]
        if sel:
            return sel, how
    return [], ""


def select_rows(rows: list[UiRow], form: str = "", component: str = "", event: str = "",
                ) -> tuple[list[UiRow], list[str], str]:
    """(rows, fact lines, error line). Filters in this order: form, component, event. A filter with no
    exact match widens to prefix, then part match, and says so in a fact line."""
    facts: list[str] = []
    if form.strip():
        sel, how = _tiers(rows, lambda r: [r.form, r.form.rsplit(".", 1)[-1], r.form.rsplit(".", 1)[-1].lstrip("T")], form)
        if not sel:
            names = sorted({r.form for r in rows})
            more = f" (+{len(names) - 30} more)" if len(names) > 30 else ""
            return [], [], f"error not_found: no form '{form.strip()}' with event wiring (forms: {', '.join(names[:30])}{more})."
        if how != "exact":
            facts.append(f"form '{form.strip()}': no exact name; {how} match, {len({r.form for r in sel})} forms")
        rows = sel
    if component.strip():
        sel, how = _tiers(rows, lambda r: [r.control, r.caption, r.handler.rsplit("::", 1)[-1],
                                           r.command.rsplit(".", 1)[-1], r.command], component)
        if not sel:
            names = sorted({r.control for r in rows if r.control})
            more = f" (+{len(names) - 40} more)" if len(names) > 40 else ""
            return [], [], (f"error not_found: no control, caption, handler or command '{component.strip()}' "
                            f"(controls: {', '.join(names[:40])}{more}).")
        if how != "exact":
            facts.append(f"component '{component.strip()}': no exact name; {how} match, {len(sel)} events")
        rows = sel
    if event.strip():
        sel, how = _tiers(rows, lambda r: [r.event], event)
        if not sel:
            evs = sorted({r.event for r in rows})
            return [], [], f"error not_found: no event '{event.strip()}' (events: {', '.join(evs[:30])})."
        if how != "exact":
            facts.append(f"event '{event.strip()}': no exact name; {how} match, {len(sel)} events")
        rows = sel
    return rows, facts, ""


def row_line(r: UiRow, show_form: bool) -> str:
    parts = [r.form] if show_form else []
    parts.append(r.control or "-")
    if r.ctype:
        parts.append(r.ctype)
    if r.caption and r.ctype != "CommandBinding":
        cap = r.caption.replace("\n", "\n")
        parts.append('"' + (cap[:57] + "…" if len(cap) > 60 else cap) + '"')
    if r.kind == "wpf" and r.event == "Command":
        c = r.command if len(r.command) <= 80 else r.command[:79] + "…"
        parts.append(f"Command {c}")
    elif r.kind == "wpf" and r.ctype == "CommandBinding":
        c = r.command if len(r.command) <= 80 else r.command[:79] + "…"
        parts.append(f"{r.event} for {c}")
    else:
        parts.append(r.event)
    if r.handler:
        parts.append(f"-> {r.handler}" + (f" 0x{r.token:08x}" if r.token else ""))
        outer = lambda_outer(r.handler)
        extra = ([f"lambda in {outer}"] if outer else []) + ([f"via {r.via}"] if r.via else [])
        extra += list(r.alt)
        if extra:
            parts.append("(" + "; ".join(extra) + ")")
    elif r.via:
        parts.append(f"-> {r.via} (no delegate found in the getter)")
    elif r.event == "Command":
        parts.append("-> no CommandBinding in the XAML")
    if r.where:
        parts.append(f"(in {r.where})")
    return " ".join(parts)
