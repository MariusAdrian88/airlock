"""PE resources (dialogs, menus, strings, version info): synthetic PE files with invented content."""

from __future__ import annotations

import shutil
import struct
from pathlib import Path

import pytest

from airlock.config.catalog import CATALOG
from airlock.index.migrations import MIGRATIONS
from airlock.index.store import SCHEMA_VERSION, Store
from airlock.server import peres, roles
from airlock.server.tools import resources as rt
from test_tools import make_ctx


def w(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\0\0"


def pad(b: bytes, n: int = 4) -> bytes:
    return b + b"\0" * (-len(b) % n)


def ctl(style, cid, cls, text, x=1, y=2, cx=30, cy=14, ex=False):
    c = (struct.pack("<H", 0xFFFF) + struct.pack("<H", cls)) if isinstance(cls, int) else w(cls)
    t = w(text) if isinstance(text, str) else struct.pack("<HH", 0xFFFF, text)
    if ex:
        head = struct.pack("<IIIhhhhI", 0, 0, style, x, y, cx, cy, cid & 0xFFFFFFFF)
    else:
        head = struct.pack("<IIhhhhH", style, 0, x, y, cx, cy, cid & 0xFFFF)
    return pad(head + c + t + struct.pack("<H", 0))


VIS = 0x50000000        # WS_CHILD | WS_VISIBLE


def dlg_template(title: str, controls: list[bytes], ex: bool = False) -> bytes:
    style = 0x80C80000 | peres.DS_SETFONT
    if ex:
        head = struct.pack("<HHIIIHhhhh", 1, 0xFFFF, 0, 0, style, len(controls), 0, 0, 200, 80)
        font = struct.pack("<HHBB", 8, 400, 0, 1) + w("MS Shell Dlg")
    else:
        head = struct.pack("<IIHhhhh", style, 0, len(controls), 0, 0, 200, 80)
        font = struct.pack("<H", 8) + w("MS Shell Dlg")
    body = head + struct.pack("<H", 0) + struct.pack("<H", 0) + w(title) + font
    return pad(body) + b"".join(controls)


def std_controls(ex: bool):
    return [
        ctl(VIS | 0x10000 | 1, 1, 0x80, "Go", ex=ex),                 # BS_DEFPUSHBUTTON, tabstop
        ctl(VIS | 0x10000 | 0, 2, 0x80, "Stop", ex=ex),
        ctl(VIS | 3, -1, 0x82, 0x7F00, ex=ex),                         # SS_ICON, ordinal title
        ctl(VIS | 0x10000 | 0x80 | 0x4, 1001, 0x81, "", ex=ex),        # ES_MULTILINE
        ctl(VIS | 3, 1002, 0x85, "", ex=ex),                           # CBS_DROPDOWNLIST
        ctl(0x40000000 | 0x08000000 | 2, 1003, "MyCtl", "x", ex=ex),   # hidden, disabled, custom class
    ]


def menu_template() -> bytes:
    def item(flags, iid, text):
        return struct.pack("<HH", flags, iid) + w(text)

    def popup(flags, text):
        return struct.pack("<H", flags | peres.MF_POPUP) + w(text)

    return (struct.pack("<HH", 0, 0)
            + popup(0, "&File") + item(0, 100, "&Open...\tCtrl+O") + item(0, 0, "")
            + popup(0, "Recent") + item(peres.MF_END, 110, "One") + item(peres.MF_END, 101, "E&xit")
            + popup(peres.MF_END, "&Help") + item(peres.MF_END, 200, "About"))


def menuex_template() -> bytes:
    def ex(typ, iid, res, text, helpid=False):
        b = struct.pack("<IIIH", typ, 0, iid, res) + w(text)
        b = pad(b)
        return b + struct.pack("<I", 0) if helpid else b

    hdr = struct.pack("<HHI", 1, 4, 0)
    return (hdr + ex(0, 0, 1, "&Tools", True) + ex(0, 300, 0, "Run") + ex(0x800, 0, 0, "")
            + ex(0, 301, peres.MF_END, "Stop") + ex(0, 0, 1 | peres.MF_END, "Extra", True)
            + ex(0, 302, peres.MF_END, "Deep"))


def string_block(items: dict[int, str]) -> bytes:
    out = b""
    for i in range(16):
        s = items.get(i, "")
        out += struct.pack("<H", len(s)) + s.encode("utf-16-le")
    return out


def version_blob() -> bytes:
    def block(key, val=b"", vlen=0, typ=1, kids=b""):
        head = pad(struct.pack("<HHH", 0, vlen, typ) + w(key), 4)
        b = pad(head + val, 4) + kids
        return struct.pack("<H", len(b)) + b[2:]

    def sv(key, text):
        v = w(text)
        return pad(block(key, v, len(v) // 2), 4)

    ffi = struct.pack("<13I", 0xFEEF04BD, 0x10000, 0x00020001, 0x00030004, 0x00020001, 0x00030004,
                      0x3F, 0, 4, 1, 0, 0, 0)
    table = block("040904B0", kids=sv("CompanyName", "Acme") + sv("ProductName", "Widget"))
    sfi = block("StringFileInfo", kids=pad(table, 4), typ=1)
    return pad(block("VS_VERSION_INFO", ffi, 52, 0, pad(sfi, 4)), 4)


def rsrc_blob(res: dict[tuple[int, int | str, int], bytes], sect_rva: int = 0x1000) -> bytes:
    """The bytes of a .rsrc section placed at ``sect_rva``: (type, id or name, lang) -> data."""
    types: dict[int, dict[int | str, dict[int, bytes]]] = {}
    for (t, i, lg), data in res.items():
        types.setdefault(t, {}).setdefault(i, {})[lg] = data
    # layout: directories first, then names, data entries, data
    blob = bytearray()
    dirs: list[tuple[int, list[tuple[int | str, int, bool]]]] = []   # placeholders built in two passes

    def dir_size(n_named: int, n_id: int) -> int:
        return 16 + 8 * (n_named + n_id)

    # pass 1: sizes
    pos = dir_size(0, len(types))
    type_off: dict[int, int] = {}
    name_off: dict[tuple[int, int | str], int] = {}
    for t, names in types.items():
        type_off[t] = pos
        pos += dir_size(sum(isinstance(k, str) for k in names), sum(isinstance(k, int) for k in names))
    for t, names in types.items():
        for k, langs in names.items():
            name_off[(t, k)] = pos
            pos += dir_size(0, len(langs))
    entries_off = pos
    pos += 16 * sum(len(v) for names in types.values() for v in names.values())
    strings_off = pos
    string_pos: dict[str, int] = {}
    for names in types.values():
        for k in names:
            if isinstance(k, str):
                string_pos[k] = pos
                pos += 2 + 2 * len(k)
    data_off = pad(b"\0" * pos, 4).__len__()
    # pass 2: write
    out = bytearray(data_off)

    def put_dir(off: int, entries: list[tuple[int, int]], n_named: int = 0) -> None:
        struct.pack_into("<IIHHHH", out, off, 0, 0, 0, 0, n_named, len(entries) - n_named)
        for j, (name, target) in enumerate(entries):
            struct.pack_into("<II", out, off + 16 + 8 * j, name, target)

    put_dir(0, [(t, 0x80000000 | type_off[t]) for t in types])
    dpos = 0
    data_chunks = bytearray()
    entry_i = 0
    for t, names in types.items():
        named = sorted(k for k in names if isinstance(k, str))
        ids = sorted(k for k in names if isinstance(k, int))
        put_dir(type_off[t], [(0x80000000 | string_pos[k], 0x80000000 | name_off[(t, k)]) for k in named]
                + [(k, 0x80000000 | name_off[(t, k)]) for k in ids], len(named))
        for k in named + ids:
            langs = names[k]
            ents = []
            for lg in sorted(langs):
                eoff = entries_off + 16 * entry_i
                entry_i += 1
                d = langs[lg]
                rva = sect_rva + data_off + len(data_chunks)
                struct.pack_into("<IIII", out, eoff, rva, len(d), 0, 0)
                data_chunks += pad(d, 4)
                ents.append((lg, eoff))
            put_dir(name_off[(t, k)], ents)
    for k, off in string_pos.items():
        struct.pack_into("<H", out, off, len(k))
        out[off + 2:off + 2 + 2 * len(k)] = k.encode("utf-16-le")
    del dpos, blob, dirs, strings_off
    return bytes(out) + bytes(data_chunks)


def make_rsrc_pe(path: Path, res: dict[tuple[int, int | str, int], bytes]) -> None:
    """A PE32 file whose .rsrc holds ``res``: (type, id or name, lang) -> data."""
    sect_rva = 0x1000
    rsrc = rsrc_blob(res, sect_rva)
    vsize = len(rsrc)
    raw = (vsize + 0x1FF) & ~0x1FF
    opt_size = 0xE0
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, opt_size, 0x2102)
    opt = struct.pack("<HBBIIIII", 0x10B, 0, 0, 0, vsize, 0, 0, sect_rva)
    opt += struct.pack("<II", sect_rva, 0x400000) + struct.pack("<II", 0x1000, 0x200)
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0) + struct.pack("<IIII", 0, 0x2000, 0x200, 0)
    opt += struct.pack("<HH", 3, 0) + struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16) + b"\0" * 16 + struct.pack("<II", sect_rva, vsize) + b"\0" * (13 * 8)
    assert len(opt) == opt_size
    sect = struct.pack("<8sIIIIIIHHI", b".rsrc", vsize, sect_rva, raw, 0x200, 0, 0, 0, 0, 0x40000040)
    hdr = (b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40) + b"PE\0\0" + coff + opt + sect).ljust(0x200, b"\0")
    path.write_bytes(hdr + rsrc.ljust(raw, b"\0"))


def sample_pe(path: Path) -> None:
    make_rsrc_pe(path, {
        (5, 129, 0x409): dlg_template("About", std_controls(False)),
        (5, 129, 0x407): dlg_template("Info", std_controls(False)[:2]),
        (5, "IDD_EX", 0x409): dlg_template("Extended", std_controls(True), ex=True),
        (4, 128, 0x409): menu_template(),
        (4, 130, 0x409): menuex_template(),
        (6, 7, 0x409): string_block({0: "alpha", 3: "bravo text"}),
        (6, 8, 0x409): string_block({15: "last of block"}),
        (16, 1, 0x409): version_blob(),
        (10, 5, 0): b"raw",
    })


# -- parsers ----------------------------------------------------------------------------------

@pytest.mark.parametrize("ex", [False, True])
def test_dialog_template(ex):
    d = peres.parse_dialog(dlg_template("Title", std_controls(ex), ex=ex))
    assert (d.caption, d.cx, d.cy) == ("Title", 200, 80)
    assert [(c.ctrl_id, c.cls) for c in d.controls] == [
        (1, "Button"), (2, "Button"), (-1, "Static"), (1001, "Edit"), (1002, "ComboBox"), (1003, "MyCtl")]
    assert d.controls[0].style == "BS_DEFPUSHBUTTON,tabstop" and d.controls[0].caption == "Go"
    assert d.controls[1].style == "BS_PUSHBUTTON,tabstop"
    assert d.controls[2].caption == "#32512" and d.controls[2].style == "SS_ICON"
    assert d.controls[3].style == "ES_MULTILINE,tabstop"
    assert d.controls[4].style == "CBS_DROPDOWNLIST"
    assert d.controls[5].style == "hidden,disabled" and d.controls[5].caption == "x"


def test_menu_templates():
    m = peres.parse_menu(menu_template())
    assert [(i.item_id, i.path) for i in m] == [
        (None, "File"), (100, "File > Open..."), (None, "File > Recent"), (110, "File > Recent > One"),
        (101, "File > Exit"), (None, "Help"), (200, "Help > About")]
    x = peres.parse_menu(menuex_template())
    assert [(i.item_id, i.path) for i in x] == [
        (None, "Tools"), (300, "Tools > Run"), (301, "Tools > Stop"), (None, "Extra"),
        (302, "Extra > Deep")]


def test_string_block_ids():
    assert peres.parse_string_block(string_block({0: "a", 3: "b"}), 7) == [(96, "a"), (99, "b")]


def test_parse_file_and_version(tmp_path):
    p = tmp_path / "s.exe"
    sample_pe(p)
    r = peres.parse_file(p)
    assert r is not None
    assert {(e.type_name, e.key, e.lang) for e in r.entries} >= {("DIALOG", "129", 0x407), ("RCDATA", "5", 0),
                                                                   ("DIALOG", "IDD_EX", 0x409)}
    assert {k for k, _, _ in r.dialogs} == {"129", "IDD_EX"}
    assert sorted((i, s) for i, _, s in r.strings) == [(96, "alpha"), (99, "bravo text"), (127, "last of block")]
    v = peres.version_info(p)
    assert v[0] == "FileVersion (fixed): 2.1.3.4"
    assert "CompanyName: Acme" in v and "ProductName: Widget" in v


def test_not_a_pe(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"not a pe file")
    assert peres.parse_file(p) is None and peres.version_info(p) is None


# -- storage and tools -------------------------------------------------------------------------

def _project(tmp_path, with_second=False):
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    ix.current = "proj"
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    ids = []
    for name, sha in [("app.exe", "ab" * 32)] + ([("lib.dll", "cd" * 32)] if with_second else []):
        sample_pe(art / sha)
        bid = st.upsert_binary(sha, name, format="pe32", arch="x86", pointer_size=4,
                               image_base=0x400000, toolchain="msvc", analysis_profile="p")
        ix.set_status(st, bid, "ready")
        ids.append(bid)
    return ctx, st, ids


def test_schema_and_migration():
    assert SCHEMA_VERSION >= 9 and 9 in MIGRATIONS


def test_migration_from_v8(tmp_path):
    db = tmp_path / "i.sqlite"
    with Store(db) as s:
        for t in ("res_dialog", "res_control", "res_menu_item", "res_string"):
            s.db.execute(f"DROP TABLE {t}")
        s.set_meta("schema_version", "8")
        s.db.commit()
    with Store(db) as s:
        assert s.schema_version >= 9
        s.db.execute("SELECT * FROM res_control").fetchall()
        names = {r[1] for r in s.db.execute("PRAGMA index_list(res_control)")}
        assert "res_control_by_id" in names


def test_ensure_fills_tables_and_is_idempotent(tmp_path):
    ctx, st, (bid,) = _project(tmp_path)
    b = st.get_binary_by_id(bid)
    art = ctx.indexer.paths("proj").artifacts / b.sha256
    assert peres.stale(st, bid) and peres.ensure(st, b, art) is True
    assert peres.ensure(st, b, art) is False
    q = lambda sql: st.db.execute(sql).fetchall()   # noqa: E731
    assert q("SELECT COUNT(*) FROM res_dialog")[0][0] == 3
    assert q("SELECT COUNT(*) FROM res_control WHERE dialog_id='129' AND lang=1033")[0][0] == 6
    assert q("SELECT item_id IS NULL, path FROM res_menu_item WHERE menu_id='128' ORDER BY seq")[0][:] == (1, "File")
    assert q("SELECT COUNT(*) FROM res_string")[0][0] == 3
    assert q("SELECT text FROM res_string WHERE string_id=96")[0][0] == "alpha"
    st.set_meta(f"resources_version:{bid}", "0")            # older version -> parsed again
    assert peres.ensure(st, b, art) is True
    assert q("SELECT COUNT(*) FROM res_string")[0][0] == 3


def test_tools_single_binary(tmp_path):
    ctx, _st, _ = _project(tmp_path)
    out = rt.dialogs(ctx)
    assert out.splitlines()[0].startswith("129 | \"About\" | 6 controls") and "also 0x0407" in out
    assert "IDD_EX | \"Extended\" | 6 controls" in out
    d = rt.dialogs(ctx, "129")
    lines = d.splitlines()
    assert lines[0].startswith("dialog 129 \"About\"")
    assert "  id=1 Button \"Go\" BS_DEFPUSHBUTTON,tabstop" in lines
    assert "  id=-1 Static \"#32512\" SS_ICON" in lines
    assert rt.dialogs(ctx, "129", lang=0x407).count("\n") == 2
    assert "dialog 129 \"Info\"" in rt.dialogs(ctx, "129", lang=0x407)
    assert rt.dialogs(ctx, "0x81").startswith("dialog 129")
    assert rt.dialogs(ctx, "idd_ex").startswith("dialog IDD_EX")
    assert rt.dialogs(ctx, "999").startswith("error not_found")
    other = rt.dialogs(ctx, "129", lang=0x999)     # a missing language: the default one, said so
    assert other.startswith('dialog 129 "About"') and "lang 0x0409 (no 0x0999)" in other.splitlines()[0]
    m = rt.menus(ctx, "128").splitlines()
    assert "  id=100 File > Open..." in m and "File >" in m and "    id=110 File > Recent > One" in m
    assert rt.menus(ctx).splitlines()[0].startswith("128 | 4 items, 3 popups")
    assert "id=302 Extra > Deep" in rt.menus(ctx, "130")
    s = rt.string_tables(ctx, "bravo")
    assert s.splitlines() == ["string table entries: 1", '99 | "bravo text"']
    assert '127 | "last of block"' in rt.string_tables(ctx, "127")
    pg = rt.string_tables(ctx, limit=2).splitlines()
    assert pg[0].startswith("string table entries: ") and len(pg) == 4
    assert "more lines. cursor=c_" in pg[-1]
    nx = rt.string_tables(ctx, limit=2, cursor=pg[-1].rsplit("cursor=", 1)[1]).splitlines()
    assert len(nx) >= 1 and not nx[0].startswith("error")
    assert rt.string_tables(ctx, "zzz").startswith("no string-table")
    r = rt.pe_resources(ctx)
    assert "DIALOG 129 lang=0x0409" in r and "RCDATA 5 lang=0x0000" in r and "MENU 128" in r
    only = rt.pe_resources(ctx, "RT_MENU")
    assert "DIALOG" not in only and "MENU 130" in only
    assert "DIALOG" not in rt.pe_resources(ctx, "4")
    v = rt.version_info(ctx)
    assert "CompanyName: Acme" in v and "FileVersion (fixed)" in v


def test_tools_multi_binary(tmp_path):
    ctx, st, _ = _project(tmp_path, with_second=True)
    every = rt.dialogs(ctx)        # no manifest, no root: every binary, lines tagged with it
    assert "[app.exe] 129 |" in every and "[lib.dll] 129 |" in every
    assert rt.dialogs(ctx, binary="lib.dll").startswith("129 |")
    both = rt.dialogs(ctx, binary="*")
    assert "[app.exe] 129" in both and "[lib.dll] 129" in both
    assert rt.dialogs(ctx, "lib.dll!129").startswith("dialog 129")
    assert rt.dialogs(ctx, "lib.dll!129", binary="app.exe").startswith("error bad_args")
    assert rt.menus(ctx, "lib.dll!128").startswith("menu 128")
    assert "[lib.dll] 99 | " in rt.string_tables(ctx, "bravo", binary="*")


def test_tools_default_to_root_executable(tmp_path):
    from airlock.projects import write_manifest
    ctx, st, _ = _project(tmp_path, with_second=True)
    pp = ctx.indexer.paths("proj")
    write_manifest(pp.manifest, {"name": "proj", "source": {"root_exe": "sub\\lib.dll"}, "files": []})
    out = rt.dialogs(ctx)
    assert out.startswith("129 |") and "[" not in out.splitlines()[0]
    assert "lib.dll" in rt.version_info(ctx) or rt.version_info(ctx).startswith("lib.dll")


def test_system_binary_if_present(tmp_path):
    src = Path(r"C:\Windows\System32\notepad.exe")
    if not src.is_file():
        pytest.skip("notepad.exe not present")
    scratch = tmp_path / "np.exe"
    shutil.copy(src, scratch)
    assert peres.parse_file(scratch) is not None
    assert any("ProductName" in x for x in (peres.version_info(scratch) or []))


def test_catalog_and_clean_gate(tmp_path):
    for t in ("pe_resources", "dialogs", "menus", "string_tables", "version_info"):
        assert CATALOG[t].set == "resources" and not CATALOG[t].clean_safe
        s = roles.SessionState(roles.CLEAN, None)
        assert roles.gate(s, t).startswith("error wrong_role")
