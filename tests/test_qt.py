"""M8: Qt metaobjects parsed from synthetic PEs (Qt5 and Qt6 layouts, 32 and 64 bit), tables, tool, hints.

Every class and method name is invented. No Ghidra."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from airlock.index.migrations import MIGRATIONS
from airlock.index.store import SCHEMA_VERSION, Store
from airlock.server import qt
from airlock.server.cpp import Image
from airlock.server.tools import qt as qtools
from test_tools import make_ctx

TEXT_VA, DATA_VA = 0x1000, 0x3000


class Pe:
    """A synthetic Qt binary. ``major`` 5 (revision 8, QByteArrayData table) or 6 (revision 12, offsets)."""

    def __init__(self, psize: int, major: int, indirect: bool = False) -> None:
        self.ps, self.major, self.indirect = psize, major, indirect     # indirect: QT_NO_DATA_RELOCATION SuperData
        self.imports: dict[int, str] = {}
        self.base = 0x400000 if psize == 4 else 0x140000000
        self.text = bytearray(0x1000)
        self.data = bytearray(0x8000)
        self.tpos = 0
        self.dpos = 0
        self.metas: dict[str, int] = {}
        self.code: dict[str, int] = {}
        self.fix: list[tuple[int, str]] = []

    def stub(self, name: str) -> int:
        va = self.base + TEXT_VA + self.tpos
        self.text[self.tpos] = 0xC3
        self.tpos += 16
        self.code[name] = va
        return va

    def alloc(self, n: int, align: int = 0) -> int:
        align = align or self.ps
        self.dpos = (self.dpos + align - 1) // align * align
        va = self.base + DATA_VA + self.dpos
        self.dpos += n
        return va

    def put(self, va: int, raw: bytes) -> None:
        off = va - self.base - DATA_VA
        self.data[off:off + len(raw)] = raw

    def p(self, v: int) -> bytes:
        return struct.pack("<I" if self.ps == 4 else "<Q", v)

    def klass(self, name: str, parent: str | None, methods=(), props=(), enums=(), info=(), nsignals=None,
              metacall=True, parent_import: str | None = None) -> int:
        """methods: (kind, name, ret, [(type, pname)]); kind signal|slot|method. Signals must come first."""
        strings: list[str] = []

        def sid(s: str) -> int:
            if s not in strings:
                strings.append(s)
            return strings.index(s)

        builtin = {"int": 2, "bool": 1, "QString": 10, "void": 43, "double": 6}

        def tword(t: str) -> int:
            return builtin[t] if t in builtin else 0x80000000 | sid(t)

        sid(name)
        for k, v in info:
            sid(k), sid(v)
        mt = {"signal": 0x06, "slot": 0x0A, "method": 0x02}
        mw = 6 if self.major == 6 else 5
        pw = 5 if self.major == 6 else 3
        ew = 5
        nsig = sum(1 for m in methods if m[0] == "signal") if nsignals is None else nsignals
        hdr = 14
        iinfo = hdr
        imeth = iinfo + 2 * len(info)
        iparam = imeth + mw * len(methods)
        blocks, params_at, cur = [], [], iparam
        for kind, mname, ret, pars in methods:
            params_at.append(cur)
            blk = [tword(ret)] + [tword(t) for t, _ in pars] + [sid(n) for _, n in pars]
            blocks.append(blk)
            cur += len(blk)
        iprop = cur
        has_notify = self.major == 5 and any(p[3] is not None for p in props)
        iprop_end = iprop + pw * len(props) + (len(props) if has_notify else 0)
        ienum = iprop_end
        ival = ienum + ew * len(enums)
        words = [12 if self.major == 6 else 8, sid(name), len(info), iinfo, len(methods), imeth if methods else 0,
                 len(props), iprop if props else 0, len(enums), ienum if enums else 0, 0, 0, 0, nsig]
        for k, v in info:
            words += [sid(k), sid(v)]
        for i, (kind, mname, ret, pars) in enumerate(methods):
            words += [sid(mname), len(pars), params_at[i], sid(""), mt[kind] | 0x40 * 0 | 0x02 * 0 | 0x02]
            words[-1] = (mt[kind] & 0x0C) | 2
            if mw == 6:
                words.append(0)
        for blk in blocks:
            words += blk
        for pname, ptype, flags, notify in props:
            fl = flags | (0x00400000 if notify is not None and self.major == 5 else 0)   # Qt6 has no Notify flag
            if self.major == 6:
                words += [sid(pname), tword(ptype), fl, notify if notify is not None else 0xFFFFFFFF, 0]
            else:
                words += [sid(pname), tword(ptype), fl]
        if has_notify:
            words += [p[3] if p[3] is not None else 0xFFFFFFFF for p in props]
        vals_at = ival
        enum_words, val_words = [], []
        for ename, values in enums:
            enum_words += [sid(ename), sid(ename), 0, len(values), vals_at + len(val_words)]
            for vn, vv in values:
                val_words += [sid(vn), vv]
        words += enum_words + val_words
        # string data
        if self.major == 5:
            isz = 16 if self.ps == 4 else 24
            tab = self.alloc(isz * len(strings))
            chars = b"".join(s.encode() + b"\0" for s in strings)
            cva = self.alloc(len(chars), 1)
            self.put(cva, chars)
            pos = 0
            for i, s in enumerate(strings):
                item = tab + i * isz
                off = (cva + pos) - item
                raw = struct.pack("<iiI", -1, len(s), 0)
                raw += (struct.pack("<i", off) if self.ps == 4 else struct.pack("<I", 0) + struct.pack("<q", off))
                self.put(item, raw)
                pos += len(s) + 1
            sdata = tab
        else:
            tab = self.alloc(8 * len(strings) + sum(len(s) + 1 for s in strings), 4)
            pos = 8 * len(strings)
            for i, s in enumerate(strings):
                self.put(tab + 8 * i, struct.pack("<II", pos, len(s)))
                self.put(tab + pos, s.encode() + b"\0")
                pos += len(s) + 1
            sdata = tab
        dva = self.alloc(4 * len(words), 4)
        self.put(dva, struct.pack(f"<{len(words)}I", *words))
        mc = self.stub(f"{name}.metacall") if metacall else 0
        n = 7 if self.major == 6 else 6
        cells = [0, sdata, dva, mc, 0] + ([0, 0] if self.major == 6 else [0])
        if self.indirect:
            cells = [0] + cells                       # direct, then the getter word (the first cell above)
            n += 1
        meta = self.alloc(n * self.ps)
        self.metas[name] = meta
        self.put(meta, b"".join(self.p(c) for c in cells))
        if parent or parent_import:
            self.fix.append((meta, parent or "", parent_import or ""))
        return meta

    def write(self, path: Path) -> None:
        for meta, parent, imp in self.fix:
            if not self.indirect:
                self.put(meta, self.p(self.metas[parent]))
                continue
            g = self.stub(f"getter{meta:x}")          # lea rax,[rip+d]; ret  /  mov rax,[rip+d]; ret
            if imp:
                slot = self.alloc(8)
                self.imports[slot] = f"?staticMetaObject@{imp}@@2UQMetaObject@@B"
                op, target = 0x8B, slot
            else:
                op, target = 0x8D, self.metas[parent]
            off = g - self.base - TEXT_VA
            self.text[off:off + 8] = bytes([0x48, op, 0x05]) + struct.pack("<i", target - (g + 7)) + b"\xc3"
            self.put(meta + self.ps, self.p(g))
        plus = self.ps == 8
        text, data = bytes(self.text), bytes(self.data)
        magic = 0x20B if plus else 0x10B
        opt = struct.pack("<HBBIII", magic, 0, 0, len(text), len(data), 0)
        opt += struct.pack("<II", TEXT_VA, TEXT_VA)
        if plus:
            opt += struct.pack("<Q", self.base)
        else:
            opt += struct.pack("<II", DATA_VA, self.base)
        opt += struct.pack("<II", 0x1000, 0x200)
        opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
        opt += struct.pack("<IIII", 0, DATA_VA + 0x8000, 0x200, 0)
        opt += struct.pack("<HH", 3, 0)
        opt += struct.pack("<QQQQ" if plus else "<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
        opt += struct.pack("<II", 0, 16) + b"\0" * (16 * 8)
        coff = struct.pack("<HHIIIHH", 0x8664 if plus else 0x14C, 2, 0, 0, 0, len(opt), 0x2022 if plus else 0x2102)
        off = 0x200
        sects = b""
        for name, va, raw, ch in ((b".text", TEXT_VA, text, 0x60000020), (b".data", DATA_VA, data, 0xC0000040)):
            sects += struct.pack("<8sIIIIIIHHI", name, len(raw), va, len(raw), off, 0, 0, 0, 0, ch)
            off += len(raw)
        hdr = (b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40) + b"PE\0\0" + coff + opt + sects).ljust(0x200, b"\0")
        path.write_bytes(hdr + text + data)


def build(path: Path, psize: int, major: int) -> Pe:
    pe = Pe(psize, major)
    pe.klass("Base", None, methods=[("signal", "changed", "void", [("int", "count")]),
                                    ("slot", "reset", "void", [])],
             props=[("count", "int", 3, 0), ("label", "QString", 3, None)],
             enums=[("Mode", [("Fast", 0), ("Slow", 1)])], info=[("Author", "nobody")])
    pe.klass("MainWindow", "Base",
             methods=[("signal", "openRequested", "void", [("QString", "path")]),
                      ("signal", "progress", "void", [("int", "done"), ("int", "total")]),
                      ("slot", "onOpenClicked", "void", []),
                      ("slot", "onSaveClicked", "bool", [("bool", "force")]),
                      ("method", "title", "QString", [])])
    pe.klass("Plain", None)
    pe.klass("Ns::Thing", "MainWindow", methods=[("slot", "poke", "void", [("QString", "text")])], metacall=False)
    pe.write(path)
    return pe


COMBOS = [(4, 5), (8, 5), (4, 6), (8, 6)]


@pytest.mark.parametrize("psize,major", COMBOS)
def test_parse_layouts(tmp_path, psize, major):
    pe = build(tmp_path / "q.dll", psize, major)
    classes = qt.parse_file(tmp_path / "q.dll")
    assert [c.name for c in classes] == ["Base", "MainWindow", "Ns::Thing", "Plain"]
    by = {c.name: c for c in classes}
    assert all(c.major == major for c in classes)
    assert by["MainWindow"].parent == "Base" and by["Ns::Thing"].parent == "MainWindow" and by["Base"].parent == ""
    assert by["MainWindow"].metacall == pe.code["MainWindow.metacall"] and by["Ns::Thing"].metacall is None
    mw = by["MainWindow"]
    assert [(m.kind, m.signature()) for m in mw.methods] == [
        ("signal", "openRequested(QString)"), ("signal", "progress(int,int)"), ("slot", "onOpenClicked()"),
        ("slot", "onSaveClicked(bool)"), ("method", "title()")]
    assert mw.methods[3].ret == "bool" and mw.methods[4].ret == "QString"
    assert [n for _, n in mw.methods[1].params] == ["done", "total"]
    assert mw.nsignals == 2 and mw.methods[0].access == "public"
    base = by["Base"]
    assert [(p.name, p.type, p.notify) for p in base.props] == [("count", "int", 0), ("label", "QString", None)]
    assert [(e.name, e.values) for e in base.enums] == [("Mode", [("Fast", 0), ("Slow", 1)])]
    assert base.info == [("Author", "nobody")]
    assert by["Plain"].methods == []


def test_qt6_superdata_getter(tmp_path):
    """Qt6 on Windows (QT_NO_DATA_RELOCATION): SuperData is {direct, getter}; the metaobject starts one pointer
    before the getter word; the parent is the getter's lea target or the name of the import it loads."""
    pe = Pe(8, 6, indirect=True)
    pe.klass("Base", None, props=[("count", "int", 3, 0)], methods=[("signal", "changed", "void", [])])
    pe.klass("Child", "Base")
    pe.klass("Widget", None, parent_import="QWidget")
    pe.klass("Other", None, parent_import="Thing@Deep")
    pe.write(tmp_path / "q.dll")
    img = Image.from_pe(tmp_path / "q.dll")
    classes = qt.parse_image(img, pe.imports)
    by = {c.name: c for c in classes}
    assert {c.name: c.meta for c in classes} == pe.metas
    assert by["Child"].parent == "Base" and by["Child"].super_addr == pe.metas["Base"]
    assert by["Widget"].parent == "QWidget" and by["Other"].parent == "Deep::Thing"
    assert by["Base"].parent == "" and by["Base"].props[0].notify == 0
    assert {c.name: c.parent for c in qt.parse_image(img)}["Widget"] == ""     # no import table: parent unknown


def test_getter_target_forms(tmp_path):
    pe = Pe(4, 6)
    pe.write(tmp_path / "q.dll")
    img = Image.from_pe(tmp_path / "q.dll")
    a = 0x400000 + TEXT_VA
    pe.text[0:6] = b"\xb8" + struct.pack("<I", 0x405000) + b"\xc3"
    pe.text[16:22] = b"\xa1" + struct.pack("<I", 0x405008) + b"\xc3"
    pe.text[32:37] = b"\xe9" + struct.pack("<i", -37)         # jmp back to the first getter
    pe.write(tmp_path / "q.dll")
    img = Image.from_pe(tmp_path / "q.dll")
    assert qt._getter_target(img, a) == ("addr", 0x405000)
    assert qt._getter_target(img, a + 16) == ("slot", 0x405008)
    assert qt._getter_target(img, a + 32) == ("addr", 0x405000)
    assert qt._getter_target(img, a + 64) is None
    assert qt.parent_from_import("?staticMetaObject@QObject@@2UQMetaObject@@B") == "QObject"
    assert qt.parent_from_import("?staticMetaObject@Inner@Outer@@2UQMetaObject@@B") == "Outer::Inner"
    assert qt.parent_from_import("malloc") == ""


def test_revision_and_noise(tmp_path):
    """Data that only looks like a metaobject is ignored; an image without Qt gives no class."""
    pe = Pe(4, 5)
    pe.write(tmp_path / "empty.dll")
    assert qt.parse_file(tmp_path / "empty.dll") == []
    assert qt.parse_file(tmp_path / "nothing") is None


# ── store, tool, hints ─────────────────────────────────────────────────────

@pytest.fixture
def proj(tmp_path):
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    ix.current = "proj"
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    sha = "cd" * 32
    pe = build(art / sha, 8, 5)
    bid = st.upsert_binary(sha, "app.exe", format="pe32+", arch="x86_64", pointer_size=8,
                           image_base=pe.base, toolchain="qt", analysis_profile="p")
    ix.set_status(st, bid, "ready")
    b = st.get_binary_by_id(bid)
    assert qt.ensure(st, b, art / sha)
    st.insert_functions(bid, [{"entry": pe.code["MainWindow.metacall"], "name": "FUN_a", "name_state": "auto", "size": 3},
                              {"entry": 0x140001800, "name": "MainWindow::onOpenClicked", "name_state": "user",
                               "size": 3}])
    return ctx, st, bid, pe


def test_schema_and_ensure(proj):
    ctx, st, bid, pe = proj
    assert SCHEMA_VERSION >= 13 and 13 in MIGRATIONS
    b = st.get_binary_by_id(bid)
    assert not qt.stale(st, bid) and not qt.ensure(st, b, Path("nope"))
    st.set_meta(qt.meta_key(bid), "0")
    assert qt.stale(st, bid)
    assert qt.ensure(st, b, ctx.indexer.paths("proj").artifacts / b.sha256)
    assert st.db.execute("SELECT COUNT(*) FROM qt_class WHERE binary_id=?", (bid,)).fetchone()[0] == 4
    other = st.upsert_binary("ef" * 32, "m.dll", format="pe32", toolchain="msvc")
    assert not qt.ensure(st, st.get_binary_by_id(other), Path("x"))        # not a Qt binary
    lib = st.upsert_binary("12" * 32, "Qt5Core.dll", format="pe32", toolchain="msvc")
    assert qt.is_qt(st.get_binary_by_id(lib))                              # a Qt library itself


def test_migration_from_v12(tmp_path):
    st = Store(tmp_path / "old.sqlite")
    st.db.execute("DROP TABLE qt_class")
    st.db.execute("DROP TABLE qt_connect")
    st.db.execute("UPDATE meta SET value='12' WHERE key='schema_version'")
    st.db.commit()
    st.close()
    st = Store(tmp_path / "old.sqlite")
    assert st.schema_version == SCHEMA_VERSION
    assert st.db.execute("SELECT COUNT(*) FROM qt_class").fetchone()[0] == 0


def test_dispatch_pending_and_store(proj):
    ctx, st, bid, pe = proj
    pend = qt.dispatch_pending(st, bid)
    names = {p["meta"]: p for p in pend}
    mw = pe.metas["MainWindow"]
    assert names[mw]["metacall"] == pe.code["MainWindow.metacall"] and not names[mw]["need_parent"]
    assert names[pe.metas["Base"]]["need_parent"] is True
    mapped, parents = qt.store_dispatch(st, bid, {"classes": [
        {"meta": mw, "cases": {"2": 0x140001800, "0": 0x140001900}, "parent": ""},
        {"meta": pe.metas["Base"], "cases": {}, "parent": "QObject"}]})
    assert mapped == 2 and parents == 1
    assert qt.dispatch_pending(st, bid) == []                 # done at this version
    parent = st.db.execute("SELECT parent FROM qt_class WHERE binary_id=? AND name='Base'", (bid,)).fetchone()[0]
    assert parent == "QObject"
    qt.store_rows(st, bid, qt.parse_file(ctx.indexer.paths("proj").artifacts / st.get_binary_by_id(bid).sha256))
    assert qt.dispatch_pending(st, bid)                       # re-derived tables need the dispatch again


def test_tool_list_and_class(proj):
    ctx, st, bid, pe = proj
    mw = pe.metas["MainWindow"]
    qt.store_dispatch(st, bid, {"classes": [{"meta": mw, "cases": {"2": 0x140001800, "0": 0x140001900},
                                             "parent": ""}]})
    out = qtools.qt_metaobjects(ctx)
    lines = out.splitlines()
    assert any(ln.startswith("MainWindow : Base") and "signals 2 slots 2" in ln and "mapped 2" in ln for ln in lines)
    assert any(ln.startswith("Plain ") for ln in lines)
    det = qtools.qt_metaobjects(ctx, class_="MainWindow")
    assert "MainWindow : Base" in det and "dispatcher 0x" in det
    assert "[2] public void onOpenClicked() -> 0x0000000140001800 MainWindow::onOpenClicked" in det.replace("  ", " ") \
        or "onOpenClicked() -> 0x0000000140001800" in det
    assert "signals:" in det and "slots:" in det and "invokable:" in det
    assert "openRequested(QString path)" in det and "bool onSaveClicked(bool force)" in det
    base = qtools.qt_metaobjects(ctx, class_="Base")
    assert "count: int rw notify changed" in base and "Mode: Fast=0,Slow=1" in base and "info Author=nobody" in base
    assert qtools.qt_metaobjects(ctx, class_="Nope").startswith("error not_found")
    assert qtools.qt_metaobjects(ctx, class_="Thing").count("Ns::Thing") >= 1      # substring
    assert qtools.qt_metaobjects(ctx, class_="0x%x" % mw).startswith("MainWindow")
    small = qtools.qt_metaobjects(ctx, budget=60)
    assert "cursor=" in small or len(small.splitlines()) <= 4


def test_not_qt_binary_error(tmp_path):
    ctx = make_ctx(tmp_path)
    st = ctx.indexer.store("proj")
    ctx.indexer.current = "proj"
    bid = st.upsert_binary("aa" * 32, "plain.exe", format="pe32", toolchain="msvc")
    ctx.indexer.set_status(st, bid, "ready")
    assert qtools.qt_metaobjects(ctx).startswith("error not_qt")


def test_hints_ui_line_and_runtime(proj):
    ctx, st, bid, pe = proj
    mw = pe.metas["MainWindow"]
    qt.store_dispatch(st, bid, {"classes": [{"meta": mw, "cases": {"2": 0x140001800}, "parent": ""}]})
    h = qt.hints_for(st, bid, 0x140001800)
    assert h == ["MainWindow::onOpenClicked() (Qt slot)"]
    assert qt.hints_for(st, bid, pe.code["MainWindow.metacall"]) == ["MainWindow::qt_static_metacall (moc dispatcher)"]
    assert qt.hints_for(st, bid, 0x123) == []
    line = qt.ui_line(st, bid)
    assert line.startswith("Qt: 4 classes, signals 3, slots 4 (1 signals and slots mapped")
    assert pe.code["MainWindow.metacall"] in qt.runtime_addrs(st, bid)
    assert qt.ui_line(st, 999) == ""


def test_string_connections(proj):
    ctx, st, bid, pe = proj
    fn = 0x140001000
    st.insert_functions(bid, [{"entry": fn, "name": "connect_all", "name_state": "auto", "size": 40}])
    db = st.db
    fid = db.execute("SELECT id FROM function WHERE binary_id=? AND entry=?", (bid, fn)).fetchone()[0]
    strings = [(0x140009000, "2progress(int,int)"), (0x140009020, "1onOpenClicked()"),
               (0x140009040, "2openRequested(QString const &)"), (0x140009060, "2changed(int)"),
               (0x140009080, "not a connection")]
    for a, v in strings:
        db.execute("INSERT INTO string(binary_id, address, encoding, value) VALUES (?,?,?,?)", (bid, a, "ascii", v))
    for k, (a, _v) in enumerate(strings):
        db.execute("INSERT INTO edge(binary_id, src_fn, src_addr, dst_fn, dst_addr, kind) VALUES (?,?,?,?,?,?)",
                   (bid, fid, fn + 4 * k, None, a, "data"))
    db.commit()
    assert qt.derive_connects(st, bid) == 0          # no connect function: order-only pairs are guesses
    rows = db.execute("SELECT kind, signal, slot, slot_kind FROM qt_connect WHERE binary_id=? ORDER BY site",
                      (bid,)).fetchall()
    assert [tuple(r) for r in rows] == [("string-guess", "progress(int,int)", "onOpenClicked()", "slot"),
                                        ("string-guess", "openRequested(QString)", "changed(int)", "signal")]
    out = qtools.qt_metaobjects(ctx, connections=True)
    assert "~signal progress(int,int) [MainWindow] -> slot onOpenClicked() [MainWindow" in out
    cls = qtools.qt_metaobjects(ctx, class_="MainWindow")
    assert "connections:" in cls and "connect_all" in cls
    line = qt.ui_line(st, bid)
    assert "string connections" not in line and "2 string pairs guessed by order" in line


def test_string_connections_import_in_register(proj):
    """MinGW loads the import into a register once: one read edge of the connect slot, several string pairs."""
    ctx, st, bid, pe = proj
    db = st.db
    fn = 0x140001000
    st.insert_functions(bid, [{"entry": fn, "name": "setup", "name_state": "auto", "size": 200}])
    fid = db.execute("SELECT id FROM function WHERE binary_id=? AND entry=?", (bid, fn)).fetchone()[0]
    slot = 0x140008000
    db.execute("INSERT INTO import(binary_id, dll, name, address) VALUES (?,?,?,?)",
               (bid, "QT5CORE.DLL", "QObject::connect", slot))
    strings = [(0x140009000, "1onOpenClicked()"), (0x140009020, "2progress(int,int)"),   # slot pushed first
               (0x140009040, "2changed(int)"), (0x140009060, "1onChanged(int)")]
    for a, v in strings:
        db.execute("INSERT INTO string(binary_id, address, encoding, value) VALUES (?,?,?,?)", (bid, a, "ascii", v))
    db.execute("INSERT INTO edge(binary_id, src_fn, src_addr, dst_fn, dst_addr, kind) VALUES (?,?,?,?,?,?)",
               (bid, fid, fn + 4, None, slot, "read"))
    for k, (a, _v) in enumerate(strings):
        db.execute("INSERT INTO edge(binary_id, src_fn, src_addr, dst_fn, dst_addr, kind) VALUES (?,?,?,?,?,?)",
                   (bid, fid, fn + 0x10 + 4 * k, None, a, "data"))
    db.commit()
    assert qt.derive_connects(st, bid) == 0
    rows = db.execute("SELECT kind, signal, slot, slot_kind FROM qt_connect WHERE binary_id=? ORDER BY site",
                      (bid,)).fetchall()
    assert [tuple(r) for r in rows] == [("string-guess", "progress(int,int)", "onOpenClicked()", "slot"),
                                        ("string-guess", "changed(int)", "onChanged(int)", "slot")]


def test_proven_pair_and_guess_are_kept_apart(proj):
    ctx, st, bid, pe = proj
    db = st.db
    fn = 0x140001000
    st.insert_functions(bid, [{"entry": fn, "name": "setup", "name_state": "auto", "size": 200}])
    fid = db.execute("SELECT id FROM function WHERE binary_id=? AND entry=?", (bid, fn)).fetchone()[0]
    slot = 0x140008000
    db.execute("INSERT INTO import(binary_id, dll, name, address) VALUES (?,?,?,?)",
               (bid, "QT5CORE.DLL", "QObject::connect", slot))
    strings = [(0x140009000, "2a()"), (0x140009020, "1b()"), (0x140009040, "2c()"), (0x140009060, "1d()")]
    for a, v in strings:
        db.execute("INSERT INTO string(binary_id, address, encoding, value) VALUES (?,?,?,?)", (bid, a, "ascii", v))
    for k, (a, _v) in enumerate(strings):
        db.execute("INSERT INTO edge(binary_id, src_fn, src_addr, dst_fn, dst_addr, kind) VALUES (?,?,?,?,?,?)",
                   (bid, fid, fn + 4 * k, None, a, "data"))
    db.execute("INSERT INTO edge(binary_id, src_fn, src_addr, dst_fn, dst_addr, kind) VALUES (?,?,?,?,?,?)",
               (bid, fid, fn + 0x10, None, slot, "call_imp"))        # one call right after the first two strings
    db.commit()
    assert qt.derive_connects(st, bid) == 1
    rows = [tuple(r) for r in db.execute("SELECT kind, signal FROM qt_connect WHERE binary_id=? ORDER BY site", (bid,))]
    assert rows == [("string-guess", "a()"), ("string", "c()")]
    line = qt.ui_line(st, bid)
    assert "string connections 1" in line and "1 string pairs guessed" in line


def test_signature_change_bumps_caller_versions(proj):
    ctx, st, bid, pe = proj
    db = st.db
    st.insert_functions(bid, [{"entry": 0x140001000, "name": "a", "name_state": "auto", "size": 20},
                              {"entry": 0x140001100, "name": "b", "name_state": "auto", "size": 20},
                              {"entry": 0x140001200, "name": "other", "name_state": "auto", "size": 20}])
    ids = {r[0]: r[1] for r in db.execute("SELECT entry, id FROM function WHERE binary_id=?", (bid,))}
    slot = 0x140008000
    db.execute("INSERT INTO import(binary_id, dll, name, address) VALUES (?,?,?,?)",
               (bid, "QT5CORE.DLL", "QObject::connectImpl", slot))
    db.execute("INSERT INTO edge(binary_id, src_fn, src_addr, dst_fn, dst_addr, kind) VALUES (?,?,?,?,?,?)",
               (bid, ids[0x140001000], 0x140001004, None, slot, "read"))
    db.execute("INSERT INTO qt_connect(binary_id, fn_entry, site, kind) VALUES (?,?,?,?)", (bid, 0x140001100, 0x140001104, "ptr"))
    db.commit()
    before = {e: db.execute("SELECT version FROM function WHERE id=?", (i,)).fetchone()[0] for e, i in ids.items()}
    assert qt.bump_connect_callers(st, bid) == 2
    after = {e: db.execute("SELECT version FROM function WHERE id=?", (i,)).fetchone()[0] for e, i in ids.items()}
    assert after[0x140001000] == before[0x140001000] + 1 and after[0x140001100] == before[0x140001100] + 1
    assert after[0x140001200] == before[0x140001200]


def test_itanium_import_names():
    assert qt.import_qualname("_ZN7QObject11connectImplEPKS_PPvS1_S3_PN9QtPrivate15QSlotObjectBaseE") == "QObject::connectImpl"
    assert qt.import_qualname("_ZN7QObject7connectEPKS_PKcS1_S3_N2Qt14ConnectionTypeE") == "QObject::connect"
    assert qt.import_qualname("_ZNK7QObject6senderEv") == "QObject::sender"
    assert qt.import_qualname("_ZN11QMetaObject10ConnectionD1Ev") == "QMetaObject::Connection::~Connection"
    assert qt.import_qualname("_ZN7QStringC1Ev") == "QString::QString"
    assert qt.import_qualname("_ZN5QListIiE6appendEi") == ""        # template class: not read
    assert qt.import_qualname("_ZN3Foo3barXE") == ""                 # truncated name


def test_fill_imports_itanium(proj, monkeypatch):
    ctx, st, bid, pe = proj
    rows = [("QT5CORE.DLL", "_ZN7QObject11connectImplEPKS_PPvS1_S3_PN9QtPrivate15QSlotObjectBaseE", 0x140008000),
            ("QT5CORE.DLL", "_ZN7QObject7connectEPKS_PKcS1_S3_N2Qt14ConnectionTypeE", 0x140008008),
            ("KERNEL32.DLL", "ExitProcess", 0x140008010)]
    monkeypatch.setattr(qt, "pe_import_rows", lambda _p: rows)
    assert qt.fill_imports(st, bid, Path("x.exe")) == 2
    assert qt._connect_slots(st.db, bid) == {0x140008000: "ptr", 0x140008008: "string"}


def test_store_connects_expanded_and_virtual(proj):
    ctx, st, bid, pe = proj
    fn = 0x140001000
    sites = [{"fn": fn, "site": fn + 4}, {"fn": fn, "site": fn + 0x80}]
    res = {"results": [
        {"fn": fn, "site": fn + 0x20, "signal": {"addr": 0x140008100, "ext": "QAction::triggered"},
         "slot": {"virtual": 0x18, "kind": "pmf"}},
        {"fn": fn, "site": fn + 0x40, "signal": {"addr": 0x140008100, "ext": "QAction::triggered"},
         "slot": {"addr": 0x140001a00, "kind": "functor"}}],
        "expanded": {str(fn + 4): [fn + 0x20, fn + 0x40, fn + 0x60]}}
    assert qt.store_connects(st, bid, res, sites) == (2, 2)      # one expanded call and the plain site stay open
    rows = [tuple(r) for r in st.db.execute("SELECT site, signal, slot, slot_kind FROM qt_connect WHERE kind='ptr' "
                                            "ORDER BY site")]
    assert rows == [(fn + 0x20, "QAction::triggered", "vtable+0x18", "virtual"),
                    (fn + 0x40, "QAction::triggered", "0x140001a00", "functor"),
                    (fn + 0x60, "", "", ""), (fn + 0x80, "", "", "")]


def test_feature_seeds(proj):
    ctx, st, bid, pe = proj
    mw = pe.metas["MainWindow"]
    qt.store_dispatch(st, bid, {"classes": [{"meta": mw, "cases": {"2": 0x140001800, "3": 0x140001900}, "parent": ""}]})
    rows = [("ptr", "QAction::triggered", "0x140001800", "slot"),
            ("ptr", "QPushButton::clicked(bool)", "0x140001a00", "fn"),        # the button base class is looked up
            ("ptr", "QAbstractButton::clicked", "0x140001b00", "lambda"),
            ("ptr", "MainWindow::progress(int,int)", "0x140001c00", "slot"),   # not a user interface signal
            ("string", "clicked()", "onSaveClicked(bool)", "slot"),
            ("string", "openRequested(QString)", "onOpenClicked()", "slot")]
    for i, r in enumerate(rows):
        st.db.execute("INSERT INTO qt_connect(binary_id, fn_entry, site, kind, signal, slot, slot_kind) "
                      "VALUES (?,?,?,?,?,?,?)", (bid, 0x140001000, 0x140001000 + i, *r))
    st.db.commit()
    got = sorted(qt.feature_seeds(st, bid))
    assert got == [(0x140001800, "ui-menu", "Qt QAction::triggered"),
                   (0x140001900, "ui-dialog", "Qt connect clicked"),
                   (0x140001a00, "ui-dialog", "Qt QAbstractButton::clicked"),
                   (0x140001b00, "ui-dialog", "Qt QAbstractButton::clicked")]
    assert qt.seed_for_signal("MainWindow", "clicked", {"MainWindow": "QPushButton"}) == (
        "ui-dialog", "Qt QAbstractButton::clicked")


def test_pointer_connects(proj):
    ctx, st, bid, pe = proj
    db = st.db
    mw = pe.metas["MainWindow"]
    qt.store_dispatch(st, bid, {"classes": [{"meta": mw, "cases": {"2": 0x140001800, "0": 0x140001900},
                                             "parent": ""}]})
    fn = 0x140001000
    st.insert_functions(bid, [{"entry": fn, "name": "setup", "name_state": "auto", "size": 80}])
    fid = db.execute("SELECT id FROM function WHERE binary_id=? AND entry=?", (bid, fn)).fetchone()[0]
    # the call of an imported C++ function is a read edge to the import slot; the import row is added from the PE
    slot = 0x140008000
    db.execute("INSERT INTO import(binary_id, dll, name, address) VALUES (?,?,?,?)",
               (bid, "QT6CORE.DLL", "QObject::connectImpl", slot))
    db.execute("INSERT INTO import(binary_id, dll, name, address) VALUES (?,?,?,?)",
               (bid, "QT6CORE.DLL", "QObject::disconnectImpl", slot + 8))
    for k, dst in enumerate((slot, slot, slot + 8)):
        db.execute("INSERT INTO edge(binary_id, src_fn, src_addr, dst_fn, dst_addr, kind) VALUES (?,?,?,?,?,?)",
                   (bid, fid, fn + 0x10 * (k + 1), None, dst, "read"))
    db.commit()
    assert qt._connect_slots(db, bid) == {slot: "ptr"}
    qt.derive_connects(st, bid)
    rows = db.execute("SELECT fn_entry, site, signal FROM qt_connect WHERE kind='ptr' ORDER BY site").fetchall()
    assert [(r[0], r[1], r[2]) for r in rows] == [(fn, fn + 0x10, ""), (fn, fn + 0x20, "")]
    sites = [{"fn": fn, "site": fn + 0x10}, {"fn": fn, "site": fn + 0x20}]
    res = {"results": [
        {"fn": fn, "site": fn + 0x10, "signal": {"addr": 0x140001500, "meta": mw, "idx": 1},
         "slot": {"addr": 0x140001800, "kind": "pmf"}},
        {"fn": 0x140002000, "site": fn + 0x20, "signal": {"addr": 0x140008100, "ext": "QAction::triggered"},
         "slot": {"addr": 0x140001a00, "kind": "functor"}}]}
    assert qt.store_connects(st, bid, res, sites) == (2, 0)
    rows = [tuple(r) for r in db.execute("SELECT fn_entry, signal, slot, slot_kind FROM qt_connect WHERE kind='ptr' "
                                         "ORDER BY site")]
    assert rows == [(fn, "MainWindow::progress(int,int)", "0x140001800", "slot"),
                    (0x140002000, "QAction::triggered", "0x140001a00", "functor")]
    out = qtools.qt_metaobjects(ctx, connections=True)
    assert "signal MainWindow::progress(int,int) -> slot 0x0000000140001800" in out
    assert "signal QAction::triggered -> functor 0x0000000140001a00" in out
    cls = qtools.qt_metaobjects(ctx, class_="MainWindow")
    assert "signal MainWindow::progress(int,int)" in cls and "QAction::triggered" not in cls
    assert "pointer connects 2 of 2 call sites resolved" in qt.ui_line(st, bid)
    assert qt.store_connects(st, bid, {"results": []}, sites) == (0, 2)
    assert qt.import_qualname("?connectImpl@QObject@@CA?AVConnection@QMetaObject@@XZ") == "QObject::connectImpl"
    assert qt.import_qualname("??0QFoo@Bar@@QEAA@XZ") == "Bar::QFoo::QFoo"
    assert qt.import_qualname("??1QFoo@@UEAA@XZ") == "QFoo::~QFoo"
    assert qt.import_qualname("malloc") == ""


def test_worker_helpers():
    from airlock.worker.ghidra_ops import qt as wq
    assert wq.parent_from_symbol("?staticMetaObject@QMainWindow@@2UQMetaObject@@B") == "QMainWindow"
    assert wq.parent_from_symbol("?staticMetaObject@Foo@Ns@@2UQMetaObject@@B") == "Ns::Foo"
    assert wq.parent_from_symbol("__imp__ZN7QObject16staticMetaObjectE") == "QObject"
    assert wq.parent_from_symbol("_ZN2Ns3Foo16staticMetaObjectE") == "Ns::Foo"
    assert wq.parent_from_symbol("QWidget::staticMetaObject") == "QWidget"
    assert wq.parent_from_symbol("something else") == ""
    assert wq._num("0x1f") == 31 and wq._num("-1") == -1 and wq._num("7U") == 7 and wq._num("x") is None
    pick = wq.pick_switch([{9: 1, 10: 2}, {0: 5, 1: 6, 2: None}, {0: 7}], 3)
    assert pick == {0: 5, 1: 6, 2: None}
    assert wq.pick_switch([{50: 1}], 3) == {}
    assert wq._signed(0xffffff70, 4) == -0x90 and wq._signed(0x10, 4) == 0x10
    assert wq._signed(0xffffffffffffff70) == -0x90


def test_class_vtables(tmp_path):
    """The vtable of a Qt class is found through its small ``metaObject()``; shared slots stay unassigned."""
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    pe = Pe(8, 5)
    pe.klass("Alpha", None)
    pe.klass("Beta", "Alpha")
    mo_a, mo_b = pe.stub("Alpha.mo"), pe.stub("Beta.mo")
    mc, fa, fb, fz = pe.stub("mc"), pe.stub("virt_a"), pe.stub("virt_b"), pe.stub("virt_z")
    vt_a, vt_b, vt_z = pe.alloc(8 * 5), pe.alloc(8 * 5), pe.alloc(8 * 5)
    pe.put(vt_a, b"".join(pe.p(x) for x in (mo_a, mc, mc, fa)))
    pe.put(vt_b, b"".join(pe.p(x) for x in (mo_b, mc, mc, fb)))
    pe.put(vt_z, b"".join(pe.p(x) for x in (mo_a, mc, mc, fz)))          # a subclass without Q_OBJECT shares Alpha's slots
    sha = "ab" * 32
    pe.write(art / sha)
    bid = st.upsert_binary(sha, "app.exe", format="pe32+", arch="x86_64", pointer_size=8, image_base=pe.base,
                           toolchain="qt", analysis_profile="p")
    ix.set_status(st, bid, "ready")
    assert qt.ensure(st, st.get_binary_by_id(bid), art / sha)
    st.insert_functions(bid, [{"entry": mo_a, "name": "FUN_a", "name_state": "auto", "size": 40},
                              {"entry": mo_b, "name": "FUN_b", "name_state": "auto", "size": 40},
                              {"entry": mc, "name": "FUN_c", "name_state": "auto", "size": 3}])
    for fn, cls in ((mo_a, "Alpha"), (mo_b, "Beta"), (mc, "Alpha"), (mc, "Beta")):
        fid = st.db.execute("SELECT id FROM function WHERE binary_id=? AND entry=?", (bid, fn)).fetchone()[0]
        st.db.execute("INSERT INTO edge(binary_id, src_fn, src_addr, dst_fn, dst_addr, kind) VALUES (?,?,?,NULL,?,?)",
                      (bid, fid, fn + 4, pe.metas[cls], "data"))
    st.db.commit()
    vts, fnc, prim = qt.class_vtables(st, bid, art / sha)
    assert vts == {vt_b: "Beta"}                                     # Alpha has a subclass: its vtables are left out
    assert prim == {"Beta": vt_b}
    assert fnc[fb] == "Beta" and fa not in fnc and fz not in fnc
    assert mc in fnc and fnc[mc] == "Beta"


def test_store_connects_uncalled(proj):
    ctx, st, bid, pe = proj
    fn = 0x140001000
    sites = [{"fn": fn, "site": fn + 0x10}, {"fn": fn, "site": fn + 0x20}, {"fn": fn, "site": fn + 0x30}]
    res = {"results": [{"fn": fn, "site": fn + 0x10, "signal": {"addr": 0x140008100, "ext": "QAction::triggered"},
                        "slot": {"addr": 0x140001a00, "kind": "pmf", "virt": 0x18, "cls": "MainWindow"}}],
           "uncalled": [fn + 0x20]}
    assert qt.store_connects(st, bid, res, sites) == (1, 2)
    rows = [tuple(r) for r in st.db.execute("SELECT site, signal, slot, slot_kind FROM qt_connect WHERE kind='ptr' "
                                            "ORDER BY site")]
    assert rows == [(fn + 0x10, "QAction::triggered", "0x140001a00", "fn"), (fn + 0x20, "", "", "uncalled"),
                    (fn + 0x30, "", "", "")]
    line = qt.ui_line(st, bid)
    assert "pointer connects 1 of 2 call sites resolved (1 more in functions nobody calls)" in line
    out = qtools.qt_metaobjects(ctx, connections=True)
    assert "1 pointer connect call sites not resolved" in out
    assert "1 pointer connect call sites in functions nobody calls" in out


class _Addr:
    def __init__(self, v):
        self.v = v

    def add(self, n):
        return _Addr(self.v + n)

    def getOffset(self):
        return self.v

    def compareTo(self, o):
        return (self.v > o.v) - (self.v < o.v)


class _Fn:
    def __init__(self, a):
        self.a = a

    def isThunk(self):
        return False

    def isExternal(self):
        return False

    def getEntryPoint(self):
        return _Addr(self.a)

    def getFunctionThunkAddresses(self, _all):
        return []


class _Ref:
    def __init__(self, frm, call):
        self.frm, self.call = frm, call

    def getFromAddress(self):
        return _Addr(self.frm)

    def getReferenceType(self):
        return self

    def isCall(self):
        return self.call

    def isJump(self):
        return False


class _Block:
    def __init__(self, name, code=True):
        self.name, self.code = name, code

    def getName(self):
        return self.name

    def isExecute(self):
        return self.code


class _Prog:
    """A duck-typed Ghidra program: bytes at addresses, functions at entries, references to entries."""

    def __init__(self, mem, funcs, refs=None, psize=8):
        self.mem, self.funcs, self.refs, self.psize = mem, funcs, refs or {}, psize

    def getMemory(self):
        return self

    def getByte(self, a):
        if a.v not in self.mem:
            raise KeyError(a.v)
        b = self.mem[a.v]
        return b - 256 if b > 127 else b

    def getLong(self, a):
        return int.from_bytes(bytes(self.mem[a.v + i] for i in range(8)), "little", signed=True)

    def getInt(self, a):
        return int.from_bytes(bytes(self.mem[a.v + i] for i in range(4)), "little", signed=True)

    def getBlock(self, a):
        return _Block(".pdata" if a.v >= 0x9000 else ".text", a.v < 0x5000)

    def getFunctionManager(self):
        return self

    def getFunctionAt(self, a):
        return _Fn(a.v) if a.v in self.funcs else None

    def getFunctionContaining(self, a):
        return None

    def getReferenceManager(self):
        return self

    def getReferencesTo(self, a):
        return self.refs.get(a.v, [])

    def getAddressFactory(self):
        return self

    def getDefaultAddressSpace(self):
        return self

    def getAddress(self, v):
        return _Addr(v)

    def getDefaultPointerSize(self):
        return self.psize


def test_worker_virtual_member_pointers():
    from airlock.worker.ghidra_ops import qt as wq
    code = {0x1000: bytes((0x48, 0x8B, 0x01, 0xFF, 0x60, 0x18)), 0x1010: bytes((0x8B, 0x01, 0xFF, 0xA0, 0x40, 1, 0, 0)),
            0x1020: bytes((0x48, 0x8B, 0x01, 0xFF, 0x20)), 0x1030: bytes((0x55, 0x48, 0x89, 0xE5, 0xC3))}
    mem = {a + i: b for a, raw in code.items() for i, b in enumerate(raw.ljust(10, bytes(1)))}
    vt = 0x5000
    for k, w in enumerate((0x1000, 0x1010, 0x1020, 0x1030, 0x7777)):         # slots 0..0x18 code, 0x20 not
        mem.update({vt + 8 * k + i: b for i, b in enumerate(w.to_bytes(8, "little"))})
    refs = {0x1030: [_Ref(0x9100, False)], 0x1040: [_Ref(0x9100, False), _Ref(0x1500, True)],
            0x1050: [_Ref(0x2000, False)]}
    cx = wq._Connects(_Prog(mem, {0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1050}, refs), None, 5,
                      vtables={vt: "Gamma"}, fnclass={0x1030: "Gamma"}, primary={"Gamma": vt})
    assert [cx.vcall_offset(a) for a in (0x1000, 0x1010, 0x1020, 0x1030)] == [0x18, 0x140, 0, None]
    assert cx.target(("const", 0x1000)) == {"virtual": 0x18, "msvc": 1}       # MSVC: the address of a vcall thunk
    assert cx.target(("const", 0x19)) == {"virtual": 0x18}                    # Itanium: vtable offset plus one
    assert cx.target(("const", 0x1030)) == {"addr": 0x1030}
    assert cx.virtual_target(vt, 0x18) == {"addr": 0x1030}                    # the slot of the receiver's vtable
    assert cx.virtual_target(vt, 0x20) is None                                # not a function
    assert cx.virtual_target(0, 0x18) is None
    assert cx.primary[cx.fnclass[0x1030]] == vt
    assert cx.uncalled(0x1030) is True                                        # only the unwind table refers to it
    assert cx.uncalled(0x1040) is False                                       # called
    assert cx.uncalled(0x1050) is False                                       # address taken


def test_class_vtables_mingw32_loose_metaobject(tmp_path):
    """32-bit MinGW: ``metaObject()`` has no Ghidra function, its read of the metaobject is a loose edge."""
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    pe = Pe(4, 5)
    pe.klass("Alpha", None)
    mo, mc, fa, far = pe.stub("Alpha.mo"), pe.stub("mc"), pe.stub("virt_a"), pe.stub("far")
    vt, vt2 = pe.alloc(4 * 5), pe.alloc(4 * 5)
    pe.put(vt, b"".join(pe.p(x) for x in (mo, mc, mc, fa)))
    pe.put(vt2, b"".join(pe.p(x) for x in (far, mc, mc, fa)))              # too far from any loose read
    sha = "cd" * 32
    pe.write(art / sha)
    bid = st.upsert_binary(sha, "app.exe", format="pe32", arch="x86", pointer_size=4, image_base=pe.base,
                           toolchain="qt", analysis_profile="p")
    ix.set_status(st, bid, "ready")
    assert qt.ensure(st, st.get_binary_by_id(bid), art / sha)
    st.insert_functions(bid, [{"entry": mc, "name": "FUN_c", "name_state": "auto", "size": 3}])
    st.db.execute("INSERT INTO edge(binary_id, src_fn, src_addr, dst_fn, dst_addr, kind) VALUES (?,NULL,?,NULL,?,?)",
                  (bid, mo + 10, pe.metas["Alpha"], "data"))
    st.db.commit()
    c = qt.connect_context(st, bid, art / sha)
    assert c["vtables"] == {vt: "Alpha"} and c["primary"] == {"Alpha": vt}
    assert c["fnclass"][fa] == "Alpha"
    # the read lies inside a known function: no loose metaObject()
    st.insert_functions(bid, [{"entry": mo, "name": "FUN_mo", "name_state": "auto", "size": 200}])
    st.db.commit()
    assert qt.class_vtables(st, bid, art / sha)[0] == {}


def test_connect_context_parents(tmp_path):
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    pe = Pe(8, 5)
    pe.klass("Alpha", None)
    pe.klass("Beta", "Alpha")
    mo_a, mo_b, mc = pe.stub("Alpha.mo"), pe.stub("Beta.mo"), pe.stub("mc")
    vt_a, vt_b = pe.alloc(8 * 4), pe.alloc(8 * 4)
    pe.put(vt_a, b"".join(pe.p(x) for x in (mo_a, mc, mc)))
    pe.put(vt_b, b"".join(pe.p(x) for x in (mo_b, mc, mc)))
    sha = "ef" * 32
    pe.write(art / sha)
    bid = st.upsert_binary(sha, "app.exe", format="pe32+", arch="x86_64", pointer_size=8, image_base=pe.base,
                           toolchain="qt", analysis_profile="p")
    ix.set_status(st, bid, "ready")
    assert qt.ensure(st, st.get_binary_by_id(bid), art / sha)
    st.insert_functions(bid, [{"entry": mo_a, "name": "FUN_a", "name_state": "auto", "size": 40},
                              {"entry": mo_b, "name": "FUN_b", "name_state": "auto", "size": 40}])
    for fn, cls in ((mo_a, "Alpha"), (mo_b, "Beta")):
        fid = st.db.execute("SELECT id FROM function WHERE binary_id=? AND entry=?", (bid, fn)).fetchone()[0]
        st.db.execute("INSERT INTO edge(binary_id, src_fn, src_addr, dst_fn, dst_addr, kind) VALUES (?,?,?,NULL,?,?)",
                      (bid, fid, fn + 4, pe.metas[cls], "data"))
    st.db.commit()
    c = qt.connect_context(st, bid, art / sha)
    assert c["vtables"] == {vt_b: "Beta"}
    assert c["allvtables"] == {vt_a: "Alpha", vt_b: "Beta"}                 # the base class too, for new objects
    assert c["parents"]["Beta"] == "Alpha"


# -- receiver classes of virtual member pointers (duck-typed Ghidra objects) --

class _NS:
    def __init__(self, name):
        self.name = name

    def getName(self, _full=False):
        return self.name


class _XFn(_Fn):
    """A function: ``ext`` = "Class::name" of an import, ``thunk`` = the function it jumps to."""

    def __init__(self, a, ext=None, thunk=None):
        super().__init__(a)
        self.ext, self.thunk = ext, thunk

    def isThunk(self):
        return self.thunk is not None

    def getThunkedFunction(self, _rec):
        return self.thunk

    def isExternal(self):
        return self.ext is not None

    def getParentNamespace(self):
        return _NS(self.ext.rsplit("::", 1)[0] if self.ext else "Global")

    def getName(self):
        return self.ext.rsplit("::", 1)[1] if self.ext else f"FUN_{self.a:x}"


class _Seq:
    def __init__(self, key):
        self.key = key

    def getTarget(self):
        return _Addr(self.key[0])

    def getTime(self):
        return self.key[1]


class _Callee:
    def __init__(self, a):
        self.a = a

    def getAddress(self):
        return _Addr(self.a)


class _Op:
    def __init__(self, mn, key, *inputs):
        self.mn, self.key, self.inputs = mn, key, list(inputs)

    def getMnemonic(self):
        return self.mn

    def getSeqnum(self):
        return _Seq(self.key)

    def getNumInputs(self):
        return len(self.inputs)

    def getInput(self, i):
        return self.inputs[i]


def _store(key, ptr, val):
    return _Op("STORE", key, None, ptr, val)


def _call(key, target, *args):
    return _Op("CALL", key, _Callee(target), *args)


class _FakeFlow:
    """A decompiled function whose varnodes are their own symbolic values."""

    def __init__(self, ops, fields=None):
        self.ops, self.fields = ops, fields or {}

    def value(self, vn):
        return None if isinstance(vn, _Callee) else vn

    def calls(self):
        return [p for p in self.ops if p.mn in ("CALL", "CALLIND")]

    def call_at(self, a):
        return next((p for p in self.calls() if p.key[0] == a.v), None)

    def field_stores(self, fld):
        return [(None, v) for v in self.fields.get(fld, [])]


class _XProg(_Prog):
    def __init__(self, mem, funcs, refs=None):
        super().__init__(mem, set(funcs), refs)
        self.fns = funcs

    def getFunctionAt(self, a):
        return self.fns.get(a.v)

    def getFunctionContaining(self, a):
        best = [f for e, f in self.fns.items() if e <= a.v and not f.isExternal()]
        return max(best, key=lambda f: f.a) if best else None


def _words(base, ws):
    return {base + 8 * k + i: b for k, w in enumerate(ws) for i, b in enumerate(w.to_bytes(8, "little"))}


def test_worker_lib_target():
    """The slot of a library class: import slots of its program subclasses that do not override it."""
    from airlock.worker.ghidra_ops import qt as wq
    acc, oth, own = _XFn(0x1100, "QDialog::accept"), _XFn(0x1108, "QFrame::other"), _XFn(0x1200)
    mem = {**_words(0x5000, (0x1000, 0x1000, 0x1100)), **_words(0x5100, (0x1000, 0x1000, 0x1100)),
           **_words(0x5200, (0x1000, 0x1000, 0x1200)), **_words(0x5300, (0x1000, 0x1000, 0x1100)),
           **_words(0x5400, (0x1000, 0x1000, 0x1108))}
    prog = _XProg(mem, {0x1000: _XFn(0x1000), 0x1100: acc, 0x1108: oth, 0x1200: own})
    cx = wq._Connects(prog, None, 5, allvts={0x5000: "Kid", 0x5100: "Kid2", 0x5200: "Over", 0x5300: "F1",
                                             0x5400: "F2"},
                      parents={"Kid": "QDialog", "Kid2": "Mid", "Mid": "QDialog", "Over": "QDialog",
                               "F1": "QFrame", "F2": "QFrame"})
    assert cx.lib_target("QDialog", 0x10) == {"addr": 0x1100, "ext": "QDialog::accept"}   # Over overrides it
    assert cx.lib_target("QFrame", 0x10) is None                                         # two imports disagree
    assert cx.lib_target("QWidget", 0x10) is None                                        # no subclass in the program
    assert cx.lib_target("QDialog", 0x18) is None                                        # past the vtables


def test_worker_receiver_classes():
    """Receiver classes: callers that agree, new objects, returns of a factory, fields typed by their stores."""
    from airlock.worker.ghidra_ops import qt as wq
    vt_a, vt_b = 0x5000, 0x5100
    mem = {**_words(vt_a, (0x1000, 0x1000)), **_words(vt_b, (0x1000, 0x1000))}
    p0, p1 = ("param", 0, 0), ("param", 1, 0)
    fns = {a: _XFn(a) for a in (0x1000, 0x2000, 0x3000, 0x3100, 0x4000, 0x4100, 0x4200, 0x4300, 0x4500, 0x4600,
                                0x4700)}
    fns[0x7000] = _XFn(0x7000, "QSpinBox::QSpinBox")
    fns[0x7100] = _XFn(0x7100, "QWidget::show")
    fns[0x3300] = _XFn(0x3300, thunk=fns[0x2000])                 # an incremental-link stub: its callers count
    refs = {0x2000: [_Ref(0x3010, True), _Ref(0x3110, True), _Ref(0x3300, False)]}
    cx = wq._Connects(_XProg(mem, fns, refs), None, 5, imports={0x8000: "QLabel::vftable"}, vtables={vt_a: "A"},
                      allvts={vt_a: "A", vt_b: "B"})
    cx.flows.update({
        0x3000: _FakeFlow([_store((0x3001, 0), p0, ("const", vt_b)), _store((0x3002, 0), p0, ("const", vt_a)),
                           _call((0x3010, 0), 0x2000, None, p0, p0)]),
        0x3100: _FakeFlow([_store((0x3101, 0), p0, ("const", vt_a)), _call((0x3110, 0), 0x2000, None, p0, p0)])})
    assert cx.ctor_vt(0x3000) == vt_a                             # the last vtable store: the derived class
    assert cx.recv_vt(0x2000, p1) == vt_a                         # both callers pass ``this`` of an A constructor
    cx._recv.clear()
    cx._ctor.clear()
    cx.flows[0x3100] = _FakeFlow([_store((0x3101, 0), p0, ("const", vt_b)), _call((0x3110, 0), 0x2000, None, p0, p0)])
    assert cx.recv_vt(0x2000, p1) == 0                            # B has subclasses: ``this`` of its ctor is unknown
    # objects new-ed in a function
    obj = ("new", (0x4010, 0), 0)
    cx.flows[0x4000] = _FakeFlow([_call((0x4010, 0), 0x4600, None), _call((0x4020, 0), 0x7000, obj),
                                  _store((0x4030, 0), obj, ("mem", 0x8000)), _call((0x4040, 0), 0x7100, obj)])
    assert cx.recv_vt(0x4000, obj) == "QLabel"                    # the vftable import store comes last
    obj2 = ("new", (0x4110, 0), 0)
    cx.flows[0x4100] = _FakeFlow([_call((0x4110, 0), 0x4600, None), _call((0x4120, 0), 0x7000, obj2)])
    assert cx.recv_vt(0x4100, obj2) == "QSpinBox"                 # the library constructor import
    obj3 = ("new", (0x4210, 0), 0)
    cx.flows[0x4200] = _FakeFlow([_call((0x4210, 0), 0x4600, None), _call((0x4220, 0), 0x7000, obj3),
                                  _store((0x4230, 0), obj3, ("const", vt_b))])
    assert cx.recv_vt(0x4200, obj3) == vt_b                       # inlined constructor of a program class (exact)
    obj4 = ("new", (0x4310, 0), 0)
    cx.flows[0x4300] = _FakeFlow([_call((0x4310, 0), 0x4600, None), _store((0x4320, 0), obj4, ("const", vt_a)),
                                  _store((0x4330, 0), obj4, ("const", 0x6666))])
    assert cx.recv_vt(0x4300, obj4) == 0                          # an unknown vtable last: unknown
    # the result of a factory: every return gives an A
    made = ("new", (0x4510, 0), 0)
    cx.flows[0x4600] = None
    cx.flows[0x4500] = _FakeFlow([_call((0x4510, 0), 0x4600, None), _store((0x4520, 0), made, ("const", vt_a)),
                                  _Op("RETURN", (0x4530, 0), None, made)])
    cx.flows[0x4700] = _FakeFlow([_call((0x4710, 0), 0x4500, None)])
    assert cx.recv_vt(0x4700, ("new", (0x4710, 0), 0)) == vt_a
    # a field the function stores a new object into
    fld = ("field", ("ld", ("p", 0), 0xf8))
    cx.flows[0x4100].fields = {fld[1]: [obj2]}
    assert cx.recv_vt(0x4100, fld) == "QSpinBox"
    cx.flows[0x4100].fields = {fld[1]: [obj2, None]}
    cx._recv.clear()
    assert cx.recv_vt(0x4100, fld) == 0                           # a second store of something unknown
    assert cx._lift(None, None, fld) is None                      # a field chain never moves to a caller


class _DT:
    def __init__(self, name):
        self.name = name

    def getDataType(self):
        return self

    def getName(self):
        return self.name


class _UnwindProg(_Prog):
    """Data at 0x6000.. is a chained UNWIND_INFO in .rdata, at 0x6100 a plain pointer table."""

    def getListing(self):
        return self

    def getDataContaining(self, a):
        return _DT("PEx64_UnwindInfo" if 0x6000 <= a.v < 0x6100 else "pointer")


def test_worker_uncalled_chained_unwind():
    """A template instance only chained unwind data names is uncalled; a pointer in a table is a use."""
    from airlock.worker.ghidra_ops import qt as wq
    refs = {0x1000: [_Ref(0x9100, False), _Ref(0x6010, False)], 0x1010: [_Ref(0x9100, False), _Ref(0x6110, False)]}
    cx = wq._Connects(_UnwindProg({}, {0x1000, 0x1010}, refs), None, 5)
    assert cx.uncalled(0x1000) is True
    assert cx.uncalled(0x1010) is False


def test_worker_prefetch_parallel():
    """The functions with call sites are decompiled on several decompilers at once, each disposed after."""
    import threading
    from airlock.worker.ghidra_ops import qt as wq
    cx = wq._Connects(_Prog({}, {0x1000, 0x1010, 0x1020, 0x1030}), None, 5)
    seen, made = set(), []

    class _Di:
        def __init__(self):
            self.disposed = False
            made.append(self)

        def dispose(self):
            self.disposed = True

    def dec(di, f):
        seen.add(threading.current_thread().name)
        return None if f.a == 0x1030 else ("hf", f.a)

    cx._decompile = dec
    assert cx.prefetch([0x1000, 0x1010, 0x1010, 0x1020, 0x1030, 0x2000], 3, _Di) == 3
    assert cx._pre == {0x1000: ("hf", 0x1000), 0x1010: ("hf", 0x1010), 0x1020: ("hf", 0x1020), 0x1030: None,
                       0x2000: None}
    assert made and all(d.disposed for d in made) and len(made) <= 3
    assert all(n.startswith("airlock-qt-") for n in seen)
    assert cx.prefetch([0x1000], 3, _Di) == 0                     # already done / too few: nothing to do


def test_worker_receiver_stack_object():
    """A dialog on the stack: its constructor import gives the class; a slot reused for two classes does not."""
    from airlock.worker.ghidra_ops import qt as wq
    fns = {0x4000: _XFn(0x4000), 0x7000: _XFn(0x7000, "QDialog::QDialog"), 0x7100: _XFn(0x7100, "QLabel::QLabel")}
    cx = wq._Connects(_XProg({}, fns), None, 5, imports={0x8000: "QDialog::vftable"})
    st = ("stack", -0x40)
    cx.flows[0x4000] = _FakeFlow([_call((0x4010, 0), 0x7000, st), _store((0x4020, 0), st, ("mem", 0x8000))])
    assert cx.recv_vt(0x4000, st) == "QDialog"
    cx._recv.clear()
    cx.flows[0x4000].ops.append(_call((0x4090, 0), 0x7100, st))
    assert cx.recv_vt(0x4000, st) == 0
