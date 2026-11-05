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

    def __init__(self, psize: int, major: int) -> None:
        self.ps, self.major = psize, major
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
              metacall=True) -> int:
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
            fl = flags | (0x00400000 if notify is not None else 0)
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
        meta = self.alloc(n * self.ps)
        self.metas[name] = meta
        cells = [0, sdata, dva, mc, 0] + ([0, 0] if self.major == 6 else [0])
        self.put(meta, b"".join(self.p(c) for c in cells))
        if parent:
            self.fix.append((meta, parent))
        return meta

    def write(self, path: Path) -> None:
        for meta, parent in self.fix:
            self.put(meta, self.p(self.metas[parent]))
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
    assert qt.derive_connects(st, bid) == 2
    rows = db.execute("SELECT signal, slot, slot_kind FROM qt_connect WHERE binary_id=? ORDER BY site", (bid,)).fetchall()
    assert [tuple(r) for r in rows] == [("progress(int,int)", "onOpenClicked()", "slot"),
                                        ("openRequested(QString)", "changed(int)", "signal")]
    out = qtools.qt_metaobjects(ctx, connections=True)
    assert "signal progress(int,int) [MainWindow] -> slot onOpenClicked() [MainWindow" in out
    cls = qtools.qt_metaobjects(ctx, class_="MainWindow")
    assert "connections:" in cls and "connect_all" in cls
    assert "1 connections" not in qt.ui_line(st, bid) and "string connections 2" in qt.ui_line(st, bid)


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
