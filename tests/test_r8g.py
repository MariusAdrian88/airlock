"""Round 8 fixes (N4, N6, N7, N8, N10): delphi_events component filter, program body selectors,
hexdump by file name, function creation on demand, small argument gaps. Synthetic stores."""

from __future__ import annotations

import struct

import pytest

from airlock.server import cpp, targets as tg
from airlock.server.tools import core
from airlock.server.tools import delphi as dtools
from test_delphi import proj          # noqa: F401  (fixture)
from test_fileformat import call, env  # noqa: F401  (fixtures)
from test_linking import _add, _store
from test_tools import make_ctx
from test_xbin_tools import _fn


# -- N4 -------------------------------------------------------------------------------------------

def test_delphi_events_component_inside_form(proj):  # noqa: F811
    ctx, st, bid, pe = proj
    a = pe.code["TMainForm.Button1Click"]
    out = dtools.delphi_events(ctx, form="TMainForm", component="Button1").splitlines()
    assert out[0] == "TMainForm events 1 of 8 (component 'Button1')"
    assert out[1:] == [f"  Button1.OnClick -> TMainForm.Button1Click 0x{a:08x} TMainForm::Button1Click"]
    low = dtools.delphi_events(ctx, form="mainform", component="button1").splitlines()   # case-insensitive
    assert low[1:] == out[1:]
    pre = dtools.delphi_events(ctx, form="TMainForm", component="Check").splitlines()    # prefix
    assert pre[0].startswith("TMainForm events 2 of 8") and len(pre) == 3
    bad = dtools.delphi_events(ctx, form="TMainForm", component="Nope")
    assert bad.startswith("error not_found: no component 'Nope' with event handlers in TMainForm (components: ")
    assert "Button1" in bad and "Check1" in bad and "\n" not in bad
    both = dtools.delphi_events(ctx, form="TMainForm").splitlines()                      # no component: all
    assert both[0] == "TMainForm events 8"


def test_delphi_events_component_without_form(proj):  # noqa: F811
    """Round 9 (P7): no form: exact name, else prefix, else part of the name, over all forms."""
    ctx, st, bid, pe = proj
    exact = dtools.delphi_events(ctx, component="Button1").splitlines()
    assert len(exact) == 1 and exact[0].startswith("TMainForm Button1.OnClick")
    pre = dtools.delphi_events(ctx, component="Check").splitlines()
    assert pre[0] == "component 'Check': no exact name; prefix match, 2 events" and len(pre) == 3
    part = dtools.delphi_events(ctx, component="utton1").splitlines()
    assert part[0] == "component 'utton1': no exact name; partial match, 1 events" and "Button1.OnClick" in part[1]
    dotted = dtools.delphi_events(ctx, component="MainForm.Button1")      # form class without its T
    assert dotted.startswith("TMainForm Button1.OnClick")
    assert dtools.delphi_events(ctx, component="Nope").startswith("error not_found:")


# -- N10: xrefs kind=code, strings without pattern, bare method -------------------------------------

def _world(tmp_path):
    from test_targets import build
    return build(tmp_path)


def test_xrefs_kind_code_is_call_and_jump(tmp_path):
    ctx, st, ids = _world(tmp_path)
    out = core.xrefs(ctx, "host.exe!ReadFile", kind="code")
    assert not out.startswith("error")
    assert "call" in out and "read" not in out.split("\n", 1)[1]
    assert "unknown kind" not in core.xrefs(ctx, "host.exe!ReadFile", kind="Code")


def test_strings_without_pattern_lists_all(tmp_path):
    ctx, st, ids = _world(tmp_path)
    out = core.strings(ctx, binary="tool.exe").splitlines()
    assert out[0] == "strings: 1"
    assert "Open the thing" in out[1]
    assert core.strings(ctx, pattern="zzz", binary="tool.exe").startswith("no strings match 'zzz'")


def _qt(st, bid, cls, meth, addr, meta):
    st.db.execute("INSERT INTO qt_class(binary_id, meta_addr, name, major, revision, data_addr, nsignals, nmethods, "
                  "nprops, nenums, nctors) VALUES (?,?,?,?,?,?,?,?,?,?,?)", (bid, meta, cls, 5, 8, 0, 0, 1, 0, 0, 0))
    st.db.execute("INSERT INTO qt_method(binary_id, meta_addr, idx, kind, name, addr) VALUES (?,?,?,?,?,?)",
                  (bid, meta, 0, "slot", meth, addr))
    st.db.commit()


def test_bare_method_name_resolves_when_unique(tmp_path):
    ctx, st, ids = _world(tmp_path)
    bid = ids["host.exe"]
    _qt(st, bid, "MainWindow", "fileOpen", 0x401100, 0x405000)
    t = tg.resolve_target(ctx, "host.exe", "fileOpen", (tg.FUNCTION,))
    assert isinstance(t, tg.FunctionTarget) and t.fn.entry == 0x401100
    assert t.note == "resolved 'fileOpen' to MainWindow::fileOpen"
    assert core.xrefs(ctx, "fileOpen", binary="host.exe").startswith("xrefs to ")
    _qt(st, bid, "Other", "fileOpen", 0x401200, 0x405100)
    amb = tg.resolve_target(ctx, "host.exe", "fileOpen", (tg.FUNCTION,))
    assert isinstance(amb, str) and amb.startswith("error ambiguous: 'fileOpen' matches 2 functions: ")
    assert "MainWindow::fileOpen 0x00401100" in amb and "Other::fileOpen 0x00401200" in amb
    nf = tg.resolve_target(ctx, "host.exe", "noSuchMethod", (tg.FUNCTION,))
    assert nf.startswith("error not_found")


# -- N6: main of a Delphi / FPC program -----------------------------------------------------------

def _prog(tmp_path, toolchain, psize=4):
    ctx = make_ctx(tmp_path)
    ix, st = _store(ctx)
    base = 0x400000 if psize == 4 else 0x140000000
    sha = "ab" * 32
    bid = st.upsert_binary(sha, "prog.exe", format="pe32", arch="x86", pointer_size=psize, image_base=base,
                           toolchain=toolchain, analysis_profile="p")
    ent, pm = base + 0x1680, base + 0x1900
    st.insert_functions(bid, [_fn(ent, "entry", 67, False, "library"), _fn(pm, "FUN_main", 542),
                              _fn(base + 0x1780, "Helper", 20)])
    ix.set_status(st, bid, "ready")
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    (art / sha).write_bytes(b"MZ")
    return ctx, st, bid, base, ent, pm


class _Info:
    def __init__(self, ep):
        self.entry_point = ep


def _patch_image(monkeypatch, base, ent, rec, psize, fields):
    if psize == 4:
        code = b"\x55\x89\xe5" + b"\xb8" + struct.pack("<I", rec) + b"\xe8" + struct.pack("<i", 0) + b"\xc3"
    else:
        disp = rec - (ent + 1 + 7)
        code = b"\x55\x48\x8d\x0d" + struct.pack("<i", disp) + b"\xc3"
    text = cpp.Section(base + 0x1000, b"\0" * 0x680 + code + b"\0" * 0x100, True, 0x1000)
    data = cpp.Section(rec - 0x10, b"\0" * 0x10 + b"".join(struct.pack("<I" if psize == 4 else "<Q", f) for f in fields)
                       + b"\0" * 0x40, False, 0x100)
    img = cpp.Image(psize, base, [text, data])
    monkeypatch.setattr(cpp.Image, "from_pe", classmethod(lambda cls, p: img))
    monkeypatch.setattr("airlock.projects.detect", lambda p: _Info(ent - base))


def test_main_resolves_to_delphi_entry(tmp_path, monkeypatch):
    ctx, st, bid, base, ent, pm = _prog(tmp_path, "delphi")
    monkeypatch.setattr("airlock.projects.detect", lambda p: _Info(ent - base))
    for name in ("main", "WinMain", "wWinMain", "program", "PASCALMAIN"):
        t = tg.resolve_target(ctx, "", name, (tg.FUNCTION,))
        assert isinstance(t, tg.FunctionTarget) and t.fn.entry == ent, name
        assert t.note == f"resolved '{name}' to the program body entry (entry)"


@pytest.mark.parametrize("psize", [4, 8])
def test_main_resolves_to_fpc_pascalmain(tmp_path, monkeypatch, psize):
    ctx, st, bid, base, ent, pm = _prog(tmp_path, "fpc", psize)
    rec = base + 0x4010
    _patch_image(monkeypatch, base, ent, rec, psize, [0x1, 0x2, 0x3, 0x4, 0, pm, 0, 0x5])
    t = tg.resolve_target(ctx, "", "main", (tg.FUNCTION,))
    assert isinstance(t, tg.FunctionTarget) and t.fn.entry == pm
    assert "program body" in (t.note or "") and "PASCALMAIN" in t.note


def test_main_keeps_real_function_and_other_toolchains(tmp_path, monkeypatch):
    ctx, st, bid, base, ent, pm = _prog(tmp_path, "msvc")
    monkeypatch.setattr("airlock.projects.detect", lambda p: _Info(ent - base))
    assert tg.resolve_target(ctx, "", "main", (tg.FUNCTION,)).startswith("error not_found")   # no guess for MSVC
    st.insert_functions(bid, [_fn(base + 0x1800, "main", 40)])
    t = tg.resolve_target(ctx, "", "main", (tg.FUNCTION,))                                   # a real main wins
    assert isinstance(t, tg.FunctionTarget) and t.fn.entry == base + 0x1800 and t.note is None


# -- N7 -------------------------------------------------------------------------------------------

def test_hexdump_wrong_folder_right_file_name(env):  # noqa: F811
    c, src, pp = env
    pp.artifacts.mkdir(parents=True, exist_ok=True)
    (pp.artifacts / ("ab" * 32)).write_bytes(b"MZ" + bytes(range(30)))
    out = call(c, "hexdump", path="D:/elsewhere/sub/app.exe", length=16).splitlines()
    assert out[0] == "path not found; used the analysed copy of app.exe"
    assert out[1] == "app.exe 32 bytes, showing 0x0-0x10"
    assert call(c, "hexdump", path="D:/elsewhere/sub/other.exe").startswith("error ")
    assert call(c, "hexdump", path="app.exe", length=16).splitlines()[0] == "app.exe 32 bytes, showing 0x0-0x10"


# -- N8 -------------------------------------------------------------------------------------------

class _Worker:
    def __init__(self, st, bid, fn_entry):
        self.calls, self.st, self.bid, self.entry = [], st, bid, fn_entry

    def request(self, op, args, timeout=0):
        self.calls.append((op, args))
        return {"created": 1}


def test_function_created_on_demand(tmp_path, monkeypatch):
    ctx, st, bid, base, ent, pm = _prog(tmp_path, "qt")
    addr = base + 0x1c00
    text = cpp.Section(base + 0x1000, b"\0" * 0x2000, True, 0x2000)
    img = cpp.Image(4, base, [text])
    monkeypatch.setattr(cpp.Image, "from_pe", classmethod(lambda cls, p: img))
    w = _Worker(st, bid, addr)
    ctx.worker = w
    monkeypatch.setattr(ctx.indexer, "ensure_open", lambda p: None)
    monkeypatch.setattr(type(ctx.indexer), "reextract_code",
                        lambda self, store, b, program: store.insert_functions(b.id, [_fn(addr, "FUN_x", 30)]))
    t = tg.resolve_target(ctx, "", f"0x{addr:08x}", (tg.FUNCTION,))
    assert isinstance(t, tg.FunctionTarget) and t.fn.entry == addr
    assert t.note == f"no Ghidra function at 0x{addr:08x}; created one from the code there"
    assert w.calls[0][0] == "create_functions" and w.calls[0][1]["addresses"] == [addr]
    again = tg.resolve_target(ctx, "", f"FUN_{addr:08x}", (tg.FUNCTION,))      # now a function: no second call
    assert isinstance(again, tg.FunctionTarget) and len(w.calls) == 1


def test_function_not_created_for_data_or_clean_role(tmp_path, monkeypatch):
    from airlock.server import roles
    ctx, st, bid, base, ent, pm = _prog(tmp_path, "qt")
    text = cpp.Section(base + 0x1000, b"\0" * 0x1000, True, 0x1000)
    data = cpp.Section(base + 0x3000, b"\0" * 0x100, False, 0x100)
    img = cpp.Image(4, base, [text, data])
    monkeypatch.setattr(cpp.Image, "from_pe", classmethod(lambda cls, p: img))
    w = _Worker(st, bid, 0)
    ctx.worker = w
    monkeypatch.setattr(ctx.indexer, "ensure_open", lambda p: None)
    r = tg.resolve_target(ctx, "", f"0x{base + 0x3010:08x}", (tg.FUNCTION,))      # data block
    assert r.startswith("error not_found: no function at or containing") and not w.calls
    ctx.session = roles.SessionState(roles.CLEAN, ctx.session.project)
    r = tg.resolve_target(ctx, "", f"0x{base + 0x1c00:08x}", (tg.FUNCTION,))      # clean role never writes
    assert r.startswith("error not_found") and not w.calls
