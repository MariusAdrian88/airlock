"""Route tables of MFC look-alike frameworks (server/routes.py) and MFC handler names as targets:
synthetic byte images (32-bit and 64-bit), no Ghidra. All names are invented."""

from __future__ import annotations

import struct

import pytest

from airlock.server import cpp, mfc, routes, targets, uijoin
from airlock.server.tools import cpp as cpp_tools
from test_cpp import Builder
from test_tools import fill, make_ctx
from test_ui_join import proj  # noqa: F401  (fixture)

WM_COMMAND, WM_SIZE, WM_NOTIFY = 0x111, 0x05, 0x4E
UPDATE = 0xFFFFFFFF


def invoker(b: Builder, handler: int) -> int:
    """push rbx; sub rsp,20; mov rax,rdx; mov rbx,rcx; mov rcx,rax; call handler; mov rax,rbx; add rsp,20;
    pop rbx; ret  (this = the second argument)."""
    va = b.text_va + (len(b.text) + 15) // 16 * 16
    pre = b"\x53\x48\x83\xec\x20\x48\x8b\xc2\x48\x8b\xd9\x48\x8b\xc8"
    call_end = va + len(pre) + 5
    return b.code(pre + b"\xe8" + struct.pack("<i", handler - call_end) + b"\x48\x8b\xc3\x48\x83\xc4\x20\x5b\xc3")


def inlined(b: Builder, callee: int) -> int:
    """push rbx; mov rbx,rcx; mov ecx,1; call callee; mov rax,rbx; pop rbx; ret  (handler body inlined)."""
    va = b.text_va + (len(b.text) + 15) // 16 * 16
    pre = b"\x53\x48\x8b\xd9\xb9\x01\x00\x00\x00"
    return b.code(pre + b"\xe8" + struct.pack("<i", callee - (va + len(pre) + 5)) + b"\x48\x8b\xc3\x5b\xc3")


def entries(b: Builder, rows: list[tuple]) -> int:
    """rows: (message, code, first, last, invoke, registered)."""
    fmt = "<4III" if b.ps == 4 else "<4IQQ"
    return b.data(b"".join(struct.pack(fmt, *r) for r in rows))


def initialiser(b: Builder, table: int, ents: int, n: int, base: int) -> int:
    """The lazy initialiser of ``static RouteTable table{base, {ents, n}}``."""
    ps = b.ps
    if ps == 4:
        st = lambda dst, imm: b"\xc7\x05" + struct.pack("<II", dst, imm)          # noqa: E731
        return b.code(st(table + 8, n) + st(table, base) + st(table + 4, ents) + b"\xc3")
    va = b.text_va + (len(b.text) + 15) // 16 * 16
    out = b""

    def rel(target: int, size: int) -> bytes:
        return struct.pack("<i", target - (va + len(out) + size))
    out += b"\x48\xc7\x05" + rel(table + 16, 11) + struct.pack("<I", n)         # mov qword [T+16], n
    out += b"\x48\x8d\x05" + rel(base, 7)                                        # lea rax, [base]
    out += b"\x48\x89\x05" + rel(table, 7)                                       # mov [T], rax
    out += b"\x48\x8d\x0d" + rel(table + 64, 7)                                  # lea rcx, [guard]
    out += b"\x48\x8d\x05" + rel(ents, 7)                                        # lea rax, [entries]
    out += b"\x48\x89\x05" + rel(table + 8, 7)                                   # mov [T+8], rax
    return b.code(out + b"\xc3")


def vtable_user(b: Builder, vt: int) -> int:
    """A constructor that stores the vtable: lea rax,[vt]; mov [rcx],rax; ret / mov [esi], vt; ret."""
    if b.ps == 4:
        return b.code(b"\xc7\x06" + struct.pack("<I", vt) + b"\xc3")
    va = b.text_va + (len(b.text) + 15) // 16 * 16
    return b.code(b"\x48\x8d\x05" + struct.pack("<i", vt - (va + 7)) + b"\x48\x89\x01\xc3")


def build(ps: int):
    """CFrame-like base table (1 entry) and a main frame table (4 entries) whose base is the first."""
    b = Builder(ps)
    h = {n: b.stub() for n in ("tool", "upd", "size", "bar", "reg", "dtor", "other")}
    inv = (lambda fn: invoker(b, fn)) if ps == 8 else (lambda fn: fn)
    regid = b.data(struct.pack("<I", 0), 4)
    base_ents = entries(b, [(WM_COMMAND, 0, 59392, 59393, inv(h["bar"]), 0)])
    main_ents = entries(b, [(WM_COMMAND, 0, 32876, 32876, inv(h["tool"]), 0),
                            (WM_COMMAND, UPDATE, 32876, 32876, inv(h["upd"]), 0),
                            (WM_SIZE, 0, 0, 0, inlined(b, h["other"]) if ps == 8 else h["size"], 0),
                            (0, 0, 0, 0, inv(h["reg"]), regid)])
    empty = b.data(bytes(4 * ps))                     # CCmdTarget's constant empty table
    base_tab, main_tab = b.data(bytes(3 * ps + 64)), b.data(bytes(3 * ps + 64))
    initialiser(b, base_tab, base_ents, 1, empty)
    initialiser(b, main_tab, main_ents, 4, base_tab)
    g_base, g_main = b.getter(base_tab), b.getter(main_tab)
    vt_base = b.data(b.ptr(h["dtor"]) + b.ptr(g_base))
    vt_main = b.data(b.ptr(h["dtor"]) + b.ptr(g_main))
    vtable_user(b, vt_base)
    vtable_user(b, vt_main)
    return b, dict(h=h, base_ents=base_ents, main_ents=main_ents, vt_base=vt_base, vt_main=vt_main,
                   size_inv=main_ents)


def test_x64_count_store_between_entries_lea_and_store():
    """The compiler may schedule the count store between ``lea rax,[entries]`` and ``mov [T+8],rax``."""
    b = Builder(8)
    h = b.stub()
    ents = entries(b, [(WM_COMMAND, 0, 4001, 4001, h, 0), (WM_SIZE, 0, 0, 0, h, 0)])
    base_ents = entries(b, [(WM_COMMAND, 0, 9, 9, h, 0)])
    base_tab, tab = b.data(bytes(64)), b.data(bytes(64))
    va = b.text_va + (len(b.text) + 15) // 16 * 16
    out = b""

    def rel(target: int, size: int) -> bytes:
        return struct.pack("<i", target - (va + len(out) + size))
    out += b"\x48\x8d\x05" + rel(base_tab, 7)                    # lea rax,[base]
    out += b"\x48\x89\x05" + rel(tab, 7)                         # mov [T],rax
    out += b"\x48\x8d\x05" + rel(ents, 7)                        # lea rax,[entries]
    out += b"\x48\xc7\x05" + rel(tab + 16, 11) + struct.pack("<I", 2)    # mov qword [T+16],2   (in between)
    out += b"\x48\x89\x05" + rel(tab + 8, 7)                     # mov [T+8],rax
    b.code(out + b"\xc3")
    # the base table, also initialised (contiguous form)
    initialiser(b, base_tab, base_ents, 1, b.data(bytes(32)))
    tables = {t.entries: t for t in routes.find_tables(b.image())}
    assert [(r.message, r.id, r.last_id) for r in tables[ents].rows] == [(WM_COMMAND, 4001, 4001), (WM_SIZE, 0, 0)]
    assert tables[ents].table == tab and tables[ents].base == base_tab


def test_x86_base_table_from_a_call():
    """32-bit: ``call F; push guard; mov [T],eax; mov [T+4],entries; mov [T+8],n`` with ``F`` = ``mov eax,B; ret``
    (the base class's ``GetStaticRouteTable``)."""
    b = Builder(4)
    h = b.stub()
    base_ents = entries(b, [(WM_COMMAND, 0, 9, 9, h, 0)])
    ents = entries(b, [(WM_COMMAND, 0, 4001, 4001, h, 0), (WM_SIZE, 0, 0, 0, h, 0)])
    base_tab, tab = b.data(bytes(32)), b.data(bytes(32))
    initialiser(b, base_tab, base_ents, 1, 0)
    getter = b.code(b"\xb8" + struct.pack("<I", base_tab) + b"\xc3")           # mov eax, base_tab; ret
    va = b.text_va + (len(b.text) + 15) // 16 * 16
    st = lambda dst, imm: b"\xc7\x05" + struct.pack("<II", dst, imm)           # noqa: E731
    code = b"\xe8" + struct.pack("<i", getter - (va + 5)) + b"\x68" + struct.pack("<I", tab + 12)
    code += b"\xa3" + struct.pack("<I", tab) + st(tab + 4, ents) + st(tab + 8, 2) + b"\xc3"
    b.code(code)
    tables = {t.entries: t for t in routes.find_tables(b.image())}
    assert tables[ents].table == tab and tables[ents].base == base_tab
    assert tables[base_ents].base == 0


@pytest.fixture(params=[4, 8], ids=["x86", "x64"])
def built(request):
    b, a = build(request.param)
    return b, a, b.image()


def test_route_tables_decoded(built):
    b, a, img = built
    maps = routes.find_route_maps(img)
    by = {m.map_addr: m for m in maps}
    assert set(by) == {a["base_ents"], a["main_ents"]}
    main = by[a["main_ents"]]
    assert main.kind == "routes" and main.cls == f"anon_{a['main_ents']:0{2 * b.ps}x}"
    assert main.vtable == a["vt_main"] and main.base_map == a["base_ents"]
    assert by[a["base_ents"]].base_map == 0 and by[a["base_ents"]].vtable == a["vt_base"]
    rows = [(e.message, e.code, e.id, e.last_id, e.handler) for e in main.entries]
    h = a["h"]
    assert rows[0] == (WM_COMMAND, 0, 32876, 32876, h["tool"])                  # the invoker is followed
    assert rows[1] == (WM_COMMAND, UPDATE, 32876, 32876, h["upd"])
    assert rows[2][:4] == (WM_SIZE, 0, 0, 0) and rows[2][4] != h["other"]       # inlined body: the invoker stays
    assert rows[3][:4] == (routes.REGISTERED, 0, 0, 0) and rows[3][4] == h["reg"]


def test_bad_rows_reject_the_table(built):
    b, a, img = built
    assert routes.parse_routes(img, a["main_ents"], 4) is not None
    assert routes.parse_routes(img, a["main_ents"], 5) is None                  # past the end: not an entry
    assert routes.parse_routes(img, a["main_ents"] + 4, 1) is None              # misaligned


def test_classic_msgmap_is_not_a_route_table():
    b = Builder(8)
    h = b.stub()
    m = b.msgmap([(WM_COMMAND, 0, 100, 100, 12, h)])
    ents = b.image().ptr(m + 8)
    assert routes.parse_routes(b.image(), ents, 1) is None                      # sig 12 is no code pointer


def test_parse_image_and_class_rows(built):
    b, a, img = built
    classes, slots, maps = cpp.parse_image(img)
    assert {m.map_addr for m in maps if m.kind == "routes"} == {a["base_ents"], a["main_ents"]}
    res = mfc.analyse(img, classes, slots, maps, None)
    rows = {c.vtable: c for c in res.classes if c.source == "routes"}
    main = rows[a["vt_main"]]
    assert main.map_addr == a["main_ents"] and main.base == f"anon_{a['base_ents']:0{2 * b.ps}x}"


def test_tool_lists_route_maps_and_versions(tmp_path, built):
    b, a, img = built
    ctx = make_ctx(tmp_path)
    bid = fill(ctx)
    st = ctx.indexer.store("proj")
    st.db.execute("UPDATE binary SET pointer_size=? WHERE id=?", (b.ps, bid))
    st.db.commit()
    classes, slots, maps = cpp.parse_image(img)
    cpp.store_rows(st, bid, classes, slots, maps, mfc.analyse(img, classes, slots, maps, None))
    name = f"anon_{a['main_ents']:0{2 * b.ps}x}"
    out = cpp_tools.mfc_message_maps(ctx, name).splitlines()
    assert out[0].startswith(f"{name} map 0x") and "entries 4 route table, vtable 0x" in out[0]
    assert ", base anon_" in out[0]
    assert any(ln.startswith("WM_COMMAND id 32876 -> ") for ln in out)
    assert any(ln.startswith("UPDATE_COMMAND_UI id 32876 -> ") for ln in out)
    from airlock.server import fnfix
    assert {a["h"]["upd"], a["h"]["reg"]} <= set(fnfix.candidates(st, bid))
    assert cpp.CPP_VERSION >= 3 and fnfix.FIX_VERSION >= 5


# ── generated handler names as targets ─────────────────────────────────────

def test_suggested_handler_names_resolve(proj):  # noqa: F811
    ctx, st, bid, h = proj
    st.db.execute("UPDATE function SET name='FUN_00401000', namespace=NULL WHERE binary_id=? AND entry=?",
                  (bid, h["open"]))
    st.db.commit()
    hd = next(x for x in uijoin.UiIndex(st, bid).handlers if x.addr == h["open"] and not x.is_update)
    assert uijoin.UiIndex(st, bid).name_of(hd) == "CMainFrame::OnCommand_100_Open (FUN_00401000)"
    for text in ("CMainFrame::OnCommand_100_Open", "CMainFrame::OnCommand_100_Open (FUN_00401000)",
                 "cmainframe::oncommand_100_open", "OnCommand_100_Open"):
        r = targets.resolve_target(ctx, "", text, [targets.FUNCTION])
        assert isinstance(r, targets.FunctionTarget), (text, r)
        assert r.fn.entry == h["open"]
    r = targets.resolve_target(ctx, "", "CMainFrame::OnUpdateCommand_100_Open", [targets.FUNCTION])
    assert isinstance(r, targets.FunctionTarget) and r.fn.entry == h["upd"]
    r = targets.resolve_target(ctx, "", "CSettingsDlg::OnCommand_100_Open", [targets.FUNCTION])
    assert isinstance(r, str) and r.startswith("error not_found")             # another class


def test_search_lists_generated_mfc_handler_names(proj):  # noqa: F811
    from airlock.server.tools import core
    ctx, st, bid, h = proj
    st.db.execute("UPDATE function SET name='FUN_00401000', namespace=NULL WHERE binary_id=? AND entry=?",
                  (bid, h["open"]))
    st.db.commit()
    out = core.search(ctx, "oncommand_100_open", kind="function")
    assert any(ln.startswith("function CMainFrame::OnCommand_100_Open 0x00401000 (MFC handler)")
               for ln in out.splitlines()), out
    assert "function FUN_00401000" not in out


def test_cpp_tool_errors_list_data_not_advice(proj):  # noqa: F811
    ctx, st, bid, h = proj
    out = cpp_tools.mfc_message_maps(ctx, "NoSuchClass")
    assert out.startswith("error not_found") and "classes with a map: " in out and "CMainFrame" in out
    assert "Call " not in out
    assert "Retry" not in cpp_tools.rtti_classes(ctx, limit=0)
