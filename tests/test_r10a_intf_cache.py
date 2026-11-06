"""Round 10 (R1, R5, R8a): the interface index is built once per binary and class-table version, notes in the plate
comment do not hide the receiver class, and the concat stub shows its part count. Synthetic data only."""

from __future__ import annotations

from types import SimpleNamespace

from airlock.server import classintf, intflabel, libnames
from airlock.server import vcallnames as V
from test_r8_intf import C_INTF, DbClasses, annotate, proj  # noqa: F401  (proj is a fixture)
from test_vcallnames import Fake


def _bd(proj):
    ctx, st, bid, pe, tab, imt = proj
    return SimpleNamespace(store=st, psize=4, addr=lambda a, *_: f"0x{a:08x}",
                           binary=SimpleNamespace(id=bid, toolchain="delphi"))


def _count(st):
    seen: list[str] = []
    st.db.set_trace_callback(seen.append)
    return seen


def test_index_computes_the_owner_table_once(proj):
    bd = _bd(proj)
    seen = _count(bd.store)
    classintf.index(bd)
    bd.store.db.set_trace_callback(None)
    assert sum("m.name<>''" in q for q in seen) == 1                  # was one per virtual-dispatching slot
    assert sum(q.startswith("SELECT vmt, parent_vmt FROM dl_class") for q in seen) == 1


def test_cached_index_does_no_class_table_work(proj):
    bd = _bd(proj)
    classintf._CACHE.clear()
    first = classintf.cached_index(bd)
    assert first == classintf.index(bd)
    seen = _count(bd.store)
    again = classintf.cached_index(bd)
    bd.store.db.set_trace_callback(None)
    assert again is first
    assert not [q for q in seen if "dl_class" in q or "interface" in q]      # only the stamp queries run


def test_cache_drops_when_class_rows_or_names_change(proj):
    ctx, st, bid, *_ = proj
    bd = _bd(proj)
    classintf._CACHE.clear()
    first = classintf.cached_index(bd)
    with st.db:
        st.db.execute("DELETE FROM dl_method WHERE rowid=(SELECT max(rowid) FROM dl_method WHERE binary_id=? "
                      "AND kind='interface')", (bid,))
    assert classintf.cached_index(bd) is not first
    second = classintf.cached_index(bd)
    with st.db:
        st.db.execute("INSERT INTO function(binary_id, space, entry, name, name_state) VALUES (?, 'ram', 4198400, "
                      "'Renamed', 'user')", (bid,))
    assert classintf.cached_index(bd) is not second


def test_function_label_reuses_the_cached_index(proj):
    ctx, st, bid, *_ = proj
    classintf._CACHE.clear()
    cls = DbClasses(st, st.get_binary_by_id(bid), 0x401000)
    out1 = annotate(C_INTF, cls)
    seen = _count(st)
    out2 = annotate(C_INTF, DbClasses(st, st.get_binary_by_id(bid), 0x401000))      # a new object, as per call
    st.db.set_trace_callback(None)
    assert out1 == out2 and "IGreeter.Greet -> TBase.Greet" in out2
    assert not [q for q in seen if "interface-table" in q or "m.name<>''" in q]


def test_note_with_parenthesis_keeps_the_receiver_class():
    c = ("void FUN_00428190(void *param_1,undefined4 param_2)\n\n{\n  void *pvStack_c;\n  \n"
         "  pvStack_c = param_1;\n  vmt_508_adc_0(pvStack_c,pvStack_14,&pbStack_10);\n  return;\n}\n")
    notes = ("/*\n--- airlock notes ---\n[high] shows a message (the text of the label) {not code}\n"
             "x = y;\nvmt_508_adc_0(a)\n--- end airlock notes ---\n*/\n")
    out = V.annotate(notes + c, Fake())
    assert "vmt_508_adc_0/*TFormMain vslot 310*/(pvStack_c" in out
    assert out.startswith(notes)                                       # the note itself is untouched
    assert V.annotate("// a note (x)\n" + c, Fake()).count("TFormMain vslot 310") == 1
    assert V._params(notes + c) == ["param_1", "param_2"]


def test_concat_multi_shows_the_part_count():
    t = "  fpc_ansistr_concat_multi/*0x00000001000091c0*/(local_20,(longlong)&local_40,3,0);"
    out = libnames.concat_parts(t)
    assert "(local_20,(longlong)&local_40,3/*4 parts*/,0)" in out
    assert libnames.concat_parts(out) == out                           # idempotent
    assert libnames.concat_parts("fpc_ansistr_concat_multi(a,b,n,0)") == "fpc_ansistr_concat_multi(a,b,n,0)"
    assert "1/*2 parts*/" in libnames.concat_parts("fpc_ansistr_concat_multi(a, f(b,c), 1, 0)")
    assert "0x2/*3 parts*/" in libnames.Display(None, None, [])("fpc_ansistr_concat_multi(a,b,0x2,0)")
