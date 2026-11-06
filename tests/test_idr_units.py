"""The unit rule for short sigdb matches (idr._drop_unsupported)."""

from __future__ import annotations

from airlock.server import delphisigs, idr


def _kb(procs: list[tuple[str, int]]) -> idr.Kb:
    kb = idr.Kb("t")
    kb.unit_support = True
    for name, fixed in procs:
        kb.procs.append(idr.Proc(name, 0, 0, fixed, fixed))
    return kb


def test_unit_of():
    assert idr.unit_of("Vcl.Dbgrids.TDBGridColumns.LoadFromFile") == "vcl.dbgrids"
    assert idr.unit_of("System.Generics.Collections.TList<System.TFoo<X>>.Add") == "system.generics.collections"
    assert idr.unit_of("Guitesting.Finalization") == "guitesting"
    assert idr.unit_of("SysUtils.IntToStr") == "sysutils"
    assert idr.unit_of("Unit1.TForm1.Button1Click") == "unit1"
    assert idr.unit_of("Vcl.Forms.EInvalidOp.Create") == "vcl.forms"


def test_short_match_needs_a_long_match_of_its_unit():
    kb = _kb([("System.Classes.TList.Add", 80),        # 0: long, unit system.classes
              ("System.Classes.TList.Clear", 20),       # 1: short, same unit: kept
              ("Vcl.Dbgrids.TCols.Load", 20),           # 2: short, unit not in the binary: dropped
              ("Vcl.Dbgrids.TCols.Save", 20),           # 3
              ("Vcl.Forms.TForm.Close", 20)])           # 4: short, one name kept of two
    out = {0x10: ["System.Classes.TList.Add"], 0x20: ["System.Classes.TList.Clear"],
           0x30: ["Vcl.Dbgrids.TCols.Load"], 0x40: ["Vcl.Dbgrids.TCols.Save", "System.Classes.TList.Clear"],
           0x50: ["Vcl.Forms.TForm.Close"]}
    kept = {0x10: [0], 0x20: [1], 0x30: [2], 0x40: [3, 1], 0x50: [4]}
    idr._drop_unsupported(kb, out, kept)
    assert len(out) == 5                                  # one long match only: too little evidence, nothing is dropped
    idr.UNIT_MIN_LONG, saved = 1, idr.UNIT_MIN_LONG
    try:
        idr._drop_unsupported(kb, out, kept)
    finally:
        idr.UNIT_MIN_LONG = saved
    assert sorted(out) == [0x10, 0x20, 0x40]
    assert out[0x20] == ["System.Classes.TList.Clear"]
    assert out[0x40] == ["System.Classes.TList.Clear"] and kept[0x40] == [1]     # unsupported alias name goes
    assert 0x30 not in kept and 0x50 not in kept


def test_rule_is_off_for_plain_knowledge_bases(tmp_path):
    kb = _kb([("A.TX.Long", 80), ("B.TY.Short", 20)])
    out, kept = {1: ["A.TX.Long"], 2: ["B.TY.Short"]}, {1: [0], 2: [1]}
    assert idr.Kb("plain").unit_support is False         # plain IDR files keep short matches
    idr.UNIT_MIN_LONG, saved = 1, idr.UNIT_MIN_LONG
    try:
        idr._drop_unsupported(kb, out, kept)
    finally:
        idr.UNIT_MIN_LONG = saved
    assert out == {1: ["A.TX.Long"]}


def test_sigdb_loader_sets_the_rule_for_delphi_not_fpc(tmp_path):
    rec = [("X.TA.Run", b"\x55\x8b\xec" + bytes(range(1, 20)), bytes(22))]
    for fname, want in (("30-32.sigdb", True), ("fpc-3.2.2-32.sigdb", False)):
        p = tmp_path / fname
        delphisigs.write_sigdb(p, 30, 4, rec)
        assert delphisigs.read_sigdb(p).unit_support is want
