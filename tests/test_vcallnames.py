"""Slot and method comments after virtual-call stub names (``vcallnames``)."""
from airlock.server import vcallnames as V


class Fake:
    psize = 4
    fpc = True

    def __init__(self):
        self.vmt = {0x500000: "TFormMain", 0x510000: "TButton"}

    def self_class(self):
        return 0x500000

    def field_class(self, vmt, offset):
        return 0x510000 if (vmt, offset) == (0x500000, 0x4a0) else None

    def class_at(self, addr):
        return addr if addr in self.vmt else None

    def method(self, vmt, slot):
        return self.vmt[vmt], ("TButton.Click" if (vmt, slot) == (0x510000, 310) else "")


def test_slot_numbers_follow_the_hints():
    assert V.slot_of(0x508, 4, True) == 310          # Free Pascal: header of 12 words
    assert V.slot_of(0x10, 4, False) == 4            # Delphi: slot N at vmt + 4 N
    assert V.slot_of(0xfffffff4, 4, False) is None   # a header entry of the Delphi vmt
    assert V.slot_of(0x20, 4, True) is None


def test_self_receiver_and_aliases():
    c = ("void FUN_00428190(void *param_1,undefined4 param_2)\n\n{\n  void *pvStack_c;\n  \n"
         "  pvStack_c = param_1;\n  vmt_508_adc_0(pvStack_c,pvStack_14,&pbStack_10);\n  return;\n}\n")
    out = V.annotate(c, Fake())
    assert "vmt_508_adc_0/*TFormMain vslot 310*/(pvStack_c" in out


def test_field_receiver_names_the_method():
    c = ("void FUN_x(void *param_1)\n{\n  vmt_508_a_0(*(void **)((int)param_1 + 0x4a0));\n}\n")
    assert "vmt_508_a_0/*TButton vslot 310 -> TButton.Click*/(" in V.annotate(c, Fake())
    c = c.replace("0x4a0", "0x4a4")
    assert "vmt_508_a_0/*vslot 310*/(" in V.annotate(c, Fake())     # a field of unknown type


def test_object_made_by_a_constructor_call():
    c = ("void FUN_x(undefined4 param_1)\n{\n  int *piVar1;\n\n"
         "  piVar1 = (int *)FUN_004ee320(&PTR_FUN_00510000,'\x01',param_1);\n  vmt_508_a_0(piVar1);\n}\n")
    assert "vmt_508_a_0/*TButton vslot 310 -> TButton.Click*/(piVar1" in V.annotate(c, Fake())


def test_unknown_receiver_gives_only_the_slot():
    c = "void FUN_x(void)\n{\n  vmt_508_a_0(DAT_00ac2dbc);\n}\n"
    assert V.annotate(c, Fake()) == c.replace("vmt_508_a_0(", "vmt_508_a_0/*vslot 310*/(")
    assert V.annotate("void f(void)\n{\n  g(1);\n}\n", Fake()) == "void f(void)\n{\n  g(1);\n}\n"


def test_crlf_text():
    c = ("void FUN_00428190(void *param_1,undefined4 param_2)\r\n\r\n{\r\n  pvStack_c = param_1;\r\n"
         "  vmt_508_adc_0(pvStack_c,uStack_14);\r\n}\r\n")
    assert "vmt_508_adc_0/*TFormMain vslot 310*/(pvStack_c" in V.annotate(c, Fake())


class Fake2(Fake):
    """Also knows classes of globals / callers and a dynamic table."""

    def __init__(self):
        super().__init__()
        self.vmt = {0x500000: "TBase", 0x510000: "TDog", 0x520000: "TCat"}
        self.globals = {}
        self.callers = {}

    def self_class(self):
        return None

    def method(self, vmt, slot):
        if vmt not in self.vmt:
            return "", ""
        return self.vmt[vmt], f"{self.vmt[vmt]}.M{slot}" if slot >= 0 else ""

    def global_classes(self, addr, name):
        return self.globals.get(addr)

    def caller_classes(self, k):
        return self.callers.get(k)

    def dynamic_index(self, target, n):
        return {0x406178: [-1, 0x78]}.get(target, [None])[n] if target == 0x406178 else None

    def dyna_class_call(self, target):
        return False

    def dynamic_label(self, idx, vmts):
        return f"dynamic {idx}" + (f" -> {','.join(self.vmt[v] for v in vmts)}" if vmts else "")


def test_global_reassigned_uses_the_store_before_the_call():
    c = ("void FUN_x(void)\n{\n"
         "  DAT_00430010 = FUN_004016d0(&DAT_00510000,1,\"Rex\");\n  vmt_68_a_0(DAT_00430010);\n"
         "  DAT_00430010 = FUN_004016d0(&DAT_00520000,1,\"Tom\");\n  vmt_68_a_0(DAT_00430010);\n}\n")
    out = V.annotate(c, Fake2())
    assert out.count("vmt_68_a_0/*TDog vslot 14 -> TDog.M14*/(") == 1
    assert out.count("vmt_68_a_0/*TCat vslot 14 -> TCat.M14*/(") == 1
    assert "&DAT_00510000/*TDog*/" in out and "&DAT_00520000/*TCat*/" in out


def test_vmt_names_only_for_classes():
    c = "void f(void)\n{\n  g(&DAT_00510000,&DAT_00999999,&local_20,&DAT_00520000/*x*/);\n}\n"
    out = V.annotate(c, Fake2())
    assert "&DAT_00510000/*TDog*/," in out and "&DAT_00999999," in out and "&DAT_00520000/*x*/" in out
    assert "/*TCat*/" not in out


def test_branches_give_all_classes():
    c = ("void FUN_x(void)\n{\n  if (a) {\n    p = FUN_c(&DAT_00510000,1);\n  }\n  else {\n"
         "    p = FUN_c(&DAT_00520000,1);\n  }\n  vmt_68_a_0(p);\n}\n")
    assert "vmt_68_a_0/*vslot 14: TDog.M14 | TCat.M14*/(p)" in V.annotate(c, Fake2())
    one = c.replace("  else {\n    p = FUN_c(&DAT_00520000,1);\n  }\n", "")
    assert "vmt_68_a_0/*vslot 14*/(p)" in V.annotate(one, Fake2())       # a store that may not run: unknown


def test_global_from_other_functions_and_parameter_from_callers():
    f = Fake2()
    f.globals[0x430010] = [0x510000]
    f.callers[1] = [0x510000, 0x520000]
    c = "void FUN_x(int param_1,int *param_2)\n{\n  vmt_68_a_0(DAT_00430010);\n  vmt_68_a_0(param_2);\n  vmt_68_a_0(param_1);\n}\n"
    out = V.annotate(c, f)
    assert "vmt_68_a_0/*TDog vslot 14 -> TDog.M14*/(DAT_00430010)" in out
    assert "vmt_68_a_0/*vslot 14: TDog.M14 | TCat.M14*/(param_2)" in out
    assert "vmt_68_a_0/*vslot 14*/(param_1)" in out                    # the callers differ in nothing known


def test_dynamic_call_gets_its_index():
    f = Fake2()
    c = ("void FUN_x(int *param_1)\n{\n  System.@CallDynaInst/*0x00406178*/(param_1,L\"x\",&l);\n"
         "  FUN_00406178(param_1,L\"y\",&l);\n  g(1);\n}\n")
    out = V.annotate(c, f)
    assert "(param_1,L\"x\",&l)/*dynamic -1*/;" in out
    assert "(param_1,L\"y\",&l)/*dynamic 120*/;" in out


def test_dyn_index_before_reads_the_register_load(monkeypatch):
    class Img:
        def __init__(self, tail):
            self.tail = tail

        def read(self, va, n):
            return (b"\x90" * 64 + self.tail)[-n:]

    for tail, want in ((b"\x66\xbe\xff\xff", -1), (b"\xbe\x78\x00\x00\x00", 0x78), (b"\xbe\xfe\xff\xff\xff", -2),
                       (b"\x48\xc7\xc6\xfc\xff\xff\xff", -4), (b"\x66\x41\xbb\xfd\xff", -3), (b"\x90\x90", None)):
        V._IMAGES.clear()
        V._IMAGES["k"] = Img(tail)
        assert V.dyn_index_before("k", 0x1000) == want


def _store():
    import sqlite3
    from types import SimpleNamespace as NS
    db = sqlite3.connect(":memory:")
    db.executescript("""
    CREATE TABLE dl_class(binary_id, vmt, name, parent_vmt);
    CREATE TABLE dl_method(binary_id, vmt, kind, slot, name, addr);
    CREATE TABLE dl_field(binary_id, vmt, offset, type);
    CREATE TABLE function(id, binary_id, entry, name);
    CREATE TABLE ast_node(function_id, kind, start_off, end_off, address, target, text);
    CREATE TABLE decomp(function_id, fn_version, c_text);
    INSERT INTO dl_class VALUES (1,5242880,'TBase',NULL),(1,5308416,'TKid',5242880);
    INSERT INTO dl_method VALUES (1,5242880,'dynamic',-1,'',4198400),(1,5242880,'published',-1,'Dyn',4198400);
    """)
    store = NS(db=db, function_at=lambda bid, addr: None, get_meta=lambda k: "")
    return db, store, NS(id=1, pointer_size=4, toolchain="delphi")


def test_db_classes_dynamic_labels_global_and_callers():
    db, store, b = _store()
    d = V.DbClasses(store, b, 0x401000)
    assert d.dynamic_label(-1, [0x50 << 16 | 0x100000 - 0x100000 + 0x500000 - 0x500000 + 0] if False else [5308416]) \
        == "dynamic -1 -> TBase.Dyn"                                   # TKid inherits the entry of TBase
    assert d.dynamic_label(-1, []) == "dynamic -1: TBase.Dyn"
    assert d.dynamic_label(-7, [5308416]) == "dynamic -7"
    # a global written in one other function with a constructor call; a parameter passed by one caller
    db.executescript("""
    INSERT INTO function VALUES (10,1,4198400,'f'),(11,1,4198500,'g'),(12,1,4198600,'h');
    INSERT INTO ast_node VALUES (11,'global_ref',0,0,0,4390928,'DAT_00430010'),(10,'global_ref',0,0,0,4390928,'DAT_00430010');
    INSERT INTO decomp VALUES (11,1,'void g(void)\n{\n  DAT_00430010 = FUN_c(&DAT_00500000,1);\n}\n'),
                              (10,1,'void f(void)\n{\n  vmt_68_a_0(DAT_00430010);\n}\n');
    """)
    assert V.DbClasses(store, b, 4198400).global_classes(0x430010, "DAT_00430010") == [5242880]
    db.executescript("""
    INSERT INTO ast_node VALUES (12,'call',10,16,0,4198400,'FUN_00401000');
    INSERT INTO decomp VALUES (12,1,'void h(void)\n{\n  piVar1 = FUN_c(&DAT_00500000,1);
  FUN_00401000(piVar1,3);\n}\n');
    """)
    # the call text starts at offset 10 here: point the node at the real call
    off = db.execute("SELECT c_text FROM decomp WHERE function_id=12").fetchone()[0].index("FUN_00401000")
    db.execute("UPDATE ast_node SET start_off=? WHERE function_id=12", (off,))
    assert V.DbClasses(store, b, 4198400).caller_classes(0) == [5242880]
    assert V.DbClasses(store, b, 4198400).caller_classes(2) is None      # no such argument


class Fake64(Fake):
    psize = 8

    def method(self, vmt, slot):
        return self.vmt[vmt], ("TButton.Click" if (vmt, slot) == (0x510000, 310) else "")


def test_plain_x64_virtual_calls_get_a_slot_comment():
    c = ("void FUN_x(longlong *param_1)\n{\n  longlong *local_18;\n\n  local_18 = param_1;\n"
         "  (**(code **)(*local_18 + 0xa10))(local_18,&local_20,local_28);\n"
         "  (**(code **)(*(longlong *)DAT_14059e150 + 0xa10))(DAT_14059e150,1);\n"
         "  (**(code **)(**(longlong **)(param_1 + 0x4a0) + 0xa10))();\n"
         "  (**(code **)*local_18)(local_18);\n  (**(code **)(*local_18 + 0x18))(local_18);\n}\n")
    f = Fake64()
    f.field_class = lambda vmt, off: 0x510000 if off == 0x4a0 else None
    out = V.annotate(c, f)
    assert "(**(code **)(*local_18 + 0xa10))/*TFormMain vslot 310*/(local_18,&local_20" in out      # FPC: 0xa10/8 - 12
    assert "0xa10))/*vslot 310*/(DAT_14059e150,1)" in out                                          # unknown receiver
    assert "0xa10))/*TButton vslot 310 -> TButton.Click*/()" in out                                # field receiver
    assert "(**(code **)*local_18)(local_18)" in out                                               # header offset: none
    assert "0x18))(local_18)" in out                                                               # slot < 0 for FPC
    f.fpc = False                                                                                  # Delphi: off / 8
    out = V.annotate(c, f)
    assert "(**(code **)*local_18)/*TFormMain vslot 0*/(local_18)" in out
    assert "0x18))/*TFormMain vslot 3*/(local_18)" in out
    assert "0xa10))/*TFormMain vslot 322*/(local_18" in out
