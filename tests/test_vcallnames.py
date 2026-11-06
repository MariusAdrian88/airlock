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
