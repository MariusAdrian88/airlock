from airlock.worker.ghidra_ops import fixups

EH_PROLOG = bytes.fromhex("6aff5064a10000000050" "8b44240c" "64892500000000" "896c240c" "8d6c240c" "50c3")


def test_classify_exact_helper():
    assert fixups.classify_helper(EH_PROLOG) == ("__EH_prolog", "EH_prolog")


def test_classify_rejects_variants():
    assert fixups.classify_helper(EH_PROLOG[:-1]) is None
    assert fixups.classify_helper(EH_PROLOG + b"\x90") is None
    assert fixups.classify_helper(EH_PROLOG[:-2] + b"\x51\xc3") is None
    assert fixups.classify_helper(b"") is None


def test_max_size_covers_patterns():
    assert fixups.MAX_HELPER_SIZE == len(EH_PROLOG)


# -- calling convention classifier ------------------------------------------------------

def I(mn, *ops):
    return (mn, tuple(ops))


# a thiscall method: saves ECX, then uses it as a pointer base
THIS_ENTRY = [I("PUSH", "EBP"), I("MOV", "EBP", "ESP"), I("PUSH", "ESI"), I("MOV", "ESI", "ECX"),
              I("MOV", "EAX", "dword ptr [ESI + 0x4]"), I("RET", "0x8")]
SET_ECX = ((I("PUSH", "0x1"), I("MOV", "ECX", "EDI")), I("MOV", "EAX", "EAX"))
LEA_ECX = ((I("LEA", "ECX", "[EBP + -0x20]"),), None)
CDECL_SITE = ((I("PUSH", "EAX"),), I("ADD", "ESP", "0x4"))
STD_SITE = ((I("PUSH", "EAX"),), I("MOV", "EBX", "EAX"))
NO_ECX_SITE = ((I("PUSH", "EAX"),), None)


def test_regs_read_first():
    assert fixups.regs_read_first(THIS_ENTRY) == (True, False)
    assert fixups.regs_read_first([I("XOR", "ECX", "ECX"), I("MOV", "EAX", "ECX")]) == (False, False)
    assert fixups.regs_read_first([I("MOV", "ECX", "0x5"), I("ADD", "EAX", "ECX")]) == (False, False)
    assert fixups.regs_read_first([I("PUSH", "ECX"), I("MOV", "EAX", "0x1")]) == (False, False)
    assert fixups.regs_read_first([I("ADD", "ECX", "0x4"), I("RET")]) == (True, False)
    assert fixups.regs_read_first([I("MOV", "EAX", "dword ptr [ECX]")]) == (True, False)
    assert fixups.regs_read_first([I("MOV", "AL", "CL"), I("MOV", "DL", "0x1")]) == (True, False)
    assert fixups.regs_read_first([I("MOV", "EAX", "EDX"), I("MOV", "EBX", "ECX")]) == (True, True)


def test_scan_stops_at_call_but_not_at_prolog_helper():
    assert fixups.regs_read_first([I("CALL", "FUN_00401000"), I("MOV", "EAX", "ECX")]) == (False, False)
    assert fixups.regs_read_first([I("CALL", "__EH_prolog3"), I("MOV", "ESI", "ECX")]) == (True, False)
    assert fixups.regs_read_first([I("CALL", "__SEH_prolog4"), I("MOV", "ESI", "ECX")]) == (True, False)
    assert fixups.regs_read_first([I("RET"), I("MOV", "ESI", "ECX")]) == (False, False)


def test_site_helpers():
    assert fixups.site_sets((I("PUSH", "1"), I("MOV", "ECX", "ESI")), "ECX")
    assert fixups.site_sets((I("LEA", "ECX", "[EBP + -4]"),), "ECX")
    assert not fixups.site_sets((I("MOV", "EAX", "ECX"),), "ECX")
    assert not fixups.site_sets((I("PUSH", "ECX"),), "ECX")
    assert fixups.site_cleanup(I("ADD", "ESP", "0xc")) == 12
    assert fixups.site_cleanup(I("POP", "ECX")) == 4
    assert fixups.site_cleanup(I("MOV", "EAX", "0x1")) == 0
    assert fixups.site_cleanup(None) == 0


def test_classify_thiscall():
    assert fixups.classify_convention(THIS_ENTRY, [8], [SET_ECX, LEA_ECX]) == "__thiscall"
    assert fixups.classify_convention(THIS_ENTRY, [0], [SET_ECX]) == "__thiscall"
    assert fixups.classify_convention(THIS_ENTRY, [8], []) == "__thiscall"      # only called through a vtable


def test_classify_ecx_not_passed_by_callers_is_not_thiscall():
    assert fixups.classify_convention(THIS_ENTRY, [8], [NO_ECX_SITE, NO_ECX_SITE, SET_ECX]) is None


def test_classify_fastcall_needs_edx():
    entry = [I("MOV", "EAX", "ECX"), I("ADD", "EAX", "EDX"), I("RET")]
    both = ((I("MOV", "EDX", "0x2"), I("MOV", "ECX", "0x1")), None)
    assert fixups.classify_convention(entry, [0], [both, both]) == "__fastcall"
    assert fixups.classify_convention(entry, [0], [SET_ECX, SET_ECX]) == "__thiscall"


def test_classify_stdcall_and_cdecl():
    plain = [I("PUSH", "EBP"), I("MOV", "EBP", "ESP"), I("MOV", "EAX", "dword ptr [EBP + 0x8]")]
    assert fixups.classify_convention(plain, [8], [STD_SITE]) == "__stdcall"
    assert fixups.classify_convention(plain, [8], []) == "__stdcall"
    assert fixups.classify_convention(plain, [0], [CDECL_SITE, CDECL_SITE, STD_SITE]) == "__cdecl"
    assert fixups.classify_convention(plain, [0], [STD_SITE, STD_SITE]) is None
    assert fixups.classify_convention(plain, [0], []) is None                    # no evidence


def test_classify_mixed_returns_are_unknown():
    assert fixups.classify_convention(THIS_ENTRY, [0, 8], [SET_ECX]) is None
