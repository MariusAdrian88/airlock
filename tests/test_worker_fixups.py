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
