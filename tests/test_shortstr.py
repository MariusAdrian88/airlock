"""ShortString literals for the string index (pure part; the Ghidra part is checked on a program)."""

from airlock.worker.ghidra_ops.shortstr import shortstring_text


def test_identifier_like_literal_is_kept():
    assert shortstring_text(b"\x00\x04purr\x00\x00", 1) == "purr"
    assert shortstring_text(b"\x0bHello world\x00", 0) == "Hello world"


def test_too_short_or_unprintable_or_past_end_refused():
    assert shortstring_text(b"\x02hi\x00", 0) is None
    assert shortstring_text(b"\x04pu\x01r", 0) is None
    assert shortstring_text(b"\x09abc", 0) is None
    assert shortstring_text(b"abc", 5) is None


def test_type_info_record_refused():
    # kind byte 7, then a ShortString name: reads as a ShortString of 7 chars that starts with a length byte
    assert shortstring_text(b"\x07\x07TObject\x00\x00", 0) is None
