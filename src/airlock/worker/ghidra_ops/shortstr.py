"""ShortString literals for the string index of Delphi / Free Pascal programs.

A ShortString literal is a length byte and the characters. The Delphi string pass (``delphistr``) defines
the ones in read-only blocks and refuses identifier-like text (type names); Free Pascal keeps its literals in
writable ``.data``, so the index missed ``'purr'`` (**[verified]** on a Free Pascal 3.2.2 test program).
Here a literal counts when an instruction points at its length byte, it is not inside other defined
string data, and it is printable ASCII of at least ``MIN_SHORT`` characters. A type info record (kind byte,
then a ShortString name) is refused as in ``delphistr``. Pure part: ``shortstring_text``.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

MIN_SHORT = 3
_IDENT_B = re.compile(rb"[\w.<>,@$&:]+\Z")


def shortstring_text(buf: bytes, off: int) -> str | None:
    """Text of the ShortString at ``buf[off]`` (printable ASCII, at least MIN_SHORT), or None. Not a type
    info record: a nested length byte followed by an identifier."""
    if off < 0 or off >= len(buf):
        return None
    n = buf[off]
    if n < MIN_SHORT or off + 1 + n > len(buf):
        return None
    raw = buf[off + 1:off + 1 + n]
    if any(c < 0x20 or c > 0x7e for c in raw):
        return None
    m = raw[0]
    if off + 2 + m <= len(buf) and _IDENT_B.match(buf[off + 2:off + 2 + m]):
        return None
    return raw.decode("ascii")


def referenced_shortstrings(p: Any) -> Iterator[tuple[Any, str]]:
    """(address, text) of the ShortString literals that code points at, in a Delphi / Free Pascal program
    (the Delphi string pass has run); nothing for other programs."""
    from ghidra.program.model.data import StringDataInstance  # type: ignore

    from .delphistr import STUB_BLOCK, _block_bytes

    if not p.getOptions("airlock").contains("delphi_strings"):
        return
    mem, listing, refman = p.getMemory(), p.getListing(), p.getReferenceManager()
    seen: set[int] = set()
    for blk in mem.getBlocks():
        if not blk.isInitialized() or blk.isOverlay() or str(blk.getName()) == STUB_BLOCK:
            continue
        try:
            buf = _block_bytes(blk)
        except Exception:  # noqa: BLE001  unreadable block
            continue
        start = blk.getStart()
        base = int(start.getOffset())
        rng = p.getAddressFactory().getAddressSet(start, blk.getEnd())
        it = refman.getReferenceDestinationIterator(rng, True)
        while it.hasNext():
            dst = it.next()
            off = int(dst.getOffset()) - base
            text = shortstring_text(buf, off)
            if text is None or int(dst.getOffset()) in seen or listing.getInstructionContaining(dst) is not None:
                continue
            d = listing.getDataContaining(dst)
            if d is not None and d.isDefined() and StringDataInstance.isString(d):
                continue        # already a string row
            if any(r.getReferenceType().isData() and listing.getInstructionAt(r.getFromAddress()) is not None
                   for r in refman.getReferencesTo(dst)):
                seen.add(int(dst.getOffset()))
                yield dst, text
