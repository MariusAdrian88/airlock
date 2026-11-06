"""Spec body filter (DESIGN 9 "Enforcement"): rejects code, Ghidra artefacts, addresses and byte runs.

A heuristic aid, not a guarantee. ``check`` returns the first offence as a one-line error, naming
the line so the agent can rewrite it as prose or a data-layout table. Pure; no I/O.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

MAX_HEX_BYTES = 8            # N: this many consecutive hex bytes (or more) are rejected
ADDRESS_SLACK = 0x100000     # image range = [image_base, highest known address + slack]

_GHIDRA = re.compile(
    r"\b(?:FUN|DAT|LAB|PTR|SUB|SUB_|UNK|EXT|BYTE|WORD|DWORD)_[0-9A-Fa-f]{4,}\b"
    r"|\bundefined[1-8]?\b|\bparam_\d+\b|\blocal_[0-9a-fA-F]+\b|\bin_[A-Z]{2,4}\b"
    r"|\b(?:[uipc]|ppc|pp|us|ul)Var\d+\b|\bunaff_\w+\b|\bextraout_\w+\b")
_C_ASSIGN = re.compile(r"^[\w\s\*\.\[\]>:()&-]*?(?<![=!<>])(?:[-+*/|&^]|<<|>>)?=(?!=)[^;]*;\s*$")
_C_CALL = re.compile(r"^(?:return\b.*|[A-Za-z_][\w:.>-]*\s*\(.*\)|delete\b.*|goto\b.*|break|continue)\s*;\s*$")
_C_BLOCK = re.compile(r"^(?:[{}]\s*;?|\}\s*(?:else\b.*|while\b.*)?|(?:if|for|while|switch)\s*\(.*\)\s*\{?"
                      r"|else\s*\{?|do\s*\{|case\s+[\w']+\s*:|default\s*:|[\w\s\*&:<>]+\)\s*\{)\s*$")
_C_DECL = re.compile(r"^(?:(?:unsigned|signed|const|static|struct|class|enum|typedef)\s+)*"
                     r"(?:int|char|short|long|void|float|double|bool|BOOL|DWORD|WORD|BYTE|HRESULT|"
                     r"size_t|u?int\d+_t|LPCSTR|LPCWSTR|HANDLE|HWND)\b[\s\*&]*[\w\[\]:]+\s*[=;(\[].*[;{]\s*$")
_C_PREPROC = re.compile(r"^#\s*(?:include|define|ifdef|ifndef|endif|pragma|if|else)\b")
_PASCAL = re.compile(r"^(?:begin|end\s*[;.]?|repeat|var|procedure\b.*|function\b.*|try|finally|except"
                     r"|[A-Za-z_][\w.\[\]^]*\s*:=.*;?)\s*$", re.I)
_FENCE = re.compile(r"^\s*(?:```|~~~)")
_HEX_LIT = re.compile(r"(?<![\w$])(?:0[xX]|\$)([0-9A-Fa-f]{1,16})\b|\b([0-9A-Fa-f]{5,16})h\b|"
                      r"(?<![\w.])([0-9A-Fa-f]{6,16})(?![\w.])")
_BYTE = r"(?:0[xX])?[0-9A-Fa-f]{2}"
_BYTE_RUN = re.compile(rf"(?<![\w])(?:{_BYTE}(?:[ ,:\-]+|(?=[ ,]|$))){{{MAX_HEX_BYTES - 1},}}{_BYTE}(?![\w])")
_LONG_HEX = re.compile(r"(?<![\w])(?:[0-9A-Fa-f]{2}){8,}(?![\w])")
_POINTER_LIT = re.compile(r"(?<![\w$])0[xX][0-9A-Fa-f]{8,16}\b")


def _preview(line: str) -> str:
    s = " ".join(line.split())
    return s if len(s) <= 60 else s[:57] + "..."


def _err(code: str, n: int, line: str, what: str, how: str) -> str:
    return f"error {code}: line {n} {what} ('{_preview(line)}'). {how}."


def image_ranges(bases: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """[(image_base, highest_known_address)] -> half-open ranges widened by ADDRESS_SLACK."""
    return [(b, max(top, b) + ADDRESS_SLACK) for b, top in bases if b]


def _in_ranges(v: int, ranges: list[tuple[int, int]]) -> bool:
    return any(lo <= v < hi for lo, hi in ranges)


def check(text: str, ranges: list[tuple[int, int]] | None = None) -> str | None:
    """First offence as ``error code: ...`` or None. ``ranges`` come from ``image_ranges``."""
    ranges = ranges or []
    in_fence = False
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        s = line.strip()
        if not s:
            continue
        if _FENCE.match(s):
            return _err("spec_has_code", n, line, "opens a fenced block",
                        "allowed: prose and field/offset/size/meaning tables")
        if _GHIDRA.search(s):
            return _err("spec_has_ghidra_names", n, line, "contains a Ghidra artefact name",
                        "allowed: the role in prose, no decompiler names")
        for pat, what in ((_C_PREPROC, "is a preprocessor line"), (_C_BLOCK, "is a code block line"),
                          (_C_ASSIGN, "is an assignment statement"), (_C_CALL, "is a call or return statement"),
                          (_C_DECL, "is a declaration"), (_PASCAL, "is a Pascal statement")):
            if pat.match(s):
                return _err("spec_has_code", n, line, what,
                            "allowed: prose and field/offset/size/meaning tables")
        if _BYTE_RUN.search(s) or _LONG_HEX.search(s):
            return _err("spec_has_bytes", n, line,
                        f"carries a run of {MAX_HEX_BYTES} or more hex bytes",
                        "allowed: the byte layout as fields, not dumped bytes")
        if _POINTER_LIT.search(s):
            return _err("spec_has_address", n, line, "carries a pointer-sized hex literal",
                        "allowed: the thing by role, no address")
        for m in _HEX_LIT.finditer(s):
            digits = m.group(1) or m.group(2) or m.group(3)
            if m.group(3) and len(digits) != 8 and not re.search("[A-Fa-f]", digits):
                continue          # a plain decimal number, not an address
            if digits and _in_ranges(int(digits, 16), ranges):
                return _err("spec_has_address", n, line, "carries an address inside a binary's image",
                            "allowed: the thing by role, no address")
    return None
