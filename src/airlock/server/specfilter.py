"""Spec body filter (DESIGN 9 "Enforcement"): rejects code, Ghidra artefacts, addresses and byte runs.

A heuristic aid, not a guarantee. ``check`` returns the first offence as a one-line error, naming
the line so the agent can rewrite it as prose or a data-layout table. Pure; no I/O.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

MAX_HEX_BYTES = 16           # N: this many consecutive hex bytes (or more) are rejected; magic values,
#                              signatures and GUIDs up to N-1 bytes stay allowed (interface facts)
MAX_DEC_BYTES = 12           # decimal byte values 0-255 in a row (space or comma separated), no table pipes
ADDRESS_SLACK = 0x100000     # image range = [image_base, highest known address + slack]

_GHIDRA = re.compile(
    r"\b(?:FUN|DAT|LAB|PTR|SUB|SUB_|UNK|EXT|BYTE|WORD|DWORD)_[0-9A-Fa-f]{4,}\b"
    r"|\bundefined[1-8]?\b|\bparam_\d+\b|\blocal_[0-9a-fA-F]+\b|\bin_[A-Z]{2,4}\b"
    r"|\b(?:[uipc]|ppc|pp|us|ul)Var\d+\b|\bunaff_\w+\b|\bextraout_\w+\b"
    # Ghidra label forms: thunk_FUN_00401100, s_Hello_00405000, switchD_00401234, field_0x10, uStack_c
    r"|\b[A-Za-z]\w*_[0-9A-Fa-f]{8}(?:[0-9A-Fa-f]{8})?\b|\b[a-z]{1,3}Var\d+\b|\b[a-z]{0,3}Stack_[0-9A-Fa-f]+\b"
    r"|\bfield_0x[0-9A-Fa-f]+\b|\b(?:switchD|caseD|switchdataD|jumptable)_[0-9A-Fa-f]+\b")
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
# .NET: IL listings and C# shapes (ilspycmd output, dotnet_decompile text)
_IL_LABEL = re.compile(r"\bIL_[0-9A-Fa-f]{4}\b")
_IL_OP = re.compile(r"^(?:ldarg|ldarga|ldloc|ldloca|stloc|starg|ldstr|ldfld|ldflda|stfld|ldsfld|ldsflda|stsfld|"
                    r"ldc\.[a-z]\d?|ldnull|newobj|newarr|callvirt|castclass|isinst|brtrue|brfalse|beq|bne\.un|"
                    r"blt|bgt|ble|bge|br|leave|endfinally|ldelem|stelem|ldind|stind|conv\.[a-z]\d?|box|unbox)"
                    r"(?:\.\w+)*\s+\S|^call\s+(?:instance\s+)?[\w.\[\]<>`]+\s+[\w.\[\]<>`]+::"
                    r"|^(?:ldarg|ldloc|stloc|ldc|conv|ldelem|stelem)(?:\.\w+)+$|^ldnull$")
_IL_DIRECTIVE = re.compile(r"^\.(?:method|class|field|locals|maxstack|custom|assembly|module|entrypoint|try|catch)\b")
_CS_STMT = re.compile(
    r"^(?:(?:foreach|using|lock|fixed|checked|unchecked)\s*\(.*\)\s*\{?|catch\s*(?:\(.*\))?\s*(?:\{.*)?"
    r"|using\s+(?:var|static)\s+.*;|using\s+[\w.]+\s*;"
    r"|(?:await|yield\s+return)\s+.*;?|yield\s+break\s*;|throw\s+new\b.*|throw\s*;"
    r"|(?:var|new)\s+[\w.<>\[\]]+.*[;{]"
    r"|namespace\s+[\w.]+\s*[;{]?|try\s*\{?|finally\s*\{?|\}\s*(?:catch|finally)\b.*)\s*$")
_CS_LAMBDA = re.compile(r"\)\s*=>|=>\s*[{(]|=>\s*[\w.]+\(")
# a line that is only a lambda (x => x.Name == n; (a, b) => a.Id.CompareTo(b.Id)) and ILDASM member references
_CS_LAMBDA_BARE = re.compile(r"^(?:\w+|\([\w\s,.<>\[\]?]*\))\s*=>\s*\S")
_IL_REF = re.compile(r"^(?:IL_[0-9A-Fa-f]{4}:\s*)?(?:call|callvirt|newobj|ldfld|ldflda|stfld|ldsfld|ldsflda|stsfld|ldftn|"
                     r"ldvirtftn|ldtoken|castclass|isinst)\s+\S.*::\S")
_CS_ATTR = re.compile(r"^\[[A-Za-z_][\w.]*(?:\(.*?\))?\](?:\s*$|\s*\[|\s+(?:public|private|internal|protected|static|extern|"
                      r"\w+(?:<[^>]*>)?\s+\w+\s*[;({=]))")
_CS_MEMBER = re.compile(
    r"^(?:\[.*\]\s*)?(?:public|private|internal|protected)\s+(?:(?:static|abstract|virtual|override|sealed|"
    r"readonly|extern|unsafe|async|partial|new|const)\s+)*(?:[\w.<>\[\],?]+\s+[\w.<>]+\s*[;({=]"
    r"|(?:class|struct|interface|enum|record|delegate)\s+\w+)")
_CS_PROPERTY = re.compile(r"\{\s*get;\s*(?:(?:private\s+|protected\s+)?(?:set|init);\s*)?\}")
# one-line code: loop or branch with its body, a braced block with a statement, Python and other shapes
_C_INLINE = re.compile(r"^(?:else\s+)?(?:if|for|while|switch)\s*\(.*\)\s*[^;]*;\s*\}?\s*$"
                       r"|.*\{[^{}]*;\s*\}\s*;?\s*$")
_PYTHON = re.compile(r"^(?:def\s+\w+\s*\(.*\)\s*(?:->\s*[\w.\[\], ]+)?:"
                     r"|class\s+\w+\s*(?:\(.*\))?:"
                     r"|import\s+[\w.]+(?:\s+as\s+\w+)?\s*$|from\s+[\w.]+\s+import\s+\S"
                     r"|(?:async\s+)?def\s+\w+\s*\(.*\)\s*:.*)")   # no for/while/if/else lines: prose pseudocode stays allowed
_COMMENT = re.compile(r"(?<=[;{}])\s*(?://|#).*$|\s//.*$")
_FENCE = re.compile(r"^\s*(?:```|~~~)")
_HEX_LIT = re.compile(r"(?<![\w$])(?:0[xX]|\$)([0-9A-Fa-f]{1,16})\b|\b([0-9A-Fa-f]{5,16})h\b|"
                      r"(?<![\w.])([0-9A-Fa-f]{6,16})(?![\w.])")
_BYTE = r"(?:0[xX])?[0-9A-Fa-f]{2}"
_BYTE_RUN = re.compile(rf"(?<![\w])(?:{_BYTE}(?:[ ,:\-]+|(?=[ ,]|$))){{{MAX_HEX_BYTES - 1},}}{_BYTE}(?![\w])")
_DECIMAL_LIST = re.compile(r"[1-9]\d?(?:\s*,\s*[1-9]\d?)+")
_LONG_HEX = re.compile(rf"(?<![\w])(?:[0-9A-Fa-f]{{2}}){{{MAX_HEX_BYTES},}}(?![\w])")
_HEX_WORDS = re.compile(rf"(?<![\w])(?:(?=[0-9A-Fa-f]*\d)[0-9A-Fa-f]{{8}}[ ,]+){{{MAX_HEX_BYTES // 4 - 1},}}"
                        r"(?=[0-9A-Fa-f]*\d)[0-9A-Fa-f]{8}(?![\w])")
_BYTE_DEC = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_DEC_RUN = re.compile(rf"(?<![\w.]){_BYTE_DEC}(?:[ ,]+{_BYTE_DEC}){{{MAX_DEC_BYTES - 1},}}(?![\w.])")
_BASE64 = re.compile(r"(?<![\w+/=])[A-Za-z0-9+/]{24,}={0,2}(?![\w+/=])")
# A decimal number is an address only when the words say so ("at 4198656"); a count or size in the image range stays allowed.
_DEC_NUM = re.compile(r"\b(?:at|address|addr|entry|located|lives|pointer|offset\s+from\s+base)\s+(?:is\s+|of\s+)?(?:decimal\s+)?"
                      r"(\d{6,10})(?![\w.,])", re.I)
_POINTER_LIT = re.compile(r"(?<![\w$])0[xX]0{3}[0-9A-Fa-f]{13}\b")   # 64-bit padded user-space pointer


def _preview(line: str) -> str:
    s = " ".join(line.split())
    return s if len(s) <= 60 else s[:57] + "..."


def _err(code: str, n: int, line: str, what: str, how: str) -> str:
    return f"error {code}: line {n} {what} ('{_preview(line)}'). {how}."


def _is_byte_dump(s: str) -> bool:
    """A hex-byte run, unless it is only a comma-separated list of plain decimal numbers (column widths,
    counts): digits only, no leading zero, no 0x. Letters, zero padding or space-only separators stay bytes."""
    for m in _BYTE_RUN.finditer(s):
        if not _DECIMAL_LIST.fullmatch(m.group(0).strip()):
            return True
    return False


# Test vectors (interface facts that let a clean implementation check itself):
#  - a single hex token of 32, 40, 64 or 128 digits on a line with a digest word
#  - a line that starts with "vector:" and holds only name=<hex> pairs, each up to 64 bytes:
#        vector: in=616263 out=900150983cd24fb0d6963f7d28e17f72
_DIGEST_WORD = re.compile(r"\b(?:md[245]|sha-?(?:1|224|256|384|512)|hash|digest|checksum|hmac|fingerprint)\b", re.I)
_DIGEST_TOKEN = re.compile(r"(?<![\w])(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{128})(?![\w])")
_VECTOR = re.compile(r"^vector:(?:\s+[A-Za-z][\w-]*=(?:[0-9A-Fa-f]{2}){0,64})+$")
_VECTOR_VALUE = re.compile(r"=(?:[0-9A-Fa-f]{2}){0,64}(?=\s|$)")


def _byte_view(s: str) -> str:
    """The line as the byte-run checks see it: test-vector values and digests next to a digest word removed.
    The address checks still run on the whole line."""
    if _VECTOR.match(s):
        return _VECTOR_VALUE.sub("=", s)
    if _DIGEST_WORD.search(s):
        return _DIGEST_TOKEN.sub("", s)
    return s


def _is_base64(s: str) -> bool:
    """A long base64-looking token: mixed case and digits, and either a base64 symbol or 40+ characters."""
    for m in _BASE64.finditer(s):
        t = m.group(0)
        if (re.search(r"[a-z]", t) and re.search(r"[A-Z]", t) and re.search(r"\d", t)
                and (re.search(r"[+/=]", t) or len(t) >= 40)):
            return True
    return False


def _is_decimal_dump(s: str) -> bool:
    return any(not _DECIMAL_LIST.fullmatch(m.group(0).strip()) for m in _DEC_RUN.finditer(s))


def _strong_forms(s: str) -> list[str]:
    """Forms of a line where code can hide: inline code (backticks), a table row (cells), a trailing comment."""
    t = _COMMENT.sub("", s.replace("`", "")).strip()
    forms = [t] if t != s else []
    if "|" in t:
        forms += [c.strip() for c in t.strip("|").split("|") if c.strip()]
    return forms


def image_ranges(bases: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """[(image_base, highest_known_address)] -> half-open ranges widened by ADDRESS_SLACK."""
    return [(b, max(top, b) + ADDRESS_SLACK) for b, top in bases if b]


def _in_ranges(v: int, ranges: list[tuple[int, int]]) -> bool:
    return any(lo <= v < hi for lo, hi in ranges)


def check_text(text: str, ranges: list[tuple[int, int]] | None = None) -> str | None:
    """``check`` for a free paragraph on one line (the project purpose): the whole text, then each
    sentence or statement alone, so that code in the middle of a paragraph is seen."""
    err = check(text, ranges)
    if err:
        return err
    for part in re.split(r"(?<=[.;!?])\s+", text):
        err = check(part, ranges)
        if err:
            return err
    return None


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
                          (_C_DECL, "is a declaration"), (_PASCAL, "is a Pascal statement"),
                          (_IL_LABEL, "is an IL line"), (_IL_OP, "is an IL line"),
                          (_IL_DIRECTIVE, "is an IL directive"), (_CS_STMT, "is a C# statement"),
                          (_CS_LAMBDA, "contains a C# lambda"), (_CS_LAMBDA_BARE, "is a C# lambda expression"),
                          (_IL_REF, "is an IL member reference"), (_CS_ATTR, "is a C# attribute line"),
                          (_CS_MEMBER, "is a C# declaration"), (_CS_PROPERTY, "is a C# property")):
            if (pat.search(s) if pat in (_IL_LABEL, _CS_LAMBDA, _CS_PROPERTY) else pat.match(s)):
                return _err("spec_has_code", n, line, what,
                            "allowed: prose and field/offset/size/meaning tables")
        for form in (s, *_strong_forms(s)):
            for pat, what in ((_C_ASSIGN, "is an assignment statement"), (_C_CALL, "is a call or return statement"),
                              (_C_INLINE, "is a one-line code block"), (_PYTHON, "is a Python statement")):
                if pat.match(form):
                    return _err("spec_has_code", n, line, what,
                                "allowed: prose and field/offset/size/meaning tables")
        b = _byte_view(s)
        if _is_byte_dump(b) or _LONG_HEX.search(b) or _HEX_WORDS.search(b) or _is_decimal_dump(b) or _is_base64(b):
            return _err("spec_has_bytes", n, line,
                        f"carries a run of {MAX_HEX_BYTES} or more hex bytes",
                        "allowed: the byte layout as fields, not dumped bytes")
        if _POINTER_LIT.search(s):
            return _err("spec_has_address", n, line, "carries a pointer-sized hex literal",
                        "allowed: the thing by role, no address")
        for m in _DEC_NUM.finditer(s):
            if _in_ranges(int(m.group(1)), ranges):
                return _err("spec_has_address", n, line, "carries a decimal address inside a binary's image",
                            "allowed: the thing by role, no address")
        for m in _HEX_LIT.finditer(s):
            digits = m.group(1) or m.group(2) or m.group(3)
            if m.group(3) and len(digits) != 8 and not re.search("[A-Fa-f]", digits):
                continue          # a plain decimal number, not an address
            if digits and _in_ranges(int(digits, 16), ranges):
                return _err("spec_has_address", n, line, "carries an address inside a binary's image",
                            "allowed: the thing by role, no address")
    return None
