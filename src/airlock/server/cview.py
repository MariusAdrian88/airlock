"""Presentation of decompiled C for the `function` tool (DESIGN.md sections 7.1, 7.4).

Pure text functions; the cached ``decomp.c_text`` is never modified. Call annotation
runs on the raw text first (it uses char offsets); everything here works on lines.
"""
from __future__ import annotations

import re

MAX_LOCALS_SHOWN_CHARS = 170
LOCALS_THRESHOLD = 6
COND_CHARS = 60
OUTLINE_MAX_LEVEL = 1          # nesting levels shown: 0 (top) and 1
OUTLINE_CAP = 25               # max callee / string lines

_DECL = re.compile(r"^\s+(?!(?:return|goto|break|continue|else|case|default)\b)"
                  r"(?:[A-Za-z_][\w:<>]*[\s\*]+)+[A-Za-z_]\w*\s*(?:\[[^\]]*\]\s*)*;\s*$")
_DECL_NAME = re.compile(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*;\s*$")
_STR = re.compile(r'"((?:[^"\\]|\\.)*)"')
_CHR = re.compile(r"'(?:[^'\\]|\\.)'")
_CALL = re.compile(r"\b([A-Za-z_~][\w:~]*)(/\*0x[0-9a-fA-F]+\*/)?\s*\(")
_NOT_CALLS = frozenset({"if", "while", "for", "switch", "return", "sizeof", "else", "do", "case"})
_INTRINSIC = re.compile(r"^(CONCAT\d+|SUB\d+|ZEXT\d+|SEXT\d+|CARRY\d+|SBORROW\d+|SCARRY\d+|"
                        r"POPCOUNT|LZCOUNT|BADSPACEBASE|PIECE\d*|INT2FLOAT|FLOAT2FLOAT|"
                        r"halt_baddata|swi|CALLOTHER)$")
_KEYWORD = re.compile(r"^(?:\}\s*)?(?:else\s+)?(if|switch|for|while|do)\b")
_CASE = re.compile(r"^case\s+(.+?)\s*:\s*$")


# ── noise reduction ────────────────────────────────────────────────────────────

def strip_warnings(lines: list[str]) -> list[str]:
    """Drop `/* WARNING ... */` lines (multi-line comments too) and the blank line after each."""
    out: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        if lines[i].strip().startswith("/* WARNING"):
            while i < n and "*/" not in lines[i]:
                i += 1
            i += 1
            if i < n and not lines[i].strip():
                i += 1
            continue
        out.append(lines[i])
        i += 1
    return out


def _body_start(lines: list[str]) -> int:
    """Index of the line holding the function's opening brace, or -1."""
    for i, ln in enumerate(lines):
        r = ln.rstrip()
        if r == "{" or (r.endswith("{") and not ln.startswith((" ", "\t"))):
            return i
    return -1


def collapse_locals(lines: list[str]) -> list[str]:
    ob = _body_start(lines)
    if ob < 0:
        return lines
    j = ob + 1
    while j < len(lines) and _DECL.match(lines[j]) and "=" not in lines[j]:
        j += 1
    decls = lines[ob + 1:j]
    if len(decls) <= LOCALS_THRESHOLD:
        return lines
    names = []
    for d in decls:
        m = _DECL_NAME.search(d)
        names.append(m.group(1) if m else d.strip().rstrip(";"))
    shown, used = [], 0
    for nm in names:
        add = len(nm) + 2
        if shown and used + add > MAX_LOCALS_SHOWN_CHARS:
            break
        shown.append(nm)
        used += add
    more = len(names) - len(shown)
    lst = ", ".join(shown) + (f", +{more} more" if more else "")
    line = f"  // {len(names)} locals: {lst} (detail=full shows types)"
    return lines[:ob + 1] + [line] + lines[j:]


def reduce_c(text: str, detail: str = "brief") -> str:
    """`full` returns the text unchanged; `brief` strips warnings and collapses locals."""
    if detail == "full":
        return text
    return "\n".join(collapse_locals(strip_warnings(text.split("\n"))))


# ── outline ────────────────────────────────────────────────────────────────────

def _scrub(line: str) -> str:
    """Line with string/char literals blanked, so braces and keywords inside are ignored."""
    return _CHR.sub("' '", _STR.sub('""', line))


def _parse_int(s: str) -> int | None:
    s = s.strip()
    try:
        return int(s, 16) if s.lower().lstrip("-").startswith("0x") else int(s)
    except ValueError:
        return None


def _fmt_int(v: int) -> str:
    return hex(v) if v > 9 else str(v)


def compress_cases(labels: list[str], limit: int = 90) -> str:
    nums: list[int] = []
    other: list[str] = []
    has_default = False
    for lb in labels:
        if lb == "default":
            has_default = True
            continue
        v = _parse_int(lb)
        if v is None:
            other.append(lb)
        else:
            nums.append(v)
    nums = sorted(set(nums))
    parts: list[str] = []
    i = 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        if j - i >= 2:
            parts.append(f"{_fmt_int(nums[i])}..{_fmt_int(nums[j])}")
        else:
            parts.extend(_fmt_int(x) for x in nums[i:j + 1])
        i = j + 1
    parts.extend(other)
    if has_default:
        parts.append("default")
    s = ",".join(parts)
    if len(s) > limit:
        s = s[:limit].rsplit(",", 1)[0] + ",..."
    return s


def _trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 3] + "..."


def outline_lines(lines: list[str], header: str) -> list[str]:
    """Outline of (reduced) C `lines`: header, signature, control skeleton, callees, strings.

    Line numbers are 1-based indexes into `lines`.
    """
    ob = _body_start(lines)
    sig = (" ".join(x.strip() for x in lines[:ob + 1] if x.strip()).rstrip("{").rstrip()
           if ob >= 0 else (lines[0].strip() if lines else ""))
    out = [header, _trunc(sig, 300)]
    depth = 0
    stack: list[dict] = []
    ctrl: list[dict] = []
    calls: dict[str, list] = {}
    strs: dict[str, list] = {}
    for idx, raw in enumerate(lines):
        no = idx + 1
        s = _scrub(raw)
        if idx <= ob:
            if idx == ob:
                depth += s.count("{") - s.count("}")
            continue
        st = s.strip()
        if st.startswith("//"):
            continue
        lead = len(st) - len(st.lstrip("}"))
        level = max(depth - lead - 1, 0)
        km = _KEYWORD.match(st)
        rec = None
        if km and not (km.group(1) == "while" and st.startswith("}")):
            rec = {"line": no, "kw": km.group(1), "level": level, "end": None, "cases": [],
                   "text": re.sub(r"^\}\s*", "", raw.strip()).rstrip("{").rstrip(),
                   "block": st.endswith("{")}
            if level <= OUTLINE_MAX_LEVEL:
                ctrl.append(rec)
        elif stack and stack[-1]["kw"] == "switch" and depth == stack[-1]["open"]:
            cm = _CASE.match(st)
            if cm:
                stack[-1]["cases"].append(cm.group(1))
            elif st.startswith("default"):
                stack[-1]["cases"].append("default")
        for m in _CALL.finditer(s):
            nm = m.group(1)
            if nm in _NOT_CALLS or _INTRINSIC.match(nm):
                continue
            c = calls.setdefault(nm, [no, 0, m.group(2)])
            c[1] += 1
            if not c[2] and m.group(2):
                c[2] = m.group(2)
        for m in _STR.finditer(raw):
            if m.group(1):
                e = strs.setdefault(m.group(1), [no, 0])
                e[1] += 1
        opened = False
        for ch in s:
            if ch == "{":
                depth += 1
                if rec is not None and rec["block"] and not opened:
                    rec["open"] = depth
                    stack.append(rec)
                    opened = True
            elif ch == "}":
                depth -= 1
                while stack and stack[-1]["open"] > depth:
                    stack.pop()["end"] = no
    ctl = ["control:"]
    for r in ctrl:
        rng = f"L{r['line']}-L{r['end']}" if r["end"] else f"L{r['line']}"
        ctl.append(f"  {rng} {'  ' * r['level']}{_trunc(r['text'], COND_CHARS)}")
        if r["kw"] == "switch" and r["cases"]:
            ctl.append(f"  {rng} {'  ' * (r['level'] + 1)}case "
                       f"{compress_cases(r['cases'])} ({len(r['cases'])} cases)")
    if len(ctl) > 1:
        out += ctl
    if calls:
        out.append("calls:")
        ranked = sorted(calls.items(), key=lambda kv: (-kv[1][1], kv[1][0]))
        for nm, (first, cnt, addr) in ranked[:OUTLINE_CAP]:
            a = f" {addr[2:-2]}" if addr else ""
            out.append(f"  {nm}{a} x{cnt} L{first}")
        if len(ranked) > OUTLINE_CAP:
            out.append(f"  +{len(ranked) - OUTLINE_CAP} more callees")
    if strs:
        out.append("strings:")
        ranked_s = sorted(strs.items(), key=lambda kv: kv[1][0])
        for txt, (first, cnt) in ranked_s[:OUTLINE_CAP]:
            out.append(f'  L{first} "{_trunc(txt, 50)}"' + (f" x{cnt}" if cnt > 1 else ""))
        if len(ranked_s) > OUTLINE_CAP:
            out.append(f"  +{len(ranked_s) - OUTLINE_CAP} more strings")
    return out
