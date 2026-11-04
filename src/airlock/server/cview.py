"""Presentation of decompiled C for the `function` tool (DESIGN.md sections 7.1, 7.4).

Pure text functions; the cached ``decomp.c_text`` is never modified. Call annotation
runs on the raw text first (it uses char offsets); everything here works on lines.
"""
from __future__ import annotations

import re

MAX_LOCALS_SHOWN_CHARS = 170
LOCALS_THRESHOLD = 6
COND_CHARS = 60
OUTLINE_DEFAULT_DEPTH = 2      # nesting levels shown by default: 0, 1 and 2
OUTLINE_MAX_DEPTH = 4
SINGLE_CHARS = 90              # brace-less control lines (`if (c) goto X;`)
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
_LABEL = re.compile(r"^([A-Za-z_]\w*)\s*:\s*$")
_NOT_LABEL = frozenset({"default", "public", "private", "protected"})
_GOTO = re.compile(r"\bgoto\s+([A-Za-z_]\w*)\s*;")
_DO_END = re.compile(r"^\}\s*while\s*(\(.*\))\s*;?\s*$")


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


def outline_lines(lines: list[str], header: str, depth_limit: int = OUTLINE_DEFAULT_DEPTH) -> list[str]:
    """Outline of (reduced) C `lines`: header, signature, control skeleton, callees, strings.

    Line numbers are 1-based indexes into `lines`. Control items down to nesting level
    `depth_limit` (0 = top level): blocks as `La-Lb text (N lines)`, brace-less control
    statements as one `Ln if (c) goto X` line, `do … while (c)` with its condition, and
    `LAB_x:` labels (jump targets) with their line and goto count.
    """
    depth_limit = max(0, min(depth_limit, OUTLINE_MAX_DEPTH))
    ob = _body_start(lines)
    sig = (" ".join(x.strip() for x in lines[:ob + 1] if x.strip()).rstrip("{").rstrip()
           if ob >= 0 else (lines[0].strip() if lines else ""))
    out = [header, _trunc(sig, 300)]
    depth = 0
    stack: list[dict] = []
    ctrl: list[dict] = []
    calls: dict[str, list] = {}
    strs: dict[str, list] = {}
    gotos: dict[str, int] = {}
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
        for gm in _GOTO.finditer(st):
            gotos[gm.group(1)] = gotos.get(gm.group(1), 0) + 1
        lm = _LABEL.match(st)
        if km and not (km.group(1) == "while" and st.startswith("}")):
            block = st.endswith("{")
            if not block and km.group(1) == "do":
                km = None
        if km and not (km.group(1) == "while" and st.startswith("}")):
            rec = {"line": no, "kw": km.group(1), "level": level, "end": None, "cases": [],
                   "text": re.sub(r"^\}\s*", "", raw.strip()).rstrip("{").rstrip(),
                   "block": block, "single": not block}
            if level <= depth_limit:
                ctrl.append(rec)
        elif lm and lm.group(1) not in _NOT_LABEL and not _CASE.match(st):
            ctrl.append({"line": no, "kw": "label", "level": level, "end": None, "cases": [],
                         "text": lm.group(1) + ":", "block": False, "single": True})
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
                    done = stack.pop()
                    done["end"] = no
                    dm = _DO_END.match(raw.strip()) if done["kw"] == "do" else None
                    if dm:
                        done["text"] = f"do … while {dm.group(1)}"
    ctl = ["control:"]
    for r in ctrl:
        rng = f"L{r['line']}-L{r['end']}" if r["end"] else f"L{r['line']}"
        if r["kw"] == "label":
            n = gotos.get(r["text"][:-1], 0)
            txt = r["text"] + (f" ({n} gotos)" if n > 1 else " (1 goto)" if n else "")
        elif r["single"]:
            txt = _trunc(r["text"].rstrip(";"), SINGLE_CHARS)
        else:
            txt = _trunc(r["text"], COND_CHARS)
            if r["end"]:
                txt += f" ({r['end'] - r['line'] + 1} lines)"
        ctl.append(f"  {rng} {'  ' * r['level']}{txt}")
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


# ── assembly ───────────────────────────────────────────────────────────────────

ASM_MAX_NOTE = 80


def format_asm(rows: list[list], psize: int, truncated_total: int | None = None) -> list[str]:
    """Lines for `function view=asm` from worker `disassemble` rows
    [addr, length, text, note, label, block].

    `0x00401000  PUSH EBP  ; → Name`. A jump target gets its own `LAB_x:` line before the
    instruction; a basic block that starts without a label (after a branch or return) is
    not marked, the line before it is the branch."""
    out: list[str] = []
    w = psize * 2
    for addr, _length, text, note, label, _block in rows:
        if label:
            out.append(f"{label}:")
        line = f"0x{addr:0{w}x}  {text}"
        if note:
            line += f"  ; → {_trunc(note, ASM_MAX_NOTE)}"
        out.append(line)
    if truncated_total is not None:
        out.append(f"; … truncated at {len(rows)} of {truncated_total} instructions")
    return out
