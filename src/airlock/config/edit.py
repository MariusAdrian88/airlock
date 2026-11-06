"""Key-preserving edits of a JSONC config text.

A small scanner finds the top-level members of the file (so braces, quotes and
`//` inside strings and comments are never mistaken for syntax). Edits touch
only the span they change: comments, order and layout of the rest stay.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass
class Tok:
    kind: str   # str | lc | bc | p | w
    start: int
    end: int


@dataclass
class Member:
    key: str
    key_start: int
    val_start: int
    val_end: int
    comma_end: int    # end of the comma after the value, or val_end if none


def scan(text: str) -> list[Tok]:
    toks: list[Tok] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            toks.append(Tok("lc", i, j))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            toks.append(Tok("bc", i, j))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            toks.append(Tok("str", i, min(j + 1, n)))
            i = j + 1
        elif c in "{}[],:":
            toks.append(Tok("p", i, i + 1))
            i += 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "{}[],:\"'" \
                    and not text.startswith("//", j) and not text.startswith("/*", j):
                j += 1
            toks.append(Tok("w", i, max(j, i + 1)))
            i = max(j, i + 1)
    return toks


def _sig(toks: list[Tok]) -> list[Tok]:
    return [t for t in toks if t.kind not in ("lc", "bc")]


def _skip_value(sig: list[Tok], i: int, text: str) -> int:
    """Index after the value that starts at sig[i]."""
    t = sig[i]
    if t.kind == "p" and text[t.start] in "{[":
        depth = 0
        while i < len(sig):
            s = sig[i]
            if s.kind == "p":
                ch = text[s.start]
                if ch in "{[":
                    depth += 1
                elif ch in "}]":
                    depth -= 1
                    if depth == 0:
                        return i + 1
            i += 1
        raise ValueError("unbalanced brackets")
    return i + 1


def _unq(text: str, t: Tok) -> str:
    s = text[t.start:t.end]
    return s[1:-1] if t.kind == "str" else s


def top_level(text: str) -> tuple[int, int, list[Member]]:
    """(index of the opening brace, index of the closing brace, members)."""
    sig = _sig(scan(text))
    if not sig or text[sig[0].start] != "{":
        raise ValueError("top level must be an object")
    members: list[Member] = []
    i = 1
    while i < len(sig):
        t = sig[i]
        if t.kind == "p" and text[t.start] == "}":
            return sig[0].start, t.start, members
        if t.kind == "p" and text[t.start] == ",":
            i += 1
            continue
        if i + 2 >= len(sig) or text[sig[i + 1].start] != ":":
            raise ValueError("cannot parse a member")
        j = _skip_value(sig, i + 2, text)
        val_start, val_end = sig[i + 2].start, sig[j - 1].end
        comma_end = val_end
        if j < len(sig) and sig[j].kind == "p" and text[sig[j].start] == ",":
            comma_end = sig[j].end
            j += 1
        members.append(Member(_unq(text, t), t.start, val_start, val_end, comma_end))
        i = j
    raise ValueError("missing closing brace")


def _line_start(text: str, pos: int) -> int:
    return text.rfind("\n", 0, pos) + 1


def _indent_of(text: str, members: list[Member]) -> str:
    if members:
        ls = _line_start(text, members[0].key_start)
        ind = text[ls:members[0].key_start]
        if ind.strip() == "":           # not the brace of a one-line object
            return ind
    return "  "


def commented_keys(text: str) -> set[str]:
    """Keys that appear only as `// "key": ...` at the top-level indentation."""
    _, _, members = top_level(text)
    ind = re.escape(_indent_of(text, members) or "  ")
    return set(re.findall(rf'^{ind}//[ \t]*"(\w+)"[ \t]*:', text, re.MULTILINE))


def present_keys(text: str) -> set[str]:
    _, _, members = top_level(text)
    return {m.key for m in members} | commented_keys(text)


def literal(value: Any, indent: str = "  ") -> str:
    if isinstance(value, list) and len(value) > 3:
        inner = "".join(f"\n{indent}  {json.dumps(v)}," for v in value)
        return f"[{inner}\n{indent}]"
    return json.dumps(value, ensure_ascii=False)


def inject(text: str, blocks: list[str]) -> str:
    """Insert text blocks before the closing brace; add the comma the last member needs."""
    if not blocks:
        return text
    open_, close, members = top_level(text)
    body = "\n\n".join(blocks)
    ls = _line_start(text, close)
    if text[ls:close].strip() == "":
        out = text[:ls] + "\n" + body + "\n" + text[ls:]
        pos = ls
    else:
        out = text[:close] + "\n" + body + "\n" + text[close:]
        pos = close
    if members and members[-1].comma_end == members[-1].val_end:
        p = members[-1].val_end
        out = out[:p] + "," + out[p:]
    return out


def active_member(text: str, key: str) -> Member | None:
    _, _, members = top_level(text)
    return next((m for m in members if m.key == key), None)


def set_key(text: str, key: str, value: Any) -> str:
    """Set key to value. Replaces an active value, uncomments a commented one,
    or appends the key before the closing brace."""
    _, _, members = top_level(text)
    ind = _indent_of(text, members) or "  "
    lit = literal(value, ind)
    m = next((x for x in members if x.key == key), None)
    if m is not None:
        return text[:m.val_start] + lit + text[m.val_end:]
    pat = re.compile(rf'^({re.escape(ind)})//[ \t]*"{re.escape(key)}"[ \t]*:[^\n]*$', re.MULTILINE)
    mm = pat.search(text)
    if mm:
        return text[:mm.start()] + f'{ind}"{key}": {lit},' + text[mm.end():]
    return inject(text, [f'{ind}"{key}": {lit},'])


def unset_key(text: str, key: str, default: Any) -> str:
    """Return an active key to its commented default."""
    _, _, members = top_level(text)
    m = next((x for x in members if x.key == key), None)
    if m is None:
        return text
    return text[:m.key_start] + f'// "{key}": {json.dumps(default)},' + text[m.comma_end:]


def comment_out(text: str, key: str, note: str) -> str:
    """Comment out an active top-level member, line by line, behind a note.

    The marker `//|` keeps the old text out of the "commented key" detection.
    """
    _, _, members = top_level(text)
    m = next((x for x in members if x.key == key), None)
    if m is None:
        return text
    ls = _line_start(text, m.key_start)
    end = m.comma_end
    nl = text.find("\n", end)
    # keep a trailing comment on the last line inside the commented block
    end = len(text) if nl < 0 else nl
    ind = text[ls:m.key_start]
    old = text[ls:end].split("\n")
    out = [f"{ind}// {note}"] + [f"{ind}//| {ln[len(ind):] if ln.startswith(ind) else ln.lstrip()}"
                                 for ln in old]
    return text[:ls] + "\n".join(out) + text[end:]
