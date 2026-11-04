"""Agent notes as text (DESIGN.md sections 4 and 6). Server side, no Ghidra.

Notes live in the ``note`` table keyed by (binary, space, entry); this module formats them for the
``function`` header, ``search kind=note`` and the Ghidra plate-comment mirror.
"""

from __future__ import annotations

import re
import sqlite3

from airlock.index.store import Function, Store

CONFIDENCE = ("low", "medium", "high")
MAX_SUMMARY = 2000
SHOWN_IN_FUNCTION = 5      # newest notes listed above a function's code
LINE_CHARS = 240
MIRROR_LINES = 10          # newest notes mirrored into the plate comment
_WS = re.compile(r"\s+")


def one_line(text: str, limit: int) -> str:
    s = _WS.sub(" ", text).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def normalise_tags(tags: str) -> str:
    """Comma separated, trimmed, spaces inside a tag become '-', duplicates dropped."""
    seen: list[str] = []
    for t in tags.replace(";", ",").split(","):
        t = _WS.sub("-", t.strip())
        if t and t not in seen:
            seen.append(t)
    return ",".join(seen)


def format_note(summary: str, tags: str, confidence: str | None, limit: int = LINE_CHARS) -> str:
    conf = f"[{confidence}] " if confidence else ""
    return f"{conf}{one_line(summary, limit)}" + (f" (tags: {tags})" if tags else "")


def note_text(row: sqlite3.Row, limit: int = LINE_CHARS) -> str:
    return format_note(row["summary"], row["tags"], row["confidence"], limit)


def function_lines(st: Store, fn: Function, limit: int = SHOWN_IN_FUNCTION) -> list[str]:
    """``// note #id ...`` lines for the top of a function view, newest first."""
    rows = st.notes_for(fn.binary_id, fn.space, fn.entry)
    if not rows:
        return []
    shown = list(reversed(rows))[:limit]
    out = [f"// note #{r['id']} {note_text(r)}" for r in shown]
    if len(rows) > len(shown):
        out.append(f"// +{len(rows) - len(shown)} older notes (search kind=note)")
    return out


def mirror_lines(st: Store, fn: Function, pending: str | None = None) -> list[str]:
    """Lines for the Ghidra plate-comment block: the newest notes, oldest first, then `pending` (a
    note not stored yet, already formatted by ``note_text``)."""
    rows = st.notes_for(fn.binary_id, fn.space, fn.entry)
    keep = MIRROR_LINES - (1 if pending else 0)
    out = [f"- {note_text(r, 300)}" for r in rows[-keep:]] if keep > 0 else []
    if pending:
        out.append(f"- {pending}")
    return out
