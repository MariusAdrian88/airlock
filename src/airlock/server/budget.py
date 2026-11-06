"""Token budgets, line-boundary truncation and in-memory cursors (DESIGN.md section 7)."""
from __future__ import annotations

import json
import math
import secrets
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

CHARS_PER_TOKEN = {"code": 3.5, "prose": 4.0}
MAX_CURSORS = 256
# Args that do not change which result set a cursor belongs to.
_IGNORED_ARGS = frozenset({"cursor", "budget"})


class CursorError(Exception):
    """Carries a ready-to-return one-line error string in project format (.message)."""

    def __init__(self, code: str, what: str, action: str = "") -> None:
        self.code = code
        self.message = f"error {code}: {what}." + (f" {action}." if action else "")
        super().__init__(self.message)


def estimate_tokens(text: str, kind: str = "prose") -> int:
    """Conservative token estimate: chars/3.5 for code, chars/4 for prose."""
    per = CHARS_PER_TOKEN.get(kind)
    if per is None:
        raise ValueError(f"unknown kind {kind!r} (use 'code' or 'prose')")
    return math.ceil(len(text) / per) if text else 0


def normalize_args(tool: str, args: dict[str, Any] | None) -> str:
    """Stable key: tool plus sorted JSON of args, minus cursor/budget and None values."""
    clean = {k: v for k, v in (args or {}).items() if k not in _IGNORED_ARGS and v is not None}
    return tool + ":" + json.dumps(clean, sort_keys=True, separators=(",", ":"), default=str)


@dataclass
class Cursor:
    id: str
    key: str
    lines: list[str] | None = None   # remaining lines (list-style tools)
    offset: int = 0                  # char offset into an external text (function tool)
    identity: tuple | None = None    # e.g. (binary, entry, fn_version)


class CursorStore:
    """Bounded LRU map of cursor id -> Cursor. Thread-safe."""

    def __init__(self, max_entries: int = MAX_CURSORS) -> None:
        self.max_entries = max_entries
        self._items: OrderedDict[str, Cursor] = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._items)

    def _put(self, **kw: Any) -> str:
        with self._lock:
            while True:
                cid = "c_" + secrets.token_hex(2)
                if cid not in self._items:
                    break
            self._items[cid] = Cursor(id=cid, **kw)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)
            return cid

    def create_lines(self, tool: str, args: dict[str, Any] | None, lines: Sequence[str]) -> str:
        return self._put(key=normalize_args(tool, args), lines=list(lines))

    def create_text(self, tool: str, args: dict[str, Any] | None, offset: int,
                    identity: tuple | None = None) -> str:
        return self._put(key=normalize_args(tool, args), offset=offset, identity=identity)

    def get(self, cid: str | None, tool: str, args: dict[str, Any] | None = None,
            identity: tuple | None = None) -> Cursor:
        """Look up a cursor; raises CursorError (use .message) when unknown, mismatched or stale.

        If `args` is given they must match the ones the cursor was issued for.
        """
        redo = ""     # the call without cursor is the only way on; the error says why
        with self._lock:
            cur = self._items.get(cid or "")
            if cur is None:
                raise CursorError("bad_cursor", f"cursor '{cid}' is unknown or expired", redo)
            if not cur.key.startswith(tool + ":"):
                raise CursorError("bad_cursor", f"cursor '{cid}' belongs to another tool", redo)
            if args is not None and cur.key != normalize_args(tool, args):
                raise CursorError("bad_cursor", f"cursor '{cid}' was issued for different arguments", redo)
            if identity is not None and cur.identity is not None and cur.identity != identity:
                raise CursorError("stale_cursor",
                                  f"cursor '{cid}' is stale, the function changed since it was issued", redo)
            self._items.move_to_end(cur.id)
            return cur

    def drop(self, cid: str) -> None:
        with self._lock:
            self._items.pop(cid, None)


STORE = CursorStore()


def footer(n_more: int, cursor_id: str) -> str:
    return f"… {n_more} more lines. cursor={cursor_id}"


def _cost(line: str, kind: str) -> int:
    return estimate_tokens(line + "\n", kind)


def _cut(lines: Sequence[str], budget: int, kind: str) -> int:
    """Number of leading lines that fit while reserving room for the footer; at least 1."""
    avail = budget - estimate_tokens(footer(99999, "c_0000") + "\n", "prose")
    used = 0
    n = 0
    for ln in lines:
        c = _cost(ln, kind)
        if n > 0 and used + c > avail:
            break
        used += c
        n += 1
    return n


def _split(lines: Sequence[str], budget: int, kind: str,
           max_lines: int = 0) -> tuple[list[str], int]:
    if sum(_cost(ln, kind) for ln in lines) <= budget and not 0 < max_lines < len(lines):
        return list(lines), 0
    n = _cut(lines, budget, kind)
    if max_lines > 0:
        n = min(n, max_lines)
    return list(lines[:n]), len(lines) - n


def fit_lines(lines: Iterable[str], budget: int, kind: str = "prose", *,
              tool: str = "", args: dict[str, Any] | None = None,
              store: CursorStore | None = None, max_lines: int = 0) -> tuple[str, int]:
    """Cut `lines` at a line boundary to fit `budget` tokens (and `max_lines` if > 0).

    Returns (text, remaining_line_count). When lines remain, the text ends with
    `… N more lines. cursor=<id>` and the rest is stored under that cursor.
    At least one line is always emitted so a resumed cursor always progresses.
    """
    seq = list(lines)
    head, rem = _split(seq, budget, kind, max_lines)
    if not rem:
        return "\n".join(head), 0
    cid = (STORE if store is None else store).create_lines(tool, args, seq[len(head):])
    return "\n".join(head + [footer(rem, cid)]), rem


def fit_text(text: str, budget: int, kind: str = "code", *, offset: int = 0,
             tool: str = "", args: dict[str, Any] | None = None,
             identity: tuple | None = None,
             store: CursorStore | None = None) -> tuple[str, int]:
    """Like fit_lines for one big text (decomp.c_text), starting at char `offset`.

    The cursor stores only (next offset, identity); on resume the caller re-reads the
    text, validates with CursorStore.get(..., identity=...) and passes cursor.offset.
    Returns (text, remaining_line_count).
    """
    head, rem = _split(text[offset:].split("\n"), budget, kind)
    if not rem:
        return "\n".join(head), 0
    next_off = offset + len("\n".join(head)) + 1
    cid = (STORE if store is None else store).create_text(tool, args, next_off, identity)
    return "\n".join(head + [footer(rem, cid)]), rem


def resume_lines(cursor_id: str, budget: int, kind: str = "prose", *, tool: str,
                 args: dict[str, Any] | None = None,
                 store: CursorStore | None = None, max_lines: int = 0) -> tuple[str, int]:
    """Continue a list-style cursor (validates it, consumes it, may issue a new one).

    Raises CursorError; return e.message to the agent.
    """
    st = STORE if store is None else store
    cur = st.get(cursor_id, tool, args)
    st.drop(cursor_id)
    return fit_lines(cur.lines or [], budget, kind, tool=tool, args=args, store=st,
                     max_lines=max_lines)
