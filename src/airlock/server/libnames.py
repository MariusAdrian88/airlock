"""Library names at call sites: a function that is still ``FUN_xxxxxxxx`` in the Ghidra project but has
exactly one IDR / sigdb / WARP name (``idr_hits`` meta, see ``idr.py``) is shown under that name in the
output of the code and name tools (DESIGN 6.9, "display names").

Display only: the Ghidra project and the index keep ``FUN_xxxxxxxx`` (a rename by user or agent is a
real name and the token is gone, so it always wins). Nothing to undo; a new ``IDR_VERSION`` recomputes
the hits and the display follows. A token is replaced only when its name is unique: one name for the
function (no ``|`` list, no ``(+N)``) and no other function of the binary with the same name. A call
``FUN_x(`` becomes ``Unit.Proc/*0x..*/(`` so the address stays visible, like in ``annotate_calls``.
"""

from __future__ import annotations

import functools
import re

from airlock.server import idr

_TOKEN = re.compile(r"(?<![A-Za-z0-9_])((?:thunk_)?)FUN_([0-9a-fA-F]{6,16})\b")
_BAD = re.compile(r"[\s|*]|\(\+\d+\)")

# Tools whose output prints code or names functions (read tools only; never the writers).
RELABEL_TOOLS = frozenset({
    "outline", "search", "function", "xrefs", "callgraph", "strings", "vtable", "mfc_message_maps",
    "switch_tables", "trace_values", "constants", "function_map", "cluster_label", "path", "overview",
    "features", "feature", "record_guess", "delphi_classes", "delphi_events", "rtti_classes",
})


@functools.lru_cache(maxsize=16)
def _unique(text: str) -> dict[int, str]:
    parsed = {}
    for a, n in idr._parse_hits(text).items():
        alts = n.split(" | ")
        parsed[a] = alts[-1] if len({x.casefold() for x in alts}) == 1 else n      # FPC_X | fpc_x: one name
    count: dict[str, int] = {}
    for names in parsed.values():
        count[names] = count.get(names, 0) + 1
    return {a: n for a, n in parsed.items() if n and not _BAD.search(n) and count[n] == 1}


def labels(store, binary_id: int) -> dict[int, str]:
    """{entry: name} of the functions with one unique library name."""
    return _unique(store.get_meta(f"{idr.HITS_META}:{binary_id}") or "")


def relabel(text: str, per_binary: list[tuple[dict[int, str], int]]) -> str:
    """Replace ``FUN_x`` tokens by their library name. ``per_binary``: ``(labels, pointer size)`` of every
    binary in scope; an address that two binaries label differently is left alone."""
    if "FUN_" not in text or not any(lb for lb, _ in per_binary):
        return text

    def sub(m: re.Match) -> str:
        addr = int(m.group(2), 16)
        found = {(lb[addr], ps) for lb, ps in per_binary if addr in lb}
        if len({n for n, _ in found}) != 1:
            return m.group(0)
        name, psize = next(iter(found))
        out = m.group(1) + name
        if m.string[m.end():m.end() + 1] == "(":
            out += f"/*0x{addr:0{psize * 2}x}*/"
        return out

    return _TOKEN.sub(sub, text)


class Display:
    """The display transform of one tool call: relabels with the hits of the ONE binary the call is bound
    to (``Bound`` objects made during the call, see ``registry.note_bound``). A call bound to several
    binaries, or to none in a project with several, is not relabelled: an address means a function only
    inside its own binary. Never raises."""

    def __init__(self, ctx, project: str | None, bounds: list):
        self.ctx, self.project, self.bounds = ctx, project, bounds
        self._key: object = None
        self._per: list[tuple[dict[int, str], int]] = []

    def _resolve(self) -> list[tuple[dict[int, str], int]]:
        ids = {(id(st), b.id): (st, b) for st, b in self.bounds}
        if len(ids) > 1:
            return []
        if ids:
            st, b = next(iter(ids.values()))
        else:
            ix = self.ctx.indexer
            st = ix.store(ix.resolve_project(self.project))
            every = st.list_binaries()
            if len(every) != 1:
                return []
            b = every[0]
        return [(labels(st, b.id), b.pointer_size or 4)]

    def __call__(self, text: str) -> str:
        if "FUN_" not in text:
            return text
        try:
            key = tuple(sorted((id(st), b.id) for st, b in self.bounds))
            if key != self._key or not self._per:
                self._per, self._key = self._resolve(), key
            return relabel(text, self._per)
        except Exception:  # noqa: BLE001  an extra: the plain output stays
            return text
