"""cpp set: rtti_classes, vtable, mfc_message_maps (MSVC RTTI and MFC, parsed from the PE bytes).

Rows come from the derived tables ``rtti_class``, ``vtable_slot`` and ``msgmap_entry`` (server/cpp.py),
filled when a binary is ready and derived here when missing or stale. Output is one item per line,
cut to the token budget with a cursor. Names are hints: nothing is renamed in Ghidra.
"""

from __future__ import annotations

from airlock.server import cpp, peres, uijoin
from airlock.server.budget import CursorError, fit_lines, resume_lines
from airlock.server.context import ServerContext
from airlock.server.registry import tool
from airlock.server.selectors import parse_address
from airlock.server.tools.common import Bound, bind_many, budget_for

DEFAULT_LIMIT = 50
MAX_VTABLES = 8                 # vtables listed for one class name


def _ready(ctx: ServerContext, bd: Bound) -> None:
    art = ctx.indexer.paths(bd.project).artifacts / bd.binary.sha256
    cpp.ensure(bd.store, bd.binary, art)
    try:
        peres.ensure(bd.store, bd.binary, art)          # resource ids for the menu / dialog join
    except Exception:  # noqa: BLE001  an extra
        pass


def _scope(ctx: ServerContext, binary: str) -> tuple[list[Bound], bool] | str:
    got = bind_many(ctx, binary)
    if isinstance(got, str):
        return got
    bounds, _skipped = got
    for bd in bounds:
        _ready(ctx, bd)
    return bounds, len(bounds) > 1


def _page(lines: list[str], bud: int, name: str, args: dict, cursor: str) -> str:
    if cursor:
        try:
            return resume_lines(cursor, bud, "code", tool=name, args=args)[0]
        except CursorError as e:
            return e.message
    return fit_lines(lines, bud, "code", tool=name, args=args)[0]


def _fn_name(bd: Bound, addr: int) -> str:
    fn = bd.store.function_at(bd.binary.id, addr)
    if fn is None:
        return ""
    return fn.qualified_name


def _prefix(bd: Bound, several: bool) -> str:
    return f"{bd.binary.name}!" if several else ""


# ── rtti_classes ───────────────────────────────────────────────────────────

@tool("rtti_classes", "List C++ classes recovered from MSVC RTTI: name, vtable address, slot count, base classes.")
def rtti_classes(ctx: ServerContext, query: str = "", limit: int = DEFAULT_LIMIT, binary: str = "",
                 cursor: str = "", budget: int = 0) -> str:
    if limit < 1:
        return "error bad_args: limit must be at least 1. Fix and retry."
    sc = _scope(ctx, binary)
    if isinstance(sc, str):
        return sc
    bounds, several = sc
    bud = budget_for(ctx, budget)
    args = {"binary": binary, "query": query, "limit": limit}
    if cursor:
        return _page([], bud, "rtti_classes", args, cursor)
    q = query.strip().lower()
    rows: list[tuple[str, str]] = []
    total = 0
    for bd in bounds:
        for r in bd.store.db.execute(
                "SELECT c.name, c.vtable_addr, c.bases, "
                "(SELECT COUNT(*) FROM vtable_slot s WHERE s.binary_id=c.binary_id "
                " AND s.vtable_addr=c.vtable_addr) AS n "
                "FROM rtti_class c WHERE c.binary_id=? ORDER BY c.name, c.vtable_addr", (bd.binary.id,)):
            if q and q not in r["name"].lower():
                continue
            total += 1
            vt = bd.addr(r["vtable_addr"]) if r["vtable_addr"] is not None else "no-vtable"
            line = f"{_prefix(bd, several)}{r['name']} vtable {vt} slots {r['n']}"
            if r["bases"]:
                line += f" bases {r['bases']}"
            rows.append((r["name"], line))
    if not rows:
        have = sum(bd.store.db.execute("SELECT COUNT(*) FROM rtti_class WHERE binary_id=?",
                                       (bd.binary.id,)).fetchone()[0] for bd in bounds)
        if have == 0:
            return "no RTTI classes: the binary has no MSVC RTTI (built without /GR) or no C++ classes."
        return f"no RTTI class matches '{query}' ({have} classes)."
    shown = [ln for _, ln in rows[:limit]]
    if total > limit:
        shown.append(f"… {total - limit} more classes beyond limit={limit}. Raise limit or narrow query.")
    return fit_lines(shown, bud, "code", tool="rtti_classes", args=args)[0]


# ── vtable ─────────────────────────────────────────────────────────────────

def _vtable_lines(bd: Bound, several: bool, vtable: int, name: str, mark: int | None) -> list[str]:
    slots = bd.store.db.execute(
        "SELECT slot, target FROM vtable_slot WHERE binary_id=? AND vtable_addr=? ORDER BY slot",
        (bd.binary.id, vtable)).fetchall()
    out = [f"{_prefix(bd, several)}{name} vtable {bd.addr(vtable)} slots {len(slots)}"]
    for r in slots:
        fn = _fn_name(bd, r["target"])
        arrow = " <-" if mark is not None and r["slot"] == mark else ""
        out.append(f"[{r['slot']}] {bd.addr(r['target'])}{' ' + fn if fn else ''}{arrow}")
    return out


@tool("vtable", "Show the slots of a C++ vtable: index, target address and function name, by class name or address.")
def vtable(ctx: ServerContext, target: str, binary: str = "", cursor: str = "", budget: int = 0) -> str:
    t = target.strip()
    if not t:
        return "error bad_target: target is empty. Pass a class name (see rtti_classes) or an address like 0x00401000."
    sc = _scope(ctx, binary)
    if isinstance(sc, str):
        return sc
    bounds, several = sc
    bud = budget_for(ctx, budget, "function_budget")
    args = {"binary": binary, "target": target}
    if cursor:
        return _page([], bud, "vtable", args, cursor)
    lines: list[str] = []
    addr = parse_address(t)
    if addr is not None:
        for bd in bounds:
            ps = bd.psize
            r = bd.store.db.execute(
                "SELECT s.vtable_addr, MAX(s.slot) AS last FROM vtable_slot s WHERE s.binary_id=? "
                "AND s.vtable_addr<=? GROUP BY s.vtable_addr ORDER BY s.vtable_addr DESC LIMIT 1",
                (bd.binary.id, addr[1])).fetchone()
            if r is None or addr[1] >= r["vtable_addr"] + ps * (r["last"] + 1):
                continue
            nm = bd.store.db.execute(
                "SELECT name FROM rtti_class WHERE binary_id=? AND vtable_addr=? LIMIT 1",
                (bd.binary.id, r["vtable_addr"])).fetchone()
            mark = (addr[1] - r["vtable_addr"]) // ps if addr[1] != r["vtable_addr"] else None
            lines += _vtable_lines(bd, several, r["vtable_addr"], nm["name"] if nm else "?", mark)
        if not lines:
            return (f"error not_found: no vtable at or around {t}. "
                    "Call rtti_classes for the class vtables.")
    else:
        want = t.lower()
        hits: list[tuple[Bound, str, int]] = []
        for bd in bounds:
            for r in bd.store.db.execute(
                    "SELECT name, vtable_addr FROM rtti_class WHERE binary_id=? AND vtable_addr IS NOT NULL "
                    "AND lower(name)=? ORDER BY vtable_addr", (bd.binary.id, want)):
                hits.append((bd, r["name"], r["vtable_addr"]))
        if not hits:
            for bd in bounds:
                for r in bd.store.db.execute(
                        "SELECT name, vtable_addr FROM rtti_class WHERE binary_id=? AND vtable_addr IS NOT NULL "
                        "AND lower(name) LIKE ? ORDER BY name, vtable_addr LIMIT 20",
                        (bd.binary.id, f"%{want}%")):
                    hits.append((bd, r["name"], r["vtable_addr"]))
            names = sorted({n for _, n, _ in hits})
            if len(names) > 1:
                shown = ", ".join(names[:10])
                more = f" (+{len(names) - 10} more)" if len(names) > 10 else ""
                return (f"error ambiguous: '{t}' matches {len(names)} classes: {shown}{more}. "
                        "Retry with the full class name.")
        if not hits:
            return f"error not_found: no class '{t}' with a vtable. Call rtti_classes with a query."
        for bd, nm, va in hits[:MAX_VTABLES]:
            lines += _vtable_lines(bd, several, va, nm, None)
        if len(hits) > MAX_VTABLES:
            lines.append(f"… {len(hits) - MAX_VTABLES} more vtables of this class. Pass an address to see one.")
    return fit_lines(lines, bud, "code", tool="vtable", args=args)[0]


# ── mfc_message_maps ───────────────────────────────────────────────────────

def _entry_line(bd: Bound, r, ui: uijoin.UiIndex | None = None) -> str:
    label = cpp.entry_label(r["message"], r["code"])
    ident = ""
    if r["ctrl_id"] or r["last_id"]:
        ident = f" id {r['ctrl_id']}"
        if r["last_id"] and r["last_id"] != r["ctrl_id"]:
            ident += f"-{r['last_id']}"
    fn = _fn_name(bd, r["handler"])
    line = f"{label}{ident} -> {bd.addr(r['handler'])}{' ' + fn if fn else ''}"
    if ui is not None and ui.has_ui:
        h = uijoin.Handler(r["class"], 0, r["message"], r["code"], r["ctrl_id"], r["last_id"], r["handler"])
        note = ui.entry_note(h)
        if note:
            line += f"  // {note}"
    return line


def _bases_of(bd: Bound, name: str) -> list[str]:
    out: list[str] = []
    for r in bd.store.db.execute("SELECT bases FROM rtti_class WHERE binary_id=? AND name=?",
                                 (bd.binary.id, name)):
        for b in r["bases"].split(", "):
            if b and b not in out:
                out.append(b)
    return out


@tool("mfc_message_maps", "List MFC message maps: per class, each message with control id and handler function.")
def mfc_message_maps(ctx: ServerContext, target: str = "", binary: str = "", cursor: str = "",
                     budget: int = 0) -> str:
    sc = _scope(ctx, binary)
    if isinstance(sc, str):
        return sc
    bounds, several = sc
    bud = budget_for(ctx, budget, "function_budget")
    args = {"binary": binary, "target": target}
    if cursor:
        return _page([], bud, "mfc_message_maps", args, cursor)
    t = target.strip()
    lines: list[str] = []
    if not t:
        for bd in bounds:
            ui = uijoin.UiIndex(bd.store, bd.binary.id)
            for r in bd.store.db.execute(
                    "SELECT class, map_addr, COUNT(*) AS n FROM msgmap_entry WHERE binary_id=? "
                    "GROUP BY class, map_addr ORDER BY class, map_addr", (bd.binary.id,)):
                dlg = ui.class_dialog_text(r["class"])
                lines.append(f"{_prefix(bd, several)}{r['class']} map {bd.addr(r['map_addr'])} entries {r['n']}"
                             + (f" {dlg}" if dlg else ""))
        if not lines:
            return "no MFC message maps found in the binary."
        return fit_lines(lines, bud, "code", tool="mfc_message_maps", args=args)[0]
    want = t.lower()
    found = False
    for bd in bounds:
        ui = uijoin.UiIndex(bd.store, bd.binary.id)
        maps = bd.store.db.execute(
            "SELECT DISTINCT class, map_addr FROM msgmap_entry WHERE binary_id=? AND lower(class)=? "
            "ORDER BY map_addr", (bd.binary.id, want)).fetchall()
        inherited = ""
        if not maps:
            like = bd.store.db.execute(
                "SELECT DISTINCT class FROM msgmap_entry WHERE binary_id=? AND lower(class) LIKE ? "
                "ORDER BY class LIMIT 20", (bd.binary.id, f"%{want}%")).fetchall()
            names = [r["class"] for r in like]
            if len(names) == 1:
                maps = bd.store.db.execute(
                    "SELECT DISTINCT class, map_addr FROM msgmap_entry WHERE binary_id=? AND class=? "
                    "ORDER BY map_addr", (bd.binary.id, names[0])).fetchall()
            elif len(names) > 1:
                shown = ", ".join(names[:10])
                more = f" (+{len(names) - 10} more)" if len(names) > 10 else ""
                return (f"error ambiguous: '{t}' matches {len(names)} classes with message maps: "
                        f"{shown}{more}. Retry with the full class name.")
            else:                                  # no own map: the nearest base class that has one
                cls = bd.store.db.execute(
                    "SELECT name FROM rtti_class WHERE binary_id=? AND lower(name)=? LIMIT 1",
                    (bd.binary.id, want)).fetchone()
                todo = _bases_of(bd, cls["name"]) if cls else []
                seen: set[str] = set()
                while todo and not maps:
                    b = todo.pop(0)
                    if b in seen:
                        continue
                    seen.add(b)
                    maps = bd.store.db.execute(
                        "SELECT DISTINCT class, map_addr FROM msgmap_entry WHERE binary_id=? AND class=? "
                        "ORDER BY map_addr", (bd.binary.id, b)).fetchall()
                    if maps:
                        inherited = f"// {cls['name']} has no message map of its own; inherited from {b}"
                    else:
                        todo += _bases_of(bd, b)
        for m in maps:
            found = True
            if inherited:
                lines.append(inherited)
                inherited = ""
            rows = bd.store.db.execute(
                "SELECT class, message, code, ctrl_id, last_id, handler FROM msgmap_entry "
                "WHERE binary_id=? AND class=? AND map_addr=? ORDER BY seq",
                (bd.binary.id, m["class"], m["map_addr"])).fetchall()
            dlg = ui.class_dialog_text(m["class"])
            lines.append(f"{_prefix(bd, several)}{m['class']} map {bd.addr(m['map_addr'])} entries {len(rows)}"
                         + (f" {dlg}" if dlg else ""))
            lines += [_entry_line(bd, r, ui) for r in rows]
    if not found:
        return (f"error not_found: no message map for '{t}'. Call mfc_message_maps without a class for "
                "the classes that have one.")
    return fit_lines(lines, bud, "code", tool="mfc_message_maps", args=args)[0]
