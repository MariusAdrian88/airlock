"""delphi set: delphi_classes, delphi_forms, delphi_events (VMT, published methods and DFM forms).

Rows come from the derived tables ``dl_*`` (server/delphi.py), filled when a binary is ready and derived
here when missing or stale. Output is one item per line, cut to the token budget with a cursor. Names are
hints: nothing is renamed in Ghidra. Dirty-role tools; clean sessions never reach them.
"""

from __future__ import annotations

from airlock.server import delphi
from airlock.server.budget import CursorError, fit_lines, resume_lines
from airlock.server.context import ServerContext
from airlock.server.registry import tool
from airlock.server.selectors import split_binary_target
from airlock.server.tools.common import Bound, bind_many, budget_for

DEFAULT_LIMIT = 50


def _scope(ctx: ServerContext, binary: str, ident: str = "") -> tuple[list[Bound], bool, str] | str:
    """(Delphi binaries with their tables filled, several?, bare ident) or a one-line error."""
    ident = ident.strip()
    if "!" in ident and not binary:
        ix = ctx.indexer
        try:
            st = ix.store(ix.resolve_project(None))
            pre, bare = split_binary_target(st, ident)
            if pre:
                binary, ident = pre, bare
        except Exception:  # noqa: BLE001  the plain lookup below reports the problem
            pass
    got = bind_many(ctx, binary)
    if isinstance(got, str):
        return got
    bounds = [bd for bd in got[0] if delphi.is_delphi(bd.binary)]
    if not bounds:
        what = f"'{got[0][0].binary.name}' is not a Delphi binary" if binary else "no Delphi binaries"
        return f"error not_delphi: {what}; frameworks: {_frameworks(got[0])}."
    for bd in bounds:
        art = ctx.indexer.paths(bd.project).artifacts / bd.binary.sha256
        cfg = ctx.config
        delphi.ensure(bd.store, bd.binary, art, cfg.idr_kb_dir, cfg.delphi_sigdb_dir, cfg.warp_dir)
    return bounds, len(bounds) > 1, ident


# framework -> table whose rows for a binary mean the framework was found in it
_FW_TABLES = (("qt", "qt_class"), ("mfc", "msgmap_entry"), (".net", "dn_type"), ("c++ rtti", "rtti_class"))


def _frameworks(bounds: list[Bound]) -> str:
    """`qt (a.exe, b.dll), mfc (c.exe)`: what the binaries have, as data, for a Delphi tool called on a
    project without Delphi; a binary with none of them is listed under its toolchain."""
    by: dict[str, list[str]] = {}
    for bd in bounds:
        hit = False
        for fw, table in _FW_TABLES:
            try:
                n = bd.store.db.execute(f"SELECT 1 FROM {table} WHERE binary_id=? LIMIT 1",
                                        (bd.binary.id,)).fetchone()
            except Exception:  # noqa: BLE001  table missing in an older index
                n = None
            if n:
                by.setdefault(fw, []).append(bd.binary.name)
                hit = True
                break       # the first (most specific) framework names the binary
        if not hit:
            by.setdefault(f"none ({bd.binary.toolchain or 'native'})", []).append(bd.binary.name)
    return ", ".join(f"{fw} ({', '.join(names)})" if not fw.startswith("none") else
                     f"{fw[:-1]}: {', '.join(names)})" for fw, names in by.items())


def _page(lines: list[str], bud: int, name: str, args: dict, cursor: str) -> str:
    if cursor:
        try:
            return resume_lines(cursor, bud, "code", tool=name, args=args)[0]
        except CursorError as e:
            return e.message
    return fit_lines(lines, bud, "code", tool=name, args=args)[0]


def _prefix(bd: Bound, several: bool) -> str:
    return f"{bd.binary.name}!" if several else ""


def _quote(text: str, n: int = 50) -> str:
    text = text.replace("\r", " ").replace("\n", " ")
    return '"' + (text if len(text) <= n else text[:n - 1] + "…") + '"'


# ── delphi_classes ─────────────────────────────────────────────────────────

@tool("delphi_classes", "List Delphi classes recovered from VMTs: name, parent, unit, vmt address, method counts.")
def delphi_classes(ctx: ServerContext, query: str = "", limit: int = DEFAULT_LIMIT, binary: str = "",
                   cursor: str = "", budget: int = 0) -> str:
    args = {"binary": binary, "query": query, "limit": limit}
    if cursor:      # a known cursor carries its own arguments
        return _page([], budget_for(ctx, budget), "delphi_classes", args, cursor)
    if limit < 1:
        return "error bad_args: limit must be at least 1."
    sc = _scope(ctx, binary)
    if isinstance(sc, str):
        return sc
    bounds, several, _ = sc
    bud = budget_for(ctx, budget)
    q = query.strip().lower()
    lines: list[str] = []
    have = 0
    for bd in bounds:
        for r in bd.store.db.execute(
                "SELECT c.name, c.parent, c.unit, c.vmt, c.size, c.nvirtual, "
                "(SELECT COUNT(*) FROM dl_method m WHERE m.binary_id=c.binary_id AND m.vmt=c.vmt "
                " AND m.kind='published') AS pub, "
                "(SELECT COUNT(*) FROM dl_field f WHERE f.binary_id=c.binary_id AND f.vmt=c.vmt) AS flds "
                "FROM dl_class c WHERE c.binary_id=? ORDER BY c.name, c.vmt", (bd.binary.id,)):
            have += 1
            if q and q not in r["name"].lower() and q not in (r["unit"] or "").lower():
                continue
            line = f"{_prefix(bd, several)}{r['name']}"
            if r["parent"]:
                line += f" : {r['parent']}"
            if r["unit"]:
                line += f" unit {r['unit']}"
            line += f" vmt {bd.addr(r['vmt'])} size {r['size']} published {r['pub']} virtual {r['nvirtual']}"
            if r["flds"]:
                line += f" fields {r['flds']}"
            lines.append(line)
    if not lines:
        if have == 0:
            if all(delphi.is_fpc(bd.binary) for bd in bounds):
                return ("no Free Pascal classes: no VMT found (packed, or an FPC version with another table "
                        "layout than 3.x).")
            return "no Delphi classes: no VMT found (a Delphi version older than 2009 with another layout, or packed)."
        return f"no Delphi class matches '{query}' ({have} classes)."
    return fit_lines(lines, bud, "code", tool="delphi_classes", args=args, max_lines=limit)[0]


# ── delphi_forms ───────────────────────────────────────────────────────────

def _find_forms(bd: Bound, ident: str) -> list[dict]:
    """Forms of the binary named ``ident``: resource name, class or form (root component) name; an exact
    match wins, else the forms that contain the text."""
    want = ident.lower()
    rows = [dict(r) for r in bd.store.db.execute(
        "SELECT res_name, class, name, caption, ncomp, nevents, flags FROM dl_form WHERE binary_id=? "
        "ORDER BY res_name", (bd.binary.id,))]
    exact = [r for r in rows if want in (r["res_name"].lower(), r["class"].lower(), r["name"].lower())]
    if exact:
        return exact
    return [r for r in rows if want in r["res_name"].lower() or want in r["class"].lower()
            or want in r["name"].lower()]


def _have_forms(bounds: list[Bound], several: bool, n: int = 12) -> str:
    """`(have: TMain, TAbout, …)`: the form classes, so a wrong name needs no listing call."""
    names = [f"{_prefix(bd, several)}{r[0]}" for bd in bounds for r in bd.store.db.execute(
        "SELECT class FROM dl_form WHERE binary_id=? ORDER BY class", (bd.binary.id,))]
    more = f", +{len(names) - n} more" if len(names) > n else ""
    return f"(have: {', '.join(names[:n]) or 'none'}{more})"


@tool("delphi_forms", "List Delphi DFM forms, or show one form's component tree: name, class, caption, event count.")
def delphi_forms(ctx: ServerContext, form: str = "", binary: str = "", cursor: str = "",
                 budget: int = 0) -> str:
    if cursor:
        return _page([], budget_for(ctx, budget), "delphi_forms", {"binary": binary, "form": form},
                     cursor)
    sc = _scope(ctx, binary, form)
    if isinstance(sc, str):
        return sc
    bounds, several, form = sc
    bud = budget_for(ctx, budget)
    args = {"binary": binary, "form": form}
    lines: list[str] = []
    if not form:
        for bd in bounds:
            for r in bd.store.db.execute(
                    "SELECT class, name, caption, ncomp, nevents, flags FROM dl_form WHERE binary_id=? "
                    "ORDER BY class", (bd.binary.id,)):
                line = f"{_prefix(bd, several)}{r['class']} {r['name']}"
                if r["caption"]:
                    line += f" {_quote(r['caption'])}"
                line += f" components {r['ncomp']} events {r['nevents']}"
                if r["flags"]:
                    line += f" {r['flags']}"
                lines.append(line)
        if not lines:
            if all(delphi.is_fpc(bd.binary) for bd in bounds):
                return ("no forms: the binary has no TPF0 form resources (Lazarus forms linked as .lrs "
                        "data are not read).")
            return "no DFM forms: the binary has no TPF0 form resources."
        return fit_lines(lines, bud, "code", tool="delphi_forms", args=args)[0]
    hits = [(bd, f) for bd in bounds for f in _find_forms(bd, form)]
    if not hits:
        return f"error not_found: no form '{form}' {_have_forms(bounds, several)}."
    if len(hits) > 1:
        names = [f"{_prefix(bd, several)}{f['class']}" for bd, f in hits]
        shown = ", ".join(names[:10]) + (f" (+{len(names) - 10} more)" if len(names) > 10 else "")
        return f"error ambiguous: '{form}' matches {len(names)} forms: {shown}."
    bd, f = hits[0]
    ev_by: dict[int, int] = {}
    for r in bd.store.db.execute("SELECT seq, COUNT(*) AS n FROM dl_event WHERE binary_id=? AND form=? "
                                 "GROUP BY seq", (bd.binary.id, f["res_name"])):
        ev_by[r["seq"]] = r["n"]
    head = f"{_prefix(bd, several)}{f['class']} {f['name']}"
    if f["caption"]:
        head += f" {_quote(f['caption'])}"
    lines.append(f"{head} components {f['ncomp']} events {f['nevents']}")
    for r in bd.store.db.execute(
            "SELECT seq, depth, name, class, flags, caption FROM dl_component WHERE binary_id=? AND form=? "
            "AND seq>0 ORDER BY seq", (bd.binary.id, f["res_name"])):
        line = "  " * r["depth"] + f"{r['name']}: {r['class']}"
        if r["caption"]:
            line += f" {_quote(r['caption'])}"
        if r["flags"]:
            line += f" {r['flags']}"
        if ev_by.get(r["seq"]):
            line += f" events {ev_by[r['seq']]}"
        lines.append(line)
    return fit_lines(lines, bud, "code", tool="delphi_forms", args=args)[0]


# ── delphi_events ──────────────────────────────────────────────────────────

def _event_line(bd: Bound, r, show_form: bool) -> str:
    who = r["cname"] or "form"
    left = f"{who}.{r['prop']}"
    if show_form:
        left = f"{r['fclass']} {left}"
    if r["addr"] is None:
        return f"{left} -> {r['handler']} (not in the published methods)"
    fn = bd.store.function_at(bd.binary.id, r["addr"])
    name = f" {fn.qualified_name}" if fn is not None else " (no function)"
    return f"{left} -> {r['owner']}.{r['handler']} {bd.addr(r['addr'])}{name}"


@tool("delphi_events", "Show the event handlers of a Delphi form or component: event, handler method, address, function.")
def delphi_events(ctx: ServerContext, form: str = "", component: str = "", binary: str = "",
                  cursor: str = "", budget: int = 0) -> str:
    args = {"binary": binary, "form": form, "component": component}
    if cursor:
        return _page([], budget_for(ctx, budget), "delphi_events", args, cursor)
    sc = _scope(ctx, binary, form or component)
    if isinstance(sc, str):
        return sc
    bounds, several, ident = sc
    bud = budget_for(ctx, budget)
    lines: list[str] = []
    base = ("SELECT e.prop, e.handler, e.owner, e.addr, c.name AS cname, c.class AS cclass, "
            "f.class AS fclass FROM dl_event e JOIN dl_component c ON c.binary_id=e.binary_id AND "
            "c.form=e.form AND c.seq=e.seq JOIN dl_form f ON f.binary_id=e.binary_id AND f.res_name=e.form "
            "WHERE e.binary_id=? ")
    if form.strip():
        hits = [(bd, f) for bd in bounds for f in _find_forms(bd, ident)]
        if not hits:
            return f"error not_found: no form '{ident}' {_have_forms(bounds, several)}."
        if len(hits) > 1:
            names = [f"{_prefix(bd, several)}{f['class']}" for bd, f in hits]
            shown = ", ".join(names[:10]) + (f" (+{len(names) - 10} more)" if len(names) > 10 else "")
            return f"error ambiguous: '{ident}' matches {len(names)} forms: {shown}."
        bd, f = hits[0]
        rows = bd.store.db.execute(base + "AND e.form=? ORDER BY e.seq, e.prop", (bd.binary.id, f["res_name"])).fetchall()
        lines.append(f"{_prefix(bd, several)}{f['class']} events {len(rows)}")
        lines += ["  " + _event_line(bd, r, False) for r in rows]
        if not rows:
            lines.append("  no event handlers")
    elif not ident:     # no form and no component: the events of all forms
        for bd in bounds:
            for r in bd.store.db.execute(base + "ORDER BY e.form, e.seq, e.prop", (bd.binary.id,)):
                lines.append(f"{_prefix(bd, several)}" + _event_line(bd, r, True))
        if not lines:
            return "error not_found: no event handlers in the forms."
    else:
        want = ident.split(".")[-1].lower()
        fwant = ident.split(".")[0].lower() if "." in ident else ""
        total = 0
        for bd in bounds:
            for r in bd.store.db.execute(base + "AND lower(c.name)=? ORDER BY e.form, e.seq, e.prop",
                                         (bd.binary.id, want)):
                if fwant and fwant not in (r["fclass"].lower(),):
                    continue
                total += 1
                lines.append(f"{_prefix(bd, several)}" + _event_line(bd, r, True))
        if not lines:
            return f"error not_found: no component '{ident}' with event handlers."
    return fit_lines(lines, bud, "code", tool="delphi_events", args=args)[0]
