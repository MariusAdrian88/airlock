"""resources set: pe_resources, dialogs, menus, string_tables, version_info (pefile, no Ghidra).

Rows come from the derived tables ``res_*`` (server/peres.py), filled when a binary is ready and
refreshed here when missing or stale. ``binary`` defaults to the root executable; ``binary="*"``
covers every binary; ``binary!id`` works for the id parameters.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from airlock.server import peres, uijoin
from airlock.server.budget import CursorError, fit_lines, resume_lines
from airlock.server.context import ServerContext
from airlock.server.indexer import IndexerError
from airlock.server.projectmap import load_manifest
from airlock.server.registry import tool
from airlock.server.tools.common import Bound, bind_binary, budget_for, preview

PREFERRED_LANGS = (0, 0x0409)


def _page(lines: list[str], bud: int, name: str, args: dict) -> str:
    return fit_lines(lines, bud, "prose", tool=name, args=args)[0]


def _resume(cursor: str, bud: int, name: str, args: dict) -> str:
    try:
        return resume_lines(cursor, bud, "prose", tool=name, args=args)[0]
    except CursorError as e:
        return e.message


def _root_binary(ctx: ServerContext, proj: str, bins: list) -> object | None:
    try:
        man = load_manifest(ctx.indexer.paths(proj))
    except Exception:  # noqa: BLE001
        return None
    root = PurePosixPath(str((man.get("source") or {}).get("root_exe", "")).replace("\\", "/")).name.lower()
    return next((b for b in bins if root and b.name.lower() == root), None)


def _scope(ctx: ServerContext, binary: str, ident: str = "") -> tuple[list[Bound], str, bool] | str:
    """(binaries, bare id, several?) or an error line. The tables of each binary are filled."""
    ix = ctx.indexer
    try:
        proj = ix.resolve_project(None)
    except IndexerError as e:
        return e.message
    st = ix.store(proj)
    ident = ident.strip()
    if "!" in ident:
        left, _, right = ident.partition("!")
        if left == "*" or any(b.name.lower() == left.strip().lower() for b in st.list_binaries()):
            if binary and binary != left.strip():
                return f"error bad_args: id names binary '{left}' but binary='{binary}'."
            binary, ident = left.strip(), right.strip()
    if binary in ("*", "all"):
        every = st.list_binaries()
        if not every:
            return f"error no_binary: project '{proj}' has no binaries."
        bounds = [Bound(proj, st, b) for b in every]
    elif binary:
        bd = bind_binary(ctx, binary, require_ready=False)
        if isinstance(bd, str):
            return bd
        bounds = [bd]
    else:
        every = st.list_binaries()
        if len(every) > 1:
            root = _root_binary(ctx, proj, every)
            # no root executable: look in every binary (lines carry the binary name)
            bounds = [Bound(proj, st, root)] if root is not None else [Bound(proj, st, b) for b in every]
        else:
            bd = bind_binary(ctx, "", require_ready=False)
            if isinstance(bd, str):
                return bd
            bounds = [bd]
    art = ix.paths(proj).artifacts
    for bd in bounds:
        try:
            if not (art / bd.binary.sha256).is_file():
                if len(bounds) == 1:
                    return f"error not_found: the stored file of '{bd.binary.name}' is missing."
                continue
            peres.ensure(st, bd.binary, art / bd.binary.sha256)
        except Exception as e:  # noqa: BLE001
            return f"error resources_failed: cannot read resources of {bd.binary.name} ({type(e).__name__}: {e})."
    return bounds, ident, len(bounds) > 1


def _tag(bd: Bound, multi: bool) -> str:
    return f"[{bd.binary.name}] " if multi else ""


def _lang(n: int) -> str:
    return f"0x{n:04x}"


def _pick_lang(langs: set[int], want: int) -> int:
    if want >= 0:
        return want if want in langs else -1
    for p in PREFERRED_LANGS:
        if p in langs:
            return p
    return min(langs)


def _norm_id(text: str) -> str:
    t = text.strip()
    try:
        return str(int(t, 0))
    except ValueError:
        return t


def _type_filter(text: str) -> tuple[int | None, str] | None:
    t = text.strip()
    if not t:
        return None
    up = t.upper().removeprefix("RT_")
    if up in peres.RT_BY_NAME:
        return peres.RT_BY_NAME[up], up
    try:
        n = int(t, 0)
        return n, peres.RT_NAMES.get(n, str(n))
    except ValueError:
        return None, t


@tool("pe_resources", "List the resources of a PE file (type, id, language, size); type filters by "
                      "name or number.")
def pe_resources(ctx: ServerContext, type: str = "", binary: str = "", cursor: str = "",
                 budget: int = 0) -> str:
    args = {"type": type, "binary": binary}
    bud = budget_for(ctx, budget)
    if cursor:
        return _resume(cursor, bud, "pe_resources", args)
    sc = _scope(ctx, binary)
    if isinstance(sc, str):
        return sc
    bounds, _, multi = sc
    flt = _type_filter(type)
    lines: list[str] = []
    for bd in bounds:
        art = ctx.indexer.paths(bd.project).artifacts / bd.binary.sha256
        pe = peres.open_pe(art)
        if pe is None:
            lines.append(f"{_tag(bd, multi)}not a PE file or no resources")
            continue
        try:
            ents = peres.list_entries(pe)
        finally:
            pe.close()
        if flt is not None:
            ents = [e for e in ents if (e.type_id == flt[0] if flt[0] is not None
                                        else e.type_name.lower() == flt[1].lower())]
        counts: dict[str, int] = {}
        for e in ents:
            counts[e.type_name] = counts.get(e.type_name, 0) + 1
        head = ", ".join(f"{k} {v}" for k, v in counts.items()) or "none"
        lines.append(f"{_tag(bd, multi)}{bd.binary.name}: {len(ents)} resources ({head})")
        ents.sort(key=lambda e: (e.type_id if e.type_id is not None else 1 << 20, e.type_name,
                                 (0, e.res_id) if e.res_id is not None else (1, 0), str(e.res_name), e.lang))
        lines += [f"{_tag(bd, multi)}{e.type_name} {e.key} lang={_lang(e.lang)} size={e.size}" for e in ents]
    return _page(lines, bud, "pe_resources", args)


@tool("dialogs", "List dialog templates, or show one with its controls (id, class, caption, style); "
                 "id may be binary!id.")
def dialogs(ctx: ServerContext, id: str = "", binary: str = "", lang: int = -1, cursor: str = "",
            budget: int = 0) -> str:
    args = {"id": id, "binary": binary, "lang": lang}
    bud = budget_for(ctx, budget)
    if cursor:
        return _resume(cursor, bud, "dialogs", args)
    sc = _scope(ctx, binary, id)
    if isinstance(sc, str):
        return sc
    bounds, ident, multi = sc
    ident = _norm_id(ident) if ident else ""
    lines: list[str] = []
    for bd in bounds:
        db = bd.store.db
        bid = bd.binary.id
        tag = _tag(bd, multi)
        ui = uijoin.UiIndex(bd.store, bid)
        rows = db.execute("SELECT dialog_id, lang, caption, x, y, cx, cy FROM res_dialog WHERE binary_id=?",
                          (bid,)).fetchall()
        by: dict[str, dict[int, object]] = {}
        for r in rows:
            by.setdefault(r["dialog_id"], {})[r["lang"]] = r
        ids = sorted(by, key=lambda k: (0, int(k)) if k.isdigit() else (1, k.lower()))
        if not ident:
            for k in ids:
                lg = _pick_lang(set(by[k]), lang)
                if lg < 0:
                    continue
                r = by[k][lg]
                n = db.execute("SELECT COUNT(*) FROM res_control WHERE binary_id=? AND dialog_id=? AND lang=?",
                               (bid, k, lg)).fetchone()[0]
                others = [_lang(x) for x in sorted(by[k]) if x != lg]
                owners = ui.dialog_classes(k)
                lines.append(f"{tag}{k} | {preview(r['caption'] or '', 50)} | {n} controls | "
                             f"{r['x']},{r['y']},{r['cx']},{r['cy']} | lang {_lang(lg)}"
                             + (f" (also {' '.join(others)})" if others else "")
                             + (f" | class {', '.join(owners[:3])}" if owners else ""))
            continue
        k = next((x for x in ids if x == ident or x.lower() == ident.lower()), None)
        if k is None:
            if not multi:
                have = ", ".join(ids[:12]) + (f", … {len(ids) - 12} more" if len(ids) > 12 else "")
                return f"error not_found: no dialog '{ident}' in {bd.binary.name} (have: {have or 'none'})."
            continue
        lg = _pick_lang(set(by[k]), lang)
        miss = f" (no {_lang(lang)})" if lg < 0 else ""      # that language is missing: the default one
        if lg < 0:
            lg = _pick_lang(set(by[k]), -1)
        r = by[k][lg]
        others = [_lang(x) for x in sorted(by[k]) if x != lg]
        owners = ui.dialog_classes(k)
        lines.append(f"{tag}dialog {k} {preview(r['caption'] or '', 80)} {r['x']},{r['y']},{r['cx']},{r['cy']} "
                     f"lang {_lang(lg)}{miss}" + (f" (also {' '.join(others)})" if others else "")
                     + (f" class {', '.join(owners[:3])}" if owners else ""))
        for c in db.execute("SELECT ctrl_id, class, caption, style FROM res_control "
                            "WHERE binary_id=? AND dialog_id=? AND lang=? ORDER BY seq", (bid, k, lg)):
            cid = c["ctrl_id"]
            ref = uijoin.CtrlRef(k, c["class"] or "", "", cid if cid is not None else 0)
            hs = ui.ctrl_suffix(ref) if cid and cid > 0 and cid not in uijoin.STATIC_IDS else ""
            lines.append(f"{tag}  id={c['ctrl_id']} {c['class']}"
                         + (f" {preview(c['caption'], 60)}" if c["caption"] else "")
                         + (f" {c['style']}" if c["style"] else "") + (f" {hs}" if hs else ""))
    if not lines:
        if ident:
            return f"error not_found: no dialog '{ident}' in any binary."
        return "no dialog templates"
    return _page(lines, bud, "dialogs", args)


@tool("menus", "List menu templates, or show one as a tree of items (id, caption, popup path); "
               "id may be binary!id.")
def menus(ctx: ServerContext, id: str = "", binary: str = "", lang: int = -1, cursor: str = "",
          budget: int = 0) -> str:
    args = {"id": id, "binary": binary, "lang": lang}
    bud = budget_for(ctx, budget)
    if cursor:
        return _resume(cursor, bud, "menus", args)
    sc = _scope(ctx, binary, id)
    if isinstance(sc, str):
        return sc
    bounds, ident, multi = sc
    ident = _norm_id(ident) if ident else ""
    lines: list[str] = []
    for bd in bounds:
        db = bd.store.db
        bid = bd.binary.id
        tag = _tag(bd, multi)
        ui = uijoin.UiIndex(bd.store, bid)
        langs: dict[str, set[int]] = {}
        for r in db.execute("SELECT DISTINCT menu_id, lang FROM res_menu_item WHERE binary_id=?", (bid,)):
            langs.setdefault(r["menu_id"], set()).add(r["lang"])
        ids = sorted(langs, key=lambda k: (0, int(k)) if k.isdigit() else (1, k.lower()))
        if not ident:
            for k in ids:
                lg = _pick_lang(langs[k], lang)
                if lg < 0:
                    continue
                r = db.execute("SELECT COUNT(*) n, SUM(item_id IS NULL) p FROM res_menu_item "
                               "WHERE binary_id=? AND menu_id=? AND lang=?", (bid, k, lg)).fetchone()
                top = [x["caption"] for x in db.execute(
                    "SELECT caption FROM res_menu_item WHERE binary_id=? AND menu_id=? AND lang=? "
                    "AND item_id IS NULL AND path=caption ORDER BY seq", (bid, k, lg))]
                lines.append(f"{tag}{k} | {r['n'] - (r['p'] or 0)} items, {r['p'] or 0} popups | "
                             f"{' / '.join(top[:8])}{' …' if len(top) > 8 else ''} | lang {_lang(lg)}")
            continue
        k = next((x for x in ids if x == ident or x.lower() == ident.lower()), None)
        if k is None:
            if not multi:
                have = ", ".join(ids[:12]) + (f", … {len(ids) - 12} more" if len(ids) > 12 else "")
                return f"error not_found: no menu '{ident}' in {bd.binary.name} (have: {have or 'none'})."
            continue
        lg = _pick_lang(langs[k], lang)
        miss = f" (no {_lang(lang)})" if lg < 0 else ""
        if lg < 0:
            lg = _pick_lang(langs[k], -1)
        others = [_lang(x) for x in sorted(langs[k]) if x != lg]
        lines.append(f"{tag}menu {k} lang {_lang(lg)}{miss}" + (f" (also {' '.join(others)})" if others else ""))
        for m in db.execute("SELECT item_id, caption, path FROM res_menu_item "
                            "WHERE binary_id=? AND menu_id=? AND lang=? ORDER BY seq", (bid, k, lg)):
            depth = m["path"].count(" > ")
            if m["item_id"] is None:
                lines.append(f"{tag}{'  ' * depth}{m['caption']} >")
            else:
                hs = ui.menu_suffix(m["item_id"]) if m["item_id"] > 0 else ""
                lines.append(f"{tag}{'  ' * depth}id={m['item_id']} {m['path']}" + (f" {hs}" if hs else ""))
    if not lines:
        if ident:
            return f"error not_found: no menu '{ident}' in any binary."
        return "no menu templates"
    return _page(lines, bud, "menus", args)


@tool("string_tables", "Find string-table entries by id or substring (id | text).")
def string_tables(ctx: ServerContext, query: str = "", limit: int = 50, binary: str = "",
                  lang: int = -1, cursor: str = "", budget: int = 0) -> str:
    args = {"query": query, "limit": limit, "binary": binary, "lang": lang}
    bud = budget_for(ctx, budget)
    if cursor:
        return _resume(cursor, bud, "string_tables", args)
    sc = _scope(ctx, binary)
    if isinstance(sc, str):
        return sc
    bounds, _, multi = sc
    limit = max(1, min(int(limit), 1000))
    q = query.strip()
    qid: int | None = None
    try:
        qid = int(q, 0)
    except ValueError:
        pass
    lines: list[str] = []
    total = 0
    for bd in bounds:
        rows = bd.store.db.execute("SELECT string_id, lang, text FROM res_string WHERE binary_id=? "
                                   "ORDER BY string_id", (bd.binary.id,)).fetchall()
        by: dict[int, dict[int, str]] = {}
        for r in rows:
            by.setdefault(r["string_id"], {})[r["lang"]] = r["text"]
        for sid in sorted(by):
            lg = _pick_lang(set(by[sid]), lang)
            if lg < 0:
                continue
            text = by[sid][lg]
            if q and not ((qid is not None and sid == qid) or q.lower() in text.lower()):
                continue
            total += 1
            lines.append(f"{_tag(bd, multi)}{sid} | {preview(text, 200)}")
    if not lines:
        return f"no string-table entries match '{q}'" if q else "no string tables"
    return fit_lines([f"string table entries: {total}", *lines], bud, "prose", tool="string_tables",
                     args=args, max_lines=limit + 1, page=limit)[0]


@tool("version_info", "Show the version resource: file and product version, company, product name, "
                      "description.")
def version_info(ctx: ServerContext, binary: str = "") -> str:
    sc = _scope(ctx, binary)
    if isinstance(sc, str):
        return sc
    bounds, _, multi = sc
    out: list[str] = []
    for bd in bounds:
        art = ctx.indexer.paths(bd.project).artifacts / bd.binary.sha256
        got = peres.version_info(art)
        tag = _tag(bd, multi)
        if not got:
            out.append(f"{tag}{bd.binary.name}: no version resource")
            continue
        out.append(f"{tag}{bd.binary.name}:")
        out += [f"{tag}  {x}" for x in got]
    return "\n".join(out)
