"""qt_metaobjects: Qt classes, signals, slots, properties and connections (server/qt.py, schema v13).

Rows come from the derived tables ``qt_*`` (parsed from the PE bytes, method addresses from the worker op
``qt_dispatch``). One item per line, cut to the token budget with a cursor. Names are hints: nothing is
renamed in Ghidra. Dirty-role tool; clean sessions never reach it.
"""

from __future__ import annotations

import re

from airlock.server import qt
from airlock.server.budget import CursorError, fit_lines, resume_lines
from airlock.server.context import ServerContext
from airlock.server.registry import tool
from airlock.server.selectors import split_binary_target
from airlock.server.tools.common import Bound, bind_many, budget_for

DEFAULT_LIMIT = 50
_NORM = re.compile(r"\bconst\b|[&\s]")


def _norm_sig(sig: str) -> str:
    """``name(QString const &, int)`` and ``name(QString,int)`` compare equal."""
    return _NORM.sub("", sig)


def _scope(ctx: ServerContext, binary: str, ident: str = "") -> tuple[list[Bound], bool, str] | str:
    """(binaries with Qt tables, several?, bare ident) or a one-line error."""
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
    bounds = []
    for bd in got[0]:
        art = ctx.indexer.paths(bd.project).artifacts / bd.binary.sha256
        qt.ensure(bd.store, bd.binary, art)
        if bd.store.db.execute("SELECT 1 FROM qt_class WHERE binary_id=? LIMIT 1", (bd.binary.id,)).fetchone():
            bounds.append(bd)
    if not bounds:
        qtb = [bd for bd in got[0] if qt.is_qt(bd.binary)]
        if qtb:
            return "no Qt metaobjects: no QMetaObject found in the binary (a static Qt build is not detected)."
        return "error not_qt: the project has no Qt binary."
    return bounds, len(bounds) > 1, ident


def _page(lines: list[str], bud: int, name: str, args: dict, cursor: str) -> str:
    if cursor:
        try:
            return resume_lines(cursor, bud, "code", tool=name, args=args)[0]
        except CursorError as e:
            return e.message
    return fit_lines(lines, bud, "code", tool=name, args=args)[0]


def _prefix(bd: Bound, several: bool) -> str:
    return f"{bd.binary.name}!" if several else ""


def _fn_name(bd: Bound, addr: int | None) -> str:
    if addr is None:
        return ""
    fn = bd.store.function_at(bd.binary.id, addr)
    nm = f" {fn.qualified_name}" if fn is not None and fn.name_state != "auto" else ""
    return f"-> {bd.addr(addr)}{nm}"


def _find_classes(bd: Bound, ident: str) -> list[dict]:
    """Classes named ``ident`` (exact, then substring), or the class at a metaobject address."""
    want = ident.lower().strip()
    rows = [dict(r) for r in bd.store.db.execute(
        "SELECT * FROM qt_class WHERE binary_id=? ORDER BY name, meta_addr", (bd.binary.id,))]
    if want.startswith("0x"):
        try:
            a = int(want, 16)
            return [r for r in rows if a in (r["meta_addr"], r["metacall"], r["data_addr"])]
        except ValueError:
            return []
    exact = [r for r in rows if r["name"].lower() == want or r["name"].lower().split("::")[-1] == want]
    return exact or [r for r in rows if want in r["name"].lower()]


def _slot_class(db, bid: int, addr: int) -> str:
    r = db.execute("SELECT c.name FROM qt_method m JOIN qt_class c ON c.binary_id=m.binary_id AND "
                   "c.meta_addr=m.meta_addr WHERE m.binary_id=? AND m.addr=? LIMIT 1", (bid, addr)).fetchone()
    return r[0] if r else ""


def _connections(bd: Bound, several: bool, cls: dict | None) -> list[str]:
    """String-based connects (resolved to classes where the text is unique enough) and the call sites of
    the pointer-to-member ``connectImpl``; with ``cls`` only those that name one of its signals or slots."""
    db = bd.store.db
    bid = bd.binary.id
    by_sig: dict[str, list[tuple[str, str, int | None, str]]] = {}
    for r in db.execute("SELECT c.name AS cname, m.kind, m.name, m.params, m.addr FROM qt_method m JOIN qt_class c "
                        "ON c.binary_id=m.binary_id AND c.meta_addr=m.meta_addr WHERE m.binary_id=? "
                        "AND m.kind IN ('signal','slot','method')", (bid,)):
        types = ",".join(p.rsplit(" ", 1)[0] if " " in p.strip() else p for p in r["params"].split(", ") if p)
        by_sig.setdefault(_norm_sig(f"{r['name']}({types})"), []).append((r["cname"], r["kind"], r["addr"], r["name"]))
    own: set[str] = set()
    if cls is not None:
        for r in db.execute("SELECT name, params FROM qt_method WHERE binary_id=? AND meta_addr=?",
                            (bid, cls["meta_addr"])):
            types = ",".join(p.rsplit(" ", 1)[0] if " " in p.strip() else p for p in r["params"].split(", ") if p)
            own.add(_norm_sig(f"{r['name']}({types})"))
    lines: list[str] = []
    for r in db.execute("SELECT fn_entry, site, signal, slot, slot_kind, kind FROM qt_connect WHERE binary_id=? "
                        "AND kind IN ('string','string-guess') ORDER BY fn_entry, site", (bid,)):
        sg, sl = _norm_sig(r["signal"]), _norm_sig(r["slot"])
        if cls is not None and sg not in own and sl not in own:
            continue
        a = [c for c, k, _ad, _n in by_sig.get(sg, []) if k == "signal"]
        b = [(c, ad) for c, k, ad, _n in by_sig.get(sl, []) if k in ("slot", "method", "signal")]
        left = ("~" if r["kind"] == "string-guess" else "") + f"signal {r['signal']}" + (f" [{', '.join(a[:3])}]" if a else "")
        right = f"{r['slot_kind']} {r['slot']}"
        if b:
            c0, ad0 = b[0]
            right += f" [{c0}" + (f" {bd.addr(ad0)}" if ad0 else "") + "]" + (f" +{len(b) - 1}" if len(b) > 1 else "")
        fn = bd.store.function_at(bid, r["fn_entry"])
        lines.append(f"{_prefix(bd, several)}{left} -> {right} in {bd.addr(r['fn_entry'])}"
                     + (f" {fn.qualified_name}" if fn is not None else ""))
    own_names = {x.split("(")[0] for x in own}
    rows = db.execute("SELECT fn_entry, site, signal, slot, slot_kind FROM qt_connect WHERE binary_id=? AND kind='ptr' "
                      "ORDER BY fn_entry, site", (bid,)).fetchall()
    if cls is not None:
        short = cls["name"]
        rows = [r for r in rows if (r["signal"] or "").startswith(short + "::")
                or (r["slot_kind"] in ("slot", "signal") and r["slot"].startswith("0x")
                    and _slot_class(db, bid, int(r["slot"], 16)) == short)]
    unresolved = dead = 0
    for r in rows:
        fn = bd.store.function_at(bid, r["fn_entry"])
        where = f"in {bd.addr(r['fn_entry'])}" + (f" {fn.qualified_name}" if fn is not None else "")
        if not r["signal"]:
            if r["slot_kind"] == "uncalled":
                dead += 1
            else:
                unresolved += 1
            continue
        right = r["slot"]
        if right.startswith("0x"):
            sf = bd.store.function_at(bid, int(right, 16))
            right = f"{r['slot_kind']} {bd.addr(int(right, 16))}" + (
                f" {sf.qualified_name}" if sf is not None and sf.name_state != "auto" else "")
        else:
            right = f"{r['slot_kind']} {right}".strip()
        lines.append(f"{_prefix(bd, several)}signal {r['signal']} -> {right} at {bd.addr(r['site'])} {where}")
    if unresolved and cls is None:
        lines.append(f"{_prefix(bd, several)}{unresolved} pointer connect call sites not resolved")
    if dead and cls is None:
        lines.append(f"{_prefix(bd, several)}{dead} pointer connect call sites in functions nobody calls (skipped)")
    return lines


@tool("qt_metaobjects", "List Qt classes with signals, slots, properties and the functions behind them, or show one class and its connections.")
def qt_metaobjects(ctx: ServerContext, class_: str = "", limit: int = DEFAULT_LIMIT, connections: bool = False,
                   binary: str = "", cursor: str = "", budget: int = 0) -> str:
    if cursor:      # a known cursor carries its own arguments
        return _page([], budget_for(ctx, budget), "qt_metaobjects",
                     {"binary": binary, "class_": class_, "limit": limit, "connections": connections},
                     cursor)
    if limit < 1:
        return "error bad_args: limit must be at least 1."
    sc = _scope(ctx, binary, class_)
    if isinstance(sc, str):
        return sc
    bounds, several, ident = sc
    bud = budget_for(ctx, budget)
    args = {"binary": binary, "class_": ident, "limit": limit, "connections": connections}
    lines: list[str] = []
    if connections and not ident:
        for bd in bounds:
            lines += _connections(bd, several, None)
        if not lines:
            return "no connections found: no SIGNAL()/SLOT() string pairs and no connectImpl call sites."
        return fit_lines(lines, bud, "code", tool="qt_metaobjects", args=args)[0]
    if not ident:
        total = 0
        for bd in bounds:
            for r in bd.store.db.execute(
                    "SELECT c.name, c.parent, c.meta_addr, c.nsignals, c.nprops, c.nenums, c.nmethods, "
                    "(SELECT COUNT(*) FROM qt_method m WHERE m.binary_id=c.binary_id AND m.meta_addr=c.meta_addr "
                    " AND m.kind='slot') AS slots, "
                    "(SELECT COUNT(*) FROM qt_method m WHERE m.binary_id=c.binary_id AND m.meta_addr=c.meta_addr "
                    " AND m.addr IS NOT NULL) AS mapped "
                    "FROM qt_class c WHERE c.binary_id=? ORDER BY c.name, c.meta_addr", (bd.binary.id,)):
                total += 1
                line = f"{_prefix(bd, several)}{r['name']}"
                if r["parent"]:
                    line += f" : {r['parent']}"
                line += (f" meta {bd.addr(r['meta_addr'])} signals {r['nsignals']} slots {r['slots']} "
                         f"methods {r['nmethods']} (mapped {r['mapped']}) props {r['nprops']}")
                if r["nenums"]:
                    line += f" enums {r['nenums']}"
                lines.append(line)
        return fit_lines(lines, bud, "code", tool="qt_metaobjects", args=args, max_lines=limit)[0]
    hits = [(bd, c) for bd in bounds for c in _find_classes(bd, ident)]
    if not hits:
        return f"error not_found: no Qt class '{ident}'."
    if len(hits) > 1 and not any(c["name"].lower() == ident.lower() for _bd, c in hits):
        names = [f"{_prefix(bd, several)}{c['name']}" for bd, c in hits]
        shown = ", ".join(names[:10]) + (f" (+{len(names) - 10} more)" if len(names) > 10 else "")
        return f"error ambiguous: '{ident}' matches {len(names)} classes: {shown}."
    for bd, c in hits[:3]:
        db, bid, meta = bd.store.db, bd.binary.id, c["meta_addr"]
        head = f"{_prefix(bd, several)}{c['name']}"
        if c["parent"]:
            head += f" : {c['parent']}"
        head += f" meta {bd.addr(meta)} Qt{c['major']} rev {c['revision']}"
        if c["metacall"]:
            head += f" dispatcher {bd.addr(c['metacall'])}"
        lines.append(head)
        if c["info"]:
            lines.append("  info " + c["info"])
        sections = (("signal", "signals"), ("slot", "slots"), ("method", "invokable"), ("constructor", "constructors"))
        for kind, label in sections:
            rows = db.execute("SELECT idx, name, ret, params, access, flags, addr FROM qt_method "
                              "WHERE binary_id=? AND meta_addr=? AND kind=? ORDER BY idx", (bid, meta, kind)).fetchall()
            if not rows:
                continue
            lines.append(f"{label}:")
            for r in rows:
                sig = f"{r['name']}({r['params']})"
                ret = f"{r['ret']} " if r["ret"] and r["ret"] != "void" else ""
                flag = " (default args)" if r["flags"] & 0x20 else ""
                tail = f" {_fn_name(bd, r['addr'])}" if r["addr"] else ""
                lines.append(f"  [{r['idx']}] {r['access']} {ret}{sig}{flag}{tail}".replace("  [", "  [", 1))
        props = db.execute("SELECT p.idx, p.name, p.type, p.flags, p.notify FROM qt_prop p WHERE p.binary_id=? AND "
                           "p.meta_addr=? ORDER BY p.idx", (bid, meta)).fetchall()
        if props:
            lines.append("properties:")
            sigs = {r["idx"]: r["name"] for r in db.execute(
                "SELECT idx, name FROM qt_method WHERE binary_id=? AND meta_addr=? AND kind='signal'", (bid, meta))}
            for p in props:
                rw = ("r" if p["flags"] & 1 else "") + ("w" if p["flags"] & 2 else "") + \
                     ("c" if p["flags"] & 0x400 else "")
                n = f" notify {sigs.get(p['notify'], p['notify'])}" if p["notify"] is not None else ""
                lines.append(f"  {p['name']}: {p['type']} {rw}{n}")
        enums = db.execute("SELECT name, is_flag, vals FROM qt_enum WHERE binary_id=? AND meta_addr=? ORDER BY idx",
                           (bid, meta)).fetchall()
        if enums:
            lines.append("enums:")
            for e in enums:
                lines.append(f"  {'flags ' if e['is_flag'] else ''}{e['name']}: {e['vals']}")
        conns = _connections(bd, several, c)
        if conns:
            lines.append("connections:")
            lines += ["  " + x for x in conns]
    if len(hits) > 3:
        rest = [f"{_prefix(bd, several)}{c['name']}" for bd, c in hits[3:]]
        lines.append(f"… {len(rest)} more classes match: " + ", ".join(rest[:10])
                     + (f" (+{len(rest) - 10} more)" if len(rest) > 10 else ""))
    return fit_lines(lines, bud, "code", tool="qt_metaobjects", args=args)[0]
