"""map set: overview, project_describe, features, feature, feature_define (dirty sessions only).

The project map and the feature index let an agent work on the whole program or on one feature.
Every line carries the identifiers for the next call. DESIGN 4 "Project map and feature index".
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from airlock.index.store import Store
from airlock.projects import ProjectPaths
from airlock.server import features as fx
from airlock.server import projectmap as pm
from airlock.server.budget import (
    CursorError, estimate_tokens, fit_lines, footer, resume_lines,
)
from airlock.server.context import ServerContext
from airlock.server.registry import tool
from airlock.server.selectors import fmt_addr, resolve_function, split_binary_target
from airlock.server.tools.common import budget_for

_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9:_.-]{0,47}$")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _session(ctx: ServerContext) -> tuple[ProjectPaths, Store] | str:
    pp = ctx.session.project
    if pp is None:
        return "error unbound: no project is open. Call projects, then project_open."
    return pp, ctx.indexer.store(pp.name)


def _page(lines: list[str], budget: int, tool_name: str, args: dict | None = None) -> str:
    return fit_lines(lines, budget, "prose", tool=tool_name, args=args)[0]


def _resume(cursor: str, budget: int, tool_name: str, args: dict | None = None) -> str:
    try:
        return resume_lines(cursor, budget, "prose", tool=tool_name, args=args)[0]
    except CursorError as e:
        return e.message


def refresh_maps(ctx: ServerContext, pp: ProjectPaths, store: Store, derive: bool = False) -> None:
    """Re-derive the auto features (optional) and rewrite both PROJECT.md files."""
    if derive:
        fx.derive_project(pp, store)
    pm.write_maps(pp, store, mermaid=bool(ctx.config.defaults.get("mermaid")))


@tool("overview", "Return the project map: purpose, binaries, relations, features with "
                  "coverage, knowledge, frontier and where to write.")
def overview(ctx: ServerContext, cursor: str = "", budget: int = 0) -> str:
    bud = budget_for(ctx, budget)
    if cursor:
        return _resume(cursor, bud, "overview")
    s = _session(ctx)
    if isinstance(s, str):
        return s
    pp, st = s
    return _page(pm.render_dirty(pp, st, heading=False), bud, "overview")


@tool("project_describe", "Set the purpose paragraph of the project map (what the program does, "
                          "no binary names or addresses).")
def project_describe(ctx: ServerContext, purpose: str = "") -> str:
    s = _session(ctx)
    if isinstance(s, str):
        return s
    pp, st = s
    text = " ".join(purpose.split())
    if not text:
        return ("error empty_purpose: purpose is empty. Pass one short paragraph about what the "
                "program does.")
    if len(text) > 1500:
        return f"error too_long: purpose has {len(text)} characters, the limit is 1500. Shorten it."
    pm.set_purpose(st, text)
    pm.write_maps(pp, st, mermaid=bool(ctx.config.defaults.get("mermaid")))
    return f"purpose set ({len(text)} chars). Maps updated: {pp.dirty / 'PROJECT.md'}, {pp.clean / 'PROJECT.md'}."


@tool("features", "List the features of the program with entry-point counts and coverage; "
                  "refresh=true derives them again.")
def features(ctx: ServerContext, refresh: bool = False, cursor: str = "", budget: int = 0) -> str:
    bud = budget_for(ctx, budget)
    if cursor:
        return _resume(cursor, bud, "features")
    s = _session(ctx)
    if isinstance(s, str):
        return s
    pp, st = s
    if refresh or not st.feature_stats():
        if any(st.get_meta(f"status:{b.id}") == "ready" for b in st.list_binaries()):
            refresh_maps(ctx, pp, st, derive=True)
    rows = fx.stats(st)
    if not rows:
        return "no features yet. They are derived when a binary is ready; feature_define adds one."
    lines = [f"{r['key']}{' [agent]' if r['source'] == 'agent' else ''} | {r['title']} | "
             f"{pm.plural(r['n'], 'entry point')} | coverage {fx.coverage(r['n'], r['named'])} | "
             f"feature(key=\"{r['key']}\")" for r in rows]
    return _page(lines, bud, "features")


def _entry_line(store: Store, names: dict[int, tuple[str, int]], r) -> str:
    bn, ps = names.get(r["binary_id"], ("?", 4))
    nm = (f"{r['namespace']}::{r['name']}" if r["namespace"] else r["name"]) or "?"
    state = r["name_state"] or "?"
    bits = [bn, f"{nm} ({fmt_addr(r['entry'], ps, r['space'])})", state, r["reason"]]
    if r["evidence"] and r["evidence"] != r["reason"]:
        bits.append(r["evidence"])
    if r["source"] == "agent":
        bits.append("agent")
    return " | ".join(bits)


def _cost(line: str) -> int:
    return estimate_tokens(line + "\n", "prose")


def _limited(lines: list[str], head: int, limit: int, budget: int, tool_name: str, args: dict) -> str:
    """fit_lines with at most `limit` entry lines after `head` header lines on this page."""
    if limit < 1 or len(lines) - head <= limit:
        return _page(lines, budget, tool_name, args)
    cut = lines[:head + limit]
    need = sum(_cost(x) for x in cut) + estimate_tokens(footer(99999, "c_0000") + "\n", "prose")
    return _page(lines, min(budget, need), tool_name, args)


@tool("feature", "List the entry points of one feature (binary, function, address, reason, "
                 "evidence) so it can be reverse engineered alone.")
def feature(ctx: ServerContext, key: str = "", limit: int = 40, cursor: str = "",
            budget: int = 0) -> str:
    bud = budget_for(ctx, budget)
    key = key.strip().lower()
    args = {"key": key}
    if cursor:
        return _resume(cursor, bud, "feature", args)
    s = _session(ctx)
    if isinstance(s, str):
        return s
    pp, st = s
    row = st.get_feature(key) if key else None
    if row is None:
        have = ", ".join(r["key"] for r in fx.stats(st)) or "none"
        return f"error not_found: no feature '{key}' (have: {have}). Call features."
    names = {b.id: (b.name, b.pointer_size or 4) for b in st.list_binaries()}
    ents = st.feature_entries(key)
    named = sum(1 for r in ents if (r["name_state"] or "auto") != "auto")
    head = [f"feature {key}{' [agent]' if row['source'] == 'agent' else ''}: {row['title']} | "
            f"{pm.plural(len(ents), 'entry point')}, coverage {fx.coverage(len(ents), named)}"]
    if row["evidence"]:
        head.append(f"evidence: {row['evidence']}")
    head.append(f"topics: {key}" + (f", {row['topics']}" if row["topics"] else "")
                + " | notes 0 | specs 0 | unnamed first. Next: function(binary, target), rename/annotate, "
                  "spec_write(topic)")
    lines = head + [_entry_line(st, names, r) for r in ents]
    return _limited(lines, len(head), int(limit), bud, "feature", args)


def _resolve_targets(st: Store, tokens: list[str]) -> tuple[list[tuple[int, str, int, str]], str | None]:
    """[(binary id, space, entry, label)] for the function tokens, or a one-line error."""
    ready = [b for b in st.list_binaries() if st.get_meta(f"status:{b.id}") == "ready"]
    out: list[tuple[int, str, int, str]] = []
    for tok in tokens:
        bname, bare = split_binary_target(st, tok)
        pool = [b for b in ready if not bname or b.name.lower() == bname.lower()]
        if not pool:
            return [], f"error not_ready: no ready binary for '{tok}'. Call list_binaries."
        found = []
        errs = []
        for b in pool:
            r = resolve_function(st, b.id, bare)
            if r.function is not None:
                found.append((b, r.function))
            elif r.error:
                errs.append(r.error)
        if not found:
            return [], errs[0] if errs else f"error not_found: no function '{tok}'. Use search."
        if len(found) > 1:
            where = ", ".join(b.name for b, _ in found)
            return [], (f"error ambiguous_binary: '{tok}' exists in {where}. "
                        "Write it as binary!function.")
        b, fn = found[0]
        out.append((b.id, fn.space, fn.entry, fn.qualified_name))
    return out, None


@tool("feature_define", "Add or refine a feature by key, title, functions (comma list, "
                        "binary!name or address) and topics.")
def feature_define(ctx: ServerContext, key: str, title: str = "", functions: str = "",
                   topics: str = "") -> str:
    s = _session(ctx)
    if isinstance(s, str):
        return s
    pp, st = s
    key = key.strip().lower()
    if not _KEY_RE.match(key):
        return (f"error bad_key: '{key}' is not a feature key. Use lowercase letters, digits and - : _ ., "
                "e.g. open-project-file.")
    cur = st.get_feature(key)
    title = " ".join(title.split()) or (cur["title"] if cur else "")
    if not title:
        return f"error need_title: new feature '{key}' needs a title. Pass title=."
    toks = [t.strip() for t in functions.replace("\n", ",").split(",") if t.strip()]
    targets, err = _resolve_targets(st, toks)
    if err:
        return err
    tp = ", ".join(t.strip() for t in topics.split(",") if t.strip()) if topics else \
        (cur["topics"] if cur else "")
    st.define_feature(key, title, tp, _now())
    by_bin: dict[int, list[tuple[str, int, str]]] = {}
    for bid, space, entry, _label in targets:
        by_bin.setdefault(bid, []).append((space, entry, f"agent: {title}"))
    for bid, rows in by_bin.items():
        st.add_feature_entries(key, bid, rows)
    refresh_maps(ctx, pp, st)
    n = len(st.feature_entries(key))
    return (f"feature {key} {'updated' if cur else 'defined'}: {title} | {pm.plural(len(targets), 'function')} added, "
            f"{pm.plural(n, 'entry point')}. feature(key=\"{key}\") lists them.")
