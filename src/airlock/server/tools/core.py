"""core set: open_binary, list_binaries, outline, search, function, xrefs, callgraph, strings.

Output is compact plain text, one item per line (DESIGN.md section 7.4); lists are
cut to the token budget with a cursor; errors are one line `error <code>: ...`.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any

from airlock.index.store import CrossRef, Function, StringHit
from airlock.projects import read_manifest, read_sections
from airlock.server.bulk import BG_TIMEOUT
from airlock.server.budget import (
    STORE, CursorError, estimate_tokens, fit_lines, fit_text, resume_lines,
)
from airlock.server.context import ServerContext
from airlock.server.cview import outline_lines, reduce_c
from airlock.server.indexer import IndexerError, worker_error
from airlock.server.registry import tool
from airlock.server.selectors import fmt_addr, parse_address, resolve_function
from airlock.server.tools.common import (
    Bound, bind_binary, bind_many, bind_target, bound_of, budget_for, fn_desc, preview,
)
from airlock.worker.protocol import WorkerError

_HEX = re.compile(r"^[0-9a-fA-F]+$")
MAX_DEPTH = 6
CALLGRAPH_FANOUT = 15
CALLGRAPH_MAX_LINES = 500


def _cursor_page(cursor: str, tool_name: str, budget: int) -> str:
    try:
        return resume_lines(cursor, budget, "code", tool=tool_name)[0]
    except CursorError as e:
        return e.message


def _page(lines: list[str], tool_name: str, args: dict, budget: int) -> str:
    return fit_lines(lines, budget, "code", tool=tool_name, args=args)[0]


# ── open_binary / list_binaries ────────────────────────────────────────────────

def _binary_line(b, status: str, project: str | None = None) -> str:
    head = f"{project}/" if project else ""
    return (f"{head}#{b.id} {b.name} {b.format or '?'} {b.arch or '?'} {b.toolchain or '?'} "
            f"sha256:{b.sha256[:12]} {status}")


@tool("open_binary", "Register a PE file in a project and start Ghidra analysis in the background; "
                     "returns at once, then poll index_status.")
def open_binary(ctx: ServerContext, project: str, path: str) -> str:
    if not project.strip():
        return "error bad_args: project is empty. Pass a project name."
    try:
        res = ctx.indexer.open_binary(project, path)
    except IndexerError as e:
        return e.message
    out = [_binary_line(res.binary, "status=" + res.status)]
    if res.status == "error":
        out.append(ctx.indexer.describe(ctx.indexer.current or project,
                                        ctx.indexer.store(ctx.indexer.current or project),
                                        res.binary)[1])
    elif res.status != "ready":
        out.append("Analysis takes minutes. Call index_status; tools work once status is ready.")
    if res.note:
        out.append(res.note)
    return "\n".join(out)


@tool("list_binaries", "List the binaries of a project (all projects when none is given) with "
                       "status, group, code size, functions and cross-binary links out/in.")
def list_binaries(ctx: ServerContext, project: str = "") -> str:
    ix = ctx.indexer
    try:
        names = [ix.resolve_project(project)] if project else ix.projects()
    except IndexerError as e:
        return e.message
    out = []
    for p in names:
        st = ix.store(p)
        try:
            files = {f.get("sha256"): f for f in read_manifest(ix.paths(p).manifest).get("files") or []
                     if isinstance(f, dict)}
        except (OSError, ValueError):
            files = {}
        for b in st.list_binaries():
            line = _binary_line(b, ix.describe(p, st, b)[0], p)
            mf = files.get(b.sha256) or {}
            if mf.get("group"):
                line += f" group={mf['group']}"
            if mf.get("code_size"):
                line += f" code={_size(int(mf['code_size']))}"
            out_n, in_n = st.cross_counts(b.id)
            line += f" fns={st.counts(b.id)['functions']} links={out_n}/{in_n}"
            out.append(line)
    return "\n".join(out) if out else "no binaries. Call open_binary with a project and a file path."


def _size(n: int) -> str:
    return f"{n / (1 << 20):.1f}MB" if n >= 1 << 20 else f"{max(1, round(n / 1024))}KB"


# ── outline ────────────────────────────────────────────────────────────────────

@tool("outline", "Summarise a binary: sections, entry point, imported DLLs, function counts.")
def outline(ctx: ServerContext, binary: str = "") -> str:
    bd = bind_binary(ctx, binary)
    if isinstance(bd, str):
        return bd
    st, b = bd.store, bd.binary
    ix = ctx.indexer
    out = [f"{b.name} {b.format} {b.arch} {b.toolchain} ptr {b.pointer_size} "
           f"base {bd.addr(b.image_base or 0)} sha256:{b.sha256[:12]}"]
    artifact = ix.paths(bd.project).artifacts / b.sha256
    if artifact.is_file():
        from airlock.projects import detect
        info = detect(artifact)
        if info.entry_point is not None and b.image_base is not None:
            ep = b.image_base + info.entry_point
            fn = st.function_containing(b.id, ep)
            out.append(f"entry {bd.addr(ep)}" + (f" {fn.qualified_name}" if fn else ""))
        secs = read_sections(artifact)
        if secs:
            out.append("sections " + ", ".join(f"{n} {f} {bd.addr(b.image_base + rva)}+0x{vs:x}"
                                               for n, rva, vs, f in secs))
    c = st.counts(b.id)
    states = ", ".join(f"{k} {v}" for k, v in st.count_by_name_state(b.id).items())
    out.append(f"functions {c['functions']} ({states}; thunks {c['thunks']}, external {c['externals']})")
    dlls = st.import_dll_counts(b.id)
    shown = ", ".join(f"{d} {n}" for d, n in dlls[:10])
    more = f", +{len(dlls) - 10} more DLLs" if len(dlls) > 10 else ""
    out.append(f"imports {c['imports']} from {len(dlls)} DLLs: {shown}{more}")
    out.append(f"exports {len(st.exports_of(b.id))}")
    others = {o.name.lower() for o in st.list_binaries() if o.id != b.id}
    mine = [(d, n) for d, n in dlls if d.lower() in others]
    if mine:
        out.append("imports from project binaries: " + ", ".join(f"{d} {n}" for d, n in mine))
    out.append(f"strings {c['strings']}, edges {c['edges']}, decompiled {c['decompiled']}")
    return "\n".join(out)


# ── search ─────────────────────────────────────────────────────────────────────

_SEARCH_KINDS = {"function": ("function",), "string": ("string",), "import": ("import",),
                 "any": ("function", "string", "import")}
_UNINDEXED_KINDS = ("const", "class", "note")


@tool("search", "Full-text search over function names, strings and imports; hits are one line each.")
def search(ctx: ServerContext, query: str = "", binary: str = "", kind: str = "any",
           limit: int = 20, cursor: str = "", budget: int = 0) -> str:
    bud = budget_for(ctx, budget)
    if cursor:
        return _cursor_page(cursor, "search", bud)
    if not query.strip():
        return "error bad_args: query is empty. Pass words to look for."
    if kind in _UNINDEXED_KINDS:
        return (f"error not_supported: kind '{kind}' is not indexed yet. "
                "Use function, string, import or any.")
    if kind not in _SEARCH_KINDS:
        return f"error bad_args: unknown kind '{kind}'. Use function, string, import or any."
    many = bind_many(ctx, binary)
    if isinstance(many, str):
        return many
    bounds, skipped = many
    multi = len(bounds) > 1
    limit = max(1, min(int(limit), 200))
    # Fetch more than `limit` per kind: dedup drops rows, and ranking needs candidates.
    fetch = limit * 5 + 20
    groups: dict[str, list[tuple[tuple[int, ...], str]]] = {}
    seq = 0
    for bd in bounds:
        seq = _search_binary(bd, query, kind, fetch, groups, seq,
                             f"[{bd.binary.name}] " if multi else "")
    for g in groups.values():
        g.sort(key=lambda x: x[0])
    if kind == "any":
        merged = _balance(groups, limit)
    else:
        merged = [ln for _, ln in groups.get(kind, [])[:limit]]
    if not merged:
        return f"no hits for '{query}'"
    args = {"binary": binary, "query": query, "kind": kind, "limit": limit}
    head = f"search '{query}': {len(merged)} hits"
    if skipped:
        head += f" ({skipped} binaries not ready, skipped)"
    return _page([head, *merged], "search", args, bud)


def _search_binary(bd: Bound, query: str, kind: str, fetch: int,
                   groups: dict[str, list[tuple[tuple[int, ...], str]]], seq: int,
                   pfx: str) -> int:
    """Add one binary's hits to `groups` (lines get the `[binary] ` prefix `pfx`); returns
    the running sequence number, so FTS order stays stable across binaries."""
    st, b = bd.store, bd.binary
    strings: dict[str, tuple[tuple[int, ...], StringHit]] = {}
    for k in _SEARCH_KINDS[kind]:
        for h in st.fts_search(b.id, query, k, fetch):
            seq += 1
            if k == "string":
                s = st.get_string(h.ref_id)
                if s is None or st.has_import_named(b.id, s.value):
                    continue  # the import name table duplicates the import rows
                cur = strings.get(s.value)
                rank = _match_rank(query, s.value)
                if cur is None or s.address < cur[1].address:
                    strings[s.value] = ((rank, 2, seq), s)
                continue
            item = _search_item(bd, h, query)
            if item:
                key, line = item
                groups.setdefault(k, []).append(((*key, seq), pfx + line))
    for value, (key, s) in strings.items():
        total = st.string_copies(b.id, value)
        enc = "" if s.encoding == "ascii" else f" {s.encoding}"
        extra = f" (+{total - 1} copies)" if total > 1 else ""
        groups.setdefault("string", []).append(
            (key, f"{pfx}string {bd.addr(s.address)}{enc} {preview(s.value)}{extra}"))
    return seq


_QUOTA = (("function", 0.4), ("import", 0.2), ("string", 0.2))


def _balance(groups: dict[str, list[tuple[tuple[int, ...], str]]], limit: int) -> list[str]:
    """Pick up to `limit` lines: each kind with hits gets its quota first (functions
    40%, imports 20%, strings 20%; one slot each is reserved first), unused
    slots then go to the kinds with leftovers in the same order. Output order:
    functions, imports, strings; rank order inside each group."""
    have = {k: len(groups.get(k, [])) for k, _ in _QUOTA}
    take = {k: 0 for k, _ in _QUOTA}
    left = limit
    for k, _ in _QUOTA:  # one slot per kind with hits
        n = min(have[k], 1, left)
        take[k] += n
        left -= n
    for k, share in _QUOTA:  # fill to the quota
        n = min(have[k], math.ceil(limit * share)) - take[k]
        n = max(0, min(n, left))
        take[k] += n
        left -= n
    for k, _ in _QUOTA:  # surplus flows on
        n = min(have[k] - take[k], left)
        take[k] += n
        left -= n
    return [ln for k, _ in _QUOTA for _, ln in groups.get(k, [])[:take[k]]]


def _match_rank(query: str, *names: str) -> int:
    """0 exact name match, 1 prefix, 2 token (anything else FTS returned)."""
    q = query.strip().lower()
    low = [n.lower() for n in names if n]
    if q in low:
        return 0
    if any(n.startswith(q) for n in low):
        return 1
    return 2


def _search_item(bd: Bound, h, query: str) -> tuple[tuple[int, int], str] | None:
    """(sort key, output line) for one FTS hit, or None when the hit is dropped.

    Order within a kind: match rank (exact name, then prefix, then token); named
    functions (user/library/recovered) before FUN_ ones. Strings are handled by the
    caller (import-name drop, collapse). Ties keep FTS order (caller appends the sequence number). An EXTERNAL
    function row is dropped when a non-external function or an import row has the
    same name; otherwise it is shown as `import-only DLL::Name` without its
    pseudo address."""
    st = bd.store
    if h.kind == "function":
        fn = st.get_function(h.ref_id)
        if fn is None:
            return None
        rank = _match_rank(query, fn.name, fn.qualified_name)
        if fn.is_external:
            if st.has_local_twin(fn.binary_id, fn.name):
                return None
            return (rank, 3), f"import-only {fn.qualified_name}"
        extra = f"{fn.size}B" if fn.size else ""
        flags = ",".join(x for x in (fn.name_state, "thunk" if fn.is_thunk else "", extra) if x)
        group = 1 if fn.name.startswith("FUN_") else 0
        return (rank, group), f"function {fn.qualified_name} {bd.addr(fn.entry, fn.space)} {flags}"
    row = st.get_import(h.ref_id)
    if row is None:
        return None
    name = row["name"] or f"#{row['ordinal']}"
    slot = f" slot {bd.addr(row['address'])}" if row["address"] is not None else ""
    rank = _match_rank(query, name, f"{row['dll']}!{name}")
    return (rank, 3), f"import {row['dll']}!{name}{slot}"


# ── function ───────────────────────────────────────────────────────────────────

def annotate_calls(c_text: str, nodes, psize: int) -> str:
    """Append ``/*0xaddr*/`` after each call's callee token, unless the callee's name
    already carries the address (FUN_00401234)."""
    inserts: list[tuple[int, str]] = []
    for n in nodes:
        if n["kind"] != "call" or n["target"] is None:
            continue
        end = n["end_off"]
        if c_text[n["start_off"]:end] != (n["text"] or ""):
            continue
        if f"{n['target']:x}" in (n["text"] or "").lower():
            continue
        inserts.append((end, f"/*{fmt_addr(n['target'], psize)}*/"))
    for pos, text in sorted(inserts, reverse=True):
        c_text = c_text[:pos] + text + c_text[pos:]
    return c_text


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timeout_error(fn: Function, what: Any) -> str:
    return (f"error decompile_timeout: {fn.qualified_name}: {what}. "
            "Try view=signature or xrefs, or raise defaults.decompile_timeout_s.")


def _get_decompiled(ctx: ServerContext, bd: Bound, fn: Function,
                    retry: bool = False) -> tuple[str | None, str | None]:
    """(c_text, error line). Uses the cache when fn_version and analysis_profile match.
    A timeout row from the background pass (short timeout) gets one decompile with the full
    timeout; a timeout from a full-timeout attempt is not repeated unless retry is set."""
    st, b = bd.store, bd.binary
    profile = b.analysis_profile or "unknown"
    cached = st.get_decomp(fn, profile)
    if cached is not None and cached.status == "ok" and cached.c_text is not None:
        return cached.c_text, None
    if (cached is not None and cached.status == "timeout" and not retry
            and not (cached.error or "").startswith(BG_TIMEOUT)):
        return None, _timeout_error(fn, cached.error or "timeout") + " Pass retry=true to try again."
    ix = ctx.indexer
    timeout = int(ctx.config.defaults.get("decompile_timeout_s") or 60)
    try:
        ix.ensure_open(bd.project)
        d = ctx.worker.request("decompile", {
            "program": ix.program_of(st, b), "entry": fn.entry, "timeout": timeout,
        }, timeout=timeout + 120)
    except WorkerError as e:
        return None, worker_error(e, "Call index_status to check the worker")
    if d.get("status") != "ok":
        st.upsert_decomp(fn.id, fn.version, profile, d.get("status") or "error",
                         error=d.get("error"), produced_at=_now())
        what = d.get("error") or d.get("status")
        if d.get("status") == "timeout":
            return None, _timeout_error(fn, what)
        return None, (f"error decompile_failed: {fn.qualified_name}: {what}. "
                      "Try view=signature or xrefs, or raise defaults.decompile_timeout_s.")
    st.upsert_decomp(fn.id, fn.version, profile, "ok", c_text=d["c_text"], produced_at=_now())
    cols = d["ast_columns"]
    st.insert_ast_nodes(fn.id, [dict(zip(cols, row)) for row in d["ast"]])
    return d["c_text"], None


def _parse_lines(spec: str) -> tuple[int, int] | None:
    m = re.fullmatch(r"\s*(\d+)\s*(?:-\s*(\d*))?\s*", spec)
    if not m:
        return None
    a = int(m.group(1))
    b = int(m.group(2)) if m.group(2) else (a if "-" not in spec else 10**9)
    return (max(a, 1), max(b, a))


@tool("function", "Show a function's decompiled C with call addresses (view=c) or its signature "
                  "(view=signature), by name or address.")
def function(ctx: ServerContext, target: str = "", binary: str = "", view: str = "c",
             lines: str = "", cursor: str = "", budget: int = 0, detail: str = "brief",
             outline: bool = True, retry: bool = False) -> str:
    bud = budget_for(ctx, budget, "function_budget")
    if not target.strip():
        return "error bad_target: target is empty. Pass a function name or an address like 0x00401000."
    if view in ("asm", "both"):
        return (f"error not_implemented: view={view} is not available yet. "
                "Use view=c or view=signature.")
    if view not in ("c", "signature"):
        return f"error bad_args: unknown view '{view}'. Use c or signature."
    if detail not in ("brief", "full"):
        return f"error bad_args: unknown detail '{detail}'. Use brief or full."
    span = None
    if lines:
        span = _parse_lines(lines)
        if span is None:
            return "error bad_args: lines must look like 40-80. Fix and retry."
    bt = bind_target(ctx, binary, target)
    if isinstance(bt, str):
        return bt
    bd, bare, bnote = bt
    st, b = bd.store, bd.binary
    r = resolve_function(st, b.id, bare)
    if not r.ok:
        return r.error or "error not_found: no such function. Use search."
    fn = r.function
    assert fn is not None
    note = r.note or (f"binary {b.name}" if bnote else None)
    if view == "signature":
        callers = len(st.callers(fn, 200)) if not fn.is_external else 0
        sig = fn.signature or fn.qualified_name
        flags = ", ".join(x for x in (fn.calling_conv, f"{fn.size} bytes" if fn.size else None,
                                      fn.name_state, "thunk" if fn.is_thunk else None,
                                      "external" if fn.is_external else None) if x)
        out = ([note] if note else []) + [
            f"{bd.addr(fn.entry, fn.space)} {sig} [{flags}] callers {callers}"]
        return "\n".join(out)
    if fn.is_external:
        return (f"error external: {fn.qualified_name} is an imported function with no code. "
                "Use xrefs on it to see its callers.")
    args = {"binary": binary, "target": target, "view": view, "lines": lines, "detail": detail}
    oargs = {**args, "outline": 1}
    identity = (b.id, fn.entry, fn.version, b.analysis_profile)
    offset = 0
    if cursor:
        try:
            cur = STORE.get(cursor, "function")
            if cur.lines is not None:   # continuation of an outline
                STORE.get(cursor, "function", oargs)
                return resume_lines(cursor, bud, "code", tool="function", args=oargs)[0]
            offset = STORE.get(cursor, "function", args, identity).offset
        except CursorError as e:
            return e.message
    c_text, err = _get_decompiled(ctx, bd, fn, retry)
    if err:
        return err
    assert c_text is not None
    full = annotate_calls(c_text, st.get_ast_nodes(fn.id, "call"), bd.psize).rstrip("\n")
    full = reduce_c(full, detail)   # after annotation: it needs raw char offsets
    if outline and not cursor and not span and estimate_tokens(full, "code") > bud:
        all_lines = full.split("\n")
        head = (f"// {fn.qualified_name} {bd.addr(fn.entry, fn.space)}: {len(all_lines)} lines, "
                f"~{estimate_tokens(full, 'code')} tokens (budget {bud}). "
                "Read with lines=a-b, or outline=false to page.")
        olines = ([f"// {note}"] if note else []) + outline_lines(all_lines, head)
        return fit_lines(olines, bud, "code", tool="function", args=oargs)[0]
    return _function_page(full, bud, span, lines, offset, note, args, identity)


def _function_page(full: str, bud: int, span: tuple[int, int] | None, lines: str,
                   offset: int, note: str | None, args: dict, identity: tuple) -> str:
    """One page of decompiled C. Line numbers count C lines only (not the note).

    If the page does not hold the whole function, a header line gives the page's
    line range plus the function's total lines and tokens, so the agent can decide
    to page on, ask for `lines=`, or raise `budget`.
    """
    all_lines = full.split("\n")
    n_total = len(all_lines)
    first = 1
    body = full
    if span:
        first = span[0]
        body = "\n".join(all_lines[span[0] - 1: span[1]])
        if not body:
            return f"error bad_args: lines {lines} is past the end of the function. Use a smaller range."
    prefix = [f"// {note}"] if note else []
    total_tok = estimate_tokens(full, "code")
    if not span and offset == 0 and estimate_tokens("\n".join(prefix + [body]), "code") <= bud:
        return "\n".join(prefix + [body])

    def make_header(start: int, end: int) -> str:
        return (f"// lines {start}-{end} of {n_total}, function ~{total_tok} tokens "
                f"(budget {bud}). More: cursor, lines=a-b or budget=<n>.")

    # Reserve note + header (worst-case digit width) before cutting the body.
    reserved = sum(estimate_tokens(ln + "\n", "code")
                   for ln in prefix + [make_header(n_total, n_total)])
    page, remaining = fit_text(body, max(1, bud - reserved), "code", offset=offset,
                               tool="function", args=args, identity=identity)
    start = first + body[:offset].count("\n")
    shown = body[offset:].count("\n") + 1 - remaining
    end = start + shown - 1
    return "\n".join(prefix + [make_header(start, end), page])


# ── xrefs ──────────────────────────────────────────────────────────────────────

_KIND_MAP = {"call": ("call", "call_ind"), "jump": ("jump",), "read": ("read",),
             "write": ("write",), "data": ("data",), "import": ("import",), "dynamic": ("dynamic",)}


def _resolve_ref_target(bd: Bound, target: str):
    """('fn', Function, note) | ('addr', (space, value)) | ('err', message)."""
    st, b = bd.store, bd.binary
    addr = parse_address(target)
    if addr is None and not st.functions_by_name(b.id, target.strip()) \
            and _HEX.match(target.strip()):
        addr = ("ram", int(target.strip(), 16))
    if addr is None:
        r = resolve_function(st, b.id, target)
        return ("fn", r.function, r.note) if r.ok else ("err", r.error)
    fn = st.function_at(b.id, addr[1], addr[0])
    if fn is not None:
        return ("fn", fn, None)
    has_refs = (st.xrefs_to_address(b.id, addr[1], None, 1) or
                st.xrefs_from_address(b.id, addr[1], None, 1))
    if not has_refs:  # nothing at the address itself: an interior address means its function
        r = resolve_function(st, b.id, target)
        if r.ok:
            return ("fn", r.function, r.note)
    return ("addr", addr)


def _describe_addr(bd: Bound, addr: int, fn: Function | None) -> str:
    st, b = bd.store, bd.binary
    if fn is not None and fn.entry == addr:
        return fn.qualified_name
    s = st.string_at(b.id, addr)
    if s is not None:
        return preview(s.value, 40)
    imp = st.import_at(b.id, addr)
    if imp is not None:
        return st.import_label(imp)
    if fn is not None:
        return f"{fn.qualified_name}+0x{addr - fn.entry:x}"
    return "-"


@tool("xrefs", "List references to (or from) a function or address, one line each with the "
               "referencing function and kind.")
def xrefs(ctx: ServerContext, target: str = "", binary: str = "", direction: str = "to",
          kind: str = "", limit: int = 50, cursor: str = "", budget: int = 0) -> str:
    bud = budget_for(ctx, budget)
    if cursor:
        return _cursor_page(cursor, "xrefs", bud)
    if not target.strip():
        return "error bad_target: target is empty. Pass a function name or an address."
    if direction not in ("to", "from"):
        return "error bad_args: direction must be to or from. Fix and retry."
    kinds = None
    if kind:
        kinds = _KIND_MAP.get(kind)
        if kinds is None:
            return (f"error bad_args: unknown kind '{kind}'. "
                    "Use call, jump, read, write, data, import or dynamic.")
    bt = bind_target(ctx, binary, target)
    if isinstance(bt, str):
        return bt
    bd, bare, bnote = bt
    st, b = bd.store, bd.binary
    limit = max(1, min(int(limit), 1000))
    res = _resolve_ref_target(bd, bare)
    if res[0] == "err":
        return res[1]
    notes: list[str] = [bnote] if bnote else []
    entries: list[tuple[str, str]] = []   # (kind, line)
    cross: list[CrossRef] = []            # callers from other binaries (direction=to)
    links: list[CrossRef] = []            # where an import slot or thunk here resolves to
    if res[0] == "fn":
        fn: Function = res[1]
        if res[2]:
            notes.append(res[2])
        label = fn_desc(bd, fn)
        if fn.space != "ram":  # imported function: callers reach it through its IAT slot
            slots = [i["address"] for i in st.imports_by_name(b.id, fn.name)
                     if i["address"] is not None]
        else:
            slots = []
        if direction == "to":
            if fn.space != "ram":
                refs = []
                for a in slots:
                    refs += st.xrefs_to_address(b.id, a, kinds, limit + 1)
            else:
                refs = st.xrefs_to_function(fn, kinds, limit + 1)
                cross = st.cross_to_function(fn, limit + 1)
        else:
            refs = st.xrefs_from_function(fn, kinds, limit + 1)
        for a in ([fn.entry] if fn.space == "ram" else []) + slots:
            links += st.cross_from_address(b.id, a, 5)
    else:
        space, value = res[1]
        s = st.string_at(b.id, value)
        label = bd.addr(value, space) + (f" {preview(s.value, 40)}" if s else "")
        notes.append("no function starts here; showing raw references")
        refs = (st.xrefs_to_address if direction == "to" else st.xrefs_from_address)(
            b.id, value, kinds, limit + 1)
        links = st.cross_from_address(b.id, value, 5)
    for x in links[:5]:
        notes.append(_cross_target(bd, x))
    for x in refs:
        if direction == "to":
            who = x.src_fn.qualified_name if x.src_fn else "-"
            entries.append((x.kind, f"  {bd.addr(x.src_addr)}  {who:<36} {x.kind}"))
        else:
            what = _describe_addr(bd, x.dst_addr, x.dst_fn)
            entries.append((x.kind, f"  {bd.addr(x.src_addr)}  -> {bd.addr(x.dst_addr)} {what:<30} "
                                    f"{x.kind}"))
    for x in cross:
        if kinds is not None and x.kind not in kinds:
            continue
        sb = bound_of(bd, x.src_binary)
        imp = sb.store.import_at(x.src_binary, x.src_addr)
        who = (x.src_fn.qualified_name if x.src_fn else
               sb.store.import_label(imp) if imp else "-")
        entries.append((x.kind, f"  [{sb.binary.name}] {sb.addr(x.src_addr)}  {who:<36} {x.kind}"))
    over = len(entries) > limit
    entries = entries[:limit]
    counts: dict[str, int] = {}
    for k, _ in entries:
        counts[k] = counts.get(k, 0) + 1
    if len(counts) == 1:
        (k, n), = counts.items()
        summary = f"{n} {k}{'s' if n != 1 else ''}"
    else:
        summary = f"{len(entries)} refs: " + ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
    if not entries:
        summary = "no references"
    out = [f"xrefs {direction} {label}, {summary}{'+' if over else ''}", *notes]
    out += [ln for _, ln in entries]
    if over:
        out.append(f"… limit {limit} reached. Raise limit or filter with kind.")
    args = {"binary": binary, "target": target, "direction": direction, "kind": kind,
            "limit": limit}
    return _page(out, "xrefs", args, bud)


def _cross_target(bd: Bound, x: CrossRef) -> str:
    """``→ engine.dll!Foo 0x10001000``: where an import slot or thunk resolves to."""
    db = bound_of(bd, x.dst_binary)
    name = x.dst_fn.qualified_name if x.dst_fn else None
    return ((f"→ {db.binary.name}!{name} " if name else f"→ {db.binary.name}!") + db.addr(x.dst_entry)
            + (" (dynamic)" if x.kind == "dynamic" else ""))


# ── callgraph ──────────────────────────────────────────────────────────────────

@tool("callgraph", "Show the call tree below (callees) or above (callers) a function as an "
                   "indented list; cycles are marked.")
def callgraph(ctx: ServerContext, target: str = "", binary: str = "", direction: str = "callees",
              depth: int = 2, cursor: str = "", budget: int = 0) -> str:
    bud = budget_for(ctx, budget)
    if cursor:
        return _cursor_page(cursor, "callgraph", bud)
    if not target.strip():
        return "error bad_target: target is empty. Pass a function name or an address."
    if direction not in ("callees", "callers"):
        return "error bad_args: direction must be callees or callers. Fix and retry."
    depth = max(1, min(int(depth), MAX_DEPTH))
    bt = bind_target(ctx, binary, target)
    if isinstance(bt, str):
        return bt
    bd, bare, bnote = bt
    st, b = bd.store, bd.binary
    r = resolve_function(st, b.id, bare)
    if not r.ok:
        return r.error or "error not_found: no such function. Use search."
    root = r.function
    assert root is not None
    out = [f"{direction} of {fn_desc(bd, root)}, depth {depth}"]
    if bnote:
        out.append(bnote)
    if r.note:
        out.append(r.note)
    base = len(out)
    expanded = {root.id}
    state = {"truncated": False}
    dyn: set[tuple[int, int]] = set()   # (binary id, entry) of hops that are run-time loaded

    def children(cb: Bound, fn: Function) -> list[tuple[Bound, Function | None, str, int | None]]:
        """(bound, function, hop mark, raw address): local edges first, then links into
        other binaries (callees: an import slot or thunk to the exporting function; callers:
        importing thunks and the callers of their import slots)."""
        s_ = cb.store
        step = s_.callees if direction == "callees" else s_.callers
        kids: list[tuple[Bound, Function | None, str, int | None]] = [
            (cb, c, "", None) for c in step(fn, CALLGRAPH_FANOUT + 1)]
        if direction == "callees":
            hops: set[tuple[int, int]] = set()
            for x in s_.cross_from_function(fn, CALLGRAPH_FANOUT + 1):
                if (x.dst_binary, x.dst_entry) in hops:   # thunk and its slot: one hop
                    continue
                hops.add((x.dst_binary, x.dst_entry))
                if x.kind == "dynamic":
                    dyn.add((x.dst_binary, x.dst_entry))
                db = bound_of(cb, x.dst_binary)
                kids.append((db, x.dst_fn, f"→ [{db.binary.name}] ", x.dst_entry))
        else:
            seen = {c.id for _, c, _, _ in kids if c is not None}
            for x in s_.cross_to_function(fn, CALLGRAPH_FANOUT + 1):
                sb = bound_of(cb, x.src_binary)
                if x.src_fn is not None and x.src_fn.entry == x.src_addr:
                    srcs = [x.src_fn]   # a thunk: its own callers come with expanding it
                else:                   # an import slot: the functions that call through it
                    srcs = [r_.src_fn for r_ in sb.store.xrefs_to_address(
                        x.src_binary, x.src_addr, ("call", "call_ind", "jump"),
                        CALLGRAPH_FANOUT + 1) if r_.src_fn]
                for f_ in srcs:
                    if f_.id not in seen:
                        seen.add(f_.id)
                        if x.kind == "dynamic":
                            dyn.add((x.src_binary, f_.entry))
                        kids.append((sb, f_, f"← [{sb.binary.name}] ", None))
        return kids

    def label(cb: Bound, f: Function | None, mark: str, raw: int | None) -> str:
        suffix = ""
        if mark and (cb.binary.id, f.entry if f is not None else raw) in dyn:
            suffix = " (dynamic)"
        if f is None:
            return mark + cb.addr(raw or 0) + suffix
        return mark + fn_desc(cb, f) + (" [thunk]" if f.is_thunk else "") + suffix

    def walk(cb: Bound, fn: Function, left: int, indent: int, path: frozenset[int]) -> None:
        kids = children(cb, fn)
        for kb, c, mark, raw in kids[:CALLGRAPH_FANOUT]:
            if len(out) >= CALLGRAPH_MAX_LINES:
                state["truncated"] = True
                return
            pad = "  " * indent
            lab = label(kb, c, mark, raw)
            if c is None:
                out.append(f"{pad}{lab}")
            elif c.id in path:
                out.append(f"{pad}{lab} [cycle]")
            elif c.id in expanded:
                out.append(f"{pad}{lab} [seen]")
            else:
                out.append(f"{pad}{lab}")
                if left > 1:
                    expanded.add(c.id)
                    walk(kb, c, left - 1, indent + 1, path | {c.id})
        if len(kids) > CALLGRAPH_FANOUT:
            out.append(f"{'  ' * indent}… more than {CALLGRAPH_FANOUT} {direction} not shown")

    walk(bd, root, depth, 1, frozenset({root.id}))
    if len(out) == base:
        out.append("  (none)")
    if state["truncated"]:
        out.append(f"… stopped at {CALLGRAPH_MAX_LINES} lines. Lower depth.")
    args = {"binary": binary, "target": target, "direction": direction, "depth": depth}
    return _page(out, "callgraph", args, bud)


# ── strings ────────────────────────────────────────────────────────────────────

@tool("strings", "Find defined strings by substring or regex (case-insensitive) with the "
                 "functions that reference them.")
def strings(ctx: ServerContext, pattern: str = "", binary: str = "", regex: bool = False,
            with_refs: bool = True, limit: int = 30, cursor: str = "", budget: int = 0) -> str:
    bud = budget_for(ctx, budget)
    if cursor:
        return _cursor_page(cursor, "strings", bud)
    if not pattern:
        return "error bad_args: pattern is empty. Pass text or a regex."
    if regex:
        try:
            re.compile(pattern)
        except re.error as e:
            return f"error bad_regex: {e}. Fix the pattern and retry."
    many = bind_many(ctx, binary)
    if isinstance(many, str):
        return many
    bounds, skipped = many
    multi = len(bounds) > 1
    limit = max(1, min(int(limit), 500))
    per_binary: list[list[str]] = []
    capped = False
    for bd in bounds:
        hits = bd.store.search_strings(bd.binary.id, pattern, regex=regex, limit=limit,
                                       with_refs=with_refs)
        capped = capped or len(hits) == limit
        lines_b = []
        for h in hits:
            enc = "" if h.encoding == "ascii" else f" {h.encoding}"
            line = f"{'[' + bd.binary.name + '] ' if multi else ''}{bd.addr(h.address)}{enc} "                    f"{preview(h.value)}"
            if with_refs:
                if h.refs:
                    names = " ".join(f.qualified_name for f in h.refs[:4])
                    extra = f" +{len(h.refs) - 4}" if len(h.refs) > 4 else ""
                    line += f"  <- {names}{extra}"
                else:
                    line += "  <- (no refs)"
            lines_b.append(line)
        per_binary.append(lines_b)
    # Round-robin over the binaries, so one chatty binary cannot crowd out the others.
    merged: list[str] = []
    for i in range(max((len(x) for x in per_binary), default=0)):
        merged += [x[i] for x in per_binary if i < len(x)]
    capped = capped or len(merged) > limit
    merged = merged[:limit]
    if not merged:
        return f"no strings match '{pattern}'"
    head = f"strings matching '{pattern}': {len(merged)}{'+' if capped else ''}"
    if skipped:
        head += f" ({skipped} binaries not ready, skipped)"
    out = [head, *merged]
    args = {"binary": binary, "pattern": pattern, "regex": regex, "with_refs": with_refs,
            "limit": limit}
    return _page(out, "strings", args, bud)
