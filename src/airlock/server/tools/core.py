"""core set: open_binary, list_binaries, outline, search, function, xrefs, callgraph, strings.

Output is compact plain text, one item per line (DESIGN.md section 7.4); lists are
cut to the token budget with a cursor; errors are one line `error <code>: ...`.
"""

from __future__ import annotations

import json
import math
import re
import time
from datetime import datetime, timezone
from typing import Any

from airlock.index.store import (CODE_EDGES, CrossRef, Function, StringHit, Xref,
                                is_transient_decomp_error)
from airlock.projects import read_manifest, read_sections
from airlock.server.bulk import BG_TIMEOUT
from airlock.server.budget import (
    STORE, CursorError, estimate_tokens, fit_lines, fit_text, note_kept, resume_lines,
)
from airlock.server.context import ServerContext
from airlock.server.cview import (
    OUTLINE_DEFAULT_DEPTH, OUTLINE_MAX_DEPTH, block_listing, format_asm, outline_lines, reduce_c,
)
from airlock.server.indexer import IndexerError, worker_error
from airlock.server.registry import add_note, call as call_tool, tool
from airlock.server.selectors import fmt_addr, parse_address
from airlock.server import classfwd, cpp, delphi, dotnet, dotnet_meta, notes, qt, uijoin
from airlock.server import targets as tg
from airlock.server.tools.common import (
    Bound, bind_binary, bind_many, bind_scope, bound_of, budget_for, fn_desc, normalize_kind, preview,
)
from airlock.worker.protocol import WorkerError

_HEX = re.compile(r"^[0-9a-fA-F]+$")
MAX_DEPTH = 6
CALLGRAPH_FANOUT = 15
CALLGRAPH_MAX_LINES = 500
CALLGRAPH_FULL = 5000   # the whole list of one cut node, behind a cursor


def _cursor_page(cursor: str, tool_name: str, budget: int, max_lines: int = 0) -> str:
    try:
        return resume_lines(cursor, budget, "code", tool=tool_name, max_lines=max_lines)[0]
    except CursorError as e:
        return e.message


def _page(lines: list[str], tool_name: str, args: dict, budget: int, max_lines: int = 0,
          page: int = 0) -> str:
    return fit_lines(lines, budget, "code", tool=tool_name, args=args, max_lines=max_lines,
                     page=page)[0]


# ── open_binary / list_binaries ────────────────────────────────────────────────

def _binary_line(b, status: str, project: str | None = None) -> str:
    head = f"{project}/" if project else ""
    host = (b.original_path or "").partition("!")[0] if "!" in (b.original_path or "") else ""
    return (f"{head}#{b.id} {b.name}{f' (in {host})' if host else ''} {b.format or '?'} "
            f"{b.arch or '?'} {b.toolchain or '?'} sha256:{b.sha256[:12]} {status}")


@tool("open_binary", "Register a PE file in a project and start Ghidra analysis in the background; "
                     "returns at once, then poll index_status.")
def open_binary(ctx: ServerContext, project: str, path: str) -> str:
    if not project.strip():
        return "error bad_args: project is empty."
    try:
        res = ctx.indexer.open_binary(project, path)
    except IndexerError as e:
        return e.message
    out = [_binary_line(res.binary, "status=" + res.status)]
    if res.status == "error":
        out.append(ctx.indexer.describe(ctx.indexer.current or project,
                                        ctx.indexer.store(ctx.indexer.current or project),
                                        res.binary)[1])
    elif res.status not in ("finishing", "ready"):
        out.append("analysis takes minutes; tools work from status finishing on")
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
    return "\n".join(out) if out else "no binaries"


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
        if b.toolchain == "dotnet":    # the managed entry point, not the native stub
            tok = info.cli_entry
            fn = st.function_containing(b.id, tok) if tok else None
            out.append(f"entry {fn.qualified_name} 0x{tok:08x}" if fn else
                       f"entry managed 0x{tok:08x}" if tok else "entry none (no managed entry point)")
        if not info.managed_only and info.entry_point is not None and b.image_base is not None:
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
                 "note": ("note",), "any": ("function", "string", "import", "note")}
_UNINDEXED_KINDS = ("const", "class")
_FORWARD_KINDS = {"const": ("constants", "value"), "class": ("rtti_classes", "query")}


@tool("search", "Full-text search over function names, strings and imports; hits are one line each.")
def search(ctx: ServerContext, query: str = "", binary: str = "", kind: str = "any",
           limit: int = 20, cursor: str = "", budget: int = 0) -> str:
    bud = budget_for(ctx, budget)
    if cursor:
        return _cursor_page(cursor, "search", bud, max(1, min(int(limit), 200)))
    if not query.strip():
        return "error bad_args: query is empty."
    fixed, note = normalize_kind(kind, (*_SEARCH_KINDS, *_UNINDEXED_KINDS))
    if fixed:
        kind = fixed
        if note:
            add_note(note)
    if kind in _UNINDEXED_KINDS:      # not in the full-text index: the tool that has them answers
        name, param = _FORWARD_KINDS[kind]
        if name not in ctx.config.tools:
            return f"error not_supported: kind '{kind}' needs {name}, which is off in config.jsonc."
        out = call_tool(ctx, name, **{param: query, "binary": binary})
        return out if out.startswith("error ") else f"({name} used for kind={kind})\n{out}"
    if kind not in _SEARCH_KINDS:
        return f"error bad_args: unknown kind '{kind}' (kinds: function, string, import, note, any, const, class)."
    many = bind_many(ctx, binary)
    if isinstance(many, str):
        return many
    bounds, skipped = many
    multi = len(bounds) > 1
    limit = max(1, min(int(limit), 200))
    # Fetch more than `limit` per kind: dedup drops rows, and ranking needs candidates.
    fetch = max(SEARCH_FETCH, limit * 5 + 20)
    groups: dict[str, list[tuple[tuple[int, ...], str]]] = {}
    seq = 0
    for bd in bounds:
        seq = _search_binary(bd, query, kind, fetch, groups, seq,
                             f"[{bd.binary.name}] " if multi else "")
    if kind in ("any", "function"):
        _program_body_hit(ctx, binary, query, groups, multi)
    for g in groups.values():
        g.sort(key=lambda x: x[0])
    if kind == "any":
        first = _balance(groups, limit)       # page 1 keeps the mix of kinds; the rest follows
        seen = set(first)
        rest = [ln for k, _ in _QUOTA for _, ln in groups.get(k, []) if ln not in seen]
        merged = first + rest
    else:
        merged = [ln for _, ln in groups.get(kind, [])]
    if not merged:
        return f"no hits for '{query}'"
    capped = any(len(g) >= fetch for g in groups.values())     # a hard cap: the count is a floor
    args = {"binary": binary, "query": query, "kind": kind, "limit": limit}
    head = f"search '{query}': {len(merged)}{'+' if capped else ''} hits"
    if skipped:
        head += f" ({skipped} binaries not ready, skipped)"
    return _page([head, *merged], "search", args, bud, limit + 1, limit)


def _program_body_hit(ctx: ServerContext, binary: str, query: str,
                       groups: dict[str, list[tuple[tuple[int, ...], str]]], multi: bool) -> None:
    """`main` / `WinMain` / `PASCALMAIN` / `program` in a Delphi or FPC program: no function has that name,
    the program body is found by the entry point (the same rule as the `function` target). Adds
    `function <body> addr (program body: main)` as the top function hit."""
    if query.strip().lower() not in tg._PROGRAM_NAMES:
        return
    try:
        t = tg.resolve_target(ctx, binary, query.strip(), (tg.FUNCTION,))
    except Exception:  # noqa: BLE001  the search stands without it
        return
    if not isinstance(t, tg.FunctionTarget) or "program body" not in (t.note or ""):
        return
    bd, fn = t.bound, t.fn
    pfx = f"[{bd.binary.name}] " if multi else ""
    groups.setdefault("function", []).append(
        ((0, 0, 0), f"{pfx}function {fn.qualified_name} {bd.addr(fn.entry, fn.space)} "
                    f"(program body: {query.strip()})"))


def _qt_method_hits(bd: Bound, query: str, fetch: int,
                    groups: dict[str, list[tuple[tuple[int, ...], str]]], seq: int, pfx: str) -> int:
    """Qt signals, slots and methods and published Delphi methods by name: such a method often sits
    in a FUN_ function, so the function name index cannot find it. Adds
    `function Class::name addr (Qt slot)` / `function TClass.name addr (Delphi published)` lines."""
    q = query.strip().lower()
    if not q or " " in q:
        return seq
    rows: list[tuple[str, str, str, int]] = []
    for sql, sep in (
            ("SELECT c.name, m.name, m.kind, m.addr FROM qt_method m JOIN qt_class c "
             "ON c.binary_id=m.binary_id AND c.meta_addr=m.meta_addr "
             "WHERE m.binary_id=? AND m.addr IS NOT NULL AND instr(lower(m.name), ?) > 0 "
             "ORDER BY m.name LIMIT ?", "::"),
            ("SELECT c.name, m.name, 'Delphi ' || m.kind, m.addr FROM dl_method m JOIN dl_class c "
             "ON c.binary_id=m.binary_id AND c.vmt=m.vmt "
             "WHERE m.binary_id=? AND m.name<>'' AND instr(lower(m.name), ?) > 0 "
             "ORDER BY m.name LIMIT ?", ".")):
        try:
            got = bd.store.db.execute(sql, (bd.binary.id, q, fetch)).fetchall()
        except Exception:       # no framework tables in an older index: nothing to add
            continue
        rows += [(f"{r[0]}{sep}{r[1]}", r[1], r[2] if r[2].startswith("Delphi") else f"Qt {r[2]}", r[3])
                 for r in got]
    for full, name, kind, addr in rows:
        at = f" {bd.addr(addr)} "
        line = f"{pfx}function {full}{at}({kind})"
        fns = groups.setdefault("function", [])
        fun = f"{pfx}function FUN_"
        if any(at in x + " " and not x.startswith(fun) for _, x in fns):
            continue            # a named function hit already covers this address
        fns[:] = [(k, x) for k, x in fns if not (at in x + " " and x.startswith(fun))]
        seq += 1
        fns.append(((_match_rank(query, name), 0, seq), line))
    return seq


def _mfc_handler_hits(bd: Bound, query: str, fetch: int,
                      groups: dict[str, list[tuple[tuple[int, ...], str]]], seq: int, pfx: str) -> int:
    """Generated MFC handler names (`Class::OnCommand_<id>_<leaf>`, see `uijoin.UiIndex.suggest`) of
    handlers that are still FUN_ functions: adds `function Class::name addr (MFC handler)` lines."""
    q = query.strip().lower()
    if not q or " " in q:
        return seq
    try:
        ui = uijoin.UiIndex(bd.store, bd.binary.id)
        hs = list(ui.handlers)
    except Exception:           # noqa: BLE001  no message map tables
        return seq
    seen: set[int] = set()
    n = 0
    for h in hs:
        if h.addr in seen or n >= fetch:
            continue
        fn = bd.store.function_at(bd.binary.id, h.addr)
        if not uijoin.is_unnamed(fn):
            continue
        name = ui.suggest(h)
        if q not in f"{h.cls}::{name}".lower():
            continue
        seen.add(h.addr)
        n += 1
        at = f" {bd.addr(h.addr)} "
        fns = groups.setdefault("function", [])
        fun = f"{pfx}function FUN_"
        if any(at in x + " " and not x.startswith(fun) for _, x in fns):
            continue
        fns[:] = [(k, x) for k, x in fns if not (at in x + " " and x.startswith(fun))]
        seq += 1
        fns.append(((_match_rank(query, name), 0, seq), f"{pfx}function {h.cls}::{name}{at}(MFC handler)"))
    return seq


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
    if kind in ("any", "function"):
        seq = _qt_method_hits(bd, query, fetch, groups, seq, pfx)
        seq = _mfc_handler_hits(bd, query, fetch, groups, seq, pfx)
    for value, (key, s) in strings.items():
        total = st.string_copies(b.id, value)
        enc = "" if s.encoding == "ascii" else f" {s.encoding}"
        extra = f" (+{total - 1} copies)" if total > 1 else ""
        groups.setdefault("string", []).append(
            (key, f"{pfx}string {bd.addr(s.address)}{enc} {preview(s.value)}{extra}"))
    return seq


_QUOTA = (("function", 0.4), ("import", 0.2), ("string", 0.2), ("note", 0.2))


SEARCH_FETCH = 200


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
    if h.kind == "note":
        row = st.get_note(h.ref_id)
        if row is None:
            return None
        nfn = st.function_at(row["binary_id"], row["entry"], row["space"])
        where = f"{nfn.qualified_name} " if nfn is not None else ""
        return (_match_rank(query, row["summary"]), 0), (
            f"note #{row['id']} {where}{bd.addr(row['entry'], row['space'])} "
            + notes.format_note(row["summary"], row["tags"], row["confidence"], 100))
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


def _vcall_names(c_text: str, bd: Bound, fn: Function, ctx: ServerContext | None = None) -> str:
    """Slot (and method) comment after each virtual-call stub name, dynamic index after each dynamic-method
    dispatcher call, class name after each VMT address (vcallnames)."""
    if bd.binary.toolchain not in ("delphi", "fpc"):
        return c_text
    from airlock.server import vcallnames
    art = ctx.indexer.paths(bd.project).artifacts / bd.binary.sha256 if ctx is not None else None
    return vcallnames.annotate(c_text, vcallnames.DbClasses(bd.store, bd.binary, fn.entry, artifact=art))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timeout_error(fn: Function, what: Any, top: int) -> str:
    return (f"error decompile_timeout: {fn.qualified_name}: {what}. "
            f"The limit is defaults.decompile_timeout_max_s={top} in config.jsonc.")


SECONDS_PER_KB = 6          # extra decompile time per KB of code beyond ADAPT_FROM (measured, DESIGN 5)
ADAPT_FROM = 8192
RELAXED = {"max_instructions": 1_000_000, "payload_mb": 200}


def adaptive_timeout(ctx: ServerContext, fn: Function) -> tuple[int, int]:
    """(timeout for the first attempt, upper limit) in seconds: ``decompile_timeout_s`` for a normal
    function, more for a large one (``SECONDS_PER_KB`` per KB beyond ``ADAPT_FROM``), never above
    ``decompile_timeout_max_s``."""
    d = ctx.config.defaults
    base = int(d.get("decompile_timeout_s") or 60)
    top = max(base, int(d.get("decompile_timeout_max_s") or 600))
    extra = max(0, (fn.size or 0) - ADAPT_FROM) * SECONDS_PER_KB // 1024
    return min(top, base + extra), top


def _block_listing(ctx: ServerContext, bd: Bound, fn: Function, why: str) -> tuple[str | None, str | None]:
    """Fallback for a function the decompiler could not finish: a one-line note and one line per
    basic block from the disassembly (not cached, not C)."""
    ix = ctx.indexer
    try:
        r = ctx.worker.request("disassemble", {"program": ix.program_of(bd.store, bd.binary),
                                               "entry": fn.entry, "max_instructions": 20000}, timeout=300)
    except WorkerError as e:
        return None, worker_error(e)
    total = r.get("total") if r.get("truncated") else None
    lines = block_listing(r["rows"], bd.psize, total)
    head = f"// decompile failed: {fn.qualified_name}: {why}. Block listing from the disassembly (not C)."
    return head + "\n" + "\n".join(lines), None


def _infra_error(text: str | None) -> bool:
    """A worker or JVM failure, not a decompiler result: never cached, always retried."""
    return is_transient_decomp_error(text)


def _get_decompiled(ctx: ServerContext, bd: Bound, fn: Function,
                    retry: bool = False, listing_ok: bool = False) -> tuple[str | None, str | None]:
    """(c_text, error line). Uses the cache when fn_version and analysis_profile match.
    A timeout row from the background pass (short timeout) gets one decompile with the adaptive
    timeout (grows with the function size); a function that times out then gets one more try with
    the limits raised and twice the time. A timeout from such an attempt is not repeated unless
    retry is set. ``listing_ok``: a function that still fails comes back as a block listing
    (one `// decompile_timeout` note line, then one line per basic block) instead of an error."""
    st, b = bd.store, bd.binary
    if dotnet.is_managed(b, fn):
        nat = dotnet_meta.native_function(st, b.id, fn)      # C++/CLI: the method body is native code
        if nat is not None:
            text, err = _get_decompiled(ctx, bd, nat, retry, listing_ok)
            return (f"// native body of {fn.qualified_name} at 0x{nat.entry:x}" + chr(10) + f"{text}" if text else text), err
        if not fn.is_thunk and "dotnet_decompile" in ctx.config.tools:
            from airlock.server.tools import dotnet as dn_tools     # late: the tool modules import core
            out = dn_tools.dotnet_decompile(ctx, type=fn.namespace or "", member=f"0x{fn.entry:08x}",
                                           binary=b.name)
            if not out.startswith("error "):
                return out, None
        if not fn.is_thunk:     # no C#: the IL listing is the code there is
            lines, _why = dotnet.il_listing(ctx.indexer.paths(bd.project).artifacts / b.sha256, fn.entry)
            if lines is not None:
                return "\n".join(["// IL (MSIL), not machine code; no C# (dotnet_decompile unavailable)",
                                  *_body_fact(st, fn, "// "), *lines]) + "\n", None
        return None, dotnet.managed_error(b, fn, st)
    profile = b.analysis_profile or "unknown"
    cached = st.get_decomp(fn, profile)
    if cached is not None and cached.status == "ok" and cached.c_text is not None:
        return cached.c_text, None
    if (cached is not None and cached.status in ("timeout", "error") and not retry
            and not (cached.error or "").startswith(BG_TIMEOUT) and not _infra_error(cached.error)):
        if listing_ok:
            return _block_listing(ctx, bd, fn, cached.error or "timeout")
        return None, _timeout_error(fn, cached.error or "timeout", adaptive_timeout(ctx, fn)[1])
    ix = ctx.indexer
    timeout, top = adaptive_timeout(ctx, fn)
    d: dict[str, Any] = {}
    args: dict[str, Any] = {"timeout": timeout}
    for round_ in (1, 2):                   # round 2 only after a transient worker failure
        attempts: list[dict[str, Any]] = [{"timeout": timeout}]
        transient = False
        try:
            ix.ensure_open(bd.project)
            prog = ix.program_of(st, b)
            while attempts:
                args = attempts.pop(0)
                d = ctx.worker.request("decompile", {"program": prog, "entry": fn.entry, **args},
                                       timeout=args["timeout"] + 120)
                if d.get("status") == "timeout" and not attempts and "max_instructions" not in args:
                    attempts.append({**RELAXED, "timeout": min(top, args["timeout"] * 2)})
                elif d.get("status") == "error" and "limit" in str(d.get("error") or "").lower()                         and "max_instructions" not in args:
                    attempts.append({**RELAXED, "timeout": args["timeout"]})
                if d.get("status") == "ok":
                    break
            transient = d.get("status") == "error" and _infra_error(d.get("error"))
        except WorkerError as e:
            if e.code == "busy" and e.message.startswith("the worker is indexing"):
                return None, worker_error(e)    # ensure_open already waited session_wait_s
            if round_ == 2 or e.code not in ("worker_exited", "busy", "no_program") and not _infra_error(e.message):
                return None, worker_error(e)
            transient = True
        if not transient:
            break
        time.sleep(2.0)
    if d.get("status") != "ok":
        if not _infra_error(d.get("error")):
            st.upsert_decomp(fn.id, fn.version, profile, d.get("status") or "error",
                             error=d.get("error"), produced_at=_now())
        what = d.get("error") or d.get("status")
        if d.get("status") == "timeout":
            if listing_ok:
                return _block_listing(ctx, bd, fn, f"{what} after {args['timeout']} s")
            return None, _timeout_error(fn, what, top)
        if listing_ok:
            return _block_listing(ctx, bd, fn, str(what))
        return None, f"error decompile_failed: {fn.qualified_name}: {what}."
    st.upsert_decomp(fn.id, fn.version, profile, "ok", c_text=d["c_text"], produced_at=_now())
    cols = d["ast_columns"]
    st.insert_ast_nodes(fn.id, [dict(zip(cols, row)) for row in d["ast"]])
    text = d["c_text"]
    if d.get("partial"):
        text = text.rstrip("\n") + f"\n// partial decompile: {d['partial']}\n"
    return text, None


def _parse_lines(spec: str) -> tuple[int, int] | None:
    m = re.fullmatch(r"\s*(\d+)\s*(?:-\s*(\d*))?\s*", spec)
    if not m:
        return None
    a = int(m.group(1))
    b = int(m.group(2)) if m.group(2) else (a if "-" not in spec else 10**9)
    return (max(a, 1), max(b, a))


def _asm_cache_file(ctx: ServerContext, bd: Bound, fn: Function):
    return ctx.indexer.paths(bd.project, create=True).data / "cache" / "asm" / f"{bd.binary.id}_{fn.entry:x}.json"


def _get_asm(ctx: ServerContext, bd: Bound, fn: Function) -> tuple[list[str] | None, str | None]:
    """(asm lines, error line). JSON file cache keyed by fn_version and analysis_profile
    (derived data, safe to delete)."""
    st, b = bd.store, bd.binary
    if dotnet.is_managed(b, fn):
        nat = dotnet_meta.native_function(st, b.id, fn)      # C++/CLI: the method body is native code
        if nat is not None:
            lines, err = _get_asm(ctx, bd, nat)
            return ([f"; native body of {fn.qualified_name} at 0x{nat.entry:x}", *lines] if lines else lines), err
        if fn.is_thunk:
            return None, dotnet.managed_error(b, fn, st)
        lines, why = dotnet.il_listing(ctx.indexer.paths(bd.project).artifacts / b.sha256, fn.entry)
        if lines is None:
            return None, f"error managed: {fn.qualified_name}: no IL listing ({why})."
        return ["; IL (MSIL), not machine code", *_body_fact(st, fn, "; "), *lines], None
    profile = b.analysis_profile or "unknown"
    path = _asm_cache_file(ctx, bd, fn)
    try:
        d = json.loads(path.read_text(encoding="utf8"))
        if d.get("version") == fn.version and d.get("profile") == profile and isinstance(d.get("lines"), list):
            return d["lines"], None
    except (OSError, ValueError):
        pass
    ix = ctx.indexer
    try:
        ix.ensure_open(bd.project)
        r = ctx.worker.request("disassemble", {"program": ix.program_of(st, b), "entry": fn.entry}, timeout=300)
    except WorkerError as e:
        return None, worker_error(e)
    total = r.get("total") if r.get("truncated") else None
    lines = format_asm(r["rows"], bd.psize, total)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"version": fn.version, "profile": profile, "lines": lines},
                                   separators=(",", ":")), encoding="utf8")
    except OSError:
        pass  # the cache is an optimisation
    return lines, None


def _asm_response(ctx: ServerContext, bd: Bound, fn: Function, note: str | None, view: str,
                  span: tuple[int, int] | None, lines: str, detail: str, retry: bool,
                  bud: int, args: dict) -> str:
    """view=asm: header + instruction lines. view=both: C section, then asm section, one
    paged line list (no outline). `lines=a-b` selects asm lines (asm only)."""
    asm, err = _get_asm(ctx, bd, fn)
    if err:
        return err
    assert asm is not None
    body: list[str] = []
    if view == "both":
        c_text, err = _get_decompiled(ctx, bd, fn, retry, listing_ok=True)
        if err:
            return err
        assert c_text is not None
        c = reduce_c(_vcall_names(annotate_calls(c_text, bd.store.get_ast_nodes(fn.id, "call"), bd.psize), bd, fn, ctx).rstrip(chr(10)), detail)
        body = ["// C"] + c.split(chr(10)) + [f"// asm ({len(asm)} lines)"]
    first = 1
    full_asm = asm
    if span:
        asm = asm[span[0] - 1: span[1]]
        first = span[0]
        if not asm:
            return f"error bad_args: lines {lines} is past the end of the function ({len(full_asm)} lines)."
    head = f"// {fn.qualified_name} {bd.addr(fn.entry, fn.space)} asm: lines {first}-{first + len(asm) - 1}"
    out = ([f"// {note}"] if note else []) + ([head] if view == "asm" else []) + body + asm
    return fit_lines(out, bud, "code", tool="function", args=args)[0]


CLASS_REFS = 20


def _class_view(ctx: ServerContext, binary: str, target: str, bud: int, cursor: str) -> str | None:
    """``function`` on the VMT or type info address of a Delphi / FPC class: one fact line, the class row, its
    virtual slots, its other methods and the references to it. None when the address is no class."""
    sc = bind_scope(ctx, binary, target)
    if isinstance(sc, str):
        return None
    pa = parse_address(sc.bare)
    if pa is None and not _HEX.match(sc.bare):
        return None
    value = pa[1] if pa is not None else int(sc.bare, 16)
    hits = classfwd.find_classes(list(sc.bounds), value)
    if not hits:
        return None
    args = {"binary": binary, "target": target}
    if cursor:
        try:
            return resume_lines(cursor, bud, "code", tool="function", args=args)[0]
        except CursorError as e:
            return e.message
    several = len({h.bd.binary.id for h in hits}) > 1
    out: list[str] = []
    for h in hits[:3]:
        bd, st = h.bd, h.bd.store
        out += [f"// {classfwd.fact(h, value, several)}", classfwd.class_line(h, several),
                *classfwd.slot_lines(h), *classfwd.dynamic_lines(h), *classfwd.method_lines(h)]
        seen: set[tuple[int, int, str]] = set()
        refs = []
        for a in dict.fromkeys(x for x in (h.vmt, h.typeinfo) if x):
            for x in st.xrefs_to_address(bd.binary.id, a, None, CLASS_REFS + 1):
                if (x.src_addr, x.dst_addr, x.kind) not in seen:
                    seen.add((x.src_addr, x.dst_addr, x.kind))
                    refs.append(x)
        out.append(f"references {len(refs)}{'+' if len(refs) > CLASS_REFS else ''}")
        out += [f"  {bd.addr(x.src_addr)}  {x.src_fn.qualified_name if x.src_fn else '-'}  {x.kind}"
                for x in refs[:CLASS_REFS]]
    return fit_lines(out, bud, "code", tool="function", args=args)[0]


@tool("function", "Show a function's decompiled C with call addresses (view=c), its assembly (view=asm), "
                  "both (view=both) or its signature (view=signature), by name or address; lines=a-b "
                  "reads a range of a long function's outline.")
def function(ctx: ServerContext, target: str = "", binary: str = "", view: str = "c",
             lines: str = "", cursor: str = "", budget: int = 0, detail: str = "brief",
             outline: bool = True, retry: bool = False,
             outline_depth: int = OUTLINE_DEFAULT_DEPTH) -> str:
    bud = budget_for(ctx, budget, "function_budget")
    if cursor:      # a known cursor carries its own arguments
        cur = STORE.peek(cursor, "function")
        if cur is not None and cur.args:
            note_kept(cur, {"binary": binary, "target": target, "view": view, "lines": lines,
                            "detail": detail, "depth": outline_depth})
            ca = cur.args
            binary, target, view = ca.get("binary", ""), ca.get("target", ""), ca.get("view", view)
            lines, detail = ca.get("lines", ""), ca.get("detail", detail)
            outline_depth = ca.get("depth", outline_depth)
    if not target.strip():
        return "error bad_target: target is empty."
    if view not in ("c", "asm", "both", "signature"):
        return f"error bad_args: unknown view '{view}' (views: c, asm, both, signature)."
    if not 0 <= outline_depth <= OUTLINE_MAX_DEPTH:
        return f"error bad_args: outline_depth must be 0 to {OUTLINE_MAX_DEPTH}."
    if view == "both" and lines:
        return "error bad_args: lines applies to view=c or view=asm, not both."
    if detail not in ("brief", "full"):
        return f"error bad_args: unknown detail '{detail}' (details: brief, full)."
    span = None
    if lines:
        span = _parse_lines(lines)
        if span is None:
            return "error bad_args: lines must look like 40-80."
    ft = tg.resolve_target(ctx, binary, target, (tg.FUNCTION, tg.IMPORT_FN))
    if isinstance(ft, str):
        if ft.startswith("error external:") and view != "signature":    # an import row: no code
            return _import_refs(ctx, target, binary, bud)
        if ft.startswith("error not_found"):                              # a Delphi / FPC VMT or type info address
            cv = _class_view(ctx, binary, target, bud, cursor)
            if cv is not None:
                return cv
            if view != "signature" and ft.startswith("error not_found: no function at or containing"):
                rv = _raw_view(ctx, binary, target, view, bud, cursor, {
                    "binary": binary, "target": target, "view": view, "lines": lines, "detail": detail})
                if rv is not None:
                    return rv
        return ft
    assert isinstance(ft, tg.FunctionTarget)
    bd, fn, note = ft.bound, ft.fn, ft.any_note
    st, b = bd.store, bd.binary
    if not fn.is_external:
        ts = st.table_strings(fn, 3)
        if ts:
            hint = "table string " + ", ".join(preview(t.value, 40) for t in ts[:2])
            hint += f" +{len(ts) - 2}" if len(ts) > 2 else ""
            note = f"{note}; {hint}" if note else hint
    for h in cpp.hints_for(st, b.id, fn.entry) + uijoin.function_hints(st, b.id, fn.entry) \
            + delphi.hints_for(st, b.id, fn.entry) + qt.hints_for(st, b.id, fn.entry):
        note = f"{note}; {h}" if note else h        # RTTI / message map / menu / dialog names: hints only
    nl, other_notes = notes.function_lines(st, fn, author=ctx.author)   # own notes above the code, others after
    if nl:
        note = chr(10).join(([note] + nl) if note else [nl[0][3:], *nl[1:]])
    if view == "signature":
        callers = len(st.callers(fn, 200))
        sig = fn.signature or fn.qualified_name
        flags = ", ".join(x for x in (fn.calling_conv, f"{fn.size} bytes" if fn.size else None,
                                      fn.name_state, "thunk" if fn.is_thunk else None,
                                      "external" if fn.is_external else None) if x)
        out = ([note] if note else []) + [
            f"{bd.addr(fn.entry, fn.space)} {sig} [{flags}] callers {callers}"]
        return "\n".join(out + other_notes)
    if fn.is_external:      # no code to show: its callers are the useful answer
        return _import_refs(ctx, target, binary, bud)
    args = {"binary": binary, "target": target, "view": view, "lines": lines, "detail": detail}
    if view in ("asm", "both"):
        if cursor:
            try:
                return resume_lines(cursor, bud, "code", tool="function", args=args)[0]
            except CursorError as e:
                return e.message
        return _with_tail(_asm_response(ctx, bd, fn, note, view, span, lines, detail, retry, bud, args),
                          other_notes)
    oargs = {**args, "outline": 1, "depth": outline_depth}
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
    c_text, err = _get_decompiled(ctx, bd, fn, retry, listing_ok=True)
    if err:
        return err
    assert c_text is not None
    full = _vcall_names(annotate_calls(c_text, st.get_ast_nodes(fn.id, "call"), bd.psize), bd, fn, ctx).rstrip("\n")
    full = reduce_c(full, detail)   # after annotation: it needs raw char offsets
    if outline and not cursor and not span and estimate_tokens(full, "code") > bud:
        all_lines = full.split("\n")
        head = (f"// {fn.qualified_name} {bd.addr(fn.entry, fn.space)}: {len(all_lines)} lines, "
                f"~{estimate_tokens(full, 'code')} tokens (budget {bud}), outline:")
        olines = ([f"// {note}"] if note else []) + outline_lines(all_lines, head, outline_depth)
        return _with_tail(fit_lines(olines, bud, "code", tool="function", args=oargs)[0], other_notes)
    return _with_tail(_function_page(full, bud, span, lines, offset, note, args, identity), other_notes)


def _with_tail(out: str, tail: list[str]) -> str:
    """Notes of other sessions go after the code, on the last page only (a page with a cursor line has more)."""
    if not tail or out.startswith("error") or "more lines. cursor=" in out.rsplit(chr(10), 1)[-1]:
        return out
    return out + chr(10) + chr(10).join(tail)


RAW_MAX = 200


def _raw_view(ctx: ServerContext, binary: str, target: str, view: str, bud: int, cursor: str,
              args: dict) -> str | None:
    """``function`` on a code address where Ghidra has no function and none could be created: the disassembly
    from that address to the first RET / unconditional jump (at most RAW_MAX instructions), one fact line first.
    None (the not_found line stands) for a clean session, data, or an address Ghidra cannot disassemble."""
    from airlock.server import roles

    if ctx.session.role == roles.CLEAN:
        return None
    if cursor:
        try:
            return resume_lines(cursor, bud, "code", tool="function", args=args)[0]
        except CursorError:
            pass
    ca = tg.code_address(ctx, binary, target)
    if ca is None:
        return None
    bd, value, sc = ca
    ix = ctx.indexer
    try:
        ix.ensure_open(bd.project)
        r = ctx.worker.request("disassemble", {"program": ix.program_of(bd.store, bd.binary), "entry": value,
                                               "raw": True, "max_instructions": RAW_MAX}, timeout=300)
    except (WorkerError, IndexerError):
        return None
    if not r.get("rows"):
        return None
    total = r.get("total") if r.get("truncated") else None
    asm = format_asm(r["rows"], bd.psize, total)
    where = bd.addr(value)
    fact = (f"// no function at {where}; disassembly from there to the first RET or unconditional JMP"
            + (f" (cut at {RAW_MAX} instructions)" if total else ""))
    if not sc.explicit:
        fact += f"; binary {bd.binary.name}"
    return fit_lines([fact] + asm, bud, "code", tool="function", args=args)[0]


def _import_refs(ctx: ServerContext, target: str, binary: str, bud: int) -> str:
    """``function`` on an import with no code: its references, which is what the agent wants next."""
    return "(an import with no code: its references)\n" + xrefs(ctx, target=target, binary=binary,
                                                                 direction="to", budget=bud)


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
            return f"error bad_args: lines {lines} is past the end of the function ({n_total} lines)."
    prefix = [f"// {note}"] if note else []
    total_tok = estimate_tokens(full, "code")
    if not span and offset == 0 and estimate_tokens("\n".join(prefix + [body]), "code") <= bud:
        return "\n".join(prefix + [body])

    def make_header(start: int, end: int) -> str:
        return f"// lines {start}-{end} of {n_total}, function ~{total_tok} tokens (budget {bud})"

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

_KIND_MAP = {"call": ("call", "call_ind", "call_imp"), "jump": ("jump",), "read": ("read",),
             "write": ("write",), "data": ("data",), "import": ("import",), "dynamic": ("dynamic",), "fnptr": ("fnptr",),
             "table": ("table",), "code": ("call", "call_ind", "call_imp", "jump")}


def _describe_addr(bd: Bound, addr: int, fn: Function | None) -> str:
    st, b = bd.store, bd.binary
    if fn is not None and fn.entry == addr:
        return fn.qualified_name
    if dotnet_meta.FIELD_LO <= addr < dotnet_meta.FIELD_HI and b.toolchain == "dotnet":
        lab = dotnet_meta.field_label(st, b.id, addr)             # a .NET field: Type::Field
        if lab:
            return lab
    s = st.string_at(b.id, addr)
    if s is not None:
        return preview(s.value, 40)
    imp = st.import_at(b.id, addr)
    if imp is not None:
        return st.import_label(imp)
    if fn is not None:
        return f"{fn.qualified_name}+0x{addr - fn.entry:x}"
    return "-"


XREFS_FETCH = 1000


@tool("xrefs", "List references to (or from) a function or address, one line each with the "
               "referencing function and kind.")
def xrefs(ctx: ServerContext, target: str = "", binary: str = "", direction: str = "to",
          kind: str = "", limit: int = 50, cursor: str = "", budget: int = 0) -> str:
    bud = budget_for(ctx, budget)
    if cursor:
        return _cursor_page(cursor, "xrefs", bud, max(1, min(int(limit), 1000)))
    if not target.strip():
        return "error bad_target: target is empty."
    if direction not in ("to", "from"):
        return "error bad_args: direction must be to or from."
    kinds = None
    if kind:
        fixed, note = normalize_kind(kind, _KIND_MAP)
        if note:
            add_note(note)
        kinds = _KIND_MAP.get(fixed)
        if kinds is None:
            return (f"error bad_args: unknown kind '{kind}' "
                    "(kinds: call, jump, code, read, write, data, import, dynamic, table).")
    page = max(1, min(int(limit), 1000))
    limit = XREFS_FETCH      # fetch deep; `page` lines are shown, the rest sits behind a cursor
    tr = tg.resolve_target(ctx, binary, target, (tg.FUNCTION, tg.IMPORT, tg.ADDRESS), create=False)
    if isinstance(tr, str) and "::" in target and tr.startswith("error not_found"):
        fld = dotnet_meta.resolve_field(ctx, binary, target)        # a .NET field: Type::Field
        if isinstance(fld, str):
            return fld
        if fld is not None:
            binary, target = fld
            tr = tg.resolve_target(ctx, binary, target, (tg.FUNCTION, tg.IMPORT, tg.ADDRESS), create=False)
    if isinstance(tr, str):
        return tr
    swapped = ""
    if isinstance(tr, tg.ImportTarget) and direction == "from":
        ft = tg.function_of_import(tr)   # only library code or a thunk has outgoing references
        if isinstance(ft, str) or ft.fn.is_external:
            direction = "to"             # nothing goes out of an import: its callers are the answer
            swapped = f"({tr.label} is an import with no code: direction=to used)"
        else:
            tr = ft
    assert not isinstance(tr, (tg.StringTarget, tg.FeatureTarget, tg.ClusterTarget))
    notes: list[str] = [tr.binary_note] if tr.binary_note else []
    if swapped:
        notes.append(swapped)
    entries: list[tuple[str, str]] = []   # (kind, line)
    refs: list[tuple[Bound, Xref]] = []
    cross: list[CrossRef] = []            # callers from other binaries (direction=to)
    links: list[tuple[Bound, CrossRef]] = []   # where an import slot or thunk here resolves to
    multi = False
    if isinstance(tr, tg.ImportTarget):
        bd = tr.bindings[0].bound
        multi = tr.multi
        b0 = tr.bindings[0]
        stub = (b0.thunks or b0.externals or (None,))[0]
        label = (f"{tr.label} (import, {tr.nbinaries} binaries)" if multi
                 else fn_desc(bd, stub) if stub is not None else tr.label)
        refs = tg.import_refs(tr, kinds, limit + 1)
        for ib in tr.bindings:
            for a in [f.entry for f in ib.thunks] + list(ib.slots):
                links += [(ib.bound, x) for x in ib.bound.store.cross_from_address(ib.bound.binary.id, a, 5)]
    elif isinstance(tr, tg.FunctionTarget):
        bd, fn = tr.bound, tr.fn
        st, b = bd.store, bd.binary
        if tr.note:
            notes.append(tr.note)
        label = fn_desc(bd, fn)
        if dotnet.is_managed(b, fn):
            notes += dotnet_meta.link_notes(st, b.id, fn.entry)      # implements / overrides / impl / override
            if direction == "to":
                from airlock.server.tools import dotnet as dotnet_tools
                notes += dotnet_tools.wired_notes(ctx, bd, fn.entry)      # wired: <control>.<Event> (<caption>)
        if fn.space != "ram":  # imported function: callers reach it through its IAT slot
            slots = [i["address"] for i in st.imports_by_name(b.id, fn.name)
                     if i["address"] is not None]
        else:
            slots = []
        if direction == "to":
            if fn.space != "ram":
                xs: list[Xref] = []
                for a in slots:
                    xs += st.xrefs_to_address(b.id, a, kinds, limit + 1)
            else:
                xs = st.xrefs_to_function(fn, kinds, limit + 1)
                cross = st.cross_to_function(fn, limit + 1)
        else:
            xs = st.xrefs_from_function(fn, kinds, limit + 1)
        refs = [(bd, x) for x in xs]
        for a in ([fn.entry] if fn.space == "ram" else []) + slots:
            links += [(bd, x) for x in st.cross_from_address(b.id, a, 5)]
    else:
        bd = tr.bound
        st, b = bd.store, bd.binary
        space, value = tr.space, tr.value
        s = st.string_at(b.id, value)
        label = bd.addr(value, space) + (f" {preview(s.value, 40)}" if s else "")
        notes.append("no function starts here; showing raw references")
        xs = list((st.xrefs_to_address if direction == "to" else st.xrefs_from_address)(
            b.id, value, kinds, limit + 1))
        for ch in classfwd.find_classes([bd], value)[:1]:     # a Delphi / FPC VMT or type info: the class's references
            notes.append(classfwd.fact(ch, value))
            seen = {(x.src_addr, x.dst_addr, x.kind) for x in xs}
            if direction == "to":
                more = [a for a in (ch.vmt, ch.typeinfo) if a and a != value]
                gets = [(st.xrefs_to_address, a) for a in more]
            else:
                gets = ([(st.xrefs_from_address, ch.vmt + i * bd.psize) for i in range(ch.nvirtual)
                         if ch.vmt + i * bd.psize != value] if value == ch.vmt else [])
            for fn_, a in gets:
                for x in fn_(b.id, a, kinds, limit + 1):
                    if (x.src_addr, x.dst_addr, x.kind) not in seen:
                        seen.add((x.src_addr, x.dst_addr, x.kind))
                        xs.append(x)
        refs = [(bd, x) for x in xs]
        links = [(bd, x) for x in st.cross_from_address(b.id, value, 5)]
        if direction == "to" and s is not None and (kinds is None or "table" in kinds):
            for entry, tab, ev in st.string_table_at(b.id, value):
                tf = st.function_at(b.id, entry)
                who = tf.qualified_name if tf else bd.addr(entry)
                entries.append(("table", f"  {bd.addr(tab)}  {who:<36} table ({ev})"))
    for lb, x in links[:5]:
        n = _cross_target(lb, x)
        if n not in notes:
            notes.append(n)
    for rb, x in refs:
        pfx = f"[{rb.binary.name}] " if multi else ""
        if direction == "to":
            who = (x.src_fn.qualified_name if x.src_fn else "-") + _il_site(x)
            entries.append((x.kind, f"  {pfx}{rb.addr(x.src_addr)}  {who:<36} {x.kind}"))
        else:
            what = _describe_addr(rb, x.dst_addr, x.dst_fn)
            entries.append((x.kind, f"  {rb.addr(x.src_addr)}{_il_site(x)}  -> {rb.addr(x.dst_addr)} {what:<30} "
                                    f"{x.kind}"))
    slots_expanded = 0
    seen_callers: set[tuple[int, int, str]] = set()
    for x in cross:
        sb = bound_of(bd, x.src_binary)
        if x.kind in ("mcall", "pinvoke"):          # a MemberRef slot or P/Invoke thunk: its callers
            callers = (sb.store.xrefs_to_function(x.src_fn, kinds or CODE_EDGES, limit + 1)
                       if x.src_fn is not None and x.src_fn.space == "ram"
                       else sb.store.xrefs_to_address(x.src_binary, x.src_addr, kinds or CODE_EDGES, limit + 1))
            if callers:
                slots_expanded += 1
                for c in callers:
                    key = (x.src_binary, c.src_addr, x.kind)
                    if key in seen_callers:
                        continue
                    seen_callers.add(key)
                    who = c.src_fn.qualified_name if c.src_fn else "-"
                    entries.append((c.kind, f"  [{sb.binary.name}] {sb.addr(c.src_addr)}  {who:<36} "
                                            f"{c.kind} (via {x.kind})"))
                continue
        if kinds is not None and x.kind not in kinds:
            continue
        imp = sb.store.import_at(x.src_binary, x.src_addr)
        who = (x.src_fn.qualified_name if x.src_fn else
               sb.store.import_label(imp) if imp else "-")
        entries.append((x.kind, f"  [{sb.binary.name}] {sb.addr(x.src_addr)}  {who:<36} {x.kind}"))
    over = len(entries) > limit      # a hard cap: the real count is unknown
    entries = entries[:limit]
    if slots_expanded:
        notes.append(f"{slots_expanded} cross-assembly reference slot{'s' if slots_expanded != 1 else ''} "
                     "listed as their callers")
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
    args = {"binary": binary, "target": target, "direction": direction, "kind": kind,
            "limit": limit}
    return _page(out, "xrefs", args, bud, page + 1 + len(notes), page)   # header and notes


def _body_fact(st: Any, fn: Function, pfx: str) -> list[str]:
    """``body: Ns.Type+<Run>d__3::MoveNext (async)``: where the code of an async or iterator stub is."""
    return [f"{pfx}body: {c.qualified_name} ({how.split()[0]})" for c, how in st.body_links(fn, True, 3)]


def _il_site(x: Xref) -> str:
    """``+IL_0012``: the IL offset of a .NET call site, empty elsewhere."""
    return f"+IL_{x.site:04x}" if x.site is not None else ""


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
              depth: int = 2, cursor: str = "", budget: int = 0, pointers: bool = True) -> str:
    bud = budget_for(ctx, budget)
    if cursor:
        return _cursor_page(cursor, "callgraph", bud)
    if not target.strip():
        return "error bad_target: target is empty."
    if direction not in ("callees", "callers"):
        return "error bad_args: direction must be callees or callers."
    depth = max(1, min(int(depth), MAX_DEPTH))
    tr = tg.resolve_target(ctx, binary, target, (tg.FUNCTION, tg.IMPORT))
    if isinstance(tr, str):
        return tr
    assert isinstance(tr, (tg.FunctionTarget, tg.ImportTarget))
    imp: tg.ImportTarget | None = None
    if isinstance(tr, tg.ImportTarget):
        ft = tg.function_of_import(tr) if direction == "callees" else None
        if isinstance(ft, tg.FunctionTarget):    # the thunk or library code has callees
            tr = ft
        else:
            imp = tr
    if imp is not None:
        b0 = imp.bindings[0]
        stub = (b0.thunks or b0.externals or (None,))[0]
        bd = b0.bound
        root = None
        head = (f"{imp.label} (import, {imp.nbinaries} binaries)" if imp.multi
                else fn_desc(bd, stub) if stub is not None else imp.label)
        out = [f"{direction} of {head}, depth {depth}"]
        if imp.binary_note:
            out.append(imp.binary_note)
        expanded: set[int] = set()
    else:
        assert isinstance(tr, tg.FunctionTarget)
        bd, root = tr.bound, tr.fn
        out = [f"{direction} of {fn_desc(bd, root)}, depth {depth}"]
        if tr.binary_note:
            out.append(tr.binary_note)
        if tr.note:
            out.append(tr.note)
        expanded = {root.id}
    base = len(out)
    state = {"truncated": False}
    dyn: set[tuple[int, int]] = set()   # (binary id, entry) of hops that are run-time loaded
    ptr: set[tuple[int, int]] = set()   # (binary id, entry) of hops through a function pointer
    bodies: dict[tuple[int, int], str] = {}   # (binary id, entry) of .NET state machine hops -> label

    def children(cb: Bound, fn: Function, lim: int = CALLGRAPH_FANOUT + 1
                 ) -> list[tuple[Bound, Function | None, str, int | None]]:
        """(bound, function, hop mark, raw address): local edges first, then links into
        other binaries (callees: an import slot or thunk to the exporting function; callers:
        importing thunks and the callers of their import slots)."""
        s_ = cb.store
        step = s_.callees if direction == "callees" else s_.callers
        kids: list[tuple[Bound, Function | None, str, int | None]] = [
            (cb, c, "", None) for c in step(fn, lim)]
        if pointers:
            seen_p = {c.id for _, c, _, _ in kids if c is not None}
            pstep = s_.ptr_callees if direction == "callees" else s_.ptr_callers
            for c in pstep(fn, lim):
                if c.id not in seen_p:
                    seen_p.add(c.id)
                    ptr.add((cb.binary.id, c.entry))
                    kids.append((cb, c, "", None))
        seen_b = {c.id for _, c, _, _ in kids if c is not None}
        for c, how in s_.body_links(fn, direction == "callees", lim):     # .NET async / iterator state machine
            if c.id not in seen_b:
                seen_b.add(c.id)
                bodies[(cb.binary.id, c.entry)] = how
                kids.append((cb, c, "", None))
        if dotnet.is_managed(cb.binary, fn):       # interface / virtual dispatch: implementations or the declaration
            for obid, f_, how in dotnet_meta.dispatch_links(s_, cb.binary.id, fn.entry, direction == "callees", lim):
                if f_.id not in seen_b:
                    seen_b.add(f_.id)
                    bodies[(obid, f_.entry)] = how
                    kids.append((bound_of(cb, obid), f_, "", None))
        if direction == "callees":
            hops: set[tuple[int, int]] = set()
            for x in s_.cross_from_function(fn, lim):
                if (x.dst_binary, x.dst_entry) in hops:   # thunk and its slot: one hop
                    continue
                hops.add((x.dst_binary, x.dst_entry))
                if x.kind == "dynamic":
                    dyn.add((x.dst_binary, x.dst_entry))
                db = bound_of(cb, x.dst_binary)
                kids.append((db, x.dst_fn, f"→ [{db.binary.name}] ", x.dst_entry))
        else:
            seen = {c.id for _, c, _, _ in kids if c is not None}
            for x in s_.cross_to_function(fn, lim):
                sb = bound_of(cb, x.src_binary)
                if x.src_fn is not None and x.src_fn.space == "ram" and x.src_fn.entry == x.src_addr:
                    srcs = [x.src_fn]   # a thunk: its own callers come with expanding it
                else:                   # an import slot: the functions that call through it
                    srcs = [r_.src_fn for r_ in sb.store.xrefs_to_address(
                        x.src_binary, x.src_addr, CODE_EDGES,
                        lim) if r_.src_fn]
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
        elif f is not None and not mark and (cb.binary.id, f.entry) in bodies:
            suffix = f" ({bodies[(cb.binary.id, f.entry)]})"
        elif f is not None and not mark and (cb.binary.id, f.entry) in ptr:
            suffix = " (ptr)"
        if f is None:
            return mark + cb.addr(raw or 0) + suffix
        return mark + fn_desc(cb, f) + (" [thunk]" if f.is_thunk else "") + suffix

    def walk(cb: Bound, fn: Function, left: int, indent: int, path: frozenset[int]) -> None:
        walk_kids(children(cb, fn), left, indent, path, fn_desc(cb, fn),
                  lambda: children(cb, fn, CALLGRAPH_FULL))

    def walk_kids(kids: list[tuple[Bound, Function | None, str, int | None]], left: int,
                  indent: int, path: frozenset[int], node: str, full) -> None:
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
            elif left > 1:
                out.append(f"{pad}{lab}")
                expanded.add(c.id)
                walk(kb, c, left - 1, indent + 1, path | {c.id})
            else:   # the depth limit stops here: say whether more lies below
                n_below = len(children(kb, c))
                more = f"{CALLGRAPH_FANOUT}+" if n_below > CALLGRAPH_FANOUT else str(n_below)
                out.append(f"{pad}{lab}" + (f" [{more} {direction} below]" if n_below else ""))
        if len(kids) > CALLGRAPH_FANOUT:
            allk = full()
            lines = [label(kb, c, mark, raw) for kb, c, mark, raw in allk]
            cid = STORE.create_lines("callgraph", {"binary": binary, "target": target,
                                     "direction": direction, "depth": depth, "node": node,
                                     "scope": "list"}, lines, 0)
            out.append(f"{'  ' * indent}… {len(allk) - CALLGRAPH_FANOUT} more {direction} "
                       f"of {node} not shown. cursor={cid}")

    if imp is not None:   # callers of an import: its calling functions in every binary that has it
        mark = "[{}] "
        callers = tg.import_callers(imp, CALLGRAPH_FANOUT + 1) if direction == "callers" else []
        def all_callers():
            return [(cb, f, mark.format(cb.binary.name) if imp.multi else "", None)
                    for cb, f in tg.import_callers(imp, CALLGRAPH_FULL)]
        walk_kids([(cb, f, mark.format(cb.binary.name) if imp.multi else "", None)
                   for cb, f in callers], depth, 1, frozenset(), imp.label, all_callers)
    else:
        assert root is not None
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
    used = ""
    page = max(1, min(int(limit), 500))
    if cursor:
        res = _cursor_page(cursor, "strings", bud, page)
        if not (pattern and res.startswith("error bad_cursor")):
            return res
        used = f"(cursor {cursor} unknown, searched anew)"   # a pattern is given: do the search
    if not pattern:         # no pattern: every defined string, in pages
        regex = False
    elif regex:
        try:
            re.compile(pattern)
        except re.error as e:           # an invalid regex is searched as literal text
            regex, used = False, f"(literal used: bad regex: {e})"
    many = bind_many(ctx, binary)
    if isinstance(many, str):
        return many
    bounds, skipped = many
    limit = STRINGS_FETCH if pattern else 4 * STRINGS_FETCH   # fetch deep; `page` lines are shown, the rest sits behind a cursor
    merged, capped = _string_lines(bounds, pattern, regex, with_refs, limit)
    if pattern and not merged and not regex and _REGEX_CHARS.search(pattern) and _compiles(pattern):
        regex, used = True, "(regex used: no literal match)"    # `a|b`, `^foo`: meant as a regex
        merged, capped = _string_lines(bounds, pattern, regex, with_refs, limit)
    elif pattern and not merged and regex and not used:
        lit, lit_capped = _string_lines(bounds, pattern, False, with_refs, limit)   # a path with backslashes
        if lit:
            regex, used, merged, capped = False, "(literal used: no regex match)", lit, lit_capped
    if not merged:
        return (f"no strings match '{pattern}'" if pattern else "no strings") + (f" {used}" if used else "")
    head = (f"strings matching '{pattern}': " if pattern else "strings: ") + f"{len(merged)}{'+' if capped else ''}"
    if used:
        head += f" {used}"
    if skipped:
        head += f" ({skipped} binaries not ready, skipped)"
    out = [head, *merged]
    args = {"binary": binary, "pattern": pattern, "regex": regex, "with_refs": with_refs,
            "limit": limit}
    return _page(out, "strings", args, bud, page + 1, page)    # +1: the header line


STRINGS_FETCH = 500
_REGEX_CHARS = re.compile(r"[|\^$*+?\[\](){}\\]")


def _compiles(pattern: str) -> bool:
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


def _string_lines(bounds: list[Bound], pattern: str, regex: bool, with_refs: bool,
                  limit: int) -> tuple[list[str], bool]:
    """String hit lines over the binaries, round-robin, cut at ``limit``; (lines, capped)."""
    multi = len(bounds) > 1
    per_binary: list[list[str]] = []
    capped = False
    for bd in bounds:
        hits = bd.store.search_strings(bd.binary.id, pattern, regex=regex, limit=limit,
                                       with_refs=with_refs)
        capped = capped or len(hits) == limit
        lines_b = []
        for h in hits:
            enc = "" if h.encoding == "ascii" else f" {h.encoding}"
            line = (f"{'[' + bd.binary.name + '] ' if multi else ''}{bd.addr(h.address)}{enc} "
                    f"{preview(h.value)}")
            if with_refs:
                if h.refs:
                    names = " ".join(f.qualified_name for f in h.refs[:4])
                    extra = f" +{len(h.refs) - 4}" if len(h.refs) > 4 else ""
                    line += f"  <- {names}{extra}"
                else:
                    line += "  <- (no refs)"
                tfs = bd.store.string_link_fns(bd.binary.id, h.address, 5)
                if tfs:
                    line += "  table: " + " ".join(f.qualified_name for f in tfs[:4])
                    line += f" +{len(tfs) - 4}" if len(tfs) > 4 else ""
            lines_b.append(line)
        per_binary.append(lines_b)
    # Round-robin over the binaries, so one chatty binary cannot crowd out the others.
    merged: list[str] = []
    for i in range(max((len(x) for x in per_binary), default=0)):
        merged += [x[i] for x in per_binary if i < len(x)]
    capped = capped or len(merged) > limit
    return merged[:limit], capped
