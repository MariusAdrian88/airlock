"""dotnet set: dotnet_types, dotnet_decompile (dnfile metadata and ilspycmd, no Ghidra, dirty role only).

Types, methods and P/Invoke declarations come from the derived tables ``dn_*`` (server/dotnet.py).
A P/Invoke bound to an export of a project binary shows ``=> binary!export``; one to a system DLL
stays a plain ``module!entry``. Decompiled C# is a reconstruction: the first line says so.
"""

from __future__ import annotations

import re
from pathlib import Path

from airlock.index.store import Binary
from airlock.server import dotnet as dn
from airlock.server.budget import CursorError, fit_lines, resume_lines
from airlock.server.context import ServerContext
from airlock.server.indexer import IndexerError
from airlock.server.registry import tool
from airlock.server.tools.common import Bound, bind_binary, budget_for


def _page(ctx: ServerContext, lines: list[str], name: str, args: dict, cursor: str, budget: int,
          kind: str = "prose", key: str = "token_budget") -> str:
    bud = budget_for(ctx, budget, key)
    if cursor:
        try:
            return resume_lines(cursor, bud, kind, tool=name, args=args)[0]
        except CursorError as e:
            return e.message
    return fit_lines(lines, bud, kind, tool=name, args=args)[0]


def _scope(ctx: ServerContext, binary: str) -> list[Bound] | str:
    """The managed binaries to look in, their .NET tables filled; or a one-line error."""
    ix = ctx.indexer
    if binary.strip():
        bd = bind_binary(ctx, binary.strip())
        if isinstance(bd, str):
            return bd
        if bd.binary.toolchain != "dotnet":
            return (f"error not_dotnet: '{bd.binary.name}' is a {bd.binary.toolchain or 'native'} binary "
                    "without .NET metadata. Pass a managed assembly or omit binary.")
        bounds = [bd]
    else:
        try:
            proj = ix.resolve_project(None)
        except IndexerError as e:
            return e.message
        st = ix.store(proj)
        bounds = [Bound(proj, st, b) for b in dn.dotnet_binaries(st)
                  if ix.not_ready_error(proj, st, b) is None]
        if not bounds:
            return (f"error not_dotnet: project '{proj}' has no ready managed assembly. "
                    "Add one with program_add or open_binary.")
    art = ix.paths(bounds[0].project).artifacts
    for bd in bounds:
        try:
            dn.ensure(bd.store, bd.binary, art / bd.binary.sha256)
        except Exception as e:  # noqa: BLE001
            return f"error dotnet_failed: cannot read metadata of {bd.binary.name} ({type(e).__name__}). Check logs."
    return bounds


@tool("dotnet_types", "List .NET types, methods and P/Invoke declarations from metadata, with the "
                      "native export each P/Invoke binds to.")
def dotnet_types(ctx: ServerContext, query: str = "", limit: int = 50, binary: str = "",
                 kind: str = "", cursor: str = "", budget: int = 0) -> str:
    args = {"query": query, "limit": limit, "binary": binary, "kind": kind}
    if cursor:
        return _page(ctx, [], "dotnet_types", args, cursor, budget)
    k = kind.strip().lower()
    if k and k not in dn.KINDS:
        return f"error bad_args: kind '{kind}' is not one of {', '.join(dn.KINDS)}. Fix and retry."
    bounds = _scope(ctx, binary)
    if isinstance(bounds, str):
        return bounds
    limit = max(1, min(int(limit), 1000))
    multi = len(bounds) > 1
    head: list[str] = []
    items: list[str] = []
    for bd in bounds:
        t, m, p, c = dn.counts(bd.store, bd.binary.id)
        head.append(f"{bd.binary.name}: {t} types, {m} methods, {p} pinvokes, {c} com")
        pfx = f"[{bd.binary.name}] " if multi else ""
        items += [pfx + ln for ln in dn.list_lines(bd.store, bd.binary.id, query, k)]
    shown = items[:limit]
    what = " ".join(x for x in (f"query '{query.strip()}'" if query.strip() else "",
                                f"kind {k}" if k else "") if x)
    lines = ["dotnet_types " + "; ".join(head) + (f" | {what}: {len(items)} matches" if what else "")]
    lines += shown
    if len(items) > limit:
        lines.append(f"… {len(items) - limit} more. Raise limit or narrow query/kind.")
    elif not items:
        lines.append("no matches" + ("" if what else ". Use query= or kind=pinvoke|method|com."))
    elif not what:
        lines.append("methods and P/Invokes: pass query= or kind=method|pinvoke|com.")
    return _page(ctx, lines, "dotnet_types", args, "", budget)


_SAFE = re.compile(r"[^A-Za-z0-9_.+`-]")


@tool("dotnet_decompile", "Decompile one .NET type to C# with ilspycmd (a reconstruction), optionally "
                          "only one member.")
def dotnet_decompile(ctx: ServerContext, type: str, member: str = "", binary: str = "",
                     cursor: str = "", budget: int = 0) -> str:
    args = {"type": type, "member": member, "binary": binary}
    if cursor:
        return _page(ctx, [], "dotnet_decompile", args, cursor, budget, "code", "function_budget")
    if not type.strip():
        return "error bad_args: type is empty. Pass a type name from dotnet_types."
    exe = ctx.config.ilspycmd
    if exe is None:
        return ('error tool_missing: ilspycmd is not configured. Run "dotnet tool install ilspycmd '
                '--tool-path <folder>" and set "ilspycmd" in config.jsonc to its ilspycmd.exe.')
    if not Path(exe).is_file():
        return (f"error tool_missing: ilspycmd not found at {exe}. Fix \"ilspycmd\" in config.jsonc "
                'or install it with "dotnet tool install ilspycmd --tool-path <folder>".')
    bounds = _scope(ctx, binary)
    if isinstance(bounds, str):
        return bounds
    hits: list[tuple[Bound, str]] = []
    for bd in bounds:
        hits += [(bd, n) for n in dn.find_type(bd.store, bd.binary.id, type)]
    if not hits:
        return (f"error not_found: no type '{type.strip()}' in {', '.join(b.binary.name for b in bounds)}. "
                "Call dotnet_types with query= to find it.")
    if len(hits) > 1:
        shown = ", ".join(f"{bd.binary.name}!{n}" for bd, n in hits[:6])
        more = f" (+{len(hits) - 6} more)" if len(hits) > 6 else ""
        return (f"error ambiguous: '{type.strip()}' matches {len(hits)} types: {shown}{more}. "
                "Pass the full name, and binary= when several assemblies have it.")
    bd, full = hits[0]
    code = _decompiled(ctx, bd, full, Path(exe))
    if code.startswith("error "):
        return code
    text = code
    if member.strip():
        part = dn.member_text(code, member.strip())
        if part is None:
            return (f"error not_found: no member '{member.strip()}' in {full}. "
                    "Call dotnet_types with kind=method and query= to list members.")
        text = f"// member {member.strip()} of {full}\n{part}"
    lines = [dn.REMINDER, f"// binary {bd.binary.name}, type {full}", *text.split("\n")]
    return _page(ctx, lines, "dotnet_decompile", args, "", budget, "code", "function_budget")


def _decompiled(ctx: ServerContext, bd: Bound, full: str, exe: Path) -> str:
    """C# of one type: the cached file, else ilspycmd output written to the cache (or an error line)."""
    b: Binary = bd.binary
    paths = ctx.indexer.paths(bd.project, create=True)
    folder = paths.cache / "dotnet" / b.sha256[:16]
    cached = folder / (_SAFE.sub("_", full) + ".cs")
    try:
        return cached.read_text(encoding="utf-8")
    except OSError:
        pass
    src = paths.artifacts / b.sha256
    if not src.is_file():
        return f"error not_found: the stored file of '{b.name}' is missing. Call open_binary again."
    folder.mkdir(parents=True, exist_ok=True)
    asm = folder / b.name          # ilspycmd wants a real assembly file name
    if not asm.is_file() or asm.stat().st_size != src.stat().st_size:
        asm.write_bytes(src.read_bytes())
    timeout = max(30, int(ctx.config.defaults.get("decompile_timeout_s") or 60))
    ref = Path(b.original_path).parent if b.original_path else None
    out, err = dn.run_ilspy(exe, asm, full, timeout, ref)
    if out is None:
        return (f"error decompile_failed: ilspycmd on {full}: {err}. "
                "Check the ilspycmd path and the .NET runtime, then retry.")
    try:
        cached.write_text(out, encoding="utf-8")
    except OSError:
        pass                       # the cache is an optimisation
    return out
