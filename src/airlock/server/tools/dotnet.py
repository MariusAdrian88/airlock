"""dotnet set: dotnet_types, dotnet_decompile (dnfile metadata and ilspycmd, no Ghidra, dirty role only).

Types, methods and P/Invoke declarations come from the derived tables ``dn_*`` (server/dotnet.py).
A P/Invoke bound to an export of a project binary shows ``=> binary!export``; one to a system DLL
stays a plain ``module!entry``. Decompiled C# is a reconstruction: the first line says so.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from airlock.index.store import Binary
from airlock.server import dotnet as dn
from airlock.server import dotnet_meta
from airlock.server import dotnet_ui as ui
from airlock.server.budget import CursorError, fit_lines, resume_lines
from airlock.server.context import ServerContext
from airlock.server.indexer import IndexerError
from airlock.server.registry import add_note, tool
from airlock.server.tools.common import Bound, bind_binary, budget_for, normalize_kind


def _page(ctx: ServerContext, lines: list[str], name: str, args: dict, cursor: str, budget: int,
          kind: str = "prose", key: str = "token_budget", max_lines: int = 0,
          page: int = 0) -> str:
    bud = budget_for(ctx, budget, key)
    if cursor:
        try:
            return resume_lines(cursor, bud, kind, tool=name, args=args)[0]
        except CursorError as e:
            return e.message
    return fit_lines(lines, bud, kind, tool=name, args=args, max_lines=max_lines, page=page)[0]


def _scope(ctx: ServerContext, binary: str) -> list[Bound] | str:
    """The managed binaries to look in, their .NET tables filled; or a one-line error."""
    ix = ctx.indexer
    if binary.strip():
        bd = bind_binary(ctx, binary.strip())
        if isinstance(bd, str):
            return bd
        if bd.binary.toolchain != "dotnet":
            managed = ", ".join(b.name for b in dn.dotnet_binaries(bd.store)) or "none"
            return (f"error not_dotnet: '{bd.binary.name}' is a {bd.binary.toolchain or 'native'} binary "
                    f"without .NET metadata (managed assemblies: {managed}).")
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
            return f"error not_dotnet: project '{proj}' has no ready managed assembly."
    art = ix.paths(bounds[0].project).artifacts
    for bd in bounds:
        try:
            dn.ensure(bd.store, bd.binary, art / bd.binary.sha256)
        except Exception as e:  # noqa: BLE001
            return f"error dotnet_failed: cannot read metadata of {bd.binary.name} ({type(e).__name__}: {e})."
    return bounds


@tool("dotnet_types", "List .NET types, methods, P/Invokes, fields with layouts, properties, events and "
                      "interface implementations or overrides from metadata (kind selects the list).")
def dotnet_types(ctx: ServerContext, query: str = "", limit: int = 50, binary: str = "",
                 kind: str = "", cursor: str = "", budget: int = 0) -> str:
    args = {"query": query, "limit": limit, "binary": binary, "kind": kind}
    if cursor:
        return _page(ctx, [], "dotnet_types", args, cursor, budget)
    k = kind.strip().lower()
    if k and k not in dn.KINDS:
        k, note = normalize_kind(kind, dn.KINDS)
        if not k:
            return f"error bad_args: kind '{kind}' is not one of {', '.join(dn.KINDS)}."
        if note:
            add_note(note)
    args["kind"] = k
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
    if k in dotnet_meta.KINDS:        # type-system facts: one query over all the binaries in scope
        items = dotnet_meta.list_lines(bounds[0].store, [bd.binary.id for bd in bounds], query, k)
    else:
        for bd in bounds:
            pfx = f"[{bd.binary.name}] " if multi else ""
            items += [pfx + ln for ln in dn.list_lines(bd.store, bd.binary.id, query, k)]
    what = " ".join(x for x in (f"query '{query.strip()}'" if query.strip() else "",
                                f"kind {k}" if k else "") if x)
    lines = ["dotnet_types " + "; ".join(head) + (f" | {what}: {len(items)} matches" if what else "")]
    lines += items
    if not items:
        lines.append("no matches")
    return _page(ctx, lines, "dotnet_types", args, "", budget, max_lines=limit + 1, page=limit)


@tool("dotnet_decompile", "Decompile one .NET type to C# with ilspycmd (a reconstruction), optionally "
                          "only one member.")
def dotnet_decompile(ctx: ServerContext, type: str = "", member: str = "", binary: str = "",
                     cursor: str = "", budget: int = 0) -> str:
    args = {"type": type, "member": member, "binary": binary}
    if cursor:
        return _page(ctx, [], "dotnet_decompile", args, cursor, budget, "code", "function_budget")
    if not type.strip():
        return "error bad_args: type is empty."
    exe = ctx.config.ilspycmd
    if exe is None:
        return ('error tool_missing: "ilspycmd" is not set in config.jsonc '
                '(install: dotnet tool install ilspycmd --tool-path <folder>).')
    if not Path(exe).is_file():
        return f'error tool_missing: ilspycmd not found at {exe} ("ilspycmd" in config.jsonc).'
    bounds = _scope(ctx, binary)
    if isinstance(bounds, str):
        return bounds
    hits: list[tuple[Bound, str]] = []
    for bd in bounds:
        hits += [(bd, n) for n in dn.find_type(bd.store, bd.binary.id, type)]
    used = ""
    if not hits:            # widen: the types whose name contains the text
        hits = [(bd, n) for bd in bounds for n in _types_like(bd, type.strip())]
        if len(hits) == 1:
            used = f"// type '{type.strip()}' not found: {hits[0][1]} used (the only name containing it)"
    if not hits:
        return f"error not_found: no type '{type.strip()}' in {', '.join(b.binary.name for b in bounds)}."
    if len(hits) > 1:
        shown = ", ".join(f"{bd.binary.name}!{n}" for bd, n in hits[:6])
        more = f" (+{len(hits) - 6} more)" if len(hits) > 6 else ""
        return f"error ambiguous: '{type.strip()}' matches {len(hits)} types: {shown}{more}."
    bd, full = hits[0]
    mem = member.strip()
    if mem and dn.ilspy_major(Path(exe)) >= 11:
        toks = _member_tokens(bd, full, mem)
        if toks:                   # ilspycmd 11: only these methods, not the whole type
            parts = [_decompiled(ctx, bd, full, Path(exe), token=t) for t in toks]
            errs = [x for x in parts if x.startswith("error ")]
            if errs and len(errs) == len(parts):
                return errs[0]
            body = "\n\n".join(x.strip("\n") for x in parts if not x.startswith("error "))
            lines = [dn.REMINDER, *([used] if used else []), f"// binary {bd.binary.name}, type {full}",
                     f"// member {mem} of {full}: {len(toks)} method(s)", *body.split("\n")]
            return _page(ctx, lines, "dotnet_decompile", args, "", budget, "code", "function_budget")
    code = _decompiled(ctx, bd, full, Path(exe))
    if code.startswith("error "):
        return code
    text = code
    if mem:
        tm = re.fullmatch(r"(?:0[xX])?([0-9A-Fa-f]{8})", mem)
        if tm:                     # a token on ilspycmd 8: cut the method out of the type by its name
            r = bd.store.db.execute("SELECT name FROM dn_method WHERE binary_id=? AND token=?",
                                    (bd.binary.id, int(tm.group(1), 16))).fetchone()
            mem = r[0] if r else mem
        part = dn.member_text(code, mem) or dn.member_text(code, dn.member_alias(mem, full))
        if part is None:
            return f"error not_found: no member '{mem}' in {full} {_members(bd, full)}."
        text = f"// member {mem} of {full}\n{part}"
    lines = [dn.REMINDER, *([used] if used else []), f"// binary {bd.binary.name}, type {full}",
             *text.split("\n")]
    return _page(ctx, lines, "dotnet_decompile", args, "", budget, "code", "function_budget")


def _types_like(bd: Bound, text: str, n: int = 7) -> list[str]:
    """Type full names containing ``text`` (compiler-generated ones left out)."""
    if len(text) < 3:
        return []
    return [r[0] for r in bd.store.db.execute(
        "SELECT name FROM dn_type WHERE binary_id=? AND instr(lower(name), lower(?)) > 0 "
        "AND name NOT LIKE '%<%' ORDER BY length(name), name LIMIT ?", (bd.binary.id, text, n))]


def _members(bd: Bound, full: str, n: int = 20) -> str:
    """`(members: A, B, …)`: the method names of the type, so a wrong member needs no listing call."""
    names = [r[0] for r in bd.store.db.execute(
        "SELECT DISTINCT m.name FROM dn_method m JOIN dn_type t ON t.binary_id=m.binary_id "
        "AND t.token=m.type_token WHERE m.binary_id=? AND t.name=? AND m.name NOT LIKE '%<%' "
        "ORDER BY m.token", (bd.binary.id, full))]
    more = f", +{len(names) - n} more" if len(names) > n else ""
    return f"(members: {', '.join(names[:n]) or 'none'}{more})"


def _member_tokens(bd: Bound, full: str, member: str, cap: int = 8) -> list[int]:
    """Method tokens named ``member`` in the type (all overloads), else in its nested types (closure
    classes, nested types), else the accessors ``get_/set_/add_/remove_`` of a property or event.
    A token (``0x06000005``) names its method directly."""
    db, bid = bd.store.db, bd.binary.id
    m = re.fullmatch(r"(?:0[xX])?([0-9A-Fa-f]{8})", member)
    if m and 0x06000000 <= int(m.group(1), 16) < 0x07000000:
        t = int(m.group(1), 16)
        return [t] if db.execute("SELECT 1 FROM dn_method WHERE binary_id=? AND token=?", (bid, t)).fetchone() else []
    like = full.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "+%"
    simple = re.split(r"[.+]", re.sub(r"`\d+.*$", "", full))[-1]
    first = [member, ".ctor"] if member == simple else [member]       # the type's own name: its constructor
    for names in (first, [p + member for p in ("get_", "set_", "add_", "remove_")]):
        marks = ",".join("?" * len(names))
        for scope in ("t.name=?", "t.name LIKE ? ESCAPE '\\'"):
            rows = db.execute(
                f"SELECT m.token FROM dn_method m JOIN dn_type t ON t.binary_id=m.binary_id "
                f"AND t.token=m.type_token WHERE m.binary_id=? AND {scope} AND m.name IN ({marks}) "
                f"ORDER BY m.token LIMIT ?", (bid, full if scope == "t.name=?" else like, *names, cap)).fetchall()
            if rows:
                return [r[0] for r in rows]
    return []


def ilspy_prepare(ctx: ServerContext, bd: Bound, exe: Path) -> tuple[Path, list[Path]] | str:
    """(assembly copy ilspycmd can read, reference folder) of a binary, or an `error ...` line. The
    copy lives in the cache folder keyed by the assembly and the ilspycmd version."""
    b: Binary = bd.binary
    paths = ctx.indexer.paths(bd.project, create=True)
    src = paths.artifacts / b.sha256
    if not src.is_file():
        return f"error not_found: the stored file of '{b.name}' is missing."
    folder = _cache_folder(ctx, bd, exe)
    folder.mkdir(parents=True, exist_ok=True)
    asm = folder / b.name          # ilspycmd wants a real assembly file name
    if not asm.is_file() or asm.stat().st_size != src.stat().st_size:
        asm.write_bytes(src.read_bytes())
    return asm, _ref_dirs(ctx, bd, folder)


def _ref_dirs(ctx: ServerContext, bd: Bound, folder: Path) -> list[Path]:
    """Reference folders for ilspycmd. A file on disk: its folder. A single-file bundle entry
    (`Host.exe!X.dll`): the folder of the host exe, plus a cache folder with the other managed entries of
    that bundle (artifacts of the project), so references between entries resolve. Never the working directory."""
    op = bd.binary.original_path or ""
    refs: list[Path] = []
    if "!" in op:
        host = op.split("!", 1)[0]
        hp = Path(host).parent
        if host and hp != Path(".") and hp.is_dir():
            refs.append(hp)
        paths = ctx.indexer.paths(bd.project, create=True)
        rd = folder / "refs"
        for o in bd.store.list_binaries():
            if o.id == bd.binary.id or not (o.original_path or "").startswith(host + "!"):
                continue
            src = paths.artifacts / o.sha256
            dst = rd / o.name
            if src.is_file() and (not dst.is_file() or dst.stat().st_size != src.stat().st_size):
                rd.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(src.read_bytes())
        if rd.is_dir():
            refs.append(rd)
    elif op and Path(op).parent != Path("."):
        refs.append(Path(op).parent)
    return refs


def ilspy_run(ctx: ServerContext, bd: Bound, args: list[str], timeout: int = 0,
              ) -> tuple[bytes | None, str | None]:
    """(stdout bytes, error text) of ilspycmd with other options on a binary, e.g. ``["--list-resources"]``,
    ``["--resource", name]``, ``["--bundle-entry", name]`` (these need ilspycmd 11). Used by the
    resource and bundle tools."""
    exe = ctx.config.ilspycmd
    if exe is None or not Path(exe).is_file():
        return None, 'ilspycmd is not set or not found ("ilspycmd" in config.jsonc)'
    if dn.ilspy_major(Path(exe)) < 11:
        return None, f"ilspycmd {dn.ilspy_version(Path(exe))} is too old for {args[0]} (needs 11)"
    prep = ilspy_prepare(ctx, bd, Path(exe))
    if isinstance(prep, str):
        return None, prep.split(": ", 1)[-1].rstrip(".")
    t = timeout or max(30, int(ctx.config.defaults.get("decompile_timeout_s") or 60))
    return dn.run_ilspy_args(Path(exe), prep[0], args, t, prep[1])


def _cache_folder(ctx: ServerContext, bd: Bound, exe: Path) -> Path:
    paths = ctx.indexer.paths(bd.project, create=True)
    ver = re.sub(r"[^A-Za-z0-9_.-]", "_", dn.ilspy_version(exe))
    return paths.cache / "dotnet" / f"{bd.binary.sha256[:16]}-{ver}"


def _decompiled(ctx: ServerContext, bd: Bound, full: str, exe: Path, token: int | None = None) -> str:
    """C# of one type, or with ``token`` of one method: the cached file, else ilspycmd output written
    to the cache (or an error line). Files are keyed by metadata token (`t_02000123.cs`,
    `m_06001106.cs`) inside the folder of the assembly and the ilspycmd version, so names never collide."""
    if token is None:
        row = bd.store.db.execute("SELECT token FROM dn_type WHERE binary_id=? AND name=? ORDER BY token",
                                  (bd.binary.id, full)).fetchone()
        key = f"t_{row[0]:08x}.cs" if row else f"n_{hashlib.sha1(full.encode('utf-8', 'replace')).hexdigest()[:16]}.cs"
    else:
        key = f"m_{token:08x}.cs"
    cached = _cache_folder(ctx, bd, exe) / key
    try:
        return cached.read_text(encoding="utf-8")
    except OSError:
        pass
    prep = ilspy_prepare(ctx, bd, exe)
    if isinstance(prep, str):
        return prep
    timeout = max(30, int(ctx.config.defaults.get("decompile_timeout_s") or 60))
    out, err = dn.run_ilspy(exe, prep[0], full, timeout, prep[1], token=token)
    if out is None:
        what = full if token is None else f"{full} method 0x{token:08x}"
        return f"error decompile_failed: ilspycmd on {what}: {err}."
    try:
        cached.write_text(out, encoding="utf-8")
    except OSError:
        pass                       # the cache is an optimisation
    return out


@tool("dotnet_events", "List the controls of .NET WinForms and WPF forms with their captions and the event "
                       "handlers wired to them.")
def dotnet_events(ctx: ServerContext, form: str = "", component: str = "", event: str = "",
                  binary: str = "", cursor: str = "", budget: int = 0) -> str:
    args = {"form": form, "component": component, "event": event, "binary": binary}
    if cursor:
        return _page(ctx, [], "dotnet_events", args, cursor, budget, "code")
    bounds = _scope(ctx, binary)
    if isinstance(bounds, str):
        return bounds
    multi = len(bounds) > 1
    rows: list[ui.UiRow] = []
    facts: list[str] = []
    tags: dict[int, str] = {}
    for bd in bounds:
        art = ctx.indexer.paths(bd.project).artifacts / bd.binary.sha256
        try:
            got = ui.winforms_rows(art)
        except Exception as e:  # noqa: BLE001
            facts.append(f"{bd.binary.name}: WinForms IL not read ({type(e).__name__}: {e})")
            got = []
        try:
            wpf, note = _wpf_rows(ctx, bd, art, form)
        except Exception as e:  # noqa: BLE001
            wpf, note = [], f"wpf: not read ({type(e).__name__}: {e})"
        if note:
            facts.append((f"{bd.binary.name}: " if multi else "") + note)
        for r in got + wpf:
            tags[id(r)] = bd.binary.name
        rows += got + wpf
    if not rows:
        names = ", ".join(b.binary.name for b in bounds)
        return "\n".join([*facts, f"error not_found: no WinForms or WPF event wiring in {names}."])
    total = len(rows)
    sel, sfacts, err = ui.select_rows(rows, form, component, event)
    if err:
        return err
    forms = {(tags[id(r)], r.form) for r in sel}
    one = len(forms) == 1
    lines = [*facts, *sfacts]
    if one:
        (bn, fm) = next(iter(forms))
        head = f"{bn + '!' if multi else ''}{fm} events {len(sel)}"
        lines.append(head + (f" of {total}" if len(sel) != total else ""))
        lines += ["  " + ui.row_line(r, False) for r in sel]
    else:
        lines.append(f"dotnet_events {len(forms)} forms, {len(sel)} events"
                     + (f" of {total}" if len(sel) != total else ""))
        lines += [(f"[{tags[id(r)]}] " if multi else "") + ui.row_line(r, True) for r in sel]
    return _page(ctx, lines, "dotnet_events", args, "", budget, "code")


def _wpf_rows(ctx: ServerContext, bd: Bound, art: Path, form: str) -> tuple[list[ui.UiRow], str]:
    """The WPF rows of a binary (BAML through ilspycmd 11), and one fact line when they cannot be read."""
    names = ui.baml_names(art)
    if not names:
        return [], ""
    exe = ctx.config.ilspycmd
    if exe is None or not Path(exe).is_file():
        return [], f"wpf: {len(names)} BAML resources not read (ilspycmd is not set or not found)"
    if dn.ilspy_major(Path(exe)) < 11:
        return [], f"wpf: {len(names)} BAML resources not read (ilspycmd {dn.ilspy_version(Path(exe))} is older than 11)"
    prep = ilspy_prepare(ctx, bd, Path(exe))
    if isinstance(prep, str):
        return [], "wpf: " + prep.split(": ", 1)[-1].rstrip(".")
    asm, ref = prep
    timeout = max(30, int(ctx.config.defaults.get("decompile_timeout_s") or 60))

    def run(name: str) -> tuple[bytes | None, str | None]:
        return dn.run_ilspy_args(Path(exe), asm, ["--resource", name], timeout, ref)

    cache = _cache_folder(ctx, bd, Path(exe)) / "baml"
    return ui.wpf_rows(art, run, cache, form)

