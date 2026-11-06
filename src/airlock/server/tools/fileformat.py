"""fileformat set: ole_streams, hexdump, file_diff, record_guess (no Ghidra, dirty role only).

Paths resolve against the program source folder of the project manifest, then ``dirty\\work``.
Absolute paths must lie inside one of those two roots, so the tools cannot read arbitrary files.
"""

from __future__ import annotations

from pathlib import Path

from airlock.server import fileformat as ff
from airlock.server.budget import CursorError, fit_lines, resume_lines
from airlock.server.context import ServerContext
from airlock.server.projectmap import load_manifest
from airlock.server.registry import tool
from airlock.server.tools.common import budget_for


def _roots(ctx: ServerContext) -> list[Path] | str:
    pp = ctx.session.project
    if pp is None:
        return "error unbound: no project is open."
    roots: list[Path] = []
    src = (load_manifest(pp).get("source") or {}).get("path")
    if src:
        p = Path(str(src))
        roots.append(p.parent if p.is_file() else p)
    roots.append(pp.dirty / "work")
    return roots


def resolve_path(ctx: ServerContext, path: str) -> Path | str:
    """A readable file inside the project roots, or a one-line error."""
    roots = _roots(ctx)
    if isinstance(roots, str):
        return roots
    text = path.strip().strip('"')
    if not text:
        return "error bad_args: path is empty."
    p = Path(text)
    cands = [p] if p.is_absolute() else [r / p for r in roots]
    inside = False
    for c in cands:
        try:
            rc = c.resolve()
        except OSError:
            continue
        if not any(rc == r.resolve() or r.resolve() in rc.parents for r in roots if r.exists()):
            continue
        inside = True
        if rc.is_file():
            return rc
    art = _artifact_copy(ctx, text)
    if art is not None:
        return art
    if not inside:
        names = ", ".join(str(r) for r in roots)
        return (f"error outside_project: '{path}' is not inside the program folder or dirty\\work "
                f"({names}).")
    near = _same_name(roots, p.name)
    return (f"error not_found: no file '{path}' under the program folder or dirty\\work"
            + (f". Files with that name: {', '.join(near)}." if near else "."))


def _artifact_copy(ctx: ServerContext, text: str) -> Path | None:
    """The stored copy (``artifacts/<sha256>``) of an analysed binary named by ``text`` (file name or
    original path), so a project without a readable root can still be dumped; None when no binary matches."""
    pp = ctx.session.project
    if pp is None:
        return None
    try:
        st = ctx.indexer.store(pp.name)
        low = text.replace("\\", "/").lower()
        for b in st.list_binaries():
            orig = (b.original_path or "").replace("\\", "/").lower()
            if low in (b.name.lower(), orig) or (orig and orig.endswith("/" + low)):
                f = pp.artifacts / b.sha256
                if f.is_file():
                    return f
    except Exception:  # noqa: BLE001  the plain error below reports the problem
        return None
    return None


MAX_NEAR = 6        # same-name files listed in a not_found error
MAX_WALK = 20000    # files looked at for them


def _same_name(roots: list[Path], name: str) -> list[str]:
    """Paths (relative to their root) of files named ``name`` anywhere under the roots."""
    out: list[str] = []
    if not name:
        return out
    low, seen = name.lower(), 0
    for r in roots:
        if not r.is_dir():
            continue
        for f in r.rglob("*"):
            seen += 1
            if seen > MAX_WALK or len(out) > MAX_NEAR:
                return out
            if f.name.lower() == low and f.is_file():
                out.append(str(f.relative_to(r)))
    return out


def _page(ctx: ServerContext, lines: list[str], name: str, args: dict, cursor: str, budget: int,
          kind: str = "prose") -> str:
    bud = budget_for(ctx, budget)
    if cursor:
        try:
            return resume_lines(cursor, bud, kind, tool=name, args=args)[0]
        except CursorError as e:
            return e.message
    return fit_lines(lines, bud, kind, tool=name, args=args)[0]


def _stream_dump(ctx: ServerContext, p: Path, stream: str, offset: int, length: int,
                 name: str, args: dict, cursor: str, budget: int) -> str:
    data = ff.read_ole_stream(p, stream)
    if isinstance(data, str):
        return data
    return _dump(ctx, data, offset, length, f"{p.name}:{stream}", name, args, cursor, budget)


def _dump(ctx: ServerContext, data: bytes, offset: int, length: int, label: str, name: str,
          args: dict, cursor: str, budget: int) -> str:
    if cursor:
        return _page(ctx, [], name, args, cursor, budget, "code")
    if offset < 0 or (offset >= len(data) and len(data) > 0):
        return f"error bad_args: offset 0x{offset:x} is past the end ({len(data)} bytes)."
    n = max(1, min(length, ff.MAX_DUMP))
    chunk = data[offset:offset + n]
    head = f"{label} {len(data)} bytes, showing 0x{offset:x}-0x{offset + len(chunk):x}"
    tail = []
    if offset + len(chunk) < len(data):
        tail = [f"… more bytes. offset=0x{offset + len(chunk):x}"
                + (f" (max {ff.MAX_DUMP} per call)" if length > ff.MAX_DUMP else "")]
    return _page(ctx, [head] + ff.hexdump_lines(chunk, offset) + tail, name, args, cursor, budget, "code")


@tool("ole_streams", "List the streams of an OLE file with sizes, or hexdump one stream.")
def ole_streams(ctx: ServerContext, path: str = "", stream: str = "", cursor: str = "",
                budget: int = 0) -> str:
    args = {"path": path, "stream": stream}
    if cursor:      # a known cursor carries its own arguments
        return _page(ctx, [], "ole_streams", args, cursor, budget, "code" if stream else "prose")
    p = resolve_path(ctx, path)
    if isinstance(p, str):
        return p
    if stream:
        return _stream_dump(ctx, p, stream, 0, ff.MAX_DUMP, "ole_streams", args, cursor, budget)
    lines = ff.ole_tree_lines(p)
    if isinstance(lines, str):
        return lines
    return _page(ctx, lines, "ole_streams", args, cursor, budget)


@tool("hexdump", "Hexdump bytes of a file or an OLE stream, 16 per line with ASCII.")
def hexdump(ctx: ServerContext, path: str = "", offset: int = 0, length: int = 256, stream: str = "",
            cursor: str = "", budget: int = 0) -> str:
    args = {"path": path, "offset": offset, "length": length, "stream": stream}
    if cursor:
        return _page(ctx, [], "hexdump", args, cursor, budget, "code")
    p = resolve_path(ctx, path)
    if isinstance(p, str):
        return p
    if stream:
        return _stream_dump(ctx, p, stream, offset, length, "hexdump", args, cursor, budget)
    src = ff.FileSrc(p)
    if offset < 0 or (offset >= src.size and src.size > 0):
        return f"error bad_args: offset 0x{offset:x} is past the end ({src.size} bytes)."
    n = max(1, min(length, ff.MAX_DUMP))
    chunk = src.read(offset, n)
    label = Path(path.strip().strip('"')).name if p.parent.name == "artifacts" else p.name
    head = f"{label} {src.size} bytes, showing 0x{offset:x}-0x{offset + len(chunk):x}"
    tail = []
    if offset + len(chunk) < src.size:
        tail = [f"… more bytes. offset=0x{offset + len(chunk):x}"
                + (f" (max {ff.MAX_DUMP} per call)" if length > ff.MAX_DUMP else "")]
    return _page(ctx, [head] + ff.hexdump_lines(chunk, offset) + tail, "hexdump", args, cursor,
                 budget, "code")


@tool("file_diff", "Diff two files: changed byte ranges with context, per stream for OLE files.")
def file_diff(ctx: ServerContext, path_a: str = "", path_b: str = "", stream: str = "", cursor: str = "",
              budget: int = 0, offset: int = 0) -> str:
    args = {"path_a": path_a, "path_b": path_b, "stream": stream, "offset": offset}
    if cursor:
        return _page(ctx, [], "file_diff", args, cursor, budget, "code")
    pa = resolve_path(ctx, path_a)
    if isinstance(pa, str):
        return pa
    pb = resolve_path(ctx, path_b)
    if isinstance(pb, str):
        return pb
    both_ole = ff.is_ole(pa) and ff.is_ole(pb)
    note = "(stream ignored: not two OLE files) " if stream and not both_ole else ""
    if not both_ole:
        a, b = ff.FileSrc(pa), ff.FileSrc(pb)
        res = ff.diff_sources(a, b, start=offset)
        head = f"{note}diff {pa.name} {a.size}B vs {pb.name} {b.size}B: "
        if not res.range_count:
            return head + "identical."
        return _page(ctx, [head + ff.summary_of(res)] + ff.range_lines(res, a, b), "file_diff", args,
                     cursor, budget, "code")
    if stream:
        da, db = ff.read_ole_stream(pa, stream), ff.read_ole_stream(pb, stream)
        if isinstance(da, str) or isinstance(db, str):
            return da if isinstance(da, str) else db  # type: ignore[return-value]
        a, b = ff.BytesSrc(da), ff.BytesSrc(db)
        res = ff.diff_sources(a, b, start=offset)
        head = f"diff stream {stream}: {a.size}B vs {b.size}B: "
        if not res.range_count:
            return head + "identical."
        return _page(ctx, [head + ff.summary_of(res)] + ff.range_lines(res, a, b), "file_diff", args,
                     cursor, budget, "code")
    return _page(ctx, ff.ole_diff(pa, pb), "file_diff", args, cursor, budget, "code")


@tool("record_guess", "Guess record layouts in a data file: strides, length prefixes, strings, columns.")
def record_guess(ctx: ServerContext, path: str = "", stream: str = "", offset: int = 0,
                 cursor: str = "", budget: int = 0) -> str:
    args = {"path": path, "stream": stream, "offset": offset}
    if cursor:
        return _page(ctx, [], "record_guess", args, cursor, budget, "code")
    p = resolve_path(ctx, path)
    if isinstance(p, str):
        return p
    if stream:
        data = ff.read_ole_stream(p, stream)
        if isinstance(data, str):
            return data
        src: ff.Src = ff.BytesSrc(data)
    else:
        src = ff.FileSrc(p)
    lines = ff.record_guess(src, offset)
    return _page(ctx, lines, "record_guess", args, cursor, budget, "code")
