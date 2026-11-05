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
        return "error unbound: no project is open. Call projects, then project_open."
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
        return "error bad_args: path is empty. Pass a file path relative to the program folder."
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
    if not inside:
        names = ", ".join(str(r) for r in roots)
        return (f"error outside_project: '{path}' is not inside the program folder or dirty\\work "
                f"({names}). Use a relative path.")
    return (f"error not_found: no file '{path}' under the program folder or dirty\\work. "
            "Use a relative path such as sub\\file.ext.")


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
        return (f"error bad_args: offset 0x{offset:x} is past the end ({len(data)} bytes). "
                f"Use 0 to {max(len(data) - 1, 0)}.")
    n = max(1, min(length, ff.MAX_DUMP))
    chunk = data[offset:offset + n]
    head = f"{label} {len(data)} bytes, showing 0x{offset:x}-0x{offset + len(chunk):x}"
    tail = []
    if offset + len(chunk) < len(data):
        tail = [f"… more bytes. offset=0x{offset + len(chunk):x}"
                + (f" (max {ff.MAX_DUMP} per call)" if length > ff.MAX_DUMP else "")]
    return _page(ctx, [head] + ff.hexdump_lines(chunk, offset) + tail, name, args, cursor, budget, "code")


@tool("ole_streams", "List the streams of an OLE file with sizes, or hexdump one stream.")
def ole_streams(ctx: ServerContext, path: str, stream: str = "", cursor: str = "",
                budget: int = 0) -> str:
    p = resolve_path(ctx, path)
    if isinstance(p, str):
        return p
    args = {"path": path, "stream": stream}
    if stream:
        return _stream_dump(ctx, p, stream, 0, ff.MAX_DUMP, "ole_streams", args, cursor, budget)
    if cursor:
        return _page(ctx, [], "ole_streams", args, cursor, budget)
    lines = ff.ole_tree_lines(p)
    if isinstance(lines, str):
        return lines
    return _page(ctx, lines, "ole_streams", args, cursor, budget)


@tool("hexdump", "Hexdump bytes of a file or an OLE stream, 16 per line with ASCII.")
def hexdump(ctx: ServerContext, path: str, offset: int = 0, length: int = 256, stream: str = "",
            cursor: str = "", budget: int = 0) -> str:
    p = resolve_path(ctx, path)
    if isinstance(p, str):
        return p
    args = {"path": path, "offset": offset, "length": length, "stream": stream}
    if stream:
        return _stream_dump(ctx, p, stream, offset, length, "hexdump", args, cursor, budget)
    if cursor:
        return _page(ctx, [], "hexdump", args, cursor, budget, "code")
    src = ff.FileSrc(p)
    if offset < 0 or (offset >= src.size and src.size > 0):
        return (f"error bad_args: offset 0x{offset:x} is past the end ({src.size} bytes). "
                f"Use 0 to {max(src.size - 1, 0)}.")
    n = max(1, min(length, ff.MAX_DUMP))
    chunk = src.read(offset, n)
    head = f"{p.name} {src.size} bytes, showing 0x{offset:x}-0x{offset + len(chunk):x}"
    tail = []
    if offset + len(chunk) < src.size:
        tail = [f"… more bytes. offset=0x{offset + len(chunk):x}"
                + (f" (max {ff.MAX_DUMP} per call)" if length > ff.MAX_DUMP else "")]
    return _page(ctx, [head] + ff.hexdump_lines(chunk, offset) + tail, "hexdump", args, cursor,
                 budget, "code")


@tool("file_diff", "Diff two files: changed byte ranges with context, per stream for OLE files.")
def file_diff(ctx: ServerContext, path_a: str, path_b: str, stream: str = "", cursor: str = "",
              budget: int = 0) -> str:
    args = {"path_a": path_a, "path_b": path_b, "stream": stream}
    if cursor:
        return _page(ctx, [], "file_diff", args, cursor, budget, "code")
    pa = resolve_path(ctx, path_a)
    if isinstance(pa, str):
        return pa
    pb = resolve_path(ctx, path_b)
    if isinstance(pb, str):
        return pb
    both_ole = ff.is_ole(pa) and ff.is_ole(pb)
    if stream and not both_ole:
        return "error not_ole: stream= needs two OLE files. Omit stream for a byte diff."
    if not both_ole:
        a, b = ff.FileSrc(pa), ff.FileSrc(pb)
        res = ff.diff_sources(a, b)
        head = f"diff {pa.name} {a.size}B vs {pb.name} {b.size}B: "
        if not res.range_count:
            return head + "identical."
        return _page(ctx, [head + ff.summary_of(res)] + ff.range_lines(res, a, b), "file_diff", args,
                     cursor, budget, "code")
    if stream:
        da, db = ff.read_ole_stream(pa, stream), ff.read_ole_stream(pb, stream)
        if isinstance(da, str) or isinstance(db, str):
            return da if isinstance(da, str) else db  # type: ignore[return-value]
        a, b = ff.BytesSrc(da), ff.BytesSrc(db)
        res = ff.diff_sources(a, b)
        head = f"diff stream {stream}: {a.size}B vs {b.size}B: "
        if not res.range_count:
            return head + "identical."
        return _page(ctx, [head + ff.summary_of(res)] + ff.range_lines(res, a, b), "file_diff", args,
                     cursor, budget, "code")
    return _page(ctx, ff.ole_diff(pa, pb), "file_diff", args, cursor, budget, "code")


@tool("record_guess", "Guess record layouts in a data file: strides, length prefixes, strings, columns.")
def record_guess(ctx: ServerContext, path: str, stream: str = "", offset: int = 0, cursor: str = "",
                 budget: int = 0) -> str:
    p = resolve_path(ctx, path)
    if isinstance(p, str):
        return p
    args = {"path": path, "stream": stream, "offset": offset}
    if cursor:
        return _page(ctx, [], "record_guess", args, cursor, budget, "code")
    if stream:
        data = ff.read_ole_stream(p, stream)
        if isinstance(data, str):
            return data
        src: ff.Src = ff.BytesSrc(data)
    else:
        src = ff.FileSrc(p)
    lines = ff.record_guess(src, offset)
    return _page(ctx, lines, "record_guess", args, cursor, budget, "code")
