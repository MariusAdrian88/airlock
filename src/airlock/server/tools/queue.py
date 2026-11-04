"""program_add: queue more files of the project's program folder (DESIGN 5.0 step 6)."""

from __future__ import annotations

from pathlib import Path

from airlock.projects import copy_artifact, hash_file, read_manifest, write_manifest
from airlock.server.context import ServerContext
from airlock.server.indexer import IndexerError
from airlock.server.registry import tool
from airlock.server.estimate import priors
from airlock.server.scan import ScannedFile, ScanResult, scan_program

_MB = 1 << 20


def _csv(s: str) -> list[str]:
    return [x.strip().replace("\\", "/") for x in (s or "").split(",") if x.strip()]


def _match(files: tuple[ScannedFile, ...], token: str) -> ScannedFile | None:
    t = token.lower()
    exact = [f for f in files if f.rel_path.lower().replace("\\", "/") == t]
    if exact:
        return exact[0]
    by_name = [f for f in files if Path(f.rel_path).name.lower() == t]
    return by_name[0] if len(by_name) == 1 else None


def _pending(scan: ScanResult, have: set[str]) -> dict[str, int]:
    """Per option key: number of PE files of the option not yet in the manifest."""
    return {o.key: sum(1 for f in o.files if f.kind == "pe" and f.rel_path not in have)
            for o in scan.options}


@tool("program_add", "Queue more files of the project's program folder for analysis: an option "
                     "letter from the scan table, or a comma list of file paths; only files "
                     "not yet in the project are added.")
def program_add(ctx: ServerContext, option: str = "", files: str = "") -> str:
    ix = ctx.indexer
    try:
        project = ix.resolve_project(None)
    except IndexerError as e:
        return e.message
    pp = ix.paths(project)
    try:
        man = read_manifest(pp.manifest)
    except (OSError, ValueError):
        return f"error no_manifest: project '{project}' has no manifest. Create it with project_create."
    src = (man.get("source") or {})
    folder = src.get("path")
    if not folder or not Path(folder).is_dir():
        return (f"error no_source: the program folder {folder or '(unknown)'} is not available. "
                "Use open_binary with a file path instead.")
    oh, spc = priors(ctx.config.defaults)
    scan = scan_program(Path(folder), src.get("root_exe") or None, spc, oh)
    have = {f.get("path") for f in man.get("files") or []}

    if not option.strip() and not files.strip():
        pend = _pending(scan, have)
        if not any(pend.values()):
            return "nothing to add: every file of the scan is already in the project."
        txt = ", ".join(f"{k} +{n}" for k, n in pend.items() if n)
        return f"files not yet in the project per option: {txt}. Call again with option= or files=."

    picked: list[ScannedFile] = []
    if option.strip():
        opt = next((o for o in scan.options if o.key == option.strip().upper()), None)
        if opt is None:
            keys = ", ".join(o.key for o in scan.options)
            return f"error bad_option: option '{option}' is not offered. Choose one of {keys}."
        picked += list(opt.files)
    for tok in _csv(files):
        f = _match(scan.files, tok)
        if f is None:
            return f"error bad_file: '{tok}' is not a file of the scan. Use paths from program_scan."
        picked.append(f)
    new: list[ScannedFile] = []
    for f in picked:
        if f.kind == "pe" and f.rel_path not in have and all(f.rel_path != n.rel_path for n in new):
            new.append(f)
    if not new:
        return "nothing to add: those files are already in the project."

    entries = []
    for f in sorted(new, key=lambda x: x.rel_path.lower()):
        path = scan.root / f.rel_path
        sha = hash_file(path)
        copy_artifact(path, pp, sha)
        entries.append({"path": f.rel_path, "group": f.group, "kind": f.kind, "size": f.size,
                        "code_size": f.code_size, "sha256": sha, "state": "queued"})
    with ix._mf_lock:
        man = read_manifest(pp.manifest)
        man.setdefault("files", []).extend(entries)
        man.setdefault("added", []).extend(
            [{"option": option.strip().upper() or None, "files": [e["path"] for e in entries]}])
        write_manifest(pp.manifest, man)
    ix.enqueue(project, entries)
    code = sum(e["code_size"] for e in entries)
    q = ix.queue_status(project)
    est = len(entries) * q.overhead_s + code / _MB * q.s_per_mb
    names = ", ".join(Path(e["path"]).name for e in entries[:6])
    more = f", +{len(entries) - 6} more" if len(entries) > 6 else ""
    return (f"queued {len(entries)} files, {code / _MB:.1f} MB code, ~{max(1, round(est / 60))} min: "
            f"{names}{more}. Call index_status for progress.")
