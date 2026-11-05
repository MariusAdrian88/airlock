"""project_create: make a project folder from a scanned program (DESIGN 5.0).

Allowed only in an unbound session (registry gating); success binds it as dirty. Needs a name (TODO: MCP
elicitation when the client supports it), then an option from the scan table.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from airlock.projects import (
    MANIFEST_VERSION, copy_artifact, hash_file, new_manifest, project_paths, read_manifest,
    slugify, write_clean_deny_rules, write_manifest,
)
from airlock.server.context import ServerContext
from airlock.server.indexer import IndexerError
from airlock.server.registry import tool
from airlock.server.estimate import priors
from airlock.server.scan import render_scan, scan_program
from airlock.server.tools.session import dirty_lines

_MB = 1 << 20


def _csv(s: str) -> list[str]:
    return [x.strip().replace("\\", "/") for x in (s or "").split(",") if x.strip()]


def _match(files, token: str):
    t = token.lower()
    exact = [f for f in files if f.rel_path.lower() == t]
    if exact:
        return exact[0]
    byname = [f for f in files if Path(f.rel_path).name.lower() == t]
    return byname[0] if len(byname) == 1 else None


@tool("project_create", "Create a project folder for a program: scan it, pick an option "
                        "(A-D) from the table, and queue the chosen files for analysis.")
def project_create(ctx: ServerContext, path: str, name: str = "", option: str = "",
                   add: str = "", remove: str = "") -> str:
    if not name.strip():
        # TODO: ask the user through MCP elicitation when the client supports it.
        return ("error need_name: a project name is required. Ask the user for a project "
                "name and call again with name=.")
    cfg = ctx.config
    if ctx.profile_role and ctx.profile_role != "dirty":
        return f"error wrong_role: this server was started with --profile {ctx.profile_role}."
    slug = slugify(name)
    pp = project_paths(cfg.projects_root, slug, create=False)
    if pp.root.exists():
        return f"error exists: project '{slug}' already exists at {pp.root}. Choose another name."
    oh, spc = priors(cfg.defaults)
    try:
        scan = scan_program(Path(path).expanduser(), None, spc, oh)
    except FileNotFoundError:
        return f"error not_found: {path} does not exist. Give an existing folder or executable."
    keys = [o.key for o in scan.options]
    if not keys:
        return "error no_binaries: no analysable executable found. Check the path."
    if not option.strip():
        span = keys[0] if len(keys) == 1 else f"{keys[0]}..{keys[-1]}"
        return "\n".join([*render_scan(scan),
                          f"Choose option={span} (recommended {scan.recommended}), optional "
                          "add=/remove= comma lists, then call again."])
    key = option.strip().upper()
    opt = next((o for o in scan.options if o.key == key), None)
    if opt is None:
        return f"error bad_option: option '{option}' is not offered. Choose one of {', '.join(keys)}."

    selected = list(opt.files)
    have = {f.rel_path for f in selected}
    for tok in _csv(add):
        f = _match(scan.files, tok)
        if f is None:
            return f"error bad_file: '{tok}' is not a file of the scan (add=). Use paths from the scan."
        if f.rel_path not in have:
            selected.append(f)
            have.add(f.rel_path)
    for tok in _csv(remove):
        f = _match(selected, tok)
        if f is None:
            return f"error bad_file: '{tok}' is not in the selection (remove=)."
        selected = [x for x in selected if x.rel_path != f.rel_path]
    pes = [f for f in selected if f.kind == "pe"]
    if not pes:
        return "error no_binaries: the selection has no executable. Adjust add=/remove=."
    root_f = next((f for f in pes if f.rel_path == scan.root_exe), None) \
        or next((f for f in pes if not f.is_dll), pes[0])

    pp = project_paths(cfg.projects_root, slug, create=True)
    files = []
    for f in sorted(selected, key=lambda x: x.rel_path.lower()):
        src = scan.root / f.rel_path
        sha = hash_file(src)
        copy_artifact(src, pp, sha)
        files.append({"path": f.rel_path, "group": f.group, "kind": f.kind, "size": f.size,
                      "code_size": f.code_size, "est_funcs": f.est_funcs, "sha256": sha,
                      "state": "queued"})
    entry = {f["path"]: f for f in files}
    man = new_manifest(slug)
    man.update({
        "version": MANIFEST_VERSION,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": {"path": str(scan.root), "root_exe": root_f.rel_path},
        "scan": {"recommended": scan.recommended,
                 "options": [{"key": o.key, "label": o.label, "files": len(o.files),
                              "code_bytes": o.code_size, "est_seconds": round(o.est_seconds)}
                             for o in scan.options]},
        "selected_option": key, "add": _csv(add), "remove": _csv(remove), "files": files,
    })
    write_manifest(pp.manifest, man)
    write_clean_deny_rules(pp)

    # Every selected PE file goes on the analysis queue (the indexer updates the manifest states).
    try:
        ctx.indexer.enqueue(slug, files)
    except IndexerError as e:
        entry[root_f.rel_path]["error"] = e.message
        entry[root_f.rel_path]["state"] = "error"
        write_manifest(pp.manifest, man)
    try:
        states = {f["path"]: f.get("state", "queued") for f in read_manifest(pp.manifest)["files"]}
    except (OSError, ValueError, KeyError):
        states = {}
    root_note = states.get(root_f.rel_path, "queued")

    code = sum(f.code_size for f in selected)
    rest = len(pes) - 1
    bound = ctx.bind_session("dirty", pp)
    return "\n".join([
        f"project {slug} created at {pp.root}",
        f"option {key}: {len(selected)} files ({len(pes)} executables), {code / _MB:.1f} MB code",
        f"root {root_f.rel_path}: {root_note}; {rest} other executables "
        f"({sum(1 for q, s in states.items() if q != root_f.rel_path and s == 'queued')} queued)",
        f"deny rules for the clean folder written in {pp.clean}",
        *(dirty_lines(pp) if bound is None else [bound]),
    ])
