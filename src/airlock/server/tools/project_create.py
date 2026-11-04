"""project_create: make a project folder from a scanned program (DESIGN 5.0).

Allowed only in an unbound session (registry gating). Needs a name (TODO: MCP
elicitation when the client supports it), then an option from the scan table.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from airlock.projects import (
    MANIFEST_VERSION, copy_artifact, hash_file, new_manifest, project_paths, slugify,
    write_clean_deny_rules, write_manifest,
)
from airlock.server.context import ServerContext
from airlock.server.indexer import IndexerError
from airlock.server.registry import tool
from airlock.server.scan import render_scan, scan_program

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
    slug = slugify(name)
    pp = project_paths(cfg.projects_root, slug, create=False)
    if pp.root.exists():
        return f"error exists: project '{slug}' already exists at {pp.root}. Choose another name."
    spc = float(cfg.defaults.get("analysis_s_per_code_mb") or 80.0)
    try:
        scan = scan_program(Path(path).expanduser(), None, spc)
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
                      "code_size": f.code_size, "sha256": sha, "state": "queued"})
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

    # Single-binary flow for the root executable; the multi-binary queue comes later.
    root_note = "queued"
    try:
        res = ctx.indexer.open_binary(slug, str(scan.root / root_f.rel_path), wait_s=0)
        root_note = res.status
    except IndexerError as e:
        root_note = "error"
        entry[root_f.rel_path]["error"] = e.message
    entry[root_f.rel_path]["state"] = root_note
    write_manifest(pp.manifest, man)

    code = sum(f.code_size for f in selected)
    rest = len(pes) - 1
    return "\n".join([
        f"project {slug} created at {pp.root}",
        f"option {key}: {len(selected)} files ({len(pes)} executables), {code / _MB:.1f} MB code",
        f"root {root_f.rel_path}: {root_note}; {rest} other executables queued",
        f"deny rules for the clean folder written in {pp.clean}",
        f"Open the MCP client in {pp.dirty} to continue.",
    ])
