"""project set: program_scan (light scan, no Ghidra)."""

from __future__ import annotations

from pathlib import Path

from airlock.server.context import ServerContext
from airlock.server.registry import tool
from airlock.server.scan import render_scan, scan_program


@tool("program_scan", "Scan a program folder or executable without Ghidra and show its file "
                      "groups, analysis options with time estimates, and a recommendation.")
def program_scan(ctx: ServerContext, path: str, root_exe: str = "") -> str:
    spc = ctx.config.defaults.get("analysis_s_per_code_mb") or 80.0
    try:
        res = scan_program(Path(path), root_exe or None, float(spc))
    except FileNotFoundError:
        return f"error not_found: {path} does not exist. Give an existing folder or executable."
    return "\n".join(render_scan(res))
