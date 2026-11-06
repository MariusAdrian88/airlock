"""Docs checks: docs/TOOLS.md follows the catalog, TROUBLESHOOTING.md names every error code,
QUICKSTART.md names only real tools.

To refresh docs/TOOLS.md after a catalog change, run the test once. It writes docs/TOOLS.md.new
and fails. Move the new file over docs/TOOLS.md.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from airlock.config.catalog import CATALOG, SET_SUMMARIES, TOOL_SUMMARIES

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SRC = ROOT / "src" / "airlock"

# Names that look like error codes in the source but are not shown to a user or an agent.
NOT_USER_CODES = {"code", "nesting", "truncated"}
# Callables whose first string argument is an error code (and every callable that ends in Error).
ERROR_FUNCS = {"err", "_err", "_error", "error", "error_line"}


def build_tools_md() -> str:
    """The text of docs/TOOLS.md, built from the catalog."""
    by_set: dict[str, list] = {}
    for info in CATALOG.values():
        by_set.setdefault(info.set, []).append(info)
    lines = [
        "# Tool reference",
        "",
        "<!-- Generated from src/airlock/config/catalog.py by tests/test_docs.py. Do not edit by hand. -->",
        "",
        "Columns: `clean_safe` means a clean session may use the tool. `writes` means the tool changes the",
        "Ghidra project and needs `allow_writes`. `always_on` means `disabled_tools` and `disabled_sets`",
        "cannot hide the tool. The sets `delphi` and `dotnet` and the tool `patch_bytes` are off by default.",
        "",
    ]
    for set_name, tools in by_set.items():
        lines += [f"## {set_name}", "", SET_SUMMARIES.get(set_name, ""), "",
                  "| Tool | clean_safe | writes | always_on | What it does |",
                  "|---|---|---|---|---|"]
        for t in tools:
            lines.append(f"| `{t.name}` | {'yes' if t.clean_safe else 'no'} | {'yes' if t.writes else 'no'} "
                         f"| {'yes' if t.always_on else 'no'} | {TOOL_SUMMARIES[t.name]} |")
        lines.append("")
    return "\n".join(lines)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def test_every_tool_has_a_summary():
    assert sorted(set(CATALOG) - set(TOOL_SUMMARIES)) == []


def test_tools_md_is_current():
    want = build_tools_md()
    path = DOCS / "TOOLS.md"
    have = _read(path) if path.exists() else None
    if have != want:
        new = DOCS / "TOOLS.md.new"
        new.write_text(want, encoding="utf-8", newline="\n")
        raise AssertionError(f"docs/TOOLS.md is out of date: move {new} over it.")


def source_error_codes() -> set[str]:
    """Every error code in src/airlock: `error <code>:` in string literals, plus the first string
    argument of error helpers and of *Error classes."""
    codes: set[str] = set()
    for p in SRC.rglob("*.py"):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                codes.update(re.findall(r"\berror ([a-z][a-z_]*):", n.value))
            elif isinstance(n, ast.Call):
                f = n.func
                name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
                if (name in ERROR_FUNCS or name.endswith("Error")) and n.args:
                    a = n.args[0]
                    if isinstance(a, ast.Constant) and isinstance(a.value, str) \
                            and re.fullmatch(r"[a-z][a-z_]*", a.value):
                        codes.add(a.value)
    return codes - NOT_USER_CODES


def test_troubleshooting_names_every_error_code():
    text = _read(DOCS / "TROUBLESHOOTING.md")
    missing = sorted(c for c in source_error_codes() if f"`{c}`" not in text)
    assert missing == [], f"docs/TROUBLESHOOTING.md lacks these error codes: {', '.join(missing)}"


def test_quickstart_names_real_tools():
    text = _read(DOCS / "QUICKSTART.md")
    used = set()
    for line in text.splitlines():
        if line.lstrip("- ").startswith("Tools:"):
            used.update(re.findall(r"`([a-z_]+)`", line))
    assert used, "QUICKSTART.md lists no tools"
    assert sorted(used - set(CATALOG)) == []
