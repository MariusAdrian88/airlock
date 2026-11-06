"""Tool output states facts; it does not tell the agent what to do (CLAUDE.md, DESIGN 7.5).

Agents ignore advice in tool output (blind evaluation, HANDOVER "Agent evaluation"): a tool does
the next step itself, lists the candidates or the cursor when only the agent can choose, and names
the fix only when the user must make it. This test scans every string literal of the server
modules (not docstrings, tool descriptions, log calls or SQL) for imperative hint phrases; a new
one fails here unless it is on the allowlist with its reason.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import airlock.server

SERVER = Path(airlock.server.__file__).parent

# Offline command-line builders (signature databases, map builds): their messages go to a console,
# never to an agent.
OFFLINE = {"delphikit.py", "delphimap.py", "delphimega.py", "delphioracle.py", "delphisigs.py"}

_START = r"(?:^|[.;:!?]\s+|,\s+(?:or|then)\s+|\(\s*|—\s*)"
_IMPERATIVE = ("Call|Use|Pass|Retry|Try|Run|Raise|Omit|Check|Narrow|Fix|Give|Follow|Repeat|Ask|"
               "Choose|Adjust|Enable|Set|Open|See|Start|Patch|Rename|Write|Describe|Rewrite|Remove|"
               "Drop|Shorten|Add|Read|Restart|Install|Swap|Widen|Poll|Wait|Create|Undo|Pick")
HINT = re.compile(
    _START + r"(?:" + _IMPERATIVE + r")\s+[a-z0-9(\"'<]"   # a sentence that starts with an order
    r"|\bpass \w+="                 # pass retry=true
    r"|\bretry="                    # retry=true decompiles again
    r"|\b(?:then|or) call\b"        # ... then call X
    r"|\bcall (?:again|it|with|without)\b"
    r"|\btry again\b"
    r"|\b[a-z_]{4,}\((?:[a-z_]+=|\))"   # feature(key="x") lists them, index_status()
    r"|\b(?:[a-z]+_[a-z_]+|overview|search|xrefs|strings|features?|function) "
    r"(?:shows|lists|adds|finds|reads|gives)\b"     # spec_list shows the status
)

# (file, text that must occur in the literal, reason). Keep it short: each entry is a hint that
# stays because only the agent or the user can act on it, said as plainly as possible.
ALLOW = [
    ("app.py", "Start every session with projects",
     "the server instructions teach the workflow once per session, like tool descriptions"),
    ("annotate.py", "force=true cuts or re-decodes",
     "the agent decides whether a patch may cut instructions (data: the flag that does it)"),
    ("annotate.py", "force=true restores anyway",
     "the agent decides whether to overwrite bytes changed after the patch"),
    ("scan.py", "root_exe= picks one",
     "the root executable is the agent's or user's choice among the listed candidates"),
    ("scan.py", "root_exe= changes it",
     "same choice, when the scan found a root but others are plausible"),
    ("project_create.py", "option=",
     "the analysis option is a choice; the line lists the options and the recommended one"),
    ("dotnet.py", "install: dotnet tool install ilspycmd",
     "only the user can install ilspycmd; one fact line names the fix"),
    ("warp.py", "pip install airlock[sigs]",
     "a missing optional package; only the user can install it"),
    ("projectmap.py", "airlock config --set",
     "a disabled tool set; only the user can enable it (fact line with the command)"),
]


def _skip_ids(tree: ast.AST) -> set[int]:
    """Ids of string nodes that are not agent output: docstrings, tool descriptions, logging,
    console output."""
    skip: set[int] = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body:
            first = n.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                skip.add(id(first.value))
        if isinstance(n, ast.Call):
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            owner = f.value.id if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) else ""
            logging = name in ("debug", "info", "warning", "error", "exception") and owner not in ("tg", "sp")
            if name in ("tool", "print", "say") or logging or name == "add_argument":
                for sub in ast.walk(n):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                        skip.add(id(sub))
    return skip


def _texts(path: Path) -> list[tuple[int, str]]:
    """(line, text) of each string literal; an f-string's parts are joined with `{}`."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    skip = _skip_ids(tree)
    out: list[tuple[int, str]] = []
    inside: set[int] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.JoinedStr):
            parts = []
            for v in n.values:
                inside.add(id(v))
                if isinstance(v, ast.Constant):
                    parts.append(str(v.value))
                    if id(v) in skip:
                        skip.add(id(n))
                else:
                    parts.append("{}")
            if id(n) not in skip:
                out.append((n.lineno, "".join(parts)))
    for n in ast.walk(tree):
        if (isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in skip
                and id(n) not in inside):
            out.append((n.lineno, n.value))
    return out


_SQL = re.compile(r"^\s*(?:SELECT|UPDATE|INSERT|DELETE|CREATE|WITH|PRAGMA|ALTER)\b")


def _allowed(fname: str, text: str) -> bool:
    return any(fname == f and needle in text for f, needle, _why in ALLOW)


def find_hints() -> list[str]:
    found = []
    for path in sorted(SERVER.rglob("*.py")):
        if path.name in OFFLINE:
            continue
        for line, text in _texts(path):
            if _SQL.match(text) or not HINT.search(text):
                continue
            if _allowed(path.name, text):
                continue
            found.append(f"{path.relative_to(SERVER)}:{line}: {text[:120]!r}")
    return found


def test_no_hint_phrases_in_tool_output():
    hits = find_hints()
    assert not hits, "tool output gives advice; do the step, list the data or name the user's fix:\n" + \
        "\n".join(hits)


def test_allowlist_entries_are_used():
    texts = {p.name: [t for _l, t in _texts(p)] for p in SERVER.rglob("*.py") if p.name not in OFFLINE}
    stale = [f"{f}: {needle!r}" for f, needle, _why in ALLOW
             if needle and not any(needle in t for t in texts.get(f, []))]
    assert not stale, "allowlist entries match nothing (remove them):\n" + "\n".join(stale)


def test_scanner_catches_known_hint_shapes():
    for text in ("Pass retry=true to try again.", "error x: y. Call list_binaries.",
                 "view=asm has the instructions, retry=true decompiles again",
                 "feature(key=\"plugins\") lists them.", "no hits. Use search to find it",
                 "Ask the user for a name and call again with name=.",
                 "(no published specs yet. spec_list shows the status.)"):
        assert HINT.search(text), text
    for text in ("error not_found: no function named 'x'.", "callers 3", "kinds: call, jump",
                 "the call graph", "use 4 calls", "(regex used: no literal match)"):
        assert not HINT.search(text), text
