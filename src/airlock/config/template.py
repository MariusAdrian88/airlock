"""The verbose, self-documenting config file, generated from `keys.KEYS`.

`airlock init` writes it. `airlock config upgrade` cuts single key blocks out of
it. `config_meta()` reads group and description back from the generated text,
so what `airlock config` prints is what the file says.
"""

from __future__ import annotations

import json
import re
import textwrap
from functools import lru_cache
from typing import Any

from airlock.config.catalog import CATALOG, SET_SUMMARIES, TOOL_SUMMARIES
from airlock.config.keys import GROUPS, KEYS, Key

IND = "  "
HEADER = r"""// airlock configuration (JSONC: comments and trailing commas are allowed).
// Global file: %APPDATA%\airlock\config.jsonc. A project folder may hold an overlay
// that overrides single keys.
//
// A line that starts with // and a key shows the built-in default.
// Remove the // and change the value to override it.
// Keys you leave out, or keep commented, use the default.
// `airlock config` shows every value in effect. `airlock config upgrade` adds
// keys that a newer airlock knows and never touches what you wrote.
"""


def _wrap(prefix: str, text: str) -> list[str]:
    return [prefix + ln for ln in textwrap.wrap(text, 84, break_on_hyphens=False, break_long_words=False)]


def doc_lines(key: Key) -> list[str]:
    out = _wrap(f"{IND}// ", key.what)
    out += _wrap(f"{IND}// ", f"Allowed: {key.allowed()}.")
    out += _wrap(f"{IND}// ", f"Default: {key.default_text()}.")
    out += _wrap(f"{IND}// ", f"Change it: {key.when}")
    return out


def _list_entries(key: Key, value: list[str]) -> list[str]:
    """One line per set or tool: active when in value, commented otherwise."""
    if key.name == "disabled_sets":
        names = list(dict.fromkeys(i.set for i in CATALOG.values()
                                   if not all(j.always_on for j in CATALOG.values() if j.set == i.set)))
        desc = SET_SUMMARIES
        fixed = [n for n, i in CATALOG.items() if i.always_on]
    else:
        names = [n for n, i in CATALOG.items() if not i.always_on]
        desc = TOOL_SUMMARIES
        fixed = [n for n, i in CATALOG.items() if i.always_on]
    extra = [v for v in value if v not in names]  # unknown names the user keeps
    rows = []
    if fixed:
        rows += _wrap(f"{IND}{IND}// ", "always on (cannot be disabled): " + ", ".join(fixed))
    for n in names + extra:
        text = f'"{n}",'
        d = desc.get(n, "")
        rows.append(f"{IND}{IND}{'' if n in value else '// '}{text}".ljust(34) + (f"  // {d}" if d else ""))
    return rows


def render_block(key: Key, value: Any = None, active: bool | None = None) -> str:
    """Comment block plus the key line(s), ready to paste into a file."""
    value = key.default if value is None and active is None else value
    on = key.active if active is None else active
    lines = doc_lines(key)
    if key.kind == "list":
        lines.append(f'{IND}"{key.name}": [')
        lines += _list_entries(key, value)
        lines.append(f"{IND}],")
    else:
        lines.append(f'{IND}{"" if on else "// "}"{key.name}": {json.dumps(value)},')
    return "\n".join(lines)


@lru_cache(maxsize=1)
def generate_template() -> str:
    parts = [HEADER + "{"]
    for g in GROUPS:
        parts.append(f"{IND}// === {g} ===\n")
        parts.append("\n\n".join(render_block(k) for k in KEYS if k.group == g))
        parts[-1] += "\n"
    return "\n".join(parts).rstrip("\n") + "\n}\n"


@lru_cache(maxsize=1)
def config_meta() -> dict[str, tuple[str, str]]:
    """key -> (group, description) read back from the generated text."""
    meta: dict[str, tuple[str, str]] = {}
    group, doc = "", []
    for line in generate_template().splitlines():
        m = re.match(rf"^{IND}// === (.+) ===$", line)
        if m:
            group, doc = m.group(1), []
            continue
        m = re.match(rf'^{IND}(?://[ \t]*)?"(\w+)"[ \t]*:', line)
        if m:
            meta[m.group(1)] = (group, " ".join(doc))
            doc = []
        elif re.match(rf"^{IND}// ", line):
            doc.append(line.strip()[3:])
        elif not line.strip():
            doc = []
    return meta


def known_keys() -> list[dict[str, Any]]:
    """name, type, default, doc of every key: for docs and tests."""
    meta = config_meta()
    return [{"name": k.name, "type": k.kind, "default": k.default,
             "group": meta[k.name][0], "doc": meta[k.name][1]} for k in KEYS]
