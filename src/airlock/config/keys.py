"""Every setting airlock knows: name, type, range, default, documentation.

This is the single source. The shipped template (`template.generate_template`),
validation, `airlock config` and `airlock config upgrade` all derive from it.
Doc strings are plain English: short sentences, no slang.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

CONFIG_VERSION = 1

# Section order in the template and in `airlock config`.
GROUPS = ("Meta", "Locations", "Response size", "Decompiler", "Analysis",
          "Notes and maps", "Tools")


@dataclass(frozen=True)
class Key:
    name: str
    kind: str             # int | float | bool | enum | path | str | list
    default: Any
    group: str
    what: str             # what it does
    when: str             # when to change it
    lo: float | None = None
    hi: float | None = None
    lo_open: bool = False  # lower bound excluded (0 < x)
    choices: tuple[str, ...] = ()
    nullable: bool = False
    pattern: str | None = None
    active: bool = False  # shipped as a live line (not commented out)

    def allowed(self) -> str:
        if self.kind == "int":
            return "whole number, " + (f"{int(self.lo)} or more" if self.lo is not None else "any")
        if self.kind == "float":
            if self.lo is not None and self.hi is not None and self.lo_open:
                return f"number above {_n(self.lo)} and at most {_n(self.hi)}"
            return "number above 0" if self.lo_open else "number"
        if self.kind == "bool":
            return "true or false"
        if self.kind == "enum":
            return "one of " + ", ".join(self.choices)
        if self.kind == "path":
            return "text (a path) or null"
        if self.kind == "str":
            return "text such as 8G, or null"
        return "list of names"

    def default_text(self) -> str:
        return json.dumps(self.default)


def _n(x: float) -> str:
    return str(int(x)) if float(x).is_integer() else str(x)


KEYS: tuple[Key, ...] = (
    Key("config_version", "int", CONFIG_VERSION, "Meta",
        "Version of this file's layout. airlock config upgrade sets it.",
        "Never by hand.", lo=0, active=True),

    Key("ghidra_dir", "path", None, "Locations",
        "Folder of the Ghidra install (the folder that holds ghidraRun.bat).",
        "Once, after install. Needed for dirty sessions, not for clean ones.",
        nullable=True, active=True),
    Key("jdk_dir", "path", None, "Locations",
        "Folder of the JDK that runs Ghidra. null means java on PATH, then the one Ghidra finds.",
        "When PATH has no Java 21 or newer.", nullable=True),
    Key("ilspycmd", "path", None, "Locations",
        "Path of ilspycmd.exe, used to decompile .NET code. Optional.",
        "When you analyse .NET programs.", nullable=True),
    Key("index_dir", "path", None, "Locations",
        "Folder for logs, cursors and caches that belong to no project. null means %LOCALAPPDATA%/airlock.",
        "To move this data to another disk.", nullable=True),
    Key("projects_root", "path", None, "Locations",
        "Folder that holds one folder per analysed program. null means %USERPROFILE%/airlock-projects. Must be an absolute path on a local disk.",
        "To keep projects on another local disk.", nullable=True),

    Key("token_budget", "int", 2000, "Response size",
        "Size limit of one response, in tokens, for list tools and outlines.",
        "Raise it if answers end too early. Lower it to save context.", lo=1),
    Key("function_budget", "int", 10000, "Response size",
        "Size limit of one response of the function tool (decompiled C), in tokens.",
        "Raise it if large functions are cut. Lower it to save context.", lo=1),
    Key("max_budget", "int", 32000, "Response size",
        "Upper limit for the budget argument that a single call may ask for.",
        "Rarely. Raise it only if a call needs a larger answer.", lo=1),
    Key("detail", "enum", "brief", "Response size",
        "How much detail tools return. brief is the answer only. full adds wider context. evidence adds how each fact was found.",
        "Use full or evidence while you debug the analysis.",
        choices=("brief", "full", "evidence")),

    Key("decompile_timeout_s", "int", 60, "Decompiler",
        "Time limit, in seconds, for one decompile that you request.",
        "Raise it for very large functions.", lo=1),
    Key("bulk_decompile", "enum", "background", "Decompiler",
        "When all functions get decompiled. background does it after analysis, while you work. lazy decompiles only what you ask for.",
        "Set lazy on a slow computer or to keep the CPU free.",
        choices=("lazy", "background")),
    Key("bulk_decompile_timeout_s", "int", 15, "Decompiler",
        "Time limit, in seconds, for one function in the background pass. A function that times out is retried with decompile_timeout_s on the first function request.",
        "Raise it if many functions time out in the background pass.", lo=1),
    Key("decompile_cpu_min", "float", 0.5, "Decompiler",
        "Share of the processors that the background pass uses while analysis or a request runs.",
        "Lower it if the computer is slow while you work.", lo=0, hi=1, lo_open=True),
    Key("decompile_cpu_max", "float", 0.75, "Decompiler",
        "Share of the processors that the background pass uses while nothing else runs. Must not be below decompile_cpu_min.",
        "Raise it to finish the pass sooner.", lo=0, hi=1, lo_open=True),

    Key("analysis_timeout_min", "int", 60, "Analysis",
        "Time limit, in minutes, for the analysis of one binary.",
        "Raise it for very large binaries.", lo=1),
    Key("analysis_s_per_code_mb", "float", 120, "Analysis",
        "Seconds of analysis per megabyte of code. Prior for the time estimates; refined from the binaries measured in the project.",
        "When the estimates differ much from the real times.", lo=0, lo_open=True),
    Key("analysis_overhead_s", "float", 20, "Analysis",
        "Fixed seconds per binary for import, extraction and linking, whatever its size. Prior for the time estimates; refined from the measured binaries.",
        "When many small binaries take much longer or shorter than estimated.", lo=0),
    Key("jvm_max_memory", "str", None, "Analysis",
        "Maximum memory of the Java process, for example 8G. null means Ghidra's default.",
        "When Ghidra runs out of memory on large binaries.", nullable=True,
        pattern=r"^\d+[kKmMgG]$"),

    Key("mermaid", "bool", False, "Notes and maps",
        "true also writes Mermaid charts to the dirty diagrams folder after each map update.",
        "When you want charts for every update, not only on request."),
    Key("mirror_notes_to_ghidra", "bool", True, "Notes and maps",
        "true also stores agent notes as plate comments in the Ghidra project.",
        "Set false to keep notes only in the index."),

    Key("allow_writes", "bool", True, "Tools",
        "false hides every tool that changes the Ghidra project (the annotate set). A clean session never has write tools.",
        "Set false for a read-only session."),
    Key("disabled_sets", "list", ["delphi", "dotnet"], "Tools",
        "Sets of tools to hide. A set that starts with // is shown. Remove the // to hide it. Tools added in a new version appear without a change here.",
        "To hide a whole group, for example cpp for a program that has no C++.", active=True),
    Key("disabled_tools", "list", ["patch_bytes"], "Tools",
        "Tools to hide. Every tool is listed below. A line that starts with // is shown. Remove the // to hide that tool. A clean session only ever has the clean-safe tools, and this list can only remove more.",
        "To hide a tool you do not want the agent to use.", active=True),
)

KEY_BY_NAME: dict[str, Key] = {k.name: k for k in KEYS}
DEFAULTS: dict[str, Any] = {k.name: k.default for k in KEYS}
CONFIG_TYPES: dict[str, str] = {k.name: k.kind for k in KEYS}

# Accepted for old files; their content is migrated by `airlock config upgrade`.
LEGACY_KEYS = ("defaults", "sets", "profiles", "default_profile", "enabled_sets")


def check_value(key: Key, v: Any) -> str | None:
    """None if v is valid for key, else a one-line complaint."""
    if v is None:
        return None if key.nullable else f"{key.name} must not be null"
    k = key.kind
    if k == "int":
        if isinstance(v, bool) or not isinstance(v, int) or (key.lo is not None and v < key.lo):
            return f"{key.name} must be a {key.allowed()}"
    elif k == "float":
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return f"{key.name} must be a {key.allowed()}"
        if key.lo is not None and (v <= key.lo if key.lo_open else v < key.lo):
            return f"{key.name} must be a {key.allowed()}"
        if key.hi is not None and v > key.hi:
            return f"{key.name} must be a {key.allowed()}"
    elif k == "bool":
        if not isinstance(v, bool):
            return f"{key.name} must be true or false"
    elif k == "enum":
        if v not in key.choices:
            return f"{key.name} must be one of {', '.join(key.choices)} (got {v!r})"
    elif k == "path":
        if not isinstance(v, str):
            return f"{key.name} must be a path string or null"
    elif k == "str":
        if not isinstance(v, str) or (key.pattern and not re.match(key.pattern, v)):
            return f"{key.name} must be {key.allowed()}"
    elif k == "list":
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            return f"{key.name} must be a list of names"
    return None


def validate_values(values: dict[str, Any]) -> list[str]:
    """All complaints about known keys present in values."""
    errs = []
    for name, v in values.items():
        key = KEY_BY_NAME.get(name)
        if key is not None:
            e = check_value(key, v)
            if e:
                errs.append(e)
    lo, hi = values.get("decompile_cpu_min"), values.get("decompile_cpu_max")
    if isinstance(lo, (int, float)) and isinstance(hi, (int, float)) and lo > hi:
        errs.append("decompile_cpu_min must not exceed decompile_cpu_max")
    return errs


def coerce(name: str, raw: Any) -> Any:
    """Turn a command-line string into the key's type. Raises ValueError."""
    key = KEY_BY_NAME.get(name)
    if key is None:
        raise ValueError(f"unknown key '{name}'" + suggestion(name))
    if name == "config_version":
        raise ValueError("config_version is set by `airlock config upgrade`")
    v: Any = raw
    if isinstance(raw, str):
        s = raw.strip()
        if s.lower() == "null" and key.nullable:
            v = None
        elif key.kind == "bool":
            if s.lower() not in ("true", "false"):
                raise ValueError(f"{name} must be true or false")
            v = s.lower() == "true"
        elif key.kind == "int":
            try:
                v = int(s)
            except ValueError:
                raise ValueError(f"{name}: '{s}' is not a whole number") from None
        elif key.kind == "float":
            try:
                v = float(s)
            except ValueError:
                raise ValueError(f"{name}: '{s}' is not a number") from None
        elif key.kind == "list":
            v = json.loads(s) if s.startswith("[") else [x.strip() for x in s.split(",") if x.strip()]
    err = check_value(key, v)
    if err:
        raise ValueError(err)
    return v


def suggestion(name: str, pool: list[str] | None = None) -> str:
    import difflib
    close = difflib.get_close_matches(name, pool if pool is not None else list(KEY_BY_NAME), n=1)
    return f"; did you mean '{close[0]}'?" if close else ""
