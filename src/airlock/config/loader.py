"""Load and resolve configuration.

Layers, later wins: built-in defaults -> global config.jsonc -> project
overlay (project.jsonc) -> the selected profile.

Merge rules: dicts merge key by key, lists and scalars replace, and an
explicit null removes a key inherited from an earlier layer (for top-level
locations, null simply means "not set").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import json5

from airlock import paths
from airlock.config.catalog import CATALOG

CLEAN_ROLE = "clean"
DIRTY_ROLE = "dirty"
_LOCATION_KEYS = ("ghidra_dir", "jdk_dir", "ilspycmd", "index_dir")


class ConfigError(Exception):
    """A configuration problem that prevents starting."""


@dataclass(frozen=True)
class Issue:
    level: str  # "error" | "warning" | "info"
    message: str

    def __str__(self) -> str:
        return f"{self.level}: {self.message}"


@dataclass
class Config:
    source: Path | None
    profile: str
    role: str
    ghidra_dir: Path | None
    jdk_dir: Path | None
    ilspycmd: Path | None
    data_dir: Path
    defaults: dict[str, Any]
    allow_writes: bool
    enabled_sets: list[str]
    sets: dict[str, list[str]]
    tools: list[str]
    issues: list[Issue] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_clean(self) -> bool:
        return self.role == CLEAN_ROLE


# ── JSONC ──────────────────────────────────────────────────────────────────

def default_config_text() -> str:
    return resources.files("airlock.config").joinpath("default_config.jsonc").read_text("utf-8")


def parse_jsonc(text: str, origin: str = "<string>") -> dict[str, Any]:
    try:
        data = json5.loads(text)
    except ValueError as e:
        raise ConfigError(f"{origin}: invalid JSONC: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError(f"{origin}: top level must be an object")
    return data


def load_jsonc(path: Path) -> dict[str, Any]:
    return parse_jsonc(path.read_text("utf-8-sig"), str(path))


def deep_merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in over.items():
        if value is None and key not in _LOCATION_KEYS:
            out.pop(key, None)
        elif isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


# ── Resolution ─────────────────────────────────────────────────────────────

def _opt_path(value: Any, key: str) -> Path | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ConfigError(f"'{key}' must be a path string or null")
    return Path(value).expanduser()


def resolve(merged: dict[str, Any], profile: str | None, source: Path | None) -> Config:
    issues: list[Issue] = []

    profiles = merged.get("profiles") or {}
    name = profile or merged.get("default_profile") or DIRTY_ROLE
    if name not in profiles:
        known = ", ".join(sorted(profiles)) or "none"
        raise ConfigError(f"profile '{name}' is not defined (known: {known})")
    prof = profiles[name] or {}

    role = prof.get("role", DIRTY_ROLE)
    if role not in (CLEAN_ROLE, DIRTY_ROLE):
        raise ConfigError(f"profile '{name}': role must be 'clean' or 'dirty'")

    defaults = dict(merged.get("defaults") or {})
    if isinstance(prof.get("defaults"), dict):
        defaults = deep_merge(defaults, prof["defaults"])
    allow_writes = bool(prof.get("allow_writes", defaults.get("allow_writes", False)))

    for key in ("token_budget", "function_budget", "max_budget",
                "decompile_timeout_s", "analysis_timeout_min"):
        v = defaults.get(key)
        if v is not None and (not isinstance(v, int) or v <= 0):
            raise ConfigError(f"defaults.{key} must be a positive integer")

    sets_raw = merged.get("sets") or {}
    sets: dict[str, list[str]] = {}
    for set_name, tools in sets_raw.items():
        if tools is None:
            continue
        if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
            raise ConfigError(f"sets.{set_name} must be a list of tool names")
        sets[set_name] = tools

    enabled_sets = prof.get("enabled_sets", merged.get("enabled_sets", []))
    if not isinstance(enabled_sets, list):
        raise ConfigError(f"profile '{name}': enabled_sets must be a list")

    tools: list[str] = []
    for set_name in enabled_sets:
        if set_name not in sets:
            issues.append(Issue("error", f"enabled set '{set_name}' is not defined in 'sets'"))
            continue
        for tool in sets[set_name]:
            info = CATALOG.get(tool)
            if info is None:
                issues.append(Issue("warning", f"unknown tool '{tool}' in set '{set_name}' (ignored)"))
                continue
            if info.writes and not allow_writes:
                issues.append(Issue("info", f"'{tool}' hidden: allow_writes is off"))
                continue
            if tool not in tools:
                tools.append(tool)

    if role == CLEAN_ROLE:
        leaking = [t for t in tools if not CATALOG[t].clean_safe]
        if leaking:
            raise ConfigError(
                f"profile '{name}' is a clean profile but exposes tools that can return "
                f"code, addresses or bytes: {', '.join(leaking)}"
            )
        if allow_writes:
            raise ConfigError(f"profile '{name}' is a clean profile and cannot allow writes")

    ghidra_dir = _opt_path(merged.get("ghidra_dir"), "ghidra_dir")
    if ghidra_dir is None and role == DIRTY_ROLE:
        issues.append(Issue("error", "ghidra_dir is not set"))

    return Config(
        source=source,
        profile=name,
        role=role,
        ghidra_dir=ghidra_dir,
        jdk_dir=_opt_path(merged.get("jdk_dir"), "jdk_dir"),
        ilspycmd=_opt_path(merged.get("ilspycmd"), "ilspycmd"),
        data_dir=_opt_path(merged.get("index_dir"), "index_dir") or paths.default_data_dir(),
        defaults=defaults,
        allow_writes=allow_writes,
        enabled_sets=list(enabled_sets),
        sets=sets,
        tools=tools,
        issues=issues,
        raw=merged,
    )


def load_config(
    path: Path | None = None,
    profile: str | None = None,
    project_overlay: Path | None = None,
) -> Config:
    """Load built-in defaults, the global file (if present) and an optional overlay."""
    merged = parse_jsonc(default_config_text(), "built-in defaults")
    source = path or paths.default_config_path()
    if source.exists():
        merged = deep_merge(merged, load_jsonc(source))
    else:
        source = None
    if project_overlay is not None and project_overlay.exists():
        merged = deep_merge(merged, load_jsonc(project_overlay))
    return resolve(merged, profile, source)


def write_default_config(path: Path, ghidra_dir: Path | None = None) -> Path:
    """Write the commented default config, optionally with ghidra_dir filled in."""
    text = default_config_text()
    if ghidra_dir is not None:
        value = str(ghidra_dir).replace("\\", "/")
        text = text.replace('"ghidra_dir": null,', f'"ghidra_dir": "{value}",', 1)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, "utf-8")
    return path
