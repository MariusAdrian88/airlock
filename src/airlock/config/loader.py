"""Load and resolve configuration.

Layers, later wins: built-in defaults (keys.DEFAULTS) -> global config.jsonc ->
project overlay. Every setting is a top-level key (see keys.py). Old files with
`defaults`, `sets` and `profiles` blocks are still read as far as possible;
`airlock config upgrade` migrates them.

Merge rules: dicts merge key by key, lists and scalars replace, and an explicit
null removes a key inherited from an earlier layer (the built-in default then
applies again). For location keys, null simply means "not set".
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import json5

from airlock import paths
from airlock.config.catalog import CATALOG
from airlock.config.keys import (
    DEFAULTS,
    KEY_BY_NAME,
    LEGACY_KEYS,
    suggestion,
    validate_values,
)

CLEAN_ROLE = "clean"
DIRTY_ROLE = "dirty"
_LOCATION_KEYS = ("ghidra_dir", "jdk_dir", "ilspycmd", "idr_kb_dir", "delphi_sigdb_dir", "warp_dir", "index_dir", "projects_root")
_NOT_DEFAULTS = set(_LOCATION_KEYS) | {"config_version", "disabled_tools", "disabled_sets"}


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
    projects_root: Path
    defaults: dict[str, Any]
    allow_writes: bool
    disabled_tools: list[str]
    disabled_sets: list[str]
    tools: list[str]
    issues: list[Issue] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    idr_kb_dir: Path | None = None
    delphi_sigdb_dir: Path | None = None   # folder of the Delphi signature databases; None: <data_dir>/sigdb
    warp_dir: Path | None = None           # folder of the WARP libraries; None: <data_dir>/warp
    file_version: int | None = None   # config_version of the global file; None: no file

    @property
    def is_clean(self) -> bool:
        return self.role == CLEAN_ROLE


# ── JSONC ──────────────────────────────────────────────────────────────────

def default_config_text() -> str:
    from airlock.config.template import generate_template
    return generate_template()


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


def _projects_root(value: Any) -> Path:
    if value is None or value == "":
        return paths.default_projects_root()
    if not isinstance(value, str):
        raise ConfigError("'projects_root' must be a path string or null")
    p = Path(os.path.expandvars(os.path.expanduser(value)))
    if not p.is_absolute():
        raise ConfigError(f"'projects_root' must be an absolute path (got '{value}')")
    return p


def effective_values(merged: dict[str, Any], role: str = DIRTY_ROLE) -> dict[str, Any]:
    """Built-in defaults, then old `defaults` blocks, then the top-level keys."""
    eff = dict(DEFAULTS)
    legacy = merged.get("defaults")
    if isinstance(legacy, dict):
        eff.update({k: v for k, v in legacy.items() if k in KEY_BY_NAME})
    profs = merged.get("profiles")
    if isinstance(profs, dict) and isinstance(profs.get(role), dict):
        p = profs[role]
        if "allow_writes" in p:
            eff["allow_writes"] = p["allow_writes"]
        if isinstance(p.get("defaults"), dict):
            eff.update({k: v for k, v in p["defaults"].items() if k in KEY_BY_NAME})
    eff.update({k: v for k, v in merged.items() if k in KEY_BY_NAME})
    return eff


def check_unknown(data: dict[str, Any], origin: str) -> list[Issue]:
    """Warnings for keys airlock does not know, with a did-you-mean."""
    out: list[Issue] = []
    for k, v in data.items():
        if k in KEY_BY_NAME:
            continue
        if k in LEGACY_KEYS:
            note = ("still read" if k == "defaults" else
                    "ignored (tools are chosen with disabled_tools and disabled_sets)")
            out.append(Issue("warning", f"{origin}: old key '{k}' is {note}; "
                                        "run `airlock config upgrade`"))
            if k == "defaults" and isinstance(v, dict):
                for ik in v:
                    if ik not in KEY_BY_NAME:
                        out.append(Issue("warning", f"{origin}: unknown key 'defaults.{ik}' "
                                                    f"(ignored){suggestion(ik)}"))
        else:
            out.append(Issue("warning", f"{origin}: unknown key '{k}' (ignored){suggestion(k)}"))
    return out


def resolve(merged: dict[str, Any], profile: str | None, source: Path | None) -> Config:
    issues: list[Issue] = []

    role = profile or DIRTY_ROLE
    if role not in (CLEAN_ROLE, DIRTY_ROLE):
        raise ConfigError(f"profile '{role}' is not defined (use 'dirty' or 'clean')")

    eff = effective_values(merged, role)
    errs = validate_values(eff)
    if errs:
        raise ConfigError("; ".join(errs))

    allow_writes = bool(eff["allow_writes"]) and role == DIRTY_ROLE
    defaults = {k: v for k, v in eff.items() if k not in _NOT_DEFAULTS}
    defaults["allow_writes"] = allow_writes

    disabled_tools = list(eff["disabled_tools"])
    disabled_sets = list(eff["disabled_sets"])
    set_names = {i.set for i in CATALOG.values()}
    for t in disabled_tools:
        if t not in CATALOG:
            issues.append(Issue("warning", f"unknown tool '{t}' in disabled_tools (ignored)"))
    for s in disabled_sets:
        if s not in set_names:
            issues.append(Issue("warning", f"unknown set '{s}' in disabled_sets (ignored)"))

    forced = {n for n in disabled_tools if n in CATALOG and CATALOG[n].always_on}
    forced |= {n for n, i in CATALOG.items() if i.always_on and i.set in disabled_sets}
    for n in CATALOG:                       # catalog order
        if n in forced:
            issues.append(Issue("warning", f"config: {n} is always on and cannot be disabled (ignored)"))

    tools: list[str] = []
    for name, info in CATALOG.items():
        if role == CLEAN_ROLE and not info.clean_safe:
            continue            # a clean session only ever gets clean-safe tools
        if not info.always_on and (name in disabled_tools or info.set in disabled_sets):
            continue
        if info.writes and not allow_writes:
            issues.append(Issue("info", f"'{name}' hidden: allow_writes is off"))
            continue
        tools.append(name)

    ghidra_dir = _opt_path(eff.get("ghidra_dir"), "ghidra_dir")
    if ghidra_dir is None and role == DIRTY_ROLE:
        issues.append(Issue("error", "ghidra_dir is not set"))

    return Config(
        source=source,
        profile=role,
        role=role,
        ghidra_dir=ghidra_dir,
        jdk_dir=_opt_path(eff.get("jdk_dir"), "jdk_dir"),
        ilspycmd=_opt_path(eff.get("ilspycmd"), "ilspycmd"),
        idr_kb_dir=_opt_path(eff.get("idr_kb_dir"), "idr_kb_dir"),
        delphi_sigdb_dir=(_opt_path(eff.get("delphi_sigdb_dir"), "delphi_sigdb_dir")
                          or (_opt_path(eff.get("index_dir"), "index_dir") or paths.default_data_dir()) / "sigdb"),
        warp_dir=(_opt_path(eff.get("warp_dir"), "warp_dir")
                  or (_opt_path(eff.get("index_dir"), "index_dir") or paths.default_data_dir()) / "warp"),
        projects_root=_projects_root(eff.get("projects_root")),
        data_dir=_opt_path(eff.get("index_dir"), "index_dir") or paths.default_data_dir(),
        defaults=defaults,
        allow_writes=allow_writes,
        disabled_tools=disabled_tools,
        disabled_sets=disabled_sets,
        tools=tools,
        issues=issues,
        raw=merged,
    )


@dataclass
class Layers:
    source: Path | None
    global_data: dict[str, Any] | None
    overlay_data: dict[str, Any] | None
    overlay_path: Path | None


def load_layers(path: Path | None = None, project_overlay: Path | None = None) -> Layers:
    source = path or paths.default_config_path()
    gdata = load_jsonc(source) if source.exists() else None
    if gdata is None:
        source = None
    odata = None
    if project_overlay is not None and project_overlay.exists():
        odata = load_jsonc(project_overlay)
    return Layers(source, gdata, odata, project_overlay if odata is not None else None)


def load_config(
    path: Path | None = None,
    profile: str | None = None,
    project_overlay: Path | None = None,
) -> Config:
    """Load the global file (if present) and an optional overlay over the built-in defaults."""
    lay = load_layers(path, project_overlay)
    merged: dict[str, Any] = {}
    issues: list[Issue] = []
    if lay.global_data is not None:
        merged = deep_merge(merged, lay.global_data)
        issues += check_unknown(lay.global_data, str(lay.source))
    if lay.overlay_data is not None:
        merged = deep_merge(merged, lay.overlay_data)
        issues += check_unknown(lay.overlay_data, str(lay.overlay_path))
    cfg = resolve(merged, profile, lay.source)
    cfg.issues += issues
    if lay.global_data is not None:
        v = lay.global_data.get("config_version", 0)
        cfg.file_version = v if isinstance(v, int) and not isinstance(v, bool) else 0
    return cfg


def write_default_config(path: Path, ghidra_dir: Path | None = None) -> Path:
    """Write the verbose, documented default config, optionally with ghidra_dir filled in."""
    text = default_config_text()
    if ghidra_dir is not None:
        value = str(ghidra_dir).replace("\\", "/")
        text = text.replace('"ghidra_dir": null,', f'"ghidra_dir": "{value}",', 1)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, "utf-8")
    return path
