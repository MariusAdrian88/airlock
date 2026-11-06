"""`airlock config upgrade`: bring a user's config file up to the built-in layout.

Rules:
- A key that is neither active nor commented out in the user's file is new.
  It is added, with its comment block, before the closing brace.
- A commented-out key was removed on purpose and is never touched.
- Old files with `defaults`, `sets` and `profiles`: values that differ from the
  default become top-level keys; tools and sets the user removed become
  `disabled_tools` / `disabled_sets`; the old blocks stay as comments.
- Nothing the user wrote is deleted or reordered.
"""

from __future__ import annotations

import difflib
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock.config import edit
from airlock.config.catalog import CATALOG
from airlock.config.keys import CONFIG_VERSION, DEFAULTS, KEY_BY_NAME, KEYS, LEGACY_KEYS
from airlock.config.legacy import OLD_DEFAULT_VALUES, reference_tools
from airlock.config.loader import (
    DIRTY_ROLE,
    ConfigError,
    deep_merge,
    parse_jsonc,
    resolve,
)
from airlock.config.template import render_block

IND = "  "


@dataclass
class UpgradePlan:
    old_text: str
    new_text: str
    from_version: int
    to_version: int = CONFIG_VERSION
    added: list[str] = field(default_factory=list)        # keys added
    migrated: list[str] = field(default_factory=list)     # old blocks converted
    new_tools: list[str] = field(default_factory=list)    # tools that become visible

    @property
    def changed(self) -> bool:
        return self.new_text != self.old_text

    def summary(self) -> str:
        parts = []
        if self.added:
            parts.append("keys: " + ", ".join(self.added))
        if self.new_tools:
            parts.append("tools: " + ", ".join(self.new_tools))
        if self.migrated:
            parts.append("migrated: " + ", ".join(self.migrated))
        return "; ".join(parts)

    def diff(self, name: str = "config.jsonc") -> str:
        return "".join(difflib.unified_diff(
            self.old_text.splitlines(True), self.new_text.splitlines(True),
            f"{name} (current)", f"{name} (upgraded)"))


def _version_of(data: dict[str, Any]) -> int:
    v = data.get("config_version", 0)
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


def _user_tools(data: dict[str, Any]) -> set[str]:
    """Tools the old allow-list exposed to the dirty profile."""
    sets = data.get("sets") or {}
    profs = data.get("profiles") or {}
    dirty = profs.get("dirty") if isinstance(profs, dict) else None
    enabled = dirty.get("enabled_sets") if isinstance(dirty, dict) else None
    if not isinstance(enabled, list):
        enabled = list(sets)
    out: set[str] = set()
    for s in enabled:
        lst = sets.get(s)
        if isinstance(lst, list):
            out.update(t for t in lst if isinstance(t, str))
    return out


def _migrate_tools(data: dict[str, Any]) -> tuple[list[str], list[str]]:
    user = _user_tools(data)
    ref = reference_tools(data.get("sets") or {})
    dt = list(DEFAULTS["disabled_tools"])
    ds = list(DEFAULTS["disabled_sets"])
    dt = [t for t in dt if t not in user]
    for s in list(ds):
        members = [n for n, i in CATALOG.items() if i.set == s]
        if any(t in user for t in members):
            ds.remove(s)
            dt += [t for t in members if t not in user]
    for name in CATALOG:
        if name in ref and name not in user and name not in dt \
                and CATALOG[name].set not in ds:
            dt.append(name)
    return dt, ds


def plan_upgrade(text: str) -> UpgradePlan:
    data = parse_jsonc(text, "config")
    n = CONFIG_VERSION
    plan = UpgradePlan(text, text, _version_of(data))
    overrides: dict[str, Any] = {}
    out = text

    # Old-style blocks.
    legacy_present = [k for k in LEGACY_KEYS if k in data]
    if legacy_present:
        ldef = data.get("defaults") if isinstance(data.get("defaults"), dict) else {}
        for k, v in ldef.items():
            if (k in KEY_BY_NAME and k not in data and v != DEFAULTS[k]
                    and v != OLD_DEFAULT_VALUES.get(k)):
                overrides[k] = v
        profs = data.get("profiles") if isinstance(data.get("profiles"), dict) else {}
        dirty = profs.get("dirty") if isinstance(profs.get("dirty"), dict) else {}
        aw = dirty.get("allow_writes", ldef.get("allow_writes", False))
        if "allow_writes" not in data:
            if aw != DEFAULTS["allow_writes"]:
                overrides["allow_writes"] = aw
            else:
                overrides.pop("allow_writes", None)
        if "sets" in data or "profiles" in data:
            dt, ds = _migrate_tools(data)
            if "disabled_tools" not in data:
                overrides["disabled_tools"] = dt
            if "disabled_sets" not in data:
                overrides["disabled_sets"] = ds
        notes = {
            "defaults": f"moved to top-level keys in config_version {n} (old block kept below)",
            "default_profile": f"not used since config_version {n} (old line kept below)",
            "profiles": f"replaced by disabled_tools in config_version {n} (old block kept below)",
            "sets": f"replaced by disabled_tools in config_version {n} (old block kept below)",
            "enabled_sets": f"replaced by disabled_tools in config_version {n}",
        }
        for k in legacy_present:
            if edit.active_member(out, k) is not None:
                out = edit.comment_out(out, k, notes[k])
                plan.migrated.append(k)

    # Missing keys.
    present = edit.present_keys(out)
    blocks = []
    for key in KEYS:
        if key.name in present:
            continue
        on = key.active or key.name in overrides
        body = render_block(key, overrides.get(key.name, key.default), active=on)
        blocks.append(f"{IND}// added in config_version {n}\n{body}")
        plan.added.append(key.name)
    if blocks:
        head = f"{IND}// === Added by airlock config upgrade (config_version {n}) ==="
        out = edit.inject(out, [head + "\n\n" + "\n\n".join(blocks)])

    # Version.
    if edit.active_member(out, "config_version") is None:
        out = edit.set_key(out, "config_version", n)
        plan.added.insert(0, "config_version")
    elif _version_of(data) < n:
        out = edit.set_key(out, "config_version", n)
    plan.new_text = out

    # The result must parse, resolve and keep every tool the user kept.
    try:
        new_data = parse_jsonc(out, "upgraded config")
        cfg = resolve(deep_merge({}, new_data), DIRTY_ROLE, None)
    except ConfigError as e:
        raise ConfigError(f"upgrade produced an invalid file ({e}); nothing was written") from e
    if legacy_present and "sets" in data:
        kept = _user_tools(data) & set(CATALOG)
        lost = sorted(t for t in kept if t not in cfg.tools
                      and not (CATALOG[t].writes and not cfg.allow_writes))
        if lost:
            raise ConfigError(f"upgrade would hide tools you use: {', '.join(lost)}")
        plan.new_tools = [t for t in cfg.tools if t not in _user_tools(data)]
    return plan


def stale_message(text: str) -> str | None:
    """Doctor and startup text if the file is older than the built-in layout."""
    plan = plan_upgrade(text)
    if plan.from_version >= plan.to_version:
        return None
    items = plan.new_tools + plan.added
    return (f"version {plan.from_version} < {plan.to_version}; {len(items)} tools/keys "
            "missing; run airlock config upgrade")


def upgrade_file(path: Path, dry_run: bool = False) -> tuple[UpgradePlan, Path | None]:
    """Upgrade in place. Writes `<file>.bak` first. Returns (plan, backup path)."""
    plan = plan_upgrade(path.read_text("utf-8-sig"))
    if dry_run or not plan.changed:
        return plan, None
    bak = path.with_name(path.name + ".bak")
    shutil.copy2(path, bak)
    path.write_text(plan.new_text, "utf-8")
    return plan, bak
