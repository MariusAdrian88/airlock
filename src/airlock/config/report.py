"""`airlock config`: show, set, unset, validate, upgrade."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from airlock import paths
from airlock.config import edit
from airlock.config.keys import DEFAULTS, KEY_BY_NAME, KEYS, coerce, validate_values
from airlock.config.loader import (
    ConfigError,
    check_unknown,
    deep_merge,
    effective_values,
    load_layers,
    parse_jsonc,
    resolve,
)
from airlock.config.template import config_meta
from airlock.config.upgrade import upgrade_file

BUILTIN = "built-in"
GLOBAL = "global file"
OVERLAY = "project overlay"


@dataclass
class Row:
    group: str
    key: str
    value: Any
    default: Any
    source: str


def _fmt(v: Any, width: int = 70) -> str:
    s = json.dumps(v)
    return s if len(s) <= width else s[: width - 3] + "..."


def config_report(path: Path | None = None, overlay: Path | None = None,
                  role: str = "dirty") -> list[Row]:
    lay = load_layers(path, overlay)
    merged: dict[str, Any] = {}
    for d in (lay.global_data, lay.overlay_data):
        if d is not None:
            merged = deep_merge(merged, d)
    eff = effective_values(merged, role)
    meta = config_meta()

    def source(k: str) -> str:
        if lay.overlay_data and k in lay.overlay_data:
            return OVERLAY
        if lay.global_data is not None:
            if k in lay.global_data:
                return GLOBAL
            if isinstance(lay.global_data.get("defaults"), dict) and k in lay.global_data["defaults"]:
                return GLOBAL + " (old defaults block)"
        return BUILTIN

    return [Row(meta[k.name][0], k.name, eff[k.name], k.default, source(k.name)) for k in KEYS]


def format_report(rows: list[Row]) -> str:
    out, group = [], None
    for r in rows:
        if r.group != group:
            group = r.group
            out.append(f"[{group}]")
        mark = "" if r.value == r.default else "  *"
        out.append(f"{r.key} = {_fmt(r.value)} | default {_fmt(r.default, 30)} | {r.source}{mark}")
    out.append("(* differs from the default)")
    return "\n".join(out)


def validate_text(path: Path | None, overlay: Path | None = None) -> list[str]:
    """One line per problem; empty when the file is fine."""
    lay = load_layers(path, overlay)
    msgs: list[str] = []
    merged: dict[str, Any] = {}
    for d, name in ((lay.global_data, str(lay.source)), (lay.overlay_data, str(lay.overlay_path))):
        if d is not None:
            merged = deep_merge(merged, d)
            msgs += [str(i) for i in check_unknown(d, name)]
    msgs += [f"error: {e}" for e in validate_values(effective_values(merged))]
    if not any(m.startswith("error") for m in msgs):
        try:
            cfg = resolve(merged, None, lay.source)
            msgs += [str(i) for i in cfg.issues if i.level == "warning" and "always on" in i.message]
        except ConfigError as e:
            msgs.append(f"error: {e}")
    return msgs


def _target(path: Path | None) -> Path:
    p = path or paths.default_config_path()
    if not p.exists():
        from airlock.config.loader import write_default_config
        write_default_config(p)
    return p


def set_value(path: Path | None, key: str, raw: Any) -> Any:
    """Validate, coerce and write one key; roll back if the result does not read back."""
    value = coerce(key, raw)
    p = _target(path)
    original = p.read_text("utf-8-sig")
    updated = edit.set_key(original, key, value)
    p.write_text(updated, "utf-8")
    try:
        data = parse_jsonc(updated, str(p))
        if data.get(key) != value:
            raise ValueError("value did not read back")
        errs = validate_values(effective_values(data))
        if errs:
            raise ValueError("; ".join(errs))
    except (ConfigError, ValueError) as e:
        p.write_text(original, "utf-8")
        raise ValueError(f"set failed (file restored): {e}") from e
    return value


def unset_value(path: Path | None, key: str) -> bool:
    """Return a key to its commented default. False if it was not active."""
    if key not in KEY_BY_NAME:
        raise ValueError(f"unknown key '{key}'")
    p = _target(path)
    original = p.read_text("utf-8-sig")
    updated = edit.unset_key(original, key, DEFAULTS[key])
    if updated == original:
        return False
    p.write_text(updated, "utf-8")
    try:
        parse_jsonc(updated, str(p))
    except ConfigError as e:
        p.write_text(original, "utf-8")
        raise ValueError(f"unset failed (file restored): {e}") from e
    return True


def run(args: Any) -> int:
    path: Path | None = args.config
    action = args.action or "show"
    try:
        if args.set:
            v = set_value(path, args.set[0], args.set[1])
            print(f"{args.set[0]} = {json.dumps(v)}")
            return 0
        if args.unset:
            done = unset_value(path, args.unset)
            print(f"{args.unset}: " + ("back to the default" if done else "was not set"))
            return 0
        if action == "upgrade":
            p = path or paths.default_config_path()
            if not p.exists():
                print(f"{p} does not exist; run `airlock init`")
                return 1
            plan, bak = upgrade_file(p, dry_run=args.dry_run)
            if not plan.changed:
                print(f"{p}: already up to date (config_version {plan.to_version})")
            elif args.dry_run:
                print(plan.diff(p.name), end="")
                print(f"# dry run: {plan.summary()}")
            else:
                print(f"upgraded {p} to config_version {plan.to_version}; backup {bak}")
                print(plan.summary())
            return 0
        if action == "validate":
            msgs = validate_text(path, args.overlay)
            print("\n".join(msgs) if msgs else "config ok")
            return 1 if any(m.startswith("error") for m in msgs) else 0
        print(format_report(config_report(path, args.overlay, args.profile or "dirty")))
        return 0
    except (ConfigError, ValueError) as e:
        print(f"airlock: {e}")
        return 2
