"""`airlock config upgrade`, doctor warning and doctor --fix."""

from pathlib import Path

import pytest

from airlock.config import CONFIG_VERSION, load_config
from airlock.config.catalog import CATALOG
from airlock.config.keys import KEYS
from airlock.config.loader import parse_jsonc
from airlock.config.template import generate_template
from airlock.config.upgrade import plan_upgrade, stale_message, upgrade_file

OLD = Path(__file__).parent / "data" / "config_m0_verbose.jsonc"

# What the M0 default file exposed to the dirty profile, minus the tool the
# fixture's user removed (hexdump).
NEW_SINCE_M0 = {"projects", "project_open", "project_create", "program_scan", "program_add",
                "overview", "features", "feature", "feature_define", "project_describe",
                "function_map", "cluster_label", "path", "graph_export"}


@pytest.fixture
def old(tmp_path):
    p = tmp_path / "config.jsonc"
    text = OLD.read_text("utf-8")
    text = text.replace('"index_dir": null,', f'"index_dir": "{(tmp_path / "data").as_posix()}",')
    p.write_text(text, "utf-8")
    return p


def test_old_file_hides_new_tools_before_upgrade_is_irrelevant_now(old):
    # old allow-lists are ignored (with a warning); all tools show until upgraded
    cfg = load_config(old, "dirty")
    assert any("old key 'sets'" in i.message for i in cfg.issues)


def test_upgrade_old_verbose_file(old):
    original = old.read_text("utf-8")
    plan, bak = upgrade_file(old)
    new = old.read_text("utf-8")

    assert bak == old.with_name("config.jsonc.bak") and bak.read_text("utf-8") == original
    data = parse_jsonc(new)                                   # still valid JSONC
    assert data["config_version"] == CONFIG_VERSION
    assert "sets" not in data and "profiles" not in data and "defaults" not in data

    # user values and comments survive
    assert data["token_budget"] == 3000 and data["decompile_timeout_s"] == 120
    assert data["ghidra_dir"] == "C:/Tools/ghidra_test"
    assert "// my own header comment." in new
    assert "MY NOTE: bigger answers please" in new
    assert "max_budget" not in data and "bulk_decompile" not in data   # old defaults not pinned
    assert "replaced by disabled_tools in config_version 1" in new
    assert "// added in config_version 1" in new

    # tools: new ones appear, the commented-out one stays removed
    cfg = load_config(old, "dirty")
    assert not [i for i in cfg.issues if i.level == "warning"], cfg.issues
    assert "hexdump" not in cfg.tools and "hexdump" in data["disabled_tools"]
    assert "patch_bytes" not in cfg.tools
    assert NEW_SINCE_M0 <= set(cfg.tools)
    expected = {t for t, i in CATALOG.items() if i.set not in ("delphi", "dotnet")} - {"patch_bytes", "hexdump"}
    assert set(cfg.tools) == expected
    assert plan.migrated == ["defaults", "default_profile", "profiles", "sets"] or \
        set(plan.migrated) == {"defaults", "default_profile", "profiles", "sets"}
    assert NEW_SINCE_M0 <= set(plan.new_tools)

    # every known key is now present, active or commented
    for k in KEYS:
        assert f'"{k.name}"' in new


def test_upgrade_is_idempotent_and_a_current_file_is_unchanged(old, tmp_path):
    upgrade_file(old)
    once = old.read_text("utf-8")
    plan, bak = upgrade_file(old)
    assert not plan.changed and bak is None and old.read_text("utf-8") == once
    fresh = tmp_path / "fresh.jsonc"
    fresh.write_text(generate_template(), "utf-8")
    plan, bak = upgrade_file(fresh)
    assert not plan.changed and bak is None
    assert not (tmp_path / "fresh.jsonc.bak").exists()


def test_dry_run_prints_a_diff_and_writes_nothing(old, capsys):
    from airlock.config.report import run
    import argparse
    before = old.read_text("utf-8")
    ns = argparse.Namespace(config=old, action="upgrade", set=None, unset=None,
                            dry_run=True, overlay=None, profile=None)
    assert run(ns) == 0
    out = capsys.readouterr().out
    assert out.startswith("--- config.jsonc (current)\n+++ config.jsonc (upgraded)")
    assert '+  "disabled_tools": [' in out and "-  \"sets\": {" in out
    assert old.read_text("utf-8") == before
    assert not old.with_name("config.jsonc.bak").exists()


def test_commented_out_keys_stay_removed_and_missing_ones_are_added(tmp_path):
    p = tmp_path / "config.jsonc"
    p.write_text("""{
  // mine
  "config_version": 0,
  "ghidra_dir": "C:/g"   // no comma, trailing comment
  // "mermaid": true,
  // "disabled_tools": ["hexdump"],
}""", "utf-8")
    plan, _ = upgrade_file(p)
    new = p.read_text("utf-8")
    data = parse_jsonc(new)
    assert "mermaid" not in data and "disabled_tools" not in data and "mermaid" not in plan.added
    assert '// "mermaid": true,' in new                       # untouched
    assert "token_budget" in plan.added and data["config_version"] == 1
    assert data["ghidra_dir"] == "C:/g" and "// mine" in new
    assert plan_upgrade(new).changed is False


def test_user_who_enabled_delphi_and_patch_bytes_keeps_them(tmp_path):
    text = OLD.read_text("utf-8").replace(
        '"enabled_sets": ["core", "cpp", "resources", "types", "annotate",\n'
        '                       "dataflow", "fileformat", "spec_write", "admin"]',
        '"enabled_sets": ["core", "cpp", "resources", "types", "annotate", "delphi",\n'
        '                       "dataflow", "fileformat", "spec_write", "admin"]').replace(
        '"struct_define"\n      // "patch_bytes"', '"struct_define", "patch_bytes"')
    plan = plan_upgrade(text)
    data = parse_jsonc(plan.new_text)
    assert "delphi" not in data["disabled_sets"] and "dotnet" in data["disabled_sets"]
    assert "patch_bytes" not in data["disabled_tools"]


def test_dirty_profile_without_writes_is_kept(tmp_path):
    text = OLD.read_text("utf-8").replace('"allow_writes": true', '"allow_writes": false')
    data = parse_jsonc(plan_upgrade(text).new_text)
    assert data["allow_writes"] is False


# ── startup / doctor ─────────────────────────────────────────────────────────

def test_stale_message_text(old):
    msg = stale_message(old.read_text("utf-8"))
    assert msg.startswith("version 0 < 1; ") and "tools/keys missing (" in msg
    assert msg.endswith("run airlock config upgrade")
    assert stale_message(generate_template()) is None


@pytest.fixture
def doctor_cfg(old):
    from airlock import doctor
    return doctor, old


def test_doctor_warns_about_an_old_file(doctor_cfg, capsys):
    doctor, p = doctor_cfg
    doctor.run(p, None, fix=False, start=False)
    out = capsys.readouterr().out
    line = next(ln for ln in out.splitlines() if "version 0 < 1" in ln)
    assert line.startswith("[WARN ] config: version 0 < 1; ")
    assert "tools/keys missing" in line and "run airlock config upgrade" in line
    assert not p.with_name("config.jsonc.bak").exists()


def test_doctor_fix_upgrades_with_a_backup(doctor_cfg, capsys):
    doctor, p = doctor_cfg
    doctor.run(p, None, fix=True, start=False)
    out = capsys.readouterr().out
    assert "[FIXED] config: upgraded to version 1" in out
    assert p.with_name("config.jsonc.bak").exists()
    assert parse_jsonc(p.read_text("utf-8"))["config_version"] == 1
    doctor.run(p, None, fix=False, start=False)
    assert "version 0 < 1" not in capsys.readouterr().out


def test_server_start_logs_the_stale_warning(old, caplog):
    from airlock.server.app import build_server
    with caplog.at_level("WARNING", logger="airlock"):
        build_server(load_config(old, "dirty"))
    assert any("version 0 < 1" in r.getMessage() for r in caplog.records)
