from pathlib import Path

import pytest

from airlock.config import ConfigError, load_config, write_default_config
from airlock.config.catalog import CATALOG
from airlock.config.loader import default_config_text, parse_jsonc


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "config.jsonc"
    p.write_text(text, "utf-8")
    return p


def test_default_config_parses_and_names_only_known_tools():
    data = parse_jsonc(default_config_text())
    for set_name, tools in data["sets"].items():
        for t in tools:
            assert t in CATALOG, f"{t} in set {set_name} is not in the catalog"


def test_dirty_profile_hides_commented_and_write_gated_tools(tmp_path):
    cfg_path = write_default_config(tmp_path / "config.jsonc", Path("C:/Tools/ghidra"))
    cfg = load_config(cfg_path, "dirty")
    assert cfg.role == "dirty"
    assert cfg.ghidra_dir == Path("C:/Tools/ghidra")
    assert "patch_bytes" not in cfg.tools          # commented out in the default file
    assert "rename" in cfg.tools                    # dirty profile allows writes
    assert "spec_read" not in cfg.tools             # spec_read set not enabled for dirty
    assert len(cfg.tools) == len(set(cfg.tools))    # spec_list listed twice, exposed once


def test_writes_off_removes_annotate_tools(tmp_path):
    p = _write(tmp_path, """{
      "ghidra_dir": "C:/g",
      "profiles": {"dirty": {"allow_writes": false}},
    }""")
    cfg = load_config(p, "dirty")
    assert not cfg.allow_writes
    assert not any(CATALOG[t].writes for t in cfg.tools)
    assert any(i.level == "info" and "rename" in i.message for i in cfg.issues)


def test_clean_profile_exposes_only_spec_tools(tmp_path):
    cfg = load_config(write_default_config(tmp_path / "c.jsonc"), "clean")
    assert cfg.is_clean
    assert set(cfg.tools) == {"spec_read", "spec_list", "spec_export"}
    assert not any(i.level == "error" for i in cfg.issues)  # no ghidra_dir needed


def test_clean_profile_with_code_tools_refuses_to_start(tmp_path):
    p = _write(tmp_path, """{
      "profiles": {"clean": {"role": "clean", "enabled_sets": ["spec_read", "core"]}}
    }""")
    with pytest.raises(ConfigError, match="function"):
        load_config(p, "clean")


def test_clean_profile_cannot_allow_writes(tmp_path):
    p = _write(tmp_path, """{
      "profiles": {"clean": {"role": "clean", "enabled_sets": ["spec_read"], "allow_writes": true}}
    }""")
    with pytest.raises(ConfigError, match="cannot allow writes"):
        load_config(p, "clean")


def test_unknown_profile_and_bad_values(tmp_path):
    p = _write(tmp_path, '{"ghidra_dir": "C:/g"}')
    with pytest.raises(ConfigError, match="not defined"):
        load_config(p, "nope")
    p = _write(tmp_path, '{"defaults": {"token_budget": -5}}')
    with pytest.raises(ConfigError, match="token_budget"):
        load_config(p)


def test_unknown_tool_and_set_are_reported_not_fatal(tmp_path):
    p = _write(tmp_path, """{
      "ghidra_dir": "C:/g",
      "sets": {"core": ["outline", "outlnie"]},
      "profiles": {"dirty": {"enabled_sets": ["core", "missing_set"]}},
    }""")
    cfg = load_config(p, "dirty")
    assert cfg.tools == ["outline"]
    msgs = " ".join(i.message for i in cfg.issues)
    assert "outlnie" in msgs and "missing_set" in msgs


def test_overlay_merges_and_null_removes(tmp_path):
    base = _write(tmp_path, '{"ghidra_dir": "C:/g", "defaults": {"token_budget": 3000}}')
    overlay = tmp_path / "project.jsonc"
    overlay.write_text("""{
      // Delphi + .NET project: add those sets
      "profiles": {"dirty": {"enabled_sets": ["core", "delphi", "dotnet"]}},
      "defaults": {"detail": null}
    }""", "utf-8")
    cfg = load_config(base, "dirty", project_overlay=overlay)
    assert "delphi_forms" in cfg.tools and "dotnet_types" in cfg.tools
    assert cfg.defaults["token_budget"] == 3000
    assert "detail" not in cfg.defaults
    assert cfg.allow_writes  # rest of the built-in dirty profile still applies


def test_missing_ghidra_dir_is_an_error_for_dirty(tmp_path):
    cfg = load_config(_write(tmp_path, "{}"), "dirty")
    assert any(i.level == "error" and "ghidra_dir" in i.message for i in cfg.issues)


def test_invalid_jsonc_names_the_file(tmp_path):
    p = _write(tmp_path, '{"ghidra_dir": }')
    with pytest.raises(ConfigError, match="config.jsonc"):
        load_config(p)
