import json
import re
from pathlib import Path

import pytest

from airlock.config import ConfigError, load_config, write_default_config
from airlock.config.catalog import CATALOG, SET_SUMMARIES, TOOL_SUMMARIES
from airlock.config.keys import DEFAULTS, KEY_BY_NAME, KEYS, coerce
from airlock.config.loader import default_config_text, parse_jsonc
from airlock.config.report import (
    config_report,
    format_report,
    set_value,
    unset_value,
    validate_text,
)
from airlock.config.template import config_meta, generate_template, known_keys


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "config.jsonc"
    p.write_text(text, "utf-8")
    return p


# ── template and known keys ──────────────────────────────────────────────────

def test_template_is_generated_and_parses_to_the_defaults():
    assert default_config_text() == generate_template()
    data = parse_jsonc(generate_template())
    for k in KEYS:
        if k.active:
            assert data[k.name] == k.default
        else:
            assert k.name not in data           # shipped commented out


def test_template_documents_every_known_key_once():
    text = generate_template()
    meta = config_meta()
    for k in KEYS:
        lines = re.findall(rf'^  (?://[ \t]*)?"{k.name}"[ \t]*:', text, re.MULTILINE)
        assert len(lines) == 1, k.name
        group, doc = meta[k.name]
        assert group and doc, k.name
        assert "Allowed:" in doc and "Change it:" in doc, k.name
        assert f"Default: {json.dumps(k.default)}." in doc, k.name


def test_known_keys_metadata_matches_template():
    rows = {r["name"]: r for r in known_keys()}
    assert set(rows) == set(KEY_BY_NAME)
    assert rows["bulk_decompile_timeout_s"]["default"] == 15
    assert "retried" in rows["bulk_decompile_timeout_s"]["doc"]
    for k in ("projects_root", "analysis_s_per_code_mb", "decompile_cpu_min", "mermaid"):
        assert k in rows


def test_every_catalog_tool_and_set_is_listed_once():
    full = generate_template()
    sets_part, text = full.split('"disabled_tools": [')
    for name in CATALOG:
        n = len(re.findall(rf'^\s+(?://\s*)?"{name}",', text, re.MULTILINE))
        assert n == (0 if CATALOG[name].always_on else 1), f"{name} listed {n} times"
        assert name in TOOL_SUMMARIES, name
    for s in {i.set for i in CATALOG.values()}:
        assert len(re.findall(rf'^\s+(?://\s*)?"{s}",', sets_part, re.MULTILINE)) == 1, s
        assert s in SET_SUMMARIES, s
    assert set(TOOL_SUMMARIES) == set(CATALOG)
    for d in (*TOOL_SUMMARIES.values(), *SET_SUMMARIES.values()):
        assert not re.search(r'["\[\]{}]', d), d    # the upgrade counts brackets


def test_registered_tools_are_all_in_the_catalog():
    from airlock.server.registry import IMPLEMENTED, load_tool_modules
    load_tool_modules()
    assert set(IMPLEMENTED) <= set(CATALOG)


# ── tool selection ───────────────────────────────────────────────────────────

def test_default_dirty_tool_list(tmp_path):
    cfg_path = write_default_config(tmp_path / "config.jsonc", Path("C:/Tools/ghidra"))
    cfg = load_config(cfg_path, "dirty")
    assert cfg.role == "dirty" and cfg.ghidra_dir == Path("C:/Tools/ghidra")
    assert "patch_bytes" not in cfg.tools           # disabled by default
    assert "rename" in cfg.tools                    # writes are on by default
    assert "delphi_forms" not in cfg.tools          # delphi set disabled by default
    assert {"projects", "project_open", "overview", "path", "graph_export"} <= set(cfg.tools)
    assert len(cfg.tools) == len(set(cfg.tools))


def test_new_tools_appear_without_editing_the_file(tmp_path):
    p = _write(tmp_path, '{"ghidra_dir": "C:/g", "disabled_tools": ["hexdump"]}')
    cfg = load_config(p, "dirty")
    assert "hexdump" not in cfg.tools and "file_diff" in cfg.tools
    assert "overview" in cfg.tools


def test_writes_off_removes_annotate_tools(tmp_path):
    p = _write(tmp_path, '{"ghidra_dir": "C:/g", "allow_writes": false}')
    cfg = load_config(p, "dirty")
    assert not cfg.allow_writes
    assert not any(CATALOG[t].writes for t in cfg.tools)
    assert any(i.level == "info" and "rename" in i.message for i in cfg.issues)


def test_clean_role_has_only_clean_safe_tools_and_cannot_be_widened(tmp_path):
    cfg = load_config(write_default_config(tmp_path / "c.jsonc"), "clean")
    assert cfg.is_clean and not cfg.allow_writes
    assert set(cfg.tools) == {t for t, i in CATALOG.items() if i.clean_safe}
    assert not any(i.level == "error" for i in cfg.issues)  # no ghidra_dir needed
    p = _write(tmp_path, '{"disabled_sets": [], "disabled_tools": ["spec_export"], "allow_writes": true}')
    cfg = load_config(p, "clean")
    assert "spec_export" not in cfg.tools and "function" not in cfg.tools
    assert not any(CATALOG[t].writes for t in cfg.tools)


def test_disabled_sets_hide_a_group(tmp_path):
    p = _write(tmp_path, '{"ghidra_dir": "C:/g", "disabled_sets": ["cpp", "delphi"]}')
    cfg = load_config(p, "dirty")
    assert "vtable" not in cfg.tools and "dotnet_types" in cfg.tools


# ── validation and unknown keys ──────────────────────────────────────────────

BAD = [
    ('{"token_budget": -5}', "token_budget"),
    ('{"token_budget": 1.5}', "token_budget"),
    ('{"detail": "loud"}', "detail"),
    ('{"mermaid": "yes"}', "mermaid"),
    ('{"bulk_decompile": "now"}', "bulk_decompile"),
    ('{"bulk_decompile_timeout_s": 0}', "bulk_decompile_timeout_s"),
    ('{"decompile_cpu_min": 0}', "decompile_cpu_min"),
    ('{"decompile_cpu_max": 1.5}', "decompile_cpu_max"),
    ('{"decompile_cpu_min": 0.9, "decompile_cpu_max": 0.5}', "must not exceed"),
    ('{"analysis_s_per_code_mb": -1}', "analysis_s_per_code_mb"),
    ('{"jvm_max_memory": "lots"}', "jvm_max_memory"),
    ('{"disabled_tools": "rename"}', "disabled_tools"),
    ('{"allow_writes": 1}', "allow_writes"),
    ('{"projects_root": "relative/dir"}', "absolute"),
    ('{"ghidra_dir": 5}', "ghidra_dir"),
    ('{"defaults": {"token_budget": -5}}', "token_budget"),
]


@pytest.mark.parametrize("text,needle", BAD)
def test_invalid_values_are_errors(tmp_path, text, needle):
    with pytest.raises(ConfigError, match=needle):
        load_config(_write(tmp_path, text), "dirty")


def test_unknown_profile(tmp_path):
    with pytest.raises(ConfigError, match="not defined"):
        load_config(_write(tmp_path, '{"ghidra_dir": "C:/g"}'), "nope")


def test_unknown_key_warns_with_a_suggestion(tmp_path):
    p = _write(tmp_path, '{"ghidra_dir": "C:/g", "token_budjet": 100, "zzzz": 1}')
    cfg = load_config(p, "dirty")                      # warns, does not fail
    msgs = [i.message for i in cfg.issues if i.level == "warning"]
    assert any("token_budjet" in m and "did you mean 'token_budget'" in m for m in msgs)
    assert any("'zzzz'" in m and "did you mean" not in m for m in msgs)
    assert cfg.defaults["token_budget"] == 2000        # ignored


def test_unknown_key_in_old_defaults_block_and_old_keys_warn(tmp_path):
    p = _write(tmp_path, '{"ghidra_dir": "C:/g", "defaults": {"detial": "full"}, "sets": {}}')
    msgs = " | ".join(i.message for i in load_config(p, "dirty").issues)
    assert "defaults.detial" in msgs and "did you mean 'detail'" in msgs
    assert "old key 'sets'" in msgs and "airlock config upgrade" in msgs


def test_unknown_tool_and_set_are_reported_not_fatal(tmp_path):
    p = _write(tmp_path, '{"ghidra_dir": "C:/g", "disabled_tools": ["outlnie"], '
                         '"disabled_sets": ["missing_set"]}')
    cfg = load_config(p, "dirty")
    msgs = " ".join(i.message for i in cfg.issues)
    assert "outlnie" in msgs and "missing_set" in msgs


def test_validate_reports_all_problems(tmp_path):
    p = _write(tmp_path, '{"token_budget": 0, "mermaid": 3, "tokn": 1}')
    msgs = validate_text(p)
    assert sum(m.startswith("error") for m in msgs) == 2
    assert any("tokn" in m for m in msgs)
    assert validate_text(write_default_config(tmp_path / "ok.jsonc")) == []


def test_old_defaults_block_is_still_read(tmp_path):
    p = _write(tmp_path, '{"ghidra_dir": "C:/g", "defaults": {"token_budget": 3000}, "token_budget": 4000}')
    assert load_config(p, "dirty").defaults["token_budget"] == 4000   # top-level wins
    p = _write(tmp_path, '{"ghidra_dir": "C:/g", "defaults": {"token_budget": 3000}}')
    assert load_config(p, "dirty").defaults["token_budget"] == 3000


# ── layers ───────────────────────────────────────────────────────────────────

def test_overlay_merges_and_null_restores_the_default(tmp_path):
    base = _write(tmp_path, '{"ghidra_dir": "C:/g", "token_budget": 3000, "detail": "full"}')
    overlay = tmp_path / "project.jsonc"
    overlay.write_text("""{
      // Delphi project: show that set again
      "disabled_sets": ["dotnet"],
      "detail": null
    }""", "utf-8")
    cfg = load_config(base, "dirty", project_overlay=overlay)
    assert "delphi_forms" in cfg.tools and "dotnet_types" not in cfg.tools
    assert cfg.defaults["token_budget"] == 3000
    assert cfg.defaults["detail"] == "brief"
    assert cfg.allow_writes


def test_missing_ghidra_dir_is_an_error_for_dirty(tmp_path):
    cfg = load_config(_write(tmp_path, "{}"), "dirty")
    assert any(i.level == "error" and "ghidra_dir" in i.message for i in cfg.issues)


def test_invalid_jsonc_names_the_file(tmp_path):
    with pytest.raises(ConfigError, match="config.jsonc"):
        load_config(_write(tmp_path, '{"ghidra_dir": }'))


# ── config show / set / unset ────────────────────────────────────────────────

def test_config_show_sources(tmp_path):
    g = _write(tmp_path, '{"token_budget": 3000, "defaults": {"detail": "full"}, "mermaid": true}')
    ov = tmp_path / "o.jsonc"
    ov.write_text('{"mermaid": false}', "utf-8")
    rows = {r.key: r for r in config_report(g, ov)}
    assert (rows["token_budget"].value, rows["token_budget"].source) == (3000, "global file")
    assert rows["detail"].source == "global file (old defaults block)"
    assert (rows["mermaid"].value, rows["mermaid"].source) == (False, "project overlay")
    assert rows["max_budget"].source == "built-in" and rows["max_budget"].value == 32000
    assert set(rows) == set(KEY_BY_NAME)
    text = format_report(list(rows.values()))
    assert "token_budget = 3000 | default 2000 | global file  *" in text


def test_config_show_without_a_file(tmp_path):
    rows = config_report(tmp_path / "none.jsonc")
    assert all(r.source == "built-in" for r in rows)


def test_set_and_unset_keep_comments_and_roll_back(tmp_path):
    p = write_default_config(tmp_path / "config.jsonc")
    before = p.read_text("utf-8")
    assert set_value(p, "token_budget", "4000") == 4000
    text = p.read_text("utf-8")
    assert '\n  "token_budget": 4000,' in text and '// "token_budget"' not in text
    assert text.count("//") == before.count("//") - 1       # only the key's own // went
    assert load_config(p).defaults["token_budget"] == 4000
    assert set_value(p, "disabled_tools", "patch_bytes,hexdump") == ["patch_bytes", "hexdump"]
    assert "hexdump" not in load_config(p).tools
    assert unset_value(p, "token_budget") is True
    assert '// "token_budget": 2000,' in p.read_text("utf-8")
    assert unset_value(p, "token_budget") is False
    snapshot = p.read_text("utf-8")
    for key, raw in (("token_budget", "-1"), ("detail", "loud"), ("tokn", "1"),
                     ("mermaid", "maybe"), ("config_version", "5")):
        with pytest.raises(ValueError):
            set_value(p, key, raw)
    assert p.read_text("utf-8") == snapshot                 # nothing written


def test_set_creates_the_file_and_coerces(tmp_path):
    p = tmp_path / "new" / "config.jsonc"
    assert set_value(p, "mermaid", "true") is True
    assert set_value(p, "jvm_max_memory", "8G") == "8G"
    assert set_value(p, "decompile_cpu_max", "0.9") == 0.9
    assert coerce("jvm_max_memory", "null") is None
    cfg = load_config(p)
    assert cfg.defaults["mermaid"] is True and cfg.defaults["jvm_max_memory"] == "8G"
    assert DEFAULTS["mermaid"] is False


# ── always-on tools ──────────────────────────────────────────────────────────

ALWAYS_ON = [n for n, i in CATALOG.items() if i.always_on]


@pytest.mark.parametrize("role", ["dirty", "clean"])
@pytest.mark.parametrize("name", ALWAYS_ON)
def test_disabling_an_always_on_tool_or_its_set_is_ignored(tmp_path, role, name):
    for key, val in (("disabled_tools", name), ("disabled_sets", CATALOG[name].set)):
        p = _write(tmp_path, '{"ghidra_dir": "C:/g", "%s": ["%s"]}' % (key, val))
        cfg = load_config(p, role)
        msgs = [i.message for i in cfg.issues if i.level == "warning"]
        assert f"config: {name} is always on and cannot be disabled (ignored)" in msgs
        if role == "dirty" or CATALOG[name].clean_safe:
            assert name in cfg.tools


def test_clean_tool_list_contents(tmp_path):
    p = _write(tmp_path, '{"disabled_sets": ["admin", "spec_read"], "disabled_tools": ["spec_export"]}')
    assert sorted(load_config(p, "clean").tools) == sorted(
        ["spec_read", "spec_list", "projects", "project_open", "project_info"])
    p = _write(tmp_path, '{}')
    assert sorted(load_config(p, "clean").tools) == sorted(
        ["spec_read", "spec_list", "spec_export", "projects", "project_open", "project_info"])


def test_template_lists_always_on_separately():
    text = generate_template()
    assert "always on (cannot be disabled)" in text
    sets_part, tools_part = text.split('"disabled_tools": [')
    for n in ALWAYS_ON:
        assert not re.search(rf'^\s+(?://\s*)?"{n}",', tools_part, re.MULTILINE), n


def test_validate_shows_always_on_warning(tmp_path):
    p = _write(tmp_path, '{"disabled_tools": ["project_open"]}')
    assert any("project_open is always on" in m for m in validate_text(p))
