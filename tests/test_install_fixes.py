"""Install-time fixes: Python 3.10 syntax, doctor --fix for ilspycmd, no-config doctor, error texts."""

import ast
from pathlib import Path

import pytest

from airlock import doctor
from airlock.config import ConfigError, load_config
from airlock.config.loader import parse_jsonc

SRC = Path(__file__).parent.parent / "src"


def test_sources_parse_as_python_310():
    bad = []
    for p in sorted(SRC.rglob("*.py")):
        try:
            ast.parse(p.read_text("utf-8-sig"), str(p), feature_version=(3, 10))
        except SyntaxError as e:
            bad.append(f"{p.name}:{e.lineno}: {e.msg}")
    assert not bad, bad


@pytest.fixture
def cfg_file(tmp_path):
    p = tmp_path / "config.jsonc"
    p.write_text('{"config_version": 1, "index_dir": "%s", "projects_root": "%s"}'
                 % ((tmp_path / "data").as_posix(), (tmp_path / "proj").as_posix()), "utf-8")
    return p


def _fake_installer(monkeypatch, ok=True):
    calls = []

    def fake(dest, *a):
        calls.append(dest)
        if ok:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"x")
        return ok, f"installed at {dest}" if ok else "offline"

    monkeypatch.setattr(doctor, "install_ilspycmd", fake)
    return calls


def test_doctor_warns_when_ilspycmd_is_not_set(cfg_file, monkeypatch, capsys):
    calls = _fake_installer(monkeypatch)
    doctor.run(cfg_file, None, fix=False, start=False)
    out = capsys.readouterr().out
    assert "[WARN ] ilspycmd: not set; optional, for .NET; run `airlock doctor --fix`" in out
    assert not calls


def test_doctor_fix_installs_ilspycmd_and_writes_config(cfg_file, tmp_path, monkeypatch, capsys):
    calls = _fake_installer(monkeypatch)
    doctor.run(cfg_file, None, fix=True, start=False)
    out = capsys.readouterr().out
    dest = tmp_path / "data" / "tools" / "ilspycmd.exe"
    assert calls == [dest] and dest.is_file()
    assert "[FIXED] ilspycmd:" in out
    assert Path(parse_jsonc(cfg_file.read_text("utf-8"))["ilspycmd"]) == dest
    assert load_config(cfg_file).ilspycmd == dest


def test_doctor_fix_reports_a_failed_install(cfg_file, monkeypatch, capsys):
    _fake_installer(monkeypatch, ok=False)
    doctor.run(cfg_file, None, fix=True, start=False)
    out = capsys.readouterr().out
    assert "[WARN ] ilspycmd: install failed: offline" in out
    assert "ilspycmd" not in parse_jsonc(cfg_file.read_text("utf-8"))


def test_doctor_without_config(tmp_path, monkeypatch, capsys):
    calls = _fake_installer(monkeypatch)
    missing = tmp_path / "none.jsonc"
    doctor.run(missing, None, fix=True, start=False)
    out = capsys.readouterr().out
    assert "[WARN ] config: no config file; run `airlock init --ghidra <path>`" in out
    assert "[WARN ] fix: needs a config file first" in out
    assert "[FAIL] config" not in out and "[FAIL ] config" not in out
    assert "[FAIL ] ghidra: ghidra_dir is not set; run `airlock init --ghidra <path>`" in out
    assert not calls and not missing.exists()


def test_stale_warning_is_short(tmp_path, capsys):
    p = tmp_path / "config.jsonc"
    p.write_text('{"index_dir": "%s", "projects_root": "%s"}'
                 % ((tmp_path / "d").as_posix(), (tmp_path / "p").as_posix()), "utf-8")
    doctor.run(p, None, fix=False, start=False)
    line = next(ln for ln in capsys.readouterr().out.splitlines() if "version 0 <" in ln)
    assert line.endswith("tools/keys missing; run airlock config upgrade") and "(" not in line


def test_invalid_jsonc_message(tmp_path):
    p = tmp_path / "config.jsonc"
    p.write_text("{\n", "utf-8")
    with pytest.raises(ConfigError) as e:
        load_config(p)
    msg = str(e.value)
    assert msg.startswith(f"{p}: invalid JSONC at line 2 column 1: Unexpected end of input.")
    assert msg.endswith("Fix the file, or run airlock init --force.") and "<string>" not in msg


def test_ghidra_dir_messages(tmp_path):
    cfg = load_config(tmp_path / "none.jsonc")
    assert any(i.message == "ghidra_dir is not set; run airlock init --ghidra <path>" for i in cfg.issues)
    from airlock.worker.client import WorkerClient
    from airlock.worker.protocol import WorkerError
    with pytest.raises(WorkerError) as e:
        WorkerClient(cfg).ensure_ghidra()
    assert "set it with airlock init --ghidra <path>" in e.value.message


def test_serve_warns_without_ghidra_dir(tmp_path, monkeypatch, capsys):
    import argparse

    from airlock import cli
    served = []
    monkeypatch.setattr("airlock.server.app.serve", lambda cfg, profile_explicit: served.append(cfg))
    monkeypatch.setattr("airlock.logs.setup_server_logging", lambda d: None)
    args = argparse.Namespace(config=tmp_path / "none.jsonc", profile=None)
    assert cli._cmd_serve(args) == 0 and served
    assert "ghidra_dir is not set in config.jsonc; set it with airlock init --ghidra <path>" in capsys.readouterr().err
    args.profile = "clean"
    cli._cmd_serve(args)
    assert "ghidra_dir" not in capsys.readouterr().err


def test_ghidra_inspect_error_has_the_fix(tmp_path):
    from airlock import ghidra_install
    with pytest.raises(FileNotFoundError, match="check ghidra_dir in config.jsonc"):
        ghidra_install.inspect(tmp_path)


def test_set_key_in_a_one_line_config():
    from airlock.config import edit
    out = edit.set_key('{"a": 1}', "ilspycmd", "C:/x/ilspycmd.exe")
    assert parse_jsonc(out) == {"a": 1, "ilspycmd": "C:/x/ilspycmd.exe"}
