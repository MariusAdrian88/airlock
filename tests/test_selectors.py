import pytest

from airlock.index.store import Store
from airlock.server.selectors import fmt_addr, parse_address, resolve_function


@pytest.fixture
def env(tmp_path):
    s = Store(tmp_path / "i.sqlite")
    b = s.upsert_binary("ab" * 32, "app.exe", pointer_size=4)
    s.insert_functions(b, [
        {"entry": 0x401000, "name": "main", "name_state": "user", "size": 0x40},
        {"entry": 0x401100, "name": "OnFoo", "namespace": "CMainFrame", "name_state": "recovered", "size": 0x20},
        {"entry": 0x401300, "name": "dup", "name_state": "auto", "size": 4},
        {"entry": 0x401400, "name": "dup", "name_state": "auto", "size": 4},
        {"entry": 0xDEAD, "name": "beef", "name_state": "auto", "size": 4},
        {"entry": 0xBEEF, "name": "deadbeef", "name_state": "auto", "size": 4},
        {"entry": 1, "space": "EXTERNAL", "name": "CreateFileW", "name_state": "library"},
    ])
    yield s, b
    s.close()


def test_parse_address():
    assert parse_address("0x401000") == ("ram", 0x401000)
    assert parse_address("0X1F") == ("ram", 0x1F)
    assert parse_address("EXTERNAL:0x1") == ("EXTERNAL", 1)
    assert parse_address("external:0x1") == ("EXTERNAL", 1)
    assert parse_address("CMainFrame::OnFoo") is None
    assert parse_address("main") is None
    assert parse_address("0xzz") is None


def test_fmt_addr():
    assert fmt_addr(0x401000, 4) == "0x00401000"
    assert fmt_addr(0x401000, 8) == "0x0000000000401000"
    assert fmt_addr(1, 4, "EXTERNAL") == "EXTERNAL:0x00000001"


def test_exact_address(env):
    s, b = env
    r = resolve_function(s, b, "0x00401000")
    assert r.ok and r.function.name == "main" and r.note is None


def test_name_and_namespace(env):
    s, b = env
    assert resolve_function(s, b, "main").function.entry == 0x401000
    assert resolve_function(s, b, "CMainFrame::OnFoo").function.entry == 0x401100
    assert resolve_function(s, b, "OnFoo").function.entry == 0x401100


def test_bare_hex(env):
    s, b = env
    assert resolve_function(s, b, "401100").function.name == "OnFoo"


def test_name_wins_over_bare_hex(env):
    s, b = env
    # "beef" is a function name AND hex 0xbeef (-> deadbeef). Name wins.
    assert resolve_function(s, b, "beef").function.entry == 0xDEAD


def test_ambiguous(env):
    s, b = env
    r = resolve_function(s, b, "dup")
    assert not r.ok
    assert r.error.startswith("error ambiguous: ")
    assert "0x00401300" in r.error and "0x00401400" in r.error
    assert r.error.endswith(".") and "\n" not in r.error


def test_interior(env):
    s, b = env
    r = resolve_function(s, b, "0x401110")
    assert r.function.name == "OnFoo"
    assert "resolved from interior address 0x00401110" in r.note
    r = resolve_function(s, b, "401110")
    assert r.function.name == "OnFoo" and r.note


def test_not_found(env):
    s, b = env
    for t in ("nope", "0x999999", "999999"):
        r = resolve_function(s, b, t)
        assert not r.ok and r.error.startswith("error not_found: ") and "\n" not in r.error


def test_external_space(env):
    s, b = env
    assert resolve_function(s, b, "EXTERNAL:0x1").function.name == "CreateFileW"
    assert resolve_function(s, b, "CreateFileW").function.space == "EXTERNAL"


def test_empty(env):
    s, b = env
    assert resolve_function(s, b, "  ").error.startswith("error bad_target: ")


def test_import_thunk_beats_external_of_same_name(tmp_path):
    s = Store(tmp_path / "i.sqlite")
    b = s.upsert_binary("cd" * 32, "a.exe", pointer_size=4)
    s.insert_functions(b, [
        {"entry": 0x401000, "name": "CreateFileW", "name_state": "library", "size": 6, "is_thunk": True},
        {"entry": 1, "space": "EXTERNAL", "name": "CreateFileW", "name_state": "library", "is_external": True},
    ])
    r = resolve_function(s, b, "CreateFileW")
    assert r.ok and r.function.entry == 0x401000
    s.close()
