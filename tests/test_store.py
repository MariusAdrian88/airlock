import sqlite3

import pytest

from airlock.index import store as store_mod
from airlock.index.store import Store

PROFILE = "p1"


@pytest.fixture
def st(tmp_path):
    s = Store(tmp_path / "sub" / "index.sqlite")
    yield s
    s.close()


@pytest.fixture
def bid(st):
    b = st.upsert_binary("ab" * 32, "app.exe", format="pe32", pointer_size=4, image_base=0x400000)
    st.insert_functions(b, [
        {"entry": 0x1000, "name": "main", "name_state": "user", "size": 0x40},
        {"entry": 0x1100, "name": "OnFoo", "namespace": "CMainFrame", "name_state": "recovered", "size": 0x20},
        {"entry": 0x1200, "name": "FUN_00001200", "name_state": "auto", "size": 0x10},
        {"entry": 0x1300, "name": "dup", "name_state": "auto", "size": 4},
        {"entry": 0x1400, "name": "dup", "name_state": "auto", "size": 4},
        {"entry": 1, "space": "EXTERNAL", "name": "CreateFileW", "name_state": "library",
         "is_external": True},
    ])
    st.insert_edges(b, [
        (0x1010, 0x1100, "call"),
        (0x1020, 0x1200, "call"),
        (0x1110, 0x1200, "jump"),
        (0x1030, 0x2000, "data"),
        (0x103c, 0x1100, "call_ind"),
        (0x120c, 0x1000, "call"),
    ])
    st.insert_strings(b, [(0x2000, "ascii", "Could not open file %s"), (0x2100, "utf16le", "100%_done")])
    st.insert_imports(b, [("KERNEL32.dll", "CreateFileW", None, 0x3000), ("USER32.dll", None, 5, 0x3004)])
    st.link_edges(b)
    st.rebuild_fts(b)
    return b


def test_schema_created_and_reopened(tmp_path):
    p = tmp_path / "i.sqlite"
    s = Store(p)
    assert s.schema_version == store_mod.SCHEMA_VERSION
    assert s.db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert s.db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    s.close()
    s2 = Store(p)
    assert s2.schema_version == store_mod.SCHEMA_VERSION
    s2.close()


def test_migration_hook(tmp_path, monkeypatch):
    p = tmp_path / "i.sqlite"
    Store(p).close()
    calls = []

    def mig(db):
        calls.append(1)
        db.execute("CREATE TABLE extra(x)")

    monkeypatch.setattr(store_mod, "SCHEMA_VERSION", 2)
    monkeypatch.setitem(store_mod.MIGRATIONS, 2, mig)
    s = Store(p)
    assert calls == [1] and s.schema_version == 2
    s.close()


def test_missing_migration_and_newer_schema(tmp_path, monkeypatch):
    p = tmp_path / "i.sqlite"
    Store(p).close()
    monkeypatch.setattr(store_mod, "SCHEMA_VERSION", 2)
    with pytest.raises(RuntimeError):
        Store(p)
    monkeypatch.setattr(store_mod, "SCHEMA_VERSION", 0)
    with pytest.raises(RuntimeError):
        Store(p)


def test_binaries(st, bid):
    assert [b.name for b in st.list_binaries()] == ["app.exe"]
    assert st.get_binary("APP.EXE").id == bid
    assert st.get_binary("abab").id == bid
    assert st.get_binary("zz") is None
    assert st.upsert_binary("ab" * 32, "app.exe", arch="x86") == bid
    assert st.get_binary_by_id(bid).arch == "x86"
    with pytest.raises(ValueError):
        st.upsert_binary("cd" * 32, "x", bogus=1)
    st.upsert_binary("abcd" * 16, "other.dll")
    assert st.get_binary("ab") is None  # ambiguous prefix
    assert len(st.find_binaries("ab")) == 2


def test_function_lookups(st, bid):
    assert st.function_at(bid, 0x1000).name == "main"
    assert st.function_at(bid, 0x1001) is None
    assert st.function_containing(bid, 0x1020).name == "main"
    assert st.function_containing(bid, 0x1040) is None  # entry+size is exclusive
    assert st.function_containing(bid, 0x500) is None
    assert [f.entry for f in st.functions_by_name(bid, "dup")] == [0x1300, 0x1400]
    fn = st.functions_by_name(bid, "CMainFrame::OnFoo")[0]
    assert fn.entry == 0x1100 and fn.qualified_name == "CMainFrame::OnFoo"
    assert st.functions_by_name(bid, "OnFoo")[0].entry == 0x1100
    assert st.functions_by_name(bid, "CreateFileW")[0].is_external is True
    assert st.count_by_name_state(bid) == {"auto": 3, "library": 1, "recovered": 1, "user": 1}
    assert len(st.list_functions(bid, name_state="auto")) == 3


def test_reinsert_bumps_version(st, bid):
    st.insert_functions(bid, [{"entry": 0x1000, "name": "main2", "name_state": "user", "size": 0x40}])
    fn = st.function_at(bid, 0x1000)
    assert fn.name == "main2" and fn.version == 1


def test_xrefs_and_calls(st, bid):
    foo = st.function_at(bid, 0x1100)
    main = st.function_at(bid, 0x1000)
    to = st.xrefs_to_function(foo)
    assert [(x.src_addr, x.kind, x.src_fn.name) for x in to] == [
        (0x1010, "call", "main"), (0x103c, "call_ind", "main")]
    assert len(st.xrefs_to_function(foo, kinds=["call"])) == 1
    assert [x.kind for x in st.xrefs_from_function(main, kinds=["data"])] == ["data"]
    assert len(st.xrefs_to_address(bid, 0x1200)) == 2
    assert len(st.xrefs_from_address(bid, 0x1010)) == 1
    assert [f.name for f in st.callees(main)] == ["OnFoo", "FUN_00001200"]
    fun = st.function_at(bid, 0x1200)
    assert [f.name for f in st.callers(fun)] == ["main", "OnFoo"]
    assert [f.name for f in st.callers(main)] == ["FUN_00001200"]


def test_strings(st, bid):
    hits = st.search_strings(bid, "open file")
    assert len(hits) == 1 and hits[0].address == 0x2000
    assert [f.name for f in hits[0].refs] == ["main"]
    assert st.search_strings(bid, r"^could.*%s$", regex=True)[0].address == 0x2000
    assert len(st.search_strings(bid, "%_")) == 1  # LIKE wildcards are escaped
    assert st.search_strings(bid, "zzz") == []
    assert st.search_strings(bid, "open", with_refs=False)[0].refs == ()
    assert st.get_string(hits[0].id).value.startswith("Could")


def test_imports(st, bid):
    assert len(st.list_imports(bid)) == 2
    assert [r["name"] for r in st.list_imports(bid, dll="kernel32.dll")] == ["CreateFileW"]


def test_fts(st, bid):
    hits = st.fts_search(bid, "onfoo", kind="function")
    assert [(h.kind, h.text) for h in hits] == [("function", "CMainFrame::OnFoo")]
    assert st.get_function(hits[0].ref_id).name == "OnFoo"
    assert {h.kind for h in st.fts_search(bid, "createfile")} == {"function", "import"}
    s = st.fts_search(bid, "open file", kind="string")
    assert len(s) == 1 and st.get_string(s[0].ref_id).address == 0x2000
    assert st.fts_search(bid, "***") == []
    # rebuild is idempotent
    st.rebuild_fts(bid)
    assert len(st.fts_search(bid, "onfoo")) == 1


def test_decomp_cache_validity(st, bid):
    fn = st.function_at(bid, 0x1000)
    assert st.get_decomp(fn, PROFILE) is None
    st.upsert_decomp(fn.id, fn.version, PROFILE, "ok", c_text="int main(){}")
    assert st.get_decomp(fn, PROFILE).c_text == "int main(){}"
    assert st.get_decomp(fn, "other") is None
    st.upsert_decomp(fn.id, fn.version, PROFILE, "ok", c_text="v2")
    assert st.get_decomp(fn, PROFILE).c_text == "v2"
    st.insert_functions(bid, [{"entry": 0x1000, "name": "main", "name_state": "user", "size": 0x40}])
    assert st.get_decomp(st.function_at(bid, 0x1000), PROFILE) is None  # version bumped


def test_ast_nodes(st, bid):
    fn = st.function_at(bid, 0x1000)
    st.insert_ast_nodes(fn.id, [
        {"kind": "call", "start_off": 5, "end_off": 9, "address": 0x1010, "target": 0x1100, "text": "OnFoo"},
        {"kind": "stmt", "start_off": 0, "end_off": 20},
    ])
    assert [r["kind"] for r in st.get_ast_nodes(fn.id)] == ["stmt", "call"]
    assert len(st.get_ast_nodes(fn.id, kind="call")) == 1
    st.insert_ast_nodes(fn.id, [])
    assert st.get_ast_nodes(fn.id) == []


def test_clear_binary_data(st, bid):
    fn = st.function_at(bid, 0x1000)
    st.upsert_decomp(fn.id, 0, PROFILE, "ok", c_text="x")
    st.insert_ast_nodes(fn.id, [{"kind": "stmt", "start_off": 0, "end_off": 1}])
    st.clear_binary_data(bid)
    assert st.list_functions(bid) == []
    assert st.search_strings(bid, "") == []
    assert st.fts_search(bid, "main") == []
    assert st.db.execute("SELECT COUNT(*) FROM edge").fetchone()[0] == 0


def test_foreign_keys_enforced(st):
    with pytest.raises(sqlite3.IntegrityError):
        st.insert_strings(999, [(1, "ascii", "x")])
