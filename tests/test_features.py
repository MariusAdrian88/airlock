"""Feature index: API/string tables, derivation (depth-2 callers, runtime exclusion, cross-binary),
coverage, agent features surviving re-derivation, schema v3 migration. Synthetic rows, invented names."""

from __future__ import annotations

import pytest

from airlock.index import store as store_mod
from airlock.index.store import Store
from airlock.server import features as fx


def fn(entry, name, state="auto", thunk=0, ns=None):
    return {"entry": entry, "name": name, "name_state": state, "is_thunk": thunk, "size": 0x20,
            "namespace": ns}


def build(st: Store):
    """Returns ids: app.exe (feature code), lib.dll (exports LibRead), msvcrt_rt.dll (runtime)."""
    app = st.upsert_binary("aa" * 32, "app.exe", pointer_size=4)
    lib = st.upsert_binary("bb" * 32, "lib.dll", pointer_size=4)
    rt = st.upsert_binary("cc" * 32, "msvcrt_rt.dll", pointer_size=4)
    st.insert_functions(app, [
        fn(0x401000, "WinMain", "user"),
        fn(0x401100, "FUN_a"), fn(0x401200, "FUN_b"), fn(0x401300, "FUN_c"), fn(0x401400, "FUN_d"),
        fn(0x401500, "FUN_cfg"), fn(0x401600, "FUN_reg"), fn(0x401700, "FUN_filter"),
        fn(0x401900, "FUN_g"),
        fn(0x401800, "ReadFile", "library", thunk=1), fn(0x401810, "LibRead", "library", thunk=1),
        fn(0x401A00, "FUN_gl"),
    ])
    st.insert_imports(app, [("KERNEL32.DLL", "ReadFile", None, 0x402000),
                            ("ADVAPI32.DLL", "RegOpenKeyExA", None, 0x402010),
                            ("lib.dll", "LibRead", None, 0x402020),
                            ("OPENGL32.DLL", "glBegin", None, 0x402030)])
    st.insert_strings(app, [(0x403000, "ascii", "settings.cfg"),
                            (0x403100, "ascii", "Brew Project (*.blg)|*.blg|All files|*.*"),
                            (0x403200, "ascii", "hello")])
    st.insert_edges(app, [
        (0x401104, 0x401800, "call"),          # FUN_a -> ReadFile thunk (seed: file-io)
        (0x401204, 0x401100, "call"),          # FUN_b -> FUN_a   depth 1
        (0x401304, 0x401200, "call"),          # FUN_c -> FUN_b   depth 2
        (0x401404, 0x401300, "call"),          # FUN_d -> FUN_c   depth 3: not included
        (0x401804, 0x402000, "jump"),          # thunk -> slot
        (0x401504, 0x403000, "read"),          # FUN_cfg refs "settings.cfg"
        (0x401604, 0x402010, "call_ind"),      # FUN_reg -> RegOpenKeyExA slot (config)
        (0x401704, 0x403100, "read"),          # FUN_filter refs the filter string
        (0x401904, 0x401810, "call"),          # FUN_g -> LibRead thunk
        (0x401814, 0x402020, "jump"),
        (0x401A04, 0x402030, "call_ind"),      # FUN_gl -> glBegin (graphics)
    ])
    st.link_edges(app)
    st.insert_functions(lib, [fn(0x1000, "FUN_lr"), fn(0x1100, "Impl")])
    st.insert_exports(lib, [("LibRead", 1, 0x1000)])
    st.insert_imports(lib, [("KERNEL32.DLL", "ReadFile", None, 0x2000)])
    st.insert_functions(lib, [fn(0x1200, "ReadFile", "library", thunk=1)])
    st.insert_edges(lib, [(0x1004, 0x1200, "call")])
    st.link_edges(lib)
    st.insert_functions(rt, [fn(0x500, "FUN_rt"), fn(0x600, "fopen", "library", thunk=1)])
    st.insert_edges(rt, [(0x504, 0x600, "call")])
    st.link_edges(rt)
    st.link_cross_binary(app, [lib, rt])
    return app, lib, rt


@pytest.fixture
def st(tmp_path):
    s = Store(tmp_path / "i.sqlite")
    yield s
    s.close()


def entries(st, key):
    """{(binary name, function name): (reason, depth)}"""
    names = {b.id: b.name for b in st.list_binaries()}
    return {(names[r["binary_id"]], r["name"]): (r["reason"], r["depth"]) for r in st.feature_entries(key)}


# -- tables -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("api,key", [
    ("CreateFileA", "file-io"), ("CreateFileW", "file-io"), ("ReadFile", "file-io"),
    ("__imp_WriteFile", "file-io"), ("_wfopen", "file-io"), ("fopen", "file-io"),
    ("CFile::Open", "file-io"), ("CreateFileMappingW", "file-io"), ("MapViewOfFile", "file-io"),
    ("GetOpenFileNameA", "file-io"), ("RegOpenKeyExA", "config"), ("RegSetValueExW", "config"),
    ("GetPrivateProfileStringA", "config"), ("WritePrivateProfileStringW", "config"),
    ("socket", "network"), ("connect", "network"), ("WSAStartup", "network"),
    ("InternetOpenA", "network"), ("WinHttpOpen", "network"), ("DeviceIoControl", "hardware"),
    ("SetupDiGetClassDevsW", "hardware"), ("HidD_GetAttributes", "hardware"),
    ("LoadLibraryA", "plugins"), ("GetProcAddress", "plugins"), ("CoCreateInstance", "plugins"),
    ("CreateWindowExW", "ui"), ("DialogBoxParamA", "ui"), ("CreateDialogIndirectParamW", "ui"),
    ("LoadMenuA", "ui"), ("wglCreateContext", "graphics"), ("glBegin", "graphics"),
    ("BitBlt", "graphics"), ("StretchBlt", "graphics"), ("CryptAcquireContextA", "licensing"),
    ("BCryptOpenAlgorithmProvider", "licensing"), ("GetSystemTime", "licensing"),
    ("CreateObject", "scripting"), ("_RegOpenKeyExA@20", "config"),
])
def test_api_table(api, key):
    assert fx.api_feature(api) == key


@pytest.mark.parametrize("name", ["global_counter", "RegisterWindowMessageA", "main", "", None])
def test_api_table_negative(name):
    assert fx.api_feature(name) is None


def test_string_patterns():
    rx = {"blg": fx._ext_regex("blg")}
    sf = fx.string_features
    assert "file-io" in sf("Docs (*.txt)|*.txt|All|*.*")
    assert "file-io" in sf("C:\\Temp\\out.dat")
    assert "config" in sf("Software\\Acme\\Brew")
    assert "config" in sf("brew.ini")
    assert "network" in sf("http://example.invalid/x")
    assert "network" in sf("COM3")
    assert "hardware" in sf("\\\\.\\Brewdev0")
    assert "plugins" in sf("plugins\\x.dll")
    assert "scripting" in sf("run.vbs")
    assert "graphics" in sf("logo.png")
    assert "licensing" in sf("Enter your serial number")
    assert "data-format:blg" in sf("Brew (*.blg)", rx) and "data-format:blg" in sf("x.BLG", rx)
    assert "data-format:blg" not in sf("blgx.blgx", rx)
    assert sf("hi") == [] and sf("hello world") == []


# -- derivation ---------------------------------------------------------------------------------------

def test_derive_imports_strings_and_callers(st):
    app, lib, rt = build(st)
    counts = fx.derive(st, runtime_ids={rt}, data_exts=["blg", "zzz"])
    fio = entries(st, "file-io")
    assert fio[("app.exe", "FUN_a")] == ("calls ReadFile", 0)
    assert fio[("app.exe", "FUN_b")] == ("caller of FUN_a", 1)
    assert fio[("app.exe", "FUN_c")] == ("caller of FUN_b", 2)
    assert ("app.exe", "FUN_d") not in fio                     # depth 3
    assert fio[("app.exe", "FUN_filter")][0].startswith('refs "Brew Project')
    assert fio[("lib.dll", "FUN_lr")] == ("calls ReadFile", 0)
    assert fio[("app.exe", "FUN_g")] == ("caller of FUN_lr", 1)  # across binaries (import thunk)
    assert ("app.exe", "ReadFile") not in fio                  # thunks are never entry points
    assert entries(st, "config")[("app.exe", "FUN_reg")] == ("calls RegOpenKeyExA", 0)
    assert ("app.exe", "FUN_cfg") in entries(st, "config")
    assert ("app.exe", "FUN_gl") in entries(st, "graphics")
    assert counts["file-io"] == len(fio)
    ev = {r["name"]: r["evidence"] for r in st.feature_entries("file-io")}
    assert ev["FUN_c"] == "calls ReadFile"                       # callers inherit the seed's evidence


def test_runtime_binaries_excluded(st):
    app, lib, rt = build(st)
    fx.derive(st, runtime_ids={rt})
    assert not any(b == "msvcrt_rt.dll" for b, _ in entries(st, "file-io"))
    fx.derive(st, runtime_ids=set())
    assert ("msvcrt_rt.dll", "FUN_rt") in entries(st, "file-io")


def test_data_format_feature_from_manifest_extensions(st):
    app, lib, rt = build(st)
    counts = fx.derive(st, runtime_ids={rt}, data_exts=["blg", "zzz"])
    assert "data-format:blg" in counts and "data-format:zzz" not in counts   # zzz not in strings
    assert ("app.exe", "FUN_filter") in entries(st, "data-format:blg")
    assert st.get_feature("data-format:blg")["title"] == "Data format .blg"


def test_coverage_counts_named_functions(st):
    app, lib, rt = build(st)
    fx.derive(st, runtime_ids={rt})
    row = next(r for r in fx.stats(st) if r["key"] == "file-io")
    assert row["named"] == 0 and row["n"] >= 5
    with st.db:
        st.db.execute("UPDATE function SET name='read_cfg', name_state='user' WHERE name='FUN_a'")
        st.db.execute("UPDATE function SET name_state='library' WHERE name='FUN_b'")
    row2 = next(r for r in fx.stats(st) if r["key"] == "file-io")
    assert row2["named"] == 2 and row2["n"] == row["n"]
    assert fx.coverage(row2["n"], row2["named"]).startswith("named 2 of ")
    assert fx.coverage(0, 0) == "named 0 of 0"
    # a rename never changes the entry points: re-deriving gives the same keys and names resolve live
    fx.derive(st, runtime_ids={rt})
    assert entries(st, "file-io")[("app.exe", "read_cfg")][0] == "calls ReadFile"


def test_stable_keys_and_order(st):
    app, lib, rt = build(st)
    fx.derive(st, runtime_ids={rt}, data_exts=["blg"])
    keys = [r["key"] for r in fx.stats(st)]
    assert keys == sorted(keys, key=fx.feature_order)
    assert keys[0] == "file-io" and keys[-1] == "data-format:blg"
    assert set(keys) <= set(fx.FEATURES) | {"data-format:blg"}


def test_agent_feature_survives_rederive(st):
    app, lib, rt = build(st)
    fx.derive(st, runtime_ids={rt})
    st.define_feature("open-project-file", "Open a project file", "io, formats", "t")
    st.add_feature_entries("open-project-file", app, [("ram", 0x401000, "agent: Open a project file")])
    st.define_feature("config", "Settings (refined)", "", "t")           # refine an auto feature
    st.add_feature_entries("config", app, [("ram", 0x401000, "agent: entry")])
    before = fx.derive(st, runtime_ids={rt})
    f = st.get_feature("open-project-file")
    assert f["source"] == "agent" and f["topics"] == "io, formats"
    assert entries(st, "open-project-file") == {("app.exe", "WinMain"): ("agent: Open a project file", 0)}
    cfg = st.get_feature("config")
    assert cfg["source"] == "agent" and cfg["title"] == "Settings (refined)"
    assert ("app.exe", "WinMain") in entries(st, "config")                  # agent entry kept
    assert ("app.exe", "FUN_reg") in entries(st, "config")                  # auto entries refreshed
    assert before["config"] == len(entries(st, "config")) - 1
    fx.derive(st, runtime_ids={rt})
    assert len(entries(st, "config")) == before["config"] + 1               # idempotent


def test_clear_binary_data_drops_its_entries(st):
    app, lib, rt = build(st)
    fx.derive(st, runtime_ids={rt})
    st.clear_binary_data(lib)
    assert not any(b == "lib.dll" for b, _ in entries(st, "file-io"))


def test_hub_functions_are_not_expanded(st):
    app, lib, rt = build(st)
    callers = [fn(0x420000 + i * 0x40, f"FUN_hub{i}") for i in range(fx.MAX_FANIN + 5)]
    st.insert_functions(app, callers)
    st.insert_edges(app, [(0x420004 + i * 0x40, 0x401100, "call") for i in range(len(callers))])
    st.link_edges(app)
    fx.derive(st, runtime_ids={rt})
    fio = entries(st, "file-io")
    assert ("app.exe", "FUN_hub0") not in fio and ("app.exe", "FUN_a") in fio


# -- schema v3 ------------------------------------------------------------------------------------------

def test_migration_v2_to_v3(tmp_path):
    p = tmp_path / "old.sqlite"
    s = Store(p)
    b = s.upsert_binary("ab" * 32, "app.exe")
    with s.db:
        s.db.execute("DROP TABLE feature_entry")
        s.db.execute("DROP TABLE feature")
        s.set_meta("schema_version", "2")
    s.close()
    s = Store(p)
    assert s.schema_version == store_mod.SCHEMA_VERSION
    s.define_feature("k", "T", "", "t")
    s.add_feature_entries("k", b, [("ram", 0x10, "r")])
    assert s.feature_stats()[0]["n"] == 1
    assert s.get_binary_by_id(b).name == "app.exe"
    s.close()
