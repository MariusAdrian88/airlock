""".NET round 2 fix N1: one writer per managed binary (R1), bundle entries added on open (R8),
folders of framework-named assemblies (R7) and the scan root of a CLI + GUI pair (P15)."""
from __future__ import annotations

import threading
import time
from pathlib import Path

from airlock.index.store import Store
from airlock.projects import hash_file, read_manifest, write_manifest
from airlock.server import dotnet as dn
from airlock.server import dotnet_meta
from airlock.server.scan import render_scan, scan_program
from test_dotnet import add_managed, make_dn_ctx, managed_dll  # noqa: F401  (fixture)
from test_net_entry import APP, LIB, _csc, make_bundle, native_exe


# -- R1 ----------------------------------------------------------------------------------------

def _fake_parsed() -> dn.Parsed:
    m1, m2 = 0x06000001, 0x06000002
    meta = dotnet_meta.Meta(fields=[(0x02000001, 0x04000001, "F", "int", "", None, None)])
    return dn.Parsed(
        types=[dn.DnType(0x02000001, "T", "class", None, "")],
        methods=[dn.DnMethod(m1, 0x02000001, "A", "void()", ""), dn.DnMethod(m2, 0x02000001, "B", "void()", "")],
        sites=[(m1, m2, "call", 3), (m1, m2, "call", 9)], strings={0x10: "hi"}, str_sites=[(m1, 0x10, 5)],
        meta=meta)


def _binary(tmp_path) -> tuple[Path, Path, int]:
    db = tmp_path / "i.sqlite"
    art = tmp_path / "art.bin"
    art.write_bytes(b"MZ-fake")
    st = Store(db)
    bid = st.upsert_binary("a" * 64, "t.dll", toolchain="dotnet", format="dotnet")
    st.close()
    return db, art, bid


def _counts(st: Store, bid: int) -> tuple[int, int, int, int]:
    q = lambda sql: st.db.execute(sql, (bid,)).fetchone()[0]  # noqa: E731
    return (q("SELECT COUNT(*) FROM dn_field WHERE binary_id=?"),
            q("SELECT COUNT(*) FROM edge WHERE binary_id=? AND kind='call'"),
            q("SELECT COUNT(*) FROM edge WHERE binary_id=? AND kind='data'"),
            q("SELECT COUNT(*) FROM function WHERE binary_id=?"))


def test_concurrent_ensure_writes_once(tmp_path, monkeypatch):
    db, art, bid = _binary(tmp_path)
    calls = []

    def slow_parse(_path):
        calls.append(1)
        time.sleep(0.2)          # the window in which the second writer used to interleave
        return _fake_parsed()

    monkeypatch.setattr(dn, "parse_file", slow_parse)
    errors: list[BaseException] = []
    started = threading.Barrier(2)

    def run(force: bool) -> None:
        st = Store(db)
        try:
            b = st.get_binary_by_id(bid)
            started.wait()
            dn.ensure(st, b, art, force=force)
        except BaseException as e:  # noqa: BLE001
            errors.append(e)
        finally:
            st.close()

    for force in (True, False):          # two forced re-parses, then two stale-key callers
        if not force:
            old = Store(db)
            old.set_meta(f"dotnet_version:{bid}", "0")
            old.close()
        ts = [threading.Thread(target=run, args=(force,)) for _ in range(2)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        assert not errors, errors
        st = Store(db)
        assert _counts(st, bid) == (1, 2, 1, 2)
        assert st.get_meta(f"dotnet_version:{bid}") == str(dn.DOTNET_VERSION)
        st.close()
    assert len(calls) == 3     # two forced + one stale caller (the other one saw the new key)


def test_failed_parse_keeps_old_rows(tmp_path, monkeypatch):
    db, art, bid = _binary(tmp_path)
    monkeypatch.setattr(dn, "parse_file", lambda _p: _fake_parsed())
    st = Store(db)
    b = st.get_binary_by_id(bid)
    assert dn.ensure(st, b, art)
    bad = _fake_parsed()
    bad.meta.fields.append(bad.meta.fields[0])           # duplicate key: the insert fails half way
    monkeypatch.setattr(dn, "parse_file", lambda _p: bad)
    try:
        dn.ensure(st, b, art, force=True)
    except Exception:  # noqa: BLE001
        pass
    assert _counts(st, bid) == (1, 2, 1, 2)              # rolled back as one transaction
    assert not st.db.in_transaction


def test_ensure_project_skips_binaries_that_are_not_ready(tmp_path, monkeypatch):
    db, art, bid = _binary(tmp_path)
    parsed = []
    monkeypatch.setattr(dn, "parse_file", lambda _p: parsed.append(1) or _fake_parsed())
    st = Store(db)
    arts = tmp_path / "arts"
    arts.mkdir()
    (arts / ("a" * 64)).write_bytes(b"MZ-fake")
    st.set_meta(f"status:{bid}", "extracting")           # its own job is still writing
    assert dn.ensure_project(st, arts, []) == 0 and not parsed
    st.set_meta(f"status:{bid}", "ready")
    assert dn.ensure_project(st, arts, []) == 1 and len(parsed) == 1


def test_error_from_the_race_recovers_on_open(tmp_path, managed_dll):
    ctx = make_dn_ctx(tmp_path)
    bid = add_managed(ctx, managed_dll)
    ix = ctx.indexer
    st = ix.store("proj")
    ix.set_status(st, bid, "error", "cannot read .NET metadata: IntegrityError: UNIQUE constraint failed: "
                                    "dn_field.binary_id, dn_field.token")
    ix._resumed.clear()
    ix.resume_project("proj")
    end = time.time() + 60
    while time.time() < end and ix.get_status(st, bid)[0] != "ready":
        time.sleep(0.02)
    assert ix.get_status(st, bid)[0] == "ready"
    assert st.db.execute("SELECT COUNT(*) FROM dn_type WHERE binary_id=?", (bid,)).fetchone()[0] > 0


# -- R8 ----------------------------------------------------------------------------------------

def test_resume_adds_the_entries_of_a_host_only_bundle(tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    lib = _csc(work, "Util.Core.dll", LIB, "library")
    app = _csc(work, "Tool.dll", APP, "exe")
    host = make_bundle(tmp_path / "Tool.exe", native_exe(tmp_path),
                       [("Tool.dll", 1, app.read_bytes(), False), ("Util.Core.dll", 1, lib.read_bytes(), True),
                        ("System.Private.CoreLib.dll", 1, b"MZ", False)])
    ctx = make_dn_ctx(tmp_path)
    ix = ctx.indexer
    pp = ix.paths("proj", create=True)
    sha = hash_file(host)
    (pp.artifacts / sha).write_bytes(host.read_bytes())
    st = ix.store("proj")
    hid = st.upsert_binary(sha, "Tool.exe", format="pe", toolchain="msvc")
    ix.set_status(st, hid, "ready")
    man = read_manifest(pp.manifest)
    man["files"] = [{"path": "Tool.exe", "group": "core", "kind": "pe", "sha256": sha, "state": "ready"}]
    write_manifest(pp.manifest, man)

    ix.resume_project("proj")
    names = lambda: {b.name for b in st.list_binaries()}  # noqa: E731
    assert names() == {"Tool.exe", "Tool.dll", "Util.Core.dll"}        # framework entry stays out
    end = time.time() + 60
    while time.time() < end and not all(ix.get_status(st, b.id)[0] == "ready" for b in st.list_binaries()):
        time.sleep(0.02)
    assert all(ix.get_status(st, b.id)[0] == "ready" for b in st.list_binaries())
    paths = [f["path"] for f in read_manifest(pp.manifest)["files"]]
    assert "Tool.exe!Tool.dll" in paths and "Tool.exe!Util.Core.dll" in paths
    # once only
    ix._resumed.clear()
    ix.resume_project("proj")
    assert len(st.list_binaries()) == 3
    assert [f["path"] for f in read_manifest(pp.manifest)["files"]].count("Tool.exe!Tool.dll") == 1


# -- R7 ----------------------------------------------------------------------------------------

def test_folder_of_framework_named_assemblies_gets_an_option(tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    lib = _csc(work, "x.dll", LIB, "library")
    prog = tmp_path / "r2r"
    prog.mkdir()
    for n in ("System.Alpha.dll", "System.Beta.dll"):
        (prog / n).write_bytes(lib.read_bytes())
    r = scan_program(prog)
    text = "\n".join(render_scan(r))
    assert "recommended: none" not in text
    assert r.recommended == "A"
    assert {Path(f.rel_path).name for f in r.options[0].files} == {"System.Alpha.dll", "System.Beta.dll"}


# -- P15 ---------------------------------------------------------------------------------------

def test_gui_exe_beats_cli_exe_of_the_product_name(tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    prog = tmp_path / "Dependencies"
    prog.mkdir()
    cli = _csc(work, "Dependencies.exe", APP, "exe")
    big = APP.replace("static void Main()", "static int F(int x) { return x * 3; } static void Main()")
    gui = _csc(work, "DependenciesGui.exe", big + "\nclass Q { public int G(int x) { return x - 1; } "
               "public string H() { return \"a\" + 2; } public double I() { return 1.5 * 2; } }", "exe")
    (prog / "Dependencies.exe").write_bytes(cli.read_bytes())
    (prog / "DependenciesGui.exe").write_bytes(gui.read_bytes())
    r = scan_program(prog)
    assert r.root_exe == "DependenciesGui.exe"
    assert {f.rel_path: f.group for f in r.files}["Dependencies.exe"] == "separate_exe"
