"""Cross-binary links against the real worker (JVM + Ghidra).

    pytest -q -m ghidra --xbin=<folder>

The folder holds one exe and one DLL it imports (copies of small System32 files will do).
Both go through the real queue in a single Ghidra project, once DLL first and once exe first;
afterwards the exe's imports must resolve to the DLL: Ghidra external path and index edges.
"""

from __future__ import annotations

import dataclasses
import time
from pathlib import Path

import pefile
import pytest

from airlock.config.loader import load_config
from airlock.projects import hash_file, read_manifest, write_manifest
from airlock.server.context import ServerContext
from airlock.worker.client import WorkerClient

pytestmark = pytest.mark.ghidra

READY_WAIT_S = 900


def find_pair(folder: str) -> tuple[Path, Path]:
    """(exe, dll) in the folder where the exe imports the dll."""
    files = [p for p in Path(folder).iterdir() if p.is_file()]
    dlls = {p.name.lower(): p for p in files if p.suffix.lower() == ".dll"}
    for exe in (p for p in files if p.suffix.lower() == ".exe"):
        pe = pefile.PE(str(exe), fast_load=True)
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                d = e.dll.decode("latin-1").lower()
                if d in dlls:
                    return exe, dlls[d]
        finally:
            pe.close()
    pytest.skip("no exe in the --xbin folder imports a DLL of that folder")


@pytest.fixture(scope="module", params=["dll_first", "exe_first"])
def world(request, xbin_dir, tmp_path_factory):
    exe, dll = find_pair(xbin_dir)
    cfg = dataclasses.replace(load_config(), data_dir=tmp_path_factory.mktemp("data"),
                              projects_root=tmp_path_factory.mktemp("projects"))
    ctx = ServerContext(config=cfg, worker=WorkerClient(cfg))
    try:
        ix = ctx.indexer
        pp = ix.paths("xb", create=True)
        entries = []
        # dll_first: the DLL is core (runs first); exe_first: the exe is core
        groups = {"dll": "core", "exe": "other"} if request.param == "dll_first" \
            else {"dll": "other", "exe": "core"}
        for kind, f in (("exe", exe), ("dll", dll)):
            sha = hash_file(f)
            (pp.artifacts / sha).write_bytes(f.read_bytes())
            entries.append({"path": f.name, "group": groups[kind], "kind": "pe", "size": f.stat().st_size,
                            "code_size": f.stat().st_size, "sha256": sha, "state": "queued"})
        man = read_manifest(pp.manifest)
        man["files"] = entries
        write_manifest(pp.manifest, man)
        t0 = time.monotonic()
        assert len(ix.enqueue("xb", entries)) == 2
        job_ids = [j for j in ix._jobs.values()]
        deadline = time.monotonic() + READY_WAIT_S
        while time.monotonic() < deadline and not all(j.finished.is_set() for j in job_ids):
            time.sleep(1)
        st = ix.store("xb")
        statuses = {b.name: ix.get_status(st, b.id) for b in st.list_binaries()}
        assert all(s[0] == "ready" for s in statuses.values()), statuses
        yield {"ctx": ctx, "exe": exe, "dll": dll, "order": request.param,
               "seconds": time.monotonic() - t0}
    finally:
        ctx.worker.stop()


def test_external_path_set_in_ghidra(world):
    ctx = world["ctx"]
    st = ctx.indexer.store("xb")
    exe_b, dll_b = st.get_binary(world["exe"].name), st.get_binary(world["dll"].name)
    paths = ctx.worker.request("external_paths", {"program": ctx.indexer.program_of(st, exe_b)})["paths"]
    want = "/" + ctx.indexer.program_of(st, dll_b)
    lib = next(k for k in paths if k.lower() == world["dll"].name.lower())
    assert paths[lib] == want


def test_exe_imports_resolve_to_dll_functions(world):
    ctx = world["ctx"]
    st = ctx.indexer.store("xb")
    exe_b, dll_b = st.get_binary(world["exe"].name), st.get_binary(world["dll"].name)
    exports = {e["name"]: e["address"] for e in st.exports_of(dll_b.id) if e["name"]}
    assert exports, "the DLL has no exports in the index"
    expected = {}
    for r in st.list_imports(exe_b.id, dll=world["dll"].name, limit=10000):
        if r["name"] in exports and r["address"] is not None:
            expected[r["address"]] = (r["name"], exports[r["name"]])
    assert expected, "no import of the exe matches an export of the DLL by name"
    got = {x.src_addr: x for x in st.cross_from_binary(exe_b.id) if x.dst_binary == dll_b.id}
    for slot, (name, export_addr) in expected.items():
        x = got[slot]
        assert x.dst_fn is not None and x.dst_fn.name == name
        assert x.dst_fn.entry <= export_addr < x.dst_fn.entry + max(x.dst_fn.size or 1, 1)
        back = [c for c in st.cross_to_function(x.dst_fn) if c.src_binary == exe_b.id]
        assert any(c.src_addr == slot for c in back)
    assert st.cross_counts(dll_b.id)[1] >= len(expected)


def test_manifest_has_timings(world):
    ctx = world["ctx"]
    man = read_manifest(ctx.indexer.paths("xb").manifest)
    assert all(f["state"] == "ready" and f["analysis_s"] > 0 for f in man["files"])
    assert man["queue"]["s_per_mb"] > 0
