"""Integration tests: the real worker, Ghidra and a real PE.

    pytest -q -m ghidra --binary=<path-to-exe>

One module-scoped worker imports and analyses the binary once (minutes for the
first run); the individual tests then read the results.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import Any

import pytest

from airlock.config.loader import load_config
from airlock.worker.client import WorkerClient
from airlock.worker.protocol import WorkerError

pytestmark = pytest.mark.ghidra

PROGRAM = "target.exe"
ANALYSIS_WAIT_S = 1800


TIMINGS: dict[str, float] = {}


def extract_all(c: WorkerClient, kind: str, limit: int = 3000) -> tuple[list[str], list[list[Any]]]:
    rows: list[list[Any]] = []
    t0 = time.monotonic()
    offset = 0
    while True:
        r = c.request("extract", {"program": PROGRAM, "kind": kind, "offset": offset,
                                  "limit": limit}, timeout=600)
        rows += r["rows"]
        if r["done"]:
            TIMINGS.setdefault(f"extract_{kind}_s", time.monotonic() - t0)
            return r["columns"], rows
        assert r["next_offset"] == offset + len(r["rows"])
        offset = r["next_offset"]


def as_dicts(cols: list[str], rows: list[list[Any]]) -> list[dict[str, Any]]:
    return [dict(zip(cols, r)) for r in rows]


@pytest.fixture(scope="module")
def world(binary_path, tmp_path_factory):
    """Start the worker, import, analyse. Records what was observable meanwhile."""
    work = tmp_path_factory.mktemp("ghidra")
    exe = work / "artifact.bin"
    shutil.copy(binary_path, exe)
    c = WorkerClient(load_config())
    w: dict[str, Any] = {"client": c, "work": work, "events": []}
    c.on_event(w["events"].append)
    try:
        w["ghidra"] = c.ensure_ghidra(timeout=300)
        w["project"] = c.request("open_project", {"path": str(work / "proj"), "name": "t"})
        t0 = time.monotonic()
        w["import"] = c.request("import_binary", {"artifact_path": str(exe),
                                                   "program_name": PROGRAM}, timeout=900)
        w["import_s"] = time.monotonic() - t0

        # before analysis, program ops are refused
        with pytest.raises(WorkerError) as e:
            c.request("extract", {"program": PROGRAM, "kind": "functions"})
        w["refused_before"] = e.value.code

        t0 = time.monotonic()
        w["analyze"] = c.request("analyze", {"program": PROGRAM})
        # while it runs: ops refused, hello/status answer
        with pytest.raises(WorkerError) as e:
            c.request("decompile", {"program": PROGRAM, "entry": 0})
        w["refused_during"] = e.value.code
        w["hello_during"] = c.request("hello", timeout=10)
        w["status_during"] = c.request("status", {"program": PROGRAM}, timeout=10)
        deadline = time.monotonic() + ANALYSIS_WAIT_S
        while time.monotonic() < deadline:
            p = c.progress(PROGRAM)
            if p and p["state"] in {"done", "error", "cancelled"}:
                break
            time.sleep(1)
        w["analysis_s"] = time.monotonic() - t0
        w["final_progress"] = c.progress(PROGRAM)
        yield w
    finally:
        c.stop()


def test_ghidra_started(world):
    assert world["ghidra"]["ghidra_version"].startswith("12.")


def test_import_describes_program(world):
    imp = world["import"]
    assert imp["program"] == PROGRAM
    assert imp["analysed"] is False and imp["state"] == "loaded"
    assert imp["pointer_size"] in (4, 8)
    assert imp["image_base"] > 0
    assert "x86" in imp["language"]


def test_ops_refused_until_analysed(world):
    assert world["refused_before"] == "not_analysed"
    assert world["refused_during"] == "not_analysed"


def test_hello_and_status_answer_during_analysis(world):
    assert world["analyze"]["state"] == "analysing"
    assert world["hello_during"]["ghidra_started"] is True
    prog = world["status_during"]["programs"][0]
    assert prog["program"] == PROGRAM and prog["state"] == "analysing"


def test_progress_events_reach_client(world):
    events = [e for e in world["events"] if e.get("program") == PROGRAM]
    assert events, "no progress events received"
    assert all(e["event"] == "progress" and e["job"] == "analysis" for e in events)
    assert any(e["state"] == "running" for e in events)
    assert events[-1]["state"] == "done"
    assert world["final_progress"]["state"] == "done"
    assert world["final_progress"]["functions"] > 0


def test_status_after_analysis(world):
    s = world["client"].request("status", {"program": PROGRAM})
    prog = s["programs"][0]
    assert prog["state"] == "ready" and prog["analysed"] is True
    assert len(prog["analysis_profile"]) == 16


def test_extract_functions(world):
    c = world["client"]
    cols, rows = extract_all(c, "functions", limit=300)  # several batches
    fns = as_dicts(cols, rows)
    assert len(fns) > 100
    entries = {(f["space"], f["entry"]) for f in fns}
    assert len(entries) == len(fns), "duplicate (space, entry)"
    internal = [f for f in fns if not f["is_external"]]
    assert all(isinstance(f["entry"], int) and f["size"] > 0 for f in internal)
    assert {f["name_state"] for f in fns} <= {"auto", "library", "recovered", "user", "agent"}
    r = c.request("extract", {"program": PROGRAM, "kind": "functions", "limit": 1})
    assert r["image_base"] == world["import"]["image_base"]
    assert r["pointer_size"] == world["import"]["pointer_size"]
    assert r["next_offset"] == 1 and r["done"] is False


def test_extract_batches_are_resumable_and_random_access(world):
    c = world["client"]
    _, all_rows = extract_all(c, "functions", limit=50)
    r = c.request("extract", {"program": PROGRAM, "kind": "functions", "offset": 100,
                              "limit": 10})
    assert r["rows"] == all_rows[100:110]
    r = c.request("extract", {"program": PROGRAM, "kind": "functions", "offset": 105,
                              "limit": 10})  # not where the cursor stands
    assert r["rows"] == all_rows[105:115]


def test_extract_imports(world):
    cols, rows = extract_all(world["client"], "imports")
    imps = as_dicts(cols, rows)
    assert imps and all(i["dll"] and i["name"] for i in imps)
    assert any(i["address"] for i in imps)
    assert all(isinstance(i["address"], int) for i in imps if i["address"] is not None)


def test_extract_strings(world):
    cols, rows = extract_all(world["client"], "strings")
    strs = as_dicts(cols, rows)
    assert strs
    assert {s["encoding"] for s in strs} <= {"ascii", "utf8", "utf16le", "utf32le"}
    assert all(s["length"] == len(s["value"]) or len(s["value"]) == 4096 for s in strs)
    assert all(isinstance(s["address"], int) for s in strs)


def test_extract_edges_and_references(world):
    c = world["client"]
    _, frows = extract_all(c, "functions")
    fn_entries = {r[1] for r in frows if r[0] == "ram"}
    cols, rows = extract_all(c, "edges", limit=5000)
    edges = as_dicts(cols, rows)
    kinds = {e["kind"] for e in edges}
    assert {"call", "data"} <= kinds
    assert kinds <= {"call", "call_ind", "jump", "read", "write", "data"}
    calls = [e for e in edges if e["kind"] == "call" and e["dst_fn"] is not None]
    assert calls
    for e in calls[:200]:
        assert e["dst_fn"] in fn_entries
        assert e["src_fn"] in fn_entries
        assert e["dst_fn"] == e["dst_addr"]  # direct calls land on the entry point
    assert all(isinstance(e["src_addr"], int) and isinstance(e["dst_addr"], int) for e in edges)


def test_decompile_and_ast_nodes(world):
    c = world["client"]
    cols, rows = extract_all(c, "functions")
    fns = [f for f in as_dicts(cols, rows) if not f["is_external"] and not f["is_thunk"]]
    _, erows = extract_all(c, "edges", limit=5000)
    caller_count: dict[int, int] = {}
    for e in as_dicts(["src_addr", "src_fn", "dst_space", "dst_addr", "dst_fn", "kind"], erows):
        if e["kind"] == "call" and e["src_fn"] is not None:
            caller_count[e["src_fn"]] = caller_count.get(e["src_fn"], 0) + 1
    # a mid-sized function that calls things
    cands = [f for f in fns if 200 < f["size"] < 1500 and caller_count.get(f["entry"], 0) >= 3]
    assert cands
    f = cands[0]
    t0 = time.monotonic()
    d = c.request("decompile", {"program": PROGRAM, "entry": f["entry"], "timeout": 120},
                  timeout=180)
    TIMINGS["first_decompile_s"] = time.monotonic() - t0
    assert d["status"] == "ok", d.get("error")
    assert d["entry"] == f["entry"] and d["name"] == f["name"]
    text = d["c_text"]
    assert f["name"] in text and "{" in text
    assert d["ast_columns"] == ["kind", "start_off", "end_off", "address", "target", "text"]
    ast = as_dicts(d["ast_columns"], d["ast"])
    kinds = {a["kind"] for a in ast}
    assert "call" in kinds
    for a in ast:
        assert 0 <= a["start_off"] < a["end_off"] <= len(text)
        assert text[a["start_off"]:a["end_off"]].startswith(a["text"][:20])
    for a in ast:
        if a["kind"] == "call":
            assert isinstance(a["address"], int) and isinstance(a["target"], int)
    # decompiler calls agree with the reference pass
    call_targets = {a["target"] for a in ast if a["kind"] == "call"}
    ref_targets = {e["dst_addr"] for e in as_dicts(
        ["src_addr", "src_fn", "dst_space", "dst_addr", "dst_fn", "kind"], erows)
        if e["src_fn"] == f["entry"] and e["kind"] in {"call", "call_ind"}}
    assert call_targets & ref_targets
    vi = d["version_inputs"]
    assert len(vi["bytes_hash"]) == 64 and vi["size"] == f["size"]
    assert vi["analysis_profile"] == world["final_progress"]["analysis_profile"]
    assert vi["ghidra_version"] == world["ghidra"]["ghidra_version"]
    assert vi["project_file_modified"] > 0
    # decompile by an interior address resolves to the containing function
    d2 = c.request("decompile", {"program": PROGRAM, "entry": f["entry"] + 1}, timeout=180)
    assert d2["entry"] == f["entry"]


def test_decompile_errors_are_codes(world):
    c = world["client"]
    with pytest.raises(WorkerError) as e:
        c.request("decompile", {"program": PROGRAM, "entry": 1})
    assert e.value.code == "no_function"
    with pytest.raises(WorkerError) as e:
        c.request("decompile", {"program": "missing.exe", "entry": 1})
    assert e.value.code == "no_program"
    with pytest.raises(WorkerError) as e:
        c.request("extract", {"program": PROGRAM, "kind": "bogus"})
    assert e.value.code == "bad_args"


def test_save_close_reopen_keeps_analysis(world):
    c = world["client"]
    assert c.request("save", {"program": PROGRAM})["saved"] == [PROGRAM]
    c.request("close_project")
    with pytest.raises(WorkerError) as e:
        c.request("extract", {"program": PROGRAM, "kind": "functions"})
    assert e.value.code == "no_project"
    again = c.request("open_project", {"path": str(world["work"] / "proj"), "name": "t"})
    assert again["created"] is False and again["programs"] == [PROGRAM]
    s = c.request("status")
    assert s["programs"] == [{"program": PROGRAM, "state": "unloaded"}]
    r = c.request("extract", {"program": PROGRAM, "kind": "functions", "limit": 5})
    assert len(r["rows"]) == 5  # opened from disk and already analysed
    assert c.request("analyze", {"program": PROGRAM})["already_analysed"] is True
    s = c.request("status", {"program": PROGRAM})["programs"][0]
    assert s["state"] == "ready" and s["analysis_profile"] == \
        world["final_progress"]["analysis_profile"]


def test_import_twice_is_idempotent(world):
    c = world["client"]
    r = c.request("import_binary", {"artifact_path": str(world["work"] / "artifact.bin"),
                                    "program_name": PROGRAM})
    assert r["already_imported"] is True


def test_report_timings(world, capsys):
    TIMINGS.update(import_s=world["import_s"], analysis_s=world["analysis_s"])
    with capsys.disabled():
        print("TIMINGS " + ", ".join(f"{k}={v:.2f}" for k, v in sorted(TIMINGS.items())))
        print("COUNTS", {k: len(extract_all(world["client"], k)[1])
                         for k in ("functions", "imports", "strings", "edges")})
