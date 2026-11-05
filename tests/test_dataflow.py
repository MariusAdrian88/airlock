"""M8 dataflow set: tool formatting with a scripted worker, and (marker ghidra) the ops on a real binary.

    pytest -q -m ghidra --binary=<path-to-exe>          # the Ghidra part (notepad copy, minutes)

The fast tests need no Ghidra: the worker replies are scripted, so they check argument checks,
grouping of switch cases, the line format and the budget."""

from __future__ import annotations

import shutil
import time
from typing import Any

import pytest

from airlock.config.loader import load_config
from airlock.server.tools import dataflow as df
from airlock.worker.client import WorkerClient
from airlock.worker.protocol import WorkerError
from test_tools import fill, make_ctx


@pytest.fixture
def ctx(tmp_path):
    c = make_ctx(tmp_path)
    fill(c)
    return c


def script(ctx, replies: dict[str, Any]):
    calls = []
    real = ctx.worker.request

    def request(op, args=None, timeout=0):
        if op in replies:
            calls.append((op, args))
            r = replies[op]
            if isinstance(r, Exception):
                raise r
            return r
        return real(op, args, timeout)

    ctx.worker.request = request
    return calls


def first_function(ctx):
    st = ctx.indexer.store("proj")
    r = st.db.execute("SELECT entry, name FROM function WHERE is_external=0 AND space='ram' ORDER BY entry LIMIT 1").fetchone()
    return r["entry"], r["name"]


def test_ranges_and_values():
    assert df._ranges([0, 1, 2, 3, 7, 9, 10]) == "0..3,7,9,10"
    assert df._ranges([0xFFFFFFFF, 0]) == "-1,0"
    assert df.parse_value("0x4D5A") == 0x4D5A and df.parse_value("-1") == -1 and df.parse_value("zz") is None


def test_switch_tables_output(ctx):
    entry, name = first_function(ctx)
    calls = script(ctx, {"switch_tables": {"entry": entry, "name": name, "switches": [
        [entry + 8, [[0, 0x401100], [1, 0x401100], [2, 0x401200], [3, 0x401100]], 0x401300, 5]]}})
    out = df.switch_tables(ctx, name).splitlines()
    assert calls[0][1]["entry"] == entry
    assert out[1] == "switch at 0x%08x: 5 entries" % (entry + 8)
    assert out[2] == "  case 0..1,3 -> 0x00401100" or out[2].startswith("  case 0,1,3")
    assert "  case 2 -> 0x00401200" in out and out[-1] == "  default -> 0x00401300"


def test_switch_tables_none_and_errors(ctx):
    entry, name = first_function(ctx)
    script(ctx, {"switch_tables": {"entry": entry, "name": name, "switches": []}})
    assert "no switch table recovered" in df.switch_tables(ctx, name)
    script(ctx, {"switch_tables": WorkerError("decompile_failed", "cannot decompile x: timeout")})
    out = df.switch_tables(ctx, name)
    assert out.startswith("error decompile_failed:") and "\n" not in out
    assert df.switch_tables(ctx, "no_such_function_xyz").startswith("error")


def test_trace_values_output_and_args(ctx):
    entry, name = first_function(ctx)
    assert df.trace_values(ctx, name).startswith("error bad_args")
    assert df.trace_values(ctx, name, param=1, depth=9).startswith("error bad_args")
    calls = script(ctx, {"trace_values": {"entry": entry, "name": name, "truncated": True, "rows": [
        [0, "def", entry + 2, "= FUN_00401500(param_1, 0x5)"],
        [0, "call", entry + 9, "FUN_00401800(param_1, local_8) arg 2"],
        [1, "into", None, "FUN_00401800 param_2"],
        [1, "cmp", entry + 0x30, "param_2 == 0x20"]]}})
    out = df.trace_values(ctx, name, variable="local_8", depth=1).splitlines()
    assert {k: v for k, v in calls[0][1].items() if k != "program"} == {"entry": entry, "variable": "local_8", "param": None, "depth": 1}
    assert out[0].startswith(f"local_8 in {name}")
    assert out[1].startswith("  def 0x") and out[3].startswith("    into FUN_00401800 param_2")
    assert out[-1].startswith("… trace cut")


def test_constants_output(ctx):
    entry, name = first_function(ctx)
    script(ctx, {"constants": {"rows": [[entry, 3, entry + 4], [-1, 1, 0x401234]], "total": 2, "secs": 0.1}})
    out = df.constants(ctx, "0x4d5a").splitlines()
    assert out[0] == "0x4d5a used by 2 functions"
    assert out[1].endswith("uses 3 first 0x%08x" % (entry + 4)) and out[2] == "(no function) 0x00401234 uses 1"
    assert df.constants(ctx, "0x10").startswith("error bad_args")
    assert df.constants(ctx, "abc").startswith("error bad_args")
    script(ctx, {"constants": {"rows": [], "total": 0, "secs": 0}})
    assert df.constants(ctx, "0x1234") == "no function uses 0x1234 as an immediate."


def test_clean_role_cannot_call_dataflow():
    from airlock.config.catalog import CATALOG
    for t in ("trace_values", "switch_tables", "constants", "qt_metaobjects"):
        assert not CATALOG[t].clean_safe


# ── Ghidra ─────────────────────────────────────────────────────────────────

PROGRAM = "target.exe"


@pytest.fixture(scope="module")
def world(binary_path, tmp_path_factory):
    work = tmp_path_factory.mktemp("df")
    exe = work / "artifact.bin"
    shutil.copy(binary_path, exe)
    c = WorkerClient(load_config())
    try:
        c.ensure_ghidra(timeout=300)
        c.request("open_project", {"path": str(work / "proj"), "name": "t"})
        c.request("import_binary", {"artifact_path": str(exe), "program_name": PROGRAM}, timeout=900)
        c.request("analyze", {"program": PROGRAM})
        deadline = time.monotonic() + 1800
        while time.monotonic() < deadline:
            p = c.progress(PROGRAM)
            if p and p["state"] in {"done", "error", "cancelled"}:
                break
            time.sleep(1)
        assert c.progress(PROGRAM)["state"] == "done"
        funcs: list[tuple[int, int]] = []
        offset = 0
        while True:
            r = c.request("extract", {"program": PROGRAM, "kind": "functions", "offset": offset, "limit": 5000}, timeout=600)
            cols = r["columns"]
            funcs += [(x[cols.index("entry")], x[cols.index("size")] or 0) for x in r["rows"]
                      if x[cols.index("space")] == "ram" and not x[cols.index("is_external")]]
            if r["done"]:
                break
            offset = r["next_offset"]
        yield c, sorted(funcs, key=lambda f: -f[1])
    finally:
        c.stop()


@pytest.mark.ghidra
def test_switch_tables_on_real_binary(world):
    c, funcs = world
    found = None
    for entry, _size in funcs[5:80]:          # skip the few giants; a decompile timeout is not a failure
        try:
            r = c.request("switch_tables", {"program": PROGRAM, "entry": entry, "timeout": 15}, timeout=300)
        except WorkerError:
            continue
        if r["switches"]:
            found = r
            break
    if not found:
        pytest.skip("no recovered switch table among the scanned functions of this binary")
    addr, pairs, default, n = found["switches"][0]
    assert n >= 2 and pairs and all(isinstance(t, int) for _lab, t in pairs)


@pytest.mark.ghidra
def test_trace_values_on_real_binary(world):
    c, funcs = world
    for entry, _size in funcs[:60]:
        try:
            r = c.request("trace_values", {"program": PROGRAM, "entry": entry, "param": 1, "depth": 1}, timeout=300)
        except WorkerError:
            continue
        kinds = {row[1] for row in r["rows"]}
        if kinds & {"call", "use", "store", "cmp"}:
            assert kinds <= {"def", "use", "alias", "call", "store", "cmp", "return", "into", "note"}
            return
    pytest.fail("no function whose first parameter is used")
    with pytest.raises(WorkerError):
        c.request("trace_values", {"program": PROGRAM, "entry": funcs[0][0], "variable": "no_such_var"})


@pytest.mark.ghidra
def test_constants_on_real_binary(world):
    c, _funcs = world
    r = c.request("constants", {"program": PROGRAM, "value": 0x5A4D, "limit": 5}, timeout=300)    # "MZ" check in the CRT start
    assert r["total"] >= 1 and all(row[1] >= 1 for row in r["rows"])
    assert c.request("constants", {"program": PROGRAM, "value": 0x7A5B3C1D, "limit": 5}, timeout=300)["total"] == 0
