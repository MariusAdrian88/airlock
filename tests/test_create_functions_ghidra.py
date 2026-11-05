"""create_functions against the real worker (JVM + Ghidra, minutes for the analysis).

    pytest -q -m ghidra --binary=<path-to-exe>

Generic properties only: existing entries and non-code addresses are classified and left alone, an
address in a gap between functions is turned into a function or reported with a reason.
"""

from __future__ import annotations

import shutil
import time
from typing import Any

import pytest

from airlock.config.loader import load_config
from airlock.worker.client import WorkerClient

pytestmark = pytest.mark.ghidra
PROGRAM = "target.exe"


def _functions(c: WorkerClient) -> list[dict[str, Any]]:
    rows: list[list[Any]] = []
    offset = 0
    while True:
        r = c.request("extract", {"program": PROGRAM, "kind": "functions", "offset": offset,
                                  "limit": 5000}, timeout=600)
        cols = r["columns"]
        rows += r["rows"]
        if r["done"]:
            break
        offset = r["next_offset"]
    return [dict(zip(cols, x)) for x in rows if x[cols.index("space")] == "ram"
            and not x[cols.index("is_external")]]


@pytest.fixture(scope="module")
def world(binary_path, tmp_path_factory):
    work = tmp_path_factory.mktemp("cf")
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
        yield c
    finally:
        c.stop()


def test_existing_and_non_code_are_left_alone(world):
    fns = sorted(_functions(world), key=lambda f: f["entry"])
    big = next(f for f in fns if f["size"] > 8)
    res = world.request("create_functions", {"program": PROGRAM, "addresses": [
        big["entry"], big["entry"] + 1, 0]}, timeout=600)
    assert res["created"] == 0 and res["failed"] == 0, res
    assert res["reasons"].get("exists") == 1
    assert res["reasons"].get("not_executable") == 1
    inside = res["reasons"].get("inside_function", 0) + res["reasons"].get("inside_instruction", 0)
    assert inside == 1, res
    assert len(_functions(world)) == len(fns)


def test_gap_address_becomes_a_function(world):
    fns = sorted(_functions(world), key=lambda f: f["entry"])
    gaps = [a["entry"] + a["size"] for a, b in zip(fns, fns[1:])
            if a["size"] and a["entry"] + a["size"] < b["entry"]]
    if not gaps:
        pytest.skip("no gap between functions in this binary")
    target = gaps[0]
    res = world.request("create_functions", {"program": PROGRAM, "addresses": [target]}, timeout=600)
    assert res["created"] + res["skipped"] + res["failed"] == 1, res
    if res["created"]:
        assert any(f["entry"] == target for f in _functions(world))
        again = world.request("create_functions", {"program": PROGRAM, "addresses": [target]}, timeout=600)
        assert again["created"] == 0 and again["reasons"].get("exists") == 1, again


def test_chunked_creation_keeps_the_worker_alive(world):
    """Several chunks (one transaction and save each, conventions with the last only), then the same
    addresses again: nothing is created twice and the worker process is the same one throughout."""
    fns = sorted(_functions(world), key=lambda f: f["entry"])
    gaps = [a["entry"] + a["size"] for a, b in zip(fns, fns[1:])
            if a["size"] and a["entry"] + a["size"] < b["entry"]][:40]
    if len(gaps) < 4:
        pytest.skip("too few gaps between functions in this binary")
    pid = world.proc.pid
    chunks = [gaps[i:i + 10] for i in range(0, len(gaps), 10)]
    created = 0
    for i, chunk in enumerate(chunks):
        res = world.request("create_functions", {"program": PROGRAM, "addresses": chunk,
                                                 "conventions": i == len(chunks) - 1}, timeout=600)
        assert res["requested"] == len(chunk), res
        created += res["created"]
    assert world.proc.pid == pid and world.running()
    again = world.request("create_functions", {"program": PROGRAM, "addresses": gaps}, timeout=600)
    assert again["created"] == 0 and again["reasons"].get("exists", 0) == created, again
