"""End-to-end tool test against the real worker (JVM + Ghidra, minutes).

    pytest -q -m ghidra --binary=<path-to-exe>

Asserts generic properties only; nothing here is specific to a binary.
"""

from __future__ import annotations

import dataclasses
import re
import time

import pytest

from airlock.config.loader import load_config
from airlock.server.budget import estimate_tokens
from airlock.server.context import ServerContext
from airlock.server.tools import admin, core
from airlock.worker.client import WorkerClient

pytestmark = pytest.mark.ghidra

READY_WAIT_S = 1800
TIMINGS: dict[str, float] = {}
SAMPLES: dict[str, str] = {}


@pytest.fixture(scope="module")
def world(binary_path, tmp_path_factory):
    cfg = dataclasses.replace(load_config(), data_dir=tmp_path_factory.mktemp("data"),
                              projects_root=tmp_path_factory.mktemp("projects"))
    ctx = ServerContext(config=cfg, worker=WorkerClient(cfg))
    try:
        t0 = time.monotonic()
        out = core.open_binary(ctx, "e2e", binary_path)
        TIMINGS["open_binary_returns_s"] = time.monotonic() - t0
        SAMPLES["open_binary"] = out
        assert "error" not in out.splitlines()[0], out
        deadline = time.monotonic() + READY_WAIT_S
        status = ""
        while time.monotonic() < deadline:
            status = admin.index_status(ctx)
            if " ready:" in status or " error:" in status:
                break
            time.sleep(2)
        TIMINGS["open_to_ready_s"] = time.monotonic() - t0
        SAMPLES["index_status"] = status
        assert " ready:" in status, status
        b = ctx.indexer.store("e2e").list_binaries()[0]
        job = ctx.indexer.job_for("e2e", b.id)
        if job:
            TIMINGS.update(job.timings)
        yield ctx
    finally:
        ctx.worker.stop()


def tokens(text: str) -> int:
    return estimate_tokens(text, "code")


def test_binary_listed_and_outlined(world):
    assert "ready" in core.list_binaries(world)
    out = core.outline(world)
    SAMPLES["outline"] = out
    assert "functions " in out and "imports " in out
    assert tokens(out) <= 600


def test_find_file_string_xrefs_and_function(world):
    hit = None
    for pat in ("file", "open", "save", ".txt", "error"):
        out = core.strings(world, pat, limit=50)
        for line in out.splitlines()[1:]:
            if "<- " in line and "(no refs)" not in line:
                hit = (pat, out, line)
                break
        if hit:
            break
    assert hit, "no referenced string found for any generic pattern"
    SAMPLES["strings"] = hit[1][:600]
    addr = re.match(r"(0x[0-9a-f]+)", hit[2]).group(1)

    refs = core.xrefs(world, addr)
    SAMPLES["xrefs"] = refs[:600]
    lines = refs.splitlines()
    assert lines[0].startswith("xrefs to ") and len(lines) >= 3, refs
    src = re.match(r"\s+(0x[0-9a-f]+)", lines[-1] if not lines[-1].startswith("…") else lines[-2])
    assert src, refs

    t0 = time.monotonic()
    fn = core.function(world, src.group(1))
    TIMINGS["first_function_call_s"] = time.monotonic() - t0
    SAMPLES["function"] = fn[:900]
    assert not fn.startswith("error"), fn
    assert "{" in fn
    assert tokens(fn) <= 2000

    t0 = time.monotonic()
    again = core.function(world, src.group(1))
    TIMINGS["cached_function_call_s"] = time.monotonic() - t0
    assert again == fn

    sig = core.function(world, src.group(1), view="signature")
    SAMPLES["function_signature"] = sig
    assert sig.splitlines()[-1].startswith("0x")

    cg = core.callgraph(world, src.group(1), depth=2)
    SAMPLES["callgraph"] = cg[:600]
    assert cg.startswith("callees of ") and not cg.startswith("error")

    callers = core.xrefs(world, src.group(1))
    assert callers.startswith("xrefs to ")


def test_search_finds_names_strings_imports(world):
    out = core.search(world, "file")
    SAMPLES["search"] = out[:600]
    assert out.startswith("search 'file'") or out.startswith("no hits")
    assert tokens(out) <= 2000


def test_not_found_is_one_line(world):
    out = core.function(world, "definitely_not_a_function_name")
    assert out.startswith("error not_found:") and "\n" not in out


def test_report(world, capsys):
    with capsys.disabled():
        print("TIMINGS " + ", ".join(f"{k}={v:.2f}" for k, v in sorted(TIMINGS.items())))
        for k, v in SAMPLES.items():
            print(f"--- {k}\n{v}")
