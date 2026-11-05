"""Another project cannot take the worker from a running import (real worker, JVM + Ghidra).

    pytest -q -m ghidra --binary=<path-to-exe>

Regression: a tool call or a resume of project A called ensure_open("A") while the queue imported a
binary into project B. The worker switched to A in between: B ended `no_program` (or `ready` with
its program saved into A's Ghidra project, B's project empty).
"""

from __future__ import annotations

import dataclasses
import threading
import time

import pytest

from airlock.config.loader import load_config
from airlock.server.context import ServerContext
from airlock.worker.client import WorkerClient
from airlock.worker.protocol import WorkerError

pytestmark = pytest.mark.ghidra


def test_import_survives_ensure_open_of_another_project(binary_path, tmp_path):
    cfg = dataclasses.replace(load_config(), data_dir=tmp_path / "data", projects_root=tmp_path / "projects")
    ctx = ServerContext(config=cfg, worker=WorkerClient(cfg))
    ix = ctx.indexer
    stop = threading.Event()
    seen: list[str] = []
    try:
        ix.paths("A", create=True)
        ix.ensure_open("A")                      # A has an (empty) Ghidra project; the worker has it open

        def hammer() -> None:
            while not stop.is_set():
                try:
                    ix.ensure_open("A")
                except WorkerError as e:
                    seen.append(e.code)
                time.sleep(0.02)

        t = threading.Thread(target=hammer, daemon=True)
        t.start()
        res = ix.open_binary("B", binary_path, wait_s=300)   # returns once analysis has started
        stop.set()
        t.join(30)
        st = ix.store("B")
        status, detail = ix.get_status(st, res.binary.id)
        assert status in ("analysing", "extracting", "finishing", "ready"), (status, detail)
        assert "busy" in seen                    # the other project was refused while B imported
        program = ix.program_of(st, res.binary)
        assert ctx.worker.request("status", {"program": program})["project"]["path"] == \
            str(ix.paths("B").ghidra)
        assert any(p.name.endswith(".prp") or p.suffix == ".gpr" for p in ix.paths("B").ghidra.iterdir())
        assert any(ix.paths("B").ghidra.joinpath("airlock.rep", "idata").rglob("*"))   # the program is saved in B
    finally:
        stop.set()
        ctx.worker.stop()
