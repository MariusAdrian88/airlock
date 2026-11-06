"""Support for the real-data suite: pinned downloads, a cache, and a real project per target.

Nothing here runs unless `--realdata` is given (see conftest.py). No environment variables: the cache
folder is the pytest option `--realdata-cache`, default `<airlock data dir>/realdata`.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import shutil
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).parent
TIMINGS: dict[str, dict[str, float]] = {}      # target -> {step: seconds}, printed by conftest
READY_WAIT_S = 1500


def load_targets() -> dict[str, dict[str, Any]]:
    data = json.loads((HERE / "targets.json").read_text("utf-8"))
    return {t["name"]: t for t in data["targets"]}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(target: dict[str, Any], cache: Path) -> Path:
    """Download (if not cached), check the sha256, extract the members. Returns the analysed file."""
    root = cache / target["name"]
    root.mkdir(parents=True, exist_ok=True)
    archive = root / "archive.zip"
    t0 = time.monotonic()
    if not archive.is_file() or _sha256(archive) != target["sha256"]:
        req = urllib.request.Request(target["url"], headers={"User-Agent": "airlock-realdata"})
        tmp = archive.with_suffix(".part")
        with urllib.request.urlopen(req, timeout=120) as r, tmp.open("wb") as out:
            shutil.copyfileobj(r, out)
        got = _sha256(tmp)
        if got != target["sha256"]:
            tmp.unlink()
            pytest.fail(f"{target['name']}: sha256 {got} differs from the pinned {target['sha256']} ({target['url']})")
        tmp.replace(archive)
    TIMINGS.setdefault(target["name"], {})["download_s"] = time.monotonic() - t0
    out_dir = root / "x"
    wanted = out_dir / target["file"]
    if not wanted.is_file() or wanted.stat().st_size == 0:
        shutil.rmtree(out_dir, ignore_errors=True)
        out_dir.mkdir()
        with zipfile.ZipFile(archive) as z:
            for m in target["members"]:
                z.extract(m, out_dir)               # zipfile rejects ../ paths itself
    return wanted


def wait_ready(ctx, count: int, timeout_s: int = READY_WAIT_S) -> str:
    """Wait until `count` binaries are ready. It polls the stored status only (not `index_status`,
    which can run index refresh code beside the analysis queue), then returns the full status text."""
    from airlock.server.tools import admin
    ix = ctx.indexer
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = [ix.get_status(st, b.id) for st in (ix.store(p) for p in ix.projects())
                  for b in st.list_binaries()]
        if any(s == "error" for s, _ in states) or sum(s == "ready" for s, _ in states) >= count:
            break
        time.sleep(2)
    status = admin.index_status(ctx)
    assert " error:" not in status and status.count(" ready:") >= count, status
    return status


def make_ctx(work: Path):
    """A ServerContext with a private data folder and project root, lazy bulk decompile."""
    from airlock.config.loader import load_config
    from airlock.server.context import ServerContext
    from airlock.worker.client import WorkerClient
    work = work.resolve()
    cfg = dataclasses.replace(load_config(), data_dir=work / "data", projects_root=work / "projects")
    cfg.defaults["bulk_decompile"] = "lazy"
    return ServerContext(config=cfg, worker=WorkerClient(cfg))


def open_project(ctx, target: dict[str, Any], exe: Path, files: int = 1) -> str:
    """project_create on the folder of the analysed file, then wait for the index. Returns the status."""
    from airlock.server.tools import project_create as pc
    t0 = time.monotonic()
    scan = pc.project_create(ctx, str(exe.parent), target["name"])
    m = re.search(r"\(recommended (\w)\)", scan)
    assert m, scan
    out = pc.project_create(ctx, str(exe.parent), target["name"], option=m.group(1))
    assert not out.startswith("error"), out
    status = wait_ready(ctx, files)
    TIMINGS.setdefault(target["name"], {})["index_s"] = time.monotonic() - t0
    return status
