"""Fixtures of the real-data suite. All of it is inert without `--realdata`: no download, no Ghidra."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

import rdsupport as rd


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--realdata"):
        return
    skip = pytest.mark.skip(reason="needs --realdata (downloads open-source targets, runs real Ghidra)")
    for item in items:
        if "realdata" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def realdata_cache(request: pytest.FixtureRequest) -> Path:
    if not request.config.getoption("--realdata"):
        pytest.skip("needs --realdata")
    given = request.config.getoption("--realdata-cache")
    if given:
        path = Path(given)
    else:
        from airlock.paths import default_data_dir
        path = default_data_dir() / "realdata"
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture(scope="module")
def target_world(request: pytest.FixtureRequest, realdata_cache: Path, tmp_path_factory):
    """Per test module: `TARGET = "name"` (from targets.json) -> (ctx, target, exe). One project, one
    worker; the worker is stopped when the module ends."""
    name = request.module.TARGET
    files = getattr(request.module, "FILES", 1)
    target = rd.load_targets()[name]
    exe = rd.fetch(target, realdata_cache)
    t0 = time.monotonic()
    ctx = None
    try:
        ctx = rd.make_ctx(tmp_path_factory.mktemp(name))
        rd.open_project(ctx, target, exe, files)
        rd.TIMINGS.setdefault(name, {})["open_total_s"] = time.monotonic() - t0
        yield ctx, target, exe
    finally:
        if ctx is not None:
            ctx.worker.stop()


def pytest_terminal_summary(terminalreporter) -> None:
    if not rd.TIMINGS:
        return
    terminalreporter.section("realdata timings (s)")
    for name, steps in rd.TIMINGS.items():
        terminalreporter.write_line(f"{name:12s} " + "  ".join(f"{k}={v:.0f}" for k, v in steps.items()))
