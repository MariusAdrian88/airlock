"""Log files: size rotation, project.log for project events, log paths in index_status."""

from __future__ import annotations

import logging

from airlock import logs
from airlock.server.tools import admin
from test_tools import fill, make_ctx


def test_rotating_handler_rolls_over(tmp_path, monkeypatch):
    monkeypatch.setattr(logs, "LOG_MAX_BYTES", 300)
    monkeypatch.setattr(logs, "LOG_BACKUPS", 2)
    p = tmp_path / "l" / "x.log"
    h = logs.rotating(p, "%(message)s")
    for i in range(60):
        h.handle(logging.makeLogRecord({"msg": f"line {i:03d} " + "x" * 20, "levelno": logging.INFO}))
    h.close()
    files = sorted(f.name for f in p.parent.iterdir())
    assert files == ["x.log", "x.log.1", "x.log.2"]            # backups capped, the rest dropped
    assert p.stat().st_size <= 300 + 60


def test_project_events_go_to_project_log(tmp_path):
    ctx = make_ctx(tmp_path)
    pp = ctx.indexer.paths("proj", create=True)
    logs.project_log(pp.logs).warning("relink: %s binaries", 3)
    logs.project_log(pp.logs).info("queue: %s -> %s", "prog", "ready")
    text = logs.project_log_path(pp.logs).read_text("utf-8")
    assert "WARNING relink: 3 binaries" in text and "INFO queue: prog -> ready" in text
    other = ctx.indexer.paths("other", create=True)
    assert not logs.project_log_path(other.logs).exists()      # no leakage between projects


def test_index_status_names_the_logs(tmp_path):
    ctx = make_ctx(tmp_path)
    fill(ctx)
    out = admin.index_status(ctx)
    pp = ctx.indexer.paths("proj")
    assert f"log {logs.project_log_path(pp.logs)}" in out
    assert f"worker {ctx.config.data_dir / 'logs' / 'worker.log'}" in out
    assert "server.log" in out
