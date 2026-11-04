"""Protocol events: worker side emit(), client side progress tracking. No Ghidra needed."""

import io
import threading
from types import SimpleNamespace

import pytest

from airlock.config.loader import parse_jsonc, resolve, default_config_text, deep_merge
from airlock.worker import main as worker_main
from airlock.worker.client import WorkerClient
from airlock.worker.protocol import WorkerError, decode, encode


@pytest.fixture
def client(tmp_path):
    merged = deep_merge(parse_jsonc(default_config_text()),
                        {"ghidra_dir": str(tmp_path / "no-ghidra"), "index_dir": str(tmp_path)})
    c = WorkerClient(resolve(merged, "dirty", None))
    yield c
    c.stop()


def test_emit_writes_one_event_line(monkeypatch):
    buf = io.BytesIO()
    monkeypatch.setattr(worker_main.STATE, "out", buf)
    worker_main.emit("progress", job="analysis", program="a.exe", pct=None)
    msg = decode(buf.getvalue())
    assert msg == {"event": "progress", "job": "analysis", "program": "a.exe", "pct": None}
    assert "id" not in msg


def test_emit_from_many_threads_keeps_lines_intact(monkeypatch):
    buf = io.BytesIO()
    monkeypatch.setattr(worker_main.STATE, "out", buf)
    ts = [threading.Thread(target=lambda i=i: [worker_main.emit("progress", n=i, pad="x" * 500)
                                               for _ in range(50)]) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    lines = buf.getvalue().splitlines()
    assert len(lines) == 400
    assert all(decode(l)["pad"] == "x" * 500 for l in lines)


def test_client_keeps_latest_progress_and_pairs_responses(client):
    got = []
    client.on_event(got.append)
    event = threading.Event()
    box: list = []
    client._pending[1] = (event, box)
    stream = [
        encode({"event": "progress", "job": "analysis", "program": "a.exe", "state": "running",
                "pct": None, "message": "1 analyzers done"}),
        encode({"event": "progress", "job": "analysis", "program": "b.exe", "state": "running"}),
        encode({"id": 1, "ok": True, "data": {"x": 1}}),  # response between events
        encode({"event": "progress", "job": "analysis", "program": "a.exe", "state": "done"}),
        b"not json\n",
    ]
    client.proc = SimpleNamespace(stdout=iter(stream))
    client._read_loop()
    assert box[0]["data"] == {"x": 1}
    assert client.progress("a.exe")["state"] == "done"
    assert client.progress("b.exe")["state"] == "running"
    assert client.progress()["program"] == "a.exe"  # most recent event overall
    assert client.progress("nope") is None
    assert len(got) == 3
    client.proc = None  # fake process: nothing to stop


def test_ghidra_ops_need_ghidra_started(client):
    for opname, args in [("open_project", {"path": "x", "name": "y"}),
                         ("extract", {"program": "a", "kind": "functions"}),
                         ("decompile", {"program": "a", "entry": 0}),
                         ("analyze", {"program": "a"})]:
        with pytest.raises(WorkerError) as e:
            client.request(opname, args, timeout=30)
        assert e.value.code == "ghidra_not_started", opname


def test_status_answers_without_ghidra(client):
    s = client.request("status", timeout=30)
    assert s == {"ghidra_started": False, "project": None, "programs": []}
