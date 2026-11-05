import pytest

from airlock.config.loader import parse_jsonc, resolve, default_config_text, deep_merge
from airlock.worker.client import WorkerClient
from airlock.worker.protocol import WorkerError


@pytest.fixture
def client(tmp_path):
    merged = deep_merge(parse_jsonc(default_config_text()),
                        {"ghidra_dir": str(tmp_path / "no-ghidra"), "index_dir": str(tmp_path)})
    c = WorkerClient(resolve(merged, "dirty", None))
    yield c
    c.stop()


def test_hello_roundtrip(client):
    data = client.request("hello", timeout=30)
    assert data["pid"] > 0
    assert data["ghidra_started"] is False
    assert client.running()


def test_unknown_op_is_an_error_not_a_crash(client):
    with pytest.raises(WorkerError) as e:
        client.request("does_not_exist", timeout=30)
    assert e.value.code == "unknown_op"
    assert client.request("hello", timeout=30)["pid"]  # still alive


def test_start_ghidra_reports_bad_install(client):
    with pytest.raises(WorkerError) as e:
        client.ensure_ghidra(timeout=60)
    assert e.value.code in {"pyghidra_missing", "ghidra_start_failed", "internal"}


def test_stop_and_restart(client):
    pid1 = client.request("hello", timeout=30)["pid"]
    client.stop()
    assert not client.running()
    pid2 = client.request("hello", timeout=30)["pid"]
    assert pid2 != pid1


def test_worker_log_receives_stderr(client):
    client.request("hello", timeout=30)
    client.stop()
    assert "[worker] airlock" in client.log_path.read_text("utf-8")


def test_requests_lost_to_stop_are_not_a_crash(client):
    """A request still pending when stop() ended the worker fails as worker_stopped; a worker that
    died on its own fails as worker_exited and its exit code goes to worker.log."""
    import types
    import threading as th
    for stopping, code in ((True, "worker_stopped"), (False, "worker_exited")):
        client.request("hello", timeout=30)
        proc = types.SimpleNamespace(stdout=iter(()), pid=4242, wait=lambda timeout=None: 3)
        client.proc, client._stopping = proc, stopping
        ev, box = th.Event(), []
        client._pending[99] = (ev, box)
        client._read_loop()
        client._pending.pop(99)
        assert ev.is_set() and box[0]["error"]["code"] == code
        client.proc = None
        client.stop()
    assert "worker pid 4242 exited with code 0x00000003" in client.log_path.read_text("utf-8")


def test_check_project_refuses_another_open_project():
    from airlock.worker.ghidra_ops import session as S
    old = S.SESSION.path
    try:
        S.SESSION.path = r"C:\a\ghidra"
        S.check_project({})                              # requests without a project are not checked
        S.check_project({"project": r"C:\a\ghidra"})
        with pytest.raises(WorkerError) as e:
            S.check_project({"project": r"C:\b\ghidra"})
        assert e.value.code == "wrong_project"
        S.SESSION.path = None
        with pytest.raises(WorkerError):
            S.check_project({"project": r"C:\a\ghidra"})
    finally:
        S.SESSION.path = old
