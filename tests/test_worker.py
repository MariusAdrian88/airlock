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
