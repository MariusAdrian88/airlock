"""fileformat set (M5): ole_streams, hexdump, file_diff, record_guess on synthetic files."""

from __future__ import annotations

import random
import struct

import olefile
import pytest

from airlock.projects import new_manifest, write_manifest
from airlock.server import registry, roles
from airlock.server.tools import fileformat as _ff  # noqa: F401  (registers the tools)
from cfb import build_cfb
from test_tools import fill, make_ctx


@pytest.fixture
def env(tmp_path):
    c = make_ctx(tmp_path)
    fill(c)
    pp = c.indexer.paths("proj")
    src = tmp_path / "prog"
    src.mkdir()
    man = new_manifest("proj")
    man["source"] = {"path": str(src), "root_exe": "app.exe"}
    write_manifest(pp.manifest, man)
    (pp.dirty / "work").mkdir(parents=True, exist_ok=True)
    c.session = roles.SessionState(roles.DIRTY, pp)
    return c, src, pp


def call(c, name, **kw):
    return registry.call(c, name, **kw)


def _doc(extra=b"x"):
    rnd = random.Random(7)
    return {"WordDocument": bytes(rnd.randrange(256) for _ in range(6000)),
            "\x05SummaryInformation": b"S" * 4096,
            "ObjectPool/Item": b"I" * 4200 + extra}


def test_builder_is_valid_cfb(tmp_path):
    p = tmp_path / "a.ole"
    p.write_bytes(build_cfb(_doc()))
    o = olefile.OleFileIO(str(p))
    assert o.openstream("WordDocument").read() == _doc()["WordDocument"]
    assert o.openstream(["ObjectPool", "Item"]).read().endswith(b"x")
    o.close()


def test_ole_streams_tree_and_stream(env):
    c, src, _ = env
    (src / "a.doc").write_bytes(build_cfb(_doc()))
    out = call(c, "ole_streams", path="a.doc")
    assert out.splitlines()[0].startswith("ole a.doc 3 streams, 1 storages")
    assert "Root/WordDocument 6000" in out
    assert "Root/\\x05SummaryInformation 4096" in out
    assert "Root/ObjectPool/ (storage)" in out
    dump = call(c, "ole_streams", path="a.doc", stream="\\x05SummaryInformation", budget=300)
    assert "0x00000000  53 53" in dump and "cursor=" in dump
    cur = dump.split("cursor=")[1].split()[0]
    assert "0x" in call(c, "ole_streams", path="a.doc", stream="\\x05SummaryInformation", cursor=cur)
    assert call(c, "ole_streams", path="a.doc", stream="Root/ObjectPool/Item").startswith("a.doc:")
    assert call(c, "ole_streams", path="a.doc", stream="nope").startswith("error not_found")


def test_not_ole(env):
    c, src, _ = env
    (src / "d.bin").write_bytes(b"hello" * 10)
    assert call(c, "ole_streams", path="d.bin").startswith("error not_ole")


def test_hexdump(env):
    c, src, _ = env
    (src / "d.bin").write_bytes(bytes(range(64)) + b"Hello, world!")
    out = call(c, "hexdump", path="d.bin", offset=60, length=20).splitlines()
    assert out[0] == "d.bin 77 bytes, showing 0x3c-0x4d"
    assert out[1].startswith("0x0000003c  3c 3d 3e 3f 48 65 ")
    assert any("|" in ln and "Hello" in ln for ln in out)
    assert call(c, "hexdump", path="d.bin", offset=999).startswith("error bad_args")
    more = call(c, "hexdump", path="d.bin", length=32)
    assert "… more bytes. offset=0x20" in more


def test_path_roots(env, tmp_path):
    c, src, pp = env
    (src / "in.bin").write_bytes(b"1234")
    (pp.dirty / "work" / "w.bin").write_bytes(b"abcd")
    outside = tmp_path / "secret.bin"
    outside.write_bytes(b"zz")
    assert "w.bin" in call(c, "hexdump", path="w.bin")
    assert "in.bin" in call(c, "hexdump", path=str(src / "in.bin"))
    assert call(c, "hexdump", path=str(outside)).startswith("error outside_project")
    assert call(c, "hexdump", path="..\\secret.bin").startswith("error")
    assert call(c, "hexdump", path="missing.bin").startswith("error not_found")


def test_clean_role_refused(env):
    c, src, pp = env
    c.session = roles.SessionState(roles.CLEAN, pp)
    for name, kw in (("hexdump", {"path": "x"}), ("ole_streams", {"path": "x"}),
                     ("file_diff", {"path_a": "x", "path_b": "y"}), ("record_guess", {"path": "x"})):
        assert call(c, name, **kw).startswith("error wrong_role")


def test_file_diff_ole_one_stream(env):
    c, src, _ = env
    d1, d2 = _doc(b"x"), _doc(b"x")
    w = bytearray(d2["WordDocument"])
    w[1000:1003] = b"\xaa\xbb\xcc"
    d2["WordDocument"] = bytes(w)
    (src / "a.doc").write_bytes(build_cfb(d1))
    (src / "b.doc").write_bytes(build_cfb(d2))
    lines = call(c, "file_diff", path_a="a.doc", path_b="b.doc").splitlines()
    assert "1 changed, 0 added, 0 removed of 3 streams" in lines[0]
    assert lines[1].startswith("changed Root/WordDocument 6000B -> 6000B: 1 ranges, 3 bytes differ")
    assert lines[2].lstrip().startswith("0x000003e8-0x000003ea 3B")
    assert "[aa bb cc]" in lines[2]
    assert len(lines) == 3
    one = call(c, "file_diff", path_a="a.doc", path_b="b.doc", stream="WordDocument")
    assert "1 ranges, 3 bytes differ" in one
    assert "All streams identical" in call(c, "file_diff", path_a="a.doc", path_b="a.doc")


def test_file_diff_added_removed(env):
    c, src, _ = env
    d1, d2 = _doc(), _doc()
    del d2["ObjectPool/Item"]
    d2["New"] = b"n" * 4096
    (src / "a.doc").write_bytes(build_cfb(d1))
    (src / "b.doc").write_bytes(build_cfb(d2))
    out = call(c, "file_diff", path_a="a.doc", path_b="b.doc")
    assert "added Root/New 4096B" in out and "removed Root/ObjectPool/Item 4201B" in out


def test_file_diff_raw_merge_and_tail(env):
    c, src, _ = env
    a = bytearray(3_000_000)
    b = bytearray(a)
    b[10] = 1
    b[14] = 2            # within the gap tolerance: merged with the first
    b[2_500_000] = 9     # second chunk
    (src / "a.dat").write_bytes(a)
    (src / "b.dat").write_bytes(bytes(b) + b"TAIL")
    out = call(c, "file_diff", path_a="a.dat", path_b="b.dat").splitlines()
    assert "3 ranges" in out[0]
    assert out[1].startswith("0x0000000a-0x0000000e 5B")
    assert out[2].startswith("0x002625a0-0x002625a0 1B")
    assert "only in b: 54 41 49 4c" in out[3]
    assert call(c, "file_diff", path_a="a.dat", path_b="a.dat").endswith("identical.")


def test_record_guess_fixed_stride(env):
    c, src, _ = env
    rnd = random.Random(3)
    recs = b"".join(struct.pack("<IHhf8s", i, rnd.randrange(1000), -5, i * 1.5 + 0.5, b"AB%05d\0" % i)
                    for i in range(200))
    (src / "f.dat").write_bytes(recs)
    out = call(c, "record_guess", path="f.dat")
    assert "fixed stride 20: 200 records, 0 bytes left over" in out
    assert "+0x00 u32 0..199" in out
    assert "f32" in out
    assert "ascii" in out


def test_record_guess_length_prefixed(env):
    c, src, _ = env
    rnd = random.Random(5)
    data = b"".join(struct.pack("<H", n) + bytes(rnd.randrange(256) for _ in range(n))
                    for n in (rnd.randrange(30, 120) for _ in range(150)))
    (src / "l.dat").write_bytes(data)
    out = call(c, "record_guess", path="l.dat")
    assert "length-prefixed u16le from 0x0: 150 records" in out
    assert f"chain ends exactly at {hex(len(data))}" in out


def test_record_guess_random_and_stream(env):
    c, src, _ = env
    rnd = random.Random(1)
    (src / "r.dat").write_bytes(bytes(rnd.randrange(256) for _ in range(4000)))
    out = call(c, "record_guess", path="r.dat")
    assert "no fixed stride" in out and "entropy 7." in out and "strings" not in out
    (src / "a.doc").write_bytes(build_cfb({"Tbl": struct.pack("<I", 7) * 1500}))
    assert "fixed stride 4" in call(c, "record_guess", path="a.doc", stream="Tbl")
    assert call(c, "record_guess", path="r.dat", offset=99999).startswith("error bad_args")
