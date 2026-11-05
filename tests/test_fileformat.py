"""fileformat set (M5): ole_streams, hexdump, file_diff, record_guess on synthetic files."""

from __future__ import annotations

import random
import re
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
    assert "length-prefixed u16le at +0, step = 2 + len: 150 records from 0x0" in out
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


# -- layouts seen in real files (dBase, BIFF, PNG, RIFF, MIDI, shapefile), rebuilt synthetically ---------

def _rg(env, name, data, **kw):
    c, src, _ = env
    (src / name).write_bytes(data)
    return call(c, "record_guess", path=name, **kw)


def test_record_guess_records_after_a_header(env):
    # dBase: 32-byte header, 32-byte field descriptors, 0x0d, then fixed records
    rnd = random.Random(11)
    fields = [(b"ID", b"N", 6), (b"NAME", b"C", 16), (b"CITY", b"C", 12), (b"BORN", b"D", 8)]
    rl = 1 + sum(f[2] for f in fields)
    hl = 32 + 32 * len(fields) + 1
    head = struct.pack("<BBBBIHH20x", 3, 126, 1, 1, 90, hl, rl)
    desc = b"".join(n.ljust(11, b"\0") + t + b"\0" * 4 + bytes([ln, 0]) + b"\0" * 14 for n, t, ln in fields)
    names = [b"Alice", b"Bob", b"Chen", b"Dora", b"Emil", b"Fay", b"Gus"]
    cities = [b"Paris", b"Rome", b"Oslo", b"Lima"]
    recs = b"".join(b" " + b"%6d" % i + rnd.choice(names).ljust(16) + rnd.choice(cities).ljust(12)
                    + b"19%02d%02d%02d" % (rnd.randrange(50, 99), rnd.randrange(1, 13), rnd.randrange(1, 28))
                    for i in range(120))
    out = _rg(env, "t.dbf", head + desc + b"\x0d" + recs)
    m = re.search(r"fixed stride %d: (\d+) records from 0x([0-9a-f]+)" % rl, out)
    assert m and 118 <= int(m.group(1)) <= 120 and abs(int(m.group(2), 16) - hl) <= 12
    assert "text" in out


def test_record_guess_run_found_in_small_data(env):
    # ten 29-byte text records behind a 400-byte header: too short for a whole-window stride score
    rnd = random.Random(21)
    hdr = bytes(rnd.randrange(32, 120) for _ in range(264)) + bytes(136)
    who = [b" Alice", b" Bob", b"*Carl", b" Dee", b" Eve", b" Fritz", b" Gina"]
    recs = b"".join(rnd.choice(who).ljust(25) + b"%04d" % rnd.randrange(1950, 2000) for _ in range(10))
    out = _rg(env, "s.dbf", hdr + recs)
    m = re.search(r"fixed stride 29: \d+ records from 0x([0-9a-f]+)", out)
    assert m and abs(int(m.group(1), 16) - len(hdr)) <= 8


def test_record_guess_biff_type_and_length(env):
    # BIFF: u16 record type, u16 length, payload; inside an OLE stream, EOF record, stream padding
    rnd = random.Random(2)
    blob = bytearray()
    for _ in range(600):
        t = rnd.choice([0x0204, 0x0203, 0x00fd, 0x027e])
        pl = bytes(rnd.randrange(256) for _ in range(rnd.choice([6, 8, 10, 14])))
        blob += struct.pack("<HH", t, len(pl)) + pl
    blob += struct.pack("<HH", 0x000a, 0) + bytes(40)
    c, src, _ = env
    (src / "b.xls").write_bytes(build_cfb({"Workbook": bytes(blob)}))
    out = call(c, "record_guess", path="b.xls", stream="Workbook")
    assert re.search(r"length-prefixed u16le at \+2, step = 4 \+ len: 6\d\d records from 0x0", out)
    assert "tag at +0 (2B): 0x" in out


def test_record_guess_png_chunks_big_endian(env):
    rnd = random.Random(4)
    ch = []
    for tag, n in [(b"IHDR", 13)] + [(b"IDAT", rnd.randrange(200, 900)) for _ in range(6)] + [(b"IEND", 0)]:
        pl = bytes(rnd.randrange(256) for _ in range(n))
        ch.append(struct.pack(">I", n) + tag + pl + struct.pack(">I", rnd.getrandbits(32)))
    data = b"\x89PNG\r\n\x1a\n" + b"".join(ch)
    out = _rg(env, "p.png", data)
    assert "length-prefixed u32be at +0, step = 12 + len: 8 records from 0x8" in out
    assert "IDATx6" in out and "IHDR" in out and "IEND" in out
    assert "from 0x8" in _rg(env, "p.png", data, offset=8)   # pointing at the first chunk: same chain


def test_record_guess_riff_chunks_padded_to_even(env):
    rnd = random.Random(6)
    body = b"WAVE"
    for tag, n in [(b"fmt ", 16), (b"LIST", 37), (b"data", 1001), (b"cue ", 24), (b"junk", 5)]:
        body += tag + struct.pack("<I", n) + bytes(rnd.randrange(1, 256) for _ in range(n)) + b"\0" * (n & 1)
    out = _rg(env, "r.wav", b"RIFF" + struct.pack("<I", len(body)) + body)
    assert "u32le at +4, step = 8 + len, padded to 2: 5 records from 0xc" in out
    assert "LIST" in out and "data" in out


def test_record_guess_midi_chunks(env):
    rnd = random.Random(8)
    data = b"MThd" + struct.pack(">IHHH", 6, 1, 3, 96)
    for n in (900, 1500, 700):
        data += b"MTrk" + struct.pack(">I", n) + bytes(rnd.randrange(256) for _ in range(n))
    out = _rg(env, "m.mid", data)
    assert "length-prefixed u32be at +4, step = 8 + len: 4 records from 0x0" in out
    assert "MTrkx3" in out and "MThd" in out


def test_record_guess_shapefile_records_len_in_words(env):
    rnd = random.Random(9)
    body = b""
    for i in range(80):
        words = rnd.randrange(10, 60)
        body += struct.pack(">II", i + 1, words) + bytes(rnd.randrange(256) for _ in range(words * 2))
    out = _rg(env, "s.shp", bytes(100) + body)
    assert "length-prefixed u32be at +4, step = 8 + len*2: 80 records from 0x64" in out


def test_record_guess_big_endian_table_columns(env):
    # shx style: u32 BE offset (ascending) and u32 BE length, after a 100-byte header
    rnd = random.Random(10)
    off, rows = 50, b""
    for _ in range(300):
        ln = rnd.randrange(10, 400)
        rows += struct.pack(">II", off, ln)
        off += ln + 4
    out = _rg(env, "x.shx", bytes(100) + rows, offset=100)
    assert "fixed stride 8: 300 records" in out
    assert "+0x00 u32be" in out and "ascending" in out and "+0x04 u32be" in out


def test_record_guess_varint_stream(env):
    rnd = random.Random(12)
    data = b""
    for _ in range(80):
        n = rnd.randrange(30, 120)
        data += bytes([n]) + bytes(rnd.randrange(1, 30) for _ in range(n))
    out = _rg(env, "v.pb", data)
    assert "length-prefixed u8 at +0" in out or "length-prefixed varint at +0" in out
    assert "chain ends exactly" in out


def test_record_guess_no_false_chain_in_text_or_tables(env):
    rnd = random.Random(13)
    assert "records from" not in _rg(env, "t.txt", b"The quick brown fox jumps over the lazy dog. " * 300)
    small = bytes(rnd.choice([0, 0, 0, 1, 2, 3, 0, 4, 0, 5]) for _ in range(20000))
    assert "records from" not in _rg(env, "n.bin", small)
