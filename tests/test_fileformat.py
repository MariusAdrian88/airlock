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


def test_file_diff_many_ranges_page_by_cursor(env, monkeypatch):
    c, src, _ = env
    a = bytearray(4000)
    b = bytearray(a)
    for i in range(10):
        b[i * 100] = 1
    (src / "a.dat").write_bytes(a)
    (src / "b.dat").write_bytes(bytes(b))
    out = call(c, "file_diff", path_a="a.dat", path_b="b.dat", budget=120)
    assert "10 ranges" in out and "cursor=" in out        # a cut diff has a real cursor
    seen = [ln for ln in out.splitlines() if ln.startswith("0x")]
    for _ in range(20):
        m = re.search(r"cursor=(c_\w+)", out.splitlines()[-1])
        if not m:
            break
        out = call(c, "file_diff", path_a="a.dat", path_b="b.dat", budget=120, cursor=m.group(1))
        seen += [ln for ln in out.splitlines() if ln.startswith("0x")]
    assert len(seen) == 10


def test_file_diff_range_cap_names_offset_to_continue(env, monkeypatch):
    from airlock.server import fileformat as ffm
    monkeypatch.setattr(ffm, "MAX_RANGES", 3)
    c, src, _ = env
    a = bytearray(4000)
    b = bytearray(a)
    for i in range(10):
        b[i * 100] = 1
    (src / "a.dat").write_bytes(a)
    (src / "b.dat").write_bytes(bytes(b))
    out = call(c, "file_diff", path_a="a.dat", path_b="b.dat")
    last = out.splitlines()[-1]
    assert "7 more ranges after 0x000000c9" in last and last.endswith("offset=0xc9")
    out2 = call(c, "file_diff", path_a="a.dat", path_b="b.dat", offset=0xc9)
    assert out2.splitlines()[1].startswith("0x0000012c")


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


# -- OpenPGP packets, delimited text, registry policy, small tables, sample streams -----------------

def _pgp_packet(tag, body, kind="old"):
    n = len(body)
    if kind == "new":
        hdr = bytes([0xc0 | tag]) + (bytes([n]) if n < 192 else bytes([192 + ((n - 192) >> 8), (n - 192) & 255]))
    elif n < 256:
        hdr = bytes([0x80 | tag << 2, n])
    else:
        hdr = bytes([0x80 | tag << 2 | 1]) + n.to_bytes(2, "big")
    return hdr + body


def test_record_guess_openpgp_packets(env):
    rnd = random.Random(11)

    def rb(n):
        return bytes(rnd.randrange(256) for _ in range(n))

    def mpi(nbytes):
        return struct.pack(">H", nbytes * 8) + bytes([0x80]) + rb(nbytes - 1)

    def pubkey():
        return bytes([4]) + rb(4) + bytes([1]) + mpi(128) + mpi(3)

    def sig(rsa_len):
        hashed = bytes([5, 2]) + rb(4)
        return (bytes([4, 0x13, 1, 8]) + struct.pack(">H", len(hashed)) + hashed + bytes([0, 10, 9, 16])
                + rb(6) + rb(2) + mpi(rsa_len))
    key = (_pgp_packet(6, pubkey()) + _pgp_packet(13, b"Test User <t@example.org>")
           + _pgp_packet(2, sig(256)) + _pgp_packet(14, pubkey(), "new") + _pgp_packet(2, sig(128), "new"))
    out = _rg(env, "k.gpg", key)
    assert "openpgp packets: 5 records from 0x0" in out
    assert f"chain ends exactly at {hex(len(key))}" in out
    assert "pubkey" in out and "uid" in out and "sigx2" in out
    assert "old 1B" in out and "old 2B" in out and "new 1B" in out
    # a flipped length byte breaks the chain: no claim
    bad = bytearray(key)
    bad[1] += 7
    assert "openpgp" not in _rg(env, "bad.gpg", bytes(bad))
    # a key packet whose body does not parse (unknown algorithm, MPI too long) is no claim
    assert "openpgp" not in _rg(env, "one.gpg", _pgp_packet(6, bytes([4]) + rb(4) + bytes([0x63]) + rb(200)))
    assert "openpgp packets: 1 records" in _rg(env, "pub.gpg", _pgp_packet(6, pubkey()))
    # a chain that starts at a non-zero offset needs 3 packets
    assert "openpgp" not in _rg(env, "off.gpg", bytes(3) + _pgp_packet(6, pubkey()))


def test_record_guess_no_openpgp_in_random_data(env):
    rnd = random.Random(2)
    for i in range(300):
        data = bytes(rnd.randrange(256) for _ in range(rnd.choice([40, 300, 3000])))
        assert "openpgp" not in _rg(env, f"r{i}.bin", data)


def test_record_guess_delimited_text(env):
    rows = ["id,name,score,when"] + [f"{i},user{i * 7 % 13},{i * 1.5:.1f},2024-01-{i % 28 + 1:02d}" for i in range(60)]
    out = _rg(env, "t.csv", ("\r\n".join(rows) + "\r\n").encode())
    assert "delimited text (ascii/utf-8): 60 rows x 4 fields, separator comma, CRLF" in out
    assert "header row: id,name,score,when" in out
    assert "field 1 id: int 0..59" in out and "field 3 score: number" in out and "field 4 when: date" in out
    # semicolon with quoted separators, inside a binary blob
    body = "\n".join(f'{i};"a;b {i}";{i * 3}' for i in range(40)).encode()
    blob = bytes(range(256)) * 3 + b"\x00\x01" + body + b"\x00" + bytes(range(255, 0, -1))
    out = _rg(env, "blob.bin", blob)
    assert "delimited text" in out and "separator semicolon" in out and "x 3 fields" in out
    # tab separated, utf-16le
    tsv = "\n".join(f"{i}\tname{i}\t{i * i}" for i in range(30)).encode("utf-16le")
    assert "separator tab" in _rg(env, "u.tsv", b"\xff\xfe" + tsv)
    # prose with commas is not a table
    prose = ("The quick brown fox, which was tired, jumped over the dog.\n"
             "Meanwhile, the dog slept. It did not notice, or care, about the fox.\n"
             "Later on, in the evening, everybody went home, and that was that.\n"
             "No more words, said the author, are needed to finish this short text.\n" * 3).encode()
    assert "delimited text" not in _rg(env, "p.txt", prose)


def test_record_guess_registry_policy(env):
    def rec(key, val, typ, data):
        u = lambda s: s.encode("utf-16le") + b"\0\0"  # noqa: E731
        return (b"[\0" + u(key) + b";\0" + u(val) + b";\0" + struct.pack("<I", typ) + b";\0"
                + struct.pack("<I", len(data)) + b";\0" + data + b"]\0")
    data = b"PReg\x01\0\0\0" + b"".join(
        rec(f"Software\Policies\Vendor{i % 3}", f"Value{i}", 4 if i % 2 else 1,
            struct.pack("<I", i) if i % 2 else "text".encode("utf-16le") + b"\0\0") for i in range(12))
    out = _rg(env, "r.pol", data)
    assert "bracketed records [key;value;type;size;data] (utf-16le): 12 records from 0x8" in out
    assert "dwordx6" in out and "szx6" in out and "3 distinct keys" in out


def _ico_like(n, rnd):
    imgs = [bytes(rnd.randrange(256) for _ in range(rnd.randrange(80, 400))) for _ in range(n)]
    off = 6 + 16 * n
    ent = b""
    for im in imgs:
        ent += struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, len(im), off)
        off += len(im)
    return struct.pack("<HHH", 0, 1, n) + ent + b"".join(imgs)


def test_record_guess_small_offset_table(env):
    out = _rg(env, "a.ico", _ico_like(4, random.Random(4)))
    assert "offset/length table: 4 entries x 16 bytes from 0x6; offset u32le at +12, length u32le at +8" in out
    assert "right after the table" in out
    # TrueType-like directory: big endian, sorted by tag, offsets unordered
    rnd = random.Random(8)
    tabs = [(t, bytes(rnd.randrange(256) for _ in range(rnd.randrange(50, 300)))) for t in (b"OS/2", b"cmap", b"head", b"glyf", b"name")]
    off = 12 + 16 * len(tabs)
    ent, body = b"", b""
    for t, b in tabs:
        ent += t + struct.pack(">III", 0x1234, off + len(body), len(b))
        body += b + b"\0" * (-len(b) % 4)
    out = _rg(env, "f.ttf", struct.pack(">IHHHH", 0x10000, len(tabs), 0, 0, 0) + ent + body)
    assert "offset/length table: 5 entries x 16 bytes from 0xc; offset u32be at +8, length u32be at +12" in out
    # a header with random fields has no table
    rnd = random.Random(9)
    assert "offset/length" not in _rg(env, "n.bin", bytes(rnd.randrange(256) for _ in range(2000)))
    # a dBase-like field list with shifted small numbers is no directory
    fl = b"".join(b"FIELD%02d\0\0\0C" % i + b"\0\0\0\0" + bytes([10 + i, 0]) + b"\0" * 14 for i in range(8))
    assert "offset/length" not in _rg(env, "d.dat", fl + b"\x0d" + b" " * 3000)


def _wave(n, rnd, stereo=False):
    import math as m
    out = bytearray()
    for i in range(n):
        v = 128 + 70 * m.sin(i / 9.0) + 30 * m.sin(i / 3.1) + rnd.gauss(0, 2)
        out.append(max(0, min(255, int(v))))
        if stereo:
            out.append(max(0, min(255, int(128 + 60 * m.sin(i / 7.0) + rnd.gauss(0, 2)))))
    return bytes(out)


def test_record_guess_sample_stream(env):
    rnd = random.Random(6)
    out = _rg(env, "s8.raw", _wave(20000, rnd))
    assert "sample stream: 8-bit PCM-like waveform" in out and "no records" in out
    assert "fixed stride" not in out and "strings" not in out
    assert "sample stream" in _rg(env, "s8st.raw", _wave(20000, rnd, stereo=True))
    # a RIFF header in front keeps its exact chain but no stride is claimed inside the samples
    wav = (b"RIFF" + struct.pack("<I", 36 + 20000) + b"WAVEfmt " + struct.pack("<IHHIIHH", 16, 1, 1, 8000, 8000, 1, 8)
           + b"data" + struct.pack("<I", 20000) + _wave(20000, rnd))
    out = _rg(env, "w.wav", wav)
    assert "length-prefixed u32le at +4" in out and "sample stream" in out and "fixed stride" not in out
    # records and noise are not waveforms
    recs = b"".join(struct.pack("<IHhf8s", i, rnd.randrange(1000), -5, i * 1.5 + 0.5, b"AB%05d\0" % i) for i in range(300))
    assert "sample stream" not in _rg(env, "rec.dat", recs)
    assert "sample stream" not in _rg(env, "noise.raw", bytes(rnd.randrange(256) for _ in range(20000)))
    assert "sample stream" not in _rg(env, "ramp.raw", bytes(range(256)) * 80)


# -- Java class files, tiny and wide tables, 16-bit and noisy samples --------------------------------

def _class_file(extra_pool=True, cut=0):
    def utf(s):
        b = s.encode()
        return b"\x01" + struct.pack(">H", len(b)) + b

    pool = [utf("demo/Widget"), b"\x07\x00\x01", utf("java/lang/Object"), b"\x07\x00\x03", utf("<init>"), utf("()V"),
            b"\x0c\x00\x05\x00\x06", b"\x0a\x00\x04\x00\x07", utf("Code")]
    slots = 9
    if extra_pool:      # long and double take two slots each
        pool += [b"\x05" + struct.pack(">q", 1 << 40), b"\x06" + struct.pack(">d", 2.5), b"\x03" + struct.pack(">i", 7),
                 utf("hello"), b"\x08\x00\x0f"]
        slots += 2 + 2 + 1 + 1 + 1
    body = struct.pack(">HHH", 0x21, 2, 4) + b"\x00\x00"
    body += struct.pack(">H", 1) + struct.pack(">HHHH", 2, 5, 6, 0)                      # one field
    code = struct.pack(">HHH", 1, 1, 0) + b"\x00" * 4 + struct.pack(">HH", 0, 0)
    body += struct.pack(">H", 1) + struct.pack(">HHHH", 1, 5, 6, 1) + struct.pack(">HI", 9, len(code)) + code
    body += b"\x00\x00"
    d = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, slots + 1) + b"".join(pool) + body
    return d[:len(d) - cut] if cut else d


def test_record_guess_java_class(env):
    out = _rg(env, "W.class", _class_file())
    assert "java class file: version 52.0 (Java 8), constant pool of 16 slots (14 entries)" in out
    assert "class demo/Widget, super java/lang/Object" in out and "1 fields, 1 methods" in out
    assert "the class ends exactly at" in out and "strings" not in out
    # a class cut inside the members still gets its pool
    out = _rg(env, "cut.class", _class_file(cut=12))
    assert "java class file" in out and "constant pool of 16 slots" in out and "ends exactly" not in out
    # a constant pool that runs out of tags is no class
    bad = bytearray(_class_file())
    bad[10 + 3 + len("demo/Widget")] = 2        # tag 2 does not exist
    assert "java class file" not in _rg(env, "bad.class", bytes(bad))
    # the magic inside a blob is found, random bytes behind it are not a class
    assert "java class file" in _rg(env, "blob.bin", b"\x00" * 40 + _class_file())
    assert "java class file" not in _rg(env, "m.bin", b"\xca\xfe\xba\xbe" + bytes(random.Random(2).randrange(256) for _ in range(900)))


def _range_table(ents, w, endian):
    code = {2: "H", 4: "I", 8: "Q"}[w]
    return b"".join(struct.pack(endian + code * 2, off, ln) for off, ln in ents)


def test_record_guess_tiny_tables_tile_the_data(env):
    rnd = random.Random(21)
    blob = lambda n: bytes(rnd.randrange(1, 256) for _ in range(n))
    # two entries of 16 bytes behind a 4-byte magic; the ranges tile the rest of the data
    data = b"TBL1" + struct.pack("<II", 36, 300) + b"\0" * 8 + struct.pack("<II", 336, 500) + b"\0" * 8
    data += blob(800)
    out = _rg(env, "two.bin", data)
    assert "offset/length table: 2 entries x 16 bytes from 0x4; offset u32le at +0, length u32le at +4" in out
    assert "tile the data exactly" in out
    # one pair that covers the rest of the data
    out = _rg(env, "one.bin", b"HDR\0" + struct.pack(">II", 16, 700) + b"\0" * 4 + blob(700))
    assert "offset/length pair: u32be offset at +0 and length at +4 from 0x4" in out and "covers the rest of the data exactly" in out
    # ranges that stop short of the end, or leave a gap, are not evidence
    assert "offset/length" not in _rg(env, "short.bin", b"HDR\0" + struct.pack(">II", 16, 600) + b"\0" * 4 + blob(700))
    gap = b"TBL1" + struct.pack("<II", 36, 300) + b"\0" * 8 + struct.pack("<II", 340, 400) + b"\0" * 8 + blob(800)
    assert "offset/length" not in _rg(env, "gap.bin", gap)
    # random data does not fit
    for seed in range(20):
        r = random.Random(seed)
        assert "offset/length" not in _rg(env, "r.bin", bytes(r.randrange(256) for _ in range(r.randrange(64, 3000))))


def test_record_guess_wide_and_narrow_tables(env):
    rnd = random.Random(33)
    sizes = [310, 120, 415, 77]
    # u64 fields, 16-byte entries behind an 8-byte header
    off, ents = 8 + 16 * 4, []
    for s in sizes:
        ents.append((off, s))
        off += s
    data = b"HEAD64\0\0" + _range_table(ents, 8, "<") + bytes(rnd.randrange(256) for _ in range(off - 8 - 64))
    out = _rg(env, "w64.bin", data)
    assert "offset/length table: 4 entries x 16 bytes from 0x8; offset u64le at +0, length u64le at +8" in out
    # u16 fields (6-byte entries, big endian): accepted when the ranges tile exactly
    off, ents = 4 + 6 * 4, []
    for s in sizes:
        ents.append((off, s))
        off += s
    ent = b"".join(struct.pack(">HHH", 0, o, s) for o, s in ents)
    out = _rg(env, "w16.bin", b"T16\0" + ent + bytes(rnd.randrange(256) for _ in range(off - 28)))
    assert "offset u16be at +2, length u16be at +4" in out and "tile the data exactly" in out
    # the same table with gaps between the ranges is not trusted at 16 bits
    off, ents = 4 + 6 * 4, []
    for s in sizes:
        ents.append((off, s))
        off += s + 9
    ent = b"".join(struct.pack(">HHH", 0, o, s) for o, s in ents)
    assert "offset/length" not in _rg(env, "g16.bin", b"T16\0" + ent + bytes(rnd.randrange(256) for _ in range(off - 28)))
    # random buffers: no 16-bit or 64-bit table
    for seed in range(40):
        r = random.Random(100 + seed)
        assert "offset/length" not in _rg(env, "r.bin", bytes(r.randrange(256) for _ in range(r.randrange(64, 5000))))


def _wave16(n, rnd, stereo=False, noise=0.0):
    import math as m
    out = []
    for i in range(n):
        out.append(int(8000 * m.sin(i / 9.0) + 3000 * m.sin(i / 3.1) + rnd.gauss(0, 40 + noise)))
        if stereo:
            out.append(int(6000 * m.sin(i / 7.0) + rnd.gauss(0, 40 + noise)))
    return struct.pack("<%dh" % len(out), *[max(-32768, min(32767, v)) for v in out])


def test_record_guess_pcm16_and_noisy_samples(env):
    rnd = random.Random(12)
    out = _rg(env, "s16.raw", _wave16(12000, rnd))
    assert "sample stream: 16-bit little-endian PCM-like waveform" in out and "no records" in out and "fixed stride" not in out
    out = _rg(env, "s16st.raw", _wave16(12000, rnd, stereo=True))
    assert "16-bit little-endian PCM-like waveform" in out and "interleaved stereo" in out
    # data that starts on an odd byte is still read
    assert "16-bit little-endian PCM" in _rg(env, "odd.raw", b"\x01" + _wave16(12000, rnd))
    # noisy 16-bit and noisy 8-bit audio
    assert "16-bit little-endian PCM" in _rg(env, "n16.raw", _wave16(12000, rnd, noise=2500))
    import math as m
    noisy8 = bytes(max(0, min(255, int(128 + 50 * m.sin(i / 9.0) + 25 * m.sin(i / 3.1) + rnd.gauss(0, 24)))) for i in range(20000))
    assert "sample stream: 8-bit PCM-like waveform" in _rg(env, "n8.raw", noisy8)
    # 16-bit tables and noise are no waveform
    assert "sample stream" not in _rg(env, "ramp16.raw", struct.pack("<8000H", *range(0, 40000, 5)))
    assert "sample stream" not in _rg(env, "tab16.raw", struct.pack("<6000H", *[rnd.randrange(0, 700) for _ in range(6000)]))
    assert "sample stream" not in _rg(env, "noise16.raw", bytes(rnd.randrange(256) for _ in range(24000)))
    recs = b"".join(struct.pack("<HhHhIf", i, -i, rnd.randrange(60000), rnd.randrange(-300, 300), i * 3, i * 0.5) for i in range(1500))
    assert "sample stream" not in _rg(env, "rec16.dat", recs)
    text = ("Chào mừng bạn đến với trình hướng dẫn, bạn có thể lập trình %d lần\n" % 0).encode()
    vi = b"".join(("Chào mừng bạn số %d: ứng dụng tập trung trong các vòng đời %d\n" % (i, i * 7 % 13)).encode() for i in range(300))
    assert "sample stream" not in _rg(env, "vi.txt", vi)


def test_file_diff_cursor_wins_over_arguments(env, monkeypatch):
    c, src, _ = env
    a = bytearray(4000)
    b = bytearray(a)
    for i in range(10):
        b[i * 100] = 1
    (src / "a.dat").write_bytes(a)
    (src / "b.dat").write_bytes(bytes(b))
    first = call(c, "file_diff", path_a="a.dat", path_b="b.dat", budget=60)
    cid = re.search(r"cursor=(c_\w+)", first.splitlines()[-1]).group(1)
    alone = call(c, "file_diff", cursor=cid, budget=60)           # the cursor alone
    assert alone.splitlines()[0].startswith("0x") and "error" not in alone
    cid = re.search(r"cursor=(c_\w+)", alone.splitlines()[-1]).group(1)
    same = call(c, "file_diff", path_a="a.dat", path_b="b.dat", cursor=cid, budget=60)
    assert "cursor kept" not in same and "error" not in same
    cid = re.search(r"cursor=(c_\w+)", same.splitlines()[-1]).group(1)
    other = call(c, "file_diff", path_a="a.dat", path_b="b.dat", offset=0x50, cursor=cid, budget=60)
    assert other.splitlines()[0] == "(cursor kept its arguments: offset=0x0)"
    assert "error" not in other
    assert call(c, "file_diff", path_a="a.dat", path_b="b.dat", cursor="c_dead").startswith(
        "error bad_cursor: cursor 'c_dead' is unknown or expired")
