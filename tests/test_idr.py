"""IDR knowledge base reader, matcher and storage (synthetic knowledge bases, synthetic PE files)."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from airlock.config.loader import default_config_text, parse_jsonc, resolve
from airlock.server import delphi, idr
from airlock.server.cpp import Image
from test_delphi import Pe
from test_tools import make_ctx

# ── a synthetic knowledge base ─────────────────────────────────────────────

MASK = 0xFF


def _pstr(s: str) -> bytes:
    return struct.pack("<H", len(s)) + s.encode("latin-1") + b"\0"


def proc_record(mod: int, name: str, dump: bytes, relocs: bytes, kind: bytes = b"C") -> bytes:
    assert len(dump) == len(relocs)
    body = struct.pack("<HH", mod, len(name)) + name.encode() + b"\0"
    body += bytes([0]) + kind + b"F" + bytes([1]) + struct.pack("<i", 0) + _pstr("")
    fix = b"A" + struct.pack("<I", 1) + _pstr("Other.Name")
    body += struct.pack("<III", 8 + 2 * len(dump) + len(fix), len(dump), 1) + dump + relocs + fix
    body += struct.pack("<IH", 2, 0)                                   # no arguments
    return body


def build_kb(path: Path, modules: list[str], procs: list[tuple[int, str, bytes, bytes]], kind: bytes = b"C") -> None:
    out = bytearray(b"IDR Knowledge Base File".ljust(24, b"\0"))
    out += struct.pack("<?iI", False, 0, 0xFFFFFFFF) + b"synthetic".ljust(256, b"\0") + struct.pack("<I", 2)
    tables: list[list[tuple[int, int]]] = []
    mods = []
    for i, m in enumerate(modules):
        off = len(out)
        out += struct.pack("<HH", i, len(m)) + m.encode() + b"\0" + _pstr(m + ".pas") + struct.pack("<H", 0)
        mods.append((off, len(out) - off))
    tables.append(mods)
    tables += [[], [], [], []]                                         # consts, types, vars, resource strings
    pr = []
    for mod, name, dump, relocs in procs:
        off = len(out)
        out += proc_record(mod, name, dump, relocs, kind)
        pr.append((off, len(out) - off))
    tables.append(pr)
    sect = len(out)
    for ents in tables:
        out += struct.pack("<ii", len(ents), 0)
        for i, (off, size) in enumerate(ents):
            out += struct.pack("<IIii", off, size, i, i)
    out += struct.pack("<i", sect)
    path.write_bytes(bytes(out))


def body(seed: int, n: int = 24) -> bytes:
    """Prologue plus pseudo-random but fixed bytes: the code of one routine with two address slots."""
    b = bytearray(b"\x55\x8b\xec\x83\xc4\xf0\x53\x56")
    x = seed * 2654435761 & 0xFFFFFFFF
    while len(b) < n:
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        b.append(0x40 + (x >> 16) % 0x30)
    b[10:14] = b"\0\0\0\0"                                           # an absolute address
    b[18:22] = b"\0\0\0\0"                                           # a relative call
    return bytes(b)


def masks(n: int, slots=((10, 14), (18, 22))) -> bytes:
    m = bytearray(n)
    for a, b in slots:
        m[a:b] = bytes([MASK]) * (b - a)
    return bytes(m)


def relocated(raw: bytes, v1: int, v2: int) -> bytes:
    b = bytearray(raw)
    b[10:14] = struct.pack("<I", v1)
    b[18:22] = struct.pack("<I", v2)
    return bytes(b)


# ── files and the reader ───────────────────────────────────────────────────

def test_kb_files_layout_and_preference(tmp_path):
    for rel in ("kb2010.bin", "syskb2010.bin", "syskb2012.bin", "x64/syskb2012.bin", "x64/syskb2014.bin", "x86/kb7.bin",
                "notes.txt", "kbx.bin"):
        p = tmp_path / rel
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(b"\0" * 500)
    (tmp_path / "x86" / "kb7.bin").write_bytes(b"\0" * 10)                       # too small to be a knowledge base
    x86 = idr.kb_files(tmp_path, 4)
    assert [f.label for f in x86] == ["kb2010", "syskb2012"]                    # kb wins over syskb of the same year
    assert x86[0].full and not x86[1].full
    x64 = idr.kb_files(tmp_path, 8)
    assert [f.label for f in x64] == ["syskb2012", "syskb2014"] and x64[0].path.parent.name == "x64"
    assert idr.kb_files(None, 4) == [] and idr.kb_files(tmp_path / "missing", 4) == []
    assert idr.kb_signature([]) == "none" and idr.kb_signature(x86) != idr.kb_signature(x64)


def test_read_kb_keeps_code_procs_with_enough_fixed_bytes(tmp_path):
    big = body(1)
    tiny = b"\x55\x8b\xec\x5d\xc3\x90\x90\x90\x90\x90\x90\x90"
    thunk = b"\xff\x25\0\0\0\0"
    build_kb(tmp_path / "kb2010.bin", ["System", "SysUtils"], [
        (0, "@Foo", big, masks(len(big))),
        (1, "Tiny", tiny, bytes(len(tiny))),                                   # 12 fixed bytes: kept
        (1, "Thunk", thunk, bytes([0, 0, MASK, MASK, MASK, MASK])),            # 2 fixed bytes: dropped
        (0, "Data", big, masks(len(big))),
    ])
    kb = idr.read_kb(tmp_path / "kb2010.bin")
    assert kb.total == 4 and kb.skipped == 1
    assert [p.name for p in kb.procs] == ["System.@Foo", "SysUtils.Tiny", "System.Data"]
    foo = kb.procs[0]
    assert foo.size == len(big) and foo.keep == int.from_bytes(bytes(0 if m else 255 for m in masks(len(big))), "little")


def test_data_dumps_are_skipped(tmp_path):
    big = body(1)
    build_kb(tmp_path / "kb2010.bin", ["System"], [(0, "Tab", big, masks(len(big)))], kind=b"D")
    assert idr.read_kb(tmp_path / "kb2010.bin").procs == []


@pytest.mark.parametrize("cut", ["short", "signature", "version", "table"])
def test_damaged_files_raise_kb_error(tmp_path, cut):
    big = body(1)
    p = tmp_path / "kb2010.bin"
    build_kb(p, ["System"], [(0, "@Foo", big, masks(len(big)))])
    raw = bytearray(p.read_bytes())
    if cut == "short":
        raw = raw[:100]
    elif cut == "signature":
        raw[:3] = b"XXX"
    elif cut == "version":
        raw[289:293] = struct.pack("<I", 1)
    else:
        raw[-4:] = struct.pack("<i", 5)
    p.write_bytes(bytes(raw))
    with pytest.raises(idr.KbError):
        idr.read_kb(p)
    with pytest.raises(idr.KbError):
        idr.read_kb(tmp_path / "missing.bin")


# ── matching ───────────────────────────────────────────────────────────────

def make_image(tmp_path, blobs: dict[str, bytes], psize: int = 4, data: bytes = b""):
    """A synthetic PE with each blob at its own 64-byte slot of the code section; returns (path, {name: va})."""
    pe = Pe(psize)
    where = {}
    for i, (name, raw) in enumerate(blobs.items()):
        off = i * 64
        pe.text[off:off + len(raw)] = raw
        where[name] = pe.base + 0x1000 + off
    pe.data[0:len(data)] = data
    pe.write(tmp_path / "app.exe")
    return tmp_path / "app.exe", where


def test_match_ignores_masked_bytes_and_padding(tmp_path):
    raw = body(1)
    build_kb(tmp_path / "kb2010.bin", ["System"], [
        (0, "@Foo", raw, masks(len(raw))),
        (0, "@FooPadded", raw + b"\x90\x90", masks(len(raw)) + b"\0\0"),
    ])
    other = bytearray(relocated(raw, 0x4a5b6c7d, 0x1234))
    other[12] ^= 0xFF                                                          # inside the masked slot
    wrong = bytearray(raw)
    wrong[5] ^= 0x01                                                           # an unmasked byte
    path, at = make_image(tmp_path, {"same": relocated(raw, 0x401234, 0xFFFF0000), "slot": bytes(other),
                                     "wrong": bytes(wrong), "padded": relocated(raw, 1, 2) + b"\x90\x90"})
    img = Image.from_pe(path)
    kb = idr.read_kb(tmp_path / "kb2010.bin")
    funcs = [(at[k], len(raw)) for k in ("same", "slot", "wrong", "padded")]
    got = idr.match_all(kb, img, funcs)
    assert got[at["same"]] == ["System.@Foo"] and got[at["slot"]] == ["System.@Foo"]
    assert at["wrong"] not in got
    assert got[at["padded"]] == ["System.@Foo", "System.@FooPadded"]
    # Ghidra leaves up to 15 padding bytes out of the function; a function much shorter than the proc is no match
    assert idr.match_all(kb, img, [(at["same"], len(raw) - 1)]) == {at["same"]: ["System.@Foo"]}
    short = idr.match_all(kb, img, [(at["padded"], len(raw) - 40)])
    assert short == {}


def test_names_are_ranked_and_common_shapes_dropped(tmp_path):
    raw = body(2)
    procs = [(0, "Zeta.Plain", raw, masks(len(raw))), (1, "TList<System.string>.Plain", raw, masks(len(raw))),
             (0, "A.Plain", raw, masks(len(raw)))]
    wrap = body(3)
    procs.append((0, "Wrapper", wrap, masks(len(wrap))))
    build_kb(tmp_path / "kb2010.bin", ["System", "Data.Bind"], procs)
    blobs = {"one": relocated(raw, 1, 2)}
    blobs.update({f"w{i}": relocated(wrap, i, i) for i in range(idr.MAX_COPIES + 1)})
    path, at = make_image(tmp_path, blobs)
    img = Image.from_pe(path)
    kb = idr.read_kb(tmp_path / "kb2010.bin")
    got = idr.match_all(kb, img, [(va, None) for va in at.values()])
    assert got[at["one"]] == ["System.A.Plain", "System.Zeta.Plain", "Data.Bind.TList<System.string>.Plain"]
    assert not any(at[f"w{i}"] in got for i in range(idr.MAX_COPIES + 1))      # one shape in too many places


def test_generic_templates_and_long_shapes_may_match_many_functions(tmp_path, monkeypatch):
    monkeypatch.setattr(idr, "LONG_SHAPE", 16)                  # 16 compared bytes here, 10 for the short proc
    gen, lng, short = body(4), body(5), body(6)
    tiny = masks(len(short), ((2, 8), (10, 14), (18, 22)))
    procs = [(0, "TList<T>.Add", gen, masks(len(gen))), (0, "Long", lng, masks(len(lng))),
             (0, "Short", short, tiny), (0, "TList<T>.Tiny", body(7), tiny)]
    build_kb(tmp_path / "kb2010.bin", ["System"], procs)
    many = idr.MAX_COPIES + 3
    blobs = {f"{k}{i}": relocated(raw, i, i) for k, raw in (("g", gen), ("l", lng), ("s", short), ("t", body(7))) for i in range(many)}
    path, at = make_image(tmp_path, blobs)
    img = Image.from_pe(path)
    got = idr.match_all(idr.read_kb(tmp_path / "kb2010.bin"), img, [(va, None) for va in at.values()])
    assert all(got[at[f"g{i}"]] == ["System.TList<T>.Add"] for i in range(many))
    assert all(got[at[f"l{i}"]] == ["System.Long"] for i in range(many))
    assert not any(at[f"s{i}"] in got for i in range(many))                       # a short plain wrapper stays dropped
    assert not any(at[f"t{i}"] in got for i in range(many))                       # so does a generic with 10 bytes


def test_pick_chooses_the_knowledge_base_with_most_matches(tmp_path):
    a, b, c = body(10), body(11), body(12)
    build_kb(tmp_path / "kb2009.bin", ["System"], [(0, "OnlyA", a, masks(len(a)))])
    build_kb(tmp_path / "kb2010.bin", ["System"], [(0, "OnlyA", a, masks(len(a))), (0, "OnlyB", b, masks(len(b)))])
    build_kb(tmp_path / "kb2012.bin", ["System"], [(0, "OnlyC", c, masks(len(c)))])
    path, at = make_image(tmp_path, {"a": relocated(a, 1, 2), "b": relocated(b, 3, 4)})
    img = Image.from_pe(path)
    files = idr.kb_files(tmp_path, 4)
    label, hits, notes = idr._pick(files, img, [(va, None) for va in at.values()])
    assert label == "kb2010" and hits == {at["a"]: ["System.OnlyA"], at["b"]: ["System.OnlyB"]}
    assert len(notes) == 3


def test_compiler_version_selects_the_knowledge_base(tmp_path):
    a, b = body(40), body(41)
    build_kb(tmp_path / "kb2009.bin", ["System"], [(0, "OnlyA", a, masks(len(a)))])
    build_kb(tmp_path / "kb2010.bin", ["System"], [(0, "OnlyA", a, masks(len(a))), (0, "OnlyB", b, masks(len(b)))])
    blobs = {"a": relocated(a, 1, 2), "b": relocated(b, 3, 4)}
    path, at = make_image(tmp_path, blobs, data=b"Embarcadero Delphi for Win32 compiler version 20.0 (12.0.3420.21218)\0")
    img = Image.from_pe(path)
    assert idr.compiler_version(img) == 20
    label, hits, notes = idr._pick(idr.kb_files(tmp_path, 4), img, [(va, None) for va in at.values()])
    assert label == "kb2009" and list(hits) == [at["a"]] and notes == ["compiler 20"]      # the version wins over the count
    path, at = make_image(tmp_path, blobs, data=b"CodeGear Delphi for Win32 compiler version 33.0 (x)\0")
    img = Image.from_pe(path)
    label, hits, notes = idr._pick(idr.kb_files(tmp_path, 4), img, [(va, None) for va in at.values()])
    assert label == "kb2010" and notes[0] == "compiler 33, no knowledge base for it"         # none fits: most matches
    path, at = make_image(tmp_path, blobs)
    assert idr.compiler_version(Image.from_pe(path)) is None


# ── storage, hints, runtime ────────────────────────────────────────────────

@pytest.fixture
def proj(tmp_path):
    ctx = make_ctx(tmp_path)
    ix = ctx.indexer
    st = ix.store("proj")
    ix.current = "proj"
    art = ix.paths("proj", create=True).artifacts
    art.mkdir(parents=True, exist_ok=True)
    sha = "cd" * 32
    raw = body(20)
    pe = Pe(4)
    pe.text[0:len(raw)] = relocated(raw, 0x401000, 0x10)
    pe.text[64:64 + len(raw)] = relocated(raw, 0x402000, 0x20)               # named by the agent: left alone
    pe.text[128:128 + len(raw)] = body(21)                                    # program code
    pe.write(art / sha)
    kbdir = tmp_path / "kb"
    kbdir.mkdir()
    build_kb(kbdir / "kb2010.bin", ["System"], [(0, "@RtlThing", raw, masks(len(raw)))])
    bid = st.upsert_binary(sha, "app.exe", format="pe32", arch="x86", pointer_size=4, image_base=0x400000,
                           toolchain="delphi", analysis_profile="p")
    ix.set_status(st, bid, "ready")
    base = pe.base + 0x1000
    st.insert_functions(bid, [
        {"entry": base, "name": f"FUN_{base:08x}", "name_state": "auto", "size": len(raw)},
        {"entry": base + 64, "name": "MyRename", "name_state": "user", "size": len(raw)},
        {"entry": base + 128, "name": f"FUN_{base + 128:08x}", "name_state": "auto", "size": len(raw)},
    ])
    return ctx, st, bid, art / sha, kbdir, base


def test_ensure_stores_hits_and_info(proj):
    ctx, st, bid, art, kbdir, base = proj
    b = st.get_binary_by_id(bid)
    assert idr.stale(st, b, kbdir)
    assert idr.ensure(st, b, art, kbdir)
    assert st.get_meta(f"idr_version:{bid}").startswith(f"{idr.IDR_VERSION}:") and not idr.stale(st, b, kbdir)
    assert not idr.ensure(st, b, art, kbdir)                                    # nothing changed
    assert idr.hits(st, bid) == {base: "System.@RtlThing"}                      # not the user-named one, not program code
    assert idr.hint_for(st, bid, base) == ["idr: System.@RtlThing"] and idr.hint_for(st, bid, base + 128) == []
    assert idr.info(st, bid).startswith("kb2010: 1 of 2 unnamed functions named")
    assert "idr: System.@RtlThing" in delphi.hints_for(st, bid, base)
    assert base in delphi.runtime_addrs(st, bid)


def test_stale_follows_files_functions_and_configuration(proj, tmp_path):
    ctx, st, bid, art, kbdir, base = proj
    b = st.get_binary_by_id(bid)
    assert idr.ensure(st, b, art, kbdir)
    raw = body(22)
    build_kb(kbdir / "kb2012.bin", ["System"], [(0, "@Other", raw, masks(len(raw)))])       # another file appears
    assert idr.stale(st, b, kbdir) and idr.ensure(st, b, art, kbdir) and not idr.stale(st, b, kbdir)
    st.insert_functions(bid, [{"entry": base + 192, "name": "FUN_00401ff0", "name_state": "auto", "size": 4}])
    assert idr.stale(st, b, kbdir)                                              # one more unnamed function
    assert idr.ensure(st, b, art, kbdir)
    assert idr.stale(st, b, None)                                               # configuration removed: result cleared
    assert idr.ensure(st, b, art, None) and idr.hits(st, bid) == {}
    assert idr.info(st, bid) == "no knowledge base configured" and not idr.stale(st, b, None)


def test_unconfigured_projects_are_left_alone(proj):
    ctx, st, bid, art, kbdir, base = proj
    b = st.get_binary_by_id(bid)
    assert not idr.stale(st, b, None) and not idr.ensure(st, b, art, None)
    assert st.get_meta(f"idr_version:{bid}") is None
    assert delphi.hints_for(st, bid, base) == []


def test_damaged_file_is_reported_and_other_toolchains_skipped(proj, tmp_path):
    ctx, st, bid, art, kbdir, base = proj
    b = st.get_binary_by_id(bid)
    (kbdir / "kb2010.bin").write_bytes(b"IDR Knowledge Base File" + b"\0" * 400)
    assert idr.ensure(st, b, art, kbdir)                                        # never raises
    assert idr.hits(st, bid) == {} and "kb2010:" in idr.info(st, bid)
    other = st.upsert_binary("ef" * 32, "m.dll", format="pe32", toolchain="msvc")
    assert not idr.ensure(st, st.get_binary_by_id(other), art, kbdir)
    assert st.get_meta(f"idr_version:{other}") is None


def test_delphi_ensure_passes_the_folder(proj):
    ctx, st, bid, art, kbdir, base = proj
    b = st.get_binary_by_id(bid)
    assert delphi.ensure(st, b, art, kbdir)
    assert idr.hits(st, bid) == {base: "System.@RtlThing"}
    assert delphi.ensure_project(st, art.parent, kbdir) == 0                    # status:<id> is not set here


def test_sixty_four_bit_files_come_from_x64(tmp_path):
    raw = body(30)
    (tmp_path / "x64").mkdir()
    build_kb(tmp_path / "x64" / "syskb2013.bin", ["System"], [(0, "@Wide", raw, masks(len(raw)))])
    build_kb(tmp_path / "syskb2013.bin", ["System"], [(0, "@Narrow", raw, masks(len(raw)))])
    path, at = make_image(tmp_path, {"f": relocated(raw, 5, 6)}, psize=8)
    img = Image.from_pe(path)
    assert img.psize == 8
    f64 = idr.kb_files(tmp_path, 8)
    assert [f.path.parent.name for f in f64] == ["x64"]
    assert idr.match_all(idr.load_kb(f64[0]), img, [(at["f"], None)]) == {at["f"]: ["System.@Wide"]}


# ── configuration ──────────────────────────────────────────────────────────

def test_config_key(tmp_path):
    cfg = resolve(parse_jsonc(default_config_text()), "dirty", None)
    assert cfg.idr_kb_dir is None
    merged = parse_jsonc(default_config_text())
    merged["idr_kb_dir"] = str(tmp_path / "kb")
    merged["ghidra_dir"] = str(tmp_path / "g")
    assert resolve(merged, "dirty", None).idr_kb_dir == tmp_path / "kb"
