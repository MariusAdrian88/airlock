"""Light scan: grouping, root choice, options, rendering (invented vendors only)."""
from __future__ import annotations

import shutil
import struct
from pathlib import Path

import pytest

from airlock.server import scan as S
from airlock.server.scan import ScannedFile, assign_groups, normalise_vendor, scan_program


def make_pe(path: Path, dll: bool = False, code: int = 0x400, bits: int = 32, pad: int = 0) -> None:
    """Smallest PE pefile parses: one executable section, no directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    plus = bits == 64
    opt_size = 0xF0 if plus else 0xE0
    chars = 0x2022 if dll else 0x0022
    coff = struct.pack("<HHIIIHH", 0x8664 if plus else 0x14C, 1, 0, 0, 0, opt_size, chars)
    opt = struct.pack("<HBBIIIII", 0x20B if plus else 0x10B, 0, 0, code, 0, 0, 0x1000, 0x1000)
    opt += struct.pack("<Q", 0x400000) if plus else struct.pack("<II", 0x2000, 0x400000)
    opt += struct.pack("<II", 0x1000, 0x200)                         # alignments
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)                  # versions
    opt += struct.pack("<IIII", 0, 0x2000, 0x200, 0)                 # win32ver, image, hdrs, csum
    opt += struct.pack("<HH", 3, 0)                                  # subsystem, dll chars
    opt += struct.pack("<QQQQ" if plus else "<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16) + b"\x00" * (16 * 8)
    assert len(opt) == opt_size
    sect = struct.pack("<8sIIIIIIHHI", b".text", code, 0x1000, code, 0x200, 0, 0, 0, 0,
                       0x60000020)
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    hdr = (dos + b"PE\x00\x00" + coff + opt + sect).ljust(0x200, b"\x00")
    path.write_bytes(hdr + b"\x90" * code + b"\x00" * pad)


def sf(rel, *, dll=True, code=1000, company=None, imports=()):
    return ScannedFile(rel, "pe", "", code + 512, code, 32, dll, False, True,
                       company, None, tuple(imports), 0)


# --- vendor / names -------------------------------------------------------------

def test_normalise_vendor():
    assert normalise_vendor("Acme Widgets, Inc.") == normalise_vendor("ACME WIDGETS INC")
    assert normalise_vendor("Acme Widgets Corp. (c) 2019") == "acme widgets"
    assert normalise_vendor("  ") is None and normalise_vendor(None) is None
    assert normalise_vendor("Foo GmbH") != normalise_vendor("Bar GmbH")


def test_runtime_names():
    for n in ("MSVCR100.dll", "mfc42u.dll", "api-ms-win-crt-heap-l1-1-0.dll", "VCRUNTIME140.dll",
              "ucrtbase.dll", "msvbvm60.dll", "mscoree.dll", "concrt140.dll", "vcomp140.dll",
              "msvcp140.dll", "msvcm90.dll", "atl100.dll"):
        assert S.is_runtime_name(n), n
    assert not S.is_runtime_name("kernel32.dll")


# --- grouping on features -------------------------------------------------------

def test_groups_all_kinds():
    files = [
        sf("app.exe", dll=False, company="Acme Widgets Inc",
           imports=["core.dll", "noco.dll", "foreign.dll", "msvcr90.dll"]),
        sf("core.dll", company="ACME WIDGETS, Inc.", imports=["deep.dll"]),
        sf("deep.dll", company="Acme Widgets"),
        sf("noco.dll", company=None),                       # imported by core, no vendor -> core
        sf("orphan.dll", company=None),                     # not imported, no vendor -> third_party
        sf("foreign.dll", company="Zeta Labs"),             # imported, other vendor -> third_party
        sf("plugins/p1.ocx", company="Acme Widgets Corp"),  # folder scan only -> own_plugin
        sf("tools/other.exe", dll=False, code=5000, company="Acme Widgets"),
        sf("vendor/z.dll", company="Zeta Labs"),
        sf("msvcr90.dll", company="Microsoft Corporation"),
        sf("api-ms-win-core-x.dll"),
    ]
    g = {f.rel_path: f.group for f in assign_groups(files, "app.exe")}
    assert g == {
        "app.exe": "core", "core.dll": "core", "deep.dll": "core", "noco.dll": "core",
        "orphan.dll": "third_party", "foreign.dll": "third_party",
        "plugins/p1.ocx": "own_plugin", "tools/other.exe": "separate_exe",
        "vendor/z.dll": "third_party", "msvcr90.dll": "runtime", "api-ms-win-core-x.dll": "runtime",
    }


def test_vendor_token_match():
    v = normalise_vendor
    root = v("Acme")
    assert S.vendor_matches(root, v("Acme, Partner 2012"))
    assert S.vendor_matches(root, v("Partner & Acme Software"))
    assert S.vendor_matches(v("Acme Widgets"), v("Widgets Unlimited"))      # shared token len>=4
    assert not S.vendor_matches(root, v("Zeta Labs"))
    assert not S.vendor_matches(v("Foo Bar"), v("Bar Baz Co"))             # 'bar' too short
    assert not S.vendor_matches(None, v("Acme")) and not S.vendor_matches(root, None)
    files = [sf("a.exe", dll=False, company="Acme"), sf("p.dll", company="Acme, Partner 2012")]
    assert {f.rel_path: f.group for f in assign_groups(files, "a.exe")}["p.dll"] == "own_plugin"


def test_root_skips_installers_and_drivers(tmp_path):
    d = tmp_path / "main_app"
    make_pe(d / "main.exe", code=0x1000)
    make_pe(d / "setup.exe", code=0x100, pad=0x20000)        # huge overlay, tiny code
    make_pe(d / "vcredist_x86.exe", code=0x8000)
    make_pe(d / "drv.sys", code=0x9000)
    make_pe(d / "tool_a.exe", code=0x800)
    make_pe(d / "tool_b.exe", code=0x400)
    make_pe(d / "tool_c.exe", code=0x200)
    r = scan_program(d)
    assert r.root_exe == "main.exe"
    assert [p for p, _ in r.root_candidates] == ["tool_a.exe", "tool_b.exe"]
    assert "others: tool_a.exe" in S.render_scan(r)[0] and "root_exe=" in S.render_scan(r)[0]
    f = sf("x.exe", dll=False)
    assert S.is_root_candidate(f)
    import dataclasses
    assert not S.is_root_candidate(dataclasses.replace(f, description="Product Setup Wizard"))
    assert not S.is_root_candidate(dataclasses.replace(f, subsystem=1))


def _pe(rel, *, dll=False, code=1000, company=None, product=None):
    return ScannedFile(rel, "pe", "", code + 512, code, 32, dll, False, True,
                       company, product, (), 0)


def test_root_scoring_beats_bigger_companion():
    pes = [_pe("zorbit.exe", code=1000, company="Zorbit Labs", product="Zorbit Suite"),
           _pe("helper.exe", code=9000),                       # no version info, more code
           _pe("zorbit_core.dll", dll=True, company="Zorbit Labs, Inc."),
           _pe("ext.dll", dll=True, company="Zorbit Labs 2012")]
    pool = [pes[0], pes[1]]
    rank = S._score_roots(pool, pes, "Zorbit")
    assert rank[0][0] == "zorbit.exe"
    assert rank[0][1] - rank[1][1] >= 2
    assert "name" in rank[0][2] and "vendor" in rank[0][2]
    assert rank[1][2] == "largest code"


def test_root_ambiguous_render(tmp_path):
    d = tmp_path / "prog"
    make_pe(d / "alpha.exe", code=0x2000)
    make_pe(d / "beta.exe", code=0x1000)
    r = scan_program(d)
    assert r.root_ambiguous and r.root_exe == "alpha.exe"
    lines = S.render_scan(r)
    assert "root unclear: alpha.exe (score 1: largest code), beta.exe (score 0: none)" in lines[0]
    assert "root_exe= picks one" in lines[0]
    assert lines[-1].startswith("recommended: ") and "after the root_exe choice" in lines[-1]
    named = scan_program(d, root_exe="beta.exe")
    assert not named.root_ambiguous and named.root_exe == "beta.exe"


def test_no_root_vendor_has_no_own_plugins():
    files = [sf("a.exe", dll=False, imports=["b.dll"]), sf("b.dll", company="Q Co"),
             sf("c.dll", company="Q Co")]
    g = {f.rel_path: f.group for f in assign_groups(files, "a.exe")}
    assert g["b.dll"] == "third_party" and g["c.dll"] == "third_party"   # vendored imports never core
    files = [sf("a.exe", dll=False, imports=["b.dll"]), sf("b.dll")]
    assert {f.rel_path: f.group for f in assign_groups(files, "a.exe")}["b.dll"] == "core"


# --- real scans of synthetic folders -------------------------------------------

@pytest.fixture
def prog(tmp_path):
    d = tmp_path / "prog"
    make_pe(d / "main.exe", code=0x6000, pad=0x8000)          # biggest file
    make_pe(d / "helper.exe", code=0x4000)                   # more code, smaller file
    make_pe(d / "lib.dll", dll=True, code=0x1000, bits=64)
    make_pe(d / "plugins" / "p.dll", dll=True, code=0x600)
    make_pe(d / "msvcr100.dll", dll=True, code=0x2000)
    (d / "bad.dll").write_bytes(b"MZ" + b"\x01" * 200)
    (d / "data").mkdir()
    for i in range(5):
        (d / "data" / f"f{i}.dat").write_bytes(b"x" * 100)
    (d / "readme.txt").write_text("hello world " * 10)
    return d


def test_scan_synthetic(prog):
    r = scan_program(prog)
    byp = {f.rel_path: f for f in r.files}
    assert r.root_exe == "main.exe"
    assert r.root_reason.startswith("best score") and r.root_reason.endswith("in top folder")
    assert byp["bad.dll"].group == "unreadable"
    assert byp["msvcr100.dll"].group == "runtime"
    assert byp["lib.dll"].bits == 64 and byp["lib.dll"].is_dll
    assert byp["lib.dll"].code_size == 0x1000
    assert byp["data/f0.dat"].kind == "data" and byp["data/f0.dat"].code_size == 0
    assert r.data_summary[0][:2] == (".dat", 5)
    assert {e for e, _, _ in r.data_summary} == {".dat", ".txt"}
    assert byp["helper.exe"].group == "separate_exe"
    assert byp["plugins/p.dll"].group == "third_party"       # no vendor, not imported
    assert [o.key for o in r.options] == ["A", "C", "D"]     # B omitted, letters stable
    assert r.recommended == "A"


def test_root_named_and_file_path(prog):
    r = scan_program(prog, root_exe="helper.exe")
    assert r.root_exe == "helper.exe" and r.root_reason == "named by user"
    r2 = scan_program(prog / "helper.exe")
    assert r2.root == prog and r2.root_exe == "helper.exe" and r2.root_reason == "named by user"
    r3 = scan_program(prog, root_exe="nope.exe")
    assert r3.root_exe is None and r3.options == () and r3.recommended == ""


def test_option_math_and_cumulation(prog):
    r = scan_program(prog, root_exe="main.exe", s_per_code_mb=100.0)
    a, c, d = r.options
    assert a.code_size == 0x6000 and a.groups == ("core",)
    assert {f.rel_path for f in a.files} == {"main.exe"}
    assert {f.rel_path for f in c.files} == {"main.exe", "lib.dll", "plugins/p.dll"}
    assert c.code_size == 0x6000 + 0x1000 + 0x600
    assert {f.rel_path for f in d.files} == {"main.exe", "lib.dll", "plugins/p.dll", "helper.exe"}
    n_pe = lambda o: sum(1 for f in o.files if f.kind == "pe")   # noqa: E731
    assert a.est_seconds == pytest.approx(6.0 + 0x6000 / (1024 * 1024) * 100.0)
    assert d.est_seconds == pytest.approx(n_pe(d) * 6.0 + d.code_size / (1024 * 1024) * 100.0)
    r2 = scan_program(prog, root_exe="main.exe", s_per_code_mb=100.0, overhead_s=0.0)
    assert r2.options[0].est_seconds == pytest.approx(0x6000 / (1024 * 1024) * 100.0)
    assert not any(f.group == "runtime" for o in r.options for f in o.files)


def test_b_present_when_own_plugins(monkeypatch, prog):
    real = S._read_pe

    def fake(path, rel, size):
        f = real(path, rel, size)
        if f.group != "unreadable":
            f = ScannedFile(**{**f.__dict__, "company": "Invented Systems Ltd"})
        return f
    monkeypatch.setattr(S, "_read_pe", fake)
    r = scan_program(prog, root_exe="main.exe")
    assert [o.key for o in r.options] == ["A", "B", "D"]     # no third party left: C omitted
    assert r.recommended == "B"
    byp = {f.rel_path: f for f in r.files}
    assert byp["plugins/p.dll"].group == "own_plugin" and byp["lib.dll"].group == "own_plugin"
    lines = S.render_scan(r)
    assert lines[-1].startswith("recommended: B")
    assert any(l.startswith("C. + third party | omitted") for l in lines)


def test_render(prog):
    lines = S.render_scan(scan_program(prog, root_exe="main.exe"))
    text = "\n".join(lines)
    assert lines[0].startswith(str(prog)) and "main.exe (named by user)" in lines[0]
    assert any(l.startswith("A. Core | 1 files |") and "~" in l for l in lines)
    assert any(l.startswith("B. Core + own plugins | omitted: no own plugins") for l in lines)
    assert "not analysed by default" in text
    assert any(l.startswith("data: .dat 5") for l in lines)
    assert lines[-1].startswith("recommended: A")


def test_render_length_cap(tmp_path):
    d = tmp_path / "big"
    make_pe(d / "app.exe")
    for i in range(150):
        make_pe(d / "p" / f"plugin_with_a_long_name_{i}.dll", dll=True, code=0x200 + i)
    (d / "d").mkdir()
    for i in range(300):
        (d / "d" / f"x{i}.e{i % 40}").write_bytes(b"1" * 10)
    r = scan_program(d)
    lines = S.render_scan(r)
    assert len(r.files) == 451
    assert len(lines) < 14
    assert len(" ".join(lines)) < 2400          # ~600 tokens
    assert "+" in " ".join(lines) and "more" in " ".join(lines)


def test_real_system_pes(tmp_path):
    sysdir = Path(r"C:\Windows\System32")
    names = ["notepad.exe", "kernel32.dll", "user32.dll", "shell32.dll"]
    if not all((sysdir / n).exists() for n in names):
        pytest.skip("system files missing")
    d = tmp_path / "real"
    d.mkdir()
    for n in names:
        shutil.copy(sysdir / n, d / n)
    r = scan_program(d)
    byp = {f.rel_path: f for f in r.files}
    assert r.root_exe == "notepad.exe"
    assert all(f.kind == "pe" and f.group != "unreadable" for f in r.files)
    assert byp["kernel32.dll"].is_dll and byp["kernel32.dll"].exports > 100
    assert byp["notepad.exe"].code_size > 0 and byp["notepad.exe"].bits == 64
    assert "microsoft" in (byp["notepad.exe"].company or "").lower()
    assert byp["notepad.exe"].imports and r.system_dlls


def _pe_with_sections(path: Path, text: bytes, data: bytes, plus: bool = False) -> Path:
    """Minimal PE with a code section at RVA 0x1000 and a data section at 0x2000."""
    opt_size = 0xF0 if plus else 0xE0
    base = 0x140000000 if plus else 0x400000
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    fh = struct.pack("<HHIIIHH", 0x8664 if plus else 0x14C, 2, 0, 0, 0, opt_size, 0x22)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B if plus else 0x10B)
    if plus:
        struct.pack_into("<Q", opt, 24, base)
    else:
        struct.pack_into("<I", opt, 28, base)
    struct.pack_into("<I", opt, 32, 0x1000)
    struct.pack_into("<I", opt, 36, 0x200)
    struct.pack_into("<I", opt, 56, 0x3000)
    struct.pack_into("<I", opt, 60, 0x200)
    struct.pack_into("<I", opt, 108 if plus else 92, 16)
    text = text.ljust(0x200, b"\x90")
    data = data.ljust(0x200, b"\0")

    def sec(name, va, raw_off, chars):
        return struct.pack("<8sIIIIIIHHI", name, 0x200, va, 0x200, raw_off, 0, 0, 0, 0, chars)

    hdr = bytes(dos) + b"PE\0\0" + fh + bytes(opt)
    hdr += sec(b".text", 0x1000, 0x400, 0x60000020) + sec(b".data", 0x2000, 0x600, 0xC0000040)
    path.write_bytes(hdr.ljust(0x400, b"\0") + text + data)
    return path


@pytest.mark.parametrize("plus", [False, True])
def test_estimate_functions_counts_distinct_code_targets(tmp_path, plus):
    import pefile
    base = 0x140000000 if plus else 0x400000
    # call at 0x1000 -> 0x1100, call at 0x1010 -> 0x1100 (same), call at 0x1020 -> 0x1180,
    # call to a target outside the code (0x2000) is not a function start
    def call(at, target):
        return b"\xe8" + struct.pack("<i", target - (at + 5))
    text = bytearray(b"\x90" * 0x200)
    text[0x00:0x05] = call(0x1000, 0x1100)
    text[0x10:0x15] = call(0x1010, 0x1100)
    text[0x20:0x25] = call(0x1020, 0x1180)
    text[0x30:0x35] = call(0x1030, 0x2000)
    # data: two pointers into code (one new, one a repeat) and one outside
    fmt = "<Q" if plus else "<I"
    data = b"".join(struct.pack(fmt, v) for v in (base + 0x1140, base + 0x1100, base + 0x9000))
    p = _pe_with_sections(tmp_path / "t.dll", bytes(text), data, plus)
    pe = pefile.PE(str(p), fast_load=True)
    try:
        assert S.estimate_functions(pe) == 3      # 0x1100, 0x1180, 0x1140
    finally:
        pe.close()
    f = scan_program(tmp_path, root_exe="t.dll").files[0]
    assert f.est_funcs == 3 and f.code_size == 0x200


def test_estimate_functions_empty_pe_is_zero(tmp_path):
    from test_projects import make_pe
    f = [x for x in scan_program(make_pe(tmp_path / "e.exe").parent, root_exe="e.exe").files][0]
    assert f.est_funcs == 0


def test_option_time_uses_function_estimate():
    from airlock.server.estimate import FUNCS_PER_MB
    dense = ScannedFile("a.exe", "pe", "core", 2000, 1 << 20, 32, False, False, True,
                        None, None, (), 0, est_funcs=int(2 * FUNCS_PER_MB))
    plain = ScannedFile("b.dll", "pe", "core", 2000, 1 << 20, 32, True, False, True,
                        None, None, (), 0)
    (opt,) = S._build_options([dense, plain], 100.0, 10.0)
    assert opt.est_seconds == pytest.approx(2 * 10.0 + (2.0 + 1.0) * 100.0)
