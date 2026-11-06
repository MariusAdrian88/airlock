"""How .NET files enter a project: single-file bundles, apphosts, ReadyToRun, NativeAOT, the managed
entry point in ``outline`` and Unix module names (P1, P8, P15, P18, P20)."""
from __future__ import annotations

import hashlib
import struct
import subprocess
import zlib
from pathlib import Path

import pefile
import pytest

from airlock.projects import (
    BUNDLE_SIG, ProjectPaths, artifact_from_scan, bundle_entry_name, bundle_manifest, detect,
    project_paths, read_bundle_entry,
)
from airlock.server import dotnet as dn
from airlock.server.scan import render_scan, scan_program
from airlock.server.tools import core
from test_dotnet import CSC, add_managed, make_dn_ctx
from test_scan import _pe_with_sections

APP = "class P { static void Main() { System.Console.WriteLine(1); } }"
LIB = "public class Util { public static int F(int x) { return x + 1; } }"


def _csc(d: Path, name: str, src: str, target: str, refs: tuple[str, ...] = ()) -> Path:
    if not CSC.is_file():
        pytest.skip("needs the .NET Framework C# compiler")
    (d / (name + ".cs")).write_text(src, encoding="utf-8")
    cmd = [str(CSC), "/nologo", f"/target:{target}", f"/out:{name}", name + ".cs",
           *[f"/r:{r}" for r in refs]]
    r = subprocess.run(cmd, cwd=d, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return d / name


def _s7(text: str) -> bytes:
    b = text.encode()
    n, out = len(b), bytearray()
    while True:
        out.append((n & 0x7F) | (0x80 if n > 0x7F else 0))
        n >>= 7
        if not n:
            return bytes(out) + b


def make_bundle(path: Path, host_pe: bytes, entries: list[tuple[str, int, bytes, bool]],
                major: int = 6) -> Path:
    """host PE + marker + entry data + header, as ``dotnet publish -p:PublishSingleFile`` writes it.
    entries: (path, kind byte, data, compress)."""
    blob = bytearray(host_pe)
    marker_at = len(blob)
    blob += b"\0" * 8 + BUNDLE_SIG
    rows = []
    for name, kind, data, comp in entries:
        stored = zlib.compress(data)[2:-4] if comp else data      # raw deflate
        blob += b"\0" * (-len(blob) % 16)
        rows.append((name, kind, len(blob), len(data), len(stored) if comp else 0))
        blob += stored
    header_at = len(blob)
    h = struct.pack("<IIi", major, 0, len(rows)) + _s7("bundleid")
    if major >= 2:
        h += struct.pack("<qqqq", 0, 0, 0, 0) + struct.pack("<Q", 0)
    for name, kind, off, size, csize in rows:
        h += struct.pack("<qq", off, size) + (struct.pack("<q", csize) if major >= 6 else b"")
        h += bytes([kind]) + _s7(name)
    blob += h
    struct.pack_into("<q", blob, marker_at, header_at)
    path.write_bytes(bytes(blob))
    return path


def native_exe(tmp: Path) -> bytes:
    return _pe_with_sections(tmp / "host_tpl.exe", b"\x90" * 16, b"\0" * 16).read_bytes()


@pytest.mark.parametrize("major", [1, 2, 6])
def test_bundle_manifest_versions(tmp_path, major):
    comp = major >= 6
    data = [("a.dll", 1, b"MZ" + b"A" * 3000, comp), ("a.runtimeconfig.json", 4, b"{}", False),
            ("n.dll", 2, b"MZ" + b"N" * 50, False)]
    host = make_bundle(tmp_path / "h.exe", native_exe(tmp_path), data, major)
    es = bundle_manifest(host)
    assert [(e.path, e.kind) for e in es] == [("a.dll", "assembly"), ("a.runtimeconfig.json", "runtimeconfig"),
                                              ("n.dll", "nativebinary")]
    assert bool(es[0].csize) is comp and es[0].size == 3002
    assert read_bundle_entry(host, es[0]) == data[0][2]
    assert read_bundle_entry(host, es[2]) == data[2][2]


def test_plain_apphost_and_non_bundle_are_no_bundle(tmp_path):
    tpl = native_exe(tmp_path)
    assert bundle_manifest(tmp_path / "host_tpl.exe") is None
    apphost = tmp_path / "apphost.exe"
    apphost.write_bytes(tpl + b"\0" * 8 + BUNDLE_SIG)       # header offset 0: nothing appended
    assert bundle_manifest(apphost) is None


def test_bundle_scan_root_and_artifacts(tmp_path):
    prog = tmp_path / "prog"
    prog.mkdir()
    work = tmp_path / "w"
    work.mkdir()
    lib = _csc(work, "Util.Core.dll", LIB, "library")
    app = _csc(work, "Tool.dll", "class P { static void Main() { System.Console.WriteLine(Util.F(1)); } }",
               "exe", (str(lib),))
    make_bundle(prog / "Tool.exe", native_exe(tmp_path),
                [("Tool.dll", 1, app.read_bytes(), False), ("Util.Core.dll", 1, lib.read_bytes(), True),
                 ("System.Private.CoreLib.dll", 1, b"MZ", False), ("Tool.deps.json", 3, b"{}", False)])
    r = scan_program(prog)
    assert r.root_exe == "Tool.exe!Tool.dll"
    by = {f.rel_path: f for f in r.files}
    assert by["Tool.exe"].group == "apphost" and by["Tool.exe"].apphost == "Tool.exe!Tool.dll"
    assert by["Tool.exe!Tool.dll"].managed and by["Tool.exe!Tool.dll"].has_entry
    assert by["Tool.exe!System.Private.CoreLib.dll"].group == "runtime"
    assert "Tool.exe!Tool.deps.json" not in by
    assert by["Tool.exe!Tool.dll"].group == "core"
    assert "single-file bundle, 3 assemblies" in "\n".join(render_scan(r))
    assert "Tool.exe" not in {Path(f.rel_path).name for o in r.options for f in o.files}
    # naming the host picks the app dll
    assert scan_program(prog, "Tool.exe").root_exe == "Tool.exe!Tool.dll"
    # the artifact is the entry itself, hashed by its own bytes
    pp: ProjectPaths = project_paths(tmp_path / "proj", "p", create=True)
    sha = artifact_from_scan(prog, "Tool.exe!Util.Core.dll", pp)
    assert sha == hashlib.sha256(lib.read_bytes()).hexdigest()
    assert (pp.artifacts / sha).read_bytes() == lib.read_bytes()
    assert detect(pp.artifacts / sha).managed_only
    assert bundle_entry_name("Tool.exe!sub/Util.Core.dll") == "Util.Core.dll"
    assert bundle_entry_name("dir/x.dll") == "x.dll"


def test_apphost_points_at_dll_beside_it(tmp_path):
    prog = tmp_path / "prog"
    prog.mkdir()
    work = tmp_path / "w"
    work.mkdir()
    app = _csc(work, "Tool.dll", APP, "exe")
    (prog / "Tool.dll").write_bytes(app.read_bytes())
    (prog / "Tool.exe").write_bytes(native_exe(tmp_path) + b"\0" * 8 + BUNDLE_SIG)
    r = scan_program(prog)
    assert r.root_exe == "Tool.dll"
    assert {f.rel_path: f.group for f in r.files}["Tool.exe"] == "apphost"
    assert "host Tool.exe: apphost; starts Tool.dll" in "\n".join(render_scan(r))
    assert scan_program(prog, "Tool.exe").root_exe == "Tool.dll"


def test_native_exe_without_marker_is_not_an_apphost(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "n.exe").write_bytes(native_exe(tmp_path))
    r = scan_program(d)
    assert r.root_exe == "n.exe" and not any(f.apphost for f in r.files)


def _patch_cli(path: Path, flags: int | None = None, mnh: tuple[int, int] | None = None,
               rtr_at: int | None = None) -> Path:
    pe = pefile.PE(str(path), fast_load=True)
    dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    cli = pe.get_offset_from_rva(dd.VirtualAddress)
    pe.close()
    b = bytearray(path.read_bytes())
    if flags is not None:
        struct.pack_into("<I", b, cli + 16, flags)
    if mnh is not None:
        struct.pack_into("<II", b, cli + 64, *mnh)
    if rtr_at is not None:
        b[rtr_at:rtr_at + 4] = b"RTR\0"
    path.write_bytes(bytes(b))
    return path


def test_detect_r2r_is_managed_only_but_mixed_mode_is_not(tmp_path):
    il = _csc(tmp_path, "il.dll", LIB, "library")
    info = detect(il)
    assert info.toolchain == "dotnet" and info.managed_only and not info.r2r
    # ReadyToRun: ILONLY cleared, ManagedNativeHeader at a place that starts with "RTR"
    r2r = tmp_path / "r2r.dll"
    r2r.write_bytes(il.read_bytes())
    _patch_cli(r2r, flags=0xC, mnh=(0x40, 8), rtr_at=0x40)       # header area: RVA == file offset
    info = detect(r2r)
    assert info.toolchain == "dotnet" and info.r2r and info.managed_only
    # no ILONLY and no RTR header: C++/CLI style mixed mode, Ghidra still needed
    mixed = tmp_path / "mixed.dll"
    mixed.write_bytes(il.read_bytes())
    _patch_cli(mixed, flags=0x0)
    info = detect(mixed)
    assert info.toolchain == "dotnet" and not info.r2r and not info.managed_only
    # scan treats R2R as managed and says so
    d = tmp_path / "scan"
    d.mkdir()
    (d / "r2r.dll").write_bytes(r2r.read_bytes())
    (d / "main.exe").write_bytes(_csc(tmp_path, "main.exe", APP, "exe").read_bytes())
    s = scan_program(d)
    assert {f.rel_path: f.managed for f in s.files}["r2r.dll"]
    assert "ReadyToRun: 1 assemblies" in "\n".join(render_scan(s))


@pytest.mark.parametrize("plus", [False, True])
def test_detect_nativeaot_by_export(tmp_path, plus):
    name = b"DotNetRuntimeDebugHeader\0"
    rva = 0x2000
    exp = struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, rva + 0x40, 1, 1, 1, rva + 0x28, rva + 0x2C, rva + 0x30)
    exp += struct.pack("<I", 0x1000) + struct.pack("<I", rva + 0x34) + struct.pack("<H", 0)
    data = exp.ljust(0x34, b"\0") + name
    data = data.ljust(0x40, b"\0") + b"x.dll\0"
    p = _pe_with_sections(tmp_path / "aot.exe", b"\x90" * 16, data, plus)
    b = bytearray(p.read_bytes())
    struct.pack_into("<II", b, 0x58 + (112 if plus else 96), rva, len(data))
    p.write_bytes(bytes(b))
    info = detect(p)
    assert info.toolchain == "nativeaot" and not info.managed_only
    plain = _pe_with_sections(tmp_path / "plain.exe", b"\x90" * 16, b"\0" * 16, plus)
    assert detect(plain).toolchain != "nativeaot"
    s = scan_program(tmp_path / "aot.exe")
    assert "NativeAOT: aot.exe has no .NET metadata" in "\n".join(render_scan(s))


def test_outline_shows_managed_entry_point(tmp_path):
    exe = _csc(tmp_path, "m.exe", APP, "exe")
    ctx = make_dn_ctx(tmp_path)
    add_managed(ctx, exe, "m.exe")
    out = core.outline(ctx, "m.exe")
    tok = detect(exe).cli_entry
    assert tok >> 24 == 0x06
    assert f"entry P::Main 0x{tok:08x}" in out
    lib = _csc(tmp_path, "l.dll", LIB, "library")
    add_managed(ctx, lib, "l.dll")
    assert "entry none" in core.outline(ctx, "l.dll")


def test_normal_module_keeps_unix_names():
    assert dn.normal_module("libgcrypt.so.20") == "libgcrypt.so.20"
    assert dn.normal_module("libc.so") == "libc.so"
    assert dn.normal_module("libfoo.dylib") == "libfoo.dylib"
    assert dn.normal_module("user32") == "user32.dll"
    assert dn.normal_module(r"C:\x\kernel32.dll") == "kernel32.dll"
    assert dn.normal_module("sqlite3.so.0.8") == "sqlite3.so.0.8"
