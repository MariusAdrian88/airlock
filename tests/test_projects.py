import hashlib
import shutil
import struct
from pathlib import Path

import pytest

from airlock import projects as P


def make_pe(path: Path, plus: bool = False) -> Path:
    """Minimal PE: DOS header, PE header, optional header, no sections."""
    opt_size = 0xF0 if plus else 0xE0
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    fh = struct.pack("<HHIIIHH", 0x8664 if plus else 0x14C, 0, 0, 0, 0, opt_size, 0x22)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B if plus else 0x10B)
    struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint
    if plus:
        struct.pack_into("<Q", opt, 24, 0x140000000)
    else:
        struct.pack_into("<I", opt, 28, 0x400000)
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt, 56, 0x2000)  # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<I", opt, 108 if plus else 92, 16)  # NumberOfRvaAndSizes
    path.write_bytes(bytes(dos) + b"PE\0\0" + fh + bytes(opt) + b"\0" * 0x200)
    return path


def test_slugify():
    assert P.slugify("My App v1.2!") == "My_App_v1_2"
    assert P.slugify("***") == "project"
    assert P.slugify("ok-name_1") == "ok-name_1"


def test_layout(tmp_path):
    pp = P.project_paths(tmp_path, "a b")
    assert pp.root == tmp_path / "a_b"
    assert pp.data == pp.root / "dirty" / ".airlock"
    assert pp.ghidra == pp.data / "ghidra" and pp.index_db == pp.data / "index.sqlite"
    assert pp.specs == pp.root / "clean" / "specs"
    for d in (pp.ghidra, pp.artifacts, pp.cache, pp.logs, pp.specs):
        assert d.is_dir()
    assert pp.manifest.is_file() and P.read_manifest(pp.manifest)["name"] == "a_b"
    assert P.list_projects(tmp_path) == ["a_b"]
    assert not P.project_paths(tmp_path, "zz", create=False).root.exists()


def test_hash_and_copy(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"hello" * 500000)
    sha = P.hash_file(f)
    assert sha == hashlib.sha256(b"hello" * 500000).hexdigest()
    pp = P.project_paths(tmp_path, "p")
    s1, dest = P.copy_artifact(f, pp)
    assert s1 == sha and dest == pp.artifacts / sha
    assert dest.read_bytes() == f.read_bytes()
    mtime = dest.stat().st_mtime_ns
    s2, dest2 = P.copy_artifact(f, pp)
    assert dest2 == dest and dest.stat().st_mtime_ns == mtime
    assert not list(pp.artifacts.glob("*.part"))


def test_detect_pe32_and_pe32plus(tmp_path):
    a = P.detect(make_pe(tmp_path / "a.exe"))
    assert (a.format, a.arch, a.pointer_size) == ("pe32", "x86", 4)
    assert (a.image_base, a.entry_point, a.toolchain) == (0x400000, 0x1000, "unknown")
    b = P.detect(make_pe(tmp_path / "b.exe", plus=True))
    assert (b.format, b.arch, b.pointer_size) == ("pe32+", "x86_64", 8)
    assert b.image_base == 0x140000000


def test_detect_not_pe(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("nope")
    assert P.detect(f).format == "not-pe"


@pytest.mark.parametrize(
    "imports,res,cli,rich,want",
    [
        ([], set(), True, True, "dotnet"),
        (["KERNEL32.dll"], {"TPF0"}, False, False, "delphi"),
        (["Qt5Core.dll", "MSVCP140.dll"], set(), False, False, "qt"),
        (["Qt6Core.dll"], set(), False, False, "qt"),
        (["VCRUNTIME140.dll"], set(), False, False, "msvc"),
        (["api-ms-win-crt-runtime-l1-1-0.dll"], set(), False, False, "msvc"),
        (["MSVCR90.dll"], set(), False, False, "msvc"),
        (["KERNEL32.dll"], set(), False, True, "msvc"),
        (["KERNEL32.dll"], set(), False, False, "unknown"),
    ],
)
def test_classify(imports, res, cli, rich, want):
    assert P.classify_toolchain(imports, res, cli, rich) == want


def test_detect_notepad(tmp_path):
    src = Path(r"C:\Windows\System32\notepad.exe")
    if not src.exists():
        pytest.skip("no notepad")
    f = tmp_path / "notepad.exe"
    shutil.copyfile(src, f)
    info = P.detect(f)
    assert info.format == "pe32+" and info.arch == "x86_64"
    assert info.toolchain in {"msvc", "unknown"}


def _with_rich_header(pe_bytes: bytes) -> bytes:
    """Insert a Rich header between the DOS header and the PE header."""
    key = 0x1234ABCD
    words = [0x536E6144, 0, 0, 0, (0x0100 << 16) | 0x5D, 7]  # DanS, pad, (compid, count)
    blob = struct.pack("<I", words[0] ^ key) + struct.pack("<III", key, key, key) \
        + struct.pack("<II", words[4] ^ key, words[5] ^ key) + b"Rich" + struct.pack("<I", key)
    blob += b"\0" * (-len(blob) % 8)
    old = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    blob = b"\x00" * (0x80 - old) + blob  # pefile looks for "Rich" at or after 0x80
    out = bytearray(pe_bytes[:old] + blob + pe_bytes[old:])
    struct.pack_into("<I", out, 0x3C, old + len(blob))
    return bytes(out)


def test_rich_header_means_msvc_without_runtime_imports(tmp_path):
    plain = make_pe(tmp_path / "plain.exe")
    assert P.detect(plain).toolchain == "unknown"
    rich = tmp_path / "rich.exe"
    rich.write_bytes(_with_rich_header(plain.read_bytes()))
    assert P.detect(rich).toolchain == "msvc"
