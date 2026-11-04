"""Project layout, artifact storage and PE detection (server side, no JVM)."""
from __future__ import annotations

import hashlib
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import pefile

_SLUG_RE = re.compile(r"[^A-Za-z0-9_-]+")

_MSVC_IMPORT_RE = re.compile(
    r"^(msvcr\d*|msvcp\d*|vcruntime\d*|ucrtbase|api-ms-win-crt-.*)(d)?(\.dll)?$", re.I
)
_QT_IMPORT_RE = re.compile(r"^qt[56]core(d)?(\.dll)?$", re.I)

_MACHINES = {
    0x014C: ("x86", 4),
    0x8664: ("x86_64", 8),
    0x01C0: ("arm", 4),
    0x01C4: ("armnt", 4),
    0xAA64: ("arm64", 8),
    0x0200: ("ia64", 8),
}


def slugify(name: str) -> str:
    """Letters, digits, '_' and '-' only; never empty."""
    s = _SLUG_RE.sub("_", name.strip()).strip("_")
    return s or "project"


@dataclass(frozen=True)
class ProjectPaths:
    root: Path
    name: str

    @property
    def ghidra(self) -> Path:
        return self.root / "ghidra"

    @property
    def artifacts(self) -> Path:
        return self.root / "artifacts"

    @property
    def index_db(self) -> Path:
        return self.root / "index.sqlite"

    @property
    def cache(self) -> Path:
        return self.root / "cache"

    @property
    def logs(self) -> Path:
        return self.root / "logs"

    @property
    def project_json(self) -> Path:
        return self.root / "project.json"

    @property
    def project_jsonc(self) -> Path:
        return self.root / "project.jsonc"

    def ensure(self) -> "ProjectPaths":
        for d in (self.ghidra, self.artifacts, self.cache, self.logs):
            d.mkdir(parents=True, exist_ok=True)
        return self


def projects_root(data_dir: Path) -> Path:
    return Path(data_dir) / "projects"


def project_paths(data_dir: Path, name: str, create: bool = True) -> ProjectPaths:
    slug = slugify(name)
    p = ProjectPaths(projects_root(data_dir) / slug, slug)
    return p.ensure() if create else p


def list_projects(data_dir: Path) -> list[str]:
    root = projects_root(data_dir)
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir())


def hash_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def copy_artifact(
    src: Path, project: ProjectPaths, sha256: str | None = None
) -> tuple[str, Path]:
    """Copy src to artifacts/<sha256>. Idempotent. Returns (sha256, artifact path)."""
    sha = sha256 or hash_file(src)
    project.artifacts.mkdir(parents=True, exist_ok=True)
    dest = project.artifacts / sha
    if not dest.exists():
        tmp = dest.with_name(dest.name + ".part")
        shutil.copyfile(src, tmp)
        tmp.replace(dest)
    return sha, dest


@dataclass(frozen=True)
class BinaryInfo:
    format: str  # pe32 | pe32+ | not-pe
    arch: str | None
    pointer_size: int | None
    image_base: int | None
    entry_point: int | None  # RVA
    toolchain: str  # msvc | delphi | qt | dotnet | unknown


def classify_toolchain(
    import_names: list[str], resource_types: set[str], has_cli: bool, has_rich: bool
) -> str:
    """Heuristics in order: dotnet, delphi (TPF0), qt, msvc, unknown."""
    if has_cli:
        return "dotnet"
    if "TPF0" in resource_types:
        return "delphi"
    if any(_QT_IMPORT_RE.match(n) for n in import_names):
        return "qt"
    if has_rich or any(_MSVC_IMPORT_RE.match(n) for n in import_names):
        return "msvc"
    return "unknown"


def _has_tpf0(pe: pefile.PE) -> bool:
    """True if an RCDATA resource starts with the Delphi form signature TPF0."""
    d = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if d is None:
        return False
    rcdata = pefile.RESOURCE_TYPE["RT_RCDATA"]
    for t in d.entries:
        if t.id != rcdata or not hasattr(t, "directory"):
            continue
        for n in t.directory.entries:
            if not hasattr(n, "directory"):
                continue
            for lang in n.directory.entries:
                data = getattr(lang, "data", None)
                if data is None:
                    continue
                try:
                    blob = pe.get_data(data.struct.OffsetToData, min(data.struct.Size, 8))
                except Exception:
                    continue
                if blob.startswith(b"TPF0"):
                    return True
    return False


def detect(path: Path) -> BinaryInfo:
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except (pefile.PEFormatError, OSError):
        return BinaryInfo("not-pe", None, None, None, None, "unknown")
    try:
        D = pefile.DIRECTORY_ENTRY
        pe.parse_data_directories(
            directories=[D["IMAGE_DIRECTORY_ENTRY_IMPORT"], D["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
        is_plus = pe.OPTIONAL_HEADER.Magic == 0x20B
        machine = pe.FILE_HEADER.Machine
        arch, ptr = _MACHINES.get(machine, (f"0x{machine:04x}", 8 if is_plus else 4))
        imports = [
            e.dll.decode("latin-1")
            for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
            if e.dll
        ]
        com = D["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        dds = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        has_cli = len(dds) > com and bool(dds[com].VirtualAddress and dds[com].Size)
        rtypes = {"TPF0"} if _has_tpf0(pe) else set()
        return BinaryInfo(
            "pe32+" if is_plus else "pe32",
            arch,
            ptr,
            pe.OPTIONAL_HEADER.ImageBase,
            pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            classify_toolchain(imports, rtypes, has_cli, pe.parse_rich_header() is not None),
        )
    finally:
        pe.close()


def read_sections(path: Path) -> list[tuple[str, int, int, str]]:
    """(name, rva, virtual size, flags like 'rx') for each PE section; [] if not a PE."""
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except (pefile.PEFormatError, OSError):
        return []
    try:
        out = []
        for s in pe.sections:
            c = s.Characteristics
            flags = ("r" if c & 0x40000000 else "") + ("w" if c & 0x80000000 else "") +                     ("x" if c & 0x20000000 else "")
            out.append((s.Name.rstrip(b"\x00").decode("latin-1"), s.VirtualAddress,
                        s.Misc_VirtualSize, flags))
        return out
    finally:
        pe.close()
