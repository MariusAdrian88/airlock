"""Project layout, artifact storage and PE detection (server side, no JVM)."""
from __future__ import annotations

import hashlib
import itertools
import json
import os
import re
import shutil
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import json5
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


MANIFEST_NAME = "airlock-project.jsonc"
MANIFEST_VERSION = 1
MANIFEST_HEADER = (
    "// airlock project manifest. Marker for the project folder and record of what was\n"
    "// scanned, selected and queued. Written by airlock; the \"settings\" key is a\n"
    "// per-project config overlay you may edit.\n"
)


@dataclass(frozen=True)
class ProjectPaths:
    """<projects_root>/<name>/{airlock-project.jsonc, dirty/{.airlock/..., airlock_ghidra}, clean/specs}."""

    root: Path
    name: str

    @property
    def manifest(self) -> Path:
        return self.root / MANIFEST_NAME

    @property
    def dirty(self) -> Path:
        return self.root / "dirty"

    @property
    def clean(self) -> Path:
        return self.root / "clean"

    @property
    def data(self) -> Path:
        return self.dirty / ".airlock"

    @property
    def ghidra(self) -> Path:
        # Not under .airlock: Ghidra rejects project paths with a '.'-prefixed element
        # ("Path element starting with '.' is not permitted"), verified with 12.1.4.
        return self.dirty / "airlock_ghidra"

    @property
    def artifacts(self) -> Path:
        return self.data / "artifacts"

    @property
    def index_db(self) -> Path:
        return self.data / "index.sqlite"

    @property
    def cache(self) -> Path:
        return self.data / "cache"

    @property
    def logs(self) -> Path:
        return self.data / "logs"

    @property
    def specs(self) -> Path:
        return self.clean / "specs"

    def ensure(self) -> "ProjectPaths":
        for d in (self.ghidra, self.artifacts, self.cache, self.logs, self.specs):
            d.mkdir(parents=True, exist_ok=True)
        return self


def read_manifest(path: Path) -> dict:
    for attempt in range(10):  # Windows: reading while write_manifest replaces the file
        try:
            text = Path(path).read_text("utf-8-sig")
            break
        except PermissionError:
            if attempt == 9:
                raise
            time.sleep(0.02)
    data = json5.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: manifest must be an object")
    return data


_tmp_seq = itertools.count()


def atomic_write_text(path: Path, text: str, newline: str | None = None) -> None:
    """Write ``text`` to ``path`` via a temp file that is unique per process, thread and call
    (two writers never share one), then replace. Windows refuses the replace while a reader has
    the target open (PermissionError), so retry briefly."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.{next(_tmp_seq)}.part")
    try:
        tmp.write_text(text, "utf-8", newline=newline)
        for attempt in range(25):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                if attempt == 24:
                    raise
                time.sleep(0.04)
    finally:
        tmp.unlink(missing_ok=True)


def write_manifest(path: Path, data: dict) -> None:
    """JSONC with a header comment; atomic replace."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".part")
    tmp.write_text(MANIFEST_HEADER + json.dumps(data, indent=2, ensure_ascii=False) + "\n", "utf-8")
    for attempt in range(25):  # Windows: replace fails while a reader has the file open
        try:
            tmp.replace(path)
            return
        except PermissionError:
            if attempt == 24:
                raise
            time.sleep(0.02)


def new_manifest(name: str) -> dict:
    return {"version": MANIFEST_VERSION, "name": name, "settings": {}}


def project_paths(root: Path, name: str, create: bool = True) -> ProjectPaths:
    """Paths of project ``name`` under the projects root. With create, make the folders
    and a minimal manifest if none exists (the manifest is what makes it a project)."""
    slug = slugify(name)
    p = ProjectPaths(Path(root) / slug, slug)
    if create:
        p.ensure()
        if not p.manifest.exists():
            write_manifest(p.manifest, new_manifest(slug))
    return p


def list_projects(root: Path) -> list[str]:
    root = Path(root)
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if (p / MANIFEST_NAME).is_file())


def find_project(root: Path, name: str) -> ProjectPaths | None:
    """The project called ``name`` (exact, case-insensitive, or as its slug), or None."""
    want = {name.strip().lower(), slugify(name).lower()}
    for n in list_projects(root):
        if n.lower() in want:
            return ProjectPaths(Path(root) / n, n)
    return None


def count_specs(pp: ProjectPaths) -> int:
    """Published specs in clean/specs: entries of specs.json, else the Markdown files."""
    idx = pp.specs / "specs.json"
    if idx.is_file():
        try:
            data = json5.loads(idx.read_text("utf-8-sig"))
            items = data.get("specs", []) if isinstance(data, dict) else data
            if isinstance(items, list):
                return len(items)
        except ValueError:
            pass
    return len(list(pp.specs.glob("*.md"))) if pp.specs.is_dir() else 0


@dataclass(frozen=True)
class ProjectSummary:
    root_exe: str
    ready: int
    queued: int
    errors: int


def summarize(pp: ProjectPaths) -> ProjectSummary:
    """Binary counts from the manifest (state ready / error / anything else = queued)."""
    try:
        man = read_manifest(pp.manifest)
    except (OSError, ValueError):
        return ProjectSummary("?", 0, 0, 0)
    files = [f for f in man.get("files") or [] if isinstance(f, dict) and f.get("kind") == "pe"]
    states = [str(f.get("state", "queued")) for f in files]
    ready = states.count("ready")
    errors = states.count("error")
    root_exe = str((man.get("source") or {}).get("root_exe") or "?")
    return ProjectSummary(root_exe, ready, len(states) - ready - errors, errors)


def _claude_rule_path(p: Path) -> str:
    return "//" + str(p.resolve()).replace("\\", "/")


def _merge_json(path: Path, patch: dict) -> None:
    cur: dict = {}
    if path.exists():
        try:
            cur = json5.loads(path.read_text("utf-8-sig"))
        except ValueError:
            cur = {}
        if not isinstance(cur, dict):
            cur = {}
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(cur.get(k), dict):
            for k2, v2 in v.items():
                if isinstance(v2, list) and isinstance(cur[k].get(k2), list):
                    cur[k][k2] = cur[k][k2] + [x for x in v2 if x not in cur[k][k2]]
                elif isinstance(v2, dict) and isinstance(cur[k].get(k2), dict):
                    cur[k][k2] = {**v2, **cur[k][k2]}  # the user's entries win
                else:
                    cur[k].setdefault(k2, v2)
        else:
            cur.setdefault(k, v)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cur, indent=2) + "\n", "utf-8")


def write_clean_deny_rules(pp: ProjectPaths) -> list[str]:
    """Deny rules in clean/ that keep the clean agent's own file tools out of ../dirty,
    using the absolute path of the sibling folder. Existing user files are merged
    (JSON) or left alone (Codex TOML). Returns the files written."""
    pp.clean.mkdir(parents=True, exist_ok=True)
    rule = _claude_rule_path(pp.dirty)
    written = []
    f = pp.clean / ".claude" / "settings.json"
    _merge_json(f, {"permissions": {"deny": [f"Read({rule}/**)", f"Edit({rule}/**)"]}})
    written.append(str(f))
    f = pp.clean / "opencode.json"
    _merge_json(f, {"permission": {"external_directory": {"*": "deny"}}})
    written.append(str(f))
    f = pp.clean / ".codex" / "config.toml"
    if not f.exists():
        d = str(pp.dirty.resolve()).replace("\\", "/")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(
            "# airlock: keep the clean session out of the sibling dirty folder. [verify] schema\n"
            'default_permissions = "airlock-clean"\n\n'
            "[permissions.airlock-clean.filesystem]\n"
            f'":workspace_roots" = {{ "." = "write" }}\n"{d}/**" = "deny"\n',
            "utf-8")
        written.append(str(f))
    return written


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
