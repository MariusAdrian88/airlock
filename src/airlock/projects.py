"""Project layout, artifact storage and PE detection (server side, no JVM)."""
from __future__ import annotations

import hashlib
import itertools
import json
import mmap
import os
import re
import shutil
import struct
import threading
import time
import zlib
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


def _index_states(pp: ProjectPaths) -> list[str]:
    """The ``status:<id>`` values of the index store (the truth when the manifest lacks the files)."""
    import sqlite3
    if not pp.index_db.is_file():
        return []
    try:
        db = sqlite3.connect(f"file:{pp.index_db.as_posix()}?mode=ro", uri=True, timeout=2)
        try:
            return [str(r[0]) for r in db.execute("SELECT value FROM meta WHERE key LIKE 'status:%'")]
        finally:
            db.close()
    except sqlite3.Error:
        return []


def summarize(pp: ProjectPaths) -> ProjectSummary:
    """Binary counts from the manifest (state ready / error / anything else = queued); from the index
    store when the manifest lists no binaries."""
    try:
        man = read_manifest(pp.manifest)
    except (OSError, ValueError):
        man = {}
    if not any(isinstance(f, dict) and f.get("kind") == "pe" for f in man.get("files") or []):
        st = _index_states(pp)
        if st:
            root = str((man.get("source") or {}).get("root_exe") or "?")
            ready, errors = st.count("ready"), st.count("error")
            return ProjectSummary(root, ready, len(st) - ready - errors, errors)
    if not man:
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
    toolchain: str  # msvc | delphi | fpc | qt | dotnet | nativeaot | unknown
    managed_only: bool = False  # IL-only or ReadyToRun image: the IL is complete, Ghidra not needed
    toolchain_ver: str | None = None  # fpc: compiler version from the RTL's version string
    r2r: bool = False  # ReadyToRun image (CLI header with a ManagedNativeHeader "RTR")
    cli_entry: int = 0  # CLI header EntryPointToken (0x06xxxxxx method; 0 = none, a library)


COR_ILONLY = 0x1


NATIVEAOT_EXPORT = b"DotNetRuntimeDebugHeader"


def _cli_header(pe: pefile.PE) -> bytes | None:
    """The bytes of the CLI header (``IMAGE_COR20_HEADER``, 72), None without one."""
    try:
        com = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        dds = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(dds) <= com or not (dds[com].VirtualAddress and dds[com].Size):
            return None
        data = pe.get_data(dds[com].VirtualAddress, 72)
        return data if len(data) >= 24 else None
    except Exception:  # noqa: BLE001  damaged header: treated as not managed by the caller
        return None


def cor_flags(pe: pefile.PE) -> int | None:
    """Flags of the CLI header, None without one."""
    h = _cli_header(pe)
    return int.from_bytes(h[16:20], "little") if h else None


def cli_entry_token(pe: pefile.PE) -> int:
    """``EntryPointToken`` of the CLI header: the managed Main (0x06xxxxxx), 0 when none or native."""
    h = _cli_header(pe)
    if not h or int.from_bytes(h[16:20], "little") & 0x10:       # COMIMAGE_FLAGS_NATIVE_ENTRYPOINT
        return 0
    tok = int.from_bytes(h[20:24], "little")
    return tok if tok >> 24 == 0x06 else 0


def is_r2r(pe: pefile.PE) -> bool:
    """ReadyToRun image: the CLI header has a ManagedNativeHeader that starts with ``RTR``."""
    h = _cli_header(pe)
    if not h or len(h) < 72:
        return False
    rva, size = struct.unpack_from("<II", h, 64)
    if not (rva and size):
        return False
    try:
        return pe.get_data(rva, 4) == b"RTR\x00"
    except Exception:  # noqa: BLE001
        return False


def is_nativeaot(pe: pefile.PE) -> bool:
    """NativeAOT image: the runtime debug header is exported (needs the export directory parsed)."""
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    return exp is not None and any(s.name == NATIVEAOT_EXPORT for s in exp.symbols)


# --- single-file bundles and apphosts -----------------------------------------------------

BUNDLE_SIG = bytes([
    0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
    0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae])
BUNDLE_KINDS = {0: "unknown", 1: "assembly", 2: "nativebinary", 3: "depsjson", 4: "runtimeconfig",
                5: "symbols"}


@dataclass(frozen=True)
class BundleEntry:
    path: str          # path inside the bundle, "/" separators
    kind: str          # assembly (managed) | nativebinary | depsjson | runtimeconfig | symbols | unknown
    offset: int
    size: int          # size after decompression
    csize: int = 0     # stored size when the entry is deflate-compressed (bundle v6+), else 0


def bundle_marker(path: Path) -> int | None:
    """None: no apphost marker in the file. 0: an apphost without payload. Else the offset of the
    bundle header (a single-file bundle)."""
    try:
        with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            i = mm.find(BUNDLE_SIG)
            if i < 8:
                return None
            off = struct.unpack_from("<q", mm, i - 8)[0]
            return off if 0 < off < len(mm) - 12 else 0
    except (OSError, ValueError, struct.error):
        return None


def _s7(d, o: int) -> tuple[str, int]:
    n = sh = 0
    while True:
        b = d[o]
        o += 1
        n |= (b & 0x7F) << sh
        sh += 7
        if b < 0x80:
            return bytes(d[o:o + n]).decode("utf-8", "replace"), o + n


def bundle_manifest(path: Path) -> list[BundleEntry] | None:
    """The file table of a .NET single-file bundle (header versions 1, 2 and 6+); None when the
    file is no bundle (also for a plain apphost)."""
    off = bundle_marker(path)
    if not off:
        return None
    try:
        with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            major, _minor, count = struct.unpack_from("<IIi", mm, off)
            if not (1 <= major <= 64) or not (0 <= count <= 100000):
                return None
            _bid, o = _s7(mm, off + 12)
            if major >= 2:
                o += 8 * 4 + 8     # deps.json and runtimeconfig.json (offset, size), flags
            out = []
            for _ in range(count):
                eoff, size = struct.unpack_from("<qq", mm, o)
                o += 16
                csize = 0
                if major >= 6:
                    csize = struct.unpack_from("<q", mm, o)[0]
                    o += 8
                kind = mm[o]
                o += 1
                name, o = _s7(mm, o)
                out.append(BundleEntry(name.replace("\\", "/"), BUNDLE_KINDS.get(kind, "unknown"),
                                       eoff, size, max(csize, 0)))
            return out
    except (OSError, ValueError, struct.error, IndexError):
        return None


def read_bundle_entry(path: Path, e: BundleEntry) -> bytes:
    """Bytes of a bundle entry; compressed entries are raw deflate (``DeflateStream``)."""
    with open(path, "rb") as f:
        f.seek(e.offset)
        if e.csize:
            return zlib.decompress(f.read(e.csize), -15)
        return f.read(e.size)


BUNDLE_SEP = "!"     # "<host>!<entry path>": a file inside a single-file bundle


def split_bundle_path(rel: str) -> tuple[str, str] | None:
    """``("host.exe", "entry.dll")`` for ``host.exe!entry.dll``, else None."""
    host, sep, entry = rel.partition(BUNDLE_SEP)
    return (host, entry) if sep and host and entry else None


def bundle_entry_name(rel: str) -> str:
    """The file name a bundle entry gets as a binary (``X.dll`` for ``host.exe!sub/X.dll``)."""
    sp = split_bundle_path(rel)
    return Path((sp[1] if sp else rel).replace("\\", "/")).name


_APPHOST_DLL_RE = re.compile(rb"([A-Za-z0-9_.\- ]{1,200}\.dll)\x00{8}")


def apphost_targets(path: Path) -> list[str]:
    """Managed dll names an apphost (no bundle) can start: ``<host stem>.dll`` first, then the names
    patched into the host. The caller checks which one exists beside the host."""
    stem = path.stem + ".dll"
    names: list[str] = []
    try:
        with open(path, "rb") as f:
            head = f.read(1 << 20)
    except OSError:
        return [stem]
    for m in _APPHOST_DLL_RE.finditer(head):
        n = m.group(1).decode("ascii", "replace").strip()
        if n.lower() not in ("hostfxr.dll", "hostpolicy.dll") and n != stem and n not in names:
            names.append(n)
    return [stem, *names]


def artifact_from_scan(root: Path, rel: str, project: "ProjectPaths") -> str:
    """Store the file ``rel`` of a scanned program folder as an artifact; returns its sha256. A
    bundle entry (``host.exe!X.dll``) is cut out of the host and hashed by its own bytes."""
    sp = split_bundle_path(rel)
    if sp is None or (root / rel).is_file():
        src = root / rel
        sha = hash_file(src)
        copy_artifact(src, project, sha)
        return sha
    host = root / sp[0]
    entry = next((e for e in bundle_manifest(host) or [] if e.path == sp[1]), None)
    if entry is None:
        raise FileNotFoundError(rel)
    data = read_bundle_entry(host, entry)
    sha = hashlib.sha256(data).hexdigest()
    project.artifacts.mkdir(parents=True, exist_ok=True)
    dest = project.artifacts / sha
    if not dest.exists():
        tmp = dest.with_name(dest.name + ".part")
        tmp.write_bytes(data)
        tmp.replace(dest)
    return sha


FPC_VERSION_RE = re.compile(rb"FPC (\d+\.\d+\.\d+)[\w.\-]* \[\d{4}/\d\d/\d\d\] for \w+")


def fpc_version(path: Path) -> str | None:
    """Compiler version of a Free Pascal program (``3.2.2``), read from the version string that the
    RTL links into every program (``FPC 3.2.2 [2021/05/15] for i386 - Win32``); None when absent."""
    try:
        with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            m = FPC_VERSION_RE.search(mm)
            return m.group(1).decode("ascii") if m else None
    except (OSError, ValueError):
        return None


def classify_toolchain(
    import_names: list[str], resource_types: set[str], has_cli: bool, has_rich: bool, fpc: bool = False,
    nativeaot: bool = False,
) -> str:
    """Heuristics in order: dotnet, nativeaot (export), fpc (version string), delphi (TPF0), qt,
    msvc, unknown."""
    if has_cli:
        return "dotnet"
    if nativeaot:
        return "nativeaot"
    if fpc:
        return "fpc"
    if "TPF0" in resource_types:
        return "delphi"
    if any(_QT_IMPORT_RE.match(n) for n in import_names):
        return "qt"
    if has_rich or any(_MSVC_IMPORT_RE.match(n) for n in import_names):
        return "msvc"
    return "unknown"


def _has_tpf0(pe: pefile.PE) -> bool:
    """True if an RCDATA resource starts with the Delphi form signature TPF0, or is the DVCLAL license
    resource that every Delphi 2+ program carries (console programs and DLLs have no form)."""
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
            if getattr(n, "name", None) is not None and str(n.name) == "DVCLAL":
                return True
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
            directories=[D["IMAGE_DIRECTORY_ENTRY_IMPORT"], D["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                         D["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
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
        has_rich = pe.parse_rich_header() is not None
        aot = not has_cli and is_nativeaot(pe)
        fpcv = None if has_cli or has_rich or aot else fpc_version(path)   # GNU ld writes no Rich header
        r2r = has_cli and is_r2r(pe)
        return BinaryInfo(
            "pe32+" if is_plus else "pe32",
            arch,
            ptr,
            pe.OPTIONAL_HEADER.ImageBase,
            pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            classify_toolchain(imports, rtypes, has_cli, has_rich, fpcv is not None, aot),
            has_cli and (r2r or bool((cor_flags(pe) or 0) & COR_ILONLY)),
            fpcv,
            r2r,
            cli_entry_token(pe) if has_cli else 0,
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
