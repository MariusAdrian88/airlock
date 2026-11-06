"""Light scan of a program folder (DESIGN section 5.0): pefile only, no JVM.

`scan_program` walks a folder, reads PE headers cheaply (fast_load, only the
import/export/resource directories), assigns each file to a group and builds
the cumulative options table. `render_scan` turns the result into compact text.
"""
from __future__ import annotations

import dataclasses
import os
import re
import struct
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pefile

from airlock.projects import (
    BUNDLE_SEP, COR_ILONLY, _cli_header, apphost_targets, bundle_manifest, bundle_marker,
    cli_entry_token, cor_flags, is_nativeaot, is_r2r, read_bundle_entry,
)
from airlock.server import estimate as est

_MB = 1024 * 1024
MANAGED_S = 1.0          # indexing one IL-only assembly with dnfile (seconds)

RUNTIME_PREFIXES = ("msvcr", "msvcp", "msvcm", "mfc", "atl", "vcruntime", "ucrtbase",
                    "api-ms-", "msvbvm", "mscoree", "concrt", "vcomp")

_VENDOR_NOISE = {
    "inc", "incorporated", "corp", "corporation", "ltd", "limited", "llc", "co", "company",
    "gmbh", "ag", "sa", "plc", "srl", "bv", "the", "software", "technologies", "systems", "all", "rights", "reserved", "copyright", "c",
}

_OPTION_DEFS = (
    ("A", "Core", ("core",)),
    ("B", "Core + own plugins", ("core", "own_plugin")),
    ("C", "+ third party", ("core", "own_plugin", "third_party")),
    ("D", "Everything", ("core", "own_plugin", "third_party", "separate_exe")),
)
_ADDED_GROUP = {"A": "core", "B": "own_plugin", "C": "third_party", "D": "separate_exe"}
_OMIT_WHY = {"A": "no core files", "B": "no own plugins found",
             "C": "no third-party files found", "D": "no separate executables found"}


@dataclass(frozen=True)
class ScannedFile:
    rel_path: str
    kind: str
    group: str
    size: int
    code_size: int
    bits: int | None
    is_dll: bool
    dotnet: bool
    rich: bool
    company: str | None
    product: str | None
    imports: tuple[str, ...]
    exports: int
    subsystem: int = 0                 # PE optional header Subsystem (1 = native/driver)
    description: str | None = None     # version FileDescription
    est_funcs: int = 0                 # estimated function count (see estimate_functions)
    managed: bool = False              # IL-only or ReadyToRun assembly: indexed with dnfile, never sent to Ghidra
    apphost: str = ""                  # apphost or single-file bundle host: rel path of its managed app dll
    has_entry: bool = False            # managed file with a CLI entry point (an application)
    meta_size: int = 0                 # managed: size of the metadata (stands in for code size)
    refs: tuple[str, ...] = ()         # managed: AssemblyRef names, lowercase
    r2r: bool = False                  # ReadyToRun image
    nativeaot: bool = False            # NativeAOT image (no .NET metadata)


@dataclass(frozen=True)
class ScanOption:
    key: str
    label: str
    groups: tuple[str, ...]
    files: tuple[ScannedFile, ...]
    code_size: int
    est_seconds: float


@dataclass(frozen=True)
class ScanResult:
    root: Path
    root_exe: str | None
    root_reason: str
    files: tuple[ScannedFile, ...]
    system_dlls: tuple[str, ...]
    data_summary: tuple[tuple[str, int, int], ...]
    options: tuple[ScanOption, ...]
    recommended: str
    root_candidates: tuple[tuple[str, int], ...] = ()   # other eligible roots (rel_path, code_size)
    root_ambiguous: bool = False
    root_ranking: tuple[tuple[str, int, str], ...] = ()  # (rel_path, score, reasons), best first


# --- vendor / names -------------------------------------------------------------

def normalise_vendor(company: str | None) -> str | None:
    """Case-insensitive vendor key without punctuation, years and legal suffixes."""
    if not company:
        return None
    tokens = [t for t in re.split(r"[^a-z0-9]+", company.lower())
              if t and t not in _VENDOR_NOISE and not re.fullmatch(r"\d{2,4}", t)]
    return " ".join(tokens) or None


def vendor_matches(root_vendor: str | None, file_vendor: str | None) -> bool:
    """Token match on normalised vendors: root's first token, or a shared token of length >= 4."""
    if not root_vendor or not file_vendor:
        return False
    rt, ft = root_vendor.split(), set(file_vendor.split())
    return rt[0] in ft or any(len(t) >= 4 for t in set(rt) & ft)


_INSTALLER_RE = re.compile(r"setup|install|uninst|vcredist|redist|runtime|update", re.I)


def is_root_candidate(f: ScannedFile) -> bool:
    """Executables that may be chosen as root automatically (no installers, no drivers)."""
    if f.kind != "pe" or f.group == "unreadable" or f.is_dll or f.subsystem == 1 or f.apphost:
        return False
    name = Path(f.rel_path).name
    if name.lower().endswith(".sys") or _INSTALLER_RE.search(name):
        return False
    d = (f.description or "").lower()
    return not ("setup" in d or "install" in d)


def is_runtime_name(name: str) -> bool:
    return name.lower().startswith(RUNTIME_PREFIXES)


def _description(pe: pefile.PE) -> str | None:
    for fi in getattr(pe, "FileInfo", None) or []:
        for entry in fi:
            for st in getattr(entry, "StringTable", None) or []:
                d = _decode(st.entries.get(b"FileDescription"))
                if d:
                    return d
    return None


def _decode(v: object) -> str | None:
    if isinstance(v, bytes):
        v = v.decode("utf-8", "replace")
    if not isinstance(v, str):
        return None
    v = v.replace("\x00", "").strip()
    return v or None


def extract_vendor(pe: pefile.PE) -> tuple[str | None, str | None]:
    """(CompanyName, ProductName) from the version resource; needs the resource dir parsed."""
    company = product = None
    for fi in getattr(pe, "FileInfo", None) or []:
        for entry in fi:
            for st in getattr(entry, "StringTable", None) or []:
                company = company or _decode(st.entries.get(b"CompanyName"))
                product = product or _decode(st.entries.get(b"ProductName"))
    return company, product


# --- PE reading -----------------------------------------------------------------

def _is_pe_magic(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False

_MAX_DATA_SCAN = 32 * _MB   # data bytes scanned per file for code pointers
_CALL_RE = re.compile(rb"[\xe8](....)", re.S)    # call rel32
_PUSH_RE = re.compile(rb"[\x68](....)", re.S)    # push imm32


def estimate_functions(pe: pefile.PE) -> int:
    """Cheap estimate of the function count Ghidra will find: the distinct addresses in the code
    sections that are the target of a `call rel32`, a `push imm32`, an export, or a pointer in a
    data section. Costs one pass over the file; no disassembly."""
    base = pe.OPTIONAL_HEADER.ImageBase
    psz, fmt = (8, "Q") if pe.OPTIONAL_HEADER.Magic == 0x20B else (4, "I")
    code, data = [], []
    for s in pe.sections:
        (code if s.Characteristics & 0x20000000 or s.Characteristics & 0x20 else data).append(s)
    if not code:
        return 0
    lo = base + min(s.VirtualAddress for s in code)
    hi = base + max(s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData) for s in code)
    starts: set[int] = set()
    for s in code:
        blob, va = s.get_data(), base + s.VirtualAddress
        for m in _CALL_RE.finditer(blob):
            t = va + m.end() + struct.unpack("<i", m.group(1))[0]
            if lo <= t < hi:
                starts.add(t)
        for m in _PUSH_RE.finditer(blob):
            t = struct.unpack("<I", m.group(1))[0]
            if lo <= t < hi:
                starts.add(t)
    budget = _MAX_DATA_SCAN
    for s in data:
        blob = s.get_data()[:budget]
        budget -= len(blob)
        n = len(blob) // psz
        if n:
            starts.update(v for v in struct.unpack(f"<{n}{fmt}", blob[:n * psz]) if lo <= v < hi)
        if budget <= 0:
            break
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    for sym in (exp.symbols if exp is not None else ()):
        t = base + sym.address
        if lo <= t < hi:
            starts.add(t)
    return len(starts)


_FRAMEWORK_RE = re.compile(
    r"^(system|microsoft|windowsbase|presentation\w*|netstandard|mscorlib|uiautomation\w*)(\.|$)", re.I)
# well-known NuGet libraries: referenced by the app but not part of it
_THIRD_PARTY_RE = re.compile(
    r"^(newtonsoft|mono\.|sharpdx|sharpcompress|zstdsharp|nlog|log4net|autofac|commandline|"
    r"communitytoolkit|harmony|dnlib|fody|castle|serilog|icsharpcode|kgysoft)", re.I)


def is_framework_name(name: str) -> bool:
    """A managed file name of the .NET runtime or the SDK (System.*, Microsoft.*, WindowsBase, ...)."""
    return bool(_FRAMEWORK_RE.match(Path(name.rpartition(BUNDLE_SEP)[2]).name))


def _assembly_refs(src: "Path | bytes") -> tuple[str, ...]:
    """Lowercase AssemblyRef names of a managed file (dnfile); () when unreadable."""
    try:
        import logging

        import dnfile
        logging.getLogger("dnfile").setLevel(logging.ERROR)
        pe = dnfile.dnPE(data=src, fast_load=True) if isinstance(src, bytes) \
            else dnfile.dnPE(str(src), fast_load=True)
        pe.parse_data_directories(directories=[14])
        tb = pe.net.mdtables.AssemblyRef
        return tuple(dict.fromkeys(str(r.Name.value).lower() for r in (tb.rows if tb else ())))
    except Exception:  # noqa: BLE001  the refs are an extra for grouping
        return ()


def _read_pe(path: "Path | None", rel: str, size: int, data: "bytes | None" = None) -> ScannedFile:
    def unreadable() -> ScannedFile:
        return ScannedFile(rel, "pe", "unreadable", size, 0, None, False, False, False,
                           None, None, (), 0)

    try:
        pe = pefile.PE(str(path), fast_load=True) if data is None \
            else pefile.PE(data=data, fast_load=True)
    except (pefile.PEFormatError, OSError, ValueError, MemoryError):
        return unreadable()
    try:
        D = pefile.DIRECTORY_ENTRY
        try:
            pe.parse_data_directories(directories=[
                D["IMAGE_DIRECTORY_ENTRY_IMPORT"], D["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
                D["IMAGE_DIRECTORY_ENTRY_EXPORT"], D["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        except Exception:  # damaged directories: keep what parsed
            pass
        opt = pe.OPTIONAL_HEADER
        bits = 64 if opt.Magic == 0x20B else 32
        code = sum(s.SizeOfRawData for s in pe.sections
                   if s.Characteristics & 0x20000000 or s.Characteristics & 0x20)
        names: list[str] = []
        for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for e in getattr(pe, attr, []) or []:
                if e.dll:
                    names.append(e.dll.decode("latin-1").lower())
        exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        n_exports = len(exp.symbols) if exp is not None else 0
        com = D["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        dds = opt.DATA_DIRECTORY
        dotnet = len(dds) > com and bool(dds[com].VirtualAddress and dds[com].Size)
        try:
            rich = pe.parse_rich_header() is not None
        except Exception:
            rich = False
        company, product = extract_vendor(pe)
        r2r = bool(dotnet and is_r2r(pe))
        managed = bool(dotnet and (r2r or (cor_flags(pe) or 0) & COR_ILONLY))
        aot = bool(not dotnet and is_nativeaot(pe))
        entry = cli_entry_token(pe) if dotnet else 0
        meta = 0
        refs: tuple[str, ...] = ()
        if managed:
            code = 0       # IL is not code for Ghidra: the assembly costs seconds, not analysis time
            h = _cli_header(pe)
            meta = int.from_bytes(h[12:16], "little") if h else 0
        try:
            funcs = 0 if dotnet else estimate_functions(pe)
        except Exception:  # the estimate is an extra: the code size alone still gives a time
            funcs = 0
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000) and not entry
        return ScannedFile(rel, "pe", "", size, code, bits,
                           is_dll, bool(dotnet), rich,
                           company, product, tuple(dict.fromkeys(names)), n_exports,
                           opt.Subsystem, _description(pe), funcs, managed,
                           has_entry=bool(entry), meta_size=meta, refs=refs, r2r=r2r, nativeaot=aot)
    except Exception:
        return unreadable()
    finally:
        pe.close()


# --- grouping -------------------------------------------------------------------

def assign_groups(files: list[ScannedFile], root_rel: str | None,
                  refs_of: "Callable[[ScannedFile], tuple[str, ...]] | None" = None) -> list[ScannedFile]:
    """Set `group` on PE files (data/unreadable keep theirs). Pure function of the features;
    `refs_of` reads the AssemblyRef names of a managed file on demand (default: `f.refs`)."""
    refs_of = refs_of or (lambda f: f.refs)
    pes = [f for f in files if f.kind == "pe" and f.group != "unreadable"]
    by_name: dict[str, list[ScannedFile]] = defaultdict(list)
    for f in pes:
        by_name[Path(f.rel_path).name.lower()].append(f)

    groups: dict[str, str] = {}
    fw_root = root_rel is not None and is_framework_name(root_rel)   # a framework assembly chosen as root
    for f in pes:
        if is_runtime_name(Path(f.rel_path).name) or (f.dotnet and not fw_root
                                                      and is_framework_name(f.rel_path)):
            groups[f.rel_path] = "runtime"
        elif f.apphost:
            groups[f.rel_path] = "apphost"      # the managed app dll is analysed instead

    root = next((f for f in pes if f.rel_path == root_rel), None)
    root_vendor = normalise_vendor(root.company) if root else None
    core: set[str] = set()

    def where(f: ScannedFile) -> str:      # assemblies resolve by simple name beside the referrer
        return f.rel_path.rpartition(BUNDLE_SEP)[0] or str(Path(f.rel_path).parent)

    def stem(f: ScannedFile) -> str:
        return Path(f.rel_path.rpartition(BUNDLE_SEP)[2]).stem.lower()

    by_stem: dict[tuple[str, str], list[ScannedFile]] = defaultdict(list)
    for f in pes:
        if f.dotnet:
            by_stem[(where(f), stem(f))].append(f)
    if root and root.rel_path not in groups:
        core.add(root.rel_path)
        stack = [root]
        while stack:
            cur = stack.pop()
            for ref in refs_of(cur):   # managed: own assemblies are the ones the app references
                for cand in by_stem.get((where(cur), ref), ()):
                    if cand.rel_path in core or cand.rel_path in groups:
                        continue
                    v = normalise_vendor(cand.company)
                    if v is None:
                        ok = not _THIRD_PARTY_RE.match(stem(cand))
                    else:
                        ok = vendor_matches(root_vendor, v)
                    if ok:
                        core.add(cand.rel_path)
                        stack.append(cand)
            for imp in cur.imports:
                for cand in by_name.get(imp, ()):
                    if cand.rel_path in core or cand.rel_path in groups or not cand.is_dll:
                        continue
                    v = normalise_vendor(cand.company)
                    if v is None or vendor_matches(root_vendor, v):
                        core.add(cand.rel_path)
                        stack.append(cand)
    for f in pes:
        if f.rel_path in groups:
            continue
        if f.rel_path in core:
            groups[f.rel_path] = "core"
        elif not f.is_dll:
            groups[f.rel_path] = "separate_exe"
        else:
            v = normalise_vendor(f.company)
            groups[f.rel_path] = "own_plugin" if vendor_matches(root_vendor, v) else "third_party"
    return [dataclasses.replace(f, group=groups[f.rel_path]) if f.rel_path in groups else f
            for f in files]


# --- apphosts and single-file bundles -----------------------------------------------

def _host_files(full: Path, rel: str, sf: ScannedFile, files: list[ScannedFile]) -> ScannedFile:
    """A single-file bundle contributes its managed entries as virtual files ``host.exe!X.dll``; an
    apphost points at the managed dll beside it. Returns the host file (``apphost`` = the app dll);
    a plain native exe comes back unchanged."""
    entries = bundle_manifest(full)
    if entries:
        hstem = Path(rel).stem.lower()
        app = ""
        found: list[ScannedFile] = []
        for e in entries:
            if e.kind != "assembly":
                continue
            erel = f"{rel}{BUNDLE_SEP}{e.path}"
            if is_framework_name(e.path):      # framework assemblies are not parsed: names only
                found.append(ScannedFile(erel, "pe", "", e.size, 0, None, True, True, False, None,
                                         None, (), 0, managed=True))
                continue
            try:
                data = read_bundle_entry(full, e)
            except Exception:  # noqa: BLE001  damaged entry: listed as unreadable
                found.append(ScannedFile(erel, "pe", "unreadable", e.size, 0, None, False, False,
                                         False, None, None, (), 0))
                continue
            found.append(_read_pe(None, erel, e.size, data))
        for f in found:
            if f.has_entry and (Path(f.rel_path.partition(BUNDLE_SEP)[2]).stem.lower() == hstem
                                or not app):
                app = f.rel_path
        files.extend(found)
        return dataclasses.replace(sf, apphost=app) if app else sf
    if bundle_marker(full) == 0:                    # an apphost: the managed dll lies beside it
        for name in apphost_targets(full):
            if (full.parent / name).is_file():
                return dataclasses.replace(sf, apphost=(name if "/" not in rel else rel.rsplit("/", 1)[0] + "/" + name))
    return sf


# --- scan -----------------------------------------------------------------------

def _pick_root(files: list[ScannedFile], named: str | None,
               base: Path) -> tuple[str | None, str, list[tuple[str, int]], bool,
                                    list[tuple[str, int, str]]]:
    pes = [f for f in files if f.kind == "pe" and f.group != "unreadable"]
    if named:
        n = named.replace("\\", "/").strip("/")
        try:
            p = Path(named)
            if p.is_absolute():
                n = p.resolve().relative_to(base.resolve()).as_posix()
        except ValueError:
            pass
        low = n.lower()
        hits = [f for f in pes if f.rel_path.lower() == low] or \
               [f for f in pes if Path(f.rel_path).name.lower() == low.rsplit("/", 1)[-1]]
        if hits:
            hit = min(hits, key=lambda f: f.rel_path.count("/"))
            if hit.apphost:
                return hit.apphost, f"named by user: apphost {Path(hit.rel_path).name}", [], False, []
            return hit.rel_path, "named by user", [], False, []
        return None, f"named executable '{named}' not found as a PE", [], False, []
    elig = [f for f in pes if is_root_candidate(f)]
    fallback = ""
    if not elig:
        elig = [f for f in pes if not f.is_dll and f.subsystem != 1]
        fallback = "only installer-like executables found; "
    top = [f for f in elig if "/" not in f.rel_path]
    pool, where = (top, "in top folder") if top else (elig, "(none in top folder)")
    if not pool:
        return None, "no executable found", [], False, []
    ranking = _score_roots(pool, pes, base.name)
    best = ranking[0]
    amb = len(ranking) > 1 and best[1] - ranking[1][1] < 2
    code = {f.rel_path: f.code_size for f in pool}
    others = [(r[0], code[r[0]]) for r in ranking[1:3]]
    return (best[0], f"{fallback}best score {best[1]}: {best[2]} {where}", others, amb,
            ranking[:3])


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 3}


def _score_roots(pool: list[ScannedFile], pes: list[ScannedFile],
                 folder: str) -> list[tuple[str, int, str]]:
    """Rank root candidates: name, dominant vendor, version info, plugins, largest code."""
    vend_count: dict[str, int] = defaultdict(int)
    prod_count: dict[str, int] = defaultdict(int)
    for f in pes:
        if is_runtime_name(Path(f.rel_path).name):
            continue
        v = normalise_vendor(f.company)
        if v and "microsoft" not in v:
            vend_count[v] += 1
        if f.product and "microsoft" not in (f.company or "").lower():
            prod_count[f.product] += 1
    dominant = max(vend_count, key=vend_count.get) if vend_count else None
    ref = _tokens(folder)
    if prod_count:
        ref |= _tokens(max(prod_count, key=prod_count.get))
    biggest = max(f.code_size or f.meta_size for f in pool)
    dlls = [f for f in pes if f.is_dll]
    out = []
    for f in pool:
        score, why = 0, []
        if _name_match(Path(f.rel_path).stem, ref):
            score += 3
            why.append("name")
        v = normalise_vendor(f.company)
        if v and dominant and vendor_matches(dominant, v):
            score += 2
            why.append("vendor")
        if f.company or f.product:
            score += 1
            why.append("version info")
        if v and any(d.rel_path != f.rel_path and vendor_matches(v, normalise_vendor(d.company))
                     for d in dlls):
            score += 1
            why.append("plugins")
        if (f.code_size or f.meta_size) == biggest:
            score += 1
            why.append("largest code")
        out.append((f.rel_path, score, ", ".join(why) or "none", f.code_size or f.meta_size))
    out.sort(key=lambda t: (-t[1], -t[3]))
    return [(r, sc, w) for r, sc, w, _ in out]


def _name_match(stem: str, ref: set[str]) -> bool:
    """The file stem shares a token with the folder/product names; a stem that starts with a long
    token counts too (``DependenciesGui`` for the product ``Dependencies``)."""
    toks = _tokens(stem)
    return bool(toks & ref) or any(t.startswith(r) for t in toks for r in ref if len(r) >= 6)


def _build_options(files: list[ScannedFile], s_per_code_mb: float,
                   overhead_s: float = 6.0) -> tuple[ScanOption, ...]:
    out = []
    for key, label, groups in _OPTION_DEFS:
        if not any(f.group == _ADDED_GROUP[key] for f in files):
            continue
        sel = tuple(f for f in files if f.group in groups)
        code = sum(f.code_size for f in sel)
        n_pe = sum(1 for f in sel if f.kind == "pe" and not f.managed)
        n_managed = sum(1 for f in sel if f.kind == "pe" and f.managed)
        work = sum(est.work_mb(f.code_size, f.est_funcs) for f in sel)
        out.append(ScanOption(key, label, groups, sel, code,
                              n_pe * overhead_s + work * s_per_code_mb + n_managed * MANAGED_S))
    return tuple(out)


def scan_program(path: Path, root_exe: str | None = None,
                 s_per_code_mb: float = 170.0, overhead_s: float = 6.0) -> ScanResult:
    path = Path(path)
    if path.is_file():
        base, root_exe = path.parent, path.name
    elif path.is_dir():
        base = path
    else:
        raise FileNotFoundError(str(path))
    root_exe = root_exe or None

    files: list[ScannedFile] = []
    for dirpath, _dirs, names in os.walk(base):
        for name in sorted(names):
            full = Path(dirpath) / name
            rel = full.relative_to(base).as_posix()
            try:
                size = full.stat().st_size
            except OSError:
                files.append(ScannedFile(rel, "data", "unreadable", 0, 0, None, False, False,
                                         False, None, None, (), 0))
                continue
            if size >= 64 and _is_pe_magic(full):
                sf = _read_pe(full, rel, size)
                if not sf.dotnet and not sf.is_dll and sf.group != "unreadable":
                    sf = _host_files(full, rel, sf, files)
                files.append(sf)
            else:
                files.append(ScannedFile(rel, "data", "data", size, 0, None, False, False,
                                         False, None, None, (), 0))
    files.sort(key=lambda f: f.rel_path.lower())

    root_rel, reason, others, amb, ranking = _pick_root(files, root_exe, base)
    cache: dict[str, tuple[str, ...]] = {}

    def refs_of(f: ScannedFile) -> tuple[str, ...]:     # only the assemblies the root reaches are read
        if f.refs or not f.managed:
            return f.refs
        if f.rel_path not in cache:
            host, sep, ename = f.rel_path.partition(BUNDLE_SEP)
            refs: tuple[str, ...] = ()
            if not sep:
                refs = _assembly_refs(base / f.rel_path)
            else:
                e = next((x for x in bundle_manifest(base / host) or [] if x.path == ename), None)
                if e is not None:
                    refs = _assembly_refs(read_bundle_entry(base / host, e))
            cache[f.rel_path] = refs
        return cache[f.rel_path]

    files = assign_groups(files, root_rel, refs_of)
    pes_g = [f for f in files if f.kind == "pe" and f.group != "unreadable"]
    folder_of_framework = (root_rel is None and bool(pes_g)
                           and all(f.group == "runtime" and f.dotnet for f in pes_g))
    if folder_of_framework:     # only framework-named assemblies (R2R folder): they are the program
        files = [dataclasses.replace(f, group="core") if f in pes_g else f for f in files]

    present = {Path(f.rel_path).name.lower() for f in files}
    system = sorted({i for f in files if f.kind == "pe" for i in f.imports
                     if i not in present and not is_runtime_name(i)})

    ext: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for f in files:
        if f.group == "data":
            e = Path(f.rel_path).suffix.lower() or "(none)"
            ext[e][0] += 1
            ext[e][1] += f.size
    data_summary = tuple(sorted(((e, c, b) for e, (c, b) in ext.items()),
                                key=lambda t: (-t[1], -t[2], t[0])))

    options = _build_options(files, s_per_code_mb, overhead_s) if root_rel or folder_of_framework else ()
    keys = [o.key for o in options]
    recommended = "B" if "B" in keys else ("A" if "A" in keys else (keys[0] if keys else ""))
    return ScanResult(base, root_rel, reason, tuple(files), tuple(system), data_summary,
                      options, recommended, tuple(others), amb, tuple(ranking))


# --- render ---------------------------------------------------------------------

def _mb(n: int) -> str:
    return f"{n / _MB:.1f} MB"


def _fmt_time(sec: float) -> str:
    if sec < 90:
        return f"~{max(1, round(sec))} s"
    if sec < 120 * 60:
        return f"~{round(sec / 60)} min"
    return f"~{sec / 3600:.1f} h"


def _largest(files: tuple[ScannedFile, ...], n: int = 3) -> str:
    top = sorted((f for f in files if f.code_size), key=lambda f: -f.code_size)
    names = [Path(f.rel_path).name for f in top[:n]]
    if len(top) > n:
        names.append(f"+{len(top) - n} more")
    return ", ".join(names) or "-"


def render_scan(result: ScanResult) -> list[str]:
    files = result.files
    pes = [f for f in files if f.kind == "pe"]
    data = [f for f in files if f.kind == "data"]
    head = f"{result.root} | {len(pes)} PE, {len(data)} data | "
    if result.root_ambiguous:
        cand = ", ".join(f"{Path(p).name} (score {sc}: {w})" for p, sc, w in result.root_ranking)
        lines = [f"{head}root unclear: {cand} — root_exe= picks one"]
    else:
        why = result.root_reason
        if result.root_candidates:
            oth = ", ".join(f"{Path(p).name} {_mb(c)}" for p, c in result.root_candidates)
            why += f"; others: {oth} — root_exe= changes it"
        lines = [f"{head}root: {result.root_exe or 'none'} ({why})"]
    unread = sum(1 for f in files if f.group == "unreadable")
    if unread:
        lines.append(f"unreadable: {unread} files skipped")

    by_key = {o.key: o for o in result.options}
    prev: ScanOption | None = None
    for key, label, _g in _OPTION_DEFS:
        o = by_key.get(key)
        if o is None:
            lines.append(f"{key}. {label} | omitted: {_OMIT_WHY[key]}")
            continue
        seen = {f.rel_path for f in prev.files} if prev else set()
        added = tuple(f for f in o.files if f.rel_path not in seen)
        lines.append(f"{key}. {label} | {len(o.files)} files | {_mb(o.code_size)} code | "
                     f"{_fmt_time(o.est_seconds)} | largest (added): {_largest(added)}")
        prev = o

    for h in (f for f in files if f.apphost):
        n = sum(1 for f in files if f.rel_path.startswith(h.rel_path + BUNDLE_SEP))
        kind = f"single-file bundle, {n} assemblies" if n else "apphost"
        lines.append(f"host {Path(h.rel_path).name}: {kind}; starts "
                     f"{Path(h.apphost.rpartition(BUNDLE_SEP)[2]).name}; not analysed (add= to include)")
    r2 = sum(1 for f in files if f.r2r)
    if r2:
        lines.append(f"ReadyToRun: {r2} assemblies, read from IL and metadata; native code not imported")
    for f in files:
        if f.nativeaot:
            lines.append(f"NativeAOT: {Path(f.rel_path).name} has no .NET metadata; names only from symbols")
    rt = [f for f in files if f.group == "runtime"]
    if rt:
        lines.append(f"runtime | {len(rt)} files | {_mb(sum(f.code_size for f in rt))} code | "
                     f"not analysed by default")
    if result.system_dlls:
        lines.append(f"system DLLs imported: {len(result.system_dlls)}")
    if result.data_summary:
        top = result.data_summary[:6]
        txt = ", ".join(f"{e} {c} ({_mb(b)})" for e, c, b in top)
        more = len(result.data_summary) - len(top)
        lines.append("data: " + txt + (f", +{more} more types" if more > 0 else ""))
    if result.recommended:
        why = ("own plugins present" if result.recommended == "B"
               else "core only" if result.recommended == "A" else "first available option")
        if result.root_ambiguous:
            lines.append(f"recommended: {result.recommended} after the root_exe choice")
        else:
            lines.append(f"recommended: {result.recommended} ({why})")
    else:
        lines.append("recommended: none (no analysable executables)")
    return lines
