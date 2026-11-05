"""Cross-binary linking beyond the import table (server side, no JVM).

* ``fix_export_ordinals``: the PE export directory (pefile on the stored artifact) gives every
  export its real ordinal; Ghidra's external entry points carry none for named exports, so
  ordinal-only imports (``Ordinal_N``) could not bind.
* ``link_dynamic``: run-time loading. A function that references a project binary's file name
  and calls LoadLibrary*, and a function that calls GetProcAddress next to a string equal to
  one of that binary's export names, give xedge rows of kind ``dynamic`` (function to exported
  function) and ``dynlib`` (function to the binary only; ``dst_entry`` is -1).
* ``relink_project``: re-run all of it without re-analysis.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

import pefile

from airlock.index.store import CODE_EDGES, Binary, Store

log = logging.getLogger(__name__)

LINK_VERSION = 6   # 3: import-slot reads rewritten to call_imp edges; 4: plugin-interface links + fnptr edges; 5: string_link; 6: fnptr tables only in data sections
CODE_KINDS = CODE_EDGES
_LOAD_RE = re.compile(r"^(?:LoadLibrary(?:Ex)?[AW]?|LdrLoadDll)$")
_GPA_RE = re.compile(r"^(?:GetProcAddress|LdrGetProcedureAddress)$")
_FIND_RE = re.compile(r"^FindFirstFile(?:Ex)?[AW]?$")
_FOLDER_RE = re.compile(r"\*\.dll|[\\/]plug-?ins?[\\/]|^plug-?ins?[\\/]", re.I)
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{1,63}$")
MIN_IFACE_NAMES = 2
MAX_EVIDENCE = 200


def _clean(name: str | None) -> str:
    n = (name or "").strip()
    for p in ("__imp_", "_imp__", "imp_"):
        if n.startswith(p):
            n = n[len(p):]
            break
    if n.startswith("_") and n[1:2].isupper():
        n = n[1:]
    if "@" in n and not n.startswith("@"):
        n = n.split("@", 1)[0]
    return n


# ── export ordinals ────────────────────────────────────────────────────────

def pe_exports(path: Path) -> tuple[int, list[tuple[str | None, int, int | None]]] | None:
    """(image base, [(name, ordinal, address)]) from the export directory; forwarded exports
    have no address. None when the file is not a PE with exports."""
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except (pefile.PEFormatError, OSError):
        return None
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        d = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if d is None:
            return None
        base = int(pe.OPTIONAL_HEADER.ImageBase)
        out: list[tuple[str | None, int, int | None]] = []
        for s in d.symbols:
            name = s.name.decode("latin-1") if s.name else None
            addr = None if getattr(s, "forwarder", None) else base + int(s.address)
            out.append((name, int(s.ordinal), addr))
        return base, out
    finally:
        pe.close()


_SCN_EXEC, _SCN_READ = 0x20000000, 0x40000000


def pe_data_ranges(path: Path) -> list[tuple[int, int]] | None:
    """Virtual address ranges ``[start, end)`` of the readable, non-executable sections of a PE
    (.rdata, .data, ...). None when the file is not a PE."""
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except (pefile.PEFormatError, OSError):
        return None
    try:
        base = int(pe.OPTIONAL_HEADER.ImageBase)
        out: list[tuple[int, int]] = []
        for sec in pe.sections:
            ch = int(sec.Characteristics)
            if ch & _SCN_READ and not ch & _SCN_EXEC:
                size = max(int(sec.Misc_VirtualSize), int(sec.SizeOfRawData))
                out.append((base + int(sec.VirtualAddress), base + int(sec.VirtualAddress) + size))
        return out
    finally:
        pe.close()


def record_sections(store: Store, binary_id: int, artifact: Path | None) -> bool:
    """Store the data-section ranges of the binary (meta ``data_ranges:<id>``) for ``link_fnptr``.
    False when the artifact is missing or no PE (the table rule then has no section check)."""
    if artifact is None or not artifact.is_file():
        return False
    ranges = pe_data_ranges(artifact)
    if ranges is None:
        return False
    with store.db:
        store.set_meta(f"data_ranges:{binary_id}", json.dumps(ranges, separators=(",", ":")))
    return True


def apply_pe_exports(store: Store, binary_id: int,
                     pe_syms: Iterable[tuple[str | None, int, int | None]]) -> int:
    """Merge the PE export directory into the binary's export rows: set the ordinal on rows
    matching by name (or by ordinal), then by address; add rows the worker did not list.
    Returns the number of ordinals set or rows added."""
    rows = [dict(r) for r in store.db.execute(
        "SELECT rowid AS rid, name, ordinal, address FROM export WHERE binary_id=?", (binary_id,))]
    by_name = defaultdict(list)
    by_addr = defaultdict(list)
    for r in rows:
        if r["name"]:
            by_name[r["name"]].append(r)
        by_addr[r["address"]].append(r)
    n = 0
    with store.db:
        for name, ordinal, addr in pe_syms:
            if addr is None:
                continue
            if name:
                cands = by_name.get(name, [])
                hit = next((r for r in cands if r["address"] == addr), None) or                     next(iter(cands), None)
            else:
                hit = next((r for r in by_addr.get(addr, ())
                            if r["name"] == f"Ordinal_{ordinal}"), None)
            if hit is not None:
                if hit["ordinal"] != ordinal:
                    store.db.execute("UPDATE export SET ordinal=? WHERE rowid=?", (ordinal, hit["rid"]))
                    hit["ordinal"] = ordinal
                    n += 1
                continue
            store.db.execute("INSERT INTO export(binary_id, name, ordinal, address) VALUES (?,?,?,?)",
                             (binary_id, name or f"Ordinal_{ordinal}", ordinal, addr))
            n += 1
    return n


def fix_export_ordinals(store: Store, b: Binary, artifact: Path) -> int:
    """Record the real export ordinal of every export of ``b`` from its stored artifact."""
    if not artifact.is_file():
        return 0
    got = pe_exports(artifact)
    if got is None:
        return 0
    return apply_pe_exports(store, b.id, got[1])


# ── dynamic links ──────────────────────────────────────────────────────────

@dataclass
class _Src:
    """What one binary does with strings and the loader APIs (built once per binary)."""
    strings: dict[int, str] = field(default_factory=dict)
    str_refs: dict[int, set[int]] = field(default_factory=lambda: defaultdict(set))
    ll_fns: set[int] = field(default_factory=set)
    gpa_fns: set[int] = field(default_factory=set)
    find_fns: set[int] = field(default_factory=set)
    iface: tuple | None = None
    out: dict[int, set[int]] = field(default_factory=lambda: defaultdict(set))
    inn: dict[int, set[int]] = field(default_factory=lambda: defaultdict(set))
    entry_of: dict[int, int] = field(default_factory=dict)


def _src_info(store: Store, binary_id: int) -> _Src:
    q = store.db.execute
    info = _Src()
    for r in q("SELECT address, value FROM string WHERE binary_id=?", (binary_id,)):
        info.strings[r["address"]] = r["value"]
    for r in q("SELECT id, entry FROM function WHERE binary_id=? AND space='ram'", (binary_id,)):
        info.entry_of[r["id"]] = r["entry"]
    ll: set[int] = set()      # slot addresses and thunk entries of the loader APIs
    gpa: set[int] = set()
    find: set[int] = set()
    thunks: set[int] = set()
    for r in q("SELECT name, address FROM import WHERE binary_id=? AND address IS NOT NULL", (binary_id,)):
        n = _clean(r["name"])
        (ll if _LOAD_RE.match(n) else gpa if _GPA_RE.match(n) else find if _FIND_RE.match(n) else set()
         ).add(r["address"])
    for r in q("SELECT id, name, entry, is_thunk FROM function WHERE binary_id=? AND space='ram' "
               "AND (is_thunk=1 OR is_external=1)", (binary_id,)):
        if r["is_thunk"]:
            thunks.add(r["id"])
        n = _clean(r["name"])
        (ll if _LOAD_RE.match(n) else gpa if _GPA_RE.match(n) else find if _FIND_RE.match(n) else set()
         ).add(r["entry"])
    for r in q("SELECT src_fn, dst_addr, dst_fn, kind FROM edge WHERE binary_id=? AND src_fn IS NOT NULL",
               (binary_id,)):
        k = r["kind"]
        if k in CODE_KINDS or k in ("read", "data"):
            # a slot read counts too (projects not yet normalised); a thunk is not a source itself:
            # its callers are, through the thunk entry in ll / gpa
            if r["dst_addr"] in ll and r["src_fn"] not in thunks:
                info.ll_fns.add(r["src_fn"])
            if r["dst_addr"] in gpa and r["src_fn"] not in thunks:
                info.gpa_fns.add(r["src_fn"])
            if r["dst_addr"] in find and r["src_fn"] not in thunks:
                info.find_fns.add(r["src_fn"])
        if k in CODE_KINDS:
            if r["dst_fn"] is not None and r["dst_fn"] != r["src_fn"]:
                info.out[r["src_fn"]].add(r["dst_fn"])
                info.inn[r["dst_fn"]].add(r["src_fn"])
        elif k in ("read", "data") and r["dst_addr"] in info.strings:
            info.str_refs[r["src_fn"]].add(r["dst_addr"])
    return info


def _basename(v: str) -> str:
    return re.split(r"[\\/]", v.strip().strip('"'))[-1].strip().lower()


def link_dynamic(store: Store, src_id: int, dst_id: int, info: _Src | None = None) -> int:
    """Rebuild the ``dynamic``/``dynlib`` xedges from ``src_id`` to ``dst_id``; returns the
    number of rows. Without a literal LoadLibrary name, the plugin-interface rule applies."""
    info = info or _src_info(store, src_id)
    n = _link_literal(store, src_id, dst_id, info)
    if n == 0 and src_id != dst_id:
        n = link_interface(store, src_id, dst_id, info)
    return n


def _iface_names(store: Store, info: _Src) -> tuple[dict[str, list[int]], bool, str]:
    """GetProcAddress name strings of a host: (name -> site functions, folder-scan evidence, the
    plugin-folder text). Names that are imports of any project binary or known API names are not
    interface names."""
    if info.iface is not None:
        return info.iface
    from airlock.server.graph import api_category   # late: graph imports the store
    imported = {r["name"] for r in store.db.execute(
        "SELECT DISTINCT name FROM import WHERE name IS NOT NULL")}
    names: dict[str, list[int]] = {}
    for g in sorted(info.gpa_fns):
        for f in sorted({g} | info.out.get(g, set()) | info.inn.get(g, set())):
            for a in sorted(info.str_refs.get(f, ())):
                v = info.strings[a].strip()
                if (not _IDENT_RE.match(v) or v in imported or _clean(v) in imported
                        or api_category(v)):
                    continue
                sites = names.setdefault(v, [])
                if g not in sites:
                    sites.append(g)
    scan, text = False, ""
    for f in sorted(info.str_refs):
        for a in sorted(info.str_refs[f]):
            if _FOLDER_RE.search(info.strings[a]):
                scan, text = True, info.strings[a][:MAX_EVIDENCE]
                break
        if scan:
            break
    if not scan and info.find_fns & info.ll_fns:
        scan, text = True, "FindFirstFile + LoadLibrary"
    info.iface = (names, scan, text)
    return info.iface


def link_interface(store: Store, src_id: int, dst_id: int, info: _Src | None = None) -> int:
    """Plugin-interface links: ``dst`` exports at least MIN_IFACE_NAMES of the names the host
    resolves with GetProcAddress (one name when the host scans a plugin folder) and the host
    calls LoadLibrary*. Rows: ``dynamic`` from each GetProcAddress site to each matching export,
    one ``dynlib`` per binary pair. Returns the number of rows added."""
    dst = store.get_binary_by_id(dst_id)
    if dst is None or src_id == dst_id:
        return 0
    info = info or _src_info(store, src_id)
    if not info.ll_fns or not info.gpa_fns:
        return 0
    names, scan, scan_text = _iface_names(store, info)
    if not names:
        return 0
    exports: dict[str, int] = {}
    for e in store.exports_of(dst_id):
        if e["name"] and not e["name"].startswith("Ordinal_"):
            exports.setdefault(e["name"], e["address"])
    hit = sorted(n for n in names if n in exports)
    if len(hit) < (1 if scan else MIN_IFACE_NAMES):
        return 0
    how = "folder scan" if scan else "run-time path"
    rows: list[tuple[int, int, int, int, str, str]] = []
    lib_fn = sorted(info.find_fns & info.ll_fns or info.ll_fns)[0]
    if info.entry_of.get(lib_fn) is not None:
        rows.append((src_id, info.entry_of[lib_fn], dst_id, -1, "dynlib",
                     f"LoadLibrary by {how}" + (f' "{scan_text}"' if scan_text else "")))
    n_dyn = 0
    for name in hit:
        fnd = store.function_containing(dst_id, exports[name])
        entry = fnd.entry if fnd is not None else exports[name]
        for g in names[name]:
            gentry = info.entry_of.get(g)
            if gentry is not None:
                n_dyn += 1
                rows.append((src_id, gentry, dst_id, entry, "dynamic",
                             f"interface name {name}; loaded by {how}"))
    if not n_dyn:
        return 0
    with store.db:
        store.db.executemany(
            "INSERT INTO xedge(src_binary, src_addr, dst_binary, dst_entry, kind, evidence) "
            "VALUES (?,?,?,?,?,?)", rows)
    return len(rows)


def _link_literal(store: Store, src_id: int, dst_id: int, info: _Src) -> int:
    dst = store.get_binary_by_id(dst_id)
    with store.db:
        store.db.execute("DELETE FROM xedge WHERE src_binary=? AND dst_binary=? "
                         "AND kind IN ('dynamic','dynlib')", (src_id, dst_id))
    if dst is None or src_id == dst_id:
        return 0
    if not info.ll_fns:
        return 0
    full = dst.name.lower()
    stem = full.rsplit(".", 1)[0] if "." in full else full
    lib_ev: dict[int, str] = {}
    for fn in info.ll_fns:
        for a in sorted(info.str_refs.get(fn, ())):
            v = info.strings[a]
            b = _basename(v)
            if b == full or (b == stem and len(stem) >= 3):
                lib_ev[fn] = v[:MAX_EVIDENCE]
                break
    if not lib_ev:
        return 0
    rows: list[tuple[int, int, int, int, str, str]] = []
    lib_text = next(iter(lib_ev.values()))
    for fn, v in lib_ev.items():
        entry = info.entry_of.get(fn)
        if entry is not None:
            rows.append((src_id, entry, dst_id, -1, "dynlib", f'LoadLibrary "{v}"'))
    exports: dict[str, int] = {}
    for e in store.exports_of(dst_id):
        if e["name"] and not e["name"].startswith("Ordinal_"):
            exports.setdefault(e["name"], e["address"])
    seen: set[tuple[int, int]] = set()
    for g in sorted(info.gpa_fns):
        gentry = info.entry_of.get(g)
        if gentry is None:
            continue
        hood = {g} | info.out.get(g, set()) | info.inn.get(g, set())
        for f in sorted(hood):
            for a in sorted(info.str_refs.get(f, ())):
                name = info.strings[a]
                addr = exports.get(name)
                if addr is None:
                    continue
                fnd = store.function_containing(dst_id, addr)
                entry = fnd.entry if fnd is not None else addr
                if (g, entry) in seen:
                    continue
                seen.add((g, entry))
                rows.append((src_id, gentry, dst_id, entry, "dynamic",
                             f'GetProcAddress "{name[:MAX_EVIDENCE]}"; LoadLibrary "{lib_text}"'))
    with store.db:
        store.db.executemany(
            "INSERT INTO xedge(src_binary, src_addr, dst_binary, dst_entry, kind, evidence) "
            "VALUES (?,?,?,?,?,?)", rows)
    return len(rows)


def link_dynamic_for(store: Store, binary_id: int, others: Iterable[int]) -> int:
    """Dynamic links in both directions between ``binary_id`` and each of ``others``."""
    n = 0
    mine = _src_info(store, binary_id)
    for o in others:
        if o == binary_id:
            continue
        n += link_dynamic(store, binary_id, o, mine)
        n += link_dynamic(store, o, binary_id)
    return n


# ── project-wide relink ────────────────────────────────────────────────────

def ready_ids(store: Store) -> list[int]:
    return [b.id for b in store.list_binaries() if store.get_meta(f"status:{b.id}") == "ready"]


def needs_relink(store: Store) -> bool:
    """A ready project whose links predate ``LINK_VERSION`` (or without export ordinals)."""
    ids = ready_ids(store)
    if not ids:
        return False
    try:
        v = int(store.get_meta("link_version") or 0)
    except ValueError:
        v = 0
    return v < LINK_VERSION


def relink_project(store: Store, artifacts: Path, after: Callable[[], None] | None = None) -> int:
    """Fix export ordinals from the artifacts, re-normalise import-slot edges (read -> call_imp),
    then rebuild import and dynamic links of all ready binaries. No Ghidra, no re-analysis.
    ``after`` runs last (the feature re-derivation hook); the cluster/graph caches re-key on the
    edge normalisation state and ``link_version``. Returns the number of xedge rows afterwards."""
    ids = ready_ids(store)
    for i in ids:
        b = store.get_binary_by_id(i)
        if b is None:
            continue
        try:
            fix_export_ordinals(store, b, artifacts / b.sha256)
        except Exception as e:  # noqa: BLE001  a broken PE must not stop the others
            log.warning("export ordinals of %s: %s", b.name, e)
    for i in ids:
        store.normalise_import_edges(i)
    for k, i in enumerate(ids):
        store.link_cross_binary(i, ids[k + 1:])
        link_dynamic_for(store, i, ids[k + 1:])
    for i in ids:
        b = store.get_binary_by_id(i)
        try:
            if b is not None:
                record_sections(store, i, artifacts / b.sha256)
        except Exception as e:  # noqa: BLE001
            log.warning("sections of binary %s: %s", i, e)
        try:
            store.link_fnptr(i)
        except Exception as e:  # noqa: BLE001
            log.warning("function-pointer edges of binary %s: %s", i, e)
        try:
            store.link_string_tables(i)
        except Exception as e:  # noqa: BLE001
            log.warning("string tables of binary %s: %s", i, e)
    with store.db:
        store.set_meta("link_version", str(LINK_VERSION))
    if after is not None:
        try:
            after()
        except Exception as e:  # noqa: BLE001  features are an extra
            log.warning("feature re-derivation after relink failed: %s", e)
    return int(store.db.execute("SELECT COUNT(*) FROM xedge").fetchone()[0])
