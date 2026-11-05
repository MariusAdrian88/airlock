"""The project map (DESIGN 4 "Project map and feature index"): seven fixed sections, regenerated
by airlock into ``dirty\\PROJECT.md``; the clean map (``clean\\PROJECT.md``) holds the project
name, the purpose and the published specs only. Server side, no Ghidra.

Every line carries the identifiers needed for the next call (binary, function, 0x address,
feature key, topic).
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
from pathlib import Path, PurePosixPath
from typing import Any

import json5

from airlock import logs
from airlock.index.store import CODE_SQL, DN_METHOD_HI, DN_METHOD_LO, Store
from airlock.projects import ProjectPaths, atomic_write_text, read_manifest
from airlock.server import clusters as cl
from airlock.server import features as fx
from airlock.server.selectors import fmt_addr
from airlock.server.delphi import ui_line as delphi_ui_line
from airlock.server.qt import ui_line as qt_ui_line
from airlock.server.uijoin import ui_line

log = logging.getLogger("airlock")

SECTIONS = ("Purpose", "Binaries", "Relations", "Features", "Subsystems", "Knowledge", "Frontier",
            "Where to write")
SUBSYSTEMS_TOP = 10
FIRST_SECTIONS = ("Purpose", "Binaries", "Features")   # what project_open returns
FRONTIER_TOP = 10
_MB = 1 << 20
PURPOSE_KEY = "purpose"
_COM_EXPORTS = ("DllRegisterServer", "DllGetClassObject", "DllCanUnloadNow", "DllUnregisterServer")


# -- helpers -----------------------------------------------------------------------

def plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def get_purpose(store: Store) -> str:
    return store.get_meta(PURPOSE_KEY) or ""


def set_purpose(store: Store, text: str) -> None:
    with store.db:
        store.set_meta(PURPOSE_KEY, " ".join(text.split()))


def load_manifest(pp: ProjectPaths) -> dict[str, Any]:
    try:
        return read_manifest(pp.manifest)
    except (OSError, ValueError):
        return {}


def _file_for(man: dict[str, Any], name: str, sha: str) -> dict[str, Any]:
    files = [f for f in man.get("files") or [] if isinstance(f, dict)]
    for f in files:
        if f.get("sha256") == sha:
            return f
    low = name.lower()
    return next((f for f in files if PurePosixPath(str(f.get("path", "")).replace("\\", "/")).name.lower()
                 == low), {})


def _status(store: Store, bid: int) -> str:
    return store.get_meta(f"status:{bid}") or "queued"


def _table_exists(store: Store, name: str) -> bool:
    return store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                            (name,)).fetchone() is not None


def _fn_label(store: Store, binary_name: str, psize: int, space: str, entry: int,
              name: str | None, ns: str | None) -> str:
    q = f"{ns}::{name}" if ns else (name or "?")
    return f"{q} ({fmt_addr(entry, psize, space)}) in {binary_name}"


# -- sections ------------------------------------------------------------------------

def _binaries(store: Store, man: dict[str, Any]) -> list[Any]:
    return list(store.list_binaries())


def purpose_lines(pp: ProjectPaths, store: Store, man: dict[str, Any]) -> list[str]:
    src = man.get("source") or {}
    text = get_purpose(store) or "(not set. Call project_describe with a short paragraph.)"
    out = [text]
    bits = [f"root {src.get('root_exe', '?')}"]
    if src.get("path"):
        bits.insert(0, f"source {src['path']}")
    if man.get("selected_option"):
        bits.append(f"option {man['selected_option']}")
    out.append(" | ".join(bits))
    return out


def _roles(store: Store, man: dict[str, Any], bins: list[Any]) -> dict[int, str]:
    root = str((man.get("source") or {}).get("root_exe", "")).replace("\\", "/")
    root_name = PurePosixPath(root).name.lower()
    imported_by: dict[int, list[str]] = {}
    names = {b.id: b.name for b in bins}
    for r in store.db.execute("SELECT DISTINCT src_binary, dst_binary FROM xedge"):
        imported_by.setdefault(r["dst_binary"], []).append(names.get(r["src_binary"], "?"))
    out: dict[int, str] = {}
    for b in bins:
        f = _file_for(man, b.name, b.sha256)
        group = f.get("group") or "other"
        exps = [e["name"] for e in store.exports_of(b.id) if e["name"]]
        com = [n for n in exps if n in _COM_EXPORTS]
        used = sorted(set(imported_by.get(b.id, [])))
        if b.name.lower() == root_name:
            role = "main program"
        elif group == "runtime":
            role = "runtime library (excluded from features)"
        elif com:
            role = f"COM server: exports {', '.join(com[:2])}"
        elif group == "own_plugin":
            role = f"plugin: exports {', '.join(exps[:3])}" if exps else "plugin"
            if used:
                role += f"; used by {', '.join(used[:3])}"
        elif b.name.lower().endswith((".dll", ".ocx")):
            role = f"library: {len(exps)} exports"
            role += f", used by {', '.join(used[:3])}" if used else ", no import from the project"
        else:
            role = "separate executable"
        out[b.id] = role
    return out


def binaries_lines(pp: ProjectPaths, store: Store, man: dict[str, Any]) -> list[str]:
    bins = _binaries(store, man)
    if not bins:
        return ["(no binary imported yet. Call project_create or open_binary.)"]
    roles = _roles(store, man, bins)
    out = []
    for b in bins:
        f = _file_for(man, b.name, b.sha256)
        st = _status(store, b.id)
        states = store.count_by_name_state(b.id)
        total = sum(states.values())
        named = total - states.get("auto", 0)
        code = f.get("code_size")
        tool = " ".join(x for x in (b.toolchain, b.toolchain_ver) if x) or "?"
        out.append(" | ".join([
            b.name, f.get("group") or "other", st,
            f"code {code / _MB:.1f} MB" if code else "code ?",
            f"functions {named}/{total} named" if total else "functions -",
            tool, roles[b.id]]))
        ui = ui_line(store, b.id) or delphi_ui_line(store, b.id) or qt_ui_line(store, b.id)
        if ui:
            out.append(f"  {ui}")
    out.append("Detail: outline(binary=<name>), search(query), strings(pattern), list_binaries.")
    return out


def relations_lines(pp: ProjectPaths, store: Store, man: dict[str, Any]) -> list[str]:
    bins = {b.id: b for b in store.list_binaries()}
    out = []
    for r in store.db.execute(
            "SELECT src_binary, dst_binary, COUNT(DISTINCT src_addr) AS n FROM xedge "
            "WHERE kind='import' "
            "GROUP BY src_binary, dst_binary ORDER BY n DESC, src_binary, dst_binary"):
        s, d = bins.get(r["src_binary"]), bins.get(r["dst_binary"])
        if s and d:
            out.append(f"{s.name} -> {d.name}: {r['n']} imports. "
                       f"xrefs(binary={d.name}, ...) shows the callers on the other side.")
    for r in store.db.execute(
            "SELECT src_binary, dst_binary, "
            "COUNT(DISTINCT CASE WHEN kind='dynlib' THEN src_addr END) AS nl, "
            "COUNT(DISTINCT CASE WHEN kind='dynamic' THEN src_addr END) AS ng FROM xedge "
            "WHERE kind IN ('dynamic','dynlib') AND COALESCE(evidence,'') NOT LIKE '%interface name%' "
            "AND COALESCE(evidence,'') NOT LIKE 'LoadLibrary by %' "
            "GROUP BY src_binary, dst_binary "
            "ORDER BY nl DESC, ng DESC, src_binary, dst_binary"):
        s, d = bins.get(r["src_binary"]), bins.get(r["dst_binary"])
        if s and d:
            via = [f"{r['nl']} via LoadLibrary"] if r["nl"] else []
            if r["ng"]:
                via.append(f"{r['ng']} via GetProcAddress")
            out.append(f"{s.name} -> {d.name}: {', '.join(via)} (dynamic). "
                       f"xrefs(binary={d.name}, kind=\"dynamic\") shows the callers.")
    for r in store.db.execute(
            "SELECT src_binary, dst_binary, COUNT(DISTINCT evidence) AS n, "
            "MAX(CASE WHEN evidence LIKE '%folder scan%' THEN 1 ELSE 0 END) AS scan FROM xedge "
            "WHERE kind='dynamic' AND evidence LIKE '%interface name%' "
            "GROUP BY src_binary, dst_binary ORDER BY n DESC, src_binary, dst_binary"):
        s, d = bins.get(r["src_binary"]), bins.get(r["dst_binary"])
        if s and d:
            out.append(f"{s.name} -> {d.name}: {r['n']} interface names via GetProcAddress "
                       f"({'folder scan' if r['scan'] else 'run-time path'}, plugin interface). "
                       f"xrefs(binary={d.name}, kind=\"dynamic\") shows the callers.")
    for r in store.db.execute(
            "SELECT e.binary_id AS b, COUNT(*) AS n FROM feature_entry e WHERE e.feature_key='plugins' "
            "AND e.depth=0 AND e.reason LIKE 'calls LoadLibrary%' GROUP BY e.binary_id"):
        if r["b"] in bins:
            out.append(f"{bins[r['b']].name}: {r['n']} functions call LoadLibrary (dynamic loading). "
                       "feature(key=\"plugins\") lists them.")
    for b in bins.values():
        names = [e["name"] for e in store.exports_of(b.id) if e["name"]]
        com = [n for n in names if n in _COM_EXPORTS]
        if com:
            out.append(f"{b.name}: COM registration exports {', '.join(com)}.")
        elif names and (_file_for(man, b.name, b.sha256).get("group") == "own_plugin"):
            out.append(f"{b.name}: plugin interface exports {', '.join(names[:6])}"
                       + (f" (+{len(names) - 6} more)" if len(names) > 6 else "") + ".")
    return out or ["(no relations between the project's binaries yet.)"]


def features_lines(store: Store) -> list[str]:
    rows = fx.stats(store)
    if not rows:
        return ["(no features derived yet. They appear when a binary is ready; "
                "feature_define adds one by hand.)"]
    out = []
    drop = fx.dropped(store)
    for r in rows:
        tag = " [agent]" if r["source"] == "agent" else ""
        out.append(f"{r['key']}{tag} | {r['title']} | {fx.size_text(r, drop.get(r['key'], 0))} | "
                   f"{fx.coverage(r['n'], r['named'])} | feature(key=\"{r['key']}\")")
    return out


def subsystems_lines(pp: ProjectPaths, store: Store, runtime: set[int] | None = None) -> list[str]:
    """Section 4b: the top call-graph clusters (dirty map only)."""
    try:
        lines = cl.cluster_summary_lines(cl.clusters_for(pp, store, runtime=runtime), limit=SUBSYSTEMS_TOP)
    except Exception as e:  # noqa: BLE001  the map is an extra
        logs.project_log(pp.logs).warning("subsystems section failed for %s: %s", pp.name, e)
        return ["(subsystems unavailable.)"]
    return lines or ["(no subsystem map yet: needs a ready binary outside the runtime group.)"]


def knowledge_lines(pp: ProjectPaths, store: Store) -> list[str]:
    notes = specs = 0
    topics: list[str] = []
    if _table_exists(store, "note"):
        try:
            notes = int(store.db.execute("SELECT COUNT(*) FROM note").fetchone()[0])
        except sqlite3.Error:
            pass
    if _table_exists(store, "spec"):
        try:
            rows = store.db.execute("SELECT topic, status FROM spec ORDER BY topic").fetchall()
            specs = len(rows)
            topics += [f"{r['topic']}: spec {r['status']}" for r in rows[:8]]
        except sqlite3.Error:
            pass
    out = [f"notes {notes} | specs {specs} | published specs {len(published_specs(pp))} | "
           "open questions 0"]
    out += [f"topic {t}" for t in topics]
    names = store.db.execute(
        "SELECT b.name AS bn, b.pointer_size AS ps, f.space, f.entry, f.name, f.namespace FROM function f "
        "JOIN binary b ON b.id=f.binary_id WHERE f.name_state='user' ORDER BY f.id DESC LIMIT 5").fetchall()
    if names:
        out.append("recently named: " + "; ".join(
            _fn_label(store, r["bn"], r["ps"] or 4, r["space"], r["entry"], r["name"], r["namespace"])
            for r in names))
    else:
        out.append("recently named: none yet")
    out.append("Detail: spec_list, annotate(...) adds notes; a feature key is a topic prefix.")
    return out


def frontier_rows(store: Store, runtime_ids: set[int], top: int = FRONTIER_TOP) -> list[dict[str, Any]]:
    """Unnamed functions with the most distinct callers; evidence (strings, imports) raises the rank."""
    pool: list[dict[str, Any]] = []
    for b in store.list_binaries():
        if b.id in runtime_ids or _status(store, b.id) != "ready":
            continue
        for r in store.db.execute(
                "SELECT f.id, f.space, f.entry, f.name, f.namespace, COUNT(DISTINCT e.src_fn) AS c "
                "FROM edge e JOIN function f ON f.id=e.dst_fn WHERE e.binary_id=? AND e.dst_fn IS NOT NULL "
                f"AND e.src_fn IS NOT NULL AND e.src_fn<>e.dst_fn AND e.kind IN ({CODE_SQL}) "
                "AND f.name_state='auto' AND f.is_thunk=0 AND f.is_external=0 AND f.space='ram' "
                "AND f.entry NOT BETWEEN ? AND ? "         # managed methods carry real names
                "GROUP BY f.id ORDER BY c DESC, f.entry LIMIT 30", (b.id, DN_METHOD_LO, DN_METHOD_HI - 1)):
            pool.append({"binary": b, "id": r["id"], "space": r["space"], "entry": r["entry"],
                         "name": r["name"], "ns": r["namespace"], "callers": r["c"]})
    pool.sort(key=lambda p: (-p["callers"], p["binary"].id, p["entry"]))
    for p in pool[:max(top * 3, 30)]:
        b = p["binary"]
        p["strings"] = [r["value"] for r in store.db.execute(
            "SELECT DISTINCT s.value FROM edge e JOIN string s ON s.binary_id=e.binary_id AND "
            "s.address=e.dst_addr WHERE e.src_fn=? AND e.kind IN ('read','data','write') "
            "ORDER BY length(s.value) DESC LIMIT 2", (p["id"],))]
        p["imports"] = [r["name"] for r in store.db.execute(
            "SELECT name FROM (SELECT i.name AS name FROM edge e JOIN import i ON "
            "i.binary_id=e.binary_id AND i.address=e.dst_addr WHERE e.src_fn=? AND "
            f"e.kind IN ({CODE_SQL}) AND i.name IS NOT NULL "
            "UNION SELECT t.name FROM edge e JOIN function t ON t.id=e.dst_fn WHERE e.src_fn=? "
            f"AND t.is_thunk=1 AND e.kind IN ({CODE_SQL})) ORDER BY name LIMIT 3",
            (p["id"], p["id"]))]
        p["score"] = p["callers"] + (3 if p["strings"] or p["imports"] else 0)
    ranked = sorted(pool[:max(top * 3, 30)],
                    key=lambda p: (-p["score"], p["binary"].id, p["entry"]))
    return ranked[:top]


def frontier_lines(store: Store, runtime_ids: set[int]) -> list[str]:
    rows = frontier_rows(store, runtime_ids)
    if not rows:
        return ["(no unnamed called functions yet; needs a ready binary.)"]
    out = []
    for p in rows:
        b = p["binary"]
        ev = [fx._short(s, 28) for s in p["strings"]] + [f"calls {n}" for n in p["imports"]]
        out.append(f"{_fn_label(store, b.name, b.pointer_size or 4, p['space'], p['entry'], p['name'], p['ns'])}"
                   f" | {p['callers']} caller{'s' if p['callers'] != 1 else ''}" + (f" | {'; '.join(ev)}" if ev else "")
                   + f" | function(binary={b.name}, target={fmt_addr(p['entry'], b.pointer_size, p['space'])})")
    return out


def write_lines(pp: ProjectPaths) -> list[str]:
    return [f"Your own files: {pp.dirty / 'work'} (create it). Never write inside {pp.data}.",
            "Names, types, comments: rename / retype / comment / annotate (they update Ghidra).",
            "Specs for the clean side: spec_write(topic, ...). Features: feature_define. "
            "Purpose: project_describe."]


def dirty_sections(pp: ProjectPaths, store: Store, man: dict[str, Any] | None = None,
                   only: tuple[str, ...] | None = None) -> dict[str, list[str]]:
    man = load_manifest(pp) if man is None else man
    runtime_ids: list[set[int]] = []

    def runtime() -> set[int]:
        if not runtime_ids:
            runtime_ids.append(fx.manifest_inputs(pp, store, man)[0])
        return runtime_ids[0]

    build = {
        "Purpose": lambda: purpose_lines(pp, store, man),
        "Binaries": lambda: binaries_lines(pp, store, man),
        "Relations": lambda: relations_lines(pp, store, man),
        "Features": lambda: features_lines(store),
        "Subsystems": lambda: subsystems_lines(pp, store, runtime()),
        "Knowledge": lambda: knowledge_lines(pp, store),
        "Frontier": lambda: frontier_lines(store, runtime()),
        "Where to write": lambda: write_lines(pp),
    }
    return {k: f() for k, f in build.items() if only is None or k in only}


def render_dirty(pp: ProjectPaths, store: Store, only: tuple[str, ...] | None = None,
                 heading: bool = True, man: dict[str, Any] | None = None) -> list[str]:
    secs = dirty_sections(pp, store, man, only)
    out = [f"# {pp.name} (dirty map)"] if heading else []
    for name in SECTIONS:
        if name in secs:
            out += [f"## {name}", *secs[name]]
    return out


# -- clean map --------------------------------------------------------------------------

def published_specs(pp: ProjectPaths) -> list[dict[str, str]]:
    """Published specs as dicts topic, title, version, status (specs.json, else the .md names)."""
    idx = pp.specs / "specs.json"
    items: list[Any] = []
    if idx.is_file():
        try:
            data = json5.loads(idx.read_text("utf-8-sig"))
            items = data.get("specs", []) if isinstance(data, dict) else data
        except ValueError:
            items = []
    out = []
    if isinstance(items, list) and items:
        for it in items:
            if isinstance(it, dict):
                out.append({k: str(it.get(k, "")) for k in ("topic", "title", "version", "status")})
        return out
    if pp.specs.is_dir():
        for p in sorted(pp.specs.glob("*.md")):
            out.append({"topic": p.stem, "title": "", "version": "", "status": ""})
    return out


def scrub_clean(text: str, names: list[str]) -> str:
    """Remove addresses and binary file names from a free text going into the clean map."""
    text = re.sub(r"\b0x[0-9A-Fa-f]{3,}\b", "[address removed]", text)
    for n in sorted({x for x in names if x}, key=len, reverse=True):
        text = re.sub(re.escape(n), "[binary]", text, flags=re.I)
        stem = Path(n).stem
        if len(stem) >= 3:
            text = re.sub(r"\b" + re.escape(stem) + r"\.(?:exe|dll|ocx|sys)\b", "[binary]", text, flags=re.I)
    return text


def render_clean(pp: ProjectPaths, store: Store | None, man: dict[str, Any] | None = None) -> list[str]:
    names: list[str] = []
    purpose = ""
    if store is not None:
        purpose = get_purpose(store)
        names = [b.name for b in store.list_binaries()]
    man = load_manifest(pp) if man is None else man
    names += [PurePosixPath(str(f.get("path", "")).replace("\\", "/")).name
              for f in man.get("files") or [] if isinstance(f, dict)]
    out = [f"# {pp.name} (clean map)", "## Purpose",
           scrub_clean(purpose, names) if purpose else "(not set yet)", "## Specs"]
    specs = published_specs(pp)
    if not specs:
        out.append("(no published specs yet. spec_list shows the status.)")
    for s in specs:
        out.append(" | ".join(x for x in (s["topic"], s["title"], f"v{s['version']}" if s["version"] else "",
                                          s["status"]) if x))
    out.append("Read a spec: spec_read(topic=<topic>).")
    return out


# -- files ----------------------------------------------------------------------------------

_write_lock = threading.Lock()     # one map write at a time per process


def _write_atomic(path: Path, lines: list[str]) -> None:
    atomic_write_text(path, "\n".join(lines) + "\n")


def write_maps(pp: ProjectPaths, store: Store, man: dict[str, Any] | None = None,
               mermaid: bool = False) -> None:
    """Regenerate dirty\\PROJECT.md and clean\\PROJECT.md; with ``mermaid`` (defaults.mermaid) also the
    charts in dirty\\diagrams\\. Never raises (a map is an extra)."""
    try:
        with _write_lock:
            man = load_manifest(pp) if man is None else man
            _write_atomic(pp.dirty / "PROJECT.md", render_dirty(pp, store, man=man))
            _write_atomic(pp.clean / "PROJECT.md", render_clean(pp, store, man))
            if mermaid:
                from airlock.server import diagrams
                diagrams.write_mermaid_set(pp, store)
    except Exception as e:  # noqa: BLE001
        logs.project_log(pp.logs).warning("could not write PROJECT.md for %s: %s", pp.name, e)
