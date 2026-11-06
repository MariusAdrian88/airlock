"""Spec storage logic (DESIGN 6 spec tools, 9 clean-room model). Server side; no Ghidra.

Dirty side: the ``spec`` / ``spec_provenance`` / ``audit`` tables of the project index.
Clean side: only the published files in ``clean\\specs`` (``specs.json`` + one Markdown file per
topic). Nothing here lets a clean call open the index.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from airlock.index.store import Store
from airlock.projects import ProjectPaths, atomic_write_text
from airlock.server import specfilter
from airlock.server.selectors import resolve_function, split_binary_target

STATUSES = ("draft", "reviewed", "final")
METHODS = ("decompile", "file_diff", "resources", "observation")
MAX_BODY = 200_000
MAX_TITLE = 160
_TOPIC = re.compile(r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*$")
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def err(code: str, what: str, nxt: str = "") -> str:
    return f"error {code}: {what}." + (f" {nxt}." if nxt else "")


def check_topic(topic: str) -> str | None:
    t = topic.strip()
    if (not t or len(t) > 120 or not _TOPIC.match(t)
            or any(seg.split(".")[0] in _RESERVED or seg.endswith(".") for seg in t.split("/"))):
        return err("bad_topic", f"'{topic}' is not a valid topic",
                   "topics are lowercase path segments, e.g. file-format/document/record-header")
    return None


# -- sources ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Source:
    binary_id: int | None
    function_id: int | None
    address: int | None
    method: str
    note: str = ""          # prose given as a source: kept with the observation


FORMS = ("accepted sources: binary!function, binary!0xADDRESS, [decompile|file_diff|resources|observation:]"
         "binary!function, or a method word alone such as 'observation'; separate items with commas")
MAX_NOTE = 300


def _parse_item(st: Store, item: str) -> Source | str | None:
    """One source item: a Source, an error line, or None when it is not a source form at all (prose)."""
    method, rest = "", item
    head, sep, tail = item.partition(":")
    if sep and head.strip().lower() in METHODS:
        method, rest = head.strip().lower(), tail.strip()
    elif item.lower() in METHODS:
        method, rest = item.lower(), ""
    if not rest:
        return Source(None, None, None, method)
    bname, bare = split_binary_target(st, rest)
    bins = st.find_binaries(bname) if bname else st.list_binaries()
    if len(bins) != 1:
        return None if " " in item else err("bad_source", f"source '{item}' does not name one binary", FORMS)
    res = resolve_function(st, bins[0].id, bare)
    if not res.ok:
        if method and method != "decompile":
            return Source(None, None, None, method)
        if " " in item:
            return None
        why = (res.error or "").partition(": ")[2].rstrip(".")
        return err("bad_source", f"source '{item}': {why}", FORMS)
    fn = res.function
    return Source(bins[0].id, fn.id, fn.entry, method or "decompile")


def parse_sources(st: Store, text: str) -> list[Source] | str:
    """``[method:]binary!function-or-address`` items, or a bare method word; or an error line.

    Items split on newlines, ``;`` and ``,``. A line that is not a source form and holds spaces is prose:
    the whole line (commas kept) is stored as an ``observation`` carrying its text."""
    lines = [x.strip() for x in re.split(r"[\n;]+", text or "") if x.strip()]
    if not lines:
        return err("sources_required", "spec_write needs sources", FORMS)
    out: list[Source] = []
    for line in lines:
        got: list[Source] = []
        prose = False
        for frag in (x.strip() for x in line.split(",") if x.strip()):
            r = _parse_item(st, frag)
            if isinstance(r, str):
                return r
            if r is None:
                prose = True
                break
            got.append(r)
        if prose:
            out.append(Source(None, None, None, "observation", " ".join(line.split())[:MAX_NOTE]))
        else:
            out += got
    if not out:
        return err("sources_required", "spec_write needs sources", FORMS)
    return list(dict.fromkeys(out))


def image_ranges(st: Store) -> list[tuple[int, int]]:
    rows = []
    for b in st.list_binaries():
        top = max(
            st.db.execute("SELECT COALESCE(MAX(entry),0) FROM function WHERE binary_id=? AND space='ram'",
                          (b.id,)).fetchone()[0],
            st.db.execute("SELECT COALESCE(MAX(address),0) FROM string WHERE binary_id=?",
                          (b.id,)).fetchone()[0])
        rows.append((b.image_base or 0, top))
    return specfilter.image_ranges(rows)


# -- dirty side: database ---------------------------------------------------------------------

def audit(st: Store, role: str, tool: str, args: str, kind: str, detail: str) -> None:
    st.db.execute("INSERT INTO audit(at, profile, tool, args_digest, result_kind, detail) "
                  "VALUES (?,?,?,?,?,?)",
                  (now(), role, tool, hashlib.sha256(args.encode("utf-8")).hexdigest()[:16], kind, detail))


def write_spec(st: Store, role: str, topic: str, title: str, body: str, status: str,
               sources: list[Source]) -> tuple[int, int, bool]:
    """(id, version, created). An identical rewrite of the latest version creates nothing."""
    with st.db:
        last = st.db.execute("SELECT id, version, title, body, status FROM spec WHERE topic=? "
                             "ORDER BY version DESC LIMIT 1", (topic,)).fetchone()
        if last and (last["title"], last["body"], last["status"]) == (title, body, status):
            audit(st, role, "spec_write", f"{topic}\n{body}", "unchanged", f"{topic} v{last['version']}")
            return last["id"], last["version"], False
        ver = (last["version"] if last else 0) + 1
        ts = now()
        cur = st.db.execute("INSERT INTO spec(topic, title, body, status, version, author, created_at, "
                            "updated_at) VALUES (?,?,?,?,?,?,?,?)",
                            (topic, title, body, status, ver, role, ts, ts))
        sid = cur.lastrowid
        st.db.executemany("INSERT INTO spec_provenance(spec_id, binary_id, function_id, address, method) "
                          "VALUES (?,?,?,?,?)",
                          [(sid, s.binary_id, s.function_id, s.address,
                           f"{s.method}: {s.note}" if s.note else s.method) for s in sources])
        audit(st, role, "spec_write", f"{topic}\n{body}", "ok", f"{topic} v{ver} {status}")
        return sid, ver, True


def latest(st: Store, prefix: str = "") -> list[dict]:
    rows = st.db.execute(
        "SELECT s.id, s.topic, s.title, s.status, s.version, s.updated_at FROM spec s "
        "JOIN (SELECT topic, MAX(version) v FROM spec GROUP BY topic) m "
        "ON m.topic=s.topic AND m.v=s.version ORDER BY s.topic").fetchall()
    return [dict(r) for r in rows if r["topic"].startswith(prefix)]


def get_spec(st: Store, topic: str = "", sid: int = 0, version: int = 0) -> dict | None:
    if sid:
        r = st.db.execute("SELECT * FROM spec WHERE id=?", (sid,)).fetchone()
    elif version:
        r = st.db.execute("SELECT * FROM spec WHERE topic=? AND version=?", (topic, version)).fetchone()
    else:
        r = st.db.execute("SELECT * FROM spec WHERE topic=? ORDER BY version DESC LIMIT 1",
                          (topic,)).fetchone()
    return dict(r) if r else None


# -- published files (clean side) ------------------------------------------------------------

def published(pp: ProjectPaths) -> list[dict]:
    """specs.json entries (topic, title, version, status, file); [] if none."""
    try:
        data = json.loads((pp.specs / "specs.json").read_text("utf-8-sig"))
    except (OSError, ValueError):
        return []
    items = data.get("specs", []) if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    return [i for i in items if isinstance(i, dict) and isinstance(i.get("topic"), str)]


def read_published(pp: ProjectPaths, topic: str) -> tuple[dict, str] | None:
    """(entry, body) of a published topic. The path comes from the index entry, never the caller."""
    for e in published(pp):
        if e["topic"] == topic:
            path = (pp.specs / str(e.get("file") or f"{topic}.md")).resolve()
            try:
                path.relative_to(pp.specs.resolve())
                text = path.read_text("utf-8")
            except (OSError, ValueError):
                return None
            return e, strip_front_matter(text)
    return None


def strip_front_matter(text: str) -> str:
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end >= 0:
            return text[end + 5:].lstrip("\n")
    return text


def _atomic(path: Path, text: str) -> None:
    atomic_write_text(path, text, newline="\n")


def render_file(s: dict) -> str:
    head = ["---", f"topic: {s['topic']}", f"title: {json.dumps(s['title'], ensure_ascii=False)}",
            f"version: {s['version']}", f"status: {s['status']}", "---", ""]
    return "\n".join(head) + s["body"].rstrip("\n") + "\n"


def publish(st: Store, pp: ProjectPaths, role: str, prefix: str) -> tuple[list[dict], int, int]:
    """Write the final latest specs under ``prefix`` to clean\\specs.

    Returns (published, skipped_not_final, withdrawn). Specs under the prefix that are no longer
    final are withdrawn (file and index entry removed). Provenance, addresses and notes never
    leave the index."""
    cur = latest(st, prefix)
    final = []
    for c in cur:
        if c["status"] == "final":
            full = get_spec(st, c["topic"], version=c["version"])
            assert full is not None
            final.append(full)
    skipped = len(cur) - len(final)
    have = published(pp)
    keep = [e for e in have if not e["topic"].startswith(prefix)]
    old = {e["topic"]: e for e in have if e["topic"].startswith(prefix)}
    new_topics = {s["topic"] for s in final}
    pp.specs.mkdir(parents=True, exist_ok=True)
    entries = list(keep)
    for s in final:
        rel = f"{s['topic']}.md"
        _atomic(pp.specs / rel, render_file(s))
        entries.append({"topic": s["topic"], "title": s["title"], "version": s["version"],
                        "status": s["status"], "file": rel})
    gone = [e for t, e in old.items() if t not in new_topics]
    for e in gone:
        _remove(pp, str(e.get("file") or f"{e['topic']}.md"))
    entries.sort(key=lambda e: e["topic"])
    _atomic(pp.specs / "specs.json", json.dumps({"specs": entries}, indent=1, ensure_ascii=False) + "\n")
    with st.db:
        for s in final:
            audit(st, role, "spec_export", f"{s['topic']}\n{s['body']}", "published",
                  f"{s['topic']} v{s['version']}")
        audit(st, role, "spec_export", prefix, "ok",
              f"published {len(final)} withdrawn {len(gone)} skipped {skipped}")
    _atomic(pp.specs / "audit-summary.md", audit_summary(st))
    return final, skipped, len(gone)


def _remove(pp: ProjectPaths, rel: str) -> None:
    root = pp.specs.resolve()
    p = (pp.specs / rel).resolve()
    try:
        p.relative_to(root)
    except ValueError:
        return
    p.unlink(missing_ok=True)
    d = p.parent
    while d != root and d.is_dir() and not any(d.iterdir()):
        shutil.rmtree(d, ignore_errors=True)
        d = d.parent


def audit_summary(st: Store) -> str:
    rows = st.db.execute("SELECT profile, tool, COUNT(*) n, MIN(at) a, MAX(at) b FROM audit "
                         "GROUP BY profile, tool ORDER BY profile, tool").fetchall()
    out = ["# Audit summary", "", "| profile | tool | calls |", "|---|---|---|"]
    out += [f"| {r['profile']} | {r['tool']} | {r['n']} |" for r in rows]
    if rows:
        out += ["", f"Date range: {min(r['a'] for r in rows)} to {max(r['b'] for r in rows)}"]
    return "\n".join(out) + "\n"
