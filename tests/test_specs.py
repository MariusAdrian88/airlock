"""Spec tools (M4): filter, versions, provenance, publish, clean-room gate, audit (no Ghidra)."""

from __future__ import annotations

import json
import re

import pytest

from airlock.projects import ProjectPaths
from airlock.server import registry, roles, specfilter
from airlock.server.tools import spec as _spec  # noqa: F401  (registers the tools)
from test_tools import fill, make_ctx

GOOD = ("The record header starts with a length field.\n\n"
        "| field | offset | size | meaning |\n|---|---|---|---|\n"
        "| length | 0 | 4 | bytes in the record |\n| kind | 4 | 2 | record type, little endian |\n")


def _pp(ctx) -> ProjectPaths:
    return ctx.indexer.paths("proj")


def _as(ctx, role: str) -> None:
    ctx.session = roles.SessionState(role, _pp(ctx))


@pytest.fixture
def dctx(tmp_path):
    c = make_ctx(tmp_path)
    fill(c)
    _as(c, roles.DIRTY)
    return c


def _w(ctx, topic="fmt/header", body=GOOD, sources="app.exe!main", **kw):
    return registry.call(ctx, "spec_write", topic=topic, title=kw.pop("title", "Header"),
                         body=body, sources=sources, **kw)


# -- filter ----------------------------------------------------------------------------

@pytest.mark.parametrize("line,code", [
    ("x = y + 1;", "spec_has_code"),
    ("  FUN_00401000(a, b);", "spec_has_ghidra_names"),
    ("return foo(a);", "spec_has_code"),
    ("if (a == b) {", "spec_has_code"),
    ("}", "spec_has_code"),
    ("begin", "spec_has_code"),
    ("count := count + 1;", "spec_has_code"),
    ("#include <windows.h>", "spec_has_code"),
    ("int count = 0;", "spec_has_code"),
    ("uVar3 holds the length", "spec_has_ghidra_names"),
    ("the param_1 value", "spec_has_ghidra_names"),
    ("```c", "spec_has_code"),
    ("50 4B 03 04 14 00 06 00 08 00 00 00", "spec_has_bytes"),
    ("magic is 0x0000000140001000 here", "spec_has_address"),
    ("handler lives at 0x00401100", "spec_has_address"),
    ("handler lives at 0x401100", "spec_has_address"),
    ("handler lives at 00401100", "spec_has_address"),
])
def test_filter_rejects(line, code):
    out = specfilter.check("fine line\n" + line, [(0x400000, 0x403100 + specfilter.ADDRESS_SLACK)])
    assert out is not None and out.startswith(f"error {code}: line 2 "), out
    assert "\n" not in out


def test_filter_accepts_prose_and_tables():
    assert specfilter.check(GOOD, [(0x400000, 0x500000)]) is None
    ok = "The flag at offset 0x10 is 0x01 when set; the version is 12; file magic is 0xFFFE."
    assert specfilter.check(ok, [(0x400000, 0x500000)]) is None
    assert specfilter.check("record count is 4194304", [(0x400000, 0x500000)]) is None


def test_write_rejects_code_and_stores_nothing(dctx):
    out = _w(dctx, body="Intro.\nx = foo(1);\n")
    assert out.startswith("error spec_has_code: line 2 ")
    assert registry.call(dctx, "spec_list").startswith("no specs")


# -- write / versions / provenance ---------------------------------------------------------

def test_write_versions_and_unchanged(dctx):
    assert re.fullmatch(r"spec \d+ fmt/header v1 draft", _w(dctx))
    assert "unchanged" in _w(dctx)
    out = _w(dctx, body=GOOD + "Extra.\n", status="reviewed")
    assert out.endswith("fmt/header v2 reviewed")
    st = dctx.indexer.store("proj")
    assert [r[0] for r in st.db.execute("SELECT version FROM spec ORDER BY version")] == [1, 2]
    prov = st.db.execute("SELECT binary_id, function_id, address, method FROM spec_provenance "
                         "WHERE spec_id=(SELECT id FROM spec WHERE version=1)").fetchall()
    assert len(prov) == 1 and prov[0]["address"] == 0x401000 and prov[0]["method"] == "decompile"


def test_write_validation(dctx):
    assert _w(dctx, sources="").startswith("error sources_required:")
    assert _w(dctx, sources="app.exe!nosuchfn").startswith("error bad_source:")
    assert _w(dctx, topic="Bad Topic").startswith("error bad_topic:")
    assert _w(dctx, topic="../x").startswith("error bad_topic:")
    assert _w(dctx, status="done").startswith("error bad_status:")
    assert _w(dctx, sources="observation").startswith("spec ")
    assert _w(dctx, topic="fmt/two", sources="file_diff, app.exe!0x401100").startswith("spec ")


def test_prose_sources_become_an_observation(dctx):
    prose = "read from the saved file, then compared with the header"
    out = _w(dctx, sources=prose)
    assert out.startswith("spec ") and f'(stored as observation: "{prose}")' in out
    prov = dctx.indexer.store("proj").db.execute(
        "SELECT * FROM spec_provenance").fetchall()
    assert len(prov) == 1 and prov[0]["method"] == f"observation: {prose}" and prov[0]["function_id"] is None
    # real items next to prose lines keep their meaning; commas inside a prose line are not split
    out = _w(dctx, topic="fmt/mix", sources="app.exe!main, app.exe!0x401100\nsaw it, twice in the UI")
    assert out.startswith("spec ") and 'observation: "saw it, twice in the UI"' in out
    rows = dctx.indexer.store("proj").db.execute(
        "SELECT method FROM spec_provenance ORDER BY rowid DESC LIMIT 3").fetchall()
    assert sorted(r["method"] for r in rows).count("decompile") == 2


def test_bad_single_word_source_lists_the_forms(dctx):
    out = _w(dctx, sources="app.exe!nosuchfn")
    assert out.startswith("error bad_source:") and "binary!function, binary!0xADDRESS" in out
    assert "observation" in out


@pytest.mark.parametrize("line", [
    "| 64, 64, 48, 73, 90, 12, 45, 33, 21 |",
    "the column widths are 64, 64, 48, 73, 90, 12, 45, 33 pixels",
])
def test_filter_accepts_decimal_lists(line):
    assert specfilter.check(line) is None


@pytest.mark.parametrize("line", [
    "50 4B 03 04 14 00 06 00 08 00 00 00",
    "00, 00, 00, 00, 00, 00, 00, 00, 00",
    "64, 4A, 48, 73, 90, 12, 45, 33",
    "0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00",
    "4d5a90000300000004000000ffff0000",
    "64 64 48 73 90 12 45 33 21",
])
def test_filter_still_rejects_byte_dumps(line):
    out = specfilter.check(line)
    assert out is not None and out.startswith("error spec_has_bytes:"), out


def test_write_filters_the_title_too(dctx):
    assert _w(dctx, title="FUN_00401000 handler").startswith("error spec_has_ghidra_names:")


# -- read / list in dirty ----------------------------------------------------------------------

def test_read_and_list_dirty(dctx):
    _w(dctx)
    _w(dctx, body=GOOD + "More.\n")
    assert registry.call(dctx, "spec_list", topic_prefix="fmt").splitlines()[0].startswith(
        "fmt/header | Header | v2 | draft | unpublished | id ")
    assert registry.call(dctx, "spec_list", topic_prefix="zzz").startswith("no specs")
    out = registry.call(dctx, "spec_read", topic="fmt/header")
    assert out.splitlines()[0] == "fmt/header | Header | v2 | draft" and "More." in out
    assert "More." not in registry.call(dctx, "spec_read", topic="fmt/header", version=1)
    sid = dctx.indexer.store("proj").db.execute("SELECT id FROM spec WHERE version=1").fetchone()[0]
    assert "fmt/header" in registry.call(dctx, "spec_read", id=sid)
    assert registry.call(dctx, "spec_read", topic="nope").startswith("error not_found:")
    listed = registry.call(dctx, "spec_read")       # no topic: the list instead of an error
    assert listed.startswith("(no topic given: the spec list)") and "fmt/header" in listed
    nf = registry.call(dctx, "spec_read", topic="nope")
    assert nf.startswith("error not_found:") and "topics: fmt/header" in nf


def test_read_dirty_never_returns_provenance(dctx):
    _w(dctx)
    out = registry.call(dctx, "spec_read", topic="fmt/header")
    assert "0x" not in out and "main" not in out and "app.exe" not in out


# -- export / clean room ------------------------------------------------------------------------

def test_export_publishes_final_only_and_audit(dctx):
    _w(dctx, topic="fmt/a", status="final")
    _w(dctx, topic="fmt/b")
    out = registry.call(dctx, "spec_export")
    assert out.startswith("published 1 specs to ") and "1 not final" in out
    pp = _pp(dctx)
    text = (pp.specs / "fmt" / "a.md").read_text("utf-8")
    assert text.startswith("---\ntopic: fmt/a\ntitle: \"Header\"\nversion: 1\nstatus: final\n---\n")
    idx = json.loads((pp.specs / "specs.json").read_text("utf-8"))
    assert [e["topic"] for e in idx["specs"]] == ["fmt/a"]
    assert not (pp.specs / "fmt" / "b.md").exists()
    summary = (pp.specs / "audit-summary.md").read_text("utf-8")
    assert "spec_write" in summary and "spec_export" in summary
    # audit rows: who (profile), when, topic + version
    rows = dctx.indexer.store("proj").db.execute(
        "SELECT profile, tool, result_kind, detail, at FROM audit ORDER BY id").fetchall()
    assert ("dirty", "spec_write", "ok", "fmt/a v1 final") in [tuple(r)[:4] for r in rows]
    assert ("dirty", "spec_export", "published", "fmt/a v1") in [tuple(r)[:4] for r in rows]
    assert all(r["at"] for r in rows)
    # a spec that is no longer final is withdrawn on the next export
    _w(dctx, topic="fmt/a", status="draft", body=GOOD + "Rework.\n")
    registry.call(dctx, "spec_export")
    assert not (pp.specs / "fmt" / "a.md").exists() and not (pp.specs / "fmt").exists()
    assert json.loads((pp.specs / "specs.json").read_text("utf-8"))["specs"] == []


def test_clean_session_reads_a_spec_and_nothing_else(dctx):
    _w(dctx, topic="fmt/a", status="final", body=GOOD)
    registry.call(dctx, "spec_export")
    _w(dctx, topic="fmt/secret", body="Draft only.\n")
    _as(dctx, roles.CLEAN)
    # M4 acceptance: spec tools work, everything else is refused
    assert registry.call(dctx, "spec_list").splitlines() == ["fmt/a | Header | v1 | final"]
    out = registry.call(dctx, "spec_read", topic="fmt/a")
    assert out.splitlines()[0] == "fmt/a | Header | v1 | final" and "length field" in out
    for name, kw in (("function", {"query": "main"}), ("spec_write", {"topic": "x", "title": "t",
                     "body": "b", "sources": "observation"}), ("index_status", {}),
                     ("program_scan", {"path": "."})):
        assert registry.call(dctx, name, **kw).startswith("error wrong_role:"), name
    # unpublished draft and ids are invisible
    assert registry.call(dctx, "spec_read", topic="fmt/secret").startswith("error not_found:")
    assert registry.call(dctx, "spec_read", id=1).startswith("error bad_args:")
    assert registry.call(dctx, "spec_read", topic="../../dirty/x").startswith("error not_found:")
    # nothing a clean call prints carries an address or provenance; export only reports
    outs = [registry.call(dctx, "spec_list"), registry.call(dctx, "spec_read", topic="fmt/a"),
            registry.call(dctx, "spec_export")]
    for o in outs:
        assert "0x" not in o and "app.exe" not in o and "main" not in o and "provenance" not in o.lower()
    assert not (_pp(dctx).specs / "fmt" / "secret.md").exists()
    assert registry.call(dctx, "spec_export").startswith("1 published specs")


def test_clean_reads_without_opening_the_index(tmp_path):
    c = make_ctx(tmp_path)
    pp = _pp(c)
    (pp.specs).mkdir(parents=True, exist_ok=True)
    (pp.specs / "a.md").write_text("---\ntopic: a\ntitle: \"T\"\nversion: 3\nstatus: final\n---\n\nBody.\n")
    (pp.specs / "specs.json").write_text(json.dumps(
        {"specs": [{"topic": "a", "title": "T", "version": 3, "status": "final", "file": "a.md"}]}))
    _as(c, roles.CLEAN)
    assert registry.call(c, "spec_read", topic="a").splitlines() == ["a | T | v3 | final", "Body."]
    v2 = registry.call(c, "spec_read", topic="a", version=2).splitlines()  # the published one, said so
    assert v2 == ["a | T | v3 | final (v2 is not published)", "Body."]
    assert registry.call(c, "spec_read", topic="b") == "error not_found: no published spec 'b'. topics: a."
    assert not pp.index_db.exists()


def test_specs_survive_binary_reextract(dctx):
    _w(dctx)
    st = dctx.indexer.store("proj")
    for b in st.list_binaries():
        st.clear_binary_data(b.id)
    assert st.db.execute("SELECT COUNT(*) FROM spec").fetchone()[0] == 1
    assert st.db.execute("SELECT COUNT(*) FROM spec_provenance").fetchone()[0] == 1
    assert st.db.execute("SELECT function_id, address FROM spec_provenance").fetchone()[:] == (None, 0x401000)


def test_migration_from_v5_adds_spec_tables(tmp_path):
    import sqlite3
    from airlock.index.migrations import MIGRATIONS
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE binary (id INTEGER PRIMARY KEY)")
    db.execute("CREATE TABLE function (id INTEGER PRIMARY KEY)")
    MIGRATIONS[7](db)
    MIGRATIONS[7](db)  # idempotent
    names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"spec", "spec_provenance", "audit"} <= names
