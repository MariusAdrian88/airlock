"""Clean-room audit fixes: purpose leak, spec filter gaps, unbound phase, deny rules, hard links,
spec approval (no Ghidra)."""

from __future__ import annotations

import json
import os

import pytest

from airlock import projects as P
from airlock.server import projectmap as pm
from airlock.server import registry, roles, specfilter
from airlock.server import specs as sp
from airlock.server.context import ServerContext
from test_tools import fill, make_ctx

registry.load_tool_modules()

RANGES = [(0x400000, 0x500000)]


@pytest.fixture
def dctx(tmp_path):
    c = make_ctx(tmp_path)
    fill(c)
    c.session = roles.SessionState(roles.DIRTY, c.indexer.paths("proj"))
    return c


def _fresh(d: ServerContext) -> ServerContext:
    """A new process-like context on the same config: unbound, nothing opened."""
    return ServerContext(config=d.config, worker=d.worker)


def _write(ctx, topic="fmt/a", body="The header starts with a length field.\n", status="final"):
    return registry.call(ctx, "spec_write", topic=topic, title="T", body=body, sources="observation",
                         status=status)


# -- 1. purpose paragraph -------------------------------------------------------------

DIRTY_PURPOSE = ("Reads the doc. thunk_FUN_00401100 parses it; puVar3 = *(param_x+4); "
                 "if (len > 3) { buf = alloc(len); }")


def test_project_describe_refuses_dirty_text(dctx):
    out = registry.call(dctx, "project_describe", purpose="FUN_00401000 parses it")
    assert out.startswith("error spec_has_ghidra_names:") and "\n" not in out
    out = registry.call(dctx, "project_describe", purpose="It parses files. x = foo(y); More text.")
    assert out.startswith("error spec_has_code:")
    assert registry.call(dctx, "project_describe",
                         purpose="Edits brew logs and shows them in a table.").startswith("purpose set")


def test_clean_open_never_shows_an_old_dirty_purpose_and_never_opens_the_index(dctx):
    pp = dctx.indexer.paths("proj")
    st = dctx.indexer.store("proj")
    pm.set_purpose(st, DIRTY_PURPOSE)              # an old row, written without the filter
    pm.write_maps(pp, st)
    mtime = pp.index_db.stat().st_mtime_ns
    # an old clean\PROJECT.md written by the old code holds the text as well
    (pp.clean / "PROJECT.md").write_text(f"# proj (clean map)\n## Purpose\n{DIRTY_PURPOSE}\n## Specs\n",
                                         "utf-8")
    c = _fresh(dctx)
    out = registry.call(c, "project_open", "proj", "clean")
    for leak in ("FUN_00401100", "puVar3", "alloc(len)", "param_x"):
        assert leak not in out, leak
    assert "(not set yet)" in out
    assert not getattr(c.indexer._tls, "stores", {})          # no store opened
    assert pp.index_db.stat().st_mtime_ns == mtime


def test_write_maps_drops_a_failing_purpose_and_keeps_a_good_one(dctx):
    pp = dctx.indexer.paths("proj")
    st = dctx.indexer.store("proj")
    pm.set_purpose(st, DIRTY_PURPOSE)
    pm.write_maps(pp, st)
    assert "FUN_00401100" not in (pp.clean / "PROJECT.md").read_text("utf-8")
    pm.set_purpose(st, "Edits brew logs for app.exe.")
    pm.write_maps(pp, st)
    c = _fresh(dctx)
    out = registry.call(c, "project_open", "proj", "clean")
    assert "Edits brew logs for [binary]." in out


def test_scrub_dirty_path_relative_and_short_forms(dctx):
    pp = dctx.indexer.paths("proj")
    pp.dirty.mkdir(parents=True, exist_ok=True)
    text = r"see ..\dirty\notes.md, ../dirty/x and dirty\y and " + pm._short_path(pp.dirty) + r"\z"
    out = pm.scrub_dirty_path(text, pp)
    assert "dirty" not in out.replace("[path removed]", "").lower()


def test_clean_open_text_survives_a_broken_manifest(dctx, monkeypatch):
    pp = dctx.indexer.paths("proj")
    monkeypatch.setattr(pm, "load_manifest", lambda p: (_ for _ in ()).throw(OSError("boom: C:/secret")))
    c = _fresh(dctx)
    out = registry.call(c, "project_open", "proj", "clean")
    assert "boom" not in out and "(project map unavailable)" in out and out.startswith("session clean")


# -- 2. spec filter -------------------------------------------------------------------

BYPASS_LINES = [
    "count = read_header(file); // reads the header",
    "`if (len > 3) { buf = alloc(len); }`",
    "| x = foo(y); |",
    "while (i < n) i++;",
    "def parse(buf): return struct.unpack('<I', buf[0:4])",
    "thunk_FUN_00401100 is the parser",
    "switchD_00401234 dispatches the commands",
    "s_Hello_00405000 is the banner string",
    "puVar3 and pcVar2 and bVar1 and lVar4 hold the length",
    "this->field_0x10 is the count",
    "header 4D5A9000 03000000 04000000 FFFF0000",
    "bytes 77 90 144 0 3 0 0 0 4 0 0 0 255 255",
    "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA== is the start",
    "the parser is at 4198656",
    "x => x.Stage != RecorderStages.Recording",
    "(a, b) => a.Id.CompareTo(b.Id)",
    "IL_0012: callvirt instance string [mscorlib]System.Object::ToString()",
    "call void Foo::Bar(int32)",
    "call class [System.Runtime]System.Version Foo.Bar::get_CurrentVersion()",
]


@pytest.mark.parametrize("line", BYPASS_LINES)
def test_filter_rejects(line):
    out = specfilter.check("fine line\n" + line, RANGES)
    assert out is not None and out.startswith("error spec_has_") and "line 2 " in out, out


GOOD_LINES = [
    "The file starts with the magic bytes 4D 5A (MZ).",
    "Magic value 0x504B0304 marks a local file header.",
    "Field at offset 0x10, 4 bytes, little-endian: the payload length.",
    "Messages use WM_USER+5 (0x0405) for the refresh request; 0x0400 starts the user range.",
    "The CRC-32 polynomial is 0xEDB88320 and the initial value is 0xFFFFFFFF.",
    "The CRC-64 polynomial is 0xC96C5795D7870F42.",
    "Error codes: 1 = bad header, 2 = checksum mismatch, 3 = truncated.",
    "The server listens on port 8080 and retries 3 times before it gives up.",
    "The PNG signature is 89 50 4E 47 0D 0A 1A 0A.",
    "| offset | size | meaning |\n|---|---|---|\n| 0x00 | 4 | signature 0x4D5A9000 |\n| begin | 4 | first offset |",
    "1. Read the 4 byte length.\n2. If size > max then fail with error 3.\n3. Allocate size bytes.",
    "for each record in the table, read its flags and skip it when the high bit is set",
    "Version 2.1.0 adds the flags field; version 1.4 lacks it.",
    "Enum values: 0 = none, 1 = read, 2 = write, 4 = execute.",
    "The block size is 4096 bytes and the maximum is 1048576.",
    "The serial port base is 0x3F8; the interrupt is 4.",
    "The checksum is the sum of all bytes modulo 256, stored in the last byte.",
    "The GUID is {6B29FC40-CA47-1067-B31D-00DD010662DA}.",
    "The record count is 4194304 at most.",
    "The list is sorted by Id.",
    "It calls ToString on each item and joins the results with a comma.",
    "Each handler is called with the sender and the event arguments.",
    'Test vector: input "abc" gives MD5 900150983cd24fb0d6963f7d28e17f72',
    "SHA-256 of an empty input: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "The SHA1 digest of abc is a9993e364706816aba3e25717850c26c9cd0d89d.",
    "vector: in=616263 out=900150983cd24fb0d6963f7d28e17f72",
    "vector: key=000102030405060708090a0b0c0d0e0f in= out=4d5a9000030000000400000000000000ffff0000",
    "Window class registration uses style 0x0003 and the message loop ends on WM_QUIT (0x0012).",
]


@pytest.mark.parametrize("line", GOOD_LINES)
def test_filter_accepts_interface_facts(line):
    assert specfilter.check(line, RANGES) is None, specfilter.check(line, RANGES)


REJECT_VECTOR_LINES = [
    "digest bytes 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00",     # spaced dump next to a hash word
    "MD5 of the header: 4d5a9000030000000400000000000000ff",              # 34 digits, not a digest length
    "vector: in=00401100 out=00",                                          # image address in a vector
    "note vector: in=4d5a9000030000000400000000000000ffff0000",         # not at the line start
    "vector: in=" + "ab" * 65,                                            # more than 64 bytes
    "the header is 4d5a9000030000000400000000000000ffff0000",           # long hex, no digest word
]


@pytest.mark.parametrize("line", REJECT_VECTOR_LINES)
def test_filter_rejects_dumps_that_look_like_vectors(line):
    assert specfilter.check(line, RANGES) is not None


def test_publish_runs_the_filter_again(dctx):
    pp = dctx.indexer.paths("proj")
    st = dctx.indexer.store("proj")
    assert _write(dctx, topic="fmt/ok").startswith("spec ")
    # a body stored directly (an old row) that the filter now refuses
    st.db.execute("INSERT INTO spec(topic, title, body, status, version, author, created_at, updated_at) "
                  "VALUES ('fmt/bad','T','thunk_FUN_00401100 is the parser','final',1,'x','t','t')")
    st.db.commit()
    out = registry.call(dctx, "spec_export")
    assert out.startswith("published 1 specs") and "fmt/bad" in out and "failed the filter" in out
    assert not (pp.specs / "fmt" / "bad.md").exists() and (pp.specs / "fmt" / "ok.md").exists()


def test_publish_withdraws_a_spec_that_now_fails(dctx):
    pp = dctx.indexer.paths("proj")
    st = dctx.indexer.store("proj")
    assert _write(dctx, topic="fmt/a").startswith("spec ")
    registry.call(dctx, "spec_export")
    assert (pp.specs / "fmt" / "a.md").exists()
    st.db.execute("UPDATE spec SET body='puVar3 holds the length'")
    st.db.commit()
    registry.call(dctx, "spec_export")
    assert not (pp.specs / "fmt" / "a.md").exists()


# -- 3. unbound phase -----------------------------------------------------------------

def test_unbound_projects_is_redacted_and_scan_blocks_a_clean_bind(dctx, tmp_path):
    pp = dctx.indexer.paths("proj")
    P.write_manifest(pp.manifest, {**P.read_manifest(pp.manifest), "source": {"root_exe": "secret.exe"}})
    c = _fresh(dctx)
    out = registry.call(c, "projects")
    assert out.startswith("proj | specs") and "secret.exe" not in out and str(pp.root) not in out
    clean_form = out
    c.session = roles.SessionState(roles.CLEAN, pp)
    assert registry.call(c, "projects") == clean_form
    c.session = roles.SessionState()
    # a path-showing tool in the unbound phase: no clean bind afterwards
    folder = tmp_path / "prog"
    folder.mkdir()
    (folder / "secret_app.exe").write_bytes(b"MZ" + b"\0" * 200)
    assert str(folder) in registry.call(c, "program_scan", path=str(folder))
    out = registry.call(c, "project_open", "proj", "clean")
    assert out.startswith("error role_locked:") and c.session.role == roles.UNBOUND
    # a dirty bind stays possible
    assert registry.call(c, "project_open", "proj", "dirty").startswith("session dirty")


def test_unbound_project_info_blocks_a_clean_bind(dctx):
    c = _fresh(dctx)
    assert str(c.config.data_dir) in registry.call(c, "project_info")
    assert registry.call(c, "project_open", "proj", "clean").startswith("error role_locked:")


def test_unbound_projects_alone_keeps_the_clean_bind_open(dctx):
    c = _fresh(dctx)
    registry.call(c, "projects")
    assert registry.call(c, "project_open", "proj", "clean").startswith("session clean")


# -- 4. deny rules --------------------------------------------------------------------

def test_deny_rules_cover_manifest_data_source_config_and_clean_side(tmp_path):
    pp = P.project_paths(tmp_path / "projects", "demo", create=True)
    data, src, cfgf = tmp_path / "data", tmp_path / "orig", tmp_path / "config.jsonc"
    out = P.write_clean_deny_rules(pp, deny_dirs=[data, src], deny_files=[cfgf])
    assert not [x for x in out if x.startswith("deny rules not applied")]
    deny = json.loads((pp.clean / ".claude" / "settings.json").read_text("utf-8"))["permissions"]["deny"]
    for p in (pp.manifest, cfgf):
        assert f"Read({P._claude_rule_path(p)})" in deny
    for p in (data, src):
        assert f"Read({P._claude_rule_path(p)}/**)" in deny
    dirty_side = json.loads((pp.dirty / ".claude" / "settings.json").read_text("utf-8"))
    assert dirty_side["permissions"]["deny"] == [f"Edit({P._claude_rule_path(pp.clean)}/**)"]


def test_deny_rules_report_a_rule_that_was_not_applied(tmp_path):
    pp = P.project_paths(tmp_path / "projects", "demo", create=True)
    (pp.clean / ".claude").mkdir(parents=True)
    (pp.clean / ".claude" / "settings.json").write_text('{"permissions": "x"}')
    (pp.clean / "opencode.json").write_text('{"permission": {"external_directory": {"*": "allow"}}}')
    out = P.write_clean_deny_rules(pp)
    failed = [x for x in out if x.startswith("deny rules not applied: ")]
    assert len(failed) == 2 and str(pp.clean / "opencode.json") in " ".join(failed)
    assert not any(x == str(pp.clean / "opencode.json") for x in out)


# -- 5. hard links --------------------------------------------------------------------

def test_spec_read_refuses_a_hard_link(dctx, tmp_path):
    pp = dctx.indexer.paths("proj")
    (pp.dirty / "work").mkdir(parents=True, exist_ok=True)
    secret = pp.dirty / "work" / "dirty.md"
    secret.write_text("DIRTY SECRET", "utf-8")
    pp.specs.mkdir(parents=True, exist_ok=True)
    try:
        os.link(secret, pp.specs / "h.md")
    except OSError:
        pytest.skip("hard links not supported here")
    (pp.specs / "specs.json").write_text(json.dumps(
        {"specs": [{"topic": "h", "title": "t", "version": 1, "status": "final", "file": "h.md"}]}))
    c = _fresh(dctx)
    c.session = roles.SessionState(roles.CLEAN, pp)
    out = registry.call(c, "spec_read", topic="h")
    assert out.startswith("error not_found:") and "SECRET" not in out


# -- 6. spec approval -----------------------------------------------------------------

def test_default_lets_the_agent_publish(dctx):
    assert dctx.config.defaults["require_spec_review"] is False
    assert _write(dctx).startswith("spec ")
    assert registry.call(dctx, "spec_export").startswith("published 1 specs")


def test_require_spec_review_blocks_final_and_publish(dctx):
    dctx.config.defaults["require_spec_review"] = True
    out = _write(dctx, status="final")
    assert out.startswith("error needs_approval:") and "airlock spec-approve proj" in out and "\n" not in out
    assert _write(dctx, status="reviewed").startswith("spec ")
    assert registry.call(dctx, "spec_export").startswith("error needs_approval:")
    pp = dctx.indexer.paths("proj")
    assert not (pp.specs / "fmt" / "a.md").exists()


def test_person_approval_sets_final_and_publish_works(dctx):
    dctx.config.defaults["require_spec_review"] = True
    _write(dctx, status="reviewed")
    _write(dctx, topic="fmt/draft", status="draft")
    st = dctx.indexer.store("proj")
    assert [s["topic"] for s in sp.approve(st, dry_run=True)] == ["fmt/a"]
    assert [s["topic"] for s in sp.approve(st)] == ["fmt/a"]
    final, skipped, gone, refused = sp.publish(st, dctx.indexer.paths("proj"), "person", "")
    assert [s["topic"] for s in final] == ["fmt/a"] and skipped == 1 and not refused


# -- follow-ups: stale clean map, old deny rules --------------------------------------

def _map(purpose: str, *specs: str) -> str:
    return "\n".join(["# proj (clean map)", "## Purpose", purpose, "## Specs", *specs]) + "\n"


def test_dirty_open_renders_the_clean_map_again(dctx):
    pp = dctx.indexer.paths("proj")
    st = dctx.indexer.store("proj")
    pm.set_purpose(st, DIRTY_PURPOSE)
    (pp.clean / "PROJECT.md").write_text(_map(DIRTY_PURPOSE), "utf-8")
    d = _fresh(dctx)
    assert registry.call(d, "project_open", "proj", "dirty").startswith("session dirty")
    text = (pp.clean / "PROJECT.md").read_text("utf-8")
    assert "FUN_00401100" not in text and "puVar3" not in text and "(not set yet)" in text


def test_server_start_migration_cleans_old_maps(dctx):
    pp = dctx.indexer.paths("proj")
    f = pp.clean / "PROJECT.md"
    f.write_text(_map(DIRTY_PURPOSE, "fmt/a | T | v1 | final"), "utf-8")
    assert pm.migrate_clean_maps(dctx.config.projects_root) == ["proj"]
    text = f.read_text("utf-8")
    assert "FUN_00401100" not in text and "fmt/a | T | v1 | final" in text and "(not set yet)" in text
    f.write_text(_map("Edits brew logs."), "utf-8")
    assert pm.migrate_clean_maps(dctx.config.projects_root) == []
    assert "Edits brew logs." in f.read_text("utf-8")


def test_dirty_open_refreshes_old_deny_rules(dctx):
    pp = dctx.indexer.paths("proj")
    cj = pp.clean / ".claude" / "settings.json"
    cj.parent.mkdir(parents=True, exist_ok=True)
    cj.write_text(json.dumps({"permissions": {"deny": [f"Read({P._claude_rule_path(pp.dirty)}/**)"]}}))  # old: one rule
    assert not P.deny_rules_current(pp)
    d = _fresh(dctx)
    registry.call(d, "project_open", "proj", "dirty")
    deny = json.loads(cj.read_text("utf-8"))["permissions"]["deny"]
    assert f"Read({P._claude_rule_path(pp.manifest)})" in deny
    assert str(dctx.config.data_dir.resolve()).replace("\\", "/") in " ".join(deny)
    assert (pp.dirty / ".claude" / "settings.json").exists()
