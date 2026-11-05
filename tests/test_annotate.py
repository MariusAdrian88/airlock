"""annotate tools against a fake worker (no Ghidra): invalidation, notes, gates."""

from __future__ import annotations

import dataclasses

import pytest

from airlock.index import store as sm
from airlock.server import registry, roles
from airlock.server.indexer import run_extraction
from airlock.server.tools import annotate as an, core
from airlock.worker.ghidra_ops.annotate import (
    check_struct_fields, join_plate, notes_block, split_name, split_plate,
)
from airlock.worker.protocol import WorkerError
from test_tools import FakeWorker, fill, make_ctx

MAIN, ONFOO, FUN2 = 0x401000, 0x401100, 0x401200
WRITE_OPS = ("patch_bytes", "rename_variable", "retype_variable", "set_comment", "annotate_function",
             "define_struct", "rename_label")


class AnnWorker(FakeWorker):
    def __init__(self) -> None:
        super().__init__()
        self.writes: list[tuple[str, dict]] = []
        self.memory = bytes.fromhex("8bff55")

    def request(self, op, args=None, timeout=0):
        args = args or {}
        if op == "rename_function":
            self.calls.append((op, args))
            self.writes.append((op, args))
            if args["new_name"] == "bad!":
                raise WorkerError("bad_name", "InvalidInputException: invalid characters")
            if args["entry"] in (FUN2, ONFOO):
                self.c_text = self.c_text.replace("FUN_00401200", args["new_name"]).replace(
                    "OnFoo", args["new_name"])
            return {"entry": args["entry"], "name": args["new_name"], "namespace": None,
                    "signature": f"void {args['new_name']}(void)", "calling_conv": "__cdecl",
                    "old": "x"}
        if op in WRITE_OPS:
            self.calls.append((op, args))
            self.writes.append((op, args))
            if args.get("new_name") == "bad!":
                raise WorkerError("bad_name", "InvalidInputException: invalid characters")
            base = {"entry": args.get("entry"), "name": "main", "namespace": None,
                    "signature": "int main(void)", "calling_conv": "__cdecl"}
            if op == "patch_bytes":
                if args["address"] == 0x7FFF0000:
                    raise WorkerError("uninitialized", "0x7fff0000 is not in initialised memory")
                if args.get("expect") and args["expect"] != self.memory.hex() and not args.get("force"):
                    raise WorkerError("changed", "bytes differ")
                old, self.memory = self.memory.hex(), bytes.fromhex(args["hex"])
                return {"address": args["address"], "length": len(self.memory), "old": old,
                        "new": args["hex"], "cleared": [args["address"], args["address"] + 2],
                        "instructions": 3, "functions": [MAIN]}
            if op == "retype_variable":
                self.c_text = self.c_text.replace("OnFoo();", "char *p = OnFoo();")
                return {**base, "variable": args["variable"], "is_param": False, "type": args["type"]}
            if op == "rename_variable":
                return {**base, "is_param": True}
            if op == "set_comment":
                return {"address": args["address"], "kind": args["kind"], "cleared": not args["text"]}
            if op == "annotate_function":
                if args.get("new_name"):
                    return {**base, "name": args["new_name"], "old": "main", "renamed": True}
                return {**base, "old": "main", "renamed": False}
            if op == "rename_label":
                return {"address": args.get("address", 0x403000), "space": "ram", "old": "",
                        "new": args["new_name"]}
            return {"name": args["name"], "size": 8, "fields": len(args["fields"]), "replaced": True}
        return super().request(op, args, timeout)


@pytest.fixture
def ctx(tmp_path):
    c = make_ctx(tmp_path)
    c.worker = AnnWorker()
    c.indexer.worker = c.worker
    c.worker.project_path = str(c.indexer.paths("proj", create=True).ghidra)
    fill(c)
    return c


def _fn(ctx, entry):
    st = ctx.indexer.store("proj")
    return st, st.function_at(st.list_binaries()[0].id, entry)


def test_rename_callee_refreshes_caller_decompile(ctx):
    w = ctx.worker
    before = core.function(ctx, "main")
    assert "FUN_00401200" in before
    n = w.count("decompile")
    assert core.function(ctx, "main") == before and w.count("decompile") == n   # cached
    out = an.rename(ctx, "FUN_00401200", "ParseHeader")
    assert out.startswith("renamed ") and "invalidated" in out, out
    st, fn = _fn(ctx, FUN2)
    assert fn.name == "ParseHeader" and fn.name_state == "user"
    after = core.function(ctx, "main")
    assert "ParseHeader" in after and "FUN_00401200" not in after
    assert w.count("decompile") > n                        # the caller was decompiled again
    assert st.fts_search(fn.binary_id, "ParseHeader", "function")


def test_rename_bumps_function_and_callers_only(ctx):
    st, _ = _fn(ctx, FUN2)
    bid = st.list_binaries()[0].id
    before = {f.entry: f.version for f in st.list_functions(bid)}
    an.rename(ctx, "FUN_00401200", "Zork")
    after = {f.entry: f.version for f in st.list_functions(bid)}
    assert {e for e in after if after[e] != before[e]} == {FUN2, ONFOO, MAIN}


def test_asm_cache_refreshes(ctx):
    core.function(ctx, "main", view="asm")
    n = ctx.worker.count("disassemble")
    core.function(ctx, "main", view="asm")
    assert ctx.worker.count("disassemble") == n
    an.rename(ctx, "OnFoo", "Handler")
    core.function(ctx, "main", view="asm")
    assert ctx.worker.count("disassemble") == n + 1


def test_rename_errors_are_one_line(ctx):
    assert an.rename(ctx, "main", "bad!").startswith("error bad_name:")
    assert an.rename(ctx, "main", "has space").startswith("error bad_args:")
    assert an.rename(ctx, "main", "x", kind="bogus").startswith("error bad_args:")
    assert an.rename(ctx, "nope_nope", "x").startswith("error not_found")
    assert an.rename(ctx, "x", "y", kind="local").startswith("error bad_args:")
    assert an.rename(ctx, "main", "main").startswith("unchanged")


def test_retype_returns_excerpt_and_invalidates(ctx):
    out = an.retype(ctx, "main", "p", "char *")
    assert out.startswith("retyped variable p in main to char *"), out
    assert "char *p = OnFoo();" in out


def test_comment_bumps_containing_function(ctx):
    st, fn = _fn(ctx, MAIN)
    out = an.comment(ctx, "0x00401010", "hello", kind="eol")
    assert "eol comment set at 0x00401010 in main" in out, out
    assert ctx.worker.writes[-1][1]["address"] == 0x401010   # exact address, not the entry
    assert st.get_function(fn.id).version == fn.version + 1
    assert an.comment(ctx, "main", "x", kind="weird").startswith("error bad_args")


def test_annotate_note_rename_and_search(ctx):
    out = an.annotate(ctx, "main", "Entry point; opens the file", tags="io, Startup",
                      confidence="high", new_name="AppMain")
    assert out.startswith("note #1 saved on AppMain") and "renamed main -> AppMain" in out, out
    _st, fn = _fn(ctx, MAIN)
    assert fn.name == "AppMain"
    w = ctx.worker.writes[-1]
    assert w[0] == "annotate_function" and w[1]["new_name"] == "AppMain"
    assert any("Entry point" in ln for ln in w[1]["notes"])      # mirrored (default on)
    text = core.function(ctx, "AppMain")
    assert "// note #1 [high] Entry point; opens the file (tags: io,Startup)" in text
    s = core.search(ctx, "opens file", kind="note")
    assert "note #1 AppMain" in s, s
    assert "note #1" in core.search(ctx, "opens")              # kind=any includes notes
    assert "note #1" in core.function(ctx, "AppMain", view="signature")


def test_annotate_without_rename_or_mirror_makes_no_ghidra_write(ctx):
    ctx.config.defaults["mirror_notes_to_ghidra"] = False
    out = an.annotate(ctx, "OnFoo", "handles foo")
    assert out.startswith("note #1 saved") and not ctx.worker.writes
    assert an.annotate(ctx, "OnFoo", "  ").startswith("error bad_args")
    assert an.annotate(ctx, "OnFoo", "x", confidence="sure").startswith("error bad_args")


def test_annotate_failure_leaves_no_note(ctx):
    assert an.annotate(ctx, "main", "x", new_name="bad!").startswith("error bad_name")
    st, _ = _fn(ctx, MAIN)
    assert st.count_notes() == 0


def test_notes_survive_reextraction(ctx):
    ctx.config.defaults["mirror_notes_to_ghidra"] = False
    an.annotate(ctx, "main", "keeper note", tags="a")
    st = ctx.indexer.store("proj")
    run_extraction(ctx.worker, st, st.list_binaries()[0].id, "app_exe")   # clears derived rows
    assert st.count_notes() == 1
    assert "keeper" in core.function(ctx, "main")
    assert "note #1" in core.search(ctx, "keeper", kind="note")


def test_struct_define_invalidates_functions_mentioning_it(ctx):
    core.function(ctx, "main")
    st, fn = _fn(ctx, MAIN)
    st.upsert_decomp(fn.id, fn.version, "prof1", "ok", c_text="void main(void){ Rec *r; }")
    out = an.struct_define(ctx, "Rec", [{"offset": 0, "type": "int", "name": "a"}])
    assert out.startswith("struct Rec replaced") and "invalidated 1" in out, out
    assert st.get_function(fn.id).version == fn.version + 1
    assert an.struct_define(ctx, "bad name", [{"offset": 0, "type": "int", "name": "a"}]
                            ).startswith("error bad_args")


def test_global_rename_invalidates_referencing_functions(ctx):
    st, fn = _fn(ctx, MAIN)
    out = an.rename(ctx, "0x00403000", "g_msg", kind="global")
    assert "named global g_msg at 0x00403000" in out, out
    assert st.get_function(fn.id).version == fn.version + 1   # main references 0x403000


def test_gates(ctx):
    ctx.session = roles.SessionState("clean", None)
    assert an.rename(ctx, "main", "x").startswith("error wrong_role")
    assert registry.call(ctx, "rename", "main", "x").startswith("error wrong_role")


def test_writes_disabled(ctx):
    ctx.config = dataclasses.replace(ctx.config, allow_writes=False)
    assert an.annotate(ctx, "main", "x").startswith("error writes_disabled")


def test_patch_bytes_note_invalidation_and_restore(ctx):
    core.function(ctx, "main")
    st, fn = _fn(ctx, MAIN)
    out = an.patch_bytes(ctx, "0x00401001", "90 90 90", why="skip the check")
    assert out.startswith("patched 3 bytes at 0x00401001 in main: old 8bff55, new 909090; note #1; "
                          "invalidated 1 cached decompile"), out
    assert "re-disassembled 3 instructions" in out and out.endswith("Undo with patch_bytes(restore=1).")
    w = ctx.worker.writes[-1]
    assert w[0] == "patch_bytes" and w[1]["hex"] == "909090" and w[1]["address"] == 0x401001
    assert st.get_function(fn.id).version == fn.version + 1           # decompile and asm are recomputed
    note = st.get_note(1)
    assert note["tags"] == "patch" and note["author"] == "agent" and note["entry"] == MAIN
    assert "old=8bff55 new=909090 why: skip the check" in note["summary"]
    assert "// note #1" in core.function(ctx, "main")
    back = an.patch_bytes(ctx, restore=1)                                # the note's old bytes come back
    assert back.startswith("patched 3 bytes at 0x00401001") and "old 909090, new 8bff55" in back, back
    w = ctx.worker.writes[-1][1]
    assert w["hex"] == "8bff55" and w["expect"] == "909090"
    assert "(restore of note #1)" in st.get_note(2)["summary"]
    assert ctx.worker.memory == bytes.fromhex("8bff55")
    assert an.patch_bytes(ctx, restore=1).startswith("error changed")      # bytes are not the patch any more
    assert an.patch_bytes(ctx, restore=99).startswith("error not_found")


def test_patch_bytes_refusals(ctx):
    assert an.patch_bytes(ctx, "0x00401001", "9").startswith("error bad_args")
    assert an.patch_bytes(ctx, "0x00401001", "zz").startswith("error bad_args")
    assert an.patch_bytes(ctx, "0x00401001", "90" * 513).startswith("error bad_args")
    assert an.patch_bytes(ctx, "", "90").startswith("error bad_target")
    assert an.patch_bytes(ctx, "0x7fff0000", "90").startswith("error uninitialized")
    st, _ = _fn(ctx, MAIN)
    assert st.count_notes() == 0                                           # a refused patch leaves no note
    ctx.session = roles.SessionState("clean", None)
    assert registry.call(ctx, "patch_bytes", "0x00401001", "90").startswith("error wrong_role")
    ctx.session = roles.SessionState("dirty", None)
    ctx.config = dataclasses.replace(ctx.config, allow_writes=False)
    assert an.patch_bytes(ctx, "0x00401001", "90").startswith("error writes_disabled")


def test_patch_bytes_is_off_by_default():
    from airlock.config.catalog import CATALOG
    from airlock.config.keys import KEYS
    assert "patch_bytes" in {k.name: k for k in KEYS}["disabled_tools"].default and not CATALOG["patch_bytes"].clean_safe


def test_patch_hex_parsing():
    from airlock.worker.ghidra_ops.annotate import parse_patch_hex
    assert parse_patch_hex("8B FF,0x55") == bytes.fromhex("8bff55")
    for bad in ("", "8", "xyz", "90" * 513):
        with pytest.raises(WorkerError):
            parse_patch_hex(bad)


def test_pure_helpers():
    user, block = split_plate("hello\n" + notes_block(["- a", "- b"]))
    assert user == "hello" and block.startswith("--- airlock notes ---") and "- b" in block
    assert join_plate("new", block).startswith("new\n--- airlock notes ---")
    assert split_plate(join_plate("x", "")) == ("x", "")
    assert split_name("A::B::c") == ("A::B", "c") and split_name("c") == ("", "c")
    got = check_struct_fields([{"offset": "0x8", "type": "int", "name": "b"},
                               {"offset": 0, "type": "int", "name": "a"}], None)
    assert got[0][0] == 0
    with pytest.raises(WorkerError):
        check_struct_fields([{"offset": 0, "type": "int", "name": "a"}] * 2, None)


def test_migration_adds_note_table(tmp_path):
    p = tmp_path / "old.sqlite"
    s = sm.Store(p)
    s.db.execute("DROP TABLE note")
    s.set_meta("schema_version", "7")
    s.db.commit()
    s.close()
    s2 = sm.Store(p)
    assert s2.db.execute("SELECT COUNT(*) FROM note").fetchone()[0] == 0
    s2.close()
