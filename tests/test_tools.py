"""Indexer mapping and every core tool, against a fake worker (no Ghidra)."""

from __future__ import annotations

import re
import time
from typing import Any

import pytest

from airlock.config.loader import deep_merge, default_config_text, parse_jsonc, resolve
from airlock.server import indexer as ixm
from airlock.server.context import ServerContext
from airlock.server.tools import admin, core
from airlock.worker.protocol import WorkerError
from test_projects import make_pe

FN_COLS = ["space", "entry", "name", "name_state", "source", "namespace", "signature",
           "calling_conv", "size", "is_thunk", "is_external"]
EDGE_COLS = ["src_addr", "src_fn", "dst_space", "dst_addr", "dst_fn", "kind"]
STR_COLS = ["space", "address", "encoding", "length", "value"]
IMP_COLS = ["dll", "name", "ordinal", "space", "address"]
EXP_COLS = ["name", "ordinal", "space", "address"]

FUNCTIONS = [
    ["ram", 0x401000, "main", "user", "USER_DEFINED", None, "int main(void)", "__cdecl", 0x40, 0, 0],
    ["ram", 0x401100, "OnFoo", "auto", "ANALYSIS", "CMainFrame", "void OnFoo(void)", "__thiscall", 0x20, 0, 0],
    ["ram", 0x401200, "FUN_00401200", "auto", "DEFAULT", None, "void FUN_00401200(void)", "__cdecl", 0x10, 0, 0],
    ["ram", 0x401300, "CreateFileW", "library", "IMPORTED", None, "void CreateFileW(void)", "__stdcall", 6, 1, 0],
    ["EXTERNAL", 1, "CreateFileW", "library", "IMPORTED", "KERNEL32.DLL", "void CreateFileW(void)", "__stdcall", 0, 0, 1],
]
EDGES = [
    [0x401005, 0x401000, "ram", 0x403000, None, "data"],
    [0x401010, 0x401000, "ram", 0x401100, 0x401100, "call"],
    [0x401020, 0x401000, "ram", 0x401200, 0x401200, "call"],
    [0x401030, 0x401000, "ram", 0x401300, 0x401300, "call"],
    [0x401110, 0x401100, "ram", 0x401200, 0x401200, "call"],
    [0x401205, 0x401200, "ram", 0x401000, 0x401000, "call"],
    [0x401300, 0x401300, "EXTERNAL", 1, 1, "jump"],
    [0x40111c, 0x401100, "ram", 0x403100, None, "read"],
]
STRINGS = [
    ["ram", 0x403000, "ascii", 16, "Open file failed"],
    ["ram", 0x403100, "utf16le", 5, "other"],
    ["OTHER", 0x10, "ascii", 3, "xyz"],
]
IMPORTS = [["KERNEL32.DLL", "CreateFileW", None, "ram", 0x402000]]
EXPORTS = [["main", None, "ram", 0x401000]]
DATA = {"functions": (FN_COLS, FUNCTIONS), "edges": (EDGE_COLS, EDGES),
        "strings": (STR_COLS, STRINGS), "imports": (IMP_COLS, IMPORTS),
        "exports": (EXP_COLS, EXPORTS)}

ASM_ROWS = [
    [0x401000, 1, "PUSH EBP", "", "", 1],
    [0x401001, 2, "MOV EBP,ESP", "", "", 0],
    [0x401003, 5, "CALL 0x00401100", "CMainFrame::OnFoo", "", 0],
    [0x401008, 2, "TEST EAX,EAX", "", "", 0],
    [0x40100a, 2, "JZ LAB_00401012", "", "", 0],
    [0x40100c, 5, "PUSH 0x403000", '"Open file failed"', "", 1],
    [0x401011, 1, "RET", "", "", 0],
    [0x401012, 1, "POP EBP", "", "LAB_00401012", 1],
]

C_TEXT = "void main(void)\n{\n  OnFoo();\n  FUN_00401200();\n  return;\n}\n"


def _ast(text: str) -> list[list[Any]]:
    rows = []
    for name, target in (("OnFoo", 0x401100), ("FUN_00401200", 0x401200)):
        i = text.find(name)
        if i < 0:
            continue
        rows.append(["call", i, i + len(name), 0x401010, target, name])
    return rows


class FakeWorker:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.listeners: list[Any] = []
        self.ghidra = {"ghidra_version": "12"}
        self.c_text = C_TEXT
        self.analyze_reply: dict[str, Any] = {"state": "analysing", "started": True}
        self.decompile_reply: dict[str, Any] | None = None
        self.fail_op: str | None = None
        self.page = 3

    def on_event(self, cb: Any) -> None:
        self.listeners.append(cb)

    def emit(self, **msg: Any) -> None:
        for cb in self.listeners:
            cb({"event": "progress", "job": "analysis", **msg})

    def progress(self, program: str | None = None) -> dict | None:
        return {"analyzers_done": 7, "functions": 99}

    def running(self) -> bool:
        return True

    def ensure_ghidra(self, timeout: float = 0) -> dict:
        return self.ghidra

    def count(self, op: str) -> int:
        return sum(1 for o, _ in self.calls if o == op)

    def request(self, op: str, args: dict | None = None, timeout: float = 0) -> dict:
        args = args or {}
        self.calls.append((op, args))
        if op == self.fail_op:
            raise WorkerError("boom", "it broke")
        if op == "open_project":
            return {"created": True}
        if op == "import_binary":
            return {"pointer_size": 4, "image_base": 0x400000}
        if op == "analyze":
            return self.analyze_reply
        if op == "status":
            return {"project": {"path": self.project_path, "name": ixm.GHIDRA_PROJECT_NAME},
                    "programs": [{"program": "x", "analysis_profile": "prof1"}]}
        if op == "extract":
            cols, rows = DATA[args["kind"]]
            o, n = args["offset"], min(args["limit"], self.page)
            part = rows[o:o + n]
            done = o + n >= len(rows)
            return {"columns": cols, "rows": part, "done": done,
                    "next_offset": None if done else o + n,
                    "image_base": 0x400000, "pointer_size": 4}
        if op == "decompile":
            if self.decompile_reply is not None:
                return self.decompile_reply
            return {"status": "ok", "c_text": self.c_text, "error": None,
                    "ast_columns": ["kind", "start_off", "end_off", "address", "target", "text"],
                    "ast": _ast(self.c_text)}
        if op == "disassemble":
            return {"entry": args["entry"], "name": "main", "columns": [], "total": len(ASM_ROWS),
                    "truncated": False, "rows": ASM_ROWS}
        raise AssertionError(op)

    project_path = ""


def make_ctx(tmp_path) -> ServerContext:
    merged = deep_merge(parse_jsonc(default_config_text()),
                        {"ghidra_dir": str(tmp_path / "g"), "index_dir": str(tmp_path / "data"),
                         "projects_root": str(tmp_path / "projects"),
                         "defaults": {"bulk_decompile": "lazy"}})  # tests opt in to the pass
    fake = FakeWorker()
    ctx = ServerContext(config=resolve(merged, "dirty", None), worker=fake)
    fake.project_path = str(ctx.indexer.paths("proj", create=True).ghidra)
    return ctx


def fill(ctx: ServerContext, project: str = "proj", name: str = "app.exe", sha: str = "ab" * 32) -> int:
    """A ready binary with synthetic rows (extracted through the real mapping code)."""
    ix = ctx.indexer
    st = ix.store(project)
    bid = st.upsert_binary(sha, name, format="pe32", arch="x86", pointer_size=4,
                           image_base=0x400000, toolchain="msvc", analysis_profile="prof1")
    st.set_meta(f"program:{bid}", "app_exe")
    ixm.run_extraction(ctx.worker, st, bid, "app_exe")
    ix.set_status(st, bid, "ready")
    ix.current = project
    return bid


@pytest.fixture
def ctx(tmp_path):
    c = make_ctx(tmp_path)
    fill(c)
    return c


# ── indexer ──────────────────────────────────────────────────────────────────

def test_row_mapping():
    fns = ixm.map_function_rows(FN_COLS, FUNCTIONS)
    assert fns[1] == {"space": "ram", "entry": 0x401100, "name": "OnFoo", "name_state": "auto",
                      "namespace": "CMainFrame", "signature": "void OnFoo(void)",
                      "calling_conv": "__thiscall", "size": 0x20, "is_thunk": False,
                      "is_external": False}
    assert fns[4]["is_external"] is True and fns[4]["space"] == "EXTERNAL"
    assert ixm.map_edge_rows(EDGE_COLS, EDGES)[:2] == [(0x401005, 0x403000, "data"),
                                                       (0x401010, 0x401100, "call")]
    assert len(ixm.map_edge_rows(EDGE_COLS, EDGES)) == len(EDGES) - 1  # EXTERNAL dst dropped
    assert ixm.map_string_rows(STR_COLS, STRINGS) == [(0x403000, "ascii", "Open file failed"),
                                                     (0x403100, "utf16le", "other")]
    assert ixm.map_import_rows(IMP_COLS, IMPORTS) == [("KERNEL32.DLL", "CreateFileW", None, 0x402000)]


def test_run_extraction_pages_and_links(ctx):
    st = ctx.indexer.store("proj")
    b = st.list_binaries()[0]
    assert ctx.worker.count("extract") == 8  # page size 3 forces several requests
    assert st.counts(b.id)["functions"] == 5
    assert st.counts(b.id)["edges"] == 7
    main = st.function_at(b.id, 0x401000)
    assert [f.name for f in st.callees(main)] == ["OnFoo", "FUN_00401200", "CreateFileW"]
    assert st.fts_search(b.id, "onfoo", "function")
    assert st.fts_search(b.id, "file", "function")  # camel-case words are searchable
    # idempotent: a second run replaces, never duplicates
    ixm.run_extraction(ctx.worker, st, b.id, "app_exe")
    assert st.counts(b.id)["functions"] == 5 and st.counts(b.id)["edges"] == 7


def _wait(job_event, secs=5.0):
    assert job_event.wait(secs), "job did not finish"


def test_open_binary_flow_and_idempotence(tmp_path):
    ctx = make_ctx(tmp_path)
    exe = make_pe(tmp_path / "App One.exe")
    out = core.open_binary(ctx, "proj", str(exe))
    assert "App One.exe" in out and "status=analysing" in out and "sha256:" in out
    ix = ctx.indexer
    st = ix.store("proj")
    b = st.list_binaries()[0]
    assert ix.get_status(st, b.id)[0] == "analysing"
    assert ctx.worker.calls[0][0] == "open_project"
    assert ctx.worker.calls[1][1]["program_name"] == "App_One_exe"
    assert "not_analysed" in core.strings(ctx, "x")
    assert "analysing" in admin.index_status(ctx)
    ctx.worker.emit(program="App_One_exe", state="done", pct=None)
    _wait(ix.job_for("proj", b.id).finished)
    assert ix.get_status(st, b.id)[0] == "ready"
    b = st.get_binary_by_id(b.id)
    assert b.analysis_profile == "prof1" and b.pointer_size == 4 and b.image_base == 0x400000
    assert st.counts(b.id)["functions"] == 5
    n = len(ctx.worker.calls)
    again = core.open_binary(ctx, "proj", str(exe))
    assert "status=ready" in again and "already opened" in again
    assert len(ctx.worker.calls) == n
    assert core.strings(ctx, "open file").startswith("strings matching")


def test_open_binary_resumes_already_analysed(tmp_path):
    ctx = make_ctx(tmp_path)
    ctx.worker.analyze_reply = {"state": "ready", "already_analysed": True}
    exe = make_pe(tmp_path / "a.exe")
    core.open_binary(ctx, "proj", str(exe))
    b = ctx.indexer.store("proj").list_binaries()[0]
    _wait(ctx.indexer.job_for("proj", b.id).finished)
    assert ctx.indexer.get_status(ctx.indexer.store("proj"), b.id)[0] == "ready"


def test_open_binary_errors(tmp_path):
    ctx = make_ctx(tmp_path)
    assert core.open_binary(ctx, "proj", str(tmp_path / "nope.exe")).startswith("error not_found:")
    txt = tmp_path / "x.txt"
    txt.write_text("hello")
    assert core.open_binary(ctx, "proj", str(txt)).startswith("error unsupported:")
    ctx.worker.fail_op = "import_binary"
    exe = make_pe(tmp_path / "b.exe")
    out = core.open_binary(ctx, "proj", str(exe))
    assert "status=error" in out and "boom" in out
    msg = core.strings(ctx, "x")
    assert msg.startswith("error not_analysed:") and "failed to index" in msg


def test_analysis_error_event(tmp_path):
    ctx = make_ctx(tmp_path)
    core.open_binary(ctx, "proj", str(make_pe(tmp_path / "c.exe")))
    ctx.worker.emit(program="c_exe", state="error", message="kaboom")
    st = ctx.indexer.store("proj")
    b = st.list_binaries()[0]
    deadline = time.time() + 5
    while ctx.indexer.get_status(st, b.id)[0] != "error" and time.time() < deadline:
        time.sleep(0.02)
    assert "kaboom" in ctx.indexer.get_status(st, b.id)[1]


# ── binary selection / readiness ─────────────────────────────────────────────

def test_not_ready_and_binary_selection(ctx):
    st = ctx.indexer.store("proj")
    b2 = st.upsert_binary("cd" * 32, "other.dll", pointer_size=4)
    ctx.indexer.set_status(st, b2, "analysing")
    out = core.strings(ctx, "open")  # no binary given: every ready binary, the other is skipped
    assert out.startswith("strings matching") and "1 binaries not ready, skipped" in out
    assert core.strings(ctx, "open", binary="app.exe").startswith("strings matching")
    out = core.strings(ctx, "open", binary="other.dll")
    assert out.startswith("error not_analysed:") and "analysing" in out and "index_status" not in out
    assert core.strings(ctx, "open", binary="zzz").startswith("error not_found:")
    assert core.strings(ctx, "open", binary="cdcd").startswith("error not_analysed:")  # sha prefix


def test_no_project_errors(tmp_path):
    ctx = make_ctx(tmp_path)
    ctx.indexer.paths("proj", create=False)
    import shutil
    shutil.rmtree(ctx.indexer.paths("proj").root)
    assert core.strings(ctx, "x").startswith("error no_project:")
    assert "no binaries" in core.list_binaries(ctx)


# ── tools ────────────────────────────────────────────────────────────────────

def test_list_binaries_and_index_status(ctx):
    out = core.list_binaries(ctx)
    assert out == "proj/#1 app.exe pe32 x86 msvc sha256:" + "ab" * 6 + " ready fns=5 links=0/0"
    st = admin.index_status(ctx)
    assert "worker running" in st and "#1 app.exe ready: 5 functions, 2 strings, 1 imports, 7 edges" in st
    assert core.list_binaries(ctx, "nope").startswith("error no_project:")


def test_outline(ctx):
    out = core.outline(ctx)
    assert out.splitlines()[0].startswith("app.exe pe32 x86 msvc ptr 4 base 0x00400000")
    assert "functions 5 (auto 2, library 2, user 1; thunks 1, external 1)" in out
    assert "imports 1 from 1 DLLs: KERNEL32.DLL 1" in out
    assert "strings 2, edges 7" in out


def test_strings(ctx):
    out = core.strings(ctx, "FILE")
    assert out.splitlines() == ["strings matching 'FILE': 1",
                                '0x00403000 "Open file failed"  <- main']
    assert '"other"' in core.strings(ctx, "oth", with_refs=False)
    assert "utf16le" in core.strings(ctx, "oth")
    assert "(no refs)" not in core.strings(ctx, "oth")  # 0x403100 is read by OnFoo
    assert core.strings(ctx, "^open.*failed$", regex=True).count("\n") == 1
    bad = core.strings(ctx, "(", regex=True)        # a bad regex is searched as literal text
    assert bad.startswith("no strings match '('") and "(literal used: bad regex:" in bad
    assert core.strings(ctx, "zzz") == "no strings match 'zzz'"
    assert core.strings(ctx, "zzz|yyy") == "no strings match 'zzz|yyy' (regex used: no literal match)"
    alt = core.strings(ctx, "zzz|other")            # literal `a|b` found nothing: the regex did
    assert alt.startswith("strings matching 'zzz|other': ") and "(regex used: no literal match)" in alt
    assert '"other"' in alt
    assert core.strings(ctx, "zzz|yyy", regex=True) == "no strings match 'zzz|yyy'"
    assert core.strings(ctx, "").startswith("error bad_args:")


def test_search(ctx):
    out = core.search(ctx, "file")
    lines = out.splitlines()
    assert lines[0] == "search 'file': 3 hits"  # the EXTERNAL CreateFileW row is dropped
    assert "EXTERNAL" not in out
    kinds = {ln.split()[0] for ln in lines[1:]}
    assert kinds == {"function", "string", "import"}
    assert "function CreateFileW 0x00401300 library,thunk,6B" in out
    assert 'string 0x00403000 "Open file failed"' in out
    assert "import KERNEL32.DLL!CreateFileW slot 0x00402000" in out
    assert core.search(ctx, "onfoo", kind="function").splitlines()[1].startswith(
        "function CMainFrame::OnFoo 0x00401100")
    assert core.search(ctx, "zzzz") == "no hits for 'zzzz'"
    assert core.search(ctx, "x", kind="class").startswith("error unbound:")   # forwarded to rtti_classes
    assert core.search(ctx, "x", kind="bogus").startswith("error bad_args:")
    paged = core.search(ctx, "file", limit=2).splitlines()
    assert paged[0] == "search 'file': 3 hits" and len(paged) == 4
    assert paged[-1].startswith("… 1 more lines. cursor=")


def _synthetic_search_store(ctx):
    st = ctx.indexer.store("proj")
    b = st.list_binaries()[0]
    st.insert_functions(b.id, [
        {"entry": 0x501000, "name": "WidgetOpen", "name_state": "user", "size": 8},
        {"entry": 0x501100, "name": "FUN_00501100", "name_state": "auto", "size": 8},
        {"entry": 0x501200, "name": "Widget", "name_state": "user", "size": 8},
        {"entry": 0x501300, "name": "OpenWidgetNow", "name_state": "user", "size": 8},
        {"entry": 0x501400, "name": "QueryThing", "name_state": "library", "is_thunk": True, "size": 6},
        {"space": "EXTERNAL", "entry": 0x101, "name": "QueryThing", "namespace": "LIB-A.DLL",
         "name_state": "library", "is_external": True},
        {"space": "EXTERNAL", "entry": 0x102, "name": "OnlyExt", "namespace": "LIB-B.DLL",
         "name_state": "library", "is_external": True},
        {"space": "EXTERNAL", "entry": 0x103, "name": "ViaImport", "namespace": "LIB-C.DLL",
         "name_state": "library", "is_external": True},
    ])
    st.insert_imports(b.id, [("LIB-A.DLL", "QueryThing", None, 0x502000),
                             ("LIB-C.DLL", "ViaImport", None, 0x502004),
                             ("LIB-D.DLL", "WidgetImp", None, 0x502008)])
    st.insert_strings(b.id, [(0x503000, "ascii", "widget text"), (0x503100, "ascii", "Widget")])
    st.rebuild_fts(b.id)


def test_search_external_dedup(ctx):
    _synthetic_search_store(ctx)
    out = core.search(ctx, "querything")
    assert "EXTERNAL" not in out
    assert out.splitlines()[0] == "search 'querything': 2 hits"
    assert out.splitlines()[1].startswith("function QueryThing 0x00501400 library,thunk,6B")
    assert out.splitlines()[2] == "import LIB-A.DLL!QueryThing slot 0x00502000"
    assert core.search(ctx, "viaimport").splitlines()[1:] == [
        "import LIB-C.DLL!ViaImport slot 0x00502004"]
    assert core.search(ctx, "onlyext").splitlines()[1:] == ["import-only LIB-B.DLL::OnlyExt"]


def test_search_ranking(ctx):
    _synthetic_search_store(ctx)
    lines = core.search(ctx, "widget").splitlines()[1:]
    kinds = [ln.split()[0] + " " + ln.split()[1] for ln in lines]
    # groups: functions, imports, strings; rank order inside each group
    assert lines[0].startswith("function Widget ")
    assert lines[1].startswith("function WidgetOpen ")
    assert lines[2].startswith("function OpenWidgetNow ")
    assert lines[3].startswith("import LIB-D.DLL!WidgetImp")
    assert lines[4].startswith('string 0x00503100 "Widget"')
    assert lines[5].startswith('string 0x00503000 "widget text"')
    assert len(lines) == 6, kinds


def test_search_fun_after_named_and_limit_after_dedup(ctx):
    _synthetic_search_store(ctx)
    st = ctx.indexer.store("proj")
    b = st.list_binaries()[0]
    st.insert_functions(b.id, [{"entry": 0x504000, "name": "FUN_00504000", "name_state": "auto"},
                               {"entry": 0x504100, "name": "FunnyHelper", "name_state": "user"}])
    st.rebuild_fts(b.id)
    lines = core.search(ctx, "fun", kind="function").splitlines()[1:]
    names = [ln.split()[1] for ln in lines]
    assert names == ["FunnyHelper", "FUN_00401200", "FUN_00501100", "FUN_00504000"]
    # the kind column is not searched: "string" must not match every string row
    assert core.search(ctx, "string") == "no hits for 'string'"
    # limit counts after dedup: both externals of 'querything'/'viaimport' vanish, so
    # limit=2 still returns two real hits.
    out = core.search(ctx, "querything", limit=2).splitlines()
    assert out[0] == "search 'querything': 2 hits" and len(out) == 3


def _balance_store(ctx, n_fn, n_imp, strings):
    st = ctx.indexer.store("proj")
    b = st.list_binaries()[0]
    st.insert_functions(b.id, [{"entry": 0x601000 + i * 16, "name": f"ReadFn{i:02d}",
                                "name_state": "user", "size": 4} for i in range(n_fn)])
    st.insert_imports(b.id, [("LIB-Z.DLL", f"ReadImp{i:02d}", None, 0x602000 + 4 * i)
                             for i in range(n_imp)])
    st.insert_strings(b.id, strings)
    st.rebuild_fts(b.id)


def _kind_counts(out):
    lines = out.splitlines()[1:]
    return [sum(1 for ln in lines if ln.startswith(k + " ")) for k in ("function", "import", "string")]


def test_search_drops_import_name_strings(ctx):
    _balance_store(ctx, 1, 1, [(0x603000, "ascii", "ReadImp00"), (0x603100, "ascii", "readimp00"),
                               (0x603200, "ascii", "ReadImp00 failed")])
    out = core.search(ctx, "readimp00")
    assert '"ReadImp00"' not in out  # exact import name: dropped
    assert '"readimp00"' in out and '"ReadImp00 failed"' in out  # case differs / longer: kept


def test_search_kind_quotas_with_surplus(ctx):
    strs = [(0x604000 + 16 * i, "ascii", f"read text {i}") for i in range(30)]
    _balance_store(ctx, 30, 30, strs)
    # quotas 4/2/2, the 2 unassigned slots go to functions
    out = core.search(ctx, "read", limit=10).splitlines()[1:11]
    assert [ln.split()[0] for ln in out] == ["function"] * 6 + ["import"] * 2 + ["string"] * 2


def test_search_quota_surplus_flows(ctx):
    _balance_store(ctx, 20, 0, [(0x604000 + 16 * i, "ascii", f"read text {i}") for i in range(2)])
    counts = _kind_counts(core.search(ctx, "read", limit=10))
    assert counts == [8, 0, 2]  # strings only have 2; functions take the rest


def test_search_collapses_duplicate_strings(ctx):
    _balance_store(ctx, 1, 0, [(0x606200, "ascii", "same value"), (0x606000, "ascii", "same value"),
                               (0x606100, "ascii", "same value"), (0x606300, "ascii", "same other")])
    lines = core.search(ctx, "same", kind="string").splitlines()[1:]
    assert len(lines) == 2
    assert '0x00606000 "same value" (+2 copies)' in " ".join(lines)
    assert any(ln.endswith('"same other"') for ln in lines)


def test_search_kind_string_has_no_quotas(ctx):
    _balance_store(ctx, 5, 5, [(0x607000 + 16 * i, "ascii", f"read text {i}") for i in range(10)])
    out = core.search(ctx, "read", kind="string", limit=10)
    assert _kind_counts(out) == [0, 0, 10]


def test_search_limit_and_cursor_with_quotas(ctx):
    _balance_store(ctx, 30, 30, [(0x608000 + 16 * i, "ascii", f"read text {i}") for i in range(30)])
    out = core.search(ctx, "read", limit=10)
    assert out.splitlines()[0] == "search 'read': 90 hits"     # the real count, not the page
    assert len(out.splitlines()) == 12 and out.splitlines()[-1].startswith("… 80 more lines. cursor=")
    nxt = core.search(ctx, cursor=out.rsplit("cursor=", 1)[1].strip())    # the cursor holds the page size
    assert len(nxt.splitlines()) == 11 and nxt.splitlines()[-1].startswith("… 70 more lines.")
    small = core.search(ctx, "read", limit=3).splitlines()
    assert [ln.split()[0] for ln in small[1:4]] == ["function", "import", "string"]
    cut = core.search(ctx, "read", limit=10, budget=60)
    assert "cursor=" in cut
    cur = cut.rsplit("cursor=", 1)[1].split()[0].rstrip(".")
    rest = core.search(ctx, cursor=cur, budget=2000)
    assert rest.splitlines()[0] != "" and not rest.startswith("error")


def test_xrefs_to_function(ctx):
    out = core.xrefs(ctx, "CMainFrame::OnFoo").splitlines()
    assert out[0] == "xrefs to CMainFrame::OnFoo (0x00401100), 1 call"
    assert out[1] == "  0x00401010  main" + " " * 32 + " call"
    out = core.xrefs(ctx, "FUN_00401200").splitlines()
    assert out[0].endswith("2 calls") and "CMainFrame::OnFoo" in out[2]
    assert core.xrefs(ctx, "0x00401204").splitlines()[1].startswith(
        "resolved from interior address")


def test_xrefs_to_import_goes_through_thunk(ctx):
    out = core.xrefs(ctx, "CreateFileW")
    assert "(0x00401300)" in out.splitlines()[0] and "main" in out


def test_xrefs_raw_address_and_from(ctx):
    out = core.xrefs(ctx, "0x00403000").splitlines()
    assert out[0] == 'xrefs to 0x00403000 "Open file failed", 1 data'
    assert out[1] == "no function starts here; showing raw references"
    assert "main" in out[2] and out[2].endswith("data")
    out = core.xrefs(ctx, "main", direction="from").splitlines()
    assert out[0].startswith("xrefs from main (0x00401000), 4 refs: 3 call, 1 data")
    assert any("-> 0x00401100 CMainFrame::OnFoo" in ln for ln in out)
    assert any('-> 0x00403000 "Open file failed"' in ln for ln in out)
    only = core.xrefs(ctx, "main", direction="from", kind="data")
    assert only.splitlines()[0].endswith("1 data")
    assert core.xrefs(ctx, "main", direction="from", kind="x").startswith("error bad_args:")
    assert core.xrefs(ctx, "main", direction="up").startswith("error bad_args:")
    assert core.xrefs(ctx, "nosuch").startswith("error not_found:")
    assert core.xrefs(ctx, "0x00500000").splitlines()[0].endswith("no references")
    lim = core.xrefs(ctx, "main", direction="from", limit=1).splitlines()
    assert lim[0].startswith("xrefs from main (0x00401000), 4 refs")      # the real count, no "+"
    assert lim[-1].startswith("… 3 more lines. cursor=")
    nxt = core.xrefs(ctx, cursor=lim[-1].rsplit("cursor=", 1)[1]).splitlines()
    assert len(nxt) == 2 and nxt[-1].startswith("… 2 more lines. cursor=")   # page size of the cursor


def test_xrefs_hard_cap_has_plus_and_cursor(ctx, monkeypatch):
    monkeypatch.setattr(core, "XREFS_FETCH", 2)
    out = core.xrefs(ctx, "main", direction="from", limit=1).splitlines()
    assert out[0].startswith("xrefs from main (0x00401000), 2 refs") and out[0].endswith("data+")
    assert out[-1].startswith("… 1 more lines. cursor=")


def test_callgraph(ctx):
    out = core.callgraph(ctx, "main", depth=3).splitlines()
    assert out[0] == "callees of main (0x00401000), depth 3"
    assert out[1:] == [
        "  CMainFrame::OnFoo (0x00401100)",
        "    FUN_00401200 (0x00401200)",
        "      main (0x00401000) [cycle]",
        "  FUN_00401200 (0x00401200) [seen]",
        "  CreateFileW (0x00401300) [thunk]",
    ]
    up = core.callgraph(ctx, "FUN_00401200", direction="callers", depth=1).splitlines()
    assert sorted(up[1:]) == sorted(["  CMainFrame::OnFoo (0x00401100) [1 callers below]",
                                     "  main (0x00401000) [1 callers below]"])
    leaf = core.callgraph(ctx, "CreateFileW", depth=2).splitlines()
    assert leaf[-1] == "  (none)"
    assert core.callgraph(ctx, "main", direction="x").startswith("error bad_args:")


def test_callgraph_fanout_cut_names_node_and_pages_rest(ctx, monkeypatch):
    monkeypatch.setattr(core, "CALLGRAPH_FANOUT", 1)
    out = core.callgraph(ctx, "main", depth=1).splitlines()
    cut = out[-1]
    assert re.match(r"^  … \d+ more callees of main \(0x00401000\) not shown\. cursor=c_\w+$", cut)
    rest = core.callgraph(ctx, cursor=cut.rsplit("cursor=", 1)[1]).splitlines()
    assert rest and all("(0x" in ln for ln in rest)
    assert len(out) - 2 + len(rest) >= 3        # shown + paged = all callees of main


def test_callgraph_depth_cut_marks_nodes_with_more_below(ctx):
    out = core.callgraph(ctx, "main", depth=1).splitlines()
    assert "  CMainFrame::OnFoo (0x00401100) [1 callees below]" in out
    assert not any(ln.startswith("  CreateFileW") and "below" in ln for ln in out)


def test_function_decompile_annotates_and_caches(ctx):
    out = core.function(ctx, "main")
    assert out == "void main(void)\n{\n  OnFoo/*0x00401100*/();\n  FUN_00401200();\n  return;\n}"
    assert ctx.worker.count("decompile") == 1
    assert core.function(ctx, "0x00401000") == out
    assert ctx.worker.count("decompile") == 1  # cached
    st = ctx.indexer.store("proj")
    b = st.list_binaries()[0]
    assert st.counts(b.id)["decompiled"] == 1
    # a change that bumps the function version invalidates the cache
    st.insert_functions(b.id, [{"entry": 0x401000, "name": "main", "name_state": "user",
                                "size": 0x44}])
    core.function(ctx, "main")
    assert ctx.worker.count("decompile") == 2
    assert st.counts(b.id)["decomp_stale"] == 0


def test_function_views_and_errors(ctx):
    sig = core.function(ctx, "main", view="signature")
    assert sig == "0x00401000 int main(void) [__cdecl, 64 bytes, user] callers 1"
    assert ctx.worker.count("decompile") == 0
    assert core.function(ctx, "main", view="zz").startswith("error bad_args:")
    assert core.function(ctx, "").startswith("error bad_target:")
    assert core.function(ctx, "nosuch").startswith("error not_found:")
    ext = core.function(ctx, "EXTERNAL:0x1")      # an import has no code: its references
    assert ext.splitlines()[0] == "(an import with no code: its references)"
    assert core.function(ctx, "0x00401104").startswith("// resolved from interior address")
    ctx.worker.decompile_reply = {"status": "timeout", "error": "took too long"}
    lst = core.function(ctx, "FUN_00401200")             # a failed decompile shows the block listing
    assert lst.startswith("// decompile failed: FUN_00401200: took too long") and "insns]" in lst
    ctx.worker.decompile_reply = {"status": "error", "error": "bad"}
    assert core.function(ctx, "FUN_00401200", retry=True).startswith("// decompile failed: FUN_00401200: bad")
    ctx.worker.decompile_reply = WorkerError  # type: ignore[assignment]


def test_function_worker_error_is_one_line(ctx):
    ctx.worker.fail_op = "decompile"
    out = core.function(ctx, "main")
    assert out.startswith("error boom: it broke.") and "\n" not in out


def test_function_lines_and_cursor(ctx):
    ctx.worker.c_text = "\n".join(f"  x{i} = OnFoo();" for i in range(200)) + "\n"
    first = core.function(ctx, "main", budget=100, outline=False)
    lines = first.splitlines()
    assert lines[-1].startswith("… ") and "more lines. cursor=c_" in lines[-1]
    cid = lines[-1].split("cursor=")[1]
    second = core.function(ctx, "main", cursor=cid, budget=100)
    head = second.splitlines()[0]
    assert head.startswith("// lines 1") and "More:" not in head
    n = int(head.split()[2].split("-")[0])
    assert second.splitlines()[1].startswith(f"  x{n - 1} =")
    assert core.function(ctx, "main", cursor="c_dead").startswith("error bad_cursor:")
    # a known cursor carries its own arguments: another target does not matter
    assert core.function(ctx, "OnFoo", cursor=cid, budget=100).startswith("// lines ")
    assert core.function(ctx, cursor=cid, budget=100).startswith("// lines ")     # the cursor alone
    part = core.function(ctx, "main", lines="2-3").splitlines()
    assert len(part) == 3 and part[0].startswith("// lines 2-3 of 200,")
    assert part[1].startswith("  x1 =")
    assert core.function(ctx, "main", lines="999-1000").startswith("error bad_args:")
    assert core.function(ctx, "main", lines="abc").startswith("error bad_args:")


def _hdr(text: str) -> tuple[int, int, int]:
    import re
    m = re.match(r"// lines (\d+)-(\d+) of (\d+),", text)
    assert m, text[:80]
    return int(m[1]), int(m[2]), int(m[3])


def _cursor(text: str) -> str | None:
    last = text.splitlines()[-1]
    return last.split("cursor=")[1] if "cursor=" in last else None


def test_function_small_has_no_header(ctx):
    out = core.function(ctx, "main")
    assert not out.startswith("// lines") and "of 6" not in out
    note = core.function(ctx, "0x00401104")
    assert note.startswith("// resolved from interior address")
    assert "// lines" not in note


def test_function_header_paging(ctx):
    from airlock.server.budget import estimate_tokens
    n = 300
    ctx.worker.c_text = "\n".join(f"  x{i} = {i};" for i in range(n)) + "\n"
    pages, cid, budget = [], None, 120
    while True:
        out = (core.function(ctx, "main", budget=budget, outline=False) if cid is None
               else core.function(ctx, "main", cursor=cid, budget=budget))
        assert estimate_tokens(out, "code") <= budget
        pages.append(out)
        cid = _cursor(out)
        if cid is None:
            break
    assert len(pages) > 2
    nxt = 1
    for p in pages:
        s, e, tot = _hdr(p)
        assert tot == n and s == nxt and e >= s
        body = [ln for ln in p.splitlines()[1:] if not ln.startswith("… ")]
        assert len(body) == e - s + 1
        assert body[0] == f"  x{s - 1} = {s - 1};" and body[-1] == f"  x{e - 1} = {e - 1};"
        nxt = e + 1
    assert nxt - 1 == n                       # last page E == N
    assert "more lines" not in pages[-1]
    assert "(budget 120)" in pages[0] and "~" in pages[0]


def test_function_header_with_note_and_lines(ctx):
    from airlock.server.budget import estimate_tokens
    ctx.worker.c_text = "\n".join(f"  x{i} = {i};" for i in range(300)) + "\n"
    out = core.function(ctx, "0x00401104", budget=150, outline=False)
    ls = out.splitlines()
    assert ls[0].startswith("// resolved from interior address") and ls[1].startswith("// lines 1-")
    assert estimate_tokens(out, "code") <= 150
    s, e, tot = _hdr(ls[1])
    assert (s, tot) == (1, 300) and ls[2] == "  x0 = 0;"   # note does not shift numbering
    sel = core.function(ctx, "0x00401104", lines="10-12").splitlines()
    assert sel[1].startswith("// lines 10-12 of 300,") and sel[2] == "  x9 = 9;"
    assert len(sel) == 5
    tail = core.function(ctx, "main", lines="299-999").splitlines()
    assert _hdr(tail[0]) == (299, 300, 300) and len(tail) == 3
    # lines= span larger than the budget pages with a cursor and continues the range
    big = core.function(ctx, "main", lines="50-250", budget=100)
    s, e, _ = _hdr(big)
    assert s == 50 and e < 250
    nxt = core.function(ctx, "main", lines="50-250", cursor=_cursor(big), budget=100)
    assert _hdr(nxt)[0] == e + 1


def test_list_tool_cursor_resume(ctx):
    st = ctx.indexer.store("proj")
    b = st.list_binaries()[0]
    st.insert_strings(b.id, [(0x500000 + i * 8, "ascii", f"needle number {i}") for i in range(300)])
    out = core.strings(ctx, "needle", limit=300, budget=200)
    last = out.splitlines()[-1]
    assert "more lines. cursor=" in last
    nxt = core.strings(ctx, cursor=last.split("cursor=")[1], budget=200)
    assert "needle number" in nxt and nxt.splitlines()[0] != out.splitlines()[0]
    assert core.strings(ctx, cursor="c_zzzz").startswith("error bad_cursor:")


def test_calls_are_registered_with_one_sentence_descriptions():
    from airlock.server.registry import IMPLEMENTED, load_tool_modules
    load_tool_modules()
    for name in ("open_binary", "list_binaries", "outline", "search", "function", "xrefs",
                 "callgraph", "strings", "index_status"):
        d = IMPLEMENTED[name].description
        assert d.count(". ") == 0 and d.endswith("."), name


# ── function: detail / outline (synthetic C) ──────────────────────────────────

def _big_c(n_locals: int = 10, n_body: int = 400) -> str:
    decls = [f"  int iVar{i};" for i in range(n_locals)]
    body = ["  /* WARNING: Removing unreachable block (ram,0x00401050) */", "",
            "  switch(iVar0) {", "  case 0:", "  case 1:", "  case 2:", "  case 3:",
            "    OnFoo();", "    break;", "  case 0x10:", "    FUN_00401200();", "    break;",
            "  default:", "    break;", "  }",
            "  if (iVar1 != 0) {", '    OnFoo("hello world");', "  }"]
    body += [f"  iVar2 = iVar2 + {i};" for i in range(n_body)]
    return "\n".join(["int main(void)", "", "{"] + decls + [""] + body + ["  return 0;", "}"]) + "\n"


def test_function_detail_brief_and_full(ctx):
    raw = _big_c(10, 5)
    ctx.worker.c_text = raw
    brief = core.function(ctx, "main")
    assert "// 10 locals: iVar0, iVar1" in brief and "WARNING" not in brief
    assert "int iVar3;" not in brief and "OnFoo/*0x00401100*/();" in brief
    full = core.function(ctx, "main", detail="full")
    assert full == core.function(ctx, "main", detail="full") and "WARNING" in full
    assert "int iVar3;" in full
    assert core.function(ctx, "main", detail="x").startswith("error bad_args:")


def test_function_outline_over_budget(ctx):
    from airlock.server.budget import estimate_tokens
    ctx.worker.c_text = _big_c(10, 400)
    out = core.function(ctx, "main", budget=400)
    ls = out.splitlines()
    assert ls[0].startswith("// main 0x00401000: ") and "(budget 400)" in ls[0]
    assert ls[0].endswith("outline:") and "outline=false" not in ls[0]
    assert estimate_tokens(out, "code") <= 400
    assert ls[1] == "int main(void)"
    assert any("switch(iVar0)" in x for x in ls) and any("case 0..3,0x10,default (6 cases)" in x for x in ls)
    assert any("OnFoo" in x and "x2 L" in x for x in ls)
    assert any('"hello world"' in x for x in ls)
    # line numbers from the outline index the reduced text (brief) and agree with lines=
    m = [x for x in ls if "switch(iVar0)" in x][0].split()[0]
    n = int(m[1:].split("-")[0])
    chunk = core.function(ctx, "main", lines=f"{n}-{n}").splitlines()
    assert chunk[0].startswith(f"// lines {n}-{n} of ") and "switch(iVar0)" in chunk[1]
    hdr_lines = int(ls[0].split(": ")[1].split(" lines")[0])
    assert chunk[0].split(" of ")[1].startswith(str(hdr_lines))


def test_function_outline_detail_full_numbering(ctx):
    ctx.worker.c_text = _big_c(10, 400)
    b = core.function(ctx, "main", budget=400).splitlines()[0]
    f = core.function(ctx, "main", budget=400, detail="full").splitlines()[0]
    nb = int(b.split(": ")[1].split(" lines")[0])
    nf = int(f.split(": ")[1].split(" lines")[0])
    assert nf - nb == 11   # 10 decls -> 1 line (-9), warning + its blank line (-2)


def test_function_outline_false_pages_and_cursors(ctx):
    ctx.worker.c_text = _big_c(10, 400)
    p1 = core.function(ctx, "main", budget=400, outline=False)
    assert p1.startswith("// lines 1-") and "more lines. cursor=c_" in p1
    cid = _cursor(p1)
    p2 = core.function(ctx, "main", cursor=cid, budget=400, outline=False)
    assert p2.startswith("// lines ")
    # a cursor keeps its detail mode, whatever the call says
    assert core.function(ctx, "main", cursor=_cursor(core.function(
        ctx, "main", budget=400, outline=False)), budget=400,
        detail="full").startswith("// lines ")


def test_function_outline_footer_cursor(ctx):
    from airlock.server.budget import estimate_tokens
    names = "\n".join(f'  FUN_{i:08x}("s{i}");' for i in range(60))
    ctx.worker.c_text = "void main(void)\n{\n" + names + "\n" + "\n".join(
        f"  a = {i};" for i in range(300)) + "\n}\n"
    out = core.function(ctx, "main", budget=150)
    assert estimate_tokens(out, "code") <= 150 and "more lines. cursor=c_" in out
    nxt = core.function(ctx, "main", cursor=_cursor(out), budget=150)
    assert not nxt.startswith("error") and "// lines" not in nxt


def test_function_small_unchanged_except_noise(ctx):
    ctx.worker.c_text = ("int main(void)\n\n{\n  int a;\n  int b;\n\n"
                         "  /* WARNING: x */\n\n  OnFoo();\n  return 0;\n}\n")
    assert core.function(ctx, "main") == (
        "int main(void)\n\n{\n  int a;\n  int b;\n\n  OnFoo/*0x00401100*/();\n  return 0;\n}")


# -- agent evaluation fixes ----------------------------------------------------------------------

def test_infra_error_is_not_a_decompiler_result():
    from airlock.server.tools.core import _infra_error
    assert _infra_error("JVMNotRunning: Java Virtual Machine is not running.")
    assert _infra_error("ClosedException: File is closed")
    assert not _infra_error("Low-level Error: Unable to resolve data-type")
    assert not _infra_error(None)


def test_search_finds_qt_methods_by_name():
    import sqlite3
    from types import SimpleNamespace
    from airlock.server.tools.core import _qt_method_hits
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("CREATE TABLE qt_class (binary_id, meta_addr, name)")
    db.execute("CREATE TABLE qt_method (binary_id, meta_addr, idx, kind, name, addr)")
    db.execute("INSERT INTO qt_class VALUES (1, 10, 'ImageWriter')")
    db.executemany("INSERT INTO qt_method VALUES (1, 10, ?, ?, ?, ?)",
                   [(0, "slot", "cancelWrite", 0x406cc0), (1, "signal", "cancelled", 0x4019f0),
                    (2, "slot", "other", 0x500000), (3, "slot", "cancelNoAddr", None)])
    bd = SimpleNamespace(store=SimpleNamespace(db=db), binary=SimpleNamespace(id=1),
                         addr=lambda a, *x: f"0x{a:08x}")
    groups = {"function": [((0, 1, 1), "function FUN_00406cc0 0x00406cc0 undefined")]}
    _qt_method_hits(bd, "cancel", 50, groups, 1, "")
    lines = sorted(x for _, x in groups["function"])
    assert lines == ["function ImageWriter::cancelWrite 0x00406cc0 (Qt slot)",
                     "function ImageWriter::cancelled 0x004019f0 (Qt signal)"]



def test_function_retries_a_transient_failure_once(ctx, monkeypatch):
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda s: None)
    replies = [{"status": "error", "error": "JVMNotRunning: Java Virtual Machine is not running"}]
    real = ctx.worker.request

    def flaky(op, args=None, timeout=0):
        if op == "decompile" and replies:
            ctx.worker.calls.append((op, args or {}))
            return replies.pop(0)
        return real(op, args, timeout)
    monkeypatch.setattr(ctx.worker, "request", flaky)
    out = core.function(ctx, "main")
    assert out.startswith("void main(void)") and ctx.worker.count("decompile") == 2
    # two transient failures in a row: the listing with the hint, and nothing cached
    ctx.worker.calls.clear()
    st = ctx.indexer.store("proj")
    st.db.execute("DELETE FROM decomp")
    st.db.commit()
    ctx.worker.decompile_reply = {"status": "error", "error": "JVMNotRunning: down"}
    monkeypatch.setattr(ctx.worker, "request", real)
    lst = core.function(ctx, "main")
    assert lst.startswith("// decompile failed") and ctx.worker.count("decompile") == 2


def test_dotnet_member_alias():
    from airlock.server.dotnet import member_alias
    assert member_alias(".ctor", "OpenHardwareMonitor.GUI.MainForm") == "MainForm"
    assert member_alias("<.ctor>b__37_5", "A.B.MainForm") == "MainForm"
    assert member_alias("<Run>d__3", "A.B.Worker") == "Run"
    assert member_alias("Load", "A.B.Worker") == "Load"
    assert member_alias("set_Startup", "A.B.StartupManager") == "Startup"


def test_qt_method_name_resolves_to_its_address():
    import sqlite3
    from types import SimpleNamespace
    from airlock.server.targets import _qt_method_addr
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE qt_class (binary_id, meta_addr, name)")
    db.execute("CREATE TABLE qt_method (binary_id, meta_addr, idx, kind, name, addr)")
    db.execute("INSERT INTO qt_class VALUES (1, 10, 'MainWindow')")
    db.executemany("INSERT INTO qt_method VALUES (1, 10, ?, 'slot', ?, ?)",
                   [(0, "fileOpen", 0x6f750), (1, "fileOpen", 0x6f750), (2, "a", 1), (3, "a", 2)])
    sc = SimpleNamespace(bounds=[SimpleNamespace(store=SimpleNamespace(db=db), binary=SimpleNamespace(id=1))])
    assert _qt_method_addr(sc, "MainWindow::fileOpen") == 0x6f750
    assert _qt_method_addr(sc, "MainWindow::fileOpen(QString)") == 0x6f750
    assert _qt_method_addr(sc, "MainWindow::a") is None          # two addresses: ambiguous
    assert _qt_method_addr(sc, "fileOpen") is None and _qt_method_addr(sc, "Other::x") is None


def test_delphi_method_names_resolve_and_search():
    import sqlite3
    from types import SimpleNamespace
    from airlock.server.targets import _qt_method_addr
    from airlock.server.tools.core import _qt_method_hits
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("CREATE TABLE dl_class (binary_id, vmt, name)")
    db.execute("CREATE TABLE dl_method (binary_id, vmt, kind, slot, name, addr)")
    db.execute("INSERT INTO dl_class VALUES (1, 5, 'TFRemoveMeta')")
    db.executemany("INSERT INTO dl_method VALUES (1, 5, ?, ?, ?, ?)",
                   [("published", 0, "Button2Click", 0x82d2a8), ("virtual", 1, "", 0x100)])
    bd = SimpleNamespace(store=SimpleNamespace(db=db), binary=SimpleNamespace(id=1),
                         addr=lambda a, *x: f"0x{a:08x}")
    sc = SimpleNamespace(bounds=[bd])
    assert _qt_method_addr(sc, "TFRemoveMeta.Button2Click") == 0x82d2a8
    assert _qt_method_addr(sc, "tfremovemeta.button2click") == 0x82d2a8
    groups = {}
    _qt_method_hits(bd, "button2", 50, groups, 0, "")
    assert [x for _, x in groups["function"]] == [
        "function TFRemoveMeta.Button2Click 0x0082d2a8 (Delphi published)"]


def test_strings_capped_result_has_cursor_and_bad_cursor_falls_back(ctx, monkeypatch):
    # Eval t14: "40+" without a cursor made the agent invent cursor '40' -> bad_cursor.
    lines = [f"0x{0x1000 + i:08x} \"s{i}\"" for i in range(100)]
    monkeypatch.setattr(core, "_string_lines", lambda *a, **k: (list(lines), False))
    out = core.strings(ctx, "FILE", limit=40, budget=100000)
    rows = out.splitlines()
    assert rows[0].startswith("strings matching 'FILE': 100") and rows[-1].startswith("… 60 more lines. cursor=")
    assert len(rows) == 1 + 40 + 1
    cid = rows[-1].rsplit("cursor=", 1)[1]
    nxt = core.strings(ctx, cursor=cid, limit=40, budget=100000).splitlines()
    assert nxt[0] == lines[40] and nxt[39] == lines[79] and "more lines" in nxt[-1]
    # an unknown cursor together with a pattern: search anew, say so, do not fail
    again = core.strings(ctx, "FILE", cursor="40", limit=40, budget=100000)
    assert not again.startswith("error") and "(cursor 40 unknown, searched anew)" in again
    assert core.strings(ctx, cursor="40").startswith("error bad_cursor")
