import anyio

from airlock.config.loader import deep_merge, default_config_text, parse_jsonc, resolve
from airlock.server.app import build_server


def _cfg(tmp_path, profile="dirty"):
    merged = deep_merge(parse_jsonc(default_config_text()),
                        {"ghidra_dir": str(tmp_path / "g"), "index_dir": str(tmp_path),
                         "projects_root": str(tmp_path / "projects")})
    return resolve(merged, profile, None)


def test_only_implemented_configured_tools_are_listed(tmp_path):
    server, ctx = build_server(_cfg(tmp_path))
    tools = anyio.run(server.list_tools)
    names = [t.name for t in tools]
    assert set(names) == {"project_info", "index_status", "open_binary", "list_binaries",
                          "outline", "search", "function", "xrefs", "callgraph", "strings",
                          "program_scan", "project_create", "program_add", "projects", "project_open"}
    assert "rename" in ctx.not_implemented
    pi = next(t for t in tools if t.name == "project_info")
    dumped = pi.model_dump(exclude_none=True)
    assert all("output_schema" not in t.model_dump(exclude_none=True) for t in tools)
    assert set(dumped["input_schema"]["properties"]) == {"check_ghidra"}
    assert len(ctx.config.tools) == 41


def test_clean_profile_lists_no_code_tools(tmp_path):
    server, ctx = build_server(_cfg(tmp_path, "clean"))
    names = [t.name for t in anyio.run(server.list_tools)]
    assert set(names) == {"projects", "project_open", "project_info"}  # spec tools not implemented yet
    assert set(ctx.not_implemented) == {"spec_read", "spec_list", "spec_export"}


def test_project_info_call(tmp_path):
    server, ctx = build_server(_cfg(tmp_path))

    async def call():
        return await server.call_tool("project_info", {})

    result = anyio.run(call)
    text = result.content[0].text
    assert "profile dirty" in text
    assert "not implemented yet" in text
    ctx.worker.stop()
