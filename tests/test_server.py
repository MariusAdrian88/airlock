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
    assert set(names) - {"function_map", "cluster_label", "path", "graph_export"} == {"project_info", "index_status", "open_binary", "list_binaries",
                          "outline", "search", "function", "xrefs", "callgraph", "strings",
                          "program_scan", "project_create", "program_add", "projects", "project_open",
                          "overview", "project_describe", "features", "feature", "feature_define",
                          "spec_write", "spec_read", "spec_list", "spec_export",
                          "rename", "retype", "comment", "annotate", "struct_define",
                          "pe_resources", "dialogs", "menus", "string_tables", "version_info",
                          "rtti_classes", "vtable", "mfc_message_maps", "qt_metaobjects",
                          "trace_values", "switch_tables", "constants",
                          "ole_streams", "hexdump", "file_diff", "record_guess"}
    assert {"function_map", "cluster_label", "path", "graph_export"} <= set(names)
    assert "type_inspect" in ctx.not_implemented
    pi = next(t for t in tools if t.name == "project_info")
    dumped = pi.model_dump(exclude_none=True)
    assert all("output_schema" not in t.model_dump(exclude_none=True) for t in tools)
    assert set(dumped["input_schema"]["properties"]) == {"check_ghidra"}
    assert len(ctx.config.tools) >= 48


def test_clean_profile_lists_no_code_tools(tmp_path):
    server, ctx = build_server(_cfg(tmp_path, "clean"))
    names = [t.name for t in anyio.run(server.list_tools)]
    assert set(names) == {"projects", "project_open", "project_info", "spec_read", "spec_list",
                          "spec_export"}
    assert not ({"spec_read", "spec_list", "spec_export"} & set(ctx.not_implemented))


def test_project_info_call(tmp_path):
    server, ctx = build_server(_cfg(tmp_path))

    async def call():
        return await server.call_tool("project_info", {})

    result = anyio.run(call)
    text = result.content[0].text
    assert "profile dirty" in text
    assert "not implemented yet" not in text
    assert "more after project_open" in text
    ctx.worker.stop()


def test_project_info_lists_only_usable_tools_when_unbound(tmp_path):
    from airlock.server.tools import admin
    server, ctx = build_server(_cfg(tmp_path))
    text = admin.project_info(ctx)
    tools = text.split("tools (", 1)[1]
    assert "index_status" not in tools and "function" not in tools.split("(+")[0].split()
    assert "project_open" in tools and "program_scan" in tools
    assert "more after project_open)" in tools
    assert "not implemented" not in text and "type_inspect" not in text
    ctx.worker.stop()


def test_unimplemented_tools_return_one_line_error(tmp_path):
    from airlock.server import registry
    server, ctx = build_server(_cfg(tmp_path, "clean"))
    ctx.session = __import__("airlock.server.roles", fromlist=["x"]).SessionState("clean", None)
    assert registry.call(ctx, "function").startswith("error wrong_role:")
    # a catalog tool without an implementation (annotate set) in a dirty session
    ctx.session = __import__("airlock.server.roles", fromlist=["x"]).SessionState("dirty", None)
    assert registry.call(ctx, "patch_bytes") == (
        "error not_implemented: patch_bytes is planned for M3 and not available yet.")
    assert registry.call(ctx, "nope").startswith("error unknown_tool:")
    ctx.worker.stop()
