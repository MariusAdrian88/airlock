"""Catalog of every tool airlock knows, by set.

The config file decides which of these are exposed. A name in the config
that is not in this catalog is a typo or a tool from a newer version, and is
reported by `airlock doctor` and at startup.

Flags:
  writes      modifies the Ghidra project; hidden unless allow_writes is on
  clean_safe  returns no code, addresses or bytes (or redacts by session role);
              allowed in a clean profile and in a clean session
  always_on   cannot be disabled by disabled_tools or disabled_sets (the loader
              ignores the entry and warns); role gating still applies
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolInfo:
    name: str
    set: str
    writes: bool = False
    clean_safe: bool = False
    always_on: bool = False


def _set(name: str, tools: list[str], **flags: bool) -> list[ToolInfo]:
    return [ToolInfo(t, name, **flags) for t in tools]


CATALOG: dict[str, ToolInfo] = {
    t.name: t
    for t in [
        *_set("core", ["open_binary", "list_binaries", "outline", "search",
                       "function", "xrefs", "callgraph", "strings"]),
        *_set("types", ["type_inspect", "type_search"]),
        *_set("annotate", ["rename", "retype", "comment", "annotate",
                           "struct_define", "patch_bytes"], writes=True),
        *_set("cpp", ["rtti_classes", "vtable", "mfc_message_maps", "qt_metaobjects"]),
        *_set("delphi", ["delphi_classes", "delphi_forms", "delphi_events"]),
        *_set("dotnet", ["dotnet_types", "dotnet_decompile"]),
        *_set("resources", ["pe_resources", "dialogs", "menus", "string_tables", "version_info"]),
        *_set("dataflow", ["trace_values", "switch_tables", "constants"]),
        *_set("fileformat", ["ole_streams", "hexdump", "file_diff", "record_guess"]),
        *_set("spec_write", ["spec_write"]),
        *_set("spec_read", ["spec_read", "spec_list"], clean_safe=True, always_on=True),
        *_set("spec_read", ["spec_export"], clean_safe=True),
        *_set("map", ["overview", "project_describe", "features", "feature", "feature_define",
                      "path", "graph_export"]),
        *_set("admin", ["reindex", "frontier", "program_add", "function_map",
                       "cluster_label"]),
        *_set("admin", ["index_status", "program_scan", "project_create"], always_on=True),
        # Role-aware: they redact their output in a clean session.
        *_set("admin", ["projects", "project_open", "project_info"],
              clean_safe=True, always_on=True),
    ]
}


# One-sentence descriptions for the config template (no quotes or brackets: the
# template parser counts those). The server's own descriptions are in the tool modules.
TOOL_SUMMARIES: dict[str, str] = {
    "open_binary": "Register a PE file in a project and start analysis in the background.",
    "list_binaries": "List the binaries of a project with status, size and cross-binary links.",
    "outline": "Summarise a binary: sections, entry point, imports, function counts.",
    "search": "Full-text search over function names, strings and imports.",
    "function": "Show a function as decompiled C or as a signature.",
    "xrefs": "List references to or from a function or address.",
    "callgraph": "Show the call tree below or above a function.",
    "strings": "Find defined strings and the functions that use them.",
    "type_inspect": "Show the layout of a struct, union or enum.",
    "type_search": "Search data types by name.",
    "rename": "Rename a function, global, label or local variable in Ghidra.",
    "retype": "Change the type of a variable.",
    "comment": "Set a plate, pre or end-of-line comment at an address.",
    "annotate": "Add a note to a function, with an optional rename, in one step.",
    "struct_define": "Create or replace a struct in the Ghidra project.",
    "patch_bytes": "Write raw bytes into the program. Off by default.",
    "rtti_classes": "List C++ classes recovered from MSVC RTTI.",
    "vtable": "Show the slots of a C++ vtable.",
    "mfc_message_maps": "List MFC message map entries and their handlers.",
    "qt_metaobjects": "List Qt signals, slots and properties.",
    "delphi_classes": "List Delphi classes recovered from VMT and RTTI.",
    "delphi_forms": "Show the Delphi form component tree.",
    "delphi_events": "Map Delphi component events to handler functions.",
    "dotnet_types": "List .NET types and methods from metadata.",
    "dotnet_decompile": "Decompile one .NET type to C# with ilspycmd.",
    "pe_resources": "List the resources of a PE file.",
    "dialogs": "Show a dialog template with its controls.",
    "menus": "Show a menu template as a tree of items with ids and popup paths.",
    "string_tables": "List string table entries.",
    "version_info": "Show product name, version and company from the version resource.",
    "trace_values": "Trace a value through def-use chains across calls.",
    "switch_tables": "Show recovered switch tables of a function.",
    "constants": "Find functions that use a given constant.",
    "ole_streams": "List the streams of an OLE file.",
    "hexdump": "Show a range of a file as hex and ASCII.",
    "file_diff": "Show changed byte ranges between two files.",
    "record_guess": "Guess record layouts in a data file.",
    "spec_write": "Write a specification page (code and addresses are rejected).",
    "spec_read": "Read a specification page.",
    "spec_list": "List specification topics.",
    "spec_export": "Export specifications as a document.",
    "overview": "Show the project map: purpose, binaries, features, knowledge, frontier.",
    "project_describe": "Set the purpose paragraph of the project map.",
    "features": "List the features of the program with coverage.",
    "feature": "List the entry points of one feature.",
    "feature_define": "Add or refine a feature.",
    "path": "Find the shortest call chains between two points.",
    "graph_export": "Write a Mermaid, DOT or GraphML graph file for the user.",
    "index_status": "Show worker state and analysis progress per binary.",
    "reindex": "Rebuild stale parts of the index.",
    "frontier": "Rank unnamed functions to reverse next.",
    "program_scan": "Scan a program folder without Ghidra and recommend an analysis option.",
    "project_create": "Create a project folder for a program and queue its files.",
    "program_add": "Queue more files of the project's program folder.",
    "function_map": "List the subsystem clusters or the functions of one cluster.",
    "cluster_label": "Name a subsystem cluster.",
    "projects": "List the projects.",
    "project_open": "Bind the session to a project as dirty or clean.",
    "project_info": "Show the session role, project, version and enabled tools.",
}

SET_SUMMARIES: dict[str, str] = {
    "core": "Open, search and read binaries.",
    "types": "Data types.",
    "annotate": "Writes to the Ghidra project (needs allow_writes).",
    "cpp": "C++ metadata: RTTI, vtables, MFC, Qt.",
    "delphi": "Delphi metadata. Off by default.",
    "dotnet": ".NET metadata. Off by default.",
    "resources": "PE resources.",
    "dataflow": "Value tracing, switch tables, constants.",
    "fileformat": "Raw file inspection without Ghidra.",
    "spec_write": "Write specifications.",
    "spec_read": "Read specifications (the clean side).",
    "map": "Project map, features and graphs.",
    "admin": "Projects, queue, subsystem map and status.",
}
