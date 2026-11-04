"""Catalog of every tool airlock knows, by set.

The config file decides which of these are exposed. A name in the config
that is not in this catalog is a typo or a tool from a newer version, and is
reported by `airlock doctor` and at startup.

Flags:
  writes      modifies the Ghidra project; hidden unless allow_writes is on
  clean_safe  returns no code, addresses or bytes; allowed in a clean profile
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolInfo:
    name: str
    set: str
    writes: bool = False
    clean_safe: bool = False


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
        *_set("resources", ["pe_resources", "dialogs", "string_tables", "version_info"]),
        *_set("dataflow", ["trace_values", "switch_tables", "constants"]),
        *_set("fileformat", ["ole_streams", "hexdump", "file_diff", "record_guess"]),
        *_set("spec_write", ["spec_write"]),
        *_set("spec_read", ["spec_read", "spec_list", "spec_export"], clean_safe=True),
        *_set("admin", ["index_status", "reindex", "project_info", "frontier",
                       "program_scan", "project_create"]),
    ]
}
