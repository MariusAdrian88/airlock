"""Tool lists of the old allow-list config files (`sets` + `enabled_sets`).

Used only by `airlock config upgrade` to turn a user's old file into a
`disabled_tools` list: a tool the old default exposed but the user's file does
not, was removed on purpose.
"""

from __future__ import annotations

_COMMON = {
    "core": ["open_binary", "list_binaries", "outline", "search", "function", "xrefs",
             "callgraph", "strings"],
    "types": ["type_inspect", "type_search"],
    "annotate": ["rename", "retype", "comment", "annotate", "struct_define"],
    "cpp": ["rtti_classes", "vtable", "mfc_message_maps", "qt_metaobjects"],
    "resources": ["pe_resources", "dialogs", "string_tables", "version_info"],
    "dataflow": ["trace_values", "switch_tables", "constants"],
    "fileformat": ["ole_streams", "hexdump", "file_diff", "record_guess"],
    "spec_write": ["spec_write", "spec_list"],
}

# Tools of the dirty profile in the first default file (before project maps).
V0_DIRTY_TOOLS: frozenset[str] = frozenset(
    t for s in _COMMON.values() for t in s
) | {"index_status", "reindex", "project_info", "frontier"}

# The default file with project folders, maps and cross-binary tools.
V1_DIRTY_TOOLS: frozenset[str] = frozenset(
    t for s in _COMMON.values() for t in s
) | {"overview", "project_describe", "features", "feature", "feature_define", "path",
    "graph_export", "index_status", "reindex", "project_info", "frontier", "program_scan",
    "projects", "project_open", "project_create", "program_add", "function_map",
    "cluster_label"}


def reference_tools(user_sets: dict) -> frozenset[str]:
    """The old default that the user's file most likely started from."""
    return V1_DIRTY_TOOLS if "map" in user_sets else V0_DIRTY_TOOLS


# Values the old default files shipped. A user value equal to one of these was
# never changed, so the upgrade does not pin it.
OLD_DEFAULT_VALUES: dict[str, object] = {"max_budget": 8000, "bulk_decompile": "lazy"}
