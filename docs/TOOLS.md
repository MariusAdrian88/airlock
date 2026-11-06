# Tool reference

<!-- Generated from src/airlock/config/catalog.py by tests/test_docs.py. Do not edit by hand. -->

Columns: `clean_safe` means a clean session may use the tool. `writes` means the tool changes the
Ghidra project and needs `allow_writes`. `always_on` means `disabled_tools` and `disabled_sets`
cannot hide the tool. The sets `delphi` and `dotnet` and the tool `patch_bytes` are off by default.

## core

Open, search and read binaries.

| Tool | clean_safe | writes | always_on | What it does |
|---|---|---|---|---|
| `open_binary` | no | no | no | Register a PE file in a project and start analysis in the background. |
| `list_binaries` | no | no | no | List the binaries of a project with status, size and cross-binary links. |
| `outline` | no | no | no | Summarise a binary: sections, entry point, imports, function counts. |
| `search` | no | no | no | Full-text search over function names, strings and imports. |
| `function` | no | no | no | Show a function as decompiled C or as a signature. |
| `xrefs` | no | no | no | List references to or from a function or address. |
| `callgraph` | no | no | no | Show the call tree below or above a function. |
| `strings` | no | no | no | Find defined strings and the functions that use them. |

## types

Data types.

| Tool | clean_safe | writes | always_on | What it does |
|---|---|---|---|---|
| `type_inspect` | no | no | no | Show the layout of a struct, union or enum. |
| `type_search` | no | no | no | Search data types by name. |

## annotate

Writes to the Ghidra project (needs allow_writes).

| Tool | clean_safe | writes | always_on | What it does |
|---|---|---|---|---|
| `rename` | no | yes | no | Rename a function, global, label or local variable in Ghidra. |
| `retype` | no | yes | no | Change the type of a variable. |
| `comment` | no | yes | no | Set a plate, pre or end-of-line comment at an address. |
| `annotate` | no | yes | no | Add a note to a function, with an optional rename, in one step. |
| `struct_define` | no | yes | no | Create or replace a struct in the Ghidra project. |
| `patch_bytes` | no | yes | no | Write raw bytes into the program. Off by default. |

## cpp

C++ metadata: RTTI, vtables, MFC, Qt.

| Tool | clean_safe | writes | always_on | What it does |
|---|---|---|---|---|
| `rtti_classes` | no | no | no | List C++ classes recovered from MSVC RTTI. |
| `vtable` | no | no | no | Show the slots of a C++ vtable or Delphi/FPC VMT: index, target, function and origin, by class name or address. |
| `mfc_message_maps` | no | no | no | List MFC message map entries and their handlers. |
| `qt_metaobjects` | no | no | no | List Qt signals, slots and properties. |

## delphi

Delphi metadata. Off by default.

| Tool | clean_safe | writes | always_on | What it does |
|---|---|---|---|---|
| `delphi_classes` | no | no | no | List Delphi classes recovered from VMT and RTTI. |
| `delphi_forms` | no | no | no | Show the Delphi form component tree. |
| `delphi_events` | no | no | no | Map Delphi component events to handler functions. |

## dotnet

.NET metadata. Off by default.

| Tool | clean_safe | writes | always_on | What it does |
|---|---|---|---|---|
| `dotnet_types` | no | no | no | List .NET types and methods from metadata. |
| `dotnet_decompile` | no | no | no | Decompile one .NET type to C# with ilspycmd. |
| `dotnet_events` | no | no | no | List the controls of .NET WinForms and WPF forms with their captions and event handlers. |

## resources

PE resources.

| Tool | clean_safe | writes | always_on | What it does |
|---|---|---|---|---|
| `pe_resources` | no | no | no | List the resources of a PE file. |
| `dialogs` | no | no | no | Show a dialog template with its controls. |
| `menus` | no | no | no | Show a menu template as a tree of items with ids and popup paths. |
| `string_tables` | no | no | no | List string table entries. |
| `version_info` | no | no | no | Show product name, version and company from the version resource. |

## dataflow

Value tracing, switch tables, constants.

| Tool | clean_safe | writes | always_on | What it does |
|---|---|---|---|---|
| `trace_values` | no | no | no | Trace a value through def-use chains across calls. |
| `switch_tables` | no | no | no | Show recovered switch tables of a function. |
| `constants` | no | no | no | Find functions that use a given constant. |

## fileformat

Raw file inspection without Ghidra.

| Tool | clean_safe | writes | always_on | What it does |
|---|---|---|---|---|
| `ole_streams` | no | no | no | List the streams of an OLE file. |
| `hexdump` | no | no | no | Show a range of a file as hex and ASCII. |
| `file_diff` | no | no | no | Show changed byte ranges between two files. |
| `record_guess` | no | no | no | Guess record layouts in a data file. |

## spec_write

Write specifications.

| Tool | clean_safe | writes | always_on | What it does |
|---|---|---|---|---|
| `spec_write` | no | no | no | Write a specification page (code and addresses are rejected). |

## spec_read

Read specifications (the clean side).

| Tool | clean_safe | writes | always_on | What it does |
|---|---|---|---|---|
| `spec_read` | yes | no | yes | Read a specification page. |
| `spec_list` | yes | no | yes | List specification topics. |
| `spec_export` | yes | no | no | Export specifications as a document. |

## map

Project map, features and graphs.

| Tool | clean_safe | writes | always_on | What it does |
|---|---|---|---|---|
| `overview` | no | no | no | Show the project map: purpose, binaries, features, knowledge, frontier. |
| `project_describe` | no | no | no | Set the purpose paragraph of the project map. |
| `features` | no | no | no | List the features of the program with coverage. |
| `feature` | no | no | no | List the entry points of one feature. |
| `feature_define` | no | no | no | Add or refine a feature. |
| `path` | no | no | no | Find the shortest call chains between two points. |
| `graph_export` | no | no | no | Write a Mermaid, DOT or GraphML graph file for the user. |

## admin

Projects, queue, subsystem map and status.

| Tool | clean_safe | writes | always_on | What it does |
|---|---|---|---|---|
| `reindex` | no | no | no | Rebuild stale parts of the index. |
| `frontier` | no | no | no | Rank unnamed functions to reverse next. |
| `program_add` | no | no | no | Queue more files of the project's program folder. |
| `function_map` | no | no | no | List the subsystem clusters or the functions of one cluster. |
| `cluster_label` | no | no | no | Name a subsystem cluster. |
| `index_status` | no | no | yes | Show worker state and analysis progress per binary. |
| `program_scan` | no | no | yes | Scan a program folder without Ghidra and recommend an analysis option. |
| `project_create` | no | no | yes | Create a project folder for a program and queue its files. |
| `projects` | yes | no | yes | List the projects. |
| `project_open` | yes | no | yes | Bind the session to a project as dirty or clean. |
| `project_info` | yes | no | yes | Show the session role, project, version and enabled tools. |
