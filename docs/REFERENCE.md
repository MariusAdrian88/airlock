# Reference

How airlock works: sessions, output rules, target forms, frameworks and configuration.
The list of tools is in [TOOLS.md](TOOLS.md). Errors are in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Use airlock

1. Register `airlock serve` with each MCP client once (see below).
2. Each session starts unbound. Ask the agent to reverse engineer a folder. The
   agent runs `program_scan` (light scan, options A to D, time estimate), then
   `project_create`. Binaries are analysed in a queue and decompiled in the background.
3. Later sessions: `projects`, then `project_open(name, "dirty" or "clean")`.
   The role stays fixed for the session.
4. Dirty: `overview`, `features`, `feature`, `function_map`, `path`, `search`,
   `strings`, `xrefs`, `callgraph`, `function`, `graph_export`.
5. Dirty writes must have `allow_writes` on: `rename`, `retype`, `comment`,
   `annotate`, `struct_define`. Write specifications with `spec_write`. `spec_export`
   publishes them to `clean\specs\`.
6. Clean: `spec_read`, `spec_list`, `spec_export`. The clean side reads the
   published files only, never the index.

The project folder `<projects_root>\<name>\` holds `dirty\` (analysis data) and
`clean\` (specifications and deny-rule files).

## Tools

The catalog (`src/airlock/config/catalog.py`) lists every tool by set. [TOOLS.md](TOOLS.md) is generated from it.


Off by default: sets `delphi` and `dotnet`, and tool `patch_bytes`.
Always on (cannot be disabled): `spec_read`, `spec_list`, `index_status`,
`program_scan`, `project_create`, `projects`, `project_open`, `project_info`.

## Output rules

- Responses are plain text, one item per line. Responses are never JSON.
- Default budget: 2000 tokens (`function`: 10000). A call can pass `budget=`.
  The config key `max_budget` (32000) caps it.
- A capped result ends with a cursor, for example `… 412 more lines. cursor=c_7f3a`.
  Every paged tool gives a real cursor and the real count. A call with only
  `cursor=` continues the stored query. If the call also sets other arguments,
  the cursor keeps its own and one fact line says so.
- Errors are one line: `error <code>: <what happened>.` For example:
  `error not_analysed: binary 'app.exe' is analysing (62%, 41s).`
- Tools do the next step themselves. They retry, widen, follow or forward, and
  report it in one fact line, such as `(regex used: no literal match)`. Where only
  the agent can choose, the tool lists candidates as data. Where only the user can
  act, the error names the fix, such as `allow_writes is off in config.jsonc`.
- `detail=brief` is the default. `detail=full` adds context, such as more callers
  or assembly next to C. `detail=evidence` adds how each fact was found.

## Target forms

Tools that take a target accept these forms:

- **Address:** `0x00401000`, `EXTERNAL:0x1` or a bare hex string. An address inside
  a function resolves to that function, and the answer says so.
- **Name:** an exact name, with its namespace (`CMainFrame::OnFoo`). A name that
  differs only in case resolves in one fact line: `resolved 'x' to X (case differs)`.
- **Ghidra default names** resolve by their address: `DAT_14026ebc8`,
  `PTR_FUN_00401000`, `LAB_0040102c`, `s_text_00402000`.
- **Binary:** `binary!target` (for example `engine.dll!LoadDoc`), `name@binary`, or
  `binary=`. A project with one binary uses it. A project with several binaries
  checks all ready binaries. One hit resolves. Several hits give `error ambiguous`
  with each candidate as `binary!name 0xaddr`. If no binary has the `binary=` name,
  the only binary or the one unique name without its extension is used, with the
  fact line `(binary: X)`.
- **Session focus:** in a multi-binary project, the binary of the last resolved
  function decides an ambiguous name when that binary has exactly one match. The
  answer says `binary X (current binary)`.
- **Imports:** `ReadFile`, `KERNEL32!ReadFile` or `KERNEL32.DLL!ReadFile`. The
  `A` and `W` forms are matched together.
- **Language forms:** Qt `Class::method`, Delphi `TClass.Method`, and MFC handler
  names such as `CMainFrame::OnCommand_<id>_<leaf>`. Tools generate the MFC names for
  handlers that have no name of their own.

## Toolchains and frameworks

- **MSVC C++.** `rtti_classes` and `vtable` read MSVC RTTI and vtables (32 and 64-bit).
- **MFC.** `mfc_message_maps` decodes message maps, dispatch maps, interface maps and
  event sink maps. Classes without RTTI get names from `CRuntimeClass`, the dialog id
  and the inherited class.
- **MFC-like frameworks.** Programs with their own route tables get the same handler
  names. Verified on WinDirStat 2.9.3 (x64).
- **Qt.** `qt_metaobjects` lists signals, slots and properties for Qt 5 and Qt 6
  (32 and 64-bit). Pointer-to-member `connect` calls resolve to `qt_connect` rows
  with their signal and slot. Verified: Qt 6 and Qt 5 with MSVC x64, Qt 5 with MinGW
  32 and 64-bit. Virtual member pointers resolve through the vtable of a known receiver.
- **Delphi.** `delphi_classes` lists classes from the VMT, published methods, fields
  and extended RTTI. `delphi_forms` shows the component tree of a form. `delphi_events`
  maps component events to handlers (a form and a component filter inside the form, all forms when none is given). Ghidra is not renamed: `function` shows the names
  as hints.
  - RTL and VCL routine names come from four sources, in this order: the exact-version
    signature database, the RTTI consensus database, WARP libraries and the IDR knowledge base.
  - String literals of type UnicodeString, AnsiString and WideString are typed in the
    decompiled C. Concatenated strings list their pieces.
  - `airlock delphi-sigs build <Delphi install folder>` writes exact-version databases
    for compilers 30 to 37, 32-bit and 64-bit. `--units` adds private routines and takes longer.
    `airlock delphi-sigs list` shows the databases. The build needs the install; the
    databases do not. The files come from licensed software: never commit them.
- **.NET.** `dotnet_types` lists types and methods from the metadata. `dotnet_decompile`
  shows C# through ilspycmd (config key `ilspycmd`). Managed-only assemblies skip Ghidra.

## Configuration

`%APPDATA%\airlock\config.jsonc` (JSONC: comments allowed). `airlock init` writes
the commented file with every key. Keys are defined in `src/airlock/config/keys.py`.
Use `airlock config` to show the keys, `airlock config --set KEY VALUE` to change one,
and `airlock config validate` to check the file.

```jsonc
{
  "ghidra_dir": "C:/Tools/ghidra_12.1.4_PUBLIC",
  "jdk_dir": null,
  "allow_writes": true,
  "disabled_sets": ["delphi", "dotnet"],
  "disabled_tools": ["patch_bytes"]
}
```

- Tools are chosen by deny lists, so a new version adds its tools without a change to the file.
- Locations: `ghidra_dir`, `jdk_dir`, `ilspycmd`, `idr_kb_dir` (IDR files),
  `delphi_sigdb_dir` (Delphi signature databases), `warp_dir` (WARP libraries),
  `projects_root`, `index_dir`.
- A project overlay can change single keys.

Data (Ghidra projects, index) lives in `%LOCALAPPDATA%\airlock`. Consider a
Windows Defender exclusion for that folder: real-time scanning slows Ghidra's
project writes considerably.

