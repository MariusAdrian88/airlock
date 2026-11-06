# Handover

Last updated: 2026-11-05. M1.5 issues fixed and verified on a fresh analysis
of the acceptance target; M2 (resources, RTTI, vtables, MFC message maps and
the UI join), M3 (annotate), M4 (specs), M5 (`fileformat`), M6 (`delphi`), M7 (`dotnet`) and M8 (`qt_metaobjects`,
`dataflow`) are done. Delphi RTL/VCL naming has 5 sources (exact sigdb from
installed packages, extended RTTI, RTTI consensus database, WARP, IDR).

## State

M1, M1.5, M3 and M4 are done and pushed to `origin main` (public repository).
Acceptance runs passed on the 32-bit MSVC acceptance target (a multi-binary
program: main executable, own DLLs and plugins). The target is a local
fixture only (gitignored via a generic `tests/fixtures/` rule plus the exact
path in `.git/info/exclude`). Never name it or quote anything from it in
tracked files or commit messages; results live in local memory notes only.

Tests: `pytest -q` → 1465 passed, 49 skipped (~1-3 min; pytest-xdist, at most 8 workers by default; Ghidra runs with `--binary`/`--xbin` are serial). Ghidra suites:
`pytest -q -m ghidra --binary=<exe>` (notepad copy) and
`--xbin=<folder>` (an exe + a DLL it imports, from System32).

## How a user works with airlock

1. Register `airlock serve` once per MCP client, no flags.
2. Every session starts unbound. "Reverse engineer `<folder>`" →
   `program_scan` (light pefile scan, options A–D with estimated time) →
   `project_create(path, name, option)` → the session is dirty for the new
   project; the binaries are analysed in a queue, then decompiled in the
   background.
3. Later sessions: `projects` → `project_open(name, "dirty"|"clean")`. The
   role is locked for the session. Clean work belongs in a new conversation.
4. Dirty: `overview` (project map), `features`/`feature`, `function_map`,
   `path`, `search`/`strings`/`xrefs`/`callgraph`/`function` across binaries
   (`binary!target`), `graph_export` for the user.
5. Dirty writes (`allow_writes`): `rename`, `retype`, `comment`, `annotate`
   (note + rename), `struct_define`; specs with `spec_write`, published to
   `clean\specs\` with `spec_export`.
6. Clean: `spec_read`/`spec_list`/`spec_export` only; reads the published
   files, never the index.

Project folder: `<projects_root>\<name>\` with `airlock-project.jsonc`,
`dirty\{PROJECT.md, work\, airlock_ghidra\, .airlock\}`,
`clean\{PROJECT.md, specs\, deny-rule files}` (DESIGN.md §4).

## Main components

| Area | Files |
|---|---|
| Config (jcodemunch-style) | `config/keys.py` (single source), `template.py` (generated JSONC), `edit.py`, `upgrade.py`, `report.py`, `legacy.py`, `loader.py`, `catalog.py` (sets, `always_on`, `clean_safe`) |
| Sessions | `server/roles.py`, `server/context.py`, `tools/session.py`, `tools/project_create.py` |
| Scan and queue | `server/scan.py`, `server/estimate.py`, `server/indexer.py`, `tools/project.py`, `tools/queue.py` |
| Links | `server/linking.py` (ordinals via pefile, dynamic LoadLibrary/GetProcAddress links, `call_imp` normalisation, relink) |
| Map | `server/features.py`, `server/projectmap.py`, `server/clusters.py`, `server/graph.py`, `server/diagrams.py`, `tools/map.py`, `tools/fmap.py`, `tools/graphtools.py` |
| Annotate and notes (M3) | `tools/annotate.py`, `server/notes.py`, `worker/ghidra_ops/annotate.py` |
| File formats (M5) | `server/fileformat.py`, `tools/fileformat.py` (olefile; paths limited to the program source folder and `dirty\work\`) |
| .NET (M7) | `server/dotnet.py`, `tools/dotnet.py` (dnfile metadata, P/Invoke thunks and import rows, ilspycmd runner); managed-only assemblies are indexed in `Indexer._run_managed` (own thread, no queue, no Ghidra) |
| Delphi (M6) | `server/delphi.py` (VMT, published methods, fields, TPF0 DFM parser, join, hints, runtime recognition), `tools/delphi.py` |
| Specs (M4) | `tools/spec.py`, `server/specs.py`, `server/specfilter.py` |
| Targets | `server/targets.py` (shared resolver) |
| Decompile | `server/bulk.py`, `worker/pool.py`, `worker/rwlock.py`, `worker/ghidra_ops/bulk.py` |
| Index | schema v13: `dl_class`/`dl_method`/`dl_field`/`dl_form`/`dl_component`/`dl_event` (v12), `export`, `xedge` (kinds import/dynamic/dynlib), `feature`, `feature_entry`, `string_link` (v6), `spec`/`spec_provenance`/`audit` (v7), `note` keyed by address (v8), `res_dialog`/`res_control`/`res_menu_item`/`res_string` (v9), `rtti_class`/`vtable_slot`/`msgmap_entry` (v10), `dn_type`/`dn_method`/`dn_pinvoke` (v11; xedge kind `pinvoke`), `qt_class`/`qt_method`/`qt_prop`/`qt_enum`/`qt_connect` (v13) |

## Config

`airlock config` (report), `--set`/`--unset`, `validate`,
`upgrade [--dry-run]`. Tools are chosen by `disabled_tools`/`disabled_sets`
(deny lists), so new tools appear after updates. Always-on tools cannot be
disabled. The user's global config was upgraded to `config_version` 1
(`config.jsonc.bak` kept).

## Verified facts (M1.5)

- Ghidra rejects project path elements that start with `.`; the Ghidra
  project lives in `dirty\airlock_ghidra`.
- MCP roots are deprecated in the current protocol and not sent by every
  client; sessions are bound explicitly with `project_open`.
- `setExternalPath(lib, "/" + program, True)` links a program's external
  library to a project program; it does not resolve calls by itself, the
  index binds imports to exports.
- 32-bit MSVC calls imports through the IAT; Ghidra reports `read`
  references to the slot. airlock normalises them to `call_imp` edges.
- Named PE exports come from Ghidra without ordinals; ordinals are read with
  pefile, so imports by ordinal bind.
- Parallel decompile with one `DecompInterface` per thread gives output
  identical to one decompiler; the AST conversion is serialised (GIL).
  Notepad full pass 7.0 s → 2.0 s with 11 threads.
- Analysis time model: about 6 s fixed per binary plus 170 s per work MB,
  where work MB = estimated function count / 9000. The function count comes
  from a cheap pefile pass (call/push targets, code pointers in data,
  exports), within about 10% of Ghidra's count. Fresh 9-binary run: total
  within 10%, every binary within 25%. Run-to-run noise on the biggest
  binaries is about ±15%.
- Decompiler Parameter ID labels this-calls as `__fastcall`; airlock relabels
  fastcall functions that read only ECX to `__thiscall`, then an instruction
  heuristic classifies the rest (unknown conventions below 1%).
- Statically linked MFC/CRT in DLLs is recognised by name rules, names that
  recur in 3 or more binaries, Function ID hits and propagation to unnamed
  functions called only from runtime code.

## Open issues

M2 was checked end to end on a fresh analysis of the acceptance target
(2026-11-05): resource and C++ tables, missing-function creation and the UI
join all run at analysis time; estimate within 20% of the real time.

1. MFC classes without RTTI are named from `CRuntimeClass`, symbols (namespace of the handlers), the dialog id
   of the constructor (32-bit and 64-bit), the dialog that holds the map's control ids, and the inherited
   runtime class (DESIGN "MFC classes without RTTI"). Left: a class with none of these stays `anon_<map>`;
   a derived class of a non-dialog base without symbols (window sub-classes of CEdit / CStatic / CWnd with no
   command ids) is named `anon_<Base>_<map>`: the binary holds no other source of its own name. The 64-bit
   constructor scan is now verified on a 64-bit `/GR-` MFC test program (round 10, see "MFC check, 64-bit
   without RTTI" below). Shared MFC without RTTI: dialog classes are named from the constructor; a frame or
   view class without a `CRuntimeClass` stays `anon_<map>` (its base lives in the DLL).
2. About 27% of visible functions are in `unclassified` clusters (mostly
   unnamed program code); `function_map` prints the coverage line.
3. MFC dispatch, interface, event sink and connection maps are decoded (`mfc_message_maps`, DESIGN "MFC
   dispatch, interface and event sink maps"). The 64-bit `AFX_DISPMAP_ENTRY` layout and the connection map
   are verified on real 64-bit binaries. A connection map of a class in a shared-MFC (`_AFXDLL`) program is
   told from an interface map by its vtable slot (15), see "MFC check" below. Left: a class whose own
   `GetConnectionMap` is itself a call into the DLL is not seen (the getter is outside the image).

Fixed on 2026-11-05 (issues 3-6, core agent):
- Same name in several binaries (DESIGN 7.3 rule 9): `name@binary` qualifier, the session focus
  (binary of the function resolved last, `ServerContext.focus`) decides an ambiguous name and the
  answer says `binary X (current binary)`; a definition beats an import elsewhere for `xrefs`,
  `callgraph`, `function_map` (note names the importing binaries). `error ambiguous` stays when
  nothing decides. Tests: `tests/test_targets.py` (end).
- `path` wrappers: `graph.wrapper_nodes` (library-tier node with one callee, small, low fan-in)
  replaces the 3-hop length cap; the CRT plumbing name list stays as a last filter (`free` is a
  perfect wrapper of an import and still noise). Size is in bytes (the index has no instruction count).
- Large functions: adaptive decompile timeout (`decompile_timeout_s` + 6 s/KB beyond 8 KB, cap
  `decompile_timeout_max_s`), one relaxed retry (instruction and payload limits up, double time),
  then a block listing with a one-line note. `normalize`/`firstpass` styles give no C (verified).
  Worker `decompile` takes `style`, `max_instructions`, `payload_mb`. Tests in `tests/test_bulk_server.py`.
- `patch_bytes` implemented (off by default via `disabled_tools`, dirty only): worker op in
  `worker/ghidra_ops/annotate.py`, tool in `tools/annotate.py`, `restore=<note id>` undoes. Ghidra
  check: `tests/test_annotate_ghidra.py::test_patch_bytes_real_program`.

- Ghidra 12.1.4 data-loss bug **[verified]** (`tests/test_transaction_ghidra.py`): ending an EMPTY
  transaction with commit=false makes the commits after it vanish from the saved program (they stay
  visible in memory). A real rollback also returns to the last saved state, so every write op saves
  at its end. All five transaction sites (`_write`, analyze, fixups, link externals, Qt connectImpl
  signature) now use `session.transaction`, which commits when the modification number did not change.

Fixed on 2026-11-05 (import into the wrong project): new projects ended `error no_program`
(or `ready` with an empty Ghidra project). Cause: the worker has one open project, and
`Indexer.ensure_open(A)` (a tool call, `resume_project` of an older project after a server
restart, the bulk pass) switched it between the queue job's `open_project(B)` and its
`import_binary`/`analyze`/`extract`. Reproduced with a loop of `ensure_open("A")` during the
import of B. Fix: `ensure_open` refuses with `busy` while the queue job runs another project
(under `Indexer._switch`, which the job also takes for its `open_project`);
`resume_project` of another project defers its refresh steps until the queue has no job of
another project; `import_binary`, `analyze` and `extract` carry `project` (the Ghidra folder)
and the worker answers `wrong_project` when another is open; the import is checked (program
saved in the project, pointer size and image base returned), else the binary is `error`
with a one-line cause. Tests: `tests/test_queue.py` (fake worker),
`tests/test_worker.py::test_check_project_*`, `tests/test_project_switch_ghidra.py` (ghidra).
A server killed with Stop-Process leaves the Ghidra `airlock.lock` of the interrupted project;
the next open took it over without error (checked).
Open: tool calls on project A while another project's job runs now get `busy` (before: the
job broke); the refresh steps of `resume_project` that start before a job of another project
begins can still fail with `busy` (logged in `project.log`, redone at the next server start).

Fixed on 2026-11-05: `ready` was published before the after-ready work. Status
sequence now `importing`, `analysing`, `extracting`, `finishing`, `ready`
(`USABLE_STATES` in `index/store.py`: tools work from `finishing` on;
`index_status` shows `finishing: functions 1200/3769`; the decompile pass
starts after `ready` and is not part of `finishing`). Interrupted `finishing`
is set to `ready` by `resume_project`, whose refresh steps redo the work.
Framework range handlers (tooltips) hidden on control
and menu lines; rotating logs and a per-project `project.log`; `path` uses `server/targets.py` (via
`server/endpoints.py`); `fnptr` tables only in data sections; stricter CRT
underscore rule; `Store.set_meta` commits outside a transaction and
`atomic_write_text` gives each writer its own temp file (the PROJECT.md and
`database is locked` races).

## Clean-room audit fixes

An audit of the clean-room gate found one real leak and several gaps. Fixed, with tests in
`tests/test_cleanroom_audit.py`:

- Purpose paragraph: `project_describe` runs the spec filter (`specfilter.check_text`); `render_clean` and
  `write_maps` drop a purpose that fails it (old rows). A clean `project_open` no longer opens the index: it reads the
  purpose from `clean\PROJECT.md` and filters it again. `scrub_dirty_path` also handles `..\dirty`, `dirty\` and 8.3 names.
- Spec filter: 14 new bypass shapes rejected (inline code, table cells, trailing comments, one-line blocks, Python,
  more Ghidra label forms, 16+ hex bytes as words, 12+ decimal byte values, base64, "at <decimal address>").
  Interface facts stay allowed (magic values, offsets, polynomials, message IDs, pseudocode in prose). The byte-run
  limit moved from 8 to 16 bytes (tests in `test_specs.py` changed to match). `spec_export` filters again.
- Unbound phase: `projects` is redacted before a bind. `project_info` and `program_scan` still show paths when unbound
  (setup needs them); after either, `project_open(..., "clean")` is refused (`ServerContext.unredacted_shown`).
- Deny rules: manifest, data folder, original program folder and `config.jsonc` added for Claude Code; the dirty
  folder gets `Edit(clean/**)`; every JSON file is read back and a missing rule is reported. Codex TOML is still **[verify]**.
- `spec_read` (clean) refuses a published file with `st_nlink > 1`.
- Config `require_spec_review` (default false): when true an agent cannot set `final` or publish; a person runs
  `airlock spec-approve <project> [--prefix P] [--yes]`. No MCP elicitation yet.
- Open: Bash in Claude Code is not covered by deny rules; the filter is a heuristic; a 16-byte GUID or a 32-digit hash
  written as hex is rejected as a byte run.

## Working rules for this project

- Sonnet agents execute; the main session briefs, reviews, runs the full
  suite with no agent active, commits and pushes.
- Agents never commit and never run `git stash`/`checkout --`/`reset`.
- Long Ghidra runs: background or `timeout: 600000`, once; read logs
  before a rerun.
- Before each push: scan commit messages and tracked files for target data.

## MFC without RTTI, automation maps, handler names

`server/mfc.py` (called by `cpp.derive_binary`, `CPP_VERSION` 2, schema v14 tables `mfc_class` and
`mfc_map_entry`). Old projects derive again on open (no re-analysis). `msgmap_entry.class` holds the
derived name (`CFoo`, `Dialog_<caption>`, `anon_<Base>_<addr>`, `anon_<addr>`). `UiIndex.suggest` gives
ClassWizard style names (`OnCommand_<id>_<menu leaf>`, `OnBnClicked_<caption>`, `OnSize`) that
`menus` / `dialogs` / `mfc_message_maps` / `function` show for functions without a name of their own.
Tests: `tests/test_mfc.py` (synthetic 32/64-bit images). `fnfix.FIX_VERSION` 5 (dispatch and route table
handlers join the missing-function pass).

Route tables (`server/routes.py`, `CPP_VERSION` 3, DESIGN §11 "Route tables"): programs with an own MFC
look-alike framework (WinDirStat 2.9.3) keep `RouteEntry {msg, code, first, last, invoke, registered}` in
`constexpr` arrays that only a lazy initialiser names (count and start), with no terminator and no getter
of the entries. Decoded from the initialiser code, tied to the vtable of the `GetRouteTable` slot and to the
base table, handlers followed through the invoker thunk. Stored as `msgmap_entry` rows (kind `routes` in
`MsgMap`, `mfc_class.source` `routes`), so `menus`, `function` hints and the target names work as for MFC.
Verified on WinDirStat x64 against its source (CMainFrame 75 routes, base CFrameWnd; CDirStatApp 7, base
CWinApp). The 32-bit initialiser form is verified on a look-alike test program (see "MFC check" below). Class
names stay `anon_<entries>` (no RTTI).
Target tools accept the generated handler names (`Class::OnCommand_<id>_<leaf>`, `targets._mfc_handler_addrs`).
Tests: `tests/test_routes.py`.

### MFC check, 64-bit without RTTI (round 10, Build Tools 2026 with "C++ ATL/MFC", MFC 14.51)

Test program (own code, open): `CAlphaDlg`, `CBetaDlg`, `CGammaDlg : CDialog` (dialog ids 201..203, control ids
1001..1004, message maps with `ON_BN_CLICKED`, `ON_WM_TIMER`, `ON_COMMAND`, `ON_EN_CHANGE`), `CMainFrame :
CFrameWnd` (`ON_WM_CREATE`, `ON_COMMAND` 40001..40004, `ON_COMMAND_RANGE` 40010..40013,
`ON_UPDATE_COMMAND_UI`), `CAutoThing : CCmdTarget` (dispatch map `ProbeDoWork`, `ProbeReset`, `ProbeValue`;
connection map `IID_IPropertyNotifySink`). Built `/GR- /O2`, Unicode: 64-bit static MFC, 64-bit shared MFC DLL,
32-bit static MFC. Sources and build script are in the session scratchpad only (not tracked).

| Check | x64 static | x64 DLL | x86 static |
|---|---|---|---|
| message map entries, ids, handlers | 4/2/1/9 correct | same | same |
| dialog classes named (`ctor_dialogs`) | 3 of 3 (was 2) | 3 of 3 (was 0) | 3 of 3 (was 2) |
| connection map `IPropertyNotifySink` | yes | yes (was `interface`) | yes |
| dispatch map names (UTF-16) | 3 of 3 | 3 of 3 | 3 of 3 |
| frame class | `anon_CFrameWnd_<map>` | `anon_<map>` | `anon_CFrameWnd_<map>` |

Fixed (`CPP_VERSION` 5): stack-object constructors (store with disp8 / disp32 / SIB) for 32- and 64-bit; the
`push 0; push 1000` scan swallowed the `E8` byte of the id; shared MFC dialog classes (`mfc._orphan_dialogs`);
connection map by slot 15 (`mfc.CONN_SLOT`); `UiIndex.class_dialogs` trusts `mfc_class.dialog`; route tables:
count store between `lea` and store (64-bit), base table from a call (32-bit). The 32-bit route initialiser
form `mov [T+4], entries` / `[T+8], count` is verified on a look-alike test program. Open: a frame or view class
of a shared-MFC program stays `anon_<map>` (its base is in the DLL; the DLL exports are by ordinal);
`symbol_class` stays **[verify]** on real data: a 64-bit static build with a full PDB next to the exe (`/Zi`) came
out of the analysis without any `CAlphaDlg::` namespaces (airlock does not load PDBs), so only unit tests cover it.
Tests: `tests/test_mfc.py` (stack objects, shared MFC, connection slot, constructor dialog), `tests/test_routes.py`.

## M2 join (menus, dialogs, message maps)

`server/uijoin.py` joins `msgmap_entry` with `res_menu_item` / `res_control` on demand (nothing
stored). Used by `menus`, `dialogs`, `mfc_message_maps`, `function` hints, the `ui-menu` / `ui-dialog`
feature seeds (`FEATURES_VERSION` 4) and the `UI:` line per binary in the project map. DESIGN §11
"MFC message maps" has the rules (dialog of a class, shared ids IDOK..IDHELP never decide alone).
Acceptance test: `tests/test_ui_join.py` (synthetic PE with RTTI, a message map, a MENU and DIALOGs).

## .NET (M7)

Design in DESIGN §6 "dotnet" and §11 ".NET". Facts:

- `detect()` sets `BinaryInfo.managed_only` (CLI header with the IL-only flag). Such a file gets
  `format='dotnet'`, is never imported into Ghidra and is ready in seconds (`MANAGED_S` = 1 s in the
  estimate; `scan` sets `ScannedFile.managed` and `code_size` 0). Mixed-mode keeps the Ghidra path;
  `_after_ready` also runs `dotnet.ensure` (toolchain `dotnet`, format `pe32`).
- Each managed method is a function at its MethodDef token (space ram, size 1). A P/Invoke is a
  thunk plus an import row (address = token). `Store._link_pair` writes xedge kind `pinvoke` for those.
  `function view=c` on a managed method returns `error managed` (names the `dotnet_decompile` call);
  `view=asm` returns the IL listing (`dotnet.il_listing`, the parsed assembly is kept 2 minutes).
  The decompile queue (`decomp_candidates`, counts) and the project map frontier skip the token range.
  `_link_libs` skips managed binaries.
- Call graph from IL (`DOTNET_VERSION` 3): edges `call` (call, callvirt, newobj, jmp) and `data`
  (ldftn, ldvirtftn, ldtoken of a method; `link_fnptr` makes them `fnptr`). Calls into other assemblies are external
  functions (space EXTERNAL, entry `0x0A000000 | MemberRef row`) plus import rows; `Store.link_cross_binary`
  calls `dotnet.link_managed`, which binds them to project assemblies with xedge kind `mcall`.
  Details in DESIGN §11 ".NET". System.Windows.Forms.dll: 92977 edges, indexed in 8 s.
- COM GUIDs: flag `guid=<lower>` in `dn_type.flags`, shown as `{GUID}` by `dotnet_types kind=com`.
- Decompile cache folder: `<sha16>-<ilspycmd version>`; files are keyed by metadata token: `t_<type token>.cs`
  (whole type) and `m_<method token>.cs` (one method, ilspycmd 11 `-m`), never by name (P17).
- Mixed-mode Ghidra test: `test_mixed_mode_assembly_through_ghidra` in `tests/test_dotnet.py` (marker
  `ghidra`; run with `-m ghidra --binary=<any file>`; it copies CustomMarshalers.dll from the Framework
  folder to a temp dir).
- `dotnet_version:<id>` meta key (`DOTNET_VERSION`): `Indexer.resume_project` re-parses stale tables.
- ilspycmd 11.2.0.10050 (NativeAOT, nuget `ilspycmd.win-x64`, no .NET runtime) is the supported tool:
  `airlock doctor --fix` downloads it to the configured `ilspycmd` path (WARN when the file is older than 11).
  Version 8.2 still works for whole types (`-t`, `DOTNET_ROLL_FORWARD=LatestMajor` is still set for the child, NativeAOT 11 ignores it); 8.2 fails on .NET 9/10 assemblies and cannot cut one method. With version >= 11,
  `dotnet_decompile member=` (and `function view=c` on a managed method, which passes the method token)
  runs `ilspycmd -m 0x06xxxxxx`: only that method, also MoveNext and lambdas, all overloads of a name, members
  of nested types. Helpers for other options: `tools/dotnet.py::ilspy_run(ctx, bd, args)` (bytes, error) and
  `server/dotnet.py::run_ilspy_args`.
- Spec filter (clean room) rejects IL lines (`IL_xxxx`, opcode lines, `.method`), C# statements, lambdas,
  attribute lines, member declarations and `{ get; set; }` as `spec_has_code` (tests in `tests/test_specs.py`).
- `calli` gets no edge (no static target); `function view=asm` shows its signature. Write tools
  (`rename`, `retype`, `comment`, `struct_define`, rename part of `annotate`) refuse managed methods,
  thunks and external callees with `error managed` before the worker; `annotate` keeps the note and
  appends the refusal line when a rename was also asked (DESIGN §11 ".NET"). Tests use `ilasm.exe`.
- Not done: call sites are the caller token (no IL
  offset); a MemberRef on a derived type that names an inherited method is not matched across assemblies;
  dnfile needs about 6 s for a 6 MB assembly (the dominant cost).
- `dotnet_types` has an extra `kind` parameter (`type|method|pinvoke|com`).

- Managed names (P19, `selectors.py`): `Type::Name(params)` / `Type.Name(params)` picks one overload by
  parameter types (loose: short names, `String` = `string`, `Int32` = `int`, `ref` ignored); `Type.Name` without
  parentheses lists the overloads. An ambiguous managed name lists `0xtoken Name(sig)` per candidate. A C++/CLI
  token and its native IJW body of one name resolve to the token with the fact line `native thunk 0x...`
  **[verified]** on KeePass (`AppConfigSerializer::Load()` -> 0x06001bb4) and ClrPhlib (`UnmanagedPE.LoadPE`).
  `xrefs`/`callgraph` do not merge overloads.
- Cross-assembly xrefs (P9, `core.xrefs`): an `mcall`/`pinvoke` in-edge is listed as the callers of the slot or
  thunk (`[Dependencies.exe] 0x... Type::Method call (via mcall)`) plus one fact line; a slot without callers
  stays as a slot line. `callgraph callers` had the same gap (EXTERNAL row taken for a thunk), fixed.
  **[verified]** Mono.Cecil `ReadAssembly(String)`: 4 callers in 2 assemblies. Tests: `tests/test_dotnet_names.py`.
- `type_inspect` / `type_search` stay in the catalog, not implemented (`error not_implemented`); no change.

- IL sites, strings, generics, state machines (net-fix C, DOTNET_VERSION 6, SCHEMA_VERSION 15 adds `edge.site`):
  every call site is one edge row with its IL offset in `site` (xrefs prints `Caller+IL_0012`; the
  caller token stays `src_addr`). `ldftn`/`ldvirtftn` write one `fnptr` edge (no `data` twin);
  `Store.link_fnptr` leaves `fnptr` edges of the managed token range alone. Each `ldstr` writes a
  string row (address `US_BASE | #US offset` with `US_BASE = 1 << 48`, a window no mapped image can
  reach, so native Ghidra string rows never clash; shown and parsed as `us:0x0002ece7`; utf16le, full
  text, empty strings skipped; `ensure` deletes only `US_BASE .. US_BASE + 2^32`) and a
  `data` edge from the method with the IL offset, so `strings` / `xrefs` on the address list the
  methods. The IL listing cuts a literal at 200 characters and appends `…(N chars)`. External
  generic instances keep their arguments in the label (`System.Nullable<uint>::.ctor(T0)`; MethodSpec
  arguments only in the IL listing); `link_managed` maps `Name<a, b>` back to `Name`2`. Async and
  iterator stubs get an edge kind `body` to the state machine `MoveNext` (from the
  Async/Iterator StateMachine attribute, a `newobj` of the machine, or an `initobj`); `callgraph`
  marks it `(async body)` / `(iterator body)` (`Store.body_links`); `function view=asm` (and the IL
  fallback of `view=c`) prints one fact line `; body: <MoveNext name> (async|iterator)`. **[verified]** on a 3.2 MB
  open-source assembly: 13 280 string sites, 7 172 literals, 73 169 call-site rows, `ensure` 3.3 s.
- P14 dnfile cost **[verified]**: `dnPE()` is 1.3 s (3.2 MB), 2.0 s (3.1 MB), 1.5 s (6.6 MB); my IL
  scan with strings adds 0.3-0.5 s; 75 % of `dnPE()` is row object creation for 80 k rows. Skipping
  `parse` of Param/Constant/MethodSemantics/GenericParam and other unused tables gains only 5-20 %,
  so it was not done. A real gain needs an own table reader (tuples via `struct`) that replaces every
  row-object consumer in `_parse_tables`; not started.

## Delphi (M6)

Design in DESIGN §6 "delphi" and §11 "Delphi" (layout facts marked **[verified]**). Facts:

- `server/delphi.py` parses VMTs (32- and 64-bit), published methods and fields, type info (unit names)
  and `TPF0` DFM forms from the PE bytes (no Ghidra). `Image` is shared with `server/cpp.py`. The scan is
  one pass over every section (about 1 s per 10 MB); a 120 MB binary takes about 3 s.
- Tables (schema v12): `dl_class`, `dl_method` (published + virtual), `dl_field`, `dl_form`,
  `dl_component`, `dl_event` (the resolved handler address is stored). Meta `delphi_version:<id>`
  (`DELPHI_VERSION`); `Indexer.resume_project` and `_after_ready` derive them for Delphi binaries only.
- `fnfix.FIX_VERSION` is 3: `dl_method` (incl. property accessors) and `dl_event` addresses are candidates for `create_functions`.
  `create_missing_functions` sends the candidates in chunks of `fnfix.BATCH` (500; one transaction and save
  each, the conventions pass with the last chunk only) and logs progress to `project.log`. It also
  re-reads the functions when the worker reports `exists` for an address the index lacks.
  **[verified]** The worker exit seen on two large Delphi DLLs was no crash: the driver script saw `ready`
  (published before `_after_ready` runs) and called `WorkerClient.stop()` while the background job was
  between `create_functions` and the re-read. The worker ended on `shutdown`; the in-flight request failed
  as `worker_exited`. Reproduced on a fresh analysis (about 3,750 functions are created in 4 s; no crash,
  no memory problem). Now: requests lost to `stop()` fail as `worker_stopped` (logged at info, redone at
  the next open through the `exists` path); a real exit is logged with its exit code in `worker.log`, and
  `fnfix.run` restarts the worker once (reopen, re-read, send the rest).
  `ready` now comes after the after-ready work (status `finishing`, see Fixed).
- Nothing is renamed in Ghidra (as for MFC): `function` shows hints. Project map `UI:` line, `ui-menu` /
  `ui-dialog` feature seeds (`FEATURES_VERSION` 6), `runtime: Delphi` clusters (`graph.CallGraph.lib_hint`
  from units of runtime classes, plus `@`-prefixed names in `clusters.runtime_family`).
- Tests: `tests/test_delphi.py` (synthetic 32/64-bit PEs, all DFM value types, tools, hints, seeds).
- Free Pascal (DESIGN §11 "Free Pascal"): toolchain `fpc` (version string in the RTL, `projects.fpc_version`),
  `delphi.parse_fpc_classes` (other VMT, method table, type info and `TPropInfo` layout), forms are the same
  `TPF0` parser, `DELPHI_VERSION` 4. **[verified]** with FPC 3.2.2 / Lazarus 4.8 programs (i386-win32 and
  x86_64-win64, stripped and with `-g`) through the real worker: classes, fields with types, published methods,
  form tree, events to handlers and string literals with references. Tests: `tests/test_fpc.py`. FPC RTL / LCL signature databases
  (`fpcsigs`, `delphi-sigs fpc-build` / `fpc-oracle`, DESIGN §11), message / interface / init tables and
  virtual slot names (`DELPHI_VERSION` 5, `IDR_VERSION` 10) are done. Interface method names (`DELPHI_VERSION` 6): the FPC 3.2 interface type info (`{$M+}`) holds a method table, read by GUID; the thunk target of a slot is the second source (a published or named virtual method of the class). **[verified]** FPC 3.2.2 i386-win32 and x86_64-win64: `Greet` / `Count` for slots 3 and 4 of a `{$M+}` interface; an interface without type info keeps `#n`. **[verified]** live (Ghidra 12.1.4, `index` of two Lazarus form programs and two console programs, 32 and 64-bit, stripped, through the real indexer): the FPC sigdb `ensure` path names 675 of 1329 (t1 32-bit), 700 of 1447 (t1 64-bit), 5888 of 10320 (Lazarus 32-bit) and 6225 of 11173 (Lazarus 64-bit) functions, shown as `idr:` hints by `function`; four programs index in 244 s. FPC x86 `CALL [reg+disp]` (virtual / interface calls) gets a stub per (vmt offset, register arguments, stack arguments) with the `register` convention (EAX Self, EDX, ECX, rest on the stack; `delphistr` VERSION 5, collector 10): before, a hidden result pointer (`LEA EDX,[local]`) was lost and the decompiler printed `uStack_10 = 0` where the value is the result of the virtual call; after, the C reads `vmt_64_ad_0(self,&uStack_20); uStack_10 = uStack_20;` (x64 was right already: its `RDX` is a known parameter). FPC 3.0.4 (round 10, `tests/test_fpc304.py`): the installers were unpacked with innoextract (no install; `fpc.cfg` made with `fpcmkcfg`, the x86_64 compiler is `ppcrossx64` of the cross package) and three programs built (console classes t1, `{$M+}` interfaces and messages t2, an RTL/FCL program t3) for i386-win32 and x86_64-win64, stripped and with `-g`. **[verified]** same as 3.2.2: version string `FPC 3.0.4 [2017/11/26]` (toolchain `fpc`, `toolchain_ver` 3.0.4), VMT header (12 words, `TObject` has 13 virtual slots, user slots from 13, slot = offset/ps - 12), class tables, published methods, message tables, `FPC_TOBJECT_VSLOTS`, vcall stubs (`vmt_64_ad_0`, `vmt_68_a_0`; x64 `TAnimal vslot 13 -> ...`), class and unit names, 83 / 83 / 133 classes found. **[verified]** differences found and fixed (`DELPHI_VERSION` 9): (1) interface table entries hold the GUID and the GUID text directly (3.2: pointers to cells), so GUID, `QueryInterface` names and type info were lost (`intf_<addr>`); (2) the init table of managed fields is `kind, name, u32 size, u32 count, {^typeinfo; offset}` (3.2 has a terminator and cells), so the managed `AnsiString` / interface fields were missing; (3) `TEntryInformation.PascalMain` is field 3 (3.2.2: field 5) and the x64 start code passes no record (the called entry function holds `xor rcx,rcx; lea rdx,[PASCALMAIN]`), so `function main` failed; (4) an interface with type info is now named from it (`IGreeter`, 3.0.4 and 3.2.2); (5) `function main` of a program where Ghidra made no function at PASCALMAIN (3.2.2 t2 32-bit, found while comparing) creates it on demand. 3.0.4 interface type info has no method table: slots 3 and later stay `#n` unless the thunk target is a published or virtual method. Signature databases (`fpc-build` of the 3.0.4 install, no Lazarus: 11027 names 32-bit in 84 s, 12763 64-bit in 76 s, 730 / 729 virtual slot names): oracle (`fpc-oracle`, `-g` builds, library routines, after the call pass) right / wrong 32-bit t1 87.2 / 0.0, t2 86.6 / 0.0, t3 85.7 / 0.1; 64-bit t1 88.3 / 0.0, t2 87.7 / 0.0, t3 86.5 / 0.2 (routines of at least 24 bytes: 97.8 to 99.0 % 32-bit, 91.3 to 93.5 % 64-bit). Same programs with 3.2.2 (database with the LCL, 25977 / 28279 names): 32-bit 87.5 / 0.1, 86.7 / 0.1, 83.5 / 0.2; 64-bit 87.7 / 0.4, 87.0 / 0.4, 83.9 / 0.6. The databases are per exact version (`idr.files_for`), so 3.2.2 names are never applied to 3.0.4; no 3.0.4 name set was needed beyond `fpc-build`. Live index (Ghidra 12.1.4, six stripped programs per version, 262 s for 3.0.4 and 335 s for 3.2.2): functions named by the sigdb 3.0.4: 779 of 1045, 818 of 1266, 775 of 1054, 815 of 1273, 1462 of 1918, 1528 of 2343 (t1, t2, t3; 32 / 64-bit); 3.2.2: 681 of 1336, 701 of 1448, 676 of 1341, 698 of 1455, 1137 of 2361, 1203 of 2615 (the 3.0.4 RTL is smaller, so the share is higher). ShortString literals: Ghidra finds those of 5 characters or more with references in both versions; 4-character ones (`purr`, `user`, `name`) are found in some builds only (3.0.4 t1 32-bit: missed, 3.2.2: found); no own ShortString pass exists (open). The 3.0.4 programs link `Windows` and `FCL` units (t3) without Lazarus; LCL / Lazarus forms are not checked with 3.0.4 (Lazarus needs 3.2.2). Strings: Ghidra's own handling already finds the
  literals and their references (ANSI and UTF-16), also in 64-bit; the 64-bit FPC string header has 8-byte
  `refCount` / `length` (24 bytes before the data) and `delphistr._STRREC` (4-byte refcount) does not match it.
- IDR names (`server/idr.py`, `tests/test_idr.py`, DESIGN §11 "Delphi"): optional, config key `idr_kb_dir`
  (a folder with the IDR `kb*.bin` / `syskb*.bin`; 32-bit files in it or in `x86\`, 64-bit files in `x64\`).
  Files come from github.com/crypto2011/IDR (32-bit: `kb2` to `kb2014`, `syskb2` to `syskb2014`, XE4 is the
  newest) and crypto2011/IDR64 (64-bit `syskb2012` to `syskb2014`, system units only); the `kb*.7z` need
  unpacking. Both repos are MIT. Hints only (no rename, no table): meta `idr_version:<id>` / `idr_hits:<id>` /
  `idr_info:<id>`; `function` shows `idr: Unit.Proc`; hits join `runtime_addrs`. Computed in `delphi.ensure`
  (ready flow, after `create_missing_functions`, and on open); stale when `IDR_VERSION`, the KB files or the
  number of unnamed functions change. Open: files for newer compilers (Delphi 10 Seattle and later only match in
  part, 64-bit much less), no 64-bit full KB (only system units), fixup
  names (calls between procs) are not used to confirm a match.
- Signature databases (`server/delphisigs.py`, `server/itanium.py`, `tests/test_delphisigs.py`, DESIGN §11 "Delphi"):
  exact-version names built from the packages of a local Delphi (`airlock delphi-sigs build <install folder>`,
  `list`; needs capstone, extra `sigs`; config key `delphi_sigdb_dir`, default `<data dir>\sigdb`; files
  `<compiler>-<32|64>.sigdb`). Derived from licensed files: never commit them. `idr.kb_files(root, psize,
  sig_dir)` lists them after the IDR files; `idr._pick` runs the exact-compiler database first, then the best
  IDR file on the functions left (merged, the database wins). `IDR_VERSION` 3.
  32-bit: export names are Borland style (`@Unit@Class@Name$q...`), bounds by a linear sweep. 64-bit: exports are
  Itanium names (`_ZN6System7Classes5TList3AddEPv`, parsed by `itanium.demangle`), bounds from `.pdata`
  (`delphisigs.read_pdata`, chained unwind info handled, unsorted table); leaf routines without unwind info are
  swept. Built from Seattle Update 1: 32-bit 123 packages, 129,545 names, 5.6 MB, 8 s with 8 jobs; 64-bit
  (`Redist\win64`, 114 packages) 118,370 names, 6.5 MB, 9 s. The build was 65 s before a quadratic slice of the
  relocation list was removed.
  Oracle (not in the repo): a program with most RTL and VCL units built with `dcc32` / `dcc64 -B -GD`, map file
  as truth, routines at map publics. Named with the right name, routines whose name the packages export and that are
  not generic instances: 32-bit 93.1% (98.4% without the `MAX_COPIES` drop), 64-bit 89.6% (99.0%). Generic
  instances of the RTL's own types are found (`TList<T>` shapes); instances for other types are not. Wrong names are
  2 to 3% of the matched routines and are code aliases. Exported names cover 62% (32-bit) and 79% (64-bit) of the
  routines of the program, so 36% / 43% of all routines are named.
  Private routines (helpers, nested routines, implementation-section routines, unexported generic instances):
  `server/delphimega.py` builds one package that *contains every `.dcu`* of the install
  (`lib\win32\release`, `lib\win64\release`; `System` and `SysInit` are implicit) with `dcc32` / `dcc64 -B -GD`, and
  `server/delphimap.py` reads the detailed map (`System.SysUtils.TStringHelper.Split`, nested `Outer.Inner`, generic
  `Unit.{Owner}TList<T>.Add` shown as `Owner.TList<T>.Add`). `delphisigs.build(pairs=)` adds the map names after the
  exported ones (an exported name wins on identical masked code). CLI: `airlock delphi-sigs build <install> --units
  [--work DIR] [--keep-work]` (about 1 minute per bitness for the package, 70 s for the scan), or `--map BINARY MAP`
  (repeatable) for a pair built another way. `IDR_VERSION` 7. **[verified]** Not done: rebuilding the RTL / VCL packages
  from `source`: the sources and the shipped `.dcu` files disagree (`F1026`, `F2051` when one unit is compiled from
  source and the rest linked from `.dcu`), no `.dpk` exists for the VCL, and `BuildWinRTL.dpk` has 176 of the 262 units
  of `rtl230.bpl`. The `.dcu` files are the truth instead: the code of a rebuilt `rtl` package equals the shipped
  one on 99.9% of the common exported routines (masked bytes). The `.jdbg` route is dropped (32-bit only, names use an
  undocumented compressed form). Units that cannot be in a package are left out by the build loop (62 of 1,951
  for 32-bit, 55 of 1,919 for 64-bit: missing `.res` / `.fmx` files, `$DENYPACKAGEUNIT`, BDE; mostly FMX and TeeChart
  editors, REST backends, WebBroker, IntraWeb, ComServ). Newer installs (compiler 33, 35) overflow the export table
  of one package (`E2621`), so `delphimega` now builds one package per shipped package (PACKAGEINFO contains list,
  requires the shipped `.dcp`) plus one for the remaining units, in parallel (`--jobs`); a failed units step prints
  one warning and the database is written from the package exports. **[verified]** on compilers 30, 33 and 35, both
  bitnesses. The Delphi install is needed only for this build; the
  `.sigdb` files stay usable without it.
  Oracle (own program, map as truth, routines that are no type tables or thunks): right name 32-bit 58.0% -> 70.9% of
  all routines, 77.0% -> 94.6% of those with at least 24 bytes; 64-bit 69.9% -> 83.9% and 78.9% -> 94.6%; wrong names about
  1.5% (code aliases). What is left is mostly routines under 10 compared bytes. Sigdb: 129,545 -> 150,015 names (32-bit),
  118,370 -> 140,900 (64-bit; most map routines share masked code with an exported one).
- Extended RTTI and the consensus database (`server/delphi.py` `_rtti_methods`, `server/delphirtti.py`,
  `tests/test_delphirtti.py`, DESIGN §11 "Delphi" and "RTTI consensus database"). **[verified]** layout of the
  extended method table (32/64-bit) and flags; `dl_method` kind `rtti-<visibility>`, `DELPHI_VERSION` 2, hint
  `rtti: Unit.Class.Method`; no schema change. `airlock delphi-sigs rtti-build <folder>... [--out] [--min-binaries 3]
  [--min-products 1] [--exclude FILE] [--indy] [--jobs]` (one folder = one product; about 8 minutes for 300
  programs with 6 jobs) writes `rtti-<compiler>-<bits>.sigdb`; `idr._pick` runs exact sigdb, then this database, then
  IDR. `IDR_VERSION` 4. Measured: direct names are the big gain on a program that still has the table (a quarter or
  more of its unnamed functions); the consensus database adds almost nothing on top of them (they name the same
  routines) but gives a Delphi-less install a database of its own (an own build: 29% / 39% of routines named, 99%
  right). The copies rule of `idr.match_all` was loosened (`LONG_SHAPE`, `GENERIC_MIN`): +48% / +62% named routines on
  the own builds at the same precision. Tried and not worth it: naming overridden virtual slots from the parent's
  RTTI (a few dozen extra functions on a real DLL).
  Open: unit-level procedures and private routines that no table lists, a larger and more varied corpus (the product-count
  rule matters once there are several products per bitness), `rtti-build` has no incremental mode (a new
  corpus rescans everything), and the Ghidra side does not rename anything (hints only).
- Property accessors and call-context names (`delphi._properties`, `delphi.accessor_names`, `idr.call_context`,
  `delphisigs` format 3, `delphioracle`; DESIGN §11 "Delphi" and "Call-context naming"). `DELPHI_VERSION` 3,
  `IDR_VERSION` 8, `fnfix.FIX_VERSION` 3: old projects recompute once. Accessors of published and extended-RTTI
  properties become `dl_method` kinds `prop-get` / `prop-set`; the hint is `prop: Unit.Class.GetProp (getter of
  Prop, name by convention)`. **[verified]** layout on compilers 30, 33, 35, 32 and 64 bit (map as truth); the
  name is right for 94% of the accessors. The sigdb stores, per reference routine, the names of its direct callees
  by operand offset; a function that code names gives each unnamed callee that name (all callers must agree).
  Old sigdb files (no call lists) still load and give no call-context names; rebuild them to get the pass
  (`airlock delphi-sigs build <kit> --units --jobs 8`, then copy the `.sigdb` files to the sigdb folder). The
  oracle command prints the stages `sigdb`, `+calls`, `+props` (table in DESIGN). Not done: a second round that
  lets a context-named callee name its own callees, callers that reach the target through a virtual call or a
  function pointer, call lists in the RTTI consensus database.
- Not done: Delphi 2007 and older layout (accepted by the scan, never seen on a real file),
  dynamic/message method tables, interface tables, virtual method names, renaming.

- WARP names (`server/warp.py`, `worker/ghidra_ops/warp.py`, `tests/test_warp.py`; DESIGN section 11): reads Binary Ninja
  `.warp` libraries (delphinja Delphi RTL) and computes the WARP function GUID from capstone blocks (used by
  `idr._pick`, tier after the RTTI database, before IDR) or from the worker op `warp_blocks` (Ghidra blocks; 81% equal
  to capstone, not used by the pipeline). Config key `warp_dir`; files in `%LOCALAPPDATA%\airlock\warp` (not in the repo).
  `IDR_VERSION` 6. 32-bit only. Approximate: Binary Ninja's block recovery differs from ours on some functions.
  **[verified]** on real programs of compilers 30, 33, 35 and 36 (extended RTTI names as truth): `library_stems` is
  `10.4-only` + `core-11` + `xe2plus-only` from compiler 30 on (before: `core-11` only for 35, which named a third
  as many); `10.4-only` and `xe2plus-only` are about 99% right, `core-11` 87 to 98% (small shapes). WARP names generic
  instances as `TDictionary__2.Add`; `warp.dotted` now writes `TDictionary<T>.Add` like the sigdb and RTTI tiers, and
  `idr._pick` puts the real type arguments in when the program has exactly one instance of that class in its RTTI.
  Own 64-bit (and 32-bit) libraries: `airlock delphi-sigs warp-build <kit>... --bits 64` writes
  `airlock-rtl-win64.warp` into `warp_dir` from the map builds of the kits (DESIGN section 11 "Own WARP libraries").
  Used for any compiler version, after the exact sigdb and the RTTI database. Leave-one-out on compiler 35 samples
  (library from 30/33/34): right 53 to 62% -> 61 to 65% (+2.8 to +7.3 points), wrong down. `IDR_VERSION` 9: old
  projects recompute once. `projects.detect` now marks a program
  without forms (console, DLL) as Delphi by its `DVCLAL` resource; before, such a program got no Delphi tiers.

## Qt and dataflow (M8)

Design in DESIGN section 6 and section 11 "Qt metaobjects" (layout facts marked **[verified]**). Facts:

- `server/qt.py` parses `QMetaObject` data from the PE bytes (Qt5 and Qt6 layouts, 32/64-bit); meta `qt_version:<id>` (`QT_VERSION`); `Indexer.resume_project` and `_after_ready` derive it for Qt binaries (toolchain `qt` or `Qt<n>*.dll`).
- Worker op `qt_dispatch` (`worker/ghidra_ops/qt.py`) maps method indices to functions from the decompiled `qt_static_metacall` and finds imported parent classes; run by `qt.resolve` after the missing-function step; meta `qt_dispatch:<id>`. Tool `qt_metaobjects` (`tools/qt.py`); hints in `function`, a `Qt:` line in the project map, moc boilerplate marked runtime family `Qt`.
- Dataflow ops (`worker/ghidra_ops/dataflow.py`) and tools (`tools/dataflow.py`): `switch_tables`, `trace_values`, `constants`. Ghidra tests: `tests/test_dataflow.py` with `-m ghidra --binary=...`.
- Qt6 layout is verified on a real 64-bit MSVC Qt 6.10 desktop client (revision 13; see DESIGN section 11 for each fact). Two parser bugs fixed: with `QT_NO_DATA_RELOCATION` `superdata` is two words `{direct, getter}` (the metaobject starts one pointer before the scan address; parents come from the getter, local or from the import name, no worker needed); Qt6 has no Notify property flag (`notifyId` is -1 or the signal index). `QT_VERSION` 2.
- Pointer-to-member connects work (Qt6 MSVC x64): `qt.fill_imports` adds the C++ imports Ghidra leaves out of the `import` table, `derive_connects` finds the call sites as read edges to the `connectImpl` slot, worker op `qt_connects` (`worker/ghidra_ops/qt.py`, `_Flow`) resolves signal and slot (chases forwarding wrappers up the callers). Rows are `qt_connect` kind `ptr`. `DISPATCH_VERSION` 2. Sites in template instances nobody calls (incremental-link leftovers) stay unresolved. Qt5 MSVC x64 and Qt5 MinGW 32-bit are verified too (DESIGN section 11): Itanium import names, calls through a register (a site stands for all calls of its function), a signature set on the imported `connectImpl`, stack stores read from instructions, string pairs for register-loaded `connect`. `QT_VERSION` 3, `DISPATCH_VERSION` 3. Virtual member pointers (MSVC vcall thunks, Itanium offsets) resolve through the receiver's vtable when the class is known (DESIGN section 11 (9)); 64-bit MinGW (Qt5) is verified. `DISPATCH_VERSION` 4. Sites in functions nobody calls are `uncalled`, not counted as unresolved. `DISPATCH_VERSION` 5 (DESIGN section 11 (13) to (17)): more receiver classes (callers that agree, new or stack objects, factory returns, fields typed by a store in the same function), library-class slots from the import stubs of program subclasses (`qt.connect_context` sends `allvtables` and `parents`), the 32-bit MinGW vtable scan (loose `metaObject()` reads), functions named only by chained unwind data count as uncalled, site functions and their callers decompiled ahead in parallel.
- Qt feature seeds (`qt.feature_seeds`, `FEATURES_VERSION` 7): slots of QAction / button / dialog signals seed ui-menu / ui-dialog; Qt library class prefixes in `features.API_PREFIX`.
- Scratch tip: `connectImpl` returns `QMetaObject::Connection` by value, so argument 1 is the result pointer (the decompiler also shows the stack arguments shifted).

## Agent evaluation (blind, 2026-11-05 and 06)

Method: `claude -p` (`--tools ""`, `--allowedTools "mcp__airlock__*"`, `--strict-mcp-config`, `--max-turns 40`,
`--output-format stream-json --verbose`) with only airlock as MCP server, once with Sonnet and once with Haiku. The server runs
through a small launcher that points it at a copy of the analysed projects and at a config copy with the delphi and
dotnet sets enabled (the user's config is not touched). The prompt names the program and the question and says that
airlock tools exist, nothing else. Per run: tool calls, errors, turns, cost, answer. Solved = the answer matches the
public source (v = yes, ~ = right but partial, x = no). Single runs, so +-30% call counts are noise.

Programs (all open source, official releases, analysed with option A): DB Browser for SQLite (Qt5 MSVC x64), Raspberry Pi
Imager (Qt5 MinGW x86), ExifToolGUI 6.2 (Delphi), Open Hardware Monitor 0.9.6 (.NET Framework), WinMerge 2.16.60
(MFC x64), WinDirStat 2.9.3 (MFC x64, recent MFC). Sources: github sqlitebrowser, raspberrypi/rpi-imager, FrankBijnen/ExifToolGui,
openhardwaremonitor, WinMerge, windirstat.

| Task | Sonnet before | Sonnet after | Haiku before | Haiku after |
|---|---|---|---|---|
| t1 DB4S: File > Open Database | v 5 calls | v 5 | v 10 (1 err) | v 10 |
| t2 DB4S: settings, geometry keys | v 9 | v 14 | v 23 (1 err) | v 16 |
| t3 RPi: download progress signal and slot | ~ 3 | ~ 3 | ~ 9 | ~ 9 |
| t4 RPi: cancel a write | v 6 | v 6 | v 24 | v 18 |
| t5 ExifToolGUI: Remove Metadata, Execute | v 8 | v 8 | v 11 (1 err) | v 11 (1 err) |
| t6 ExifToolGUI: settings file | v 16 | v 8 | v 25 | v 13 |
| t7 OHM: Run On Windows Startup | v 11 (2 err) | v 5 | v 10 (3 err) | v 8 (r4: 9, 0 err) |
| t8 OHM: settings file | v 6 | v 9 | v 15 (5 err) | v 11 |
| t9 WinDirStat: Tools > Recovery | x 33 | x 45, r3: v 11 | x 37 | x 40, r3: v 17 |
| t10 WinDirStat: options storage | v 15 | v 6 | v 12 | v 11 |
| t11 WinMerge: Edit > Options | (new) | v 5, r3: v 5 | (new) | v 10, r3: v 9 |
| t12 WinMerge: options storage | (new) | v 12, r3: v 9 (1 err) | (new) | v 15, r3: v 17 |

"~" in t3: the signal and the command-line slot are found; the QML handler is invisible in the binary. "Before" is the
state after the first round (instructions, Frameworks lines, search, no auto-retry); "after" includes the round-2 fixes.

Failure patterns and fixes (round 2):
- Hints were not acted on (`retry=true`): `function` now retries once by itself after 2 s when the worker restarted,
  the JVM was not running or the file was closed; the hint appears only if the second try fails too (`_get_decompiled`).
- Names the tools print were not accepted as targets: `search` showed `MainWindow::fileOpen (Qt slot)` but
  `function MainWindow::fileOpen` said not found. `function`, `xrefs` and the other target tools now resolve
  `Class::method` of Qt `qt_method` rows and `TClass.Method` of Delphi `dl_method` rows (`targets._qt_method_addr`);
  `search` finds both by name (`_qt_method_hits`).
- .NET: `function` on a managed method said "use dotnet_decompile" and the agent then guessed member names that do not
  exist in the C# (`.ctor`, `<.ctor>b__37_5`, `set_Startup`). `function` now forwards to `dotnet_decompile` and the
  member lookup maps constructors, lambdas and accessors to the C# name (`dotnet.member_alias`).
- `overview` has a `Win32 resources` line (dialogs, menus, string_tables) for any binary with dialogs, so an MFC binary
  whose message maps are not decoded still points at the id route. The empty `mfc_message_maps` answer now says so.
- Rule since then (DESIGN 7.5): no advice in tool output. Tools retry, widen (`strings` falls back to
  regex, `path` raises max_depth or swaps from/to, `function_map` drops an empty scope), follow (an
  import's references for `function`, a thunk's import in `path`, IL when C# is unavailable) or forward
  (`search kind=class|const`), list candidates as data (close names, forms, members, topics, binaries)
  and name a fix only when the user must make it. `tests/test_no_hints.py` scans for new hints.
- Haiku wanders more than Sonnet (24 turns where Sonnet needs 6) mostly in unnamed code: it reads big FUN_ functions
  and repeats `constants`/`xrefs`. Tools that name things (Qt, Delphi events, MFC maps, .NET) cut it to 8-18 calls.
- Both models call `overview` rarely (Haiku sometimes, Sonnet never). It does not matter where a framework tool is
  reached by name (qt_metaobjects, delphi_forms, dotnet_*), so the Frameworks lines were not needed in these runs.

Round 3 (t9, t11, t12): WinDirStat 2.9.3 is no MFC program. It has an own MFC look-alike framework whose
route tables `{msg, code, first, last, invoke thunk, registered}` only a lazy initialiser names (see the MFC part
above, `server/routes.py`). Now decoded: both models go menu id -> `anon_<table>::OnCommand_32876_IDS_MENU_RECOVERY`
-> `function` and answer correctly (elevation check, modal dialog 111, update handler enables only when elevated).
`function` / `xrefs` accept the generated handler names (WinMerge `CMainFrame::OnCommand_32786_Options`). t11/t12
unchanged in result; the t12 error is a `delphi_classes` call on an MFC project.
Open: the QML side of Qt signals; the virtual call `this+0xf0 -> +0x34` without RTTI (t4).

Round 4 (transcripts `r5_b_*`, code at 10e5574: no hints, route tables, MFC handler names in `search`). All 12 old
tasks plus three new tests, Sonnet and Haiku, same method. New program: HeidiSQL 12.22 64-bit (Delphi 12 VCL, x64,
official portable zip; source tag `v12.22-Windows`, the plain `v12.22` tag is the Lazarus port).

| Task | Sonnet r3 | Sonnet r5_b | Haiku r3 | Haiku r5_b |
|---|---|---|---|---|
| t1-t8 (DB4S, RPi, ExifToolGUI, OHM) | as above | same grades; 68 calls (r3 58) | as above | same grades; 123 calls (r3 96) |
| t9 WinDirStat: Tools > Recovery | v 11 | v 12 | v 17 | v 7 |
| t10 WinDirStat: options storage | v 6 | v 18 (2 err) | v 11 | ~ 23 (INI trigger not found) |
| t11 WinMerge: Edit > Options | v 5 | v 5 | v 9 | v 10 |
| t12 WinMerge: options storage | v 9 | v 8 | v 17 | v 20 |
| t13 HeidiSQL: Tools > Flush > Tables with read lock | (new) | v 7 | (new) | v 11 |
| t14 HeidiSQL: settings storage | (new) | v 6 | (new) | ~ 17 (format guessed as JSON) |
| cr1 dirty: write and publish settings specs (ExifToolGUI) | (new) | ~ 54 calls, 4 specs | (new) | ~ 58 calls, 4 specs |
| cr2 clean: answer from the specs only | (new) | ~ 7, faithful | (new) | ~ 7, faithful |
| long: t9, t11, t10, t12, recall, compare in one session | (new) | 4 v, 2 ~ | (new) | 4 v, 2 ~ |

Totals t1-t12: Sonnet 111 calls, 6 errors, 0 repeated calls (r3: 126, 2, 2); Haiku 183 calls, 8 errors, 0 repeated
(r3: 172, 7, 0). The hint removal shows no measurable effect: repeated calls were already near zero and the
errors are other kinds (below). t6 answers name the INI file `<title>.ini`; the real name is `ExifToolGUIV6.ini` and an
`-IniPath=` switch exists; r3 had the same gaps and was graded v, so the grade is kept.

Clean-room test: a dirty session (own project copy, `rd_cr_<model>`) writes `settings.*` specs and runs `spec_export`; a
new session in a server started with `--profile clean` answers from them. The clean tool list has only the 6 clean tools,
and no result carried code, addresses, bytes or notes. Both clean answers report the specs faithfully and list what the
specs leave out; their errors are the dirty side's (Sonnet got the V6 name and the load order right, both missed the
`-IniPath` switch and said no switch selects the folder). The clean `project_open` text names the absolute path of the
sibling `dirty\` folder in its "never read ..." line; that tells a clean agent where the dirty data is.

Long session (one `claude -p --input-format stream-json` process, project `mfc2` with both exes): no binary confusion
(every call names the right exe, L6 keeps the two registry keys apart), 0 repeated calls across tasks, 0 calls for the
recall and compare questions, `--max-turns` counts per message. Context at the end 77k (Sonnet) and 84k (Haiku) tokens.
Per-task calls 9/6/5/3 (Sonnet) and 18/7/14/11 (Haiku); the later tasks are cheaper because menus and names are
already in context. The two ~ are the WinDirStat INI trigger (L3, and so L6), missed by both, as in Haiku t10.

Failure patterns (round 4):
- `spec_write` `bad_source` in every dirty run (4 of 4 first writes, both models): agents put prose into `sources`
  ("Static analysis of ...: the routine that builds the path"). The list is split on commas and the first fragment is
  resolved as a function name; the error says `no function named '<prose>'` plus "method words such as 'observation'
  count too", without the accepted forms. Both models then retried with `binary!FUN_x` and succeeded. Fix: show the
  forms (`binary!function`, `binary!0xADDRESS`, method words) in that error, or store an item with spaces as an
  `observation` with its text.
- `spec_has_bytes` false positive: a table row of decimal column widths (`64, 64, 48, 73, 73, 56, 88, 80`) was taken
  for a hex byte run.
- Delphi x64 (HeidiSQL): the handler header of `TMainForm.actFlushExecute` lists 4 of its 6 `OnExecute` bindings
  (`actFlushTableswithreadlock` and `actFlushStatus` are missing), so both models call the read-lock branch
  `actFlushTables`. Unicode string literals passed as `0x124ab50` stay numbers in the C, so the exact SQL suffix and
  the portable-file delimiter `<|||>` were not read (Haiku then guessed JSON for the settings file).
  Fixed after round 4: the header query had `LIMIT 4`; it now lists every binding and groups components
  of one class (`handler OnExecute of 6 TAction: ...`). The strings: Parameter ID had typed the
  source parameter of the RTL string assignment as `longlong`, and the decompiler turns a constant into
  a string only for a pointer or undefined parameter. A new fixup step (`delphistr`, DESIGN §11
  "Delphi", `COLLECTOR_VERSION` 4, so old projects are refreshed on open) types the literals and
  retypes such parameters; the C now reads `FUN_00412a40(local_28, L"TABLES WITH READ LOCK")` and
  `FUN_00d48cc0(L"<|||>", ...)`. `delphi_*` on a project without Delphi answers
  `error not_delphi: no Delphi binaries; frameworks: qt (rpi-imager.exe)`.
  Rerun r6 (transcripts `r6_*`, a refreshed copy of the project, same prompts): t13 Sonnet v 7 calls,
  Haiku v 6 (r5_b 11); both name `actFlushTableswithreadlock` and quote the SQL. t14 Sonnet v 11 calls
  (1 `bad_cursor`), Haiku v 22 (r5_b ~ 17); both read the `<|||>` line format and the `<{{{>` / `<}}}>`
  escapes from the C.
  Pass version 2 (`COLLECTOR_VERSION` 5, DESIGN §11 "String literals, pass version 2") closes the gaps
  left open: stack arguments are retyped (`PUSH lit`, `MOV [RSP+d],reg`); literals Ghidra had
  disassembled as code are cleared and typed; concatenation routines are found by their calls and get a
  variadic signature on x64 (the C lists every piece) or a PRE comment with the pieces at each x86 call;
  Delphi 2007 and older `AnsiString` literals and `WideString` literals (all versions) are detected,
  only where code references them. Stores to locals and fields needed nothing once the data is typed.
  **[verified]** on the x64 and x86 programs above and on an open-source Delphi 7-2007 program: on 20
  sampled functions per program no literal is left as a hex constant (1 before on each); a project at
  collector 4 reruns only this pass on open (end-to-end on a copy of the x64 project). Collector 6: each call of a concat routine
  (x86 and x64) is pointed, by a primary CALL_OVERRIDE_UNCONDITIONAL reference, at a 1-byte stub function in the block
  `airlock_stubs` with custom storage for exactly its n pieces, so the C lists every piece in order
  (x86 pushes left to right, so a plain signature came out reversed; x64 varargs lost the stack pieces). The PRE
  comment remains only where no stub could be made. **[verified]** live (Ghidra 12.1.4, x86 and x64 Delphi programs, opened through the MCP tools): outline / function_map / search / xrefs / callgraph / function show no stub and no `airlock_stubs` block; a caller's callgraph edge goes to the real concat routine; the C lists every piece; renaming the routine renames its stubs; a project at collector 7 reruns only the string pass on open. Collector 9 (`delphistr.VERSION` 4, so the Delphi decompiles are recomputed; a project at collector 8 reruns only the string pass): the decompile op rewrites a call of a stub to the routine itself (`decompile._unstub_calls`: the row target is the routine's entry, the C text names the routine and not `Name_3`, all token offsets move with the text), so the C reads `LStrCatN(...)` with the real entry address in the `/*0x...*/` note and never shows a stub name or address; every output that prints C (function, diff, dataflow, bulk pass) takes the one worker result. Piece lists are untouched. Collector 8: the caps are 255 pieces and 1024 stubs (no sample came near the old 64 / 256); Free Pascal x64 literals (24-byte header `u16 codePage; u16 elemSize; u32 pad; i64 refCount; i64 length`, `scan_strrec64`) are typed and their callee parameters retyped (Free Pascal 32-bit uses the Delphi 12-byte header and needed nothing). FPC concat routines (`fpc_*_concat`: fixed registers; `_multi`: an open array built in a stack array) and the Delphi fixed-register forms (`UStrCat3`, `LStrCat3`) need no stub: the decompiler already lists their pieces (as arguments, or as the stores into the array). The array element that a virtual call fills (FPC x86) is right only with the vcall stub above. Collector 11 (`delphistr.VERSION` 6; a project at collector 10 reruns only the string pass): the vcall stubs also cover 32-bit Delphi (the `register` convention is the same). Differences from FPC, each **[verified]** on 32-bit Delphi programs (two small test programs with virtual, interface, `stdcall`, `safecall` and string/record-result methods, built by two Delphi versions; a small real program; a VCL program): (1) the vmt pointer is loaded into another register (`MOV ESI,[EAX]` / `MOV EBX,EAX`, then `CALL [ESI+8]`): the first write of the base register is skipped (before, the scan stopped there and every register argument was lost); (2) the hidden result pointer is the last register argument (`LEA ECX,[local]`), not the first; (3) byte and word arguments (`MOV DL,1`, `MOV CL,5`) make the stub parameter `DL` / `CL` (the key letters `Db`, `Cb`, `Dw`, `Cw`; the nearest load decides), else the C printed `CONCAT31(...)` of the old upper bytes; (4) `PUSH EBP` is never an argument and the oldest pushes of EBX, ESI, EDI before the frame set-up or a branch are the prologue; (5) `stdcall` / `safecall` interface calls (`PUSH args; PUSH Self; MOV EAX,[EAX]; CALL [EAX+n]`) have no register argument: they get a stack-only stub `vmt_<n>_s_<pushes>` (Self is the top stack word, so the C reads `vmt_20_s_3(self,3,4)` for `Std(3,4)`) but only when the vmt load `MOV reg,[reg]` is in the scan window, and none when `ADD ESP,n` follows (cdecl); `PUSH EAX; CALL [EAX+n]` alone is a register call that saves EAX and gets no stub; (6) the stack arguments of the register convention are pushed left to right, so the old default read them in reverse order (`(self,a,b,x,y)` for `(self,a,b,y,x)`). Dynamic methods go through the direct helper `CallDynaInst` and are not touched. The stub block grows by 2048 slots (joined to the block, max 8192) when it is full: a Delphi program has 100 to 1500 different (vmt offset, arguments) shapes, the old 1024 slots and 512 vcall stubs were too few. The decompile op drops the target of a vcall stub (`decompile._unstub_calls`, `stubs.is_vcall_stub`), so the C prints `vmt_34_adc_1(...)` without `/*0x........*/` and no stub address reaches the agent (concat stubs still print the real routine's address). Numbers (decompiler call inputs vs. the arguments found in the instructions, calls with more than Self, up to 150 sampled functions per program, stubs removed first = before): small test program (Delphi 10 Seattle build) 5 of 17 calls lost an argument -> 0; (Delphi 11 build) 6 of 20 -> 0; real small program 9 of 254 lost and 16 with surplus junk arguments -> 0 and 0; VCL program 10 of 237 lost and 9 surplus -> 0 and 0. FPC 3.2.2 programs (32-bit, 150 sampled functions each): 0 lost after (194 and 199 of about 220 before). 20 sampled functions per program compared as C text before/after (about 60 functions): no call got worse; the changes are the stub name and the right argument count and order; two kinds of new variables appear where a stack argument was missing before (`unaff_ESI` for an uninitialised variable that is really passed). `PUSH` of a register that the compiler saves in the middle of a frameless function (`PUSH EBX`) is still counted as an argument when it sits between the loads. End to end on a copy of the small real program (collector 8 -> 11, string pass only, 35 s bind): the C shows `vmt_50_adc_1(...)` and `vmt_138_adcb_2(...)`, no address note. `create_functions` refuses an address in the stub block like `set_comment`.
- Round 7 fixes (r7c): Collector 13 (`delphistr.VERSION` 7; a project at collector 12 or older reruns only the string pass). (1) `worker/ghidra_ops/pascalconv.py`: every 32-bit Pascal function (Delphi and Free Pascal; the pass runs at the end of `apply_delphi_strings`) gets the full `register` prototype with custom storage: EAX, EDX, ECX for the arguments it takes, then the stack arguments in source order (the first argument is the one at the highest offset; Ghidra's Delphi spec lists them the other way, so `TBase.Num(X,Y,Z,W)` read `(param_3 * param_5 + param_2) - param_4` and now reads `(param_3 * param_4 + param_2) - param_5`). The number of stack words is the `RET n` of the function (no `RET`, differing `RET`s, or `RET` without a count while Ghidra sees stack parameters (`cdecl`) leave the function alone). The register count is a liveness pass over the function (reads before writes on any path; a call or tail jump reads the registers its callee takes, so `ADD EAX,4; JMP g` keeps g's EDX and ECX), raised to the registers Ghidra stored for a `__register` function, to the decompiler's own result when the entry pushes EAX/EDX/ECX before writing them (the decompiler's data flow tells a saved argument from a reserved slot; Delphi spec only), and, for a function that reads none, to the registers that all its callers load. A byte or word argument keeps a `DL` / `CL` / `AL` storage (Ghidra's own, or the narrow reads, or callers that all load only `DL`) so the caller does not print `CONCAT31(in_EDX >> 8, 1)`. Free Pascal programs (Visual Studio spec) get `__fastcall` as the name where the function had none (no "unknown calling convention" warning); the storage does not depend on the name. **[verified]** (Ghidra 12.1.4, FPC 3.2.2 GUI test program with 10832 functions; 300 random functions decompiled before and after): `in_EAX/EDX/ECX` 798 -> 24, `extraout_E*` 405 -> 30, `CONCAT` 21 -> 22; the pass takes 17 s. On a large local Delphi program the register leftovers also went down (`in_E*` 15 -> 2, 300 functions) and the pass takes about 30 s. The FPC event handler `FUN_00428250(void)` with `in_EAX` / `in_ECX` is now `FUN_00428250(int param_1, undefined4 param_2)`, `fpc_ansistr_concat(&dest,"Button was clicked: ",(char *)pbStack_10,sVar1)` lists all pieces. A second run changes a handful of prototypes (a callee gained a register in the first run); it does not oscillate. (2) `vcall_scan`: after a vmt load (`MOV EBX,[EBX]`) the writes that feed it (`MOV EBX,[EBP-8]`) are skipped too, so `vmt_508_adc_0(self,text,&result)` is found for `MOV EDX,..; MOV EAX,..; LEA ECX,..; MOV EBX,[EBP-8]; MOV EBX,[EBX]; CALL [EBX+0x508]` (test `test_vcall_args_base_register_loaded_from_a_local_after_the_arguments`). (3) `server/vcallnames.py` (hook `_vcall_names` in `tools/core.py`, after `annotate_calls`): the C names the slot after each stub: `vmt_508_adc_0/*TFormMain vslot 310 -> FUN_004280b0*/(...)`; slot N is the numbering of the hints (Delphi: offset / 4, FPC: offset / 4 - 12), the class comes from Self (the first parameter of a published, virtual, message, property or event-handler method of one class, also through one `x = param_1;` copy), a class-typed field of it (`*(T *)(self + 0x4a0)`), or an object made in the same function by a call whose first argument is a VMT address (`x = ctor(&PTR_..._0047ad10, ...)`); without a class the comment is `/*vslot N*/`. **[verified]** live on the FPC GUI program (`BtnGoClick`: `/*TFormMain vslot 310 -> FUN_004280b0*/`, a project at collector 11 reopens in 58 s) and the Delphi test program (`vmt_8_adc_2/*vslot 2*/(param_1,local_1c,local_18,local_14,local_10)`: the arguments are in source order). Not done: the class of a global (`DAT_xxx` typed by a constructor store elsewhere) and of a parameter of a plain procedure.
- Binary named by project name: Haiku passed `binary=ohm` (4 errors in t7/t8); the error lists the one binary, but
  with a single binary the tool could just use it.
- Other errors are wrong tool choices: `delphi_classes` on a Qt project, `dotnet_types kind=methods`,
  `xrefs DAT_14026ebc8` (a data name the decompiler prints is not accepted as a target), `function` on a string address.

Files (tasks, launcher, transcripts, source copies) are in the session scratchpad, `agenteval\`.

## Round 7 fixes: names as targets (items 2, 8, 10)

- `vtable` lists Delphi/FPC classes (name, `unit.Class`, VMT, type info or an address inside the slots)
  with the `vslot N` numbering of the function hints and the origin of every slot (`server/classfwd.py`).
- `function Class.Method`, `Unit.Class.Method`, `TClass::vslot N` and IDR/signature names resolve
  (`selectors.alias_functions`, DESIGN 7.3 rule 10); overloads are `error ambiguous` with addresses.
- `xrefs` on a data address searches all ready binaries; `xrefs` / `function` on a Delphi/FPC VMT or type
  info forward to the class. Tests: `tests/test_r7b_names.py`. No cache version key changed.
- Open: a name that exists as IDR name for many functions (short bare names) lists up to 20 candidates;
  the Ghidra-side name is not changed. `tests/test_idr.py` had 2 failing tests from another agent's work in the tree.

## Library names at call sites (round 7 item 6)

`server/libnames.py` + `registry._library_names`: read tools show a unique IDR/sigdb/WARP name instead of `FUN_xxxxxxxx` (display only, see DESIGN). Measured on a Delphi project copy: 153161 -> 72879 `FUN_` tokens in cached C. Tests: `tests/test_libnames.py`. Relabel uses only the hits of the one bound binary (cross-binary output keeps `FUN_`); the budget cut measures the shown text (`budget.DISPLAY`) and cursors keep raw lines; case variants of a name count as one. No version key changed.

## Round 7 fixes: IDR names kept, hexdump, projects, events, ShortStrings (items 1, 9, 11, 12, 13)

- Item 1: `tools/delphi.py::_scope` called `delphi.ensure` without the knowledge base, sigdb and warp folders, so the first `delphi_*` call wrote "no knowledge base configured" and empty hits (and for FPC wiped the vslot names: `delphi_names:<id>` = `none`). Now it passes `ctx.config` folders. "No folder given at all" now means keep: `idr.stale` is false when all three folders are None and a result is stored, and `delphi.ensure` skips the FPC name reload when `sig_dir` is None. **[verified]** on a copy of the round-7 vc project (vc22 had `idr_info` "no knowledge base configured"): `project_open` re-derived it (471 of 532 named), then `delphi_classes` on vc17 and vc22 left all three `idr_info` rows intact. The erased vc22 / gui64 copies had the same cause (a `delphi_*` call on them; `project_open` alone repairs it now). Not reproducible beyond that.
- Item 9: `hexdump` / `file_diff` / `ole_streams` / `record_guess` paths fall back to the stored copy `artifacts/<sha256>` of an analysed binary named by file name or original path (`fileformat._artifact_copy`). **[verified]** `hexdump path=vc22.exe` on the copy with no project root.
- Item 11: `projects.summarize` counts `status:<id>` from the index store when the manifest lists no PE files (was "0 ready/0 queued", now "3 ready/0 queued").
- Item 12: `delphi_events` without form or component lists the events of all forms (`Class Comp.Prop -> ...`), cut to the budget with a cursor; `not_found` only when no form has handlers.
- Item 13: Free Pascal keeps ShortString literals in writable `.data`; the Delphi pass skips writable blocks and refuses identifier-like text, so `'purr'` was not in the index. `worker/ghidra_ops/shortstr.py` adds, to the `strings` extraction of Delphi/FPC programs, the ShortStrings (printable, 3+ chars, no type info record) that an instruction points at and that are in no string data. **COLLECTOR_VERSION 12** (11 added to `STRINGS_ONLY_FROM`); `Indexer.refresh_fixups` re-reads the strings of Delphi/FPC binaries below collector 12 and adds the rows at new addresses. **[verified]** (Ghidra 12.1.4, copy of the 4-program FPC 3.2.2 project, opened through `project_open`): `strings pattern=purr` finds `0x00428218 "purr" <- FUN_00401890`; new rows per program: 5 (t1), 13 (Lazarus), e.g. `Inf`, `Nan`, `Empty`, `default`, `.stab`; none removed.

## Round 8 fixes: argument gaps and targets (N4, N6, N7, N8, N10)

- N4: `delphi_events form=X component=Y` filters inside the form (exact component or action name, case-insensitive, else prefix). Head line `TMainForm events 6 of 457 (component 'actFlush')`. No match: one `error not_found` line with the form's component names. **[verified]** HeidiSQL copy: `form=MainForm component=actFlush` gives the 6 `actFlush*` actions (was 457 events), `component=zzz` lists components.
- N6: `main`, `WinMain`, `wWinMain`, `PASCALMAIN`, `program` resolve in `targets._resolve` (after exact names, aliases and bare methods have found nothing, so a real `main` of an MSVC program wins; other toolchains get no guess) to the program body of a Delphi or FPC binary, with the fact line `resolved 'main' to the program body FUN_00401900 (PASCALMAIN)`. Delphi: the function that holds the PE entry point (`entry`; the program body is inlined there). FPC: the entry point passes `@EntryInformation` to `FPC_EXE_ENTRY` as the last `mov eax, imm32` (x86) or `lea rcx,[rip+d]` (x64) before the call; **field 5** (in pointers) of that record is PASCALMAIN. Several binaries without a binary name: `error ambiguous` with the candidates (the session focus decides first). **[verified]** FPC 3.2.2 copy: t1_32 -> `FUN_00401900`, t1_64 -> `FUN_1000019a0`, gui64 -> `FUN_100002bb0`; Delphi copy: vc22 -> `entry`.
- N7: `hexdump` (and the other path tools through `resolve_path(..., notes)`) with a path that does not exist but whose file name is that of exactly one analysed binary reads `artifacts/<sha256>` and prints `path not found; used the analysed copy of vc22.exe` first.
- N8: `resolve_target` with a function-only tool and an address in an executable block (PE section flags) of one binary that has no function: `targets._create_on_demand` calls the worker op `create_functions` for that address, `Indexer.reextract_code` re-reads functions and edges, the function is returned with the fact line `no Ghidra function at 0x00417190; created one from the code there`. Not done in a clean session or with `allow_writes` off, for a data block, or when Ghidra refuses; the old `not_found` line stays then. The disassembly fallback is built (see the next entry). **[verified]** rpi-imager copy: `function target=0x00417190` -> decompiled `FUN_00417190(this)` calling `FUN_00411540` and `FUN_00416420`, 12.5 s the first time (create + re-read), 0.0 s after.
- N10: `xrefs kind=code` = call + indirect call + import call + jump. A bare method name (`fileOpen`) that is exactly one Qt method (`qt_method`) or published Delphi method (`dl_method`) of the scope resolves to it with `resolved 'fileOpen' to MainWindow::fileOpen` (`targets._bare_method`); several give `error ambiguous` with `Class::name 0xaddr` candidates. `strings` with no pattern lists every defined string (up to 2000, paged by the budget and a cursor); the header reads `strings: N`. **[verified]** DB Browser copy: `xrefs target=fileOpen kind=code` -> `xrefs to FUN_14006f750 ... 42 refs: 11 call, 31 jump`.
- Tests: `tests/test_r8g.py` (11 tests); `tests/test_tools.py::test_strings` now expects the listing for an empty pattern. No cache version key changed.

## Round 8 follow-up: raw disassembly when no function can be made (N8)

- `function` on a code address with no Ghidra function, when `create_functions` is not allowed (clean role, `allow_writes` off) or fails: `core._raw_view` sends the worker op `disassemble` with `raw=true` (`ghidra_ops/disasm.py::disassemble_range`) and prints `// no function at 0x..; disassembly from there to the first RET or unconditional JMP` plus the instructions (same format as view=asm, cut at `RAW_MAX` = 200 with the truncation line). Same for view=c / asm / both; view=signature keeps `not_found`. The run stops at RET / unconditional or computed JMP, before a function entry, a missing instruction or the `airlock_stubs` block. Rows use the shared `_rows` (call overrides to stubs are skipped as in view=asm).
- Existing instructions are read under the read lock. When Ghidra has none there, the bytes are disassembled inside a transaction that is rolled back (nothing is written, the project is not saved).
- Clean role: `function` is not clean-safe and `_raw_view` also returns None for a clean session; data blocks and unreadable addresses keep the `not_found` line. `targets.code_address` is the shared "address in an executable block of one binary" check (also used by `_create_on_demand`).
- **[verified]** rpi-imager copy, `allow_writes` off: `function target=0x00417190` gives 8 instructions up to `JMP 0x00416420  ; -> FUN_00416420` (0.0 s); `0x00417191` starts mid-function the same way. Rollback path: 2123 gap addresses, 826 had no instruction after the trial disassembly (`no_code`, no crash, no state change); no gap address decoded through that path, so a successful decode of undefined bytes is not verified.
- Tests: `tests/test_r8_rawdis.py` (3), `tests/test_worker_ghidra.py::test_disassemble` (raw checks, marker ghidra, not run). No cache version key changed.
- DESIGN tool table: `function`, `xrefs`, `strings`, `vtable`, `delphi_events`, `hexdump` rows brought up to date.

## Round 8 fixes: dynamic method calls, classes of globals and parameters (N2, N3)

- N2: `vcallnames` writes the dynamic index after each call of `@CallDynaInst` / `@CallDynaClass` / `@FindDynaInst` / `@FindDynaClass` (the call is found by its target address, also while the token is still `FUN_xxxxxxxx`; `libnames` renames it later): `System.@CallDynaInst/*0x00406178*/(param_1,L"x",&local_24)/*dynamic -1 -> TBase.Dyn*/;`. The index is the `MOV SI,imm16` / `MOV ESI,imm32` / `MOV RSI,imm32` / `MOV R11,imm` in the 24 bytes before the call (read from the stored copy of the PE; the call address is `ast_node.address`). The class comes from the receiver (first argument); `-> A | B` lists the targets of all possible classes, the class chain is walked (a child without an own entry inherits the parent's). Class unknown: `/*dynamic -1: TBase.Dyn*/` (every method with that index, at most 3, else `/*dynamic -1*/`). **[verify]** the 64-bit register (R11) is a guess: no 64-bit Delphi compiler was available; a load that is not an immediate gives no comment.
- DMT: `delphi._dynamic` reads `vmtDynamicTable` (slot 7 from the self pointer; word count, signed word indexes, pointers) into `dl_method` rows `kind='dynamic'`, `slot` = index, `name` empty; `DELPHI_VERSION` 7 (was 6). `vtable <Delphi class>` ends with `dynamic [-1] 0x0041e15c FUN_...` lines (own entries of that class only; `function <class>` shows them too); `classfwd.dynamic_lines`.
- N3 (a): every `&NAME_xxxxxxxx` that is the VMT of a Delphi/FPC class gets `/*TDog*/` in the C (`FUN_004016d0(&DAT_0042807c/*TDog*/,1,"Rex")`).
- N3 (b): the receiver is resolved flow-sensitive: the nearest earlier store of the variable (a store in a block that is still open is "may not run": unknown, unless there are at least two stores in deeper blocks, e.g. if/else: all of them are listed). `DAT_00430010 = ctor(&TDog...); vcall; DAT_00430010 = ctor(&TCat...); vcall` now gives TDog then TCat (was: no class, two stores). A global that has no earlier store in the function takes the classes of all its stores in the other decompiled functions that reference it (index `global_ref` nodes, at most 40 functions, cached decompile text); one unknown store (not a constructor call, not 0) gives no class.
- N3 (c): a parameter of a plain procedure takes the classes that all callers pass (`ast_node` call rows with that target, at most 10 callers, their cached text; two levels deep). A parameter 0 of a method still uses Self. Several classes: `vmt_0_adc_0/*vslot 0: TDerived.Greet | TBase.Greet*/`; when all classes give one target: `/*vslot 1 -> TBase.Make*/`. Targets use the function name, else the rtti name (`TBase.Greet`), else `FUN_...`.
- **[verified]** local Delphi test program (`UseObj(O: TBase)`, called from the program body with `TDerived.Create` or `TBase.Create`): `vmt_0_adc_0/*vslot 0: TDerived.Greet | TBase.Greet*/`, `vmt_c_ad_0/*vslot 3: TDerived.Name | TBase.Name*/`, `vmt_4_adc_0/*vslot 1 -> TBase.Make*/`, and the dynamic call `/*dynamic -1 -> TBase.Dyn*/`; FPC test program: `vmt_68_a_0/*TDog vslot 14 -> FUN_004017a0*/` and `/*TCat vslot 14 -> ...*/` for the two `Rex` / `Tom` stores to one global. Tests: `tests/test_vcallnames.py`, `test_dynamic_method_table` in `tests/test_delphi.py`.

## Round 8 fixes: interface tables and FPC VMT origins (N1, N9)

- N1: `delphi._delphi_all_interfaces` reads `vmtIntfTable` (the slot after the self pointer) of every Delphi class. 32-bit table: `i32 count`, entries at +4, 28 bytes `{TGUID, IMT ptr, i32 IOffset, i32 ImplGetter}`; 64-bit table: count padded to 8, entries at +8, 40 bytes `{TGUID, IMT ptr, i64 IOffset, i64 ImplGetter}`. The IMT thunks are decoded by `_delphi_thunk`: `ADD EAX,-n` / `ADD [ESP+4],-n` / `ADD RCX,-n` (also SUB) then `JMP rel32|rel8` (target = the class method), or the same then a call through the object's VMT (`PUSH EAX; MOV EAX,[EAX]; MOV EAX,[EAX+d]; XCHG [ESP],EAX; RET`, the stack form `MOV EAX,[ESP+4]; MOV EAX,[EAX]; JMP [EAX+d]`, 64-bit `MOV RAX,[RCX]; JMP [RAX+d]`): the target is the class's own virtual slot d/ps. No adjustment: the entry is the method. The interface name is `KNOWN_GUIDS`, else the `tkInterface` type info (kind 15, found by the GUID, also inside the code section), else the GUID; the all-zero GUID of anonymous-method interfaces gives `intf_<imt>`. Slots 0-2 are `QueryInterface/_AddRef/_Release`; the others take the name of the class method the thunk reaches (published/RTTI/virtual names), else `#k`. The FPC reader (`_fpc_interfaces`) writes the same rows.
- Rows in `dl_method` (no schema change): `interface-tab` (slot = count, addr = table), `interface-table` (slot = index, name `IGreeter {GUID} offset 12 slots 9 type 0x41dbd0`, addr = IMT), `interface` (slot k, name `IGreeter.Greet`, addr = thunk), `interface-target` (slot index*4096+k, addr = target), `header` (slot = pointer slots before the VMT, addr = start of the header). `fnfix.candidates` skips the data kinds (`interface-tab`, `interface-table`, `header`). `DELPHI_VERSION` 8 (was 7): re-derives on the next open.
- `vtable <class>` and `function <class>` end with `interface IGreeter {GUID} imt 0x0041dc5c offset 12 slots 9` and per slot `  [3] 0x0041dbf9 Greet -> 0x0041e03c TBase.Greet` (`server/classintf.py`, called from `classfwd`). `vtable|function|xrefs` on an IMT address, an address inside the IMT (the slot ends with ` <-`), the interface table or the header words before a Delphi VMT (`0x0041dca8` in the d2 task) print a fact line (`0x0041dc5c is the interface method table of IGreeter of Delphi class vc.TBase`, `... is the interface table ...`, `... is in the header before the VMT ...`) and the class's interface listing.
- Interface calls in C (`server/intflabel.py`, called from `vcallnames.annotate`): a receiver is an interface variable when the function passes it to `IntfAddRef/IntfClear/IntfCopy/IntfCast` (aliases like `local_8 = param_1` are followed) or finalizes it with the type info of an interface (`FinalizeArray(&local_c,&DAT_0041dbd0,2)`: that also names the interface; `n` adjacent locals). Label `/*IGreeter.Greet -> TBase.Greet*/` (interface known, or the only interface with a method in that slot; several implementing classes: `-> A.m | B.m`); several candidate interfaces: `/*intf slot 3: IA.m | IB.n*/`; none: `/*intf slot 10*/`; slots 0-2: `/*intf slot 1: _AddRef*/`. Never `vslot`. Not an interface variable: unchanged (`vslot N`). The hook in `annotate` is five lines before the class lookup (`vcallnames.py` belongs to the N2/N3 agent).
- **[verified]** vc22.exe (Delphi 13, 32-bit): `function 0x0041e360` now reads `vmt_c_adc_0/*IGreeter.Greet -> TBase.Greet*/`, `vmt_10_adc_0/*IGreeter.Make -> TBase.Make*/`, `Num`, `Self2`, `vmt_c_adc_0/*IGreeter.Greet -> TBase.Greet*/(local_c,...)` (G2), `Safe`, `Std` (was `vslot 3..8`). `vtable 0x41dc5c`, `vtable 0x41dca8`, `function 0x41dc80` give the TBase listing (were not_found). vc17.exe: same 9 slots. a larger 32-bit Delphi program: all thunks decoded (3 forms found: ADD+JMP, ADD+virtual call, stack form). HeidiSQL 64-bit (2739 classes): 236 entries, 3219 slots, 0 undecoded (interface names from type info: `IFDStanObject`, ...). **[verify]** the 64-bit virtual-call thunk form (`MOV RAX,[RCX]; JMP [RAX+d]`) is a guess; HeidiSQL had only `ADD RCX,-n; JMP` thunks.
- N9: the FPC TObject VMT was read correctly. In t1_32 (FPC 3.2.2, 90 classes) the linker put one shared empty stub (`FPC_EMPTYMETHOD`, a bare `RET`, 0x0040a970) into slots 4-7 of 87 classes (TObject, the RTL exceptions: nothing calls these methods), while the classes of the program (TAnimal, TDog, TCat) carry the four real `TObject.DefaultHandler/AfterConstruction/BeforeDestruction/DefaultHandlerStr` bodies (0x409240, 0x4092b0, 0x4092c0, 0x409250, also bare `RET`s). The compare therefore saw four "overrides". New rows `empty-stub` (slot code is a bare `RET`/`RET n`) and `empty-shared` (that address is held by 3 or more virtual slots) in `delphi._mark_empty`; `classfwd._origin` treats a bare `RET` against a shared empty stub as the same code, `_fpc_name_virtuals` gives such a slot no name of its own. `vtable TAnimal` slots 4-7: `inherited from TObject` (was `override, introduced by TObject`); a class that really overrides with its own empty body (neither address shared) stays `override`.
- Shared stubs: `vtable` marks a slot `empty` (bare `RET`) or `abstract` (function named `*abstract*`, or one address in several different virtual slots: a method is not in two slots); `hints_for` gives a code address that sits in more than one slot number no slot names and one line `shared stub of virtual slots 13, 14, 15, ...: an abstract or empty method; the slots have no common method name`; a single slot gets a name only when every class that uses the code gives the same one. **[verified]** t1_32: `hints 0x40a980` was `TAnimal::vslot 13 (GETBYTECOUNT) (+4 classes); TEncoding::vslot 14 (getBytes)...`, now `TAnimal::vslot 13 (+4 classes); TEncoding::vslot 14 (+3 classes); ...; shared stub of virtual slots 13, 14, 15, 16, 17, 18: ...`. t1_64 shows the same structure (87 classes with the shared stub `0x10000a410`).
- Tests: `tests/test_r8_intf.py` (9: table 32/64-bit, anonymous GUID and unknown thunk, vtable listing, IMT/table/header addresses in vtable/function/xrefs, C comments incl. FinalizeArray and two candidate interfaces), `tests/test_r8_fpcvt.py` (4: stub rows, origins, labels, hints). Version key: `DELPHI_VERSION` 8.

## Next

- Done 2026-11-06 (round 8, N5): FPC `Dialogs.ShowMessage` had no name because the reference programs did not keep
  routines the program never calls (smart-linked LCL). `fpcsigs` now links keep objects (DESIGN 11 "RTL / LCL
  signatures"); sigdb 32/64 rebuilt with the same `fpc-build` command (9913 -> 25977 and 10774 -> 28279 names);
  `IDR_VERSION` 12 (projects recompute names on open). Oracle: wrong rises 0.1-0.4% -> 0.5-1.1% (look-alike
  `Destroy` / `Create` bodies), right within -0.8 / +0.4 points; ShowMessage, NotifyUser, PromptUser,
  TApplication.Run are named. Rebuild old FPC databases with `delphi-sigs fpc-build`. The new wrong matches are removed again by `idr._fpc_disambiguate` (class tables, evidence order, drop of big sets; `IDR_VERSION` 13): wrong 0.17 / 0.19 / 0.11 / 0.36%, right 83.6 / 83.7 / 87.3 / 87.0%.
- Done 2026-11-06 (stub names, sigdb unit rule, Qt recheck): (1) decompiled calls to a concat stub name the real routine
  and its real address (Collector 9 above; live check on a Delphi program: `UStrCatN_probe/*0x0040515c*/(&local_c,3,param_2,local_10,local_8)`,
  pieces intact). (2) DESIGN 11 "Unit rule for short matches": wrong library names 3.80% -> 3.66%, right 83.84% -> 83.86%,
  own routines with a runtime name 23 -> 16; `IDR_VERSION` 11. (3) Qt after the stub filter, on copies of the analysed
  projects: rpi-imager ptr 5/5, slots 21/21, invokables 60/60, signals 14/19, string pairs 26 (5 by call site + 21 guessed by
  order since the Qt5 MinGW change); DB Browser ptr 667 sites, 665 resolved (was 640/604), string 316 + 10 guessed = 326.
  No regression. Left: the unit rule does not help Free Pascal; the oracle programs hold few own routines (9 to 54).
- Qt: a few virtual member-pointer connects stay `vtable+0x..`: the receiver is a field stored by another function (`this->ui->x` set in a separate `setupUi`), the result of a getter that returns a field, or a class whose virtual lives only in another DLL. No open site needs function pointers stored in structs. Statically linked Qt is not scanned.
- Delphi: `delphi-sigs kit` makes a small rebuild kit of an install, `delphi-sigs oracle` is the supported
  oracle measurement (DESIGN §11); the sigdb no longer stores records the matcher drops (import stubs), and a
  `--units` run locks its work folder (a second run on the same folder used to delete the maps of the first).
  Routines under 10 compared bytes are named by the call-context pass only when a named caller exists; the map
  build brings back the FMX / TeeChart / REST-backend units: missing `.fmx` / `.res` / `.dfm` files get empty stubs
  (`delphimega.stub_missing`), `$DENYPACKAGEUNIT` units (WebBroker, ComServ, OleAuto) are built into one console
  program (`m_program`, `delphimega.build(programs=True)`). Left out per build 48 to 62 -> 0 to 2 (only units whose
  own dependency the install lacks: `BDE`, `Vcl.RibbonConsts`, `DUnitX.Windows.Console`). Rebuild old sigdb files to get them.
- WARP is tested on compilers 30, 33, 35 and 36 (no compiler 34 binary was
  available). delphinja has no 64-bit library; build the own one with `warp-build` (it reruns the units build per
  kit, about 2 minutes per kit and bitness; `--map BIN MAP` reuses existing builds). No compiler 36 64-bit program was
  at hand: the 64-bit numbers are for compilers 32 and 35.
- `record_guess` is proven on public sample files (DESIGN §6 `record_guess`).
  OpenPGP packets, `.pol`, delimited text, offset/length tables (ICO,
  TrueType; u16, u32, u64 fields; 1 or 2 entries when they tile the data),
  Java class constant pools and 8-bit / 16-bit sample streams (also noisy) are
  found (`server/recdetect.py`). The table scan and the stride pass are about
  2.5 times faster (large DLL: under 0.5 s on a quiet machine).
  Open: 24-bit PCM, tables whose fields are not adjacent, delimited text
  without line ends.

## Round 9 fix A: worker failures in the decompile cache (P1)

Cause [verified in code]: `index_status` called `resume_project` for every project; the bulk pass of
project B opened B in the worker, `_close_project` set `Entry.closed` on the programs of A, and the
queued functions of A came back as `error` results ("no_program ... was closed") that
`save_decomp_batch` stored; `function` served the stored row. `JVMNotRunning` rows had the same path.
Fixes:
- `index_status` is read-only (`_resolve_project`, no `resume_project`, no worker call).
- `Store.upsert_decomp` and `save_decomp_batch` skip rows whose error is a worker failure
  (`TRANSIENT_DECOMP_ERRORS` in `index/store.py`: no_program, JVMNotRunning, ClosedException, File is closed,
  worker_exited, WorkerError: timeout/busy, worker stopped). Decompiler results (timeout status, bg_timeout) stay.
- Old rows: `get_decomp` treats such a row as a miss and deletes it; `bulk.resume` and the bulk plan call
  `purge_transient_decomp`. No cache version bump.
- The bulk pass counts dropped results and a pass cut by a project switch (`cancelled`, not by the user) and
  queues the binary again (max 3 times, `MAX_REQUEUE`).
- The bulk thread runs only items of the project the session is bound to (`Indexer.current`); others wait,
  so the worker is not switched under a session.
- `function`: `no_program` from the worker is a transient failure (reopen via `ensure_open`, retry once).
- `check_open` message has no instruction text now.
Tests: tests/test_bulk_server.py (round 9 block at the end). No Ghidra run (all paths are server side).

## Round 9 fix B: interface and x64 virtual call labels (P2, P3 C-label part, P5)

- P2: the stored C names the runtime helpers `FUN_xxxxxxxx`; the library names come from the display relabel after
  `vcallnames.annotate`, so `intflabel._HELPER` / `_FINAL` never matched. `DbClasses.helper_names()` gives
  {entry: name} (IDR / sigdb hits plus Ghidra names with `Intf` / `Finalize`); `intflabel.named_helpers` renames the
  `FUN_` calls in the analysis copy of the text. `intflabel._index` now passes an `addr` formatter to `classintf`.
- P3 (C label): `classintf.index` uses `virtual_slot` / `virtual_impls` (shared with the `vtable` listing, group C):
  a thunk that dispatches through VMT slot N lists `vslot N: TBase.Greet | TDerived.Greet`.
- P5: `vcallnames._plain_calls` finds `(**(code **)(*recv + off))(...)` and `(**(code **)*recv)(...)` (64-bit, no stub)
  and labels them like stub calls (FPC slot = off/8 - 12, Delphi slot = off/8; interface receivers use the IMT label).
- Cache keys: none changed (display only).
Tests: tests/test_vcallnames.py `test_plain_x64_virtual_calls_get_a_slot_comment`; tests/test_r8_intf.py
`test_helpers_found_by_address_when_the_text_has_ghidra_names`,
`test_interface_call_through_a_virtual_thunk_names_the_overrides`.
Evidence (copies of the r9dv and r9fpc projects, stored C): vc22 function 0x41e360 now reads
`vmt_c_adc_0/*IGreeter.Greet -> vslot 0: TBase.Greet | TDerived.Greet*/(...)`, `vmt_10_adc_0/*IGreeter.Make -> vslot 1: TBase.Make*/`,
`vmt_20_s_3/*IGreeter.Std -> TBase.Std*/` (before: `/*vslot N*/`). gui64 `BtnGoClick`: `(**(code **)(*local_18 + 0xa10))/*TFormMain vslot 310 -> FUN_10002f480*/(local_18,...)`.

## Round 9 fixes: vtable listing and delphi_events (P3 listing, P6, P7)
- P3: an IMT slot whose thunk dispatches through the VMT (Delphi, target = a virtual slot of the class) reads `[3] 0x0041dbf9 Greet -> vslot 0 (virtual: TBase.Greet; TDerived.Greet)`; `vtable TDerived` lists the inherited interfaces (`interface IGreeter {..} .. inherited from TBase`) with only the dispatching slots, resolved against the child (`Greet -> vslot 0 (virtual: TDerived.Greet)`). Helpers in `server/classintf.py`: `virtual_slot(bd, vmt, thunk_target)` and `virtual_impls(bd, vmt, slot)` (names of the class's code and of the overriding descendants), `parent_chain`. FPC thunks jump to the method and keep the address form. The vslot test is "target address is exactly one virtual slot of the owner" (no new index row, no version key changed).
- P6: `vtable` (and `function` on a class address) print a run of 4 or more inherited slots, in a table of 64 or more slots (small tables keep every slot, so empty/abstract facts stay visible), as `[0-309] inherited from TCustomForm, TObject, .. (+N more), 310 slots`; own (new / override) slots, slots with an RTTI name and the marked slot stay. **[verified]** copy of the r9fpc project: `vtable TFormMain` 30,189 chars (2 binaries, 311 slots each) -> 1,416 chars. The tool still uses `function_budget`.
- P7: `delphi_events component=X` without `form`: exact component/action name, else prefix, else part of the name, over all forms (also with `form`); a non-exact match adds `component 'Flush': no exact name; partial match, 6 events`. `MainForm.actFlush` form prefix accepts the class name without its T. **[verified]** HeidiSQL copy: `component=actFlush` and `component=Flush` list the 6 `actFlush*` actions (was `not_found`).
- Tests: `test_r8_intf.py::test_interface_listing_shows_virtual_dispatch`, `test_inherited_slot_runs_are_one_line`, `test_r8g.py::test_delphi_events_component_without_form`.

## Round 9 fix D: strings retry, search program body, incremental function creation (P4, P8, P9)

- P4: `strings`: a literal pattern that finds nothing and contains a regex character (now also `\`) is retried as a regex
  (`(regex used: no literal match)`); a `regex=true` pattern that finds nothing is retried as literal text
  (`(literal used: no regex match)`, only when the literal finds something). `server/tools/core.py`.
- P9: `search` with `main`, `WinMain`, `wWinMain`, `PASCALMAIN` or `program` adds the line
  `function <body> <addr> (program body: <query>)` for Delphi/FPC programs without a function of that name (same rule as
  the `function` target). Not added when a real function has that name.
- P8: **[verified]** on a copy of the ExifToolGUI project (31k functions): the call creating one function took 41 s, all of
  it `reextract_code` (38.5 s: edges extract about 20 s, `link_edges` 8.7 s, functions extract, `rebuild_fts` 0.5 s).
  `targets._create_on_demand` now calls worker op `extract_at` (function rows of the new function, edge rows from its
  body, body ranges) through `Indexer.extract_new_functions`; `Store.replace_edges_in` replaces the edges that start in the
  body and relinks only edges that start or end there (then `link_fnptr`, `link_string_tables`, `rebuild_fts`). Same
  call after the change: 8.6 s (create, extract, decompile). The edge and function tables were identical
  (md5 of all edge rows with `src_fn`/`dst_fn`, and of all function rows) before and after a full `reextract_code` run.
  Fallback to the full read: `extract_at` fails, finds no function, or `create_functions` changed the calling
  convention of more than one function. No version key changed. Tests: `tests/test_r9d.py`.

## Round 10 fix A: interface index cost, notes in the C header, concat part count (R1, R5, R8a)

- R1: a cached `function` call on a Delphi program with interface tables took 29.2 s (HeidiSQL, 272 `virtual_impls`
  calls, 273 `_owners` full joins). `classintf.index` now passes `owners`, a prebuilt parent->children map and a
  prebuilt `(vmt, slot)` virtual-row map into `virtual_impls` (new `_kids`, `_virtuals`), and memoises the result per
  `(vmt, vslot)`. `classintf.cached_index(bd)` keeps the index in a module cache (6 entries) keyed by index file path and
  binary id; the stamp is (count / max rowid / sum addr of `dl_method`, count + sum of version + crc32 of the names of
  the non-`FUN_` functions), so a re-parse or a rename drops it. `intflabel._index` uses it. **[verified]** same
  `function TMainForm.actFlushExecute` call on a copy of the heidi base: call 1 0.5 s (index build included), call 2
  0.2 s (before 33.0 s and 29.2 s). Tests: `tests/test_r10a_intf_cache.py` (count of owner joins = 1 per index build, no
  class-table query on a cached call, invalidation).
- R5: `vcallnames._params` read the first `(` before the first `{` of the whole C, which is inside the plate comment
  when a note holds `(`. New `vcallnames.skip_comments` / `mask_head`: `annotate` works on the text with the leading
  comments blanked (same length), and inserts into the original. A note can no longer add parameters, aliases or stubs.
  The other C-text parsers (`intflabel`, libnames) get the masked text through `annotate`; `classfwd` and `pascalconv`
  do not parse C text. Test: `test_note_with_parenthesis_keeps_the_receiver_class`.
- R8a: `libnames.concat_parts` (run by `Display`) shows `fpc_ansistr_concat_multi(dst, arr, 3/*4 parts*/, 0)`.
- No version key changed (display and server-side cache only).

## Round 10 fix C: notes of other sessions, session reads during another project's analysis (R6, R7, R8b, R8c)

- R6: notes had `author="agent"` for every session. `ServerContext.author` is now `s-<8 hex>` per process
  (`notes.new_author`), stored by `annotate` and `patch_bytes`. `notes.function_lines` returns (own lines, other lines):
  own notes stay above the code; notes of any other author (old `agent` rows included) go after the code, under one
  header "notes from other sessions (unverified ...)", with date and the author's own confidence (never changed).
  Plate-comment mirror lines now end `(agent note <date>, unverified)`. `search kind=note` lines are unchanged (open point:
  no origin there). The design (DESIGN.md note model) says only "author = session/agent label", so this fits it.
  Not done: the check "a note names a callee the C contradicts". Tests: `test_notes_of_other_sessions_come_after_the_code_marked_unverified`.
- R7: new config key `session_wait_s` (default 120). `Indexer.ensure_open` waits for a running job of another project
  (event wait, 2 s steps), then raises `busy` with "about N s left there, waited W s". The queue (`_run_queue`) yields
  between jobs to waiting sessions and for 30 s after a session that waited (`_yield_needed`, `_waiters`, `_hold`).
  `_get_decompiled` does not retry that busy error (the wait is the retry). Cached C already needed no worker; the
  round-9 P1 rule (bulk pass only for the bound project) is untouched. Tests: `test_session_read_waits_for_other_project_job`,
  `test_queue_yields_to_waiting_session_between_jobs`, `test_function_busy_worker_error_is_not_retried_after_the_wait`.
  Internal callers (bulk, Qt, `refresh_fixups`, `create_missing_functions`) pass `wait_s=0` and never wait
  (`test_internal_callers_never_wait_for_the_worker`). Real Ghidra: a session read waited 31.0 s for the analysis of a
  new project, then returned the C (before: `error busy` after 6.2 s). The yield between 2 jobs was not seen with real
  Ghidra (one-binary project). Open point: a real analysis of one big binary is one job, so the wait can still reach
  `session_wait_s`.
- R8b: `index_status` says "background pass waits until a session opens <project>" (session bound to another project),
  "waiting for analysis" (queue busy), else "about to start".
- R8c: the old count compared the manifest state of the other files with "queued", but the queue starts the first
  (sorted) file at once, so the other file was "importing", not queued. `project_create` now prints the states: `(1 importing, 2 queued)`.
- Version keys: none.

## Round 10 fix B: on-demand creation never damages the project (R2, R3, R4)

- R2: `create_functions` keeps defined data (strings, pointers) that starts at the address unless a call or jump
  reference points there or the caller sets `known_code` (fnfix and the Qt pass do; on-demand calls do not). The
  server refuses a string, the middle of a string or the Delphi string header (12 bytes before it) before it asks
  the worker: `error not_found: no function at 0x..; it is the string "..", referenced from ..`. `xrefs` calls
  `resolve_target(..., create=False)`: a read never writes. In a multi-binary project a string address is a data
  target, not a not_found.
- R3: a trial disassembly that makes no function is undone (instructions and references of the disassembled
  address set). An address with no call reference first looks for the nearest call target before it (at most
  0x4000 bytes, 3 tries, none across a function) and creates that routine; if its body holds the address the answer
  is that routine ("0x.. is inside the code that starts at 0x..; no Ghidra function there, created one from that
  start"), otherwise the trial is removed. Jump references to an address do not make it an entry.
- R4: `fnfix.candidates` adds direct call targets (edge kind `call`, no function, not inside a body).
  `FIX_VERSION` 5 -> 6. After the pass `create_functions` runs Ghidra's `ScalarOperandAnalyzer` over the new
  bodies, so string literals loaded only by new functions get their `data` references.
- Verified on a copy of the TS.exe base (`probe.py` in the round-10 scratch folder): fix pass created 92 of 132
  candidates (98 orphan call targets before); `function 0x004c19f4` and `0x004c1c00` resolve to the writer
  0x004c1984 (6.7 s, then 0.0 s); `function 0x004c1df8`/`0x004c1930` give the string line, no new function;
  `strings Settings` shows `0x004c1df8 "[Settings]" <- FUN_004c1984`; `xrefs 0x004c1d84` shows 1 data ref.
- Tests: `tests/test_r10b.py`. Not run: ExifToolGUI (n6) re-check.

## .NET fix E: dotnet_events and managed resources (P4, P11)

- New tool `dotnet_events` (set dotnet; `server/dotnet_ui.py`, tool in `tools/dotnet.py`). No schema change, no
  DOTNET_VERSION change: rows are read from the stored assembly on demand and kept in memory per file and mtime.
- WinForms: IL of `InitializeComponent` and of every method of types that derive (through the assembly's own types) from
  `System.Windows.Forms.*`. Pattern, read backwards from `callvirt add_<Event>`: `newobj <Delegate>::.ctor`, `ldftn <handler>`,
  target (`ldarg.0`), receiver (`ldarg.0 ldfld <field>`, `ldarg.0` = the form, or `ldloc n` that a later `ldarg.0 ldloc n stfld <field>`
  stores). Caption = `<receiver> ldstr "text" callvirt set_Text`, or `ApplyResources(<receiver>, "name")` / `GetString("x.Text")` read from
  the form `.resources`. **[verified]** KeePass 2.60: 830 events in 1.4 s; the 7 name-guessing calls of kp_menu become one call
  (`component="Generate Password List"`). Lambdas show as `Class::<Method>b__N`.
- WPF: BAML names from the ManifestResource `*.g.resources` entries; XAML from `ilspycmd --resource` (ilspycmd 11; uses `ilspy_run` helpers
  of `tools/dotnet.py`, 6 threads, cached per BAML file). An attribute is an event when it is in a list of known WPF events or names a
  method of the `x:Class` type and ends like an event name. `Command=` is joined to `CommandBinding Executed=` of the same XAML (`{x:Static}`
  and `ApplicationCommands.` prefixes removed); a command with no binding in the XAML prints `-> no CommandBinding in the XAML` (view-model
  commands, `RoutedCommand`s bound in code). **[verified]** Dependencies 1.11.1: 64 rows in 0.5 s; `Properties` -> `OpenUserSettingsCommandBinding_Executed`,
  `OK` -> `OnValidate`.
- `pe_resources` on a managed assembly adds `managed <name> <size> B embedded|linked ...` lines and the entries of `*.g.resources`;
  `type=managed|resources|baml` lists entries (strings with a text preview). Own `.resources` reader (no dnfile resource parse: 1.1 s on KeePass, 3 ms now).
- Open: `xrefs` on a handler does not yet print a `wired:` line; WPF code-behind `Connect` wiring and `ICommand` properties of view
  models are not read; the ICommand join is by XAML text only.

## .NET fix B: how .NET files enter a project (P1, P8, P15, P18, P20)

- **[verified]** Single-file bundles: `projects.bundle_manifest(path)` reads the file table (header versions 1, 2, 6+;
  real v6.0 from `dotnet publish -p:PublishSingleFile` and the ScreenToGif 2.43 bundle, 17 entries in 0.06 s).
  Compressed entries (`csize > 0`) are raw deflate (`zlib.decompress(data, -15)`): **[verify]** on a real
  self-contained+compressed bundle (the offline SDK has no runtime pack); the unit test uses a synthetic one.
- Scan: a bundle host becomes group `apphost` (not in A-D, selectable with `add=`); each `assembly` entry is a virtual
  file `Host.exe!Entry.dll` (managed, sizes from the manifest). Root = the entry named like the host (else the only one
  with a CLI entry point). Framework entries (System.*, Microsoft.*, WindowsBase, ...) are group `runtime`, not parsed.
  `project_create` / `program_add` store each entry as an artifact (`artifact_from_scan`, sha256 of the entry bytes);
  the binary name is the entry file name (`ScreenToGif.dll`), `original_path` keeps `Host.exe!ScreenToGif.dll`,
  `list_binaries` prints `ScreenToGif.dll (in ScreenToGif.exe)`.
  Result (ScreenToGif copy): option A = 5 binaries, all `ready` in 16 s, cross links 1095/0 ... `dotnet_types` works.
- Apphost (no payload, marker with offset 0) + `<stem>.dll` or the dll name patched into the host: root = the managed dll, host
  group `apphost`. ILSpy folder: root `ILSpy.dll` (before: "root unclear: ILSpy.exe, ILSpy.dll"), scan 4 s.
  Named root `host.exe` maps to the app dll. Own assemblies = reached through AssemblyRef names from the root (read on demand,
  only for assemblies that stay core), minus a small list of known NuGet names; roots rank by metadata size when code size is 0.
- R2R: `BinaryInfo.r2r` (ManagedNativeHeader size > 0 and `RTR` at its RVA) => `managed_only`: IL and metadata path only.
  Native R2R code is **not** imported into Ghidra: the IL is complete, the native bodies are compiler output of the same IL
  (r2r_kill spent four calls on stubs), and Ghidra took minutes per assembly. Scan prints `ReadyToRun: N assemblies, ...`.
  A mixed-mode (C++/CLI) image (no ILONLY, no RTR) stays on the Ghidra path.
- NativeAOT: no CLI header + export `DotNetRuntimeDebugHeader` => toolchain `nativeaot` (native path, no metadata); scan line says so.
- `outline` of a `dotnet` binary prints `entry Type::Main 0x06xxxxxx` from the CLI `EntryPointToken` (`entry none` for a library);
  the native entry line stays only for mixed-mode images.
- `normal_module` keeps `.so[.N]` / `.dylib` names. Version keys: none changed (no index schema change).
- Tests: `tests/test_net_entry.py`.
- **[verified]** (real files) R2R: `System.Diagnostics.Process.dll` and `Microsoft.Win32.Registry.dll` 8.0.33 detect as `dotnet`, `r2r`,
  `managed_only`; `project_create` on the dll file (option A) makes both ready in 1.0 s (before 62 s through Ghidra, 2592 functions;
  now 1182 managed functions). The r2r_kill calls `search Kill`, `dotnet_decompile Kill` answer at once from the IL; `function`/`callgraph`
  on `Process::Kill` still say `ambiguous` (two overloads, P19, not this item). NativeAOT: `ilspycmd.exe` 11.2 detects as `nativeaot`, scan prints the
  NativeAOT line (project_create would send it to Ghidra, not run). A framework-named assembly chosen as root keeps its siblings out of group `runtime`.
- **[verified]** Dependencies scan: root `DependenciesGui.exe`; `DependenciesLib.dll` and `ClrPhlib.dll` are `core` (before `third_party`);
  `Dependencies.exe` is `separate_exe`.

## .NET fix D: implementations, fields, native bodies (P5, P7, P10)

- New module `src/airlock/server/dotnet_meta.py` (parse, store, queries); tests `tests/test_dotnet_meta.py` (9 tests: overrides and
  implementations with explicit `MethodImpl` and `newslot`, fields/layout/constants/properties/events, field access scan, the
  `dotnet_types` kinds, two assemblies, `xrefs`/`callgraph` dispatch, field edges, native link, framework enum values).
  Hooks: `dotnet._parse_tables` (`Parsed.meta`, `_Resolver.field_owner` for `Type::Field` labels), `dotnet.ensure`
  (`clear`/`write`), `dotnet.list_lines` (base + interfaces on type lines), `tools/dotnet.py` (kinds `impl field property
  event`), `core.py` (`_describe_addr` field label, `xrefs` notes, `callgraph` children, `_get_decompiled`/`_get_asm`
  forward for native methods), `indexer.bind_native_methods`, worker op `name_functions` (`ghidra_ops/funcs.py`).
- Tables are in `schema.sql`; SCHEMA_VERSION 16, migration `_v16` (test `test_schema_has_meta_tables_and_migration`);
  DOTNET_VERSION was bumped (to 5 by this item, others went on) so every managed binary is parsed again once.
- **[verified]** ClrPhlib.dll run on a copy (project of 2 files, Ghidra 81 s): `function PhLoadMappedImage` now prints the
  native decompile (`ulonglong <Module>::PhLoadMappedImage(longlong param_1, ...)` with the `NtUnmapViewOfSection` call) instead of
  the ilspycmd extern stub; `callgraph` shows `<Module>::PhLoadMappedImage (0x0000000180001220) (native)`.
  Test hint: the worker is started with `python -I`, which ignores PYTHONPATH; a script that tests worktree code against Ghidra
  must start the worker with `-c "import sys; sys.path.insert(0, '<worktree>\\src'); import runpy; runpy.run_module('airlock.worker', run_name='__main__')"`.
- Open: sequential layouts have no offsets; inherited implementations through a base class that implements the interface of
  another assembly are matched by name only; the IL listing does not name enum constants (use `dotnet_types kind=field
  query=<enum>`); `xrefs` takes `Type::Field` (other tools do not).

## Install-time fixes (clean install test)

- `server/tools/admin.py`: a `"` inside a `"` f-string (SyntaxError on Python 3.10 and 3.11) is gone.
  `tests/test_install_fixes.py` parses every `.py` under `src` with `feature_version=(3, 10)`.
- `doctor`: with `ilspycmd` unset it prints `WARN ilspycmd: not set; optional, for .NET; run airlock doctor --fix`.
  `doctor --fix` installs it to `<data_dir>/tools/ilspycmd.exe` (`install_ilspycmd`) and writes the key with
  `config.report.set_value` (same code as `airlock config --set`). Tests use a fake installer.
  `tool_missing` texts in `tools/dotnet.py` now say `run airlock doctor --fix`.
- `doctor` without a config file: one WARN with the fix, no duplicate `config` FAIL, the `ghidra` FAIL says
  `run airlock init --ghidra <path>`; `--fix` says it needs a config first and fixes nothing.
- `parse_jsonc`: `<path>: invalid JSONC at line N column M: <reason>. Fix the file, or run airlock init --force.`
- `airlock serve` (dirty role) without `ghidra_dir` prints one line to stderr and still serves: spec, scan, file
  format and .NET file tools work without Ghidra. `WorkerClient.ensure_ghidra` error names the fix.
- Stale-config WARN shows the count and the fix only. Fix text added to the Ghidra, JDK, network-drive and
  `ghidra_start_failed` messages. Sigdbs cannot be downloaded: doctor names `airlock delphi-sigs build|fpc-build`.
- Bug found by the `--fix` test: `config.edit.set_key` on a one-line config (`{"a": 1}`) wrote broken JSON
  (indent was `{`). Fixed in `_indent_of`.
