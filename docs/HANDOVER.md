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

Tests: `pytest -q` → 1136 passed, 47 skipped (~1-3 min; pytest-xdist, at most 8 workers by default; Ghidra runs with `--binary`/`--xbin` are serial). Ghidra suites:
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

1. MFC classes without RTTI are named from `CRuntimeClass`, the dialog id of the constructor and the
   inherited runtime class (DESIGN "MFC classes without RTTI"). Left: a class with none of these stays
   `anon_<map>`; `ctor_dialogs` reads 32-bit constructors only; a derived class that inherits a library
   `CRuntimeClass` is named `anon_<Base>_<map>`, not by its own name.
2. About 27% of visible functions are in `unclassified` clusters (mostly
   unnamed program code); `function_map` prints the coverage line.
3. MFC dispatch, interface and event sink maps are decoded (`mfc_message_maps`, DESIGN "MFC dispatch,
   interface and event sink maps"). Left: the 64-bit `AFX_DISPMAP_ENTRY` layout is not verified on a
   real binary (unit tests only); `AFX_CONNECTIONMAP` (connection points) is not decoded.

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
CWinApp). The 32-bit initialiser form is unverified. Class names stay `anon_<entries>` (no RTTI).
Target tools accept the generated handler names (`Class::OnCommand_<id>_<leaf>`, `targets._mfc_handler_addrs`).
Tests: `tests/test_routes.py`.

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
- Decompile cache folder: `<sha16>-<ilspycmd version>`.
- Mixed-mode Ghidra test: `test_mixed_mode_assembly_through_ghidra` in `tests/test_dotnet.py` (marker
  `ghidra`; run with `-m ghidra --binary=<any file>`; it copies CustomMarshalers.dll from the Framework
  folder to a temp dir).
- `dotnet_version:<id>` meta key (`DOTNET_VERSION`): `Indexer.resume_project` re-parses stale tables.
- ilspycmd 8.2.0.7535 installed under `.venv\dotnet-tools` (gitignored). The config key `ilspycmd`
  points at it; the user's own config is not changed. It runs with `DOTNET_ROLL_FORWARD=LatestMajor`
  set for the child process only (needs .NET 6, the machine has 7 and 8).
- `calli` gets no edge (no static target); `function view=asm` shows its signature. Write tools
  (`rename`, `retype`, `comment`, `struct_define`, rename part of `annotate`) refuse managed methods,
  thunks and external callees with `error managed` before the worker; `annotate` keeps the note and
  appends the refusal line when a rename was also asked (DESIGN §11 ".NET"). Tests use `ilasm.exe`.
- Not done: call sites are the caller token (no IL
  offset); a MemberRef on a derived type that names an inherited method is not matched across assemblies;
  dnfile needs about 6 s for a 6 MB assembly (the dominant cost).
- `dotnet_types` has an extra `kind` parameter (`type|method|pinvoke|com`).

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
- Binary named by project name: Haiku passed `binary=ohm` (4 errors in t7/t8); the error lists the one binary, but
  with a single binary the tool could just use it.
- Other errors are wrong tool choices: `delphi_classes` on a Qt project, `dotnet_types kind=methods`,
  `xrefs DAT_14026ebc8` (a data name the decompiler prints is not accepted as a target), `function` on a string address.

Files (tasks, launcher, transcripts, source copies) are in the session scratchpad, `agenteval\`.

## Next

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
