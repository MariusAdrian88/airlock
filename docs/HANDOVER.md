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

Tests: `pytest -q` → 964 passed, 43 skipped (~45 s; pytest-xdist, at most 8 workers by default; Ghidra runs with `--binary`/`--xbin` are serial). Ghidra suites:
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

1. Most MFC message maps in the target belong to classes built without RTTI
   (`anon_<map>`), so handler hints show `FUN_` names.
2. About 27% of visible functions are in `unclassified` clusters (mostly
   unnamed program code); `function_map` prints the coverage line.
3. `xrefs`/`callgraph` return `ambiguous` for same-named functions in several
   binaries (imports aggregate; DESIGN §7.3 rule 8).
4. `path` treats runtime wrappers just before an import as clean through a
   length cap and a CRT plumbing name list (heuristic).
5. Some very large functions hit `decompile_timeout`; `view=asm` still works.
6. `patch_bytes` is not implemented.
7. MFC dispatch/automation (OLE) tables are not decoded.

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
- `fnfix.FIX_VERSION` is 2: `dl_method` and `dl_event` addresses are candidates for `create_functions`.
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
  Open: property accessors (the `GetProc` / `SetProc` code of published properties are not named), unit-level
  procedures and private routines that no table lists, a larger and more varied corpus (the product-count
  rule matters once there are several products per bitness), `rtti-build` has no incremental mode (a new
  corpus rescans everything), and the Ghidra side does not rename anything (hints only).
- Not done: Delphi 2007 and older layout (accepted by the scan, never seen on a real file), published
  properties, dynamic/message method tables, interface tables, virtual method names, renaming.

- WARP names (`server/warp.py`, `worker/ghidra_ops/warp.py`, `tests/test_warp.py`; DESIGN section 11): reads Binary Ninja
  `.warp` libraries (delphinja Delphi RTL) and computes the WARP function GUID from capstone blocks (used by
  `idr._pick`, tier after the RTTI database, before IDR) or from the worker op `warp_blocks` (Ghidra blocks; 81% equal
  to capstone, not used by the pipeline). Config key `warp_dir`; files in `%LOCALAPPDATA%\airlock\warp` (not in the repo).
  `IDR_VERSION` 6. 32-bit only. Approximate: Binary Ninja's block recovery differs from ours on some functions.
  **[verified]** on real programs of compilers 30, 33, 35 and 36 (extended RTTI names as truth): `library_stems` is
  `10.4-only` + `core-11` + `xe2plus-only` from compiler 30 on (before: `core-11` only for 35, which named a third
  as many); `10.4-only` and `xe2plus-only` are about 99% right, `core-11` 87 to 98% (small shapes). WARP names generic
  instances as `TDictionary__2.Add` (RTTI says `TDictionary<K,V>.Add`). `projects.detect` now marks a program
  without forms (console, DLL) as Delphi by its `DVCLAL` resource; before, such a program got no Delphi tiers.

## Qt and dataflow (M8)

Design in DESIGN section 6 and section 11 "Qt metaobjects" (layout facts marked **[verified]**). Facts:

- `server/qt.py` parses `QMetaObject` data from the PE bytes (Qt5 and Qt6 layouts, 32/64-bit); meta `qt_version:<id>` (`QT_VERSION`); `Indexer.resume_project` and `_after_ready` derive it for Qt binaries (toolchain `qt` or `Qt<n>*.dll`).
- Worker op `qt_dispatch` (`worker/ghidra_ops/qt.py`) maps method indices to functions from the decompiled `qt_static_metacall` and finds imported parent classes; run by `qt.resolve` after the missing-function step; meta `qt_dispatch:<id>`. Tool `qt_metaobjects` (`tools/qt.py`); hints in `function`, a `Qt:` line in the project map, moc boilerplate marked runtime family `Qt`.
- Dataflow ops (`worker/ghidra_ops/dataflow.py`) and tools (`tools/dataflow.py`): `switch_tables`, `trace_values`, `constants`. Ghidra tests: `tests/test_dataflow.py` with `-m ghidra --binary=...`.
- Qt6 layout is verified on a real 64-bit MSVC Qt 6.10 desktop client (revision 13; see DESIGN section 11 for each fact). Two parser bugs fixed: with `QT_NO_DATA_RELOCATION` `superdata` is two words `{direct, getter}` (the metaobject starts one pointer before the scan address; parents come from the getter, local or from the import name, no worker needed); Qt6 has no Notify property flag (`notifyId` is -1 or the signal index). `QT_VERSION` 2.
- Pointer-to-member connects work (Qt6 MSVC x64): `qt.fill_imports` adds the C++ imports Ghidra leaves out of the `import` table, `derive_connects` finds the call sites as read edges to the `connectImpl` slot, worker op `qt_connects` (`worker/ghidra_ops/qt.py`, `_Flow`) resolves signal and slot (chases forwarding wrappers up the callers). Rows are `qt_connect` kind `ptr`. `DISPATCH_VERSION` 2. Sites in template instances nobody calls (incremental-link leftovers) stay unresolved. Not tried: Qt5 / MinGW (Itanium) shapes of the call, 32-bit, virtual member pointers.
- Qt feature seeds (`qt.feature_seeds`, `FEATURES_VERSION` 7): slots of QAction / button / dialog signals seed ui-menu / ui-dialog; Qt library class prefixes in `features.API_PREFIX`.
- Scratch tip: `connectImpl` returns `QMetaObject::Connection` by value, so argument 1 is the result pointer (the decompiler also shows the stack arguments shifted).

## Next

- Qt: pointer-to-member connects are only checked on Qt6 / MSVC x64; try Qt5 and MinGW (Itanium
  `_ZN7QObject11connectImpl...` import, different argument order), 32-bit, and `QObject::connect`
  string form through import slots. Unresolved call sites could be chased through function pointers.
- Delphi: property accessors are not named; routines under 10 compared bytes cannot be named by code
  signatures (a call-context pass could); the map build skips the FMX / TeeChart / REST-backend units.
- WARP is tested on compilers 30, 33, 35 and 36 (no compiler 34 binary was
  available). 64-bit WARP has no library: 64-bit relies on extended RTTI and IDR.
- `record_guess` is proven on public sample files (DESIGN §6 `record_guess`).
  Open: OpenPGP-style packets (length width depends on the tag), delimited
  text records, tables under about 20 entries, 8-bit PCM frames.
