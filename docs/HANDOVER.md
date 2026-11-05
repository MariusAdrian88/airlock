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

Tests: `pytest -q` → 925 passed, 42 skipped (~45 s; pytest-xdist, at most 8 workers by default; Ghidra runs with `--binary`/`--xbin` are serial). Ghidra suites:
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

Fixed on 2026-11-05: framework range handlers (tooltips) hidden on control
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
  Open: `ready` still comes before the after-ready work; a client that stops right after `ready` loses the
  cross-binary links and the decompile pass until the next open.
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
  Open: routines the packages do not export. The `.jdbg` files next to the 32-bit packages (`bin\rtl230.jdbg`
  and 314 more; none exist for Win64) hold them. **Not usable yet:** the container is clear (header `JDBG`,
  version 1, offsets of units, source names, symbols, line numbers and words; LEB128 style integers with 32-bit
  wraparound for negatives; symbols are triples of deltas: address, first word, second word; words are `0x01`
  + text xor `0xAA` + `0x00`), but about 97% of the symbol names are not plain words. They are short binary
  records (8 to 20 bytes for a 10 to 25 character name) that look like lists of references into the text of
  other words. I could not decode them without the JCL source or a known pair of name and record, and no
  oracle (a `.map` of the package) exists. Other ways: a `-GD` map of a program that uses every unit (no
  packages needed, gives the private routines of the units it links), or reading the `.dcu` files.
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
  `IDR_VERSION` 5. 32-bit only. Approximate: Binary Ninja's block recovery differs from ours on some functions.

## Qt and dataflow (M8)

Design in DESIGN section 6 and section 11 "Qt metaobjects" (layout facts marked **[verified]**). Facts:

- `server/qt.py` parses `QMetaObject` data from the PE bytes (Qt5 and Qt6 layouts, 32/64-bit); meta `qt_version:<id>` (`QT_VERSION`); `Indexer.resume_project` and `_after_ready` derive it for Qt binaries (toolchain `qt` or `Qt<n>*.dll`).
- Worker op `qt_dispatch` (`worker/ghidra_ops/qt.py`) maps method indices to functions from the decompiled `qt_static_metacall` and finds imported parent classes; run by `qt.resolve` after the missing-function step; meta `qt_dispatch:<id>`. Tool `qt_metaobjects` (`tools/qt.py`); hints in `function`, a `Qt:` line in the project map, moc boilerplate marked runtime family `Qt`.
- Dataflow ops (`worker/ghidra_ops/dataflow.py`) and tools (`tools/dataflow.py`): `switch_tables`, `trace_values`, `constants`. Ghidra tests: `tests/test_dataflow.py` with `-m ghidra --binary=...`.
- Qt6 layout is synthetic-only (no sample authorised). Pointer-to-member connect call sites were not found on the MinGW sample. Not done: Qt seeds for the feature index.

## Next

- `ready` is published before the after-ready work (cross-binary links,
  missing functions, decompile pass). Add a `finishing` state to
  `index_status` so a client knows when that work is done.
- Qt6 metaobject layout is proven only on synthetic data; check it on a
  real Qt6 program. Qt feature seeds and pointer-to-member connects are open.
- Delphi: private routines have no name source (`.jdbg` names use a
  compressed form that is not decoded); property accessors are not named.
- WARP covers compilers 34/35 and older from public libraries; it is not
  tested on a binary of those compilers yet. 64-bit WARP has no library.
- The `fileformat` record detectors (`record_guess` strides and length
  prefixes) are only proven on synthetic files.
