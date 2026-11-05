# Handover

Last updated: 2026-11-05. M1.5 issues fixed and verified on a fresh analysis
of the acceptance target; M2 (resources, RTTI, vtables, MFC message maps and
the UI join), M3 (annotate) and M4 (specs) are done. Next: **M5**.

## State

M1, M1.5, M3 and M4 are done and pushed to `origin main` (public repository).
Acceptance runs passed on the 32-bit MSVC acceptance target (a multi-binary
program: main executable, own DLLs and plugins). The target is a local
fixture only (gitignored via a generic `tests/fixtures/` rule plus the exact
path in `.git/info/exclude`). Never name it or quote anything from it in
tracked files or commit messages; results live in local memory notes only.

Tests: `pytest -q` → 732 passed, 37 skipped (~2 min). Ghidra suites:
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
| Specs (M4) | `tools/spec.py`, `server/specs.py`, `server/specfilter.py` |
| Targets | `server/targets.py` (shared resolver) |
| Decompile | `server/bulk.py`, `worker/pool.py`, `worker/rwlock.py`, `worker/ghidra_ops/bulk.py` |
| Index | schema v10: `export`, `xedge` (kinds import/dynamic/dynlib), `feature`, `feature_entry`, `string_link` (v6), `spec`/`spec_provenance`/`audit` (v7), `note` keyed by address (v8), `res_dialog`/`res_control`/`res_menu_item`/`res_string` (v9), `rtti_class`/`vtable_slot`/`msgmap_entry` (v10) |

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
6. `patch_bytes` and `qt_metaobjects` are not implemented.
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

## Next

M5 (`fileformat` set, DESIGN.md §12).
