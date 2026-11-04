# Handover

Last updated: 2026-11-04, end of M1.5. Next: **M1.5 polish (open issues
1–4), then M2**.

## State

M1 and M1.5 are done and pushed to `origin main` (public repository).
Acceptance runs passed on the 32-bit MSVC acceptance target (a multi-binary
program: main executable, own DLLs and plugins). The target is a local
fixture only (gitignored via a generic `tests/fixtures/` rule plus the exact
path in `.git/info/exclude`). Never name it or quote anything from it in
tracked files or commit messages; results live in local memory notes only.

Tests: `pytest -q` → 460 passed, 30 skipped (~2 min). Ghidra suites:
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
5. Clean: specs only (spec tools are M4; today they return
   `error not_implemented`).

Project folder: `<projects_root>\<name>\` with `airlock-project.jsonc`,
`dirty\{PROJECT.md, work\, airlock_ghidra\, .airlock\}`,
`clean\{PROJECT.md, specs\, deny-rule files}` (DESIGN.md §4).

## Main components (M1.5)

| Area | Files |
|---|---|
| Config (jcodemunch-style) | `config/keys.py` (single source), `template.py` (generated JSONC), `edit.py`, `upgrade.py`, `report.py`, `legacy.py`, `loader.py`, `catalog.py` (sets, `always_on`, `clean_safe`) |
| Sessions | `server/roles.py`, `server/context.py`, `tools/session.py`, `tools/project_create.py` |
| Scan and queue | `server/scan.py`, `server/estimate.py`, `server/indexer.py`, `tools/project.py`, `tools/queue.py` |
| Links | `server/linking.py` (ordinals via pefile, dynamic LoadLibrary/GetProcAddress links, `call_imp` normalisation, relink) |
| Map | `server/features.py`, `server/projectmap.py`, `server/clusters.py`, `server/graph.py`, `server/diagrams.py`, `tools/map.py`, `tools/fmap.py`, `tools/graphtools.py` |
| Decompile | `server/bulk.py`, `worker/pool.py`, `worker/rwlock.py`, `worker/ghidra_ops/bulk.py` |
| Index | schema v5: `export`, `xedge` (kinds import/dynamic/dynlib), `feature`, `feature_entry`, `import.resolved`, `xedge.evidence` |

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
- Analysis time model: about 20 s fixed per binary plus about 120 s per MB
  of code (measured on a 9-binary program; refined per project).

## Open issues

1. Most subsystem clusters stay `unclassified` (runtime MFC/CRT code inside
   plugins). Recognise library functions and label those clusters.
2. The `ui` feature hits the 1500 cap; its count is not faithful. Split
   `ui` (windows, dialogs, menus, drawing) or rank harder.
3. `xrefs`/`callgraph` do not accept `KERNEL32!ReadFile`; only `path` does.
   Use the same endpoint resolver everywhere.
4. Plugins loaded through run-time paths (no string names the DLL) get no
   dynamic link. Calls through function pointers are not in the graph.
5. Calling convention `unknown` for most functions; `__thiscall` not
   detected (`in_ECX[...]` in MFC methods).
6. Outline control section shows nesting levels 0–1 only.
7. Named strings with no references (dispatch/automation tables): M2
   (MFC/OLE analysers).
8. `view=asm`/`both` return `not_implemented`.
9. Spec tools (M4) and annotate tools (M3) are not implemented.
10. The new time estimate is not yet measured on a fresh analysis.

## Working rules for this project

- Sonnet agents execute; the main session briefs, reviews, runs the full
  suite with no agent active, commits and pushes.
- Agents never commit and never run `git stash`/`checkout --`/`reset`.
- Long Ghidra runs: background or `timeout: 600000`, once; read logs
  before a rerun.
- Before each push: scan commit messages and tracked files for target data.

## Next

Open issues 1–4, then M2 (DESIGN.md §12: resources, RTTI/vtables, MFC
message maps).
