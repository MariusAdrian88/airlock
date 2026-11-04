# Handover

Last updated: 2026-11-04, end of M1. Next: **M1 polish, then M2**.

## State

M1 is done. The acceptance run (DESIGN.md §12) passed on the 32-bit MSVC
acceptance target: `open_binary` → `index_status` ready → `strings` for
file-related text → `xrefs` → `function`, every step far below its budget.
The target is a local fixture only (gitignored); do not name it or quote
anything from it in tracked files.

Commits this session:

| Commit | Content |
|---|---|
| `699dfb2` | index store + schema, projects/PE detection, budget + cursors, selectors, worker Ghidra ops |
| `dc9abdf` | indexer (open_binary flow) and the 9 M1 tools |
| `382ebfa` | `function_budget` 10000 (separate from `token_budget` 2000), `max_budget` 32000 |
| `f5a6e65` | `function` page header: `// lines S-E of N, function ~T tokens (budget B)` |
| `2335e7f` | worker: name `__EH_prolog` + set its call fixup after analysis |

Tests: `pytest -q` → 107 passed, 21 skipped. Ghidra suite on a copy of
`C:\Windows\System32\notepad.exe` → 21 passed (~6 min).

| Area | Files |
|---|---|
| Index | `index/schema.sql`, `index/store.py`, `index/migrations/` |
| Projects | `projects.py` (layout, SHA-256 artifacts, `detect` with pefile) |
| Server | `server/indexer.py`, `budget.py`, `selectors.py`, `tools/core.py`, `tools/common.py`, `tools/admin.py` |
| Worker | `worker/ghidra_ops/{session,project,extract,decompile,fixups}.py` |

## How to run

- Ghidra tests: `pytest -q -m ghidra --binary=<exe>`. Use the `=` form:
  with a space pytest takes the exe as a test path and never loads
  `tests/conftest.py`.
- Any Ghidra run can take minutes (notepad: open to ready ~3 min). In an
  agent: Bash `timeout: 600000` or background, run once, read
  `logs\worker.log` before a rerun. Iterate with the fake-worker unit tests.
- Analysed projects can be reused: `open_binary` on the same sha256 is
  idempotent and `analyze` returns `already_analysed`.

## Timings (notepad.exe copy, 853 functions)

JVM start + import 18 s, analysis 168 s, extract 1.2 s, first decompile
0.35 s, cached decompile ~0 s.

## Verified facts (new this session)

- `GhidraProject.importProgram` needs `pathlib.Path`/`java.io.File`;
  `createProject` needs an existing parent directory.
- `DefinedDataIterator.definedStrings` does not exist in 12.1.4; use
  `byDataInstance(program, StringDataInstance.isString)`.
- `pyghidra.analyze()` marks a cancelled analysis as analysed; the worker
  has its own loop.
- Auto-analysis reports no percentage; progress = analyzers done + function
  count.
- `Program.getModificationNumber` is not stable across sessions; the worker
  uses `DomainFile.getLastModifiedTime()`. Not yet checked: does it change
  on GUI edits.
- pefile `fast_load` does not set `RICH_HEADER`; use `parse_rich_header()`.
  Static-CRT MSVC binaries import no runtime DLL, so the Rich header decides.
- Function ID leaves the static-CRT `__EH_prolog` unnamed. The x86win cspec
  `EH_prolog` call fixup works only once `Function.setCallFixup` is set;
  renaming alone changes nothing. See DESIGN.md §11.
- Decompiled size (32-bit MSVC sample): median ~70 tokens, ~1% over 2000,
  largest 8000–30000. Hence `function_budget` 10000.

## Done in M1 polish

- `__EH_prolog` fixup verified through a full fresh analysis of the
  acceptance target: `unaff_EBP` in 30 callers 0 (was 335 in 20).
  `COLLECTOR_VERSION` is 2: projects analysed before `2335e7f` need
  `analyze(force)`.
- `function` `detail=brief` (default): WARNING lines dropped, more than 6
  locals collapsed into one line; `detail=full` = raw. About 10% fewer
  tokens on a large function.
- `function` over budget returns an outline (control skeleton with line
  ranges, callees, strings); a 20000-token function gives ~1100 tokens.
  `outline=false` pages instead.
- `search`: EXTERNAL rows with a thunk/import twin dropped; kind balance
  (functions, imports, strings); IAT name strings dropped; identical
  strings collapsed.

## Open issues

1. Calling convention `unknown` for most functions of a static-CRT MSVC
   binary. Evidence: large MFC methods show `in_ECX[...]` (the `this`
   pointer) everywhere, so `__thiscall` is not detected. Next task.
2. Outline control section shows nesting levels 0–1 only; brace-less
   `if (...) goto` has no range.
3. Profile switching: decided against a runtime tool (it breaks the
   clean-room model, DESIGN.md §9). Proposed for M2: `airlock init
   --client <name>` that writes both registrations, and the role shown in
   `project_info`/server instructions. Waiting for the user's decision.
4. Named strings with no references (dispatch/automation tables). Needs an
   analyser for those tables (M2, MFC/OLE).
5. `view=asm` / `both` return `not_implemented` (needs a worker op).
6. The edge table has no destination space, so edges into EXTERNAL are
   dropped; import callers are found via thunk or IAT slot.
7. The worker loop is sequential: a long `extract`/`decompile` blocks
   `hello`/`status`. Crash reconciliation is minimal.
8. A user `config.jsonc` with `max_budget` 8000 caps per-call overrides at
   the tool default; raise it to 32000 to use larger overrides.
9. `index_status` with more than one project on disk: a caller that polls
   for ` ready:` can match another project's line.

## Next (M2, DESIGN.md §12)

Read DESIGN.md §12 for the M2 scope; start with open issue 1 (thiscall).
