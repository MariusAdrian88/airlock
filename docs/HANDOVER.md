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

## Open issues (M1 polish)

1. `COLLECTOR_VERSION` is 2 now: projects analysed before `2335e7f` need
   `analyze(force)` to get the `__EH_prolog` fixup.
2. `function` noise: strip `/* WARNING ... */` lines and collapse local
   declarations into one line (`// 47 locals`).
3. `function` over budget, option 2: an outline (signature, callees,
   strings, switch cases) instead of page 1, then `lines=`.
4. `search` lists EXTERNAL function rows before the useful thunk/import
   hits; hide externals that have a same-named thunk.
5. Named strings with no references (dispatch/automation tables). Needs an
   analyser for those tables (M2, MFC/OLE).
6. Calling convention `unknown` for most functions of a static-CRT MSVC
   binary; not yet investigated whether it affects output quality.
7. `view=asm` / `both` return `not_implemented` (needs a worker op).
8. The edge table has no destination space, so edges into EXTERNAL are
   dropped; import callers are found via thunk or IAT slot.
9. The worker loop is sequential: a long `extract`/`decompile` blocks
   `hello`/`status`. Crash reconciliation is minimal.
10. A user `config.jsonc` with `max_budget` 8000 caps per-call overrides at
    the tool default; raise it to 32000 to use larger overrides.

## Next (M2, DESIGN.md §12)

Read DESIGN.md §12 for the M2 scope; start with the open issues 1–4 above.
