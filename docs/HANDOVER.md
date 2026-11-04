# Handover

Last updated: 2026-11-04, end of M0. Next: **M1**.

## State

M0 is done and checked on the target machine:

```
[OK   ] python: 3.13.17 (D:\1.Development\1.PROJECTS\airlock\.venv\Scripts\python.exe)
[OK   ] ghidra: 12.1.4 at C:\Devopment\ghidra_12.1.4_PUBLIC
[OK   ] jdk: Java 25 from PATH (...\Eclipse Adoptium\jdk-25.0.4.101-hotspot\bin\java.EXE)
[OK   ] pyghidra: 3.1.0 installed
[OK   ] worker: pid 22120, Python 3.13.17, in kill-on-close job
[OK   ] ghidra start: Ghidra 12.1.4, Java 25.0.4.1, 4.71s
```

What exists:

| Area | Files | Notes |
|---|---|---|
| Config | `config/loader.py`, `catalog.py`, `default_config.jsonc` | profiles with `role`, sets, overlays, clean-profile enforcement |
| CLI | `cli.py`, `doctor.py` | `serve`, `init`, `doctor [--fix] [--start]` |
| Server | `server/app.py`, `registry.py`, `tools/admin.py` | `MCPServer` (mcp 2.x); only `project_info` implemented |
| Worker | `worker/main.py`, `client.py`, `protocol.py` | ops `hello`, `start_ghidra`, `shutdown`; sequential request loop |
| Windows | `win/jobobject.py`, `win/drives.py` | kill-on-close job; network-drive check |
| Tests | `tests/` | 19 tests, no Ghidra needed |

Not done in M0 on purpose: index, projects, any analysis.

## Verified facts (Ghidra 12.1.4 source and the run above)

- PyGhidra 3.1.0 is bundled. Public API used so far:
  `pyghidra.launcher.HeadlessPyGhidraLauncher(install_dir=...)`, `.java_home = ...`,
  `.add_vmargs(...)`, `.start()`.
- Available for M1 (from `pyghidra/__init__.py`, not yet exercised):
  `open_project(path, name, create)`, `program_loader()` (returns
  `ghidra.app.util.importer.ProgramLoader.Builder`), `analyze(program, monitor)`,
  `transaction(program, desc)`, `program_context(project, path)`,
  `consume_program(project, path)`, `task_monitor(timeout)`, `walk_programs(...)`.
  `pyghidra.core._setup_project` shows a working import flow using
  `GhidraProject.createProject/openProject/importProgram/saveAs` as an alternative.
- `pyghidra.analyze` runs `AutoAnalysisManager.reAnalyzeAll` + `startAnalysis`
  inside a transaction and marks the program analyzed.
- Parallel decompiler package exists: `ghidra.app.decompiler.parallel`
  (`ParallelDecompiler`, `ChunkingParallelDecompiler`).
- Project locks are OS channel locks on local disks; a dead process's lock
  self-releases. No airlock lock cleanup needed.
- Java 21 is the minimum; Java 25 works.

Still **[verify]** (see DESIGN.md): `Program.getModificationNumber` semantics,
making the parallel decompiler interruptible, MFC/Qt layouts, ilspycmd flags.

## M1 plan

Goal (DESIGN.md §12): on a 32-bit MSVC application, find a file-loading
function by a string and read its decompilation within the token budget.

Tools: `open_binary`, `list_binaries`, `outline`, `search`, `function`,
`xrefs`, `callgraph`, `strings`, `index_status`.

Ask the user which binary to use for the acceptance run (and any DLLs that
belong with it). Use a small binary for fast iteration, e.g. a copy of
`C:\Windows\System32\notepad.exe` (never commit binaries).

### Steps

1. **Index store** (`src/airlock/index/`)
   - `schema.sql` with the M1 subset of DESIGN.md §4: `binary`, `function`,
     `decomp`, `ast_node`, `edge`, `string`, `import`, `fts`, `meta`.
   - `store.py`: open with WAL + foreign keys, `meta.schema_version`, batch
     inserts, simple migration hook. Unit tests without Ghidra.

2. **Projects** (server side, `src/airlock/projects.py`)
   - Layout per DESIGN.md §4 under `config.data_dir\projects\<name>\`.
   - `open_binary`: SHA-256, copy to `artifacts\<sha256>`, register in index.
   - Format/arch/image base/toolchain detection with `pefile` (add dependency).
     Toolchain heuristics: CLI header → dotnet; `TPF0` RCDATA → delphi;
     Qt5Core/Qt6Core imports → qt; MSVC runtime imports or Rich header → msvc.

3. **Worker ops** (`src/airlock/worker/ghidra_ops/`)
   - `open_project`, `import_binary` (artifact path → program in project),
     `analyze` (background thread in the worker, progress events
     `{"event":"progress",...}`; requests on that binary return `not_analysed`
     until done), `save`.
   - `extract` (cheap full pass, batched): functions (entry, name, namespace,
     signature, calling convention, size, thunk/external, name_state from
     `SourceType`), imports, defined strings (with encoding), references
     (call/jump/read/write/data) → edges.
   - `decompile(entry)`: `DecompInterface` with timeout; C text plus
     `ast_node` rows from `getCCodeMarkup()` (calls, string refs, globals,
     each with instruction address). Cache in `decomp` with `fn_version` and
     `analysis_profile`.
   - Worker concurrency: one lock around program access; the analysis thread
     holds it. Keep `hello`/`index_status` answerable while analysis runs.
   - Pointer size and image base always from the program.

4. **Server helpers**
   - `server/budget.py`: token estimate (chars/3.5 code, /4 prose), truncation,
     in-memory cursors keyed by tool + args; `function` cursors as offsets into
     `decomp.c_text`.
   - `server/selectors.py`: DESIGN.md §7.3 rules (0x/space prefix → address;
     exact name incl. namespace; bare hex; ambiguity lists candidates;
     interior address → containing function, said in the output).

5. **Tools** (`server/tools/core.py`, add `index_status` to `admin.py`)
   - Output formats per DESIGN.md §7.4. Keep descriptions to one sentence.
   - `search` uses FTS5 over names, strings, imports.

6. **Tests**
   - Unit: store, selectors, budget/cursors, toolchain detection (on a tiny
     synthetic PE built with `pefile` or a checked-in minimal header blob).
   - Integration (`@pytest.mark.ghidra`, skipped unless `--binary` is given):
     import + analyse + extract + decompile one function + xrefs, via the real
     worker. Add the `--binary` option in `tests/conftest.py`.

7. **Acceptance run** on the binary the user names: `open_binary` → wait for
   `index_status` ready → `strings` / `search` for a file-related string → `xrefs` → `function`
   within 2000 tokens. Record timings (analysis, extract, first decompile) in
   this file.

### Watch out for

- JPype returns Java strings as Python `str` (PyGhidra starts JPype with
  `convertStrings=True`); Java `long` addresses: use `getOffset()` and keep
  ints, never `str(address)` for storage.
- Java exceptions surface as `java.lang.*Exception` Python exceptions; catch in
  ops and turn into `WorkerError` codes.
- Analysis of a large binary can take many minutes; never block an MCP call on
  it. `open_binary` returns `analysing` immediately.
- Windows paths: pass `str(Path)` to Java; Ghidra handles backslashes, but keep
  project names free of characters Ghidra rejects (use the slug of the name).
