# airlock: instructions for Claude Code

Lean Ghidra MCP server for clean-room reverse engineering of Windows software.
Design: `docs/DESIGN.md` (source of truth). Current state and next steps:
`docs/HANDOVER.md` (read it at the start of a session).

## Environment

- Windows x64, PowerShell. Python 3.13 in `.venv` (activate: `.venv\Scripts\activate`).
- Ghidra 12.1.4 and the JDK are configured in `%APPDATA%\airlock\config.jsonc`.
  Read the paths from there; do not hard-code them and do not add environment
  variables (project rule: configuration lives only in config.jsonc).
- Install: `pip install -e .[dev]`. Tests: `pytest -q`. Ghidra integration tests:
  `pytest -q -m ghidra --binary <path-to-exe>` (see HANDOVER).
- Check the install: `airlock doctor --start`.

## Architecture rules

- Two processes. The MCP server (`src/airlock/server`) never imports pyghidra or
  touches the JVM. All Ghidra API calls live in the worker (`src/airlock/worker`),
  reached through the JSON-lines protocol (`worker/protocol.py`).
- The worker's real stdout is the protocol stream. Never write to it except via
  the protocol; `print()` goes to stderr / `logs\worker.log` and that is fine.
- Ghidra project = source of truth for names, types, comments. SQLite index =
  derived cache plus agent notes and specs. Anything in the index except notes
  and specs must be rebuildable.
- A new tool must be in `config/catalog.py` and registered with `@tool` in a
  module under `server/tools/`, imported in `registry.load_tool_modules()`.

## Output rules (the point of the project: small agent context)

- Tool descriptions: one sentence. No output schemas (`structured_output=False`).
- Responses are compact plain text, one item per line, not JSON. Default budget
  `defaults.token_budget` (2000 tokens); cut and end with
  `… N more lines. cursor=<id>` when longer.
- Errors are one line: `error <code>: <what happened>. <what to do next>.`
- A tool does the next step itself and does not tell the agent what to do: it retries, widens
  or forwards and says so in one fact line; "what to do next" is only data (candidates, a cursor)
  or a fix only the user can make. `tests/test_no_hints.py` enforces it.
- Address formatting: `0x` + lowercase hex, zero-padded to pointer size.

## Clean-room rules

- A profile with `"role": "clean"` may only expose `spec_read`, `spec_list`,
  `spec_export` (catalog flag `clean_safe`). The loader enforces this; keep it so.
- Nothing reachable from a clean profile may return decompiled code, assembly,
  addresses, bytes, notes or `spec_provenance`.

## Working style

- Verify Ghidra/PyGhidra API behaviour by running it (a scratch script in the
  worker, or `python -c` with pyghidra) before building on it. Mark anything not
  verified with **[verify]** in DESIGN.md; replace with **[verified]** once checked.
- Never commit analysed third-party binaries, Ghidra projects or index files.
- Keep `docs/HANDOVER.md` current at the end of a work session: state, what
  was verified, what is next.
- Commit in small steps with clear messages; run `pytest -q` before committing.
