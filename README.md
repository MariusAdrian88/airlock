# airlock

Lean Ghidra MCP server for clean-room reverse engineering: indexed decompilation,
small agent context, dirty/clean spec separation.

> Status: milestones **M1 to M8** are done. Design and output rules:
> [docs/DESIGN.md](docs/DESIGN.md). Current state, test count and next steps:
> [docs/HANDOVER.md](docs/HANDOVER.md).

## What it is

- **Light on context.** Few tools, no output schemas, compact text responses
  with a token budget. A capped result ends with a cursor.
- **Index once.** Ghidra analysis and decompilation results go into a local
  SQLite index and are served as function-level slices.
- **Only the Ghidra path is required.** Everything else lives in one global
  `config.jsonc`. No environment variables.
- **Tool sets.** Tools are grouped in sets. Hide a tool or a set with
  `disabled_tools` or `disabled_sets`.
- **Clean room.** A `dirty` session analyses code and writes specifications.
  A `clean` session exposes only the specification tools.

Windows-first. Targets: native PE (MSVC and MinGW builds of MFC, Qt and Delphi
programs) and .NET.

## Start here

1. [docs/QUICKSTART.md](docs/QUICKSTART.md): install, connect a client, first project, 5 typical tasks.
2. [docs/TOOLS.md](docs/TOOLS.md): every tool, by set (generated from the catalog).
3. [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md): every error code, with cause and fix.

More pages:

- [docs/INSTALL.md](docs/INSTALL.md): requirements, the 4 install ways (clone, uvx, uv tool, wheel file), releases, MCP client setup.
- [docs/REFERENCE.md](docs/REFERENCE.md): sessions, output rules, target forms, frameworks, configuration.
- [docs/DESIGN.md](docs/DESIGN.md): design and rules (source of truth).
- [docs/HANDOVER.md](docs/HANDOVER.md): current state and next steps.

## Install in brief

You need Windows x64, Python 3.13, [Ghidra 12.1.4](https://github.com/NationalSecurityAgency/ghidra/releases)
and JDK 21 or newer. Run in PowerShell:

```powershell
git clone https://github.com/MariusAdrian88/airlock
cd airlock
py -3.13 -m venv .venv
.venv\Scripts\activate
pip install -e .
airlock init --ghidra C:/Tools/ghidra_12.1.4_PUBLIC
airlock doctor --fix
airlock doctor --start
```

Then register the server with your client:

```powershell
claude mcp add airlock -- C:\path\to\airlock\.venv\Scripts\airlock.exe serve --profile dirty
```

Settings live in `%APPDATA%\airlock\config.jsonc` only. There are no environment variables.
Data (Ghidra projects, index) lives in `%LOCALAPPDATA%\airlock`. Consider a Windows Defender
exclusion for that folder: real-time scanning slows Ghidra's project writes considerably.

## Development

- Install for development: `pip install -e .[dev]`. Check the install with `airlock doctor --start`.
- Tests: `pytest -q` (1469 passed, 49 skipped). Tests run in parallel, at most 8 workers.
- Ghidra tests: `pytest -q -m ghidra --binary=<exe>` or `--xbin=<folder>`. They run one at a time.
- A new tool must be in `catalog.py` and registered with `@tool` in a module under
  `src/airlock/server/tools/`. Tool output must not contain hints (`tests/test_no_hints.py`).
- Rules for contributors: [CLAUDE.md](CLAUDE.md) and [docs/DESIGN.md](docs/DESIGN.md).

## Legal

airlock is meant for lawful analysis, in particular interoperability under
EU Directive 2009/24/EC, Article 6. You are responsible for having the right
to analyse the software you load. This is not legal advice.

## License

MIT. Third-party notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
