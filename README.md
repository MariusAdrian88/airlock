# airlock

Lean Ghidra MCP server for clean-room reverse engineering: indexed decompilation,
small agent context, dirty/clean spec separation.

> Status: **M0** (skeleton). Only `project_info` is implemented. See
> [docs/DESIGN.md](docs/DESIGN.md) for the design and milestones.

## What it is

- **Light on context.** Few tools, no output schemas, compact text responses
  with a token budget and cursors for more.
- **Index once.** Ghidra analysis and decompilation results go into a local
  SQLite index and are served as function-level slices.
- **Only the Ghidra path is required.** Everything else lives in one global
  `config.jsonc`. No environment variables.
- **Tool sets.** Tools are grouped in sets, enabled per profile; comment out a
  line in the JSONC to drop a tool.
- **Clean room.** A `dirty` profile analyses code and writes specifications;
  a `clean` profile can only read specifications and refuses to start with
  any tool that returns code, addresses or bytes.

Windows-first. Targets: native PE (MSVC/MFC, Qt, Delphi) and .NET.

## Requirements

- Windows x64 (Linux/macOS should work but are not the primary target)
- Python **3.13** (3.10–3.13 work; Ghidra bundles JPype wheels only up to 3.13)
- [Ghidra 12.1.4](https://github.com/NationalSecurityAgency/ghidra/releases)
- JDK 21+ (e.g. Eclipse Temurin 21)

## Install

```powershell
git clone https://github.com/MariusAdrian88/airlock
cd airlock
py -3.13 -m venv .venv
.venv\Scripts\activate
pip install -e .

airlock init --ghidra C:/Tools/ghidra_12.1.4_PUBLIC
airlock doctor --fix      # installs PyGhidra from Ghidra's bundled wheels (offline)
airlock doctor --start    # also starts the worker and Ghidra once
```

`airlock init` writes `%APPDATA%\airlock\config.jsonc`. If `java` is not on
your PATH, set `"jdk_dir"` in that file (e.g. `"C:/Program Files/Eclipse
Adoptium/jdk-21..."`).

## Register with an MCP client

Claude Code:

```powershell
claude mcp add airlock -- C:\path\to\airlock\.venv\Scripts\airlock.exe serve --profile dirty
```

For clean-room work, register a second server with `--profile clean` in a
**separate** session. The clean side only ever sees specifications.

## Configuration

`%APPDATA%\airlock\config.jsonc` (JSONC: comments allowed). The important keys:

```jsonc
{
  "ghidra_dir": "C:/Tools/ghidra_12.1.4_PUBLIC",
  "jdk_dir": null,
  "default_profile": "dirty",
  "profiles": {
    "dirty": { "role": "dirty", "enabled_sets": ["core", "cpp", "resources", "annotate", "admin"], "allow_writes": true },
    "clean": { "role": "clean", "enabled_sets": ["spec_read"] }
  },
  "sets": {
    "annotate": ["rename", "retype", "comment", "annotate", "struct_define"
      // "patch_bytes"
    ]
  }
}
```

The full commented default is in
[src/airlock/config/default_config.jsonc](src/airlock/config/default_config.jsonc).
Data (Ghidra projects, index) lives in `%LOCALAPPDATA%\airlock`. Consider a
Windows Defender exclusion for that folder: real-time scanning slows Ghidra's
project writes considerably.

## Legal

airlock is meant for lawful analysis, in particular interoperability under
EU Directive 2009/24/EC, Article 6. You are responsible for having the right
to analyse the software you load. This is not legal advice.

## License

MIT. Third-party notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
