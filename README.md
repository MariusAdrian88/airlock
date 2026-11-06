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

## Requirements

- Windows x64 (Linux/macOS can work but are not the primary target)
- Python **3.13** (3.10–3.13 work; Ghidra bundles JPype wheels only up to 3.13)
- [Ghidra 12.1.4](https://github.com/NationalSecurityAgency/ghidra/releases)
- JDK 21+ (e.g. Eclipse Temurin 21)

## Install

There are 4 ways to install airlock. All of them need Ghidra, a JDK and the
config file. Pick one:

| Way | Use it when |
|---|---|
| [A. From a clone](#a-from-a-clone) | You want to change the airlock code. |
| [B. uvx, no install](#b-uvx-no-install) | You want no install step. The MCP client starts airlock directly from GitHub. |
| [C. uv tool install](#c-uv-tool-install) | You want a fixed `airlock.exe` on the PATH. The MCP command is then only `airlock serve`. |
| [D. Wheel file](#d-wheel-file) | You install on a machine with no internet, or you give a file to other people. |

**PyGhidra.** PyGhidra is not a dependency of airlock, because its version must
match your Ghidra install. Ghidra bundles the correct wheels (PyGhidra and JPype)
in this folder:

```
<ghidra>/Ghidra/Features/PyGhidra/pypkg/dist
```

Ghidra 12.1.4 has `pyghidra-3.1.0`. If your Ghidra has another version, use that
version in the commands below. Method A and the venv form of method D install
PyGhidra with `airlock doctor --fix`. A uv environment has no `pip`. Methods B and C,
and the uv form of method D, give PyGhidra with `--with` and `--find-links` instead.

**Python.** Use Python 3.13. Ghidra bundles JPype wheels only for Python 3.9 to 3.13.
uv downloads Python 3.13 itself if it is not installed.

The examples use these 2 PowerShell variables:

```powershell
$ghidra = "C:/Tools/ghidra_12.1.4_PUBLIC"
$dist   = "$ghidra/Ghidra/Features/PyGhidra/pypkg/dist"
```

### A. From a clone

```powershell
git clone https://github.com/MariusAdrian88/airlock
cd airlock
py -3.13 -m venv .venv
.venv\Scripts\activate
pip install -e .            # for the tests: pip install -e .[dev]

airlock init --ghidra $ghidra
airlock doctor --fix        # installs PyGhidra from Ghidra's bundled wheels (offline)
airlock doctor --start      # also starts the worker and Ghidra once
```

To update, run `git pull` in the clone. The MCP command is
`C:\path\to\airlock\.venv\Scripts\airlock.exe serve`.

### B. uvx, no install

[uv](https://docs.astral.sh/uv/) runs airlock in a cached environment that it
builds from GitHub. You need no clone and no venv.

```powershell
$src = "git+https://github.com/MariusAdrian88/airlock"

uvx --from $src airlock init --ghidra $ghidra
uvx --python 3.13 --from $src --find-links $dist --with pyghidra==3.1.0 airlock doctor --start
```

The MCP command is the same `uvx` line with `serve` in place of `doctor --start`
(see [Register with an MCP client](#register-with-an-mcp-client)).

- The first start takes about 1 minute, because uv builds the environment. Later starts use the cache.
- Without a commit or tag, uvx uses the newest `main`. To keep one version, add a tag
  or commit to the URL: `git+https://github.com/MariusAdrian88/airlock@v0.1.0`.
- To get the newest `main` again, add `--refresh` to the command one time.

### C. uv tool install

`uv tool install` makes a permanent environment for airlock. It puts `airlock.exe`
in `%USERPROFILE%\.local\bin`. If that folder is not on your PATH, run
`uv tool update-shell` one time.

```powershell
$src = "git+https://github.com/MariusAdrian88/airlock"    # or a wheel file, see D

uv tool install --python 3.13 --find-links $dist --with pyghidra==3.1.0 $src
airlock init --ghidra $ghidra
airlock doctor --start
```

uv remembers the `--with` and `--find-links` options for this tool.

| Task | Command |
|---|---|
| Update to the newest `main` | `uv tool upgrade airlock` |
| Install one fixed version | `uv tool install --force --python 3.13 --find-links $dist --with pyghidra==3.1.0 "$src@v0.1.0"` |
| Also install capstone (for `airlock delphi-sigs build`) | add `--with capstone` to the install command |
| Remove | `uv tool uninstall airlock` |

The MCP command is `airlock serve`. Your configuration and projects stay when you
remove the tool. They are in `%APPDATA%\airlock` and `%LOCALAPPDATA%\airlock`.

### D. Wheel file

A wheel (`airlock-<version>-py3-none-any.whl`) is one file that holds airlock.
It holds no Ghidra and no PyGhidra.

**Get the wheel.** Use one of these sources:

- **From a GitHub release.** Open the [Releases](https://github.com/MariusAdrian88/airlock/releases)
  page and download the `.whl` file. You can also install directly from its URL:
  `https://github.com/MariusAdrian88/airlock/releases/download/v<version>/airlock-<version>-py3-none-any.whl`.
- **Build it yourself** from a clone. The wheel and the source archive (`.tar.gz`) go to `dist\`:

  ```powershell
  uv build              # or: pip install build; python -m build
  ```

**Install it with uv:**

```powershell
uv tool install --python 3.13 --find-links $dist --with pyghidra==3.1.0 .\airlock-0.1.0-py3-none-any.whl
airlock init --ghidra $ghidra
airlock doctor --start
```

**Install it with pip in a venv:**

```powershell
py -3.13 -m venv C:\Tools\airlock-venv
C:\Tools\airlock-venv\Scripts\activate
pip install .\airlock-0.1.0-py3-none-any.whl
airlock init --ghidra $ghidra
airlock doctor --fix
airlock doctor --start
```

The MCP command is then `C:\Tools\airlock-venv\Scripts\airlock.exe serve`.

**Machine with no internet.** airlock needs some packages from PyPI: `mcp`, `json5`,
`pefile`, `olefile`, `dnfile`, and their dependencies. On a machine with internet,
download them all to one folder with the same Python version:

```powershell
pip download --only-binary=:all: -d .\wheels .\airlock-0.1.0-py3-none-any.whl
```

Copy the `wheels` folder and the airlock wheel to the other machine. Then install
with no index:

```powershell
pip install --no-index --find-links .\wheels .\airlock-0.1.0-py3-none-any.whl
airlock doctor --fix        # PyGhidra comes from the Ghidra folder, also offline
```

### After the install

`airlock init` writes `%APPDATA%\airlock\config.jsonc`. If `java` is not on your
PATH, set `"jdk_dir"` in that file (for example `"C:/Program Files/Eclipse
Adoptium/jdk-21..."`). Before you register airlock with a client, make sure that
each line of `airlock doctor --start` shows `[OK   ]`.

### Releases

The GitHub workflow `.github/workflows/release.yml` builds the wheel and the
source archive. To publish a release:

1. Change `__version__` in `src/airlock/__init__.py` (for example `0.1.0`) and commit.
2. Create a tag with the same version and a `v` in front: `git tag v0.1.0`.
3. Push the tag: `git push origin v0.1.0`.

The workflow checks that the tag and `__version__` agree. It runs the tests on
Windows, builds the wheel, and starts `airlock --version` from that wheel. Then
it makes a GitHub release with the 2 files. To build the files without a release,
start the workflow by hand (Actions > release > Run workflow). The workflow then
attaches the files to the run as an artifact.

## Use airlock

1. Register `airlock serve` with each MCP client once (see below).
2. Each session starts unbound. Ask the agent to reverse engineer a folder. The
   agent runs `program_scan` (light scan, options A to D, time estimate), then
   `project_create`. Binaries are analysed in a queue and decompiled in the background.
3. Later sessions: `projects`, then `project_open(name, "dirty" or "clean")`.
   The role stays fixed for the session.
4. Dirty: `overview`, `features`, `feature`, `function_map`, `path`, `search`,
   `strings`, `xrefs`, `callgraph`, `function`, `graph_export`.
5. Dirty writes must have `allow_writes` on: `rename`, `retype`, `comment`,
   `annotate`, `struct_define`. Write specifications with `spec_write`. `spec_export`
   publishes them to `clean\specs\`.
6. Clean: `spec_read`, `spec_list`, `spec_export`. The clean side reads the
   published files only, never the index.

The project folder `<projects_root>\<name>\` holds `dirty\` (analysis data) and
`clean\` (specifications and deny-rule files).

## Tools

The catalog (`src/airlock/config/catalog.py`) lists every tool by set.

| Set | Tools |
|---|---|
| core | `open_binary`, `list_binaries`, `outline`, `search`, `function`, `xrefs`, `callgraph`, `strings` |
| types | `type_inspect`, `type_search` |
| annotate | `rename`, `retype`, `comment`, `annotate`, `struct_define`, `patch_bytes` (writes) |
| cpp | `rtti_classes`, `vtable`, `mfc_message_maps`, `qt_metaobjects` |
| delphi | `delphi_classes`, `delphi_forms`, `delphi_events` |
| dotnet | `dotnet_types`, `dotnet_decompile` |
| resources | `pe_resources`, `dialogs`, `menus`, `string_tables`, `version_info` |
| dataflow | `trace_values`, `switch_tables`, `constants` |
| fileformat | `ole_streams`, `hexdump`, `file_diff`, `record_guess` (no Ghidra) |
| spec_write | `spec_write` |
| spec_read | `spec_read`, `spec_list`, `spec_export` (clean side) |
| map | `overview`, `project_describe`, `features`, `feature`, `feature_define`, `path`, `graph_export` |
| admin | `reindex`, `frontier`, `program_add`, `function_map`, `cluster_label`, `index_status`, `program_scan`, `project_create`, `projects`, `project_open`, `project_info` |

Off by default: sets `delphi` and `dotnet`, and tool `patch_bytes`.
Always on (cannot be disabled): `spec_read`, `spec_list`, `index_status`,
`program_scan`, `project_create`, `projects`, `project_open`, `project_info`.

## Output rules

- Responses are plain text, one item per line. Responses are never JSON.
- Default budget: 2000 tokens (`function`: 10000). A call can pass `budget=`.
  The config key `max_budget` (32000) caps it.
- A capped result ends with a cursor, for example `… 412 more lines. cursor=c_7f3a`.
  Every paged tool gives a real cursor and the real count. A call with only
  `cursor=` continues the stored query. If the call also sets other arguments,
  the cursor keeps its own and one fact line says so.
- Errors are one line: `error <code>: <what happened>.` For example:
  `error not_analysed: binary 'app.exe' is analysing (62%, 41s).`
- Tools do the next step themselves. They retry, widen, follow or forward, and
  report it in one fact line, such as `(regex used: no literal match)`. Where only
  the agent can choose, the tool lists candidates as data. Where only the user can
  act, the error names the fix, such as `allow_writes is off in config.jsonc`.
- `detail=brief` is the default. `detail=full` adds context, such as more callers
  or assembly next to C. `detail=evidence` adds how each fact was found.

## Target forms

Tools that take a target accept these forms:

- **Address:** `0x00401000`, `EXTERNAL:0x1` or a bare hex string. An address inside
  a function resolves to that function, and the answer says so.
- **Name:** an exact name, with its namespace (`CMainFrame::OnFoo`). A name that
  differs only in case resolves in one fact line: `resolved 'x' to X (case differs)`.
- **Ghidra default names** resolve by their address: `DAT_14026ebc8`,
  `PTR_FUN_00401000`, `LAB_0040102c`, `s_text_00402000`.
- **Binary:** `binary!target` (for example `engine.dll!LoadDoc`), `name@binary`, or
  `binary=`. A project with one binary uses it. A project with several binaries
  checks all ready binaries. One hit resolves. Several hits give `error ambiguous`
  with each candidate as `binary!name 0xaddr`. If no binary has the `binary=` name,
  the only binary or the one unique name without its extension is used, with the
  fact line `(binary: X)`.
- **Session focus:** in a multi-binary project, the binary of the last resolved
  function decides an ambiguous name when that binary has exactly one match. The
  answer says `binary X (current binary)`.
- **Imports:** `ReadFile`, `KERNEL32!ReadFile` or `KERNEL32.DLL!ReadFile`. The
  `A` and `W` forms are matched together.
- **Language forms:** Qt `Class::method`, Delphi `TClass.Method`, and MFC handler
  names such as `CMainFrame::OnCommand_<id>_<leaf>`. Tools generate the MFC names for
  handlers that have no name of their own.

## Toolchains and frameworks

- **MSVC C++.** `rtti_classes` and `vtable` read MSVC RTTI and vtables (32 and 64-bit).
- **MFC.** `mfc_message_maps` decodes message maps, dispatch maps, interface maps and
  event sink maps. Classes without RTTI get names from `CRuntimeClass`, the dialog id
  and the inherited class.
- **MFC-like frameworks.** Programs with their own route tables get the same handler
  names. Verified on WinDirStat 2.9.3 (x64).
- **Qt.** `qt_metaobjects` lists signals, slots and properties for Qt 5 and Qt 6
  (32 and 64-bit). Pointer-to-member `connect` calls resolve to `qt_connect` rows
  with their signal and slot. Verified: Qt 6 and Qt 5 with MSVC x64, Qt 5 with MinGW
  32 and 64-bit. Virtual member pointers resolve through the vtable of a known receiver.
- **Delphi.** `delphi_classes` lists classes from the VMT, published methods, fields
  and extended RTTI. `delphi_forms` shows the component tree of a form. `delphi_events`
  maps component events to handlers. Ghidra is not renamed: `function` shows the names
  as hints.
  - RTL and VCL routine names come from four sources, in this order: the exact-version
    signature database, the RTTI consensus database, WARP libraries and the IDR knowledge base.
  - String literals of type UnicodeString, AnsiString and WideString are typed in the
    decompiled C. Concatenated strings list their pieces.
  - `airlock delphi-sigs build <Delphi install folder>` writes exact-version databases
    for compilers 30 to 37, 32-bit and 64-bit. `--units` adds private routines and takes longer.
    `airlock delphi-sigs list` shows the databases. The build needs the install; the
    databases do not. The files come from licensed software: never commit them.
- **.NET.** `dotnet_types` lists types and methods from the metadata. `dotnet_decompile`
  shows C# through ilspycmd (config key `ilspycmd`). Managed-only assemblies skip Ghidra.

## Configuration

`%APPDATA%\airlock\config.jsonc` (JSONC: comments allowed). `airlock init` writes
the commented file with every key. Keys are defined in `src/airlock/config/keys.py`.
Use `airlock config` to show the keys, `airlock config --set KEY VALUE` to change one,
and `airlock config validate` to check the file.

```jsonc
{
  "ghidra_dir": "C:/Tools/ghidra_12.1.4_PUBLIC",
  "jdk_dir": null,
  "allow_writes": true,
  "disabled_sets": ["delphi", "dotnet"],
  "disabled_tools": ["patch_bytes"]
}
```

- Tools are chosen by deny lists, so a new version adds its tools without a change to the file.
- Locations: `ghidra_dir`, `jdk_dir`, `ilspycmd`, `idr_kb_dir` (IDR files),
  `delphi_sigdb_dir` (Delphi signature databases), `warp_dir` (WARP libraries),
  `projects_root`, `index_dir`.
- A project overlay can change single keys.

Data (Ghidra projects, index) lives in `%LOCALAPPDATA%\airlock`. Consider a
Windows Defender exclusion for that folder: real-time scanning slows Ghidra's
project writes considerably.

## Register with an MCP client

Claude Code, from a clone (method A):

```powershell
claude mcp add airlock -- C:\path\to\airlock\.venv\Scripts\airlock.exe serve --profile dirty
```

Claude Code, after `uv tool install` (method C):

```powershell
claude mcp add airlock -- airlock serve --profile dirty
```

OpenCode (`opencode.json`), with uvx (method B):

```jsonc
"mcp": {
  "airlock": {
    "type": "local",
    "command": ["uvx", "--python", "3.13",
                "--from", "git+https://github.com/MariusAdrian88/airlock",
                "--find-links", "C:/Tools/ghidra_12.1.4_PUBLIC/Ghidra/Features/PyGhidra/pypkg/dist",
                "--with", "pyghidra==3.1.0",
                "airlock", "serve", "--profile", "dirty"],
    "enabled": true
  }
}
```

After `uv tool install` (method C), the OpenCode command is only
`["airlock", "serve", "--profile", "dirty"]`.

`--profile` picks the role: `dirty` (the default) or `clean`. For clean-room work,
register a second server with `--profile clean` in a **separate** session. The clean
side only ever sees specifications.

## Development

- Install for development: `pip install -e .[dev]`. Check the install with `airlock doctor --start`.
- Tests: `pytest -q` (1248 passed, 47 skipped). Tests run in parallel, at most 8 workers.
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
