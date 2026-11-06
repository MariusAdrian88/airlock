# airlock: design

Status: draft v0.2 (2026-11-04)
Target: Ghidra 12.1.4 PUBLIC, Windows x64, Python 3.10–3.13 (3.13 recommended)
License: MIT

Statements marked **[verify]** are assumptions that must be checked against
Ghidra 12.1.4 and its bundled PyGhidra before code depends on them.
Statements marked **[verified]** were checked against the Ghidra 12.1.4 source
(tag `Ghidra_12.1.4_build`).

---

## 1. Goals and non-goals

### Goals

1. **Light on the agent's context.** Few tools advertised, no output schemas,
   small default responses, large data behind cursors. An agent should be able
   to work for hours without the server dominating its context window.
2. **Index once, query cheaply.** Ghidra analysis and decompilation are slow;
   results are stored in a local SQLite index and served as symbol-level slices.
3. **Only the Ghidra path is required.** Everything else is optional and set in
   a global `config.jsonc`. No environment variables.
4. **Configurable tool surface.** Tools are grouped in sets; sets are enabled
   per profile and per project; individual tools are disabled by commenting
   them out in the JSONC file.
5. **Clean-room workflow built in.** A dirty profile analyses code and writes
   specifications; a clean profile only reads specifications. The server
   enforces the separation and keeps an audit trail.
6. **Windows-first.** Correct process lifetime, lock recovery and path handling
   on Windows. Linux and macOS should work but are not the primary target.

### Non-goals

- Covering every target type (JavaScript, APK, firmware, pcaps...). Native
  Windows PE binaries plus .NET assemblies and file formats only.
- Debugging or running the target. Static analysis only in v1.
- Replacing the Ghidra GUI. The Ghidra project stays a normal Ghidra project
  that can be opened in the GUI when airlock is not holding it.
- Byte patching as a goal. Available, but off by default.

### Target order

Toolchains in order of implementation: 32-bit MSVC/MFC, then C++/Qt, then
64-bit Delphi with .NET components.

---

## 2. Architecture

```
MCP client (Claude Code, OpenCode, ...)
   │  stdio, MCP
   ▼
airlock server  (CPython, no JVM)
   │  - config, tool registry, budgets, cursors
   │  - SQLite index (read/write)
   │  - non-Ghidra backends: .NET metadata, file formats, PE resources
   │
   │  stdio, JSON lines (internal protocol, §8)
   ▼
airlock worker  (CPython + PyGhidra → JVM)
   - one per active project
   - owns the Ghidra project lock
   - import, analysis, decompilation, Ghidra writes
```

Why two processes:

- A JVM crash, a hung decompile or an out-of-memory error kills the worker,
  not the MCP server. The server reports the failure and restarts the worker.
- The server answers cached queries instantly while the worker is busy with a
  long analysis or a background decompile pass.
- The server starts without a JVM, so tool listing and index-only queries are
  fast.

Why PyGhidra instead of a socket script inside Ghidra (the approach of
IDA-Ghidra-bridge): no GUI, no `analyzeHeadless` script loop, no port
discovery. The worker calls the Ghidra API directly. Handler logic from the
bridge (xrefs, vtables, RTTI, renames) is ported into the worker, with the
32-bit assumptions removed (pointer size comes from the program).

### Package layout

```
airlock/
  cli.py                  # airlock serve | init | doctor (later: close, export-spec)
  config/                 # jsonc loading, keys (single source), generated template, overlays, upgrade
  server/
    app.py                # MCP server, tool registration from enabled sets
    budget.py             # token estimation, truncation, cursors
    selectors.py          # name/address resolution rules (§7.3)
    tools/                # one module per tool set
  index/
    schema.sql
    migrations/
    store.py
  server/fileformat.py    # olefile, hexdump, diff, record guessing
  worker/
    main.py               # PyGhidra entry, request loop
    ghidra_ops/           # functions, decompile, xrefs, types, writes
    analyzers/            # msvc_rtti, mfc, qt, delphi
  backends/
    dotnet.py             # dnfile + ilspycmd
    pe.py                 # pefile: resources, version info, imports
  win/
    jobobject.py          # kill-on-close job object
    drives.py             # network-drive check for the data dir
THIRD_PARTY_NOTICES.md
```

### Dependencies

| Package | Purpose | Notes |
|---|---|---|
| `mcp` | MCP server SDK | official Python SDK, 2.x (`MCPServer`) |
| `json5` | JSONC parsing | comments and trailing commas |
| `pyghidra` | Ghidra in Python | not a pip dependency. Installed offline by `airlock doctor --fix` from `Ghidra\Features\PyGhidra\pypkg\dist`, which holds PyGhidra 3.1.0 and JPype 1.5.2 wheels for CPython 3.9–3.13 **[verified]**. Ghidra lists Python 3.14 as supported, but has no bundled JPype wheel for it, so use 3.13 |
| `pefile` | PE headers, resources, imports | |
| `dnfile` | .NET metadata | pure Python |
| `olefile` | OLE compound files | document formats stored as OLE streams |
| `ilspycmd` | C# decompilation | external executable, optional, configured by path |

---

## 3. Configuration

### Locations

| What | Path |
|---|---|
| Global config | `%APPDATA%\airlock\config.jsonc` |
| Project folders | `projects_root` (default `%USERPROFILE%\airlock-projects`), one folder per program, §4 |
| Machine data (logs, cursors, caches not tied to a project) | `%LOCALAPPDATA%\airlock\` unless `index_dir` is set |
| Project overlay | `<project folder>\airlock-project.jsonc` (the `settings` key) |

`projects_root` must be on a local disk (Ghidra projects on network drives
are unreliable); `doctor` checks it with `win/drives.py`.

`airlock init --ghidra <path>` writes the documented default config.
`airlock doctor` checks every configured path (Ghidra, JDK, ilspycmd), the
Python version against the bundled JPype wheels, the PyGhidra install, and
write access to the data directory. `--fix` installs PyGhidra from Ghidra's
bundled wheels and upgrades an old config file (see "Versions and upgrade");
`--start` also launches the worker and the JVM.

### Resolution order

Built-in defaults (`config/keys.py`) -> global `config.jsonc` -> project
overlay. Keys present in a later layer win; keys absent fall through. Every
setting is a top-level key. Dicts merge key by key, lists and scalars replace,
and `null` in a later layer removes the key, so the built-in default applies
again (for the location keys, `null` means "not set").

### Keys and the generated file

`config/keys.py` is the one source: for every key it holds the name, type,
range or allowed values, default, group, what it does and when to change it.
`config/template.py` generates the shipped file from it: a section header
(`// === Locations ===`), then per key a comment block (what, `Allowed:`,
`Default:`, `Change it:`) and the key line. Keys that most users never change
ship commented out and show their default (`// "mermaid": false,`); remove the
`//` to override. A few keys ship active: `config_version`, `ghidra_dir`,
`disabled_sets`, `disabled_tools`. `airlock config` reads its descriptions
back from the generated text, and tests check that the template documents
every key, once, with the right default.

Keys: `config_version`; locations `ghidra_dir`, `jdk_dir`, `ilspycmd`,
`index_dir`, `projects_root`; response size `token_budget`, `function_budget`,
`max_budget`, `detail`; decompiler `decompile_timeout_s`, `decompile_timeout_max_s`, `bulk_decompile`,
`bulk_decompile_timeout_s`, `decompile_cpu_min`, `decompile_cpu_max`;
analysis `analysis_timeout_min`, `analysis_s_per_code_mb`, `jvm_max_memory`;
`mermaid`, `mirror_notes_to_ghidra`; tools `allow_writes`, `disabled_sets`,
`disabled_tools`.

### Tool selection

Tools are chosen by a deny list. Every tool in the catalog (`config/catalog.py`,
which also groups tools into sets) is shown unless it is named in
`disabled_tools` or its set is named in `disabled_sets`. A tool added in a new
version therefore appears without any change to the user's file. The template
lists every tool and set, one per line with its description; a line that
starts with `//` is shown, a line without it is hidden.

Rules:

- `disabled_sets` defaults to `delphi` and `dotnet`, `disabled_tools` to
  `patch_bytes`.
- `allow_writes: false` removes `annotate` tools even if the set is shown.
  Writes are never silently refused at call time.
- The role is code-enforced, not configured. `airlock serve --profile
  dirty|clean` (default `dirty`) picks the role of the tool list. A clean role
  only ever has catalog tools flagged `clean_safe`, never has write tools, and
  `disabled_*` can only remove more (§9).
- Tools flagged `always_on` in the catalog cannot be disabled. The loader
  ignores such an entry (directly or through its set) and warns
  `config: <tool> is always on and cannot be disabled (ignored)`; `airlock
  config validate` and `doctor` show it. The template lists them in an
  "always on" comment, not as candidates. Table in §9.
- A name in `disabled_tools` or `disabled_sets` that is not in the catalog is
  reported by `doctor` and at startup (logged, not fatal).
- Unknown keys are reported, not fatal: `unknown key 'token_budjet' (ignored);
  did you mean 'token_budget'?` A wrong type or range is an error that names
  the key and the allowed values.
- A project overlay can change single keys, for example `disabled_sets`.

### Versions and upgrade

`config_version` (integer, missing means 0) says which layout the file has;
the built-in version is `CONFIG_VERSION`. At server start, and in `airlock
doctor`, a lower file version gives a warning:
`config: version 0 < 1; N tools/keys missing (...) - run airlock config upgrade`.

`airlock config upgrade [--dry-run]` edits the file in place and never deletes
or reorders what the user wrote:

- A key that is neither active nor commented out in the user's file is new:
  it is added before the closing brace with its comment block, marked
  `// added in config_version N`. Commented out means removed on purpose and
  is never touched.
- An old file with `defaults`, `profiles` or `sets` (allow lists) is migrated:
  values that differ from the default become top-level keys; tools or sets
  that the old file did not expose, although the old default file did, go into
  `disabled_tools` and `disabled_sets`; the old blocks stay as comments behind
  `// replaced by disabled_tools in config_version N`.
- `config_version` is set, `config.jsonc.bak` is written first, and the result
  must parse and resolve (otherwise nothing is written). `--dry-run` prints a
  unified diff. `doctor --fix` runs the same upgrade.

### The `airlock config` command

| Command | Effect |
|---|---|
| `airlock config` | every key: value in effect, default, source (`built-in`, `global file`, `project overlay`), one line each |
| `airlock config --set KEY VALUE` | validates and converts the value, writes it into the file keeping comments, re-reads the file and restores it if the result is invalid |
| `airlock config --unset KEY` | comments the key out again with its default |
| `airlock config validate` | types and ranges, unknown keys with a suggestion; exit code 1 on errors |
| `airlock config upgrade [--dry-run]` | see "Versions and upgrade" |


### Runtime set switching

Not in v1. Tool-list-changed notifications are not refreshed reliably by every
MCP client, so the config file and profile are the supported way to choose
tools. Revisit later.

### No runtime role switching

There is no tool to switch between the dirty and the clean role. A switch
cannot remove what the agent context already holds, so dirty → clean would
fake a clean session and clean → dirty would contaminate one. Every session
starts unbound; `project_open(name, role)` (or a successful `project_create`)
binds the process to one project and one role for the rest of its life, and
any later call returns `error role_locked: ...`. A restart starts a new
unbound session, so clean work must begin in a new conversation. `airlock
serve` is registered once per MCP client, with no flags; `--profile` stays as
an optional restriction for scripted use (a mismatching role returns
`error wrong_role: this server was started with --profile X`).

---

## 4. Storage

### Layout

A project is a **program** (an installation folder with executables, DLLs,
plugins and data files), not a single file. Each project is one folder under
`projects_root`, with one subfolder per clean-room role:

```
<projects_root>\<name>\
  airlock-project.jsonc    # marker + manifest: name, source folder, scan
                           #   result, selected option, file list with groups,
                           #   per-project settings overlay
  dirty\                   # analysis side (session opened with project_open(name, "dirty"))
    PROJECT.md             # project map, regenerated by airlock (see "Project map")
    work\                  # the dirty agent's own notes, scratch files, probes
    airlock_ghidra\        # ONE Ghidra project holding every analysed binary
                           #   (Ghidra rejects path elements starting with '.' [verified])
    .airlock\              # airlock-internal; agents use tools, never open these files
      artifacts\           # private copies of the program's files, by sha256
      index.sqlite         # derived index + agent notes + draft specs
      cache\               # ilspycmd output, extracted resources
      logs\
  clean\                   # implementation side (project_open(name, "clean"))
    PROJECT.md             # clean map: purpose + published specs only
    specs\                 # published specs (.md + specs.json), nothing else from dirty
    .claude\settings.json  # deny rules for the sibling dirty folder; opencode.json and
                           #   .codex\config.toml are the equivalents for other clients (§9)
```

- The original program folder is never modified; files are copied into
  `artifacts\` by SHA-256, so a later program version can join the same
  project and be compared.
- `airlock-project.jsonc` is the marker that makes a folder a project folder.
  A folder named `dirty` without the marker is not a project.
- Nothing under `dirty\.airlock\` is ever committed to git. `clean\` can be a
  git repository of the new implementation.

### Project map and feature index

Goal: an agent that opens a project understands the whole program, its
parts and what is already known in one call, and can then work either on the
whole program or on one feature only, without reading everything. Rules:

- One place per kind of data. SQLite and Ghidra stay behind the tools; the
  agent reads text maps and calls tools. `PROJECT.md` says which tool gives
  more detail for each part.
- Every map line carries the identifiers needed for the next call (binary
  name, function name and address, topic), so no line is a dead end.
- The map is regenerated by airlock after every change that affects it
  (import, analysis or extraction finished, notes, renames, spec publish),
  never edited by hand. Its sections have fixed names and order.

**`dirty\PROJECT.md`** (and the `overview` tool, which returns the same map
within the budget; `project_open` returns its first part):

`overview` (the tool only, not `PROJECT.md`) adds a `## Frameworks` section before `## Features` with one line
per framework found in the index: `Delphi (N classes): delphi_classes, delphi_forms, delphi_events`;
`Qt (N classes): qt_metaobjects`; `MFC (N message map entries): mfc_message_maps, dialogs, menus`;
`.NET (N types): dotnet_types, dotnet_decompile`; `C++ RTTI (N classes): rtti_classes, vtable`; `Win32 resources (N dialogs): dialogs, menus, string_tables`
(rows in `dl_class`, `qt_class`, `msgmap_entry`, `dn_type`, `rtti_class`, `res_dialog`). A tool the active profile hides is
marked `off in this profile: ...` with the exact `airlock config --set disabled_sets a,b` (or
`disabled_tools`; `[]` for none left) command that enables it, followed by a server restart (`projectmap.framework_lines`).

1. *Purpose*: one paragraph from the user or the dirty agent
   (`project_describe`), plus program source folder, root executable,
   selected option.
2. *Binaries*: one line each: name, group (core / own_plugin / ...), state,
   code size, functions (named/total), toolchain, one-line role ("main
   program", "plugin: exports the plugin interface", "imaging library").
3. *Relations*: who imports whom across the project with counts
   (`main.exe → engine.dll 42 imports, 3 via LoadLibrary`), plugin interface
   exports, COM/OCX registrations.
4. *Features* (the feature index, below): one line per feature with entry
   points count, coverage and the call to drill in.
5. *Knowledge*: note and spec topic tree with counts and status; recently
   named functions; open questions recorded by the agent.
6. *Frontier*: the top unexplored functions by centrality and evidence
   (same as the `frontier` tool, short).
7. *Where to write*: `dirty\work\` for the agent's own files; notes via
   `annotate`; specs via `spec_write`; never inside `.airlock\`.

**Feature index.** Features are derived automatically and refined by the
agent. Each feature has a stable key, a title, evidence and entry points
(functions with binary, name, address and why they belong):

| Feature (key) | Evidence used to find entry points |
|---|---|
| `file-io` | calls to file APIs (CreateFile/ReadFile/WriteFile, fopen/fread, CFile, mapping), file-dialog filters, file-extension strings, path strings |
| `config` | registry APIs, INI/profile APIs, XML parser imports, config-file names |
| `ui-window`, `ui-controls`, `ui-dialog`, `ui-menu`, `ui-draw`, `ui-input` | `ui-window`: window creation, class registration, window procedures, message loop. `ui-controls`: control text/state and messages (SendMessage, Get/SetWindowText, ShowWindow, CWnd control methods). Dialog, menu, GDI and keyboard/mouse/timer APIs for the others. Generic calls (messages, text get/set, DC select/release, constructors and destructors of MFC classes) are weak seeds: listed, but their callers are not followed. Library code (MFC, CRT) is never a seed. A list over the cap says its true total (at least) and that it is ranked, strong seeds first. Message maps and resources: M2 |
| `network` | socket, WinINet/WinHTTP, serial/COM port APIs |
| `hardware` | DeviceIoControl, port I/O, driver service APIs, HID/USB |
| `plugins` | LoadLibrary/GetProcAddress sites, exported plugin interface, plugin folders |
| `scripting` | script engine imports (VBScript/OLE automation), script file extensions |
| `graphics` | GDI/OpenGL/DirectX imports, image libraries |
| `licensing` | crypto APIs, license/serial strings, time checks |
| `data-format:<ext>` | one per data-file extension found by the scan: functions that reference the extension, its file filters, or read files opened with it |

- Auto-derivation runs after extraction: import categories (a fixed table
  of API name → feature) and string patterns give seed functions; the
  feature's entry points are the seeds plus their callers up to depth 2
  inside the program's own binaries (runtime libraries excluded). Weak
  seeds do not expand. `FEATURES_VERSION` (index meta `features_version`)
  makes a project derived by an older version derive again when opened.
- Coverage per feature: entry points named or annotated / total, specs
  written for its topic. The map shows it, so "reverse engineer the whole
  program" means working through the features until coverage is complete.
- Tools: `features()` lists them (key, title, entry points, coverage);
  `feature(key)` returns the entry points with binary, address, reason and
  the strings/imports that put them there, plus related notes and specs, so
  an agent can reverse engineer only that feature. `feature_define(key,
  title, functions?, topics?)` lets the agent add or refine a feature (for
  example a user-visible function such as "open a project file").
- Notes and specs share the topic tree; a feature key is a topic prefix, so
  the work on one feature is found together.

**Function map (subsystems).** The level between features (behaviour) and
`callgraph` (one function). A flat list of "all connected functions" is not
offered: in a real program nearly every function reaches every other within
a few calls, so it would be the whole program with no structure.

- Clusters are computed from the call graph of the program's own binaries
  (runtime-group binaries, thunks and externals excluded; cross-binary edges
  included): functions that call each other much more than they call the
  rest form one cluster. Algorithm: weighted label propagation or Louvain
  over undirected call edges (pure Python, deterministic seed), with
  very-high-degree utility functions (top 1% by callers) kept out of
  clustering and listed as a `util` group, so they do not glue everything
  into one cluster. Target: seconds for 20,000 functions.
- Each cluster gets a stable id per analysis profile (`C1`, `C2`, … ordered
  by size), a label from the features and import categories of its members
  (`file-io + config`), size (named/total), the 3–5 most central members,
  its links to other clusters (call counts), and the features it serves.
- Recomputed after every binary becomes ready and after renames; agent
  labels (`cluster_label`) survive recomputation by member overlap.
- Runtime code inside program binaries (statically linked MFC/CRT/ATL/STL,
  common in plugin DLLs) is recognised per function by name rules (also
  `FID_conflict:` Function ID hits, `@N`/`___` decorations, `Catch@`/`Unwind@`
  funclets), by recurrence (a plain name present in at least 3 binaries, not
  exported, not agent-named) and by propagation (an unnamed function called
  only from runtime functions). A cluster with at least 60% runtime members
  is labelled `runtime: MFC|CRT|ATL/STL` and hidden, unless it contains
  program evidence (an agent-named function or an exported entry point): it
  then stays visible. A visible cluster with no other label and at least
  30% runtime members is `mixed: MFC+program`. Deterministic; the cache
  version (`ALGO_VERSION`) invalidates stored clusters when the rules change.
- Shown in the project map as section 4b *Subsystems* (top clusters), and
  through the tool `function_map`. Both start with one coverage line with one
  denominator: `coverage: N visible functions (runtime excluded: R in K
  clusters); unclassified U = P% of the N visible functions (misc and util count
  in the total)`. Visible functions are the members of every cluster that is not
  runtime (regular, `misc` and `util`); unclassified are the members of visible
  clusters whose label is `unclassified` (an agent label classifies it). The
  clustering itself is unchanged (`ALGO_VERSION` stays).

**Graph view: paths and export.** Functions, clusters, features, strings and
imports form one graph (call/reference edges from `edge`/`xedge`, membership
from `feature_entry` and clusters). Storage stays in SQLite; a shared graph
module (the one the clusters use) answers graph questions:

- `path(from, to)`: shortest call chains between two points, across
  binaries, one step per line with the call-site address. `from`/`to` are
  functions (`binary!name`, address), an import (`KERNEL32!ReadFile`), a
  string (`"*.cfg"`: every function that references it), a feature key or a
  cluster id (any member). Returns up to `k=3` shortest paths (more by
  cursor), `max_depth=8`; chains that avoid `util` hubs and runtime library
  functions (CRT error-exit helpers, locks, allocators: `graph.runtime_nodes`,
  the same rules as the runtime clusters) are preferred. A chain through a
  hub or a runtime function is returned only when no clean chain exists and is
  marked `[via util]`, `[via runtime]` or `[via util+runtime]`. Runtime wrappers at the end of a
  chain (just before an import or runtime target, e.g. `... -> CFile::Write -> WriteFile`;
  likewise at the start when the source is runtime) are the normal route and count as clean.
  A wrapper is recognised by structure (`graph.wrapper_nodes`): a library-tier function (the
  `runtime_nodes` rules: names, FLIRT/IDR/sigdb `library` state, recurrence, propagation) with one
  distinct callee (call or jump to a function or import, arguments passed through), at most
  `WRAPPER_BYTES` (160 bytes, a stand-in for about 40 instructions: the index keeps sizes only)
  and at most `WRAPPER_FANIN` (4) distinct callers; a chain of such functions counts up to 6 hops.
  The CRT plumbing name list (`_free`, `__lock`, `__amsg_exit`, `__NMSG_WRITE`, ...) stays as a
  last filter, since `free` is a perfect wrapper of an import and still not a route anyone wants.
  Hubs, plumbing and runtime functions in the middle of a chain flag it. A bare name resolves to a function first, then an import,
  then a feature key. Output: header `path A → B, N hops (M more paths:
  cursor=…)`, one step per line `→ [bin] Name 0xentry   call at 0xsite`; a
  call to an import no project binary provides ends in `→ import DLL!Name`.
  Answers questions such as "how does the Open command reach
  ReadFile" or "how does the plugin call back into the executable".
- `graph_export(scope, format)`: `mermaid`, `dot` or `graphml` for a
  binary-relation graph, a cluster graph, one cluster's functions, a feature
  or a `path` result, capped at 150 nodes (the rest summarised in one node).
  For the user to view; agents use the text tools. Written to
  `dirty\diagrams\<name>.<ext>` and the path returned; the response itself
  holds no graph text unless `inline=true`.
- Config `defaults.mermaid` (default `false`): when `true`, airlock also
  writes Mermaid charts after each map update to `dirty\diagrams\`:
  `binaries.md` (who imports whom), `subsystems.md` (clusters and their
  links), `feature-<key>.md` (entry points and their clusters). They are
  separate files, so `PROJECT.md` and tool responses stay compact.
- `fnptr` edges come from references to a function entry and from tables of
  function pointers (>= 3 consecutive pointers). A table must lie in a
  readable, non-executable PE section (`.rdata`, `.data`); the ranges are read
  from the stored PE (`meta data_ranges:<id>`, `linking.record_sections`), and
  without them the section check is skipped. Runtime-library names starting
  with `_` count as CRT only for a known CRT stem (`_malloc`, `__strlen_sse2`,
  `_beginthreadex`); a program's own `_do_work` stays program code.
- `neighbors(node, kinds, depth)` (all edge kinds around any node) is
  deferred to M3/M4, when notes and specs add more node kinds.

**`clean\PROJECT.md`**: project name, purpose paragraph, published specs with
topic, title, version and status. Nothing from code, no addresses, no binary
names.

### Roles

- **Ghidra project = source of truth** for analysis results, names, types,
  comments. Renames and retypes go there because only there do they improve
  the decompilation of other functions.
- **index.sqlite = derived cache plus agent memory.** Everything in it can be
  rebuilt from the Ghidra project except notes and specs, which are backed up
  by `airlock export-spec` and (optionally) mirrored as Ghidra plate comments.

### Identity and analysis profile

- Each binary is copied into `artifacts\` and identified by its SHA-256. The
  copy is what Ghidra imports; the original path is recorded but never read
  again. If the original changes, nothing in the index changes silently; a new
  import is a new binary.
- `analysis_profile` is a hash of: Ghidra version, analyzer options, airlock
  collector version. Every cached row stores the profile it was produced
  under. A mismatch means the row is stale and is recomputed on demand.

### SQLite schema (v1)

WAL mode. Foreign keys on. Addresses stored as integers (offset) plus an
address-space name, so 64-bit addresses and `EXTERNAL:` space work.

```sql
CREATE TABLE binary (
  id            INTEGER PRIMARY KEY,
  sha256        TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  original_path TEXT,
  format        TEXT,          -- pe32 | pe64 | dotnet | ole | other
  arch          TEXT,          -- x86 | x86_64 | ...
  pointer_size  INTEGER,
  image_base    INTEGER,
  toolchain     TEXT,          -- msvc | delphi | fpc | qt | dotnet | unknown (detected)
  toolchain_ver TEXT,
  analysis_profile TEXT,
  imported_at   TEXT,
  analysed_at   TEXT
);

CREATE TABLE function (
  id            INTEGER PRIMARY KEY,
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  space         TEXT NOT NULL DEFAULT 'ram',
  entry         INTEGER NOT NULL,
  name          TEXT NOT NULL,
  name_state    TEXT NOT NULL,  -- auto | library | recovered | user | agent
  namespace     TEXT,
  signature     TEXT,
  calling_conv  TEXT,
  size          INTEGER,
  is_thunk      INTEGER NOT NULL DEFAULT 0,
  is_external   INTEGER NOT NULL DEFAULT 0,
  bytes_hash    TEXT,           -- sha256 of body bytes
  masked_hash   TEXT,           -- operands masked, for similarity
  version       INTEGER NOT NULL DEFAULT 0, -- bumped on any change affecting decompile
  UNIQUE (binary_id, space, entry)
);

CREATE TABLE decomp (
  function_id   INTEGER PRIMARY KEY REFERENCES function(id),
  fn_version    INTEGER NOT NULL,
  analysis_profile TEXT NOT NULL,
  c_text        TEXT,
  status        TEXT NOT NULL,  -- ok | timeout | error
  error         TEXT,
  produced_at   TEXT
);

-- Compact AST: one row per statement/call/reference that tools need.
CREATE TABLE ast_node (
  id            INTEGER PRIMARY KEY,
  function_id   INTEGER NOT NULL REFERENCES function(id),
  kind          TEXT NOT NULL,  -- stmt | call | str_ref | const | global_ref | var
  start_off     INTEGER NOT NULL, -- byte offset in decomp.c_text
  end_off       INTEGER NOT NULL,
  address       INTEGER,        -- instruction address the token came from
  target        INTEGER,        -- callee / referenced address, if any
  text          TEXT            -- short token text (name, literal)
);
CREATE INDEX ast_by_fn ON ast_node(function_id, kind);

CREATE TABLE edge (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  src_fn        INTEGER REFERENCES function(id),
  src_addr      INTEGER NOT NULL,
  dst_fn        INTEGER REFERENCES function(id),
  dst_addr      INTEGER NOT NULL,
  kind          TEXT NOT NULL   -- call | call_ind | jump | read | write | data
);
CREATE INDEX edge_dst ON edge(binary_id, dst_addr, kind);
CREATE INDEX edge_src ON edge(binary_id, src_addr, kind);

-- schema v6: strings tied to functions through data tables. Derived by the link phase from `edge`
-- (no worker data): data slots outside functions that point at a string and at a function entry,
-- within +-2 pointer slots, in a run of >= 3 records with one stride (or two parallel arrays).
-- Rebuilt by link_edges / relink (LINK_VERSION 5); old projects get it on open without re-analysis.
CREATE TABLE string_link (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  string_addr   INTEGER NOT NULL,
  fn_entry      INTEGER NOT NULL,
  table_addr    INTEGER NOT NULL,   -- first slot of the table
  slot_addr     INTEGER NOT NULL,   -- the string pointer slot
  evidence      TEXT NOT NULL DEFAULT ''   -- 'record stride 0x8 2/4' | 'parallel arrays 2/4'
);

CREATE TABLE string (
  id            INTEGER PRIMARY KEY,
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  address       INTEGER NOT NULL,
  encoding      TEXT NOT NULL,  -- ascii | utf16le | delphi_ansi | delphi_unicode
  value         TEXT NOT NULL
);

CREATE TABLE import (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  dll           TEXT,
  name          TEXT,
  ordinal       INTEGER,
  address       INTEGER          -- IAT slot / thunk
);

-- Classes recovered from RTTI / VMTs / metaobjects / .NET metadata.
CREATE TABLE class (
  id            INTEGER PRIMARY KEY,
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  name          TEXT NOT NULL,
  source        TEXT NOT NULL,  -- msvc_rtti | delphi_vmt | qt_meta | dotnet
  vtable        INTEGER,
  parent_id     INTEGER REFERENCES class(id),
  size          INTEGER
);
CREATE TABLE class_method (
  class_id      INTEGER NOT NULL REFERENCES class(id),
  slot          INTEGER,
  name          TEXT,
  function_id   INTEGER REFERENCES function(id),
  kind          TEXT            -- virtual | published | message | signal | slot | handler
);

-- UI resources: dialogs, menus, DFM forms, string tables.
CREATE TABLE ui_element (
  id            INTEGER PRIMARY KEY,
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  source        TEXT NOT NULL,  -- dialog | menu | dfm | stringtable
  container     TEXT,           -- dialog id / form name
  ctrl_id       TEXT,           -- numeric id or component name
  ctrl_class    TEXT,
  caption       TEXT,
  handler_fn    INTEGER REFERENCES function(id), -- via message map / DFM event
  event         TEXT
);

-- Full-text search over names, strings, decompiled text, notes.
CREATE VIRTUAL TABLE fts USING fts5(
  kind, ref_id UNINDEXED, binary_id UNINDEXED, text,
  tokenize = 'unicode61 remove_diacritics 2'
);

-- Agent knowledge (dirty side).
CREATE TABLE note (
  id            INTEGER PRIMARY KEY,
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  space         TEXT NOT NULL DEFAULT 'ram',
  entry         INTEGER NOT NULL,  -- function entry; NOT function.id: function rows are recreated by
                                   -- every re-extraction, notes must survive it (class notes: M2)
  summary       TEXT NOT NULL,
  tags          TEXT NOT NULL DEFAULT '',  -- comma separated
  confidence    TEXT,           -- low | medium | high
  author        TEXT,           -- session/agent label
  created_at    TEXT
);

-- Clean-room specifications (§9).
CREATE TABLE spec (
  id            INTEGER PRIMARY KEY,
  topic         TEXT NOT NULL,  -- e.g. "file-format/document/record-header"
  title         TEXT NOT NULL,
  body          TEXT NOT NULL,  -- prose + data layouts, no code
  status        TEXT NOT NULL,  -- draft | reviewed | final
  version       INTEGER NOT NULL DEFAULT 1,
  author        TEXT,
  created_at    TEXT,
  updated_at    TEXT,
  UNIQUE (topic, version)
);
-- Dirty-only: what each spec entry was derived from.
CREATE TABLE spec_provenance (
  spec_id       INTEGER NOT NULL REFERENCES spec(id),
  binary_id     INTEGER REFERENCES binary(id),
  function_id   INTEGER REFERENCES function(id),
  address       INTEGER,
  method        TEXT            -- decompile | file_diff | resources | observation
);
CREATE TABLE audit (
  id            INTEGER PRIMARY KEY,
  at            TEXT NOT NULL,
  profile       TEXT NOT NULL,
  tool          TEXT NOT NULL,
  args_digest   TEXT,
  result_kind   TEXT,
  detail        TEXT            -- e.g. "topic v3 final" (added in schema v7)
);

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);  -- schema_version, etc.
```

---

## 5. Indexing pipeline

### 5.0 Project creation: light scan, options, queue

The first request to reverse engineer a program, made from any folder that is
not a project folder, goes through `project_create`:

1. **Name.** The server asks the user for the project name (MCP elicitation
   if the client supports it **[verify]** per client; else the tool returns
   `error need_name` and the agent asks the user). The name is slugged.
2. **Light scan** (`program_scan`, server side, `pefile` only, no JVM;
   seconds even for 100+ files). For every file under the given folder (or
   the folder of a given executable):
   - PE files: bitness, code size (sum of executable sections), imports,
     export count, version info (`CompanyName`, `ProductName`), Rich
     header, CLI header (.NET).
   - Other files: counted and sized by extension (data-file candidates for
     the `fileformat` set).
3. **Groups**, decided in this order:
   - `runtime`: known compiler/framework runtimes (`msvcr*`, `msvcp*`,
     `mfc*`, `atl*`, `vcruntime*`, `ucrtbase`, `api-ms-*`, VB/.NET runtimes)
     by name and vendor.
   - `core`: the root executable(s) plus the transitive closure of DLLs they
     import from inside the program folder, if the vendor matches.
   - `own_plugin`: other DLLs/OCXs with the root executable's vendor
     (`CompanyName`), e.g. in plugin folders. They are found only by the
     folder scan, because they are loaded with `LoadLibrary`.
   - `third_party`: DLLs/OCXs with a different vendor, including imported
     ones.
   - `separate_exe`: other executables, drivers and installers in the folder
     (often separate programs; can be larger than the main executable).
   - `system`: DLLs imported but not present in the folder (names only).
   - `data`: non-PE files, by extension.
   The root executable is the one the user named, else the largest non-DLL
   executable in the top folder; the scan report says which and why.
4. **Options table.** Cumulative options with code size and an analysis-time
   estimate, shown to the user before any Ghidra work, for example:

   | Option | Contents | Files | Code | Est. analysis |
   |---|---|---|---|---|
   | A. Core | `core` | 3 | 1.5 MB | ~2 min |
   | B. Core + own plugins | A + `own_plugin` | 9 | 2.8 MB | ~4 min |
   | C. + third party | B + `third_party` | 30 | 9 MB | ~12 min |
   | D. Everything | C + `separate_exe` | 45 | 16 MB | ~21 min |
   | (never by default) | `runtime` (Function ID covers them) | 8 | 2.5 MB | |

   (Illustrative numbers.)

   Each option row also names its largest files. The estimate is
   per binary `analysis_overhead_s` (config, default 6: import, extraction,
   linking) plus `work MB × analysis_s_per_code_mb` (config, default 170).
   Work MB is the estimated function count divided by 9000 functions per MB
   (analysis time follows the function count better than the code size; a
   function-dense plugin was 58% over a pure code-size estimate). The light
   scan estimates the function count in one pass without disassembly: the
   distinct in-code targets of `call rel32` and `push imm32`, pointers into
   code found in data sections, and exports (about 0.1 s per 2 MB of code;
   within about 10% of Ghidra's count on the acceptance binaries). Binaries
   without an estimate use their code MB. The model is refined from the
   project's own measured times as binaries finish, as a blend with the
   prior (rate prior worth 1 work MB, overhead prior worth 2 binaries,
   both bounded), so a single large binary cannot swing it. The table ends with the
   data-file summary and a recommendation (default: B when own plugins
   exist, else A). The user picks an option or adds/removes single files.
5. **Create.** Write the folder structure (§4), the manifest, the deny rules
   in `clean\`, copy the selected files into `artifacts\`, and queue them.
   The response tells the user to open the client in `<project>\dirty` to
   continue; the creating session is not a project session.
6. **Queue.** Binaries are imported and analysed one at a time in priority
   order (`core`, then `own_plugin`, then the rest by size). A binary goes
   `queued`, `importing`, `analysing`, `extracting`, `finishing`, `ready`
   (`error` on failure). `finishing` is the after-ready work: toolchain
   tables, missing functions, Qt dispatch, cross-binary links, feature and
   project-map refresh. `ready` means all index work is done; the background
   decompile pass runs after it and has its own progress. Tools already work
   during `finishing` (they may see partial links or functions, with no
   extra note); a project counts a binary as ready only at `ready`. Older
   projects keep `ready`. A server stop in `finishing` is completed at the
   next open (the refresh steps), without re-analysis. `index_status` shows
   the queue, the current binary, finished times and the remaining estimate;
   a finishing binary has one line `#1 app.exe finishing: functions
   1200/3769` (step: `tables`, `functions d/n`, `Qt dispatch`, `links`,
   `features`). Options can be
   extended later (`program_add`), which re-runs the light scan and queues
   only the new files.
7. **Cross-binary links.** All binaries live in one Ghidra project. After
   import, each program's external library paths are set to the project's
   programs (`ExternalManager.setExternalPath`) so imports resolve to the
   exporting binary **[verify]**; the index adds `edge` rows from an import
   slot to the export's function in the other binary.

`open_binary` stays as the single-file path inside an existing project.

`open_binary(project, path)`:

1. Hash the file, copy to `artifacts\<sha256>`, register in `binary`.
2. Detect format and toolchain with `pefile` (no JVM): PE32/PE32+, CLI header
   (→ .NET), Free Pascal version string (`FPC 3.2.2 [...] for ...`, → `fpc`), Delphi markers (`TPF0` DFM resources, `Borland`/`Embarcadero`
   strings, Delphi RTTI patterns), Qt imports (`Qt5Core.dll`/`Qt6Core.dll`),
   MSVC Rich header / runtime imports.
3. .NET-only assembly (CLI header with the IL-only flag): index with `dnfile` on the server and
   stop. No Ghidra, no queue; the estimate is about 1 s per assembly. Mixed-mode assemblies (CLI
   header, native code) take the Ghidra path and are also indexed with `dnfile`.
4. Native: worker imports into the project and runs auto-analysis. Progress is
   reported through `index_status`. This is the slow step (minutes).
5. Cheap full pass (worker): functions, thunks, imports, strings, xrefs/call
   edges, written to the index in batches.
6. Toolchain analyzers: MSVC RTTI + vtables, MFC message maps, Qt metaobjects,
   Delphi VMT/RTTI + DFM. Each writes `class`, `class_method`, `ui_element`
   and may rename functions (`name_state = recovered`) in the Ghidra project.
7. PE resources (server side, `pefile`): dialogs, menus, string tables,
   version info → `ui_element`.
8. Decompilation:
   - `background` (default): after a binary is `ready`, decompile all its
     non-thunk, non-external, non-runtime functions in parallel and cache them,
     so `function`, feature entry points and full-text search over C are
     instant. Order: feature entry points first, then by call-graph
     centrality, then the rest.
   - `lazy`: only on first `function` request, then cached.
   - **Threads.** N parallel decompilers, each its own `DecompInterface` (one
     native decompiler process each). Nothing is fixed to one machine: the
     worker reads the processors available to its own process at start
     (`os.process_cpu_count()`, which respects CPU affinity and job limits;
     fallback `os.cpu_count()`, then 1) and computes N from the shares
     `decompile_cpu_min` and `decompile_cpu_max` (defaults ½ and ¾, rounded
     down, at least 1). Example only: 16 processors → 8–12, 4 → 2–3, 2 → 1.
     `index_status` and `project_info` show the detected processor count and
     the N in use:
     - ¾ while nothing else runs;
     - ½ while Ghidra auto-analysis of another binary runs or a foreground
       request (`function` on an uncached function, `extract`) is in
       progress; the foreground request is served first by a reserved
       decompiler, never queued behind the background pass;
     - always at least 1, and at most what `jvm_max_memory` allows (each
       decompiler process needs memory; the worker lowers N and logs it if
       decompiles fail with out-of-memory).
   - Implementation **[verified]**: a worker-side pool with one
     `DecompInterface` per thread (`worker/pool.py` Engine, `ghidra_ops/bulk.py`).
     `ParallelDecompiler` / `ChunkingParallelDecompiler` exist, but
     `DecompilerCallback` is an abstract class that PyGhidra cannot subclass;
     with a plain `QCallback` proxy they were no faster (notepad, 473
     functions, 8 threads: 3.3 s and 4.0 s against 3.2 s for own threads,
     sequential 7.0 s) and their thread count is the shared `GThreadPool`
     size, not per call. Own threads follow N between functions: each thread
     checks the current N before taking the next function, a thread above N
     closes its decompiler and parks, a cancel aborts in-flight functions
     through the task monitor (about 0.1 s). The ~50-function chunk is the
     batch size of result events, not a barrier. The Python conversion of a
     result into `ast_node` rows holds the GIL (many small JPype calls) and is
     serialised with one lock: 11 threads 4.0 s unserialised, 2.0 s with the
     lock; flat from 6 threads up. Results are written to the index in
     batches by the server. `index_status` shows `decompiled X/Y, R fn/s,
     threads N of P`.
   - One decompiler of the N is reserved for foreground `decompile`; the
     background pass uses max(1, N-1) threads. N follows the min share while
     a foreground request or an analysis runs (seen: 12 -> 8 on 16
     processors) and the max share otherwise.
   - Thread-safety **[verified]** on Ghidra 12.1.4: decompiling different
     functions of one read-only program from several Python threads, each with
     its own `DecompInterface`, gives output identical to a single decompiler;
     the speed-up (measured, cause not isolated: probably Ghidra's program lock plus the GIL)
     stops at about 6 threads. Writes
     (analysis, link_externals, save, renames) take the per-program write
     lock, which waits for the in-flight functions and blocks new readers.
   - The worker request loop does not block on the pass (§8): `status`,
     `hello`, `cancel_*` and foreground `decompile` answer while a pass or an
     `extract` runs.
9. Each decompile also produces `ast_node` rows from the decompiler's
   `ClangNode` markup tree, so every call or string reference in the C text
   maps to an instruction address.

### Invalidation

| Change | Bumps `function.version` of |
|---|---|
| rename function | the function and its direct callers |
| change signature / calling convention | the function and its direct callers |
| retype a local | the function |
| change a struct / field | every function whose cached decompile text names the struct (`struct_define` on an existing name; uncached functions are decompiled fresh anyway) |
| retype a parameter | the function and its direct callers |
| comment, plate-comment mirror of a note | the function (comments are part of the decompile text) |
| rename a global | functions referencing it |
| `patch_bytes` | the function(s) overlapping the patched range (a function body that changes its flow is not re-created) |

A cached `decomp` row is valid only if `fn_version` and `analysis_profile`
match. Invalid rows are recomputed on next request, not eagerly.

### Large functions (decompile time limits)

The background pass uses `bulk_decompile_timeout_s` (short). A function that
timed out there, or has no row, is decompiled on its first request with an
adaptive limit: `decompile_timeout_s` plus 6 s per KB of code beyond 8 KB,
never above `decompile_timeout_max_s` (default 600). Time grows faster than the
size, so the slope is a rough guide only. If that attempt times out, or fails with a
limit message, one more attempt runs with the instruction limit
(`maxInstructions`) and the message payload limit (`maxPayloadMBytes`)
raised and twice the time (still capped). **[verified]** The simplification
styles `normalize` and `firstpass` give no C text in Ghidra 12.1.4 (the
result is an error), so they are not used as a fallback. A function that
still fails is not an error for `function view=c|both`: the answer is one note
line (`// decompile failed: ... Block listing ...`; also for a decompiler error, not only a timeout) and one line per basic
block built from the disassembly (`0xaddr [N insns] calls A, B; refs "str" ->
JNZ LAB_x`). It is not cached as C; the timeout row stays, so the next request
shows the listing again without a new attempt, and `retry=true` decompiles
again. A decompile that Ghidra ends early with a result ("incomplete") keeps its
text and gets a trailing `// partial decompile` line. Tools that need C (`retype`
excerpt, `dataflow`) still answer `error decompile_timeout`.

The Ghidra project cannot be open in the GUI and the worker at the same time.
`airlock close <project>` releases it; the next tool call reopens it. Changes
made in the GUI are picked up by comparing the project file's last-modified
time (`DomainFile.getLastModifiedTime()`) with the one stored at close, and
marking all decompiles stale if it changed. `Program.getModificationNumber`
is a per-session counter (142498 after an analysis run, 3 on reopening the
same saved file), so it cannot be compared across sessions **[verified]**.

---

## 6. Tool catalog

All tools take `binary` (name or sha256 prefix) where relevant; it may be
omitted when the project has one binary. With several ready binaries,
`search` and `strings` cover all of them (§7.4) and `function`, `xrefs` and
`callgraph` look the target up in all of them (§7.3 rule 6). Default budget is
`defaults.token_budget` (2000) unless stated; `function` uses
`defaults.function_budget` (10000).

### core

| Tool | Parameters | Returns |
|---|---|---|
| `open_binary` | `project`, `path` | binary id, format, toolchain, status (`queued`/`analysing`/`finishing`/`ready`) |
| `list_binaries` | `project?` | one line per binary: id, name, format, arch, toolchain, sha256 prefix, status, then `group=` and `code=` (from the manifest, when known), `fns=` and `links=out/in` (cross-binary edges) |
| `outline` | `binary` | sections, entry points, import DLLs with counts, `exports N`, `imports from project binaries: x.dll 12, …`, function counts by `name_state`, classes count, toolchain. ~300 tokens |
| `search` | `query`, `kind?` (`function`/`string`/`import`/`const`/`class`/`note`/`any`), `limit=20` | ranked hits, one line each: kind, name, address, short context; ranking and dedup in §7.4 |
| `function` | `target`, `view=c` (`c`/`asm`/`both`/`signature`), `lines?` | decompiled C (or asm) with address annotations on calls; truncated to budget with a cursor |
| `xrefs` | `target`, `direction=to` (`to`/`from`), `kind?` (`call`/`read`/`write`/`data`), `limit=50` | one line per reference: from-function, address, kind |
| `callgraph` | `target`, `direction=callees`, `depth=2` | indented tree, names + addresses; cycles marked |
| `strings` | `pattern`, `regex=false`, `with_refs=true`, `limit=30` | string, address, referencing functions |

### types

| Tool | Parameters | Returns |
|---|---|---|
| `type_inspect` | `name` or `address` | struct/union/enum layout: offset, size, type, name |
| `type_search` | `query`, `limit=20` | matching data type paths |

### annotate (requires `allow_writes`)

| Tool | Parameters | Effect |
|---|---|---|
| `rename` | `target`, `new_name`, `kind=function` (`function`/`global`/`label`/`local`), `function?` for locals | Ghidra rename, invalidation (§5), returns new signature |
| `retype` | `function`, `variable`, `type` | sets type, returns refreshed decompile excerpt around uses |
| `comment` | `address`, `text`, `kind=plate` (`plate`/`pre`/`eol`) | Ghidra comment |
| `annotate` | `target`, `summary`, `tags?`, `confidence?`, `new_name?` | atomic: optional rename + note row (+ plate comment if configured) |
| `struct_define` | `name`, `fields` (list of `{offset, type, name}`), `size?` | creates or replaces a struct |
| `patch_bytes` | `address`, `hex`, `why?`, `force=false`, `restore?`, `binary?` | off by default; see below |

Details settled in M3:

- Each write is one worker op: write lock, one Ghidra transaction, program saved before the reply,
  foreground decompiler dropped and `Entry.epoch` bumped so bulk decompilers reopen. The index is
  updated only after the worker answered. `function.name_state` becomes `user`; `function.version` is
  bumped as in §5 (direct callers include `fnptr` callers); the next request recomputes decompile, asm
  and outline lazily, never eagerly.
- `rename` function: `A::B::name` moves the function into that namespace, a bare name keeps it. Global
  and label renames take an address (creates a label when there is none) or an existing global label
  name; they invalidate the referencing functions and the containing function. A local is renamed with
  `target=<name shown in the decompile>` and `function=`.
- `retype` returns the decompile lines that name the variable (at most 12).
- `comment` takes an exact address; a function name means its entry. A plate comment keeps the airlock
  notes block.
- `annotate` stores a note keyed by function entry (any number per function, newest listed first, up to
  5 shown as `// note #id [confidence] summary (tags: ...)` above `function` output). With
  `mirror_notes_to_ghidra` the newest 10 notes are mirrored into the function's plate comment between
  `--- airlock notes ---` and `--- end airlock notes ---` lines, together with the optional rename in one
  transaction; without rename and mirror no Ghidra write happens. `search kind=note` (and `any`) finds
  summary and tags. A failed Ghidra write stores no note.
- `struct_define` fields may not overlap; gaps stay undefined; types are parsed by Ghidra's data type
  parser (`int`, `char *`, structs of the project).
- `patch_bytes` (dirty only: the catalog gives it no `clean_safe`; off by default through
  `disabled_tools`, and `allow_writes` must be on) writes `hex` (1 to 512 bytes) at `address` into
  the Ghidra program memory only, never the original file. One worker op, one transaction, program
  saved before the reply. It refuses uninitialised memory (`error uninitialized`) and a patch that
  cuts an instruction, or whose new bytes do not decode to whole instructions over the old
  instruction range (`error boundary`), unless `force=true`. Instructions in the range are cleared
  and disassembled again (a seed at every undefined gap, restricted to the range); data-only
  ranges are just overwritten. A note (tag `patch`, author `agent`) is written in the same step on
  the containing function, or at the address: `patch 0x… N bytes: old=<hex> new=<hex> [(restore of
  note #M)] [why: text]`. The versions of the functions that overlap the range are bumped (§5), so
  decompile and asm are recomputed. `restore=<note id>` is the unpatch: it reads the note, checks
  that the memory still holds the note's `new` bytes (`error changed` otherwise, `force=true`
  overrides) and writes the `old` bytes back with a new note. Not covered: function boundaries
  (a patched `ret`) and the stored `bytes_hash` of the function are not recomputed.

### cpp

| Tool | Parameters | Returns |
|---|---|---|
| `rtti_classes` | `query?`, `limit=50` | classes from MSVC RTTI: name, vtable, slot count, direct base classes |
| `vtable` | `target` (class name or address; C++ RTTI, Delphi, FPC) | slots: index, address, function name, origin |
| `mfc_message_maps` | `target?` (class) | no class: the classes that have a message map (with the class's dialog) and the dispatch / interface / event sink maps; a class: message, control id, handler function per entry (`as OnCommand_57600_Open` when the function has no name of its own), `// menu "File > Open..."` or `// dialog 101 button "OK"` for the id (a class without a map of its own shows the nearest base class that has one), then its automation maps: `method Name(long, LPCSTR) -> void dispid 2 -> 0x... fn`, `property Name BSTR dispid 5 get 0x... set 0x...`, `stock BackColor dispid -501 long`, `interface IDispatch offset 0x10`, `event dispid 7 ctrl 1000 -> 0x...` |
| `qt_metaobjects` | `class_?`, `limit=50`, `connections=false`, `binary?` | no class: one line per Qt class (parent, signal/slot/property counts, methods mapped); a class: signals, slots, invokable methods and constructors with index, parameter types and names, flags and the function behind each; properties (notify signal), enums, `Q_CLASSINFO`, connections that name its signals or slots. `connections=true`: all string connects and `connectImpl` call sites. Done in M8 |

### delphi

| Tool | Parameters | Returns |
|---|---|---|
| `delphi_classes` | `query?`, `limit=50`, `binary?`, `cursor?`, `budget?` | classes from the VMTs: `Name : Parent unit U vmt 0x.. size N published P virtual V fields F`; `query` matches the class or unit name |
| `delphi_forms` | `form?`, `binary?`, `cursor?`, `budget?` | no form: one line per DFM form (class, name, caption, component and event counts). A form (resource name, class or form name; `binary!form` works): the component tree, indented, `Name: Class "caption" events N` (no addresses) |
| `delphi_events` | `form?` or `component?`, `binary?`, `cursor?`, `budget?` | `Button1.OnClick -> TMainForm.Button1Click 0x.. TMainForm::Button1Click`; a handler the form class (and its ancestors) do not publish shows `(not in the published methods)` |

Dirty-role only. Tables `dl_class`, `dl_method`, `dl_field`, `dl_form`, `dl_component`, `dl_event`
(schema v12, meta `delphi_version:<id>`), filled on the server from the PE bytes (`server/delphi.py`,
no Ghidra) when a Delphi binary becomes ready and on open for older projects. Published methods, virtual
methods and event handlers that Ghidra has no function for are created through `fnfix` (the same
`create_functions` op as for MFC handlers). Nothing is renamed in Ghidra: `function` shows hints
(`TMainForm.Button1Click (published)`, `handler OnClick of Button1 (TButton "Run") in form TMainForm`,
`TFoo::vslot 3`). The Delphi tools on a project without Delphi binaries answer with what it has:
`error not_delphi: no Delphi binaries; frameworks: qt (app.exe)`. The project map gets a `UI:` line, handlers seed the `ui-menu` / `ui-dialog`
features, and methods of classes from runtime units (`System`, `Vcl.*`, `Classes`...) plus `@`-prefixed
helper names count as runtime (`runtime: Delphi`).

The format code is written from the format description (no code copied; DelphiReSym was not used).
64-bit Delphi binaries use the standard Win64 calling convention.

**Library names at call sites** (`server/libnames.py`, round 7 item 6). A function that is still `FUN_xxxxxxxx` but has exactly one
IDR / sigdb / WARP name in `idr_hits` is shown under that name in the output of the read tools in `libnames.RELABEL_TOOLS`
(`function`, bulk and dataflow views, `callgraph`, `xrefs`, `search`, `function_map`, ...): display only, done in the tool wrapper
(`registry._library_names`) on the finished text. A call `FUN_x(` becomes `Unit.Proc/*0x..*/(`; other tokens become `Unit.Proc`.
Chosen over renaming in Ghidra because it needs no worker run, no undo and follows `IDR_VERSION` at once; a user or agent rename
removes the token, so it always wins. Ambiguous hits (a `|` list, `(+N)`, or the same name at several addresses) stay `FUN_`.
Names that differ only in case (`FPC_X | fpc_x`) count as one name. Only the hits of the ONE binary a call is bound to are used
(`Bound` objects made during the call, `registry.note_bound`; a single-binary project needs no bound): an address means a function only
inside its own binary, so output bound to several binaries (cross-binary `callgraph`, `search` over all) keeps `FUN_`. The budget cut
measures the shown text (`budget.DISPLAY` in `_cost`), and cursors keep the raw lines, so output stays inside the budget and no line is lost.
**[verified]** on a 36964-function Delphi project: 153161 `FUN_` tokens in the cached C, 72879 after; `FileExists` caller shows
`System.Sysutils.FileExists/*0x0047b330*/(...)`.

**IDR names for the RTL and VCL** (`server/idr.py`, optional). The IDR project (crypto2011/IDR, MIT)
publishes knowledge bases: the compiled code of the RTL and VCL units of one Delphi release with the
address-dependent bytes masked. The files are never committed; the user downloads them and sets
`idr_kb_dir` in config.jsonc (32-bit files in the folder or `x86\`, 64-bit files in `x64\`).
The reader is written from the file layout (IDR is a format reference only). Matching: an unnamed
(`FUN_...`) function gets the name of every KB proc whose unmasked bytes equal the code at the entry
(a proc dump ends with up to 15 padding bytes that Ghidra leaves out). Procs with fewer than 10
unmasked bytes and procs matching more than 3 functions of one binary (a wrapper around one call) are
not used. The KB is chosen by the compiler version that the System unit stores as `Embarcadero Delphi
for Win32 compiler version N.0`; without an exact file the one with the most matches on a sample wins.
**Decision: hints, no rename.** The worker has no bulk rename (each `rename_function` saves the whole
Ghidra project), a rename would make the name `user`, and Ghidra stays the truth for names. The result
is meta only (no table): `idr_version:<id>` (`IDR_VERSION:kb signature:unnamed functions`, so old
projects compute on open and again when the KB files or the function list change), `idr_hits:<id>`
(`address<TAB>names` lines, at most 3 names, plain names first) and `idr_info:<id>`. `function` shows
`idr: System.@LStrAsg`, and the addresses count as runtime (`graph.lib_hint`, `runtime: Delphi`
clusters), so they and the functions that only they call leave the unclassified part. Without
`idr_kb_dir` nothing is computed. Knowledge bases exist for Delphi 2 to XE4 (32-bit) and system units
only for XE2 to XE4 (64-bit); newer compilers match in part (the code of the RTL changed).

**Signature databases from a local Delphi install** (`server/delphisigs.py`, `server/itanium.py`, optional). The IDR
files end at XE4; newer compilers match in part. A Delphi install ships the RTL and VCL as packages
(`Redist\win32\*.bpl`, `Redist\win64\*.bpl`). `airlock delphi-sigs build <install>` reads the export table itself
(pefile stops at 8192 names), turns each export into a name (`System.@LStrAsg`, `System.Classes.TList.Add`;
`Create` / `Destroy` for constructors and destructors, `ClassCreate` / `ClassDestroy` for class constructors,
`op_Implicit` for operators; template arguments are left out: `TList<T>.Add`) and masks the position dependent bytes
of each routine: relocation entries (`HIGHLOW`, `DIR64`), `rel32` operands of `call` / `jmp` / `jcc` whose target is
outside the routine, and RIP-relative `disp32` outside the routine in 64-bit code. **Decision: capstone**
(BSD-3-Clause, optional `sigs` extra, needed by the build only) decodes the instructions; a hand-written length
decoder would need the x87, SSE and VEX tables.

*32-bit packages* export C++ Builder style names (`@System@Classes@TList@Add$qqrpv`). Exports without a parameter
list are type info, class tables or strings and are skipped. **Bounds:** a linear sweep from the export to the first
`ret` or unconditional jump that no earlier forward branch reaches past, at most 2048 bytes kept; a jump table in the
code stream is followed through its relocated slots; a routine that cannot be swept to its end keeps the swept prefix
(a prefix still matches the start of the static copy).

*64-bit packages* export Itanium C++ ABI names (`_ZN6System7Classes5TList3AddEPv`; `_ZTV` / `_ZTR` are class and type
info and are skipped). `server/itanium.py` parses the nested name, the template arguments (`I...E`, literals
`Lt0E`) and the substitutions (`S_`, `S0_`), because the arguments can refer to the prefixes of the name; the
parameter types are not kept. Delphi extras: `v04cctr` is a class constructor, `v18explicit` / `cv` are conversion
operators (a target type follows inside the name), `_op_Add` is `op_Add`, and a unit level `_LStrAsg` is
`@LStrAsg` as in the 32-bit style. Checked on all 114 Win64 packages of Seattle: every `_ZN` export parses (176,000 names, 0 failures). **The bounds come from `.pdata`**
(`RUNTIME_FUNCTION` begin / end / unwind info): an export that starts a `.pdata` routine is a routine with its exact
size, so no sweep is needed. Unwind info that is chained to a parent (`UNW_FLAG_CHAININFO`) is a piece of the parent:
a piece that starts where the routine ends extends it, a piece elsewhere (cold code) is ignored. The table is not
sorted. A few leaf routines have no unwind info (zlib); an export without `.pdata` entry that has a parameter list is
swept as in 32-bit, one without a parameter list is data and skipped.

**[verified]** with Delphi 10 Seattle Update 1: a program built with `dcc32 -B -GD` / `dcc64 -B -GD` and no runtime
packages (map file as oracle; the Win64 map lists the same routines) is named by the database. Over the routines whose
name the packages export and that are not generic instances: 32-bit 93.1%, 64-bit 89.6% named with the right name,
and 98.4% / 99.0% when the matcher's `MAX_COPIES` rule is lifted (the rest is dropped because the same code shape
occurs in more than 3 functions). Generic instances for types the RTL never instantiates (`TList<TFoo>`) have other
code and are not found. Wrong names (2 to 3% of the matched functions) are routines with identical code
(`Exception.Create` and `CreateFmt`). The database is derived data of a licensed install, cached outside the repo as
`<compiler>-<bits>.sigdb` in `delphi_sigdb_dir` (null: `sigdb\` in the data directory), zlib packed, and is never
committed. It loads into the same matcher as an IDR file. Selection: the database of the binary's exact compiler
version names the functions first; the IDR file (or a database of another version) that matches most then names the
rest, so a name from the database wins. `IDR_VERSION` 3 (now 8) makes projects compute again on open (version 2 databases stay
loadable: the file layout did not change). The export tables alone name only the public routines: 32-bit exports cover
about 60% of the routines of a static program, 64-bit about 79%. `airlock doctor` lists the databases.

**Private routines: a package of all compiled units with a detailed map** (`server/delphimega.py`,
`server/delphimap.py`). Tried first, rejected: rebuilding the runtime packages from `source/rtl` and `source/vcl`.
**[verified]** The install ships no `.dpk` for the VCL (the RTL one, `BuildWinRTL.dpk`, lists 176 units of the 262 of
`rtl230.bpl`), and the sources do not agree with the shipped `.dcu` files: compiling `Winapi.ActiveX` from source
fails with `F1026 File not found: 'System.Variants'`, and a `System.Variants` compiled from source is refused with
`F2051 ... compiled with a different version of "".TWordHelper`. The whole chain would have to be rebuilt from
`System.pas`, and the result still would not be the shipped code. Also rejected: a `.jdbg` reader (32-bit only, names
only, undocumented compressed names) and reading `.dcu` files (undocumented). **Decision:** the compiled units
(`lib/win32/release`, `lib/win64/release`: one `.dcu` per unit, the machine code that a program links statically) are
the truth, and a *package* has no smart linking. `dcc32` / `dcc64` build a package whose contains clause lists every
`.dcu` (`System` and `SysInit` are implicit), with `-B -GD` and the unit folder as the only unit path. No source is
read. The output is a package binary of 70 to 100 MB plus a detailed map (`-GD`: every routine with its segment
offset, private, nested and unexported generic instances included). Units that cannot be in a package are
handled in this order, and the build repeats after each step: (1) a resource file the install does not ship
(`E1026 ... .fmx|.res|.dfm`: the FMX TeeChart editors, the `.res` of the platform units) gets an **empty stub** in a
`stubs` folder of the work folder (`-R` path; an empty text form `object X: TX end`, an empty resource record).
**[verified]** The compiler links the stub without parsing the form, and the code of the unit comes from its `.dcu`,
so the routines and their names are the real ones. (2) `$DENYPACKAGEUNIT` units (WebBroker, ISAPI, CGI, ComServ,
OleAuto, IntraWeb bridge; their users go with them) cannot be in any package. They go into **one console program**
(`m_program.dpr`: a `uses` clause, `{$STRONGLINKTYPES ON}` so that classes nobody references stay linked) built with
`-GD`; its map is read like the packages' (smart linking still drops free routines that nothing calls, so the
coverage of these units is partial: about 480 routines of the WebBroker group on Alexandria 32-bit). (3) What is
still blamed by the compiler is left out: units whose own dependencies the install does not ship (`BDE`,
`Bde.DBTables`, `Vcl.RibbonConsts`, `DUnitX.Windows.Console`). Left out per build, before -> after: compiler 30 (17.0)
62 -> 2 (32-bit), 55 -> 2 (64-bit); 33 (20.0) 56 -> 2 / 54 -> 1; 34 (21.0) 56 -> 2 / 54 -> 1; 35 (22.0) 55 -> 1 / 48 -> 0.
Build time is about 1 minute per bitness (programs and stubs add a few seconds). **[verified]** The code is the shipped code: for the exports that a rebuilt `rtl`
package and `rtl230.bpl` have in common, 99.9% have the same masked bytes (the layout differs by a few hundred bytes,
the unit order is another one).

**One package is too big for newer Delphi versions.** **[verified]** With Rio (compiler 33) and Alexandria (35) the
package of all units fails with `E2621 Export table in output file too large: exceeds 65536 limits`, in both
bitnesses. Decision: split along the shipped packages. Each shipped `.bpl` (`Redist\win32|win64`, `bin`, `bin64`) has a
`PACKAGEINFO` resource (flags, required packages as hash and name, contained units as flags, hash and name), and the
`.dcp` files of the packages sit in `lib\<platform>\release` without the version number (`rtl260.bpl` -> `rtl.dcp`).
`delphimega.plan_parts` makes one package per shipped package: the same contains list (limited to units that have a
`.dcu`), and `requires` the `.dcp` of the packages the shipped one requires. A unit that a required package holds is
dropped, so no unit is linked twice. A shipped package that has no `.dcp`, or that requires one without, is not used.
One last package holds the units that no used package holds and requires all used packages. Each shipped package is
under the export limit by construction. The culprit rounds run per package, the packages build in parallel (`--jobs`,
a work folder each), and the map files of all of them are merged into the name records. A package that fails does not
end the build (it is listed in the result); if no package can be built, the CLI prints one warning line and writes the
database from the package exports alone.

`server/delphimap.py` reads the map. Segment numbers map to the PE section of the same name; a public is a segment
offset and a name in the Pascal form (`System.SysUtils.TStringHelper.Split`, nested `Unit.Outer.Inner.Method`, a generic
instance `Unit.{Owner}TList<System.Integer>.Add`, shown as `Owner.TList<System.Integer>.Add`). A name with an empty part
(`Unit..TClass`: VMT, type information) or an import thunk is not a routine and ends the routine before it. Bounds and
masks are the ones of the export path (`delphisigs.scan_named`: `.pdata` for 64-bit, a sweep up to the next public for
32-bit). `delphisigs.build(..., pairs=[(binary, map)])` adds the map records after the exported ones; a routine whose
masked code equals an exported one gets no second name from the map (an exported name wins). CLI: `airlock delphi-sigs
build <install> --units` runs the package build in a work folder (`--work`, deleted unless `--keep-work`) and merges
it; `--map BINARY MAP` (repeatable) merges a pair that was built another way (a program or package of your own; any
Delphi that writes a `-GD` map). The sigdb header keeps `mapped` (names from maps). Records the matcher would drop anyway (`idr.usable`: fewer than
`MIN_FIXED` compared bytes, such as the 6-byte `jmp [mem]` import stubs that the maps name after their targets) are not
written. A `--units` run holds an OS lock on its work folder (`<work>\win64.lock`): two runs on one folder delete each
other's packages and maps.

`airlock delphi-sigs kit <install> <dest>` copies the minimal rebuild kit (`server/delphikit.py`): `dcc32` / `dcc64` with
their `dccNNN` libraries, `borlndmm`, `rlink32`, `lnkdfmNNN` (units with a form file fail with E2161 without it), `cgrc`,
the compiler `.cfg` files rewritten to name the kit, `bin*\*.bpl`, `lib\win32|win64\release`, `Redist\win32|win64`, and
the resource files under `source` that `delphimega.resource_folders` lists. The libraries are found by name pattern.
`delphi-sigs build <kit>` works on it like on the install, so the install can be removed.

**Oracle measurement** (`airlock delphi-sigs oracle <binary> <map> [--own DIR]`, `server/delphioracle.py`). Method: a
Delphi program built with `-GD` has a map that gives the true name and bounds of every routine, so the map is the truth
and the installed database is the subject. The routines of the map are named with the same matcher the analysis uses
(`idr.match_all` with the exact-compiler database). A routine is *library* when its module is not one of the program's
own units (`.dcu` files in `--own`, default next to the binary, plus the program name); only library routines are
scored, since no database can know the program's own code. Each is counted `right` (a returned name equals a map name,
generic arguments ignored: `TList<X>.Add` equals `TList<T>.Add`), `exact` (the same without that tolerance), `wrong`
(a name that differs) or `none`, over all routines and over those of at least 24 bytes (the short ones carry too few
compared bytes to be named by code). Wrong names are code aliases: different routines with the same machine code.

**[verified]** Measured on the own test program (map as truth; routines = map publics that are not type tables or
thunks): named with a right name, 32-bit 58.0% -> 70.9% of all routines and 77.0% -> 94.6% of the routines of at least 24
bytes; 64-bit 69.9% -> 83.9% and 78.9% -> 94.6%. Wrong names stay at about 1.5%
(code aliases). Nearly all that is left are routines under 10 compared bytes (getters, wrappers, import thunks), which no
masked code signature can name, and tiny abstract stubs. The sigdb grew from 129,545 to 150,015 names (32-bit) and from
118,370 to 140,900 (64-bit): most map routines have the same masked code as an exported one, so the new names are the
distinct code only.

**Call-context naming** (`idr.call_context`, `IDR_VERSION` 8, sigdb format 3). A routine under `MIN_FIXED` compared
bytes cannot be matched by its code, but its callers often can. For each reference routine the database stores the
direct `call` / `jmp` (`E8` / `E9`) to a routine whose name is known at build time (package exports; map names of
the units package): `(offset of the operand, opcode, callee name)`. A function that matches the record on every
compared byte has the same instruction at that offset, because the opcode byte is one of the compared bytes. The
target of that instruction gets the callee name when it is an unnamed function that code did not name. Rules: aliases
of one routine that disagree at an offset give no vote; a target whose callers give two different names is left
unnamed; a name by code is never replaced; the pass runs for the exact-compiler database only (the other tiers have no
call lists). When a map record repeats code that an exported name already covers, the exported record keeps its name
and takes the calls of the map (the map names the private callees). A format 2 file has no `"calls"` key in its header
and reads as before (no pass). `CTX_MIN_VOTES` (callers that must agree) is 1; with 2 the wrong share was 0.2 points
lower and a third of the names were lost. The analysis note of the exact tier reads `sigdb30-32 N/M +K by calls`.
**[verified]** Oracle on the Embarcadero samples (compilers 30, 33, 35; 32 and 64 bit; VCL, FMX, FireDAC, console;
right / wrong share of the library routines, `sigdb` -> `+calls` + `+props`): all routines 32-bit 65 to 74% -> 74 to 88%
(right) with wrong 2.7 to 4.1% -> 2.8 to 4.4%; 64-bit 66 to 79% -> 80 to 86% with wrong 3.8 to 6.8% -> 4.0 to 7.2%; the
rise of wrong names is at most 0.4 points in every run. Routines of at least 24 bytes: 84 to 93% -> 87 to 95%, wrong
+0.0 to +0.2. The call-context pass names 900 to 1,200 routines per VCL program at 97 to 98% right; the accessors 90
to 530 more at 96 to 99%. The console programs gain most (68% -> 88%): their routines are mostly RTL helpers that
callers reach.
**Unit rule for short matches** (`idr._drop_unsupported`, `IDR_VERSION` 11, Delphi sigdb only). A match under
`SHORT_FIXED` (48) compared bytes keeps only the names whose unit (`idr.unit_of`: `Vcl.Dbgrids.TX.M` -> `vcl.dbgrids`)
also has a match of at least 48 compared bytes in the binary; a name with no such unit is dropped, and the match with
it. A routine of the runtime is linked with its unit, so a unit without any long match is not in the program, and
the short code is a routine of the program that has the same bytes (an accessor, a `Destroy` that frees one field,
the `Finalization` of a unit). The rule applies from 20 long matches (`UNIT_MIN_LONG`; a tiny test binary has none).
Call-context votes use the pruned matches. **[verified]** Oracle on 10 sample programs (compilers 31, 34, 36, 37; VCL and
FireDAC; 32 and 64 bit; map as truth), stage `+props`, library routines, all programs together: wrong 6,923 -> 6,678
(3.80% -> 3.66%, -3.5%), right 152,893 -> 152,929 (83.84% -> 83.86%); routines of at least 24 bytes: wrong 4.28% -> 4.16%,
right 92.18% -> 92.20%; routines of the program itself that got a runtime name: 23 -> 16 (the rest come from the
call-context or accessor pass, or share a unit with a long match). Thresholds tried (24 / 32 / 48 / 64, code stage):
wrong 6,621 -> 6,525 / 6,418 / 6,376 / 6,240, right -16 / +3 / -20 / -137: 48 is the last one that keeps the right names.
Not kept: dropping short matches with many alias names (42% wrong, but 59% right) or without a named caller (5% wrong
against 9%: too weak). Free Pascal: the same rule made the oracle worse (gui 32-bit right 83.3% -> 82.9%, wrong 0.2% ->
0.3%; FPC unit names do not follow the Delphi shape), so it is off for `fpc-*.sigdb` files.

Property accessors (section 11 "Delphi") come as hints, not as `idr_hits`. The oracle shows each stage: `sigdb`
(code), `+calls`, `+props` (accessors by convention) and, for the last two, how many routines the stage named and
how many of those are right.

**RTTI consensus database** (`server/delphirtti.py`, optional, needs capstone like the sigdb build). Since Delphi 2010 the
extended method table (see "Delphi" in section 11) names the methods of every class that a program links, the RTL and
VCL classes included, with their code addresses. A program therefore states the names of thousands of its own RTL
routines. `airlock delphi-sigs rtti-build <folder>...` (one folder = one product) reads these names from many
unrelated programs, takes the masked code bytes at each address and keeps a (code shape, name) pair only where
independent files agree. The idea is the "extended RTTI consensus" of psifertex/delphinja (MIT, `tools/RTTI.md`); the
code is new (THIRD_PARTY_NOTICES). Pure Python: pefile and capstone, no Ghidra. Rules:
- Only classes of runtime units go in (`delphi.runtime_unit`: `System.*`, `Vcl.*`, `Winapi.*`, `Data.*`, `Xml.*`...;
  `--indy` adds `Id*`). Program classes never do: they are the code of the target and their names would leak
  between products. Generic instances are stored as `TList<T>.Add`, and a class name that a ShortString cut at 255
  characters leaves with an open bracket is cut at the bracket, because type arguments are program types.
- Bounds and masks are the ones of the package sigdb (`delphisigs._scan_routine`): `.pdata` for 64-bit, a sweep for
  32-bit, relocations, `rel32` operands that leave the routine and RIP-relative operands masked. A program has no
  package relocations to rely on (an exe may have none), so 32-bit absolute operands that point into the image are
  masked too (`_mask_abs`).
- A name needs `--min-binaries` distinct files (default 3; identical files count once, by SHA-256) and
  `--min-products` distinct products (default 1; the build reports how many names several products agree on). All
  the binaries of one product share one RTL build, so agreement inside a product is weaker evidence than agreement
  across products. A shape with more than 6 names is a stub (`ret`, one call) and is dropped; a shape with 2 to 6
  names keeps all of them (code aliases such as `Exception.Create` and `CreateFmt` are listed together).
- A method that a parent class already names (same name and address) belongs to the parent.
- `--exclude <file>` leaves a file (and its identical copies) out, to measure a database on a program it has
  not seen.
Output: `rtti-<compiler>-<32|64>.sigdb` next to the other sigdb files (same file layout, header `kind: rtti`). Selection
in `idr._pick`: exact-version package database, then the RTTI database of the exact compiler, then the IDR file that
matches most; each tier names only the functions the earlier ones left. Derived data of the user's programs: never
committed; a database holds names of RTL classes only.

**Direct names and where the consensus database helps.** A binary's own extended table names its functions directly
(hint `rtti: Unit.Class.Method`, kind `rtti-<visibility>` in `dl_method`), whatever the compiler version, so the
consensus database adds almost nothing on a program that still has this table: the routines it knows are the ones
the table already names. The database is for programs without a local Delphi install (no exact sigdb), where it
names routines the IDR files do not know: on an own `dcc32` / `dcc64` build of most RTL and VCL units (map file as
truth) a database built from other programs alone names 29% (32-bit) and 39% (64-bit) of all routines, 99% of them
with the right name (Delphi 10 Seattle, held out). Unit-level procedures, private routines of units and everything
the table does not list stay unnamed, as does a program's own code.

**Copies of a code shape.** `idr.match_all` drops a proc that matches more than `MAX_COPIES` (3) functions of one binary:
a short wrapper around one call occurs in hundreds of program functions. That rule dropped about 9% of the routines
that the database can name. Since `IDR_VERSION` 4 two kinds of proc are kept: a proc with at least `LONG_SHAPE` (64)
compared bytes, and a generic template (`<` in the name) with at least `GENERIC_MIN` (16): one instance per element
type is normal (`TList<T>.Add`). Measured with the oracle programs (map file as truth, right = same class and method,
or the same method of a generic or alias class): with the exact package database 32-bit named 5,126 routines with
97.5% right and now 7,564 with 98.3%, 64-bit 5,452 with 98.4% and now 8,807 with 98.7%; lifting the rule completely
gives 8,291 / 9,847 named but 3% / 1.5% wrong and, on real programs, adds many program functions that
only look like runtime code (measured as methods of the program's own classes, whose true names are in its RTTI, that
get a runtime name). A generic stub of 10 compared bytes shared by thousands of functions was the main source, hence
`GENERIC_MIN`; with it the increase is small. Rules tried and not kept: all procs of one unit, all functions
with the same name, a lower length threshold.

**WARP signature libraries** (`server/warp.py`, `worker/ghidra_ops/warp.py`, tier in `idr._pick`).
Binary Ninja WARP (github.com/Vector35/warp, Apache-2.0) with the Delphi libraries of psifertex/delphinja
(`signatures/*.warp`, MIT, built from IDR knowledge bases and Delphi 10.4/11 packages). **[verified]** Function GUID =
UUIDv5 (namespace `0192a179-61ac-7cef-88ed-012296e9492f`) of the block GUIDs ordered by ascending start address; block
GUID = UUIDv5 (namespace `0192a178-7a5f-7936-8653-3cbaa7d6afe7`) of the block's instruction bytes with nops (and
`mov r,r` of one register on x86) dropped and every "variant" instruction zeroed as a whole. The README says "highest
to lowest" but the reference code and the data say ascending. Variant, in Binary Ninja's own LLIL: a constant or
pointer operand that lies inside a segment or within 0x10000 of one. The GUID therefore depends on Binary Ninja's
analysis (block recovery, no-return calls, lifter), but only mildly: rules that Ghidra bytes can reproduce give,
**[verified]** on a Delphi 10 Seattle program (map file as truth, libraries of other compilers): zero the whole
instruction for calls and for instructions with an operand or reference in the image; zero a jump only when it leaves
the function or is indirect; keep conditional jumps and returns. Counting a conditional jump as variant drops the
matches from 61% to 17% of the same-name pairs. Of the functions with a same-name entry in the libraries 61% have an
equal GUID (the rest differ in code between compiler versions, or in Binary Ninja's blocks). Over all functions of
16 bytes or more: 27% (capstone blocks) and 35% (Ghidra blocks) got a name, 94% of them with the right name or the
same name under an older unit name; ambiguous GUIDs (more than 3 names) are dropped. The `.warp` file is a FlatBuffers
`File` with chunks that the delphinja files store zlib packed although the header says zstd; `read_warp` takes the
magic. Constraints (called functions, adjacency) are read but not used. Blocks come from the capstone recursive
descent over the PE bytes (`image_blocks`, 32-bit, same input as the IDR matcher) or from the worker op `warp_blocks`
(Ghidra blocks plus per-instruction facts). They agree on 81% of the functions; the rest differ in no-return and
function extent handling. delphinja has no 64-bit library; see "Own libraries" below.
Wiring: config key `warp_dir` (null: `warp\` in the data directory) holds the `delphi-rtl-*.warp` files, pinned to
delphinja commit `b2952e99` and checked by size and git blob id; `airlock doctor` lists them. `kb_files` lists them
as `KbFile(warp=True)` (32-bit only), so they are part of the stale signature (`IDR_VERSION` 5). `_pick` order: exact
sigdb, RTTI database, WARP, IDR; an earlier name wins. The libraries come from the compiler version
(`warp.library_stems`: 30 and newer = `10.4-only` + `core-11` + `xe2plus-only` (each names routines of programs built with
compilers 30 to 36; the extended RTTI names agree with `10.4-only` and `xe2plus-only` in about 99%), 26 to 29 = `core-11` + `xe2plus-only`, older =
`<year>-only` + `core-8`); an unknown compiler uses none. The matcher is the capstone route (`warp.match_functions`,
functions of 16 bytes or more, at most 3 names per GUID). Names are written like the other tiers (`warp.dotted`:
`Unit::Class::Member` becomes `Unit.Class.Member`; the arity suffix of a generic instance becomes the placeholder form of the
sigdb and RTTI tiers, `TDictionary__2` -> `TDictionary<T>` (the type arguments are program types and the code is shared);
`idr._pick` puts the real arguments in when the program's own RTTI (`dl_class`) has exactly one instance of that generic
class, `TStack<System.Integer>.Push`, `warp.refine_generics`; units that old compilers wrote without a namespace get it back,
`SysUtils` to `System.SysUtils`, `Graphics` to `Vcl.Graphics`, `Windows` to `Winapi.Windows`). The IDR file is chosen on
the functions that no earlier tier named, before WARP runs, so WARP cannot change that choice. On a compiler 30 program
(no library for it) WARP agrees with the exact sigdb name in about 98% of the functions both name (the rest are code
aliases such as `Exception.Create` and `CreateFmt`), adds names net and loses none. Cost: about 20 s more for a large program.

**Own WARP libraries, 64-bit** (`delphi-sigs warp-build <kit>... [--bits 32|64|both] [--out DIR] [--map BIN MAP]`,
`warp.build_library`, `warp.library_pair`, `warp.write_warp`). The same function GUID, computed from the rebuilt
packages of the units build (`delphimega`, with map file) instead of from Binary Ninja: for each named routine the
capstone blocks of its extent (next public) give the GUID, so a library holds `GUID -> Unit.Class.Member` for every routine
the maps name, private and nested ones included, and several compiler versions go into one file. Operand rules for x64
(**[verified]** only by the measurements below, there is no Binary Ninja reference for Delphi x64): an immediate or an absolute
displacement inside a section, or within 0x10000 of one, and a RIP-relative operand whose target (`next ip + disp`) is
inside one, make the whole instruction variant; calls, jumps out of the function and indirect jumps likewise. The library
is the layout `read_warp` reads (FlatBuffers `File`, one zlib signature chunk, names already dotted, generic arguments
collapsed to `<T>`); whether Binary Ninja loads it is not checked. GUIDs with more than 3 names are not stored (the matcher
skips them). The file is `airlock-rtl-win64.warp` (`win32` for `--bits 32`) in `warp_dir`; `idr.warp_files` lists it for
the pointer size, and `_pick` uses it for **any** compiler version (also an unknown one), after the exact sigdb and the
RTTI database, before IDR, like the delphinja files. Kits of compilers 30, 33, 34, 35 (kits 17.0, 20.0, 21.0, 22.0), 64-bit:
183,701 GUIDs / 207,069 names, 7.0 MB, about 90 s per kit with 8 jobs. `IDR_VERSION` 9.

Measured **[verified]**, 64-bit, leave-one-out (library from the kits of compilers 30, 33, 34 = 162,670 GUIDs; the
exact compiler 35 sigdb hidden, `delphi-sigs oracle --hide-exact --warp-dir`; Embarcadero sample programs, map as truth,
library routines; right name before -> after WARP): console 53.3% -> 60.6%, VCL 59.0% -> 62.3%, FMX 58.4% -> 61.2%,
FireDAC 62.3% -> 65.3%; wrong 4.0 -> 2.4, 4.4 -> 3.9, 5.9 -> 5.6, 4.1 -> 3.7 %. The routines WARP names that the other
versions' sigdbs do not: 56 / 355 / 670 / 569, 100 / 95.8 / 92.8 / 93.0 % right. The gain is small because the other
versions' sigdbs already match by masked code (`_pick` pool); WARP's block GUID adds the routines whose bytes differ in
immediate or layout details. On programs without a map (names of runtime classes from extended RTTI as truth), all kits
in the library: xEdit 4.0.4 `xDump64` (compiler 32, no kit): named functions 5,410 -> 7,622 of 23,561, RTTI-truth
routines right 2,356 -> 3,343, wrong 343 -> 330; compiler 35 programs with the library of 30, 33, 34 (exact sigdb
hidden): `BSArch64` right 2,065 -> 2,138 (wrong 164 -> 148), `xDump64` 3,764 -> 3,860 (wrong 305 -> 284). No compiler 36 64-bit
program was available. 32-bit own libraries work the same way and are listed beside the delphinja ones.

### dotnet

| Tool | Parameters | Returns |
|---|---|---|
| `dotnet_types` | `query?`, `limit=50`, `binary?`, `kind?`, `cursor?`, `budget?` | types/methods from `dnfile` metadata, incl. P/Invoke declarations (`module!entry`, `=> binary!export` when bound) and COM imports. Without `kind`: types, plus P/Invokes and methods that match `query`. `kind` = `type`, `method`, `pinvoke` or `com` |
| `dotnet_decompile` | `type`, `member?`, `binary?`, `cursor?`, `budget?` | C# from `ilspycmd`, one type at a time, cached in `dirty\.airlock\cache\dotnet\`; first line marks it as a reconstruction. `type` is the full name, or a unique suffix. `error tool_missing` without a configured ilspycmd |

Both are dirty-role only. Tables: `dn_type`, `dn_method`, `dn_pinvoke` (schema v11, meta
`dotnet_version:<id>`). Every managed method is a function (space ram, entry = MethodDef token, size 1,
namespace = full type name). A P/Invoke method is a thunk plus an import row (address = the token,
module with `.dll` added). The normal import linking binds it to an export of a project binary and
writes an xedge of kind `pinvoke`, so `xrefs`, `callgraph` and `path` follow it. A module no project
binary provides stays an unresolved import. `dotnet_types kind=com` shows the GUID of a type with a
`GuidAttribute` as `{GUID}` (ComImport types and interfaces).

`function` on a managed method: `view=c` answers `error managed` and names the `dotnet_decompile`
call; `view=asm` lists the IL (`IL_0000 opcode operand`, operands named, branch targets as `IL_xxxx`).
A P/Invoke thunk answers `error managed` for both views.

### resources

Parsed on the server with `pefile` (no Ghidra). All take `binary` (default: the root executable;
`*` = every binary; `binary!id` works for the id parameters), `lang` where a resource has several
languages (default: neutral, then 0x0409, then the lowest), `cursor` and `budget`. Rows are filled into
the derived tables `res_dialog`, `res_control`, `res_menu_item`, `res_string` (schema v9) when a binary
is ready, and again on open or on first use when `RESOURCES_VERSION` (index meta
`resources_version:<binary id>`) is older. Control and menu item ids are indexed for the M2 join with
MFC message map entries.

| Tool | Parameters | Returns |
|---|---|---|
| `pe_resources` | `type?` | resource inventory: type, id/name, language, size |
| `dialogs` | `id?` | no id: one line per dialog (caption, control count, size, languages). With id: DLGTEMPLATE/DLGTEMPLATEEX controls with id, class (predefined atoms by name), caption, short style words (`BS_DEFPUSHBUTTON,tabstop,hidden`); each control line ends with `-> BN_CLICKED Class::Handler, EN_CHANGE Class::Other` when a message map handles its id (the handlers of the dialog's own class win over other classes that share the id); the dialog line names its class |
| `menus` | `id?` | no id: one line per menu (item and popup counts, top-level captions). With id: MENU/MENUEX tree, one line per item: `id=<n> <popup path>`, popups as `<caption> >`; an item with handlers ends with `-> Class::OnOpen; update -> Class::OnUpdateOpen` |
| `string_tables` | `query?`, `limit=50` | id → string (RT_STRING id = (block-1)*16 + index); query is an id or a substring |
| `version_info` | | product name, version, company, file description |

### dataflow

| Tool | Parameters | Returns |
|---|---|---|
| `trace_values` | `function`, `variable` or `param`, `depth=2` | def-use chain across resolved calls (high p-code). Done in M8: lines `def`/`use`/`alias`/`call ... arg N`/`store`/`cmp`/`return`/`into <callee> param_N`; follows COPY/CAST/arithmetic/phi forward and into direct callees up to `depth` (max 5), 120 lines. Not done: backward into callers, indirect calls, aliasing through stores |
| `switch_tables` | `function` | recovered switch: case values → targets, defaults separate. Done in M8 from the decompiler jump tables; compare chains are not listed |
| `constants` | `value`, `limit=30` | functions using the constant (magic numbers, record tags). Done in M8: byte search for the 32/16/64-bit immediate in executable blocks, then an operand check; values below 0x80 are refused; constants in data tables are not searched |

### fileformat (no Ghidra)

| Tool | Parameters | Returns |
|---|---|---|
| `ole_streams` | `path`, `stream?` | stream tree with sizes; one stream as hexdump page |
| `hexdump` | `path`, `offset=0`, `length=256` | hex + ASCII |
| `file_diff` | `path_a`, `path_b`, `stream?` | changed byte ranges with context; for OLE, per stream |
| `record_guess` | `path`, `stream?`, `offset?` | candidate record layouts: length prefixes, repeated strides, string fields |

Implemented in `server/fileformat.py` (logic) and `server/tools/fileformat.py` (tools); `olefile` is a dependency.

- **Role and paths.** Dirty only (not `clean_safe`). A relative path resolves against the program source folder from the manifest (`source.path`), then `dirty\work\`. An absolute path is accepted only inside one of those two roots (`error outside_project`), so the tools cannot read arbitrary files. `binary!` is not used.
- **Paging.** All four take `cursor` and `budget` (§7). `hexdump` and `ole_streams stream=` take `offset`/`length` (max 16 KiB per call; the footer gives the next `offset=`).
- **`ole_streams`.** One line per stream (`Root/WordDocument 4096`) and storage (`Root/ObjectPool/ (storage)`); control characters in names are shown as hex escapes (the byte 0x05 before `SummaryInformation` is shown as backslash, x, 05), and `stream=` accepts the escaped form with or without `Root/`. Not an OLE file: `error not_ole`.
- **`hexdump`.** `0x` offset, 16 hex bytes, `|ASCII|`; `stream=` dumps an OLE stream instead of the file.
- **`file_diff`.** Compares in 1 MiB chunks (memory bounded; an OLE stream is held in memory, one pair at a time). Changed bytes closer than 8 bytes merge into one range; each range shows 4 context bytes on each side and up to 16 changed bytes per side (`[..]`); a size difference ends in an `only in a/b` range. If both files are OLE: header counts, `added`/`removed` streams, then `changed <stream>` with its ranges (`stream=` limits it to one). At most 4000 ranges per pair are listed; the rest is counted.
- **`record_guess`.** Analyses a window of up to 1 MiB from `offset`. Candidates, strongest first:
  - *Fixed stride*: byte autocorrelation over the first 32 KiB, strides 2..512, fundamental only. The run where the stride holds is found (matches inside zero/ff padding are neutral), so a header before the records gives `N records from 0x<start>`; a stride that holds only in part of a small window is found by a local pass. Per column: constants, printable text, u16/u32 in either byte order (`u32be`, `ascending`, `+N per record`), f32/f64 ranges.
  - *Length-prefixed chains*: a length field of u16/u32/u64 in either byte order at `+k`, step = header + len (or len, or len*2 for word counts), optional trailer (PNG crc) and padding to 2/4 (RIFF). Starts 0..32 and a few larger offsets. A text tag next to the length (`IDAT`, `MTrk`) or a 2-byte record type (BIFF) is listed with counts. Evidence is the chance that random field values would fit into what is left of the data, plus the chain ending exactly at the end (or in zero padding, one pad byte, or a trailer that repeats the bytes before the first record). The threshold is raised to the best chain found in a block-shuffled copy of the same data (tables of small numbers chain by accident), and a chain is dropped when other start offsets give unrelated chains as long. 1-byte and varint (protobuf-style) lengths carry no such evidence and are accepted only when the chain ends exactly (low-entropy data, at least 12 records).
  - *OpenPGP packets* (`recdetect.py`): old and new packet headers (1, 2, 4-byte and partial lengths) from start 0..8. Every tag must be a known one and the chain must end exactly at the end of the data (a cut window needs 4 packets). At least one body must parse as its tag says: key packets (version, known algorithm, MPI bit counts that fit the body), signatures (version, type, algorithm and hash in known sets, subpacket lengths inside the body), public-key encrypted and symmetric key packets, one-pass signatures, user ids as text, literal data with a printable file name. A chain from a start other than 0 needs 3 packets; one packet needs 64 bytes. A match replaces all other layouts and the strings list. Lost on purpose: lone packets without a checkable body (compressed, symmetric data, trust, marker, user attributes) and packets under 64 bytes.
  - *Registry policy* (`[key;value;type;size;data]` in UTF-16LE, `Registry.pol`): the bracket chain is parsed exactly; a match replaces all other layouts.
  - *Delimited text*: the three longest printable spans (ASCII/UTF-8, or UTF-16LE) are read as CSV with `, ; tab | :`. At least 4 rows, 90% of them with the same field count (3 or more for `:`), short cells, rows that differ. Output: row and field counts, header row, per field a type (int, number, date, bool, text) with range. Works inside a binary blob.
  - *Offset/length tables*: 3 or more entries of 8..64 bytes with a u32 offset and a u32 length (either order and byte order) in the first 128 bytes. The ranges must lie behind the table, not overlap, and reach into the last quarter of the data. They must start right behind the table, or the table has 4 entries with unaligned values. This finds ICO and TrueType directories. Fields of 8 bytes (u64, same rules) are tried when no u32 table fits. Fields of 2 bytes (u16) are accepted only when the ranges tile exactly (each starts where the previous one ends, the table is followed by the first range or the last range ends at the end of the data). Tables of 1 or 2 entries are accepted only when the whole data is in the window and the ranges tile it exactly (2 entries: the lowest range starts right behind the table, they follow each other, the last one ends at the end of the data; 1 entry: one pair whose range ends at the end of the data); the output says so. The scan keeps only positions where a range fits and walks entries from there (about 20 ms on a 5 MB file). A table that a longer stride explains (20 or more records) is dropped, as is a short stride over the same bytes.
  - *Java class files* (`recdetect.py`): the `CAFEBABE` magic (also inside a blob), then the constant pool is walked with the tag-dependent entry sizes (long and double take two slots). It must end exactly at the slot count, and the this-class entry must name a class with a plausible name. Fields, methods and attributes behind it are walked too; the line says where the class ends. A match replaces all other layouts and the strings list.
  - *Sample streams*: PCM-like data (blocks of 1 KiB, mean step small against the deviation, at least 75% of the blocks, not text) gets "sample stream ... no records". 8-bit: the step is measured at lag 1 or 2, even and odd steps apart (the low bytes of 16-bit audio are noise between smooth high bytes). 16-bit little endian, mono or interleaved stereo (reported when every second sample is smoother), either sample phase; loud blocks need noise-like low bytes, so 8-bit stereo does not pass as 16-bit. Clean streams are tried before noisy ones; noisy means the step is up to 0.88 of the deviation while neighbouring samples still correlate (0.4 or more). Stride guesses are dropped; an exact chain (the RIFF header) stays.
  - Then strings (ASCII and UTF-16LE runs of 4+, spacing, length prefix before runs) and entropy.
  - Mostly-zero files give no global stride; high-entropy data skips strings. These are hints to verify with `hexdump`, not a parser.
  - Verified on real files (dBase `.dbf`, shapefile `.shp`/`.shx`, BIFF in `.xls`, PNG/APNG, RIFF/WAV, MIDI, DSDIFF, MCAP, TrueType `hmtx`/`loca`/directory, ICO, OpenPGP keys and messages, `.pol`, CSV/TSV, 8-bit and 16-bit WAV, a Java class) and on synthetic layouts in `tests/test_fileformat.py`. Not found: tables of 1 or 2 entries that do not tile the data, 24-bit PCM, audio below the noise limit, delimited text without line ends.

### spec_write / spec_read

| Tool | Parameters | Returns |
|---|---|---|
| `spec_write` | `topic`, `title`, `body`, `sources`, `status=draft` | `spec <id> <topic> v<n> <status>`; rejects code/addresses (§9); an identical rewrite returns `unchanged`, a changed one is a new version |
| `spec_list` | `topic_prefix?` | topics, titles, versions, status; dirty also publish state and id |
| `spec_read` | `topic` or `id` (dirty only), `version?` | title line + body; a clean session gets the published version only |
| `spec_export` | `topic_prefix?`, `format=md` | dirty: publishes (§9 Publishing specs); clean: only reports the published count |

### admin

| Tool | Parameters | Returns |
|---|---|---|
| `program_scan` | `path` | light scan (§5.0): groups, options table with estimated analysis time per option, data files, recommendation. No Ghidra; allowed when unbound |
| `project_create` | `path`, `name?`, `option` (`A`–`D`), `add?`, `remove?` | creates the project folder (§4), queues the selection and binds the session as dirty. Allowed only when unbound |
| `program_add` | `option` or `files` | re-scan and queue more files of the same program |
| `overview` | | the project map (§4 "Project map"): purpose, binaries, relations, features with coverage, knowledge, frontier; same content as `dirty\PROJECT.md` |
| `project_describe` | `purpose` | sets the purpose paragraph of the map (dirty only) |
| `features` | | feature index: key, title, entry points, coverage |
| `feature` | `key`, `limit=40` | entry points of one feature (binary, function, address, reason, evidence strings/imports) + related notes/specs |
| `feature_define` | `key`, `title`, `functions?`, `topics?` | add or refine a feature |
| `function_map` | `scope?` (feature key, binary, or `binary!function`), `cluster?`, `limit=30` | without `cluster`: one line per subsystem cluster in the scope (id, label, named/total, key functions with addresses, links to other clusters, features); with `cluster`: its member functions by importance, each with binary, name, address, callers/callees counts, evidence |
| `cluster_label` | `cluster`, `label` | the agent names a subsystem; kept across recomputation |
| `path` | `from`, `to`, `k=3`, `max_depth=8`, `cursor` | shortest call chains across binaries, one step per line with call-site address |
| `graph_export` | `scope`, `format=mermaid` (`mermaid`/`dot`/`graphml`), `inline=false` | writes a graph file to `dirty\diagrams\` for the user and returns its path |
| `index_status` | `project?` | analysis queue (per binary: state, time, remaining estimate), decompile progress, worker state, stale counts |
| `reindex` | `binary`, `scope=stale` (`stale`/`all`/`analyzers`) | job id |
| `project_info` | | config in effect, enabled sets, profile, paths |
| `frontier` | `limit=20` | unnamed functions ranked by call-graph centrality and how interesting their strings/imports/UI links are: "what to reverse next" |

Total in the catalog: 58 tools. The default dirty tool list has 52 (without
`delphi`, `dotnet` and `patch_bytes`); the clean role has the 6 `clean_safe` tools.

---

## 7. Output conventions

### 7.1 Budgets and detail

- Every response is estimated in tokens (characters / 3.5 for code, / 4 for
  prose; conservative) and cut at the budget.
- `detail=brief` (default): the answer only.
- `detail=full`: wider context (e.g. asm next to C, more callers).
- `detail=evidence`: adds how the fact was obtained (analyzer, profile,
  limitations). Never default.
- Default budgets: `defaults.token_budget` (2000) for every tool except
  `function`, which uses `defaults.function_budget` (10000). Measured on a
  32-bit MSVC application (sample of decompiled functions): the median
  function is about 70 tokens and about 1% exceed 2000, but the largest
  (parsers, dispatch switches, loaders) reach 8000–30000, and those are the
  functions an agent reads most. **[verified]**
- Any tool accepts `budget` to override, capped by config `max_budget`
  (default 32000). The cap is never below the tool's own default.
- `function` (view=c) honours `detail`: `brief` (default) strips decompiler
  `/* WARNING */` lines and collapses a local-declaration block of more than 6
  lines into one `// N locals: ...` line; `full` returns the cached text
  unchanged. Line numbers (`lines=`, page header, outline) refer to the text of
  the chosen detail level, and cursors are bound to it. Reduction is purely
  presentational (the cached `decomp.c_text` stays raw) and runs after call
  annotation.

### 7.2 Cursors

Truncated output ends with one line:
`… 412 more lines. cursor=c_7f3a` and the agent calls the same tool with
`cursor`. Cursors live in memory for the session and in the index for
`function` text (offsets into `decomp.c_text`), so they survive a worker
restart.

### 7.3 Selectors

`target` resolution (adapted from REA's rules):

1. `0x…`, or an explicit address space (`EXTERNAL:0x1`) → address.
2. Otherwise an exact symbol name, including namespace (`CMainFrame::OnFoo`).
3. Otherwise a bare hex string → address.
4. A name that matches several functions returns an error listing every
   candidate's address; the agent retries with the address.
5. An address inside a function resolves to that function, and the response
   says so (`resolved from interior address`).
6. **Binary prefix.** `binary!target` (`engine.dll!LoadDoc`,
   `engine.dll!0x10001000`) names the binary in the target and is equivalent
   to `binary=engine.dll`. The text is split at the first `!` only when the
   left part is the exact name (case-insensitive) of a binary of the project;
   otherwise the whole text is the target, so names containing `!` still
   work. Naming two different binaries (prefix and `binary=`) is
   `error bad_args`. Without a prefix and without `binary=`, a project with
   one binary uses it; a project with several looks the target up in every
   ready binary: exactly one hit resolves there (the response adds a
   `binary <name>` line), several hits give `error ambiguous` listing each as
   `bin!name 0x…`, none gives `error not_found`. Applies to `function`,
   `xrefs` and `callgraph` (several matches: rule 8).

7. **Imports and typed targets.** One resolver (`server/targets.py`) serves
   every tool. A name is first looked up as a function; stubs of an import
   (thunk, EXTERNAL row, import-table row) form an *import*, not a function.
   Accepted import spellings (case-insensitive, `__imp_`/`@N` decoration
   ignored): `ReadFile`, `KERNEL32!ReadFile`, `KERNEL32.DLL!ReadFile`,
   `KERNEL32.DLL::ReadFile`, `<KERNEL32>!ReadFile`; without an exact match the
   `A`/`W` forms are tried together (`CreateFile` = `CreateFileA` +
   `CreateFileW`). `DLL!` is read as a DLL only when the project imports from
   it, else the whole text is a name. A bare name that is an import in
   several binaries and a function in none is the import across all of them
   (not ambiguous); a function in one binary plus an import elsewhere: rule 8.
   `binary!name`/`binary=` limits the import to one binary.
   A statically linked library function (a real function of that name) is the
   import's *library function*.

   | form | function | xrefs | callgraph | function_map scope | feature_define functions | path |
   |---|---|---|---|---|---|---|
   | `name`, `ns::name`, `bin!name` | yes | yes | yes | yes | yes | yes |
   | `0x…`, `SPACE:0x…`, bare hex, interior address | yes | yes | yes | yes | yes | yes |
   | raw address that starts no function | no | yes (raw refs) | no | no | no | no |
   | import, any spelling above | its library function, else its one thunk, else `error external` (use xrefs) | callers in all binaries, merged, `[bin]` prefixed | callers tree rooted at the import; callees only via its thunk/library code | clusters of its callers | no (`error bad_target`) | yes (import node) |
   | quoted or plain string | no | no | no | no | no | yes |
   | feature key, cluster id | no | no | no | feature key, binary name | no | yes |

8. **One ambiguity rule per tool kind.** A name can match several functions
   (same name in several binaries, overloads), or a function in one binary and
   an import of that name in another.
   - *Tools that show one body or edit one function* (`function`, `annotate`
     tools, `feature_define`, `function_map` seeds): single target. Several
     matches give `error ambiguous`, listing every candidate as a ready-to-use
     selector, `binary!name 0xaddr` (`binary!0xaddr name` when the name repeats
     inside one binary, since the name is then no selector).
   - *Tools that list relations* (`xrefs`, `callgraph`, `path`): an import is
     aggregated over all binaries that have it (rule 7). `path` also takes
     every function of a name as one multi-node endpoint (header
     `(N functions in M binaries)`); `xrefs` and `callgraph` print one tree per
     call, so they keep a single function and give `error ambiguous` like
     `function`.
   - *Function in one binary, import in another*: the function wins when every
     import binding resolves to it (xedge from the import slot or thunk to the
     function's entry): the import is that definition. Otherwise the candidates
     are listed (`error ambiguous`, or in `path` one endpoint with both).
   `path` resolves its endpoints with `targets.resolve_target(aggregate=True)`
   and only maps the typed target to call-graph nodes (`server/endpoints.py`);
   strings accept `*`/`?` globs there. A cluster id (`C1`) is checked before a
   bare hex string.

9. **Cheaper than `error ambiguous`.** Before an ambiguity is reported, three things can decide
   (checked in this order; `error ambiguous` stays only when none does):
   - *Qualifier* `name@binary` is the same as `binary!name` (split at the last `@`, only when
     the right part is the exact name of a binary, so `_foo@8` is untouched).
   - *Definition over import* (tools that list relations, i.e. the typed kind `import` is
     accepted: `xrefs`, `callgraph`, `function_map`): a name that is one function in one binary
     and an import in others is the function, even without an xedge binding; the note line says
     `binary lib.exe; also an import in host.exe, plug.dll`.
   - *Session focus*: the binary of the function resolved last in a multi-binary project
     (`ServerContext.focus`, per project, set by every successful function target, also with an
     explicit `binary!`) resolves an unqualified ambiguous name when that binary has exactly
     one such function. The response says so in one line: `binary tool.exe (current binary)`.
     An explicit `binary=`/`binary!` never uses the focus.

   Errors have one wording everywhere: `error not_found: no function or import
   named 'X' [in N ready binaries]. Use search …`, `error ambiguous: 'X' matches
   N functions: bin!name 0x…, …. Retry with binary!name or binary!address.`,
   `error bad_target: 'X' is <kind>, but this tool takes <kinds>. <next step>.`

10. **Name hints are targets, and data addresses find their binary.** Every name a tool prints for a
    function resolves as a target (`selectors.alias_functions`, after the exact and case-insensitive
    name): `Unit.Class.Method` / `Class.Method` / `Class::Method` of Delphi and FPC (published, RTTI
    and property accessor names, named virtual slots), `TClass::vslot N` (Delphi VMT or C++ vtable
    slot, a trailing `(+N classes)` or `(Name)` is ignored), and the IDR / signature names of
    `idr: Unit.Proc` (with or without the unit). Matching is case-insensitive; several functions
    (overloads) are `error ambiguous` with the addresses; one function resolves with a note line.
    A raw address that is no function (typed kind `address`, i.e. `xrefs`) in a project with several
    binaries and no binary given is looked up in every ready binary: one binary with references or a
    Delphi/FPC class there wins (note `binary x.exe`), several give `error ambiguous` with
    `binary!0xaddr` candidates. The VMT, type info or an address inside the virtual slots of a
    Delphi/FPC class (`server/classfwd.py`) adds one fact line to `xrefs` (`0x.. is the vmt of Delphi
    class vc.TBase`) and merges the references to the VMT and the type info (direction=from: every
    virtual slot); `function` on such an address shows the fact line, the class row, the `vslot`
    lines, the published/RTTI methods and the references. `vtable` takes a Delphi/FPC class name
    (also `unit.Class`) or such an address: `[N] 0xaddr function rtti: Unit.Class.Method; origin`
    with origin `new`, `override, introduced by X` or `inherited from Y[, introduced by X]`; N is
    the number of the `TClass::vslot N` hint. **[verified]** on a two-class Delphi 13 test program
    (`vtable TDerived`, `function 0x0041dcfc` on a 3-binary project, `function vc.TBase.Greet`).

### 7.4 Format

Plain text with a fixed, compact line layout, not JSON. JSON costs more
tokens for the same information and agents read the line format reliably.
Example `xrefs` output:

```
xrefs to CAppDoc::LoadSettings (0x004a1c20), 3 calls
  0x004a3310  CMainFrame::OnFileOpen       call
  0x004b0e48  CSettingsDlg::OnOK           call
  0x0045f1a2  FUN_0045f100                 call
```

Across binaries: `search` and `strings` without `binary` cover every ready
binary of the project when there are several (binaries not ready are skipped,
and the header says how many). Each hit line then starts with the binary
name in brackets (`[engine.dll] function Foo 0x10001000 user,64B`); with
`binary=` or a single binary there is no prefix. Ranking, dedup and kind
balance below apply to the merged list (the exact-name hits of all binaries
first, in binary order for ties), `limit` and cursors count merged lines. In
`strings` the binaries are interleaved round-robin so one cannot crowd out the
others.

Cross-binary lines (from the `xedge` table): `xrefs` direction `to` on an
exported function appends the importing side of other binaries, kind `import`:
`  [main.exe] 0x00401300  LoadDoc   import` (the importing thunk or import
slot; callers of a thunk are one `xrefs` away). On a thunk or import slot,
`xrefs` adds `→ engine.dll!Foo 0x10001000` after the header. `callgraph`
follows these links: a callee hop is `→ [engine.dll] Foo (0x10001000)`, a
caller hop `← [main.exe] LoadDoc (0x00401300) [thunk]`; a hop is an ordinary
edge for depth, `[cycle]` and `[seen]`.

Table links (`string_link`): a string held by a command/dispatch table record
next to its handler pointer has no code reference. `strings` appends
`  table: Handler1 Handler2` to the line (after `<- (no refs)` when there are
none), `xrefs` on the string address adds `  0x00404008  Handler  table
(record stride 0x8 2/3)` (kind `table`, address = first table slot; filter with
`kind=table`), and `function` (brief and full, any view) adds the note
`// table string "name", ...` as a name hint. Feature seeding treats the
handler as referencing the string.

`search` ordering and dedup (deterministic):

1. Kinds are balanced when `kind` is `any`: functions, imports and strings each
   get one slot first, then a share of `limit` (functions 40%, imports 20%,
   strings 20%); slots a kind cannot fill flow to the others, functions first.
   Code entry points therefore never get crowded out by string hits.
   `kind=function|import|string` applies no quotas.
2. Inside a kind: match rank (exact name, then prefix, then token match); real
   names before default-named (`FUN_…`) functions.
3. Remaining ties keep the full-text engine's order.
4. Output order is functions, imports, strings; each group in rank order.

String hits whose value equals an import name (case-sensitive) are dropped: they
are the import name table and duplicate the import rows. Identical string values
collapse to one line with the lowest address and `(+N copies)`.

An imported function exists as an EXTERNAL function row, usually a thunk and an
import row. The EXTERNAL row carries no code and a pseudo address, so it is
dropped when a non-external function or an import row has the same name; the
thunk and the import row stay. An EXTERNAL row with neither is printed as
`import-only DLL::Name`. `limit` applies after dedup and ranking (the search
fetches more candidates than `limit`); paging uses the usual cursor footer.

`function` over budget: when the reduced C does not fit the budget and no
`cursor` or `lines` is given, the response is an outline instead of page 1
(`outline=false` pages as usual): a header with line count, estimated tokens and
how to read on, the signature, the control skeleton (nesting levels 0 to `outline_depth`,
default 2, max 4, of `if`/`switch`/loops: blocks as `La-Lb text (N lines)`,
brace-less statements as one `Ln if (c) goto X` line, `do … while (c)` with its
condition, `LAB_x:` labels with their line and goto count; switch case labels
compressed into ranges), callees with call count and first line, and referenced strings with
line numbers. It is built by a line/brace scanner, not a C parser, and is cut
to the budget with the usual cursor footer.

`function view=asm` / `view=both`: the worker op `disassemble` (read lock,
concurrent lane) returns the function body in address order; Ghidra prints the
instruction (names resolved), a note lists resolved call/string/global targets,
jump targets inside the function become `LAB_x` labels. Output lines:
`0x00401000  PUSH EBP  ; → Name`, a `LAB_x:` line before each jump target, a
header `// name addr asm: lines a-b`, budget + cursor as for C (`lines=a-b`
selects asm lines). Basic-block starts without a label are not marked. The
formatted text is cached per function in
`<project>\dirty\.airlock\cache\asm\<binary id>_<entry hex>.json`, keyed by
fn_version and analysis_profile (derived data, deletable; no schema change). More
than 4000 instructions are cut with a `; … truncated at N of M` line. `view=both`
is the C section (`// C`, brace/call annotated, `detail` honoured, no outline)
followed by `// asm (N lines)` and the asm lines, one paged list; `lines` is
rejected for it.

### 7.5 Errors

One line, a code and what happened:
`error not_analysed: binary 'app.exe' is analysing (62%, 41s).`

**A tool does the next step itself and does not tell the agent what to do** (agents ignore
advice in output, HANDOVER "Agent evaluation"). It retries, widens, follows or forwards on its
own and says so in one short fact line (`(regex used: no literal match)`); where only the agent
can choose it lists the candidates or the cursor as data; where only the user can act it names
the fix in one fact line (`allow_writes is off in config.jsonc`). A name that is not found
resolves when one function matches it ignoring case (`resolved 'x' to X (case differs)`), else
the error lists close names (`close names: a 0x.., b 0x..`). `tests/test_no_hints.py` scans
the server's string literals for imperative hints. **[verified]**

### 7.6 No output schemas

Tools declare input schemas only, with short descriptions (one sentence plus
parameter names). No `outputSchema` is advertised.

---

## 8. Server ↔ worker protocol

- Transport: worker stdin/stdout, UTF-8, one JSON object per line. Worker
  stderr goes to `logs\worker.log`.
- Request: `{"id": 17, "op": "decompile", "args": {...}, "deadline_s": 60}`
- Response: `{"id": 17, "ok": true, "data": {...}}` or
  `{"id": 17, "ok": false, "error": {"code": "...", "message": "..."}}`
- Progress (unsolicited): `{"event": "progress", "job": "analysis", "pct": 62}`
- Lanes **[verified]**: `hello`, `status`, `cancel_*`, `decompile`,
  `decompile_batch`, `bulk_decompile` and `external_paths` run on their own
  threads; every other op runs one at a time on the main thread in arrival
  order (the JVM must start there). Responses carry the request id and may
  arrive in any order; protocol writes share one lock. The request pipe is
  moved off fd 0 (fd 0 points at NUL): a thread blocked reading the pipe makes
  `start_ghidra` hang on Windows otherwise.
- Bulk decompile: `bulk_decompile(program, order, timeout, cpu_min, cpu_max)`
  returns at once; events `decompile_results` (`job`, `ast_columns`, at most 50
  results or about 512 KB each) and `decompile_progress` (`state`, `done`,
  `total`, `rate`, `threads`, `processors`; terminal state last).
  `cancel_bulk(program)`; `decompile_batch(program, entries<=500, timeout)`
  answers like `decompile` per entry.
- Ops are internal (`import`, `analyze`, `list_functions`, `decompile`,
  `xrefs`, `rename`, ...), not one-to-one with MCP tools.
- Cancellation: `{"op": "cancel", "id": 17}`; decompiles honour it through the
  task monitor.
- Health: the server pings every 30 s while a request is outstanding; no reply
  for 120 s → worker is killed and restarted, the request returns
  `worker_restarted`.
- Writes are serialized: one write op at a time, each inside a Ghidra
  transaction, committed before the response.

---

## 9. Clean-room model

### Roles

- **Dirty session:** reads code, decompiles, writes notes and specifications.
- **Clean session:** sees only `spec_read`, `spec_list`, `spec_export`. Never
  sees code, addresses, bytes or notes.
- **Unbound session:** the state of every new session. Only `projects`,
  `project_open`, `project_create`, `program_scan` and `project_info` work;
  every other tool returns `error unbound: ...`.

Always-on tools (config cannot disable them; role gating still applies):

| Tool | Unbound | Dirty | Clean |
|---|---|---|---|
| `projects`, `project_open`, `project_info` | yes | yes | yes |
| `project_create`, `program_scan` | yes | yes | no |
| `index_status` | no | yes | no |
| `spec_read`, `spec_list` | no | yes | yes |

`spec_export` is clean-safe but can be disabled. Config can never add tools to
the clean role: it is the `clean_safe` tools only, and `disabled_*` can only
remove from them (never the always-on ones). A clean session therefore has
`spec_read`, `spec_list`, `spec_export` (unless disabled), `projects`,
`project_open`, `project_info`.

The role is chosen by the agent, with the user, not detected from the client's
folder, flags or environment. The server instructions tell the agent to start
with `projects` and `project_open(name, role)` (reverse engineering and specs:
dirty; implementation from specs: clean; ask the user when unclear). The
role is fixed for the life of the process: a second `project_open` or
`project_create` returns `error role_locked: ...`. Because a restart starts a
new unbound session, the user starts clean work in a new conversation.

The instructions also give the dirty workflow in one sentence (about 170 tokens in all, paid once per
session): `overview` first; `features`, `function_map` or `search` find the area; `function` reads code;
`xrefs`, `callgraph` and `path` follow it; `annotate` records findings; `spec_write` is for the clean side.
The cursor is named: "pass it back". Framework tools are not listed there; `overview` names them (below).

Agents do not act on hints, so the tools act themselves: `function` retries a decompile once after a transient worker
failure (worker restarted, JVM not running, file closed; such errors are never cached) and prints `retry=true` only if
that fails too; a name the tools print is accepted as a target (`Class::slot` of `qt_method`, `TClass.Method` of
`dl_method`, found by `search` as `function Class::name addr (Qt slot)`); `function` on a managed method returns the
`dotnet_decompile` text of that member.

`projects` and `project_info` are allowed in every role and are role-aware
(catalog flag `clean_safe`): in a clean session `projects` shows only name and
published spec count, and `project_info` only role, project name, version and
enabled tool names. No paths into `dirty\`, no binary names, no Ghidra paths.

The folders still matter to the clients. `project_create` writes deny rules into
`clean\` so that a client started there cannot read the sibling `dirty\`:

| Client | Deny rules written into `clean\` | Shell blocked? |
|---|---|---|
| Claude Code | `.claude\settings.json`: `permissions.deny` with `Read(//<abs>/dirty/**)` and `Edit(//<abs>/dirty/**)` (`//` = absolute from filesystem root, forward slashes; Windows drive form **[verify]**) | no: `cat`/`type` on the path still work; rules cover Read/Grep/Glob and @-mentions |
| OpenCode | `opencode.json`: `permission.external_directory {"*": "deny"}` (blocks paths outside the launch folder, bash included) **[verify]** | yes, for paths outside the launch folder **[verify]** |
| Codex | `.codex\config.toml`: permission profile `airlock-clean` denying `<abs>/dirty/**`; exact TOML nesting **[verify]** | per profile **[verify]** |

Existing user files in `clean\` are never overwritten: the JSON files are
merged, the Codex TOML is skipped when present. Relative `..\dirty` rules are
not used because their resolution is unconfirmed in all three clients.

- One registration of `airlock serve` per client, with no flags; the server
  loads automatically and the user just states the task.
- The server never guesses a role: an unbound session cannot reach any
  analysis or spec tool.
- The tool list is the same in every role (clients do not refresh tool lists
  reliably); tools outside the role return `error wrong_role: ...` and do
  nothing. Descriptions contain no program data.
- One agent session that both decompiles and implements is not clean room,
  whatever the tooling does. The two folders make the separation visible;
  the deny rules in `clean\` stop the clean agent's own file tools from
  reading `..\dirty` (not a guarantee).

### Publishing specs

Specs are written in the dirty session as `draft` into the project index,
with provenance. "Publish" (`spec_export` in the dirty role) writes the
`final` specs to `clean\specs\` as Markdown plus a `specs.json` index
(topic, title, version, status), without provenance, addresses or notes.
The clean role reads only `clean\specs\`; it never opens `dirty\.airlock\`.
Export publishes the latest version of each `final` topic under the prefix as
`specs\<topic>.md` (front matter: topic, title, version, status), rewrites `specs.json`
(`{"specs":[{topic,title,version,status,file}]}`) and `audit-summary.md`; topics under the
prefix that are no longer final are withdrawn (file and entry removed).

### Enforcement

- The clean profile refuses to start if its sets include any tool outside
  `spec_read`/`spec_list`/`spec_export`.
- `spec_read` returns only `spec.body`, `title`, `status`, `version`. It never
  returns `spec_provenance`.
- `spec_write` rejects a body that looks like code or carries addresses:
  - lines matching C/C++/Pascal statement patterns (`;` endings with
    assignments or calls, braces blocks, `begin`/`end` blocks),
  - Ghidra artefacts (`FUN_`, `DAT_`, `undefined4`, `param_1`, `local_`),
  - hex addresses in the image range of any binary in the project,
  - more than N consecutive hex bytes (a comma-separated list of plain decimal numbers, such as column widths, is not a byte run).
  The rejection names the offending line so the agent rewrites it as prose or
  as a data-layout table. This filter is a heuristic aid, not a guarantee; the
  reviewer remains responsible.
- A clean session never shows the dirty folder's path (`project_open` names only the clean and specs folders; the clean map scrubs it from the purpose text).
- Data layouts in specs use a neutral table form (field, offset, size,
  meaning), which describes the format without copying code.
- `spec_write` requires `sources`, stored in `spec_provenance` (dirty only). A line of `sources` that is not a valid form and holds spaces is prose: it is stored whole (commas kept) as an `observation` with its text, and the reply says so; other bad items list the accepted forms.
  `sources` is a list (newline, `;` or `,`) of `[method:]binary!function-or-address` items
  or bare method words (`decompile`, `file_diff`, `resources`, `observation`). Targets
  resolve with the §7.3 rules; a non-decompile method with an unresolvable target keeps
  just the method. `binary_id`, `function_id` and `address` are stored; re-extraction of a
  binary keeps the rows and clears only `function_id`.
- Filter details (module `server/specfilter.py`, errors `spec_has_code`,
  `spec_has_ghidra_names`, `spec_has_bytes`, `spec_has_address`; each names the line):
  N = 8 consecutive hex bytes; "image range" = `[image_base, highest known function or
  string address + 1 MB]` per binary; any pointer-sized hex literal (8+ digits) is also
  rejected; fenced code blocks are rejected; small values (field offsets, magic numbers of
  up to 7 digits) stay allowed. Title and body are both checked. Topics are lowercase path
  segments (`a-z0-9._-`), which also name the published file.
- Spec versions are immutable rows (`UNIQUE (topic, version)`); specs, provenance and audit
  are agent data and are never dropped by re-extraction or rebuild of derived rows.
- Audit: the `audit` table (`at`, `profile` = session role, `tool`, `args_digest`,
  `result_kind`, `detail` = `topic vN status`) is append-only. Dirty `spec_write` and each
  published spec in `spec_export` write a row; clean sessions never open the index, so their
  reads are not logged there.
- Target: every tool call is written to `audit` with profile, tool and an argument
  digest. Implemented so far: spec writes and publishes.

### Export

`spec_export` writes `specs\<topic>.md` plus `audit-summary.md` (counts per
tool and profile, date range). The clean side implements from the exported
document. `export-spec --with-provenance` is a dirty-only CLI command for the
legal file, never exposed as a tool.

### Legal basis (informational, not legal advice)

EU Directive 2009/24/EC, Article 6: decompilation is permitted where
indispensable to obtain the information necessary to achieve interoperability
of an independently created program, the information is not otherwise readily
available, and it is confined to the parts necessary. Article 8: contractual
provisions contrary to Article 6 are null and void. Interoperability with file
formats is the primary use case of this project.

---

## 10. Windows lifecycle

- **Job Object.** The server creates a job with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and assigns the worker to it at spawn
  (ctypes, no pywin32). When the server dies for any reason, the worker and
  its JVM die too.
- **Project locks.** No airlock-side lock removal is needed **[verified]**.
  On a local disk Ghidra locks the project with `ChannelLocker`, an OS
  file-channel lock on the lock file. When the holding process dies, the OS
  releases the channel lock, and the next open finds the file unlocked and
  takes it over. If a live Ghidra GUI holds the project, the open fails;
  airlock reports the holder from `getExistingLockFileInformation()` and tells
  the user to close the GUI.
- **Private artifact copy.** Imported binaries are copied first (§4), so an
  installed program that is running, updating or on a share does not matter.
- **JDK discovery** **[verified]**. With `jdk_dir` set, the worker assigns it
  to the PyGhidra launcher's `java_home` before start, skipping discovery.
  Without it, PyGhidra runs `java` from PATH (or `JAVA_HOME\bin\java` if
  `java` is not on PATH) to execute `support\LaunchSupport.jar -jdk_home
  -save`, which picks and remembers a JDK. Ghidra 12.1.4 requires Java 21+
  (`application.java.min=21`). PyGhidra sets `JAVA_HOME` inside the worker
  process itself; the user never sets it.
- **Logs.** Rotating by size (`logging.handlers.RotatingFileHandler`, 2 MB, 3 backups; constants
  in `airlock/logs.py`, no config keys). Machine logs in `%LOCALAPPDATA%\airlock\logs`:
  `server.log` (the `airlock` logger of the server process) and `worker.log` (the worker's stderr,
  piped through the server so it rotates too). Per-project events (analysis queue state changes,
  missing-function creation, relink, map and feature refresh errors) also go to the project's
  `dirty\.airlock\logs\project.log`. `project_info` and `index_status` name the paths. Nothing is
  written to the worker's stdout (the protocol stream).
- **Protocol isolation.** Before anything else runs, the worker duplicates its
  stdout for the protocol and points fd 1 (and, on Windows, `STD_OUTPUT_HANDLE`)
  at stderr, so output from Ghidra or the JVM can never corrupt the JSON
  stream. stderr goes to `logs\worker.log`.
- **Lifetime off Windows.** The worker exits when its stdin closes, which
  happens when the server exits or dies.
- **Paths.** `pathlib` everywhere; Ghidra receives forward-slash absolute
  paths. Tests include spaces and non-ASCII characters in project and binary
  paths.
- **Data location.** `%LOCALAPPDATA%` on a local NTFS volume; `doctor` warns
  if `index_dir` is on a network drive (SQLite WAL).
- **Defender.** Real-time scanning slows Ghidra's project writes. The README
  documents adding an exclusion for the data directory; airlock never changes
  security settings itself.
- **stdio.** Binary-safe UTF-8 for both the MCP transport and the worker pipe;
  no newline translation.

---

## 11. Toolchain analyzers

### MSVC exception-frame prolog helpers

- 32-bit static-CRT MSVC code starts most functions with a call to a tiny
  helper that builds the exception frame (`__EH_prolog`: `push -1; push eax;
  mov eax,fs:[0]; ...; ret`). Without a fixup the decompiler shows
  `unaff_EBP + -0x18` frame accesses and `extraout_ECX` in every caller **[verified]**.
- Ghidra 12.1.4 ships Function ID databases for VS2012 to VS2019 and
  `vsOlder` (x86 and x64), and the Function ID analyzer runs by default. It
  names and fixes up the larger helpers (`__SEH_prolog`, `__SEH_epilog`) but
  left the 30-byte `__EH_prolog` unnamed in the sample binary **[verified]**.
- `x86win.cspec` has a call fixup (`EH_prolog`, inline p-code) for it. Renaming
  the function is not enough; `Function.setCallFixup("EH_prolog")` is required.
  With it, `unaff_EBP` drops from 335 to 0 over 20 sampled callers **[verified]**.
- airlock therefore runs `ghidra_ops/fixups.py` after auto-analysis: it matches
  helpers by exact entry bytes, names them and sets the fixup. It is part of
  the collector version; existing projects get it through `apply_fixups` on resume.
- The `unknown` calling convention on most functions is Ghidra's default before
  parameter analysis and is not what causes the frame-access noise **[verified]**.

### x86 calling conventions (`__thiscall` detection)

- Ghidra 12.1.4 lists "Decompiler Parameter ID" and "Call Convention ID" as enabled in
  the analysis options, but on a large static-MFC 32-bit binary (about 14,400
  functions) 82% of the functions kept the convention `unknown` and the DEFAULT
  signature source after airlock's auto-analysis **[verified]**. The reason is not
  established; on a 3,500-function 32-bit exe the same analysis set every convention.
- Running the Decompiler Parameter ID analyzer once afterwards
  (`AutoAnalysisManager.scheduleOneTimeAnalysis` over the loaded memory, then
  `startAnalysis`) took 86 s on the 14,400 functions (about 6 ms each) and set every
  convention plus parameter types **[verified]**. It tries `__fastcall` first, so plain
  this-calls (ECX only) come out as `__fastcall` with `param_1` in ECX: 2,372 of
  14,400 functions, about 2,300 of them wrong **[verified]**.
- airlock's post-analysis step (`fixups.apply_all`, run after auto-analysis and by the
  worker op `apply_fixups` on existing projects) therefore does, in order: prolog helper
  fixups; Decompiler Parameter ID when more than 5% of functions have no convention
  (config `decompiler_parameter_id`, default true); `__fastcall` functions whose
  instructions read only ECX are relabelled `__thiscall` through `Function.updateFunction`
  with the ECX parameter dropped, so the decompiler shows `this` instead of a stale
  `param_1` **[verified]**; then an instruction-only classifier (entry path reads ECX
  before writing it, callers load ECX before the CALL, `RET n` / caller `ADD ESP`) for
  functions still without a convention (13 s over 14,400 functions).
- `Function.updateFunction` lives on a nested enum: `Function.FunctionUpdateType`.
- `COLLECTOR_VERSION` is part of `analysis_profile`. The server stores the collector
  version per binary (meta `collector:<id>`) and `resume_project` runs `apply_fixups`
  for binaries with an older one: no re-analysis, 1.3 s when nothing is left to do.

### MSVC RTTI and vtables

- Parsed server side from the PE bytes with pefile (`server/cpp.py`), no worker: sections, image
  base and pointer size come from the PE header, never constants. Rows go to `rtti_class`,
  `vtable_slot`, `msgmap_entry` (schema v10, derived; `mfc_class` and `mfc_map_entry` from schema v14, below). They are filled when a binary becomes ready
  and, for old projects, on open when meta `cpp_version:<binary id>` is older than `CPP_VERSION`
  (about 0.1 s per megabyte; no re-analysis).
- 32-bit: Complete Object Locator holds absolute pointers (signature 0).
- 64-bit: COL holds image-relative offsets (signature 1, and a `pSelf` field).
- Walk: type descriptor (`.?AV…@@`, `.?AU…@@`; `pVFTable`, `spare`, name) → COL (found as the
  dword that references the descriptor, 12 bytes into the COL) → vtable at the address that holds
  the COL pointer + pointer size; slots run while they point into an executable section.
  Base classes from the Class Hierarchy Descriptor: the base array is a pre-order list, so the direct
  bases are found by skipping `numContainedBases` entries; `bases` stores the direct ones.
- Class names are demangled to `A::B`; templates go through `dbghelp` (Windows) with a plain fallback.
- One row per (type descriptor, COL): a class with several vtables (multiple inheritance, COL
  `offset` != 0) has several rows; the lowest vtable address of a COL wins.
- A class compiled without `/GR` has no COL: it gets no `rtti_class` row (its message map is still
  found, see below). Statically linked MFC usually carries RTTI for the framework classes; 32-bit MFC
  DLLs of the VS2005-VS2015 generation carry type descriptors but no COLs **[verified]**.
- Name hints: `function` shows `// Class::vslot N` for a vtable target and
  `// handler WM_COMMAND id N of Class` for a message map handler. Nothing is renamed in Ghidra.
  vtable targets and handlers need not be function entries in the Ghidra index (unreferenced code
  that analysis did not turn into a function); the hint only shows where a function exists.

### MFC message maps

- `GetMessageMap` is virtual in every `CCmdTarget`-derived class. airlock does not look for a fixed
  slot: it decodes every vtable slot target (and, for classes without RTTI, every code pointer in the
  data sections) as a trivial getter and keeps those whose constant is a valid `AFX_MSGMAP`.
  Getter shapes: 32-bit `mov eax, imm32; ret`, also with a frame (`push ebp; mov ebp,esp; [push ecx;
  mov [ebp-4],ecx;] mov eax,imm32; [pop ebp | leave]; ret`); 64-bit `lea rax,[rip+d]; ret`; the
  `_AFXDLL` form that jumps or calls into `GetThisMessageMap` (`jmp rel32`, `call rel32; ret`,
  `sub rsp,28h; call; add rsp,28h; ret`) is followed up to four hops.
- `AFX_MSGMAP`: two pointers, `pfnGetBaseMap` (DLL MFC: a function; static MFC: the base class
  `AFX_MSGMAP`) and `lpEntries`.
- `AFX_MSGMAP_ENTRY`: `nMessage`, `nCode`, `nID`, `nLastID` (4 x u32), `nSig` (`UINT_PTR`), `pfn`
  (member function pointer, a code address); the table ends with an all-zero entry. **[verified]**
  32-bit: 6 x u32 = 24 bytes; 64-bit: 4 x u32, u64, u64 = 32 bytes (no padding: `nSig` is at +16).
  Checked on real data: MFC 4.0 (32-bit DLL), a statically linked 32-bit MFC program, and the 64-bit
  MFC 10, 12 and 14 DLLs (hundreds of maps each): every map ends with an all-zero entry of that size,
  every `pfn` is a code address, `nSig` values agree between 32-bit and 64-bit (same `AfxSig_*`
  enum), and in 64-bit the upper half of `nSig` is zero except for registered messages.
  Registered messages (`ON_REGISTERED_MESSAGE`) have `nMessage` 0xC000 and `nSig` holds the address
  of the message variable (a pointer, so up to 64 bits). `ON_UPDATE_COMMAND_UI` is `WM_COMMAND`
  with `nCode` 0xFFFFFFFF; `ON_COMMAND` has `nCode` 0; `ON_CONTROL` carries the notification code.
- A map is attributed to the class whose vtable returns it; a derived class that only inherits the
  slot (same getter) is not listed (the base, an ancestor of the others, is). Maps of classes
  without RTTI start as `anon_<map address>` and get a better name from "MFC classes without RTTI" below
  (otherwise they keep it). The tool `mfc_message_maps <class>` follows the recorded base classes to the
  nearest class with a map.
- **Join** (`server/uijoin.py`, computed per binary on demand, nothing stored): `msgmap_entry.ctrl_id ..
  last_id` (ranges included) x `res_control.ctrl_id` / `res_menu_item.item_id`, `WM_COMMAND` and
  `WM_NOTIFY` entries only. `ON_COMMAND` (code 0) is the menu command, `UPDATE_COMMAND_UI` (code
  0xFFFFFFFF) the update handler; for a dialog control every code counts and is named by the control
  class (`BN_CLICKED`, `EN_CHANGE`, `CBN_SELCHANGE`, `NM_CLICK`, ...). A handler shows as `Class::name`;
  a function without a name of its own (no row, or a default `FUN_` name) shows `Class::OnXxx (FUN_00401000)`, see "Handler names". Ids that occur in several menus or
  dialogs list every place, compact (3, then `+N`). Ids 0, 0xFFFF and -1 (static text) never join.
- **Framework noise**: an entry whose id range spans (almost) the whole id space
  (width >= 0xF000, e.g. `ON_NOTIFY_EX_RANGE(.., 0, 0xFFFF)` tooltip / chevron handlers of
  `CFrameWnd`) matches every control. It is also noise when it is a range or a `WM_NOTIFY` entry
  whose handler is runtime code (an MFC framework class, or a function the runtime rules recognise).
  Noise entries are not shown on `menus` / `dialogs` lines, in function hints, in the class-dialog
  link or as feature seeds (`UiIndex.is_noise`); `mfc_message_maps` still lists them. Single-id
  `WM_COMMAND` entries of framework classes (`CWinApp::OnFileNew`) are kept.
- **Dialog of a class**: a class's dialog is the dialog that contains every control id its map handles.
  At least one of the ids must be specific (not IDOK..IDHELP = 1..9), a class whose ids include menu
  ids is a frame/view and gets none, and more than 3 candidate dialogs give none. A dialog shows its
  classes (`dialogs`), a class its dialog (`mfc_message_maps`). Best effort.
- **Consumers**: `menus`, `dialogs`, `mfc_message_maps` (above); `function` adds `// handler for menu
  "File > Open..."` or `// handler for button "OK" in dialog 101` (`update handler for ...` for
  `UPDATE_COMMAND_UI`); the features `ui-menu` and `ui-dialog` get the handlers as strong seeds with
  evidence `menu "File > Open..."` / `dialog 101 button "OK"` (`FEATURES_VERSION` 4, 5 without framework noise); the project map
  adds a line `UI: N dialogs, M menus; handlers mapped: ...` under each binary that has resources.
- **Missing functions** (`server/fnfix.py`, worker op `create_functions`): handlers and vtable slot targets
  (slots exist only for vtables of RTTI classes) that are no function entry in the index are code proven
  by a static table that Ghidra's flow never reached. After `cpp.ensure` (when a binary becomes ready, and
  on project open for old projects) the server sends them to `create_functions`: per address, in one
  transaction under the write lock, it checks an initialised executable block, skips an address inside
  another function's body (`inside_function`, never split) or in the middle of an instruction, clears a
  defined data unit that starts exactly there, disassembles, runs `CreateFunctionCmd`, then sets the
  conventions of the new functions (`fixups.apply_conventions`) and saves. The server re-reads the binary's
  functions (upsert: ids and decompiles of unchanged rows stay) and replaces its edges, relinks, and records
  meta `fnfix_version:<id>` and `fnfix_info:<id>` (counts and reasons). Failed addresses are not retried
  until `FIX_VERSION` is bumped. **[verified]** on notepad (gap address, existing entry, non-code address).

### MFC classes without RTTI

Server side, from the PE bytes (`server/mfc.py`, called by `cpp.derive_binary`, `CPP_VERSION` 3). Most
program classes of an MFC application are built without `/GR`, so `find_msgmaps` only knows their map as
`anon_<map address>`. The framework offers more sources, all found without symbols:

- **`CRuntimeClass`** (`DECLARE_DYNAMIC` / `DYNCREATE` / `SERIAL`): `lpszClassName`, `nObjectSize`,
  `wSchema` (0xFFFF or the schema, bit 31 = versionable), `pfnCreateObject` (code or 0), `pBaseClass`,
  `pNextClass`, `pClassInit`; five pointers and two u32, no padding: 28 bytes (32-bit), 48 bytes (64-bit).
  Found by scanning the data sections for a pointer to an identifier string followed by a plausible size
  and schema; the base pointer must be 0, another runtime class, or a function (`_AFXDLL`:
  `pfnGetBaseClass`). **[verified]** on a static 32-bit MFC program (the base chains end in the framework
  classes), on 32-bit MFC DLL users and on the 64-bit MFC 10..12 DLLs.
- **`GetRuntimeClass` is slot 0** of every `CObject` vtable and a trivial getter returning `&classX`.
  A vtable therefore starts at the slot whose getter returns a `CRuntimeClass`; `GetMessageMap`,
  `GetDispatchMap`, `GetInterfaceMap` and `GetEventSinkMap` are later slots of the same vtable (up to the
  next such slot). Vtables of RTTI classes are skipped here: RTTI already names them.
- **Owner of a runtime class.** A class without `DECLARE_DYNAMIC` inherits the slot and so returns its
  base's `CRuntimeClass`. The compiler emits a class's `CRuntimeClass` and its vtable together, so the
  owner is the closest vtable behind the structure (at most `NEAR` = 0x4000 bytes; a control's dispatch
  tables can sit in between). A binary that keeps them apart falls back to "the only vtable of the class".
  Checked against RTTI as ground truth (the RTTI vtables treated as anonymous) on several programs and DLLs:
  almost all owners were right; the misses were framework classes whose own vtable was not found.
- **Names** (`msgmap_entry.class` is rewritten, derived data), in this order: the runtime class name for the
  owner; the class (namespace) that the disassembler gave the functions of the class (`symbols`: a PDB,
  exports, renames; `mfc.symbol_class`: handlers of the map and the vtable slots, at least two votes and two
  thirds of the namespaced functions, framework classes and non-identifiers do not vote); `Dialog_<caption>`
  (`_<id>` when the caption repeats) for a class whose constructor passes a dialog resource id to the base
  constructor, or (base runtime class named *Dialog, *Page, *FormView, *Sheet or *Wizard) a class whose map
  handles single `WM_COMMAND` / `WM_NOTIFY` ids that exactly one dialog resource contains, one of them above
  IDHELP (`mfc.map_dialog`); `anon_<Base>_<map address>` for a class that inherits the runtime class of
  `<Base>` (so the base is known); `anon_<map address>` when nothing identifies it. A map reachable from
  several vtables goes to the owner whose runtime class is an ancestor of the others, and is left alone when
  that is not unique. `mfc_class.source`: `rc` | `symbols` | `dialog` | `inherited` | `routes`. **[verified]**
  on a 32-bit static MFC program: the dialog classes get their names; the derived classes left over are
  window sub-classes (CEdit / CStatic / CListBox / CWnd bases) with no command ids and no string in their
  constructors that names them; no source in the binary names them (RTTI is absent, and so are file-name
  strings in a release build).
- **Dialog id from the constructor**: the constructor loads the id, calls the `CDialog` constructor, then
  stores the vtable pointer. 32-bit: locate the `mov [reg], imm32` with the vtable address in code and read
  the 96 bytes before it for `push imm; ...; call rel32` with the call at most 28 bytes before the store.
  64-bit: locate `lea reg, [rip+d]` that resolves to the vtable, followed within 4 bytes by `mov [reg2], reg`
  (the store to offset 0), and read the 96 bytes before it for `mov edx, imm32` (or `mov r8d, imm32`) ...
  `call rel32` with the call at most 28 bytes before the `lea`. The id must be a dialog resource of the
  binary and the call target must be shared by at least two classes. **[verified]** 32-bit on a program with
  dozens of dialog classes (the captions match the class purpose). The 64-bit form follows the MSVC x64
  constructor shape and is covered by unit tests only **[verify]** (no 64-bit MFC program without RTTI
  was at hand: every 64-bit MFC binary found has RTTI).
- **`mfc_class`** (schema v14): `name`, `vtable_addr` (the `GetRuntimeClass` slot), `rc_addr`, `obj_size`,
  `schema`, `base` (the owner of the base message map, else the base runtime class), `map_addr`,
  `dialog` (resource id), `source` (`rc` | `dialog` | `inherited` | `routes`, see "Route tables").
  Rows only for classes without RTTI.

**Handler names.** Nothing is renamed in Ghidra. `UiIndex.suggest` builds a ClassWizard style name from
the message and the UI element: `OnCommand_<id>_<menu leaf>` for a menu item, `OnUpdateCommand_<id>_<leaf>`,
`OnBnClicked_<button caption>`, `OnEnChange_<caption or id>` (the notification name in camel case),
`OnCommand_<lo>_<hi>` for a range, `OnNotify_<code>_<id>` for an unknown `WM_NOTIFY`, `OnSize`, `OnPaint`,
... for window messages (table `STD_HANDLERS`), `OnMessage_<WM name>` otherwise. It is shown where a
handler has no name of its own (`uijoin.is_unnamed`: no function row, or `name_state` auto with a `FUN_`
style name): `menus` / `dialogs` lines as `Class::OnXxx (FUN_00401000)`, `mfc_message_maps` entry lines as
`as OnXxx`, and `function` as the hint `likely Class::OnXxx`. The target tools (`function`, `xrefs`, ...)
accept these names: `Class::OnXxx`, also with the ` (FUN_..)` tail or without the class, any case
(`targets._mfc_handler_addrs`, after the real names and the Qt / Delphi names; one handler only).

### Route tables (MFC look-alike frameworks)

Some programs drop MFC for an own framework that keeps the MFC class names (`CWnd`, `CFrameWnd`,
`CCmdUI`) and the command routing but not `AFX_MSGMAP` (`server/routes.py`, `CPP_VERSION` 3). Seen in
WinDirStat 2.9.3 (`UiTypes.h`: `RouteEntry`, `RouteTable`, `MessageTarget<Derived, Base>`). **[verified]**
on that binary (64-bit) against its source.

- **Entry** `RouteEntry {u32 message, code, firstId, lastId; invoke; registeredMessage}`: 32 bytes in
  64-bit, 24 in 32-bit. `invoke` is a template thunk `InvokeCommandHandler<&Class::OnX>` that calls the
  member function; `registeredMessage` points to the id of a registered message (`message` is then 0,
  stored as 0xC000). `Route::Command` has code 0, `Route::Update` 0xFFFFFFFF (as MFC), `Route::Window`
  carries no code or ids. The tables are `static constexpr std::array` without terminator, often side by
  side in `.rdata`, so nothing marks where one ends.
- **Table** `RouteTable {base, span<entries>}` is a function-local static that `GetStaticRouteTable`
  fills on first use, so it is zero in the file. The initialiser names everything: 64-bit
  `mov qword [rip+T+16], count` ... `lea r, [rip+entries]; mov [rip+T+8], r`, and the base table goes to
  `[rip+T]` (`lea rax, [rip+B]`, or `call` of the base's getter). Each candidate is kept only when all
  `count` rows are valid (invoke a code address, message 1..0xFFFF or a registered one, first <= last,
  window messages without code and ids). 32-bit: `mov dword [T+4], entries` / `[T+8], count` **[verify]**.
- **Class**: `GetRouteTable` (a vtable slot, often folded with `GetStaticRouteTable`, or a `jmp` to it)
  ends in `lea rax, [rip+T]; ... ret`. The vtable starts at the closest address before that slot that
  code loads (`lea r, [rip+X]`), with only code pointers in between. Without RTTI the map keeps the name
  `anon_<entries address>`; `mfc_class` gets a row with `source` `routes`, the vtable and the base map's
  name, and `mfc_message_maps` prints `route table, vtable 0x.., base anon_..` on the map line.
- **Handler**: the first direct `call` in the invoker whose `rcx` holds the incoming `rdx` (the target
  object; register moves tracked, loads clear a register). An invoker with the handler inlined keeps its
  own address. Only 64-bit invokers are followed.

### MFC dispatch, interface and event sink maps (OLE automation)

Same discovery as the message maps (`mfc.kind_of`): a trivial getter that returns the address of a static
structure of one of these shapes. `cpp` owns the message maps; the rest is tried as dispatch map, event
sink map, interface map, and every structure must parse to its terminator, so neighbours do not
cross-match. RTTI classes get them from their vtable slots (a map shared through an inherited slot goes
to the ancestor, as for message maps); classes without RTTI through the vtable groups above (owner groups
only). `GetDispatchMap` and `GetInterfaceMap` are `CCmdTarget` virtuals; `GetEventSinkMap` belongs to
classes with `DECLARE_EVENTSINK_MAP` (dialogs hosting ActiveX controls).

- `AFX_DISPMAP`: `pBaseMap` (static) or `pfnGetBaseMap` (`_AFXDLL`), `lpEntries`, `lpEntryCount` (a `UINT`
  that MFC fills at run time, so it is not read: the table ends with the entry whose `lpszName` is NULL and
  `nPropOffset` is -1), `lpStockPropMask`. **[verified]**
- `AFX_DISPMAP_ENTRY` (natural alignment): `lpszName` (ptr), `lDispID` (i32), `lpszParams` (ptr, `VTS_*`
  bytes, NULL for none), `vt` (u16), `pfn`, `pfnSet`, `nPropOffset` (ptrs), `flags` (u32, `afxDispStock` =
  1). 32 bytes in 32-bit, 64 bytes in 64-bit (padding after `lDispID`, `vt` and `flags`). **[verified]** in
  32-bit on a program (method names, ids 1..N, `double&` out parameters, `BSTR` returns) and on an ActiveX
  control (`DISP_PROPERTY_NOTIFY` entries). The 64-bit layout is the same struct with 8-byte pointers
  **[verified]** on a 64-bit MFC ActiveX control of Windows (a Unicode build, 13 entries: one property with
  getter and setter, 12 methods; the table ends with the NULL / -1 entry, every `pfn` is a code address, the
  `VTS_*` bytes read as plausible argument lists, `lDispID` is -1 for all). `lpszName` is an `LPCTSTR`: **UTF-16
  in a Unicode build** (a name read as ANSI shows one letter), `mfc.disp_name` reads both **[verified]**.
- Kind of an entry: `flags & 1` stock property (name empty, id from the stock table `STOCK_DISPIDS`);
  `pfn` and no `pfnSet`: method (`VTS_*` argument bytes: 2 short, 3 long, 4 float, 5 double, 8 BSTR,
  9 IDispatch*, 11 BOOL, 12 VARIANT, 0x4E `VTS_BSTR` = LPCSTR, 0x40 or'ed = by reference; `vt` is the
  return type); `pfn` and `pfnSet`: property with getter and setter; no `pfn`: data member at
  `nPropOffset`, `pfnSet` then is the after-set notification (`DISP_PROPERTY_NOTIFY`). `lDispID` -1
  (`DISPID_UNKNOWN`) is shown as `auto`.
- `AFX_INTERFACEMAP`: base map, `pEntry` -> `{ piid (ptr to a GUID), nOffset (size_t) }` ending with
  `{ NULL, -1 }`. Shown as `interface IDispatch offset 0x10`; known IIDs (table `_IIDS`) by name, else the
  GUID. **[verified]** in 32-bit (IDispatch, IUnknown, OLE document interfaces) and on the 64-bit MFC DLLs.
- `AFX_CONNECTIONMAP` (connection points): the same two pointers and the same entry as the interface map
  (`piid` of an outgoing interface, `nOffset` of the `CConnectionPoint` member), so the shape cannot tell
  them apart. The vtable can: in a `CCmdTarget` vtable `GetConnectionMap` is the slot right before
  `GetInterfaceMap` (slot 15 and 16 after `GetRuntimeClass` is slot 0 of the group), so two different
  interface-shaped maps in adjacent slots are (connection map, interface map) (`mfc.mark_connections`; a lone
  interface-shaped map stays an interface map). Shown as `connection IPropertyNotifySink offset 0x2c8`, rows
  `kind` = `connection`. **[verified]** on the 64-bit MFC 4.2 DLLs: `COleControl` has one connection entry
  (`IPropertyNotifySink`) in the slot before its interface map (a long list of OLE interfaces); the same adjacent pair
  appears nowhere else. The empty `CCmdTarget` map is not stored (a map needs an entry).
- `AFX_EVENTSINKMAP`: base, `lpEntries`, `lpEntryCount`; entry = `AFX_DISPMAP_ENTRY` + `nCtrlIDFirst` +
  `nCtrlIDLast` (u32), ends like a dispatch map. Shown as `event dispid 7 ctrl 1000 -> handler`.
  **[verified]** in 32-bit (a dialog hosting a browser control) and on the 64-bit MFC DLLs.
- Rows: `mfc_map_entry(binary_id, class, kind, map_addr, seq, name, id, vt, flags, pfn, pfn_set, extra)`,
  `kind` = dispatch | interface | event | connection; `extra` holds the argument types, the data offset or the
  control ids. `pfn` and `pfn_set` are candidates for the missing-function pass (`fnfix`, `FIX_VERSION` 4).
- `CPP_VERSION` 4 (connection maps, 64-bit constructors, symbol and dialog-join names, UTF-16 dispatch names)
  makes old projects derive again on open; no schema change (`kind` is free text).
- Old projects: `CPP_VERSION` 2 makes `cpp.ensure_project` derive again on open (about 0.1 s per
  megabyte, no re-analysis); the schema migration only creates the two tables.

### Qt metaobjects

- Parsed from the PE bytes in `server/qt.py` (tables `qt_class`, `qt_method`, `qt_prop`, `qt_enum`, `qt_connect`, schema v13, meta `qt_version:<id>`). Scan: every pointer-wide word in the data sections whose next two words point into the image and whose second target starts with a plausible header; the class name must decode.
- `QMetaObject::d` Qt5: `superdata, stringdata, data, static_metacall, relatedMetaObjects, extradata` (6 pointers) **[verified]** on 64-bit MSVC and 32-bit MinGW builds. Qt6 adds `metaTypes` before `extradata` (7 pointers) **[verified]** (Qt 6.10.2, 64-bit MSVC, all Qt6 DLLs of a desktop client). With `QT_NO_DATA_RELOCATION` (Windows) `superdata` is a two word `SuperData {direct, getter}`: 8 pointers, `direct` is 0 in the file, the `QMetaObject` starts one pointer before the getter word **[verified]** (all 73 exported `staticMetaObject` of Qt6Core.dll are at scan address minus 8). The getter is a `jmp` thunk to `lea rax,[rip+d]; ret` (parent in the same image) or `mov rax,[rip+d]; ret` (the import slot of the parent's `staticMetaObject`: the parent class comes from the import name) **[verified]**: every parent of a program with 135 metaobjects is found without the worker.
- `data` header, 14 words: revision, className, classInfo(count, offset), methods, properties, enums, constructors, flags, signalCount **[verified]** (revision 8 = Qt 5.12 to 5.15; revision 7 occurs in a few internal classes). Method record 5 words (name, argc, parameters, tag, flags), parameter block `ret, types, names`, bit 31 of a type word = string index, else a `QMetaType` id **[verified]**; access = flags & 3, kind = flags & 0xc (signal 4, slot 8), cloned 0x20; the first `signalCount` methods are the signals **[verified]**. Property record 3 words (name, type, flags) plus a notify-id array of `propertyCount` words when any property has the Notify flag **[verified]** against the notify signals of Qt classes with known sources. Enum record 5 words from revision 8 (name, alias, flags, count, data) **[verified]**; 4 words for revision 7 **[verify]**. Qt6 (revision 9 and up): method 6 words, property 5 words (name, type, flags, notifyId, revision) **[verified]**; revision 13 seen (Qt 6.10.2), no revision between 9 and 12 seen. Qt6 has no Notify property flag: `notifyId` is 0xFFFFFFFF or the signal index (fixed: the Notify flag was required before). Type slots use `QMetaType` ids of QtCore or string indices; no unknown id in 120 binaries **[verified]**. Signals, slots, order, overloads and cloned signals equal the public source of the program (checked on two classes, version drift aside).
- String data Qt5: `QByteArrayData[]` of 16 (32-bit) or 24 (64-bit) bytes, `ref = -1`, `size`, `alloc`, `offset` relative to the item **[verified]**. Qt6 since 6.4: `uint offsetsAndSizes[]` pairs, offset relative to the array **[verified]** (revision 13); the reader tries both.
- Superclass: `d.superdata` is a pointer for a parent in the same image **[verified]**; for a parent in another DLL it is 0 in the file and the program fills it at start-up. Worker op `qt_dispatch` finds the store to the field, traces the source register back to the load of the import `staticMetaObject` and reads the class from its (MSVC, Itanium or demangled) name **[verified]** on a MinGW 32-bit build (every imported parent found).
- Method to function: `qt_dispatch` decompiles `d.static_metacall` and walks the tokens. The `InvokeMetaMethod` switch is the one whose case labels fit the method count best; the first call to a function of the program in each case is the method. Small classes (the compiler drops the switch) use `if (id == K)` blocks; a class with one method uses the first call. Signals the compiler inlined into the dispatcher (a call to `QMetaObject::activate` only) are taken from the `IndexOfMethod` branch (`== signalFunction` then `*result = index`). **[verified]** on both builds: about 94% of signals and 75% to 100% of slots and invokable methods are mapped. Limits: a method inlined into the dispatcher maps nothing; inherited methods are not in the switch; property accessors (ReadProperty/WriteProperty) are not mapped.
- String connections: `QObject::connect` with `SIGNAL("2name(args)")` and `SLOT("1name(args)")` strings. Each connect call takes the two closest signal/slot strings of its function; without identifiable connect call edges adjacent strings are paired (a 32-bit cdecl call pushes the slot first, so both orders are accepted). Connected classes are looked up by normalised signature (const and & removed).
- Pointer-to-member connects (`QObject::connectImpl`), Qt6 64-bit MSVC **[verified]**: (1) Why the call sites were missing: Ghidra files a C++ import under the class namespace of the external library, so the `import` table has no row for it and a call through the import slot is only a `read` edge to the slot (`dst_fn` NULL). `qt.fill_imports` adds the missing rows from the PE import table (`Class::method`, MSVC names only), `derive_connects` takes the `read` edges to the slots of `QObject::connect(Impl)` as call sites (kind `ptr`). (2) The function returns `QMetaObject::Connection` by value, so the first argument is the result pointer: sender, signal pointer, receiver, slot pointer, slot object are arguments 2 to 6. (3) Worker op `qt_connects` decompiles the function of each site and gives every argument a symbolic value (`_Flow`: constant, import slot read, parameter, stack slot, `new` result). The signal pointer points at a stack slot that holds the member pointer; the slot object is `new`-ed with the `impl` function at +8 and the slot (a member pointer, or the captured lambda) at +0x10. A member pointer to an imported signal is the *content of an import slot* (name from the external reference of the slot); to a signal of the binary it is the address of the moc function (or its thunk), whose `QMetaObject::activate(this, &staticMetaObject, index, argv)` call gives class and index. (4) A call site that only forwards parameters (a template instance kept as a function of its own) is chased up the callers (4 levels, 12 callers each) until the signal is a constant; the connection is filed at the call that holds the constants. Instances without any caller (kept by an incremental link, never called) stay unresolved.
- Pointer-to-member connects on Qt5 MSVC x64 and Qt5 MinGW 32-bit (Itanium) **[verified]** on real programs checked against their sources: (1) The Qt5 call and the Qt5 `QSlotObject` have the same shape as Qt6 (result pointer, sender, signal, receiver, slot, slot object; `m_impl` at one pointer, the member pointer at two pointers), so the 64-bit MSVC code works unchanged. The offsets now come from the pointer size. (2) Itanium imports are named `_ZN7QObject11connectImplE...`; `qt.import_qualname` reads plain nested names, constructors and destructors, and `fill_imports` adds them like the MSVC names. (3) MinGW loads the import into a register once (`mov edi,[slot]`) and calls it from there, so only one `read` edge exists for many calls. A site that is no call stands for every `connectImpl` call of its function (worker result `expanded`). (4) Ghidra cannot demangle the `connectImpl` name of MinGW, so the decompiler shows the call without arguments. The worker gives the imported `connectImpl` a nine pointer signature once (`ANALYSIS` source, saved with the project) and the arguments appear. (5) The decompiler drops the stores that fill the member pointer on the stack when only the slot address goes to a call; `MOV [stack slot], imm` instructions are read as a fallback. (6) The string form has the same register problem: strings that no call site claimed are paired in order. Such pairs, and all pairs of a binary without a connect function, are guesses: `qt_connect` kind `string-guess`, shown with a `~` and counted apart. After the signature change the worker result carries `stats.signatures`, and the server bumps `function.version` of every caller of `connectImpl` (`bump_connect_callers`), so cached decompiles are recomputed. (7) Itanium member pointers have two words; an odd first word below 0x4000 is a virtual function (vtable offset plus one) and is filed as `vtable+0x..` with `slot_kind` virtual. Virtual pointers: see (9). (8) The import table of the server is sent to the worker (`imports`), so an imported signal is named even where Ghidra has no external reference on the slot. A wrapper with a constant signal and a slot parameter is chased up the callers; a chased result counts for the site where it started (`origin`).
- Virtual member pointers, uncalled instances, 64-bit MinGW (Itanium names, Win64 convention) **[verified]** on real programs checked against their sources: (9) MSVC passes a pointer to a virtual member as the address of a vcall thunk (`mov rax,[rcx]; jmp [rax+off]`, 32-bit `mov eax,[ecx]; jmp [eax+off]`); Itanium has the vtable offset plus one. Both give a vtable byte offset. The receiver class comes from the connect: `this` of a constructor (a store of a vtable address into `this`) or of a known method, or an object `new`-ed in the function and passed to its constructor. The slot is then the word at that offset in the vtable (thunks followed; a stub `jmp [import]` of an inherited library virtual gives the import name, slot kind `ext`); without a class it stays `vtable+0x..`. The server sends the worker `vtables` (address point to class), `fnclass` (function to class) and `primary` (class to its only vtable): `qt.class_vtables` finds a Qt vtable without RTTI because `metaObject()` is a small function that reads the class's `QMetaObject` and sits in slot 0, and adds the RTTI vtables. A subclass without `Q_OBJECT` shares the three moc functions, so the parent then has no `primary`. (10) A member pointer stored as one 16 byte value is a `PIECE` op; its low part is the pointer. (11) `_Flow.value` and `slot_value` are memoised and bounded in depth and in time per site (`SITE_BUDGET_S`); before that a huge initialisation function made the walk exponential, and a recursion error silently dropped the site. A decompile that times out is tried once more with a longer timeout. (12) A call site in a function that nothing refers to except the unwind table (a template instance the linker kept) is not a live connection: it is filed with `slot_kind` `uncalled`, listed apart and left out of the resolved/total count. `DISPATCH_VERSION` 4. 64-bit MinGW needed no other change: sret in `rcx`, sender, signal, receiver in `rdx`, `r8`, `r9`, slot and slot object on the stack, member pointers as two words, and the Win64 `ABI` shows up in the decompiler as the same argument order.
- Receiver classes, 32-bit MinGW vtables, unwind-only instances **[verified]** on real programs checked against their sources: (13) More sources for the class of the receiver of a virtual member pointer, each used only when the answer is unique: a parameter (also `this` of a method of unknown class) that every caller fills with objects of one class (thunks are looked through); an object `new`-ed in the function (a stack object: all of these must agree, a slot can hold several objects in turn), decided by the last of: a vtable store at its start (an inlined constructor; any known vtable, the class is exact), a call of a program constructor, a library constructor import `L::L`, an MSVC import `L::vftable` stored (an unknown vtable last means unknown); the result of a call whose returns all give one class (a returned parameter is the argument of that call); a field (`this->ui->button`, a chain of loads from a parameter) that the same function stores such an object into. A slot is read only when the vtable holds code pointers up to its offset. (14) A library class has no vtable in the program. Its slot at an offset comes from the program classes whose chain of program superclasses ends at that class: a slot they do not override is an import stub, an override is program code; all import stubs must name the same function, else the slot stays `vtable+0x..`. The server sends `allvtables` (also the vtables of classes others derive from) and `parents` (class to superclass: metaobject, else the first RTTI base), `qt.connect_context`. (15) 32-bit MinGW: Ghidra makes no function of `metaObject()` (only the vtable points to it), so its read of the metaobject is an edge without a function. A code word in data that is no known function and starts at most `META_LOOSE` bytes before such a read stands for `metaObject()`. (16) A function that only unwind data names (`.pdata`, or a chained `UNWIND_INFO` in `.rdata`) is uncalled. (17) Time: the decompiles are most of the time of `qt_connects`, and a few huge initialisation functions dominate. The functions with call sites and their callers are decompiled ahead on several decompilers at once (`PREFETCH_THREADS`, within the pool budget); the walk then uses the stored results. `DISPATCH_VERSION` 5.
- `qt_connect` rows of kind `ptr`: `signal` = `Class::name(args)` (binary) or `Class::name` (imported), `slot` = function address `0x...` with `slot_kind` slot / signal / fn (member pointer) / functor (lambda or functor: the address is the `impl` function of the slot object, which holds or calls the body) or the name of an imported function (`ext`). Not resolved: a virtual member pointer whose receiver class is unknown, a signal or slot chosen at run time, `connect` to a `QMetaMethod`, `connectImpl` calls whose result of the stack slot analysis is ambiguous, more than 12 callers or 4 levels of forwarding.
- Feature seeds (`qt.feature_seeds`, features version 7): the slot of a connect whose signal is `QAction::triggered/toggled`, `QMenu::triggered/aboutToShow`, `QActionGroup::triggered` seeds `ui-menu`; `QAbstractButton::clicked/toggled/pressed/released` (and the button subclasses), `QDialog::accepted/rejected/finished`, `QDialogButtonBox` and `QWizard` signals seed `ui-dialog`. A subclass in the binary counts through its parent chain. String connects have no class: the signal names `triggered`, `clicked`, `accepted`, `rejected` are enough, and the slot name must be unique in the binary. Seeds are strong (they expand to callers). Calls of Qt library classes (`QNetworkAccessManager::`, `QFile::`, `QSettings::`, `QMenu::`, `QDialog::`, `QPainter::` and others, via the added import rows) seed the API features like MFC classes do (constructors weak).
- Runtime recognition: the dispatcher and, with RTTI, vtable slots 0 to 2 of every Qt class (`metaObject`, `qt_metacast`, `qt_metacall`) are boilerplate: `function` hints say so and the call graph marks them runtime family `Qt`. Gate: toolchain `qt` or a file named `Qt<n>*.dll`; a statically linked Qt is not scanned.

### Delphi

- VMT (Delphi 2009+, positive offsets from the class reference), parsed from the PE bytes in
  `server/delphi.py`. The class reference points at the first virtual slot; the slots before it, lowest
  address first: `vmtSelfPtr` (holds the class reference itself), `IntfTable`, `AutoTable`, `InitTable`,
  `TypeInfo`, `FieldTable`, `MethodTable`, `DynamicTable`, `ClassName` (ShortString), `InstanceSize`,
  `Parent` (a pointer to a cell that holds the parent class reference), then the standard `TObject`
  virtuals (`Equals`... `Destroy`). Every slot is pointer wide, so the layout scales with the pointer size.
  The self-pointer pattern (an aligned word equal to its own address plus 19 to 32 pointer sizes) finds
  the classes; the longest distance that passes the name check (ShortString identifier, plausible
  instance size, type info inside the image) wins. **[verified]** on real binaries: 22 slots before the
  class reference in 32-bit and 25 in the 64-bit builds checked; the first 11 slots keep their positions;
  `Parent` is always indirect. Delphi 2007 and older (19 slots) is accepted by the same scan, **[verify]**
  not checked on a real file.
- Type info (`TypeInfo` slot): kind `7` (class), name, class type pointer, parent info pointer, `i16`
  property count, then the unit name (ShortString); it gives the unit of every class **[verified]**.
- Published method table: `u16 count`, then entries `u16 size; ptr code; ShortString name` (`size` covers
  the entry including extended RTTI that follows the name). Published field table: `u16 count; ptr
  classTab`, then `pointer-wide offset; u16 typeIndex; ShortString name`; `classTab` is `u16 count` and
  pointers to cells that hold class references **[verified]**, 32-bit and 64-bit.
- Extended method table (Delphi 2010 and later): right after the `count` entries of the method table, `u16
  exCount` and `exCount` packed records `{ptr entry; u16 flags; i16 virtualIndex}` (`ps + 4` bytes each).
  `entry` points to a method entry of the layout above, anywhere in the image (not necessarily inside the
  table; with `count` 0 all entries lie elsewhere). The records name every method that has RTTI, published
  or not, with its code address; an abstract method has code 0. Flags: bits 0 to 2 kind (1 static class
  method, 2 method, 3 class method, 4 constructor, 5 destructor), bits 3 and 4 dispatch (0 static, 1
  virtual, 2 dynamic, 3 message), bits 5 and 6 visibility (0 private, 1 protected, 2 public, 3 published),
  bit 7 abstract. `virtualIndex` is the vtable index of a virtual method (negative for the standard
  `TObject` virtuals `Equals` to `Destroy`, which sit before the class reference), the message number of a
  message method, and a negative number otherwise. **[verified]** with Delphi 10 Seattle `dcc32` / `dcc64`
  programs (map file as truth: every one of 5,605 / 5,648 RTTI methods starts a routine of the map and
  5,603 / 5,646 carry the same class and method name; the other two are redeclared properties of a parent
  class) and with the two real programs of the acceptance corpus (32- and 64-bit). Visibility 3 matched the
  published methods of forms. In the RTL the table also lists private and protected methods (174 and 21 in
  the oracle). Stored as `dl_method` rows of kind `rtti-<visibility>` (slot = virtual index, -1 when the
  method is not virtual; no schema change); `DELPHI_VERSION` 2. The hint is `rtti: Unit.Class.Method`.
  A table that is absent (older compilers) or does not parse gives no rows.
- Property accessors (`delphi._properties`, `DELPHI_VERSION` 3). After the unit name the class type info holds
  `u16 count` and `count` packed `TPropInfo` records of the properties the class itself declares (parents are not
  repeated): `PropType`, `GetProc`, `SetProc`, `StoredProc` (pointers), `Index` (i32), `Default` (i32),
  `NameIndex` (i16), the name as a ShortString. With extended RTTI (Delphi 2010 and later) `u16 exCount` and
  records `{u8 flags; ptr info; u16 attrLen; attribute bytes}` follow (`attrLen` counts its own two bytes, so a
  record without attributes is `ps + 3` bytes); `info` points to a `TPropInfo`, also for properties that are not
  published. An accessor word is decoded by its top byte: `0xFF` a field (low bits = offset, no method), `0xFE` a
  virtual method (low 16 bits = byte offset of the VMT slot from the class reference; the code address is the
  pointer in the class's own VMT), anything else is the code address; 0 is none. **[verified]** with `dcc32` /
  `dcc64` programs of compilers 30, 33 and 35 (map as truth): the record sizes, the field and virtual encodings
  and the accessor addresses start routines of the map. Rows are `dl_method` kinds `prop-get` / `prop-set` (name =
  property, slot = vtable slot or -1; no schema change). A property that an ancestor already lists with the same
  accessor address (a redeclared `published` property) belongs to the ancestor and is dropped from the class. The
  method name is not in the file: `accessor_name` gives `Get<Prop>` / `Set<Prop>`, which is the real name for 94%
  of the accessors in the VCL programs (6 programs, 3 compilers, 2 bitnesses, 94 to 95% each); the others are
  accessors with another name or ones inherited from an ancestor. The hint says so:
  `prop: Unit.Class.GetProp (getter of Prop, name by convention)`. An address that is the accessor of several
  properties (an indexed getter, the abstract-method stub of virtual properties) has no name guess
  (`accessor_names` leaves it out); the hint lists up to 3 owners.
- Virtual methods: consecutive code pointers from the class reference, up to the start of the next
  class's slots. Their names are unknown.
- DFM: `RT_RCDATA` resources starting with `TPF0`. Component: optional prefix byte `0xF0 | flags`
  (1 inherited, 2 child position + integer, 4 inline), class and name as ShortStrings, properties
  (`ShortString name`, value) until an empty name, children until a zero byte. Values: 0 nil/end of list,
  1 list, 2/3/4 int8/16/32, 5 extended (10 bytes), 6 string, 7 identifier, 8 false, 9 true, 10 binary
  (`u32` length), 11 set (ShortStrings until empty), 12 long string, 13 nil, 14 collection, 15 single, 16
  currency, 17 date, 18 wide string (`u32` char count), 19 int64, 20 UTF-8 string. A collection item
  starts with a list marker, an old-style integer index is skipped when the item does not parse without
  it. An event is an identifier value whose property name (last dotted part) starts with `On` and an upper
  case letter **[verified]**: every form of the checked binaries parses.
- Join: the handler name is looked up (case-insensitive) in the published method table of the owner
  class and its ancestors. The owner is the form class (the root component's class), or the class of the
  nearest `inline` ancestor (a frame). A form whose class is not linked into the binary stays unresolved.
- Handler header: every DFM binding of a handler is listed. Components of one class that share the
  handler (one `OnExecute` for six actions) form one hint, `handler OnExecute of 6 TAction: actA "A",
  actB "B", ... in form TMainForm`, with up to 24 names per group. A limit of 4 bindings used to drop the
  fifth and sixth action, and agents named the wrong one.
- String literals (`worker/ghidra_ops/delphistr.py`, a step of the post-analysis fixups,
  `COLLECTOR_VERSION` 4). A Delphi 2009+ `UnicodeString` / `AnsiString` literal is a constant header
  (`u16 codePage` 1200 for UTF-16, `u16 elemSize` 2 or 1, `i32 refCnt` -1, `i32 length`; on x64 a `u32`
  padding comes first) followed by the characters and a zero; code passes the address of the characters.
  The step finds the headers in the initialized blocks, types the characters as `unicode` / `string` data
  where only undefined bytes are, follows each instruction reference to the call it feeds (`LEA RDX,[lit]`
  ... `CALL f`, no other write to the register in between, at most 8 instructions) and retypes that
  register parameter of `f` from an integer or undefined type to `wchar_t *` / `char *`. Signatures the
  user or agent set and pointer parameters are kept. **[verified]** (Ghidra 12.1.4, a Delphi 12 x64
  program) the decompiler prints a constant as a string only for a pointer or undefined parameter;
  Parameter ID had typed the RTL string assignment's source as `longlong`, so literals showed as
  `0x124ab50`. After the step: `FUN_00412a40(local_28, L"TABLES WITH READ LOCK")`; 24896 literals,
  176 parameters retyped, 4.8 s on a 25 MB program. ShortString literals (length byte, then text) are
  found through data references from code and typed as `PascalString255`; the decompiler then shows the
  label (`p_Segoe_UI_0051e150`). Identifiers are not taken as ShortStrings: code also points at RTTI
  names and at type info records (kind byte, then the name), which read as a ShortString **[verified]**.
  On a 32-bit Delphi program the step found 5811 literals and retyped 76 parameters in 1.7 s.
- String literals, pass version 2 (`COLLECTOR_VERSION` 5). Additions, each **[verified]** on a Delphi 12
  x64 program, a Delphi 2009+ x86 program and an x86 program built with Delphi 7-2007 (Ghidra 12.1.4):
  - Stack arguments: the walk follows `PUSH lit` (x86; offset 4 + 4 per later push), a register that is
    pushed, and `MOV [RSP+d],reg` (x64; offset d + 8) to the call and retypes the callee's stack parameter
    at that offset under the same rules. The walk allows 16 instructions.
  - Stores: a literal stored to a local or a field already prints as `L"..."` once the characters are
    typed (`*(wchar_t **)(param_2 + 0x30) = L"Phys"`); nothing else is needed. Where it did not, Ghidra had
    disassembled the literal as code (`SUB AL,0x0` for `","`, shown as `&LAB_00418a28`). The step clears
    such instructions when none starts before the header, no function holds them and nothing outside
    flows into them, then types the string (596 runs on the x64 program, 75 on the x86 one).
  - Concatenation routines (`UStrCatN`, `LStrCatN`, `WStrCatN`): found by their calls, not by name: at
    least 3 calls, and 80% of all, pass a count in EDX and exactly that many pieces (x86: pushes, a call in
    between takes its own stack arguments; x64: R8, R9, `[RSP+0x20]`...). On x64 the routine gets a
    variadic signature (not when user-defined) and the decompiler then lists every piece in order:
    `FUN_00414620(param_2,5,local_180[0],L"-",local_188,L",",local_190)`. On x86 the routine pops its
    own variable argument list; Ghidra keeps purge 0, the stack tracking drifts and a variadic signature
    brought back the pieces at 12 of 102 calls (in reverse order); a per-call stack depth change
    (`CallDepthChangeInfo.setStackDepthChange`) did not help. So on x86 the step writes a PRE comment at
    each call that has a literal piece, in concatenation order (first pushed first):
    `/* concat ? + L"exiftool -@ \"" + ? + L"\"" */`. The decompiler prints PRE comments by default, EOL
    comments not. A PRE comment someone else wrote is kept; the step replaces only its own (`concat `).
  - Delphi 2007 and older: `AnsiString` literals have the header `i32 refCnt -1, i32 length` (no code page
    or element size) and `WideString` literals are `u32 byte length`, wide characters, `u16 0` (no
    reference count; Delphi 2009+ uses the same shape, 61 of them in the x64 program). Headers are 4-byte
    aligned. Because both shapes occur in other data, a literal counts only when an instruction references
    its characters; the short ANSI header is tried only when fewer than 16 modern headers exist, the
    program holds a Delphi RTL registry path (`Software\Borland\Locales` and successors, ANSI or UTF-16),
    and at least 16 referenced literals remain. Wide text that reads as pairs of ASCII bytes is refused.
    Three MFC / Qt programs: nothing found, nothing changed.
  - Refresh: the program records the pass version (options `airlock`, `delphi_strings`), and
    `analysis_profile` includes it only when present. A project at collector 4 reruns only this pass on
    open, so decompiles of non-Delphi programs stay cached.
  - Measured on 20 functions per program with string use (same functions before and after): literal
    addresses still printed as a hex constant or label 1 -> 0 on each program; literal references with no
    text in the C 6 -> 2 (x86), 6 -> 2 (x64), 2 -> 2 (old); the rest are pointer variables loaded through
    another pointer, not literals passed. Time of the step 2.6 -> 6-9 s (x86), 6 -> 13-22 s (x64), 0.1 ->
    1-3 s (old, 1 MB).

### Free Pascal (FPC / Lazarus)

Free Pascal programs go through the same tools (`delphi_classes`, `delphi_forms`, `delphi_events`; the
`delphi` set). Layout facts, **[verified]** on FPC 3.2.2 programs built for i386-win32 and x86_64-win64
(console program with classes, and a Lazarus LCL form; stripped and not stripped):

- Detection (`projects.fpc_version`, `classify_toolchain(..., fpc=True)`): the RTL links the version string
  `FPC 3.2.2 [2021/05/15] for i386 - Win32` into every program; it gives toolchain `fpc` and
  `toolchain_ver` `3.2.2`. It wins over the `TPF0` form resource (Lazarus forms are binary `TPF0` RCDATA, so
  the form parser is shared). A binary with a Rich header or a CLI header is not scanned. `is_delphi` is true
  for `delphi` and `fpc`; IDR / signature / WARP names are never applied to `fpc` (they are Delphi code).
- VMT (`delphi.parse_fpc_classes`): the class reference points at the start of the table (no negative
  slots). Pointer-wide words: `vmtInstanceSize`, `vmtInstanceSize2` (= minus the size, the scan pattern),
  `vmtParent` (the parent VMT, or a cell that holds it: both occur in one program), `vmtClassName`
  (pointer to a ShortString), `vmtDynamicTable`, `vmtMethodTable`, `vmtFieldTable`, `vmtTypeInfo`,
  `vmtInitTable`, `vmtAutoTable`, `vmtIntfTable`, `vmtMsgStrTable`, then the virtual methods (slot 0 is
  `Destroy`; `TObject` has 13). Type info must name its own VMT.
- Method table: `u32 count`, then packed `{ptr ^ShortString name; ptr code}` (no size field, no extended
  RTTI). Field table: as Delphi, but the type index counts from 1 (0 = none) and the class table holds class
  references directly. Type info: kind `15` (`tkClass`), name, `ClassType`, `ParentInfo` (pointer to
  pointer), `i16` property count, unit name, `u16` count, then packed `TPropInfo` of `4*ps + 11` bytes +
  name: `PropType, GetProc, SetProc, StoredProc, i32 Index, i32 Default, i16 NameIndex, u8 PropProcs`.
  `PropProcs` bits 0-1 get, 2-3 set: 0 field, 1 static method (code address), 2 virtual method (byte offset
  in the VMT), 3 constant. No extended property list.
- Other tables (`delphi.parse_fpc_classes`, **[verified]** on FPC 3.2.2 i386-win32 and x86_64-win64): the
  dynamic table (`vmtDynamicTable`) holds the integer `message` handlers, never `dynamic` methods (FPC
  treats `dynamic` as `virtual`): pointer-wide `u32 count`, then `{u32 id; ptr code}` entries of two
  pointer-wide words. The string message table (`vmtMsgStrTable`): count, then `{^ShortString name; ptr code}`.
  Rows `message` (name = `WM_xxx` through `cpp.message_name`, slot = id) and `message-str` (name = the
  string). The interface table (`vmtIntfTable`): `sizeuint count`, then entries `{^^GUID; vtable;
  IOffset; ^ShortString GUID text; u32 IType}` of 5 words (the last is padded: 20 bytes in 32-bit, 40 in
  64-bit). Rows `interface` (the code pointers of each interface vtable up to the next vtable or the first
  non-code word, named `Interface.Method`: `QueryInterface`/`_AddRef`/`_Release` for the first three slots
  of a COM interface, then the method name of the interface type info (FPC 3.2 with `{$M+}`: `TIntfMethodTable` after the unit name and the property table, found by the GUID bytes; entry `^^result, u8 cc, u8 kind, u16 params, sizeint stack, ^name`, then per parameter `^^type, u16 flags, ^name, ^locs`; parents first), else the named class method that the slot's thunk (`sub eax|rcx|[esp+4], off; jmp code`) jumps to, else `#n`; an interface is named from `fpcsigs` GUID names, `IUnknown`/`IDispatch`, or
  is its GUID text) and one field per interface (name = interface, offset = `IOffset`, type `interface`).
  The init table (`vmtInitTable`, FPC 3.2): `kind, ShortString name`, then packed `ptr terminator, i32
  size, ptr, ptr, i32 count` and `{^^typeinfo; sizeint offset}` entries: managed fields (fields without a
  name, type = kind of the type info: `AnsiString`, `UnicodeString`, `interface`, `DynArray`, ...) that
  the published field table lacks. Not read: the automation table, Lazarus forms linked as `.lrs` data.
- Virtual slot names: `delphi.FPC_TOBJECT_VSLOTS` (the 13 slots of `TVmt`: `Destroy` ... `ToString`, from
  `objpash.inc`); other classes (TPersistent, TComponent, TControl ... of the RTL and the LCL) from
  `fpc-<version>-names.json` next to the signature databases (`fpcsigs.vslot_names`: the method name of the
  symbol of the code in each slot of the reference programs, voted over a class and its descendants). Only
  a slot a class introduces or overrides carries the name (an inherited slot has the parent's code and no
  name); `hints_for` prints `TClass::vslot N (Name)`. Message, interface and virtual-name rows need
  `DELPHI_VERSION` 5.
- RTL / LCL signatures (`fpcsigs`, `airlock delphi-sigs fpc-build <fpc install or fpc.exe>... [--lazarus
  <Lazarus folder>] [--source <folder>]`, `fpc-oracle <program built with -g> [--own-units a,b]`): the build
  compiles three reference programs per compiler (an `rtlmega` that `uses` every RTL / FCL unit, an `lclmega`
  that uses the LCL and LazUtils units, and `systouch`, calls that pull the per-routine linked System
  routines in) with `-g`. **[verified]** FPC links a whole unit when the program uses it (the shipped unit
  objects are not smart-linked), and the executable keeps its COFF symbol table, whose names are the
  truth: `UNIT$_$CLASS_$__$$_METHOD$params$$result`, `UNIT_$$_PROC$params$$result`, `fpc_*` helpers
  (`fpcsigs.demangle`; the case is restored from the most frequent spelling in the Pascal sources when
  `--source` or the install's `source` folder exists; parameter lists are not kept). The routine code is
  dumped and masked like the Delphi package routines (`delphisigs.scan_named`: `rel32` operands outside the
  routine, RIP-relative operands, and absolute 32-bit addresses inside the image because FPC executables have
  no `.reloc`; bounds: next symbol, `.pdata` in 64-bit). Output `fpc-<version>-<32|64>.sigdb` (+ names file) in
  `delphi_sigdb_dir`. `idr.files_for`: a binary with toolchain `fpc` uses only the database of its
  `toolchain_ver` and bitness (tier: by code, then call context; `IDR_VERSION` 10); a Delphi binary never sees an FPC
  database. Only the exact bytes match: the units must be compiled like the shipped ones (a Lazarus that
  rebuilt the LCL with other flags, `-O` levels of the RTL, a different FPC patch level give other code).
  Oracle (`fpcsigs.measure`, the Delphi oracle's counting; truth = symbols of a `-g` build of the same
  program, whose `.text`/`.data` are byte-identical to the stripped build, **[verified]**): FPC 3.2.2 on a
  Lazarus form program that was not used for the build, library routines only, >=24 bytes in brackets:
  32-bit 83.4% right (89.6%), 0.2% wrong, 16.4% none; 64-bit 83.4% right (86.9%), 0.4% wrong, 16.3% none; a
  console program (32-bit) 86.5% right (94.6%), 0.1% wrong, 13.4% none (all three after the call-context pass;
  by code alone 80.4% / 79.4% / 79.4%). The `none` routines are mostly tiny or
  identical bodies (empty virtual stubs, accessors) that the matcher drops on purpose when one proc matches
  more than `MAX_COPIES` functions. **[verified]** index of FPC 3.2.2 Lazarus and console programs (32 and 64-bit) names 48% to 57% of all functions (`idr:` hints). FPC x86 indirect calls `CALL [reg+disp]` get a stub with the Free Pascal `register` convention (`delphistr.vcall_args`: EAX Self, EDX/ECX when loaded just before the call and not used for the vmt address, pushes right before the loads), named `vmt_<offset>_<regs>_<pushes>` and tagged `airlock:concat vcall <key>`; without it a hidden result pointer is not an argument for the decompiler. The same pass runs for 32-bit Delphi (`delphistr` VERSION 6, collector 11): vmt load into another register skipped, byte/word register arguments (`DL`, `CL`), `PUSH EBP` and prologue pushes ignored, `stdcall`/`safecall` calls with the vmt load in the window get a stack-only stub (`vmt_<offset>_s_<pushes>`), `cdecl` (`ADD ESP,n` after the call) none; the decompiler drops the stub address after a vcall stub name. **[verified]** on 32-bit Delphi programs: calls that lost a register or stack argument in the C, 5 of 17, 6 of 20, 9 of 254 and 10 of 237 before, none after. A program built with `-g` also gets names (`P$T1$_$TDOG_$__$$_SPEAK$$ANSISTRING`,
  `fpc_ansistr_concat_multi`) from Ghidra's own symbol loader.
- Pascal register convention (32-bit Delphi and Free Pascal): arguments in EAX, EDX, ECX (Self first), the rest on the stack pushed left to right, the callee pops (`RET n`). Ghidra's `__register` (borlanddelphi spec) orders the stack parameters by offset, i.e. reversed; Free Pascal programs use the Visual Studio spec and no EAX parameter. `pascalconv.apply_register_prototypes` writes custom storage for each such function (registers, then stack slots from the highest offset down), see HANDOVER "Round 7 fixes (r7c)". **[verified]** `TBase.Num(X,Y,Z,W)` decompiles as `(param_3 * param_4 + param_2) - param_5`. Decompiled virtual calls show the slot and the resolved method (`vcallnames`): `vmt_508_adc_0/*TFormMain vslot 310 -> ...*/`.
- Strings: `AnsiString` / `UnicodeString` literals are `{u16 codePage; u16 elemSize; (u32 pad on 64-bit);
  SizeInt refCount = -1; SizeInt length}` followed by the data and a NUL: 12 bytes before the data in
  32-bit, 24 in 64-bit (Delphi has 12 in both). ANSI literals carry code page 0 when the source uses
  `{$H+}` without a codepage directive, 1200 for `UnicodeString`.

### .NET

- `dnfile` for the index (types, methods, signatures, P/Invokes, resources).
- `ilspycmd` per type on demand (`-t <type>`), output cached in `cache\`,
  stored as reconstruction (never overriding metadata facts).
  **[verified 2026-11-05]** ilspycmd 8.2.0.7535: `-t <FullName>` prints the C# of one type to stdout
  (nested types print with their outer type; `Outer+Inner` works); `-r <dir>` sets the reference path;
  `--disable-updatecheck` avoids the version check. A missing type exits with code 70 and a stack
  trace on stderr. It targets .NET 6 and needs `DOTNET_ROLL_FORWARD=LatestMajor` when only newer
  runtimes are installed: airlock sets that for the child process only. With SDK 7 the tool installs
  from nuget.org with `dotnet tool install ilspycmd --version 8.2.0.7535 --tool-path <folder>
  --add-source https://api.nuget.org/v3/index.json`. One type of a 6 MB assembly takes under 1 s.
- P/Invoke declarations link managed code to the native exports of the same project (xedge kind
  `pinvoke`). COM interop declarations (`ComImport`) are listed in `dotnet_types kind=com` only,
  with the GUID from the `GuidAttribute` (flag `guid=<lower>` in `dn_type.flags`).
- Managed call graph (`DOTNET_VERSION` 3). The IL body of each MethodDef is read from its RVA (tiny
  and fat headers; exception clauses are skipped). Opcodes `call`, `callvirt`, `newobj`, `jmp` give an edge of
  kind `call`; `ldftn`, `ldvirtftn` and `ldtoken` of a method token give a `data` edge that
  `Store.link_fnptr` turns into `fnptr` (`ldtoken` of a type or field: no edge). `calli` has no static
  target: no edge, but `function view=asm` prints its signature (`calli int(int, string)`, with
  `instance` / `unmanaged stdcall` when set). Targets by token table:
  MethodDef: an edge to that function. MethodSpec: the method behind it. MemberRef: parent TypeDef or
  a TypeSpec of a local generic type: matched to the local method by type, name and parameter list
  (an edge to the function); parent TypeRef: an external function (space EXTERNAL, entry =
  `0x0A000000 | MemberRef row`, namespace = `<assembly>.dll`, name = `Ns.Type::Method(params)`) plus
  an import row at the same address. Array TypeSpecs and field references are dropped.
  `Store.link_cross_binary` calls `dotnet.link_managed`: a reference whose assembly name matches a
  project assembly is bound by type name, method name and parameter list (one overload may match by
  name alone) with an xedge of kind `mcall` (src = the reference slot, dst = the MethodDef token). The
  graph, `xrefs`, `callgraph` and `path` follow it like an import. Call-site addresses are the caller's
  token, so `xrefs` shows one edge per caller and callee. Managed functions are excluded from the
  decompile queue and from the project map frontier.
- Write tools on managed targets (method, P/Invoke thunk, external callee; also in a mixed-mode
  binary, where the token addresses are not in Ghidra): `rename`, `retype`, `comment` and the rename
  part of `annotate` answer `error managed: ...` before any worker call; `rename` of a label or
  global at a token address too. In a managed-only assembly (no Ghidra program) `struct_define` and
  label/global renames and `comment` are refused as well. `annotate` stores the note (index `note`
  table, no plate mirror) and, when `new_name` is given, adds the `error managed` line after the
  note line.
- ilspycmd output is cached in `cache\dotnet\<sha16>-<ilspycmd version>\` (version from
  `ilspycmd --version`, asked once per process; the file size stands in when it prints none).
  **[verified]** System.Windows.Forms.dll (6 MB): 2416 types, 30149 methods, 625 P/Invokes,
  227 COM types, 92977 call edges, 2535 external callees, indexed in 8 s (dnfile alone takes 6 s).

---

## 12. Milestones

| # | Scope | Done when |
|---|---|---|
| M0 | Skeleton: config loading, `init`, `doctor`, MCP server with `project_info`, worker spawn in Job Object, PyGhidra start | `airlock doctor --start` passes on Ghidra 12.1.4; `project_info` callable from Claude Code. **Done 2026-11-04: Ghidra 12.1.4 + Java 25 on Windows, JVM start 4.7 s** |
| M1 | `open_binary`, analysis, cheap pass, `outline`, `search`, `function`, `xrefs`, `callgraph`, `strings`, `index_status` | End-to-end on a 32-bit MSVC application: find a file-loading function by string and read its decompile within budget |
| M1.5 | Project folders (`projects_root`, `dirty\`/`clean\`, `projects` and `project_open` with a role locked per session), `program_scan` with options table and time estimates, `project_create`, analysis queue for many binaries, cross-binary import links, tools across all binaries | From an unbound session: scan a multi-file program, show the options table, create the project, analyse option B; in `dirty\` search across binaries and follow a call from the executable into a DLL; in `clean\` every non-spec tool returns `wrong_role`; `project_open` returns the project map; `feature("file-io")` lists the program's file-loading entry points across binaries |
| M2 | `resources` set, `cpp` set (RTTI, vtables, MFC message maps) | MFC menu items and dialog buttons mapped to handler functions |
| M3 | `annotate` set + invalidation, `frontier`, notes | Renaming a callee refreshes callers' cached decompiles |
| M4 | `spec_write`/`spec_read`/`spec_export`, clean profile, audit | Clean session can read a spec and nothing else |
| M5 | `fileformat` set | Diff two OLE-based document files per stream |
| M6 | `delphi` set | Delphi form → event → handler resolved. **Done 2026-11-05** |
| M7 | `dotnet` set | Managed assemblies indexed; P/Invokes linked to native exports. **Done 2026-11-05** |
| M8 | `qt_metaobjects`, `dataflow` set | Qt signals/slots mapped |

---

## 13. Open questions

1. Mirror agent notes into Ghidra plate comments by default, or only on
   request? (Proposal: config flag `mirror_notes_to_ghidra`, default `true`
   so the GUI shows the agent's work.)
2. ~~Background decompile priority and CPU cap~~ Decided: ½ to ¾ of the
   logical processors (`decompile_cpu_min`/`max`), §5 step 8.
3. Similarity across versions: own masked hashes first, or go straight to
   Ghidra's BSim?
4. Spec filter strictness: reject, or accept with a warning and mark the spec
   `needs_review`?

---

## 14. Third-party code

| Component | License | Use |
|---|---|---|
| DelphiReSym | BSD-3-Clause | format reference only; nothing copied |
| IDR / IDR64 (crypto2011) | MIT | knowledge base file format reference only; the reader is written from the layout; the `kb*.bin` files are never committed or shipped |
| REA (morluto/rea) | MIT | design ideas: selectors, artifact identity, analysis profiles, bounded output; any copied code keeps its notice |
| IDA-Ghidra-bridge | MIT | handler logic ported to the worker |
| Ghidra / PyGhidra | Apache-2.0 | runtime dependency, not redistributed |
| pefile, dnfile, olefile | MIT / BSD | dependencies |
| ilspycmd | MIT | optional external executable, not redistributed |

jCodeMunch (dual-use license, no rebranding) is a design inspiration only; no
code is taken from it.

### Round 7 fixes: names kept, ShortString index rows

- A tool that derives Delphi/IDR data passes the configured `idr_kb_dir`, `delphi_sigdb_dir`, `warp_dir`. A call with no folder keeps the stored IDR names and FPC vslot names (never wipes). **[verified]** vc project copy: `delphi_classes` leaves `idr_info` of all binaries unchanged.
- `projects` / `project_open` count binaries from the index store when the manifest lists none. `hexdump` and the other file tools fall back to `artifacts/<sha256>` for an analysed binary. `delphi_events` with no form lists all forms.
- Strings of Delphi/FPC programs include ShortString literals (length byte, printable, 3+ chars) that an instruction references and that lie in no string data (`shortstr.py`, collector 12). **[verified]** FPC 3.2.2: `'purr'` at 0x00428218 found.
- `delphi.ensure` takes `NOT_GIVEN` as the default of the three folders: a caller that did not pass the configuration keeps the stored IDR and FPC names. `None` passed means the config has no such folder; `idr.stale` then clears an old result (names dropped, unchanged behaviour).
