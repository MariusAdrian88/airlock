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
`max_budget`, `detail`; decompiler `decompile_timeout_s`, `bulk_decompile`,
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
  chain (a short run of at most 3 runtime functions just before an import or runtime target, e.g.
  `... -> CFile::Write -> WriteFile`; likewise at the start when the source is runtime) are the
  normal route and count as clean. CRT plumbing (`_free`, `__lock`, `__amsg_exit`,
  `__NMSG_WRITE`, ...), hubs and runtime functions in the middle of a chain still flag it. A bare name resolves to a function first, then an import,
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
  toolchain     TEXT,          -- msvc | delphi | qt | dotnet | unknown (detected)
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
   order (`core`, then `own_plugin`, then the rest by size). Each binary is
   usable as soon as it is `ready`; `index_status` shows the queue, the
   current binary, finished times and the remaining estimate. Options can be
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
   (→ .NET), Delphi markers (`TPF0` DFM resources, `Borland`/`Embarcadero`
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

A cached `decomp` row is valid only if `fn_version` and `analysis_profile`
match. Invalid rows are recomputed on next request, not eagerly.

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
| `open_binary` | `project`, `path` | binary id, format, toolchain, status (`queued`/`analysing`/`ready`) |
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
| `patch_bytes` | `address`, `hex` | off by default |

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
- `patch_bytes` stays `not_implemented`.

### cpp

| Tool | Parameters | Returns |
|---|---|---|
| `rtti_classes` | `query?`, `limit=50` | classes from MSVC RTTI: name, vtable, slot count, direct base classes |
| `vtable` | `target` (class name or address) | slots: index, address, function name |
| `mfc_message_maps` | `target?` (class) | no class: the classes that have a map (with the class's dialog); a class: message, control id, handler function per entry, `// menu "File > Open..."` or `// dialog 101 button "OK"` for the id (a class without a map of its own shows the nearest base class that has one) |
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
`TFoo::vslot 3`). The project map gets a `UI:` line, handlers seed the `ui-menu` / `ui-dialog`
features, and methods of classes from runtime units (`System`, `Vcl.*`, `Classes`...) plus `@`-prefixed
helper names count as runtime (`runtime: Delphi`).

The format code is written from the format description (no code copied; DelphiReSym was not used).
64-bit Delphi binaries use the standard Win64 calling convention.

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
rest, so a name from the database wins. `IDR_VERSION` 3 makes projects compute again on open (version 2 databases stay
loadable: the file layout did not change). Routines the packages do not export (private helpers, nested routines,
generic instances nobody exports) stay unnamed: 32-bit exports cover about 60% of the routines of a static program,
64-bit about 79%. The `.jdbg` files next to the 32-bit packages hold them (see HANDOVER), but the name table is
compressed and the reader is not written. `airlock doctor` lists the databases.

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
- **`record_guess`.** Analyses a window of up to 1 MiB from `offset`. Candidates, strongest first: fixed stride (byte autocorrelation over the first 32 KiB, strides 2..512, fundamental only; per-column constants, u16/u32, f32/f64 ranges), length-prefixed chains (u8/u16/u32 LE, with or without the prefix counted, header skip 0/2/4/8/16; evidence is that the chain ends exactly at the end of the data, so it is weak for short records), then strings (ASCII and UTF-16LE runs of 4+, spacing, length prefix before runs) and entropy. Mostly-zero files give no stride (autocorrelation is meaningless); high-entropy data skips strings. These are hints to verify with `hexdump`, not a parser.

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

   Errors have one wording everywhere: `error not_found: no function or import
   named 'X' [in N ready binaries]. Use search …`, `error ambiguous: 'X' matches
   N functions: bin!name 0x…, …. Retry with binary!name or binary!address.`,
   `error bad_target: 'X' is <kind>, but this tool takes <kinds>. <next step>.`

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

One line, a code and the next action:
`error not_analysed: binary 'app.exe' is still analysing (62%). Retry later or call index_status.`

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
  - more than N consecutive hex bytes.
  The rejection names the offending line so the agent rewrites it as prose or
  as a data-layout table. This filter is a heuristic aid, not a guarantee; the
  reviewer remains responsible.
- Data layouts in specs use a neutral table form (field, offset, size,
  meaning), which describes the format without copying code.
- `spec_write` requires `sources`, stored in `spec_provenance` (dirty only).
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
  `vtable_slot`, `msgmap_entry` (schema v10, derived). They are filled when a binary becomes ready
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
  without RTTI are named `anon_<map address>`. The tool `mfc_message_maps <class>` follows the
  recorded base classes to the nearest class with a map.
- **Join** (`server/uijoin.py`, computed per binary on demand, nothing stored): `msgmap_entry.ctrl_id ..
  last_id` (ranges included) x `res_control.ctrl_id` / `res_menu_item.item_id`, `WM_COMMAND` and
  `WM_NOTIFY` entries only. `ON_COMMAND` (code 0) is the menu command, `UPDATE_COMMAND_UI` (code
  0xFFFFFFFF) the update handler; for a dialog control every code counts and is named by the control
  class (`BN_CLICKED`, `EN_CHANGE`, `CBN_SELCHANGE`, `NM_CLICK`, ...). A handler shows as `Class::name`;
  for an `anon_` class as the function name (or the address). Ids that occur in several menus or
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

### Qt metaobjects

- Parsed from the PE bytes in `server/qt.py` (tables `qt_class`, `qt_method`, `qt_prop`, `qt_enum`, `qt_connect`, schema v13, meta `qt_version:<id>`). Scan: every pointer-wide word in the data sections whose next two words point into the image and whose second target starts with a plausible header; the class name must decode.
- `QMetaObject::d` Qt5: `superdata, stringdata, data, static_metacall, relatedMetaObjects, extradata` (6 pointers) **[verified]** on 64-bit MSVC and 32-bit MinGW builds. Qt6 adds `metaTypes` before `extradata` (7 pointers) **[verify]** (no Qt6 sample was authorised; synthetic tests only).
- `data` header, 14 words: revision, className, classInfo(count, offset), methods, properties, enums, constructors, flags, signalCount **[verified]** (revision 8 = Qt 5.12 to 5.15; revision 7 occurs in a few internal classes). Method record 5 words (name, argc, parameters, tag, flags), parameter block `ret, types, names`, bit 31 of a type word = string index, else a `QMetaType` id **[verified]**; access = flags & 3, kind = flags & 0xc (signal 4, slot 8), cloned 0x20; the first `signalCount` methods are the signals **[verified]**. Property record 3 words (name, type, flags) plus a notify-id array of `propertyCount` words when any property has the Notify flag **[verified]** against the notify signals of Qt classes with known sources. Enum record 5 words from revision 8 (name, alias, flags, count, data) **[verified]**; 4 words for revision 7 **[verify]**. Qt6 (revision 9 and up): method 6 words, property 5 words (name, type, flags, notifyId, revision) **[verify]**.
- String data Qt5: `QByteArrayData[]` of 16 (32-bit) or 24 (64-bit) bytes, `ref = -1`, `size`, `alloc`, `offset` relative to the item **[verified]**. Qt6 since 6.4: `uint offsetsAndSizes[]` pairs, offset relative to the array **[verify]**; the reader tries both.
- Superclass: `d.superdata` is a pointer for a parent in the same image **[verified]**; for a parent in another DLL it is 0 in the file and the program fills it at start-up. Worker op `qt_dispatch` finds the store to the field, traces the source register back to the load of the import `staticMetaObject` and reads the class from its (MSVC, Itanium or demangled) name **[verified]** on a MinGW 32-bit build (every imported parent found).
- Method to function: `qt_dispatch` decompiles `d.static_metacall` and walks the tokens. The `InvokeMetaMethod` switch is the one whose case labels fit the method count best; the first call to a function of the program in each case is the method. Small classes (the compiler drops the switch) use `if (id == K)` blocks; a class with one method uses the first call. Signals the compiler inlined into the dispatcher (a call to `QMetaObject::activate` only) are taken from the `IndexOfMethod` branch (`== signalFunction` then `*result = index`). **[verified]** on both builds: about 94% of signals and 75% to 100% of slots and invokable methods are mapped. Limits: a method inlined into the dispatcher maps nothing; inherited methods are not in the switch; property accessors (ReadProperty/WriteProperty) are not mapped.
- Connections: `QObject::connect` with `SIGNAL("2name(args)")` and `SLOT("1name(args)")` strings. Each connect call takes the two closest signal/slot strings of its function; without identifiable connect call edges adjacent strings are paired (a 32-bit cdecl call pushes the slot first, so both orders are accepted). Pointer-to-member connects (`connectImpl`) carry no strings: their call sites are listed when the call edges are found (**[open]** not found for calls through the import table of a MinGW build). Connected classes are looked up by normalised signature (const and & removed).
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
