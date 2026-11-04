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
  worker/
    main.py               # PyGhidra entry, request loop
    ghidra_ops/           # functions, decompile, xrefs, types, writes
    analyzers/            # msvc_rtti, mfc, qt, delphi
  backends/
    dotnet.py             # dnfile + ilspycmd
    fileformat.py         # olefile, hexdump, diff, record guessing
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
| `ui` | window/dialog/menu creation, message maps and resources (M2), command IDs |
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
  inside the program's own binaries (runtime libraries excluded).
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
- Shown in the project map as section 4b *Subsystems* (top clusters), and
  through the tool `function_map`.

**Graph view: paths and export.** Functions, clusters, features, strings and
imports form one graph (call/reference edges from `edge`/`xedge`, membership
from `feature_entry` and clusters). Storage stays in SQLite; a shared graph
module (the one the clusters use) answers graph questions:

- `path(from, to)`: shortest call chains between two points, across
  binaries, one step per line with the call-site address. `from`/`to` are
  functions (`binary!name`, address), an import (`KERNEL32!ReadFile`), a
  string (`"*.cfg"`: every function that references it), a feature key or a
  cluster id (any member). Returns up to `k=3` shortest paths (more by
  cursor), `max_depth=8`; chains without `util` hubs are preferred, a chain
  through a hub is returned only when no other chain exists and is marked
  `[via util]`. A bare name resolves to a function first, then an import,
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
  function_id   INTEGER REFERENCES function(id),
  class_id      INTEGER REFERENCES class(id),
  summary       TEXT NOT NULL,
  tags          TEXT,           -- comma separated
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
  result_kind   TEXT
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
   `code MB × analysis_s_per_code_mb` (config, default 80, measured on a
   32-bit MSVC application **[verified]**) and is refined from the project's
   own measured analysis times as binaries finish. The table ends with the
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
3. .NET-only assembly: index with `dnfile` and stop. No Ghidra.
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
| change a struct / field | every function using that type (queried from Ghidra's data type references) |
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

### cpp

| Tool | Parameters | Returns |
|---|---|---|
| `rtti_classes` | `query?`, `limit=50` | classes from MSVC RTTI: name, vtable, base classes |
| `vtable` | `class` or `address` | slots: index, function name, address |
| `mfc_message_maps` | `class?` | per class: message, control id, handler function |
| `qt_metaobjects` | `class?` | signals, slots, properties with method indices → functions |

### delphi

| Tool | Parameters | Returns |
|---|---|---|
| `delphi_classes` | `query?`, `limit=50` | classes from VMT/RTTI: name, parent, unit, method count |
| `delphi_forms` | `form?` | DFM component tree: name, class, caption (no addresses by default) |
| `delphi_events` | `form` or `component` | event → handler function |

Implementation: metadata recovery adapted from DelphiReSym (BSD-3-Clause,
noticed in `THIRD_PARTY_NOTICES.md`), our own binary DFM (`TPF0`) parser,
optional IDR knowledge base for RTL/VCL library naming in a later milestone.
64-bit Delphi binaries use the standard Win64 calling convention.

### dotnet

| Tool | Parameters | Returns |
|---|---|---|
| `dotnet_types` | `query?`, `limit=50` | types/methods from `dnfile` metadata, incl. P/Invoke declarations |
| `dotnet_decompile` | `type`, `member?` | C# from `ilspycmd`, one type at a time, cached; marked as reconstruction |

### resources

| Tool | Parameters | Returns |
|---|---|---|
| `pe_resources` | `type?` | resource inventory: type, id/name, language, size |
| `dialogs` | `id?` | dialog template: controls with id, class, caption; handler if a message map links it |
| `string_tables` | `query?`, `limit=50` | id → string |
| `version_info` | | product name, version, company, file description |

### dataflow

| Tool | Parameters | Returns |
|---|---|---|
| `trace_values` | `function`, `variable` or `param`, `depth=2` | def-use chain across resolved calls (high p-code) |
| `switch_tables` | `function` | recovered switch: case values → targets, defaults separate |
| `constants` | `value`, `limit=30` | functions using the constant (magic numbers, record tags) |

### fileformat (no Ghidra)

| Tool | Parameters | Returns |
|---|---|---|
| `ole_streams` | `path`, `stream?` | stream tree with sizes; one stream as hexdump page |
| `hexdump` | `path`, `offset=0`, `length=256` | hex + ASCII |
| `file_diff` | `path_a`, `path_b`, `stream?` | changed byte ranges with context; for OLE, per stream |
| `record_guess` | `path`, `stream?`, `offset?` | candidate record layouts: length prefixes, repeated strides, string fields |

### spec_write / spec_read

| Tool | Parameters | Returns |
|---|---|---|
| `spec_write` | `topic`, `title`, `body`, `status=draft`, `sources` | spec id + version; rejects code/addresses (§9) |
| `spec_list` | `topic_prefix?` | topics, titles, status, versions |
| `spec_read` | `topic`, `version?` | spec body |
| `spec_export` | `topic_prefix?`, `format=md` | spec document file path + audit summary |

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
   `xrefs` and `callgraph`.

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
how to read on, the signature, the control skeleton (top two nesting levels of
`if`/`switch`/loops with line ranges; switch case labels compressed into
ranges), callees with call count and first line, and referenced strings with
line numbers. It is built by a line/brace scanner, not a C parser, and is cut
to the budget with the usual cursor footer.

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
- Every tool call is written to `audit` with profile, tool and an argument
  digest.

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
  the collector version, so existing projects need `analyze(force)` to benefit.
- The `unknown` calling convention on most functions is Ghidra's default before
  parameter analysis and is not what causes the frame-access noise **[verified]**.

### MSVC RTTI and vtables

- 32-bit: Complete Object Locator holds absolute pointers (signature 0).
- 64-bit: COL holds image-relative offsets (signature 1).
- Walk: type descriptor (`.?AV…@@`) → COL → vtable at COL reference + pointer
  size. Base classes from the Class Hierarchy Descriptor.
- Pointer size and image base always come from the program, never constants.

### MFC message maps

- Locate `GetMessageMap` implementations via vtables of `CCmdTarget`-derived
  classes; each returns an `AFX_MSGMAP` (`pfnGetBaseMap`, `lpEntries`).
- `AFX_MSGMAP_ENTRY`: `nMessage`, `nCode`, `nID`, `nLastID`, `nSig`, `pfn`;
  the table ends with an all-zero entry **[verify layout per MFC version]**.
- Join `nID` with dialog templates and menus → "menu item 'Open…' →
  `CMainFrame::OnFileOpen`".

### Qt metaobjects

- `staticMetaObject` → `QMetaObject::d.stringdata` and `d.data`; method
  descriptors give signal/slot names and indices; `qt_static_metacall` maps
  indices to functions **[verify layout per Qt major version]**.

### Delphi

- Delphi 2009+ metadata format (positive-offset VMT) via DelphiReSym-derived
  code; Delphi 2–2007 format later if needed.
- DFM: `RT_RCDATA` resources starting with `TPF0`; parse component tree and
  event properties; map event method names to VMT published methods →
  functions.

### .NET

- `dnfile` for the index (types, methods, signatures, P/Invokes, resources).
- `ilspycmd` per type on demand (`-t <type>`), output cached in `cache\`,
  stored as reconstruction (never overriding metadata facts)
  **[verify ilspycmd 11.x flags for single-type output]**.
- P/Invoke and COM declarations link managed code to native exports in the
  Delphi binaries of the same project.

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
| M6 | `delphi` set | Delphi form → event → handler resolved |
| M7 | `dotnet` set | Managed assemblies indexed; P/Invokes linked to native exports |
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
| DelphiReSym | BSD-3-Clause | adapted Delphi metadata recovery; notice in `THIRD_PARTY_NOTICES.md` |
| REA (morluto/rea) | MIT | design ideas: selectors, artifact identity, analysis profiles, bounded output; any copied code keeps its notice |
| IDA-Ghidra-bridge | MIT | handler logic ported to the worker |
| Ghidra / PyGhidra | Apache-2.0 | runtime dependency, not redistributed |
| pefile, dnfile, olefile | MIT / BSD | dependencies |
| ilspycmd | MIT | optional external executable, not redistributed |

jCodeMunch (dual-use license, no rebranding) is a design inspiration only; no
code is taken from it.
