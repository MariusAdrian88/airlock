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
  config/                 # jsonc loading, schema, overlays, profiles
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
| Data (index, projects) | `%LOCALAPPDATA%\airlock\` unless `index_dir` is set |
| Project overlay | `<project dir>\project.jsonc` |

`airlock init --ghidra <path>` writes the commented default config.
`airlock doctor` checks every configured path (Ghidra, JDK, ilspycmd), the
Python version against the bundled JPype wheels, the PyGhidra install, and
write access to the data directory. `--fix` installs PyGhidra from Ghidra's
bundled wheels; `--start` also launches the worker and the JVM.

### Resolution order

Built-in defaults → global `config.jsonc` → project `project.jsonc` → the
selected profile. Keys present in a later layer win; keys absent fall through.

### Schema (default file)

```jsonc
{
  // ── Locations. Only ghidra_dir is required. ──────────────────────────
  "ghidra_dir": "C:/Tools/ghidra_12.1.4_PUBLIC",
  "jdk_dir": null,          // null: let Ghidra's launcher find the JDK
  "ilspycmd": null,         // e.g. "C:/Tools/ilspycmd/ilspycmd.exe"
  "index_dir": null,        // null: %LOCALAPPDATA%/airlock

  // ── Behaviour ─────────────────────────────────────────────────────────
  "defaults": {
    "token_budget": 2000,           // per response (list tools, outline, ...)
    "function_budget": 10000,       // per response of `function` (decompiled C)
    "detail": "brief",              // brief | full | evidence
    "decompile_timeout_s": 60,
    "bulk_decompile": "lazy",       // lazy | background
    "analysis_timeout_min": 60,
    "max_budget": 32000,            // cap for a per-call budget override
    "allow_writes": false,          // gate for every tool in "annotate"
    "mirror_notes_to_ghidra": true, // agent notes also become plate comments
    "jvm_max_memory": null          // e.g. "8G"; null: Ghidra's default
  },

  // ── Profiles: which sets each kind of session gets ───────────────────
  // Select with `airlock serve --profile <name>` in the MCP registration.
  "profiles": {
    "dirty": {
      "role": "dirty",
      "enabled_sets": ["core", "cpp", "resources", "types", "annotate",
                       "dataflow", "fileformat", "spec_write", "admin"],
      "allow_writes": true
    },
    "clean": {
      // Clean side sees specifications only. Do not add code sets here.
      "role": "clean",
      "enabled_sets": ["spec_read"]
    }
  },
  "default_profile": "dirty",

  // ── Tool sets. Comment a line to disable that tool. ──────────────────
  "sets": {
    "core": [
      "open_binary", "list_binaries", "outline",
      "search", "function", "xrefs", "callgraph", "strings"
    ],
    "types": ["type_inspect", "type_search"],
    "annotate": [
      "rename", "retype", "comment", "annotate", "struct_define"
      // "patch_bytes"
    ],
    "cpp": ["rtti_classes", "vtable", "mfc_message_maps", "qt_metaobjects"],
    "delphi": ["delphi_classes", "delphi_forms", "delphi_events"],
    "dotnet": ["dotnet_types", "dotnet_decompile"],
    "resources": ["pe_resources", "dialogs", "string_tables", "version_info"],
    "dataflow": ["trace_values", "switch_tables", "constants"],
    "fileformat": ["ole_streams", "hexdump", "file_diff", "record_guess"],
    "spec_write": ["spec_write", "spec_list"],
    "spec_read": ["spec_read", "spec_list", "spec_export"],
    "admin": ["index_status", "reindex", "project_info", "frontier"]
  }
}
```

Rules:

- A tool appears in the MCP tool list only if it is in an enabled set and not
  commented out.
- A tool listed in a set that does not exist in code is a config error,
  reported by `doctor` and at startup (logged, not fatal).
- `allow_writes: false` removes `annotate` tools from the list even if the set
  is enabled. Writes are never silently refused at call time.
- A profile with `"role": "clean"` refuses to start if any of its sets contains
  a tool that returns code, addresses or bytes, or if it allows writes (§9).
- Merging: dicts merge key by key, lists replace, `null` removes an inherited
  key. A project overlay can therefore change one profile's `enabled_sets`
  without restating the rest of the file.

### Runtime set switching

Not in v1. Tool-list-changed notifications are not refreshed reliably by every
MCP client, so the config file and profile are the supported way to choose
tools. Revisit later.

---

## 4. Storage

### Layout

```
%LOCALAPPDATA%\airlock\
  projects\
    <project>\
      project.jsonc        # overlay config (optional)
      project.json         # binaries, hashes, Ghidra version, analysis profile
      ghidra\              # Ghidra project (.gpr + .rep)
      artifacts\           # private copies of imported binaries, by sha256
      index.sqlite         # derived index + agent notes + specs
      cache\               # ilspycmd output, extracted resources
      logs\
```

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
   - `lazy` (default): on first `function` request, then cached.
   - `background`: Ghidra's parallel decompiler over all non-thunk functions,
     lowest priority, interruptible by foreground requests. The package
     `ghidra.app.decompiler.parallel` (`ParallelDecompiler`,
     `ChunkingParallelDecompiler`) exists in 12.1.4 **[verified]**; how to make
     it interruptible is **[verify]**.
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
omitted when the project has one binary. Default budget is
`defaults.token_budget` (2000) unless stated; `function` uses
`defaults.function_budget` (10000).

### core

| Tool | Parameters | Returns |
|---|---|---|
| `open_binary` | `project`, `path` | binary id, format, toolchain, status (`queued`/`analysing`/`ready`) |
| `list_binaries` | `project?` | one line per binary |
| `outline` | `binary` | sections, entry points, import DLLs with counts, function counts by `name_state`, classes count, toolchain. ~300 tokens |
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
| `index_status` | `project?` | analysis/decompile progress, worker state, stale counts |
| `reindex` | `binary`, `scope=stale` (`stale`/`all`/`analyzers`) | job id |
| `project_info` | | config in effect, enabled sets, profile, paths |
| `frontier` | `limit=20` | unnamed functions ranked by call-graph centrality and how interesting their strings/imports/UI links are: "what to reverse next" |

Total with every set enabled: 44 tools. The default dirty profile enables
36 (no `delphi`, `dotnet`, `spec_read`, and `patch_bytes` commented out); the
clean profile 3.

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

`search` ordering and dedup (deterministic):

1. Match rank: exact name, then prefix, then token match.
2. Within a rank: functions with a real name, then default-named (`FUN_…`)
   functions, then strings, then imports.
3. Remaining ties keep the full-text engine's order.

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

- **Dirty session:** profile `dirty`. Reads code, decompiles, writes notes and
  specifications.
- **Clean session:** profile `clean`. Sees only `spec_read`, `spec_list`,
  `spec_export`. Never sees code, addresses, bytes or notes.

They must be separate sessions with separate MCP registrations, e.g.:

```
airlock serve --profile dirty
airlock serve --profile clean
```

One agent session that both decompiles and implements is not clean room,
whatever the tooling does.

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
2. Background decompile priority and CPU cap on large binaries (some targets have
   very large executables): thread count config, default `cores / 2`.
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
