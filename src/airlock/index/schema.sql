-- airlock index schema v2 (M1 subset of DESIGN.md section 4 plus export/xedge).
CREATE TABLE binary (
  id            INTEGER PRIMARY KEY,
  sha256        TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  original_path TEXT,
  format        TEXT,
  arch          TEXT,
  pointer_size  INTEGER,
  image_base    INTEGER,
  toolchain     TEXT,
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
  name_state    TEXT NOT NULL,
  namespace     TEXT,
  signature     TEXT,
  calling_conv  TEXT,
  size          INTEGER,
  is_thunk      INTEGER NOT NULL DEFAULT 0,
  is_external   INTEGER NOT NULL DEFAULT 0,
  bytes_hash    TEXT,
  masked_hash   TEXT,
  version       INTEGER NOT NULL DEFAULT 0,
  UNIQUE (binary_id, space, entry)
);
CREATE INDEX function_by_name ON function(binary_id, name);

CREATE TABLE decomp (
  function_id   INTEGER PRIMARY KEY REFERENCES function(id),
  fn_version    INTEGER NOT NULL,
  analysis_profile TEXT NOT NULL,
  c_text        TEXT,
  status        TEXT NOT NULL,
  error         TEXT,
  produced_at   TEXT
);

CREATE TABLE ast_node (
  id            INTEGER PRIMARY KEY,
  function_id   INTEGER NOT NULL REFERENCES function(id),
  kind          TEXT NOT NULL,
  start_off     INTEGER NOT NULL,
  end_off       INTEGER NOT NULL,
  address       INTEGER,
  target        INTEGER,
  text          TEXT
);
CREATE INDEX ast_by_fn ON ast_node(function_id, kind);

CREATE TABLE edge (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  src_fn        INTEGER REFERENCES function(id),
  src_addr      INTEGER NOT NULL,
  dst_fn        INTEGER REFERENCES function(id),
  dst_addr      INTEGER NOT NULL,
  kind          TEXT NOT NULL
);
CREATE INDEX edge_dst ON edge(binary_id, dst_addr, kind);
CREATE INDEX edge_src ON edge(binary_id, src_addr, kind);
CREATE INDEX edge_src_fn ON edge(src_fn, kind);
CREATE INDEX edge_dst_fn ON edge(dst_fn, kind);

CREATE TABLE string (
  id            INTEGER PRIMARY KEY,
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  address       INTEGER NOT NULL,
  encoding      TEXT NOT NULL,
  value         TEXT NOT NULL
);
CREATE INDEX string_by_addr ON string(binary_id, address);

CREATE TABLE import (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  dll           TEXT,
  name          TEXT,
  ordinal       INTEGER,
  address       INTEGER
);
CREATE INDEX import_by_binary ON import(binary_id, dll);

CREATE TABLE export (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  name          TEXT,
  ordinal       INTEGER,
  address       INTEGER NOT NULL
);
CREATE INDEX export_by_name ON export(binary_id, name);
CREATE INDEX export_by_ordinal ON export(binary_id, ordinal);

-- cross-binary edges: an import slot (or its thunk) in src_binary -> function entry in dst_binary
CREATE TABLE xedge (
  src_binary    INTEGER NOT NULL REFERENCES binary(id),
  src_addr      INTEGER NOT NULL,
  dst_binary    INTEGER NOT NULL REFERENCES binary(id),
  dst_entry     INTEGER NOT NULL,
  kind          TEXT NOT NULL DEFAULT 'import'
);
CREATE INDEX xedge_src ON xedge(src_binary, src_addr);
CREATE INDEX xedge_dst ON xedge(dst_binary, dst_entry);

CREATE VIRTUAL TABLE fts USING fts5(
  kind, ref_id UNINDEXED, binary_id UNINDEXED, text,
  tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
