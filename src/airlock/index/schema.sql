-- airlock index schema v3 (M1 subset of DESIGN.md section 4 plus export/xedge and the feature index).
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
  address       INTEGER,
  resolved      TEXT
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
  kind          TEXT NOT NULL DEFAULT 'import',
  evidence      TEXT
);
CREATE INDEX xedge_src ON xedge(src_binary, src_addr);
CREATE INDEX xedge_dst ON xedge(dst_binary, dst_entry);

-- feature index (DESIGN 4 "Project map and feature index"); source 'auto' is rebuilt on every
-- derivation, source 'agent' (feature_define) survives it.
CREATE TABLE feature (
  key           TEXT PRIMARY KEY,
  title         TEXT NOT NULL,
  source        TEXT NOT NULL DEFAULT 'auto',
  topics        TEXT NOT NULL DEFAULT '',
  evidence      TEXT NOT NULL DEFAULT '',
  updated       TEXT
);

CREATE TABLE feature_entry (
  feature_key   TEXT NOT NULL REFERENCES feature(key) ON DELETE CASCADE,
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  space         TEXT NOT NULL DEFAULT 'ram',
  entry         INTEGER NOT NULL,
  reason        TEXT NOT NULL,
  evidence      TEXT NOT NULL DEFAULT '',
  depth         INTEGER NOT NULL DEFAULT 0,
  source        TEXT NOT NULL DEFAULT 'auto',
  PRIMARY KEY (feature_key, binary_id, space, entry)
);
CREATE INDEX feature_entry_by_fn ON feature_entry(binary_id, space, entry);

-- strings tied to functions through data tables (derived by the link phase: a record or parallel
-- arrays holding a string pointer and a function pointer; table_addr = first slot of the table)
CREATE TABLE string_link (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  string_addr   INTEGER NOT NULL,
  fn_entry      INTEGER NOT NULL,
  table_addr    INTEGER NOT NULL,
  slot_addr     INTEGER NOT NULL,
  evidence      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX string_link_by_string ON string_link(binary_id, string_addr);
CREATE INDEX string_link_by_fn ON string_link(binary_id, fn_entry);

CREATE VIRTUAL TABLE fts USING fts5(
  kind, ref_id UNINDEXED, binary_id UNINDEXED, text,
  tokenize = 'unicode61 remove_diacritics 2'
);

-- Clean-room specifications (DESIGN 9). Agent data: kept across re-extraction, never rebuilt.
CREATE TABLE spec (
  id            INTEGER PRIMARY KEY,
  topic         TEXT NOT NULL,
  title         TEXT NOT NULL,
  body          TEXT NOT NULL,
  status        TEXT NOT NULL,  -- draft | reviewed | final
  version       INTEGER NOT NULL DEFAULT 1,
  author        TEXT,
  created_at    TEXT,
  updated_at    TEXT,
  UNIQUE (topic, version)
);
-- Dirty-only: what each spec version was derived from.
CREATE TABLE spec_provenance (
  spec_id       INTEGER NOT NULL REFERENCES spec(id),
  binary_id     INTEGER REFERENCES binary(id),
  function_id   INTEGER REFERENCES function(id),
  address       INTEGER,
  method        TEXT            -- decompile | file_diff | resources | observation
);
CREATE INDEX spec_provenance_by_spec ON spec_provenance(spec_id);
-- Append-only log of spec writes and publishes (profile = session role).
CREATE TABLE audit (
  id            INTEGER PRIMARY KEY,
  at            TEXT NOT NULL,
  profile       TEXT NOT NULL,
  tool          TEXT NOT NULL,
  args_digest   TEXT,
  result_kind   TEXT,
  detail        TEXT
);

-- Agent notes on functions (DESIGN 4). Agent data: kept across re-extraction, never rebuilt. Keyed by
-- address, not function.id, because function rows are recreated by every re-extraction.
CREATE TABLE note (
  id            INTEGER PRIMARY KEY,
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  space         TEXT NOT NULL DEFAULT 'ram',
  entry         INTEGER NOT NULL,
  summary       TEXT NOT NULL,
  tags          TEXT NOT NULL DEFAULT '',   -- comma separated
  confidence    TEXT,                       -- low | medium | high
  author        TEXT,
  created_at    TEXT
);
CREATE INDEX note_by_fn ON note(binary_id, space, entry);

-- PE resources (DESIGN 6 "resources"), parsed server side with pefile. Derived: rebuilt when the
-- index meta resources_version:<binary id> is older than RESOURCES_VERSION (server/peres.py).
CREATE TABLE res_dialog (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  dialog_id     TEXT NOT NULL,           -- numeric resource id or resource name
  lang          INTEGER NOT NULL,
  caption       TEXT,
  x INTEGER, y INTEGER, cx INTEGER, cy INTEGER,
  PRIMARY KEY (binary_id, dialog_id, lang)
);
CREATE TABLE res_control (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  dialog_id     TEXT NOT NULL,
  lang          INTEGER NOT NULL,
  ctrl_id       INTEGER,                 -- -1 = IDC_STATIC
  class         TEXT,                    -- Button, Edit, Static, ... or the registered class name
  caption       TEXT,
  style         TEXT,                    -- short words: BS_PUSHBUTTON,tabstop
  seq           INTEGER NOT NULL
);
CREATE INDEX res_control_by_dialog ON res_control(binary_id, dialog_id, lang, seq);
CREATE INDEX res_control_by_id ON res_control(binary_id, ctrl_id);
CREATE TABLE res_menu_item (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  menu_id       TEXT NOT NULL,
  lang          INTEGER NOT NULL,
  item_id       INTEGER,                 -- NULL for a popup
  caption       TEXT,
  path          TEXT,                    -- "File > Open..."
  seq           INTEGER NOT NULL
);
CREATE INDEX res_menu_item_by_menu ON res_menu_item(binary_id, menu_id, lang, seq);
CREATE INDEX res_menu_item_by_id ON res_menu_item(binary_id, item_id);
CREATE TABLE res_string (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  string_id     INTEGER NOT NULL,        -- (block - 1) * 16 + index
  lang          INTEGER NOT NULL,
  text          TEXT
);
CREATE INDEX res_string_by_id ON res_string(binary_id, string_id);

-- C++ (DESIGN 11), parsed server side from the PE bytes (server/cpp.py). Derived: rebuilt when the
-- index meta cpp_version:<binary id> is older than CPP_VERSION.
CREATE TABLE rtti_class (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  name          TEXT NOT NULL,           -- demangled: A::B
  td_addr       INTEGER NOT NULL,        -- type descriptor
  col_addr      INTEGER NOT NULL,        -- complete object locator
  vtable_addr   INTEGER,                 -- first slot; NULL when no vtable references the COL
  bases         TEXT NOT NULL DEFAULT '',   -- direct base classes, ", " separated
  PRIMARY KEY (binary_id, td_addr, col_addr)
);
CREATE INDEX rtti_class_by_name ON rtti_class(binary_id, name);
CREATE INDEX rtti_class_by_vtable ON rtti_class(binary_id, vtable_addr);
CREATE TABLE vtable_slot (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  vtable_addr   INTEGER NOT NULL,
  slot          INTEGER NOT NULL,
  target        INTEGER NOT NULL
);
CREATE INDEX vtable_slot_by_vtable ON vtable_slot(binary_id, vtable_addr, slot);
CREATE INDEX vtable_slot_by_target ON vtable_slot(binary_id, target);
CREATE TABLE msgmap_entry (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  class         TEXT NOT NULL,           -- RTTI name, or anon_<map address> without RTTI
  map_addr      INTEGER NOT NULL,        -- the AFX_MSGMAP
  message       INTEGER NOT NULL,        -- nMessage
  code          INTEGER NOT NULL,        -- nCode (WM_COMMAND: 0 command, 0xFFFFFFFF update-UI)
  ctrl_id       INTEGER NOT NULL,        -- nID
  last_id       INTEGER NOT NULL,        -- nLastID (ranges)
  sig           INTEGER NOT NULL,        -- nSig (AfxSig_*; a pointer for registered messages)
  handler       INTEGER NOT NULL,        -- pfn
  seq           INTEGER NOT NULL
);
CREATE INDEX msgmap_entry_by_ctrl ON msgmap_entry(binary_id, ctrl_id);
CREATE INDEX msgmap_entry_by_class ON msgmap_entry(binary_id, class, map_addr, seq);
CREATE INDEX msgmap_entry_by_handler ON msgmap_entry(binary_id, handler);

CREATE TABLE mfc_class (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  name          TEXT NOT NULL,           -- CRuntimeClass name, Dialog_<caption>, or anon_<base>_<map address>
  vtable_addr   INTEGER NOT NULL,        -- the slot of GetRuntimeClass (first virtual function)
  rc_addr       INTEGER NOT NULL DEFAULT 0,   -- CRuntimeClass the class declares (0: it only inherits one)
  obj_size      INTEGER NOT NULL DEFAULT 0,   -- CRuntimeClass.m_nObjectSize
  schema        INTEGER NOT NULL DEFAULT 0,   -- CRuntimeClass.m_wSchema
  base          TEXT NOT NULL DEFAULT '',     -- base class: owner of the base message map, else of the base CRuntimeClass
  map_addr      INTEGER NOT NULL DEFAULT 0,   -- its AFX_MSGMAP (0: none)
  dialog        TEXT NOT NULL DEFAULT '',     -- dialog resource id passed to the CDialog constructor
  source        TEXT NOT NULL,                -- rc | dialog | inherited | routes (route table, routes.py)
  PRIMARY KEY (binary_id, vtable_addr)
);
CREATE INDEX mfc_class_by_name ON mfc_class(binary_id, name);
CREATE TABLE mfc_map_entry (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  class         TEXT NOT NULL,
  kind          TEXT NOT NULL,           -- dispatch | interface | event
  map_addr      INTEGER NOT NULL,
  seq           INTEGER NOT NULL,
  name          TEXT NOT NULL,           -- dispatch: member name; interface: IID name or GUID
  id            INTEGER NOT NULL,        -- dispatch: DISPID; interface: offset in the object; event: DISPID
  vt            INTEGER NOT NULL,        -- dispatch: VT of the value / return
  flags         INTEGER NOT NULL,        -- dispatch: afxDispStock = 1
  pfn           INTEGER,                 -- method / getter / event handler
  pfn_set       INTEGER,                 -- property setter
  extra         TEXT NOT NULL            -- argument types, data offset, control ids
);
CREATE INDEX mfc_map_entry_by_class ON mfc_map_entry(binary_id, class, kind, map_addr, seq);
CREATE INDEX mfc_map_entry_by_fn ON mfc_map_entry(binary_id, pfn);

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);

-- .NET metadata (DESIGN 11), parsed server side with dnfile (server/dotnet.py). Derived: rebuilt when
-- the index meta dotnet_version:<binary id> is older than DOTNET_VERSION. Tokens are metadata tokens
-- (type 0x02xxxxxx, method 0x06xxxxxx). A P/Invoke method also gets a thunk function (entry = token)
-- and an import row (address = token), so the import linking binds it to a project export.
CREATE TABLE dn_type (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  token         INTEGER NOT NULL,
  name          TEXT NOT NULL,           -- Namespace.Outer+Inner (the form ilspycmd -t takes)
  kind          TEXT NOT NULL,           -- class | interface | struct | enum | delegate
  base          TEXT,
  flags         TEXT NOT NULL DEFAULT '',   -- public, abstract, sealed, static, com (ComImport), nested
  PRIMARY KEY (binary_id, token)
);
CREATE INDEX dn_type_by_name ON dn_type(binary_id, name);
CREATE TABLE dn_method (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  token         INTEGER NOT NULL,
  type_token    INTEGER NOT NULL,
  name          TEXT NOT NULL,
  sig           TEXT NOT NULL,           -- ret(params), simple type names
  flags         TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (binary_id, token)
);
CREATE INDEX dn_method_by_type ON dn_method(binary_id, type_token);
CREATE TABLE dn_pinvoke (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  token         INTEGER NOT NULL,        -- the method
  module        TEXT NOT NULL,           -- as declared (user32, kernel32.dll)
  entry         TEXT,                    -- entry point name; NULL for an ordinal
  ordinal       INTEGER,
  flags         TEXT NOT NULL DEFAULT '',   -- charset, calling convention, lasterror
  PRIMARY KEY (binary_id, token)
);

-- Delphi (schema v12): classes from VMTs, published methods, DFM forms and events. Derived, filled by
-- server/delphi.py; events carry the resolved handler address (NULL when the method is not published).
CREATE TABLE dl_class (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  vmt           INTEGER NOT NULL,        -- class reference (address of the first virtual slot)
  name          TEXT NOT NULL,
  parent_vmt    INTEGER,
  parent        TEXT NOT NULL DEFAULT '',
  size          INTEGER NOT NULL,        -- instance size
  unit          TEXT NOT NULL DEFAULT '',
  typeinfo      INTEGER,
  nvirtual      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (binary_id, vmt)
);
CREATE INDEX dl_class_by_name ON dl_class(binary_id, name);
CREATE TABLE dl_method (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  vmt           INTEGER NOT NULL,
  kind          TEXT NOT NULL,           -- published | virtual
  slot          INTEGER NOT NULL,
  name          TEXT NOT NULL DEFAULT '',   -- empty for virtual methods
  addr          INTEGER NOT NULL
);
CREATE INDEX dl_method_by_class ON dl_method(binary_id, vmt, kind, slot);
CREATE INDEX dl_method_by_addr ON dl_method(binary_id, addr);
CREATE TABLE dl_field (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  vmt           INTEGER NOT NULL,
  name          TEXT NOT NULL,
  offset        INTEGER NOT NULL,
  type          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX dl_field_by_class ON dl_field(binary_id, vmt);
CREATE TABLE dl_form (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  res_name      TEXT NOT NULL,           -- RCDATA resource name (the form class, upper case)
  class         TEXT NOT NULL,
  name          TEXT NOT NULL,
  caption       TEXT NOT NULL DEFAULT '',
  ncomp         INTEGER NOT NULL,
  nevents       INTEGER NOT NULL,
  flags         TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (binary_id, res_name)
);
CREATE TABLE dl_component (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  form          TEXT NOT NULL,           -- dl_form.res_name
  seq           INTEGER NOT NULL,        -- document order, 0 = the form
  parent        INTEGER NOT NULL,
  depth         INTEGER NOT NULL,
  name          TEXT NOT NULL,
  class         TEXT NOT NULL,
  flags         TEXT NOT NULL DEFAULT '',   -- inherited, inline
  caption       TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (binary_id, form, seq)
);
CREATE TABLE dl_event (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  form          TEXT NOT NULL,
  seq           INTEGER NOT NULL,        -- dl_component.seq
  prop          TEXT NOT NULL,           -- OnClick, Columns[0].OnClick
  handler       TEXT NOT NULL,           -- method name from the DFM
  owner         TEXT NOT NULL,           -- class that should declare the method
  addr          INTEGER                  -- code address from the published method table
);
CREATE INDEX dl_event_by_form ON dl_event(binary_id, form, seq);
CREATE INDEX dl_event_by_addr ON dl_event(binary_id, addr);

-- Qt metaobjects (DESIGN 11), parsed server side from the PE bytes (server/qt.py). Derived: rebuilt when
-- the index meta qt_version:<binary id> is older than QT_VERSION. qt_method.addr and qt_class.parent
-- (when the superclass is imported) come from the worker op qt_dispatch (meta qt_dispatch:<binary id>).
CREATE TABLE qt_class (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  meta_addr     INTEGER NOT NULL,        -- staticMetaObject
  name          TEXT NOT NULL,           -- Qt class name, Ns::Foo
  major         INTEGER NOT NULL,        -- 5 or 6
  revision      INTEGER NOT NULL,        -- moc output revision (data[0])
  super_addr    INTEGER,                 -- d.superdata, NULL when not stored in the file
  parent        TEXT NOT NULL DEFAULT '',
  metacall      INTEGER,                 -- d.static_metacall
  data_addr     INTEGER NOT NULL,
  nsignals      INTEGER NOT NULL,
  nmethods      INTEGER NOT NULL,
  nprops        INTEGER NOT NULL,
  nenums        INTEGER NOT NULL,
  nctors        INTEGER NOT NULL,
  info          TEXT NOT NULL DEFAULT '',   -- Q_CLASSINFO key=value;...
  PRIMARY KEY (binary_id, meta_addr)
);
CREATE INDEX qt_class_by_name ON qt_class(binary_id, name);
CREATE TABLE qt_method (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  meta_addr     INTEGER NOT NULL,
  idx           INTEGER NOT NULL,        -- method index in the class (the id of qt_static_metacall)
  kind          TEXT NOT NULL,           -- signal | slot | method | constructor
  name          TEXT NOT NULL,
  ret           TEXT NOT NULL DEFAULT '',
  params        TEXT NOT NULL DEFAULT '',   -- "int count, QString text"
  access        TEXT NOT NULL DEFAULT '',   -- public | protected | private
  flags         INTEGER NOT NULL DEFAULT 0,
  addr          INTEGER,                 -- function that runs it (worker op qt_dispatch)
  PRIMARY KEY (binary_id, meta_addr, kind, idx)
);
CREATE INDEX qt_method_by_addr ON qt_method(binary_id, addr);
CREATE INDEX qt_method_by_name ON qt_method(binary_id, name);
CREATE TABLE qt_prop (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  meta_addr     INTEGER NOT NULL,
  idx           INTEGER NOT NULL,
  name          TEXT NOT NULL,
  type          TEXT NOT NULL DEFAULT '',
  flags         INTEGER NOT NULL DEFAULT 0,
  notify        INTEGER,                 -- signal index in the class, NULL without one
  PRIMARY KEY (binary_id, meta_addr, idx)
);
CREATE TABLE qt_enum (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  meta_addr     INTEGER NOT NULL,
  idx           INTEGER NOT NULL,
  name          TEXT NOT NULL,
  is_flag       INTEGER NOT NULL DEFAULT 0,
  vals          TEXT NOT NULL DEFAULT '',   -- "A=0,B=1"
  PRIMARY KEY (binary_id, meta_addr, idx)
);
CREATE TABLE qt_connect (
  binary_id     INTEGER NOT NULL REFERENCES binary(id),
  fn_entry      INTEGER NOT NULL,        -- function that makes the connection
  site          INTEGER NOT NULL,        -- address of the reference to the signal string / call
  kind          TEXT NOT NULL,           -- string | ptr
  signal        TEXT NOT NULL DEFAULT '',   -- name(args) of the SIGNAL() string
  slot          TEXT NOT NULL DEFAULT '',   -- name(args) of the SLOT() / SIGNAL() string
  slot_kind     TEXT NOT NULL DEFAULT ''    -- slot | signal
);
CREATE INDEX qt_connect_by_fn ON qt_connect(binary_id, fn_entry);
