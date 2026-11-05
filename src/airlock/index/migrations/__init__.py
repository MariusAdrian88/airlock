"""Schema migrations: ``MIGRATIONS[n]`` upgrades schema version n-1 to n."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable

MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {}


def _v2(db: sqlite3.Connection) -> None:
    """Cross-binary links: exports per binary and import->export edges between binaries."""
    for sql in (
        "CREATE TABLE IF NOT EXISTS export (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "name TEXT, ordinal INTEGER, address INTEGER NOT NULL)",
        "CREATE INDEX IF NOT EXISTS export_by_name ON export(binary_id, name)",
        "CREATE INDEX IF NOT EXISTS export_by_ordinal ON export(binary_id, ordinal)",
        "CREATE TABLE IF NOT EXISTS xedge (src_binary INTEGER NOT NULL REFERENCES binary(id), "
        "src_addr INTEGER NOT NULL, dst_binary INTEGER NOT NULL REFERENCES binary(id), "
        "dst_entry INTEGER NOT NULL, kind TEXT NOT NULL DEFAULT 'import')",
        "CREATE INDEX IF NOT EXISTS xedge_src ON xedge(src_binary, src_addr)",
        "CREATE INDEX IF NOT EXISTS xedge_dst ON xedge(dst_binary, dst_entry)",
    ):
        db.execute(sql)


MIGRATIONS[2] = _v2


def _v3(db: sqlite3.Connection) -> None:
    """Feature index: features and their entry points (auto rows are derived, agent rows kept)."""
    for sql in (
        "CREATE TABLE IF NOT EXISTS feature (key TEXT PRIMARY KEY, title TEXT NOT NULL, "
        "source TEXT NOT NULL DEFAULT 'auto', topics TEXT NOT NULL DEFAULT '', "
        "evidence TEXT NOT NULL DEFAULT '', updated TEXT)",
        "CREATE TABLE IF NOT EXISTS feature_entry (feature_key TEXT NOT NULL "
        "REFERENCES feature(key) ON DELETE CASCADE, binary_id INTEGER NOT NULL "
        "REFERENCES binary(id), space TEXT NOT NULL DEFAULT 'ram', entry INTEGER NOT NULL, "
        "reason TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '', depth INTEGER NOT NULL DEFAULT 0, "
        "source TEXT NOT NULL DEFAULT 'auto', PRIMARY KEY (feature_key, binary_id, space, entry))",
        "CREATE INDEX IF NOT EXISTS feature_entry_by_fn ON feature_entry(binary_id, space, entry)",
    ):
        db.execute(sql)


MIGRATIONS[3] = _v3


def _v4(db: sqlite3.Connection) -> None:
    """Reserved (no change)."""


MIGRATIONS.setdefault(4, _v4)


def _v5(db: sqlite3.Connection) -> None:
    """Dynamic links and ordinal imports: xedge.evidence and import.resolved."""
    for table, col in (("xedge", "evidence"), ("import", "resolved")):
        cols = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        if col not in cols:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")


MIGRATIONS[5] = _v5


def _v6(db: sqlite3.Connection) -> None:
    """string_link: strings tied to functions through data tables (derived; rebuilt by the link phase)."""
    for sql in (
        "CREATE TABLE IF NOT EXISTS string_link (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "string_addr INTEGER NOT NULL, fn_entry INTEGER NOT NULL, table_addr INTEGER NOT NULL, "
        "slot_addr INTEGER NOT NULL, evidence TEXT NOT NULL DEFAULT '')",
        "CREATE INDEX IF NOT EXISTS string_link_by_string ON string_link(binary_id, string_addr)",
        "CREATE INDEX IF NOT EXISTS string_link_by_fn ON string_link(binary_id, fn_entry)",
    ):
        db.execute(sql)


MIGRATIONS[6] = _v6


MIGRATIONS.setdefault(6, lambda db: None)   # placeholder; the real v6 is registered above when present


def _v7(db: sqlite3.Connection) -> None:
    """Specs (versioned pages), their dirty-only provenance, and the audit log (DESIGN 4, 9)."""
    for sql in (
        "CREATE TABLE IF NOT EXISTS spec (id INTEGER PRIMARY KEY, topic TEXT NOT NULL, "
        "title TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL, "
        "version INTEGER NOT NULL DEFAULT 1, author TEXT, created_at TEXT, updated_at TEXT, "
        "UNIQUE (topic, version))",
        "CREATE TABLE IF NOT EXISTS spec_provenance (spec_id INTEGER NOT NULL REFERENCES spec(id), "
        "binary_id INTEGER REFERENCES binary(id), function_id INTEGER REFERENCES function(id), "
        "address INTEGER, method TEXT)",
        "CREATE INDEX IF NOT EXISTS spec_provenance_by_spec ON spec_provenance(spec_id)",
        "CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at TEXT NOT NULL, "
        "profile TEXT NOT NULL, tool TEXT NOT NULL, args_digest TEXT, result_kind TEXT, detail TEXT)",
    ):
        db.execute(sql)


MIGRATIONS[7] = _v7


MIGRATIONS.setdefault(6, lambda db: None)   # placeholders: the real v6/v7 are registered by their own blocks
MIGRATIONS.setdefault(7, lambda db: None)


def _v8(db: sqlite3.Connection) -> None:
    """Agent notes on functions. Keyed by (binary, space, entry), not function.id: the function rows
    are rebuilt by every re-extraction, the notes must survive it."""
    for sql in (
        "CREATE TABLE IF NOT EXISTS note (id INTEGER PRIMARY KEY, "
        "binary_id INTEGER NOT NULL REFERENCES binary(id), space TEXT NOT NULL DEFAULT 'ram', "
        "entry INTEGER NOT NULL, summary TEXT NOT NULL, tags TEXT NOT NULL DEFAULT '', "
        "confidence TEXT, author TEXT, created_at TEXT)",
        "CREATE INDEX IF NOT EXISTS note_by_fn ON note(binary_id, space, entry)",
    ):
        db.execute(sql)


MIGRATIONS[8] = _v8


def _v9(db: sqlite3.Connection) -> None:
    """PE resource tables (dialogs, controls, menu items, strings); derived, filled by server/peres.py."""
    for sql in (
        "CREATE TABLE IF NOT EXISTS res_dialog (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "dialog_id TEXT NOT NULL, lang INTEGER NOT NULL, caption TEXT, x INTEGER, y INTEGER, "
        "cx INTEGER, cy INTEGER, PRIMARY KEY (binary_id, dialog_id, lang))",
        "CREATE TABLE IF NOT EXISTS res_control (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "dialog_id TEXT NOT NULL, lang INTEGER NOT NULL, ctrl_id INTEGER, class TEXT, caption TEXT, "
        "style TEXT, seq INTEGER NOT NULL)",
        "CREATE INDEX IF NOT EXISTS res_control_by_dialog ON res_control(binary_id, dialog_id, lang, seq)",
        "CREATE INDEX IF NOT EXISTS res_control_by_id ON res_control(binary_id, ctrl_id)",
        "CREATE TABLE IF NOT EXISTS res_menu_item (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "menu_id TEXT NOT NULL, lang INTEGER NOT NULL, item_id INTEGER, caption TEXT, path TEXT, "
        "seq INTEGER NOT NULL)",
        "CREATE INDEX IF NOT EXISTS res_menu_item_by_menu ON res_menu_item(binary_id, menu_id, lang, seq)",
        "CREATE INDEX IF NOT EXISTS res_menu_item_by_id ON res_menu_item(binary_id, item_id)",
        "CREATE TABLE IF NOT EXISTS res_string (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "string_id INTEGER NOT NULL, lang INTEGER NOT NULL, text TEXT)",
        "CREATE INDEX IF NOT EXISTS res_string_by_id ON res_string(binary_id, string_id)",
    ):
        db.execute(sql)


MIGRATIONS[9] = _v9


MIGRATIONS.setdefault(9, lambda db: None)   # placeholder: the real v9 (resource tables) is registered above when present


def _v10(db: sqlite3.Connection) -> None:
    """C++ tables from the PE bytes (MSVC RTTI, vtables, MFC message maps); derived, rebuilt by
    server/cpp.py. ``handler`` and ``ctrl_id`` join with function entries and resource ids."""
    for sql in (
        "CREATE TABLE IF NOT EXISTS rtti_class (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "name TEXT NOT NULL, td_addr INTEGER NOT NULL, col_addr INTEGER NOT NULL, vtable_addr INTEGER, "
        "bases TEXT NOT NULL DEFAULT '', PRIMARY KEY (binary_id, td_addr, col_addr))",
        "CREATE INDEX IF NOT EXISTS rtti_class_by_name ON rtti_class(binary_id, name)",
        "CREATE INDEX IF NOT EXISTS rtti_class_by_vtable ON rtti_class(binary_id, vtable_addr)",
        "CREATE TABLE IF NOT EXISTS vtable_slot (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "vtable_addr INTEGER NOT NULL, slot INTEGER NOT NULL, target INTEGER NOT NULL)",
        "CREATE INDEX IF NOT EXISTS vtable_slot_by_vtable ON vtable_slot(binary_id, vtable_addr, slot)",
        "CREATE INDEX IF NOT EXISTS vtable_slot_by_target ON vtable_slot(binary_id, target)",
        "CREATE TABLE IF NOT EXISTS msgmap_entry (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "class TEXT NOT NULL, map_addr INTEGER NOT NULL, message INTEGER NOT NULL, code INTEGER NOT NULL, "
        "ctrl_id INTEGER NOT NULL, last_id INTEGER NOT NULL, sig INTEGER NOT NULL, "
        "handler INTEGER NOT NULL, seq INTEGER NOT NULL)",
        "CREATE INDEX IF NOT EXISTS msgmap_entry_by_ctrl ON msgmap_entry(binary_id, ctrl_id)",
        "CREATE INDEX IF NOT EXISTS msgmap_entry_by_class ON msgmap_entry(binary_id, class, map_addr, seq)",
        "CREATE INDEX IF NOT EXISTS msgmap_entry_by_handler ON msgmap_entry(binary_id, handler)",
    ):
        db.execute(sql)


MIGRATIONS[10] = _v10


def _v11(db: sqlite3.Connection) -> None:
    """.NET metadata tables (types, methods, P/Invokes); derived, filled by server/dotnet.py."""
    for sql in (
        "CREATE TABLE IF NOT EXISTS dn_type (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "token INTEGER NOT NULL, name TEXT NOT NULL, kind TEXT NOT NULL, base TEXT, "
        "flags TEXT NOT NULL DEFAULT '', PRIMARY KEY (binary_id, token))",
        "CREATE INDEX IF NOT EXISTS dn_type_by_name ON dn_type(binary_id, name)",
        "CREATE TABLE IF NOT EXISTS dn_method (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "token INTEGER NOT NULL, type_token INTEGER NOT NULL, name TEXT NOT NULL, sig TEXT NOT NULL, "
        "flags TEXT NOT NULL DEFAULT '', PRIMARY KEY (binary_id, token))",
        "CREATE INDEX IF NOT EXISTS dn_method_by_type ON dn_method(binary_id, type_token)",
        "CREATE TABLE IF NOT EXISTS dn_pinvoke (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "token INTEGER NOT NULL, module TEXT NOT NULL, entry TEXT, ordinal INTEGER, "
        "flags TEXT NOT NULL DEFAULT '', PRIMARY KEY (binary_id, token))",
    ):
        db.execute(sql)


MIGRATIONS[11] = _v11
MIGRATIONS.setdefault(11, lambda db: None)   # placeholder: the real v11 (.NET tables) is registered above


def _v12(db: sqlite3.Connection) -> None:
    """Delphi classes, published methods, DFM forms and events; derived, filled by server/delphi.py."""
    for sql in (
        "CREATE TABLE IF NOT EXISTS dl_class (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "vmt INTEGER NOT NULL, name TEXT NOT NULL, parent_vmt INTEGER, parent TEXT NOT NULL DEFAULT '', "
        "size INTEGER NOT NULL, unit TEXT NOT NULL DEFAULT '', typeinfo INTEGER, "
        "nvirtual INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (binary_id, vmt))",
        "CREATE INDEX IF NOT EXISTS dl_class_by_name ON dl_class(binary_id, name)",
        "CREATE TABLE IF NOT EXISTS dl_method (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "vmt INTEGER NOT NULL, kind TEXT NOT NULL, slot INTEGER NOT NULL, name TEXT NOT NULL DEFAULT '', "
        "addr INTEGER NOT NULL)",
        "CREATE INDEX IF NOT EXISTS dl_method_by_class ON dl_method(binary_id, vmt, kind, slot)",
        "CREATE INDEX IF NOT EXISTS dl_method_by_addr ON dl_method(binary_id, addr)",
        "CREATE TABLE IF NOT EXISTS dl_field (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "vmt INTEGER NOT NULL, name TEXT NOT NULL, offset INTEGER NOT NULL, type TEXT NOT NULL DEFAULT '')",
        "CREATE INDEX IF NOT EXISTS dl_field_by_class ON dl_field(binary_id, vmt)",
        "CREATE TABLE IF NOT EXISTS dl_form (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "res_name TEXT NOT NULL, class TEXT NOT NULL, name TEXT NOT NULL, caption TEXT NOT NULL DEFAULT '', "
        "ncomp INTEGER NOT NULL, nevents INTEGER NOT NULL, flags TEXT NOT NULL DEFAULT '', "
        "PRIMARY KEY (binary_id, res_name))",
        "CREATE TABLE IF NOT EXISTS dl_component (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "form TEXT NOT NULL, seq INTEGER NOT NULL, parent INTEGER NOT NULL, depth INTEGER NOT NULL, "
        "name TEXT NOT NULL, class TEXT NOT NULL, flags TEXT NOT NULL DEFAULT '', "
        "caption TEXT NOT NULL DEFAULT '', PRIMARY KEY (binary_id, form, seq))",
        "CREATE TABLE IF NOT EXISTS dl_event (binary_id INTEGER NOT NULL REFERENCES binary(id), "
        "form TEXT NOT NULL, seq INTEGER NOT NULL, prop TEXT NOT NULL, handler TEXT NOT NULL, "
        "owner TEXT NOT NULL, addr INTEGER)",
        "CREATE INDEX IF NOT EXISTS dl_event_by_form ON dl_event(binary_id, form, seq)",
        "CREATE INDEX IF NOT EXISTS dl_event_by_addr ON dl_event(binary_id, addr)",
    ):
        db.execute(sql)


MIGRATIONS[12] = _v12
MIGRATIONS.setdefault(12, lambda db: None)   # placeholder: the real v12 (Delphi tables) is registered above


def _v13(db: sqlite3.Connection) -> None:
    """Qt metaobjects (classes, methods, properties, enums, string connections); derived, filled by
    server/qt.py. The statements are the Qt block of schema.sql, made idempotent."""
    from importlib import resources
    sql = resources.files("airlock.index").joinpath("schema.sql").read_text("utf-8")
    block = sql[sql.index("CREATE TABLE qt_class"):]
    block = "\n".join(ln.split("--", 1)[0] for ln in block.splitlines())     # comments may hold a ';'
    for stmt in block.split(";"):
        text = " ".join(stmt.split())
        if not text:
            continue
        if text.startswith("CREATE TABLE"):
            text = text.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
        else:
            text = text.replace("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ", 1)
        db.execute(text)


MIGRATIONS[13] = _v13
MIGRATIONS.setdefault(13, lambda db: None)   # placeholder: the real v13 (Qt tables) is registered above
