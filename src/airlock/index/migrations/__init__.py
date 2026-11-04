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
