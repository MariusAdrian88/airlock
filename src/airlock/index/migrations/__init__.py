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
