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
