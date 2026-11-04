"""Schema migrations: ``MIGRATIONS[n]`` upgrades schema version n-1 to n."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable

MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {}
