"""Drive type checks (SQLite WAL is unreliable on network drives)."""

from __future__ import annotations

import sys
from pathlib import Path


def is_network_path(path: Path) -> bool | None:
    """True if path is on a network drive, False if local, None if unknown."""
    if sys.platform != "win32":
        return None
    s = str(path.resolve() if path.exists() else path)
    if s.startswith("\\\\"):
        return True  # UNC path
    import ctypes

    drive = Path(s).anchor  # "C:\\"
    if not drive:
        return None
    DRIVE_REMOTE = 4
    return ctypes.windll.kernel32.GetDriveTypeW(drive) == DRIVE_REMOTE
