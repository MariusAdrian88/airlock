"""Platform locations for the global config and the data directory.

Windows: config in %APPDATA%\\airlock, data in %LOCALAPPDATA%\\airlock.
Elsewhere: XDG locations (~/.config/airlock, ~/.local/share/airlock).

These read the OS-defined location variables only; airlock has no
environment variables of its own.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP = "airlock"


def is_windows() -> bool:
    return sys.platform == "win32"


def config_dir() -> Path:
    if is_windows():
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / APP
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP


def default_config_path() -> Path:
    return config_dir() / "config.jsonc"


def default_projects_root() -> Path:
    return Path.home() / "airlock-projects"


def default_data_dir() -> Path:
    if is_windows():
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / APP
