"""Facts about a Ghidra installation that can be read without starting a JVM.

Layout checked against the Ghidra 12.1.4 source:
  <ghidra_dir>/Ghidra/application.properties        version, java.min, python.supported
  <ghidra_dir>/support/LaunchSupport.jar            JDK discovery (used by PyGhidra)
  <ghidra_dir>/Ghidra/Features/PyGhidra/pypkg/dist  pyghidra wheel + bundled JPype wheels
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class GhidraInstall:
    root: Path
    version: str | None
    java_min: int | None
    python_supported: list[str]
    pypkg_dist: Path | None
    pyghidra_wheel: Path | None
    jpype_python_tags: list[str]  # e.g. ["cp313", "cp312", ...] for this OS

    @property
    def pyghidra_version(self) -> str | None:
        if self.pyghidra_wheel is None:
            return None
        m = re.match(r"pyghidra-([^-]+)-", self.pyghidra_wheel.name)
        return m.group(1) if m else None

    def bundled_jpype_for(self, major: int, minor: int) -> bool:
        return f"cp{major}{minor}" in self.jpype_python_tags


def read_properties(path: Path) -> dict[str, str]:
    props: dict[str, str] = {}
    for line in path.read_text("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        props[key.strip()] = value.strip()
    return props


def _platform_tag() -> str:
    if sys.platform == "win32":
        return "win_amd64"
    if sys.platform == "darwin":
        return "macosx"
    return "manylinux"


def inspect(root: Path) -> GhidraInstall:
    """Read an install directory. Raises FileNotFoundError if it is not Ghidra."""
    props_file = root / "Ghidra" / "application.properties"
    if not props_file.is_file():
        raise FileNotFoundError(f"{root} is not a Ghidra installation ({props_file} missing)")
    props = read_properties(props_file)

    java_min = props.get("application.java.min")
    python_supported = [
        v.strip() for v in props.get("application.python.supported", "").split(",") if v.strip()
    ]

    dist = root / "Ghidra" / "Features" / "PyGhidra" / "pypkg" / "dist"
    wheel = None
    tags: list[str] = []
    if dist.is_dir():
        wheels = sorted(dist.glob("pyghidra-*.whl"))
        wheel = wheels[-1] if wheels else None
        plat = _platform_tag()
        for w in dist.glob("jpype1-*.whl"):
            m = re.match(r"jpype1-[^-]+-(cp\d+)-", w.name)
            if m and plat in w.name:
                tags.append(m.group(1))
    else:
        dist = None

    return GhidraInstall(
        root=root,
        version=props.get("application.version"),
        java_min=int(java_min) if java_min and java_min.isdigit() else None,
        python_supported=python_supported,
        pypkg_dist=dist,
        pyghidra_wheel=wheel,
        jpype_python_tags=sorted(set(tags), reverse=True),
    )
