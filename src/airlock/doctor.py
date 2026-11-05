"""`airlock doctor`: check the installation, optionally fix it and start Ghidra."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from airlock import ghidra_install
from airlock.config import Config, ConfigError, load_config
from airlock.win import drives

RECOMMENDED_PY = ((3, 10), (3, 13))


@dataclass
class Check:
    status: str  # OK | WARN | FAIL | FIXED
    name: str
    detail: str

    def line(self) -> str:
        return f"[{self.status:<5}] {self.name}: {self.detail}"


def _java_version(java: str) -> tuple[int | None, str]:
    try:
        r = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, str(e)
    text = (r.stderr or r.stdout).strip()
    m = re.search(r'version "(\d+)(?:\.(\d+))?', text)
    if not m:
        return None, text.splitlines()[0] if text else "no output"
    major = int(m.group(1))
    if major == 1 and m.group(2):  # "1.8"
        major = int(m.group(2))
    return major, text.splitlines()[0]


def _java_exe(jdk: Path) -> Path:
    return jdk / "bin" / ("java.exe" if sys.platform == "win32" else "java")


def _pyghidra_installed() -> str | None:
    try:
        from importlib.metadata import version
        return version("pyghidra")
    except Exception:
        return None


def install_pyghidra(info: ghidra_install.GhidraInstall) -> tuple[bool, str]:
    """pip install pyghidra (and JPype) from the wheels bundled with Ghidra, offline."""
    if info.pypkg_dist is None:
        return False, "Ghidra has no bundled PyGhidra packages"
    cmd = [sys.executable, "-m", "pip", "install", "--no-index",
           "-f", str(info.pypkg_dist), "pyghidra"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        tail = (r.stderr or r.stdout).strip().splitlines()[-3:]
        return False, " | ".join(tail)
    return True, f"installed pyghidra from {info.pypkg_dist}"


def run(config_path: Path | None, profile: str | None, fix: bool, start: bool) -> int:
    checks: list[Check] = []
    add = checks.append

    # Python
    v = sys.version_info
    py = f"{v.major}.{v.minor}.{v.micro} ({sys.executable})"
    lo, hi = RECOMMENDED_PY
    add(Check("OK" if lo <= (v.major, v.minor) <= hi else "WARN", "python",
              py if lo <= (v.major, v.minor) <= hi else
              f"{py}; Ghidra bundles JPype wheels for 3.9–3.13 only, use 3.13"))

    # Config
    try:
        cfg: Config = load_config(config_path, profile)
    except ConfigError as e:
        add(Check("FAIL", "config", str(e)))
        _print(checks)
        return 1
    add(Check("OK" if cfg.source else "WARN", "config",
              str(cfg.source) if cfg.source else
              "no config file; run `airlock init --ghidra <path>` to create one"))
    add(Check("OK", "profile", f"{cfg.profile} (role {cfg.role}), {len(cfg.tools)} tools enabled"))
    for issue in cfg.issues:
        if issue.level != "info":
            add(Check("FAIL" if issue.level == "error" else "WARN", "config", issue.message))
    if cfg.source is not None:
        from airlock.config.upgrade import stale_message, upgrade_file
        stale = stale_message(cfg.source.read_text("utf-8-sig"))
        if stale and fix:
            plan, bak = upgrade_file(cfg.source)
            add(Check("FIXED", "config", f"upgraded to version {plan.to_version}; "
                                         f"backup {bak}; {plan.summary()}"))
            cfg = load_config(config_path, profile)
        elif stale:
            add(Check("WARN", "config", stale))

    # Data dir
    data = cfg.data_dir
    try:
        data.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=data, delete=True):
            pass
        net = drives.is_network_path(data)
        if net:
            add(Check("WARN", "data dir", f"{data} is on a network drive; SQLite WAL needs a local disk"))
        else:
            add(Check("OK", "data dir", str(data)))
    except OSError as e:
        add(Check("FAIL", "data dir", f"{data}: {e}"))

    # Projects root
    root = cfg.projects_root
    try:
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=root, delete=True):
            pass
        if drives.is_network_path(root):
            add(Check("WARN", "projects root",
                      f"{root} is on a network drive; Ghidra projects need a local disk"))
        else:
            add(Check("OK", "projects root", str(root)))
    except OSError as e:
        add(Check("FAIL", "projects root", f"{root}: {e}"))

    if cfg.is_clean:
        _print(checks)
        return 0 if all(c.status != "FAIL" for c in checks) else 1

    # Ghidra
    info = None
    if cfg.ghidra_dir is None:
        add(Check("FAIL", "ghidra", "ghidra_dir is not set"))
    else:
        try:
            info = ghidra_install.inspect(cfg.ghidra_dir)
            add(Check("OK", "ghidra", f"{info.version} at {info.root}"))
            if info.python_supported and f"{v.major}.{v.minor}" not in info.python_supported:
                add(Check("WARN", "ghidra/python",
                          f"Ghidra lists Python {', '.join(info.python_supported)}"))
            if info.pyghidra_wheel is None:
                add(Check("FAIL", "pyghidra bundle", "no pyghidra wheel in Ghidra/Features/PyGhidra/pypkg/dist"))
            elif not info.bundled_jpype_for(v.major, v.minor):
                add(Check("WARN", "jpype bundle",
                          f"no bundled JPype wheel for Python {v.major}.{v.minor} on this OS "
                          f"(bundled: {', '.join(info.jpype_python_tags) or 'none'}); "
                          "offline install will fail, use Python 3.13"))
        except FileNotFoundError as e:
            add(Check("FAIL", "ghidra", str(e)))

    # JDK
    need = info.java_min if info and info.java_min else 21
    if cfg.jdk_dir:
        java = _java_exe(cfg.jdk_dir)
        major, text = _java_version(str(java)) if java.exists() else (None, f"{java} not found")
        where = f"jdk_dir {cfg.jdk_dir}"
    else:
        found = shutil.which("java")
        major, text = _java_version(found) if found else (None, "java not on PATH")
        where = f"PATH ({found})" if found else "PATH"
    if major is None:
        hint = "" if cfg.jdk_dir else " (set jdk_dir in config.jsonc, or PyGhidra falls back to JAVA_HOME)"
        add(Check("FAIL" if cfg.jdk_dir else "WARN", "jdk", f"{text}{hint}"))
    elif major < need:
        add(Check("FAIL", "jdk", f"Java {major} from {where}; Ghidra needs {need}+"))
    else:
        add(Check("OK", "jdk", f"Java {major} from {where}"))

    # PyGhidra
    have = _pyghidra_installed()
    want = info.pyghidra_version if info else None
    if have and (want is None or have == want):
        add(Check("OK", "pyghidra", f"{have} installed"))
    else:
        problem = "not installed" if not have else f"{have} installed, Ghidra bundles {want}"
        if fix and info:
            ok, msg = install_pyghidra(info)
            add(Check("FIXED" if ok else "FAIL", "pyghidra", msg if ok else f"{problem}; install failed: {msg}"))
        else:
            add(Check("FAIL", "pyghidra", f"{problem}; run `airlock doctor --fix`"))

    # ilspycmd
    if cfg.ilspycmd:
        add(Check("OK" if cfg.ilspycmd.exists() else "WARN", "ilspycmd",
                  str(cfg.ilspycmd) + ("" if cfg.ilspycmd.exists() else " not found")))

    # IDR knowledge bases
    if cfg.idr_kb_dir:
        from airlock.server import idr
        n = len(idr.kb_files(cfg.idr_kb_dir, 4)) + len(idr.kb_files(cfg.idr_kb_dir, 8))
        add(Check("OK" if n else "WARN", "idr_kb_dir",
                  f"{cfg.idr_kb_dir}: {n} knowledge base file(s)" if n else f"{cfg.idr_kb_dir}: no kb*.bin / syskb*.bin found"))

    # Delphi signature databases
    from airlock.server import idr as _idr
    sigs = _idr.sig_files(cfg.delphi_sigdb_dir, 4) + _idr.sig_files(cfg.delphi_sigdb_dir, 8)
    if sigs:
        add(Check("OK", "delphi sigdb", f"{cfg.delphi_sigdb_dir}: " + ", ".join(f.path.name for f in sigs)))
    else:
        add(Check("OK", "delphi sigdb",
                  f"none in {cfg.delphi_sigdb_dir}; build with `airlock delphi-sigs build <Delphi install folder>`"))

    # WARP libraries (delphinja)
    warps = _idr.warp_files(cfg.warp_dir, 4) + _idr.warp_files(cfg.warp_dir, 8)
    add(Check("OK", "warp libraries",
              f"{cfg.warp_dir}: " + ", ".join(f.path.name for f in warps) if warps else
              f"none in {cfg.warp_dir}; optional, delphi-rtl-*.warp from github.com/psifertex/delphinja (signatures)"))

    # Live start
    if start and not any(c.status == "FAIL" for c in checks):
        from airlock.worker.client import WorkerClient
        from airlock.worker.protocol import WorkerError

        client = WorkerClient(cfg)
        try:
            hello = client.request("hello", timeout=30)
            job = "in kill-on-close job" if client.in_job else "no job object (not Windows)"
            add(Check("OK", "worker", f"pid {hello['pid']}, Python {hello['python']}, {job}"))
            g = client.ensure_ghidra()
            add(Check("OK", "ghidra start",
                      f"Ghidra {g['ghidra_version']}, Java {g['java_version']} "
                      f"({g['java_home']}), {g['startup_s']}s"))
        except WorkerError as e:
            add(Check("FAIL", "ghidra start", f"{e.code}: {e.message} (log: {client.log_path})"))
        finally:
            client.stop()

    _print(checks)
    return 0 if all(c.status != "FAIL" for c in checks) else 1


def _print(checks: list[Check]) -> None:
    for c in checks:
        print(c.line())
