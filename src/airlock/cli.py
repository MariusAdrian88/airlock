"""Command line: airlock serve | init | config | doctor."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from airlock import __version__, paths


def _cmd_serve(args: argparse.Namespace) -> int:
    from airlock.config import ConfigError, load_config
    from airlock.server.app import serve

    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="[airlock] %(levelname)s %(message)s")
    try:
        cfg = load_config(args.config, args.profile)
    except ConfigError as e:
        print(f"airlock: {e}", file=sys.stderr)
        return 2
    from airlock import logs
    logs.setup_server_logging(cfg.data_dir)         # rotating logs\server.log next to worker.log
    serve(cfg, profile_explicit=args.profile is not None)
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    from airlock.config import write_default_config

    target = args.config or paths.default_config_path()
    if target.exists() and not args.force:
        print(f"{target} already exists (use --force to overwrite)")
        return 1
    write_default_config(target, args.ghidra)
    print(f"wrote {target}")
    if args.ghidra is None:
        print("set \"ghidra_dir\" in it, then run `airlock doctor`")
    return 0


def _cmd_config(args: argparse.Namespace) -> int:
    from airlock.config.report import run

    return run(args)


def _cmd_doctor(args: argparse.Namespace) -> int:
    from airlock.doctor import run

    return run(args.config, args.profile, fix=args.fix, start=args.start)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="airlock", description="Lean Ghidra MCP server")
    p.add_argument("--version", action="version", version=f"airlock {__version__}")
    p.add_argument("--config", type=Path, default=None,
                   help=f"config file (default: {paths.default_config_path()})")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the MCP server on stdio")
    s.add_argument("--profile", default=None, choices=["dirty", "clean"],
                   help="role of the tool list (default: dirty)")
    s.set_defaults(fn=_cmd_serve)

    i = sub.add_parser("init", help="write the documented default config.jsonc")
    i.add_argument("--ghidra", type=Path, default=None, help="Ghidra install directory")
    i.add_argument("--force", action="store_true", help="overwrite an existing config")
    i.set_defaults(fn=_cmd_init)

    c = sub.add_parser("config", help="show, set, validate or upgrade the config file")
    c.add_argument("action", nargs="?", choices=["show", "upgrade", "validate"],
                   help="show (default): every key with value, default and source")
    c.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"), help="change one key")
    c.add_argument("--unset", metavar="KEY", help="return one key to its default")
    c.add_argument("--dry-run", action="store_true", help="upgrade: print the diff, write nothing")
    c.add_argument("--overlay", type=Path, default=None, help="project overlay file to include")
    c.add_argument("--profile", choices=["dirty", "clean"], default=None)
    c.set_defaults(fn=_cmd_config)

    d = sub.add_parser("doctor", help="check the installation")
    d.add_argument("--profile", default=None)
    d.add_argument("--fix", action="store_true", help="install PyGhidra from Ghidra's bundled wheels")
    d.add_argument("--start", action="store_true", help="also start the worker and Ghidra")
    d.set_defaults(fn=_cmd_doctor)

    args = p.parse_args(argv)
    return args.fn(args)
