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


def _cmd_delphi_sigs(args: argparse.Namespace) -> int:
    from airlock.config import ConfigError, load_config
    from airlock.server import delphisigs

    try:
        cfg = load_config(args.config, None)
    except ConfigError as e:
        print(f"airlock: {e}", file=sys.stderr)
        return 2
    out = args.out or cfg.delphi_sigdb_dir
    if args.action == "list":
        from airlock.server import idr
        files = idr.sig_files(out, 4) + idr.sig_files(out, 8)
        for f in files:
            h = delphisigs.read_sigdb_header(f.path)
            print(f"{f.path.name}: compiler {h.get('compiler')}, {h.get('bits')}-bit, {h.get('count')} names, "
                  f"{f.size // 1024} KB, built {h.get('built', '?')} from "
                  f"{h.get('install') or str(h.get('binaries', '?')) + ' binaries'}")
        if not files:
            print(f"no signature databases in {out}")
        return 0
    if args.action == "rtti-build":
        from airlock.server import delphirtti
        if not args.install:
            print("airlock: give one or more folders with Delphi programs (one product per folder)", file=sys.stderr)
            return 2
        try:
            res = delphirtti.build(args.install, out, args.min_binaries, args.min_products, args.jobs,
                                   args.exclude or [], args.indy, progress=print if args.verbose else None)
        except (delphirtti.RttiError, delphisigs.SigError) as e:
            print(f"airlock: {e}", file=sys.stderr)
            return 2
        for r in res:
            print(f"{r.path}: compiler {r.compiler}, {r.psize * 8}-bit, {r.binaries} binaries, {r.names} names, "
                  f"{r.shapes} code shapes ({r.cross_product} names agreed by several products, "
                  f"{r.single_product} by one), {r.stubs} stub shapes dropped, {r.path.stat().st_size // 1024} KB, "
                  f"{r.seconds:.0f} s")
        if not res:
            print("no database written: no Delphi program with extended RTTI, or too few binaries agree")
        return 0 if res else 1
    if not args.install:
        print("airlock: give the Delphi install folder (the one with bin and Redist)", file=sys.stderr)
        return 2
    bits = [4, 8] if args.bits == "both" else [int(args.bits) // 8]
    built = 0
    for psize in bits:
        try:
            r = delphisigs.build(args.install[0], out, psize, progress=print if args.verbose else None,
                                 jobs=args.jobs)
        except delphisigs.SigError as e:
            print(f"{psize * 8}-bit: {e}")
            continue
        built += 1
        print(f"{r.path}: compiler {r.compiler}, {r.psize * 8}-bit, {r.packages} packages, {r.names} names, "
              f"{r.routines} distinct routines, {r.path.stat().st_size // 1024} KB, {r.seconds:.0f} s")
    return 0 if built else 1


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

    g = sub.add_parser("delphi-sigs", help="build or list Delphi RTL / VCL signature databases")
    g.add_argument("action", choices=["build", "rtti-build", "list"])
    g.add_argument("install", nargs="*", type=Path,
                   help="build: Delphi install folder (the one with bin and Redist); rtti-build: folders with "
                        "Delphi programs, one product per folder")
    g.add_argument("--min-binaries", type=int, default=3, help="rtti-build: distinct files that must agree (3)")
    g.add_argument("--min-products", type=int, default=1, help="rtti-build: distinct products that must agree (1)")
    g.add_argument("--exclude", type=Path, action="append", help="rtti-build: a file to leave out (repeatable)")
    g.add_argument("--indy", action="store_true", help="rtti-build: also keep Indy (Id*) units")
    g.add_argument("--bits", choices=["32", "64", "both"], default="both", help="build: platform (default both)")
    g.add_argument("--out", type=Path, default=None, help="folder of the databases (default: delphi_sigdb_dir)")
    g.add_argument("--jobs", type=int, default=4, help="build: worker processes")
    g.add_argument("-v", "--verbose", action="store_true")
    g.set_defaults(fn=_cmd_delphi_sigs)

    args = p.parse_args(argv)
    return args.fn(args)
