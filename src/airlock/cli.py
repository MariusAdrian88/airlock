"""Command line: airlock serve | init | config | doctor."""

from __future__ import annotations

import argparse
import contextlib
import logging
import shutil
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
    if cfg.ghidra_dir is None and not cfg.is_clean:
        print("airlock: ghidra_dir is not set in config.jsonc; set it with airlock init --ghidra <path>",
              file=sys.stderr)
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


def _cmd_spec_approve(args: argparse.Namespace) -> int:
    """The person's approval step (config require_spec_review): reviewed specs -> final -> published."""
    from airlock.config import ConfigError, load_config
    from airlock.index.store import Store
    from airlock.projects import find_project
    from airlock.server import specs as sp

    try:
        cfg = load_config(args.config, None)
    except ConfigError as e:
        print(f"airlock: {e}", file=sys.stderr)
        return 2
    pp = find_project(cfg.projects_root, args.project)
    if pp is None or not pp.index_db.exists():
        print(f"airlock: no project '{args.project}'", file=sys.stderr)
        return 2
    prefix = args.prefix.strip()
    with Store(pp.index_db) as st:
        todo = sp.approve(st, prefix, dry_run=not args.yes)
        if not todo:
            print("no reviewed specs to approve")
            return 0
        for s in todo:
            print(f"=== {s['topic']} v{s['version']} | {s['title']}\n{s['body'].rstrip()}\n")
        if not args.yes:
            print(f"{len(todo)} specs read above. Run again with --yes to approve and publish them.")
            return 1
        final, _, gone, refused = sp.publish(st, pp, "person", prefix)
        print(f"approved {len(todo)}; published {len(final)} specs to {pp.specs}"
              + (f"; {len(refused)} failed the filter" if refused else "") + (f"; {gone} withdrawn" if gone else ""))
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    from airlock.doctor import run

    return run(args.config, args.profile, fix=args.fix, start=args.start)


def _cmd_delphi_oracle(args: argparse.Namespace, sigdir: Path, warp_dir: Path | None = None) -> int:
    from airlock.server import delphioracle
    if len(args.install) != 2:
        print("airlock: oracle needs <binary> <map file>", file=sys.stderr)
        return 2
    try:
        if args.hide_exact:
            r = delphioracle.measure_foreign(args.install[0], args.install[1], sigdir, args.warp_dir or warp_dir, args.own)
        else:
            r = delphioracle.measure(args.install[0], args.install[1], sigdir, args.own)
        print(delphioracle.format_result(r))
    except (delphioracle.OracleError, OSError, ValueError) as e:
        print(f"airlock: {e}", file=sys.stderr)
        return 2
    return 0


def _cmd_fpc_sigs(args: argparse.Namespace, out: Path) -> int:
    """`delphi-sigs fpc-build <fpc install or fpc.exe>... [--lazarus DIR]` builds the Free Pascal RTL / LCL
    signature databases; `delphi-sigs fpc-oracle <binary with symbols>` measures one."""
    from airlock.server import delphioracle, delphisigs, fpcsigs
    try:
        if args.action == "fpc-oracle":
            if len(args.install) != 1:
                print("airlock: fpc-oracle needs <binary built with -g>", file=sys.stderr)
                return 2
            own = {u.strip() for u in (args.own_units or "").split(",") if u.strip()}
            print(delphioracle.format_result(fpcsigs.measure(args.install[0], out, own)))
            return 0
        if not args.install:
            print("airlock: give the FPC install folder (or fpc.exe)", file=sys.stderr)
            return 2
        exes: list[Path] = []
        for item in args.install:
            exes += fpcsigs.find_compilers(item)
        if args.bits != "both":
            exes = [e for e in exes if fpcsigs.probe_compiler(e).bits == int(args.bits)]
        if not exes:
            print("airlock: no fpc.exe found", file=sys.stderr)
            return 2
        res = fpcsigs.build(exes, out, args.work or (out / "work"), None, args.lazarus, args.source or None,
                            print if args.verbose else None)
    except (fpcsigs.FpcError, delphisigs.SigError, OSError, ValueError) as e:
        print(f"airlock: {e}", file=sys.stderr)
        return 2
    for r in res:
        print(f"{r.path}: FPC {r.version}, {r.psize * 8}-bit, {r.programs} programs, {r.names} names, "
              f"{r.routines} distinct routines, {r.path.stat().st_size // 1024} KB, {r.seconds:.0f} s")
    return 0


def _cmd_warp_build(args: argparse.Namespace, cfg) -> int:
    """`delphi-sigs warp-build <kit>... [--bits 64]`: one own WARP library per bitness from the map builds of
    the given Delphi installs or kits (all compiler versions together; the GUIDs tolerate small layout changes)."""
    from airlock.server import delphimap, delphimega, warp
    out = args.out or cfg.warp_dir
    say = print if args.verbose else None
    built = 0
    for psize in ([4, 8] if args.bits == "both" else [int(args.bits) // 8]):
        pairs = [(Path(b), Path(m)) for b, m in args.map or [] if delphimap.pair_psize(Path(b)) == psize]
        work = args.work or (out / "work")
        for kit in args.install:
            folder = work / f"{kit.name}-win{psize * 8}"
            try:
                with delphimega.work_lock(folder):
                    mega = delphimega.build(kit, folder, psize, say, jobs=args.jobs)
            except delphimega.MegaError as e:
                print(f"{kit}: {psize * 8}-bit: {e}")
                continue
            print(f"{kit}: {psize * 8}-bit, {len(mega.pairs)} packages, {mega.units} units, {len(mega.excluded)} left out")
            pairs += mega.pairs
        if not pairs:
            print(f"{psize * 8}-bit: no package built")
            continue
        dest = out / f"{warp.OWN_PREFIX}win{psize * 8}.warp"
        try:
            guids, names = warp.build_library(pairs, dest, args.jobs, say)
        except warp.WarpError as e:
            print(f"{psize * 8}-bit: {e}")
            continue
        finally:
            if not args.keep_work:
                for kit in args.install:
                    shutil.rmtree(work / f"{kit.name}-win{psize * 8}", ignore_errors=True)
        built += 1
        print(f"{dest}: {guids} function GUIDs, {names} names, {dest.stat().st_size // 1024} KB")
    return 0 if built else 1


def _cmd_delphi_sigs(args: argparse.Namespace) -> int:
    from airlock.config import ConfigError, load_config
    from airlock.server import delphisigs

    try:
        cfg = load_config(args.config, None)
    except ConfigError as e:
        print(f"airlock: {e}", file=sys.stderr)
        return 2
    out = args.out or cfg.delphi_sigdb_dir
    if args.action in ("fpc-build", "fpc-oracle"):
        return _cmd_fpc_sigs(args, out)
    if args.action == "list":
        from airlock.server import fpcsigs, idr
        files = idr.sig_files(out, 4) + idr.sig_files(out, 8) + fpcsigs.sig_files(out, 4) + fpcsigs.sig_files(out, 8)
        for f in files:
            h = delphisigs.read_sigdb_header(f.path)
            print(f"{f.path.name}: {'FPC ' + str(h.get('fpc')) if h.get('fpc') else 'compiler ' + str(h.get('compiler'))}, "
                  f"{h.get('bits')}-bit, {h.get('count')} names, "
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
    if args.action == "kit":
        from airlock.server import delphikit
        if len(args.install) != 2:
            print("airlock: kit needs <install folder> <destination folder>", file=sys.stderr)
            return 2
        try:
            size = delphikit.make_kit(args.install[0], args.install[1], print if args.verbose else None)
        except (delphikit.KitError, OSError) as e:
            print(f"airlock: {e}", file=sys.stderr)
            return 2
        print(f"{args.install[1]}: kit of {size / 1048576:.0f} MB; use it like the install: delphi-sigs build")
        return 0
    if args.action == "oracle":
        return _cmd_delphi_oracle(args, out, cfg.warp_dir)
    if args.action == "warp-build":
        return _cmd_warp_build(args, cfg)
    from airlock.server import delphimap, delphimega
    bits = [4, 8] if args.bits == "both" else [int(args.bits) // 8]
    say = print if args.verbose else None
    built = 0
    for psize in bits:
        pairs = [(Path(b), Path(m)) for b, m in args.map or [] if delphimap.pair_psize(Path(b)) == psize]
        work = None
        lock = contextlib.ExitStack()
        if args.units:
            work = args.work or (out / "work")
            try:
                lock.enter_context(delphimega.work_lock(work / f"win{psize * 8}"))
            except delphimega.MegaError as e:
                print(f"{psize * 8}-bit: {e}")
                continue
        try:
            if args.units:
                try:
                    mega = delphimega.build(args.install[0], work / f"win{psize * 8}", psize, say, jobs=args.jobs)
                except delphimega.MegaError as e:
                    print(f"{psize * 8}-bit: warning: the units step failed, the database has the package "
                          f"exports only ({e})")
                else:
                    pairs += mega.pairs
                    print(f"{psize * 8}-bit units: {len(mega.pairs)} packages, {mega.units} units, "
                          f"{len(mega.excluded)} left out, {len(mega.stubbed)} resource files stubbed, "
                          f"{mega.program_units} units in a program, {mega.rounds} rounds, {mega.seconds:.0f} s")
                    if mega.failed:
                        print(f"{psize * 8}-bit: warning: {len(mega.failed)} packages failed: "
                              + "; ".join(mega.failed))
            r = delphisigs.build(args.install[0], out, psize, progress=say, jobs=args.jobs, pairs=pairs)
        except (delphisigs.SigError, delphimega.MegaError) as e:
            print(f"{psize * 8}-bit: {e}")
            continue
        finally:
            if work is not None and not args.keep_work:
                shutil.rmtree(work / f"win{psize * 8}", ignore_errors=True)
            lock.close()
        built += 1
        extra = f", {r.mapped} from maps" if pairs else ""
        print(f"{r.path}: compiler {r.compiler}, {r.psize * 8}-bit, {r.packages} packages, {r.names} names{extra}, "
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

    a = sub.add_parser("spec-approve", help="read reviewed specs, then set them final and publish them")
    a.add_argument("project")
    a.add_argument("--prefix", default="", help="only topics that start with this text")
    a.add_argument("--yes", action="store_true", help="approve and publish (without it: print the specs only)")
    a.set_defaults(fn=_cmd_spec_approve)

    d = sub.add_parser("doctor", help="check the installation")
    d.add_argument("--profile", default=None)
    d.add_argument("--fix", action="store_true", help="install PyGhidra from Ghidra's bundled wheels")
    d.add_argument("--start", action="store_true", help="also start the worker and Ghidra")
    d.set_defaults(fn=_cmd_doctor)

    g = sub.add_parser("delphi-sigs", help="build or list Delphi RTL / VCL signature databases")
    g.add_argument("action", choices=["build", "rtti-build", "list", "kit", "oracle", "warp-build", "fpc-build", "fpc-oracle"])
    g.add_argument("install", nargs="*", type=Path,
                   help="build: Delphi install folder (the one with bin and Redist); kit: install folder and "
                        "destination; oracle: binary and its map file; warp-build: installs or kits; rtti-build: folders with "
                        "Delphi programs, one product per folder; fpc-build: FPC install folders or fpc.exe files; "
                        "fpc-oracle: a program built with -g")
    g.add_argument("--lazarus", type=Path, default=None, help="fpc-build: Lazarus folder (adds the LCL)")
    g.add_argument("--source", type=Path, action="append",
                   help="fpc-build: Pascal source folder whose identifiers restore the case of the names (repeatable)")
    g.add_argument("--own-units", default=None, help="fpc-oracle: comma separated units that are the program's own code")
    g.add_argument("--own", type=Path, default=None,
                   help="oracle: folder of the program's own .dcu files (their units are not library code)")
    g.add_argument("--hide-exact", action="store_true",
                   help="oracle: leave-one-out, hide the database of the program's own compiler and measure the "
                        "other databases without and with the WARP libraries")
    g.add_argument("--warp-dir", type=Path, default=None, help="oracle --hide-exact: folder of the WARP libraries")
    g.add_argument("--min-binaries", type=int, default=3, help="rtti-build: distinct files that must agree (3)")
    g.add_argument("--min-products", type=int, default=1, help="rtti-build: distinct products that must agree (1)")
    g.add_argument("--exclude", type=Path, action="append", help="rtti-build: a file to leave out (repeatable)")
    g.add_argument("--indy", action="store_true", help="rtti-build: also keep Indy (Id*) units")
    g.add_argument("--bits", choices=["32", "64", "both"], default="both", help="build: platform (default both)")
    g.add_argument("--out", type=Path, default=None,
                   help="folder of the databases (default: delphi_sigdb_dir; warp-build: warp_dir)")
    g.add_argument("--jobs", type=int, default=4, help="build: worker processes")
    g.add_argument("--units", action="store_true",
                   help="build: also build a package of all compiled units (.dcu) with dcc and read its map file "
                        "(names of the routines the packages do not export; takes many minutes)")
    g.add_argument("--map", nargs=2, action="append", metavar=("BINARY", "MAP"),
                   help="build: add the routine names of a binary and its linker map (-GD); repeatable")
    g.add_argument("--work", type=Path, default=None, help="build --units: work folder (default: a folder work in the output folder)")
    g.add_argument("--keep-work", action="store_true", help="build --units: keep the package and map files")
    g.add_argument("-v", "--verbose", action="store_true")
    g.set_defaults(fn=_cmd_delphi_sigs)

    args = p.parse_args(argv)
    return args.fn(args)
