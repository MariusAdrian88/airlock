"""admin set: project_info, index_status. reindex, frontier come later."""

from __future__ import annotations

from airlock import __version__, ghidra_install
from airlock.server.context import ServerContext
from airlock.server.registry import tool
from airlock.worker.protocol import WorkerError


def _wrap_list(label: str, items: list[str], width: int = 78) -> list[str]:
    lines, cur = [], f"{label} ({len(items)}):"
    for item in items:
        if len(cur) + len(item) + 1 > width:
            lines.append(cur)
            cur = "  "
        cur += " " + item
    lines.append(cur)
    return lines


@tool("project_info", "Show airlock's effective configuration: profile, enabled tools, paths "
                      "and Ghidra status. Set check_ghidra to start Ghidra and verify it.")
def project_info(ctx: ServerContext, check_ghidra: bool = False) -> str:
    cfg = ctx.config
    out = [
        f"airlock {__version__} | profile {cfg.profile} (role {cfg.role}) | "
        f"writes {'on' if cfg.allow_writes else 'off'}",
        f"config  {cfg.source or '(built-in defaults only)'}",
        f"data    {cfg.data_dir}",
    ]
    if not cfg.is_clean:
        g = "not set"
        if cfg.ghidra_dir:
            try:
                info = ghidra_install.inspect(cfg.ghidra_dir)
                g = f"{cfg.ghidra_dir} (Ghidra {info.version})"
            except FileNotFoundError as e:
                g = f"{cfg.ghidra_dir} (invalid: {e})"
        out.append(f"ghidra  {g}")
        out.append(f"jdk     {cfg.jdk_dir or 'auto'}")

    exposed = [t for t in cfg.tools if t not in ctx.not_implemented]
    out += _wrap_list("tools", exposed)
    if ctx.not_implemented:
        out += _wrap_list("configured, not implemented yet", ctx.not_implemented)
    for issue in cfg.issues:
        if issue.level != "info":
            out.append(str(issue))

    if check_ghidra and not cfg.is_clean:
        try:
            g = ctx.worker.ensure_ghidra()
            out.append(
                f"worker  ok: Ghidra {g.get('ghidra_version')}, Java {g.get('java_version')}, "
                f"PyGhidra {g.get('pyghidra_version')}, started in {g.get('startup_s')}s"
            )
        except WorkerError as e:
            out.append(f"worker  error {e.code}: {e.message} (log: {ctx.worker.log_path})")
    elif not cfg.is_clean:
        state = "running" if ctx.worker.running() else "not started"
        out.append(f"worker  {state}")
    return "\n".join(out)


@tool("index_status", "Show worker state and, per binary, analysis progress or index counts.")
def index_status(ctx: ServerContext, project: str = "") -> str:
    from airlock.server.indexer import IndexerError
    ix = ctx.indexer
    w = ctx.worker
    out = [f"worker {'running' if w.running() else 'not started'}, "
           f"ghidra {'started' if w.ghidra is not None and w.running() else 'not started'}"]
    try:
        names = [ix.resolve_project(project)] if project else ix.projects()
    except IndexerError as e:
        return e.message
    if not names:
        out.append("no projects. Call open_binary with a project and a file path.")
    for p in names:
        st = ix.store(p)
        bins = st.list_binaries()
        out.append(f"project {p}: {len(bins)} binaries")
        for b in bins:
            status, detail = ix.describe(p, st, b)
            if status == "ready":
                c = st.counts(b.id)
                out.append(
                    f"  #{b.id} {b.name} ready: {c['functions']} functions, {c['strings']} strings, "
                    f"{c['imports']} imports, {c['edges']} edges; decompiled {c['decompiled']} "
                    f"(stale {c['decomp_stale']})")
            else:
                out.append(f"  #{b.id} {b.name} {status}: {detail}")
    return chr(10).join(out)
