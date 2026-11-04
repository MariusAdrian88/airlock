"""admin set: project_info, index_status. reindex, frontier come later."""

from __future__ import annotations

from airlock import __version__, ghidra_install
from airlock.config.catalog import CATALOG
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


@tool("project_info", "Show the session role, project, version and enabled tools; "
                      "set check_ghidra to start Ghidra and verify it.")
def project_info(ctx: ServerContext, check_ghidra: bool = False) -> str:
    cfg = ctx.config
    se = ctx.session
    exposed = [t for t in cfg.tools if t not in ctx.not_implemented]
    if se.role == "clean" or cfg.is_clean:
        out = [f"airlock {__version__} | role clean | "
               f"project {se.project.name if se.project else '-'}"]
        safe = [t for t in exposed if CATALOG[t].clean_safe]
        return "\n".join(out + _wrap_list("tools", safe))
    out = [
        f"airlock {__version__} | profile {cfg.profile} (role {cfg.role}) | "
        f"writes {'on' if cfg.allow_writes else 'off'}",
        f"config  {cfg.source or '(built-in defaults only)'}",
        f"data    {cfg.data_dir}",
        f"projects {cfg.projects_root}",
        f"session role {se.role} | project {se.project.name if se.project else '-'}",
    ]
    g = "not set"
    if cfg.ghidra_dir:
        try:
            info = ghidra_install.inspect(cfg.ghidra_dir)
            g = f"{cfg.ghidra_dir} (Ghidra {info.version})"
        except FileNotFoundError as e:
            g = f"{cfg.ghidra_dir} (invalid: {e})"
    out.append(f"ghidra  {g}")
    out.append(f"jdk     {cfg.jdk_dir or 'auto'}")
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
        ix.resume_project(p)
        st = ix.store(p)
        out += _project_lines(ix, p, st)
    return chr(10).join(out)


STATUS_LINES = 16  # binary lines per project; the rest is summarised as "+N more"


def _dur(sec: float | None) -> str:
    if sec is None:
        return "?"
    if sec < 90:
        return f"{round(sec)}s"
    return f"{round(sec / 60)} min"


def _decomp_text(ix, p: str, st, b, counts) -> str:
    """`decompiled X/Y`, plus rate and threads while the background pass runs."""
    done = st.decomp_current_count(b.id, b.analysis_profile or "unknown")
    text = f"decompiled {done}/{st.decomp_target_count(b.id)}"
    if counts["decomp_stale"]:
        text += f" (stale {counts['decomp_stale']})"
    if counts.get("timeouts"):
        text += f", timeouts {counts['timeouts']}"
    bp = ix.bulk.progress(p, b.id)
    if bp is None:
        return text
    if bp.state == "running":
        text += f", {bp.rate:.1f} fn/s, threads {bp.threads} of {bp.processors}"
    elif bp.state in ("waiting", "planning"):
        text += ", background pass waiting for analysis"
    elif bp.state in ("error", "interrupted"):
        text += f", background pass {bp.state}: {bp.message}"
    return text


def _project_lines(ix, p: str, st) -> list[str]:
    q = ix.queue_status(p)
    counts: dict[str, int] = {}
    for r in q.rows:
        counts[r.state] = counts.get(r.state, 0) + 1
    out = [f"project {p}: {len(q.rows)} binaries"]
    open_ = [r for r in q.rows if r.state not in ("ready", "error")]
    if open_:
        parts = [f"{counts[s]} {s}" for s in ("ready", "importing", "analysing", "extracting",
                                              "queued", "error") if counts.get(s)]
        out.append(f"  queue: {', '.join(parts)} | remaining ~{_dur(q.remaining_s)} "
                   f"({q.s_per_mb:.0f} s/MB)")
        c = q.current
        if c is not None:
            out.append(f"  current: {c.name} {c.state} {_dur(c.seconds)}"
                       + (f" of ~{_dur(c.est_seconds)}" if c.est_seconds else ""))
    by_id = {r.binary_id: r for r in q.rows}
    shown = 0
    for r in q.rows:  # current, waiting in run order, then finished/failed
        if shown >= STATUS_LINES:
            break
        b = st.get_binary_by_id(r.binary_id)
        status, detail = ix.describe(p, st, b)
        if status == "ready":
            c = st.counts(b.id)
            line = (f"  #{b.id} {b.name} ready: {c['functions']} functions, {c['strings']} strings, "
                    f"{c['imports']} imports, {c['edges']} edges; {_decomp_text(ix, p, st, b, c)}")
            links = st.cross_counts(b.id)
            if links[0] or links[1]:
                line += f"; links out {links[0]} in {links[1]}"
            if by_id[b.id].seconds:
                line += f"; analysed in {_dur(by_id[b.id].seconds)}"
            out.append(line)
        elif status == "queued" and by_id[b.id].est_seconds:
            out.append(f"  #{b.id} {b.name} queued: {detail}, est ~{_dur(by_id[b.id].est_seconds)}")
        else:
            out.append(f"  #{b.id} {b.name} {status}: {detail}")
        shown += 1
    if len(q.rows) > shown:
        out.append(f"  +{len(q.rows) - shown} more")
    return out
