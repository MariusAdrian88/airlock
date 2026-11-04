"""Session tools: projects (list) and project_open (bind the session to project + role)."""

from __future__ import annotations

from airlock.projects import ProjectPaths, count_specs, find_project, list_projects, summarize
from airlock.server import roles
from airlock.server.context import ServerContext
from airlock.server.registry import tool


def redacted(ctx: ServerContext) -> bool:
    """Clean session or clean profile: no paths into dirty, no binary names."""
    return ctx.session.role == roles.CLEAN or ctx.config.is_clean


def dirty_lines(pp: ProjectPaths) -> list[str]:
    s = summarize(pp)
    state = f"binaries: {s.ready} ready, {s.queued} queued" + (f", {s.errors} failed" if s.errors else "")
    return [f"session dirty for {pp.name}: write notes and scratch files only under {pp.dirty}",
            state]


def clean_line(pp: ProjectPaths) -> str:
    return (f"session clean for {pp.name}: write the implementation under {pp.clean}; "
            f"never read {pp.dirty}. Specs: {count_specs(pp)} published in {pp.specs}")


@tool("projects", "List the projects with their state; call it first to choose one for "
                  "project_open.")
def projects(ctx: ServerContext) -> str:
    root = ctx.config.projects_root
    names = list_projects(root)
    if not names:
        return "no projects. Call project_create with the path of a program."
    hide = redacted(ctx)
    out = []
    for n in names:
        pp = find_project(root, n)
        if pp is None:
            continue
        if hide:
            out.append(f"{n} | specs {count_specs(pp)}")
            continue
        s = summarize(pp)
        bins = f"{s.ready} ready/{s.queued} queued" + (f"/{s.errors} failed" if s.errors else "")
        out.append(f"{n} | root {s.root_exe} | binaries {bins} | specs {count_specs(pp)} | {pp.root}")
    return "\n".join(out)


@tool("project_open", "Bind this session to a project as dirty (analysis) or clean "
                      "(implementation); it cannot be changed afterwards.")
def project_open(ctx: ServerContext, name: str, role: str) -> str:
    role = role.strip().lower()
    if role not in (roles.DIRTY, roles.CLEAN):
        return f"error bad_role: role '{role}' is not dirty or clean. Use dirty or clean."
    if ctx.session.role != roles.UNBOUND:
        return roles.role_locked(ctx.session)
    pp = find_project(ctx.config.projects_root, name)
    if pp is None:
        return f"error not_found: no project '{name}'. Call projects."
    err = ctx.bind_session(role, pp)
    if err:
        return err
    if role == roles.CLEAN:
        return clean_line(pp)
    return "\n".join(dirty_lines(pp))
