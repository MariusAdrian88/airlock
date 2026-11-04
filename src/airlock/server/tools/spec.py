"""spec set: spec_write (dirty), spec_read / spec_list / spec_export (dirty and clean). DESIGN 6, 9.

Dirty sessions use the index (specs, provenance, audit). Clean sessions read only the published
files in ``clean\\specs`` and never open the index, so nothing they get can carry provenance,
addresses, notes or code.
"""

from __future__ import annotations

from airlock.projects import ProjectPaths
from airlock.server import roles, specs as sp
from airlock.server import specfilter
from airlock.server.budget import CursorError, fit_lines, resume_lines
from airlock.server.context import ServerContext
from airlock.server.registry import tool
from airlock.server.tools.common import budget_for


def _project(ctx: ServerContext) -> ProjectPaths | str:
    pp = ctx.session.project
    if pp is None:
        return "error unbound: no project is open. Call projects, then project_open."
    return pp


def _is_clean(ctx: ServerContext) -> bool:
    return ctx.session.role == roles.CLEAN


def _page(ctx: ServerContext, lines: list[str], tool_name: str, args: dict, cursor: str, budget: int) -> str:
    bud = budget_for(ctx, budget)
    if cursor:
        try:
            return resume_lines(cursor, bud, "prose", tool=tool_name, args=args)[0]
        except CursorError as e:
            return e.message
    return fit_lines(lines, bud, "prose", tool=tool_name, args=args)[0]


@tool("spec_write", "Write a specification page (code and addresses are rejected); a rewrite of a "
                    "topic makes a new version.")
def spec_write(ctx: ServerContext, topic: str, title: str, body: str, sources: str,
               status: str = "draft") -> str:
    pp = _project(ctx)
    if isinstance(pp, str):
        return pp
    topic, title, status = topic.strip(), " ".join(title.split()), status.strip().lower()
    bad = sp.check_topic(topic)
    if bad:
        return bad
    if status not in sp.STATUSES:
        return sp.err("bad_status", f"status '{status}' is not valid", "Use draft, reviewed or final")
    if not title or len(title) > sp.MAX_TITLE:
        return sp.err("bad_title", f"the title must be 1 to {sp.MAX_TITLE} characters",
                      "Give a short one-line title")
    if not body.strip() or len(body) > sp.MAX_BODY:
        return sp.err("bad_body", f"the body must be 1 to {sp.MAX_BODY} characters",
                      "Write prose and data-layout tables; split a long topic")
    st = ctx.indexer.store(pp.name)
    ranges = sp.image_ranges(st)
    refusal = specfilter.check(title, ranges) or specfilter.check(body, ranges)
    if refusal:
        return refusal
    srcs = sp.parse_sources(st, sources)
    if isinstance(srcs, str):
        return srcs
    sid, ver, created = sp.write_spec(st, ctx.session.role, topic, title, body, status, srcs)
    if not created:
        return f"spec {sid} {topic} v{ver} {status} unchanged: the text is the same as the latest version."
    return f"spec {sid} {topic} v{ver} {status}"


@tool("spec_list", "List specification topics with title, version and status.")
def spec_list(ctx: ServerContext, topic_prefix: str = "", cursor: str = "", budget: int = 0) -> str:
    pp = _project(ctx)
    if isinstance(pp, str):
        return pp
    prefix = topic_prefix.strip()
    args = {"topic_prefix": prefix}
    if cursor:
        return _page(ctx, [], "spec_list", args, cursor, budget)
    if _is_clean(ctx):
        rows = [e for e in sp.published(pp) if e["topic"].startswith(prefix)]
        lines = [f"{e['topic']} | {e.get('title', '')} | v{e.get('version', '')} | {e.get('status', '')}"
                 for e in sorted(rows, key=lambda e: e["topic"])]
        if not lines:
            return "no published specs" + (f" under '{prefix}'" if prefix else "") + "."
        return _page(ctx, lines, "spec_list", args, "", budget)
    st = ctx.indexer.store(pp.name)
    pub = {e["topic"]: e.get("version") for e in sp.published(pp)}
    lines = []
    for r in sp.latest(st, prefix):
        mark = "published" if pub.get(r["topic"]) == r["version"] else (
            f"published v{pub[r['topic']]}" if r["topic"] in pub else "unpublished")
        lines.append(f"{r['topic']} | {r['title']} | v{r['version']} | {r['status']} | {mark} | id {r['id']}")
    if not lines:
        return "no specs" + (f" under '{prefix}'" if prefix else "") + ". Write one with spec_write."
    return _page(ctx, lines, "spec_list", args, "", budget)


@tool("spec_read", "Read a specification page by topic (latest version unless version is given).")
def spec_read(ctx: ServerContext, topic: str = "", version: int = 0, id: int = 0,
              cursor: str = "", budget: int = 0) -> str:
    pp = _project(ctx)
    if isinstance(pp, str):
        return pp
    topic = topic.strip()
    args = {"topic": topic, "version": version, "id": id}
    if cursor:
        return _page(ctx, [], "spec_read", args, cursor, budget)
    if _is_clean(ctx):
        if id or not topic:
            return sp.err("bad_args", "a clean session reads a spec by topic", "Call spec_list, then spec_read(topic=...)")
        got = sp.read_published(pp, topic)
        if got is None:
            return sp.err("not_found", f"no published spec '{topic}'", "Call spec_list")
        entry, body = got
        if version and str(version) != str(entry.get("version")):
            return sp.err("not_found", f"only version {entry.get('version')} of '{topic}' is published",
                          "Read without version")
        head = f"{entry['topic']} | {entry.get('title', '')} | v{entry.get('version', '')} | {entry.get('status', '')}"
        return _page(ctx, [head, *body.splitlines()], "spec_read", args, "", budget)
    if not topic and not id:
        return sp.err("bad_args", "give a topic or an id", "Call spec_list")
    st = ctx.indexer.store(pp.name)
    row = sp.get_spec(st, topic, id, version)
    if row is None:
        return sp.err("not_found", f"no spec {topic or id}" + (f" v{version}" if version else ""),
                      "Call spec_list")
    head = f"{row['topic']} | {row['title']} | v{row['version']} | {row['status']}"
    return _page(ctx, [head, *row["body"].splitlines()], "spec_read", args, "", budget)


@tool("spec_export", "Publish the final specs to the project's clean folder as Markdown files plus an "
                     "index; a clean session only lists what is published.")
def spec_export(ctx: ServerContext, topic_prefix: str = "", format: str = "md") -> str:
    pp = _project(ctx)
    if isinstance(pp, str):
        return pp
    if format.strip().lower() != "md":
        return sp.err("bad_format", f"format '{format}' is not supported", "Use md")
    prefix = topic_prefix.strip()
    if _is_clean(ctx):
        n = len([e for e in sp.published(pp) if e["topic"].startswith(prefix)])
        return f"{n} published specs in {pp.specs}. Read them with spec_read(topic=...)."
    st = ctx.indexer.store(pp.name)
    final, skipped, gone = sp.publish(st, pp, ctx.session.role, prefix)
    extra = (f", {skipped} not final and left out" if skipped else "") + (
        f", {gone} withdrawn" if gone else "")
    return f"published {len(final)} specs to {pp.specs}{extra}. Index: specs.json; audit-summary.md."
