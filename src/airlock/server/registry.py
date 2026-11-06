"""Tool implementations register here; the config decides which get exposed.

A tool module declares:

    @tool("project_info", "One-sentence description.")
    def project_info(ctx: ServerContext, check_ghidra: bool = False) -> str: ...

Only names in Config.tools that also have an implementation are advertised.
Descriptions stay to one sentence: they are part of every session's context.
"""

from __future__ import annotations

import contextvars
import functools
import inspect
import typing
from dataclasses import dataclass
from typing import Any, Callable

import anyio.to_thread

from airlock.config.catalog import CATALOG
from airlock.server import roles

Impl = Callable[..., str]


@dataclass
class ToolImpl:
    name: str
    description: str
    fn: Impl


IMPLEMENTED: dict[str, ToolImpl] = {}


_NOTES: contextvars.ContextVar[list[str] | None] = contextvars.ContextVar("airlock_notes", default=None)


NL = chr(10)


def add_note(text: str) -> None:
    """A one-line fact about how the call's arguments were read (``(binary: X)``); the outermost
    tool call puts the notes above a successful result. Does nothing outside a tool call."""
    notes = _NOTES.get()
    if notes is not None and text not in notes:
        notes.append(text)


def _noting(fn: Impl) -> Impl:
    @functools.wraps(fn)
    def run(*args: Any, **kwargs: Any) -> str:
        if _NOTES.get() is not None:        # nested tool call: the outer call owns the notes
            return fn(*args, **kwargs)
        notes: list[str] = []
        token = _NOTES.set(notes)
        try:
            out = fn(*args, **kwargs)
        finally:
            _NOTES.reset(token)
        if notes and isinstance(out, str) and not out.startswith("error "):
            return NL.join(notes) + NL + out
        return out
    return run


_BOUND: contextvars.ContextVar[list | None] = contextvars.ContextVar("airlock_bound", default=None)


def note_bound(store: Any, binary: Any) -> None:
    """A tool call bound a binary (``Bound``); the library-name display uses only that binary's hits."""
    bounds = _BOUND.get()
    if bounds is not None:
        bounds.append((store, binary))


def _library_names(name: str, fn: Impl) -> Impl:
    """Read tools show a unique IDR/sigdb/WARP name instead of ``FUN_xxxxxxxx`` (``server/libnames.py``),
    inside the budget cut (``budget.DISPLAY``: the cut measures the shown text) and on the final text."""
    from airlock.server import budget, libnames
    if name not in libnames.RELABEL_TOOLS:
        return fn

    @functools.wraps(fn)
    def run(ctx: Any, *args: Any, **kwargs: Any) -> str:
        if _BOUND.get() is not None:        # nested tool call: the outer call owns the display
            return fn(ctx, *args, **kwargs)
        bounds: list = []
        disp = libnames.Display(ctx, kwargs.get("project"), bounds)
        t1, t2 = _BOUND.set(bounds), budget.DISPLAY.set(disp)
        try:
            out = fn(ctx, *args, **kwargs)
            if isinstance(out, str) and not out.startswith("error "):
                out = disp(out)
        finally:
            budget.DISPLAY.reset(t2)
            _BOUND.reset(t1)
        return out
    return run


def tool(name: str, description: str) -> Callable[[Impl], Impl]:
    if name not in CATALOG:
        raise ValueError(f"tool '{name}' is not in the catalog")

    def deco(fn: Impl) -> Impl:
        IMPLEMENTED[name] = ToolImpl(name, description, _library_names(name, _noting(fn)))
        return fn
    return deco


# Planned milestone per catalog set (docs/DESIGN.md milestones); a few tools differ.
_SET_MILESTONE = {"types": "M2", "cpp": "M2", "resources": "M2", "annotate": "M3", "admin": "M3",
                  "spec_write": "M4", "spec_read": "M4", "fileformat": "M5", "delphi": "M6",
                  "dotnet": "M7", "dataflow": "M8"}
_TOOL_MILESTONE = {"qt_metaobjects": "M8"}


def not_implemented_error(name: str) -> str:
    info = CATALOG.get(name)
    if info is None:
        return f"error unknown_tool: {name} is not a tool of this server."
    ms = _TOOL_MILESTONE.get(name) or _SET_MILESTONE.get(info.set, "a later milestone")
    return f"error not_implemented: {name} is planned for {ms} and not available yet."


def _refusal(ctx: Any, name: str, args: tuple = (), kwargs: dict | None = None) -> str | None:
    """The role gate; an unbound refusal lists the projects (the choice is the agent's).
    ``list_binaries`` with a project name reads that project without a bound session."""
    refusal = roles.gate(ctx.session, name)
    if refusal == roles.UNBOUND_ERROR and name == "list_binaries" and (
            (kwargs or {}).get("project") or (args and args[0])):
        return None
    if refusal == roles.UNBOUND_ERROR:
        try:
            return roles.unbound_error(ctx.indexer.projects())
        except Exception:  # noqa: BLE001  the list is an extra
            return refusal
    return refusal


def call(ctx: Any, name: str, *args: Any, **kwargs: Any) -> str:
    """Direct (non-MCP) call with the same gate as the MCP path; never raises for a tool that
    exists in the catalog but has no implementation yet."""
    refusal = _refusal(ctx, name, args, kwargs)
    if refusal is not None:
        return refusal
    impl = IMPLEMENTED.get(name)
    if impl is None:
        return not_implemented_error(name)
    return impl.fn(ctx, *args, **kwargs)


def bind(impl: ToolImpl, ctx: Any) -> Callable[..., Any]:
    """Return an async function without the ctx parameter, keeping the rest of the
    signature so the MCP SDK derives the input schema from it. The implementation
    runs in a worker thread, so slow calls (JVM start, decompiles) never block the
    server's event loop."""
    sig = inspect.signature(impl.fn)
    hints = typing.get_type_hints(impl.fn, include_extras=True)
    params = [p.replace(annotation=hints.get(p.name, p.annotation))
              for p in list(sig.parameters.values())[1:]]

    async def bound(*args: Any, **kwargs: Any) -> str:
        refusal = _refusal(ctx, impl.name, args, kwargs)
        if refusal is not None:
            return refusal
        if "from" in kwargs:      # `from` is a Python keyword: tools name the parameter `from_`
            kwargs["from_"] = kwargs.pop("from")
        return await anyio.to_thread.run_sync(functools.partial(impl.fn, ctx, *args, **kwargs))

    bound.__name__ = impl.name
    bound.__doc__ = impl.description
    bound.__signature__ = sig.replace(parameters=params, return_annotation=str)  # type: ignore[attr-defined]
    bound.__annotations__ = {p.name: p.annotation for p in params} | {"return": str}
    return bound


def load_tool_modules() -> None:
    """Import every module that defines tools (each registers on import)."""
    from airlock.server.tools import (  # noqa: F401
        admin, annotate, core, fmap, graphtools, map, project, project_create, queue, session, spec,
    )
    from airlock.server.tools import resources  # noqa: F401
    from airlock.server.tools import fileformat as fileformat_tools  # noqa: F401
    from airlock.server.tools import cpp as cpp_tools  # noqa: F401
    from airlock.server.tools import dotnet as dotnet_tools  # noqa: F401
    from airlock.server.tools import delphi as delphi_tools  # noqa: F401
    from airlock.server.tools import qt as qt_tools  # noqa: F401
    from airlock.server.tools import dataflow as dataflow_tools  # noqa: F401
