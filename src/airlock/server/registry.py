"""Tool implementations register here; the config decides which get exposed.

A tool module declares:

    @tool("project_info", "One-sentence description.")
    def project_info(ctx: ServerContext, check_ghidra: bool = False) -> str: ...

Only names in Config.tools that also have an implementation are advertised.
Descriptions stay to one sentence: they are part of every session's context.
"""

from __future__ import annotations

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


def tool(name: str, description: str) -> Callable[[Impl], Impl]:
    if name not in CATALOG:
        raise ValueError(f"tool '{name}' is not in the catalog")

    def deco(fn: Impl) -> Impl:
        IMPLEMENTED[name] = ToolImpl(name, description, fn)
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
        return f"error unknown_tool: {name} is not a tool of this server. Call project_info for the list."
    ms = _TOOL_MILESTONE.get(name) or _SET_MILESTONE.get(info.set, "a later milestone")
    return f"error not_implemented: {name} is planned for {ms} and not available yet."


def call(ctx: Any, name: str, *args: Any, **kwargs: Any) -> str:
    """Direct (non-MCP) call with the same gate as the MCP path; never raises for a tool that
    exists in the catalog but has no implementation yet."""
    refusal = roles.gate(ctx.session, name)
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
        refusal = roles.gate(ctx.session, impl.name)
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
        admin, core, fmap, graphtools, map, project, project_create, queue, session,
    )
