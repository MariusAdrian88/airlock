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
from mcp.server.mcpserver import Context as McpContext

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


def bind(impl: ToolImpl, ctx: Any) -> Callable[..., Any]:
    """Return an async function without the ctx parameter, keeping the rest of the
    signature so the MCP SDK derives the input schema from it. The implementation
    runs in a worker thread, so slow calls (JVM start, decompiles) never block the
    server's event loop."""
    sig = inspect.signature(impl.fn)
    hints = typing.get_type_hints(impl.fn, include_extras=True)
    params = [p.replace(annotation=hints.get(p.name, p.annotation))
              for p in list(sig.parameters.values())[1:]]

    ctx_param = inspect.Parameter("mcp_ctx", inspect.Parameter.KEYWORD_ONLY, default=None,
                                  annotation=McpContext)

    async def bound(*args: Any, mcp_ctx: Any = None, **kwargs: Any) -> str:
        if not ctx.roots_done and mcp_ctx is not None:
            try:
                await ctx.ensure_roots(mcp_ctx.request_context.session)
            except ValueError:  # no request context (direct call)
                pass
        refusal = roles.gate(ctx.session, impl.name)
        if refusal is not None:
            return refusal
        return await anyio.to_thread.run_sync(functools.partial(impl.fn, ctx, *args, **kwargs))

    bound.__name__ = impl.name
    bound.__doc__ = impl.description
    bound.__signature__ = sig.replace(parameters=[*params, ctx_param], return_annotation=str)  # type: ignore[attr-defined]
    bound.__annotations__ = {p.name: p.annotation for p in params} | {"mcp_ctx": McpContext, "return": str}
    return bound


def load_tool_modules() -> None:
    """Import every module that defines tools (each registers on import)."""
    from airlock.server.tools import admin, core, project, project_create  # noqa: F401
