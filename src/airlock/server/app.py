"""Build the MCP server from the resolved config."""

from __future__ import annotations

import logging
from typing import Any

from mcp import types
from mcp.server.mcpserver import MCPServer

from airlock import __version__
from airlock.config import Config
from airlock.server import roles
from airlock.server.context import ServerContext
from airlock.server.registry import IMPLEMENTED, bind, load_tool_modules
from airlock.worker.client import WorkerClient

log = logging.getLogger("airlock")

INSTRUCTIONS = (
    "airlock: Ghidra-backed reverse engineering tools. Responses are compact text and "
    "may end with a cursor for more. Call project_info to see what is enabled."
)
CLEAN_INSTRUCTIONS = (
    "airlock (clean room): you can read specifications only. You never receive code, "
    "addresses or bytes from the analysed software."
)


def build_server(config: Config, profile_explicit: bool = False
                 ) -> tuple[MCPServer, ServerContext]:
    """Raises roles.RoleConflict when an explicit --profile contradicts the folder role."""
    load_tool_modules()
    ctx = ServerContext(config=config, worker=WorkerClient(config))
    if profile_explicit:
        ctx.profile_role = config.role
    ws, source = roles.detect_workspace()
    ctx.set_session(roles.resolve_session(ws, source, ctx.profile_role))
    server = MCPServer(
        name="airlock",
        version=__version__,
        instructions=CLEAN_INSTRUCTIONS if ctx.session.role == roles.CLEAN else INSTRUCTIONS,
    )
    for name in config.tools:
        impl = IMPLEMENTED.get(name)
        if impl is None:
            ctx.not_implemented.append(name)
            continue
        # structured_output=False: no outputSchema is advertised (keeps tools/list small).
        server.add_tool(bind(impl, ctx), name=impl.name, description=impl.description,
                        structured_output=False)
    for issue in config.issues:
        if issue.level != "info":
            log.warning("%s", issue)

    async def on_initialized(rctx: Any, _params: Any) -> None:
        # Roots need a round trip to the client; ask right after the handshake. Tool
        # calls that arrive first do the same through bind() (ensure_roots runs once).
        await ctx.ensure_roots(rctx.session)

    server._lowlevel_server.add_notification_handler(
        "notifications/initialized", types.NotificationParams, on_initialized)
    return server, ctx


def serve(config: Config, profile_explicit: bool = False) -> None:
    server, ctx = build_server(config, profile_explicit)
    try:
        server.run("stdio")
    finally:
        ctx.worker.stop()
