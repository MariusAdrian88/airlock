"""Build the MCP server from the resolved config."""

from __future__ import annotations

import logging
from mcp.server.mcpserver import MCPServer

from airlock import __version__
from airlock.config import Config
from airlock.server.context import ServerContext
from airlock.server.registry import IMPLEMENTED, bind, load_tool_modules
from airlock.worker.client import WorkerClient

log = logging.getLogger("airlock")

INSTRUCTIONS = (
    "airlock: Ghidra-backed reverse engineering tools with a clean-room split. Start every "
    "session with projects, then project_open(name, role) chosen from the user's task: "
    "reverse engineering and specs are dirty, implementing from specs is clean (ask the "
    "user if unclear). To analyse a new program call project_create. The role cannot change "
    "in a session. Responses are compact text and may end with a cursor for more."
)


def build_server(config: Config, profile_explicit: bool = False
                 ) -> tuple[MCPServer, ServerContext]:
    load_tool_modules()
    ctx = ServerContext(config=config, worker=WorkerClient(config))
    if profile_explicit:
        ctx.profile_role = config.role
    server = MCPServer(name="airlock", version=__version__, instructions=INSTRUCTIONS)
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
    if config.source is not None:
        from airlock.config.upgrade import stale_message
        try:
            stale = stale_message(config.source.read_text("utf-8-sig"))
        except Exception:  # a broken file already failed in load_config
            stale = None
        if stale:
            log.warning("config: %s", stale)
    return server, ctx


def serve(config: Config, profile_explicit: bool = False) -> None:
    server, ctx = build_server(config, profile_explicit)
    try:
        server.run("stdio")
    finally:
        ctx.worker.stop()
