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
    "airlock: Ghidra-backed reverse engineering tools. Responses are compact text and "
    "may end with a cursor for more. Call project_info to see what is enabled."
)
CLEAN_INSTRUCTIONS = (
    "airlock (clean room): you can read specifications only. You never receive code, "
    "addresses or bytes from the analysed software."
)


def build_server(config: Config) -> tuple[MCPServer, ServerContext]:
    load_tool_modules()
    ctx = ServerContext(config=config, worker=WorkerClient(config))
    server = MCPServer(
        name="airlock",
        version=__version__,
        instructions=CLEAN_INSTRUCTIONS if config.is_clean else INSTRUCTIONS,
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
    return server, ctx


def serve(config: Config) -> None:
    server, ctx = build_server(config)
    try:
        server.run("stdio")
    finally:
        ctx.worker.stop()
