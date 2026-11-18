"""praxis-mcp: the PRAXIS tool surface over the Model Context Protocol.

The same registry the in-process agents use (`praxis.agents.toolbox`). It can
read coverage, search and score rules, run lab tests and backtests, and write
proposals into the working tree. It holds no deploy credentials.

Claude Code picks it up from `.mcp.json` at the repo root, which runs `./px mcp`.
"""

from __future__ import annotations

from typing import Any

import mcp_types as types
from mcp.server.lowlevel import Server

from praxis.agents.llm import model_schema, run_tool
from praxis.agents.toolbox import Toolbox
from praxis.settings import get_settings


def build_server(toolbox: Toolbox) -> Server:
    async def list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name=t.name, description=t.description, input_schema=model_schema(t.schema)
                )
                for t in toolbox.tools().values()
            ]
        )

    async def call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        tool = toolbox.tools().get(params.name)
        if tool is None:
            text, failed = f"unknown tool {params.name!r}", True
        else:
            text, failed = run_tool(toolbox, tool, params.arguments or {})
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=text)], is_error=failed
        )

    return Server(
        "praxis",
        instructions="PRAXIS detection engineering tools. They read coverage, search and "
        "score rules, run lab tests and backtests, and write proposals into the working "
        "tree. They cannot deploy.",
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )


def serve() -> None:
    import anyio
    from mcp.server.stdio import stdio_server

    server = build_server(Toolbox(get_settings().content_dir))

    async def main() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(main)
