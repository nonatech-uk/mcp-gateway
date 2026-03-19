"""MCP gateway — exposes Tautulli MCP server over HTTP with OAuth2 auth."""

import os

from fastmcp import FastMCP
from mcp_search.tautulli_mcp import mcp as tautulli_mcp
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_gateway.auth import create_auth


def create_server() -> FastMCP:
    """Create the gateway server with Tautulli mounted."""
    auth_enabled = os.environ.get("MCP_AUTH_ENABLED", "true").lower() == "true"

    kwargs: dict = {"name": "mcp-gateway"}
    if auth_enabled:
        kwargs["auth"] = create_auth()

    gateway = FastMCP(**kwargs)
    gateway.mount(tautulli_mcp)

    @gateway.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    return gateway


gateway = create_server()

if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "streamable-http")
    if transport == "stdio":
        gateway.run(transport="stdio")
    else:
        host = os.environ.get("MCP_HOST", "0.0.0.0")
        port = int(os.environ.get("MCP_PORT", "8080"))
        gateway.run(transport="streamable-http", host=host, port=port)
