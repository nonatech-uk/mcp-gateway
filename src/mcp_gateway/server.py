"""MCP gateway — proxies to backend MCP servers over HTTP with OAuth2 auth."""

import os

from fastmcp import FastMCP
from fastmcp.server import create_proxy
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_gateway.auth import create_auth

# Backend MCP servers configured via env: MCP_BACKENDS=name=url,name=url,...
# e.g. MCP_BACKENDS=tautulli=http://mcp-tautulli:8080/mcp,paperless=http://mcp-paperless:8080/mcp


def create_server() -> FastMCP:
    """Create the gateway server with remote backends mounted as proxies."""
    auth_enabled = os.environ.get("MCP_AUTH_ENABLED", "true").lower() == "true"

    kwargs: dict = {"name": "mcp-gateway"}
    if auth_enabled:
        kwargs["auth"] = create_auth()

    gateway = FastMCP(**kwargs)

    backends = os.environ.get("MCP_BACKENDS", "")
    for entry in backends.split(","):
        entry = entry.strip()
        if not entry or "=" not in entry:
            continue
        name, url = entry.split("=", 1)
        proxy = create_proxy(url.strip(), name=name.strip())
        gateway.mount(proxy)

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
