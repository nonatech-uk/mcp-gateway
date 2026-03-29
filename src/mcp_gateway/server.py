"""MCP gateway — proxies to backend MCP servers over HTTP with OAuth2 auth."""

import logging
import os

import httpx
from fastmcp import FastMCP
from fastmcp.server import create_proxy
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_gateway.auth import create_auth

log = logging.getLogger(__name__)

# Backend MCP servers configured via env: MCP_BACKENDS=name=url,name=url,...
# e.g. MCP_BACKENDS=tautulli=http://mcp-tautulli:8080/mcp,paperless=http://mcp-paperless:8080/mcp

# The NAS host-tools backend is registered as direct tools (not a proxy)
# to avoid lazy-loading issues where tools aren't available at connection time.
NAS_HOST_TOOLS_URL = os.environ.get("NAS_HOST_TOOLS_URL", "")
_NAS_API_KEY = os.environ.get("NAS_HOST_TOOLS_API_KEY", "")
_SSL_CA_CERTFILE = os.environ.get("SSL_CA_CERTFILE", "")


def create_server() -> FastMCP:
    """Create the gateway server with remote backends mounted as proxies."""
    auth_enabled = os.environ.get("MCP_AUTH_ENABLED", "true").lower() == "true"

    kwargs: dict = {"name": "mcp-gateway"}
    if auth_enabled:
        kwargs["auth"] = create_auth()

    gw = FastMCP(**kwargs)

    backends = os.environ.get("MCP_BACKENDS", "")
    for entry in backends.split(","):
        entry = entry.strip()
        if not entry or "=" not in entry:
            continue
        name, url = entry.split("=", 1)
        proxy = create_proxy(url.strip(), name=name.strip())
        gw.mount(proxy)

    # Register NAS host-tools as direct tools (not proxy) for immediate availability
    if NAS_HOST_TOOLS_URL:
        _nas_url = NAS_HOST_TOOLS_URL.rstrip("/")

        async def _nas_call(endpoint: str, body: dict | None = None) -> str:
            try:
                ckw: dict = {"timeout": 60}
                if _SSL_CA_CERTFILE:
                    ckw["verify"] = _SSL_CA_CERTFILE
                headers = {}
                if _NAS_API_KEY:
                    headers["Authorization"] = f"Bearer {_NAS_API_KEY}"
                async with httpx.AsyncClient(**ckw) as client:
                    if body is not None:
                        resp = await client.post(f"{_nas_url}{endpoint}", json=body, headers=headers)
                    else:
                        resp = await client.get(f"{_nas_url}{endpoint}", headers=headers)
                    resp.raise_for_status()
                    data = resp.json()
                    return data.get("output", data.get("result", str(data)))
            except Exception as e:
                return f"Error calling NAS host-tools: {e}"

        @gw.tool(name="host_list")
        async def host_list() -> str:
            """List all available hosts that can be targeted with host_exec."""
            return await _nas_call("/api/tools/list_hosts")

        @gw.tool(name="host_commands")
        async def host_commands(host: str | None = None) -> str:
            """List all available commands on a host.

            Args:
                host: Target host name from host_list. Defaults to the local host.
            """
            return await _nas_call("/api/tools/list_commands", {"host": host})

        @gw.tool(name="host_exec")
        async def host_exec(
            name: str, params: dict[str, str | int] | None = None, host: str | None = None,
        ) -> str:
            """Run an allowed command on a host.

            Args:
                name: Command name from host_commands (e.g. 'zpool_status', 'systemctl_status')
                params: Parameters for the command (e.g. {"service": "traefik"})
                host: Target host name from host_list. Defaults to the local host.
            """
            return await _nas_call("/api/tools/run_command", {
                "name": name, "params": params or {}, "host": host,
            })

        @gw.tool(name="host_suggest")
        async def host_suggest(
            command: str,
            reason: str,
            suggested_name: str | None = None,
            params: dict | None = None,
            host: str | None = None,
        ) -> str:
            """Suggest a new command to add to the allowlist for admin review.

            Args:
                command: The full command template (e.g. 'smartctl -a /dev/{device}')
                reason: Why this command would be useful for investigation
                suggested_name: Proposed command name following {resource}_{action} convention (e.g. 'disk_containers')
                params: Optional parameter definitions for templatizing
                host: Which host this command is for. Defaults to the local host.
            """
            if suggested_name:
                reason = f"Suggested name: {suggested_name} | {reason}"
            return await _nas_call("/api/tools/suggest_command", {
                "command": command, "reason": reason, "params": params, "host": host,
            })

        @gw.tool(name="suggestions_pending")
        async def suggestions_pending(host: str | None = None) -> str:
            """Show pending command suggestions awaiting approval. Check this before suggesting to avoid duplicates.

            Args:
                host: Filter by host name. Omit to see all hosts.
            """
            return await _nas_call("/api/tools/suggestions_pending", {"host": host})

        @gw.tool(name="suggestions_recent")
        async def suggestions_recent(count: int = 10, host: str | None = None) -> str:
            """Show recently approved/rejected suggestions. Use to confirm a suggestion landed correctly.

            Args:
                count: Number of recent items to show (default 10)
                host: Filter by host name. Omit to see all hosts.
            """
            return await _nas_call("/api/tools/suggestions_recent", {"count": count, "host": host})

    @gw.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> JSONResponse:
        tools = await gw.list_tools()
        return JSONResponse({
            "status": "ok",
            "tools": len(tools),
        })

    return gw


gateway = create_server()

if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "streamable-http")
    if transport == "stdio":
        gateway.run(transport="stdio")
    else:
        host = os.environ.get("MCP_HOST", "0.0.0.0")
        port = int(os.environ.get("MCP_PORT", "8080"))
        gateway.run(transport="streamable-http", host=host, port=port)
