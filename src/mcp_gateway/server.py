"""MCP gateway — proxies to backend MCP servers over HTTP."""

import logging
import os
import ssl
from collections.abc import Awaitable, Callable

import httpx
from fastmcp import Context, FastMCP
from fastmcp.client.transports.http import StreamableHttpTransport
from fastmcp.server import create_proxy
from fastmcp.server.middleware import MiddlewareContext
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

log = logging.getLogger(__name__)

_GATEWAY_KEY = os.environ.get("MCP_GATEWAY_KEY", "")
_BEARER_TOKEN = os.environ.get("MCP_BEARER_TOKEN", "")


class BearerTokenMiddleware(BaseHTTPMiddleware):
    """Reject requests without a valid token in query param or Authorization header. Returns bare 403."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)
        if not _BEARER_TOKEN:
            return await call_next(request)
        # Check query param first, then Authorization header
        token = request.query_params.get("token", "")
        if not token:
            auth = request.headers.get("authorization", "")
            if auth.startswith("Bearer "):
                token = auth[7:]
        if token != _BEARER_TOKEN:
            return Response(status_code=403)
        return await call_next(request)
_unlocked_sessions: set[str] = set()

# Backend MCP servers configured via env: MCP_BACKENDS=name=url,name=url,...
# e.g. MCP_BACKENDS=tautulli=http://mcp-tautulli:8080/mcp,paperless=http://mcp-paperless:8080/mcp

# The NAS host-tools backend is registered as direct tools (not a proxy)
# to avoid lazy-loading issues where tools aren't available at connection time.
NAS_HOST_TOOLS_URL = os.environ.get("NAS_HOST_TOOLS_URL", "")
_NAS_API_KEY = os.environ.get("NAS_HOST_TOOLS_API_KEY", "")
_SSL_CA_CERTFILE = os.environ.get("SSL_CA_CERTFILE", "")

_MAC_API_KEY = os.environ.get("MAC_MCP_API_KEY", "")
_MAC_CA_CERTFILE = os.environ.get("MAC_MCP_CA_CERTFILE", "")


async def gateway_key_middleware(
    context: MiddlewareContext,
    call_next: Callable[[MiddlewareContext], Awaitable],
):
    """FastMCP middleware: block tool calls from sessions that haven't unlocked."""
    # Only gate tools/call requests
    if context.method != "tools/call":
        return await call_next(context)

    # The message is CallToolRequestParams directly — name is on the message itself
    tool_name = getattr(context.message, "name", "") or ""

    # Always allow gateway_unlock through
    if tool_name == "gateway_unlock":
        return await call_next(context)

    # Check session
    ctx = context.fastmcp_context
    sid = ctx.session_id if ctx else None
    if not sid or sid not in _unlocked_sessions:
        log.warning("Blocked %s — session %s not unlocked", tool_name, (sid or "?")[:8])
        raise ValueError("Session not unlocked. Call gateway_unlock with the correct key first.")

    return await call_next(context)


def create_server() -> FastMCP:
    """Create the gateway server with remote backends mounted as proxies."""
    gw = FastMCP(name="mcp-gateway")

    # Bearer token auth at HTTP level — returns bare 403, hides MCP identity
    if _BEARER_TOKEN:
        log.warning("Bearer token middleware enabled")

    # Register gateway key middleware if key is configured
    if _GATEWAY_KEY:
        gw.add_middleware(gateway_key_middleware)
        log.warning("Gateway key middleware enabled")

    def _backend_httpx_factory(headers=None, timeout=None, auth=None, **kwargs):
        return httpx.AsyncClient(
            headers=headers or {},
            timeout=httpx.Timeout(10.0, read=30.0),
            auth=auth,
            follow_redirects=True,
        )

    backends = os.environ.get("MCP_BACKENDS", "")
    for entry in backends.split(","):
        entry = entry.strip()
        if not entry or "=" not in entry:
            continue
        name, url = entry.split("=", 1)
        transport = StreamableHttpTransport(
            url=url.strip(),
            httpx_client_factory=_backend_httpx_factory,
        )
        proxy = create_proxy(transport, name=name.strip())
        gw.mount(proxy)

    # MAC backends: TLS with custom CA + API key auth
    if _MAC_CA_CERTFILE:
        _mac_ssl_ctx = ssl.create_default_context(cafile=_MAC_CA_CERTFILE)

    mac_backends = os.environ.get("MAC_MCP_BACKENDS", "")
    for entry in mac_backends.split(","):
        entry = entry.strip()
        if not entry or "=" not in entry:
            continue
        name, url = entry.split("=", 1)
        url = url.strip()
        if not url.endswith("/mcp"):
            url += "/mcp"

        def _mac_httpx_factory(
            headers=None, timeout=None, auth=None, **kwargs,
        ):
            return httpx.AsyncClient(
                verify=_mac_ssl_ctx if _MAC_CA_CERTFILE else True,
                headers=headers or {},
                timeout=timeout or httpx.Timeout(10.0, read=30.0),
                auth=auth,
                follow_redirects=True,
            )

        transport = StreamableHttpTransport(
            url=url,
            auth=_MAC_API_KEY or None,
            httpx_client_factory=_mac_httpx_factory,
        )
        proxy = create_proxy(transport, name=name.strip())
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

    # Session unlock tool — required before any other tool call when MCP_GATEWAY_KEY is set
    if _GATEWAY_KEY:
        @gw.tool(name="gateway_unlock")
        async def gateway_unlock(key: str, ctx: Context) -> str:
            """Unlock this session to allow tool calls. Must be called before using any other tool.

            Args:
                key: The gateway access key.
            """
            if key != _GATEWAY_KEY:
                log.warning("gateway_unlock failed — wrong key")
                return "ERROR: Invalid key."
            sid = ctx.session_id
            if not sid:
                return "ERROR: No session ID found."
            _unlocked_sessions.add(sid)
            log.info("Session %s unlocked", sid[:8])
            return "Session unlocked. You may now use all tools."

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
        # MCP_JSON_RESPONSE=1 closes POST streams after the response body instead
        # of keeping SSE open. Needed when fronted by Cloudflare Tunnel, which
        # handles the held-open SSE pattern poorly compared to CF proxy-to-origin.
        json_response = os.environ.get("MCP_JSON_RESPONSE", "").lower() in ("1", "true", "yes") or None
        if _BEARER_TOKEN:
            app = gateway.http_app(json_response=json_response)
            app.add_middleware(BearerTokenMiddleware)
            import uvicorn
            uvicorn.run(app, host=host, port=port)
        else:
            gateway.run(transport="streamable-http", host=host, port=port, json_response=json_response)
