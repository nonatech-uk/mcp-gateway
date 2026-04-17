"""MCP gateway — proxies to backend MCP servers over HTTP."""

import logging
import os
import ssl
import time
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
_MCP_RESOURCE_URL = os.environ.get("MCP_RESOURCE_URL", "")
_MCP_AUTHORIZATION_SERVER = os.environ.get("MCP_AUTHORIZATION_SERVER", "")
# OAuth introspection (RFC 7662) for Keycloak-issued bearer tokens.
_INTROSPECTION_URL = os.environ.get("MCP_INTROSPECTION_URL", "")
_INTROSPECTION_CLIENT_ID = os.environ.get("MCP_INTROSPECTION_CLIENT_ID", "")
_INTROSPECTION_CLIENT_SECRET = os.environ.get("MCP_INTROSPECTION_CLIENT_SECRET", "")
_INTROSPECTION_REQUIRED_SCOPE = os.environ.get("MCP_INTROSPECTION_REQUIRED_SCOPE", "mcp")
_INTROSPECTION_REQUIRED_AUD = os.environ.get("MCP_INTROSPECTION_REQUIRED_AUD", "")
_CORS_ALLOWED_ORIGINS = {
    o.strip() for o in os.environ.get(
        "MCP_CORS_ALLOWED_ORIGINS",
        "https://claude.ai,https://www.claude.ai",
    ).split(",") if o.strip()
}


def _resource_metadata_url() -> str:
    """Absolute URL to the resource metadata endpoint. Anthropic's MCP client
    silently rejects relative values; the URL MUST be absolute."""
    if not _MCP_RESOURCE_URL:
        return ""
    from urllib.parse import urlparse
    u = urlparse(_MCP_RESOURCE_URL)
    return f"{u.scheme}://{u.netloc}/.well-known/oauth-protected-resource"


class BearerTokenMiddleware(BaseHTTPMiddleware):
    """Bearer token auth. Accepts either:
      1. The static MCP_BEARER_TOKEN (Claude Code CLI path, URL ?token= or
         Authorization header). Unchanged from pre-OAuth behaviour.
      2. An opaque OAuth bearer token validated via RFC 7662 introspection
         against Keycloak (claude.ai web/Desktop path). Requires active=true
         plus the configured required scope and audience.

    Returns 401 with WWW-Authenticate on failure so MCP clients discover the
    authorization server and start OAuth. Preserves CORS for browser clients."""

    # token → (expires_at, accepted_bool)
    _introspect_cache: dict[str, tuple[float, bool]] = {}
    _cache_ttl = 60.0

    async def dispatch(self, request: Request, call_next):
        p = request.url.path
        origin = request.headers.get("origin", "")
        cors_ok = bool(origin) and (origin in _CORS_ALLOWED_ORIGINS or _CORS_ALLOWED_ORIGINS == {"*"})

        # CORS preflight — browser sends before any cross-origin request carrying
        # non-simple headers (Authorization, Content-Type: application/json, …).
        if request.method == "OPTIONS":
            headers = {
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version",
                "Access-Control-Max-Age": "600",
            }
            if cors_ok:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
                headers["Vary"] = "Origin"
            return Response(status_code=204, headers=headers)

        # /health + /.well-known/* are always public.
        if p == "/health" or p.startswith("/.well-known/"):
            resp = await call_next(request)
            self._apply_cors(resp, origin, cors_ok)
            return resp

        if not _BEARER_TOKEN and not _INTROSPECTION_URL:
            return await call_next(request)

        # Query param first, then Authorization header.
        token = request.query_params.get("token", "")
        if not token:
            auth = request.headers.get("authorization", "")
            if auth.startswith("Bearer "):
                token = auth[7:]

        if not token:
            return self._unauthorized(origin, cors_ok)

        # Static token fast path (Claude Code CLI). No introspection round-trip.
        if _BEARER_TOKEN and token == _BEARER_TOKEN:
            resp = await call_next(request)
            self._apply_cors(resp, origin, cors_ok)
            return resp

        # OAuth bearer path.
        if _INTROSPECTION_URL and await self._introspect_ok(token):
            resp = await call_next(request)
            self._apply_cors(resp, origin, cors_ok)
            return resp

        return self._unauthorized(origin, cors_ok)

    async def _introspect_ok(self, token: str) -> bool:
        now = time.monotonic()
        cached = self._introspect_cache.get(token)
        if cached and cached[0] > now:
            return cached[1]
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r = await c.post(
                    _INTROSPECTION_URL,
                    auth=(_INTROSPECTION_CLIENT_ID, _INTROSPECTION_CLIENT_SECRET),
                    data={"token": token},
                    headers={"Accept": "application/json"},
                )
                r.raise_for_status()
                body = r.json()
        except Exception as e:
            log.warning("Introspection failed: %s", e)
            self._introspect_cache[token] = (now + self._cache_ttl, False)
            return False

        if not body.get("active"):
            self._introspect_cache[token] = (now + self._cache_ttl, False)
            return False
        # Required scope (space-separated string in RFC 7662).
        if _INTROSPECTION_REQUIRED_SCOPE:
            scopes = (body.get("scope") or "").split()
            if _INTROSPECTION_REQUIRED_SCOPE not in scopes:
                log.info("Token rejected: missing required scope %r", _INTROSPECTION_REQUIRED_SCOPE)
                self._introspect_cache[token] = (now + self._cache_ttl, False)
                return False
        # Required audience (string or list per RFC 7662).
        if _INTROSPECTION_REQUIRED_AUD:
            aud = body.get("aud")
            aud_list = aud if isinstance(aud, list) else ([aud] if aud else [])
            if _INTROSPECTION_REQUIRED_AUD not in aud_list:
                log.info("Token rejected: aud %r does not include %r", aud, _INTROSPECTION_REQUIRED_AUD)
                self._introspect_cache[token] = (now + self._cache_ttl, False)
                return False

        self._introspect_cache[token] = (now + self._cache_ttl, True)
        # Opportunistic cache trim.
        if len(self._introspect_cache) > 1024:
            for k, (exp, _) in list(self._introspect_cache.items()):
                if exp <= now:
                    self._introspect_cache.pop(k, None)
        return True

    def _unauthorized(self, origin: str, cors_ok: bool) -> Response:
        # Minimal WWW-Authenticate — Anthropic's MCP client expects
        # `Bearer realm="MCP", resource_metadata="<absolute-url>"` exactly.
        # Extra params (error, error_description) are dropped to minimise the
        # surface their parser can trip on.
        rm = _resource_metadata_url()
        parts = ['Bearer realm="MCP"']
        if rm:
            parts.append(f'resource_metadata="{rm}"')
        headers = {
            "WWW-Authenticate": ", ".join(parts),
            # Browser JS can only read WWW-Authenticate when it's in
            # Access-Control-Expose-Headers; otherwise the CORS layer hides it.
            "Access-Control-Expose-Headers": "WWW-Authenticate, Mcp-Session-Id",
        }
        if cors_ok:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
            headers["Vary"] = "Origin"
        return Response(status_code=401, headers=headers)

    @staticmethod
    def _apply_cors(resp: Response, origin: str, cors_ok: bool) -> None:
        if cors_ok:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers.setdefault("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id")
            resp.headers["Vary"] = "Origin"
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

    # RFC 9728 protected-resource metadata. Tells MCP clients which authorization
    # server to use. Served at both the root and resource-specific paths
    # (some clients check /.well-known/oauth-protected-resource/<path>).
    if _MCP_RESOURCE_URL and _MCP_AUTHORIZATION_SERVER:
        _resource_metadata = {
            "resource": _MCP_RESOURCE_URL,
            "authorization_servers": [_MCP_AUTHORIZATION_SERVER],
            "scopes_supported": ["mcp", "offline_access"],
            "bearer_methods_supported": ["header"],
        }

        @gw.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
        async def opr_root(request: Request) -> JSONResponse:
            return JSONResponse(_resource_metadata)

        @gw.custom_route("/.well-known/oauth-protected-resource/mcp", methods=["GET"])
        async def opr_mcp(request: Request) -> JSONResponse:
            return JSONResponse(_resource_metadata)

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
