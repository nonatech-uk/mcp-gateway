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
from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import MiddlewareContext
from fastmcp.exceptions import ToolError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .access_log import init_pool as init_access_log_pool, log_event as log_access
from .tokens import (
    TokenPolicy,
    UnlockProfile,
    _dsn_from_env,
    clear_bearer_cache,
    ip_allowed,
    load_policies,
    match_oauth,
    match_token,
    match_unlock_profile,
    tool_allowed,
)

log = logging.getLogger(__name__)

_GATEWAY_KEY = os.environ.get("MCP_GATEWAY_KEY", "")  # legacy single-key fallback
_TOKENS_FILE = os.environ.get("MCP_TOKENS_FILE", "/etc/mcp-gateway/tokens.yaml")
# Reload endpoint bearer; the admin app POSTs here after every mutation.
_RELOAD_TOKEN = os.environ.get("MCP_RELOAD_TOKEN", "")


def _initial_load() -> tuple[list[TokenPolicy], list[UnlockProfile]]:
    yaml_path = _TOKENS_FILE if os.path.exists(_TOKENS_FILE) else None
    try:
        return load_policies(yaml_path)
    except Exception:
        log.exception("Initial policy load failed; starting with empty policy set")
        return [], []


_POLICIES, _UNLOCK_PROFILES = _initial_load()

# Access-log pool — initialised once. log_access() is a no-op until init.
_log_dsn = _dsn_from_env()
if _log_dsn:
    init_access_log_pool(_log_dsn)
# session_id → matched policy. Populated by the HTTP middleware on every
# authenticated request (Mcp-Session-Id header). Read by the FastMCP tool
# middleware, which runs in the session-worker task where ContextVars set
# in the HTTP request's task are not visible.
_session_policy: dict[str, TokenPolicy] = {}
# Scope key used to stash the policy on the Starlette request so FastMCP
# code running in the same task (via get_http_request()) can recover it.
_SCOPE_POLICY_KEY = "mcp_gateway_policy"
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
      1. A static token declared in tokens.yaml (Claude Code CLI path, URL
         ?token= or Authorization header). The matched policy's IP allowlist
         is enforced and the policy is stashed in a ContextVar so downstream
         FastMCP middleware can filter tools.
      2. An opaque OAuth bearer token validated via RFC 7662 introspection
         against Keycloak (claude.ai web/Desktop path). Requires active=true
         plus the configured required scope and audience. OAuth callers get
         the full tool set — per-token filtering is for static tokens only.

    Returns 401 with WWW-Authenticate on failure so MCP clients discover the
    authorization server and start OAuth. Preserves CORS for browser clients."""

    # token → (expires_at, accepted_bool, claims_dict).
    # claims_dict carries sub/email/preferred_username for OAuth policy lookup.
    _introspect_cache: dict[str, tuple[float, bool, dict]] = {}
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

        # /health + /.well-known/* are always public. /admin/* is bearer-gated
        # by the route handler itself (MCP_RELOAD_TOKEN), separate from the
        # tokens.yaml/DB policy bearers handled below.
        if p == "/health" or p.startswith("/.well-known/") or p.startswith("/admin/"):
            resp = await call_next(request)
            self._apply_cors(resp, origin, cors_ok)
            return resp

        if not _POLICIES and not _INTROSPECTION_URL:
            return await call_next(request)

        # Query param first, then Authorization header.
        token = request.query_params.get("token", "")
        if not token:
            auth = request.headers.get("authorization", "")
            if auth.startswith("Bearer "):
                token = auth[7:]

        if not token:
            return self._unauthorized(origin, cors_ok)

        # Static token path. Match against configured policies, enforce the
        # policy's IP allowlist, then expose the policy to downstream
        # middleware via two routes: request.scope (recoverable from the
        # same task via get_http_request()) and a session_id → policy map
        # keyed on Mcp-Session-Id, because FastMCP dispatches tool calls
        # from a pre-spawned session worker task whose ContextVar snapshot
        # predates our HTTP middleware.
        policy = match_token(_POLICIES, token) if _POLICIES else None
        if policy is not None:
            client_ip = _client_ip(request)
            if not ip_allowed(policy, client_ip):
                log.warning(
                    "Token %r rejected — client IP %s not in allowlist",
                    policy.name, client_ip,
                )
                log_access("auth_fail_ip", actor_kind="static_bearer", actor_name=policy.name, client_ip=client_ip)
                return self._unauthorized(origin, cors_ok)
            log_access("auth_success", actor_kind="static_bearer", actor_name=policy.name, client_ip=client_ip)
            request.scope[_SCOPE_POLICY_KEY] = policy
            sid = request.headers.get("mcp-session-id", "")
            if sid:
                _session_policy[sid] = policy
            resp = await call_next(request)
            # On initialize the server assigns a session_id in the response;
            # pick it up so subsequent messages on that session can find the
            # policy even if the client's next request race-races auth.
            new_sid = resp.headers.get("mcp-session-id", "")
            if new_sid and new_sid not in _session_policy:
                _session_policy[new_sid] = policy
            self._apply_cors(resp, origin, cors_ok)
            return resp

        # OAuth bearer path. A valid Keycloak token must additionally match
        # an explicit policy in tokens.yaml; without one we deny, so adding
        # a user to the realm is not by itself enough to grant tool access.
        if _INTROSPECTION_URL:
            ok, claims = await self._introspect_ok(token)
            if ok:
                sub = claims.get("sub", "")
                email = claims.get("email", "")
                username = claims.get("preferred_username", "")
                oauth_policy = match_oauth(
                    _POLICIES, sub=sub, email=email, username=username,
                )
                if oauth_policy is None:
                    log.warning(
                        "OAuth token rejected — no policy matches "
                        "(sub=%r email=%r username=%r)",
                        sub, email, username,
                    )
                    log_access(
                        "auth_fail_token", actor_kind="oauth",
                        client_ip=_client_ip(request),
                        detail={"sub": sub, "email": email, "username": username},
                    )
                    return self._unauthorized(origin, cors_ok)
                client_ip = _client_ip(request)
                if not ip_allowed(oauth_policy, client_ip):
                    log.warning(
                        "OAuth policy %r rejected — client IP %s not in allowlist",
                        oauth_policy.name, client_ip,
                    )
                    log_access(
                        "auth_fail_ip", actor_kind="oauth",
                        actor_name=oauth_policy.name, client_ip=client_ip,
                    )
                    return self._unauthorized(origin, cors_ok)
                log_access(
                    "auth_success", actor_kind="oauth",
                    actor_name=oauth_policy.name, client_ip=client_ip,
                    detail={"email": email, "username": username},
                )
                log.info(
                    "OAuth policy %r matched (email=%r ip=%s)",
                    oauth_policy.name, email, client_ip,
                )
                request.scope[_SCOPE_POLICY_KEY] = oauth_policy
                sid = request.headers.get("mcp-session-id", "")
                if sid:
                    _session_policy[sid] = oauth_policy
                resp = await call_next(request)
                new_sid = resp.headers.get("mcp-session-id", "")
                if new_sid and new_sid not in _session_policy:
                    _session_policy[new_sid] = oauth_policy
                self._apply_cors(resp, origin, cors_ok)
                return resp

        # No static-bearer match and no successful OAuth introspection.
        log_access("auth_fail_token", client_ip=_client_ip(request))
        return self._unauthorized(origin, cors_ok)

    async def _introspect_ok(self, token: str) -> tuple[bool, dict]:
        now = time.monotonic()
        cached = self._introspect_cache.get(token)
        if cached and cached[0] > now:
            return cached[1], cached[2]
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
            self._introspect_cache[token] = (now + self._cache_ttl, False, {})
            return False, {}

        if not body.get("active"):
            self._introspect_cache[token] = (now + self._cache_ttl, False, {})
            return False, {}
        # Required scope (space-separated string in RFC 7662).
        if _INTROSPECTION_REQUIRED_SCOPE:
            scopes = (body.get("scope") or "").split()
            if _INTROSPECTION_REQUIRED_SCOPE not in scopes:
                log.info("Token rejected: missing required scope %r", _INTROSPECTION_REQUIRED_SCOPE)
                self._introspect_cache[token] = (now + self._cache_ttl, False, {})
                return False, {}
        # Required audience (string or list per RFC 7662).
        if _INTROSPECTION_REQUIRED_AUD:
            aud = body.get("aud")
            aud_list = aud if isinstance(aud, list) else ([aud] if aud else [])
            if _INTROSPECTION_REQUIRED_AUD not in aud_list:
                log.info("Token rejected: aud %r does not include %r", aud, _INTROSPECTION_REQUIRED_AUD)
                self._introspect_cache[token] = (now + self._cache_ttl, False, {})
                return False, {}

        claims = {
            "sub": body.get("sub", ""),
            "email": body.get("email", ""),
            "preferred_username": body.get("preferred_username", ""),
        }
        self._introspect_cache[token] = (now + self._cache_ttl, True, claims)
        # Opportunistic cache trim.
        if len(self._introspect_cache) > 1024:
            for k, (exp, *_rest) in list(self._introspect_cache.items()):
                if exp <= now:
                    self._introspect_cache.pop(k, None)
        return True, claims

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


def _client_ip(request: Request) -> str:
    """Real client IP. Traefik is the only HTTP hop and is trusted, so the
    leftmost X-Forwarded-For entry is the original caller. Fall back to the
    raw peer for the mcp-local deployment where no proxy sits in front."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        first = xff.split(",", 1)[0].strip()
        if first:
            return first
    return request.client.host if request.client else ""


# session_id → unlock-profile name. Populated by gateway_unlock; consulted
# by gateway_key_middleware (gate) and tool_policy_middleware (intersection).
# The legacy "default" profile carries `tools_glob: ['*']` so callers that
# still call gateway_unlock(key=...) without specifying a profile see no
# narrowing — same observable behaviour as the previous global-key model.
_unlocked_sessions: dict[str, str] = {}

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
        raise ToolError(
            "AUTH: this session is locked. Call gateway_unlock(profile=…, key=…) "
            "before calling other tools.",
        )

    return await call_next(context)


def _profile_for(context: MiddlewareContext) -> UnlockProfile | None:
    """The unlock profile bound to this session, if any."""
    ctx = context.fastmcp_context
    sid = ctx.session_id if ctx else None
    if not sid:
        return None
    name = _unlocked_sessions.get(sid)
    if not name:
        return None
    for p in _UNLOCK_PROFILES:
        if p.name == name:
            return p
    return None


def _policy_for(context: MiddlewareContext) -> TokenPolicy | None:
    """Recover the policy bound to this request.

    Two sources, in order:
      1. The per-session map populated by the HTTP middleware, keyed on the
         Mcp-Session-Id header. Works for every message after initialize.
      2. request.scope[_SCOPE_POLICY_KEY], for code paths (e.g. the initialize
         request itself) where FastMCP is still running in the original HTTP
         request task and get_http_request() returns the live Starlette request.
    """
    sid = None
    ctx = context.fastmcp_context
    if ctx is not None:
        try:
            sid = ctx.session_id
        except Exception:
            sid = None
    if sid:
        pol = _session_policy.get(sid)
        if pol is not None:
            return pol
    try:
        req = get_http_request()
    except Exception:
        return None
    return req.scope.get(_SCOPE_POLICY_KEY)


async def tool_policy_middleware(
    context: MiddlewareContext,
    call_next: Callable[[MiddlewareContext], Awaitable],
):
    """FastMCP middleware: enforce per-token tool allowlist.

    When the request was authenticated via a static-token or OAuth policy,
    filter tools/list and gate tools/call against the policy's glob patterns.
    Local no-auth traffic (mcp-local) leaves no policy bound and passes
    through unchanged. Authenticated callers always have a policy because
    the HTTP middleware denies OAuth tokens without a matching policy.
    """
    policy = _policy_for(context)
    if policy is None:
        return await call_next(context)

    profile = _profile_for(context)

    if context.method == "tools/list":
        tools = await call_next(context)
        return [t for t in tools if tool_allowed(policy, t.name, profile)]

    if context.method == "tools/call":
        tool_name = getattr(context.message, "name", "") or ""
        if not tool_allowed(policy, tool_name, profile):
            log.warning(
                "Token %r blocked from calling tool %r", policy.name, tool_name,
            )
            try:
                req = get_http_request()
                ip = _client_ip(req) if req else None
            except Exception:
                ip = None
            log_access(
                "tool_deny",
                actor_name=policy.name, client_ip=ip,
                tool_name=tool_name, profile=profile.name if profile else None,
            )
            scope_hint = ""
            if profile is not None:
                scope_hint = (
                    f" (session unlocked with profile {profile.name!r}; "
                    f"tools must satisfy both the policy and the profile)"
                )
            raise ToolError(
                f"AUTH: tool {tool_name!r} is not permitted for token "
                f"{policy.name!r}{scope_hint}.",
            )

    return await call_next(context)


def create_server() -> FastMCP:
    """Create the gateway server with remote backends mounted as proxies."""
    gw = FastMCP(name="mcp-gateway")

    # Bearer token auth at HTTP level — returns bare 403, hides MCP identity
    if _POLICIES:
        log.warning("Bearer token middleware enabled (%d policies)", len(_POLICIES))

    # Register gateway-key middleware whenever any unlock mechanism is
    # configured (DB-backed profiles take precedence; legacy single key is
    # the fallback for boot-without-DB scenarios).
    if _UNLOCK_PROFILES or _GATEWAY_KEY:
        gw.add_middleware(gateway_key_middleware)
        log.warning(
            "Gateway key middleware enabled (%d profile(s)%s)",
            len(_UNLOCK_PROFILES), ", legacy key" if _GATEWAY_KEY else "",
        )

    # Per-token tool filtering (only active when a policy matched at HTTP layer)
    if _POLICIES:
        gw.add_middleware(tool_policy_middleware)

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

        @gw.tool(name="host_tools_list")
        async def host_list() -> str:
            """List all available hosts that can be targeted with host_exec."""
            return await _nas_call("/api/tools/list_hosts")

        @gw.tool(name="host_tools_commands")
        async def host_commands(host: str | None = None) -> str:
            """List all available commands on a host.

            Args:
                host: Target host name from host_list. Defaults to the local host.
            """
            return await _nas_call("/api/tools/list_commands", {"host": host})

        @gw.tool(name="host_tools_exec")
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

        @gw.tool(name="host_tools_suggest")
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

        @gw.tool(name="host_tools_suggestions_pending")
        async def suggestions_pending(host: str | None = None) -> str:
            """Show pending command suggestions awaiting approval. Check this before suggesting to avoid duplicates.

            Args:
                host: Filter by host name. Omit to see all hosts.
            """
            return await _nas_call("/api/tools/suggestions_pending", {"host": host})

        @gw.tool(name="host_tools_suggestions_recent")
        async def suggestions_recent(count: int = 10, host: str | None = None) -> str:
            """Show recently approved/rejected suggestions. Use to confirm a suggestion landed correctly.

            Args:
                count: Number of recent items to show (default 10)
                host: Filter by host name. Omit to see all hosts.
            """
            return await _nas_call("/api/tools/suggestions_recent", {"count": count, "host": host})

    # Session unlock tool — gates tool calls behind a profile-bound key.
    # Backwards-compatible: callers that pass only `key` get profile="default".
    # The "default" profile is seeded with `tools_glob: ['*']` so legacy
    # behaviour is unchanged. Supplying a different profile narrows the session
    # to the intersection of the matched policy's tools and the profile's tools.
    @gw.tool(name="gateway_unlock")
    async def gateway_unlock(key: str, ctx: Context, profile: str = "default") -> str:
        """Unlock this session to allow tool calls. Must be called before using any other tool.

        Args:
            key: The unlock key for the chosen profile.
            profile: Profile name (default 'default'). Profiles narrow the
                session's tool scope to the intersection of the matched
                policy and the profile's own tools_glob.
        """
        # Pull client_ip if available so the access log can correlate.
        try:
            req = get_http_request()
            ip = _client_ip(req) if req else None
        except Exception:
            ip = None

        # 1) DB-backed profiles take precedence.
        if _UNLOCK_PROFILES:
            p = match_unlock_profile(_UNLOCK_PROFILES, profile, key)
            if p is None:
                log.warning("gateway_unlock failed — wrong profile/key (profile=%r)", profile)
                log_access("unlock_fail", client_ip=ip, profile=profile)
                raise ToolError(
                    f"AUTH: invalid key for unlock profile {profile!r}. "
                    "Check the profile name and key in mcp-admin.",
                )
            sid = ctx.session_id if ctx else None
            if not sid:
                raise ToolError("AUTH: no session ID — gateway_unlock cannot bind a session.")
            _unlocked_sessions[sid] = p.name
            log.info("Session %s unlocked for profile %r", sid[:8], p.name)
            log_access("unlock_success", client_ip=ip, profile=p.name)
            return f"Session unlocked for profile '{p.name}'. You may now use all tools permitted by your policy and this profile."

        # 2) Fallback: legacy single-global-key (YAML-only deployments).
        if _GATEWAY_KEY:
            if key != _GATEWAY_KEY:
                log.warning("gateway_unlock failed — wrong key (legacy mode)")
                raise ToolError("AUTH: invalid gateway key.")
            sid = ctx.session_id if ctx else None
            if not sid:
                raise ToolError("AUTH: no session ID — gateway_unlock cannot bind a session.")
            _unlocked_sessions[sid] = "default"
            log.info("Session %s unlocked (legacy global key)", sid[:8])
            return "Session unlocked. You may now use all tools."

        raise ToolError("AUTH: no unlock mechanism configured on this gateway.")

    @gw.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> JSONResponse:
        tools = await gw.list_tools()
        return JSONResponse({
            "status": "ok",
            "tools": len(tools),
        })

    # mcp-admin reads this to populate its Tools page. Bearer-protected with
    # the same MCP_RELOAD_TOKEN as /admin/reload.
    @gw.custom_route("/admin/tools", methods=["GET"])
    async def admin_tools(request: Request) -> JSONResponse:
        if not _RELOAD_TOKEN:
            return JSONResponse({"error": "admin endpoints disabled"}, status_code=503)
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != _RELOAD_TOKEN:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        tools = await gw.list_tools()
        out = sorted([
            {
                "name": t.name,
                "description": (t.description or "").splitlines()[0][:200] if t.description else "",
            }
            for t in tools
        ], key=lambda d: d["name"])
        return JSONResponse({"tools": out, "count": len(out)})

    # mcp-admin POSTs here after every mutation so policies refresh without
    # a full process restart. Bearer-protected with MCP_RELOAD_TOKEN (a
    # podman secret shared between gateway and admin app).
    @gw.custom_route("/admin/reload", methods=["POST"])
    async def admin_reload(request: Request) -> JSONResponse:
        if not _RELOAD_TOKEN:
            return JSONResponse({"error": "reload disabled (MCP_RELOAD_TOKEN unset)"}, status_code=503)
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != _RELOAD_TOKEN:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        global _POLICIES, _UNLOCK_PROFILES
        try:
            new_policies, new_profiles = _initial_load()
        except Exception as e:
            log.exception("Reload failed")
            return JSONResponse({"error": str(e)}, status_code=500)
        _POLICIES = new_policies
        _UNLOCK_PROFILES = new_profiles
        clear_bearer_cache()
        log.warning(
            "Reloaded policy via /admin/reload: %d policies, %d profiles",
            len(_POLICIES), len(_UNLOCK_PROFILES),
        )
        return JSONResponse({
            "ok": True,
            "policies": len(_POLICIES),
            "unlock_profiles": len(_UNLOCK_PROFILES),
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
        if _POLICIES or _INTROSPECTION_URL:
            app = gateway.http_app(json_response=json_response)
            app.add_middleware(BearerTokenMiddleware)
            import uvicorn
            uvicorn.run(app, host=host, port=port)
        else:
            gateway.run(transport="streamable-http", host=host, port=port, json_response=json_response)
