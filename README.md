# mcp-gateway

MCP gateway that proxies to backend MCP servers over HTTP. Two concurrent auth
paths: a static bearer token for trusted local callers (Claude Code CLI) and
OAuth 2.1 + introspection for remote clients (claude.ai web, Claude Desktop).

Consumed by Claude via `query.mees.st`.

## Architecture

```
Claude Code CLI                claude.ai web / Claude Desktop
      │                                     │
      │ URL ?token=<static>                 │ OAuth 2.1 + DCR → Bearer
      │                                     │
      ▼                                     ▼
             Cloudflare Tunnel
                    │
                    ▼
          Traefik (anthropic-only IP allowlist on /mcp)
                    │
                    ▼
         mcp-gateway  ── MCP_BACKENDS (streamable-http proxies)
              │      ── MAC_MCP_BACKENDS (TLS + API key over WireGuard)
              │      ── NAS host-tools (direct, HTTPS + Bearer)
              │
              └── validates tokens:
                  1. static MCP_BEARER_TOKEN match → 200 (CLI fast-path)
                  2. else RFC 7662 introspection at
                     https://kc.mees.st/realms/mees/.../introspect
                     → accept iff active + scope "mcp" + aud matches
                     this resource URL. 60s in-process cache.
```

## Auth

- **Static bearer token** (`MCP_BEARER_TOKEN`) — the Claude Code CLI path, presented as `?token=…` or `Authorization: Bearer …`. Skips introspection, fast. Not suitable for claude.ai web.
- **OAuth 2.1 via Keycloak** (`kc.mees.st/realms/mees`) — claude.ai web / Desktop path. Clients discover the authorization server via the gateway's RFC 9728 `/.well-known/oauth-protected-resource` metadata, DCR a new client, then drive the standard auth-code + PKCE flow. Issued access tokens have `aud` bound to this gateway's URL via a hardcoded-audience scope mapper on the `mcp` scope in Keycloak.
- **401 responses** carry an absolute-URL `WWW-Authenticate` challenge:
  ```
  Bearer realm="MCP", resource_metadata="https://query.mees.st/.well-known/oauth-protected-resource"
  ```
  Anthropic's MCP client silently rejects relative resource_metadata values, so the URL must be absolute.
- **IP allowlist** (`anthropic-only` Traefik middleware) — restricts the `/mcp` path to Anthropic's published IPs + NAS WAN + RFC1918 + loopback. Layered on top of token auth; tokens still required.
- **Session unlock gate** (optional, `MCP_GATEWAY_KEY`) — if set, every session must call the `gateway_unlock` tool with the key before any other tool call.

## Environment variables

### Server

| Variable | Default | Description |
|---|---|---|
| `MCP_TRANSPORT` | `streamable-http` | Transport mode (`streamable-http` or `stdio`) |
| `MCP_HOST` | `0.0.0.0` | Bind address |
| `MCP_PORT` | `8080` | Bind port |
| `MCP_JSON_RESPONSE` | — | If truthy, POST /mcp closes the response stream after the body instead of keeping SSE open. Needed when fronted by Cloudflare Tunnel. |
| `MCP_CORS_ALLOWED_ORIGINS` | `https://claude.ai,https://www.claude.ai` | Comma-separated allowed origins for CORS preflight + Allow-Origin. |

### Auth

| Variable | Default | Description |
|---|---|---|
| `MCP_BEARER_TOKEN` | — | Static bearer token for the CLI fast-path. Presented as `?token=…` or `Authorization: Bearer …`. |
| `MCP_GATEWAY_KEY` | — | Session unlock key for the optional `gateway_unlock` tool gate. |
| `MCP_RESOURCE_URL` | — | Absolute URL of this resource (e.g. `https://query.mees.st/mcp`). Published in RFC 9728 metadata and in `WWW-Authenticate.resource_metadata`. |
| `MCP_AUTHORIZATION_SERVER` | — | Issuer URL clients should discover (e.g. `https://kc.mees.st/realms/mees`). |
| `MCP_INTROSPECTION_URL` | — | RFC 7662 introspection endpoint on the authorization server. |
| `MCP_INTROSPECTION_CLIENT_ID` | — | Service-account client used to authenticate to the introspection endpoint. |
| `MCP_INTROSPECTION_CLIENT_SECRET` | — | …matching secret. |
| `MCP_INTROSPECTION_REQUIRED_SCOPE` | `mcp` | Token must have this scope to pass. |
| `MCP_INTROSPECTION_REQUIRED_AUD` | — | Token `aud` must contain this value. Typically set to `MCP_RESOURCE_URL`. |

### Generic MCP backends

| Variable | Default | Description |
|---|---|---|
| `MCP_BACKENDS` | — | Comma-separated `name=url` pairs, e.g. `tautulli=http://mcp-tautulli:8080/mcp,paperless=http://mcp-paperless:8080/mcp` |
| `MAC_MCP_BACKENDS` | — | As above, but tunnelled to Mac-hosted MCP servers over WireGuard. |
| `MAC_MCP_API_KEY` | — | API key for Mac backends. |
| `MAC_MCP_CA_CERTFILE` | — | CA cert path for verifying Mac TLS. |

### NAS host-tools

| Variable | Default | Description |
|---|---|---|
| `NAS_HOST_TOOLS_URL` | — | Base URL, e.g. `https://172.24.0.1:8092` |
| `NAS_HOST_TOOLS_API_KEY` | — | Bearer token for NAS host-tools auth |
| `SSL_CA_CERTFILE` | — | CA certificate for verifying internal TLS |

## Build & run

```bash
# Container
podman build -t mcp-gateway -f Containerfile .
podman run -p 8080:8080 --env-file .env mcp-gateway

# Local dev
uv pip install -e .
python -m mcp_gateway.server
```

## Endpoints

| Path | Auth | Purpose |
|---|---|---|
| `/mcp` | Required | Streamable-HTTP MCP server |
| `/health` | Public | Liveness + tool count (`{"status":"ok","tools":N}`) |
| `/.well-known/oauth-protected-resource` | Public | RFC 9728 metadata |
| `/.well-known/oauth-protected-resource/mcp` | Public | Same payload, resource-specific path |
