# mcp-gateway

MCP gateway that proxies to backend MCP servers over HTTP. Authentication is
a URL-embedded bearer token, layered with an IP allowlist enforced by Traefik.

Consumed by Claude via `query.mees.st`.

## Architecture

```
Claude ──► Cloudflare ──► Traefik (IP allowlist: Anthropic + LAN/loopback)
                           │
                           └► mcp-gateway (bearer-token middleware) ──┬── MCP_BACKENDS (streamable-http proxies)
                                                                     ├── MAC_MCP_BACKENDS (TLS + API key)
                                                                     └── NAS host-tools (direct, HTTPS + Bearer)
```

- **Bearer token** — required on every request as `?token=…` query param or `Authorization: Bearer …` header. Missing/wrong token → bare `403`.
- **IP allowlist** (`anthropic-only` middleware in Traefik) — restricts `/mcp` path to Anthropic's ranges, NAS WAN IP, and RFC1918/loopback for internal testing. Non-`/mcp` paths are served by the gateway directly (still token-gated).
- **MCP_BACKENDS** — generic MCP servers proxied via `fastmcp.create_proxy` (streamable-http).
- **MAC_MCP_BACKENDS** — Mac MCP servers over WireGuard with custom CA + API key.
- **NAS host-tools** — hand-wired direct tools with TLS + Bearer auth.

> `src/mcp_gateway/auth.py` contains legacy Authelia OIDC introspection code and is currently unused — the initial design delegated to Authelia but that path was dropped in favour of the simpler token+IP approach.

## Environment variables

### Server

| Variable | Default | Description |
|---|---|---|
| `MCP_TRANSPORT` | `streamable-http` | Transport mode (`streamable-http` or `stdio`) |
| `MCP_HOST` | `0.0.0.0` | Bind address |
| `MCP_PORT` | `8080` | Bind port |

### Authentication

| Variable | Default | Description |
|---|---|---|
| `MCP_BEARER_TOKEN` | — | If set, all requests (except `/health`) must present this token as `?token=…` or `Authorization: Bearer …`. Missing/wrong → bare 403. |
| `MCP_GATEWAY_KEY` | — | Session unlock key. If set, tool calls are blocked until `gateway_unlock` is called with this key. |

### Generic MCP backends

| Variable | Default | Description |
|---|---|---|
| `MCP_BACKENDS` | — | Comma-separated `name=url` pairs, e.g. `tautulli=http://mcp-tautulli:8080/mcp,paperless=http://mcp-paperless:8080/mcp` |

### NAS host-tools

| Variable | Default | Description |
|---|---|---|
| `NAS_HOST_TOOLS_URL` | — | Base URL, e.g. `https://10.10.0.1:8092/api` |
| `NAS_HOST_TOOLS_API_KEY` | — | Bearer token for NAS auth |
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
