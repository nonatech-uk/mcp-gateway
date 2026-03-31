# mcp-gateway

MCP gateway that proxies to backend MCP servers over HTTP, with OAuth2
authentication via Authelia and session-level access control.

Consumed by Claude via `query.mees.st`.

## Architecture

```
Claude ──► Authelia OAuth2 ──► mcp-gateway ──┬── MCP_BACKENDS (SSE proxies)
                                             ├── NAS host-tools (direct, HTTPS + Bearer)
                                             └── Mac MCP (direct, HTTPS + Bearer)
```

- **MCP_BACKENDS** — generic MCP servers proxied via `fastmcp.create_proxy` (SSE)
- **NAS host-tools** — hand-wired direct tools with TLS + Bearer auth
- **Mac MCP** — auto-discovered Apple tools with TLS + Bearer auth + priority routing

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
| `MCP_AUTH_ENABLED` | `true` | Enable OAuth2 via Authelia |
| `AUTHELIA_URL` | — | Authelia base URL (required if auth enabled) |
| `OIDC_CLIENT_ID` | — | OAuth2 client ID |
| `OIDC_CLIENT_SECRET` | — | OAuth2 client secret |
| `MCP_BASE_URL` | `https://query.mees.st` | OAuth redirect base URL |
| `MCP_GATEWAY_KEY` | — | Session unlock key (if set, all tool calls blocked until `gateway_unlock` called) |

### Generic MCP backends

| Variable | Default | Description |
|---|---|---|
| `MCP_BACKENDS` | — | Comma-separated `name=url` pairs, e.g. `tautulli=http://mcp-tautulli:8080/mcp,paperless=http://mcp-paperless:8080/mcp` |

### NAS host-tools

| Variable | Default | Description |
|---|---|---|
| `NAS_HOST_TOOLS_URL` | — | Base URL, e.g. `https://10.10.0.1:8092/api` |
| `NAS_HOST_TOOLS_API_KEY` | — | Bearer token for NAS auth |
| `SSL_CA_CERTFILE` | — | CA certificate for verifying internal TLS (shared by NAS + Mac backends) |

### Mac MCP backends

| Variable | Default | Description |
|---|---|---|
| `MAC_MCP_BACKENDS` | — | Comma-separated `name=url` pairs, e.g. `mac-studio=https://10.10.0.3:3456,mac-notebook=https://10.10.0.4:3456` |
| `MAC_MCP_API_KEY` | — | Shared Bearer token for Mac MCP auth |

At startup the gateway calls `GET /tools` on the first reachable Mac backend to
discover all available tools (Reminders, Calendar, Contacts, Messages, Notes,
Shell, Clipboard, Notifications, System, Spotify, Plex, Browser). At call time
it probes `GET /health` on all backends and routes to the highest-priority
reachable host (Studio=10, Notebook=5).

Both Mac and NAS backends verify TLS using `SSL_CA_CERTFILE`.

## Build & run

```bash
# Container
podman build -t mcp-gateway -f Containerfile .
podman run -p 8080:8080 --env-file .env mcp-gateway

# Local dev
uv pip install -e .
python -m mcp_gateway.server
```
