"""Token policy + unlock-profile loader.

Policy entries can come from either:

1. **`tokens.yaml`** (legacy) — hand-edited file holding per-caller policies.
   Static-bearer tokens are resolved from podman-secret-backed env vars at
   load time. This path is preserved as a fallback for boot scenarios where
   the admin database is unreachable.

2. **The `mcp_admin` Postgres database** (preferred) — populated by the
   `mcp-admin` UI. Token / unlock-key cleartext is never stored, only argon2
   hashes (peppered with `MCP_TOKEN_PEPPER`). The admin app POSTs to
   `/admin/reload` to make the gateway re-fetch on every change.

`load_policies(...)` picks DB if `MCP_DB_DSN` is set, otherwise YAML.
"""

from __future__ import annotations

import fnmatch
import hmac
import ipaddress
import logging
import os
import socket
from dataclasses import dataclass, field

import psycopg2
import yaml
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

log = logging.getLogger(__name__)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class TokenPolicy:
    name: str
    tool_patterns: list[str]
    # Static-bearer entries set exactly one of `token` (cleartext, YAML legacy)
    # or `token_hash` (argon2, DB-backed). OAuth-subject entries leave both
    # empty and populate one or more of oauth_sub / oauth_email / oauth_username.
    token: str = ""
    token_hash: str = ""
    ip_networks: list[IPNetwork] = field(default_factory=list)
    oauth_sub: list[str] = field(default_factory=list)
    oauth_email: list[str] = field(default_factory=list)
    oauth_username: list[str] = field(default_factory=list)
    # Per-host scope for host-aware tools (host_tools_*, logs_*).
    # Empty list = deny; ['*'] = allow any host; otherwise the exact set.
    host_allowlist: list[str] = field(default_factory=list)


@dataclass
class UnlockProfile:
    name: str
    key_hash: str
    tool_patterns: list[str]
    host_allowlist: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

_pepper = os.environ.get("MCP_TOKEN_PEPPER", "")
_hasher = PasswordHasher()


def _verify(hashed: str, presented: str) -> bool:
    try:
        return _hasher.verify(hashed, _pepper + presented)
    except VerifyMismatchError:
        return False
    except Exception:
        log.exception("argon2 verify failed unexpectedly")
        return False


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def _dsn_from_env() -> str:
    """Assemble a libpq DSN from MCP_DB_* env vars. Empty if MCP_DB_HOST unset."""
    dsn = os.environ.get("MCP_DB_DSN", "")
    if dsn:
        return dsn
    host = os.environ.get("MCP_DB_HOST", "")
    if not host:
        return ""
    return (
        f"host={host} "
        f"port={os.environ.get('MCP_DB_PORT', '5432')} "
        f"dbname={os.environ.get('MCP_DB_NAME', 'mcp_admin')} "
        f"user={os.environ.get('MCP_DB_USER', 'mcp_admin')} "
        f"password={os.environ.get('MCP_DB_PASSWORD', '')} "
        f"sslmode={os.environ.get('MCP_DB_SSLMODE', 'prefer')}"
    )


def load_policies(yaml_path: str | None = None) -> tuple[list[TokenPolicy], list[UnlockProfile]]:
    """Pick DB if MCP_DB_HOST is set, else YAML. On DB failure fall back to YAML
    so a momentarily-unreachable Postgres doesn't lock everyone out at boot."""
    dsn = _dsn_from_env()
    if dsn:
        try:
            return _load_from_db(dsn)
        except Exception:
            log.exception("DB load failed; falling back to YAML")
    if yaml_path:
        return _load_from_yaml(yaml_path), []
    return [], []


def _load_from_db(dsn: str) -> tuple[list[TokenPolicy], list[UnlockProfile]]:
    policies: list[TokenPolicy] = []
    profiles: list[UnlockProfile] = []
    # connect_timeout keeps boot fast if Postgres is unreachable.
    with psycopg2.connect(dsn + " connect_timeout=5") as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT name, token_hash, tools_glob, ip_allowlist, host_allowlist "
            "  FROM static_tokens WHERE revoked_at IS NULL"
        )
        for name, token_hash, tools, ips, hosts in cur.fetchall():
            policies.append(TokenPolicy(
                name=name,
                token_hash=token_hash,
                tool_patterns=list(tools or []),
                ip_networks=[ipaddress.ip_network(str(c), strict=False) for c in (ips or [])],
                host_allowlist=list(hosts or []),
            ))

        cur.execute(
            "SELECT name, oauth_sub, oauth_email, oauth_username, tools_glob, ip_allowlist, host_allowlist "
            "  FROM oauth_policies WHERE revoked_at IS NULL"
        )
        for name, subs, emails, usernames, tools, ips, hosts in cur.fetchall():
            policies.append(TokenPolicy(
                name=name,
                tool_patterns=list(tools or []),
                ip_networks=[ipaddress.ip_network(str(c), strict=False) for c in (ips or [])],
                oauth_sub=list(subs or []),
                oauth_email=list(emails or []),
                oauth_username=list(usernames or []),
                host_allowlist=list(hosts or []),
            ))

        cur.execute(
            "SELECT name, key_hash, tools_glob, host_allowlist "
            "  FROM unlock_profiles WHERE revoked_at IS NULL"
        )
        for name, key_hash, tools, hosts in cur.fetchall():
            profiles.append(UnlockProfile(
                name=name,
                key_hash=key_hash,
                tool_patterns=list(tools or []),
                host_allowlist=list(hosts or []),
            ))

    log.warning("Loaded %d policies and %d unlock profiles from DB", len(policies), len(profiles))
    return policies, profiles


def _load_from_yaml(path: str) -> list[TokenPolicy]:
    """Legacy YAML loader. Kept for boot fallback when DB is unreachable."""
    with open(path) as f:
        raw = yaml.safe_load(f) or {}
    entries = raw.get("tokens") or []
    if not isinstance(entries, list):
        raise ValueError(f"{path}: 'tokens' must be a list")

    policies: list[TokenPolicy] = []
    for i, entry in enumerate(entries):
        name = entry.get("name") or f"token[{i}]"

        tools = entry.get("tools") or []
        if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
            raise ValueError(f"{path}: policy {name!r} 'tools' must be a list of strings")

        ip_entries = entry.get("ip_allowlist") or []
        ip_networks = [ipaddress.ip_network(s, strict=False) for s in ip_entries]

        host_allowlist = entry.get("host_allowlist") or []
        if not isinstance(host_allowlist, list) or not all(isinstance(h, str) for h in host_allowlist):
            raise ValueError(f"{path}: policy {name!r} 'host_allowlist' must be a list of strings")

        def _listify(key: str) -> list[str]:
            v = entry.get(key)
            if v is None:
                return []
            if isinstance(v, str):
                return [v]
            if isinstance(v, list):
                return list(v)
            return []

        oauth_sub = _listify("oauth_sub")
        oauth_email = _listify("oauth_email")
        oauth_username = _listify("oauth_username")

        token = ""
        env_var = entry.get("token_env")
        if env_var:
            token = os.environ.get(env_var, "")
            if not token:
                log.warning("Token policy %r skipped — env var %s is not set", name, env_var)
                continue

        if not token and not (oauth_sub or oauth_email or oauth_username):
            raise ValueError(f"{path}: policy {name!r} has no auth method")

        policies.append(TokenPolicy(
            name=name,
            token=token,
            tool_patterns=list(tools),
            ip_networks=ip_networks,
            oauth_sub=oauth_sub,
            oauth_email=oauth_email,
            oauth_username=oauth_username,
            host_allowlist=list(host_allowlist),
        ))

    log.warning("Loaded %d policies from %s (YAML fallback)", len(policies), path)
    return policies


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

# bearer cleartext -> policy name. Populated on first match; cleared on reload.
# Avoids re-running argon2 on every request once the bearer is known.
_bearer_cache: dict[str, str] = {}


def clear_bearer_cache() -> None:
    _bearer_cache.clear()


def match_token(policies: list[TokenPolicy], presented: str) -> TokenPolicy | None:
    """Match a presented bearer against the policy list.

    Tries the in-memory cache first; on miss, walks the policies and verifies
    each one's hash (DB-backed) or compares cleartext (YAML legacy).
    """
    if not presented:
        return None

    cached_name = _bearer_cache.get(presented)
    if cached_name is not None:
        for p in policies:
            if p.name == cached_name:
                return p
        # Cache stale — drop and fall through.
        _bearer_cache.pop(presented, None)

    for p in policies:
        if p.token_hash:
            if _verify(p.token_hash, presented):
                _bearer_cache[presented] = p.name
                return p
        elif p.token:
            if hmac.compare_digest(p.token, presented):
                _bearer_cache[presented] = p.name
                return p
    return None


def match_oauth(
    policies: list[TokenPolicy],
    sub: str = "",
    email: str = "",
    username: str = "",
) -> TokenPolicy | None:
    """Resolve the policy that best matches the authenticated OAuth subject.

    Returns None when no policy claims this user; the HTTP middleware
    rejects such requests so a valid Keycloak account in the realm is not
    by itself enough to receive any tools.
    """
    sub, email, username = sub or "", (email or "").lower(), username or ""
    for p in policies:
        if sub and sub in p.oauth_sub:
            return p
        if email and email in (e.lower() for e in p.oauth_email):
            return p
        if username and username in p.oauth_username:
            return p
    return None


def match_unlock_profile(
    profiles: list[UnlockProfile], name: str, presented_key: str,
) -> UnlockProfile | None:
    """Verify a presented unlock key against a profile of the given name."""
    if not name or not presented_key:
        return None
    for p in profiles:
        if p.name == name and _verify(p.key_hash, presented_key):
            return p
    return None


def tool_allowed(policy: TokenPolicy, tool_name: str, profile: UnlockProfile | None = None) -> bool:
    """Whether this policy (intersected with profile, if any) grants `tool_name`.

    gateway_unlock is always allowed so locked sessions can present a key.
    """
    if tool_name == "gateway_unlock":
        return True
    if not any(fnmatch.fnmatchcase(tool_name, pat) for pat in policy.tool_patterns):
        return False
    if profile is not None:
        if not any(fnmatch.fnmatchcase(tool_name, pat) for pat in profile.tool_patterns):
            return False
    return True


def ip_allowed(policy: TokenPolicy, client_ip: str) -> bool:
    """Whether a peer IP is covered by the policy's CIDR list. Empty list → allow."""
    if not policy.ip_networks:
        return True
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return any(addr in net for net in policy.ip_networks)


def _host_match(allow: list[str], target: str) -> bool:
    """Empty list = deny. '*' = allow any. Otherwise exact (case-sensitive) match."""
    if not allow:
        return False
    if "*" in allow:
        return True
    return target in allow


def host_allowed(
    policy: TokenPolicy,
    profile: UnlockProfile | None,
    host: str | None,
) -> bool:
    """Whether this policy (intersected with profile, if any) grants `host`.

    A None / empty `host` is resolved to MCP_DEFAULT_HOST (or
    socket.gethostname() as a last resort) so the check has a concrete
    target — matches what the host-tools backend does when it gets a
    bare call.
    """
    target = host or os.environ.get("MCP_DEFAULT_HOST") or socket.gethostname()
    if not _host_match(policy.host_allowlist, target):
        return False
    if profile is not None and not _host_match(profile.host_allowlist, target):
        return False
    return True


def filter_hosts(
    policy: TokenPolicy,
    profile: UnlockProfile | None,
    hosts: list[str],
) -> list[str]:
    """Filter a list of hostnames down to those the policy + profile permit.

    Used for response-filtered tools (host_tools_list, logs_hosts) where the
    caller didn't pass a host arg but we need to scrub the response.
    """
    return [h for h in hosts if host_allowed(policy, profile, h)]
