"""Token policy loader for multi-token auth.

Each policy binds a static bearer token to a set of allowed tools (glob
patterns) and an optional IP allowlist (CIDR ranges). Policies are loaded
at startup from a YAML file; the token value itself lives in an env var
(typically backed by a podman secret) referenced by `token_env`.
"""

from __future__ import annotations

import fnmatch
import hmac
import ipaddress
import logging
import os
from dataclasses import dataclass, field

import yaml

log = logging.getLogger(__name__)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class TokenPolicy:
    name: str
    token: str
    tool_patterns: list[str]
    ip_networks: list[IPNetwork] = field(default_factory=list)


def load_policies(path: str) -> list[TokenPolicy]:
    """Parse the tokens YAML and resolve each entry's token_env to a live value.

    Entries whose token_env is unset in the environment are skipped with a
    warning — this lets the file list every known policy even when a given
    secret isn't provisioned yet.
    """
    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    entries = raw.get("tokens") or []
    if not isinstance(entries, list):
        raise ValueError(f"{path}: 'tokens' must be a list")

    policies: list[TokenPolicy] = []
    for i, entry in enumerate(entries):
        name = entry.get("name") or f"token[{i}]"
        env_var = entry.get("token_env")
        if not env_var:
            raise ValueError(f"{path}: policy {name!r} missing token_env")
        token = os.environ.get(env_var, "")
        if not token:
            log.warning("Token policy %r skipped — env var %s is not set", name, env_var)
            continue

        tools = entry.get("tools") or []
        if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
            raise ValueError(f"{path}: policy {name!r} 'tools' must be a list of strings")

        ip_entries = entry.get("ip_allowlist") or []
        if not isinstance(ip_entries, list):
            raise ValueError(f"{path}: policy {name!r} 'ip_allowlist' must be a list")
        ip_networks = [ipaddress.ip_network(s, strict=False) for s in ip_entries]

        policies.append(TokenPolicy(
            name=name,
            token=token,
            tool_patterns=list(tools),
            ip_networks=ip_networks,
        ))

    log.warning("Loaded %d token policies from %s", len(policies), path)
    return policies


def match_token(policies: list[TokenPolicy], presented: str) -> TokenPolicy | None:
    """Constant-time lookup of the policy whose token matches `presented`."""
    if not presented:
        return None
    for p in policies:
        if hmac.compare_digest(p.token, presented):
            return p
    return None


def tool_allowed(policy: TokenPolicy, tool_name: str) -> bool:
    """Whether this policy grants access to a given fully-qualified tool name.

    gateway_unlock is always allowed so clients can unlock the session gate
    regardless of their policy's tool patterns.
    """
    if tool_name == "gateway_unlock":
        return True
    return any(fnmatch.fnmatchcase(tool_name, pat) for pat in policy.tool_patterns)


def ip_allowed(policy: TokenPolicy, client_ip: str) -> bool:
    """Whether a peer IP is covered by the policy's CIDR list. Empty list → allow."""
    if not policy.ip_networks:
        return True
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return any(addr in net for net in policy.ip_networks)
