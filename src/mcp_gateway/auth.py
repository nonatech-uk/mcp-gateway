"""Authelia OAuth2 token introspection for MCP gateway."""

import os

from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.introspection import IntrospectionTokenVerifier
from pydantic import AnyHttpUrl


def create_auth() -> RemoteAuthProvider:
    """Create auth provider using Authelia's RFC 7662 introspection endpoint."""
    authelia_url = os.environ["AUTHELIA_URL"]

    verifier = IntrospectionTokenVerifier(
        introspection_url=f"{authelia_url}/api/oidc/introspection",
        client_id=os.environ["OIDC_CLIENT_ID"],
        client_secret=os.environ["OIDC_CLIENT_SECRET"],
    )

    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[AnyHttpUrl(authelia_url)],
        base_url=os.environ.get("MCP_BASE_URL", "https://query.mees.st"),
    )
