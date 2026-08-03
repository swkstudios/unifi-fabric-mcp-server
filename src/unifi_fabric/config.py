"""Configuration for UniFi Fabric MCP Server."""

from __future__ import annotations

import os
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode


class APIKeyConfig(BaseSettings):
    """Configuration for a single UniFi Site Manager API key."""

    key: str
    label: str = "default"
    is_org_key: bool = Field(
        default=False,
        description="Organization keys cover all sites under the org. "
        "Personal keys only access consoles owned by the key holder.",
    )

    def __repr__(self) -> str:
        return f"APIKeyConfig(label={self.label!r}, key='***', is_org_key={self.is_org_key!r})"


def _resolved_fastmcp_transport() -> str:
    """Resolve the effective FastMCP transport (the ``FASTMCP_*`` namespace).

    The auth/TLS selectors live in the ``MCP_*`` namespace; the transport lives in
    the ``FASTMCP_*`` namespace. These two namespaces must be reconciled explicitly.
    The live ``FASTMCP_TRANSPORT`` env var is read first so runtime and
    test overrides are honoured, falling back to ``fastmcp.settings.transport`` and
    finally the documented ``"stdio"`` default.
    """
    env_val = os.environ.get("FASTMCP_TRANSPORT")
    if env_val:
        return env_val.strip().lower()
    try:
        from fastmcp import settings as _fastmcp_settings
    except Exception:
        # FastMCP not importable — fall back to the documented default.
        return "stdio"
    transport = getattr(_fastmcp_settings, "transport", None)
    return str(transport).strip().lower() if transport else "stdio"


class MCPTransportSettings(BaseSettings):
    """Transport-layer auth + TLS selectors (env_prefix ``MCP_``).

    Defines the auth (``auth_mode``) and TLS (``tls_mode``) selector matrix for the
    HTTP transports. All validation is **fail-closed**: an incomplete or
    inconsistent selector combination raises at construction rather than silently
    degrading to an insecure default.

    Backward compatibility / deprecation note:
        ``bearer_token`` (``MCP_BEARER_TOKEN``) predates the ``auth_mode`` selector.
        When ``auth_mode`` is left unset (``MCP_AUTH_MODE`` absent) it is resolved
        automatically: a non-empty ``bearer_token`` resolves to ``"bearer"`` (the
        legacy behaviour) and an empty one resolves to ``"none"``. Setting
        ``MCP_AUTH_MODE`` explicitly is preferred going forward; the implicit
        bearer resolution is retained for compatibility and is **not** removed in
        this release.

    Security invariant (fail-closed):
        Auth and TLS apply to HTTP transports only. If the resolved FastMCP
        transport (``FASTMCP_TRANSPORT`` / ``fastmcp.settings.transport``) is
        ``stdio`` while ``auth_mode`` or ``tls_mode`` is anything other than
        ``"none"``, construction raises — silently ignoring auth/TLS on stdio is a
        security footgun.
    """

    model_config = {"env_prefix": "MCP_"}

    bearer_token: str = Field(
        default="",
        description="Optional shared secret for bearer-token auth on HTTP transport. "
        "When set, all incoming MCP requests must include 'Authorization: Bearer <token>'. "
        "When empty (default), the server runs without transport auth. "
        "Deprecated in favour of the explicit MCP_AUTH_MODE selector, but still honoured.",
    )

    # --- Auth selector -------------------------------------------------------
    auth_mode: Literal["none", "bearer", "oauth"] | None = Field(
        default=None,
        description="Auth mode selector (MCP_AUTH_MODE): one of 'none', 'bearer', 'oauth'. "
        "Unset resolves from bearer_token for backward compatibility.",
    )
    oauth_issuer: str = Field(
        default="",
        description="OAuth 2.0 issuer URL (MCP_OAUTH_ISSUER). Required when auth_mode='oauth'.",
    )
    oauth_jwks_uri: str = Field(
        default="",
        description="OAuth JWKS URI for signature verification (MCP_OAUTH_JWKS_URI). "
        "Required when auth_mode='oauth'.",
    )
    oauth_audience: str = Field(
        default="",
        description="Expected token audience (MCP_OAUTH_AUDIENCE). "
        "Required when auth_mode='oauth'.",
    )
    oauth_required_scopes: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="Comma-separated list of scopes a token must carry "
        "(MCP_OAUTH_REQUIRED_SCOPES).",
    )
    oauth_algorithm: str = Field(
        default="RS256",
        description="JWT signing algorithm to accept (MCP_OAUTH_ALGORITHM).",
    )
    oauth_base_url: str = Field(
        default="",
        description="Public base URL of this resource server (MCP_OAUTH_BASE_URL). "
        "Required when auth_mode='oauth'.",
    )
    oauth_authorization_servers: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="Comma-separated authorization-server URLs "
        "(MCP_OAUTH_AUTHORIZATION_SERVERS). Defaults to [oauth_issuer] when unset.",
    )

    # --- TLS selector --------------------------------------------------------
    tls_mode: Literal["none", "https", "mtls"] = Field(
        default="none",
        description="TLS mode selector (MCP_TLS_MODE): one of 'none', 'https', 'mtls'.",
    )
    tls_certfile: str = Field(
        default="",
        description="Path to the server certificate (MCP_TLS_CERTFILE). "
        "Required when tls_mode is 'https' or 'mtls'.",
    )
    tls_keyfile: str = Field(
        default="",
        description="Path to the server private key (MCP_TLS_KEYFILE). "
        "Required when tls_mode is 'https' or 'mtls'.",
    )
    tls_ca_certs: str = Field(
        default="",
        description="Path to the client CA bundle used to verify client certificates "
        "(MCP_TLS_CA_CERTS). Required when tls_mode='mtls'.",
    )
    tls_key_password: str = Field(
        default="",
        description="Password for an encrypted private key (MCP_TLS_KEY_PASSWORD). Optional.",
    )
    tls_cert_reqs: Literal["none", "optional", "required"] | None = Field(
        default=None,
        description="Client-certificate verification level for mTLS (MCP_TLS_CERT_REQS): "
        "one of 'none', 'optional', 'required'.",
    )

    # --- Field-level normalisation / enum guards -----------------------------
    @field_validator("oauth_required_scopes", "oauth_authorization_servers", mode="before")
    @classmethod
    def _split_csv(cls, v: object) -> object:
        """Parse a comma-separated env string into a list (JSON decoding disabled)."""
        if v is None or v == "":
            return []
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @field_validator("auth_mode", mode="before")
    @classmethod
    def _validate_auth_mode(cls, v: object) -> object:
        if v is None or v == "":
            return None
        valid = ("none", "bearer", "oauth")
        if v not in valid:
            raise ValueError(f"MCP_AUTH_MODE must be one of {', '.join(valid)} (got {v!r})")
        return v

    @field_validator("tls_mode", mode="before")
    @classmethod
    def _validate_tls_mode(cls, v: object) -> object:
        if v is None or v == "":
            return "none"
        valid = ("none", "https", "mtls")
        if v not in valid:
            raise ValueError(f"MCP_TLS_MODE must be one of {', '.join(valid)} (got {v!r})")
        return v

    @field_validator("tls_cert_reqs", mode="before")
    @classmethod
    def _validate_cert_reqs(cls, v: object) -> object:
        if v is None or v == "":
            return None
        valid = ("none", "optional", "required")
        if v not in valid:
            raise ValueError(f"MCP_TLS_CERT_REQS must be one of {', '.join(valid)} (got {v!r})")
        return v

    # --- Cross-field, fail-closed resolution + reconciliation ----------------
    @model_validator(mode="after")
    def _resolve_and_validate(self) -> MCPTransportSettings:
        # Backward-compat: resolve an unset auth_mode from the legacy bearer_token.
        if self.auth_mode is None:
            self.auth_mode = "bearer" if self.bearer_token else "none"

        # Bearer requires a non-empty shared secret (fail-closed: an empty token
        # would build a verifier whose only valid credential is the empty string).
        if self.auth_mode == "bearer" and not self.bearer_token:
            raise ValueError(
                "auth_mode='bearer' requires a non-empty MCP_BEARER_TOKEN shared secret"
            )

        # OAuth requires a complete resource-server descriptor (fail-closed).
        if self.auth_mode == "oauth":
            required = {
                "MCP_OAUTH_ISSUER": self.oauth_issuer,
                "MCP_OAUTH_JWKS_URI": self.oauth_jwks_uri,
                "MCP_OAUTH_AUDIENCE": self.oauth_audience,
                "MCP_OAUTH_BASE_URL": self.oauth_base_url,
            }
            missing = [name for name, value in required.items() if not value]
            if missing:
                raise ValueError(
                    "auth_mode='oauth' requires "
                    + ", ".join(required)
                    + "; missing: "
                    + ", ".join(missing)
                )
            # Default the advertised authorization servers to the issuer.
            if not self.oauth_authorization_servers:
                self.oauth_authorization_servers = [self.oauth_issuer]

        # HTTPS/mTLS require a server cert + key; mTLS additionally a client CA.
        if self.tls_mode in ("https", "mtls"):
            missing = [
                name
                for name, value in (
                    ("MCP_TLS_CERTFILE", self.tls_certfile),
                    ("MCP_TLS_KEYFILE", self.tls_keyfile),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    f"tls_mode={self.tls_mode!r} requires MCP_TLS_CERTFILE and "
                    f"MCP_TLS_KEYFILE; missing: {', '.join(missing)}"
                )
        if self.tls_mode == "mtls":
            if not self.tls_ca_certs:
                raise ValueError(
                    "tls_mode='mtls' requires MCP_TLS_CA_CERTS (client CA bundle for "
                    "verifying client certificates)"
                )
            # Fail-closed: mTLS exists to verify client certs. Allowing
            # tls_cert_reqs='none' would silently turn the client-cert check off
            # while still advertising mTLS, so reject the combination outright.
            # (Unset defaults to CERT_REQUIRED in build_uvicorn_config.)
            if self.tls_cert_reqs == "none":
                raise ValueError(
                    "tls_mode='mtls' is incompatible with MCP_TLS_CERT_REQS='none' — "
                    "mTLS must verify client certificates; use 'optional' or 'required'"
                )

        # fail-closed: auth/TLS are HTTP-only. Reconcile the MCP_* selectors with the
        # FASTMCP_* transport namespace and fail closed on the stdio footgun.
        transport = _resolved_fastmcp_transport()
        if transport == "stdio" and (self.auth_mode != "none" or self.tls_mode != "none"):
            raise ValueError(
                "FastMCP transport is 'stdio' but "
                f"auth_mode={self.auth_mode!r} / tls_mode={self.tls_mode!r} are set. "
                "Auth and TLS apply to HTTP transports only — set "
                "FASTMCP_TRANSPORT=streamable-http (or sse), or clear "
                "MCP_AUTH_MODE/MCP_BEARER_TOKEN and MCP_TLS_MODE."
            )
        return self


class Settings(BaseSettings):
    """Top-level settings loaded from environment variables."""

    model_config = {"env_prefix": "UNIFI_", "env_nested_delimiter": "__"}

    api_base_url: str = Field(
        default="https://api.ui.com",
        description="UniFi Site Manager API base URL.",
    )
    api_keys: list[APIKeyConfig] = Field(
        default_factory=list,
        description="List of API key configs. Set via UNIFI_API_KEY for single key.",
    )
    api_key: str = Field(
        default="",
        description="Single API key shorthand. Used when api_keys is empty.",
    )
    cache_ttl_seconds: int = Field(
        default=900,
        description="TTL for host/site registry cache (default 15 min).",
    )
    cache_max_hosts: int = Field(
        default=512,
        description="Max entries in the hosts TTLCache (default 512).",
    )
    cache_max_sites: int = Field(
        default=2048,
        description="Max entries in the sites TTLCache (default 2048).",
    )
    max_concurrency: int = Field(
        default=10,
        description="Max concurrent requests for cross-site aggregation.",
    )
    request_timeout_seconds: int = Field(
        default=30,
        description="HTTP request timeout in seconds for UniFi API calls.",
    )
    paginate_max_pages: int | None = Field(
        default=None,
        description="Hard cap on pagination page count (defense-in-depth backstop). "
        "Unset by default — stall detection is the primary safeguard. "
        "Set UNIFI_PAGINATE_MAX_PAGES to a generous number (e.g. 100000) if desired.",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level for the server. Accepts standard Python logging levels: "
        "DEBUG, INFO, WARNING, ERROR, CRITICAL. Logs go to stderr only — no file handlers. "
        "Request/response bodies are never logged.",
    )

    def get_key_configs(self) -> list[APIKeyConfig]:
        """Return resolved list of API key configs."""
        if self.api_keys:
            return self.api_keys
        if self.api_key:
            return [APIKeyConfig(key=self.api_key, label="default")]
        return []
