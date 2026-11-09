"""Configuration for UniFi Fabric MCP Server."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import sys
import unicodedata
from collections.abc import Mapping
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, SecretStr, ValidationInfo, field_validator, model_validator
from pydantic.fields import FieldInfo
from pydantic_core import PydanticUseDefault
from pydantic_settings import (
    BaseSettings,
    EnvSettingsSource,
    NoDecode,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    SettingsError,
)

from .selector_syntax import selector_reason
from .switches import FALSE_VALUES, TRUE_VALUES, parse_bool

_AUDIT_HMAC_KEY_RE = re.compile(r"[A-Za-z0-9_-]{43}")


def whole_number(value: object) -> int | None:
    """``value`` as a whole number, or ``None`` when it is not one.

    A Python ``int`` (never a ``bool``) is taken as is; a string must be ASCII digits
    only once surrounding whitespace is stripped -- no sign, no ``_`` separator, no
    decimal point and no non-ASCII digit (``int()`` accepts ``"1_000"``, ``"+5"`` and
    ``"\u0663"``, which are not how an operator writes a count).
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or not text.isascii() or not text.isdigit():
        return None
    return int(text)


def _negative_whole_number(value: object) -> int | None:
    """``-N`` (ASCII digits) as a negative number, so a below-bound value gets the bound
    message rather than the syntax one; ``None`` otherwise."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value if value < 0 else None
    if isinstance(value, str) and value.strip().startswith("-"):
        magnitude = whole_number(value.strip()[1:])
        return -magnitude if magnitude else None
    return None


def api_base_url_problem(url: str, *, allow_query: bool = False) -> str | None:
    """Why ``url`` cannot be ``UNIFI_API_BASE_URL`` (or another absolute http(s) URL
    setting), or None (the value is never echoed: a URL may carry credentials).
    ``allow_query`` admits a query string (a JWKS URI may carry one)."""
    from urllib.parse import urlsplit

    if not url.isascii() and not _utf8_encodable(url):
        return "is not encodable as UTF-8"
    if any(ch.isspace() or unicodedata.category(ch) == "Cc" for ch in url):
        return "contains whitespace or a control character"
    try:
        parts = urlsplit(url)
        port = parts.port  # raises on a non-numeric or out-of-range port
    except ValueError:
        return "is not a valid URL (invalid host, IPv6 address or port)"
    if parts.scheme.lower() not in ("http", "https") or "://" not in url:
        return "must start with http:// or https://"
    if "@" in parts.netloc:
        return "must not carry user info (user:password@); pass the API key via UNIFI_API_KEY"
    if not parts.hostname:
        return "has no host"
    if not allow_query and (parts.query or "?" in url):
        return "must not carry a query string (?...)"
    if parts.fragment or "#" in url:
        return "must not carry a fragment (#...)"
    del port
    return None


def _utf8_encodable(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def text_setting_problem(value: str) -> str | None:
    """Why a free-text setting (a path, an audience, a label) is malformed, or None: it
    must be encodable as UTF-8 and hold no control character and no surrounding
    whitespace (a stray newline or space copied with the value). The value is never
    echoed by the caller's message."""
    if not _utf8_encodable(value):
        return "is not encodable as UTF-8 (it holds a lone surrogate, e.g. a non-UTF-8 byte)"
    if any(unicodedata.category(ch) == "Cc" for ch in value):
        return "contains a control character (such as a NUL or a line break)"
    if value != value.strip():
        return "has surrounding whitespace"
    return None


#: Accepted MCP_OAUTH_ALGORITHM values: the asymmetric JWT algorithms FastMCP's
#: JWTVerifier verifies against a JWKS (MCP_OAUTH_JWKS_URI is required, and a JWKS never
#: holds an HS* shared secret, which FastMCP refuses with a JWKS URI).
OAUTH_ALGORITHMS = (
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
    "EdDSA",
    "Ed25519",
    "Ed448",
)

#: An OAuth scope token (RFC 6749 3.3): printable ASCII except space, ``"`` and ``\``.
_SCOPE_CHARS = frozenset(chr(c) for c in range(0x21, 0x7F)) - {'"', "\\"}


#: Integer settings that must be at least 1, with what 0 or a negative value would do.
#: Validated at construction so a bad value fails startup with an actionable message
#: instead of hanging (concurrency 0), raising on every cache write (cache size 0), or
#: being silently accepted (a page cap of 0 or below).
_MIN_ONE_INTS: dict[str, str] = {
    "max_concurrency": "0 would block every upstream request forever",
    "cache_max_hosts": "0 would make every host-cache write raise",
    "cache_max_sites": "0 would make every site-cache write raise",
    "paginate_max_pages": "a cap below 1 would stop every list before its first page; "
    "leave it unset for no page cap",
}

#: Integer settings that may be 0 but not negative.
_MIN_ZERO_INTS: dict[str, str] = {
    "cache_ttl_seconds": "0 disables registry caching",
}

#: Boolean settings: an empty or whitespace-only value means unset (the default).
_BOOL_FIELDS = ("redact_secrets", "audit_calls")

#: The spellings a boolean setting accepts live in ``switches`` (one parser for
#: ``Settings`` and every runtime switch reader).
_TRUE_VALUES = TRUE_VALUES
_FALSE_VALUES = FALSE_VALUES

#: Valid UNIFI_LOG_LEVEL values (standard Python logging levels, case-insensitive).
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

#: Valid UNIFI_AUDIT_LOG_FORMAT values (case-insensitive).
AUDIT_LOG_FORMATS = ("text", "json")
#: Valid UNIFI_AUDIT_SINK / UNIFI_AUDIT_LEVEL / UNIFI_AUDIT_LOG_MODE values.
AUDIT_SINKS = ("none", "stderr", "file")
AUDIT_LEVELS = ("off", "normal", "debug")
AUDIT_LOG_MODES = ("0600", "0640")

#: The expected format of each JSON-decoded (complex) setting, named in its error.
API_KEYS_FORMAT = (
    'a JSON list of {"key": "<api key>", "label": "<name>", "is_org_key": false} '
    'objects, e.g. [{"key": "...", "label": "default"}]'
)
_COMPLEX_FORMATS: dict[str, str] = {"UNIFI_API_KEYS": API_KEYS_FORMAT}


def _env_name(field: str) -> str:
    return f"UNIFI_{field.upper()}"


class _EnvFormatError(ValueError):
    """A present but malformed complex env value; the message names the variable."""


class _StrictEnvSource(EnvSettingsSource):
    """The environment source with two guarantees for every setting.

    * An empty or whitespace-only value means unset: the setting keeps its default
      (``env_ignore_empty`` alone covers only the exact empty string).
    * A malformed JSON value (``UNIFI_API_KEYS``) fails naming the variable and the
      expected format; the value itself is never included.
    """

    def _load_env_vars(self) -> Any:
        loaded = super()._load_env_vars()
        return {k: v for k, v in loaded.items() if v is None or v.strip()}

    def decode_complex_value(self, field_name: str, field: FieldInfo, value: Any) -> Any:
        try:
            return super().decode_complex_value(field_name, field, value)
        except ValueError as exc:
            env = f"{self.env_prefix}{field_name}".upper()
            expected = _COMPLEX_FORMATS.get(env, "valid JSON")
            # json's message carries a position only, never the document.
            raise _EnvFormatError(f"{env} is not valid JSON ({exc}); expected {expected}") from None

    def __call__(self) -> dict[str, Any]:
        try:
            return super().__call__()
        except SettingsError as exc:
            if isinstance(exc.__cause__, _EnvFormatError):
                raise SettingsError(str(exc.__cause__)) from None
            raise


def _strict_sources(
    settings_cls: type[BaseSettings], init_settings: PydanticBaseSettingsSource
) -> tuple[PydanticBaseSettingsSource, ...]:
    """Constructor arguments, then the strict environment (no dotenv or secrets dir)."""
    return (init_settings, _StrictEnvSource(settings_cls))


#: A boolean setting: the server's single boolean parser (``switches.parse_bool``).
_parse_bool = parse_bool


#: How a credential value is checked (see :func:`credential_problem`).
#: ``"header"``: sent in an HTTP header (an API key, the bearer token): printable ASCII
#: with no whitespace. ``"password"``: the TLS private-key password, handed to OpenSSL as
#: UTF-8 bytes: spaces and non-ASCII are legitimate, control characters are not.
CredentialKind = Literal["header", "password"]


def credential_problem(value: str, kind: CredentialKind = "header") -> str | None:
    """What is wrong with a credential value, or None when it is usable.

    The value is never quoted in the result, and is never stripped or otherwise changed:
    surrounding whitespace is part of a secret as configured, so it is reported instead
    of being silently removed. The single check used by the server's settings and the
    placement-snapshot CLI (which loads the same settings).
    """
    if not _utf8_encodable(value):
        return (
            "is not encodable as UTF-8 (it holds a lone surrogate, e.g. a non-UTF-8 byte in "
            "the environment)"
        )
    if kind == "header":
        if not value:
            return "is empty"
        if not value.strip():
            return "is whitespace-only"
        if any(ch.isspace() for ch in value):
            return (
                "contains whitespace (a space, tab or line break; often a stray newline "
                "or space copied with the value)"
            )
    if any(unicodedata.category(ch) == "Cc" for ch in value):
        return "contains a control character (such as a NUL or a line break)"
    if kind == "header" and not value.isascii():
        return "contains a non-ASCII character (an HTTP header value must be ASCII)"
    return None


def _credential_error(what: str, problem: str) -> str:
    """The actionable message for a bad credential; names it, never shows its value."""
    return (
        f"{what} {problem}. Set it to the exact credential with nothing added; the value "
        "is not shown here"
    )


def key_fingerprint(key: str) -> str:
    """A one-way fingerprint of an API key, for comparison and cache keys (never logged)."""
    return hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()


class APIKeyConfig(BaseModel):
    """Configuration for a single UniFi Site Manager API key.

    A plain model, not a settings class: it is built from a ``UNIFI_API_KEYS`` entry or
    from ``UNIFI_API_KEY``, never from bare ``KEY`` / ``LABEL`` environment variables.
    """

    # hide_input_in_errors: a validation error never echoes the key value; repr=False
    # keeps the key out of str() and repr() of the model. extra="forbid": an unknown field
    # (a misspelt "is_org_key", say) fails startup instead of being silently ignored;
    # Settings names the entry and the field (``UNIFI_API_KEYS[i]``).
    model_config = {"hide_input_in_errors": True, "extra": "forbid"}

    key: str = Field(repr=False)
    label: str = "default"
    is_org_key: bool = Field(
        default=False,
        description="Organization keys cover all sites under the org. "
        "Personal keys only access consoles owned by the key holder.",
    )

    @field_validator("is_org_key", mode="before")
    @classmethod
    def _is_org_key(cls, v: object) -> object:
        return _parse_bool(v, "UNIFI_API_KEYS entry is_org_key")

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

    # hide_input_in_errors: a startup validation error never echoes an input value
    # (MCP_BEARER_TOKEN, MCP_TLS_KEY_PASSWORD). Empty or whitespace means unset.
    model_config = SettingsConfigDict(
        env_prefix="MCP_", hide_input_in_errors=True, env_ignore_empty=True
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return _strict_sources(settings_cls, init_settings)

    bearer_token: str = Field(
        default="",
        repr=False,
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
        repr=False,
        description="Password for an encrypted private key (MCP_TLS_KEY_PASSWORD). Optional.",
    )
    tls_cert_reqs: Literal["none", "optional", "required"] | None = Field(
        default=None,
        description="Client-certificate verification level for mTLS (MCP_TLS_CERT_REQS): "
        "one of 'none', 'optional', 'required'.",
    )

    # --- Opt-in liveness route ------------------------------------------------
    health_route: bool = Field(
        default=False,
        description="Opt-in GET /health liveness route on the HTTP transports "
        "(MCP_HEALTH_ROUTE): off by default. When on, the route answers 'ok' or "
        "'degraded:<reason>' from local process state only; it never contacts a console.",
    )

    # --- Host / Origin validation (DNS-rebinding and cross-site defence) -------
    host_origin_protection: bool = Field(
        default=True,
        description="Host and Origin header validation on the HTTP transports "
        "(MCP_HOST_ORIGIN_PROTECTION): on by default; 'off' disables both checks.",
    )
    allowed_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="Comma-separated browser origins allowed besides loopback and the origin "
        "of MCP_OAUTH_BASE_URL (MCP_ALLOWED_ORIGINS), e.g. https://app.example.com.",
    )
    allowed_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="Comma-separated Host header values accepted besides loopback "
        "(MCP_ALLOWED_HOSTS); setting it turns the Host check on for every bind address.",
    )
    oauth_write_scope: str = Field(
        default="",
        description="OAuth scope a token must carry to call write tools "
        "(MCP_OAUTH_WRITE_SCOPE). Unset: every admitted token can call every tool.",
    )

    cache_ttl: int = Field(
        default=300,
        validation_alias="UNIFI_MCP_CACHE_TTL",
        description="Seconds MCP clients may cache the tool list and other list results "
        "(UNIFI_MCP_CACHE_TTL). Sent as a public cache hint to clients that negotiate MCP "
        "protocol 2026-07-28; older clients ignore it. Unset -> 300; 0 -> ttlMs 0 (do not "
        "reuse).",
    )

    # --- Field-level normalisation / enum guards -----------------------------
    @field_validator("oauth_required_scopes", "oauth_authorization_servers", mode="before")
    @classmethod
    def _split_csv(cls, v: object, info: ValidationInfo) -> object:
        """Parse a comma-separated env string into a list (JSON decoding disabled), then
        check each item: a scope is an RFC 6749 scope token, an authorization server an
        absolute http(s) URL. The error names the variable."""
        env = f"MCP_{str(info.field_name).upper()}"
        if v is None or (isinstance(v, str) and not v.strip()):
            return []
        items = [item.strip() for item in v.split(",")] if isinstance(v, str) else v
        if not isinstance(items, list):
            return items
        for index, item in enumerate(items):
            if not isinstance(item, str):
                raise ValueError(f"{env} item {index} must be a string")
            if info.field_name == "oauth_required_scopes":
                if (
                    not item
                    or not _utf8_encodable(item)
                    or any(ch not in _SCOPE_CHARS for ch in item)
                ):
                    raise ValueError(
                        f"{env} item {index} is not an OAuth scope token: printable "
                        "ASCII with no space, '\"' or '\\'; separate scopes with commas"
                    )
            else:
                problem = api_base_url_problem(item)
                if problem is not None:
                    raise ValueError(
                        f"{env} item {index} must be an absolute http(s) URL: it {problem}"
                    )
        return items

    @field_validator("host_origin_protection", mode="before")
    @classmethod
    def _protection_switch(cls, v: object) -> object:
        """A boolean switch (on/off and the other accepted spellings); empty = on."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return True
        return parse_bool(v, "MCP_HOST_ORIGIN_PROTECTION")

    @field_validator("health_route", mode="before")
    @classmethod
    def _health_route_switch(cls, v: object) -> object:
        """A boolean switch (the accepted spellings); empty = off."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return False
        return parse_bool(v, "MCP_HEALTH_ROUTE")

    @field_validator("allowed_origins", "allowed_hosts", mode="before")
    @classmethod
    def _split_allowlist(cls, v: object, info: ValidationInfo) -> object:
        """Parse a comma-separated allowlist. An origin is ``scheme://host[:port]`` (http or
        https, no path); a host is a host name or IP literal with an optional port. The
        error names the variable."""
        from .transport_security import normalize_origin

        env = f"MCP_{str(info.field_name).upper()}"
        if v is None or v == "":
            return []
        items = [item.strip() for item in v.split(",") if item.strip()] if isinstance(v, str) else v
        if not isinstance(items, list):
            return items
        for index, item in enumerate(items):
            if not isinstance(item, str):
                raise ValueError(f"{env} item {index} must be a string")
            if info.field_name == "allowed_origins":
                if normalize_origin(item) is None or item.rstrip("/").count("/") != 2:
                    raise ValueError(
                        f"{env} item {index} is not an origin (the value is not shown here): use "
                        "scheme://host[:port] with http or https and no path, e.g. "
                        "https://app.example.com"
                    )
            elif any(ch.isspace() or ch in "/@?#" or not ch.isprintable() for ch in item):
                raise ValueError(
                    f"{env} item {index} is not a host name (the value is not shown here): use "
                    "a host name or IP literal with an optional port, e.g. mcp.example.com or "
                    "mcp.example.com:3000"
                )
        return items

    @field_validator("oauth_write_scope", mode="before")
    @classmethod
    def _write_scope(cls, v: object) -> object:
        """Empty means unset; otherwise one RFC 6749 scope token."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return ""
        if (
            not isinstance(v, str)
            or not _utf8_encodable(v)
            or any(ch not in _SCOPE_CHARS for ch in v)
        ):
            raise ValueError(
                "MCP_OAUTH_WRITE_SCOPE is not an OAuth scope token (the value is not shown "
                "here): printable ASCII with no space, '\"' or '\\'; give exactly one scope"
            )
        return v

    @field_validator("oauth_issuer", "oauth_jwks_uri", "oauth_base_url", mode="before")
    @classmethod
    def _url_setting(cls, v: object, info: ValidationInfo) -> object:
        """Empty means unset; otherwise an absolute http(s) URL with a host (a JWKS URI
        may carry a query string), the error naming the variable."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return ""
        env = f"MCP_{str(info.field_name).upper()}"
        if not isinstance(v, str):
            raise ValueError(f"{env} must be a string URL")
        problem = api_base_url_problem(v, allow_query=info.field_name == "oauth_jwks_uri")
        if problem is not None:
            raise ValueError(
                f"{env} must be an absolute http(s) URL such as https://auth.example.com/: "
                f"it {problem}"
            )
        return v

    @field_validator("oauth_algorithm", mode="before")
    @classmethod
    def _validate_algorithm(cls, v: object) -> object:
        """Empty means unset (RS256); otherwise one of :data:`OAUTH_ALGORITHMS`
        (case-sensitive, as JWT ``alg`` values are)."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return "RS256"
        if v not in OAUTH_ALGORITHMS:
            raise ValueError(
                f"MCP_OAUTH_ALGORITHM must be one of {', '.join(OAUTH_ALGORITHMS)} (case-sensitive)"
            )
        return v

    @field_validator("oauth_audience", mode="before")
    @classmethod
    def _audience_setting(cls, v: object) -> object:
        """Keep the audience opaque, including spaces, as in 0.6.2."""
        if v is None:
            return ""
        if not isinstance(v, str):
            raise ValueError("MCP_OAUTH_AUDIENCE must be a string")
        if not _utf8_encodable(v):
            raise ValueError("MCP_OAUTH_AUDIENCE is not encodable as UTF-8")
        if any(unicodedata.category(ch) == "Cc" for ch in v):
            raise ValueError("MCP_OAUTH_AUDIENCE contains a control character")
        return v

    @field_validator("tls_certfile", "tls_keyfile", "tls_ca_certs", mode="before")
    @classmethod
    def _text_setting(cls, v: object, info: ValidationInfo) -> object:
        """Empty means unset; otherwise UTF-8 text with no control character and no
        surrounding whitespace, the error naming the variable."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return ""
        env = f"MCP_{str(info.field_name).upper()}"
        if not isinstance(v, str):
            raise ValueError(f"{env} must be a string")
        problem = text_setting_problem(v)
        if problem is not None:
            raise ValueError(f"{env} {problem}")
        return v

    @field_validator("cache_ttl", mode="before")
    @classmethod
    def _validate_cache_ttl(cls, v: object) -> object:
        if v is None or (isinstance(v, str) and v.strip() == ""):
            return 300
        ttl = whole_number(v)
        if ttl is None:
            ttl = _negative_whole_number(v)
        if ttl is None or ttl < 0:
            raise ValueError(
                "UNIFI_MCP_CACHE_TTL must be a whole number of seconds, 0 or greater, "
                "written with ASCII digits only (no sign, '_' or decimal point); "
                "0 sends ttlMs 0 (do not reuse)."
            )
        return ttl

    @field_validator("auth_mode", mode="before")
    @classmethod
    def _validate_auth_mode(cls, v: object) -> object:
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        valid = ("none", "bearer", "oauth")
        # Case-insensitive, edge whitespace ignored (like every enumerated setting).
        value = v.strip().lower() if isinstance(v, str) else v
        if value not in valid:
            raise ValueError(f"MCP_AUTH_MODE must be one of {', '.join(valid)} (case-insensitive)")
        return value

    @field_validator("tls_mode", mode="before")
    @classmethod
    def _validate_tls_mode(cls, v: object) -> object:
        if v is None or (isinstance(v, str) and not v.strip()):
            return "none"
        valid = ("none", "https", "mtls")
        # Case-insensitive, edge whitespace ignored (like every enumerated setting).
        value = v.strip().lower() if isinstance(v, str) else v
        if value not in valid:
            raise ValueError(f"MCP_TLS_MODE must be one of {', '.join(valid)} (case-insensitive)")
        return value

    @field_validator("tls_cert_reqs", mode="before")
    @classmethod
    def _validate_cert_reqs(cls, v: object) -> object:
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        valid = ("none", "optional", "required")
        # Case-insensitive, edge whitespace ignored (like every enumerated setting).
        value = v.strip().lower() if isinstance(v, str) else v
        if value not in valid:
            raise ValueError(
                f"MCP_TLS_CERT_REQS must be one of {', '.join(valid)} (case-insensitive)"
            )
        return value

    # --- Cross-field, fail-closed resolution + reconciliation ----------------
    @model_validator(mode="after")
    def _resolve_and_validate(self) -> MCPTransportSettings:
        # Credential values are checked as configured (never stripped); the message names
        # the variable and never shows the value.
        problems = []
        if self.bearer_token:
            problem = credential_problem(self.bearer_token, "header")
            if problem:
                problems.append(_credential_error("MCP_BEARER_TOKEN", problem))
        if self.tls_key_password:
            problem = credential_problem(self.tls_key_password, "password")
            if problem:
                problems.append(_credential_error("MCP_TLS_KEY_PASSWORD", problem))
        if problems:
            raise ValueError("; ".join(problems))
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
        elif self.oauth_write_scope:
            # Fail-closed: a write scope with no OAuth token to read it from would
            # silently leave writes open to every caller.
            raise ValueError(
                "MCP_OAUTH_WRITE_SCOPE applies only to MCP_AUTH_MODE=oauth (resolved "
                f"auth_mode={self.auth_mode!r}); unset it, or set MCP_AUTH_MODE=oauth"
            )

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
            active = [
                f"{name}={value!r}"
                for name, value in (("auth_mode", self.auth_mode), ("tls_mode", self.tls_mode))
                if value != "none"
            ]
            raise ValueError(
                "FastMCP transport is 'stdio' but "
                f"{', '.join(active)} is set. "
                "Auth and TLS apply to HTTP transports only — set "
                "FASTMCP_TRANSPORT=streamable-http (or sse), or clear "
                "MCP_AUTH_MODE/MCP_BEARER_TOKEN and MCP_TLS_MODE."
            )
        return self


def _json_type(value: object) -> str:
    """The JSON type name of a decoded value (never the value itself)."""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int | float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if value is None:
        return "null"
    return type(value).__name__


class Settings(BaseSettings):
    """Top-level settings loaded from environment variables."""

    # hide_input_in_errors: a validation error must never echo the input, which for this
    # model includes every API key value. Empty or whitespace means unset, for every
    # setting (see _StrictEnvSource).
    model_config = SettingsConfigDict(
        env_prefix="UNIFI_",
        env_nested_delimiter="__",
        hide_input_in_errors=True,
        env_ignore_empty=True,
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return _strict_sources(settings_cls, init_settings)

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
        repr=False,
        description="Single API key shorthand. Used when api_keys is empty.",
    )
    cache_ttl_seconds: int = Field(
        default=900,
        ge=0,
        description="TTL for host/site registry cache (default 15 min).",
    )
    cache_max_hosts: int = Field(
        default=512,
        ge=1,
        description="Max entries in the hosts TTLCache (default 512).",
    )
    cache_max_sites: int = Field(
        default=2048,
        ge=1,
        description="Max entries in the sites TTLCache (default 2048).",
    )
    max_concurrency: int = Field(
        default=10,
        ge=1,
        description="Max concurrent requests for cross-site aggregation.",
    )
    request_timeout_seconds: None = Field(
        default=None,
        description="Removed setting. Leave unset: UniFi HTTP calls await completion "
        "or cancellation without an elapsed-time deadline.",
    )
    paginate_max_pages: int | None = Field(
        default=None,
        ge=1,
        description="Hard cap on pages drained per list call; query_traffic_flows and "
        "export_traffic_flows are exempt and always drain every page. "
        "Unset by default — stall detection is the primary safeguard. "
        "Set UNIFI_PAGINATE_MAX_PAGES to a generous number (e.g. 100000) if desired. "
        "Bound a traffic-flow call with body.pageSize instead.",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level for the server. Accepts standard Python logging levels: "
        "DEBUG, INFO, WARNING, ERROR, CRITICAL. Logs go to stderr only — no file handlers. "
        "Request/response bodies are never logged.",
    )
    redact_secrets: bool = Field(
        default=False,
        description="Opt-in credential redaction for responses. Env: UNIFI_REDACT_SECRETS. "
        "Default OFF: the server is a faithful pass-through and returns upstream "
        "responses verbatim (byte-identical to prior behaviour). Set to a truthy value "
        "(1/true/yes/on/t/y) to mask documented credential fields in every tool "
        "response: an explicit list of exact key names (x_passphrase, x_password, "
        "passphrase, password, secret, token, RADIUS secrets, WPA/cert key material), "
        "string values under keys ending in _api_key, _private_key, _secret, _token, "
        "_password or "
        "_passphrase, and string values under hidden x_ credential fields (x_ keys "
        "ending in key, psk, passphrase, password, passwd, secret, token or signature, "
        "except x_has_ flags). Matching is case-insensitive and anchored to the key.",
    )
    audit_log: str = Field(
        default="",
        description="Opt-in audit-log file path for ALL write/action operations. "
        "Env: UNIFI_AUDIT_LOG. Unset/empty by default: no audit file is written and the request "
        "path is byte-identical to today. When set to a path, every write attempt at the shared "
        "HTTP chokepoint appends a structured record (timestamp, method, resolved path, outcome, "
        "status). The API key value is never recorded; the request body only at "
        "UNIFI_AUDIT_LEVEL=debug, with credential fields masked.",
    )
    audit_log_format: str = Field(
        default="json",
        description="Format of the audit stream. Env: UNIFI_AUDIT_LOG_FORMAT. One of "
        '"json" (default, one canonical JSON object per line) or "text" (key=value line), '
        "case-insensitive; any other value fails at startup listing the formats.",
    )
    audit_sink: str = Field(
        default="",
        description="Audit stream sink. Env: UNIFI_AUDIT_SINK. One of none, stderr or file. "
        "Unset means file when UNIFI_AUDIT_LOG is set and none otherwise. file requires "
        "UNIFI_AUDIT_LOG; none or stderr with UNIFI_AUDIT_LOG set fails at startup.",
    )
    audit_level: str = Field(
        default="normal",
        description="Audit stream level. Env: UNIFI_AUDIT_LEVEL. off (only the two policy "
        "records), normal (default, metadata only) or debug (adds scrubbed request bodies "
        "and call arguments).",
    )
    audit_calls: bool = Field(
        default=False,
        description="Per-call audit records. Env: UNIFI_AUDIT_CALLS. Off by default; when on, "
        "every tool call writes one call record (or one error record when it fails).",
    )
    audit_log_mode: str = Field(
        default="0600",
        description="Permission bits of a NEW audit file. Env: UNIFI_AUDIT_LOG_MODE. 0600 "
        "(default, owner only) or 0640 (owner plus group read). An existing file keeps its "
        "mode.",
    )
    audit_hmac_key: SecretStr | None = Field(
        default=None,
        repr=False,
        description="Per-installation Code Mode argument-audit HMAC key. Env: "
        "UNIFI_AUDIT_HMAC_KEY. Canonical unpadded base64url encoding of exactly 32 bytes. "
        "Required only when UNIFI_TOOL_MODE=codemode; every replica in one installation "
        "must receive the same operator-provisioned key.",
    )
    tool_mode: Literal["full", "discovery", "codemode"] = Field(
        default="discovery",
        description="Tool catalog mode (UNIFI_TOOL_MODE): full advertises every selected tool; "
        "discovery advertises compact search, describe and registered-dispatch meta-tools; "
        "codemode (experimental, read-only, opt-in) advertises search_tools, describe_tool "
        "and execute, which runs a sandboxed Python script over the read tools.",
    )
    write_policy: str | None = Field(
        default=None,
        description="Global write policy (UNIFI_WRITE_POLICY): allow (default), dry-run or deny. "
        "dry-run returns a labelled preview for every write without sending it; deny refuses "
        "every write tool and write route before any upstream call (write_denied). "
        "Case-sensitive; a blank value fails startup.",
    )
    write_exceptions: str | None = Field(
        default=None,
        description="Per-family and per-tool write exceptions (UNIFI_WRITE_EXCEPTIONS): one "
        "semicolon list of <target>=deny or <target>=dry-run, the target family:<family-id> or "
        "tool:<public-name>, e.g. family:protect=deny;tool:fabric_connector_post=dry-run. The "
        "strictest of the global policy and every matching exception wins (allow < dry-run < "
        "deny); there is no allow exception. Unset means none; a blank value fails startup.",
    )
    family_allow: str | None = Field(
        default=None,
        description="Tool-family allowlist (UNIFI_FAMILY_ALLOW): a comma set of family IDs "
        "(unifi_fabric.families.ALL_FAMILIES). Unset means every family; tools of other "
        "families are not registered. The meta tools are never removed. A blank value fails "
        "startup.",
    )
    exclude: str | None = Field(
        default=None,
        description="Exclusions (UNIFI_EXCLUDE): one comma list of family:<id>, tool:<name>, "
        "source:<selector> (unifi_fabric.api_sources.valid_selectors(), case-sensitive) and "
        "unofficial (every tool whose primary API source is private). Excluded tools are not "
        "registered; no token removes a meta tool. Unset means none; a blank value fails "
        "startup.",
    )

    @field_validator("write_policy", "write_exceptions", "family_allow", "exclude", mode="before")
    @classmethod
    def _policy_setting(cls, v: object, info: ValidationInfo) -> object:
        """Checked at load with the startup grammar (:mod:`unifi_fabric.policy`); the message
        names the setting, never the value. ``tool:`` targets are checked for form here and
        against the registered catalog at server startup."""
        if v is None:
            return None
        env = _env_name(str(info.field_name))
        if not isinstance(v, str):
            raise ValueError(f"{env} must be a string")
        from .policy import StartupRefusal, operator_policy

        try:
            operator_policy({env: v}, None)
        except StartupRefusal as exc:
            # The message starts with the startup token, the one line a refusal prints.
            raise ValueError(f"{exc.token}: {exc.message}") from None
        return v

    @field_validator("request_timeout_seconds", mode="before")
    @classmethod
    def _retired_request_deadline(cls, _value: object) -> None:
        """Fail clearly rather than silently accepting an obsolete deadline knob."""
        if _value is not None and (not isinstance(_value, str) or _value.strip()):
            raise ValueError(
                "UNIFI_REQUEST_TIMEOUT_SECONDS setting removed; delete it "
                "from configuration. Requests await completion or cancellation."
            )
        return None

    @field_validator(*_BOOL_FIELDS, mode="before")
    @classmethod
    def _bool_setting(cls, v: object, info: ValidationInfo) -> object:
        """Empty means unset; otherwise an accepted boolean spelling, else an error
        naming the variable and listing the accepted values."""
        if isinstance(v, str) and not v.strip():
            raise PydanticUseDefault()
        return _parse_bool(v, _env_name(str(info.field_name)))

    @field_validator("log_level", mode="before")
    @classmethod
    def _log_level(cls, v: object) -> object:
        """Empty means unset (INFO); otherwise one of the standard levels."""
        if v is None or (isinstance(v, str) and not v.strip()):
            raise PydanticUseDefault()
        level = str(v).strip().upper()
        if level not in LOG_LEVELS:
            raise ValueError(
                f"UNIFI_LOG_LEVEL must be one of {', '.join(LOG_LEVELS)} (case-insensitive)"
            )
        return level

    @field_validator("audit_log_format", mode="before")
    @classmethod
    def _audit_log_format(cls, v: object) -> object:
        """Empty means unset (json); otherwise one of the formats, else fail fast."""
        if v is None or (isinstance(v, str) and not v.strip()):
            raise PydanticUseDefault()
        fmt = str(v).strip().lower()
        if fmt not in AUDIT_LOG_FORMATS:
            raise ValueError(
                f"UNIFI_AUDIT_LOG_FORMAT must be one of {', '.join(AUDIT_LOG_FORMATS)} "
                f"(case-insensitive)"
            )
        return fmt

    @field_validator("audit_sink", "audit_level", "audit_log_mode", mode="before")
    @classmethod
    def _audit_choice(cls, v: object, info: ValidationInfo) -> object:
        """Empty means unset; otherwise one of the listed values, else fail fast."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return (
                ""
                if info.field_name == "audit_sink"
                else ("normal" if info.field_name == "audit_level" else "0600")
            )
        choices, env = {
            "audit_sink": (AUDIT_SINKS, "UNIFI_AUDIT_SINK"),
            "audit_level": (AUDIT_LEVELS, "UNIFI_AUDIT_LEVEL"),
            "audit_log_mode": (AUDIT_LOG_MODES, "UNIFI_AUDIT_LOG_MODE"),
        }[info.field_name or ""]
        value = str(v).strip()
        value = value if info.field_name == "audit_log_mode" else value.lower()
        if value not in choices:
            raise ValueError(f"{env} must be one of {', '.join(choices)}")
        return value

    @model_validator(mode="after")
    def _audit_sink_matches_path(self) -> Settings:
        """file needs a path; none or stderr with a path set is a contradiction."""
        path = (self.audit_log or "").strip()
        if self.audit_sink == "file" and not path:
            raise ValueError("UNIFI_AUDIT_SINK=file requires UNIFI_AUDIT_LOG (a file path)")
        if self.audit_sink in ("none", "stderr") and path:
            raise ValueError(
                f"UNIFI_AUDIT_SINK={self.audit_sink} conflicts with UNIFI_AUDIT_LOG; unset one"
            )
        return self

    @field_validator("audit_log", mode="before")
    @classmethod
    def _audit_log_path(cls, v: object) -> object:
        """Empty means unset (no audit file); otherwise a path that is UTF-8 text with no
        control character and no surrounding whitespace."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return ""  # the default; validated defaults must not raise UseDefault (recursion)
        if not isinstance(v, str):
            raise ValueError("UNIFI_AUDIT_LOG must be a file path")
        problem = text_setting_problem(v)
        if problem is not None:
            raise ValueError(f"UNIFI_AUDIT_LOG {problem}")
        return v

    @field_validator("audit_hmac_key", mode="before")
    @classmethod
    def _audit_hmac_key(cls, value: object) -> SecretStr | None:
        """Validate key shape without ever echoing the key in an error."""
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        if isinstance(value, SecretStr):
            text = value.get_secret_value()
        elif isinstance(value, str):
            text = value
        else:
            raise ValueError(
                "UNIFI_AUDIT_HMAC_KEY must be canonical unpadded base64url for 32 bytes"
            )
        if _AUDIT_HMAC_KEY_RE.fullmatch(text) is None:
            raise ValueError(
                "UNIFI_AUDIT_HMAC_KEY must be canonical unpadded base64url for 32 bytes"
            )
        try:
            raw = base64.b64decode(text + "=", altchars=b"-_", validate=True)
        except (binascii.Error, ValueError):
            raise ValueError(
                "UNIFI_AUDIT_HMAC_KEY must be canonical unpadded base64url for 32 bytes"
            ) from None
        canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        if len(raw) != 32 or canonical != text:
            raise ValueError(
                "UNIFI_AUDIT_HMAC_KEY must be canonical unpadded base64url for 32 bytes"
            )
        return SecretStr(text)

    @field_validator("tool_mode", mode="before")
    @classmethod
    def _tool_mode(cls, value: object) -> str:
        if value is None or (isinstance(value, str) and not value.strip()):
            return "discovery"
        if isinstance(value, str) and value.strip().lower() in {"discovery", "full", "codemode"}:
            return value.strip().lower()
        raise ValueError("UNIFI_TOOL_MODE must be one of discovery, full, codemode")

    @model_validator(mode="after")
    def _code_mode_requires_audit_hmac_key(self) -> Settings:
        if self.tool_mode == "codemode" and self.audit_hmac_key is None:
            raise ValueError("UNIFI_AUDIT_HMAC_KEY is required when UNIFI_TOOL_MODE=codemode")
        return self

    def audit_hmac_key_bytes(self) -> bytes | None:
        """Decoded Code Mode audit key, passed through lifecycle wiring only."""
        if self.audit_hmac_key is None:
            return None
        text = self.audit_hmac_key.get_secret_value()
        return base64.b64decode(text + "=", altchars=b"-_", validate=True)

    @field_validator("api_base_url", mode="before")
    @classmethod
    def _api_base_url(cls, v: object) -> object:
        """Empty means unset; otherwise an absolute http(s) URL with a host and no user
        info, query, fragment or whitespace (the value is not echoed)."""
        if v is None or (isinstance(v, str) and not v.strip()):
            raise PydanticUseDefault()
        url = str(v)
        problem = api_base_url_problem(url)
        if problem is not None:
            raise ValueError(
                "UNIFI_API_BASE_URL must be an absolute http(s) URL such as "
                f"https://api.ui.com: it {problem} (unset or empty keeps that default)"
            )
        return url

    @field_validator("api_keys", mode="before")
    @classmethod
    def _api_keys_shape(cls, v: object) -> object:
        """UNIFI_API_KEYS must be a list of key objects; name the variable and format.

        Only the JSON type of a bad entry is reported, never its content.
        """
        if v is None:
            raise PydanticUseDefault()
        if not isinstance(v, list):
            raise ValueError(
                f"UNIFI_API_KEYS must be {API_KEYS_FORMAT} (got a JSON {_json_type(v)})"
            )
        for index, item in enumerate(v):
            if isinstance(item, APIKeyConfig):
                continue
            if not isinstance(item, dict):
                raise ValueError(
                    f'UNIFI_API_KEYS entry {index} must be an object with a string "key" '
                    f"(got a JSON {_json_type(item)}); expected {API_KEYS_FORMAT}"
                )
            unknown_count = sum(k not in APIKeyConfig.model_fields for k in item)
            if unknown_count:
                raise ValueError(
                    f"UNIFI_API_KEYS[{index}] has {unknown_count} unknown field(s); "
                    f"the allowed fields are "
                    f"{', '.join(repr(k) for k in APIKeyConfig.model_fields)}. Remove or "
                    f"rename the field; expected {API_KEYS_FORMAT}"
                )
            if not isinstance(item.get("key"), str):
                raise ValueError(
                    f'UNIFI_API_KEYS entry {index} needs a string "key"; expected {API_KEYS_FORMAT}'
                )
        return v

    @field_validator(*_MIN_ONE_INTS, *_MIN_ZERO_INTS, mode="before")
    @classmethod
    def _bounded_int(cls, v: object, info: ValidationInfo) -> object:
        """Empty means unset; otherwise a whole number within the field's bound.

        The message names the environment variable, the bound and what an out-of-bound
        value would do, so startup fails fast and says how to fix it. The value received is
        never shown (a value set in the wrong variable may be a credential).
        """
        field = str(info.field_name)
        if v is None:
            # Only the optional page cap admits None (its default: no cap); the type
            # check rejects None for every other field. Defaults are validated too
            # (validate_default), so None must not be routed back to the default here.
            return v
        if isinstance(v, str) and not v.strip():
            raise PydanticUseDefault()
        if field in _MIN_ONE_INTS:
            floor, why = 1, _MIN_ONE_INTS[field]
        else:
            floor, why = 0, _MIN_ZERO_INTS[field]
        number = whole_number(v)
        if number is None:
            number = _negative_whole_number(v)
        if number is None:
            raise ValueError(
                f"{_env_name(field)} must be a whole number >= {floor} written with ASCII "
                "digits only (no sign, '_' separator, decimal point or non-ASCII digit); "
                f"{why}; the value is not shown here"
            )
        if number < floor:
            raise ValueError(
                f"{_env_name(field)} must be >= {floor}: {why}. "
                f"Set it to {floor} or more, or unset it for the default."
            )
        return number

    @model_validator(mode="after")
    def _valid_credentials(self) -> Settings:
        """Fail fast on an unusable API key or label, naming its position and never its value.

        ``UNIFI_API_KEY`` and every ``UNIFI_API_KEYS`` key must be printable ASCII with
        no whitespace (an HTTP header value); a key is never stripped, so a stray newline
        or space is reported instead of being silently sent or removed. Every
        ``UNIFI_API_KEYS`` entry needs a label that passes the ``key_label`` selector rule
        (non-empty, no control character, no surrounding whitespace; the error names
        ``UNIFI_API_KEYS[i].label``), and one key may not be configured under two labels
        (compared by fingerprint).
        """
        problems: list[str] = []
        if self.api_key:
            problem = credential_problem(self.api_key, "header")
            if problem:
                problems.append(_credential_error("UNIFI_API_KEY", problem))
        entries_by_fingerprint: dict[str, list[tuple[int, str]]] = {}
        for index, cfg in enumerate(self.api_keys):
            # The SAME selector rule key_label is checked with at call time, so every
            # label config accepts is selectable via key_label.
            label_reason = selector_reason(cfg.label)
            if label_reason is not None:
                problems.append(
                    f"UNIFI_API_KEYS[{index}].label {label_reason}. Give every key a unique "
                    "non-empty 'label' with no surrounding whitespace or control character "
                    "(labels select the key for key_label arguments)"
                )
            name = f"UNIFI_API_KEYS entry {index}"
            problem = credential_problem(cfg.key, "header")
            if problem:
                problems.append(_credential_error(f"the key of {name}", problem))
            elif label_reason is None:
                entries_by_fingerprint.setdefault(key_fingerprint(cfg.key), []).append(
                    (index, cfg.label)
                )
        for entries in entries_by_fingerprint.values():
            if len({label for _index, label in entries}) > 1:
                problems.append(
                    "UNIFI_API_KEYS configures the same key under different labels at entries "
                    + ", ".join(str(index) for index, _label in entries)
                    + ". Keep one entry per key (values are not shown here)"
                )
        if problems:
            raise ValueError("; ".join(problems))
        return self

    @model_validator(mode="after")
    def _unique_key_labels(self) -> Settings:
        """Fail fast when two API keys share a label.

        Keys are looked up and their HTTP clients cached by label, so a duplicate label
        would route one key's requests with another key's credential. The error lists the
        affected entry positions only, never a label or key value.
        """
        # Only UNIFI_API_KEYS can carry several keys (UNIFI_API_KEY is one 'default').
        # Labels already passed the selector rule, so duplicates are compared exactly.
        indices_by_label: dict[str, list[int]] = {}
        for index, cfg in enumerate(self.api_keys):
            indices_by_label.setdefault(cfg.label, []).append(index)
        duplicates = sorted(
            index for indices in indices_by_label.values() if len(indices) > 1 for index in indices
        )
        if duplicates:
            raise ValueError(
                "UNIFI_API_KEYS has duplicate key labels at entries "
                + ", ".join(str(index) for index in duplicates)
                + ". Give every key a unique 'label' (labels select the key for "
                "key_label arguments and route each request with that key)."
            )
        return self

    def get_key_configs(self) -> list[APIKeyConfig]:
        """Return resolved list of API key configs."""
        if self.api_keys:
            return self.api_keys
        if self.api_key:
            return [APIKeyConfig(key=self.api_key, label="default")]
        return []


#: ``UNIFI_*`` settings read outside the two settings models: the credential mode
#: (header or environment keys). Every other current setting is a field (or alias) of
#: :class:`Settings` or :class:`MCPTransportSettings`.
_DIRECT_SETTINGS: frozenset[str] = frozenset({"UNIFI_KEY_MODE"})

#: Variables of the maintainers' test harnesses (tests/, scripts/). The
#: server never reads them; they are tolerated so a live run that exports them into the
#: shell that starts the server does not refuse to start. They configure nothing here.
_HARNESS_VARIABLES: frozenset[str] = frozenset(
    {
        "UNIFI_MATRIX_API_KEY",
        "UNIFI_PAGINATION_PROFILE",
        "UNIFI_SCRUB_CORPUS_AGGREGATE",
        "UNIFI_SCRUB_CORPUS_EVIDENCE",
        "UNIFI_SCRUB_ORACLE_SLOW",
        "UNIFI_TEST_ALLOW_MUTATIONS",
        "UNIFI_TEST_AXIS_BATCH",
        "UNIFI_TEST_CONSOLE_ID",
        "UNIFI_TEST_DERIVED_BATCH",
        "UNIFI_TEST_HOST",
        "UNIFI_TEST_MAX_BATCH",
        "UNIFI_TEST_SELECTION_CACHE",
        "UNIFI_TEST_SELECTION_CACHE_DIR",
        "UNIFI_TEST_SITE",
    }
)


def known_setting_names() -> frozenset[str]:
    """Every current ``UNIFI_*`` setting name: both settings models, their aliases and the
    settings read directly. Any other ``UNIFI_*`` name in the environment is retired and
    refuses startup (:func:`unifi_fabric.policy.check_retired_settings`)."""
    names: set[str] = set(_DIRECT_SETTINGS) | _HARNESS_VARIABLES
    for model in (Settings, MCPTransportSettings):
        prefix = str(model.model_config.get("env_prefix") or "")
        for field_name, field in model.model_fields.items():
            alias = field.validation_alias
            if isinstance(alias, str):
                names.add(alias.upper())
            else:
                names.add(f"{prefix}{field_name}".upper())
    return frozenset(n for n in names if n.startswith("UNIFI_"))


def startup_gate(environ: Mapping[str, str] | None = None) -> None:
    """The one startup gate, run before any settings model loads.

    Refuses a retired (or non-canonically spelled) ``UNIFI_*`` name, then a blank or
    malformed policy setting (:mod:`unifi_fabric.policy` grammar; ``tool:`` targets are
    checked for form here and against the registered catalog in the server lifespan). A
    refusal prints its startup token as the last stderr line and exits 2; an unrecognized
    ``UNIFI_*`` name also prints the migration line before it.
    """
    from .policy import StartupRefusal, check_retired_settings, operator_policy

    env = os.environ if environ is None else environ
    try:
        check_retired_settings(env, known_setting_names())
        operator_policy(env, None)
    except StartupRefusal as exc:
        print(exc.stderr_text(), end="", file=sys.stderr, flush=True)
        raise SystemExit(2) from None
