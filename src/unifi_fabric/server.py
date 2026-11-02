"""UniFi Fabric MCP Server — FastMCP server exposing UniFi Site Manager API tools."""

from __future__ import annotations

if __name__ == "__main__":
    # Route module execution through the lightweight CLI preflight before this
    # module imports and registers the full MCP tool catalog.
    from .entrypoint import main as _entrypoint_main

    _entrypoint_main()
    raise SystemExit

import asyncio
import inspect
import json
import logging
import os
import re
import ssl
import sys

from .tool_annotations import READ_ONLY, WRITE, install_tool_annotations

# Suppress pydantic version URLs in validation error messages (information disclosure).
os.environ.setdefault("PYDANTIC_ERRORS_INCLUDE_URL", "0")

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AuthProvider
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult
from mcp.types import ImageContent, TextContent
from pydantic import Field
from pydantic.fields import FieldInfo

from . import route_secrets
from ._read_only_audit import state_changing_get
from .api_sources import apply_api_source_filter, install_api_sources
from .argument_errors import ArgumentErrorMiddleware
from .argument_values import ArgumentValueMiddleware
from .audit import audit_call
from .catalog_descriptions import install_compact_selector_descriptions
from .client import UniFiClient, UniFiConnectionError, UniFiHTTPError
from .config import MCPTransportSettings, Settings
from .confirm_compat import ConfirmIgnoredMiddleware
from .discovery import apply_tool_mode
from .entrypoint import _version
from .families import apply_tool_family_filter
from .list_results import install_structured_list_results
from .read_only_tools import (
    AreaOptOutMiddleware,
    ReadOnlyToolMiddleware,
    apply_area_opt_out_tool_filter,
    apply_read_only_tool_filter,
)
from .redaction import RedactionScopeMiddleware, install_response_redaction
from .refusal_audit import RefusedWriteAuditMiddleware, credential_values
from .registry import PartialListingError, Registry
from .resolution_state import install_resolution_state
from .secret_scrub import (
    configured_secrets,
    install_log_scrubber,
    scrub,
    secret_scope,
    set_secret_provider,
)
from .selector_args import SelectorArgumentMiddleware
from .spec_limits import SpecLimitMiddleware
from .tool_shapes import install_tool_shapes
from .tool_titles import install_tool_titles
from .tools import (
    _keys,
    aggregation,
    carrier_fabric,
    client_records,
    clients,
    connector,
    device_commands,
    device_mgmt,
    device_radios,
    firewall_proxy,
    hotspot,
    innerspace,
    innerspace_internal,
    matter,
    mobility,
    network,
    network_clients_guests,
    network_controller_admin,
    network_controller_insights,
    network_device_operations,
    network_dpi_policy,
    network_mobile_wan,
    network_nat_qos_traffic,
    network_proav_sandbox,
    network_routing_topology,
    network_security_diagnostics,
    network_services_proxy,
    network_switching_power,
    network_vpn_dns,
    network_wifi_radio,
    placement_snapshot,
    protect,
    protect_automation_backup,
    protect_camera_recording,
    protect_device_lifecycle,
    protect_events_cases,
    protect_private,
    protect_ptz_doorbell,
    protect_recognition_search,
    protect_users_assets,
    radius_profiles,
    recognition,
    scheduled_tasks,
    site_admin,
    site_config,
    site_manager,
    statistics,
    system_log,
    vpn,
    vpn_clients,
)
from .tools._results import deletion_result
from .transport_security import (
    HTTP_TRANSPORTS,
    ConstantTimeTokenVerifier,
    OriginGuardMiddleware,
    StrictJWTVerifier,
    StrictRemoteAuthProvider,
    WriteScopeMiddleware,
    allowed_origins,
    capped_jwks_client,
    http_app_options,
    install_host_refusal_hint,
    startup_warnings,
)
from .write_body import EmptyUpdateMiddleware


def _image_result(metadata: dict[str, Any]) -> ToolResult:
    """Serve image content and preserve the upstream image metadata for callers.

    The image is sent three times on purpose: as MCP image content, in the JSON text
    block (the structured-content compatibility copy) and in ``structured_content``,
    which carries the documented ``{image_base64, content_type, size_bytes}`` result for
    clients that read only text or structured content. Dropping a copy changes that
    result shape.
    """
    mime = (metadata.get("content_type") or "image/jpeg").split(";", 1)[0].strip()
    return ToolResult(
        content=[
            ImageContent(type="image", data=metadata["image_base64"], mime_type=mime),
            TextContent(type="text", text=json.dumps(metadata)),
        ],
        structured_content=metadata,
    )


def _nullable_default(value: Any, unset: Any) -> Any:
    """Resolve optional Field defaults for direct Python calls as well as MCP calls."""
    return unset if isinstance(value, FieldInfo) else value


_settings: Settings | None = None
_client: UniFiClient | None = None
_registry: Registry | None = None


def get_settings() -> Settings:
    """Lazily construct and cache the top-level :class:`Settings`.

    Importing this module must not read the environment or be able to crash.
    ``Settings()`` parses the ``UNIFI_*`` environment (including JSON-decoding
    ``UNIFI_API_KEYS`` into ``list[APIKeyConfig]``) and raises ``SettingsError``
    on malformed input. Constructing it at module scope turned a bad env var
    into an *import-time* crash — surfacing as a pytest collection error for
    every module that imports this one. Construction is deferred to first use
    (``lifespan`` at server startup, or explicit callers) so the failure mode
    is a proper startup error, not an import-time one.
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


@asynccontextmanager
async def lifespan(app: FastMCP) -> AsyncIterator[None]:
    global _client, _registry
    settings = get_settings()
    app.instructions = deployment_instructions(settings)
    logging.basicConfig(
        level=settings.log_level.upper(),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        force=True,
    )
    # basicConfig(force=True) replaced the root handler: attach the scrub filter to it
    # and to uvicorn's handlers (configured by now). The record factory already covers
    # every record; the filter covers records built without it.
    install_log_scrubber()
    if not settings.get_key_configs():
        raise RuntimeError(
            "No API key configured. Set UNIFI_API_KEY or UNIFI_API_KEYS before starting the server."
        )
    _client = UniFiClient(settings)
    _registry = Registry(
        _client,
        ttl_seconds=settings.cache_ttl_seconds,
        cache_max_hosts=settings.cache_max_hosts,
        cache_max_sites=settings.cache_max_sites,
    )
    # Everything after the client exists runs inside the try, so a startup failure
    # (an invalid family or source selector, a tool-mode error) still closes the client
    # and clears the module globals instead of leaking them.
    registered: dict[str, Any] = {}
    hidden_writes: set[str] = set()
    hidden_area_writes: dict[str, str] = {}
    restore_tool_mode: Callable[[], None] | None = None
    try:
        # Opt-in tool-family selection: no-op when UNIFI_TOOL_FAMILIES and
        # UNIFI_DISABLED_TOOL_FAMILIES are unset (full roster advertised); otherwise
        # de-register out-of-allowlist tools, then the tools of every disabled family.
        await apply_tool_family_filter(app, settings.tool_families, settings.disabled_tool_families)
        # Opt-in API-source disable list: no-op when UNIFI_DISABLE_API_SOURCES is unset;
        # otherwise de-register every tool a selector covers (api_sources.is_disabled).
        await apply_api_source_filter(app, settings.disable_api_sources)
        # The write tools read-only mode and the area opt-outs hide are put back when this
        # lifespan ends, so the registered catalog is the same for the next session.
        registered = {tool.name: tool for tool in await app.list_tools()}
        hidden_writes = await apply_read_only_tool_filter(app, settings.read_only)
        # Per-area write opt-outs hide that area's write tools the same way (no-op by
        # default).
        hidden_area_writes = await apply_area_opt_out_tool_filter(
            app, settings.enable_connector_write
        )
        # Tool-mode selection (UNIFI_TOOL_MODE): discovery, the default, advertises the
        # meta-tools and reaches every registered tool through them; full advertises every
        # registered tool.
        restore_tool_mode = await apply_tool_mode(
            app,
            settings.tool_mode,
            read_only=settings.read_only,
            hidden_write_names=hidden_writes,
            hidden_area_writes=hidden_area_writes,
            audit=_audit_refusal,
        )
        # Discovery adds its own annotated dispatcher; hide that write as well.
        hidden_writes.update(await apply_read_only_tool_filter(app, settings.read_only))
        yield
    finally:
        if restore_tool_mode is not None:
            restore_tool_mode()
        listed = {tool.name for tool in await app.list_tools()}
        for name in (hidden_writes | set(hidden_area_writes)) - listed:
            if name in registered:
                app.add_tool(registered[name])
        close_error: BaseException | None = None
        try:
            await _client.close()
        except BaseException as exc:
            close_error = exc
            raise
        finally:
            _client = None
            _registry = None
            auth = app.auth
            if isinstance(auth, StrictRemoteAuthProvider) and isinstance(
                auth.token_verifier, StrictJWTVerifier
            ):
                # The verifier borrows this server-owned client; FastMCP does not close it.
                jwks_client = auth.token_verifier._http_client  # noqa: SLF001
                if jwks_client is not None:
                    try:
                        await jwks_client.aclose()
                    except BaseException as exc:
                        if close_error is None:
                            raise
                        close_error.add_note(f"JWKS HTTP client cleanup also failed: {exc!r}")


INSTRUCTIONS = """UniFi Fabric manages UniFi infrastructure through Site Manager/Fabric.
Discover consoles with list_hosts; use reportedState.hostname/name or the composite id as host.
Prefer site names: list_sites has Fabric ids; list_local_sites has Network UUIDs.
The server resolves the right id; ambiguous names fail with choices.
Devices are infrastructure; clients are end-user devices.
Read tool schemas for identifiers, time units and body shapes.
Shape: outlines use local aliases such as T1, defined by the trailing "where T1=...".
For firewall rules use zone-based policies unless the user asks for ACL/classic rules.
Discover zones with list_firewall_zones_proxy; destination ports use destination.trafficFilter.
Full PUT replaces fields: fetch the current object first.
Deletes and physical actions may be irreversible.
UNIFI_TOOL_FAMILIES and UNIFI_DISABLED_TOOL_FAMILIES select families.
Writes are enabled by default;
UNIFI_READ_ONLY and per-area opt-outs hide their write tools and refuse calls to them.
UNIFI_DRY_RUN previews without sending writes, though reads may occur.
UNIFI_REDACT_SECRETS is opt-in; previews may contain secrets.
List pagination drains all pages by default.
UNIFI_PAGINATE_MAX_PAGES is an explicit cap reported with incomplete=true.
Supply paging arguments for one page and continue its cursor/offset.
Multi-key org cursor pages need key_label;
unscoped lists aggregate keys and report per-key failures.
Upstream bodies and error reasons are preserved. Relay 4xx/5xx results are errors.
Never swallow failures or infer unsupported from one error.
See docs/TOOLS.md and docs/TOOL-USAGE.md for examples."""


def deployment_instructions(settings: Settings) -> str:
    """Initialize advertises the active, validated mode without exposing credentials."""
    return INSTRUCTIONS + (
        "\nCurrent deployment: "
        f"UNIFI_READ_ONLY={int(settings.read_only)}; UNIFI_DRY_RUN={int(settings.dry_run)}."
    )


def build_auth(s: MCPTransportSettings) -> AuthProvider | None:
    """Build the FastMCP auth provider for the resolved auth_mode.

    - ``"none"``   -> ``None`` (no transport auth)
    - ``"bearer"`` -> ``ConstantTimeTokenVerifier`` over the shared MCP_BEARER_TOKEN
      secret (a ``StaticTokenVerifier`` that compares with ``hmac.compare_digest``)
    - ``"oauth"``  -> ``RemoteAuthProvider`` wrapping a ``StrictJWTVerifier`` (this server
      is an OAuth 2.0 **resource server**: it verifies bearer JWTs minted by an
      external authorization server and advertises itself via the
      ``/.well-known/oauth-protected-resource`` metadata route — no IdP, login,
      consent or dynamic client registration lives here). The verifier also requires
      ``exp``, checks ``nbf``/``iat`` with a 60 s leeway (the 401 names the claim) and
      downloads the JWKS with a 1 MiB cap.

    The Phase-0 config validator already guarantees the oauth descriptor is complete
    (issuer + jwks_uri + audience + base_url, fail-closed), so this builder can rely
    on those fields being populated.
    """
    mode = s.auth_mode
    if mode in (None, "none"):
        return None
    if mode == "bearer":
        return ConstantTimeTokenVerifier(s.bearer_token)
    if mode == "oauth":
        from pydantic import AnyHttpUrl

        class ExactIssuerUrl(AnyHttpUrl):
            """Validate as a URL while publishing the operator's exact issuer string.

            Pydantic retains AnyHttpUrl subclass instances in metadata and serializes
            them through str(). Normalization would change JWT issuer identities.
            """

            def __init__(self, url: str) -> None:
                super().__init__(url)
                self.configured = url

            def __str__(self) -> str:
                return self.configured

        # Token verifier: validate the JWT signature against the IdP's JWKS and
        # enforce issuer / audience / required-scope claims, plus exp/nbf/iat. ssrf_safe
        # defaults to False, which is appropriate for a JWKS URI supplied by the operator;
        # the download is capped at 1 MiB by the client passed here.
        verifier = StrictJWTVerifier(
            jwks_uri=s.oauth_jwks_uri,
            issuer=s.oauth_issuer,
            audience=s.oauth_audience,
            required_scopes=s.oauth_required_scopes,
            algorithm=s.oauth_algorithm,
            http_client=capped_jwks_client(),
        )
        # Resource-server wrapper: serves the protected-resource discovery document
        # naming the upstream authorization server(s). No client-redirect handling
        # belongs here — that is the authorization server's responsibility.
        return StrictRemoteAuthProvider(
            token_verifier=verifier,
            authorization_servers=[ExactIssuerUrl(u) for u in s.oauth_authorization_servers],
            base_url=s.oauth_base_url,
        )
    # Unreachable: config validation restricts auth_mode to the values above.
    raise ValueError(f"Unsupported auth_mode: {mode!r}")


# Maps the MCP_TLS_CERT_REQS selector to the stdlib ssl client-verification
# constant uvicorn expects. mTLS-only knob (https has no client cert).
_CERT_REQS_MAP: dict[str, int] = {
    "none": ssl.CERT_NONE,
    "optional": ssl.CERT_OPTIONAL,
    "required": ssl.CERT_REQUIRED,
}


def build_uvicorn_config(s: MCPTransportSettings) -> dict[str, Any]:
    """Build HTTP uvicorn kwargs, disabling its unbounded access records.

    Plain HTTP and TLS both use the server-owned bounded access logger.
    The stdio transport does not call this builder.

    Client-certificate verification (``ssl_cert_reqs``) is driven by the
    ``tls_cert_reqs`` selector rather than hard-coded:

    - ``https`` requests no client certificate, so ``ssl_cert_reqs`` is left
      unset — uvicorn's default is ``ssl.CERT_NONE``. The selector is an mTLS
      knob and does not apply here.
    - ``mtls`` maps the selector (``none``/``optional``/``required``) to the
      matching ``ssl.CERT_*`` constant, defaulting to ``ssl.CERT_REQUIRED`` when
      unset. ``none`` is rejected up-front by the fail-closed config validator,
      so it can never reach this builder under mTLS.
    """
    config: dict[str, Any] = {"access_log": False, "ws": "none"}
    if s.tls_mode == "none":
        return config
    config.update(
        {
            "ssl_certfile": s.tls_certfile,
            "ssl_keyfile": s.tls_keyfile,
            "ssl_keyfile_password": s.tls_key_password or None,
        }
    )
    if s.tls_mode == "mtls":
        config["ssl_ca_certs"] = s.tls_ca_certs
        config["ssl_cert_reqs"] = _CERT_REQS_MAP[s.tls_cert_reqs or "required"]
    return config


# Every log record (any logger, any handler) is scrubbed of the configured secrets
# before it is formatted; installed before the transport settings load so even a
# startup failure logged by a library cannot carry MCP_BEARER_TOKEN or an API key.
install_log_scrubber()
set_secret_provider(lambda: configured_secrets(_settings, globals().get("_mcp_transport")))

# Environment-dependent validation is deferred to startup. Importing this module
# must not leak a pydantic traceback before the CLI error renderer is available.
_mcp_transport: MCPTransportSettings | None = None
_cache_ttl: int | None = None
#: A docstring's own result statement, in any case ("Returns ...", "delete returns ...").
_RESULT_STATEMENT = re.compile(r"\breturn(?:s|ed)?\b", re.IGNORECASE)


class FabricMCP(FastMCP):
    """FastMCP with this server's Host/Origin policy on every HTTP app it builds.

    Environment-dependent transport settings are validated lazily
    (:func:`_configure_transport`) the first time an HTTP app is built or the server
    runs, never at import. ``http_app`` (used by ``run`` for streamable-http and SSE,
    and by tests) applies :func:`http_app_options` and, unless
    ``MCP_HOST_ORIGIN_PROTECTION=off``, adds :class:`OriginGuardMiddleware` as the
    layer before authentication and MCP handling. The bounded access logger wraps
    the whole app, including Origin and Host refusals.
    """

    async def call_tool(self, name: str, *args: Any, **kwargs: Any) -> Any:
        try:
            return await super().call_tool(name, *args, **kwargs)
        except UniFiHTTPError as exc:
            notes = getattr(exc, "__notes__", ())
            if not notes:
                raise
            # The notes stay notes: SecretScrubMiddleware renders each unique note of the
            # error and its cause chain once (embedding them here as well showed them twice).
            error = UniFiHTTPError(
                f"Error calling tool {name!r}: {exc}",
                status=exc.status,
                request_sent=exc.request_sent,
            )
            for note in notes:
                error.add_note(note)
            raise error from exc

    def tool(self, name_or_fn: Any = None, **kwargs: Any) -> Any:
        """Register a tool after preserving result prose in its public description.

        FastMCP exposes only docstring text before its first structured section. A
        ``Returns:`` Google-docstring section is therefore not advertised, so result
        wording must remain in that prose. Each tool states its own result there; a
        docstring that states none gets one short pass-through line. It stays short and
        names no keys: the same words on many tools dilute ``search_tools`` ranking, and a
        tool that adds keys must name them itself (the cd result-key check enforces it).
        A result statement in any case counts ("Action delete returns {...}"), so the
        line never sits beside a tool's own result and contradicts one of its branches
        (tests/test_result_shape_claims.py).
        """

        def prepare(fn: Any) -> Any:
            if kwargs.get("description") is None:
                doc = inspect.getdoc(fn)
                prose, marker, args = (doc or "").partition("\n\nArgs:\n")
                if doc and _RESULT_STATEMENT.search(prose) is None:
                    returns = "Returns: the upstream response body verbatim."
                    fn.__doc__ = (
                        f"{prose.rstrip()}\n\n{returns}{marker}{args}"
                        if marker
                        else f"{doc.rstrip()}\n\n{returns}"
                    )
            return fn

        if callable(name_or_fn) and not isinstance(name_or_fn, str):
            return super().tool(prepare(name_or_fn), **kwargs)
        decorator = super().tool(name_or_fn, **kwargs)

        def register(fn: Any) -> Any:
            return decorator(prepare(fn))

        return register

    def http_app(self, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        transport = _transport_settings()
        app = super().http_app(*args, **http_app_options(transport, kwargs))
        install_host_refusal_hint(app)
        if transport.host_origin_protection:
            app.add_middleware(OriginGuardMiddleware, allowed=allowed_origins(transport))
        from .access_log import AccessLogMiddleware

        return AccessLogMiddleware(app)

    async def run_http_async(self, *args: Any, **kwargs: Any) -> None:
        # Also cover direct/programmatic HTTP starts and every HTTP alias.
        config = build_uvicorn_config(_transport_settings())
        config.update(kwargs.pop("uvicorn_config", None) or {})
        config["access_log"] = False
        # MCP HTTP exposes no WebSocket routes; uvicorn logs upgrade targets
        # via uvicorn.error before the ASGI HTTP boundary can see them.
        config["ws"] = "none"
        kwargs["uvicorn_config"] = config
        await super().run_http_async(*args, **kwargs)

    async def run_async(self, *args: Any, **kwargs: Any) -> None:
        if _mcp_transport is None:
            _configure_transport()
        await super().run_async(*args, **kwargs)


mcp = FabricMCP(
    "UniFi Fabric",
    instructions=INSTRUCTIONS,
    version=_version(),
    lifespan=lifespan,
)


def _configure_transport() -> MCPTransportSettings:
    """Validate and apply auth/cache settings before starting any transport."""
    from fastmcp.server.server import build_cache_hints

    global _mcp_transport, _cache_ttl
    transport = MCPTransportSettings()
    auth = build_auth(transport)
    cache_ttl = transport.cache_ttl or None
    hints = build_cache_hints(cache_ttl, "public" if cache_ttl else None)
    mcp.auth = auth
    mcp._mcp_server.cache_hints = {  # noqa: SLF001 - SDK cache configuration
        str(method): hint for method, hint in (hints or {}).items()
    }
    _mcp_transport = transport
    _cache_ttl = cache_ttl
    return transport


def _transport_settings() -> MCPTransportSettings:
    """The validated transport settings, validating and applying them on first use."""
    return _mcp_transport if _mcp_transport is not None else _configure_transport()


def _require() -> tuple[UniFiClient, Registry]:
    if _client is None or _registry is None:
        raise RuntimeError("Server not initialized")
    return _client, _registry


# --- Site Manager Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_hosts(
    page_token: str | None = None,
    page_size: int | None = None,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List all UniFi consoles (hosts) with firmware, WAN IP, and status.

    Returns {data: [host…], _count} with upstream envelope fields, including GPS
    coordinates. data[].id is the long composite id; reportedState.hostname/name is
    the short name. Either identifies host arguments case-insensitively; ambiguous
    names return the matching consoles so the caller can choose an id.

    Default drains all pages in batches of 200. page_size gathers native pages until
    the requested host count or the end; the full final page can exceed the total; _pageSize reports
    requested count, actual sent sizes per request,
    observed effective size and returned count. page_token accepts the unchanged
    native nextToken for one verbatim page, or the opaque _continuation string
    preserving its physical size when the requested total changes.
    Capped drains carry incomplete=true.

    With several keys, the default aggregates all keys, annotates each host with
    _keyLabel, and returns _key_labels, byKey envelopes and per-key errors. key_label
    reads one key and adds _key_labels. Paging with several keys needs key_label.

    Args:
        page_token: Raw nextToken string for one verbatim page, or the returned opaque
            _continuation string preserving physical size when changing page_size.
            Example: the token from the previous response.
        page_size: Requested host count, gathered across effective pages. Omit both
            paging arguments to drain every page. Example: `100`.
        key_label: Configured API-key label from list_configured_api_keys to read one
            key; required with paging when several keys exist. Example: "primary".
    """
    client, registry = _require()
    return await site_manager.list_hosts(
        client, registry, page_token=page_token, page_size=page_size, key_label=key_label
    )


@mcp.tool(annotations=READ_ONLY)
async def get_host(
    host: str,
) -> dict[str, Any]:
    """Get details for a single UniFi console by name or ID.

    Returns the upstream response object verbatim: the host record under data (including
    reportedState GPS coordinates) beside httpStatusCode and traceId.

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts
            (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
            "my-console") or the long data[].id (MAC:numericId composite).
    """
    client, registry = _require()
    return await site_manager.get_host(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def list_sites(
    page_token: str | None = None,
    page_size: int | None = None,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List all sites with device/client counts and ISP info.

    Returns {data: [site...], _count} plus upstream envelope fields. siteId is the
    Site Manager Fabric ObjectId, distinct from per-site proxy UUIDs. Pass site names
    such as "Default" to tools; the server resolves the appropriate id.

    Default drains all pages in batches of 200. page_size gathers native pages until
    the requested site count or the end; the full final page can exceed the total; _pageSize reports
    requested count, actual sent sizes per request,
    observed effective size and returned count. page_token accepts the unchanged
    native nextToken for one verbatim page, or the opaque _continuation string
    preserving its physical size when the requested total changes.
    Capped drains carry incomplete=true.

    With several keys, the default aggregates all keys, annotates each site with
    _keyLabel, and returns _key_labels, byKey envelopes and per-key errors. key_label
    reads one key and adds _key_labels. Paging with several keys needs key_label.

    Args:
        page_token: Raw nextToken string for one verbatim page, or the returned opaque
            _continuation string preserving physical size when changing page_size.
            Example: the token from the previous response.
        page_size: Requested site count, gathered across effective pages. Omit both
            paging arguments to drain every page. Example: `100`.
        key_label: Configured API-key label from list_configured_api_keys to read one
            key; required with paging when several keys exist. Example: "primary".
    """
    client, registry = _require()
    return await site_manager.list_sites(
        client, registry, page_token=page_token, page_size=page_size, key_label=key_label
    )


@mcp.tool(annotations=READ_ONLY)
async def list_devices(
    host: str | None = None,
    page_token: str | None = None,
    time: str | None = None,
    page_size: int | None = None,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List all devices across the fleet with status, firmware, and model.

    Returns {data, _count, _consoleCount} plus upstream envelope fields. data contains
    console wrappers {hostId, hostName, devices: [...]}, unchanged; _count counts their
    devices and _consoleCount counts wrappers. Null/missing/empty devices count as 0.

    Default drains all pages in batches of 200. page_size gathers native pages until
    the requested wrapper count or the end; the full final page can exceed the total; _pageSize
    reports requested count, actual sent sizes per request, observed effective size
    and returned count. page_token accepts native nextToken for one verbatim page,
    or the opaque _continuation string preserving the physical size when the
    requested total changes. Capped drains carry incomplete.

    host filters server-side to that console on its owning key. Without host,
    key_label or paging, several keys are aggregated with _keyLabel per wrapper,
    _key_labels, byKey envelopes and per-key errors. Paging without host needs
    key_label when several keys exist; a single selected key is named in _key_labels.

    Args:
        host: Optional console name or composite id from list_hosts; for example
            "my-console" from reportedState.hostname or its data[].id. Names are case-insensitive.
        page_token: Raw nextToken string for one verbatim page, or the returned opaque
            _continuation string preserving physical size when changing page_size.
            Example: the token from the previous response.
        time: Optional RFC3339 last-processed timestamp, forwarded unchanged as time;
            for example "2026-10-26T00:00:00Z". Omitted when unset.
        page_size: Requested wrapper count, gathered across effective pages.
            Omit both paging arguments to drain all. Example: `100`.
        key_label: Configured API-key label from list_configured_api_keys; required
            with paging and no host when several keys exist. Example: "primary".
    """
    client, registry = _require()
    return await site_manager.list_devices(
        client,
        registry,
        host=host,
        page_token=page_token,
        time=time,
        page_size=page_size,
        key_label=key_label,
    )


@mcp.tool(annotations=READ_ONLY)
async def get_isp_metrics(
    interval: Literal["5m", "1h"],
    duration: str | None = None,
    begin_timestamp: str | None = None,
    end_timestamp: str | None = None,
) -> dict[str, Any]:
    """Get WAN health metrics (speed, latency, packet loss, uptime).

    `interval` ('5m' or '1h') is the metric bucket size. This is the unscoped variant (every
    site the key sees); duration, or begin_timestamp/end_timestamp, bound the time range. To
    scope by console/site, use `query_isp_metrics` instead.

    Returns the upstream body verbatim: {data, httpStatusCode, traceId}. data is a list with
    one object per site, {metricType, hostId, siteId, periods}; each periods[] entry is
    {metricTime, version, data: {wan: {avgLatency, maxLatency, packetLoss, download_kbps,
    upload_kbps, uptime, downtime, ispName, ispAsn}}}. So the WAN values of a site are at
    data[i].periods[j].data.wan.

    In a multi-key deployment every configured key is queried and the result keeps the same
    data path: data holds every key's per-site objects (each with an additive _keyLabel),
    byKey (one entry per key label) holds the rest of that key's body (httpStatusCode,
    traceId), _key_labels lists the keys that answered, and a key that fails is reported
    under errors.

    Args:
        interval: time bucket for metrics aggregation — '5m' or '1h'.
        duration: Optional (query duration): time range ending now — '24h' for 5m metrics, '7d'
            or '30d' for 1h metrics. Cannot be combined with begin_timestamp/end_timestamp.
        begin_timestamp: Optional (query beginTimestamp): earliest time, an RFC3339 string such
            as "2026-07-23T00:00:00Z".
        end_timestamp: Optional (query endTimestamp): latest time, an RFC3339 string.
    """
    client, _ = _require()
    return await site_manager.get_isp_metrics(
        client,
        interval,
        duration=duration,
        begin_timestamp=begin_timestamp,
        end_timestamp=end_timestamp,
    )


@mcp.tool(annotations=READ_ONLY)
async def query_isp_metrics(
    interval: Literal["5m", "1h"],
    host: str | None = None,
    site: str | None = None,
    sites: list[dict | None] | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
) -> dict[str, Any]:
    """Query filtered ISP metrics for one or more scoped sites (via `sites`, or `host`+`site`).

    One of: `sites`, or `host`+`site` (passing both is an error, never a duplicate query).

    This is the filtered variant of `get_isp_metrics`: pass host/site to scope the query and
    start_time/end_time to bound the window. For a quick unscoped read, use `get_isp_metrics`.

    Returns the upstream body verbatim: {data: {metrics, status?, message?}, httpStatusCode,
    traceId}. data.metrics has one object per site, {metricType, hostId, siteId, periods};
    each periods[] entry is {metricTime, version, data: {wan: {...}}}. data.status /
    data.message report a partial success (some sites returned no data).

    In a multi-key deployment each site is queried on the key that owns its console. When
    the sites span several keys the result keeps the same data.metrics path: it holds every
    key's per-site objects (each with an additive _keyLabel), byKey (one entry per key
    label) holds the rest of that key's body verbatim (its data.status / data.message,
    httpStatusCode, traceId),
    _key_labels lists the keys that answered, and a key whose query fails is reported under
    errors (the call fails only when every key fails).

    Required arguments: interval (see each parameter's description).

    Args:
        interval: time bucket for metrics aggregation — '5m' or '1h'.
        host: Optional. Console name or id: the short name from list_hosts
            (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
            "my-console") or the long data[].id (MAC:numericId composite). One console serves both
            Network and Protect. Resolves to hostId.
        site: site name or ID — resolves to siteId automatically.
        sites: advanced use — list of {hostId, siteId} dicts, optionally with per-entry
            beginTimestamp/endTimestamp. hostId may be a console name or id (resolved to the
            id); siteId must be a Site Manager site on that console (from list_sites; a site
            name is resolved too). An unknown console or site fails before the query, listing
            the valid choices; a malformed hostId/siteId (empty, whitespace, control character)
            fails before any request. A null beginTimestamp/endTimestamp is treated as absent
            (start_time/end_time apply). Use host/site instead for a single site. An empty list
            names no site: with host/site those scope the query; alone it is sent as given
            ({"sites": []}) for the upstream to judge, and an upstream error gets a hint
            appended.
            Shape: ({hostId:string,siteId:string,beginTimestamp?:string|null,
            endTimestamp?:string|null}|null)[]
        start_time: ISO 8601 UTC timestamp STRINGS, e.g. "2026-07-23T00:00:00Z". These are strings,
            NOT epoch numbers — passing an epoch integer (seconds or milliseconds) is rejected by
            schema validation with 'Input should be a valid string [type=string_type]'. (Note the
            deliberate inconsistency with the epoch-based history tools: list_protect_events,
            list_client_sessions and get_historical_stats take epoch SECONDS as integers, whereas
            this Site Manager tool takes ISO 8601 strings.) An epoch supplied AS a string (e.g.
            "1690000000000") is also rejected, with the expected format, rather than being forwarded
            to the API as a meaningless window. An empty or
            whitespace-only value is an error, never read as omitted.
        end_time: ISO 8601 UTC timestamp STRINGS, e.g. "2026-07-23T00:00:00Z". These are strings,
            NOT epoch numbers — passing an epoch integer (seconds or milliseconds) is rejected by
            schema validation with 'Input should be a valid string [type=string_type]'. (Note the
            deliberate inconsistency with the epoch-based history tools: list_protect_events,
            list_client_sessions and get_historical_stats take epoch SECONDS as integers, whereas
            this Site Manager tool takes ISO 8601 strings.) An epoch supplied AS a string (e.g.
            "1690000000000") is also rejected, with the expected format, rather than being forwarded
            to the API as a meaningless window. An empty or
            whitespace-only value is an error, never read as omitted.
    """
    client, registry = _require()
    # Every argument (the window, the host/site pair, every sites[] entry) is validated
    # before ANY console/site resolution: a malformed entry anywhere in sites[] fails
    # with zero upstream requests, never after earlier entries were resolved.
    site_manager.validate_isp_query(interval, start_time, end_time)
    entries = site_manager.validate_isp_sites(sites, host, site)
    # Group selectors by their owning key, but resolve each key's sites inside its
    # error boundary so one failed /v1/sites listing cannot abort healthy keys.
    by_key: dict[str | None, tuple[Any, list[dict[str, Any] | None]]] = {}
    routed_entries: dict[int, str | None] = {}
    for index, entry in enumerate(entries):
        if entry is None:
            continue
        owner = await registry.resolve_key_for_host(entry["hostId"])
        label = owner.label if owner is not None else None
        routed_entries[index] = label
        by_key.setdefault(label, (owner, []))[1].append(entry)
    if host and site:
        owner = await registry.resolve_key_for_host(host)
        label = owner.label if owner is not None else None
        by_key.setdefault(label, (owner, []))[1].append({"hostId": host, "siteId": site})
    if any(entry is None for entry in entries):
        if not by_key:
            for label in client.list_key_labels():
                by_key[label] = (client.get_key_by_label(label), [])
        for label, (_owner, group) in by_key.items():
            group[:] = [
                entry
                for index, entry in enumerate(entries)
                if entry is None or routed_entries[index] == label
            ]
    if not by_key:
        by_key[None] = (None, [])
    query_path = f"/v1/isp-metrics/{interval}/query"

    # Resolve every selector before the first metrics request. A query for a healthy
    # key must not race ahead of an invalid selector on another key. Upstream listing
    # failures remain scoped to their key, while invalid selectors fail the whole call.
    async def _resolve(owner: Any, group: list[dict[str, Any] | None]) -> list[Any]:
        resolved: list[dict[str, Any] | None] = []
        for entry in group:
            if entry is None:
                resolved.append(None)
                continue
            host_id = await registry.resolve_host_id(entry["hostId"], key=owner)
            # ISP metrics uses the Fabric ObjectId from /v1/sites, not a proxy UUID.
            site_id = await registry.resolve_ea_site_id(entry["siteId"], host_id=host_id, key=owner)
            resolved.append({**entry, "hostId": host_id, "siteId": site_id})
        return resolved

    resolved_by_key: dict[str | None, list[dict[str, Any] | None]] = {}
    resolution_errors: dict[str | None, Exception] = {}
    outcomes = await asyncio.gather(
        *(_resolve(owner, group) for owner, group in by_key.values()), return_exceptions=True
    )
    for label, outcome in zip(by_key, outcomes, strict=True):
        if not isinstance(outcome, BaseException):
            resolved_by_key[label] = outcome
            continue
        if not isinstance(outcome, Exception):
            raise outcome
        # An invalid selector fails the whole call; a key that could not list its hosts or
        # sites, or listed them only in part, fails only that key's query.
        if isinstance(outcome, ValueError) and not isinstance(
            outcome, (UniFiConnectionError, PartialListingError)
        ):
            raise outcome
        resolution_errors[label] = outcome
        resolved_by_key[label] = []

    async def _query(owner: Any) -> dict[str, Any]:
        label = owner.label if owner is not None else None
        if label in resolution_errors:
            raise resolution_errors[label]
        resolved = resolved_by_key[label]
        body = await site_manager.query_isp_metrics(
            client,
            interval,
            sites=resolved,
            start_time=start_time,
            end_time=end_time,
            key=owner,
        )
        if len(by_key) > 1:
            site_manager.isp_metric_records(body, "POST", query_path, query=True)
        return body

    results, errors, multi = await _keys.fan_out_scopes(
        [(label, owner) for label, (owner, _entries) in by_key.items()], _query
    )
    if not multi:
        return results[0][1]
    return site_manager.merge_isp_metric_bodies(results, errors, query=True)


@mcp.tool(annotations=READ_ONLY)
async def list_sdwan_configs(
    page_token: str | None = None,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List Site Magic (SD-WAN) VPN mesh configurations.

    Returns {data, _count} plus the upstream envelope fields (httpStatusCode, traceId), and
    nextToken when the service returns one; with several keys {data, _count, _key_labels, byKey}
    plus errors; incomplete / incompleteReason on a capped drain.

    In a multi-key deployment without key_label every configured key is queried: results are
    merged, each record carries an additive _keyLabel, and a key that fails is reported under
    errors.

    The published contract declares no pagination parameters or nextToken. By default the server
    follows a nextToken if the service returns one. Pass page_token to fetch a single page manually;
    with several API keys it needs key_label (a cursor belongs to one key's listing). A capped
    drain returns the configs gathered so far with incomplete=true rather than truncating silently.

    Args:
        page_token: Optional pagination cursor (a nextToken if returned by the service) to fetch one
            page manually. Omit it to drain every page and get the complete list.
            Example: the `nextToken` string from a previous response, passed unchanged.
        key_label: Optional configured API-key label (see list_configured_api_keys) to read one
            key. Omit it to cover every key. With several keys configured, page_token needs it;
            without it the call fails listing the labels.
    """
    client, _ = _require()
    return await site_manager.list_sdwan_configs(client, page_token=page_token, key_label=key_label)


@mcp.tool(annotations=READ_ONLY)
async def get_sdwan_config(
    config_id: str,
) -> dict[str, Any]:
    """Get a single SD-WAN configuration by ID.

    Returns the upstream response object verbatim: the configuration under data beside
    httpStatusCode and traceId.
    In a multi-key deployment every configured key is tried and the first that answers is used.

    Example call (get_sdwan_config):
        {"config_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    Args:
        config_id: SD-WAN configuration id (Site Manager). Get it from list_sdwan_configs (id).
    """
    client, _ = _require()
    return await site_manager.get_sdwan_config(client, config_id)


@mcp.tool(annotations=READ_ONLY)
async def get_sdwan_config_status(
    config_id: str,
) -> dict[str, Any]:
    """Get the status of an SD-WAN configuration by ID.

    Returns the upstream response object verbatim: the status under data beside
    httpStatusCode and traceId.
    In a multi-key deployment every configured key is tried and the first that answers is used.

    Example call (get_sdwan_config_status):
        {"config_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    Args:
        config_id: SD-WAN configuration id (Site Manager). Get it from list_sdwan_configs (id).
    """
    client, _ = _require()
    return await site_manager.get_sdwan_config_status(client, config_id)


@mcp.tool(annotations=READ_ONLY)
async def list_all_sites_aggregated() -> dict[str, Any]:
    """List all sites with aggregated health stats from the /v1/sites/ API.

    Result: {data, _count} plus the upstream envelope fields (httpStatusCode, traceId); with several
    keys {data, _count, _key_labels, byKey} plus errors.

    Returns sites merged with health summary: device counts, client counts,
    alerts, and connectivity status in a single call. Every page is drained (multi-key:
    every key, per-key failures under errors); a capped drain is flagged incomplete and is
    never cached for name resolution.
    """
    client, registry = _require()
    return await site_manager.list_all_sites_aggregated(client, registry)


@mcp.tool(annotations=READ_ONLY)
async def get_site_health_summary(
    site: str,
) -> dict[str, Any]:
    """Get a site's health: the Classic /stat/health body, verbatim.

    Returns the controller's {meta, data} envelope unchanged: meta is {rc, msg?} and data has
    one record per subsystem (wan, www, wlan, lan, vpn) with its status and that subsystem's
    counters (e.g. num_adopted / num_disconnected devices, num_user clients, wan latency and
    uptime fields), plus an additive _healthSummary {subsystems: {subsystem: status}, notOk:
    [subsystem…], allOk} derived from data[] (omitted when data has no subsystem records). When
    the site was resolved against a partial Site Manager site list the result adds _incomplete
    and _incompleteReason.

    Args:
        site: Site Manager site name or siteId (list_sites: data[].meta.desc / meta.name, or
            siteId). A name shared by sites on several consoles is rejected with the matches
            listed; pass that siteId then.
    """
    client, registry = _require()
    return await site_manager.get_site_health_summary(client, registry, site)


@mcp.tool(annotations=READ_ONLY)
async def compare_site_performance(
    sites: list[str],
) -> dict[str, Any]:
    """Compare health and performance metrics across multiple sites side-by-side.

    Returns {_comparison, _count}: one comparison entry per site, in the order given, each the
    site's Classic /stat/health body verbatim with its additive _healthSummary (as
    get_site_health_summary returns it) plus an additive _siteLabel, or {_siteLabel, error} for
    a site that failed (the call fails only
    when every site fails). incomplete/incompleteReason name any site resolved against a
    partial site list.

    Args:
        sites: Site Manager site names or siteIds to compare (list_sites: meta.desc / meta.name, or
            siteId); a shared name is reported as an error for that entry — pass the siteId. An
            empty list compares no site: _comparison is empty and no request is sent.
    """
    client, registry = _require()
    return await site_manager.compare_site_performance(client, registry, sites)


@mcp.tool(annotations=READ_ONLY)
async def search_across_sites(
    query: str,
) -> dict[str, Any]:
    """Search for devices or clients matching a query across all sites.

    Returns {data (the matching records), _count, _query, _sitesTotal, _sitesSearched,
    _sitesSucceeded, _sitesFailed, _sitesIncomplete} plus errors and _skipped (sites that could
    not be searched, each with its reason) when present. Each errors entry is an object {key
    (the API-key label), siteId, scope ("devices" / "clients" for a per-site fetch failure;
    "sites" with siteId "" for a key whose site list failed), reason (a string)}. A site whose
    device or client list stopped at
    the UNIFI_PAGINATE_MAX_PAGES cap counts in _sitesIncomplete (not _sitesFailed or
    _sitesSucceeded) and the result carries
    incomplete=true with the reasons. Each match is the upstream record plus additive _type /
    _siteId / _siteName / _hostId (its console), and _keyLabel (the API key that read it) when
    several keys are configured.

    Args:
        query: case-insensitive substring matched against a device's name, macAddress,
            ipAddress or model, or a client's name, macAddress, ipAddress or hostname, e.g.
            "02:00:5e" or "10.0.2.". An empty or whitespace query applies no filter: every
            device and client record of every searched site is returned.
    """
    client, registry = _require()
    return await site_manager.search_across_sites(client, registry, query)


@mcp.tool(annotations=READ_ONLY)
async def get_site_inventory(
    site: str,
    device_filter: str | None = None,
    client_filter: str | None = None,
) -> dict[str, Any]:
    """Get full inventory for a site: all devices and connected clients.

    _devicesEnvelope and _clientsEnvelope hold each list's upstream envelope fields (totalCount,
    ...).

    Returns {_siteId (the console site UUID), _devices, _deviceCount, _clients, _clientCount}
    (the two upstream record lists, verbatim, under additive keys); both
    lists are drained across every page (incomplete=true with the reason only when the opt-in
    UNIFI_PAGINATE_MAX_PAGES cap stops a drain).

    Args:
        site: Site Manager site name or siteId (list_sites: data[].meta.desc / meta.name, or
            siteId). A name shared by sites on several consoles is rejected with the matches
            listed; pass that siteId then.
        device_filter: Optional Network Integration API filter expression, forwarded unchanged as
            the `filter` query parameter of the site's device list. Omitted when unset.
        client_filter: Optional Network Integration API filter expression, forwarded unchanged as
            the `filter` query parameter of the site's client list. Omitted when unset.
    """
    client, registry = _require()
    return await site_manager.get_site_inventory(
        client, registry, site, device_filter=device_filter, client_filter=client_filter
    )


# --- Network Tools ---


@mcp.tool(annotations=READ_ONLY)
async def get_network_application_info(
    host: str,
) -> Any:
    """Get the UniFi Network application version reported by a console.

    Returns the upstream application-info ({applicationVersion, ...}) object verbatim, exactly as
    the API answers it.

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await network.get_network_application_info(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def list_local_sites(
    host: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List sites managed by one UniFi Network application.

    Returns {data, totalCount}: every page is drained; data holds the site records verbatim and
    totalCount is the upstream total (null when none was reported). The first page's other envelope
    fields are kept beside them, and incomplete / incompleteReason are added when a capped drain
    stopped short.

    By default every page is drained and the complete list is returned. Pass
    offset alone to fetch a single page manually (native envelope preserved).
    A capped drain returns the sites gathered so far with incomplete=true rather
    than truncating silently. filter: optional UniFi Integration API filter.

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: Optional UniFi Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter. Omitted entirely when unset.
            Example: `name.eq('Default')`."""
    client, registry = _require()
    return await network.list_local_sites(
        client,
        registry,
        host,
        offset=offset,
        limit=limit,
        filter=filter,
    )


@mcp.tool(annotations=READ_ONLY)
async def list_networks(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all networks/VLANs for a site.

    Returns {data, totalCount}: every page is drained; data holds the network records verbatim and
    totalCount is the upstream total (null when none was reported). The first page's other envelope
    fields are kept beside them, and incomplete / incompleteReason are added when a capped drain
    stopped short.

    Networks are offset-paginated (native default page size 25); by default every page
    is drained and the complete list is returned as {data, totalCount}. Pass offset alone
    for a single manual page. filter: optional Network Integration API filter
    expression, forwarded unchanged as the upstream `filter` query parameter for
    server-side filtering (e.g. `vlanId.eq(100)`, `name.like('*guest*')`,
    `metadata.origin.eq('USER_DEFINED')`); omitted entirely when unset. A capped drain is
    flagged incomplete.

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: Optional Network Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter (e.g. `vlanId.eq(100)`, `name.like('*guest*')`,
            `metadata.origin.eq('USER_DEFINED')`). Omitted entirely when unset.
            Example: `metadata.origin.eq('USER_DEFINED')`."""
    client, registry = _require()
    return await network.list_networks(
        client, registry, host, site, offset=offset, limit=limit, filter=filter
    )


@mcp.tool(annotations=WRITE)
async def create_network(
    host: str,
    site: str,
    network_config: dict[str, Any],
) -> Any:
    """Create a new network/VLAN on a site.

    Returns the upstream response body verbatim: the created network object the API answers with
    (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message, preview: {method, path, params (query parameters), body}} instead).

    Validated locally before the request (a missing field raises ValueError naming it):
    ``management`` — the discriminator the controller validates first. The rest of the
    required schema is management-mode-specific and enforced by the controller.
    `network_config` is sent verbatim. Field names are camelCase exactly as in the spec —
    the IPv4 block is ``ipv4Configuration`` (lower-case v), not ``ipV4Configuration``; there
    is no 'purpose' field in the Network Integration API. For management='GATEWAY' the
    controller also requires name, vlanId (1 only for the default network,
    otherwise 2-4009), enabled, internetAccessEnabled, isolationEnabled,
    cellularBackupEnabled, and ipv4Configuration (e.g. hostIpAddress + prefixLength, with
    required autoScaleEnabled and optional DHCP settings). Optional: zoneId (zone UUID from
    list_firewall_zones_proxy). Read an existing network with get_network to copy a working
    ipv4Configuration shape.

    Network auto-exclusion: UniFi silently adds every new network to the
    ``excluded_networkconf_ids`` of ALL custom-tagged port profiles
    (``tagged_vlan_mgmt == 'custom'``), blackholing the VLAN at the host uplink.
    When that happens this response carries an additive ``_warnings`` entry (code
    ``D12_AUTO_EXCLUSION``) naming each affected profile and the network's Classic
    networkconf ``_id`` (profiles store that ``_id``, not this response's ``id``); run
    ``allow_network_on_port_profile`` on each to restore tagging (it accepts either id).


    Full request shapes are in the parameter schema; detailed examples and workflows:
    docs/TOOL-USAGE.md#create_network.

    Required arguments: host, site, network_config (see parameter descriptions for identifiers).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        network_config: Full object to create; spec Create or update Network. Required: enabled,
            management, name, vlanId. 'management' selects variant: GATEWAY|SWITCH|UNMANAGED.
    """
    client, registry = _require()
    created = await network.create_network(client, registry, host, site, network_config)
    return await network_services_proxy.annotate_auto_exclusions(
        client, registry, host, site, created
    )


@mcp.tool(annotations=READ_ONLY)
async def get_network(
    host: str,
    site: str,
    network_id: str,
) -> Any:
    """Get a single network/VLAN by ID.

    Returns: the network object, verbatim. To change it, edit it and pass it as `network_config` to
    update_network.

    Example call (get_network):
        {
          "host": "my-console",
          "site": "Default",
          "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        network_id: Network/VLAN UUID. Get it from list_networks (data[].id). Network-app UUID — not
            a Protect id.
    """
    client, registry = _require()
    return await network.get_network(client, registry, host, site, network_id)


@mcp.tool(annotations=WRITE)
async def update_network(
    host: str,
    site: str,
    network_id: str,
    network_config: dict[str, Any],
) -> Any:
    """Update an existing network/VLAN.

    Returns the upstream response body verbatim: the updated network object the API answers with
    (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message, preview: {method, path, params (query parameters), body}} instead).

    Request body (Network 10.6.106, PUT /v1/sites/{siteId}/networks/{networkId} (updateNetwork);
    schema "Create or update Network") is passed in `network_config`. Required keys — enabled,
    management, name, vlanId.
    - dhcpGuarding: object (Network DHCP Guarding)
    - enabled: boolean
    - management: string
    - name: string
    - vlanId: integer(int32)
    Variants by `management` — GATEWAY requires cellularBackupEnabled, enabled,
    internetAccessEnabled, ipv4Configuration, isolationEnabled, name, vlanId, management; SWITCH
    requires cellularBackupEnabled, deviceId, enabled, ipv4Configuration, isolationEnabled, name,
    vlanId, management; UNMANAGED requires enabled, name, vlanId, management.

    Example call (update_network):
        {
          "host": "my-console",
          "site": "Default",
          "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "network_config": {
            "management": "GATEWAY",
            "cellularBackupEnabled": true,
            "enabled": true,
            "internetAccessEnabled": true,
            "ipv4Configuration": {
              "autoScaleEnabled": true,
              "hostIpAddress": "192.0.2.1",
              "prefixLength": 24
            },
            "isolationEnabled": true,
            "name": "Office VLAN",
            "vlanId": 20
          }
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        network_id: Network/VLAN UUID. Get it from list_networks (data[].id). Network-app UUID — not
            a Protect id.
        network_config: FULL replacement object (PUT; omitted fields reset); spec Create or update
            Network. Required: enabled, management, name, vlanId. 'management' selects variant:
            GATEWAY|SWITCH|UNMANAGED.
    """
    client, registry = _require()
    return await network.update_network(client, registry, host, site, network_id, network_config)


@mcp.tool(annotations=WRITE)
async def delete_network(
    host: str,
    site: str,
    network_id: str,
    force: bool | None = None,
) -> dict[str, Any]:
    """Delete a network/VLAN.

    Consequence: removes the VLAN and disconnects all clients on that network; there is no undo.

    Network 10.6.106 DELETE /v1/sites/{siteId}/networks/{networkId} (deleteNetwork). The
    spec's optional `force` query parameter is sent only when given.

    Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
    (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is deleted: {status: "dry_run", deleted: false, message,
    response (the preview)}.

    Example call (delete_network):
        {
          "host": "my-console",
          "site": "Default",
          "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        network_id: Network/VLAN UUID. Get it from list_networks (data[].id). Network-app UUID — not
            a Protect id.
        force: Optional spec query parameter `force` (boolean, upstream default false); true asks
            the controller to delete a network that is still referenced. Omitted when unset.
    """
    client, registry = _require()
    response = await network.delete_network(client, registry, host, site, network_id, force=force)
    return deletion_result(f"Network {network_id} deleted.", response)


@mcp.tool(annotations=READ_ONLY)
async def get_network_references(
    host: str,
    site: str,
    network_id: str,
) -> Any:
    """Get all resources referencing a network — useful before deleting to check dependencies.

    Returns {referenceResources: [...]}, one entry per resource type that references the
    network; each entry is returned as {resourceType, referenceCount, references: [...]}
    and each reference as {referenceId}. resourceType is one of CLIENT, DEVICE,
    STATIC_ROUTE, OSPF_ROUTE, NEXT_AI, WIFI, NAT_RULE or SD_WAN (the pinned enum);
    referenceCount is how many resources of that type reference it, and referenceId is
    the id of one of them. The body is passed through as the console sent it.

    The console may return HTTP 500 for some networks; this is an upstream condition.

    Example call (get_network_references):
        {
          "host": "my-console",
          "site": "Default",
          "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        network_id: Network/VLAN UUID. Get it from list_networks (data[].id). Network-app UUID — not
            a Protect id.
    """
    client, registry = _require()
    return await network.get_network_references(client, registry, host, site, network_id)


@mcp.tool(annotations=READ_ONLY)
async def list_lags(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List Link Aggregation Groups (LAGs) on a site.

    Returns {data, totalCount}: every page is drained; data holds the LAG records verbatim and
    totalCount is the upstream total (null when none was reported). The first page's other envelope
    fields are kept beside them, and incomplete / incompleteReason are added when a capped drain
    stopped short.

    Drains all pages by default; pass offset alone for a single manual page. A
    capped drain is flagged incomplete rather than truncated silently.

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: optional UniFi Integration API filter expression.
            Example: `metadata.origin.eq('USER_DEFINED')`."""
    client, registry = _require()
    return await network.list_lags(
        client,
        registry,
        host,
        site,
        offset=offset,
        limit=limit,
        filter=filter,
    )


@mcp.tool(annotations=READ_ONLY)
async def get_lag(
    host: str,
    site: str,
    lag_id: str,
) -> Any:
    """Get one Link Aggregation Group.

    Returns the upstream LAG object verbatim, exactly as the API answers it.

    Example call (get_lag):
        {"host": "my-console", "site": "Default", "lag_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        lag_id: LAG UUID. Get it from list_lags (data[].id).
    """
    client, registry = _require()
    return await network.get_lag(client, registry, host, site, lag_id)


@mcp.tool(annotations=READ_ONLY)
async def list_mc_lag_domains(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List Multi-Chassis Link Aggregation (MC-LAG) domains on a site.

    Returns {data, totalCount}: every page is drained; data holds the MC-LAG domain records verbatim
    and totalCount is the upstream total (null when none was reported). The first page's other
    envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
    drain stopped short.

    Drains all pages by default; pass offset alone for a single manual page. A
    capped drain is flagged incomplete rather than truncated silently.

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: optional UniFi Integration API filter expression.
            Example: `metadata.origin.eq('USER_DEFINED')`."""
    client, registry = _require()
    return await network.list_mc_lag_domains(
        client,
        registry,
        host,
        site,
        offset=offset,
        limit=limit,
        filter=filter,
    )


@mcp.tool(annotations=READ_ONLY)
async def get_mc_lag_domain(
    host: str,
    site: str,
    mc_lag_domain_id: str,
) -> Any:
    """Get one Multi-Chassis Link Aggregation domain.

    Returns the upstream MC-LAG domain object verbatim, exactly as the API answers it.

    Example call (get_mc_lag_domain):
        {
          "host": "my-console",
          "site": "Default",
          "mc_lag_domain_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        mc_lag_domain_id: MC-LAG domain UUID. Get it from list_mc_lag_domains (data[].id).
    """
    client, registry = _require()
    return await network.get_mc_lag_domain(client, registry, host, site, mc_lag_domain_id)


@mcp.tool(annotations=READ_ONLY)
async def list_switch_stacks(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List switch stacks on a site.

    Returns {data, totalCount}: every page is drained; data holds the switch stack records verbatim
    and totalCount is the upstream total (null when none was reported). The first page's other
    envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
    drain stopped short.

    Drains all pages by default; pass offset alone for a single manual page. A
    capped drain is flagged incomplete rather than truncated silently.

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: optional UniFi Integration API filter expression.
            Example: `metadata.origin.eq('USER_DEFINED')`."""
    client, registry = _require()
    return await network.list_switch_stacks(
        client,
        registry,
        host,
        site,
        offset=offset,
        limit=limit,
        filter=filter,
    )


@mcp.tool(annotations=READ_ONLY)
async def get_switch_stack(
    host: str,
    site: str,
    switch_stack_id: str,
) -> Any:
    """Get one switch stack.

    Returns the upstream switch stack object verbatim, exactly as the API answers it.

    Example call (get_switch_stack):
        {
          "host": "my-console",
          "site": "Default",
          "switch_stack_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        switch_stack_id: Switch stack UUID. Get it from list_switch_stacks (data[].id).
    """
    client, registry = _require()
    return await network.get_switch_stack(client, registry, host, site, switch_stack_id)


@mcp.tool(annotations=READ_ONLY)
async def list_wifi_broadcasts(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all WiFi broadcast SSIDs for a site.

    Returns {data, totalCount} with every page drained (the API pages at 25 by default).
    Pass offset alone to fetch a single manual page (native envelope preserved).

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: optional Network Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter for server-side filtering (e.g. `enabled.eq(true)`,
            `name.like('*Guest*')`); omitted entirely when unset.
            Example: `metadata.origin.eq('USER_DEFINED')`."""
    client, registry = _require()
    return await network.list_wifi_broadcasts(
        client, registry, host, site, offset=offset, limit=limit, filter=filter
    )


@mcp.tool(annotations=WRITE)
async def create_wifi_broadcast(
    host: str,
    site: str,
    broadcast: dict[str, Any],
) -> Any:
    """Create a new WiFi broadcast SSID on a site.

    Returns the upstream response body verbatim: the created WiFi broadcast object the API
    answers
    with (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message,
    preview: {method, path, params (query parameters), body}} instead).

    Validated locally before the request (a missing field raises ValueError naming it):
    ``type`` — the discriminator the controller validates first (observed value:
    'STANDARD'). The remaining fields are type-specific and enforced by the controller.
    `broadcast`: its parameter description lists the keys each ``type`` requires
    ("Variants by type"; STANDARD and IOT_OPTIMIZED differ). Field names are camelCase.
    For an open SSID use securityConfiguration: {type: "OPEN"} and an explicit network
    reference: network: {type: "SPECIFIC", networkId: UUID from list_networks}. The spec
    permits omitting network, but the live controller requires it for OPEN broadcasts.
    An access point carries a limited number of SSIDs: when the controller refuses with HTTP
    400 too-many-wifi-broadcasts, the error keeps its whole body and adds a hint to scope
    the SSID with broadcastingDeviceFilter.

    Full request shapes are in the parameter schema; detailed examples and workflows:
    docs/TOOL-USAGE.md#create_wifi_broadcast.

    Required arguments: host, site, broadcast (see parameter descriptions for identifiers).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        broadcast: Full object to create; spec Wifi broadcast create or update. 'type' selects
            variant: IOT_OPTIMIZED|STANDARD.
    """
    client, registry = _require()
    return await network.create_wifi_broadcast(client, registry, host, site, broadcast)


@mcp.tool(annotations=READ_ONLY)
async def get_wifi_broadcast(
    host: str,
    site: str,
    broadcast_id: str,
) -> Any:
    """Get a single WiFi broadcast SSID by ID.

    Returns: the WiFi broadcast object, verbatim. To change it, edit it and pass it as `broadcast`
    to update_wifi_broadcast.

    Example call (get_wifi_broadcast):
        {
          "host": "my-console",
          "site": "Default",
          "broadcast_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        broadcast_id: WiFi broadcast (SSID) UUID. Get it from list_wifi_broadcasts (data[].id).
            Network-app UUID — not a Protect id.
    """
    client, registry = _require()
    return await network.get_wifi_broadcast(client, registry, host, site, broadcast_id)


@mcp.tool(annotations=WRITE)
async def update_wifi_broadcast(
    host: str,
    site: str,
    broadcast_id: str,
    broadcast: dict[str, Any],
) -> Any:
    """Update an existing WiFi broadcast SSID.

    Returns the upstream response body verbatim: the updated WiFi broadcast object the API
    answers
    with (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message,
    preview: {method, path, params (query parameters), body}} instead).


    For an open SSID use securityConfiguration: {type: "OPEN"} and an explicit network
    reference: network: {type: "SPECIFIC", networkId: UUID from list_networks}. Retain that
    reference in the full replacement object; the live controller requires it for OPEN.

    Full request shapes are in the parameter schema; detailed examples and workflows:
    docs/TOOL-USAGE.md#update_wifi_broadcast.

    Required arguments: host, site, broadcast_id, broadcast (see parameter descriptions for
    identifiers).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        broadcast_id: WiFi broadcast (SSID) UUID. Get it from list_wifi_broadcasts (data[].id).
            Network-app UUID — not a Protect id.
        broadcast: FULL replacement object (PUT; omitted fields reset); spec Wifi broadcast create
            or update. 'type' selects variant: IOT_OPTIMIZED|STANDARD.
    """
    client, registry = _require()
    return await network.update_wifi_broadcast(
        client, registry, host, site, broadcast_id, broadcast
    )


@mcp.tool(annotations=WRITE)
async def delete_wifi_broadcast(
    host: str,
    site: str,
    broadcast_id: str,
    force: bool | None = None,
) -> dict[str, Any]:
    """Delete a WiFi broadcast SSID.

    Consequence: the SSID stops broadcasting and its connected clients are disconnected; there is no
    undo.

    Network 10.6.106 DELETE /v1/sites/{siteId}/wifi/broadcasts/{wifiBroadcastId}
    (deleteWifiBroadcast). The spec's optional `force` query parameter is sent only when given.

    Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
    (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is deleted: {status: "dry_run", deleted: false, message,
    response (the preview)}.

    Example call (delete_wifi_broadcast):
        {
          "host": "my-console",
          "site": "Default",
          "broadcast_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        broadcast_id: WiFi broadcast (SSID) UUID. Get it from list_wifi_broadcasts (data[].id).
            Network-app UUID — not a Protect id.
        force: Optional spec query parameter `force` (boolean, upstream default false); true asks
            the controller to delete a broadcast that is still referenced. Omitted when unset.
    """
    client, registry = _require()
    response = await network.delete_wifi_broadcast(
        client, registry, host, site, broadcast_id, force=force
    )
    return deletion_result(f"WiFi broadcast {broadcast_id} deleted.", response)


@mcp.tool(annotations=READ_ONLY)
async def list_wan_interfaces(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List WAN interfaces for a site.

    Returns: {data: [wan…], totalCount, _health}. data is the Integration WAN list, entries verbatim
    (every page drained; incomplete/incompleteReason when a capped drain stopped short; with offset
    alone, that single page in its native envelope, plus _health, and a page the upstream
    answers as a bare array is returned as that array, without _health); totalCount is the upstream
    total of that list (null when the upstream reports none). The additive _health is the Classic
    /stat/health body verbatim ({meta: {rc}, data: [...]}, every subsystem; the WAN health entries
    are its data[] entries with subsystem "wan"). When the stat/health read fails, the additive
    _wanHealthError carries the reason (and _health is the body received, if any) — the interfaces
    are still returned. To change one, pass the native Classic networkconf fields to change (e.g.
    wan_load_balance_weight, wan_failover_priority, wan_dns1) as `wan` to update_wan_interface
    (wan_id = its data[] id).

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`."""
    client, registry = _require()
    return await network.list_wan_interfaces(
        client, registry, host, site, offset=offset, limit=limit
    )


@mcp.tool(annotations=WRITE)
async def update_wan_interface(
    host: str,
    site: str,
    wan_id: str,
    wan: dict[str, Any],
) -> Any:
    """Update a WAN interface configuration.

    A WAN interface is a Classic REST networkconf record of purpose wan, written with PUT
    /proxy/network/api/s/{site}/rest/networkconf/{_id} (the route the controller's own UI uses;
    the published Integration API serves WANs GET-only, PUT answers HTTP 404 "No endpoint" on
    Network 11.0.81). The id is resolved among the site's wan records first; an unknown id fails
    listing every WAN with both ids. Send only the fields to change: the Classic PUT merges them
    into the stored record.

    Returns: the upstream body verbatim, the Classic envelope {meta: {rc}, data: [the updated
    networkconf record]}.
    Under UNIFI_DRY_RUN nothing is sent: the result is the bare dry-run preview {status: "dry_run",
    dryRun: true, sent: false,
    message, preview: {method, path, params, body}} in place of the upstream body.

    Example call (update_wan_interface):
        {
          "host": "my-console",
          "site": "Default",
          "wan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "wan": {"wan_load_balance_weight": 50}
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        wan_id: WAN interface id. Get it from list_wan_interfaces (data[].id); the Classic
            networkconf _id also works. Network-app UUID — not a Protect id.
        wan: Native Classic networkconf fields to change, e.g. name, wan_type, wan_dns1,
            wan_load_balance_weight, wan_failover_priority, wan_vlan_enabled. Sent unchanged
            (empty-string list placeholders dropped); an absent or null purpose is sent as
            wan, another is sent as given (an upstream error then gets a hint).
            Free-form JSON object; no fixed body shape is published.
    """
    client, registry = _require()
    return await network.update_wan_interface(client, registry, host, site, wan_id, wan)


protect_private.register(mcp, _require)
device_mgmt.register(mcp, _require)
device_commands.register(mcp, _require)
scheduled_tasks.register(mcp, _require)
device_radios.register(mcp, _require)
network_wifi_radio.register(mcp, _require)
network_nat_qos_traffic.register(mcp, _require)
clients.register(mcp, _require)
network_clients_guests.register(mcp, _require)
network_switching_power.register(mcp, _require)
protect_camera_recording.register(mcp, _require)
network_controller_admin.register(mcp, _require)
network_routing_topology.register(mcp, _require)
matter.register(mcp, _require)


# --- Firewall Policy Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_firewall_policies(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List firewall policies for a site.

    Returns {data, totalCount}: every page is drained; data holds the firewall policy records
    verbatim and totalCount is the upstream total (null when none was reported). The first page's
    other envelope fields are kept beside them, and incomplete / incompleteReason are added when a
    capped drain stopped short.

    By default every page is drained and the complete policy list is returned as
    {data, totalCount}. Pass offset alone to fetch a single page manually (the
    API's totalCount is surfaced so you can advance). filter: optional Network
    Integration API filter expression, forwarded unchanged as the upstream `filter`
    query parameter for server-side filtering (e.g. `name.like('*guest*')`,
    `metadata.origin.eq('USER_DEFINED')`); omitted entirely when unset. A capped drain
    returns the policies gathered so far with incomplete=true rather than truncating
    silently.

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: Optional Network Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter for server-side filtering (e.g.
            `name.like('*guest*')`). Omitted entirely when unset.
            Example: `metadata.origin.eq('USER_DEFINED')`."""
    client, registry = _require()
    return await firewall_proxy.list_firewall_policies(
        client, registry, host, site, offset, limit, filter=filter
    )


@mcp.tool(annotations=WRITE)
async def create_firewall_policy(
    host: str,
    site: str,
    policy: dict[str, Any],
) -> Any:
    """Create a new firewall policy on a site.

    Returns the upstream response body verbatim: the created firewall policy object the API
    answers
    with (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message,
    preview: {method, path, params (query parameters), body}} instead).

    The seven required keys of `policy` (name, enabled, loggingEnabled, action, source,
    destination, ipProtocolScope) are validated locally — a missing key raises ValueError
    naming it. action.type is ALLOW, BLOCK, or REJECT (ALLOW also requires
    allowReturnTraffic); ipProtocolScope.ipVersion is IPV4, IPV6, or IPV4_AND_IPV6. There is
    NO 'index' field; use set_firewall_policy_ordering to manage rule order. Get zone IDs
    from list_firewall_zones_proxy (data[].id; match zone names case-insensitively).

    For port-only destination matching use destination.trafficFilter type PORT; for combined
    address and port matching use type IP_ADDRESS with portFilter. A source portFilter
    matches ephemeral source ports. Get zone UUIDs from list_firewall_zones_proxy.
    Use set_firewall_policy_ordering; there is no index field. action.type is ALLOW (requires
    allowReturnTraffic), BLOCK or REJECT; ipProtocolScope.ipVersion is IPV4, IPV6 or
    IPV4_AND_IPV6. Parameter schemas contain the complete trafficFilter variants and body shape.
    Detailed examples: docs/TOOL-USAGE.md#create_firewall_policy.

    Required arguments: host, site, policy (see parameter descriptions for identifiers).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        policy: Full policy, schema "Create or update firewall policy". Required: name, enabled,
            loggingEnabled, action{type:ALLOW|BLOCK|REJECT}, source{zoneId}, destination{zoneId},
            ipProtocolScope{ipVersion}.
    """
    client, registry = _require()
    return await firewall_proxy.create_firewall_policy(client, registry, host, site, policy)


@mcp.tool(annotations=READ_ONLY)
async def get_firewall_policy(
    host: str,
    site: str,
    policy_id: str,
) -> Any:
    """Get a single firewall policy by ID.

    Returns: the firewall policy object, verbatim. To change it, edit it and pass it as `policy` to
    update_firewall_policy (full replace); patch_firewall_policy takes only the fields its schema
    allows, as `fields`.

    Example call (get_firewall_policy):
        {
          "host": "my-console",
          "site": "Default",
          "policy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        policy_id: Firewall policy UUID. Get it from list_firewall_policies (data[].id). Network-app
            UUID — not a Protect id.
    """
    client, registry = _require()
    return await firewall_proxy.get_firewall_policy(client, registry, host, site, policy_id)


@mcp.tool(annotations=WRITE)
async def update_firewall_policy(
    host: str,
    site: str,
    policy_id: str,
    policy: dict[str, Any],
) -> Any:
    """Full-replace a firewall policy by ID.

    Returns the upstream response body verbatim: the replaced firewall policy object the API
    answers
    with (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message,
    preview: {method, path, params (query parameters), body}} instead).

    For port-only destination matching use destination.trafficFilter type PORT; for combined
    address and port matching use type IP_ADDRESS with portFilter. A source portFilter
    matches ephemeral source ports. Get zone UUIDs from list_firewall_zones_proxy.
    Use set_firewall_policy_ordering; there is no index field. action.type is ALLOW (requires
    allowReturnTraffic), BLOCK or REJECT; ipProtocolScope.ipVersion is IPV4, IPV6 or
    IPV4_AND_IPV6. Full replacement: get_firewall_policy, edit and send the entire object;
    omitted optional fields are cleared. Parameter schemas contain the complete trafficFilter
    variants and body shape. Detailed examples: docs/TOOL-USAGE.md#update_firewall_policy.

    Required arguments: host, site, policy_id, policy (see parameter descriptions for
    identifiers).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        policy_id: Firewall policy UUID. Get it from list_firewall_policies (data[].id). Network-app
            UUID — not a Protect id.
        policy: Complete official firewall policy object. Fetch it with get_firewall_policy;
            omitted optional fields are cleared by this PUT.
    """
    client, registry = _require()
    return await firewall_proxy.update_firewall_policy(
        client, registry, host, site, policy_id, policy
    )


@mcp.tool(annotations=WRITE)
async def patch_firewall_policy(
    host: str,
    site: str,
    policy_id: str,
    fields: dict[str, Any],
) -> Any:
    """Partially update a firewall policy by ID.

    Returns the upstream response body verbatim: the updated firewall policy object the API answers
    with (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message,
    preview: {method, path, params (query parameters), body}} instead).

    Request body (Network 10.6.106, PATCH /v1/sites/{siteId}/firewall/policies/{firewallPolicyId}
    (patchFirewallPolicy); schema "Patch firewall policy") is passed in `fields`. No key is
    required; send only the keys to change.
    - loggingEnabled: boolean
    Only loggingEnabled is patchable per spec; enabled/name/action changes need
    update_firewall_policy (full PUT).

    Example call (patch_firewall_policy):
        {
          "host": "my-console",
          "site": "Default",
          "policy_id": "7d1e4a52-1c3b-4f6e-8a90-0b1c2d3e4f01",
          "fields": {"loggingEnabled": true}
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        policy_id: Firewall policy UUID. Get it from list_firewall_policies (data[].id). Network-app
            UUID — not a Protect id.
        fields: Partial update. Spec "Patch firewall policy" defines ONLY loggingEnabled (boolean).
            For any other change use update_firewall_policy.
    """
    client, registry = _require()
    return await firewall_proxy.patch_firewall_policy(
        client, registry, host, site, policy_id, fields
    )


@mcp.tool(annotations=WRITE)
async def delete_firewall_policy(
    host: str,
    site: str,
    policy_id: str,
) -> dict[str, Any]:
    """Delete a firewall policy.

    Consequence: the policy stops applying immediately, so traffic it allowed or blocked falls
    through to the remaining policies; there is no undo.

    Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
    (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is deleted: {status: "dry_run", deleted: false, message,
    response (the preview)}.

    Example call (delete_firewall_policy):
        {
          "host": "my-console",
          "site": "Default",
          "policy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        policy_id: Firewall policy UUID. Get it from list_firewall_policies (data[].id). Network-app
            UUID — not a Protect id.
    """
    client, registry = _require()
    response = await firewall_proxy.delete_firewall_policy(client, registry, host, site, policy_id)
    return deletion_result(f"Firewall policy {policy_id} deleted.", response)


@mcp.tool(annotations=READ_ONLY)
async def get_firewall_policy_ordering(
    host: str,
    site: str,
    source_zone_id: str,
    destination_zone_id: str,
) -> Any:
    """Get the ordering of firewall policies for a site filtered by source and destination zone.

    Returns: {"orderedFirewallPolicyIds": {"beforeSystemDefined": [policy id…],
    "afterSystemDefined": [policy id…]}}, verbatim — the user-defined order for this zone pair. Pass
    it verbatim (reordered, or unchanged for a no-op) as `ordering` to set_firewall_policy_ordering
    with the same source_zone_id and destination_zone_id.
    Ordering is per source/destination zone pair: find the pairs that have policies by
    calling list_firewall_policies and grouping data[] by source.zoneId /
    destination.zoneId (its `filter` narrows it, e.g. metadata.origin.eq('USER_DEFINED')).

    Prerequisite — {"tool": "list_firewall_zones_proxy", "arguments": {"host": "my-console", "site":
    "Default"}, "use": "data[].id of the source and destination zones"}.

    Example call (get_firewall_policy_ordering):
        {
          "host": "my-console",
          "site": "Default",
          "source_zone_id": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01",
          "destination_zone_id": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d02"
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        source_zone_id: REQUIRED source firewall zone UUID, sent as query param
            sourceFirewallZoneId. Get it from list_firewall_zones_proxy (data[].id); pick the zone
            by name case-insensitively (e.g. Internal, External). Network UUID.
        destination_zone_id: REQUIRED destination firewall zone UUID, sent as query param
            destinationFirewallZoneId. Get it from list_firewall_zones_proxy (data[].id); pick the
            zone by name case-insensitively (e.g. Internal, External). Network UUID.
    """
    client, registry = _require()
    return await firewall_proxy.get_firewall_policy_ordering(
        client, registry, host, site, source_zone_id, destination_zone_id
    )


@mcp.tool(annotations=WRITE)
async def set_firewall_policy_ordering(
    host: str,
    site: str,
    source_zone_id: str,
    destination_zone_id: str,
    ordering: dict[str, Any],
) -> Any:
    """Set the ordering of firewall policies within one source/destination zone pair.

    Returns: the controller's response, verbatim — the resulting order in the same
    {"orderedFirewallPolicyIds": {"beforeSystemDefined": […], "afterSystemDefined": […]}} shape
    (published response schema IntegrationFirewallPolicyOrderingDto).
    Under UNIFI_DRY_RUN nothing is sent: the result is the bare dry-run preview {status: "dry_run",
    dryRun: true, sent: false,
    message, preview: {method, path, params, body}} in place of the upstream body.

    Full replace of the user-defined order for ONE source/destination zone pair: start from
    get_firewall_policy_ordering for the same pair, reorder, and send it back. Use [] for an empty
    side. Afterwards, read back with get_firewall_policy_ordering and compare. If either zone id is
    missing, upstream returns HTTP 400 (the zone ids are query parameters, never read from the
    body).

    Example call (set_firewall_policy_ordering):
        {"host": "my-console", "site": "Default",
         "source_zone_id": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d01",
         "destination_zone_id": "0b6c3c4e-6a0f-4f3e-9a51-6a2b8f0c1d02",
         "ordering": {"orderedFirewallPolicyIds": {
           "beforeSystemDefined": ["7d1e4a52-1c3b-4f6e-8a90-0b1c2d3e4f02"],
           "afterSystemDefined": []}}}

    Full request shapes are in the parameter schema; detailed examples and workflows:
    docs/TOOL-USAGE.md#set_firewall_policy_ordering.

    Required arguments: host, site, source_zone_id, destination_zone_id, ordering (see parameter
    descriptions for identifiers).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        source_zone_id: REQUIRED source firewall zone UUID, sent as query param
            sourceFirewallZoneId. Get it from list_firewall_zones_proxy (data[].id); pick the zone
            by name case-insensitively (e.g. Internal, External). Network UUID.
        destination_zone_id: REQUIRED destination firewall zone UUID, sent as query param
            destinationFirewallZoneId. Get it from list_firewall_zones_proxy (data[].id); pick the
            zone by name case-insensitively (e.g. Internal, External). Network UUID.
        ordering: Full replacement
            {"orderedFirewallPolicyIds":{"beforeSystemDefined":[uuid…],"afterSystemDefined":[uuid…]}};
            both arrays required. Start from get_firewall_policy_ordering output.
    """
    client, registry = _require()
    return await firewall_proxy.set_firewall_policy_ordering(
        client, registry, host, site, source_zone_id, destination_zone_id, ordering
    )


# --- Firewall Zone Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_firewall_zones_proxy(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all firewall zones for a site via connector proxy.

    This is the firewall-zone list; the _proxy suffix is historical. Returns {data: [{id, name,
    networkIds, metadata: {origin, configurable}}], totalCount}. System-defined zones
    (metadata.origin SYSTEM_DEFINED) carry the names the controller returns — Internal, External,
    Gateway, Vpn, Hotspot and Dmz on Network 11.0.81 — so compare zone names case-insensitively
    ("VPN" matches "Vpn"). Every other tool takes a zone by its id (data[].id), never by name.

    Zones are offset-paginated (native default page size 25); by default every page is
    drained and the complete list is returned as {data, totalCount}. Pass offset alone for a
    single manual page. A capped drain is flagged incomplete.

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: Optional Network Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter for server-side filtering (e.g.
            `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
            when paging manually.
            Example: `metadata.origin.eq('USER_DEFINED')`."""
    client, registry = _require()
    return await firewall_proxy.list_firewall_zones(
        client, registry, host, site, offset=offset, limit=limit, filter=filter
    )


@mcp.tool(annotations=WRITE)
async def create_firewall_zone_proxy(
    host: str,
    site: str,
    zone: dict[str, Any],
) -> Any:
    """Create a new firewall zone on a site via connector proxy.

    Returns the upstream response body verbatim: the created firewall zone object the API answers
    with (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message,
    preview: {method, path, params (query parameters), body}} instead).

    `zone`: must include {'name': str, 'networkIds': [str]} — both required, validated
    locally (a missing field raises ValueError naming it) and verified against the live
    controller. Get network IDs from list_networks.

    Request body (Network 10.6.106, POST /v1/sites/{siteId}/firewall/zones (createFirewallZone);
    schema "Create or update firewall zone") is passed in `zone`. Required keys — name, networkIds.
    - name: string
    - networkIds: array of string (uuid)

    Example call (create_firewall_zone_proxy):
        {
          "host": "my-console",
          "site": "Default",
          "zone": {"name": "Hotspot", "networkIds": ["dfb21062-8ea0-4dca-b1d8-1eb3da00e58b"]}
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        zone: Full object to create; spec Create or update firewall zone. Required: name,
            networkIds.
    """
    client, registry = _require()
    return await firewall_proxy.create_firewall_zone(client, registry, host, site, zone)


@mcp.tool(annotations=READ_ONLY)
async def get_firewall_zone_proxy(
    host: str,
    site: str,
    zone_id: str,
) -> Any:
    """Get a single firewall zone by ID via connector proxy.

    Returns: the firewall zone object, verbatim. To change it, edit it and pass it as `zone` to
    update_firewall_zone_proxy.

    Example call (get_firewall_zone_proxy):
        {"host": "my-console", "site": "Default", "zone_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        zone_id: Firewall zone UUID. Get it from list_firewall_zones_proxy (data[].id). Network-app
            UUID — not a Protect id.
    """
    client, registry = _require()
    return await firewall_proxy.get_firewall_zone(client, registry, host, site, zone_id)


@mcp.tool(annotations=WRITE)
async def update_firewall_zone_proxy(
    host: str,
    site: str,
    zone_id: str,
    zone: dict[str, Any],
) -> Any:
    """Update a firewall zone by ID via connector proxy.

    Returns the upstream response body verbatim: the updated firewall zone object the API answers
    with (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message,
    preview: {method, path, params (query parameters), body}} instead).

    Request body (Network 10.6.106, PUT /v1/sites/{siteId}/firewall/zones/{firewallZoneId}
    (updateFirewallZone); schema "Create or update firewall zone") is passed in `zone`. Required
    keys — name, networkIds.
    - name: string
    - networkIds: array of string (uuid)

    Example call (update_firewall_zone_proxy):
        {
          "host": "my-console",
          "site": "Default",
          "zone_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "zone": {"name": "Hotspot", "networkIds": ["dfb21062-8ea0-4dca-b1d8-1eb3da00e58b"]}
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        zone_id: Firewall zone UUID. Get it from list_firewall_zones_proxy (data[].id). Network-app
            UUID — not a Protect id.
        zone: FULL replacement object (PUT; omitted fields reset); spec Create or update firewall
            zone. Required: name, networkIds.
    """
    client, registry = _require()
    return await firewall_proxy.update_firewall_zone(client, registry, host, site, zone_id, zone)


@mcp.tool(annotations=WRITE)
async def delete_firewall_zone_proxy(
    host: str,
    site: str,
    zone_id: str,
) -> dict[str, Any]:
    """Delete a firewall zone via connector proxy.

    Consequence: the zone is permanently removed; there is no undo.

    Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
    (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is deleted: {status: "dry_run", deleted: false, message,
    response (the preview)}.

    Example call (delete_firewall_zone_proxy):
        {"host": "my-console", "site": "Default", "zone_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        zone_id: Firewall zone UUID. Get it from list_firewall_zones_proxy (data[].id). Network-app
            UUID — not a Protect id.
    """
    client, registry = _require()
    response = await firewall_proxy.delete_firewall_zone(client, registry, host, site, zone_id)
    return deletion_result(f"Firewall zone {zone_id} deleted.", response)


# --- ACL Rule Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_acl_rules(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all ACL rules for a site.

    ACL rules include IPv4 network-layer (L3) and MAC access lists, used to filter traffic
    between networks or within a VLAN. Use them only when the user asks for ACL rules; for an
    ordinary firewall rule use zone-based firewall policies (create_firewall_policy).

    Returns {data, totalCount} with every page drained (the API pages at 25 by default).
    Pass offset alone to fetch a single manual page (native envelope preserved).

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: Optional Network Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter for server-side filtering (e.g.
            `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
            when paging manually.
            Example: `metadata.origin.eq('USER_DEFINED')`."""
    client, registry = _require()
    return await firewall_proxy.list_acl_rules(
        client, registry, host, site, offset=offset, limit=limit, filter=filter
    )


@mcp.tool(annotations=WRITE)
async def create_acl_rule(
    host: str,
    site: str,
    rule: dict[str, Any],
) -> Any:
    """Create a new ACL rule on a site.

    Returns the upstream response body verbatim: the created ACL rule object the API answers with
    (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message, preview: {method, path, params (query parameters), body}} instead).

    Validated locally before the request (a missing field raises ValueError naming it):
    ``type`` — the discriminator the controller validates first (verified live: an empty
    body is rejected with ``Missing $.type value``; observed value: 'MAC'). The remaining
    fields are type-specific and enforced by the controller.
    `rule`: for a MAC-type rule the live object also carries: name (str), action, enabled
    (bool), sourceFilter, networkIdFilter. Read an existing rule with get_acl_rule to see
    the exact shape for the type you want.
    Note: ACL rules include IPv4 network-layer (L3) and MAC access lists for filtering traffic
    between networks or within a VLAN. Use them only when the user asks for ACL rules; otherwise
    use zone-based firewall policies (create_firewall_policy).

    Request body (Network 10.6.106, POST /v1/sites/{siteId}/acl-rules (createAclRule); schema "ACL
    rule update") is passed in `rule`. Required keys — action, enabled, name, type.
    - action: enum[ALLOW|BLOCK]
    - description: string
    - destinationFilter: any
    - enabled: boolean
    - enforcingDeviceFilter: oneOf by type[DEVICES] (ACL rule device filter)
    - index: integer(int32)
    - name: string
    - sourceFilter: any
    - type: string
    Variants by `type` — IPV4 requires action, enabled, name, type; MAC requires action, enabled,
    name, networkIdFilter, type.

    Example call (create_acl_rule):
        {
          "host": "my-console",
          "site": "Default",
          "rule": {
            "type": "IPV4",
            "action": "ALLOW",
            "enabled": true,
            "name": "Allow printer access"
          }
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        rule: Full object to create; spec ACL rule update. Required: action, enabled, name, type.
            'type' selects variant: IPV4|MAC.
    """
    client, registry = _require()
    return await firewall_proxy.create_acl_rule(client, registry, host, site, rule)


@mcp.tool(annotations=READ_ONLY)
async def get_acl_rule(
    host: str,
    site: str,
    rule_id: str,
) -> Any:
    """Get a single ACL rule by ID.

    Returns: the ACL rule object, verbatim. To change it, edit it and pass it as `rule` to
    update_acl_rule.

    Example call (get_acl_rule):
        {"host": "my-console", "site": "Default", "rule_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        rule_id: ACL rule UUID. Get it from list_acl_rules (data[].id). Network-app UUID — not a
            Protect id.
    """
    client, registry = _require()
    return await firewall_proxy.get_acl_rule(client, registry, host, site, rule_id)


@mcp.tool(annotations=WRITE)
async def update_acl_rule(
    host: str,
    site: str,
    rule_id: str,
    rule: dict[str, Any],
) -> Any:
    """Update an existing ACL rule by ID.

    Returns the upstream response body verbatim: the updated ACL rule object the API answers with
    (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message, preview: {method, path, params (query parameters), body}} instead).

    Request body (Network 10.6.106, PUT /v1/sites/{siteId}/acl-rules/{aclRuleId} (updateAclRule);
    schema "ACL rule update") is passed in `rule`. Required keys — action, enabled, name, type.
    - action: enum[ALLOW|BLOCK]
    - description: string
    - destinationFilter: any
    - enabled: boolean
    - enforcingDeviceFilter: oneOf by type[DEVICES] (ACL rule device filter)
    - index: integer(int32)
    - name: string
    - sourceFilter: any
    - type: string
    Variants by `type` — IPV4 requires action, enabled, name, type; MAC requires action, enabled,
    name, networkIdFilter, type.

    Example call (update_acl_rule):
        {
          "host": "my-console",
          "site": "Default",
          "rule_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "rule": {
            "type": "IPV4",
            "action": "ALLOW",
            "enabled": true,
            "name": "Allow printer access"
          }
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        rule_id: ACL rule UUID. Get it from list_acl_rules (data[].id). Network-app UUID — not a
            Protect id.
        rule: FULL replacement object (PUT; omitted fields reset); spec ACL rule update. Required:
            action, enabled, name, type. 'type' selects variant: IPV4|MAC.
    """
    client, registry = _require()
    return await firewall_proxy.update_acl_rule(client, registry, host, site, rule_id, rule)


@mcp.tool(annotations=WRITE)
async def delete_acl_rule(
    host: str,
    site: str,
    rule_id: str,
) -> dict[str, Any]:
    """Delete an ACL rule.

    Consequence: the rule stops filtering traffic immediately; there is no undo (recreate it from a
    saved copy).

    Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
    (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is deleted: {status: "dry_run", deleted: false, message,
    response (the preview)}.

    Example call (delete_acl_rule):
        {"host": "my-console", "site": "Default", "rule_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        rule_id: ACL rule UUID. Get it from list_acl_rules (data[].id). Network-app UUID — not a
            Protect id.
    """
    client, registry = _require()
    response = await firewall_proxy.delete_acl_rule(client, registry, host, site, rule_id)
    return deletion_result(f"ACL rule {rule_id} deleted.", response)


@mcp.tool(annotations=READ_ONLY)
async def get_acl_rule_ordering(
    host: str,
    site: str,
) -> Any:
    """Get the ordering of ACL rules for a site.

    Returns: {"orderedAclRuleIds": [rule id…]}, verbatim, in evaluation order. Pass it verbatim
    (reordered, or unchanged for a no-op) as `ordering` to set_acl_rule_ordering.

    Example call (get_acl_rule_ordering):
        {"host": "my-console", "site": "Default"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await firewall_proxy.get_acl_rule_ordering(client, registry, host, site)


@mcp.tool(annotations=WRITE)
async def set_acl_rule_ordering(
    host: str,
    site: str,
    ordering: dict[str, Any],
) -> Any:
    """Set the ordering of ACL rules for a site.

    Returns: the controller's response, verbatim — the resulting order in the same
    {"orderedAclRuleIds": […]} shape (published response schema "ACL rule ordering").
    Under UNIFI_DRY_RUN nothing is sent: the result is the bare dry-run preview {status: "dry_run",
    dryRun: true, sent: false,
    message, preview: {method, path, params, body}} in place of the upstream body.

    Request body (Network 10.6.106, PUT /v1/sites/{siteId}/acl-rules/ordering
    (updateAclRuleOrdering) — "Reorder User-Defined ACL Rules"; schema "ACL rule ordering") is
    passed in `ordering` (sent verbatim as the body). Required keys — orderedAclRuleIds.
    - orderedAclRuleIds: array of string (uuid)
    Full replace of the site-wide user-defined ACL rule order. No zone/query params. Read with
    get_acl_rule_ordering first.

    Typical sequence (one tool call per step):
    1. get_acl_rule_ordering(host="my-console", site="Default").
    2. set_acl_rule_ordering(host="my-console", site="Default", ordering={…}).
    3. get_acl_rule_ordering(host="my-console", site="Default") — read back and compare.

    Example call (set_acl_rule_ordering):
        {
          "host": "my-console",
          "site": "Default",
          "ordering": {
            "orderedAclRuleIds": [
              "5c2b9e10-3d4f-4a6b-9c8d-7e6f5a4b3c02",
              "5c2b9e10-3d4f-4a6b-9c8d-7e6f5a4b3c01"
            ]
          }
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        ordering: Full replacement {"orderedAclRuleIds":[uuid…]} in evaluation order (schema "ACL
            rule ordering"). Start from get_acl_rule_ordering; ids from list_acl_rules.
    """
    client, registry = _require()
    return await firewall_proxy.set_acl_rule_ordering(client, registry, host, site, ordering)


# --- DNS Policy Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_dns_policies(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all DNS policies for a site.

    Returns {data, totalCount}: every page is drained; data holds the DNS policy records verbatim
    and totalCount is the upstream total (null when none was reported). The first page's other
    envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
    drain stopped short.

    DNS policies are offset-paginated (native default page size 25); by default every
    page is drained and the complete list is returned as {data, totalCount}. Pass
    offset alone for a single manual page. A capped drain is flagged incomplete.

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: Optional Network Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter for server-side filtering (e.g.
            `domain.like('*example*')`). Omitted entirely when unset; applies when draining and
            when paging manually.
            Example: `type.eq('A_RECORD')`."""
    client, registry = _require()
    return await network_services_proxy.list_dns_policies(
        client, registry, host, site, offset=offset, limit=limit, filter=filter
    )


@mcp.tool(annotations=WRITE)
async def create_dns_policy(
    host: str,
    site: str,
    policy: dict[str, Any],
) -> Any:
    """Create a new DNS policy on a site.

    Returns the upstream response body verbatim: the created DNS policy object the API answers with
    (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message, preview: {method, path, params (query parameters), body}} instead).

    Validated locally before the request (a missing field raises ValueError naming it):
    ``type`` — the discriminator the controller validates first (verified live: an empty
    body is rejected with ``Missing $.type value``). The remaining fields are type-specific
    and enforced by the controller.

    Request body (Network 10.6.106, POST /v1/sites/{siteId}/dns/policies (createDnsPolicy); schema
    "Create or update DNS policy") is passed in `policy`. Required keys — enabled, type.
    - enabled: boolean
    - type: string
    Variants by `type` — AAAA_RECORD requires domain, enabled, ipv6Address, ttlSeconds, type;
    A_RECORD requires domain, enabled, ipv4Address, ttlSeconds, type; CNAME_RECORD requires domain,
    enabled, targetDomain, ttlSeconds, type; FORWARD_DOMAIN requires domain, enabled, ipAddress,
    type; MX_RECORD requires domain, enabled, mailServerDomain, priority, type; SRV_RECORD requires
    domain, enabled, port, priority, protocol, serverDomain, service, weight, type; TXT_RECORD
    requires domain, enabled, text, type.

    Example call (create_dns_policy):
        {
          "host": "my-console",
          "site": "Default",
          "policy": {
            "type": "AAAA_RECORD",
            "domain": "example.com",
            "enabled": true,
            "ipv6Address": "cafe::babe",
            "ttlSeconds": 14400
          }
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        policy: Full object to create; spec Create or update DNS policy. Required: enabled, type.
            'type' selects variant:
            AAAA_RECORD|A_RECORD|CNAME_RECORD|FORWARD_DOMAIN|MX_RECORD|SRV_RECORD|TXT_RECORD.
    """
    client, registry = _require()
    return await network_services_proxy.create_dns_policy(client, registry, host, site, policy)


@mcp.tool(annotations=READ_ONLY)
async def get_dns_policy(
    host: str,
    site: str,
    policy_id: str,
) -> Any:
    """Get a single DNS policy by ID.

    Returns: the DNS policy object, verbatim. To change it, edit it and pass it as `policy` to
    update_dns_policy.

    Example call (get_dns_policy):
        {
          "host": "my-console",
          "site": "Default",
          "policy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        policy_id: DNS policy UUID. Get it from list_dns_policies (data[].id). Network-app UUID —
            not a Protect id.
    """
    client, registry = _require()
    return await network_services_proxy.get_dns_policy(client, registry, host, site, policy_id)


@mcp.tool(annotations=WRITE)
async def update_dns_policy(
    host: str,
    site: str,
    policy_id: str,
    policy: dict[str, Any],
) -> Any:
    """Update a DNS policy by ID.

    Returns the upstream response body verbatim: the updated DNS policy object the API answers with
    (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message, preview: {method, path, params (query parameters), body}} instead).

    Request body (Network 10.6.106, PUT /v1/sites/{siteId}/dns/policies/{dnsPolicyId}
    (updateDnsPolicy); schema "Create or update DNS policy") is passed in `policy`. Required keys —
    enabled, type.
    - enabled: boolean
    - type: string
    Variants by `type` — AAAA_RECORD requires domain, enabled, ipv6Address, ttlSeconds, type;
    A_RECORD requires domain, enabled, ipv4Address, ttlSeconds, type; CNAME_RECORD requires domain,
    enabled, targetDomain, ttlSeconds, type; FORWARD_DOMAIN requires domain, enabled, ipAddress,
    type; MX_RECORD requires domain, enabled, mailServerDomain, priority, type; SRV_RECORD requires
    domain, enabled, port, priority, protocol, serverDomain, service, weight, type; TXT_RECORD
    requires domain, enabled, text, type.

    Example call (update_dns_policy):
        {
          "host": "my-console",
          "site": "Default",
          "policy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "policy": {
            "type": "AAAA_RECORD",
            "domain": "example.com",
            "enabled": true,
            "ipv6Address": "cafe::babe",
            "ttlSeconds": 14400
          }
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        policy_id: DNS policy UUID. Get it from list_dns_policies (data[].id). Network-app UUID —
            not a Protect id.
        policy: FULL replacement object (PUT; omitted fields reset); spec Create or update DNS
            policy. Required: enabled, type.
    """
    client, registry = _require()
    return await network_services_proxy.update_dns_policy(
        client, registry, host, site, policy_id, policy
    )


@mcp.tool(annotations=WRITE)
async def delete_dns_policy(
    host: str,
    site: str,
    policy_id: str,
) -> dict[str, Any]:
    """Delete a DNS policy.

    Consequence: the record or forwarding rule stops being served immediately; there is no undo.

    Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
    (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is deleted: {status: "dry_run", deleted: false, message,
    response (the preview)}.

    Example call (delete_dns_policy):
        {
          "host": "my-console",
          "site": "Default",
          "policy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        policy_id: DNS policy UUID. Get it from list_dns_policies (data[].id). Network-app UUID —
            not a Protect id.
    """
    client, registry = _require()
    response = await network_services_proxy.delete_dns_policy(
        client, registry, host, site, policy_id
    )
    return deletion_result(f"DNS policy {policy_id} deleted.", response)


# --- Traffic Matching List Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_traffic_matching_lists(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all traffic matching lists for a site.

    Returns {data, totalCount} with every page drained (the API pages at 25 by default).
    Pass offset alone to fetch a single manual page (native envelope preserved).

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: Optional Network Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter for server-side filtering (e.g.
            `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
            when paging manually.
            Example: `name.eq('Business Apps')`."""
    client, registry = _require()
    return await network_services_proxy.list_traffic_matching_lists(
        client, registry, host, site, offset=offset, limit=limit, filter=filter
    )


@mcp.tool(annotations=WRITE)
async def create_traffic_matching_list(
    host: str,
    site: str,
    traffic_list: dict[str, Any],
) -> Any:
    """Create a new traffic matching list on a site.

    Returns the upstream response body verbatim: the created traffic matching list object the API
    answers with (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent:
    false, message, preview: {method, path, params (query parameters), body}} instead).

    Validated locally before the request (a missing field raises ValueError naming it):
    a top-level ``type`` — the discriminator the controller validates first (verified live:
    an empty body is rejected with ``Missing $.type value``; observed value: 'PORTS').

    Request body (Network 10.6.106, POST /v1/sites/{siteId}/traffic-matching-lists
    (createTrafficMatchingList); schema "Create or update traffic matching list") is passed in
    `traffic_list`. Required keys — name, type.
    - name: string
    - type: string
    Variants by `type` — IPV4_ADDRESSES requires items, name, type; IPV6_ADDRESSES requires items,
    name, type; PORTS requires items, name, type.

    Example call (create_traffic_matching_list):
        {
          "host": "my-console",
          "site": "Default",
          "traffic_list": {
            "type": "IPV4_ADDRESSES",
            "items": [{"type": "IP_ADDRESS", "value": "192.0.2.5"}],
            "name": "Allowed address list"
          }
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        traffic_list: Full object to create; spec Create or update traffic matching list. Required:
            name, type. 'type' selects variant: IPV4_ADDRESSES|IPV6_ADDRESSES|PORTS.
    """
    client, registry = _require()
    return await network_services_proxy.create_traffic_matching_list(
        client, registry, host, site, traffic_list
    )


@mcp.tool(annotations=READ_ONLY)
async def get_traffic_matching_list(
    host: str,
    site: str,
    list_id: str,
) -> Any:
    """Get a single traffic matching list by ID.

    Returns: the traffic matching list object, verbatim. To change it, edit it and pass it as
    `traffic_list` to update_traffic_matching_list.

    Example call (get_traffic_matching_list):
        {"host": "my-console", "site": "Default", "list_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        list_id: Traffic matching list UUID. Get it from list_traffic_matching_lists (data[].id).
            Network-app UUID — not a Protect id.
    """
    client, registry = _require()
    return await network_services_proxy.get_traffic_matching_list(
        client, registry, host, site, list_id
    )


@mcp.tool(annotations=WRITE)
async def update_traffic_matching_list(
    host: str,
    site: str,
    list_id: str,
    traffic_list: dict[str, Any],
) -> Any:
    """Update a traffic matching list by ID.

    Returns the upstream response body verbatim: the updated traffic matching list object the API
    answers with (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent:
    false, message, preview: {method, path, params (query parameters), body}} instead).

    Request body (Network 10.6.106, PUT
    /v1/sites/{siteId}/traffic-matching-lists/{trafficMatchingListId} (updateTrafficMatchingList);
    schema "Create or update traffic matching list") is passed in `traffic_list`. Required keys —
    name, type.
    - name: string
    - type: string
    Variants by `type` — IPV4_ADDRESSES requires items, name, type; IPV6_ADDRESSES requires items,
    name, type; PORTS requires items, name, type.

    Example call (update_traffic_matching_list):
        {
          "host": "my-console",
          "site": "Default",
          "list_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "traffic_list": {
            "type": "IPV4_ADDRESSES",
            "items": [{"type": "IP_ADDRESS", "value": "192.0.2.5"}],
            "name": "Allowed address list"
          }
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        list_id: Traffic matching list UUID. Get it from list_traffic_matching_lists (data[].id).
            Network-app UUID — not a Protect id.
        traffic_list: FULL replacement object (PUT; omitted fields reset); spec Create or update
            traffic matching list. Required: name, type. 'type' selects variant:
            IPV4_ADDRESSES|IPV6_ADDRESSES|PORTS.
    """
    client, registry = _require()
    return await network_services_proxy.update_traffic_matching_list(
        client, registry, host, site, list_id, traffic_list
    )


@mcp.tool(annotations=WRITE)
async def delete_traffic_matching_list(
    host: str,
    site: str,
    list_id: str,
) -> dict[str, Any]:
    """Delete a traffic matching list.

    Consequence: the list is permanently removed; there is no undo.

    Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
    (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is deleted: {status: "dry_run", deleted: false, message,
    response (the preview)}.

    Example call (delete_traffic_matching_list):
        {"host": "my-console", "site": "Default", "list_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        list_id: Traffic matching list UUID. Get it from list_traffic_matching_lists (data[].id).
            Network-app UUID — not a Protect id.
    """
    client, registry = _require()
    response = await network_services_proxy.delete_traffic_matching_list(
        client, registry, host, site, list_id
    )
    return deletion_result(f"Traffic matching list {list_id} deleted.", response)


# --- VPN Server Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_vpn_servers(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List VPN servers for a site.

    Returns {data, totalCount}: every page is drained; data holds the VPN server records verbatim
    and totalCount is the upstream total (null when none was reported). The first page's other
    envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
    drain stopped short.

    VPN servers are offset-paginated (native default page size 25); by default every
    page is drained and the complete list is returned as {data, totalCount}. Pass
    offset alone for a single manual page. A capped drain is flagged incomplete.

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: Optional Network Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter for server-side filtering (e.g.
            `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
            when paging manually.
            Example: `metadata.origin.eq('USER_DEFINED')`."""
    client, registry = _require()
    return await network_services_proxy.list_vpn_servers(
        client, registry, host, site, offset=offset, limit=limit, filter=filter
    )


@mcp.tool(annotations=READ_ONLY)
async def list_site_to_site_tunnels(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List site-to-site VPN tunnels for a site.

    Returns: {data: [tunnel…], totalCount} with every page drained, entries verbatim (pass
    offset alone to fetch a single manual page, native envelope preserved). To change one,
    pass the native Classic networkconf fields to change (e.g. enabled, name) as `tunnel` to
    update_site_to_site_tunnel (tunnel_id = its data[] id).

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: Optional Network Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter for server-side filtering (e.g.
            `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
            when paging manually.
            Example: `metadata.origin.eq('USER_DEFINED')`."""
    client, registry = _require()
    return await network_services_proxy.list_site_to_site_tunnels(
        client, registry, host, site, offset=offset, limit=limit, filter=filter
    )


# --- RADIUS Profile Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_radius_profiles(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List RADIUS profiles for a site.

    Returns {data, totalCount}: every page is drained; data holds the RADIUS profile records
    verbatim and totalCount is the upstream total (null when none was reported). The first page's
    other envelope fields are kept beside them, and incomplete / incompleteReason are added when a
    capped drain stopped short.

    RADIUS profiles are offset-paginated (native default page size 25); by default
    every page is drained and the complete list is returned as {data, totalCount}.
    Pass offset alone for a single manual page. A capped drain is flagged incomplete.

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: Optional Network Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter for server-side filtering (e.g.
            `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
            when paging manually.
            Example: `metadata.origin.eq('USER_DEFINED')`."""
    client, registry = _require()
    return await network_services_proxy.list_radius_profiles(
        client, registry, host, site, offset=offset, limit=limit, filter=filter
    )


# --- Hotspot Voucher Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_hotspot_vouchers(
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all hotspot/guest vouchers for a site (there is no `list_vouchers` — this is it).

    Returns {data, totalCount}: every page is drained; data holds the voucher records verbatim and
    totalCount is the upstream total (null when none was reported). The first page's other envelope
    fields are kept beside them, and incomplete / incompleteReason are added when a capped drain
    stopped short.

    This is the voucher-listing tool; the family is `list_hotspot_vouchers`,
    `create_hotspot_vouchers`, `get_hotspot_voucher`, `delete_hotspot_voucher` — all
    prefixed `hotspot_`. There is no shorter `list_vouchers`/`get_voucher` alias.

    Vouchers are offset-paginated (native page size 100) and batches routinely
    exceed that; by default every page is drained and all records are returned as
    {data, totalCount}. Pass offset alone for a single manual page. A capped drain
    is flagged incomplete.

    limit requests a total, gathered automatically in batches up to 1000;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 1000; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 1000, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: Optional Network Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter for server-side filtering (e.g.
            `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
            when paging manually.
            Example: `name.eq('Conference')`."""
    client, registry = _require()
    return await network_services_proxy.list_hotspot_vouchers(
        client, registry, host, site, offset=offset, limit=limit, filter=filter
    )


@mcp.tool(annotations=WRITE)
async def create_hotspot_vouchers(
    host: str,
    site: str,
    voucher_config: dict[str, Any],
) -> Any:
    """Generate hotspot vouchers for a site.

    Returns the upstream response body verbatim: the voucher-creation object the API answers with
    (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message, preview: {method, path, params (query parameters), body}} instead).

    `voucher_config`: required fields (validated locally — a missing field raises ValueError
    naming it — and verified against the live controller): ``name`` and
    ``timeLimitMinutes`` (voucher validity window, minutes). Optional: count, quota,
    bandwidth limits, etc.

    Request body (Network 10.6.106, POST /v1/sites/{siteId}/hotspot/vouchers (createVouchers);
    schema "Hotspot voucher creation request") is passed in `voucher_config`. Required keys — name,
    timeLimitMinutes.
    - authorizedGuestLimit: integer(int64)
    - count: integer(int32)
    - dataUsageLimitMBytes: integer(int64)
    - name: string
    - rxRateLimitKbps: integer(int64)
    - timeLimitMinutes: integer(int64)
    - txRateLimitKbps: integer(int64)

    Example call (create_hotspot_vouchers):
        {
          "host": "my-console",
          "site": "Default",
          "voucher_config": {"name": "Conference", "timeLimitMinutes": 1440}
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        voucher_config: Full object to create; spec Hotspot voucher creation request. Required:
            name, timeLimitMinutes.
    """
    client, registry = _require()
    return await network_services_proxy.create_hotspot_vouchers(
        client, registry, host, site, voucher_config
    )


@mcp.tool(annotations=READ_ONLY)
async def get_hotspot_voucher(
    host: str,
    site: str,
    voucher_id: str,
) -> Any:
    """Get a single hotspot voucher by ID.

    Returns the upstream voucher object verbatim, exactly as the API answers it.

    Example call (get_hotspot_voucher):
        {
          "host": "my-console",
          "site": "Default",
          "voucher_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        voucher_id: Hotspot voucher UUID. Get it from list_hotspot_vouchers (data[].id). Network-app
            UUID — not a Protect id.
    """
    client, registry = _require()
    return await network_services_proxy.get_hotspot_voucher(
        client, registry, host, site, voucher_id
    )


@mcp.tool(annotations=WRITE)
async def delete_hotspot_voucher(
    host: str,
    site: str,
    voucher_id: str,
) -> dict[str, Any]:
    """Delete a single hotspot voucher.

    Consequence: the voucher can no longer be redeemed; there is no undo.

    Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
    (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is deleted: {status: "dry_run", deleted: false, message,
    response (the preview)}.

    Example call (delete_hotspot_voucher):
        {
          "host": "my-console",
          "site": "Default",
          "voucher_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        voucher_id: Hotspot voucher UUID. Get it from list_hotspot_vouchers (data[].id). Network-app
            UUID — not a Protect id.
    """
    client, registry = _require()
    response = await network_services_proxy.delete_hotspot_voucher(
        client, registry, host, site, voucher_id
    )
    return deletion_result(f"Hotspot voucher {voucher_id} deleted.", response)


@mcp.tool(annotations=WRITE)
async def bulk_delete_hotspot_vouchers(
    host: str,
    site: str,
    filter_params: dict[str, Any],
    confirm: bool = False,
) -> dict[str, Any]:
    """Bulk delete hotspot vouchers matching filter criteria.

    Consequence: every voucher matching the filter is permanently removed and can no longer be
    redeemed; there is no undo.

    Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
    (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is deleted: {status: "dry_run", deleted: false, message,
    response (the preview)}.

    Example call (bulk_delete_hotspot_vouchers):
        {
          "host": "my-console",
          "site": "Default",
          "filter_params": {"filter": "name.eq('Conference')"}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        filter_params: Query parameters sent with the DELETE; must contain `filter`, which selects
            the vouchers to delete (Network 10.6.106 DELETE /v1/sites/{siteId}/hotspot/vouchers),
            e.g. {"filter": "name.eq('Conference')"}. Filter syntax as list_hotspot_vouchers.
            Free-form JSON object; no fixed body shape is published.
        confirm: Ignored; accepted for backward compatibility. The call executes immediately when
            made unless the operator opted in to UNIFI_DRY_RUN (then nothing is
            sent upstream and a preview of the request is returned).
    """
    client, registry = _require()
    response = await network_services_proxy.bulk_delete_hotspot_vouchers(
        client, registry, host, site, filter_params
    )
    return deletion_result("Hotspot vouchers deleted.", response)


# --- Supporting Resources Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_device_tags(
    host: str,
    site: str,
) -> Any:
    """List all device tags defined in a site (the tags the Network UI shows).

    Reads the v2 route the controller's own UI uses, GET
    /proxy/network/v2/api/site/{site}/device-tags; the published Integration device-tag list
    is a separate collection that answers empty on Network 11.0.81 while the UI has tags.

    Returns: the v2 API's bare JSON array of tags, verbatim, the whole list in one response
    (each entry {_id, name, member_device_macs, ...}). To change one, pass it as `tag` to
    update_device_tag (tag_id = its _id): either the entry itself, edited (rename it, or set
    member_device_macs to the desired members; the tool sends the additions and removals
    and drops _id), or a native v2 update body {name, device_mac_additions,
    device_mac_removals}.

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_device_tags(client, registry, host, site)


@mcp.tool(annotations=READ_ONLY)
async def list_countries(
    host: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all countries with ISO codes available on a console.

    Returns {data, totalCount} with every page drained (about 250 entries; the API pages at
    25 by default). Pass offset alone to fetch a single manual page (native envelope
    preserved).

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: Optional Network Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter for server-side filtering (e.g.
            `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
            when paging manually.
            Example: `code.eq('US')`."""
    client, registry = _require()
    return await network_services_proxy.list_countries(
        client, registry, host, offset=offset, limit=limit, filter=filter
    )


# --- Protect Camera Management Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_cameras(
    host: str,
) -> dict[str, Any]:
    """List all cameras on a Protect console.

    Returns {result, _count}: result is the upstream array of cameras verbatim and _count its length
    (an upstream object carrying a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_cameras(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_camera(
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect camera by ID.

    Returns: the camera object, verbatim. To change it, pass only the fields to change as `settings`
    to update_camera (a partial PATCH).

    Example call (get_camera):
        {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
            Network device UUID.
    """
    client, registry = _require()
    return await protect.get_camera(client, registry, host, camera_id)


@mcp.tool(annotations=WRITE)
async def update_camera(
    host: str,
    camera_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect camera (name, OSD, LED, LCD message, mic volume, video mode,
    HDR, smart detection).

    Returns {status: "updated", verified, before, after, response}, or {status: "noop", reason,
    resource} when every sent leaf already matches (no PATCH is sent). Read-before, no-op,
    PATCH, read-after: before/after are the object read before and after the write, verified
    is true when the read-after carries every sent leaf value (nested objects such as
    osdSettings are compared leaf by leaf, so a partial nested update verifies by the leaves
    it sends; sibling keys it does not send are ignored), and response is the PATCH body
    verbatim (decoded JSON, the text of a non-JSON body, or null when the body is empty).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", before (the body read first),
    response
    (the preview)}; there is no read-after.


    Full request shapes are in the parameter schema; detailed examples and workflows:
    docs/TOOL-USAGE.md#update_camera.

    Required arguments: host, camera_id, settings (see parameter descriptions for identifiers).

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
            Network device UUID.
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.70 PATCH
            /v1/cameras/{id} body. Keys: name, osdSettings, ledSettings, lcdMessage, micVolume
            (number 1-100), videoMode, hdrType, smartDetectSettings (nested keys in the
            parameter schema and
            docs/TOOL-USAGE.md#update_camera).
    """
    client, registry = _require()
    return await protect.update_camera(client, registry, host, camera_id, **settings)


@mcp.tool(annotations=WRITE)
async def enable_camera_share_link(host: str, camera_id: str) -> Any:
    """Enable a bearer share link that exposes a camera livestream to anyone with the link.

    Consequence: anyone holding the link can watch the camera's live video, without signing
    in, until it expires or disable_camera_share_link revokes it.

    Cloud-only: POST protect/api/cameras/{id}/sharedStream through the Fabric connector.
    No request body. Returns the upstream body verbatim, including null for an empty body.
    Expiry and maxStreams are server configuration (defaults 24 hours and 1 stream),
    not tool parameters. The share URL/token is a bearer secret: keep it out of logs,
    evidence and fixtures. Writes are enabled by default; UNIFI_PROTECT_MUTATIONS_ENABLED=0 or
    UNIFI_READ_ONLY=1 refuses the mutation. UNIFI_DRY_RUN sends nothing and returns the dry-run
    preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
    body}}. Exposure actions are sent once, never automatically retried.

    Example call (enable_camera_share_link):
        {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id from list_hosts, e.g. "my-console"; resolved to its owning
            Fabric API key and console id before the camera request.
        camera_id: Protect camera id from list_cameras, e.g. "66d025b301ebc903e80003ea";
            pass the full id, not a camera name or Network device UUID.
    """
    client, registry = _require()
    return await protect.enable_camera_share_link(client, registry, host, camera_id)


@mcp.tool(annotations=READ_ONLY)
async def get_camera_share_link(host: str, camera_id: str) -> Any:
    """Read a camera's current livestream share link and status.

    Cloud-only: GET protect/api/cameras/{id}/sharedStream through the Fabric connector.
    No request body. Returns the upstream body verbatim. Object bodies are returned
    directly as structured output; arrays use {result: body}, and an empty body uses
    {result: null}. String, integer and boolean bodies have structured_content=None
    and are returned as text content.
    Expiry and maxStreams are server configuration (defaults 24 hours and 1 stream),
    not tool parameters. The share URL/token is a bearer secret: keep it out of logs,
    evidence and fixtures. This is a read and does not enable sharing.

    Example call (get_camera_share_link):
        {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id from list_hosts, e.g. "my-console"; resolved to its owning
            Fabric API key and console id before the camera request.
        camera_id: Protect camera id from list_cameras, e.g. "66d025b301ebc903e80003ea";
            pass the full id, not a camera name or Network device UUID.
    """
    client, registry = _require()
    return await protect.get_camera_share_link(client, registry, host, camera_id)


@mcp.tool(annotations=WRITE)
async def disable_camera_share_link(host: str, camera_id: str) -> Any:
    """Disable a camera's livestream share link, revoking public viewing access.

    Consequence: the existing link stops working for everyone who holds it; a new link
    needs enable_camera_share_link.

    Cloud-only: DELETE protect/api/cameras/{id}/sharedStream through the Fabric connector.
    No request body. Returns the upstream body verbatim, including null for an empty body.
    Expiry and maxStreams are server configuration (defaults 24 hours and 1 stream),
    not tool parameters. The share URL/token is a bearer secret: keep it out of logs,
    evidence and fixtures. Writes are enabled by default; UNIFI_PROTECT_MUTATIONS_ENABLED=0 or
    UNIFI_READ_ONLY=1 refuses the mutation. UNIFI_DRY_RUN sends nothing and returns the dry-run
    preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
    body}}. Exposure actions are sent once, never automatically retried.

    Example call (disable_camera_share_link):
        {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id from list_hosts, e.g. "my-console"; resolved to its owning
            Fabric API key and console id before the camera request.
        camera_id: Protect camera id from list_cameras, e.g. "66d025b301ebc903e80003ea";
            pass the full id, not a camera name or Network device UUID.
    """
    client, registry = _require()
    return await protect.disable_camera_share_link(client, registry, host, camera_id)


@mcp.tool(annotations=READ_ONLY)
async def get_camera_snapshot(
    host: str,
    camera_id: str,
    channel: str | None = None,
    high_quality: bool | None = None,
    ts: int | None = None,
) -> Any:
    """Get a snapshot from a Protect camera. Returns MCP ImageContent plus image metadata.

    Returns MCP ImageContent plus text and structured metadata
    {image_base64, content_type, size_bytes}; content_type is the upstream
    Content-Type header (typically image/jpeg), not assumed, and null when the upstream
    sends none. channel and high_quality are the spec's optional query parameters, sent only
    when given. With ts the tool reads a past moment from the private Protect route
    cameras/{id}/recording-snapshot instead of the live frame (see ts below for its
    provenance).

    Example call (get_camera_snapshot):
        {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
            Network device UUID.
        channel: Optional camera channel (query channel): 'main', or 'package' for the package
            camera of a camera whose hasPackageCamera is true. Sent verbatim; omit for the
            controller default.
        high_quality: Optional (query highQuality): true forces a 1080p-or-higher snapshot, false
            does not. Omit for the controller default.
        ts: Optional moment to snapshot, sent as query ts to the private route
            cameras/{id}/recording-snapshot instead of the live snapshot. Provenance: probed
            on a live console 2026-10-17 (Protect 5.3.18), where the route answered 400 without
            ts and 404 "Recording not found" with it, so the key is accepted; the unit is
            inferred to be epoch milliseconds and is unverified, and a returned image has not
            been observed. Omit for the live frame. Example: `1760140800000`.
    """
    client, registry = _require()
    return _image_result(
        await protect.get_camera_snapshot(
            client, registry, host, camera_id, channel=channel, high_quality=high_quality, ts=ts
        )
    )


@mcp.tool(annotations=READ_ONLY)
async def get_rtsps_stream(
    host: str,
    camera_id: str,
) -> dict[str, Any]:
    """Get existing RTSPS stream URLs for a Protect camera.

    Returns the upstream RTSPS stream (one URL per quality) object verbatim, exactly as the API
    answers it.

    Example call (get_rtsps_stream):
        {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
            Network device UUID.
    """
    client, registry = _require()
    return await protect.get_rtsps_stream(client, registry, host, camera_id)


@mcp.tool(annotations=WRITE)
async def create_rtsps_stream(
    host: str,
    camera_id: str,
    qualities: list[str],
) -> dict[str, Any]:
    """Create an RTSPS stream for a Protect camera.

    Returns {status: "created", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    `qualities`: list of channel names to enable. The exhaustive set is 'high', 'medium',
      'low', and 'package' (verified live against get_rtsps_stream, which reports exactly
      these four channel keys). 'package' exists only on package-camera doorbells; on other
      cameras it is null. There is NO 'highest' channel. Each value must be exactly one of
      those spec enum values (lowercase); any other value, a different case included, fails
      before any request.

    Request body (Protect 7.3.70, POST /v1/cameras/{id}/rtsps-stream; schema "inline requestBody
    schema") is built from scalar parameters. Required keys — qualities.
    - qualities: array of enum high|medium|low|package

    Example call (create_rtsps_stream):
        {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea", "qualities": ["high"]}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
            Network device UUID.
        qualities: Channels to enable (at least one; an empty list fails before any request,
            spec minItems 1); spec enum channelQuality: high|medium|low|package (package only on
            cameras with a package lens).
    """
    client, registry = _require()
    return await protect.create_rtsps_stream(client, registry, host, camera_id, qualities)


@mcp.tool(annotations=WRITE)
async def delete_rtsps_stream(
    host: str,
    camera_id: str,
    qualities: str | list[str],
) -> dict[str, Any]:
    """Delete an RTSPS stream for a Protect camera.

    Consequence: the RTSPS URL of each deleted quality stops working for every consumer; there is no
    undo.

    Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
    (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is deleted: {status: "dry_run", deleted: false, message,
    response (the preview; preview.params.qualities is exactly the lowercased list the DELETE
    would send)}.

    `qualities`: one channel name, or a list of channel names, to delete (spec
      removedQualities: a channelQuality value or a non-empty array of them). A list needs
      at least one entry (spec minItems 1): an empty list fails before any request (it
      would otherwise send no qualities query at all). The exhaustive set is 'high',
      'medium', 'low', and 'package' (verified live; 'package' only on package-camera
      doorbells). There is NO 'highest' channel. Each value must be exactly one of those
      spec enum values (lowercase); any other value, a different case included, fails
      before any request.

    Example call (delete_rtsps_stream):
        {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea", "qualities": ["high"]}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
            Network device UUID.
        qualities: Channel to delete ('high'), or a list of channels (at least one; an empty list
            fails before any request); spec enum channelQuality: high|medium|low|package.
            Shape: 'high'|'medium'|'low'|'package'|('high'|'medium'|'low'|'package')[]
    """
    client, registry = _require()
    response = await protect.delete_rtsps_stream(client, registry, host, camera_id, qualities)
    return deletion_result(f"RTSPS stream for camera {camera_id} deleted.", response)


@mcp.tool(annotations=WRITE)
async def start_talkback_session(
    host: str,
    camera_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Start a talkback audio session on a Protect camera.

    Consequence: audio sent to the session plays aloud from the camera's speaker.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    Example call (start_talkback_session):
        {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
            Network device UUID.
        confirm: Ignored. The call runs when made; there is no confirmation step.
    """
    client, registry = _require()
    return await protect.talkback_start(client, registry, host, camera_id, confirm=confirm)


@mcp.tool(annotations=WRITE)
async def disable_camera_mic_permanently(
    host: str,
    camera_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Permanently disable the microphone on a Protect camera. This cannot be undone.

    Consequence: the camera's microphone cannot be re-enabled.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    Example call (disable_camera_mic_permanently):
        {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
            Network device UUID.
        confirm: Ignored. The call runs when made; there is no confirmation step.
    """
    client, registry = _require()
    return await protect.disable_mic_permanently(client, registry, host, camera_id, confirm=confirm)


@mcp.tool(annotations=WRITE)
async def ptz_goto_preset(
    host: str,
    camera_id: str,
    slot: int,
    confirm: bool = False,
) -> dict[str, Any]:
    """Move a PTZ camera to a preset position slot.

    Consequence: the camera physically moves, changing what it records.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    Example call (ptz_goto_preset):
        {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea", "slot": 0}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
            Network device UUID.
        slot: PTZ preset slot to move to (path param slot): -1 is the home preset, 0 or more
            the other presets (spec); a smaller value is refused before any request.
        confirm: Ignored. The call runs when made; there is no confirmation step.
    """
    client, registry = _require()
    return await protect.ptz_goto(client, registry, host, camera_id, slot, confirm=confirm)


@mcp.tool(annotations=WRITE)
async def ptz_patrol_start(
    host: str,
    camera_id: str,
    slot: int,
    confirm: bool = False,
) -> dict[str, Any]:
    """Start a PTZ patrol: the patrol saved in patrol slot 0-4 (not a preset slot).

    Consequence: the camera physically moves along the patrol, changing what it records, until
    stopped.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    Example call (ptz_patrol_start):
        {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea", "slot": 0}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
            Network device UUID.
        slot: PTZ patrol slot number 0-4 (path param slot).
        confirm: Ignored. The call runs when made; there is no confirmation step.
    """
    client, registry = _require()
    return await protect.ptz_patrol_start(client, registry, host, camera_id, slot, confirm=confirm)


@mcp.tool(annotations=WRITE)
async def ptz_patrol_stop(
    host: str,
    camera_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Stop the current PTZ patrol on a camera.

    Consequence: the camera stops patrolling.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    Example call (ptz_patrol_stop):
        {"host": "my-console", "camera_id": "66d025b301ebc903e80003ea"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
            Network device UUID.
        confirm: Ignored. The call runs when made; there is no confirmation step.
    """
    client, registry = _require()
    return await protect.ptz_patrol_stop(client, registry, host, camera_id, confirm=confirm)


# --- Protect Sensor Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_sensors(
    host: str,
) -> dict[str, Any]:
    """List all sensors on a Protect console.

    Returns {result, _count}: result is the upstream array of sensors verbatim and _count its length
    (an upstream object carrying a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_sensors(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_sensor(
    host: str,
    sensor_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect sensor by ID.

    Returns: the sensor object, verbatim. To change it, pass only the fields to change as `settings`
    to update_sensor (a partial PATCH).

    Example call (get_sensor):
        {"host": "my-console", "sensor_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        sensor_id: Protect sensor id. Get it from list_sensors (id). Protect id (24-hex) — not a
            Network device UUID.
    """
    client, registry = _require()
    return await protect.get_sensor(client, registry, host, sensor_id)


@mcp.tool(annotations=WRITE)
async def update_sensor(
    host: str,
    sensor_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect sensor.

    Returns {status: "updated", verified, before, after, response}, or {status: "noop", reason,
    resource} when every sent leaf already matches (no PATCH is sent). Read-before, no-op,
    PATCH, read-after: before/after are the object read before and after the write, verified
    is true when the read-after carries every sent leaf value (nested objects are compared
    leaf by leaf, so a partial nested update verifies by the leaves
    it sends; sibling keys it does not send are ignored), and response is the PATCH body
    verbatim (decoded JSON, the text of a non-JSON body, or null when the body is empty).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    UNIFI_DRY_RUN sends nothing: {status: "dry_run", before (read body),
    response (preview)}; no read-after.

    Request body (Protect 7.3.70, PATCH /v1/sensors/{id}; inline schema) is `settings`.
    No required key; send only changed keys.
    - name: string
    - lightSettings: object {isEnabled: boolean, margin: number, lowThreshold: number or
      null (1-503192), highThreshold: number or null (1-503192)}
    - humiditySettings: object {isEnabled: boolean, margin: number, lowThreshold: number or
      null (1-99), highThreshold: number or null (1-99)}
    - temperatureSettings: object {isEnabled: boolean, margin: number, lowThreshold: number
      or null (-39-124), highThreshold: number or null (-39-124)}
    - motionSettings: object {isEnabled: boolean, sensitivity: number (0-100),
      sensitivityWhenArmed: number (0-100)}
    - glassBreakSettings: object {isEnabled: boolean, sensitivity: number (0-100),
      sensitivityWhenArmed: number (0-100)}
    - scheduleMode: enum[always|when_armed]
    - armProfileIds: array|null
    - hasCustomSensitivityWhenArmed: boolean
    - alarmSettings: object {isEnabled: boolean}

    Example call (update_sensor):
        {
          "host": "my-console",
          "sensor_id": "66d025b301ebc903e80003ea",
          "settings": {"name": "Front Door"}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        sensor_id: Protect sensor id. Get it from list_sensors (id). Protect id (24-hex) — not a
            Network device UUID.
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.70 PATCH
            /v1/sensors/{id} body.
    """
    client, registry = _require()
    return await protect.update_sensor(client, registry, host, sensor_id, **settings)


# --- Protect Historical Events ---


@mcp.tool(annotations=READ_ONLY)
async def list_protect_events(
    host: str,
    start: int,
    end: int,
    types: str | list[str] | None = None,
    cameras: str | list[str] | None = None,
    limit: int | None = None,
    offset: int | None = None,
    order_direction: str | None = None,
    smart_detect_types: str | list[str] | None = None,
    categories: str | list[str] | None = None,
    without_descriptions: bool | None = None,
) -> dict[str, Any]:
    """Query historical Protect events via private /proxy/protect/api/events; the official
    Integration events endpoint is WebSocket-only.

    Returns drained object pages preserving data and the first page's envelope fields, adding _count
    and _warnings. A drain of bare arrays returns {result, _count} with _warnings when applicable.
    Capped drains also carry incomplete/incompleteReason. An explicit offset/limit fetches one page
    when offset is supplied: a bare list stays a list (without warnings); an object page
    preserves every upstream top-level field verbatim, including data and totalCount, adding
    only _count and _warnings. Sensor events retain sensor:null and gain _resolved_sensor from
    metadata.sensorId.text. All event fields and identifiers are preserved.
    Object pages carry epoch-unit and smart-detect _warnings, as drained results do.

    Required host/start/end; time is integer epoch SECONDS, never ISO strings or
    milliseconds. Negative or millisecond-magnitude times are sent as given with _warnings on
    object results. query_isp_metrics instead takes ISO 8601 strings. Face names are at
    metadata.detectedThumbnails[].matchedName. types, smart_detect_types and categories are
    forwarded as given (empty list sends no parameter); empty cameras applies no filter. Full
    examples: docs/TOOL-USAGE.md#list_protect_events.

    Required arguments: host, start, end (see parameter descriptions for identifiers).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        start: REQUIRED. Epoch SECONDS (UTC) as integers, converted to milliseconds internally.
            Ranges are inclusive on both ends. History depth is bounded by the NVR's retention.
            (Contrast query_isp_metrics, which wants ISO 8601 strings.)
        end: REQUIRED. Epoch SECONDS (UTC) as integers, converted to milliseconds internally. Ranges
            are inclusive on both ends. History depth is bounded by the NVR's retention. (Contrast
            query_isp_metrics, which wants ISO 8601 strings.)
        types: Filter by event TYPE; single value or a list. Verified-present values: motion,
            smartDetectZone, smartAudioDetect, sensorOpened, sensorClosed, access. Smart-detect
            subtypes (person, face, animal, alrmSpeak and so on) are not event types; pass them in
            smart_detect_types instead. An unrecognised value returns zero events.
            Shape: string|string[]
        cameras: filter by camera NAME or ID; single value or list. Names resolve to IDs: an exact
            match first, then Unicode-normalized (NFC) and case-insensitive, then ignoring
            surrounding whitespace (case kept before case-insensitive); an unknown name errors
            (listing the camera names as the console has them) rather than silently matching
            nothing.
            Shape: string|string[]
        limit: Without offset, the event count gathered from the beginning across pages;
            fewer only when the window ends. With offset, limit is sent unchanged as one
            page. No size clamp is measured on this feed. _pageSize reports the requested
            count, the size sent on each request, the observed effective size and the
            returned count. Omit limit and offset to drain all events; the only page cap is
            opt-in UNIFI_PAGINATE_MAX_PAGES, which marks an early stop incomplete.
            Example: `25`.
        offset: Zero-based starting record. Fetches one page: with limit, limit is sent
            unchanged as that page size (not collected across pages). Omit both to drain every
            event for the window. The opt-in UNIFI_PAGINATE_MAX_PAGES marks an early stop
            incomplete; no default page cap applies.
            Example: `25`.
        order_direction: Optional sort order sent as orderDirection: "ASC" (oldest-first) or "DESC"
            (newest-first). Omitted (default): no orderDirection is sent and the upstream's own
            order applies.
        smart_detect_types: filter by the smart-detect SUBTYPE — person, vehicle, animal, package,
            face, licensePlate (on smartDetectZone events) and the audio alarms alrmSpeak,
            alrmSiren, alrmBark, alrmCarHorn (on smartAudioDetect events). This is a distinct
            upstream parameter from types. The API only honours it when types is also set to the
            relevant event type(s); passing smart_detect_types alone is a silent no-op upstream:
            it is still sent, and the result carries a _warnings entry
            (SMART_DETECT_TYPES_WITHOUT_TYPES). Example: types="smartDetectZone",
            smart_detect_types="person" for just person detections; types="smartAudioDetect",
            smart_detect_types="alrmSpeak" to isolate the dominant audio-alarm noise.
            Shape: string|string[]
        categories: filter by event category; single value or list. Verified values: motion, smart,
            iot, admin. Unknown values are silently ignored by the upstream API.
            Shape: string|string[]
        without_descriptions: when true, ask the API to omit each event's description block (~16%
            smaller payload). Opt-in only — full-fidelity records are the default and descriptions
            are never dropped automatically."""
    client, registry = _require()
    return await protect.list_protect_events(
        client,
        registry,
        host,
        start,
        end,
        types,
        cameras,
        limit,
        offset,
        order_direction,
        smart_detect_types=smart_detect_types,
        categories=categories,
        without_descriptions=without_descriptions,
    )


# --- Protect Live-Stream Collectors (explicit poll-count REST collection) ---


@mcp.tool(annotations=READ_ONLY)
async def collect_protect_events(
    host: str,
    poll_count: int = 6,
    max_events: int | None = None,
    since: int | None = None,
    types: str | list[str] | None = None,
    cameras: str | list[str] | None = None,
    smart_detect_types: str | list[str] | None = None,
    poll_interval_seconds: float = 2.0,
    order_direction: str | None = None,
) -> dict[str, Any]:
    """Collect Protect events over a bounded polling window (live-feed stand-in).

    The window is bounded by `poll_count` complete polls, never by elapsed time.
    The result adds incomplete / incompleteReason when a poll's drain stopped short or a
    later poll failed.

    Protect's `/v1/subscribe/events` WebSocket feed is NOT reachable over the Fabric
    cloud connector (a unary request/response relay — verified: an upgrade GET
    returns 404, never 101). This tool is the REST equivalent: it polls the
    historical-events path for `poll_count` complete polls and returns every distinct event
    seen in one call. Read-only and stateless — each call starts fresh and holds no
    cursor between calls.

    Returns {result, _poll_count, _polls, _truncated} — result holds the verbatim upstream
    objects, de-duplicated by event id with the LATEST object per id kept; an event with no
    id is de-duplicated by its full record (an identical id-less event seen by several
    polls is kept, and counted toward max_events, once). Each poll
    drains every page; there is no page cap by default, and only the opt-in
    UNIFI_PAGINATE_MAX_PAGES can stop a poll early (the result then carries incomplete:
    true with the reason). When a poll fails after an earlier poll succeeded (any error: an
    HTTP error, a 429 that outlasted the retries, a transport or shape error), polling stops
    and the events gathered so far are returned with incomplete: true and an
    incompleteReason carrying that poll's complete error; a failing first poll raises it.
    An upstream 404/501 (Protect absent) is passed straight through.

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        poll_count: positive integer number of complete polls in the bounded polling window
            (default 6). An active poll is never interrupted by elapsed time; lifecycle
            cancellation remains available.
        max_events: Optional early stop: once this many distinct events are collected, stop and
            flag `_truncated=true`. Default None (omit it): no limit, all requested polls complete.
            A single poll is never truncated mid-page, so the count may slightly exceed it.
        since: optional epoch SECONDS lower bound; defaults to the moment the call starts, so only
            events at/after the call are collected. A negative or millisecond-magnitude value
            (>= 1e11) is sent as given and the result carries a _warnings entry saying so.
        types: same filters and validation as `list_protect_events` (camera names resolve to IDs;
            smart_detect_types without types is sent with a _warnings entry).
            Shape: string|string[]
        cameras: same filters and validation as `list_protect_events` (camera names resolve to IDs;
            smart_detect_types without types is sent with a _warnings entry).
            Shape: string|string[]
        smart_detect_types: same filters and validation as `list_protect_events` (camera names
            resolve to IDs; smart_detect_types without types is sent with a _warnings entry).
            Shape: string|string[]
        poll_interval_seconds: pacing delay between completed polls (default 2). This never
            bounds request duration or cancels active work.
            Zero means no timed delay; the event loop still yields. Small values may hit
            the shared 429 backoff, which the client handles.
        order_direction: Optional sort order sent on every poll as orderDirection: "ASC"
            (oldest-first) or "DESC" (newest-first). Omitted (default): no orderDirection is sent
            and the upstream's own order applies.
    """
    client, registry = _require()
    return await protect.collect_protect_events(
        client,
        registry,
        host,
        poll_count=poll_count,
        max_events=max_events,
        since=since,
        types=types,
        cameras=cameras,
        smart_detect_types=smart_detect_types,
        poll_interval_seconds=poll_interval_seconds,
        order_direction=order_direction,
    )


@mcp.tool(annotations=READ_ONLY)
async def collect_protect_device_changes(
    host: str,
    poll_count: int = 6,
    max_changes: int | None = None,
    poll_interval_seconds: float = 2.0,
) -> dict[str, Any]:
    """Collect Protect device add/remove/modify changes by polling every device family for
    poll_count complete snapshots. The WebSocket subscription is unavailable through Fabric;
    this read-only, stateless tool is its REST equivalent.

    Returns {_poll_count, _polls, _truncated, changes}; each change has
    change=added|removed|modified and the upstream device object verbatim (current for
    added/modified, last-seen for removed). Heartbeat-only lastSeen/uptime/upSince changes are
    ignored. Objects without id cannot be diffed: each distinct object appears verbatim in
    unidentified as {family, device}, even if later absent; heartbeat-only differences collapse
    to the latest form. These produce incomplete/incompleteReason.

    404/501 families appear in unavailableFamilies with their complete upstream errors and
    incomplete=true. A family unavailable in either consecutive poll is excluded from that diff,
    preventing false additions/removals. Every family unavailable raises the upstream error. A
    failed first poll raises; failure after a successful poll stops and returns collected
    changes with incomplete=true and the complete poll error in incompleteReason. Other families
    still count. Full workflow: docs/TOOL-USAGE.md#collect_protect_device_changes.

    Required arguments: host (see parameter descriptions for identifiers).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        poll_count: positive integer number of complete snapshots (default 6). At least two
            polls detect changes; elapsed time never interrupts an active snapshot.
        max_changes: Optional early stop: once this many change records accumulate, stop and flag
            `_truncated=true`. Default None (omit it): no limit, all requested polls complete.
        poll_interval_seconds: pacing delay between completed polls (default 2). This never
            bounds request duration or cancels active work.
            Zero means no timed delay; the event loop still yields. Small values may hit
            the shared 429 backoff, which the client handles.
    """
    client, registry = _require()
    return await protect.collect_protect_device_changes(
        client,
        registry,
        host,
        poll_count=poll_count,
        max_changes=max_changes,
        poll_interval_seconds=poll_interval_seconds,
    )


# --- Protect Face/Vehicle Recognition (private REST path) ---


@mcp.tool(annotations=READ_ONLY)
async def list_recognition_groups(
    host: str,
    type: str,
    has_name: bool | None = None,
    page_size: int | None = None,
    order_by: str | None = None,
    order_direction: str | None = None,
    page: int | None = None,
) -> dict[str, Any]:
    """List recognition groups (enrolled faces or vehicles) on a Protect console.

    Returns {groups, _count} plus upstream envelope fields. Each group has a stable
    monotonic id (for example face_90), name/matchedName, detectionsCount, and
    createdAt/firstDetectedAt/lastDetectedAt timestamps. Names remain unchanged.
    The private recognition API returns groups under groups, rather than data.

    Default drains all links.next pages in batches up to 100. page_size=N returns
    records [(page-1)*N, page*N): exactly N when that many exist, fewer only at the
    end, never more. page is the 1-based window number counted in units of page_size
    (default 1); without page_size, returns one native console page.
    To continue, resume from _nextPage with the same page_size. _pageSize reports requested,
    sent, effective and returned sizes. Incomplete drains carry incomplete/incompleteReason.

    Args:
        host: Console reportedState.hostname or data[].id from list_hosts, for example "my-console";
            names match reportedState.hostname/name case-insensitively.
        type: Recognition type, normally 'face' or 'vehicle' (singular). Forwarded
            unchanged; plural forms return HTTP 400 from upstream.
        has_name: When true, return named groups only. Example: true.
        page_size: N returns records [(page-1)*N, page*N): exactly N when that many exist,
            fewer only at the end, never more; resume from _nextPage with the same page_size.
            Example: `100`.
        order_by: Sort field: name, createdAt, lastDetectedAt or detectionsCount.
            Example: 'name'. With no order_direction, upstream defaults to descending.
        order_direction: 'asc' or 'desc', case-insensitive; effective only with
            order_by. Unknown values return upstream HTTP 400. Example: 'asc'.
        page: 1-based window number counted in units of page_size (default 1); without
            page_size, returns one native console page; resume from _nextPage with the same
            page_size. Example: `2`.
    """
    client, registry = _require()
    return await recognition.list_recognition_groups(
        client, registry, host, type, has_name, page_size, order_by, order_direction, page
    )


@mcp.tool(annotations=READ_ONLY)
async def get_recognition_group_counts(
    host: str,
    type: str,
) -> dict[str, Any]:
    """Get aggregate recognition-group counts for a Protect console.

    Returns totals such as totalCount, nameNotNullCount (named groups), nameIsNullCount,
    notificationEnabledCount, and degradedCount.

    Required arguments: host, type (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        type: recognition type. Use 'face' or 'vehicle' (singular — plural forms return HTTP 400
            from upstream). Forwarded to the API as-is.
    """
    client, registry = _require()
    return await recognition.get_recognition_group_counts(client, registry, host, type)


@mcp.tool(annotations=READ_ONLY)
async def get_recognition_group_image(
    host: str,
    type: str,
    group_id: str,
) -> Any:
    """Get a recognition group's reference crop. Returns MCP ImageContent plus image metadata.

    Returns MCP ImageContent plus text and structured metadata
    {image_base64, content_type, size_bytes}; content_type is the upstream
    Content-Type header (typically image/jpeg), not assumed, and null when the upstream
    sends none.

    `type`: recognition type. Use 'face' or 'vehicle' (singular -- plural forms
      return HTTP 400 from upstream). Forwarded to the API as-is.

    Example call (get_recognition_group_image):
        {"host": "my-console", "type": "face", "group_id": "face_90"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        type: 'face' or 'vehicle' (singular; plural returns HTTP 400).
        group_id: Recognition group id, e.g. 'face_90'. Get it from list_recognition_groups (id).
            Protect recognition id.
    """
    client, registry = _require()
    return _image_result(
        await recognition.get_recognition_group_image(client, registry, host, type, group_id)
    )


@mcp.tool(annotations=READ_ONLY)
async def list_recognition_detections(
    host: str,
    type: str,
    group_id: str,
    page_size: int | None = None,
    start: int | None = None,
    end: int | None = None,
    page: int | None = None,
) -> dict[str, Any]:
    """List one enrolled recognition group's detections (sightings) on Protect.

    Returns {detections, _count} plus upstream envelope fields and epoch warnings.
    Required group_id comes from list_recognition_groups, for example face_90. There
    is no all-groups mode; a nonexistent group returns HTTP 404. Each detection has
    id, eventId (list_protect_events), thumbnailId (get_thumbnail), detectedAt (epoch
    milliseconds), cameraId and matchedGroupConfidence (0-100).

    Default drains all links.next pages in batches up to 100. page_size=N returns
    records [(page-1)*N, page*N): exactly N when that many exist, fewer only at the
    end, never more. page is the 1-based window number counted in units of page_size
    (default 1); without page_size, returns one native console page.
    To continue, resume from _nextPage with the same page_size. _pageSize reports requested,
    sent, effective and returned sizes. Incomplete drains carry incomplete/incompleteReason.

    page without page_size fetches one native page, with _nextPage when more exist.
    An explicit page keeps a bare list verbatim (no _warnings) when page_size is absent,
    and preserves every field of an object page verbatim with epoch-unit _warnings.
    A bare-list manual page is unchanged without _warnings; object pages preserve
    upstream fields and add epoch warnings.
    Examples are in docs/TOOL-USAGE.md#list_recognition_detections.

    Args:
        host: Console reportedState.hostname or data[].id from list_hosts, for example "my-console";
            names match reportedState.hostname/name case-insensitively.
        type: 'face' or 'vehicle' (singular); plural forms return HTTP 400 upstream.
        group_id: Group id from list_recognition_groups, for example 'face_90'.
        page_size: N returns records [(page-1)*N, page*N): exactly N when that many exist,
            fewer only at the end, never more; resume from _nextPage with the same page_size.
            Example: `100`.
        start: Optional UTC epoch seconds start, converted to milliseconds. Negative
            or millisecond-magnitude values add _warnings. Example: 1792972800.
        end: Optional UTC epoch seconds end, converted to milliseconds; omit both for
            all detections. The same magnitude warnings apply. Example: 1793059200.
        page: 1-based window number counted in units of page_size (default 1); without
            page_size, returns one native console page; resume from _nextPage with the same
            page_size. Example: `2`.
    """
    client, registry = _require()
    return await recognition.list_recognition_detections(
        client, registry, host, type, group_id, page_size, start, end, page
    )


@mcp.tool(annotations=READ_ONLY)
async def get_thumbnail(
    host: str,
    thumbnail_id: str,
) -> Any:
    """Get a detection thumbnail crop. Returns MCP ImageContent plus image metadata.

    Returns MCP ImageContent plus text and structured metadata
    {image_base64, content_type, size_bytes}; content_type is the upstream
    Content-Type header (typically image/jpeg), not assumed, and null when the upstream
    sends none.

    Example call (get_thumbnail):
        {"host": "my-console", "thumbnail_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        thumbnail_id: Detection thumbnail id. Get it from list_recognition_detections
            (detections[].thumbnailId).
    """
    client, registry = _require()
    return _image_result(await recognition.get_thumbnail(client, registry, host, thumbnail_id))


# --- Protect Light Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_lights(
    host: str,
) -> dict[str, Any]:
    """List all lights on a Protect console.

    Returns {result, _count}: result is the upstream array of lights verbatim and _count its length
    (an upstream object carrying a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_lights(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_light(
    host: str,
    light_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect light by ID.

    Returns: the light object, verbatim. To change it, pass only the fields to change as `settings`
    to update_light (a partial PATCH).

    Example call (get_light):
        {"host": "my-console", "light_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        light_id: Protect light id. Get it from list_lights (id). Protect id (24-hex) — not a
            Network device UUID.
    """
    client, registry = _require()
    return await protect.get_light(client, registry, host, light_id)


@mcp.tool(annotations=WRITE)
async def update_light(
    host: str,
    light_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect light (brightness, sensitivity, etc.).

    Returns {status: "updated", verified, before, after, response}, or {status: "noop", reason,
    resource} when every sent leaf already matches (no PATCH is sent). Read-before, no-op,
    PATCH, read-after: before/after are the object read before and after the write, verified
    is true when the read-after carries every sent leaf value (nested objects are compared
    leaf by leaf, so a partial nested update verifies by the leaves
    it sends; sibling keys it does not send are ignored), and response is the PATCH body
    verbatim (decoded JSON, the text of a non-JSON body, or null when the body is empty).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", before (the body read first), response
    (the preview)}; there is no read-after.

    Request body (Protect 7.3.70, PATCH /v1/lights/{id}; schema "inline requestBody schema") is
    passed in `settings`. No key is required; send only the keys to change.
    - name: string
    - isLightForceEnabled: boolean
    - lightModeSettings: object {mode: enum[always|motion|off], enableAt:
      enum[fulltime|dark]}
    - lightDeviceSettings: object {isIndicatorEnabled: boolean, pirDuration: number (>= 0),
      pirSensitivity: number (0-100), ledLevel: number (1-6)}

    Example call (update_light):
        {
          "host": "my-console",
          "light_id": "66d025b301ebc903e80003ea",
          "settings": {"name": "Front Door"}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        light_id: Protect light id. Get it from list_lights (id). Protect id (24-hex) — not a
            Network device UUID.
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.70 PATCH
            /v1/lights/{id} body. Keys: name, isLightForceEnabled, lightModeSettings,
            lightDeviceSettings.
    """
    client, registry = _require()
    return await protect.update_light(client, registry, host, light_id, **settings)


# --- Protect Chime Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_chimes(
    host: str,
) -> dict[str, Any]:
    """List all chimes on a Protect console.

    Returns {result, _count}: result is the upstream array of chimes verbatim and _count its length
    (an upstream object carrying a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_chimes(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_chime(
    host: str,
    chime_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect chime by ID.

    Returns: the chime object, verbatim. To change it, pass only the fields to change as `settings`
    to update_chime (a partial PATCH).

    Example call (get_chime):
        {"host": "my-console", "chime_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        chime_id: Protect chime id. Get it from list_chimes (id). Protect id (24-hex) — not a
            Network device UUID.
    """
    client, registry = _require()
    return await protect.get_chime(client, registry, host, chime_id)


@mcp.tool(annotations=WRITE)
async def update_chime(
    host: str,
    chime_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect chime (volume, ringtone, etc.).

    Returns {status: "updated", verified, before, after, response}, or {status: "noop", reason,
    resource} when every sent leaf already matches (no PATCH is sent). Read-before, no-op,
    PATCH, read-after: before/after are the object read before and after the write, verified
    is true when the read-after carries every sent leaf value (nested objects are compared
    leaf by leaf, so a partial nested update verifies by the leaves
    it sends; sibling keys it does not send are ignored), and response is the PATCH body
    verbatim (decoded JSON, the text of a non-JSON body, or null when the body is empty).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", before (the body read first), response
    (the preview)}; there is no read-after.

    Request body (Protect 7.3.70, PATCH /v1/chimes/{id}; schema "inline requestBody schema") is
    passed in `settings`. No key is required; send only the keys to change.
    - name: string
    - cameraIds: array of string
    - ringSettings: array of object {cameraId: string, repeatTimes: number (1-10),
      ringtoneId: string, volume: number (0-100)} (every item key required)

    Example call (update_chime):
        {
          "host": "my-console",
          "chime_id": "66d025b301ebc903e80003ea",
          "settings": {"name": "Hallway chime"}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        chime_id: Protect chime id. Get it from list_chimes (id). Protect id (24-hex) — not a
            Network device UUID.
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.70 PATCH
            /v1/chimes/{id} body. Keys: name, cameraIds, ringSettings.
    """
    client, registry = _require()
    return await protect.update_chime(client, registry, host, chime_id, **settings)


# --- Protect Viewer Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_viewers(
    host: str,
) -> dict[str, Any]:
    """List all viewers on a Protect console.

    Returns {result, _count}: result is the upstream array of viewers verbatim and _count its length
    (an upstream object carrying a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_viewers(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_viewer(
    host: str,
    viewer_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect viewer by ID.

    Returns: the viewer object, verbatim. To change it, pass only the fields to change as `settings`
    to update_viewer (a partial PATCH).

    Example call (get_viewer):
        {"host": "my-console", "viewer_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        viewer_id: Protect viewer id. Get it from list_viewers (id). Protect id (24-hex) — not a
            Network device UUID.
    """
    client, registry = _require()
    return await protect.get_viewer(client, registry, host, viewer_id)


@mcp.tool(annotations=WRITE)
async def update_viewer(
    host: str,
    viewer_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update settings for a Protect viewer (liveview assignment, etc.).

    Returns {status: "updated", verified, before, after, response}, or {status: "noop", reason,
    resource} when every sent leaf already matches (no PATCH is sent). Read-before, no-op,
    PATCH, read-after: before/after are the object read before and after the write, verified
    is true when the read-after carries every sent leaf value (nested objects are compared
    leaf by leaf, so a partial nested update verifies by the leaves
    it sends; sibling keys it does not send are ignored), and response is the PATCH body
    verbatim (decoded JSON, the text of a non-JSON body, or null when the body is empty).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", before (the body read first), response
    (the preview)}; there is no read-after.

    Request body (Protect 7.3.70, PATCH /v1/viewers/{id}; schema "inline requestBody schema") is
    passed in `settings`. No key is required; send only the keys to change.
    - name: string
    - liveview: oneOf[liveviewId|null]

    Example call (update_viewer):
        {
          "host": "my-console",
          "viewer_id": "66d025b301ebc903e80003ea",
          "settings": {"name": "Front Door"}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        viewer_id: Protect viewer id. Get it from list_viewers (id). Protect id (24-hex) — not a
            Network device UUID.
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.70 PATCH
            /v1/viewers/{id} body. Keys: name, liveview.
    """
    client, registry = _require()
    return await protect.update_viewer(client, registry, host, viewer_id, **settings)


# --- Protect Liveview Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_liveviews(
    host: str,
) -> dict[str, Any]:
    """List all liveviews on a Protect console.

    Returns {result, _count}: result is the upstream array of liveviews verbatim and _count its
    length (an upstream object carrying a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_liveviews(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_liveview(
    host: str,
    liveview_id: str,
) -> dict[str, Any]:
    """Get details for a single Protect liveview by ID.

    Returns: the liveview object, verbatim. To change it, pass only the fields to change as
    `settings` to update_liveview (a partial PATCH).

    Example call (get_liveview):
        {"host": "my-console", "liveview_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        liveview_id: Protect liveview id. Get it from list_liveviews (id). Protect id (24-hex) — not
            a Network device UUID.
    """
    client, registry = _require()
    return await protect.get_liveview(client, registry, host, liveview_id)


@mcp.tool(annotations=WRITE)
async def create_liveview(
    host: str,
    name: str,
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a liveview on a Protect console.

    Returns {status: "created", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    Request body (Protect 7.3.70, POST /v1/liveviews; schema "inline requestBody schema") is passed
    in `settings`. Required keys — id, modelKey, name, isDefault, isGlobal, owner, layout, slots.
    - id: string
    - modelKey: string
    - name: string
    - isDefault: boolean
    - isGlobal: boolean
    - owner: string
    - layout: number (1-26; the number of slots)
    - slots: array of object {cameras: array of string (camera ids), cycleMode:
      enum[motion|time], cycleInterval: number} (every item key required)
    Spec POST /v1/liveviews body is allOf[liveview] whose required list includes server-side fields
    (id, modelKey, owner); tool merges name + settings into the body. Provide layout + slots; treat
    id/modelKey/owner requirement as spec-as-published.

    Example call (create_liveview):
        {
          "host": "my-console",
          "name": "Front of house",
          "settings": {
            "id": "66d025b301ebc903e80003ea",
            "modelKey": "liveview",
            "isDefault": true,
            "isGlobal": true,
            "owner": "66d025b301ebc903e80003ea",
            "layout": 9,
            "slots": [
              {
                "cameras": ["66d025b301ebc903e80003ea"],
                "cycleMode": "motion",
                "cycleInterval": 10
              }
            ]
          }
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        name: Liveview display name (body field name).
        settings: Rest of the body (Protect 7.3.70 POST /v1/liveviews), merged with name. Provide
            layout, slots, id, modelKey, isDefault, isGlobal and owner, all required by the
            published schema. Leave name out; it comes from the name argument.
            Shape: {layout:number,slots:{cameras:string[],cycleMode:'motion'|'time',
            cycleInterval:number}[],id:string,modelKey:string,isDefault:boolean,
            isGlobal:boolean,owner:string}
    """
    client, registry = _require()
    extra = settings or {}
    return await protect.create_liveview(client, registry, host, name, **extra)


@mcp.tool(annotations=WRITE)
async def update_liveview(
    host: str,
    liveview_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update a liveview on a Protect console.

    Returns {status: "updated", verified, before, after, response}, or {status: "noop", reason,
    resource} when every sent leaf already matches (no PATCH is sent). Read-before, no-op,
    PATCH, read-after: before/after are the object read before and after the write, verified
    is true when the read-after carries every sent leaf value (nested objects are compared
    leaf by leaf, so a partial nested update verifies by the leaves
    it sends; sibling keys it does not send are ignored), and response is the PATCH body
    verbatim (decoded JSON, the text of a non-JSON body, or null when the body is empty).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", before (the body read first), response
    (the preview)}; there is no read-after.

    Request body (Protect 7.3.70, PATCH /v1/liveviews/{id}; schema "inline requestBody schema") is
    passed in `settings`. Required keys — id, modelKey, name, isDefault, isGlobal, owner, layout,
    slots (spec list, not checked: partial settings are sent as given).
    - id: string
    - modelKey: string
    - name: string
    - isDefault: boolean
    - isGlobal: boolean
    - owner: string
    - layout: number (1-26; the number of slots)
    - slots: array of object {cameras: array of string (camera ids), cycleMode:
      enum[motion|time], cycleInterval: number} (every item key required)

    Example call (update_liveview):
        {
          "host": "my-console",
          "liveview_id": "66d025b301ebc903e80003ea",
          "settings": {
            "id": "66d025b301ebc903e80003ea",
            "modelKey": "liveview",
            "name": "Lobby",
            "isDefault": true,
            "isGlobal": true,
            "owner": "66d025b301ebc903e80003ea",
            "layout": 9,
            "slots": [
              {
                "cameras": ["66d025b301ebc903e80003ea"],
                "cycleMode": "motion",
                "cycleInterval": 10
              }
            ]
          }
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        liveview_id: Protect liveview id. Get it from list_liveviews (id). Protect id (24-hex) — not
            a Network device UUID.
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.70 PATCH
            /v1/liveviews/{id} body. Required: id, modelKey, name, isDefault, isGlobal, owner,
            layout, slots. Spec list, not checked here: partial settings are sent as given.
    """
    client, registry = _require()
    return await protect.update_liveview(client, registry, host, liveview_id, **settings)


# --- Protect NVR Tools ---


@mcp.tool(annotations=READ_ONLY)
async def get_nvr(
    host: str,
) -> dict[str, Any]:
    """Get NVR details from a Protect console.

    Returns NVR hardware info, storage status, firmware version, and system health.

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.get_nvr(client, registry, host)


# --- Protect File Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_protect_files(
    host: str,
    file_type: str,
) -> dict[str, Any]:
    """List Protect device asset files of a given type.

    Returns {result, _count}: result is the upstream array of files verbatim and _count its length
    (an upstream object carrying a data array is returned verbatim plus _count); _file_type echoes
    the file_type argument.

    Required arguments: host, file_type (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        file_type: Protect asset category (path fileType). Protect 7.3.70 documents one value,
            'animations'; the value is passed through as given. The GET
            endpoint does NOT validate this value — an unrecognised category returns HTTP 200 with
            an empty list rather than an error, so a wrong value is indistinguishable from a
            genuinely empty category. Pass a known category exactly. Letters, digits, '-' and
            '_' only; anything else is rejected before any request.
    """
    client, registry = _require()
    return await protect.list_protect_files(client, registry, host, file_type)


@mcp.tool(annotations=WRITE)
async def upload_protect_file(
    host: str,
    file_type: str,
    filename: str,
    file_content_base64: str,
    content_type: str | None = None,
) -> dict[str, Any]:
    """Upload a Protect device asset file. WARNING: Uploads asset file to NVR storage.
    Overwriting system files may not be reversible.

    Consequence: the file is stored on the console and may overwrite an existing asset, which may
    not be reversible.

    Returns {status: "uploaded", response}: response is the upstream body verbatim (decoded
    JSON, the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    `file_type`: Protect asset category. Protect 7.3.70 documents one value, 'animations';
      the value is passed through as given and selects the upload target path
      (/files/{file_type}). The category is not
      validated on read-back, so pass a known category exactly.

    Request body: Protect 7.3.70 POST /v1/files/{fileType} is a multipart upload; the tool builds
    the file part from filename + file_content_base64. No JSON body. The part's Content-Type is
    content_type when given, else the spec type of the filename extension: .gif image/gif,
    .jpg/.jpeg image/jpeg, .png image/png, .mp3 audio/mpeg, .m4a/.mp4 audio/mp4, .wav
    audio/wave, .caf audio/x-caf. Any other extension without content_type is rejected before
    any request, listing these types.

    Example call (upload_protect_file):
        {
          "host": "my-console",
          "file_type": "animations",
          "filename": "alert.gif",
          "file_content_base64": "R0lGODlhAQABAAAAACw="
        }

    The dry-run preview contains method, path, params (query parameters), body (null: no JSON
    body) and multipart: one {field, filename, contentType, sizeBytes} entry per file part
    (field "file"), never the file bytes.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        file_type: Protect asset category (path fileType); Protect 7.3.70 documents one value,
            'animations'. Letters, digits, '-' and '_' only; anything else is rejected before
            any request.
        filename: Filename for the uploaded asset; its extension selects the part's Content-Type
            unless content_type is given.
        file_content_base64: File bytes, standard base64 (padded). Line-wrapped base64 (MIME/PEM
            line breaks) is accepted; a data: URL prefix is not.
        content_type: Optional MIME type of the file part (e.g. "audio/wave"), sent as given; omit
            it to derive the type from the filename extension.
    """
    client, registry = _require()
    return await protect.upload_protect_file(
        client, registry, host, file_type, filename, file_content_base64, content_type
    )


# --- Protect Alarm Manager Tools ---


@mcp.tool(annotations=WRITE)
async def trigger_alarm_webhook(
    host: str,
    webhook_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Trigger an alarm manager webhook by ID. WARNING: triggers physical alarm hardware.
    Verify the webhook ID before calling; the trigger is never auto-retried.

    Consequence: the alarm hardware behind the webhook acts in the real world.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    Example call (trigger_alarm_webhook):
        {"host": "my-console", "webhook_id": "66d025b301ebc903e80003ea"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        webhook_id: Alarm Manager webhook id (from the Protect Alarm Manager webhook trigger; the
            spec alarmTriggerId, a user-defined string). Any non-empty string without a control
            character is accepted and percent-encoded into the path as one segment ("." / ".."
            segments are refused). No list tool exists; verify before calling.
        confirm: Ignored. The call runs when made; there is no confirmation step.
    """
    client, registry = _require()
    return await protect.trigger_alarm_webhook(client, registry, host, webhook_id)


# --- Protect Arm Profile & Alarm Tools ---
#
# Extended Protect Integration API families, all reached over the same
# Fabric connector base (…/proxy/protect/integration/v1) as the camera tools. The
# write/action tools are governed by the UNIFI_PROTECT_MUTATIONS_ENABLED env gate
# (default ON); the confirm argument is accepted for compatibility and no longer required.


@mcp.tool(annotations=READ_ONLY)
async def list_arm_profiles(
    host: str,
) -> dict[str, Any]:
    """List arm profiles on a Protect console (GET /v1/arm-profiles via Fabric proxy).

    Returns {result, _count}: result is the upstream array of arm profiles verbatim and _count its
    length (an upstream object carrying a data array is returned verbatim plus _count).

    Availability requires a Protect application exposing the published Protect Integration API.

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_arm_profiles(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_arm_profile(
    host: str,
    arm_profile_id: str,
) -> dict[str, Any]:
    """Get one arm profile by id (filters GET /v1/arm-profiles; no GET-by-id exists upstream).

    Returns: the arm profile object, verbatim. To change it, pass only the fields to change as
    `settings` to update_arm_profile (a partial PATCH). An id the list does not carry fails,
    listing every valid arm_profile_id.

    Example call (get_arm_profile):
        {"host": "my-console", "arm_profile_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        arm_profile_id: Protect arm profile id. Get it from list_arm_profiles (id). Protect id
            (24-hex) — not a Network device UUID.
    """
    client, registry = _require()
    return await protect.get_arm_profile(client, registry, host, arm_profile_id)


@mcp.tool(annotations=WRITE)
async def create_arm_profile(
    host: str,
    name: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Create an arm profile (POST /v1/arm-profiles via Fabric proxy).

    Returns {status: "created", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    Request body (Protect 7.3.70, POST /v1/arm-profiles; schema "inline requestBody schema") is
    passed in `name` + settings (merged; settings must NOT contain name). Required keys — name,
    automations, schedules, recordEverything, activationDelay.
    - name: string 1-255
    - automations: array of string (automation ids)
    - schedules: array of armSchedule objects {start: string (cron expression), end: string
      (cron expression)} (both required)
    - recordEverything: boolean
    - activationDelay: one of 0|60000|300000|600000 (ms)

    Example call (create_arm_profile):
        {
          "host": "my-console",
          "name": "Night",
          "settings": {
            "automations": [],
            "schedules": [],
            "recordEverything": false,
            "activationDelay": 0
          }
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        name: REQUIRED profile name (1-255 chars), sent as the body field name. Do not repeat it
            inside settings; a settings['name'] that differs from this value is rejected with a
            clear error.
        settings: Rest of the body (Protect 7.3.70 POST /v1/arm-profiles). Required: automations,
            schedules, recordEverything, activationDelay (0|60000|300000|600000). Leave name out; it
            comes from the name argument.
    """
    client, registry = _require()
    return await protect.create_arm_profile(client, registry, host, name, **settings)


@mcp.tool(annotations=WRITE)
async def update_arm_profile(
    host: str,
    arm_profile_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update an arm profile (PATCH /v1/arm-profiles/{id}) with read-before/no-op/read-after.

    Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or
    {status: "noop", reason, resource} when every sent leaf already matches (nested objects
    compared leaf by leaf; sibling keys not sent are ignored). An unknown arm_profile_id fails
    before any PATCH, listing every valid id.
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", before (the body read first), response
    (the preview)}; there is no read-after.

    Request body (Protect 7.3.70, PATCH /v1/arm-profiles/{id}; schema "inline requestBody schema")
    is passed in `settings`. No key is required; send only the keys to change.
    - name: string
    - automations: array of string
    - schedules: array of armSchedule objects {start: string (cron expression), end: string
      (cron expression)} (both required)
    - recordEverything: boolean
    - activationDelay: one of 0|60000|300000|600000

    Example call (update_arm_profile):
        {
          "host": "my-console",
          "arm_profile_id": "66d025b301ebc903e80003ea",
          "settings": {"name": "Arm Profile"}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        arm_profile_id: Protect arm profile id. Get it from list_arm_profiles (id). Protect id
            (24-hex) — not a Network device UUID.
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.70 PATCH
            /v1/arm-profiles/{id} body. Keys: name, automations, schedules, recordEverything,
            activationDelay.
    """
    client, registry = _require()
    return await protect.update_arm_profile(client, registry, host, arm_profile_id, **settings)


@mcp.tool(annotations=WRITE)
async def delete_arm_profile(
    host: str,
    arm_profile_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Delete an arm profile (DELETE /v1/arm-profiles/{id}). Irreversible — no undo.

    Consequence: the profile can no longer be selected to arm the system.

    The id is found in the arm-profile list first (as update_arm_profile does): an unknown
    arm_profile_id fails before any DELETE, listing every valid id, and the DELETE addresses
    the profile by the id the console listed (hex ids match case-insensitively).

    Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
    (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is deleted: {status: "dry_run", deleted: false, message,
    response (the preview)}.

    Example call (delete_arm_profile):
        {"host": "my-console", "arm_profile_id": "66d025b301ebc903e80003ea"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        arm_profile_id: Protect arm profile id. Get it from list_arm_profiles (id). Protect id
            (24-hex) — not a Network device UUID.
        confirm: Ignored. The call runs when made; there is no confirmation step.
    """
    client, registry = _require()
    return await protect.delete_arm_profile(client, registry, host, arm_profile_id, confirm=confirm)


@mcp.tool(annotations=WRITE)
async def update_arm_profile_settings(
    host: str,
    arm_profile_id: str,
) -> dict[str, Any]:
    """Select the active arm profile (PATCH /v1/arm-profiles/settings).

    Returns {status: "updated", verified, before, after (the NVR armMode objects), response (the
    PATCH body verbatim)}, or {status: "noop", reason, resource (the current armMode)}. When
    the read-after fails or carries no armMode object, verified and after are null and
    readAfterError says why. Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", before
    (the body read first), response (the preview)}; there is no read-after.

    `arm_profile_id`: REQUIRED. Obtain it from `list_arm_profiles` (its id field); this
      becomes the console's selected arm profile. The id is checked against
      `list_arm_profiles` first: an id the list does not carry fails before any write,
      naming the valid ids; a hex id matches case-insensitively and the body sends the
      id as the list spells it. Reads the NVR armMode before/after (no-op if already
      selected). Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.

    Request body (Protect 7.3.70, PATCH /v1/arm-profiles/settings; schema "inline requestBody
    schema") is built from scalar parameters. Required keys — armProfileId.
    - armProfileId: string

    Example call (update_arm_profile_settings):
        {"host": "my-console", "arm_profile_id": "66d025b301ebc903e80003ea"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        arm_profile_id: Protect arm profile id. Get it from list_arm_profiles (id). Protect id
            (24-hex) — not a Network device UUID.
    """
    client, registry = _require()
    return await protect.update_arm_profile_settings(client, registry, host, arm_profile_id)


@mcp.tool(annotations=WRITE)
async def enable_arm(
    host: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Enable the arm alarm using the selected profile (POST /v1/arm-profiles/enable).

    Arm the alarm system using the selected arm profile.

    Consequence: the alarm system is armed: sensors in the selected profile can trigger alarms.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    WARNING: arms the alarm system (physical side effects); requires a local Alarm Manager.

    Example call (enable_arm):
        {"host": "my-console"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        confirm: Ignored. The call runs when made; there is no confirmation step.
    """
    client, registry = _require()
    return await protect.enable_arm(client, registry, host, confirm=confirm)


@mcp.tool(annotations=WRITE)
async def disable_arm(
    host: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Disable the arm alarm (POST /v1/arm-profiles/disable). Disarms the system.

    Consequence: the alarm system is disarmed: armed sensors no longer trigger alarms.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    WARNING: physical side effects; requires a local Alarm Manager.

    Example call (disable_arm):
        {"host": "my-console"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        confirm: Ignored. The call runs when made; there is no confirmation step.
    """
    client, registry = _require()
    return await protect.disable_arm(client, registry, host, confirm=confirm)


# --- Protect Siren Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_sirens(
    host: str,
) -> dict[str, Any]:
    """List sirens on a Protect console (GET /v1/sirens via Fabric proxy).

    Returns {result, _count}: result is the upstream array of sirens verbatim and _count its length
    (an upstream object carrying a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_sirens(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_siren(
    host: str,
    siren_id: str,
) -> dict[str, Any]:
    """Get one siren by id (GET /v1/sirens/{id}).

    Returns: the siren object, verbatim. To change it, pass only the fields to change as `settings`
    to update_siren (a partial PATCH).

    Example call (get_siren):
        {"host": "my-console", "siren_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        siren_id: Protect siren id. Get it from list_sirens (id). Protect id (24-hex) — not a
            Network device UUID.
    """
    client, registry = _require()
    return await protect.get_siren(client, registry, host, siren_id)


@mcp.tool(annotations=WRITE)
async def update_siren(
    host: str,
    siren_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update siren settings (PATCH /v1/sirens/{id}) with read-before/no-op/read-after.

    Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or
    {status: "noop", reason, resource} when every sent leaf already matches (nested objects
    compared leaf by leaf; sibling keys not sent are ignored).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", before (the body read first), response
    (the preview)}; there is no read-after.

    Request body (Protect 7.3.70, PATCH /v1/sirens/{id}; schema "inline requestBody schema") is
    passed in `settings`. No key is required; send only the keys to change.
    - name: string
    - volume: integer (1-100)
    - ledSettings: object {isEnabled: boolean (required inside ledSettings)}

    Example call (update_siren):
        {
          "host": "my-console",
          "siren_id": "66d025b301ebc903e80003ea",
          "settings": {"name": "Front Door"}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        siren_id: Protect siren id. Get it from list_sirens (id). Protect id (24-hex) — not a
            Network device UUID.
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.70 PATCH
            /v1/sirens/{id} body. Keys: name, volume, ledSettings.
    """
    client, registry = _require()
    return await protect.update_siren(client, registry, host, siren_id, **settings)


@mcp.tool(annotations=WRITE)
async def siren_play(
    host: str,
    siren_id: str,
    confirm: bool = False,
    duration: int | None = None,
) -> dict[str, Any]:
    """Sound a siren (POST /v1/sirens/{id}/play). WARNING: physical alarm sound.

    Consequence: a loud siren sounds at the site for the chosen duration.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    The siren sounds for `duration` seconds (5/10/20/30; 5 upstream when omitted).
    Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.

    Request body (Protect 7.3.70, POST /v1/sirens/{id}/play; schema "inline requestBody schema") is
    built from scalar parameters. No key is required; send only the keys to change.
    - duration: one of 5|10|20|30

    Example call (siren_play):
        {"host": "my-console", "siren_id": "66d025b301ebc903e80003ea"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        siren_id: Protect siren id. Get it from list_sirens (id). Protect id (24-hex) — not a
            Network device UUID.
        confirm: Ignored. The call runs when made; there is no confirmation step.
        duration: Seconds to sound: 5, 10, 20, or 30 (spec sirenDurationSeconds). Default 5.
    """
    client, registry = _require()
    return await protect.siren_play(
        client, registry, host, siren_id, confirm=confirm, duration=duration
    )


@mcp.tool(annotations=WRITE)
async def siren_stop(
    host: str,
    siren_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Stop a sounding siren (POST /v1/sirens/{id}/stop). WARNING: physical action.

    Consequence: the siren is silenced.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    Example call (siren_stop):
        {"host": "my-console", "siren_id": "66d025b301ebc903e80003ea"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        siren_id: Protect siren id. Get it from list_sirens (id). Protect id (24-hex) — not a
            Network device UUID.
        confirm: Ignored. The call runs when made; there is no confirmation step.
    """
    client, registry = _require()
    return await protect.siren_stop(client, registry, host, siren_id, confirm=confirm)


@mcp.tool(annotations=WRITE)
async def siren_test_sound(
    host: str,
    siren_id: str,
    confirm: bool = False,
    volume: int | None = None,
) -> dict[str, Any]:
    """Test a siren's sound (POST /v1/sirens/{id}/test-sound). WARNING: physical sound.

    Consequence: the siren plays a test sound aloud.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    `volume`: 1-100 (defaults to device volume upstream).
      Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.

    Request body (Protect 7.3.70, POST /v1/sirens/{id}/test-sound; schema "inline requestBody
    schema") is built from scalar parameters. No key is required; send only the keys to change.
    - volume: integer (1-100)

    Example call (siren_test_sound):
        {"host": "my-console", "siren_id": "66d025b301ebc903e80003ea"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        siren_id: Protect siren id. Get it from list_sirens (id). Protect id (24-hex) — not a
            Network device UUID.
        confirm: Ignored. The call runs when made; there is no confirmation step.
        volume: Test volume 1-100; omit to use the device volume.
    """
    client, registry = _require()
    return await protect.siren_test_sound(
        client, registry, host, siren_id, confirm=confirm, volume=volume
    )


# --- Protect Fob Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_fobs(
    host: str,
) -> dict[str, Any]:
    """List fobs on a Protect console (GET /v1/fobs via Fabric proxy).

    Returns {result, _count}: result is the upstream array of fobs verbatim and _count its length
    (an upstream object carrying a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_fobs(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_fob(
    host: str,
    fob_id: str,
) -> dict[str, Any]:
    """Get one fob by id (GET /v1/fobs/{id}).

    Returns: the fob object, verbatim. To change it, pass only the fields to change as `settings` to
    update_fob (a partial PATCH).

    Example call (get_fob):
        {"host": "my-console", "fob_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        fob_id: Protect fob id. Get it from list_fobs (id). Protect id (24-hex) — not a Network
            device UUID.
    """
    client, registry = _require()
    return await protect.get_fob(client, registry, host, fob_id)


@mcp.tool(annotations=WRITE)
async def update_fob(
    host: str,
    fob_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update fob settings (PATCH /v1/fobs/{id}) with read-before/no-op/read-after.

    Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or
    {status: "noop", reason, resource} when every sent leaf already matches (nested objects
    compared leaf by leaf; sibling keys not sent are ignored).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", before (the body read first), response
    (the preview)}; there is no read-after.

    Request body (Protect 7.3.70, PATCH /v1/fobs/{id}; schema "inline requestBody schema") is passed
    in `settings`. No key is required; send only the keys to change.
    - name: string

    Example call (update_fob):
        {
          "host": "my-console",
          "fob_id": "66d025b301ebc903e80003ea",
          "settings": {"name": "Front Door"}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        fob_id: Protect fob id. Get it from list_fobs (id). Protect id (24-hex) — not a Network
            device UUID.
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.70 PATCH
            /v1/fobs/{id} body. Keys: name.
    """
    client, registry = _require()
    return await protect.update_fob(client, registry, host, fob_id, **settings)


# --- Protect Relay Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_relays(
    host: str,
) -> dict[str, Any]:
    """List relays on a Protect console (GET /v1/relays via Fabric proxy).

    Returns {result, _count}: result is the upstream array of relays verbatim and _count its length
    (an upstream object carrying a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_relays(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_relay(
    host: str,
    relay_id: str,
) -> dict[str, Any]:
    """Get one relay by id (GET /v1/relays/{id}).

    Returns: the relay object, verbatim. To change it, pass only the fields to change as `settings`
    to update_relay (a partial PATCH).

    Example call (get_relay):
        {"host": "my-console", "relay_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        relay_id: Protect relay id. Get it from list_relays (id). Protect id (24-hex) — not a
            Network device UUID.
    """
    client, registry = _require()
    return await protect.get_relay(client, registry, host, relay_id)


@mcp.tool(annotations=WRITE)
async def update_relay(
    host: str,
    relay_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update relay settings (PATCH /v1/relays/{id}) with read-before/no-op/read-after.

    Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or
    {status: "noop", reason, resource} when every sent leaf already matches (nested objects
    compared leaf by leaf; sibling keys not sent are ignored).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", before (the body read first), response
    (the preview)}; there is no read-after.

    Request body (Protect 7.3.70, PATCH /v1/relays/{id}; schema "inline requestBody schema") is
    passed in `settings`. No key is required; send only the keys to change.
    - name: string
    - ledSettings: object {isEnabled: boolean}

    Example call (update_relay):
        {
          "host": "my-console",
          "relay_id": "66d025b301ebc903e80003ea",
          "settings": {"name": "Front Door"}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        relay_id: Protect relay id. Get it from list_relays (id). Protect id (24-hex) — not a
            Network device UUID.
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.70 PATCH
            /v1/relays/{id} body. Keys: name, ledSettings.
    """
    client, registry = _require()
    return await protect.update_relay(client, registry, host, relay_id, **settings)


@mcp.tool(annotations=WRITE)
async def relay_activate_output(
    host: str,
    relay_id: str,
    output_id: int | str,
    confirm: bool = False,
    state: str | None = None,
    pulse_duration: int | None = None,
) -> dict[str, Any]:
    """Switch a relay output (POST /v1/relays/{id}/outputs/{outputId}/activate).

    Consequence: whatever is wired to the relay output (door lock, gate, light) acts in the real
    world.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    WARNING: physically switches hardware.

    Request body (Protect 7.3.70, POST /v1/relays/{id}/outputs/{outputId}/activate; schema "inline
    requestBody schema") is built from scalar parameters. No key is required; send only the keys to
    change.
    - state: enum[on|off]
    - pulseDuration: integer

    Example call (relay_activate_output):
        {"host": "my-console", "relay_id": "66d025b301ebc903e80003ea", "output_id": 0}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        relay_id: Protect relay id. Get it from list_relays (id). Protect id (24-hex) — not a
            Network device UUID.
        output_id: Output channel id on that device; spec: integer 0 or 1 (an integer, or the same
            value as a decimal string '0'|'1'). See get_relay.
        confirm: Ignored. The call runs when made; there is no confirmation step.
        state: 'on' or 'off'; omit to toggle (spec body state).
        pulse_duration: Auto-off after N ms (spec body pulseDuration, >=0). The spec applies it
            only when state is 'on'; the server sends it as given and does not check state.
    """
    client, registry = _require()
    return await protect.relay_activate_output(
        client,
        registry,
        host,
        relay_id,
        output_id,
        confirm=confirm,
        state=state,
        pulse_duration=pulse_duration,
    )


# --- Protect Speaker Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_speakers(
    host: str,
) -> dict[str, Any]:
    """List speakers on a Protect console (GET /v1/speakers via Fabric proxy).

    Returns {result, _count}: result is the upstream array of speakers verbatim and _count its
    length (an upstream object carrying a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_speakers(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_speaker(
    host: str,
    speaker_id: str,
) -> dict[str, Any]:
    """Get one speaker by id (GET /v1/speakers/{id}).

    Returns: the speaker object, verbatim. To change it, pass only the fields to change as
    `settings` to update_speaker (a partial PATCH).

    Example call (get_speaker):
        {"host": "my-console", "speaker_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        speaker_id: Protect speaker id. Get it from list_speakers (id). Protect id (24-hex) — not a
            Network device UUID.
    """
    client, registry = _require()
    return await protect.get_speaker(client, registry, host, speaker_id)


@mcp.tool(annotations=WRITE)
async def update_speaker(
    host: str,
    speaker_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update speaker settings (PATCH /v1/speakers/{id}) with read-before/no-op/read-after.

    Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or
    {status: "noop", reason, resource} when every sent leaf already matches (nested objects
    compared leaf by leaf; sibling keys not sent are ignored).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", before (the body read first), response
    (the preview)}; there is no read-after.

    Request body (Protect 7.3.70, PATCH /v1/speakers/{id}; schema "inline requestBody schema") is
    passed in `settings`. No key is required; send only the keys to change.
    - name: string
    - volume: integer (0-100)
    - micVolume: integer (0-100)
    - isMicEnabled: boolean

    Example call (update_speaker):
        {
          "host": "my-console",
          "speaker_id": "66d025b301ebc903e80003ea",
          "settings": {"name": "Front Door"}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        speaker_id: Protect speaker id. Get it from list_speakers (id). Protect id (24-hex) — not a
            Network device UUID.
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.70 PATCH
            /v1/speakers/{id} body. Keys: name, volume, micVolume, isMicEnabled.
    """
    client, registry = _require()
    return await protect.update_speaker(client, registry, host, speaker_id, **settings)


@mcp.tool(annotations=WRITE)
async def speaker_test_sound(
    host: str,
    speaker_id: str,
    confirm: bool = False,
    volume: int | None = None,
) -> dict[str, Any]:
    """Test a speaker's sound (POST /v1/speakers/{id}/test-sound). WARNING: physical sound.

    Consequence: the speaker plays a test sound aloud.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    `volume`: 0-100 (defaults to device volume upstream).
      Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.

    Request body (Protect 7.3.70, POST /v1/speakers/{id}/test-sound; schema "inline requestBody
    schema") is built from scalar parameters. No key is required; send only the keys to change.
    - volume: integer (0-100)

    Example call (speaker_test_sound):
        {"host": "my-console", "speaker_id": "66d025b301ebc903e80003ea"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        speaker_id: Protect speaker id. Get it from list_speakers (id). Protect id (24-hex) — not a
            Network device UUID.
        confirm: Ignored. The call runs when made; there is no confirmation step.
        volume: Test volume 0-100; omit to use the device volume.
    """
    client, registry = _require()
    return await protect.speaker_test_sound(
        client, registry, host, speaker_id, confirm=confirm, volume=volume
    )


# --- Protect Bridge Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_bridges(
    host: str,
) -> dict[str, Any]:
    """List bridges on a Protect console (GET /v1/bridges via Fabric proxy).

    Returns {result, _count}: result is the upstream array of bridges verbatim and _count its length
    (an upstream object carrying a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_bridges(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_bridge(
    host: str,
    bridge_id: str,
) -> dict[str, Any]:
    """Get one bridge by id (GET /v1/bridges/{id}).

    Returns: the bridge object, verbatim. To change it, pass only the fields to change as `settings`
    to update_bridge (a partial PATCH).

    Example call (get_bridge):
        {"host": "my-console", "bridge_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        bridge_id: Protect bridge id. Get it from list_bridges (id). Protect id (24-hex) — not a
            Network device UUID.
    """
    client, registry = _require()
    return await protect.get_bridge(client, registry, host, bridge_id)


@mcp.tool(annotations=WRITE)
async def update_bridge(
    host: str,
    bridge_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update bridge settings (PATCH /v1/bridges/{id}) with read-before/no-op/read-after.

    Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or
    {status: "noop", reason, resource} when every sent leaf already matches (nested objects
    compared leaf by leaf; sibling keys not sent are ignored).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", before (the body read first), response
    (the preview)}; there is no read-after.

    Request body (Protect 7.3.70, PATCH /v1/bridges/{id}; schema "inline requestBody schema") is
    passed in `settings`. No key is required; send only the keys to change.
    - name: string

    Example call (update_bridge):
        {
          "host": "my-console",
          "bridge_id": "66d025b301ebc903e80003ea",
          "settings": {"name": "Front Door"}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        bridge_id: Protect bridge id. Get it from list_bridges (id). Protect id (24-hex) — not a
            Network device UUID.
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.70 PATCH
            /v1/bridges/{id} body. Keys: name.
    """
    client, registry = _require()
    return await protect.update_bridge(client, registry, host, bridge_id, **settings)


# --- Protect Link Station Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_link_stations(
    host: str,
) -> dict[str, Any]:
    """List link stations on a Protect console (GET /v1/link-stations via Fabric proxy).

    Returns {result, _count}: result is the upstream array of link stations verbatim and _count its
    length (an upstream object carrying a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_link_stations(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_link_station(
    host: str,
    link_station_id: str,
) -> dict[str, Any]:
    """Get one link station by id (GET /v1/link-stations/{id}).

    Returns: the link station object, verbatim. To change it, pass only the fields to change as
    `settings` to update_link_station (a partial PATCH).

    Example call (get_link_station):
        {"host": "my-console", "link_station_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        link_station_id: Protect link station id. Get it from list_link_stations (id). Protect id
            (24-hex) — not a Network device UUID.
    """
    client, registry = _require()
    return await protect.get_link_station(client, registry, host, link_station_id)


@mcp.tool(annotations=WRITE)
async def update_link_station(
    host: str,
    link_station_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update link-station settings (PATCH /v1/link-stations/{id}) with read/no-op/read-after.

    Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or
    {status: "noop", reason, resource} when every sent leaf already matches (nested objects
    compared leaf by leaf; sibling keys not sent are ignored).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", before (the body read first), response
    (the preview)}; there is no read-after.

    Request body (Protect 7.3.70, PATCH /v1/link-stations/{id}; schema "inline requestBody schema")
    is passed in `settings`. No key is required; send only the keys to change.
    - name: string

    Example call (update_link_station):
        {
          "host": "my-console",
          "link_station_id": "66d025b301ebc903e80003ea",
          "settings": {"name": "Front Door"}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        link_station_id: Protect link station id. Get it from list_link_stations (id). Protect id
            (24-hex) — not a Network device UUID.
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.70 PATCH
            /v1/link-stations/{id} body. Keys: name.
    """
    client, registry = _require()
    return await protect.update_link_station(client, registry, host, link_station_id, **settings)


# --- Protect Alarm Hub Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_alarm_hubs(
    host: str,
) -> dict[str, Any]:
    """List alarm hubs on a Protect console (GET /v1/alarm-hubs via Fabric proxy).

    Returns {result, _count}: result is the upstream array of alarm hubs verbatim and _count its
    length (an upstream object carrying a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_alarm_hubs(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_alarm_hub(
    host: str,
    alarm_hub_id: str,
) -> dict[str, Any]:
    """Get one alarm hub by id (GET /v1/alarm-hubs/{id}).

    Returns: the alarm hub object, verbatim. To change it, pass only the fields to change as
    `settings` to update_alarm_hub (a partial PATCH).

    Example call (get_alarm_hub):
        {"host": "my-console", "alarm_hub_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        alarm_hub_id: Protect alarm hub id. Get it from list_alarm_hubs (id). Protect id (24-hex) —
            not a Network device UUID.
    """
    client, registry = _require()
    return await protect.get_alarm_hub(client, registry, host, alarm_hub_id)


@mcp.tool(annotations=WRITE)
async def update_alarm_hub(
    host: str,
    alarm_hub_id: str,
    settings: dict[str, Any],
) -> dict[str, Any]:
    """Update alarm-hub settings (PATCH /v1/alarm-hubs/{id}) with read-before/no-op/read-after.

    Returns {status: "updated", verified, before, after, response (the PATCH body verbatim)}, or
    {status: "noop", reason, resource} when every sent leaf already matches (nested objects
    compared leaf by leaf; sibling keys not sent are ignored).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", before (the body read first), response
    (the preview)}; there is no read-after.

    Request body (Protect 7.3.70, PATCH /v1/alarm-hubs/{id}; schema "inline requestBody schema") is
    passed in `settings`. No key is required; send only the keys to change.
    - name: string

    Example call (update_alarm_hub):
        {
          "host": "my-console",
          "alarm_hub_id": "66d025b301ebc903e80003ea",
          "settings": {"name": "Front Door"}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        alarm_hub_id: Protect alarm hub id. Get it from list_alarm_hubs (id). Protect id (24-hex) —
            not a Network device UUID.
        settings: Partial update (PATCH; only listed keys change); spec Protect 7.3.70 PATCH
            /v1/alarm-hubs/{id} body. Keys: name.
    """
    client, registry = _require()
    return await protect.update_alarm_hub(client, registry, host, alarm_hub_id, **settings)


@mcp.tool(annotations=WRITE)
async def alarm_hub_trigger_output(
    host: str,
    alarm_hub_id: str,
    output_id: int | str,
    confirm: bool = False,
    enable: bool | None = None,
    delay: int | None = None,
    duration: int | None = None,
) -> dict[str, Any]:
    """Trigger an alarm-hub output (POST /v1/alarm-hubs/{id}/outputs/{outputId}/trigger).

    Consequence: whatever is wired to the output (siren, strobe, lock, relay) acts in the real
    world.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    WARNING: physically triggers alarm-hub output hardware. `enable` true turns the
    output on, false off (omit to toggle); `delay` is ms before activating; `duration` is
    ms to stay active (0 = indefinite). Governed by UNIFI_PROTECT_MUTATIONS_ENABLED.

    Request body (Protect 7.3.70, POST /v1/alarm-hubs/{id}/outputs/{outputId}/trigger; schema
    "inline requestBody schema") is built from scalar parameters. No key is required; send only the
    keys to change.
    - enable: boolean
    - delay: integer
    - duration: integer

    Example call (alarm_hub_trigger_output):
        {"host": "my-console", "alarm_hub_id": "66d025b301ebc903e80003ea", "output_id": 0}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        alarm_hub_id: Protect alarm hub id. Get it from list_alarm_hubs (id). Protect id (24-hex) —
            not a Network device UUID.
        output_id: Output channel id on that device; spec: integer 0 or 1 (an integer, or the same
            value as a decimal string '0'|'1'). See get_alarm_hub.
        confirm: Ignored. The call runs when made; there is no confirmation step.
        enable: true = on, false = off; omit to toggle.
        delay: Milliseconds to wait before activating.
        duration: Milliseconds to stay active (0 = indefinite).
    """
    client, registry = _require()
    return await protect.alarm_hub_trigger_output(
        client,
        registry,
        host,
        alarm_hub_id,
        output_id,
        confirm=confirm,
        enable=enable,
        delay=delay,
        duration=duration,
    )


# --- Protect User Tools (read-only) ---


@mcp.tool(annotations=READ_ONLY)
async def list_protect_users(
    host: str,
) -> dict[str, Any]:
    """List Protect users (GET /v1/users via Fabric proxy). Read-only in the Integration API.

    Returns {result, _count}: result is the upstream array of users verbatim and _count its length
    (an upstream object carrying a data array is returned verbatim plus _count).

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_protect_users(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_protect_user(
    host: str,
    user_id: str,
) -> dict[str, Any]:
    """Get one Protect user by id (GET /v1/users/{id}). Read-only.

    Returns the upstream user object verbatim, exactly as the API answers it.

    Example call (get_protect_user):
        {"host": "my-console", "user_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        user_id: Protect user id. Get it from list_protect_users (id). Not a ULP (UI account) user
            id.
    """
    client, registry = _require()
    return await protect.get_protect_user(client, registry, host, user_id)


# --- Protect Application Metadata ---


@mcp.tool(annotations=READ_ONLY)
async def get_protect_application_info(
    host: str,
) -> dict[str, Any]:
    """Get Protect application metadata (GET /v1/meta/info via Fabric proxy). Read-only.

    Returns the upstream meta-info ({applicationVersion, ...}) object verbatim, exactly as the API
    answers it.

    Reports the Protect application version and Integration-API capabilities — the
    authoritative check for which extended Protect families this console supports.

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.get_protect_application_info(client, registry, host)


# --- Protect ULP User Tools (read-only) ---


@mcp.tool(annotations=READ_ONLY)
async def list_ulp_users(
    host: str,
) -> dict[str, Any]:
    """List ULP (UniFi account) users (GET /v1/ulp-users). Read-only.

    Returns {result, _count}: result is the upstream array of ULP users verbatim and _count its
    length (an upstream object carrying a data array is returned verbatim plus _count).

    Distinct from `list_protect_users` (/v1/users): these are UI-account identities.

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await protect.list_ulp_users(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_ulp_user(
    host: str,
    ulp_user_id: str,
) -> dict[str, Any]:
    """Get one ULP (UniFi account) user by id (GET /v1/ulp-users/{id}). Read-only.

    Returns the upstream ULP user object verbatim, exactly as the API answers it.

    Example call (get_ulp_user):
        {"host": "my-console", "ulp_user_id": "66d025b301ebc903e80003ea"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        ulp_user_id: ULP (UI account) user id. Get it from list_ulp_users (id). Not a Protect user
            id.
    """
    client, registry = _require()
    return await protect.get_ulp_user(client, registry, host, ulp_user_id)


# --- Protect POS Transaction Ingestion ---


@mcp.tool(annotations=WRITE)
async def pos_ingest_transaction(
    host: str,
    camera_id: str,
    transaction: dict[str, Any],
    confirm: bool = False,
) -> dict[str, Any]:
    """Ingest a POS transaction overlay onto camera footage.

    Consequence: the transaction is overlaid on the camera's recorded footage.

    Returns {status: "sent", response}: response is the upstream body verbatim (decoded JSON,
    the text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", response (the preview)}.

    Route: POST /v1/pos/cameras/{id}/transactions (Fabric proxy).

    WARNING: creates a footage overlay event with no documented rollback. The transaction is
    validated locally and carries an idempotency key; the POS write is never auto-retried.
    `transaction`: REQUIRED posTransactionRequest object. Must include `type`
      ('sale'|'refund'), `externalId` (per-camera unique idempotency/dedup key), and
      `amount`; optional currency/lineItems/location/paymentTypes/timestamp pass through.

    Request body (Protect 7.3.70, POST /v1/pos/cameras/{id}/transactions; schema
    "posTransactionRequest") is passed in `transaction`. Required keys — type, externalId, amount.
    - type: enum[sale|refund]
    - externalId: string
    - amount: number
    - currency: string
    - lineItems: array of object, at most 200 items {title: string (1-255 characters),
      quantity: integer (>= 1)} (both item keys required)
    - location: object {id: string (1-255 characters, required), name: string (1-255
      characters)}
    - paymentTypes: array of string
    - timestamp: integer

    Example call (pos_ingest_transaction):
        {
          "host": "my-console",
          "camera_id": "66d025b301ebc903e80003ea",
          "transaction": {"type": "sale", "externalId": "order-1042", "amount": 24.95}
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        camera_id: Protect camera id. Get it from list_cameras (id). Protect id (24-hex) — not a
            Network device UUID.
        transaction: posTransactionRequest (Protect 7.3.70). Required: type ('sale'|'refund'),
            externalId (per-camera unique dedup key), amount. Never auto-retried.
        confirm: Ignored. The call runs when made; there is no confirmation step.
    """
    client, registry = _require()
    return await protect.pos_ingest_transaction(
        client, registry, host, camera_id, transaction, confirm=confirm
    )


# --- Port Forwarding Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_port_forwards(
    host: str,
    site: str,
) -> Any:
    """List all port forwarding rules for a site.

    Returns: the controller envelope {meta, data: [rule…]}, entries verbatim. To change one, edit
    its data[] entry and pass it as `payload` to update_port_forward (forward_id = its _id).

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_port_forwards(client, registry, host, site)


@mcp.tool(annotations=WRITE)
async def create_port_forward(
    host: str,
    site: str,
    payload: dict[str, Any],
) -> Any:
    """Create a port forwarding rule via the Classic REST API.

    Returns: the controller's Classic REST response envelope {meta: {rc}, data: [...]}
    verbatim (meta is relayed as received, never interpreted).
    Under UNIFI_DRY_RUN nothing is sent: the result is the bare dry-run preview {status: "dry_run",
    dryRun: true, sent: false,
    message, preview: {method, path, params, body}} in place of the upstream body.

    `payload`: port forward config. Pass name, dst_port, fwd and fwd_port. ``proto`` is
    optional (the controller defaults it, typically 'tcp_udp'). The body is sent as given:
    this Classic REST endpoint has no published schema and is observed to accept a body
    without those fields and create a broken rule, so include them; an upstream error gets a
    hint naming any that are missing.
    Example: {"enabled": true, "name": "SSH", "pfwd_interface": "wan", "src": "any",
    "dst_port": "2222", "fwd": "192.168.1.10", "fwd_port": "22", "proto": "tcp", "log": false}

    Request body: no published schema exists for POST network/api/s/{site}/rest/portforward
    (classic/v2 controller API). Pass the controller's native payload; read the current object first
    with the matching list/get tool and send back the edited object.

    Example call (create_port_forward):
        {
          "host": "my-console",
          "site": "Default",
          "payload": {
            "enabled": true,
            "name": "SSH",
            "pfwd_interface": "wan",
            "src": "any",
            "dst_port": "2222",
            "fwd": "192.0.2.10",
            "fwd_port": "22",
            "proto": "tcp",
            "log": false
          }
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        payload: spec: free-form (classic REST portforward), sent as given. Pass name,
            dst_port, fwd (target IP), fwd_port; proto optional (tcp|udp|tcp_udp).
            Free-form JSON object; no fixed body shape is published.
    """
    client, registry = _require()
    return await network_services_proxy.create_port_forward(client, registry, host, site, payload)


@mcp.tool(annotations=WRITE)
async def update_port_forward(
    host: str,
    site: str,
    forward_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a port forwarding rule by ID.

    The id is resolved in list_port_forwards first: an unknown id fails listing every valid _id, and
    nothing is written.

    Returns: the controller's Classic REST response envelope {meta: {rc}, data: [...]}
    verbatim (meta is relayed as received, never interpreted).
    Under UNIFI_DRY_RUN nothing is sent: the result is the bare dry-run preview {status: "dry_run",
    dryRun: true, sent: false,
    message, preview: {method, path, params, body}} in place of the upstream body.

    Request body: no published schema exists for PUT network/api/s/{site}/rest/portforward/{id}
    (classic/v2 controller API). Pass the controller's native payload; read the current object first
    with the matching list/get tool and send back the edited object.

    Example call (update_port_forward):
        {
          "host": "my-console",
          "site": "Default",
          "forward_id": "65f1c0ffee0123456789abcd",
          "payload": {"enabled": false}
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        forward_id: Port-forward rule _id (classic REST portforward). Get it from list_port_forwards
            (_id).
        payload: spec: free-form (classic REST portforward). Fields to change (snake_case, e.g.
            dst_port, fwd, fwd_port, enabled). Read current via list_port_forwards.
            Free-form JSON object; no fixed body shape is published.
    """
    client, registry = _require()
    return await network_services_proxy.update_port_forward(
        client, registry, host, site, forward_id, payload
    )


@mcp.tool(annotations=WRITE)
async def delete_port_forward(
    host: str,
    site: str,
    forward_id: str,
) -> dict[str, Any]:
    """Delete a port forwarding rule by ID.

    Consequence: inbound connections on the forwarded port stop reaching the internal host; there is
    no undo.

    The id is resolved in list_port_forwards first (the controller answers a DELETE on an unknown id
    with HTTP 200): an unknown id fails listing every valid _id, and nothing is deleted.

    Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
    (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is deleted: {status: "dry_run", deleted: false, message,
    response (the preview)}.

    Example call (delete_port_forward):
        {"host": "my-console", "site": "Default", "forward_id": "65f1c0ffee0123456789abcd"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        forward_id: Port-forward rule _id (classic REST portforward). Get it from list_port_forwards
            (_id).
    """
    client, registry = _require()
    response = await network_services_proxy.delete_port_forward(
        client, registry, host, site, forward_id
    )
    return deletion_result(f"Port forward {forward_id} deleted.", response)


# --- Traffic Rule Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_traffic_rules(
    host: str,
    site: str,
) -> Any:
    """List traffic matching rules (QoS, application, IP group matching).

    Requires a controller implementing the v2 trafficrules route. Consoles without it
    return HTTP 501 api.err.NotImplemented; the upstream error is returned to the caller.

    Returns: the v2 API's bare JSON array of rules, verbatim (the same shape as
    list_traffic_routes). To change one, edit its entry and pass it as `payload` to
    update_traffic_rule (rule_id = its _id).

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_traffic_rules(client, registry, host, site)


@mcp.tool(annotations=WRITE)
async def create_traffic_rule(
    host: str,
    site: str,
    payload: dict[str, Any],
) -> Any:
    """Create a traffic matching rule (QoS, block, or route by application/IP group).

    Returns the upstream response body verbatim: the created traffic rule object the API answers
    with (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message,
    preview: {method, path, params (query parameters), body}} instead).

    `payload`: sent as given; the controller requires these fields (verified live; an
    upstream error gets a hint naming any that are missing):
      - action: 'BLOCK'|'THROTTLE_RATE'|'QUEUE'
      - matching_target: 'INTERNET'|'LOCAL'|'ALL' or a traffic matching list id (from
        list_traffic_matching_lists)
      - target_devices: the devices/networks the rule applies to (required by the API;
        previously undocumented)
      Optional (NOT required by the API): description (str), enabled (bool, controller
      defaults it), matching_target_type ('INTERNET'|'DOMAIN'|'IP_GROUP'|'APPLICATION_GROUP'),
      bandwidth_limit (dict with up_limit_kbps/down_limit_kbps for THROTTLE_RATE).
    Note: uses the Classic REST v2 API (/v2/api/site/{siteId}/trafficrules). May not exist
    on firmware 10.2.105 and below. On the tested Network 11.0.89 controller this POST
    returned HTTP 501 api.err.NotImplemented; the upstream error is returned to the caller.
    The separately supported firewall-policy tools use a different policy schema.

    Request body: no published schema exists for POST network/v2/api/site/{site}/trafficrules
    (classic/v2 controller API). Pass the controller's native payload; read the current object first
    with the matching list/get tool and send back the edited object.

    Example call (create_traffic_rule):
        {
          "host": "my-console",
          "site": "Default",
          "payload": {
            "action": "BLOCK",
            "matching_target": "INTERNET",
            "target_devices": [{"client_mac": "aa:bb:cc:dd:ee:ff"}],
            "description": "Block guests",
            "enabled": true
          }
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        payload: spec: free-form (Network v2 trafficrules), sent as given. The controller
            requires action BLOCK|THROTTLE_RATE|QUEUE, matching_target (INTERNET|LOCAL|ALL or
            list id) and target_devices.
            Free-form JSON object; no fixed body shape is published.
    """
    client, registry = _require()
    return await network_services_proxy.create_traffic_rule(client, registry, host, site, payload)


@mcp.tool(annotations=WRITE)
async def update_traffic_rule(
    host: str,
    site: str,
    rule_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a traffic rule by ID.

    Requires a controller implementing the v2 trafficrules route. Consoles without it
    return HTTP 501 api.err.NotImplemented; the upstream error is returned to the caller.

    The id is resolved in list_traffic_rules first: an unknown id fails listing every valid _id, and
    nothing is written.

    Returns the upstream response body verbatim: the updated traffic rule object the API answers
    with (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message,
    preview: {method, path, params (query parameters), body}} instead).

    Request body: no published schema exists for PUT network/v2/api/site/{site}/trafficrules/{id}/
    (classic/v2 controller API). Pass the controller's native payload; read the current object first
    with the matching list/get tool and send back the edited object.

    Example call (update_traffic_rule):
        {
          "host": "my-console",
          "site": "Default",
          "rule_id": "65f1c0ffee0123456789abcd",
          "payload": {"enabled": false}
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        rule_id: Traffic rule id (Network v2 API _id). Get it from list_traffic_rules (_id).
        payload: spec: free-form (Network v2 trafficrules). Fields to change; read current via
            list_traffic_rules.
            Free-form JSON object; no fixed body shape is published.
    """
    client, registry = _require()
    return await network_services_proxy.update_traffic_rule(
        client, registry, host, site, rule_id, payload
    )


@mcp.tool(annotations=WRITE)
async def delete_traffic_rule(
    host: str,
    site: str,
    rule_id: str,
) -> dict[str, Any]:
    """Delete a traffic rule by ID.

    Requires a controller implementing the v2 trafficrules route. Consoles without it
    return HTTP 501 api.err.NotImplemented; the upstream error is returned to the caller.

    Consequence: the rule stops applying to matching traffic immediately; there is no undo.

    The id is resolved in list_traffic_rules first (the controller answers a DELETE on an unknown id
    with HTTP 200): an unknown id fails listing every valid _id, and nothing is deleted.

    Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
    (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is deleted: {status: "dry_run", deleted: false, message,
    response (the preview)}.

    Example call (delete_traffic_rule):
        {"host": "my-console", "site": "Default", "rule_id": "65f1c0ffee0123456789abcd"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        rule_id: Traffic rule id (Network v2 API _id). Get it from list_traffic_rules (_id).
    """
    client, registry = _require()
    response = await network_services_proxy.delete_traffic_rule(
        client, registry, host, site, rule_id
    )
    return deletion_result(f"Traffic rule {rule_id} deleted.", response)


vpn.register(mcp, _require)
network_vpn_dns.register(mcp, _require)
site_config.register(mcp, _require)
radius_profiles.register(mcp, _require)
hotspot.register(mcp, _require)
aggregation.register(mcp, _require)
statistics.register(mcp, _require)
protect_events_cases.register(mcp, _require)
network_controller_insights.register(mcp, _require)
network_dpi_policy.register(mcp, lambda: _require())
protect_users_assets.register(mcp, _require)
protect_automation_backup.register(mcp, _require)
network_security_diagnostics.register(mcp, _require)
network_proav_sandbox.register(mcp, _require)
protect_ptz_doorbell.register(mcp, _require)
protect_recognition_search.register(mcp, _require)
protect_device_lifecycle.register(mcp, _require)
network_mobile_wan.register(mcp, _require)
network_device_operations.register(mcp, _require)
client_records.register(mcp, _require)
system_log.register(mcp, _require)
vpn_clients.register(mcp, _require)
site_admin.register(mcp, _require)


# --- User / DHCP Reservation Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_users(
    host: str,
    site: str,
) -> Any:
    """List DHCP fixed-IP reservations and client aliases for a site.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [entry…]} verbatim; data[]
    entries carry fields such as name, note, fixed_ip, use_fixedip, network_id.

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_users(client, registry, host, site)


@mcp.tool(annotations=READ_ONLY)
async def get_user(
    host: str,
    site: str,
    user_id: str,
) -> Any:
    """Get a single DHCP/client-alias entry by ID.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [client-alias/DHCP user
    entry]} verbatim. To change it, edit data[0] and pass it as `payload` to update_user.

    Example call (get_user):
        {"host": "my-console", "site": "Default", "user_id": "65f1c0ffee0123456789abcd"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        user_id: Network client-alias/DHCP user _id (classic REST user). Get it from list_users
            (_id).
    """
    client, registry = _require()
    return await network_services_proxy.get_user(client, registry, host, site, user_id)


@mcp.tool(annotations=WRITE)
async def update_user(
    host: str,
    site: str,
    user_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a DHCP/client-alias entry by ID.

    The id is resolved in list_users first: an unknown id fails listing every valid _id, and nothing
    is written.

    Returns: the controller's Classic REST response envelope {meta: {rc}, data: [...]}
    verbatim (meta is relayed as received, never interpreted).
    Under UNIFI_DRY_RUN nothing is sent: the result is the bare dry-run preview {status: "dry_run",
    dryRun: true, sent: false,
    message, preview: {method, path, params, body}} in place of the upstream body.

    Request body: no published schema exists for PUT network/api/s/{site}/rest/user/{id} (classic/v2
    controller API). Pass the controller's native payload; read the current object first with the
    matching list/get tool and send back the edited object.

    Example call (update_user):
        {
          "host": "my-console",
          "site": "Default",
          "user_id": "65f1c0ffee0123456789abcd",
          "payload": {"name": "Printer", "note": "2nd floor"}
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        user_id: Network client-alias/DHCP user _id (classic REST user). Get it from list_users
            (_id).
        payload: spec: free-form (classic REST user). Fields to change: name, note, fixed_ip,
            use_fixedip, network_id (classic networkconf _id).
            Free-form JSON object; no fixed body shape is published.
    """
    client, registry = _require()
    return await network_services_proxy.update_user(client, registry, host, site, user_id, payload)


# --- Traffic Route Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_traffic_routes(
    host: str,
    site: str,
) -> Any:
    """List static/policy traffic routes for a site.

    Returns the v2 API's bare JSON array of routes, verbatim (a list result: structured content
    {result: [...]}).

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_traffic_routes(client, registry, host, site)


@mcp.tool(annotations=WRITE)
async def create_traffic_route(
    host: str,
    site: str,
    payload: dict[str, Any],
) -> Any:
    """Create a traffic route on a site (policy-based routing / WAN load-balancing).

    Returns the upstream response body verbatim: the created traffic route object the API answers
    with (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message,
    preview: {method, path, params (query parameters), body}} instead).

    `payload`: sent as given; the controller requires these fields (verified live; an
    upstream error gets a hint naming any that are missing). This v2 endpoint uses snake_case wire
    field names (verified: 'network_id' is accepted, 'networkId' is not):
      - network_id (str): source network UUID (from list_networks), or 'ANY'
      - matching_target: 'INTERNET'|'ALL' or a traffic matching list id (from
        list_traffic_matching_lists)
      - target_devices: the devices/networks the route applies to
      Optional: matching_target_type ('INTERNET'|'DOMAIN'|'IP_GROUP'), description (str).

    Request body: no published schema exists for POST network/v2/api/site/{site}/trafficroutes
    (classic/v2 controller API). Pass the controller's native payload; read the current object first
    with the matching list/get tool and send back the edited object.

    Example call (create_traffic_route):
        {
          "host": "my-console",
          "site": "Default",
          "payload": {
            "network_id": "ANY",
            "matching_target": "INTERNET",
            "target_devices": [{"client_mac": "aa:bb:cc:dd:ee:ff"}],
            "description": "Route via WAN2"
          }
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        payload: spec: free-form (Network v2 trafficroutes, snake_case), sent as given. The
            controller requires network_id (list_networks UUID or 'ANY'), matching_target,
            target_devices.
            Free-form JSON object; no fixed body shape is published.
    """
    client, registry = _require()
    return await network_services_proxy.create_traffic_route(client, registry, host, site, payload)


@mcp.tool(annotations=READ_ONLY)
async def get_traffic_route(
    host: str,
    site: str,
    route_id: str,
) -> Any:
    """Get a single traffic route by ID.

    Returns: the traffic route object, verbatim. To change it, edit it and pass it as `payload` to
    update_traffic_route.

    Example call (get_traffic_route):
        {"host": "my-console", "site": "Default", "route_id": "65f1c0ffee0123456789abcd"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        route_id: Traffic route _id (Network v2 API). Get it from list_traffic_routes (_id).
    """
    client, registry = _require()
    return await network_services_proxy.get_traffic_route(client, registry, host, site, route_id)


@mcp.tool(annotations=WRITE)
async def update_traffic_route(
    host: str,
    site: str,
    route_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a traffic route by ID.

    The id is resolved in list_traffic_routes first: an unknown id fails listing every valid _id,
    and nothing is written.

    Returns the upstream response body verbatim: the updated traffic route object the API answers
    with (under UNIFI_DRY_RUN, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
    message,
    preview: {method, path, params (query parameters), body}} instead).

    Request body: no published schema exists for PUT network/v2/api/site/{site}/trafficroutes/{id}
    (classic/v2 controller API). Pass the controller's native payload; read the current object first
    with the matching list/get tool and send back the edited object.

    Example call (update_traffic_route):
        {
          "host": "my-console",
          "site": "Default",
          "route_id": "65f1c0ffee0123456789abcd",
          "payload": {
            "description": "IoT via WAN2",
            "enabled": false,
            "matching_target": "INTERNET",
            "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            "target_devices": [{"client_mac": "aa:bb:cc:dd:ee:ff"}]
          }
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        route_id: Traffic route _id (Network v2 API). Get it from list_traffic_routes (_id).
        payload: spec: free-form (Network v2 trafficroutes, snake_case). FULL replacement object;
            start from get_traffic_route output.
            Free-form JSON object; no fixed body shape is published.
    """
    client, registry = _require()
    return await network_services_proxy.update_traffic_route(
        client, registry, host, site, route_id, payload
    )


@mcp.tool(annotations=WRITE)
async def delete_traffic_route(
    host: str,
    site: str,
    route_id: str,
) -> dict[str, Any]:
    """Delete a traffic route by ID.

    Consequence: matching traffic stops following the route and uses the default routing; there is
    no undo.

    The id is resolved in list_traffic_routes first (the controller answers a DELETE on an unknown
    id with HTTP 200): an unknown id fails listing every valid _id, and nothing is deleted.

    Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
    (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
    Under UNIFI_DRY_RUN nothing is deleted: {status: "dry_run", deleted: false, message,
    response (the preview)}.

    Example call (delete_traffic_route):
        {"host": "my-console", "site": "Default", "route_id": "65f1c0ffee0123456789abcd"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        route_id: Traffic route _id (Network v2 API). Get it from list_traffic_routes (_id).
    """
    client, registry = _require()
    response = await network_services_proxy.delete_traffic_route(
        client, registry, host, site, route_id
    )
    return deletion_result(f"Traffic route {route_id} deleted.", response)


# --- Controller Settings Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_settings(
    host: str,
    site: str,
) -> Any:
    """List all controller setting groups for a site.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [setting group…]}
    verbatim; data[] holds one object per key (mgmt, super_smtp, guest_access, etc.).

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_settings(client, registry, host, site)


@mcp.tool(annotations=READ_ONLY)
async def get_setting(
    host: str,
    site: str,
    setting_key: str,
) -> Any:
    """Get a controller setting group by key.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [setting group]} verbatim.
    To change it, edit data[0] and pass it as `payload` to update_setting.

    There is no schema endpoint, so reading a group is how you discover what it accepts:
    the returned object lists every settable field and its current (valid) value. Inspect
    it before calling update_setting — the controller silently drops any field or enum
    value it does not recognise, so match an existing field's shape exactly. Common keys
    and notable enum fields (grounded in live responses): mdns (mode, enabled_for),
    ntp (setting_preference), doh (state), ips (ips_mode), global_nat (mode),
    ssl_inspection (state), dashboard (layout_preference), locale (timezone),
    country (code), guest_access (auth), super_mgmt (data_retention_setting_preference).
    Fields prefixed 'x_' hold credentials/secrets and are returned verbatim.

    Required arguments: host, site, setting_key (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        setting_key: setting group identifier (e.g. 'mgmt', 'super_smtp', 'guest_access').
    """
    client, registry = _require()
    return await network_services_proxy.get_setting(client, registry, host, site, setting_key)


@mcp.tool(annotations=WRITE)
async def update_setting(
    host: str,
    site: str,
    setting_key: str,
    payload: dict[str, Any],
) -> Any:
    """Update a controller setting group by key.

    Discover the schema first by calling get_setting(setting_key): it returns every
    settable field and its current (valid) value. The controller silently drops any
    unrecognised field or enum value (HTTP 200, value unchanged), so a guessed value
    fails invisibly; this tool reports that no-op separately from the PUT response, naming
    every rejected field and pointing you back at get_setting. The check walks the payload
    leaf by leaf: a nested object is compared as a partial update (only the keys you send
    must take), and a
    nested leaf left unchanged is named by its dotted path (e.g. radius.port) even when a sibling
    leaf in the same object was applied; _verificationNote names the rejected and applied
    leaves.

    Returns: the controller's PUT response envelope {meta: {rc}, data: [setting group]} verbatim
    plus the additive _verified: true only when the read-after confirms every submitted leaf
    (type-strict: true is not 1), false with _unverifiedFields (dotted paths) when a leaf was
    rejected or changed to a value other than the one sent (v0.6.2 raised for a rejected
    leaf; check _verified), null with _readAfterError when the read-after failed or could not
    be matched (the write was still sent). When every submitted field already holds the sent
    value, no PUT is made and the current GET envelope is returned verbatim plus an additive
    _note "no change needed".
    Under UNIFI_DRY_RUN nothing is sent: the result is the bare dry-run preview {status: "dry_run",
    dryRun: true, sent: false,
    message, preview: {method, path, params, body}} in place of the upstream body.

    Request body: no published schema exists for PUT network/api/s/{site}/rest/setting/{setting_key}
    (classic controller API). Pass the controller's native payload; read the current object first
    with the matching list/get tool and send back the edited object.

    Example call (update_setting):
        {
          "host": "my-console",
          "site": "Default",
          "setting_key": "mgmt",
          "payload": {"led_enabled": false}
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        setting_key: Classic setting group key, e.g. 'mgmt', 'super_smtp', 'guest_access'. Get keys
            from list_settings (data[].key). Keys a Network 11.0.81 site reports: auto_speedtest,
            connectivity, country, dashboard, device_supervision, doh, dpi, element_adopt,
            ether_lighting, global_nat, global_network, global_switch, guest_access,
            igmp_snooping, ips, ips_suppression, ipsec, lcm, locale, magic_site_to_site_vpn, mdns,
            mgmt, netflow, network_optimization, ntp, openvpn, peer_to_peer,
            provider_capabilities, radio_ai, radius, rsyslogd, snmp, ssl_inspection,
            super_cloudaccess, super_fabric_system_log, super_fwupdate, super_identity,
            super_mail, super_mgmt, super_smtp, super_stats, teleport, traffic_flow, ugw, usg,
            usg_geo (super_* groups are console-wide). Groups holding credentials in x_-prefixed
            fields: connectivity, element_adopt, guest_access, magic_site_to_site_vpn, mgmt,
            openvpn, radius, snmp, super_cloudaccess, super_fwupdate, super_smtp.
        payload: spec: free-form (classic REST setting). Call get_setting(setting_key) first and
            change only fields it returns; unknown fields/enums are reported separately in
            verification metadata.
            Free-form JSON object; no fixed body shape is published.
    """
    client, registry = _require()
    return await network_services_proxy.update_setting(
        client, registry, host, site, setting_key, payload
    )


# --- Dynamic DNS Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_dynamic_dns(
    host: str,
    site: str,
) -> Any:
    """List Dynamic DNS provider configurations for a site.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim,
    including plaintext x_password credential fields.

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_dynamic_dns(client, registry, host, site)


@mcp.tool(annotations=READ_ONLY)
async def get_dynamic_dns(
    host: str,
    site: str,
    ddns_id: str,
) -> Any:
    """Get a single Dynamic DNS configuration by ID.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [Dynamic DNS entry]}
    verbatim. To change it, edit data[0] and pass it as `payload` to update_dynamic_dns.

    Returned verbatim, including plaintext x_password credential fields.

    Example call (get_dynamic_dns):
        {"host": "my-console", "site": "Default", "ddns_id": "65f1c0ffee0123456789abcd"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        ddns_id: Dynamic DNS entry _id (classic REST dynamicdns). Get it from list_dynamic_dns
            (_id).
    """
    client, registry = _require()
    return await network_services_proxy.get_dynamic_dns(client, registry, host, site, ddns_id)


@mcp.tool(annotations=WRITE)
async def update_dynamic_dns(
    host: str,
    site: str,
    ddns_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a Dynamic DNS configuration by ID.

    The id is resolved in list_dynamic_dns first: an unknown id fails listing every valid _id, and
    nothing is written.

    Returns: the controller's Classic REST response envelope {meta: {rc}, data: [...]}
    verbatim (meta is relayed as received, never interpreted).
    Under UNIFI_DRY_RUN nothing is sent: the result is the bare dry-run preview {status: "dry_run",
    dryRun: true, sent: false,
    message, preview: {method, path, params, body}} in place of the upstream body.

    Request body: no published schema exists for PUT network/api/s/{site}/rest/dynamicdns/{id}
    (classic/v2 controller API). Pass the controller's native payload; read the current object first
    with the matching list/get tool and send back the edited object.

    Example call (update_dynamic_dns):
        {
          "host": "my-console",
          "site": "Default",
          "ddns_id": "65f1c0ffee0123456789abcd",
          "payload": {"service": "dyndns", "hostname": "home.example.com"}
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        ddns_id: Dynamic DNS entry _id (classic REST dynamicdns). Get it from list_dynamic_dns
            (_id).
        payload: spec: free-form (classic REST dynamicdns). Fields to change; read current via
            get_dynamic_dns.
            Free-form JSON object; no fixed body shape is published.
    """
    client, registry = _require()
    return await network_services_proxy.update_dynamic_dns(
        client, registry, host, site, ddns_id, payload
    )


# --- Port Profile Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_port_profiles(
    host: str,
    site: str,
) -> Any:
    """List switch port profiles (speed, VLAN, PoE config) for a site.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [profile…]}, each profile
    verbatim (networkconf id fields stay bare Classic _ids). A profile that references networks
    also carries an additive _resolved_networks key mapping excluded_networkconf_ids /
    native_networkconf_id / voice_networkconf_id to {id, name, vlan} (id there is the Classic
    networkconf _id); it is not a controller field and update_port_profile ignores it.

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_port_profiles(client, registry, host, site)


@mcp.tool(annotations=READ_ONLY)
async def get_port_profile(
    host: str,
    site: str,
    profile_id: str,
) -> Any:
    """Get a single switch port profile by ID.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [port profile]}
    verbatim, plus an additive _resolved_networks key on the profile mapping its networkconf ids
    to {id, name, vlan}. To change it, edit data[0] and pass it as `payload` to
    update_port_profile (the _resolved_networks key is dropped before the write).

    Example call (get_port_profile):
        {"host": "my-console", "site": "Default", "profile_id": "65f1c0ffee0123456789abcd"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        profile_id: Switch port profile _id (classic REST portconf). Get it from list_port_profiles
            (_id).
    """
    client, registry = _require()
    return await network_services_proxy.get_port_profile(client, registry, host, site, profile_id)


@mcp.tool(annotations=WRITE)
async def update_port_profile(
    host: str,
    site: str,
    profile_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a switch port profile by ID.

    The id is resolved in list_port_profiles first: an unknown id fails listing every valid _id, and
    nothing is written.

    WARNING -- SHARED PROFILE, WIDE BLAST RADIUS: this edits a shared Ethernet Port
    Profile (Classic REST /rest/portconf), NOT one switch or one port. A single write
    changes STP/PoE/storm-control/VLAN/etc. for EVERY port on EVERY switch that has this
    profile assigned. It is NOT a per-device or per-port writer and must never be
    presented or used as a per-port/per-device STP-priority or PoE-mode writer -- for
    that, no confirmed per-port config route exists via this API. Read the profile's
    assignments and confirm the intended blast radius before writing.

    Request body: no published schema exists for PUT network/api/s/{site}/rest/portconf/{id}
    (classic/v2 controller API). Pass the controller's native payload; read the current object first
    with the matching list/get tool and send back the edited object.

    Returns: the controller's PUT response envelope {meta: {rc}, data: [port profile]} verbatim,
    the profile plus the additive _resolved_networks key.
    Under UNIFI_DRY_RUN nothing is sent: the result is the bare dry-run preview {status: "dry_run",
    dryRun: true, sent: false,
    message, preview: {method, path, params, body}} in place of the upstream body.

    Example call (update_port_profile):
        {
          "host": "my-console",
          "site": "Default",
          "profile_id": "65f1c0ffee0123456789abcd",
          "payload": {"poe_mode": "auto"}
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        profile_id: Switch port profile _id (classic REST portconf). Get it from list_port_profiles
            (_id).
        payload: spec: free-form (classic REST portconf). Fields to change, e.g. speed,
            native_networkconf_id, op_mode, poe_mode. Read current via get_port_profile; its
            additive _resolved_networks key is dropped before the write.
            native_networkconf_id, voice_networkconf_id and excluded_networkconf_ids accept a
            Classic networkconf _id or the Integration id from list_networks (data[].id), which
            the tool converts to the _id before the PUT (a value the profile already holds
            passes unchanged); an unknown value fails listing every network (name, _id, id),
            and no PUT is sent.
            Free-form JSON object; no fixed body shape is published.
    """
    client, registry = _require()
    return await network_services_proxy.update_port_profile(
        client, registry, host, site, profile_id, payload
    )


@mcp.tool(annotations=WRITE)
async def allow_network_on_port_profile(
    host: str,
    site: str,
    profile_id: str,
    network_id: str,
    confirm: bool = False,
) -> Any:
    """Atomically allow (un-exclude) a VLAN network on a switch port profile.

    The result carries _profileNote only when the controller PUT response data array
    contains no profile; _tagged_networks is derived from the written payload.
    Other response bodies are returned unchanged.

    `confirm`: accepted and ignored. This is a live PUT to a SHARED port profile (its
      exclusion list affects every switch port using it); it runs immediately either way.

    This is the Network auto-exclusion remediation: it validates `network_id` against the site's
    networks, fresh-reads the profile, removes the network from `excluded_networkconf_ids`, and
    PUTs. Use it on every profile named in a `create_network` `D12_AUTO_EXCLUSION` _warnings
    entry.

    `network_id` accepts EITHER id of the network: the Network Integration id (list_networks
    data[].id, the id create_network returns) or the Classic networkconf _id (the value stored in
    excluded_networkconf_ids). An Integration id is mapped to its _id through the /rest/networkconf
    external_id field. An unknown id fails before any write, listing every network (name, vlan,
    _id and id).

    Returns: the controller's PUT response envelope {meta: {rc}, data: [profile]} verbatim (the
    profile plus the additive _resolved_networks key), plus additive keys: _tagged_networks (the
    resulting tagged VLAN set with names) and _network ({_id, id, name, vlan} of the network
    acted on).
    Under UNIFI_DRY_RUN nothing is sent: the result is the bare dry-run preview {status: "dry_run",
    dryRun: true, sent: false,
    message, preview: {method, path, params, body}} in place of the upstream body.

    Request body: none is passed by the caller. The tool fresh-reads the classic portconf record,
    removes the network's _id from excluded_networkconf_ids, and PUTs it back (no published spec
    for network/api/s/{site}/rest/portconf).

    Example call (allow_network_on_port_profile):
        {
          "host": "my-console",
          "site": "Default",
          "profile_id": "65f1c0ffee0123456789abcd",
          "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        profile_id: Switch port profile _id (classic REST portconf). Get it from list_port_profiles
            (_id).
        network_id: Network (networkconf) id to (un)exclude. Get it from list_networks (data[].id)
            or list_port_profiles (_resolved_networks).
        confirm: Ignored; accepted for backward compatibility. The call executes immediately when
            made unless the operator opted in to UNIFI_DRY_RUN (then nothing is
            sent upstream and a preview of the request is returned).
    """
    client, registry = _require()
    return await network_services_proxy.allow_network_on_port_profile(
        client, registry, host, site, profile_id, network_id, confirm=confirm
    )


@mcp.tool(annotations=WRITE)
async def exclude_network_on_port_profile(
    host: str,
    site: str,
    profile_id: str,
    network_id: str,
    confirm: bool = False,
) -> Any:
    """Atomically exclude (untag) a VLAN network from a switch port profile.

    The result carries _profileNote only when the controller PUT response data array
    contains no profile; _tagged_networks is derived from the written payload.
    Other response bodies are returned unchanged.

    `confirm`: accepted and ignored. This is a live PUT to a SHARED port profile (its
      exclusion list affects every switch port using it); it runs immediately either way.

    Inverse of `allow_network_on_port_profile`: validates `network_id` against the site's
    networks, fresh-reads the profile, adds the network to `excluded_networkconf_ids`, and PUTs.

    `network_id` accepts EITHER id of the network: the Network Integration id (list_networks
    data[].id, the id create_network returns) or the Classic networkconf _id (the value stored in
    excluded_networkconf_ids). An Integration id is mapped to its _id through the /rest/networkconf
    external_id field, and the _id is what gets written. An unknown id fails before any write,
    listing every network (name, vlan, _id and id).

    Returns: the controller's PUT response envelope {meta: {rc}, data: [profile]} verbatim (the
    profile plus the additive _resolved_networks key), plus additive keys: _tagged_networks (the
    resulting tagged VLAN set with names) and _network ({_id, id, name, vlan} of the network
    acted on).
    Under UNIFI_DRY_RUN nothing is sent: the result is the bare dry-run preview {status: "dry_run",
    dryRun: true, sent: false,
    message, preview: {method, path, params, body}} in place of the upstream body.

    Request body: none is passed by the caller. The tool fresh-reads the classic portconf record,
    adds the network's _id to excluded_networkconf_ids, and PUTs it back (no published spec for
    network/api/s/{site}/rest/portconf).

    Example call (exclude_network_on_port_profile):
        {
          "host": "my-console",
          "site": "Default",
          "profile_id": "65f1c0ffee0123456789abcd",
          "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        profile_id: Switch port profile _id (classic REST portconf). Get it from list_port_profiles
            (_id).
        network_id: Network (networkconf) id to (un)exclude. Get it from list_networks (data[].id)
            or list_port_profiles (_resolved_networks).
        confirm: Ignored; accepted for backward compatibility. The call executes immediately when
            made unless the operator opted in to UNIFI_DRY_RUN (then nothing is
            sent upstream and a preview of the request is returned).
    """
    client, registry = _require()
    return await network_services_proxy.exclude_network_on_port_profile(
        client, registry, host, site, profile_id, network_id, confirm=confirm
    )


# --- Routing Table Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_routing_entries(
    host: str,
    site: str,
) -> Any:
    """List static routing table entries for a site.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
    (meta is relayed as received, never interpreted).

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_routing_entries(client, registry, host, site)


# --- WLAN Config Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_wlan_configs(
    host: str,
    site: str,
) -> Any:
    """List per-SSID WLAN configurations (security, band steering, rate limits) for a site.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim,
    including plaintext x_passphrase credential fields.

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_wlan_configs(client, registry, host, site)


@mcp.tool(annotations=READ_ONLY)
async def get_wlan_config(
    host: str,
    site: str,
    wlan_id: str,
) -> Any:
    """Get a single WLAN (SSID) configuration by ID.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [WLAN configuration]}
    verbatim. To change it, edit data[0] and pass it as `payload` to update_wlan_config.

    Returned verbatim, including plaintext x_passphrase credential fields.

    Example call (get_wlan_config):
        {"host": "my-console", "site": "Default", "wlan_id": "65f1c0ffee0123456789abcd"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        wlan_id: Classic WLAN config _id (wlanconf). Get it from list_wlan_configs (_id). Not a wifi
            broadcast UUID.
    """
    client, registry = _require()
    return await network_services_proxy.get_wlan_config(client, registry, host, site, wlan_id)


@mcp.tool(annotations=WRITE)
async def update_wlan_config(
    host: str,
    site: str,
    wlan_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a WLAN (SSID) configuration by ID.

    The id is resolved in list_wlan_configs first: an unknown id fails listing every valid _id, and
    nothing is written.

    Returns: the controller's Classic REST response envelope {meta: {rc}, data: [...]}
    verbatim (meta is relayed as received, never interpreted).
    Under UNIFI_DRY_RUN nothing is sent: the result is the bare dry-run preview {status: "dry_run",
    dryRun: true, sent: false,
    message, preview: {method, path, params, body}} in place of the upstream body.

    Request body: no published schema exists for PUT network/api/s/{site}/rest/wlanconf/{id}
    (classic/v2 controller API). Pass the controller's native payload; read the current object first
    with the matching list/get tool and send back the edited object.

    Example call (update_wlan_config):
        {
          "host": "my-console",
          "site": "Default",
          "wlan_id": "65f1c0ffee0123456789abcd",
          "payload": {"enabled": false}
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        wlan_id: Classic WLAN config _id (wlanconf). Get it from list_wlan_configs (_id). Not a wifi
            broadcast UUID.
        payload: spec: free-form (classic REST wlanconf). Fields to change, e.g. x_passphrase,
            security, enabled. Read current via get_wlan_config.
            Free-form JSON object; no fixed body shape is published.
    """
    client, registry = _require()
    return await network_services_proxy.update_wlan_config(
        client, registry, host, site, wlan_id, payload
    )


# --- WLAN Group Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_wlan_groups(
    host: str,
    site: str,
) -> Any:
    """List WLAN groups for a site.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
    (meta is relayed as received, never interpreted).

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_wlan_groups(client, registry, host, site)


@mcp.tool(annotations=READ_ONLY)
async def get_wlan_group(
    host: str,
    site: str,
    group_id: str,
) -> Any:
    """Get a single WLAN group by ID.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
    (meta is relayed as received, never interpreted).

    Reads the Classic REST /rest/wlangroup collection and returns that envelope
    {meta: {rc}, data: [group]} with data narrowed to the group whose _id matches; an unknown id
    fails listing the valid groups (name and _id). The controller rejects
    GET /rest/wlangroup/{id} with HTTP 400 api.err.InvalidObject for every id, including
    the built-in Default group, so the collection route is the supported read. The
    matching entry is returned unchanged.

    Example call (get_wlan_group):
        {"host": "my-console", "site": "Default", "group_id": "000000000000000000000001"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        group_id: Classic WLAN group _id. Get it from list_wlan_groups (_id).
    """
    client, registry = _require()
    return await network_services_proxy.get_wlan_group(client, registry, host, site, group_id)


# --- Channel Plan Tools ---


@mcp.tool(annotations=READ_ONLY)
async def get_channel_plan(
    host: str,
    site: str,
) -> Any:
    """Get RF channel assignments and DFS status for a site.

    Returns the controller's Classic REST envelope {meta: {rc}, data: [channel plan…]} verbatim;
    an empty data array means the controller has no channel plan stored (for example,
    auto-channel optimization has not run).

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.get_channel_plan(client, registry, host, site)


# --- Rogue AP Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_rogue_aps(
    host: str,
    site: str,
    rogue_only: bool = False,
) -> Any:
    """List neighboring APs detected by the site's radios.

    Returns ALL neighboring APs (most will have is_rogue=false and are benign neighbors).
    Only a small subset with is_rogue=true are confirmed rogue APs. Set rogue_only=true to
    filter to confirmed rogues only.

    Returns: the controller's Classic REST /stat/rogueap envelope {meta: {rc}, data: [ap…]}
    verbatim (with rogue_only, data is narrowed to is_rogue=true entries); entries carry BSSID,
    SSID, channel, signal strength, is_rogue flag, and detection time.

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        rogue_only: When true, return only confirmed rogue APs (is_rogue=true). Default false
            returns every neighboring AP, most of them benign.
    """
    client, registry = _require()
    return await network_services_proxy.list_rogue_aps(
        client, registry, host, site, rogue_only=rogue_only
    )


# --- Classic Firewall Rule Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_firewall_rules(
    host: str,
    site: str,
) -> Any:
    """List classic L3/L4 firewall rules for a site (distinct from Integration API policies).

    Legacy, read-only: classic rules predate zone-based firewalling, and the Network 11.0.81
    web UI no longer reads this route. For the current firewall use list_firewall_policies
    (and get_firewall_policy, create_firewall_policy, update_firewall_policy).

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
    (meta is relayed as received, never interpreted).

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_firewall_rules(client, registry, host, site)


@mcp.tool(annotations=READ_ONLY)
async def get_firewall_rule(
    host: str,
    site: str,
    rule_id: str,
) -> Any:
    """Get a single classic firewall rule by ID.

    Legacy, read-only: for the current zone-based firewall use get_firewall_policy (ids from
    list_firewall_policies).

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
    (meta is relayed as received, never interpreted).

    Example call (get_firewall_rule):
        {"host": "my-console", "site": "Default", "rule_id": "65f1c0ffee0123456789abcd"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        rule_id: Legacy firewall rule _id (classic REST). Get it from list_firewall_rules (_id).
            Not a firewall policy UUID.
    """
    client, registry = _require()
    return await network_services_proxy.get_firewall_rule(client, registry, host, site, rule_id)


# --- Firewall Group Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_firewall_groups(
    host: str,
    site: str,
) -> Any:
    """List firewall groups (IP/port sets referenced by firewall rules) for a site.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
    (meta is relayed as received, never interpreted).

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_firewall_groups(client, registry, host, site)


@mcp.tool(annotations=READ_ONLY)
async def get_firewall_group(
    host: str,
    site: str,
    group_id: str,
) -> Any:
    """Get a single firewall group by ID.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
    (meta is relayed as received, never interpreted).

    Example call (get_firewall_group):
        {"host": "my-console", "site": "Default", "group_id": "65f1c0ffee0123456789abcd"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        group_id: Legacy firewall group _id (classic REST). Get it from list_firewall_groups (_id).
    """
    client, registry = _require()
    return await network_services_proxy.get_firewall_group(client, registry, host, site, group_id)


# --- RADIUS Account Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_accounts(
    host: str,
    site: str,
) -> Any:
    """List local RADIUS user accounts for a site.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim,
    including plaintext x_password credential fields.

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_accounts(client, registry, host, site)


@mcp.tool(annotations=READ_ONLY)
async def get_account(
    host: str,
    site: str,
    account_id: str,
) -> Any:
    """Get a single RADIUS account by ID.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim,
    including plaintext x_password credential fields.

    Example call (get_account):
        {"host": "my-console", "site": "Default", "account_id": "65f1c0ffee0123456789abcd"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        account_id: RADIUS account _id (classic REST account). Get it from list_accounts (_id).
    """
    client, registry = _require()
    return await network_services_proxy.get_account(client, registry, host, site, account_id)


# --- Hotspot Package Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_hotspot_packages(
    host: str,
    site: str,
) -> Any:
    """List guest portal billing packages for a site.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
    (meta is relayed as received, never interpreted).

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_hotspot_packages(client, registry, host, site)


@mcp.tool(annotations=READ_ONLY)
async def get_hotspot_package(
    host: str,
    site: str,
    package_id: str,
) -> Any:
    """Get a single hotspot billing package by ID.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
    (meta is relayed as received, never interpreted).

    Example call (get_hotspot_package):
        {"host": "my-console", "site": "Default", "package_id": "65f1c0ffee0123456789abcd"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        package_id: Hotspot package _id (classic REST hotspotpackage). Get it from
            list_hotspot_packages (_id).
    """
    client, registry = _require()
    return await network_services_proxy.get_hotspot_package(
        client, registry, host, site, package_id
    )


# --- Scheduled Task Tools ---


@mcp.tool(annotations=READ_ONLY)
async def list_scheduled_tasks(
    host: str,
    site: str,
) -> Any:
    """List scheduled tasks (firmware upgrade schedules, speed tests) for a site.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
    (meta is relayed as received, never interpreted).

    Required arguments: host, site (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
    """
    client, registry = _require()
    return await network_services_proxy.list_scheduled_tasks(client, registry, host, site)


@mcp.tool(annotations=READ_ONLY)
async def get_scheduled_task(
    host: str,
    site: str,
    task_id: str,
) -> Any:
    """Get a single scheduled task by ID.

    Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
    (meta is relayed as received, never interpreted).

    Example call (get_scheduled_task):
        {"host": "my-console", "site": "Default", "task_id": "65f1c0ffee0123456789abcd"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
            id). Names like "Default" work.
        task_id: Scheduled task _id (classic REST scheduletask). Get it from list_scheduled_tasks
            (_id).
    """
    client, registry = _require()
    return await network_services_proxy.get_scheduled_task(client, registry, host, site, task_id)


# --- DPI Tools ---


async def _validate_optional_site(registry: Registry, host: str, site: str | None) -> None:
    """Reject a site that does not exist on the console (fail fast, valid sites listed)."""
    if site is not None:
        key = await registry.resolve_key_for_host(host)
        host_id = await registry.resolve_host_id(host, key=key)
        await registry.resolve_site_id(site, host_id, key=key)


@mcp.tool(annotations=READ_ONLY)
async def list_dpi_categories(
    host: str,
    site: str | None = None,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List DPI (Deep Packet Inspection) app categories available for traffic rules.

    Returns {data, totalCount}: every page is drained; data holds the DPI category records verbatim
    and totalCount is the upstream total (null when none was reported). The first page's other
    envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
    drain stopped short.

    Categories include Social Media, Streaming Video, Gaming, etc.
    By default every page is drained and the complete catalogue is returned as
    {data, totalCount}. Pass offset alone to fetch a single page manually. A
    capped drain returns the categories gathered so far with incomplete=true
    rather than truncating silently.

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Optional. DPI data is host-level, so a site does not narrow the result; when
            given it must name a site on the console (an unknown site is rejected with the
            valid site names).
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: Optional Network Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter for server-side filtering (e.g.
            `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
            when paging manually.
            Example: `name.eq('Business')`."""
    client, registry = _require()
    await _validate_optional_site(registry, host, site)
    return await network_services_proxy.list_dpi_categories(
        client, registry, host, offset, limit, filter=filter
    )


@mcp.tool(annotations=READ_ONLY)
async def list_dpi_applications(
    host: str,
    site: str | None = None,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List DPI applications available for traffic rules.

    Returns {data, totalCount}: every page is drained; data holds the DPI application records
    verbatim and totalCount is the upstream total (null when none was reported). The first page's
    other envelope fields are kept beside them, and incomplete / incompleteReason are added when a
    capped drain stopped short.

    Companion to list_dpi_categories; use application IDs in traffic rule configurations.
    By default every page is drained and the complete catalogue is returned as
    {data, totalCount}. Pass offset alone to fetch a single page manually. A
    capped drain returns the applications gathered so far with incomplete=true
    rather than truncating silently.

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site: Optional. DPI data is host-level, so a site does not narrow the result; when
            given it must name a site on the console (an unknown site is rejected with the
            valid site names).
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is sent
            unchanged as one page. The console clamps that page to 200, so fewer can
            return while more exist (compare _pageSize requested and returned). Omit
            offset and limit to drain all.
            Example: `25`.
        filter: Optional Network Integration API filter expression, forwarded unchanged as the
            upstream `filter` query parameter for server-side filtering (e.g.
            `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
            when paging manually.
            Example: `name.eq('Zoom')`."""
    client, registry = _require()
    await _validate_optional_site(registry, host, site)
    return await network_services_proxy.list_dpi_applications(
        client, registry, host, offset, limit, filter=filter
    )


# --- InnerSpace Floor-Plan Tools ---


@mcp.tool(annotations=READ_ONLY)
async def get_unifi_placement_snapshot(host: str) -> dict[str, Any]:
    """Return a bounded, read-only UniFi topology and placement projection
    (unifi.placement-snapshot/v1).

    Unlike the other tools' whole upstream bodies, this closed schema selects, renames and
    derives fields: a MAC-only device gets a SHA-256 source_id; device_type is a closed enum.
    Projected strings retain upstream values. GET-backed sources are InnerSpace 3D placement,
    Protect cameras/sensors and Site Manager inventory; no connector writes occur. Provenance
    includes a 120-second freshness contract.

    Returns schema_version, generated_at, freshness, provenance, floors, walls,
    placed_devices, topology and placement_links, plus incomplete/incompleteReason if a source
    list stops short. Address/asset fields are included by default (topology/placed_devices
    ip/mac and floor image/model/zip/bin URLs). Only opt-in UNIFI_REDACT_SECRETS removes
    address/asset fields and strings identified as URL/IP/MAC/credential markers. Every removed
    value is counted in _withheld (section.field/reason); _withheld_how_to_obtain names its
    source tool or instructs disabling redaction. Both are absent with redaction off.

    In either mode, records outside schema v1 (not_an_object, no_position, no_geometry,
    no_source_id, not_numeric) are counted in _unprojected; _unprojected_how_to_obtain names the
    full source read tool. Nothing disappears silently. For full payloads use
    get_innerspace_project, list_innerspace_devices, list_cameras, list_sensors or list_devices.
    Full field reference: docs/TOOL-USAGE.md#get_unifi_placement_snapshot.

    Required arguments: host (see parameter descriptions for identifiers).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
    """
    client, registry = _require()
    return await placement_snapshot.get_unifi_placement_snapshot(client, registry, host)


@mcp.tool(annotations=READ_ONLY)
async def get_innerspace_summary(
    host: str,
    mode: str = "3D",
) -> dict[str, Any]:
    """Inventory a console's InnerSpace floor-plan project without the full payload.

    Returns counts and structure: shape breakdown by type (wall / device / map /
    scale), per-floor plans with each plan's own scale, product and wall-material /
    attenuation-type dictionary sizes, and project metadata. Call this before
    get_innerspace_project when you only need to know what's present. Surfaces the
    multi-floor caveat: floors do not share a coordinate origin. Top-level keys: mode,
    shape_total, shape_counts, wall_variants, plan_count, plans, plan_scales, product_count,
    wall_type_count, attenuation_object_type_count (null when the document has no
    attenuationObjectTypes), project, multi_floor, and multi_floor_note when there are
    several plans.

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        mode: '3D' (default; device shapes carry real metric mounting heights) or '2D'.
    """
    client, registry = _require()
    return await innerspace.get_innerspace_summary(client, registry, host, mode)


@mcp.tool(annotations=READ_ONLY)
async def get_innerspace_project(
    host: str,
    mode: str = "3D",
    user_email: str | None = None,
    site_id: str | None = None,
) -> dict[str, Any]:
    """Return the full InnerSpace floor-plan project geometry for a console.

    The complete (~66 KB) project document: shapes, plans, products, wall types,
    and attenuation-object types. The upstream response object is returned verbatim
    (the documented API wraps the project under data; the legacy path returns it bare),
    including device meta.mac / meta.ip and floor-plan image/asset URLs. Prefer
    get_innerspace_summary first
    if you only need an inventory — this payload is large.

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        mode: '3D' (default; device shapes carry real metric mounting heights) or '2D' (device
            shapes flattened to z=0). 3D is the only mode with real heights.
        user_email: Optional userEmail query of the legacy /api/project route, e.g.
            "admin@example.com". When it or site_id is given the legacy route is used.
        site_id: Optional siteId query of the legacy /api/project route, e.g. "default".
    """
    client, registry = _require()
    return await innerspace.get_innerspace_project(
        client, registry, host, mode, user_email, site_id
    )


@mcp.tool(annotations=READ_ONLY)
async def list_innerspace_devices(
    host: str,
    mode: str = "3D",
) -> dict[str, Any]:
    """List placed device shapes from a console's InnerSpace floor-plan.

    Returns {shapes, _mode, _count}: shapes holds the project's device shapes verbatim, _mode the
    normalized mode argument and _count the number of shapes.

    Each mounted device's placement: mount, productId, title, position, and
    rotation (pov = heading/yaw, base = mount tilt). Returned verbatim, including
    device meta.mac / meta.ip. Use mode='3D' (default) for real metric mounting
    heights; mode='2D' flattens positions to z=0.

    Required arguments: host (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        mode: '3D' (default) or '2D'.
    """
    client, registry = _require()
    return await innerspace.list_innerspace_devices(client, registry, host, mode)


@mcp.tool(annotations=READ_ONLY)
async def list_innerspace_floor_plans(
    host: str,
    site_id: str | None = None,
) -> dict[str, Any]:
    """List a console's InnerSpace floor plans (documented Integration API).

    Returns the upstream body verbatim (floor_plans and every other top-level key the API sends)
    plus the additive _count of floor_plans.

    Each floor plan carries id, name, floor_number, image_url (an asset path — fetch
    with get_innerspace_asset), ppm (pixels per metre, the scale for interpreting
    coordinates/heights), width/height (image pixels), origin_x/origin_y, and site_id
    when filtered. Returned verbatim.

    Example call (list_innerspace_floor_plans):
        {"host": "my-console"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site_id: Optional filter: Network site UUID matched against each InnerSpace record's product
            siteId. Get it from list_local_sites (id).
    """
    client, registry = _require()
    return await innerspace.list_innerspace_floor_plans(client, registry, host, site_id)


@mcp.tool(annotations=READ_ONLY)
async def list_innerspace_access_points(
    host: str,
    site_id: str | None = None,
) -> dict[str, Any]:
    """List placed access points from a console's InnerSpace floor plans (Integration API).

    Returns the upstream body verbatim (access_points and every other top-level key the API sends)
    plus the additive _count of access_points.

    Each AP carries id, name, model (SKU), mac, serial, floor_plan_id, x/y (pixels on
    the floor-plan image), height (mounting height in metres), azimuth (antenna
    orientation, 0-360 degrees), mount, and status. Returned verbatim, including
    mac/serial.

    Example call (list_innerspace_access_points):
        {"host": "my-console"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site_id: Optional filter: Network site UUID matched against each InnerSpace record's product
            siteId. Get it from list_local_sites (id).
    """
    client, registry = _require()
    return await innerspace.list_innerspace_access_points(client, registry, host, site_id)


@mcp.tool(annotations=READ_ONLY)
async def list_innerspace_switches(
    host: str,
    site_id: str | None = None,
) -> dict[str, Any]:
    """List placed switches from a console's InnerSpace floor plans (Integration API).

    Returns the upstream body verbatim (switches and every other top-level key the API sends) plus
    the additive _count of switches.

    Each switch carries id, name, model, type (switch), mac, serial, floor_plan_id,
    x/y (pixels on the floor-plan image), and status. Returned verbatim, including
    mac/serial.

    Example call (list_innerspace_switches):
        {"host": "my-console"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site_id: Optional filter: Network site UUID matched against each InnerSpace record's product
            siteId. Get it from list_local_sites (id).
    """
    client, registry = _require()
    return await innerspace.list_innerspace_switches(client, registry, host, site_id)


@mcp.tool(annotations=READ_ONLY)
async def list_innerspace_inventory(
    host: str,
    site_id: str | None = None,
) -> dict[str, Any]:
    """List UNPLACED device inventory for a console's InnerSpace project (Integration API).

    Returns the upstream body verbatim (devices and every other top-level key the API sends) plus
    the additive _count of devices.

    Devices known to the project but not yet positioned on a floor plan. Each carries
    id, name, model, mac, and serial. Returned verbatim, including mac/serial. The
    response array key is 'devices'.

    Example call (list_innerspace_inventory):
        {"host": "my-console"}

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        site_id: Optional filter: Network site UUID matched against each InnerSpace record's product
            siteId. Get it from list_local_sites (id).
    """
    client, registry = _require()
    return await innerspace.list_innerspace_inventory(client, registry, host, site_id)


@mcp.tool(annotations=READ_ONLY)
async def get_innerspace_asset(
    host: str,
    plan_id: str,
    filename: str,
    metadata_only: bool = False,
) -> dict[str, Any]:
    """Download a floor-plan asset (image) from a console's InnerSpace project.

    Returns {_plan_id, _filename, path, content_type, size_bytes, image_base64}: the asset bytes
    complete, base64-encoded, with the upstream Content-Type and size; _plan_id / _filename echo the
    arguments.

    Fetches the binary asset from the documented …/integration/v1/assets/{planId}/
    {filename} endpoint (a floor plan's image_url resolves here). The complete bytes are
    returned base64-encoded under image_base64 whatever the size (no size cap). Pass
    metadata_only=true to leave out the bytes: the same keys come back with
    image_base64=null. content_type is the upstream media type (typically image/jpeg or
    image/png), or null when the upstream sends no Content-Type.

    `plan_id`: the id in the {planId} segment of the floor plan's image_url -- i.e. the
      value between '/assets/' and the trailing '/{filename}'. This is the asset-group
      UUID and is NOT the floor plan's own 'id' field (they differ); passing the plan
      'id' returns HTTP 404. Parse both plan_id and filename from image_url (from
      list_innerspace_floor_plans) rather than constructing them from the plan id.

    Example call (get_innerspace_asset):
        {
          "host": "my-console",
          "plan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "filename": "plan.png"
        }

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        plan_id: Asset-group UUID parsed from a floor plan's image_url
            (/assets/{planId}/{filename}). NOT the floor plan id. From list_innerspace_floor_plans.
        filename: Filename segment from the floor plan's image_url (after /assets/{planId}/), as
            the plain (decoded) name, e.g. "2DPreview.svg"; the tool percent-encodes it. If that
            segment carries %XX escapes, pass it percent-decoded ("my%20plan.png" -> "my plan.png"),
            or the escapes are sent literally (%25XX).
        metadata_only: Optional. True leaves out the image bytes: every other key is returned
            and image_base64 is null. Default false: the full image is returned.
    """
    client, registry = _require()
    return await innerspace.get_innerspace_asset(
        client, registry, host, plan_id, filename, metadata_only=metadata_only
    )


innerspace_internal.register(mcp, _require)


# --- Carrier / ISP Fabric Tools (org-scoped identity; no host/site resolution) ---
#
# Spec-conformance tested only: the UniFi Carrier / ISP Fabric tools (published Subscriber
# API v1.0.0, developer.ui.com/carrier-fabric/v1.0.0) are verified against the OpenAPI
# request/response shapes with hermetic fixtures, not against a live Carrier Fabric. The
# seven writes use read-before/no-op/read-after and the UNIFI_ENABLE_CARRIER_FABRIC_WRITE
# opt-out (writes enabled by default; set 0/false for a read-only deployment).


@mcp.tool(annotations=READ_ONLY)
async def list_carrier_subscribers(
    plan_id: str | None = None,
    suspended: bool | None = None,
    sort: str | None = None,
    key_label: str | None = None,
    limit: int | None = None,
    cursor: str | None = None,
) -> dict[str, Any]:
    """List Carrier / ISP Fabric subscribers visible to the authenticated ISP key.

    Returns {data, _count} and the first page's envelope fields; several keys put
    envelopes under byKey, annotate records with _keyLabel, and report per-key
    errors. incomplete/incompleteReason appear when a drain stops early. A response
    without a data array raises. Spec-conformance tested only, without live Carrier.

    Default drains every cursor page. limit requests that many subscribers, or all
    available if fewer exist, gathered in native pages up to the spec maximum 500;
    the full final page can exceed limit to preserve its native continuation;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count. cursor selects the
    starting meta.nextCursor; alone, it fetches one page with its native meta
    continuation. With several keys, limit/cursor needs key_label.

    Args:
        plan_id: Optional service-plan UUID from list_carrier_service_plans (id).
            Example: "3fa85f64-5717-4562-b3fc-2c963f66afa6".
        suspended: Optional filter: true for suspended, false for active. Example: false.
        sort: createdAt|-createdAt|name|-name|subscriberNumber|-subscriberNumber.
            Example: "-createdAt".
        key_label: Configured API-key label from list_configured_api_keys; omit to
            aggregate all keys. Required with limit/cursor and several keys.
            Example: "primary".
        limit: Requested subscriber count, gathered in batches up to 500. Example: `100`.
        cursor: Raw meta.nextCursor for one verbatim page, or the returned opaque
            _continuation string preserving physical size when changing the requested limit.
            Example: the token from the previous response.
    """
    client, _ = _require()
    return await carrier_fabric.list_carrier_subscribers(
        client,
        plan_id=plan_id,
        suspended=suspended,
        sort=sort,
        key_label=key_label,
        limit=limit,
        cursor=cursor,
    )


@mcp.tool(annotations=READ_ONLY)
async def get_carrier_subscriber(
    subscriber_id: str,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Get one Carrier / ISP Fabric subscriber by ID.

    Spec-conformance tested only (not against a live Carrier Fabric).
    Returns the upstream response object verbatim: the Subscriber under data beside
    httpStatusCode and traceId; an unknown id surfaces the upstream
    subscriber_not_found (404) verbatim.

    Example call (get_carrier_subscriber):
        {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    Args:
        subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
    """
    client, _ = _require()
    return await carrier_fabric.get_carrier_subscriber(client, subscriber_id, key_label=key_label)


@mcp.tool(annotations=READ_ONLY)
async def list_carrier_service_plans(
    key_label: str | None = None,
) -> dict[str, Any]:
    """List the Carrier / ISP Fabric service plans for the authenticated organization.

    Returns the upstream body verbatim ({data, httpStatusCode, traceId, ...}) plus _count; with
    several keys {data, _count, byKey} plus errors.

    Spec-conformance tested only (not against a live Carrier Fabric).
    Not query-
    paginated by the API; the full set is returned under data (the upstream key), with the
    additive _count.

    Args:
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to cover
            every configured key: results are merged, each record carries an additive _keyLabel, and
            a key that fails is reported under errors.
    """
    client, _ = _require()
    return await carrier_fabric.list_carrier_service_plans(client, key_label=key_label)


@mcp.tool(annotations=READ_ONLY)
async def get_carrier_service_plan(
    plan_id: str,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Get one Carrier / ISP Fabric service plan by ID.

    Spec-conformance tested only (not against a live Carrier Fabric).
    Returns the upstream response object verbatim: the ServicePlan under data beside
    httpStatusCode and traceId. An unknown id
    surfaces the upstream service_plan_not_found (404) verbatim.

    Example call (get_carrier_service_plan):
        {"plan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    Args:
        plan_id: Carrier Fabric service-plan UUID. Get it from list_carrier_service_plans (id).
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
    """
    client, _ = _require()
    return await carrier_fabric.get_carrier_service_plan(client, plan_id, key_label=key_label)


@mcp.tool(annotations=WRITE)
async def create_carrier_subscriber(
    subscriber_number: str,
    name: str | None = None,
    email: str | None = None,
    notes: str | None = None,
    service_address: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
    plan_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Create a Carrier / ISP Fabric subscriber (POST /v1/carrier/subscribers). Guarded write.

    Returns {status: "created", changed (every sent field as {from: null, to}), subscriber (the
    201 body verbatim, {data, traceId}, when it carries the created resource, else null),
    response (the upstream write body verbatim)}.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", subscriber: null, response (the
    preview)}.

    Spec-conformance tested only (not against a live Carrier Fabric).
    subscriber_number is required (1-32 chars). Optional name (<=128 bytes),
    email (<=255 bytes), notes (<=4096 bytes), service_address (<=1024 bytes), plan_id (UUID),
    metadata (object). Per the spec those limits are bytes of UTF-8, so a multi-byte character
    counts as more than one. Gated by UNIFI_ENABLE_CARRIER_FABRIC_WRITE (enabled by default;
    set 0 for read-only).

    Request body (Carrier Fabric 1.0.0, POST /v1/carrier/subscribers (createSubscriber); schema
    "SubscriberCreate") is built from scalar parameters. Required keys — subscriberNumber.
    - subscriberNumber: string
    - name: string
    - email: string(email)
    - notes: string
    - serviceAddress: string
    - planId: string(uuid)
    - metadata: object

    Example call (create_carrier_subscriber):
        {"subscriber_number": "SUB-1001"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        subscriber_number: Unique subscriber number, 1-32 chars. REQUIRED (body field
            subscriberNumber: string).
        name: Subscriber display name. Optional (body field name: string).
        email: Subscriber email. Optional (body field email: string(email)).
        notes: Free-text notes. Optional (body field notes: string).
        service_address: Free-text service address (a string, per the spec), at most 1024
            bytes of UTF-8. Optional (body field serviceAddress: string).
        plan_id: Carrier Fabric service-plan UUID. Get it from list_carrier_service_plans (id).
        metadata: Optional profile key/values (body field metadata: object); its serialized
            JSON may be at most 8192 bytes of UTF-8, as the spec states.
            Free-form JSON object; arbitrary metadata properties are passed unchanged.
        confirm: Ignored. The call runs when made; there is no confirmation step.
        key_label: Optional configured API-key label (see list_configured_api_keys). With one key,
            omit it. With several keys: when plan_id is given and key_label is omitted, the
            subscriber is created under the key that owns that plan; otherwise pass the label
            of the organization that should own the subscriber (omitting it fails fast listing
            the configured labels, it never picks the first key).
    """
    service_address = _nullable_default(service_address, carrier_fabric._UNSET)
    client, _ = _require()
    return await carrier_fabric.create_carrier_subscriber(
        client,
        subscriber_number,
        name=name,
        email=email,
        notes=notes,
        service_address=service_address,
        plan_id=plan_id,
        metadata=metadata,
        confirm=confirm,
        key_label=key_label,
    )


@mcp.tool(annotations=WRITE)
async def update_carrier_subscriber(
    subscriber_id: str,
    subscriber_number: str | None = None,
    name: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
    email: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
    notes: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
    service_address: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
    plan_id: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
    metadata: dict[str, Any] | None = Field(  # noqa: B008 — distinguish omission from null
        default_factory=lambda: carrier_fabric._UNSET
    ),
    confirm: bool = False,
    key_label: str | None = None,
    clear_fields: list[str] | None = None,
) -> dict[str, Any]:
    """Update a Carrier Fabric subscriber (PATCH .../subscribers/{id}).

    Returns {status: "updated", changed: {field: {from, to}}, verified, subscriber, response
    (the upstream write body verbatim)}, or {status: "no_op", reason, subscriber}.
    subscriber is a full body, never unwrapped: the write response when it carries the
    subscriber, else the read-back GET body (for no_op, the GET body read first).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", subscriber (the body read first),
    response (the preview)}; there is no read-after.

    Spec-conformance tested only (not live). Partial update: pass at least one field.
    subscriber_number is 1-32 chars after trimming when
    provided; name, email, notes,
    service_address are limited to 128 / 255 / 4096 / 1024 bytes of UTF-8 (the spec's unit).
    Guarded, in order: the Carrier write opt-out (UNIFI_ENABLE_CARRIER_FABRIC_WRITE=0 refuses
    first), read-before, no-op when all provided
    fields already match, write, read-after. Omission leaves a field unchanged; explicit null
    clears a nullable field, as does naming it in clear_fields (sent as JSON null). Per the spec,
    null
    clears name, email, notes, serviceAddress and planId; subscriberNumber cannot be cleared,
    and metadata=null leaves metadata unchanged (send metadata={} to empty it).
    Explicit metadata=null alone is a no-op; null is forwarded only alongside another change.

    Request body (Carrier Fabric 1.0.0, PATCH /v1/carrier/subscribers/{id} (updateSubscriber);
    schema "SubscriberPatch") is built from scalar parameters. No key is required; send only the
    keys to change.
    - subscriberNumber: string
    - name: string
    - email: string(email)
    - notes: string
    - serviceAddress: string
    - planId: string(uuid)
    - metadata: object

    Example call (update_carrier_subscriber):
        {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "notes": "Moved to plan B"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
        subscriber_number: Unique subscriber number, 1-32 chars. Optional (body field
            subscriberNumber: string).
        name: Subscriber display name, non-empty after trimming (the spec rejects a blank name;
            clear it with explicit null or clear_fields). Optional (body field name: string).
        email: Subscriber email. Optional (body field email: string(email)).
        notes: Free-text notes. Optional (body field notes: string).
        service_address: Free-text service address (a string, per the spec), at most 1024
            bytes of UTF-8. Optional (body field serviceAddress: string).
        plan_id: Carrier Fabric service-plan UUID. Get it from list_carrier_service_plans (id).
        metadata: Optional replacement metadata object (body field metadata); it replaces the
            whole document, so pass {} to empty it. Explicit metadata=null alone is a no-op;
            null is forwarded only alongside another change and leaves metadata unchanged.
            Omission leaves metadata unchanged. A subscriber with no metadata reads back
            without the key (the spec omits it), which counts as {}: metadata={} on it is a no-op.
            Its serialized JSON may be at most 8192 bytes of UTF-8, as the spec states.
            Free-form JSON object; arbitrary metadata properties are passed unchanged.
        confirm: Ignored. The call runs when made; there is no confirmation step.
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
        clear_fields: Optional list of fields to clear by sending JSON null: any of "name",
            "email", "notes", "service_address", "plan_id". A field named here must not also be
            given a value. Omit to clear nothing (the default; existing behaviour).
            Shape: ('name'|'email'|'notes'|'service_address'|'plan_id')[]
    """
    name = _nullable_default(name, carrier_fabric._UNSET)
    email = _nullable_default(email, carrier_fabric._UNSET)
    notes = _nullable_default(notes, carrier_fabric._UNSET)
    service_address = _nullable_default(service_address, carrier_fabric._UNSET)
    plan_id = _nullable_default(plan_id, carrier_fabric._UNSET)
    metadata = _nullable_default(metadata, carrier_fabric._UNSET)
    client, _ = _require()
    kwargs: dict[str, Any] = {"confirm": confirm, "key_label": key_label}
    clearable = ("name", "email", "notes", "service_address", "plan_id")
    given = {
        "name": name,
        "email": email,
        "notes": notes,
        "service_address": service_address,
        "plan_id": plan_id,
    }
    for field in clear_fields or []:
        if field not in clearable:
            raise ValueError(
                f"clear_fields: {field!r} cannot be cleared. Clearable fields (sent as JSON null): "
                f"{', '.join(clearable)}. subscriber_number cannot be cleared, and metadata is not "
                "cleared by null (pass metadata={} to empty it)."
            )
        if given[field] is not carrier_fabric._UNSET and given[field] is not None:
            raise ValueError(
                f"clear_fields names {field!r} but a value was also given for it: pass one or the "
                "other."
            )
        kwargs[field] = None
    # Preserve omitted fields separately from explicit JSON null clears.
    if subscriber_number is not None:
        kwargs["subscriber_number"] = subscriber_number
        kwargs["_preserve_subscriber_number"] = True
    if name is not carrier_fabric._UNSET:
        kwargs["name"] = name
    if email is not carrier_fabric._UNSET:
        kwargs["email"] = email
    if notes is not carrier_fabric._UNSET:
        kwargs["notes"] = notes
    if service_address is not carrier_fabric._UNSET:
        kwargs["service_address"] = service_address
    if plan_id is not carrier_fabric._UNSET:
        kwargs["plan_id"] = plan_id
    if metadata is not carrier_fabric._UNSET:
        kwargs["metadata"] = metadata
    return await carrier_fabric.update_carrier_subscriber(client, subscriber_id, **kwargs)


@mcp.tool(annotations=WRITE)
async def attach_carrier_subscriber_host(
    subscriber_id: str,
    host_id: str,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Attach or re-link a subscriber's gateway host (PUT .../subscribers/{id}/host). Guarded.

    Returns {status: "attached", changed, _prev_host_id (the response's prevHostId), verified,
    subscriber, response (verbatim)}, or {status: "no_op", reason, subscriber}. subscriber is
    a full body ({data, ...}), never unwrapped: the write response when it carries the
    subscriber, else the read-back GET body (for no_op, the GET body read first).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", subscriber (the body read first),
    response (the preview)}; there is no read-after.

    Spec-conformance tested only (not against a live Carrier Fabric). host_id must be a host in
    the same ISP organization. Guarded, in order: the Carrier write opt-out
    (UNIFI_ENABLE_CARRIER_FABRIC_WRITE=0 refuses first), read-before, no-op when already linked,
    write, read-after (reports _prev_host_id).

    Request body (Carrier Fabric 1.0.0, PUT /v1/carrier/subscribers/{id}/host
    (attachSubscriberHost); schema "inline requestBody schema") is built from scalar parameters.
    Required keys — hostId.
    - hostId: string

    Example call (attach_carrier_subscriber_host):
        {
          "subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "host_id": "942A6FF664C0000000000964970E0000000009E710560000000068A9873F:9999999999"
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
        host_id: Gateway host id (Site Manager) in the same ISP org. Get it from list_hosts (id).
        confirm: Ignored. The call runs when made; there is no confirmation step.
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
    """
    client, _ = _require()
    return await carrier_fabric.attach_carrier_subscriber_host(
        client, subscriber_id, host_id, confirm=confirm, key_label=key_label
    )


@mcp.tool(annotations=WRITE)
async def detach_carrier_subscriber_host(
    subscriber_id: str,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Detach a subscriber's gateway host (DELETE .../subscribers/{id}/host). Guarded write.

    Consequence: the gateway host is no longer linked to the subscriber until re-attached with
    attach_carrier_subscriber_host.

    Returns {status: "detached", changed, _prev_host_id (the response's prevHostId), verified,
    subscriber, response (verbatim)}, or {status: "no_op", reason, subscriber}. subscriber is
    a full body ({data, ...}), never unwrapped: the write response when it carries the
    subscriber, else the read-back GET body (for no_op, the GET body read first).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", subscriber (the body read first),
    response (the preview)}; there is no read-after.

    Spec-conformance tested only (not against a live Carrier Fabric). Guarded, in order: the
    Carrier write opt-out (UNIFI_ENABLE_CARRIER_FABRIC_WRITE=0 refuses first), read-before,
    no-op when no host is attached, write, read-after (reports the just-detached
    _prev_host_id).

    Example call (detach_carrier_subscriber_host):
        {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
        confirm: Ignored. The call runs when made; there is no confirmation step.
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
    """
    client, _ = _require()
    return await carrier_fabric.detach_carrier_subscriber_host(
        client, subscriber_id, confirm=confirm, key_label=key_label
    )


@mcp.tool(annotations=WRITE)
async def assign_carrier_subscriber_plan(
    subscriber_id: str,
    plan_id: str,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Assign a service plan to a subscriber (PUT .../subscribers/{id}/plan). Guarded write.

    Returns {status: "assigned", changed, verified, subscriber, response (verbatim)}, or
    {status: "no_op", reason, subscriber}. subscriber is a full body ({data, ...}), never
    unwrapped: the write response when it carries the subscriber, else the read-back GET body
    (for no_op, the GET body read first).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", subscriber (the body read first),
    response (the preview)}; there is no read-after.

    Spec-conformance tested only (not against a live Carrier Fabric). An archived or unknown
    plan is rejected upstream. Guarded, in order: the Carrier write opt-out
    (UNIFI_ENABLE_CARRIER_FABRIC_WRITE=0 refuses first), read-before, no-op when already on this
    plan, write, read-after.

    Request body (Carrier Fabric 1.0.0, PUT /v1/carrier/subscribers/{id}/plan
    (assignSubscriberPlan); schema "inline requestBody schema") is built from scalar parameters.
    Required keys — planId.
    - planId: string(uuid)

    Example call (assign_carrier_subscriber_plan):
        {
          "subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "plan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
        plan_id: Carrier Fabric service-plan UUID. Get it from list_carrier_service_plans (id).
        confirm: Ignored. The call runs when made; there is no confirmation step.
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
    """
    client, _ = _require()
    return await carrier_fabric.assign_carrier_subscriber_plan(
        client, subscriber_id, plan_id, confirm=confirm, key_label=key_label
    )


@mcp.tool(annotations=WRITE)
async def suspend_carrier_subscriber(
    subscriber_id: str,
    reason: str | None = None,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Suspend a subscriber's service (POST .../subscribers/{id}/suspend). Guarded write.

    Consequence: the subscriber's service stops until resumed with resume_carrier_subscriber.

    Returns {status: "suspended", changed (suspended, and suspendReason when a reason is sent),
    verified, subscriber, response (verbatim)}, or {status: "no_op", reason, subscriber}.
    subscriber is a full body ({data, ...}), never unwrapped: the write response when it
    carries the subscriber, else the read-back GET body (for no_op, the GET body read first).
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", subscriber (the body read first),
    response (the preview)}; there is no read-after.

    Spec-conformance tested only (not against a live Carrier Fabric). Guarded, in order: the
    Carrier write opt-out (UNIFI_ENABLE_CARRIER_FABRIC_WRITE=0 refuses first), read-before,
    no-op only when already suspended AND no reason is given or the current suspendReason
    already equals it (a different reason is sent upstream), write, read-after. An optional
    reason is recorded on the subscriber.

    Request body (Carrier Fabric 1.0.0, POST /v1/carrier/subscribers/{id}/suspend
    (suspendSubscriber); schema "inline requestBody schema") is built from scalar parameters. No key
    is required; send only the keys to change.
    - reason: string

    Example call (suspend_carrier_subscriber):
        {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
        reason: Optional suspension reason, max 1024 chars (spec body reason).
        confirm: Ignored. The call runs when made; there is no confirmation step.
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
    """
    client, _ = _require()
    return await carrier_fabric.suspend_carrier_subscriber(
        client, subscriber_id, reason=reason, confirm=confirm, key_label=key_label
    )


@mcp.tool(annotations=WRITE)
async def resume_carrier_subscriber(
    subscriber_id: str,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Resume a suspended subscriber's service (POST .../subscribers/{id}/resume). Guarded.

    Consequence: the subscriber's service is restored.

    Returns {status: "resumed", changed, verified, subscriber, response (verbatim)}, or {status:
    "no_op", reason, subscriber}. subscriber is a full body ({data, ...}), never unwrapped: the
    write response when it carries the subscriber, else the read-back GET body; for no_op it is
    the GET body read first.
    verified is null, with readAfterError, when the read-after fails or cannot be matched.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", subscriber (the body read first),
    response (the preview)}; there is no read-after.

    Spec-conformance tested only (not against a live Carrier Fabric). Guarded, in order: the
    Carrier write opt-out (UNIFI_ENABLE_CARRIER_FABRIC_WRITE=0 refuses first), read-before,
    no-op when not currently suspended, write, read-after.

    Example call (resume_carrier_subscriber):
        {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
        confirm: Ignored. The call runs when made; there is no confirmation step.
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
    """
    client, _ = _require()
    return await carrier_fabric.resume_carrier_subscriber(
        client, subscriber_id, confirm=confirm, key_label=key_label
    )


# --- Guarded generic Fabric connector relay ---
#
# An ordinary GET is always available (a GET of a state-changing route is a write).
# POST/PUT/PATCH/DELETE are mutations gated by the
# server-side UNIFI_ENABLE_CONNECTOR_WRITE capability flag, enabled by default; set it
# to 0/false for a read-only deployment. The confirm argument is accepted for
# compatibility and no longer required. See
# tools/connector.py for the full guard model (Registry-only
# identity, namespace allowlist, positive-charset path validation, read-before/
# write/read-after, scope guard, verbatim bodies, structured audit).


@mcp.tool(annotations=WRITE)
@state_changing_get
async def fabric_connector_get(
    host: str,
    path: str,
    site: str | None = None,
    params: dict[str, Any] | None = None,
    scope: str | None = None,
) -> dict[str, Any]:
    """Relay a GET through the official Fabric connector to a console's /proxy/{path}.

    For routes without typed tools. GET needs no confirm. State-changing GET routes
    (Protect enable-control/disable-control) require write authorization, obey connector/area
    opt-outs, read-only mode and dry-run, and are sent once. In discovery mode use
    call_write_tool for them. Ordinary GET reads remain available. A 4xx/5xx returns status,
    so unknown-route probes expose reachability.

    Consequence: Protect enable-control/disable-control changes camera controllability
    until set back.

    Under UNIFI_DRY_RUN an action GET sends no action request: status is "dry_run"; body
    previews method, path, params (query parameters), and body. Ordinary GETs still return
    upstream responses.

    Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body}; body is
    the upstream body verbatim: decoded JSON, the exact text of a non-JSON body, or null when
    the body is empty (masked only when the operator opts in with UNIFI_REDACT_SECRETS).
    contentType is the upstream Content-Type (null when none). A text body is decoded with its
    declared charset when that is a known codec (latin-1, windows-1252, utf-16 ...; UTF-8
    otherwise), so non-UTF-8 text comes back as text under body. A binary body (a non-text
    Content-Type such as image/jpeg, or bytes that do not decode in that charset) is returned
    complete, with no size cap, base64-encoded as bodyBase64 plus sizeBytes, and body is null.
    A 3xx (never followed) also returns its response headers (Location included; credentials
    and cookies excluded) under headers.

    HTTP 401/403 keeps body and status, adding _hint with key setup/permission advice.
    A Classic route (network/api/...) answered 2xx without meta.rc "ok" is an upstream error
    reported like a 4xx: status and body stay verbatim and _classicRcError gives the reason
    (meta.msg included).

    Required arguments: host, path (see each parameter's description).

    Args:
        host: Console name or id: the short name from list_hosts
            (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
            "my-console") or the long data[].id (MAC:numericId composite).
        path: the relay-relative application path AFTER ``/proxy/`` — e.g.
            ``network/integration/v1/sites`` or ``network/api/s/{site}/stat/device``. Use the
            ``{site}`` (slug) or ``{site_id}`` (UUID) placeholder for the site segment; the server
            resolves and substitutes it, and resolvedPath reports the path as sent (the console id
            and API key are never part of path or resolvedPath). Mapped application routes carry
            their routeClass; unmapped routes relay as
            routeClass "unclassified". Ordinary GET reads relay while an area write opt-out
            is active. Mutations on unclassified routes are refused only while an area write
            opt-out is active, with the refusal naming its variable. ``..``, ``%``-encoding,
            and control characters are rejected.
        site: site name or UUID — REQUIRED only when path contains a site placeholder.
        params: optional query-string parameters.
            Free-form JSON object; the caller-chosen route determines its shape.
        scope: optional 'device' / 'site' / 'global' — cross-checked against the path so a device
            route cannot be confused with a site-global setting route.
    """
    client, registry = _require()
    return await connector.connector_get(
        client, registry, host, path, site=site, params=params, scope=scope
    )


@mcp.tool(annotations=WRITE)
async def fabric_connector_post(
    host: str,
    path: str,
    site: str | None = None,
    body: connector.RelayBody = None,
    confirm: bool = False,
    scope: str | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Relay a POST (create/command) through the Fabric connector. Writes to the controller.

    Consequence: whatever the target route creates or does happens on the live controller
    immediately.

    POST targets a collection or command route (e.g. ``network/api/s/{site}/cmd/...``). See
    fabric_connector_get for host/path/site/scope semantics; body is sent verbatim and confirm is
    ignored. Every attempt is audit-logged (never the key value).

    Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body,
    writeEnabled}. status and body are the upstream's, verbatim (a 4xx/5xx is returned, not raised);
    a binary body is bodyBase64 plus sizeBytes with body null; a 3xx (never followed) adds its
    headers. POST has no GET twin: no read-before/after. Under UNIFI_DRY_RUN nothing is sent: status
    is "dry_run" and body is the preview.

    Refused before any request if UNIFI_ENABLE_CONNECTOR_WRITE is falsey, UNIFI_READ_ONLY is on, a
    protect/ path meets UNIFI_PROTECT_MUTATIONS_ENABLED falsey (every area write opt-out applies),
    or an unclassified route meets any active area opt-out. Sent once: never auto-retried on 429
    (raised with the upstream body).

    Full request shapes are in the parameter schema; detailed examples and workflows:
    docs/TOOL-USAGE.md#fabric_connector_post.

    HTTP 401/403 keeps body and status, adding _hint with key setup/permission advice.
    A Classic route (network/api/...) answered 2xx without meta.rc "ok" is an upstream error
    reported like a 4xx: status and body stay verbatim and _classicRcError gives the reason
    (meta.msg included).

    Required arguments: host, path.

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
            routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
            An ordinary GET relays even while an area write opt-out is active. A GET of a
            state-changing route (protect/api/cameras/{id}/enable-control or
            protect/api/cameras/{id}/disable-control) is a write: it follows the area write
            opt-outs, UNIFI_ENABLE_CONNECTOR_WRITE, read-only mode and dry-run, and is sent
            once. Mutations on
            unclassified routes are refused only while an area write opt-out is active, with
            the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
            placeholder for the site segment; '..', %-encoding and control characters are
            rejected.
        site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
            (UUID); the server substitutes it.
        body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
            Network 10.6.106 for network/integration/v1). Use the typed tool when one exists.
            Free-form JSON value: object, array (e.g. []), string, number, boolean or null.
            The caller-chosen route determines its shape.
        confirm: Ignored; accepted for backward compatibility. The call executes immediately when
            made unless the operator opted in to UNIFI_DRY_RUN (then nothing is sent upstream and
            a preview of the request is returned).
        scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
            global-setting routes; 'site'/'global' reject /rest|/stat/device.
        params: Optional query-string parameters sent with the write (and with the
            read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
            sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
            Free-form JSON object; the caller-chosen route determines its shape.
    """
    client, registry = _require()
    return await connector.connector_write(
        client,
        registry,
        host,
        "POST",
        path,
        site=site,
        body=body,
        params=params,
        confirm=confirm,
        scope=scope,
        write_enabled=get_settings().enable_connector_write,
    )


@mcp.tool(annotations=WRITE)
async def fabric_connector_put(
    host: str,
    path: str,
    site: str | None = None,
    body: connector.RelayBody = None,
    confirm: bool = False,
    scope: str | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Relay a PUT (full replace) through the Fabric connector. Writes upstream.

    Consequence: replaces the resource immediately; omitted fields can be reset.

    For ``network/api/s/{site}/rest/device/{id}``, pass scope='device' to reject site-global
    setting routes; it has no GET, so reads use stat/device and noOp compares only sent fields
    (noOpBasis). Undocumented routes are EXPERIMENTAL. fabric_connector_get defines
    host/path/site/scope; body is verbatim; confirm is ignored.

    Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body,
    writeEnabled, readBefore, readAfter, noOp[, changed, noOpBasis]}. status/body are verbatim,
    including 4xx/5xx; binary is {bodyBase64, sizeBytes, body: null}; an unfollowed 3xx adds
    headers. readBefore/readAfter are twin GET results ({status: null, error} on failure);
    readAfterError explains a failed or non-2xx read-after. For rest/device each read has the
    stat/device list as body, matched comparisonRecords, twin and twinError (why a device
    was not compared). noOp is true only if the write and both reads are 2xx and every sent
    leaf matches (unsent siblings ignored; body-less writes compare whole bodies);
    null if unknown (noOpReason unless readAfterError explains). changed (= not noOp) is
    present only when noOp is non-null. A Classic network/api/... 2xx lacking meta.rc "ok" is
    rejected: _classicRcError includes meta.msg, noOp is null, reads carry the marker.
    UNIFI_DRY_RUN sends nothing: status "dry_run", body the {method, path, params, body}
    preview, readAfter/noOp null.

    Refused before requests if UNIFI_ENABLE_CONNECTOR_WRITE is falsey, UNIFI_READ_ONLY is on,
    a protect/ path has UNIFI_PROTECT_MUTATIONS_ENABLED falsey (all area write opt-outs apply), or
    an unclassified route meets an active area opt-out. Sent once: never auto-retried on 429
    (raised with the upstream body).

    Details: docs/TOOL-USAGE.md#fabric_connector_put.

    HTTP 401/403 adds _hint (key setup/permission advice);
    readBefore/readAfter carry the same guidance for failed GET twins.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
            routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
            An ordinary GET relays even while an area write opt-out is active. A GET of a
            state-changing route (protect/api/cameras/{id}/enable-control or
            protect/api/cameras/{id}/disable-control) is a write: it follows the area write
            opt-outs, UNIFI_ENABLE_CONNECTOR_WRITE, read-only mode and dry-run, and is sent
            once. Mutations on
            unclassified routes are refused only while an area write opt-out is active, with
            the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
            placeholder for the site segment; '..', %-encoding and control characters are
            rejected.
        site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
            (UUID); the server substitutes it.
        body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
            Network 10.6.106 for network/integration/v1). Use the typed tool when one exists.
            Free-form JSON value: object, array (e.g. []), string, number, boolean or null.
            The caller-chosen route determines its shape.
        confirm: Ignored; accepted for backward compatibility. The call executes immediately when
            made unless the operator opted in to UNIFI_DRY_RUN (then nothing is sent upstream and
            a preview of the request is returned).
        scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
            global-setting routes; 'site'/'global' reject /rest|/stat/device.
        params: Optional query-string parameters sent with the write (and with the
            read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
            sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
            Free-form JSON object; the caller-chosen route determines its shape.
    """
    client, registry = _require()
    return await connector.connector_write(
        client,
        registry,
        host,
        "PUT",
        path,
        site=site,
        body=body,
        params=params,
        confirm=confirm,
        scope=scope,
        write_enabled=get_settings().enable_connector_write,
    )


@mcp.tool(annotations=WRITE)
async def fabric_connector_patch(
    host: str,
    path: str,
    site: str | None = None,
    body: connector.RelayBody = None,
    confirm: bool = False,
    scope: str | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Relay a PATCH (partial update) through the Fabric connector. Writes upstream.

    Consequence: the change is applied to the live controller immediately.

    Classic rest/device/{id} reads use stat/device as for fabric_connector_put. For candidate
    legacy InnerSpace ``innerspace/api/shapes/{id}``, first
    probe a nonexistent shape ID with an empty body: 4xx = reachable; 200/204 = stop.
    EXPERIMENTAL. fabric_connector_get defines host/path/site/scope; body is verbatim; confirm is
    ignored.

    Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body,
    writeEnabled, readBefore, readAfter, noOp[, changed]}. status/body are verbatim,
    including 4xx/5xx; binary is {bodyBase64, sizeBytes, body: null}; an unfollowed 3xx adds
    headers. readBefore/readAfter are twin GET results ({status: null, error} on failure);
    readAfterError explains a failed or non-2xx read-after. For rest/device each read has the
    stat/device list as body, matched comparisonRecords, twin and twinError (why a device
    was not compared). noOp is true only if the write and both reads are 2xx and every sent
    leaf matches (unsent siblings ignored; body-less writes compare whole bodies);
    null if unknown (noOpReason unless readAfterError explains). changed (= not noOp) is
    present only when noOp is non-null. A Classic network/api/... 2xx lacking meta.rc "ok" is
    rejected: _classicRcError includes meta.msg, noOp is null, reads carry the marker.
    UNIFI_DRY_RUN sends nothing: status "dry_run", body the {method, path, params, body}
    preview, readAfter/noOp null.

    Refused before requests if UNIFI_ENABLE_CONNECTOR_WRITE is falsey, UNIFI_READ_ONLY is on,
    a protect/ path has UNIFI_PROTECT_MUTATIONS_ENABLED falsey (all area write opt-outs apply), or
    an unclassified route meets an active area opt-out. Sent once: never auto-retried on 429
    (raised with the upstream body).

    Details: docs/TOOL-USAGE.md#fabric_connector_patch.

    HTTP 401/403 adds _hint (key setup/permission advice);
    readBefore/readAfter carry the same guidance for failed GET twins.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
            routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
            An ordinary GET relays even while an area write opt-out is active. A GET of a
            state-changing route (protect/api/cameras/{id}/enable-control or
            protect/api/cameras/{id}/disable-control) is a write: it follows the area write
            opt-outs, UNIFI_ENABLE_CONNECTOR_WRITE, read-only mode and dry-run, and is sent
            once. Mutations on
            unclassified routes are refused only while an area write opt-out is active, with
            the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
            placeholder for the site segment; '..', %-encoding and control characters are
            rejected.
        site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
            (UUID); the server substitutes it.
        body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
            Network 10.6.106 for network/integration/v1). Use the typed tool when one exists.
            Free-form JSON value: object, array (e.g. []), string, number, boolean or null.
            The caller-chosen route determines its shape.
        confirm: Ignored; accepted for backward compatibility. The call executes immediately when
            made unless the operator opted in to UNIFI_DRY_RUN (then nothing is sent upstream and
            a preview of the request is returned).
        scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
            global-setting routes; 'site'/'global' reject /rest|/stat/device.
        params: Optional query-string parameters sent with the write (and with the
            read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
            sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
            Free-form JSON object; the caller-chosen route determines its shape.
    """
    client, registry = _require()
    return await connector.connector_write(
        client,
        registry,
        host,
        "PATCH",
        path,
        site=site,
        body=body,
        params=params,
        confirm=confirm,
        scope=scope,
        write_enabled=get_settings().enable_connector_write,
    )


@mcp.tool(annotations=WRITE)
async def fabric_connector_delete(
    host: str,
    path: str,
    site: str | None = None,
    body: dict[str, Any] | None = None,
    confirm: bool = False,
    scope: str | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Relay a DELETE through the Fabric connector. Irreversible write to the controller.

    Consequence: the target resource is removed from the controller; there is no undo.

    DELETE reads its GET twin before/after; confirm the exact resource path first; body is
    optional. fabric_connector_get defines host/path/site/scope; body is verbatim; confirm is
    ignored.

    Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body,
    writeEnabled, readBefore, readAfter, noOp[, changed]}. status/body are verbatim,
    including 4xx/5xx; binary is {bodyBase64, sizeBytes, body: null}; an unfollowed 3xx adds
    headers. readBefore/readAfter are twin GET results ({status: null, error} on failure);
    readAfterError explains a failed or non-2xx read-after. DELETE is confirmed only by a
    404 read-after following a 2xx read-before: noOp false, changed true. If read-after still
    returns the resource, noOp is null with noOpReason "deletion not confirmed". Unknown is also
    noOp null; changed (= not noOp) is present only when noOp is non-null.
    A Classic network/api/... 2xx lacking meta.rc "ok" is rejected: status/body stay verbatim,
    _classicRcError includes meta.msg, noOp is null with no changed, and reads carry the marker.
    UNIFI_DRY_RUN sends nothing: status "dry_run", body the {method, path, params, body}
    preview, readAfter/noOp null, no changed.

    Refused before requests if UNIFI_ENABLE_CONNECTOR_WRITE is falsey, UNIFI_READ_ONLY is on,
    a protect/ path has UNIFI_PROTECT_MUTATIONS_ENABLED falsey (all area write opt-outs apply), or
    an unclassified route meets any active area opt-out. Sent once: never auto-retried on 429
    (raised with the upstream body).

    Details: docs/TOOL-USAGE.md#fabric_connector_delete.

    HTTP 401/403 keeps body/status and adds _hint (key setup/permission advice);
    readBefore/readAfter carry the same guidance for failed GET twins.

    Args:
        host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
            reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
            (MAC:numericId composite). One console serves both Network and Protect.
        path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
            routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
            An ordinary GET relays even while an area write opt-out is active. A GET of a
            state-changing route (protect/api/cameras/{id}/enable-control or
            protect/api/cameras/{id}/disable-control) is a write: it follows the area write
            opt-outs, UNIFI_ENABLE_CONNECTOR_WRITE, read-only mode and dry-run, and is sent
            once. Mutations on
            unclassified routes are refused only while an area write opt-out is active, with
            the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
            placeholder for the site segment; '..', %-encoding and control characters are
            rejected.
        site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
            (UUID); the server substitutes it.
        body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
            Network 10.6.106 for network/integration/v1). Optional for DELETE.
            Omit to send no body; an explicit null is sent as the JSON body null.
            Free-form JSON object; the caller-chosen route determines its shape.
        confirm: Ignored; accepted for backward compatibility. The call executes immediately when
            made unless the operator opted in to UNIFI_DRY_RUN (then nothing is sent upstream and
            a preview of the request is returned).
        scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
            global-setting routes; 'site'/'global' reject /rest|/stat/device.
        params: Optional query-string parameters sent with the write (and with the
            read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
            sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
            Free-form JSON object; the caller-chosen route determines its shape.
    """
    client, registry = _require()
    return await connector.connector_write(
        client,
        registry,
        host,
        "DELETE",
        path,
        site=site,
        body=body,
        params=params,
        confirm=confirm,
        scope=scope,
        write_enabled=get_settings().enable_connector_write,
    )


# --- Mobility Tools (workspace-scoped identity; no host/site resolution) ---


@mcp.tool(annotations=READ_ONLY)
async def list_mobility_workspaces(
    key_label: str | None = None,
) -> dict[str, Any]:
    """List UniFi Mobility workspaces visible to the authenticated API key.

    Returns the upstream body verbatim ({data, total, offset, limit, httpStatusCode, traceId}) plus
    _count; incomplete / incompleteReason when total exceeds the rows returned. With several keys:
    {data, _count, _key_labels, byKey} plus errors.

    A workspace is a mobility "cloud site" (workspace_id, workspace_name, is_owner,
    status). Returned verbatim. Not query-paginated by the API. Mobility identity is
    workspace-based and independent of the console host/site model.

    Args:
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to cover
            every configured key: results are merged, each record carries an additive _keyLabel, and
            a key that fails is reported under errors.
    """
    client, _ = _require()
    return await mobility.list_mobility_workspaces(client, key_label=key_label)


@mcp.tool(annotations=READ_ONLY)
async def list_mobility_admins(
    workspace_id: str,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List the admins of a Mobility workspace (mobility permissions only).

    Returns the upstream body verbatim ({data, total, offset, limit, httpStatusCode, traceId}) plus
    _count; incomplete / incompleteReason when total exceeds the rows returned.

    Each admin carries name, email, status, is_owner and a permissions object
    exposing the umr (Mobile Routing) level (ALL/VIEW_ONLY/NONE); permissions is
    null for a pending invite. Returned verbatim.

    Example call (list_mobility_admins):
        {"workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    Args:
        workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
    """
    client, _ = _require()
    return await mobility.list_mobility_admins(client, workspace_id, key_label=key_label)


@mcp.tool(annotations=READ_ONLY)
async def list_mobility_devices(
    workspace_id: str,
    key_label: str | None = None,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List the UMR devices in a Mobility workspace.

    Returns {data, _count} plus the first page's other envelope fields (httpStatusCode,
    traceId); total (the upstream total, never computed) only when the upstream sent an
    integer one; incomplete / incompleteReason when the drain stopped short.

    Each device is the lightweight summary (id, name, model, state,
    firmware_version, mac_address). Offset-paginated by the API (limit/offset, 200
    max); every page is drained. Pass offset alone to fetch a single manual page (the
    upstream page body verbatim).

    Example call (list_mobility_devices):
        {"workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is gathered
            across pages of at most 200 starting at offset. Omit offset and limit to drain
            all.
            Example: `25`."""
    client, _ = _require()
    return await mobility.list_mobility_devices(
        client, workspace_id, key_label=key_label, offset=offset, limit=limit
    )


@mcp.tool(annotations=READ_ONLY)
async def get_mobility_device(
    workspace_id: str,
    device_id: str,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Get full detail for one UMR device in a Mobility workspace.

    Returns the upstream response object verbatim: the complete DeviceDetail
    (WAN/cellular/WiFi/VPN/subscription/GPS, counts, and the summary fields) under data,
    beside every other envelope field the API sends.

    Example call (get_mobility_device):
        {
          "workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    Args:
        workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
        device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
            Mobility id — not a Network device UUID.
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
    """
    client, _ = _require()
    return await mobility.get_mobility_device(client, workspace_id, device_id, key_label=key_label)


@mcp.tool(annotations=READ_ONLY)
async def list_mobility_clients(
    workspace_id: str,
    device_id: str,
    key_label: str | None = None,
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """List the clients associated with a UMR device.

    Returns {data, _count} plus the first page's other envelope fields (httpStatusCode,
    traceId); total (the upstream total, never computed) only when the upstream sent an
    integer one; incomplete / incompleteReason when the drain stopped short.

    Each client carries mac, name, type (WIRED/WIRELESS), connection_status,
    ip_address, is_blocked and (wireless only) a wifi_experience score.
    Offset-paginated by the API (limit/offset, 200 max); every page is drained. Pass
    offset alone to fetch a single manual page (the upstream page body verbatim).

    Example call (list_mobility_clients):
        {
          "workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        }

    limit requests a total, gathered automatically in batches up to 200;
    _pageSize reports requested count, actual sent sizes per request,
    observed effective size and returned count, without capping the total.

    Args:
        workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
        device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
            Mobility id — not a Network device UUID.
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
        offset: Optional zero-based starting record; alone, fetch one page manually.
            Example: `25`.
        limit: Without offset, the record count gathered from the start in pages of at
            most 200; fewer only when the collection ends. With offset, limit is gathered
            across pages of at most 200 starting at offset. Omit offset and limit to drain
            all.
            Example: `25`."""
    client, _ = _require()
    return await mobility.list_mobility_clients(
        client, workspace_id, device_id, key_label=key_label, offset=offset, limit=limit
    )


@mcp.tool(annotations=WRITE)
async def update_mobility_device_name(
    workspace_id: str,
    device_id: str,
    name: str,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Rename a UMR device (guarded write). WARNING: mutates live device config.

    Returns {status: "updated", changed: {field: {from, to}}, verified: {field: bool} for the
    fields observable in the device detail (null when the read-after fails; readAfterError says
    why), device (the read-after device-detail GET body verbatim, {data, httpStatusCode,
    traceId}), response (the PUT body verbatim; null for the documented 204)}, or {status:
    "no_op", reason, device (the GET body read first)}.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", device (the body read first), response
    (the preview)}; verified is absent (there is no read-after).

    Sends the full documented body {"name": name} (1-32 chars). Guarded, in order: the Mobility
    write opt-out (UNIFI_ENABLE_MOBILITY_WRITE=0 refuses first; writes are enabled by default),
    read-before, no-op detection (returns status="no_op" when already named this), write, and a
    read-after verification.

    Request body (Mobility 1.0.0, PUT /v1/mobility/workspaces/{workspaceID}/devices/{deviceID}
    (updateDeviceName); schema "UpdateDeviceNameReq") is built from scalar parameters. Required keys
    — name.
    - name: string

    Example call (update_mobility_device_name):
        {
          "workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "name": "Van 12"
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
        device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
            Mobility id — not a Network device UUID.
        name: New device name, 1-32 chars (spec UpdateDeviceNameReq.name).
        confirm: Ignored. The call runs when made; there is no confirmation step.
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
    """
    client, _ = _require()
    return await mobility.update_mobility_device_name(
        client, workspace_id, device_id, name, confirm=confirm, key_label=key_label
    )


@mcp.tool(annotations=WRITE)
async def update_mobility_device_network(
    workspace_id: str,
    device_id: str,
    host_address: str | None = Field(default_factory=lambda: mobility._UNSET),
    dhcp_mode: str | None = Field(default_factory=lambda: mobility._UNSET),
    dhcp_range_start: str | None = Field(default_factory=lambda: mobility._UNSET),
    dhcp_range_stop: str | None = Field(default_factory=lambda: mobility._UNSET),
    dhcp_lease_time: int | None = Field(default_factory=lambda: mobility._UNSET),
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Update a UMR device's LAN / DHCP settings (guarded write). Mutates live config.

    Returns {status: "updated", changed: {field: {from, to}}, verified: {field: bool or null}
    for every requested field (null for fields absent from the pinned device-detail schema;
    the whole map is null on read-after failure, with readAfterError), device
    (the read-after device-detail GET body verbatim, {data, httpStatusCode,
    traceId}), response (the PUT body verbatim; null for the documented 204)}, or {status:
    "no_op", reason, device (the GET body read first)}.
    Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", device (the body read first),
    response
    (the preview)}; verified is absent (there is no read-after).

    DOCUMENTED partial update: only provided fields are applied (WAN/IPv6/InternetSource are
    not configurable here). At least one field is required. The Mobility docs differ on PUT
    semantics (full replacement vs this endpoint's documented partial merge); if the console
    applies full replacement, unsent LAN/DHCP fields can be reset. Set
    UNIFI_ENABLE_MOBILITY_WRITE=0 for a read-only deployment. dhcp_mode is 'dhcp' (enabled) or
    'none' (disabled); IPs must be dotted-quad IPv4 (spec format: ipv4; a leading-zero octet
    such as 192.168.01.1 is refused before any request); dhcp_lease_time is seconds
    (0 = infinite). Guarded, in order: the Mobility write opt-out
    (UNIFI_ENABLE_MOBILITY_WRITE=0 refuses first), read-before, no-op detection on the
    observable host_address, write, read-after.

    Each field is nullable: explicit null is forwarded as null; an omitted field stays omitted
    (unchanged).

    Full request shapes are in the parameter schema; detailed examples and workflows:
    docs/TOOL-USAGE.md#update_mobility_device_network.

    Required arguments: workspace_id, device_id (see parameter descriptions for identifiers).

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
        device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
            Mobility id — not a Network device UUID.
        host_address: Optional new LAN gateway IPv4 (spec UpdateNetworkReq).
        dhcp_mode: Optional 'dhcp' or 'none'.
        dhcp_range_start: Optional DHCP pool start IPv4.
        dhcp_range_stop: Optional DHCP pool end IPv4.
        dhcp_lease_time: Optional lease seconds (>=0; 0 = infinite).
        confirm: Ignored. The call runs when made; there is no confirmation step.
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
    """
    host_address = _nullable_default(host_address, mobility._UNSET)
    dhcp_mode = _nullable_default(dhcp_mode, mobility._UNSET)
    dhcp_range_start = _nullable_default(dhcp_range_start, mobility._UNSET)
    dhcp_range_stop = _nullable_default(dhcp_range_stop, mobility._UNSET)
    dhcp_lease_time = _nullable_default(dhcp_lease_time, mobility._UNSET)
    client, _ = _require()
    return await mobility.update_mobility_device_network(
        client,
        workspace_id,
        device_id,
        host_address=host_address,
        dhcp_mode=dhcp_mode,
        dhcp_range_start=dhcp_range_start,
        dhcp_range_stop=dhcp_range_stop,
        dhcp_lease_time=dhcp_lease_time,
        confirm=confirm,
        key_label=key_label,
    )


@mcp.tool(annotations=WRITE)
async def update_mobility_device_wireless(
    workspace_id: str,
    device_id: str,
    ssid: str,
    password: str,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Update a UMR device's WiFi SSID + password (guarded write). Mutates live config.

    Returns {status: "updated", changed: {field: {from, to}}, verified: {field: bool or null}
    for every requested field (null for fields absent from the pinned device-detail schema;
    the whole map is null on read-after failure, with readAfterError), device
    (the read-after device-detail GET body verbatim, {data, httpStatusCode,
    traceId}), response (the PUT body verbatim; null for the documented 204)}. It never returns
    no_op. Under UNIFI_DRY_RUN nothing is sent: {status: "dry_run", device (the body read first),
    response (the preview)}; verified is absent (there is no read-after).

    Both fields are required by the API (channel/TX power/security protocol are not configurable
    here). ssid is 1-32 chars; password is a WPA2-PSK secret of 8-63 chars. Guarded, in order:
    the Mobility write opt-out (UNIFI_ENABLE_MOBILITY_WRITE=0 refuses first), read-before,
    write, read-after. There is no no-op short-circuit (the password is not observable, so an
    unchanged config cannot be proven). The supplied password is not echoed back in the result;
    under UNIFI_DRY_RUN the preview body shows the request as it would be sent, password
    included (masked as ***REDACTED*** only when UNIFI_REDACT_SECRETS is on, like every
    credential field of every dry-run preview).

    Request body (Mobility 1.0.0, PUT
    /v1/mobility/workspaces/{workspaceID}/devices/{deviceID}/wireless (updateDeviceWireless); schema
    "UpdateWirelessReq") is built from scalar parameters. Required keys — ssid, password.
    - ssid: string
    - password: string

    Example call (update_mobility_device_wireless):
        {
          "workspace_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "ssid": "Fleet-WiFi",
          "password": "correct-horse-9"
        }

    The dry-run preview contains method, path, params (query parameters), and body.

    Args:
        workspace_id: Mobility workspace UUID. Get it from list_mobility_workspaces (workspace_id).
        device_id: Mobility device UUID. Get it from list_mobility_devices (same workspace).
            Mobility id — not a Network device UUID.
        ssid: New SSID, 1-32 chars (spec UpdateWirelessReq.ssid).
        password: New WPA2-PSK, 8-63 chars (spec UpdateWirelessReq.password).
        confirm: Ignored. The call runs when made; there is no confirmation step.
        key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
            whichever configured key owns the object: every key is tried and the first that answers
            is used.
    """
    client, _ = _require()
    return await mobility.update_mobility_device_wireless(
        client, workspace_id, device_id, ssid, password, confirm=confirm, key_label=key_label
    )


# Install opt-in credential redaction (public issue
# https://github.com/swkstudios/unifi-fabric-mcp-server/issues/26) at one shared point: every
# registered tool handler is wrapped so that, when UNIFI_REDACT_SECRETS is enabled,
# the documented credential fields are masked in the response. The flag is read at
# call time; when disabled the wrapper is a byte-identical pass-through.
install_resolution_state(mcp)
install_response_redaction(mcp, lambda: get_settings().redact_secrets)

# Explicit, structured list results: FastMCP turns an empty list into content: []
# with no structuredContent, so a client cannot tell "zero items" from "no output".
# Every list-shaped result is returned as a JSON text block plus
# structuredContent: {"result": [...]}; items are unchanged. Installed through the
# public add_transform() API (raises at startup if that API is missing); tools whose
# advertised outputSchema does not admit {"result": [...]} are served unchanged. The
# redaction wrapper replaces handlers at registration, so it runs inside this one.
install_structured_list_results(mcp)

# Display titles with acronyms and product names spelled correctly (``List ISP
# Metrics``, not ``List Isp Metrics``). Title metadata only; names, schemas and
# behaviour are unchanged.
install_tool_titles(mcp)
install_tool_annotations(mcp)
install_compact_selector_descriptions(mcp)

# Generated, permissive pinned-spec body shapes for AI clients.
install_tool_shapes(mcp)

# API-source class (app/source/access) as tool metadata (unifi/apiSource), derived from
# each tool's routes. Metadata only.
install_api_sources(mcp)


# Actionable argument errors: a call that omits a required argument, passes an unknown
# one, or sends the wrong type gets a ToolError naming each parameter, where its value
# comes from, and an example call. Only the framework's own argument parsing is
# rewritten; errors raised inside a tool and upstream response bodies pass unchanged.
class SecretScrubMiddleware(Middleware):
    """Tool-call middleware inside RedactionScope and ConfirmIgnored: no secret leaves in an error.

    The client already scrubs its own errors; this is the backstop for every other
    error a tool (or another middleware) raises. An error holding no secret is
    re-raised unchanged; one that does is replaced by a ``ToolError`` carrying the
    scrubbed text, without its cause chain. Exception notes are rendered after the
    original text so fallback context survives MCP error serialization.
    """

    async def on_call_tool(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        # One scope per tool call. It starts with the registered secret arguments
        # (route_secrets: a typed tool's secret argument, or the relay body's secret
        # fields for a registered path), bound before any argument validation can echo
        # them; the client adds a registered route's request and response secrets to it.
        # Credential-named arguments of any tool (refusal_audit.credential_values: a
        # password, token or key field, at any depth) join them.
        arguments = getattr(context.message, "arguments", None) or {}
        tool = getattr(context.message, "name", None)
        values = (
            route_secrets.tool_call_secrets(tool, arguments)
            if isinstance(tool, str) and isinstance(arguments, dict)
            else ()
        )
        with secret_scope((*values, *credential_values(arguments))):
            return await self._call_scrubbed(context, call_next)

    async def _call_scrubbed(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        try:
            return await call_next(context)
        except Exception as exc:
            text = str(exc)
            notes: list[str] = []
            source: BaseException | None = exc
            seen: set[int] = set()
            while source is not None and id(source) not in seen:
                seen.add(id(source))
                for note in getattr(source, "__notes__", ()):
                    if note not in notes:
                        notes.append(note)
                source = source.__cause__
            if notes:
                text = "\n\n".join((text, *notes))
            clean = scrub(
                text,
                configured_secrets(
                    _settings,
                    _mcp_transport,
                    include_call=bool(_settings and _settings.redact_secrets),
                ),
            )
            if clean == text and not notes:
                raise
            raise ToolError(clean) from None


class AuditContextMiddleware(Middleware):
    """Bind a tool name and elapsed time to additive audit records."""

    async def on_call_tool(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        with audit_call(getattr(context.message, "name", None)):
            return await call_next(context)


# Bind runtime redaction settings before middleware validates incoming bodies.
def _redaction_scope_enabled() -> bool:
    """Resolve the same lazy settings as tool wrappers, even before lifespan startup."""
    try:
        return get_settings().redact_secrets
    except Exception:
        # Malformed settings are reported by startup; middleware must remain callable.
        return False


mcp.add_middleware(RedactionScopeMiddleware(_redaction_scope_enabled))
# Strip legacy arguments before discovery dispatch validates its outer envelope.
mcp.add_middleware(ConfirmIgnoredMiddleware())
# The scrubber wraps every tool error inside the redaction setting scope.
mcp.add_middleware(SecretScrubMiddleware())
mcp.add_middleware(AuditContextMiddleware())
mcp.add_middleware(connector.RelayBodyPresenceMiddleware())


def _audit_log_on() -> bool:
    """True when the live client writes an audit log (``UNIFI_AUDIT_LOG``)."""
    return _client is not None and _client.audit_enabled


# Every refused write tool call is audited exactly once (outcome=refused), whichever
# layer refused it: a gate below that audits its own refusal is counted, and any
# other refusal (argument checks, in-tool guards, the chokepoint, the relay) is
# audited here with its message as the reason. Outside every refusing middleware.
mcp.add_middleware(
    RefusedWriteAuditMiddleware(mcp, _audit_log_on, lambda t, r: _audit_refusal(t, r))
)

mcp.add_middleware(ArgumentErrorMiddleware(mcp))


def _audit_refusal(tool: str, reason: str) -> None:
    """Audit a write tool call a middleware gate refused (``outcome=refused``, ``reason`` =
    the gate) to the live client's opt-in audit log; a no-op before startup or when off."""
    if _client is not None:
        _client.audit_refusal(tool=tool, reason=reason)


# Opt-in read-only mode (UNIFI_READ_ONLY): a tool not annotated readOnlyHint is refused
# before its body runs, so a write tool's read-before step never reaches the console.
# With the mode off the call passes straight through.
mcp.add_middleware(ReadOnlyToolMiddleware(mcp, audit=_audit_refusal))


def _oauth_write_scope() -> str:
    """The configured OAuth write scope (oauth mode only); validates the transport
    settings on first use when the server was not started through :func:`main`."""
    transport = _transport_settings()
    return transport.oauth_write_scope if transport.auth_mode == "oauth" else ""


# Opt-in OAuth write scope (MCP_OAUTH_WRITE_SCOPE, oauth mode only): a write tool is
# refused before its body runs unless the caller's access token carries the scope.
# Unset, every admitted token can call every tool.
mcp.add_middleware(
    WriteScopeMiddleware(
        mcp,
        _oauth_write_scope,
        audit=_audit_refusal,
    )
)

# Per-area write opt-outs refuse every write tool of their area before its body runs, so
# the opt-out message comes before any argument validation or upstream call. The same
# write tools are hidden at startup; a hidden name called by a client is refused here.
mcp.add_middleware(
    AreaOptOutMiddleware(mcp, lambda: get_settings().enable_connector_write, audit=_audit_refusal)
)


# Every update tool with a free-form body: a body with no field to change (empty, only
# additive '_' keys, only masked secrets, only empty objects) is refused before the tool
# body runs, so no resolution or read-before happens (write_body.py).
mcp.add_middleware(EmptyUpdateMiddleware(mcp, audit=_audit_refusal))


def _configured_key_labels() -> list[str] | None:
    """The configured API key labels (the live client's, else the settings'), or None
    when the settings cannot be read (the tool then reports the configuration error)."""
    if _client is not None:
        return _client.list_key_labels()
    try:
        return [cfg.label for cfg in get_settings().get_key_configs()]
    except Exception:  # noqa: BLE001 - a settings error surfaces from the tool itself
        return None


# A host / site / key_label that cannot name anything (empty, whitespace, surrounding
# whitespace, a control character such as a trailing newline) is refused before the tool
# body runs, so it never costs a console-list fetch (selector_args.py); so is a
# key_label naming no configured key, for every tool and any number of keys.
# A well-formed unknown host / site name stays the resolver's error.
mcp.add_middleware(SelectorArgumentMiddleware(_configured_key_labels))

# A NaN or Infinity anywhere in the arguments fails before any request (JSON validity,
# argument_values.py). A blank filter string or an empty list is a value, never refused.
mcp.add_middleware(ArgumentValueMiddleware(mcp))

# Every value limit the vendored specs state for an argument (minimum / maximum /
# lengths / pattern / enum / item counts, mapped to arguments by spec_limits_gen) is
# checked before the tool body runs, so an out-of-range value sends no request
# (spec_limits.py). Exactly the spec's limits, never stricter.
mcp.add_middleware(SpecLimitMiddleware())


def _reconcile_stateless_http() -> None:
    """Keep ``FASTMCP_TRANSPORT=sse`` working when stateless HTTP is the image default.

    The container image sets ``FASTMCP_STATELESS_HTTP=true`` (each streamable-HTTP
    request is served independently, with no session to keep). The SSE transport is
    inherently session-based and FastMCP refuses to start it in stateless mode, so for
    SSE the stateless default is switched off instead of failing at startup.
    """
    import fastmcp

    if fastmcp.settings.transport == "sse" and fastmcp.settings.stateless_http:
        logging.getLogger(__name__).info(
            "FASTMCP_TRANSPORT=sse is session-based; ignoring FASTMCP_STATELESS_HTTP=true."
        )
        fastmcp.settings.stateless_http = False


def _configuration_error_line(exc: ValueError) -> str:
    """One actionable line for a malformed setting, never echoing a value.

    The settings models set ``hide_input_in_errors`` and their validators name the
    variable without its value, so only each error's message is used: never the input,
    the location's value or the pydantic error URL.
    """
    from pydantic import ValidationError

    if isinstance(exc, ValidationError):
        reasons = [
            str(err.get("msg", "")).removeprefix("Value error, ")
            for err in exc.errors(include_url=False, include_context=False, include_input=False)
        ]
    else:
        reasons = [str(exc)]
    reason = "; ".join(" ".join(r.split()) for r in reasons if r.strip()) or type(exc).__name__
    line = f"unifi-fabric-mcp: invalid configuration: {reason}. See README#configuration"
    return scrub(line, configured_secrets(_settings, _mcp_transport))


def _print_startup_warnings(transport: MCPTransportSettings) -> None:
    """Print a WARNING line to stderr for each risky posture the server starts with
    (:func:`startup_warnings`); the server still starts."""
    import fastmcp

    from .config import _resolved_fastmcp_transport

    for line in startup_warnings(
        transport,
        _resolved_fastmcp_transport(),
        str(fastmcp.settings.host),
        int(fastmcp.settings.port),
    ):
        print(f"unifi-fabric-mcp: {line}", file=sys.stderr)


def main() -> None:
    """Entry point for the MCP server."""
    import fastmcp

    # Validate the upstream key before FastMCP starts its transport/lifespan, so a
    # missing or malformed key is a concise CLI error rather than a startup traceback.
    try:
        transport = _configure_transport()
        key_configs = get_settings().get_key_configs()
    except ValueError as exc:  # pydantic ValidationError and SettingsError included
        print(_configuration_error_line(exc), file=sys.stderr)
        raise SystemExit(1) from None
    if not key_configs:
        print(
            "UNIFI_API_KEY is not set — get a key at https://unifi.ui.com "
            "(Site Manager > API Keys) and set UNIFI_API_KEY or UNIFI_API_KEYS; "
            "see README#get-your-api-key",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        _reconcile_stateless_http()
        _print_startup_warnings(transport)
        # Every HTTP transport uses bounded server-owned access logging.
        # stdio takes no uvicorn_config keyword.
        if fastmcp.settings.transport in HTTP_TRANSPORTS:
            mcp.run(uvicorn_config=build_uvicorn_config(transport))
        else:
            mcp.run()
    except ValueError as exc:
        # Library/transport startup validation uses the same safe renderer too.
        print(_configuration_error_line(exc), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
