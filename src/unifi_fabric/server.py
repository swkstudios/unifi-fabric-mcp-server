"""UniFi Fabric MCP Server — FastMCP server exposing UniFi Site Manager API tools."""

from __future__ import annotations

if __name__ == "__main__":
    # Route module execution through the lightweight CLI preflight before this
    # module imports and registers the full MCP tool catalog.
    from .entrypoint import main as _entrypoint_main

    _entrypoint_main()
    raise SystemExit

import inspect
import logging
import os
import re
import ssl
import sys

from .tool_annotations import install_tool_annotations

# Suppress pydantic version URLs in validation error messages (information disclosure).
os.environ.setdefault("PYDANTIC_ERRORS_INCLUDE_URL", "0")

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AuthProvider
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult

from . import policy, request_policy, route_secrets, switches
from .api_sources import install_api_sources
from .argument_errors import ArgumentErrorMiddleware
from .argument_values import ArgumentValueMiddleware
from .audit import AUDIT_UNAVAILABLE, NOTICE_META_KEY, audit_call
from .catalog_descriptions import install_compact_selector_descriptions
from .client import UniFiClient, UniFiHTTPError
from .config import MCPTransportSettings, Settings, known_setting_names
from .confirm_compat import ConfirmIgnoredMiddleware
from .contracts import EffectivePolicy
from .discovery import apply_tool_mode
from .entrypoint import _version
from .header_credentials import (
    HEADER_MODE,
    CredentialLeaseMiddleware,
    HeaderCredentialMiddleware,
    StartupRefusal,
    check_startup,
    header_mode_enabled,
    set_policy_provider,
    set_process_key_mode,
)
from .list_results import install_structured_list_results
from .read_only_tools import (
    AreaOptOutMiddleware,
    ExposureMiddleware,
    ReadOnlyToolMiddleware,
    apply_area_opt_out_tool_filter,
    apply_read_only_tool_filter,
)
from .redaction import (
    RedactionScopeMiddleware,
    install_response_redaction,
    mask_error_text,
    write_redaction_enabled,
)
from .refusal_audit import RefusedWriteAuditMiddleware, credential_values
from .registry import Registry
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
from .tools._shared import (  # noqa: F401  (re-exported for server-level callers)
    _image_result,
    _nullable_default,
    _validate_optional_site,
)
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


async def startup_policy(app: FastMCP) -> EffectivePolicy:
    """Refuse a retired setting, then evaluate the four policy settings over the registered
    catalog. A refusal prints its startup token as the last stderr line (an unrecognized
    setting also prints the migration line before it) and exits non-zero. On
    success the ``policy.startup`` record is written once to stderr, whatever the log or
    audit level."""
    try:
        policy.check_retired_settings(os.environ, known_setting_names())
        names = policy.Catalog.for_names(tool.name for tool in await app.list_tools())
        effective = policy.operator_policy(os.environ, names)
    except policy.StartupRefusal as exc:
        print(exc.stderr_text(), end="", file=sys.stderr, flush=True)
        raise SystemExit(2) from None
    policy.install_catalog(names, effective)
    policy.emit(policy.startup_record(effective))
    return effective


@asynccontextmanager
async def lifespan(app: FastMCP) -> AsyncIterator[None]:
    global _client, _registry
    effective_policy = await startup_policy(app)
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
    if not header_mode_enabled() and not settings.get_key_configs():
        policy.clear_exposure()
        raise RuntimeError(
            "No API key configured. Set UNIFI_API_KEY or UNIFI_API_KEYS before starting the server."
        )
    _client = UniFiClient(settings)
    if _client.audit_stream is not None:
        _client.audit_stream.startup(_version())
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
    excluded: set[str] = set()
    restore_tool_mode: Callable[[], None] | None = None
    try:
        # Exposure (UNIFI_FAMILY_ALLOW and UNIFI_EXCLUDE): no-op when both are unset (full
        # roster); otherwise de-register every tool policy.is_exposed rejects. Meta tools
        # always stay.
        registered = {tool.name: tool for tool in await app.list_tools(run_middleware=False)}
        excluded = set(await policy.apply_exposure(app, effective_policy))
        # The tools the exposure settings, a deny policy and the area exceptions hide are put
        # back when this lifespan ends, so the registered catalog is the same for the next
        # session.
        hidden_writes = await apply_read_only_tool_filter(app, switches.is_read_only())
        # Per-area write opt-outs hide that area's write tools the same way (no-op by
        # default).
        hidden_area_writes = await apply_area_opt_out_tool_filter(
            app, switches.connector_writes_enabled()
        )
        # Tool-mode selection (UNIFI_TOOL_MODE): discovery, the default, advertises the
        # meta-tools and reaches every registered tool through them; full advertises every
        # registered tool.
        restore_tool_mode = await apply_tool_mode(
            app,
            settings.tool_mode,
            read_only=switches.is_read_only(),
            hidden_write_names=hidden_writes,
            hidden_area_writes=hidden_area_writes,
            audit=_audit_refusal,
            audit_hmac_key=settings.audit_hmac_key_bytes(),
        )
        # Discovery adds its own annotated dispatcher; hide that write as well.
        hidden_writes.update(await apply_read_only_tool_filter(app, switches.is_read_only()))
        yield
    finally:
        if restore_tool_mode is not None:
            restore_tool_mode()
        listed = {tool.name for tool in await app.list_tools(run_middleware=False)}
        for name in (hidden_writes | set(hidden_area_writes) | excluded) - listed:
            if name in registered:
                app.add_tool(registered[name])
        policy.clear_exposure()
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


INSTRUCTIONS = """UniFi Fabric manages UniFi infrastructure via Site Manager/Fabric.
list_hosts discovers consoles; host is reportedState.hostname/name or composite id.
Use site names: list_sites has Fabric ids, list_local_sites Network UUIDs.
Ambiguous names fail with choices. Devices are infrastructure; clients are end-user devices.
Read schemas for ids, time units and body shapes; Shape aliases end in "where T1=...".
Use zone-based firewall policies unless the user asks for ACL/classic rules.
list_firewall_zones_proxy discovers zones; ports use destination.trafficFilter.
Fetch before full PUT; deletes and physical actions may be irreversible.
UNIFI_FAMILY_ALLOW and UNIFI_EXCLUDE select tools. Writes default to allowed.
UNIFI_WRITE_POLICY=deny hides writes except fabric_connector_get; state-changing GETs fail.
UNIFI_WRITE_EXCEPTIONS family:ID=deny hides writes for:
network, protect, mobility, carrier, innerspace and connector.
Network includes firewall, clients, devices, vpn, hotspot and statistics;
connector includes typed relays. Other denies refuse calls.
A dry-run policy previews writes unsent; reads may occur.
UNIFI_REDACT_SECRETS is opt-in; previews may contain secrets.
List pagination drains all pages; UNIFI_PAGINATE_MAX_PAGES caps with incomplete=true.
Read schemas for page bases; continue with returned cursor, offset, _continuation or _nextPage.
Multi-key org cursors need key_label; unscoped lists report per-key failures.
Bodies and error reasons are preserved; relay 4xx/5xx are errors.
Never swallow failures or infer unsupported from one error.
See docs/TOOLS.md and docs/TOOL-USAGE.md."""


def deployment_instructions(settings: Settings) -> str:
    """Initialize advertises the active, validated mode without exposing credentials."""
    return INSTRUCTIONS + (
        f"\nCurrent deployment: UNIFI_WRITE_POLICY={policy.current().write_policy}."
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
        if transport.health_route:
            # Ahead of the MCP mount so the path never reaches the MCP handler.
            from .health import ServerState, health_route

            app.router.routes.insert(
                0, health_route(lambda: ServerState(_settings, _client is not None))
            )
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


_site_manager_tools = site_manager.register(mcp, lambda: _require())
list_hosts = _site_manager_tools["list_hosts"]
get_host = _site_manager_tools["get_host"]
list_sites = _site_manager_tools["list_sites"]
list_devices = _site_manager_tools["list_devices"]
get_isp_metrics = _site_manager_tools["get_isp_metrics"]
query_isp_metrics = _site_manager_tools["query_isp_metrics"]
list_sdwan_configs = _site_manager_tools["list_sdwan_configs"]
get_sdwan_config = _site_manager_tools["get_sdwan_config"]
get_sdwan_config_status = _site_manager_tools["get_sdwan_config_status"]
list_all_sites_aggregated = _site_manager_tools["list_all_sites_aggregated"]
get_site_health_summary = _site_manager_tools["get_site_health_summary"]
compare_site_performance = _site_manager_tools["compare_site_performance"]
search_across_sites = _site_manager_tools["search_across_sites"]
get_site_inventory = _site_manager_tools["get_site_inventory"]


# --- Network Tools ---


_network_tools = network.register(mcp, lambda: _require())
get_network_application_info = _network_tools["get_network_application_info"]
list_local_sites = _network_tools["list_local_sites"]
list_networks = _network_tools["list_networks"]
create_network = _network_tools["create_network"]
get_network = _network_tools["get_network"]
update_network = _network_tools["update_network"]
delete_network = _network_tools["delete_network"]
get_network_references = _network_tools["get_network_references"]
list_lags = _network_tools["list_lags"]
get_lag = _network_tools["get_lag"]
list_mc_lag_domains = _network_tools["list_mc_lag_domains"]
get_mc_lag_domain = _network_tools["get_mc_lag_domain"]
list_switch_stacks = _network_tools["list_switch_stacks"]
get_switch_stack = _network_tools["get_switch_stack"]
list_wifi_broadcasts = _network_tools["list_wifi_broadcasts"]
create_wifi_broadcast = _network_tools["create_wifi_broadcast"]
get_wifi_broadcast = _network_tools["get_wifi_broadcast"]
update_wifi_broadcast = _network_tools["update_wifi_broadcast"]
delete_wifi_broadcast = _network_tools["delete_wifi_broadcast"]
list_wan_interfaces = _network_tools["list_wan_interfaces"]
update_wan_interface = _network_tools["update_wan_interface"]


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


_firewall_proxy_tools = firewall_proxy.register(mcp, lambda: _require())
list_firewall_policies = _firewall_proxy_tools["list_firewall_policies"]
create_firewall_policy = _firewall_proxy_tools["create_firewall_policy"]
get_firewall_policy = _firewall_proxy_tools["get_firewall_policy"]
update_firewall_policy = _firewall_proxy_tools["update_firewall_policy"]
patch_firewall_policy = _firewall_proxy_tools["patch_firewall_policy"]
delete_firewall_policy = _firewall_proxy_tools["delete_firewall_policy"]
get_firewall_policy_ordering = _firewall_proxy_tools["get_firewall_policy_ordering"]
set_firewall_policy_ordering = _firewall_proxy_tools["set_firewall_policy_ordering"]
list_firewall_zones_proxy = _firewall_proxy_tools["list_firewall_zones_proxy"]
create_firewall_zone_proxy = _firewall_proxy_tools["create_firewall_zone_proxy"]
get_firewall_zone_proxy = _firewall_proxy_tools["get_firewall_zone_proxy"]
update_firewall_zone_proxy = _firewall_proxy_tools["update_firewall_zone_proxy"]
delete_firewall_zone_proxy = _firewall_proxy_tools["delete_firewall_zone_proxy"]
list_acl_rules = _firewall_proxy_tools["list_acl_rules"]
create_acl_rule = _firewall_proxy_tools["create_acl_rule"]
get_acl_rule = _firewall_proxy_tools["get_acl_rule"]
update_acl_rule = _firewall_proxy_tools["update_acl_rule"]
delete_acl_rule = _firewall_proxy_tools["delete_acl_rule"]
get_acl_rule_ordering = _firewall_proxy_tools["get_acl_rule_ordering"]
set_acl_rule_ordering = _firewall_proxy_tools["set_acl_rule_ordering"]


# --- DNS Policy Tools ---


_network_services_proxy_tools = network_services_proxy.register(mcp, lambda: _require())
list_dns_policies = _network_services_proxy_tools["list_dns_policies"]
create_dns_policy = _network_services_proxy_tools["create_dns_policy"]
get_dns_policy = _network_services_proxy_tools["get_dns_policy"]
update_dns_policy = _network_services_proxy_tools["update_dns_policy"]
delete_dns_policy = _network_services_proxy_tools["delete_dns_policy"]
list_traffic_matching_lists = _network_services_proxy_tools["list_traffic_matching_lists"]
create_traffic_matching_list = _network_services_proxy_tools["create_traffic_matching_list"]
get_traffic_matching_list = _network_services_proxy_tools["get_traffic_matching_list"]
update_traffic_matching_list = _network_services_proxy_tools["update_traffic_matching_list"]
delete_traffic_matching_list = _network_services_proxy_tools["delete_traffic_matching_list"]
list_vpn_servers = _network_services_proxy_tools["list_vpn_servers"]
list_site_to_site_tunnels = _network_services_proxy_tools["list_site_to_site_tunnels"]
list_radius_profiles = _network_services_proxy_tools["list_radius_profiles"]
list_hotspot_vouchers = _network_services_proxy_tools["list_hotspot_vouchers"]
create_hotspot_vouchers = _network_services_proxy_tools["create_hotspot_vouchers"]
get_hotspot_voucher = _network_services_proxy_tools["get_hotspot_voucher"]
delete_hotspot_voucher = _network_services_proxy_tools["delete_hotspot_voucher"]
bulk_delete_hotspot_vouchers = _network_services_proxy_tools["bulk_delete_hotspot_vouchers"]
list_device_tags = _network_services_proxy_tools["list_device_tags"]
list_countries = _network_services_proxy_tools["list_countries"]


# --- Protect Camera Management Tools ---


_protect_tools = protect.register(mcp, lambda: _require())
list_cameras = _protect_tools["list_cameras"]
get_camera = _protect_tools["get_camera"]
update_camera = _protect_tools["update_camera"]
enable_camera_share_link = _protect_tools["enable_camera_share_link"]
get_camera_share_link = _protect_tools["get_camera_share_link"]
disable_camera_share_link = _protect_tools["disable_camera_share_link"]
get_camera_snapshot = _protect_tools["get_camera_snapshot"]
get_rtsps_stream = _protect_tools["get_rtsps_stream"]
create_rtsps_stream = _protect_tools["create_rtsps_stream"]
delete_rtsps_stream = _protect_tools["delete_rtsps_stream"]
start_talkback_session = _protect_tools["start_talkback_session"]
disable_camera_mic_permanently = _protect_tools["disable_camera_mic_permanently"]
ptz_goto_preset = _protect_tools["ptz_goto_preset"]
ptz_patrol_start = _protect_tools["ptz_patrol_start"]
ptz_patrol_stop = _protect_tools["ptz_patrol_stop"]
list_sensors = _protect_tools["list_sensors"]
get_sensor = _protect_tools["get_sensor"]
update_sensor = _protect_tools["update_sensor"]
list_protect_events = _protect_tools["list_protect_events"]
collect_protect_events = _protect_tools["collect_protect_events"]
collect_protect_device_changes = _protect_tools["collect_protect_device_changes"]


# --- Protect Face/Vehicle Recognition (private REST path) ---


_recognition_tools = recognition.register(mcp, lambda: _require())
list_recognition_groups = _recognition_tools["list_recognition_groups"]
get_recognition_group_counts = _recognition_tools["get_recognition_group_counts"]
get_recognition_group_image = _recognition_tools["get_recognition_group_image"]
list_recognition_detections = _recognition_tools["list_recognition_detections"]
get_thumbnail = _recognition_tools["get_thumbnail"]


# --- Protect Light Tools ---


_protect_tools_2 = protect.register_2(mcp, lambda: _require())
list_lights = _protect_tools_2["list_lights"]
get_light = _protect_tools_2["get_light"]
update_light = _protect_tools_2["update_light"]
list_chimes = _protect_tools_2["list_chimes"]
get_chime = _protect_tools_2["get_chime"]
update_chime = _protect_tools_2["update_chime"]
list_viewers = _protect_tools_2["list_viewers"]
get_viewer = _protect_tools_2["get_viewer"]
update_viewer = _protect_tools_2["update_viewer"]
list_liveviews = _protect_tools_2["list_liveviews"]
get_liveview = _protect_tools_2["get_liveview"]
create_liveview = _protect_tools_2["create_liveview"]
update_liveview = _protect_tools_2["update_liveview"]
get_nvr = _protect_tools_2["get_nvr"]
list_protect_files = _protect_tools_2["list_protect_files"]
upload_protect_file = _protect_tools_2["upload_protect_file"]
trigger_alarm_webhook = _protect_tools_2["trigger_alarm_webhook"]
list_arm_profiles = _protect_tools_2["list_arm_profiles"]
get_arm_profile = _protect_tools_2["get_arm_profile"]
create_arm_profile = _protect_tools_2["create_arm_profile"]
update_arm_profile = _protect_tools_2["update_arm_profile"]
delete_arm_profile = _protect_tools_2["delete_arm_profile"]
update_arm_profile_settings = _protect_tools_2["update_arm_profile_settings"]
enable_arm = _protect_tools_2["enable_arm"]
disable_arm = _protect_tools_2["disable_arm"]
list_sirens = _protect_tools_2["list_sirens"]
get_siren = _protect_tools_2["get_siren"]
update_siren = _protect_tools_2["update_siren"]
siren_play = _protect_tools_2["siren_play"]
siren_stop = _protect_tools_2["siren_stop"]
siren_test_sound = _protect_tools_2["siren_test_sound"]
list_fobs = _protect_tools_2["list_fobs"]
get_fob = _protect_tools_2["get_fob"]
update_fob = _protect_tools_2["update_fob"]
list_relays = _protect_tools_2["list_relays"]
get_relay = _protect_tools_2["get_relay"]
update_relay = _protect_tools_2["update_relay"]
relay_activate_output = _protect_tools_2["relay_activate_output"]
list_speakers = _protect_tools_2["list_speakers"]
get_speaker = _protect_tools_2["get_speaker"]
update_speaker = _protect_tools_2["update_speaker"]
speaker_test_sound = _protect_tools_2["speaker_test_sound"]
list_bridges = _protect_tools_2["list_bridges"]
get_bridge = _protect_tools_2["get_bridge"]
update_bridge = _protect_tools_2["update_bridge"]
list_link_stations = _protect_tools_2["list_link_stations"]
get_link_station = _protect_tools_2["get_link_station"]
update_link_station = _protect_tools_2["update_link_station"]
list_alarm_hubs = _protect_tools_2["list_alarm_hubs"]
get_alarm_hub = _protect_tools_2["get_alarm_hub"]
update_alarm_hub = _protect_tools_2["update_alarm_hub"]
alarm_hub_trigger_output = _protect_tools_2["alarm_hub_trigger_output"]
list_protect_users = _protect_tools_2["list_protect_users"]
get_protect_user = _protect_tools_2["get_protect_user"]
get_protect_application_info = _protect_tools_2["get_protect_application_info"]
list_ulp_users = _protect_tools_2["list_ulp_users"]
get_ulp_user = _protect_tools_2["get_ulp_user"]
pos_ingest_transaction = _protect_tools_2["pos_ingest_transaction"]


# --- Port Forwarding Tools ---


_network_services_proxy_tools_2 = network_services_proxy.register_2(mcp, lambda: _require())
list_port_forwards = _network_services_proxy_tools_2["list_port_forwards"]
create_port_forward = _network_services_proxy_tools_2["create_port_forward"]
update_port_forward = _network_services_proxy_tools_2["update_port_forward"]
delete_port_forward = _network_services_proxy_tools_2["delete_port_forward"]
list_traffic_rules = _network_services_proxy_tools_2["list_traffic_rules"]
create_traffic_rule = _network_services_proxy_tools_2["create_traffic_rule"]
update_traffic_rule = _network_services_proxy_tools_2["update_traffic_rule"]
delete_traffic_rule = _network_services_proxy_tools_2["delete_traffic_rule"]


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


_network_services_proxy_tools_3 = network_services_proxy.register_3(mcp, lambda: _require())
list_users = _network_services_proxy_tools_3["list_users"]
get_user = _network_services_proxy_tools_3["get_user"]
update_user = _network_services_proxy_tools_3["update_user"]
list_traffic_routes = _network_services_proxy_tools_3["list_traffic_routes"]
create_traffic_route = _network_services_proxy_tools_3["create_traffic_route"]
get_traffic_route = _network_services_proxy_tools_3["get_traffic_route"]
update_traffic_route = _network_services_proxy_tools_3["update_traffic_route"]
delete_traffic_route = _network_services_proxy_tools_3["delete_traffic_route"]
list_settings = _network_services_proxy_tools_3["list_settings"]
get_setting = _network_services_proxy_tools_3["get_setting"]
update_setting = _network_services_proxy_tools_3["update_setting"]
list_dynamic_dns = _network_services_proxy_tools_3["list_dynamic_dns"]
get_dynamic_dns = _network_services_proxy_tools_3["get_dynamic_dns"]
update_dynamic_dns = _network_services_proxy_tools_3["update_dynamic_dns"]
list_port_profiles = _network_services_proxy_tools_3["list_port_profiles"]
get_port_profile = _network_services_proxy_tools_3["get_port_profile"]
update_port_profile = _network_services_proxy_tools_3["update_port_profile"]
allow_network_on_port_profile = _network_services_proxy_tools_3["allow_network_on_port_profile"]
exclude_network_on_port_profile = _network_services_proxy_tools_3["exclude_network_on_port_profile"]
list_routing_entries = _network_services_proxy_tools_3["list_routing_entries"]
list_wlan_configs = _network_services_proxy_tools_3["list_wlan_configs"]
get_wlan_config = _network_services_proxy_tools_3["get_wlan_config"]
update_wlan_config = _network_services_proxy_tools_3["update_wlan_config"]
list_wlan_groups = _network_services_proxy_tools_3["list_wlan_groups"]
get_wlan_group = _network_services_proxy_tools_3["get_wlan_group"]
get_channel_plan = _network_services_proxy_tools_3["get_channel_plan"]
list_rogue_aps = _network_services_proxy_tools_3["list_rogue_aps"]
list_firewall_rules = _network_services_proxy_tools_3["list_firewall_rules"]
get_firewall_rule = _network_services_proxy_tools_3["get_firewall_rule"]
list_firewall_groups = _network_services_proxy_tools_3["list_firewall_groups"]
get_firewall_group = _network_services_proxy_tools_3["get_firewall_group"]
list_accounts = _network_services_proxy_tools_3["list_accounts"]
get_account = _network_services_proxy_tools_3["get_account"]
list_hotspot_packages = _network_services_proxy_tools_3["list_hotspot_packages"]
get_hotspot_package = _network_services_proxy_tools_3["get_hotspot_package"]
list_scheduled_tasks = _network_services_proxy_tools_3["list_scheduled_tasks"]
get_scheduled_task = _network_services_proxy_tools_3["get_scheduled_task"]
list_dpi_categories = _network_services_proxy_tools_3["list_dpi_categories"]
list_dpi_applications = _network_services_proxy_tools_3["list_dpi_applications"]


# --- InnerSpace Floor-Plan Tools ---


_placement_snapshot_tools = placement_snapshot.register(mcp, lambda: _require())
get_unifi_placement_snapshot = _placement_snapshot_tools["get_unifi_placement_snapshot"]


_innerspace_tools = innerspace.register(mcp, lambda: _require())
get_innerspace_summary = _innerspace_tools["get_innerspace_summary"]
get_innerspace_project = _innerspace_tools["get_innerspace_project"]
list_innerspace_devices = _innerspace_tools["list_innerspace_devices"]
list_innerspace_floor_plans = _innerspace_tools["list_innerspace_floor_plans"]
list_innerspace_access_points = _innerspace_tools["list_innerspace_access_points"]
list_innerspace_switches = _innerspace_tools["list_innerspace_switches"]
list_innerspace_inventory = _innerspace_tools["list_innerspace_inventory"]
get_innerspace_asset = _innerspace_tools["get_innerspace_asset"]


innerspace_internal.register(mcp, _require)


# --- Carrier / ISP Fabric Tools (org-scoped identity; no host/site resolution) ---
#
# Spec-conformance tested only: the UniFi Carrier / ISP Fabric tools (published Subscriber
# API v1.0.0, developer.ui.com/carrier-fabric/v1.0.0) are verified against the OpenAPI
# request/response shapes with hermetic fixtures, not against a live Carrier Fabric. The
# seven writes use read-before/no-op/read-after and the family:carrier=deny
# opt-out (writes enabled by default; add family:carrier=deny to UNIFI_WRITE_EXCEPTIONS,
# or set UNIFI_WRITE_POLICY=deny, for a read-only deployment).


_carrier_fabric_tools = carrier_fabric.register(mcp, lambda: _require())
list_carrier_subscribers = _carrier_fabric_tools["list_carrier_subscribers"]
get_carrier_subscriber = _carrier_fabric_tools["get_carrier_subscriber"]
list_carrier_service_plans = _carrier_fabric_tools["list_carrier_service_plans"]
get_carrier_service_plan = _carrier_fabric_tools["get_carrier_service_plan"]
create_carrier_subscriber = _carrier_fabric_tools["create_carrier_subscriber"]
update_carrier_subscriber = _carrier_fabric_tools["update_carrier_subscriber"]
attach_carrier_subscriber_host = _carrier_fabric_tools["attach_carrier_subscriber_host"]
detach_carrier_subscriber_host = _carrier_fabric_tools["detach_carrier_subscriber_host"]
assign_carrier_subscriber_plan = _carrier_fabric_tools["assign_carrier_subscriber_plan"]
suspend_carrier_subscriber = _carrier_fabric_tools["suspend_carrier_subscriber"]
resume_carrier_subscriber = _carrier_fabric_tools["resume_carrier_subscriber"]


# --- Guarded generic Fabric connector relay ---
#
# An ordinary GET is always available (a GET of a state-changing route is a write).
# POST/PUT/PATCH/DELETE are mutations gated by the
# UNIFI_WRITE_EXCEPTIONS entry family:connector=deny (writes enabled by default;
# add the entry, or set UNIFI_WRITE_POLICY=deny, for a read-only deployment).
# The confirm argument is accepted for
# compatibility and no longer required. See
# tools/connector.py for the full guard model (Registry-only
# identity, namespace allowlist, positive-charset path validation, read-before/
# write/read-after, scope guard, verbatim bodies, structured audit).


_connector_tools = connector.register(mcp, lambda: _require())
fabric_connector_get = _connector_tools["fabric_connector_get"]
fabric_connector_post = _connector_tools["fabric_connector_post"]
fabric_connector_put = _connector_tools["fabric_connector_put"]
fabric_connector_patch = _connector_tools["fabric_connector_patch"]
fabric_connector_delete = _connector_tools["fabric_connector_delete"]


# --- Mobility Tools (workspace-scoped identity; no host/site resolution) ---


_mobility_tools = mobility.register(mcp, lambda: _require())
list_mobility_workspaces = _mobility_tools["list_mobility_workspaces"]
list_mobility_admins = _mobility_tools["list_mobility_admins"]
list_mobility_devices = _mobility_tools["list_mobility_devices"]
get_mobility_device = _mobility_tools["get_mobility_device"]
list_mobility_clients = _mobility_tools["list_mobility_clients"]
update_mobility_device_name = _mobility_tools["update_mobility_device_name"]
update_mobility_device_network = _mobility_tools["update_mobility_device_network"]
update_mobility_device_wireless = _mobility_tools["update_mobility_device_wireless"]


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
    error a tool (or another middleware) raises. Under ``UNIFI_REDACT_SECRETS`` the
    final text also passes :func:`~unifi_fabric.redaction.mask_error_text`, so a
    credential field's value never reaches the client in an error, whatever builder
    formatted it. An error holding no secret is re-raised unchanged; one that does is
    replaced by a ``ToolError`` carrying the scrubbed text, without its cause chain.
    Exception notes are rendered after the original text so fallback context survives
    MCP error serialization.
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
            # Detect credential keys before configured-secret scrubbing can
            # replace an encoded key at its own decoding bound.
            guarded = mask_error_text(text) if write_redaction_enabled() else text
            clean = scrub(
                guarded,
                configured_secrets(
                    _settings,
                    _mcp_transport,
                    include_call=bool(_settings and _settings.redact_secrets),
                ),
            )
            if write_redaction_enabled():
                # The one boundary every tool error crosses to the client: under
                # UNIFI_REDACT_SECRETS no credential field's value leaves in it, in any
                # form a message can carry it (JSON, a repr, k=v, at any escape depth),
                # whichever builder formatted the message.
                clean = mask_error_text(clean)
            if clean == text and not notes:
                raise
            raise ToolError(clean) from None


class AuditContextMiddleware(Middleware):
    """Bind a tool name and elapsed time to additive audit records; write the per-call
    ``call`` / ``error`` record (``UNIFI_AUDIT_CALLS``); and add the fixed
    ``audit_unavailable`` notice to every response while the audit sink cannot be
    written (fail open: the call itself is never broken by the audit stream)."""

    async def on_call_tool(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        stream = _client.audit_stream if _client is not None else None
        name = getattr(context.message, "name", None)
        with audit_call(name):
            try:
                result = await call_next(context)
            except Exception as exc:
                if stream is not None:
                    stream.error(name, exc)
                    if stream.probe() and isinstance(exc, ToolError):
                        raise ToolError(f"{exc} [{AUDIT_UNAVAILABLE}]") from exc
                raise
            if stream is not None:
                stream.call(name, getattr(context.message, "arguments", None))
                if stream.probe():
                    result = _with_audit_notice(result)
            return result


def _with_audit_notice(result: Any) -> Any:
    """``result`` with the ``audit_unavailable`` notice in its ``_meta``."""
    if isinstance(result, ToolResult):
        meta = dict(result.meta or {})
        meta[NOTICE_META_KEY] = AUDIT_UNAVAILABLE
        return ToolResult(
            content=result.content,
            structured_content=result.structured_content,
            meta=meta,
            is_error=getattr(result, "is_error", False),
        )
    return result


def audit_policy_record(line: str) -> None:
    """Carry one policy record (``policy.startup`` / ``policy.refusal``) to the audit
    sink byte-identical, at every level (the policy module writes it to stderr itself)."""
    if _client is not None and _client.audit_stream is not None:
        _client.audit_stream.policy_record(line)


policy.set_record_listener(audit_policy_record)


def _audit_log_on() -> bool:
    """True when the live client writes an audit log (``UNIFI_AUDIT_LOG``)."""
    return _client is not None and _client.audit_enabled


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


def _environment_key_configs() -> list[Any]:
    """Environment-mode credentials in configured order (the live client's settings)."""
    settings = _client._settings if _client is not None else get_settings()  # noqa: SLF001
    return list(settings.get_key_configs())


# Header-credential ingress (UNIFI_KEY_MODE): builds the RequestContext and applies the
# ingress pre-dispatch refusals (invalid_api_key_header, repeated policy header,
# missing_api_key_header, key_label_not_allowed) before any other tool middleware, so a
# refused call makes no upstream call and allocates nothing.
_refused_write_audit = RefusedWriteAuditMiddleware(
    mcp, _audit_log_on, lambda t, r: _audit_refusal(t, r)
)
mcp.add_middleware(
    HeaderCredentialMiddleware(
        environment_configs=_environment_key_configs,
        on_refusal=_refused_write_audit.audit_ingress_refusal,
    )
)

# The policy evaluator supplies the header-mode baseline: the current operator policy.
set_policy_provider(policy.current)

# Every refused write tool call is audited exactly once (outcome=refused), whichever
# layer refused it: a gate below that audits its own refusal is counted, and any
# other refusal (the request policy's tool_not_exposed / write_denied, argument checks,
# in-tool guards, the chokepoint, the relay) is audited here: a coded refusal with its
# gate as the reason, any other with its message. Outside every refusing middleware, so
# it sits above the exposure and request-policy gates.
mcp.add_middleware(_refused_write_audit)

# Policy exposure (refusal order: tool_not_exposed before write_denied): a call to a tool
# the operator policy removed, directly or through call_read_tool / call_write_tool.
mcp.add_middleware(ExposureMiddleware())

# Request tightening: request policy headers tighten the operator policy. The ingress
# runs step (2) through the evaluator's hook; this middleware runs steps (5) and (6) and
# the request dry-run before every tool guard, argument check and upstream call.
_request_policy = request_policy.install(mcp)
mcp.add_middleware(request_policy.RequestPolicyMiddleware(_request_policy))
mcp.add_middleware(connector.RelayBodyPresenceMiddleware())


mcp.add_middleware(ArgumentErrorMiddleware(mcp))


def _audit_refusal(tool: str, reason: str) -> None:
    """Audit a write tool call a middleware gate refused (``outcome=refused``, ``reason`` =
    the gate) to the live client's opt-in audit log; a no-op before startup or when off."""
    if _client is not None:
        _client.audit_refusal(tool=tool, reason=reason)


# Opt-in read-only mode (UNIFI_WRITE_POLICY=deny): a tool not annotated readOnlyHint is refused
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
    AreaOptOutMiddleware(mcp, switches.connector_writes_enabled, audit=_audit_refusal)
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

# Header-credential lease: innermost, so credential_cache_saturated is the last
# pre-dispatch check (the policy, request-policy and Code Mode refusals are added above this line).
mcp.add_middleware(
    CredentialLeaseMiddleware(
        lambda: _client._credential_cache if _client is not None else None  # noqa: SLF001
    )
)


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
    line = f"unifi-fabric-mcp: invalid configuration: {reason}. See docs/CONFIGURATION.md"
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

    from .config import startup_gate

    # The one startup gate runs before any settings load (also when server.main is the
    # entry point): the startup token as the last stderr line, exit 2.
    startup_gate()

    # Validate the upstream key before FastMCP starts its transport/lifespan, so a
    # missing or malformed key is a concise CLI error rather than a startup traceback.
    try:
        transport = _configure_transport()
        key_configs = get_settings().get_key_configs()
    except ValueError as exc:  # pydantic ValidationError and SettingsError included
        print(_configuration_error_line(exc), file=sys.stderr)
        raise SystemExit(1) from None
    try:
        # Header mode needs HTTP: stdio carries no request headers.
        key_mode = check_startup(
            "http" if fastmcp.settings.transport in HTTP_TRANSPORTS else "stdio"
        )
    except StartupRefusal as refusal:
        print(refusal.token, file=sys.stderr)
        raise SystemExit(1) from None
    set_process_key_mode(key_mode)
    if key_mode == HEADER_MODE:
        if key_configs:
            logging.getLogger(__name__).warning(
                "UNIFI_KEY_MODE=header: the configured UNIFI_API_KEY/UNIFI_API_KEYS are "
                "ignored; every tool call uses only its X-UniFi-Api-Key header"
            )
    elif not key_configs:
        print(
            "UNIFI_API_KEY is not set — get a key at https://unifi.ui.com "
            "(Site Manager > API Keys) and set UNIFI_API_KEY or UNIFI_API_KEYS; "
            "see README#1-join-your-fabric-and-create-an-api-key",
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
