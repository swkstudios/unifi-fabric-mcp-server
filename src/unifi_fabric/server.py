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

from . import (
    background_tasks,
    policy,
    protect_resources,
    relay_policy,
    request_policy,
    route_secrets,
    stream_buffers,
    switches,
)
from .argument_errors import ArgumentErrorMiddleware
from .argument_values import ArgumentValueMiddleware
from .audit import AUDIT_UNAVAILABLE, NOTICE_META_KEY, audit_call
from .catalog import deferred, membership
from .client import UniFiClient, UniFiHTTPError
from .config import MCPTransportSettings, Settings, known_setting_names
from .confirm_compat import ConfirmIgnoredMiddleware
from .contracts import EffectivePolicy
from .discovery import _BROKER_CALL as _code_mode_broker
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
from .lane import LaneMiddleware
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
    mask_error_text,
    write_redaction_enabled,
)
from .refusal_audit import RefusedWriteAuditMiddleware, credential_values
from .registry import Registry
from .secret_scrub import (
    configured_secrets,
    install_log_scrubber,
    scrub,
    secret_scope,
    set_secret_provider,
)
from .selector_args import SelectorArgumentMiddleware
from .shared_shapes._shared import (  # noqa: F401  (re-exported for server-level callers)
    _image_result,
    _nullable_default,
    _validate_optional_site,
)
from .spec_limits import SpecLimitMiddleware
from .tracing import configure_trace_export, register_component_names, shutdown_trace_export
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
        listed = await app.list_tools(run_middleware=False)
        names = policy.Catalog.for_names(tool.name for tool in listed)
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
        # Deferred loading (public #41): UNIFI_PRELOAD loads the selected exposed steps now,
        # through the same path a first call takes; a hidden or excluded step never loads.
        controller = deferred.controller_for(app)
        if controller is not None:
            await controller.preload(settings.preload)
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
        # Trace export names only these tools and prompts; a name a caller invents is
        # never exported.
        register_component_names(
            set(registered) | {tool.name for tool in await app.list_tools(run_middleware=False)},
            {prompt.name for prompt in await app.list_prompts(run_middleware=False)},
        )
        yield
    finally:
        if restore_tool_mode is not None:
            restore_tool_mode()
        listed = {tool.name for tool in await app.list_tools(run_middleware=False)}
        hidden = (hidden_writes | set(hidden_area_writes) | excluded) - listed
        order = [name for name in registered if name in listed or name in hidden]
        # Put the hidden tools back where they were registered, not at the end: from the
        # first one on, the roster is re-added in registration order, so the next session
        # lists the same tools in the same order.
        first = next((i for i, name in enumerate(order) if name in hidden), len(order))
        for name in order[first:]:
            if name in listed:
                app.local_provider.remove_tool(name)
        for name in order[first:]:
            app.add_tool(registered[name])
        policy.clear_exposure()
        close_error: BaseException | None = None
        if _client.audit_stream is not None:
            # The chain head at clean shutdown narrows the unanchored tail (best effort).
            _client.audit_stream.log_head("shutdown")
        try:
            # Event-stream listeners (none exist while no product stream is supported).
            await stream_buffers.MANAGER.close_all()
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


def _prepare_tool_fn(fn: Any, kwargs: dict[str, Any]) -> Any:
    """Give a tool docstring with no result statement the short pass-through line
    (:meth:`FabricMCP.tool`); also applied to a deferred step's staged tools."""
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

    async def get_tool(self, name: str, version: Any = None) -> Any:
        """Resolve a tool, loading its deferred step first (public #41).

        Every call path resolves its target here (the call core and each middleware that
        reads a target), so the first of them loads the step before anything reads ``fn``
        or validates arguments. A failed load raises ``family_load_failed``; it never
        returns ``None``, which the write guards would read as "not a write".
        """
        controller = deferred.controller_for(self)
        if controller is not None:
            await controller.resolve(name)
        return await super().get_tool(name, version)

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
            return _prepare_tool_fn(fn, kwargs)

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
    # A resource read is per caller and time-sensitive (Protect events and snapshots):
    # never reused and never shared, whatever UNIFI_MCP_CACHE_TTL says for the lists.
    mcp._mcp_server.cache_hints.update(protect_resources.resource_read_cache_hint())  # noqa: SLF001
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


# --- Tool registration ---
#
# Every family registers through the explicit loader map (catalog/loaders.py), in its
# order, which is the tools/list order. Deferred loading (public #41,
# catalog/deferred.py): at import each tool is a fn-less stub built from the committed
# snapshot catalog/deferred.json, so tools/list, describe_tool and exposure are unchanged
# and no family module is imported. A tool's step loads on its first resolution: the step
# registers on a private staging app, the per-tool install passes run there in this order
# (resolution state, opt-in credential redaction (public issue
# https://github.com/swkstudios/unifi-fabric-mcp-server/issues/26), acronym-aware titles,
# source-derived annotations, compact selector descriptions, generated body shapes and
# API-source metadata), every staged tool is checked against its stub, and only then is it
# swapped into this server. No family tool is ever callable here without the redaction and
# resolution wrappers. When the snapshot was generated under another Python, fastmcp or
# pydantic version, every step registers eagerly at import, as before.
#
# The registration must then be exactly the explicit inventory (catalog/membership.py,
# public #42 step 6): every tool it lists, registered once (a stub by the step index it
# carries), by the step it names, in its order. A missing, duplicate or unknown tool
# refuses startup, naming it. No family module is imported for the check.
#
# The re-exports (server.<tool>, server.<module>) resolve through __getattr__ below.
globals().update(
    deferred.install(
        mcp,
        late=lambda: _require(),
        bound=_require,
        should_redact=lambda: get_settings().redact_secrets,
        prepare=_prepare_tool_fn,
    )
)
membership.verify(mcp)


def __getattr__(name: str) -> Any:
    """``server.<tool>`` and ``server.<module>``: load that step (or import that module)
    on first use, through the deferred loader's one load path."""
    controller = deferred.controller_for(globals().get("mcp"))
    if controller is None or name.startswith("__"):
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = controller.attribute(name)
    globals()[name] = value
    return value


# Explicit, structured list results: FastMCP turns an empty list into content: []
# with no structuredContent, so a client cannot tell "zero items" from "no output".
# Every list-shaped result is returned as a JSON text block plus
# structuredContent: {"result": [...]}; items are unchanged. Installed through the
# public add_transform() API (raises at startup if that API is missing); tools whose
# advertised outputSchema does not admit {"result": [...]} are served unchanged (a stub
# passes through). The redaction wrapper replaces handlers at registration, so it runs
# inside this one.
install_structured_list_results(mcp)


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
mcp.add_middleware(LaneMiddleware())
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

# Protect MCP resources (resources/list, resources/templates/list, resources/read). Each
# read re-enters its backing read tool through call_tool, so every tool control above and
# below applies to it; the listing hides a resource whose backing tool is not exposed.
# In Code Mode a resource read goes through the read broker, as a script read does.
protect_resources.register(
    mcp,
    evaluator=_request_policy,
    broker=lambda: _code_mode_broker.set(True),
)
mcp.add_middleware(relay_policy.RelayBodyPresenceMiddleware())


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

# Opt-in MCP background tasks (UNIFI_BACKGROUND_TASKS=on; off by default): outermost, so
# a client that opts in per request runs the long multi-site reads as a task with every
# middleware above inside it. Off, nothing is installed and every call is unchanged.
background_tasks.install(mcp)


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


def ignored_key_settings(settings: Settings) -> list[str]:
    """The key settings configured (names only) that ``UNIFI_KEY_MODE=header`` ignores."""
    names = [
        name
        for name, present in (
            ("UNIFI_API_KEY", bool(settings.api_key)),
            ("UNIFI_API_KEYS", bool(settings.api_keys)),
        )
        if present
    ]
    return names + settings.configured_key_providers()


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
        ignored = ignored_key_settings(get_settings())
        if ignored:
            logging.getLogger(__name__).warning(
                "UNIFI_KEY_MODE=header: the configured %s are ignored (no key file is read "
                "and no helper is run); every tool call uses only its X-UniFi-Api-Key header",
                "/".join(ignored),
            )
    elif not key_configs:
        print(
            "UNIFI_API_KEY is not set — get a key at https://unifi.ui.com "
            "(Site Manager > API Keys) and set UNIFI_API_KEY or UNIFI_API_KEYS (or read it "
            "from a file or helper with UNIFI_API_KEY_FILE / UNIFI_API_KEY_COMMAND); "
            "see README#1-join-your-fabric-and-create-an-api-key",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        _reconcile_stateless_http()
        _print_startup_warnings(transport)
        # Optional OTLP trace export: process environment only, installed once, after
        # every startup check passed; silent and import-free when no endpoint is set.
        trace_export = configure_trace_export()
        if trace_export.message:
            print(f"unifi-fabric-mcp: {trace_export.message}", file=sys.stderr)
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
    finally:
        # Flush pending spans and stop the exporter (no-op when export is off).
        shutdown_trace_export()


if __name__ == "__main__":
    main()
