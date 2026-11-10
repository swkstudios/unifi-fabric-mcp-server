"""Optional OTLP trace export for the MCP server's own spans.

FastMCP and the MCP SDK open a span for every inbound MCP request through the
OpenTelemetry API alone, so without an SDK ``TracerProvider`` those spans are no-ops.
This module installs a provider with an OTLP span exporter when, and only when, the
operator configures an OTLP endpoint in the process environment at startup:

* ``OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`` (used as given) wins over
  ``OTEL_EXPORTER_OTLP_ENDPOINT`` (a base URL; ``v1/traces`` is appended for HTTP).
* ``OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`` wins over ``OTEL_EXPORTER_OTLP_PROTOCOL``;
  ``http/protobuf`` (the default) or ``grpc``.
* ``OTEL_SDK_DISABLED=true`` or ``OTEL_TRACES_EXPORTER=none`` turns export off.

Without an endpoint nothing is imported beyond this module: no SDK, no exporter, no
provider and no collector connection, whether or not the optional packages are
installed. The SDK reads the other standard ``OTEL_*`` variables itself (headers,
timeout, compression, certificates, sampler, resource attributes).

Every finished span passes through :class:`SafeSpanProcessor` before export: only the
attributes in :data:`SAFE_SPAN_ATTRIBUTES` are kept, MCP span names are rebuilt from
those attributes, and free text (status descriptions, exception messages, stack
traces) is never exported. Trace configuration is trusted operator startup
configuration: no tool argument or request header reaches it, and it changes no tool
list, annotation, authorization or write policy.

Design reference: the OpenTelemetry OTLP exporter specification and the conditional
provider setup in sirkirby/unifi-mcp (MIT); this is an independent implementation.
"""

from __future__ import annotations

import importlib
import os
import re
import sys
import threading
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

#: Status values reported by :func:`configure_trace_export`.
TraceExportStatus = Literal["off", "exporting", "existing-provider", "unavailable", "invalid"]

TRACES_ENDPOINT_VAR = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
ENDPOINT_VAR = "OTEL_EXPORTER_OTLP_ENDPOINT"
TRACES_PROTOCOL_VAR = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"
PROTOCOL_VAR = "OTEL_EXPORTER_OTLP_PROTOCOL"
SDK_DISABLED_VAR = "OTEL_SDK_DISABLED"
TRACES_EXPORTER_VAR = "OTEL_TRACES_EXPORTER"

DEFAULT_PROTOCOL = "http/protobuf"
#: Path the OTLP/HTTP specification appends to the generic endpoint for traces.
HTTP_TRACES_PATH = "v1/traces"
SERVICE_NAME = "unifi-fabric-mcp-server"

#: protocol -> (exporter module, extra that installs it).
_EXPORTERS: dict[str, tuple[str, str]] = {
    "http/protobuf": ("opentelemetry.exporter.otlp.proto.http.trace_exporter", "otel"),
    "grpc": ("opentelemetry.exporter.otlp.proto.grpc.trace_exporter", "otel-grpc"),
}

#: The only span, event and link attributes that are exported. Everything else -- the
#: caller identity (``enduser.*``), the MCP session id, resource URIs, URLs, headers and
#: anything another instrumentation library adds -- is dropped before export.
SAFE_SPAN_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "mcp.method.name",
        "mcp.protocol.version",
        "gen_ai.operation.name",
        "gen_ai.tool.name",
        "gen_ai.prompt.name",
        "jsonrpc.request.id",
        "error.type",
        "rpc.response.status_code",
        "fastmcp.server.name",
        "fastmcp.component.type",
        "fastmcp.provider.type",
        "fastmcp.span.seam",
        # Exception events keep their type only; message and stack trace are dropped.
        "exception.type",
    }
)

_MASK_NAME = "span"

#: Placeholder exported in place of a caller-supplied value that is not in a closed set.
UNKNOWN = "unknown"

#: The JSON-RPC methods of the MCP specification. FastMCP opens a request's span with the
#: caller's raw method before looking it up, so any other value is caller text and is
#: exported as :data:`UNKNOWN`.
KNOWN_METHODS: frozenset[str] = frozenset(
    {
        "initialize",
        "ping",
        "server/discover",
        "tools/list",
        "tools/call",
        "prompts/list",
        "prompts/get",
        "resources/list",
        "resources/templates/list",
        "resources/read",
        "resources/subscribe",
        "resources/unsubscribe",
        "completion/complete",
        "logging/setLevel",
        "roots/list",
        "sampling/createMessage",
        "elicitation/create",
        "tasks/get",
        "tasks/result",
        "tasks/list",
        "tasks/cancel",
        "notifications/initialized",
        "notifications/cancelled",
        "notifications/progress",
        "notifications/message",
        "notifications/roots/list_changed",
        "notifications/resources/list_changed",
        "notifications/resources/updated",
        "notifications/tools/list_changed",
        "notifications/prompts/list_changed",
        "notifications/tasks/status",
    }
)

_PROTOCOL_VERSION = re.compile(r"\d{4}-\d{2}-\d{2}")

_names_lock = threading.Lock()
_registered_tools: frozenset[str] = frozenset()
_registered_prompts: frozenset[str] = frozenset()


def register_component_names(tools: Iterable[str], prompts: Iterable[str]) -> None:
    """Record the server's registered tool and prompt names (the closed set).

    Only these names are ever exported in ``gen_ai.tool.name`` / ``gen_ai.prompt.name``
    and span names; a name a caller invents is dropped. Until names are registered
    nothing is exported for them (fail closed).
    """
    global _registered_tools, _registered_prompts
    with _names_lock:
        _registered_tools = frozenset(tools)
        _registered_prompts = frozenset(prompts)


@dataclass(frozen=True)
class TraceExportConfig:
    """The resolved export target: ``endpoint`` is what the exporter is given."""

    endpoint: str
    protocol: str
    endpoint_source: str

    @property
    def display_endpoint(self) -> str:
        """``scheme://host[:port]`` only: never the path, query, user info or headers."""
        return display_endpoint(self.endpoint)


@dataclass(frozen=True)
class TraceExportResult:
    """Outcome of :func:`configure_trace_export`; ``message`` is safe to print."""

    status: TraceExportStatus
    message: str = ""

    @property
    def exporting(self) -> bool:
        return self.status == "exporting"


def _value(environ: Mapping[str, str], name: str) -> str:
    """An environment value, stripped; an empty value counts as unset (OTel spec)."""
    return str(environ.get(name, "") or "").strip()


def display_endpoint(url: str) -> str:
    """Render an endpoint as ``scheme://host[:port]`` without user info, path or query."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return "<invalid endpoint>"
    if not parts.scheme or not host:
        return "<invalid endpoint>"
    if ":" in host:
        host = f"[{host}]"
    return f"{parts.scheme}://{host}" + (f":{port}" if port is not None else "")


def _endpoint_problem(url: str) -> str | None:
    try:
        parts = urlsplit(url)
        host = parts.hostname
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return "is not a valid URL"
    if parts.scheme not in ("http", "https"):
        return "must be an http:// or https:// URL"
    if not host:
        return "has no host"
    # The SDK logs the endpoint on every failed export and the log scrubber does not know
    # it, so a credential or token in the URL would leak. Collector credentials belong in
    # OTEL_EXPORTER_OTLP_HEADERS.
    if "@" in parts.netloc:
        return (
            "must not contain user information in the URL "
            "(put collector credentials in OTEL_EXPORTER_OTLP_HEADERS)"
        )
    if parts.query or "?" in url:
        return "must not contain a query string"
    if parts.fragment or "#" in url:
        return "must not contain a fragment"
    return None


def _http_signal_url(base: str) -> str:
    return base + HTTP_TRACES_PATH if base.endswith("/") else f"{base}/{HTTP_TRACES_PATH}"


def resolve_trace_export(
    environ: Mapping[str, str] | None = None,
) -> TraceExportConfig | TraceExportResult:
    """Resolve the trace export target from the process environment.

    Returns a :class:`TraceExportConfig` when export is configured, otherwise a
    :class:`TraceExportResult` with status ``off`` (nothing configured, or disabled)
    or ``invalid`` (a configured value that cannot be used; the message names the
    variable, never its value). Pure: reads only ``environ`` and imports nothing.
    """
    env = os.environ if environ is None else environ
    if _value(env, SDK_DISABLED_VAR).lower() == "true":
        return TraceExportResult("off")
    exporters = {
        item.strip().lower() for item in _value(env, TRACES_EXPORTER_VAR).split(",") if item.strip()
    }
    if "none" in exporters:
        return TraceExportResult("off")

    endpoint_source = next(
        (name for name in (TRACES_ENDPOINT_VAR, ENDPOINT_VAR) if _value(env, name)), None
    )
    if endpoint_source is None:
        return TraceExportResult("off")
    if exporters and "otlp" not in exporters:
        return TraceExportResult(
            "invalid",
            f"trace export is off: {TRACES_EXPORTER_VAR} names no 'otlp' exporter "
            "(this server exports traces only over OTLP)",
        )

    protocol_source = next(
        (name for name in (TRACES_PROTOCOL_VAR, PROTOCOL_VAR) if _value(env, name)), None
    )
    protocol = _value(env, protocol_source) if protocol_source else DEFAULT_PROTOCOL
    if protocol not in _EXPORTERS:
        return TraceExportResult(
            "invalid",
            f"trace export is off: unsupported {protocol_source} (use http/protobuf or grpc)",
        )

    raw = _value(env, endpoint_source)
    problem = _endpoint_problem(raw)
    if problem is not None:
        return TraceExportResult("invalid", f"trace export is off: {endpoint_source} {problem}")
    endpoint = raw
    if protocol == "http/protobuf" and endpoint_source == ENDPOINT_VAR:
        endpoint = _http_signal_url(raw)
    return TraceExportConfig(endpoint=endpoint, protocol=protocol, endpoint_source=endpoint_source)


def _safe_attributes(attributes: Mapping[str, Any] | None) -> dict[str, Any]:
    """Keep allowlisted keys, and of those only values that are not caller text.

    FastMCP fills the method, tool/prompt name and protocol version from the request
    before any lookup, so each is checked against its closed set; the JSON-RPC id is
    exported only when it is an integer.
    """
    if not attributes:
        return {}
    out = {key: value for key, value in attributes.items() if key in SAFE_SPAN_ATTRIBUTES}
    if "mcp.method.name" in out and out["mcp.method.name"] not in KNOWN_METHODS:
        out["mcp.method.name"] = UNKNOWN
    if "gen_ai.tool.name" in out and out["gen_ai.tool.name"] not in _registered_tools:
        del out["gen_ai.tool.name"]
    if "gen_ai.prompt.name" in out and out["gen_ai.prompt.name"] not in _registered_prompts:
        del out["gen_ai.prompt.name"]
    request_id = out.get("jsonrpc.request.id")
    if "jsonrpc.request.id" in out and (
        isinstance(request_id, bool) or not isinstance(request_id, int)
    ):
        del out["jsonrpc.request.id"]
    version = out.get("mcp.protocol.version")
    if "mcp.protocol.version" in out and not (
        isinstance(version, str) and _PROTOCOL_VERSION.fullmatch(version)
    ):
        out["mcp.protocol.version"] = UNKNOWN
    return out


def _without_trace_state(context: Any) -> Any:
    """A copy of a span context with an empty ``tracestate``: the caller's value, which
    the server span inherits, is free text and is never exported."""
    from opentelemetry.trace import SpanContext, TraceState

    if context is None:
        return None
    return SpanContext(
        trace_id=context.trace_id,
        span_id=context.span_id,
        is_remote=context.is_remote,
        trace_flags=context.trace_flags,
        trace_state=TraceState(),
    )


def _safe_name(name: str, attributes: Mapping[str, Any]) -> str:
    """An MCP span is renamed from its allowlisted attributes (FastMCP names a resource
    span after its URI); any other span keeps its name with configured secrets masked."""
    method = attributes.get("mcp.method.name")
    if isinstance(method, str) and method:
        if method == UNKNOWN:
            return method
        target = attributes.get("gen_ai.tool.name") or attributes.get("gen_ai.prompt.name")
        return f"{method} {target}" if isinstance(target, str) and target else method
    from .secret_scrub import configured_secrets, scrub_log_text

    return scrub_log_text(name, configured_secrets()) or _MASK_NAME


def safe_span(span: Any) -> Any:
    """Return an export copy of a finished SDK span that carries only safe data.

    Attributes, event attributes and link attributes are reduced to
    :data:`SAFE_SPAN_ATTRIBUTES`; the status keeps its code and drops its description;
    identity (trace/span ids, parent, kind, timing, resource and scope) is unchanged
    except that ``tracestate`` is emptied. Caller-supplied values (method, tool and
    prompt names, protocol version, request id) are exported only from closed sets.
    """
    from opentelemetry.sdk.trace import Event, ReadableSpan
    from opentelemetry.trace import Link, Status

    attributes = _safe_attributes(span.attributes)
    events = [
        Event(event.name, _safe_attributes(event.attributes), event.timestamp)
        for event in span.events
    ]
    links = [
        Link(_without_trace_state(link.context), _safe_attributes(link.attributes))
        for link in span.links
    ]
    return ReadableSpan(
        name=_safe_name(span.name, attributes),
        context=_without_trace_state(span.context),
        parent=_without_trace_state(span.parent),
        resource=span.resource,
        attributes=attributes,
        events=events,
        links=links,
        kind=span.kind,
        status=Status(span.status.status_code),
        start_time=span.start_time,
        end_time=span.end_time,
        instrumentation_scope=span.instrumentation_scope,
    )


def _safe_span_processor_class() -> type:
    from opentelemetry.sdk.trace import SpanProcessor

    class SafeSpanProcessor(SpanProcessor):
        """Hand the wrapped processor a :func:`safe_span` copy of every finished span.

        ``on_end`` runs synchronously where the span ends (the request's context), so
        the copy is made before any export thread sees the span.
        """

        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def on_start(self, span: Any, parent_context: Any = None) -> None:
            self._inner.on_start(span, parent_context=parent_context)

        def on_end(self, span: Any) -> None:
            # Never let the copy fail the request that ended the span: a span that
            # cannot be copied safely is not exported.
            try:
                copy = safe_span(span)
            except Exception:  # noqa: BLE001
                return
            self._inner.on_end(copy)

        def shutdown(self) -> None:
            self._inner.shutdown()

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return bool(self._inner.force_flush(timeout_millis))

    return SafeSpanProcessor


def safe_span_processor(inner: Any) -> Any:
    """Wrap a span processor so it only ever receives :func:`safe_span` copies."""
    return _safe_span_processor_class()(inner)


def _version() -> str:
    try:
        from importlib.metadata import version

        return version(SERVICE_NAME)
    except Exception:  # pragma: no cover - packaging-metadata absence is rare
        return "unknown"


def _resource(environ: Mapping[str, str]) -> Any:
    """Service name/version defaults; ``OTEL_SERVICE_NAME`` and
    ``OTEL_RESOURCE_ATTRIBUTES`` (operator configuration) win."""
    from opentelemetry.sdk.resources import OTELResourceDetector, Resource

    attributes: dict[str, Any] = {"service.name": SERVICE_NAME, "service.version": _version()}
    attributes.update(OTELResourceDetector().detect().attributes)
    return Resource.create(attributes)


_lock = threading.Lock()
_result: TraceExportResult | None = None
_provider: Any = None


def configure_trace_export(environ: Mapping[str, str] | None = None) -> TraceExportResult:
    """Install the OTLP trace pipeline once per process, if configured.

    Idempotent: a second call (also after :func:`shutdown_trace_export`) returns the
    first call's result and installs nothing. Never raises for configuration, missing
    packages or exporter construction; those return ``invalid``/``unavailable`` with a
    printable message and the server runs without trace export. An already installed
    SDK provider is left in place (``existing-provider``).
    """
    global _result, _provider
    with _lock:
        if _result is not None:
            return _result
        env = os.environ if environ is None else environ
        resolved = resolve_trace_export(env)
        if isinstance(resolved, TraceExportResult):
            _result = resolved
            return _result
        _result, _provider = _install(resolved, env)
        return _result


def _install(
    config: TraceExportConfig, environ: Mapping[str, str]
) -> tuple[TraceExportResult, Any]:
    module_name, extra = _EXPORTERS[config.protocol]
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        return (
            TraceExportResult(
                "unavailable",
                "trace export is off: an OTLP endpoint is set but the OpenTelemetry SDK is "
                "not installed (install unifi-fabric-mcp-server[otel], or [otel-grpc] for gRPC)",
            ),
            None,
        )
    try:
        exporter_class = importlib.import_module(module_name).OTLPSpanExporter
    except ImportError:
        return (
            TraceExportResult(
                "unavailable",
                f"trace export is off: protocol {config.protocol} needs the OTLP exporter "
                f"from unifi-fabric-mcp-server[{extra}], which is not installed",
            ),
            None,
        )
    if not isinstance(trace.get_tracer_provider(), trace.ProxyTracerProvider):
        return (
            TraceExportResult(
                "existing-provider",
                "trace export: a tracer provider is already installed; spans go to it and "
                "this server adds no exporter",
            ),
            None,
        )
    try:
        provider = TracerProvider(resource=_resource(environ))
        provider.add_span_processor(
            safe_span_processor(BatchSpanProcessor(exporter_class(endpoint=config.endpoint)))
        )
    except Exception as exc:  # noqa: BLE001 - any setup failure leaves export off
        return (
            TraceExportResult(
                "unavailable",
                f"trace export is off: exporter setup failed ({type(exc).__name__})",
            ),
            None,
        )
    trace.set_tracer_provider(provider)
    return (
        TraceExportResult(
            "exporting",
            f"trace export: OTLP {config.protocol} to {config.display_endpoint} "
            f"(from {config.endpoint_source})",
        ),
        provider,
    )


def shutdown_trace_export() -> None:
    """Flush pending spans and shut the installed provider down; at most once."""
    global _provider
    with _lock:
        provider, _provider = _provider, None
    if provider is not None:
        try:
            provider.shutdown()
        except Exception as exc:  # noqa: BLE001 - shutdown never masks the exit path
            print(
                f"unifi-fabric-mcp: trace export shutdown failed ({type(exc).__name__})",
                file=sys.stderr,
            )


def trace_export_result() -> TraceExportResult | None:
    """The result of the first :func:`configure_trace_export` call, if any."""
    return _result


def _reset_for_tests() -> None:
    """Forget the process state (tests only; the global OTel provider is not reset)."""
    global _result, _provider
    with _lock:
        _result = None
        _provider = None


__all__: Sequence[str] = (
    "SAFE_SPAN_ATTRIBUTES",
    "TraceExportConfig",
    "TraceExportResult",
    "configure_trace_export",
    "display_endpoint",
    "register_component_names",
    "resolve_trace_export",
    "safe_span",
    "safe_span_processor",
    "shutdown_trace_export",
    "trace_export_result",
)
