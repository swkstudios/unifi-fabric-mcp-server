"""Optional OTLP trace export (docs/CONFIGURATION.md, "Trace export").

In-process tests cover the pure resolver, the failure statuses, the safe-span copy and
an end-to-end tool call through the real server on the simulated upstream. The global
OpenTelemetry provider can be set once per process, so every test that installs the
real pipeline runs in a fresh interpreter against a controlled collector started here
(OTLP/HTTP on a local HTTP server, OTLP/gRPC on a local gRPC server).

Every secret is built at run time; none is a literal in this file.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
import textwrap
import threading
import types
import uuid
from concurrent import futures
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import grpc
import pytest
from fastmcp.exceptions import ToolError
from opentelemetry import trace as trace_api
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2, trace_service_pb2_grpc
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from unifi_fabric import tracing
from unifi_fabric.config import APIKeyConfig

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "unifi_fabric"


def _synthetic(tag: str) -> str:
    return "-".join(("synth", tag, uuid.uuid4().hex))


@pytest.fixture(autouse=True)
def _fresh_trace_state():
    tracing._reset_for_tests()
    tracing.register_component_names((), ())
    yield
    tracing._reset_for_tests()
    tracing.register_component_names((), ())


# ------------------------------------------------------------------ resolver (pure)
HTTP = "http://collector.example:4318"
GRPC = "http://collector.example:4317"


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"OTEL_EXPORTER_OTLP_ENDPOINT": "  "},
        {"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": ""},
        {"OTEL_EXPORTER_OTLP_PROTOCOL": "grpc"},  # a protocol alone configures nothing
        {"OTEL_EXPORTER_OTLP_ENDPOINT": HTTP, "OTEL_SDK_DISABLED": "TRUE"},
        {"OTEL_EXPORTER_OTLP_ENDPOINT": HTTP, "OTEL_TRACES_EXPORTER": "none"},
        {"OTEL_EXPORTER_OTLP_ENDPOINT": HTTP, "OTEL_TRACES_EXPORTER": "otlp, none"},
    ],
)
def test_no_endpoint_or_disabled_resolves_off(env):
    result = tracing.resolve_trace_export(env)
    assert result == tracing.TraceExportResult("off")


@pytest.mark.parametrize(
    ("env", "endpoint", "protocol", "source"),
    [
        # generic endpoint: http/protobuf by default, v1/traces appended
        ({"OTEL_EXPORTER_OTLP_ENDPOINT": HTTP}, f"{HTTP}/v1/traces", "http/protobuf", "generic"),
        (
            {"OTEL_EXPORTER_OTLP_ENDPOINT": HTTP + "/base/"},
            f"{HTTP}/base/v1/traces",
            "http/protobuf",
            "generic",
        ),
        # the traces endpoint is used as given and wins over the generic one
        (
            {
                "OTEL_EXPORTER_OTLP_ENDPOINT": "http://generic.example:4318",
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": HTTP + "/custom/path",
            },
            HTTP + "/custom/path",
            "http/protobuf",
            "traces",
        ),
        # an empty traces endpoint counts as unset
        (
            {"OTEL_EXPORTER_OTLP_ENDPOINT": HTTP, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": " "},
            f"{HTTP}/v1/traces",
            "http/protobuf",
            "generic",
        ),
        # gRPC: no path is appended
        (
            {"OTEL_EXPORTER_OTLP_ENDPOINT": GRPC, "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc"},
            GRPC,
            "grpc",
            "generic",
        ),
        # the traces protocol wins over the generic protocol, both ways
        (
            {
                "OTEL_EXPORTER_OTLP_ENDPOINT": GRPC,
                "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
                "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "grpc",
            },
            GRPC,
            "grpc",
            "generic",
        ),
        (
            {
                "OTEL_EXPORTER_OTLP_ENDPOINT": HTTP,
                "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc",
                "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf",
            },
            f"{HTTP}/v1/traces",
            "http/protobuf",
            "generic",
        ),
        # an explicit otlp exporter selection is accepted
        (
            {"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": HTTP, "OTEL_TRACES_EXPORTER": "otlp"},
            HTTP,
            "http/protobuf",
            "traces",
        ),
    ],
)
def test_endpoint_and_protocol_precedence(env, endpoint, protocol, source):
    result = tracing.resolve_trace_export(env)
    assert isinstance(result, tracing.TraceExportConfig)
    assert result.endpoint == endpoint
    assert result.protocol == protocol
    assert (
        result.endpoint_source
        == {
            "generic": "OTEL_EXPORTER_OTLP_ENDPOINT",
            "traces": "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        }[source]
    )


@pytest.mark.parametrize(
    ("env", "needle"),
    [
        ({"OTEL_EXPORTER_OTLP_PROTOCOL": "http/json"}, "OTEL_EXPORTER_OTLP_PROTOCOL"),
        ({"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "zipkin"}, "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"),
        ({"OTEL_TRACES_EXPORTER": "console"}, "OTEL_TRACES_EXPORTER"),
    ],
)
def test_unsupported_protocol_or_exporter_is_invalid_and_names_only_the_variable(env, needle):
    marker = _synthetic("cfg")
    env = {"OTEL_EXPORTER_OTLP_ENDPOINT": f"http://{marker}.example:4318", **env}
    result = tracing.resolve_trace_export(env)
    assert isinstance(result, tracing.TraceExportResult)
    assert result.status == "invalid"
    assert needle in result.message
    assert marker not in result.message


@pytest.mark.parametrize(
    "template",
    [
        "{m}.example:4318",  # no scheme
        "ftp://{m}.example:4318",
        "http://:4318/{m}",  # no host
        "http://{m}.example:notaport",
        "http://[{m}",
    ],
)
def test_invalid_endpoint_is_reported_without_its_value(template):
    marker = _synthetic("url")
    for var in ("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"):
        result = tracing.resolve_trace_export({var: template.format(m=marker)})
        assert isinstance(result, tracing.TraceExportResult)
        assert result.status == "invalid"
        assert var in result.message
        assert marker not in result.message


@pytest.mark.parametrize(
    ("template", "word"),
    [
        ("https://user:{m}@collector.example:4318/v1/traces", "user information"),
        ("https://{m}@collector.example:4318", "user information"),
        ("https://collector.example:4318/v1/traces?token={m}", "query"),
        ("https://collector.example:4318/v1/traces?", "query"),
        ("https://collector.example:4318/v1/traces#{m}", "fragment"),
        ("https://collector.example:4318/v1/traces#", "fragment"),
    ],
)
def test_endpoint_with_user_info_query_or_fragment_is_refused_without_echo(template, word):
    marker = _synthetic("cred")
    for var in ("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"):
        result = tracing.resolve_trace_export({var: template.format(m=marker)})
        assert isinstance(result, tracing.TraceExportResult)
        assert result.status == "invalid"
        assert var in result.message
        assert word in result.message
        assert marker not in result.message


@pytest.mark.parametrize(
    "url",
    [
        "https://collector.example:4318/v1/traces",
        "http://collector.example",
        "https://collector.example:4318/base/",
        "http://[::1]:4318/v1/traces",
    ],
)
def test_plain_collector_endpoint_is_accepted(url):
    for var in ("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"):
        assert isinstance(tracing.resolve_trace_export({var: url}), tracing.TraceExportConfig)


def test_display_endpoint_never_shows_user_info_path_or_query():
    secret = _synthetic("userinfo")
    shown = tracing.display_endpoint(
        f"https://user:{secret}@otel.example:4318/p/{secret}?k={secret}"
    )
    assert shown == "https://otel.example:4318"
    assert tracing.display_endpoint("http://[::1]:4317") == "http://[::1]:4317"


def test_resolver_and_module_import_load_no_sdk():
    code = textwrap.dedent(
        """
        import sys
        from unifi_fabric import tracing
        tracing.resolve_trace_export({"OTEL_EXPORTER_OTLP_ENDPOINT": "http://h.example:4318"})
        r = tracing.configure_trace_export({})
        print(r.status, any(m.startswith("opentelemetry.sdk") for m in sys.modules))
        """
    )
    out = _run_child(code, {})
    assert out.stdout.split() == ["off", "False"], out.stderr


# ------------------------------------------------------- statuses without the global
@pytest.fixture
def proxy_global(monkeypatch):
    """Keep the in-process tests away from the real global provider."""
    installed: list[Any] = []
    monkeypatch.setattr(trace_api, "get_tracer_provider", lambda: trace_api.ProxyTracerProvider())
    monkeypatch.setattr(trace_api, "set_tracer_provider", installed.append)
    return installed


ON = {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9"}


def test_missing_sdk_is_unavailable_with_install_hint(monkeypatch, proxy_global):
    monkeypatch.setitem(sys.modules, "opentelemetry.sdk.trace", None)
    result = tracing.configure_trace_export(ON)
    assert result.status == "unavailable"
    assert "unifi-fabric-mcp-server[otel]" in result.message
    assert proxy_global == []


@pytest.mark.parametrize(("protocol", "extra"), [("http/protobuf", "otel"), ("grpc", "otel-grpc")])
def test_missing_exporter_is_unavailable_naming_its_extra(
    monkeypatch, proxy_global, protocol, extra
):
    module_name, _ = tracing._EXPORTERS[protocol]
    monkeypatch.setitem(sys.modules, module_name, None)
    result = tracing.configure_trace_export({**ON, "OTEL_EXPORTER_OTLP_PROTOCOL": protocol})
    assert result.status == "unavailable"
    assert f"unifi-fabric-mcp-server[{extra}]" in result.message
    assert proxy_global == []


def test_exporter_setup_failure_is_unavailable_and_sanitized(monkeypatch, proxy_global):
    secret = _synthetic("setup")

    class Exploding:
        def __init__(self, **kwargs: Any) -> None:
            raise ValueError(f"bad header value {secret}")

    fake = types.ModuleType("synthetic_exploding_exporter")
    fake.OTLPSpanExporter = Exploding  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "synthetic_exploding_exporter", fake)
    monkeypatch.setitem(
        tracing._EXPORTERS, "http/protobuf", ("synthetic_exploding_exporter", "otel")
    )
    result = tracing.configure_trace_export(ON)
    assert result.status == "unavailable"
    assert "ValueError" in result.message
    assert secret not in result.message
    assert proxy_global == []


def test_configure_is_once_per_process(monkeypatch, proxy_global):
    first = tracing.configure_trace_export(ON)
    assert first.status == "exporting"
    assert len(proxy_global) == 1
    provider = proxy_global[0]
    assert tracing.configure_trace_export(ON) is first
    assert tracing.configure_trace_export({}) is first  # a later call changes nothing
    assert len(proxy_global) == 1
    processors = provider._active_span_processor._span_processors  # noqa: SLF001
    assert len(processors) == 1
    tracing.shutdown_trace_export()
    tracing.shutdown_trace_export()  # idempotent
    assert tracing.configure_trace_export(ON) is first  # no re-install after shutdown
    assert len(proxy_global) == 1


# --------------------------------------------------------------------- safe spans
def _pipeline() -> tuple[TracerProvider, InMemorySpanExporter, InMemorySpanExporter]:
    safe, raw = InMemorySpanExporter(), InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(tracing.safe_span_processor(SimpleSpanProcessor(safe)))
    provider.add_span_processor(SimpleSpanProcessor(raw))  # negative control
    return provider, safe, raw


def _all_text(span: Any) -> str:
    parts = [span.name, str(dict(span.attributes or {})), str(span.status.description)]
    for event in span.events:
        parts += [event.name, str(dict(event.attributes or {}))]
    for link in span.links:
        parts.append(str(dict(link.attributes or {})))
    return "\n".join(parts)


def test_safe_span_keeps_only_allowlisted_attributes_and_no_free_text(monkeypatch):
    tracing.register_component_names(["list_hosts"], [])
    key = _synthetic("apikey")
    monkeypatch.setenv("UNIFI_API_KEY", key)
    session, client_id, uri = _synthetic("sess"), _synthetic("client"), _synthetic("uri")
    provider, safe, raw = _pipeline()
    tracer = provider.get_tracer("t")
    link_ctx = trace_api.SpanContext(1, 2, is_remote=True)
    with tracer.start_as_current_span(
        f"resources/read resource://x/{uri}",
        kind=SpanKind.SERVER,
        links=[trace_api.Link(link_ctx, {"authorization": key, "error.type": "x"})],
        attributes={
            "mcp.method.name": "resources/read",
            "mcp.resource.uri": f"resource://x/{uri}",
            "mcp.session.id": session,
            "enduser.id": client_id,
            "enduser.scope": "write",
            "http.request.header.authorization": f"Bearer {key}",
            "url.full": f"https://h.example/?apikey={key}",
            "fastmcp.server.name": "UniFi Fabric",
            "fastmcp.component.key": f"resource://x/{uri}",
            "jsonrpc.request.id": 7,
        },
    ) as span:
        try:
            raise RuntimeError(f"upstream said {key} and psk {session}")
        except RuntimeError as exc:
            span.record_exception(exc)
            span.set_status(trace_api.Status(StatusCode.ERROR, f"failed: {key}"))
    with tracer.start_as_current_span(f"GET /proxy?apikey={key}"):
        pass
    provider.shutdown()

    raw_text = "\n".join(_all_text(s) for s in raw.get_finished_spans())
    assert key in raw_text and session in raw_text  # the control did see the secrets
    spans = safe.get_finished_spans()
    assert len(spans) == 2
    mcp_span, other = spans
    assert mcp_span.name == "resources/read"
    assert dict(mcp_span.attributes) == {
        "mcp.method.name": "resources/read",
        "fastmcp.server.name": "UniFi Fabric",
        "jsonrpc.request.id": 7,
    }
    assert mcp_span.status.status_code == StatusCode.ERROR
    assert mcp_span.status.description is None
    assert [dict(e.attributes) for e in mcp_span.events] == [{"exception.type": "RuntimeError"}]
    assert [dict(link.attributes) for link in mcp_span.links] == [{"error.type": "x"}]
    assert mcp_span.context == raw.get_finished_spans()[0].context  # identity unchanged
    assert key not in other.name
    for span in spans:
        text = _all_text(span)
        for secret in (key, session, client_id, uri):
            assert secret not in text


def test_tool_span_name_is_rebuilt_from_the_allowlisted_tool_name():
    tracing.register_component_names(["list_hosts"], [])
    provider, safe, _ = _pipeline()
    with provider.get_tracer("t").start_as_current_span(
        "anything", attributes={"mcp.method.name": "tools/call", "gen_ai.tool.name": "list_hosts"}
    ):
        pass
    assert [s.name for s in safe.get_finished_spans()] == ["tools/call list_hosts"]


def test_a_span_that_cannot_be_copied_is_dropped_not_raised(monkeypatch):
    provider, safe, raw = _pipeline()

    def broken(span: Any) -> Any:
        raise RuntimeError("copy failed")

    monkeypatch.setattr(tracing, "safe_span", broken)
    with provider.get_tracer("t").start_as_current_span("x"):
        pass
    assert safe.get_finished_spans() == ()
    assert len(raw.get_finished_spans()) == 1


# ------------------------------------------- end to end through the real server
@pytest.fixture
def traced_server(monkeypatch):
    """FastMCP's spans for this test go to a local provider through the safe processor."""
    import fastmcp.server.telemetry as server_telemetry

    provider, safe, raw = _pipeline()
    monkeypatch.setattr(
        server_telemetry, "get_tracer", lambda version=None: provider.get_tracer("fastmcp")
    )
    # Direct ``mcp.call_tool`` runs no lifespan, so register the catalog the lifespan would.
    tracing.register_component_names({"list_hosts", *cti._lz_WRITE_TOOLS()}, ())
    yield safe, raw
    provider.shutdown()


async def test_tool_error_with_secrets_reaches_caller_but_no_exported_span(
    monkeypatch, traced_server
):
    safe, raw = traced_server
    key, psk, token = _synthetic("key"), _synthetic("psk"), _synthetic("bearer")
    body = json.dumps(
        {"message": f"denied for {key}", "x_passphrase": psk, "authorization": f"Bearer {token}"}
    )
    up = uh.FakeUpstream(mode="error", error_status=500, error_body=body, error_resolution=True)
    with pytest.raises(Exception) as caught:  # noqa: B017 - the server's own error type
        await cti._call(
            monkeypatch, "list_hosts", up, args={}, keys=[APIKeyConfig(key=key, label="a")]
        )
    # The caller's result is not obscured: the upstream body is passed through.
    assert psk in str(caught.value)
    raw_text = "\n".join(_all_text(s) for s in raw.get_finished_spans())
    assert psk in raw_text  # control: the unfiltered span did carry the payload
    exported = safe.get_finished_spans()
    assert [s.name for s in exported] == ["tools/call list_hosts"]
    assert exported[0].status.status_code == StatusCode.ERROR
    for span in exported:
        text = _all_text(span)
        for secret in (key, psk, token):
            assert secret not in text


def _first_write_tool() -> str:
    return sorted(cti._lz_WRITE_TOOLS())[0]


async def _write_outcome(monkeypatch, name: str, audit_log: Path) -> tuple[str, list[str], list]:
    monkeypatch.setenv("UNIFI_AUDIT_SINK", "file")
    monkeypatch.setenv("UNIFI_AUDIT_LOG", str(audit_log))
    up = uh.FakeUpstream()
    try:
        await cti._call(monkeypatch, name, up)
        outcome = "ok"
    except ToolError as exc:
        outcome = str(exc)
    writes = [s.method for s in up.served if s.method not in ("GET", "HEAD")]
    lines = audit_log.read_text().splitlines() if audit_log.exists() else []
    return outcome, writes, lines


@pytest.mark.parametrize("policy", ["allow", "deny"])
async def test_tracing_changes_no_write_policy_or_audit_record(
    monkeypatch, tmp_path, policy, request
):
    if policy == "deny":
        monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    name = _first_write_tool()
    off = await _write_outcome(monkeypatch, name, tmp_path / "off.jsonl")
    safe, _ = request.getfixturevalue("traced_server")
    on = await _write_outcome(monkeypatch, name, tmp_path / "on.jsonl")
    assert on[0] == off[0]
    assert on[1] == off[1]
    if policy == "deny":
        assert on[1] == []  # tracing cannot bypass the write policy
    else:
        assert on[1], "the write reached the simulated upstream"
    # Audit logging remains functional and identical in shape with tracing on.
    assert len(on[2]) == len(off[2]) and on[2]
    strip = lambda line: {k: v for k, v in json.loads(line).items() if k in ("event", "outcome")}  # noqa: E731
    assert [strip(line) for line in on[2]] == [strip(line) for line in off[2]]
    names = [s.name for s in safe.get_finished_spans()]
    # A denied write is refused by the policy middleware before FastMCP opens the span.
    assert names == ([f"tools/call {name}"] if policy == "allow" else [])


def test_trace_configuration_is_read_only_at_startup():
    """configure_trace_export has exactly one caller, server.main, and the tracing module
    reads no request state (headers, context, tool arguments)."""
    callers = []
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "trace_export" not in text:
            continue
        tree = ast.parse(text)
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for node in ast.walk(fn):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in ("configure_trace_export", "shutdown_trace_export")
                ):
                    callers.append((path.name, fn.name, node.func.id))
    assert sorted(callers) == [
        ("server.py", "main", "configure_trace_export"),
        ("server.py", "main", "shutdown_trace_export"),
    ]
    source = (SRC / "tracing.py").read_text(encoding="utf-8")
    for forbidden in (
        "get_http_headers",
        "get_context",
        "request_ctx",
        "import fastmcp",
        "from fastmcp",
    ):
        assert forbidden not in source


# ------------------------------- caller-supplied text through the real server
def _proto_text(collector: Any) -> str:
    """Every representation the collector received: the decoded protobuf text and the raw
    request bytes (as latin-1, so a literal secret in any field is found)."""
    parts = [str(span) for span in collector.spans()]
    parts += [body.decode("latin-1") for _, _, body in collector.requests]
    return "\n".join(parts)


def _span_text(span: Any) -> str:
    state = span.context.trace_state
    parts = [_all_text(span), str(state), str(span.context), str(span.parent)]
    parts += [str(link.context) for link in span.links]
    return "\n".join(parts)


async def _raw_request(client: Any, method: str, meta: dict[str, str]) -> None:
    """Send a JSON-RPC request with an arbitrary method name through the live session."""
    data: dict[str, Any] = {"method": method, "params": {}}
    options: dict[str, Any] = {}
    client.session._stamp(data, options)
    data["params"].setdefault("_meta", {}).update(meta)
    await client.session._dispatcher.send_raw_request(method, data["params"], options)


async def _exercise_real_server(monkeypatch, collector: Any):
    """Send synthetic secrets through every caller-controlled channel of the real server
    (resource URI, unknown tool/prompt/method names, a tracestate, a string request id)
    and return (secrets, in-memory spans, collector text)."""
    import fastmcp.server.telemetry as server_telemetry
    from fastmcp import Client
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    from unifi_fabric import server

    secrets = {
        "uri": _synthetic("uri"),
        "tool": _synthetic("tool"),
        "prompt": _synthetic("prompt"),
        "method": _synthetic("method"),
        "tracestate": _synthetic("tracestate"),
    }
    memory = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(tracing.safe_span_processor(SimpleSpanProcessor(memory)))
    provider.add_span_processor(
        tracing.safe_span_processor(
            SimpleSpanProcessor(OTLPSpanExporter(endpoint=f"{collector.url}/v1/traces"))
        )
    )
    monkeypatch.setattr(
        server_telemetry, "get_tracer", lambda version=None: provider.get_tracer("fastmcp")
    )
    uh.install(monkeypatch, uh.FakeUpstream())
    meta = {"traceparent": "00-" + "1" * 32 + "-" + "2" * 16 + "-01"}
    meta["tracestate"] = f"vendor={secrets['tracestate']}"
    async with Client(server.mcp) as client:
        listed = {tool.name for tool in await client.list_tools()}
        assert "search_tools" in listed
        await client.call_tool_mcp("search_tools", {"query": "hosts"}, meta=meta)
        await client.call_tool_mcp(secrets["tool"], {}, meta=meta)
        for call in (
            lambda: client.get_prompt_mcp(secrets["prompt"], {}, meta=meta),
            lambda: client.read_resource_mcp(f"resource://{secrets['uri']}/x", meta=meta),
            lambda: _raw_request(client, secrets["method"], meta),
        ):
            try:
                await call()
            except Exception:  # noqa: BLE001 - not-found is the expected outcome
                pass
    provider.force_flush()
    provider.shutdown()
    return secrets, list(memory.get_finished_spans()), _proto_text(collector)


async def test_caller_supplied_text_never_leaves_the_process_through_the_real_server(
    monkeypatch, http_collector
):
    secrets, spans, collected = await _exercise_real_server(monkeypatch, http_collector)
    names = [s.name for s in spans]
    assert "tools/call search_tools" in names  # known, registered names still export
    assert any(s.attributes.get("mcp.method.name") == "unknown" for s in spans)
    assert http_collector.requests, "the collector received no export"
    for span in spans:
        text = _span_text(span)
        for label, secret in secrets.items():
            assert secret not in text, f"{label} leaked into {span.name!r}"
        assert "fastmcp.component.key" not in (span.attributes or {})
        assert not span.context.trace_state
    for label, secret in secrets.items():
        assert secret not in collected, f"{label} reached the collector"
        assert secret.encode() not in b"".join(b for _, _, b in http_collector.requests)


async def test_negative_control_filter_disabled_leaks_every_channel(monkeypatch, http_collector):
    """With the guards off (allowlist membership only, tracestate kept) each synthetic
    secret reaches the collector, so the test above is able to fail."""
    monkeypatch.setattr(
        tracing,
        "_safe_attributes",
        lambda attributes: {
            k: v
            for k, v in (attributes or {}).items()
            if k in tracing.SAFE_SPAN_ATTRIBUTES | {"fastmcp.component.key"}
        },
    )
    monkeypatch.setattr(tracing, "_without_trace_state", lambda context: context)
    tracing.register_component_names([_synthetic("unused")], [])
    secrets, _, collected = await _exercise_real_server(monkeypatch, http_collector)
    for label in ("uri", "method", "tracestate"):
        assert secrets[label] in collected, f"control: {label} should leak when unfiltered"


def test_jsonrpc_request_id_is_exported_only_when_an_integer():
    attrs = tracing._safe_attributes
    assert attrs({"jsonrpc.request.id": 7}) == {"jsonrpc.request.id": 7}
    for value in ("7", _synthetic("id"), 1.5, True, None):
        assert attrs({"jsonrpc.request.id": value}) == {}


def test_unknown_method_tool_and_prompt_names_are_masked_in_names_and_attributes():
    tracing.register_component_names(["list_hosts"], ["a_prompt"])
    secret = _synthetic("name")
    provider, safe, _ = _pipeline()
    tracer = provider.get_tracer("t")
    with tracer.start_as_current_span(
        f"{secret} {secret}", attributes={"mcp.method.name": secret, "gen_ai.tool.name": secret}
    ):
        pass
    with tracer.start_as_current_span(
        "x", attributes={"mcp.method.name": "tools/call", "gen_ai.tool.name": secret}
    ):
        pass
    with tracer.start_as_current_span(
        "x", attributes={"mcp.method.name": "prompts/get", "gen_ai.prompt.name": "a_prompt"}
    ):
        pass
    first, second, third = safe.get_finished_spans()
    assert (first.name, dict(first.attributes)) == ("unknown", {"mcp.method.name": "unknown"})
    assert (second.name, dict(second.attributes)) == (
        "tools/call",
        {"mcp.method.name": "tools/call"},
    )
    assert third.name == "prompts/get a_prompt"


# ------------------------------------------- controlled collectors (fresh processes)
class _HTTPCollector:
    def __init__(self, status: int = 200) -> None:
        self.requests: list[tuple[str, str, bytes]] = []
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server API
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                collector.requests.append((self.path, self.headers.get("Content-Type", ""), body))
                self.send_response(status)
                self.send_header("Content-Type", "application/x-protobuf")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def spans(self) -> list[Any]:
        out = []
        for _, _, body in self.requests:
            req = trace_service_pb2.ExportTraceServiceRequest.FromString(body)
            out += _proto_spans(req)
        return out

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class _GRPCCollector:
    def __init__(self) -> None:
        self.requests: list[Any] = []
        collector = self

        class Servicer(trace_service_pb2_grpc.TraceServiceServicer):
            def Export(self, request: Any, context: Any) -> Any:  # noqa: N802 - gRPC API
                collector.requests.append(request)
                return trace_service_pb2.ExportTraceServiceResponse()

        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
        trace_service_pb2_grpc.add_TraceServiceServicer_to_server(Servicer(), self.server)
        port = self.server.add_insecure_port("127.0.0.1:0")
        self.server.start()
        self.url = f"http://127.0.0.1:{port}"

    def spans(self) -> list[Any]:
        return [s for req in self.requests for s in _proto_spans(req)]

    def close(self) -> None:
        self.server.stop(None)


def _proto_spans(req: Any) -> list[dict[str, Any]]:
    out = []
    for rs in req.resource_spans:
        resource = {a.key: a.value.string_value for a in rs.resource.attributes}
        for ss in rs.scope_spans:
            for span in ss.spans:
                out.append(
                    {
                        "name": span.name,
                        "span_id": span.span_id.hex(),
                        "attributes": {a.key for a in span.attributes},
                        "resource": resource,
                        "text": str(span),
                    }
                )
    return out


@pytest.fixture
def http_collector():
    collector = _HTTPCollector()
    yield collector
    collector.close()


@pytest.fixture
def grpc_collector():
    collector = _GRPCCollector()
    yield collector
    collector.close()


CHILD = textwrap.dedent(
    """
    import asyncio, json, sys
    from unifi_fabric import tracing

    APP, QUERY, META_URL = sys.argv[1], sys.argv[2], sys.argv[3]

    def probe_app():
        # FastMCP opens the same per-request spans for any app; a one-tool app keeps the
        # collector cases fast. The real server is driven by the surface and stdio tests.
        from fastmcp import FastMCP
        app = FastMCP("probe")

        @app.tool
        def search_tools(query: str) -> str:
            return "result:" + query

        return app

    async def run():
        from fastmcp import Client
        tracing.register_component_names(["search_tools"], [])
        first = tracing.configure_trace_export()
        second = tracing.configure_trace_export()
        from opentelemetry import trace
        provider = trace.get_tracer_provider()
        processors = getattr(getattr(provider, "_active_span_processor", None),
                             "_span_processors", ())
        async with Client(probe_app()) as client:
            tools = await client.list_tools()
            result = await client.call_tool(
                "search_tools", {"query": QUERY},
                meta={"traceparent": "00-" + "1" * 32 + "-" + "2" * 16 + "-01",
                      "OTEL_EXPORTER_OTLP_ENDPOINT": META_URL})
        with trace.get_tracer("child").start_as_current_span("last-before-shutdown"):
            pass
        tracing.shutdown_trace_export()
        tracing.shutdown_trace_export()
        print(json.dumps({
            "first": [first.status, first.message], "same": first is second,
            "provider": type(provider).__name__, "processors": len(processors),
            "sdk_loaded": any(m.startswith("opentelemetry.sdk") for m in sys.modules),
            "tools": sorted(t.name for t in tools), "result": result.data,
        }))

    asyncio.run(run())
    """
)


def _run_child(code: str, env: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    base = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(ROOT / "src"),
        "UNIFI_API_KEY": _synthetic("childkey"),
        # Bound a failing exporter's retries so a failure case ends promptly.
        "OTEL_EXPORTER_OTLP_TIMEOUT": "2",
    }
    return subprocess.run(  # noqa: S603 - fixed interpreter, synthetic environment
        [sys.executable, "-c", code, *args],
        env={**base, **env},
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def _report(out: subprocess.CompletedProcess) -> dict[str, Any]:
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def _child(env: dict[str, str], query: str = "hosts", meta_url: str = "") -> dict[str, Any]:
    return _report(_run_child(CHILD, env, "probe", query, meta_url or "http://127.0.0.1:9"))


def _names(spans: list[dict[str, Any]]) -> list[str]:
    return sorted(s["name"] for s in spans)


def test_http_collector_receives_each_span_exactly_once_at_the_default_path(http_collector):
    report = _child({"OTEL_EXPORTER_OTLP_ENDPOINT": http_collector.url})
    assert report["first"][0] == "exporting"
    assert "OTLP http/protobuf to http://127.0.0.1:" in report["first"][1]
    assert report["same"] is True
    assert report["provider"] == "TracerProvider" and report["processors"] == 1
    assert report["result"] == "result:hosts"
    assert {path for path, _, _ in http_collector.requests} == {"/v1/traces"}
    assert {ctype for _, ctype, _ in http_collector.requests} == {"application/x-protobuf"}
    spans = http_collector.spans()
    names = _names(spans)
    assert "tools/call search_tools" in names
    assert "tools/list" in names
    assert "last-before-shutdown" in names  # pending work was flushed at shutdown
    ids = [s["span_id"] for s in spans]
    assert len(ids) == len(set(ids))  # no span exported twice
    resource = spans[0]["resource"]
    assert resource["service.name"] == "unifi-fabric-mcp-server"
    for span in spans:
        assert span["attributes"] <= tracing.SAFE_SPAN_ATTRIBUTES


def test_traces_endpoint_wins_and_is_used_verbatim(http_collector):
    other = _HTTPCollector()
    try:
        report = _child(
            {
                "OTEL_EXPORTER_OTLP_ENDPOINT": other.url,
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": http_collector.url + "/custom/traces",
            }
        )
        assert report["first"][0] == "exporting"
        assert "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT" in report["first"][1]
        assert other.requests == []
        assert {path for path, _, _ in http_collector.requests} == {"/custom/traces"}
    finally:
        other.close()


def test_grpc_protocol_selection_and_traces_protocol_precedence(grpc_collector, http_collector):
    report = _child(
        {
            "OTEL_EXPORTER_OTLP_ENDPOINT": grpc_collector.url,
            "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
            "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "grpc",
        }
    )
    assert report["first"][0] == "exporting"
    assert "OTLP grpc" in report["first"][1]
    names = _names(grpc_collector.spans())
    assert "tools/call search_tools" in names and "last-before-shutdown" in names
    ids = [s["span_id"] for s in grpc_collector.spans()]
    assert len(ids) == len(set(ids))
    for span in grpc_collector.spans():
        assert span["attributes"] <= tracing.SAFE_SPAN_ATTRIBUTES
    assert http_collector.requests == []


def test_no_endpoint_creates_no_pipeline_and_no_collector_traffic(http_collector):
    """Also a request cannot select a collector: the tool arguments and the request
    ``_meta`` name the collector, and nothing is sent to it."""
    report = _child({}, query=http_collector.url, meta_url=http_collector.url)
    assert report["first"] == ["off", ""]
    assert report["provider"] == "ProxyTracerProvider" and report["processors"] == 0
    assert report["sdk_loaded"] is False
    assert report["result"] == "result:" + http_collector.url
    assert http_collector.requests == []


SURFACE_CHILD = textwrap.dedent(
    """
    import asyncio, json, sys
    from fastmcp import Client
    from unifi_fabric import server, tracing

    def surface(tools):
        return sorted((t.name, bool(t.annotations and t.annotations.readOnlyHint))
                      for t in tools)

    async def session(meta_url):
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            await client.call_tool(
                "search_tools", {"query": meta_url},
                meta={"OTEL_EXPORTER_OTLP_ENDPOINT": meta_url,
                      "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": meta_url})
        return surface(tools)

    async def run():
        before = await session(sys.argv[1])
        sdk_before = any(m.startswith("opentelemetry.sdk") for m in sys.modules)
        status = tracing.configure_trace_export().status
        after = await session(sys.argv[1])
        tracing.shutdown_trace_export()
        print(json.dumps({"before": before, "after": after, "status": status,
                          "sdk_before": sdk_before}))

    asyncio.run(run())
    """
)


def test_real_server_tool_surface_and_request_meta_cannot_select_a_collector(http_collector):
    """The real server: the advertised tools and their read-only annotations are the same
    before and after trace export starts, and a request naming another collector in its
    arguments and ``_meta`` reaches nothing (no SDK before startup configuration)."""
    decoy = _HTTPCollector()
    try:
        report = _report(
            _run_child(
                SURFACE_CHILD, {"OTEL_EXPORTER_OTLP_ENDPOINT": http_collector.url}, decoy.url
            )
        )
    finally:
        decoy.close()
    assert report["status"] == "exporting"
    assert report["sdk_before"] is False
    assert report["after"] == report["before"] and report["before"]
    assert decoy.requests == []
    names = _names(http_collector.spans())
    assert "tools/call search_tools" in names and "tools/list" in names
    for span in http_collector.spans():
        assert span["attributes"] <= tracing.SAFE_SPAN_ATTRIBUTES


def test_existing_provider_is_left_in_place(http_collector):
    code = (
        "from opentelemetry import trace\n"
        "from opentelemetry.sdk.trace import TracerProvider\n"
        "trace.set_tracer_provider(TracerProvider())\n" + CHILD
    )
    env = {"OTEL_EXPORTER_OTLP_ENDPOINT": http_collector.url}
    report = _report(_run_child(code, env, "probe", "x", "http://127.0.0.1:9"))
    assert report["first"][0] == "existing-provider"
    assert report["processors"] == 0  # nothing added to the operator's provider
    assert report["result"] == "result:x"
    assert http_collector.requests == []


@pytest.mark.parametrize("failure", ["refused", "http-500"])
def test_exporter_failure_does_not_affect_tool_results(failure):
    if failure == "refused":
        with ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler) as probe:
            url = f"http://127.0.0.1:{probe.server_address[1]}"  # closed once released
        collector = None
    else:
        collector = _HTTPCollector(status=500)
        url = collector.url
    try:
        report = _child({"OTEL_EXPORTER_OTLP_ENDPOINT": url})
    finally:
        if collector is not None:
            collector.close()
    assert report["first"][0] == "exporting"
    assert report["result"] == "result:hosts"  # the tool result is unaffected
    if collector is not None:
        assert collector.requests  # the export was attempted and refused


STDIO_CHILD = textwrap.dedent(
    """
    import importlib.abc, sys

    class Block(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name.startswith(("opentelemetry.sdk", "opentelemetry.exporter")):
                raise ImportError(name)
            return None

    sys.meta_path.insert(0, Block())
    sys.argv = ["unifi-fabric-mcp"]
    from unifi_fabric.entrypoint import main
    main()
    """
)


async def test_server_starts_and_serves_without_optional_packages(tmp_path, http_collector):
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport

    script = tmp_path / "server_without_sdk.py"
    script.write_text(STDIO_CHILD, encoding="utf-8")
    log = tmp_path / "stderr.log"
    transport = StdioTransport(
        command=sys.executable,
        args=[str(script)],
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": str(ROOT / "src"),
            "UNIFI_API_KEY": _synthetic("stdiokey"),
            "OTEL_EXPORTER_OTLP_ENDPOINT": http_collector.url,
        },
        cwd=str(ROOT),
        keep_alive=False,
        log_file=log,
    )
    async with Client(transport) as client:
        tools = await client.list_tools()
        result = await client.call_tool("search_tools", {"query": "hosts"})
    assert tools and not result.is_error
    stderr = log.read_text(encoding="utf-8")
    assert "trace export is off" in stderr
    assert "unifi-fabric-mcp-server[otel]" in stderr
    assert "Traceback" not in stderr
    assert http_collector.requests == []
