"""Header-credential contract: header mode credentials, request context, transport and cache.

Covers:

* ``X-UniFi-Api-Key`` parsing (duplicate raw labels, malformed, empty, repeated header);
* the ingress pre-dispatch refusals in the closed order, with zero upstream calls;
* environment mode: a tools/call carrying the header refuses; tools/list never reads it;
* request order, host resolution over request labels (the baseline resolve_key_for_host
  rule unchanged), host-less selection (fan-out set vs credentials[0]);
* the identity/cache matrix: (label, full key digest) identity, synthetic 8-hex
  prefix collisions, the 256-identity bound with saturation, retry after release,
  close-once eviction, cancellation and shutdown;
* the synthetic leak matrix: no key, full key digest or raw header value in results,
  errors, refusals, reprs or log records; only 8-hex fingerprints;
* concurrent request isolation and context cleanup;
* startup: ``UNIFI_KEY_MODE`` grammar and header mode on stdio.

Every key here is synthetic.
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import itertools
import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests._tool_classes import tool_module_paths
from unifi_fabric import header_credentials as hc
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.contracts import CredentialHandle, RequestContext
from unifi_fabric.registry import Registry

KEY_A = "synthetic-key-a"
KEY_B = "synthetic-key-b"
KEY_C = "synthetic-key-c"
ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "src" / "unifi_fabric" / "families"


def _hdr(obj: Any) -> str:
    return obj if isinstance(obj, str) else json.dumps(obj)


def _headers(pairs: list[tuple[str, str]]):
    """A wire header source: every value of a (case-insensitive) name, in order."""

    def source(name: str) -> list[str]:
        return [v for n, v in pairs if n.lower() == name.lower()]

    return source


def _env_configs(*cfgs: APIKeyConfig):
    return lambda: list(cfgs)


@pytest.fixture
def header_mode(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("UNIFI_KEY_MODE", "header")
    hc.set_process_key_mode(None)
    yield
    hc.set_process_key_mode(None)


# ----------------------------------------------------------------------------- recorder


class Upstream:
    """A MockTransport recording which key every upstream request carried."""

    def __init__(
        self,
        hosts_by_key: dict[str, list[dict[str, Any]]] | None = None,
        status_by_key: dict[str, int] | None = None,
        echo_key: bool = False,
    ) -> None:
        self.hosts_by_key = hosts_by_key or {}
        self.status_by_key = status_by_key or {}
        self.echo_key = echo_key
        self.calls: list[tuple[str, str]] = []  # (key, path)
        self.closed = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        key = request.headers.get("X-API-KEY", "")
        self.calls.append((key, request.url.path))
        status = self.status_by_key.get(key, 200)
        if status != 200:
            body = {"message": f"unauthorized key {key}" if self.echo_key else "unauthorized"}
            return httpx.Response(status, json=body, request=request)
        if request.url.path == "/v1/hosts":
            return httpx.Response(
                200, json={"data": self.hosts_by_key.get(key, [])}, request=request
            )
        return httpx.Response(200, json={"data": [], "path": request.url.path}, request=request)

    def keys_used(self) -> list[str]:
        return [k for k, _ in self.calls]


@pytest.fixture
def upstream(monkeypatch: pytest.MonkeyPatch) -> Upstream:
    up = Upstream()

    def factory(self: UniFiClient, key_config: APIKeyConfig) -> httpx.AsyncClient:
        client = httpx.AsyncClient(
            base_url=self._settings.api_base_url,
            headers={"X-API-KEY": key_config.key, "Accept": "application/json"},
            transport=httpx.MockTransport(up.handler),
        )
        original = client.aclose

        async def aclose() -> None:
            up.closed += 1
            await original()

        client.aclose = aclose  # type: ignore[method-assign]
        return client

    monkeypatch.setattr(UniFiClient, "_new_http_client", factory)
    return up


def _client() -> UniFiClient:
    return UniFiClient(
        Settings(max_retries=0) if "max_retries" in Settings.model_fields else Settings()
    )


def _ingress(
    pairs: list[tuple[str, str]],
    *,
    tool: str = "list_hosts",
    arguments: dict[str, Any] | None = None,
    header_mode: bool = True,
    env: tuple[APIKeyConfig, ...] = (),
) -> tuple[RequestContext, hc.CredentialTransport]:
    return hc.evaluate_call(
        tool_name=tool,
        arguments=arguments or {},
        header_mode=header_mode,
        headers=_headers(pairs),
        environment_configs=_env_configs(*env),
    )


def _code(exc: pytest.ExceptionInfo[hc.PreDispatchRefusal]) -> str:
    return exc.value.code


# ----------------------------------------------------------------------------- parsing


@pytest.mark.parametrize(
    ("values", "why"),
    [
        (['{"alpha":"synthetic-key-a","alpha":"synthetic-key-b"}'], "duplicate raw labels"),
        (["not-json"], "malformed"),
        (["{}"], "empty object"),
        (['{"":"synthetic-key-a"}'], "empty label"),
        (['{"alpha":""}'], "empty value"),
        (['{"alpha":"   "}'], "blank value"),
        (['{"alpha":7}'], "non-string value"),
        (['["alpha","synthetic-key-a"]'], "not an object"),
        (['{"alpha":"synthetic-kéy"}'], "non-ascii key"),
        (['{"alpha":"synthetic-key-a"}', '{"beta":"synthetic-key-b"}'], "sent twice"),
    ],
)
def test_parse_rejects_invalid_api_key_header(values: list[str], why: str) -> None:
    with pytest.raises(hc.PreDispatchRefusal) as exc:
        hc.parse_api_key_header(values)
    assert exc.value.code == hc.INVALID_API_KEY_HEADER, why
    # The actionable message never echoes a key or the raw header.
    assert "synthetic-key" not in exc.value.message
    assert "synthetic-kéy" not in exc.value.message


def test_parse_preserves_request_order() -> None:
    pairs = hc.parse_api_key_header([_hdr({"beta": KEY_B, "alpha": KEY_A})])
    assert [label for label, _ in pairs] == ["beta", "alpha"]


def test_request_order_preserved_in_context() -> None:
    ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"beta": KEY_B, "alpha": KEY_A}))])
    assert [h.label for h in ctx.credentials] == ["beta", "alpha"]
    assert list(ctx.credentials_by_label) == ["beta", "alpha"]
    assert all(ctx.credentials_by_label[h.label] is h for h in ctx.credentials)
    assert [c.key for c in transport.key_configs(ctx.credentials)] == [KEY_B, KEY_A]
    assert ctx.selected_credential is None


# ----------------------------------------------------------------------------- refusals


def test_env_mode_tools_call_with_header_refuses() -> None:
    with pytest.raises(hc.PreDispatchRefusal) as exc:
        _ingress(
            [("X-UniFi-Api-Key", "anything")],
            header_mode=False,
            env=(APIKeyConfig(key=KEY_A, label="default"),),
        )
    assert _code(exc) == hc.INVALID_API_KEY_HEADER


def test_env_mode_tools_call_without_header_uses_configured_keys() -> None:
    ctx, transport = _ingress(
        [], header_mode=False, env=(APIKeyConfig(key=KEY_A, label="default"),)
    )
    assert [h.label for h in ctx.credentials] == ["default"]
    assert transport.key_config(ctx.credentials[0]).key == KEY_A


def test_header_mode_missing_header_refuses() -> None:
    with pytest.raises(hc.PreDispatchRefusal) as exc:
        _ingress([])
    assert _code(exc) == hc.MISSING_API_KEY_HEADER


@pytest.mark.parametrize("arguments", [{"key_label": None}, {"key_label": "alpha"}])
def test_header_mode_key_label_present_refuses(arguments: dict[str, Any]) -> None:
    with pytest.raises(hc.PreDispatchRefusal) as exc:
        _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A}))], arguments=arguments)
    assert _code(exc) == hc.KEY_LABEL_NOT_ALLOWED


@pytest.mark.parametrize("dispatcher", ["call_read_tool", "call_write_tool"])
@pytest.mark.parametrize("value", [None, "alpha"])
def test_header_mode_nested_dispatch_key_label_refuses_all(dispatcher: str, value: Any) -> None:
    with pytest.raises(hc.PreDispatchRefusal) as exc:
        _ingress(
            [("X-UniFi-Api-Key", _hdr({"alpha": KEY_A}))],
            tool=dispatcher,
            arguments={"name": "list_hosts", "arguments": {"key_label": value}},
        )
    assert _code(exc) == hc.KEY_LABEL_NOT_ALLOWED


def test_header_mode_nested_dispatch_key_label_refuses() -> None:
    with pytest.raises(hc.PreDispatchRefusal) as exc:
        _ingress(
            [("X-UniFi-Api-Key", _hdr({"alpha": KEY_A}))],
            tool="call_read_tool",
            arguments={"name": "list_hosts", "arguments": {"key_label": "alpha"}},
        )
    assert _code(exc) == hc.KEY_LABEL_NOT_ALLOWED


def test_header_mode_key_label_omitted_is_permitted() -> None:
    ctx, _ = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A}))], arguments={})
    assert [h.label for h in ctx.credentials] == ["alpha"]
    assert ctx.present_arguments == frozenset()


@pytest.mark.parametrize("name", hc.POLICY_HEADERS)
def test_repeated_policy_header_refuses(name: str) -> None:
    with pytest.raises(hc.PreDispatchRefusal) as exc:
        _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A})), (name, "deny"), (name, "deny")])
    assert _code(exc) == hc.INVALID_POLICY_HEADER


def test_refusal_order_1_before_2() -> None:
    with pytest.raises(hc.PreDispatchRefusal) as exc:
        _ingress(
            [
                ("X-UniFi-Api-Key", "x"),
                ("X-UniFi-Api-Key", "y"),
                ("X-UniFi-Exclude", "a"),
                ("X-UniFi-Exclude", "b"),
            ]
        )
    assert _code(exc) == hc.INVALID_API_KEY_HEADER


def test_refusal_order_2_before_3() -> None:
    with pytest.raises(hc.PreDispatchRefusal) as exc:
        _ingress([("X-UniFi-Write-Policy", "deny"), ("X-UniFi-Write-Policy", "deny")])
    assert _code(exc) == hc.INVALID_POLICY_HEADER


def test_refusal_order_3_before_4() -> None:
    with pytest.raises(hc.PreDispatchRefusal) as exc:
        _ingress([], arguments={"key_label": "alpha"})
    assert _code(exc) == hc.MISSING_API_KEY_HEADER


def test_refusal_payload_shape() -> None:
    refusal = hc.PreDispatchRefusal(hc.MISSING_API_KEY_HEADER, "send the header")
    assert json.loads(refusal.payload()) == {
        "error": {"code": "missing_api_key_header", "message": "send the header"}
    }


# ----------------------------------------------------------------------------- startup


@pytest.mark.parametrize("value", ["", "Header", "env", " header"])
def test_key_mode_grammar(value: str) -> None:
    with pytest.raises(hc.StartupRefusal) as exc:
        hc.key_mode({"UNIFI_KEY_MODE": value})
    assert exc.value.token == "startup:UNIFI_KEY_MODE"


def test_key_mode_default_environment() -> None:
    assert hc.key_mode({}) == "environment"


def test_header_mode_on_stdio_fails_startup() -> None:
    with pytest.raises(hc.StartupRefusal) as exc:
        hc.check_startup("stdio", {"UNIFI_KEY_MODE": "header"})
    assert exc.value.token == "startup:UNIFI_KEY_MODE"
    assert hc.check_startup("http", {"UNIFI_KEY_MODE": "header"}) == "header"
    assert hc.check_startup("stdio", {}) == "environment"


def test_entrypoint_header_mode_needs_no_stored_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from unifi_fabric import entrypoint

    monkeypatch.setenv("UNIFI_KEY_MODE", "header")
    entrypoint._validate_api_key_configuration()  # no SystemExit without UNIFI_API_KEY


def test_entrypoint_bad_key_mode_prints_token(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    from unifi_fabric import entrypoint

    monkeypatch.setenv("UNIFI_KEY_MODE", "loud")
    with pytest.raises(SystemExit):
        entrypoint._validate_api_key_configuration()
    assert capsys.readouterr().err.strip() == "startup:UNIFI_KEY_MODE"


# ----------------------------------------------------------------------------- middleware


def _server_mcp():
    from unifi_fabric import server

    return server


async def _call(server_mod, pairs, name="list_tool_families", arguments=None):
    from fastmcp import Client

    async with Client(server_mod.mcp) as client:
        return await client.call_tool(name, arguments or {}, raise_on_error=False)


async def test_middleware_header_mode_missing_header_is_mcp_error(
    header_mode: None, monkeypatch: pytest.MonkeyPatch, upstream: Upstream
) -> None:
    server = _server_mcp()
    monkeypatch.setattr(hc, "_raw_header_values", _headers([]))
    result = await _call(server, [], name="list_hosts")
    assert result.is_error
    payload = json.loads(result.content[0].text)
    assert payload["error"]["code"] == "missing_api_key_header"
    assert upstream.calls == []


async def test_middleware_env_mode_tools_call_with_header_is_refused(
    monkeypatch: pytest.MonkeyPatch, upstream: Upstream
) -> None:
    monkeypatch.setenv("UNIFI_API_KEY", KEY_A)
    server = _server_mcp()
    monkeypatch.setattr(hc, "_raw_header_values", _headers([("X-UniFi-Api-Key", "{}")]))
    result = await _call(server, [], name="list_hosts")
    assert result.is_error
    assert json.loads(result.content[0].text)["error"]["code"] == "invalid_api_key_header"
    assert upstream.calls == []


async def test_middleware_tools_list_never_reads_key_header(
    header_mode: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fastmcp import Client

    server = _server_mcp()
    read: list[str] = []

    def spy(name: str) -> list[str]:
        read.append(name)
        # Only the key header is poisoned; the policy headers stay absent so the policy grammar
        # accepts the request and the test isolates the key-header read.
        return ["{not json"] if name == hc.API_KEY_HEADER else []

    monkeypatch.setattr(hc, "_raw_header_values", spy)
    async with Client(server.mcp) as client:
        tools = await client.list_tools()

    assert tools
    assert hc.API_KEY_HEADER not in read


async def test_middleware_env_mode_tools_list_ignores_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fastmcp import Client

    monkeypatch.setenv("UNIFI_API_KEY", KEY_A)
    server = _server_mcp()
    async with Client(server.mcp) as client:
        baseline = sorted(t.name for t in await client.list_tools())
    monkeypatch.setattr(hc, "_raw_header_values", _headers([("X-UniFi-Api-Key", "garbage")]))
    async with Client(server.mcp) as client:
        with_header = sorted(t.name for t in await client.list_tools())
    assert with_header == baseline


async def test_middleware_binds_and_resets_context(
    header_mode: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Any] = []

    class CallProbe(hc.Middleware):
        async def on_call_tool(self, context, call_next):
            seen.append((hc.current_request_context(), hc.request_key_configs()))
            raise RuntimeError("tool body failed")

    mw = hc.HeaderCredentialMiddleware(
        environment_configs=_env_configs(),
        headers=_headers([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A}))]),
    )

    class Msg:
        name = "list_hosts"
        arguments: dict[str, Any] = {}

    class Ctx:
        message = Msg()

    async def call_next(_ctx):
        return await CallProbe().on_call_tool(_ctx, None)

    with pytest.raises(RuntimeError):
        await mw.on_call_tool(Ctx(), call_next)  # type: ignore[arg-type]
    ctx, keys = seen[0]
    assert [h.label for h in ctx.credentials] == ["alpha"]
    assert [k.key for k in keys] == [KEY_A]
    assert len(ctx.request_id) == 32 and int(ctx.request_id, 16) >= 0
    # Reset in finally: no context, and header mode has no default key.
    assert hc.current_request_context() is None
    assert hc.request_key_configs() == []


# ----------------------------------------------------------------------------- routing


async def test_no_header_no_upstream_call(header_mode: None, upstream: Upstream) -> None:
    client = _client()
    with pytest.raises(ValueError, match="X-UniFi-Api-Key"):
        await client.get("/v1/hosts")
    assert upstream.calls == []
    await client.close()


async def test_hostless_non_fanout_call_uses_first_label(
    header_mode: None, upstream: Upstream
) -> None:
    client = _client()
    ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A, "beta": KEY_B}))])
    with hc.bind_request(ctx, transport, header_mode=True):
        await client.get("/ea/sites")
    assert upstream.keys_used() == [KEY_A]
    await client.close()


async def test_hostless_fanout_list_hosts_uses_every_label_in_request_order(
    header_mode: None, upstream: Upstream
) -> None:
    from unifi_fabric.families.site_manager.site_manager import list_hosts

    upstream.hosts_by_key = {
        KEY_A: [{"id": "host-a1", "name": "HQ-A"}],
        KEY_B: [{"id": "host-b1", "name": "HQ-B"}],
    }
    client = _client()
    registry = Registry(client, ttl_seconds=900)
    for order, expected in (
        ({"alpha": KEY_A, "beta": KEY_B}, [KEY_A, KEY_B]),
        ({"beta": KEY_B, "alpha": KEY_A}, [KEY_B, KEY_A]),
    ):
        upstream.calls.clear()
        ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr(order))])
        with hc.bind_request(ctx, transport, header_mode=True):
            result = await list_hosts(client, registry)
        assert sorted(h["id"] for h in result["data"]) == ["host-a1", "host-b1"]
        assert sorted(upstream.keys_used()) == sorted(expected)
        assert [h.label for h in ctx.credentials] == list(order)
    await client.close()


async def test_single_label_header_list_hosts_single_call(
    header_mode: None, upstream: Upstream
) -> None:
    from unifi_fabric.families.site_manager.site_manager import list_hosts

    upstream.hosts_by_key = {KEY_A: [{"id": "host-a1", "name": "HQ-A"}]}
    client = _client()
    registry = Registry(client, ttl_seconds=900)
    ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A}))])
    with hc.bind_request(ctx, transport, header_mode=True):
        await list_hosts(client, registry)
    assert upstream.keys_used() == [KEY_A]
    await client.close()


async def test_paged_call_over_two_labels_refuses_before_any_request(
    header_mode: None, upstream: Upstream
) -> None:
    from unifi_fabric.families.site_manager.site_manager import list_hosts

    client = _client()
    registry = Registry(client, ttl_seconds=900)
    ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A, "beta": KEY_B}))])
    with hc.bind_request(ctx, transport, header_mode=True), pytest.raises(ValueError) as exc:
        await list_hosts(client, registry, page_size=5)
    assert "alpha" in str(exc.value) and "beta" in str(exc.value)
    assert "synthetic-key" not in str(exc.value)
    assert upstream.calls == []
    await client.close()


SHARED = [{"id": "host-s1", "name": "shared"}]


@pytest.mark.parametrize(
    ("order", "winner"),
    [({"alpha": KEY_A, "beta": KEY_B}, "alpha"), ({"beta": KEY_B, "alpha": KEY_A}, "beta")],
)
async def test_same_console_two_labels_resolves_first_in_request_order(
    header_mode: None, upstream: Upstream, order: dict[str, str], winner: str
) -> None:
    upstream.hosts_by_key = {KEY_A: SHARED, KEY_B: SHARED}
    client = _client()
    registry = Registry(client, ttl_seconds=900)
    ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr(order))])
    with hc.bind_request(ctx, transport, header_mode=True) as active:
        cfg = await registry.resolve_key_for_host("shared")
        handle = active.handle_for_config(cfg)
        child = ctx.child({"host": "shared"}, selected_credential=handle)
    assert cfg is not None and cfg.label == winner
    assert child.selected_credential is ctx.credentials_by_label[winner]
    assert {p for _, p in upstream.calls} == {"/v1/hosts"}
    await client.close()


async def test_distinct_consoles_same_name_two_labels_is_ambiguous(
    header_mode: None, upstream: Upstream
) -> None:
    upstream.hosts_by_key = {
        KEY_A: [{"id": "host-a1", "name": "HQ"}],
        KEY_B: [{"id": "host-b1", "name": "HQ"}],
    }
    client = _client()
    registry = Registry(client, ttl_seconds=900)
    ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A, "beta": KEY_B}))])
    with hc.bind_request(ctx, transport, header_mode=True), pytest.raises(ValueError) as exc:
        await registry.resolve_key_for_host("HQ")
    assert "host-a1" in str(exc.value) and "host-b1" in str(exc.value)
    assert "synthetic-key" not in str(exc.value)
    assert {p for _, p in upstream.calls} == {"/v1/hosts"}  # no tool-route call
    await client.close()


async def test_unknown_host_lists_request_labels_never_default(
    header_mode: None, upstream: Upstream
) -> None:
    upstream.hosts_by_key = {
        KEY_A: [{"id": "host-a1", "name": "HQ-A"}],
        KEY_B: [{"id": "host-b1", "name": "HQ-B"}],
    }
    client = _client()
    registry = Registry(client, ttl_seconds=900)
    ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A, "beta": KEY_B}))])
    with hc.bind_request(ctx, transport, header_mode=True), pytest.raises(ValueError) as exc:
        await registry.resolve_key_for_host("nowhere")
    assert "synthetic-key" not in str(exc.value)
    await client.close()


async def test_every_label_failing_is_runtime_error(header_mode: None, upstream: Upstream) -> None:
    upstream.status_by_key = {KEY_A: 401, KEY_B: 401}
    client = _client()
    registry = Registry(client, ttl_seconds=900)
    ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A, "beta": KEY_B}))])
    with hc.bind_request(ctx, transport, header_mode=True), pytest.raises(RuntimeError) as exc:
        await registry.resolve_key_for_host("HQ")
    assert "alpha" in str(exc.value) and "synthetic-key" not in str(exc.value)
    await client.close()


async def test_single_label_resolution_short_circuits(
    header_mode: None, upstream: Upstream
) -> None:
    client = _client()
    registry = Registry(client, ttl_seconds=900)
    ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A}))])
    with hc.bind_request(ctx, transport, header_mode=True) as active:
        cfg = await registry.resolve_key_for_host("anything")
        assert cfg is None
        assert active.handle_for_config(cfg) is ctx.credentials[0]
    assert upstream.calls == []
    await client.close()


def test_child_rejects_foreign_handle() -> None:
    ctx, _ = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A}))])
    twin = CredentialHandle(label="alpha", key_fingerprint=ctx.credentials[0].key_fingerprint)
    with pytest.raises(ValueError):
        ctx.child({}, selected_credential=twin)
    with pytest.raises(RuntimeError):
        hc.require_selected(ctx)


def test_fanout_children_one_per_label() -> None:
    ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A, "beta": KEY_B}))])
    with hc.bind_request(ctx, transport, header_mode=True):
        kids = hc.children_for({}, hc.hostless_selection("list_hosts", frozenset({"list_hosts"})))
        first = hc.hostless_selection("get_ea_sites", frozenset({"list_hosts"}))
    assert [k.selected_credential for k in kids] == list(ctx.credentials)
    assert all(k.request_id == ctx.request_id for k in kids)
    assert first == [ctx.credentials[0]]


# ----------------------------------------------------------------------------- fan-out set

_FANOUT_HELPERS = {"key_scopes", "fan_out", "first_success", "_aggregate_lists_over_keys"}


def _reaches(
    name: str,
    funcs: dict[str, Any],
    calls: dict[str, set[str]],
    reach: dict[str, bool],
    stack: frozenset[str] = frozenset(),
) -> bool:
    if name in reach:
        return reach[name]
    if name in stack:
        return False
    direct = calls.get(name, set())
    hit = bool(direct & _FANOUT_HELPERS) or any(
        _reaches(c, funcs, calls, reach, stack | {name}) for c in direct if c in funcs
    )
    reach[name] = hit
    return hit


def _fanout_functions() -> set[str]:
    """Public tool functions whose baseline code reaches a key-coverage helper.

    Derived from the call sites: a module-level function is in the set when
    it, or a same-module function it calls (transitively), calls key_scopes, fan_out,
    first_success or _aggregate_lists_over_keys.
    """
    out: set[str] = set()
    for path in sorted(tool_module_paths()):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        funcs = {
            n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        calls = {
            name: {
                c.func.id if isinstance(c.func, ast.Name) else getattr(c.func, "attr", "")
                for c in ast.walk(node)
                if isinstance(c, ast.Call)
            }
            for name, node in funcs.items()
        }
        reach: dict[str, bool] = {}
        out |= {n for n in funcs if not n.startswith("_") and _reaches(n, funcs, calls, reach)}
    return out


def test_fanout_set_is_derived_and_nonempty() -> None:
    fanout = _fanout_functions()
    assert "list_hosts" in fanout
    assert "get_isp_metrics" in fanout
    assert "list_sites" in fanout


def test_hostless_selection_matches_fanout_set_for_every_tool() -> None:
    fanout = frozenset(_fanout_functions())
    ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A, "beta": KEY_B}))])
    with hc.bind_request(ctx, transport, header_mode=True):
        for path in sorted(tool_module_paths()):
            for node in ast.parse(path.read_text(encoding="utf-8")).body:
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef)
                ) and not node.name.startswith("_"):
                    labels = [h.label for h in hc.hostless_selection(node.name, fanout)]
                    assert labels == (["alpha", "beta"] if node.name in fanout else ["alpha"]), (
                        node.name
                    )


# ----------------------------------------------------------------------------- identity/cache


def test_environment_cache_label_is_unchanged() -> None:
    a = APIKeyConfig(key=KEY_A, label="alpha")
    assert hc.cache_label("alpha", a) == "alpha"  # environment mode unchanged


def test_header_cache_label_differs_per_key(header_mode: None) -> None:
    a = APIKeyConfig(key=KEY_A, label="alpha")
    b = APIKeyConfig(key=KEY_B, label="alpha")
    assert hc.cache_label("alpha", a) != hc.cache_label("alpha", b)
    assert hc.full_key_digest(KEY_A) in hc.cache_label("alpha", a)
    assert hashlib.sha256(KEY_A.encode()).hexdigest() not in hc.cache_label("alpha", a)


def _prefix_collision() -> tuple[str, str]:
    seen: dict[str, str] = {}
    for i in itertools.count():
        key = f"synthetic-collide-{i}"
        fp = hc.key_fingerprint(key)
        if fp in seen:
            return seen[fp], key
        seen[fp] = key


def test_synthetic_prefix_collision_is_distinct_identity() -> None:
    k1, k2 = _prefix_collision()
    assert hc.key_fingerprint(k1) == hc.key_fingerprint(k2)
    assert hc.full_key_digest(k1) != hc.full_key_digest(k2)
    t, handles = hc.CredentialTransport.from_pairs([("alpha", k1)])
    t2, handles2 = hc.CredentialTransport.from_pairs([("alpha", k2)])
    assert t.identities() != t2.identities()
    assert handles[0] != handles2[0]


async def test_prefix_collision_never_shares_client_or_registry_entry(
    header_mode: None, upstream: Upstream
) -> None:
    k1, k2 = _prefix_collision()
    upstream.hosts_by_key = {k1: [{"id": "h1", "name": "one"}], k2: [{"id": "h2", "name": "two"}]}
    client = _client()
    registry = Registry(client, ttl_seconds=900)
    seen = []
    for key in (k1, k2):
        ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": key}))])
        with hc.bind_request(ctx, transport, header_mode=True):
            hosts = await registry.get_hosts()
            seen.append([h["id"] for h in hosts])
    assert seen == [["h1"], ["h2"]]  # second key did not read the first key's cache
    assert upstream.keys_used() == [k1, k2]
    assert len(client._credential_cache) == 2  # noqa: SLF001
    await client.close()


async def test_same_label_two_keys_concurrent_isolation(
    header_mode: None, upstream: Upstream
) -> None:
    upstream.hosts_by_key = {KEY_A: [{"id": "ha", "name": "a"}], KEY_B: [{"id": "hb", "name": "b"}]}
    client = _client()
    registry = Registry(client, ttl_seconds=0)
    gate = asyncio.Event()

    async def one(key: str) -> list[str]:
        ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": key}))])
        with hc.bind_request(ctx, transport, header_mode=True):
            await gate.wait()
            assert [c.key for c in hc.request_key_configs() or []] == [key]
            return [h["id"] for h in await registry.get_hosts()]

    tasks = [asyncio.create_task(one(KEY_A)), asyncio.create_task(one(KEY_B))]
    await asyncio.sleep(0)
    gate.set()
    assert await asyncio.gather(*tasks) == [["ha"], ["hb"]]
    assert hc.current_request_context() is None
    await client.close()


class FakeClient:
    def __init__(self) -> None:
        self.closed = 0

    async def aclose(self) -> None:
        self.closed += 1


def _ident(i: int) -> tuple[str, str]:
    return (f"label-{i}", hc.full_key_digest(f"synthetic-key-{i}"))


def _cfg(i: int) -> APIKeyConfig:
    return APIKeyConfig(key=f"synthetic-key-{i}", label=f"label-{i}")


async def test_identity_257_refused_while_256_pinned_with_two_sources() -> None:
    cache = hc.CredentialCache()
    clients: list[FakeClient] = []

    def factory(_cfg: APIKeyConfig) -> FakeClient:
        c = FakeClient()
        clients.append(c)
        return c

    for i in range(256):
        await cache.acquire([_ident(i)])
        cache.client(_cfg(i), "site_manager", factory)
        cache.client(_cfg(i), "connector", factory)
    assert len(cache) == 256 and len(clients) == 512
    with pytest.raises(hc.PreDispatchRefusal) as exc:
        await cache.acquire([_ident(256)])
    assert exc.value.code == hc.CREDENTIAL_CACHE_SATURATED
    assert "retry" in exc.value.message
    assert len(cache) == 256 and all(c.closed == 0 for c in clients)
    # Existing identities continue.
    held = await cache.acquire([_ident(5)])
    cache.release(held)
    # Retry after one release succeeds and evicts exactly that identity, closing its
    # two clients once each.
    cache.release([_ident(0)])
    await cache.acquire([_ident(256)])
    assert _ident(0) not in cache.identities()
    assert [c.closed for c in clients[:2]] == [1, 1]
    assert all(c.closed == 0 for c in clients[2:])
    await cache.aclose()
    assert all(c.closed == 1 for c in clients)  # shutdown closes every client once


async def test_lru_eviction_picks_least_recent_unpinned_and_closes_once() -> None:
    cache = hc.CredentialCache(maxsize=2)
    made: dict[int, FakeClient] = {}

    for i in range(2):
        held = await cache.acquire([_ident(i)])
        made[i] = cache.client(_cfg(i), "s", lambda _c: FakeClient())
        cache.release(held)
    # Touch identity 0 so identity 1 is least recent.
    cache.release(await cache.acquire([_ident(0)]))
    await cache.acquire([_ident(2)])
    assert _ident(1) not in cache.identities()
    assert made[1].closed == 1 and made[0].closed == 0
    await cache.aclose()
    await cache.aclose()
    assert made[1].closed == 1 and made[0].closed == 1


async def test_cancellation_releases_pin(header_mode: None) -> None:
    cache = hc.CredentialCache(maxsize=1)
    started = asyncio.Event()

    mw = hc.CredentialLeaseMiddleware(lambda: cache)
    ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A}))])

    async def call_next(_ctx):
        started.set()
        await asyncio.sleep(3600)

    async def run() -> None:
        with hc.bind_request(ctx, transport, header_mode=True):
            await mw.on_call_tool(object(), call_next)  # type: ignore[arg-type]

    task = asyncio.create_task(run())
    await started.wait()
    assert cache.pinned(transport.identities()[0]) == 1
    # A second identity is refused while the only slot is pinned.
    with pytest.raises(hc.PreDispatchRefusal):
        await cache.acquire([("other", hc.full_key_digest(KEY_B))])
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cache.pinned(("alpha", hc.full_key_digest(KEY_A))) == 0
    await cache.acquire([("other", hc.full_key_digest(KEY_B))])
    await cache.aclose()


async def test_lease_middleware_saturation_is_mcp_refusal(header_mode: None) -> None:
    from fastmcp.exceptions import ToolError

    cache = hc.CredentialCache(maxsize=1)
    await cache.acquire([("busy", hc.full_key_digest(KEY_C))])
    mw = hc.CredentialLeaseMiddleware(lambda: cache)
    ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A}))])
    called = []

    async def call_next(_ctx):
        called.append(1)

    with hc.bind_request(ctx, transport, header_mode=True), pytest.raises(ToolError) as exc:
        await mw.on_call_tool(object(), call_next)  # type: ignore[arg-type]
    assert json.loads(str(exc.value))["error"]["code"] == "credential_cache_saturated"
    assert called == []


async def test_client_close_closes_header_cache(header_mode: None, upstream: Upstream) -> None:
    client = _client()
    ctx, transport = _ingress([("X-UniFi-Api-Key", _hdr({"alpha": KEY_A, "beta": KEY_B}))])
    with hc.bind_request(ctx, transport, header_mode=True):
        await client.get("/ea/sites")
        await client.get("/ea/sites", key=client.get_key_by_label("beta"))
    assert client._clients == {}  # noqa: SLF001 - header keys never enter the env pool
    await client.close()
    assert upstream.closed == 2


# ----------------------------------------------------------------------------- leak matrix


async def test_synthetic_leak_matrix(
    header_mode: None, upstream: Upstream, caplog: pytest.LogCaptureFixture
) -> None:
    """Plant synthetic keys in the header, arguments, upstream error bodies and debug
    logging; only 8-hex fingerprints may appear anywhere observable."""
    leak_a, leak_b = "synthetic-leak-key-alpha-0001", "synthetic-leak-key-beta-0002"
    raw_header = _hdr({"alpha": leak_a, "beta": leak_b})
    upstream.echo_key = True
    upstream.status_by_key = {leak_a: 401, leak_b: 401}
    caplog.set_level(logging.DEBUG)
    observed: list[str] = []

    client = _client()
    registry = Registry(client, ttl_seconds=900)
    ctx, transport = _ingress(
        [("X-UniFi-Api-Key", raw_header)], arguments={"host": leak_a, "note": leak_b}
    )
    observed += [repr(ctx), str(ctx), repr(ctx.credentials), repr(transport)]
    with hc.bind_request(ctx, transport, header_mode=True):
        for call in (client.get("/ea/sites"), registry.resolve_key_for_host("HQ")):
            try:
                await call
            except Exception as exc:  # noqa: BLE001
                observed.append(f"{type(exc).__name__}: {exc}")
                observed.append(repr(exc))
    # Refusals in every ingress shape.
    for pairs, args in (
        ([("X-UniFi-Api-Key", raw_header), ("X-UniFi-Api-Key", raw_header)], {}),
        ([("X-UniFi-Api-Key", f'{{"alpha":"{leak_a}","alpha":"{leak_b}"}}')], {}),
        ([("X-UniFi-Api-Key", raw_header)], {"key_label": leak_a}),
        ([("X-UniFi-Api-Key", f'{{"alpha":"{leak_a}",')], {}),
    ):
        with pytest.raises(hc.PreDispatchRefusal) as exc:
            _ingress(pairs, arguments=args)
        observed.append(exc.value.payload())
    observed += [r.getMessage() for r in caplog.records]
    observed += [str(r.args) for r in caplog.records if r.args]
    await client.close()

    allowed = {hc.key_fingerprint(leak_a), hc.key_fingerprint(leak_b)}
    blob = "\n".join(observed)
    for secret in (
        leak_a,
        leak_b,
        raw_header,
        hc.full_key_digest(leak_a),
        hc.full_key_digest(leak_b),
    ):
        assert secret not in blob
    assert {h.key_fingerprint for h in ctx.credentials} == allowed
    assert transport.secret_values() == ()  # wiped when the request ended


async def test_cancel_during_eviction_close_releases_pins() -> None:
    """A cancellation while acquire() closes evicted clients must not leak pins."""
    cache = hc.CredentialCache(maxsize=1)
    gate = asyncio.Event()

    class SlowClient:
        async def aclose(self) -> None:
            gate.set()
            await asyncio.sleep(0.05)

    held = await cache.acquire([_ident(0)])
    cache.client(_cfg(0), "s", lambda _c: SlowClient())
    cache.release(held)
    task = asyncio.create_task(cache.acquire([_ident(1)]))
    await gate.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cache.pinned(_ident(1)) == 0
    # The slot is reusable: a later identity is not refused as saturated.
    cache.release(await cache.acquire([_ident(2)]))


async def test_unleased_eviction_closes_promptly() -> None:
    cache = hc.CredentialCache(maxsize=1)
    first = FakeClient()
    cache.client(_cfg(0), "s", lambda _c: first)
    cache.client(_cfg(1), "s", lambda _c: FakeClient())
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert first.closed == 1
    await cache.aclose()
    assert first.closed == 1


async def test_env_mode_bad_key_settings_pass_through(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> list[APIKeyConfig]:
        raise ValueError("bad UNIFI_API_KEYS")

    mw = hc.HeaderCredentialMiddleware(
        environment_configs=broken, headers=_headers([]), header_mode=lambda: False
    )

    class Msg:
        name = "list_hosts"
        arguments: dict[str, Any] = {}

    class Ctx:
        message = Msg()

    async def call_next(_ctx: Any) -> str:
        assert hc.current_request_context() is None
        return "tool reported its own configuration error"

    assert await mw.on_call_tool(Ctx(), call_next) == "tool reported its own configuration error"  # type: ignore[arg-type]


@pytest.mark.parametrize("label", [" alpha", "alpha\n", "al\x01pha"])
def test_parse_rejects_invalid_label_without_echo(label: str) -> None:
    with pytest.raises(hc.PreDispatchRefusal) as exc:
        hc.parse_api_key_header([json.dumps({label: KEY_A})])
    assert exc.value.code == hc.INVALID_API_KEY_HEADER
    assert label.strip() not in exc.value.message


def test_parse_rejects_control_character_key() -> None:
    with pytest.raises(hc.PreDispatchRefusal) as exc:
        hc.parse_api_key_header([json.dumps({"alpha": "synthetic\x01key"})])
    assert exc.value.code == hc.INVALID_API_KEY_HEADER
    assert "synthetic" not in exc.value.message


async def test_cancel_midway_close_completes_every_client() -> None:
    """Cancelled while closing the first evicted client: that client and the rest still
    finish closing (the close runs shielded from the caller's cancellation)."""
    cache = hc.CredentialCache(maxsize=1)
    gate = asyncio.Event()
    done: list[str] = []

    class Slow:
        def __init__(self, name: str) -> None:
            self.name = name

        async def aclose(self) -> None:
            gate.set()
            await asyncio.sleep(0.05)
            done.append(self.name)

    held = await cache.acquire([_ident(0)])
    cache.client(_cfg(0), "a", lambda _c: Slow("interrupted"))
    cache.client(_cfg(0), "b", lambda _c: Slow("later"))
    cache.release(held)
    task = asyncio.create_task(cache.acquire([_ident(1)]))
    await gate.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cache.pinned(_ident(1)) == 0
    await cache.aclose()  # shutdown waits for in-flight closes
    assert done == ["interrupted", "later"]


async def test_leak_matrix_through_mcp_stack(
    header_mode: None,
    monkeypatch: pytest.MonkeyPatch,
    upstream: Upstream,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """End to end through the server middleware stack (scrub, audit, credential ingress, lease):
    a key echoed by the upstream, a key-shaped label and DEBUG logs with tracebacks
    never surface a key, a full digest or the raw header."""
    from fastmcp import Client

    leak = "synthetic-leak-key-stack-0003"
    label_leak = "synthetic-key-in-label-slot-0004"
    raw = _hdr({"alpha": leak, label_leak: KEY_B})
    upstream.echo_key = True
    upstream.status_by_key = {leak: 401, KEY_B: 401}
    caplog.set_level(logging.DEBUG)
    server = _server_mcp()
    monkeypatch.setattr(hc, "_raw_header_values", _headers([("X-UniFi-Api-Key", raw)]))
    async with Client(server.mcp) as client:
        results = [
            await client.call_tool("list_hosts", {}, raise_on_error=False),
            await client.call_tool("get_host", {"host": "HQ"}, raise_on_error=False),
        ]
    texts = [c.text for r in results for c in r.content if hasattr(c, "text")]
    assert upstream.calls, "the calls reached the mocked upstream"
    formatter = logging.Formatter()
    logs = [formatter.format(r) for r in caplog.records]
    blob = "\n".join(texts)
    log_blob = "\n".join(logs)
    for secret in (leak, KEY_B, raw, hc.full_key_digest(leak), hc.full_key_digest(KEY_B)):
        assert secret not in blob
        assert secret not in log_blob
    assert label_leak not in log_blob
