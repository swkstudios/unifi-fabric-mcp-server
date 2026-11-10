"""Protect MCP resources through a real MCP client session against a simulated upstream.

Acceptance: a resource-capable MCP client enumerates and resolves the
documented resources and templates; event freshness and coverage, JPEG bytes and MIME, and
missing or inaccessible object errors are verified; credentials stay isolated (environment
and header modes) and the existing event and snapshot tools are unchanged.

The URIs are written out here on purpose: they are the documented contract.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from fastmcp import Client
from mcp.types import BlobResourceContents, TextResourceContents

from tests import upstream_harness as uh
from unifi_fabric import header_credentials as hc
from unifi_fabric import server
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.registry import Registry

HOST = uh.HOST
HOST_ID = uh.HOST_ID
CONSOLES = "unifi-protect://consoles"
TEMPLATES = {
    "unifi-protect://hosts/{host}/events/recent{?window_seconds}": "application/json",
    "unifi-protect://hosts/{host}/events/summary{?window_seconds}": "application/json",
    "unifi-protect://hosts/{host}/cameras/snapshots": "application/json",
    "unifi-protect://hosts/{host}/cameras/{camera_id}/snapshot{?channel,high_quality}": (
        "image/jpeg"
    ),
}
CAMERA = "00000000000000000000010b"
PACKAGE_CAMERA = "00000000000000000000010c"
MISSING_CAMERA = "0000000000000000000001ff"
NOW = 1_762_600_000
#: A JPEG-shaped synthetic body: SOI marker, filler, EOI marker.
JPEG = b"\xff\xd8\xff\xe0" + bytes(range(256)) * 4 + b"\xff\xd9"
EVENTS_PATH = f"/v1/connector/consoles/{HOST_ID}/proxy/protect/api/events"
PROTECT = f"/v1/connector/consoles/{HOST_ID}/proxy/protect/integration/v1"


def _key(tag: str) -> str:
    """A synthetic key, built at run time (no secret-shaped literal in the source)."""
    return "-".join(("synthetic", "resource", tag, "0832"))


def _event(i: int) -> dict[str, Any]:
    kinds = ("motion", "smartDetectZone", "ring")
    event: dict[str, Any] = {
        "id": f"{i:024x}",
        "type": kinds[i % 3],
        "camera": CAMERA if i % 2 == 0 else PACKAGE_CAMERA,
        "start": (NOW - i) * 1000,
        "end": None if i == 0 else (NOW - i) * 1000 + 500,
        "smartDetectTypes": ["person"] if i % 3 == 1 else [],
        "score": i,
    }
    return event


class Upstream:
    """Protect routes plus /v1/hosts; records every request with the key it carried."""

    def __init__(self, events: int = 5, echo_key: bool = False) -> None:
        self.events = [_event(i) for i in range(events)]
        self.echo_key = echo_key
        self.requests: list[tuple[str, str, dict[str, list[str]]]] = []

    def protect_requests(self) -> list[tuple[str, str, dict[str, list[str]]]]:
        return [r for r in self.requests if "/proxy/protect/" in r[1]]

    def handler(self, request: httpx.Request) -> httpx.Response:
        key = request.headers.get("X-API-KEY", "")
        path = request.url.path
        query = parse_qs(request.url.query.decode(), keep_blank_values=True)
        self.requests.append((key, path, query))
        if path == "/v1/hosts":
            return httpx.Response(200, json=uh._HOSTS)
        if path == EVENTS_PATH:
            offset = int(query.get("offset", ["0"])[0])
            limit = int(query.get("limit", ["200"])[0])
            return httpx.Response(200, json=self.events[offset : offset + limit])
        if path == f"{PROTECT}/cameras":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": CAMERA,
                        "name": "Front Door",
                        "state": "CONNECTED",
                        "modelKey": "camera",
                        "featureFlags": {"hasPackageCamera": False},
                    },
                    {
                        "id": PACKAGE_CAMERA,
                        "name": "Porch",
                        "state": "DISCONNECTED",
                        "modelKey": "camera",
                        "featureFlags": {"hasPackageCamera": True},
                    },
                ],
            )
        if path == f"{PROTECT}/cameras/{CAMERA}/snapshot":
            return httpx.Response(200, content=JPEG, headers={"content-type": "image/jpeg"})
        if path.startswith(f"{PROTECT}/cameras/") and path.endswith("/snapshot"):
            reason = f"camera not found (key {key})" if self.echo_key else "camera not found"
            return httpx.Response(
                404, json={"error": "NOT_FOUND", "name": "NOT_FOUND", "message": reason}
            )
        return httpx.Response(404, json={"message": f"unrouted {path}"})


@pytest.fixture
def upstream(monkeypatch: pytest.MonkeyPatch) -> Iterator[Upstream]:
    up = Upstream()

    def factory(self: UniFiClient, key_config: APIKeyConfig) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._settings.api_base_url,
            headers={"X-API-KEY": key_config.key, "Accept": "application/json"},
            transport=httpx.MockTransport(up.handler),
            follow_redirects=False,
        )

    monkeypatch.setattr(UniFiClient, "_new_http_client", factory)
    try:
        from unifi_fabric import protect_resources
    except ImportError:  # the base revision has no resources: the tests then fail on asserts
        pass
    else:
        monkeypatch.setattr(protect_resources.time, "time", lambda: float(NOW))
    yield up


def _env_key(monkeypatch: pytest.MonkeyPatch, **settings: Any) -> str:
    key = _key("env")
    s = Settings(api_key=key, **settings)
    client = UniFiClient(s)
    monkeypatch.setattr(server, "_settings", s)
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", Registry(client, ttl_seconds=0))
    return key


def _json(contents: list[Any]) -> Any:
    (item,) = contents
    assert isinstance(item, TextResourceContents)
    assert item.mime_type == "application/json"
    return json.loads(item.text)


async def _read_error(client: Client, uri: str) -> str:
    with pytest.raises(Exception) as caught:
        await client.read_resource(uri)
    return f"{type(caught.value).__name__}: {caught.value}"


# ----------------------------------------------------------------------------- inventory


async def test_inventory_lists_the_documented_resource_and_templates(monkeypatch, upstream):
    key = _env_key(monkeypatch)
    async with Client(server.mcp) as client:
        resources = await client.list_resources()
        templates = await client.list_resource_templates()
    assert [str(r.uri) for r in resources] == [CONSOLES]
    assert resources[0].mime_type == "application/json"
    assert {t.uri_template: t.mime_type for t in templates} == TEMPLATES
    for item in [*resources, *templates]:
        assert item.description and item.name
        text = json.dumps(item.model_dump(mode="json"))
        assert key not in text
        assert not {"token", "apikey", "api_key", "password"} & set(text.lower().split('"'))
        assert (item.meta or {}).get("subscribe") is False
    assert upstream.requests == [], "listing makes no upstream request"


async def test_no_subscription_or_list_changed_capability_is_advertised(monkeypatch, upstream):
    _env_key(monkeypatch)
    async with Client(server.mcp) as client:
        capabilities = client.server_capabilities
    assert capabilities.resources is not None
    assert not capabilities.resources.subscribe
    assert not capabilities.resources.list_changed


async def test_every_uri_the_consoles_index_advertises_resolves(monkeypatch, upstream):
    _env_key(monkeypatch)
    async with Client(server.mcp) as client:
        index = _json(await client.read_resource(CONSOLES))
        (console,) = index["consoles"]
        assert console["host_id"] == HOST_ID and console["hostname"] == HOST
        assert console["events_uri"] == f"unifi-protect://hosts/{HOST_ID}/events/recent"
        for name in ("events_uri", "summary_uri", "snapshot_index_uri"):
            assert isinstance(_json(await client.read_resource(console[name])), dict)
        cameras = _json(await client.read_resource(console["snapshot_index_uri"]))["cameras"]
        (blob,) = await client.read_resource(cameras[0]["snapshot_uri"])
    assert isinstance(blob, BlobResourceContents)
    assert index["freshness"]["cached"] is False
    assert index["coverage"] == {"complete": True, "console_count": 1}


# ------------------------------------------------------------------------------- events


async def test_recent_events_report_source_freshness_and_exact_window(monkeypatch, upstream):
    _env_key(monkeypatch)
    async with Client(server.mcp) as client:
        body = _json(
            await client.read_resource(
                f"unifi-protect://hosts/{HOST}/events/recent?window_seconds=900"
            )
        )
    assert body["events"] == upstream.events  # verbatim, newest first as served
    assert body["source"]["kind"] == "rest-history"
    assert body["source"]["tool"] == "list_protect_events"
    assert body["source"]["streaming"]["available"] is False
    assert body["freshness"]["read_at_epoch_seconds"] == NOW
    assert body["freshness"]["cached"] is False
    assert body["freshness"]["subscribe"] is False
    coverage = body["coverage"]
    assert coverage["window_seconds"] == 900
    assert coverage["window_start_epoch_seconds"] == NOW - 900
    assert coverage["window_end_epoch_seconds"] == NOW
    assert coverage["complete"] is True and coverage["event_count"] == 5
    request = upstream.protect_requests()[0]
    assert {r[1] for r in upstream.protect_requests()} == {EVENTS_PATH}
    assert request[1] == EVENTS_PATH
    assert request[2]["start"] == [str((NOW - 900) * 1000)]
    assert request[2]["end"] == [str(NOW * 1000)]
    assert request[2]["orderDirection"] == ["DESC"]


async def test_recent_events_default_window_is_one_hour(monkeypatch, upstream):
    _env_key(monkeypatch)
    async with Client(server.mcp) as client:
        body = _json(await client.read_resource(f"unifi-protect://hosts/{HOST}/events/recent"))
    assert body["coverage"]["window_seconds"] == 3600
    assert upstream.protect_requests()[0][2]["start"] == [str((NOW - 3600) * 1000)]


async def test_recent_events_read_every_page(monkeypatch, upstream):
    upstream.events = [_event(i) for i in range(450)]
    _env_key(monkeypatch)
    async with Client(server.mcp) as client:
        body = _json(await client.read_resource(f"unifi-protect://hosts/{HOST}/events/recent"))
    assert body["coverage"]["event_count"] == 450
    assert body["coverage"]["complete"] is True
    assert body["events"] == upstream.events
    offsets = [int(r[2].get("offset", ["0"])[0]) for r in upstream.protect_requests()]
    assert offsets[:3] == [0, 200, 400]


async def test_event_summary_counts_the_same_window(monkeypatch, upstream):
    _env_key(monkeypatch)
    async with Client(server.mcp) as client:
        body = _json(await client.read_resource(f"unifi-protect://hosts/{HOST}/events/summary"))
    assert "events" not in body
    assert body["events_uri"] == f"unifi-protect://hosts/{HOST}/events/recent"
    assert body["summary"] == {
        "total_events": 5,
        "by_type": {"motion": 2, "smartDetectZone": 2, "ring": 1},
        "by_camera": {CAMERA: 3, PACKAGE_CAMERA: 2},
        "by_smart_detect_type": {"person": 2},
        "ongoing_events": 1,
        "newest_event_start": NOW * 1000,
        "oldest_event_start": (NOW - 4) * 1000,
    }
    assert body["source"]["kind"] == "rest-history"
    assert body["coverage"]["window_seconds"] == 3600


@pytest.mark.parametrize("window", ["0", "-5", "abc", "1.5", ""])
async def test_invalid_window_fails_before_any_request(monkeypatch, upstream, window):
    _env_key(monkeypatch)
    async with Client(server.mcp) as client:
        text = await _read_error(
            client, f"unifi-protect://hosts/{HOST}/events/recent?window_seconds={window}"
        )
    assert "window_seconds must be a positive whole number" in text
    assert upstream.requests == []


@pytest.mark.parametrize("path", ["recent", "summary"])
async def test_window_longer_than_the_epoch_fails_before_any_request(monkeypatch, upstream, path):
    _env_key(monkeypatch)
    async with Client(server.mcp) as client:
        text = await _read_error(
            client,
            f"unifi-protect://hosts/{HOST}/events/{path}?window_seconds=99999999999999999999",
        )
    assert "window_seconds is longer than" in text
    assert "OverflowError" not in text and "time_t" not in text
    assert upstream.protect_requests() == []


# ----------------------------------------------------------------------------- snapshots


async def test_snapshot_index_lists_cameras_with_snapshot_uris(monkeypatch, upstream):
    _env_key(monkeypatch)
    async with Client(server.mcp) as client:
        body = _json(await client.read_resource(f"unifi-protect://hosts/{HOST}/cameras/snapshots"))
    base = f"unifi-protect://hosts/{HOST}/cameras"
    assert body["cameras"] == [
        {
            "camera_id": CAMERA,
            "name": "Front Door",
            "state": "CONNECTED",
            "model": "camera",
            "snapshot_uri": f"{base}/{CAMERA}/snapshot",
        },
        {
            "camera_id": PACKAGE_CAMERA,
            "name": "Porch",
            "state": "DISCONNECTED",
            "model": "camera",
            "snapshot_uri": f"{base}/{PACKAGE_CAMERA}/snapshot",
            "package_snapshot_uri": f"{base}/{PACKAGE_CAMERA}/snapshot?channel=package",
        },
    ]
    assert body["coverage"] == {"complete": True, "camera_count": 2}


async def test_snapshot_is_jpeg_bytes_with_its_mime(monkeypatch, upstream):
    _env_key(monkeypatch)
    uri = f"unifi-protect://hosts/{HOST}/cameras/{CAMERA}/snapshot?high_quality=true"
    async with Client(server.mcp) as client:
        (blob,) = await client.read_resource(uri)
    assert isinstance(blob, BlobResourceContents)
    assert blob.mime_type == "image/jpeg"
    data = base64.b64decode(blob.blob, validate=True)
    assert data == JPEG and data[:3] == b"\xff\xd8\xff" and data[-2:] == b"\xff\xd9"
    assert str(blob.uri) == uri
    (request,) = upstream.protect_requests()
    assert request[1] == f"{PROTECT}/cameras/{CAMERA}/snapshot"
    assert request[2] == {"highQuality": ["true"]}


async def test_missing_camera_returns_the_upstream_error_and_a_hint(monkeypatch, upstream):
    _env_key(monkeypatch)
    async with Client(server.mcp) as client:
        text = await _read_error(
            client, f"unifi-protect://hosts/{HOST}/cameras/{MISSING_CAMERA}/snapshot"
        )
    assert "404" in text and "camera not found" in text and "NOT_FOUND" in text
    assert f"unifi-protect://hosts/{HOST}/cameras/snapshots" in text


async def test_invalid_high_quality_fails_before_any_request(monkeypatch, upstream):
    _env_key(monkeypatch)
    async with Client(server.mcp) as client:
        text = await _read_error(
            client, f"unifi-protect://hosts/{HOST}/cameras/{CAMERA}/snapshot?high_quality=yes"
        )
    assert "high_quality must be true or false" in text
    assert upstream.requests == []


async def test_unknown_host_fails_fast_with_the_valid_choices(monkeypatch, upstream):
    _env_key(monkeypatch)
    async with Client(server.mcp) as client:
        texts = [
            await _read_error(client, "unifi-protect://hosts/no-such-console/events/recent"),
            await _read_error(
                client, f"unifi-protect://hosts/no-such-console/cameras/{CAMERA}/snapshot"
            ),
        ]
    for text in texts:
        assert "no-such-console" in text and HOST in text
    assert upstream.protect_requests() == []


# --------------------------------------------------------------- credentials and policy


async def test_header_mode_reads_use_only_the_request_key(monkeypatch, upstream):
    """Per-request credential isolation: a header-mode read uses the caller's header key,
    never the environment key, and no key reaches a URI, a payload or an error."""
    env_key = _env_key(monkeypatch)
    header_key = _key("header")
    monkeypatch.setenv("UNIFI_KEY_MODE", "header")
    hc.set_process_key_mode(None)
    monkeypatch.setattr(
        hc,
        "_raw_header_values",
        lambda name: (
            [json.dumps({"caller": header_key})] if name.lower() == "x-unifi-api-key" else []
        ),
    )
    upstream.echo_key = True
    try:
        async with Client(server.mcp) as client:
            texts = [
                json.dumps(_json(await client.read_resource(CONSOLES))),
                json.dumps(
                    _json(await client.read_resource(f"unifi-protect://hosts/{HOST}/events/recent"))
                ),
                await _read_error(
                    client, f"unifi-protect://hosts/{HOST}/cameras/{MISSING_CAMERA}/snapshot"
                ),
            ]
    finally:
        hc.set_process_key_mode(None)
    keys = {request[0] for request in upstream.requests}
    assert keys == {header_key}
    for text in texts:
        assert header_key not in text and env_key not in text
    assert "camera not found" in texts[2]


async def test_missing_header_in_header_mode_is_refused_before_any_request(monkeypatch, upstream):
    _env_key(monkeypatch)
    monkeypatch.setenv("UNIFI_KEY_MODE", "header")
    hc.set_process_key_mode(None)
    monkeypatch.setattr(hc, "_raw_header_values", lambda name: [])
    try:
        async with Client(server.mcp) as client:
            text = await _read_error(client, f"unifi-protect://hosts/{HOST}/events/recent")
    finally:
        hc.set_process_key_mode(None)
    assert "missing_api_key_header" in text
    assert upstream.requests == []


async def test_excluded_protect_family_hides_and_refuses_the_resources(monkeypatch, upstream):
    _env_key(monkeypatch)
    monkeypatch.setenv("UNIFI_FAMILY_ALLOW", "site_manager,network")
    async with Client(server.mcp) as client:
        resources = [str(r.uri) for r in await client.list_resources()]
        templates = [t.uri_template for t in await client.list_resource_templates()]
        text = await _read_error(client, f"unifi-protect://hosts/{HOST}/events/recent")
    assert resources == [CONSOLES]  # list_hosts stays exposed
    assert templates == []
    assert "tool_not_exposed" in text or "is not exposed" in text
    assert upstream.protect_requests() == []


async def test_resources_work_in_code_mode(monkeypatch, upstream):
    hmac_key = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    monkeypatch.setenv("UNIFI_AUDIT_HMAC_KEY", hmac_key)
    _env_key(monkeypatch, tool_mode="codemode", audit_hmac_key=hmac_key)
    async with Client(server.mcp) as client:
        body = _json(await client.read_resource(f"unifi-protect://hosts/{HOST}/events/recent"))
    assert body["coverage"]["event_count"] == 5


def test_resource_reads_are_never_cached_or_shared(monkeypatch):
    """The server-wide list cache hint (UNIFI_MCP_CACHE_TTL, public) never applies to a
    resource read: events and snapshots are per caller and time-sensitive."""
    from mcp.server.caching import CacheHint

    monkeypatch.setattr(server.mcp._mcp_server, "cache_hints", {})  # noqa: SLF001
    monkeypatch.setattr(server, "_mcp_transport", None)
    monkeypatch.setattr(server, "_cache_ttl", None)
    monkeypatch.setattr(server.mcp, "auth", server.mcp.auth)
    monkeypatch.delenv("UNIFI_MCP_CACHE_TTL", raising=False)
    server._configure_transport()  # noqa: SLF001
    hints = server.mcp._mcp_server.cache_hints  # noqa: SLF001
    assert hints["tools/list"] == CacheHint(ttl_ms=300_000, scope="public")
    assert hints["resources/read"] == CacheHint(ttl_ms=0, scope="private")


async def test_existing_snapshot_and_event_tools_are_unchanged(monkeypatch, upstream):
    _env_key(monkeypatch, tool_mode="full")
    async with Client(server.mcp) as client:
        snap = await client.call_tool("get_camera_snapshot", {"host": HOST, "camera_id": CAMERA})
        events = await client.call_tool(
            "list_protect_events", {"host": HOST, "start": NOW - 60, "end": NOW}
        )
    assert snap.structured_content == {
        "image_base64": base64.b64encode(JPEG).decode(),
        "content_type": "image/jpeg",
        "size_bytes": len(JPEG),
    }
    assert events.structured_content["result"] == upstream.events


async def test_catalog_passes_see_tools_only_never_resources():
    """Titles, annotations, API sources, shapes, redaction and the policy catalog read
    tools through tool_components: a resource template (it has parameters and fn too)
    is never titled, annotated or classified as a tool."""
    from fastmcp.resources import Resource, ResourceTemplate

    from unifi_fabric.local_components import tool_components
    from unifi_fabric.request_policy import local_tools

    components = list(server.mcp._local_provider._components.values())  # noqa: SLF001
    resources = [c for c in components if isinstance(c, (Resource, ResourceTemplate))]
    assert len(resources) == 1 + len(TEMPLATES)
    tools = await server.mcp.list_tools(run_middleware=False)
    names = {c.name for c in tool_components(server.mcp)}
    assert names == {t.name for t in tools}
    assert not names & {r.name for r in resources}
    assert set(local_tools(server.mcp)) == names
