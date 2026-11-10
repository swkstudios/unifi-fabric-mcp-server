"""Regression coverage for Protect event envelopes and collector identities."""

from unittest.mock import AsyncMock

import pytest
import respx
from httpx import Response

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.families.protect import protect

HOST = "host-envelope"
BASE = "https://api.ui.com"
EVENTS = protect.PROTECT_PRIVATE_BASE.format(host_id=HOST) + "/events"


@pytest.fixture
async def client():
    client = UniFiClient(Settings(api_keys=[APIKeyConfig(key="fixture-key", label="one")]))
    yield client
    await client.close()


@pytest.fixture
def registry():
    return AsyncMock(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value=HOST),
    )


@pytest.mark.parametrize("explicit", [False, True])
async def test_event_object_preserves_array_key_and_envelope(client, registry, explicit):
    body = {
        "data": [{"id": "event-1"}],
        "traceId": "first-trace",
        "httpStatusCode": 200,
        "totalCount": 1,
        "custom": {"keep": [1, 2]},
    }
    async with respx.mock(base_url=BASE) as mock:
        mock.get(EVENTS).return_value = Response(200, json=body)
        result = await protect.list_protect_events(
            client, registry, HOST, 1700000000, 1700000100, **({"limit": 1} if explicit else {})
        )
    assert {key: result[key] for key in body} == body
    assert "result" not in result


async def test_event_drain_preserves_first_envelope_when_capped(client, registry):
    client._settings.paginate_max_pages = 1
    body = {"data": [{"id": "event-1"}], "traceId": "first-trace", "totalCount": 2}
    async with respx.mock(base_url=BASE) as mock:
        mock.get(EVENTS).return_value = Response(200, json=body)
        result = await protect.list_protect_events(client, registry, HOST, 1700000000, 1700000100)
    assert result["data"] == body["data"]
    assert result["traceId"] == body["traceId"]
    assert result["totalCount"] == 2
    assert result["incomplete"] is True


@pytest.mark.parametrize("bad_id", [["not-scalar"], {"id": "not-scalar"}])
@pytest.mark.parametrize("collector", ["events", "devices"])
async def test_collector_non_scalar_id_is_actionable_shape_error(
    client, registry, monkeypatch, bad_id, collector
):
    async with respx.mock(base_url=BASE) as mock:
        if collector == "events":
            mock.get(EVENTS).return_value = Response(200, json=[{"id": bad_id}])
            operation = protect.collect_protect_events(client, registry, HOST, poll_count=1)
        else:
            for family in protect.DEVICE_FAMILIES[:1]:
                mock.get(protect._proxy(HOST, "/" + family)).return_value = Response(
                    200, json=[{"id": bad_id}] if family == "cameras" else []
                )
            operation = protect.collect_protect_device_changes(client, registry, HOST, poll_count=1)
        with pytest.raises(UniFiConnectionError, match="[Ss]hape.*id.*scalar"):
            await operation


def test_collector_description_matches_forwarded_smart_detect_filter():
    assert "rejected the same way" not in protect.collect_protect_events.__doc__


@pytest.mark.parametrize("object_page", [False, True])
async def test_event_drain_keeps_array_key_even_without_envelope_metadata(
    client, registry, object_page
):
    events = [{"id": "event-1"}]
    bodies = [{"data": events}, {"data": []}] if object_page else [events, []]
    async with respx.mock(base_url=BASE) as mock:
        mock.get(EVENTS).side_effect = [Response(200, json=body) for body in bodies]
        result = await protect.list_protect_events(client, registry, HOST, 1700000000, 1700000100)
    array_key = "data" if object_page else "result"
    assert result[array_key] == events
    assert ("result" if object_page else "data") not in result


@pytest.mark.parametrize("collector", ["events", "devices"])
async def test_later_non_scalar_id_keeps_earlier_poll_and_marks_incomplete(
    client, registry, monkeypatch, collector
):
    monkeypatch.setattr(protect, "_sleep", AsyncMock(return_value=None))
    async with respx.mock(base_url=BASE) as mock:
        bodies = [[{"id": "good-id"}], [], [{"id": ["bad"]}], []]
        if collector == "events":
            mock.get(EVENTS).side_effect = [Response(200, json=body) for body in bodies]
            result = await protect.collect_protect_events(client, registry, HOST, poll_count=2)
            assert result["result"] == [{"id": "good-id"}]
        else:
            for family in protect.DEVICE_FAMILIES:
                route = mock.get(protect._proxy(HOST, "/" + family))
                if family == "cameras":
                    route.side_effect = [
                        Response(200, json=[{"id": "good-id"}]),
                        Response(200, json=[{"id": ["bad"]}]),
                    ]
                else:
                    route.return_value = Response(200, json=[])
            result = await protect.collect_protect_device_changes(
                client, registry, HOST, poll_count=2
            )
        assert result["incomplete"] is True
        assert "id" in result["incompleteReason"]
        assert "scalar" in result["incompleteReason"]
        assert "unhashable" not in result["incompleteReason"]


async def test_collector_subtype_without_type_is_forwarded_with_warning(
    client, registry, monkeypatch
):
    async with respx.mock(base_url=BASE) as mock:
        mock.get(EVENTS).return_value = Response(200, json=[])
        result = await protect.collect_protect_events(
            client, registry, HOST, poll_count=1, smart_detect_types="person"
        )
        request = mock.calls[0].request
    assert request.url.params["smartDetectTypes"] == "person"
    assert "types" not in request.url.params
    assert result["_warnings"][0]["code"] == "SMART_DETECT_TYPES_WITHOUT_TYPES"


@pytest.mark.parametrize("family", protect.DEVICE_FAMILIES)
async def test_every_device_family_rejects_non_scalar_identity(client, family):
    async with respx.mock(base_url=BASE) as mock:
        for candidate in protect.DEVICE_FAMILIES[: protect.DEVICE_FAMILIES.index(family) + 1]:
            mock.get(protect._proxy(HOST, "/" + candidate)).return_value = Response(
                200, json=[{"id": {"bad": "id"}}] if candidate == family else []
            )
        with pytest.raises(UniFiConnectionError, match=f"GET .*{family}:.*id.*scalar"):
            await protect._poll_device_snapshot(client, HOST, HOST, None)
