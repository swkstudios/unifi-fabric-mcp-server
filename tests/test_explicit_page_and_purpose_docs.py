"""The descriptions of three r17 behaviours match the code exactly, and the code is pinned.

* ``create_vpn_server``: an absent or null ``fields.purpose`` is sent as remote-user-vpn;
  any other supplied purpose (e.g. ``wan``) is sent as given.
* ``list_protect_events`` explicit page: a BARE-LIST upstream page is returned as that
  list without ``_warnings``, each event verbatim except that a sensor event gains the
  additive ``_resolved_sensor`` key; an OBJECT page preserves its native fields
  (including ``data`` and ``totalCount``) and carries the epoch-unit and
  smart-detect ``_warnings`` exactly like a drain.
* ``list_recognition_detections`` explicit page: a bare-list page is returned verbatim
  (no ``_warnings``); an object page is returned as ``{detections, _count}`` plus its
  other top-level fields and ``_nextPage``, and carries the epoch-unit ``_warnings``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from tests import test_invariants_paging_ids_and_relays as paging_invariants
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from unifi_fabric import server
from unifi_fabric.tools.protect import list_protect_events
from unifi_fabric.tools.recognition import list_recognition_detections, list_recognition_groups
from unifi_fabric.tools.vpn import _create_vpn_server as create_vpn_server

HOST_ID = "host-001"
# Epoch SECONDS inside the plausible range (no epoch warning) ...
START_S = 1_735_000_000
END_S = 1_735_086_400
# ... and a millisecond-magnitude value that draws EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS.
START_MS = 1_735_000_000_000

SENSOR_EVENT = {
    "id": "evt-s",
    "type": "sensorOpened",
    "sensor": None,
    "metadata": {"sensorId": {"text": "sensor-1"}},
}
MOTION_EVENT = {"id": "evt-m", "type": "motion", "camera": "cam-1"}


@pytest.fixture()
def client() -> AsyncMock:
    c = AsyncMock()
    c.get = AsyncMock()
    c.post = AsyncMock(return_value={})
    c.paginate_offset = AsyncMock()
    c.paginate_links = AsyncMock()
    c.paginate_max_pages = None
    return c


@pytest.fixture()
def registry() -> AsyncMock:
    r = AsyncMock()
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_slug = AsyncMock(return_value="default")
    return r


def _tool_text(name: str) -> str:
    """The whole published description of ``name``: its text and every parameter's."""
    tools = {t.name: t for t in asyncio.run(server.mcp.list_tools())}
    tool = tools[name]
    params = tool.parameters.get("properties", {}).values()
    return " ".join([tool.description or "", *(str(p.get("description", "")) for p in params)])


def _flat(text: str) -> str:
    return " ".join(text.split())


def _codes(result: Any) -> list[str]:
    return [w["code"] for w in result.get("_warnings", [])]


# --- create_vpn_server: purpose ---------------------------------------------------------


class TestCreateVpnServerPurpose:
    @pytest.mark.parametrize("fields", [None, {}, {"purpose": None}])
    async def test_absent_or_null_purpose_defaults(self, client, registry, fields):
        await create_vpn_server(client, registry, "h", "s", "V", "wireguard", fields=fields)
        assert client.post.call_args.kwargs["json"]["purpose"] == "remote-user-vpn"

    async def test_other_purpose_sent_as_given(self, client, registry):
        await create_vpn_server(
            client, registry, "h", "s", "V", "wireguard", fields={"purpose": "wan"}
        )
        assert client.post.call_args.kwargs["json"]["purpose"] == "wan"

    def test_description_states_the_rule(self):
        text = _flat(_tool_text("create_vpn_server"))
        assert (
            "An absent or null purpose is sent as remote-user-vpn; any other purpose is "
            "sent as given" in text
        )
        assert "explicit purpose is passed through unchanged" not in text


# --- list_protect_events: explicit page ---------------------------------------------------


class TestProtectEventsExplicitPage:
    async def test_bare_list_page_returned_as_list_without_warnings(self, client, registry):
        client.get.return_value = [dict(MOTION_EVENT)]
        result = await list_protect_events(
            client, registry, "h", START_MS, END_S, smart_detect_types="person", offset=0
        )
        # Both warnings would apply, but a bare list has no place for them.
        assert result == [MOTION_EVENT]

    async def test_requested_total_bare_page_is_aggregated_with_size_and_warnings(
        self, client, registry
    ):
        client.get.return_value = [dict(MOTION_EVENT)]
        result = await list_protect_events(
            client, registry, "h", START_MS, END_S, smart_detect_types="person", limit=10
        )
        assert result["data"] == [MOTION_EVENT]
        assert result["_count"] == 1
        assert result["_pageSize"] == {
            "requested": 10,
            "sent": [10],
            "effective": 10,
            "returned": 1,
        }
        assert _codes(result) == [
            "EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS",
            "SMART_DETECT_TYPES_WITHOUT_TYPES",
        ]
        client.get.assert_awaited_once()

    async def test_bare_list_sensor_event_gains_resolved_sensor(self, client, registry):
        client.get.return_value = [dict(SENSOR_EVENT), dict(MOTION_EVENT)]
        result = await list_protect_events(client, registry, "h", START_S, END_S, offset=0)
        assert isinstance(result, list)
        assert result[0] == {**SENSOR_EVENT, "_resolved_sensor": "sensor-1"}
        assert result[0]["sensor"] is None
        assert result[1] == MOTION_EVENT

    async def test_object_page_carries_epoch_and_smart_detect_warnings(self, client, registry):
        client.get.return_value = {"data": [dict(SENSOR_EVENT)], "totalCount": 7, "offset": 0}
        result = await list_protect_events(
            client, registry, "h", START_MS, END_S, smart_detect_types="person", offset=0
        )
        assert _codes(result) == [
            "EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS",
            "SMART_DETECT_TYPES_WITHOUT_TYPES",
        ]
        # Native data array and every upstream top-level field survive unchanged.
        assert set(result) == {"data", "totalCount", "offset", "_count", "_warnings"}
        assert result["data"] == [{**SENSOR_EVENT, "_resolved_sensor": "sensor-1"}]
        assert result["totalCount"] == 7
        assert result["offset"] == 0
        assert result["_count"] == 1

    async def test_drain_carries_the_same_warnings(self, client, registry):
        client.get.return_value = {"data": [dict(MOTION_EVENT)], "totalCount": 1}
        result = await list_protect_events(
            client, registry, "h", START_MS, END_S, smart_detect_types="person"
        )
        assert _codes(result) == [
            "EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS",
            "SMART_DETECT_TYPES_WITHOUT_TYPES",
        ]

    def test_description_states_each_case(self):
        text = _flat(_tool_text("list_protect_events"))
        assert "a bare list stays a list (without warnings)" in text
        assert "Sensor events retain sensor:null and gain _resolved_sensor" in text
        assert "an object page preserves every upstream top-level field verbatim" in text
        assert "its other top-level fields (e.g. totalCount) are not carried" not in text
        assert (
            "Object pages carry epoch-unit and smart-detect _warnings, as drained results do"
            in (text)
        )
        assert "return it verbatim" not in text


# --- list_recognition_detections: explicit page ------------------------------------------


class TestRecognitionDetectionsExplicitPage:
    async def test_bare_list_page_verbatim_without_warnings(self, client, registry):
        page = [{"id": "d1", "detectedAt": 1}]
        client.get.return_value = page
        result = await list_recognition_detections(
            client, registry, "h", "face", "face_90", start=START_MS, page=1
        )
        assert result is page

    async def test_object_page_carries_epoch_warnings_and_its_fields(self, client, registry):
        client.get.return_value = {
            "detections": [{"id": "d1"}],
            "links": {"prev": None, "next": "/next?page=2"},
        }
        result = await list_recognition_detections(
            client, registry, "h", "face", "face_90", start=START_MS, page=1
        )
        assert _codes(result) == ["EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS"]
        assert result["detections"] == [{"id": "d1"}]
        assert result["_count"] == 1
        assert result["_nextPage"] == 2
        assert result["links"] == {"prev": None, "next": "/next?page=2"}

    def test_description_states_each_case(self):
        text = _flat(_tool_text("list_recognition_detections"))
        assert "A bare-list manual page is unchanged" in text
        assert "without _warnings" in text
        assert "_nextPage when more exist" in text
        assert "_pageSize" in text
        assert "object pages preserve upstream fields and add epoch warnings" in text
        assert "smart-detect" not in text


# --- CHANGELOG [0.7.0] -------------------------------------------------------------------


def test_changelog_states_each_case():
    text = _flat((Path(__file__).resolve().parents[1] / "docs" / "MIGRATING-0.7.md").read_text())
    assert "return an upstream bare-list page verbatim, so `_warnings` are not attached" not in (
        text
    )
    assert (
        "A bare-list page is returned as that list without `_warnings`; on "
        "`list_protect_events` each sensor event in it gains the additive `_resolved_sensor` key"
        in text
    )
    assert (
        "An object page keeps every upstream top-level field verbatim and carries the epoch-unit "
        "`_warnings` (and, on `list_protect_events`, the smart-detect `_warnings`), as a "
        "drained result does" in text
    )


@pytest.mark.parametrize("key_label", [None, "secondary"])
@pytest.mark.parametrize("paging", [{"limit": 10}, {"offset": 0}, {"offset": 0, "limit": 10}])
async def test_protect_object_page_preserves_unknown_fields(client, registry, key_label, paging):
    registry.resolve_key_for_host.return_value = key_label
    upstream = {
        "data": [dict(MOTION_EVENT)],
        "totalCount": 7,
        "offset": 0,
        "count": 1,
        "limit": 10,
        "traceId": "page-trace",
        "result": {"unknown": [None, True]},
        "future": {"nested": [1, 2]},
    }
    records = [{**MOTION_EVENT, "id": f"event-{number}"} for number in range(7)]

    async def get(path, *, key=None, params=None):
        if "limit" not in paging:
            return upstream
        offset = params.get("offset", 0)
        return {
            **upstream,
            "data": records[offset : offset + 1],
            "offset": offset,
            "limit": 1,
        }

    client.get.side_effect = get
    result = await list_protect_events(client, registry, "h", START_S, END_S, **paging)
    # The old limit-presence branch encoded batching even for a manual offset+limit page.
    # Limit alone batches; a caller-supplied offset returns exactly one native page.
    if "limit" in paging and "offset" not in paging:
        expected = {
            name: value
            for name, value in upstream.items()
            if name not in {"offset", "limit", "count"}
        }
        expected["data"] = records
        assert client.get.await_count == 7
        assert result["_pageSize"] == {
            "requested": 10,
            "sent": [10, 1, 1, 1, 1, 1, 1],
            "effective": 1,
            "returned": 7,
        }
        assert result["_count"] == 7
        assert not result.get("incomplete")
        assert [
            call.kwargs["params"].get("offset", 0) for call in client.get.await_args_list
        ] == list(range(7))
    else:
        expected = (
            {**upstream, "data": records[:1], "offset": 0, "limit": 1}
            if "limit" in paging
            else upstream
        )
        assert client.get.await_count == 1
        assert result["_count"] == 1
        if "limit" in paging:
            assert result["_pageSize"] == {
                "requested": 10,
                "sent": [10],
                "effective": 1,
                "returned": 1,
            }
        else:
            assert "_pageSize" not in result
    assert {k: v for k, v in result.items() if not k.startswith("_")} == expected
    assert client.get.call_args.kwargs["key"] == key_label


@pytest.mark.parametrize("key_label", [None, "secondary"])
@pytest.mark.parametrize("field", ["groups", "detections"])
async def test_recognition_object_pages_preserve_unknown_fields(client, registry, key_label, field):
    registry.resolve_key_for_host.return_value = key_label
    upstream = {
        field: [{"id": "one"}],
        "links": {"next": "/next?page=2"},
        "totalCount": 7,
        "traceId": "recognition-trace",
        "future": {"nested": [1, 2]},
    }
    client.get.return_value = upstream
    if field == "groups":
        result = await list_recognition_groups(client, registry, "h", "face", page=1)
    else:
        result = await list_recognition_detections(client, registry, "h", "face", "face_90", page=1)
    assert {k: v for k, v in result.items() if not k.startswith("_")} == upstream
    assert result["_nextPage"] == 2
    assert result["_count"] == 1
    assert client.get.call_args.kwargs["key"] == key_label


@lazy_parametrize("name", lambda: paging_invariants._lz_EXPLICIT_PAGE_TOOLS())
async def test_every_explicit_page_preserves_upstream_envelope(monkeypatch, name):
    upstream = uh.FakeUpstream(
        replay_recordings=False,
        envelope_probe=True,
        envelope_extra={"futurePageField": {"nested": [1, None]}},
    )
    args = {
        **tool_args.generated_args(paging_invariants.TOOLS[name]),
        **paging_invariants._explicit_page_args(name),
    }
    payload = uh.result_payload(await paging_invariants._call(monkeypatch, name, upstream, args))
    pages = [
        s.body
        for s in upstream.served
        if isinstance(s.body, dict) and uh.ENVELOPE_PROBE_KEY in s.body and not s.resolution
    ]
    # Host/site listings are resolution endpoints even when they are the primary tool.
    if name in {"list_hosts", "list_sites", "list_local_sites"}:
        pages = [
            s.body
            for s in upstream.served
            if isinstance(s.body, dict) and uh.ENVELOPE_PROBE_KEY in s.body
        ]
    if name == "list_local_sites":
        pages = [s.body for s in upstream.served if s.path.endswith("/integration/v1/sites")]
    if name == "list_wan_interfaces":
        pages = [s.body for s in upstream.served if s.path.endswith("/wans")]
    if name == "list_protect_events":
        pages = [s.body for s in upstream.served if s.path.endswith("/events")]
        assert len(pages) == 1
        assert isinstance(pages[0], list)
        actual = payload.get("result") if isinstance(payload, dict) else payload
        assert uh.strip_additive(actual, pages[0]) == pages[0]
        return
    bare = [s.body for s in upstream.served if not s.resolution and isinstance(s.body, list)]
    if not pages and len(bare) == 1:
        # A route whose page is a bare JSON array (search_detections' detection-nls) has
        # no envelope to preserve: the page itself comes back verbatim.
        actual = payload.get("result") if isinstance(payload, dict) else payload
        assert uh.strip_additive(actual, bare[0]) == bare[0], (name, payload)
        return
    assert len(pages) == 1, (name, pages)
    assert isinstance(payload, dict), (name, payload)
    page = pages[0]
    for field, value in page.items():
        assert uh.strip_additive(payload.get(field), value) == value, (name, field)
    assert all(k in page or k.startswith("_") for k in payload), (name, payload.keys())
