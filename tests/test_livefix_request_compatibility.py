"""Native-body precedence and UI arrays keep complete bodies and non-first-key routing."""

from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest

from tests import upstream_harness as uh
from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric import server


@pytest.mark.parametrize(
    ("name", "arguments", "body"),
    [
        (
            "assign_detections_to_recognition_group",
            {
                "type": "face",
                "assignment": {"objectIds": ["synthetic-detection"], "groupId": "face_1"},
            },
            {"objectIds": ["synthetic-detection"], "groupId": "face_1"},
        ),
        (
            "merge_recognition_groups",
            {
                "type": "face",
                "merge": {"fromGroupIds": ["face_2"], "toGroupId": "face_1"},
            },
            {"fromGroupIds": ["face_2"], "toGroupId": "face_1"},
        ),
        (
            "reset_switch_port",
            {"site": uh.SITE, "port_id": uh.ARG_MAC, "body": {"port_idx": 1}},
            {"port_idx": 1},
        ),
        (
            "query_switch_mac_tables",
            {"site": uh.SITE, "query": {"mac": uh.ARG_MAC, "ports": [1, 24]}},
            [{"mac": uh.ARG_MAC, "ports": [1, 24]}],
        ),
        (
            "query_switch_mac_tables",
            {"site": uh.SITE, "queries": [{"mac": uh.ARG_MAC, "ports": [1, 24]}]},
            [{"mac": uh.ARG_MAC, "ports": [1, 24]}],
        ),
        (
            "query_switch_mac_tables",
            {
                "site": uh.SITE,
                "queries": [{"mac": uh.ARG_MAC, "ports": [1]}],
                "query": {"future": {"nested": [None, 7]}},
            },
            {"future": {"nested": [None, 7]}},
        ),
        (
            "reset_switch_port",
            {
                "site": uh.SITE,
                "device": uh.ARG_MAC,
                "ports": [{"port_idx": 1}],
                "body": {"future": {"nested": [None, 7]}},
            },
            {"future": {"nested": [None, 7]}},
        ),
    ],
)
async def test_compatibility_inputs_write_once_on_the_owning_key(
    monkeypatch, multikey_client, multikey_registry, name, arguments, body
):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_site_slug = AsyncMock(return_value="default")
    upstream = uh.FakeUpstream(replay_recordings=False)
    sessions = {}

    async def http_session(key):
        if key.label not in sessions:
            sessions[key.label] = httpx.AsyncClient(
                base_url="https://api.ui.com",
                headers={"X-API-KEY": key.key},
                transport=httpx.MockTransport(upstream),
            )
        return sessions[key.label]

    monkeypatch.setattr(multikey_client, "_get_client", http_session)
    monkeypatch.setattr(server, "_client", multikey_client)
    monkeypatch.setattr(server, "_registry", multikey_registry)
    try:
        result = await server.mcp.call_tool(name, {"host": "Beta-Branch", **arguments})
        writes = [row for row in upstream.served if row.method != "GET"]
        assert len(writes) == 1
        assert writes[0].sent_json == body
        assert writes[0].api_key == "k-beta"
        assert "/consoles/console-beta-1/" in writes[0].path
        assert uh.result_payload(result) == writes[0].body
    finally:
        for session in sessions.values():
            await session.aclose()
        await multikey_client.close()
