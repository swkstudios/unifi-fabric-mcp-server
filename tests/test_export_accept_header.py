"""Synthetic exports retain the UI Accept header across every drained page."""

from __future__ import annotations

import json

import pytest

from tests import upstream_harness as uh
from tests.test_traffic_flows_page_batching import FlowsUpstream
from unifi_fabric import server
from unifi_fabric.tools import network_nat_qos_traffic as nc


class ExportAcceptUpstream(FlowsUpstream):
    def __init__(self):
        super().__init__(total=5, clamp=2, replay_recordings=False)
        self.accept_headers = []

    def __call__(self, request):
        if request.url.path.endswith("/traffic-flows/export"):
            self.accept_headers.append(request.headers.get("accept"))
        return super().__call__(request)


@pytest.mark.parametrize("requested", [None, 7, 10000])
async def test_every_export_page_keeps_ui_accept_header(monkeypatch, requested):
    upstream = ExportAcceptUpstream()
    client = uh.install(monkeypatch, upstream)
    body = {"timestampFrom": 1, "custom": {"kept": [1, 2]}}
    if requested is not None:
        body["pageSize"] = requested
    original = json.loads(json.dumps(body))
    try:
        result = await nc.export_traffic_flows(client, server._registry, uh.HOST, uh.SITE, body)
        assert result["data"] == [{"id": i} for i in range(5)]
        assert result["_pages"] == 3
        assert "incomplete" not in result
        assert upstream.accept_headers == ["application/json, text/plain, */*"] * 3
        assert [page.get("pageNumber", 0) for page in upstream.flow_requests] == [0, 1, 2]
        assert all(page["custom"] == original["custom"] for page in upstream.flow_requests)
        assert all(page["timestampFrom"] == 1 for page in upstream.flow_requests)
        assert body == original
    finally:
        await client.close()
