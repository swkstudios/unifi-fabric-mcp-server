"""Request shapes pinned to Network 11.0.81's UI; fake HTTP, no estate claims."""

from __future__ import annotations

import json

import httpx

from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.tools import network_nat_qos_traffic as nc
from unifi_fabric.tools.network_proav_sandbox import get_multicast_insights


class RequestProbe(uh.FakeUpstream):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.requests = []

    def __call__(self, request):
        if request.url.path.endswith(
            (
                "/traffic-flows/export",
                "/app-traffic-rate",
                "/multicast/clients",
                "/multicast/history",
            )
        ):
            self.requests.append(request)
            if request.url.path.endswith("/export"):
                if request.headers["accept"] != "application/json, text/plain, */*":
                    return httpx.Response(406, text="CSV requires an acceptable media type")
                return httpx.Response(
                    200, text="flow,bytes\n1,42\n", headers={"Content-Type": "text/csv"}
                )
            return httpx.Response(200, json={"data": [{"source": "query"}]})
        return super().__call__(request)


async def test_ui_export_accepts_csv_without_changing_body(monkeypatch):
    upstream = RequestProbe(replay_recordings=False)
    client = uh.install(monkeypatch, upstream)
    body = {"timestampFrom": 1, "timestampTo": 2, "custom": [1, 2]}
    try:
        result = await nc.export_traffic_flows(client, server._registry, uh.HOST, uh.SITE, body)
        request = upstream.requests[-1]
        assert request.headers["content-type"] == "application/json"
        assert json.loads(request.content) == body
        assert result["body"] == "flow,bytes\n1,42\n"
    finally:
        await client.close()


async def test_ui_application_rate_query_and_body_pass_through(monkeypatch):
    upstream = RequestProbe(replay_recordings=False)
    client = uh.install(monkeypatch, upstream)
    params = {"start": 1710000000000, "end": 1710003600000, "includeUnidentified": True}
    body = {"apps": ["custom-app"], "client_macs": [], "future": True}
    try:
        await nc.query_app_traffic_rates(client, server._registry, uh.HOST, uh.SITE, params, body)
        request = upstream.requests[-1]
        assert dict(request.url.params) == {
            k: str(v).lower() if isinstance(v, bool) else str(v) for k, v in params.items()
        }
        assert json.loads(request.content) == body
        assert "period" not in request.url.params
    finally:
        await client.close()


async def test_ui_multicast_routes_forward_query_and_json_body(monkeypatch):
    upstream = RequestProbe(replay_recordings=False)
    client = uh.install(monkeypatch, upstream)
    params = {"start": 1, "end": 2}
    body = {"client_macs": ["02:00:5e:00:00:aa"], "future": {"kept": True}}
    try:
        for view in ("clients", "history"):
            await get_multicast_insights(
                client, server._registry, uh.HOST, uh.SITE, view, query_params=params, body=body
            )
            request = upstream.requests[-1]
            assert request.method == "POST"
            assert request.url.path.endswith("/insights/multicast/" + view)
            assert dict(request.url.params) == {"start": "1", "end": "2"}
            assert json.loads(request.content) == body
    finally:
        await client.close()


async def test_every_export_page_keeps_ui_accept_header(monkeypatch):
    class PagedExport(RequestProbe):
        def __call__(self, request):
            if request.url.path.endswith("/traffic-flows/export"):
                self.requests.append(request)
                assert request.headers["accept"] == "application/json, text/plain, */*"
                number = json.loads(request.content)["pageNumber"]
                return httpx.Response(
                    200,
                    json={
                        "data": [{"flow": number}],
                        "page_number": number,
                        "has_next": number < 2,
                    },
                )
            return super().__call__(request)

    upstream = PagedExport(replay_recordings=False)
    client = uh.install(monkeypatch, upstream)
    body = {"pageNumber": 0, "custom": {"kept": True}}
    try:
        result = await nc.export_traffic_flows(client, server._registry, uh.HOST, uh.SITE, body)
        assert result["data"] == [{"flow": n} for n in range(3)]
        assert len(upstream.requests) == 3
        for number, request in enumerate(upstream.requests):
            assert json.loads(request.content) == {**body, "pageNumber": number}
    finally:
        await client.close()


async def test_read_flow_body_preserves_mask_and_additive_looking_fields(monkeypatch):
    class FlowProbe(RequestProbe):
        def __call__(self, request):
            if request.url.path.endswith("/traffic-flows"):
                self.requests.append(request)
                return httpx.Response(200, json={"data": []})
            return super().__call__(request)

    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    upstream = FlowProbe(replay_recordings=False)
    client = uh.install(monkeypatch, upstream)
    body = {"x_passphrase": "***REDACTED***", "_future": {"nested": [1, None, True]}}
    try:
        await nc.query_traffic_flows(client, server._registry, uh.HOST, uh.SITE, body)
        assert json.loads(upstream.requests[-1].content) == body
    finally:
        await client.close()
