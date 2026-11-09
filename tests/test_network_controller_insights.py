"""Network controller insights (GS3 lane N02).

Every tool is exercised against the real ``UniFiClient`` with only the HTTP transport
mocked: routes, query parameters and bodies sent, verbatim pass-through, the affirmative
Classic ``meta.rc`` rule, the sites-overview page drain, dry-run previews, read-only mode
(zero requests), zero-request input validation, multi-key routing, the registration
contract (annotations derived from source, described properties), the secret-registry
entry for UPS pairing and the recorded live fixtures.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from fastmcp import FastMCP
from pydantic import ValidationError

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric import route_secrets, server
from unifi_fabric._read_only_audit import classify_tool_verbs
from unifi_fabric.client import ClassicApiError, UniFiClient, UniFiConnectionError, _key_fingerprint
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.redaction import REDACTION_MASK
from unifi_fabric.tools import network_controller_insights as nci
from unifi_fabric.tools._classic_cmd import ClassicCommandError

HOST = "console-n02"
SITE = "Default"
SLUG = "default"
NET = f"/v1/connector/consoles/{HOST}/proxy/network"
V2 = f"{NET}/v2/api"
V2S = f"{V2}/site/{SLUG}"
CLASSIC = f"{NET}/api"
CLASSIC_S = f"{CLASSIC}/s/{SLUG}"
MAC = "02:00:5e:00:53:01"
UPS_MAC = "02:00:5e:00:53:02"
OK = {"meta": {"rc": "ok"}, "data": [{"kept": True}]}
FIXTURES = Path(__file__).parent / "fixtures" / "recorded" / "network" / "controller_insights"

READ_TOOLS = {
    "get_network_config_defaults",
    "get_controller_stats",
    "get_network_ui_data",
    "get_sdn_status",
    "list_installed_applications",
    "get_console_general_info",
    "get_first_system_event",
    "list_timezones",
    "list_ups_devices",
    "list_vendor_ids",
    "list_device_models",
    "get_device_fingerprint",
    "list_site_features",
    "get_site_dashboard",
    "list_site_warnings",
    "get_cybersecure_summary",
    "get_site_degradation_status",
    "get_observability_site_health",
    "get_observability_people",
    "list_ulp_user_groups",
    "list_network_anomalies",
}
WRITE_TOOLS = {"get_sites_overview", "set_ups_pairing"}


def registry(key: APIKeyConfig | None = None) -> AsyncMock:
    return AsyncMock(
        **{
            "resolve_key_for_host.return_value": key or APIKeyConfig(key="test-key", label="beta"),
            "resolve_host_id.return_value": HOST,
            "resolve_site_slug.return_value": SLUG,
        }
    )


@pytest.fixture(autouse=True)
def _write_policy_env_reset(monkeypatch):
    """Start every test without a write policy; ``_modes`` sets one for a client's modes."""
    # setenv first so the teardown removes a value a helper set directly in os.environ
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "allow")
    monkeypatch.delenv("UNIFI_WRITE_POLICY")


def _modes(settings: dict) -> dict:
    """Express the retired ``dry_run`` / ``read_only`` client modes as the write policy."""
    settings = dict(settings)
    dry = settings.pop("dry_run", False)
    deny = settings.pop("read_only", False)
    if deny:
        os.environ["UNIFI_WRITE_POLICY"] = "deny"
    elif dry:
        os.environ["UNIFI_WRITE_POLICY"] = "dry-run"
    return settings


def client(handler, **settings: Any) -> UniFiClient:
    settings = _modes(settings)
    c = UniFiClient(Settings(api_key="test-key", **settings))
    c._clients[("beta", _key_fingerprint("test-key"))] = httpx.AsyncClient(
        base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
    )
    return c


class Upstream:
    """Route table: (method, path) -> response factory; records every request."""

    def __init__(self, routes: dict[tuple[str, str], Any]):
        self.routes = routes
        self.seen: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        entry = self.routes.get((req.method, req.url.path))
        if entry is None:
            return httpx.Response(404, json={"errorCode": 404, "message": "no route in test"})
        if callable(entry):
            entry = entry(req)
        if isinstance(entry, httpx.Response):
            return entry
        return httpx.Response(200, json=entry)

    def writes(self) -> list[httpx.Request]:
        return [r for r in self.seen if r.method != "GET"]


def body_of(req: httpx.Request) -> Any:
    return json.loads(req.content) if req.content else None


def query(req: httpx.Request) -> dict[str, str]:
    return dict(req.url.params)


async def run(handler, coro_fn, *args, settings: dict[str, Any] | None = None, **kwargs):
    c = client(handler, **(settings or {}))
    try:
        return await coro_fn(c, registry(), HOST, *args, **kwargs)
    finally:
        await c.close()


# ----------------------------------------------------------------- configuration defaults


@pytest.mark.parametrize("kind", sorted(nci.DEFAULTS_ROUTES))
async def test_every_defaults_kind_reads_its_route_verbatim(kind):
    scope, route = nci.DEFAULTS_ROUTES[kind]
    url = (V2S if scope == "site" else V2) + route
    body = [{"zone_key": "internal"}] if kind == "firewall_zone" else {"unknownFuture": [1]}
    up = Upstream({("GET", url): body})
    assert await run(up, nci.get_network_config_defaults, kind, SITE) == body
    assert len(up.seen) == 1 and not up.seen[0].url.query


def test_defaults_cover_the_twenty_live_kinds():
    assert len(nci.DEFAULTS_ROUTES) == 20
    assert {k for k, (s, _) in nci.DEFAULTS_ROUTES.items() if s == "console"} == {
        "log_levels",
        "super_mgmt",
    }


@pytest.mark.parametrize("kind", ["lan", "wlan", "system_log_setting"])
async def test_site_kind_without_site_fails_before_any_request(kind):
    up = Upstream({})
    reg = registry()
    c = client(up)
    try:
        with pytest.raises(ValueError, match="'site' must be a string"):
            await nci.get_network_config_defaults(c, reg, HOST, kind)
    finally:
        await c.close()
    assert up.seen == []
    reg.resolve_key_for_host.assert_not_called()


async def test_console_kind_needs_no_site_and_resolves_none():
    up = Upstream({("GET", f"{V2}/log-levels/defaults"): {"mgmt": "normal"}})
    reg = registry()
    c = client(up)
    try:
        assert await nci.get_network_config_defaults(c, reg, HOST, "log_levels") == {
            "mgmt": "normal"
        }
    finally:
        await c.close()
    reg.resolve_site_slug.assert_not_called()


async def test_unknown_defaults_kind_fails_listing_choices():
    up = Upstream({})
    with pytest.raises(ValidationError, match="Input should be"):
        await run(up, nci.get_network_config_defaults, "vpn", SITE)
    assert up.seen == []


# ------------------------------------------------------------------------ statistics


async def test_stats_recent_series_sends_only_given_params_in_upstream_form():
    series = [{"siteId": "s", "series": [{"timestamp": 1}]}]
    up = Upstream({("GET", f"{V2}/stats/recent/series"): series})
    result = await run(
        up,
        nci.get_controller_stats,
        "recent_series",
        schema="wanBySiteByDevice",
        start=1760140800,
        end=1760227200,
        bucket="OF_5_MINUTES",
        filter=f"deviceMac.eq('{MAC}')",
        projection=["rxBytes", "txBytes"],
        nested_projection=["byNetworkGroup"],
        no_gaps=False,
    )
    assert result == series
    assert query(up.seen[0]) == {
        "schema": "wanBySiteByDevice",
        "start": "1760140800000",
        "end": "1760227200000",
        "bucket": "OF_5_MINUTES",
        "filter": f"deviceMac.eq('{MAC}')",
        "projection": "values(rxBytes, txBytes),nested(byNetworkGroup)",
        "noGaps": "false",
    }
    await run(
        up, nci.get_controller_stats, "recent_series", schema="clientCountBySite", period="DAY"
    )
    assert query(up.seen[1]) == {"schema": "clientCountBySite", "period": "DAY"}


@pytest.mark.parametrize("view", sorted(nci.STATS_ROUTES))
async def test_every_stats_view_reads_its_route(view):
    up = Upstream({("GET", V2 + nci.STATS_ROUTES[view]): "MODERN"})
    given = {}
    assert await run(up, nci.get_controller_stats, view, **given) == "MODERN"
    assert query(up.seen[0]) == given


class LiveStatsService:
    """GET /v2/api/stats/recent/series as Network 11.0.89 answered it live (2026-10-28)."""

    def __init__(self) -> None:
        self.seen: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        q = dict(req.url.params)
        if "schema" not in q:
            return httpx.Response(
                400,
                json={
                    "errorCode": 400,
                    "message": "Validation failed for argument [0] in public "
                    "org.springframework.http.ResponseEntity",
                },
            )
        if ("period" in q) == ("start" in q):
            return httpx.Response(
                400,
                json={
                    "code": "api.err.InvalidStatQuery",
                    "details": {"invalid_fields": ["period", "start"]},
                    "errorCode": 400,
                    "message": "Exactly one of period or start must be specified",
                },
            )
        return httpx.Response(200, json=[{"siteId": "s", "series": [{"timestamp": 1}]}])


@pytest.mark.parametrize(
    "kwargs,missing",
    [
        ({}, "schema"),
        ({"schema": "clientCountBySite"}, "one of period"),
        ({"period": "DAY"}, "schema"),
        ({"schema": "clientCountBySite", "period": "DAY", "start": 1793188385}, "not both"),
    ],
)
async def test_recent_series_without_schema_and_one_of_period_or_start_is_refused(kwargs, missing):
    """E2E 0.7.0 bug 19: the default call (view recent_series, nothing else) reached the
    statistics service and answered HTTP 400."""
    up = LiveStatsService()
    with pytest.raises(UniFiConnectionError) as info:
        await run(up, nci.get_controller_stats, **kwargs)
    assert info.value.status == 400
    assert len(up.seen) == 1
    expected = {k: str(v * 1000 if k == "start" else v) for k, v in kwargs.items()}
    assert query(up.seen[0]) == expected


@pytest.mark.parametrize(
    "kwargs",
    [
        {"period": "DAY"},
        {"period": "HOUR", "end": 1793191985},
        {"start": 1793188385},
        {"start": 1793188385, "end": 1793191985, "bucket": "OF_1_HOUR"},
    ],
)
async def test_recent_series_with_schema_and_one_of_period_or_start_is_served(kwargs):
    up = LiveStatsService()
    result = await run(up, nci.get_controller_stats, schema="clientCountBySite", **kwargs)
    assert isinstance(result, list) and result[0]["series"] == [{"timestamp": 1}]
    assert len(up.seen) == 1


async def test_stats_not_served_view_is_refused_before_upstream():
    up = Upstream({("GET", f"{V2}/stats"): httpx.Response(405, text="<html>405</html>")})
    with pytest.raises(ValidationError):
        await run(up, nci.get_controller_stats, "stats", schema="clientCountBySite")


async def test_stats_upstream_query_error_reason_kept_in_full():
    reason = {
        "errorCode": 400,
        "code": "api.err.InvalidStatQuery",
        "message": "failed to parse filter expression: unexpected right-bracket at 1:38",
    }
    up = Upstream({("GET", f"{V2}/stats/recent/series"): httpx.Response(400, json=reason)})
    with pytest.raises(UniFiConnectionError) as exc:
        await run(up, nci.get_controller_stats, schema="x", period="DAY", filter="and(a.eq(1))")
    assert "InvalidStatQuery" in str(exc.value) and "right-bracket at 1:38" in str(exc.value)


@pytest.mark.parametrize(
    "kwargs,exc",
    [
        ({"start": "1760140800"}, ValueError),
        ({"end": True}, ValueError),
        ({"no_gaps": "true"}, ValidationError),
        ({"view": "series"}, ValidationError),
    ],
)
async def test_stats_bad_input_fails_before_any_request(kwargs, exc):
    up = Upstream({})
    with pytest.raises(exc):
        await run(up, nci.get_controller_stats, **kwargs)
    assert up.seen == []


# ---------------------------------------------------------------------- sites overview


def _overview_page(number: int, total_pages: int, rows: list[Any]) -> dict[str, Any]:
    return {
        "data": rows,
        "page_number": number,
        "total_page_count": total_pages,
        "total_element_count": 5,
        "unknownFuture": "kept",
    }


async def test_sites_overview_drains_every_page_with_upstream_envelope():
    pages = {0: [{"id": "a"}, {"id": "b"}], 1: [{"id": "c"}, {"id": "d"}], 2: [{"id": "e"}]}

    def answer(req):
        number = body_of(req)["pageNumber"]
        return _overview_page(number, 3, pages[number])

    up = Upstream({("POST", f"{V2}/sites/overview"): answer})
    result = await run(up, nci.get_sites_overview, search_text="b", page_size=1000)
    assert [body_of(r) for r in up.seen] == [
        {"searchText": "b", "pageSize": size, "pageNumber": n}
        for n, size in enumerate((1000, 2, 2))
    ]
    assert result == {
        "data": [{"id": x} for x in "abcde"],
        "total_page_count": 3,
        "total_element_count": 5,
        "unknownFuture": "kept",
        "page_number": 0,
        "_count": 5,
        "_pages": 3,
        "_pageSize": {"requested": 1000, "sent": [1000, 2, 2], "effective": 2, "returned": 5},
    }


async def test_sites_overview_explicit_page_is_one_verbatim_request():
    page = _overview_page(1, 3, [{"id": "c"}])
    up = Upstream({("POST", f"{V2}/sites/overview"): page})
    assert await run(up, nci.get_sites_overview, page=1) == page
    assert [body_of(r) for r in up.seen] == [{"pageNumber": 1}]


async def test_sites_overview_page_cap_marks_incomplete():
    up = Upstream(
        {
            ("POST", f"{V2}/sites/overview"): lambda req: _overview_page(
                body_of(req)["pageNumber"], 4, [{"id": str(body_of(req)["pageNumber"])}]
            )
        }
    )
    result = await run(up, nci.get_sites_overview, settings={"paginate_max_pages": 2})
    assert len(up.seen) == 2
    assert result["_count"] == 2 and result["_incomplete"] is True
    assert "UNIFI_PAGINATE_MAX_PAGES" in result["_incompleteReason"]


def _no_total_page(number: int, rows: list[Any], **extra: Any) -> dict[str, Any]:
    return {"data": rows, "page_number": number, **extra}


@pytest.mark.parametrize("total", [None, "3", 2.5, True])
async def test_sites_overview_missing_or_non_int_total_drains_until_empty_page(total):
    pages = {0: [{"id": "a"}, {"id": "b"}], 1: [{"id": "c"}, {"id": "d"}], 2: [{"id": "e"}]}

    def answer(req):
        number = body_of(req)["pageNumber"]
        extra = {} if total is None else {"total_page_count": total}
        return _no_total_page(number, pages.get(number, []), **extra)

    up = Upstream({("POST", f"{V2}/sites/overview"): answer})
    result = await run(up, nci.get_sites_overview, page_size=1000)
    assert len(up.seen) == 4
    assert result["data"] == [{"id": x} for x in "abcde"]
    assert result["_count"] == 5 and result["_pages"] == 4
    assert "_incomplete" not in result


async def test_sites_overview_missing_total_drains_until_empty_page_without_page_size():
    pages = {0: [{"id": "a"}, {"id": "b"}], 1: [{"id": "c"}, {"id": "d"}]}

    def answer(req):
        number = body_of(req)["pageNumber"]
        return _no_total_page(number, pages.get(number, []))

    up = Upstream({("POST", f"{V2}/sites/overview"): answer})
    result = await run(up, nci.get_sites_overview)
    assert len(up.seen) == 3
    assert result["_count"] == 4 and result["_pages"] == 3 and "_incomplete" not in result


async def test_sites_overview_missing_total_page_cap_marks_incomplete():
    up = Upstream(
        {
            ("POST", f"{V2}/sites/overview"): lambda req: _no_total_page(
                body_of(req)["pageNumber"], [{"id": str(body_of(req)["pageNumber"])}]
            )
        }
    )
    result = await run(up, nci.get_sites_overview, settings={"paginate_max_pages": 3})
    assert len(up.seen) == 3
    assert result["_count"] == 3 and result["_incomplete"] is True
    assert "total unknown" in result["_incompleteReason"]


async def test_sites_overview_repeated_page_stops_the_drain_marked_incomplete():
    up = Upstream({("POST", f"{V2}/sites/overview"): _overview_page(0, 3, [{"id": "a"}])})
    result = await run(up, nci.get_sites_overview)
    assert len(up.seen) == 2
    assert result["data"] == [{"id": "a"}] and result["_incomplete"] is True
    assert "answered as page 0" in result["_incompleteReason"]


async def test_sites_overview_body_without_paged_envelope_is_returned_as_received():
    up = Upstream({("POST", f"{V2}/sites/overview"): [{"id": "a"}]})
    assert await run(up, nci.get_sites_overview) == [{"id": "a"}]


# --------------------------------------------------------------------- Classic reads

CLASSIC_READS = [
    (nci.get_network_ui_data, (), f"{CLASSIC}/ui-data"),
    (nci.get_sdn_status, (SITE,), f"{CLASSIC_S}/stat/sdn"),
    (nci.list_network_anomalies, (SITE,), f"{CLASSIC_S}/stat/anomalies"),
    (nci.list_site_warnings, (SITE, "controller"), f"{CLASSIC_S}/stat/widget/warnings"),
]


@pytest.mark.parametrize("fn,args,url", CLASSIC_READS, ids=lambda v: getattr(v, "__name__", ""))
async def test_classic_reads_return_the_envelope_verbatim(fn, args, url):
    up = Upstream({("GET", url): OK})
    assert await run(up, fn, *args) == OK


@pytest.mark.parametrize("fn,args,url", CLASSIC_READS, ids=lambda v: getattr(v, "__name__", ""))
async def test_classic_rc_error_on_http_200_is_not_success(fn, args, url):
    body = {"meta": {"rc": "error", "msg": "api.err.NoSiteContext"}, "data": []}
    up = Upstream({("GET", url): body})
    with pytest.raises((ClassicCommandError, ClassicApiError)) as exc:
        await run(up, fn, *args)
    message = str(exc.value)
    assert "meta.rc 'error'" in message and "api.err.NoSiteContext" in message
    assert f"GET {url}" in message


async def test_classic_body_without_meta_is_not_success():
    # The one Classic success rule (e4a823fe): HTTP 2xx AND meta.rc == "ok"; a body
    # without the meta envelope is not a confirmed success.
    up = Upstream({("GET", f"{CLASSIC_S}/stat/sdn"): [{"connected": True}]})
    with pytest.raises(ClassicCommandError, match="without the Classic meta envelope"):
        await run(up, nci.get_sdn_status, SITE)


async def test_classic_http_error_keeps_upstream_reason():
    reason = {"meta": {"rc": "error", "msg": "api.err.NotFound"}, "data": []}
    up = Upstream({("GET", f"{CLASSIC_S}/stat/anomalies"): httpx.Response(404, json=reason)})
    with pytest.raises(UniFiConnectionError) as exc:
        await run(up, nci.list_network_anomalies, SITE)
    assert "HTTP 404" in str(exc.value) and "api.err.NotFound" in str(exc.value)


async def test_anomalies_sends_only_given_params_in_ms():
    up = Upstream({("GET", f"{CLASSIC_S}/stat/anomalies"): OK})
    await run(up, nci.list_network_anomalies, SITE, start=1760140800, scale="hourly")
    assert query(up.seen[0]) == {"scale": "hourly", "start": "1760140800000"}


# ------------------------------------------------------------------- v2 console reads

ROOT_READS = [
    (nci.list_installed_applications, (), "/system/installed-applications", [{"name": "x"}]),
    (nci.get_console_general_info, (), "/unifi-core/general-info", {"cloud_access_enabled": 1}),
    (nci.list_timezones, (), "/timezones", [{"timezone": "UTC", "offset": "+00:00"}]),
    (nci.list_ups_devices, (), "/ups/consoles", [{"console_mac": MAC, "ups_mac": None}]),
    (nci.get_device_fingerprint, (1,), "/fingerprint_devices/1", {"dev_ids": {"1": "x"}}),
    (nci.get_first_system_event, ("SETUP_COMPLETED",), "/system/event/SETUP_COMPLETED/first", {}),
]


@pytest.mark.parametrize(
    "fn,args,route,body", ROOT_READS, ids=lambda v: getattr(v, "__name__", None) or ""
)
async def test_console_reads_route_and_verbatim(fn, args, route, body):
    up = Upstream({("GET", V2 + route): body})
    assert await run(up, fn, *args) == body
    assert len(up.seen) == 1


async def test_first_event_literal_null_is_passed_through():
    up = Upstream(
        {
            ("GET", f"{V2}/system/event/SETUP_COMPLETED/first"): httpx.Response(
                200, content=b"null", headers={"content-type": "application/json"}
            )
        }
    )
    assert await run(up, nci.get_first_system_event, "SETUP_COMPLETED") is None


@pytest.mark.parametrize("bad", ["", "../x", "a/.."])
async def test_first_event_unsafe_type_fails_before_any_request(bad):
    up = Upstream({})
    with pytest.raises(ValueError):
        await run(up, nci.get_first_system_event, bad)
    assert up.seen == []


async def test_first_event_type_is_one_encoded_segment():
    route = f"{V2}/system/event/A%20B/first"
    up = GenericUpstream()
    await run(up, nci.get_first_system_event, "A B")
    assert up.seen[0].url.raw_path.decode().startswith(route)


@pytest.mark.parametrize("bad", [True, "1", 1.0])
async def test_fingerprint_source_must_be_an_integer(bad):
    up = Upstream({})
    with pytest.raises(ValidationError):
        await run(up, nci.get_device_fingerprint, bad)
    assert up.seen == []


async def test_fingerprint_negative_source_reaches_upstream():
    reason = {"errorCode": 404, "message": "Device list could not be found for folder"}
    up = Upstream({("GET", f"{V2}/fingerprint_devices/-1"): httpx.Response(404, json=reason)})
    with pytest.raises(UniFiConnectionError, match="could not be found for folder"):
        await run(up, nci.get_device_fingerprint, -1)


# ---------------------------------------------------------------------- v2 site reads

SITE_READS = [
    (nci.list_vendor_ids, (), "/vendor-ids", ["Apple"]),
    (nci.list_device_models, (), "/models", {"model_list": []}),
    (nci.list_site_features, (), "/described-features", [{"name": "ips", "enabled": True}]),
    (nci.get_site_dashboard, (), "/aggregated-dashboard", {"dashboard_meta": {}}),
    (nci.list_site_warnings, ("network",), "/warnings", {"rogue_clients": []}),
    (nci.get_cybersecure_summary, ("DAY",), "/cybersecure/summary", {"threats": 0}),
    (nci.get_site_degradation_status, (), "/degradation-status", {"safe_mode": False}),
    (nci.get_observability_site_health, (), "/observability/sitehealth", {"wan_history": []}),
    (nci.get_observability_people, (), "/observability/people", [{"id": "p"}]),
    (nci.list_ulp_user_groups, (), "/ulp/users_groups", {"users": [], "groups": []}),
]


@pytest.mark.parametrize(
    "fn,args,route,body", SITE_READS, ids=lambda v: getattr(v, "__name__", None) or ""
)
async def test_site_reads_route_and_verbatim(fn, args, route, body):
    up = Upstream({("GET", V2S + route): body})
    assert await run(up, fn, SITE, *args) == body
    assert len(up.seen) == 1


async def test_model_by_id_and_feature_exists_routes():
    up = Upstream(
        {
            ("GET", f"{V2S}/models/UDMPRO"): {"id": "UDMPRO"},
            ("GET", f"{V2S}/features/ips/exists"): {"feature_exists": True},
        }
    )
    assert await run(up, nci.list_device_models, SITE, "UDMPRO") == {"id": "UDMPRO"}
    assert await run(up, nci.list_site_features, SITE, feature="ips") == {"feature_exists": True}


async def test_site_read_params_are_sent_only_when_given_in_upstream_form():
    up = GenericUpstream()
    await run(up, nci.list_site_features, SITE, include_system_features=True)
    await run(up, nci.get_site_dashboard, SITE, history_seconds=86400, radio_activity_ap_mac=MAC)
    await run(up, nci.get_cybersecure_summary, SITE, "WEEK")
    await run(up, nci.get_observability_site_health, SITE, start=1760140800, end=1760227200)
    await run(up, nci.get_site_dashboard, SITE)
    assert [query(r) for r in up.seen] == [
        {"includeSystemFeatures": "true"},
        {"historySeconds": "86400", "radio_activity.access_point_mac": MAC},
        {"period": "WEEK"},
        {"start": "1760140800000", "end": "1760227200000"},
        {},
    ]


async def test_site_warnings_all_returns_both_sources():
    v2 = {"rogue_clients": [], "rogue_dhcps": []}
    up = Upstream(
        {("GET", f"{V2S}/warnings"): v2, ("GET", f"{CLASSIC_S}/stat/widget/warnings"): OK}
    )
    assert await run(up, nci.list_site_warnings, SITE) == {"network": v2, "controller": OK}


async def test_site_warnings_unknown_source_fails_before_any_request():
    up = Upstream({})
    with pytest.raises(ValidationError, match="Input should be"):
        await run(up, nci.list_site_warnings, SITE, "classic")
    assert up.seen == []


@pytest.mark.parametrize("bad", ["", "../models", "x/.."])
async def test_unsafe_model_and_feature_ids_fail_before_any_request(bad):
    for fn, kwargs in (
        (nci.list_device_models, {"model_id": bad}),
        (nci.list_site_features, {"feature": bad}),
    ):
        up = Upstream({})
        with pytest.raises(ValueError):
            await run(up, fn, SITE, **kwargs)
        assert up.seen == [], fn.__name__


# ----------------------------------------------------------------------- UPS pairing


async def test_ups_pair_sends_the_web_app_body():
    up = Upstream({("POST", f"{V2}/ups/pair"): {"ok": True}})
    result = await run(
        up,
        nci.set_ups_pairing,
        "pair",
        MAC,
        ups_mac=UPS_MAC,
        username="admin@example.com",
        password="example-pass",
    )
    assert body_of(up.seen[0]) == {
        "console_mac": MAC,
        "username": "admin@example.com",
        "password": "example-pass",
        "ups_mac": UPS_MAC,
    }
    assert result == {"ok": True}


async def test_ups_unpair_sends_only_the_console_mac_and_passes_an_empty_body():
    up = Upstream({("POST", f"{V2}/ups/unpair"): httpx.Response(200)})
    result = await run(up, nci.set_ups_pairing, "unpair", MAC)
    assert body_of(up.seen[0]) == {"console_mac": MAC}
    assert result is None


async def test_ups_upstream_error_reason_kept():
    reason = {"errorCode": 400, "code": "api.err.UpsConsoleNotFound", "message": "not found"}
    up = Upstream({("POST", f"{V2}/ups/unpair"): httpx.Response(400, json=reason)})
    with pytest.raises(UniFiConnectionError, match="UpsConsoleNotFound"):
        await run(up, nci.set_ups_pairing, "unpair", "00:00:5e:00:53:01")


@pytest.mark.parametrize(
    "args,kwargs,exc",
    [
        (("link", MAC), {}, ValidationError),
        (("pair", ""), {}, ValueError),
        (("pair", f"{MAC}\n"), {}, ValueError),
        (("pair", MAC), {"ups_mac": " "}, ValueError),
    ],
)
async def test_ups_bad_input_fails_before_any_request(args, kwargs, exc):
    up = Upstream({})
    with pytest.raises(exc):
        await run(up, nci.set_ups_pairing, *args, **kwargs)
    assert up.seen == []


async def test_ups_password_never_in_a_validation_message():
    up = Upstream({})
    with pytest.raises(ValueError) as exc:
        await run(up, nci.set_ups_pairing, "pair", "", password="sentinel-pass-0001")
    assert "sentinel-pass-0001" not in str(exc.value)


# ------------------------------------------------------------ cross-tool properties

CALLS: dict[str, tuple[Any, tuple[Any, ...], dict[str, Any]]] = {
    "get_network_config_defaults": (nci.get_network_config_defaults, ("lan", SITE), {}),
    "get_controller_stats": (nci.get_controller_stats, ("source",), {}),
    "get_sites_overview": (nci.get_sites_overview, (), {}),
    "get_network_ui_data": (nci.get_network_ui_data, (), {}),
    "get_sdn_status": (nci.get_sdn_status, (SITE,), {}),
    "list_installed_applications": (nci.list_installed_applications, (), {}),
    "get_console_general_info": (nci.get_console_general_info, (), {}),
    "get_first_system_event": (nci.get_first_system_event, ("SETUP_COMPLETED",), {}),
    "list_timezones": (nci.list_timezones, (), {}),
    "list_ups_devices": (nci.list_ups_devices, (), {}),
    "set_ups_pairing": (nci.set_ups_pairing, ("unpair", MAC), {}),
    "list_vendor_ids": (nci.list_vendor_ids, (SITE,), {}),
    "list_device_models": (nci.list_device_models, (SITE,), {}),
    "get_device_fingerprint": (nci.get_device_fingerprint, (0,), {}),
    "list_site_features": (nci.list_site_features, (SITE,), {}),
    "get_site_dashboard": (nci.get_site_dashboard, (SITE,), {}),
    "list_site_warnings": (nci.list_site_warnings, (SITE,), {}),
    "get_cybersecure_summary": (nci.get_cybersecure_summary, (SITE, "DAY"), {}),
    "get_site_degradation_status": (nci.get_site_degradation_status, (SITE,), {}),
    "get_observability_site_health": (nci.get_observability_site_health, (SITE,), {}),
    "get_observability_people": (nci.get_observability_people, (SITE,), {}),
    "list_ulp_user_groups": (nci.list_ulp_user_groups, (SITE,), {}),
    "list_network_anomalies": (nci.list_network_anomalies, (SITE,), {}),
}


class GenericUpstream(Upstream):
    """Answers every route a tool in this module calls, shaped like the live console."""

    def __init__(self) -> None:
        super().__init__({})

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        path = req.url.path
        if path.endswith("/sites/overview"):
            return httpx.Response(200, json=_overview_page(0, 1, [{"id": "a"}]))
        if "/proxy/network/api/" in path:
            return httpx.Response(200, json=OK)
        return httpx.Response(200, json={"ok": True})


def test_calls_cover_every_tool():
    assert set(CALLS) == READ_TOOLS | WRITE_TOOLS == set(nci.ROUTE_CHOICES)


@pytest.mark.parametrize("name", sorted(CALLS))
async def test_every_tool_valid_call_reaches_upstream(name):
    fn, args, kwargs = CALLS[name]
    up = GenericUpstream()
    await run(up, fn, *args, **kwargs)
    assert up.seen, name
    if name in WRITE_TOOLS:
        assert up.writes(), f"{name} sent no POST"
    else:
        assert not up.writes(), f"read tool {name} sent a write"


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
async def test_dry_run_previews_every_write_and_sends_none(name):
    fn, args, kwargs = CALLS[name]
    up = GenericUpstream()
    result = await run(up, fn, *args, settings={"dry_run": True}, **kwargs)
    assert up.writes() == [], name
    assert result["status"] == "dry_run" and result["dryRun"] is True, result
    assert result["preview"]["method"] == "POST"
    assert "verified" not in result and "_count" not in result


async def test_dry_run_preview_masks_the_ups_password_only_under_redact_secrets():
    for redact, expected in ((False, "example-pass"), (True, REDACTION_MASK)):
        up = GenericUpstream()
        result = await run(
            up,
            nci.set_ups_pairing,
            "pair",
            MAC,
            password="example-pass",
            settings={"dry_run": True, "redact_secrets": redact},
        )
        assert result["preview"]["body"]["password"] == expected


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
async def test_read_only_mode_refuses_every_write_before_any_request(name, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    fn, args, kwargs = CALLS[name]
    up = GenericUpstream()
    with pytest.raises(Exception, match="read-only mode"):
        await run(up, fn, *args, **kwargs)
    assert up.seen == []


@pytest.mark.parametrize("name", sorted(READ_TOOLS))
async def test_read_only_mode_leaves_reads_working(name, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    fn, args, kwargs = CALLS[name]
    up = GenericUpstream()
    await run(up, fn, *args, **kwargs)
    assert up.seen


@pytest.mark.parametrize("bad", ["", " Home", "Home\n"])
@pytest.mark.parametrize("name", sorted(n for n in CALLS if SITE in CALLS[n][1]))
async def test_malformed_site_selector_fails_before_any_request(name, bad):
    fn, args, kwargs = CALLS[name]
    broken = tuple(bad if a == SITE else a for a in args)
    up = GenericUpstream()
    c = client(up)
    reg = AsyncMock(
        **{
            "resolve_key_for_host.return_value": APIKeyConfig(key="test-key", label="beta"),
            "resolve_host_id.return_value": HOST,
        }
    )

    async def real_slug(name_or_id, host_id, *, key=None):
        from unifi_fabric.selector_args import check_selector

        check_selector("site", name_or_id)
        return SLUG

    reg.resolve_site_slug.side_effect = real_slug
    try:
        with pytest.raises(ValueError, match="'site'"):
            await fn(c, reg, HOST, *broken, **kwargs)
    finally:
        await c.close()
    assert up.seen == [], name


async def test_multikey_data_requests_ride_the_owning_key(multikey_client, multikey_registry):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_host_id = AsyncMock(return_value="console-beta-1")
    multikey_registry.resolve_site_slug = AsyncMock(return_value=SLUG)
    seen: list[str | None] = []

    async def capture(path, *a, key=None, **kw):
        seen.append(key.label if key else None)
        if path.endswith("/sites/overview"):
            return _overview_page(0, 1, [])
        return {}

    async def capture_request(method, path, *a, key=None, **kw):
        seen.append(key.label if key else None)
        return httpx.Response(200, json=OK)

    for method in ("get", "post"):
        setattr(multikey_client, method, AsyncMock(side_effect=capture))
    multikey_client.request = AsyncMock(side_effect=capture_request)
    assert "get_network_config_defaults" in CALLS
    for name, (fn, args, kwargs) in sorted(CALLS.items()):
        seen.clear()
        await fn(multikey_client, multikey_registry, "Beta-Branch", *args, **kwargs)
        assert seen and set(seen) == {"beta"}, (name, seen)


# --------------------------------------------------------------- registration contract


def _registered() -> dict[str, Any]:
    mcp = FastMCP("n02-test")
    nci.register(mcp, lambda: (None, None))
    res = mcp.list_tools()
    tools = asyncio.run(res) if inspect.isawaitable(res) else res
    return {t.name: t for t in tools}


def test_register_adds_exactly_the_twenty_three_tools():
    assert set(_registered()) == READ_TOOLS | WRITE_TOOLS
    assert len(READ_TOOLS | WRITE_TOOLS) == 23


def test_every_n02_tool_appears_in_the_real_server_catalog():
    tools = asyncio.run(server.mcp.list_tools())
    names = {tool.name for tool in tools}
    assert READ_TOOLS | WRITE_TOOLS <= names


def test_annotations_match_the_source_derived_write_set():
    tools = _registered()
    verbs = classify_tool_verbs(list(tools.values()))
    assert {name for name, v in verbs.items() if v} == WRITE_TOOLS
    for name, tool in tools.items():
        writes = name in WRITE_TOOLS
        hints = tool.annotations.model_dump(by_alias=True)
        assert hints["readOnlyHint"] is (not writes), name


def test_every_property_is_described_and_descriptions_fit():
    tools = _registered()
    assert set(tools) == READ_TOOLS | WRITE_TOOLS
    for name, tool in tools.items():
        assert tool.description and len(tool.description) <= 2048, name
        props = (tool.parameters or {}).get("properties", {})
        assert props, name
        for prop, schema in props.items():
            assert schema.get("description"), f"{name}.{prop} has no description"


def test_closed_choices_are_advertised_in_the_schema():
    tools = _registered()
    kind = json.dumps(tools["get_network_config_defaults"].parameters["properties"]["kind"])
    assert all(k in kind for k in nci.DEFAULTS_ROUTES)
    view = json.dumps(tools["get_controller_stats"].parameters["properties"]["view"])
    assert all(v in view for v in nci.STATS_ROUTES)


def test_write_tools_accept_and_ignore_confirm():
    tools = _registered()
    for name in WRITE_TOOLS:
        assert "confirm" in tools[name].parameters["properties"], name
    for name in READ_TOOLS:
        assert "confirm" not in tools[name].parameters["properties"], name


def test_the_only_raise_site_is_the_classic_rc_check():
    """Every pre-upstream refusal here comes from an already-registered helper (selector
    and path-segment checks, integer epoch seconds, read-only mode, pydantic choice
    validation). The raises are the affirmative Classic meta.rc rule on Classic reads
    (upstream-judged), handed to the refusal registry as
    tools/network_controller_insights.py:_classic_get, ."""
    tree = ast.parse(Path(nci.__file__).read_text())
    sites = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            sites += [node.name for n in ast.walk(node) if isinstance(n, ast.Raise)]
    assert sites == ["_classic_get"]


def test_route_choices_record_source_route_and_reason_for_every_tool():
    for name, (source, route, reason) in nci.ROUTE_CHOICES.items():
        assert source in {"v2", "classic", "v2+classic (SPLIT)"}, name
        assert route and reason, name
    assert {n for n, (s, _, _) in nci.ROUTE_CHOICES.items() if s == "classic"} == {
        "get_network_ui_data",
        "get_sdn_status",
        "list_network_anomalies",
    }


# ------------------------------------------------------------------- secret registry


def test_ups_secret_entry_matches_its_route_and_relay_path():
    entry = nci.UPS_PAIRING_SECRET
    assert entry.verified and entry.request_fields == ("password",)
    assert entry.matches("POST", f"{V2}/ups/pair")
    assert entry.matches("POST", entry.relay_path)
    assert not entry.matches("POST", f"{V2}/ups/unpair")
    assert not entry.matches("GET", f"{V2}/ups/pair")


def test_ups_secret_entry_scrubs_and_masks_in_central_registry():
    args = {"host": HOST, "action": "pair", "console_mac": MAC, "password": "sentinel-0001"}
    assert route_secrets.tool_call_secrets("set_ups_pairing", args) == ("sentinel-0001",)
    body = {"console_mac": MAC, "password": "sentinel-0001"}
    path = f"{V2}/ups/pair"
    assert route_secrets.mask_request_body("POST", path, body, redact_secrets=False) == body
    masked = route_secrets.mask_request_body("POST", path, body, redact_secrets=True)
    assert masked["password"] == route_secrets.MASK and masked["console_mac"] == MAC


# ------------------------------------------------------------------ recorded fixtures


def _fixture_files() -> list[Path]:
    return sorted(FIXTURES.glob("*.json"))


def test_recorded_fixtures_exist_for_every_live_read_tool():
    recorded = {json.loads(p.read_text())["recorded_by_tool"] for p in _fixture_files()}
    assert READ_TOOLS <= recorded, sorted(READ_TOOLS - recorded)


def _replay_route(rec: dict[str, Any]) -> str:
    return NET + rec["request"]["path"].split("/proxy/network", 1)[1].split("?", 1)[0]


@pytest.mark.parametrize("path", _fixture_files(), ids=lambda p: p.stem)
async def test_recorded_fixture_replays_through_its_tool(path):
    """Every recorded live exchange replays through the tool that recorded it: a 200 body
    comes back verbatim (a sites-overview drain is compared on its rows).
    Errors keep the upstream status and reason."""
    rec = json.loads(path.read_text())
    route = _replay_route(rec)
    method = rec["request"]["method"]
    status = rec["status"]
    if "body" in rec:
        response = httpx.Response(status, json=rec["body"])
    else:
        response = httpx.Response(status, text=rec.get("text", ""))
    up = Upstream({(method, route): response})
    fn = getattr(nci, rec["recorded_by_tool"])
    args, kwargs = tuple(rec.get("args", [])), dict(rec.get("kwargs", {}))
    if (
        rec["recorded_by_tool"] == "get_controller_stats"
        and args
        and args[0] in {"stats", "recent"}
    ):
        with pytest.raises(ValidationError):
            await run(up, fn, *args, **kwargs)
        assert up.seen == []
        return
    if 200 <= status < 300:
        result = await run(up, fn, *args, **kwargs)
        if rec["recorded_by_tool"] == "get_sites_overview" and "page" not in kwargs:
            assert result["data"] == rec["body"]["data"]
            assert result["_count"] == len(rec["body"]["data"])
        else:
            assert result == rec.get("body"), path.stem
    else:
        with pytest.raises(UniFiConnectionError) as exc:
            await run(up, fn, *args, **kwargs)
        assert f"HTTP {status}" in str(exc.value)
        if isinstance(rec.get("body"), dict):
            for k in rec["body"]:
                assert f'"{k}"' in str(exc.value), k


# Registry and resolution regressions: HTTP transport only.
def cold_client(up, **settings):
    from unifi_fabric.registry import Registry

    key = APIKeyConfig(key="test-key", label="beta")
    c = UniFiClient(Settings(api_keys=[key], **settings))
    c._clients[(key.label, _key_fingerprint(key.key))] = httpx.AsyncClient(
        base_url="https://api.ui.com", transport=httpx.MockTransport(up)
    )
    return c, Registry(c)


def cold_upstream(routes):
    return Upstream(
        {
            ("GET", "/v1/hosts"): {"data": [{"id": HOST, "reportedState": {"name": HOST}}]},
            ("GET", f"{NET}/integration/v1/sites"): {
                "offset": 0,
                "limit": 25,
                "count": 1,
                "totalCount": 1,
                "data": [
                    {
                        "id": "00000000-0000-4000-8000-000000000001",
                        "description": SITE,
                        "internalReference": SLUG,
                    }
                ],
            },
            **routes,
        }
    )


@pytest.mark.parametrize("name", sorted(CALLS))
@pytest.mark.parametrize("bad", ["", "  "])
async def test_review_cold_registry_blank_host_sends_zero_requests(name, bad):
    up = Upstream({})
    c, reg = cold_client(up)
    fn, args, kwargs = CALLS[name]
    try:
        with pytest.raises(ValueError):
            await fn(c, reg, bad, *args, **kwargs)
    finally:
        await c.close()
    assert up.seen == []


@pytest.mark.parametrize(
    "name", sorted(name for name, (_, args, _) in CALLS.items() if SITE in args)
)
@pytest.mark.parametrize("bad", ["", "  ", None])
async def test_review_cold_registry_blank_site_sends_zero_requests(name, bad):
    up = Upstream({})
    c, reg = cold_client(up)
    fn, args, kwargs = CALLS[name]
    args = tuple(bad if arg == SITE else arg for arg in args)
    try:
        with pytest.raises(ValueError):
            await fn(c, reg, HOST, *args, **kwargs)
    finally:
        await c.close()
    assert up.seen == []


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("relay", [False, True])
@pytest.mark.parametrize("status", [400, 403, 500])
async def test_review_ups_echo_error_respects_call_scope_redaction_policy(
    redact, relay, status, caplog
):
    secret = "synthetic-N02-pairing-password"
    reason = {"code": "api.err.PairFailed", "message": f"Rejected {secret}", "other": "kept"}
    up = cold_upstream({("POST", f"{V2}/ups/pair"): httpx.Response(status, json=reason)})
    c, reg = cold_client(up, redact_secrets=redact)
    try:
        if relay:
            # Exact central path used by connector_write, including its raw error response.
            response = await c.request(
                "POST",
                f"{V2}/ups/pair",
                json={"password": secret},
                raise_on_error=False,
                strip_additive=False,
                always_write=True,
            )
            assert (secret not in response.text) is redact
            assert "PairFailed" in response.text and "kept" in response.text
        else:
            with pytest.raises(UniFiConnectionError) as exc:
                await nci.set_ups_pairing(c, reg, HOST, "pair", MAC, password=secret)
            assert (secret not in str(exc.value)) is redact
            assert "PairFailed" in str(exc.value) and "kept" in str(exc.value)
        assert secret not in caplog.text
        assert body_of(up.writes()[0])["password"] == secret
        # Scope ends at return/raise: it must not redact another call's ordinary data.
        up.routes[("GET", f"{V2}/timezones")] = {"message": secret}
        assert await nci.list_timezones(c, reg, HOST) == {"message": secret}
    finally:
        await c.close()


@pytest.mark.parametrize("redact", [False, True])
async def test_review_ups_transport_exception_respects_redaction_policy(redact, caplog):
    secret = "synthetic-N02-transport-password"

    def fail(req):
        raise httpx.ConnectError(f"upstream echoed {secret}", request=req)

    up = cold_upstream({("POST", f"{V2}/ups/pair"): fail})
    c, reg = cold_client(up, redact_secrets=redact)
    try:
        with pytest.raises(UniFiConnectionError) as exc:
            await nci.set_ups_pairing(c, reg, HOST, "pair", MAC, password=secret)
        assert (secret not in str(exc.value)) is redact
        # The public exception is intentionally raised without a chained transport cause.
        assert exc.value.__cause__ is None
        assert secret not in caplog.text
    finally:
        await c.close()


async def test_review_ups_response_is_upstream_body_verbatim():
    body = {"ok": True, "future": [1, {"unchanged": True}]}
    up = cold_upstream({("POST", f"{V2}/ups/pair"): body})
    c, reg = cold_client(up)
    try:
        assert await nci.set_ups_pairing(c, reg, HOST, "pair", MAC) == body
    finally:
        await c.close()


@pytest.mark.parametrize("cap", [1, 2, None])
async def test_review_overview_preserves_metadata_and_prefixes_additions(cap):
    up = cold_upstream(
        {
            ("POST", f"{V2}/sites/overview"): lambda req: _overview_page(
                body_of(req)["pageNumber"], 3, [{"id": body_of(req)["pageNumber"]}]
            )
        }
    )
    c, reg = cold_client(up, paginate_max_pages=cap)
    try:
        result = await nci.get_sites_overview(c, reg, HOST)
        assert result["page_number"] == 0
        assert result["total_page_count"] == 3
        assert result["unknownFuture"] == "kept"
        assert len(up.writes()) == (cap or 3)
        assert result["_count"] == (cap or 3)
        assert set(result) - set(_overview_page(0, 3, [])) <= {
            "_count",
            "_pages",
            "_incomplete",
            "_incompleteReason",
        }
        assert result.get("_incomplete", False) is (cap is not None)
    finally:
        await c.close()


@pytest.mark.parametrize("view", ["stats", "recent"])
async def test_review_unsupported_stats_views_fail_before_resolution(view):
    up = Upstream({})
    c, reg = cold_client(up)
    try:
        with pytest.raises(ValidationError):
            await nci.get_controller_stats(c, reg, HOST, view)
    finally:
        await c.close()
    assert up.seen == []


def test_review_ups_secret_is_registered_for_typed_and_relay_calls():
    secret = "synthetic-N02-registry-password"
    assert route_secrets.tool_call_secrets("set_ups_pairing", {"password": secret}) == (secret,)
    assert route_secrets.request_secrets("POST", f"{V2}/ups/pair", {"password": secret}) == (
        secret,
    )


def test_review_registration_derives_annotations():
    source = inspect.getsource(nci.register)
    assert "classify_tool_verbs" in source or "derive_write_tools" in source
    assert "annotations=READ_ONLY" not in source and "annotations=WRITE" not in source


@pytest.mark.parametrize("redact", [False, True])
async def test_review_pairing_success_echo_and_preview_respect_explicit_opt_in(redact):
    secret = "synthetic-N02-success-password"
    body = {"message": f"echo {secret}", "password": secret, "keep": 7}
    up = cold_upstream({("POST", f"{V2}/ups/pair"): body})
    c, reg = cold_client(up, redact_secrets=redact)
    try:
        result = await nci.set_ups_pairing(c, reg, HOST, "pair", MAC, password=secret)
        assert result["keep"] == 7
        assert (secret in json.dumps(result)) is (not redact)
        assert body_of(up.writes()[0])["password"] == secret
    finally:
        await c.close()


@pytest.mark.parametrize("redact", [False, True])
async def test_review_real_connector_ups_error_body_respects_redaction_policy(redact):
    from unifi_fabric.tools.connector import connector_write

    secret = "synthetic-N02-real-relay-password"
    up = cold_upstream(
        {
            ("POST", f"{V2}/ups/pair"): httpx.Response(
                400, json={"message": f"rejected {secret}", "code": "PairFailed"}
            )
        }
    )
    c, reg = cold_client(up, redact_secrets=redact)
    try:
        result = await connector_write(
            c, reg, HOST, "POST", "network/v2/api/ups/pair", body={"password": secret}
        )
        assert (secret not in json.dumps(result)) is redact
        assert "PairFailed" in json.dumps(result)
        assert body_of(up.writes()[0])["password"] == secret
    finally:
        await c.close()


async def test_review_parallel_requests_do_not_share_submitted_secret_scope():
    secret = "synthetic-N02-parallel-password"
    entered = asyncio.Event()
    release = asyncio.Event()
    seen = []

    async def answer(req):
        seen.append(req)
        if req.method == "POST":
            entered.set()
            await release.wait()
            return httpx.Response(400, json={"message": f"rejected {secret}"})
        return httpx.Response(200, json={"message": secret})

    c, _ = cold_client(answer, redact_secrets=True)
    try:
        task = asyncio.create_task(
            c.request("POST", f"{V2}/ups/pair", json={"password": secret}, raise_on_error=False)
        )
        await entered.wait()
        try:
            assert await c.get(f"{V2}/timezones") == {"message": secret}
        finally:
            release.set()
        response = await task
        assert secret not in response.text
    finally:
        await c.close()


_LIST_FIXTURES = [
    p for p in _fixture_files() if json.loads(p.read_text())["recorded_by_tool"].startswith("list_")
]


@pytest.mark.parametrize("path", _LIST_FIXTURES, ids=lambda p: p.stem)
@pytest.mark.parametrize("cap", [1, 2])
async def test_review_every_unpaginated_list_keeps_all_rows_under_page_cap(path, cap):
    """These routes return complete bodies without a pagination contract; no truncation.

    Overview is the paged route and has separate complete/capped drain tests.
    """
    rec = json.loads(path.read_text())
    assert rec["status"] == 200
    body = rec["body"]
    # More than a usual page: a cap must never truncate an unpaged collection.
    if isinstance(body, list):
        body = (body or [{"kept": True}]) * 201
    elif isinstance(body, dict):
        body = {k: (v * 201 if isinstance(v, list) else v) for k, v in body.items()}
    route = _replay_route(rec)
    up = cold_upstream({("GET", route): body})
    c, reg = cold_client(up, paginate_max_pages=cap)
    try:
        result = await getattr(nci, rec["recorded_by_tool"])(
            c, reg, HOST, *rec.get("args", []), **rec.get("kwargs", {})
        )
        assert result == body
        assert len([r for r in up.seen if r.url.path == route]) == 1
    finally:
        await c.close()


@pytest.mark.parametrize("redact", [False, True])
async def test_review_route_response_mask_preserves_duplicate_headers(redact):
    path = f"{V2S}/matter/nodes"
    body = {"setup_code": "synthetic-N02-response-code", "keep": 3}
    up = Upstream(
        {
            ("POST", path): httpx.Response(
                200, json=body, headers=[("set-cookie", "one=1"), ("set-cookie", "two=2")]
            )
        }
    )
    c, _ = cold_client(up, redact_secrets=redact)
    try:
        response = await c.request("POST", path)
        assert response.headers.get_list("set-cookie") == ["one=1", "two=2"]
        assert response.json()["keep"] == 3
        assert response.json()["setup_code"] == (
            route_secrets.MASK if redact else body["setup_code"]
        )
        assert int(response.headers["content-length"]) == len(response.content)
    finally:
        await c.close()


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("relay", [False, True])
async def test_review_tool_scope_resolution_error_respects_redaction_policy(redact, relay, caplog):
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    from unifi_fabric.secret_scrub import configured_secrets
    from unifi_fabric.server import SecretScrubMiddleware
    from unifi_fabric.tools.connector import connector_write

    secret = "synthetic-N02-before-pairing-password"
    up = cold_upstream(
        {
            ("GET", "/v1/hosts"): httpx.Response(
                400, json={"message": f"resolution rejected {secret}", "code": "ResolveFailed"}
            )
        }
    )
    c, reg = cold_client(up, redact_secrets=redact)
    mcp = FastMCP("n02-review-tool-scope")
    nci.register(mcp, lambda: (c, reg))
    mcp.add_middleware(SecretScrubMiddleware())

    @mcp.tool(name="fabric_connector_post")
    async def relay_post(host: str, path: str, body: dict[str, Any]) -> Any:
        return await connector_write(c, reg, host, "POST", path, body=body)

    name = "fabric_connector_post" if relay else "set_ups_pairing"
    arguments = (
        {"host": HOST, "path": "network/v2/api/ups/pair", "body": {"password": secret}}
        if relay
        else {
            "host": HOST,
            "action": "pair",
            "console_mac": "02:00:5e:00:53:01",
            "password": secret,
        }
    )
    try:
        async with Client(mcp) as mc:
            with pytest.raises(ToolError) as exc:
                await mc.call_tool(name, arguments)
        assert (secret not in str(exc.value)) is redact
        assert "ResolveFailed" in str(exc.value)
        assert secret not in caplog.text
        assert len(up.seen) == 1
        assert up.seen[0].url.path == "/v1/hosts"
        assert secret not in configured_secrets(c._settings)
    finally:
        await c.close()
