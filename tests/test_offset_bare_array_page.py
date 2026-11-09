"""Explicit-page offset lists return the upstream page unchanged, whatever its shape.

A page the upstream answers as a bare array is returned as that array by every tool
that pages through the shared offset helper (derived by spying on the helper across
every read tool with ``offset`` / ``limit``), never wrapped in an invented
``{"data": ...}`` key.
"""

from __future__ import annotations

import functools
import importlib
import logging
import pkgutil
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from unifi_fabric import tools as tools_pkg
from unifi_fabric.tools import _pagination

TOOLS = cti.TOOLS
_call = cti._call


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _payload(res: Any) -> Any:
    """What a client receives, with FastMCP's ``{"result": ...}`` list wrapper undone."""
    body = uh.result_payload(res)
    if isinstance(body, dict) and set(body) == {"result"}:
        return body["result"]
    return body


# =========================================================================== explicit-page shape
@dataclass
class _BareArrayPages(uh.FakeUpstream):
    """Answers every explicitly requested page (``limit=2``) as a bare JSON array of the
    records the normal envelope would carry."""

    bare_pages: list[Any] = field(default_factory=list)

    def __call__(self, req: httpx.Request) -> httpx.Response:
        resp = super().__call__(req)
        query = dict(parse_qsl(req.url.query.decode()))
        if req.method == "GET" and query.get("limit") == "2" and resp.status_code == 200:
            body = resp.json()
            if isinstance(body, dict) and isinstance(body.get("data"), list):
                self.bare_pages.append(body["data"])
                return httpx.Response(200, json=body["data"])
        return resp


#: Every tool known to page through the shared offset helper (guards the derivation).
_OFFSET_HELPER_TOOLS = {
    "list_acl_rules",
    "list_clients",
    "list_countries",
    "list_dns_policies",
    "list_dpi_applications",
    "list_dpi_categories",
    "list_firewall_policies",
    "list_firewall_zones_proxy",
    "list_hotspot_vouchers",
    "list_integration_device_tags",
    "list_lags",
    "list_local_sites",
    "list_mc_lag_domains",
    "list_networks",
    "list_pending_devices",
    "list_radius_profiles",
    "list_site_devices",
    "list_site_to_site_tunnels",
    "list_switch_stacks",
    "list_traffic_matching_lists",
    "list_vpn_servers",
    "list_wan_interfaces",
    "list_wifi_broadcasts",
}


@functools.cache
def _lz__OFFSET_PAGED():
    return sorted(
        n
        for n in cti.READ_TOOLS
        if {"offset", "limit"} <= set((TOOLS[n].parameters or {}).get("properties") or {})
    )


def _spy_offset_helper(monkeypatch) -> list[Any]:
    """Record every ``offset_list_result`` call, in every tools module that imported it."""
    calls: list[Any] = []
    real = _pagination.offset_list_result

    def spy(collected: dict[str, Any]) -> Any:
        calls.append(collected)
        return real(collected)

    for info in pkgutil.iter_modules(tools_pkg.__path__):
        mod = importlib.import_module(f"{tools_pkg.__name__}.{info.name}")
        if getattr(mod, "offset_list_result", None) is real:
            monkeypatch.setattr(mod, "offset_list_result", spy)
    return calls


@lazy_parametrize("name", lambda: sorted(_OFFSET_HELPER_TOOLS))
async def test_explicit_bare_array_page_is_returned_unchanged(monkeypatch, name):
    calls = _spy_offset_helper(monkeypatch)
    # Generated data: offset=0&limit=2 is no captured query, and an exact-capture replay
    # answers an unrecorded query with a harness LookupError before the helper runs.
    up = _BareArrayPages(replay_recordings=False)
    args = {**tool_args.generated_args(TOOLS[name]), "offset": 0, "limit": 2}
    try:
        res = await _call(monkeypatch, name, up, args=args)
    except ToolError:
        if calls:
            raise
        res = None
    assert calls, f"{name} no longer pages via the helper"
    assert up.bare_pages, f"{name}: the explicit page was not requested with limit=2"
    payload = _payload(res)
    assert payload == up.bare_pages[-1], f"{name}: bare page not returned unchanged: {payload!r}"


@lazy_parametrize("name", lambda: sorted(set(_lz__OFFSET_PAGED()) - _OFFSET_HELPER_TOOLS))
async def test_offset_paged_tool_outside_the_helper_set_does_not_call_it(monkeypatch, name):
    """An offset-paged tool outside _OFFSET_HELPER_TOOLS must not reach the helper."""
    calls = _spy_offset_helper(monkeypatch)
    up = _BareArrayPages(replay_recordings=False)
    args = {**tool_args.generated_args(TOOLS[name]), "offset": 0, "limit": 2}
    try:
        await _call(monkeypatch, name, up, args=args)
    except ToolError:
        pass
    assert not calls, f"{name}: add it to _OFFSET_HELPER_TOOLS"


def test_offset_helper_tool_set_is_swept():
    assert set(_lz__OFFSET_PAGED()) >= _OFFSET_HELPER_TOOLS


def test_offset_list_result_shapes():
    page = [{"id": "a"}]
    assert _pagination.offset_list_result({"raw": page}) is page
    envelope = {"offset": 0, "limit": 1, "count": 1, "totalCount": 3, "data": page}
    assert _pagination.offset_list_result({"raw": envelope}) is envelope
