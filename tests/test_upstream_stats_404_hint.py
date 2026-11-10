"""An HTML 404 from the Network v2 statistics routes (``/v2/api/stats/*``) is hinted.

The console's Network application older than 11.0 does not serve them. The upstream body
stays verbatim; the hint follows it.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
import pytest
import respx

from unifi_fabric.client import UniFiClient, UniFiHTTPError, route_hint
from unifi_fabric.config import Settings

BASE = "https://api.ui.com"
CONSOLE = "/v1/connector/consoles/h1/proxy"
V2 = f"{CONSOLE}/network/v2/api/site/default/nat"
V2_STATS = f"{CONSOLE}/network/v2/api/stats/recent/series"


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _client(**kw: Any) -> UniFiClient:
    return UniFiClient(Settings(api_key="probe-key-1", api_base_url=BASE, **kw))


def _json(status: int, body: Any, **headers: str) -> httpx.Response:
    return httpx.Response(
        status,
        content=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json", **headers},
    )


# =========================================================================== E: stats 404 hint
_HTML_404 = (
    '<!doctype html><html lang="en"><head><title>HTTP Status 404 – Not Found</title>'
    "</head><body><h1>HTTP Status 404 – Not Found</h1></body></html>"
)


@respx.mock
async def test_e_an_html_404_from_v2_stats_is_hinted_with_the_body_verbatim():
    route = respx.get(BASE + V2_STATS).mock(
        return_value=httpx.Response(404, text=_HTML_404, headers={"content-type": "text/html"})
    )
    with pytest.raises(UniFiHTTPError) as exc:
        await _client().get(V2_STATS)
    msg = str(exc.value)
    assert exc.value.status == 404 and route.call_count == 1
    assert msg.startswith(f"HTTP 404 from GET {V2_STATS}: {_HTML_404}")  # verbatim
    assert "does not serve that statistics route" in msg


@pytest.mark.parametrize(
    ("path", "body", "ctype"),
    [
        (f"{CONSOLE}/network/v2/api/stats", _HTML_404, "text/html"),
        (f"{CONSOLE}/network/v2/api/stats/clients?x=1", _HTML_404, "text/html"),
    ],
)
def test_e_the_stats_family_is_hinted(path, body, ctype):
    assert "does not serve that statistics route" in route_hint(404, path, body)


@pytest.mark.parametrize(
    ("path", "text"),
    [
        # A JSON 404 (a real, served route with an unknown object), another v2 family,
        # another surface, and a lookalike prefix are not the version gap.
        (V2_STATS, '{"code":"api.err.NotFound","message":"unknown"}'),
        (V2, _HTML_404),
        (f"{CONSOLE}/network/api/s/default/stat/sta", _HTML_404),
        (f"{CONSOLE}/network/v2/api/statsx/y", _HTML_404),
    ],
)
def test_e_other_404s_get_no_stats_hint(path, text):
    assert route_hint(404, path, text) == ""


@respx.mock
async def test_e_the_relay_gets_the_hint_beside_status_and_body():
    respx.get(BASE + V2_STATS).mock(return_value=httpx.Response(404, text=_HTML_404))
    resp = await _client().request("GET", V2_STATS, raise_on_error=False)
    assert resp.status_code == 404 and resp.text == _HTML_404
    assert "does not serve that statistics route" in resp.extensions["unifi_auth_hint"]
