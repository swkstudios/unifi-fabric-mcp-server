"""docs/RETRY.md states the client's retry rule as the client applies it.

Checked against ``UniFiClient.request`` itself, never against other docs:

* a read via GET answered 429 every time is sent ``Max retries`` + 1 times, sleeping
  ``min(2^attempt, 32)`` plus jitter between attempts, as documented;
* every state-changing GET route the document names is one the write classifier treats
  as a write, every such route the classifier knows is named, and a 429 on it is raised
  after exactly one request (a retry could repeat the state change);
* a non-GET request is sent once on 429;
* no tool raises the rule: every ``max_retries=`` a tool passes is 0.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
import respx
from httpx import Response

from unifi_fabric import client as client_module
from unifi_fabric.client import RateLimitError, UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.read_only import STATE_CHANGING_GET_ROUTES, is_write_request

ROOT = Path(__file__).resolve().parents[1]
RETRY_MD = (ROOT / "docs" / "RETRY.md").read_text(encoding="utf-8")
BASE = "https://api.ui.com"
PROXY = "/v1/connector/consoles/host-1/proxy/"
#: How each documented route's ``{id}`` placeholder is filled for a request.
SAMPLE_ID = "65d4f1e2a1b2c3d4e5f60718"


def _documented_max_retries() -> int:
    match = re.search(r"\*\*Max retries\*\*: (\d+)", RETRY_MD)
    assert match, "docs/RETRY.md states no **Max retries** value"
    return int(match.group(1))


def _documented_state_changing_routes() -> list[str]:
    """The backticked ``protect/...`` routes of the one-rule paragraph."""
    rule = RETRY_MD.split("**One rule:**", 1)[1].split("\n\n", 1)[0]
    return re.findall(r"`([a-z][\w{}.-]*/[\w/{}.-]*)`", rule)


@pytest.fixture
def client():
    return UniFiClient(Settings(api_key="sk-retry-doc"))


@pytest.fixture
def sleeps(monkeypatch):
    waited: list[float] = []

    async def _sleep(delay: float) -> None:
        waited.append(delay)

    monkeypatch.setattr(client_module.asyncio, "sleep", _sleep)
    monkeypatch.setattr(client_module._secure_random, "uniform", lambda low, high: 0.0)
    return waited


def test_the_documented_backoff_formula_is_the_clients():
    assert "`delay = min(2^attempt, 32) + random_jitter`" in RETRY_MD
    assert "Uniform random(0, base_delay)" in RETRY_MD


@respx.mock
async def test_a_read_get_is_retried_the_documented_number_of_times(client, sleeps):
    retries = _documented_max_retries()
    route = respx.get(f"{BASE}/v1/hosts").mock(return_value=Response(429))
    with pytest.raises(RateLimitError):
        await client.request("GET", "/v1/hosts")
    assert route.call_count == retries + 1
    assert sleeps == [min(2**attempt, 32) for attempt in range(retries)]


def test_every_documented_state_changing_get_route_is_a_write_and_none_is_missing():
    routes = _documented_state_changing_routes()
    assert routes, "docs/RETRY.md names no state-changing GET route"
    for route in routes:
        path = PROXY + route.replace("{id}", SAMPLE_ID)
        assert is_write_request("GET", path), route
    for pattern in STATE_CHANGING_GET_ROUTES:
        named = [r for r in routes if pattern.fullmatch(r.replace("{id}", SAMPLE_ID))]
        assert named, f"docs/RETRY.md does not name the state-changing GET {pattern.pattern}"


@respx.mock
async def test_a_state_changing_get_is_sent_once_on_429(client, sleeps):
    routes = _documented_state_changing_routes()
    assert routes, "docs/RETRY.md names no state-changing GET route"
    for route in routes:
        path = PROXY + route.replace("{id}", SAMPLE_ID)
        upstream = respx.get(f"{BASE}{path}").mock(return_value=Response(429))
        with pytest.raises(RateLimitError):
            await client.request("GET", path)
        assert upstream.call_count == 1, route
    assert sleeps == []


@respx.mock
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_every_other_method_is_sent_once_on_429(client, sleeps, method):
    upstream = respx.route(method=method, url=f"{BASE}/v1/x").mock(return_value=Response(429))
    with pytest.raises(RateLimitError):
        await client.request(method, "/v1/x", json={} if method != "DELETE" else None)
    assert upstream.call_count == 1
    assert sleeps == []


def test_no_tool_raises_the_retry_rule():
    raised = []
    for path in sorted((ROOT / "src" / "unifi_fabric").rglob("*.py")):
        if path.name == "client.py" and path.parent.name == "unifi_fabric":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "max_retries" and not (
                        isinstance(kw.value, ast.Constant) and kw.value.value == 0
                    ):
                        raised.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert raised == [], raised
