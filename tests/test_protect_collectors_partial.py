"""Protect window collectors keep what they gathered when a later poll fails.

``collect_protect_events`` and ``collect_protect_device_changes`` poll for a window. A
poll that fails after earlier polls succeeded ends the window: the events / changes
already gathered are returned with ``incomplete: true`` and an ``incompleteReason``
carrying the failed poll's complete upstream error (never discarded). A failing FIRST
poll has gathered nothing and raises the upstream error unchanged.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from unifi_fabric import server
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.protect import protect
from unifi_fabric.registry import Registry

H = "host-col-001"
CONSOLE = f"https://api.ui.com/v1/connector/consoles/{H}/proxy/protect"
EVENTS = f"{CONSOLE}/api/events"
FAMILIES = "|".join(re.escape(f) for f in protect.DEVICE_FAMILIES)
ERROR_BODY = '{"message":"transient upstream hiccup 7f3a"}'


@pytest.fixture()
def tools(monkeypatch):
    settings = Settings(api_key="sk-collector-test")
    client = UniFiClient(settings)
    monkeypatch.setattr(server, "_settings", settings)
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", Registry(client, ttl_seconds=60))

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(protect, "_sleep", no_sleep)


def _hosts(router: respx.Router) -> None:
    router.get("https://api.ui.com/v1/hosts").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"id": H, "type": "console", "reportedState": {"hostname": "c1"}}]},
        )
    )


async def _call(name: str, args: dict[str, Any]) -> Any:
    return (await server.mcp.call_tool(name, args)).structured_content


def _events_upstream(fail_from_poll: int, pages: list[list[dict[str, Any]]]):
    """One events poll per first-page request; later pages of a poll are empty."""
    polls = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if int(req.url.params.get("offset", "0") or 0) > 0:
            return httpx.Response(200, json=[])
        polls["n"] += 1
        if polls["n"] >= fail_from_poll:
            return httpx.Response(400, text=ERROR_BODY)
        return httpx.Response(200, json=pages[polls["n"] - 1])

    return handler, polls


@pytest.mark.parametrize("fail_from_poll", [2, 3])
async def test_events_mid_window_failure_keeps_gathered_events(tools, fail_from_poll):
    pages = [[{"id": "e1", "type": "motion"}, {"id": "e2"}], [{"id": "e3"}]]
    handler, _polls = _events_upstream(fail_from_poll, pages)
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        router.get(EVENTS).mock(side_effect=handler)
        result = await _call(
            "collect_protect_events",
            {"host": H, "poll_count": 5, "poll_interval_seconds": 1.0},
        )
    expected = [e for page in pages[: fail_from_poll - 1] for e in page]
    assert result["result"] == expected
    assert result["_polls"] == fail_from_poll - 1
    assert result["incomplete"] is True
    assert f"poll {fail_from_poll} failed" in result["incompleteReason"]
    assert ERROR_BODY in result["incompleteReason"]  # the complete upstream error


async def test_events_first_poll_failure_raises_the_upstream_error(tools):
    handler, _polls = _events_upstream(1, [])
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        router.get(EVENTS).mock(side_effect=handler)
        with pytest.raises(ToolError, match="transient upstream hiccup 7f3a"):
            await _call("collect_protect_events", {"host": H, "poll_count": 5})


def _devices_upstream(fail_from_poll: int):
    """Poll 1: camera c1; poll 2: c1 + c2; from ``fail_from_poll`` on: 400 on cameras."""
    seen = {"cameras": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if not req.url.path.endswith("/cameras"):
            return httpx.Response(200, json=[])
        seen["cameras"] += 1
        poll = seen["cameras"]
        if poll >= fail_from_poll:
            return httpx.Response(400, text=ERROR_BODY)
        return httpx.Response(200, json=[{"id": "c1"}] + ([{"id": "c2"}] if poll >= 2 else []))

    return handler


async def test_device_changes_mid_window_failure_keeps_gathered_changes(tools):
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        router.get(url__regex=rf"{re.escape(CONSOLE)}/integration/v1/({FAMILIES})$").mock(
            side_effect=_devices_upstream(3)
        )
        result = await _call(
            "collect_protect_device_changes",
            {"host": H, "poll_count": 5, "poll_interval_seconds": 1.0},
        )
    assert result["changes"] == [{"change": "added", "device": {"id": "c2"}}]
    assert result["_polls"] == 2
    assert result["incomplete"] is True
    assert "poll 3 failed" in result["incompleteReason"]
    assert ERROR_BODY in result["incompleteReason"]


async def test_device_changes_first_poll_failure_raises_the_upstream_error(tools):
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        router.get(url__regex=rf"{re.escape(CONSOLE)}/integration/v1/({FAMILIES})$").mock(
            side_effect=_devices_upstream(1)
        )
        with pytest.raises(ToolError, match="transient upstream hiccup 7f3a"):
            await _call("collect_protect_device_changes", {"host": H, "poll_count": 5})
