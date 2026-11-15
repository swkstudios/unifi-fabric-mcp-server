"""A per-area dry-run entry previews exactly the relay writes its deny entry refuses.

A relayed mutation on an unclassified route is refused while any per-area
``family:<area>=deny`` entry is set, because its area cannot be shown to be outside the
opted-out one. The same entry set to ``dry-run`` must preview that write, never send it.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from unifi_fabric import switches
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.connector import connector

HOST_ID = "AABBCCDDEEFF:1"
UNCLASSIFIED_PATH = "talk/api/settings"
AREAS = [switch.family for switch in switches.AREA_WRITE_SWITCHES]


class _Registry:
    async def resolve_key_for_host(self, _host: str) -> None:
        return None

    async def resolve_host_id(self, _host: str, *, key: Any = None) -> str:
        return HOST_ID


def _client(sent: list[str]) -> UniFiClient:
    client = UniFiClient(Settings(api_key="k" * 24))

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.method)
        return httpx.Response(200, json={"ok": True})

    http = httpx.AsyncClient(
        base_url=client._settings.api_base_url, transport=httpx.MockTransport(handler)
    )

    async def get_client(_key: Any) -> httpx.AsyncClient:
        return http

    client._get_client = get_client  # type: ignore[method-assign]
    return client


async def _post(monkeypatch: pytest.MonkeyPatch, entry: str) -> tuple[list[str], Any]:
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "allow")
    if entry:
        monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", entry)
    else:
        monkeypatch.delenv("UNIFI_WRITE_EXCEPTIONS", raising=False)
    sent: list[str] = []
    client = _client(sent)
    try:
        result = await connector.connector_write(
            client, _Registry(), "console", "POST", UNCLASSIFIED_PATH, body={"x": 1}
        )
    finally:
        await client.close()
    return sent, result


@pytest.mark.parametrize("area", AREAS)
async def test_area_deny_refuses_the_unclassified_relay_write(monkeypatch, area) -> None:
    with pytest.raises(ValueError, match="unclassified route is refused"):
        await _post(monkeypatch, f"family:{area}=deny")


@pytest.mark.parametrize("area", AREAS)
async def test_area_dry_run_previews_the_unclassified_relay_write(monkeypatch, area) -> None:
    sent, result = await _post(monkeypatch, f"family:{area}=dry-run")
    assert "POST" not in sent
    assert result["routeClass"] == "unclassified"
    assert (
        result.get("dryRun") is True
        or result.get("status") == "dry_run"
        or "dry_run" in str(result)
    )


async def test_without_an_area_entry_the_unclassified_write_relays(monkeypatch) -> None:
    sent, result = await _post(monkeypatch, "")
    assert sent == ["POST"]
    assert result["routeClass"] == "unclassified"
