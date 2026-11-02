"""The connector relay's non-GET is a write for dry-run, read-only and the audit log.

Security review F6: the read-POST patterns treat every Classic ``stat/*`` POST as a read,
and the relay lets its caller pick any ``stat`` sub-path, so a relayed
``POST .../stat/anything/delete`` used to skip ``UNIFI_DRY_RUN`` and the audit log. Every
relayed non-GET is now a write whatever its path; the typed tools keep the documented
read-POST routes (``list_client_sessions`` -> ``stat/session``) as reads.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

_RELAY_STAT = "/v1/connector/consoles/H/proxy/network/api/s/default/stat/anything/delete"
_TYPED_SESSION = "/v1/connector/consoles/H/proxy/network/api/s/default/stat/session"


class TestRelayWritesUnderDryRun:
    async def test_relayed_stat_post_is_previewed_and_audited(self, tmp_path):
        from unifi_fabric.client import UniFiClient, is_dry_run_preview
        from unifi_fabric.config import Settings

        audit = tmp_path / "audit.log"
        client = UniFiClient(Settings(api_key="sk-test", dry_run=True, audit_log=str(audit)))
        resp = await client.request("POST", _RELAY_STAT, json={}, always_write=True)
        await client.close()
        assert is_dry_run_preview(resp.json())
        lines = audit.read_text().splitlines()
        assert len(lines) == 1 and "stat/anything/delete" in lines[0] and "dry_run" in lines[0]

    async def test_typed_read_post_stays_a_read(self, monkeypatch):
        import httpx

        from unifi_fabric.client import UniFiClient
        from unifi_fabric.config import Settings

        client = UniFiClient(Settings(api_key="sk-test", dry_run=True))
        sent = AsyncMock(return_value=httpx.Response(200, json={"data": []}))
        monkeypatch.setattr(httpx.AsyncClient, "request", sent)
        resp = await client.request("POST", _TYPED_SESSION, json={"type": "all"})
        await client.close()
        assert resp.json() == {"data": []}
        sent.assert_awaited_once()

    async def test_relayed_get_is_never_a_write(self, monkeypatch):
        import httpx

        from unifi_fabric.client import UniFiClient
        from unifi_fabric.config import Settings

        client = UniFiClient(Settings(api_key="sk-test", dry_run=True))
        sent = AsyncMock(return_value=httpx.Response(200, json={"ok": 1}))
        monkeypatch.setattr(httpx.AsyncClient, "request", sent)
        resp = await client.request("GET", _RELAY_STAT, always_write=True)
        await client.close()
        assert resp.json() == {"ok": 1}

    async def test_read_only_refuses_a_relayed_stat_post_at_the_chokepoint(self, monkeypatch):
        from unifi_fabric.client import UniFiClient
        from unifi_fabric.config import Settings
        from unifi_fabric.read_only import ReadOnlyModeError

        monkeypatch.setenv("UNIFI_READ_ONLY", "1")
        client = UniFiClient(Settings(api_key="sk-test"))
        with pytest.raises(ReadOnlyModeError):
            await client.request("POST", _RELAY_STAT, json={}, always_write=True)
        await client.close()

    async def test_connector_write_marks_the_request_as_a_write(self):
        from tests.test_connector import FakeResp
        from unifi_fabric.tools.connector import connector_write

        client = AsyncMock()
        client.request = AsyncMock(return_value=FakeResp(200, {"ok": True}))
        registry = AsyncMock()
        registry.resolve_key_for_host = AsyncMock(return_value=None)
        registry.resolve_host_id = AsyncMock(return_value="H")
        await connector_write(
            client, registry, "h", "POST", "network/api/s/default/stat/anything/delete", body={}
        )
        assert client.request.await_args.kwargs["always_write"] is True
