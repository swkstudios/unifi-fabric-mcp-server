"""InnerSpace fallback retains its structured capability failure status."""

from unittest.mock import AsyncMock

import pytest
import respx
from httpx import Response

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.tools import innerspace, placement_snapshot


@pytest.mark.parametrize("fallback_status", [403, 404, 500])
async def test_project_fallback_status_is_classified_without_body_text_guessing(fallback_status):
    host = "host-fallback"
    registry = AsyncMock(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value=host),
    )
    client = UniFiClient(Settings(api_keys=[APIKeyConfig(key="fixture-key", label="one")]))
    try:
        async with respx.mock(base_url="https://api.ui.com") as mock:
            mock.get(innerspace._integration_proxy(host, "/v1/project")).return_value = Response(
                403, json={"error": "host not found"}
            )
            mock.get(innerspace._proxy(host, "/project")).return_value = Response(
                fallback_status, json={"error": "forbidden"}
            )
            with pytest.raises(UniFiConnectionError) as caught:
                await innerspace._fetch_project(client, registry, host, "3D")
        outcome = placement_snapshot._capability_outcome(caught.value)
        assert outcome["outcome"] == ("auth_denied" if fallback_status == 403 else "unavailable")
        if fallback_status == 403:
            assert getattr(caught.value, "status_code", None) == 403
            assert "BOTH" in str(caught.value)
            assert "host not found" in str(caught.value)
            assert "forbidden" in str(caught.value)
        assert "HTTP 403" in outcome["error"]
    finally:
        await client.close()


async def test_preflight_reports_both_inner_space_paths_denied(monkeypatch):
    host = "host-fallback"
    registry = AsyncMock(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value=host),
    )
    monkeypatch.setattr(placement_snapshot.protect, "list_cameras", AsyncMock(return_value=[]))
    monkeypatch.setattr(placement_snapshot.protect, "list_sensors", AsyncMock(return_value=[]))
    monkeypatch.setattr(placement_snapshot.site_manager, "list_devices", AsyncMock(return_value=[]))
    client = UniFiClient(Settings(api_keys=[APIKeyConfig(key="fixture-key", label="one")]))
    try:
        async with respx.mock(base_url="https://api.ui.com") as mock:
            for path in (
                innerspace._integration_proxy(host, "/v1/project"),
                innerspace._proxy(host, "/project"),
            ):
                mock.get(path).return_value = Response(403, json={"error": "host not found"})
            result = await placement_snapshot.preflight_placement_snapshot_capabilities(
                client, registry, host
            )
        project = next(c for c in result["capabilities"] if c["name"] == "innerspace.project.3d")
        assert project["outcome"] == "auth_denied"
        assert "BOTH" in project["error"]
        assert [c["outcome"] for c in result["capabilities"][1:]] == ["ok"] * 3
    finally:
        await client.close()


def test_augmented_integration_namespace_error_keeps_status():
    upstream = UniFiConnectionError("HTTP 403 from GET /devices: host not found")
    error = innerspace._integration_namespace_error("host", "/devices", upstream)
    assert error.status_code == 403
    assert str(error).startswith(str(upstream))
    assert placement_snapshot._capability_outcome(error)["outcome"] == "auth_denied"


def test_structured_status_classification_without_message_guessing():
    error = UniFiConnectionError("synthetic upstream failure", status=403)
    assert placement_snapshot._capability_outcome(error)["outcome"] == "auth_denied"
