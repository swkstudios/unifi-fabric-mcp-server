"""Namespace fallback and error hints require the upstream HTTP status."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.families.innerspace import innerspace
from unifi_fabric.shared_shapes._history_common import translate_host_not_found

CASES = [
    (innerspace._fetch_project_document, {"mode": "3D"}, "get"),
    (
        innerspace._fetch_integration_list,
        {"path": "/v1/floor-plans", "array_key": "floorPlans", "site_id": None},
        "get",
    ),
    (innerspace.get_innerspace_asset, {"plan_id": "p1", "filename": "preview.svg"}, "get_binary"),
]


@pytest.mark.parametrize("fn,kwargs,method", CASES, ids=[x[0].__name__ for x in CASES])
@pytest.mark.parametrize("status", [400, 401, 404, 409, 500, 502, 503])
@pytest.mark.parametrize(
    "reason", ["host not found", "forbidden", "body quotes HTTP 403 forbidden"]
)
async def test_every_namespace_path_raises_nonfallback_verbatim(fn, kwargs, method, status, reason):
    registry = MagicMock()
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="h1")
    client = MagicMock()
    error = UniFiConnectionError(f"HTTP {status} from GET /route: {reason}")
    request = AsyncMock(side_effect=error)
    setattr(client, method, request)
    with pytest.raises(UniFiConnectionError) as caught:
        await fn(client, registry, "console", **kwargs)
    assert caught.value is error
    assert request.await_count == 1


@pytest.mark.parametrize("status", [400, 401, 404, 500, 503])
@pytest.mark.parametrize("reason", ["host not found", "forbidden with HTTP 403"])
def test_shared_namespace_hint_preserves_non403_error(status, reason):
    error = UniFiConnectionError(f"HTTP {status} from GET /route: {reason}")
    assert translate_host_not_found(error, "console") is error


async def test_legacy_nonfallback_error_preserved_with_context_as_note():
    registry = MagicMock()
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="h1")
    error = UniFiConnectionError("HTTP 500 from GET /legacy: forbidden")
    client = MagicMock()
    client.get = AsyncMock(
        side_effect=[UniFiConnectionError("HTTP 403 from GET /integration: host not found"), error]
    )
    with pytest.raises(UniFiConnectionError) as caught:
        await innerspace._fetch_project_document(client, registry, "console", "3D")
    assert caught.value is error
    assert client.get.await_count == 2
    assert any("HTTP 403" in note for note in getattr(error, "__notes__", []))


@pytest.mark.parametrize("status", [400, 401, 403, 409, 500, 502, 503])
@pytest.mark.parametrize("reason", ["body mentions HTTP 404 from GET /stale", "host not found"])
async def test_device_cache_fallback_uses_status_and_preserves_other_errors(
    monkeypatch, status, reason
):
    from unifi_fabric.families.devices import device_mgmt

    error = UniFiConnectionError(f"HTTP {status} from GET /device: {reason}")
    monkeypatch.setattr(
        device_mgmt,
        "_resolve_device_id_cached",
        AsyncMock(return_value=("00000000-0000-4000-8000-000000000001", True)),
    )
    refresh = AsyncMock()
    monkeypatch.setattr(device_mgmt, "_resolve_device_id", refresh)
    call = AsyncMock(side_effect=error)
    with pytest.raises(UniFiConnectionError) as caught:
        await device_mgmt._call_with_device_id(
            MagicMock(), "h1", "s1", "00:11:22:33:44:55", call, key=None, write=False
        )
    assert caught.value is error
    refresh.assert_not_awaited()
    assert call.await_count == 1


@pytest.mark.parametrize("status", [400, 401, 403, 409, 500, 502, 503])
@pytest.mark.parametrize("reason", ["body mentions HTTP 404 from GET /stale", "host not found"])
async def test_classic_client_lookup_fallback_uses_status(monkeypatch, status, reason):
    from unifi_fabric.families.clients import clients

    error = UniFiConnectionError(f"HTTP {status} from GET /client: {reason}")
    monkeypatch.setattr(clients, "_client_mac", AsyncMock(side_effect=error))
    with pytest.raises(UniFiConnectionError) as caught:
        await clients._stamgr_mac(
            MagicMock(), "h1", "s1", "00000000-0000-4000-8000-000000000001", None
        )
    assert caught.value is error


@pytest.mark.parametrize("reason", ["unauthorized", "request timed out", "unknown route"])
async def test_namespace_403_without_documented_reason_does_not_fallback(reason):
    registry = MagicMock()
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="h1")
    error = UniFiConnectionError(f"HTTP 403 from GET /integration: {reason}")
    client = MagicMock()
    client.get = AsyncMock(side_effect=error)
    with pytest.raises(UniFiConnectionError) as caught:
        await innerspace._fetch_project_document(client, registry, "console", "3D")
    assert caught.value is error
    assert client.get.await_count == 1


def test_every_namespace_fallback_path_has_a_property():
    import ast
    from pathlib import Path

    tree = ast.parse(Path(innerspace.__file__).read_text())
    paths = {
        node.name
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef)
        and any(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "_is_namespace_forbidden"
            for call in ast.walk(node)
        )
    }
    assert paths == {fn.__name__ for fn, _, _ in CASES}
