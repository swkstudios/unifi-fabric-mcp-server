"""Resolution integrity properties over every device/client list-resolution caller."""

from __future__ import annotations

import ast
import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import RateLimitError, UniFiConnectionError
from unifi_fabric.families.clients import clients
from unifi_fabric.families.devices import device_mgmt
from unifi_fabric.resolution_state import wrap_resolution_result

MAC = "02:00:5e:00:00:aa"
ID = "00000000-0000-4000-8000-0000000000aa"
OTHER = "00000000-0000-4000-8000-0000000000bb"


def callers(module, helpers):
    """Discover the transitive caller catalog, so new siblings inherit these tests."""
    tree = ast.parse(inspect.getsource(module))
    nodes = [n for n in tree.body if isinstance(n, ast.AsyncFunctionDef)]
    selected = set(helpers)
    while True:
        found = {
            n.name
            for n in nodes
            if any(
                isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id in selected
                for c in ast.walk(n)
            )
        }
        if found <= selected:
            break
        selected |= found
    return [
        (module, n.name)
        for n in nodes
        if n.name in selected
        and "registry" in inspect.signature(getattr(module, n.name)).parameters
    ]


CATALOG = callers(
    device_mgmt,
    {"_resolve_device_id_cached", "_resolve_device_id", "_call_with_device_id", "_device_mac"},
) + callers(clients, {"_resolve_client"})
assert CATALOG


def setup(monkeypatch, module, rows, incomplete=False):
    device_mgmt._mac_uuid_cache.clear()
    client = SimpleNamespace()

    # A weak-referenceable client is required by the per-client MAC cache.
    class Client:
        pass

    client = Client()
    client.get = AsyncMock(return_value={"macAddress": MAC})
    client.post = AsyncMock(return_value={})
    client.delete = AsyncMock(return_value={})
    registry = SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="host"),
        resolve_site_id=AsyncMock(return_value=ID),
        resolve_site_slug=AsyncMock(return_value="default"),
    )
    collector = AsyncMock(
        return_value={
            "items": rows,
            "incomplete": incomplete,
            "incompleteReason": "page cap reached",
        }
    )
    monkeypatch.setattr(module, "collect_offset", collector)
    return client, registry, collector


async def invoke(module, name, client, registry):
    values = {
        "client": client,
        "registry": registry,
        "host": "host",
        "site": ID,
        "device_id": MAC,
        "client_id": MAC,
        "action": {"action": "AUTHORIZE_GUEST_ACCESS"},
        "cmd": "set-locate",
        "port_idx": 1,
        # _classic_device_command (cmd/devmgr, MAC-addressed)
        "suffix": "",
        "fields": {"cmd": "restart"},
        "plural": False,
    }
    fn = getattr(module, name)
    kwargs = {k: values[k] for k in inspect.signature(fn).parameters if k in values}
    return await fn(**kwargs)


@pytest.mark.parametrize("module,name", CATALOG, ids=[n for _, n in CATALOG])
@pytest.mark.parametrize("native_id", [None, "", 0, False, [], {}])
async def test_selected_native_id_is_a_nonempty_string(monkeypatch, module, name, native_id):
    row = {"id": native_id, "macAddress": MAC, "name": "identifying-device"}
    client, registry, _ = setup(monkeypatch, module, [row])
    with pytest.raises(UniFiConnectionError) as error:
        await invoke(module, name, client, registry)
    assert "identifying-device" in str(error.value)
    assert not client.post.called and not client.delete.called


@pytest.mark.parametrize("module,name", CATALOG, ids=[n for _, n in CATALOG])
async def test_ambiguous_distinct_mac_ids_never_address_or_cache(monkeypatch, module, name):
    client, registry, _ = setup(
        monkeypatch, module, [{"id": i, "macAddress": MAC} for i in (ID, OTHER)]
    )
    with pytest.raises(ValueError) as error:
        await invoke(module, name, client, registry)
    assert ID in str(error.value) and OTHER in str(error.value)
    assert not device_mgmt._mac_cache_for(client)
    assert not client.post.called and not client.delete.called


@pytest.mark.parametrize("module,name", CATALOG, ids=[n for _, n in CATALOG])
async def test_incomplete_enumeration_is_never_complete_or_cached(monkeypatch, module, name):
    client, registry, _ = setup(monkeypatch, module, [{"id": ID, "macAddress": MAC}], True)
    result = await wrap_resolution_result(invoke)(module, name, client, registry)
    assert (result.get("incomplete") or result.get("_incomplete")) is True
    assert "page cap reached" in (result.get("_incompleteReason") or result.get("incompleteReason"))
    assert not device_mgmt._mac_cache_for(client)


@pytest.mark.parametrize("module,name", CATALOG, ids=[n for _, n in CATALOG])
@pytest.mark.parametrize("bad", [None, 7, "not an object", []])
async def test_nonobject_rows_are_shape_errors(monkeypatch, module, name, bad):
    client, registry, _ = setup(monkeypatch, module, [bad, {"id": ID, "macAddress": MAC}])
    with pytest.raises(UniFiConnectionError, match="shape"):
        await invoke(module, name, client, registry)
    assert not client.post.called and not client.delete.called


REFRESH_CALLERS = callers(device_mgmt, {"_call_with_device_id"})


@pytest.mark.parametrize("module,name", REFRESH_CALLERS, ids=[n for _, n in REFRESH_CALLERS])
@pytest.mark.parametrize("refresh_error", [UniFiConnectionError, ValueError, RateLimitError])
async def test_failed_404_refresh_keeps_original_reason(monkeypatch, module, name, refresh_error):
    client, registry, collector = setup(monkeypatch, module, [{"id": ID, "macAddress": MAC}])
    await device_mgmt._resolve_device_id(client, "host", ID, MAC, key=None)
    original = "HTTP 404 from target: original-controller-reason"
    for method in (client.get, client.post, client.delete):
        method.side_effect = UniFiConnectionError(original)
    collector.side_effect = refresh_error("HTTP 503 from list: refresh-unavailable")
    with pytest.raises(UniFiConnectionError) as error:
        await invoke(module, name, client, registry)
    assert original in str(error.value) and "refresh-unavailable" in str(error.value)


READ_REFRESH_CALLERS = [
    (device_mgmt, n.name)
    for n in ast.parse(inspect.getsource(device_mgmt)).body
    if isinstance(n, ast.AsyncFunctionDef)
    and any(
        isinstance(c, ast.Call)
        and isinstance(c.func, ast.Name)
        and c.func.id == "_call_with_device_id"
        and any(
            k.arg == "write" and isinstance(k.value, ast.Constant) and k.value.value is False
            for k in c.keywords
        )
        for c in ast.walk(n)
    )
]
assert READ_REFRESH_CALLERS


@pytest.mark.parametrize(
    "module,name", READ_REFRESH_CALLERS, ids=[n for _, n in READ_REFRESH_CALLERS]
)
async def test_failed_fresh_read_keeps_original_404(monkeypatch, module, name):
    client, registry, collector = setup(monkeypatch, module, [{"id": ID, "macAddress": MAC}])
    await device_mgmt._resolve_device_id(client, "host", ID, MAC, key=None)
    collector.return_value["items"] = [{"id": OTHER, "macAddress": MAC}]
    original = "HTTP 404 from target: original-controller-reason"
    client.get.side_effect = [
        UniFiConnectionError(original),
        UniFiConnectionError("HTTP 503 from fresh: retry-unavailable"),
    ]
    with pytest.raises(UniFiConnectionError) as error:
        await invoke(module, name, client, registry)
    assert original in str(error.value) and "retry-unavailable" in str(error.value)
    assert client.get.call_count == 2
