"""Resolution properties shared by host/site/camera list-first helpers."""

import functools
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_classes import class_axis
from unifi_fabric import server
from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.registry import (
    FetchedRecords,
    Registry,
    _match_proxy_site,
    match_ea_site,
    match_host,
)
from unifi_fabric.tools.protect import _resolve_camera_refs


async def resolve(kind, rows):
    if kind == "host":
        match = match_host(rows, "Selected")
        return match[1]["id"] if match else None
    if kind == "proxy":
        return _match_proxy_site(rows, "Selected")
    if kind == "ea":
        return match_ea_site(rows, "Selected", partial=[], max_pages=None)
    return await _resolve_camera_refs(
        AsyncMock(get=AsyncMock(return_value=rows)), "host", "Selected"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["host", "proxy", "ea", "camera"])
@pytest.mark.parametrize("bad_id", [None, "", 7, [], {}])
async def test_selected_record_requires_native_id(kind, bad_id):
    record = {"name": "Selected", "id": bad_id}
    if kind == "ea":
        record = {"meta": {"name": "Selected"}, "siteId": bad_id}
    with pytest.raises(ValueError, match="Selected"):
        await resolve(kind, [record])


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["host", "proxy", "ea", "camera"])
@pytest.mark.parametrize("bad_row", [None, 7, "unexpected", []])
async def test_malformed_collection_rows_raise_shape(kind, bad_row):
    with pytest.raises(UniFiConnectionError, match="shape"):
        await resolve(kind, [bad_row])


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["host", "proxy", "ea", "camera"])
async def test_distinct_native_ids_are_ambiguous(kind):
    rows = [{"name": "Selected", "id": sid} for sid in ["abc", "def"]]
    if kind == "ea":
        rows = [{"meta": {"name": "Selected"}, "siteId": sid} for sid in ["abc", "def"]]
    with pytest.raises(ValueError, match="ambiguous.*Selected") as caught:
        await resolve(kind, rows)
    assert "abc" in str(caught.value) and "def" in str(caught.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["host", "proxy", "ea", "camera"])
async def test_same_native_id_is_one_choice(kind):
    rows = [{"name": "Selected", "id": sid} for sid in ["abc", "ABC"]]
    if kind == "ea":
        rows = [{"meta": {"name": "Selected"}, "siteId": sid} for sid in ["abc", "ABC"]]
    assert await resolve(kind, rows)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["hosts", "ea_sites", "sites"])
async def test_incomplete_enumeration_is_never_cached_by_setters(kind):
    registry = Registry(AsyncMock(list_key_labels=MagicMock(return_value=["default"])))
    partial = FetchedRecords([{"id": "abc"}], "page cap 1")
    if kind == "sites":
        await registry.set_sites("host", partial)
    else:
        await getattr(registry, "set_" + kind)(partial)
    assert not getattr(registry, "_" + kind)


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_row", [None, 7, "unexpected", []])
async def test_arm_profile_resolution_malformed_rows_raise_shape(bad_row):
    from unifi_fabric.tools.protect import _find_arm_profile

    with pytest.raises(UniFiConnectionError, match="shape"):
        await _find_arm_profile(
            AsyncMock(get=AsyncMock(return_value=[bad_row])), "host", "abc", key=None
        )


# Discover all exposed MCP host resolvers from their catalog schemas; additions
# automatically join every property instead of relying on a manually curated list.
@functools.cache
def _lz_HOST_RESOLVERS():
    return [
        name
        for name, tool in cti.TOOLS.items()
        if "host" in (tool.parameters.get("properties") or {})
    ]


@class_axis(
    "name",
    lambda: _lz_HOST_RESOLVERS(),
    problem=lambda: ["malformed", "native_id", "ambiguous", "incomplete"],
)
async def test_host_resolution_properties_cover_catalog(monkeypatch, name, problem):
    args = {**tool_args.generated_args(cti.TOOLS[name]), "host": uh.HOST}
    env = {}
    if problem == "malformed":
        rows = [None]
        up = uh.FakeUpstream(hosts_by_key={"k-test": rows})
    elif problem == "native_id":
        row = {**uh.HOST_RECORD, "id": 7}
        up = uh.FakeUpstream(hosts_by_key={"k-test": [row]})
    elif problem == "ambiguous":
        up = uh.FakeUpstream(hosts_by_key={"k-test": cti._twin_hosts()})
    else:
        up = uh.FakeUpstream(mode="paged", page_resolution=True)
        env = {"UNIFI_PAGINATE_MAX_PAGES": "1"}
    with pytest.raises(ToolError) as caught:
        await cti._call(monkeypatch, name, up, args, env=env)
    message = str(caught.value)
    if problem == "malformed":
        assert "shape" in message and "NoneType" in message, (name, message)
    elif problem == "native_id":
        assert "native id" in message and uh.HOST in message, (name, message)
    elif problem == "ambiguous":
        assert "ambiguous" in message and uh.HOST_ID in message and "FA0099" in message
    else:
        assert "incomplete" in message and "page cap" in message, (name, message)
        assert not server._registry._hosts
    assert up.served, f"{name}: did not exercise host enumeration"
    assert not up.writes(), f"{name}: write sent after failed resolution"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method",
    ["resolve_host_id", "resolve_site_id", "resolve_site_slug", "resolve_ea_site_id"],
)
async def test_scalar_exact_resolution_is_complete_on_partial_list(method):
    from unifi_fabric.resolution_state import wrap_resolution_result

    registry = Registry(AsyncMock(list_key_labels=MagicMock(return_value=["default"])))
    sid = "11111111-1111-4111-8111-111111111111"
    row = {"id": sid, "siteId": sid, "internalReference": "default"}
    partial = FetchedRecords([row], "page cap 1")
    registry.get_hosts = AsyncMock(return_value=partial)
    registry.get_sites = AsyncMock(return_value=partial)
    registry.get_ea_sites = AsyncMock(return_value=partial)
    args = (sid, "host") if method in {"resolve_site_id", "resolve_site_slug"} else (sid,)
    result = await wrap_resolution_result(getattr(registry, method))(*args)
    assert result == ("default" if method == "resolve_site_slug" else sid)


@pytest.mark.asyncio
async def test_multi_key_same_native_host_is_one_choice():
    from unittest.mock import MagicMock

    client = MagicMock()
    client.list_key_labels.return_value = ["a", "b"]
    registry = Registry(client)
    registry.get_hosts = AsyncMock(
        side_effect=[
            [{"id": "abc", "name": "Selected"}],
            [{"id": "ABC", "name": "Selected"}],
        ]
    )
    assert await registry.resolve_key_for_host("Selected") is not None


@pytest.mark.asyncio
async def test_exact_key_selection_is_complete_on_partial_list():
    from unittest.mock import MagicMock

    from unifi_fabric.resolution_state import wrap_resolution_result

    client = MagicMock()
    client.list_key_labels.return_value = ["a", "b"]
    registry = Registry(client)
    registry.get_hosts = AsyncMock(return_value=FetchedRecords([{"id": "abc"}], "page cap 1"))
    result = await wrap_resolution_result(registry.resolve_key_for_host)("abc")
    assert result is client.get_key_by_label.return_value
