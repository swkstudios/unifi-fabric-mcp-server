"""Network write checks: update_setting's per-leaf rejection report, and the documented
contracts of device-tag selection, the hotspot dry-run helper and create_wifi_broadcast.

update_setting verifies a write by reading the setting group back. The check walks the
request leaf by leaf: a nested object whose one leaf took while a sibling leaf was silently
dropped (an unrecognised enum) changed as a whole, yet the dropped leaf is a rejection and
must be reported with false verification beside the unchanged upstream PUT body.
"""

from __future__ import annotations

import copy
import itertools
import json
import pathlib
from typing import Any
from unittest.mock import AsyncMock

import pytest

from tests import test_cross_tool_invariants as cti
from unifi_fabric.client import DRY_RUN_MESSAGE
from unifi_fabric.tools._results import dry_run_or_verbatim
from unifi_fabric.tools.device_mgmt import _delete_device_tag, _update_device_tag
from unifi_fabric.tools.network_services_proxy import update_setting

TOOLS = cti.TOOLS
HOST_ID = "host-001"
SPEC = pathlib.Path(__file__).parent / "fixtures" / "openapi" / "network-11.0.97.json"


@pytest.fixture()
def client():
    c = AsyncMock()
    c.dry_run = False
    c.get = AsyncMock()
    c.put = AsyncMock()
    c.delete = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_slug = AsyncMock(return_value="default")
    return r


def _envelope(state: dict[str, Any]) -> dict[str, Any]:
    return {"meta": {"rc": "ok"}, "data": [state]}


def _set(state: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    for k in path[:-1]:
        state = state.setdefault(k, {})
    state[path[-1]] = value


# --- update_setting: per-leaf post-write check ------------------------------------------

# A request touching top-level and nested leaves at two depths. Each leaf's pre value
# differs from the requested one, so every leaf is a real change.
_PRE = {
    "key": "ips",
    "enabled": False,
    "mode": "ids",
    "radius": {"port": 1812, "host": "192.0.2.1", "acct": {"port": 1813, "on": False}},
    "untouched": {"x": 1},
}
_REQUEST = {
    "enabled": True,
    "radius": {"port": 1815, "acct": {"port": 1814, "on": True}},
}
_LEAVES = [("enabled",), ("radius", "port"), ("radius", "acct", "port"), ("radius", "acct", "on")]
_WANTED = {("enabled",): True, ("radius", "port"): 1815}
_WANTED |= {("radius", "acct", "port"): 1814, ("radius", "acct", "on"): True}


@pytest.mark.parametrize(
    "dropped",
    [frozenset(c) for n in range(len(_LEAVES) + 1) for c in itertools.combinations(_LEAVES, n)],
    ids=lambda d: "+".join(".".join(p) for p in sorted(d)) or "none",
)
async def test_update_setting_reports_exactly_the_dropped_leaves(client, registry, dropped):
    """Every subset of dropped leaves has an exact negative verification report.
    The upstream PUT body survives for both applied and rejected updates; the note
    names the dropped dotted paths and every applied sibling.
    """
    post = copy.deepcopy(_PRE)
    for path in _LEAVES:
        if path not in dropped:
            _set(post, path, _WANTED[path])
    put_body = {**_envelope(post), "upstreamOnly": {"source": "put-response"}}
    client.get.side_effect = [_envelope(copy.deepcopy(_PRE)), _envelope(post)]
    client.put.return_value = copy.deepcopy(put_body)

    result = await update_setting(client, registry, "h", "s", "ips", copy.deepcopy(_REQUEST))
    assert {key: result[key] for key in put_body} == put_body
    client.put.assert_awaited_once()
    assert client.put.await_args.kwargs["json"] == _REQUEST
    if not dropped:
        assert result == {**put_body, "_verified": True}
        return
    want_rejected = [".".join(p) for p in _LEAVES if p in dropped]
    want_applied = [".".join(p) for p in _LEAVES if p not in dropped]
    assert result["_verified"] is False
    assert result["_unverifiedFields"] == want_rejected
    msg = result["_verificationNote"]
    assert result == {
        **put_body,
        "_verified": False,
        "_unverifiedFields": want_rejected,
        "_verificationNote": msg,
    }
    assert f"rejected fields {want_rejected!r}" in msg
    if want_applied:
        assert f"Fields {want_applied!r} were applied" in msg
    else:
        assert "were applied" not in msg
    assert "get_setting(setting_key='ips')" in msg


async def test_update_setting_nested_partial_rejection_is_reported(client, registry):
    """Leaf n.a applied and sibling n.b dropped: preserve both in the PUT response."""
    pre = _envelope({"key": "ips", "n": {"a": 0, "b": "old"}})
    post = _envelope({"key": "ips", "n": {"a": 1, "b": "old"}})
    put_body = {**post, "upstreamOnly": {"source": "put-response"}}
    client.get.side_effect = [pre, post]
    client.put.return_value = copy.deepcopy(put_body)
    result = await update_setting(
        client, registry, "h", "s", "ips", {"n": {"a": 1, "b": "BADENUM"}}
    )
    assert {key: result[key] for key in put_body} == put_body
    assert result["_verified"] is False
    assert result["_unverifiedFields"] == ["n.b"]
    assert "rejected fields ['n.b']" in result["_verificationNote"]
    assert "Fields ['n.a'] were applied" in result["_verificationNote"]
    assert "get_setting(setting_key='ips')" in result["_verificationNote"]
    client.put.assert_awaited_once()
    assert client.put.await_args.kwargs["json"] == {"n": {"a": 1, "b": "BADENUM"}}


@pytest.mark.parametrize(
    ("request_body", "pre", "post"),
    [
        # A leaf the controller normalised to another value changed: not a silent drop.
        ({"n": {"a": 1, "b": "x"}}, {"n": {"a": 0, "b": "old"}}, {"n": {"a": 1, "b": "X"}}),
        # A padded list leaf equal after the controller's padding is stripped.
        (
            {"n": {"dns": ["8.8.8.8"], "a": 1}},
            {"n": {"dns": [], "a": 0}},
            {"n": {"dns": ["8.8.8.8", "", ""], "a": 1}},
        ),
        # Top-level server-managed fields are never compared.
        ({"a": 1, "_updatedAt": 5}, {"a": 0, "_updatedAt": 1}, {"a": 1, "_updatedAt": 1}),
        # An empty nested object is one leaf, satisfied by any object.
        ({"a": 1, "n": {}}, {"a": 0, "n": {"z": 1}}, {"a": 1, "n": {"z": 1}}),
    ],
    ids=["normalised", "padded-list", "server-managed", "empty-object"],
)
async def test_update_setting_leaf_check_has_no_false_rejection(
    client, registry, request_body, pre, post
):
    client.get.side_effect = [_envelope({"key": "k", **pre}), _envelope({"key": "k", **post})]
    client.put.return_value = _envelope({"key": "k", **post})
    result = await update_setting(client, registry, "h", "s", "k", request_body)
    expected = _envelope({"key": "k", **post})
    assert {key: result[key] for key in ("data", "meta")} == expected
    if "b" in request_body.get("n", {}):
        assert result["_verified"] is False
        assert result["_unverifiedFields"] == ["n.b"]
    else:
        assert result["_verified"] is True


async def test_update_setting_nested_leaf_absent_before_and_after_is_rejected(client, registry):
    """An absent nested leaf is named by its dotted path; the PUT body stays unchanged."""
    pre = _envelope({"key": "k", "n": {"a": 0}})
    post = _envelope({"key": "k", "n": {"a": 1}})
    put_body = {**post, "upstreamOnly": {"source": "put-response"}}
    client.get.side_effect = [pre, post]
    client.put.return_value = copy.deepcopy(put_body)
    result = await update_setting(client, registry, "h", "s", "k", {"n": {"a": 1, "unknown": True}})
    assert {key: result[key] for key in put_body} == put_body
    assert result["_verified"] is False
    assert result["_unverifiedFields"] == ["n.unknown"]
    assert "rejected fields ['n.unknown']" in result["_verificationNote"]
    assert "Fields ['n.a'] were applied" in result["_verificationNote"]
    assert "get_setting(setting_key='k')" in result["_verificationNote"]
    assert "unknown" not in result["data"][0]["n"]
    client.put.assert_awaited_once()
    assert client.put.await_args.kwargs["json"] == {"n": {"a": 1, "unknown": True}}


def test_update_setting_description_names_the_leaf_check():
    desc = TOOLS["update_setting"].description or ""
    assert "leaf by leaf" in desc
    assert "dotted path" in desc


# --- device tags: tag_id selection is documented as it matches --------------------------

_TIERS = "name (exact, then case-insensitive, then edge-whitespace stripped)"
_TAGS = [
    {"_id": "65f1c0ffee0123456789ab01", "name": "Cameras", "member_device_macs": []},
    {"_id": "65f1c0ffee0123456789ab02", "name": "Fiber - ", "member_device_macs": []},
]


@pytest.mark.parametrize("name", ["update_device_tag", "delete_device_tag"])
def test_tag_id_description_states_the_name_tiers(name):
    props = TOOLS[name].parameters["properties"]
    text = " ".join(props["tag_id"]["description"].split())
    assert "exact name" not in text
    assert "its name (exact, then case-insensitive, then edge-whitespace stripped)" in text


@pytest.mark.parametrize("fn", [_update_device_tag, _delete_device_tag], ids=lambda f: f.__name__)
def test_tag_helpers_docstrings_state_the_name_tiers(fn):
    assert _TIERS in " ".join((fn.__doc__ or "").split())


@pytest.mark.parametrize(
    ("given", "want_id"),
    [
        ("Cameras", "65f1c0ffee0123456789ab01"),  # exact
        ("cAMERAS", "65f1c0ffee0123456789ab01"),  # case-insensitive
        ("Fiber -", "65f1c0ffee0123456789ab02"),  # edge whitespace stripped
        ("65F1C0FFEE0123456789AB02", "65f1c0ffee0123456789ab02"),  # hex _id, any case
    ],
)
@pytest.mark.parametrize("op", ["update", "delete"])
async def test_tag_id_matches_as_documented(client, registry, given, want_id, op):
    client.get.return_value = copy.deepcopy(_TAGS)
    client.put.return_value = {}
    client.delete.return_value = None
    if op == "update":
        body = {"device_mac_additions": [], "device_mac_removals": []}
        await _update_device_tag(client, registry, "h", "s", given, body)
        assert client.put.call_args[0][0].endswith(f"/device-tags/{want_id}")
    else:
        await _delete_device_tag(client, registry, "h", "s", given)
        assert client.delete.call_args[0][0].endswith(f"/device-tags/{want_id}")


# --- dry_run_or_verbatim: docstring states the shapes it and its siblings return --------


def test_dry_run_or_verbatim_docstring_matches_the_shapes():
    doc = " ".join((dry_run_or_verbatim.__doc__ or "").split())
    assert "the shape every other write tool uses" not in doc
    assert "create_hotspot_operator" in doc and "update_hotspot_operator" in doc
    assert (
        'bare preview ``{status: "dry_run", dryRun: true, sent: false, message, preview: '
        "{method, path, params" in doc
    )
    preview = {
        "status": "dry_run",
        "dryRun": True,
        "message": DRY_RUN_MESSAGE,
        "preview": {"method": "POST", "path": "/probe", "params": None, "body": {"name": "probe"}},
    }
    assert dry_run_or_verbatim(preview) == {"status": "dry_run", "response": preview}
    assert dry_run_or_verbatim({"meta": {"rc": "ok"}}) == {"meta": {"rc": "ok"}}


async def test_update_setting_dry_run_is_the_bare_preview(client, registry):
    """The Network write named in the docstring returns the bare preview."""
    preview = {
        "status": "dry_run",
        "dryRun": True,
        "message": DRY_RUN_MESSAGE,
        "preview": {"method": "PUT", "path": "/probe", "params": None, "body": {"name": "probe"}},
    }
    client.dry_run = True
    client.get.side_effect = [_envelope({"key": "k", "a": 0})]
    client.put.return_value = preview
    assert await update_setting(client, registry, "h", "s", "k", {"a": 1}) == preview


# --- create_wifi_broadcast: required fields point at the per-variant list ---------------


def _variant_required() -> dict[str, list[str]]:
    schemas = json.loads(SPEC.read_text())["components"]["schemas"]
    return {
        "STANDARD": schemas["IntegrationStandardWifiBroadcastCreateUpdateDto"]["required"],
        "IOT_OPTIMIZED": schemas["IntegrationIotOptimizedWifiBroadcastCreateUpdateDto"]["required"],
    }


def test_create_wifi_broadcast_hint_points_at_the_variant_list():
    tool = TOOLS["create_wifi_broadcast"]
    flat = " ".join((tool.description or "").split())
    assert "for a STANDARD SSID also include" not in flat
    assert "parameter description lists the keys each ``type`` requires" in flat
    param = " ".join(tool.parameters["properties"]["broadcast"]["description"].split())
    common = {f.strip() for f in param.split("Required: ", 1)[1].split(".", 1)[0].split(",")}
    variants = param.split("Variants by type: ", 1)[1]
    for variant, required in _variant_required().items():
        after = variants.split(variant, 1)[1]
        listed = set(common)
        if after.startswith(" (requires "):
            needs = after[len(" (requires ") :].split(";", 1)[0].split(")", 1)[0]
            listed |= {f.strip() for f in needs.split(",")}
        assert set(required) <= listed, (variant, set(required) - listed)
        # The pinned spec does not require `network` for any variant; the hint says so.
        assert "network" not in required
    assert "The spec permits omitting network" in flat
    assert "the live controller requires it for OPEN broadcasts" in flat
    assert 'securityConfiguration: {type: "OPEN"}' in flat
    assert 'network: {type: "SPECIFIC", networkId: UUID from list_networks}' in flat
