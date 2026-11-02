"""Regression cases for the remaining upstream/context collision sites found in the 0.7.0 review."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import DRY_RUN_MESSAGE, UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.redaction import MASKED_FIELDS_KEY, _with_dropped_report
from unifi_fabric.tools import (
    _device_config,
    aggregation,
    connector,
    device_commands,
    device_mgmt,
    device_radios,
    innerspace_internal,
    network_controller_admin,
    protect_camera_recording,
    protect_recognition_search,
)
from unifi_fabric.tools._keys import context_value, with_context


@pytest.mark.parametrize("array", [False, True], ids=["object", "array-record"])
@pytest.mark.parametrize("upstream", [False, None, ["upstream"], {"source": "upstream"}])
def test_dropped_report_preserves_upstream_field(array, upstream):
    record = {
        "id": "upstream-record",
        MASKED_FIELDS_KEY: upstream,
        "_wrapperFields": {"keep": "upstream bucket"},
    }
    original = copy.deepcopy(record)
    body = [record, 7, None] if array else record
    result = _with_dropped_report(body, ["password", "nested.secret"])
    node = result[0] if array else result
    assert node == {
        **original,
        "_wrapperFields_2": {MASKED_FIELDS_KEY: ["password", "nested.secret"]},
    }
    assert record == original
    if array:
        assert result[1:] == [7, None]


@pytest.mark.parametrize("partial", ["managed", "both"])
@pytest.mark.parametrize("upstream_flag", [False, None])
async def test_firmware_reads_private_incomplete_context(monkeypatch, partial, upstream_flag):
    integration = with_context(
        {"data": [], "incomplete": upstream_flag, "incompleteReason": "upstream integration"},
        {"incomplete": True, "incompleteReason": "integration stalled"}
        if partial == "both"
        else {},
    )
    managed = with_context(
        {"data": [], "incomplete": upstream_flag, "incompleteReason": "upstream managed"},
        {"incomplete": True, "incompleteReason": "managed stalled"},
    )
    monkeypatch.setattr(
        network_controller_admin.device_mgmt,
        "_list_site_devices",
        AsyncMock(return_value=integration),
    )
    monkeypatch.setattr(
        network_controller_admin.site_manager,
        "list_devices",
        AsyncMock(return_value=managed),
    )
    result = await network_controller_admin.get_latest_firmware_versions(None, None, "host", "site")
    expected = (
        "Integration devices: integration stalled; Site Manager: managed stalled"
        if partial == "both"
        else "Site Manager: managed stalled"
    )
    assert result["incomplete"] is upstream_flag
    assert result["incompleteReason"] == "upstream integration"
    assert result["_siteManagerDevices"] is managed
    assert context_value(result, "incomplete") is True
    assert context_value(result, "incompleteReason") == expected
    assert any(
        isinstance(bucket, dict) and bucket.get("incompleteReason") == expected
        for key, bucket in result.items()
        if key.startswith("_wrapperFields")
    )


@pytest.mark.parametrize("upstream_flag", [False, None, True])
async def test_group_lookup_reads_private_incomplete_reason(monkeypatch, upstream_flag):
    listed = with_context(
        {"groups": [{"id": "known"}], "incomplete": upstream_flag, "incompleteReason": "upstream"},
        {"incomplete": True, "incompleteReason": "group drain stalled"},
    )
    monkeypatch.setattr(
        protect_recognition_search, "list_recognition_groups", AsyncMock(return_value=listed)
    )
    with pytest.raises(ValueError, match=r"incomplete \(group drain stalled\)"):
        await protect_recognition_search._find_group(None, None, "host", "face", "missing")
    assert listed["incomplete"] is upstream_flag
    assert listed["incompleteReason"] == "upstream"


async def test_multikey_fleet_envelope_preserves_pre521_bytes(monkeypatch):
    envelopes = {"alpha": {"traceId": "a"}, "beta": {"traceId": "b"}}

    async def fleet(client, key_label, params, out):
        out.update(envelopes)
        return [{"id": "device"}], ["alpha", "beta"], [], []

    monkeypatch.setattr(aggregation, "_fleet_devices", fleet)
    result = await aggregation._list_all_devices_fleet(None)
    expected = {
        "data": [{"id": "device"}],
        "_count": 1,
        "_filter": None,
        "_key_label": None,
        "byKey": envelopes,
        "_key_labels": ["alpha", "beta"],
    }
    assert json.dumps(result).encode() == json.dumps(expected).encode()


@pytest.mark.parametrize(
    ("site", "field"),
    [
        ("command", "_consequence"),
        ("physical", "_consequence"),
        ("devmgr", "_consequence"),
        ("classic-command", "_consequence"),
        ("config", "_verified"),
        ("radios", "_readBeforeResponse"),
        ("upload", "_form"),
        ("epoch", "_warnings"),
    ],
)
async def test_upstream_preview_shaped_metadata_survives(monkeypatch, site, field):
    upstream = {
        "dryRun": True,
        "message": DRY_RUN_MESSAGE,
        "preview": {},
        field: {"keep": "upstream"},
        "_wrapperFields": "occupied",
    }
    original = copy.deepcopy(upstream)
    client = UniFiClient(Settings(api_key="synthetic-test-key"))
    monkeypatch.setattr(client, "post", AsyncMock(return_value=upstream))
    monkeypatch.setattr(client, "post_multipart", AsyncMock(return_value=upstream))
    registry = AsyncMock()
    registry.resolve_site_id.return_value = "11111111-0000-4000-8000-000000000001"
    if site == "command":
        result = await device_commands._command(
            client, registry, "host", "site", "devmgr", {"cmd": "force-provision"}
        )
    elif site == "physical":
        result = device_mgmt._physical_preview(upstream, "physical consequence")
    elif site == "devmgr":
        monkeypatch.setattr(device_mgmt, "_device_mac", AsyncMock(return_value="aa:bb:cc:dd:ee:ff"))
        result = await device_mgmt._classic_devmgr(
            client, registry, "host", "site", "device-id", "restart"
        )
    elif site == "classic-command":
        monkeypatch.setattr(device_mgmt, "_device_mac", AsyncMock(return_value="aa:bb:cc:dd:ee:ff"))
        result = await device_mgmt._classic_device_command(
            client,
            registry,
            "host",
            "site",
            "device-id",
            "/upgrade",
            {"url": "https://example.invalid/firmware"},
            plural=False,
        )
    elif site == "config":
        monkeypatch.setattr(client, "put", AsyncMock(return_value=upstream))
        result = await _device_config.update_device_config(
            client,
            "/device",
            {"enabled": False},
            {"enabled": True},
            {"enabled": True},
            AsyncMock(),
            lambda before, after: {"enabled": after["enabled"]},
            key=None,
        )
    elif site == "radios":
        before = {
            "_id": "device-id",
            "mac": "aa:bb:cc:dd:ee:ff",
            "radio_table": [{"radio": "na", "channel": 36}],
        }
        monkeypatch.setattr(
            device_radios,
            "_read_device",
            AsyncMock(return_value=({"meta": {"rc": "ok"}}, before)),
        )
        monkeypatch.setattr(
            device_radios,
            "resolve_site_slug",
            AsyncMock(return_value=(None, "host-id", "site-slug")),
        )
        monkeypatch.setattr(
            client, "get", AsyncMock(return_value={"meta": {"rc": "ok"}, "data": [before]})
        )
        # The update core can return a preserved upstream dry-run-shaped response.
        monkeypatch.setattr(device_radios, "update_device_config", AsyncMock(return_value=upstream))
        result = await device_radios._update_device_radio(
            client, registry, "host", "site", "aa:bb:cc:dd:ee:ff", {"na": {"channel": 40}}
        )
    elif site == "upload":
        result = await innerspace_internal.upload_innerspace_plan_asset(
            client, registry, "host", "plan.png", "aGVsbG8=", "assets"
        )
    else:
        result = protect_camera_recording._with_epoch_unit(upstream, start=-1)
    assert result[field] == original[field]
    assert result["_wrapperFields"] == "occupied"
    assert field in result["_wrapperFields_2"]
    assert upstream == original
    await client.close()


def test_readme_documents_empty_patch_whole_body_fallback():
    before = {"status": 200, "body": {"enabled": True, "updatedAt": 1}}
    after = {"status": 200, "body": {"enabled": True, "updatedAt": 2}}
    assert connector._no_op_verdict("PATCH", 200, before, after, {}) == (False, None)
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
    paragraph = next(line for line in readme.splitlines() if line.startswith("- **Read-before"))
    assert "empty object" in paragraph and "whole reads" in paragraph
    assert "empty-object PATCH" in paragraph and "noOp: false" in paragraph


def test_existing_tool_collision_fragment_is_a_fix():
    from tests.changelog_section import current_release

    version, release = current_release()
    assert version == "0.7.0"
    entry = next(
        line
        for line in release.splitlines()
        if line.startswith("- Keep upstream `_redactedFieldsNotSent` values")
    )
    fixed = release.split("### Fixed", 1)[1].split("### ", 1)[0]
    assert entry in fixed
    assert "put a colliding server report in `_wrapperFields`" in entry
    assert "fleet device envelope's field order" in entry
