"""Source-defined reboot and custom firmware extensions."""

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.families.devices.device_mgmt import _restart_device, _upgrade_device


@pytest.fixture
def deps():
    c, r = AsyncMock(), AsyncMock()
    c.dry_run = False
    r.resolve_key_for_host.return_value = "owning-key"
    r.resolve_host_id.return_value = "console"
    r.resolve_site_id.return_value = "11111111-0000-0000-0000-000000000001"
    r.resolve_site_slug.return_value = "default"
    c.get.return_value = {"macAddress": "02:00:5e:00:00:01"}
    c.post.return_value = {"meta": {"rc": "ok"}, "data": [], "extra": "verbatim"}
    return c, r


async def test_hard_restart_exact_source_body(deps):
    c, r = deps
    out = await _restart_device(c, r, "h", "s", "device", reboot_type="hard")
    c.post.assert_awaited_once_with(
        "/v1/connector/consoles/console/proxy/network/api/s/default/cmd/devmgr",
        key="owning-key",
        json={"cmd": "restart", "macs": ["02:00:5e:00:00:01"], "reboot_type": "hard"},
    )
    assert out is c.post.return_value


async def test_default_restart_integration_unchanged(deps):
    c, r = deps
    await _restart_device(c, r, "h", "s", "device")
    assert c.post.call_args.kwargs["json"] == {"action": "RESTART"}


async def test_external_firmware_exact_source_body(deps):
    c, r = deps
    out = await _upgrade_device(
        c, r, "h", "s", "device", firmware_url="https://example.com/firmware.bin"
    )
    c.post.assert_awaited_once_with(
        "/v1/connector/consoles/console/proxy/network/api/s/default/cmd/devmgr/upgrade-external",
        key="owning-key",
        json={"url": "https://example.com/firmware.bin", "macs": ["02:00:5e:00:00:01"]},
    )
    assert out is c.post.return_value


async def test_default_upgrade_body_unchanged(deps):
    c, r = deps
    await _upgrade_device(c, r, "h", "s", "device")
    assert c.post.call_args.kwargs["json"] == {"cmd": "upgrade", "mac": "02:00:5e:00:00:01"}
