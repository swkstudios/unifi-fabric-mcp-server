"""Dry-run results and previews, forget_device shape, physical actions.

1. Every delete tool under dry-run policy returns ``status: "dry_run"`` and never
   ``deleted: true`` (deletion_result recognises the preview).
2. The dry-run preview carries the query ``params`` the write would have sent.
3. forget_device with several MACs under dry-run is a dry-run result, never "forgotten".
4. forget_device with a list always returns ``{byMac, forgotten, errors}``.
5. update_setting / Protect verified updates ignore the additive ``_`` keys the client
   never sends (no false "silent no-op", no false ``verified: false``).
6. allow_/exclude_network_on_port_profile (and update_port_profile) return the bare
   preview under dry-run, with no name-resolution GET after the suppressed PUT.
8. list_client_sessions rejects an unknown session_type before any request.
9. restart_device / execute_device_action / execute_port_action / unadopt_device resolve a
   MAC to the device id; an unknown MAC fails listing the site's devices.
10. Network physical actions are not auto-retried on HTTP 429.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import LazyCatalog
from unifi_fabric import server
from unifi_fabric.client import DRY_RUN_MESSAGE, RateLimitError, is_dry_run_preview
from unifi_fabric.tools import device_mgmt, statistics
from unifi_fabric.tools._results import deletion_result
from unifi_fabric.tools.network import PROXY_BASE

TOOLS = LazyCatalog()


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


async def _call(monkeypatch, name: str, up: uh.FakeUpstream, args: dict | None = None, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    uh.install(monkeypatch, up)
    call_args = tool_args.generated_args(TOOLS[name])
    call_args.update(args or {})
    return uh.result_payload(await server.mcp.call_tool(name, call_args))


def _preview(payload: Any) -> dict[str, Any]:
    """The single dry-run preview in a result (bare, or under ``response``)."""
    if is_dry_run_preview(payload):
        return payload["preview"]
    assert isinstance(payload, dict) and is_dry_run_preview(payload.get("response")), payload
    return payload["response"]["preview"]


# --------------------------------------------------------------------------- (1)
def test_deletion_result_on_a_preview_is_a_dry_run_not_a_deletion():
    preview = {
        "dryRun": True,
        "message": DRY_RUN_MESSAGE,
        "preview": {"method": "DELETE", "path": "/x", "params": None, "body": None},
    }
    result = deletion_result("Network n-1 deleted.", preview)
    assert result == {
        "status": "dry_run",
        "deleted": False,
        "message": DRY_RUN_MESSAGE,
        "response": preview,
    }


def test_deletion_result_on_a_real_body_is_unchanged():
    assert deletion_result("Gone.", {"count": 2}) == {
        "deleted": True,
        "message": "Gone.",
        "response": {"count": 2},
    }


@pytest.mark.parametrize(
    "name",
    ["delete_network", "unadopt_device", "delete_vpn_server", "delete_arm_profile"],
)
async def test_named_delete_callers_report_dry_run(monkeypatch, name):
    up = uh.FakeUpstream()
    payload = await _call(monkeypatch, name, up, UNIFI_WRITE_POLICY="dry-run")
    assert up.writes() == []
    assert payload.get("deleted") is not True, payload
    assert payload["status"] == "dry_run"
    assert payload["message"] == DRY_RUN_MESSAGE
    assert _preview(payload)["method"] == "DELETE"


# --------------------------------------------------------------------------- (2)
async def test_preview_shows_the_bulk_voucher_delete_filter(monkeypatch):
    up = uh.FakeUpstream()
    payload = await _call(
        monkeypatch,
        "bulk_delete_hotspot_vouchers",
        up,
        {"filter_params": {"filter": "name.eq('Conference')"}},
        UNIFI_WRITE_POLICY="dry-run",
    )
    assert up.writes() == []
    assert _preview(payload)["params"] == {"filter": "name.eq('Conference')"}
    assert payload.get("deleted") is not True


@pytest.mark.parametrize("force", [True, False])
async def test_preview_shows_delete_network_force(monkeypatch, force):
    up = uh.FakeUpstream()
    payload = await _call(
        monkeypatch, "delete_network", up, {"force": force}, UNIFI_WRITE_POLICY="dry-run"
    )
    assert _preview(payload)["params"] == {"force": "true" if force else "false"}


async def test_preview_shows_the_policy_ordering_zone_ids(monkeypatch):
    up = uh.FakeUpstream()
    src, dst = "00000000-0000-4000-8000-0000000000b1", "00000000-0000-4000-8000-0000000000b2"
    payload = await _call(
        monkeypatch,
        "set_firewall_policy_ordering",
        up,
        {
            "source_zone_id": src,
            "destination_zone_id": dst,
            "ordering": {"orderedFirewallPolicyIds": ["00000000-0000-4000-8000-0000000000b3"]},
        },
        UNIFI_WRITE_POLICY="dry-run",
    )
    assert up.writes() == []
    assert _preview(payload)["params"] == {
        "sourceFirewallZoneId": src,
        "destinationFirewallZoneId": dst,
    }


async def test_preview_params_is_null_when_the_write_has_none(monkeypatch):
    up = uh.FakeUpstream()
    payload = await _call(monkeypatch, "delete_network", up, UNIFI_WRITE_POLICY="dry-run")
    preview = _preview(payload)
    assert "params" in preview and preview["params"] is None


# --------------------------------------------------------------------------- (3)/(4)
async def test_forget_several_macs_under_dry_run_is_not_forgotten(monkeypatch):
    up = uh.FakeUpstream()
    macs = ["02:00:5e:00:00:a1", "02-00-5E-00-00-A2"]
    payload = await _call(
        monkeypatch, "forget_device", up, {"mac": macs}, UNIFI_WRITE_POLICY="dry-run"
    )
    assert up.writes() == []
    assert "forgotten" not in payload, payload
    assert payload["status"] == "dry_run"
    assert payload["errors"] == []
    assert sorted(payload["byMac"]) == ["02:00:5e:00:00:a1", "02:00:5e:00:00:a2"]
    for mac, preview in payload["byMac"].items():
        assert is_dry_run_preview(preview)
        assert preview["preview"]["body"] == {"cmd": "delete-device", "mac": mac}


async def test_forget_one_mac_string_under_dry_run_returns_the_preview(monkeypatch):
    up = uh.FakeUpstream()
    payload = await _call(
        monkeypatch, "forget_device", up, {"mac": uh.ARG_MAC}, UNIFI_WRITE_POLICY="dry-run"
    )
    assert is_dry_run_preview(payload)


HOST_ID = "host-001"
SITE_ID = "11111111-0000-0000-0000-000000000001"
BASE = PROXY_BASE.format(host_id=HOST_ID)
SITEMGR = f"/v1/connector/consoles/{HOST_ID}/proxy/network/api/s/default/cmd/sitemgr"
OK = {"meta": {"rc": "ok"}, "data": []}


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    c.post = AsyncMock()
    c.put = AsyncMock()
    c.delete = AsyncMock()
    c.paginate_max_pages = None
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    r.resolve_site_slug = AsyncMock(return_value="default")
    return r


class TestForgetDeviceListShape:
    async def test_one_item_list_returns_the_per_mac_shape(self, client, registry):
        client.post.return_value = OK
        result = await device_mgmt._forget_device(client, registry, "h", "s", ["AABBCCDDEE01"])
        assert result == {
            "byMac": {"aa:bb:cc:dd:ee:01": OK},
            "forgotten": ["aa:bb:cc:dd:ee:01"],
            "errors": [],
        }

    async def test_duplicates_of_one_mac_return_the_per_mac_shape(self, client, registry):
        client.post.return_value = OK
        result = await device_mgmt._forget_device(
            client, registry, "h", "s", ["aa:bb:cc:dd:ee:01", "AA-BB-CC-DD-EE-01"]
        )
        assert client.post.await_count == 1
        assert set(result) == {"byMac", "forgotten", "errors"}
        assert result["forgotten"] == ["aa:bb:cc:dd:ee:01"]

    async def test_one_failure_in_a_list_goes_in_errors(self, client, registry):
        from unifi_fabric.client import UniFiConnectionError

        err = UniFiConnectionError("HTTP 400 from POST x: api.err.UnknownDevice")
        client.post.side_effect = [err, OK]
        result = await device_mgmt._forget_device(
            client, registry, "h", "s", ["02:de:ad:be:ef:01", "aa:bb:cc:dd:ee:02"]
        )
        assert result["errors"] == [{"mac": "02:de:ad:be:ef:01", "error": str(err)}]
        assert result["forgotten"] == ["aa:bb:cc:dd:ee:02"]

    async def test_a_one_item_list_whose_mac_fails_raises(self, client, registry):
        from unifi_fabric.client import UniFiConnectionError

        client.post.side_effect = UniFiConnectionError("HTTP 400: api.err.UnknownDevice")
        with pytest.raises(UniFiConnectionError, match="every MAC failed"):
            await device_mgmt._forget_device(client, registry, "h", "s", ["02:de:ad:be:ef:01"])

    async def test_a_string_returns_the_envelope_verbatim(self, client, registry):
        client.post.return_value = OK
        assert await device_mgmt._forget_device(client, registry, "h", "s", "aabbccddee01") is OK


# --------------------------------------------------------------------------- (5)
async def test_update_setting_ignores_additive_keys_in_the_payload(monkeypatch):
    """A payload carrying ``_note`` (as a no-op update_setting result does) is not a
    "silent no-op": the client never sends ``_note``, so it is not checked either."""
    up = uh.FakeUpstream()
    payload = await _call(
        monkeypatch,
        "update_setting",
        up,
        {"payload": {"name": "probe-renamed", "_note": "no change needed", "_keyLabel": "k"}},
    )
    puts = [s for s in up.writes() if s.method == "PUT"]
    assert len(puts) == 1
    assert "_note" not in puts[0].sent_json and "_keyLabel" not in puts[0].sent_json
    assert isinstance(payload, dict)


async def test_update_setting_noop_check_ignores_additive_keys(monkeypatch):
    # Both calls must address the same setting: on generated records both use the
    # generated setting_key, while replay would read get_setting's captured key
    # (super_cloudaccess) and send update_setting's synthetic one.
    up = uh.FakeUpstream(replay_recordings=False)
    current = await _call(monkeypatch, "get_setting", up)
    record = dict(current["data"][0])
    record["_note"] = "no change needed"
    up2 = uh.FakeUpstream(replay_recordings=False)
    payload = await _call(monkeypatch, "update_setting", up2, {"payload": record})
    assert up2.writes() == [], "a read result fed back in (plus _note) is no change"
    assert payload["_note"] == "no change needed"


async def test_protect_update_verifies_despite_additive_keys(monkeypatch):
    # Generated records: the read-after must reflect the PATCH, which a replayed camera
    # capture (the same body on every read) never does.
    up = uh.FakeUpstream(replay_recordings=False)
    payload = await _call(
        monkeypatch,
        "update_camera",
        up,
        {"settings": {"name": "probe-renamed", "_keyLabel": "k-alpha"}},
    )
    assert payload["status"] == "updated"
    assert payload["verified"] is True, payload


# --------------------------------------------------------------------------- (6)
@pytest.mark.parametrize(
    "name",
    ["allow_network_on_port_profile", "exclude_network_on_port_profile", "update_port_profile"],
)
async def test_port_profile_writes_return_the_bare_preview(monkeypatch, name):
    up = uh.FakeUpstream()
    payload = await _call(monkeypatch, name, up, UNIFI_WRITE_POLICY="dry-run")
    assert up.writes() == []
    assert is_dry_run_preview(payload), payload
    assert not {"_profileNote", "_tagged_networks", "_network"} & set(payload)
    # No name-resolution read after the suppressed PUT: allow/exclude read networkconf
    # once (to validate the network) and update_port_profile not at all.
    networkconf_reads = [s for s in up.served if s.path.endswith("/rest/networkconf")]
    assert len(networkconf_reads) == (0 if name == "update_port_profile" else 1)


# --------------------------------------------------------------------------- (8)
async def test_list_client_sessions_rejects_a_mistyped_session_type(client, registry):
    with pytest.raises(ValueError) as exc:
        await statistics._list_client_sessions(
            client, registry, "h", "s", uh.NOW - 60, uh.NOW, "guests"
        )
    assert set(statistics.SESSION_TYPES) == {"all", "user", "guest", "voucher"}
    for choice in statistics.SESSION_TYPES:
        assert repr(choice) in str(exc.value)
    client.post.assert_not_called()
    registry.resolve_key_for_host.assert_not_called()


@pytest.mark.parametrize("session_type", ["all", "user", "guest", "voucher"])
async def test_list_client_sessions_forwards_a_valid_session_type(client, registry, session_type):
    client.post.return_value = OK
    await statistics._list_client_sessions(
        client, registry, "h", "s", uh.NOW - 60, uh.NOW, session_type
    )
    assert client.post.call_args.kwargs["json"]["type"] == session_type


# --------------------------------------------------------------------------- (9)
DEVICE_UUID = "dddddddd-0000-4000-8000-000000000001"
DEVICES = [{"id": DEVICE_UUID, "name": "AP-1", "macAddress": "aa:bb:cc:dd:ee:01"}]


def _mac_tool_calls() -> list[Any]:
    devices = f"{BASE}/sites/{SITE_ID}/devices/{{id}}"
    return [
        pytest.param(
            lambda c, r, d: device_mgmt._restart_device(c, r, "h", "s", d),
            "post",
            devices + "/actions",
            id="restart_device",
        ),
        pytest.param(
            lambda c, r, d: device_mgmt._execute_device_action(
                c, r, "h", "s", d, {"action": "RESTART"}
            ),
            "post",
            devices + "/actions",
            id="execute_device_action",
        ),
        pytest.param(
            lambda c, r, d: device_mgmt._execute_port_action(
                c, r, "h", "s", d, 3, {"action": "POWER_CYCLE"}
            ),
            "post",
            devices + "/interfaces/ports/3/actions",
            id="execute_port_action",
        ),
        pytest.param(
            lambda c, r, d: device_mgmt._unadopt_device(c, r, "h", "s", d),
            "delete",
            devices,
            id="unadopt_device",
        ),
    ]


@pytest.mark.parametrize("call,verb,path", _mac_tool_calls())
@pytest.mark.parametrize("mac", ["AA:BB:CC:DD:EE:01", "aabbccddee01", "aa-bb-cc-dd-ee-01"])
async def test_mac_is_resolved_to_the_device_id(client, registry, call, verb, path, mac):
    device_mgmt._mac_uuid_cache.clear()
    client.get.return_value = {"data": DEVICES, "totalCount": len(DEVICES)}
    await call(client, registry, mac)
    sent = getattr(client, verb)
    sent.assert_awaited_once()
    assert sent.call_args.args[0] == path.format(id=DEVICE_UUID)
    # Sent once by the client's one retry rule (no per-call retry override).
    assert "max_retries" not in sent.call_args.kwargs


@pytest.mark.parametrize("call,verb,path", _mac_tool_calls())
async def test_unknown_mac_fails_listing_the_devices(client, registry, call, verb, path):
    device_mgmt._mac_uuid_cache.clear()
    client.get.return_value = {"data": DEVICES, "totalCount": len(DEVICES)}
    with pytest.raises(ValueError) as exc:
        await call(client, registry, "02:de:ad:be:ef:99")
    msg = str(exc.value)
    assert "02:de:ad:be:ef:99" in msg and "AP-1" in msg and DEVICE_UUID in msg
    getattr(client, verb).assert_not_called()


# --------------------------------------------------------------------------- (10)
PHYSICAL_TOOLS = {
    "restart_device": {},
    "execute_device_action": {"action": {"action": "RESTART"}},
    "execute_port_action": {"action": {"action": "POWER_CYCLE"}},
    "locate_device": {},
    "upgrade_device": {},
    "forget_device": {"mac": uh.ARG_MAC},
    "unadopt_device": {},
}


class _RateLimitedWrites(uh.FakeUpstream):
    """Answers every write with HTTP 429 (reads as normal)."""

    def __call__(self, request: httpx.Request) -> httpx.Response:  # type: ignore[override]
        from unifi_fabric.read_only import is_write_request

        if is_write_request(request.method, request.url.path, uh.request_json(request)):
            self._record(request, 429, None, False)
            return httpx.Response(429, text="rate limited", request=request)
        return super().__call__(request)


@pytest.mark.parametrize("name", sorted(PHYSICAL_TOOLS))
async def test_network_physical_actions_are_not_retried_on_429(monkeypatch, name):
    async def _no_sleep(_s: float) -> None:
        return None

    monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", _no_sleep)
    up = _RateLimitedWrites()
    with pytest.raises(Exception) as exc:
        await _call(monkeypatch, name, up, PHYSICAL_TOOLS[name])
    assert "429" in str(exc.value) or isinstance(exc.value, RateLimitError)
    assert len(up.writes()) == 1, f"{name}: a 429 was retried ({len(up.writes())} writes)"
