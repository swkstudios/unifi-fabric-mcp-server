"""Network 11.1.47 write tools: port automations, wake_client, and the guest-password redaction.

Hermetic: synthetic upstream bodies only. The request shapes are the ones the Network
11.1.47 web application sends (``port-automations`` module and the ``wake-on-lan`` client
action, mined with ``scripts/private_api/mine_fe_routes.py``); the empty-list body of
``GET port-automations`` was recorded read-only from the development console (HTTP 200, ``[]``).
"""

from __future__ import annotations

import copy
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastmcp import FastMCP

from unifi_fabric.client import DRY_RUN_MESSAGE, UniFiConnectionError
from unifi_fabric.families.clients import clients as clients_mod
from unifi_fabric.families.clients import registrar as clients_registrar
from unifi_fabric.families.network import network_switching_power as power
from unifi_fabric.families.network import registrar as network_registrar
from unifi_fabric.redaction import REDACTION_MASK, redact_credentials

HOST = "console-a"
SITE = "Default"
AUTOMATION_ID = "65f1c0ffee0123456789abcd"
OTHER_ID = "65f1c0ffee0123456789abce"
V2 = "/v1/connector/consoles/host-1/proxy/network/v2/api/site/default"
MAC = "aa:bb:cc:dd:ee:ff"

#: The record shape the 11.1.47 web application writes and reads (zod schema and
#: ``$s`` serializer in its port-automations chunk).
AUTOMATION = {
    "id": AUTOMATION_ID,
    "name": "Phones",
    "enabled": True,
    "port_profile_id": "65f1c0ffee0123456789ab00",
    "match": {"vendor_ids": [12], "mac_ouis": ["001122"]},
    "scope": {
        "switch_macs": ["02:00:5e:00:53:01"],
        "device_tag_ids": [],
        "port_range": {"from_port": 1, "to_port": 24},
    },
}


class Registry:
    def __init__(self) -> None:
        self.calls = 0

    async def resolve_key_for_host(self, host: str) -> None:
        self.calls += 1

    async def resolve_host_id(self, host: str, *, key: None) -> str:
        self.calls += 1
        return "host-1"

    async def resolve_site_slug(self, site: str, host_id: str, *, key: None) -> str:
        self.calls += 1
        return "default"


class Client:
    def __init__(self, rows: Any = None, *, dry_run: bool = False) -> None:
        self.rows = [copy.deepcopy(AUTOMATION)] if rows is None else rows
        self.dry_run = dry_run
        self.calls: list[tuple[str, str, Any]] = []

    async def get(self, path: str, *, key: None) -> Any:
        self.calls.append(("GET", path, None))
        return copy.deepcopy(self.rows)

    def _write(self, method: str, path: str, body: Any) -> Any:
        self.calls.append((method, path, body))
        if self.dry_run:
            return {
                "status": "dry_run",
                "dryRun": True,
                "sent": False,
                "message": DRY_RUN_MESSAGE,
                "preview": {"method": method, "path": path, "params": None, "body": body},
            }
        return {"echo": body}

    async def post(self, path: str, *, key: None, json: Any) -> Any:
        return self._write("POST", path, json)

    async def put(self, path: str, *, key: None, json: Any) -> Any:
        return self._write("PUT", path, json)

    async def delete(self, path: str, *, key: None) -> Any:
        return self._write("DELETE", path, None)


async def test_every_port_automation_tool_uses_the_11_1_47_route() -> None:
    client, registry = Client(), Registry()
    await power.list_port_automations(client, registry, HOST, SITE)
    await power.get_port_automation(client, registry, HOST, SITE, AUTOMATION_ID)
    await power.create_port_automation(client, registry, HOST, SITE, {"name": "n"})
    await power.update_port_automation(
        client, registry, HOST, SITE, AUTOMATION_ID, {"enabled": False}
    )
    await power.delete_port_automation(client, registry, HOST, SITE, AUTOMATION_ID)
    sent = {(method, path.removeprefix(V2)) for method, path, _ in client.calls}
    assert sent == {
        ("GET", "/port-automations"),
        ("POST", "/port-automations"),
        ("PUT", f"/port-automations/{AUTOMATION_ID}"),
        ("DELETE", f"/port-automations/{AUTOMATION_ID}"),
    }
    assert all(path.startswith(V2) for _, path, _ in client.calls)


async def test_list_passes_the_recorded_empty_body_and_get_returns_the_record_verbatim() -> None:
    assert await power.list_port_automations(Client([]), Registry(), HOST, SITE) == []
    record = await power.get_port_automation(
        Client(), Registry(), HOST, SITE, AUTOMATION_ID.upper()
    )
    assert record == AUTOMATION


async def test_get_and_delete_name_every_valid_id_for_an_unknown_id() -> None:
    for call in (power.get_port_automation, power.delete_port_automation):
        client = Client()
        with pytest.raises(ValueError, match=f"id={AUTOMATION_ID}") as excinfo:
            await call(client, Registry(), HOST, SITE, OTHER_ID)
        assert "No write was sent" in str(excinfo.value)
        assert [method for method, *_ in client.calls] == ["GET"]


async def test_create_sends_the_body_verbatim() -> None:
    body = copy.deepcopy(AUTOMATION)
    del body["id"]
    result = await power.create_port_automation(Client(), Registry(), HOST, SITE, body)
    assert result == {"echo": body}


async def test_update_merges_nested_leaves_and_puts_the_whole_record() -> None:
    client = Client()
    result = await power.update_port_automation(
        client,
        Registry(),
        HOST,
        SITE,
        AUTOMATION_ID,
        {"scope": {"port_range": {"to_port": 48}}, "enabled": False},
    )
    assert [method for method, *_ in client.calls] == ["GET", "PUT", "GET"]
    expected = copy.deepcopy(AUTOMATION)
    expected["enabled"] = False
    expected["scope"]["port_range"]["to_port"] = 48
    assert client.calls[1][2] == expected
    # The synthetic upstream did not apply the change, so the read-back must say so.
    assert result["_verified"] is False


@pytest.mark.parametrize(
    "call",
    [
        lambda c, r: power.update_port_automation(c, r, HOST, SITE, "bad id", {"enabled": True}),
        lambda c, r: power.update_port_automation(c, r, HOST, SITE, AUTOMATION_ID, {}),
        lambda c, r: power.update_port_automation(c, r, HOST, SITE, AUTOMATION_ID, {"id": "x"}),
        lambda c, r: power.delete_port_automation(c, r, HOST, SITE, "a/b"),
        lambda c, r: power.get_port_automation(c, r, HOST, SITE, "../x"),
    ],
)
async def test_invalid_input_fails_before_any_resolution_or_request(call: Any) -> None:
    client, registry = Client(), Registry()
    with pytest.raises(ValueError):
        await call(client, registry)
    assert client.calls == []
    assert registry.calls == 0


async def test_dry_run_previews_every_write_and_sends_nothing_else() -> None:
    client = Client(dry_run=True)
    created = await power.create_port_automation(client, Registry(), HOST, SITE, {"name": "n"})
    assert created["status"] == "dry_run" and created["sent"] is False
    deleted = await power.delete_port_automation(client, Registry(), HOST, SITE, AUTOMATION_ID)
    assert deleted["deleted"] is False and deleted["response"]["status"] == "dry_run"


async def test_annotations_are_derived_reads_for_list_and_get_only() -> None:
    mcp = FastMCP("port-automations")
    network_registrar.register_5(mcp, lambda: (Client(), Registry()))
    tools = {t.name: t for t in await mcp.list_tools()}
    names = {
        "list_port_automations",
        "get_port_automation",
        "create_port_automation",
        "update_port_automation",
        "delete_port_automation",
    }
    assert names <= set(tools)
    for name in names:
        read_only = name.startswith(("list_", "get_"))
        assert tools[name].annotations.readOnlyHint is read_only, name
        assert tools[name].annotations.destructiveHint is (not read_only), name
        for prop, schema in tools[name].parameters["properties"].items():
            assert schema.get("description"), (name, prop)


# --------------------------------------------------------------------------- wake_client


@pytest.fixture()
def wake_client_fixture():
    client = AsyncMock()
    client.get = AsyncMock()
    client.post = AsyncMock(return_value={})
    registry = AsyncMock()
    registry.resolve_host_id = AsyncMock(return_value="host-1")
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_site_id = AsyncMock(return_value="11111111-0000-0000-0000-000000000001")
    registry.resolve_site_slug = AsyncMock(return_value="default")
    return client, registry


async def test_wake_client_posts_an_empty_body_to_the_wake_on_lan_route(
    wake_client_fixture,
) -> None:
    client, registry = wake_client_fixture
    result = await clients_mod._wake_client(client, registry, HOST, SITE, "AA-BB-CC-DD-EE-FF")
    client.get.assert_not_called()
    client.post.assert_called_once_with(f"{V2}/wake-on-lan/{MAC}", key=None, json={})
    assert result == {}


async def test_wake_client_resolves_a_client_id_to_its_mac(wake_client_fixture) -> None:
    client, registry = wake_client_fixture
    client_id = "00000000-0000-4000-8000-0000000000c1"
    client.get.return_value = {"id": client_id, "macAddress": MAC.upper()}
    await clients_mod._wake_client(client, registry, HOST, SITE, client_id)
    client.post.assert_called_once_with(f"{V2}/wake-on-lan/{MAC}", key=None, json={})


async def test_wake_client_refuses_a_bad_reference_before_any_request(wake_client_fixture) -> None:
    client, registry = wake_client_fixture
    with pytest.raises(ValueError):
        await clients_mod._wake_client(client, registry, HOST, SITE, "not-a-client")
    registry.resolve_host_id.assert_not_called()
    client.post.assert_not_called()


async def test_wake_client_needs_a_mac_for_a_vpn_client(wake_client_fixture) -> None:
    client, registry = wake_client_fixture
    client_id = "00000000-0000-4000-8000-0000000000c2"
    client.get.return_value = {"id": client_id, "type": "VPN"}
    with pytest.raises(ValueError, match="no MAC"):
        await clients_mod._wake_client(client, registry, HOST, SITE, client_id)
    client.post.assert_not_called()


async def test_wake_client_surfaces_an_unreadable_client(wake_client_fixture) -> None:
    client, registry = wake_client_fixture
    client.get.return_value = {"id": "x"}
    with pytest.raises(UniFiConnectionError, match="MAC address"):
        await clients_mod._wake_client(
            client, registry, HOST, SITE, "00000000-0000-4000-8000-0000000000c1"
        )


async def test_wake_client_is_a_derived_write() -> None:
    mcp = FastMCP("wake")
    clients_registrar.register(mcp, lambda: (AsyncMock(), AsyncMock()))
    tool = next(t for t in await mcp.list_tools() if t.name == "wake_client")
    assert tool.annotations.readOnlyHint is False
    assert set(tool.parameters["properties"]) == {"host", "site", "client_id"}
    assert all(p.get("description") for p in tool.parameters["properties"].values())


# ------------------------------------------------------------ guest personal password


def test_guest_personal_wifi_password_is_masked_when_redaction_is_on() -> None:
    """Network 11.1.47 hotspot guests carry ``personal_wifi_password`` (the web app's guest
    panel reads it); the opt-in ``_password`` suffix rule masks it and leaves the rest."""
    guest = {
        "_id": AUTOMATION_ID,
        "mac": MAC,
        "authorized_by": "voucher",
        "personal_wifi_password": "correct-horse",
        "hotspot_client": {"fingerprint": {"has_override": False}},
    }
    masked = redact_credentials(copy.deepcopy(guest))
    assert masked["personal_wifi_password"] == REDACTION_MASK
    assert {k: v for k, v in masked.items() if k != "personal_wifi_password"} == {
        k: v for k, v in guest.items() if k != "personal_wifi_password"
    }


async def _write_with_masked_guest_password(monkeypatch, name: str, redact: bool):
    """Run a write whose body carries a redacted ``personal_wifi_password`` and return
    the sent bodies and the tool payload."""
    from tests import test_cross_tool_invariants as cti
    from tests import tool_args
    from tests import upstream_harness as uh

    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true" if redact else "false")
    up = uh.FakeUpstream()
    args = tool_args.generated_args(cti.TOOLS[name])
    body_arg = "automation"
    fields = {"name": "kept", "personal_wifi_password": REDACTION_MASK}
    args[body_arg] = fields
    payload = uh.result_payload(await cti._call(monkeypatch, name, up, args))
    return [w.sent_json for w in up.writes() if w.sent_json is not None], payload


@pytest.mark.parametrize("name", ["create_port_automation", "update_port_automation"])
async def test_a_redacted_guest_password_is_left_out_of_the_write_body(monkeypatch, name) -> None:
    """With ``UNIFI_REDACT_SECRETS`` on, a read-side mask fed back into a write is dropped
    (never stored over the real password), siblings are kept and the drop is reported."""
    from unifi_fabric.redaction import MASKED_FIELDS_KEY

    sent, payload = await _write_with_masked_guest_password(monkeypatch, name, redact=True)
    assert sent, f"{name}: no write was sent"
    assert all("personal_wifi_password" not in body for body in sent)
    assert any(body.get("name") == "kept" for body in sent)
    assert payload[MASKED_FIELDS_KEY] == ["personal_wifi_password"]


async def test_the_mask_is_not_dropped_when_redaction_is_off(monkeypatch) -> None:
    sent, payload = await _write_with_masked_guest_password(
        monkeypatch, "create_port_automation", redact=False
    )
    assert any(body.get("personal_wifi_password") == REDACTION_MASK for body in sent)
    assert "_redactedFieldsNotSent" not in payload
