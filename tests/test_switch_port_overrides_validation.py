"""Switch port override editor: physical-port targets, network id validation, read-back.

Phantom port handling, network ids checked against the site before the PUT, and
verification of every field sent on an updated port.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.families.devices.switch_port_overrides import (
    _update_switch_port_overrides,
)

SPAN = "mir" + "ror"
SPAN_PORT = SPAN + "_port_idx"
PORT_TABLE = [{"port_idx": n, "op_mode": "switch"} for n in range(1, 9)]  # 8-port switch
PHANTOM = 52
BASE = [
    {"port_idx": 1, "name": "uplink", "poe_mode": "auto"},
    {"port_idx": 2, "name": "desk", "poe_mode": "off"},
]


def make(overrides: list[dict[str, Any]] | None = None) -> uh.FakeUpstream:
    up = uh.FakeUpstream(replay_recordings=False)
    up.overlay.update(
        {
            "port_table": copy.deepcopy(PORT_TABLE),
            "port_overrides": copy.deepcopy(BASE if overrides is None else overrides),
        }
    )
    return up


def puts(up):
    return [s for s in up.served if s.method == "PUT"]


def by_port(rows):
    return {r["port_idx"]: r for r in rows}


async def upd(c, r, host=None, site=None, device=None, ports=None, remove=None, **kw):
    return await _update_switch_port_overrides(
        c, r, host or uh.HOST, site or uh.SITE, device or uh.ARG_MAC, ports, remove, **kw
    )


# ------------------------------------------------------------------ Q1 phantom ports


async def test_q1a_new_phantom_port_is_refused_before_any_write(monkeypatch):
    up = make()
    c, r = uh.install(monkeypatch, up), server._registry
    with pytest.raises(
        ValueError, match=r"Unknown port_idx 9 .*valid ports: \[1, 2, 3, 4, 5, 6, 7, 8\]"
    ):
        await upd(c, r, ports=[{"port_idx": 9, "name": "ghost"}])
    assert not puts(up)
    await c.close()


async def test_q1b_existing_phantom_override_is_not_offered_as_a_writable_port(monkeypatch):
    """Peer rule: refuse any port_idx not in a non-empty port_table, even if an override exists."""
    up = make([*BASE, {"port_idx": PHANTOM, "name": "dangling"}])
    c, r = uh.install(monkeypatch, up), server._registry
    with pytest.raises(ValueError, match="Unknown port_idx 52"):
        await upd(c, r, ports=[{"port_idx": PHANTOM, "name": "still-ghost"}])
    assert not puts(up)
    await c.close()


async def test_q1c_monitor_target_must_be_a_physical_port(monkeypatch):
    up = make([*BASE, {"port_idx": PHANTOM, "name": "dangling"}])
    c, r = uh.install(monkeypatch, up), server._registry
    with pytest.raises(ValueError, match="Unknown " + SPAN_PORT):
        await upd(c, r, ports=[{"port_idx": 8, "op_mode": SPAN, SPAN_PORT: PHANTOM}])
    assert not puts(up)
    await c.close()


async def test_q1d_existing_phantom_is_preserved_verbatim_and_removable(monkeypatch):
    ghost = {"port_idx": PHANTOM, "name": "dangling", "poe_mode": "off"}
    up = make([*BASE, ghost])
    c, r = uh.install(monkeypatch, up), server._registry
    out = await upd(c, r, ports=[{"port_idx": 2, "name": "desk2"}])
    assert by_port(puts(up)[0].sent_json["port_overrides"])[PHANTOM] == ghost
    assert out["_outcome"] == "verified"
    out = await upd(c, r, remove=[PHANTOM])
    assert PHANTOM not in by_port(puts(up)[1].sent_json["port_overrides"])
    assert out["_outcome"] == "verified"
    await c.close()


# ------------------------------------------------------------------ Q2 serialisation


# ------------------------------------------------------------------ Q3 empty tagged list


CUSTOM_EMPTY = {
    "port_idx": 3,
    "op_mode": "switch",
    "tagged_vlan_mgmt": "custom",
    "tagged_networkconf_ids": [],
    "excluded_networkconf_ids": [],
    "native_networkconf_id": uh.ARG_HEX,
}


async def test_q3a_untouched_custom_trunk_with_empty_list_is_sent_byte_exact(monkeypatch):
    up = make([*BASE, CUSTOM_EMPTY])
    c, r = uh.install(monkeypatch, up), server._registry
    await upd(c, r, ports=[{"port_idx": 1, "name": "x"}])
    sent = by_port(puts(up)[0].sent_json["port_overrides"])[3]
    assert sent == CUSTOM_EMPTY and sent["tagged_networkconf_ids"] == []
    raw = puts(up)[0].body_bytes if hasattr(puts(up)[0], "body_bytes") else None
    if raw is not None:
        assert b'"tagged_networkconf_ids":[]' in raw.replace(b" ", b"")
    await c.close()


async def test_q3b_mentioned_port_keeps_its_empty_list_when_other_fields_change(monkeypatch):
    up = make([*BASE, CUSTOM_EMPTY])
    c, r = uh.install(monkeypatch, up), server._registry
    out = await upd(c, r, ports=[{"port_idx": 3, "name": "native-only"}])
    sent = by_port(puts(up)[0].sent_json["port_overrides"])[3]
    assert sent["tagged_networkconf_ids"] == [] and sent["tagged_vlan_mgmt"] == "custom"
    assert out["_outcome"] == "verified"
    await c.close()


async def test_q3c_setting_an_empty_list_through_mcp_schema_reaches_the_wire(monkeypatch):
    up = make()
    uh.install(monkeypatch, up)
    res = await server.mcp.call_tool(
        "update_switch_port_overrides",
        {
            "host": uh.HOST,
            "site": uh.SITE,
            "device": uh.ARG_MAC,
            "ports": [{"port_idx": 4, "tagged_vlan_mgmt": "custom", "tagged_networkconf_ids": []}],
        },
    )
    sent = by_port(puts(up)[0].sent_json["port_overrides"])[4]
    assert sent == {"port_idx": 4, "tagged_vlan_mgmt": "custom", "tagged_networkconf_ids": []}
    assert uh.result_payload(res)["_outcome"] == "verified"


async def test_q3d_controller_dropping_the_empty_list_is_a_mismatch_not_verified(monkeypatch):
    class DropEmpty(uh.FakeUpstream):
        def __call__(self, req):
            resp = super().__call__(req)
            if req.method == "PUT":
                for row in self.overlay["port_overrides"]:
                    if row.get("tagged_networkconf_ids") == []:
                        row.pop("tagged_networkconf_ids")
                        row["tagged_vlan_mgmt"] = "auto"
            return resp

    up = DropEmpty(replay_recordings=False)
    up.overlay.update(
        {"port_table": copy.deepcopy(PORT_TABLE), "port_overrides": copy.deepcopy(BASE)}
    )
    c, r = uh.install(monkeypatch, up), server._registry
    out = await upd(
        c, r, ports=[{"port_idx": 4, "tagged_vlan_mgmt": "custom", "tagged_networkconf_ids": []}]
    )
    assert out["_outcome"] == "mismatch" and out["_verified"] is False
    fields = {m.get("field") for m in out["_mismatches"]}
    assert {"tagged_networkconf_ids", "tagged_vlan_mgmt"} <= fields
    await c.close()


# ------------------------------------------------------------------ checklist probes


@pytest.mark.parametrize(
    "field,value",
    [
        ("native_networkconf_id", "f" * 24),
        ("voice_networkconf_id", "f" * 24),
        ("tagged_networkconf_ids", ["f" * 24]),
        ("excluded_networkconf_ids", ["f" * 24]),
    ],
)
async def test_cl1_unknown_network_id_is_refused_before_the_put(monkeypatch, field, value):
    up = make()
    c, r = uh.install(monkeypatch, up), server._registry
    with pytest.raises(ValueError, match="(?i)unknown .*networkconf"):
        await upd(c, r, ports=[{"port_idx": 4, field: value}])
    assert not puts(up)
    await c.close()


async def test_q3e_raw_wire_bytes_carry_the_empty_list(monkeypatch):
    raw: list[bytes] = []

    class Capture(uh.FakeUpstream):
        def __call__(self, req):
            if req.method == "PUT":
                raw.append(bytes(req.content))
            return super().__call__(req)

    up = Capture(replay_recordings=False)
    up.overlay.update(
        {
            "port_table": copy.deepcopy(PORT_TABLE),
            "port_overrides": copy.deepcopy([*BASE, CUSTOM_EMPTY]),
        }
    )
    c, r = uh.install(monkeypatch, up), server._registry
    await upd(c, r, ports=[{"port_idx": 1, "name": "x"}])
    [body] = raw
    compact = body.replace(b" ", b"")
    assert compact.count(b'"tagged_networkconf_ids":[]') == 1
    assert compact.count(b'"excluded_networkconf_ids":[]') == 1
    await c.close()


class DropEmptyList(uh.FakeUpstream):
    """Controller that drops an empty tagged list on write and widens the port to auto."""

    def __call__(self, req):
        resp = super().__call__(req)
        if req.method == "PUT":
            for row in self.overlay["port_overrides"]:
                if row.get("tagged_networkconf_ids") == []:
                    row.pop("tagged_networkconf_ids")
                    row["tagged_vlan_mgmt"] = "auto"
        return resp


def _drop_up():
    up = DropEmptyList(replay_recordings=False)
    up.overlay.update(
        {
            "port_table": copy.deepcopy(PORT_TABLE),
            "port_overrides": copy.deepcopy([*BASE, CUSTOM_EMPTY]),
        }
    )
    return up


async def test_q3f_preserved_field_lost_on_a_mentioned_port_is_not_verified(monkeypatch):
    up = _drop_up()
    c, r = uh.install(monkeypatch, up), server._registry
    out = await upd(c, r, ports=[{"port_idx": 3, "name": "rename-only"}])  # list NOT requested
    after = by_port(out["readAfter"])[3]
    assert "tagged_networkconf_ids" not in after and after["tagged_vlan_mgmt"] == "auto"
    assert out["_outcome"] != "verified", out["_mismatches"]
    await c.close()


async def test_q3g_same_loss_on_an_unmentioned_port_is_a_mismatch(monkeypatch):
    up = _drop_up()
    c, r = uh.install(monkeypatch, up), server._registry
    out = await upd(c, r, ports=[{"port_idx": 1, "name": "rename-other"}])
    assert out["_outcome"] == "mismatch"
    assert {"port_idx": 3, "problem": "unrelated override changed"} in out["_mismatches"]
    await c.close()
