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
    _get_switch_port_overrides,
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


# ------------------------------------------------------------------ F1-F4 follow-ups


@pytest.mark.parametrize(("port", "count"), [(8, 2), (7, 3), (1, 9)])
async def test_f1_aggregate_reaching_past_the_last_port_is_refused_before_any_write(
    monkeypatch, port, count
):
    up = make()
    c, r = uh.install(monkeypatch, up), server._registry
    change = {"port_idx": port, "op_mode": "aggregate", "aggregate_num_ports": count}
    with pytest.raises(ValueError, match=r"past the last known port 8; use at most"):
        await upd(c, r, ports=[change])
    assert not puts(up)
    await c.close()


@pytest.mark.parametrize(("port", "count"), [(7, 2), (1, 8), (8, 1)])
async def test_f1_aggregate_ending_on_the_last_port_is_sent(monkeypatch, port, count):
    up = make()
    c, r = uh.install(monkeypatch, up), server._registry
    change = {"port_idx": port, "op_mode": "aggregate", "aggregate_num_ports": count}
    await upd(c, r, ports=[change])
    [put] = puts(up)
    assert by_port(put.sent_json["port_overrides"])[port]["aggregate_num_ports"] == count
    await c.close()


async def test_f2_port_monitoring_itself_is_refused_before_any_write(monkeypatch):
    up = make()
    c, r = uh.install(monkeypatch, up), server._registry
    with pytest.raises(ValueError, match=r"Port 3 cannot monitor itself"):
        await upd(c, r, ports=[{"port_idx": 3, "op_mode": SPAN, SPAN_PORT: 3}])
    assert not puts(up)
    await c.close()


async def test_f3_read_flags_an_override_without_a_port_table_row(monkeypatch):
    up = make([*BASE, {"port_idx": PHANTOM, "name": "ghost"}])
    c, r = uh.install(monkeypatch, up), server._registry
    out = await _get_switch_port_overrides(c, r, uh.HOST, uh.SITE, uh.ARG_MAC)
    assert out["_ports"][str(PHANTOM)]["_phantom"] is True
    assert out["_ports"][str(PHANTOM)]["port_table"] is None
    assert "_phantom" not in out["_ports"]["1"]
    assert "_phantom" not in out["_ports"]["3"]
    assert not puts(up)
    await c.close()


async def test_f3_no_port_table_means_nothing_is_flagged(monkeypatch):
    up = make()
    up.overlay["port_table"] = []
    c, r = uh.install(monkeypatch, up), server._registry
    out = await _get_switch_port_overrides(c, r, uh.HOST, uh.SITE, uh.ARG_MAC)
    assert all("_phantom" not in entry for entry in out["_ports"].values())
    await c.close()


async def test_f4_read_exposes_the_native_monitoring_names_without_any_monitoring_port(
    monkeypatch,
):
    up = make()
    c, r = uh.install(monkeypatch, up), server._registry
    out = await _get_switch_port_overrides(c, r, uh.HOST, uh.SITE, uh.ARG_MAC)
    assert out["_spanMode"] == {"op_mode": SPAN, "monitored_port_key": SPAN_PORT}
    await c.close()


# ------------------------------------------------------------------ Merged-row and integer checks


async def test_c1_stale_aggregate_size_on_the_row_is_refused_when_the_mode_switches(monkeypatch):
    """Reported case: the existing row holds aggregate_num_ports 4 on port 7 of an 8-port switch
    and the request only sets op_mode aggregate: the merged row would aggregate ports 7-10."""
    stale = {"port_idx": 7, "op_mode": "switch", "aggregate_num_ports": 4}
    up = make([*BASE, stale])
    c, r = uh.install(monkeypatch, up), server._registry
    with pytest.raises(ValueError, match=r"reaches port 10, past the last known port 8"):
        await upd(c, r, ports=[{"port_idx": 7, "op_mode": "aggregate"}])
    assert not puts(up)
    await c.close()


async def test_c1_stale_monitored_key_naming_its_own_port_is_refused_when_the_mode_switches(
    monkeypatch,
):
    """Reported case: the existing row holds the monitored-port key 3 on port 3 and the request
    only sets the monitoring mode: the merged row would monitor itself."""
    stale = {"port_idx": 3, SPAN_PORT: 3}
    up = make([*BASE, stale])
    c, r = uh.install(monkeypatch, up), server._registry
    with pytest.raises(ValueError, match=r"Port 3 cannot monitor itself"):
        await upd(c, r, ports=[{"port_idx": 3, "op_mode": SPAN}])
    assert not puts(up)
    await c.close()


async def test_c1_stale_fields_do_not_block_an_unrelated_edit_of_the_same_port(monkeypatch):
    """An inert stale size (the row is not an aggregate and the request does not make it one)
    does not stop a rename; the merged row is judged only where the fields take effect."""
    stale = {"port_idx": 7, "op_mode": "switch", "aggregate_num_ports": 4}
    up = make([*BASE, stale])
    c, r = uh.install(monkeypatch, up), server._registry
    await upd(c, r, ports=[{"port_idx": 7, "name": "renamed"}])
    [put] = puts(up)
    assert by_port(put.sent_json["port_overrides"])[7]["name"] == "renamed"
    await c.close()


@pytest.mark.parametrize("count", ["9", 9.0, True, 0, -1, "x"])
async def test_c2_non_integer_or_non_positive_aggregate_size_is_refused(monkeypatch, count):
    up = make()
    c, r = uh.install(monkeypatch, up), server._registry
    change = {"port_idx": 8, "op_mode": "aggregate", "aggregate_num_ports": count}
    with pytest.raises(ValueError, match=r"aggregate_num_ports must be a positive integer"):
        await upd(c, r, ports=[change])
    assert not puts(up)
    await c.close()


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
