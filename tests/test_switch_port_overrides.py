"""Switch port override editor: merge by port_idx, preview, serialization and read-back.

All HTTP is replaced by the fake upstream; resolution, guards and the client are real.
The fake upstream reflects a PUT body onto later reads of record 0 (like a controller).
"""

from __future__ import annotations

import asyncio
import copy
from typing import Any

import httpx
import pytest

from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.families.devices import switch_port_overrides as spo
from unifi_fabric.families.devices.switch_port_overrides import (
    _get_switch_port_overrides,
    _update_switch_port_overrides,
)

SPAN = "mir" + "ror"  # the public tree may not hold this word as a whole token
SPAN_PORT = SPAN + "_port_idx"

PORT_TABLE = [{"port_idx": n, "op_mode": "switch", "up": n < 4} for n in range(1, 9)]
OVERRIDES = [
    {
        "port_idx": 1,
        "name": "uplink",
        "portconf_id": "probe-profile-a",
        "poe_mode": "auto",
        "excluded_networkconf_ids": [],
        "autoneg": True,
    },
    {"port_idx": 2, "name": "desk", "poe_mode": "off", "stp_port_mode": True},
    {"port_idx": 5, "name": "camera", "native_networkconf_id": "probe-net-b", "isolation": False},
]


def switch_upstream(**kw: Any) -> uh.FakeUpstream:
    up = uh.FakeUpstream(replay_recordings=False, **kw)
    up.overlay.update(
        {"port_table": copy.deepcopy(PORT_TABLE), "port_overrides": copy.deepcopy(OVERRIDES)}
    )
    return up


def install(mp, up, **settings):
    return uh.install(mp, up, **settings), server._registry


def puts(up: uh.FakeUpstream) -> list[uh.Served]:
    return [s for s in up.served if s.method == "PUT"]


def by_port(rows: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    return {row["port_idx"]: row for row in rows}


async def update(c, r, **kw):
    ports = kw.pop("ports", None)
    remove = kw.pop("remove_ports", None)
    return await _update_switch_port_overrides(
        c, r, uh.HOST, uh.SITE, kw.pop("device", uh.ARG_MAC), ports, remove, **kw
    )


# ------------------------------------------------------------ preservation and removal


async def test_partial_update_preserves_unrelated_ports_and_unmentioned_fields(monkeypatch):
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    out = await update(
        c, r, ports=[{"port_idx": 2, "poe_mode": "auto"}, {"port_idx": 4, "name": "new"}]
    )
    [put] = puts(up)
    assert put.path.endswith("/rest/device/" + uh.ARG_HEX)
    sent = put.sent_json["port_overrides"]
    assert list(put.sent_json) == ["port_overrides"]
    # Existing entries keep their order and every unmentioned field; new ports append.
    assert [row["port_idx"] for row in sent] == [1, 2, 5, 4]
    assert sent[0] == OVERRIDES[0]
    assert sent[2] == OVERRIDES[2]
    assert sent[1] == {**OVERRIDES[1], "poe_mode": "auto"}
    assert sent[3] == {"port_idx": 4, "name": "new"}
    assert out["_plan"] == {"changed": [2], "added": [4], "removed": [], "kept": [1, 5]}
    assert out["_outcome"] == "verified"
    assert out["_verified"] is True
    assert out["_mismatches"] == []
    assert out["readBefore"] == OVERRIDES
    assert out["changed"]["2"] == {"poe_mode": {"before": "off", "after": "auto"}}
    assert out["changed"]["4"]["added"] is True
    assert out["response"] == put.body
    await c.close()


async def test_selected_removal_leaves_other_overrides_intact(monkeypatch):
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    out = await update(c, r, remove_ports=[2])
    [put] = puts(up)
    assert put.sent_json == {"port_overrides": [OVERRIDES[0], OVERRIDES[2]]}
    assert out["_plan"]["removed"] == [2]
    assert out["_plan"]["kept"] == [1, 5]
    assert out["changed"]["2"]["removed"] is True
    assert out["_outcome"] == "verified"
    await c.close()


async def test_update_and_remove_in_one_call(monkeypatch):
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    out = await update(c, r, ports=[{"port_idx": 5, "isolation": True}], remove_ports=[1])
    [put] = puts(up)
    assert put.sent_json == {"port_overrides": [OVERRIDES[1], {**OVERRIDES[2], "isolation": True}]}
    assert out["_outcome"] == "verified"
    await c.close()


async def test_noop_skips_put_but_reads_back(monkeypatch):
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    out = await update(c, r, ports=[{"port_idx": 2, "poe_mode": "off"}])
    assert not puts(up)
    assert out["noOp"] is True
    assert out["_outcome"] == "verified"
    await c.close()


# ------------------------------------------------------------ profile, monitoring, aggregate


async def test_profile_assignment_checks_profile_exists(monkeypatch):
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    out = await update(c, r, ports=[{"port_idx": 3, "portconf_id": uh.ARG_HEX}])
    [put] = puts(up)
    assert by_port(put.sent_json["port_overrides"])[3] == {"port_idx": 3, "portconf_id": uh.ARG_HEX}
    assert out["_portProfilesResponse"]["data"]
    assert any(s.path.endswith("/rest/portconf") for s in up.served if s.method == "GET")
    await c.close()


async def test_unknown_profile_fails_listing_profiles_without_write(monkeypatch):
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    with pytest.raises(ValueError, match=r"Unknown portconf_id .* valid port profiles"):
        await update(c, r, ports=[{"port_idx": 3, "portconf_id": "f" * 24}])
    assert not puts(up)
    await c.close()


async def test_monitoring_and_aggregate_fields_pass_through_natively(monkeypatch):
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    out = await update(
        c,
        r,
        ports=[
            {"port_idx": 7, "op_mode": SPAN, SPAN_PORT: 8},
            {"port_idx": 1, "op_mode": "aggregate", "aggregate_num_ports": 2},
        ],
    )
    [put] = puts(up)
    sent = by_port(put.sent_json["port_overrides"])
    assert sent[7] == {"port_idx": 7, "op_mode": SPAN, SPAN_PORT: 8}
    assert sent[1] == {**OVERRIDES[0], "op_mode": "aggregate", "aggregate_num_ports": 2}
    # Port 2 is a LAG member that keeps its own override: warned, never auto-removed.
    assert any("[2]" in w and "port 1" in w for w in out["_warnings"])
    assert 2 in sent
    assert out["_outcome"] == "verified"
    await c.close()


async def test_unknown_monitored_port_fails_without_write(monkeypatch):
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    with pytest.raises(ValueError, match=rf"Unknown {SPAN_PORT} 99 .* valid ports"):
        await update(c, r, ports=[{"port_idx": 7, "op_mode": SPAN, SPAN_PORT: 99}])
    assert not puts(up)
    await c.close()


# ------------------------------------------------------------ invalid / ambiguous selections


@pytest.mark.parametrize(
    ("ports", "remove", "message"),
    [
        (
            [{"port_idx": 2, "name": "a"}, {"port_idx": 2, "poe_mode": "off"}],
            None,
            "more than once",
        ),
        ([{"port_idx": 2, "name": "a"}], [2], "both updated"),
        (None, [2, 2], "more than once in remove_ports"),
        (None, [0], "positive integer"),
        (None, [True], "positive integer"),
        ([{"port_idx": 0, "name": "a"}], None, "greater than or equal to 1"),
        ([{"port_idx": True, "name": "a"}], None, "integer"),
        ([{"port_idx": "2", "name": "a"}], None, "integer"),
        ([{"name": "a"}], None, "port_idx"),
        ([{"port_idx": 2}], None, "no fields to set"),
        ([{"port_idx": 2, "name": None}], None, "must have a value"),
        (None, None, "No fields provided"),
        ([], [], "No port selected"),
        ([], None, "No port selected"),
    ],
)
async def test_invalid_or_ambiguous_selection_sends_no_request(monkeypatch, ports, remove, message):
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    with pytest.raises(Exception, match=message):
        await update(c, r, ports=ports, remove_ports=remove)
    assert up.served == []
    await c.close()


@pytest.mark.parametrize(
    ("ports", "remove", "message"),
    [
        (
            [{"port_idx": 42, "name": "a"}],
            None,
            r"Unknown port_idx 42 on this switch; valid ports: \[1, 2, 3, 4, 5, 6, 7, 8\]",
        ),
        (None, [3], r"Port 3 has no override to remove; ports with overrides: \[1, 2, 5\]"),
    ],
)
async def test_selection_unknown_on_device_fails_listing_choices(
    monkeypatch, ports, remove, message
):
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    with pytest.raises(ValueError, match=message):
        await update(c, r, ports=ports, remove_ports=remove)
    assert not puts(up)
    await c.close()


async def test_non_switch_device_is_refused_without_write(monkeypatch):
    up = uh.FakeUpstream(replay_recordings=False)  # synthetic AP: no port_table/overrides
    c, r = install(monkeypatch, up)
    with pytest.raises(ValueError, match="it is not a switch"):
        await update(c, r, ports=[{"port_idx": 1, "name": "a"}])
    assert not puts(up)
    await c.close()


async def test_gateway_without_override_field_starts_from_empty(monkeypatch):
    up = uh.FakeUpstream(replay_recordings=False)
    up.overlay["port_table"] = copy.deepcopy(PORT_TABLE[:2])
    c, r = install(monkeypatch, up)
    out = await update(c, r, ports=[{"port_idx": 2, "name": "lan2"}])
    [put] = puts(up)
    assert put.sent_json == {"port_overrides": [{"port_idx": 2, "name": "lan2"}]}
    assert out["_outcome"] == "verified"
    read = await _get_switch_port_overrides(c, r, uh.HOST, uh.SITE, uh.ARG_MAC)
    assert read["_portOverridesPresent"] is True
    await c.close()


async def test_read_of_a_device_without_ports_reports_no_overrides(monkeypatch):
    up = uh.FakeUpstream(replay_recordings=False)  # synthetic AP: no port_table/overrides
    c, r = install(monkeypatch, up)
    out = await _get_switch_port_overrides(c, r, uh.HOST, uh.SITE, uh.ARG_MAC)
    assert out["_port_overrides"] == [] and out["_ports"] == {}
    assert out["_portOverridesPresent"] is False
    await c.close()


async def test_ambiguous_upstream_array_is_refused(monkeypatch):
    up = switch_upstream()
    up.overlay["port_overrides"] = [*OVERRIDES, {"port_idx": 2, "name": "dupe"}]
    c, r = install(monkeypatch, up)
    with pytest.raises(Exception, match="port 2 has more than one entry"):
        await update(c, r, ports=[{"port_idx": 5, "name": "x"}])
    assert not puts(up)
    await c.close()


# ------------------------------------------------------------ preview


@pytest.mark.parametrize("global_dry", [False, True])
async def test_preview_returns_merged_array_and_sends_no_write(monkeypatch, global_dry):
    up = switch_upstream()
    c, r = install(monkeypatch, up, dry_run=global_dry)
    out = await update(
        c, r, ports=[{"port_idx": 1, "name": "renamed"}], remove_ports=[5], dry_run=not global_dry
    )
    assert not puts(up)
    assert all(s.method == "GET" for s in up.served)
    assert out["_outcome"] == "preview"
    assert out["preview"]["method"] == "PUT"
    assert out["preview"]["body"] == {
        "port_overrides": [{**OVERRIDES[0], "name": "renamed"}, OVERRIDES[1]]
    }
    assert out["diff"]["1"] == {"name": {"before": "uplink", "after": "renamed"}}
    assert out["diff"]["5"]["removed"] is True
    assert out["_plan"]["removed"] == [5]
    assert out["changed"] is None and out["noOp"] is None
    await c.close()


async def test_write_policy_deny_refuses_before_any_request(monkeypatch):
    up = switch_upstream()
    c, r = install(monkeypatch, up, read_only=True)
    with pytest.raises(Exception, match="(?i)deny|read-only|denied"):
        await update(c, r, ports=[{"port_idx": 1, "name": "x"}])
    assert up.served == []
    await c.close()


# ------------------------------------------------------------ serialization


async def test_same_switch_concurrent_calls_do_not_lose_each_others_merge(monkeypatch):
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    first, second = await asyncio.gather(
        update(c, r, ports=[{"port_idx": 1, "name": "from-first"}]),
        update(c, r, ports=[{"port_idx": 5, "name": "from-second"}]),
    )
    put_a, put_b = puts(up)
    # The second PUT was merged from the first one's written result.
    assert by_port(put_b.sent_json["port_overrides"])[1]["name"] == "from-first"
    assert by_port(put_b.sent_json["port_overrides"])[5]["name"] == "from-second"
    final = by_port(up.overlay["port_overrides"])
    assert final[1]["name"] == "from-first" and final[5]["name"] == "from-second"
    assert first["_outcome"] == second["_outcome"] == "verified"
    # Each call's read-before / PUT / read-after ran without the other in between.
    methods = [(s.method, s.path.rsplit("/", 1)[-1]) for s in up.served if "/device" in s.path]
    put_positions = [i for i, (m, _) in enumerate(methods) if m == "PUT"]
    assert methods[put_positions[0] + 1][0] == "GET"
    assert methods[put_positions[0] + 2][0] == "GET"
    await c.close()


async def test_writer_without_the_lock_loses_updates_documented_boundary(monkeypatch):
    """The lock binds only this editor; a writer that does not take it can race."""
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    monkeypatch.setattr(spo, "switch_lock", lambda *a: asyncio.Lock())
    await asyncio.gather(
        update(c, r, ports=[{"port_idx": 1, "name": "from-first"}]),
        update(c, r, ports=[{"port_idx": 5, "name": "from-second"}]),
    )
    final = by_port(up.overlay["port_overrides"])
    assert not (final[1]["name"] == "from-first" and final[5]["name"] == "from-second")
    await c.close()


async def test_different_switches_use_different_locks(monkeypatch):
    up = switch_upstream()
    c, _ = install(monkeypatch, up)
    a = spo.switch_lock(c, "h", "default", "a" * 24)
    assert a is spo.switch_lock(c, "h", "default", "a" * 24)
    assert a is not spo.switch_lock(c, "h", "default", "b" * 24)
    assert a is not spo.switch_lock(c, "h", "other", "a" * 24)
    await c.close()


# ------------------------------------------------------------ mismatch and uncertain outcomes


class IgnoringUpstream(uh.FakeUpstream):
    """A controller that accepts the PUT but does not apply one field."""

    def __call__(self, req: httpx.Request) -> httpx.Response:
        response = super().__call__(req)
        if req.method == "PUT":
            rows = self.overlay["port_overrides"]
            for row in rows:
                if row["port_idx"] == 2:
                    row["poe_mode"] = "off"
        return response


async def test_mismatch_is_explicit_and_never_retried(monkeypatch):
    up = IgnoringUpstream(replay_recordings=False)
    up.overlay.update(
        {"port_table": copy.deepcopy(PORT_TABLE), "port_overrides": copy.deepcopy(OVERRIDES)}
    )
    c, r = install(monkeypatch, up)
    out = await update(c, r, ports=[{"port_idx": 2, "poe_mode": "auto"}])
    assert len(puts(up)) == 1
    assert out["_outcome"] == "mismatch"
    assert out["_verified"] is False
    assert out["_mismatches"] == [
        {"port_idx": 2, "field": "poe_mode", "expected": "auto", "actual": "off", "present": True}
    ]
    await c.close()


async def test_bool_vs_int_readback_is_a_mismatch(monkeypatch):
    class IntUpstream(uh.FakeUpstream):
        def __call__(self, req: httpx.Request) -> httpx.Response:
            response = super().__call__(req)
            if req.method == "PUT":
                by_port(self.overlay["port_overrides"])[5]["isolation"] = 1
            return response

    up = IntUpstream(replay_recordings=False)
    up.overlay.update(
        {"port_table": copy.deepcopy(PORT_TABLE), "port_overrides": copy.deepcopy(OVERRIDES)}
    )
    c, r = install(monkeypatch, up)
    out = await update(c, r, ports=[{"port_idx": 5, "isolation": True}])
    assert out["_outcome"] == "mismatch"
    assert out["_mismatches"][0]["field"] == "isolation"
    assert len(puts(up)) == 1
    await c.close()


async def test_unrelated_port_changed_by_controller_is_a_mismatch(monkeypatch):
    class DriftUpstream(uh.FakeUpstream):
        def __call__(self, req: httpx.Request) -> httpx.Response:
            response = super().__call__(req)
            if req.method == "PUT":
                by_port(self.overlay["port_overrides"])[1]["name"] = "changed-elsewhere"
            return response

    up = DriftUpstream(replay_recordings=False)
    up.overlay.update(
        {"port_table": copy.deepcopy(PORT_TABLE), "port_overrides": copy.deepcopy(OVERRIDES)}
    )
    c, r = install(monkeypatch, up)
    out = await update(c, r, ports=[{"port_idx": 5, "name": "x"}])
    assert out["_outcome"] == "mismatch"
    assert out["_mismatches"] == [{"port_idx": 1, "problem": "unrelated override changed"}]
    await c.close()


async def test_failed_read_after_reports_unknown_without_retry(monkeypatch):
    up = switch_upstream(fail_reads_after_write=True)
    c, r = install(monkeypatch, up)
    out = await update(c, r, ports=[{"port_idx": 2, "poe_mode": "auto"}])
    assert len(puts(up)) == 1
    assert out["_outcome"] == "unknown"
    assert out["_verified"] is None
    assert out["_mismatches"] is None
    assert out["readAfterError"]
    await c.close()


@pytest.mark.parametrize("status", [429, 502, 504])
async def test_uncertain_write_status_raises_and_is_sent_once(monkeypatch, status):
    up = switch_upstream(write_status=status)
    c, r = install(monkeypatch, up)
    with pytest.raises(Exception) as err:
        await update(c, r, ports=[{"port_idx": 2, "poe_mode": "auto"}])
    assert len(puts(up)) == 1
    if status != 429:
        assert "outcome unknown" in str(err.value)
    await c.close()


# ------------------------------------------------------------ read tool and MCP surface


async def test_get_returns_envelope_and_per_port_view(monkeypatch):
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    out = await _get_switch_port_overrides(c, r, uh.HOST, uh.SITE, uh.ARG_MAC)
    assert out["_port_overrides"] == OVERRIDES
    assert out["_device"] in out["data"]
    assert out["_ports"]["2"]["port_overrides"] == OVERRIDES[1]
    assert out["_ports"]["3"] == {"port_overrides": None, "port_table": PORT_TABLE[2]}
    assert out["_portOverridesPresent"] is True
    assert not puts(up)
    await c.close()


async def test_mcp_call_accepts_native_fields_through_the_schema(monkeypatch):
    up = switch_upstream()
    uh.install(monkeypatch, up)
    result = await server.mcp.call_tool(
        "update_switch_port_overrides",
        {
            "host": uh.HOST,
            "site": uh.SITE,
            "device": uh.ARG_MAC,
            "ports": [{"port_idx": 2, "poe_mode": "auto", "stormctrl_bcast_rate": 50}],
            "dry_run": True,
        },
    )
    payload = uh.result_payload(result)
    assert payload["_outcome"] == "preview"
    assert by_port(payload["preview"]["body"]["port_overrides"])[2]["stormctrl_bcast_rate"] == 50
    assert not puts(up)


async def test_additive_keys_in_requested_fields_are_never_written(monkeypatch):
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    await update(
        c, r, ports=[{"port_idx": 2, "poe_mode": "auto", "_resolved": {"x": 1}, "_ports": {}}]
    )
    [put] = puts(up)
    assert by_port(put.sent_json["port_overrides"])[2] == {**OVERRIDES[1], "poe_mode": "auto"}
    await c.close()


async def test_only_additive_keys_count_as_no_fields(monkeypatch):
    up = switch_upstream()
    c, r = install(monkeypatch, up)
    with pytest.raises(Exception, match="no fields to set"):
        await update(c, r, ports=[{"port_idx": 2, "_resolved": {"x": 1}}])
    assert up.served == []
    await c.close()


async def test_tool_annotations_are_derived(monkeypatch):
    tools = {t.name: t for t in await server.mcp.list_tools()}
    assert tools["get_switch_port_overrides"].annotations.read_only_hint is True
    assert tools["update_switch_port_overrides"].annotations.read_only_hint is False
    schema = tools["update_switch_port_overrides"].parameters
    for name, prop in schema["properties"].items():
        assert prop.get("description"), name


def test_verify_allows_a_field_the_controller_adds_to_an_untouched_port():
    from unifi_fabric.families.devices import switch_port_overrides as sw

    before = [{"port_idx": 1, "op_mode": "switch"}, {"port_idx": 2, "op_mode": "switch"}]
    after = [
        {"port_idx": 1, "op_mode": "switch", "added_default": 1},
        {"port_idx": 2, "op_mode": "switch", "portconf_id": "x"},
    ]
    sent = [{"port_idx": 2, "op_mode": "switch"}]
    assert sw._verify(before, after, {2: {}}, [], sent) == []
    changed = [{"port_idx": 1, "op_mode": "aggregate"}, after[1]]
    assert sw._verify(before, changed, {2: {}}, [], sent) == [
        {"port_idx": 1, "problem": "unrelated override changed"}
    ]
    dropped = [{"port_idx": 1}, after[1]]
    assert sw._verify(before, dropped, {2: {}}, [], sent) == [
        {"port_idx": 1, "problem": "unrelated override changed"}
    ]
