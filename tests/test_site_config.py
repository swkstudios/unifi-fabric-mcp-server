"""Site configuration CRUD (user groups, static routes, legacy firewall rules,
RADIUS accounts and profiles, AP groups, port profiles, Dynamic DNS) and
set_client_user_group.

Shapes follow the live probe on Network 11.0.81 (L16-NET-A): Classic ``{meta, data}``
envelopes with UUID ``_id`` values; v2 apgroups as bare arrays/objects with ``external_id``;
a legacy firewall rule POST on a zone-based console answers rc ok with no ``_id``.
RADIUS accounts follow the NET-A-FIX5 live probe: v2 ``radius/users`` lists a bare array,
``batch_add`` / ``batch_update`` answer a bare one-element array of the record,
``batch_update`` refuses a partial record (HTTP 400) and ``batch_delete`` answers no body.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

from unifi_fabric import families, server
from unifi_fabric.client import DRY_RUN_MESSAGE, UniFiConnectionError
from unifi_fabric.tools import site_config as sc

HOST_ID = "host-001"
CLASSIC = f"/v1/connector/consoles/{HOST_ID}/proxy/network/api/s/default"
V2 = f"/v1/connector/consoles/{HOST_ID}/proxy/network/v2/api/site/default"
GID = "9c9843ba-8a21-4366-9e66-6a26e33825d8"
DEFAULT_GID = "6e542420-8d68-44e5-bfad-cba42dcfc41e"
UID = "7d355e8c-e407-402f-9dd5-c9fb8190d173"


def env(*rows: dict[str, Any]) -> dict[str, Any]:
    return {"meta": {"rc": "ok"}, "data": list(rows)}


USER_GROUPS = env(
    {"_id": DEFAULT_GID, "name": "Default", "qos_rate_max_down": -1, "qos_rate_max_up": -1},
    {"_id": GID, "name": "zz-mcp-test-ug", "qos_rate_max_down": -1, "qos_rate_max_up": -1},
)
KNOWN_CLIENTS = env({"_id": UID, "mac": "02:00:5e:10:00:01", "name": "zz-mcp-test-client"})
R_PROFILES = env(
    {
        "_id": "6823cdc1-2d5b-41fe-8971-24359b1a55ef",
        "external_id": "8690e791-4d52-4809-8477-77ef9dc0ab8c",
        "name": "zz-mcp-test-rp",
        "group_members": ["198.51.100.10"],
    }
)
RADIUS_USERS = [
    {
        "_id": "68f1d2c3b4a5968778695a4b",
        "name": "mcp-test-alice",
        "x_password": "synthetic-stored-value",
        "group_policy": "default",
        "filter_ids": [],
        "vlan": 20,
        "tunnel_type": 13,
        "tunnel_medium_type": 6,
    }
]
AP_GROUPS = [
    {
        "_id": "c7098490-f73b-4fe5-846f-b88feab610ad",
        "external_id": "c450568f-b07e-4acc-8c47-900d46e38706",
        "name": "zz-mcp-test-apg",
        "device_macs": ["02:00:5e:00:00:01"],
        "for_wlanconf": False,
        "attr_no_delete": False,
    }
]


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    c.post = AsyncMock()
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


def _preview(method: str, path: str, body: Any) -> dict[str, Any]:
    return {
        "dryRun": True,
        "message": DRY_RUN_MESSAGE,
        "preview": {"method": method, "path": path, "params": None, "body": body},
    }


# --------------------------------------------------------------------------- create


async def test_create_posts_body_verbatim_to_the_collection(client, registry):
    created = env({"_id": GID, "name": "zz", "qos_rate_max_down": 10000})
    client.post.return_value = created
    body = {"name": "zz", "qos_rate_max_down": 10000, "_warnings": ["from a read"]}
    out = await sc._create_config_record(
        client, registry, "h", "Default", sc.USER_GROUPS, body, None
    )
    client.post.assert_awaited_once()
    assert client.post.await_args.args[0] == f"{CLASSIC}/rest/usergroup"
    # additive _ keys a read adds are never sent
    assert client.post.await_args.kwargs["json"] == {"name": "zz", "qos_rate_max_down": 10000}
    assert out == created


async def test_create_without_id_is_flagged_not_stored(client, registry):
    """rest/firewallrule on a zone-based console: rc ok, the rule echoed, no _id, nothing kept."""
    echoed = env({"name": "r", "ruleset": "LAN_IN", "rule_index": 20000, "action": "drop"})
    client.post.return_value = echoed
    body = {"name": "r", "ruleset": "LAN_IN", "rule_index": 20000, "action": "drop"}
    out = await sc._create_config_record(
        client,
        registry,
        "h",
        "Default",
        sc._Collection("/firewallrule", "Firewall rule", "list_firewall_rules"),
        body,
        None,
    )
    assert {k: v for k, v in out.items() if k != "_warnings"} == echoed
    assert [w["code"] for w in out["_warnings"]] == ["NO_ID_RETURNED"]
    assert "list_firewall_rules" in out["_warnings"][0]["message"]


@pytest.mark.parametrize(
    ("sent", "stored", "fields"),
    [
        ({"forward": "disabled"}, {"forward": "all"}, ["forward"]),
        ({"enabled": True}, {"enabled": 1}, ["enabled"]),  # type-strict: True is not 1
        ({"tagged": ["a"]}, {}, ["tagged"]),  # dropped
        ({"forward": "native"}, {"forward": "native"}, []),
    ],
)
async def test_create_reports_fields_not_stored_as_sent(client, registry, sent, stored, fields):
    client.post.return_value = env({"_id": "p1", "name": "zz", **stored})
    out = await sc._create_config_record(
        client, registry, "h", "Default", sc.RADIUS_PROFILES, {"name": "zz", **sent}, None
    )
    got = [w for w in out.get("_warnings", []) if w["code"] == "NOT_STORED_AS_SENT"]
    assert (got[0]["fields"] if got else []) == fields


async def test_secret_fields_are_never_compared_or_echoed(client, registry):
    client.post.return_value = [{"_id": "a1", "name": "alice", "x_password": "<masked>"}]
    out = await sc._create_batch_record(
        client,
        registry,
        "h",
        "Default",
        sc.RADIUS_ACCOUNTS,
        {"name": "alice", "x_password": "s3cret-value"},
        None,
    )
    assert out == [{"_id": "a1", "name": "alice", "x_password": "<masked>"}]
    client.post.return_value = [{"_id": "a1", "name": "bob"}]
    out = await sc._create_batch_record(
        client,
        registry,
        "h",
        "Default",
        sc.RADIUS_ACCOUNTS,
        {"name": "alice", "x_password": "s3cret-value"},
        None,
    )
    assert out[0]["_warnings"][0]["fields"] == ["name"]
    assert "s3cret-value" not in repr(out[0]["_warnings"])


async def test_create_dry_run_preview_is_returned_bare(client, registry):
    preview = _preview("POST", f"{CLASSIC}/rest/routing", {"name": "zz"})
    client.post.return_value = preview
    out = await sc._create_config_record(
        client, registry, "h", "Default", sc.STATIC_ROUTES, {"name": "zz"}, None
    )
    assert out == preview


async def test_create_ap_group_posts_to_v2_and_checks_the_bare_object(client, registry):
    client.post.return_value = {**AP_GROUPS[0], "name": "other"}
    out = await sc._create_config_record(
        client,
        registry,
        "h",
        "Default",
        sc.AP_GROUPS,
        {"name": "zz-mcp-test-apg", "device_macs": []},
        None,
    )
    assert client.post.await_args.args[0] == f"{V2}/apgroups"
    assert [w["fields"] for w in out["_warnings"]] == [["device_macs", "name"]]


# --------------------------------------------------------------------------- update


async def test_update_resolves_in_the_list_and_addresses_the_upstream_id(client, registry):
    client.get.return_value = R_PROFILES
    client.put.return_value = env({**R_PROFILES["data"][0], "group_members": ["198.51.100.11"]})
    ext = R_PROFILES["data"][0]["external_id"]
    out = await sc._update_config_record(
        client,
        registry,
        "h",
        "Default",
        sc.RADIUS_PROFILES,
        ext.upper(),
        "group_id",
        {"group_members": ["198.51.100.11"], "_resolved_networks": {}},
    )
    native = R_PROFILES["data"][0]["_id"]
    assert client.get.await_args.args[0] == f"{CLASSIC}/rest/radiusprofile"
    assert client.put.await_args.args[0] == f"{CLASSIC}/rest/radiusprofile/{native}"
    # only the fields given (the Classic PUT merges), additive keys dropped
    assert client.put.await_args.kwargs["json"] == {"group_members": ["198.51.100.11"]}
    assert "_warnings" not in out


async def test_update_body_id_in_another_spelling_is_respelt(client, registry):
    client.get.return_value = R_PROFILES
    client.put.return_value = env(R_PROFILES["data"][0])
    row = R_PROFILES["data"][0]
    await sc._update_config_record(
        client,
        registry,
        "h",
        "Default",
        sc.RADIUS_PROFILES,
        row["_id"],
        "group_id",
        {"_id": row["external_id"], "name": "zz-mcp-test-rp"},
    )
    assert client.put.await_args.kwargs["json"]["_id"] == row["_id"]


async def test_update_body_id_of_another_record_is_refused(client, registry):
    client.get.return_value = R_PROFILES
    row = R_PROFILES["data"][0]
    with pytest.raises(ValueError, match="does not match.*resolved"):
        await sc._update_config_record(
            client,
            registry,
            "h",
            "Default",
            sc.RADIUS_PROFILES,
            row["_id"],
            "group_id",
            {"_id": "other-id", "name": "zz"},
        )
    client.put.assert_not_awaited()


async def test_update_unknown_id_lists_every_record_and_sends_nothing(client, registry):
    client.get.return_value = USER_GROUPS
    with pytest.raises(ValueError, match="not found; valid: ") as err:
        await sc._update_config_record(
            client, registry, "h", "Default", sc.USER_GROUPS, "0" * 24, "group_id", {"name": "x"}
        )
    assert "'Default'" in str(err.value) and GID in str(err.value)
    assert "No write was sent." in str(err.value)
    client.put.assert_not_awaited()


async def test_update_ap_group_lays_fields_over_the_stored_group(client, registry):
    """The v2 PUT replaces the whole group: a rename must keep the members."""
    client.get.return_value = AP_GROUPS
    client.put.return_value = {**AP_GROUPS[0], "name": "Floor 2"}
    gid = AP_GROUPS[0]["_id"]
    out = await sc._update_config_record(
        client,
        registry,
        "h",
        "Default",
        sc.AP_GROUPS,
        gid,
        "group_id",
        {"name": "Floor 2"},
        merge=True,
    )
    assert client.put.await_args.args[0] == f"{V2}/apgroups/{gid}"
    assert client.put.await_args.kwargs["json"] == {**AP_GROUPS[0], "name": "Floor 2"}
    assert "_warnings" not in out


async def test_update_unexpected_list_shape_raises_with_the_shape(client, registry):
    client.get.return_value = {"meta": {"rc": "ok"}}
    with pytest.raises(UniFiConnectionError, match="Unexpected response shape"):
        await sc._update_config_record(
            client, registry, "h", "Default", sc.STATIC_ROUTES, "r1", "route_id", {"name": "x"}
        )
    client.put.assert_not_awaited()


# --------------------------------------------------------------------------- delete


async def test_delete_unknown_id_is_never_reported_deleted(client, registry):
    """The controller answers DELETE of an unknown id with 200; the list check comes first."""
    client.get.return_value = env()
    with pytest.raises(ValueError, match=r"not found; valid: \(none\)"):
        await sc._delete_config_record(
            client,
            registry,
            "h",
            "Default",
            sc._Collection("/firewallrule", "Firewall rule", "list_firewall_rules"),
            "r1",
            "rule_id",
        )
    client.delete.assert_not_awaited()


async def test_delete_returns_deletion_result_and_dry_run_shape(client, registry):
    client.get.return_value = AP_GROUPS
    client.delete.return_value = None  # HTTP 204
    gid = AP_GROUPS[0]["external_id"]
    out = await sc._delete_config_record(
        client, registry, "h", "Default", sc.AP_GROUPS, gid, "group_id"
    )
    assert client.delete.await_args.args[0] == f"{V2}/apgroups/{AP_GROUPS[0]['_id']}"
    assert out == {"deleted": True, "message": f"AP group {gid} deleted.", "response": None}
    client.delete.return_value = _preview("DELETE", "x", None)
    out = await sc._delete_config_record(
        client, registry, "h", "Default", sc.AP_GROUPS, gid, "group_id"
    )
    assert out["status"] == "dry_run" and out["deleted"] is False


# --------------------------------------------------------------------------- reads


async def test_get_ap_group_reads_the_collection_by_either_id(client, registry):
    client.get.return_value = AP_GROUPS
    for wanted in (AP_GROUPS[0]["_id"], AP_GROUPS[0]["external_id"]):
        assert await sc._get_ap_group(client, registry, "h", "Default", wanted) == AP_GROUPS[0]
    assert client.get.await_args.args[0] == f"{V2}/apgroups"
    with pytest.raises(ValueError, match="AP group 'nope' not found; valid: 'zz-mcp-test-apg'"):
        await sc._get_ap_group(client, registry, "h", "Default", "nope")


async def test_get_static_route_is_a_classic_by_id_get(client, registry):
    client.get.return_value = env()
    assert (
        await sc._get_config_record(
            client, registry, "h", "Default", sc.STATIC_ROUTES, "r1", "route_id"
        )
        == env()
    )
    assert client.get.await_args.args[0] == f"{CLASSIC}/rest/routing/r1"
    with pytest.raises(ValueError, match="'route_id'"):
        await sc._get_config_record(
            client, registry, "h", "Default", sc.STATIC_ROUTES, "../x", "route_id"
        )


# --------------------------------------------------------------------------- set_client_user_group


def _gets(client, *bodies):
    client.get.side_effect = list(bodies)


async def test_set_client_user_group_by_mac_and_group_name(client, registry):
    _gets(client, USER_GROUPS, KNOWN_CLIENTS)
    client.post.return_value = env({**KNOWN_CLIENTS["data"][0], "usergroup_id": GID})
    out = await sc._set_client_user_group(
        client, registry, "h", "Default", "02-00-5E-10-00-01", "zz-mcp-test-ug"
    )
    assert client.post.await_args.args[0] == f"{CLASSIC}/upd/user/{UID}"
    assert client.post.await_args.kwargs["json"] == {"usergroup_id": GID}
    assert out["data"][0]["usergroup_id"] == GID


async def test_set_client_user_group_by_ids(client, registry):
    _gets(client, USER_GROUPS, KNOWN_CLIENTS)
    client.post.return_value = env()
    await sc._set_client_user_group(client, registry, "h", "Default", UID, DEFAULT_GID)
    assert client.post.await_args.kwargs["json"] == {"usergroup_id": DEFAULT_GID}


async def test_set_client_user_group_unknown_client_sends_nothing(client, registry):
    _gets(client, USER_GROUPS, KNOWN_CLIENTS)
    with pytest.raises(ValueError, match="Known client 'nope' not found") as err:
        await sc._set_client_user_group(client, registry, "h", "Default", "nope", "Default")
    assert "02:00:5e:10:00:01" in str(err.value) and "No write was sent." in str(err.value)
    client.post.assert_not_awaited()


async def test_set_client_user_group_ambiguous_group_name_fails(client, registry):
    twin = env(*USER_GROUPS["data"], {"_id": "g3", "name": "zz-mcp-test-ug"})
    _gets(client, twin, KNOWN_CLIENTS)
    with pytest.raises(ValueError, match="matches 2 records; pass the _id"):
        await sc._set_client_user_group(client, registry, "h", "Default", UID, "zz-mcp-test-ug")
    client.post.assert_not_awaited()


@pytest.mark.parametrize("bad", ["", " x", "x\n"])
async def test_set_client_user_group_selectors_are_checked_first(client, registry, bad):
    with pytest.raises(ValueError):
        await sc._set_client_user_group(client, registry, "h", "Default", bad, "Default")
    client.get.assert_not_awaited()


# --------------------------------------------------------------------------- port profile


async def test_create_port_profile_adds_resolution_and_warnings(client, registry):
    native = "0a8bb8db-3f65-4670-82c0-344068ed3ee6"
    client.post.return_value = env(
        {"_id": "pp1", "name": "zz", "forward": "all", "native_networkconf_id": native}
    )
    client.get.return_value = env({"_id": native, "name": "Default"})
    out = await sc._create_port_profile(
        client,
        registry,
        "h",
        "Default",
        {"name": "zz", "forward": "native", "_resolved_networks": {"x": 1}},
    )
    assert client.post.await_args.args[0] == f"{CLASSIC}/rest/portconf"
    assert client.post.await_args.kwargs["json"] == {"name": "zz", "forward": "native"}
    assert out["_warnings"][0]["fields"] == ["forward"]
    resolved = out["data"][0]["_resolved_networks"]["native_networkconf_id"]
    assert resolved == {"id": native, "name": "Default", "vlan": None}


async def test_create_port_profile_maps_integration_ids_to_classic_ids(client, registry):
    lan = {"_id": "65f1c0ffee00000000000001", "external_id": "3fa85f64-5717-4562-b3fc-2c963f660001"}
    iot = {"_id": "65f1c0ffee00000000000003", "external_id": "3fa85f64-5717-4562-b3fc-2c963f660003"}
    client.get.return_value = env({**lan, "name": "LAN"}, {**iot, "name": "IoT"})
    client.post.return_value = env({"_id": "pp1", "name": "zz"})
    await sc._create_port_profile(
        client,
        registry,
        "h",
        "Default",
        {
            "name": "zz",
            "forward": "customize",
            "native_networkconf_id": lan["external_id"],
            "excluded_networkconf_ids": [iot["external_id"], lan["_id"]],
            # A non-string payload value is sent unchanged (create has no stored profile).
            "voice_networkconf_id": 5,
        },
    )
    sent = client.post.await_args.kwargs["json"]
    assert sent["native_networkconf_id"] == lan["_id"]
    assert sent["excluded_networkconf_ids"] == [iot["_id"], lan["_id"]]
    assert sent["voice_networkconf_id"] == 5


async def test_create_port_profile_unknown_network_id_never_posts(client, registry):
    client.get.return_value = env({"_id": "65f1c0ffee00000000000001", "name": "LAN"})
    with pytest.raises(ValueError, match="native_networkconf_id value .*valid: LAN"):
        await sc._create_port_profile(
            client,
            registry,
            "h",
            "Default",
            {"name": "zz", "native_networkconf_id": "3fa85f64-5717-4562-b3fc-2c963f66ffff"},
        )
    client.post.assert_not_awaited()


# --------------------------------------------------------------------------- registration


def test_tools_are_registered_in_their_families():
    names = {t.name for t in asyncio.run(server.mcp.list_tools())}
    new = {
        "list_user_groups", "get_user_group", "create_user_group", "update_user_group",
        "delete_user_group", "set_client_user_group", "get_static_route", "create_static_route",
        "update_static_route", "delete_static_route", "create_radius_account",
        "update_radius_account", "delete_radius_account", "update_radius_profile",
        "delete_radius_profile", "list_ap_groups", "get_ap_group", "create_ap_group",
        "update_ap_group", "delete_ap_group", "create_port_profile", "delete_port_profile",
        "create_dynamic_dns", "delete_dynamic_dns",
    }  # fmt: skip
    assert new <= names
    assert "create_firewall_rule" in names
    assert not {"update_firewall_rule", "delete_firewall_rule"} & names
    # firewall-group writes are the official traffic-matching-list tools (NET-A-FIX5)
    assert not {"create_firewall_group", "update_firewall_group", "delete_firewall_group"} & names
    assert {
        "create_traffic_matching_list",
        "update_traffic_matching_list",
        "delete_traffic_matching_list",
    } <= names
    assert {"list_firewall_rules", "get_firewall_rule"} <= names
    index = families.build_family_index()
    assert {index[n] for n in new - {"update_radius_profile", "delete_radius_profile"}} == {
        "network"
    }
    assert index["update_radius_profile"] == index["create_radius_profile"] == "vpn"


@pytest.mark.parametrize("merge", [False, True])
@pytest.mark.parametrize("members", [[""], ["198.51.100.20", ""], []])
async def test_update_preserves_explicit_list_values(client, registry, merge, members):
    client.get.return_value = env(
        {"_id": "g1", "group_members": ["old", ""], "read_derived": ["kept", ""]}
    )
    client.put.return_value = env({"_id": "g1", "group_members": members})
    await sc._update_config_record(
        client,
        registry,
        "h",
        "Default",
        sc.RADIUS_PROFILES,
        "g1",
        "group_id",
        {"group_members": members},
        merge=merge,
    )
    sent = client.put.await_args.kwargs["json"]
    assert sent["group_members"] == members
    if merge:
        assert sent["read_derived"] == ["kept"]


@pytest.mark.parametrize("field", ["auth_servers", "acct_servers"])
@pytest.mark.parametrize("secret_readback", [{"x_secret": "<masked>"}, {}])
@pytest.mark.parametrize("stored_port", [1812, True, 1812.0, "1812", None])
async def test_radius_nested_secrets_are_unreadable_but_other_leaves_are_type_strict(
    client,
    registry,
    field,
    secret_readback,
    stored_port,
):
    sent_server = {
        "ip": "192.0.2.1",
        "port": 1812,
        "x_secret": "synthetic-test-value",
        "nested": {"enabled": True, "x_secret": "synthetic-test-value"},
    }
    stored_server = {
        "ip": "192.0.2.1",
        **secret_readback,
        "nested": {"enabled": True, **secret_readback},
    }
    if stored_port is not None:
        stored_server["port"] = stored_port
    client.put.return_value = env({"_id": "r1", field: [stored_server]})
    client.get.return_value = env({"_id": "r1"})
    out = await sc._update_config_record(
        client,
        registry,
        "h",
        "Default",
        sc.RADIUS_PROFILES,
        "r1",
        "profile_id",
        {field: [sent_server]},
    )
    warnings = [w for w in out.get("_warnings", []) if w["code"] == "NOT_STORED_AS_SENT"]
    # JSON numbers compare by value (1812 == 1812.0); bool, string and absence differ.
    same_number = type(stored_port) in (int, float) and stored_port == 1812
    assert bool(warnings) == (not same_number)
    if warnings:
        assert warnings[0]["fields"] == [field]
        assert "synthetic-test-value" not in repr(warnings)


@pytest.mark.parametrize(
    "coll",
    [
        sc.USER_GROUPS,
        sc.STATIC_ROUTES,
        sc.RADIUS_PROFILES,
        sc.PORT_PROFILES,
        sc.DYNAMIC_DNS,
        sc.AP_GROUPS,
    ],
)
@pytest.mark.parametrize("response", [None, {"meta": {"rc": "ok"}, "data": [], "extra": 7}])
async def test_all_site_config_deletes_use_catalog_result_convention(
    client, registry, coll, response
):
    from unifi_fabric.tools._results import deletion_result

    record = {"_id": "record-1", "name": "Synthetic"}
    client.get.return_value = [record] if coll.v2 else env(record)
    client.delete.return_value = response
    out = await sc._delete_config_record(
        client,
        registry,
        "h",
        "Default",
        coll,
        "record-1",
        "record_id",
    )
    assert out == deletion_result(f"{coll.kind} record-1 deleted.", response)
    assert out["response"] is response


@pytest.mark.parametrize(
    ("sent", "stored"),
    [
        ({"enabled": True}, {"enabled": 1}),
        ({"enabled": 1}, {"enabled": True}),
        ({"enabled": False}, {"enabled": 0}),
        ({"port": 1812}, {"port": 1812.5}),
        ({"port": 1812}, {"port": "1812"}),
        ({"port": 1812}, {}),
        ({}, {"port": 1812}),
        ([{"port": 1812}], []),
        ([{"port": 1812}, {"port": 1813}], [{"port": 1813}, {"port": 1812}]),
    ],
)
def test_readable_comparison_preserves_every_nonsecret_difference(sent, stored):
    assert not sc._readable_config_equal(sent, stored)


@pytest.mark.parametrize(
    ("sent", "stored"),
    [
        ({"port": 1812}, {"port": 1812.0}),
        ({"port": 1812.0}, {"port": 1812}),
        ([{"port": 1812, "x_secret": "synthetic"}], [{"port": 1812.0}]),
        ({"enabled": True}, {"enabled": True}),
    ],
)
def test_readable_comparison_treats_json_numbers_by_value(sent, stored):
    """1812 and 1812.0 are one JSON number: no NOT_STORED_AS_SENT false positive."""
    assert sc._readable_config_equal(sent, stored)


# ------------------------------------------------------------------- RADIUS accounts (v2 batch)


async def test_create_radius_account_posts_a_one_element_batch_add(client, registry):
    created = [{**RADIUS_USERS[0], "_id": "68f1d2c3b4a5968778695a4c"}]
    client.post.return_value = created
    body = {"vlan": 20, "tunnel_type": 13, "tunnel_medium_type": 6, "name": "mcp-test-alice"}
    out = await sc._create_batch_record(
        client,
        registry,
        "h",
        "Default",
        sc.RADIUS_ACCOUNTS,
        {**body, "x_password": "synthetic-stored-value", "_warnings": ["from a read"]},
        None,
    )
    assert client.post.await_args.args[0] == f"{V2}/radius/users/batch_add"
    # a JSON array with exactly the account, additive _ keys dropped
    assert client.post.await_args.kwargs["json"] == [
        {**body, "x_password": "synthetic-stored-value"}
    ]
    assert out == created  # the bare array verbatim, no warnings
    client.get.assert_not_awaited()


async def test_batch_write_warnings_go_on_the_answered_record(client, registry):
    client.post.return_value = [{"_id": "", "name": "other"}]
    out = await sc._create_batch_record(
        client, registry, "h", "Default", sc.RADIUS_ACCOUNTS, {"name": "mcp-test-alice"}, None
    )
    assert isinstance(out, list) and len(out) == 1
    assert out[0]["name"] == "other"
    assert [w["code"] for w in out[0]["_warnings"]] == ["NO_ID_RETURNED"]
    client.post.return_value = [{"_id": "a1", "name": "other"}]
    out = await sc._create_batch_record(
        client, registry, "h", "Default", sc.RADIUS_ACCOUNTS, {"name": "mcp-test-alice"}, None
    )
    assert out[0]["_warnings"][0]["code"] == "NOT_STORED_AS_SENT"
    assert out[0]["_warnings"][0]["fields"] == ["name"]


@pytest.mark.parametrize(
    "answer", [[], [{"_id": "a"}, {"_id": "b"}], {"meta": {"rc": "ok"}}, None, "text"]
)
async def test_batch_write_other_answers_are_returned_verbatim(client, registry, answer):
    client.post.return_value = answer
    out = await sc._create_batch_record(
        client, registry, "h", "Default", sc.RADIUS_ACCOUNTS, {"name": "zz"}, None
    )
    assert out == answer


async def test_update_radius_account_sends_the_stored_record_with_the_change(client, registry):
    client.get.return_value = RADIUS_USERS
    client.post.return_value = [{**RADIUS_USERS[0], "vlan": 30}]
    uid = RADIUS_USERS[0]["_id"]
    out = await sc._update_batch_record(
        client,
        registry,
        "h",
        "Default",
        sc.RADIUS_ACCOUNTS,
        uid.upper(),
        "account_id",
        {"vlan": 30, "_warnings": []},
    )
    assert client.get.await_args.args[0] == f"{V2}/radius/users"
    assert client.post.await_args.args[0] == f"{V2}/radius/users/batch_update"
    # the route refuses a partial record: every stored field is sent, the change laid over
    assert client.post.await_args.kwargs["json"] == [{**RADIUS_USERS[0], "vlan": 30}]
    assert out == [{**RADIUS_USERS[0], "vlan": 30}]
    client.put.assert_not_awaited()


async def test_update_radius_account_password_change_is_never_compared(client, registry):
    client.get.return_value = RADIUS_USERS
    client.post.return_value = [{**RADIUS_USERS[0], "x_password": "<masked>"}]
    out = await sc._update_batch_record(
        client,
        registry,
        "h",
        "Default",
        sc.RADIUS_ACCOUNTS,
        RADIUS_USERS[0]["_id"],
        "account_id",
        {"x_password": "synthetic-new-value"},
    )
    assert client.post.await_args.kwargs["json"][0]["x_password"] == "synthetic-new-value"
    assert "_warnings" not in out[0]


async def test_update_radius_account_reports_a_field_not_stored(client, registry):
    client.get.return_value = RADIUS_USERS
    client.post.return_value = [{**RADIUS_USERS[0], "vlan": 20}]
    out = await sc._update_batch_record(
        client,
        registry,
        "h",
        "Default",
        sc.RADIUS_ACCOUNTS,
        RADIUS_USERS[0]["_id"],
        "account_id",
        {"vlan": 30},
    )
    assert out[0]["_warnings"][0]["code"] == "NOT_STORED_AS_SENT"
    assert out[0]["_warnings"][0]["fields"] == ["vlan"]
    assert "synthetic-stored-value" not in repr(out[0]["_warnings"])


@pytest.mark.parametrize("write", ["update", "delete"])
async def test_radius_account_unknown_id_lists_every_account_and_sends_nothing(
    client, registry, write
):
    client.get.return_value = RADIUS_USERS
    with pytest.raises(ValueError, match="RADIUS account 'nope' not found; valid: ") as err:
        if write == "update":
            await sc._update_batch_record(
                client,
                registry,
                "h",
                "Default",
                sc.RADIUS_ACCOUNTS,
                "nope",
                "account_id",
                {"vlan": 1},
            )
        else:
            await sc._delete_batch_record(
                client, registry, "h", "Default", sc.RADIUS_ACCOUNTS, "nope", "account_id"
            )
    assert "'mcp-test-alice'" in str(err.value) and "No write was sent." in str(err.value)
    assert "synthetic-stored-value" not in str(err.value)
    client.post.assert_not_awaited()


@pytest.mark.parametrize("response", [None, {"extra": 7}])
async def test_delete_radius_account_posts_a_one_element_id_batch(client, registry, response):
    from unifi_fabric.tools._results import deletion_result

    client.get.return_value = RADIUS_USERS
    client.post.return_value = response
    uid = RADIUS_USERS[0]["_id"]
    out = await sc._delete_batch_record(
        client, registry, "h", "Default", sc.RADIUS_ACCOUNTS, uid, "account_id"
    )
    assert client.post.await_args.args[0] == f"{V2}/radius/users/batch_delete"
    assert client.post.await_args.kwargs["json"] == [uid]
    assert out == deletion_result(f"RADIUS account {uid} deleted.", response)
    client.delete.assert_not_awaited()


async def test_radius_account_batch_dry_run_previews_are_returned(client, registry):
    client.get.return_value = RADIUS_USERS
    uid = RADIUS_USERS[0]["_id"]
    preview = _preview("POST", f"{V2}/radius/users/batch_add", [{"name": "zz"}])
    client.post.return_value = preview
    assert (
        await sc._create_batch_record(
            client, registry, "h", "Default", sc.RADIUS_ACCOUNTS, {"name": "zz"}, None
        )
        == preview
    )
    preview = _preview("POST", f"{V2}/radius/users/batch_update", [RADIUS_USERS[0]])
    client.post.return_value = preview
    assert (
        await sc._update_batch_record(
            client,
            registry,
            "h",
            "Default",
            sc.RADIUS_ACCOUNTS,
            uid,
            "account_id",
            {"name": "zz"},
        )
        == preview
    )
    client.post.return_value = _preview("POST", f"{V2}/radius/users/batch_delete", [uid])
    out = await sc._delete_batch_record(
        client, registry, "h", "Default", sc.RADIUS_ACCOUNTS, uid, "account_id"
    )
    assert out["status"] == "dry_run" and out["deleted"] is False


def test_radius_account_tools_route_only_to_v2_batch_writes():
    """The three RADIUS account write tools reach the v2 batch helpers, never Classic
    rest/account (official > v2 > Classic route preference)."""
    import inspect

    src = inspect.getsource(sc.register)
    for tool, helper in (
        ("create_radius_account", "_create_batch_record"),
        ("update_radius_account", "_update_batch_record"),
        ("delete_radius_account", "_delete_batch_record"),
    ):
        body = src[src.index(f"async def {tool}(") :]
        body = body[: body.index("@mcp.tool")] if "@mcp.tool" in body else body
        assert helper in body, tool
        assert "_config_record(" not in body.split('"""')[-1], tool
    assert sc.RADIUS_ACCOUNTS.v2 and sc.RADIUS_ACCOUNTS.batch
    assert sc.RADIUS_ACCOUNTS.path == "/radius/users"
