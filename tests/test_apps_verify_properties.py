"""Every requested application-write field participates in readback verification."""

import ast
import copy
import inspect
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools import carrier_fabric, mobility, protect

SID = "00000000-0000-4000-8000-000000000001"
PID = "00000000-0000-4000-8000-000000000002"

CARRIER = [
    (
        "update_carrier_subscriber",
        {
            "name": "requested",
            "email": "synthetic@example.invalid",
            "notes": "requested",
            "service_address": "synthetic address",
            "plan_id": PID,
            "subscriber_number": "synthetic-2",
            "metadata": {"synthetic": "requested"},
        },
        {
            "name": "requested",
            "email": "synthetic@example.invalid",
            "notes": "requested",
            "serviceAddress": "synthetic address",
            "planId": PID,
            "subscriberNumber": "synthetic-2",
            "metadata": {"synthetic": "requested"},
        },
    ),
    ("attach_carrier_subscriber_host", {"host_id": "synthetic-host"}, {"hostId": "synthetic-host"}),
    ("detach_carrier_subscriber_host", {}, {"hostId": None}),
    ("assign_carrier_subscriber_plan", {"plan_id": PID}, {"planId": PID}),
    (
        "suspend_carrier_subscriber",
        {"reason": "synthetic reason"},
        {"suspended": True, "suspendReason": "synthetic reason"},
    ),
    ("resume_carrier_subscriber", {}, {"suspended": False}),
]


def _client():
    return SimpleNamespace(
        dry_run=False,
        post=AsyncMock(return_value={}),
        patch=AsyncMock(return_value={}),
        put=AsyncMock(return_value={}),
        delete=AsyncMock(return_value={}),
        get=AsyncMock(),
    )


@pytest.mark.parametrize("name,args,wanted", CARRIER)
@pytest.mark.parametrize("mutation", ["missing", "different"])
async def test_carrier_every_requested_field_verifies(monkeypatch, name, args, wanted, mutation):
    """For each requested field, a missing/wrong readback must prevent a true verdict."""
    before = {"id": SID, "hostId": "synthetic-old-host", "suspended": name.startswith("resume")}
    monkeypatch.setattr(
        carrier_fabric, "first_success", AsyncMock(return_value=(None, {"data": before}))
    )
    client = _client()
    for field in wanted:
        after = {"id": SID, **wanted}
        if mutation == "missing":
            # Missing hostId represents the documented detached state.
            if field == "hostId" and wanted[field] is None:
                continue
            del after[field]
        else:
            after[field] = "synthetic-unapplied"
        monkeypatch.setattr(
            carrier_fabric, "_after_write", AsyncMock(return_value=({"data": after}, None))
        )
        result = await getattr(carrier_fabric, name)(client, SID, **args)
        assert result["verified"] is False, (name, field, mutation)


PROTECT = sorted(
    name
    for name, func in vars(protect).items()
    if name.startswith("update_") and inspect.iscoroutinefunction(func)
)


@pytest.mark.parametrize("name", PROTECT)
@pytest.mark.parametrize("mutation", ["missing", "different"])
async def test_protect_every_requested_leaf_verifies(monkeypatch, name, mutation):
    """Exercise every public verified updater, including arm-profile special paths."""
    monkeypatch.setattr(protect, "_resolve", AsyncMock(return_value=(None, "synthetic-host")))
    client = _client()
    monkeypatch.setattr(protect, "_patch", AsyncMock(return_value={}))
    if name == "update_arm_profile_settings":
        monkeypatch.setattr(
            protect, "_find_arm_profile", AsyncMock(return_value=({"id": SID}, [SID]))
        )
        after = {} if mutation == "missing" else {"armProfileId": "synthetic-unapplied"}
        client.get.side_effect = [{"armMode": {}}, {"armMode": after}]
        result = await getattr(protect, name)(client, None, "synthetic-host", SID)
        assert result["verified"] is False
        return
    wanted = {"name": "synthetic requested", "settings": {"enabled": True, "level": 3}}
    for path in [("name",), ("settings", "enabled"), ("settings", "level")]:
        after = {"id": SID, **copy.deepcopy(wanted)}
        target = after
        for part in path[:-1]:
            target = target[part]
        if mutation == "missing":
            del target[path[-1]]
        else:
            target[path[-1]] = "synthetic-unapplied"
        before = {"id": SID, "name": "synthetic old"}
        if name == "update_arm_profile":
            monkeypatch.setattr(
                protect,
                "_find_arm_profile",
                AsyncMock(side_effect=[(before, [SID]), (after, [SID])]),
            )
        else:
            client.get.side_effect = [before, after]
        result = await getattr(protect, name)(client, None, "synthetic-host", SID, **wanted)
        assert result["verified"] is False, (name, path, mutation)


@pytest.mark.parametrize(
    "name,args,expected",
    [
        ("update_mobility_device_name", {"name": "synthetic requested"}, {"name": True}),
        (
            "update_mobility_device_network",
            {
                "host_address": "192.0.2.1",
                "dhcp_mode": "dhcp",
                "dhcp_range_start": "192.0.2.2",
                "dhcp_range_stop": "192.0.2.10",
                "dhcp_lease_time": 600,
            },
            {
                "host_address": True,
                "dhcp_mode": None,
                "dhcp_range_start": None,
                "dhcp_range_stop": None,
                "dhcp_lease_time": None,
            },
        ),
        (
            "update_mobility_device_wireless",
            {"ssid": "synthetic requested", "password": "synthetic-password"},
            {"ssid": True, "password": None},
        ),
    ],
)
async def test_mobility_every_requested_field_accounted_for(monkeypatch, name, args, expected):
    """Unobservable spec fields explicitly report unknown, never disappear or claim true."""
    schemas = json.loads(Path("tests/fixtures/openapi/mobility-1.0.0.json").read_text())[
        "components"
    ]["schemas"]
    observable = set(schemas["DeviceSummary"]["properties"])
    for component in schemas["DeviceDetail"]["allOf"]:
        observable.update(component.get("properties", {}))
    for field, verdict in expected.items():
        if verdict is None:
            assert field not in observable
    client = _client()
    before = {"id": SID}
    after = {
        "id": SID,
        "name": "synthetic requested",
        "wifi_ssid": "synthetic requested",
        "host_address": "192.0.2.1",
    }
    monkeypatch.setattr(mobility, "_owning_device", AsyncMock(return_value=(None, before)))
    monkeypatch.setattr(mobility, "_put_no_content", AsyncMock(return_value={}))
    monkeypatch.setattr(mobility, "_read_after", AsyncMock(return_value=(after, after, None)))
    result = await getattr(mobility, name)(client, SID, PID, **args)
    assert result["verified"] == expected
    for field, verdict in expected.items():
        if verdict is None:
            continue
        bad_after = {**after}
        del bad_after[{"ssid": "wifi_ssid"}.get(field, field)]
        monkeypatch.setattr(
            mobility, "_read_after", AsyncMock(return_value=(bad_after, bad_after, None))
        )
        result = await getattr(mobility, name)(client, SID, PID, **args)
        assert result["verified"][field] is False


def test_verify_catalog_is_complete():
    """The mutation matrix cannot silently miss a new verified Carrier/Mobility write."""
    tree = ast.parse(inspect.getsource(carrier_fabric))
    verified = {
        function.name
        for function in tree.body
        if isinstance(function, ast.AsyncFunctionDef)
        and any(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "_written"
            for call in ast.walk(function)
        )
    }
    assert verified == {name for name, _args, _wanted in CARRIER}
    assert {
        name
        for name, function in vars(mobility).items()
        if name.startswith("update_") and inspect.iscoroutinefunction(function)
    } == {
        "update_mobility_device_name",
        "update_mobility_device_network",
        "update_mobility_device_wireless",
    }
