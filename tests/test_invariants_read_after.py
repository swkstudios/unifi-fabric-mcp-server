"""Cross-tool read-after invariants (Build rules 1, 11, 16, 19).

A write is reported verified only when a read-after confirms every requested leaf,
leaf by leaf and type-strict (``True`` is not ``1``), after the additive ``_`` keys are
stripped. A read-after that fails, errors, returns an unexpected shape or cannot be
matched keeps the write response verbatim and reports verification unknown with the
reason, never "verified" and never a raised error. No-op detection compares requested
leaves only. Dry-run never reports verified. A relayed DELETE is "changed" only when the
read-after answers 404.

The catalog is derived from the source: every public tool function that reaches a
read-after (``safe_read_after`` or the relay's ``_safe_get``), directly, through a
module-local helper or a module-qualified call, must be in one of the matrices below.
"""

from __future__ import annotations

import ast
import copy
import inspect
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from unifi_fabric.client import DRY_RUN_MESSAGE, UniFiConnectionError
from unifi_fabric.tools import (
    carrier_fabric,
    connector,
    innerspace,
    innerspace_internal,
    mobility,
    network_clients_guests,
    network_controller_admin,
    network_dpi_policy,
    network_mobile_wan,
    network_nat_qos_traffic,
    network_proav_sandbox,
    network_routing_topology,
    network_security_diagnostics,
    network_services_proxy,
    network_switching_power,
    network_vpn_dns,
    protect,
    protect_automation_backup,
    protect_events_cases,
    protect_ptz_doorbell,
    protect_recognition_search,
    protect_users_assets,
)
from unifi_fabric.tools._results import (
    read_after_verdict,
    requested_leaves_verdict,
)

TOOLS_DIR = Path(__file__).resolve().parents[1] / "src" / "unifi_fabric" / "tools"
SID = "00000000-0000-4000-8000-000000000001"
PID = "00000000-0000-4000-8000-000000000002"
HEX_ID = "0000000000000000000000a1"
NC_HEX_ID = "0000000000000000000000a1"
VPN_DNS_HEX = "0000000000000000000000a7"
PREVIEW = {
    "status": "dry_run",
    "dryRun": True,
    "message": DRY_RUN_MESSAGE,
    "preview": {"method": "PATCH", "path": "/x", "params": None, "body": {}},
}
WRITE_RESPONSE = {"synthetic": "write-response"}
_DEFAULT_WRITE_RESPONSE = object()
SEEDS = frozenset({"safe_read_after", "_safe_get"})


# --------------------------------------------------------------------------- catalog


def _read_after_tools() -> set[str]:
    """``module.function`` for every public tool function reaching a read-after seed.

    Calls are resolved by name across all tool modules (``helper(...)`` and
    ``module.helper(...)`` alike), transitively, including nested functions.
    """
    graph: dict[str, set[str]] = {}
    public: dict[str, str] = {}
    for path in sorted(TOOLS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            calls: set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    func = sub.func
                    if isinstance(func, ast.Name):
                        calls.add(func.id)
                    elif isinstance(func, ast.Attribute):
                        calls.add(func.attr)
                elif isinstance(sub, ast.Name):
                    # helpers passed as callables (lambda: helper(...), first_success(...))
                    calls.add(sub.id)
            graph.setdefault(node.name, set()).update(calls)
            if (
                not node.name.startswith("_")
                and not path.stem.startswith("_")  # shared helpers, not tools
                and isinstance(node, ast.AsyncFunctionDef)
            ):
                public[node.name] = path.stem
    reach: dict[str, bool] = {}

    def reaches(name: str, stack: frozenset[str] = frozenset()) -> bool:
        if name in SEEDS:
            return True
        if name in reach:
            return reach[name]
        if name in stack or name not in graph:
            return False
        result = any(reaches(c, stack | {name}) for c in graph[name])
        reach[name] = result
        return result

    return {f"{module}.{name}" for name, module in public.items() if reaches(name)}


PROTECT_VERIFIED = sorted(
    name
    for name, func in vars(protect).items()
    if name.startswith("update_") and inspect.iscoroutinefunction(func)
)
# Private verifying writes are exercised by test_invariants_protect_private_verification.
# The other writes expose connector read-back without a private verification verdict.
PROTECT_PRIVATE_CLASSIFICATION = {
    "get_camera_private": "read",
    "get_nvr_private": "read",
    "get_sensor_private": "read",
    "list_ptz_patrols": "read",
    "list_ptz_presets": "read",
    "export_camera_video": "read",
    "update_camera_private": "verified",
    "update_nvr": "verified",
    "update_sensor_private": "verified",
    "clear_sensor_tamper": "verified",
    "unadopt_protect_device": "verified",
    "adopt_protect_device": "connector_read_back",
    "reboot_protect_device": "connector_read_back",
    "reboot_nvr": "connector_read_back",
}
PROTECT_PRIVATE_READ_AFTER = {
    f"protect_private.{name}"
    for name, classification in PROTECT_PRIVATE_CLASSIFICATION.items()
    if classification != "read"
}
MOBILITY_VERIFIED = [
    "update_mobility_device_name",
    "update_mobility_device_network",
    "update_mobility_device_wireless",
]
CARRIER_VERIFIED = [
    "update_carrier_subscriber",
    "attach_carrier_subscriber_host",
    "detach_carrier_subscriber_host",
    "assign_carrier_subscriber_plan",
    "suspend_carrier_subscriber",
    "resume_carrier_subscriber",
]
NETWORK_CLIENTS_GUESTS_VERIFIED = [
    "update_dhcp_option",
    "update_hotspot_package",
]
SWITCHING_POWER_VERIFIED = [
    "update_energy_saving_policy",
    "update_power_supervisor",
    "update_power_supervisor_link",
]
SECURITY_VERIFIED = [
    "update_ssl_inspection_profile",
    "update_ssl_inspection_settings",
    "update_system_log_settings",
]
NC_VERIFIED = ["update_nat_rule", "update_qos_rule", "update_content_filter"]
VPN_DNS_VERIFIED = [
    "update_static_dns_record",
    "update_ipsec_settings",
    "update_wireguard_users",
]
ADMIN_VERIFIED = ["update_my_admin_profile"]
ADMIN_HEX = "0000000000000000000000a1"
PTZ_DOORBELL_VERIFIED = ["update_ptz_patrol", "update_ptz_preset", "update_camera_shortcut"]
ROUTING_TOPOLOGY_VERIFIED = [
    "update_bgp_config",
    "update_ospf_router",
    "update_global_network_config",
    "manage_mclag_group",
    "update_switch_stack",
]
ROUTING_TOPOLOGY_DELETES = ["delete_bgp_config", "delete_ospf_router"]
BATCH_DELETES = {
    "network_nat_qos_traffic.delete_qos_rule",
    "network_vpn_dns.delete_wireguard_users",
}
MOBILE_WAN_VERIFIED = ["update_wan_load_balancing", "update_wan_sla"]
DPI_POLICY_VERIFIED = [
    "update_network_members_group",
    "update_policy_engine_rule",
    "update_predefined_firewall_policy",
]
EVENTS_CASES_VERIFIED = [
    "update_protect_case",
    "update_protect_case_asset",
    "set_protect_event_favorite",
]
#: Read-after paths that report no verdict at all (an additive name resolution or a
#: follow-up check): they may only ever add ``_readAfterError``, never a verdict.
NO_VERDICT = {
    "network_services_proxy.list_port_profiles",
    "network_services_proxy.get_port_profile",
    "network_services_proxy.update_port_profile",
    "network_services_proxy.allow_network_on_port_profile",
    "network_services_proxy.exclude_network_on_port_profile",
}

ASSETS_VERIFIED = [
    "update_protect_device_tag",
    "update_protect_user_group",
    "update_protect_user",
    "update_protect_user_notifications",
    "set_protect_notifications_muted",
]


def test_read_after_catalog_is_complete():
    """A new tool that reads after it writes must join a matrix here (rule 19)."""
    covered = (
        {f"protect.{n}" for n in PROTECT_VERIFIED}
        | {f"mobility.{n}" for n in MOBILITY_VERIFIED}
        | {f"carrier_fabric.{n}" for n in CARRIER_VERIFIED}
        | PROTECT_PRIVATE_READ_AFTER
        | {f"network_clients_guests.{n}" for n in NETWORK_CLIENTS_GUESTS_VERIFIED}
        | {f"network_switching_power.{n}" for n in SWITCHING_POWER_VERIFIED}
        | {f"protect_users_assets.{n}" for n in ASSETS_VERIFIED}
        | {f"network_security_diagnostics.{n}" for n in SECURITY_VERIFIED}
        | {f"network_nat_qos_traffic.{n}" for n in NC_VERIFIED}
        | {f"network_vpn_dns.{n}" for n in VPN_DNS_VERIFIED}
        | {f"protect_ptz_doorbell.{n}" for n in PTZ_DOORBELL_VERIFIED}
        | {f"network_routing_topology.{n}" for n in ROUTING_TOPOLOGY_VERIFIED}
        | {f"network_routing_topology.{n}" for n in ROUTING_TOPOLOGY_DELETES}
        | {f"network_mobile_wan.{n}" for n in MOBILE_WAN_VERIFIED}
        | {f"network_dpi_policy.{n}" for n in DPI_POLICY_VERIFIED}
        | {f"protect_events_cases.{n}" for n in EVENTS_CASES_VERIFIED}
        | {"network_services_proxy.update_setting", "connector.connector_write"}
        | {"network_services_proxy.update_traffic_rule"}
        | {"network_wifi_radio.configure_wifi_wan"}
        | {"network_proav_sandbox.update_digital_twin_layout"}
        | {f"network_controller_admin.{n}" for n in ADMIN_VERIFIED}
        | {"innerspace_internal.update_innerspace_plan"}
        | {"protect_device_lifecycle.update_protect_device_settings"}
        | NO_VERDICT
        | BATCH_DELETES
    )
    found = _read_after_tools()
    assert found - covered == set(), "read-after tools missing from the property matrix"
    assert covered - found == set(), "matrix lists tools that no longer read after"


# --------------------------------------------------------------------------- helper


@pytest.mark.parametrize(
    "after,error",
    [
        (None, None),
        ([], None),
        ("text", None),
        (7, None),
        (True, None),
        ({"a": 1}, "UniFiConnectionError: boom"),
    ],
)
def test_helper_never_verifies_an_unusable_read_after(after, error):
    verdict, reason = requested_leaves_verdict({"a": 1}, after, error)
    assert verdict is None
    assert reason


def test_helper_check_failure_is_unknown_not_raised():
    def boom(_after: dict[str, Any]) -> bool:
        raise KeyError("data")

    verdict, reason = read_after_verdict({"a": 1}, None, boom)
    assert verdict is None and "KeyError" in reason


@pytest.mark.parametrize(
    "requested,after,expected",
    [
        ({"a": True}, {"a": 1}, False),
        ({"a": 1}, {"a": True}, False),
        ({"a": False}, {"a": 0}, False),
        ({"a": 1}, {}, False),
        ({"a": {"b": True}}, {"a": {"b": 1}}, False),
        ({"a": {"b": True}}, {"a": {"b": True, "c": 9}}, True),
        ({"a": 1}, {"a": 1, "sibling": "changed"}, True),
        ({"a": 1, "_note": "x"}, {"a": 1}, True),
        ({"a": [True]}, {"a": [1]}, False),
    ],
)
def test_helper_compares_requested_leaves_type_strict(requested, after, expected):
    assert requested_leaves_verdict(requested, after, None) == (expected, None)


# --------------------------------------------------------------------------- drivers
#
# Each driver runs one verifying tool against a synthetic upstream. ``before`` is the
# record the read-before returns; ``after`` is the read-after record, an Exception to
# raise, or a non-object shape. It returns (result, write_mock).


def _client(dry_run: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        dry_run=dry_run,
        get=AsyncMock(),
        post=AsyncMock(return_value=WRITE_RESPONSE),
        put=AsyncMock(return_value=WRITE_RESPONSE),
        patch=AsyncMock(return_value=WRITE_RESPONSE),
        delete=AsyncMock(return_value=WRITE_RESPONSE),
    )


def _reader(after: Any, wrapped: Any) -> AsyncMock:
    """A read-after mock: the wrapped record, the exception raised, or the raw shape."""
    if isinstance(after, BaseException):
        return AsyncMock(side_effect=after)
    return AsyncMock(return_value=wrapped if isinstance(after, dict) else after)


class Case:
    """One verifying tool: its requested leaves and how to drive and read it."""

    family: str
    name: str
    requested: dict[str, Any]
    bool_field: str | None = None
    has_noop: bool = True

    def __init__(self, family: str, name: str) -> None:
        self.family, self.name = family, name

    def __repr__(self) -> str:
        return f"{self.family}.{self.name}"

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        raise NotImplementedError

    def verdict(self, result: dict[str, Any]) -> bool | None:
        return result["verified"]

    def error(self, result: dict[str, Any]) -> Any:
        return result.get("readAfterError")

    def is_noop(self, result: dict[str, Any]) -> bool:
        return result.get("status") in ("noop", "no_op")

    def response(self, result: dict[str, Any]) -> Any:
        return result["response"]


class ProtectCase(Case):
    requested_wanted = {"name": "synthetic requested", "settings": {"enabled": True, "level": 3}}

    def __init__(self, name: str) -> None:
        super().__init__("protect", name)
        if name == "update_arm_profile_settings":
            self.requested = {"armProfileId": SID}
        else:
            self.requested = copy.deepcopy(self.requested_wanted)
            self.bool_field = "settings.enabled"

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        monkeypatch.setattr(protect, "_resolve", AsyncMock(return_value=(None, "synthetic-host")))
        patch = AsyncMock(return_value=PREVIEW if dry_run else (write or WRITE_RESPONSE))
        monkeypatch.setattr(protect, "_patch", patch)
        if self.name == "update_arm_profile_settings":
            monkeypatch.setattr(
                protect, "_find_arm_profile", AsyncMock(return_value=({"id": SID}, [SID]))
            )
            after_nvr = after if isinstance(after, BaseException) else {"armMode": after}
            client.get.side_effect = [{"armMode": before}, after_nvr]
            result = await protect.update_arm_profile_settings(client, None, "h", SID)
            return result, patch
        fields = copy.deepcopy(self.requested_wanted)
        if self.name == "update_arm_profile":
            before = {"id": SID, **before}
            reads = [(before, [SID])]
            if isinstance(after, BaseException):
                reads.append(after)
            elif isinstance(after, dict):
                reads.append(({"id": SID, **after}, [SID]))
            else:
                reads.append((None, [SID]))  # the profile cannot be found / matched
            monkeypatch.setattr(protect, "_find_arm_profile", AsyncMock(side_effect=reads))
        else:
            client.get.side_effect = [before, after]
        result = await getattr(protect, self.name)(client, None, "h", SID, **fields)
        return result, patch


class AssetsCase(Case):
    def __init__(self, name):
        super().__init__("protect_users_assets", name)
        self.requested = copy.deepcopy(ProtectCase.requested_wanted)
        self.bool_field = "settings.enabled"
        if name == "set_protect_notifications_muted":
            self.requested = {"validUntil": 1893456000000}
            self.bool_field = None
            self.has_noop = False

    async def run(
        self, monkeypatch, before, after, *, dry_run=False, write=_DEFAULT_WRITE_RESPONSE
    ):
        client = _client(dry_run)
        monkeypatch.setattr(
            protect_users_assets, "_resolve", AsyncMock(return_value=(None, "synthetic-host"))
        )
        monkeypatch.setattr(protect_users_assets, "_require_mutations", lambda: None)
        before = {"id": SID, **before}
        if self.name == "update_protect_device_tag":
            final = [{"id": SID, **after}] if isinstance(after, dict) else after
            client.get.side_effect = [[before], final]
        else:
            family = "groups" if self.name == "update_protect_user_group" else "users"

            def wrap(record):
                if isinstance(record, dict):
                    if self.name == "update_protect_user_notifications":
                        record = {"id": SID, "notifications": record}
                    elif self.name == "set_protect_notifications_muted":
                        record = {"id": SID, "notificationSnoozeSettings": record}
                    return {family: [{"id": SID, **record}]}
                return record

            client.get.side_effect = [wrap(before), wrap(after)]
        writer = client.post if self.name == "set_protect_notifications_muted" else client.patch
        writer.return_value = (
            PREVIEW if dry_run else (WRITE_RESPONSE if write is _DEFAULT_WRITE_RESPONSE else write)
        )
        fn = getattr(protect_users_assets, self.name)
        if self.name == "set_protect_notifications_muted":
            result = await fn(client, None, "h", SID, True, self.requested["validUntil"])
        else:
            result = await fn(client, None, "h", SID, copy.deepcopy(self.requested))
        return result, writer

    def verdict(self, result):
        return result["_verified"]

    def error(self, result):
        return result.get("_readAfterError")

    def is_noop(self, result):
        return result.get("_status") == "noop"

    def response(self, result):
        return {k: v for k, v in result.items() if not k.startswith("_")}


class ProtectAutomationCase(Case):
    has_noop = False
    bool_field = "settings.enabled"
    requested = {"name": "synthetic requested", "settings": {"enabled": True, "level": 3}}

    def __init__(self):
        super().__init__("protect_automation_backup", "_update_protect_automation")

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        monkeypatch.setattr(
            protect_automation_backup, "_resolve", AsyncMock(return_value=(None, "h"))
        )
        # _known returns only a listed record whose id names the request (c6da28d1),
        # so a stubbed record read carries that id like the real one does.
        reads = [{**r, "id": SID} if isinstance(r, dict) else r for r in (before, after)]
        monkeypatch.setattr(protect_automation_backup, "_known", AsyncMock(side_effect=reads))
        client.patch.return_value = PREVIEW if dry_run else (write or WRITE_RESPONSE)
        result = await protect_automation_backup._update_protect_automation(
            client, None, "h", SID, copy.deepcopy(self.requested)
        )
        return result, client.patch

    def verdict(self, result):
        return result["_verified"]

    def error(self, result):
        return result.get("_readAfterError")

    def response(self, result):
        return {k: v for k, v in result.items() if not k.startswith("_")}


class MobilityCase(Case):
    ARGS = {
        "update_mobility_device_name": (
            {"name": "synthetic requested"},
            {"name": "synthetic requested"},
        ),
        "update_mobility_device_network": (
            {"host_address": "192.0.2.1"},
            {"host_address": "192.0.2.1"},
        ),
        "update_mobility_device_wireless": (
            {"ssid": "synthetic requested", "password": "synthetic-password"},
            {"wifi_ssid": "synthetic requested"},
        ),
    }

    def __init__(self, name: str) -> None:
        super().__init__("mobility", name)
        self.args, self.requested = self.ARGS[name]
        self.has_noop = name != "update_mobility_device_wireless"

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        monkeypatch.setattr(
            mobility, "_owning_device", AsyncMock(return_value=(None, {"data": before}))
        )
        put = AsyncMock(return_value=PREVIEW if dry_run else (write or WRITE_RESPONSE))
        monkeypatch.setattr(mobility, "_put_no_content", put)
        monkeypatch.setattr(mobility, "_fetch_device_body", _reader(after, {"data": after}))
        result = await getattr(mobility, self.name)(client, SID, PID, **self.args)
        return result, put

    def verdict(self, result):
        verified = result["verified"]
        if verified is None:
            return None
        known = [v for v in verified.values() if v is not None]
        if any(v is not True for v in known):
            return False
        return True if known else None


class CarrierCase(Case):
    ARGS = {
        "update_carrier_subscriber": (
            {"name": "synthetic requested", "notes": "synthetic"},
            {"name": "synthetic requested", "notes": "synthetic"},
        ),
        "attach_carrier_subscriber_host": (
            {"host_id": "synthetic-host"},
            {"hostId": "synthetic-host"},
        ),
        "detach_carrier_subscriber_host": ({}, {"hostId": None}),
        "assign_carrier_subscriber_plan": ({"plan_id": PID}, {"planId": PID}),
        "suspend_carrier_subscriber": ({}, {"suspended": True}),
        "resume_carrier_subscriber": ({}, {"suspended": False}),
    }
    WRITE = {
        "update_carrier_subscriber": "patch",
        "attach_carrier_subscriber_host": "put",
        "assign_carrier_subscriber_plan": "put",
        "detach_carrier_subscriber_host": "delete",
        "suspend_carrier_subscriber": "post",
        "resume_carrier_subscriber": "post",
    }

    def __init__(self, name: str) -> None:
        super().__init__("carrier_fabric", name)
        self.args, self.requested = self.ARGS[name]
        if name in ("suspend_carrier_subscriber", "resume_carrier_subscriber"):
            self.bool_field = "suspended"

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        writer = getattr(client, self.WRITE[self.name])
        writer.return_value = PREVIEW if dry_run else (write or {})
        monkeypatch.setattr(
            carrier_fabric,
            "first_success",
            AsyncMock(return_value=(None, {"data": {"id": SID, **before}})),
        )
        wrapped = {"data": {"id": SID, **after}} if isinstance(after, dict) else None
        monkeypatch.setattr(carrier_fabric, "_fetch_subscriber", _reader(after, wrapped))
        result = await getattr(carrier_fabric, self.name)(client, SID, **self.args)
        return result, writer

    def response(self, result):
        return result["response"]


class SwitchingPowerCase(Case):
    def __init__(self, name: str) -> None:
        super().__init__("network_switching_power", name)
        self.requested = {
            "name": "synthetic requested",
            "settings": {"enabled": True, "level": 3},
        }
        self.bool_field = "settings.enabled"
        self.has_noop = False

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        client.put.return_value = PREVIEW if dry_run else (write or dict(WRITE_RESPONSE))
        registry = _registry()
        reads: list[Any] = [[{"_id": HEX_ID, **before}]]
        if isinstance(after, BaseException):
            reads.append(after)
        elif isinstance(after, dict):
            reads.append([{"_id": HEX_ID, **after}])
        else:
            reads.append(after)
        client.get = AsyncMock(side_effect=reads)
        result = await getattr(network_switching_power, self.name)(
            client, registry, "h", "default", HEX_ID, copy.deepcopy(self.requested)
        )
        return result, client.put

    def verdict(self, result):
        return result["_verified"]

    def error(self, result):
        return result.get("_readAfterError")

    def response(self, result):
        return {key: value for key, value in result.items() if not key.startswith("_")}


class SecurityCase(Case):
    HEX_ID = "0000000000000000000000d1"

    def __init__(self, name: str) -> None:
        super().__init__("network_security_diagnostics", name)
        self.requested = {"name": "synthetic requested", "settings": {"enabled": True, "level": 3}}
        self.bool_field = "settings.enabled"
        self.has_noop = False

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        client.audit_refusal = MagicMock()
        client.put.return_value = PREVIEW if dry_run else (write or dict(WRITE_RESPONSE))
        listed = self.name == "update_ssl_inspection_profile"
        reads: list[Any] = [[{"_id": self.HEX_ID, **before}] if listed else dict(before)]
        if isinstance(after, BaseException):
            reads.append(after)
        elif isinstance(after, dict):
            reads.append([{"_id": self.HEX_ID, **after}] if listed else dict(after))
        else:
            reads.append(after)
        client.get = AsyncMock(side_effect=reads)
        args = (self.HEX_ID,) if listed else ()
        result = await getattr(network_security_diagnostics, self.name)(
            client, _registry(), "h", "default", *args, copy.deepcopy(self.requested)
        )
        return result, client.put

    def verdict(self, result):
        return result["_verified"]

    def error(self, result):
        return result.get("_readAfterError")

    def response(self, result):
        return {key: value for key, value in result.items() if not key.startswith("_")}


class NcCase(Case):
    """GS3 NC v2 updates: read-before from the collection, merged PUT, read-after list."""

    def __init__(self, name: str) -> None:
        super().__init__("network_nat_qos_traffic", name)
        self.requested = {
            "name": "synthetic requested",
            "settings": {"enabled": True, "level": 3},
        }
        self.bool_field = "settings.enabled"
        self.has_noop = False

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        client.put.return_value = PREVIEW if dry_run else (write or dict(WRITE_RESPONSE))
        reads: list[Any] = [[{"_id": NC_HEX_ID, **before}]]
        if isinstance(after, BaseException):
            reads.append(after)
        elif isinstance(after, dict):
            reads.append([{"_id": NC_HEX_ID, **after}])
        else:
            reads.append(after)
        client.get = AsyncMock(side_effect=reads)
        result = await getattr(network_nat_qos_traffic, self.name)(
            client, _registry(), "h", "default", NC_HEX_ID, copy.deepcopy(self.requested)
        )
        return result, client.put

    def verdict(self, result):
        return result["_verified"]

    def error(self, result):
        return result.get("_readAfterError")

    def response(self, result):
        return {key: value for key, value in result.items() if not key.startswith("_")}


class TrafficRuleCase(NcCase):
    """update_traffic_rule: read-before from list_traffic_rules, merged v2 PUT, read-after."""

    def __init__(self) -> None:
        super().__init__("update_traffic_rule")
        self.family = "network_services_proxy"

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        client.put.return_value = PREVIEW if dry_run else (write or dict(WRITE_RESPONSE))
        reads: list[Any] = [[{"_id": NC_HEX_ID, **before}]]
        if isinstance(after, BaseException):
            reads.append(after)
        elif isinstance(after, dict):
            reads.append([{"_id": NC_HEX_ID, **after}])
        else:
            reads.append(after)
        client.get = AsyncMock(side_effect=reads)
        result = await network_services_proxy.update_traffic_rule(
            client, _registry(), "h", "default", NC_HEX_ID, copy.deepcopy(self.requested)
        )
        return result, client.put


class VpnDnsCase(Case):
    """N07 read-merge-write tools: the upstream body verbatim plus additive _verified."""

    def __init__(self, name: str) -> None:
        super().__init__("network_vpn_dns", name)
        self.requested = {"name": "synthetic requested", "settings": {"enabled": True, "level": 3}}
        self.bool_field = "settings.enabled"
        self.has_noop = False

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        writer = client.post if self.name == "update_ipsec_settings" else client.put
        writer.return_value = PREVIEW if dry_run else (write or dict(WRITE_RESPONSE))
        row = {"_id": VPN_DNS_HEX}
        if isinstance(after, dict):
            after_body: Any = (
                {**row, **after} if self.name == "update_ipsec_settings" else [{**row, **after}]
            )
        else:
            after_body = after
        args: tuple[Any, ...]
        if self.name == "update_ipsec_settings":
            reads: list[Any] = [{**row, **before}, after_body]
            args = (copy.deepcopy(self.requested),)
        elif self.name == "update_static_dns_record":
            reads = [[{**row, **before}], after_body]
            args = (VPN_DNS_HEX, copy.deepcopy(self.requested))
        else:
            server = {"_id": VPN_DNS_HEX, "external_id": SID, "purpose": "remote-user-vpn"}
            reads = [{"meta": {"rc": "ok"}, "data": [server]}, [{**row, **before}], after_body]
            args = (SID, [{**row, **copy.deepcopy(self.requested)}])
        client.get = AsyncMock(side_effect=reads)
        result = await getattr(network_vpn_dns, self.name)(
            client, _registry(), "h", "default", *args
        )
        return result, writer

    def verdict(self, result):
        return result["_verified"]

    def error(self, result):
        return result.get("_readAfterError")

    def response(self, result):
        return {k: v for k, v in result.items() if not k.startswith("_")}


class SettingCase(Case):
    def __init__(self) -> None:
        super().__init__("network_services_proxy", "update_setting")
        self.requested = {"enabled": True, "mode": "requested"}
        self.bool_field = "enabled"

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        client.put.return_value = PREVIEW if dry_run else (write or dict(WRITE_RESPONSE))
        registry = AsyncMock()
        registry.resolve_key_for_host.return_value = None
        registry.resolve_host_id.return_value = "synthetic-host"
        registry.resolve_site_slug.return_value = "default"
        pre = {"data": [{"key": "synthetic", **before}]}
        if isinstance(after, dict):
            post: Any = {"data": [{"key": "synthetic", **after}]}
        else:
            post = after
        client.get.side_effect = [pre, post]
        result = await network_services_proxy.update_setting(
            client, registry, "h", "default", "synthetic", dict(self.requested)
        )
        return result, client.put

    def verdict(self, result):
        return result["_verified"]

    def error(self, result):
        return result.get("_readAfterError")

    def is_noop(self, result):
        return result.get("_note") == "no change needed"

    def response(self, result):
        return {k: v for k, v in result.items() if not k.startswith("_")}


class ClassicRecordCase(Case):
    """network_clients_guests Classic PUTs: listed record re-read, ``_verified`` additive."""

    requested = {"name": "synthetic requested", "nested": {"enabled": True, "level": 3}}
    bool_field = "nested.enabled"
    has_noop = False  # the Classic update always writes; only verification is derived

    def __init__(self, name: str) -> None:
        super().__init__("network_clients_guests", name)
        self.requested = copy.deepcopy(type(self).requested)

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        client.put.return_value = PREVIEW if dry_run else (write or WRITE_RESPONSE)
        monkeypatch.setattr(
            network_clients_guests,
            "resolve_site_slug",
            AsyncMock(return_value=(None, "synthetic-host", "default")),
        )
        before_record = {"_id": "65f1c0ffee0123456789abcd", **before}
        if isinstance(after, BaseException):
            second: Any = after
        elif isinstance(after, dict):
            second = {"_id": "65f1c0ffee0123456789abcd", **after}
        else:
            second = after
        monkeypatch.setattr(
            network_clients_guests,
            "require_listed_record",
            AsyncMock(side_effect=[before_record, second]),
        )
        result = await getattr(network_clients_guests, self.name)(
            client, None, "h", "default", "65f1c0ffee0123456789abcd", self.requested
        )
        return result, client.put

    def verdict(self, result):
        return result.get("_verified")

    def error(self, result):
        return result.get("_readAfterError")

    def is_noop(self, result):
        return False

    def response(self, result):
        return {k: v for k, v in result.items() if not k.startswith("_")}


class DigitalTwinLayoutCase(Case):
    """update_digital_twin_layout: read, merge the requested leaves, PUT, read back."""

    def __init__(self) -> None:
        super().__init__("network_proav_sandbox", "update_digital_twin_layout")
        self.requested = {
            "name": "synthetic requested",
            "settings": {"enabled": True, "level": 3},
        }
        self.bool_field = "settings.enabled"
        self.has_noop = False

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        client.put.return_value = PREVIEW if dry_run else (write or dict(WRITE_RESPONSE))
        reads: list[Any] = [copy.deepcopy(before)]
        reads.append(after if isinstance(after, BaseException) else copy.deepcopy(after))
        client.get = AsyncMock(side_effect=reads)
        result = await network_proav_sandbox.update_digital_twin_layout(
            client, _registry(), "h", "default", copy.deepcopy(self.requested)
        )
        return result, client.put

    def verdict(self, result):
        return result["_verified"]

    def error(self, result):
        return result.get("_readAfterError")

    def response(self, result):
        return {key: value for key, value in result.items() if not key.startswith("_")}


class AdminCase(Case):
    """N01 Classic admin write: read GET api/self, write, read back."""

    def __init__(self, name: str) -> None:
        super().__init__("network_controller_admin", name)
        self.requested = {"name": "synthetic requested", "settings": {"enabled": True, "level": 3}}
        self.bool_field = "settings.enabled"
        self.has_noop = False

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        response = PREVIEW if dry_run else (write or dict(WRITE_RESPONSE))
        client = _client(dry_run)
        client.put.return_value = response
        reads: list[Any] = [{"data": [{"_id": ADMIN_HEX, **before}]}]
        if isinstance(after, dict):
            reads.append({"data": [{"_id": ADMIN_HEX, **after}]})
        else:
            reads.append(after)
        client.get = AsyncMock(side_effect=reads)
        registry = _registry()
        result = await network_controller_admin.update_my_admin_profile(
            client, registry, "h", copy.deepcopy(self.requested)
        )
        return result, client.put

    def verdict(self, result):
        return result["_verified"]

    def error(self, result):
        return result.get("_readAfterError")

    def response(self, result):
        return {key: value for key, value in result.items() if not key.startswith("_")}


class PtzDoorbellCase(Case):
    """GS3 P02: PTZ slots verified through the camera's slot list; a shortcut through the
    camera object's shortcuts array, located by the body's id."""

    def __init__(self, name: str) -> None:
        super().__init__("protect_ptz_doorbell", name)
        self.requested = copy.deepcopy(ProtectCase.requested_wanted)
        if name == "update_camera_shortcut":
            self.requested = {"id": SID, **self.requested}
        self.bool_field = "settings.enabled"

    def _wrap(self, record: dict[str, Any]) -> Any:
        if self.name == "update_camera_shortcut":
            return {"id": PID, "shortcuts": [record]}
        return [{"slot": 0, **record}]

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        mod = protect_ptz_doorbell
        monkeypatch.setattr(mod, "_resolve", AsyncMock(return_value=(None, "synthetic-host")))
        monkeypatch.setattr(mod, "_require_mutations", lambda: None)
        client.patch.return_value = PREVIEW if dry_run else (write or WRITE_RESPONSE)
        if self.name == "update_camera_shortcut":
            before = {"id": SID, **before}
        after_body = self._wrap(after) if isinstance(after, dict) else after
        reads: list[Any] = [self._wrap(before)]
        reads.append(after_body)
        client.get.side_effect = reads
        fields = copy.deepcopy(self.requested)
        if self.name == "update_camera_shortcut":
            result = await mod.update_camera_shortcut(client, None, "h", PID, fields)
        else:
            result = await getattr(mod, self.name)(client, None, "h", PID, 0, fields)
        return result, client.patch


class InnerSpacePlanCase(Case):
    """``update_innerspace_plan``: read-merge-write of one plan of the project document."""

    def __init__(self) -> None:
        super().__init__("innerspace_internal", "update_innerspace_plan")
        self.requested = {"title": "synthetic requested", "settings": {"enabled": True}}
        self.bool_field = "settings.enabled"

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        client.patch.return_value = PREVIEW if dry_run else (write or dict(WRITE_RESPONSE))
        registry = AsyncMock()
        registry.resolve_key_for_host.return_value = None
        registry.resolve_host_id.return_value = "synthetic-host"
        reads: list[Any] = [{"data": {"plans": [{"id": PID, **before}]}}]
        if isinstance(after, BaseException):
            reads.append(after)
        elif isinstance(after, dict):
            reads.append({"data": {"plans": [{"id": PID, **after}]}})
        else:
            reads.append(after)
        monkeypatch.setattr(innerspace, "get_innerspace_project", AsyncMock(side_effect=reads))
        result = await innerspace_internal.update_innerspace_plan(
            client, registry, "h", PID, copy.deepcopy(self.requested)
        )
        return result, client.patch

    def verdict(self, result):
        return result["_verified"]

    def error(self, result):
        return result.get("_readAfterError")

    def is_noop(self, result):
        return result.get("_noOp") is True

    def response(self, result):
        return {k: v for k, v in result.items() if not k.startswith("_")}


class RecognitionGroupCase(Case):
    """update_recognition_group: the group re-read from the recognition group list."""

    bool_field = "settings.enabled"
    requested = {"name": "synthetic requested", "settings": {"enabled": True, "level": 3}}

    def __init__(self) -> None:
        super().__init__("protect_recognition_search", "_update_recognition_group")

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        module = protect_recognition_search
        monkeypatch.setattr(module, "_resolve", AsyncMock(return_value=(None, "h")))
        before = {"id": "face_1", **before}  # the listed group, matched by its id
        monkeypatch.setattr(module, "_find_group", AsyncMock(side_effect=[before, after]))
        client.patch.return_value = PREVIEW if dry_run else (write or WRITE_RESPONSE)
        result = await module._update_recognition_group(
            client, None, "h", "face", "face_1", copy.deepcopy(self.requested)
        )
        return result, client.patch

    def verdict(self, result):
        return result["_verified"]

    def error(self, result):
        return result.get("_readAfterError")

    def response(self, result):
        return {k: v for k, v in result.items() if not k.startswith("_")}


class LifecycleCase(Case):
    """update_protect_device_settings (GS3 P01): the official route reuses
    protect._update_item_verified; the private route verifies through its own reader."""

    def __init__(self, route: str) -> None:
        super().__init__("protect_device_lifecycle", f"update_protect_device_settings[{route}]")
        self.route = route
        self.requested = copy.deepcopy(ProtectCase.requested_wanted)
        self.bool_field = "settings.enabled"

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        from unifi_fabric.tools import protect_device_lifecycle as pdl

        client = _client(dry_run)
        resolved = AsyncMock(return_value=(None, "synthetic-host"))
        monkeypatch.setattr(pdl, "_resolve", resolved)
        monkeypatch.setattr(protect, "_resolve", resolved)
        response = PREVIEW if dry_run else (write or WRITE_RESPONSE)
        if self.route == "official":
            writer = AsyncMock(return_value=response)
            monkeypatch.setattr(protect, "_patch", writer)
            device_type = "camera"
        else:
            client.patch.return_value = response
            writer = client.patch
            device_type = "doorlock"
        client.get.side_effect = [before, after]
        fields = copy.deepcopy(self.requested)
        result = await pdl.update_protect_device_settings(
            client, None, "h", device_type, fields, device_id=SID
        )
        return result, writer


class RoutingTopologyCase(Case):
    HEX_ID = "0000000000000000000000a1"

    def __init__(self, name: str) -> None:
        super().__init__("network_routing_topology", name)
        self.requested = {
            "name": "synthetic requested",
            "settings": {"enabled": True, "level": 3},
        }
        self.bool_field = "settings.enabled"
        self.has_noop = False

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        written = PREVIEW if dry_run else (write or dict(WRITE_RESPONSE))
        client.put.return_value = written
        client.post.return_value = written
        registry = _registry()
        singleton = self.name == "update_global_network_config"

        def wrap(record: dict[str, Any]) -> Any:
            return dict(record) if singleton else [{"_id": self.HEX_ID, **record}]

        reads: list[Any] = [wrap(before)]
        if self.name == "update_bgp_config":
            reads.append(wrap(before))  # gateway singleton route discovery
        reads.append(wrap(after) if isinstance(after, dict) else after)
        client.get = AsyncMock(side_effect=reads)
        events: list[tuple[str, str]] = []
        if self.name == "update_bgp_config":
            root = network_routing_topology.v2_site("aabbccddeeff0000:1", "default", "")
            read_paths = [root + "/bgp/config/all", root + "/bgp/config", root + "/bgp/config/all"]

            async def bgp_read(path, **kwargs):
                assert path == read_paths[len([event for event in events if event[0] == "GET"])]
                events.append(("GET", path))
                response = reads.pop(0)
                if isinstance(response, BaseException):
                    raise response
                return response

            async def bgp_write(path, **kwargs):
                assert path == root + "/bgp/config"
                events.append(("POST", path))
                return written

            client.get = AsyncMock(side_effect=bgp_read)
            client.post = AsyncMock(side_effect=bgp_write)
        requested = copy.deepcopy(self.requested)
        module = network_routing_topology
        if singleton:
            result = await module.update_global_network_config(
                client, registry, "h", "default", requested
            )
        elif self.name == "manage_mclag_group":
            result = await module.manage_mclag_group(
                client, registry, "h", "default", "update", self.HEX_ID, requested
            )
        else:
            result = await getattr(module, self.name)(
                client, registry, "h", "default", self.HEX_ID, requested
            )
        writer = client.post if self.name == "update_bgp_config" else client.put
        if self.name == "update_bgp_config":
            expected = [("GET", read_paths[0]), ("GET", read_paths[1]), ("POST", read_paths[1])]
            if not dry_run:
                expected.append(("GET", read_paths[2]))
            assert events == expected
        return result, writer

    def verdict(self, result):
        return result["_verified"]

    def error(self, result):
        return result.get("_readAfterError")

    def response(self, result):
        return {key: value for key, value in result.items() if not key.startswith("_")}


class MobileWanCase(Case):
    """network_mobile_wan v2 read-merge-write updates: ``_verified`` additive on the body."""

    requested_wanted = {"name": "synthetic requested", "nested": {"enabled": True, "level": 3}}
    bool_field = "nested.enabled"
    has_noop = False  # the v2 update always writes; only verification is derived
    SLA = "65f1c0ffee0123456789abcd"

    def __init__(self, name: str) -> None:
        super().__init__("network_mobile_wan", name)
        self.requested = copy.deepcopy(self.requested_wanted)

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        client.put.return_value = PREVIEW if dry_run else (write or dict(WRITE_RESPONSE))
        monkeypatch.setattr(
            network_mobile_wan,
            "resolve_site_slug",
            AsyncMock(return_value=(None, "synthetic-host", "default")),
        )
        fields = copy.deepcopy(self.requested_wanted)
        if self.name == "update_wan_sla":
            post: Any = [{"_id": self.SLA, **after}] if isinstance(after, dict) else after
            client.get.side_effect = [[{"_id": self.SLA, **before}], post]
            result = await network_mobile_wan.update_wan_sla(
                client, None, "h", "default", self.SLA, fields
            )
        else:
            client.get.side_effect = [before, after]
            result = await network_mobile_wan.update_wan_load_balancing(
                client, None, "h", "default", fields
            )
        return result, client.put

    def verdict(self, result):
        return result["_verified"]

    def error(self, result):
        return result.get("_readAfterError")

    def is_noop(self, result):
        return False

    def response(self, result):
        return {k: v for k, v in result.items() if not k.startswith("_")}


class DpiPolicyCase(Case):
    """network_dpi_policy read-merge-write PUTs: ``_verified`` additive on the write body.

    The policy-engine rule and the network member group are read from their private v2
    collection; the predefined firewall policy from its Integration object route."""

    requested_wanted = {"name": "synthetic requested", "settings": {"enabled": True, "level": 3}}
    bool_field = "settings.enabled"
    has_noop = False  # the PUT is always sent; only verification is derived

    def __init__(self, name: str) -> None:
        super().__init__("network_dpi_policy", name)
        self.requested = copy.deepcopy(self.requested_wanted)

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        client.put.return_value = PREVIEW if dry_run else (write or dict(WRITE_RESPONSE))
        monkeypatch.setattr(
            network_dpi_policy,
            "resolve_site_slug",
            AsyncMock(return_value=(None, "synthetic-host", "default")),
        )
        fields = copy.deepcopy(self.requested_wanted)
        if self.name == "update_predefined_firewall_policy":
            post: Any = {"data": {"id": SID, **after}} if isinstance(after, dict) else after
            client.get.side_effect = [{"data": {"id": SID, **before}}, post]
            result = await network_dpi_policy.update_predefined_firewall_policy(
                client, _registry(), "h", "default", SID, fields
            )
        else:
            post = [{"id": SID, **after}] if isinstance(after, dict) else after
            client.get.side_effect = [[{"id": SID, **before}], post]
            result = await getattr(network_dpi_policy, self.name)(
                client, None, "h", "default", SID, fields
            )
        return result, client.put

    def verdict(self, result):
        return result["_verified"]

    def error(self, result):
        return result.get("_readAfterError")

    def is_noop(self, result):
        return False

    def response(self, result):
        return {k: v for k, v in result.items() if not k.startswith("_")}


class EventsCasesCase(Case):
    """protect_events_cases: the case and case-asset PATCHes verified through their
    collection, and the single-event favorite verified by the event read back."""

    def __init__(self, name: str) -> None:
        super().__init__("protect_events_cases", name)
        if name == "set_protect_event_favorite":
            self.requested = {"isFavorite": True}
            self.bool_field = "isFavorite"
            self.has_noop = False  # no read-before: the mark is always sent
        else:
            self.requested = copy.deepcopy(ProtectCase.requested_wanted)
            self.bool_field = "settings.enabled"

    async def run(self, monkeypatch, before, after, *, dry_run=False, write=None):
        client = _client(dry_run)
        written = PREVIEW if dry_run else (write or WRITE_RESPONSE)
        client.patch.return_value = written
        client.post.return_value = written
        monkeypatch.setattr(
            protect_events_cases, "_resolve", AsyncMock(return_value=(None, "synthetic-host"))
        )
        monkeypatch.setattr(protect_events_cases, "_require_mutations", lambda: None)
        if self.name == "set_protect_event_favorite":
            client.get.side_effect = [{"id": SID, **after} if isinstance(after, dict) else after]
            result = await protect_events_cases.set_protect_event_favorite(
                client, None, "h", SID, True
            )
            return result, client.post
        post: Any = [{"id": PID, **after}] if isinstance(after, dict) else after
        collection_reads = AsyncMock(side_effect=[[{"id": PID, **before}], post])
        fields = copy.deepcopy(ProtectCase.requested_wanted)
        if self.name == "update_protect_case":
            client.get.side_effect = collection_reads
            result = await protect_events_cases.update_protect_case(
                client, None, "h", PID, fields=fields
            )
        else:
            cases_path = "/v1/connector/consoles/synthetic-host/proxy/protect/api/cases"

            async def read_asset_route(path, **kwargs):
                # Parent resolution is independent of the asset before/after reads.
                if path == cases_path:
                    return [{"id": SID}]
                assert path == f"{cases_path}/{SID}/assets"
                return await collection_reads()

            client.get.side_effect = read_asset_route
            result = await protect_events_cases.update_protect_case_asset(
                client, None, "h", SID, PID, fields=fields
            )
        return result, client.patch


CASES: list[Case] = [
    *(AssetsCase(n) for n in ASSETS_VERIFIED),
    ProtectAutomationCase(),
    RecognitionGroupCase(),
    *(ProtectCase(n) for n in PROTECT_VERIFIED),
    LifecycleCase("official"),
    LifecycleCase("private"),
    *(MobilityCase(n) for n in MOBILITY_VERIFIED),
    *(CarrierCase(n) for n in CARRIER_VERIFIED),
    *(ClassicRecordCase(n) for n in NETWORK_CLIENTS_GUESTS_VERIFIED),
    *(SwitchingPowerCase(n) for n in SWITCHING_POWER_VERIFIED),
    *(SecurityCase(n) for n in SECURITY_VERIFIED),
    *(NcCase(n) for n in NC_VERIFIED),
    TrafficRuleCase(),
    *(VpnDnsCase(n) for n in VPN_DNS_VERIFIED),
    DigitalTwinLayoutCase(),
    *(PtzDoorbellCase(n) for n in PTZ_DOORBELL_VERIFIED),
    *(RoutingTopologyCase(n) for n in ROUTING_TOPOLOGY_VERIFIED),
    SettingCase(),
    *(AdminCase(n) for n in ADMIN_VERIFIED),
    InnerSpacePlanCase(),
    *(MobileWanCase(n) for n in MOBILE_WAN_VERIFIED),
    *(DpiPolicyCase(n) for n in DPI_POLICY_VERIFIED),
    *(EventsCasesCase(n) for n in EVENTS_CASES_VERIFIED),
]


def _stale(case: Case) -> dict[str, Any]:
    """A read-before that differs from the request in every requested leaf."""
    if isinstance(case, PtzDoorbellCase):
        return {"name": "synthetic old", "settings": {"enabled": False, "level": 1}}
    if isinstance(case, ProtectCase) and case.name != "update_arm_profile_settings":
        return {"name": "old", "settings": {"enabled": False, "level": 1}}
    if isinstance(case, LifecycleCase):
        return {"name": "synthetic old", "settings": {"enabled": False, "level": 1}}
    if isinstance(case, ProtectCase):
        return {"armProfileId": PID}
    if isinstance(case, MobilityCase):
        return {"name": "old", "host_address": "192.0.2.99", "wifi_ssid": "old"}
    if isinstance(case, ClassicRecordCase):
        return {"name": "synthetic old", "nested": {"enabled": False, "level": 1}}
    if isinstance(case, SwitchingPowerCase):
        return {"name": "old", "settings": {"enabled": False, "level": 1}}
    if isinstance(case, SecurityCase):
        return {"name": "old", "settings": {"enabled": False, "level": 1}}
    if isinstance(case, NcCase):
        return {"name": "old", "settings": {"enabled": False, "level": 1}}
    if isinstance(case, VpnDnsCase):
        return {"name": "old", "settings": {"enabled": False, "level": 1}}
    if isinstance(case, DigitalTwinLayoutCase):
        return {"name": "old", "settings": {"enabled": False, "level": 1}}
    if isinstance(case, RoutingTopologyCase):
        return {"name": "old", "settings": {"enabled": False, "level": 1}}
    if isinstance(case, MobileWanCase):
        return {"name": "synthetic old", "nested": {"enabled": False, "level": 1}}
    if isinstance(case, EventsCasesCase) and case.name == "set_protect_event_favorite":
        return {"isFavorite": False}
    if isinstance(case, DpiPolicyCase | EventsCasesCase):
        return {"name": "synthetic old", "settings": {"enabled": False, "level": 1}}
    if isinstance(case, CarrierCase):
        stale = {
            "name": "old",
            "notes": "old",
            "hostId": "synthetic-old-host",
            "planId": SID,
            "suspended": case.name != "suspend_carrier_subscriber",
        }
        return stale
    if isinstance(case, InnerSpacePlanCase):
        return {"title": "synthetic old", "settings": {"enabled": False}}
    return {"enabled": False, "mode": "old"}


def _applied(case: Case) -> dict[str, Any]:
    return copy.deepcopy(case.requested)


def _set_leaf(record: dict[str, Any], dotted: str, value: Any) -> dict[str, Any]:
    out = copy.deepcopy(record)
    *parents, leaf = dotted.split(".")
    target = out
    for part in parents:
        target = target[part]
    target[leaf] = value
    return out


def _drop_leaf(record: dict[str, Any], dotted: str) -> dict[str, Any]:
    out = copy.deepcopy(record)
    *parents, leaf = dotted.split(".")
    target = out
    for part in parents:
        target = target[part]
    del target[leaf]
    return out


def _leaves(record: dict[str, Any], prefix: str = "") -> list[str]:
    out: list[str] = []
    for key, value in record.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict) and value:
            out.extend(_leaves(value, path + "."))
        else:
            out.append(path)
    return out


# --------------------------------------------------------------------------- properties


@pytest.mark.parametrize("case", CASES, ids=repr)
async def test_full_read_after_match_verifies(monkeypatch, case):
    result, _ = await case.run(monkeypatch, _stale(case), _applied(case))
    assert case.verdict(result) is True
    assert case.error(result) is None


@pytest.mark.parametrize("case", CASES, ids=repr)
@pytest.mark.parametrize(
    "failure",
    [
        UniFiConnectionError("synthetic read-after failure"),
        RuntimeError("synthetic unexpected error"),
    ],
    ids=["transport", "unexpected"],
)
async def test_read_after_failure_is_unknown_with_reason(monkeypatch, case, failure):
    result, writer = await case.run(monkeypatch, _stale(case), failure)
    writer.assert_awaited_once()
    assert case.verdict(result) is None
    assert "synthetic" in str(case.error(result))
    if not isinstance(case, CarrierCase):
        assert case.response(result) == WRITE_RESPONSE


@pytest.mark.parametrize("case", CASES, ids=repr)
@pytest.mark.parametrize("shape", [["synthetic"], "synthetic text"], ids=["list", "text"])
async def test_read_after_shape_mismatch_is_unknown_with_reason(monkeypatch, case, shape):
    result, _ = await case.run(monkeypatch, _stale(case), shape)
    assert case.verdict(result) is None
    assert case.error(result)


@pytest.mark.parametrize("case", [c for c in CASES if isinstance(c, AssetsCase)], ids=repr)
@pytest.mark.parametrize(
    "ack",
    [None, [], ["synthetic ack"], "", "synthetic ack", False, 0, 7],
    ids=["null", "empty-list", "list", "empty-text", "text", "false", "zero", "scalar"],
)
@pytest.mark.parametrize("outcome", ["verified", "unapplied", "read-error"])
async def test_protect_assets_preserve_non_object_ack_and_verdict(monkeypatch, case, ack, outcome):
    before = _stale(case)
    if outcome == "verified":
        after = _applied(case)
        expected = True
    elif outcome == "unapplied":
        after = _stale(case)
        expected = False
    else:
        after = UniFiConnectionError("synthetic read-after unavailable")
        expected = None

    result, writer = await case.run(monkeypatch, before, after, write=ack)

    writer.assert_awaited_once()
    assert result["response"] == ack
    assert case.verdict(result) is expected
    if outcome == "read-error":
        assert "synthetic read-after unavailable" in str(case.error(result))
    else:
        assert case.error(result) is None


@pytest.mark.parametrize("case", CASES, ids=repr)
async def test_every_missing_leaf_is_never_verified(monkeypatch, case):
    leaves = _leaves(case.requested)
    assert leaves, case
    for leaf in leaves:
        if isinstance(case, CarrierCase) and case.requested.get(leaf, 0) is None:
            continue  # an omitted nullable field is the documented cleared state
        after = _drop_leaf(_applied(case), leaf)
        result, _ = await case.run(monkeypatch, _stale(case), after)
        assert case.verdict(result) is not True, leaf


@pytest.mark.parametrize("case", CASES, ids=repr)
async def test_every_different_leaf_is_never_verified(monkeypatch, case):
    leaves = _leaves(case.requested)
    assert leaves, case
    for leaf in leaves:
        after = _set_leaf(_applied(case), leaf, "synthetic-unapplied")
        result, _ = await case.run(monkeypatch, _stale(case), after)
        assert case.verdict(result) is not True, leaf


@pytest.mark.parametrize("case", [c for c in CASES if c.bool_field], ids=repr)
async def test_int_over_bool_is_never_verified(monkeypatch, case):
    wanted = _leaf_value(case.requested, case.bool_field)
    after = _set_leaf(_applied(case), case.bool_field, int(wanted))
    result, _ = await case.run(monkeypatch, _stale(case), after)
    assert case.verdict(result) is not True


def _leaf_value(record: dict[str, Any], dotted: str) -> Any:
    value: Any = record
    for part in dotted.split("."):
        value = value[part]
    return value


@pytest.mark.parametrize("case", CASES, ids=repr)
async def test_unrequested_sibling_change_still_verifies(monkeypatch, case):
    after = {**_applied(case), "syntheticSibling": "changed-by-the-server"}
    result, _ = await case.run(monkeypatch, _stale(case), after)
    assert case.verdict(result) is True


@pytest.mark.parametrize("case", [c for c in CASES if c.has_noop], ids=repr)
async def test_noop_compares_requested_leaves_only(monkeypatch, case):
    """Already applied in every requested leaf, a differing sibling: a no-op, no write."""
    before = {**_applied(case), "syntheticSibling": "different"}
    result, writer = await case.run(monkeypatch, before, AssertionError("no read-after"))
    assert case.is_noop(result)
    writer.assert_not_awaited()


@pytest.mark.parametrize("case", CASES, ids=repr)
async def test_noop_is_false_when_a_requested_leaf_differs(monkeypatch, case):
    result, writer = await case.run(monkeypatch, _stale(case), _applied(case))
    assert not case.is_noop(result)
    writer.assert_awaited_once()


@pytest.mark.parametrize("case", CASES, ids=repr)
async def test_dry_run_never_verifies(monkeypatch, case):
    result, _ = await case.run(
        monkeypatch, _stale(case), AssertionError("no read-after"), dry_run=True
    )
    assert result.get("status") == "dry_run"
    assert result.get("verified") is not True
    assert result.get("_verified") is not True


# ---------------------------------------------------------------- routing delete read-after


@pytest.mark.parametrize("name", ROUTING_TOPOLOGY_DELETES)
@pytest.mark.parametrize(
    "outcome", ["absent", "present", "transport", "unexpected", "shape", "dry-run"]
)
@pytest.mark.parametrize("ack", [None, {"synthetic": "upstream response"}], ids=["empty", "object"])
async def test_routing_delete_read_after_matrix(name, outcome, ack):
    client = _client(dry_run=outcome == "dry-run")
    root = network_routing_topology.v2_site("aabbccddeeff0000:1", "default", "")
    is_bgp = name == "delete_bgp_config"
    collection = root + ("/bgp/config/all" if is_bgp else "/ospf/router")
    route = root + ("/bgp/config" if is_bgp else f"/ospf/router/{HEX_ID}")
    record = {"_id": HEX_ID, "name": "synthetic"}
    sibling = {"_id": "0000000000000000000000a2", "name": "other"}
    after = {
        "absent": [sibling],
        "present": [record, sibling],
        "transport": UniFiConnectionError("synthetic read-after failure"),
        "unexpected": RuntimeError("synthetic unexpected failure"),
        "shape": "synthetic invalid shape",
        "dry-run": AssertionError("dry-run must not read after"),
    }[outcome]
    reads = [[record, sibling]] + ([[record]] if is_bgp else []) + [after]
    events = []

    async def read(path, **kwargs):
        events.append(("GET", path))
        response = reads.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    async def delete(path, **kwargs):
        events.append(("DELETE", path))
        return PREVIEW if outcome == "dry-run" else ack

    client.get.side_effect = read
    client.delete.side_effect = delete
    result = await getattr(network_routing_topology, name)(
        client, _registry(), "h", "default", HEX_ID
    )
    expected = [("GET", collection)] + ([("GET", route)] if is_bgp else []) + [("DELETE", route)]
    if outcome != "dry-run":
        expected.append(("GET", collection))
    assert events == expected
    client.delete.assert_awaited_once()
    assert result["response"] == (PREVIEW if outcome == "dry-run" else ack)
    assert (
        result["deleted"]
        is {
            "absent": True,
            "present": False,
            "transport": None,
            "unexpected": None,
            "shape": None,
            "dry-run": False,
        }[outcome]
    )
    if outcome in {"transport", "unexpected", "shape"}:
        assert result["readAfterError"]
    else:
        assert "readAfterError" not in result
    if outcome == "present":
        assert "still listed" in result["message"]
    if outcome == "dry-run":
        assert result["status"] == "dry_run"


@pytest.mark.parametrize("name", ROUTING_TOPOLOGY_DELETES)
async def test_routing_delete_unknown_id_never_writes(name):
    client = _client()
    client.get.return_value = [{"_id": "0000000000000000000000a2"}]
    with pytest.raises(ValueError, match="not found"):
        await getattr(network_routing_topology, name)(client, _registry(), "h", "default", HEX_ID)
    client.delete.assert_not_awaited()


@pytest.mark.parametrize("qualified_name", sorted(BATCH_DELETES))
@pytest.mark.parametrize(
    "outcome", ["absent", "present", "transport", "unexpected", "shape", "missing-id", "dry-run"]
)
@pytest.mark.parametrize("ack", [None, {"synthetic": "upstream response"}], ids=["empty", "object"])
async def test_batch_delete_read_after_matrix(monkeypatch, qualified_name, outcome, ack):
    client = _client(dry_run=outcome == "dry-run")
    is_qos = qualified_name.endswith("delete_qos_rule")
    root = network_nat_qos_traffic.v2_site("aabbccddeeff0000:1", "default", "")
    collection = root + ("/qos-rules" if is_qos else f"/wireguard/{HEX_ID}/users")
    route = collection + ("/batch-delete" if is_qos else "/batch_delete")
    record = {"_id": HEX_ID, "name": "synthetic"}
    sibling = {"_id": "0000000000000000000000a2", "name": "other"}
    after = {
        "absent": [sibling],
        "present": [record, sibling],
        "transport": UniFiConnectionError("synthetic read-after failure"),
        "unexpected": RuntimeError("synthetic unexpected failure"),
        "shape": "synthetic invalid shape",
        "missing-id": [{"name": "unknown identity"}],
        "dry-run": AssertionError("dry-run must not read after"),
    }[outcome]
    reads = [[record, sibling], after]
    events = []
    payload = [HEX_ID]
    preview = {
        **PREVIEW,
        "preview": {"method": "POST", "path": route, "params": None, "body": payload},
    }

    async def read(path, **kwargs):
        events.append(("GET", path))
        response = reads.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    async def post(path, **kwargs):
        events.append(("POST", path))
        assert kwargs["json"] == payload
        return preview if outcome == "dry-run" else ack

    client.get.side_effect = read
    client.post.side_effect = post
    if is_qos:
        monkeypatch.setattr(
            network_nat_qos_traffic,
            "_nc_site",
            AsyncMock(return_value=(None, "aabbccddeeff0000:1", "default")),
        )
        result = await network_nat_qos_traffic.delete_qos_rule(
            client, _registry(), "h", "default", payload
        )
    else:
        monkeypatch.setattr(
            network_vpn_dns,
            "_vpn_server",
            AsyncMock(return_value=(None, "aabbccddeeff0000:1", "default", HEX_ID)),
        )
        result = await network_vpn_dns.delete_wireguard_users(
            client, _registry(), "h", "default", HEX_ID, payload
        )
    expected = [("GET", collection), ("POST", route)]
    if outcome != "dry-run":
        expected.append(("GET", collection))
    assert events == expected
    client.post.assert_awaited_once()
    assert result["response"] is (preview if outcome == "dry-run" else ack)
    assert result["deleted"] is (outcome == "absent")
    if outcome in {"transport", "unexpected", "shape", "missing-id"}:
        assert result["readAfterError"]
    else:
        assert "readAfterError" not in result
    if outcome == "present":
        assert "remain listed" in result["message"]
    if outcome == "dry-run":
        assert result["status"] == "dry_run"


# --------------------------------------------------------------------------- relay


class _Resp:
    def __init__(self, status: int, body: Any = None, *, content: bytes | None = None) -> None:
        import json

        self.status_code = status
        self._json = body
        if content is not None:
            self.content = content
            self.text = ""
            self.headers = {"content-type": "application/octet-stream"}
        else:
            self.text = json.dumps(body) if body is not None else ""
            self.content = self.text.encode()
            self.headers = {"content-type": "application/json"} if body is not None else {}

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("no json")
        return self._json


def _registry() -> AsyncMock:
    registry = AsyncMock()
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="aabbccddeeff0000:1")
    registry.resolve_site_id = AsyncMock(return_value=SID)
    registry.resolve_site_slug = AsyncMock(return_value="default")
    return registry


RELAY_PATH = "network/integration/v1/sites/{site_id}/firewall/policies/x"


async def _relay(method: str, responses: list[Any], body: Any = None) -> dict[str, Any]:
    client = MagicMock()
    client.dry_run = False
    client.request = AsyncMock(side_effect=responses)
    return await connector.connector_write(
        client, _registry(), "h", method, RELAY_PATH, site="default", body=body
    )


@pytest.mark.parametrize("method", ["PUT", "PATCH"])
async def test_relay_noop_ignores_unrequested_sibling(method):
    before = {"enabled": True, "name": "x", "updatedAt": 1}
    after = {"enabled": True, "name": "x", "updatedAt": 2}
    result = await _relay(
        method, [_Resp(200, before), _Resp(200, {}), _Resp(200, after)], {"enabled": True}
    )
    assert result["noOp"] is True and result["changed"] is False


@pytest.mark.parametrize("method", ["PUT", "PATCH"])
@pytest.mark.parametrize(
    "before,after",
    [
        ({"enabled": 1}, {"enabled": True}),  # bool over int is a change
        ({"cfg": {"a": 1}}, {"cfg": {"a": 2}}),  # nested requested leaf
        ({}, {"enabled": True}),  # a requested leaf appeared
    ],
)
async def test_relay_requested_leaf_change_is_changed(method, before, after):
    body = {"enabled": True} if "enabled" in after else {"cfg": {"a": 2}}
    result = await _relay(method, [_Resp(200, before), _Resp(200, {}), _Resp(200, after)], body)
    assert result["noOp"] is False and result["changed"] is True


@pytest.mark.parametrize("method", ["PUT", "PATCH"])
async def test_relay_nested_sibling_change_is_not_a_change(method):
    before = {"cfg": {"a": 1, "counter": 1}}
    after = {"cfg": {"a": 1, "counter": 2}}
    result = await _relay(
        method, [_Resp(200, before), _Resp(200, {}), _Resp(200, after)], {"cfg": {"a": 1}}
    )
    assert result["noOp"] is True


@pytest.mark.parametrize("method", ["PUT", "PATCH"])
async def test_relay_classic_envelope_resolves_the_record(method):
    before = {"meta": {"rc": "ok"}, "data": [{"_id": "x", "name": "a", "ts": 1}]}
    after = {"meta": {"rc": "ok"}, "data": [{"_id": "x", "name": "a", "ts": 2}]}
    result = await _relay(
        method, [_Resp(200, before), _Resp(200, {}), _Resp(200, after)], {"name": "a"}
    )
    assert result["noOp"] is True


@pytest.mark.parametrize("method", ["PUT", "PATCH"])
@pytest.mark.parametrize(
    "after",
    [
        UniFiConnectionError("synthetic read-after failure"),
        _Resp(500, {"error": "synthetic"}),
        _Resp(200, ["synthetic", "list"]),
        _Resp(200, content=b"\x00\x01"),
        _Resp(200, {"other": 1}),  # the requested leaf is unobservable in both reads
    ],
    ids=["raises", "http-500", "list", "binary", "unobservable"],
)
async def test_relay_unusable_read_after_is_unknown_with_reason(method, after):
    result = await _relay(
        method, [_Resp(200, {"other": 1}), _Resp(200, WRITE_RESPONSE), after], {"enabled": True}
    )
    assert result["noOp"] is None
    assert "changed" not in result
    assert result.get("readAfterError") or result.get("noOpReason")
    assert result["body"] == WRITE_RESPONSE  # the write response stays verbatim


async def test_relay_delete_is_changed_only_on_404():
    gone = await _relay("DELETE", [_Resp(200, {"id": "x"}), _Resp(204), _Resp(404, {})])
    assert gone["noOp"] is False and gone["changed"] is True
    assert "readAfterError" not in gone


@pytest.mark.parametrize(
    "after",
    [_Resp(200, {"id": "x"}), _Resp(200, {"id": "x", "state": "deleting"})],
    ids=["identical", "changed"],
)
async def test_relay_delete_still_readable_is_unknown(after):
    result = await _relay("DELETE", [_Resp(200, {"id": "x"}), _Resp(204), after])
    assert result["noOp"] is None
    assert "changed" not in result
    assert "deletion not confirmed" in result["noOpReason"]


@pytest.mark.parametrize(
    "after",
    [UniFiConnectionError("synthetic read-after failure"), _Resp(500, {"error": "synthetic"})],
    ids=["raises", "http-500"],
)
async def test_relay_delete_failed_read_after_is_unknown(after):
    result = await _relay("DELETE", [_Resp(200, {"id": "x"}), _Resp(204), after])
    assert result["noOp"] is None
    assert result["readAfterError"]


async def test_relay_dry_run_never_reports_a_verdict():
    client = MagicMock()
    client.dry_run = True
    client.request = AsyncMock(side_effect=[_Resp(200, {"a": 1}), _Resp(200, PREVIEW)])
    result = await connector.connector_write(
        client, _registry(), "h", "PATCH", RELAY_PATH, site="default", body={"a": 2}
    )
    assert result["status"] == "dry_run"
    assert result["noOp"] is None and "changed" not in result


DEVICE_PATH = "network/api/s/{site}/rest/device/aabbccddeeff00112233aabb"


async def _device(responses: list[Any], body: dict[str, Any]) -> dict[str, Any]:
    client = MagicMock()
    client.dry_run = False
    client.request = AsyncMock(side_effect=responses)
    return await connector.connector_write(
        client, _registry(), "h", "PUT", DEVICE_PATH, site="default", body=body, scope="device"
    )


def _twin(**record: Any) -> _Resp:
    return _Resp(
        200, {"meta": {"rc": "ok"}, "data": [{"_id": "aabbccddeeff00112233aabb", **record}]}
    )


async def test_device_twin_noop_ignores_live_and_nested_siblings():
    result = await _device(
        [
            _twin(cfg={"a": 1, "x": 1}, uptime=1),
            _Resp(200, {}),
            _twin(cfg={"a": 1, "x": 2}, uptime=2),
        ],
        {"cfg": {"a": 1}},
    )
    assert result["noOp"] is True


async def test_device_twin_bool_over_int_is_a_change():
    result = await _device([_twin(flag=1), _Resp(200, {}), _twin(flag=True)], {"flag": True})
    assert result["noOp"] is False
