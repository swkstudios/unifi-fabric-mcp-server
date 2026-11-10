"""Placement snapshot withholding is opt-in, like every credential mask on this server.

* Default (``UNIFI_REDACT_SECRETS`` off): every projected string is an upstream string
  verbatim, the address / floor-plan asset-URL fields are additive v1 keys, and no value
  is withheld (``_withheld`` is never present; records schema v1 cannot represent are
  counted, in either mode, under the separate ``_unprojected`` key).
* ``UNIFI_REDACT_SECRETS`` on: those fields and sensitive-looking text are left out, each
  counted under ``_withheld``, and ``_withheld_how_to_obtain`` says for every key how to
  get the value.
* The MCP tool, the collector and both CLI subcommands follow the same setting.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from tests import test_cross_tool_invariants as cti
from tests import test_spec_conformance as sc
from tests import upstream_harness as uh
from unifi_fabric import placement_snapshot_cli as cli
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.innerspace import placement_snapshot as ps

RECORDED = Path(__file__).parent / "fixtures" / "recorded"

#: Additive v1 keys exposed by default and withheld (by field) under redaction:
#: (section, key, reason).
ADDRESS_FIELDS = (
    ("topology", "mac", "hardware_address"),
    ("topology", "ip", "network_address"),
    ("placed_devices", "mac", "hardware_address"),
    ("placed_devices", "ip", "network_address"),
    ("floors", "image_url", "url"),
    ("floors", "model_url", "url"),
    ("floors", "additional_zip_url", "url"),
    ("floors", "additional_bin_url", "url"),
)

#: Snapshot keys whose values the projection derives instead of copying.
DERIVED_KEYS = frozenset({"kind", "device_type", "match_method"})


def _body(name: str) -> Any:
    return json.loads((RECORDED / name).read_text())["body"]


def _recorded_sources() -> dict[str, dict[str, Any]]:
    project = _body("innerspace/innerspace_integration_v1_project.json")["data"]
    # The recorded project's map shape carries only urlImage; give the other three asset
    # URLs values so every floor asset key is exercised.
    for shape in project["shapes"]:
        if shape.get("type") == "map":
            shape.update(
                {
                    "urlModel": "https://assets.example.test/plan.glb",
                    "additionalZipUrl": "https://assets.example.test/plan.zip",
                    "additionalBinUrl": "https://assets.example.test/plan.bin",
                }
            )
    return {
        "project_result": {"project": project},
        "cameras_result": {"result": _body("protect/protect_integration_v1_cameras.json")},
        "sensors_result": {"result": _body("protect/protect_integration_v1_sensors.json")},
        "devices_result": _body("site_manager/v1_devices.json"),
    }


def _strings(node: Any, path: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            out.extend(_strings(value, f"{path}.{key}" if path else str(key)))
    elif isinstance(node, list):
        for value in node:
            out.extend(_strings(value, f"{path}[]"))
    elif isinstance(node, str):
        out.append((path, node))
    return out


def _projected_strings(snapshot: dict[str, Any]) -> list[tuple[str, str]]:
    """Every string the projection copied from upstream (derived values excluded)."""
    out = []
    for section in ("floors", "walls", "placed_devices", "topology"):
        for path, value in _strings(snapshot[section], section):
            if path.rsplit(".", 1)[-1] in DERIVED_KEYS:
                continue
            if path.endswith(".source_id") and value.startswith("smdev-"):
                continue  # SHA-256 derived id for a MAC-only record
            out.append((path, value))
    return out


def _all_upstream_strings(sources: dict[str, Any]) -> set[str]:
    return {value for _path, value in _strings(sources)}


# --------------------------------------------------------------------------- default
def test_default_every_projected_string_is_an_upstream_string_verbatim():
    sources = _recorded_sources()
    snapshot = ps.build_snapshot(**sources)
    upstream = _all_upstream_strings(sources)
    copied = _projected_strings(snapshot)
    assert copied, "the recorded sources project no strings"
    not_verbatim = [(path, value) for path, value in copied if value not in upstream]
    assert not_verbatim == []


def test_default_exposes_every_address_and_asset_field_verbatim():
    sources = _recorded_sources()
    snapshot = ps.build_snapshot(**sources)
    shapes = sources["project_result"]["project"]["shapes"]
    map_plan = next(s["planId"] for s in shapes if s.get("type") == "map")
    floor = next(f for f in snapshot["floors"] if f["source_id"] == map_plan)
    assert floor["image_url"] == "urlImage-0001"
    assert floor["model_url"] == "https://assets.example.test/plan.glb"
    assert floor["additional_zip_url"] == "https://assets.example.test/plan.zip"
    assert floor["additional_bin_url"] == "https://assets.example.test/plan.bin"
    placed = snapshot["placed_devices"][0]
    assert (placed["ip"], placed["mac"]) == ("10.0.2.155", "000000FA0017")
    cameras = sources["cameras_result"]["result"]
    nodes = {n["source_id"]: n for n in snapshot["topology"]}
    for camera in cameras:
        assert nodes[camera["id"]]["mac"] == camera["mac"]
    assert cameras, "the fixture has no camera (vacuous)"
    devices = [d for w in sources["devices_result"]["data"] for d in w["devices"]]
    checked = 0
    for device in devices:
        node = nodes.get(device.get("id"))
        if node is not None and node["kind"] == "network_device":
            checked += 1
            assert (node.get("mac"), node.get("ip")) == (device.get("mac"), device.get("ip"))
    assert checked, "no network device node was compared (vacuous)"
    # every additive key appears somewhere in the default snapshot
    for section, key, _reason in ADDRESS_FIELDS:
        assert any(key in record for record in snapshot[section]), f"{section}[].{key}"
    # no value is withheld by default: the key is never present
    assert "_withheld" not in snapshot and "_withheld_how_to_obtain" not in snapshot


# --------------------------------------------------------------------------- redaction on
def test_redaction_withholds_every_address_and_asset_field_and_says_how_to_get_it():
    sources = _recorded_sources()
    snapshot = ps.build_snapshot(**sources, redact_secrets=True)
    for section, key, reason in ADDRESS_FIELDS:
        assert not any(key in record for record in snapshot[section]), f"{section}[].{key}"
        assert reason in snapshot["_withheld"][f"{section}.{key}"], f"{section}.{key}"
    serialized = json.dumps(snapshot)
    for value in ("10.0.2.155", "000000FA0017", "urlImage-0001", "assets.example.test"):
        assert value not in serialized
    how = snapshot["_withheld_how_to_obtain"]
    assert set(how) == set(snapshot["_withheld"])
    tools = {
        "floors": "get_innerspace_project",
        "placed_devices": "get_innerspace_project",
        "topology": "list_cameras, list_sensors or list_devices",
    }
    for key, reasons in snapshot["_withheld"].items():
        assert tools.get(key.split(".")[0], "") in how[key], key
        assert set(reasons) <= ps.REDACTION_REASONS, (key, reasons)
        assert "UNIFI_REDACT_SECRETS is on: unset it" in how[key], key


def test_structural_entries_are_unprojected_and_say_how_to_get_the_record_in_either_mode():
    sources = _recorded_sources()
    sources["project_result"]["project"]["shapes"].append({"type": "device", "id": "x"})
    for redact in (False, True):
        snapshot = ps.build_snapshot(**sources, redact_secrets=redact)
        assert snapshot["_unprojected"]["placed_devices.record"] == {"no_position": 1}
        assert set(snapshot["_unprojected_how_to_obtain"]) == set(snapshot["_unprojected"])
        how = snapshot["_unprojected_how_to_obtain"]["placed_devices.record"]
        assert "no_position" in how and "get_innerspace_project" in how
        assert "UNIFI_REDACT_SECRETS" not in how
        for reasons in snapshot["_unprojected"].values():
            assert not set(reasons) & ps.REDACTION_REASONS, reasons
        if redact:
            assert "placed_devices.record" not in snapshot["_withheld"]
        else:
            assert "_withheld" not in snapshot and "_withheld_how_to_obtain" not in snapshot


def test_redact_enabled_only_for_an_explicit_true_setting():
    assert ps._redact_enabled(UniFiClient(Settings(api_key="k", redact_secrets=True))) is True
    assert ps._redact_enabled(UniFiClient(Settings(api_key="k"))) is False
    assert ps._redact_enabled(AsyncMock()) is False  # a mock attribute is not opt-in


# --------------------------------------------------------------------------- tool == CLI
class _PlacementUpstream(uh.FakeUpstream):
    """The default fake upstream, with an InnerSpace project carrying the address fields."""

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/proxy/innerspace/integration/v1/project"):
            self._record(req, 200, None, False)
            project = {
                "plans": [{"id": "p1", "title": "Ground", "ordering": 0}],
                "shapes": [
                    {"type": "map", "planId": "p1", "urlImage": "https://a.example.test/i.png"},
                    {
                        "type": "device",
                        "id": "d1",
                        "planId": "p1",
                        "title": "Door Cam",
                        "position": [{"x": 1, "y": 2, "z": 0}],
                        "meta": {"ip": "10.9.8.7", "mac": "AABBCCDDEEFF"},
                    },
                ],
                "products": [],
                "wallTypes": [],
            }
            return httpx.Response(200, json={"data": project})
        return super().__call__(req)


TOOL = "get_unifi_placement_snapshot"


@pytest.mark.parametrize("redact", [False, True])
async def test_mcp_tool_follows_unifi_redact_secrets(monkeypatch, redact):
    env = {"UNIFI_REDACT_SECRETS": "1"} if redact else {}
    up = _PlacementUpstream()
    payload = uh.result_payload(
        await cti._call(monkeypatch, TOOL, up, sc.conformance_args(TOOL), env)
    )
    placed = payload["placed_devices"][0]
    floor = payload["floors"][0]
    if redact:
        assert "ip" not in placed and "mac" not in placed and "image_url" not in floor
        assert payload["_withheld"]["placed_devices.ip"] == {"network_address": 1}
        assert payload["_withheld"]["floors.image_url"] == {"url": 1}
        assert set(payload["_withheld_how_to_obtain"]) == set(payload["_withheld"])
    else:
        assert (placed["ip"], placed["mac"]) == ("10.9.8.7", "AABBCCDDEEFF")
        assert floor["image_url"] == "https://a.example.test/i.png"
        assert "_withheld" not in payload and "_withheld_how_to_obtain" not in payload


def _patch_sources(monkeypatch) -> None:
    sources = _recorded_sources()

    async def project(*_a, **_k):
        return sources["project_result"]["project"]

    async def cameras(*_a, **_k):
        return sources["cameras_result"]

    async def sensors(*_a, **_k):
        return sources["sensors_result"]

    async def devices(*_a, **_k):
        return sources["devices_result"]

    monkeypatch.setattr(ps.innerspace, "fetch_project", project)
    monkeypatch.setattr(ps.protect, "list_cameras", cameras)
    monkeypatch.setattr(ps.protect, "list_sensors", sensors)
    monkeypatch.setattr(ps.site_manager, "list_devices", devices)


@pytest.mark.parametrize("redact", [False, True])
async def test_collector_and_cli_export_agree_with_the_setting(monkeypatch, redact):
    _patch_sources(monkeypatch)
    expected = ps.build_snapshot(**_recorded_sources(), redact_secrets=redact)
    client = UniFiClient(Settings(api_key="k-test", redact_secrets=redact))
    collected = await ps.get_unifi_placement_snapshot(client, AsyncMock(), "HQ")
    await client.close()

    for name in ("UNIFI_API_KEYS", "UNIFI_REDACT_SECRETS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("UNIFI_API_KEY", "k-test")
    if redact:
        monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1")
    exported = await cli.export_snapshot("HQ")

    for snapshot in (collected, exported, expected):
        for volatile in ("generated_at", "freshness"):
            snapshot.pop(volatile)
    assert collected == expected
    assert exported == expected


async def test_preflight_cli_carries_the_error_text(monkeypatch):
    async def denied(*_a, **_k):
        raise ps.UniFiConnectionError("HTTP 403 from GET /proxy/protect/integration/v1/cameras")

    _patch_sources(monkeypatch)
    monkeypatch.setattr(ps.protect, "list_cameras", denied)
    monkeypatch.delenv("UNIFI_API_KEYS", raising=False)
    monkeypatch.setenv("UNIFI_API_KEY", "k-test")
    report = await cli.preflight_snapshot_capabilities("HQ")
    failed = [c for c in report["capabilities"] if c["outcome"] != "ok"]
    assert failed == [
        {
            "name": "protect.cameras",
            "outcome": "auth_denied",
            "error": "UniFiConnectionError: HTTP 403 from GET "
            "/proxy/protect/integration/v1/cameras",
        }
    ]
    assert all("error" not in c for c in report["capabilities"] if c["outcome"] == "ok")
