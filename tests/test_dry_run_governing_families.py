"""A ``family:<id>=dry-run`` entry previews exactly the writes ``family:<id>=deny`` refuses.

The deny reach of a family entry is wider than the tool's own catalog family: the
connector switch also governs the typed tools that check it
(``families.connector_write_tools``: the Wi-Fi radio actions, ``update_device_radio``, the
Protect private writes), and ``family:network`` also covers the ``firewall``,
``devices``, ``clients``, ``vpn``, ``hotspot`` and ``statistics`` families. The dry-run
decision (``switches.dry_run_active``, read by the client chokepoint and by
``UniFiClient.dry_run``) must reach the same tools, or the entry sends live writes the
operator asked to preview.

Two layers are checked:

* the decision itself for every tool a family entry governs (pure, no upstream);
* every connector-governed write tool run end to end against the fake upstream with
  ``family:connector=dry-run``: no write reaches the transport.
"""

from __future__ import annotations

import logging

import pytest

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from unifi_fabric import families, switches
from unifi_fabric._read_only_audit import write_verbs_for
from unifi_fabric.audit import audit_call

TOOLS = cti.TOOLS


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _connector_governed_writes() -> list[str]:
    return sorted(
        name
        for name in families.connector_write_tools()
        if name in TOOLS and write_verbs_for(TOOLS[name].fn)
    )


def test_connector_governs_typed_write_tools():
    # Guard the premise: the class is not empty and names the reported Wi-Fi writes.
    governed = set(_connector_governed_writes())
    assert {
        "configure_wifi_wan",
        "start_spectrum_scan",
        "preview_radio_ai_optimization",
        "apply_radio_ai_optimization",
        "control_wifi_doctor_optimization",
        "start_wifi_quick_scan",
        "update_device_radio",
        "update_camera_private",
    } <= governed


@pytest.mark.parametrize("area", [s.family for s in switches.AREA_WRITE_SWITCHES] + ["connector"])
def test_dry_run_reaches_every_tool_the_family_deny_reaches(monkeypatch, area):
    index = families.build_family_index()
    governed = sorted(
        name for name in index if area in switches.governing_families(name, index[name])
    )
    assert governed, area
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "allow")
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", f"family:{area}=dry-run")
    missed = [name for name in governed if not switches.dry_run_active(tool=name)]
    assert missed == [], f"family:{area}=dry-run does not preview {missed}"


def test_governing_families_match_the_deny_reach():
    index = families.build_family_index()
    connector_tools = families.connector_write_tools()
    for name, family in index.items():
        reach = set(switches.governing_families(name, family))
        expected = {family} | {s.family for s in switches.AREA_WRITE_SWITCHES if s.governs(family)}
        if name in connector_tools:
            expected.add("connector")
        assert reach == expected, name


def test_unrelated_family_dry_run_does_not_preview(monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "allow")
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", "family:mobility=dry-run")
    assert not switches.dry_run_active(tool="configure_wifi_wan")
    assert not switches.dry_run_active(tool="update_camera_private")


@lazy_parametrize("name", _connector_governed_writes)
async def test_connector_dry_run_sends_no_write(name):
    up = uh.FakeUpstream()
    mp = pytest.MonkeyPatch()
    env = {
        **tool_args.TOOL_ENV.get(name, {}),
        "UNIFI_WRITE_POLICY": "allow",
        "UNIFI_WRITE_EXCEPTIONS": "family:connector=dry-run",
    }
    try:
        for k, v in env.items():
            mp.setenv(k, v)
        uh.install(mp, up)
        args = tool_args.generated_args(TOOLS[name])
        if name == "fabric_connector_get":
            args["path"] = f"protect/api/cameras/{uh.ARG_ID}/enable-control"
        try:
            # The tool-call scope the server opens around every call (current_tool).
            with audit_call(name):
                await TOOLS[name].run(args)
        except Exception:  # noqa: BLE001 - only the writes sent matter here
            pass
    finally:
        mp.undo()
    assert [(s.method, s.path) for s in up.writes()] == [], name
