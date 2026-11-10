"""Integration tests for the statistics projection tools.

Covers the three telemetry projections whose field extraction is otherwise only
exercised against mocked responses:

* ``get_device_stp_state``        — STP/RSTP fields from Classic REST ``/stat/device``
* ``get_device_port_state``       — ``port_table`` / ``lldp_table`` / thermal-power slice
* ``get_client_link_diagnostics`` — per-client link quality from ``/stat/sta``

These validate the *projection logic* against a real controller payload, not just a
200 response: each test asserts the projected sub-structure is populated with the
fields the tool claims to surface. The unit suite covers the same tools with mocked
responses; this is the only place the extraction is checked against live data.

Requires ``UNIFI_API_KEY``. Host-scoped: also requires ``UNIFI_TEST_HOST`` and
``UNIFI_TEST_SITE`` (missing prerequisites fail once the live tier is enabled). Grounded on a
representative UniFi controller payload: the USW Pro 24 PoE
(``US24PRO``) reports ``stp_version=rstp``, ``stp_priority=4096`` and is the root
bridge; its ``port_table`` carries PoE fields (``poe_enable``/``poe_good``/...); and
``/stat/sta`` carries per-client ``rssi``/``signal``/``noise``/``satisfaction`` for
wireless clients. The assertions below stay tolerant to value drift (they check that a
field was extracted, not a specific magnitude) so they validate the projection without
pinning to one estate snapshot.

Run (with UNIFI_API_KEY already in the environment, loaded from a secret store; never
type the key on the command line, where shell history keeps it):
    UNIFI_TEST_HOST=<host> UNIFI_TEST_SITE=<site> \
        pytest tests/test_statistics_integration.py -v
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.statistics.statistics import (
    _get_client_link_diagnostics,
    _get_device_port_state,
    _get_device_stp_state,
    _list_active_clients_stats,
    _list_device_stats,
)
from unifi_fabric.registry import Registry

# Gated on UNIFI_API_KEY so they always skip in credential-less CI; host-scoped tests
# additionally fail without UNIFI_TEST_HOST/SITE. Module-scoped event loop keeps the
# module-scoped client valid across every test (mirrors test_console_integration.py).
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("UNIFI_API_KEY"),
        reason="UNIFI_API_KEY not set - required for live integration tests",
    ),
    pytest.mark.asyncio(loop_scope="module"),
]

_TEST_HOST = os.environ.get("UNIFI_TEST_HOST", "")
_TEST_SITE = os.environ.get("UNIFI_TEST_SITE", "")


@pytest.fixture(scope="module")
def settings():
    return Settings()


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def client(settings):
    c = UniFiClient(settings)
    yield c
    await c.close()


@pytest.fixture(scope="module")
def registry(client, settings):
    return Registry(client, ttl_seconds=settings.cache_ttl_seconds)


def _records(result) -> list[dict]:
    """Coerce a /stat/* tool result (list, or {data:[...]}) into a list of dicts."""
    if isinstance(result, list):
        return [r for r in result if isinstance(r, dict)]
    if isinstance(result, dict):
        return [r for r in result.get("data", []) if isinstance(r, dict)]
    return []


def _selector(record: dict) -> str:
    """A stable selector the projection helpers accept (mac / _id / id)."""
    return record.get("mac") or record.get("_id") or record.get("id") or ""


async def _find_switch(client, registry) -> dict | None:
    """A /stat/device record with a non-empty port_table (a switch), or None.

    Prefers a switch that reports STP (so the STP projection is genuinely exercised)
    rather than pinning to a single SKU.
    """
    records = _records(await _list_device_stats(client, registry, _TEST_HOST, _TEST_SITE))
    switches = [d for d in records if isinstance(d.get("port_table"), list) and d["port_table"]]
    if not switches:
        return None
    for d in switches:
        if d.get("stp_version") is not None:
            return d
    return switches[0]


async def _find_wireless_clients(client, registry) -> list[dict]:
    """Wireless /stat/sta records carrying link-quality fields (rssi/signal)."""
    records = _records(await _list_active_clients_stats(client, registry, _TEST_HOST, _TEST_SITE))
    return [c for c in records if not c.get("is_wired") and ("rssi" in c or "signal" in c)]


# ---------------------------------------------------------------------------
# get_device_stp_state - STP/RSTP projection from /stat/device
# ---------------------------------------------------------------------------


class TestDeviceStpStateIntegration:
    async def test_envelope_and_device_stp_populated(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.fail("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        switch = await _find_switch(client, registry)
        if switch is None:
            pytest.fail("No switch with a port_table on this site - required for STP projection")
        result = await _get_device_stp_state(
            client, registry, _TEST_HOST, _TEST_SITE, _selector(switch)
        )
        # 0.7.0 envelope: the projections ride under additive underscore keys beside the
        # complete verbatim device record (_device_record) and the upstream meta.
        assert set(result) >= {"_device", "_source", "_stp", "_ports", "_device_record"}, (
            "STP envelope keys missing"
        )
        assert result["_source"] == "/stat/device"
        stp = result["_stp"]
        assert isinstance(stp, dict) and stp, "device-level STP projection must not be empty"
        # The projection must have EXTRACTED the STP mode, not just returned a 200.
        assert "stp_version" in stp, "stp_version was not projected from /stat/device"
        assert isinstance(stp["stp_version"], str) and stp["stp_version"].lower() in {
            "stp",
            "rstp",
        }, f"unexpected stp_version projection: {stp['stp_version']!r}"

    async def test_per_port_stp_slice_populated(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.fail("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        switch = await _find_switch(client, registry)
        if switch is None:
            pytest.fail("No switch with a port_table on this site - required for per-port STP")
        result = await _get_device_stp_state(
            client, registry, _TEST_HOST, _TEST_SITE, _selector(switch)
        )
        ports = result["_ports"]
        assert isinstance(ports, list) and ports, "per-port STP list must be populated"
        # Every entry carries its port_idx envelope key ...
        assert all("port_idx" in p for p in ports), "each port entry must carry port_idx"
        # ... and at least one port must have a real STP field sliced out (role/state/cost),
        # proving the _PORT_STP_KEYS / stp_* extraction actually fires.
        stp_field_keys = {"stp_state", "stp_role", "stp_pathcost", "stp_path_cost"}
        assert any(
            (stp_field_keys & set(p)) or any(k.startswith("stp_") for k in p) for p in ports
        ), "no per-port stp_* field was projected from any port_table row"

    async def test_root_bridge_fields_present(self, client, registry):
        """Grounded: the estate's switch is the RSTP root bridge (stp_priority=4096).

        Assert the projection surfaced the root/priority fields - value-tolerant so it
        validates extraction without pinning to a specific priority.
        """
        if not _TEST_HOST or not _TEST_SITE:
            pytest.fail("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        switch = await _find_switch(client, registry)
        if switch is None:
            pytest.fail("No switch with a port_table on this site - required for root-bridge check")
        if switch.get("stp_version") is None:
            pytest.fail("Discovered switch reports no STP - required for root-bridge check")
        stp = (
            await _get_device_stp_state(client, registry, _TEST_HOST, _TEST_SITE, _selector(switch))
        )["_stp"]
        assert "stp_priority" in stp, "stp_priority was not projected"
        # The controller sends stp_priority verbatim as a numeric STRING (e.g. "4096"); the
        # tool passes it through unchanged (no coercion). Assert it is a scalar that reads
        # as a number - validates extraction and value-tolerant to the str/int wire form.
        priority = stp["stp_priority"]
        assert isinstance(priority, (str, int)), f"stp_priority not a scalar: {priority!r}"
        assert str(priority).isdigit(), f"stp_priority did not project as a number: {priority!r}"
        assert "root_switch" in stp or "root" in stp, (
            "neither root_switch nor root was projected (root-bridge signal lost)"
        )


# ---------------------------------------------------------------------------
# get_device_port_state - port_table / lldp_table / thermal projection
# ---------------------------------------------------------------------------


class TestDevicePortStateIntegration:
    async def test_device_view_projects_port_table_with_poe(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.fail("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        switch = await _find_switch(client, registry)
        if switch is None:
            pytest.fail("No switch with a port_table on this site - required for port projection")
        result = await _get_device_port_state(
            client, registry, _TEST_HOST, _TEST_SITE, _selector(switch)
        )
        # 0.7.0 envelope: verbatim port_table / lldp_table beside the additive underscore
        # keys and the complete verbatim device record.
        assert set(result) >= {
            "_device",
            "_port_idx",
            "_source",
            "port_table",
            "lldp_table",
            "_thermal_power",
            "_device_record",
        }, "port device-view envelope keys missing"
        assert result["_port_idx"] is None, "device view must report _port_idx=None"
        assert result["_source"] == "/stat/device"
        ports = result["port_table"]
        assert isinstance(ports, list) and ports, "port_table projection must be populated"
        assert all("port_idx" in p for p in ports), "each port row must carry port_idx"
        # A PoE switch: at least one row must carry PoE telemetry (poe_enable/poe_good/...).
        assert any(any(k.startswith("poe") for k in row) for row in ports), (
            "no PoE fields projected from any port_table row on a PoE switch"
        )

    async def test_single_port_view_returns_that_row(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.fail("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        switch = await _find_switch(client, registry)
        if switch is None:
            pytest.fail("No switch with a port_table on this site - required for single-port view")
        device_view = await _get_device_port_state(
            client, registry, _TEST_HOST, _TEST_SITE, _selector(switch)
        )
        target_idx = device_view["port_table"][0].get("port_idx")
        assert target_idx is not None, "could not read a port_idx from the projected port_table"
        one = await _get_device_port_state(
            client, registry, _TEST_HOST, _TEST_SITE, _selector(switch), target_idx
        )
        assert set(one) >= {"_device", "_port_idx", "_source", "_port"}, (
            "single-port envelope missing"
        )
        assert one["_port_idx"] == target_idx
        assert isinstance(one["_port"], dict) and one["_port"].get("port_idx") == target_idx

    async def test_unknown_port_idx_raises(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.fail("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        switch = await _find_switch(client, registry)
        if switch is None:
            pytest.fail("A switch with port_table is required for unknown-port check")
        with pytest.raises(ValueError):
            await _get_device_port_state(
                client, registry, _TEST_HOST, _TEST_SITE, _selector(switch), 9999
            )

    async def test_sfp_fields_projected_when_present(self, client, registry):
        """Optics/SFP fields exist only on SFP ports; assert they survive projection if
        any exist, otherwise skip cleanly (a PoE-only access switch has none)."""
        if not _TEST_HOST or not _TEST_SITE:
            pytest.fail("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        switch = await _find_switch(client, registry)
        if switch is None:
            pytest.fail("No switch with a port_table on this site - required for SFP check")
        # Determine hardware eligibility from the raw controller record, before the
        # projection under test. A dropped field must fail rather than cause a skip.
        source_rows = [row for row in switch["port_table"] if "SFP" in row.get("media", "").upper()]
        if not source_rows:
            pytest.fail("No SFP hardware ports exposed on this switch")
        expected = {
            row["port_idx"]: {key: value for key, value in row.items() if "sfp" in key.lower()}
            for row in source_rows
        }
        assert any(expected.values()), "SFP hardware exposes no optics fields to check"
        ports = (
            await _get_device_port_state(
                client, registry, _TEST_HOST, _TEST_SITE, _selector(switch)
            )
        )["port_table"]
        projected = {row["port_idx"]: row for row in ports}
        for port_idx, fields in expected.items():
            assert port_idx in projected, f"SFP port {port_idx} dropped in projection"
            assert fields.keys() <= projected[port_idx].keys()
            assert {key: projected[port_idx][key] for key in fields} == fields


# ---------------------------------------------------------------------------
# get_client_link_diagnostics - per-client link quality from /stat/sta
# ---------------------------------------------------------------------------


class TestClientLinkDiagnosticsIntegration:
    async def test_single_client_link_quality_populated(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.fail("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        wireless = await _find_wireless_clients(client, registry)
        if not wireless:
            pytest.fail("No wireless clients with link data on this site")
        result = await _get_client_link_diagnostics(
            client, registry, _TEST_HOST, _TEST_SITE, client_id=_selector(wireless[0])
        )
        # 0.7.0 returns the upstream /stat/sta {meta, data} envelope with data narrowed to
        # the selected record, unchanged.
        assert isinstance(result, dict) and isinstance(result.get("data"), list)
        assert len(result["data"]) == 1, "single-client selection must return one record"
        record = result["data"][0]
        assert _selector(record) == _selector(wireless[0]), "the wrong client was selected"
        # The record is returned unchanged, so its link-quality fields must be present.
        assert "rssi" in record or "signal" in record, "no rssi/signal on a wireless client record"
        assert "noise" in record, "noise was not present on the projected client record"
        assert "satisfaction" in record, "satisfaction was not present on the client record"

    async def test_multi_client_selection_preserves_order(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.fail("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        wireless = await _find_wireless_clients(client, registry)
        if len(wireless) < 2:
            pytest.fail("Need >=2 wireless clients for the multi-select test")
        selectors = [_selector(wireless[0]), _selector(wireless[1])]
        result = await _get_client_link_diagnostics(
            client, registry, _TEST_HOST, _TEST_SITE, client_ids=selectors
        )
        # 0.7.0 returns the upstream envelope with data narrowed to the selected records.
        assert isinstance(result, dict) and isinstance(result.get("data"), list)
        assert len(result["data"]) == 2, "multi-select must return 2 records"
        assert [_selector(r) for r in result["data"]] == selectors, "requested order not kept"

    async def test_mutual_exclusion_guard(self, client, registry):
        # Neither selector supplied -> the tool must reject before any network call.
        with pytest.raises(ValueError):
            await _get_client_link_diagnostics(client, registry, _TEST_HOST, _TEST_SITE)
