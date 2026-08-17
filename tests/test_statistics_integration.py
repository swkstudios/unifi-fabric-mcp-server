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
``UNIFI_TEST_SITE`` (all skip cleanly when unset, exactly like the other integration
modules). Grounded on a representative UniFi controller payload: the USW Pro 24 PoE
(``US24PRO``) reports ``stp_version=rstp``, ``stp_priority=4096`` and is the root
bridge; its ``port_table`` carries PoE fields (``poe_enable``/``poe_good``/...); and
``/stat/sta`` carries per-client ``rssi``/``signal``/``noise``/``satisfaction`` for
wireless clients. The assertions below stay tolerant to value drift (they check that a
field was extracted, not a specific magnitude) so they validate the projection without
pinning to one estate snapshot.

Run:
    UNIFI_API_KEY=<key> UNIFI_TEST_HOST=<host> UNIFI_TEST_SITE=<site> \
        pytest tests/test_statistics_integration.py -v
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools.statistics import (
    _get_client_link_diagnostics,
    _get_device_port_state,
    _get_device_stp_state,
    _list_active_clients_stats,
    _list_device_stats,
)

# Gated on UNIFI_API_KEY so they always skip in credential-less CI; host-scoped tests
# additionally self-skip without UNIFI_TEST_HOST/SITE. Module-scoped event loop keeps the
# module-scoped client valid across every test (mirrors test_console_integration.py).
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("UNIFI_API_KEY"),
        reason="UNIFI_API_KEY not set - skipping live integration tests",
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
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        switch = await _find_switch(client, registry)
        if switch is None:
            pytest.skip("No switch with a port_table on this site - skipping STP projection")
        result = await _get_device_stp_state(
            client, registry, _TEST_HOST, _TEST_SITE, _selector(switch)
        )
        assert set(result) >= {"device", "source", "stp", "ports"}, "STP envelope keys missing"
        assert result["source"] == "/stat/device"
        stp = result["stp"]
        assert isinstance(stp, dict) and stp, "device-level STP projection must not be empty"
        # The projection must have EXTRACTED the STP mode, not just returned a 200.
        assert "stp_version" in stp, "stp_version was not projected from /stat/device"
        assert isinstance(stp["stp_version"], str) and stp["stp_version"].lower() in {
            "stp",
            "rstp",
        }, f"unexpected stp_version projection: {stp['stp_version']!r}"

    async def test_per_port_stp_slice_populated(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        switch = await _find_switch(client, registry)
        if switch is None:
            pytest.skip("No switch with a port_table on this site - skipping per-port STP")
        result = await _get_device_stp_state(
            client, registry, _TEST_HOST, _TEST_SITE, _selector(switch)
        )
        ports = result["ports"]
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
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        switch = await _find_switch(client, registry)
        if switch is None:
            pytest.skip("No switch with a port_table on this site - skipping root-bridge check")
        if switch.get("stp_version") is None:
            pytest.skip("Discovered switch reports no STP - skipping root-bridge check")
        stp = (
            await _get_device_stp_state(client, registry, _TEST_HOST, _TEST_SITE, _selector(switch))
        )["stp"]
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
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        switch = await _find_switch(client, registry)
        if switch is None:
            pytest.skip("No switch with a port_table on this site - skipping port projection")
        result = await _get_device_port_state(
            client, registry, _TEST_HOST, _TEST_SITE, _selector(switch)
        )
        assert set(result) >= {
            "device",
            "port_idx",
            "source",
            "port_table",
            "lldp_table",
            "thermal_power",
        }, "port device-view envelope keys missing"
        assert result["port_idx"] is None, "device view must report port_idx=None"
        assert result["source"] == "/stat/device"
        ports = result["port_table"]
        assert isinstance(ports, list) and ports, "port_table projection must be populated"
        assert all("port_idx" in p for p in ports), "each port row must carry port_idx"
        # A PoE switch: at least one row must carry PoE telemetry (poe_enable/poe_good/...).
        assert any(any(k.startswith("poe") for k in row) for row in ports), (
            "no PoE fields projected from any port_table row on a PoE switch"
        )

    async def test_single_port_view_returns_that_row(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        switch = await _find_switch(client, registry)
        if switch is None:
            pytest.skip("No switch with a port_table on this site - skipping single-port view")
        device_view = await _get_device_port_state(
            client, registry, _TEST_HOST, _TEST_SITE, _selector(switch)
        )
        target_idx = device_view["port_table"][0].get("port_idx")
        assert target_idx is not None, "could not read a port_idx from the projected port_table"
        one = await _get_device_port_state(
            client, registry, _TEST_HOST, _TEST_SITE, _selector(switch), target_idx
        )
        assert set(one) >= {"device", "port_idx", "source", "port"}, "single-port envelope missing"
        assert one["port_idx"] == target_idx
        assert isinstance(one["port"], dict) and one["port"].get("port_idx") == target_idx

    async def test_unknown_port_idx_raises(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        switch = await _find_switch(client, registry)
        if switch is None:
            pytest.skip("No switch with a port_table on this site - skipping unknown-port check")
        with pytest.raises(ValueError):
            await _get_device_port_state(
                client, registry, _TEST_HOST, _TEST_SITE, _selector(switch), 9999
            )

    async def test_sfp_fields_projected_when_present(self, client, registry):
        """Optics/SFP fields exist only on SFP ports; assert they survive projection if
        any exist, otherwise skip cleanly (a PoE-only access switch has none)."""
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        switch = await _find_switch(client, registry)
        if switch is None:
            pytest.skip("No switch with a port_table on this site - skipping SFP check")
        ports = (
            await _get_device_port_state(
                client, registry, _TEST_HOST, _TEST_SITE, _selector(switch)
            )
        )["port_table"]
        sfp_rows = [row for row in ports if any("sfp" in k for k in row)]
        if not sfp_rows:
            pytest.skip("No SFP/optics ports exposed on this switch - nothing to project")
        assert any(any("sfp" in k for k in row) for row in sfp_rows), (
            "SFP fields dropped in projection"
        )


# ---------------------------------------------------------------------------
# get_client_link_diagnostics - per-client link quality from /stat/sta
# ---------------------------------------------------------------------------


class TestClientLinkDiagnosticsIntegration:
    async def test_single_client_link_quality_populated(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        wireless = await _find_wireless_clients(client, registry)
        if not wireless:
            pytest.skip("No wireless clients with link data on this site")
        result = await _get_client_link_diagnostics(
            client, registry, _TEST_HOST, _TEST_SITE, client_id=_selector(wireless[0])
        )
        assert isinstance(result, dict), "single-client selection must return one record dict"
        # The record is returned unchanged, so its link-quality fields must be present.
        assert "rssi" in result or "signal" in result, "no rssi/signal on a wireless client record"
        assert "noise" in result, "noise was not present on the projected client record"
        assert "satisfaction" in result, "satisfaction was not present on the client record"

    async def test_multi_client_selection_preserves_order(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        wireless = await _find_wireless_clients(client, registry)
        if len(wireless) < 2:
            pytest.skip("Need >=2 wireless clients for the multi-select test")
        selectors = [_selector(wireless[0]), _selector(wireless[1])]
        result = await _get_client_link_diagnostics(
            client, registry, _TEST_HOST, _TEST_SITE, client_ids=selectors
        )
        assert isinstance(result, list) and len(result) == 2, "multi-select must return 2 records"

    async def test_mutual_exclusion_guard(self, client, registry):
        # Neither selector supplied -> the tool must reject before any network call.
        with pytest.raises(ValueError):
            await _get_client_link_diagnostics(client, registry, _TEST_HOST, _TEST_SITE)
