"""Catalog regression audit tests (issue #190).

Two layers:

1. **Hermetic (always in CI).** Unit tests for the pure comparison logic in
   ``unifi_fabric._catalog_audit`` plus guards that run against the *live registered*
   tool set (introspected from the imported FastMCP instance — no network, no creds):
   the gateway name transform must be collision-free and round-trip losslessly, a
   catalog that exactly mirrors the registrations must diff clean, and a deliberately
   dropped / injected name must be caught. These lock the naming contract the deployed
   catalog depends on and the drift-detection logic, without reaching the gateway.

2. **Live (Tier-2, ``@pytest.mark.integration``, skipped in CI).** Fetch the real
   deployed gateway catalog and assert it matches the registered set. Gated on
   ``UNIFI_CATALOG_ENDPOINT`` so it is always skipped where that env var is absent
   (i.e. in CI). The fetch helper is reused from ``scripts/check_catalog_regression.py``
   so the CLI tool and this test exercise one implementation.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import sys
from pathlib import Path

import pytest

from unifi_fabric import server
from unifi_fabric._catalog_audit import (
    DEFAULT_GATEWAY_SLUG,
    CatalogDiff,
    base_tool_name,
    catalog_base_names,
    diff_catalog,
    extract_catalog_names,
    federated_tool_name,
)

# Make scripts/ importable so the live test reuses the CLI's single fetch implementation.
_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))


def _registered_tool_names() -> list[str]:
    """Authoritative registered tool names from the imported FastMCP instance."""
    result = server.mcp.list_tools()
    if inspect.isawaitable(result):
        result = asyncio.run(result)
    return [tool.name for tool in result]


# ---------------------------------------------------------------------------
# Pure transform: federated_tool_name / base_tool_name
# ---------------------------------------------------------------------------


def test_federated_tool_name_prefixes_and_hyphenates() -> None:
    assert federated_tool_name("list_lags", "unifi-fabric-dev") == "unifi-fabric-dev-list-lags"
    assert (
        federated_tool_name("list_mc_lag_domains", "unifi-fabric-dev")
        == "unifi-fabric-dev-list-mc-lag-domains"
    )
    # default slug is the dev gateway
    assert federated_tool_name("get_lag") == "unifi-fabric-dev-get-lag"


def test_base_tool_name_inverts_transform() -> None:
    assert base_tool_name("unifi-fabric-dev-list-lags", "unifi-fabric-dev") == "list_lags"
    assert (
        base_tool_name("unifi-fabric-dev-list-mc-lag-domains", "unifi-fabric-dev")
        == "list_mc_lag_domains"
    )


def test_base_tool_name_returns_none_for_foreign_gateway() -> None:
    # A name from a different federated gateway must not be attributed to this one.
    assert base_tool_name("unifi-fabric-prod-list-lags", "unifi-fabric-dev") is None
    assert base_tool_name("hindsight-recall", "unifi-fabric-dev") is None


def test_transform_round_trips_for_every_registered_name() -> None:
    for name in _registered_tool_names():
        assert base_tool_name(federated_tool_name(name)) == name


def test_federation_is_collision_free_across_registered_names() -> None:
    # Two distinct registered names must never collapse to the same federated name;
    # if they did, the deployed catalog would silently drop one of them.
    names = _registered_tool_names()
    federated = [federated_tool_name(n) for n in names]
    assert len(set(federated)) == len(names), "gateway name transform collides two tools"


# ---------------------------------------------------------------------------
# catalog_base_names / extract_catalog_names
# ---------------------------------------------------------------------------


def test_catalog_base_names_filters_foreign_and_maps_own() -> None:
    catalog = [
        "unifi-fabric-dev-list-lags",
        "unifi-fabric-dev-get-lag",
        "unifi-fabric-prod-list-lags",  # foreign gateway -> dropped
        "hindsight-recall",  # foreign gateway -> dropped
    ]
    assert catalog_base_names(catalog, "unifi-fabric-dev") == {"list_lags", "get_lag"}


def test_extract_catalog_names_from_bare_list() -> None:
    assert extract_catalog_names(["a-b", "a-c"]) == ["a-b", "a-c"]


def test_extract_catalog_names_from_mcp_tools_list_result() -> None:
    payload = {"result": {"tools": [{"name": "gw-list_x"}, {"name": "gw-get_y"}]}}
    assert extract_catalog_names(payload) == ["gw-list_x", "gw-get_y"]


def test_extract_catalog_names_from_unwrapped_tools() -> None:
    payload = {"tools": [{"name": "gw-list_x"}]}
    assert extract_catalog_names(payload) == ["gw-list_x"]


def test_extract_catalog_names_from_data_envelope() -> None:
    assert extract_catalog_names({"data": ["gw-list_x", {"name": "gw-get_y"}]}) == [
        "gw-list_x",
        "gw-get_y",
    ]


def test_extract_catalog_names_rejects_unknown_shape() -> None:
    with pytest.raises(ValueError, match="unrecognised catalog snapshot shape"):
        extract_catalog_names({"unexpected": 1})
    with pytest.raises(ValueError, match="unrecognised catalog snapshot shape"):
        extract_catalog_names(42)


def test_extract_catalog_names_rejects_nameless_entry() -> None:
    with pytest.raises(ValueError, match="no string name"):
        extract_catalog_names([{"id": "x"}])


# ---------------------------------------------------------------------------
# diff_catalog + CatalogDiff
# ---------------------------------------------------------------------------


def test_diff_clean_when_catalog_mirrors_registrations() -> None:
    registered = _registered_tool_names()
    catalog = [federated_tool_name(n) for n in registered]
    diff = diff_catalog(registered, catalog)
    assert diff.is_clean, diff.summary()
    assert diff.missing_from_catalog == []
    assert diff.unexpected_in_catalog == []
    assert "in sync" in diff.summary()


def test_diff_flags_dropped_and_phantom_against_live_registrations() -> None:
    registered = _registered_tool_names()
    dropped = sorted(registered)[0]
    catalog = [federated_tool_name(n) for n in registered if n != dropped]
    catalog.append(federated_tool_name("zzz_synthetic_phantom_tool"))
    diff = diff_catalog(registered, catalog)
    assert not diff.is_clean
    assert dropped in diff.missing_from_catalog
    assert "zzz_synthetic_phantom_tool" in diff.unexpected_in_catalog
    summary = diff.summary()
    assert "DRIFT" in summary
    assert dropped in summary
    assert "zzz_synthetic_phantom_tool" in summary


def test_diff_missing_only() -> None:
    diff = diff_catalog(["list_a", "get_b"], ["unifi-fabric-dev-list-a"])
    assert diff.missing_from_catalog == ["get_b"]
    assert diff.unexpected_in_catalog == []
    assert not diff.is_clean


def test_diff_unexpected_only() -> None:
    diff = diff_catalog(["list_a"], ["unifi-fabric-dev-list-a", "unifi-fabric-dev-get-stale"])
    assert diff.missing_from_catalog == []
    assert diff.unexpected_in_catalog == ["get_stale"]


def test_diff_ignores_other_gateways_entries() -> None:
    # A prod-slug entry in a mixed catalog is neither missing nor unexpected for dev.
    diff = diff_catalog(
        ["list_a"],
        ["unifi-fabric-dev-list-a", "unifi-fabric-prod-list-a"],
        gateway_slug="unifi-fabric-dev",
    )
    assert diff.is_clean, diff.summary()


def test_catalog_diff_default_is_clean() -> None:
    assert CatalogDiff().is_clean


def test_default_gateway_slug_constant() -> None:
    assert DEFAULT_GATEWAY_SLUG == "unifi-fabric-dev"


# ---------------------------------------------------------------------------
# Live (Tier-2): compare registered tools to the real deployed gateway catalog.
# Skipped unless UNIFI_CATALOG_ENDPOINT is set, so it never runs in CI.
# ---------------------------------------------------------------------------

_CATALOG_ENDPOINT = os.environ.get("UNIFI_CATALOG_ENDPOINT")


@pytest.mark.integration
@pytest.mark.skipif(
    not _CATALOG_ENDPOINT,
    reason="UNIFI_CATALOG_ENDPOINT not set (live deployed-catalog check is Tier-2 only)",
)
def test_deployed_catalog_matches_registered() -> None:
    # Imported lazily so a missing scripts/ import never breaks hermetic collection.
    from check_catalog_regression import fetch_deployed_catalog_names

    slug = os.environ.get("UNIFI_CATALOG_GATEWAY_SLUG", DEFAULT_GATEWAY_SLUG)
    bearer = os.environ.get("MCP_BEARER_TOKEN")
    catalog_names = fetch_deployed_catalog_names(
        _CATALOG_ENDPOINT, bearer_token=bearer, timeout=30.0
    )
    diff = diff_catalog(_registered_tool_names(), catalog_names, gateway_slug=slug)
    assert diff.is_clean, diff.summary()
