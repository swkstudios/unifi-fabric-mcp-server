"""Integrity checks for complete native-capture families and canonical fixture routes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parent / "fixtures" / "recorded"


def load(name):
    return json.loads((ROOT / name).read_text())


@pytest.mark.parametrize(
    "name",
    [
        "network_integration/network_integration_v1_sites_ID_networks.json",
        "network_integration/network_integration_v1_sites_ID_wifi_broadcasts.json",
        "network_integration/network_integration_v1_sites_ID_devices.json",
        "network_integration/network_integration_v1_sites_ID_clients.json",
        "network_integration/network_integration_v1_sites_ID_firewall_policies__offset0.json",
        "network_integration/network_integration_v1_sites_ID_firewall_policies__offset200.json",
        "network_integration/network_integration_v1_countries.json",
        "network_integration/network_integration_v1_countries__offset200.json",
    ],
)
def test_captured_page_is_complete_without_rewritten_framing(name):
    record = load(name)
    body = record["body"]
    assert body["count"] == len(body["data"])
    assert body["offset"] == int(record["request"]["query"]["offset"])
    assert body["limit"] == int(record["request"]["query"]["limit"])
    assert body["totalCount"] >= body["offset"] + body["count"]


@pytest.mark.parametrize(
    ("listing", "detail"),
    [
        (
            "network_integration/network_integration_v1_sites_ID_networks.json",
            "network_integration/network_integration_v1_sites_ID_networks_ID.json",
        ),
        (
            "network_integration/network_integration_v1_sites_ID_wifi_broadcasts.json",
            "network_integration/network_integration_v1_sites_ID_wifi_broadcasts_ID.json",
        ),
        (
            "network_integration/network_integration_v1_sites_ID_devices.json",
            "network_integration/network_integration_v1_sites_ID_devices_ID.json",
        ),
        (
            "network_integration/network_integration_v1_sites_ID_clients.json",
            "network_integration/network_integration_v1_sites_ID_clients_ID.json",
        ),
        (
            "protect/protect_integration_v1_cameras.json",
            "protect/protect_integration_v1_cameras_ID.json",
        ),
    ],
)
def test_positive_route_and_detail_identifier_resolve_in_same_captured_list(listing, detail):
    parent = load(listing)
    child = load(detail)
    rows = parent["body"]["data"] if isinstance(parent["body"], dict) else parent["body"]
    assert child["body"]["id"] in [row["id"] for row in rows]
    assert child["request"]["path"] == parent["request"]["path"] + "/" + child["body"]["id"]
    host = parent["request"]["path"].split("/consoles/")[1].split("/")[0]
    assert host.endswith("FA0001:0000000001")


def test_voucher_create_shape_is_native_batch_wrapper():
    record = load(
        "network_integration/network_integration_v1_sites_ID_hotspot_vouchers__create.json"
    )
    assert record["request"]["method"] == "POST"
    assert record["status"] == 201
    assert set(record["body"]) == {"vouchers"}
    assert len(record["body"]["vouchers"]) == 1
    voucher = record["body"]["vouchers"][0]
    assert set(voucher) == {
        "id",
        "createdAt",
        "name",
        "code",
        "authorizedGuestCount",
        "expired",
        "timeLimitMinutes",
    }
    assert voucher["code"] == "00000000"
    assert isinstance(voucher["timeLimitMinutes"], int)


def test_page_pairs_preserve_captured_total_counts():
    for first, second in [
        (
            "network_integration/network_integration_v1_sites_ID_firewall_policies__offset0.json",
            "network_integration/network_integration_v1_sites_ID_firewall_policies__offset200.json",
        ),
        (
            "network_integration/network_integration_v1_countries.json",
            "network_integration/network_integration_v1_countries__offset200.json",
        ),
    ]:
        a, b = load(first)["body"], load(second)["body"]
        assert a["totalCount"] == b["totalCount"] == a["count"] + b["count"]
        assert b["offset"] == a["offset"] + a["count"]


@pytest.mark.parametrize("page", [1, 2])
def test_native_recognition_limit_and_link_routes_share_identifiers(page):
    a = load(f"protect/protect_api_recognition_face_groups__page{page}_pageSize200.json")
    b = load(f"protect/protect_api_recognition_face_groups__page{page}_pageSize100.json")
    assert [row["id"] for row in a["body"]["groups"]] == [row["id"] for row in b["body"]["groups"]]
    assert a["request"]["query"]["pageSize"] == "200"
    assert b["request"]["query"]["pageSize"] == "100"
    if page == 1:
        assert b["body"]["links"]["next"] == "/recognition/face/groups?pageSize=100&page=2"
    else:
        assert b["body"]["links"]["next"] is None
