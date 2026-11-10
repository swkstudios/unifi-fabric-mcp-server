"""The shared Classic networkconf purpose selection keeps records verbatim and in order."""

from __future__ import annotations

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.shared_shapes._classic_objects import _classic_data, of_purpose

RECORDS = [
    {"_id": "a", "purpose": "vpn-client", "name": "first"},
    {"_id": "b", "purpose": "corporate"},
    {"_id": "c", "name": "no purpose"},
    {"_id": "d", "purpose": "vpn-client", "extra": {"nested": [1, 2]}},
    {"_id": "e", "purpose": "VPN-CLIENT"},
]


def test_of_purpose_keeps_matching_records_verbatim_and_in_order():
    selected = of_purpose(RECORDS, "vpn-client")
    assert [record["_id"] for record in selected] == ["a", "d"]
    assert selected[0] is RECORDS[0] and selected[1] is RECORDS[3]


def test_of_purpose_matches_exactly_and_skips_records_without_a_purpose():
    assert of_purpose(RECORDS, "corporate") == [RECORDS[1]]
    assert of_purpose(RECORDS, "VPN-CLIENT") == [RECORDS[4]]
    assert of_purpose(RECORDS, "wan") == []
    assert of_purpose([], "vpn-client") == []


def test_of_purpose_does_not_mutate_its_input():
    before = [dict(record) for record in RECORDS]
    of_purpose(RECORDS, "vpn-client")
    assert RECORDS == before


@pytest.mark.parametrize(
    "response", [{"meta": {"rc": "ok"}}, {"meta": {"rc": "ok"}, "data": {}}, [], "text"]
)
def test_classic_data_requires_a_data_array(response):
    with pytest.raises(UniFiConnectionError, match="expected an object with a 'data' array"):
        _classic_data(response, "/networkconf")


def test_classic_data_requires_object_rows():
    with pytest.raises(UniFiConnectionError, match="row 1 expected an object"):
        _classic_data({"meta": {"rc": "ok"}, "data": [{"_id": "a"}, "b"]}, "/networkconf")


def test_upstream_error_credential_fields_use_shared_formatter():
    from unifi_fabric.client import UniFiConnectionError
    from unifi_fabric.redaction import write_redaction_scope
    from unifi_fabric.shared_shapes._classic_objects import checked_classic_response

    body = {"meta": {"rc": "error"}, "password": "CLASSIC_SHAPE_SENTINEL"}
    with write_redaction_scope(True), pytest.raises(UniFiConnectionError) as exc:
        checked_classic_response(body, "/synthetic")
    assert "CLASSIC_SHAPE_SENTINEL" not in str(exc.value)
