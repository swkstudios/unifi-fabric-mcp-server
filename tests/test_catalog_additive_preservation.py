"""Synthetic collisions preserve every upstream additive field."""

import pytest

from unifi_fabric.families.network import network_services_proxy
from unifi_fabric.families.protect import protect
from unifi_fabric.families.site_manager import site_manager
from unifi_fabric.shared_shapes._history_common import with_warnings
from unifi_fabric.shared_shapes._pagination import (
    mark_incomplete,
    verbatim_list_result,
    with_envelope,
)
from unifi_fabric.shared_shapes._results import with_read_after_error


class TestReadAfterCollision:
    def test_upstream_error_is_preserved(self):
        upstream = {"_readAfterError": "SENTINEL-UPSTREAM"}
        result = with_read_after_error(upstream, "server-error", additive=True)
        assert result["_readAfterError"] == "SENTINEL-UPSTREAM"
        assert result["_wrapperFields"]["_readAfterError"] == "server-error"
        assert upstream == {"_readAfterError": "SENTINEL-UPSTREAM"}


class TestResolutionCollision:
    def test_upstream_partial_markers_are_preserved(self):
        upstream = {"_incomplete": "SENTINEL-FLAG", "_incompleteReason": "SENTINEL-REASON"}
        result = site_manager._resolution_metadata(
            upstream, {"_incompleteReason": "server-partial"}
        )
        assert result["_incomplete"] == "SENTINEL-FLAG"
        assert result["_incompleteReason"] == "SENTINEL-REASON"
        assert result["_wrapperFields"] == {
            "_incomplete": True,
            "_incompleteReason": "server-partial",
        }
        assert "_wrapperFields" not in upstream

    def test_single_key_label_is_preserved(self):
        upstream = {"_key_labels": ["SENTINEL-KEY"]}
        result = site_manager._single_key_result(upstream, "server-key")
        assert result["_key_labels"] == ["SENTINEL-KEY"]
        assert result["_wrapperFields"]["_key_labels"] == ["server-key"]
        assert upstream == {"_key_labels": ["SENTINEL-KEY"]}


class TestWarningCollision:
    @pytest.mark.parametrize("existing", [["SENTINEL-WARNING"], "SENTINEL-WARNING", None])
    @pytest.mark.parametrize(
        "writer",
        [network_services_proxy._with_warning, lambda obj, warning: with_warnings(obj, [warning])],
    )
    def test_warning_keeps_upstream_value(self, existing, writer):
        upstream = {"_warnings": existing}
        warning = {"code": "server-warning"}
        result = writer(upstream, warning)
        assert result["_warnings"] == existing
        assert result["_wrapperFields"]["_warnings"] == [warning]
        assert upstream == {"_warnings": existing}


class TestListMetadataCollision:
    def test_count_and_partial_preserve_upstream(self):
        upstream = {
            "data": [],
            "totalCount": 2,
            "_count": "SENTINEL-COUNT",
            "incomplete": "SENTINEL-FLAG",
            "incompleteReason": "SENTINEL-REASON",
        }
        result = verbatim_list_result(upstream, [], "/synthetic")
        assert result["_count"] == "SENTINEL-COUNT"
        assert result["incomplete"] == "SENTINEL-FLAG"
        assert result["incompleteReason"] == "SENTINEL-REASON"
        assert result["_wrapperFields"]["_count"] == 0

    def test_capped_marker_keeps_upstream(self):
        upstream = {"incomplete": "SENTINEL-FLAG", "incompleteReason": "SENTINEL-REASON"}
        result = mark_incomplete(
            upstream, {"incomplete": True, "incompleteReason": "server-partial"}
        )
        assert result["incomplete"] == "SENTINEL-FLAG"
        assert result["incompleteReason"] == "SENTINEL-REASON"
        assert result["_wrapperFields"]["incompleteReason"] == "server-partial"
        assert "_wrapperFields" not in upstream

    def test_drain_envelope_keeps_additive_fields(self):
        result = with_envelope(
            {"data": [1, 2], "_count": 2},
            {"envelope": {"_count": "SENTINEL-COUNT", "traceId": "SENTINEL-TRACE"}},
        )
        assert result["data"] == [1, 2]
        assert result["_count"] == "SENTINEL-COUNT"
        assert result["_wrapperFields"]["_count"] == 2

    def test_protect_count_keeps_upstream(self):
        upstream = {"data": [], "_count": "SENTINEL-COUNT"}
        result = protect._list_body(upstream, "synthetic")
        assert result["_count"] == "SENTINEL-COUNT"
        assert result["_wrapperFields"]["_count"] == 0


class TestSensorContextCollision:
    def test_sensor_reference_keeps_upstream(self):
        upstream = {
            "sensor": None,
            "metadata": {"sensorId": {"text": "server-id"}},
            "_resolved_sensor": "SENTINEL-SENSOR",
        }
        result = protect._normalize_sensor_reference(upstream)
        assert result["_resolved_sensor"] == "SENTINEL-SENSOR"
        assert result["_wrapperFields"]["_resolved_sensor"] == "server-id"
        assert "_wrapperFields" not in upstream


class TestSitePartialContextCollision:
    def test_reason_report_keeps_upstream(self):
        upstream = {"incomplete": "SENTINEL-FLAG", "incompleteReason": "SENTINEL-REASON"}
        result = site_manager._mark_reasons(upstream, ["server-partial"])
        assert result["incomplete"] == "SENTINEL-FLAG"
        assert result["incompleteReason"] == "SENTINEL-REASON"
        assert result["_wrapperFields"]["incompleteReason"] == "server-partial"
        assert "_wrapperFields" not in upstream
