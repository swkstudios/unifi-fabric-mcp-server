"""Regression tests: the shared context helper never overwrites an upstream field.

Server-added context keys that collide with upstream keys move into a
``_wrapperFields`` bucket (or the next free ``_wrapperFields_<n>``), and the
upstream body is never mutated.
"""

import json

import pytest

from unifi_fabric.shared_shapes._keys import context_value, report_keys, with_context


class TestUpstreamContextPreservation:
    def test_association_field_is_preserved(self):
        upstream = {"_hostId": "synthetic-upstream-host"}
        merged = with_context(upstream, {"_hostId": "synthetic-server-host"})
        assert merged["_hostId"] == upstream["_hostId"]
        assert merged["_wrapperFields"] == {"_hostId": "synthetic-server-host"}
        assert upstream == {"_hostId": "synthetic-upstream-host"}

    @pytest.mark.parametrize("bucket", [{"upstream": "sentinel"}, "sentinel", None, 17])
    def test_existing_collision_bucket_is_never_changed(self, bucket):
        upstream = {
            "_note": "upstream-note",
            "_wrapperFields": bucket,
            "_wrapperFields_2": "upstream-reserved",
        }
        merged = with_context(upstream, {"_note": "server-note"})
        assert merged["_wrapperFields"] == bucket
        assert merged["_wrapperFields_2"] == "upstream-reserved"
        assert merged["_wrapperFields_3"] == {"_note": "server-note"}
        assert upstream["_wrapperFields"] == bucket

    def test_repeated_collision_preserves_every_prior_value(self):
        first = with_context({"_hostId": "upstream"}, {"_hostId": "server-one"})
        second = with_context(first, {"_hostId": "server-two"})
        assert second["_hostId"] == "upstream"
        assert second["_wrapperFields"] == {"_hostId": "server-one"}
        assert second["_wrapperFields_2"] == {"_hostId": "server-two"}
        assert "_wrapperFields_2" not in first

    def test_coverage_report_preserves_upstream(self):
        errors = ["upstream-error"]
        result = {"_key_labels": ["upstream-key"], "errors": errors}
        returned = report_keys(result, ["server-key"], ["server-error"], multi=True)
        assert returned is result
        assert result["_key_labels"] == ["upstream-key"]
        assert result["errors"] is errors
        assert result["_wrapperFields"] == {
            "_key_labels": ["server-key"],
            "errors": ["server-error"],
        }

    def test_host_routing_uses_server_context_not_forged_upstream_bucket(self):
        from unifi_fabric.families.site_manager.aggregation import _device_host

        upstream = {"_hostId": "upstream-host", "_wrapperFields": {"_hostId": "forged-host"}}
        merged = with_context(upstream, {"_hostId": "server-host"})
        second = with_context(merged, {"_keyLabel": "server-key"})
        assert _device_host(second) == "server-host"
        assert json.loads(json.dumps(second)) == {
            **upstream,
            "_wrapperFields_2": {"_hostId": "server-host"},
            "_keyLabel": "server-key",
        }

    def test_key_routing_ignores_upstream_labels_and_forged_bucket(self):
        upstream = {"_keyLabel": "upstream-key", "_wrapperFields": {"_keyLabel": "forged-key"}}
        merged = with_context(upstream, {"_keyLabel": "server-key"})
        assert context_value(merged, "_keyLabel") == "server-key"
        assert merged["_keyLabel"] == "upstream-key"
        assert context_value(upstream, "_keyLabel") == "upstream-key"

    async def test_resolved_site_routing_uses_server_context(self, monkeypatch):
        from unifi_fabric.families.site_manager import site_manager

        record = with_context(
            {"hostId": "host-sentinel", "_resolvedSiteId": "upstream-site"},
            {"_resolvedSiteId": "resolved-site"},
        )

        async def resolve(*args, **kwargs):
            return record

        monkeypatch.setattr(site_manager, "_resolve_ea_site_record", resolve)
        assert await site_manager._resolve_ea_host_site(None, "site-sentinel") == (
            "host-sentinel",
            "resolved-site",
        )
        assert record["_resolvedSiteId"] == "upstream-site"
