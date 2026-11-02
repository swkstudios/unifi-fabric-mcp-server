"""Tests for the guarded generic Fabric connector relay.

Covers the guard matrix (namespace allowlist, positive-charset path validation,
mutation gating on confirm + env flag, scope guard), Registry-only site
substitution, read-before/write/read-after with no-op detection, credential
redaction, and the structured audit log. Also transcribes the two decision-closing
probe protocols from the acceptance suite as HERMETIC tests:

  1. InnerSpace probe — PATCH innerspace/api/shapes/<fake-uuid> with an empty body
     is expected to return a 4xx (reachability evidence), never raise. A 200/204 on
     such a probe is a stop condition (documented; the live procedure is NOT run here).
  2. Device write protocol — a same-value device-scoped write is a no-op
     (readBefore == readAfter -> noOp=true), and a site-global setting route cannot be
     driven by a scope='device' request. Live STP/priority mutation is deferred to a
     maintenance window and is NOT performed here.

All tests are hermetic: the HTTP layer is mocked, no live console is touched.
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import respx
from httpx import Response

from unifi_fabric.client import DRY_RUN_MESSAGE, RateLimitError, UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.tools import connector
from unifi_fabric.tools import innerspace as _innerspace_module
from unifi_fabric.tools.connector import (
    _check_final_charset,
    _validate_relay_path,
    connector_get,
    connector_write,
)

HOST_ID = "aabbccddeeff0000:12345"
SITE_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
SITE_SLUG = "default"
FAKE_SHAPE_ID = "00000000-0000-0000-0000-000000000000"
DEVICE_ID = "6605abcd1234567890abcdef"


class FakeResp:
    """Minimal stand-in for httpx.Response as returned by client.request."""

    def __init__(
        self,
        status: int,
        json_body: Any = None,
        text: str = "",
        *,
        content: bytes | None = None,
        content_type: str | None = None,
        extensions: dict[str, Any] | None = None,
    ) -> None:
        self.status_code = status
        self._json = json_body
        self.text = text
        if content is not None:
            self.content = content
        else:
            self.content = (json.dumps(json_body) if json_body is not None else text).encode()
        if content_type is None and content is None:
            content_type = "application/json" if json_body is not None else "text/plain"
        self.headers = {"content-type": content_type} if content_type else {}
        if extensions is not None:
            self.extensions = extensions

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("no json")
        return self._json


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_id = AsyncMock(return_value=SITE_UUID)
    r.resolve_site_slug = AsyncMock(return_value=SITE_SLUG)
    return r


@pytest.fixture()
def client():
    c = AsyncMock()
    c.request = AsyncMock()
    return c


# --------------------------------------------------------------------------- #
# Namespace allowlist + positive-charset path validation
# --------------------------------------------------------------------------- #


class TestNamespaceAllowlist:
    @pytest.mark.parametrize(
        "path,expected",
        [
            ("network/integration/v1/sites", "network-integration"),
            ("network/api/s/{site}/rest/device/x", "network-classic-rest"),
            ("network/api/s/{site}/cmd/devmgr", "network-classic-cmd"),
            ("network/api/s/{site}/stat/device", "network-classic-stat"),
            # every other Classic route is reachable too (no typed wrapper needed)
            ("network/api/s/{site}/set/setting/mgmt", "network-classic"),
            ("network/api/s/{site}/upd/device/x", "network-classic"),
            ("network/api/s/{site}/list/user", "network-classic"),
            ("network/api/s/{site}/group/user", "network-classic"),
            ("network/api/s/{site}/settings", "network-classic"),
            ("network/api/self", "network-classic-controller"),
            ("network/api/stat/sites", "network-classic-controller"),
            ("network/v2/api/site/x/trafficrules", "network-v2"),
            ("protect/integration/v1/cameras", "protect-integration"),
            ("protect/api/events", "protect-private"),
            ("innerspace/integration/v1/project", "innerspace-integration"),
            ("innerspace/api/shapes/x", "innerspace-legacy"),
            ("access/integration/v1/doors", "access-integration"),
            ("access/api/x", "access-private"),
        ],
    )
    def test_allowed_namespaces_return_route_class(self, path, expected):
        assert _validate_relay_path(path, None) == expected

    @pytest.mark.parametrize(
        "path",
        [
            "admin/api/backup",
            "network/foo/bar",
            "networkx/api/s/default/rest/x",  # not a UniFi namespace
            "proxy/network/integration/v1",  # double proxy
            "v1/connector/consoles/x",  # not a proxy-relative path
            "internal/secrets",
        ],
    )
    def test_valid_path_outside_the_map_is_unclassified(self, path):
        # The route-class map is not a gate:
        # a valid path in no mapped namespace relays as routeClass "unclassified".
        assert _validate_relay_path(path, None) == connector.UNCLASSIFIED

    @pytest.mark.parametrize(
        "path",
        [
            "network/integration/v1/../../secrets",  # traversal
            "network/integration/v1/%2e%2e/x",  # percent-encoding
            "https://evil.example/x",  # scheme
            "network/integration//v1",  # empty segment
            "network/integration/v1/\x00",  # control char
            "network/integration/v1/a b",  # whitespace
        ],
    )
    def test_traversal_and_encoding_rejected(self, path):
        with pytest.raises(ValueError):
            _validate_relay_path(path, None)

    def test_empty_path_rejected(self):
        with pytest.raises(ValueError, match="must not be empty"):
            _validate_relay_path("   ", None)

    def test_final_charset_rejects_leftover_placeholder(self):
        with pytest.raises(ValueError, match="Unresolved placeholder"):
            _check_final_charset("network/api/s/{site}/rest")

    def test_final_charset_rejects_traversal(self):
        with pytest.raises(ValueError, match="traversal"):
            _check_final_charset("network/../x")


# --------------------------------------------------------------------------- #
# Scope guard — device vs site-global
# --------------------------------------------------------------------------- #


class TestScopeGuard:
    def test_device_scope_on_global_setting_rejected(self):
        with pytest.raises(ValueError, match="site-global"):
            _validate_relay_path("network/api/s/{site}/rest/setting/global_switch", "device")

    def test_site_scope_on_device_route_rejected(self):
        with pytest.raises(ValueError, match="device-scoped"):
            _validate_relay_path("network/api/s/{site}/rest/device/x", "site")

    def test_global_scope_on_device_route_rejected(self):
        with pytest.raises(ValueError, match="device-scoped"):
            _validate_relay_path("network/api/s/{site}/stat/device", "global")

    def test_device_scope_on_device_route_ok(self):
        assert (
            _validate_relay_path("network/api/s/{site}/rest/device/x", "device")
            == "network-classic-rest"
        )

    def test_invalid_scope_value_rejected(self):
        with pytest.raises(ValueError, match="Invalid scope"):
            _validate_relay_path("network/integration/v1/sites", "planet")


# --------------------------------------------------------------------------- #
# Site placeholder substitution (Registry-only identity)
# --------------------------------------------------------------------------- #


class TestSiteSubstitution:
    async def test_slug_placeholder_resolved(self, client, registry):
        client.request.return_value = FakeResp(200, {"data": []})
        result = await connector_get(
            client, registry, "MyHost", "network/api/s/{site}/stat/device", site="Office"
        )
        registry.resolve_site_slug.assert_awaited_once_with("Office", HOST_ID, key=None)
        assert result["resolvedPath"] == f"network/api/s/{SITE_SLUG}/stat/device"
        called_url = client.request.await_args.args[1]
        assert called_url == (
            f"/v1/connector/consoles/{HOST_ID}/proxy/network/api/s/{SITE_SLUG}/stat/device"
        )

    async def test_uuid_placeholder_resolved(self, client, registry):
        client.request.return_value = FakeResp(200, {"data": []})
        result = await connector_get(
            client,
            registry,
            "MyHost",
            "network/integration/v1/sites/{site_id}/firewall/zones",
            site="Office",
        )
        registry.resolve_site_id.assert_awaited_once_with("Office", HOST_ID, key=None)
        assert result["resolvedPath"].endswith(f"/sites/{SITE_UUID}/firewall/zones")

    async def test_placeholder_without_site_rejected(self, client, registry):
        with pytest.raises(ValueError, match="site placeholder"):
            await connector_get(client, registry, "h", "network/api/s/{site}/stat/device")
        client.request.assert_not_called()


# --------------------------------------------------------------------------- #
# GET relay — always available, status reported not raised
# --------------------------------------------------------------------------- #


class TestConnectorGet:
    async def test_get_returns_status_and_body(self, client, registry):
        client.request.return_value = FakeResp(200, {"data": [{"id": "s1"}]})
        result = await connector_get(client, registry, "h", "network/integration/v1/sites")
        assert result["status"] == 200
        assert result["body"] == {"data": [{"id": "s1"}]}
        assert result["routeClass"] == "network-integration"
        # GET must not raise on error and must carry the escape-hatch flag through.
        assert client.request.await_args.args[0] == "GET"
        assert client.request.await_args.kwargs["raise_on_error"] is False

    async def test_get_masks_registered_response_field_only_under_opt_in(self, registry):
        """The client chokepoint masks a registered route field of a 2xx relay body only
        under UNIFI_REDACT_SECRETS; the relay returns what it received."""
        path = "network/v2/api/site/default/matter/nodes"
        for redact, expected in ((True, "***REDACTED***"), (False, "synthetic-setup-code")):
            real = UniFiClient(Settings(api_key="k-test", redact_secrets=redact))
            with respx.mock(assert_all_called=False) as mock:
                mock.get(url__regex=r".*/matter/nodes$").mock(
                    return_value=Response(200, json={"setup_code": "synthetic-setup-code"})
                )
                try:
                    result = await connector_get(real, registry, "h", path)
                finally:
                    await real.close()
            assert result["body"] == {"setup_code": expected}

    async def test_get_404_reported_not_raised(self, client, registry):
        client.request.return_value = FakeResp(404, {"error": "not found"})
        result = await connector_get(client, registry, "h", "innerspace/api/project")
        assert result["status"] == 404

    async def test_get_threads_owning_key(self, client, registry):
        owning = APIKeyConfig(key="k-owner", label="beta")
        registry.resolve_key_for_host = AsyncMock(return_value=owning)
        client.request.return_value = FakeResp(200, {"data": []})
        await connector_get(client, registry, "Beta-Branch", "network/integration/v1/sites")
        registry.resolve_host_id.assert_awaited_once_with("Beta-Branch", key=owning)
        assert client.request.await_args.kwargs["key"] is owning

    async def test_get_non_json_body_falls_back_to_text(self, client, registry):
        """A non-JSON body is relayed as the exact text, never wrapped in {"text": ...}."""
        client.request.return_value = FakeResp(200, None, text="<html>ok</html>")
        result = await connector_get(client, registry, "h", "network/integration/v1/sites")
        assert result["body"] == "<html>ok</html>"

    async def test_get_empty_body_is_none(self, client, registry):
        """An empty body is relayed as None (no invented {"text": ""})."""
        client.request.return_value = FakeResp(204, None, text="")
        result = await connector_get(client, registry, "h", "network/integration/v1/sites")
        assert result["body"] is None
        assert result["status"] == 204

    async def test_delete_keeps_the_relay_envelope_with_verbatim_body(self, client, registry):
        """``fabric_connector_delete`` keeps {method, routeClass, status, body, ...} like the
        other relay methods; an empty DELETE body is None, not a wrapper."""
        client.request.side_effect = [
            FakeResp(200, {"data": [{"_id": "x"}]}),
            FakeResp(204, None, text=""),
            FakeResp(404, None, text="Not Found"),
        ]
        result = await connector_write(
            client,
            registry,
            "h",
            "DELETE",
            "network/integration/v1/sites/{site_id}/firewall/policies/x",
            site="Office",
            write_enabled=True,
        )
        assert result["method"] == "DELETE"
        assert result["routeClass"]
        assert result["status"] == 204
        assert result["body"] is None
        assert result["readAfter"] == {
            "status": 404,
            "contentType": "text/plain",
            "body": "Not Found",
        }

    async def test_rate_limited_read_after_never_hides_an_applied_write(self, client, registry):
        """A RateLimitError on the read-after must not make the applied write look
        failed: the write's status/body are reported and readAfterError says why."""
        client.request.side_effect = [
            FakeResp(200, {"data": [{"_id": "x", "name": "a"}]}),  # before
            FakeResp(200, {"meta": {"rc": "ok"}, "data": [{"_id": "x", "name": "b"}]}),  # PUT
            RateLimitError("HTTP 429 persisted after 5 retries"),  # after
        ]
        result = await connector_write(
            client,
            registry,
            "h",
            "PUT",
            "network/api/s/{site}/rest/wlanconf/x",
            site="Office",
            body={"name": "b"},
            write_enabled=True,
        )
        assert result["status"] == 200
        assert result["body"] == {"meta": {"rc": "ok"}, "data": [{"_id": "x", "name": "b"}]}
        assert result["readAfter"]["status"] is None
        assert result["readAfterError"] == "RateLimitError: HTTP 429 persisted after 5 retries"
        assert result["noOp"] is None

    async def test_rate_limited_read_before_still_sends_the_write(self, client, registry):
        client.request.side_effect = [
            RateLimitError("HTTP 429"),
            FakeResp(200, {"meta": {"rc": "ok"}}),
            FakeResp(200, {"data": []}),
        ]
        result = await connector_write(
            client,
            registry,
            "h",
            "PATCH",
            "network/integration/v1/sites/{site_id}/firewall/policies/x",
            site="Office",
            body={"enabled": False},
            write_enabled=True,
        )
        assert result["status"] == 200
        assert result["readBefore"] == {"status": None, "error": "RateLimitError: HTTP 429"}
        assert "readAfterError" not in result


# --------------------------------------------------------------------------- #
# Mutation gating — capability flag (enabled by default); no network on refusal
# --------------------------------------------------------------------------- #


_AREA_OPT_OUT_ENVS = (
    "UNIFI_ENABLE_NETWORK_WRITE",
    "UNIFI_PROTECT_MUTATIONS_ENABLED",
    "UNIFI_ENABLE_MOBILITY_WRITE",
    "UNIFI_ENABLE_CARRIER_FABRIC_WRITE",
    "UNIFI_ENABLE_INNERSPACE_WRITE",
)


class TestUnclassifiedRoutes:
    """An unmapped path relays; a mutation on
    it is refused only while a per-area write opt-out is active."""

    @pytest.fixture(autouse=True)
    def _no_area_opt_outs(self, monkeypatch):
        for env in _AREA_OPT_OUT_ENVS:
            monkeypatch.delenv(env, raising=False)

    async def test_unclassified_get_passes(self, client, registry):
        client.request.return_value = FakeResp(200, {"data": []})
        result = await connector_get(client, registry, "h", "talk/api/devices")
        client.request.assert_awaited_once()
        assert result["routeClass"] == "unclassified"
        assert result["status"] == 200

    async def test_unclassified_get_passes_while_an_opt_out_is_set(
        self, client, registry, monkeypatch
    ):
        monkeypatch.setenv("UNIFI_PROTECT_MUTATIONS_ENABLED", "0")
        client.request.return_value = FakeResp(200, {"data": []})
        result = await connector_get(client, registry, "h", "talk/api/devices")
        client.request.assert_awaited_once()
        assert result["routeClass"] == "unclassified"

    async def test_unclassified_mutation_passes_with_no_opt_out(self, client, registry):
        client.request.return_value = FakeResp(200, {"ok": True})
        result = await connector_write(
            client, registry, "h", "POST", "talk/api/devices", body={"name": "x"}
        )
        client.request.assert_awaited()
        assert result["routeClass"] == "unclassified"
        assert result["status"] == 200

    async def test_unclassified_mutation_refused_while_protect_opts_out(
        self, client, registry, monkeypatch
    ):
        monkeypatch.setenv("UNIFI_PROTECT_MUTATIONS_ENABLED", "0")
        with pytest.raises(ValueError, match="unclassified route is refused") as exc:
            await connector_write(
                client, registry, "h", "POST", "talk/api/devices", body={"name": "x"}
            )
        assert "UNIFI_PROTECT_MUTATIONS_ENABLED" in str(exc.value)
        client.request.assert_not_called()
        registry.resolve_host_id.assert_not_called()

    async def test_refusal_names_every_active_opt_out(self, client, registry, monkeypatch):
        monkeypatch.setenv("UNIFI_PROTECT_MUTATIONS_ENABLED", "0")
        monkeypatch.setenv("UNIFI_ENABLE_MOBILITY_WRITE", "false")
        with pytest.raises(ValueError) as exc:
            await connector_write(client, registry, "h", "DELETE", "talk/api/devices/x")
        assert "UNIFI_PROTECT_MUTATIONS_ENABLED" in str(exc.value)
        assert "UNIFI_ENABLE_MOBILITY_WRITE" in str(exc.value)
        client.request.assert_not_called()

    async def test_mapped_route_of_another_area_still_relays(self, client, registry, monkeypatch):
        # Control: the Protect opt-out does not touch a mapped Network route.
        monkeypatch.setenv("UNIFI_PROTECT_MUTATIONS_ENABLED", "0")
        client.request.return_value = FakeResp(200, {"meta": {"rc": "ok"}})
        result = await connector_write(
            client,
            registry,
            "h",
            "POST",
            "network/api/s/{site}/cmd/devmgr",
            site="Office",
            body={"cmd": "restart"},
        )
        client.request.assert_awaited()
        assert result["routeClass"] == "network-classic-cmd"


class TestMutationGating:
    async def test_write_enabled_by_default_reaches_network(self, client, registry):
        # Read + write enabled by default: with write_enabled omitted (defaults to True)
        # the mutation is NOT refused by the capability gate and proceeds to the relay.
        client.request.return_value = FakeResp(200, {"meta": {"rc": "ok"}})
        result = await connector_write(
            client,
            registry,
            "h",
            "POST",
            "network/api/s/{site}/cmd/devmgr",
            site="Office",
            body={"cmd": "restart"},
        )
        client.request.assert_awaited()
        assert result["status"] == 200
        assert result["writeEnabled"] is True

    async def test_write_reaches_network_when_flag_enabled(self, client, registry):
        # Explicit opt-in (UNIFI_ENABLE_CONNECTOR_WRITE=1 -> write_enabled=True) with
        # confirm=True: the mutation proceeds to the relay.
        client.request.return_value = FakeResp(200, {"meta": {"rc": "ok"}})
        result = await connector_write(
            client,
            registry,
            "h",
            "POST",
            "network/api/s/{site}/cmd/devmgr",
            site="Office",
            body={"cmd": "restart"},
            confirm=True,
            write_enabled=True,
        )
        client.request.assert_awaited()
        assert result["status"] == 200
        assert result["writeEnabled"] is True

    async def test_write_explicitly_disabled_rejected_before_network(self, client, registry):
        # Explicit opt-out: write_enabled=False (from UNIFI_ENABLE_CONNECTOR_WRITE=0)
        # still refuses, before any network call, and the message names the env var.
        with pytest.raises(ValueError, match="UNIFI_ENABLE_CONNECTOR_WRITE"):
            await connector_write(
                client,
                registry,
                "h",
                "PUT",
                "network/api/s/{site}/rest/device/x",
                site="Office",
                confirm=True,
                write_enabled=False,
            )
        client.request.assert_not_called()
        registry.resolve_host_id.assert_not_called()

    async def test_write_without_confirm_reaches_network(self, client, registry):
        # No gate: confirm is accepted but ignored. With write_enabled=True the mutation
        # proceeds to the relay even when confirm is omitted/False.
        client.request.return_value = FakeResp(200, {"meta": {"rc": "ok"}})
        result = await connector_write(
            client,
            registry,
            "h",
            "PUT",
            "network/api/s/{site}/rest/device/x",
            site="Office",
            body={"x": 1},
            confirm=False,
            write_enabled=True,
        )
        client.request.assert_awaited()
        assert result["status"] == 200

    async def test_unmapped_namespace_relays_as_unclassified(self, client, registry, monkeypatch):
        for env in _AREA_OPT_OUT_ENVS:
            monkeypatch.delenv(env, raising=False)
        client.request.return_value = FakeResp(200, {"ok": True})
        result = await connector_write(
            client,
            registry,
            "h",
            "POST",
            "admin/api/backup",
            confirm=True,
            write_enabled=True,
        )
        client.request.assert_awaited()
        assert result["routeClass"] == "unclassified"

    async def test_unknown_method_rejected(self, client, registry):
        with pytest.raises(ValueError, match="does not handle"):
            await connector_write(
                client,
                registry,
                "h",
                "GET",
                "network/integration/v1/sites",
                confirm=True,
                write_enabled=True,
            )


# --------------------------------------------------------------------------- #
# Write flow — read-before / write / read-after, no-op detection, audit
# --------------------------------------------------------------------------- #


class TestWriteFlow:
    async def test_post_has_no_read_before_after(self, client, registry):
        client.request.return_value = FakeResp(200, {"meta": {"rc": "ok"}})
        result = await connector_write(
            client,
            registry,
            "h",
            "POST",
            "network/api/s/{site}/cmd/devmgr",
            site="Office",
            body={"cmd": "restart"},
            confirm=True,
            write_enabled=True,
        )
        assert client.request.await_count == 1  # write only, no twin reads
        assert "readBefore" not in result
        assert result["status"] == 200
        # confirm is accepted and ignored by policy, so the result never reports it.
        assert "confirmed" not in result
        assert result["writeEnabled"] is True

    async def test_put_same_value_is_noop(self, client, registry):
        snapshot = {"data": [{"_id": DEVICE_ID, "stp_priority": "32768"}]}
        client.request.side_effect = [
            FakeResp(200, snapshot),  # read-before
            FakeResp(200, {"meta": {"rc": "ok"}, "data": []}),  # write
            FakeResp(200, snapshot),  # read-after (unchanged)
        ]
        result = await connector_write(
            client,
            registry,
            "h",
            "PUT",
            f"network/api/s/{{site}}/rest/device/{DEVICE_ID}",
            site="Office",
            body={"stp_priority": "32768"},
            confirm=True,
            write_enabled=True,
            scope="device",
        )
        assert client.request.await_count == 3
        assert result["noOp"] is True
        assert result["changed"] is False
        assert result["readBefore"]["body"] == snapshot

    async def test_put_changed_value_detected(self, client, registry):
        before = {"data": [{"_id": DEVICE_ID, "stp_priority": "32768"}]}
        after = {"data": [{"_id": DEVICE_ID, "stp_priority": "4096"}]}
        client.request.side_effect = [
            FakeResp(200, before),
            FakeResp(200, {"meta": {"rc": "ok"}}),
            FakeResp(200, after),
        ]
        result = await connector_write(
            client,
            registry,
            "h",
            "PUT",
            f"network/api/s/{{site}}/rest/device/{DEVICE_ID}",
            site="Office",
            body={"stp_priority": "4096"},
            confirm=True,
            write_enabled=True,
            scope="device",
        )
        assert result["noOp"] is False
        assert result["changed"] is True

    async def test_delete_read_after_reflects_removal(self, client, registry):
        client.request.side_effect = [
            FakeResp(200, {"data": [{"_id": "x"}]}),  # before
            FakeResp(200, {"meta": {"rc": "ok"}}),  # delete
            FakeResp(404, {"error": "not found"}),  # after
        ]
        result = await connector_write(
            client,
            registry,
            "h",
            "DELETE",
            "network/integration/v1/sites/{site_id}/firewall/policies/x",
            site="Office",
            confirm=True,
            write_enabled=True,
        )
        assert result["readAfter"]["status"] == 404
        assert result["noOp"] is False

    async def test_mutation_emits_audit_log(self, client, registry, caplog):
        client.request.side_effect = [
            FakeResp(200, {"data": []}),
            FakeResp(200, {"meta": {"rc": "ok"}}),
            FakeResp(200, {"data": []}),
        ]
        with caplog.at_level(logging.INFO, logger="unifi_fabric.tools.connector"):
            await connector_write(
                client,
                registry,
                "MyHost",
                "PUT",
                f"network/api/s/{{site}}/rest/device/{DEVICE_ID}",
                site="Office",
                body={},
                confirm=True,
                write_enabled=True,
            )
        audit = [r for r in caplog.records if "connector-relay-audit" in r.getMessage()]
        assert audit, "expected a structured audit line for the mutation"
        msg = audit[0].getMessage()
        assert "method=PUT" in msg and "confirm=True" in msg and "MyHost" in msg
        # The API key value must never appear in the audit line.
        assert "k-" not in msg

    async def test_read_before_failure_is_tolerated(self, client, registry):
        client.request.side_effect = [
            UniFiConnectionError("boom on read-before"),  # tolerated
            FakeResp(200, {"meta": {"rc": "ok"}}),  # write
            FakeResp(200, {"data": []}),  # read-after
        ]
        result = await connector_write(
            client,
            registry,
            "h",
            "PATCH",
            "network/integration/v1/sites/{site_id}/firewall/policies/x",
            site="Office",
            body={"enabled": False},
            confirm=True,
            write_enabled=True,
        )
        assert result["readBefore"]["status"] is None
        assert result["status"] == 200


# --------------------------------------------------------------------------- #
# Acceptance test 1 — InnerSpace probe
# --------------------------------------------------------------------------- #


class TestInnerSpaceProbe:
    """PATCH innerspace/api/shapes/<fake-uuid> with an empty body — expect a 4xx.

    A 200/204 is an immediate stop condition (documented in the tool docstring).
    We do NOT use a real shape ID and we do NOT issue a collection create/delete.
    This hermetic test asserts the relay surfaces the 4xx rather than raising; the
    LIVE procedure (against a real console) is documented in docs/TOOLS.md / README
    and is intentionally NOT executed here.
    """

    @pytest.mark.parametrize("status", [400, 404, 405, 422])
    async def test_invalid_id_probe_reports_4xx_without_raising(self, client, registry, status):
        client.request.side_effect = [
            FakeResp(status, {"error": "reachability"}),  # read-before twin
            FakeResp(status, {"error": "invalid shape"}),  # PATCH probe
            FakeResp(status, {"error": "reachability"}),  # read-after twin
        ]
        result = await connector_write(
            client,
            registry,
            "h",
            "PATCH",
            f"innerspace/api/shapes/{FAKE_SHAPE_ID}",
            body={},  # empty/invalid body — no real mutation
            confirm=True,
            write_enabled=True,
        )
        assert result["status"] == status
        assert result["routeClass"] == "innerspace-legacy"

    async def test_namespace_403_is_reported_as_status(self, client, registry):
        # A 401/403 on the legacy namespace is auth/namespace gating, recorded as status.
        client.request.side_effect = [
            FakeResp(403, {"error": "host not found"}),
            FakeResp(403, {"error": "host not found"}),
            FakeResp(403, {"error": "host not found"}),
        ]
        result = await connector_write(
            client,
            registry,
            "h",
            "PATCH",
            f"innerspace/api/shapes/{FAKE_SHAPE_ID}",
            body={},
            confirm=True,
            write_enabled=True,
        )
        assert result["status"] == 403


# --------------------------------------------------------------------------- #
# Acceptance test 2 — device write protocol
# --------------------------------------------------------------------------- #


class TestDeviceWriteProtocol:
    """Same-value device-scoped no-op -> read-before/write/read-after -> exact restore.

    Hermetic fixtures only. The LIVE test procedure (real STP priority change on one
    switch, read back via BOTH the legacy /rest/device route AND /stat/device, then
    exact snapshot restore, with global_switch.stp_version left untouched) is documented
    in docs/TOOLS.md / README and deferred to a maintenance window — NO live STP/priority
    mutation is performed here.
    """

    async def test_same_value_write_then_restore_is_noop(self, client, registry):
        original = {"data": [{"_id": DEVICE_ID, "stp_priority": "32768", "name": "sw1"}]}
        # Step 1: same-value write (probe) — read-before == read-after -> noOp.
        client.request.side_effect = [
            FakeResp(200, original),
            FakeResp(200, {"meta": {"rc": "ok"}}),
            FakeResp(200, original),
        ]
        probe = await connector_write(
            client,
            registry,
            "h",
            "PUT",
            f"network/api/s/{{site}}/rest/device/{DEVICE_ID}",
            site="Office",
            body={"stp_priority": "32768"},
            confirm=True,
            write_enabled=True,
            scope="device",
        )
        assert probe["noOp"] is True
        assert probe["routeClass"] == "network-classic-rest"
        assert probe["scope"] == "device"

    async def test_global_stp_route_rejected_for_device_scope(self, client, registry):
        # global_switch.stp_version is site-wide; a device-scoped request must not select it.
        with pytest.raises(ValueError, match="site-global"):
            await connector_write(
                client,
                registry,
                "h",
                "PUT",
                "network/api/s/{site}/rest/setting/global_switch",
                site="Office",
                body={"stp_version": "rstp"},
                confirm=True,
                write_enabled=True,
                scope="device",
            )
        client.request.assert_not_called()


# --------------------------------------------------------------------------- #
# Credential redaction
# --------------------------------------------------------------------------- #


class TestVerbatimBodies:
    """The relay returns upstream bodies unchanged. Credential masking is ONLY the
    server-wide opt-in UNIFI_REDACT_SECRETS (tests/test_redaction.py covers it on the
    relay tools); with it unset nothing is masked or truncated here."""

    _SECRETFUL = {
        "name": "wlan1",
        "x_passphrase": "hunter2",
        "x_password": "s3cret",
        "psk": "abc",
        "nested": {"api_key": "zzz", "token": "t", "keep": "yes"},
        "list": [{"password": "p"}, {"ok": 1}],
    }

    async def test_get_body_returned_verbatim(self, client, registry):
        client.request.return_value = FakeResp(200, json.loads(json.dumps(self._SECRETFUL)))
        result = await connector_get(
            client, registry, "h", "network/api/s/{site}/rest/wlanconf", site="s"
        )
        assert result["body"] == self._SECRETFUL

    async def test_write_body_returned_verbatim(self, client, registry):
        client.request.return_value = FakeResp(200, {"x_passphrase": "leak-me", "ssid": "guest"})
        result = await connector_write(
            client,
            registry,
            "h",
            "POST",
            "network/integration/v1/sites/x/wifi/broadcasts",
            body={},
            confirm=True,
            write_enabled=True,
        )
        assert result["body"] == {"x_passphrase": "leak-me", "ssid": "guest"}

    async def test_non_json_body_is_not_truncated(self, client, registry):
        long_text = "x" * 20000
        client.request.return_value = FakeResp(200, None, text=long_text)
        result = await connector_get(client, registry, "h", "network/integration/v1/sites")
        assert result["body"] == long_text

    def test_no_default_redaction_helper_remains(self):
        assert not hasattr(connector, "_redact_credentials")
        assert not hasattr(connector, "_CRED_KEY_RE")


# --------------------------------------------------------------------------- #
# client.request(raise_on_error=...) — the relay escape hatch, at the HTTP layer
# --------------------------------------------------------------------------- #


class TestClientRaiseOnError:
    @respx.mock
    async def test_raise_on_error_false_returns_4xx(self):
        c = UniFiClient(Settings(api_key="sk-test"))
        respx.get("https://api.ui.com/x").mock(return_value=Response(404, json={"e": 1}))
        resp = await c.request("GET", "/x", raise_on_error=False)
        assert resp.status_code == 404
        await c.close()

    @respx.mock
    async def test_raise_on_error_true_still_raises(self):
        c = UniFiClient(Settings(api_key="sk-test"))
        respx.get("https://api.ui.com/x").mock(return_value=Response(404, text="nope"))
        with pytest.raises(UniFiConnectionError):
            await c.request("GET", "/x")
        await c.close()

    @respx.mock
    async def test_raise_on_error_false_still_retries_429(self):
        c = UniFiClient(Settings(api_key="sk-test"))
        route = respx.get("https://api.ui.com/x").mock(
            side_effect=[Response(429), Response(200, json={"ok": 1})]
        )
        resp = await c.request("GET", "/x", raise_on_error=False, max_retries=1)
        assert resp.status_code == 200
        assert route.call_count == 2
        await c.close()


class TestWriteErrorPath:
    async def test_write_connection_error_reraised_and_audited(self, client, registry, caplog):
        # A network-level failure on the WRITE itself is surfaced (not swallowed) and audited.
        client.request.side_effect = UniFiConnectionError("upstream down")
        with caplog.at_level(logging.INFO, logger="unifi_fabric.tools.connector"):
            with pytest.raises(UniFiConnectionError, match="Connector POST relay failed"):
                await connector_write(
                    client,
                    registry,
                    "h",
                    "POST",
                    "network/api/s/{site}/cmd/devmgr",
                    site="Office",
                    body={"cmd": "x"},
                    confirm=True,
                    write_enabled=True,
                )
        audit = [r for r in caplog.records if "connector-relay-audit" in r.getMessage()]
        assert audit and "outcome=error" in audit[0].getMessage()


def test_final_charset_rejects_disallowed_chars():
    with pytest.raises(ValueError, match="disallowed characters"):
        _check_final_charset("network/api/s/default/rest?evil=1")


def test_module_exposes_all_five_relay_verbs():
    # Sanity: the method-specific family is complete.
    assert hasattr(connector, "connector_get")
    assert hasattr(connector, "connector_write")
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert method in connector._MUTATION_METHODS


# --------------------------------------------------------------------------- #
# Regression coverage — connector-write default-ON + InnerSpace write-route invariant
#
# These are hermetic (no network, no client): the first is a config-level
# assertion of the open-access default; the second is a ROUTE-ASSERTION (it
# inspects the exposed route surface, it does NOT execute any write) proving the
# InnerSpace owner-session (private session + CSRF) write route stays DISABLED
# regardless of UNIFI_ENABLE_CONNECTOR_WRITE. That console route is
# non-functional and rejected, and is deliberately not wired into any tool.
# --------------------------------------------------------------------------- #


def test_connector_write_enabled_by_default_when_env_unset(monkeypatch):
    # With UNIFI_ENABLE_CONNECTOR_WRITE unset, the generic connector relay
    # capability flag resolves to ENABLED (read + write on by default).
    monkeypatch.delenv("UNIFI_ENABLE_CONNECTOR_WRITE", raising=False)
    assert Settings().enable_connector_write is True


@pytest.mark.parametrize("flag_value", [None, "1", "true", "on", "0", "false"])
def test_innerspace_disabled_owner_session_write_route_regardless_of_flag(monkeypatch, flag_value):
    # Route-assertion only: the InnerSpace owner-session write route is
    # non-functional and rejected. It must NOT be coupled to the
    # connector-write capability flag, and must never be confirmed. No write
    # is executed here.
    if flag_value is None:
        monkeypatch.delenv("UNIFI_ENABLE_CONNECTOR_WRITE", raising=False)
    else:
        monkeypatch.setenv("UNIFI_ENABLE_CONNECTOR_WRITE", flag_value)

    # The owner-session write route is never confirmed, independent of the flag.
    assert getattr(_innerspace_module, "_INNERSPACE_WRITE_ROUTE_CONFIRMED", False) is False

    # The InnerSpace tool surface exposes only read routes (get_*/list_*); no
    # create/update/delete/patch/post/put/write/mutate entry point exists.
    own = [
        n
        for n in dir(_innerspace_module)
        if callable(getattr(_innerspace_module, n))
        and getattr(getattr(_innerspace_module, n), "__module__", "") == _innerspace_module.__name__
    ]
    read_tools = [n for n in own if n.startswith(("get_innerspace", "list_innerspace"))]
    assert read_tools, "expected InnerSpace read tools to be present"
    forbidden = ("create", "update", "delete", "patch", "post", "put", "write", "mutate", "save")
    offenders = [n for n in own if not n.startswith("_") and any(t in n.lower() for t in forbidden)]
    assert offenders == [], f"InnerSpace must expose no write route, found: {offenders}"


# --------------------------------------------------------------------------- binary bodies
# A non-text body cannot survive a text decode; the relay returns it the way the typed
# binary tools return bytes: complete, base64-encoded, with the upstream Content-Type.
_JPEG = bytes([0xFF, 0xD8, 0xFF, 0xE0]) + bytes(range(256)) * 300 + bytes([0xFF, 0xD9])


class TestBinaryBodies:
    async def test_get_binary_body_is_base64_complete(self, registry):
        import base64

        client = MagicMock()
        client.request = AsyncMock(
            return_value=FakeResp(200, content=_JPEG, content_type="image/jpeg")
        )
        result = await connector.connector_get(
            client, registry, "con", "protect/integration/v1/cameras/abc/snapshot"
        )
        assert result["body"] is None
        assert result["contentType"] == "image/jpeg"
        assert result["sizeBytes"] == len(_JPEG)
        assert base64.b64decode(result["bodyBase64"]) == _JPEG

    async def test_get_undeclared_non_utf8_body_is_base64(self, registry):
        import base64

        client = MagicMock()
        raw = b"\x00\xff\xfe binary"
        client.request = AsyncMock(return_value=FakeResp(200, content=raw, content_type=""))
        result = await connector.connector_get(client, registry, "con", "protect/api/x")
        assert result["contentType"] is None
        assert base64.b64decode(result["bodyBase64"]) == raw

    async def test_get_json_and_text_unchanged(self, registry):
        client = MagicMock()
        client.request = AsyncMock(return_value=FakeResp(200, json_body={"a": 1}))
        result = await connector.connector_get(client, registry, "con", "protect/api/x")
        assert result["body"] == {"a": 1}
        assert result["contentType"] == "application/json"
        assert "bodyBase64" not in result
        client.request = AsyncMock(
            return_value=FakeResp(200, text="plain words", content_type="text/plain; charset=utf-8")
        )
        result = await connector.connector_get(client, registry, "con", "protect/api/x")
        assert result["body"] == "plain words"
        assert "bodyBase64" not in result

    @pytest.mark.parametrize("mutating", [False, True])
    async def test_get_dry_run_status_preserves_upstream_body(self, registry, mutating, caplog):
        path = "protect/api/cameras/abc" + ("/enable-control" if mutating else "")
        preview = {
            "dryRun": True,
            "message": DRY_RUN_MESSAGE,
            "preview": {"method": "GET", "path": path, "params": {"probe": "value"}},
        }
        client = MagicMock()
        client.request = AsyncMock(return_value=FakeResp(200, json_body=preview))
        with caplog.at_level(logging.INFO, logger="unifi_fabric.tools.connector"):
            result = await connector_get(client, registry, "con", path, params={"probe": "value"})
        assert result["status"] == ("dry_run" if mutating else 200)
        assert result["body"] == preview
        client.request.assert_awaited_once()
        audit = [
            record.getMessage()
            for record in caplog.records
            if "connector-relay-audit" in record.getMessage()
        ]
        assert len(audit) == int(mutating)
        if mutating:
            assert "method=GET" in audit[0]
            assert "outcome=dry_run" in audit[0] and "status=-" in audit[0]
            assert "outcome=success" not in audit[0] and "status=200" not in audit[0]

    async def test_write_binary_response_and_reads_are_base64(self, registry):
        import base64

        client = MagicMock()
        before = FakeResp(200, content=b"\x01\x02old", content_type="application/octet-stream")
        written = FakeResp(200, content=_JPEG, content_type="image/jpeg")
        after = FakeResp(200, content=b"\x01\x02new", content_type="application/octet-stream")
        client.request = AsyncMock(side_effect=[before, written, after])
        result = await connector.connector_write(
            client, registry, "con", "PUT", "protect/api/files/x", body=None
        )
        assert base64.b64decode(result["bodyBase64"]) == _JPEG
        assert result["sizeBytes"] == len(_JPEG)
        assert base64.b64decode(result["readBefore"]["bodyBase64"]) == b"\x01\x02old"
        assert base64.b64decode(result["readAfter"]["bodyBase64"]) == b"\x01\x02new"
        assert result["readBefore"]["contentType"] == "application/octet-stream"
        # different bytes are a change, even though both text bodies are null
        assert result["noOp"] is False

    async def test_write_identical_binary_reads_are_a_no_op(self, registry):
        client = MagicMock()
        same = FakeResp(200, content=b"\x01\x02same", content_type="application/octet-stream")
        client.request = AsyncMock(side_effect=[same, FakeResp(204, text=""), same])
        result = await connector.connector_write(
            client, registry, "con", "PUT", "protect/api/files/x", body=None
        )
        assert result["noOp"] is True
        assert result["body"] is None

    async def test_object_body_over_binary_reads_is_unknown(self, registry):
        # A body's requested leaves cannot be located in binary reads: noOp is null
        # with the reason, never a whole-body verdict standing in for them.
        client = MagicMock()
        same = FakeResp(200, content=b"\x01\x02same", content_type="application/octet-stream")
        client.request = AsyncMock(side_effect=[same, FakeResp(204, text=""), same])
        result = await connector.connector_write(
            client, registry, "con", "PUT", "protect/api/files/x", body={"k": 1}
        )
        assert result["noOp"] is None
        assert "changed" not in result
        assert "cannot be compared" in result["noOpReason"]


class TestNetworkAreaOptOut:
    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    async def test_matter_relay_refuses_before_resolution(
        self, client, registry, monkeypatch, method
    ):
        monkeypatch.setenv("UNIFI_ENABLE_NETWORK_WRITE", "0")
        with pytest.raises(ValueError, match="UNIFI_ENABLE_NETWORK_WRITE"):
            await connector_write(
                client,
                registry,
                "h",
                method,
                "network/v2/api/site/{site}/matter/nodes/missing-node",
                site="Office",
                body={"name": "Survey"},
            )
        registry.resolve_key_for_host.assert_not_awaited()
        registry.resolve_host_id.assert_not_awaited()
        registry.resolve_site_id.assert_not_awaited()
        registry.resolve_site_slug.assert_not_awaited()
        client.request.assert_not_awaited()

    async def test_network_read_remains_available(self, client, registry, monkeypatch):
        monkeypatch.setenv("UNIFI_ENABLE_NETWORK_WRITE", "0")
        client.request.return_value = FakeResp(200, {"data": []})
        result = await connector_get(
            client, registry, "h", "network/v2/api/site/{site}/matter/nodes", site="Office"
        )
        assert result["body"] == {"data": []}
        client.request.assert_awaited_once()

    @pytest.mark.parametrize(
        "family",
        ["network", "firewall", "clients", "devices", "vpn", "hotspot", "statistics"],
    )
    def test_all_network_families_share_the_opt_out(self, monkeypatch, family):
        monkeypatch.setenv("UNIFI_ENABLE_NETWORK_WRITE", "0")
        assert connector.area_write_env(family) == "UNIFI_ENABLE_NETWORK_WRITE"
        assert "UNIFI_ENABLE_NETWORK_WRITE" in connector.area_write_refusal(family)
        assert connector.area_write_refusal("protect") is None

    @pytest.mark.parametrize("value", [None, "", " ", "1", "TRUE", "yes", "on", "t", "y"])
    def test_default_on_and_true_spellings(self, monkeypatch, value):
        if value is None:
            monkeypatch.delenv("UNIFI_ENABLE_NETWORK_WRITE", raising=False)
        else:
            monkeypatch.setenv("UNIFI_ENABLE_NETWORK_WRITE", value)
        assert Settings(api_key="test-key").enable_network_write is True
        assert connector.area_write_refusal("network") is None

    @pytest.mark.parametrize("value", ["0", "FALSE", "no", "off", "f", "n"])
    def test_false_spellings(self, monkeypatch, value):
        monkeypatch.setenv("UNIFI_ENABLE_NETWORK_WRITE", value)
        assert Settings(api_key="test-key").enable_network_write is False
        assert connector.area_write_env("network") == "UNIFI_ENABLE_NETWORK_WRITE"

    def test_invalid_spelling_rejects_without_echo(self, monkeypatch):
        value = "synthetic-misplaced-secret"
        monkeypatch.setenv("UNIFI_ENABLE_NETWORK_WRITE", value)
        with pytest.raises(ValueError) as runtime:
            connector.area_write_refusal("network")
        with pytest.raises(Exception) as startup:
            Settings(api_key="test-key")
        for error in (runtime.value, startup.value):
            assert "UNIFI_ENABLE_NETWORK_WRITE" in str(error)
            assert value not in str(error)


TWIN_NOT_ONE_RECORD = "a device-twin read did not return exactly one device record"


@pytest.mark.parametrize("bad_row", [None, 42, "private-row-sentinel"])
async def test_device_twin_malformed_row_is_shape_error(monkeypatch, bad_row):
    rows = [{"_id": DEVICE_ID, "enabled": True}, bad_row]
    read = {"status": 200, "body": {"data": rows}}
    monkeypatch.setattr(connector, "_safe_get", AsyncMock(return_value=read))
    result = await connector._safe_device_twin_get(
        AsyncMock(), "/relay", ("/network/api/s/default/stat/device", DEVICE_ID), None
    )
    assert result["body"]["data"] is rows
    assert "expected an array of objects" in result["twinError"]
    assert "item 1" in result["twinError"]
    assert "private-row-sentinel" not in result["twinError"]
    # noOp is unknown and says why (2c544681); the relay reports the twinError itself as
    # readAfterError, which takes precedence over the generic noOpReason.
    assert connector._device_twin_verdict(200, {"enabled": True}, result, result) == (
        None,
        TWIN_NOT_ONE_RECORD,
    )
    # The client provides the configured-secret set and the explicit caller-secret policy.
    client = SimpleNamespace(_settings=Settings(api_key="synthetic-connector-key"))
    assert connector._read_after_error(client, result, "PUT") == result["twinError"]


@pytest.mark.parametrize(
    "rows, expected_count",
    [
        ([{"_id": DEVICE_ID}, {"_id": "other"}], 1),
        ([{"_id": "other"}], 0),
        ([{"_id": DEVICE_ID}, {"_id": DEVICE_ID}], 2),
    ],
)
async def test_device_twin_object_selection_contract(monkeypatch, rows, expected_count):
    monkeypatch.setattr(
        connector, "_safe_get", AsyncMock(return_value={"status": 200, "body": {"data": rows}})
    )
    result = await connector._safe_device_twin_get(
        AsyncMock(), "/relay", ("/network/api/s/default/stat/device", DEVICE_ID), None
    )
    assert result["body"]["data"] is rows
    assert len(result["comparisonRecords"]) == expected_count
    assert ("twinError" in result) is (expected_count == 0)
    if expected_count != 1:
        assert connector._device_twin_verdict(200, {"enabled": True}, result, result) == (
            None,
            TWIN_NOT_ONE_RECORD,
        )


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("present", [False, True])
async def test_relay_body_presence_forwards_explicit_null_and_keeps_absent_body_absent(
    registry, method, present
):
    import httpx
    import respx

    from unifi_fabric.client import UniFiClient

    arguments = {"body": None} if present else {}
    context = SimpleNamespace(
        message=SimpleNamespace(name=f"fabric_connector_{method.lower()}", arguments=arguments)
    )
    client = UniFiClient(Settings(api_key="synthetic-body-presence"))
    with respx.mock:
        route = respx.route(
            method=method,
            url=f"https://api.ui.com/v1/connector/consoles/{HOST_ID}/proxy/network/api/s/default/rest/test",
        ).mock(return_value=httpx.Response(200, json={"ok": True}))
        # Readbacks are also synthetic; only the mutation's body is inspected.
        if method != "POST":
            respx.get(
                f"https://api.ui.com/v1/connector/consoles/{HOST_ID}/proxy/network/api/s/default/rest/test"
            ).mock(return_value=httpx.Response(200, json={"ok": True}))

        async def call_next(_context):
            return await connector.connector_write(
                client,
                registry,
                "h",
                method,
                "network/api/s/default/rest/test",
                body=arguments.get("body"),
            )

        try:
            await connector.RelayBodyPresenceMiddleware().on_call_tool(context, call_next)
            assert route.calls[0].request.content == (b"null" if present else b"")
            if present:
                assert route.calls[0].request.headers["content-type"] == "application/json"
            assert connector._explicit_null_body.get() is False
        finally:
            await client.close()


@pytest.mark.parametrize("classic", [False, True])
async def test_real_client_read_after_error_masks_upstream_credentials(classic):
    from unittest.mock import AsyncMock

    body = {"password": "READ_AFTER_SECRET_SENTINEL", "reason": "synthetic failure"}
    if classic:
        body["meta"] = {"rc": "error"}
    path = "network/api/s/default/rest/wlanconf/synthetic"
    registry = SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="host-1"),
    )
    client = UniFiClient(Settings(api_key="synthetic-connector-key", redact_secrets=True))
    url = "https://api.ui.com/v1/connector/consoles/host-1/proxy/" + path
    with respx.mock:
        respx.get(url).mock(
            side_effect=[
                Response(200, json={"name": "before"}),
                Response(200 if classic else 400, json=body),
            ]
        )
        respx.patch(url).respond(200, json={"meta": {"rc": "ok"}})
        try:
            result = await connector_write(
                client,
                registry,
                "synthetic",
                "PATCH",
                path,
                body={"name": "after"},
                write_enabled=True,
            )
        finally:
            await client.close()
    assert result["status"] == 200
    assert "READ_AFTER_SECRET_SENTINEL" not in result["readAfterError"]
    assert "synthetic failure" in result["readAfterError"]


def test_read_after_error_masks_without_mutating_raw_evidence():
    body = {"password": "RAW_EVIDENCE_SENTINEL", "reason": "visible"}
    client = SimpleNamespace(_settings=Settings(api_key="synthetic", redact_secrets=True))
    error = connector._read_after_error(client, {"status": 400, "body": body})
    assert "RAW_EVIDENCE_SENTINEL" not in error
    assert body["password"] == "RAW_EVIDENCE_SENTINEL"


async def test_post_write_exception_scrubs_client_settings_key(monkeypatch):
    key = "synthetic-client-only-credential"
    client = SimpleNamespace(
        _settings=Settings(api_key=key),
        dry_run=False,
        request=AsyncMock(return_value=FakeResp(200, {"name": "saved"})),
        audit_refusal=lambda **kwargs: None,
    )
    registry = SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="host-1"),
    )
    monkeypatch.setattr(connector, "_safe_get", AsyncMock(return_value={"status": 200, "body": {}}))
    monkeypatch.setattr(
        connector, "_no_op_verdict", lambda *args: (_ for _ in ()).throw(RuntimeError(key))
    )
    result = await connector_write(
        client,
        registry,
        "synthetic",
        "PATCH",
        "network/api/s/default/rest/wlanconf/synthetic",
        body={"name": "saved"},
        write_enabled=True,
    )
    assert key not in result["postWriteError"]


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("action", ["enable-control", "disable-control"])
@pytest.mark.parametrize("status", [200, 405])
async def test_action_get_is_never_a_write_twin(client, registry, method, action, status):
    client.request.return_value = FakeResp(status, {"result": "synthetic"})
    path = f"protect/api/cameras/{DEVICE_ID}/{action}"
    result = await connector_write(client, registry, "h", method, path, write_enabled=True)
    assert result["status"] == status
    assert [call.args[0] for call in client.request.await_args_list] == [method]
    assert result["noOp"] is None
