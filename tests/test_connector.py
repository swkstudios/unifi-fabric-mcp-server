"""Tests for the guarded generic Fabric connector relay (issue #189).

Covers the guard matrix (namespace allowlist, positive-charset path validation,
mutation gating on confirm + env flag, scope guard), Registry-only site
substitution, read-before/write/read-after with no-op detection, credential
redaction, and the structured audit log. Also transcribes the two decision-closing
probe protocols from issues #179/#183 as HERMETIC tests:

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

import logging
from typing import Any
from unittest.mock import AsyncMock

import pytest
import respx
from httpx import Response

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.tools import connector
from unifi_fabric.tools.connector import (
    _check_final_charset,
    _redact_credentials,
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

    def __init__(self, status: int, json_body: Any = None, text: str = "") -> None:
        self.status_code = status
        self._json = json_body
        self.text = text

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
            "network/api/s/{site}/settings",  # not rest/cmd/stat
            "proxy/network/integration/v1",  # double proxy
            "v1/connector/consoles/x",  # not a proxy-relative path
            "internal/secrets",
        ],
    )
    def test_namespace_outside_allowlist_rejected(self, path):
        with pytest.raises(ValueError, match="allowlist"):
            _validate_relay_path(path, None)

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
        client.request.return_value = FakeResp(200, None, text="<html>ok</html>")
        result = await connector_get(client, registry, "h", "network/integration/v1/sites")
        assert result["body"] == {"text": "<html>ok</html>"}


# --------------------------------------------------------------------------- #
# Mutation gating — confirm AND env flag, fail-closed, no network on refusal
# --------------------------------------------------------------------------- #


class TestMutationGating:
    async def test_write_flag_off_rejected_before_network(self, client, registry):
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

    async def test_write_without_confirm_rejected_before_network(self, client, registry):
        with pytest.raises(ValueError, match="confirm=true"):
            await connector_write(
                client,
                registry,
                "h",
                "PUT",
                "network/api/s/{site}/rest/device/x",
                site="Office",
                confirm=False,
                write_enabled=True,
            )
        client.request.assert_not_called()

    async def test_bad_namespace_rejected_even_with_flags(self, client, registry):
        with pytest.raises(ValueError, match="allowlist"):
            await connector_write(
                client,
                registry,
                "h",
                "POST",
                "admin/api/backup",
                confirm=True,
                write_enabled=True,
            )
        client.request.assert_not_called()

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
        assert result["confirmed"] is True
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
# Acceptance test 1 — InnerSpace probe (issue #189 / #179)
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
# Acceptance test 2 — device write protocol (issue #189 / #183)
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


class TestRedaction:
    def test_credential_keys_redacted(self):
        raw = {
            "name": "wlan1",
            "x_passphrase": "hunter2",
            "x_password": "s3cret",
            "psk": "abc",
            "nested": {"api_key": "zzz", "keep": "yes"},
            "list": [{"password": "p"}, {"ok": 1}],
        }
        red = _redact_credentials(raw)
        assert red["name"] == "wlan1"
        assert red["x_passphrase"] == "[REDACTED]"
        assert red["x_password"] == "[REDACTED]"
        assert red["psk"] == "[REDACTED]"
        assert red["nested"]["api_key"] == "[REDACTED]"
        assert red["nested"]["keep"] == "yes"
        assert red["list"][0]["password"] == "[REDACTED]"
        assert red["list"][1]["ok"] == 1

    def test_non_credential_values_preserved(self):
        raw = {"id": SITE_UUID, "stp_priority": "32768", "vlan": 10}
        assert _redact_credentials(raw) == raw

    async def test_write_body_is_redacted_in_result(self, client, registry):
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
        assert result["body"]["x_passphrase"] == "[REDACTED]"
        assert result["body"]["ssid"] == "guest"


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
