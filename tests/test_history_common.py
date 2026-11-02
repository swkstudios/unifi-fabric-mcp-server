"""translate_host_not_found appends a hint and never replaces the upstream reason."""

from __future__ import annotations

from unifi_fabric.client import UniFiConnectionError, UniFiHTTPError, log_reason
from unifi_fabric.tools._history_common import translate_host_not_found


def test_host_not_found_keeps_full_upstream_message_and_appends_hint():
    upstream = UniFiConnectionError(
        "HTTP 403 from GET /v1/connector/consoles/AABB:1/proxy/network/api/s/x: "
        '{"code":"forbidden","message":"forbidden: host not found"}'
    )
    out = translate_host_not_found(upstream, "AABB")
    assert str(out).startswith(str(upstream))
    assert "Hint:" in str(out) and "'AABB'" in str(out)


def test_other_errors_returned_unchanged():
    upstream = UniFiConnectionError('HTTP 500 from GET /x: {"error":"boom"}')
    assert translate_host_not_found(upstream, "h") is upstream


def test_host_not_found_hint_keeps_error_type_status_and_request_sent():
    upstream = UniFiHTTPError(
        'HTTP 403 from GET /v1/connector/consoles/AABB/proxy/x: {"message":"host not found"}',
        status=403,
        request_sent=True,
    )
    out = translate_host_not_found(upstream, "AABB")
    assert out is not upstream and "Hint:" in str(out)
    assert type(out) is UniFiHTTPError
    assert out.status == 403 and out.request_sent is True
    assert log_reason(out) == "HTTP 403"
