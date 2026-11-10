"""Behavioral regressions for share-link review and shared route extraction."""

from __future__ import annotations

import json

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import upstream_harness as uh
from tests.test_share_link_secret_routes import CAM, LINK, MARKER, REASON, ROUTE, _Upstream
from tests.test_share_link_secret_routes import logs as logs
from tests.test_share_link_secret_routes import wire as wire
from unifi_fabric import route_secrets, server
from unifi_fabric.redaction import REDACTION_MASK

RTSPS = f"protect/integration/v1/cameras/{CAM}/rtsps-stream"


@pytest.fixture
def encoded_wire(wire, monkeypatch):
    original = _Upstream.__call__

    def install(statuses, *, charset="utf-8", empty=False, **settings):
        def respond(upstream, request):
            response = original(upstream, request)
            body = response.json()
            if request.url.path.endswith("/rtsps-stream"):
                body.pop("shareLink", None)
                body.update(
                    {
                        field: f"rtsps://stream.example.invalid/{MARKER}/{field}"
                        for field in ("high", "medium", "low", "package")
                    }
                )
            return httpx.Response(
                response.status_code,
                headers={"Content-Type": f"application/json; charset={charset}"},
                content=b"" if empty else json.dumps(body).encode(charset),
            )

        monkeypatch.setattr(_Upstream, "__call__", respond)
        return wire(statuses, **settings)

    return install


@pytest.mark.parametrize("charset", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("delete_status", [200, 400])
async def test_share_snapshots_follow_success_or_failure_policy(
    encoded_wire, charset, redact, dry_run, delete_status
):
    encoded_wire(
        {"DELETE": delete_status},
        charset=charset,
        redact_secrets=redact,
        write_policy="dry-run" if dry_run else "allow",
    )
    result = uh.result_payload(
        await server.mcp.call_tool("fabric_connector_delete", {"host": "console", "path": ROUTE})
    )
    expected = (
        "***"
        if redact and not dry_run and delete_status != 200
        else REDACTION_MASK
        if redact
        else LINK
    )
    assert result["readBefore"]["body"]["shareLink"] == expected
    if not dry_run and delete_status != 200:
        if redact:
            assert MARKER not in json.dumps(result)
        else:
            assert MARKER in json.dumps(result)
        assert result["noOp"] is None
    if not dry_run:
        assert result["readAfter"]["body"]["shareLink"] == expected
        if delete_status == 200:
            assert result["body"]["shareLink"] == expected
        else:
            if redact:
                assert MARKER not in json.dumps(result["body"])
            else:
                assert MARKER in json.dumps(result["body"])
            assert result["body"]["error"] == REASON


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("charset", ["utf-16", "utf-16-le", "utf-16-be", "iso-8859-1"])
@pytest.mark.parametrize(
    "tool,method",
    [
        ("get_camera_share_link", "GET"),
        ("enable_camera_share_link", "POST"),
        ("disable_camera_share_link", "DELETE"),
        ("fabric_connector_get", "GET"),
        ("fabric_connector_post", "POST"),
        ("fabric_connector_put", "PUT"),
        ("fabric_connector_patch", "PATCH"),
        ("fabric_connector_delete", "DELETE"),
    ],
)
async def test_encoded_share_errors_follow_opt_in(encoded_wire, redact, charset, tool, method):
    encoded_wire({method: 400}, charset=charset, redact_secrets=redact)
    args = (
        {"host": "console", "path": ROUTE}
        if tool.startswith("fabric_")
        else {"host": "console", "camera_id": CAM}
    )
    if tool.startswith("fabric_"):
        payload = uh.result_payload(await server.mcp.call_tool(tool, args))["body"]
        text = json.dumps(payload)
    else:
        with pytest.raises(ToolError) as exc:
            await server.mcp.call_tool(tool, args)
        text = str(exc.value)
    if redact:
        assert MARKER not in text
    else:
        assert MARKER in text
    assert REASON in text


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize(
    "tool,method",
    [
        ("get_rtsps_stream", "GET"),
        ("create_rtsps_stream", "POST"),
        ("delete_rtsps_stream", "DELETE"),
        ("fabric_connector_get", "GET"),
        ("fabric_connector_post", "POST"),
        ("fabric_connector_delete", "DELETE"),
    ],
)
async def test_rtsps_errors_follow_opt_in(encoded_wire, redact, tool, method):
    encoded_wire({method: 400}, redact_secrets=redact)
    args = (
        {"host": "console", "path": RTSPS}
        if tool.startswith("fabric_")
        else {"host": "console", "camera_id": CAM}
    )
    if tool in ("create_rtsps_stream", "delete_rtsps_stream"):
        args["qualities"] = ["high"]
    if tool.startswith("fabric_"):
        text = json.dumps(uh.result_payload(await server.mcp.call_tool(tool, args))["body"])
    else:
        with pytest.raises(ToolError) as exc:
            await server.mcp.call_tool(tool, args)
        text = str(exc.value)
    if redact:
        assert MARKER not in text
    else:
        assert MARKER in text
    assert REASON in text


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize(
    "tool", ["fabric_connector_post", "fabric_connector_put", "fabric_connector_patch"]
)
async def test_dry_run_request_masking_follows_opt_in(encoded_wire, redact, tool):
    encoded_wire({}, write_policy="dry-run", redact_secrets=redact)
    payload = uh.result_payload(
        await server.mcp.call_tool(
            tool, {"host": "console", "path": ROUTE, "body": {"shareLink": LINK}}
        )
    )
    assert payload["body"]["preview"]["body"]["shareLink"] == (REDACTION_MASK if redact else LINK)


@pytest.mark.parametrize("body", [{"enabled": True}, ["item"], "share-status", 42, True, None])
async def test_get_description_matches_structured_shapes(wire, monkeypatch, body):
    wire({})

    def respond(upstream, request):
        upstream.calls.append(request)
        return httpx.Response(200, content=b"") if body is None else httpx.Response(200, json=body)

    monkeypatch.setattr(_Upstream, "__call__", respond)
    result = await server.mcp.call_tool(
        "get_camera_share_link", {"host": "console", "camera_id": CAM}
    )
    if isinstance(body, dict):
        assert result.structured_content == body
    elif isinstance(body, list) or body is None:
        assert result.structured_content == {"result": body}
    else:
        assert result.structured_content is None
        assert result.content and result.content[0].text
    description = (await server.mcp.get_tool("get_camera_share_link")).description
    assert "Object bodies" in description and "{result: null}" in description
    assert "String, integer and boolean bodies have structured_content=None" in description


@pytest.mark.parametrize("redact", [False, True])
async def test_route_redaction_does_not_change_delete_verdict_when_deleted(
    encoded_wire, monkeypatch, redact
):
    """A DELETE confirmed by a 404 read-after reports a change, with or without
    secret redaction (the still-readable case is the test below)."""
    upstream = encoded_wire({}, redact_secrets=redact)
    original = _Upstream.__call__

    def respond(up, request):
        response = original(up, request)
        if request.method == "GET" and len(up.calls) > 1:
            return httpx.Response(404, json={"error": "gone"})
        return httpx.Response(200, json=response.json())

    monkeypatch.setattr(_Upstream, "__call__", respond)
    result = uh.result_payload(
        await server.mcp.call_tool("fabric_connector_delete", {"host": "console", "path": ROUTE})
    )
    assert len(upstream.calls) == 3
    assert [call.method for call in upstream.calls] == ["GET", "DELETE", "GET"]
    assert result["noOp"] is False and result["changed"] is True


@pytest.mark.parametrize("redact", [False, True])
async def test_route_redaction_does_not_change_no_op_verdict(encoded_wire, monkeypatch, redact):
    upstream = encoded_wire({}, redact_secrets=redact)
    original = _Upstream.__call__

    def respond(up, request):
        response = original(up, request)
        body = response.json()
        if request.method == "GET" and len(up.calls) > 1:
            body["shareLink"] = LINK + "-changed"
        return httpx.Response(200, json=body)

    monkeypatch.setattr(_Upstream, "__call__", respond)
    result = uh.result_payload(
        await server.mcp.call_tool("fabric_connector_delete", {"host": "console", "path": ROUTE})
    )
    assert len(upstream.calls) == 3
    assert result["noOp"] is None and "changed" not in result
    assert "still readable after the DELETE" in result["noOpReason"]


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize(
    "tool",
    [
        "get_camera_share_link",
        "enable_camera_share_link",
        "disable_camera_share_link",
        "get_rtsps_stream",
        "create_rtsps_stream",
        "delete_rtsps_stream",
    ],
)
async def test_typed_route_success_masking_follows_opt_in(encoded_wire, redact, tool):
    encoded_wire({}, redact_secrets=redact)
    args = {"host": "console", "camera_id": CAM}
    if tool in ("create_rtsps_stream", "delete_rtsps_stream"):
        args["qualities"] = ["high"]
    payload = uh.result_payload(await server.mcp.call_tool(tool, args))
    text = json.dumps(payload)
    if redact:
        assert MARKER not in text and REDACTION_MASK in text
    else:
        assert MARKER in text


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("charset", ["utf-8", "utf-16"])
@pytest.mark.parametrize("status", [200, 400])
async def test_post_write_failure_always_masks_fallback(
    encoded_wire, monkeypatch, redact, charset, status
):
    import base64

    from unifi_fabric.families.connector import connector

    encoded_wire({"POST": status}, redact_secrets=redact, charset=charset)

    def fail_processing(_response):
        raise RuntimeError(f"synthetic post-write processing failure: {LINK}")

    monkeypatch.setattr(connector, "_relay_body", fail_processing)
    payload = uh.result_payload(
        await server.mcp.call_tool(
            "fabric_connector_post", {"host": "console", "path": ROUTE, "body": {}}
        )
    )
    raw = base64.b64decode(payload["bodyBase64"])
    assert payload["sizeBytes"] == len(raw)
    assert payload["contentType"] == f"application/json; charset={charset}"
    body = json.loads(raw.decode(charset))
    expected = ("***", REDACTION_MASK) if redact else (LINK,)
    assert body["shareLink"] in expected
    if status == 200:
        assert body["cameraId"] == CAM
    else:
        assert body["error"] == REASON
    if redact:
        assert MARKER not in json.dumps(payload)
    else:
        assert MARKER in json.dumps(payload)
    assert "synthetic post-write processing failure" in payload["postWriteError"]


@pytest.mark.parametrize("method", ["DELETE", "PUT", "PATCH", "POST"])
@pytest.mark.parametrize("redact", [False, True])
async def test_failed_write_masks_reason_snapshots_redirect_and_logs(
    wire, logs, monkeypatch, method, redact
):
    wire({}, redact_secrets=redact)

    def respond(upstream, request):
        upstream.calls.append(request)
        if request.method == method:
            return httpx.Response(
                302, headers={"Location": LINK}, json={"error": f"{REASON}: {LINK}"}
            )
        return httpx.Response(200, json={"shareLink": LINK, "enabled": True})

    monkeypatch.setattr(_Upstream, "__call__", respond)
    payload = uh.result_payload(
        await server.mcp.call_tool(
            f"fabric_connector_{method.lower()}", {"host": "console", "path": ROUTE}
        )
    )
    if redact:
        assert MARKER not in json.dumps(payload)
    else:
        assert MARKER in json.dumps(payload)
    assert REASON in json.dumps(payload)
    assert payload["headers"]["location"] == ("***" if redact else LINK)
    assert MARKER not in "\n".join(logs)


@pytest.mark.parametrize("redact", [False, True])
async def test_partial_write_masks_success_body_and_snapshots(wire, monkeypatch, redact):
    wire({}, redact_secrets=redact)

    def respond(upstream, request):
        upstream.calls.append(request)
        status = 400 if request.method == "GET" and len(upstream.calls) > 1 else 200
        return httpx.Response(status, json={"shareLink": LINK, "reason": f"{REASON}: {LINK}"})

    monkeypatch.setattr(_Upstream, "__call__", respond)
    payload = uh.result_payload(
        await server.mcp.call_tool("fabric_connector_delete", {"host": "console", "path": ROUTE})
    )
    assert payload["status"] == 200
    assert payload["noOp"] is None
    assert "readAfterError" in payload
    if redact:
        assert MARKER not in json.dumps(payload)
    else:
        assert MARKER in json.dumps(payload)
    assert REASON in payload["readAfterError"]


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("registered_method", ["GET", "PUT"])
async def test_failed_snapshots_cover_get_only_and_write_only_entries(
    wire, monkeypatch, redact, registered_method
):
    from dataclasses import replace

    from unifi_fabric import route_secrets

    entries = tuple(
        replace(entry, methods=frozenset({registered_method}))
        if entry.name == "protect-share-link"
        else entry
        for entry in route_secrets.ROUTE_SECRETS
    )
    monkeypatch.setattr(route_secrets, "ROUTE_SECRETS", entries)
    wire({"PUT": 400}, redact_secrets=redact)
    payload = uh.result_payload(
        await server.mcp.call_tool("fabric_connector_put", {"host": "console", "path": ROUTE})
    )
    if redact:
        assert MARKER not in json.dumps(payload)
    else:
        assert MARKER in json.dumps(payload)
    expected = "***" if redact else LINK
    assert payload["readBefore"]["body"]["shareLink"] == expected
    assert payload["readAfter"]["body"]["shareLink"] == expected


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("entry", route_secrets.ROUTE_SECRETS, ids=lambda entry: entry.name)
def test_failed_snapshot_envelope_covers_every_registered_route(entry, redact):
    from types import SimpleNamespace

    from unifi_fabric import route_secrets
    from unifi_fabric.config import Settings
    from unifi_fabric.families.connector import connector
    from unifi_fabric.secret_scrub import secret_scope

    method = sorted(entry.methods)[0]
    request = {field: LINK for field in entry.request_fields}
    body = LINK if entry.response_body else {field: LINK for field in entry.response_fields}
    snapshot = {"status": 200, "body": body}
    result = {
        "status": 400,
        "body": body if entry.response_body or entry.response_fields else {"reason": REASON},
        "readBefore": snapshot,
        "readAfter": snapshot,
        "postWriteError": REASON,
        "headers": {field: LINK for field in entry.response_headers},
    }
    client = SimpleNamespace(
        _settings=Settings(api_key="synthetic-share-key", redact_secrets=redact)
    )
    with secret_scope(route_secrets.request_secrets(method, entry.relay_path, request)):
        clean = connector._failed_write_result(client, method, entry.relay_path, result)
    if entry.response_fields or entry.response_body or entry.response_headers:
        if redact:
            assert MARKER not in json.dumps(clean)
        else:
            assert MARKER in json.dumps(clean)
    assert REASON in clean["postWriteError"]
    assert snapshot["body"] == body


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("processing_failure", [False, True])
async def test_failed_undecodable_registered_body_follows_opt_in(
    wire, monkeypatch, processing_failure, redact
):
    import base64

    from unifi_fabric.families.connector import connector

    wire({"POST": 400}, redact_secrets=redact)
    malformed = json.dumps({"shareLink": LINK}).encode("utf-16") + b"x"

    def respond(upstream, request):
        upstream.calls.append(request)
        return httpx.Response(
            400, headers={"Content-Type": "application/json; charset=utf-16"}, content=malformed
        )

    monkeypatch.setattr(_Upstream, "__call__", respond)
    if processing_failure:

        def fail_processing(response):
            raise RuntimeError("synthetic processing failure")

        monkeypatch.setattr(connector, "_relay_body", fail_processing)
    payload = uh.result_payload(
        await server.mcp.call_tool("fabric_connector_post", {"host": "console", "path": ROUTE})
    )
    expected = b"***" if redact else malformed
    assert base64.b64decode(payload["bodyBase64"]) == expected
    assert payload["sizeBytes"] == len(expected)
