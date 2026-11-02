"""ROUTE-SECRET REGISTRY INVARIANT: a route secret is protected identically on every path.

Every entry of :data:`unifi_fabric.route_secrets.ROUTE_SECRETS` is driven through the MCP
surface (``server.mcp.call_tool``) twice: through each typed tool that reaches the route
and through the generic connector relay (``fabric_connector_<method>``) on the same route.
Each check uses a fresh synthetic sentinel (a per-run random hex marker, so every escaped
form is caught by an exact marker search) and a real :class:`UniFiClient` on a mock
transport:

* dry-run: previews mask registered fields only under the redaction opt-in;
* errors and structured data: caller/upstream credentials stay complete unless
  redaction is enabled, for both 2xx and non-2xx responses and raised errors;
* logs and audit records: bound credentials remain masked in every configuration.

A new registry entry is covered automatically for the relay; its typed tools are listed
in :data:`TYPED_CALLS` (the completeness check fails until they are).
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from unifi_fabric import client as client_module
from unifi_fabric import route_secrets, server
from unifi_fabric.client import UniFiClient, _key_fingerprint
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.redaction import REDACTION_MASK
from unifi_fabric.route_secrets import ROUTE_SECRETS, RouteSecret

HOST = "console"
SITE = "default"
MARKER = secrets.token_hex(8)

#: Typed tools per registry entry: (tool name, method it sends, arguments builder taking
#: the request-field sentinel). The Protect share-link typed tools land with the
#: SHARE-FIX lane, which adds their rows here.
TYPED_CALLS: dict[str, list[tuple[str, str, Callable[[str], dict[str, Any]]]]] = {
    "matter-setup-code": [
        (
            "commission_matter_node",
            "POST",
            lambda value: {"host": HOST, "site": SITE, "setup_code": value},
        ),
    ],
    "protect-share-link": [],
}

#: Registered typed tools a registry entry names that have no row in this matrix yet.
#: Their lanes merged after this matrix and test their secret argument in their own module
#: tests; adding a row (with a handler their route accepts) removes the name here. The
#: list may only shrink: a new typed tool on a registry route must add its row.
ROWLESS_TYPED_TOOLS = frozenset(
    {
        "advanced_adopt_device",
        "authorize_lte_device",
        "configure_wifi_wan",
        "connect_cloud_archive_provider",
        "create_dhcp_option",
        "create_hotspot_package",
        "delete_doorbell_credential",
        "enroll_doorbell_credential",
        "get_camera_adoption_qr",
        "get_lte_subscription_status",
        "import_innerspace_shared_project",
        "link_ubiquiti_sso_account",
        "refresh_sso_session",
        "reset_guest_access_settings",
        "send_test_email",
        "set_client_fingerprint_override",
        "set_client_icon",
        "set_cloud_access_registration",
        "set_ups_pairing",
        "update_dhcp_option",
        "update_hotspot_package",
        "update_protect_device_password",
        "verify_sim_pin",
    }
)

TYPED_CALLS = {entry.name: TYPED_CALLS.get(entry.name, []) for entry in ROUTE_SECRETS}

TYPED_CALLS_TOOLS = {tool for rows in TYPED_CALLS.values() for tool, _, _ in rows}

_counter = iter(range(1_000_000))

#: The unpatched request method (each call wraps this, never a previous call's wrapper).
_ORIGINAL_REQUEST = UniFiClient.request


@pytest.fixture
def retry_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record the relay read-before GET's real backoff without wall-clock waits."""
    delays: list[float] = []

    async def record_sleep(delay: float) -> None:
        delays.append(delay)

    # Patch the client's view, not the shared asyncio module used by the server.
    clock = SimpleNamespace(**vars(asyncio))
    clock.sleep = record_sleep
    monkeypatch.setattr(client_module, "asyncio", clock)
    monkeypatch.setattr(
        client_module, "_secure_random", SimpleNamespace(uniform=lambda low, high: high / 2)
    )
    return delays


def _sentinel(kind: str) -> str:
    # Characters escaping and URL-encoding change, behind a marker they never touch.
    return f"{MARKER}{next(_counter)}{kind}/+=x"


def _registry() -> AsyncMock:
    return AsyncMock(
        **{
            "resolve_key_for_host.return_value": APIKeyConfig(key="test-key", label="beta"),
            "resolve_host_id.return_value": HOST,
            "resolve_site_slug.return_value": SITE,
            "resolve_site_id.return_value": SITE,
        }
    )


def _client(handler: Callable[[httpx.Request], httpx.Response], **settings: Any) -> UniFiClient:
    c = UniFiClient(Settings(api_key="test-key", **settings))
    c._clients[("beta", _key_fingerprint("test-key"))] = httpx.AsyncClient(
        base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
    )
    return c


def _relay_args(entry: RouteSecret, method: str, body: Any = None) -> dict[str, Any]:
    args: dict[str, Any] = {"host": HOST, "path": entry.relay_path}
    if "{site" in entry.relay_path:
        args["site"] = SITE
    if body is not None:
        # A GET route carries its request field as a query parameter (the relay's params).
        args["params" if method == "GET" else "body"] = body
    return args


def _calls(entry: RouteSecret, request_value: str) -> list[tuple[str, str, dict[str, Any]]]:
    """Every (tool, method, arguments) reaching ``entry``: typed tools, then the relay."""
    out = [(tool, method, build(request_value)) for tool, method, build in TYPED_CALLS[entry.name]]
    for method in sorted(entry.methods):
        body = {name: request_value for name in entry.request_fields} or None
        relay_tool = f"fabric_connector_{method.lower()}"
        out.append((relay_tool, method, _relay_args(entry, method, body)))
    return out


def _result_text(result: Any) -> str:
    parts = [getattr(item, "text", "") for item in getattr(result, "content", []) or []]
    parts.append(json.dumps(getattr(result, "structured_content", None), default=str))
    return "\n".join(parts)


async def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    tool: str,
    arguments: dict[str, Any],
    handler: Callable[[httpx.Request], httpx.Response],
    after_log: str | None = None,
    result_capture: list[Any] | None = None,
    **settings: Any,
) -> tuple[str, str, bool]:
    """Call ``tool``; return (result-or-error text, audit text, raised)."""
    audit = tmp_path / f"audit-{next(_counter)}.jsonl"
    c = _client(handler, audit_log=str(audit), audit_log_format="json", **settings)
    monkeypatch.setattr(server, "_client", c)
    monkeypatch.setattr(server, "_settings", c._settings)
    monkeypatch.setattr(server, "_registry", _registry())
    if after_log is not None:
        original = _ORIGINAL_REQUEST

        async def request_then_log(self: UniFiClient, *a: Any, **kw: Any) -> Any:
            # A later log line in the same call quoting what the request carried.
            try:
                return await original(self, *a, **kw)
            finally:
                logging.getLogger("unifi_fabric.test").warning("after request: %s", after_log)

        monkeypatch.setattr(UniFiClient, "request", request_then_log)
    try:
        try:
            result = await server.mcp.call_tool(tool, arguments)
        except Exception as exc:  # noqa: BLE001 - the error text is what is checked
            return str(exc), audit.read_text() if audit.exists() else "", True
        if result_capture is not None:
            result_capture.append(result.structured_content)
        return _result_text(result), audit.read_text() if audit.exists() else "", False
    finally:
        await c.close()


def _assert_clean(where: Any, **texts: str) -> None:
    for name, text in texts.items():
        at = text.find(MARKER)
        assert at < 0, (where, name, text[max(0, at - 160) : at + 60])


def _dry_run_handler(req: httpx.Request) -> httpx.Response:
    # The relay's PUT/PATCH/DELETE read-before GET is a read and still runs under
    # dry-run; no write may be sent.
    if req.method != "GET":
        pytest.fail(f"dry-run sent a {req.method}")
    return httpx.Response(200, json={})


def _ids(entry: RouteSecret) -> str:
    return entry.name


async def test_registry_has_typed_call_rows_for_every_entry_and_tool() -> None:
    registered = {tool.name for tool in await server.mcp.list_tools()}
    assert set(TYPED_CALLS) == {entry.name for entry in ROUTE_SECRETS}
    assert set(route_secrets.RELAY_TOOLS) <= registered
    for entry in ROUTE_SECRETS:
        listed = {tool for tool, _, _ in TYPED_CALLS[entry.name]}
        # W0 also names future typed tools; their lanes adopt this wiring later.
        assert set(entry.tool_arguments) & registered - ROWLESS_TYPED_TOOLS <= listed, entry.name
        assert listed <= registered, entry.name
        assert entry in route_secrets.matching(sorted(entry.methods)[0], entry.relay_path)
    unrowed = {
        tool for entry in ROUTE_SECRETS for tool in entry.tool_arguments if tool in registered
    } - TYPED_CALLS_TOOLS
    assert unrowed == ROWLESS_TYPED_TOOLS, "add a row, then drop the tool from the list"


def test_registry_routes_match_console_and_relay_paths() -> None:
    assert {entry.name for entry in ROUTE_SECRETS} == set(TYPED_CALLS)
    assert ROUTE_SECRETS
    for entry in ROUTE_SECRETS:
        for method in entry.methods:
            console = f"/v1/connector/consoles/{HOST}:1/proxy/" + entry.relay_path.replace(
                "{site}", SITE
            )
            assert entry in route_secrets.matching(method, console)
            assert entry in route_secrets.matching(method, "/" + entry.relay_path + "?x=1")
        for method in route_secrets.ALL_METHODS - entry.methods:
            assert entry not in route_secrets.matching(method, entry.relay_path)
        assert route_secrets.matching("POST", entry.relay_path + "/extra/segment/x") == ()


@pytest.mark.parametrize("entry", [e for e in ROUTE_SECRETS if e.request_fields], ids=_ids)
@pytest.mark.parametrize("redact", [False, True])
async def test_dry_run_preview_masks_request_fields(monkeypatch, tmp_path, caplog, entry, redact):
    value = _sentinel("dry")
    calls = _calls(entry, value)
    assert calls, entry.name
    for tool, method, arguments in calls:
        if method == "GET":

            def read_handler(req: httpx.Request) -> httpx.Response:
                assert all(req.url.params.get(name) == value for name in entry.request_fields)
                return httpx.Response(200, json={"ok": True})

            caplog.clear()
            with caplog.at_level(logging.DEBUG):
                text, audit, raised = await _run(
                    monkeypatch,
                    tmp_path,
                    tool,
                    arguments,
                    read_handler,
                    dry_run=True,
                    redact_secrets=redact,
                )
            assert not raised, (tool, text)
            assert "dryRun" not in text
            if entry.verified:
                _assert_clean(tool, audit=audit, logs=caplog.text)
            continue
        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            text, audit, raised = await _run(
                monkeypatch,
                tmp_path,
                tool,
                arguments,
                _dry_run_handler,
                dry_run=True,
                redact_secrets=redact,
            )
        assert not raised, (tool, text)
        assert '"dryRun": true' in text or '"dryRun":true' in text, (tool, text)
        assert (value in text) == (not redact), (tool, text)
        if entry.verified:
            _assert_clean(tool, audit=audit, logs=caplog.text)
        for name in entry.request_fields:
            expected = REDACTION_MASK if redact else value
            assert f'"{name}": "{expected}"' in text or f'"{name}":"{expected}"' in text, (
                tool,
                text,
            )


@pytest.mark.parametrize("entry", [e for e in ROUTE_SECRETS if e.request_fields], ids=_ids)
@pytest.mark.parametrize("status", [429, 500])
@pytest.mark.parametrize("redact", [False, True])
async def test_upstream_errors_echoing_request_fields_are_scrubbed(
    monkeypatch, tmp_path, caplog, entry, status, retry_clock, redact
):
    value = _sentinel("err")
    calls = _calls(entry, value)
    assert calls, entry.name
    for tool, method, arguments in calls:
        requests: list[str] = []
        retry_clock.clear()

        def handler(req: httpx.Request, requests: list[str] = requests) -> httpx.Response:
            requests.append(req.method)
            logging.getLogger("unifi_fabric.test").warning("in flight: %s", value)
            return httpx.Response(status, json={"error": f"bad code {value}", "echo": value})

        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            text, audit, raised = await _run(
                monkeypatch,
                tmp_path,
                tool,
                arguments,
                handler,
                after_log=value,
                redact_secrets=redact,
            )
        _assert_clean((tool, status), audit=audit, logs=caplog.text)
        assert (value in text) is (not redact), (tool, status, text)
        assert "in flight" in caplog.text and "after request" in caplog.text
        if status == 429 or tool in TYPED_CALLS_TOOLS:
            assert raised, (tool, status, text)

        if status == 429:
            if method in {"PUT", "PATCH", "DELETE", "GET"}:
                # Reads retry six times; writes with a read-before then mutate once.
                expected_requests = ["GET"] * 6
                if method != "GET":
                    expected_requests.append(method)
                assert requests == expected_requests, tool
                assert retry_clock == [1.5, 3.0, 6.0, 12.0, 24.0], tool
            else:
                assert requests == [method], tool
                assert retry_clock == [], tool


@pytest.mark.parametrize("entry", [e for e in ROUTE_SECRETS if e.response_fields], ids=_ids)
@pytest.mark.parametrize("redact", [False, True])
async def test_error_bodies_and_their_message_copies_are_scrubbed(
    monkeypatch, tmp_path, caplog, entry, redact
):
    calls = _calls(entry, "dummy-request-value")
    assert calls, entry.name
    for tool, method, arguments in calls:
        value = _sentinel("resp")

        def handler(req: httpx.Request, value: str = value) -> httpx.Response:
            return httpx.Response(400, json={name: value for name in entry.response_fields})

        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            text, audit, raised = await _run(
                monkeypatch,
                tmp_path,
                tool,
                arguments,
                handler,
                after_log=value,
                redact_secrets=redact,
            )
        _assert_clean((tool, method), audit=audit, logs=caplog.text)
        assert "after request" in caplog.text
        if tool in TYPED_CALLS_TOOLS:
            assert raised, (tool, text)
            assert (value in text) is (not redact), (tool, method, text)
        else:
            assert '"status": 400' in text or '"status":400' in text, (tool, text)
            assert (value in text) is (not redact), (tool, method, text)


@pytest.mark.parametrize("entry", [e for e in ROUTE_SECRETS if e.response_headers], ids=_ids)
@pytest.mark.parametrize("redact", [False, True])
async def test_redirect_header_values_are_scrubbed(monkeypatch, tmp_path, caplog, entry, redact):
    """A redirect is never a success: its relayed headers are failed-call output."""
    calls = _calls(entry, "dummy-request-value")
    assert calls, entry.name
    for tool, method, arguments in calls:
        value = _sentinel("loc")
        headers = {
            name: f"https://share.example.invalid/{value}" for name in entry.response_headers
        }

        def handler(req: httpx.Request, headers: dict[str, str] = headers) -> httpx.Response:
            return httpx.Response(302, headers=headers)

        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            text, audit, raised = await _run(
                monkeypatch,
                tmp_path,
                tool,
                arguments,
                handler,
                after_log=" ".join(headers.values()),
                redact_secrets=redact,
            )
        _assert_clean((tool, method), audit=audit, logs=caplog.text)
        assert (value in text) is (not redact), (tool, method, text)
        if tool in TYPED_CALLS_TOOLS:
            assert raised and "302" in text, (tool, text)
        else:
            assert '"status": 302' in text or '"status":302' in text, (tool, text)


@pytest.mark.parametrize("entry", ROUTE_SECRETS, ids=_ids)
async def test_successful_bodies_stay_verbatim(monkeypatch, tmp_path, entry):
    calls = _calls(entry, _sentinel("ok-req"))
    assert calls, entry.name
    for tool, method, arguments in calls:
        value = _sentinel("ok")
        fields = set(entry.request_fields) | set(entry.response_fields)
        body = {name: value for name in fields} or {"value": value}

        def handler(req: httpx.Request, body: dict[str, str] = body) -> httpx.Response:
            return httpx.Response(200, json=body)

        text, _, raised = await _run(monkeypatch, tmp_path, tool, arguments, handler)
        assert not raised, (tool, text)
        assert value in text, (tool, method, text)


def _assert_no_secret_forms(where: Any, *values: str, **texts: str) -> None:
    from unifi_fabric.secret_scrub import secret_forms

    for name, text in texts.items():
        for value in values:
            for form in secret_forms(value):
                assert form not in text, (where, name, form)


@pytest.mark.parametrize(
    "entry", [e for e in ROUTE_SECRETS if e.response_fields or e.request_fields], ids=_ids
)
@pytest.mark.parametrize("status", [200, 400, 500])
@pytest.mark.parametrize("redact", [False, True])
async def test_route_scope_bodies_and_errors_follow_opt_in_but_logs_never_leak(
    monkeypatch, tmp_path, caplog, entry, status, redact
):
    value = _sentinel("structured")
    field = (entry.response_fields or entry.request_fields)[0]
    request_value = value if entry.request_fields else _sentinel("request")
    body = {field: value}

    def handler(req: httpx.Request, body: dict[str, str] = body) -> httpx.Response:
        # Before the upstream body exists, only a request value can be in scope.
        in_flight_value = request_value if req.method != "GET" else _sentinel("not-sent")
        logging.getLogger("unifi_fabric.test").warning("in flight: %s", in_flight_value)
        return httpx.Response(status, json=body)

    calls = _calls(entry, request_value)
    assert calls, entry.name
    for tool, method, arguments in calls:
        caplog.clear()
        captured: list[Any] = []
        with caplog.at_level(logging.DEBUG):
            text, audit, raised = await _run(
                monkeypatch,
                tmp_path,
                tool,
                arguments,
                handler,
                after_log=value,
                result_capture=captured,
                redact_secrets=redact,
            )
        after_logs = "\n".join(
            record.getMessage()
            for record in caplog.records
            if record.getMessage().startswith("after request:")
        )
        _assert_no_secret_forms((entry.name, tool, status), value, logs=after_logs, audit=audit)
        in_flight_logs = "\n".join(
            record.getMessage()
            for record in caplog.records
            if record.getMessage().startswith("in flight:")
        )
        if entry.request_fields and method != "GET":
            _assert_no_secret_forms(
                (entry.name, tool, status), request_value, logs=in_flight_logs, audit=audit
            )
        if raised or status >= 300:
            if redact:
                _assert_no_secret_forms((entry.name, tool, status), value, result=text)
            else:
                assert value in text, (entry.name, tool, status, text)
            continue
        expected = REDACTION_MASK if redact else value
        structured = captured[0]
        data = structured["body"] if tool.startswith("fabric_connector_") else structured
        assert data[field] == expected, (entry.name, tool, status, redact, structured)
        assert f'"{field}": "{expected}"' in text or f'"{field}":"{expected}"' in text, (
            entry.name,
            tool,
            status,
            redact,
            text,
        )


@pytest.mark.parametrize("charset", ["utf-16", "latin-1"])
@pytest.mark.parametrize("status", [200, 400])
@pytest.mark.parametrize("redact", [False, True])
async def test_matter_relay_non_utf8_json_uses_response_secret_chokepoint(
    monkeypatch, tmp_path, caplog, charset, status, redact
):
    """Registered Matter replies apply the same masking rule in every text charset."""
    entry = next(e for e in ROUTE_SECRETS if e.name == "matter-setup-code")
    value = _sentinel(f"{charset}-{status}")
    encoded = json.dumps({"setup_code": value}).encode(charset)

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            content=encoded,
            headers={"content-type": f"application/json; charset={charset}"},
        )

    captured: list[Any] = []
    with caplog.at_level(logging.DEBUG):
        text, audit, raised = await _run(
            monkeypatch,
            tmp_path,
            "fabric_connector_post",
            _relay_args(entry, "POST", {"setup_code": _sentinel("request")}),
            handler,
            after_log=value,
            result_capture=captured,
            redact_secrets=redact,
        )
    assert not raised, text
    _assert_no_secret_forms((charset, status, redact), value, logs=caplog.text, audit=audit)
    structured = captured[0]
    assert structured["status"] == status
    if status >= 300 and redact:
        assert structured["body"]["setup_code"] in ("***", REDACTION_MASK)
        _assert_no_secret_forms((charset, status, redact), value, result=text)
    else:
        assert structured["body"]["setup_code"] == (REDACTION_MASK if redact else value)


def test_tool_call_secrets_cover_typed_arguments_and_relay_bodies() -> None:
    for entry in ROUTE_SECRETS:
        value = _sentinel("args")
        for tool, _, build in TYPED_CALLS[entry.name]:
            if tool in entry.tool_arguments:
                assert value in route_secrets.tool_call_secrets(tool, build(value))
        for method in entry.methods - {"GET"}:
            args = _relay_args(entry, method, {"outer": [{n: value} for n in entry.request_fields]})
            found = route_secrets.tool_call_secrets(f"fabric_connector_{method.lower()}", args)
            assert (value in found) == bool(entry.request_fields), (
                entry.name,
                method,
            )
        # An unregistered route's body is not a route secret.
        assert (
            route_secrets.tool_call_secrets(
                "fabric_connector_post",
                {"path": "network/api/s/{site}/rest/x", "body": {"a": value}},
            )
            == ()
        )


@pytest.mark.parametrize("tool", ["fabric_connector_post", "commission_matter_node"])
@pytest.mark.parametrize("redact", [False, True])
async def test_matter_400_scrubs_relay_body_tool_errors_and_logs(
    monkeypatch, tmp_path, caplog, tool, redact
):
    entry = next(e for e in ROUTE_SECRETS if e.name == "matter-setup-code")
    value = "SYNTHETIC-X"
    body = {"setup_code": value}
    arguments = (
        _relay_args(entry, "POST", body)
        if tool == "fabric_connector_post"
        else {"host": HOST, "site": SITE, "setup_code": value}
    )

    def handler(req: httpx.Request) -> httpx.Response:
        logging.getLogger("unifi_fabric.test").warning("request code: %s", value)
        return httpx.Response(400, json=body)

    captured: list[Any] = []
    with caplog.at_level(logging.DEBUG):
        text, audit, raised = await _run(
            monkeypatch,
            tmp_path,
            tool,
            arguments,
            handler,
            after_log=value,
            result_capture=captured,
            redact_secrets=redact,
        )
    _assert_no_secret_forms(tool, value, logs=caplog.text, audit=audit)
    if tool == "fabric_connector_post":
        assert not raised
        assert captured[0]["status"] == 400
        assert captured[0]["body"] == {"setup_code": "***" if redact else value}
    else:
        assert raised and "HTTP 400" in text
        assert (value in text) is (not redact)


@pytest.mark.parametrize("redact", [False, True])
async def test_failed_write_snapshots_and_read_after_reason_are_scrubbed(
    monkeypatch, tmp_path, caplog, redact
):
    entry = next(e for e in ROUTE_SECRETS if e.name == "protect-share-link")
    values = {
        "before": _sentinel("before"),
        "write": _sentinel("write"),
        "after": _sentinel("after"),
    }
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.method)
        phase = "before" if len(calls) == 1 else "write" if req.method == "PUT" else "after"
        return httpx.Response(200 if phase == "before" else 400, json={"shareLink": values[phase]})

    captured: list[Any] = []
    with caplog.at_level(logging.DEBUG):
        _, audit, raised = await _run(
            monkeypatch,
            tmp_path,
            "fabric_connector_put",
            _relay_args(entry, "PUT", {"shareLink": "request-code"}),
            handler,
            after_log=" ".join(values.values()),
            result_capture=captured,
            redact_secrets=redact,
        )
    assert not raised
    assert calls == ["GET", "PUT", "GET"]
    result = captured[0]
    for phase, data in (
        ("before", result["readBefore"]["body"]),
        ("write", result["body"]),
        ("after", result["readAfter"]["body"]),
    ):
        if redact:
            assert data["shareLink"] in ("***", REDACTION_MASK), (phase, data)
        else:
            assert data["shareLink"] == values[phase]
    _assert_no_secret_forms("failed snapshots", *values.values(), audit=audit)
    assert (values["after"] in result["readAfterError"]) is (not redact)
    # Each response is added to the scope only after its own request; inspect the
    # final post-response log, when all three values have been registered.
    final_log = [
        r.getMessage() for r in caplog.records if r.getMessage().startswith("after request:")
    ][-1]
    _assert_no_secret_forms("failed snapshots", *values.values(), logs=final_log)


# ----------------------------------------------------------------- policy table (H1)
# One row per secret class, through the MCP surface: the server's own configured
# secrets are masked in errors, failed results, logs and audit at every setting; a
# caller-sent credential follows UNIFI_REDACT_SECRETS in error text and failed results
# and is always masked in logs and audit; a dry-run preview echoes the body the caller
# wrote, masking only credential-named or registered fields under the opt-in.

_UNREGISTERED_RELAY_PATH = "network/api/s/{site}/rest/user"


def _typed_sim_pin_args(pin: str) -> dict[str, Any]:
    return {"host": HOST, "site": SITE, "pin": pin}


@pytest.mark.parametrize("tool", ["fabric_connector_post", "verify_sim_pin"])
@pytest.mark.parametrize("redact", [False, True])
async def test_policy_errors_and_failed_results_by_secret_class(
    monkeypatch, tmp_path, caplog, tool, redact
):
    """Configured secret: always masked. Caller-sent: masked only with the opt-in."""
    # A second configured UniFi API key: a server secret, never sent by this call.
    configured = _sentinel("configured")
    pin = _sentinel("pin")
    entry = next(e for e in ROUTE_SECRETS if e.name == "sim-pin")
    arguments = (
        _relay_args(entry, "POST", {"cmd": "lte-verify-pin", "pin": pin})
        if tool == "fabric_connector_post"
        else _typed_sim_pin_args(pin)
    )

    def handler(req: httpx.Request) -> httpx.Response:
        logging.getLogger("unifi_fabric.test").warning("in flight: %s %s", pin, configured)
        return httpx.Response(500, json={"error": f"bad pin {pin}", "echo": configured})

    captured: list[Any] = []
    with caplog.at_level(logging.DEBUG):
        text, audit, raised = await _run(
            monkeypatch,
            tmp_path,
            tool,
            arguments,
            handler,
            after_log=f"{pin} {configured}",
            result_capture=captured,
            redact_secrets=redact,
            api_keys=[APIKeyConfig(key=configured, label="other")],
        )
    # A typed tool raises the error; the relay returns it as a failed result.
    assert raised is (tool == "verify_sim_pin"), (tool, text)
    if not raised:
        assert captured[0]["status"] == 500, captured
    assert "bad pin" in text, text
    _assert_no_secret_forms((tool, redact), configured, result=text)
    assert (pin in text) is (not redact), (tool, redact, text)
    assert "in flight" in caplog.text and "after request" in caplog.text
    _assert_no_secret_forms((tool, redact), pin, configured, logs=caplog.text, audit=audit)


@pytest.mark.parametrize("redact", [False, True])
async def test_policy_dry_run_preview_echoes_the_caller_body(monkeypatch, tmp_path, caplog, redact):
    """Previews scrub configured server secrets; other credential fields are opt-in masked."""
    # A second configured UniFi API key: a server secret, never sent by this call.
    configured = _sentinel("configured")
    password = _sentinel("password")
    ordinary = _sentinel("ordinary")
    arguments = {
        "host": HOST,
        "site": SITE,
        "path": _UNREGISTERED_RELAY_PATH,
        "body": {"note": configured, "x_password": password, "ordinary": ordinary},
    }
    captured: list[Any] = []
    with caplog.at_level(logging.DEBUG):
        text, audit, raised = await _run(
            monkeypatch,
            tmp_path,
            "fabric_connector_post",
            arguments,
            _dry_run_handler,
            result_capture=captured,
            dry_run=True,
            redact_secrets=redact,
            api_keys=[APIKeyConfig(key=configured, label="other")],
        )
    assert not raised, text
    assert '"dryRun": true' in text or '"dryRun":true' in text, text
    assert captured[0]["body"]["preview"]["body"] == {
        "note": "***",
        "x_password": REDACTION_MASK if redact else password,
        "ordinary": ordinary,
    }
    _assert_no_secret_forms(redact, configured, logs=caplog.text, audit=audit)
