"""Route-aware secret-field registry (route_secrets.ROUTE_SECRETS).

Iterates every entry, so a new entry is covered automatically:

* the entry matches its own relay path and the equivalent console path, for its methods;
* listed values are extracted for error/log scrubbing at any depth;
* masking happens ONLY under the UNIFI_REDACT_SECRETS opt-in (default pass-through);
* unrelated routes and unlisted methods are untouched.
"""

from __future__ import annotations

import json

import pytest

from unifi_fabric import route_secrets as rs
from unifi_fabric.secret_scrub import MASK as SCRUB_MASK

SENTINEL = "s3nt1nel-0123456789abcdef"
CONSOLE = "/v1/connector/consoles/HOST:1/proxy/"
IDS = [e.name for e in rs.ROUTE_SECRETS]

REQUIRED = {
    "remote-access-turn-credentials",
    "openvpn-client-config",
    "wireguard-user-keys",
    "teleport-token",
    "ssl-inspection-private-key",
    "protect-device-password",
    "protect-stream-url-token",
    "protect-cloud-archive-credentials",
    "protect-ufv-credentials",
}


def _concrete(relay_path: str) -> str:
    return relay_path.replace("{site}", "default")


def test_required_families_present_and_unique():
    names = [e.name for e in rs.ROUTE_SECRETS]
    assert len(names) == len(set(names))
    assert REQUIRED <= set(names)
    for entry in rs.ROUTE_SECRETS:
        assert entry.relay_path and entry.evidence, entry.name
        assert entry.methods <= rs.ALL_METHODS and entry.methods, entry.name
        assert set(entry.request_path_groups) <= entry._pattern.groupindex.keys()
        assert (
            entry.request_fields
            or entry.response_fields
            or entry.response_log_fields
            or entry.response_body
            or entry.response_headers
            # a credential carried only as a typed tool's path segment (a share token)
            or entry.tool_arguments
        ), entry.name


def test_each_route_field_is_registered_once():
    # A second entry for the same route, method and field adds nothing but drift: the
    # two can diverge (one gains tool_arguments, the other not) while both stay "covered".
    seen: dict[tuple[str, str, str, str], str] = {}
    for entry in rs.ROUTE_SECRETS:
        for method in entry.methods:
            for kind, fields in (
                ("request", entry.request_fields),
                ("response", entry.response_fields),
            ):
                for field in fields:
                    key = (entry.route, method, kind, field)
                    assert key not in seen, f"{entry.name} repeats {seen.get(key)}: {key}"
                    seen[key] = entry.name


@pytest.mark.parametrize("entry", rs.ROUTE_SECRETS, ids=IDS)
def test_entry_matches_relay_and_console_paths(entry):
    for method in entry.methods:
        assert entry.matches(method, entry.relay_path)
        assert entry.matches(method.lower(), CONSOLE + _concrete(entry.relay_path) + "?x=1")
        assert entry in rs.matching(method, "/" + _concrete(entry.relay_path) + "/")
    for method in rs.ALL_METHODS - entry.methods:
        assert not entry.matches(method, entry.relay_path)
    assert not entry.matches(next(iter(entry.methods)), entry.relay_path + "/extra/segment/x")


@pytest.mark.parametrize("entry", rs.ROUTE_SECRETS, ids=IDS)
def test_request_values_extracted_and_masked_only_under_opt_in(entry):
    method = next(iter(sorted(entry.methods)))
    if not entry.request_fields:
        # A response-only or path-only route must preserve unrelated request data.
        body = {"unregistered_test_field": SENTINEL, "keep": "visible"}
        assert rs.request_secrets(method, entry.relay_path, body) == rs.request_path_secrets(
            method, entry.relay_path
        )
        for redact in (False, True):
            assert (
                rs.mask_request_body(method, entry.relay_path, body, redact_secrets=redact) == body
            )
        return
    field = entry.request_fields[0]
    body = {"outer": [{field: SENTINEL, "keep": "visible"}], "name": "n"}
    assert SENTINEL in rs.request_secrets(method, entry.relay_path, body)
    assert rs.mask_request_body(method, entry.relay_path, body, redact_secrets=False) is body
    masked = rs.mask_request_body(method, entry.relay_path, body, redact_secrets=True)
    assert SENTINEL not in json.dumps(masked) and "visible" in json.dumps(masked)
    assert SENTINEL in json.dumps(body)  # the caller's body is never mutated


@pytest.mark.parametrize("entry", rs.ROUTE_SECRETS, ids=IDS)
def test_response_values_extracted_and_masked_only_under_opt_in(entry):
    method = next(iter(sorted(entry.methods)))
    if entry.response_fields:
        field = entry.response_fields[0]
        payload = {"data": [{field: SENTINEL, "other": 1}]}
        content = json.dumps(payload).encode()
        assert SENTINEL in rs.response_secrets(method, entry.relay_path, content, [])
        assert (
            rs.mask_response_body(method, entry.relay_path, payload, redact_secrets=False)
            is payload
        )
        masked = rs.mask_response_body(method, entry.relay_path, payload, redact_secrets=True)
        assert SENTINEL not in json.dumps(masked)
    if entry.response_body:
        text = f"client\nkey {SENTINEL}\n"
        assert text in rs.response_secrets(method, entry.relay_path, text.encode(), [])
        assert rs.mask_response_body(method, entry.relay_path, text, redact_secrets=False) == text
        assert rs.mask_response_body(method, entry.relay_path, text, redact_secrets=True) == rs.MASK
    for header in entry.response_headers:
        got = rs.response_secrets(method, entry.relay_path, b"", [(header.upper(), SENTINEL)])
        assert SENTINEL in got


def test_unlisted_routes_are_untouched():
    body = {"password": SENTINEL, "private_key": SENTINEL}
    for path in ("network/integration/v1/sites/x/networks", CONSOLE + "network/api/s/d/rest/user"):
        assert rs.matching("POST", path) == ()
        assert rs.request_secrets("POST", path, body) == ()
        assert rs.mask_request_body("POST", path, body, redact_secrets=True) is body


def test_relay_tool_arguments_are_extracted():
    path = "network/v2/api/site/{site}/wireguard/abc/users/batch"
    args = {"path": path, "body": [{"name": "p", "private_key": SENTINEL}]}
    # Inferred (unconfirmed) key names bind too: they only add error/log scrubbing.
    assert SENTINEL in rs.tool_call_secrets("fabric_connector_post", args)
    matter = {"path": "network/v2/api/site/{site}/matter/nodes", "body": {"setup_code": SENTINEL}}
    assert rs.tool_call_secrets("fabric_connector_get", matter) == ()  # POST-only route
    assert SENTINEL in rs.tool_call_secrets("fabric_connector_post", matter)
    assert SENTINEL in rs.tool_call_secrets("commission_matter_node", {"setup_code": SENTINEL})


def test_bools_and_blank_values_are_not_secrets():
    path = "protect/api/nvr/device-password"
    assert rs.request_secrets("PATCH", path, {"devicePassword": True}) == ()
    assert rs.request_secrets("PATCH", path, {"devicePassword": "  "}) == ()
    assert rs.request_secrets("PATCH", path, {"devicePassword": 1234}) == ("1234",)


@pytest.mark.parametrize("verified", [False, True])
def test_confirmed_and_inferred_fields_bind(monkeypatch, verified):
    """An inferred (verified=False) key name binds too: binding only adds error/log
    scrubbing, so an unconfirmed name can never leak a value it does carry."""
    from dataclasses import replace

    from unifi_fabric.secret_scrub import configured_secrets, secret_scope

    entry = replace(
        next(e for e in rs.ROUTE_SECRETS if e.name == "matter-setup-code"), verified=verified
    )
    monkeypatch.setattr(rs, "ROUTE_SECRETS", (entry,))
    with secret_scope(()):
        rs.bind_request("POST", entry.relay_path, {"setup_code": SENTINEL})
        assert SENTINEL in configured_secrets()


@pytest.mark.parametrize("value", ["1", "10", "abc", "4821", "12345", "Abcd", "87654321"])
def test_bound_values_are_scrubbed_whatever_their_length(value):
    """A short bound value (a 4-digit SIM PIN) is a secret like a configured one: it is
    scrubbed from free text as a whole token, and text without it is unchanged."""
    from unifi_fabric.secret_scrub import add_call_secrets, configured_secrets, scrub, secret_scope

    with secret_scope(()):
        add_call_secrets((value,))
        assert value in configured_secrets()
        assert value not in scrub(f"rejected code {value} for the device")
        assert scrub("retry 99 of 77") == "retry 99 of 77"
    # Field masking masks a short value too.
    path = next(e for e in rs.ROUTE_SECRETS if e.name == "matter-setup-code").relay_path
    assert rs.mask_request_body("POST", path, {"setup_code": value}, redact_secrets=True) == {
        "setup_code": rs.MASK
    }


def test_add_without_scope_does_not_leak():
    from unifi_fabric.secret_scrub import add_call_secrets, configured_secrets

    add_call_secrets((SENTINEL,))
    assert SENTINEL not in configured_secrets()


@pytest.mark.parametrize("fails", [False, True])
async def test_child_bindings_reach_parent(fails):
    import asyncio

    from unifi_fabric.secret_scrub import add_call_secrets, scrub, secret_scope

    async def child(value, fail):
        add_call_secrets((value,))
        await asyncio.sleep(0)
        if fail:
            raise ValueError("synthetic child failure")

    with secret_scope(()):
        results = await asyncio.gather(
            child(SENTINEL, fails), child("OtherSecretSentinel", False), return_exceptions=True
        )
        assert isinstance(results[0], ValueError) == fails
        assert scrub(f"{SENTINEL} OtherSecretSentinel") == f"{SCRUB_MASK} {SCRUB_MASK}"
    assert scrub(SENTINEL) == SENTINEL


def test_case_sensitive_binding():
    from unifi_fabric.secret_scrub import scrub, secret_scope

    with secret_scope(("AbCdSentinel",)):
        assert scrub("AbCdSentinel abcdsentinel ABCDSENTINEL") == (
            f"{SCRUB_MASK} abcdsentinel ABCDSENTINEL"
        )


def test_repeated_call_text_is_prepared_once(monkeypatch):
    from unifi_fabric import secret_scrub as ss

    original = ss._scrub_view
    calls = []

    def counted(*args):
        calls.append(args)
        return original(*args)

    monkeypatch.setattr(ss, "_scrub_view", counted)
    with ss.secret_scope((SENTINEL,)):
        for _ in range(3):
            assert ss.scrub(SENTINEL) == SCRUB_MASK
        assert len(calls) == 1
        ss.add_call_secrets((SENTINEL,))
        assert ss.scrub(SENTINEL) == SCRUB_MASK
        assert len(calls) == 1
        ss.add_call_secrets(("OtherSecretSentinel",))
        assert ss.scrub(SENTINEL) == SCRUB_MASK
        assert len(calls) == 2


@pytest.mark.parametrize("status", [200, 201, 299, 300, 400, 500])
@pytest.mark.parametrize("verified", [False, True])
def test_response_body_binding_preserves_diagnostics(monkeypatch, status, verified):
    """A whole-body credential binds only for a 2xx (confirmed or inferred entry): an
    error page stays diagnostic text."""
    from dataclasses import replace

    from unifi_fabric.secret_scrub import scrub, secret_scope

    entry = replace(next(e for e in rs.ROUTE_SECRETS if e.response_body), verified=verified)
    monkeypatch.setattr(rs, "ROUTE_SECRETS", (entry,))
    diagnostic = f"<html>diagnostic {SENTINEL}</html>"
    with secret_scope(()):
        rs.bind_response("GET", entry.relay_path, diagnostic.encode(), [], status_code=status)
        assert scrub(diagnostic) == (SCRUB_MASK if 200 <= status < 300 else diagnostic)


@pytest.mark.parametrize("verified", [False, True])
def test_response_fields_and_tool_args_bind_confirmed_or_inferred(monkeypatch, verified):
    from dataclasses import replace

    from unifi_fabric.secret_scrub import configured_secrets, secret_scope

    entry = replace(
        next(e for e in rs.ROUTE_SECRETS if e.name == "matter-setup-code"), verified=verified
    )
    monkeypatch.setattr(rs, "ROUTE_SECRETS", (entry,))
    with secret_scope(()):
        rs.bind_response(
            "POST",
            entry.relay_path,
            json.dumps({"setup_code": SENTINEL}).encode(),
            [],
            status_code=400,
        )
        assert SENTINEL in configured_secrets()
        assert SENTINEL in rs.tool_call_secrets("commission_matter_node", {"setup_code": SENTINEL})


def test_error_body_binds_no_request_field_by_key_name():
    path = "protect/api/cloud-provider/authenticate-device-code"
    body = json.dumps({"code": "api.err.X"}).encode()
    assert rs.response_secrets("POST", path, body, [], status_code=400) == ()
    assert "api.err.X" in rs.response_secrets("POST", path, body, [], status_code=200)


@pytest.mark.parametrize("redact", [False, True])
async def test_standalone_request_scope_follows_opt_in_and_resets(redact):
    import httpx

    from unifi_fabric.client import UniFiClient, UniFiConnectionError, _key_fingerprint
    from unifi_fabric.config import APIKeyConfig, Settings
    from unifi_fabric.secret_scrub import configured_secrets

    key = APIKeyConfig(key="synthetic-api-key", label="scope")
    c = UniFiClient(Settings(api_keys=[key], redact_secrets=redact))

    def handler(request):
        return httpx.Response(500, text=f"invalid setup code {SENTINEL}")

    c._clients[(key.label, _key_fingerprint(key.key))] = httpx.AsyncClient(
        base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
    )
    try:
        with pytest.raises(UniFiConnectionError) as exc:
            await c.request(
                "POST",
                CONSOLE + "network/v2/api/site/default/matter/nodes",
                key=key,
                json={"setup_code": SENTINEL},
            )
        assert (SENTINEL not in str(exc.value)) is redact
        if redact:
            assert SCRUB_MASK in str(exc.value)
        assert SENTINEL not in configured_secrets()
    finally:
        await c.close()


@pytest.mark.parametrize("ends", ["normal", "error", "cancel"])
async def test_top_level_scopes_are_isolated(ends):
    import asyncio

    from unifi_fabric.secret_scrub import scrub, secret_scope

    async def worker(own, other):
        try:
            with secret_scope((own,)):
                await asyncio.sleep(0)
                assert scrub(f"{own} {other}") == f"{SCRUB_MASK} {other}"
                if ends == "error":
                    raise ValueError("synthetic scope exit")
                if ends == "cancel":
                    raise asyncio.CancelledError()
        finally:
            assert scrub(own) == own

    results = await asyncio.gather(
        worker(SENTINEL, "OtherSecretSentinel"),
        worker("OtherSecretSentinel", SENTINEL),
        return_exceptions=True,
    )
    assert not any(isinstance(result, AssertionError) for result in results), results
    assert scrub(SENTINEL) == SENTINEL


async def test_outliving_child_keeps_its_inherited_secrets():
    import asyncio

    from unifi_fabric.secret_scrub import scrub, secret_scope

    ready = asyncio.Event()
    release = asyncio.Event()

    async def child():
        ready.set()
        await release.wait()
        return scrub(SENTINEL)

    with secret_scope((SENTINEL,)):
        task = asyncio.create_task(child())
        await ready.wait()
    assert scrub(SENTINEL) == SENTINEL
    release.set()
    assert await task == SCRUB_MASK


async def test_parent_scrubs_gather_error_before_siblings_finish():
    import asyncio

    from unifi_fabric.secret_scrub import add_call_secrets, scrub, secret_scope

    ready = asyncio.Event()
    release = asyncio.Event()

    async def failing():
        await ready.wait()
        add_call_secrets((SENTINEL,))
        raise ValueError(f"failed {SENTINEL}")

    async def survivor():
        add_call_secrets(("OtherSecretSentinel",))
        ready.set()
        await release.wait()
        return scrub("OtherSecretSentinel")

    task = None
    try:
        with secret_scope(()):
            task = asyncio.create_task(survivor())
            with pytest.raises(ValueError) as exc:
                await asyncio.gather(failing(), task)
            assert scrub(str(exc.value)) == f"failed {SCRUB_MASK}"
            assert scrub("OtherSecretSentinel") == SCRUB_MASK
        assert scrub(SENTINEL) == SENTINEL
        release.set()
        assert await task == SCRUB_MASK
    finally:
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


def test_nested_scope_restores_parent():
    from unifi_fabric.secret_scrub import add_call_secrets, scrub, secret_scope

    with secret_scope((SENTINEL,)):
        with secret_scope(("OtherSecretSentinel",)):
            add_call_secrets(("NestedSecretSentinel",))
            assert scrub(SENTINEL) == SCRUB_MASK
        assert scrub(SENTINEL) == SCRUB_MASK
        assert scrub("OtherSecretSentinel NestedSecretSentinel") == (
            "OtherSecretSentinel NestedSecretSentinel"
        )
    assert scrub(SENTINEL) == SENTINEL


@pytest.mark.parametrize(
    ("method", "path", "argument"),
    [
        (None, "protect/api/bootstrap", "method"),
        (7, "protect/api/bootstrap", "method"),
        ("GET", None, "path"),
        ("GET", {"route": "protect/api/bootstrap"}, "path"),
    ],
)
def test_matching_rejects_malformed_argument_shapes(method, path, argument):
    from unifi_fabric.client import describe_shape

    value = method if argument == "method" else path
    with pytest.raises(ValueError, match=argument) as caught:
        rs.matching(method, path)
    assert describe_shape(value) in str(caught.value)


@pytest.mark.parametrize(
    ("method", "path", "field"),
    [
        ("GET", "network/v2/api/site/default/matter/nodes", "setup_code"),
        ("GET", "protect/api/cameras/camera-id", "shareLink"),
        ("GET", "protect/api/cameras/camera-id", "token"),
        ("PATCH", "protect/api/cameras/camera-id", "shareLink"),
        ("PATCH", "protect/api/cameras/camera-id", "token"),
        ("GET", "protect/api/bootstrap", "shareLink"),
        ("GET", "protect/api/bootstrap", "token"),
        ("GET", "protect/api/cameras/camera-id/sharedStream", "token"),
        ("GET", "protect/api/ws/livestream", "url"),
        ("GET", "protect/api/ws/livestream", "directUrl"),
        ("GET", "protect/api/ws/livestream", "alias"),
        ("GET", "protect/api/video/live", "url"),
        ("GET", "protect/api/video/live", "directUrl"),
        ("GET", "protect/api/video/live", "alias"),
        ("GET", "protect/integration/v1/cameras/camera-id/rtsps-stream", "high"),
        ("GET", "protect/integration/v1/cameras/camera-id/rtsps-stream", "medium"),
        ("GET", "protect/integration/v1/cameras/camera-id/rtsps-stream", "low"),
        ("GET", "protect/integration/v1/cameras/camera-id/rtsps-stream", "package"),
        ("POST", "protect/integration/v1/cameras/camera-id/rtsps-stream", "high"),
        ("POST", "protect/integration/v1/cameras/camera-id/rtsps-stream", "medium"),
        ("POST", "protect/integration/v1/cameras/camera-id/rtsps-stream", "low"),
        ("POST", "protect/integration/v1/cameras/camera-id/rtsps-stream", "package"),
    ],
)
def test_converged_response_secret_fields(method, path, field):
    payload = {"data": [{"streamSharing": {field: SENTINEL}, "unrelated": 1}]}
    assert SENTINEL in rs.response_secrets(method, path, json.dumps(payload).encode(), [])
    assert rs.mask_response_body(method, path, payload, redact_secrets=False) is payload
    assert SENTINEL not in json.dumps(
        rs.mask_response_body(method, path, payload, redact_secrets=True)
    )


@pytest.mark.parametrize(
    "path",
    [
        "network/v2/api/ups/pair",
        "network/api/s/default/cmd/devmgr",
    ],
)
def test_converged_request_password_fields(path):
    body = {"cmd": "adv-adopt", "password": SENTINEL}
    assert SENTINEL in rs.request_secrets("POST", path, body)
    assert rs.mask_request_body("POST", path, body, redact_secrets=False) is body
    assert SENTINEL not in json.dumps(rs.mask_request_body("POST", path, body, redact_secrets=True))


@pytest.mark.parametrize("first", ["unifi_fabric.client", "unifi_fabric.route_secrets"])
def test_registry_client_import_orders(first):
    import subprocess
    import sys

    second = "unifi_fabric.route_secrets" if first.endswith("client") else "unifi_fabric.client"
    subprocess.run(  # noqa: S603 -- fixed package modules, no external inputs.
        [
            sys.executable,
            "-c",
            "import importlib, sys; [importlib.import_module(x) for x in sys.argv[1:]]",
            first,
            second,
        ],
        check=True,
        capture_output=True,
    )


@pytest.mark.parametrize("entry", rs.ROUTE_SECRETS, ids=lambda e: e.name)
def test_all_entries_bind_registered_values(entry):
    from unifi_fabric.secret_scrub import configured_secrets, secret_scope

    assert entry.methods, entry.name

    for method in entry.methods:
        with secret_scope(()):
            body = {"data": [{name: SENTINEL for name in entry.request_fields}]}
            rs.bind_request(method, entry.relay_path, body)
            assert (SENTINEL in configured_secrets()) == bool(entry.request_fields)
        with secret_scope(()):
            payload = {"data": [{name: SENTINEL for name in entry.response_fields}]}
            headers = [(name, SENTINEL) for name in entry.response_headers]
            content = SENTINEL.encode() if entry.response_body else json.dumps(payload).encode()
            rs.bind_response(method, entry.relay_path, content, headers, status_code=200)
            assert (SENTINEL in configured_secrets()) == bool(
                entry.response_fields or entry.response_headers or entry.response_body
            )


@pytest.mark.parametrize("entry", rs.ROUTE_SECRETS, ids=IDS)
@pytest.mark.parametrize("charset", ["utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "iso-8859-1"])
def test_registered_response_secrets_follow_declared_charset(entry, charset):
    method = next(iter(sorted(entry.methods)))
    headers = [("Content-Type", f'application/json; charset="{charset}"')]
    if entry.response_fields:
        payload = {"outer": [{entry.response_fields[0]: SENTINEL}]}
        content = json.dumps(payload).encode(charset)
        assert SENTINEL in rs.response_secrets(method, entry.relay_path, content, iter(headers))
    if entry.response_body:
        text = f"client key {SENTINEL}"
        assert rs.response_secrets(method, entry.relay_path, text.encode(charset), iter(headers))


@pytest.mark.parametrize("charset", ["unknown-codec", "base64", "rot13"])
def test_unusable_charset_is_not_guessed(charset):
    path = "protect/api/cameras/cam/sharedStream"
    content = json.dumps({"shareLink": SENTINEL}).encode()
    assert (
        rs.response_secrets(
            "GET", path, content, [("content-type", f"application/json; charset={charset}")]
        )
        == ()
    )


@pytest.mark.parametrize("charset", ["utf-8", "utf-16"])
def test_whole_configuration_json_string_is_extracted(charset):
    path = "network/v2/api/site/default/vpn/openvpn/id/configuration"
    content = json.dumps(SENTINEL).encode(charset)
    headers = [("content-type", f"application/json; charset={charset}")]
    assert SENTINEL in rs.response_secrets("GET", path, content, headers)


@pytest.mark.parametrize("kind", ["nfc", "fingerprint"])
def test_relay_delete_binds_credential_path_for_audit(kind):
    path = f"protect/api/cameras/fixture-camera/{kind}/{SENTINEL}"
    assert SENTINEL in rs.tool_call_secrets("fabric_connector_delete", {"path": path})
    assert SENTINEL in rs.request_secrets("DELETE", CONSOLE + path, None)
    assert SENTINEL not in rs.mask_request_path("DELETE", path, redact_secrets=True)
    assert rs.mask_request_path("DELETE", path, redact_secrets=False) == path
    assert rs.request_path_secrets("POST", path) == ()


@pytest.mark.parametrize("redact", [False, True])
async def test_voucher_code_is_logged_scrubbed_but_always_returned(redact, caplog):
    import logging

    import respx

    from unifi_fabric.client import UniFiClient
    from unifi_fabric.config import Settings
    from unifi_fabric.redaction import CREDENTIAL_FIELDS
    from unifi_fabric.secret_scrub import secret_scope

    path = (
        "/v1/connector/consoles/host-1/proxy/network/integration/v1/sites/site-1/hotspot/vouchers"
    )
    body = {"data": [{"code": SENTINEL}]}
    assert "code" not in CREDENTIAL_FIELDS
    with secret_scope(), respx.mock:
        respx.get("https://api.ui.com" + path).respond(200, json=body)
        client = UniFiClient(Settings(api_key="synthetic-voucher-key", redact_secrets=redact))
        try:
            assert await client.get(path) == body
            with caplog.at_level(logging.WARNING):
                logging.getLogger("voucher-regression").warning("voucher %s", SENTINEL)
            assert SENTINEL not in caplog.text
        finally:
            await client.close()


def test_classic_networkconf_openvpn_binding_and_opt_in():
    from unifi_fabric.redaction import redact_credentials

    path = "network/api/s/default/rest/networkconf/0000000000000000000000aa"
    body = {"openvpn_configuration": SENTINEL, "name": "synthetic"}
    assert SENTINEL in rs.response_secrets(
        "GET", path, json.dumps(body).encode(), [("content-type", "application/json")]
    )
    assert redact_credentials(body)["openvpn_configuration"] == rs.MASK


def test_error_formatter_masks_nested_upstream_objects_without_mutation():
    from unifi_fabric.client import upstream_error_text, wrong_type_error
    from unifi_fabric.redaction import write_redaction_scope

    body = {"password": SENTINEL, "reason": "visible"}
    with write_redaction_scope(True):
        assert SENTINEL not in upstream_error_text(body)
        assert SENTINEL not in str(wrong_type_error("upstream", body))
    assert body["password"] == SENTINEL
    with write_redaction_scope(False):
        assert SENTINEL in upstream_error_text(body)
