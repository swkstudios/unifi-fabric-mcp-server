"""Audit records: default path masking, route templates, closed reasons and ``ref``."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import pytest

from tests._synthetic_secrets import synth
from unifi_fabric import audit
from unifi_fabric.audit import AuditSink
from unifi_fabric.audit_vocabulary import PATH_MASK, mask_path, reason_code, route_template
from unifi_fabric.catalog.membership import family_index
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.connector import connector
from unifi_fabric.generated_api_facts.route_manifest import MANIFEST
from unifi_fabric.route_secrets import ROUTE_SECRETS

#: Credential-shaped values of the kinds a relay path segment can carry.
CREDENTIALS = (
    "Ab3xYz9Secret0TokenAb3xYz",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # 32 lowercase letters, hex-range only
    "0123456789abcdef0123456789abcdef01234567",  # 40 hex digits
    "correcthorsebatterystaple",
    "S3cr3t.value-with~chars",
)
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
OBJECT_ID = "00aabbccddeeff0011223344"
UUID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
MAC = "aa:bb:cc:dd:ee:ff"


def _connector_write_routes() -> list[tuple[str, str, str]]:
    """Every connector relay route a typed tool writes to, from the generated manifest."""
    routes: list[tuple[str, str, str]] = []
    for tool, entries in MANIFEST["tools"].items():
        for entry in entries:
            path = entry.get("path") or ""
            if entry["method"] in WRITE_METHODS and "/proxy/" in path:
                routes.append((tool, entry["method"], path))
    return routes


def _filled(path: str, value: str) -> str:
    out = []
    for segment in path.split("/"):
        if segment.startswith("{") and segment.endswith("}"):
            out.append(
                "default"
                if segment == "{site}"
                else "abc:123"
                if segment == "{console_id}"
                else value
            )
        else:
            out.append(segment)
    return "/".join(out)


CONNECTOR_WRITES = _connector_write_routes()


def test_the_manifest_has_connector_write_routes_to_prove():
    assert len(CONNECTOR_WRITES) > 300


@pytest.mark.parametrize("credential", CREDENTIALS)
def test_a_credential_in_any_connector_write_route_segment_is_masked(credential):
    """Every connector write route, whether or not it is registered as carrying a secret."""
    for tool, method, template in CONNECTOR_WRITES:
        if not any(
            p in template
            for p in (
                "{id}",
                "{internal_path}",
                "{path}",
                "{filename}",
                "{slot}",
                "{app}",
                "{at}",
                "{source}",
                "{port_idx}",
                "{client_ip}",
            )
        ):
            continue
        path = _filled(template, credential)
        masked = mask_path(path)
        assert credential not in masked, (tool, method, template, masked)
        assert PATH_MASK in masked, (tool, method, template, masked)


@pytest.mark.parametrize("identifier", [OBJECT_ID, UUID, MAC, "12", "192.168.1.20"])
def test_validated_identifiers_stay_so_the_audit_path_stays_useful(identifier):
    for _tool, _method, template in CONNECTOR_WRITES:
        if "{id}" not in template:
            continue
        path = _filled(template.replace("{console_id}", "abc:123"), identifier)
        assert identifier in mask_path(path), (template, mask_path(path))


def test_route_words_sites_and_consoles_stay():
    assert mask_path(
        f"/v1/connector/consoles/70A7415CB2C6:123456/proxy/network/api/s/default/rest/networkconf/{OBJECT_ID}"
    ) == (
        f"/v1/connector/consoles/70A7415CB2C6:123456/proxy/network/api/s/default/rest/networkconf/{OBJECT_ID}"
    )
    assert (
        mask_path("network/api/s/{site}/rest/networkconf")
        == "network/api/s/{site}/rest/networkconf"
    )


def test_a_registered_credential_route_is_still_listed():
    """A UUID share token stays protected: the caller scrubs it by name first."""
    names = {entry.name for entry in ROUTE_SECRETS if entry.request_path_groups}
    assert "innerspace-shared-project-token" in names


def test_unregistered_route_segment_masked_on_the_real_relay_log_line(caplog):
    """An unregistered relay path, through the real ``_audit_mutation``."""
    secret = "Ab3xYz9Secret0TokenAb3xYz"
    path = f"/proxy/network/api/s/default/rest/user/{secret}"
    with caplog.at_level(logging.INFO, logger=connector.__name__):
        connector._audit_mutation("host-1", "default", "POST", path, True, "success", 200)
    text = caplog.text
    assert "connector-relay-audit" in text
    assert secret not in text
    assert "path=/proxy/network/api/s/default/rest/user/***" in text


def test_registered_uuid_token_is_scrubbed_before_the_shape_mask(caplog):
    """A UUID share token is an identifier shape, so only the registered route protects it."""
    path = f"/proxy/innerspace/api/import/projects/{UUID}"
    with caplog.at_level(logging.INFO, logger=connector.__name__):
        connector._audit_mutation("host-1", None, "POST", path, True, "success", 200)
    assert UUID not in caplog.text


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_unregistered_segment_masked_in_the_audit_stream(tmp_path, fmt):
    log = tmp_path / "audit.log"
    sink = AuditSink(path=str(log), fmt=fmt)
    secret = "Ab3xYz9Secret0TokenAb3xYz"
    sink.record(
        method="PUT",
        path=f"/v1/connector/consoles/abc:1/proxy/network/api/s/default/rest/user/{secret}",
        outcome="success",
        status=200,
    )
    text = log.read_text()
    assert secret not in text
    assert "/rest/user/***" in text


# ------------------------------------------------------------------------ route templates
def test_every_tool_has_a_unique_well_formed_template():
    templates = {tool: route_template(tool) for tool in family_index()}
    pattern = re.compile(r"[a-z0-9_]+\.[a-z0-9_]+\.[a-z0-9_]+")
    assert all(t and pattern.fullmatch(t) for t in templates.values()), [
        (k, v) for k, v in templates.items() if not (v and pattern.fullmatch(v))
    ]
    assert len(set(templates.values())) == len(templates)


def test_template_examples():
    assert route_template("create_firewall_policy") == "firewall.policies.create"
    assert route_template("fabric_connector_post") == "connector.relay.post"


@pytest.mark.parametrize("name", [None, "", "not_a_known_tool", "../../etc/passwd"])
def test_an_unknown_tool_has_no_template(name):
    assert route_template(name) is None


# ---------------------------------------------------------------- reasons and correlation
@pytest.mark.parametrize(
    "reason",
    [
        "UNIFI_WRITE_POLICY",
        "family:protect=deny",
        "tool:create_network=deny",
        "empty_update",
        "unsafe_path",
        "masked_body",
        "write_denied",
        "missing_api_key_header",
    ],
)
def test_known_reasons_are_codes(reason):
    assert reason_code(reason) == (reason, None)


@pytest.mark.parametrize(
    "reason",
    ["family:not-a-family=deny", "tool:nope=deny", "free text about password=hunter2", "x=y"],
)
def test_free_text_reasons_become_other_with_the_text_for_the_log(reason):
    assert reason_code(reason) == ("other", reason)


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_free_text_reason_stays_out_of_the_record_and_in_the_log_under_ref(tmp_path, caplog, fmt):
    log = tmp_path / "audit.log"
    sink = AuditSink(path=str(log), fmt=fmt)
    secret = "Ab3xYz9Secret0TokenAb3xYz"
    text_reason = f"Unsafe thing happened with {secret} '/p/q?a={secret}'"
    with caplog.at_level(logging.INFO, logger=audit.__name__), audit.audit_call("create_network"):
        sink.record(
            method="POST", path="/sites", outcome="refused", status=None, reason=text_reason
        )
    line = log.read_text()
    assert secret not in line
    ref = re.search(r'"ref":"([0-9a-f-]+)"|ref=([0-9a-f-]+)', line)
    assert ref is not None
    found = ref.group(1) or ref.group(2)
    detail = [r.getMessage() for r in caplog.records if "audit reason detail" in r.getMessage()]
    assert detail and f"ref={found}" in detail[0]
    assert "reason" in line and "other" in line
    if fmt == "json":
        rec = json.loads(line)
        assert rec["reason"] == "other"
        assert rec["route_template"] == route_template("create_network")


def test_one_ref_for_the_whole_tool_call(tmp_path: Path):
    log = tmp_path / "audit.log"
    sink = AuditSink(path=str(log), fmt="json")
    with audit.audit_call("create_network"):
        sink.record(method="POST", path="/sites", outcome="refused", status=None, reason="x")
        sink.record(method="POST", path="/sites", outcome="success", status=200)
    with audit.audit_call("delete_network"):
        sink.record(method="DELETE", path="/sites", outcome="success", status=200)
    recs = [json.loads(line) for line in log.read_text().splitlines()]
    assert recs[0]["ref"] == recs[1]["ref"] != recs[2]["ref"]


def test_exception_text_of_an_error_record_stays_debug_only(tmp_path: Path):
    """The error message is written at debug, never at normal."""
    secret = "Ab3xYz9Secret0TokenAb3xYz"
    for level, expected in (("normal", False), ("debug", True)):
        log = tmp_path / f"{level}.log"
        sink = AuditSink(path=str(log), fmt="json", level=level, calls=True)
        sink.error("create_network", ValueError(f"boom {secret[:6]}"))
        rec = json.loads(log.read_text().strip())
        assert ("message" in rec) is expected, rec


# ---------------------------------------------------- positions are anchored, not patterns
SYNTHETIC = "Ab3xYz9Secret0TokenAb3xYz"
SHORT_SYNTHETIC = "abc123secret"  # fits the site-slug shape


@pytest.mark.parametrize(
    "path",
    [
        f"/proxy/network/api/s/default/connector/consoles/{SYNTHETIC}",
        f"/proxy/network/v1/hosts/{SYNTHETIC}",
        f"/proxy/network/ea/hosts/{SYNTHETIC}",
        f"/v1/connector/consoles/abc/proxy/network/api/s/default/rest/connector/consoles/{SYNTHETIC}",
    ],
)
def test_console_and_host_words_mid_path_keep_nothing(path):
    assert SYNTHETIC not in mask_path(path)


@pytest.mark.parametrize(
    "path",
    [
        f"/proxy/network/rest/api/s/{SHORT_SYNTHETIC}",
        f"/proxy/network/api/s/default/api/s/{SHORT_SYNTHETIC}",
        f"/proxy/network/rest/v1/sites/{SHORT_SYNTHETIC}",
    ],
)
def test_a_site_position_counts_only_right_after_the_app(path):
    assert SHORT_SYNTHETIC not in mask_path(path)


@pytest.mark.parametrize(
    "path",
    [f"/v1/connector/consoles/{SYNTHETIC}/x", f"/v1/hosts/{SYNTHETIC}", f"/ea/hosts/{SYNTHETIC}"],
)
def test_a_relay_path_never_holds_a_console_or_host_position(path, caplog):
    assert SYNTHETIC not in mask_path(path, relay=True)
    with caplog.at_level(logging.INFO, logger=connector.__name__):
        connector._audit_mutation("host-1", None, "POST", path, True, "success", 200)
    assert SYNTHETIC not in caplog.text


def test_the_server_built_positions_stay():
    console = "70A7415CB2C6:123456"
    for path in (
        f"/v1/connector/consoles/{console}/proxy/network/api/s/default/rest/networkconf",
        f"/v1/connector/consoles/{console}/proxy/network/v2/api/site/default/trafficrules",
        f"/v1/connector/consoles/{console}/proxy/network/integration/v1/sites/default/networks",
        f"/v1/hosts/{console}",
        f"/ea/hosts/{console}",
    ):
        assert mask_path(path) == path


# -------------------------------------------- upstream text in the log has no credentials
LOGGED_SECRET = synth("passphrase")


@pytest.mark.parametrize("redact", [False, True])
async def test_an_echoed_credential_is_not_logged_with_the_upstream_error(tmp_path, caplog, redact):
    client = UniFiClient(
        Settings(api_key="synthetic-only", audit_log=str(tmp_path / "a.log"), redact_secrets=redact)
    )
    body = json.dumps({"error": "bad", "x_passphrase": LOGGED_SECRET})
    with caplog.at_level(logging.WARNING, logger="unifi_fabric.client"):
        client._audit_write("PUT", "/sites", "http_400", 400, upstream_error=body)
    await client.close()
    assert "upstream write error" in caplog.text and "status=400" in caplog.text
    assert LOGGED_SECRET not in caplog.text


@pytest.mark.parametrize("redact", [False, True])
async def test_a_call_bound_value_across_the_log_cap_leaks_no_prefix(tmp_path, caplog, redact):
    # A value the call bound (a credential argument echoed in free text, not under a
    # credential-named key) is scrubbed from the WHOLE upstream text before the cap cuts
    # it: cutting first would leave a prefix no value scrub can recognise.
    from unifi_fabric.secret_scrub import secret_scope

    secret = synth("call-bound-passphrase") * 2
    lead = " rejected value "
    body = "x" * (2048 - len(lead) - len(secret) // 2) + lead + secret + " end"
    client = UniFiClient(
        Settings(api_key="synthetic-only", audit_log=str(tmp_path / "a.log"), redact_secrets=redact)
    )
    with secret_scope([secret]), caplog.at_level(logging.WARNING, logger="unifi_fabric.client"):
        client._audit_write("POST", "/v1/sites/abc/things", "http_400", 400, upstream_error=body)
    await client.close()
    assert "upstream write error" in caplog.text
    assert secret[:8] not in caplog.text


async def test_audit_level_off_logs_no_upstream_write_error(tmp_path, caplog):
    # UNIFI_AUDIT_LEVEL=off writes no record, so no body line tagged with a ref that
    # matches no record either.
    client = UniFiClient(
        Settings(api_key="synthetic-only", audit_log=str(tmp_path / "a.log"), audit_level="off")
    )
    with caplog.at_level(logging.WARNING, logger="unifi_fabric.client"):
        client._audit_write("PUT", "/sites", "http_400", 400, upstream_error='{"error": "bad"}')
    await client.close()
    assert "upstream write error" not in caplog.text


@pytest.mark.parametrize("redact", [False, True])
async def test_a_credential_cut_by_the_log_cap_is_still_masked(tmp_path, caplog, redact):
    client = UniFiClient(
        Settings(api_key="synthetic-only", audit_log=str(tmp_path / "a.log"), redact_secrets=redact)
    )
    prefix = json.dumps({"note": "n" * 2000})[:-1] + ', "x_passphrase": "'
    body = prefix + LOGGED_SECRET * 4 + '"}'
    with caplog.at_level(logging.WARNING, logger="unifi_fabric.client"):
        client._audit_write("PUT", "/sites", "http_400", 400, upstream_error=body)
    await client.close()
    assert LOGGED_SECRET[:8] not in caplog.text


def test_a_free_text_reason_is_masked_in_the_log(tmp_path, caplog):
    sink = AuditSink(path=str(tmp_path / "a.log"), fmt="json")
    reason = json.dumps({"detail": "refused", "x_passphrase": LOGGED_SECRET})
    with caplog.at_level(logging.INFO, logger=audit.__name__):
        sink.record(method="POST", path="/sites", outcome="refused", status=None, reason=reason)
    assert "audit reason detail" in caplog.text
    assert LOGGED_SECRET not in caplog.text
