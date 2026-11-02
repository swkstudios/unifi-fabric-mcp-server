"""Cross-tool invariants for the shared chokepoints.

Each property names ONE chokepoint and is enforced by behaviour across EVERY registered
tool it can apply to (derived from the live registry, so a tool is covered the moment it
is registered). The harness and helpers are those of ``tests/test_cross_tool_invariants``.

bo. One boolean parser: for every boolean setting and every accepted spelling (any case,
    surrounding whitespace), ``Settings`` and the runtime switch reader agree; every
    runtime switch is a ``Settings`` boolean field with the same default; no source file
    but ``switches.py`` reads a boolean ``UNIFI_*`` switch from the environment; and every
    area opt-out refuses its writes for every false spelling (read-only mode for every
    true spelling).
bp. One safe read-after: a write tool whose read-after GET fails (HTTP 500) after the
    write succeeded returns success plus ``readAfterError``; it never raises.
bq. One empty-update guard: every update tool given a body with no field to change (empty,
    only additive ``_`` keys, only masked secrets, only empty objects) raises "No fields
    provided" with zero upstream requests; the guard judges the FINAL sanitized body, so
    an update given only the server-managed fields its sanitizer strips (``id``,
    ``metadata``, ``default``, ``index`` where not a request property) raises the same way,
    and no update tool ever sends an empty object body. The guard covers every WRITE tool
    whose payload is one required object body (updates, ``set_*_ordering`` and
    every other full-replace write, creates and actions; derived from the registry, never
    from a name prefix); a full-replace write lacking a key its published request schema
    requires (``orderedAclRuleIds`` / ``orderedFirewallPolicyIds``) is refused too, and a
    body of only the pinned networkconf ``purpose`` is identity-only.
br. One type-strict compare: a no-op-capable write whose current state holds a sent value
    with another JSON type (``true`` vs ``1``) is never answered "no change"; the relay
    never reports ``noOp`` for a write the upstream did not accept (non-2xx).
bs. One multi-key de-duplication: every multi-key tool, with two keys that see the same
    consoles and objects, returns each record once and the same counts as one key.
bt. One validate-before-resolve: every tool that rejects an argument does so with zero
    upstream requests (no key/host/site resolution, no read); and for an opted-out area
    the opt-out refusal comes first. The battery enumerates scalar errors, argument-
    structure errors (blank / control-character host, site and key_label; a left-out host
    or site, e.g. the site a relay path placeholder needs; malformed entries after a valid
    one in an array of objects such as ``sites[]``) and multi-argument cases. Every
    tool taking a selector also refuses a whitespace-padded one (an explicit ``""`` is
    never read as "omitted"). A selector-ish argument that also takes ONE string
    (``cameras``, ``mac``) is checked in that form too; a NAME selector
    (``cameras``) refuses only empty / control characters, so a camera named "Garage "
    resolves.
bu. One id validator: every id / MAC argument with a trailing newline is rejected naming
    the argument, with zero upstream requests.
bv. One retry rule: a 429 on any write tool's write sends that write exactly once.
bw. Dry-run always previews: under ``UNIFI_DRY_RUN`` a write whose change is already
    applied (its no-op path) still returns ``status: "dry_run"`` with the preview and sends
    nothing; an upload preview shows the multipart summary, never the content.
bx. Relay fidelity: a 3xx carries its ``Location`` and safe headers; non-UTF-8 bytes under a
    text/JSON content type come back as ``bodyBase64``; a relayed POST to an ``api/s/<site>/
    stat`` route outside the Network application is a write (previewed, audited).
"""

from __future__ import annotations

import base64
import copy
import functools
import inspect
import json
import logging
import pathlib
import re
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from tests._tool_classes import tool_batches
from unifi_fabric import config, server, switches
from unifi_fabric.client import is_dry_run_preview
from unifi_fabric.config import Settings
from unifi_fabric.read_only import is_write_request
from unifi_fabric.redaction import REDACTION_MASK
from unifi_fabric.selector_args import (
    NAME_SELECTOR_KINDS,
    NESTED_SELECTOR_ARGUMENTS,
    NESTED_SELECTOR_FIELDS,
    nested_selector_problems,
)
from unifi_fabric.tools._payload import INTEGRATION_UPDATE_KEEP, server_managed_fields
from unifi_fabric.write_body import (
    NO_FIELDS,
    REQUIRED_BODY_KEYS,
    body_argument,
    update_body_argument,
)


@functools.cache
def _lz_TOOLS():
    return cti.TOOLS


@functools.cache
def _lz_READ_TOOLS():
    return cti.READ_TOOLS


@functools.cache
def _lz_WRITE_TOOLS():
    return cti.WRITE_TOOLS


FAMILY = cti.FAMILY
_call = cti._call


def _write_args(name: str) -> dict[str, Any]:
    """Exercise the mutating route when a mixed relay enters a write-class sweep."""
    args = {**tool_args.generated_args(_lz_TOOLS()[name])}
    if name == "fabric_connector_get":
        args["path"] = f"protect/api/cameras/{uh.ARG_ID}/enable-control"
    return args


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _keys_anywhere(obj: Any) -> set[str]:
    out: set[str] = set()
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            out |= {str(k) for k in node}
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return out


# =========================================================================== (bo)
_BOOL_FIELDS = sorted(config._BOOL_FIELDS)
_SPELLINGS = [
    variant
    for word in (*switches.TRUE_VALUES, *switches.FALSE_VALUES)
    for variant in (word, word.upper(), word.capitalize(), f"  {word}\t")
]


def test_bo_bool_fields_are_the_known_switches():
    assert set(_BOOL_FIELDS) >= {
        "read_only",
        "dry_run",
        "redact_secrets",
        "enable_connector_write",
        "protect_mutations_enabled",
        "enable_mobility_write",
        "enable_network_write",
        "enable_carrier_fabric_write",
        "enable_innerspace_write",
    }, _BOOL_FIELDS


def test_bo_every_runtime_switch_is_a_settings_field_with_the_same_default():
    fields = {f"UNIFI_{n.upper()}": n for n in _BOOL_FIELDS}
    assert {"UNIFI_READ_ONLY", "UNIFI_ENABLE_NETWORK_WRITE"} <= set(switches.RUNTIME_SWITCHES)
    for env, default in switches.RUNTIME_SWITCHES.items():
        assert env in fields, f"{env} is read at call time but is not a Settings field"
        assert Settings.model_fields[fields[env]].default is default, env


@pytest.mark.parametrize("field", _BOOL_FIELDS)
@pytest.mark.parametrize("spelling", _SPELLINGS)
def test_bo_settings_and_runtime_agree_on_every_spelling(monkeypatch, field, spelling):
    env = f"UNIFI_{field.upper()}"
    monkeypatch.setenv(env, spelling)
    settings_value = getattr(Settings(api_key="k-test"), field)
    expected = spelling.strip().lower() in switches.TRUE_VALUES
    assert settings_value is expected, (env, spelling, settings_value)
    runtime = switches.env_flag(env, not expected)
    assert runtime is settings_value, (env, spelling, runtime, settings_value)


@pytest.mark.parametrize("field", _BOOL_FIELDS)
def test_bo_a_malformed_value_fails_in_settings_and_at_runtime(monkeypatch, field):
    env = f"UNIFI_{field.upper()}"
    monkeypatch.setenv(env, "maybe")
    with pytest.raises(Exception) as at_startup:
        Settings(api_key="k-test")
    with pytest.raises(ValueError) as at_runtime:
        switches.env_flag(env, False)
    assert env in str(at_startup.value) and env in str(at_runtime.value)


_SRC = pathlib.Path(server.__file__).parent
_ENV_READ = re.compile(r"os\.(?:environ\.get|getenv|environ\[)\(?\s*['\"](UNIFI_[A-Z_]+)")


def test_bo_no_boolean_switch_is_parsed_outside_switches():
    bool_envs = {f"UNIFI_{n.upper()}" for n in _BOOL_FIELDS}
    hits = []
    for path in sorted(_SRC.rglob("*.py")):
        if path.name == "switches.py":
            continue
        text = path.read_text()
        for m in _ENV_READ.finditer(text):
            line = text[: m.start()].count("\n") + 1
            # Echoing the raw value into a refusal message is not parsing it.
            context = text[m.start() : m.start() + 200]
            if m.group(1) in bool_envs and "_value" not in text[max(0, m.start() - 40) : m.start()]:
                hits.append(f"{path.name}:{line}: {context.splitlines()[0]}")
        for falsy in ('("0", "false", "no", "off")', "'0', 'false'"):
            if falsy in text:
                hits.append(f"{path.name}: private falsey spelling list {falsy}")
    assert hits == [], hits


_AREA_SAMPLE = {
    "UNIFI_ENABLE_NETWORK_WRITE": "create_network",
    "UNIFI_PROTECT_MUTATIONS_ENABLED": "update_camera",
    "UNIFI_ENABLE_MOBILITY_WRITE": "update_mobility_device_name",
    "UNIFI_ENABLE_CARRIER_FABRIC_WRITE": "update_carrier_subscriber",
    "UNIFI_ENABLE_INNERSPACE_WRITE": "create_innerspace_plan",
}


def test_bo_area_sample_covers_every_area_switch():
    assert set(_AREA_SAMPLE) == {s.env for s in switches.AREA_WRITE_SWITCHES}


@pytest.mark.parametrize("env", sorted(_AREA_SAMPLE))
@pytest.mark.parametrize(
    "spelling", [v for w in switches.FALSE_VALUES for v in (w, w.upper(), f" {w} ")]
)
async def test_bo_every_false_spelling_opts_an_area_out(monkeypatch, env, spelling):
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, _AREA_SAMPLE[env], up, env={env: spelling})
    assert env in str(exc.value), str(exc.value)
    assert up.served == [], up.served


@pytest.mark.parametrize(
    "spelling", [v for w in switches.TRUE_VALUES for v in (w, w.upper(), f" {w} ")]
)
async def test_bo_every_true_spelling_turns_read_only_on(monkeypatch, spelling):
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(
            monkeypatch, "update_mobility_device_name", up, env={"UNIFI_READ_ONLY": spelling}
        )
    assert "UNIFI_READ_ONLY" in str(exc.value)
    assert up.served == []


# =========================================================================== (bp)
@tool_batches("name", lambda: _lz_WRITE_TOOLS())
async def test_bp_failing_read_after_is_reported_never_raised(monkeypatch, name):
    up = uh.FakeUpstream(fail_reads_after_write=True)
    try:
        res = await _call(monkeypatch, name, up)
    except ToolError as exc:
        writes = [
            i for i, s in enumerate(up.served) if is_write_request(s.method, s.path, s.sent_json)
        ]
        late_gets = (
            [s for s in up.served[writes[0] + 1 :] if s.method == "GET" and not s.resolution]
            if writes
            else []
        )
        pytest.fail(
            f"{name}: raised after its write was applied (read-after GETs: "
            f"{[s.path for s in late_gets]}): {exc}"
        )
    writes = [i for i, s in enumerate(up.served) if is_write_request(s.method, s.path, s.sent_json)]
    assert writes, f"{name}: no write reached the transport"
    late_gets = [s for s in up.served[writes[0] + 1 :] if s.method == "GET" and not s.resolution]
    if late_gets:
        payload = uh.result_payload(res)
        reported = _keys_anywhere(payload) & {"readAfterError", "_readAfterError"}
        assert reported, (
            f"{name}: its read-after failed ({late_gets[0].path}) but the result does not say "
            f"so: {payload}"
        )


# =========================================================================== (bq)
def _update_tools() -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for name in _lz_WRITE_TOOLS():
        if name.startswith(("update_", "patch_")):
            out[name] = update_body_argument(_lz_TOOLS()[name])
    return out


@functools.cache
def _lz_UPDATE_TOOLS():
    return _update_tools()


# Update tools whose required arguments ARE the whole body (there is no empty form).
_FULL_BODY_UPDATES = {
    "update_arm_profile_settings": "the arm_profile_id argument is the whole body",
    "update_ips_signatures": "this is the controller's no-body signature-upgrade action",
    "update_mobility_device_name": "name is a required argument (the whole body)",
    "update_mobility_device_wireless": "ssid and password are required (the whole body)",
    "update_device_battery_settings": (
        "battery_ids is a required argument (the whole body); the tool is a firmware-upgrade action"
    ),
    "update_protect_device_password": "device_password is a required field to change",
    "update_wireguard_users": "each required users entry carries the fields to change",
}
_EMPTY_BODIES = {
    "empty": {},
    "additive_only": {"_keyLabel": "alpha", "_resolved_networks": []},
    "masked_only": {"x_password": REDACTION_MASK},
    "empty_nested": {"osdSettings": {}},
    # Keys that only address the object are no field to change.
    "identity_classic_id": {"_id": "6512a0b1c2d3e4f5a6b7c8d9"},
    "identity_id": {"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"},
    "identity_all": {
        "_id": "6512a0b1c2d3e4f5a6b7c8d9",
        "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "site_id": "6512a0b1c2d3e4f5a6b7c8d0",
        "_keyLabel": "alpha",
    },
}


def test_bq_update_tool_set_is_derived_and_complete():
    assert len(_lz_UPDATE_TOOLS()) >= 40, sorted(_lz_UPDATE_TOOLS())
    scalar = sorted(n for n, arg in _lz_UPDATE_TOOLS().items() if arg is None)
    assert set(_FULL_BODY_UPDATES) <= set(scalar), scalar
    # The scalar-argument updates that remain build their body and use the guard.
    assert set(scalar) - set(_FULL_BODY_UPDATES) == {
        "update_carrier_subscriber",
        "update_mobility_device_network",
        # Optional typed fields plus a free-form fields object; no field to change fails
        # before any request (their docstrings, protect._fields_to_send).
        "update_protect_case",
        "update_protect_case_asset",
    }, scalar


def _required_only_args(name: str) -> dict[str, Any]:
    tool = _lz_TOOLS()[name]
    required = set(tool.parameters.get("required") or ())
    return {k: v for k, v in tool_args.generated_args(tool).items() if k in required}


@functools.cache
def _lz__BQ_CASES():
    return sorted(
        (name, kind)
        for name, arg in _lz_UPDATE_TOOLS().items()
        if name not in _FULL_BODY_UPDATES
        for kind in (_EMPTY_BODIES if arg is not None else ["no_fields"])
    )


@tool_batches(("name", "kind"), lambda: _lz__BQ_CASES())
async def test_bq_update_with_no_field_raises_before_any_request(monkeypatch, name, kind):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    arg = _lz_UPDATE_TOOLS()[name]
    args = _required_only_args(name)
    if arg is not None:
        args[arg] = copy.deepcopy(_EMPTY_BODIES[kind])
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    assert NO_FIELDS in str(exc.value), f"{name} ({kind}): {exc.value}"
    assert not up.writes()
    assert up.served == []


# A _FULL_BODY_UPDATES member has no "no field to change" form, so the bq refusal above
# cannot be expressed for it. Each member instead has a tool-specific test of what it
# refuses and what it sends; this table names that test, and the drift guard below fails
# when a member is added without one.
_FULL_BODY_TESTS = {
    "update_arm_profile_settings": "test_bq_full_body_arm_profile_settings_sends_only_the_id",
    "update_device_battery_settings": "test_bq_full_body_battery_settings_needs_a_battery",
    "update_ips_signatures": "test_bq_full_body_ips_signatures_sends_one_post_without_a_body",
    "update_mobility_device_name": "test_bq_full_body_mobility_device_name_sends_only_the_name",
    "update_mobility_device_wireless": "test_bq_full_body_mobility_wireless_sends_ssid_and_key",
    "update_protect_device_password": "test_bq_full_body_device_password_sends_only_the_password",
    "update_wireguard_users": "test_bq_full_body_wireguard_users_needs_a_user",
}
#: Synthetic secret for the password write (never a real credential).
_SYNTHETIC_DEVICE_PASSWORD = "synthetic-device-pass-0001"


def test_bq_every_full_body_update_has_a_tool_specific_test():
    assert set(_FULL_BODY_TESTS) == set(_FULL_BODY_UPDATES)
    for name, test_name in _FULL_BODY_TESTS.items():
        test = globals().get(test_name)
        assert test_name.startswith("test_") and callable(test), (name, test_name)
        assert f'"{name}"' in inspect.getsource(test), (name, test_name)


def _full_body_args(name: str, **overrides: Any) -> dict[str, Any]:
    return {**tool_args.generated_args(_lz_TOOLS()[name]), **overrides}


async def _only_write(monkeypatch, name: str, args: dict[str, Any]) -> uh.Served:
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, args)
    writes = up.writes()
    assert len(writes) == 1, [(w.method, w.path) for w in writes]
    return writes[0]


async def test_bq_full_body_arm_profile_settings_sends_only_the_id(monkeypatch):
    args = _full_body_args("update_arm_profile_settings")
    write = await _only_write(monkeypatch, "update_arm_profile_settings", args)
    assert write.method == "PATCH" and write.path.endswith("/arm-profiles/settings"), write.path
    assert write.sent_json == {"armProfileId": args["arm_profile_id"]}


async def test_bq_full_body_battery_settings_needs_a_battery(monkeypatch):
    name = "update_device_battery_settings"
    up = uh.FakeUpstream()
    with pytest.raises(ToolError, match="names no battery pack"):
        await _call(monkeypatch, name, up, _full_body_args(name, battery_ids=[]))
    assert up.served == []
    args = _full_body_args(name)
    write = await _only_write(monkeypatch, name, args)
    assert write.method == "POST" and write.path.endswith("/battery/update"), write.path
    assert write.sent_json["macs"] == args["battery_ids"], write.sent_json


async def test_bq_full_body_ips_signatures_sends_one_post_without_a_body(monkeypatch):
    args = _full_body_args("update_ips_signatures")
    write = await _only_write(monkeypatch, "update_ips_signatures", args)
    assert write.method == "POST", write.method
    assert write.path.endswith("/settings/ips/suricata-upgrade"), write.path
    assert write.sent_json is None


async def test_bq_full_body_mobility_device_name_sends_only_the_name(monkeypatch):
    args = _full_body_args("update_mobility_device_name")
    write = await _only_write(monkeypatch, "update_mobility_device_name", args)
    assert write.method == "PUT" and write.path.endswith(f"/devices/{args['device_id']}")
    assert write.sent_json == {"name": args["name"]}


async def test_bq_full_body_mobility_wireless_sends_ssid_and_key(monkeypatch):
    args = _full_body_args("update_mobility_device_wireless")
    write = await _only_write(monkeypatch, "update_mobility_device_wireless", args)
    assert write.method == "PUT" and write.path.endswith("/wireless"), write.path
    assert write.sent_json == {"ssid": args["ssid"], "password": args["password"]}


async def test_bq_full_body_device_password_sends_only_the_password(monkeypatch):
    name = "update_protect_device_password"
    args = _full_body_args(name, device_password=_SYNTHETIC_DEVICE_PASSWORD)
    write = await _only_write(monkeypatch, name, args)
    assert write.method == "PATCH" and write.path.endswith("/nvr/device-password"), write.path
    assert write.sent_json == {"devicePassword": _SYNTHETIC_DEVICE_PASSWORD}


async def test_bq_full_body_wireguard_users_needs_a_user(monkeypatch):
    name = "update_wireguard_users"
    up = uh.FakeUpstream()
    with pytest.raises(ToolError, match="names no WireGuard user"):
        await _call(monkeypatch, name, up, _full_body_args(name, users=[]))
    assert up.served == []
    args = _full_body_args(name)
    write = await _only_write(monkeypatch, name, args)
    assert write.method == "PUT" and write.path.endswith("/users/batch"), write.path
    assert isinstance(write.sent_json, list) and len(write.sent_json) == len(args["users"])
    for sent, given in zip(write.sent_json, args["users"], strict=True):
        assert {k: sent.get(k) for k in given} == given, (sent, given)


#: Every write tool taking a single required object body, by registry shape.
@functools.cache
def _lz_GUARDED_BODY_TOOLS():
    return {n: arg for n in _lz_WRITE_TOOLS() if (arg := body_argument(_lz_TOOLS()[n])) is not None}


def test_bq_guard_selection_is_by_shape_not_name():
    """The guard covers every write tool with a single required object body, whatever
    its name: the set_*_ordering full-replace writes, creates and actions included."""
    names = set(_lz_GUARDED_BODY_TOOLS())
    assert {"set_acl_rule_ordering", "set_firewall_policy_ordering"} <= names, sorted(names)
    assert {n for n, a in _lz_UPDATE_TOOLS().items() if a is not None} <= names
    assert any(not n.startswith(("update_", "patch_")) for n in names)
    for name in names:
        assert not cti._is_read(_lz_TOOLS()[name]), name


@functools.cache
def _lz__BQ_SHAPE_CASES():
    return sorted(
        (name, kind)
        for name in _lz_GUARDED_BODY_TOOLS()
        if name not in _lz_UPDATE_TOOLS()
        for kind in _EMPTY_BODIES
    )


@tool_batches(("name", "kind"), lambda: _lz__BQ_SHAPE_CASES())
async def test_bq_full_replace_or_create_with_no_field_raises_before_any_request(
    monkeypatch, name, kind
):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    args = _required_only_args(name)
    args[_lz_GUARDED_BODY_TOOLS()[name]] = copy.deepcopy(_EMPTY_BODIES[kind])
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    assert NO_FIELDS in str(exc.value), f"{name} ({kind}): {exc.value}"
    assert not up.writes()
    assert up.served == []


@pytest.mark.parametrize("name", sorted(REQUIRED_BODY_KEYS))
async def test_bq_full_replace_missing_spec_required_key_raises(monkeypatch, name):
    args = _required_only_args(name)
    args[_lz_GUARDED_BODY_TOOLS()[name]] = {"probeField": ["x"]}
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    for key in REQUIRED_BODY_KEYS[name]:
        assert key in str(exc.value), f"{name}: {exc.value}"
    assert not up.writes()
    assert up.served == []


def test_bq_required_body_keys_match_the_published_spec():
    """REQUIRED_BODY_KEYS is the vendored spec's ``required`` list of each operation."""
    spec = json.loads(
        (pathlib.Path(__file__).parent / "fixtures/openapi/network-10.6.106.json").read_text()
    )
    paths = {
        "set_acl_rule_ordering": "/v1/sites/{siteId}/acl-rules/ordering",
        "set_firewall_policy_ordering": "/v1/sites/{siteId}/firewall/policies/ordering",
    }
    assert set(paths) == set(REQUIRED_BODY_KEYS)
    for name, path in paths.items():
        schema = spec["paths"][path]["put"]["requestBody"]["content"]["application/json"]["schema"]
        if "$ref" in schema:
            schema = spec["components"]["schemas"][schema["$ref"].rsplit("/", 1)[-1]]
        assert tuple(schema.get("required") or ()) == REQUIRED_BODY_KEYS[name], name


_PURPOSE_PINNED = {
    "update_vpn_server": "remote-user-vpn",
    "update_wan_interface": "wan",
    "update_site_to_site_tunnel": "site-vpn",
}


@pytest.mark.parametrize("name", sorted(_PURPOSE_PINNED))
async def test_bq_purpose_only_body_is_identity_only(monkeypatch, name):
    """The pinned networkconf ``purpose`` addresses the record kind; a body of
    only ``purpose`` changes nothing and is refused before any request."""
    args = _required_only_args(name)
    args[_lz_GUARDED_BODY_TOOLS()[name]] = {"purpose": _PURPOSE_PINNED[name]}
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    assert NO_FIELDS in str(exc.value) and "purpose" in str(exc.value), f"{name}: {exc.value}"
    assert not up.writes()
    assert up.served == []


# Every server-managed field a get_ response carries (the read-modify-write round trip).
_SERVER_MANAGED_VALUES: dict[str, Any] = {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "metadata": {"origin": "USER_DEFINED"},
    "default": False,
    "index": 3,
}


@functools.cache
def _lz__BODY_UPDATES():
    return sorted(n for n, arg in _lz_UPDATE_TOOLS().items() if arg is not None)


def test_bq_integration_update_declaration_is_complete():
    """Every update tool that sanitizes an Integration body declares it (the guard reads
    the declaration), and no tool calls the bare sanitizer on an update body."""
    assert set(INTEGRATION_UPDATE_KEEP) <= set(_lz__BODY_UPDATES()), sorted(INTEGRATION_UPDATE_KEEP)
    src = (_SRC / "tools").rglob("*.py")
    bare = [
        f"{f.name}:{i}"
        for f in src
        if f.name != "_payload.py"
        for i, line in enumerate(f.read_text().splitlines(), 1)
        if "sanitize_integration_write(" in line
    ]
    assert bare == [], f"update bodies must go through integration_update_body: {bare}"
    assert INTEGRATION_UPDATE_KEEP["update_acl_rule"] == frozenset({"index"})


@pytest.mark.parametrize("name", sorted(INTEGRATION_UPDATE_KEEP))
async def test_bq_server_managed_only_body_raises_before_any_request(monkeypatch, name):
    managed = server_managed_fields(name)
    args = _required_only_args(name)
    args[_lz_UPDATE_TOOLS()[name]] = {
        k: v for k, v in _SERVER_MANAGED_VALUES.items() if k in managed
    }
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    assert NO_FIELDS in str(exc.value), f"{name}: {exc.value}"
    assert "server-managed" in str(exc.value), f"{name}: {exc.value}"
    assert not up.writes()
    assert up.served == []


@tool_batches("name", lambda: _lz__BODY_UPDATES())
async def test_bq_no_update_tool_sends_an_empty_body(monkeypatch, name):
    """Given only server-managed fields, an update either refuses before any request or
    sends a body that still carries a field: never ``{}``."""
    args = _required_only_args(name)
    args[_lz_UPDATE_TOOLS()[name]] = copy.deepcopy(_SERVER_MANAGED_VALUES)
    up = uh.FakeUpstream()
    try:
        await _call(monkeypatch, name, up, args)
    except ToolError as exc:
        if NO_FIELDS in str(exc):
            assert not up.writes()
            assert up.served == []
    writes = [s for s in up.served if is_write_request(s.method, s.path, s.sent_json)]
    assert all(w.sent_json not in ({}, None) for w in writes if w.method in {"PUT", "PATCH"}), (
        f"{name}: sent an empty update body: {[(w.method, w.path, w.sent_json) for w in writes]}"
    )


async def test_bq_update_setting_key_only_body_is_empty(monkeypatch):
    """update_setting addresses the group by its ``key`` too: {_id, key} changes nothing."""
    args = _required_only_args("update_setting")
    args[_lz_UPDATE_TOOLS()["update_setting"]] = {"_id": "6512a0b1c2d3e4f5a6b7c8d9", "key": "mgmt"}
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, "update_setting", up, args)
    assert NO_FIELDS in str(exc.value) and "address" in str(exc.value), exc.value
    assert not up.writes()
    assert up.served == []


@pytest.mark.parametrize("name", ["update_wlan_config", "update_user"])
async def test_bq_identity_key_is_still_sent_beside_a_real_field(monkeypatch, name):
    """An identity key is no field on its own, but a read result fed back keeps it."""
    args = _required_only_args(name)
    args[_lz_UPDATE_TOOLS()[name]] = {"_id": "6512a0b1c2d3e4f5a6b7c8d9", "name": "probe-name"}
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, args)
    writes = [s for s in up.served if s.method in {"PUT", "PATCH"}]
    assert writes and writes[0].sent_json.get("_id") == "6512a0b1c2d3e4f5a6b7c8d9"
    assert writes[0].sent_json.get("name") == "probe-name"


async def test_bq_acl_rule_index_is_a_field_and_is_sent(monkeypatch):
    args = _required_only_args("update_acl_rule")
    args["rule"] = {"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "index": 2}
    up = uh.FakeUpstream()
    await _call(monkeypatch, "update_acl_rule", up, args)
    writes = [s for s in up.served if s.method == "PUT"]
    assert [w.sent_json for w in writes] == [{"index": 2}], writes


# =========================================================================== (br) (bw)
class _ReflectingUpstream(cti._StatefulWriteUpstream):
    """The stateful fake, reflecting nested objects of a write body too (a later read of
    record 0 carries every field sent, objects included)."""

    def __call__(self, req: Any) -> Any:
        resp = super().__call__(req)
        if 200 <= resp.status_code < 300 and is_write_request(
            req.method, req.url.path, uh.request_json(req)
        ):
            try:
                sent = json.loads(req.content) if req.content else None
            except ValueError:
                sent = None
            if isinstance(sent, dict):
                for k, v in sent.items():
                    if isinstance(v, dict):
                        self.overlay[k] = copy.deepcopy(v)
        return resp


def _with_probe_flag(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """``args`` whose sent body also carries a boolean leaf (``probeFlag: true``)."""
    out = copy.deepcopy(args)
    arg = update_body_argument(_lz_TOOLS()[name]) or (
        "settings" if isinstance(out.get("settings"), dict) else None
    )
    if name == "update_device_radio":
        out["radios"].setdefault("na", {})["min_rssi_enabled"] = True
    elif arg is not None and isinstance(out.get(arg), dict):
        out[arg]["probeFlag"] = True
    elif name == "update_carrier_subscriber":
        out["metadata"] = {"probeFlag": True}
    return out


async def _applied_then_repeat(
    monkeypatch, name: str, *, dry_run: bool = False, flip: bool = False
):
    # Generated records: the repeat must read the state the first write applied, which a
    # replayed capture (the same body on every read) never shows.
    up = _ReflectingUpstream(replay_recordings=False)
    for k, v in tool_args.TOOL_ENV.get(name, {}).items():
        monkeypatch.setenv(k, v)
    client = uh.install(monkeypatch, up)
    args = _with_probe_flag(
        name, {**cti.sc.conformance_args(name), **cti._SENT_OPTIONALS.get(name, {})}
    )
    first = uh.result_payload(await server.mcp.call_tool(name, args))
    first_writes = len(up.writes())
    flipped: list[str] = []
    if flip:
        flipped = _flip_types(up.overlay)
    if dry_run:
        client._dry_run = True
    before = len(up.writes())
    second = uh.result_payload(await server.mcp.call_tool(name, args))
    return first, first_writes, second, len(up.writes()) - before, flipped


def _flip_types(node: Any, path: str = "") -> list[str]:
    """Flip bool <-> int leaves in place (True -> 1, 1 -> True); returns their paths."""
    flipped: list[str] = []
    if isinstance(node, dict):
        for k, v in list(node.items()):
            here = f"{path}.{k}" if path else str(k)
            if isinstance(v, bool):
                node[k] = int(v)
                flipped.append(here)
            elif isinstance(v, int) and v in (0, 1):
                node[k] = bool(v)
                flipped.append(here)
            else:
                flipped += _flip_types(v, here)
    return flipped


# Observed, not hand-picked: a write tool whose repeat of an applied write sends no write
# (it has a no-op path). Membership is derived before batching; unexpected baseline
# errors fail selection rather than silently removing tools from coverage.
_NO_OP_SEEN: dict[str, bool] = {}


_DELETED_REPEAT_ERRORS = {
    "delete_protect_backup": r"Unknown backup .*valid choices: \[\]\. No write was sent\.",
    "delete_bgp_config": r"BGP config .* not found; valid: \(none\)\. No write was sent\.",
    "delete_ospf_router": r"OSPF router .* not found; valid: \(none\)\. No write was sent\.",
    "delete_qos_rule": (
        r"QoS rule .* not found; valid choices: \(none\)\. "
        r"Get ids from list_qos_rules \(_id\)\. No write was sent\."
    ),
    "delete_wireguard_users": (
        r"WireGuard user\(s\) .* not found; valid: \(none\)\. "
        r"Get ids from list_wireguard_users \(_id\)\. No write was sent\."
    ),
}


async def _assert_deleted_record_cannot_be_repeated(monkeypatch, name):
    # A successful delete removes the item from the live listing. A repeat therefore
    # fails lookup, rather than returning a successful no-op response.
    up = _ReflectingUpstream(replay_recordings=False)
    for key, value in tool_args.TOOL_ENV.get(name, {}).items():
        monkeypatch.setenv(key, value)
    uh.install(monkeypatch, up)
    args = {**cti.sc.conformance_args(name), **cti._SENT_OPTIONALS.get(name, {})}
    first = uh.result_payload(await server.mcp.call_tool(name, args))
    assert first["deleted"] is True
    assert len(up.writes()) == 1
    write = up.writes()[0]
    expected_method = cti._AA_DELETE_SHAPES.get(name, {}).get("method", "DELETE")
    assert write.method == expected_method and 200 <= write.status < 300
    if expected_method == "POST":
        assert cti._is_delete_preview(
            {
                "method": write.method,
                "path": write.path,
                "body": write.sent_json,
                "params": write.query,
            },
            name,
            up,
        )
    with pytest.raises(ToolError, match=_DELETED_REPEAT_ERRORS[name]):
        await server.mcp.call_tool(name, args)
    assert len(up.writes()) == 1


@pytest.mark.parametrize("name", sorted(_DELETED_REPEAT_ERRORS))
async def test_deleted_record_repeat_reports_missing_without_another_write(monkeypatch, name):
    await _assert_deleted_record_cannot_be_repeated(monkeypatch, name)


async def test_camera_shortcut_array_patch_is_reflected_for_repeat(monkeypatch):
    seq = await cti._write_sequence(monkeypatch, "update_camera_shortcut")
    assert seq["results"][0]["status"] == "updated"
    assert seq["results"][0]["verified"] is True
    assert seq["results"][1]["status"] == "noop"
    assert seq["changed"]
    assert seq["results"][2]["status"] == "updated"
    assert seq["writes"] == [1, 0, 1]


async def _is_no_op(name: str) -> bool:
    if name not in _NO_OP_SEEN:
        if name in _DELETED_REPEAT_ERRORS:
            mp = pytest.MonkeyPatch()
            try:
                await _assert_deleted_record_cannot_be_repeated(mp, name)
            finally:
                mp.undo()
            _NO_OP_SEEN[name] = False
            return False
        mp = pytest.MonkeyPatch()
        previous = logging.root.manager.disable
        logging.disable(logging.CRITICAL)
        try:
            _f, first_writes, _s, second_writes, _ = await _applied_then_repeat(mp, name)
            _NO_OP_SEEN[name] = bool(first_writes) and second_writes == 0
        finally:
            mp.undo()
            logging.disable(previous)
    return _NO_OP_SEEN[name]


def _derive_no_op_tools() -> list[str]:
    async def run_all() -> list[str]:
        return [n for n in _lz_WRITE_TOOLS() if await _is_no_op(n)]

    return cti._run_coroutine(run_all())


@functools.cache
def _lz_NO_OP_TOOLS():
    return _derive_no_op_tools()


def test_bw_no_op_tools_are_derived_and_include_every_family():
    fams = {FAMILY.get(n) for n in _lz_NO_OP_TOOLS()}
    assert {"protect", "mobility", "carrier"} <= fams, sorted(_lz_NO_OP_TOOLS())
    assert "update_setting" in _lz_NO_OP_TOOLS(), sorted(_lz_NO_OP_TOOLS())
    assert len(_lz_NO_OP_TOOLS()) >= 20, sorted(_lz_NO_OP_TOOLS())


async def _eligible_br_a_value_of_another_type_is_never_already_applied(monkeypatch, name):
    _f, _fw, second, second_writes, flipped = await _applied_then_repeat(
        monkeypatch, name, flip=True
    )
    if not flipped:
        return False
    return True


@tool_batches(
    "name",
    lambda: _lz_WRITE_TOOLS(),
    member=_is_no_op,
    eligible=_eligible_br_a_value_of_another_type_is_never_already_applied,
)
async def test_br_a_value_of_another_type_is_never_already_applied(monkeypatch, name):
    _f, _fw, second, second_writes, flipped = await _applied_then_repeat(
        monkeypatch, name, flip=True
    )
    if not flipped:
        raise AssertionError("inapplicable case was not filtered before batching")
    assert second_writes >= 1, (
        f"{name}: the console holds {flipped} as another JSON type (1 vs true) but the "
        f"repeat was answered without a write: {second}"
    )


def test_br_type_strict_coverage():
    must = {"update_carrier_subscriber", "update_setting", "update_camera"}
    assert must <= set(_lz_NO_OP_TOOLS()), sorted(must - set(_lz_NO_OP_TOOLS()))


@tool_batches("name", lambda: _lz_WRITE_TOOLS(), member=_is_no_op)
async def test_bw_dry_run_no_op_path_still_previews(monkeypatch, name):
    _f, _fw, second, second_writes, _ = await _applied_then_repeat(monkeypatch, name, dry_run=True)
    assert second_writes == 0, f"{name}: a write was sent under dry-run"
    # The dry-run result: status "dry_run" with the preview, or (Network tools, which
    # return the upstream body) the bare preview itself; never the no-op answer.
    assert isinstance(second, dict) and (
        second.get("status") == "dry_run" or is_dry_run_preview(second)
    ), f"{name}: an already-applied change under dry-run returned {second!r}"
    previews = [node for node in cti._nested_objects(second) if is_dry_run_preview(node)]
    assert previews, f"{name}: no dry-run preview in {second!r}"


async def test_bw_upload_preview_shows_the_multipart_summary(monkeypatch):
    raw = b"\x89PNG\r\n\x1a\nprobe-file-bytes"
    args = {
        "host": uh.HOST,
        "file_type": "animations",
        "filename": "probe.png",
        "file_content_base64": base64.b64encode(raw).decode(),
    }
    up = uh.FakeUpstream()
    res = await _call(monkeypatch, "upload_protect_file", up, args, env={"UNIFI_DRY_RUN": "1"})
    payload = uh.result_payload(res)
    assert payload["status"] == "dry_run" and up.writes() == []
    parts = payload["response"]["preview"]["multipart"]
    assert parts == [
        {
            "field": "file",
            "filename": "probe.png",
            "contentType": "image/png",
            "sizeBytes": len(raw),
        }
    ], parts
    text = json.dumps(payload)
    assert base64.b64encode(raw).decode() not in text and "probe-file-bytes" not in text
    # The description names the multipart preview key and its entry fields.
    description = cti.TOOLS["upload_protect_file"].description or ""
    assert "multipart: one {field, filename, contentType, sizeBytes}" in description


# =========================================================================== (bs)
_SHARED = {"k-alpha": [uh.HOST_RECORD], "k-beta": [uh.HOST_RECORD]}


def _counts(obj: Any) -> list[Any]:
    out = []
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("count", "consoleCount", "total", "hosts", "sites") and isinstance(v, int):
                    out.append((k, v))
                if k in ("byKey", "_keyTotals", "errors", "key_labels"):
                    continue
                stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)
    return sorted(out, key=repr)


@tool_batches("name", lambda: cti._multi_key_candidates(), member=cti._is_aggregation)
async def test_bs_object_seen_by_two_keys_is_returned_once(monkeypatch, name):
    single = uh.result_payload(
        await _call(
            monkeypatch,
            name,
            uh.FakeUpstream(hosts_by_key={"k-alpha": [uh.HOST_RECORD]}),
            keys=cti._KEYS[:1],
        )
    )
    double = uh.result_payload(
        await _call(monkeypatch, name, uh.FakeUpstream(hosts_by_key=_SHARED), keys=cti._KEYS)
    )
    dupes = {
        p: n
        for p, n in cti._probe_counts(double).items()
        if n > cti._probe_counts(single).get(p, 0)
    }
    assert not dupes, f"{name}: records returned again for the second key: {sorted(dupes)[:5]}"
    assert _counts(double) == _counts(single), (
        f"{name}: counts with two keys seeing the same data {_counts(double)} differ from one "
        f"key {_counts(single)}"
    )


def test_bs_covers_every_multi_key_list_tool():
    must = {
        "list_hosts",
        "list_sites",
        "list_devices",
        "list_all_devices",
        "list_all_sites_aggregated",
        "list_sdwan_configs",
        "list_mobility_workspaces",
        "list_carrier_subscribers",
        "list_carrier_service_plans",
        "get_isp_metrics",
    }
    assert must <= set(cti.AGGREGATION_TOOLS), sorted(must - set(cti.AGGREGATION_TOOLS))


# =========================================================================== (bt) (bu)
_SKIP_ARGS = {"confirm"}
# Arguments never used as a conflicting field inside an object body.
_CONFLICT_SKIP = {"host", "site", "key_label", "confirm"}
_DATA_MARKERS = (
    uh.ARG_ID,
    uh.ARG_HEX,
    uh.ARG_MAC,
    uh.ARG_NAME,
    uh.SITE_ID,
    uh.HOST_ID,
    "probe#",
)


def _types(spec: dict[str, Any]) -> set[str]:
    return {spec.get("type")} | {s.get("type") for s in spec.get("anyOf", []) or []} - {None}


def _invalid_values(tool: Any, pname: str, spec: dict[str, Any]) -> list[Any]:
    if spec.get("enum") or any(s.get("enum") for s in spec.get("anyOf", []) or []):
        return []
    types = _types(spec)
    values: list[Any] = []
    if "string" in types:
        values += ["", "   ", "x\n", "zz?#/", "1690000000000"]
    if "integer" in types:
        # A large positive integer is valid for unbounded work counts. Executing
        # it as a negative probe can start that much real work (e.g. poll_count).
        values += [-1, 1.5, "not-an-integer"]
        if "positive integer" in spec.get("description", "").lower():
            values.append(0)
        if "minimum" in spec:
            values.append(spec["minimum"] - 1)
        if "exclusiveMinimum" in spec:
            values.append(spec["exclusiveMinimum"])
        if "maximum" in spec:
            values.append(spec["maximum"] + 1)
        if "exclusiveMaximum" in spec:
            values.append(spec["exclusiveMaximum"])
    if "number" in types and "integer" not in types:
        values += [-1.5]
    if "array" in types:
        values += [["x\n"]]
    if "object" in types:
        scalars = [
            p
            for p, s in (tool.parameters.get("properties") or {}).items()
            if p != pname and p not in _CONFLICT_SKIP and not ({"object", "array"} & _types(s))
        ]
        for p in scalars:
            camel = re.sub(r"_(\w)", lambda m: m.group(1).upper(), p)
            values += [{p: "zz-conflict"}, {camel: "zz-conflict"}]
    return values


def test_integer_negative_battery_respects_declared_bounds_and_work_counts():
    """No arbitrary upper limit is invented for an unbounded positive work count."""
    from unifi_fabric.tools.protect import _validate_collector_controls

    for name in ("collect_protect_events", "collect_protect_device_changes"):
        tool = _lz_TOOLS()[name]
        spec = tool.parameters["properties"]["poll_count"]
        invalid = _invalid_values(tool, "poll_count", spec)
        assert {0, -1, 1.5, "not-an-integer"} <= set(invalid)
        assert not any(isinstance(value, int) and value > 0 for value in invalid)
        assert ("poll_count", 10**13) not in _battery(name)
        # Validate the huge count without executing trillions of polls. The
        # real two-poll collector tests separately prove completed work.
        for valid in (1, 2, 10**13):
            _validate_collector_controls(valid, 0)
        for value in invalid:
            with pytest.raises(ValueError, match="positive integer"):
                _validate_collector_controls(value, 0)
        bounded = {"type": "integer", "minimum": 1, "maximum": 8}
        assert 0 in _invalid_values(tool, "bounded", bounded)
        assert 9 in _invalid_values(tool, "bounded", bounded)
        exclusive = {"type": "integer", "exclusiveMinimum": 2, "exclusiveMaximum": 8}
        assert 2 in _invalid_values(tool, "exclusive", exclusive)
        assert 8 in _invalid_values(tool, "exclusive", exclusive)


def _battery(name: str) -> list[tuple[str, Any]]:
    tool = _lz_TOOLS()[name]
    out: list[tuple[str, Any]] = []
    for pname, spec in (tool.parameters.get("properties") or {}).items():
        if pname in _SKIP_ARGS:
            continue
        out += [(pname, v) for v in _invalid_values(tool, pname, spec)]
    return out


#: Marks an argument left out of the call (a missing ``site`` the path needs, ...).
_DROP = object()
_ENTRY = {"hostId": uh.HOST, "siteId": uh.SITE}


def _object_array(spec: dict[str, Any]) -> bool:
    """True for an array-of-objects argument (``sites[]`` entries), including one whose
    items are nullable objects (``anyOf: [object, null]``)."""
    for s in [spec, *(spec.get("anyOf", []) or [])]:
        items = s.get("items") if isinstance(s, dict) else None
        if s.get("type") == "array" and isinstance(items, dict):
            for item in [items, *(items.get("anyOf", []) or [])]:
                if item.get("type") == "object" or "additionalProperties" in item:
                    return True
    return False


def _structure_battery(name: str) -> list[tuple[str, Any]]:
    """Argument-structure errors: blank / malformed host, site and key_label, a left-out
    host or site, and malformed entries AFTER a valid one in an array of objects."""
    props = _lz_TOOLS()[name].parameters.get("properties") or {}
    out: list[tuple[str, Any]] = []
    for pname in ("host", "site"):
        if pname in props:
            out += [(pname, ""), (pname, "   "), (pname, "x\n"), (pname, _DROP)]
    if "key_label" in props:
        out += [("key_label", ""), ("key_label", "   "), ("key_label", "x\n")]
    for pname, spec in props.items():
        if _object_array(spec):
            out += [
                (pname, []),
                (pname, [_ENTRY, {}]),
                (pname, [_ENTRY, {"hostId": uh.HOST}]),
                (pname, [_ENTRY, {"siteId": uh.SITE}]),
                (pname, [_ENTRY, "x"]),
                (pname, [_ENTRY, {**_ENTRY, "endTimestamp": "1700000000"}]),
            ]
    return out


def _multi_battery(name: str) -> list[dict[str, Any]]:
    """Multi-argument cases: two arguments changed at once (a scalar error together with a
    left-out site; a valid array of objects together with a lone host)."""
    props = _lz_TOOLS()[name].parameters.get("properties") or {}
    cases: list[dict[str, Any]] = []
    first = _battery(name)[:1]
    if "site" in props:
        cases += [{pname: value, "site": _DROP} for pname, value in first]
        if "host" in props:
            cases.append({"host": uh.HOST, "site": _DROP})
            cases.append({"host": _DROP, "site": uh.SITE})
    for pname, spec in props.items():
        if _object_array(spec) and "site" in props:
            cases.append({pname: [_ENTRY, {"hostId": uh.HOST}], "host": uh.HOST, "site": _DROP})
    return cases


def _apply(base: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    args = dict(base)
    for k, v in changes.items():
        if v is _DROP:
            args.pop(k, None)
        else:
            args[k] = v
    return args


@functools.cache
def _lz_BATTERY_TOOLS():
    return sorted(
        n
        for n in _lz_TOOLS()
        if n not in cti.NO_UPSTREAM and (_battery(n) or _structure_battery(n) or _multi_battery(n))
    )


def test_bt_battery_enumerates_structure_and_multi_argument_cases():
    """The structure classes are enumerated, not hand-picked: a missing site on the relay,
    malformed sites[] entries on query_isp_metrics, and multi-argument cases exist."""
    relay = dict(_structure_battery("fabric_connector_put"))
    assert relay.get("site") is not None and any(
        v is _DROP for p, v in _structure_battery("fabric_connector_put") if p == "site"
    )
    isp = [v for p, v in _structure_battery("query_isp_metrics") if p == "sites"]
    assert [_ENTRY, {"hostId": uh.HOST}] in isp and [_ENTRY, "x"] in isp, isp
    assert len([n for n in _lz_TOOLS() if _multi_battery(n)]) >= 100
    assert sum(len(_structure_battery(n)) for n in _lz_TOOLS()) >= 1000


#: "valid <field> values:" is the listing form of a well-formed index the selected record
#: does not have (get_device_port_state: "An unknown port_idx fails listing the valid
#: port_idx values").
_LOOKUP_MISS = re.compile(
    r"not found|[Vv]alid(?: choices| \w+ values)?:|Unexpected .*response shape"
)


def _data_dependent(message: str) -> bool:
    """An error that depends on upstream data: a well-formed selector the upstream does not
    have (it lists the valid choices), or an upstream shape the tool cannot use."""
    return bool(_LOOKUP_MISS.search(message)) or any(m in message for m in _DATA_MARKERS)


@tool_batches("name", lambda: _lz_BATTERY_TOOLS())
async def test_bt_argument_errors_come_before_any_request(monkeypatch, name):
    base = {**tool_args.generated_args(_lz_TOOLS()[name])}
    late: list[str] = []
    cases = [{pname: value} for pname, value in _battery(name) + _structure_battery(name)]
    cases += _multi_battery(name)
    for changes in cases:
        up = uh.FakeUpstream()
        mp = pytest.MonkeyPatch()
        try:
            await _call(mp, name, up, _apply(base, changes))
        except ToolError as exc:
            message = str(exc)
            if up.served and not _data_dependent(message):
                shown = {k: ("<left out>" if v is _DROP else v) for k, v in changes.items()}
                late.append(
                    f"{shown!r}: {len(up.served)} request(s) ({up.served[0].method} "
                    f"{up.served[0].path}) before: {message[:160]}"
                )
        finally:
            mp.undo()
    assert late == [], f"{name}: argument validated after upstream requests: {late}"


@tool_batches("name", lambda: cti.OPT_OUT_WRITE_TOOLS)
async def test_bt_opt_out_refusal_comes_before_argument_errors(monkeypatch, name):
    env_var = cti._AREA_WRITE_OPT_OUTS[FAMILY[name]]
    base = _write_args(name)
    cases = _battery(name) or [(None, None)]
    if name == "fabric_connector_get":
        # The numeric battery path is also a valid unclassified read. Cover a known
        # read route and both state-changing GET routes alongside it.
        cases += [
            ("path", "protect/api/cameras"),
            ("path", f"protect/api/cameras/{uh.ARG_ID}/disable-control"),
        ]
    for pname, value in cases:
        args = base if pname is None else {**base, pname: value}
        valid_read = (
            name == "fabric_connector_get"
            and pname == "path"
            and value in ("1690000000000", "protect/api/cameras")
        )
        up = uh.FakeUpstream()
        mp = pytest.MonkeyPatch()
        try:
            if valid_read:
                await _call(mp, name, up, args, env={env_var: "0"})
                assert up.writes() == []
                assert any(
                    request.method == "GET" and request.path.endswith(f"/proxy/{value}")
                    for request in up.served
                ), f"{name}: read route {value!r} was not relayed under opt-out"
            else:
                with pytest.raises(ToolError) as exc:
                    await _call(mp, name, up, args, env={env_var: "0"})
                message = str(exc.value)
                assert up.served == []
                # Schema validation precedes the tool and cannot name its opt-out.
                if "validation error" in message.lower() and env_var not in message:
                    continue
                if name == "fabric_connector_get" and not is_write_request(
                    "GET", args.get("path", "")
                ):
                    # Invalid paths fail before they can be classified as writes.
                    assert "path" in message, f"{name} {pname}={value!r}: {message[:200]}"
                else:
                    assert env_var in message, f"{name} {pname}={value!r}: {message[:200]}"
        finally:
            mp.undo()


_SELECTORS = ("host", "site", "key_label")
_BAD_SELECTORS = ["", "   ", "x\n", "x\r\n", "\tx", "x ", "a\x00b", "x\x7f"]


@functools.cache
def _lz_SELECTOR_CASES():
    return sorted(
        (n, p)
        for n in _lz_TOOLS()
        for p in _SELECTORS
        if p in (_lz_TOOLS()[n].parameters.get("properties") or {})
    )


def test_bt_selector_cases_cover_every_host_or_site_tool():
    with_selector = {n for n, _p in _lz_SELECTOR_CASES()}
    expected = {
        n
        for n, t in _lz_TOOLS().items()
        if {"host", "site"} & set(t.parameters.get("properties") or {})
    }
    assert expected <= with_selector and len(expected) >= 240, len(expected)


@tool_batches(("name", "pname"), lambda: _lz_SELECTOR_CASES())
async def test_bt_malformed_selector_is_rejected_before_any_request(monkeypatch, name, pname):
    base = {**tool_args.generated_args(_lz_TOOLS()[name])}
    failures = []
    for value in _BAD_SELECTORS:
        up = uh.FakeUpstream()
        mp = pytest.MonkeyPatch()
        try:
            await _call(mp, name, up, {**base, pname: value})
            failures.append(f"{value!r}: accepted")
        except ToolError as exc:
            if pname not in str(exc):
                failures.append(f"{value!r}: error does not name {pname!r}: {exc}")
            if up.served:
                failures.append(f"{value!r}: {len(up.served)} request(s) before: {exc}")
        finally:
            mp.undo()
    assert failures == [], f"{name}.{pname}: {failures}"


_ID_ARG = re.compile(r"(^|_)(id|ids|mac|macs)\Z")


def _id_args(name: str) -> list[str]:
    props = _lz_TOOLS()[name].parameters.get("properties") or {}
    return sorted(
        p for p, s in props.items() if _ID_ARG.search(p) and _types(s) & {"string", "array"}
    )


@functools.cache
def _lz_ID_ARG_CASES():
    return sorted((n, p) for n in _lz_TOOLS() for p in _id_args(n))


def test_bu_id_argument_set_is_non_trivial():
    assert len(_lz_ID_ARG_CASES()) >= 150, len(_lz_ID_ARG_CASES())


@tool_batches(("name", "pname"), lambda: _lz_ID_ARG_CASES())
async def test_bu_trailing_newline_id_is_rejected_before_any_request(monkeypatch, name, pname):
    args = {**tool_args.generated_args(_lz_TOOLS()[name])}
    valid = args.get(pname)
    spec = (_lz_TOOLS()[name].parameters.get("properties") or {})[pname]
    if "array" in _types(spec) and "string" not in _types(spec):
        item = valid[0] if isinstance(valid, list) and valid else uh.ARG_ID
        args[pname] = [f"{item}\n"]
    else:
        args[pname] = f"{valid if isinstance(valid, str) and valid else uh.ARG_ID}\n"
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    assert pname in str(exc.value) or pname.rstrip("s") in str(exc.value), (
        f"{name}: the error does not name {pname!r}: {exc.value}"
    )
    assert up.served == [], f"{name}.{pname}: requests before the rejection: {up.served}"


# ---- (bt) selectors nested inside list or dict arguments: every selector
# embedded in a list (``sites[i]``, ``host_ids[i]``, ...) or in the objects of a list
# (``sites[i].hostId`` / ``.siteId``) gets the top-level selector check before any request.
_NESTED_NAME = re.compile(r"(^|_)(sites|hosts|host_ids|ids|macs|mac|cameras)\Z")
#: Arguments dropped when a nested list is passed (the tool takes one or the other).
_NESTED_DROP = {
    "query_isp_metrics": ("host", "site"),
    "get_client_link_diagnostics": ("client_id",),
}


def _array_arg(spec: dict[str, Any]) -> bool:
    return "array" in _types(spec)


@functools.cache
def _lz_NESTED_CASES():
    return sorted(
        (n, p)
        for n in _lz_TOOLS()
        for p, spec in (_lz_TOOLS()[n].parameters.get("properties") or {}).items()
        if _array_arg(spec) and _NESTED_NAME.search(p)
    )


def test_bt_nested_selector_set_is_derived_and_covered():
    """Every list argument of hosts, sites or ids is a declared nested selector."""
    declared = set(NESTED_SELECTOR_ARGUMENTS) | set(NESTED_SELECTOR_FIELDS)
    assert {p for _n, p in _lz_NESTED_CASES()} <= declared, _lz_NESTED_CASES()
    assert {n for n, _p in _lz_NESTED_CASES()} >= {
        "compare_site_performance",
        "query_isp_metrics",
        "list_all_devices",
        "get_client_link_diagnostics",
        "list_protect_events",
        "collect_protect_events",
        "forget_device",
    }, _lz_NESTED_CASES()


#: Malformed NAME selectors (``cameras``): a name may carry surrounding whitespace (a
#: camera literally named "Garage "), so only empty and control characters are bad.
_BAD_NAMES = ["", "x\n", "x\r\n", "\tx", "a\x00b", "x\x7f"]
_PADDED_NAMES = ["Garage ", " Garage", "   "]


def _bad_for(pname: str) -> list[str]:
    kind = NESTED_SELECTOR_ARGUMENTS.get(pname)
    return _BAD_NAMES if kind in NAME_SELECTOR_KINDS else _BAD_SELECTORS


def _nested_values(pname: str) -> list[tuple[str, Any]]:
    """(path named in the error, list value) for each malformed nested selector."""
    out: list[tuple[str, Any]] = []
    fields = NESTED_SELECTOR_FIELDS.get(pname)
    for bad in [*_bad_for(pname), 5, ["x"]]:
        if fields:
            for field in fields:
                out.append((f"{pname}[1].{field}", [_ENTRY, {**_ENTRY, field: bad}]))
        else:
            out.append((f"{pname}[1]", ["probe-ok", bad]))
    return out


@tool_batches(("name", "pname"), lambda: _lz_NESTED_CASES())
async def test_bt_malformed_nested_selector_is_rejected_before_any_request(
    monkeypatch, name, pname
):
    base = {**tool_args.generated_args(_lz_TOOLS()[name])}
    for drop in _NESTED_DROP.get(name, ()):
        base.pop(drop, None)
    failures = []
    for where, value in _nested_values(pname):
        up = uh.FakeUpstream()
        mp = pytest.MonkeyPatch()
        try:
            await _call(mp, name, up, {**base, pname: value})
            failures.append(f"{value!r}: accepted")
        except ToolError as exc:
            if where not in str(exc) and "validation error" not in str(exc).lower():
                failures.append(f"{value!r}: error does not name {where!r}: {exc}")
            if up.served:
                failures.append(f"{value!r}: {len(up.served)} request(s) before: {exc}")
        finally:
            mp.undo()
    assert failures == [], f"{name}.{pname}: {failures}"


def _string_arg(spec: dict[str, Any]) -> bool:
    return "string" in _types(spec)


#: (tool, argument) for every selector-ish list argument that also takes ONE value as a
#: plain string (``cameras="Garage"``, ``mac="aa:..."``): the string form gets the same
#: check as the list form.
@functools.cache
def _lz_STRING_FORM_CASES():
    return sorted(
        (n, p)
        for n in _lz_TOOLS()
        for p, spec in (_lz_TOOLS()[n].parameters.get("properties") or {}).items()
        if p in NESTED_SELECTOR_ARGUMENTS and _string_arg(spec)
    )


def test_bt_string_form_cases_are_derived():
    assert {p for _n, p in _lz_STRING_FORM_CASES()} >= {"cameras", "mac"}, _lz_STRING_FORM_CASES()


@tool_batches(("name", "pname"), lambda: _lz_STRING_FORM_CASES())
async def test_bt_malformed_string_form_selector_is_rejected_before_any_request(
    monkeypatch, name, pname
):
    base = {**tool_args.generated_args(_lz_TOOLS()[name])}
    failures = []
    for bad in _bad_for(pname):
        up = uh.FakeUpstream()
        mp = pytest.MonkeyPatch()
        try:
            await _call(mp, name, up, {**base, pname: bad})
            failures.append(f"{bad!r}: accepted")
        except ToolError as exc:
            if f"'{pname}'" not in str(exc):
                failures.append(f"{bad!r}: error does not name {pname!r}: {exc}")
            if up.served:
                failures.append(f"{bad!r}: {len(up.served)} request(s) before: {exc}")
        finally:
            mp.undo()
    assert failures == [], f"{name}.{pname}: {failures}"


@lazy_parametrize(
    ("name", "pname"),
    lambda: [(n, p) for n, p in _lz_STRING_FORM_CASES() + _lz_NESTED_CASES() if p in ("cameras",)],
)
def test_bt_padded_name_selector_is_accepted_in_both_forms(name, pname):
    """A NAME selector may carry surrounding whitespace (only host, site,
    key_label and id / MAC selectors refuse it), in the string and the list form."""
    for value in _PADDED_NAMES:
        assert nested_selector_problems(pname, value) is None, (name, value)
        assert nested_selector_problems(pname, ["ok", value]) is None, (name, value)
    for value in _BAD_NAMES:
        assert nested_selector_problems(pname, value) is not None, (name, value)
        assert nested_selector_problems(pname, ["ok", value]) is not None, (name, value)


class _GarageUpstream(uh.FakeUpstream):
    """Serves one Protect camera literally named "Garage " (and a "Garage" twin)."""

    def __call__(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if req.method == "GET" and path.endswith("/protect/integration/v1/cameras"):
            body = [{"id": "6" * 24, "name": "Garage "}, {"id": "7" * 24, "name": "Garage"}]
            self._record(req, 200, body, False)
            return httpx.Response(200, json=body)
        return super().__call__(req)


@pytest.mark.parametrize("form", ["string", "list"])
@pytest.mark.parametrize("name", ["list_protect_events", "collect_protect_events"])
async def test_bt_camera_named_with_trailing_space_resolves(monkeypatch, name, form):
    """A camera literally named "Garage " passes the selector middleware and resolves to
    its own id (not the "Garage" twin), passed as a string and as a list."""
    up = _GarageUpstream(replay_recordings=False)
    args = {**tool_args.generated_args(_lz_TOOLS()[name])}
    args["cameras"] = "Garage " if form == "string" else ["Garage "]
    await _call(monkeypatch, name, up, args)
    events = [x for x in up.served if "/protect/api/events" in x.path]
    assert events, f"{name}: no events read"
    assert all("6" * 24 in x.query and "7" * 24 not in x.query for x in events), [
        x.query for x in events
    ]


# =========================================================================== (bv)
@tool_batches("name", lambda: _lz_WRITE_TOOLS())
async def test_bv_429_on_a_write_sends_it_once(monkeypatch, name):
    up = uh.FakeUpstream(write_status=429, error_body='{"error":"probe slow down"}')
    try:
        await _call(monkeypatch, name, up)
    except ToolError:
        pass
    sent = [
        (s.method, s.path, s.query, json.dumps(s.sent_json, sort_keys=True))
        for s in up.served
        if is_write_request(s.method, s.path, s.sent_json)
    ]
    assert sent, f"{name}: no write reached the transport"
    repeats = {w for w in sent if sent.count(w) > 1}
    assert not repeats, f"{name}: a write answered 429 was sent again: {sorted(repeats)[:2]}"


# =========================================================================== (bx)
class _RawUpstream(uh.FakeUpstream):
    """Answers relay requests to ``/probe-raw/`` paths with a fixed raw response."""

    raw: tuple[int, bytes, dict[str, str]] = (200, b"", {})

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if "/probe-raw" in req.url.path:
            status, content, headers = self.raw
            self._record(req, status, content, False)
            return httpx.Response(status, content=content, headers=headers)
        return super().__call__(req)


async def test_bx_relay_3xx_carries_location_and_safe_headers(monkeypatch):
    up = _RawUpstream()
    up.raw = (
        302,
        b"",
        {
            "location": "https://elsewhere.example/next",
            "x-probe": "kept",
            "set-cookie": "session=probe-cookie",
        },
    )
    args = {"host": uh.HOST, "path": "access/api/probe-raw/thing"}
    payload = uh.result_payload(await _call(monkeypatch, "fabric_connector_get", up, args))
    assert payload["status"] == 302
    headers = {k.lower(): v for k, v in payload["headers"].items()}
    assert headers["location"] == "https://elsewhere.example/next"
    assert headers["x-probe"] == "kept"
    assert "set-cookie" not in headers and "probe-cookie" not in json.dumps(payload)


@pytest.mark.parametrize("ctype", ["application/json", "text/plain; charset=utf-8"])
async def test_bx_relay_non_utf8_text_body_is_base64(monkeypatch, ctype):
    raw = b'{"name": "caf\xe9"}'  # Latin-1 bytes under a UTF-8 text/JSON type
    up = _RawUpstream()
    up.raw = (200, raw, {"content-type": ctype})
    args = {"host": uh.HOST, "path": "access/api/probe-raw/thing"}
    payload = uh.result_payload(await _call(monkeypatch, "fabric_connector_get", up, args))
    assert payload["body"] is None and base64.b64decode(payload["bodyBase64"]) == raw


@pytest.mark.parametrize(
    "path",
    [
        "access/api/s/{site}/stat/probe",
        "protect/api/s/{site}/stat/probe",
        "innerspace/api/s/{site}/stat",
    ],
)
async def test_bx_relay_stat_post_outside_network_is_a_write(monkeypatch, tmp_path, path):
    audit = tmp_path / "audit.log"
    up = uh.FakeUpstream()
    args = {"host": uh.HOST, "site": uh.SITE, "path": path, "body": {"probe": "relay"}}
    env = {"UNIFI_DRY_RUN": "1", "UNIFI_AUDIT_LOG": str(audit)}
    payload = uh.result_payload(
        await _call(monkeypatch, "fabric_connector_post", up, args, env=env)
    )
    assert not [s for s in up.served if s.method == "POST"], "a POST was sent under dry-run"
    assert is_dry_run_preview(payload.get("body")), payload
    assert audit.exists() and "dry_run" in audit.read_text()


async def test_br_relay_never_reports_no_op_for_a_rejected_write(monkeypatch):
    up = uh.FakeUpstream(write_status=409, error_body='{"error":"probe conflict"}')
    args = {
        "host": uh.HOST,
        "site": uh.SITE,
        "path": "network/api/s/{site}/rest/probe/1",
        "body": {"a": 1},
    }
    payload = uh.result_payload(await _call(monkeypatch, "fabric_connector_put", up, args))
    assert payload["status"] == 409
    assert payload["noOp"] is None and "changed" not in payload, payload


def __getattr__(name: str):
    """Lazy module attributes: the catalog-derived names, built on first access.

    ``cti.READ_TOOLS`` etc. keep working for importers without building the catalog
    when this module is imported.
    """
    accessor = globals().get(f"_lz_{name}")
    if accessor is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return accessor()
