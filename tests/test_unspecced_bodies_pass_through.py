"""Bodies with no published request schema are sent as given; guidance rides on errors.

Every write whose upstream operation has no published request schema (Classic REST, the
v2 API) sends the caller's body as given, whatever documented field is left out, and an
upstream error keeps its text with the documented guidance appended as a hint. Covered:

* the documented-fields writes (``create_port_forward``, ``create_traffic_rule``,
  ``create_traffic_route``, ``create_site_to_site_tunnel``, ``create_device_tag``): each
  documented field left out, one at a time;
* the purpose-scoped networkconf writes (VPN servers, site-to-site tunnels, WAN): a body
  naming another purpose;
* ``update_device_tag`` bodies that are neither documented form;
* ``create_radius_profile`` accounting port / secret without ``acct_server_ip``.

A tool whose operation IS published keeps refusing a spec-required field
(``unifi_fabric.refusals.SPEC_REQUIRED_FIELDS``, pinned in ``test_refusal_policy``).
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import test_spec_conformance as sc
from tests import tool_args
from tests import upstream_harness as uh

TOOLS = cti.TOOLS
_call = cti._call
_ERROR = json.dumps({"meta": {"rc": "error", "msg": "api.err.InvalidPayload"}, "data": []})


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


#: tool -> (body argument, documented fields, a body carrying them all).
DOCUMENTED: dict[str, tuple[str, tuple[str, ...], dict[str, Any]]] = {
    "create_port_forward": (
        "payload",
        ("name", "dst_port", "fwd", "fwd_port"),
        {"name": "SSH", "dst_port": "2222", "fwd": "192.0.2.10", "fwd_port": "22"},
    ),
    "create_traffic_rule": (
        "payload",
        ("action", "matching_target", "target_devices"),
        {
            "action": "BLOCK",
            "matching_target": "INTERNET",
            "target_devices": [{"type": "ALL_CLIENTS"}],
        },
    ),
    "create_traffic_route": (
        "payload",
        ("network_id", "matching_target", "target_devices"),
        {
            "network_id": uh.ARG_ID,
            "matching_target": "INTERNET",
            "target_devices": [{"type": "ALL_CLIENTS"}],
        },
    ),
    "create_site_to_site_tunnel": (
        "tunnel",
        ("name", "vpn_type"),
        {"name": "probe-tunnel", "vpn_type": "ipsec-vpn"},
    ),
    "create_device_tag": (
        "tag",
        ("name", "member_device_macs"),
        {"name": "probe-tag", "member_device_macs": [uh.ARG_MAC]},
    ),
}

CASES = sorted((n, f) for n, (_a, fields, _b) in DOCUMENTED.items() for f in fields)


def test_documented_tools_are_exactly_the_unspecced_creates():
    """Every tool listed has no published request schema (else it belongs in
    SPEC_REQUIRED_FIELDS)."""
    assert {"create_port_forward", "create_traffic_rule", "create_traffic_route"} <= set(DOCUMENTED)
    for name in DOCUMENTED:
        assert name in sc.UNSPECCED_EXEMPT, name


def _args(name: str, body: dict[str, Any]) -> dict[str, Any]:
    arg = DOCUMENTED[name][0] if name in DOCUMENTED else None
    out = tool_args.generated_args(TOOLS[name])
    if arg is not None:
        out[arg] = body
    return out


def _writes(up: uh.FakeUpstream) -> list[Any]:
    return [s for s in up.writes() if s.method != "GET"]


@pytest.mark.parametrize(("name", "field"), CASES)
async def test_body_without_a_documented_field_is_sent_as_given(monkeypatch, name, field):
    arg, _fields, full = DOCUMENTED[name]
    body = {k: v for k, v in full.items() if k != field}
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, _args(name, body))
    writes = _writes(up)
    assert len(writes) == 1, writes
    assert field not in (writes[0].sent_json or {})
    for key, value in body.items():
        assert writes[0].sent_json.get(key) == value, (key, writes[0].sent_json)


@pytest.mark.parametrize(("name", "field"), CASES)
async def test_upstream_error_keeps_its_text_and_gets_the_field_hint(monkeypatch, name, field):
    _arg, _fields, full = DOCUMENTED[name]
    body = {k: v for k, v in full.items() if k != field}
    up = uh.FakeUpstream(write_status=400, error_body=_ERROR)
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, _args(name, body))
    text = str(exc.value)
    assert "api.err.InvalidPayload" in text and "Hint:" in text, text
    assert text.index("api.err.InvalidPayload") < text.index("Hint:")
    assert field in text[text.index("Hint:") :], text


@pytest.mark.parametrize("name", sorted(DOCUMENTED))
async def test_complete_body_error_has_no_hint(monkeypatch, name):
    up = uh.FakeUpstream(write_status=400, error_body=_ERROR)
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, _args(name, DOCUMENTED[name][2]))
    assert "api.err.InvalidPayload" in str(exc.value) and "Hint:" not in str(exc.value)


# ---------------------------------------------------------------- purpose-scoped writes
PURPOSE = {
    "create_vpn_server": ("fields", "remote-user-vpn"),
    "update_vpn_server": ("fields", "remote-user-vpn"),
    "create_site_to_site_tunnel": ("tunnel", "site-vpn"),
    "update_site_to_site_tunnel": ("tunnel", "site-vpn"),
    "update_wan_interface": ("wan", "wan"),
}


def _purpose_args(name: str, purpose: str) -> dict[str, Any]:
    arg, _own = PURPOSE[name]
    args = tool_args.generated_args(TOOLS[name])
    base = dict(DOCUMENTED[name][2]) if name in DOCUMENTED else {"name": "probe-renamed"}
    args[arg] = {**base, "purpose": purpose}
    return args


@pytest.mark.parametrize("name", sorted(PURPOSE))
async def test_another_purpose_is_sent_as_given(monkeypatch, name):
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, _purpose_args(name, "corporate"))
    writes = _writes(up)
    assert len(writes) == 1 and writes[0].sent_json.get("purpose") == "corporate", writes


@pytest.mark.parametrize("name", sorted(PURPOSE))
async def test_another_purpose_error_gets_the_purpose_hint(monkeypatch, name):
    up = uh.FakeUpstream(write_status=400, error_body=_ERROR)
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, _purpose_args(name, "corporate"))
    text = str(exc.value)
    own = PURPOSE[name][1]
    assert "api.err.InvalidPayload" in text and f"purpose {own!r}" in text, text


# ---------------------------------------------------------------- update_device_tag forms
_BAD_TAG_BODIES = [
    {"member_device_macs": [uh.ARG_MAC], "device_mac_additions": []},
    {"member_device_macs": uh.ARG_MAC},
    {"member_device_macs": [7]},
    {"name": "probe-renamed"},
]


@pytest.mark.parametrize(
    "body", _BAD_TAG_BODIES, ids=["both", "not-a-list", "not-strings", "no-lists"]
)
async def test_update_device_tag_other_body_is_sent_verbatim(monkeypatch, body):
    name = "update_device_tag"
    args = {**tool_args.generated_args(TOOLS[name]), "tag": body}
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, args)
    writes = _writes(up)
    assert len(writes) == 1
    sent = {k: v for k, v in writes[0].sent_json.items() if k != "_id"}
    assert sent == body, sent
    up = uh.FakeUpstream(write_status=400, error_body=_ERROR)
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    assert "api.err.InvalidPayload" in str(exc.value) and "device_mac_additions" in str(exc.value)


async def test_update_device_tag_non_mac_member_is_sent_as_given(monkeypatch):
    name = "update_device_tag"
    args = {**tool_args.generated_args(TOOLS[name]), "tag": {"member_device_macs": ["not-a-mac"]}}
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, args)
    writes = _writes(up)
    assert len(writes) == 1 and "not-a-mac" in writes[0].sent_json.get("device_mac_additions", [])


# ---------------------------------------------------------------- RADIUS accounting
@pytest.mark.parametrize(
    "extra",
    [{"acct_server_port": 1813}, {"acct_server_secret": "probe-acct"}],
    ids=["port", "secret"],
)
async def test_radius_accounting_without_ip_is_sent_with_a_hint_on_error(monkeypatch, extra):
    name = "create_radius_profile"
    args = {**tool_args.generated_args(TOOLS[name]), **extra}
    up = uh.FakeUpstream()
    await _call(monkeypatch, name, up, args)
    writes = _writes(up)
    assert len(writes) == 1
    acct = writes[0].sent_json.get("acct_servers")
    assert acct and "ip" not in acct[0], writes[0].sent_json
    up = uh.FakeUpstream(write_status=400, error_body=_ERROR)
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    assert "api.err.InvalidPayload" in str(exc.value) and "acct_server_ip" in str(exc.value)
