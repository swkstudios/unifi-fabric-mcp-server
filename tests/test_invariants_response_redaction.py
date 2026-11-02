"""Catalog response redaction: upstream fields are opt-in; own secrets never escape.

Every read and every connector relay runs against the REAL client/registry with only
HTTP transport mocked. Selection, wrappers and the four documented projections use
the same explicit contracts as test_cross_tool_invariants, not blanket exclusions.
Binary assets are checked byte-for-byte after removing only the echoed server key.
"""

from __future__ import annotations

import copy
import functools
import json
import re
from typing import Any

import httpx
import pytest

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from tests._tool_classes import class_axis
from unifi_fabric import route_secrets
from unifi_fabric.config import APIKeyConfig
from unifi_fabric.redaction import CREDENTIAL_FIELDS, REDACTION_MASK
from unifi_fabric.secret_scrub import MASK

# Synthetic test fixture, never a deployed credential.
OWN_KEY = "synthetic-l17-server-key-sentinel"
FIELDS = {
    "token": "upstream-token-value",
    "secret": "upstream-secret-value",
    "password": "upstream-password-value",
    "profileToken": "upstream-profile-token-value",
    "digitalInputTokens": ["upstream-digital-input-token-value"],
    "credentialProbe": {
        "TOKEN": "nested-upstream-token-value",
        "secret": {"arbitrary": [1, False, None]},
        "password": "nested-upstream-password-value",
    },
    "serverCredentialEcho": OWN_KEY,
    # Opt-in suffix rule (snake_case *_api_key/_secret/_token/_password/_passphrase).
    "google_maps_api_key": "upstream-google-maps-api-key-value",
    "utm_token": "upstream-utm-token-value",
    # Opt-in x_ rule (controller hidden credential fields).
    "x_authkey": "upstream-x-authkey-value",
    "x_stripe_api_key": "upstream-x-stripe-api-key-value",
    "x_wireguard_private_key": "upstream-x-wireguard-private-key-value",
    "x_openvpn_password": "upstream-x-openvpn-password-value",
    "wireguard_private_key": "upstream-wireguard-private-key-value",
    # Look-alikes that must stay verbatim in both modes.
    "token_count": 7,
    "key_id": "upstream-key-id",
    "radius_macacl_empty_password": False,
    "x_ssh_username": "upstream-ssh-username",
    "x_has_ssh_hostkey": True,
}
PATTERN_FIELDS = (
    "google_maps_api_key",
    "utm_token",
    "x_authkey",
    "x_stripe_api_key",
    "x_wireguard_private_key",
    "x_openvpn_password",
    "wireguard_private_key",
)
LOOKALIKE_FIELDS = (
    "token_count",
    "key_id",
    "radius_macacl_empty_password",
    "x_ssh_username",
    "x_has_ssh_hostkey",
    "profileToken",
    "digitalInputTokens",
)
# Independent oracle for the documented opt-in rules 2 and 3 (string values only),
# written as regexes so it never shares code with the production matcher.
_SUFFIX_RULE = re.compile(r"(?i)\A.*_(api_key|private_key|secret|token|password|passphrase)\Z")
_X_RULE = re.compile(
    r"(?i)\Ax_(?!has_).*(key|psk|passphrase|password|passwd|secret|token|signature)\Z"
)
# Rule 1 also covers these camelCase names, string values only; pagination cursors are
# never credentials; an exact-name field that is null or empty is left as is.
_STRING_ONLY_NAMES = frozenset({"acctserversecret", "authtoken", "hashedpassword", "wpapsk"})
_CURSOR_RULE = re.compile(r"(?i)\A(next|page|continuation)_?token\Z")


def _oracle_masks(key: str, item: Any) -> bool:
    if _CURSOR_RULE.match(key):
        return False
    lowered = key.lower()
    if lowered in CREDENTIAL_FIELDS or lowered in _STRING_ONLY_NAMES:
        if item is None or item == "":
            return False
        return lowered in CREDENTIAL_FIELDS or isinstance(item, str)
    return isinstance(item, str) and bool(_SUFFIX_RULE.match(key) or _X_RULE.match(key))


@functools.cache
def _lz_CATALOG():
    return sorted(set(cti.READ_TOOLS) | cti.RAW_RELAY)


def _inject(node: Any) -> Any:
    if isinstance(node, list):
        return [_inject(item) for item in node]
    if not isinstance(node, dict):
        return node
    result = {key: _inject(value) for key, value in node.items()}
    if any(key in node for key in ("id", "_id", "probe", "mac", "siteId")):
        result.update(copy.deepcopy(FIELDS))
    return result


class CredentialUpstream(uh.FakeUpstream):
    """Add probes to native record shapes before the client sees the HTTP body."""

    def __call__(self, req: httpx.Request) -> httpx.Response:
        response = super().__call__(req)
        served = self.served[-1]
        if isinstance(served.body, bytes):
            body = served.body + b"\n" + OWN_KEY.encode()
            served.body = body
            return httpx.Response(response.status_code, content=body, headers=response.headers)
        body = _inject(served.body)
        served.body = body
        return httpx.Response(response.status_code, json=body)


def _route_fields(method: str, path: str) -> frozenset[str]:
    """The JSON keys the route-secret registry lists for one served route.

    The registry is the documented policy table (each entry's own route matching is
    proved in tests/test_route_secrets.py); this oracle reads only which keys a route
    lists (request fields echoed back count, as the registry documents) and masks them
    itself.
    """
    return frozenset(
        name
        for entry in route_secrets.matching(method, path)
        for name in (*entry.request_fields, *entry.response_fields)
    )


def _has_secret_leaf(value: Any) -> bool:
    """A non-blank string or a number (not a bool) anywhere in ``value``."""
    if isinstance(value, dict):
        return any(_has_secret_leaf(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_secret_leaf(item) for item in value)
    if isinstance(value, str):
        return bool(value.strip())
    return type(value) in (int, float)


def _route_values(served: list[uh.Served]) -> frozenset[str]:
    """Every credential value the call binds from its served route-secret fields.

    Under the opt-in a successful body is also scrubbed of the call's bound secret
    values (client._request), so such a value is masked (``MASK``) wherever it appears
    as a whole token, not only under its listed key. Numbers bind as their text.
    """
    out: set[str] = set()

    def leaves(value: Any) -> None:
        if isinstance(value, dict):
            for item in value.values():
                leaves(item)
        elif isinstance(value, list):
            for item in value:
                leaves(item)
        elif isinstance(value, str) and value.strip():
            out.add(value)
        elif type(value) in (int, float):
            out.add(str(value))

    def walk(value: Any, names: frozenset[str]) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in names:
                    leaves(item)
                else:
                    walk(item, names)
        elif isinstance(value, list):
            for item in value:
                walk(item, names)

    for entry in served:
        if not isinstance(entry.body, bytes | str):
            walk(entry.body, _route_fields(entry.method, entry.path))
    return frozenset(out)


def _scrub_tokens(text: str, values: frozenset[str]) -> str:
    """``text`` with each bound value replaced by ``MASK`` where it stands as a whole token
    (no ASCII letter or digit directly before or after it)."""
    for value in sorted(values, key=len, reverse=True):
        text = re.sub(rf"(?<![A-Za-z0-9]){re.escape(value)}(?![A-Za-z0-9])", MASK, text)
    return text


def _expected(
    node: Any,
    enabled: bool,
    *,
    route: frozenset[str] = frozenset(),
    bound: frozenset[str] = frozenset(),
) -> Any:
    # Own-key scrubbing is unconditional and distinct from the central field mask.
    if isinstance(node, bytes):
        return node.replace(OWN_KEY.encode(), MASK.encode())
    scrubbed = json.loads(json.dumps(node).replace(OWN_KEY, MASK))
    if not enabled:
        return scrubbed

    # Independent oracle: never invoke the production transform under test.
    def mask(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: REDACTION_MASK
                if isinstance(key, str)
                and (_oracle_masks(key, item) or key in route and _has_secret_leaf(item))
                else mask(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [mask(item) for item in value]
        if isinstance(value, str) and bound:
            return _scrub_tokens(value, bound)
        return value

    return mask(scrubbed)


@class_axis(
    "name",
    lambda: _lz_CATALOG(),
    enabled=lambda: ([False, True]),
)
async def test_catalog_upstream_redaction_is_opt_in(monkeypatch, name, enabled):
    """Every read/relay preserves upstream records or applies only central masking."""
    upstream = CredentialUpstream()
    result = await cti._call(
        monkeypatch,
        name,
        upstream,
        env={"UNIFI_REDACT_SECRETS": "1" if enabled else "0"},
        keys=[APIKeyConfig(label="synthetic", key=OWN_KEY)],
    )
    payload = uh.result_payload(result)
    assert OWN_KEY not in json.dumps(payload), name
    # Verify text and structured result channels, rather than checking only one view.
    for block in result.content:
        assert OWN_KEY not in (getattr(block, "text", None) or ""), name
    if name in cti.NO_UPSTREAM:
        assert not upstream.served, cti.NO_UPSTREAM[name]
        return
    assert upstream.served, f"{name}: transport was not exercised"
    assert any(OWN_KEY in repr(s.body) for s in upstream.served), name
    bound = _route_values(upstream.served) if enabled else frozenset()
    for served in upstream.served:
        served.body = _expected(
            served.body, enabled, route=_route_fields(served.method, served.path), bound=bound
        )
    if name in cti.DERIVED:
        # Explicit sanitized-placement projection, fleet/InnerSpace rollups and
        # device-change diff are computed contracts, checked against served inputs.
        problems = cti._derived_problems(name, payload, upstream)
    else:
        problems = cti._fidelity_violations(name, payload, upstream)
    problems += cti._binary_problems(name, payload, upstream)
    assert problems == [], f"{name}: " + "; ".join(problems[:5])


@pytest.mark.parametrize("enabled", [False, True], ids=["redaction-off", "redaction-on"])
async def test_known_device_credentials_use_documented_mask(monkeypatch, enabled):
    """Explicit field assertions also catch accidental credential-table removal."""
    upstream = CredentialUpstream()
    result = await cti._call(
        monkeypatch,
        "list_devices",
        upstream,
        env={"UNIFI_REDACT_SECRETS": "1" if enabled else "0"},
        keys=[APIKeyConfig(label="synthetic", key=OWN_KEY)],
    )
    payload = uh.result_payload(result)
    # Every object the upstream double injected the probe fields into (a recorded device
    # carries no synthetic ``probe`` key since captures are replayed).
    records = [record for record in cti._nested_objects(payload) if "credentialProbe" in record]
    assert records, "list_devices must return the injected upstream device"
    for record in records:
        for field in ("token", "secret", "password"):
            assert record[field] == (REDACTION_MASK if enabled else FIELDS[field])
        nested = record["credentialProbe"]
        for field in ("TOKEN", "secret", "password"):
            assert nested[field] == (
                REDACTION_MASK if enabled else FIELDS["credentialProbe"][field]
            )
        for field in PATTERN_FIELDS:
            assert record[field] == (REDACTION_MASK if enabled else FIELDS[field]), field
        for field in LOOKALIKE_FIELDS:
            assert record[field] == FIELDS[field], field
    assert OWN_KEY not in json.dumps(payload)


async def test_protect_private_relay_preserves_noncredential_token_fields(monkeypatch):
    """profileToken/digitalInputTokens caused the live substring-redaction defect."""
    upstream = CredentialUpstream()
    result = await cti._call(
        monkeypatch,
        "fabric_connector_get",
        upstream,
        args={"host": uh.HOST, "path": "protect/api/cameras"},
        env={"UNIFI_REDACT_SECRETS": "0"},
        keys=[APIKeyConfig(label="synthetic", key=OWN_KEY)],
    )
    payload = uh.result_payload(result)
    assert any("/proxy/protect/api/cameras" in s.path for s in upstream.served)
    index = uh.PayloadIndex(payload)
    for served in upstream.served:
        if served.resolution:
            continue
        for record in uh.upstream_records(served.body):
            assert index.contains(_expected(record, False))
    assert OWN_KEY not in json.dumps(payload)


def test_catalog_redaction_exceptions_remain_explicit():
    assert set(cti.NO_UPSTREAM) <= set(_lz_CATALOG())
    assert set(cti.DERIVED) <= set(_lz_CATALOG())
    assert cti.RAW_RELAY <= set(_lz_CATALOG())
    for reason in [*cti.NO_UPSTREAM.values(), *cti.DERIVED.values()]:
        assert len(reason.split()) >= 4
