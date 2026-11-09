"""Client ids, MAC rule and client types.

``purpose`` as an identity field of the pinned networkconf updates is in the ``bq``
battery of ``test_cross_tool_chokepoints``; a body naming another ``purpose`` is sent as
given (the upstream judges it) and its error gets the purpose hint, pinned in
``test_unspecced_bodies_pass_through``. This file pins: a non-UUID client id failing
fast, one MAC rule for every tool (a padded MAC is refused everywhere; a registry-derived
invariant), and ``list_clients(client_type=...)`` accepting every type the vendored spec
lists.
"""

from __future__ import annotations

import functools
import json
import pathlib
import re
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from tests._tool_classes import class_axis
from unifi_fabric import macs
from unifi_fabric.tools.clients import CLIENT_TYPES

SRC = pathlib.Path(macs.__file__).parent
TOOLS = cti.TOOLS
_MAC = "aa:bb:cc:dd:ee:ff"


# ============================================== client ids: a UUID or the client's MAC
@functools.cache
def _lz__CLIENT_ID_TOOLS():
    return sorted(
        n
        for n in ("block_client", "unblock_client", "reconnect_client", "get_client")
        if n in TOOLS
    )


@lazy_parametrize("name", lambda: _lz__CLIENT_ID_TOOLS())
@lazy_parametrize("bad", lambda: (["client-1", "6512a0b1c2d3e4f5a6b7c8d9", "12345"]))
async def test_non_uuid_client_id_fails_fast(monkeypatch, name, bad):
    args = {**tool_args.generated_args(TOOLS[name]), "client_id": bad}
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await cti._call(monkeypatch, name, up, args)
    assert "pass a UUID" in str(exc.value) and "MAC" in str(exc.value), exc.value
    assert up.served == [], f"{name}: requests before the refusal: {up.served}"


# ============================================== one MAC rule, a padded MAC refused anywhere
def _mac_args() -> list[tuple[str, str, bool]]:
    """(tool, argument, is_list) for every argument whose description says it takes a
    MAC (derived from the registry)."""
    out = []
    for name, tool in TOOLS.items():
        for pname, spec in (tool.parameters.get("properties") or {}).items():
            text = json.dumps(spec)
            # host / host_ids name consoles by their MAC:numericId composite, not a MAC
            skip = ("filter", "query", "body", "params", "path", "host", "host_ids")
            if "MAC" not in text or pname in skip:
                continue
            types = {spec.get("type")} | {s.get("type") for s in spec.get("anyOf", []) or []}
            if "string" in types or "array" in types:
                out.append((name, pname, "string" not in types))
    return sorted(out)


@functools.cache
def _lz_MAC_ARGS():
    return _mac_args()


def test_mac_argument_set_is_derived():
    names = {p for _n, p, _l in _lz_MAC_ARGS()}
    assert {"device_id", "client_id", "mac", "client_ids"} <= names, sorted(names)


@class_axis(
    ("name", "pname", "is_list"),
    lambda: _lz_MAC_ARGS(),
    padded=lambda: ([f" {_MAC}", f"{_MAC} ", f"\t{_MAC}", f"{_MAC}\n"]),
)
async def test_padded_mac_is_refused_before_any_request(monkeypatch, name, pname, is_list, padded):
    args = {**tool_args.generated_args(TOOLS[name])}
    if name == "get_client_link_diagnostics" and pname == "client_ids":
        args.pop("client_id", None)
    args[pname] = [padded] if is_list else padded
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await cti._call(monkeypatch, name, up, args)
    assert pname in str(exc.value), f"{name}.{pname}: {exc.value}"
    assert up.served == [], f"{name}.{pname}: requests before the refusal: {up.served}"


def _has_mac_pattern(text: str) -> bool:
    # A single hex byte also occurs in Python's xXX string-escape grammar.
    # Match MAC structure: repeated octets, a bare address, or MAC separators.
    octet = r"\[(?:0-9a-fA-F|0-9A-Fa-f)\]\{2\}"
    return bool(
        re.search(r"\[(?:0-9a-fA-F|0-9A-Fa-f)\]\{12\}|\[:[^\]\n]*-\]", text)
        or re.search(octet + r".*" + octet, text)
        or re.search(octet + r".*\{[56]\}", text)
    )


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        (r"\\x[0-9A-Fa-f]{2}", False),
        (r"\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2})", False),
        (r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", True),
        (r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", True),
        (r"(?:[0-9A-Fa-f]{2}:?){6}", True),
        (r"[0-9a-fA-F]{12}", True),
        (r"[:.-]", True),
    ],
)
def test_mac_pattern_lint_distinguishes_string_escapes(pattern, expected):
    assert _has_mac_pattern(pattern) is expected


def test_one_mac_validator():
    """``unifi_fabric.macs`` is the only MAC rule: no other module compiles a MAC pattern
    (the placement-snapshot sanitizer finds MACs inside free text to WITHHOLD
    them; secret_scrub escapes free-text patterns and does not validate caller MACs)
    and no tool strips a caller's MAC before checking."""
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name in ("macs.py", "placement_snapshot.py", "secret_scrub.py"):
            continue
        text = path.read_text()
        if _has_mac_pattern(text):
            offenders.append(f"{path.name}: compiles a MAC pattern")
        if re.search(r"_is_mac\([a-z_]+\.strip\(\)\)|is_mac\([a-z_]+\.strip\(\)\)", text):
            offenders.append(f"{path.name}: strips a caller's MAC before the check")
    assert offenders == [], offenders
    for form in (_MAC, "AA-BB-CC-DD-EE-FF", "aabbccddeeff", "aabb.ccdd.eeff"):
        assert macs.is_mac(form), form
    for bad in (f" {_MAC}", f"{_MAC} ", "aa:bb-cc:dd:ee:ff", "aa:bb:cc:dd:ee", "gg:bb:cc:dd:ee:ff"):
        assert not macs.is_mac(bad), bad


# ============================================== list_clients: every spec client type
def test_client_types_are_the_spec_discriminator():
    spec = json.loads(
        (pathlib.Path(__file__).parent / "fixtures/openapi/network-11.0.97.json").read_text()
    )
    schemas = spec["components"]["schemas"]
    for name in ("Client overview", "Client details"):
        mapping = schemas[name]["discriminator"]["mapping"]
        assert set(mapping) == set(CLIENT_TYPES), (name, sorted(mapping))


@pytest.mark.parametrize("ctype", [*CLIENT_TYPES, "vpn", "Teleport"])
async def test_list_clients_accepts_every_spec_type(monkeypatch, ctype):
    up = uh.FakeUpstream(replay_recordings=False)
    args: dict[str, Any] = {**tool_args.generated_args(TOOLS["list_clients"]), "client_type": ctype}
    await cti._call(monkeypatch, "list_clients", up, args)
    reads = [s for s in up.served if s.path.endswith("/clients") and not s.resolution]
    assert reads and all(f"type.eq('{ctype.upper()}')" in _unquote(s.query) for s in reads)


def _unquote(query: str) -> str:
    from urllib.parse import unquote_plus

    return unquote_plus(query)
