"""Security equivalence across the public #42 step 6 switch (explicit inventory).

Public #42: "Security-focused tests and reviews verify auth/OAuth, read/write decisions,
dry-run and confirmation behavior, audit logging, and redaction remain equivalent."

Three layers, each against what the server did *before* the switch:

1. **Per-tool facts** (:mod:`tests.security_equivalence`): family, module, the four hints,
   the call-sensitive policy (read/write, by argument, confirmation, ``dry_run``, write
   families), the redaction wrapper and the connector write switch, for every tool, equal
   the capture frozen on the pre-switch head.
2. **Calls under fork profiles**: the behaviour baseline's recorded calls (public #42 step
   1: read, dry-run write, confirmed write, denied write, validation error, ``tool_not_
   exposed``) replayed under a family allowlist and under a ``module:`` exclusion return
   exactly the recorded result, and a removed family's tool is refused as recorded. The
   ``policy.refusal`` audit record of every refusal names the same ``tool_id`` and code.
   Opt-in redaction masks a credential in a write preview under every profile.
3. **Auth/OAuth**: bearer and OAuth accept and reject the same requests under every
   profile; selection never changes the HTTP auth gate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from tests import security_equivalence as se

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "scripts",):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import dump_tool_baseline as baseline  # noqa: E402

#: The profiles the calls are replayed under. ``fork`` is a family allowlist (a fork that
#: ships three families); ``module`` removes one sub-area module (the DNS tools of
#: ``vpn``) with the per-module switch, which the switch adds.
PROFILES: dict[str, dict[str, str]] = {
    "fork": {"UNIFI_FAMILY_ALLOW": "carrier,connector,vpn"},
    "module": {"UNIFI_EXCLUDE": "module:network_vpn_dns"},
}
#: The families each profile keeps, of those the replay covers.
KEPT: dict[str, tuple[str, ...]] = {
    "fork": ("carrier", "connector", "vpn"),
    "module": ("carrier", "connector", "vpn"),
}
#: Families each profile removes: their recorded read is refused with tool_not_exposed.
REMOVED: dict[str, tuple[str, ...]] = {"fork": ("network", "protect"), "module": ()}
CALL_KEYS = ("read", "write_dry_run", "write_confirm", "write_denied", "validation_error")


def _recorded(family: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((baseline.BASELINE_DIR / f"{family}.json").read_text())
    return data["calls"]


def _merge(env: dict[str, str], profile: dict[str, str]) -> dict[str, str]:
    out = dict(env)
    for name, value in profile.items():
        out[name] = f"{out[name]},{value}" if name == "UNIFI_EXCLUDE" and name in out else value
    return out


async def _replay(tool: str, arguments: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    async with baseline._session("full", env) as client:  # noqa: SLF001
        return await baseline._call(client, tool, arguments)  # noqa: SLF001


def _refusals(text: str) -> list[dict[str, Any]]:
    """The ``policy.refusal`` records on stderr, without their per-call fields."""
    out = []
    for line in text.splitlines():
        if '"event":"policy.refusal"' in line:
            record = json.loads(line)
            out.append(
                {k: v for k, v in record.items() if k not in ("timestamp_utc", "request_id")}
            )
    return out


# ------------------------------------------------------------------- 1. per-tool facts


def test_security_facts_equal_the_pre_switch_capture() -> None:
    problems = se.differences(se.load_fixture(), se.capture())
    assert problems == [], "\n".join(problems[:40])


def test_the_facts_comparison_names_a_moved_family_and_a_dropped_wrapper() -> None:
    """The comparison bites: a write tool filed under another family, or a handler that
    lost its redaction wrapper, is a named difference (seeded on a copy of the fixture)."""
    base = se.load_fixture()
    head = json.loads(json.dumps(base))
    head["tools"]["create_vpn_server"]["family"] = "network"
    head["tools"]["get_wlan_config"]["redacted"] = False
    assert se.differences(base, head) == [
        "create_vpn_server: family was 'vpn', is 'network'",
        "get_wlan_config: redacted was True, is False",
    ]


def test_every_family_tool_keeps_the_redaction_wrapper_and_meta_tools_their_policy() -> None:
    tools = se.load_fixture()["tools"]
    domain = {n: t for n, t in tools.items() if t["family"] != "meta"}
    assert domain and all(t["redacted"] for t in domain.values())
    assert tools["call_write_tool"]["policy"]["rule"] == "dispatch_target"
    assert tools["fabric_connector_get"]["policy"]["access"] == "by_argument"


# ------------------------------------------------------- 2. calls under fork profiles


@pytest.mark.parametrize("profile", sorted(PROFILES))
@pytest.mark.parametrize("family", ["carrier", "connector", "vpn"])
async def test_recorded_calls_are_unchanged_under_a_fork_profile(
    profile: str, family: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert family in KEPT[profile]
    calls = _recorded(family)
    for key in CALL_KEYS:
        call = calls[key]
        if call is None:
            continue
        capsys.readouterr()
        env = _merge(call["env"], PROFILES[profile])
        result = await _replay(call["tool"], call["arguments"], env)
        assert result == call["result"], f"{profile}/{family}/{key}"
        if key == "write_denied":
            # The audit record of the refusal names the same tool_id (family.name).
            assert _refusals(capsys.readouterr().err) == [
                {
                    "code": "write_denied",
                    "event": "policy.refusal",
                    "schema_version": "1",
                    "tool_id": f"{family}.{call['tool']}",
                    "upstream_calls": 0,
                }
            ]


@pytest.mark.parametrize("family", ["network", "protect"])
async def test_a_removed_family_is_refused_exactly_as_recorded(
    family: str, capsys: pytest.CaptureFixture[str]
) -> None:
    recorded = _recorded(family)["tool_not_exposed"]
    capsys.readouterr()
    result = await _replay(recorded["tool"], recorded["arguments"], PROFILES["fork"])
    assert result == recorded["result"]
    assert _refusals(capsys.readouterr().err) == [
        {
            "code": "tool_not_exposed",
            "event": "policy.refusal",
            "schema_version": "1",
            "tool_id": f"{family}.{recorded['tool']}",
            "upstream_calls": 0,
        }
    ]


async def test_a_module_exclusion_refuses_only_that_module(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The DNS tools of ``vpn`` (module ``network_vpn_dns``) are refused with the same
    ``tool_not_exposed`` envelope as a family exclusion; the rest of ``vpn`` is served."""
    vpn = _recorded("vpn")
    removed = vpn["tool_not_exposed"]["result"]
    capsys.readouterr()
    args = {"host": "hostname-0001", "site": "Default"}
    result = await _replay("list_static_dns_records", args, PROFILES["module"])
    text = removed["content"][0]["text"].replace("list_vpn_servers", "list_static_dns_records")
    assert result == {**removed, "content": [{"type": "text", "text": text}]}
    assert _refusals(capsys.readouterr().err)[0]["tool_id"] == "vpn.list_static_dns_records"
    read = vpn["read"]
    assert await _replay(read["tool"], read["arguments"], PROFILES["module"]) == read["result"]


_SECRET = "probe-passphrase-not-a-credential"


@pytest.mark.parametrize("profile", ["complete", "fork-network", "module"])
@pytest.mark.parametrize("redact", [False, True])
async def test_opt_in_redaction_masks_a_credential_under_every_profile(
    profile: str, redact: bool
) -> None:
    """A dry-run WLAN update carrying a passphrase: shown verbatim with redaction off and
    masked with ``UNIFI_REDACT_SECRETS`` on, whichever profile selects the tool."""
    env = {
        "complete": {},
        "fork-network": {"UNIFI_FAMILY_ALLOW": "network"},
        "module": PROFILES["module"],
    }[profile]
    env = {**env, "UNIFI_WRITE_POLICY": "dry-run"}
    if redact:
        env["UNIFI_REDACT_SECRETS"] = "true"
    arguments = {
        "host": "hostname-0001",
        "site": "Default",
        "wlan_id": "00000000-0000-4000-a000-000000000132",
        "payload": {"x_passphrase": _SECRET},
    }
    result = await _replay("update_wlan_config", arguments, env)
    assert result["isError"] is False, result
    body = result["structuredContent"]["preview"]["body"]
    assert body == {"x_passphrase": "***REDACTED***" if redact else _SECRET}
    assert (_SECRET in json.dumps(result)) is (not redact)


# ------------------------------------------------------------------------ 3. auth/OAuth

_AUTH_PROFILES = {"complete": {}, **PROFILES}


@pytest.mark.parametrize("profile", sorted(_AUTH_PROFILES))
async def test_bearer_auth_is_unchanged_under_every_profile(auth_http_client, profile) -> None:
    from tests.test_auth_http import post_initialize

    token = "profile-equivalence-token-0001"  # noqa: S105 - test-only value
    env = {"MCP_BEARER_TOKEN": token, **_AUTH_PROFILES[profile]}
    async with auth_http_client("bearer", env=env) as client:
        assert (await post_initialize(client)).status_code == 401
        assert (await post_initialize(client, authorization="Bearer wrong")).status_code == 401
        ok = await post_initialize(client, authorization=f"Bearer {token}")
        assert ok.status_code == 200


@pytest.mark.parametrize("profile", sorted(_AUTH_PROFILES))
async def test_oauth_is_unchanged_under_every_profile(auth_http_client, profile) -> None:
    from tests import test_auth_oauth as oauth

    env = {**oauth._oauth_env(), **_AUTH_PROFILES[profile]}  # noqa: SLF001
    for authorization, status in (
        (oauth._bearer(), 200),  # noqa: SLF001
        (None, 401),
        (oauth._bearer(audience="wrong-audience"), 401),  # noqa: SLF001
        (oauth._bearer(scopes=()), 401),  # noqa: SLF001
    ):
        resp = await oauth._initialize_oauth(auth_http_client, authorization, env=env)  # noqa: SLF001
        assert resp.status_code == status, (profile, status)
