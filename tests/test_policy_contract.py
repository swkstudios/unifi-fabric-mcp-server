"""Policy contract: settings grammar, evaluator, truth table and the policy records.

The versioned fixture envelopes live in tests/fixtures/contracts/s/v1 and are loaded
unchanged. Settings cells of the unset/blank/empty truth table each have a fixture or a
case here; the header cells belong to tests/test_tightening_contract.py.
"""

from __future__ import annotations

import functools
import io
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from tests._tool_catalog import lazy_parametrize
from unifi_fabric import api_sources, policy
from unifi_fabric.contracts import EffectivePolicy, canonical_policy_json, policy_digest
from unifi_fabric.policy import (
    Catalog,
    PolicyHeaderError,
    StartupRefusal,
    ToolFacts,
    canonical_policy_object,
)

FIXTURES = Path(__file__).parent / "fixtures" / "contracts" / "s" / "v1"
FIXTURE_FILES = sorted(FIXTURES.glob("*.json"))
DISCOVERY_META = (
    "search_tools",
    "describe_tool",
    "call_read_tool",
    "call_write_tool",
    "list_tool_families",
)
RELAYS = tuple(f"fabric_connector_{verb}" for verb in ("delete", "get", "patch", "post", "put"))
ENVELOPE_KEYS = {"schema_version", "contract", "name", "description", "kind", "input", "expected"}
ACCEPT_KEYS = {
    "effective_policy",
    "ignored_loosening",
    "selected_labels",
    "listed_tools",
    "upstream_calls",
    "upstream_mutations",
}


# --------------------------------------------------------------------------- helpers


@pytest.fixture(scope="session")
def catalog() -> Catalog:
    """The baseline roster as policy facts (the discovery meta tools added as reads)."""
    from tests._tool_catalog import tools
    from unifi_fabric.families import build_family_index

    registered = {tool.name: api_sources.selection_access(tool) for tool in tools()}
    registered.update({name: api_sources.READ for name in DISCOVERY_META})
    return Catalog.build(
        families=build_family_index(), sources=api_sources.table(), access=registered
    )


def _synthetic_catalog() -> Catalog:
    access = {name: api_sources.READ for name in policy.META_TOOL_NAMES}
    access.update(
        {
            "list_cameras": api_sources.READ,
            "update_camera": api_sources.WRITE,
            "create_network": api_sources.WRITE,
            "fabric_connector_post": api_sources.WRITE,
            "fabric_connector_get": api_sources.READ,
        }
    )
    return Catalog.build(
        families={
            "list_cameras": "protect",
            "update_camera": "protect",
            "create_network": "network",
            "fabric_connector_post": "connector",
            "fabric_connector_get": "connector",
        },
        sources={
            "list_configured_api_keys": ("server/local",),
            "list_cameras": ("protect/official",),
            "update_camera": ("protect/private",),
            "create_network": ("network/official",),
            "fabric_connector_post": ("relay/generic",),
            "fabric_connector_get": ("relay/generic",),
        },
        access=access,
    )


SYNTH = _synthetic_catalog()


def _known_settings(env: dict[str, str]) -> set[str]:
    """Settings this test treats as current: every fixture env name except the generic
    retired one (the real set is derived from the settings models)."""
    return {name for name in env if "RETIRED" not in name and name == name.upper()}


def _evaluate(env: dict[str, str], cat: Catalog) -> EffectivePolicy:
    policy.check_retired_settings(env, _known_settings(env))
    return policy.operator_policy(env, cat)


def _listed(effective: EffectivePolicy, cat: Catalog, mode: str) -> list[str]:
    if mode == "discovery":
        return sorted(DISCOVERY_META)
    return sorted(
        name for name in policy.exposed_names(effective, cat) if name not in DISCOVERY_META
    )


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- envelopes


def test_fixture_directory_is_populated() -> None:
    assert len(FIXTURE_FILES) >= 8


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda p: p.stem)
def test_fixture_envelope_shape(path: Path) -> None:
    data = _load(path)
    assert set(data) == ENVELOPE_KEYS
    assert data["schema_version"] == "1"
    assert data["contract"] == "s" == path.parent.parent.name
    assert data["name"] == path.stem
    assert data["description"].strip()
    assert data["kind"] in {"accept", "reject"}
    assert set(data["input"]) <= {"env", "headers", "arguments", "route", "transport", "upstream"}
    assert all(isinstance(v, str) for v in data["input"]["env"].values())
    if data["kind"] == "reject":
        assert set(data["expected"]) == {"code", "upstream_calls"}
        assert data["expected"]["upstream_calls"] == 0
    else:
        assert set(data["expected"]) <= ACCEPT_KEYS


def test_fixtures_validate_against_c0_schema() -> None:
    import jsonschema

    schema_path = FIXTURES.parent.parent / "fixture.schema.json"
    schema = _load(schema_path)
    for path in FIXTURE_FILES:
        jsonschema.validate(_load(path), schema)


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda p: p.stem)
def test_fixture_outcome(path: Path, catalog: Catalog) -> None:
    data = _load(path)
    env = data["input"]["env"]
    expected = data["expected"]
    if data["kind"] == "reject":
        with pytest.raises(StartupRefusal) as info:
            _evaluate(env, catalog)
        assert info.value.token == expected["code"]
        assert "synthetic-key-a" not in info.value.message
        return
    effective = _evaluate(env, catalog)
    if "effective_policy" in expected:
        assert canonical_policy_object(effective) == expected["effective_policy"]
    if "listed_tools" in expected:
        mode = env.get("UNIFI_TOOL_MODE", "discovery")
        assert _listed(effective, catalog, mode) == expected["listed_tools"]
    assert expected.get("upstream_calls", 0) == 0


# --------------------------------------------------------------------------- truth table


def test_unset_settings_take_defaults() -> None:
    effective = policy.operator_policy({}, SYNTH)
    assert effective == EffectivePolicy("allow", (), policy.FAMILIES, frozenset())
    assert len(effective.exposed_families) == 13


@pytest.mark.parametrize("setting", policy.POLICY_SETTINGS)
@pytest.mark.parametrize("blank", ["", " ", "\t \n"])
def test_blank_setting_fails_startup_naming_it(setting: str, blank: str) -> None:
    with pytest.raises(StartupRefusal) as info:
        policy.operator_policy({setting: blank}, SYNTH)
    assert info.value.token == f"startup:{setting}"
    assert setting in info.value.message


def test_exclusions_may_remove_every_domain_tool(catalog: Catalog) -> None:
    env = {"UNIFI_EXCLUDE": ",".join(f"family:{f}" for f in sorted(policy.FAMILIES))}
    effective = policy.operator_policy(env, catalog)
    assert effective.exposed_families == frozenset()
    assert policy.exposed_names(effective, catalog) == policy.META_TOOL_NAMES


# --------------------------------------------------------------------------- grammar


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("UNIFI_WRITE_POLICY", "Allow"),
        ("UNIFI_WRITE_POLICY", "read-only"),
        ("UNIFI_WRITE_POLICY", "allow,deny"),
        ("UNIFI_WRITE_EXCEPTIONS", "family:network"),
        ("UNIFI_WRITE_EXCEPTIONS", "family:network=allow"),
        ("UNIFI_WRITE_EXCEPTIONS", "family:network=deny;"),
        ("UNIFI_WRITE_EXCEPTIONS", ";family:network=deny"),
        ("UNIFI_WRITE_EXCEPTIONS", "family:network=deny;;family:protect=deny"),
        ("UNIFI_WRITE_EXCEPTIONS", "family:meta=deny"),
        ("UNIFI_WRITE_EXCEPTIONS", "tool:search_tools=deny"),
        ("UNIFI_WRITE_EXCEPTIONS", "source:relay=deny"),
        ("UNIFI_WRITE_EXCEPTIONS", "family:Network=deny"),
        ("UNIFI_WRITE_EXCEPTIONS", "family:network=deny,family:protect=deny"),
        ("UNIFI_FAMILY_ALLOW", "meta"),
        ("UNIFI_FAMILY_ALLOW", "Network"),
        ("UNIFI_FAMILY_ALLOW", "network protect"),
        ("UNIFI_FAMILY_ALLOW", "network,network"),
        ("UNIFI_FAMILY_ALLOW", ",network"),
        ("UNIFI_EXCLUDE", "protect"),
        ("UNIFI_EXCLUDE", "family:"),
        ("UNIFI_EXCLUDE", "tool:list_configured_api_keys"),
        ("UNIFI_EXCLUDE", "source:"),
        ("UNIFI_EXCLUDE", "source:network/official/write"),
        ("UNIFI_EXCLUDE", "Unofficial"),
        ("UNIFI_EXCLUDE", "unofficial,unofficial"),
        ("UNIFI_EXCLUDE", "family:protect;family:network"),
    ],
)
def test_malformed_values_fail_startup(setting: str, value: str) -> None:
    with pytest.raises(StartupRefusal) as info:
        policy.operator_policy({setting: value}, SYNTH)
    assert info.value.token == f"startup:{setting}"


def test_tokens_are_trimmed_of_ascii_whitespace() -> None:
    effective = policy.operator_policy(
        {
            "UNIFI_WRITE_POLICY": "\tdeny \n",
            "UNIFI_FAMILY_ALLOW": " network , protect ",
            "UNIFI_EXCLUDE": " unofficial ,\tsource:relay ",
        },
        SYNTH,
    )
    assert effective.write_policy == "deny"
    assert effective.exposed_families == {"network", "protect"}
    assert effective.exclusions == {"unofficial", "source:relay"}


def test_meta_tool_target_names_the_token() -> None:
    with pytest.raises(StartupRefusal) as info:
        policy.operator_policy({"UNIFI_EXCLUDE": "family:protect,tool:search_tools"}, SYNTH)
    assert info.value.token == "startup:UNIFI_EXCLUDE"
    assert "tool:search_tools" in info.value.message


def test_meta_tool_header_form_is_invalid_policy_header() -> None:
    base = policy.operator_policy({}, SYNTH)
    with pytest.raises(PolicyHeaderError) as info:
        policy.request_policy(base, SYNTH, exclude="tool:search_tools")
    assert info.value.code == "invalid_policy_header"
    assert info.value.header == "x-unifi-exclude"


def test_source_values_are_exactly_the_baseline_selectors() -> None:
    for selector in api_sources.valid_selectors():
        effective = policy.operator_policy({"UNIFI_EXCLUDE": f"source:{selector}"}, SYNTH)
        assert effective.exclusions == {f"source:{selector}"}


def test_retired_setting_fails_by_name_never_value() -> None:
    env = {"UNIFI_EXAMPLE_RETIRED": "value-not-shown", "UNIFI_API_KEY": "synthetic-key-a"}
    with pytest.raises(StartupRefusal) as info:
        policy.check_retired_settings(env, {"UNIFI_API_KEY"})
    assert info.value.token == "startup:retired:UNIFI_EXAMPLE_RETIRED"
    assert "UNIFI_EXAMPLE_RETIRED" in info.value.message
    assert policy.MIGRATION_URL in info.value.message
    assert info.value.explain
    assert "value-not-shown" not in info.value.message
    assert "synthetic-key-a" not in info.value.message


def test_non_prefixed_and_known_settings_pass_retired_check() -> None:
    env = {"PATH": "/bin", "FASTMCP_PORT": "8000", "UNIFI_API_KEY": "k", "UNIFI_EXCLUDE": "x"}
    policy.check_retired_settings(env, {"UNIFI_API_KEY"})


# --------------------------------------------------------------------------- meta tools


@pytest.mark.parametrize(
    "token",
    ["source:server", "source:server/local", "source:*/local", "source:relay", "unofficial"],
)
def test_exclusions_never_remove_meta_tools(token: str, catalog: Catalog) -> None:
    effective = policy.operator_policy({"UNIFI_EXCLUDE": token}, catalog)
    exposed = policy.exposed_names(effective, catalog)
    assert policy.META_TOOL_NAMES <= exposed
    assert {catalog.tools[n].family for n in policy.META_TOOL_NAMES} == {"meta"}


def test_source_relay_removes_the_five_relays(catalog: Catalog) -> None:
    effective = policy.operator_policy({"UNIFI_EXCLUDE": "source:relay"}, catalog)
    exposed = policy.exposed_names(effective, catalog)
    assert not set(RELAYS) & exposed
    removed = set(catalog.tools) - exposed
    assert removed == set(RELAYS)


def test_unofficial_removes_only_private_source_tools(catalog: Catalog) -> None:
    effective = policy.operator_policy({"UNIFI_EXCLUDE": "unofficial"}, catalog)
    exposed = policy.exposed_names(effective, catalog)
    removed = set(catalog.tools) - exposed
    assert removed
    assert all(catalog.tools[n].api_status == "unofficial" for n in removed)
    assert set(RELAYS) <= exposed


def test_catalog_facts_cover_every_tool(catalog: Catalog) -> None:
    assert catalog.meta_names == policy.META_TOOL_NAMES
    assert len(catalog.domain_names) > 700
    assert {t.family for t in catalog.tools.values()} == policy.FAMILIES | {"meta"}
    assert catalog.canonical_id("search_tools") == "meta.search_tools"
    assert catalog.canonical_id("fabric_connector_post") == "connector.fabric_connector_post"
    assert catalog.canonical_id("nope") is None


def test_unclassified_domain_tool_fails_catalog_validation() -> None:
    with pytest.raises(ValueError, match="no family or API-source"):
        Catalog.build(families={}, sources={}, access={"mystery_tool": api_sources.READ})


def test_meta_names_match_discovery() -> None:
    from unifi_fabric.discovery import META_TOOLS

    assert policy.META_TOOL_NAMES == META_TOOLS | {"list_configured_api_keys"}


# --------------------------------------------------------------------------- exposure


def test_tool_and_family_exclusions(catalog: Catalog) -> None:
    effective = policy.operator_policy(
        {"UNIFI_FAMILY_ALLOW": "protect,connector", "UNIFI_EXCLUDE": "tool:fabric_connector_post"},
        catalog,
    )
    exposed = policy.exposed_names(effective, catalog)
    assert "fabric_connector_get" in exposed
    assert "fabric_connector_post" not in exposed
    assert all(catalog.tools[n].family in {"protect", "connector", "meta"} for n in exposed)


# --------------------------------------------------------------------------- write decisions

_ORDER = ("allow", "dry-run", "deny")


@pytest.mark.parametrize("global_policy", _ORDER)
@pytest.mark.parametrize("family_exc", [None, "dry-run", "deny"])
@pytest.mark.parametrize("tool_exc", [None, "dry-run", "deny"])
def test_strictest_of_global_and_exceptions_wins(
    global_policy: str, family_exc: str | None, tool_exc: str | None
) -> None:
    exceptions = []
    if family_exc:
        exceptions.append(f"family:network={family_exc}")
    if tool_exc:
        exceptions.append(f"tool:create_network={tool_exc}")
    env = {"UNIFI_WRITE_POLICY": global_policy}
    if exceptions:
        env["UNIFI_WRITE_EXCEPTIONS"] = ";".join(exceptions)
    effective = policy.operator_policy(env, SYNTH)
    expected = max((global_policy, family_exc or "allow", tool_exc or "allow"), key=_ORDER.index)
    assert policy.write_mode(effective, tool_name="create_network", family="network") == expected
    other = policy.write_mode(effective, tool_name="update_camera", family="protect")
    assert other == global_policy


# --------------------------------------------------------------------------- request headers


def test_request_policy_only_tightens() -> None:
    base = policy.operator_policy(
        {"UNIFI_WRITE_POLICY": "dry-run", "UNIFI_FAMILY_ALLOW": "protect,network"}, SYNTH
    )
    effective, ignored = policy.request_policy(
        base, SYNTH, write_policy="allow", family_allow="vpn,network,mobility"
    )
    assert effective.write_policy == "dry-run"
    assert effective.exposed_families == {"network"}
    assert ignored == (
        "x-unifi-write-policy=allow",
        "x-unifi-family-allow=vpn",
        "x-unifi-family-allow=mobility",
    )


def test_request_exclude_family_net_reading() -> None:
    base = policy.operator_policy({}, SYNTH)
    effective, ignored = policy.request_policy(base, SYNTH, exclude="family:network")
    assert "network" not in effective.exposed_families
    assert effective.exclusions == {"family:network"}
    assert ignored == ()


def test_request_empty_intersection() -> None:
    base = policy.operator_policy({"UNIFI_FAMILY_ALLOW": "protect"}, SYNTH)
    effective, ignored = policy.request_policy(base, SYNTH, family_allow="network")
    assert effective.exposed_families == frozenset()
    assert ignored == ("x-unifi-family-allow=network",)
    assert policy.exposed_names(effective, SYNTH) == policy.META_TOOL_NAMES


@pytest.mark.parametrize(
    ("kwargs", "header"),
    [
        ({"write_policy": " "}, "x-unifi-write-policy"),
        ({"write_policy": "loud"}, "x-unifi-write-policy"),
        ({"family_allow": ""}, "x-unifi-family-allow"),
        ({"family_allow": "meta"}, "x-unifi-family-allow"),
        ({"exclude": "\t"}, "x-unifi-exclude"),
        ({"exclude": "family:protect,"}, "x-unifi-exclude"),
    ],
)
def test_request_header_errors(kwargs: dict[str, str], header: str) -> None:
    base = policy.operator_policy({}, SYNTH)
    with pytest.raises(PolicyHeaderError) as info:
        policy.request_policy(base, SYNTH, **kwargs)
    assert info.value.header == header
    assert info.value.code == "invalid_policy_header"


# --------------------------------------------------------------------------- records


def _sample_policy() -> EffectivePolicy:
    return policy.operator_policy(
        {
            "UNIFI_WRITE_POLICY": "dry-run",
            "UNIFI_WRITE_EXCEPTIONS": "tool:fabric_connector_post=deny;family:network=deny",
            "UNIFI_EXCLUDE": "family:protect,unofficial",
        },
        SYNTH,
    )


def test_canonical_json_and_digest() -> None:
    effective = _sample_policy()
    text = canonical_policy_json(effective)
    assert " " not in text
    obj = json.loads(text)
    assert list(obj) == sorted(obj)
    assert obj["write_exceptions"] == [
        ["family:network", "deny"],
        ["tool:fabric_connector_post", "deny"],
    ]
    assert obj["exclusions"] == ["family:protect", "unofficial"]
    import hashlib

    assert policy_digest(effective) == hashlib.sha256(text.encode()).hexdigest()


def test_startup_record_shape() -> None:
    effective = _sample_policy()
    line = policy.startup_record(effective)
    assert "\n" not in line
    record = json.loads(line)
    assert set(record) == policy.STARTUP_FIELDS
    assert record["schema_version"] == "1"
    assert record["event"] == "policy.startup"
    assert record["effective_policy"] == canonical_policy_object(effective)
    assert record["digest"] == policy_digest(effective)
    assert record["timestamp_utc"].endswith("+00:00")
    assert line == json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def test_refusal_record_shape() -> None:
    line = policy.refusal_record(
        request_id="0" * 32, tool_id="network.create_network", code="write_denied", upstream_calls=0
    )
    record = json.loads(line)
    assert set(record) == policy.REFUSAL_FIELDS
    assert record["event"] == "policy.refusal"
    assert record["tool_id"] == "network.create_network"
    assert record["upstream_calls"] == 0
    assert line == json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    unresolved = json.loads(
        policy.refusal_record(
            request_id="1" * 32, tool_id=None, code="tool_not_exposed", upstream_calls=0
        )
    )
    assert unresolved["tool_id"] is None


def test_records_carry_no_label_key_fingerprint_or_header() -> None:
    lines = [
        policy.startup_record(_sample_policy()),
        policy.refusal_record(
            request_id="a" * 32, tool_id=None, code="write_denied", upstream_calls=0
        ),
    ]
    for line in lines:
        lowered = line.lower()
        for forbidden in ("label", "key_fingerprint", "x-unifi", "api_key", "synthetic-key"):
            assert forbidden not in lowered


def test_records_are_emitted_with_logging_off() -> None:
    stream = io.StringIO()
    logging.disable(logging.CRITICAL)
    try:
        policy.emit(policy.startup_record(_sample_policy()), stream)
        policy.emit(
            policy.refusal_record(
                request_id="b" * 32, tool_id=None, code="tool_not_exposed", upstream_calls=0
            ),
            stream,
        )
    finally:
        logging.disable(logging.NOTSET)
    lines = stream.getvalue().splitlines()
    assert [json.loads(line)["event"] for line in lines] == ["policy.startup", "policy.refusal"]
    assert stream.getvalue().endswith("\n")


def test_tool_facts_api_status() -> None:
    assert SYNTH.tools["list_cameras"].api_status == "official"
    assert SYNTH.tools["update_camera"].api_status == "unofficial"
    assert SYNTH.tools["fabric_connector_post"].api_status == "local"
    assert SYNTH.tools["list_configured_api_keys"].api_status == "local"
    assert ToolFacts("x", "meta", (), "read").api_status == "local"


# --------------------------------------------------------------------------- server level


def _stderr_records(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        if line.startswith("{") and '"event":"policy.' in line:
            out.append(json.loads(line))
    return out


async def _run_lifespan(monkeypatch: pytest.MonkeyPatch, env: dict[str, str]) -> list[str]:
    from unifi_fabric import server

    monkeypatch.setenv("UNIFI_API_KEY", "synthetic-key-a")
    monkeypatch.setenv("UNIFI_LOG_LEVEL", "CRITICAL")
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    async with server.lifespan(server.mcp):
        return sorted(tool.name for tool in await server.mcp.list_tools())


async def test_startup_record_on_stderr_with_logging_and_audit_off(monkeypatch, capsys) -> None:
    monkeypatch.delenv("UNIFI_AUDIT_LOG", raising=False)
    await _run_lifespan(monkeypatch, {"UNIFI_WRITE_POLICY": "dry-run"})
    records = _stderr_records(capsys.readouterr().err)
    startup = [r for r in records if r["event"] == "policy.startup"]
    assert len(startup) == 1
    assert set(startup[0]) == policy.STARTUP_FIELDS
    assert startup[0]["effective_policy"]["write_policy"] == "dry-run"
    assert "synthetic-key-a" not in json.dumps(startup[0])


async def test_retired_setting_refuses_startup_with_its_token(monkeypatch, capsys) -> None:
    with pytest.raises(SystemExit) as info:
        await _run_lifespan(monkeypatch, {"UNIFI_EXAMPLE_RETIRED": "1"})
    assert info.value.code != 0
    err = capsys.readouterr().err
    assert err.strip().splitlines()[-1] == "startup:retired:UNIFI_EXAMPLE_RETIRED"
    assert "policy.startup" not in err


async def test_malformed_setting_refuses_startup_with_its_token(monkeypatch, capsys) -> None:
    with pytest.raises(SystemExit):
        await _run_lifespan(monkeypatch, {"UNIFI_EXCLUDE": "tool:search_tools"})
    assert capsys.readouterr().err.strip().splitlines()[-1] == "startup:UNIFI_EXCLUDE"


def _write_call(name: str) -> dict[str, Any]:
    from tests import tool_args
    from tests._tool_catalog import tools_by_name

    return tool_args.generated_args(tools_by_name()[name])


async def test_deny_write_refuses_with_write_denied_and_a_record(monkeypatch, capsys) -> None:
    from fastmcp.exceptions import ToolError

    from tests import upstream_harness as uh
    from unifi_fabric import server

    up = uh.FakeUpstream()
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    uh.install(monkeypatch, up)
    capsys.readouterr()
    with pytest.raises(ToolError) as info:
        await server.mcp.call_tool("create_network", _write_call("create_network"))
    error = json.loads(str(info.value))["error"]
    assert error["code"] == "write_denied"
    assert up.served == []
    records = [
        r for r in _stderr_records(capsys.readouterr().err) if r["event"] == "policy.refusal"
    ]
    assert len(records) == 1
    assert set(records[0]) == policy.REFUSAL_FIELDS
    assert records[0]["code"] == "write_denied"
    assert records[0]["upstream_calls"] == 0
    assert records[0]["tool_id"].endswith(".create_network")
    assert len(records[0]["request_id"]) == 32


async def test_tool_deny_exception_refuses_only_that_tool(monkeypatch) -> None:
    from fastmcp.exceptions import ToolError

    from tests import upstream_harness as uh
    from unifi_fabric import server

    up = uh.FakeUpstream()
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", "tool:create_network=deny")
    uh.install(monkeypatch, up)
    with pytest.raises(ToolError) as info:
        await server.mcp.call_tool("create_network", _write_call("create_network"))
    assert json.loads(str(info.value))["error"]["code"] == "write_denied"
    assert up.served == []


async def test_dry_run_write_makes_zero_mutation(monkeypatch) -> None:
    from tests import upstream_harness as uh
    from unifi_fabric import server

    up = uh.FakeUpstream()
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    uh.install(monkeypatch, up)
    result = await server.mcp.call_tool("create_network", _write_call("create_network"))
    assert up.writes() == []
    assert "dry_run" in json.dumps(uh.result_payload(result))


async def test_tool_dry_run_exception_previews_that_tool(monkeypatch) -> None:
    from tests import upstream_harness as uh
    from unifi_fabric import server

    up = uh.FakeUpstream()
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", "tool:create_network=dry-run")
    uh.install(monkeypatch, up)
    await server.mcp.call_tool("create_network", _write_call("create_network"))
    assert up.writes() == []


async def test_exclude_all_domain_fixture_against_the_real_server(monkeypatch) -> None:
    data = _load(FIXTURES / "accept-exclude-all-domain-leaves-meta.json")
    env = {k: v for k, v in data["input"]["env"].items() if k != "UNIFI_API_KEY"}
    listed = await _run_lifespan(monkeypatch, env)
    assert listed == data["expected"]["listed_tools"]
    from unifi_fabric import server

    # Restored after the lifespan: the registered catalog is whole again. The environment
    # still excludes every domain tool, so tools/list (which the request policy filters by
    # that environment) is read around its middleware.
    assert len(await server.mcp.list_tools(run_middleware=False)) > 700


def test_unparsable_source_token_fails_closed() -> None:
    bad = EffectivePolicy("allow", (), policy.FAMILIES, frozenset({"source:Nope"}))
    with pytest.raises(ValueError, match="unparsable"):
        policy.is_exposed(bad, SYNTH.tools["list_cameras"])


def test_emit_survives_a_closed_stream() -> None:
    stream = io.StringIO()
    stream.close()
    policy.emit(policy.startup_record(_sample_policy()), stream)


@pytest.mark.parametrize(
    ("name", "token"),
    [
        ("unifi_write_policy", "startup:UNIFI_WRITE_POLICY"),
        ("Unifi_Exclude", "startup:UNIFI_EXCLUDE"),
        ("unifi_example_retired", "startup:retired:UNIFI_EXAMPLE_RETIRED"),
    ],
)
def test_non_canonical_case_fails_closed(name: str, token: str) -> None:
    with pytest.raises(StartupRefusal) as info:
        policy.check_retired_settings({name: "deny"}, {"UNIFI_API_KEY"})
    assert info.value.token == token
    assert "deny" not in info.value.message


SENTINEL = "planted-secret-0123456789"


@pytest.mark.parametrize(
    ("setting", "shape"),
    [
        ("UNIFI_WRITE_POLICY", "{s}"),
        ("UNIFI_WRITE_EXCEPTIONS", "{s}"),
        ("UNIFI_WRITE_EXCEPTIONS", "family:{s}=deny"),
        ("UNIFI_WRITE_EXCEPTIONS", "tool:{s}=deny"),
        ("UNIFI_WRITE_EXCEPTIONS", "family:network={s}"),
        ("UNIFI_FAMILY_ALLOW", "{s}"),
        ("UNIFI_FAMILY_ALLOW", "network,{s}"),
        ("UNIFI_EXCLUDE", "{s}"),
        ("UNIFI_EXCLUDE", "tool:{s}"),
        ("UNIFI_EXCLUDE", "source:{s}"),
        ("UNIFI_EXCLUDE", "family:{s}"),
    ],
)
def test_errors_never_echo_the_value(setting: str, shape: str) -> None:
    value = shape.format(s=SENTINEL)
    with pytest.raises(StartupRefusal) as info:
        policy.operator_policy({setting: value}, SYNTH)
    assert SENTINEL not in info.value.message
    base = policy.operator_policy({}, SYNTH)
    header = {
        "UNIFI_WRITE_POLICY": "write_policy",
        "UNIFI_FAMILY_ALLOW": "family_allow",
        "UNIFI_EXCLUDE": "exclude",
    }.get(setting)
    if header:
        with pytest.raises(PolicyHeaderError) as hinfo:
            policy.request_policy(base, SYNTH, **{header: value})
        assert SENTINEL not in str(hinfo.value)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"code": "x-unifi-api-key: secret"},
        {"request_id": "not-hex"},
        {"tool_id": "X-UniFi-Api-Key"},
        {"upstream_calls": -1},
    ],
)
def test_refusal_record_rejects_free_text(kwargs: dict[str, Any]) -> None:
    args: dict[str, Any] = {
        "request_id": "c" * 32,
        "tool_id": "network.create_network",
        "code": "write_denied",
        "upstream_calls": 0,
    }
    args.update(kwargs)
    with pytest.raises(ValueError):
        policy.refusal_record(**args)


@pytest.mark.parametrize("dispatch", [None, "call_read_tool", "call_write_tool"])
async def test_non_exposed_tool_refuses_with_tool_not_exposed(
    monkeypatch, capsys, dispatch
) -> None:
    from fastmcp.exceptions import ToolError

    from tests import upstream_harness as uh
    from unifi_fabric import server

    up = uh.FakeUpstream()
    monkeypatch.setenv("UNIFI_API_KEY", "synthetic-key-a")
    monkeypatch.setenv("UNIFI_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("UNIFI_EXCLUDE", "family:protect")
    uh.install(monkeypatch, up)
    async with server.lifespan(server.mcp):
        capsys.readouterr()
        with pytest.raises(ToolError) as info:
            if dispatch is None:
                await server.mcp.call_tool("list_cameras", {"host": "h"})
            else:
                await server.mcp.call_tool(
                    dispatch, {"name": "list_cameras", "arguments": {"host": "h"}}
                )
        records = [
            r for r in _stderr_records(capsys.readouterr().err) if r["event"] == "policy.refusal"
        ]
    error = json.loads(str(info.value))["error"]
    assert error["code"] == "tool_not_exposed"
    assert up.served == []
    assert len(records) == 1
    assert records[0]["code"] == "tool_not_exposed"
    assert records[0]["tool_id"] == "protect.list_cameras"
    assert records[0]["upstream_calls"] == 0
    from unifi_fabric import policy as runtime_policy

    assert runtime_policy.excluded_names() == frozenset()


# --------------------------------------------------------------------------- deny for every family


def _no_upstream(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Refuse (and record) any real upstream request a lifespan-built client would send."""
    import httpx

    sent: list[str] = []

    async def send(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
        sent.append(f"{request.method} {request.url.path}")
        raise AssertionError("a denied write must not reach upstream")

    monkeypatch.setattr(httpx.AsyncClient, "send", send)
    return sent


# Families whose registered catalog has no write tool: nothing for family:<id>=deny to refuse.
FAMILIES_WITHOUT_WRITE_TOOL = frozenset({"site_manager"})


@functools.cache
def _family_write_tools() -> dict[str, str]:
    """Family -> its first (sorted) write tool, for every family that registers one."""
    from tests._tool_catalog import tools_by_name
    from unifi_fabric.families import build_family_index
    from unifi_fabric.read_only_tools import is_write_tool_call

    index = build_family_index()
    first: dict[str, str] = {}
    for name, tool in sorted(tools_by_name().items()):
        family = index.get(name)
        if (
            family is not None
            and name != "fabric_connector_get"
            and is_write_tool_call(tool, name, {})
        ):
            first.setdefault(family, name)
    return first


def test_every_family_but_site_manager_registers_a_write_tool() -> None:
    """A new site_manager write tool fails here until the deny tests below cover it."""
    writes = _family_write_tools()
    assert set(writes) <= policy.FAMILIES
    assert policy.FAMILIES - set(writes) == FAMILIES_WITHOUT_WRITE_TOOL


@lazy_parametrize("family", lambda: sorted(_family_write_tools()))
@pytest.mark.parametrize("global_policy", [None, "dry-run"])
async def test_family_deny_refuses_writes_of_every_family_directly(
    monkeypatch, capsys, family, global_policy
) -> None:
    """family:<id>=deny binds every family with a write tool, never weaker than dry-run."""
    from fastmcp.exceptions import ToolError

    from tests import upstream_harness as uh
    from unifi_fabric import server

    name = _family_write_tools()[family]
    up = uh.FakeUpstream()
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", f"family:{family}=deny")
    if global_policy is not None:
        monkeypatch.setenv("UNIFI_WRITE_POLICY", global_policy)
    uh.install(monkeypatch, up)
    capsys.readouterr()
    with pytest.raises(ToolError) as info:
        await server.mcp.call_tool(name, _write_call(name))
    assert json.loads(str(info.value))["error"]["code"] == "write_denied"
    assert up.writes() == [], (family, name)
    records = [
        r for r in _stderr_records(capsys.readouterr().err) if r["event"] == "policy.refusal"
    ]
    assert [r["tool_id"] for r in records] == [f"{family}.{name}"]
    assert records[0]["code"] == "write_denied"


@lazy_parametrize("family", lambda: sorted(_family_write_tools()))
async def test_family_deny_refuses_writes_of_every_family_via_call_write_tool(
    monkeypatch, capsys, family
) -> None:
    from fastmcp.exceptions import ToolError

    from unifi_fabric import server

    name = _family_write_tools()[family]
    sent = _no_upstream(monkeypatch)
    monkeypatch.setenv("UNIFI_API_KEY", "synthetic-key-a")
    monkeypatch.setenv("UNIFI_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", f"family:{family}=deny")
    async with server.lifespan(server.mcp):
        capsys.readouterr()
        with pytest.raises(ToolError) as info:
            await server.mcp.call_tool(
                "call_write_tool", {"name": name, "arguments": _write_call(name)}
            )
        records = [
            r for r in _stderr_records(capsys.readouterr().err) if r["event"] == "policy.refusal"
        ]
    assert json.loads(str(info.value))["error"]["code"] == "write_denied"
    assert sent == []
    assert [r["tool_id"] for r in records] == [f"{family}.{name}"]


@pytest.mark.parametrize("dispatch", ["call_write_tool", "call_read_tool"])
async def test_dispatchers_under_deny_return_the_coded_refusal_for_the_target(
    monkeypatch, capsys, dispatch
) -> None:
    from fastmcp.exceptions import ToolError

    from unifi_fabric import server

    sent = _no_upstream(monkeypatch)
    monkeypatch.setenv("UNIFI_API_KEY", "synthetic-key-a")
    monkeypatch.setenv("UNIFI_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    async with server.lifespan(server.mcp):
        capsys.readouterr()
        with pytest.raises(ToolError) as info:
            await server.mcp.call_tool(
                dispatch,
                {"name": "create_network", "arguments": _write_call("create_network")},
            )
        records = [
            r for r in _stderr_records(capsys.readouterr().err) if r["event"] == "policy.refusal"
        ]
    assert json.loads(str(info.value))["error"]["code"] == "write_denied"
    assert sent == []
    assert len(records) == 1
    assert records[0]["tool_id"].endswith(".create_network")
    assert not records[0]["tool_id"].startswith("meta.")


async def test_chokepoint_refusal_is_coded_with_a_record(monkeypatch, capsys) -> None:
    """A relayed write the relay/chokepoint refuses (not the tool middleware) is coded too."""
    from fastmcp.exceptions import ToolError

    from tests import upstream_harness as uh
    from unifi_fabric import server

    up = uh.FakeUpstream()
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", "family:network=deny")
    uh.install(monkeypatch, up)
    args = _write_call("fabric_connector_post")
    args["path"] = "network/api/s/{site}/rest/networkconf"
    capsys.readouterr()
    with pytest.raises(ToolError) as info:
        await server.mcp.call_tool("fabric_connector_post", args)
    error = json.loads(str(info.value))["error"]
    assert error["code"] == "write_denied"
    assert "family:network=deny" in error["message"]
    assert up.writes() == []
    records = [
        r for r in _stderr_records(capsys.readouterr().err) if r["event"] == "policy.refusal"
    ]
    assert [r["tool_id"] for r in records] == ["connector.fabric_connector_post"]
    assert records[0]["upstream_calls"] == 0


# --------------------------------------------------------------------------- process start


@pytest.mark.parametrize(
    ("env", "token"),
    [
        ({"UNIFI_EXAMPLE_RETIRED": "1"}, "startup:retired:UNIFI_EXAMPLE_RETIRED"),
        ({"unifi_write_policy": "deny"}, "startup:UNIFI_WRITE_POLICY"),
        ({"UNIFI_EXCLUDE": "nope"}, "startup:UNIFI_EXCLUDE"),
        ({"UNIFI_WRITE_POLICY": " "}, "startup:UNIFI_WRITE_POLICY"),
        (
            {"UNIFI_EXAMPLE_RETIRED": "1", "UNIFI_API_KEY": ""},
            "startup:retired:UNIFI_EXAMPLE_RETIRED",
        ),
    ],
)
def test_process_start_prints_only_the_token(env, token) -> None:
    """python -m unifi_fabric: the startup gate runs before any settings load. The token
    is the last stderr line; an unrecognized setting adds only the migration line."""
    import os
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[1]
    base = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(root),
        "PYTHONPATH": str(root / "src"),
        "UNIFI_API_KEY": "synthetic-key-a",
    }
    proc = subprocess.run(  # noqa: S603 - this interpreter, the package's own entry point
        [sys.executable, "-m", "unifi_fabric"],
        env={**base, **env},
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    assert proc.returncode == 2, proc.stderr
    if token.startswith("startup:retired:"):
        message, last = proc.stderr.splitlines()
        assert last == token
        assert token.removeprefix("startup:retired:") in message
        assert policy.MIGRATION_URL in message
        assert "synthetic-key-a" not in proc.stderr
    elif "UNIFI_EXCLUDE" in env or "UNIFI_WRITE_POLICY" in env:
        assert proc.stderr.splitlines()[-1] == token
        assert len(proc.stderr.splitlines()) == 2
    else:
        assert proc.stderr == token + "\n"
    assert proc.stdout == ""
