"""Shared contract: the frozen RequestContext, CredentialHandle, EffectivePolicy and
Dependencies types."""

from __future__ import annotations

import asyncio
import dataclasses
import functools
import hashlib
import importlib
import json
import re
import sys
import uuid
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from unifi_fabric import registration
from unifi_fabric.contracts import (
    TOOLS_LIST_POLICY_ERROR_CODE,
    CredentialHandle,
    Dependencies,
    EffectivePolicy,
    RequestContext,
    canonical_policy_json,
    credentials_index,
    policy_digest,
    require_selected_credential,
)
from unifi_fabric.registration import (
    CATALOG_REASONS,
    PRE_IMPORT_REASONS,
    BoundHandler,
    CatalogChecks,
    CatalogError,
    ToolRegistrar,
    ToolSpec,
    validate_catalog,
)
from unifi_fabric.tools._shared import require_dependencies

FAMILIES = frozenset(
    {
        "network",
        "protect",
        "innerspace",
        "site_manager",
        "mobility",
        "carrier_fabric",
    }
)


def _policy(**overrides: object) -> EffectivePolicy:
    fields: dict[str, object] = {
        "write_policy": "allow",
        "write_exceptions": (),
        "exposed_families": FAMILIES,
        "exclusions": frozenset(),
    }
    fields.update(overrides)
    return EffectivePolicy(**fields)  # type: ignore[arg-type]


def _ctx(
    *labels: str, policy: EffectivePolicy | None = None, **overrides: object
) -> RequestContext:
    creds = tuple(
        CredentialHandle(label=label, key_fingerprint=f"{i:08x}") for i, label in enumerate(labels)
    )
    fields: dict[str, object] = {
        "present_arguments": frozenset(),
        "credentials": creds,
        "credentials_by_label": credentials_index(creds),
        "selected_credential": None,
        "effective_policy": policy or _policy(),
        "request_id": uuid.uuid4().hex,
        "ignored_loosening": (),
    }
    fields.update(overrides)
    return RequestContext(**fields)  # type: ignore[arg-type]


def _names(cls: type) -> set[str]:
    return {f.name for f in dataclasses.fields(cls)}


# --- exact field sets and frozenness ------------------------------------------------


def test_request_context_fields_exact() -> None:
    assert _names(RequestContext) == {
        "present_arguments",
        "credentials",
        "credentials_by_label",
        "selected_credential",
        "effective_policy",
        "request_id",
        "ignored_loosening",
    }


def test_request_context_frozen() -> None:
    ctx = _ctx("alpha")
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.request_id = "x"  # type: ignore[misc]
    assert "__slots__" in vars(RequestContext)
    assert not hasattr(ctx, "__dict__")


def test_request_context_one_public_method() -> None:
    public = {
        name
        for name, value in vars(RequestContext).items()
        if callable(value) and not name.startswith("_")
    }
    assert public == {"child"}


def test_request_context_is_never_hashable() -> None:
    with pytest.raises(TypeError):
        hash(_ctx("alpha"))


def test_effective_policy_fields_exact() -> None:
    assert _names(EffectivePolicy) == {
        "write_policy",
        "write_exceptions",
        "exposed_families",
        "exclusions",
    }


def test_effective_policy_frozen() -> None:
    policy = _policy()
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.write_policy = "deny"  # type: ignore[misc]
    assert "__slots__" in vars(EffectivePolicy)


@pytest.mark.parametrize(
    "overrides",
    [
        {"write_policy": "loud"},
        {"write_exceptions": (("b", "deny"), ("a", "deny"))},
        {"write_exceptions": (("a", "allow"),)},
        {"exposed_families": frozenset({"meta"})},
        {"exclusions": ["family:protect"]},
    ],
)
def test_effective_policy_rejects_invalid_values(overrides: dict[str, object]) -> None:
    with pytest.raises((ValueError, TypeError)):
        _policy(**overrides)


def test_dependencies_fields_exact() -> None:
    assert _names(Dependencies) == {"client", "registry"}
    deps = Dependencies(client=object(), registry=object())  # type: ignore[arg-type]
    with pytest.raises(dataclasses.FrozenInstanceError):
        deps.client = object()  # type: ignore[misc]
    assert "__slots__" in vars(Dependencies)


# --- CredentialHandle ---------------------------------------------------------------


def test_credential_handle_identity_equality() -> None:
    a = CredentialHandle("alpha", "0123abcd")
    b = CredentialHandle("alpha", "0123abcd")
    assert a == a
    assert a != b
    assert hash(a) == hash(a)
    assert len({a, b}) == 2
    assert _names(CredentialHandle) == {"label", "key_fingerprint"}
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.label = "beta"  # type: ignore[misc]


def test_credential_handle_repr_no_key() -> None:
    handle = CredentialHandle("alpha", "0123abcd")
    text = repr(handle)
    assert "alpha" in text and "0123abcd" in text
    assert "synthetic" not in text and "key=" not in text
    assert not hasattr(handle, "__dict__")


@pytest.mark.parametrize("fingerprint", ["0123ABCD", "0123abc", "synthetic-key-a", ""])
def test_credential_handle_rejects_non_fingerprint(fingerprint: str) -> None:
    with pytest.raises(ValueError):
        CredentialHandle("alpha", fingerprint)


# --- credentials_by_label and request order ------------------------------------------


def test_credentials_by_label_is_mapping_proxy() -> None:
    ctx = _ctx("alpha", "beta")
    assert isinstance(ctx.credentials_by_label, MappingProxyType)
    assert set(ctx.credentials_by_label) == {h.label for h in ctx.credentials}
    for handle in ctx.credentials:
        assert ctx.credentials_by_label[handle.label] is handle
    with pytest.raises(TypeError):
        ctx.credentials_by_label["gamma"] = ctx.credentials[0]  # type: ignore[index]


def test_credentials_by_label_must_match_credentials() -> None:
    ctx = _ctx("alpha", "beta")
    other = credentials_index((CredentialHandle("alpha", "00000000"), ctx.credentials[1]))
    with pytest.raises(ValueError):
        dataclasses.replace(ctx, credentials_by_label=other)
    with pytest.raises(TypeError):
        dataclasses.replace(ctx, credentials_by_label=dict(ctx.credentials_by_label))
    with pytest.raises(ValueError):
        credentials_index((ctx.credentials[0], CredentialHandle("alpha", "00000001")))


def test_credentials_never_empty() -> None:
    with pytest.raises(ValueError):
        _ctx(credentials=(), credentials_by_label=MappingProxyType({}))


def test_request_order_preserved() -> None:
    # A header object ordered beta, alpha gives credentials (beta, alpha).
    header = json.loads('{"beta": "synthetic-key-b", "alpha": "synthetic-key-a"}')
    ctx = _ctx(*header)
    assert [h.label for h in ctx.credentials] == ["beta", "alpha"]
    assert list(ctx.credentials_by_label) == ["beta", "alpha"]


# --- child() derivation ---------------------------------------------------------------

_KEPT = (
    "credentials",
    "credentials_by_label",
    "effective_policy",
    "request_id",
    "ignored_loosening",
)


def test_child_keeps_shared_fields() -> None:
    ctx = _ctx("alpha", "beta", ignored_loosening=("x-unifi-write-policy=allow",))
    child = ctx.child({"host": "h", "key_label": None})
    for name in _KEPT:
        assert getattr(child, name) is getattr(ctx, name)
    assert child.present_arguments == frozenset({"host", "key_label"})
    assert child.selected_credential is None


def test_fanout_children_differ_only_in_selection() -> None:
    ctx = _ctx("alpha", "beta")
    alpha, beta = ctx.credentials
    first = ctx.child({"host": "a"}, selected_credential=alpha)
    second = ctx.child({}, selected_credential=beta)
    differing = {
        f.name
        for f in dataclasses.fields(RequestContext)
        if getattr(first, f.name) is not getattr(second, f.name)
    }
    assert differing == {"selected_credential", "present_arguments"}
    assert first.selected_credential is alpha
    assert second.selected_credential is beta


def test_grandchild_inherits_selection() -> None:
    ctx = _ctx("alpha", "beta")
    beta = ctx.credentials[1]
    grandchild = ctx.child({}, selected_credential=beta).child({"site": "default"})
    assert grandchild.selected_credential is beta
    assert grandchild.present_arguments == frozenset({"site"})


def test_child_rejects_non_member_handle() -> None:
    ctx = _ctx("alpha")
    with pytest.raises(ValueError):
        ctx.child({}, selected_credential=CredentialHandle("gamma", "ffffffff"))


def test_child_rejects_lookalike_handle() -> None:
    ctx = _ctx("alpha")
    member = ctx.credentials[0]
    lookalike = CredentialHandle(member.label, member.key_fingerprint)
    with pytest.raises(ValueError):
        ctx.child({}, selected_credential=lookalike)


def test_constructor_rejects_non_member_selection() -> None:
    ctx = _ctx("alpha")
    with pytest.raises(ValueError):
        dataclasses.replace(ctx, selected_credential=CredentialHandle("alpha", "00000000"))


# --- the credential selection cases --------------------------------------------------------------


def test_env_single_key_default_label() -> None:
    # A single UNIFI_API_KEY is one handle labelled "default" (config.py:1291).
    ctx = _ctx("default")
    assert [h.label for h in ctx.credentials] == ["default"]
    assert (
        ctx.child({}, selected_credential=ctx.credentials[0]).selected_credential
        is (ctx.credentials_by_label["default"])
    )


def test_env_two_keys_hostless_selects_first() -> None:
    ctx = _ctx("primary", "secondary")
    child = ctx.child({"site": "default"}, selected_credential=ctx.credentials[0])
    assert child.selected_credential is ctx.credentials[0]
    assert child.selected_credential.label == "primary"


def test_env_explicit_key_label_selects_by_label() -> None:
    ctx = _ctx("primary", "secondary")
    child = ctx.child(
        {"key_label": "secondary"}, selected_credential=ctx.credentials_by_label["secondary"]
    )
    assert child.selected_credential is ctx.credentials[1]


def test_header_single_label() -> None:
    ctx = _ctx("alpha")
    child = ctx.child({"host": "h"}, selected_credential=ctx.credentials[0])
    assert child.selected_credential is not None
    assert child.selected_credential.label == "alpha"


def test_header_two_labels_hostless_first() -> None:
    ctx = _ctx("alpha", "beta")
    child = ctx.child({}, selected_credential=ctx.credentials[0])
    assert child.selected_credential is ctx.credentials_by_label["alpha"]


def test_fanout_one_child_per_label() -> None:
    ctx = _ctx("alpha", "beta")
    children = [ctx.child({}, selected_credential=h) for h in ctx.credentials]
    assert [c.selected_credential for c in children] == list(ctx.credentials)
    assert all(c.selected_credential is h for c, h in zip(children, ctx.credentials, strict=True))


def test_upstream_with_no_selection_is_programming_error() -> None:
    ctx = _ctx("alpha", "beta")
    with pytest.raises(RuntimeError):
        require_selected_credential(ctx.child({}))
    assert (
        require_selected_credential(ctx.child({}, selected_credential=ctx.credentials[1]))
        is (ctx.credentials[1])
    )


def test_request_id_format_and_inheritance() -> None:
    ctx = _ctx("alpha")
    assert re.fullmatch(r"[0-9a-f]{32}", ctx.request_id)
    child = ctx.child({}, selected_credential=ctx.credentials[0])
    assert child.request_id == ctx.request_id
    assert child.child({}).request_id == ctx.request_id


def test_ignored_loosening_ordering() -> None:
    entries = (
        "x-unifi-write-policy=allow",
        "x-unifi-family-allow=network",
        "x-unifi-family-allow=protect",
    )
    ctx = _ctx("alpha", ignored_loosening=entries)
    assert ctx.child({}).ignored_loosening == entries
    assert len(set(entries)) == len(entries)
    assert not any(e.startswith("x-unifi-exclude=") for e in entries)
    assert all(re.fullmatch(r"x-unifi-[a-z-]+=.+", e) for e in entries)


# --- canonical policy JSON and digest ------------------------------------------------


def test_canonical_policy_json_and_digest_order_independent() -> None:
    p1 = EffectivePolicy(
        write_policy="dry-run",
        write_exceptions=(("network.create_network", "deny"), ("protect", "dry-run")),
        exposed_families=frozenset(["protect", "network", "mobility"]),
        exclusions=frozenset(["tool:list_hosts", "family:innerspace", "unofficial"]),
    )
    p2 = EffectivePolicy(
        write_policy="dry-run",
        write_exceptions=(("network.create_network", "deny"), ("protect", "dry-run")),
        exposed_families=frozenset(["mobility", "network", "protect"]),
        exclusions=frozenset(["unofficial", "family:innerspace", "tool:list_hosts"]),
    )
    text = canonical_policy_json(p1)
    assert text == canonical_policy_json(p2)
    assert text == (
        '{"exclusions":["family:innerspace","tool:list_hosts","unofficial"],'
        '"exposed_families":["mobility","network","protect"],'
        '"write_exceptions":[["network.create_network","deny"],["protect","dry-run"]],'
        '"write_policy":"dry-run"}'
    )
    expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert policy_digest(p1) == policy_digest(p2) == expected
    assert re.fullmatch(r"[0-9a-f]{64}", expected)


def test_canonical_policy_json_keeps_non_ascii() -> None:
    policy = _policy(exclusions=frozenset({"tool:café"}))
    assert "café" in canonical_policy_json(policy)


# --- constants -----------------------------------------------------------------------


def test_tools_list_policy_error_code_constant() -> None:
    assert isinstance(TOOLS_LIST_POLICY_ERROR_CODE, int)
    assert not isinstance(TOOLS_LIST_POLICY_ERROR_CODE, bool)


# --- fixture envelopes: every contract fixture validates against its schema ---------

CONTRACTS_DIR = Path(__file__).parent / "fixtures" / "contracts"
_SCHEMA_FOR = {"c": "catalog.schema.json", "h": "fixture.schema.json"}
_SCHEMA_FOR.update(s="fixture.schema.json", t="fixture.schema.json")


@functools.cache
def _validator(schema_file: str) -> Draft202012Validator:
    schema = json.loads((CONTRACTS_DIR / schema_file).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def _fixture_files() -> list[Path]:
    return sorted(CONTRACTS_DIR.glob("*/v1/*.json"))


def test_contract_directories_are_known() -> None:
    for path in CONTRACTS_DIR.iterdir():
        if path.is_dir():
            assert path.name in _SCHEMA_FOR, path
            assert sorted(p.name for p in path.iterdir()) == ["v1"], path


@pytest.mark.parametrize("path", _fixture_files(), ids=lambda p: f"{p.parent.parent.name}/{p.stem}")
def test_every_fixture_file_validates(path: Path) -> None:
    contract = path.parent.parent.name
    raw = path.read_bytes()
    fixture = json.loads(raw.decode("utf-8"))
    errors = sorted(
        _validator(_SCHEMA_FOR[contract]).iter_errors(fixture), key=lambda e: list(e.path)
    )
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors]
    assert fixture["name"] == path.stem
    assert fixture["contract"] == contract
    assert fixture["schema_version"] == path.parent.name.removeprefix("v")
    expected = fixture["expected"]
    for key in ("listed_tools", "registered_names"):
        if key in expected:
            assert expected[key] == sorted(expected[key]), f"{key} must be sorted"


def test_fixture_names_unique_per_contract() -> None:
    seen: dict[tuple[str, str], Path] = {}
    for path in _fixture_files():
        key = (path.parent.parent.name, json.loads(path.read_text(encoding="utf-8"))["name"])
        assert key not in seen, (path, seen.get(key))
        seen[key] = path


# The three schema-valid examples quoted verbatim in the contract (one amended, noted inline).
_CONTRACT_EXAMPLES: dict[str, object] = {
    "c/reject-cross-family-emitted-name": {
        "schema_version": "1",
        "contract": "c",
        "name": "reject-cross-family-emitted-name",
        "description": "Two families emit the same public name",
        "kind": "reject",
        "input": {
            "tool_specs": [
                {"base": "list_cameras"},
                {
                    "base": "list_cameras",
                    "id": "network.list_cameras",
                    "family": "network",
                    "family_id": "network",
                },
            ]
        },
        "expected": {"code": "startup:catalog:duplicate_emitted_name", "registered": 0},
    },
    "h/accept-fanout-two-labels": {
        "schema_version": "1",
        "contract": "h",
        "name": "accept-fanout-two-labels",
        "description": "A host-less fan-out uses each request label once, in request order",
        "kind": "accept",
        "input": {
            "env": {"UNIFI_KEY_MODE": "header", "UNIFI_TOOL_MODE": "full"},
            "headers": [
                ["X-UniFi-Api-Key", '{"alpha":"synthetic-key-a","beta":"synthetic-key-b"}']
            ],
            "route": "list_hosts",
            "arguments": {},
            "upstream": {
                "alpha": {"status": "ok", "consoles": [{"id": "host-a1", "name": "HQ-A"}]},
                "beta": {"status": "ok", "consoles": [{"id": "host-b1", "name": "HQ-B"}]},
            },
        },
        "expected": {"selected_labels": ["alpha", "beta"]},
    },
    "t/accept-dry-run-header-relay-post": {
        "schema_version": "1",
        "contract": "t",
        "name": "accept-dry-run-header-relay-post",
        "description": "A request dry-run header tightens an allow operator and sends no mutation",
        "kind": "accept",
        "input": {
            "env": {"UNIFI_API_KEY": "synthetic-key-a", "UNIFI_TOOL_MODE": "full"},
            "headers": [["X-UniFi-Write-Policy", "dry-run"]],
            "route": "fabric_connector_post",
            # Amended from the quoted example, which omits fabric_connector_post's required
            # host: the call then failed argument validation before any write, so its
            # upstream_mutations == 0 never exercised dry-run. host-a1 is the console its
            # own input.upstream lists.
            "arguments": {"host": "host-a1", "path": "/proxy/network/integration/v1/sites"},
            "upstream": {
                "default": {"status": "ok", "consoles": [{"id": "host-a1", "name": "HQ"}]}
            },
        },
        "expected": {"upstream_mutations": 0},
    },
}


@pytest.mark.parametrize("key", sorted(_CONTRACT_EXAMPLES))
def test_verbatim_contract_examples_present(key: str) -> None:
    contract, name = key.split("/")
    path = CONTRACTS_DIR / contract / "v1" / f"{name}.json"
    assert json.loads(path.read_text(encoding="utf-8")) == _CONTRACT_EXAMPLES[key]


_H_ACCEPT = {
    "schema_version": "1",
    "contract": "h",
    "name": "accept-example",
    "description": "example",
    "kind": "accept",
    "input": {"route": "list_hosts"},
    "expected": {"selected_labels": ["alpha"]},
}
_C_REJECT = {
    "schema_version": "1",
    "contract": "c",
    "name": "reject-example",
    "description": "example",
    "kind": "reject",
    "input": {"tool_specs": [{"base": "list_cameras"}]},
    "expected": {"code": "startup:catalog:duplicate_key", "registered": 0},
}


def _with(base: dict[str, object], path: tuple[str, ...], value: object) -> dict[str, object]:
    obj = json.loads(json.dumps(base))
    target = obj
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    return obj


def test_schema_examples_are_valid() -> None:
    assert not list(_validator("fixture.schema.json").iter_errors(_H_ACCEPT))
    assert not list(_validator("catalog.schema.json").iter_errors(_C_REJECT))


@pytest.mark.parametrize(
    ("schema_file", "base", "path", "value"),
    [
        ("fixture.schema.json", _H_ACCEPT, ("extra",), 1),
        ("fixture.schema.json", _H_ACCEPT, ("input", "cookies"), {}),
        ("fixture.schema.json", _H_ACCEPT, ("expected", "upstream_bodies"), []),
        ("fixture.schema.json", _H_ACCEPT, ("input", "transport"), "sse"),
        ("fixture.schema.json", _H_ACCEPT, ("input", "upstream"), {"a": {"status": "ok"}}),
        ("fixture.schema.json", _H_ACCEPT, ("input", "headers"), [["X-UniFi-Api-Key"]]),
        ("fixture.schema.json", _H_ACCEPT, ("description",), ""),
        ("fixture.schema.json", _H_ACCEPT, ("contract",), "c"),
        ("catalog.schema.json", _C_REJECT, ("extra",), 1),
        ("catalog.schema.json", _C_REJECT, ("input", "env"), {}),
        ("catalog.schema.json", _C_REJECT, ("input", "tool_specs"), [{"id": "protect.x"}]),
        ("catalog.schema.json", _C_REJECT, ("input", "tool_specs"), [{"base": "x", "y": 1}]),
        ("catalog.schema.json", _C_REJECT, ("expected", "registered"), 1),
        ("catalog.schema.json", _C_REJECT, ("contract",), "h"),
    ],
)
def test_schema_rejects_unknown_key(
    schema_file: str, base: dict[str, object], path: tuple[str, ...], value: object
) -> None:
    assert list(_validator(schema_file).iter_errors(_with(base, path, value)))


@pytest.mark.parametrize(
    ("schema_file", "base"),
    [("fixture.schema.json", _H_ACCEPT), ("catalog.schema.json", _C_REJECT)],
)
@pytest.mark.parametrize("version", ["2", 1, "v1"])
def test_schema_rejects_schema_version_2(
    schema_file: str, base: dict[str, object], version: object
) -> None:
    assert list(_validator(schema_file).iter_errors(_with(base, ("schema_version",), version)))


_H_REJECT = {
    **_H_ACCEPT,
    "name": "reject-example",
    "kind": "reject",
    "expected": {"code": "invalid_api_key_header", "upstream_calls": 0},
}


@pytest.mark.parametrize(
    "code",
    [
        "invalid_api_key_header",
        "invalid_policy_header",
        "missing_api_key_header",
        "key_label_not_allowed",
        "tool_not_exposed",
        "write_denied",
        "code_mode_invalid_source",
        "code_mode_busy",
        "credential_cache_saturated",
        "startup:UNIFI_KEY_MODE",
        "startup:retired:UNIFI_EXAMPLE_RETIRED",
        "startup:catalog:duplicate_key",
    ],
)
def test_schema_accepts_each_closed_code(code: str) -> None:
    obj = _with(_H_REJECT, ("expected", "code"), code)
    assert not list(_validator("fixture.schema.json").iter_errors(obj))


@pytest.mark.parametrize(
    ("schema_file", "base", "code"),
    [
        ("fixture.schema.json", _H_REJECT, "rate_limited"),
        ("fixture.schema.json", _H_REJECT, "startup:catalog:not_a_reason"),
        ("fixture.schema.json", _H_REJECT, "startup:unifi_exclude"),
        ("catalog.schema.json", _C_REJECT, "startup:catalog:not_a_reason"),
        ("catalog.schema.json", _C_REJECT, "startup:UNIFI_EXCLUDE"),
    ],
)
def test_schema_rejects_unknown_reason(
    schema_file: str, base: dict[str, object], code: str
) -> None:
    assert list(_validator(schema_file).iter_errors(_with(base, ("expected", "code"), code)))


def test_schema_reject_requires_zero_upstream_calls() -> None:
    obj = _with(_H_REJECT, ("expected", "upstream_calls"), 1)
    assert list(_validator("fixture.schema.json").iter_errors(obj))
    obj = _with(_H_REJECT, ("expected", "selected_labels"), ["alpha"])
    assert list(_validator("fixture.schema.json").iter_errors(obj))


# --- register_tool: catalog validation order over the c/v1 fixtures ----------------

_ADAPTERS = "unifi_fabric._generated.adapters"


async def _ok_handler(request_context: Any, validated_arguments: Any, dependencies: Any) -> Any:
    return {"context": request_context, "arguments": dict(validated_arguments)}


def _sync_handler(request_context: Any, validated_arguments: Any, dependencies: Any) -> Any:
    return None


def _fake_adapters(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Inject a test-local adapter package; return the list of imported module names."""
    modules: dict[str, ModuleType] = {}
    for name in ("unifi_fabric._generated", _ADAPTERS):
        modules[name] = ModuleType(name)
        modules[name].__path__ = []  # type: ignore[attr-defined]
    protect = ModuleType(f"{_ADAPTERS}.protect")
    protect.list_cameras = _ok_handler  # type: ignore[attr-defined]
    protect.get_camera = _sync_handler  # type: ignore[attr-defined]  # invalid signature
    network = ModuleType(f"{_ADAPTERS}.network")
    network.list_cameras = _ok_handler  # type: ignore[attr-defined]
    site_manager = ModuleType(f"{_ADAPTERS}.site_manager")
    site_manager.list_hosts = _ok_handler  # type: ignore[attr-defined]
    for module in (protect, network, site_manager):
        modules[module.__name__] = module
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    imported: list[str] = []
    real_import = importlib.import_module

    def spy(name: str, package: str | None = None) -> ModuleType:
        if name.startswith(_ADAPTERS):
            imported.append(name)
        return real_import(name, package)

    monkeypatch.setattr(registration.importlib, "import_module", spy)
    return imported


def _base_spec(name: str, family: str, *, read_only: bool = True) -> ToolSpec:
    return ToolSpec(
        id=f"{family}.{name}",
        name=name,
        family=family,
        family_id=family,
        api_source_id=f"{family}/integration",
        api_status="official",
        read_only=read_only,
        description=f"Synthetic {name}",
        input_schema={"type": "object", "properties": {}},
        output_schema=None,
        version="1.0.0",
        fixtures=(),
        handler=f"{_ADAPTERS}.{family}:{name}",
    )


_SYNTHETIC_BASELINE = (
    _base_spec("list_hosts", "site_manager"),
    _base_spec("list_cameras", "protect"),
    _base_spec("get_camera", "protect"),
)


def _overlay(entries: list[dict[str, Any]]) -> list[ToolSpec]:
    """Apply a catalog fixture overlay to the synthetic baseline (not the real catalog)."""
    by_name = {spec.name: spec for spec in _SYNTHETIC_BASELINE}
    replaced = {entry["base"] for entry in entries}
    specs = [spec for spec in _SYNTHETIC_BASELINE if spec.name not in replaced]
    for entry in entries:
        fields_ = {k: v for k, v in entry.items() if k != "base"}
        if "fixtures" in fields_:
            fields_["fixtures"] = tuple(fields_["fixtures"])
        spec = dataclasses.replace(by_name[entry["base"]], **fields_)
        if "handler" not in entry:
            spec = dataclasses.replace(spec, handler=f"{_ADAPTERS}.{spec.family_id}:{spec.name}")
        specs.append(spec)
    return specs


def _c_fixtures(kind: str) -> list[Path]:
    return [
        p
        for p in sorted((CONTRACTS_DIR / "c" / "v1").glob("*.json"))
        if json.loads(p.read_text(encoding="utf-8"))["kind"] == kind
    ]


def _deps() -> Dependencies:
    return Dependencies(client=object(), registry=object())  # type: ignore[arg-type]


@pytest.mark.parametrize("path", _c_fixtures("reject"), ids=lambda p: p.stem)
def test_register_tool_validation_order(path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    imported = _fake_adapters(monkeypatch)
    sink: list[str] = []
    registrar = ToolRegistrar(lambda spec, bound: sink.append(spec.name))
    with pytest.raises(CatalogError) as excinfo:
        registrar.register_catalog(_overlay(fixture["input"]["tool_specs"]), dependencies=_deps)
    assert excinfo.value.token == fixture["expected"]["code"]
    assert sink == [] and registrar.registered_names == []  # registered == 0
    if excinfo.value.reason in PRE_IMPORT_REASONS:
        assert imported == [], "no handler is imported before the pre-import checks pass"
    else:
        assert imported, "missing_handler/invalid_signature are found by importing"


def test_catalog_reason_order_matches_the_schema() -> None:
    schema = json.loads((CONTRACTS_DIR / "catalog.schema.json").read_text(encoding="utf-8"))
    pattern = schema["oneOf"][1]["properties"]["expected"]["properties"]["code"]["pattern"]
    assert pattern == "^startup:catalog:(" + "|".join(CATALOG_REASONS) + ")$"
    assert CATALOG_REASONS[: len(PRE_IMPORT_REASONS)] == PRE_IMPORT_REASONS


def test_register_tool_registers_under_spec_name(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_adapters(monkeypatch)
    sink: list[tuple[str, BoundHandler]] = []
    registrar = ToolRegistrar(lambda spec, bound: sink.append((spec.name, bound)))
    names = registrar.register_catalog(list(_SYNTHETIC_BASELINE[:2]), dependencies=_deps)
    assert names == sorted(spec.name for spec in _SYNTHETIC_BASELINE[:2])
    assert [name for name, _ in sink] == ["list_hosts", "list_cameras"]
    assert all("." not in name for name in names)  # no family prefix; id is never a key
    with pytest.raises(CatalogError) as excinfo:
        registrar.register_tool(_SYNTHETIC_BASELINE[1], dependencies=_deps)
    assert excinfo.value.reason == "duplicate_key"


def test_baseline_registration_fixture_is_the_public_catalog() -> None:
    fixture = json.loads(
        (CONTRACTS_DIR / "c" / "v1" / "accept-baseline-registration.json").read_text(
            encoding="utf-8"
        )
    )
    assert fixture["input"] == {"tool_specs": []}
    names = fixture["expected"]["registered_names"]
    assert names == sorted(set(names))
    assert {"list_hosts", "list_cameras", "list_configured_api_keys"} <= set(names)
    assert not any("." in name for name in names)


def test_bound_handler_passes_context_arguments_and_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_adapters(monkeypatch)
    sink: list[BoundHandler] = []
    deps = _deps()
    registrar = ToolRegistrar(lambda spec, bound: sink.append(bound))
    registrar.register_tool(_SYNTHETIC_BASELINE[0], dependencies=lambda: deps)
    ctx = _ctx("alpha")
    result = asyncio.run(sink[0](ctx, {"page_size": 5}))
    assert result == {"context": ctx, "arguments": {"page_size": 5}}


def test_require_dependencies_raises_the_existing_error_when_uninitialized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from unifi_fabric import server

    monkeypatch.setattr(server, "_client", None)
    with pytest.raises(RuntimeError, match="Server not initialized"):
        require_dependencies()
    client, registry = object(), object()
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", registry)
    deps = require_dependencies()
    assert deps.client is client and deps.registry is registry


def test_server_reexports_the_shared_helpers() -> None:
    from unifi_fabric import server
    from unifi_fabric.tools import _shared

    for name in ("_image_result", "_nullable_default", "_validate_optional_site"):
        assert getattr(server, name) is getattr(_shared, name)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"id": "protect.other"}, "invalid_spec"),
        ({"family": "network"}, "invalid_spec"),
        ({"api_status": "beta"}, "invalid_spec"),
        ({"description": " "}, "invalid_spec"),
        ({"handler": "not-a-ref"}, "invalid_spec"),
        ({"output_schema": {"type": "object"}}, "missing_fixture"),
        ({"fixtures": ("tests/fixtures/does-not-exist.json",)}, "missing_fixture"),
    ],
)
def test_spec_level_reasons(
    change: dict[str, Any], reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    imported = _fake_adapters(monkeypatch)
    spec = dataclasses.replace(_SYNTHETIC_BASELINE[1], **change)
    with pytest.raises(CatalogError) as excinfo:
        validate_catalog([spec], fixture_root=Path(__file__).parent.parent)
    assert excinfo.value.reason == reason
    assert imported == []


def test_catalog_checks_run_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    imported = _fake_adapters(monkeypatch)
    calls: list[str] = []

    def failing(name: str) -> Any:
        def check(specs: Any) -> str:
            calls.append(name)
            return f"{name} failed"

        return check

    checks = CatalogChecks(
        unclassified_source=None,
        annotation_mismatch=failing("annotation_mismatch"),
        unbumped_version=failing("unbumped_version"),
    )
    dup = [_SYNTHETIC_BASELINE[1], _SYNTHETIC_BASELINE[1]]
    with pytest.raises(CatalogError) as excinfo:
        validate_catalog(dup, checks=checks)
    assert excinfo.value.reason == "annotation_mismatch"
    assert calls == ["annotation_mismatch"]
    assert imported == []
