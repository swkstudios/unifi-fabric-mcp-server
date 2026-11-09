"""Catalog contract: the typed tool catalog (schema and acceptance).

* the committed catalog (src/unifi_fabric/_generated/catalog.json) equals a fresh
  in-memory build (staleness);
* it covers exactly the registered roster plus the discovery meta tools, with one spec
  per tool, no duplicate (family, name) key and no duplicate emitted name;
* classification is one derivation: read_only and the four hints come from
  tool_annotations.for_tool over the audited verb set, and every emitted MCP annotation
  equals the catalog's;
* api_source_id/api_status follow the baseline source table and the local rule;
* validate_catalog returns the first applicable reason in contract order, including the
  annotation-table pass/fail cases;
* the catalog fixtures under tests/fixtures/contracts/c/v1 (the import/collision set)
  overlay
  the baseline catalog and give their expected outcome.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from unifi_fabric import catalog as cat
from unifi_fabric.catalog import (
    CATALOG_PATH,
    CATALOG_REASONS,
    META_FAMILY,
    META_TOOL_NAMES,
    CatalogError,
    ToolSpec,
    load_catalog,
    overlay,
    render_catalog,
    validate_catalog,
)
from unifi_fabric.families import ALL_FAMILIES

ROOT = Path(__file__).resolve().parents[1]
C_FIXTURES = ROOT / "tests" / "fixtures" / "contracts" / "c" / "v1"

# One worker builds the live roster once for the whole module.
pytestmark = pytest.mark.xdist_group("catalog-contract")


@pytest.fixture(scope="module")
def live() -> dict[str, Any]:
    from unifi_fabric.catalog_build import classified_sources, derivation, registered_tools

    tools = asyncio.run(registered_tools())
    names = [tool.name for tool in tools]
    sources = classified_sources(names)
    return {
        "tools": {tool.name: tool for tool in tools},
        "sources": sources,
        "derivation": derivation(tools, sources),
    }


@pytest.fixture(scope="module")
def committed() -> cat.Catalog:
    return load_catalog()


def _validate(specs: list[ToolSpec], live: dict[str, Any], committed: cat.Catalog) -> None:
    validate_catalog(
        specs,
        families=ALL_FAMILIES,
        sources=live["sources"],
        derivation=live["derivation"],
        baseline={spec.id: spec for spec in committed.tools},
        root=ROOT,
    )


def test_committed_catalog_is_fresh() -> None:
    from unifi_fabric.catalog_build import build_catalog

    fresh = render_catalog(build_catalog())
    assert CATALOG_PATH.read_text(encoding="utf-8") == fresh, (
        "tool catalog is stale; run scripts/gen_tool_catalog.py --write"
    )


@pytest.mark.parametrize("name", ["get_camera_playback_history", "update_camera"])
def test_protect_tool_version_preserves_dev_contract(committed: cat.Catalog, name: str) -> None:
    from unifi_fabric.catalog_build import build_catalog

    expected = next(spec for spec in committed.tools if spec.name == name)
    assert expected.version == "1.2.0"
    regenerated = next(spec for spec in build_catalog().tools if spec.name == name)
    assert regenerated.version == expected.version
    assert regenerated.input_schema == expected.input_schema
    assert regenerated.output_schema == expected.output_schema


@pytest.mark.parametrize(
    "tool_id",
    [
        "devices.list_pending_devices",
        "devices.list_site_devices",
        "protect.get_camera_playback_history",
        "protect.update_camera",
    ],
)
def test_catalog_preserves_dev_schema_versions(committed: cat.Catalog, tool_id: str) -> None:
    """Freshness alone cannot catch a merge reverting an unchanged schema version."""
    spec = next(spec for spec in committed.tools if spec.id == tool_id)
    assert tuple(int(part) for part in spec.version.split(".")) >= (1, 2, 0)


def test_catalog_shape(committed: cat.Catalog) -> None:
    raw = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    assert set(raw) == {"version", "tools", "fixtures"}
    assert cat.SEMVER_RE.fullmatch(raw["version"])
    ids = [item["id"] for item in raw["tools"]]
    assert ids == sorted(ids), "tools are ordered by id"
    assert all(list(item) == list(cat.SPEC_FIELDS) for item in raw["tools"])


def test_committed_catalog_validates(live: dict[str, Any], committed: cat.Catalog) -> None:
    _validate(list(committed.tools), live, committed)


def test_catalog_covers_the_registered_roster_once(
    live: dict[str, Any], committed: cat.Catalog
) -> None:
    names = [spec.name for spec in committed.tools]
    assert len(names) == len(set(names))
    assert set(names) == set(live["tools"])
    keys = {spec.key for spec in committed.tools}
    assert len(keys) == len(committed.tools)
    handlers = {spec.handler for spec in committed.tools}
    assert len(handlers) == len(committed.tools)


def test_meta_family_is_exactly_the_six_meta_tools(committed: cat.Catalog) -> None:
    meta = {spec.name for spec in committed.tools if spec.family == META_FAMILY}
    assert meta == META_TOOL_NAMES
    assert META_FAMILY not in ALL_FAMILIES
    for spec in committed.tools:
        if spec.family == META_FAMILY:
            assert spec.id == f"meta.{spec.name}"
            assert spec.api_source_id == "server/local"
            assert spec.api_status == "local"


def test_domain_families_match_the_baseline_index(committed: cat.Catalog) -> None:
    from unifi_fabric.families import derive_family_index

    index = derive_family_index()
    for spec in committed.tools:
        if spec.family == META_FAMILY:
            continue
        assert index[spec.name] == spec.family, spec.name
    assert {s.family for s in committed.tools} - {META_FAMILY} == set(ALL_FAMILIES)


def test_handler_refs_follow_the_family_rule(committed: cat.Catalog) -> None:
    for spec in committed.tools:
        assert spec.handler == f"unifi_fabric._generated.adapters.{spec.family}:{spec.name}"


def test_emitted_annotations_equal_the_catalog(
    live: dict[str, Any], committed: cat.Catalog
) -> None:
    wrong = []
    for spec in committed.tools:
        tool = live["tools"][spec.name]
        wire = tool.annotations.model_dump(by_alias=True)
        emitted = {key: wire[key] for key in cat.HINT_KEYS}
        expected = {key: spec.annotations[key] for key in cat.HINT_KEYS}
        if emitted != expected:
            wrong.append(spec.name)
    assert wrong == []


def test_input_schemas_and_descriptions_equal_the_registration(
    live: dict[str, Any], committed: cat.Catalog
) -> None:
    for spec in committed.tools:
        tool = live["tools"][spec.name]
        assert spec.to_dict()["input_schema"] == tool.parameters, spec.name
        assert spec.description == tool.description, spec.name


def test_api_source_rules(committed: cat.Catalog) -> None:
    by_name = committed.by_name()
    for verb in ("delete", "get", "patch", "post", "put"):
        spec = by_name[f"fabric_connector_{verb}"]
        assert (spec.api_source_id, spec.api_status) == ("relay/generic", "local")
        assert spec.family == "connector"
    assert by_name["list_configured_api_keys"].api_source_id == "server/local"
    for spec in committed.tools:
        local = spec.api_source_id in {"server/local", "relay/generic"}
        assert (spec.api_status == "local") == local, spec.name
        assert spec.annotations["api_class"] == spec.api_status


def test_every_tool_starts_pass_through(committed: cat.Catalog) -> None:
    # A non-null output schema must list a fixture (missing_fixture); none is invented.
    for spec in committed.tools:
        if spec.output_schema is not None:
            assert spec.fixtures, spec.name


# --- validation order and the annotation table -------------------------------------


def _spec(committed: cat.Catalog, name: str, **changes: Any) -> ToolSpec:
    data = committed.by_name()[name].to_dict()
    data.update(changes)
    return ToolSpec.from_dict(data)


def _reason(specs: list[ToolSpec], live: dict[str, Any], committed: cat.Catalog) -> str | None:
    try:
        _validate(specs, live, committed)
    except CatalogError as exc:
        return exc.reason
    return None


def _replace(committed: cat.Catalog, *specs: ToolSpec) -> list[ToolSpec]:
    names = {s.name for s in specs}
    return [s for s in committed.tools if s.name not in names] + list(specs)


def _a(read: bool, destructive: bool, idempotent: bool, open_world: bool, cls: str) -> dict:
    return {
        "readOnlyHint": read,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
        "openWorldHint": open_world,
        "api_class": cls,
    }


def _first_by(committed: cat.Catalog, predicate) -> ToolSpec:
    for spec in committed.tools:
        if predicate(spec):
            return spec
    raise AssertionError("no tool matches")


def test_annotation_table_failing_rows(live: dict[str, Any], committed: cat.Catalog) -> None:
    read = _first_by(committed, lambda s: s.read_only and s.api_status != "local")
    write = _first_by(committed, lambda s: not s.read_only and s.api_status != "local")
    post = _first_by(committed, lambda s: not s.read_only and not s.annotations["idempotentHint"])
    put = _first_by(committed, lambda s: not s.read_only and s.annotations["idempotentHint"])
    local = committed.by_name()["list_configured_api_keys"]
    cases = {
        "read_only true with destructiveHint true": _spec(
            committed, read.name, annotations=_a(True, True, True, True, read.api_status)
        ),
        "read_only false with readOnlyHint true": _spec(
            committed, write.name, annotations=_a(True, False, True, True, write.api_status)
        ),
        "read_only true for a nonempty verb set": _spec(
            committed,
            write.name,
            read_only=True,
            annotations=_a(True, False, True, True, write.api_status),
        ),
        "POST with idempotentHint true": _spec(
            committed,
            post.name,
            annotations={**dict(post.annotations), "idempotentHint": True},
        ),
        "PUT with idempotentHint false": _spec(
            committed,
            put.name,
            annotations={**dict(put.annotations), "idempotentHint": False},
        ),
        "local-only tool with openWorldHint true": _spec(
            committed,
            local.name,
            annotations={**dict(local.annotations), "openWorldHint": True},
        ),
        "api_class different from api_status": _spec(
            committed,
            read.name,
            annotations={**dict(read.annotations), "api_class": "local"},
        ),
    }
    got = {
        label: _reason(_replace(committed, spec), live, committed) for label, spec in cases.items()
    }
    assert got == dict.fromkeys(cases, "annotation_mismatch")


def test_validation_reasons_in_order(live: dict[str, Any], committed: cat.Catalog) -> None:
    base = committed.by_name()["list_cameras"]
    off_pattern = _spec(committed, "list_cameras", id="Protect.list_cameras")
    # invalid_spec beats a cross-family duplicate in the same catalog (first reason wins).
    cross = ToolSpec.from_dict(
        {
            **base.to_dict(),
            "id": "network.list_cameras",
            "family": "network",
            "family_id": "network",
            "handler": cat.handler_ref("network", "list_cameras"),
        }
    )
    assert _reason(_replace(committed, off_pattern) + [cross], live, committed) == "invalid_spec"
    outside = _spec(committed, "list_cameras", handler=cat.handler_ref("network", "list_cameras"))
    assert _reason(_replace(committed, outside), live, committed) == "invalid_spec"
    other = (
        "innerspace/official"
        if base.api_source_id != "innerspace/official"
        else "mobility/official"
    )
    unclassified = _spec(committed, "list_cameras", api_source_id=other)
    assert _reason(_replace(committed, unclassified), live, committed) == "unclassified_source"
    wrong_status = _spec(
        committed,
        "list_cameras",
        api_status="local" if base.api_status != "local" else "official",
        annotations={
            **dict(base.annotations),
            "api_class": "local" if base.api_status != "local" else "official",
        },
    )
    assert _reason(_replace(committed, wrong_status), live, committed) == "unclassified_source"
    sources = {k: v for k, v in live["sources"].items() if k != "list_cameras"}
    try:
        validate_catalog(list(committed.tools), families=ALL_FAMILIES, sources=sources)
    except CatalogError as exc:
        assert exc.reason == "unclassified_source"
    else:
        raise AssertionError("a tool without a classified source must fail")
    changed = dict(base.to_dict()["input_schema"])
    changed["properties"] = {
        **changed.get("properties", {}),
        "extra": {"type": "string", "description": "x"},
    }
    unbumped = _spec(committed, "list_cameras", input_schema=changed)
    assert _reason(_replace(committed, unbumped), live, committed) == "unbumped_version"
    bumped = _spec(committed, "list_cameras", input_schema=changed, version="1.1.0")
    assert _reason(_replace(committed, bumped), live, committed) is None
    no_fixture = _spec(committed, "list_cameras", output_schema={"type": "object"}, version="1.1.0")
    assert _reason(_replace(committed, no_fixture), live, committed) == "missing_fixture"
    absent = _spec(committed, "list_cameras", fixtures=["tests/fixtures/no/such/file.json"])
    assert _reason(_replace(committed, absent), live, committed) == "missing_fixture"
    assert _reason(list(committed.tools) + [base], live, committed) == "duplicate_key"
    assert _reason(list(committed.tools) + [cross], live, committed) == "duplicate_emitted_name"
    assert CATALOG_REASONS[-1] == "duplicate_emitted_name"


def test_first_applicable_reason_wins_pairwise(
    live: dict[str, Any], committed: cat.Catalog
) -> None:
    """Each adjacent pair of reasons in one catalog returns the earlier reason."""
    base = committed.by_name()["list_cameras"]
    other = committed.by_name()["list_hosts"]
    changed = dict(base.to_dict()["input_schema"])
    changed["properties"] = {
        **changed.get("properties", {}),
        "extra": {"type": "string", "description": "x"},
    }
    bad_annotations = _spec(
        committed,
        "list_hosts",
        annotations={**dict(other.annotations), "destructiveHint": True},
    )
    unbumped = _spec(committed, "list_cameras", input_schema=changed)
    assert (
        _reason(_replace(committed, bad_annotations, unbumped), live, committed)
        == "annotation_mismatch"
    )
    no_fixture = _spec(committed, "list_hosts", output_schema={"type": "object"}, version="1.1.0")
    assert _reason(_replace(committed, unbumped, no_fixture), live, committed) == "unbumped_version"
    assert _reason(_replace(committed, no_fixture) + [base], live, committed) == "missing_fixture"
    cross = ToolSpec.from_dict(
        {
            **base.to_dict(),
            "id": "network.list_cameras",
            "family": "network",
            "family_id": "network",
            "handler": cat.handler_ref("network", "list_cameras"),
        }
    )
    assert _reason(list(committed.tools) + [other, cross], live, committed) == "duplicate_key"


def test_overlay_semantics(committed: cat.Catalog) -> None:
    specs = overlay(
        committed.tools,
        [
            {"base": "list_cameras"},
            {
                "base": "list_cameras",
                "id": "network.list_cameras",
                "family": "network",
                "family_id": "network",
            },
        ],
    )
    assert len(specs) == len(committed.tools) + 1
    moved = [s for s in specs if s.id == "network.list_cameras"]
    assert moved and moved[0].handler == cat.handler_ref("network", "list_cameras")
    with pytest.raises(CatalogError) as err:
        overlay(committed.tools, [{"base": "no_such_tool"}])
    assert err.value.reason == "invalid_spec"


def _c_fixture_files() -> list[Path]:
    return sorted(C_FIXTURES.glob("*.json")) if C_FIXTURES.is_dir() else []


@pytest.mark.parametrize("path", _c_fixture_files(), ids=lambda p: p.stem)
def test_c_fixture_catalog_outcome(
    path: Path, live: dict[str, Any], committed: cat.Catalog
) -> None:
    """Each catalog fixture overlays the baseline catalog; catalog-level reasons are checked here,
    handler-level reasons (missing_handler, invalid_signature) by registration."""
    fixture = json.loads(path.read_text(encoding="utf-8"))
    assert fixture["contract"] == "c" and fixture["name"] == path.stem
    expected = fixture["expected"]
    try:
        specs = overlay(committed.tools, fixture["input"]["tool_specs"])
        _validate(specs, live, committed)
    except CatalogError as exc:
        assert fixture["kind"] == "reject", f"{path.stem}: unexpected {exc.code}"
        assert exc.code == expected["code"]
        return
    if fixture["kind"] == "reject":
        reason = expected["code"].removeprefix("startup:catalog:")
        assert reason in cat.HANDLER_REASONS, f"{path.stem}: expected {expected['code']}"
        if reason == "invalid_signature":
            # Needs the test-local fake adapter module (tests/test_contract_c0.py runs it).
            return
        from unifi_fabric.catalog_registration import registration_specs, validate_registration
        from unifi_fabric.registration import CatalogError as RegistrationError

        with pytest.raises(RegistrationError) as err:
            validate_registration(registration_specs(cat.Catalog("1.0.0", tuple(specs))))
        assert reason in str(err.value), path.stem
        return
    # Accept fixtures describe UNIFI_TOOL_MODE=full: the discovery meta tools register only
    # in discovery mode.
    full_mode = sorted(s.name for s in specs if s.name not in cat.DISCOVERY_META_TOOLS)
    assert expected["registered_names"] == full_mode


# --- generated handler adapters ------------------------------------------------------

ADAPTER_PARAMS = ["request_context", "validated_arguments", "dependencies"]


def _adapter_generator():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gen_handler_adapters", ROOT / "scripts" / "gen_handler_adapters.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_committed_adapters_are_fresh() -> None:
    gen = _adapter_generator()
    files = gen.render()
    present = {p.name for p in gen.ADAPTER_DIR.glob("*.py")}
    assert present == set(files), "adapter modules missing or extra"
    stale = [
        n for n, text in files.items() if (gen.ADAPTER_DIR / n).read_text(encoding="utf-8") != text
    ]
    assert stale == [], "adapters stale; run scripts/gen_handler_adapters.py --write"


def _resolve(handler: str):
    import importlib

    module_name, _, symbol = handler.partition(":")
    assert module_name.startswith(cat.ADAPTER_PACKAGE + "."), handler
    return getattr(importlib.import_module(module_name), symbol)


def test_every_spec_resolves_to_exactly_one_adapter(committed: cat.Catalog) -> None:
    import importlib
    import inspect

    resolved = {}
    for spec in committed.tools:
        fn = _resolve(spec.handler)
        assert inspect.iscoroutinefunction(fn), spec.handler
        assert list(inspect.signature(fn).parameters) == ADAPTER_PARAMS, spec.handler
        assert fn.__name__ == spec.name
        resolved[spec.key] = fn
    assert len(resolved) == len(committed.tools) == len({s.name for s in committed.tools})
    # No adapter module exports a symbol that is not a catalog spec of its family.
    families = {s.family for s in committed.tools}
    for family in families:
        module = importlib.import_module(f"{cat.ADAPTER_PACKAGE}.{family}")
        assert set(module.__all__) == {s.name for s in committed.tools if s.family == family}


async def test_adapters_pass_arguments_verbatim(committed: cat.Catalog, monkeypatch) -> None:
    """Every adapter calls its wrapper with exactly **validated_arguments: omitted keys
    stay absent, an explicit null arrives as None, and the result returns unchanged."""
    calls: list[tuple[str, dict]] = []
    sentinel = object()

    def fake_lookup(name: str):
        async def wrapper(**kwargs):
            calls.append((name, kwargs))
            return sentinel

        return wrapper

    import importlib

    for spec in committed.tools:
        module = importlib.import_module(spec.handler.partition(":")[0])
        monkeypatch.setattr(module, "registered_wrapper", fake_lookup)
    arguments = {"site": None, "host": "console"}
    for spec in committed.tools:
        result = await _resolve(spec.handler)(object(), dict(arguments), object())
        assert result is sentinel
    assert len(calls) == len(committed.tools)
    assert all(kwargs == arguments for _name, kwargs in calls)
    assert [name for name, _ in calls] == [spec.name for spec in committed.tools]


SHARE_CAM = "0000000000000000000000aa"
SHARE_RECORDED = ROOT / "tests" / "fixtures" / "recorded" / "protect"


@pytest.mark.parametrize(
    "name,fixture",
    [
        ("get_camera_share_link", "share_get_on"),
        ("enable_camera_share_link", "share_post_enable"),
        ("disable_camera_share_link", "share_delete_disable"),
    ],
)
async def test_adapter_equals_direct_wrapper_on_recorded_fixtures(
    name: str, fixture: str, monkeypatch
) -> None:
    from unittest.mock import AsyncMock

    import httpx

    from unifi_fabric import server
    from unifi_fabric._adapter_runtime import registered_wrapper

    body = json.loads((SHARE_RECORDED / f"{fixture}.json").read_text())["body"]

    def deps():
        client = AsyncMock()
        client.get.return_value = body
        client.delete.return_value = body
        client.request.return_value = httpx.Response(200, json=body)
        registry = AsyncMock()
        registry.resolve_key_for_host.return_value = None
        registry.resolve_host_id.return_value = "host-a"
        return client, registry

    arguments = {"host": "console", "camera_id": SHARE_CAM}
    client, registry = deps()
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", registry)
    direct = await registered_wrapper(name)(**arguments)
    direct_calls = [
        c for m in (client.get, client.delete, client.request) for c in m.await_args_list
    ]
    client, registry = deps()
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", registry)
    spec = load_catalog().by_name()[name]
    via_adapter = await _resolve(spec.handler)(object(), arguments, object())
    adapter_calls = [
        c for m in (client.get, client.delete, client.request) for c in m.await_args_list
    ]
    assert via_adapter == direct == body
    assert adapter_calls == direct_calls


# --- generated runtime tool index (path-insensitive families and sub-areas) ---------


def _tool_index_generator():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "gen_tool_index", ROOT / "scripts" / "gen_tool_index.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_committed_tool_index_is_fresh() -> None:
    gen = _tool_index_generator()
    assert gen.TARGET.read_text(encoding="utf-8") == gen.render(), (
        "tool index is stale; run scripts/gen_tool_index.py --write"
    )


def test_runtime_family_index_is_the_catalog(committed: cat.Catalog) -> None:
    from unifi_fabric import families
    from unifi_fabric._generated import tool_index

    runtime = families.build_family_index()
    expected = committed.family_index()
    expected.update(tool_index.SELECTION_FAMILY_OVERRIDES)
    assert runtime == expected
    assert set(tool_index.SELECTION_FAMILY_OVERRIDES) <= META_TOOL_NAMES
    assert tool_index.SELECTION_FAMILY_OVERRIDES == {"list_configured_api_keys": "site_manager"}
    assert families.build_family_index() is families.build_family_index()


def test_runtime_index_parses_no_source(monkeypatch) -> None:
    from unifi_fabric import families

    def boom(*_args, **_kwargs):
        raise AssertionError("runtime index parsed source")

    monkeypatch.setattr(families, "_module_source", boom)
    assert families.build_family_index()
    assert families.build_module_index()
    assert families.firewall_route_tools()
    assert families.connector_write_tools()


def test_runtime_index_equals_the_source_derivation() -> None:
    from unifi_fabric import families

    assert families.build_module_index() == families.derive_module_index()
    assert families.firewall_route_tools() == families.derive_firewall_route_tools()
    assert families.connector_write_tools() == families.tools_referencing("CONNECTOR_WRITE_ENV")
    derived = families.derive_family_index()
    assert families.build_family_index() == derived


def test_registered_wrapper_resolves_every_domain_spec(committed: cat.Catalog) -> None:
    """Every non-discovery spec resolves to its registered wrapper under the full roster;
    the discovery meta tools resolve only while discovery mode registers them."""
    import inspect

    from unifi_fabric import server
    from unifi_fabric._adapter_runtime import registered_wrapper

    registered = {t.name: t.fn for t in asyncio.run(server.mcp.list_tools())}
    for spec in committed.tools:
        if spec.name in cat.DISCOVERY_META_TOOLS:
            with pytest.raises(LookupError):
                registered_wrapper(spec.name)
            continue
        resolved = registered_wrapper(spec.name)
        expected = registered[spec.name]
        assert inspect.unwrap(resolved).__code__ is inspect.unwrap(expected).__code__, spec.name
    with pytest.raises(LookupError):
        registered_wrapper("no_such_tool")


async def test_adapter_propagates_wrapper_exceptions(committed: cat.Catalog, monkeypatch) -> None:
    import importlib

    spec = committed.by_name()["list_cameras"]
    module = importlib.import_module(spec.handler.partition(":")[0])

    class Boom(Exception):
        pass

    def lookup(_name: str):
        async def wrapper(**_kwargs):
            raise Boom("raised by the wrapper")

        return wrapper

    monkeypatch.setattr(module, "registered_wrapper", lookup)
    with pytest.raises(Boom):
        await _resolve(spec.handler)(object(), {}, object())


def test_catalog_validates_and_resolves_through_the_c0_registrar(committed: cat.Catalog) -> None:
    """Every spec passes the registration validator with the catalog checks and resolves to
    exactly one adapter; resolved-handler, spec, key and emitted-name counts are equal."""
    from unifi_fabric.catalog_registration import registration_specs, validate_registration

    specs = registration_specs(committed)
    bound = validate_registration(specs)
    assert len(bound) == len(specs) == len({s.key for s in specs}) == len({s.name for s in specs})
    for spec in specs:
        handler = bound[spec.name].handler
        assert f"{handler.__module__}:{handler.__qualname__}" == spec.handler


@pytest.mark.parametrize(
    "reason", ["unclassified_source", "annotation_mismatch", "unbumped_version"]
)
def test_c_checks_reject_through_the_registrar(reason: str, committed: cat.Catalog) -> None:
    import dataclasses

    from unifi_fabric.catalog_registration import registration_specs, validate_registration
    from unifi_fabric.registration import CatalogError as RegistrationError

    specs = registration_specs(committed)
    index = next(i for i, s in enumerate(specs) if s.name == "list_cameras")
    base = specs[index]
    changes: dict[str, Any] = {
        "unclassified_source": {"api_source_id": "mobility/official"},
        "annotation_mismatch": {"annotations": {**dict(base.annotations), "destructiveHint": True}},
        "unbumped_version": {
            "input_schema": {**dict(base.input_schema), "title": "changed without a bump"}
        },
    }[reason]
    specs[index] = dataclasses.replace(base, **changes)
    with pytest.raises(RegistrationError) as err:
        validate_registration(specs)
    assert reason in str(err.value)


def test_registrar_rejects_a_valid_but_wrong_symbol(committed: cat.Catalog) -> None:
    """A HandlerRef naming another tool's adapter in the same family module passes the
    schema check and is refused by the registrar as missing_handler."""
    import dataclasses

    from unifi_fabric.catalog_registration import registration_specs, validate_registration
    from unifi_fabric.registration import CatalogError as RegistrationError

    specs = registration_specs(committed)
    index = next(i for i, s in enumerate(specs) if s.name == "list_cameras")
    specs[index] = dataclasses.replace(
        specs[index], handler=cat.handler_ref("protect", "get_camera")
    )
    with pytest.raises(RegistrationError) as err:
        validate_registration(specs)
    assert "missing_handler" in str(err.value)


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"annotations": {}}, "annotation_mismatch"),
        ({"input_schema": {"type": "object", "title": "x"}, "version": "1.0"}, "unbumped_version"),
    ],
)
def test_c_checks_refuse_malformed_fields(changes, reason, committed: cat.Catalog) -> None:
    import dataclasses

    from unifi_fabric.catalog_registration import registration_specs, validate_registration
    from unifi_fabric.registration import CatalogError as RegistrationError

    specs = registration_specs(committed)
    index = next(i for i, s in enumerate(specs) if s.name == "list_cameras")
    specs[index] = dataclasses.replace(specs[index], **changes)
    with pytest.raises(RegistrationError) as err:
        validate_registration(specs)
    assert reason in str(err.value) or "invalid_spec" in str(err.value)
