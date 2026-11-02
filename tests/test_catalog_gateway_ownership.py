"""Opt-in ownership disambiguates overlapping gateway slugs without guessing."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

from unifi_fabric._catalog_audit import (
    base_tool_name,
    catalog_base_names,
    diff_catalog,
    federated_tool_name,
)

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import check_catalog_regression as cli  # noqa: E402


@pytest.mark.parametrize("slug", ["unifi-fabric", "custom-gateway"])
def test_identical_wire_name_requires_explicit_ownership(slug):
    child = f"{slug}-dev"
    raw = federated_tool_name("dev_list_a", slug)
    assert raw == federated_tool_name("list_a", child)
    # Legacy interpretation stays intact without caller-supplied metadata.
    assert base_tool_name(raw, slug) == "dev_list_a"
    assert diff_catalog(["dev_list_a"], [raw], slug).is_clean
    assert base_tool_name(raw, child) == "list_a"
    assert base_tool_name(raw, slug, other_gateway_slugs={child}) is None
    diff = diff_catalog(["dev_list_a"], [raw], slug, other_gateway_slugs={child})
    assert diff.missing_from_catalog == ["dev_list_a"]
    assert diff.unexpected_in_catalog == []
    assert diff_catalog(["list_a"], [raw], child, other_gateway_slugs={slug}).is_clean


@pytest.mark.parametrize("slug", ["unifi-fabric", "custom-gateway"])
def test_multi_gateway_catalog_uses_longest_known_slug(slug):
    child = f"{slug}-dev"
    grandchild = f"{child}-qa"
    catalog = [
        federated_tool_name("list_a", slug),
        federated_tool_name("get_b", slug),
        federated_tool_name("list_a", child),
        federated_tool_name("list_a", grandchild),
        "unrelated-list-a",
    ]
    # Materialize one-shot ownership iterables once for the entire catalog.
    assert catalog_base_names(
        catalog, slug, other_gateway_slugs=(s for s in [child, grandchild, slug])
    ) == {"list_a", "get_b"}
    assert diff_catalog(["list_a"], catalog, child, other_gateway_slugs={slug, grandchild}).is_clean
    assert diff_catalog(["list_a"], catalog, grandchild, other_gateway_slugs={slug, child}).is_clean
    assert base_tool_name("unrelated-list-a", slug, other_gateway_slugs={child}) is None


@pytest.mark.parametrize("slug", ["unifi-fabric", "custom-gateway"])
def test_compare_catalog_keeps_native_names_and_excludes_foreign_prefix(slug):
    diff = cli.compare_catalog(
        ["list_a"],
        ["list_a", federated_tool_name("list_a", f"{slug}-dev")],
        slug,
        other_gateway_slugs={f"{slug}-dev"},
    )
    assert diff.is_clean, diff.summary()


@pytest.mark.parametrize("slug", ["unifi-fabric", "custom-gateway"])
def test_native_names_keep_their_explicit_gateway_context(slug):
    diff = cli.compare_catalog(
        ["dev_list_a"],
        ["dev_list_a", federated_tool_name("list_a", f"{slug}-dev")],
        slug,
        other_gateway_slugs={f"{slug}-dev"},
    )
    assert diff.is_clean, diff.summary()


@pytest.mark.parametrize("slug", ["unifi-fabric", "custom-gateway"])
@pytest.mark.parametrize("target_child", [False, True])
def test_snapshot_cli_ownership_is_opt_in(tmp_path, monkeypatch, capsys, slug, target_child):
    child = f"{slug}-dev"
    target, other = (child, slug) if target_child else (slug, child)
    monkeypatch.setattr(cli, "registered_tool_catalog", lambda: [{"name": "list_a"}])
    snapshot = tmp_path / "catalog.json"
    snapshot.write_text(json.dumps([federated_tool_name("list_a", s) for s in [slug, child]]))
    args = ["--snapshot", str(snapshot)]
    if target != "unifi-fabric":
        args += ["--gateway-slug", target]
    assert cli.main(args) == (0 if target_child else 1)
    legacy = capsys.readouterr().out
    assert ("dev_list_a" in legacy) is (not target_child)
    assert cli.main([*args, "--other-gateway-slug", other]) == 0
    assert "in sync" in capsys.readouterr().out


@pytest.mark.parametrize("slug", ["unifi-fabric", "custom-gateway"])
@pytest.mark.parametrize("discovery", [False, True])
@pytest.mark.parametrize("target_child", [False, True])
@pytest.mark.parametrize("native_name", ["list_a", "dev_list_a"])
def test_endpoint_cli_uses_ownership_for_diff_and_discovery(
    respx_mock, monkeypatch, capsys, slug, discovery, target_child, native_name
):
    endpoint = "https://catalog-ownership.invalid/mcp"
    child = f"{slug}-dev"
    target, other = (child, slug) if target_child else (slug, child)
    tools = [{"name": native_name, "inputSchema": {"type": "object", "properties": {}}}]
    monkeypatch.setattr(cli, "registered_tool_catalog", lambda: tools)
    meta = [
        "search_tools",
        "describe_tool",
        "call_read_tool",
        "call_write_tool",
        "list_tool_families",
    ]
    advertised = [
        {"name": federated_tool_name(name, gateway)}
        for gateway in [slug, child]
        for name in (meta if discovery else [native_name])
    ]
    called = []

    def respond(request):
        message = json.loads(request.content)
        method = message["method"]
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
        elif method == "notifications/initialized":
            return httpx.Response(202)
        elif method == "tools/list":
            result = {"tools": advertised}
        else:
            assert method == "tools/call"
            name = message["params"]["name"]
            called.append(name)
            if name == federated_tool_name("search_tools", target):
                data = [{"name": native_name}]
            else:
                assert name == federated_tool_name("describe_tool", target)
                assert message["params"]["arguments"] == {"name": native_name}
                data = tools[0]
            result = {"content": [{"type": "text", "text": json.dumps(data)}]}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": result})

    route = respx_mock.post(endpoint).mock(side_effect=respond)
    args = ["--live", "--endpoint", endpoint, "--other-gateway-slug", other]
    if target != "unifi-fabric":
        args += ["--gateway-slug", target]
    # Full-mode wire names can truly collide: parent.dev_list_a is child.list_a.
    # The supplied metadata assigns both to the child; native discovery names
    # carry their own gateway context and therefore retain dev_list_a.
    ambiguous_full = not discovery and native_name == "dev_list_a"
    assert cli.main(args) == (1 if ambiguous_full else 0)
    output = capsys.readouterr().out
    if ambiguous_full:
        assert "DRIFT" in output
        if target_child:
            assert "in catalog but NOT registered (stale/phantom): list_a" in output
        else:
            assert "registered but MISSING from catalog (unreachable): dev_list_a" in output
    else:
        assert "in sync" in output
    assert route.call_count == (5 if discovery else 3)
    assert called == (
        [federated_tool_name(name, target) for name in ["search_tools", "describe_tool"]]
        if discovery
        else []
    )


def test_snapshot_cli_accepts_multiple_other_slugs(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "registered_tool_catalog", lambda: [{"name": "list_a"}])
    snapshot = tmp_path / "catalog.json"
    snapshot.write_text(
        json.dumps(["unifi-fabric-list-a", "unifi-fabric-lab-list-a", "unifi-fabric-demo-list-a"])
    )
    assert (
        cli.main(
            [
                "--snapshot",
                str(snapshot),
                "--other-gateway-slug",
                "unifi-fabric-lab",
                "--other-gateway-slug",
                "unifi-fabric-demo",
            ]
        )
        == 0
    )
    assert "in sync" in capsys.readouterr().out
