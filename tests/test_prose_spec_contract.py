"""Tool prose examples and claims remain aligned with pinned API contracts."""

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/openapi"
NETWORK = json.loads((FIXTURES / "network-11.0.97.json").read_text())
PROTECT = json.loads((FIXTURES / "protect-7.3.74.json").read_text())
SITE = json.loads((FIXTURES / "site-manager-1.0.0.json").read_text())


def docs(path):
    tree = ast.parse((ROOT / path).read_text())
    return {
        node.name: ast.get_docstring(node) or ""
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def wrapper_docs():
    """Docstrings of the public tool wrappers formerly inline in server.py.

    server.py keeps any remaining inline wrapper and re-exports each moved one from the
    ``register``/``register_N`` call of its tools module
    (``_<module>_tools = <module>.register(...)``); the moved wrapper's docstring is read
    from the function nested in that register function.
    """
    out = docs("src/unifi_fabric/server.py")
    tree = ast.parse((ROOT / "src/unifi_fabric/server.py").read_text())
    calls = set()
    for node in tree.body:
        value = getattr(node, "value", None)
        if (
            isinstance(node, ast.Assign)
            and isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and isinstance(value.func.value, ast.Name)
            and re.fullmatch(r"register(?:_[0-9]+)?", value.func.attr)
        ):
            calls.add((value.func.value.id, value.func.attr))
    for module, function in sorted(calls):
        module_tree = ast.parse((ROOT / f"src/unifi_fabric/tools/{module}.py").read_text())
        for node in module_tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == function:
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        out[sub.name] = ast.get_docstring(sub) or ""
    return out


def test_network_prose_matches_schema():
    server = wrapper_docs()
    module = docs("src/unifi_fabric/tools/network.py")
    schemas = NETWORK["components"]["schemas"]
    assert "autoScaleEnabled" in schemas["Gateway Managed IPv4 Configuration"]["required"]
    assert "required autoScaleEnabled" in server["create_network"]
    enum = schemas["Network reference resource"]["properties"]["resourceType"]["enum"]
    for doc in (server["get_network_references"], module["get_network_references"]):
        assert all(re.search(rf"\b{kind}\b", doc) for kind in enum)
        assert "firewall policies" not in doc and "port profiles" not in doc
    mapping = schemas["Firewall policy destination traffic filter"]["discriminator"]["mapping"]
    for kind in ("PORT", "IP_ADDRESS"):
        schema = schemas[mapping[kind].rsplit("/", 1)[-1]]
        assert any("portFilter" in part.get("properties", {}) for part in schema["allOf"])
    for name in ("create_firewall_policy", "update_firewall_policy"):
        doc = server[name]
        assert "port-only" in doc and "IP_ADDRESS with portFilter" in doc
        assert "MUST use destination.trafficFilter" not in doc
    assert set(schemas["ACL rule update"]["discriminator"]["mapping"]) == {"IPV4", "MAC"}
    for name in ("list_acl_rules", "create_acl_rule"):
        assert "IPv4" in server[name] and "MAC" in server[name]


def test_liveview_required_fields_and_example():
    doc = wrapper_docs()["create_liveview"]
    required = set(PROTECT["components"]["schemas"]["liveview"]["required"])
    example = json.loads(
        doc.split("Example call (create_liveview):", 1)[1].split("The dry-run preview", 1)[0]
    )
    body = {"name": example["name"], **example["settings"]}
    assert required <= body.keys()
    shape = doc.split("Shape:", 1)[1]
    for field in required - {"name"}:
        assert re.search(rf"\b{field}:", shape)
        assert not re.search(rf"\b{field}\?:", shape)


def test_sdwan_prose_matches_published_contract():
    operation = SITE["paths"]["/v1/sd-wan-configs"]["get"]
    assert not operation.get("parameters")
    schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert "nextToken" not in schema["properties"]
    for doc in (
        wrapper_docs()["list_sdwan_configs"],
        docs("src/unifi_fabric/tools/site_manager.py")["list_sdwan_configs"],
    ):
        assert "declares no pagination parameters or nextToken" in doc
        assert "if the service returns one" in doc


def test_all_list_filter_examples_match_pinned_fields_and_operators():
    paths = {
        "list_local_sites": "/v1/sites",
        "list_networks": "/v1/sites/{siteId}/networks",
        "list_integration_device_tags": "/v1/sites/{siteId}/device-tags",
        "list_lags": "/v1/sites/{siteId}/switching/lags",
        "list_mc_lag_domains": "/v1/sites/{siteId}/switching/mc-lag-domains",
        "list_switch_stacks": "/v1/sites/{siteId}/switching/switch-stacks",
        "list_wifi_broadcasts": "/v1/sites/{siteId}/wifi/broadcasts",
        "list_firewall_policies": "/v1/sites/{siteId}/firewall/policies",
        "list_firewall_zones_proxy": "/v1/sites/{siteId}/firewall/zones",
        "list_acl_rules": "/v1/sites/{siteId}/acl-rules",
        "list_dns_policies": "/v1/sites/{siteId}/dns/policies",
        "list_traffic_matching_lists": "/v1/sites/{siteId}/traffic-matching-lists",
        "list_vpn_servers": "/v1/sites/{siteId}/vpn/servers",
        "list_site_to_site_tunnels": "/v1/sites/{siteId}/vpn/site-to-site-tunnels",
        "list_radius_profiles": "/v1/sites/{siteId}/radius/profiles",
        "list_hotspot_vouchers": "/v1/sites/{siteId}/hotspot/vouchers",
        "list_countries": "/v1/countries",
        "list_dpi_categories": "/v1/dpi/categories",
        "list_dpi_applications": "/v1/dpi/applications",
    }
    server = wrapper_docs()
    expression = re.compile(r"\b([\w.]+)\.(eq|like)\(")
    described = {
        name for name, doc in server.items() if name.startswith("list_") and expression.search(doc)
    }
    assert described == paths.keys()
    for name, path in paths.items():
        description = NETWORK["paths"][path]["get"]["description"]
        fields = {
            field: set(re.findall(r"`([^`]+)`", funcs))
            for field, funcs in re.findall(r"\|`([^`]+)`\|[^|]*\|([^|]*)\|", description)
        }
        for field, operator in expression.findall(server[name]):
            assert operator in fields.get(field, set()), (name, field, operator)
