"""Catalog-wide documentation examples remain useful without adding validation."""

import ast
import ipaddress
import json
import re
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "src" / "unifi_fabric"
PAGING = {"cursor", "limit", "offset", "page", "page_token", "page_size"}


def tool_docs():
    catalog = {}
    for path in SOURCE.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "tool"
                for decorator in node.decorator_list
            ):
                args = {arg.arg for arg in node.args.args + node.args.kwonlyargs}
                catalog[node.name] = (args, ast.get_docstring(node) or "")
    assert catalog
    return catalog


def example(name):
    doc = tool_docs()[name][1]
    if f"Example call ({name}):" not in doc and f"docs/TOOL-USAGE.md#{name}" in doc:
        from tests.test_spec_conformance import usage_section

        doc = usage_section(name)
    text = doc.split(f"Example call ({name}):", 1)[1].lstrip()
    return json.JSONDecoder().raw_decode(text)[0]


def test_public_descriptions_explain_auto_exclusion_without_internal_finding_id():
    docs = tool_docs()
    for name, (_, doc) in docs.items():
        assert not re.search(r"\bD12\b", doc), name
    assert "D12_AUTO_EXCLUSION" in docs["create_network"][1]


def test_realistic_network_voucher_and_pos_examples():
    network = example("create_network")["network_config"]
    assert 2 <= network["vlanId"] <= 4009
    assert network["name"] != "Default Network"
    ipv4 = network["ipv4Configuration"]
    assert ipv4["prefixLength"] == 24
    assert any(
        ipaddress.ip_address(ipv4["hostIpAddress"]) in ipaddress.ip_network(prefix)
        for prefix in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    )
    assert example("create_hotspot_vouchers")["voucher_config"]["timeLimitMinutes"] == 1440
    assert example("pos_ingest_transaction")["transaction"]["amount"] > 1


def test_every_read_filter_and_paging_parameter_has_a_concrete_example():
    seen_filter = seen_paging = 0
    failures = []
    for name, (args, doc) in tool_docs().items():
        for arg in args & (PAGING | {"filter"}):
            block = re.search(rf"(?m)^    {arg}:.*(?:\n        .*|\n(?=\n))*", doc)
            text = block.group() if block else ""
            if arg == "filter":
                seen_filter += 1
                valid = re.search(r"Example:.*\w+\.eq\('[^']+'\)", text)
            else:
                seen_paging += 1
                valid = re.search(r"Example:", text)
                if arg in {"limit", "page_size"}:
                    valid = valid and re.search(r"Example: `(?:25|50|100|200)`", text)
                elif arg == "offset":
                    valid = valid and "Example: `25`" in text
                elif arg == "page":
                    valid = valid and "Example: `2`" in text
                else:
                    valid = valid and "previous response" in text
            if not valid:
                failures.append(f"{name}.{arg}")
    assert seen_filter and seen_paging
    assert not failures, failures


def test_historical_retention_is_not_a_partial_interval_list():
    doc = tool_docs()["get_historical_stats"][1]
    retention = next((line for line in doc.splitlines() if "Retention differs" in line), "")
    assert not retention or all(
        interval in retention
        for interval in ("minute", "5minutes", "hourly", "daily", "monthly", "archive")
    )
