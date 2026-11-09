"""Breaking tool lists follow registered source and the public 0.6.2 catalog.

The frozen return annotations were extracted from v0.6.2 docs/TOOLS.md. Current
sets are recomputed from registered tools, output schemas and transitive helper
calls. Git history is not needed to check the release notes.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

import pytest

from tests.test_changelog_input_schemas import _bullets

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "docs" / "MIGRATING-0.7.md"


@lru_cache(maxsize=1)
def derived_sets():
    import inspect

    from tests.test_tool_schema_contract import _tools
    from unifi_fabric._read_only_audit import _called_package_functions, _direct_write_verbs
    from unifi_fabric.families import build_family_index
    from unifi_fabric.write_body import body_argument

    tools = {tool.name: tool for tool in _tools()}
    old = json.loads((ROOT / "tests/fixtures/tool_return_types_v0_6_2.json").read_text())
    common = set(tools) & set(old)
    graph = {}
    sources, children, verbs = {}, {}, {}
    for name, tool in tools.items():
        seen, pending = set(), [inspect.unwrap(tool.fn)]
        while pending:
            fn = inspect.unwrap(pending.pop())
            if fn in seen:
                continue
            seen.add(fn)
            if fn not in sources:
                try:
                    sources[fn] = inspect.getsource(fn)
                except (OSError, TypeError):
                    sources[fn] = ""
            if fn not in children:
                children[fn] = _called_package_functions(fn)
                verbs[fn] = _direct_write_verbs(fn)
            pending.extend(children[fn])
        graph[name] = seen

    def reaching(*helpers):
        return {name for name in common if any(fn.__name__ in helpers for fn in graph[name])}

    def matching(pattern):
        return {
            name for name in common if any(re.search(pattern, sources[fn]) for fn in graph[name])
        }

    writes = {name for name in common if any(verbs[fn] for fn in graph[name])}
    retrying = writes | matching(r"\.(?:post|post_multipart)\s*\(")
    connector = {name for name in common if name.startswith("fabric_connector_")}
    family = build_family_index()
    protect_family = {name for name in common if family[name] == "protect"}
    protect_wrapped = reaching("_write_result") & protect_family
    protect_updates = (reaching("_update_item_verified", "_updated") & protect_family) | {
        "update_arm_profile_settings"
    }
    mobility = {name for name in writes if family[name] == "mobility"}
    carrier = {name for name in writes if family[name] == "carrier"}
    selectors = {
        name
        for name in common
        if set(tools[name].parameters.get("properties", {}))
        & {
            "host",
            "site",
            "key_label",
            "device_id",
            "client_id",
            "sites",
            "host_ids",
            "client_ids",
            "cameras",
            "mac",
        }
    }
    return {
        "every Protect write and action tool returns": protect_wrapped,
        "every Protect update tool returns one shape": protect_updates,
        "an opted-out write area raises": (writes & protect_family)
        | mobility
        | carrier
        | (connector - {"fabric_connector_get"}),
        "port-profile network fields": reaching("_resolve_profile_networkconf"),
        "the per-area write opt-outs apply to relayed writes": connector - {"fabric_connector_get"},
        "only a GET is retried": retrying - {"fabric_connector_get"},
        "host and site resolution never guess": selectors,
        "arguments are validated before any request": {
            name for name in common if tools[name].parameters.get("properties")
        },
        "update tools refuse a body with nothing to change": reaching("require_update_fields")
        | {name for name in common if body_argument(tools[name]) is not None},
        # update_traffic_rule gained leaf-by-leaf verification in 0.7.1 (its changelog.d
        # fragment says so); the released 0.7 list keeps its 0.7.0 contents.
        "no-op and verification checks compare leaf by leaf": (
            reaching("requested_leaves_match", "short_circuit_no_op", "_updated")
            | (connector - {"fabric_connector_get"})
        )
        - {"update_traffic_rule"},
        "a call that reached nothing fails": reaching(
            "_require_object",
            "_object_body",
            "_as_list",
            "_list_body",
            "isp_metric_records",
            "_drain",
            "_extract_list",
            "_require_objects",
            # The batched paging helpers that replaced client.paginate* drains.
            "collect_offset",
            "collect_links",
            "collect_cursor",
        )
        | matching(r"\.paginate(?:_offset|_links)?\s*\(")
        | {
            "search_across_sites",
            "list_all_clients",
            "compare_site_performance",
            "get_innerspace_summary",
        },
        "write tools drop server-added": writes - connector,
        "no longer declare an object `outputSchema`": {
            name
            for name in common
            if old[name].startswith("dict[") and tools[name].output_schema is None
        },
    }


@pytest.mark.parametrize(
    "title",
    (
        "every Protect write and action tool returns",
        "every Protect update tool returns one shape",
        "an opted-out write area raises",
        "port-profile network fields",
        "the per-area write opt-outs apply to relayed writes",
        "only a GET is retried",
        "host and site resolution never guess",
        "arguments are validated before any request",
        "update tools refuse a body with nothing to change",
        "no-op and verification checks compare leaf by leaf",
        "a call that reached nothing fails",
        "write tools drop server-added",
        "no longer declare an object `outputSchema`",
    ),
)
def test_breaking_entry_lists_exactly_the_derived_tools(title):
    entries = [
        b for b in _bullets(MIGRATION.read_text()) if b.startswith("**Breaking") and title in b
    ]
    assert len(entries) == 1, title
    entry = entries[0]
    match = re.search(r"Affected tools: (.*?)\.(?: |\Z)", entry)
    assert match, f"{title}: missing explicit affected-tool list"
    listed = re.findall(r"`([a-z_]+)`", match.group(1))
    expected = derived_sets()[title]
    catalog_reference_titles = {
        "arguments are validated before any request",
        "write tools drop server-added",
    }
    if title in catalog_reference_titles:
        assert re.search(rf"\b{len(expected)} tools\b", entry)
        assert (
            "https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.0/"
            "docs/TOOLS.md#tool-categories"
        ) in entry
        return
    if title == "no longer declare an object `outputSchema`":
        assert f"{len(expected)} tools no longer declare" in entry
    assert len(listed) == len(set(listed)), title
    assert set(listed) == expected, {
        "missing": sorted(expected - set(listed)),
        "extra": sorted(set(listed) - expected),
    }


def test_old_confirmation_gates_are_enumerated():
    baseline = json.loads((ROOT / "tests/fixtures/tool_input_schemas_v0_6_2.json").read_text())
    expected = {
        name
        for name, schema in baseline["schemas"].items()
        if "confirm" in schema.get("properties", {})
    }
    (entry,) = [
        b
        for b in _bullets(MIGRATION.read_text())
        if b.startswith("**Breaking (behavior): no unrequested gates;")
    ]
    paragraph = entry.split("`confirm` is still accepted", 1)[0]
    assert set(re.findall(r"`([a-z_]+)`", paragraph)) == expected


def test_connector_relay_body_forwarding_is_documented():
    text = MIGRATION.read_text()
    assert "sends its body exactly as given" in text
    for name in (
        "fabric_connector_get",
        "fabric_connector_post",
        "fabric_connector_put",
        "fabric_connector_patch",
        "fabric_connector_delete",
    ):
        assert f"`{name}`" in text
