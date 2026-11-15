"""The typed catalog inventory (unifi_fabric.catalog.models and .inventory).

* every registered tool has exactly one ToolSpec: the count equals the catalog count and
  the registered count, with no missing, duplicate or unknown entry;
* each ToolSpec equals what full-mode tools/list emits, in registration order, and the
  catalog's family and handler; each FamilySpec equals its tools;
* the call-sensitive policy matches the runtime write decision on every sample call, and
  a seeded wrong entry (a write tool marked read, an argument-decided relay flattened to a
  write) fails with a message naming the tool, the call and both answers;
* catalog and runtime parity against the frozen behaviour baseline: the inventory's
  tools/list projection, grouped and ordered as the baseline is, passes the baseline's own
  comparator (scripts/dump_tool_baseline.py, mode l1) with no difference, and a seeded
  wrong entry shows up in that comparator's report;
* the inventory is deterministic and the runtime never imports it (registration is
  unchanged).
"""

from __future__ import annotations

import asyncio
import copy
import dataclasses
import subprocess
import sys
from typing import Any

import pytest

from scripts import dump_tool_baseline as dump
from unifi_fabric.catalog import DISCOVERY_META_TOOLS, META_FAMILY
from unifi_fabric.catalog.inventory import (
    ROUTE_DECIDED_GETS,
    STATE_CHANGING_GET_SAMPLE,
    RuntimeView,
    inventory_from,
    render_inventory,
    runtime_view,
    validate_inventory,
)
from unifi_fabric.catalog.models import (
    INVENTORY_REASONS,
    CallPolicy,
    Inventory,
    InventoryError,
    ToolSpec,
)
from unifi_fabric.families import ALL_FAMILIES, build_family_index

# One worker builds the runtime view once for the whole module.
pytestmark = pytest.mark.xdist_group("catalog-inventory")


@pytest.fixture(scope="module")
def view() -> RuntimeView:
    return asyncio.run(runtime_view())


@pytest.fixture(scope="module")
def inventory(view: RuntimeView) -> Inventory:
    return inventory_from(view)


def _replace_tool(inventory: Inventory, name: str, **changes: Any) -> Inventory:
    tools = tuple(
        dataclasses.replace(spec, **changes) if spec.name == name else spec
        for spec in inventory.tools
    )
    return dataclasses.replace(inventory, tools=tools)


def _fails(inventory: Inventory, view: RuntimeView, reason: str) -> InventoryError:
    with pytest.raises(InventoryError) as caught:
        validate_inventory(inventory, view)
    assert caught.value.reason == reason, str(caught.value)
    assert str(caught.value).startswith(f"catalog:inventory:{reason}: ")
    return caught.value


# --------------------------------------------------------------------------- membership


def test_every_registered_tool_has_exactly_one_toolspec(
    inventory: Inventory, view: RuntimeView
) -> None:
    names = [spec.name for spec in inventory.tools]
    registered = [entry["name"] for entry in view.listed]
    catalog = [row.name for row in view.catalog.tools]
    assert len(names) == len(set(names)), "a tool has more than one ToolSpec"
    assert len(names) == len(catalog) == len(registered)
    assert set(names) == set(catalog) == set(registered)
    assert set(DISCOVERY_META_TOOLS) <= set(names)


def test_only_the_three_long_reads_may_run_as_tasks(inventory: Inventory) -> None:
    from unifi_fabric.background_tasks import TASK_OPTIONAL_TOOLS

    modes = {spec.name: spec.task_mode for spec in inventory.tools}
    assert {name for name, mode in modes.items() if mode != "forbidden"} == TASK_OPTIONAL_TOOLS
    assert {modes[name] for name in TASK_OPTIONAL_TOOLS} == {"optional"}
    assert all(spec.to_dict()["task_mode"] == spec.task_mode for spec in inventory.tools)


def test_the_committed_inventory_validates(inventory: Inventory, view: RuntimeView) -> None:
    validate_inventory(inventory, view)


def test_toolspecs_are_in_registration_order(inventory: Inventory, view: RuntimeView) -> None:
    order = [entry["name"] for entry in view.listed]
    assert [spec.name for spec in inventory.tools] == order
    meta = [name for name in order if name in DISCOVERY_META_TOOLS]
    assert order[-len(meta) :] == meta, "the discovery meta tools come last"


def test_the_inventory_is_deterministic(inventory: Inventory, view: RuntimeView) -> None:
    assert render_inventory(inventory_from(view)) == render_inventory(inventory)


def test_a_missing_toolspec_fails(inventory: Inventory, view: RuntimeView) -> None:
    dropped = inventory.tools[3]
    tools = tuple(spec for spec in inventory.tools if spec is not dropped)
    error = _fails(dataclasses.replace(inventory, tools=tools), view, "missing_tool")
    assert dropped.name in str(error)


def test_a_duplicate_toolspec_fails(inventory: Inventory, view: RuntimeView) -> None:
    tools = (*inventory.tools, inventory.tools[0])
    error = _fails(dataclasses.replace(inventory, tools=tools), view, "duplicate_tool")
    assert inventory.tools[0].name in str(error)


def test_an_unknown_toolspec_fails(inventory: Inventory, view: RuntimeView) -> None:
    extra = dataclasses.replace(inventory.tools[0], name="list_unregistered_things")
    tools = (*inventory.tools, extra)
    error = _fails(dataclasses.replace(inventory, tools=tools), view, "unknown_tool")
    assert "list_unregistered_things" in str(error)


# --------------------------------------------------------------------------- fields


def test_a_changed_description_fails(inventory: Inventory, view: RuntimeView) -> None:
    seeded = _replace_tool(inventory, "list_hosts", description="List hosts.")
    error = _fails(seeded, view, "field_mismatch")
    assert "list_hosts: description differs from tools/list" in str(error)


def test_a_changed_family_fails(inventory: Inventory, view: RuntimeView) -> None:
    seeded = _replace_tool(inventory, "list_hosts", family="network")
    error = _fails(seeded, view, "family_mismatch")
    assert "list_hosts: family is 'network', catalog.json has 'site_manager'" in str(error)


def test_handlers_and_families_follow_the_catalog(inventory: Inventory, view: RuntimeView) -> None:
    catalog = view.catalog.by_name()
    for spec in inventory.tools:
        assert spec.family == catalog[spec.name].family, spec.name
        assert spec.handler == catalog[spec.name].handler, spec.name


def test_familyspecs_partition_the_inventory(inventory: Inventory) -> None:
    assert [family.id for family in inventory.families] == [*ALL_FAMILIES, META_FAMILY]
    owners: dict[str, str] = {}
    for family in inventory.families:
        assert family.tools, family.id
        assert family.loader, family.id
        assert family.id not in family.dependencies
        assert family.selectable == (family.id != META_FAMILY)
        for name in family.tools:
            assert name not in owners, f"{name} is in {owners.get(name)} and {family.id}"
            owners[name] = family.id
    assert owners == {spec.name: spec.family for spec in inventory.tools}
    for spec in inventory.tools:
        assert spec.loader in inventory.family(spec.family).loader, spec.name


def test_firewall_loads_through_its_own_steps(inventory: Inventory) -> None:
    # The firewall tools register in families/firewall; their handlers are still network
    # modules, so firewall still depends on network.
    firewall = inventory.family("firewall")
    assert firewall.loader
    assert all(
        ref.startswith("unifi_fabric.families.firewall.registrar:") for ref in firewall.loader
    )
    assert "network" in firewall.dependencies


# --------------------------------------------------------------------------- policy


def test_seeded_write_marked_read_fails_clearly(inventory: Inventory, view: RuntimeView) -> None:
    """A write tool given a read policy is refused by the runtime write decision."""
    assert inventory.by_name()["create_network"].policy.access == "write"
    seeded = _replace_tool(inventory, "create_network", policy=CallPolicy(access="read"))
    error = _fails(seeded, view, "policy_mismatch")
    assert str(error) == (
        "catalog:inventory:policy_mismatch: create_network: the inventory says a call with "
        "arguments {} is a read, but the runtime write decision (request_policy.decide "
        "under UNIFI_WRITE_POLICY=deny) refuses it as a write"
    )


def test_flattening_the_get_relay_to_a_write_fails(inventory: Inventory, view: RuntimeView) -> None:
    """The GET relay's access depends on its path; a flat label is wrong for one call."""
    relay = inventory.by_name()["fabric_connector_get"]
    flat = dataclasses.replace(relay.policy, access="write", rule=None, decided_by=())
    error = _fails(_replace_tool(inventory, relay.name, policy=flat), view, "policy_mismatch")
    assert "fabric_connector_get: the inventory says a call with arguments {} is a write" in str(
        error
    )
    assert "lets it through as a read" in str(error)


def test_a_wrong_derived_field_fails(inventory: Inventory, view: RuntimeView) -> None:
    spec = inventory.by_name()["update_device_radio"]
    wrong = dataclasses.replace(spec.policy, write_families=("devices",))
    error = _fails(_replace_tool(inventory, spec.name, policy=wrong), view, "policy_mismatch")
    assert "update_device_radio: write_families is ['devices'], the derivation gives" in str(error)


def test_argument_decided_tools(inventory: Inventory) -> None:
    by_name = inventory.by_name()
    decided = {spec.name for spec in inventory.tools if spec.policy.access == "by_argument"}
    assert decided == ROUTE_DECIDED_GETS | {"call_read_tool", "call_write_tool"}
    relay = by_name["fabric_connector_get"].policy
    assert (relay.rule, relay.decided_by) == ("state_changing_get_route", ("path",))
    resolve = inventory.resolver()
    assert relay.writes({"path": STATE_CHANGING_GET_SAMPLE}, resolve) is True
    assert relay.writes({"path": "/proxy/network/integration/v1/sites"}, resolve) is False
    for name in ("call_read_tool", "call_write_tool"):
        policy = by_name[name].policy
        assert (policy.rule, policy.decided_by) == ("dispatch_target", ("name", "arguments"))
        assert policy.target_argument == "name"
        assert policy.writes({"name": "create_network", "arguments": {}}, resolve) is True
        assert policy.writes({"name": "list_hosts", "arguments": {}}, resolve) is False
    assert by_name["describe_tool"].policy.access == "read"
    assert by_name["describe_tool"].policy.target_argument == "name"


def test_confirm_and_dry_run_follow_the_schemas(inventory: Inventory) -> None:
    for spec in inventory.tools:
        properties = dict(spec.input_schema.get("properties") or {})
        policy = spec.policy
        assert policy.confirmation_required is False, spec.name
        assert (policy.confirm_argument == "ignored") == ("confirm" in properties), spec.name
        if policy.dry_run_argument is not None:
            assert "dry_run" in properties and policy.access == "write", spec.name


def test_read_tools_carry_no_write_facts(inventory: Inventory) -> None:
    for spec in inventory.tools:
        if spec.policy.access == "read":
            assert spec.annotations["readOnlyHint"] is True, spec.name
            assert spec.policy.write_verbs == () and spec.policy.write_families == ()


def test_write_families_are_per_tool(inventory: Inventory) -> None:
    """The connector write switch also reaches some typed writes of other families."""
    network_writes = [
        spec
        for spec in inventory.tools
        if spec.family == "network" and spec.policy.access == "write"
    ]
    reach = {spec.policy.write_families for spec in network_writes}
    assert ("network",) in reach and ("network", "connector") in reach
    for spec in network_writes:
        assert spec.policy.write_families[0] == "network", spec.name


def test_a_malformed_policy_is_refused() -> None:
    with pytest.raises(InventoryError, match="invalid_spec: a rule is set exactly when"):
        CallPolicy(access="by_argument")
    with pytest.raises(InventoryError, match="a write issues at least one write verb"):
        CallPolicy(access="write")
    assert INVENTORY_REASONS[0] == "invalid_spec"


# --------------------------------------------------------------------------- baseline parity


def _as_baseline(inventory: Inventory) -> dump.Baseline:
    """The committed baseline with every family's tools and the order taken from the
    inventory: its full-mode ToolSpecs, grouped by the baseline's family index."""
    full = [spec.listed() for spec in inventory.tools if spec.name not in DISCOVERY_META_TOOLS]
    grouped = dump.split_by_family(full, build_family_index())
    head = copy.deepcopy(dump.read_baseline_dir(dump.BASELINE_DIR))
    for family in ALL_FAMILIES:
        head[f"{family}.json"]["tools"] = grouped[family]
    head[dump.ORDER_FILE] = [entry["name"] for entry in full]
    return head


def test_inventory_matches_the_behaviour_baseline(inventory: Inventory) -> None:
    """Catalog and runtime parity: no difference the l1 (location-only) mode would refuse."""
    committed = dump.read_baseline_dir(dump.BASELINE_DIR)
    problems = dump.compare(committed, _as_baseline(inventory), "l1")
    assert problems == [], dump.report(problems)
    in_baseline = sum(len(committed[f"{family}.json"]["tools"]) for family in ALL_FAMILIES)
    assert in_baseline == len(committed[dump.ORDER_FILE])
    assert in_baseline == len(inventory.tools) - len(DISCOVERY_META_TOOLS)


def test_a_seeded_inventory_change_shows_in_the_baseline_comparator(
    inventory: Inventory,
) -> None:
    spec = inventory.by_name()["get_host"]
    flipped = dict(spec.annotations, readOnlyHint=False)
    seeded = _replace_tool(inventory, "get_host", annotations=flipped)
    problems = dump.compare(dump.read_baseline_dir(dump.BASELINE_DIR), _as_baseline(seeded), "l1")
    expected = "site_manager.json: tools[get_host].annotations.readOnlyHint: true -> false"
    assert problems == [expected]


# --------------------------------------------------------------------------- no behaviour change


def test_the_runtime_never_imports_the_inventory() -> None:
    probe = (
        "import sys, unifi_fabric.server\n"
        "print(sorted(m for m in sys.modules if m.startswith('unifi_fabric.catalog.')))"
    )
    out = subprocess.run(  # noqa: S603 - this interpreter, a fixed import probe
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    # The loader map and the deferred loader (public #41) are the runtime registration
    # path, and the explicit inventory (membership) the runtime family source; the
    # ToolSpec inventory and models are not.
    assert out.stdout.strip() == (
        "['unifi_fabric.catalog.deferred', 'unifi_fabric.catalog.loaders', "
        "'unifi_fabric.catalog.membership']"
    )


def test_toolspec_listed_shape(inventory: Inventory) -> None:
    spec: ToolSpec = inventory.by_name()["list_hosts"]
    assert list(spec.listed()) == [
        "name",
        "description",
        "inputSchema",
        "outputSchema",
        "annotations",
        "title",
        "_meta",
    ]
    assert list(spec.listed()) == list(dump.ENTRY_KEYS + dump.EXTRA_ENTRY_KEYS)
    from unifi_fabric.catalog.loaders import LOADERS

    step = next(e for e in LOADERS if e.family == "site_manager" and e.origin == "site_manager")
    assert spec.loader == step.ref  # site_manager.site_manager:register before its move
