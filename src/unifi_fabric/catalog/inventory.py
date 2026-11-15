"""The deterministic catalog inventory: one :class:`ToolSpec` per registered tool.

:func:`build_inventory` reads the registered server and returns an
:class:`~unifi_fabric.catalog.models.Inventory`: every public tool once, in registration
order, and one :class:`~unifi_fabric.catalog.models.FamilySpec` per family.
:func:`validate_inventory` checks an inventory against the runtime and the committed
catalog and raises :class:`~unifi_fabric.catalog.models.InventoryError` with the first
reason that applies (:data:`~unifi_fabric.catalog.models.INVENTORY_REASONS`).

Generation and test time only. Building imports the server, as
:mod:`unifi_fabric.catalog_build` does, so the runtime never imports this module, and
registration is unchanged: the server registers through the loader map.

Where each field comes from (none is hand-set):

* name, title, description, schemas, annotations and ``_meta``: ``tools/list`` as an MCP
  client receives it (:func:`listing_session`), full mode, and discovery mode for the
  five discovery meta tools;
* family and handler: the committed catalog (``catalog.json``);
* loader: the registration step whose nested function the tool registered, which must be
  an entry of the explicit loader map (:data:`unifi_fabric.catalog.loaders.LOADERS`);
* family dependencies: declared in the loader map
  (:data:`unifi_fabric.catalog.loaders.FAMILY_DEPENDENCIES`), not scanned from imports;
* policy (:func:`derive_policy`): the source verb audit
  (:func:`unifi_fabric._read_only_audit.write_verbs_for`) for read versus write; the
  runtime's two argument-decided cases (:data:`ROUTE_DECIDED_GETS`, the discovery
  dispatchers); the registered schema for ``confirm`` and ``dry_run``; and
  :func:`unifi_fabric.switches.governing_families` for the write exceptions.

The policy check does not trust that derivation: :func:`validate_inventory` runs the
runtime's own write decision (:func:`unifi_fabric.request_policy.decide` under
``UNIFI_WRITE_POLICY=deny``) for every tool over :func:`sample_arguments`, and every
answer must match what the spec's policy predicts.

``python -m unifi_fabric.catalog.inventory --check`` builds and validates the inventory
and prints a summary; ``--json`` prints the inventory itself.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import sys
from collections.abc import AsyncIterator, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..background_tasks import task_mode
from . import DISCOVERY_META_TOOLS, META_FAMILY, Catalog, _thaw, load_catalog
from .models import (
    LISTED_KEYS,
    LISTED_OPTIONAL_KEYS,
    CallPolicy,
    FamilySpec,
    Inventory,
    InventoryError,
    ToolSpec,
)

#: The tools whose GET is a write only on a route the upstream acts on: the generic GET
#: relay, which :func:`unifi_fabric.read_only_tools.is_write_tool_call` judges by its
#: ``path`` argument. :func:`validate_inventory` proves this set against the runtime.
ROUTE_DECIDED_GETS: frozenset[str] = frozenset({"fabric_connector_get"})

#: A GET route the upstream acts on (Protect camera control), and a plain read route.
STATE_CHANGING_GET_SAMPLE = "/proxy/protect/api/cameras/inventory-sample/enable-control"
READ_GET_SAMPLE = "/proxy/network/integration/v1/sites"

#: The environment prefixes of the server's settings, set aside for a listing session.
_SETTINGS = ("UNIFI_", "MCP_")

#: ``(name, arguments) -> bool``: the runtime refuses this call as a write.
RuntimeWrites = Callable[[str, Mapping[str, Any]], bool]


@dataclass(frozen=True)
class RuntimeView:
    """What the registered server shows: the facts an inventory is derived from and
    checked against.

    ``listed`` is each tool's ``tools/list`` entry as a client receives it, in list order
    (full mode, then the discovery meta tools); ``tools``
    the registered FastMCP tool objects by name; ``verbs`` the source-audited write verbs;
    ``confirm_stripped`` whether the server drops ``confirm`` before validation;
    ``runtime_writes`` the runtime write decision (:func:`runtime_decision`).
    """

    listed: tuple[Mapping[str, Any], ...]
    tools: Mapping[str, Any]
    catalog: Catalog
    verbs: Mapping[str, frozenset[str]]
    confirm_stripped: bool
    runtime_writes: RuntimeWrites


def _entry(tool: Any) -> dict[str, Any]:
    """A ``tools/list`` entry as the MCP client receives it."""
    return tool.model_dump(by_alias=True, exclude_none=True)


def _tool_verbs(tool: Any) -> frozenset[str]:
    """The write verbs the source audit derives (the discovery tools' own rule for them).

    The discovery tools write only through ``call_write_tool``, as the catalog's
    derivation records (:func:`unifi_fabric.catalog_build.derivation`).
    """
    from .._read_only_audit import write_verbs_for

    if tool.name in DISCOVERY_META_TOOLS:
        return frozenset({"POST"}) if tool.name == "call_write_tool" else frozenset()
    return frozenset(write_verbs_for(tool.fn))


def runtime_decision(tools: Mapping[str, Any]) -> RuntimeWrites:
    """The runtime write decision over ``tools``: does the request policy refuse a call as
    a write under ``UNIFI_WRITE_POLICY=deny``? Its step (6) path, unchanged
    (:func:`unifi_fabric.request_policy.decide` with the evaluator's ``is_write``)."""
    from .. import policy as sp
    from .. import request_policy as rp

    catalog = rp.catalog_from_tools(tools.values())
    deny = sp.operator_policy({sp.WRITE_POLICY_ENV: "deny"}, catalog)
    evaluator = rp.RequestPolicy(lambda: tools)

    def writes(name: str, arguments: Mapping[str, Any]) -> bool:
        code, _message, _mode = rp.decide(
            name=name,
            arguments=arguments,
            policy=deny,
            catalog=catalog,
            is_write=evaluator.is_write,
        )
        return code == rp.WRITE_DENIED

    return writes


@contextlib.asynccontextmanager
async def listing_session(mode: str) -> AsyncIterator[Any]:
    """One in-process MCP client session on the server, in tool ``mode``.

    The session runs the server's startup as a deployment does, and lists what a client
    is sent. The ambient ``UNIFI_*``/``MCP_*`` settings are set aside for it, so the
    inventory never depends on the machine that builds it, and the server starts in header
    key mode: no API key is configured, read or sent. Both are restored afterwards.
    """
    from fastmcp import Client

    from .. import server

    saved = {name: value for name, value in os.environ.items() if name.startswith(_SETTINGS)}
    settings = server._settings  # noqa: SLF001 - the cached startup settings, restored below
    for name in saved:
        del os.environ[name]
    os.environ["UNIFI_TOOL_MODE"] = mode
    os.environ["UNIFI_KEY_MODE"] = "header"
    server._settings = None  # noqa: SLF001 - read this session's settings at startup
    try:
        async with Client(server.mcp) as client:
            yield client
    finally:
        for name in [name for name in os.environ if name.startswith(_SETTINGS)]:
            del os.environ[name]
        os.environ.update(saved)
        server._settings = settings  # noqa: SLF001 - restore the cached startup settings


async def client_listing() -> list[dict[str, Any]]:
    """Every tool's ``tools/list`` entry as an MCP client receives it, in list order: full
    mode, then the five discovery meta tools (discovery mode), each through a
    :func:`listing_session`. The committed catalog's schemas are generated from it."""
    async with listing_session("full") as client:
        listed = [_entry(tool) for tool in await client.list_tools()]
    async with listing_session("discovery") as client:
        listed += [
            _entry(tool) for tool in await client.list_tools() if tool.name in DISCOVERY_META_TOOLS
        ]
    return listed


async def runtime_view() -> RuntimeView:
    """Read the registered server: full-mode ``tools/list``, then the discovery meta tools
    (discovery mode), each through a :func:`listing_session`."""
    from ..confirm_compat import ConfirmIgnoredMiddleware
    from ..server import mcp
    from .deferred import load_all

    # Every step is loaded first: the view reads each tool's ``fn`` (public #41).
    load_all(mcp)

    async with listing_session("full") as client:
        listed = [_entry(tool) for tool in await client.list_tools()]
        local = {tool.name: tool for tool in await mcp.list_tools(run_middleware=False)}
    async with listing_session("discovery") as client:
        meta_listed = [
            _entry(tool) for tool in await client.list_tools() if tool.name in DISCOVERY_META_TOOLS
        ]
        meta_local = {
            tool.name: tool
            for tool in await mcp.list_tools(run_middleware=False)
            if tool.name in DISCOVERY_META_TOOLS
        }
    confirm_stripped = any(isinstance(m, ConfirmIgnoredMiddleware) for m in mcp.middleware)
    tools = {**local, **meta_local}
    return RuntimeView(
        listed=tuple([*listed, *meta_listed]),
        tools=tools,
        catalog=load_catalog(),
        verbs={name: _tool_verbs(tool) for name, tool in tools.items()},
        confirm_stripped=confirm_stripped,
        runtime_writes=runtime_decision(tools),
    )


def loader_ref(fn: Any) -> str:
    """``<module>:<function>`` of the registration step that registered ``fn``.

    A wrapper nested in ``register`` (or ``register_2``, ...) names that function; a
    module-level tool function names itself.
    """
    qualname = str(fn.__qualname__)
    return f"{fn.__module__}:{qualname.split('.<locals>', 1)[0]}"


def derive_policy(
    name: str,
    *,
    family: str,
    verbs: Iterable[str],
    input_schema: Mapping[str, Any],
    confirm_stripped: bool,
) -> CallPolicy:
    """The call-sensitive policy of one tool, from source and runtime tables only."""
    from ..request_policy import DISPATCH_TOOLS, TARGETED_META_TOOLS
    from ..switches import governing_families

    write_verbs = tuple(sorted(verbs))
    rule: Any = None
    decided_by: tuple[str, ...] = ()
    if name in ROUTE_DECIDED_GETS:
        access: Any = "by_argument"
        rule, decided_by = "state_changing_get_route", ("path",)
    elif name in DISPATCH_TOOLS:
        access = "by_argument"
        rule, decided_by = "dispatch_target", ("name", "arguments")
    else:
        access = "write" if write_verbs else "read"
    properties = input_schema.get("properties") or {}
    required = input_schema.get("required") or ()
    confirm_declared = "confirm" in properties
    # A dispatcher's writes are its target's; only a tool that writes itself carries them.
    writes_itself = access == "write" or rule == "state_changing_get_route"
    return CallPolicy(
        access=access,
        write_verbs=write_verbs if access != "read" else (),
        rule=rule,
        decided_by=decided_by,
        target_argument="name" if name in TARGETED_META_TOOLS else None,
        confirmation_required="confirm" in required and not confirm_stripped,
        confirm_argument="ignored" if confirm_declared and confirm_stripped else "absent",
        dry_run_argument="dry_run" if writes_itself and "dry_run" in properties else None,
        write_families=governing_families(name, family) if writes_itself else (),
    )


def _dependencies(family: str) -> tuple[str, ...]:
    """The family's declared dependencies (the loader map)."""
    from .loaders import FAMILY_DEPENDENCIES

    return tuple(FAMILY_DEPENDENCIES.get(family, ()))


def _family_ids() -> list[str]:
    from ..families import ALL_FAMILIES

    return [*ALL_FAMILIES, META_FAMILY]


def _family_spec(family: str, specs: Sequence[ToolSpec]) -> FamilySpec:
    tools = tuple(spec.name for spec in specs if spec.family == family)
    loader = tuple(dict.fromkeys(spec.loader for spec in specs if spec.family == family))
    return FamilySpec(
        id=family,
        tools=tools,
        dependencies=_dependencies(family),
        loader=loader,
        selectable=family != META_FAMILY,
    )


def inventory_from(view: RuntimeView) -> Inventory:
    """The inventory of ``view``: deterministic for a given registration."""
    catalog = view.catalog.by_name()
    specs: list[ToolSpec] = []
    for listed in view.listed:
        name = listed["name"]
        row = catalog.get(name)
        if row is None:
            raise InventoryError("missing_tool", f"{name}: registered but not in catalog.json")
        input_schema = listed.get("inputSchema") or {}
        specs.append(
            ToolSpec.build(
                name=name,
                family=row.family,
                title=listed.get("title"),
                description=listed.get("description") or "",
                input_schema=input_schema,
                output_schema=listed.get("outputSchema"),
                annotations=listed.get("annotations") or {},
                meta=listed.get("_meta"),
                handler=row.handler,
                loader=loader_ref(view.tools[name].fn),
                policy=derive_policy(
                    name,
                    family=row.family,
                    verbs=view.verbs[name],
                    input_schema=input_schema,
                    confirm_stripped=view.confirm_stripped,
                ),
                task_mode=task_mode(name),
            )
        )
    families = tuple(_family_spec(family, specs) for family in _family_ids())
    return Inventory(tools=tuple(specs), families=families)


def build_inventory() -> Inventory:
    """Build the inventory from the registered server (outside a running event loop)."""
    return inventory_from(asyncio.run(runtime_view()))


def render_inventory(inventory: Inventory) -> str:
    """The deterministic JSON text of an inventory."""
    return json.dumps(inventory.to_dict(), indent=1, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- validation


def sample_arguments(view: RuntimeView) -> tuple[Mapping[str, Any], ...]:
    """The calls every tool's policy is checked on.

    Each argument a runtime write decision reads, both ways: no arguments, a ``confirm``
    and a ``dry_run``, a relay ``path`` that reads and one the upstream acts on, and a
    dispatcher ``name`` naming a read, a write and the GET relay on both routes.
    """
    from .. import read_only

    if not read_only.is_write_request("GET", STATE_CHANGING_GET_SAMPLE):
        raise RuntimeError("STATE_CHANGING_GET_SAMPLE is no longer a state-changing GET route")
    if read_only.is_write_request("GET", READ_GET_SAMPLE):
        raise RuntimeError("READ_GET_SAMPLE is no longer a read route")
    rows = sorted(view.catalog.tools, key=lambda row: row.id)
    domain = [r for r in rows if r.family != META_FAMILY and r.name not in ROUTE_DECIDED_GETS]
    read_target = next(r.name for r in domain if r.read_only)
    write_target = next(r.name for r in domain if not r.read_only)
    relay = min(ROUTE_DECIDED_GETS)
    return (
        {},
        {"confirm": True},
        {"dry_run": True},
        {"path": READ_GET_SAMPLE},
        {"path": STATE_CHANGING_GET_SAMPLE},
        {"name": read_target, "arguments": {}},
        {"name": write_target, "arguments": {"confirm": True}},
        {"name": relay, "arguments": {"path": READ_GET_SAMPLE}},
        {"name": relay, "arguments": {"path": STATE_CHANGING_GET_SAMPLE}},
    )


def _first_duplicate(names: Iterable[str]) -> str | None:
    seen: set[str] = set()
    for name in names:
        if name in seen:
            return name
        seen.add(name)
    return None


def _policy_diff(have: CallPolicy, want: CallPolicy) -> str:
    a, b = have.to_dict(), want.to_dict()
    return "; ".join(f"{k} is {a[k]!r}, the derivation gives {b[k]!r}" for k in a if a[k] != b[k])


def _check_membership(inventory: Inventory, view: RuntimeView) -> None:
    families = set(_family_ids())
    for spec in inventory.tools:
        problem = spec.policy.problem()
        if problem:
            raise InventoryError("invalid_spec", f"{spec.name}: {problem}")
        if spec.family not in families:
            raise InventoryError("invalid_spec", f"{spec.name}: unknown family {spec.family!r}")
    duplicate = _first_duplicate(spec.name for spec in inventory.tools)
    if duplicate:
        raise InventoryError("duplicate_tool", f"{duplicate}: has more than one ToolSpec")
    names = [spec.name for spec in inventory.tools]
    have = set(names)
    listed = [entry["name"] for entry in view.listed]
    catalog_names = [row.name for row in view.catalog.tools]
    for name in listed:
        if name not in have:
            raise InventoryError("missing_tool", f"{name}: registered but has no ToolSpec")
    for name in catalog_names:
        if name not in have:
            raise InventoryError("missing_tool", f"{name}: in catalog.json but has no ToolSpec")
    for name in names:
        if name not in set(listed):
            raise InventoryError("unknown_tool", f"{name}: has a ToolSpec but is not registered")
        if name not in set(catalog_names):
            raise InventoryError(
                "unknown_tool", f"{name}: has a ToolSpec but is not in catalog.json"
            )
    if not len(names) == len(listed) == len(catalog_names):
        raise InventoryError(
            "missing_tool",
            f"{len(names)} ToolSpecs, {len(listed)} registered tools, "
            f"{len(catalog_names)} catalog tools",
        )


def _check_fields(inventory: Inventory, view: RuntimeView) -> None:
    if [spec.name for spec in inventory.tools] != [entry["name"] for entry in view.listed]:
        raise InventoryError("field_mismatch", "ToolSpecs are not in registration order")
    from .loaders import refs

    by_name = inventory.by_name()
    catalog = view.catalog.by_name()
    mapped = set(refs())
    for entry in view.listed:
        spec = by_name[entry["name"]]
        unknown = sorted(set(entry) - {*LISTED_KEYS, *LISTED_OPTIONAL_KEYS})
        if unknown:
            raise InventoryError(
                "field_mismatch",
                f"{spec.name}: tools/list emits {', '.join(unknown)}, which a ToolSpec does "
                "not carry",
            )
        listed = spec.listed()
        for key in (*LISTED_KEYS, *LISTED_OPTIONAL_KEYS):
            if listed.get(key) != entry.get(key):
                raise InventoryError(
                    "field_mismatch", f"{spec.name}: {key} differs from tools/list"
                )
        if spec.handler != catalog[spec.name].handler:
            raise InventoryError(
                "field_mismatch", f"{spec.name}: handler differs from catalog.json"
            )
        step = loader_ref(view.tools[spec.name].fn)
        if spec.loader != step:
            raise InventoryError(
                "field_mismatch",
                f"{spec.name}: loader is {spec.loader!r}, the registration step is {step!r}",
            )
        if spec.family != META_FAMILY and spec.loader not in mapped:
            raise InventoryError(
                "field_mismatch",
                f"{spec.name}: its registration step {spec.loader!r} is not in the loader map",
            )


def _check_families(inventory: Inventory, view: RuntimeView) -> None:
    catalog = view.catalog.by_name()
    for spec in inventory.tools:
        expected = catalog[spec.name].family
        if spec.family != expected:
            raise InventoryError(
                "family_mismatch",
                f"{spec.name}: family is {spec.family!r}, catalog.json has {expected!r}",
            )
    ids = [family.id for family in inventory.families]
    if ids != _family_ids():
        raise InventoryError("family_mismatch", f"FamilySpecs {ids} are not the 13 families + meta")
    for family in inventory.families:
        want = _family_spec(family.id, inventory.tools).to_dict()
        wrong = [key for key, value in family.to_dict().items() if value != want[key]]
        if wrong:
            raise InventoryError(
                "family_mismatch", f"family {family.id}: {', '.join(wrong)} differ from its tools"
            )


def _check_policy(inventory: Inventory, view: RuntimeView) -> None:
    resolve = inventory.resolver()
    samples = sample_arguments(view)
    for spec in inventory.tools:
        outcomes: set[bool] = set()
        for arguments in samples:
            predicted = spec.policy.writes(arguments, resolve)
            actual = view.runtime_writes(spec.name, arguments)
            if predicted != actual:
                # One of this module's own sample calls, never upstream data.
                call = json.dumps(dict(arguments), sort_keys=True)
                raise InventoryError(
                    "policy_mismatch",
                    f"{spec.name}: the inventory says a call with arguments {call} is a "
                    f"{'write' if predicted else 'read'}, but the runtime write decision "
                    "(request_policy.decide under UNIFI_WRITE_POLICY=deny) "
                    f"{'refuses it as a write' if actual else 'lets it through as a read'}",
                )
            outcomes.add(actual)
        if spec.policy.access == "by_argument" and outcomes != {True, False}:
            raise InventoryError(
                "policy_mismatch",
                f"{spec.name}: access is by_argument, but no sampled call changes the "
                "runtime write decision",
            )
        hint = bool(_thaw(spec.annotations).get("readOnlyHint"))
        if spec.policy.access != "by_argument" and hint != (spec.policy.access == "read"):
            raise InventoryError(
                "policy_mismatch",
                f"{spec.name}: access is {spec.policy.access!r}, but tools/list advertises "
                f"readOnlyHint={str(hint).lower()}",
            )
        derived = derive_policy(
            spec.name,
            family=spec.family,
            verbs=view.verbs[spec.name],
            input_schema=_thaw(spec.input_schema),
            confirm_stripped=view.confirm_stripped,
        )
        if spec.policy != derived:
            raise InventoryError(
                "policy_mismatch", f"{spec.name}: {_policy_diff(spec.policy, derived)}"
            )


def validate_inventory(inventory: Inventory, view: RuntimeView) -> None:
    """Raise :class:`InventoryError` with the first reason that applies, in order.

    invalid_spec; duplicate_tool, missing_tool and unknown_tool (every registered and
    every catalog tool has exactly one ToolSpec, and the three counts agree);
    field_mismatch (each spec equals ``tools/list``, the catalog's handler and its
    registration step, in registration order); family_mismatch (the catalog's family,
    and each FamilySpec equals its tools); policy_mismatch (the runtime write decision on
    every sample call, the advertised readOnlyHint, then the source derivation).
    """
    _check_membership(inventory, view)
    _check_fields(inventory, view)
    _check_families(inventory, view)
    _check_policy(inventory, view)


def summary(inventory: Inventory, view: RuntimeView) -> str:
    """The report ``--check`` prints."""
    full = sum(1 for entry in view.listed if entry["name"] not in DISCOVERY_META_TOOLS)
    policies = [spec.policy for spec in inventory.tools]
    by_argument = [spec.name for spec in inventory.tools if spec.policy.access == "by_argument"]
    families = ", ".join(f"{family.id} {len(family.tools)}" for family in inventory.families)
    return "\n".join(
        [
            f"inventory: {len(inventory.tools)} ToolSpecs, catalog.json {len(view.catalog.tools)}, "
            f"registered {len(view.listed)} (full-mode tools/list {full} + "
            f"{len(view.listed) - full} discovery meta tools); none missing, duplicate or unknown",
            f"families ({len(inventory.families)}): {families}",
            f"policy: read {sum(p.access == 'read' for p in policies)}, "
            f"write {sum(p.access == 'write' for p in policies)}, "
            f"by_argument {len(by_argument)} ({', '.join(by_argument)}); "
            f"confirm ignored on {sum(p.confirm_argument == 'ignored' for p in policies)}, "
            f"confirmation required on {sum(p.confirmation_required for p in policies)}; "
            f"dry_run argument on {sum(p.dry_run_argument is not None for p in policies)}",
            f"runtime write decision matched: {len(inventory.tools)} tools x "
            f"{len(sample_arguments(view))} sample calls",
        ]
    )


def main(argv: Sequence[str] | None = None) -> int:
    """``--check``: validate and print the summary (the default); ``--json``: print it."""
    parser = argparse.ArgumentParser(prog="python -m unifi_fabric.catalog.inventory")
    parser.add_argument("--check", action="store_true", help="validate and print a summary")
    parser.add_argument("--json", action="store_true", help="print the inventory as JSON")
    args = parser.parse_args(argv)
    view = asyncio.run(runtime_view())
    inventory = inventory_from(view)
    if args.json:
        sys.stdout.write(render_inventory(inventory))
    if args.check or not args.json:
        try:
            validate_inventory(inventory, view)
        except InventoryError as exc:
            print(exc, file=sys.stderr)
            return 1
        print(summary(inventory, view))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
