#!/usr/bin/env python3
"""Generate selected catalog-size figures in README.md and CHANGELOG.md.

The catalog keeps growing, so these generated figures are never hand-edited. This script
measures the running server and rewrites these figures in place:

* the README blocks it owns in the block registry (``BLOCKS`` in scripts/doc_blocks.py):
  ``catalog-headline`` and ``how-it-works-catalog`` (the registered tool count) and
  ``verification-status`` (the CI tool count and the docs/COVERAGE.md live evidence). It
  rewrites nothing else in the README but the installation versions: prose outside a
  generated block is free, and a missing or broken block fails the run;
* the registered tool count in the current CHANGELOG release section (Highlights and the
  catalog-size note);
* the docs/CATALOG.md family table: tool count and ``tools/list`` size per listed
  ``UNIFI_FAMILY_ALLOW`` value (UTF-8 JSON-RPC response line, 1 KB = 1000 bytes);
* the docs/CONFIGURATION.md family-count table: tools and write tools of each family
  (``families.ALL_FAMILIES``; a missing or extra row fails the run). Covers text is editorial;
* the docs/CONFIGURATION.md opt-out table: write tools
  hidden and tools listed under each per-area
  ``UNIFI_WRITE_EXCEPTIONS`` deny entry and ``UNIFI_WRITE_POLICY=deny``, from the startup
  selection functions themselves;
* no domain table: ``DOMAINS`` below still classifies every registered tool into exactly one
  domain (an unclassified tool fails the run), and the counts must sum to the catalog;
* the docs/CATALOG.md mode table: advertised tools, domain tools available and exact compact
  ``tools/list`` result bytes for ``UNIFI_TOOL_MODE=full`` and ``discovery``;
* the pinned-spec body-shape figures (shaped count, free-form count, compact bytes), in
  docs/CATALOG.md, the CHANGELOG and docs/MIGRATING-0.7.md;
* the installation versions (package pins, image tags, release bundle links and the encoded
  install-badge pins) in README.md, docs/DOCKER.md and the Claude Desktop bundle README;
* the catalog and ignored-confirm parameter counts in docs/COVERAGE.md;
* the read-only and write annotation counts in CHANGELOG and the migration guide;
* the official-only figures, wherever AGENTS.md, llms.txt and docs/CONFIGURATION.md state
  them: the tools that remain and are excluded in full mode
  under the official-only recipe ``UNIFI_EXCLUDE=unofficial,source:relay``
  (``OFFICIAL_ONLY_EXCLUDE``), the same with ``UNIFI_WRITE_POLICY=deny``, and the generic
  relays that ``unofficial`` alone keeps. The run fails if any tool the recipe leaves
  listed calls an API source other than an official one or ``server/local``;
* docs/site-stats.json, the release figures the project website reads (scripts/site_stats.py:
  registered tool count, live-verified count from docs/COVERAGE.md, their difference as the
  unit-tested count, and the release tag).

Measurement matches tests/test_readme_catalog_size.py: the package entry point is
started over stdio with a placeholder key, sent ``initialize`` and ``tools/list``,
and the reply is counted. The families listed in the catalog table are an editorial
choice and are kept; only their figures are regenerated.

A CHANGELOG section whose heading carries a date has shipped: the generator leaves it
untouched, so no restore step is needed after a run on a released tree.

Usage:
    python3 scripts/gen_catalog_figures.py          # rewrite the figures in place
    python3 scripts/gen_catalog_figures.py --check  # exit 1 if any figure is stale (CI)

``python3 scripts/regen_docs.py`` runs this generator together with the other documentation
generators.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tomllib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Installation examples track the published release until the next release ships.
PUBLISHED_VERSION = (ROOT / "scripts" / "published-version.txt").read_text().strip()
README = ROOT / "README.md"
CHANGELOG = ROOT / "CHANGELOG.md"
MIGRATING = ROOT / "docs" / "MIGRATING-0.7.md"
COVERAGE = ROOT / "docs" / "COVERAGE.md"
CONFIGURATION = ROOT / "docs" / "CONFIGURATION.md"
AGENTS = ROOT / "AGENTS.md"
LLMS = ROOT / "llms.txt"
CATALOG = ROOT / "docs" / "CATALOG.md"
DOCKER = ROOT / "docs" / "DOCKER.md"
BUNDLE_README = ROOT / "plugins" / "claude-desktop" / "README.md"
SITE_STATS = ROOT / "docs" / "site-stats.json"

FAMILY_TABLE_HEADER = "| `UNIFI_FAMILY_ALLOW` | Tools | `tools/list` size |"
MODE_TABLE_HEADER = (
    "| `UNIFI_TOOL_MODE` | Advertised tools | Domain tools available | "
    "`tools/list` bytes | Size (1 KB = 1000 bytes) |"
)
FAMILY_COUNT_HEADER = "| Family | Tools | Write tools | Covers |"
_FAMILY_COUNT_ROW_RE = re.compile(r"^\| `([a-z_]+)` \| \d+ \| \d+ \| (.*) \|$", re.M)
SWITCH_TABLE_HEADER = "| Setting | Write tools hidden | Tools listed |"
_SWITCH_ROW_RE = re.compile(
    r"^\| (none \(default\)|`(UNIFI_[A-Z_]+=[a-z:=_-]+)`) \| \d+ \| \d+ \|$", re.M
)
_FAMILY_ROW_RE = re.compile(
    r"^\| (unset \(all families\)|`([a-z_,]+)`) \| (\d+) \| ~(\d+) KB \|$", re.M
)
_MODE_ROW_RE = re.compile(
    r"^\| `(full|discovery)`( \(default\))? \| \d+ \| \d+ \| \d+ \| ~\d+ KB \|$", re.M
)
DOMAIN_TABLE_HEADER = "| Domain | Domain tools available | Purpose |"
_RELEASE_RE = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.M)
#: A released (shipped) CHANGELOG heading: ``## [X.Y.Z] - YYYY-MM-DD``.
_DATED_RE = re.compile(r"^## \[\d+\.\d+\.\d+\] - \d{4}-\d{2}-\d{2}", re.M)
#: The documented official-only recipe. ``unofficial`` alone keeps the generic relays
#: (``relay/generic``, API status ``local``), which can reach private routes.
OFFICIAL_ONLY_EXCLUDE = "unofficial,source:relay"
#: The official-only figures (README.md, AGENTS.md, llms.txt, docs/CONFIGURATION.md): full
#: mode, and (``OFFICIAL_ONLY_DENY_RE``) the same under ``UNIFI_WRITE_POLICY=deny``.
_DENY_SUFFIX = r"(\s+)under(\s+)`UNIFI_WRITE_POLICY=deny`"
OFFICIAL_ONLY_RE = (
    r"(\s)\d+(\s+)tools(\s+)remain(\s+)and(\s+)\d+(\s+)are(\s+)excluded"
    rf"(?!{_DENY_SUFFIX})"
)
OFFICIAL_ONLY_DENY_RE = (
    r"(\s)\d+(\s+)tools(\s+)remain(\s+)and(\s+)\d+(\s+)are(\s+)excluded" + _DENY_SUFFIX
)
RELAYS_RE = r"the(\s+)\d+(\s+)generic(\s+)relays"
# The figures render_changelog maintains in the release section. lane_gate masks them, so
# regenerating them is not a hand edit of CHANGELOG.md.
CHANGELOG_FIGURE_PATTERNS = (
    r"Highlights: \d+ tools(?: \(\d+ added, \d+ removed\))?",
    r"\(\d+(\s+)tools,(\s+)about(\s+)\d+(\s+)KB(\s+)of(\s+)`tools/list`\)",
    r"Tool annotations: the \d+ read-only tools",
    r"the \d+ write tools advertise",
)


def mask_changelog_figures(text: str) -> str:
    """Return ``text`` with the digits of the generated figures replaced by ``#``.

    Only the current (first numbered) release section is masked, the one render_changelog
    maintains; figures of released sections stay literal.
    """
    headings = list(_RELEASE_RE.finditer(text))
    if not headings:
        return text
    start = headings[0].start()
    end = headings[1].start() if len(headings) > 1 else len(text)
    section = text[start:end]
    for pattern in CHANGELOG_FIGURE_PATTERNS:
        section = re.sub(pattern, lambda m: re.sub(r"\d+", "#", m[0]), section)
    return text[:start] + section + text[end:]


def _measure(
    families: str | None,
    mode: str = "full",
    *,
    compact_result: bool = False,
    exclude: str | None = None,
    write_policy: str | None = None,
) -> tuple[int, int]:
    """(tool count, bytes) of ``tools/list`` from the stdio entry point."""
    result, size = _tools_list(
        families, mode, compact_result=compact_result, exclude=exclude, write_policy=write_policy
    )
    return len(result["tools"]), size


def _tools_list(
    families: str | None,
    mode: str = "full",
    *,
    compact_result: bool = False,
    exclude: str | None = None,
    write_policy: str | None = None,
) -> tuple[dict, int]:
    """(``tools/list`` result, bytes) from the stdio entry point."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "MCP_", "FASTMCP_"))}
    env["UNIFI_API_KEY"] = "catalog-figures-placeholder-key"
    env["UNIFI_TOOL_MODE"] = mode
    if families is not None:
        env["UNIFI_FAMILY_ALLOW"] = families
    if exclude is not None:
        env["UNIFI_EXCLUDE"] = exclude
    if write_policy is not None:
        env["UNIFI_WRITE_POLICY"] = write_policy
    proc = subprocess.Popen(  # noqa: S603 - this interpreter running the package's entry point
        [sys.executable, "-c", "from unifi_fabric.entrypoint import main; main()"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    try:
        if proc.stdin is None or proc.stdout is None:
            raise RuntimeError("stdio pipes were not created")

        def send(msg: dict) -> None:
            proc.stdin.write((json.dumps(msg) + "\n").encode())
            proc.stdin.flush()

        def reply(want: int) -> bytes:
            for line in iter(proc.stdout.readline, b""):
                if json.loads(line).get("id") == want:
                    return line.rstrip(b"\n")
            raise RuntimeError(f"server exited before answering request {want}")

        send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "catalog-figures", "version": "1"},
                },
            }
        )
        reply(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        line = reply(2)
    finally:
        proc.kill()
        proc.wait()
    result = json.loads(line)["result"]
    if result.get("nextCursor") is not None:
        raise RuntimeError("tools/list is paginated; measure every page")
    size = len(line)
    if compact_result:
        size = len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    return result, size


def official_only_leaks(names: list[str]) -> list[str]:
    """``name: pair`` for each listed tool that calls an API source other than an official
    one or ``server/local`` (an unclassified tool counts too), sorted."""
    sys.path.insert(0, str(ROOT / "src"))
    from unifi_fabric import api_sources

    table = api_sources.table()
    leaks = []
    for name in names:
        pairs = tuple(table.get(name, ()))
        if not pairs:
            leaks.append(f"{name}: unclassified")
        leaks.extend(
            f"{name}: {pair}"
            for pair in pairs
            if pair != "server/local" and pair.split("/", 1)[-1] != "official"
        )
    return sorted(leaks)


def shape_totals() -> tuple[int, int, int]:
    """(shaped body parameters, free-form object parameters, compact bytes of all shapes)."""
    sys.path.insert(0, str(ROOT / "src"))
    from unifi_fabric.generated_api_facts._tool_shapes_table import SHAPE_SOURCES, TOOL_SHAPES

    size = sum(
        len(json.dumps(shape, separators=(",", ":"), ensure_ascii=False).encode())
        for args in TOOL_SHAPES.values()
        for shape in args.values()
    )
    shaped = sum(1 for src in SHAPE_SOURCES.values() if src["classification"] == "shaped")
    free = sum(1 for src in SHAPE_SOURCES.values() if src["classification"] == "free-form")
    return shaped, free, size


@dataclass(frozen=True)
class Domain:
    """One README domain row: which registered tools it counts.

    A tool belongs to the domain that names it in ``names`` (exact tool names). Failing
    that, to the first domain whose ``modules`` lists the ``tools/`` module defining it, or,
    for the tools defined inline in ``server.py``, whose ``delegates`` lists the ``tools/``
    module it delegates to (``families.build_module_index``).
    """

    label: str
    modules: tuple[str, ...] = ()
    delegates: tuple[str, ...] = ()
    names: tuple[str, ...] = ()


#: The tools modules of the Network & VLAN and Protect domain rows (server.py delegates).
NETWORK_MODULES = (
    "network",
    "network_clients_guests",
    "network_controller_insights",
    "network_nat_qos_traffic",
    "matter",
    "site_admin",
    "network_wifi_radio",
    "network_switching_power",
    "network_controller_admin",
    "network_routing_topology",
    "network_security_diagnostics",
    "network_proav_sandbox",
    "network_mobile_wan",
    "network_device_operations",
)
PROTECT_MODULES = (
    "protect",
    "protect_private",
    "protect_camera_recording",
    "protect_device_lifecycle",
    "protect_door_locks",
    "protect_events_cases",
    "protect_users_assets",
    "protect_automation_backup",
    "protect_ptz_doorbell",
    "protect_recognition_search",
)

DOMAINS: tuple[Domain, ...] = (
    Domain("Fleet & Aggregation", modules=("aggregation",)),
    Domain("Site Manager", delegates=("site_manager",)),
    Domain("Site Management", modules=("site_admin",)),
    Domain(
        "Network & VLAN",
        delegates=NETWORK_MODULES,
        modules=("matter",),
        names=(
            "list_port_profiles",
            "get_port_profile",
            "update_port_profile",
            "allow_network_on_port_profile",
            "exclude_network_on_port_profile",
            "create_port_profile",
            "delete_port_profile",
            "list_ap_groups",
            "get_ap_group",
            "create_ap_group",
            "update_ap_group",
            "delete_ap_group",
        ),
    ),
    Domain("Controller Administration", modules=("network_controller_admin",)),
    Domain(
        "Insights & Diagnostics",
        modules=("network_controller_insights", "network_security_diagnostics"),
    ),
    Domain(
        "Switching, Power & Routing",
        modules=("network_switching_power", "network_routing_topology"),
    ),
    Domain(
        "Wi-Fi & Radio",
        modules=("network_wifi_radio",),
        names=(
            "list_wlan_configs",
            "get_wlan_config",
            "update_wlan_config",
            "list_wlan_groups",
            "get_wlan_group",
            "get_channel_plan",
            "list_rogue_aps",
        ),
    ),
    Domain("Mobile & WAN", modules=("network_mobile_wan",)),
    Domain("ProAV, Sandbox & Digital Twin", modules=("network_proav_sandbox",)),
    Domain(
        "Device Management",
        modules=(
            "device_mgmt",
            "device_commands",
            "scheduled_tasks",
            "device_radios",
            "switch_port_overrides",
            "network_device_operations",
        ),
    ),
    Domain(
        "Clients & Guests",
        modules=("clients", "client_records", "network_clients_guests"),
        names=(
            "list_user_groups",
            "get_user_group",
            "create_user_group",
            "update_user_group",
            "delete_user_group",
            "set_client_user_group",
        ),
    ),
    Domain("NAT, QoS & Traffic Shaping", modules=("network_nat_qos_traffic",)),
    Domain(
        "DNS & Traffic",
        names=(
            "list_dns_policies",
            "create_dns_policy",
            "get_dns_policy",
            "update_dns_policy",
            "delete_dns_policy",
            "list_traffic_matching_lists",
            "create_traffic_matching_list",
            "get_traffic_matching_list",
            "update_traffic_matching_list",
            "delete_traffic_matching_list",
            "list_traffic_rules",
            "list_traffic_routes",
            "create_traffic_route",
            "get_traffic_route",
            "update_traffic_route",
            "delete_traffic_route",
            "list_routing_entries",
            "list_dynamic_dns",
            "get_dynamic_dns",
            "update_dynamic_dns",
            "create_dynamic_dns",
            "delete_dynamic_dns",
            "get_static_route",
            "create_static_route",
            "update_static_route",
            "delete_static_route",
            "list_dpi_categories",
            "list_dpi_applications",
        ),
    ),
    Domain(
        "Firewall",
        delegates=("firewall_proxy",),
        names=(
            "list_firewall_rules",
            "create_firewall_rule",
            "get_firewall_rule",
            "list_firewall_groups",
            "get_firewall_group",
        ),
    ),
    Domain("Network Policy & DPI", modules=("network_dpi_policy",)),
    Domain(
        "Port Forwarding",
        names=(
            "list_port_forwards",
            "create_port_forward",
            "update_port_forward",
            "delete_port_forward",
        ),
    ),
    Domain(
        "VPN",
        modules=("vpn", "vpn_clients", "network_vpn_dns", "radius_profiles"),
        names=("list_vpn_servers", "list_site_to_site_tunnels", "list_radius_profiles"),
    ),
    Domain(
        "Hotspot",
        modules=("hotspot",),
        names=(
            "list_hotspot_vouchers",
            "create_hotspot_vouchers",
            "get_hotspot_voucher",
            "delete_hotspot_voucher",
            "bulk_delete_hotspot_vouchers",
            "list_hotspot_packages",
            "get_hotspot_package",
        ),
    ),
    Domain(
        "Settings & Monitoring",
        names=(
            "list_settings",
            "get_setting",
            "update_setting",
            "list_scheduled_tasks",
            "get_scheduled_task",
        ),
    ),
    Domain(
        "Utilities",
        names=(
            "list_countries",
            "list_device_tags",
            "list_users",
            "get_user",
            "update_user",
            "list_accounts",
            "get_account",
            "create_radius_account",
            "update_radius_account",
            "delete_radius_account",
        ),
    ),
    Domain(
        "Protect",
        modules=(
            "protect_private",
            "protect_camera_recording",
            "protect_device_lifecycle",
            "protect_door_locks",
        ),
        delegates=PROTECT_MODULES,
    ),
    Domain("Protect Events & Cases", modules=("protect_events_cases",)),
    Domain("Protect Automation & Backup", modules=("protect_automation_backup",)),
    Domain("Protect PTZ & Doorbell", modules=("protect_ptz_doorbell",)),
    Domain(
        "Protect Recognition & Search",
        modules=("protect_recognition_search",),
        delegates=("recognition",),
    ),
    Domain("Protect Users & Assets", modules=("protect_users_assets",)),
    Domain("InnerSpace", modules=("innerspace_internal",), delegates=("innerspace",)),
    Domain("Mobility", delegates=("mobility",)),
    Domain("Carrier / ISP Fabric", delegates=("carrier_fabric",)),
    Domain("Connector Relay", delegates=("connector",)),
    Domain("Statistics, History & Logs", modules=("statistics", "system_log", "event_streams")),
    Domain("Placement Snapshot", delegates=("placement_snapshot",)),
)


def tool_inventory() -> list[tuple[str, str, str | None]]:
    """(tool name, defining module, delegated tools module) for every registered tool."""
    import asyncio

    sys.path.insert(0, str(ROOT / "src"))
    import unifi_fabric.server as server
    from unifi_fabric.families import build_module_index

    modules = build_module_index()
    tools = asyncio.run(server.mcp.list_tools())
    return [(t.name, t.fn.__module__.rsplit(".", 1)[-1], modules.get(t.name)) for t in tools]


def annotation_counts() -> tuple[int, int]:
    """Count the annotations the registered catalog actually advertises."""
    import asyncio

    sys.path.insert(0, str(ROOT / "src"))
    import unifi_fabric.server as server

    tools = asyncio.run(server.mcp.list_tools())
    reads = sum(bool(t.annotations and t.annotations.read_only_hint) for t in tools)
    return reads, len(tools) - reads


def confirm_parameter_count() -> int:
    """Count registered tools accepting the ignored compatibility parameter."""
    import asyncio

    sys.path.insert(0, str(ROOT / "src"))
    import unifi_fabric.server as server

    tools = asyncio.run(server.mcp.list_tools())
    return sum("confirm" in (tool.parameters.get("properties") or {}) for tool in tools)


def domain_counts(
    inventory: list[tuple[str, str, str | None]], domains: tuple[Domain, ...] = DOMAINS
) -> dict[str, int]:
    """Tools per domain label; each tool counted once, and none left over."""
    labels = [d.label for d in domains]
    if len(set(labels)) != len(labels):
        raise RuntimeError("DOMAINS lists a label twice")
    registered = {name for name, _module, _delegate in inventory}
    by_name: dict[str, str] = {}
    for domain in domains:
        stale = sorted(set(domain.names) - registered)
        if stale:
            raise RuntimeError(f"DOMAINS {domain.label!r} names unregistered tools: {stale}")
        for name in domain.names:
            if by_name.setdefault(name, domain.label) != domain.label:
                raise RuntimeError(f"DOMAINS names {name} in two domains")
    counts = dict.fromkeys(labels, 0)
    unclassified: list[str] = []
    for name, module, delegate in inventory:
        label = by_name.get(name)
        if label is None:
            # A wrapper defined in server.py, or moved into the tools module it delegates
            # to (and that module has no modules= rule of its own), is classified by that
            # delegated module.
            delegated = module == "server" or (
                module == delegate and not any(module in d.modules for d in domains)
            )
            label = next(
                (
                    d.label
                    for d in domains
                    if module in d.modules or (delegated and delegate in d.delegates)
                ),
                None,
            )
        if label is None:
            unclassified.append(f"{name} (module {module}, delegates to {delegate})")
        else:
            counts[label] += 1
    if unclassified:
        raise RuntimeError(
            f"{len(unclassified)} tools fit no README domain; add a rule to DOMAINS: "
            + ", ".join(sorted(unclassified))
        )
    empty = [label for label, n in counts.items() if n == 0]
    if empty:
        raise RuntimeError(f"DOMAINS rows count no tool: {empty}")
    return counts


def selection_counts() -> tuple[dict[str, tuple[int, int]], dict[str | None, int]]:
    """Per family (tools, write tools); per opt-out the write tools its startup selection
    hides (``None``: the default, 0), keyed by the README row (``SETTING=value``). Measured
    with the selection functions the server runs at startup, on a copy of the registered
    catalog, with every ``UNIFI_*`` setting unset but the one measured."""
    import asyncio

    sys.path.insert(0, str(ROOT / "src"))
    from fastmcp import FastMCP

    import unifi_fabric.server as server
    from unifi_fabric import switches
    from unifi_fabric.families import ALL_FAMILIES, build_family_index
    from unifi_fabric.families.connector.connector import CONNECTOR_WRITE_ENV
    from unifi_fabric.read_only_tools import (
        _is_read_tool,
        apply_area_opt_out_tool_filter,
        apply_read_only_tool_filter,
    )

    async def run() -> tuple[dict[str, tuple[int, int]], dict[str | None, int]]:
        tools = await server.mcp.list_tools()
        index = build_family_index()
        families = {
            family: (
                sum(index.get(t.name) == family for t in tools),
                sum(index.get(t.name) == family and not _is_read_tool(t) for t in tools),
            )
            for family in ALL_FAMILIES
        }

        def copy() -> FastMCP:
            app = FastMCP("catalog-figures")
            for tool in tools:
                app.add_tool(tool)
            return app

        hidden: dict[str | None, int] = {None: 0}
        saved = dict(os.environ)
        try:
            for token in [s.env for s in switches.AREA_WRITE_SWITCHES] + [CONNECTOR_WRITE_ENV]:
                for name in [k for k in os.environ if k.startswith("UNIFI_")]:
                    del os.environ[name]
                os.environ[switches.WRITE_EXCEPTIONS_ENV] = token
                hidden[f"{switches.WRITE_EXCEPTIONS_ENV}={token}"] = len(
                    await apply_area_opt_out_tool_filter(copy(), token != CONNECTOR_WRITE_ENV)
                )
            for name in [k for k in os.environ if k.startswith("UNIFI_")]:
                del os.environ[name]
            hidden[f"{switches.WRITE_POLICY_ENV}=deny"] = len(
                await apply_read_only_tool_filter(copy(), True)
            )
        finally:
            os.environ.clear()
            os.environ.update(saved)
        return families, hidden

    return asyncio.run(run())


@dataclass(frozen=True)
class Figures:
    tools: int
    full_kb: int
    families: dict[str | None, tuple[int, int]]
    modes: dict[str, tuple[int, int]]
    shaped: int
    free: int
    shape_bytes: int
    domains: dict[str, int]
    family_counts: dict[str, tuple[int, int]]
    hidden: dict[str | None, int]
    read_only: int
    writes: int
    confirm: int = 0
    #: Tools listed in full mode under OFFICIAL_ONLY_EXCLUDE (also with
    #: UNIFI_WRITE_POLICY=deny), and the generic relays UNIFI_EXCLUDE=unofficial alone keeps.
    official_only: int = 0
    official_only_deny: int = 0
    official_relays: int = 0
    catalog_delta: tuple[int, int] | None = None


def _kb(size: int) -> int:
    return round(size / 1000)


def _table_block(text: str, header: str) -> tuple[int, int]:
    start = text.index(header)
    end = text.find("\n\n", start)
    return start, len(text) if end == -1 else end


def listed_families(readme: str) -> list[str | None]:
    start, end = _table_block(readme, FAMILY_TABLE_HEADER)
    rows = [m.group(2) for m in _FAMILY_ROW_RE.finditer(readme[start:end])]
    if not rows or rows[0] is not None:
        raise RuntimeError("the family table must start with the unset (all families) row")
    return rows


def catalog_delta() -> tuple[int, int]:
    """Compare the current tool names with the previous release's schema snapshot."""
    headings = list(_RELEASE_RE.finditer(CHANGELOG.read_text()))
    previous = headings[1][1].replace(".", "_")
    snapshot = ROOT / "tests" / "fixtures" / f"tool_input_schemas_v{previous}.json"
    old = set(json.loads(snapshot.read_text())["schemas"])
    new = {name for name, _module, _delegate in tool_inventory()}
    return len(new - old), len(old - new)


def measure(readme: str) -> Figures:
    families = listed_families(readme)
    jobs: dict[tuple[str, str | None], Callable[[], tuple[int, int]]] = {
        ("family", fam): (lambda fam=fam: _measure(fam)) for fam in families
    }
    for mode in ("full", "discovery"):
        jobs[("mode", mode)] = lambda mode=mode: _measure(None, mode, compact_result=True)
    jobs[("exclude", "unofficial")] = lambda: _measure(None, exclude="unofficial")
    jobs[("exclude", "deny")] = lambda: _measure(
        None, exclude=OFFICIAL_ONLY_EXCLUDE, write_policy="deny"
    )
    official_listing = _tools_list(None, exclude=OFFICIAL_ONLY_EXCLUDE)[0]
    official_names = [tool["name"] for tool in official_listing["tools"]]
    leaks = official_only_leaks(official_names)
    if leaks:
        raise RuntimeError(
            f"UNIFI_EXCLUDE={OFFICIAL_ONLY_EXCLUDE} is documented as official-only but lists "
            "tools that call other API sources:\n" + "\n".join(leaks)
        )
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {key: pool.submit(job) for key, job in jobs.items()}
        results = {key: future.result() for key, future in futures.items()}
    family_figures = {fam: results[("family", fam)] for fam in families}
    modes = {mode: results[("mode", mode)] for mode in ("full", "discovery")}
    tools, full_bytes = family_figures[None]
    if modes["full"][0] != tools:
        raise RuntimeError(f"full mode lists {modes['full'][0]} tools, unset families {tools}")
    shaped, free, shape_bytes = shape_totals()
    domains = domain_counts(tool_inventory())
    if sum(domains.values()) != tools:
        raise RuntimeError(f"domain counts sum to {sum(domains.values())}, catalog has {tools}")
    family_counts, hidden = selection_counts()
    if sum(count for count, _writes in family_counts.values()) != tools:
        raise RuntimeError(f"family counts do not sum to the catalog's {tools} tools")
    read_only, writes = annotation_counts()
    if read_only + writes != tools:
        raise RuntimeError("annotation counts do not cover the registered catalog")
    official_only = len(official_names)
    official_only_deny = results[("exclude", "deny")][0]
    official_relays = results[("exclude", "unofficial")][0] - official_only
    if not 0 < official_only_deny < official_only < tools or official_relays < 1:
        raise RuntimeError(
            f"UNIFI_EXCLUDE={OFFICIAL_ONLY_EXCLUDE} lists {official_only} of {tools} tools "
            f"({official_only_deny} under deny) and unofficial alone {official_relays} more; "
            "the official-only measurement is wrong"
        )
    return Figures(
        tools,
        _kb(full_bytes),
        family_figures,
        modes,
        shaped,
        free,
        shape_bytes,
        domains,
        family_counts,
        hidden,
        read_only,
        writes,
        confirm_parameter_count(),
        official_only,
        official_only_deny,
        official_relays,
        catalog_delta(),
    )


def _sub(
    text: str,
    pattern: str,
    repl: Callable[[re.Match[str]], str],
    where: str,
    *,
    required: bool = True,
) -> str:
    new, count = re.subn(pattern, repl, text)
    if count == 0 and required:
        raise RuntimeError(f"{where}: no figure matched {pattern!r}; update the generator")
    return new


class MarkerError(RuntimeError):
    """A generated block is missing, duplicated, unregistered, out of order or crossed."""


#: This generator's name in the block registry (``BLOCKS`` in scripts/doc_blocks.py).
OWNER = "gen_catalog_figures"


def _doc_blocks():
    """scripts/doc_blocks.py, the block registry, loaded by path: this module runs as a script,
    is imported from ``scripts`` and is loaded by path in tests. Loaded on first use, so a copy
    of this file that never renders a block needs no sibling registry."""
    import importlib.util

    path = Path(__file__).with_name("doc_blocks.py")
    module = sys.modules.get("doc_blocks")
    if module is not None and Path(module.__file__ or "").resolve() == path.resolve():
        return module
    spec = importlib.util.spec_from_file_location("doc_blocks", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("scripts/doc_blocks.py is missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules["doc_blocks"] = module  # dataclasses resolve their module
    spec.loader.exec_module(module)
    return module


def fill_blocks(path: Path, text: str, renderers: dict[str, Callable[[], str]]) -> str:
    """``text`` with this generator's registered blocks of ``path`` regenerated.

    Every block the registry lists for ``path`` must be present once, in order, with intact
    markers (whoever owns it); otherwise ``MarkerError`` names the file and the marker, in
    write and --check modes alike, before anything is written.
    """
    where = path.relative_to(ROOT).as_posix()
    new, found = _doc_blocks().fill(where, text, OWNER, renderers)
    if found:
        raise MarkerError("; ".join(f"{where}: {block}: {message}" for block, message in found))
    return new


def render_official_only(
    text: str, fig: Figures, where: str, *, relays: bool = False, deny: bool = False
) -> str:
    """Rewrite the official-only figures (and, where stated, the deny figures and the
    generic relay count)."""
    excluded = fig.tools - fig.official_only
    text = _sub(
        text,
        OFFICIAL_ONLY_RE,
        lambda m: (
            f"{m[1]}{fig.official_only}{m[2]}tools{m[3]}remain{m[4]}and{m[5]}{excluded}"
            f"{m[6]}are{m[7]}excluded"
        ),
        where,
    )
    excluded_deny = fig.tools - fig.official_only_deny
    text = _sub(
        text,
        OFFICIAL_ONLY_DENY_RE,
        lambda m: (
            f"{m[1]}{fig.official_only_deny}{m[2]}tools{m[3]}remain{m[4]}and{m[5]}"
            f"{excluded_deny}{m[6]}are{m[7]}excluded{m[8]}under{m[9]}`UNIFI_WRITE_POLICY=deny`"
        ),
        where,
        required=deny,
    )
    if relays:
        text = _sub(
            text,
            RELAYS_RE,
            lambda m: f"the{m[1]}{fig.official_relays}{m[2]}generic{m[3]}relays",
            where,
        )
    return text


CURSOR_DEEPLINK_RE = re.compile(
    r"(cursor\.com/en/install-mcp\?[^\"\s]*?config=)([A-Za-z0-9_+/-]+=*)"
)
# A pin is X.Y.Z plus any suffix (rc1, .post1, .1, -dev.1, +local, %2Blocal in a URL). The
# whole token is replaced, so a hand-edited suffixed pin is re-rendered and fails --check
# instead of surviving it. Every pin position below uses this one tail.
# Linear grammar: one alphanumeric run, then any number of (separator, run) pairs. The
# separator is mandatory, so no input has two ways to be split and a near miss fails in
# one pass instead of trying every split.
PIN_TAIL = r"[0-9A-Za-z]*(?:(?:[.+_-]|%2[Bb])[0-9A-Za-z]+)*"
PIN_BODY = r"\d+\.\d+\.\d+" + PIN_TAIL
CURSOR_PIN_RE = re.compile(r"(unifi-fabric-mcp-server==)" + PIN_BODY)

#: Every plain-text pin position: (what it is, pattern). Group 1 is the text before the
#: version; the match ends at the end of the version token.
PIN_KINDS = (
    ("package pin (unifi-fabric-mcp-server==VERSION)", r"(unifi-fabric-mcp-server==)" + PIN_BODY),
    (
        "VS Code install-badge pin (unifi-fabric-mcp-server%3D%3DVERSION)",
        r"(?i)(unifi-fabric-mcp-server%3D%3D)" + PIN_BODY,
    ),
    (
        "container image tag (ghcr.io/.../unifi-fabric-mcp-server:VERSION)",
        r"(ghcr\.io/[^/\s]+/unifi-fabric-mcp-server:)" + PIN_BODY,
    ),
    ("release download link (releases/download/vVERSION)", r"(releases/download/v)" + PIN_BODY),
    (
        "extension bundle file name (unifi-fabric-VERSION.mcpb)",
        r"(/unifi-fabric-)" + PIN_BODY + r"(?=\.mcpb)",
    ),
)


#: The VS Code install link itself (the badge's href) carrying the encoded pin, not merely text
#: that holds the encoded token.
VSCODE_BADGE_RE = (
    r"(?i)(?:vscode(?:-insiders)?\.dev/redirect/mcp/install|vscode(?:-insiders)?:mcp/install)\?"
    r"[^\"\s<>]*?unifi-fabric-mcp-server%3D%3D" + PIN_BODY
)


def _decode_cursor_payload(payload: str) -> tuple[str, bool] | None:
    """The config JSON text inside a Cursor deeplink payload, and whether the payload uses the
    URL-safe alphabet; ``None`` when the payload does not decode."""
    urlsafe = "-" in payload or "_" in payload
    bare = payload.rstrip("=")
    decode = base64.urlsafe_b64decode if urlsafe else base64.b64decode
    try:
        return decode(bare + "=" * (-len(bare) % 4)).decode(), urlsafe
    except ValueError:
        return None


def _repin_cursor_config(m: re.Match[str], version: str) -> str:
    """Re-pin the package inside a Cursor deeplink's base64 config, keeping its alphabet.

    A payload that does not decode, or holds no pin, is left untouched here (``pin_findings``
    reports it). Padding follows the payload's own style: a payload that carries ``=`` stays
    padded, and so does one whose length needs none (that says nothing about its style, and a
    longer or shorter version can need padding); only a payload that is unpadded although its
    length needs padding is written unpadded."""
    payload = m[2]
    decoded = _decode_cursor_payload(payload)
    if decoded is None:
        return m[0]
    config, urlsafe = decoded
    pinned = CURSOR_PIN_RE.sub(lambda p: p[1] + version, config)
    if pinned == config:
        return m[0]
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    encoded = encode(pinned.encode()).decode()
    bare = payload.rstrip("=")
    if len(bare) == len(payload) and len(bare) % 4:
        encoded = encoded.rstrip("=")
    return m[1] + encoded


def render_install_versions(text: str, version: str) -> str:
    """Refresh package pins, image tags and release bundle links from project metadata.

    The install badges carry the pin twice more in encoded form: URL-encoded in the VS Code
    deeplink and base64 in the Cursor deeplink; both are rewritten too."""
    text = CURSOR_DEEPLINK_RE.sub(lambda m: _repin_cursor_config(m, version), text)
    for _what, pattern in PIN_KINDS:
        text = re.sub(pattern, lambda m: m[1] + version, text)
    return text


def pin_findings(text: str, version: str, where: str) -> list[str]:
    """One line per pin in ``text`` that is not ``version``: ``where:LINE: WHAT is X, expected
    Y``. The Cursor badge is named too (it is base64, so a diff of it shows nothing a reader
    can act on)."""
    found: list[tuple[int, str]] = []
    for what, pattern in PIN_KINDS:
        for m in re.finditer(pattern, text):
            token = m[0][len(m[1]) :]
            if token != version:
                found.append((m.start(), f"{what} is {token}, expected {version}"))
    for m in CURSOR_DEEPLINK_RE.finditer(text):
        decoded = _decode_cursor_payload(m[2])
        if decoded is None:
            found.append((m.start(), "Cursor install-badge config does not decode"))
            continue
        pins = list(CURSOR_PIN_RE.finditer(decoded[0]))
        if not pins:
            found.append((m.start(), "Cursor install-badge config holds no package pin"))
        for p in pins:
            token = p[0][len(p[1]) :]
            if token != version:
                found.append(
                    (
                        m.start(),
                        f"Cursor install-badge pin (base64 config) is {token}, expected {version}",
                    )
                )
    return [f"{where}:{text.count(chr(10), 0, pos) + 1}: {msg}" for pos, msg in sorted(found)]


def require_install_badges(text: str, where: str) -> None:
    """Fail closed when the VS Code or Cursor install badge is gone or carries no pin.

    ``render_install_versions`` rewrites only a pin it finds, so a deleted badge, a payload that
    does not decode, or a config with no pin would otherwise pass ``--check`` and be caught only
    by the test suite."""
    problems: list[str] = []
    if not re.search(VSCODE_BADGE_RE, text):
        problems.append(
            "no VS Code install badge with a pin (unifi-fabric-mcp-server%3D%3DVERSION)"
        )
    cursor = list(CURSOR_DEEPLINK_RE.finditer(text))
    if not cursor:
        problems.append("no Cursor install badge (cursor.com/en/install-mcp?...&config=...)")
    for m in cursor:
        decoded = _decode_cursor_payload(m[2])
        line = text.count("\n", 0, m.start()) + 1
        if decoded is None:
            problems.append(f"line {line}: the Cursor install badge config does not decode")
        elif not CURSOR_PIN_RE.search(decoded[0]):
            problems.append(f"line {line}: the Cursor install badge config pins no package version")
    if problems:
        raise MarkerError(
            f"{where}: " + "; ".join(problems) + ". Restore the badge, then run "
            "python3 scripts/regen_docs.py"
        )


def render_catalog_size_prose(text: str, fig: Figures, where: str, *, required: bool) -> str:
    """The "Catalog size" paragraph: full-mode tool count and size, body-shape figures."""
    text = _sub(
        text,
        r"full mode advertises \d+ tools and its",
        lambda m: f"full mode advertises {fig.tools} tools and its",
        where,
        required=required,
    )
    text = _sub(
        text,
        r"`tools/list` response is roughly \d+ KB of JSON",
        lambda m: f"`tools/list` response is roughly {fig.full_kb} KB of JSON",
        where,
        required=required,
    )
    return _sub(
        text,
        r"the \d+(\s+)pinned-spec(\s+)request(\s+)bodies([^(]*)"
        r"\([\d,]+(\s+)bytes(\s+)of(\s+)compact(\s+)JSON",
        lambda m: (
            f"the {fig.shaped}{m[1]}pinned-spec{m[2]}request{m[3]}bodies{m[4]}"
            f"({fig.shape_bytes:,}{m[5]}bytes{m[6]}of{m[7]}compact{m[8]}JSON"
        ),
        where,
        required=required,
    )


def render_switch_table(text: str, fig: Figures, where: str) -> str:
    """The opt-out table: write tools hidden and tools listed under each switch."""
    start, end = _table_block(text, SWITCH_TABLE_HEADER)
    switch_rows = [m.group(2) for m in _SWITCH_ROW_RE.finditer(text[start:end])]
    if switch_rows != list(fig.hidden):
        raise RuntimeError(
            f"{where} opt-out table rows must be {list(fig.hidden)}, in order; got {switch_rows}"
        )

    def switch_row(m: re.Match[str]) -> str:
        count = fig.hidden[m.group(2)]
        return f"| {m.group(1)} | {count} | {fig.tools - count} |"

    block = _SWITCH_ROW_RE.sub(switch_row, text[start:end])
    return text[:start] + block + text[end:]


def verification_status(fig: Figures) -> str:
    """The README verification table: the CI tool count and the COVERAGE live evidence."""
    match = re.search(
        r"<!-- live-evidence: passed=(\d+) writes=(\d+) total=(\d+) "
        r"build=([0-9a-f]+) date=(\d{4}-\d{2}-\d{2}) -->",
        COVERAGE.read_text(),
    )
    if not match:
        raise RuntimeError("COVERAGE live evidence marker is missing")
    passed, writes, total, build, date = match.groups()
    return "\n".join(
        (
            "| Evidence | Result |",
            "|---|---|",
            f"| Every tool runs in CI against a simulated upstream | {fig.tools} tools |",
            f"| Live-tested on a real console | {passed} of {total} passed on build "
            f"`{build}`, {date} |",
            f"| Live write tools passed | {writes} on that build and date |",
        )
    )


def readme_blocks(fig: Figures) -> dict[str, Callable[[], str]]:
    """The README blocks this generator owns (``BLOCKS`` in scripts/doc_blocks.py), by name.

    The text around each figure is fixed here; the README prose outside the blocks is free and
    no generator rewrites it.
    """
    t = fig.tools
    return {
        "catalog-headline": lambda: "\n".join(
            (
                f"- **{t} tools, loaded on demand.** Discovery mode gives your assistant a small",
                "  search-and-call toolset instead of flooding its context with the whole catalog;",
                "  the full catalog is one setting away.",
            )
        ),
        "how-it-works-catalog": lambda: "\n".join(
            (
                "By default, the server exposes a small set of discovery tools to your assistant "
                "rather",
                f"than loading the entire {t}-tool catalog into context at once. When you ask a "
                "question",
                "or request a change, the assistant searches the catalog, inspects the matching "
                "tool, and",
                "calls it through the server.",
            )
        ),
        "verification-status": lambda: verification_status(fig),
    }


def render_readme(text: str, fig: Figures) -> str:
    """README.md: the install pins (``published-version.txt``) and this generator's blocks.

    Nothing else in the README is rewritten: a figure outside a generated block is hand-written
    prose (tests/test_docs_currency.py holds any "N tools" there to the registry).
    """
    require_install_badges(text, "README.md")
    text = render_install_versions(text, PUBLISHED_VERSION)
    return fill_blocks(README, text, readme_blocks(fig))


def render_catalog(text: str, fig: Figures) -> str:
    """Refresh the relocated family and mode size tables."""
    start, end = _table_block(text, FAMILY_TABLE_HEADER)

    def family_row(m: re.Match[str]) -> str:
        count, size = fig.families[m.group(2)]
        return f"| {m.group(1)} | {count} | ~{_kb(size)} KB |"

    block = _FAMILY_ROW_RE.sub(family_row, text[start:end])
    text = text[:start] + block + text[end:]

    start, end = _table_block(text, MODE_TABLE_HEADER)

    def mode_row(m: re.Match[str]) -> str:
        advertised, size = fig.modes[m.group(1)]
        label = f"`{m.group(1)}`{m.group(2) or ''}"
        return f"| {label} | {advertised} | {fig.tools} | {size} | ~{_kb(size)} KB |"

    block, count = _MODE_ROW_RE.subn(mode_row, text[start:end])
    if count != 2:
        raise RuntimeError(f"README mode table: expected 2 rows, matched {count}")
    text = text[:start] + block + text[end:]
    return render_catalog_size_prose(text, fig, "CATALOG", required=True)


def render_annotations(text: str, fig: Figures, where: str, *, required: bool = True) -> str:
    text = _sub(
        text,
        CHANGELOG_FIGURE_PATTERNS[2],
        lambda m: f"Tool annotations: the {fig.read_only} read-only tools",
        where,
        required=required,
    )
    return _sub(
        text,
        CHANGELOG_FIGURE_PATTERNS[3],
        lambda m: f"the {fig.writes} write tools advertise",
        where,
        required=required,
    )


def render_changelog(text: str, fig: Figures) -> str:
    """Rewrite figures in the current (first numbered) release section only.

    Every release opens with ``Highlights: N tools (A added, R removed)``, so that count
    is required (tests/test_front_page_docs.py recomputes A and R against the previous
    release). The size and annotation figures belong to the entries that change them; a
    release that changes neither need not restate them, so they are rewritten only where
    the section carries them. The body-shape figures live in docs/MIGRATING-0.7.md
    (render_migrating).
    """
    headings = list(_RELEASE_RE.finditer(text))
    if not headings:
        raise RuntimeError("CHANGELOG has no numbered release section")
    if _DATED_RE.match(text, headings[0].start()):
        return text  # the first numbered section has shipped; its figures stay verbatim
    start = headings[0].start()
    end = headings[1].start() if len(headings) > 1 else len(text)
    section = text[start:end]
    t = str(fig.tools)
    highlights = f"Highlights: {t} tools"
    if fig.catalog_delta is not None:
        added, removed = fig.catalog_delta
        highlights += f" ({added} added, {removed} removed)"
    section = _sub(
        section,
        CHANGELOG_FIGURE_PATTERNS[0],
        lambda m: (
            highlights
            if fig.catalog_delta is not None
            else re.sub(r"^Highlights: \d+ tools", highlights, m[0])
        ),
        "CHANGELOG",
    )
    section = _sub(
        section,
        CHANGELOG_FIGURE_PATTERNS[1],
        lambda m: (
            f"({t}{m[1]}tools,{m[2]}about{m[3]}{fig.full_kb}{m[4]}KB{m[5]}of{m[6]}`tools/list`)"
        ),
        "CHANGELOG",
        required=False,
    )
    section = render_annotations(section, fig, "CHANGELOG", required=False)
    return text[:start] + section + text[end:]


def render_migrating(text: str, fig: Figures) -> str:
    """Rewrite body-shape and annotation figures of the 0.7 migration guide."""
    text = render_annotations(text, fig, "MIGRATING-0.7")
    text = _sub(
        text,
        r"describe(\s+)\d+(\s+)pinned-spec(\s+)body(\s+)shapes",
        lambda m: f"describe{m[1]}{fig.shaped}{m[2]}pinned-spec{m[3]}body{m[4]}shapes",
        "MIGRATING-0.7",
    )
    text = _sub(
        text,
        r"The(\s+)other(\s+)\d+(\s+)object(\s+)parameters",
        lambda m: f"The{m[1]}other{m[2]}{fig.free}{m[3]}object{m[4]}parameters",
        "MIGRATING-0.7",
    )
    return _sub(
        text,
        r"The(\s+)shapes(\s+)are(\s+)[\d,]+(\s+)bytes(\s+)of(\s+)compact(\s+)JSON",
        lambda m: (
            f"The{m[1]}shapes{m[2]}are{m[3]}{fig.shape_bytes:,}{m[4]}bytes{m[5]}of"
            f"{m[6]}compact{m[7]}JSON"
        ),
        "MIGRATING-0.7",
    )


def render_configuration(text: str, fig: Figures) -> str:
    """Rewrite the tools and write tools of each family in docs/CONFIGURATION.md."""
    start, end = _table_block(text, FAMILY_COUNT_HEADER)
    rows = [m.group(1) for m in _FAMILY_COUNT_ROW_RE.finditer(text[start:end])]
    if rows != sorted(fig.family_counts):
        raise RuntimeError(
            f"README family-count rows must be every family, sorted: README {rows}, "
            f"families {sorted(fig.family_counts)}"
        )

    def family_count_row(m: re.Match[str]) -> str:
        count, writes = fig.family_counts[m.group(1)]
        return f"| `{m.group(1)}` | {count} | {writes} | {m.group(2)} |"

    block = _FAMILY_COUNT_ROW_RE.sub(family_count_row, text[start:end])
    text = text[:start] + block + text[end:]
    text = render_switch_table(text, fig, "CONFIGURATION")

    return render_official_only(text, fig, "CONFIGURATION", relays=True, deny=True)


def render_coverage(text: str, fig: Figures) -> str:
    """Rewrite registered catalog and compatibility-parameter counts."""
    text = _sub(
        text,
        r"this release's \d+ tools",
        lambda m: f"this release's {fig.tools} tools",
        "COVERAGE",
    )
    return _sub(
        text,
        r"\d+ write and action tools accept an optional `confirm`",
        lambda m: f"{fig.confirm} write and action tools accept an optional `confirm`",
        "COVERAGE",
    )


def render_site_stats(version: str, tools: int, coverage_text: str) -> str:
    """docs/site-stats.json, rendered by scripts/site_stats.py (loaded by path, so this module
    imports the same way whether it runs as a script or is loaded by a test)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "site_stats", Path(__file__).with_name("site_stats.py")
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("scripts/site_stats.py is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.render(version, tools, coverage_text)


#: Diff lines --check prints per stale file; the rest is summarised.
DIFF_LINES = 120


def print_diff(path: Path, new: str) -> None:
    """A unified diff (to stderr) from ``path`` on disk to the regenerated ``new`` text."""
    import difflib

    rel = path.relative_to(ROOT).as_posix()
    lines = list(
        difflib.unified_diff(
            path.read_text().splitlines(keepends=True),
            new.splitlines(keepends=True),
            f"a/{rel}",
            f"b/{rel}",
        )
    )
    for line in lines[:DIFF_LINES]:
        sys.stderr.write(line if line.endswith("\n") else line + "\n")
    if len(lines) > DIFF_LINES:
        print(f"... {len(lines) - DIFF_LINES} more diff lines for {rel}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--check", action="store_true", help="fail when any figure is stale")
    args = parser.parse_args()

    try:
        outputs, fig = render_outputs()
    except MarkerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    summary = (
        f"{fig.tools} tools; full tools/list ~{fig.full_kb} KB; "
        f"modes {json.dumps(fig.modes)}; shapes {fig.shaped} shaped, {fig.free} free, "
        f"{fig.shape_bytes:,} bytes"
    )
    stale = [path for path, new in outputs.items() if path.read_text() != new]
    if args.check:
        if stale:
            for path in stale:
                for finding in pin_findings(
                    path.read_text(), PUBLISHED_VERSION, path.relative_to(ROOT).as_posix()
                ):
                    print(f"stale pin: {finding}", file=sys.stderr)
                print_diff(path, outputs[path])
            names = ", ".join(p.relative_to(ROOT).as_posix() for p in stale)
            print(
                f"Catalog figures are stale in {names} ({summary}); "
                "run python3 scripts/gen_catalog_figures.py",
                file=sys.stderr,
            )
            return 1
        print(f"Catalog figures are current: {summary}", file=sys.stderr)
        return 0
    for path in stale:
        path.write_text(outputs[path])
    print(f"Wrote catalog figures ({summary}) to {len(stale)} file(s)", file=sys.stderr)
    return 0


def render_outputs() -> tuple[dict[Path, str], Figures]:
    """Every output file rendered in memory; nothing is written until all of them succeed."""
    readme, changelog = README.read_text(), CHANGELOG.read_text()
    fig = measure(CATALOG.read_text())
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    outputs = {
        README: render_readme(readme, fig),
        CATALOG: render_catalog(CATALOG.read_text(), fig),
        DOCKER: render_install_versions(DOCKER.read_text(), PUBLISHED_VERSION),
        BUNDLE_README: render_install_versions(BUNDLE_README.read_text(), PUBLISHED_VERSION),
        # Pending fragments belong to the next fold; keep the folded release unchanged.
        CHANGELOG: changelog
        if any(
            any((ROOT / "changelog.d").glob(f"*.{category}.md"))
            for category in ("added", "changed", "removed", "fixed", "security")
        )
        else render_changelog(changelog, fig),
        MIGRATING: render_migrating(MIGRATING.read_text(), fig),
        COVERAGE: render_coverage(COVERAGE.read_text(), fig),
        CONFIGURATION: render_configuration(CONFIGURATION.read_text(), fig),
        AGENTS: render_official_only(AGENTS.read_text(), fig, "AGENTS"),
        LLMS: render_official_only(LLMS.read_text(), fig, "llms.txt"),
        SITE_STATS: render_site_stats(version, fig.tools, COVERAGE.read_text()),
    }
    return outputs, fig


if __name__ == "__main__":
    raise SystemExit(main())
