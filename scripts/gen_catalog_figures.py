#!/usr/bin/env python3
"""Generate selected catalog-size figures in README.md and CHANGELOG.md.

The catalog keeps growing, so these generated figures are never hand-edited. This script
measures the running server and rewrites these figures in place:

* the registered tool count wherever the README states the catalog size, and in
  the current CHANGELOG release section (Highlights and the catalog-size note);
* the docs/CATALOG.md family table: tool count and ``tools/list`` size per listed
  ``UNIFI_TOOL_FAMILIES`` value (UTF-8 JSON-RPC response line, 1 KB = 1000 bytes);
* the docs/CONFIGURATION.md family-count table: tools and write tools of each family
  (``families.ALL_FAMILIES``; a missing or extra row fails the run). Covers text is editorial;
* the README opt-out table: write tools hidden and tools listed under each per-area write
  opt-out and ``UNIFI_READ_ONLY``, from the startup selection functions themselves;
* the README domain table: the tool count of each row, from the rule table ``DOMAINS``
  below (every registered tool is counted in exactly one domain; an unclassified tool, or a
  README row without a rule, fails the run). The Purpose text stays editorial;
* the docs/CATALOG.md mode table: advertised tools, domain tools available and exact compact
  ``tools/list`` result bytes for ``UNIFI_TOOL_MODE=full`` and ``discovery``;
* the pinned-spec body-shape figures (shaped count, free-form count, compact bytes), in the
  README, the CHANGELOG and docs/MIGRATING-0.7.md;
* the README product table, first-screen counts and sizes, installation versions, and
  verification evidence from docs/COVERAGE.md;
* the catalog and ignored-confirm parameter counts in docs/COVERAGE.md;
* the read-only and write annotation counts in CHANGELOG and the migration guide;
* docs/site-stats.json, the release figures the project website reads (scripts/site_stats.py:
  registered tool count, live-verified count from docs/COVERAGE.md, their difference as the
  unit-tested count, and the release tag).

Measurement matches tests/test_readme_catalog_size.py: the package entry point is
started over stdio with a placeholder key, sent ``initialize`` and ``tools/list``,
and the reply is counted. The families listed in the catalog table are an editorial
choice and are kept; only their figures are regenerated. The same holds for the domain
rows: the labels and Purpose text are editorial, the counts are measured.

Usage:
    python3 scripts/gen_catalog_figures.py          # rewrite README.md and CHANGELOG.md
    python3 scripts/gen_catalog_figures.py --check  # exit 1 if any figure is stale (CI)
"""

from __future__ import annotations

import argparse
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
README = ROOT / "README.md"
CHANGELOG = ROOT / "CHANGELOG.md"
MIGRATING = ROOT / "docs" / "MIGRATING-0.7.md"
COVERAGE = ROOT / "docs" / "COVERAGE.md"
CONFIGURATION = ROOT / "docs" / "CONFIGURATION.md"
CATALOG = ROOT / "docs" / "CATALOG.md"
DOCKER = ROOT / "docs" / "DOCKER.md"
BUNDLE_README = ROOT / "plugins" / "claude-desktop" / "README.md"
SITE_STATS = ROOT / "docs" / "site-stats.json"

FAMILY_TABLE_HEADER = "| `UNIFI_TOOL_FAMILIES` | Tools | `tools/list` size |"
MODE_TABLE_HEADER = (
    "| `UNIFI_TOOL_MODE` | Advertised tools | Domain tools available | "
    "`tools/list` bytes | Size (1 KB = 1000 bytes) |"
)
FAMILY_COUNT_HEADER = "| Family | Tools | Write tools | Covers |"
_FAMILY_COUNT_ROW_RE = re.compile(r"^\| `([a-z_]+)` \| \d+ \| \d+ \| (.*) \|$", re.M)
SWITCH_TABLE_HEADER = "| Setting | Write tools hidden | Tools listed |"
_SWITCH_ROW_RE = re.compile(r"^\| (none \(default\)|`([A-Z_]+)=[01]`) \| \d+ \| \d+ \|$", re.M)
_FAMILY_ROW_RE = re.compile(
    r"^\| (unset \(all families\)|`([a-z_,]+)`) \| (\d+) \| ~(\d+) KB \|$", re.M
)
_MODE_ROW_RE = re.compile(
    r"^\| `(full|discovery)`( \(default\))? \| \d+ \| \d+ \| \d+ \| ~\d+ KB \|$", re.M
)
DOMAIN_TABLE_HEADER = "| Domain | Domain tools available | Purpose |"
_DOMAIN_ROW_RE = re.compile(r"^\| \*\*([^|]+)\*\* \| (\d+) \|", re.M)
_RELEASE_RE = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.M)
# The figures render_changelog maintains in the release section. lane_gate masks them, so
# regenerating them is not a hand edit of CHANGELOG.md.
CHANGELOG_FIGURE_PATTERNS = (
    r"Highlights: \d+ tools",
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
    families: str | None, mode: str = "full", *, compact_result: bool = False
) -> tuple[int, int]:
    """(tool count, bytes) of ``tools/list`` from the stdio entry point."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "MCP_", "FASTMCP_"))}
    env["UNIFI_API_KEY"] = "catalog-figures-placeholder-key"
    env["UNIFI_TOOL_MODE"] = mode
    if families is not None:
        env["UNIFI_TOOL_FAMILIES"] = families
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
    return len(result["tools"]), size


def shape_totals() -> tuple[int, int, int]:
    """(shaped body parameters, free-form object parameters, compact bytes of all shapes)."""
    sys.path.insert(0, str(ROOT / "src"))
    from unifi_fabric._tool_shapes_table import SHAPE_SOURCES, TOOL_SHAPES

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
            "create_traffic_rule",
            "update_traffic_rule",
            "delete_traffic_rule",
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
        modules=("protect_private", "protect_camera_recording", "protect_device_lifecycle"),
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
    Domain("Statistics, History & Logs", modules=("statistics", "system_log")),
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
            label = next(
                (
                    d.label
                    for d in domains
                    if module in d.modules or (module == "server" and delegate in d.delegates)
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
    hides (``None``: the default, 0). Measured with the selection functions the server runs
    at startup, on a copy of the registered catalog, with every ``UNIFI_*`` switch unset but
    the one measured."""
    import asyncio

    sys.path.insert(0, str(ROOT / "src"))
    from fastmcp import FastMCP

    import unifi_fabric.server as server
    from unifi_fabric import switches
    from unifi_fabric.families import ALL_FAMILIES, build_family_index
    from unifi_fabric.read_only_tools import (
        _is_read_tool,
        apply_area_opt_out_tool_filter,
        apply_read_only_tool_filter,
    )
    from unifi_fabric.tools.connector import CONNECTOR_WRITE_ENV

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
            for env in [s.env for s in switches.AREA_WRITE_SWITCHES] + [CONNECTOR_WRITE_ENV]:
                for name in [k for k in os.environ if k.startswith("UNIFI_")]:
                    del os.environ[name]
                os.environ[env] = "0"
                hidden[env] = len(
                    await apply_area_opt_out_tool_filter(copy(), env != CONNECTOR_WRITE_ENV)
                )
            hidden[switches.READ_ONLY_ENV] = len(await apply_read_only_tool_filter(copy(), True))
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


def measure(readme: str) -> Figures:
    families = listed_families(readme)
    jobs: dict[tuple[str, str | None], Callable[[], tuple[int, int]]] = {
        ("family", fam): (lambda fam=fam: _measure(fam)) for fam in families
    }
    for mode in ("full", "discovery"):
        jobs[("mode", mode)] = lambda mode=mode: _measure(None, mode, compact_result=True)
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
    )


def _sub(text: str, pattern: str, repl: Callable[[re.Match[str]], str], where: str) -> str:
    new, count = re.subn(pattern, repl, text)
    if count == 0:
        raise RuntimeError(f"{where}: no figure matched {pattern!r}; update the generator")
    return new


def render_install_versions(text: str, version: str) -> str:
    """Refresh package pins, image tags and release bundle links from project metadata."""
    patterns = (
        r"(unifi-fabric-mcp-server==)\d+\.\d+\.\d+",
        r"(ghcr\.io/[^/\s]+/unifi-fabric-mcp-server:)\d+\.\d+\.\d+",
        r"(releases/download/v)\d+\.\d+\.\d+",
        r"(/unifi-fabric-)\d+\.\d+\.\d+(?=\.mcpb)",
    )
    for pattern in patterns:
        text = re.sub(pattern, lambda m: m[1] + version, text)
    return text


def render_readme(text: str, fig: Figures) -> str:
    t = str(fig.tools)
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    text = render_install_versions(text, version)
    text = _sub(
        text,
        r"\*\* \d+ tools across Site Manager",
        lambda m: f"** {t} tools across Site Manager",
        "README",
    )
    text = _sub(text, r"(?m)^- \d+ tools across", lambda m: f"- {t} tools across", "README")
    text = _sub(
        text,
        r"By default the client sees \d+ discovery meta-tools",
        lambda m: f"By default the client sees {fig.modes['discovery'][0]} discovery meta-tools",
        "README",
    )
    text = _sub(
        text,
        r"Discovery mode advertises \d+ tools in about \d+ KB while reaching the full catalog; "
        r"full mode uses about \d+ KB\.",
        lambda m: (
            f"Discovery mode advertises {fig.modes['discovery'][0]} tools in about "
            f"{_kb(fig.modes['discovery'][1])} KB "
            f"while reaching the full catalog; full mode uses about {_kb(fig.modes['full'][1])} KB."
        ),
        "README",
    )

    text = _sub(
        text, r"\*\*\d+ tools\*\* organized", lambda m: f"**{t} tools** organized", "README"
    )
    text = _sub(
        text, r"including all \d+ tool names", lambda m: f"including all {t} tool names", "README"
    )
    text = _sub(
        text,
        r"full mode advertises \d+ tools and its",
        lambda m: f"full mode advertises {t} tools and its",
        "README",
    )
    text = _sub(
        text,
        r"`tools/list` response is roughly \d+ KB of JSON",
        lambda m: f"`tools/list` response is roughly {fig.full_kb} KB of JSON",
        "README",
    )
    text = _sub(
        text,
        r"the \d+(\s+)pinned-spec(\s+)request(\s+)bodies([^(]*)"
        r"\([\d,]+(\s+)bytes(\s+)of(\s+)compact(\s+)JSON",
        lambda m: (
            f"the {fig.shaped}{m[1]}pinned-spec{m[2]}request{m[3]}bodies{m[4]}"
            f"({fig.shape_bytes:,}{m[5]}bytes{m[6]}of{m[7]}compact{m[8]}JSON"
        ),
        "README",
    )

    start, end = _table_block(text, SWITCH_TABLE_HEADER)
    switch_rows = [m.group(2) for m in _SWITCH_ROW_RE.finditer(text[start:end])]
    if switch_rows != list(fig.hidden):
        raise RuntimeError(
            f"README opt-out table rows must be {list(fig.hidden)}, in order; got {switch_rows}"
        )

    def switch_row(m: re.Match[str]) -> str:
        count = fig.hidden[m.group(2)]
        return f"| {m.group(1)} | {count} | {fig.tools - count} |"

    block = _SWITCH_ROW_RE.sub(switch_row, text[start:end])
    text = text[:start] + block + text[end:]

    groups = {
        "Site Manager and fleet": ("Fleet & Aggregation", "Site Manager"),
        "Protect": tuple(k for k in fig.domains if k.startswith("Protect")),
        "InnerSpace": ("InnerSpace", "Placement Snapshot"),
        "Mobility": ("Mobility",),
        "Carrier Fabric": ("Carrier / ISP Fabric",),
        "Generic connector relay": ("Connector Relay",),
    }
    assigned = {name for names in groups.values() for name in names}
    groups["Network"] = tuple(name for name in fig.domains if name not in assigned)
    product_order = (
        "Site Manager and fleet",
        "Network",
        "Protect",
        "InnerSpace",
        "Mobility",
        "Carrier Fabric",
        "Generic connector relay",
    )
    rows = ["<!-- product-table:start -->", "| Product | Tools |", "|---|---:|"]
    rows += [
        f"| {product} | {sum(fig.domains[n] for n in groups[product])} |"
        for product in product_order
    ]
    rows.append("<!-- product-table:end -->")
    text = re.sub(
        r"<!-- product-table:start -->.*?<!-- product-table:end -->",
        lambda _: "\n".join(rows),
        text,
        flags=re.S,
    )

    match = re.search(
        r"<!-- live-evidence: passed=(\d+) writes=(\d+) total=(\d+) "
        r"build=([0-9a-f]+) date=(\d{4}-\d{2}-\d{2}) -->",
        COVERAGE.read_text(),
    )
    if not match:
        raise RuntimeError("COVERAGE live evidence marker is missing")
    passed, writes, total, build, date = match.groups()
    verification = "\n".join(
        (
            "<!-- verification-status:start -->",
            "| Evidence | Result |",
            "|---|---|",
            f"| Every tool runs in CI against a simulated upstream | {t} tools |",
            f"| Live-tested on a real console | {passed} of {total} passed on build "
            f"`{build}`, {date} |",
            f"| Live write tools passed | {writes} on that build and date |",
            "<!-- verification-status:end -->",
        )
    )
    text = re.sub(
        r"<!-- verification-status:start -->.*?<!-- verification-status:end -->",
        lambda _: verification,
        text,
        flags=re.S,
    )

    start, end = _table_block(text, DOMAIN_TABLE_HEADER)
    labels = [label.strip() for label, _ in _DOMAIN_ROW_RE.findall(text[start:end])]
    if labels != list(fig.domains):
        raise RuntimeError(
            "README domain table rows differ from DOMAINS (labels and order must match): "
            f"README {labels}, DOMAINS {list(fig.domains)}"
        )

    def domain_row(m: re.Match[str]) -> str:
        return f"| **{m.group(1)}** | {fig.domains[m.group(1).strip()]} |"

    block = _DOMAIN_ROW_RE.sub(domain_row, text[start:end])
    text = text[:start] + block + text[end:]

    return text


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
    return text[:start] + block + text[end:]


def render_annotations(text: str, fig: Figures, where: str) -> str:
    text = _sub(
        text,
        CHANGELOG_FIGURE_PATTERNS[2],
        lambda m: f"Tool annotations: the {fig.read_only} read-only tools",
        where,
    )
    return _sub(
        text,
        CHANGELOG_FIGURE_PATTERNS[3],
        lambda m: f"the {fig.writes} write tools advertise",
        where,
    )


def render_changelog(text: str, fig: Figures) -> str:
    """Rewrite figures in the current (first numbered) release section only.

    The body-shape figures live in docs/MIGRATING-0.7.md (render_migrating).
    """
    headings = list(_RELEASE_RE.finditer(text))
    if not headings:
        raise RuntimeError("CHANGELOG has no numbered release section")
    start = headings[0].start()
    end = headings[1].start() if len(headings) > 1 else len(text)
    section = text[start:end]
    t = str(fig.tools)
    section = _sub(
        section, CHANGELOG_FIGURE_PATTERNS[0], lambda m: f"Highlights: {t} tools", "CHANGELOG"
    )
    section = _sub(
        section,
        CHANGELOG_FIGURE_PATTERNS[1],
        lambda m: (
            f"({t}{m[1]}tools,{m[2]}about{m[3]}{fig.full_kb}{m[4]}KB{m[5]}of{m[6]}`tools/list`)"
        ),
        "CHANGELOG",
    )
    section = render_annotations(section, fig, "CHANGELOG")
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

    return text


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


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--check", action="store_true", help="fail when any figure is stale")
    args = parser.parse_args()

    readme, changelog = README.read_text(), CHANGELOG.read_text()
    fig = measure(CATALOG.read_text())
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    outputs = {
        README: render_readme(readme, fig),
        CATALOG: render_catalog(CATALOG.read_text(), fig),
        DOCKER: render_install_versions(DOCKER.read_text(), version),
        BUNDLE_README: render_install_versions(BUNDLE_README.read_text(), version),
        CHANGELOG: render_changelog(changelog, fig),
        MIGRATING: render_migrating(MIGRATING.read_text(), fig),
        COVERAGE: render_coverage(COVERAGE.read_text(), fig),
        CONFIGURATION: render_configuration(CONFIGURATION.read_text(), fig),
        SITE_STATS: render_site_stats(version, fig.tools, COVERAGE.read_text()),
    }
    summary = (
        f"{fig.tools} tools; full tools/list ~{fig.full_kb} KB; "
        f"modes {json.dumps(fig.modes)}; shapes {fig.shaped} shaped, {fig.free} free, "
        f"{fig.shape_bytes:,} bytes"
    )
    stale = [path for path, new in outputs.items() if path.read_text() != new]
    if args.check:
        if stale:
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


if __name__ == "__main__":
    raise SystemExit(main())
