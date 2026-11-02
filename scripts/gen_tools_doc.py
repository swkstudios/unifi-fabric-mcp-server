#!/usr/bin/env python3
"""Generate docs/TOOLS.md from FastMCP runtime tool metadata."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
DOCS_PATH = ROOT / "docs" / "TOOLS.md"
#: Prose files whose "this release's N tools" phrase names the current catalog size; the
#: generator rewrites it from the registry and ``--check`` fails when it drifts.
RELEASE_COUNT_FILES = (ROOT / "docs" / "COVERAGE.md",)
RELEASE_COUNT_RE = re.compile(r"(this release's )(\d+)( tools\b)")


def _tool_name(tool: Any) -> str:
    return str(getattr(tool, "name", ""))


def _tool_description(tool: Any) -> str:
    return str(getattr(tool, "description", "") or "").strip()


def _type_label(schema: dict[str, Any] | None) -> str:
    if not schema:
        return "unknown"
    if "type" in schema:
        return str(schema["type"])
    if "const" in schema:
        return "constant"
    if "enum" in schema:
        return "enum"
    for union_key in ("anyOf", "oneOf"):
        variants = schema.get(union_key)
        if isinstance(variants, list):
            return " | ".join(_type_label(item) for item in variants if isinstance(item, dict))
    if "$ref" in schema:
        return str(schema["$ref"]).rsplit("/", maxsplit=1)[-1]
    return "any JSON value"


def _escape_table_cell(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>")


def _default_label(value: Any) -> str:
    if isinstance(value, str):
        if value == "":
            return '`""`'
        return f"`{_escape_table_cell(value)}`"
    if value is None:
        return "`null`"
    return f"`{_escape_table_cell(json.dumps(value, sort_keys=True))}`"


def _parameter_descriptions(description: str, parameter_names: set[str]) -> dict[str, str]:
    """Extract simple ``name: description`` lines from tool docstrings."""

    descriptions: dict[str, str] = {}
    last_name: str | None = None
    for line in description.splitlines():
        stripped = line.strip()
        pattern = r"(?:^|\s)([a-zA-Z_][a-zA-Z0-9_]*):\s*"
        matches = [
            match for match in re.finditer(pattern, stripped) if match.group(1) in parameter_names
        ]
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(stripped)
            descriptions[match.group(1)] = stripped[match.end() : end].strip()
            last_name = match.group(1)
        if (
            not matches
            and last_name is not None
            and descriptions[last_name].count("(") > descriptions[last_name].count(")")
        ):
            descriptions[last_name] = f"{descriptions[last_name]} {stripped}".strip()
    return descriptions


def _parameter_table(tool: Any) -> list[str]:
    parameters = getattr(tool, "parameters", None) or {}
    properties = parameters.get("properties") or {}
    if not properties:
        return ["No parameters."]

    required = set(parameters.get("required") or [])
    doc_descriptions = _parameter_descriptions(_tool_description(tool), set(properties))
    lines = [
        "| Name | Type | Required | Default | Description |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name, schema in properties.items():
        if not isinstance(schema, dict):
            schema = {}
        default = _default_label(schema["default"]) if "default" in schema else ""
        # Docstring Args entries wrap across lines; collapse to one table-cell line.
        description = " ".join(
            str(schema.get("description") or doc_descriptions.get(name) or "").split()
        )
        lines.append(
            f"| `{_escape_table_cell(name)}` | `{_escape_table_cell(_type_label(schema))}` | "
            f"{'yes' if name in required else 'no'} | {default} | "
            f"{_escape_table_cell(description)} |"
        )
    return lines


ANNOTATION_HEADER = "| readOnly | destructive | idempotent | openWorld |"


def _annotation_table(tool: Any) -> list[str]:
    """The tool's four MCP annotation hints as advertised by the runtime."""
    hints = tool.annotations.model_dump(by_alias=True) if tool.annotations else {}
    cells = [
        str(hints.get(key)).lower()
        for key in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
    ]
    return [ANNOTATION_HEADER, "| --- | --- | --- | --- |", "| " + " | ".join(cells) + " |"]


def _return_type(tool: Any) -> str:
    return_type = getattr(tool, "return_type", None)
    if return_type is not None:
        if isinstance(return_type, type):
            return return_type.__name__
        return str(return_type).replace("typing.", "")
    output_schema = getattr(tool, "output_schema", None) or {}
    return _type_label(output_schema)


# ---------------------------------------------------------------------------
# README domain table vs. TOOLS.md operation-type categories
#
# _category() below groups tools by *operation type* (prefix-based) for
# TOOLS.md.  The README's domain table ("Protect", "Fleet & Aggregation",
# etc.) uses a separate, editorial grouping by *functional/product area*.
# These two taxonomies are independent; every tool is counted exactly once
# in the README table regardless of its operation-type category.
#
# README domain membership is determined by which UniFi application family a
# tool serves, not by its name prefix.  When the two are ambiguous — most
# notably get_thumbnail, which returns a Protect detection crop but carries no
# Protect-specific keyword in its name — the tool belongs to whichever domain
# owns the resource (Protect, in that case: thumbnailId originates from
# list_protect_events / list_recognition_detections).  The canonical boundary
# for the Protect row: cameras, sensors, lights, chimes, liveviews, PTZ,
# RTSPS streams, snapshots, historical events (list_protect_events),
# face/vehicle recognition, arm profiles, sirens, fobs, Protect relays,
# speakers, bridges, link stations, alarm hubs, Protect users, ULP users,
# application metadata (get_protect_application_info), POS overlay ingestion,
# and detection thumbnails (get_thumbnail).
# ---------------------------------------------------------------------------
def _category(tool_name: str) -> str:
    if tool_name.startswith("list_"):
        return "Listing & Discovery"
    if tool_name.startswith(("get_", "download_")):
        return "Reading & Inspection"
    if tool_name.startswith(("create_", "upload_")):
        return "Create"
    if tool_name.startswith(("update_", "patch_")):
        return "Update"
    if tool_name.startswith("delete_"):
        return "Delete"
    if tool_name.startswith(("execute_", "trigger_", "start_", "disable_")):
        return "Execute & Actions"
    if tool_name.startswith("search_"):
        return "Search"
    if tool_name.startswith(("block_", "unblock_", "reconnect_")):
        return "Client Management"
    if tool_name.startswith(("adopt_", "unadopt_", "restart_", "upgrade_")):
        return "Device Management"
    if tool_name.startswith(("ptz_", "locate_")):
        return "Device Control"
    if tool_name.startswith("set_"):
        return "Configuration"
    return "Other"


async def _runtime_tools() -> list[Any]:
    # The reference documents domain tools regardless of the startup default.
    os.environ["UNIFI_TOOL_MODE"] = "full"
    sys.path.insert(0, str(SRC))
    from unifi_fabric.server import mcp

    return sorted(await mcp.list_tools(), key=_tool_name)


def _anchor(text: str) -> str:
    return re.sub(r"[^a-z0-9 -]", "", text.lower()).replace(" ", "-")


#: Tool metadata key carrying the API-source class (unifi_fabric.api_sources.META_CLASS).
API_SOURCE_META = "unifi/apiSource"


def _api_source(tool: Any) -> str:
    """The tool's ``app/source/access`` class from its metadata (``unclassified`` if none)."""
    meta = getattr(tool, "meta", None) or {}
    return str(meta.get(API_SOURCE_META) or "unclassified")


def _api_source_section(tools: list[Any]) -> list[str]:
    """Tools grouped by app, then source (official / private), then read / write."""
    tree: dict[str, dict[str, dict[str, list[str]]]] = {}
    for tool in tools:
        cls = _api_source(tool)
        app, source, access = (cls.split("/") + ["?", "?"])[:3]
        tree.setdefault(app, {}).setdefault(source, {}).setdefault(access, []).append(
            _tool_name(tool)
        )
    lines = [
        "## Tools by API source",
        "",
        (
            "Every tool is classified as `<app>/<source>/<access>` from the routes it calls "
            "(the `unifi/apiSource` tool metadata). `official` is a published Ubiquiti API; "
            "`private` and `private.<surface>` are the routes the controller web UIs call "
            "(no published spec); `relay/generic` is the generic connector relay. "
            "`UNIFI_DISABLE_API_SOURCES` disables any app, source or access level "
            "(see docs/CONFIGURATION.md); everything is enabled by default."
        ),
        "",
    ]
    for app in sorted(tree):
        total = sum(len(names) for src in tree[app].values() for names in src.values())
        lines.append(f"**{app}** ({total} tools)")
        lines.append("")
        for source in sorted(tree[app], key=lambda s: (s != "official", s)):
            for access in sorted(tree[app][source]):
                names = sorted(tree[app][source][access])
                links = ", ".join(f"[`{n}`](#{n.lower()})" for n in names)
                lines.append(f"- `{app}/{source}/{access}` ({len(names)}): {links}")
        lines.append("")
    return lines[:-1]


def _access(tool: Any) -> str:
    """``read`` for a tool annotated ``readOnlyHint`` true, else ``write``.

    The mixed GET relay (``fabric_connector_get``) is listed as ``read``, matching selector
    filtering and the published ``unifi/apiSource`` class (``selection_access``).

    The annotation is derived from the tool's upstream calls, not hand-kept
    (``tests/test_tool_schema_contract.py`` checks it against the source).
    """
    sys.path.insert(0, str(SRC))
    from unifi_fabric.api_sources import selection_access

    return selection_access(tool)


def _family_index() -> dict[str, str]:
    """``tool -> family`` (``unifi_fabric.families``): the names UNIFI_TOOL_FAMILIES takes."""
    sys.path.insert(0, str(SRC))
    from unifi_fabric.families import build_family_index

    return build_family_index()


def _family_section(tools: list[Any], families: dict[str, str]) -> list[str]:
    """Tools grouped by family (the names the family variables take)."""
    groups: dict[str, list[str]] = {}
    for tool in tools:
        groups.setdefault(families.get(_tool_name(tool), "unclassified"), []).append(
            _tool_name(tool)
        )
    lines = [
        "## Tools by family",
        "",
        (
            "Every tool is in one family, the name `UNIFI_TOOL_FAMILIES` and "
            "`UNIFI_DISABLED_TOOL_FAMILIES` take (separated by commas or whitespace, any "
            "letter case). `firewall` is assigned by route: a tool that calls a firewall "
            "policy, firewall zone, ACL rule or classic firewall rule or group route is in "
            "`firewall`. Every family is enabled by default; `list_tool_families` reports the "
            "families and counts of the running catalog."
        ),
        "",
    ]
    for family in sorted(groups):
        names = sorted(groups[family])
        links = ", ".join(f"[`{n}`](#{n.lower()})" for n in names)
        lines.append(f"- `{family}` ({len(names)}): {links}")
    return lines


def _access_index_section(tools: list[Any]) -> list[str]:
    """One row per tool: name (linked to its entry), family and access."""
    families = _family_index()
    lines = [
        "## Tool access index",
        "",
        (
            "Every tool with its family (the name `UNIFI_TOOL_FAMILIES` and "
            "`UNIFI_DISABLED_TOOL_FAMILIES` take) and its access: `read` tools make no "
            "change upstream (`readOnlyHint` true, or the mixed `fabric_connector_get` relay, "
            "which is selected as read) and stay available in read-only mode "
            "(`UNIFI_READ_ONLY`); `write` tools change state and are enabled by default."
        ),
        "",
        "| Tool | Family | Access |",
        "|---|---|---|",
    ]
    for tool in tools:
        name = _tool_name(tool)
        family = families.get(name, "unclassified")
        lines.append(f"| [`{name}`](#{name.lower()}) | `{family}` | {_access(tool)} |")
    return lines


def render_markdown(tools: list[Any]) -> str:
    families = _family_index()
    categories: dict[str, list[Any]] = {}
    for tool in tools:
        categories.setdefault(_category(_tool_name(tool)), []).append(tool)

    lines = [
        "# UniFi Fabric MCP Server - Tools Reference",
        "",
        "<!-- This file is generated by scripts/gen_tools_doc.py. Do not edit by hand. -->",
        "",
        "Reference manual for every tool registered with the FastMCP runtime.",
        "",
        "Discovery mode is the default: use search_tools, describe_tool, "
        "call_read_tool and call_write_tool "
        "to discover and invoke these same tools through a compact catalog. "
        "Set UNIFI_TOOL_MODE=full to advertise the complete catalog. "
        "UNIFI_TOOL_FAMILIES and UNIFI_DISABLED_TOOL_FAMILIES select the available families "
        "in either mode; UNIFI_READ_ONLY and the per-area write opt-outs hide the write "
        "tools they refuse.",
        "",
        *_access_index_section(tools),
        "",
        "## Linked-page logical windows",
        "",
        "For linked-page collections (recognition groups, recognition detections, and "
        "case activity), `page_size=N` selects records `[(page-1)*N, page*N)` "
        "with page 1 as the default. Console page sizes may be smaller; the server "
        "gathers only the pages intersecting that logical window after probing the "
        "effective size. `_pageSize` reports every wire size and the effective size. "
        "Resume from `_nextPage` with the same `page_size` to concatenate contiguous, "
        "disjoint windows. Passing `page` alone still selects one native console page; "
        "omitting both arguments drains every page. An ambiguous terminal probe may "
        "require one discovery request to page 1, and every request shares the configured "
        "page budget.",
        "",
        "## Filter expressions (`filter` parameter)",
        "",
        (
            "Several collection tools accept a `filter` expression forwarded unchanged "
            "to the upstream UniFi Integration API. Cautions:"
        ),
        "",
        (
            "- **Filter properties are per-schema \u2014 there is no universal set.** A "
            "property valid on one endpoint is rejected on another: e.g. "
            "`enabled.eq(true)` is valid on `list_wifi_broadcasts` but returns HTTP 400 "
            "`unknown filter property 'enabled'` on `list_firewall_policies`. Use only "
            "properties that appear on that endpoint's own records."
        ),
        (
            "- **No conjunction operator.** The grammar has no `and`/`&&` (both return "
            "HTTP 400), so two conditions cannot be composed into a single `filter` "
            "expression."
        ),
        (
            "- **A valid property with a non-matching value returns an empty set, not "
            'an error.** `{data: [], totalCount: 0}` can mean either "no records '
            'match" or "the value never matches this field"; it is not proof the '
            "filter is malformed. Only an *invalid property* raises HTTP 400."
        ),
        (
            "- Each tool's own docstring lists live-verified example expressions valid "
            "for that endpoint."
        ),
        "",
        "## Enabling / disabling connector writes",
        "",
        (
            "The generic Fabric connector relay exposes four mutating tools "
            "(`fabric_connector_post`, `fabric_connector_put`, `fabric_connector_patch`, "
            "`fabric_connector_delete`). Read and write are enabled by default; one "
            "deployment control applies:"
        ),
        "",
        (
            "1. **`UNIFI_ENABLE_CONNECTOR_WRITE` \u2014 a deployment capability flag, "
            "ENABLED by default.** With the variable unset, connector writes are enabled "
            "and no action is needed for write capability. For a deliberate read-only "
            'deployment, set it to `"0"` in the environment of the process that starts the '
            "server; the server reads it from its environment. For a Compose deployment "
            "that is the **service's `environment:` block of the docker-compose file that "
            "deploys this server** (then recreate the container); for a local install it is "
            "the client's server `env` block or a shell `export` before the client starts. "
            "It is not set in the application source. Accepted values: unset / `1` / "
            "`true` / `yes` / `on` enable writes; `0` / `false` / `no` / `off` disable them."
        ),
        "",
        "   Compose example (read-only opt-out):",
        "",
        "   ```yaml",
        "   services:",
        "     unifi-fabric-mcp:",
        "       environment:",
        '         UNIFI_ENABLE_CONNECTOR_WRITE: "0"   # read-only: refuse connector mutations',
        "   ```",
        "",
        (
            "   If this server shares a network namespace with a sidecar (for example a "
            '`ghostunnel` proxy via `network_mode: "service:..."`), restart the whole '
            "compose group together, not the app container alone. To re-enable, remove "
            'the variable or set it to `"1"`, with the same restart rule.'
        ),
        "",
        (
            "2. **`confirm` \u2014 accepted and ignored.** The "
            "`confirm` argument is still accepted on the mutating relay tools so existing "
            "callers do not break, but it is ignored: the mutation runs whenever the "
            "capability flag is enabled, whether or not `confirm` is passed."
        ),
        "",
        (
            "When writes are disabled, the write tools this flag governs are hidden from "
            "`tools/list` and from discovery search at startup. A call to one by name is "
            "refused before the console is touched and audited, and the refusal message "
            "names `UNIFI_ENABLE_CONNECTOR_WRITE` and points back to this section."
        ),
        "",
        (
            "**Scope.** `UNIFI_ENABLE_CONNECTOR_WRITE` governs the four generic "
            "connector relay mutation tools (`fabric_connector_post`, "
            "`fabric_connector_put`, `fabric_connector_patch`, "
            "`fabric_connector_delete`), a `fabric_connector_get` call to a known "
            "state-changing GET route (Protect camera `enable-control` / "
            "`disable-control`), and these typed tools: `update_device_radio`; the Wi-Fi "
            "radio tools `preview_radio_ai_optimization`, `apply_radio_ai_optimization`, "
            "`control_wifi_doctor_optimization`, `start_wifi_quick_scan`, "
            "`start_spectrum_scan` and `configure_wifi_wan`; and the Protect private-API "
            "writes `update_camera_private`, `update_nvr`, `update_sensor_private`, "
            "`reboot_protect_device`, `adopt_protect_device`, `unadopt_protect_device`, "
            "`reboot_nvr` and `clear_sensor_tamper`. All use the same enabled-by-default "
            "flag, and each typed tool also follows its own area's opt-out. Ordinary GET "
            "reads through `fabric_connector_get` stay available. "
            "The InnerSpace typed write tools are governed by "
            "`UNIFI_ENABLE_INNERSPACE_WRITE`, not by this flag. An InnerSpace write path "
            "reached through the generic relay follows the connector write flag, "
            "`UNIFI_ENABLE_INNERSPACE_WRITE` and read-only mode, as other relay "
            "mutations; writes are enabled by default."
        ),
        "",
        f"Total tools: {len(tools)}",
        "",
        "## Tool Categories",
        "",
    ]
    for category in sorted(categories):
        lines.append(f"- [{category}](#{_anchor(category)}) ({len(categories[category])})")
    lines.extend(["", *_api_source_section(tools)])
    lines.extend(["", *_family_section(tools, families)])

    for category in sorted(categories):
        category_tools = categories[category]
        lines.extend(["", "---", "", f"## {category}", "", f"**{len(category_tools)} tools**", ""])
        for tool in category_tools:
            description = _tool_description(tool) or "No description provided."
            lines.extend(
                [
                    f"### `{_tool_name(tool)}`",
                    "",
                    description,
                    "",
                    f"**API source:** `{_api_source(tool)}`",
                    "",
                    f"**Family:** `{families.get(_tool_name(tool), 'unclassified')}`",
                    "",
                    "**Annotations**",
                    "",
                    *_annotation_table(tool),
                    "",
                    "**Parameters**",
                    "",
                    *_parameter_table(tool),
                    "",
                    "**Return type**",
                    "",
                    f"`{_return_type(tool)}`",
                    "",
                ]
            )

    lines.extend(
        [
            "---",
            "",
            "## Usage Notes",
            "",
            "- Tool metadata is read from `await mcp.list_tools()` in "
            "`src/unifi_fabric/server.py`.",
            "- Parameter types and defaults come from FastMCP's runtime schema.",
            "- Annotations are the MCP hints each tool advertises, derived from the "
            "upstream routes it can reach (`src/unifi_fabric/tool_annotations.py`).",
            "- Descriptions come from tool docstrings exposed through FastMCP metadata.",
            "- Run `python3 scripts/gen_tools_doc.py --check` to verify this file has no drift.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _with_release_count(text: str, count: int) -> str:
    return RELEASE_COUNT_RE.sub(lambda m: f"{m.group(1)}{count}{m.group(3)}", text)


def release_count_drift(count: int) -> list[str]:
    """``path:line`` of every release-count phrase that does not equal ``count``."""
    stale = []
    for path in RELEASE_COUNT_FILES:
        for no, line in enumerate(path.read_text().splitlines(), 1):
            if any(int(m.group(2)) != count for m in RELEASE_COUNT_RE.finditer(line)):
                stale.append(f"{path.relative_to(ROOT)}:{no}")
    return stale


def write_release_counts(count: int) -> None:
    for path in RELEASE_COUNT_FILES:
        text = path.read_text()
        updated = _with_release_count(text, count)
        if updated != text:
            path.write_text(updated)


async def generate() -> str:
    tools = await _runtime_tools()
    if not tools:
        raise RuntimeError("No FastMCP tools were registered")
    return render_markdown(tools)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail when docs/TOOLS.md is stale")
    parser.add_argument("--output", type=Path, default=DOCS_PATH)
    args = parser.parse_args()

    content = asyncio.run(generate())
    count = len(asyncio.run(_runtime_tools()))
    if args.check:
        existing = args.output.read_text() if args.output.exists() else ""
        stale = release_count_drift(count)
        if existing != content or stale:
            print(
                f"{args.output} or a release tool count ({', '.join(stale) or 'none'}) is out "
                "of date; run python3 scripts/gen_tools_doc.py",
                file=sys.stderr,
            )
            return 1
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content)
    write_release_counts(count)
    print(f"Generated {args.output} from FastMCP metadata", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
