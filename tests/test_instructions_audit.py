"""Tier-1 schema<->INSTRUCTIONS cross-checks.

The server ``INSTRUCTIONS`` block is agent-facing documentation: an agent reads it and
calls the tools it names. Two independent defect classes can make it lie, and this file
carries a gate for each:

1. **Phantom names** — INSTRUCTIONS names a tool that is not registered, so the agent gets
   ``tool-not-found`` with no recovery path. ``test_instructions_names_no_phantom_tools``
   parses every tool reference and asserts each is really registered.

2. **Wrong parameter-scope claims** — a real tool is filed under a bucket ("host + site
   required", "host only", "no host/site") that disagrees with its registered ``host``/
   ``site`` parameters. ``test_instructions_param_scope_matches_schema`` compares each
   explicitly-filed tool's bucket against its live schema.

**Documented blind spot.** The phantom-name check verifies tool *names* only; it says
nothing about whether the *claims* around those names are true, so a green phantom-name
check is not evidence that INSTRUCTIONS is accurate. The parameter-scope check closes that
gap for the one prose-claim class that is mechanically verifiable (the schema knows the
true required params). Prose claims about what a tool *does*, what a field *means*, or
workflow ordering remain unchecked by any static test and still need human review — do not
read a green suite as "all of INSTRUCTIONS is correct". See ``_instructions_audit`` module
docstring for the full rationale and the historical defect that motivated the split.

Both gates run on every PR with no live server and no credentials — they introspect the
imported FastMCP instance directly, which is the authoritative registered tool set. That
makes them strictly cheaper than the live ``docs/internal/check_instructions_tools.py``
variant while catching the same phantom-tool class (e.g. the ``update_radius_profile`` /
``delete_radius_profile`` references that named tools which were never built).
"""

from __future__ import annotations

import asyncio
import inspect

from unifi_fabric import server
from unifi_fabric._instructions_audit import (
    instruction_tool_refs,
    param_scope_violations,
    parse_param_scope_buckets,
    phantom_tool_refs,
    tool_verbs,
)


def _registered_tools() -> list:
    """Authoritative registered tool objects from the imported FastMCP instance."""
    result = server.mcp.list_tools()
    if inspect.isawaitable(result):
        result = asyncio.run(result)
    return list(result)


def _registered_tool_names() -> list[str]:
    """Authoritative registered tool names from the imported FastMCP instance."""
    return [tool.name for tool in _registered_tools()]


def _registered_tool_params() -> dict[str, set[str]]:
    """Map each registered tool name to its parameter names from the live schema."""
    return {
        tool.name: set((tool.parameters or {}).get("properties", {}).keys())
        for tool in _registered_tools()
    }


# ---------------------------------------------------------------------------
# The gate: every tool named in INSTRUCTIONS must be registered
# ---------------------------------------------------------------------------


def test_instructions_names_no_phantom_tools() -> None:
    names = _registered_tool_names()
    assert names, "no tools registered — introspection is broken"
    phantoms = phantom_tool_refs(server.INSTRUCTIONS, names)
    assert phantoms == [], (
        "INSTRUCTIONS references tool name(s) that are not registered: "
        f"{phantoms}. Either build the tool(s) or remove the reference from the "
        "INSTRUCTIONS constant in server.py."
    )


# ---------------------------------------------------------------------------
# The gate: every tool's parameter-scope bucket must match its real schema
# ---------------------------------------------------------------------------


def test_instructions_param_scope_matches_schema() -> None:
    tool_params = _registered_tool_params()
    assert tool_params, "no tools registered — introspection is broken"
    violations = param_scope_violations(server.INSTRUCTIONS, tool_params)
    assert violations == [], (
        "INSTRUCTIONS 'Parameter Scope Quick Reference' files tool(s) under a bucket that "
        "disagrees with their registered host/site parameters:\n  "
        + "\n  ".join(violations)
        + "\nMove the tool to the correct bucket in the INSTRUCTIONS constant in server.py."
    )


def test_param_scope_buckets_are_populated() -> None:
    # Guard against the section header being renamed/removed and the check silently
    # degrading to a no-op: the three buckets must parse and name real tools.
    buckets = parse_param_scope_buckets(server.INSTRUCTIONS)
    assert set(buckets) == {"host + site required", "host only", "no host/site"}
    registered = set(_registered_tool_names())
    # 'no host/site' names its members only by category, so it may be empty; the other two
    # explicitly name tools that must resolve to real registrations.
    assert buckets["host + site required"] & registered
    assert buckets["host only"] & registered


# ---------------------------------------------------------------------------
# Unit tests for the extraction helpers (lock behaviour + no false positives)
# ---------------------------------------------------------------------------


def test_tool_verbs_derives_leading_segments() -> None:
    assert tool_verbs(["list_hosts", "get_host", "delete_vpn_server"]) == {
        "list",
        "get",
        "delete",
    }
    # single-word names have no verb segment and are ignored
    assert tool_verbs(["hosts"]) == set()


def test_instruction_tool_refs_ignores_param_and_field_names() -> None:
    text = (
        "Use `list_hosts` then `get_host`. Pass `page_token` for paging and read "
        "`siteId` / `hostId`. Set `interval='5m'`."
    )
    verbs = {"list", "get"}
    refs = instruction_tool_refs(text, verbs)
    assert refs == {"list_hosts", "get_host"}
    # page_token is snake_case but 'page' is not a tool verb -> excluded
    assert "page_token" not in refs


def test_phantom_tool_refs_flags_unregistered_reference() -> None:
    text = "Real: `update_vpn_server`. Phantom: `update_radius_profile`."
    registered = ["update_vpn_server", "list_radius_profiles"]
    assert phantom_tool_refs(text, registered) == ["update_radius_profile"]


def test_phantom_tool_refs_empty_when_all_present() -> None:
    text = "`list_hosts` and `get_host` are both real."
    assert phantom_tool_refs(text, ["list_hosts", "get_host"]) == []


# ---------------------------------------------------------------------------
# Unit tests for the parameter-scope parser + violation detector
# ---------------------------------------------------------------------------

_SCOPE_FIXTURE = (
    "## Parameter Scope Quick Reference\n"
    "- **host + site required**: network tools, `list_lags`, `get_lag`\n"
    "- **host only** (no site): `list_devices`, `list_cameras`\n"
    "- **no host/site** (global EA API): fleet/aggregation tools\n"
    "\n"
    "## Next Section\n"
    "- **host only**: `should_not_be_parsed`\n"
)


def test_parse_param_scope_buckets_extracts_explicit_names_only() -> None:
    buckets = parse_param_scope_buckets(_SCOPE_FIXTURE)
    assert buckets["host + site required"] == {"list_lags", "get_lag"}
    assert buckets["host only"] == {"list_devices", "list_cameras"}
    # category-only bucket names no backtick tools
    assert buckets["no host/site"] == set()
    # parsing stops at the next '## ' header
    assert "should_not_be_parsed" not in buckets["host only"]


def test_param_scope_violations_flags_wrong_bucket() -> None:
    # `list_devices` is host-only but is mis-filed as host+site required here.
    text = "## Parameter Scope Quick Reference\n- **host + site required**: `list_devices`\n"
    params = {"list_devices": {"host", "page_token"}}
    violations = param_scope_violations(text, params)
    assert len(violations) == 1
    assert "list_devices" in violations[0]
    assert "site" in violations[0]


def test_param_scope_violations_flags_ghost_host_site_on_global_tool() -> None:
    # A tool filed under 'no host/site' that actually requires both is the exact defect
    # class that motivated this check.
    text = "## Parameter Scope Quick Reference\n- **no host/site**: `update_vpn_server`\n"
    params = {"update_vpn_server": {"host", "site", "server_id", "fields"}}
    violations = param_scope_violations(text, params)
    assert len(violations) == 2  # both host and site are forbidden here but present


def test_param_scope_catches_historical_id_only_defect() -> None:
    # Regression: the scope marker lived in the parenthetical, not the bold label. The
    # parser must still bucket it and flag the ghost host/site params.
    text = (
        "## Parameter Scope Quick Reference\n"
        "- **ID only** (no host/site): `update_vpn_server`, `delete_hotspot_operator`\n"
    )
    params = {
        "update_vpn_server": {"host", "site", "server_id"},
        "delete_hotspot_operator": {"host", "site", "operator_id"},
    }
    violations = param_scope_violations(text, params)
    # each tool wrongly forbidden host AND site -> 2 violations apiece
    assert len(violations) == 4


def test_param_scope_violations_skips_unregistered_tools() -> None:
    # Unregistered names are the phantom class; the scope check leaves them alone.
    text = "## Parameter Scope Quick Reference\n- **host only**: `list_phantom_thing`\n"
    assert param_scope_violations(text, {"list_devices": {"host"}}) == []


def test_param_scope_violations_empty_when_consistent() -> None:
    text = (
        "## Parameter Scope Quick Reference\n"
        "- **host + site required**: `update_vpn_server`\n"
        "- **host only**: `list_devices`\n"
        "- **no host/site**: `list_hosts`\n"
    )
    params = {
        "update_vpn_server": {"host", "site", "server_id"},
        "list_devices": {"host", "page_token"},
        "list_hosts": {"page_token"},
    }
    assert param_scope_violations(text, params) == []
