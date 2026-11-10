"""MCP tool annotations (behaviour hints), derived from source and attached to every tool.

Without annotations, MCP clients apply the protocol defaults to every tool —
``readOnlyHint=false`` and ``destructiveHint=true`` — so a pure read such as
``get_firewall_policy_ordering`` is advertised as a destructive write.

All four hints are explicit on every tool (Anthropic Software Directory Policy 5E), and
none is hand-judged. They come from two source audits in
:mod:`unifi_fabric._read_only_audit`: the write verbs a tool can issue
(:func:`~unifi_fabric._read_only_audit.write_verbs_for`, the same call-graph walk that
protects read-only mode) and whether it reaches the UniFi upstream client
(:func:`~unifi_fabric._read_only_audit.reaches_upstream`).

* ``readOnlyHint``: true when the tool can issue no write verb.
* ``destructiveHint``: false for a read, true for EVERY write. No name or verb carves a
  write out: a create can still replace or collide with live configuration.
* ``idempotentHint``: true for a read, and for a write whose verb set is exactly
  ``{PUT}`` or exactly ``{DELETE}``. A POST, a PATCH, several verbs, a state-changing GET
  (counted as a POST by the audit) and the connector relays (every verb) are false.
* ``openWorldHint``: true when the tool reaches the UniFi upstream, false for a tool that
  only reads local state: ``list_configured_api_keys``, ``get_event_stream_status`` and the
  discovery tools ``search_tools``, ``describe_tool`` and ``list_tool_families``. The
  discovery dispatch tools ``call_read_tool`` and ``call_write_tool`` run domain tools, so
  they are true.

``tests/test_tool_schema_contract.py`` checks every registered tool against this
derivation, including the discovery-mode tools, and ``docs/TOOLS.md`` lists the hints.
"""

from __future__ import annotations

from typing import Any

from mcp.types import ToolAnnotations

from ._read_only_audit import classify_tool_verbs, reaches_upstream

#: Write verb sets whose repetition leaves the upstream as one call left it.
_IDEMPOTENT_WRITES = ({"PUT"}, {"DELETE"})


def for_tool(
    *, verbs: set[str] | None = None, writes: bool | None = None, open_world: bool = True
) -> ToolAnnotations:
    """The annotations for a tool that can issue ``verbs`` (empty: a read).

    Registration decorators that know only whether a tool writes pass ``writes``; the
    installation pass below replaces that provisional value with the route-derived one.
    """
    # Built from the wire (camelCase) names so the same code works with MCP SDK releases
    # that expose the fields as camelCase attributes and with those that use snake_case
    # attributes behind camelCase aliases.
    if verbs is None:
        verbs = {"POST"} if writes else set()
    is_write = bool(verbs)
    return ToolAnnotations.model_validate(
        {
            "readOnlyHint": not is_write,
            "destructiveHint": is_write,
            "idempotentHint": not is_write or verbs in _IDEMPOTENT_WRITES,
            "openWorldHint": open_world,
        }
    )


READ_ONLY = for_tool(verbs=set())
WRITE = for_tool(verbs={"POST"})


def install_tool_annotations(mcp: Any) -> int:
    """Replace decorator defaults with source-derived annotations on every registered tool.

    Fails closed: a FastMCP release without the registry this pass reads raises instead
    of leaving tools on their provisional (or default) hints. Returns the number annotated.
    """
    try:
        from .local_components import tool_components

        tools = tool_components(mcp)
    except AttributeError as exc:
        raise RuntimeError(
            "cannot read the registered tool catalog to annotate it; "
            "FastMCP's local provider layout changed"
        ) from exc
    verbs = classify_tool_verbs(tools)
    for tool in tools:
        tool.annotations = for_tool(verbs=verbs[tool.name], open_world=reaches_upstream(tool.fn))
    return len(tools)
