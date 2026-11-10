"""Compact equivalent selector guidance without removing catalog semantics.

One registration-time pass keeps these agent-facing invariants on the advertised surface:

* Every ``host`` parameter names both accepted console forms, the short
  ``reportedState.hostname`` and the long ``data[].id``. The standard long hint becomes
  :data:`HOST_DESCRIPTION`; each generic short phrasing ("Console name or id from
  list_hosts, e.g. ...") becomes :data:`HOST_SELECTOR`, keeping its own example (and its
  "e.g." or "for example"), its "Protect" qualifier and any tool-specific text after it.
  The selector deliberately adds no common words such as product names or
  "case-insensitive": a term on every tool erases its weight in ``search_tools`` ranking
  ("case" would stop finding Protect cases).
* Every tool names each required parameter in its description. A description that
  leaves one out gets the catalog's ``Required arguments:`` line, listing every required
  parameter in schema order.
* Tool-surface notes (:func:`surface_notes`): the ``_proxy`` suffix, how dry-run is switched
  on, and a one-line disambiguation for each overlapping filtering family are stated once
  here instead of in hundreds of docstrings.
* Final description prose is also the callable docstring prose, with its ``Args:``
  section preserved. Paragraphs about parameter identifiers start complete sentences.
"""

from __future__ import annotations

import inspect
import re
from typing import Any

_ORIGINAL_HOST = (
    "Console name or id: the short name from list_hosts (data[].reportedState.hostname or "
    'reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id '
    "(MAC:numericId composite). One console serves both Network and Protect."
)
HOST_DESCRIPTION = (
    'Console name (case-insensitive reportedState.hostname/name, e.g. "my-console") or '
    "data[].id (MAC:numericId), from list_hosts. Serves Network and Protect."
)
HOST_SELECTOR = (
    "{console} name, MAC or id from list_hosts: reportedState.hostname/name{example} or data[].id."
)
# The generic console-selector phrasings that predate HOST_DESCRIPTION, e.g. 'Console name
# or id from list_hosts, e.g. "my-console".' or 'Protect console name or composite id from
# list_hosts; for example "Home NVR".'. ``rest`` is any tool-specific text after them.
_GENERIC_HOST = re.compile(
    r"(?:Required )?(?P<protect>Protect )?console (?:name or (?:composite )?id|selector)"
    r"(?: from list_hosts| \(list_hosts\))?"
    r"(?:[,;] (?P<lead>e\.g\.|for example) (?P<example>(?P<quote>[\"'])[^\"']*(?P=quote)))?"
    r"[.;]\s*(?P<rest>.*)",
    re.IGNORECASE | re.DOTALL,
)
REQUIRED_ARGUMENTS = "Required arguments: {names}."
DELETE_PREFIXES = ("delete_", "bulk_delete_", "remove_", "revoke_", "unadopt_")
#: The one success wording of every tool that returns ``tools._results.deletion_result``
#: (tests/test_deletion_result_descriptions.py derives that set from the code).
DELETION_RESULT = (
    "Returns {deleted, message, response}: deleted is true, message summarizes the delete, "
    "and response is the upstream body verbatim (decoded JSON, raw text, or null when the "
    "body is empty)."
)


#: Appended to every ``*_proxy`` tool: the suffix names the route, not a different feature.
PROXY_NOTE = "_proxy suffix: calls the Network Integration API through the connector proxy."
#: Appended as its own sentence to a description that mentions "dry-run policy": the setting
#: that turns it on (``write_policy`` in src/unifi_fabric/config.py). ``UNIFI_WRITE_EXCEPTIONS``
#: narrows it to one tool or family. It is never a call argument. It is a separate note, never
#: edited into the tool's own result statement, so that statement stays the tool's own.
DRY_RUN_SETTING = "Set UNIFI_WRITE_POLICY=dry-run."
#: The advertised description limit (tests/test_alpha06_review_findings.py and others).
MAX_DESCRIPTION = 2048
PREVIEW_SHAPE_REPEAT = (
    "The dry-run preview contains method, path, params (query parameters), and body."
)
_DRY_RUN_POLICY = re.compile(r"dry-run policy", re.IGNORECASE)
#: One line per overlapping filtering family, keyed by the resource noun in the tool name.
FAMILY_NOTES: dict[str, str] = {
    "firewall_polic": (
        "Filter family: zone-to-zone allow/block rules; not ACL rules, traffic rules or "
        "content filters."
    ),
    "acl_rule": (
        "Filter family: L3/MAC access lists between networks or in a VLAN; zone-to-zone "
        "rules are firewall policies."
    ),
    "traffic_rule": (
        "Filter family: QoS, application and IP-group traffic matching; not firewall "
        "policies or content filters."
    ),
    "content_filter": (
        "Filter family: category-based web-filtering profiles; not firewall policies or "
        "traffic rules."
    ),
}
_FAMILY_TOOL = re.compile(
    r"(?:list|get|create|update|patch|delete|batch_delete)_"
    r"(?P<key>firewall_polic|acl_rule|traffic_rule|content_filter)(?!_categor|y_order|ies_order)"
)


def surface_notes(name: str, description: str, *, read_only: bool = False) -> str:
    """``description`` plus the shared tool-surface notes its tool ``name`` earns.

    A read-only tool never gets the dry-run switch: the policy does not intercept it.
    """
    original = description
    notes: list[str] = []
    if (
        not read_only
        and _DRY_RUN_POLICY.search(description)
        and "UNIFI_WRITE_POLICY=dry-run" not in description
    ):
        notes.append(DRY_RUN_SETTING)
    if name.endswith("_proxy") and PROXY_NOTE not in description:
        notes.append(PROXY_NOTE)
    match = _FAMILY_TOOL.match(name)
    if match and FAMILY_NOTES[match.group("key")] not in description:
        notes.append(FAMILY_NOTES[match.group("key")])
    if not notes and description == original:
        return description
    result = f"{description.rstrip()}\n\n{' '.join(notes)}" if notes else description
    if len(result) > MAX_DESCRIPTION:
        # Make room: this sentence only repeats the preview shape the Returns text gives.
        result = result.replace(f"\n{PREVIEW_SHAPE_REPEAT}", "")
    return result


def _is_delete_family(name: str) -> bool:
    """Whether ``name`` has the common canonical deletion-result contract."""
    return name.startswith(DELETE_PREFIXES) and name != "unadopt_protect_device"


def _host_description(text: str) -> str | None:
    """The shared host text for a standard or generic host hint, or ``None`` to keep it."""
    flat = " ".join(text.split())
    if flat == _ORIGINAL_HOST:
        return HOST_DESCRIPTION
    if "reportedState.hostname" in flat:
        return None
    match = _GENERIC_HOST.fullmatch(flat)
    if match is None:
        return None
    example = match.group("example")
    selector = HOST_SELECTOR.format(
        console="Protect console" if match.group("protect") else "Console",
        example=f' ({match.group("lead")} "{example[1:-1]}")' if example else "",
    )
    rest = match.group("rest").strip()
    return f"{selector} {rest[:1].upper()}{rest[1:]}" if rest else selector


def _names(name: str, text: str) -> bool:
    """Return whether a literal parameter name occurs as a Python regex word."""
    start = 0
    while (index := text.find(name, start)) >= 0:
        before = text[index - 1] if index else ""
        end = index + len(name)
        after = text[end] if end < len(text) else ""
        if (not before or not (before.isalnum() or before == "_")) and (
            not after or not (after.isalnum() or after == "_")
        ):
            return True
        start = index + 1
    return False


def install_compact_selector_descriptions(mcp: Any) -> int:
    """Finalize shared selector and description prose; return the change count."""
    changed = 0
    from .local_components import tool_components

    for component in tool_components(mcp):
        parameters = getattr(component, "parameters", None)
        if not isinstance(parameters, dict):
            continue
        host = parameters.get("properties", {}).get("host")
        if isinstance(host, dict) and isinstance(host.get("description"), str):
            replacement = _host_description(host["description"])
            if replacement is not None and replacement != host["description"]:
                host["description"] = replacement
                changed += 1
        required = [str(name) for name in parameters.get("required", [])]
        description = getattr(component, "description", None) or ""
        # A paragraph about a parameter starts a sentence, retaining its identifier.
        properties = parameters.get("properties", {})
        paragraphs = re.split(r"(\n\s*\n)", description)
        for index in range(0, len(paragraphs), 2):
            first = paragraphs[index].split(maxsplit=1)
            if first and first[0] in properties and first[0][:1].islower():
                paragraphs[index] = "The " + paragraphs[index]
        description = "".join(paragraphs)
        if (
            required
            and "Required arguments:" not in description
            and not all(_names(name, description) for name in required)
        ):
            line = REQUIRED_ARGUMENTS.format(names=", ".join(required))
            description = f"{description.rstrip()}\n\n{line}" if description else line
        if _is_delete_family(
            str(getattr(component, "name", ""))
        ) and DELETION_RESULT not in " ".join(description.split()):
            description = (
                f"{description.rstrip()}\n\n{DELETION_RESULT}" if description else DELETION_RESULT
            )
        annotations = getattr(component, "annotations", None)
        description = surface_notes(
            str(getattr(component, "name", "")),
            description,
            read_only=getattr(annotations, "read_only_hint", None) is True,
        )
        if description != (getattr(component, "description", None) or ""):
            component.description = description
            changed += 1
        fn = getattr(component, "fn", None)
        if fn is not None:
            fn = inspect.unwrap(fn)
            doc = inspect.getdoc(fn) or ""
            prose, marker, args = doc.partition("\n\nArgs:\n")
            # FastMCP already parsed Args into the schema; preserve that section
            # while publishing the same final prose on both documentation surfaces.
            if description != prose.strip():
                fn.__doc__ = f"{description}{marker}{args}"
    return changed
