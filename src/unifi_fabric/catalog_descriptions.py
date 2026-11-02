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
    for component in mcp._local_provider._components.values():
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
