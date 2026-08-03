"""Static cross-checks of the server ``INSTRUCTIONS`` block against the registered tools.

For an MCP server the ``instructions`` string is agent-facing documentation: an agent
reads it and calls the tools it names. Two distinct classes of defect can make that
documentation lie to the agent, and this module carries a separate check for each.

1. **Phantom tool names.** A tool name that appears in ``INSTRUCTIONS`` but was never
   registered — the agent calls it, gets ``tool-not-found``, and has no recovery path
   from the schema. :func:`phantom_tool_refs` extracts the tool references out of the
   INSTRUCTIONS prose and reports any that are not in the registered tool set.

2. **Wrong parameter-scope claims.** The "Parameter Scope Quick Reference" section sorts
   tools into buckets ("host + site required", "host only", "no host/site"). A tool can be
   filed under the wrong bucket — it exists, its *name* is real, but the prose claims it
   takes a different set of ``host``/``site`` parameters than its registered schema
   actually requires. :func:`param_scope_violations` compares the bucket each tool is
   filed under against the tool's real parameters and reports the mismatches.

## What the phantom-name check does NOT cover (documented blind spot)

The phantom-name check (:func:`phantom_tool_refs`) asserts only that every backtick tool
*name* in INSTRUCTIONS is registered. It says **nothing** about whether the *claims* made
around those names are true. A green phantom-name check is therefore **not** evidence that
INSTRUCTIONS is accurate — only that it names no nonexistent tools. The concrete defect
that motivated this note: four tools (``update_vpn_server``, ``delete_vpn_server``,
``update_hotspot_operator``, ``delete_hotspot_operator``) were filed under an "ID only
(no host/site)" bucket while their registered schemas required ``host`` and ``site``. Every
one of those names is registered, so the phantom-name check passed the defect cleanly.

:func:`param_scope_violations` closes exactly that gap for the parameter-scope class — the
one class of prose claim that can be verified mechanically, because the registered schema
knows the true required parameters. Other prose claims (what a tool *does*, what a field
*means*, workflow ordering) remain unchecked by any static test and still require human
review; do not read a green suite as "all of INSTRUCTIONS is correct".
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

# Backtick-delimited pure lower snake_case identifiers, e.g. `list_recognition_groups`.
# camelCase (`siteId`), tokens with `=`/`:`/quotes (`interval='5m'`) and single words
# without an underscore never match, so they are excluded up front.
_BACKTICK_SNAKE_RE = re.compile(r"`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`")

# Each parameter-scope bucket, keyed by a substring that identifies its bold label, mapped
# to the (host_required, site_required) contract its members must satisfy. ``True`` means
# the parameter must be present, ``False`` means it must be absent.
_SCOPE_CONTRACTS: dict[str, tuple[bool, bool]] = {
    "host + site required": (True, True),
    "host only": (True, False),
    "no host/site": (False, False),
}


def tool_verbs(tool_names: Iterable[str]) -> set[str]:
    """Return the set of leading verb segments across the registered tool names."""
    return {name.split("_", 1)[0] for name in tool_names if "_" in name}


def instruction_tool_refs(instructions: str, verbs: set[str]) -> set[str]:
    """Extract backtick tokens from INSTRUCTIONS that look like tool references.

    A token qualifies when it is a lower snake_case identifier whose first segment is a
    known tool verb — that filter keeps parameter/field names (``page_token`` etc.) from
    being misread as tools.
    """
    tokens = set(_BACKTICK_SNAKE_RE.findall(instructions))
    return {token for token in tokens if token.split("_", 1)[0] in verbs}


def phantom_tool_refs(instructions: str, tool_names: Iterable[str]) -> list[str]:
    """Return the sorted tool names referenced in INSTRUCTIONS that are not registered.

    An empty list means every tool the INSTRUCTIONS prose names really exists.

    Blind spot: this only checks tool *names*, not the *claims* made about them. See the
    module docstring and :func:`param_scope_violations`.
    """
    names = set(tool_names)
    refs = instruction_tool_refs(instructions, tool_verbs(names))
    return sorted(refs - names)


def parse_param_scope_buckets(instructions: str) -> dict[str, set[str]]:
    """Parse the "Parameter Scope Quick Reference" section into bucket -> explicit tools.

    Returns a mapping keyed by the contract-identifying substrings in :data:`_SCOPE_CONTRACTS`
    (``"host + site required"``, ``"host only"``, ``"no host/site"``). Each value is the set
    of backtick-delimited snake_case tool names named *explicitly* in that bucket. Buckets
    describe some members only by category word ("network, firewall, DNS ... tools"); those
    are not backticked and are intentionally not extracted — the check makes claims only
    about tools the prose names outright.
    """
    # The section runs from its header to the next "## " header (or end of string).
    section_match = re.search(
        r"##\s*Parameter Scope Quick Reference\n(.*?)(?:\n##\s|\Z)",
        instructions,
        re.DOTALL,
    )
    section = section_match.group(1) if section_match else ""

    # Split the section into bullets: each begins at a line-leading "- **".
    bullets = re.split(r"\n(?=- \*\*)", section)

    buckets: dict[str, set[str]] = {}
    for bullet in bullets:
        if not bullet.startswith("- **"):
            continue
        # The bucket's scope marker may live in the bold label ("host + site required") or
        # in a trailing parenthetical ("**ID only** (no host/site)"), so match the whole
        # header up to the first colon rather than the bold text alone. This keeps the
        # check honest against a mis-labelled bucket whose real scope is in the aside — the
        # exact shape of the historical "ID only (no host/site)" defect.
        header = bullet.split(":", 1)[0]
        for key in _SCOPE_CONTRACTS:
            if key in header:
                buckets.setdefault(key, set()).update(_BACKTICK_SNAKE_RE.findall(bullet))
                break
    return buckets


def param_scope_violations(
    instructions: str, tool_params: Mapping[str, Iterable[str]]
) -> list[str]:
    """Return human-readable mismatches between bucket claims and real tool parameters.

    ``tool_params`` maps each registered tool name to its parameter names (from the live
    schema). For every tool named explicitly in a parameter-scope bucket, this asserts the
    tool's real ``host``/``site`` parameters match the bucket's contract:

    - "host + site required": tool must have both ``host`` and ``site``;
    - "host only": tool must have ``host`` and must NOT have ``site``;
    - "no host/site": tool must have neither.

    Tools named in a bucket but absent from ``tool_params`` (i.e. not registered) are the
    phantom-name class and are left to :func:`phantom_tool_refs`; they are skipped here so
    the two checks report cleanly separated failures. An empty list means every explicitly
    filed tool sits in a bucket consistent with its schema.
    """
    violations: list[str] = []
    for bucket, tools in parse_param_scope_buckets(instructions).items():
        host_required, site_required = _SCOPE_CONTRACTS[bucket]
        for tool in sorted(tools):
            if tool not in tool_params:
                continue  # unregistered -> phantom-name class, not our concern
            params = set(tool_params[tool])
            has_host = "host" in params
            has_site = "site" in params
            if has_host != host_required:
                violations.append(
                    f'`{tool}` is filed under "{bucket}" (host '
                    f"{'required' if host_required else 'forbidden'}) but its schema "
                    f"{'has no' if host_required else 'has a'} `host` parameter"
                )
            if has_site != site_required:
                violations.append(
                    f'`{tool}` is filed under "{bucket}" (site '
                    f"{'required' if site_required else 'forbidden'}) but its schema "
                    f"{'has no' if site_required else 'has a'} `site` parameter"
                )
    return violations
