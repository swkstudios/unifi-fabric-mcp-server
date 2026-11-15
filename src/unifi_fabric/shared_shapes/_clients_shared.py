"""Names the clients family's ``clients`` shares with other families.

Used by clients, statistics. Moved verbatim by ``scripts/move_family.py`` from
``families/clients/clients.py``, which import them back where they use them, so their own code and
import paths stay.
"""

from __future__ import annotations

from typing import Any


def _given(value: Any) -> bool:
    """An argument names something: not omitted and not a blank string."""
    return value is not None and not (isinstance(value, str) and not value.strip())


def resolve_list_source(
    tool: str,
    source: str | None,
    choices: tuple[str, ...],
    default: str,
    newer: str,
    *,
    newer_args: dict[str, Any],
    default_args: dict[str, Any],
) -> str:
    """The route a list tool reads, from its own ``source`` argument and the arguments
    that belong to only one route.

    A blank or omitted ``source`` keeps ``default`` unless an argument that only the
    ``newer`` route takes was given (then ``newer`` is used: the argument names it). An
    explicit ``source`` that contradicts the given arguments, or arguments of both routes
    given together, raise before any request: they name two routes at once. A blank string
    names nothing, so it never counts as given.
    """
    chosen = source.strip().lower() if isinstance(source, str) and source.strip() else None
    if chosen is not None and chosen not in choices:
        raise ValueError(f"{tool} source must be one of {', '.join(choices)} (got {source!r})")
    given_newer = sorted(name for name, value in newer_args.items() if _given(value))
    given_default = sorted(name for name, value in default_args.items() if _given(value))
    if given_newer and given_default:
        raise ValueError(
            f"{tool} source conflict: {', '.join(given_newer)} apply only to source "
            f"{newer!r} and {', '.join(given_default)} only to source {default!r}; "
            "pass the arguments of one source."
        )
    if chosen is None:
        return newer if given_newer else default
    if chosen == default and given_newer:
        raise ValueError(
            f"{tool} source conflict: {', '.join(given_newer)} apply only to source "
            f"{newer!r}, but source {default!r} was given; omit source or pass {newer!r}."
        )
    if chosen == newer and given_default:
        raise ValueError(
            f"{tool} source conflict: {', '.join(given_default)} apply only to source "
            f"{default!r}, but source {newer!r} was given; omit them or omit source."
        )
    return chosen


#: The v2 client-list query flags the Network 11.0.81 web UI sends on clients/active,
#: clients/local and clients/history: {tool argument: upstream query key}.
V2_CLIENT_FLAGS = {
    "include_matter_thread_clients": "includeMatterThreadClients",
    "include_traffic_usage": "includeTrafficUsage",
    "include_unifi_devices": "includeUnifiDevices",
}


def v2_flag_params(flags: dict[str, bool | None]) -> dict[str, str]:
    """The v2 query parameters for the boolean flags that were given (``"true"`` /
    ``"false"``, the form the web UI sends); an omitted (``None``) flag sends nothing."""
    return {
        V2_CLIENT_FLAGS.get(name, name): "true" if value else "false"
        for name, value in flags.items()
        if value is not None
    }
