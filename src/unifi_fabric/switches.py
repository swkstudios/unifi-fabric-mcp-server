"""The server's one boolean switch parser and its runtime readers.

Every boolean environment switch is parsed here, by one function, whether it is read
once at startup (:class:`unifi_fabric.config.Settings`) or at call time (read-only mode
and the per-area write opt-outs, so a deployment or a test can toggle them without
rebuilding the client). The two paths cannot disagree about a spelling: ``Settings``
validates each boolean field with :func:`parse_bool`, and every runtime check reads
its variable with :func:`env_flag`, which calls the same function.

Accepted spellings (case-insensitive, surrounding whitespace ignored) are
:data:`TRUE_VALUES` and :data:`FALSE_VALUES`. An unset, empty or whitespace-only value
means the switch's default. Any other value is an error naming the variable and listing
the accepted spellings (``Settings`` refuses it at startup; a runtime reader raises the
same error rather than guessing).

This module is dependency-free so the low-level client and the tool modules can import
it without a settings cycle.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

#: The spellings a boolean switch accepts (case-insensitive), as listed in its error.
TRUE_VALUES = ("1", "true", "yes", "on", "t", "y")
FALSE_VALUES = ("0", "false", "no", "off", "f", "n")

#: ``1/true/yes/on/t/y`` and ``0/false/no/off/f/n``: the spellings, for messages.
TRUE_HINT = "/".join(TRUE_VALUES)
FALSE_HINT = "/".join(FALSE_VALUES)


def parse_bool(value: object, env: str) -> object:
    """A boolean switch value: one of the accepted spellings, else an error listing them.

    ``bool`` and ``None`` pass through; the integers ``0`` and ``1`` are booleans. A
    string is matched case-insensitively after stripping surrounding whitespace. The
    message names ``env`` and the accepted spellings, never the value received (a value
    set in the wrong variable may be a credential).
    """
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    text = str(value).strip().lower()
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES:
        return False
    raise ValueError(
        f"{env} must be a boolean: one of {', '.join(TRUE_VALUES)} (true) or "
        f"{', '.join(FALSE_VALUES)} (false), case-insensitive; the value is not shown here; "
        "unset or empty keeps the default"
    )


def env_flag(env: str, default: bool) -> bool:
    """The current value of the boolean switch ``env``, read from the environment now.

    Unset, empty or whitespace-only -> ``default``; otherwise :func:`parse_bool` decides
    (a malformed value raises ``ValueError`` naming the variable, exactly as ``Settings``
    refuses it at startup).
    """
    raw = os.environ.get(env)
    if raw is None or not raw.strip():
        return default
    return bool(parse_bool(raw, env))


@dataclass(frozen=True)
class AreaWriteSwitch:
    """A product area's write opt-out: enabled by default, ``0`` refuses its writes."""

    #: The tool family (``families.build_family_index``) whose write tools it governs.
    family: str
    #: The environment variable (also the ``Settings`` field ``UNIFI_<FIELD>``).
    env: str
    #: The connector-relay ``routeClass`` prefix of the area's console routes.
    relay_prefix: str
    #: Additional catalog families belonging to the same application area.
    related_families: tuple[str, ...] = ()
    #: The upstream API routes of the area (regular expressions searched, ignoring case,
    #: in the fully percent-decoded request path). The client refuses every write request to one of
    #: them while the area is opted out, whichever tool or relay sent it.
    routes: tuple[str, ...] = ()

    def owns_route(self, path: str) -> bool:
        """Whether the decoded upstream request ``path`` is one of the area's routes."""
        return any(re.search(pattern, path, re.IGNORECASE) for pattern in self.routes)

    def governs(self, family: str | None) -> bool:
        """Whether a catalog family belongs to this application area."""
        return family == self.family or family in self.related_families

    def enabled(self) -> bool:
        """True unless the variable is set to a false spelling (read now)."""
        return env_flag(self.env, True)


#: Read-only mode (opt-in, default off), read at call time by ``unifi_fabric.read_only``.
READ_ONLY_ENV = "UNIFI_READ_ONLY"

#: Every per-area write opt-out, in one table. The typed tools of each area, the
#: connector relay's route-class check and the cross-tool invariants all read it, so an
#: area's switch is parsed and honoured the same way everywhere.
NETWORK_WRITES = AreaWriteSwitch(
    "network",
    "UNIFI_ENABLE_NETWORK_WRITE",
    "network-",
    ("firewall", "clients", "devices", "vpn", "hotspot", "statistics"),
    (r"(?:^|/)proxy/network(?:/|\Z)",),
)
PROTECT_WRITES = AreaWriteSwitch(
    "protect", "UNIFI_PROTECT_MUTATIONS_ENABLED", "protect-", (), (r"(?:^|/)proxy/protect(?:/|\Z)",)
)
MOBILITY_WRITES = AreaWriteSwitch(
    "mobility", "UNIFI_ENABLE_MOBILITY_WRITE", "mobility-", (), (r"^/v1/mobility(?:/|\Z)",)
)
CARRIER_WRITES = AreaWriteSwitch(
    "carrier",
    "UNIFI_ENABLE_CARRIER_FABRIC_WRITE",
    "carrier-",
    (),
    (r"^/v1/carrier(?:/|\Z)",),
)
INNERSPACE_WRITES = AreaWriteSwitch(
    "innerspace",
    "UNIFI_ENABLE_INNERSPACE_WRITE",
    "innerspace-",
    (),
    (r"(?:^|/)proxy/innerspace(?:/|\Z)",),
)
AREA_WRITE_SWITCHES: tuple[AreaWriteSwitch, ...] = (
    NETWORK_WRITES,
    PROTECT_WRITES,
    MOBILITY_WRITES,
    CARRIER_WRITES,
    INNERSPACE_WRITES,
)

#: Every boolean switch read at call time, with its default. ``Settings`` declares the
#: same variables as boolean fields with the same defaults (checked by the cross-tool
#: invariants), so a malformed value still fails at startup.
RUNTIME_SWITCHES: dict[str, bool] = {
    READ_ONLY_ENV: False,
    **{s.env: True for s in AREA_WRITE_SWITCHES},
}


def opted_out_area_for_route(path: str) -> AreaWriteSwitch | None:
    """The opted-out area whose routes include the decoded request ``path`` now, else None."""
    for switch in AREA_WRITE_SWITCHES:
        if switch.owns_route(path) and not switch.enabled():
            return switch
    return None


def current_value_note(env: str) -> str:
    """The note ``" Current value: ENV=<value>."`` for a set switch, else an empty string.

    Only called for a switch that parsed as a boolean spelling (an opt-out is in force),
    so the value is one of the accepted spellings, never a credential.
    """
    raw = os.environ.get(env)
    if raw is None or not raw.strip():
        return ""
    return f" Current value: {env}={raw.strip()}."


def is_read_only() -> bool:
    """True only when ``UNIFI_READ_ONLY`` is set to a true spelling (default off)."""
    return env_flag(READ_ONLY_ENV, False)
