"""The server's one boolean switch parser and the call-time write-policy readers.

Every boolean environment switch is parsed here by :func:`parse_bool`, whether it is
read once at startup (:class:`unifi_fabric.config.Settings`) or at call time
(:func:`env_flag`). The write decisions (a global ``deny`` or ``dry-run`` in
``UNIFI_WRITE_POLICY``, and the ``family:<id>`` and ``tool:<name>`` exceptions of
``UNIFI_WRITE_EXCEPTIONS``) are read at call time through
:func:`unifi_fabric.policy.current`, so a deployment or a test can change them without
rebuilding the client.

Accepted spellings (case-insensitive, surrounding whitespace ignored) are
:data:`TRUE_VALUES` and :data:`FALSE_VALUES`. An unset, empty or whitespace-only value
means the switch's default. Any other value is an error naming the variable and listing
the accepted spellings (``Settings`` refuses it at startup; a runtime reader raises the
same error rather than guessing).

This module imports :mod:`unifi_fabric.policy` lazily, so the low-level client and the
tool modules can import it without a settings cycle.
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
    """A product area's write opt-out: the ``family:<id>=deny`` write exception."""

    #: The tool family (``families.build_family_index``) whose write tools it governs.
    family: str
    #: The connector-relay ``routeClass`` prefix of the area's console routes.
    relay_prefix: str
    #: Additional catalog families belonging to the same application area.
    related_families: tuple[str, ...] = ()
    #: The upstream API routes of the area (regular expressions searched, ignoring case,
    #: in the fully percent-decoded request path). The client refuses every write request to
    #: one of them while the area's family is denied, whichever tool or relay sent it.
    routes: tuple[str, ...] = ()

    @property
    def env(self) -> str:
        """The exception token that opts the area out (also the audited reason)."""
        return deny_token(self.family)

    def owns_route(self, path: str) -> bool:
        """Whether the decoded upstream request ``path`` is one of the area's routes."""
        return any(re.search(pattern, path, re.IGNORECASE) for pattern in self.routes)

    def governs(self, family: str | None) -> bool:
        """Whether a catalog family belongs to this application area."""
        return family == self.family or family in self.related_families

    def enabled(self) -> bool:
        """True unless ``UNIFI_WRITE_EXCEPTIONS`` denies the area's family (read now)."""
        return not family_denied(self.family)


#: The global write policy setting; ``deny`` is read-only mode (also the audited reason).
WRITE_POLICY_ENV = "UNIFI_WRITE_POLICY"
#: The write exceptions setting.
WRITE_EXCEPTIONS_ENV = "UNIFI_WRITE_EXCEPTIONS"
#: The audited reason of a global deny (kept under its historical symbol name).
READ_ONLY_ENV = WRITE_POLICY_ENV


def deny_token(family: str) -> str:
    """The ``UNIFI_WRITE_EXCEPTIONS`` item that denies ``family``'s writes."""
    return f"family:{family}=deny"


def _policy():  # type: ignore[no-untyped-def]
    from . import policy

    return policy.current()


def family_denied(family: str) -> bool:
    """True when ``UNIFI_WRITE_EXCEPTIONS`` holds ``family:<family>=deny`` now."""
    return (f"family:{family}", "deny") in _policy().write_exceptions


#: Every per-area write opt-out, in one table. The typed tools of each area, the
#: connector relay's route-class check and the cross-tool invariants all read it, so an
#: area's exception is honoured the same way everywhere.
NETWORK_WRITES = AreaWriteSwitch(
    "network",
    "network-",
    ("firewall", "clients", "devices", "vpn", "hotspot", "statistics"),
    (
        r"(?:^|/)proxy/network(?:/|\Z)",
        r"^/ea/sites/[^/]+/rest/firewallrule(?:/|\Z)",
    ),
)
PROTECT_WRITES = AreaWriteSwitch("protect", "protect-", (), (r"(?:^|/)proxy/protect(?:/|\Z)",))
MOBILITY_WRITES = AreaWriteSwitch("mobility", "mobility-", (), (r"^/v1/mobility(?:/|\Z)",))
CARRIER_WRITES = AreaWriteSwitch("carrier", "carrier-", (), (r"^/v1/carrier(?:/|\Z)",))
INNERSPACE_WRITES = AreaWriteSwitch(
    "innerspace", "innerspace-", (), (r"(?:^|/)proxy/innerspace(?:/|\Z)",)
)
AREA_WRITE_SWITCHES: tuple[AreaWriteSwitch, ...] = (
    NETWORK_WRITES,
    PROTECT_WRITES,
    MOBILITY_WRITES,
    CARRIER_WRITES,
    INNERSPACE_WRITES,
)

#: The connector relay's write opt-out token (``family:connector=deny``).
CONNECTOR_WRITE_TOKEN = deny_token("connector")


def connector_writes_enabled() -> bool:
    """True unless ``UNIFI_WRITE_EXCEPTIONS`` denies the connector family (read now)."""
    return not family_denied("connector")


def area_deny_text(area: str, token: str) -> str:
    """The refusal text of a denied area: the exception, that no request was sent, and
    where to change it. The current setting is appended when the refusal is raised
    (:func:`current_value_note`)."""
    return (
        f"{area} writes are denied: {WRITE_EXCEPTIONS_ENV} contains {token}. No request was "
        "sent. Writes are allowed by default. To allow them, remove that item from "
        f"{WRITE_EXCEPTIONS_ENV} (or change it to dry-run) in the MCP client env block (and "
        "set the plugin's Write policy option to allow if it is deny), the "
        "environment of the shell that starts the server, or this service's "
        "'environment:' block in the deploy docker-compose.yml (a host shell export does "
        "not reach the container), then restart the server (recreate the container). "
        f"{WRITE_POLICY_ENV} must not be deny either. See Enabling / disabling connector writes "
        "in docs/CONFIGURATION.md#enabling--disabling-connector-writes."
    )


def opted_out_area_for_route(path: str) -> AreaWriteSwitch | None:
    """The opted-out area whose routes include the decoded request ``path`` now, else None."""
    for switch in AREA_WRITE_SWITCHES:
        if switch.owns_route(path) and not switch.enabled():
            return switch
    return None


def current_value_note(env: str) -> str:
    """The note naming the setting that refuses now (never a free-form value)."""
    if env == WRITE_POLICY_ENV:
        return f" Current value: {WRITE_POLICY_ENV}=deny."
    if env.startswith("family:"):
        return f" Current value: {WRITE_EXCEPTIONS_ENV} includes {env}."
    return ""


def is_read_only() -> bool:
    """True when ``UNIFI_WRITE_POLICY=deny`` (default allow), read now."""
    return _policy().write_policy == "deny"


def governing_families(tool: str, family: str | None) -> tuple[str, ...]:
    """Every ``family:<id>`` whose write exception reaches ``tool``, its own family first.

    The reach of a ``deny`` entry, so a ``dry-run`` entry previews exactly the writes it
    would refuse: the tool's own family, the area whose reach includes that family
    (``family:network`` also covers ``firewall``, ``devices``, ``clients``, ``vpn``,
    ``hotspot`` and ``statistics``), and ``connector`` for the typed tools the connector
    switch also governs (:func:`families.connector_write_tools`).
    """
    from .families import connector_write_tools

    found: list[str] = [family] if family else []
    for switch in AREA_WRITE_SWITCHES:
        if switch.governs(family) and switch.family not in found:
            found.append(switch.family)
    if tool in connector_write_tools() and "connector" not in found:
        found.append("connector")
    return tuple(found)


def dry_run_active(*, tool: str | None = None, path: str | None = None) -> bool:
    """True when a write now gets the dry-run preview instead of being sent.

    ``UNIFI_WRITE_POLICY=dry-run`` covers every write. Otherwise a ``dry-run`` exception
    reaching the calling tool (``tool:<name>`` or any family of
    :func:`governing_families`, so exactly the writes the same entry set to ``deny``
    refuses) or the area owning the decoded ``path`` applies. A deny decision is made
    earlier (tool middleware and the request guards), so it always wins.
    """
    from . import policy

    current = policy.current()
    if current.write_policy == "dry-run":
        return True
    if not any(value == "dry-run" for _target, value in current.write_exceptions):
        return False
    if tool is None:
        from .audit import current_tool

        tool = current_tool()
    if tool is not None:
        from .families import build_family_index

        family = build_family_index().get(tool) or ""
        if policy.write_mode(current, tool_name=tool, family=family) == "dry-run":
            return True
        if any(
            policy.family_exception(current, governing) == "dry-run"
            for governing in governing_families(tool, family)
        ):
            return True
    if path is not None:
        for switch in AREA_WRITE_SWITCHES:
            if (
                switch.owns_route(path)
                and policy.family_exception(current, switch.family) == "dry-run"
            ):
                return True
    return False
