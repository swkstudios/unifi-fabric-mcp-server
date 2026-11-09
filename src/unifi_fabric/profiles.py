"""Tool profiles: which catalog families one deployable server registers.

A profile is an explicit family allowlist over the typed catalog
(:mod:`unifi_fabric.catalog`). The default profile, ``complete``, is every one of the 13
families, so the upstream default never narrows. A fork selects a smaller profile by
configuration (a family allowlist and exclusion list, today supplied by the operator policy,
resolved here), never by editing a registration file: every profile uses the same registration
path, and family selection only de-registers tools after the complete roster registers.

The six ``meta`` tools are not a family and are never selected by a profile.

Capability boundary: a profile selects typed tools. It is not a security boundary on
upstream API routes. A profile that keeps the ``connector`` family keeps the generic
Fabric relays (``fabric_connector_get/post/put/patch/delete``), whose path argument can
reach endpoints outside the profile's typed families; their own authorization, read-only,
write-switch and policy checks still apply. A fork that must not reach other product
areas excludes ``connector``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .families import (
    ALL_FAMILIES,
    DISABLED_TOOL_FAMILIES_ENV,
    TOOL_FAMILIES_ENV,
    unknown_families_problem,
)

#: The default profile's name.
DEFAULT_PROFILE = "complete"


@dataclass(frozen=True, slots=True)
class Profile:
    """A named, explicit family allowlist."""

    name: str
    families: frozenset[str]

    def __post_init__(self) -> None:
        unknown = self.families - set(ALL_FAMILIES)
        if unknown:
            raise ValueError(
                f"profile {self.name!r} names unknown families: {', '.join(sorted(unknown))}; "
                f"valid families: {', '.join(ALL_FAMILIES)}"
            )

    def includes(self, family: str | None) -> bool:
        """Whether a tool of ``family`` stays registered (an unclassified tool stays)."""
        return family is None or family in self.families


#: The named profiles. ``complete`` is the whole supported capability set.
PROFILES: Mapping[str, Profile] = MappingProxyType(
    {DEFAULT_PROFILE: Profile(DEFAULT_PROFILE, frozenset(ALL_FAMILIES))}
)


def default_profile() -> Profile:
    """The complete profile."""
    return PROFILES[DEFAULT_PROFILE]


def selection_profile(
    allowed: Iterable[str] = (),
    disabled: Iterable[str] = (),
    *,
    allowed_value: str | None = None,
    disabled_value: str | None = None,
) -> Profile:
    """The profile an allowlist and an opt-out list select.

    No allowlist means the complete profile; the opt-out list applies after it. Pass the
    raw ``allowed_value``/``disabled_value`` so an unknown name fails with the message that
    never repeats the raw value; without them an unknown name fails in :class:`Profile`,
    which names it. An empty result is allowed: the operator emptied the domain catalog.
    """
    for value, variable in (
        (allowed_value, TOOL_FAMILIES_ENV),
        (disabled_value, DISABLED_TOOL_FAMILIES_ENV),
    ):
        problem = unknown_families_problem(value, variable)
        if problem:
            raise ValueError(problem)
    allow = frozenset(allowed)
    deny = frozenset(disabled)
    if not allow and not deny:
        return default_profile()
    return Profile("custom", (allow or frozenset(ALL_FAMILIES)) - deny)
