"""The ONE MAC-address validator every tool uses (no per-module MAC rules).

A MAC selector is accepted in colon (``aa:bb:cc:dd:ee:ff``), dash (``aa-bb-cc-dd-ee-ff``),
bare (``aabbccddeeff``) or dotted (``aabb.ccdd.eeff``) form, any case, and nothing else:
a value with surrounding whitespace is NOT a MAC (the selector rule refuses padded
selectors everywhere, so ``" aa:bb:cc:dd:ee:ff"`` is rejected, never silently stripped
by one tool and refused by another). MACs read from upstream records may be normalized
freely; this module governs what a CALLER passes.
"""

from __future__ import annotations

import re

#: Every accepted form, anchored, bounded repeats only (no backtracking).
_MAC_RE = re.compile(
    r"^(?:[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}"
    r"|[0-9A-Fa-f]{12}|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})\Z"
)
_SEPARATORS = re.compile(r"[:.-]")


def is_mac(value: object) -> bool:
    """True when ``value`` is a MAC in an accepted form (no surrounding whitespace)."""
    return isinstance(value, str) and _MAC_RE.match(value) is not None


def normalize_mac(mac: str) -> str:
    """``mac`` as 12 lowercase hex digits (separators removed)."""
    return _SEPARATORS.sub("", mac).lower()


def colon_mac(mac: str) -> str:
    """``mac`` in the controller's lowercase colon form (aa:bb:cc:dd:ee:ff)."""
    bare = normalize_mac(mac)
    return ":".join(bare[i : i + 2] for i in range(0, 12, 2))


def record_mac(value: object) -> str | None:
    """A MAC read from an UPSTREAM record, normalized; ``None`` when it is not one.

    Upstream data is matched leniently (surrounding whitespace ignored); a caller's
    selector is not (see :func:`is_mac`).
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    return normalize_mac(text) if is_mac(text) else None
