"""The selector syntax rule, shared by the tool middleware and config load.

Dependency-free so :mod:`unifi_fabric.config` can apply it to ``UNIFI_API_KEYS`` labels.
"""

from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def selector_reason(value: str) -> str | None:
    """Why the string ``value`` cannot name anything (the selector syntax rule), or None.

    The one rule for every selector -- a ``host`` / ``site`` / ``key_label`` argument, a
    selector inside a list or dict argument, and a configured key label
    (``UNIFI_API_KEYS[i].label``, checked at config load so every accepted label is
    selectable via ``key_label``): non-empty, no control character, no surrounding
    whitespace.
    """
    if not value.strip():
        return "must not be empty or whitespace"
    if _CONTROL.search(value):
        return f"contains a control character (newline, tab ...): {value!r}"
    if value != value.strip():
        return f"has surrounding whitespace: {value!r}"
    return None


def name_reason(value: str) -> str | None:
    """Why ``value`` cannot be an upstream object NAME, or None.

    A name selector (a camera name in ``cameras``) is matched against names the upstream
    reports, which may legitimately carry surrounding whitespace (a camera literally named
    ``"Garage "``): only an empty string or a control character is refused. Console, site,
    key-label and id / MAC selectors keep the stricter :func:`selector_reason`.
    """
    if value == "":
        return "must not be empty"
    if _CONTROL.search(value):
        return f"contains a control character (newline, tab ...): {value!r}"
    return None
