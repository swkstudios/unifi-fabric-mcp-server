"""Shared helpers for the historical-stat and Protect-event tools.

The historical endpoints mix time units on sibling paths (``/stat/session`` takes epoch
seconds while ``/stat/report`` takes epoch milliseconds). Every tool here accepts one
documented unit -- epoch **seconds** as an integer -- and converts to milliseconds
internally where the endpoint requires it.

Only the JSON type is checked before the request (``refusals`` entry ``epoch-type``). The
value itself is the upstream's to judge (the refusal policy, ``refusals``): a negative
value, or one large enough to be epoch milliseconds passed by mistake (>= 1e11, about the
year 5138), is not refused or rescaled: it is sent in the unit every value takes
(multiplied by 1000 where the endpoint takes milliseconds), and the result carries an
additive ``_warnings`` entry saying so (:func:`epoch_warnings`), because milliseconds
sent to ``/stat/session`` answer HTTP 200 with an empty array rather than an error.

These tools return payloads verbatim: per-client and per-sensor identifiers (MAC
addresses, IPs, hostnames, and client/sensor display names) are passed through
unchanged. See the pass-through invariant in ``CLAUDE.md`` -- the server is a faithful
access layer and does not withhold data from its caller.
"""

from __future__ import annotations

import re
from typing import Any

from ..client import UniFiConnectionError
from ._keys import with_context

#: Epoch seconds this large (~year 5138) are almost certainly milliseconds passed by
#: mistake: the value is still sent, with a ``_warnings`` hint.
MILLISECONDS_HINT_AT = 100_000_000_000


def require_epoch_seconds(value: int, name: str) -> int:
    """``value`` when it is a JSON integer (booleans are not), else raise.

    Sign and magnitude are not checked here: see :func:`epoch_warnings`.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name!r} must be an integer epoch-seconds timestamp, got {value!r}")
    return value


def epoch_warnings(**values: int | None) -> list[dict[str, Any]]:
    """One ``_warnings`` entry per epoch-seconds argument that is negative or looks like
    epoch milliseconds (>= :data:`MILLISECONDS_HINT_AT`); omitted arguments are skipped.
    The value was not refused or rescaled (only the usual unit conversion applied); the
    entry says so."""
    out: list[dict[str, Any]] = []
    for name, value in values.items():
        if value is None or isinstance(value, bool) or not isinstance(value, int):
            continue
        # Source: docs/MIGRATING-0.7.md#change-009 documents these warning-only
        # heuristics (negative or >= 1e11); neither is an upstream spec bound.
        if value < 0:
            out.append(
                {
                    "code": "EPOCH_SECONDS_NEGATIVE",
                    "argument": name,
                    "value": value,
                    "message": (
                        f"{name}={value} is negative (before 1970-01-01); it was sent "
                        "uncorrected (multiplied by 1000 where the endpoint takes "
                        "milliseconds, like any value). Pass epoch SECONDS, e.g. 1690000000."
                    ),
                }
            )
        elif value >= MILLISECONDS_HINT_AT:
            out.append(
                {
                    "code": "EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS",
                    "argument": name,
                    "value": value,
                    "message": (
                        f"{name}={value} looks like epoch milliseconds; this tool takes "
                        "epoch SECONDS and did not rescale it (an endpoint that takes "
                        "milliseconds received it multiplied by 1000, like any value; such "
                        "a window can answer with an empty result rather than an error). "
                        "Divide by 1000 for seconds."
                    ),
                }
            )
    return out


def with_warnings(result: Any, warnings: list[dict[str, Any]]) -> Any:
    """An object result plus server warnings, preserving any upstream collision.

    No warnings: ``result`` as is. Array results are kept intact under ``result`` so
    the additive warning has a place without changing the upstream array contents.
    """
    if not warnings:
        return result
    if isinstance(result, list):
        return {"result": result, "_warnings": warnings}
    if not isinstance(result, dict):
        return result
    return with_context(result, {"_warnings": warnings})


def seconds_to_millis(value: int) -> int:
    """Convert an epoch-seconds timestamp to epoch milliseconds."""
    return value * 1000


def translate_host_not_found(exc: UniFiConnectionError, host: str) -> UniFiConnectionError:
    """Append a host-id hint to a proxy '403 host not found' — never replace the reason.

    A truncated or otherwise invalid host id returns ``403 forbidden: host not found``
    from the connector, which reads like a service outage. The upstream message (status,
    path and body) is kept verbatim and a hint is appended; any other error is returned
    unchanged.
    """
    message = str(exc).lower()
    if re.match(r"^http 403\b", message) is not None and (
        "host not found" in message or "forbidden" in message
    ):
        # The same error type, status and request_sent as the upstream error (as
        # upstream_hint keeps them): only the text gains the hint.
        return type(exc)(
            f"{exc} -- Hint: if the host id {host!r} may be truncated or wrong, verify the "
            "full id (or use the console name) with list_hosts; a 403 can also mean the "
            "connector does not relay this route for the API key in use.",
            request_sent=exc.request_sent,
            status=exc.status,
        )
    return exc
