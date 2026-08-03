"""Shared helpers for the historical-stat and Protect-event tools.

The historical endpoints mix time units on sibling paths (``/stat/session``
takes epoch seconds while ``/stat/report`` takes epoch milliseconds), which is a
silent-corruption footgun: milliseconds passed to ``/stat/session`` return
HTTP 200 with an empty array. To make that impossible, every new tool accepts a
single documented unit — epoch **seconds** — validates it, and converts to
milliseconds internally where the endpoint requires it.

These tools return payloads verbatim: per-client and per-sensor identifiers
(MAC addresses, IPs, hostnames, and client/sensor display names) are passed
through unchanged. See the pass-through invariant in ``CLAUDE.md`` — the server
is a faithful access layer and does not withhold data from its caller.
"""

from __future__ import annotations

from ..client import UniFiConnectionError

# Epoch seconds this large (~year 5138) are almost certainly milliseconds passed
# by mistake. Rejecting them turns the /stat/session silent-empty-array failure
# mode into a loud, actionable error.
_MAX_EPOCH_SECONDS = 100_000_000_000


def require_epoch_seconds(value: int, name: str) -> int:
    """Validate that ``value`` is a non-negative epoch-**seconds** timestamp.

    Rejects booleans, non-integers, negatives, and values large enough to be
    epoch milliseconds — the classic mistake that makes ``/stat/session`` return
    an empty array with no error.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name!r} must be an integer epoch-seconds timestamp, got {value!r}")
    if value < 0:
        raise ValueError(f"{name!r} must be a non-negative epoch-seconds timestamp, got {value!r}")
    if value >= _MAX_EPOCH_SECONDS:
        raise ValueError(
            f"{name}={value} looks like epoch milliseconds; pass epoch SECONDS. "
            "Milliseconds sent to /stat/session return HTTP 200 with an empty array."
        )
    return value


def seconds_to_millis(value: int) -> int:
    """Convert an epoch-seconds timestamp to epoch milliseconds."""
    return value * 1000


def translate_host_not_found(exc: UniFiConnectionError, host: str) -> UniFiConnectionError:
    """Turn a proxy '403 host not found' into a clear host-id error.

    A truncated or otherwise invalid host id returns ``403 forbidden: host not
    found`` from the connector, which reads like a service outage. Re-frame it as
    the host-id problem it actually is. Any other error is returned unchanged.
    """
    message = str(exc).lower()
    if "host not found" in message or ("403" in message and "forbidden" in message):
        return UniFiConnectionError(
            f"Host {host!r} was rejected by the connector (HTTP 403 host not found). "
            "This is an invalid or truncated host id, not an unavailable service — "
            "verify the full host id with list_hosts."
        )
    return exc
