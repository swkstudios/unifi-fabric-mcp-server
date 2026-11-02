"""Shared payload sanitizers for write (create/update) tools.

The UniFi APIs return objects whose list-valued fields are padded with empty
strings — e.g. ``get_network`` returns ``"dns_servers": ["192.168.1.1", "", ""]``
for a network that has one DNS server but a three-slot field. Those empty
strings are placeholders, not data. Passing them straight back into an
``update_*`` PUT (the natural read-modify-write round-trip) makes the controller
reject the request: an empty string is not a valid IPv4 address, so the write
fails with HTTP 400 ``must be valid IPv4 address`` (see public issue
https://github.com/swkstudios/unifi-fabric-mcp-server/issues/17).

``strip_empty_list_values`` removes empty-string *elements* from every
list-valued field, recursing through nested objects and lists so padded fields
buried inside sub-objects (``ipv4Configuration.dhcp.dnsServers`` and the like)
are handled too. It is deliberately narrow:

- Only the empty string ``""`` is dropped, and only when it appears as a list
  *element*. A scalar string field the caller set to ``""`` (a name, a note, a
  cleared password) is left untouched — clearing a scalar is a legitimate edit.
- A list that reduces to empty becomes ``[]`` rather than being omitted. Under
  the full-replace PUT semantics these tools use, ``[]`` is the valid "no
  entries" value; dropping the key would instead read as "leave unchanged" and
  silently discard the caller's intent to clear the field.
- Order of the surviving elements is preserved.
- The input is never mutated; a new structure is returned.

The function is a no-op on any payload that carries no padding, so it is safe to
apply uniformly to every round-trip write tool even where a given upstream does
not pad. That uniformity is the point: the padding is a *class* of API behaviour,
not a single field, so the guard sits in one shared place rather than being
re-derived per field or per tool.
"""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

# Top-level fields the UniFi Network *Integration* API assigns and manages itself
# and rejects with HTTP 400 ``api.request.unknown-property`` when they appear in a
# write body. They are present in every ``get_*`` response for an Integration
# object, so the natural read-modify-write round-trip (GET, tweak a field, PUT the
# whole object back) fails unless they are removed first:
#
#   * ``id`` / ``metadata`` — present on every Integration object (networks,
#     firewall zones/policies, ACL rules, WiFi broadcasts, DNS policies, traffic
#     lists, VPN servers/tunnels). Verified live: PUT rejects ``$.id`` and
#     ``$.metadata``.
#   * ``default`` — the read-only "is this the default network" flag on networks.
#   * ``index`` — the server-managed ordering position on firewall policies
#     (ordering is changed through ``set_firewall_policy_ordering``, never by writing
#     ``index`` back). Verified live: a policy round-trip PUT rejects ``$.index``
#     even after ``id``/``metadata`` are removed. ACL rules are the exception: the
#     published "ACL rule update" schema (Network 10.6.106) lists ``index`` as a
#     request property, so ``update_acl_rule`` keeps it (``keep={"index"}``).
#
# The set is deliberately a *fixed, known* list rather than "strip whatever the
# server rejects": auto-dropping any field the API calls unknown would silently
# discard a caller's mistyped field name (e.g. ``nam`` for ``name``) and report
# success for a write that changed nothing — the exact silent-write-failure class
# these tools are meant to surface, not hide.
_INTEGRATION_READONLY_FIELDS = frozenset({"id", "metadata", "default", "index"})


def require_fields(tool: str, payload: Any, required: set[str]) -> None:
    """Validate that a create payload carries every field the tool declares required.

    Raises ``ValueError`` naming the missing field(s) so a caller can self-correct
    locally, instead of forwarding an incomplete body and either surfacing an opaque
    upstream ``400`` or — on the Classic REST endpoints, which do not enforce required
    fields server-side — silently creating a broken object. This is the self-correcting
    error pattern used across the create/write tools: the message names exactly what is
    missing.

    ``required`` is the same set the tool's docstring declares required; the two are
    kept identical on purpose so the documentation can never drift from the check.
    Only *presence* of each key is checked (an explicit empty value is the caller's
    choice); the upstream API remains the authority on field values.
    """
    if not isinstance(payload, dict):
        raise ValueError(
            f"{tool} requires a JSON object with fields: {', '.join(sorted(required))}"
        )
    missing = required - set(payload)
    if missing:
        raise ValueError(f"{tool} requires: {', '.join(sorted(missing))}")


def upstream_hint(exc: Exception, hint: str | None) -> Exception:
    """``exc`` with ``hint`` appended when it is an upstream error (the server may
    append a hint to an upstream error, never replace or drop its text); any other
    exception, or no hint, is returned unchanged."""
    from ..client import ResponseShapeError, UniFiConnectionError

    if hint is None or not isinstance(exc, UniFiConnectionError):
        return exc
    if isinstance(exc, ResponseShapeError):
        return exc
    exc.args = (f"{exc} -- Hint: {hint}",)
    return exc


async def with_upstream_hint[T](call: Awaitable[T], hint: str | None) -> T:
    """Await ``call``; an upstream error it raises gets ``hint`` appended."""
    try:
        return await call
    except Exception as exc:
        hinted = upstream_hint(exc, hint)
        if hinted is exc:
            raise
        raise hinted from exc


def missing_fields_hint(tool: str, body: Any, fields: tuple[str, ...], why: str) -> str | None:
    """The guidance for an unspecced body the upstream rejected: the documented fields
    ``body`` lacks (``why`` says where the list comes from), or None when it has them."""
    if not isinstance(body, dict):
        return f"{tool} sends a JSON object body with {', '.join(fields)} ({why})."
    missing = [f for f in fields if f not in body]
    if not missing:
        return None
    return (
        f"{tool} was sent without {', '.join(missing)}; the body takes {', '.join(fields)} ({why})."
    )


def strip_readonly_fields(value: Any, keep: frozenset[str] = frozenset()) -> Any:
    """Return a copy of ``value`` without the Integration API's read-only top-level fields.

    ``keep`` names fields of the read-only set that the target operation's published
    request schema accepts (``index`` on ACL rule writes); they are forwarded as given.

    Only *top-level* keys are removed. Nested objects are left untouched — a
    sub-object may legitimately carry a field literally named ``id`` (a
    reference), and the Integration API only rejects the read-only fields at the
    document root (``$.id``, ``$.metadata``, ...). A non-dict value is returned
    unchanged so the helper is safe to apply unconditionally.
    """
    if not isinstance(value, dict):
        return value
    dropped = _INTEGRATION_READONLY_FIELDS - keep
    return {k: v for k, v in value.items() if k not in dropped}


def sanitize_integration_write(value: Any, keep: frozenset[str] = frozenset()) -> Any:
    """Prepare an Integration write body from a read-modify-write round-trip.

    Applies both round-trip guards a ``get_* -> update_*`` cycle needs:
    :func:`strip_readonly_fields` (drop server-managed top-level fields the API
    rejects) and :func:`strip_empty_list_values` (drop the placeholder empty
    strings the API pads list fields with). Neither mutates the input. ``keep`` is
    passed to :func:`strip_readonly_fields`.
    """
    return strip_readonly_fields(strip_empty_list_values(value), keep)


#: The update tools whose body is an Integration write (sanitized by
#: :func:`sanitize_integration_write`), mapped to the read-only fields their published
#: request schema accepts (kept). The one source for both the tool and the empty-update
#: guard (``write_body.EmptyUpdateMiddleware``), which judges the FINAL sanitized body, so
#: a body of only server-managed fields (``{"id": ..., "metadata": ...}``) is refused
#: before any request instead of being sent as ``{}``.
INTEGRATION_UPDATE_KEEP: dict[str, frozenset[str]] = {
    "update_network": frozenset(),
    "update_wifi_broadcast": frozenset(),
    "update_dns_policy": frozenset(),
    "update_traffic_matching_list": frozenset(),
    "update_firewall_policy": frozenset(),
    "patch_firewall_policy": frozenset(),
    "update_firewall_zone_proxy": frozenset(),
    # The published "ACL rule update" schema lists ``index`` as a request property.
    "update_acl_rule": frozenset({"index"}),
}


def server_managed_fields(tool: str) -> frozenset[str]:
    """The top-level fields ``tool`` never sends (empty for a non-Integration update)."""
    keep = INTEGRATION_UPDATE_KEEP.get(tool)
    return frozenset() if keep is None else _INTEGRATION_READONLY_FIELDS - keep


def integration_update_body(tool: str, value: Any) -> Any:
    """The final Integration body ``tool`` sends; raises when it carries no field.

    ``tool`` must be in :data:`INTEGRATION_UPDATE_KEEP` (``KeyError`` otherwise, so a new
    tool cannot skip the declaration the guard reads). The empty-update check runs on the
    sanitized body, the one the client would send. Call this helper before host/site
    resolution or any other request.
    """
    from ..write_body import require_update_fields

    require_update_fields(value, f"{tool} body", server_managed=server_managed_fields(tool))
    return sanitize_integration_write(value, INTEGRATION_UPDATE_KEEP[tool])


def strip_empty_list_values(value: Any) -> Any:
    """Return a copy of ``value`` with empty-string entries removed from lists.

    Recurses into dicts and lists. Empty strings are dropped only when they are
    list elements; scalar string fields are preserved verbatim.
    """
    if isinstance(value, dict):
        return {k: strip_empty_list_values(v) for k, v in value.items()}
    if isinstance(value, list):
        return [strip_empty_list_values(item) for item in value if item != ""]
    return value
