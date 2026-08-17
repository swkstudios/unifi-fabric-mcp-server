"""UniFi Carrier / ISP Fabric — Subscriber API tools (cloud, api.ui.com/v1/carrier).

The UniFi Carrier / ISP Fabric *Subscriber API* (published at
https://developer.ui.com/carrier-fabric/v1.0.0, OpenAPI 3.0.3, version 1.0.0) lets
an ISP operator's CRM / BSS manage subscribers and read service plans on the UniFi
Carrier (ISP) Fabric. It is a *cloud* resource family served directly from the Site
Manager gateway (base ``https://api.ui.com``) under ``/v1/carrier/...``. Its identity
model is the ISP **organization** that owns the API key — there is no console
``host``/``site`` resolution here (like Mobility, and unlike the Network/Protect
tools), so these tools never touch the host/site registry.

Auth is the same Fabric / Site Manager API key plumbing used everywhere else in this
server: the key is sent in the ``X-API-Key`` header (the spec's ``apiKeyAuth``
scheme), and an optional ``key_label`` selects a specific configured key for
multi-key deployments (``APIKeyConfig.label``). A key of the wrong type (the spec
requires an *ISP* key), a missing permission-whitelist scope, or a request outside a
key's subscriber-group whitelist surfaces as the upstream error verbatim (HTTP
401 ``unauthorized`` / 403 ``insufficient_scope`` / 404 / 409, with the gateway's
machine-readable ``error.code`` and ``traceId``) — the server does not mask it. The
documented, stable field to switch on is ``error.code``; never parse ``error.message``.

CRITICAL — not testable against the maintainer's live hardware; hermetic/spec-conformance
tested only. The Carrier / ISP Fabric is **not deployed on the maintainer's hardware**:
there is no ISP organization and no ISP-type API key, so no
live call to these endpoints is possible, ever. Every tool here is verified only by
hermetic respx fixtures built from the exact OpenAPI request/response shapes — it is
spec-conformance tested, NOT live-verified against a production deployment. Treat any
"verified" flag in a
write result as "matched the documented response shape in a mock", not as evidence
the real Carrier Fabric behaved this way.

Reads are typed pass-throughs. The seven documented writes (create / patch a
subscriber; attach / detach the gateway host; assign a plan; suspend / resume) are
each guarded: read-before (proves existence + snapshots state), no-op detection
against the observable subscriber state, a required ``confirm=true``, an environment
kill-switch (``UNIFI_ENABLE_CARRIER_FABRIC_WRITE``, OFF by default), and a read-after
that reports what actually changed. Because the family cannot be exercised live, the
write gate ships OFF and dev compose decides whether to enable it.
"""

from __future__ import annotations

import os
from typing import Any

from ..client import PaginationAbortedError, UniFiClient, validate_id
from ..config import APIKeyConfig

#: Cloud gateway base for the Carrier / ISP Fabric family (served from api.ui.com).
CARRIER_BASE = "/v1/carrier"
_SUBSCRIBERS = f"{CARRIER_BASE}/subscribers"
_SERVICE_PLANS = f"{CARRIER_BASE}/service-plans"

#: Documented ``limit`` bound for the cursor-paginated subscriber collection
#: (OpenAPI: minimum 1, maximum 500, default 50). The drainer requests the max.
_MAX_PAGE_SIZE = 500

#: Documented ``sort`` enum for listSubscribers.
_SORT_VALUES = ("createdAt", "-createdAt", "name", "-name", "subscriberNumber", "-subscriberNumber")

#: Backstop for the cursor drain when the gateway never signals ``hasMore: false``.
_MAX_PAGES = 10_000

#: Environment write-gate for the seven Carrier Fabric writes. Gated OFF by default:
#: an *unset* variable leaves writes DISABLED. This family is not testable against the
#: maintainer's live hardware (no ISP organization / ISP key exists here), so nothing has
#: ever exercised a real
#: Carrier write; the gate ships OFF and the dev compose environment decides whether to
#: enable it. Enable only by setting the variable to a truthy value ("1"/"true"/"yes"/
#: "on"). ``confirm=true`` remains independently required on every write.
WRITE_ENABLED_ENV = "UNIFI_ENABLE_CARRIER_FABRIC_WRITE"

_DISABLED_MSG = (
    "Carrier Fabric writes are gated OFF: environment variable "
    f"{WRITE_ENABLED_ENV} is unset or not truthy. This tool family is "
    "not testable against the maintainer's live hardware (no ISP organization/key on "
    "this deployment) and the "
    "gate ships OFF; set it to a truthy value (1/true/yes/on) to enable. confirm=true "
    "remains required."
)

#: sentinel value distinguishing "argument omitted" from "explicitly set to null" on the
#: nullable PATCH fields, so a caller can clear a nullable subscriber field.
_UNSET: Any = object()


# --- Key / gate / envelope helpers ------------------------------------------


def _select_key(client: UniFiClient, key_label: str | None) -> APIKeyConfig | None:
    """Resolve the optional API-key label to a key config (None → default key).

    Raises ``KeyError`` (via ``get_key_by_label``) when the label is unknown, so a
    typo'd label fails loudly rather than silently riding the default key.
    """
    if key_label is None:
        return None
    return client.get_key_by_label(key_label)


def _writes_enabled() -> bool:
    """True only when the write-gate env var is explicitly set to a truthy value.

    Gated OFF by default (unset → disabled). ``confirm=true`` is a separate,
    always-required guard.
    """
    raw = os.environ.get(WRITE_ENABLED_ENV)
    if raw is None:
        return False
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _unwrap_data_obj(raw: Any) -> dict[str, Any]:
    """Return the ``data`` object from a single-resource envelope (``{}`` otherwise)."""
    if isinstance(raw, dict):
        inner = raw.get("data")
        if isinstance(inner, dict):
            return inner
    return {}


# --- Validation helpers ------------------------------------------------------


def _validate_len(value: Any, name: str, low: int, high: int) -> None:
    """Enforce the documented min/max character length for a string field."""
    if not isinstance(value, str):
        raise ValueError(f"{name!r} must be a string")
    if not (low <= len(value) <= high):
        raise ValueError(f"{name!r} must be {low}-{high} characters (got {len(value)})")


def _validate_metadata(value: Any, name: str = "metadata") -> None:
    """Enforce that a metadata field is a JSON object (the documented ``type: object``)."""
    if not isinstance(value, dict):
        raise ValueError(f"{name!r} must be an object (mapping)")


# --- Cursor pagination -------------------------------------------------------


async def _paginate_cursor(
    client: UniFiClient,
    path: str,
    *,
    key: APIKeyConfig | None,
    params: dict[str, Any],
    page_size: int,
) -> list[dict[str, Any]]:
    """Drain the Carrier Fabric cursor-paginated collection into a single list.

    The subscriber list is neither offset- nor ``nextToken``-paginated: it returns a
    ``{"data": [...], "meta": {"nextCursor": ..., "limit": N, "hasMore": bool}}``
    envelope where the follow-up page is requested with ``?cursor=<meta.nextCursor>``.
    Pages are drained until ``meta.hasMore`` is false (or ``nextCursor`` is absent).
    Two defensive backstops match the house pagination style: a repeated-cursor stall
    guard and an absolute page cap, both raising ``PaginationAbortedError`` (carrying
    the pages already gathered) rather than looping forever or truncating silently.
    """
    all_items: list[dict[str, Any]] = []
    req_params = dict(params)
    req_params["limit"] = page_size
    prev_cursor: str | None = None
    page_count = 0

    while True:
        data = await client.get(path, key=key, params=req_params)
        page_count += 1
        items = data.get("data") if isinstance(data, dict) else None
        if isinstance(items, list):
            all_items.extend(items)

        meta = data.get("meta") if isinstance(data, dict) else None
        next_cursor = meta.get("nextCursor") if isinstance(meta, dict) else None
        has_more = bool(meta.get("hasMore")) if isinstance(meta, dict) else False
        if not has_more or not next_cursor:
            break

        if next_cursor == prev_cursor:
            raise PaginationAbortedError(
                path,
                page_count,
                f"stall detected — nextCursor {next_cursor!r} repeated",
                items=all_items,
            )
        if page_count >= _MAX_PAGES:
            raise PaginationAbortedError(
                path, page_count, f"page cap of {_MAX_PAGES} reached", items=all_items
            )

        prev_cursor = next_cursor
        req_params["cursor"] = next_cursor

    return all_items


# --- Reads -------------------------------------------------------------------


async def list_carrier_subscribers(
    client: UniFiClient,
    *,
    plan_id: str | None = None,
    suspended: bool | None = None,
    sort: str | None = None,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List Carrier / ISP Fabric subscribers visible to the authenticated ISP key.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only — the Carrier
    Fabric is not deployed here, so this is verified against the OpenAPI shapes, not
    a live console.

    Each subscriber carries ``id``, ``orgId``, ``subscriberNumber``, ``name``,
    ``email``, ``notes``, ``serviceAddress``, ``planId``, ``hostId``, ``state``
    (pending_assignment/provisioned/installed/suspended), ``suspended``,
    ``suspendReason``, and the ``*At`` timestamps, returned verbatim. The collection
    is cursor-paginated by the API (``limit``/``cursor`` with a ``meta.hasMore``
    signal); every page is drained and the complete list is returned under
    ``subscribers``.

    plan_id: optional service-plan UUID to return only subscribers on that plan.
    suspended: optional boolean to filter by suspension state.
    sort: optional ordering — one of createdAt, -createdAt, name, -name,
        subscriberNumber, -subscriberNumber.
    key_label: optional configured API-key label to route on a specific key.
    """
    params: dict[str, Any] = {}
    if plan_id is not None:
        validate_id(plan_id, "plan_id")
        params["planId"] = plan_id
    if suspended is not None:
        if not isinstance(suspended, bool):
            raise ValueError("suspended must be a boolean")
        params["suspended"] = suspended
    if sort is not None:
        if sort not in _SORT_VALUES:
            raise ValueError(f"Invalid sort {sort!r}: expected one of {', '.join(_SORT_VALUES)}")
        params["sort"] = sort

    key = _select_key(client, key_label)
    items = await _paginate_cursor(
        client, _SUBSCRIBERS, key=key, params=params, page_size=_MAX_PAGE_SIZE
    )
    return {"subscribers": items, "count": len(items)}


async def get_carrier_subscriber(
    client: UniFiClient,
    subscriber_id: str,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Get one Carrier / ISP Fabric subscriber by ID.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only.

    Returns the full Subscriber object verbatim under ``subscriber``. A subscriber
    outside the key's whitelist, or an unknown id, surfaces the upstream
    ``subscriber_not_found`` (404) verbatim.

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(subscriber_id, "subscriber_id")
    key = _select_key(client, key_label)
    raw = await client.get(f"{_SUBSCRIBERS}/{subscriber_id}", key=key)
    return {"subscriber": _unwrap_data_obj(raw)}


async def list_carrier_service_plans(
    client: UniFiClient,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List the Carrier / ISP Fabric service plans for the authenticated organization.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only.

    Each plan carries ``id``, ``orgId``, ``name``, ``status`` (active/archived),
    ``downloadMbps``, ``uploadMbps``, ``metadata`` and the ``*At`` timestamps,
    returned verbatim under ``service_plans``. This endpoint is not query-paginated
    by the API; the full set is returned in one call.

    key_label: optional configured API-key label to route on a specific key.
    """
    key = _select_key(client, key_label)
    raw = await client.get(_SERVICE_PLANS, key=key)
    data = raw.get("data") if isinstance(raw, dict) else None
    items = data if isinstance(data, list) else []
    return {"service_plans": items, "count": len(items)}


async def get_carrier_service_plan(
    client: UniFiClient,
    plan_id: str,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Get one Carrier / ISP Fabric service plan by ID.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only.

    Returns the full ServicePlan object verbatim under ``service_plan``. An unknown
    id surfaces the upstream ``service_plan_not_found`` (404) verbatim.

    plan_id: the service-plan UUID from list_carrier_service_plans.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(plan_id, "plan_id")
    key = _select_key(client, key_label)
    raw = await client.get(f"{_SERVICE_PLANS}/{plan_id}", key=key)
    return {"service_plan": _unwrap_data_obj(raw)}


# --- Writes ------------------------------------------------------------------
#
# All seven writes are not testable against the maintainer's live hardware and share the
# guarded flow:
#   1. validate   — enforce the documented field constraints locally;
#   2. read-before— (mutations of an existing subscriber) GET it: proves existence
#                   and snapshots the current, observable state;
#   3. no-op      — if the change is fully observable AND already applied, return
#                   status="no_op" without writing;
#   4. confirm    — confirm must be True (the operative guard), else
#                   status="unconfirmed" with a current-vs-proposed preview;
#   5. env gate   — the write kill-switch (OFF by default) blocks the write;
#   6. write      — issue it. Unlike the Mobility 204 writes, every Carrier write
#                   answers 200/201 with the updated resource, so the JSON body is
#                   decoded and used as the read-after.
#
# "verified" flags mean "matched the documented response shape in a mock", never
# "confirmed against the live Carrier Fabric" (no live Carrier Fabric deployment here).


async def _fetch_subscriber(
    client: UniFiClient, subscriber_id: str, key: APIKeyConfig | None
) -> dict[str, Any]:
    """GET a subscriber and unwrap its ``{"data": {...}}`` envelope (read-before)."""
    raw = await client.get(f"{_SUBSCRIBERS}/{subscriber_id}", key=key)
    return _unwrap_data_obj(raw)


def _unconfirmed(proposed: dict[str, Any], action: str, **extra: Any) -> dict[str, Any]:
    result = {
        "status": "unconfirmed",
        "reason": f"Set confirm=true to {action}.",
        "proposed": proposed,
    }
    result.update(extra)
    return result


async def create_carrier_subscriber(
    client: UniFiClient,
    subscriber_number: str,
    *,
    name: str | None = None,
    email: str | None = None,
    notes: str | None = None,
    service_address: str | None = None,
    plan_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Create a Carrier / ISP Fabric subscriber (POST /v1/carrier/subscribers). Guarded write.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only. There is no ISP
    organization on this deployment; a live create is impossible.

    Sends the documented SubscriberCreate body. ``subscriber_number`` is required
    (1-32 chars, unique within the org). Optional: ``name`` (<=128), ``email``
    (<=255), ``notes`` (<=4096), ``service_address`` (<=1024), ``plan_id`` (a service
    plan UUID; an archived/unknown plan is rejected upstream), and ``metadata`` (an
    opaque JSON object). There is no read-before/no-op for a create; the POST returns
    the created subscriber (201), reported under ``subscriber``. Requires confirm=true
    and the write kill-switch.

    subscriber_number: the unique subscriber number (1-32 characters).
    name/email/notes/service_address: optional profile fields (see length limits above).
    plan_id: optional service-plan UUID to assign at creation.
    metadata: optional opaque JSON object.
    confirm: must be true to apply the create.
    key_label: optional configured API-key label to route on a specific key.
    """
    _validate_len(subscriber_number, "subscriber_number", 1, 32)
    body: dict[str, Any] = {"subscriberNumber": subscriber_number}
    if name is not None:
        _validate_len(name, "name", 0, 128)
        body["name"] = name
    if email is not None:
        _validate_len(email, "email", 0, 255)
        body["email"] = email
    if notes is not None:
        _validate_len(notes, "notes", 0, 4096)
        body["notes"] = notes
    if service_address is not None:
        _validate_len(service_address, "service_address", 0, 1024)
        body["serviceAddress"] = service_address
    if plan_id is not None:
        validate_id(plan_id, "plan_id")
        body["planId"] = plan_id
    if metadata is not None:
        _validate_metadata(metadata)
        body["metadata"] = metadata

    if not confirm:
        return _unconfirmed(body, "create this subscriber")
    if not _writes_enabled():
        return {"status": "disabled", "reason": _DISABLED_MSG}

    raw = await client.post(_SUBSCRIBERS, key=_select_key(client, key_label), json=body)
    return {"status": "created", "subscriber": _unwrap_data_obj(raw)}


async def update_carrier_subscriber(
    client: UniFiClient,
    subscriber_id: str,
    *,
    subscriber_number: str = _UNSET,
    name: str | None = _UNSET,
    email: str | None = _UNSET,
    notes: str | None = _UNSET,
    service_address: str | None = _UNSET,
    plan_id: str | None = _UNSET,
    metadata: dict[str, Any] | None = _UNSET,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Update a Carrier / ISP Fabric subscriber (PATCH .../subscribers/{id}). Guarded write.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only.

    This is a DOCUMENTED partial update: only the fields you pass are sent, and any
    field you omit is left unchanged. At least one field must be provided. The
    nullable fields (``name``, ``email``, ``notes``, ``service_address``, ``plan_id``,
    ``metadata``) accept an explicit ``None`` to clear them; ``subscriber_number`` is
    not nullable (1-32 chars when provided). Guarded: read-before, no-op when every
    provided field already matches the current subscriber, confirm=true, write
    kill-switch, and a read-after from the PATCH response (200).

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    subscriber_number: optional new subscriber number (1-32 characters).
    name/email/notes/service_address/plan_id/metadata: optional new values; pass None
        to clear a nullable field. Fields not passed are left untouched.
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(subscriber_id, "subscriber_id")

    # Build the partial body from only the provided (non-sentinel) fields. The map is
    # (arg value, wire key, current-state key, validator|None).
    body: dict[str, Any] = {}
    if subscriber_number is not _UNSET:
        _validate_len(subscriber_number, "subscriber_number", 1, 32)
        body["subscriberNumber"] = subscriber_number
    if name is not _UNSET:
        if name is not None:
            _validate_len(name, "name", 0, 128)
        body["name"] = name
    if email is not _UNSET:
        if email is not None:
            _validate_len(email, "email", 0, 255)
        body["email"] = email
    if notes is not _UNSET:
        if notes is not None:
            _validate_len(notes, "notes", 0, 4096)
        body["notes"] = notes
    if service_address is not _UNSET:
        if service_address is not None:
            _validate_len(service_address, "service_address", 0, 1024)
        body["serviceAddress"] = service_address
    if plan_id is not _UNSET:
        if plan_id is not None:
            validate_id(plan_id, "plan_id")
        body["planId"] = plan_id
    if metadata is not _UNSET:
        if metadata is not None:
            _validate_metadata(metadata)
        body["metadata"] = metadata

    if not body:
        raise ValueError(
            "No fields provided: supply at least one of subscriber_number, name, email, "
            "notes, service_address, plan_id, metadata"
        )

    key = _select_key(client, key_label)
    before = await _fetch_subscriber(client, subscriber_id, key)
    if all(before.get(wire) == value for wire, value in body.items()):
        return {
            "status": "no_op",
            "reason": "Every provided field already matches the subscriber; no write performed.",
            "subscriber": before,
        }
    if not confirm:
        return _unconfirmed(body, "apply this subscriber update", subscriber=before)
    if not _writes_enabled():
        return {"status": "disabled", "reason": _DISABLED_MSG}

    raw = await client.patch(f"{_SUBSCRIBERS}/{subscriber_id}", key=key, json=body)
    after = _unwrap_data_obj(raw)
    changed = {
        wire: {"from": before.get(wire), "to": value}
        for wire, value in body.items()
        if before.get(wire) != value
    }
    return {"status": "updated", "changed": changed, "subscriber": after}


async def attach_carrier_subscriber_host(
    client: UniFiClient,
    subscriber_id: str,
    host_id: str,
    *,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Attach or re-link a subscriber's gateway host (PUT .../subscribers/{id}/host). Guarded.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only.

    Sends the documented body ``{"hostId": host_id}``. ``host_id`` must be a host in
    the same ISP organization (an out-of-org host, or a gateway already attached
    elsewhere, is rejected upstream — 400 ``host_not_in_organization`` / 409
    ``gateway_already_attached``). Guarded: read-before, no-op when the subscriber is
    already linked to this host, confirm=true, write kill-switch, and a read-after
    from the response (200 HostLinkResponse, which also reports ``prevHostId``).

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    host_id: the gateway host id to link (as reported by the host directory).
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(subscriber_id, "subscriber_id")
    if not isinstance(host_id, str) or not host_id:
        raise ValueError("host_id must be a non-empty string")

    key = _select_key(client, key_label)
    before = await _fetch_subscriber(client, subscriber_id, key)
    if before.get("hostId") == host_id:
        return {
            "status": "no_op",
            "reason": f"Subscriber is already linked to host {host_id!r}; no write performed.",
            "subscriber": before,
        }
    if not confirm:
        return _unconfirmed(
            {"hostId": host_id},
            "attach this gateway host",
            current_host_id=before.get("hostId"),
        )
    if not _writes_enabled():
        return {"status": "disabled", "reason": _DISABLED_MSG}

    raw = await client.put(
        f"{_SUBSCRIBERS}/{subscriber_id}/host", key=key, json={"hostId": host_id}
    )
    after = _unwrap_data_obj(raw)
    return {
        "status": "attached",
        "changed": {"hostId": {"from": before.get("hostId"), "to": host_id}},
        "prev_host_id": raw.get("prevHostId") if isinstance(raw, dict) else None,
        "verified": after.get("hostId") == host_id,
        "subscriber": after,
    }


async def detach_carrier_subscriber_host(
    client: UniFiClient,
    subscriber_id: str,
    *,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Detach a subscriber's gateway host (DELETE .../subscribers/{id}/host). Guarded write.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only.

    Takes no body. Guarded: read-before, no-op when the subscriber has no attached
    host (``hostId`` is null — the upstream would otherwise answer 409
    ``no_attached_host``), confirm=true, write kill-switch, and a read-after from the
    response (200 HostLinkResponse, reporting the just-detached host as ``prevHostId``).
    The DELETE returns a JSON body, so the raw request is used and decoded (the shared
    ``client.delete`` discards the body).

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(subscriber_id, "subscriber_id")
    key = _select_key(client, key_label)
    before = await _fetch_subscriber(client, subscriber_id, key)
    if before.get("hostId") in (None, ""):
        return {
            "status": "no_op",
            "reason": "Subscriber has no attached host; no write performed.",
            "subscriber": before,
        }
    if not confirm:
        return {
            "status": "unconfirmed",
            "reason": "Set confirm=true to detach this gateway host.",
            "current_host_id": before.get("hostId"),
        }
    if not _writes_enabled():
        return {"status": "disabled", "reason": _DISABLED_MSG}

    resp = await client.request("DELETE", f"{_SUBSCRIBERS}/{subscriber_id}/host", key=key)
    raw = client._decode_json(resp)  # HostLinkResponse body (client.delete discards it)
    after = _unwrap_data_obj(raw)
    return {
        "status": "detached",
        "changed": {"hostId": {"from": before.get("hostId"), "to": None}},
        "prev_host_id": raw.get("prevHostId") if isinstance(raw, dict) else before.get("hostId"),
        "verified": after.get("hostId") in (None, ""),
        "subscriber": after,
    }


async def assign_carrier_subscriber_plan(
    client: UniFiClient,
    subscriber_id: str,
    plan_id: str,
    *,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Assign a service plan to a subscriber (PUT .../subscribers/{id}/plan). Guarded write.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only.

    Sends the documented body ``{"planId": plan_id}``. An archived or unknown plan is
    rejected upstream (400 ``service_plan_archived`` / 404 ``service_plan_not_found``).
    Guarded: read-before, no-op when the subscriber is already on this plan,
    confirm=true, write kill-switch, and a read-after from the response (200).

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    plan_id: the service-plan UUID to assign (from list_carrier_service_plans).
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(subscriber_id, "subscriber_id")
    validate_id(plan_id, "plan_id")

    key = _select_key(client, key_label)
    before = await _fetch_subscriber(client, subscriber_id, key)
    if before.get("planId") == plan_id:
        return {
            "status": "no_op",
            "reason": f"Subscriber is already on plan {plan_id!r}; no write performed.",
            "subscriber": before,
        }
    if not confirm:
        return _unconfirmed(
            {"planId": plan_id}, "assign this service plan", current_plan_id=before.get("planId")
        )
    if not _writes_enabled():
        return {"status": "disabled", "reason": _DISABLED_MSG}

    raw = await client.put(
        f"{_SUBSCRIBERS}/{subscriber_id}/plan", key=key, json={"planId": plan_id}
    )
    after = _unwrap_data_obj(raw)
    return {
        "status": "assigned",
        "changed": {"planId": {"from": before.get("planId"), "to": plan_id}},
        "verified": after.get("planId") == plan_id,
        "subscriber": after,
    }


async def suspend_carrier_subscriber(
    client: UniFiClient,
    subscriber_id: str,
    *,
    reason: str | None = None,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Suspend a subscriber's service (POST .../subscribers/{id}/suspend). Guarded write.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only.

    Sends the documented body ``{"reason": reason}`` when a reason is supplied (the
    body is optional per the spec; an omitted reason sends no body). Guarded:
    read-before, no-op when the subscriber is already suspended, confirm=true, write
    kill-switch, and a read-after from the response (200).

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    reason: optional free-text suspension reason recorded on the subscriber.
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(subscriber_id, "subscriber_id")
    if reason is not None and not isinstance(reason, str):
        raise ValueError("reason must be a string")

    key = _select_key(client, key_label)
    before = await _fetch_subscriber(client, subscriber_id, key)
    if before.get("suspended") is True:
        return {
            "status": "no_op",
            "reason": "Subscriber is already suspended; no write performed.",
            "subscriber": before,
        }
    if not confirm:
        return {
            "status": "unconfirmed",
            "reason": "Set confirm=true to suspend this subscriber.",
            "proposed_reason": reason,
        }
    if not _writes_enabled():
        return {"status": "disabled", "reason": _DISABLED_MSG}

    body = {"reason": reason} if reason is not None else None
    raw = await client.post(f"{_SUBSCRIBERS}/{subscriber_id}/suspend", key=key, json=body)
    after = _unwrap_data_obj(raw)
    return {
        "status": "suspended",
        "verified": after.get("suspended") is True,
        "subscriber": after,
    }


async def resume_carrier_subscriber(
    client: UniFiClient,
    subscriber_id: str,
    *,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Resume a suspended subscriber's service (POST .../subscribers/{id}/resume). Guarded.

    Not testable against the maintainer's live hardware; hermetic/spec-conformance
    tested only.

    Takes no body. Guarded: read-before, no-op when the subscriber is not currently
    suspended, confirm=true, write kill-switch, and a read-after from the response
    (200).

    subscriber_id: the subscriber UUID from list_carrier_subscribers.
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(subscriber_id, "subscriber_id")
    key = _select_key(client, key_label)
    before = await _fetch_subscriber(client, subscriber_id, key)
    if before.get("suspended") is False:
        return {
            "status": "no_op",
            "reason": "Subscriber is not suspended; no write performed.",
            "subscriber": before,
        }
    if not confirm:
        return {
            "status": "unconfirmed",
            "reason": "Set confirm=true to resume this subscriber.",
            "current_suspended": before.get("suspended"),
        }
    if not _writes_enabled():
        return {"status": "disabled", "reason": _DISABLED_MSG}

    raw = await client.post(f"{_SUBSCRIBERS}/{subscriber_id}/resume", key=key, json=None)
    after = _unwrap_data_obj(raw)
    return {
        "status": "resumed",
        "verified": after.get("suspended") is False,
        "subscriber": after,
    }
