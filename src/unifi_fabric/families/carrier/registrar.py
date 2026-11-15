"""The carrier family registrar: its tool wrappers, in registration order (the family-owned layout).

The loader map (``catalog/loaders.py``) runs each ``register`` / ``register_<n>`` below at its place
in the ``tools/list`` order, with the ``origin`` its tools are indexed under. The wrappers are the
tools' public surface (names, annotations, docstrings, signatures), moved by
``scripts/move_family.py``; each calls its handler through the handler's module, so a patched
handler still applies (``handlers.py`` indexes them).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP
from pydantic import Field

from ...shared_shapes._shared import _nullable_default
from ...tool_annotations import READ_ONLY, WRITE
from . import carrier_fabric


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the carrier_fabric tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_carrier_subscribers(
        plan_id: str | None = None,
        suspended: bool | None = None,
        sort: str | None = None,
        key_label: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """List Carrier / ISP Fabric subscribers visible to the authenticated ISP key.

        Returns {data, _count} and the first page's envelope fields; several keys put
        envelopes under byKey, annotate records with _keyLabel, and report per-key
        errors. incomplete/incompleteReason appear when a drain stops early. A bare-array
        page is returned as an array; an object without a data array raises.
        Spec-conformance tested only, without live Carrier.

        Default drains every cursor page. limit requests that many subscribers, or all
        available if fewer exist, gathered in native pages up to the spec maximum 500;
        the full final page can exceed limit to preserve its native continuation;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count. cursor selects the
        starting meta.nextCursor; alone, it fetches one page with its native meta
        continuation. With several keys, limit/cursor needs key_label.

        Args:
            plan_id: Optional service-plan UUID from list_carrier_service_plans (id).
                Example: "3fa85f64-5717-4562-b3fc-2c963f66afa6".
            suspended: Optional filter: true for suspended, false for active. Example: false.
            sort: createdAt|-createdAt|name|-name|subscriberNumber|-subscriberNumber.
                Example: "-createdAt".
            key_label: Configured API-key label from list_configured_api_keys; omit to
                aggregate all keys. Required with limit/cursor and several keys.
                Example: "primary".
            limit: Requested subscriber count, gathered in batches up to 500. Example: `100`.
            cursor: Raw meta.nextCursor for one verbatim page, or the returned opaque
                _continuation string preserving physical size when changing the requested limit.
                Example: the token from the previous response.
        """
        client, _ = deps_fn()
        return await carrier_fabric.list_carrier_subscribers(
            client,
            plan_id=plan_id,
            suspended=suspended,
            sort=sort,
            key_label=key_label,
            limit=limit,
            cursor=cursor,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_carrier_subscriber(
        subscriber_id: str,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Get one Carrier / ISP Fabric subscriber by ID.

        Spec-conformance tested only (not against a live Carrier Fabric).
        Returns the upstream response object verbatim: the Subscriber under data beside
        httpStatusCode and traceId; an unknown id surfaces the upstream
        subscriber_not_found (404) verbatim.

        Example call (get_carrier_subscriber):
            {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await carrier_fabric.get_carrier_subscriber(
            client, subscriber_id, key_label=key_label
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_carrier_service_plans(
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """List the Carrier / ISP Fabric service plans for the authenticated organization.

        Returns the upstream body verbatim ({data, httpStatusCode, traceId, ...}) plus _count; with
        several keys {data, _count, byKey} plus errors.

        Spec-conformance tested only (not against a live Carrier Fabric).
        Not query-
        paginated by the API; the full set is returned under data (the upstream key), with the
        additive _count.

        Args:
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to cover
                every configured key: results are merged, each record carries an additive _keyLabel, and
                a key that fails is reported under errors.
        """
        client, _ = deps_fn()
        return await carrier_fabric.list_carrier_service_plans(client, key_label=key_label)

    @mcp.tool(annotations=READ_ONLY)
    async def get_carrier_service_plan(
        plan_id: str,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Get one Carrier / ISP Fabric service plan by ID.

        Spec-conformance tested only (not against a live Carrier Fabric).
        Returns the upstream response object verbatim: the ServicePlan under data beside
        httpStatusCode and traceId. An unknown id
        surfaces the upstream service_plan_not_found (404) verbatim.

        Example call (get_carrier_service_plan):
            {"plan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            plan_id: Carrier Fabric service-plan UUID. Get it from list_carrier_service_plans (id).
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await carrier_fabric.get_carrier_service_plan(client, plan_id, key_label=key_label)

    @mcp.tool(annotations=WRITE)
    async def create_carrier_subscriber(
        subscriber_number: str,
        name: str | None = None,
        email: str | None = None,
        notes: str | None = None,
        service_address: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
        plan_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Create a Carrier / ISP Fabric subscriber (POST /v1/carrier/subscribers). Guarded write.

        Returns {status: "created", changed (every sent field as {from: null, to}), subscriber (the 201 body verbatim, {data, traceId}, when it carries the created resource, else null), response (the upstream write body verbatim)}. Under dry-run policy nothing is sent: {status: "dry_run", subscriber: null, response (the preview)}.

        Spec-conformance tested only (not against a live Carrier Fabric). subscriber_number is required (1-32 chars). Optional name (<=128 bytes), email (<=255 bytes), notes (<=4096 bytes), service_address (<=1024 bytes), plan_id (UUID), metadata (object). Per the spec those limits are bytes of UTF-8, so a multi-byte character counts as more than one. Refused when UNIFI_WRITE_POLICY=deny or the UNIFI_WRITE_EXCEPTIONS entry family:carrier=deny is set (writes are enabled by default).

        Example call (create_carrier_subscriber):
            {"subscriber_number": "SUB-1001"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Details: docs/TOOL-USAGE.md#create_carrier_subscriber.

        Args:
            subscriber_number: Unique subscriber number, 1-32 chars. REQUIRED (body field
                subscriberNumber: string).
            name: Subscriber display name. Optional (body field name: string).
            email: Subscriber email. Optional (body field email: string(email)).
            notes: Free-text notes. Optional (body field notes: string).
            service_address: Free-text service address (a string, per the spec), at most 1024
                bytes of UTF-8. Optional (body field serviceAddress: string).
            plan_id: Carrier Fabric service-plan UUID. Get it from list_carrier_service_plans (id).
            metadata: Optional profile key/values (body field metadata: object); its serialized
                JSON may be at most 8192 bytes of UTF-8, as the spec states.
                Free-form JSON object; arbitrary metadata properties are passed unchanged.
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). With one key,
                omit it. With several keys: when plan_id is given and key_label is omitted, the
                subscriber is created under the key that owns that plan; otherwise pass the label
                of the organization that should own the subscriber (omitting it fails fast listing
                the configured labels, it never picks the first key).
        """
        service_address = _nullable_default(service_address, carrier_fabric._UNSET)
        client, _ = deps_fn()
        return await carrier_fabric.create_carrier_subscriber(
            client,
            subscriber_number,
            name=name,
            email=email,
            notes=notes,
            service_address=service_address,
            plan_id=plan_id,
            metadata=metadata,
            confirm=confirm,
            key_label=key_label,
        )

    @mcp.tool(annotations=WRITE)
    async def update_carrier_subscriber(
        subscriber_id: str,
        subscriber_number: str | None = None,
        name: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
        email: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
        notes: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
        service_address: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
        plan_id: str | None = Field(default_factory=lambda: carrier_fabric._UNSET),
        metadata: dict[str, Any] | None = Field(  # noqa: B008 — distinguish omission from null
            default_factory=lambda: carrier_fabric._UNSET
        ),
        confirm: bool = False,
        key_label: str | None = None,
        clear_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Update a Carrier Fabric subscriber (PATCH .../subscribers/{id}).

        Returns {status: "updated", changed: {field: {from, to}}, verified, subscriber, response (the upstream write body verbatim)}, or {status: "no_op", reason, subscriber}. subscriber is a full body, never unwrapped: the write response when it carries the subscriber, else the read-back GET body (for no_op, the GET body read first). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", subscriber (the body read first), response (the preview: method, path, params, body)}; there is no read-after.

        Spec-conformance tested only (not live). Partial update: pass at least one field. subscriber_number is 1-32 chars after trimming when provided; name, email, notes, service_address are limited to 128 / 255 / 4096 / 1024 bytes of UTF-8 (the spec's unit). Guarded, in order: the Carrier write opt-out (family:carrier=deny refuses first), read-before, no-op when all provided fields already match, write, read-after. Omission leaves a field unchanged; explicit null clears a nullable field, as does naming it in clear_fields (sent as JSON null). Per the spec, null clears name, email, notes, serviceAddress and planId; subscriberNumber cannot be cleared, and metadata=null leaves metadata unchanged (send metadata={} to empty it). Explicit metadata=null alone is a no-op; null is forwarded only alongside another change.

        Example call (update_carrier_subscriber):
            {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "notes": "Moved to plan B"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Details: docs/TOOL-USAGE.md#update_carrier_subscriber.

        Args:
            subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
            subscriber_number: Unique subscriber number, 1-32 chars. Optional (body field
                subscriberNumber: string).
            name: Subscriber display name, non-empty after trimming (the spec rejects a blank name;
                clear it with explicit null or clear_fields). Optional (body field name: string).
            email: Subscriber email. Optional (body field email: string(email)).
            notes: Free-text notes. Optional (body field notes: string).
            service_address: Free-text service address (a string, per the spec), at most 1024
                bytes of UTF-8. Optional (body field serviceAddress: string).
            plan_id: Carrier Fabric service-plan UUID. Get it from list_carrier_service_plans (id).
            metadata: Optional replacement metadata object (body field metadata); it replaces the
                whole document, so pass {} to empty it. Explicit metadata=null alone is a no-op;
                null is forwarded only alongside another change and leaves metadata unchanged.
                Omission leaves metadata unchanged. A subscriber with no metadata reads back
                without the key (the spec omits it), which counts as {}: metadata={} on it is a no-op.
                Its serialized JSON may be at most 8192 bytes of UTF-8, as the spec states.
                Free-form JSON object; arbitrary metadata properties are passed unchanged.
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
            clear_fields: Optional list of fields to clear by sending JSON null: any of "name",
                "email", "notes", "service_address", "plan_id". A field named here must not also be
                given a value. Omit to clear nothing (the default; existing behaviour).
                Shape: ('name'|'email'|'notes'|'service_address'|'plan_id')[]
        """
        name = _nullable_default(name, carrier_fabric._UNSET)
        email = _nullable_default(email, carrier_fabric._UNSET)
        notes = _nullable_default(notes, carrier_fabric._UNSET)
        service_address = _nullable_default(service_address, carrier_fabric._UNSET)
        plan_id = _nullable_default(plan_id, carrier_fabric._UNSET)
        metadata = _nullable_default(metadata, carrier_fabric._UNSET)
        client, _ = deps_fn()
        kwargs: dict[str, Any] = {"confirm": confirm, "key_label": key_label}
        clearable = ("name", "email", "notes", "service_address", "plan_id")
        given = {
            "name": name,
            "email": email,
            "notes": notes,
            "service_address": service_address,
            "plan_id": plan_id,
        }
        for field in clear_fields or []:
            if field not in clearable:
                raise ValueError(
                    f"clear_fields: {field!r} cannot be cleared. Clearable fields (sent as JSON null): "
                    f"{', '.join(clearable)}. subscriber_number cannot be cleared, and metadata is not "
                    "cleared by null (pass metadata={} to empty it)."
                )
            if given[field] is not carrier_fabric._UNSET and given[field] is not None:
                raise ValueError(
                    f"clear_fields names {field!r} but a value was also given for it: pass one or the "
                    "other."
                )
            kwargs[field] = None
        # Preserve omitted fields separately from explicit JSON null clears.
        if subscriber_number is not None:
            kwargs["subscriber_number"] = subscriber_number
            kwargs["_preserve_subscriber_number"] = True
        if name is not carrier_fabric._UNSET:
            kwargs["name"] = name
        if email is not carrier_fabric._UNSET:
            kwargs["email"] = email
        if notes is not carrier_fabric._UNSET:
            kwargs["notes"] = notes
        if service_address is not carrier_fabric._UNSET:
            kwargs["service_address"] = service_address
        if plan_id is not carrier_fabric._UNSET:
            kwargs["plan_id"] = plan_id
        if metadata is not carrier_fabric._UNSET:
            kwargs["metadata"] = metadata
        return await carrier_fabric.update_carrier_subscriber(client, subscriber_id, **kwargs)

    @mcp.tool(annotations=WRITE)
    async def attach_carrier_subscriber_host(
        subscriber_id: str,
        host_id: str,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Attach or re-link a subscriber's gateway host (PUT .../subscribers/{id}/host). Guarded.

        Returns {status: "attached", changed, _prev_host_id (the response's prevHostId), verified, subscriber, response (verbatim)}, or {status: "no_op", reason, subscriber}. subscriber is a full body ({data, ...}), never unwrapped: the write response when it carries the subscriber, else the read-back GET body (for no_op, the GET body read first). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", subscriber (the body read first), response (the preview: method, path, params, body)}; there is no read-after.

        Spec-conformance tested only (not against a live Carrier Fabric). host_id must be a host in the same ISP organization. Guarded, in order: the Carrier write opt-out (family:carrier=deny refuses first), read-before, no-op when already linked, write, read-after (reports _prev_host_id).

        Request body (Carrier Fabric 1.0.0, PUT /v1/carrier/subscribers/{id}/host
        (attachSubscriberHost); schema "inline requestBody schema") is built from scalar parameters.
        Required keys — hostId.
        - hostId: string

        Example call (attach_carrier_subscriber_host):
            {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
             "host_id": "942A6FF664C0000000000964970E0000000009E710560000000068A9873F:9999999999"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
            host_id: Gateway host id (Site Manager) in the same ISP org. Get it from list_hosts (id).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await carrier_fabric.attach_carrier_subscriber_host(
            client, subscriber_id, host_id, confirm=confirm, key_label=key_label
        )

    @mcp.tool(annotations=WRITE)
    async def detach_carrier_subscriber_host(
        subscriber_id: str,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Detach a subscriber's gateway host (DELETE .../subscribers/{id}/host). Guarded write.

        Consequence: the gateway host is no longer linked to the subscriber until re-attached with attach_carrier_subscriber_host.

        Returns {status: "detached", changed, _prev_host_id (the response's prevHostId), verified, subscriber, response (verbatim)}, or {status: "no_op", reason, subscriber}. subscriber is a full body ({data, ...}), never unwrapped: the write response when it carries the subscriber, else the read-back GET body (for no_op, the GET body read first). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", subscriber (the body read first), response (the preview: method, path, params, body)}; there is no read-after.

        Spec-conformance tested only (not against a live Carrier Fabric). Guarded, in order: the Carrier write opt-out (family:carrier=deny refuses first), read-before, no-op when no host is attached, write, read-after (reports the just-detached _prev_host_id).

        Example call (detach_carrier_subscriber_host):
            {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await carrier_fabric.detach_carrier_subscriber_host(
            client, subscriber_id, confirm=confirm, key_label=key_label
        )

    @mcp.tool(annotations=WRITE)
    async def assign_carrier_subscriber_plan(
        subscriber_id: str,
        plan_id: str,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Assign a service plan to a subscriber (PUT .../subscribers/{id}/plan). Guarded write.

        Returns {status: "assigned", changed, verified, subscriber, response (verbatim)}, or {status: "no_op", reason, subscriber}. subscriber is a full body ({data, ...}), never unwrapped: the write response when it carries the subscriber, else the read-back GET body (for no_op, the GET body read first). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", subscriber (the body read first), response (the preview: method, path, params, body)}; there is no read-after.

        Spec-conformance tested only (not against a live Carrier Fabric). An archived or unknown plan is rejected upstream. Guarded, in order: the Carrier write opt-out (family:carrier=deny refuses first), read-before, no-op when already on this plan, write, read-after.

        Request body (Carrier Fabric 1.0.0, PUT /v1/carrier/subscribers/{id}/plan
        (assignSubscriberPlan); schema "inline requestBody schema") is built from scalar parameters.
        Required keys — planId.
        - planId: string(uuid)

        Example call (assign_carrier_subscriber_plan):
            {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
             "plan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
            plan_id: Carrier Fabric service-plan UUID. Get it from list_carrier_service_plans (id).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await carrier_fabric.assign_carrier_subscriber_plan(
            client, subscriber_id, plan_id, confirm=confirm, key_label=key_label
        )

    @mcp.tool(annotations=WRITE)
    async def suspend_carrier_subscriber(
        subscriber_id: str,
        reason: str | None = None,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Suspend a subscriber's service (POST .../subscribers/{id}/suspend). Guarded write.

        Consequence: the subscriber's service stops until resumed with resume_carrier_subscriber.

        Returns {status: "suspended", changed (suspended, and suspendReason when a reason is sent), verified, subscriber, response (verbatim)}, or {status: "no_op", reason, subscriber}. subscriber is a full body ({data, ...}), never unwrapped: the write response when it carries the subscriber, else the read-back GET body (for no_op, the GET body read first). verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", subscriber (the body read first), response (the preview: method, path, params, body)}; there is no read-after.

        Spec-conformance tested only (not against a live Carrier Fabric). Guarded, in order: the Carrier write opt-out (family:carrier=deny refuses first), read-before, no-op only when already suspended AND no reason is given or the current suspendReason already equals it (a different reason is sent upstream), write, read-after. An optional reason is recorded on the subscriber.

        Request body (Carrier Fabric 1.0.0, POST /v1/carrier/subscribers/{id}/suspend
        (suspendSubscriber); schema "inline requestBody schema") is built from scalar parameters. No key
        is required; send only the keys to change.
        - reason: string

        Example call (suspend_carrier_subscriber):
            {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
            reason: Optional suspension reason, max 1024 chars (spec body reason).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await carrier_fabric.suspend_carrier_subscriber(
            client, subscriber_id, reason=reason, confirm=confirm, key_label=key_label
        )

    @mcp.tool(annotations=WRITE)
    async def resume_carrier_subscriber(
        subscriber_id: str,
        confirm: bool = False,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Resume a suspended subscriber's service (POST .../subscribers/{id}/resume). Guarded.

        Consequence: the subscriber's service is restored.

        Returns {status: "resumed", changed, verified, subscriber, response (verbatim)}, or {status: "no_op", reason, subscriber}. subscriber is a full body ({data, ...}), never unwrapped: the write response when it carries the subscriber, else the read-back GET body; for no_op it is the GET body read first. verified is null, with readAfterError, when the read-after fails or cannot be matched. Under dry-run policy nothing is sent: {status: "dry_run", subscriber (the body read first), response (the preview: method, path, params, body)}; there is no read-after.

        Spec-conformance tested only (not against a live Carrier Fabric). Guarded, in order: the Carrier write opt-out (family:carrier=deny refuses first), read-before, no-op when not currently suspended, write, read-after.

        Example call (resume_carrier_subscriber):
            {"subscriber_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            subscriber_id: Carrier Fabric subscriber UUID. Get it from list_carrier_subscribers (id).
            confirm: Ignored. The call runs when made; there is no confirmation step.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to use
                whichever configured key owns the object: every key is tried and the first that answers
                is used.
        """
        client, _ = deps_fn()
        return await carrier_fabric.resume_carrier_subscriber(
            client, subscriber_id, confirm=confirm, key_label=key_label
        )

    return {
        "list_carrier_subscribers": list_carrier_subscribers,
        "get_carrier_subscriber": get_carrier_subscriber,
        "list_carrier_service_plans": list_carrier_service_plans,
        "get_carrier_service_plan": get_carrier_service_plan,
        "create_carrier_subscriber": create_carrier_subscriber,
        "update_carrier_subscriber": update_carrier_subscriber,
        "attach_carrier_subscriber_host": attach_carrier_subscriber_host,
        "detach_carrier_subscriber_host": detach_carrier_subscriber_host,
        "assign_carrier_subscriber_plan": assign_carrier_subscriber_plan,
        "suspend_carrier_subscriber": suspend_carrier_subscriber,
        "resume_carrier_subscriber": resume_carrier_subscriber,
    }
