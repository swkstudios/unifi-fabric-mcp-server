"""The connector family registrar: its tool wrappers, in registration order (the family-owned
layout).

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

from ... import switches
from ..._read_only_audit import state_changing_get
from ...tool_annotations import WRITE
from . import connector


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the connector tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=WRITE)
    @state_changing_get
    async def fabric_connector_get(
        host: str,
        path: str,
        site: str | None = None,
        params: dict[str, Any] | None = None,
        scope: str | None = None,
    ) -> dict[str, Any]:
        """Relay a GET through the Fabric connector to any console /proxy/{path} route without a typed tool. Reaches private APIs too.

        Official-only setups also exclude source:relay.

        State-changing GET routes (Protect enable-control/disable-control) need write authorization, obey connector/area opt-outs, read-only mode and dry-run, and are sent once; in discovery mode use call_write_tool. Consequence: they change camera controllability until set back. Under dry-run policy (UNIFI_WRITE_POLICY=dry-run) an action GET sends nothing: status "dry_run", body previews method, path, params, body.

        Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body}. status/body are the upstream's verbatim (4xx/5xx returned, not raised): decoded JSON, text in its declared charset, or null when empty (masked only with UNIFI_REDACT_SECRETS). Binary is base64 bodyBase64 plus sizeBytes with body null; an unfollowed 3xx adds headers. HTTP 401/403 adds _hint (key/permission advice). A 2xx error body (_classicRcError, _upstreamError) is reported like a 4xx.

        Limits (Site Manager spec): 25 s/request, 100 requests/min/console, 10 MB response body, firmware 5.0.3+; a matching 408/429/502 adds a hint.

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive, e.g.
                "my-console") or the long data[].id (MAC:numericId composite).
            path: the relay-relative application path AFTER ``/proxy/`` — e.g.
                ``network/integration/v1/sites`` or ``network/api/s/{site}/stat/device``. Use the
                ``{site}`` (slug) or ``{site_id}`` (UUID) placeholder for the site segment; the server
                resolves and substitutes it, and resolvedPath reports the path as sent (the console id
                and API key are never part of path or resolvedPath). Mapped application routes carry
                their routeClass; unmapped routes relay as
                routeClass "unclassified". Ordinary GET reads relay while an area write opt-out
                is active. Mutations on unclassified routes are refused only while an area write
                opt-out is active, with the refusal naming its variable. ``..``, ``%``-encoding,
                and control characters are rejected.
            site: site name or UUID — REQUIRED only when path contains a site placeholder.
            params: optional query-string parameters.
                Free-form JSON object; the caller-chosen route determines its shape.
            scope: optional 'device' / 'site' / 'global' — cross-checked against the path so a device
                route cannot be confused with a site-global setting route.
        """
        client, registry = deps_fn()
        return await connector.connector_get(
            client, registry, host, path, site=site, params=params, scope=scope
        )

    @mcp.tool(annotations=WRITE)
    async def fabric_connector_post(
        host: str,
        path: str,
        site: str | None = None,
        body: connector.RelayBody = None,
        confirm: bool = False,
        scope: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Relay a POST (create/command) through the Fabric connector. Writes to the controller; reaches private APIs too.

        Consequence: whatever the target route creates or does happens on the live controller immediately.

        Targets a collection or command route (e.g. network/api/s/{site}/cmd/...). Params as fabric_connector_get; body is sent verbatim, confirm is ignored.

        Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body, writeEnabled}: status/body are the upstream's verbatim (4xx/5xx returned, not raised); binary is bodyBase64 plus sizeBytes with body null. No GET twin, so no read-before/after. Under dry-run policy (UNIFI_WRITE_POLICY=dry-run) nothing is sent: status "dry_run", body the dry-run preview (method, path, params, body). HTTP 401/403 adds _hint (key/permission advice). A 2xx error body (_classicRcError, _upstreamError) is reported like a 4xx.

        Refused under family:connector=deny, UNIFI_WRITE_POLICY=deny, family:protect=deny (protect/ paths) or an unclassified route meeting an active area opt-out; never auto-retried on 429. Details: docs/TOOL-USAGE.md#fabric_connector_post. Limits (Site Manager spec): 25 s/request, 100 requests/min/console, 10 MB response body, firmware 5.0.3+; a matching 408/429/502 adds a hint.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
                routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
                An ordinary GET relays even while an area write opt-out is active. A GET of a
                state-changing route (protect/api/cameras/{id}/enable-control or
                protect/api/cameras/{id}/disable-control) is a write: it follows the area write
                opt-outs, family:connector=deny, read-only mode and dry-run, and is sent
                once. Mutations on
                unclassified routes are refused only while an area write opt-out is active, with
                the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
                placeholder for the site segment; '..', %-encoding and control characters are
                rejected.
            site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
                (UUID); the server substitutes it.
            body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
                Network 11.0.97 for network/integration/v1). Use the typed tool when one exists.
                Free-form JSON value: object, array (e.g. []), string, number, boolean or null.
                The caller-chosen route determines its shape.
            confirm: Ignored; accepted for backward compatibility. The call executes immediately when
                made unless the operator opted in to dry-run policy (then nothing is sent upstream and
                a preview of the request is returned).
            scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
                global-setting routes; 'site'/'global' reject /rest|/stat/device.
            params: Optional query-string parameters sent with the write (and with the
                read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
                sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
                Free-form JSON object; the caller-chosen route determines its shape.
        """
        client, registry = deps_fn()
        return await connector.connector_write(
            client,
            registry,
            host,
            "POST",
            path,
            site=site,
            body=body,
            params=params,
            confirm=confirm,
            scope=scope,
            write_enabled=switches.connector_writes_enabled(),
        )

    @mcp.tool(annotations=WRITE)
    async def fabric_connector_put(
        host: str,
        path: str,
        site: str | None = None,
        body: connector.RelayBody = None,
        confirm: bool = False,
        scope: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Relay a PUT (full replace) through the Fabric connector. Writes upstream; reaches private APIs too.

        Consequence: replaces the resource now; omitted fields may reset.

        For network/api/s/{site}/rest/device/{id}, pass scope='device' to refuse site-global routes; it has no GET, so reads use stat/device and noOp compares only sent fields (noOpBasis). A device write can restart or reprovision it. Undocumented routes are EXPERIMENTAL. Params as fabric_connector_get; body is verbatim; confirm is ignored.

        Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body, writeEnabled, readBefore/readAfter (twin GET results), noOp[, changed, noOpBasis]}. readAfterError explains a failed or non-2xx read-after. Binary is {bodyBase64, sizeBytes, body: null}. noOp is true only if the write and both reads are 2xx and every sent leaf matches; null if unknown (noOpReason unless readAfterError explains). changed (= not noOp) is present only when noOp is non-null. dry-run policy (UNIFI_WRITE_POLICY=dry-run) sends nothing: status "dry_run", body the dry-run preview (method, path, params, body).

        Refused under family:connector=deny, UNIFI_WRITE_POLICY=deny, family:protect=deny (protect/ paths) or an unclassified route meeting an active area opt-out; never auto-retried on 429. HTTP 401/403 adds _hint (key/permission advice); readBefore/readAfter carry the same guidance for failed GET twins. A 2xx error body (_classicRcError, _upstreamError) is reported like a 4xx: status/body verbatim, noOp null, no changed. Details: docs/TOOL-USAGE.md#fabric_connector_put; limits: see fabric_connector_get.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
                routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
                An ordinary GET relays even while an area write opt-out is active. A GET of a
                state-changing route (protect/api/cameras/{id}/enable-control or
                protect/api/cameras/{id}/disable-control) is a write: it follows the area write
                opt-outs, family:connector=deny, read-only mode and dry-run, and is sent
                once. Mutations on
                unclassified routes are refused only while an area write opt-out is active, with
                the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
                placeholder for the site segment; '..', %-encoding and control characters are
                rejected.
            site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
                (UUID); the server substitutes it.
            body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
                Network 11.0.97 for network/integration/v1). Use the typed tool when one exists.
                Free-form JSON value: object, array (e.g. []), string, number, boolean or null.
                The caller-chosen route determines its shape.
            confirm: Ignored; accepted for backward compatibility. The call executes immediately when
                made unless the operator opted in to dry-run policy (then nothing is sent upstream and
                a preview of the request is returned).
            scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
                global-setting routes; 'site'/'global' reject /rest|/stat/device.
            params: Optional query-string parameters sent with the write (and with the
                read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
                sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
                Free-form JSON object; the caller-chosen route determines its shape.
        """
        client, registry = deps_fn()
        return await connector.connector_write(
            client,
            registry,
            host,
            "PUT",
            path,
            site=site,
            body=body,
            params=params,
            confirm=confirm,
            scope=scope,
            write_enabled=switches.connector_writes_enabled(),
        )

    @mcp.tool(annotations=WRITE)
    async def fabric_connector_patch(
        host: str,
        path: str,
        site: str | None = None,
        body: connector.RelayBody = None,
        confirm: bool = False,
        scope: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Relay a PATCH (partial update) through the Fabric connector. Writes upstream; reaches private APIs too.

        Consequence: applies to the live controller immediately.

        Classic rest/device/{id} reads use stat/device as for fabric_connector_put; a device write can restart or reprovision it. For legacy InnerSpace innerspace/api/shapes/{id} (EXPERIMENTAL), first probe a nonexistent shape ID with an empty body: 4xx = reachable; 200/204 = stop. Params as fabric_connector_get; body is verbatim; confirm is ignored.

        Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body, writeEnabled, readBefore/readAfter (twin GET results), noOp[, changed]}. readAfterError explains a failed or non-2xx read-after. Binary is {bodyBase64, sizeBytes, body: null}. noOp is true only if the write and both reads are 2xx and every sent leaf matches; null if unknown (noOpReason unless readAfterError explains). changed (= not noOp) is present only when noOp is non-null. dry-run policy (UNIFI_WRITE_POLICY=dry-run) sends nothing: status "dry_run", body the dry-run preview (method, path, params, body).

        Refused under family:connector=deny, UNIFI_WRITE_POLICY=deny, family:protect=deny (protect/ paths) or an unclassified route meeting an active area opt-out; never auto-retried on 429. HTTP 401/403 adds _hint (key/permission advice); readBefore/readAfter carry the same guidance for failed GET twins. A 2xx error body (_classicRcError, _upstreamError) is reported like a 4xx: status/body verbatim, noOp null, no changed. Details: docs/TOOL-USAGE.md#fabric_connector_patch; limits: see fabric_connector_get.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
                routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
                An ordinary GET relays even while an area write opt-out is active. A GET of a
                state-changing route (protect/api/cameras/{id}/enable-control or
                protect/api/cameras/{id}/disable-control) is a write: it follows the area write
                opt-outs, family:connector=deny, read-only mode and dry-run, and is sent
                once. Mutations on
                unclassified routes are refused only while an area write opt-out is active, with
                the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
                placeholder for the site segment; '..', %-encoding and control characters are
                rejected.
            site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
                (UUID); the server substitutes it.
            body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
                Network 11.0.97 for network/integration/v1). Use the typed tool when one exists.
                Free-form JSON value: object, array (e.g. []), string, number, boolean or null.
                The caller-chosen route determines its shape.
            confirm: Ignored; accepted for backward compatibility. The call executes immediately when
                made unless the operator opted in to dry-run policy (then nothing is sent upstream and
                a preview of the request is returned).
            scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
                global-setting routes; 'site'/'global' reject /rest|/stat/device.
            params: Optional query-string parameters sent with the write (and with the
                read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
                sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
                Free-form JSON object; the caller-chosen route determines its shape.
        """
        client, registry = deps_fn()
        return await connector.connector_write(
            client,
            registry,
            host,
            "PATCH",
            path,
            site=site,
            body=body,
            params=params,
            confirm=confirm,
            scope=scope,
            write_enabled=switches.connector_writes_enabled(),
        )

    @mcp.tool(annotations=WRITE)
    async def fabric_connector_delete(
        host: str,
        path: str,
        site: str | None = None,
        body: dict[str, Any] | None = None,
        confirm: bool = False,
        scope: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Relay a DELETE through the Fabric connector. Irreversible write to the controller; reaches private APIs too.

        Consequence: the target resource is removed from the controller; there is no undo.

        Confirm the exact resource path first; body is optional and verbatim, confirm is ignored. Params as fabric_connector_get.

        Returns {method, routeClass, scope, path, resolvedPath, status, contentType, body, writeEnabled, readBefore/readAfter (twin GET results), noOp[, changed]}. readAfterError explains a failed or non-2xx read-after. Deletion is confirmed only by a 404 read-after following a 2xx read-before: noOp false, changed true; changed (= not noOp) is present only when noOp is non-null; binary is {bodyBase64, sizeBytes, body: null}. If the read-after still returns the resource, noOp is null with noOpReason "deletion not confirmed". HTTP 401/403 adds _hint (key/permission advice); readBefore/readAfter carry the same guidance for failed GET twins. A 2xx error body (_classicRcError, _upstreamError) is reported like a 4xx: status/body verbatim, noOp null, no changed. dry-run policy (UNIFI_WRITE_POLICY=dry-run) sends nothing: status "dry_run", body the {method, path, params, body} preview.

        Refused under family:connector=deny, UNIFI_WRITE_POLICY=deny, family:protect=deny (protect/ paths) or an unclassified route meeting an active area opt-out; never auto-retried on 429. Details: docs/TOOL-USAGE.md#fabric_connector_delete. Limits (Site Manager spec): 25 s/request, 100 requests/min/console, 10 MB response body, firmware 5.0.3+; a matching 408/429/502 adds a hint.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            path: Path AFTER /proxy/, e.g. 'network/integration/v1/sites/{site_id}/networks'. Mapped
                routes carry their routeClass; unmapped routes relay as routeClass "unclassified".
                An ordinary GET relays even while an area write opt-out is active. A GET of a
                state-changing route (protect/api/cameras/{id}/enable-control or
                protect/api/cameras/{id}/disable-control) is a write: it follows the area write
                opt-outs, family:connector=deny, read-only mode and dry-run, and is sent
                once. Mutations on
                unclassified routes are refused only while an area write opt-out is active, with
                the refusal naming its variable. Use the {site} (slug) or {site_id} (UUID)
                placeholder for the site segment; '..', %-encoding and control characters are
                rejected.
            site: Site name or UUID. Required only when path contains '{site}' (slug) or '{site_id}'
                (UUID); the server substitutes it.
            body: JSON body sent verbatim to the target route. Shape = that route's spec schema (e.g.
                Network 11.0.97 for network/integration/v1). Optional for DELETE.
                Omit to send no body; an explicit null is sent as the JSON body null.
                Free-form JSON object; the caller-chosen route determines its shape.
            confirm: Ignored; accepted for backward compatibility. The call executes immediately when
                made unless the operator opted in to dry-run policy (then nothing is sent upstream and
                a preview of the request is returned).
            scope: Optional 'device'|'site'|'global'. Cross-checked against path: 'device' rejects
                global-setting routes; 'site'/'global' reject /rest|/stat/device.
            params: Optional query-string parameters sent with the write (and with the
                read-before/read-after GET for PUT/PATCH/DELETE), e.g. the
                sourceFirewallZoneId/destinationFirewallZoneId of an Integration ordering route.
                Free-form JSON object; the caller-chosen route determines its shape.
        """
        client, registry = deps_fn()
        return await connector.connector_write(
            client,
            registry,
            host,
            "DELETE",
            path,
            site=site,
            body=body,
            params=params,
            confirm=confirm,
            scope=scope,
            write_enabled=switches.connector_writes_enabled(),
        )

    return {
        "fabric_connector_get": fabric_connector_get,
        "fabric_connector_post": fabric_connector_post,
        "fabric_connector_put": fabric_connector_put,
        "fabric_connector_patch": fabric_connector_patch,
        "fabric_connector_delete": fabric_connector_delete,
    }
