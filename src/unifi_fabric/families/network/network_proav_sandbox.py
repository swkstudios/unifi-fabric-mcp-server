"""Network ProAV, Shadow Mode, test-config sandbox, digital-twin and observability tools.

These routes have no published Integration API. They are the Network controller's own
web-UI routes, cited from the Network 11.0.81 private-API inventory
(``tests/fixtures/private_api/inventory_network_11.0.81.json``): the v2 routes under
``/proxy/network/v2/api/site/{site}`` and one Classic route
(``/proxy/network/api/s/{site}/stat/portforward``). Both take the site's short name
(``default``), resolved from the caller's site name or UUID with the key that owns the
console (multi-key: the first key that owns the host wins).

* The inventory records no request-body keys for any of these routes (``body_keys``
  is empty; the writes are ``body_dynamic``), so every body argument is FREE-FORM: it is
  sent verbatim, and no key is required or invented here. The upstream judges it.
* None of these collections takes a paging parameter in the inventory, so every read
  sends one request and returns the upstream body verbatim (no drain, no cap).
* ``update_digital_twin_layout`` reads the layout, merges only the requested leaves,
  PUTs the merged layout and reads it back, comparing every requested leaf type-strictly
  (``_verified``; ``_readAfterError`` when the read-back failed or was unusable).
* ``delete_test_config`` / ``apply_test_config`` resolve the id in the test-config list
  first and fail listing every valid id. ProAV groups have no list route in the
  inventory (only the matrix reads), so a group id is passed through for the upstream
  to judge, and a group update is the complete group body (nothing to read or merge).
* The multicast ``clients`` / ``history`` views are POSTs that are not on the read-POST
  allowlist, so they are writes: ``UNIFI_WRITE_POLICY=deny`` refuses them and ``dry-run policy``
  previews them.
* The Classic ``stat/portforward`` read is a success only on HTTP 2xx with
  ``meta.rc == "ok"`` (affirmative; the full upstream body is in the error otherwise).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from fastmcp import FastMCP

from ...client import (
    ClassicApiError,
    UniFiClient,
    UniFiConnectionError,
    decode_body,
    describe_shape,
    is_dry_run_preview,
    upstream_error_text,
    validate_id,
)
from ...config import APIKeyConfig
from ...macs import colon_mac, is_mac
from ...redaction import drop_and_note_masked_fields
from ...registry import Registry
from ...selector_args import check_selector
from ...shared_shapes._classic_cmd import classic_rc_failure
from ...shared_shapes._classic_objects import resolve_site_slug, v2_site
from ...shared_shapes._keys import with_context
from ...shared_shapes._payload import upstream_hint
from ...shared_shapes._results import deletion_result, requested_leaves_verdict, safe_read_after
from ...tool_annotations import READ_ONLY, WRITE
from ...write_body import require_unmasked_fields, require_update_fields
from .network_routing_topology import _listed_record

PROAV_KINDS = ("audio", "video")
SHADOW_VIEWS = {"info": "/shadowmode/info", "managed_group": "/shadowmode/managed/group"}
SHADOW_ACTIONS = {
    "begin": "/shadowmode/managed/begin-adoption",
    "complete": "/shadowmode/managed/complete-adoption",
    "rollback": "/shadowmode/managed/rollback",
}
TV_WALL_ACTIONS = {
    "set": "/proav/video/set-tv-wall-calibration",
    "unset": "/proav/video/unset-tv-wall-calibration",
}
TEST_CONFIG_ACTIONS = ("apply", "commit")
MULTICAST_VIEWS = ("client", "clients", "history")
_TEST_CONFIGS = "/test-configs"
_LAYOUT = "/digital-twin/layout"

#: Epoch values below this are almost certainly seconds passed by mistake. Not a spec
#: limit: a unit hint only; the value is always sent as given.
_SECONDS_HINT_BELOW = 100_000_000_000


# --------------------------------------------------------------------------- validation


def _choice(value: Any, name: str, choices: tuple[str, ...]) -> str:
    """``value`` when it is one of the inventoried route segments, else raise."""
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"{name} must be one of {', '.join(choices)}; got {value!r}")
    return value


def _mac(value: Any, name: str) -> str:
    """A MAC address in the controller's colon form, else raise."""
    if not is_mac(value):
        raise ValueError(f"{name} must be a MAC address such as '02:00:5e:00:00:a1'; got {value!r}")
    return colon_mac(value)


def _mac_or_id(value: Any, name: str) -> str:
    """A MAC (colon form) or a path-safe id, validated as one path segment."""
    if is_mac(value):
        return colon_mac(value)
    validate_id(value, name)
    return str(value)


def _object(value: Any, name: str) -> dict[str, Any] | None:
    """``value`` when it is a JSON object or omitted (``None``), else raise."""
    if value is not None and not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object, got {describe_shape(value)}")
    return value


def _query(value: Any) -> dict[str, Any] | None:
    """Query parameters: an object of string, number or boolean values (or omitted)."""
    if _object(value, "query_params") is None:
        return None
    for key, item in value.items():
        if not isinstance(item, str | int | float):  # bool is an int: accepted
            raise ValueError(
                f"query_params values must be strings, numbers or booleans; {key!r} is "
                f"{describe_shape(item)}"
            )
    return dict(value)


def _epoch_ms(value: Any, name: str) -> int:
    """``value`` when it is a JSON integer (booleans are not), else raise."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer epoch-milliseconds timestamp; got {value!r}")
    return value


def _multicast_route(view: Any, client_mac: Any) -> str:
    """The multicast-insights route suffix for ``view`` (``client`` needs one MAC)."""
    _choice(view, "view", MULTICAST_VIEWS)
    if view == "client":
        if client_mac is None:
            raise ValueError("client_mac is required for view 'client' (the client's MAC)")
        return f"/insights/multicast/client/{_mac(client_mac, 'client_mac')}"
    if client_mac is not None:
        raise ValueError(
            f"client_mac applies only to view 'client'; view {view!r} reads every client"
        )
    return f"/insights/multicast/{view}"


def _epoch_warning(name: str, value: int) -> dict[str, Any]:
    """The additive epoch-unit ``_warnings`` entry for an epoch-milliseconds argument."""
    message = f"{name} is a Unix epoch in MILLISECONDS (e.g. 1760000000000); sent as given."
    if value < _SECONDS_HINT_BELOW:
        message += " The value looks like epoch seconds; multiply by 1000 for milliseconds."
    return {"code": "EPOCH_MILLISECONDS", "argument": name, "value": value, "message": message}


def _with_warnings(result: Any, warnings: list[dict[str, Any]]) -> Any:
    if not isinstance(result, dict):
        return result
    return with_context(result, {"_warnings": warnings})


# --------------------------------------------------------------------------- helpers


async def _site(registry: Registry, host: str, site: str) -> tuple[APIKeyConfig | None, str, str]:
    check_selector("host", host)
    check_selector("site", site)
    return await resolve_site_slug(registry, host, site)


def _merge(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge only the requested leaves into the current upstream object."""
    merged = dict(current)
    for key, value in changes.items():
        prior = merged.get(key)
        merged[key] = (
            _merge(prior, value) if isinstance(prior, dict) and isinstance(value, dict) else value
        )
    return merged


async def _test_config_id(
    client: UniFiClient, path: str, key: APIKeyConfig | None, identifier: str
) -> str:
    """Resolve the upstream test-config id from its list record."""
    _, resolved = await _listed_record(client, path, key, identifier, "Test config")
    return resolved


def _body(value: Any, name: str, tool: str) -> dict[str, Any] | None:
    """An optional free-form body: an object or omitted; a body of nothing but redaction
    masks is refused here, before any resolution request."""
    body = _object(value, name)
    if body is not None:
        require_unmasked_fields(body, f"{tool} {name!r}")
    return body


def _deleted(message: str, response: Any) -> Any:
    """The client's dry-run preview unchanged, else the shared delete result."""
    return deletion_result(message, response)


# --------------------------------------------------------------------------- ProAV


async def get_proav_matrix(
    client: UniFiClient, registry: Registry, host: str, site: str, kind: str
) -> Any:
    """GET the site's ProAV audio or video matrix; the body is returned verbatim."""
    _choice(kind, "kind", PROAV_KINDS)
    key, host_id, slug = await _site(registry, host, site)
    return await client.get(v2_site(host_id, slug, f"/proav/{kind}/matrix"), key=key)


async def get_proav_snapshot(
    client: UniFiClient, registry: Registry, host: str, site: str, snapshot_id: str
) -> Any:
    """GET one ProAV snapshot; the body is returned verbatim."""
    validate_id(snapshot_id, "snapshot_id")
    key, host_id, slug = await _site(registry, host, site)
    return await client.get(v2_site(host_id, slug, f"/proav/snapshot/{snapshot_id}"), key=key)


async def create_proav_group(
    client: UniFiClient, registry: Registry, host: str, site: str, kind: str, group: dict[str, Any]
) -> Any:
    """POST ``group`` verbatim to the site's ProAV audio or video groups."""
    _choice(kind, "kind", PROAV_KINDS)
    _object(group, "group")
    key, host_id, slug = await _site(registry, host, site)
    return await client.post(v2_site(host_id, slug, f"/proav/{kind}/group"), key=key, json=group)


async def update_proav_group(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    kind: str,
    group_id: str,
    group: dict[str, Any],
) -> Any:
    """PUT the complete ``group`` body to one ProAV group (no read route exists to merge)."""
    _choice(kind, "kind", PROAV_KINDS)
    validate_id(group_id, "group_id")
    body = require_update_fields(drop_and_note_masked_fields(group), "update_proav_group group")
    key, host_id, slug = await _site(registry, host, site)
    return await client.put(
        v2_site(host_id, slug, f"/proav/{kind}/group/{group_id}"), key=key, json=body
    )


async def delete_proav_group(
    client: UniFiClient, registry: Registry, host: str, site: str, kind: str, group_id: str
) -> Any:
    """DELETE one ProAV group; the upstream body is kept in the result."""
    _choice(kind, "kind", PROAV_KINDS)
    validate_id(group_id, "group_id")
    key, host_id, slug = await _site(registry, host, site)
    response = await client.delete(
        v2_site(host_id, slug, f"/proav/{kind}/group/{group_id}"), key=key
    )
    return _deleted(f"ProAV {kind} group {group_id} deleted", response)


async def set_tv_wall_calibration(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    action: str,
    calibration: dict[str, Any] | None = None,
) -> Any:
    """POST the set or unset TV-wall calibration route with ``calibration`` verbatim."""
    _choice(action, "action", tuple(TV_WALL_ACTIONS))
    _body(calibration, "calibration", "set_tv_wall_calibration")
    key, host_id, slug = await _site(registry, host, site)
    return await client.post(
        v2_site(host_id, slug, TV_WALL_ACTIONS[action]), key=key, json=calibration
    )


# --------------------------------------------------------------------------- Shadow Mode


async def get_shadow_mode_status(
    client: UniFiClient, registry: Registry, host: str, site: str, view: str = "info"
) -> Any:
    """GET Shadow Mode info or the managed adoption group; returned verbatim."""
    _choice(view, "view", tuple(SHADOW_VIEWS))
    key, host_id, slug = await _site(registry, host, site)
    return await client.get(v2_site(host_id, slug, SHADOW_VIEWS[view]), key=key)


async def control_shadow_mode_adoption(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    action: str,
    body: dict[str, Any] | None = None,
) -> Any:
    """POST a Shadow Mode managed-adoption action with ``body`` verbatim."""
    _choice(action, "action", tuple(SHADOW_ACTIONS))
    _body(body, "body", "control_shadow_mode_adoption")
    key, host_id, slug = await _site(registry, host, site)
    return await client.post(v2_site(host_id, slug, SHADOW_ACTIONS[action]), key=key, json=body)


# --------------------------------------------------------------------------- test configs


async def list_test_configs(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """GET the site's test configs; the upstream body is returned verbatim."""
    key, host_id, slug = await _site(registry, host, site)
    return await client.get(v2_site(host_id, slug, _TEST_CONFIGS), key=key)


async def create_test_config(
    client: UniFiClient, registry: Registry, host: str, site: str, test_config: dict[str, Any]
) -> Any:
    """POST ``test_config`` verbatim to the site's test configs."""
    _object(test_config, "test_config")
    key, host_id, slug = await _site(registry, host, site)
    return await client.post(v2_site(host_id, slug, _TEST_CONFIGS), key=key, json=test_config)


async def delete_test_config(
    client: UniFiClient, registry: Registry, host: str, site: str, test_config_id: str
) -> Any:
    """Resolve ``test_config_id`` in the list, then DELETE it."""
    validate_id(test_config_id, "test_config_id")
    key, host_id, slug = await _site(registry, host, site)
    collection = v2_site(host_id, slug, _TEST_CONFIGS)
    resolved = await _test_config_id(client, collection, key, test_config_id)
    response = await client.delete(f"{collection}/{resolved}", key=key)
    return _deleted(f"Test config {resolved} deleted", response)


async def apply_test_config(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    test_config_id: str,
    action: str = "apply",
    body: dict[str, Any] | None = None,
) -> Any:
    """Resolve ``test_config_id`` in the list, then POST its apply or commit action."""
    validate_id(test_config_id, "test_config_id")
    _choice(action, "action", TEST_CONFIG_ACTIONS)
    _body(body, "body", "apply_test_config")
    key, host_id, slug = await _site(registry, host, site)
    collection = v2_site(host_id, slug, _TEST_CONFIGS)
    resolved = await _test_config_id(client, collection, key, test_config_id)
    return await client.post(f"{collection}/{resolved}/{action}", key=key, json=body)


# --------------------------------------------------------------------------- Classic stat


async def get_port_forward_statistics(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET Classic ``stat/portforward``; success requires ``meta.rc == "ok"``."""
    key, host_id, slug = await _site(registry, host, site)
    path = f"/v1/connector/consoles/{host_id}/proxy/network/api/s/{slug}/stat/portforward"
    resp = await client.request("GET", path, key=key)
    body = decode_body(resp)
    reason = classic_rc_failure(resp.status_code, body)
    if reason is not None:
        text = upstream_error_text(resp.text, client)
        raise ClassicApiError(f"Classic API error from GET {path}: {reason}: {text}")
    return body


# --------------------------------------------------------------------------- digital twin


async def get_digital_twin_layout(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET the site's digital-twin layout; the upstream body is returned verbatim."""
    key, host_id, slug = await _site(registry, host, site)
    return await client.get(v2_site(host_id, slug, _LAYOUT), key=key)


async def update_digital_twin_layout(
    client: UniFiClient, registry: Registry, host: str, site: str, layout: dict[str, Any]
) -> Any:
    """Merge ``layout`` into the current layout, PUT it and verify the requested leaves.

    A non-object write body is kept whole under ``response`` so the verdict keys are never dropped.
    """
    changes = require_update_fields(
        drop_and_note_masked_fields(_object(layout, "layout")), "update_digital_twin_layout layout"
    )
    key, host_id, slug = await _site(registry, host, site)
    path = v2_site(host_id, slug, _LAYOUT)
    current = await client.get(path, key=key)
    # No layout object yet (null, empty or a non-object body): nothing to preserve, so the
    # requested layout is the whole body.
    body = _merge(current, changes) if isinstance(current, dict) else changes
    response = await client.put(path, key=key, json=body)
    if is_dry_run_preview(response):
        return response
    after, error = await safe_read_after(lambda: client.get(path, key=key))
    verified, error = requested_leaves_verdict(changes, after, error)
    if not isinstance(response, dict):
        response = {"response": response}
    additions: dict[str, Any] = {"_verified": verified}
    if error is not None:
        additions["_readAfterError"] = error
    return with_context(response, additions)


async def delete_digital_twin_layout(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """DELETE the site's digital-twin layout; the upstream body is kept in the result."""
    key, host_id, slug = await _site(registry, host, site)
    response = await client.delete(v2_site(host_id, slug, _LAYOUT), key=key)
    return _deleted("Digital-twin layout deleted", response)


# --------------------------------------------------------------------------- observability

#: Appended to an HTTP 404 from the 5G topology route. The Network 11.0.89 web app builds
#: the same route (``observability/5g/:mac:/topology/at/:timestamp:``) and reads it only
#: when the site's internet connection is a 5G device. Live evidence for the two wordings:
#: on 11.0.89 (2026-10-28) an adopted U5G Max in failover mode with no SIM answered the
#: bare HTML 404 the console gives an unserved path, and on 11.1.47 (2026-11-10) the
#: console's own MAC, which is not a 5G device, answered JSON ``api.err.DeviceNotFound``.
_5G_TOPOLOGY_NOT_SERVED = (
    "a 404 here means the console served no 5G topology for this MAC and time. Network "
    "11.1.47 answers JSON api.err.DeviceNotFound when the MAC is not a 5G device; Network "
    "11.0.89 answered its HTML 404 page even for an adopted U5G Max in failover mode with "
    "no SIM. Pass the MAC of a 5G device (list_devices, type umbb) with an epoch-milliseconds "
    "time; if list_devices shows no umbb device, the site has no 5G and the console serves "
    "no topology."
)


async def get_5g_topology(
    client: UniFiClient, registry: Registry, host: str, site: str, device: str, at: int
) -> Any:
    """GET one 5G device's topology snapshot at ``at`` (epoch milliseconds)."""
    segment = _mac_or_id(device, "device")
    at_ms = _epoch_ms(at, "at")
    key, host_id, slug = await _site(registry, host, site)
    try:
        result = await client.get(
            v2_site(host_id, slug, f"/observability/5g/{segment}/topology/at/{at_ms}"), key=key
        )
    except UniFiConnectionError as exc:
        if exc.status != 404:
            raise
        upstream_hint(exc, _5G_TOPOLOGY_NOT_SERVED)
        raise
    return _with_warnings(result, [_epoch_warning("at", at_ms)])


#: Appended to an HTTP 404 from a multicast-insights route. The routes exist in the pinned
#: Network 11.0.81 and 11.0.99 route tables; live on Network 11.1.47 (an early-access build)
#: the bare Tomcat HTML 404 an unserved path gets came back for the clients view.
_MULTICAST_NOT_SERVED = (
    "an HTML 404 here means this console's Network application does not serve multicast "
    "insights on this route: Network 11.0.81-11.0.99 serve it and the 11.1.47 web app no "
    "longer calls it. Check the version with get_network_application_info; there is no "
    "other route for this data."
)


async def get_multicast_insights(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    view: str,
    client_mac: str | None = None,
    query_params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> Any:
    """GET one client's multicast insight, or POST the clients / history query."""
    suffix = _multicast_route(view, client_mac)
    params = _query(query_params)
    if view == "client" and body is not None:
        raise ValueError("body is not supported for client view")
    if view != "client":
        body = _body(body, "body", "get_multicast_insights")
    key, host_id, slug = await _site(registry, host, site)
    path = v2_site(host_id, slug, suffix)
    try:
        if view == "client":
            return await client.get(path, key=key, params=params)
        return await client.post(path, key=key, params=params, json=body)
    except UniFiConnectionError as exc:
        if exc.status != 404:
            raise
        upstream_hint(exc, _MULTICAST_NOT_SERVED)
        raise


# --------------------------------------------------------------------------- registration


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the 18 ProAV, Shadow Mode, sandbox, digital-twin and insight tools."""

    @mcp.tool(name="get_proav_matrix", annotations=READ_ONLY)
    async def get_proav_matrix_tool(host: str, site: str, kind: Literal["audio", "video"]) -> Any:
        """Read a site's ProAV audio or video routing matrix (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/proav/{kind}/matrix; the upstream body is
        returned verbatim. The route takes no paging parameter.

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, kind.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            kind: Which matrix to read, "audio" or "video", e.g. "video".
        """
        client, registry = deps_fn()
        return await get_proav_matrix(client, registry, host, site, kind)

    @mcp.tool(name="get_proav_snapshot", annotations=READ_ONLY)
    async def get_proav_snapshot_tool(host: str, site: str, snapshot_id: str) -> Any:
        """Read one ProAV snapshot (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/proav/snapshot/{snapshot_id}; the upstream
        body is returned verbatim. The inventory records only a path placeholder for the
        snapshot identifier, so it is passed through as one path segment.

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, snapshot_id.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            snapshot_id: Snapshot identifier (letters, digits, - and _), e.g.
                "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await get_proav_snapshot(client, registry, host, site, snapshot_id)

    @mcp.tool(name="create_proav_group", annotations=WRITE)
    async def create_proav_group_tool(
        host: str, site: str, kind: Literal["audio", "video"], group: dict[str, Any]
    ) -> Any:
        """Create a ProAV audio or video group (Network v2 route).

        POST /proxy/network/v2/api/site/{site}/proav/{kind}/group with group sent verbatim;
        the upstream body is returned verbatim. Never auto-retried. The group body is
        free-form: the route inventory records no body keys, so none is required here.
        Consequence: changes which ProAV endpoints share a stream.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, message and preview (method, path, params, body).

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, kind, group.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            kind: Group type, "audio" or "video", e.g. "video".
            group: Free-form group object as the Network UI sends it, e.g.
                {"name": "lobby-wall"}.
        """
        client, registry = deps_fn()
        return await create_proav_group(client, registry, host, site, kind, group)

    @mcp.tool(name="update_proav_group", annotations=WRITE)
    async def update_proav_group_tool(
        host: str,
        site: str,
        kind: Literal["audio", "video"],
        group_id: str,
        group: dict[str, Any],
    ) -> Any:
        """Replace a ProAV audio or video group (Network v2 route).

        PUT /proxy/network/v2/api/site/{site}/proav/{kind}/group/{group_id} with group sent
        verbatim as the complete group; the upstream body is returned verbatim. No route
        reads a single group, so nothing is merged or read back. An empty group is refused
        before any request. Consequence: changes live ProAV stream routing.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, message and preview (method, path, params, body).

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, kind, group_id, group.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            kind: Group type, "audio" or "video", e.g. "audio".
            group_id: Group id, e.g. "000000000000000000000107".
            group: Free-form complete group object, e.g. {"name": "lobby-wall"}.
        """
        client, registry = deps_fn()
        return await update_proav_group(client, registry, host, site, kind, group_id, group)

    @mcp.tool(name="delete_proav_group", annotations=WRITE)
    async def delete_proav_group_tool(
        host: str, site: str, kind: Literal["audio", "video"], group_id: str
    ) -> Any:
        """Delete a ProAV audio or video group (Network v2 route).

        DELETE /proxy/network/v2/api/site/{site}/proav/{kind}/group/{group_id}; returns
        deleted, message and the upstream body as response. Never auto-retried.
        Consequence: the group is removed permanently and its streams stop.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, message and preview with method, path, params, body).

        Returns deleted, message and response (the upstream body).

        Required arguments: host, site, kind, group_id.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            kind: Group type, "audio" or "video", e.g. "video".
            group_id: Group id, e.g. "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await delete_proav_group(client, registry, host, site, kind, group_id)

    @mcp.tool(name="set_tv_wall_calibration", annotations=WRITE)
    async def set_tv_wall_calibration_tool(
        host: str,
        site: str,
        action: Literal["set", "unset"],
        calibration: dict[str, Any] | None = None,
    ) -> Any:
        """Set or clear the ProAV video TV-wall calibration (Network v2 route).

        POST /proxy/network/v2/api/site/{site}/proav/video/set-tv-wall-calibration (action
        "set") or .../unset-tv-wall-calibration (action "unset") with calibration sent
        verbatim (free-form: the inventory records no body keys; omitted sends no body).
        The upstream body is returned verbatim. Never auto-retried. Consequence: changes
        what the physical displays of the TV wall show.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, message and preview (method, path, params, body).

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, action.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            action: "set" or "unset", e.g. "set".
            calibration: Free-form calibration object as the Network UI sends it, e.g.
                {"rows": 2, "columns": 2}.
        """
        client, registry = deps_fn()
        return await set_tv_wall_calibration(client, registry, host, site, action, calibration)

    @mcp.tool(name="get_shadow_mode_status", annotations=READ_ONLY)
    async def get_shadow_mode_status_tool(
        host: str, site: str, view: Literal["info", "managed_group"] = "info"
    ) -> Any:
        """Read Shadow Mode state (Network v2 route).

        With view "info": GET /proxy/network/v2/api/site/{site}/shadowmode/info; with
        view "managed_group": GET .../shadowmode/managed/group (the managed adoption group).
        The upstream body is returned verbatim.

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            view: "info" (default) or "managed_group", e.g. "managed_group".
        """
        client, registry = deps_fn()
        return await get_shadow_mode_status(client, registry, host, site, view)

    @mcp.tool(name="control_shadow_mode_adoption", annotations=WRITE)
    async def control_shadow_mode_adoption_tool(
        host: str,
        site: str,
        action: Literal["begin", "complete", "rollback"],
        body: dict[str, Any] | None = None,
    ) -> Any:
        """Begin, complete or roll back Shadow Mode managed adoption (Network v2 route).

        POST /proxy/network/v2/api/site/{site}/shadowmode/managed/begin-adoption,
        complete-adoption or rollback with body sent verbatim (free-form: the inventory
        records no body keys; omitted sends no body). The upstream body is returned
        verbatim. Never auto-retried. Consequence: devices change which controller manages
        them; complete and rollback can disconnect devices while they re-provision.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, message and preview (method, path, params, body).

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, action.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            action: "begin", "complete" or "rollback", e.g. "begin".
            body: Free-form request object as the Network UI sends it, e.g.
                {"devices": ["02:00:5e:00:00:a1"]}.
        """
        client, registry = deps_fn()
        return await control_shadow_mode_adoption(client, registry, host, site, action, body)

    @mcp.tool(name="list_test_configs", annotations=READ_ONLY)
    async def list_test_configs_tool(host: str, site: str) -> Any:
        """List a site's sandbox test configs (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/test-configs; the upstream body is returned
        verbatim. The route takes no paging parameter.

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await list_test_configs(client, registry, host, site)

    @mcp.tool(name="create_test_config", annotations=WRITE)
    async def create_test_config_tool(host: str, site: str, test_config: dict[str, Any]) -> Any:
        """Create a sandbox test config (Network v2 route).

        POST /proxy/network/v2/api/site/{site}/test-configs with test_config sent verbatim
        (free-form: the inventory records no body keys); the upstream body is returned
        verbatim. Never auto-retried. Consequence: stores a staged configuration; nothing
        is applied until apply_test_config.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, message and preview (method, path, params, body).

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, test_config.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            test_config: Free-form test-config object as the Network UI sends it, e.g.
                {"name": "vlan-trial"}.
        """
        client, registry = deps_fn()
        return await create_test_config(client, registry, host, site, test_config)

    @mcp.tool(name="delete_test_config", annotations=WRITE)
    async def delete_test_config_tool(host: str, site: str, test_config_id: str) -> Any:
        """Delete a sandbox test config (Network v2 route).

        Reads GET .../test-configs to resolve test_config_id (_id or id; an unknown id
        fails listing every valid id), then DELETE
        /proxy/network/v2/api/site/{site}/test-configs/{id}; returns deleted, message and
        the upstream body as response. Consequence: the staged config is removed
        permanently.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, message and preview with method, path, params, body).

        Returns deleted, message and response (the upstream body).

        Required arguments: host, site, test_config_id.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            test_config_id: Test-config id from list_test_configs, e.g.
                "000000000000000000000107".
        """
        client, registry = deps_fn()
        return await delete_test_config(client, registry, host, site, test_config_id)

    @mcp.tool(name="apply_test_config", annotations=WRITE)
    async def apply_test_config_tool(
        host: str,
        site: str,
        test_config_id: str,
        action: Literal["apply", "commit"] = "apply",
        body: dict[str, Any] | None = None,
    ) -> Any:
        """Apply or commit a sandbox test config (Network v2 route).

        Resolves test_config_id in GET .../test-configs (an unknown id fails listing every
        valid id), then POST /proxy/network/v2/api/site/{site}/test-configs/{id}/apply or
        .../commit with body sent verbatim (free-form; omitted sends no body). The upstream
        body is returned verbatim. Never auto-retried. Consequence: the staged
        configuration goes live on the site's devices and can interrupt traffic.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, message and preview (method, path, params, body).

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, test_config_id.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            test_config_id: Test-config id from list_test_configs, e.g.
                "000000000000000000000107".
            action: "apply" (default) or "commit", e.g. "commit".
            body: Free-form request object as the Network UI sends it, e.g.
                {"duration": 300}.
        """
        client, registry = deps_fn()
        return await apply_test_config(client, registry, host, site, test_config_id, action, body)

    @mcp.tool(name="get_port_forward_statistics", annotations=READ_ONLY)
    async def get_port_forward_statistics_tool(host: str, site: str) -> Any:
        """Read port-forward rule statistics (Network Classic route).

        GET /proxy/network/api/s/{site}/stat/portforward; success is HTTP 2xx with
        meta.rc "ok" (anything else raises with the full upstream body). The upstream
        {meta, data} body is returned verbatim. Rules themselves: list_port_forwards.

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await get_port_forward_statistics(client, registry, host, site)

    @mcp.tool(name="get_digital_twin_layout", annotations=READ_ONLY)
    async def get_digital_twin_layout_tool(host: str, site: str) -> Any:
        """Read a site's digital-twin topology layout (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/digital-twin/layout; the upstream body is
        returned verbatim.

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await get_digital_twin_layout(client, registry, host, site)

    @mcp.tool(name="update_digital_twin_layout", annotations=WRITE)
    async def update_digital_twin_layout_tool(host: str, site: str, layout: dict[str, Any]) -> Any:
        """Update a site's digital-twin topology layout (Network v2 route).

        Reads GET .../digital-twin/layout, merges only the given leaves over it (when no
        layout object exists yet the given layout is the whole body), PUTs it to
        /proxy/network/v2/api/site/{site}/digital-twin/layout and reads it back: the
        upstream body plus _verified (every requested leaf matched, type-strict) and
        _readAfterError when the read-back failed. An empty layout is refused before any
        request. Consequence: replaces the saved layout other operators see.

        Under dry-run policy nothing is sent and the tool returns a dry-run preview:
        status "dry_run", dryRun, message and preview (method, path, params, body).

        Returns the upstream body plus _verified and, when the read-back failed, _readAfterError;
        a non-object write body is returned whole under response with those keys beside it.

        Required arguments: host, site, layout.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            layout: Free-form layout leaves to set, e.g. {"zoom": 1.5}.
        """
        client, registry = deps_fn()
        return await update_digital_twin_layout(client, registry, host, site, layout)

    @mcp.tool(name="delete_digital_twin_layout", annotations=WRITE)
    async def delete_digital_twin_layout_tool(host: str, site: str) -> Any:
        """Delete a site's saved digital-twin topology layout (Network v2 route).

        DELETE /proxy/network/v2/api/site/{site}/digital-twin/layout; returns deleted,
        message and the upstream body as response. Never auto-retried. Consequence: the
        saved layout is removed permanently.

        Under dry-run policy nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, message and preview with method, path, params, body).

        Returns deleted, message and response (the upstream body).

        Required arguments: host, site.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        client, registry = deps_fn()
        return await delete_digital_twin_layout(client, registry, host, site)

    @mcp.tool(name="get_5g_topology", annotations=READ_ONLY)
    async def get_5g_topology_tool(host: str, site: str, device: str, at: int) -> Any:
        """Read a 5G device's topology snapshot at a point in time (Network v2 route).

        GET /proxy/network/v2/api/site/{site}/observability/5g/{device}/topology/at/{at},
        the route the Network 11.0.89 web app reads for a site whose internet connection is
        a 5G device (it sends the device MAC). The upstream body is returned verbatim plus
        an additive _warnings entry naming the epoch unit. at is epoch MILLISECONDS and is
        sent as given. A console that serves no 5G topology for the device answers an HTML
        404; the error keeps it and adds a hint.

        Returns the upstream body plus _warnings (the epoch unit of at).

        Required arguments: host, site, device, at.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            device: The 5G device's MAC (what the web app sends) or id, e.g.
                "02:00:5e:00:00:a1".
            at: Point in time, epoch milliseconds, e.g. 1760000000000.
        """
        client, registry = deps_fn()
        return await get_5g_topology(client, registry, host, site, device, at)

    @mcp.tool(name="get_multicast_insights", annotations=WRITE)
    async def get_multicast_insights_tool(
        host: str,
        site: str,
        view: Literal["client", "clients", "history"],
        client_mac: str | None = None,
        query_params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        """Read multicast insights (Network v2 routes).

        With view "client": GET /proxy/network/v2/api/site/{site}/insights/multicast/
        client/{client_mac}. With view "clients" or "history": POST
        .../insights/multicast/clients or .../history, sending query_params as the query
        string and body verbatim as JSON. These routes are present in the Network
        11.0.81 UI; the 2026-10-26 development-controller capture returned HTTP 404 for
        both POST views (controller version was not recorded). A firmware exposing these
        routes is required; the earliest supported version is unverified. Those POSTs
        are not on the read-POST allowlist, so this tool is
        a write: UNIFI_WRITE_POLICY=deny hides the whole tool, including the client GET view.
        Consequence: none intended; the POST is
        classed as a write.

        Under dry-run policy the POST views return a dry-run preview without sending a POST:
        status "dry_run", dryRun, sent=false, message and preview (method, path, params, body).
        The client GET view still reads normally.

        Returns the upstream body verbatim (a JSON array arrives as result).

        Required arguments: host, site, view.

        Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides
        the whole tool and discovery mode runs it through call_write_tool.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            view: "client", "clients" or "history", e.g. "history".
            client_mac: Client MAC, required for view "client" only, e.g.
                "02:00:5e:00:00:a1".
            query_params: Free-form query parameters (string, number or boolean
                values), e.g. {"start": 1760000000000, "end": 1760003600000}.
            body: Optional free-form query body for clients/history, e.g. {"client_macs": []}.
        """
        client, registry = deps_fn()
        return await get_multicast_insights(
            client, registry, host, site, view, client_mac, query_params, body
        )
