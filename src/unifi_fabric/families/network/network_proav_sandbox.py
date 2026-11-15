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

from typing import Any

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
from ...write_body import require_unmasked_fields, require_update_fields
from .network_routing_topology import _listed_record
from .schemas import (  # the family's shapes (family-owned layout)
    _5G_TOPOLOGY_NOT_SERVED,
    _LAYOUT,
    _MULTICAST_NOT_SERVED,
    _SECONDS_HINT_BELOW,
    _TEST_CONFIGS,
    MULTICAST_VIEWS,
    PROAV_KINDS,
    SHADOW_ACTIONS,
    SHADOW_VIEWS,
    TEST_CONFIG_ACTIONS,
    TV_WALL_ACTIONS,
)

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
