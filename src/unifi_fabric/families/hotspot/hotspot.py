"""Hotspot operator tools — manage captive portal operator accounts.

Hotspot vouchers are served by the network-services proxy (see
``families/network/network_services_proxy.py`` and the ``*_hotspot_vouchers`` tools in
``server.py``), not from this module. This module only owns the Classic-REST
``/rest/hotspotop`` operator tools.
"""

from __future__ import annotations

from typing import Any

from ...client import UniFiClient, UniFiConnectionError, describe_shape, validate_id
from ...config import APIKeyConfig
from ...registry import Registry
from ...shared_shapes._classic_objects import (
    addressed_body,
    listed_record_id,
    require_listed_record,
)
from ...shared_shapes._payload import strip_empty_list_values
from ...shared_shapes._results import deletion_result, dry_run_or_verbatim
from ...write_body import require_update_fields
from .schemas import (  # the family's shapes (family-owned layout)
    _CLASSIC_REST_BASE,
)


def _classic_rest(host_id: str, site_slug: str, path: str) -> str:
    return _CLASSIC_REST_BASE.format(host_id=host_id, site_slug=site_slug) + path


# ---------------------------------------------------------------------------
# Hotspot operators
# ---------------------------------------------------------------------------


async def _list_hotspot_operators(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
) -> Any:
    """List hotspot operator accounts via Classic REST (/rest/hotspotop).

    Returns the controller's ``{"meta": {...}, "data": [operator, ...]}`` envelope
    verbatim. A body that is not that envelope raises with the shape received.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    path = _classic_rest(host_id, site_slug, "/hotspotop")
    data = await client.get(path, key=key)
    items = data.get("data") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected an object with a 'data' "
            f"array, got {describe_shape(data)}"
        )
    return data


async def _create_hotspot_operator(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    name: str,
    password: str,
    *,
    note: str | None = None,
    **extra: Any,
) -> Any:
    """Create a hotspot operator account via Classic REST (/rest/hotspotop).

    Operators are managed through the console's Classic REST controller — the
    same base ``list_hotspot_operators`` reads from — not the Site Manager
    ``/ea/hotspot-operators`` path, which is not served on the console and 404s at
    the route level. The site is addressed by its slug in the URL, so host/site
    identifiers are not repeated in the body; the controller field for the
    operator secret is ``x_password``. ``note`` is sent only when the caller passed
    it. Returns the controller's ``{"meta": {...}, "data": [...]}`` body verbatim.

    Args:
        host: Host name or ID.
        site: Site name or ID.
        name: Operator username.
        password: Operator password.
        note: Optional note for this operator.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)

    body: dict[str, Any] = {
        "name": name,
        "x_password": password,
        **extra,
    }
    if note is not None:
        body["note"] = note

    return dry_run_or_verbatim(
        await client.post(_classic_rest(host_id, site_slug, "/hotspotop"), key=key, json=body)
    )


async def _require_operator(
    client: UniFiClient,
    host_id: str,
    site_slug: str,
    operator_id: str,
    key: APIKeyConfig | None,
) -> str:
    """The upstream ``_id`` of hotspot operator ``operator_id`` (resolved in its list)."""
    record = await require_listed_record(
        client,
        _classic_rest(host_id, site_slug, "/hotspotop"),
        operator_id,
        key=key,
        kind="Hotspot operator",
        list_tool="list_hotspot_operators",
    )
    return listed_record_id(record, "operator_id")


async def _update_hotspot_operator(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    operator_id: str,
    fields: dict[str, Any],
    /,
) -> Any:
    """Update a hotspot operator by ID via Classic REST (/rest/hotspotop/{id}).

    ``fields`` is the caller's body, passed as one positional-only dict so a body key
    named like a parameter (``site``, ``host``, ``client``) is sent, never bound.

    Empty-string entries are stripped from list-valued fields (the controller pads
    lists on read), like every other Classic REST PUT. The id is resolved in the
    /rest/hotspotop list first: an unknown id fails listing every operator, and no PUT
    is sent. Returns the controller's ``{"meta": {...}, "data": [...]}`` body verbatim.
    """
    validate_id(operator_id, "operator_id")
    clean = require_update_fields(fields, "update_hotspot_operator")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    upstream_id = await _require_operator(client, host_id, site_slug, operator_id, key)
    return dry_run_or_verbatim(
        await client.put(
            _classic_rest(host_id, site_slug, f"/hotspotop/{upstream_id}"),
            key=key,
            json=strip_empty_list_values(addressed_body(clean, upstream_id)),
        )
    )


async def _delete_hotspot_operator(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    operator_id: str,
) -> dict[str, Any]:
    """Delete a hotspot operator by ID via Classic REST (/rest/hotspotop/{id}).

    The id is resolved in the /rest/hotspotop list first (the controller answers a
    DELETE on an unknown id with HTTP 200): an unknown id fails listing every operator,
    and no DELETE is sent."""
    validate_id(operator_id, "operator_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    upstream_id = await _require_operator(client, host_id, site_slug, operator_id, key)
    response = await client.delete(
        _classic_rest(host_id, site_slug, f"/hotspotop/{upstream_id}"), key=key
    )
    return deletion_result(f"Hotspot operator {operator_id} deleted.", response)
