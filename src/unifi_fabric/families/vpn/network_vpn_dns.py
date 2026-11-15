"""Network VPN tools: IPsec settings, VPN users and connections, the OpenVPN client
configuration, WireGuard users, Teleport invitations and site VPNs.

The vpn family's DNS tools (static DNS records, DoH server names) live in the family-owned
layout (public #42): ``handlers.py``, ``schemas.py`` and ``registrar.py`` beside this
module. Their handlers stay importable from here.

Route choice: the official published API when it can do the job, else the newer v2 API,
else the Classic API. No published Network spec (11.0.97) has a route for any operation
in this module, so (routes from the Network 11.0.81 web-app route inventory,
``tests/fixtures/private_api/inventory_network_11.0.81.json``):

* v2 (``/proxy/network/v2/api/site/{site}/...``): static DNS records (``static-dns``),
  DoH server names, IPsec settings, VPN users and connections, the OpenVPN client
  configuration, the VPN server restart, WireGuard users and used subnets, Teleport
  invitations and clients, and the Site Magic VPN list (``magicsitetositevpn/configs``
  is GET-only).
* Classic ``cmd/sitemgr`` (the only route the web app uses to change a site VPN):
  ``add-site-vpn``, ``delete-site-vpn``, ``enable-site-vpn``, ``disable-site-vpn`` and
  ``rebuild-site-vpn``, through ``tools._classic_cmd`` (success requires
  ``meta.rc == "ok"``).

The static DNS record tools use the web app's own v2 ``static-dns`` collection (its
``_id`` ids and field names). The published DNS-policy tools (``*_dns_policy``) use the
Integration route ``/v1/sites/{siteId}/dns/policies`` with its own ids and schema; the
two routes differ, so both are offered.

Every response body is passed through verbatim; additions are ``_``-prefixed keys. Request
bodies with no published schema are free-form and sent as given. Under ``dry-run policy``
every write returns the client's dry-run preview and sends nothing. Credentials these
routes carry (WireGuard keys, Teleport tokens, the OpenVPN configuration, IPsec
pre-shared keys) are listed in ``route_secrets.ROUTE_SECRETS``: passed through by default,
masked in results and errors only under ``UNIFI_REDACT_SECRETS``, and always scrubbed
from logs and the audit log.
"""

from __future__ import annotations

import base64
from typing import Any, cast

from ...argument_values import require_finite
from ...client import (
    UniFiClient,
    UniFiConnectionError,
    decode_body,
    describe_shape,
    is_dry_run_preview,
    keep_stored_secrets,
    unmasked_read,
    upstream_error_value,
    validate_id,
)
from ...config import APIKeyConfig
from ...registry import Registry
from ...selector_args import check_selector
from ...shared_shapes._classic_cmd import classic_command_for_site
from ...shared_shapes._classic_objects import (
    listed_record_id,
    resolve_networkconf,
    v2_site,
)
from ...shared_shapes._keys import with_context
from ...shared_shapes._number_window import collect_number_window
from ...shared_shapes._pagination import collect_batch, mark_incomplete, validate_pagination
from ...shared_shapes._payload import upstream_hint
from ...shared_shapes._results import (
    deletion_readback_ids,
    deletion_result,
    requested_leaves_verdict,
    safe_read_after,
    with_read_after_error,
)
from ...write_body import require_unmasked_fields
from ._v2_records import merge_leaves as _merge
from ._v2_records import site_slug as _site
from ._v2_records import update_leaves as _update_body
from ._v2_records import v2_get as _v2_get
from ._v2_records import with_verdict as _with_verdict

# The DNS handlers moved to the family layout (handlers.py); their import path here stays.
from .handlers import (  # noqa: F401  (re-exported: families and tests import them here)
    create_static_dns_record,
    delete_static_dns_record,
    list_doh_servers,
    list_static_dns_records,
    update_static_dns_record,
)
from .schemas import (  # the family's shapes (family-owned layout)
    _SITE_VPN_ACTIONS,
    _TEXT_TYPES,
    SiteVpnAction,
)

#: Classic networkconf purpose of a VPN server (OpenVPN, WireGuard, L2TP).
_VPN_SERVER = "remote-user-vpn"
# --------------------------------------------------------------------------- helpers


def _require_items(items: Any, arg: str) -> list[Any]:
    """The caller's batch array, checked for JSON validity; an empty array names no user."""
    require_finite(items, arg)
    if isinstance(items, list) and not items:
        raise ValueError(
            f"{arg}: an empty list names no WireGuard user: pass at least one user object "
            "(create, update) or user _id (delete)"
        )
    return cast(list[Any], items)


async def _vpn_server(
    client: UniFiClient, registry: Registry, host: str, site: str, server_id: str
) -> tuple[APIKeyConfig | None, str, str, str]:
    """``(key, host_id, slug, classic _id)`` of one VPN server (unknown ids list choices)."""
    validate_id(server_id, "server_id")
    check_selector("host", host)
    check_selector("site", site)
    return await resolve_networkconf(
        client,
        registry,
        host,
        site,
        server_id,
        _VPN_SERVER,
        "VPN server",
        "list_vpn_servers",
        "server_id",
    )


# --------------------------------------------------------------------------- IPsec


async def get_ipsec_settings(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """GET v2 ``settings/ipsec``: the site's IPsec settings, verbatim."""
    return await _v2_get(client, registry, host, site, "/settings/ipsec")


async def update_ipsec_settings(
    client: UniFiClient, registry: Registry, host: str, site: str, fields: dict[str, Any], /
) -> Any:
    """Read-merge-write v2 ``settings/ipsec``: GET, lay ``fields`` over it, POST, verify."""
    changes = _update_body(fields, "update_ipsec_settings fields")
    key, host_id, slug = await _site(registry, host, site)
    path = v2_site(host_id, slug, "/settings/ipsec")
    with unmasked_read():  # the stored PSK is written back as stored
        current = await client.get(path, key=key)
    if not isinstance(current, dict):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected an object, got "
            f"{describe_shape(current)}. No write was sent."
        )
    body = keep_stored_secrets(client, _merge(current, changes), current, fields)
    response = await client.post(path, key=key, json=body)
    if is_dry_run_preview(response):
        return response
    after, error = await safe_read_after(lambda: client.get(path, key=key))
    verified, error = requested_leaves_verdict(changes, after, error)
    return _with_verdict(response, after, verified, error)


# --------------------------------------------------------------------------- VPN users


async def list_vpn_users(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """GET v2 ``vpn/users``: every remote-access VPN user of the site."""
    return await _v2_get(client, registry, host, site, "/vpn/users")


async def list_vpn_connections(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET v2 ``vpn/connections``: the site's VPN connections."""
    return await _v2_get(client, registry, host, site, "/vpn/connections")


def _binary_or_text(resp: Any) -> Any:
    """A JSON or text body verbatim; any other body as base64 plus its content type."""
    content_type = resp.headers.get("content-type")
    lowered = (content_type or "").lower()
    if not resp.content or any(lowered.startswith(t) for t in _TEXT_TYPES):
        return decode_body(resp)
    try:
        resp.content.decode("utf-8")
    except UnicodeDecodeError:
        return {
            "bodyBase64": base64.b64encode(resp.content).decode("ascii"),
            "contentType": content_type,
            "sizeBytes": len(resp.content),
        }
    return decode_body(resp)


async def get_openvpn_client_config(
    client: UniFiClient, registry: Registry, host: str, site: str, server_id: str
) -> Any:
    """GET v2 ``vpn/openvpn/{_id}/configuration``: the OpenVPN client configuration."""
    key, host_id, slug, classic_id = await _vpn_server(client, registry, host, site, server_id)
    try:
        resp = await client.request(
            "GET", v2_site(host_id, slug, f"/vpn/openvpn/{classic_id}/configuration"), key=key
        )
    except UniFiConnectionError as exc:
        if exc.status == 404:
            upstream_hint(
                exc,
                (
                    "The console could not find an OpenVPN configuration for this server. "
                    "Check list_vpn_servers and select an OpenVPN server configured on this site."
                ),
            )
            raise
        raise
    return _binary_or_text(resp)


async def restart_vpn_server(
    client: UniFiClient, registry: Registry, host: str, site: str, server_id: str
) -> Any:
    """POST v2 ``vpn/{_id}/restart`` ``{"cmd": "restart-vpn"}`` once (never retried)."""
    key, host_id, slug, classic_id = await _vpn_server(client, registry, host, site, server_id)
    return await client.post(
        v2_site(host_id, slug, f"/vpn/{classic_id}/restart"),
        key=key,
        json={"cmd": "restart-vpn"},
    )


# --------------------------------------------------------------------------- WireGuard


async def list_wireguard_users(
    client: UniFiClient, registry: Registry, host: str, site: str, server_id: str | None = None
) -> Any:
    """GET v2 ``wireguard/users`` (every server) or ``wireguard/{_id}/users`` (one server)."""
    if server_id is None:
        return await _v2_get(client, registry, host, site, "/wireguard/users")
    key, host_id, slug, classic_id = await _vpn_server(client, registry, host, site, server_id)
    return await client.get(v2_site(host_id, slug, f"/wireguard/{classic_id}/users"), key=key)


async def list_wireguard_used_subnets(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET v2 ``wireguard/users/existing-subnets``: subnets WireGuard users already use."""
    return await _v2_get(client, registry, host, site, "/wireguard/users/existing-subnets")


async def create_wireguard_users(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    server_id: str,
    users: list[dict[str, Any]],
    /,
) -> Any:
    """POST v2 ``wireguard/{_id}/users/batch`` with the caller's user array, verbatim."""
    _require_items(users, "users")
    key, host_id, slug, classic_id = await _vpn_server(client, registry, host, site, server_id)
    return await client.post(
        v2_site(host_id, slug, f"/wireguard/{classic_id}/users/batch"),
        key=key,
        json=cast(Any, users),
    )


def _user_ref(item: Any) -> str | None:
    """The ``_id`` an item names (a bare string, or an object's ``_id``), else None."""
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        value = item.get("_id")
        if isinstance(value, str):
            return value
    return None


def _require_user_refs(items: list[Any], tool: str) -> list[str]:
    """Each item's WireGuard user ``_id``, validated as a path-safe id before any request."""
    refs: list[str] = []
    for index, item in enumerate(items):
        ref = _user_ref(item)
        if ref is None:
            raise ValueError(
                f"{tool}: users[{index}] names no WireGuard user: pass the user's _id "
                "(from list_wireguard_users) as a string or as the item's _id field"
            )
        validate_id(ref, f"users[{index}]._id")
        refs.append(ref)
    return refs


def _select_users(
    body: Any, path: str, refs: list[str], client: UniFiClient | None = None
) -> list[dict[str, Any]]:
    """The listed user record of every ref from ONE list body (unknown refs list choices)."""
    rows = body.get("data") if isinstance(body, dict) else body
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected a JSON array of objects or "
            f"an object with a 'data' array of objects, got {describe_shape(body)}"
        )
    by_id = {str(r.get("_id")).lower(): r for r in rows if isinstance(r.get("_id"), str)}
    missing = [ref for ref in refs if ref.lower() not in by_id]
    if missing:
        valid = (
            "; ".join(
                f"{upstream_error_value(r.get('name'), client)!r} "
                f"(_id={upstream_error_value(r.get('_id'), client)})"
                for r in rows
            )
            or "(none)"
        )
        raise ValueError(
            f"WireGuard user(s) {', '.join(repr(m) for m in missing)} not found; valid: "
            f"{valid}. Get ids from list_wireguard_users (_id). No write was sent."
        )
    return [by_id[ref.lower()] for ref in refs]


async def update_wireguard_users(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    server_id: str,
    users: list[dict[str, Any]],
    /,
) -> Any:
    """Read-merge-write PUT v2 ``wireguard/{_id}/users/batch``, verified per user."""
    _require_items(users, "users")
    refs = _require_user_refs(users, "update_wireguard_users")
    changes = [
        _update_body(item, f"update_wireguard_users users[{index}]")
        for index, item in enumerate(users)
    ]
    key, host_id, slug, classic_id = await _vpn_server(client, registry, host, site, server_id)
    list_path = v2_site(host_id, slug, f"/wireguard/{classic_id}/users")
    with unmasked_read():  # each user's stored keys are written back as stored
        listed = await client.get(list_path, key=key)
    current = _select_users(listed, list_path, refs, client)
    ids = [listed_record_id(record, "users._id") for record in current]
    merged = [
        keep_stored_secrets(client, _merge(record, change), record, asked)
        for record, change, asked in zip(current, changes, users, strict=True)
    ]
    response = await client.put(f"{list_path}/batch", key=key, json=cast(Any, merged))
    if is_dry_run_preview(response):
        return response

    async def read_after() -> dict[str, Any]:
        rows = _select_users(await client.get(list_path, key=key), list_path, ids, client)
        return {user_id: row for user_id, row in zip(ids, rows, strict=True)}

    after, error = await safe_read_after(read_after)
    verdicts = [
        requested_leaves_verdict(change, after.get(user_id) if after else None, error)
        for user_id, change in zip(ids, changes, strict=True)
    ]
    reasons = [reason for _verdict, reason in verdicts if reason is not None]
    known = [verdict for verdict, _reason in verdicts]
    verified: bool | None
    if not known or any(v is None for v in known):
        verified = None
    else:
        verified = all(known)
    return _with_verdict(response, after, verified, reasons[0] if reasons else None)


async def delete_wireguard_users(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    server_id: str,
    users: list[Any],
    /,
) -> Any:
    """POST v2 ``wireguard/{_id}/users/batch_delete`` with the caller's array, verbatim."""
    _require_items(users, "users")
    refs = _require_user_refs(users, "delete_wireguard_users")
    key, host_id, slug, classic_id = await _vpn_server(client, registry, host, site, server_id)
    list_path = v2_site(host_id, slug, f"/wireguard/{classic_id}/users")
    _select_users(await client.get(list_path, key=key), list_path, refs, client)
    response = await client.post(f"{list_path}/batch_delete", key=key, json=cast(Any, users))
    result = deletion_result(f"{len(refs)} WireGuard user(s) deleted.", response)
    if is_dry_run_preview(response):
        return result

    async def read_after() -> set[str]:
        body = await client.get(list_path, key=key)
        rows = body.get("data") if isinstance(body, dict) else body
        if not isinstance(rows, list):
            raise UniFiConnectionError(
                f"Unexpected response shape from GET {list_path}: got {describe_shape(body)}"
            )
        return {item.lower() for item in deletion_readback_ids(rows, "_id")}

    after, error = await safe_read_after(read_after)
    if after is None:
        result.update(deleted=False, message="WireGuard batch-delete accepted; read-back failed.")
        return with_read_after_error(result, error)
    if any(ref.lower() in after for ref in refs):
        result.update(
            deleted=False, message="WireGuard batch-delete accepted; users remain listed."
        )
    return result


# --------------------------------------------------------------------------- Teleport


async def create_teleport_invitation(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    body: dict[str, Any] | None = None,
    /,
) -> Any:
    """POST v2 ``teleport/token``: issue a Teleport invitation (token and link)."""
    require_finite(body, "body")
    require_unmasked_fields(body, "create_teleport_invitation body")
    key, host_id, slug = await _site(registry, host, site)
    return await client.post(v2_site(host_id, slug, "/teleport/token"), key=key, json=body)


async def revoke_teleport_invitation(
    client: UniFiClient, registry: Registry, host: str, site: str, invitation_id: str
) -> Any:
    """DELETE v2 ``teleport/token/{id}``: revoke one Teleport invitation."""
    validate_id(invitation_id, "invitation_id")
    key, host_id, slug = await _site(registry, host, site)
    response = await client.delete(
        v2_site(host_id, slug, f"/teleport/token/{invitation_id}"), key=key
    )
    return deletion_result(f"Teleport invitation {invitation_id} revoked.", response)


def _page_rows(body: Any) -> list[Any] | None:
    """The records of one invitation-history page (a bare array or ``data``), else None."""
    if isinstance(body, list):
        return body
    rows = body.get("data") if isinstance(body, dict) else None
    return rows if isinstance(rows, list) else None


async def query_teleport_invitations(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    page_number: int | None = None,
    page_size: int | None = None,
) -> Any:
    """POST v2 ``teleport/invitation-history``. Zero-based page_number: with page_size,
    returns exactly page_size records starting at record page_number * page_size, gathered
    across console pages whatever the console page size; resume with _nextPage and the same
    page_size. Without page_size, one request returns that console page verbatim.
    page_size alone is page_number 0: exactly page_size records from record 0; with
    neither, every record is read. This read-type POST remains classified as a write.
    """
    # The zero-based page is checked at entry, before site resolution or any request.
    validate_pagination(
        page_size=page_size,
        zero_page=page_number,
        names={"page_size": "page_size", "zero_page": "page_number"},
    )
    key, host_id, slug = await _site(registry, host, site)
    path = v2_site(host_id, slug, "/teleport/invitation-history")
    extra: dict[str, Any] = {} if page_size is None else {"pageSize": page_size}
    if page_number is not None and page_size is None:
        return await client.post(path, key=key, json={"pageNumber": page_number, **extra})

    async def fetch(paging: dict[str, Any]) -> Any:
        return await client.post(path, key=key, json=paging)

    if page_size is not None and page_size > 0 and (page_number or 0) >= 0:
        # The logical window [page*N, page*N + N), whatever the console page size;
        # page_size alone is window 0, so its _nextPage counts page_size windows.
        collected = await collect_number_window(
            fetch,
            page=page_number or 0,
            page_size=page_size,
            max_pages=client.paginate_max_pages,
            # page_size alone keeps the first page's envelope, as the drain from page 0 did.
            keep_console_keys=page_number is None,
        )
    else:
        collected = await collect_batch(
            fetch,
            requested=page_size,
            default_size=None,
            family="number",
            start=page_number or 0,
            max_pages=client.paginate_max_pages,
        )
    if "raw" in collected:
        first = collected["raw"]
        if isinstance(first, dict) and _page_rows(first) is None and not is_dry_run_preview(first):
            return with_context(
                first,
                {
                    "_pages": 1,
                    "_drainNote": (
                        f"page {page_number or 0} has no 'data' array (no paged "
                        "envelope recognised), so no later page was requested"
                    ),
                },
            )
        return first
    items = collected["items"]
    return mark_incomplete(
        with_context(
            {**collected["envelope"], "data": items},
            {"_count": len(items), "_pages": collected["pages"]},
        ),
        collected,
    )


async def remove_teleport_client(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    client_id: str,
    body: dict[str, Any] | None = None,
    /,
) -> Any:
    """DELETE v2 ``teleport/client/{id}`` (with the caller's body when given)."""
    validate_id(client_id, "client_id")
    require_finite(body, "body")
    require_unmasked_fields(body, "remove_teleport_client body")
    key, host_id, slug = await _site(registry, host, site)
    response = await client.delete(
        v2_site(host_id, slug, f"/teleport/client/{client_id}"), key=key, json=body
    )
    return deletion_result(f"Teleport client {client_id} removed.", response)


# --------------------------------------------------------------------------- Site VPN


async def list_magic_site_vpn(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """GET v2 ``magicsitetositevpn/configs``: Site Magic site-to-site VPN configurations."""
    return await _v2_get(client, registry, host, site, "/magicsitetositevpn/configs")


async def create_site_vpn(
    client: UniFiClient, registry: Registry, host: str, site: str, params: dict[str, Any], /
) -> Any:
    """Classic ``cmd/sitemgr`` ``add-site-vpn`` with the caller's parameters, verbatim."""
    return await classic_command_for_site(
        client, registry, host, site, "sitemgr", "add-site-vpn", params
    )


async def delete_site_vpn(
    client: UniFiClient, registry: Registry, host: str, site: str, name: str, vpn_site: str
) -> Any:
    """Classic ``cmd/sitemgr`` ``delete-site-vpn`` ``{name, site}``."""
    response = await classic_command_for_site(
        client, registry, host, site, "sitemgr", "delete-site-vpn", {"name": name, "site": vpn_site}
    )
    return deletion_result(f"Site VPN {name!r} deleted.", response)


async def control_site_vpn(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    action: SiteVpnAction,
    name: str | None = None,
    vpn_site: str | None = None,
    params: dict[str, Any] | None = None,
) -> Any:
    """Classic ``cmd/sitemgr`` ``enable-site-vpn`` / ``disable-site-vpn`` / ``rebuild-site-vpn``."""
    if action not in _SITE_VPN_ACTIONS:
        raise ValueError(
            f"Invalid site VPN action {action!r}: action must be one of "
            f"{', '.join(_SITE_VPN_ACTIONS)}"
        )
    given = {k: v for k, v in (("name", name), ("site", vpn_site)) if v is not None}
    twice = sorted(k for k in given if isinstance(params, dict) and k in params)
    if twice:
        raise ValueError(
            f"Site VPN arguments name {' and '.join(twice)} twice, as typed argument(s) and as "
            "key(s) of params; give each once. Nothing was sent."
        )
    body = {**(params or {}), **given}
    return await classic_command_for_site(
        client, registry, host, site, "sitemgr", f"{action}-site-vpn", body
    )


# --------------------------------------------------------------------------- registration
