"""Network VPN and DNS tools: static DNS records, DoH servers, IPsec settings, VPN users
and connections, the OpenVPN client configuration, WireGuard users, Teleport invitations
and site VPNs.

Route choice: the official published API when it can do the job, else the newer v2 API,
else the Classic API. No published Network spec (10.6.106) has a route for any operation
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
bodies with no published schema are free-form and sent as given. Under ``UNIFI_DRY_RUN``
every write returns the client's dry-run preview and sends nothing. Credentials these
routes carry (WireGuard keys, Teleport tokens, the OpenVPN configuration, IPsec
pre-shared keys) are listed in ``route_secrets.ROUTE_SECRETS``: passed through by default,
masked in results and errors only under ``UNIFI_REDACT_SECRETS``, and always scrubbed
from logs and the audit log.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Any, Literal, cast

from fastmcp import FastMCP

from ..argument_values import require_finite
from ..client import (
    UniFiClient,
    UniFiConnectionError,
    decode_body,
    describe_shape,
    is_dry_run_preview,
    validate_id,
)
from ..config import APIKeyConfig
from ..redaction import drop_and_note_masked_fields
from ..registry import Registry
from ..selector_args import check_selector
from ..tool_annotations import READ_ONLY, WRITE
from ..write_body import IDENTITY_FIELDS, require_unmasked_fields, require_update_fields
from ._classic_cmd import classic_command_for_site
from ._classic_objects import (
    listed_record_id,
    require_listed_record,
    resolve_networkconf,
    resolve_site_slug,
    v2_site,
)
from ._keys import with_context
from ._number_window import collect_number_window
from ._pagination import collect_batch, mark_incomplete, validate_pagination
from ._payload import upstream_hint
from ._results import (
    deletion_readback_ids,
    deletion_result,
    requested_leaves_verdict,
    safe_read_after,
    with_read_after_error,
)

#: Classic networkconf purpose of a VPN server (OpenVPN, WireGuard, L2TP).
_VPN_SERVER = "remote-user-vpn"
#: The v2 static DNS record collection.
_STATIC_DNS = "/static-dns"
#: Site VPN actions on Classic ``cmd/sitemgr`` (``<action>-site-vpn``).
SiteVpnAction = Literal["enable", "disable", "rebuild"]
_SITE_VPN_ACTIONS = ("enable", "disable", "rebuild")

_TEXT_TYPES = ("text/", "application/json", "application/x-openvpn-profile")


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


def _update_body(value: Any, what: str) -> dict[str, Any]:
    """The requested update leaves (masked and identity fields dropped), or raise."""
    clean = require_update_fields(drop_and_note_masked_fields(value), what)
    return {key: item for key, item in clean.items() if key not in IDENTITY_FIELDS}


def _merge(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """Recursively lay only the requested leaves over the current upstream record."""
    merged = dict(current)
    for key, value in changes.items():
        prior = merged.get(key)
        merged[key] = (
            _merge(prior, value) if isinstance(prior, dict) and isinstance(value, dict) else value
        )
    return merged


def _with_verdict(response: Any, after: Any, verified: bool | None, error: str | None) -> Any:
    """The write response verbatim plus ``_verified`` / ``_readAfter`` (additive keys).

    A non-object write body is kept whole under ``response`` so the verdict keys are never dropped.
    """
    if not isinstance(response, dict):
        response = {"response": response}
    result = with_context(response, {"_verified": verified, "_readAfter": after})
    return with_read_after_error(result, error, additive=True)


async def _site(registry: Registry, host: str, site: str) -> tuple[APIKeyConfig | None, str, str]:
    check_selector("host", host)
    check_selector("site", site)
    return await resolve_site_slug(registry, host, site)


async def _v2_get(client: UniFiClient, registry: Registry, host: str, site: str, route: str) -> Any:
    key, host_id, slug = await _site(registry, host, site)
    return await client.get(v2_site(host_id, slug, route), key=key)


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


# --------------------------------------------------------------------------- static DNS


async def list_static_dns_records(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET v2 ``static-dns``: every static DNS record of the site, verbatim."""
    return await _v2_get(client, registry, host, site, _STATIC_DNS)


async def create_static_dns_record(
    client: UniFiClient, registry: Registry, host: str, site: str, record: dict[str, Any], /
) -> Any:
    """POST v2 ``static-dns`` with the caller's record, verbatim."""
    require_finite(record, "record")
    key, host_id, slug = await _site(registry, host, site)
    return await client.post(v2_site(host_id, slug, _STATIC_DNS), key=key, json=record)


async def update_static_dns_record(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    record_id: str,
    record: dict[str, Any],
    /,
) -> Any:
    """Read-merge-write PUT v2 ``static-dns/{_id}``, then verify the requested leaves."""
    validate_id(record_id, "record_id")
    changes = _update_body(record, "update_static_dns_record record")
    key, host_id, slug = await _site(registry, host, site)
    collection = v2_site(host_id, slug, _STATIC_DNS)

    async def listed(wanted: str) -> dict[str, Any]:
        return await require_listed_record(
            client,
            collection,
            wanted,
            key=key,
            kind="Static DNS record",
            list_tool="list_static_dns_records",
            label_fields=("key", "name"),
        )

    current = await listed(record_id)
    resolved = listed_record_id(current, "record_id")
    response = await client.put(f"{collection}/{resolved}", key=key, json=_merge(current, changes))
    if is_dry_run_preview(response):
        return response
    after, error = await safe_read_after(lambda: listed(resolved))
    verified, error = requested_leaves_verdict(changes, after, error)
    return _with_verdict(response, after, verified, error)


async def delete_static_dns_record(
    client: UniFiClient, registry: Registry, host: str, site: str, record_id: str
) -> Any:
    """Resolve ``record_id`` in v2 ``static-dns``, then DELETE ``static-dns/{_id}``."""
    validate_id(record_id, "record_id")
    key, host_id, slug = await _site(registry, host, site)
    collection = v2_site(host_id, slug, _STATIC_DNS)
    current = await require_listed_record(
        client,
        collection,
        record_id,
        key=key,
        kind="Static DNS record",
        list_tool="list_static_dns_records",
        label_fields=("key", "name"),
    )
    resolved = listed_record_id(current, "record_id")
    response = await client.delete(f"{collection}/{resolved}", key=key)
    return deletion_result(f"Static DNS record {resolved} deleted.", response)


# --------------------------------------------------------------------------- DoH / IPsec


async def list_doh_servers(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """GET v2 ``settings/doh/available-server-names``: DNS-over-HTTPS server names."""
    return await _v2_get(client, registry, host, site, "/settings/doh/available-server-names")


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
    current = await client.get(path, key=key)
    if not isinstance(current, dict):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected an object, got "
            f"{describe_shape(current)}. No write was sent."
        )
    response = await client.post(path, key=key, json=_merge(current, changes))
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


def _select_users(body: Any, path: str, refs: list[str]) -> list[dict[str, Any]]:
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
        valid = "; ".join(f"{r.get('name')!r} (_id={r.get('_id')})" for r in rows) or "(none)"
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
    current = _select_users(await client.get(list_path, key=key), list_path, refs)
    ids = [listed_record_id(record, "users._id") for record in current]
    merged = [_merge(record, change) for record, change in zip(current, changes, strict=True)]
    response = await client.put(f"{list_path}/batch", key=key, json=cast(Any, merged))
    if is_dry_run_preview(response):
        return response

    async def read_after() -> dict[str, Any]:
        rows = _select_users(await client.get(list_path, key=key), list_path, ids)
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
    _select_users(await client.get(list_path, key=key), list_path, refs)
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


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the N07 VPN and DNS tools as typed FastMCP functions."""

    def deps() -> tuple[UniFiClient, Registry]:
        return cast(tuple[UniFiClient, Registry], deps_fn())

    @mcp.tool(name="list_static_dns_records", annotations=READ_ONLY)
    async def _list_static_dns_records(host: str, site: str) -> Any:
        """List the site's static DNS records (v2 static-dns, the web app's DNS records).

        Required: host and site. Route: v2 GET static-dns (no published route serves this
        collection; the published dns/policies route is list_dns_policies). Returns the upstream
        body verbatim (a JSON array or object, as sent); each record's _id is the record_id of the
        other static DNS record tools.

        Example call (list_static_dns_records):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        return await list_static_dns_records(*deps(), host, site)

    @mcp.tool(name="create_static_dns_record", annotations=WRITE)
    async def _create_static_dns_record(
        host: str, site: str, record: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Create a static DNS record (v2 POST static-dns).

        Required: host, site and record. Request body: no published schema; record is
        free-form and sent verbatim, named as list_static_dns_records returns records
        (for example key, value, record_type and enabled). An empty record fails before
        any request. Returns the upstream body verbatim. Dry-run (UNIFI_DRY_RUN) returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (create_static_dns_record):
            {"host": "my-console", "site": "Default", "record": {"key": "nas.example.com",
             "value": "192.0.2.20", "record_type": "A", "enabled": true}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            record: Free-form record object, e.g. {"key": "nas.example.com", "value": "192.0.2.20"}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await create_static_dns_record(*deps(), host, site, record)

    @mcp.tool(name="update_static_dns_record", annotations=WRITE)
    async def _update_static_dns_record(
        host: str, site: str, record_id: str, record: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Update a static DNS record (v2 PUT static-dns/{_id}, read-merge-write).

        Required: host, site, record_id and record. record_id is resolved in
        list_static_dns_records first; an unknown id fails listing every record and
        nothing is sent. record holds only the fields to change (free-form, no published
        schema); they are laid leaf by leaf over the listed record and the whole record is
        PUT. An empty update fails before any request. Returns the upstream body verbatim
        plus _verified (type-strict comparison of every requested leaf in a read-after)
        and _readAfter, or _readAfterError; a non-object write body is returned whole under
        response with those keys beside it. Dry-run (UNIFI_DRY_RUN) returns a dry-run
        preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}; nothing is sent.

        Example call (update_static_dns_record):
            {"host": "my-console", "site": "Default", "record_id": "65f1c0ffee0123456789abcd",
             "record": {"value": "192.0.2.21"}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            record_id: Record _id from list_static_dns_records, e.g. "65f1c0ffee0123456789abcd".
            record: Fields to change, e.g. {"value": "192.0.2.21"}. Free-form object.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await update_static_dns_record(*deps(), host, site, record_id, record)

    @mcp.tool(name="delete_static_dns_record", annotations=WRITE)
    async def _delete_static_dns_record(
        host: str, site: str, record_id: str, confirm: bool = False
    ) -> Any:
        """Delete a static DNS record (v2 DELETE static-dns/{_id}).

        Consequence: the name stops resolving through the gateway; there is no undo.
        Required: host, site and record_id. record_id is resolved in
        list_static_dns_records first; an unknown id fails listing every record and
        nothing is deleted. Returns {deleted, message, response} with the upstream body
        verbatim. Dry-run (UNIFI_DRY_RUN) returns {status: "dry_run", deleted: false,
        message, response}, where response is the dry-run preview {status: "dry_run",
        dryRun, sent: false, message, preview: {method, path, params, body}}; nothing is sent.

        Example call (delete_static_dns_record):
            {"host": "my-console", "site": "Default", "record_id": "65f1c0ffee0123456789abcd"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            record_id: Record _id from list_static_dns_records, e.g. "65f1c0ffee0123456789abcd".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await delete_static_dns_record(*deps(), host, site, record_id)

    @mcp.tool(name="list_doh_servers", annotations=READ_ONLY)
    async def _list_doh_servers(host: str, site: str) -> Any:
        """List the DNS-over-HTTPS server names the gateway offers (v2 settings/doh).

        Required: host and site. Route: v2 GET settings/doh/available-server-names (no
        published route). Returns the upstream body verbatim (a JSON array or object, as sent).

        Example call (list_doh_servers):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        return await list_doh_servers(*deps(), host, site)

    @mcp.tool(name="get_ipsec_settings", annotations=READ_ONLY)
    async def _get_ipsec_settings(host: str, site: str) -> Any:
        """Get the site's IPsec settings (v2 settings/ipsec).

        Required: host and site. Route: v2 GET settings/ipsec (no published route).
        Returns the upstream object verbatim; a pre-shared key in it is masked only under
        UNIFI_REDACT_SECRETS. Change it with update_ipsec_settings.

        Example call (get_ipsec_settings):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        return await get_ipsec_settings(*deps(), host, site)

    @mcp.tool(name="update_ipsec_settings", annotations=WRITE)
    async def _update_ipsec_settings(
        host: str, site: str, fields: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Update the site's IPsec settings (v2 POST settings/ipsec, read-merge-write).

        Consequence: IPsec tunnels and remote IPsec users may reconnect.
        Required: host, site and fields. Request body: no published schema; fields is
        free-form and holds only the keys to change, named as get_ipsec_settings returns
        them. The current settings are read, your fields laid over them leaf by leaf and
        the whole object POSTed. An empty update fails before any request. Returns the
        upstream body verbatim plus _verified (type-strict leaf comparison of a
        read-after) and _readAfter, or _readAfterError (a non-object write body is returned
        whole under response with those keys beside it). Dry-run (UNIFI_DRY_RUN) returns a
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (update_ipsec_settings):
            {"host": "my-console", "site": "Default", "fields": {"enabled": true}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            fields: Free-form settings to change, e.g. {"enabled": true}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await update_ipsec_settings(*deps(), host, site, fields)

    @mcp.tool(name="list_vpn_users", annotations=READ_ONLY)
    async def _list_vpn_users(host: str, site: str) -> Any:
        """List the site's remote-access VPN users (v2 vpn/users).

        Required: host and site. Route: v2 GET vpn/users (no published route). Returns the upstream
        body verbatim (a JSON array or object, as sent).

        Example call (list_vpn_users):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        return await list_vpn_users(*deps(), host, site)

    @mcp.tool(name="list_vpn_connections", annotations=READ_ONLY)
    async def _list_vpn_connections(host: str, site: str) -> Any:
        """List the site's VPN connections (v2 vpn/connections).

        Required: host and site. Route: v2 GET vpn/connections (no published route).
        Returns the upstream body verbatim (a JSON array or object, as sent).

        Example call (list_vpn_connections):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        return await list_vpn_connections(*deps(), host, site)

    @mcp.tool(name="get_openvpn_client_config", annotations=READ_ONLY)
    async def _get_openvpn_client_config(host: str, site: str, server_id: str) -> Any:
        """Get an OpenVPN server's client configuration (v2 vpn/openvpn/{_id}/configuration).

        Required: host, site and server_id. The configuration is a credential (certificate and
        private key): it is returned as received and masked only under UNIFI_REDACT_SECRETS.
        server_id is resolved among the site's VPN servers first; an unknown id fails listing every
        server. An upstream 404 adds a hint to check for an OpenVPN server on this site.
        Returns the upstream body verbatim (a JSON array or object, as sent) (JSON or text);
        a binary body comes back as {bodyBase64, contentType, sizeBytes}.

        Example call (get_openvpn_client_config):
            {"host": "my-console", "site": "Default", "server_id": "65f1c0ffee0123456789abcd"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            server_id: VPN server id from list_vpn_servers or its Classic _id,
                e.g. "65f1c0ffee0123456789abcd".
        """
        return await get_openvpn_client_config(*deps(), host, site, server_id)

    @mcp.tool(name="restart_vpn_server", annotations=WRITE)
    async def _restart_vpn_server(
        host: str, site: str, server_id: str, confirm: bool = False
    ) -> Any:
        """Restart one VPN server (v2 POST vpn/{_id}/restart, cmd restart-vpn).

        Consequence: every user connected to this VPN server is disconnected.
        Required: host, site and server_id. Sent once, never retried automatically.
        server_id is resolved among the site's VPN servers first; an unknown id fails
        listing every server and nothing is sent. Returns the upstream body verbatim.
        Dry-run (UNIFI_DRY_RUN) returns a dry-run preview {status: "dry_run", dryRun: true, sent:
        false, message, preview: {method, path, params, body}}; nothing is sent.

        Example call (restart_vpn_server):
            {"host": "my-console", "site": "Default", "server_id": "65f1c0ffee0123456789abcd"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            server_id: VPN server id from list_vpn_servers or its Classic _id,
                e.g. "65f1c0ffee0123456789abcd".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await restart_vpn_server(*deps(), host, site, server_id)

    @mcp.tool(name="list_wireguard_users", annotations=READ_ONLY)
    async def _list_wireguard_users(host: str, site: str, server_id: str | None = None) -> Any:
        """List WireGuard VPN users (v2 wireguard/users or wireguard/{_id}/users).

        Required: host and site. Without server_id every WireGuard server's users are listed; with
        it only that server's (resolved among the site's VPN servers first; an unknown id fails
        listing every server). Returns the upstream body verbatim (a JSON array or object, as sent);
        key fields are masked only under UNIFI_REDACT_SECRETS.

        Example call (list_wireguard_users):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            server_id: Optional WireGuard server id from list_vpn_servers or its Classic _id,
                e.g. "65f1c0ffee0123456789abcd".
        """
        return await list_wireguard_users(*deps(), host, site, server_id)

    @mcp.tool(name="list_wireguard_used_subnets", annotations=READ_ONLY)
    async def _list_wireguard_used_subnets(host: str, site: str) -> Any:
        """List the subnets WireGuard users already use (v2 wireguard/users/existing-subnets).

        Required: host and site. Route: v2 GET (no published route). Returns the upstream body
        verbatim (a JSON array or object, as sent).

        Example call (list_wireguard_used_subnets):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        return await list_wireguard_used_subnets(*deps(), host, site)

    @mcp.tool(name="create_wireguard_users", annotations=WRITE)
    async def _create_wireguard_users(
        host: str,
        site: str,
        server_id: str,
        users: list[dict[str, Any]],
        confirm: bool = False,
    ) -> Any:
        """Create WireGuard users on one server (v2 POST wireguard/{_id}/users/batch).

        Consequence: issues VPN credentials; each new peer can reach the network. Required: host,
        site, server_id and users. Request body: no published schema; users is a free-form JSON
        array of user objects sent verbatim (the web app's batch body), named as
        list_wireguard_users returns users. Keys are passed through and masked only under
        UNIFI_REDACT_SECRETS. server_id is resolved among the site's VPN servers first. Returns the
        upstream body verbatim. Dry-run (UNIFI_DRY_RUN) returns a dry-run preview {status:
        "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}};
        nothing is sent.

        Example call (create_wireguard_users):
            {"host": "my-console", "site": "Default", "server_id": "65f1c0ffee0123456789abcd",
             "users": [{"name": "laptop-01", "interface_ip": "192.0.2.10"}]}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            server_id: WireGuard server id from list_vpn_servers or its Classic _id,
                e.g. "65f1c0ffee0123456789abcd".
            users: Non-empty free-form array of user objects (an empty list fails before any
                request), e.g. [{"name": "laptop-01"}].
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await create_wireguard_users(*deps(), host, site, server_id, users)

    @mcp.tool(name="update_wireguard_users", annotations=WRITE)
    async def _update_wireguard_users(
        host: str,
        site: str,
        server_id: str,
        users: list[dict[str, Any]],
        confirm: bool = False,
    ) -> Any:
        """Update WireGuard users on one server (v2 PUT wireguard/{_id}/users/batch).

        Consequence: changed keys or addresses disconnect the affected peers.
        Required: host, site, server_id and users. Each users item names a user by _id
        (from list_wireguard_users) plus only the fields to change (free-form; no
        published schema). Every _id is resolved in the server's user list first; an
        unknown _id fails listing every user and nothing is sent; an item with nothing to
        change fails before any request. Each listed record with your fields laid over it
        leaf by leaf is PUT as one array. Returns the upstream body verbatim plus
        _verified (type-strict, every requested leaf of every user) and _readAfter, or
        _readAfterError (a non-object write body is returned whole under response with those
        keys beside it). Dry-run (UNIFI_DRY_RUN) returns a dry-run preview {status:
        "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}}.

        Example call (update_wireguard_users):
            {"host": "my-console", "site": "Default", "server_id": "65f1c0ffee0123456789abcd",
             "users": [{"_id": "65f1c0ffee0123456789abce", "name": "laptop-02"}]}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            server_id: WireGuard server id from list_vpn_servers or its Classic _id,
                e.g. "65f1c0ffee0123456789abcd".
            users: Non-empty array of _id plus fields to change (an empty list fails before any
                request), e.g. [{"_id": "65f1c0ffee0123456789abce", "name": "laptop-02"}].
                Shape: {_id:string,...}[]; the other keys of each entry are the fields to change
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await update_wireguard_users(*deps(), host, site, server_id, users)

    @mcp.tool(name="delete_wireguard_users", annotations=WRITE)
    async def _delete_wireguard_users(
        host: str,
        site: str,
        server_id: str,
        users: list[str | dict[str, Any]],
        confirm: bool = False,
    ) -> Any:
        """Delete WireGuard users from one server (v2 POST wireguard/{_id}/users/batch_delete).

        Consequence: the peers lose VPN access at once; there is no undo.
        Required: host, site, server_id and users. users is the batch_delete array sent
        verbatim (no published schema): user _id strings or user objects carrying _id,
        from list_wireguard_users. Every _id is resolved in the server's user list first;
        an unknown _id fails listing every user and nothing is deleted. Returns {deleted,
        message, response} with the upstream body verbatim. Dry-run (UNIFI_DRY_RUN)
        returns {status: "dry_run", deleted: false, message, response}, where response is
        the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (delete_wireguard_users):
            {"host": "my-console", "site": "Default", "server_id": "65f1c0ffee0123456789abcd",
             "users": ["65f1c0ffee0123456789abce"]}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            server_id: WireGuard server id from list_vpn_servers or its Classic _id,
                e.g. "65f1c0ffee0123456789abcd".
            users: Non-empty list of user _ids or objects with _id (an empty list fails before
                any request), e.g. ["65f1c0ffee0123456789abce"].
                Shape: (string|{_id:string,...})[]; each entry is sent as given
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await delete_wireguard_users(*deps(), host, site, server_id, list(users))

    @mcp.tool(name="create_teleport_invitation", annotations=WRITE)
    async def _create_teleport_invitation(
        host: str, site: str, body: dict[str, Any] | None = None, confirm: bool = False
    ) -> Any:
        """Create a Teleport invitation (v2 POST teleport/token).

        Consequence: issues a credential; whoever holds the link can join the network
        through Teleport until it is used or revoked (revoke_teleport_invitation).
        Required: host and site. The web app sends no body; body is optional, free-form
        and sent verbatim when given. Returns the upstream body verbatim (the token and
        invitation link, masked only under UNIFI_REDACT_SECRETS). Dry-run (UNIFI_DRY_RUN)
        returns a dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}}; nothing is sent.

        Example call (create_teleport_invitation):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            body: Optional free-form request body, e.g. {"name": "guest-laptop"}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await create_teleport_invitation(*deps(), host, site, body)

    @mcp.tool(name="revoke_teleport_invitation", annotations=WRITE)
    async def _revoke_teleport_invitation(
        host: str, site: str, invitation_id: str, confirm: bool = False
    ) -> Any:
        """Revoke a Teleport invitation (v2 DELETE teleport/token/{id}).

        Consequence: the invitation link stops working; there is no undo.
        Required: host, site and invitation_id (from query_teleport_invitations). No GET
        route lists invitations by id, so the id is sent as given and the controller
        judges it. Returns {deleted, message, response} with the upstream body verbatim.
        Dry-run (UNIFI_DRY_RUN) returns {status: "dry_run", deleted: false, message,
        response}, where response is the dry-run preview {status: "dry_run", dryRun, sent: false,
        message, preview: {method, path, params, body}}; nothing is sent.

        Example call (revoke_teleport_invitation):
            {"host": "my-console", "site": "Default", "invitation_id": "65f1c0ffee0123456789abcd"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            invitation_id: Invitation id from query_teleport_invitations,
                e.g. "65f1c0ffee0123456789abcd".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await revoke_teleport_invitation(*deps(), host, site, invitation_id)

    @mcp.tool(name="query_teleport_invitations", annotations=WRITE)
    async def _query_teleport_invitations(
        host: str,
        site: str,
        page_number: int | None = None,
        page_size: int | None = None,
        confirm: bool = False,
    ) -> Any:
        """List Teleport invitation history (v2 POST teleport/invitation-history).

        Required: host and site. A read sent as POST (Consequence: none intended; it only
        reads the history): it is not on the read-POST allowlist, so it is classed as a
        write: UNIFI_READ_ONLY refuses it, and under UNIFI_DRY_RUN it returns a dry-run
        preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}} of the first page and sends nothing.
        Without a requested total every page is read (pageNumber 0, 1, ... to the end)
        and the records are joined under data, adding _count and _pages; a stopped drain
        (page cap, repeated page, a later page without records) adds incomplete: true and
        incompleteReason. Returns that joined object. An empty first page is returned
        verbatim; a first page without a data array is returned verbatim plus _pages and
        _drainNote. page_number alone returns that page verbatim. page_size alone is window
        0: exactly page_size records from record 0; _nextPage counts page_size windows, so
        resume with page_number=_nextPage and the same page_size. page_number with page_size
        returns that window. Omit both to drain every record.
        _pageSize reports the requested count, sent (every pageSize sent, in request order),
        the effective console page size and the returned count. _nextPage is absent when no
        record follows the window or the call stopped incomplete.

        Example call (query_teleport_invitations):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            page_number: Zero-based page. With page_size, returns exactly page_size records
                starting at record page_number * page_size, gathered across console pages
                whatever the console page size; resume with _nextPage and the same page_size.
                Without page_size, one request returns that console page verbatim. Example: 0.
            page_size: Number of invitations. Alone, window 0 (the first page_size records,
                fewer only at the end); with page_number, the size of the window. Omit to
                drain all. Example: `100`.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await query_teleport_invitations(*deps(), host, site, page_number, page_size)

    @mcp.tool(name="remove_teleport_client", annotations=WRITE)
    async def _remove_teleport_client(
        host: str,
        site: str,
        client_id: str,
        body: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> Any:
        """Remove a Teleport client (v2 DELETE teleport/client/{id}).

        Consequence: the client loses Teleport access and must be invited again.
        Required: host, site and client_id. No GET route lists Teleport clients by id, so
        the id is sent as given and the controller judges it. body is optional and
        free-form (the web app builds one; its shape is not published) and is sent
        verbatim when given. Returns {deleted, message, response} with the upstream body
        verbatim. Dry-run (UNIFI_DRY_RUN) returns {status: "dry_run", deleted: false,
        message, response}, where response is the dry-run preview {status: "dry_run",
        dryRun, sent: false, message, preview: {method, path, params, body}}; nothing is sent.

        Example call (remove_teleport_client):
            {"host": "my-console", "site": "Default", "client_id": "65f1c0ffee0123456789abcd"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            client_id: Teleport client id from list_vpn_connections,
                e.g. "65f1c0ffee0123456789abcd".
            body: Optional free-form request body, e.g. {"name": "guest-laptop"}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await remove_teleport_client(*deps(), host, site, client_id, body)

    @mcp.tool(name="list_magic_site_vpn", annotations=READ_ONLY)
    async def _list_magic_site_vpn(host: str, site: str) -> Any:
        """List Site Magic site-to-site VPN configurations (v2 magicsitetositevpn/configs).

        Required: host and site. Route: v2 GET (GET-only; change site VPNs with create_site_vpn,
        control_site_vpn and delete_site_vpn). Returns the upstream body verbatim (a JSON array or
        object, as sent).

        Example call (list_magic_site_vpn):
            {"host": "my-console", "site": "Default"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
        """
        return await list_magic_site_vpn(*deps(), host, site)

    @mcp.tool(name="create_site_vpn", annotations=WRITE)
    async def _create_site_vpn(
        host: str, site: str, params: dict[str, Any], confirm: bool = False
    ) -> Any:
        """Create a site VPN (Classic POST cmd/sitemgr, cmd add-site-vpn).

        Consequence: builds a VPN between controller sites; routing between them changes.
        Required: host, site and params. Request body: no published schema and no
        captured body; params is free-form and sent verbatim beside cmd. Success requires
        meta.rc ok; any other answer raises with the full upstream body. Returns the
        Classic {meta, data} envelope verbatim. Dry-run (UNIFI_DRY_RUN) returns a dry-run
        preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}; nothing is sent.

        Example call (create_site_vpn):
            {"host": "my-console", "site": "Default", "params": {"site": "branch-1"}}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            params: Free-form add-site-vpn parameters, e.g. {"site": "branch-1"}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await create_site_vpn(*deps(), host, site, params)

    @mcp.tool(name="delete_site_vpn", annotations=WRITE)
    async def _delete_site_vpn(
        host: str, site: str, name: str, vpn_site: str, confirm: bool = False
    ) -> Any:
        """Delete a site VPN (Classic POST cmd/sitemgr, cmd delete-site-vpn).

        Consequence: the VPN between the sites is torn down; there is no undo.
        Required: host, site, name and vpn_site. Sends {cmd: delete-site-vpn, name, site:
        vpn_site} as the web app does; the controller judges both values. Success
        requires meta.rc ok; any other answer raises with the full upstream body. Returns
        {deleted, message, response} with the envelope verbatim. Dry-run (UNIFI_DRY_RUN)
        returns {status: "dry_run", deleted: false, message, response}, where response is
        the dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (delete_site_vpn):
            {"host": "my-console", "site": "Default", "name": "branch-vpn",
             "vpn_site": "branch-1"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            name: Site VPN name, e.g. "branch-vpn".
            vpn_site: The peer site sent as the body's site, e.g. "branch-1".
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await delete_site_vpn(*deps(), host, site, name, vpn_site)

    @mcp.tool(name="control_site_vpn", annotations=WRITE)
    async def _control_site_vpn(
        host: str,
        site: str,
        action: SiteVpnAction,
        name: str | None = None,
        vpn_site: str | None = None,
        params: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> Any:
        """Enable, disable or rebuild a site VPN (Classic POST cmd/sitemgr).

        Consequence: disable and rebuild interrupt traffic between the sites.
        Required: host, site and action. Sends cmd enable-site-vpn, disable-site-vpn or
        rebuild-site-vpn with name and site (vpn_site) when given (the web app's
        enable/disable body) plus any free-form params (rebuild has no captured body).
        Success requires meta.rc ok; any other answer raises with the full upstream body.
        Returns the Classic {meta, data} envelope verbatim. Dry-run (UNIFI_DRY_RUN) returns
        a dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}; nothing is sent.

        Example call (control_site_vpn):
            {"host": "my-console", "site": "Default", "action": "disable",
             "name": "branch-vpn", "vpn_site": "branch-1"}

        Args:
            host: Console name or id (list_hosts), e.g. "my-console".
            site: Network site name or UUID, e.g. "Default".
            action: One of enable, disable, rebuild, e.g. "disable".
            name: Site VPN name, e.g. "branch-vpn".
            vpn_site: The peer site sent as the body's site, e.g. "branch-1".
            params: Optional free-form extra parameters, e.g. {"name": "branch-vpn"}.
            confirm: Ignored; accepted for compatibility. The call executes when made.
        """
        return await control_site_vpn(*deps(), host, site, action, name, vpn_site, params)
