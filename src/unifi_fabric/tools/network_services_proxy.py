"""Network services tools — DNS, traffic lists, VPN, RADIUS, hotspot via connector proxy."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from fastmcp import FastMCP

from ..client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    object_records,
    strip_additive_keys,
    upstream_error_value,
    validate_id,
)
from ..config import APIKeyConfig
from ..matching import find_by_id, name_matches, same_id
from ..redaction import drop_and_note_masked_fields
from ..registry import Registry, _assert_uuid
from ..tool_annotations import READ_ONLY, WRITE
from ..write_body import identity_fields, require_update_fields
from ._classic_objects import (
    addressed_body,
    consumed_string_array,
    listed_record_id,
    require_listed_record,
)
from ._keys import with_context
from ._pagination import collect_offset, offset_list_result, validate_pagination
from ._payload import (
    integration_update_body,
    missing_fields_hint,
    require_fields,
    strip_empty_list_values,
    upstream_hint,
    with_upstream_hint,
)
from ._results import (
    MISSING,
    UNVERIFIED_FIELDS_KEY,
    VERIFIED_KEY,
    deletion_result,
    leaf_equal,
    read_after_verdict,
    requested_leaves_verdict,
    safe_read_after,
    short_circuit_no_op,
    with_read_after_error,
)
from ._shared import _validate_optional_site
from .network import _proxy


async def _drain_offset_list(
    client: UniFiClient,
    url: str,
    *,
    key: APIKeyConfig | None = None,
    offset: int | None,
    limit: int | None,
    filter: str | None = None,
) -> dict[str, Any]:
    """Offset list fetch: drain all pages by default, single page when paged manually.

    The same shared paging path as every other Integration list (``collect_offset``):
    manual offset/limit values are forwarded as given and validated by the upstream,
    whose own error is returned verbatim. ``filter`` is the Integration API's
    server-side filter expression, forwarded unchanged in either mode.
    """
    params = {"filter": filter} if filter is not None else None
    collected = await collect_offset(
        client, url, key=key, params=params, offset=offset, limit=limit
    )
    return offset_list_result(collected)


# --- DNS Policies ---


async def list_dns_policies(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List DNS policies for a site.

    This Network Integration endpoint is offset-paginated (verified live: the
    response carries an ``{offset, limit, count, totalCount, data}`` envelope and
    the native default page size is only 25). By default every page is drained and
    the complete list is returned as ``{data, totalCount}``; pass offset or limit to
    fetch a single manual page (native envelope preserved). A capped drain is
    flagged ``incomplete`` rather than truncating silently.
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await _drain_offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/dns/policies"),
        key=key,
        offset=offset,
        limit=limit,
        filter=filter,
    )


async def create_dns_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy: dict[str, Any]
) -> dict[str, Any]:
    """Create a DNS policy.

    Required field: ``type`` — the policy's discriminator, which the API validates first
    (verified live: an empty body is rejected with ``Missing $.type value``). Fields
    beyond the discriminator are type-specific and are not validated here.
    """
    require_fields("create_dns_policy", policy, {"type"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/dns/policies"), key=key, json=policy
    )


async def get_dns_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy_id: str
) -> dict[str, Any]:
    validate_id(policy_id, "policy_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(_proxy(host_id, f"/sites/{site_id}/dns/policies/{policy_id}"), key=key)


async def update_dns_policy(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    policy_id: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    validate_id(policy_id, "policy_id")
    policy = integration_update_body("update_dns_policy", policy)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/dns/policies/{policy_id}"),
        key=key,
        json=policy,
    )


async def delete_dns_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy_id: str
) -> Any:
    validate_id(policy_id, "policy_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.delete(
        _proxy(host_id, f"/sites/{site_id}/dns/policies/{policy_id}"), key=key
    )


# --- Traffic Matching Lists ---


async def list_traffic_matching_lists(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await _drain_offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/traffic-matching-lists"),
        key=key,
        offset=offset,
        limit=limit,
        filter=filter,
    )


async def create_traffic_matching_list(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    traffic_list: dict[str, Any],
) -> dict[str, Any]:
    """Create a traffic-matching list.

    Required field: ``type`` — the list's discriminator, which the API validates first
    (verified live: an empty body is rejected with ``Missing $.type value``). Observed
    values include ``PORTS``. Fields beyond the discriminator (e.g. ``name``, ``items``)
    are type-specific and are not validated here.
    """
    require_fields("create_traffic_matching_list", traffic_list, {"type"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/traffic-matching-lists"), key=key, json=traffic_list
    )


async def get_traffic_matching_list(
    client: UniFiClient, registry: Registry, host: str, site: str, list_id: str
) -> dict[str, Any]:
    validate_id(list_id, "list_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(
        _proxy(host_id, f"/sites/{site_id}/traffic-matching-lists/{list_id}"), key=key
    )


async def update_traffic_matching_list(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    list_id: str,
    traffic_list: dict[str, Any],
) -> dict[str, Any]:
    validate_id(list_id, "list_id")
    traffic_list = integration_update_body("update_traffic_matching_list", traffic_list)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.put(
        _proxy(host_id, f"/sites/{site_id}/traffic-matching-lists/{list_id}"),
        key=key,
        json=traffic_list,
    )


async def delete_traffic_matching_list(
    client: UniFiClient, registry: Registry, host: str, site: str, list_id: str
) -> Any:
    validate_id(list_id, "list_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.delete(
        _proxy(host_id, f"/sites/{site_id}/traffic-matching-lists/{list_id}"), key=key
    )


# --- VPN Servers (read-only) ---


async def list_vpn_servers(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List VPN servers for a site.

    This Network Integration endpoint is offset-paginated (verified live: the
    response carries an ``{offset, limit, count, totalCount, data}`` envelope with a
    native default page size of 25). By default every page is drained and the
    complete list is returned as ``{data, totalCount}``; pass offset or limit for a
    single manual page. A capped drain is flagged ``incomplete`` rather than
    truncating silently.
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await _drain_offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/vpn/servers"),
        key=key,
        offset=offset,
        limit=limit,
        filter=filter,
    )


async def list_site_to_site_tunnels(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await _drain_offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/vpn/site-to-site-tunnels"),
        key=key,
        offset=offset,
        limit=limit,
        filter=filter,
    )


# --- RADIUS Profiles (read-only) ---


async def list_radius_profiles(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List RADIUS profiles for a site.

    This Network Integration endpoint is offset-paginated (verified live: the
    response carries an ``{offset, limit, count, totalCount, data}`` envelope with a
    native default page size of 25). By default every page is drained and the
    complete list is returned as ``{data, totalCount}``; pass offset or limit for a
    single manual page. A capped drain is flagged ``incomplete`` rather than
    truncating silently.
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await _drain_offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/radius/profiles"),
        key=key,
        offset=offset,
        limit=limit,
        filter=filter,
    )


# --- Hotspot Vouchers ---


async def list_hotspot_vouchers(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List hotspot vouchers for a site.

    This Network Integration endpoint is offset-paginated (verified live: the
    response carries an ``{offset, limit, count, totalCount, data}`` envelope with a
    native default page size of 100). Voucher batches routinely exceed that, so a
    single page silently truncated large sets. By default every page is now drained
    and the complete list is returned as ``{data, totalCount}``; pass offset or limit
    for a single manual page. A capped drain is flagged ``incomplete`` rather than
    truncating silently.
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await _drain_offset_list(
        client,
        _proxy(host_id, f"/sites/{site_id}/hotspot/vouchers"),
        key=key,
        offset=offset,
        limit=limit,
        filter=filter,
    )


async def create_hotspot_vouchers(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    voucher_config: dict[str, Any],
) -> dict[str, Any]:
    """Create a hotspot voucher batch.

    Required fields (verified live — an empty body is rejected naming both):
    ``name`` and ``timeLimitMinutes`` (the voucher validity window in minutes).
    """
    require_fields("create_hotspot_vouchers", voucher_config, {"name", "timeLimitMinutes"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.post(
        _proxy(host_id, f"/sites/{site_id}/hotspot/vouchers"), key=key, json=voucher_config
    )


async def get_hotspot_voucher(
    client: UniFiClient, registry: Registry, host: str, site: str, voucher_id: str
) -> dict[str, Any]:
    validate_id(voucher_id, "voucher_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.get(
        _proxy(host_id, f"/sites/{site_id}/hotspot/vouchers/{voucher_id}"), key=key
    )


async def delete_hotspot_voucher(
    client: UniFiClient, registry: Registry, host: str, site: str, voucher_id: str
) -> Any:
    validate_id(voucher_id, "voucher_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.delete(
        _proxy(host_id, f"/sites/{site_id}/hotspot/vouchers/{voucher_id}"), key=key
    )


async def bulk_delete_hotspot_vouchers(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    params: dict[str, Any],
) -> Any:
    # The spec's DELETE /hotspot/vouchers requires the ``filter`` query parameter.
    require_fields("bulk_delete_hotspot_vouchers filter_params", params, {"filter"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    return await client.delete(
        _proxy(host_id, f"/sites/{site_id}/hotspot/vouchers"), key=key, params=params
    )


# --- Supporting Resources ---


async def list_device_tags(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List a site's device tags via the v2 API the controller UI uses.

    GET /v2/api/site/{site}/device-tags answers the whole list in one bare JSON array (the
    route takes no paging parameters), returned verbatim. These are the tags the Network UI
    shows and the records create/update/delete_device_tag write, keyed by ``_id``; the
    Integration ``/sites/{id}/device-tags`` collection is separate (empty on Network 11.0.81
    while the UI has tags).
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_v2_api(host_id, site_slug, "/device-tags"), key=key)


async def list_countries(
    client: UniFiClient,
    registry: Registry,
    host: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    return await _drain_offset_list(
        client, _proxy(host_id, "/countries"), key=key, offset=offset, limit=limit, filter=filter
    )


# --- Port Forwards (Classic REST API) ---

# Classic REST: /proxy/network/api/s/{site_slug}/rest/portforward
_CLASSIC_REST_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/rest"
# Traffic Rules v2: /proxy/network/v2/api/site/{site_slug}/trafficrules
_V2_API_BASE = "/v1/connector/consoles/{host_id}/proxy/network/v2/api/site/{site_slug}"
# Classic Stat: /proxy/network/api/s/{site_slug}/stat
_CLASSIC_STAT_BASE = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/stat"


def _classic_rest(host_id: str, site_slug: str, path: str) -> str:
    return _CLASSIC_REST_BASE.format(host_id=host_id, site_slug=site_slug) + path


def _v2_api(host_id: str, site_slug: str, path: str) -> str:
    return _V2_API_BASE.format(host_id=host_id, site_slug=site_slug) + path


def _classic_stat(host_id: str, site_slug: str, path: str) -> str:
    return _CLASSIC_STAT_BASE.format(host_id=host_id, site_slug=site_slug) + path


async def list_port_forwards(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    """List port-forward rules for a site via the Classic REST API.

    Example response item: {"_id": "abc123", "name": "SSH", "dst_port": "2222",
    "fwd": "192.168.1.10", "fwd_port": "22", "proto": "tcp", "enabled": true}
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, "/portforward"), key=key)


async def create_port_forward(
    client: UniFiClient, registry: Registry, host: str, site: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """Create a port-forward rule via the Classic REST API.

    Required fields: name (str), dst_port (str), fwd (str), fwd_port (str).
    ``proto`` is optional — the controller defaults it (typically ``tcp_udp``) when
    omitted. Verified live that this Classic REST endpoint enforces *no* required
    fields server-side: it accepts an empty body and silently creates a broken rule,
    so this local check is the only guard against a malformed forward.
    Example: {"enabled": true, "name": "SSH", "pfwd_interface": "wan", "src": "any",
    "dst_port": "2222", "fwd": "192.168.1.10", "fwd_port": "22", "proto": "tcp", "log": false}
    """
    hint = missing_fields_hint(
        "create_port_forward",
        payload,
        ("name", "dst_port", "fwd", "fwd_port"),
        "the Classic endpoint is observed to accept a body without them and create a broken rule",
    )
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await with_upstream_hint(
        client.post(_classic_rest(host_id, site_slug, "/portforward"), key=key, json=payload), hint
    )


async def _require_port_forward(
    client: UniFiClient, host_id: str, site_slug: str, forward_id: str, key: APIKeyConfig | None
) -> str:
    """The upstream ``_id`` of port forward ``forward_id`` (resolved in its list)."""
    record = await require_listed_record(
        client,
        _classic_rest(host_id, site_slug, "/portforward"),
        forward_id,
        key=key,
        kind="Port forward",
        list_tool="list_port_forwards",
    )
    return listed_record_id(record, "forward_id")


async def update_port_forward(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    forward_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Update a port-forward rule via the Classic REST API (the id is resolved first)."""
    validate_id(forward_id, "forward_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    upstream_id = await _require_port_forward(client, host_id, site_slug, forward_id, key)
    return await client.put(
        _classic_rest(host_id, site_slug, f"/portforward/{upstream_id}"),
        key=key,
        json=strip_empty_list_values(addressed_body(payload, upstream_id)),
    )


async def delete_port_forward(
    client: UniFiClient, registry: Registry, host: str, site: str, forward_id: str
) -> Any:
    """Delete a port-forward rule via the Classic REST API (the id is resolved first)."""
    validate_id(forward_id, "forward_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    upstream_id = await _require_port_forward(client, host_id, site_slug, forward_id, key)
    return await client.delete(
        _classic_rest(host_id, site_slug, f"/portforward/{upstream_id}"), key=key
    )


# --- Traffic Rules (v2 API) ---


async def list_traffic_rules(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List traffic rules for a site via the v2 API.

    Example response item: {"_id": "rule-1", "description": "Block Social Media",
    "action": "BLOCK", "matching_target": "INTERNET", "enabled": true}
    The v2 API answers with a bare JSON array, returned verbatim (the same shape as
    ``list_traffic_routes``); nothing is added around it.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_v2_api(host_id, site_slug, "/trafficrules"), key=key)


#: The error a Network 11.0.89 and 11.0.97 console answers (HTTP 501) to POST v2
#: trafficrules while it still answers GET on the same route (live 2026-11-08).
_TRAFFIC_RULE_NOT_IMPLEMENTED = "api.err.NotImplemented"
_TRAFFIC_RULE_NOT_IMPLEMENTED_HINT = (
    "this console's Network application does not implement creating traffic rules on the v2 "
    "trafficrules route (it may still list them with list_traffic_rules), so no change to "
    "the payload will help. No Network version that creates traffic rules here is recorded "
    "by this server's sources: the pinned Network 11.0.97 Integration spec has no traffic-rule "
    "route and the Network 11.0.81 web UI only reads this one. Build the rule with a supported "
    "family instead: create_firewall_policy (block or allow; match IPs or domains with a list "
    "from create_traffic_matching_list), create_qos_rule (rate limit or queue) or "
    "create_traffic_route (send matching traffic through a chosen WAN or VPN)."
)


async def create_traffic_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """Create a traffic rule via the v2 API.

    Required fields (verified live): ``action``, ``matching_target`` and
    ``target_devices``. Note that ``target_devices`` — the devices/networks the rule
    applies to — is required by the API but was previously undocumented, while
    ``description`` and ``enabled`` are *not* API-required (the controller defaults
    ``enabled``); both are accepted as optional fields.

    A console that does not implement this route answers HTTP 501 api.err.NotImplemented;
    the error keeps the upstream body and gets a hint naming the supported alternatives.
    """
    hint = missing_fields_hint(
        "create_traffic_rule",
        payload,
        ("action", "matching_target", "target_devices"),
        "observed required by the v2 API",
    )
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    try:
        return await client.post(
            _v2_api(host_id, site_slug, "/trafficrules"), key=key, json=payload
        )
    except UniFiConnectionError as exc:
        # A route the console does not implement: a missing-field hint would mislead.
        if exc.status == 501 or _TRAFFIC_RULE_NOT_IMPLEMENTED in str(exc):
            hint = _TRAFFIC_RULE_NOT_IMPLEMENTED_HINT
        upstream_hint(exc, hint)
        raise


async def _listed_traffic_rule(
    client: UniFiClient, host_id: str, site_slug: str, rule_id: str, key: APIKeyConfig | None
) -> dict[str, Any]:
    """The listed record of traffic rule ``rule_id`` (an unknown id raises, no write)."""
    return await require_listed_record(
        client,
        _v2_api(host_id, site_slug, "/trafficrules"),
        rule_id,
        key=key,
        kind="Traffic rule",
        list_tool="list_traffic_rules",
        label_fields=("description", "name"),
    )


async def _require_traffic_rule(
    client: UniFiClient, host_id: str, site_slug: str, rule_id: str, key: APIKeyConfig | None
) -> str:
    """The upstream ``_id`` of traffic rule ``rule_id`` (resolved in its list)."""
    record = await _listed_traffic_rule(client, host_id, site_slug, rule_id, key)
    return listed_record_id(record, "rule_id")


def _merged_record(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """``current`` with only the requested leaves of ``changes`` written over it.

    Objects merge recursively; any other value (a list included) replaces the stored one.
    Neither argument is mutated.
    """
    merged = dict(current)
    for name, value in changes.items():
        prior = merged.get(name)
        merged[name] = (
            _merged_record(prior, value)
            if isinstance(prior, dict) and isinstance(value, dict)
            else value
        )
    return merged


async def update_traffic_rule(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    rule_id: str,
    payload: dict[str, Any],
) -> Any:
    """Read-merge-write a traffic rule via the v2 API, then verify the requested leaves.

    The v2 ``trafficrules/{id}/`` PUT replaces the whole rule, so ``payload`` (the fields
    to change) is merged into the rule as ``list_traffic_rules`` lists it and the merged
    rule is PUT: unrequested fields (``matching_target``, ``target_devices``, ``schedule``
    and the rest) are sent back unchanged. A payload with no field to change (empty, or
    only identity, additive ``_`` or masked keys) is refused before any request. The
    upstream PUT body is returned plus ``_verified`` (every requested leaf read back
    equal, type-strict) and ``_readAfterError`` when the read-back failed; a non-object
    PUT body is kept under ``response``.
    """
    validate_id(rule_id, "rule_id")
    clean = require_update_fields(
        drop_and_note_masked_fields(payload), "update_traffic_rule payload"
    )
    identity = identity_fields("update_traffic_rule")
    changes = {name: value for name, value in clean.items() if name not in identity}
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    record = await _listed_traffic_rule(client, host_id, site_slug, rule_id, key)
    upstream_id = listed_record_id(record, "rule_id")
    body = _merged_record(strip_additive_keys(record), changes)
    response = await client.put(
        _v2_api(host_id, site_slug, f"/trafficrules/{upstream_id}/"),
        key=key,
        json=strip_empty_list_values(addressed_body(body, upstream_id)),
    )
    if is_dry_run_preview(response):
        # dry-run policy: nothing was written, so there is nothing to verify.
        return response
    after, error = await safe_read_after(
        lambda: _listed_traffic_rule(client, host_id, site_slug, upstream_id, key)
    )
    verified, error = requested_leaves_verdict(strip_empty_list_values(changes), after, error)
    result = response if isinstance(response, dict) else {"response": response}
    additions: dict[str, Any] = {VERIFIED_KEY: verified}
    if error is not None:
        additions["_readAfterError"] = error
    return with_context(result, additions)


async def delete_traffic_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule_id: str
) -> Any:
    """Delete a traffic rule via the v2 API (the id is resolved first)."""
    validate_id(rule_id, "rule_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    upstream_id = await _require_traffic_rule(client, host_id, site_slug, rule_id, key)
    return await client.delete(
        _v2_api(host_id, site_slug, f"/trafficrules/{upstream_id}/"), key=key
    )


# Classic REST tools return the controller's {"meta": {...}, "data": [...]} body verbatim
# (meta included; meta.rc is relayed, not interpreted). Tools that select records return
# that envelope with ``data`` narrowed to the selection; tools that add a convenience view
# add it only as ``_``-prefixed keys.


def _classic_records(response: Any, path: str) -> list[dict[str, Any]]:
    """The ``data`` array of a Classic REST envelope, or raise with the shape received."""
    data = response.get("data") if isinstance(response, dict) else None
    if not isinstance(data, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from {path}: expected an object with a 'data' array, "
            f"got {describe_shape(response)}"
        )
    return object_records(data, path)


# Fields managed by the UniFi controller that may change on every write
# regardless of whether the submitted payload was accepted.  Exclude these
# from silent-no-op comparison so that timestamp churn does not mask a
# genuinely rejected setting update.
_SERVER_MANAGED_FIELDS = frozenset(
    {
        "_id",
        "site_id",
        "key",
        "last_modified",
        "_updatedAt",
        "_createdAt",
    }
)


# --- Users / DHCP Reservations (Classic REST) ---


async def list_users(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List DHCP fixed-IP reservations and client aliases via Classic REST /rest/user."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, "/user"), key=key)


async def get_user(
    client: UniFiClient, registry: Registry, host: str, site: str, user_id: str
) -> Any:
    """Get a single DHCP/client-alias entry by ID via Classic REST /rest/user."""
    validate_id(user_id, "user_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, f"/user/{user_id}"), key=key)


async def update_user(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    user_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a DHCP/client-alias entry via Classic REST /rest/user (id resolved first)."""
    validate_id(user_id, "user_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    record = await require_listed_record(
        client,
        _classic_rest(host_id, site_slug, "/user"),
        user_id,
        key=key,
        kind="User",
        list_tool="list_users",
        label_fields=("name", "hostname", "mac"),
    )
    upstream_id = listed_record_id(record, "user_id")
    return await client.put(
        _classic_rest(host_id, site_slug, f"/user/{upstream_id}"),
        key=key,
        json=strip_empty_list_values(addressed_body(payload, upstream_id)),
    )


# --- Traffic Routes (v2 API) ---


async def list_traffic_routes(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List static/policy traffic routes via the v2 API."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_v2_api(host_id, site_slug, "/trafficroutes"), key=key)


async def create_traffic_route(
    client: UniFiClient, registry: Registry, host: str, site: str, payload: dict[str, Any]
) -> Any:
    """Create a traffic route via the v2 API.

    Required fields (verified live): ``network_id``, ``matching_target`` and
    ``target_devices`` — the API rejects a body missing any of them.
    """
    hint = missing_fields_hint(
        "create_traffic_route",
        payload,
        ("network_id", "matching_target", "target_devices"),
        "observed required by the v2 API",
    )
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await with_upstream_hint(
        client.post(_v2_api(host_id, site_slug, "/trafficroutes"), key=key, json=payload), hint
    )


async def get_traffic_route(
    client: UniFiClient, registry: Registry, host: str, site: str, route_id: str
) -> Any:
    """Get a single traffic route by ID (list + filter; the API has no GET-by-ID endpoint).

    The v2 list is a bare JSON array; any other shape raises with the shape received. An
    unknown id fails listing every valid route (description and ``_id``).
    """
    validate_id(route_id, "route_id")
    routes = await list_traffic_routes(client, registry, host, site)
    if not isinstance(routes, list):
        raise UniFiConnectionError(
            "Unexpected response shape from GET v2 trafficroutes: expected a JSON array, got "
            f"{describe_shape(routes)}"
        )
    records = object_records(routes, "GET v2 trafficroutes")
    route = find_by_id(records, route_id, "_id")
    if route is not None:
        listed_record_id(route, "route_id")
        return route
    valid = "; ".join(
        f"{upstream_error_value(r.get('description') or '(no description)', client)} "
        f"({upstream_error_value(r.get('_id'), client)})"
        for r in records
    )
    raise ValueError(
        f"Traffic route {route_id!r} not found; valid: {valid or '(none)'}. "
        "Get ids from list_traffic_routes (_id)."
    )


async def _require_traffic_route(
    client: UniFiClient, host_id: str, site_slug: str, route_id: str, key: APIKeyConfig | None
) -> str:
    """The upstream ``_id`` of traffic route ``route_id`` (resolved in its list)."""
    record = await require_listed_record(
        client,
        _v2_api(host_id, site_slug, "/trafficroutes"),
        route_id,
        key=key,
        kind="Traffic route",
        list_tool="list_traffic_routes",
        label_fields=("description", "name"),
    )
    return listed_record_id(record, "route_id")


async def update_traffic_route(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    route_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a traffic route by ID via the v2 API (the id is resolved first)."""
    validate_id(route_id, "route_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    upstream_id = await _require_traffic_route(client, host_id, site_slug, route_id, key)
    return await client.put(
        _v2_api(host_id, site_slug, f"/trafficroutes/{upstream_id}"),
        key=key,
        json=strip_empty_list_values(addressed_body(payload, upstream_id)),
    )


async def delete_traffic_route(
    client: UniFiClient, registry: Registry, host: str, site: str, route_id: str
) -> Any:
    """Delete a traffic route by ID via the v2 API (the id is resolved first)."""
    validate_id(route_id, "route_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    upstream_id = await _require_traffic_route(client, host_id, site_slug, route_id, key)
    return await client.delete(
        _v2_api(host_id, site_slug, f"/trafficroutes/{upstream_id}"), key=key
    )


# --- Controller Settings (Classic REST) ---


async def list_settings(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List controller settings (grouped by key) via Classic REST /rest/setting."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, "/setting"), key=key)


async def get_setting(
    client: UniFiClient, registry: Registry, host: str, site: str, setting_key: str
) -> Any:
    """Get a single controller setting group by key via Classic REST /rest/setting.

    The returned object is the group's full current state: every settable field and its
    current (valid) value. There is no separate schema endpoint, so **reading a group is
    how you discover what it accepts** — inspect the returned keys and current values
    before calling ``update_setting``. The controller silently drops any field or enum
    value it does not recognise (it returns HTTP 200 with the value unchanged rather than
    a validation error), so match an existing field's shape exactly.

    Common setting keys and notable enum fields (grounded in live controller responses;
    valid values are controller-defined — read the current value to confirm):

    * ``mdns`` — ``mode`` (e.g. ``all``), ``enabled_for`` (e.g. ``some``/``none``)
    * ``ntp`` — ``setting_preference`` (``auto``/manual), ``ntp_server_1``..``ntp_server_4``
    * ``locale`` — ``timezone``;  ``country`` — ``code`` (numeric string, e.g. ``840``)
    * ``doh`` — ``state`` (e.g. ``auto``/``off``)
    * ``ips`` — ``ips_mode`` (e.g. ``ids``/``ips``), ``advanced_filtering_preference``
    * ``global_nat`` — ``mode`` (e.g. ``auto``);  ``dashboard`` — ``layout_preference``
    * ``ssl_inspection`` — ``state`` (e.g. ``off``)
    * ``super_mgmt`` — ``data_retention_setting_preference``, ``live_updates``, ``live_chat``
    * ``guest_access`` — ``auth`` (e.g. ``hotspot``);  ``mgmt`` — ``led_enabled`` (bool)

    Fields prefixed ``x_`` hold credentials/secrets (passwords, keys, tokens) and are
    returned verbatim (masked when UNIFI_REDACT_SECRETS is enabled).
    """
    validate_id(setting_key, "setting_key")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, f"/setting/{setting_key}"), key=key)


async def update_setting(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    setting_key: str,
    payload: dict[str, Any],
) -> Any:
    """Update a controller setting group by key via Classic REST /rest/setting.

    Discovering the schema: there is no schema endpoint. Call ``get_setting(setting_key)``
    first — the returned object lists every settable field and its current (valid) value,
    which is what you match against. The controller silently drops any unrecognised field
    or enum value (HTTP 200, value unchanged), so a guessed value fails invisibly; the
    verification below reports that separately while preserving the PUT response. See
    ``get_setting`` for common setting keys and their notable enum fields.

    Implements silent-no-op detection (public issue
    https://github.com/swkstudios/unifi-fabric-mcp-server/issues/17, Defect 1):
    1. GET current state before writing.
    2. If every submitted field is already satisfied by the current state, skip
       the PUT and return the GET envelope verbatim plus an additive ``_note``.
    3. Otherwise PUT, then GET again and verify the targeted fields actually
       took (excluding server-managed timestamp/metadata fields).
    4. Walk the submitted payload leaf by leaf (a nested object is descended into; a
       list or scalar is a leaf). If any requested leaf is not satisfied after the
       write AND is unchanged from the pre-state, return ``_verified: false`` listing every
       rejected leaf as a dotted path (``"radius.port"``; a top-level field is its own
       name) in ``_unverifiedFields``, with an actionable ``_verificationNote`` naming the
       leaves that were applied. A nested object with one leaf
       applied and a sibling leaf dropped is therefore reported, not passed as success.

    "Satisfied" compares a submitted nested object as a partial update: every key
    the caller sent must hold the sent value, and keys the caller did not send are
    ignored. So a partial nested write (``{"x": {"a": 1}}`` against a stored
    ``{"a": 0, "b": 2}``) that the controller applied is never reported as a
    silent no-op. The PUT response envelope is always returned verbatim (a non-object
    body whole under ``response``) plus the additive ``_verified``
    (:func:`read_after_verdict`): true only when the read-after
    confirms every compared leaf, false with ``_unverifiedFields`` when a leaf changed
    to a value other than the one sent or was rejected, and null with ``_readAfterError`` when the
    read-after failed or could not be matched (the write was still sent).

    Empty-string entries are stripped from list-valued fields before the
    idempotency comparison and the PUT, so a setting group read back with
    padded list fields round-trips cleanly.

    A field whose value is exactly the redaction mask (a ``UNIFI_REDACT_SECRETS`` read
    fed back in) is left out of the comparison and the PUT, so the stored secret is kept
    and is never reported as a rejected field; the dropped paths are listed on the result
    under ``_redactedFieldsNotSent``.

    The additive ``_``-prefixed top-level keys this server adds to read results (``_note``,
    ``_keyLabel``, ...; ``_id`` is kept) are removed from ``payload`` before the no-op check,
    the PUT and the post-write check alike: the client never sends them, so comparing them
    would report a field that was never written as "rejected" (a false silent no-op) and
    would make a get_setting result fed back in look like a change.

    Under ``dry-run policy`` the PUT returns the dry-run preview; it is returned as is and
    the post-write verification is skipped (nothing was written to verify).
    """
    validate_id(setting_key, "setting_key")
    # The server's one empty-update guard, before any request: a payload with no field to
    # change (empty, only '_' keys, only masked values, only empty objects) is refused.
    require_update_fields(
        payload, f"setting {setting_key!r} 'payload'", identity=identity_fields("update_setting")
    )
    payload = strip_empty_list_values(drop_and_note_masked_fields(strip_additive_keys(payload)))
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    url = _classic_rest(host_id, site_slug, f"/setting/{setting_key}")

    # --- pre-write snapshot ---
    pre_response = await client.get(url, key=key)
    # Classic REST wraps single settings in a one-element list.
    pre_state = _setting_state(pre_response, url)

    # Idempotent-write false-positive guard: if submitted values already
    # equal the current values, skip the PUT entirely. The controller pads
    # list fields with placeholder empty strings on read (e.g.
    # ``["8.8.8.8", "", ""]``) but ``payload`` has already had that padding
    # stripped, so the current state must be stripped the same way before
    # comparing — otherwise a genuinely-equal list field reads as "changed"
    # and skips this guard.
    # Under dry-run policy the PUT is always issued to the preview (short_circuit_no_op).
    applied = all(_satisfies(pre_state.get(k, MISSING), v) for k, v in payload.items())
    if short_circuit_no_op(client, applied):
        return with_context(pre_response, {"_note": "no change needed"})

    # --- perform the write ---
    response = await client.put(url, key=key, json=payload)
    if is_dry_run_preview(response):
        # dry-run policy: nothing was written, so there is nothing to verify.
        return response

    # --- post-write verification (the write is applied: a failing re-read is reported) ---
    async def _read_after() -> dict[str, Any]:
        return _setting_state(await client.get(url, key=key), url)

    post_state, read_error = await safe_read_after(_read_after)

    # Compare only the leaves the caller submitted, excluding top-level
    # server-managed fields that may change on every request. The walk is per leaf, not
    # per top-level field: a nested object whose one leaf was applied and whose sibling
    # leaf was silently dropped changed as a whole, yet the dropped leaf is still a
    # rejection. Both snapshots are stripped of the controller's empty-string list
    # padding so a field that differs only by that padding is not mis-flagged as a
    # rejected write (which would report a spurious "silent no-op" for a write that
    # in fact succeeded — or that was a genuine no-op on an already-correct list field).
    def _classify(post: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
        applied: list[str] = []
        rejected: list[str] = []
        unconfirmed: list[str] = []
        for path, wanted in _requested_leaves(payload):
            if path[0] in _SERVER_MANAGED_FIELDS:
                continue
            pre_v = strip_empty_list_values(_value_at(pre_state, path))
            post_v = strip_empty_list_values(_value_at(post, path))
            dotted = ".".join(path)
            if _satisfies(post_v, wanted):
                applied.append(dotted)
            elif leaf_equal(post_v, pre_v):
                rejected.append(dotted)
            else:
                # Changed, but not to the requested value: never verified.
                unconfirmed.append(dotted)
        return applied, rejected, unconfirmed

    leaves, read_error = read_after_verdict(post_state, read_error, _classify)
    if leaves is None:
        # The write was applied but the read-after failed or could not be matched: the
        # PUT response stays verbatim, verification is unknown and the reason is given.
        if isinstance(response, dict):
            return with_context(
                with_read_after_error(dict(response), read_error, additive=True),
                {VERIFIED_KEY: None},
            )
        return {"response": response, "_readAfterError": read_error, VERIFIED_KEY: None}
    applied_leaves, rejected_leaves, unconfirmed_leaves = leaves

    # Verification cannot turn an accepted upstream write into a failed tool call.
    # Preserve its response and report every mismatched leaf separately.
    unverified_leaves = rejected_leaves + unconfirmed_leaves
    verified: bool | None = False if unverified_leaves else (True if applied_leaves else None)
    if not isinstance(response, dict):
        # Keep a non-object write body whole so the verdict keys are never dropped.
        response = {"response": response}
    context: dict[str, Any] = {VERIFIED_KEY: verified}
    if unverified_leaves:
        context[UNVERIFIED_FIELDS_KEY] = unverified_leaves
    if rejected_leaves:
        applied_note = (
            f" Fields {applied_leaves!r} were applied by the same write." if applied_leaves else ""
        )
        context["_verificationNote"] = (
            f"update_setting silent no-op: setting key {setting_key!r} "
            f"rejected fields {rejected_leaves!r} -- values unchanged after write."
            f"{applied_note} "
            f"The controller silently drops values it does not recognise (most often an "
            f"invalid enum). Call get_setting(setting_key={setting_key!r}) to read the "
            f"current valid values and matching field shape before retrying."
        )
    return with_context(response, context)


def _requested_leaves(
    wanted: dict[str, Any], prefix: tuple[str, ...] = ()
) -> list[tuple[tuple[str, ...], Any]]:
    """Every leaf of a submitted payload as ``(path, value)``.

    A non-empty object is descended into; anything else (scalar, list, empty object) is a
    leaf compared whole. Paths are tuples of keys from the setting object's top level.
    """
    leaves: list[tuple[tuple[str, ...], Any]] = []
    for k, v in wanted.items():
        path = (*prefix, k)
        if isinstance(v, dict) and v:
            leaves.extend(_requested_leaves(v, path))
        else:
            leaves.append((path, v))
    return leaves


def _value_at(state: Any, path: tuple[str, ...]) -> Any:
    """The value at ``path`` in a setting object, or ``MISSING`` where the path is absent."""
    current = state
    for k in path:
        if not isinstance(current, dict) or k not in current:
            return MISSING
        current = current[k]
    return current


def _satisfies(current: Any, wanted: Any) -> bool:
    """True if ``current`` already holds every value the caller sent in ``wanted``.

    Nested objects compare as partial updates (keys the caller did not send are
    ignored); everything else compares after the controller's empty-string list
    padding is stripped from both sides, type-strictly (``leaf_equal``: ``0`` never
    satisfies ``false``, ``1`` never satisfies ``true``).
    """
    if isinstance(wanted, dict):
        if not isinstance(current, dict):
            return False
        return all(k in current and _satisfies(current[k], v) for k, v in wanted.items())
    return leaf_equal(strip_empty_list_values(current), strip_empty_list_values(wanted))


def _setting_state(response: Any, url: str) -> dict[str, Any]:
    """The setting object from a Classic REST read (``data`` is a one-element list).

    Any other shape raises with the shape received: comparing against an invented
    empty object would misreport every field as changed or rejected.
    """
    data = response.get("data") if isinstance(response, dict) else None
    setting_key = url.rsplit("/", 1)[-1]
    if (
        isinstance(data, list)
        and len(data) == 1
        and isinstance(data[0], dict)
        and data[0].get("key") == setting_key
    ):
        return cast(dict[str, Any], data[0])
    raise UniFiConnectionError(
        f"Unexpected response shape for GET {url}: expected an object whose 'data' array "
        f"holds a singleton setting object with key {setting_key!r}, got {describe_shape(response)}"
    )


# --- Dynamic DNS (Classic REST) ---


async def list_dynamic_dns(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
) -> Any:
    """List Dynamic DNS provider configurations via Classic REST /rest/dynamicdns."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, "/dynamicdns"), key=key)


async def get_dynamic_dns(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    ddns_id: str,
) -> Any:
    """Get a single Dynamic DNS config by ID via Classic REST /rest/dynamicdns."""
    validate_id(ddns_id, "ddns_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, f"/dynamicdns/{ddns_id}"), key=key)


async def update_dynamic_dns(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    ddns_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a Dynamic DNS config via Classic REST /rest/dynamicdns (id resolved first)."""
    validate_id(ddns_id, "ddns_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    record = await require_listed_record(
        client,
        _classic_rest(host_id, site_slug, "/dynamicdns"),
        ddns_id,
        key=key,
        kind="Dynamic DNS config",
        list_tool="list_dynamic_dns",
        label_fields=("host_name", "service"),
    )
    upstream_id = listed_record_id(record, "ddns_id")
    return await client.put(
        _classic_rest(host_id, site_slug, f"/dynamicdns/{upstream_id}"),
        key=key,
        json=strip_empty_list_values(addressed_body(payload, upstream_id)),
    )


# --- Port Profiles (Classic REST) ---
#
# Two id spaces name the same network (verified against the recorded /rest/networkconf
# fixture): the Network Integration API id (a UUID, ``list_networks`` data[].id, the id
# ``create_network`` returns) and the Classic REST networkconf ``_id`` (24-hex Mongo id).
# A networkconf document links them through its ``external_id`` field (= the Integration
# id). Port-profile fields (``excluded_networkconf_ids``, ``native_networkconf_id``, ...)
# hold Classic ``_id`` values, so every port-profile tool that takes or matches a network
# maps the Integration id through ``external_id`` first.
#
# D12 auto-exclusion footgun (documented UniFi behavior).
# UniFi auto-adds every newly created network to ``excluded_networkconf_ids`` of
# ALL custom-tagged port profiles (``tagged_vlan_mgmt == "custom"``), which
# silently blackholes the new VLAN at the host uplink (guest ARP to gateway
# FAILS).  The UI "Tagged VLANs" list is DERIVED — all VLAN networks minus the
# native minus the excluded — there is no separate tagged-list object.  These
# tools resolve the bare 24-hex networkconf ids to ``{id, name, vlan}`` objects, reported
# under an additive ``_resolved_networks`` key (the controller fields stay verbatim),
# against ``/rest/networkconf`` (the same id->name join the remediation runbook
# uses; port-profile ``*_networkconf_id(s)`` fields reference those documents by
# their Mongo ``_id``) so an operator can see at a glance which id IS the new
# network, and the allow_/exclude_ helpers do the whole fresh-read ->
# mutate exclusion list -> PUT cycle in one call.

_NETWORKCONF_LIST_ID_FIELDS = ("excluded_networkconf_ids",)
_NETWORKCONF_SINGLE_ID_FIELDS = ("native_networkconf_id", "voice_networkconf_id")


async def _networkconf_docs(
    client: UniFiClient,
    host_id: str,
    site_slug: str,
    *,
    key: APIKeyConfig | None,
) -> list[dict[str, Any]]:
    """The networkconf documents from Classic REST /rest/networkconf (shape-checked)."""
    path = _classic_rest(host_id, site_slug, "/networkconf")
    response = await client.get(path, key=key)
    data = _classic_records(response, f"GET {path}")
    return object_records(data, f"GET {path}")


def _name_map_from_docs(docs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """``{networkconf _id: {id, name, vlan}}`` from networkconf documents."""
    name_map: dict[str, dict[str, Any]] = {}
    for conf in object_records(docs, "networkconf name map"):
        native_id = listed_record_id(conf, "networkconf _id")
        name_map[native_id] = {"id": native_id, "name": conf.get("name"), "vlan": conf.get("vlan")}
    return name_map


async def _networkconf_name_map(
    client: UniFiClient,
    host_id: str,
    site_slug: str,
    *,
    key: APIKeyConfig | None,
) -> dict[str, dict[str, Any]]:
    """Build ``{networkconf_id: {id, name, vlan}}`` from Classic REST /rest/networkconf."""
    return _name_map_from_docs(await _networkconf_docs(client, host_id, site_slug, key=key))


def _valid_networks(docs: list[dict[str, Any]]) -> str:
    """Every network as ``name (vlan N): _id=CLASSIC_ID, id=INTEGRATION_ID`` (never truncated)."""
    return (
        "; ".join(
            f"{upstream_error_value(conf.get('name'))} "
            f"(vlan {upstream_error_value(conf.get('vlan'))}): "
            f"_id={upstream_error_value(conf.get('_id'))}, "
            f"id={upstream_error_value(conf.get('external_id'))}"
            for conf in docs
        )
        or "(none)"
    )


def _match_networkconf(docs: list[dict[str, Any]], network_id: str) -> dict[str, Any] | None:
    """The networkconf document named by either id space (Classic ``_id`` or Integration id)."""
    conf = find_by_id(
        object_records(docs, "networkconf resolution"), network_id, "_id", "external_id"
    )
    if conf is not None:
        listed_record_id(conf, "networkconf _id")
    return conf


def _classic_networkconf_id(
    docs: list[dict[str, Any]],
    field: str,
    value: str,
    stored: set[str],
    malformed: dict[str, str] | None = None,
) -> str:
    """The networkconf ``_id`` a caller's ``field`` value names: an ``_id`` as is, an
    Integration id (``external_id``) or a unique network name mapped to its ``_id``. A value
    the profile already stores (``stored``, e.g. a stale reference) passes unchanged. When
    ``field`` is unresolvable and the profile stores a non-string there (``malformed``,
    field -> shape), the error says so."""
    conf = _match_networkconf(docs, value)
    if conf is None and value in stored:
        return value
    if conf is None:
        named = name_matches(docs, value, lambda d: d.get("name"))
        if len({id(d) for d in named}) > 1:
            raise ValueError(
                f"{field} value {value!r} matches {len(named)} networks by name; pass its "
                f"_id or id. valid: {_valid_networks(docs)}."
            )
        conf = named[0] if named else None
    if conf is None:
        shape = (malformed or {}).get(field)
        stored_note = (
            f" The stored port profile holds {shape} in {field}, which cannot be kept as a "
            "reference."
            if shape is not None
            else ""
        )
        raise ValueError(
            f"{field} value {value!r} is neither a networkconf _id, a network id nor a network "
            f"name on this site; valid: {_valid_networks(docs)}. Get ids from list_networks "
            f"(data[].id) or list_port_profiles (_resolved_networks).{stored_note}"
        )
    return listed_record_id(conf, "networkconf _id")


async def _with_classic_networkconf_ids(
    client: UniFiClient,
    host_id: str,
    site_slug: str,
    payload: dict[str, Any],
    *,
    key: APIKeyConfig | None,
    stored: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """``payload`` with every networkconf id field value mapped to its Classic ``_id``.

    Port-profile fields hold networkconf ``_id`` values, but a caller usually has the
    Integration id from ``list_networks``. When the payload carries any of those fields,
    /rest/networkconf is read once and each non-empty string value (each list element for
    ``excluded_networkconf_ids``) is mapped through ``_match_networkconf``; an unknown value
    raises before any write. A value the ``stored`` record (the profile being updated)
    already holds in one of those fields passes unchanged, so a read result with a stale
    reference round-trips. A non-string stored value (malformed) is never rewritten and never
    blocks the call: it only shows in the error when the payload's own value for that same
    field is unresolvable, so an unrelated malformed field passes through and a payload that
    sets the field to a valid id repairs it. Empty values, non-string values and every other
    key are unchanged, and a payload without those fields is returned as is with no read."""
    fields = (*_NETWORKCONF_SINGLE_ID_FIELDS, *_NETWORKCONF_LIST_ID_FIELDS)
    if not any(field in payload for field in fields):
        return payload
    held: set[str] = set()
    malformed: dict[str, str] = {}
    for field in fields:
        value = (stored or {}).get(field)
        for held_value in value if isinstance(value, list) else [value]:
            if held_value is None or held_value == "":
                continue  # the stored profile does not set this field
            if isinstance(held_value, str):
                held.add(held_value)
            else:
                # Pass-through: a malformed stored value cannot be kept as a reference and is
                # not rewritten; it only matters if the payload needs this field resolved.
                malformed[field] = describe_shape(held_value)
    docs = await _networkconf_docs(client, host_id, site_slug, key=key)
    mapped = dict(payload)
    for field in _NETWORKCONF_SINGLE_ID_FIELDS:
        value = mapped.get(field)
        if isinstance(value, str) and value:
            mapped[field] = _classic_networkconf_id(docs, field, value, held, malformed)
    for field in _NETWORKCONF_LIST_ID_FIELDS:
        values = mapped.get(field)
        if isinstance(values, list):
            mapped[field] = [
                _classic_networkconf_id(docs, field, v, held, malformed)
                if isinstance(v, str) and v
                else v
                for v in values
            ]
    return mapped


#: Additive key carrying the id -> {id, name, vlan} resolution for a port profile. It is
#: added NEXT TO the controller's fields (which stay byte-identical, bare ids included)
#: and is stripped from any update_port_profile payload before the write.
RESOLVED_NETWORKS_KEY = "_resolved_networks"


def _render_networkconf_id(nid: Any, name_map: dict[str, dict[str, Any]]) -> Any:
    """Render a single bare networkconf id as ``{id, name, vlan}``.

    An id with no match in the map (e.g. a stale reference) still renders as an
    object with ``name``/``vlan`` = ``None``.
    """
    entry = name_map.get(nid)
    if entry is not None:
        return dict(entry)
    return {"id": nid, "name": None, "vlan": None}


def _resolve_profile_networkconf(profile: Any, name_map: dict[str, dict[str, Any]]) -> Any:
    """Return the port profile unchanged plus an additive ``_resolved_networks`` key.

    The controller's own fields (``excluded_networkconf_ids``, ``native_networkconf_id``,
    ``voice_networkconf_id``) are never rewritten; the name/VLAN of each id they
    reference is reported under ``_resolved_networks`` instead. Non-dict inputs pass
    through unchanged.
    """
    if not isinstance(profile, dict):
        return profile
    resolved: dict[str, Any] = {}
    for field in _NETWORKCONF_LIST_ID_FIELDS:
        vals = profile.get(field)
        if isinstance(vals, list):
            resolved[field] = [
                _render_networkconf_id(v, name_map) for v in vals if isinstance(v, str) and v
            ]
    for field in _NETWORKCONF_SINGLE_ID_FIELDS:
        val = profile.get(field)
        if isinstance(val, str) and val:
            resolved[field] = _render_networkconf_id(val, name_map)
    if not resolved:
        return profile
    return with_context(profile, {RESOLVED_NETWORKS_KEY: resolved})


RESOLVED_NETWORKS_ERROR_KEY = "_resolvedNetworksError"


async def _name_map_or_error(
    client: UniFiClient, host_id: str, site_slug: str, *, key: APIKeyConfig | None
) -> tuple[dict[str, dict[str, Any]], str | None]:
    """The networkconf name map, or ``({}, reason)`` when it cannot be read.

    The name resolution is an additive convenience: its failure is reported next to the
    controller's data (``_resolvedNetworksError``) and never fails the read — or a
    write that the controller already applied.
    """
    name_map, error = await safe_read_after(
        lambda: _networkconf_name_map(client, host_id, site_slug, key=key)
    )
    return (name_map or {}), error


def _with_resolution(data: Any, name_map: dict[str, dict[str, Any]], error: str | None) -> Any:
    if error is None:
        return _resolve_profiles(data, name_map)
    if isinstance(data, list):
        return [
            with_context(p, {RESOLVED_NETWORKS_ERROR_KEY: error}) if isinstance(p, dict) else p
            for p in data
        ]
    if isinstance(data, dict):
        return with_context(data, {RESOLVED_NETWORKS_ERROR_KEY: error})
    return data


def _envelope_with_resolution(
    response: Any, name_map: dict[str, dict[str, Any]], error: str | None
) -> Any:
    """The Classic envelope verbatim, each ``data`` profile carrying the additive resolution.

    A body that is not a ``{..., "data": [...]}`` envelope is returned unchanged.
    """
    if isinstance(response, dict) and isinstance(response.get("data"), list):
        return {**response, "data": _with_resolution(response["data"], name_map, error)}
    return response


def _without_resolved_networks(payload: dict[str, Any]) -> dict[str, Any]:
    """Drop the additive keys a read adds so a read result round-trips safely."""
    return {
        k: v
        for k, v in payload.items()
        if k not in (RESOLVED_NETWORKS_KEY, RESOLVED_NETWORKS_ERROR_KEY)
    }


def _resolve_profiles(data: Any, name_map: dict[str, dict[str, Any]]) -> Any:
    if isinstance(data, list):
        return [_resolve_profile_networkconf(p, name_map) for p in data]
    return _resolve_profile_networkconf(data, name_map)


def _derive_tagged_networks(
    profile: dict[str, Any], name_map: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Compute the DERIVED tagged-VLAN set for a profile: every VLAN network
    (``vlan`` truthy) minus the native minus the excluded, rendered with names.
    Mirrors how the UniFi UI derives its "Tagged VLANs" list."""
    native = profile.get("native_networkconf_id")
    excluded = {v for v in consumed_string_array(profile, "excluded_networkconf_ids") if v}
    tagged: list[dict[str, Any]] = []
    for nid, entry in name_map.items():
        if not entry.get("vlan"):
            continue
        if nid == native or nid in excluded:
            continue
        tagged.append(dict(entry))
    tagged.sort(key=lambda e: e.get("vlan") or 0)
    return tagged


async def list_port_profiles(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List switch port profiles via Classic REST /rest/portconf.

    Returns the controller's ``{meta, data}`` envelope; profiles are verbatim. Each one
    that references networks also gets an additive ``_resolved_networks`` key mapping its
    networkconf id fields (``excluded_networkconf_ids``, ``native_networkconf_id``,
    ``voice_networkconf_id``) to ``{id, name, vlan}`` objects resolved against
    /rest/networkconf, so the Network auto-exclusion footgun (a bare id that is silently the
    newest VLAN) is legible.
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    path = _classic_rest(host_id, site_slug, "/portconf")
    response = await client.get(path, key=key)
    _classic_records(response, f"GET {path}")
    name_map, error = await _name_map_or_error(client, host_id, site_slug, key=key)
    return _envelope_with_resolution(response, name_map, error)


async def get_port_profile(
    client: UniFiClient, registry: Registry, host: str, site: str, profile_id: str
) -> Any:
    """Get a single switch port profile by ID via Classic REST /rest/portconf.

    The profile is returned verbatim plus the additive ``_resolved_networks`` key (see
    ``list_port_profiles``)."""
    validate_id(profile_id, "profile_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    path = _classic_rest(host_id, site_slug, f"/portconf/{profile_id}")
    response = await client.get(path, key=key)
    _classic_records(response, f"GET {path}")
    name_map, error = await _name_map_or_error(client, host_id, site_slug, key=key)
    return _envelope_with_resolution(response, name_map, error)


async def update_port_profile(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    profile_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a switch port profile by ID via Classic REST /rest/portconf.

    The write ``payload`` is sent as given, minus the additive ``_resolved_networks``
    key a read adds (so a get_port_profile result round-trips safely), except that each
    networkconf id field value (``native_networkconf_id``, ``voice_networkconf_id``,
    ``excluded_networkconf_ids``) is mapped to its Classic ``_id`` (an Integration id from
    ``list_networks`` or a unique network name converts; a value the profile already holds
    passes unchanged; any other unknown value fails listing every network, and no PUT is
    sent). The returned
    PUT envelope is verbatim, each profile plus ``_resolved_networks`` (see
    ``list_port_profiles``). The id is resolved in the /rest/portconf list first: an
    unknown id fails listing every profile, and no PUT is sent."""
    validate_id(profile_id, "profile_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    record = await require_listed_record(
        client,
        _classic_rest(host_id, site_slug, "/portconf"),
        profile_id,
        key=key,
        kind="Port profile",
        list_tool="list_port_profiles",
    )
    upstream_id = listed_record_id(record, "profile_id")
    body = await _with_classic_networkconf_ids(
        client, host_id, site_slug, _without_resolved_networks(payload), key=key, stored=record
    )
    response = await client.put(
        _classic_rest(host_id, site_slug, f"/portconf/{upstream_id}"),
        key=key,
        json=strip_empty_list_values(addressed_body(body, upstream_id)),
    )
    if is_dry_run_preview(response):
        # dry-run policy: nothing was written; the bare preview, no name-resolution read.
        return response
    # The write is applied at this point; a failed name lookup must not fail the call
    # (the server's one safe read-after: readAfterError says why it is missing).
    name_map, error = await _name_map_or_error(client, host_id, site_slug, key=key)
    envelope = _envelope_with_resolution(response, name_map, error)
    if isinstance(envelope, dict):
        envelope = with_read_after_error(dict(envelope), error, additive=True)
    return envelope


async def _port_profile_for_write(
    client: UniFiClient, host_id: str, site_slug: str, profile_id: str, key: APIKeyConfig | None
) -> dict[str, Any]:
    """Fresh-read the port profile ``profile_id`` (Classic REST) before a write.

    The profile is the /rest/portconf list entry whose ``_id`` is ``profile_id`` (one
    read; the Classic list carries every profile in full). An unexpected body raises with
    the shape received; an unknown id fails listing every profile (name and ``_id``) and
    no write is sent. A single record answered for another id is never written back
    under ``profile_id``.
    """
    return await require_listed_record(
        client,
        _classic_rest(host_id, site_slug, "/portconf"),
        profile_id,
        key=key,
        kind="Port profile",
        list_tool="list_port_profiles",
    )


async def _mutate_port_profile_exclusion(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    profile_id: str,
    network_id: str,
    *,
    exclude: bool,
    confirm: bool = False,
) -> dict[str, Any]:
    """Add/remove a network from a port profile's exclusion list.

    ``network_id`` may be either id of the network: the Classic networkconf ``_id`` or the
    Network Integration id (``list_networks`` data[].id / the id ``create_network``
    returns), which is mapped to its ``_id`` through the networkconf ``external_id``. It is
    validated against /rest/networkconf BEFORE the write; an unknown id fails listing every
    valid network (name, vlan, both ids).

    The fresh-read and PUT cycle is not atomic against concurrent edits. Fresh-reads the
    profile, mutates ``excluded_networkconf_ids``, PUTs the whole object
    back, and returns the controller's PUT envelope verbatim (each profile carrying the
    additive ``_resolved_networks``) plus the additive ``_tagged_networks`` (the derived
    tagged-VLAN set) and ``_network`` (the networkconf the id resolved to). Under
    ``dry-run policy`` the bare dry-run preview is returned (none of those additive keys,
    and no name-resolution read after the suppressed PUT).

    This is a live write to a SHARED port profile — the exclusion list affects
    every switch port using the profile. The ``confirm`` argument is accepted for
    compatibility and no longer required.
    """
    validate_id(profile_id, "profile_id")
    validate_id(network_id, "network_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    docs = await _networkconf_docs(client, host_id, site_slug, key=key)
    conf = _match_networkconf(docs, network_id)
    if conf is None:
        raise ValueError(
            f"network {network_id!r} is neither a networkconf _id nor a network id on this "
            f"site; valid: {_valid_networks(docs)}. Get ids from list_networks (data[].id) or "
            "list_port_profiles (_resolved_networks)."
        )
    networkconf_id = conf["_id"]
    profile = await _port_profile_for_write(client, host_id, site_slug, profile_id, key)
    upstream_id = listed_record_id(profile, "profile_id")
    excluded = [v for v in consumed_string_array(profile, "excluded_networkconf_ids") if v]
    if exclude:
        if networkconf_id not in excluded:
            excluded.append(networkconf_id)
    else:
        excluded = [v for v in excluded if v != networkconf_id]
    write_payload = _without_resolved_networks(profile)
    write_payload["excluded_networkconf_ids"] = excluded
    response = await client.put(
        _classic_rest(host_id, site_slug, f"/portconf/{upstream_id}"),
        key=key,
        json=strip_empty_list_values(write_payload),
    )
    if is_dry_run_preview(response):
        # dry-run policy: nothing was written, so there is no profile to derive
        # _tagged_networks from and no reason for the name-resolution read: the bare
        # preview, as every other write returns it.
        return response
    # Only the documented list envelope can be enriched. Other successful bodies
    # remain verbatim, and do not trigger an unnecessary post-write lookup.
    if not isinstance(response, dict) or not isinstance(response.get("data"), list):
        return response
    # The write is applied at this point; a failed name lookup must not fail the call.
    name_map, error = await _name_map_or_error(client, host_id, site_slug, key=key)
    resp_data = response["data"]
    updated = next(
        (p for p in resp_data if isinstance(p, dict) and same_id(upstream_id, p.get("_id"))),
        None,
    )
    result: dict[str, Any] = dict(_envelope_with_resolution(response, name_map, error))
    context: dict[str, Any] = {}
    if updated is None:
        # The controller did not return the profile: report that, never stand the
        # write payload in for the controller's response.
        context["_profileNote"] = (
            "the controller's PUT response carried no profile; _tagged_networks is derived "
            "from the payload that was written"
        )
        basis = write_payload
    else:
        basis = updated
    context["_tagged_networks"] = _derive_tagged_networks(basis, name_map)
    context["_network"] = {
        "_id": networkconf_id,
        "id": conf.get("external_id"),
        "name": conf.get("name"),
        "vlan": conf.get("vlan"),
    }
    if error is not None:
        context[RESOLVED_NETWORKS_ERROR_KEY] = error
    return with_read_after_error(with_context(result, context), error, additive=True)


async def allow_network_on_port_profile(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    profile_id: str,
    network_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Allow (un-exclude) a network on a port profile after auto-exclusion.

    Removes the network (either id; see ``_mutate_port_profile_exclusion``) from the
    profile's ``excluded_networkconf_ids`` via a fresh-read -> PUT cycle and returns the
    PUT envelope plus ``_tagged_networks``. This is the remediation for the
    auto-exclusion warning emitted by ``create_network``.

    Live write to a shared port profile; affects every switch port using it.
    """
    return await _mutate_port_profile_exclusion(
        client, registry, host, site, profile_id, network_id, exclude=False, confirm=confirm
    )


async def exclude_network_on_port_profile(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    profile_id: str,
    network_id: str,
    confirm: bool = False,
) -> dict[str, Any]:
    """Exclude (untag) a network on a port profile.

    Adds the network (either id; see ``_mutate_port_profile_exclusion``) to the profile's
    ``excluded_networkconf_ids`` via a fresh-read -> PUT cycle. Inverse of
    ``allow_network_on_port_profile``.

    Live write to a shared port profile; affects every switch port using it."""
    return await _mutate_port_profile_exclusion(
        client, registry, host, site, profile_id, network_id, exclude=True, confirm=confirm
    )


async def annotate_auto_exclusions(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    created: Any,
) -> Any:
    """Append a Network auto-exclusion warning to a ``create_network`` response (additive
    ``_warnings`` key; the created object is otherwise verbatim; a non-object body is
    returned whole under ``response``).

    ``create_network`` returns the Network Integration id (``id``, a UUID), while
    port-profile ``excluded_networkconf_ids`` hold Classic networkconf ``_id`` values. The
    new network's ``_id`` is found through /rest/networkconf (the document whose
    ``external_id`` equals the created ``id``); then /rest/portconf is fresh-read and every
    custom-tagged profile (``tagged_vlan_mgmt == "custom"``) that already auto-excluded
    that ``_id`` is listed, so the follow-up ``allow_network_on_port_profile`` step cannot
    be missed. If the check itself cannot run (including when no networkconf document
    links to the created id), a ``D12_CHECK_FAILED`` warning carrying the reason is
    appended instead (the created network is never hidden).
    """
    if not isinstance(created, dict):
        # A non-object create body is kept whole under ``response``; the check cannot run
        # (there is no id to read), and the warning says so beside it.
        return _with_warning(
            {"response": created},
            {
                "code": "D12_CHECK_FAILED",
                "message": (
                    "The network was created, but the create response is not an object, so "
                    "its id cannot be read and the port-profile auto-exclusion check could "
                    "not run. Run list_port_profiles and look for this network in each "
                    "profile's _resolved_networks.excluded_networkconf_ids."
                ),
            },
        )
    new_id = created.get("id") or created.get("_id")
    if not new_id:
        return created

    def _check_failed(reason: str) -> dict[str, Any]:
        # The network WAS created; report that the follow-up check could not run (and
        # why) instead of silently returning as if no profile were affected.
        return _with_warning(
            created,
            {
                "code": "D12_CHECK_FAILED",
                "message": (
                    "The network was created, but the port-profile auto-exclusion check "
                    f"could not run: {reason}. Run list_port_profiles and look for this "
                    "network in each profile's _resolved_networks.excluded_networkconf_ids."
                ),
            },
        )

    try:
        key = await registry.resolve_key_for_host(host)
        host_id = await registry.resolve_host_id(host, key=key)
        site_slug = await registry.resolve_site_slug(site, host_id, key=key)
        docs = await _networkconf_docs(client, host_id, site_slug, key=key)
        conf = _match_networkconf(docs, str(new_id))
        if conf is None:
            return _check_failed(
                f"no /rest/networkconf document links to network id {new_id!r} (external_id or _id)"
            )
        networkconf_id = conf["_id"]
        portconf_path = _classic_rest(host_id, site_slug, "/portconf")
        profiles = _classic_records(
            await client.get(portconf_path, key=key), f"GET {portconf_path}"
        )
        for profile in profiles:
            if profile.get("tagged_vlan_mgmt") == "custom":
                consumed_string_array(profile, "excluded_networkconf_ids")
    except Exception as exc:
        # The network is created; the follow-up reads are its read-after (one shape for a
        # failed read-after: readAfterError, beside the D12 warning).
        reason = f"{type(exc).__name__}: {exc}"
        checked = _check_failed(reason)
        if isinstance(checked, dict):
            return with_read_after_error(checked, reason, additive=True)
        return checked
    auto_excluded: list[dict[str, Any]] = []
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        if profile.get("tagged_vlan_mgmt") != "custom":
            continue
        if networkconf_id in consumed_string_array(profile, "excluded_networkconf_ids"):
            auto_excluded.append({"id": profile.get("_id"), "name": profile.get("name")})
    if not auto_excluded:
        return created
    vlan = created.get("vlanId", created.get("vlan"))
    names = ", ".join(str(entry.get("name")) for entry in auto_excluded)
    warning = {
        "code": "D12_AUTO_EXCLUSION",
        "message": (
            f"UniFi auto-excluded this new network (vlan {vlan}, networkconf _id "
            f"{networkconf_id}) from {len(auto_excluded)} custom-tagged port profile(s): "
            f"{names}. This blackholes the VLAN at the host uplink (guest->gateway ARP will "
            "FAIL). Run allow_network_on_port_profile(profile_id, network_id) for each "
            "profile to restore tagging; network_id may be this network's id or its "
            "networkconf _id."
        ),
        "profiles": auto_excluded,
        "networkconf_id": networkconf_id,
        "remediation_tool": "allow_network_on_port_profile",
    }
    return _with_warning(created, warning)


def _with_warning(created: dict[str, Any], warning: dict[str, Any]) -> dict[str, Any]:
    """The created object verbatim plus server warning context, preserving collisions."""
    return with_context(created, {"_warnings": [warning]})


# --- Routing Table (Classic REST) ---


async def list_routing_entries(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """List static routing table entries via Classic REST /rest/routing."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, "/routing"), key=key)


# --- WLAN Configs (Classic REST) ---


async def list_wlan_configs(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
) -> Any:
    """List per-SSID WLAN configurations via Classic REST /rest/wlanconf."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, "/wlanconf"), key=key)


async def get_wlan_config(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    wlan_id: str,
) -> Any:
    """Get a single WLAN configuration by ID via Classic REST /rest/wlanconf."""
    validate_id(wlan_id, "wlan_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, f"/wlanconf/{wlan_id}"), key=key)


async def update_wlan_config(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    wlan_id: str,
    payload: dict[str, Any],
) -> Any:
    """Update a WLAN configuration via Classic REST /rest/wlanconf (id resolved first)."""
    validate_id(wlan_id, "wlan_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    record = await require_listed_record(
        client,
        _classic_rest(host_id, site_slug, "/wlanconf"),
        wlan_id,
        key=key,
        kind="WLAN configuration",
        list_tool="list_wlan_configs",
    )
    upstream_id = listed_record_id(record, "wlan_id")
    return await client.put(
        _classic_rest(host_id, site_slug, f"/wlanconf/{upstream_id}"),
        key=key,
        json=strip_empty_list_values(addressed_body(payload, upstream_id)),
    )


# --- WLAN Groups (Classic REST) ---


async def list_wlan_groups(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List WLAN group assignments via Classic REST /rest/wlangroup."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, "/wlangroup"), key=key)


async def get_wlan_group(
    client: UniFiClient, registry: Registry, host: str, site: str, group_id: str
) -> Any:
    """Get a single WLAN group by ID from the Classic REST /rest/wlangroup collection.

    The controller does not serve ``GET /rest/wlangroup/{id}``: it answers HTTP 400
    ``api.err.InvalidObject`` for every id, including the built-in Default group that
    the collection route lists (verified live on Network 11.0.81 with the Default
    group's ``_id`` and with arbitrary ids, while every other classic
    ``rest/<collection>/{id}`` getter answers 200). The supported read is the
    collection route, so this fetches ``GET /rest/wlangroup`` and returns that envelope
    with ``data`` narrowed to the entry whose ``_id`` equals ``group_id`` — the same
    ``{meta, data: [group]}`` shape a classic by-id GET returns. An unknown id fails
    listing the valid groups (name and ``_id``). The matching entry is returned unchanged.
    """
    validate_id(group_id, "group_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    path = _classic_rest(host_id, site_slug, "/wlangroup")
    response = await client.get(path, key=key)
    data = _classic_records(response, f"GET {path}")
    records = object_records(data, f"GET {path}")
    group = find_by_id(records, group_id, "_id")
    matches = [group] if group is not None else []
    if not matches:
        valid = ", ".join(
            f"{upstream_error_value(g.get('name'), client)} "
            f"({upstream_error_value(g.get('_id'), client)})"
            for g in data
            if isinstance(g, dict)
        )
        raise ValueError(
            f"WLAN group {group_id!r} not found; valid: {valid or '(none)'}. "
            "Get ids from list_wlan_groups (_id)."
        )
    return {**response, "data": matches}


# --- Channel Plan (Classic REST) ---


async def get_channel_plan(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """Get RF channel assignments and DFS status via Classic REST /rest/channelplan."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    # Verbatim, including an empty data array (no channel plan stored on the controller).
    return await client.get(_classic_rest(host_id, site_slug, "/channelplan"), key=key)


# --- Rogue APs (Classic Stat) ---


async def list_rogue_aps(
    client: UniFiClient, registry: Registry, host: str, site: str, rogue_only: bool = False
) -> Any:
    """List neighboring APs via Classic REST stat /stat/rogueap.

    Returns the controller's ``{meta, data}`` envelope verbatim; with ``rogue_only`` the
    envelope's ``data`` is narrowed to the entries flagged ``is_rogue`` (an unexpected
    body then raises with the shape received).
    """
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    path = _classic_stat(host_id, site_slug, "/rogueap")
    response = await client.get(path, key=key)
    if not rogue_only:
        return response
    data = _classic_records(response, f"GET {path}")
    return {**response, "data": [ap for ap in data if isinstance(ap, dict) and ap.get("is_rogue")]}


# --- Classic Firewall Rules (Classic REST) ---


async def list_firewall_rules(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List classic L3/L4 firewall rules via Classic REST /rest/firewallrule."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, "/firewallrule"), key=key)


async def create_firewall_rule(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    rule: dict[str, Any],
) -> Any:
    """Create a classic L3/L4 firewall rule through the Site Manager EA route.

    The private API publishes no fixed request schema. All supplied fields are forwarded
    unchanged so the controller remains authoritative for their contents.
    """
    if not isinstance(rule, dict):
        raise ValueError("create_firewall_rule requires a JSON object")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_ea_site_id(site, host_id=host_id, key=key)
    validate_id(site_id, "site_id")
    return await client.post(f"/ea/sites/{site_id}/rest/firewallrule", key=key, json=rule)


async def get_firewall_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule_id: str
) -> Any:
    """Get a single classic firewall rule by ID via Classic REST /rest/firewallrule."""
    validate_id(rule_id, "rule_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, f"/firewallrule/{rule_id}"), key=key)


# --- Firewall Groups (Classic REST) ---


async def list_firewall_groups(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """List firewall groups (IP/port sets used in rules) via Classic REST /rest/firewallgroup."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, "/firewallgroup"), key=key)


async def get_firewall_group(
    client: UniFiClient, registry: Registry, host: str, site: str, group_id: str
) -> Any:
    """Get a single firewall group by ID via Classic REST /rest/firewallgroup."""
    validate_id(group_id, "group_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(
        _classic_rest(host_id, site_slug, f"/firewallgroup/{group_id}"), key=key
    )


# --- RADIUS Accounts (Classic REST) ---


async def list_accounts(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
) -> Any:
    """List local RADIUS user accounts via Classic REST /rest/account."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, "/account"), key=key)


async def get_account(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    account_id: str,
) -> Any:
    """Get a single RADIUS account by ID via Classic REST /rest/account."""
    validate_id(account_id, "account_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, f"/account/{account_id}"), key=key)


# --- Hotspot Packages (Classic REST) ---


async def list_hotspot_packages(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """List guest portal billing packages via Classic REST /rest/hotspotpackage."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, "/hotspotpackage"), key=key)


async def get_hotspot_package(
    client: UniFiClient, registry: Registry, host: str, site: str, package_id: str
) -> Any:
    """Get a single hotspot billing package by ID via Classic REST /rest/hotspotpackage."""
    validate_id(package_id, "package_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(
        _classic_rest(host_id, site_slug, f"/hotspotpackage/{package_id}"), key=key
    )


# --- Scheduled Tasks (Classic REST) ---


async def list_scheduled_tasks(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """List scheduled tasks (firmware upgrades, speed tests) via Classic REST /rest/scheduletask."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, "/scheduletask"), key=key)


async def get_scheduled_task(
    client: UniFiClient, registry: Registry, host: str, site: str, task_id: str
) -> Any:
    """Get a single scheduled task by ID via Classic REST /rest/scheduletask."""
    validate_id(task_id, "task_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return await client.get(_classic_rest(host_id, site_slug, f"/scheduletask/{task_id}"), key=key)


# --- DPI Categories ---


async def list_dpi_categories(
    client: UniFiClient,
    registry: Registry,
    host: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List DPI app categories available for traffic rules.

    DPI data is host-level (not site-scoped); the site parameter is ignored.
    Drains all pages by default; pass offset/limit for a single manual page. A
    capped drain is flagged incomplete rather than truncated silently.
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    return await _drain_offset_list(
        client,
        _proxy(host_id, "/dpi/categories"),
        key=key,
        offset=offset,
        limit=limit,
        filter=filter,
    )


# --- DPI Applications ---


async def list_dpi_applications(
    client: UniFiClient,
    registry: Registry,
    host: str,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List DPI applications available for traffic rules, grouped by category.

    DPI data is host-level (not site-scoped); the site parameter is ignored.
    Drains all pages by default; pass offset/limit for a single manual page. A
    capped drain is flagged incomplete rather than truncated silently.
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    return await _drain_offset_list(
        client,
        _proxy(host_id, "/dpi/applications"),
        key=key,
        offset=offset,
        limit=limit,
        filter=filter,
    )


# Tool modules the wrappers below delegate to, imported after this module's
# own definitions so a module importing from this one never sees it half-built.
from . import network_services_proxy  # noqa: E402


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the network_services_proxy tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_dns_policies(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all DNS policies for a site.

        Returns {data, totalCount}: every page is drained; data holds the DNS policy records verbatim
        and totalCount is the upstream total (null when none was reported). The first page's other
        envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
        drain stopped short.

        DNS policies are offset-paginated (native default page size 25); by default every
        page is drained and the complete list is returned as {data, totalCount}. Pass
        offset alone for a single manual page. A capped drain is flagged incomplete.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `domain.like('*example*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `type.eq('A_RECORD')`."""
        client, registry = deps_fn()
        return await network_services_proxy.list_dns_policies(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_dns_policy(
        host: str,
        site: str,
        policy: dict[str, Any],
    ) -> Any:
        """Create a new DNS policy on a site.

        Returns the upstream response body verbatim: the created DNS policy object the API answers with
        (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params (query parameters), body}} instead).

        Validated locally before the request (a missing field raises ValueError naming it):
        ``type`` — the discriminator the controller validates first (verified live: an empty
        body is rejected with ``Missing $.type value``). The remaining fields are type-specific
        and enforced by the controller.

        Request body (Network 11.0.97, POST /v1/sites/{siteId}/dns/policies (createDnsPolicy); schema
        "Create or update DNS policy") is passed in `policy`. Required keys — enabled, type.
        - enabled: boolean
        - type: string
        Variants by `type` — AAAA_RECORD requires domain, enabled, ipv6Address, ttlSeconds, type;
        A_RECORD requires domain, enabled, ipv4Address, ttlSeconds, type; CNAME_RECORD requires domain,
        enabled, targetDomain, ttlSeconds, type; FORWARD_DOMAIN requires domain, enabled, ipAddress,
        type; MX_RECORD requires domain, enabled, mailServerDomain, priority, type; SRV_RECORD requires
        domain, enabled, port, priority, protocol, serverDomain, service, weight, type; TXT_RECORD
        requires domain, enabled, text, type.

        Example call (create_dns_policy):
            {
              "host": "my-console",
              "site": "Default",
              "policy": {
                "type": "AAAA_RECORD",
                "domain": "example.com",
                "enabled": true,
                "ipv6Address": "cafe::babe",
                "ttlSeconds": 14400
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy: Full object to create; spec Create or update DNS policy. Required: enabled, type.
                'type' selects variant:
                AAAA_RECORD|A_RECORD|CNAME_RECORD|FORWARD_DOMAIN|MX_RECORD|SRV_RECORD|TXT_RECORD.
        """
        client, registry = deps_fn()
        return await network_services_proxy.create_dns_policy(client, registry, host, site, policy)

    @mcp.tool(annotations=READ_ONLY)
    async def get_dns_policy(
        host: str,
        site: str,
        policy_id: str,
    ) -> Any:
        """Get a single DNS policy by ID.

        Returns: the DNS policy object, verbatim. To change it, edit it and pass it as `policy` to
        update_dns_policy.

        Example call (get_dns_policy):
            {
              "host": "my-console",
              "site": "Default",
              "policy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy_id: DNS policy UUID. Get it from list_dns_policies (data[].id). Network-app UUID —
                not a Protect id.
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_dns_policy(client, registry, host, site, policy_id)

    @mcp.tool(annotations=WRITE)
    async def update_dns_policy(
        host: str,
        site: str,
        policy_id: str,
        policy: dict[str, Any],
    ) -> Any:
        """Update a DNS policy by ID.

        Returns the upstream response body verbatim: the updated DNS policy object the API answers with
        (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params (query parameters), body}} instead).

        Request body (Network 11.0.97, PUT /v1/sites/{siteId}/dns/policies/{dnsPolicyId}
        (updateDnsPolicy); schema "Create or update DNS policy") is passed in `policy`. Required keys —
        enabled, type.
        - enabled: boolean
        - type: string
        Variants by `type` — AAAA_RECORD requires domain, enabled, ipv6Address, ttlSeconds, type;
        A_RECORD requires domain, enabled, ipv4Address, ttlSeconds, type; CNAME_RECORD requires domain,
        enabled, targetDomain, ttlSeconds, type; FORWARD_DOMAIN requires domain, enabled, ipAddress,
        type; MX_RECORD requires domain, enabled, mailServerDomain, priority, type; SRV_RECORD requires
        domain, enabled, port, priority, protocol, serverDomain, service, weight, type; TXT_RECORD
        requires domain, enabled, text, type.

        Example call (update_dns_policy):
            {
              "host": "my-console",
              "site": "Default",
              "policy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "policy": {
                "type": "AAAA_RECORD",
                "domain": "example.com",
                "enabled": true,
                "ipv6Address": "cafe::babe",
                "ttlSeconds": 14400
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy_id: DNS policy UUID. Get it from list_dns_policies (data[].id). Network-app UUID —
                not a Protect id.
            policy: FULL replacement object (PUT; omitted fields reset); spec Create or update DNS
                policy. Required: enabled, type.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_dns_policy(
            client, registry, host, site, policy_id, policy
        )

    @mcp.tool(annotations=WRITE)
    async def delete_dns_policy(
        host: str,
        site: str,
        policy_id: str,
    ) -> dict[str, Any]:
        """Delete a DNS policy.

        Consequence: the record or forwarding rule stops being served immediately; there is no undo.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_dns_policy):
            {
              "host": "my-console",
              "site": "Default",
              "policy_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            policy_id: DNS policy UUID. Get it from list_dns_policies (data[].id). Network-app UUID —
                not a Protect id.
        """
        client, registry = deps_fn()
        response = await network_services_proxy.delete_dns_policy(
            client, registry, host, site, policy_id
        )
        return deletion_result(f"DNS policy {policy_id} deleted.", response)

    # --- Traffic Matching List Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_traffic_matching_lists(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all traffic matching lists for a site.

        Returns {data, totalCount} with every page drained (the API pages at 25 by default).
        Pass offset alone to fetch a single manual page (native envelope preserved).

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `name.eq('Business Apps')`."""
        client, registry = deps_fn()
        return await network_services_proxy.list_traffic_matching_lists(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_traffic_matching_list(
        host: str,
        site: str,
        traffic_list: dict[str, Any],
    ) -> Any:
        """Create a new traffic matching list on a site.

        Returns the upstream response body verbatim: the created traffic matching list object the API
        answers with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent:
        false, message, preview: {method, path, params (query parameters), body}} instead).

        Validated locally before the request (a missing field raises ValueError naming it):
        a top-level ``type`` — the discriminator the controller validates first (verified live:
        an empty body is rejected with ``Missing $.type value``; observed value: 'PORTS').

        Request body (Network 11.0.97, POST /v1/sites/{siteId}/traffic-matching-lists
        (createTrafficMatchingList); schema "Create or update traffic matching list") is passed in
        `traffic_list`. Required keys — name, type.
        - name: string
        - type: string
        Variants by `type` — IPV4_ADDRESSES requires items, name, type; IPV6_ADDRESSES requires items,
        name, type; PORTS requires items, name, type.

        Example call (create_traffic_matching_list):
            {
              "host": "my-console",
              "site": "Default",
              "traffic_list": {
                "type": "IPV4_ADDRESSES",
                "items": [{"type": "IP_ADDRESS", "value": "192.0.2.5"}],
                "name": "Allowed address list"
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            traffic_list: Full object to create; spec Create or update traffic matching list. Required:
                name, type. 'type' selects variant: IPV4_ADDRESSES|IPV6_ADDRESSES|PORTS.
        """
        client, registry = deps_fn()
        return await network_services_proxy.create_traffic_matching_list(
            client, registry, host, site, traffic_list
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_traffic_matching_list(
        host: str,
        site: str,
        list_id: str,
    ) -> Any:
        """Get a single traffic matching list by ID.

        Returns: the traffic matching list object, verbatim. To change it, edit it and pass it as
        `traffic_list` to update_traffic_matching_list.

        Example call (get_traffic_matching_list):
            {"host": "my-console", "site": "Default", "list_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            list_id: Traffic matching list UUID. Get it from list_traffic_matching_lists (data[].id).
                Network-app UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_traffic_matching_list(
            client, registry, host, site, list_id
        )

    @mcp.tool(annotations=WRITE)
    async def update_traffic_matching_list(
        host: str,
        site: str,
        list_id: str,
        traffic_list: dict[str, Any],
    ) -> Any:
        """Update a traffic matching list by ID.

        Returns the upstream response body verbatim: the updated traffic matching list object the API
        answers with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent:
        false, message, preview: {method, path, params (query parameters), body}} instead).

        Request body (Network 11.0.97, PUT
        /v1/sites/{siteId}/traffic-matching-lists/{trafficMatchingListId} (updateTrafficMatchingList);
        schema "Create or update traffic matching list") is passed in `traffic_list`. Required keys —
        name, type.
        - name: string
        - type: string
        Variants by `type` — IPV4_ADDRESSES requires items, name, type; IPV6_ADDRESSES requires items,
        name, type; PORTS requires items, name, type.

        Example call (update_traffic_matching_list):
            {
              "host": "my-console",
              "site": "Default",
              "list_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "traffic_list": {
                "type": "IPV4_ADDRESSES",
                "items": [{"type": "IP_ADDRESS", "value": "192.0.2.5"}],
                "name": "Allowed address list"
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            list_id: Traffic matching list UUID. Get it from list_traffic_matching_lists (data[].id).
                Network-app UUID — not a Protect id.
            traffic_list: FULL replacement object (PUT; omitted fields reset); spec Create or update
                traffic matching list. Required: name, type. 'type' selects variant:
                IPV4_ADDRESSES|IPV6_ADDRESSES|PORTS.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_traffic_matching_list(
            client, registry, host, site, list_id, traffic_list
        )

    @mcp.tool(annotations=WRITE)
    async def delete_traffic_matching_list(
        host: str,
        site: str,
        list_id: str,
    ) -> dict[str, Any]:
        """Delete a traffic matching list.

        Consequence: the list is permanently removed; there is no undo.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_traffic_matching_list):
            {"host": "my-console", "site": "Default", "list_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            list_id: Traffic matching list UUID. Get it from list_traffic_matching_lists (data[].id).
                Network-app UUID — not a Protect id.
        """
        client, registry = deps_fn()
        response = await network_services_proxy.delete_traffic_matching_list(
            client, registry, host, site, list_id
        )
        return deletion_result(f"Traffic matching list {list_id} deleted.", response)

    # --- VPN Server Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_vpn_servers(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List VPN servers for a site.

        Returns {data, totalCount}: every page is drained; data holds the VPN server records verbatim
        and totalCount is the upstream total (null when none was reported). The first page's other
        envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
        drain stopped short.

        VPN servers are offset-paginated (native default page size 25); by default every
        page is drained and the complete list is returned as {data, totalCount}. Pass
        offset alone for a single manual page. A capped drain is flagged incomplete.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await network_services_proxy.list_vpn_servers(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_site_to_site_tunnels(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List site-to-site VPN tunnels for a site.

        Returns: {data: [tunnel…], totalCount} with every page drained, entries verbatim (pass
        offset alone to fetch a single manual page, native envelope preserved). To change one,
        pass the native Classic networkconf fields to change (e.g. enabled, name) as `tunnel` to
        update_site_to_site_tunnel (tunnel_id = its data[] id).

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await network_services_proxy.list_site_to_site_tunnels(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    # --- RADIUS Profile Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_radius_profiles(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List RADIUS profiles for a site.

        Returns {data, totalCount}: every page is drained; data holds the RADIUS profile records
        verbatim and totalCount is the upstream total (null when none was reported). The first page's
        other envelope fields are kept beside them, and incomplete / incompleteReason are added when a
        capped drain stopped short.

        RADIUS profiles are offset-paginated (native default page size 25); by default
        every page is drained and the complete list is returned as {data, totalCount}.
        Pass offset alone for a single manual page. A capped drain is flagged incomplete.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `metadata.origin.eq('USER_DEFINED')`."""
        client, registry = deps_fn()
        return await network_services_proxy.list_radius_profiles(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    # --- Hotspot Voucher Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_hotspot_vouchers(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all hotspot/guest vouchers for a site (there is no `list_vouchers` — this is it).

        Returns {data, totalCount}: every page is drained; data holds the voucher records verbatim and
        totalCount is the upstream total (null when none was reported). The first page's other envelope
        fields are kept beside them, and incomplete / incompleteReason are added when a capped drain
        stopped short.

        This is the voucher-listing tool; the family is `list_hotspot_vouchers`,
        `create_hotspot_vouchers`, `get_hotspot_voucher`, `delete_hotspot_voucher` — all
        prefixed `hotspot_`. There is no shorter `list_vouchers`/`get_voucher` alias.

        Vouchers are offset-paginated (native page size 100) and batches routinely
        exceed that; by default every page is drained and all records are returned as
        {data, totalCount}. Pass offset alone for a single manual page. A capped drain
        is flagged incomplete.

        limit requests a total, gathered automatically in batches up to 1000;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 1000; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 1000, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `name.eq('Conference')`."""
        client, registry = deps_fn()
        return await network_services_proxy.list_hotspot_vouchers(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_hotspot_vouchers(
        host: str,
        site: str,
        voucher_config: dict[str, Any],
    ) -> Any:
        """Generate hotspot vouchers for a site.

        Returns the upstream response body verbatim: the voucher-creation object the API answers with
        (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params (query parameters), body}} instead).

        `voucher_config`: required fields (validated locally — a missing field raises ValueError
        naming it — and verified against the live controller): ``name`` and
        ``timeLimitMinutes`` (voucher validity window, minutes). Optional: count, quota,
        bandwidth limits, etc.

        Request body (Network 11.0.97, POST /v1/sites/{siteId}/hotspot/vouchers (createVouchers);
        schema "Hotspot voucher creation request") is passed in `voucher_config`. Required keys — name,
        timeLimitMinutes.
        - authorizedGuestLimit: integer(int64)
        - count: integer(int32)
        - dataUsageLimitMBytes: integer(int64)
        - name: string
        - rxRateLimitKbps: integer(int64)
        - timeLimitMinutes: integer(int64)
        - txRateLimitKbps: integer(int64)

        Example call (create_hotspot_vouchers):
            {
              "host": "my-console",
              "site": "Default",
              "voucher_config": {"name": "Conference", "timeLimitMinutes": 1440}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            voucher_config: Full object to create; spec Hotspot voucher creation request. Required:
                name, timeLimitMinutes.
        """
        client, registry = deps_fn()
        return await network_services_proxy.create_hotspot_vouchers(
            client, registry, host, site, voucher_config
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_hotspot_voucher(
        host: str,
        site: str,
        voucher_id: str,
    ) -> Any:
        """Get a single hotspot voucher by ID.

        Returns the upstream voucher object verbatim, exactly as the API answers it.

        Example call (get_hotspot_voucher):
            {
              "host": "my-console",
              "site": "Default",
              "voucher_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            voucher_id: Hotspot voucher UUID. Get it from list_hotspot_vouchers (data[].id). Network-app
                UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_hotspot_voucher(
            client, registry, host, site, voucher_id
        )

    @mcp.tool(annotations=WRITE)
    async def delete_hotspot_voucher(
        host: str,
        site: str,
        voucher_id: str,
    ) -> dict[str, Any]:
        """Delete a single hotspot voucher.

        Consequence: the voucher can no longer be redeemed; there is no undo.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_hotspot_voucher):
            {
              "host": "my-console",
              "site": "Default",
              "voucher_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            voucher_id: Hotspot voucher UUID. Get it from list_hotspot_vouchers (data[].id). Network-app
                UUID — not a Protect id.
        """
        client, registry = deps_fn()
        response = await network_services_proxy.delete_hotspot_voucher(
            client, registry, host, site, voucher_id
        )
        return deletion_result(f"Hotspot voucher {voucher_id} deleted.", response)

    @mcp.tool(annotations=WRITE)
    async def bulk_delete_hotspot_vouchers(
        host: str,
        site: str,
        filter_params: dict[str, Any],
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Bulk delete hotspot vouchers matching filter criteria.

        Consequence: every voucher matching the filter is permanently removed and can no longer be
        redeemed; there is no undo.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (bulk_delete_hotspot_vouchers):
            {
              "host": "my-console",
              "site": "Default",
              "filter_params": {"filter": "name.eq('Conference')"}
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            filter_params: Query parameters sent with the DELETE; must contain `filter`, which selects
                the vouchers to delete (Network 11.0.97 DELETE /v1/sites/{siteId}/hotspot/vouchers),
                e.g. {"filter": "name.eq('Conference')"}. Filter syntax as list_hotspot_vouchers.
                Free-form JSON object; no fixed body shape is published.
            confirm: Ignored; accepted for backward compatibility. The call executes immediately when
                made unless the operator opted in to dry-run policy (then nothing is
                sent upstream and a preview of the request is returned).
        """
        client, registry = deps_fn()
        response = await network_services_proxy.bulk_delete_hotspot_vouchers(
            client, registry, host, site, filter_params
        )
        return deletion_result("Hotspot vouchers deleted.", response)

    # --- Supporting Resources Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_device_tags(
        host: str,
        site: str,
    ) -> Any:
        """List all device tags defined in a site (the tags the Network UI shows).

        Reads the v2 route the controller's own UI uses, GET
        /proxy/network/v2/api/site/{site}/device-tags; the published Integration device-tag list
        is a separate collection that answers empty on Network 11.0.81 while the UI has tags.

        Returns: the v2 API's bare JSON array of tags, verbatim, the whole list in one response
        (each entry {_id, name, member_device_macs, ...}). To change one, pass it as `tag` to
        update_device_tag (tag_id = its _id): either the entry itself, edited (rename it, or set
        member_device_macs to the desired members; the tool sends the additions and removals
        and drops _id), or a native v2 update body {name, device_mac_additions,
        device_mac_removals}.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_device_tags(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def list_countries(
        host: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all countries with ISO codes available on a console.

        Returns {data, totalCount} with every page drained (about 250 entries; the API pages at
        25 by default). Pass offset alone to fetch a single manual page (native envelope
        preserved).

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `code.eq('US')`."""
        client, registry = deps_fn()
        return await network_services_proxy.list_countries(
            client, registry, host, offset=offset, limit=limit, filter=filter
        )

    return {
        "list_dns_policies": list_dns_policies,
        "create_dns_policy": create_dns_policy,
        "get_dns_policy": get_dns_policy,
        "update_dns_policy": update_dns_policy,
        "delete_dns_policy": delete_dns_policy,
        "list_traffic_matching_lists": list_traffic_matching_lists,
        "create_traffic_matching_list": create_traffic_matching_list,
        "get_traffic_matching_list": get_traffic_matching_list,
        "update_traffic_matching_list": update_traffic_matching_list,
        "delete_traffic_matching_list": delete_traffic_matching_list,
        "list_vpn_servers": list_vpn_servers,
        "list_site_to_site_tunnels": list_site_to_site_tunnels,
        "list_radius_profiles": list_radius_profiles,
        "list_hotspot_vouchers": list_hotspot_vouchers,
        "create_hotspot_vouchers": create_hotspot_vouchers,
        "get_hotspot_voucher": get_hotspot_voucher,
        "delete_hotspot_voucher": delete_hotspot_voucher,
        "bulk_delete_hotspot_vouchers": bulk_delete_hotspot_vouchers,
        "list_device_tags": list_device_tags,
        "list_countries": list_countries,
    }


def register_2(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the network_services_proxy tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_port_forwards(
        host: str,
        site: str,
    ) -> Any:
        """List all port forwarding rules for a site.

        Returns: the controller envelope {meta, data: [rule…]}, entries verbatim. To change one, edit
        its data[] entry and pass it as `payload` to update_port_forward (forward_id = its _id).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_port_forwards(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def create_port_forward(
        host: str,
        site: str,
        payload: dict[str, Any],
    ) -> Any:
        """Create a port forwarding rule via the Classic REST API.

        Returns: the controller's Classic REST response envelope {meta: {rc}, data: [...]}
        verbatim (meta is relayed as received, never interpreted).
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        `payload`: port forward config. Pass name, dst_port, fwd and fwd_port. ``proto`` is
        optional (the controller defaults it, typically 'tcp_udp'). The body is sent as given:
        this Classic REST endpoint has no published schema and is observed to accept a body
        without those fields and create a broken rule, so include them; an upstream error gets a
        hint naming any that are missing.
        Example: {"enabled": true, "name": "SSH", "pfwd_interface": "wan", "src": "any",
        "dst_port": "2222", "fwd": "192.168.1.10", "fwd_port": "22", "proto": "tcp", "log": false}

        Request body: no published schema exists for POST network/api/s/{site}/rest/portforward
        (classic/v2 controller API). Pass the controller's native payload; read the current object first
        with the matching list/get tool and send back the edited object.

        Example call (create_port_forward):
            {
              "host": "my-console",
              "site": "Default",
              "payload": {
                "enabled": true,
                "name": "SSH",
                "pfwd_interface": "wan",
                "src": "any",
                "dst_port": "2222",
                "fwd": "192.0.2.10",
                "fwd_port": "22",
                "proto": "tcp",
                "log": false
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            payload: spec: free-form (classic REST portforward), sent as given. Pass name,
                dst_port, fwd (target IP), fwd_port; proto optional (tcp|udp|tcp_udp).
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.create_port_forward(
            client, registry, host, site, payload
        )

    @mcp.tool(annotations=WRITE)
    async def update_port_forward(
        host: str,
        site: str,
        forward_id: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a port forwarding rule by ID.

        The id is resolved in list_port_forwards first: an unknown id fails listing every valid _id, and
        nothing is written.

        Returns: the controller's Classic REST response envelope {meta: {rc}, data: [...]}
        verbatim (meta is relayed as received, never interpreted).
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Request body: no published schema exists for PUT network/api/s/{site}/rest/portforward/{id}
        (classic/v2 controller API). Pass the controller's native payload; read the current object first
        with the matching list/get tool and send back the edited object.

        Example call (update_port_forward):
            {
              "host": "my-console",
              "site": "Default",
              "forward_id": "000000000000000000000107",
              "payload": {"enabled": false}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            forward_id: Port-forward rule _id (classic REST portforward). Get it from list_port_forwards
                (_id).
            payload: spec: free-form (classic REST portforward). Fields to change (snake_case, e.g.
                dst_port, fwd, fwd_port, enabled). Read current via list_port_forwards.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_port_forward(
            client, registry, host, site, forward_id, payload
        )

    @mcp.tool(annotations=WRITE)
    async def delete_port_forward(
        host: str,
        site: str,
        forward_id: str,
    ) -> dict[str, Any]:
        """Delete a port forwarding rule by ID.

        Consequence: inbound connections on the forwarded port stop reaching the internal host; there is
        no undo.

        The id is resolved in list_port_forwards first (the controller answers a DELETE on an unknown id
        with HTTP 200): an unknown id fails listing every valid _id, and nothing is deleted.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_port_forward):
            {"host": "my-console", "site": "Default", "forward_id": "000000000000000000000107"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            forward_id: Port-forward rule _id (classic REST portforward). Get it from list_port_forwards
                (_id).
        """
        client, registry = deps_fn()
        response = await network_services_proxy.delete_port_forward(
            client, registry, host, site, forward_id
        )
        return deletion_result(f"Port forward {forward_id} deleted.", response)

    # --- Traffic Rule Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_traffic_rules(
        host: str,
        site: str,
    ) -> Any:
        """List traffic matching rules (QoS, application, IP group matching).

        Requires a controller implementing the v2 trafficrules route. Consoles without it
        return HTTP 501 api.err.NotImplemented; the upstream error is returned to the caller.

        Returns: the v2 API's bare JSON array of rules, verbatim (the same shape as
        list_traffic_routes). To change one, edit its entry and pass it as `payload` to
        update_traffic_rule (rule_id = its _id).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_traffic_rules(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def create_traffic_rule(
        host: str,
        site: str,
        payload: dict[str, Any],
    ) -> Any:
        """Create a traffic matching rule (QoS, block, or route by application/IP group).

        Returns the upstream response body verbatim: the created traffic rule object the API answers
        with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        `payload`: sent as given; the controller requires these fields (verified live; an
        upstream error gets a hint naming any that are missing):
          - action: 'BLOCK'|'THROTTLE_RATE'|'QUEUE'
          - matching_target: 'INTERNET'|'LOCAL'|'ALL' or a traffic matching list id (from
            list_traffic_matching_lists)
          - target_devices: the devices/networks the rule applies to (required by the API;
            previously undocumented)
          Optional (NOT required by the API): description (str), enabled (bool, controller
          defaults it), matching_target_type ('INTERNET'|'DOMAIN'|'IP_GROUP'|'APPLICATION_GROUP'),
          bandwidth_limit (dict with up_limit_kbps/down_limit_kbps for THROTTLE_RATE).
        Note: uses the Classic REST v2 API (/v2/api/site/{siteId}/trafficrules); may not exist
        on firmware 10.2.105 and below. A console that does not implement creating here answers
        HTTP 501 api.err.NotImplemented (GET may still list rules) and no payload change will
        help: use create_firewall_policy (match with create_traffic_matching_list),
        create_qos_rule or create_traffic_route, each with its own schema.

        Request body: no published schema exists for POST network/v2/api/site/{site}/trafficrules
        (classic/v2 controller API). Pass the controller's native payload; read the current object first
        with the matching list/get tool and send back the edited object.

        Example call (create_traffic_rule):
            {
              "host": "my-console",
              "site": "Default",
              "payload": {
                "action": "BLOCK",
                "matching_target": "INTERNET",
                "target_devices": [{"client_mac": "aa:bb:cc:dd:ee:ff"}],
                "description": "Block guests",
                "enabled": true
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            payload: spec: free-form (Network v2 trafficrules), sent as given. The controller
                requires action BLOCK|THROTTLE_RATE|QUEUE, matching_target (INTERNET|LOCAL|ALL or
                list id) and target_devices.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.create_traffic_rule(
            client, registry, host, site, payload
        )

    @mcp.tool(annotations=WRITE)
    async def update_traffic_rule(
        host: str,
        site: str,
        rule_id: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a traffic rule by ID.

        Requires a controller implementing the v2 trafficrules route. Consoles without it
        return HTTP 501 api.err.NotImplemented; the upstream error is returned to the caller.

        The id is resolved in list_traffic_rules first: an unknown id fails listing every valid _id, and
        nothing is written. The v2 PUT replaces the whole rule, so the tool reads the rule from
        list_traffic_rules, merges only the given fields into it (objects merge recursively; a list
        replaces the stored list), PUTs the merged rule and reads it back: fields not in payload are
        sent back unchanged. A payload with no field to change is refused before any request.

        Returns the upstream PUT body plus _verified (true only when every requested leaf read back
        equal, type-strict) and _readAfterError when the read-back failed; a non-object PUT body is
        kept under response. Under dry-run policy nothing is sent and the tool returns the dry-run
        preview {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params (query parameters), body}} instead.

        Request body: no published schema exists for PUT network/v2/api/site/{site}/trafficrules/{id}/
        (classic/v2 controller API). Pass only the native fields to change; the tool supplies the rest
        from the listed rule.

        Example call (update_traffic_rule):
            {
              "host": "my-console",
              "site": "Default",
              "rule_id": "000000000000000000000107",
              "payload": {"enabled": false}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            rule_id: Traffic rule id (Network v2 API _id). Get it from list_traffic_rules (_id).
            payload: spec: free-form (Network v2 trafficrules). Fields to change, merged into the
                listed rule before the PUT, e.g. {"enabled": false}.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_traffic_rule(
            client, registry, host, site, rule_id, payload
        )

    @mcp.tool(annotations=WRITE)
    async def delete_traffic_rule(
        host: str,
        site: str,
        rule_id: str,
    ) -> dict[str, Any]:
        """Delete a traffic rule by ID.

        Requires a controller implementing the v2 trafficrules route. Consoles without it
        return HTTP 501 api.err.NotImplemented; the upstream error is returned to the caller.

        Consequence: the rule stops applying to matching traffic immediately; there is no undo.

        The id is resolved in list_traffic_rules first (the controller answers a DELETE on an unknown id
        with HTTP 200): an unknown id fails listing every valid _id, and nothing is deleted.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_traffic_rule):
            {"host": "my-console", "site": "Default", "rule_id": "000000000000000000000107"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            rule_id: Traffic rule id (Network v2 API _id). Get it from list_traffic_rules (_id).
        """
        client, registry = deps_fn()
        response = await network_services_proxy.delete_traffic_rule(
            client, registry, host, site, rule_id
        )
        return deletion_result(f"Traffic rule {rule_id} deleted.", response)

    return {
        "list_port_forwards": list_port_forwards,
        "create_port_forward": create_port_forward,
        "update_port_forward": update_port_forward,
        "delete_port_forward": delete_port_forward,
        "list_traffic_rules": list_traffic_rules,
        "create_traffic_rule": create_traffic_rule,
        "update_traffic_rule": update_traffic_rule,
        "delete_traffic_rule": delete_traffic_rule,
    }


def register_3(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the network_services_proxy tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(annotations=READ_ONLY)
    async def list_users(
        host: str,
        site: str,
    ) -> Any:
        """List DHCP fixed-IP reservations and client aliases for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [entry…]} verbatim; data[]
        entries carry fields such as name, note, fixed_ip, use_fixedip, network_id.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_users(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_user(
        host: str,
        site: str,
        user_id: str,
    ) -> Any:
        """Get a single DHCP/client-alias entry by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [client-alias/DHCP user
        entry]} verbatim. To change it, edit data[0] and pass it as `payload` to update_user.

        Example call (get_user):
            {"host": "my-console", "site": "Default", "user_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            user_id: Network client-alias/DHCP user _id (classic REST user). Get it from list_users
                (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_user(client, registry, host, site, user_id)

    @mcp.tool(annotations=WRITE)
    async def update_user(
        host: str,
        site: str,
        user_id: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a DHCP/client-alias entry by ID.

        The id is resolved in list_users first: an unknown id fails listing every valid _id, and nothing
        is written.

        Returns: the controller's Classic REST response envelope {meta: {rc}, data: [...]}
        verbatim (meta is relayed as received, never interpreted).
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Request body: no published schema exists for PUT network/api/s/{site}/rest/user/{id} (classic/v2
        controller API). Pass the controller's native payload; read the current object first with the
        matching list/get tool and send back the edited object.

        Example call (update_user):
            {
              "host": "my-console",
              "site": "Default",
              "user_id": "000000000000000000000107",
              "payload": {"name": "Printer", "note": "2nd floor"}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            user_id: Network client-alias/DHCP user _id (classic REST user). Get it from list_users
                (_id).
            payload: spec: free-form (classic REST user). Fields to change: name, note, fixed_ip,
                use_fixedip, network_id (classic networkconf _id).
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_user(
            client, registry, host, site, user_id, payload
        )

    # --- Traffic Route Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_traffic_routes(
        host: str,
        site: str,
    ) -> Any:
        """List static/policy traffic routes for a site.

        Returns the v2 API's bare JSON array of routes, verbatim (a list result: structured content
        {result: [...]}).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_traffic_routes(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def create_traffic_route(
        host: str,
        site: str,
        payload: dict[str, Any],
    ) -> Any:
        """Create a traffic route on a site (policy-based routing / WAN load-balancing).

        Returns the upstream response body verbatim: the created traffic route object the API answers
        with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        `payload`: sent as given; the controller requires these fields (verified live; an
        upstream error gets a hint naming any that are missing). This v2 endpoint uses snake_case wire
        field names (verified: 'network_id' is accepted, 'networkId' is not):
          - network_id (str): source network UUID (from list_networks), or 'ANY'
          - matching_target: 'INTERNET'|'ALL' or a traffic matching list id (from
            list_traffic_matching_lists)
          - target_devices: the devices/networks the route applies to
          Optional: matching_target_type ('INTERNET'|'DOMAIN'|'IP_GROUP'), description (str).

        Request body: no published schema exists for POST network/v2/api/site/{site}/trafficroutes
        (classic/v2 controller API). Pass the controller's native payload; read the current object first
        with the matching list/get tool and send back the edited object.

        Example call (create_traffic_route):
            {
              "host": "my-console",
              "site": "Default",
              "payload": {
                "network_id": "ANY",
                "matching_target": "INTERNET",
                "target_devices": [{"client_mac": "aa:bb:cc:dd:ee:ff"}],
                "description": "Route via WAN2"
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            payload: spec: free-form (Network v2 trafficroutes, snake_case), sent as given. The
                controller requires network_id (list_networks UUID or 'ANY'), matching_target,
                target_devices.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.create_traffic_route(
            client, registry, host, site, payload
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_traffic_route(
        host: str,
        site: str,
        route_id: str,
    ) -> Any:
        """Get a single traffic route by ID.

        Returns: the traffic route object, verbatim. To change it, edit it and pass it as `payload` to
        update_traffic_route.

        Example call (get_traffic_route):
            {"host": "my-console", "site": "Default", "route_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            route_id: Traffic route _id (Network v2 API). Get it from list_traffic_routes (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_traffic_route(
            client, registry, host, site, route_id
        )

    @mcp.tool(annotations=WRITE)
    async def update_traffic_route(
        host: str,
        site: str,
        route_id: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a traffic route by ID.

        The id is resolved in list_traffic_routes first: an unknown id fails listing every valid _id,
        and nothing is written.

        Returns the upstream response body verbatim: the updated traffic route object the API answers
        with (under dry-run policy, the dry-run preview {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params (query parameters), body}} instead).

        Request body: no published schema exists for PUT network/v2/api/site/{site}/trafficroutes/{id}
        (classic/v2 controller API). Pass the controller's native payload; read the current object first
        with the matching list/get tool and send back the edited object.

        Example call (update_traffic_route):
            {
              "host": "my-console",
              "site": "Default",
              "route_id": "000000000000000000000107",
              "payload": {
                "description": "IoT via WAN2",
                "enabled": false,
                "matching_target": "INTERNET",
                "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "target_devices": [{"client_mac": "aa:bb:cc:dd:ee:ff"}]
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            route_id: Traffic route _id (Network v2 API). Get it from list_traffic_routes (_id).
            payload: spec: free-form (Network v2 trafficroutes, snake_case). FULL replacement object;
                start from get_traffic_route output.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_traffic_route(
            client, registry, host, site, route_id, payload
        )

    @mcp.tool(annotations=WRITE)
    async def delete_traffic_route(
        host: str,
        site: str,
        route_id: str,
    ) -> dict[str, Any]:
        """Delete a traffic route by ID.

        Consequence: matching traffic stops following the route and uses the default routing; there is
        no undo.

        The id is resolved in list_traffic_routes first (the controller answers a DELETE on an unknown
        id with HTTP 200): an unknown id fails listing every valid _id, and nothing is deleted.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_traffic_route):
            {"host": "my-console", "site": "Default", "route_id": "000000000000000000000107"}

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            route_id: Traffic route _id (Network v2 API). Get it from list_traffic_routes (_id).
        """
        client, registry = deps_fn()
        response = await network_services_proxy.delete_traffic_route(
            client, registry, host, site, route_id
        )
        return deletion_result(f"Traffic route {route_id} deleted.", response)

    # --- Controller Settings Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_settings(
        host: str,
        site: str,
    ) -> Any:
        """List all controller setting groups for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [setting group…]}
        verbatim; data[] holds one object per key (mgmt, super_smtp, guest_access, etc.).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_settings(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_setting(
        host: str,
        site: str,
        setting_key: str,
    ) -> Any:
        """Get a controller setting group by key.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [setting group]} verbatim.
        To change it, edit data[0] and pass it as `payload` to update_setting.

        There is no schema endpoint, so reading a group is how you discover what it accepts:
        the returned object lists every settable field and its current (valid) value. Inspect
        it before calling update_setting — the controller silently drops any field or enum
        value it does not recognise, so match an existing field's shape exactly. Common keys
        and notable enum fields (grounded in live responses): mdns (mode, enabled_for),
        ntp (setting_preference), doh (state), ips (ips_mode), global_nat (mode),
        ssl_inspection (state), dashboard (layout_preference), locale (timezone),
        country (code), guest_access (auth), super_mgmt (data_retention_setting_preference).
        Fields prefixed 'x_' hold credentials/secrets and are returned verbatim
        (masked when UNIFI_REDACT_SECRETS is enabled).

        Required arguments: host, site, setting_key (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            setting_key: setting group identifier (e.g. 'mgmt', 'super_smtp', 'guest_access').
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_setting(client, registry, host, site, setting_key)

    @mcp.tool(annotations=WRITE)
    async def update_setting(
        host: str,
        site: str,
        setting_key: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a controller setting group by key.

        Discover the schema first by calling get_setting(setting_key): it returns every
        settable field and its current (valid) value. The controller silently drops any
        unrecognised field or enum value (HTTP 200, value unchanged), so a guessed value
        fails invisibly; this tool reports that no-op separately from the PUT response, naming
        every rejected field and pointing you back at get_setting. The check walks the payload
        leaf by leaf: a nested object is compared as a partial update (only the keys you send
        must take), and a
        nested leaf left unchanged is named by its dotted path (e.g. radius.port) even when a sibling
        leaf in the same object was applied; _verificationNote names the rejected and applied
        leaves.

        Returns: the controller's PUT response envelope {meta: {rc}, data: [setting group]} verbatim
        plus the additive _verified: true only when the read-after confirms every submitted leaf
        (type-strict: true is not 1), false with _unverifiedFields (dotted paths) when a leaf was
        rejected or changed to a value other than the one sent (v0.6.2 raised for a rejected
        leaf; check _verified), null with _readAfterError when the read-after failed or could not
        be matched (the write was still sent). When every submitted field already holds the sent
        value, no PUT is made and the current GET envelope is returned verbatim plus an additive
        _note "no change needed".
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Request body: no published schema exists for PUT network/api/s/{site}/rest/setting/{setting_key}
        (classic controller API). Pass the controller's native payload; read the current object first
        with the matching list/get tool and send back the edited object.

        Example call (update_setting):
            {
              "host": "my-console",
              "site": "Default",
              "setting_key": "mgmt",
              "payload": {"led_enabled": false}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            setting_key: Classic setting group key, e.g. 'mgmt', 'super_smtp', 'guest_access'. Get keys
                from list_settings (data[].key). Keys a Network 11.0.81 site reports: auto_speedtest,
                connectivity, country, dashboard, device_supervision, doh, dpi, element_adopt,
                ether_lighting, global_nat, global_network, global_switch, guest_access,
                igmp_snooping, ips, ips_suppression, ipsec, lcm, locale, magic_site_to_site_vpn, mdns,
                mgmt, netflow, network_optimization, ntp, openvpn, peer_to_peer,
                provider_capabilities, radio_ai, radius, rsyslogd, snmp, ssl_inspection,
                super_cloudaccess, super_fabric_system_log, super_fwupdate, super_identity,
                super_mail, super_mgmt, super_smtp, super_stats, teleport, traffic_flow, ugw, usg,
                usg_geo (super_* groups are console-wide). Groups holding credentials in x_-prefixed
                fields: connectivity, element_adopt, guest_access, magic_site_to_site_vpn, mgmt,
                openvpn, radius, snmp, super_cloudaccess, super_fwupdate, super_smtp.
            payload: spec: free-form (classic REST setting). Call get_setting(setting_key) first and
                change only fields it returns; unknown fields/enums are reported separately in
                verification metadata.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_setting(
            client, registry, host, site, setting_key, payload
        )

    # --- Dynamic DNS Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_dynamic_dns(
        host: str,
        site: str,
    ) -> Any:
        """List Dynamic DNS provider configurations for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim,
        including x_password credential fields (masked when UNIFI_REDACT_SECRETS is enabled).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_dynamic_dns(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_dynamic_dns(
        host: str,
        site: str,
        ddns_id: str,
    ) -> Any:
        """Get a single Dynamic DNS configuration by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [Dynamic DNS entry]}
        verbatim. To change it, edit data[0] and pass it as `payload` to update_dynamic_dns.

        Returned verbatim, including x_password credential fields (masked when UNIFI_REDACT_SECRETS is enabled).

        Example call (get_dynamic_dns):
            {"host": "my-console", "site": "Default", "ddns_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            ddns_id: Dynamic DNS entry _id (classic REST dynamicdns). Get it from list_dynamic_dns
                (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_dynamic_dns(client, registry, host, site, ddns_id)

    @mcp.tool(annotations=WRITE)
    async def update_dynamic_dns(
        host: str,
        site: str,
        ddns_id: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a Dynamic DNS configuration by ID.

        The id is resolved in list_dynamic_dns first: an unknown id fails listing every valid _id, and
        nothing is written.

        Returns: the controller's Classic REST response envelope {meta: {rc}, data: [...]}
        verbatim (meta is relayed as received, never interpreted).
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Request body: no published schema exists for PUT network/api/s/{site}/rest/dynamicdns/{id}
        (classic/v2 controller API). Pass the controller's native payload; read the current object first
        with the matching list/get tool and send back the edited object.

        Example call (update_dynamic_dns):
            {
              "host": "my-console",
              "site": "Default",
              "ddns_id": "000000000000000000000107",
              "payload": {"service": "dyndns", "host_name": "home.example.com"}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            ddns_id: Dynamic DNS entry _id (classic REST dynamicdns). Get it from list_dynamic_dns
                (_id).
            payload: spec: free-form (classic REST dynamicdns). Native fields: service (e.g.
                dyndns, cloudflare, custom), host_name, login, x_password, server (for custom),
                interface (wan, wan2). Read the current object via get_dynamic_dns and send it
                back edited.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_dynamic_dns(
            client, registry, host, site, ddns_id, payload
        )

    # --- Port Profile Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_port_profiles(
        host: str,
        site: str,
    ) -> Any:
        """List switch port profiles (speed, VLAN, PoE config) for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [profile…]}, each profile
        verbatim (networkconf id fields stay bare Classic _ids). A profile that references networks
        also carries an additive _resolved_networks key mapping excluded_networkconf_ids /
        native_networkconf_id / voice_networkconf_id to {id, name, vlan} (id there is the Classic
        networkconf _id); it is not a controller field and update_port_profile ignores it.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_port_profiles(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_port_profile(
        host: str,
        site: str,
        profile_id: str,
    ) -> Any:
        """Get a single switch port profile by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [port profile]}
        verbatim, plus an additive _resolved_networks key on the profile mapping its networkconf ids
        to {id, name, vlan}. To change it, edit data[0] and pass it as `payload` to
        update_port_profile (the _resolved_networks key is dropped before the write).

        Example call (get_port_profile):
            {"host": "my-console", "site": "Default", "profile_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            profile_id: Switch port profile _id (classic REST portconf). Get it from list_port_profiles
                (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_port_profile(
            client, registry, host, site, profile_id
        )

    @mcp.tool(annotations=WRITE)
    async def update_port_profile(
        host: str,
        site: str,
        profile_id: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a switch port profile by ID.

        The id is resolved in list_port_profiles first: an unknown id fails listing every valid _id, and
        nothing is written.

        WARNING -- SHARED PROFILE, WIDE BLAST RADIUS: this edits a shared Ethernet Port
        Profile (Classic REST /rest/portconf), NOT one switch or one port. A single write
        changes STP/PoE/storm-control/VLAN/etc. for EVERY port on EVERY switch that has this
        profile assigned. It is NOT a per-device or per-port writer and must never be
        presented or used as a per-port/per-device STP-priority or PoE-mode writer -- for
        that, no confirmed per-port config route exists via this API. Read the profile's
        assignments and confirm the intended blast radius before writing.

        Request body: no published schema exists for PUT network/api/s/{site}/rest/portconf/{id}
        (classic/v2 controller API). Pass the controller's native payload; read the current object first
        with the matching list/get tool and send back the edited object.

        Returns: the controller's PUT response envelope {meta: {rc}, data: [port profile]} verbatim,
        the profile plus the additive _resolved_networks key.
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Example call (update_port_profile):
            {
              "host": "my-console",
              "site": "Default",
              "profile_id": "000000000000000000000107",
              "payload": {"poe_mode": "auto"}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            profile_id: Switch port profile _id (classic REST portconf). Get it from list_port_profiles
                (_id).
            payload: spec: free-form (classic REST portconf). Fields to change, e.g. speed,
                native_networkconf_id, op_mode, poe_mode. Read current via get_port_profile; its
                additive _resolved_networks key is dropped before the write.
                native_networkconf_id, voice_networkconf_id and excluded_networkconf_ids accept a
                Classic networkconf _id or the Integration id from list_networks (data[].id), which
                the tool converts to the _id before the PUT (a value the profile already holds
                passes unchanged); an unknown value fails listing every network (name, _id, id),
                and no PUT is sent.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_port_profile(
            client, registry, host, site, profile_id, payload
        )

    @mcp.tool(annotations=WRITE)
    async def allow_network_on_port_profile(
        host: str,
        site: str,
        profile_id: str,
        network_id: str,
        confirm: bool = False,
    ) -> Any:
        """Allow (un-exclude) a VLAN network on a switch port profile.

        A fresh read followed by one PUT is not atomic against concurrent edits.

        The result carries _profileNote only when the controller PUT response data array
        contains no profile; _tagged_networks is derived from the written payload.
        Other response bodies are returned unchanged.

        `confirm`: accepted and ignored. This is a live PUT to a SHARED port profile (its
          exclusion list affects every switch port using it); it runs immediately either way.

        This is the Network auto-exclusion remediation: it validates `network_id` against the site's
        networks, fresh-reads the profile, removes the network from `excluded_networkconf_ids`, and
        PUTs. Use it on every profile named in a `create_network` `D12_AUTO_EXCLUSION` _warnings
        entry.

        `network_id` accepts EITHER id of the network: the Network Integration id (list_networks
        data[].id, the id create_network returns) or the Classic networkconf _id (the value stored in
        excluded_networkconf_ids). An Integration id is mapped to its _id through the /rest/networkconf
        external_id field. An unknown id fails before any write, listing every network (name, vlan,
        _id and id).

        Returns: the controller's PUT response envelope {meta: {rc}, data: [profile]} verbatim (the
        profile plus the additive _resolved_networks key), plus additive keys: _tagged_networks (the
        resulting tagged VLAN set with names) and _network ({_id, id, name, vlan} of the network
        acted on).
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Request body: fresh portconf with the network's _id removed from excluded_networkconf_ids (no published spec for network/api/s/{site}/rest/portconf).

        Example call (allow_network_on_port_profile):
            {
              "host": "my-console",
              "site": "Default",
              "profile_id": "000000000000000000000107",
              "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            profile_id: Switch port profile _id (classic REST portconf). Get it from list_port_profiles
                (_id).
            network_id: Network (networkconf) id to (un)exclude. Get it from list_networks (data[].id)
                or list_port_profiles (_resolved_networks).
            confirm: Ignored; accepted for backward compatibility. The call executes immediately when
                made unless the operator opted in to dry-run policy (then nothing is
                sent upstream and a preview of the request is returned).
        """
        client, registry = deps_fn()
        return await network_services_proxy.allow_network_on_port_profile(
            client, registry, host, site, profile_id, network_id, confirm=confirm
        )

    @mcp.tool(annotations=WRITE)
    async def exclude_network_on_port_profile(
        host: str,
        site: str,
        profile_id: str,
        network_id: str,
        confirm: bool = False,
    ) -> Any:
        """Exclude (untag) a VLAN network from a switch port profile.

        A fresh read followed by one PUT is not atomic against concurrent edits.

        The result carries _profileNote only when the controller PUT response data array
        contains no profile; _tagged_networks is derived from the written payload.
        Other response bodies are returned unchanged.

        `confirm`: accepted and ignored. This is a live PUT to a SHARED port profile (its
          exclusion list affects every switch port using it); it runs immediately either way.

        Inverse of `allow_network_on_port_profile`: validates `network_id` against the site's
        networks, fresh-reads the profile, adds the network to `excluded_networkconf_ids`, and PUTs.

        `network_id` accepts EITHER id of the network: the Network Integration id (list_networks
        data[].id, the id create_network returns) or the Classic networkconf _id (the value stored in
        excluded_networkconf_ids). An Integration id is mapped to its _id through the /rest/networkconf
        external_id field, and the _id is what gets written. An unknown id fails before any write,
        listing every network (name, vlan, _id and id).

        Returns: the controller's PUT response envelope {meta: {rc}, data: [profile]} verbatim (the
        profile plus the additive _resolved_networks key), plus additive keys: _tagged_networks (the
        resulting tagged VLAN set with names) and _network ({_id, id, name, vlan} of the network
        acted on).
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Request body: none is passed by the caller. The tool fresh-reads the classic portconf record,
        adds the network's _id to excluded_networkconf_ids, and PUTs it back (no published spec for
        network/api/s/{site}/rest/portconf).

        Example call (exclude_network_on_port_profile):
            {
              "host": "my-console",
              "site": "Default",
              "profile_id": "000000000000000000000107",
              "network_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            profile_id: Switch port profile _id (classic REST portconf). Get it from list_port_profiles
                (_id).
            network_id: Network (networkconf) id to (un)exclude. Get it from list_networks (data[].id)
                or list_port_profiles (_resolved_networks).
            confirm: Ignored; accepted for backward compatibility. The call executes immediately when
                made unless the operator opted in to dry-run policy (then nothing is
                sent upstream and a preview of the request is returned).
        """
        client, registry = deps_fn()
        return await network_services_proxy.exclude_network_on_port_profile(
            client, registry, host, site, profile_id, network_id, confirm=confirm
        )

    # --- Routing Table Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_routing_entries(
        host: str,
        site: str,
    ) -> Any:
        """List static routing table entries for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_routing_entries(client, registry, host, site)

    # --- WLAN Config Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_wlan_configs(
        host: str,
        site: str,
    ) -> Any:
        """List per-SSID WLAN configurations (security, band steering, rate limits) for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim,
        including x_passphrase credential fields (masked when UNIFI_REDACT_SECRETS is enabled).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_wlan_configs(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_wlan_config(
        host: str,
        site: str,
        wlan_id: str,
    ) -> Any:
        """Get a single WLAN (SSID) configuration by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [WLAN configuration]}
        verbatim. To change it, edit data[0] and pass it as `payload` to update_wlan_config.

        Returned verbatim, including x_passphrase credential fields (masked when UNIFI_REDACT_SECRETS is enabled).

        Example call (get_wlan_config):
            {"host": "my-console", "site": "Default", "wlan_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            wlan_id: Classic WLAN config _id (wlanconf). Get it from list_wlan_configs (_id). Not a wifi
                broadcast UUID.
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_wlan_config(client, registry, host, site, wlan_id)

    @mcp.tool(annotations=WRITE)
    async def update_wlan_config(
        host: str,
        site: str,
        wlan_id: str,
        payload: dict[str, Any],
    ) -> Any:
        """Update a WLAN (SSID) configuration by ID.

        The id is resolved in list_wlan_configs first: an unknown id fails listing every valid _id, and
        nothing is written.

        Returns: the controller's Classic REST response envelope {meta: {rc}, data: [...]}
        verbatim (meta is relayed as received, never interpreted).
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status: "dry_run",
        dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Request body: no published schema exists for PUT network/api/s/{site}/rest/wlanconf/{id}
        (classic/v2 controller API). Pass the controller's native payload; read the current object first
        with the matching list/get tool and send back the edited object.

        Example call (update_wlan_config):
            {
              "host": "my-console",
              "site": "Default",
              "wlan_id": "000000000000000000000107",
              "payload": {"enabled": false}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            wlan_id: Classic WLAN config _id (wlanconf). Get it from list_wlan_configs (_id). Not a wifi
                broadcast UUID.
            payload: spec: free-form (classic REST wlanconf). Fields to change, e.g. x_passphrase,
                security, enabled. Read current via get_wlan_config.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await network_services_proxy.update_wlan_config(
            client, registry, host, site, wlan_id, payload
        )

    # --- WLAN Group Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_wlan_groups(
        host: str,
        site: str,
    ) -> Any:
        """List WLAN groups for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_wlan_groups(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_wlan_group(
        host: str,
        site: str,
        group_id: str,
    ) -> Any:
        """Get a single WLAN group by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Reads the Classic REST /rest/wlangroup collection and returns that envelope
        {meta: {rc}, data: [group]} with data narrowed to the group whose _id matches; an unknown id
        fails listing the valid groups (name and _id). The controller rejects
        GET /rest/wlangroup/{id} with HTTP 400 api.err.InvalidObject for every id, including
        the built-in Default group, so the collection route is the supported read. The
        matching entry is returned unchanged.

        Example call (get_wlan_group):
            {"host": "my-console", "site": "Default", "group_id": "000000000000000000000001"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            group_id: Classic WLAN group _id. Get it from list_wlan_groups (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_wlan_group(client, registry, host, site, group_id)

    # --- Channel Plan Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def get_channel_plan(
        host: str,
        site: str,
    ) -> Any:
        """Get RF channel assignments and DFS status for a site.

        Returns the controller's Classic REST envelope {meta: {rc}, data: [channel plan…]} verbatim;
        an empty data array means the controller has no channel plan stored (for example,
        auto-channel optimization has not run).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_channel_plan(client, registry, host, site)

    # --- Rogue AP Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_rogue_aps(
        host: str,
        site: str,
        rogue_only: bool = False,
    ) -> Any:
        """List neighboring APs detected by the site's radios.

        Returns ALL neighboring APs (most will have is_rogue=false and are benign neighbors).
        Only a small subset with is_rogue=true are confirmed rogue APs. Set rogue_only=true to
        filter to confirmed rogues only.

        Returns: the controller's Classic REST /stat/rogueap envelope {meta: {rc}, data: [ap…]}
        verbatim (with rogue_only, data is narrowed to is_rogue=true entries); entries carry BSSID,
        SSID, channel, signal strength, is_rogue flag, and detection time.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            rogue_only: When true, return only confirmed rogue APs (is_rogue=true). Default false
                returns every neighboring AP, most of them benign.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_rogue_aps(
            client, registry, host, site, rogue_only=rogue_only
        )

    # --- Classic Firewall Rule Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_firewall_rules(
        host: str,
        site: str,
    ) -> Any:
        """List classic L3/L4 firewall rules for a site (distinct from Integration API policies).

        Legacy, read-only: classic rules predate zone-based firewalling, and the Network 11.0.81
        web UI no longer reads this route. For the current firewall use list_firewall_policies
        (and get_firewall_policy, create_firewall_policy, update_firewall_policy).

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_firewall_rules(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def create_firewall_rule(
        host: str,
        site: str,
        rule: dict[str, Any],
        confirm: bool = False,
    ) -> Any:
        """Create a classic L3/L4 firewall rule for a site.

        This is an immediate, destructive Network write. It can change which traffic is
        allowed through the site's firewall. ``confirm`` is accepted for compatibility
        and ignored; the write runs whether it is true or false.

        This uses the private Early Access Site Manager route because the current official
        Network specification publishes only zone-based firewall policies. Prefer
        create_firewall_policy on zone-based Network releases.

        Returns the controller's response verbatim, typically {meta: {rc}, data: [...]}.
        Under dry-run policy nothing is sent: the result is the bare dry-run preview
        {status: "dry_run", dryRun: true, sent: false, message,
        preview: {method, path, params, body}} instead of the upstream body.

        Required arguments: host, site, rule (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts
                (data[].reportedState.hostname or reportedState.name, case-insensitive,
                e.g. "my-console") or the long data[].id (MAC:numericId composite).
            site: Site Manager site name or ObjectId, scoped to host. Get names and ids from
                list_sites (data[].meta.name or data[].siteId).
            rule: Free-form classic firewall-rule request body, forwarded unchanged for the
                controller to validate. Observed fields include name, action, enabled,
                ruleset, rule_index, protocol, src_address, dst_address,
                src_networkconf_id, dst_networkconf_id and dst_port.
            confirm: Accepted and ignored. The write always runs. Example: false.
        """
        del confirm
        client, registry = deps_fn()
        return await network_services_proxy.create_firewall_rule(client, registry, host, site, rule)

    @mcp.tool(annotations=READ_ONLY)
    async def get_firewall_rule(
        host: str,
        site: str,
        rule_id: str,
    ) -> Any:
        """Get a single classic firewall rule by ID.

        Legacy, read-only: for the current zone-based firewall use get_firewall_policy (ids from
        list_firewall_policies).

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Example call (get_firewall_rule):
            {"host": "my-console", "site": "Default", "rule_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            rule_id: Legacy firewall rule _id (classic REST). Get it from list_firewall_rules (_id).
                Not a firewall policy UUID.
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_firewall_rule(client, registry, host, site, rule_id)

    # --- Firewall Group Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_firewall_groups(
        host: str,
        site: str,
    ) -> Any:
        """List firewall groups (IP/port sets referenced by firewall rules) for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_firewall_groups(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_firewall_group(
        host: str,
        site: str,
        group_id: str,
    ) -> Any:
        """Get a single firewall group by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Example call (get_firewall_group):
            {"host": "my-console", "site": "Default", "group_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            group_id: Legacy firewall group _id (classic REST). Get it from list_firewall_groups (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_firewall_group(
            client, registry, host, site, group_id
        )

    # --- RADIUS Account Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_accounts(
        host: str,
        site: str,
    ) -> Any:
        """List local RADIUS user accounts for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim,
        including x_password credential fields (masked when UNIFI_REDACT_SECRETS is enabled).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_accounts(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_account(
        host: str,
        site: str,
        account_id: str,
    ) -> Any:
        """Get a single RADIUS account by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim,
        including x_password credential fields (masked when UNIFI_REDACT_SECRETS is enabled).

        Example call (get_account):
            {"host": "my-console", "site": "Default", "account_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            account_id: RADIUS account _id (classic REST account). Get it from list_accounts (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_account(client, registry, host, site, account_id)

    # --- Hotspot Package Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_hotspot_packages(
        host: str,
        site: str,
    ) -> Any:
        """List guest portal billing packages for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_hotspot_packages(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_hotspot_package(
        host: str,
        site: str,
        package_id: str,
    ) -> Any:
        """Get a single hotspot billing package by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Example call (get_hotspot_package):
            {"host": "my-console", "site": "Default", "package_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            package_id: Hotspot package _id (classic REST hotspotpackage). Get it from
                list_hotspot_packages (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_hotspot_package(
            client, registry, host, site, package_id
        )

    # --- Scheduled Task Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_scheduled_tasks(
        host: str,
        site: str,
    ) -> Any:
        """List scheduled tasks (firmware upgrade schedules, speed tests) for a site.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
        """
        client, registry = deps_fn()
        return await network_services_proxy.list_scheduled_tasks(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_scheduled_task(
        host: str,
        site: str,
        task_id: str,
    ) -> Any:
        """Get a single scheduled task by ID.

        Returns: the controller's Classic REST envelope {meta: {rc}, data: [...]} verbatim
        (meta is relayed as received, never interpreted).

        Example call (get_scheduled_task):
            {"host": "my-console", "site": "Default", "task_id": "000000000000000000000107"}

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites (name or
                id). Names like "Default" work.
            task_id: Scheduled task _id (classic REST scheduletask). Get it from list_scheduled_tasks
                (_id).
        """
        client, registry = deps_fn()
        return await network_services_proxy.get_scheduled_task(
            client, registry, host, site, task_id
        )

    # --- DPI Tools ---

    @mcp.tool(annotations=READ_ONLY)
    async def list_dpi_categories(
        host: str,
        site: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List DPI (Deep Packet Inspection) app categories available for traffic rules.

        Returns {data, totalCount}: every page is drained; data holds the DPI category records verbatim
        and totalCount is the upstream total (null when none was reported). The first page's other
        envelope fields are kept beside them, and incomplete / incompleteReason are added when a capped
        drain stopped short.

        Categories include Social Media, Streaming Video, Gaming, etc.
        By default every page is drained and the complete catalogue is returned as
        {data, totalCount}. Pass offset alone to fetch a single page manually. A
        capped drain returns the categories gathered so far with incomplete=true
        rather than truncating silently.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Optional. DPI data is host-level, so a site does not narrow the result; when
                given it must name a site on the console (an unknown site is rejected with the
                valid site names).
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `name.eq('Business')`."""
        client, registry = deps_fn()
        await _validate_optional_site(registry, host, site)
        return await network_services_proxy.list_dpi_categories(
            client, registry, host, offset, limit, filter=filter
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_dpi_applications(
        host: str,
        site: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List DPI applications available for traffic rules.

        Returns {data, totalCount}: every page is drained; data holds the DPI application records
        verbatim and totalCount is the upstream total (null when none was reported). The first page's
        other envelope fields are kept beside them, and incomplete / incompleteReason are added when a
        capped drain stopped short.

        Companion to list_dpi_categories; use application IDs in traffic rule configurations.
        By default every page is drained and the complete catalogue is returned as
        {data, totalCount}. Pass offset alone to fetch a single page manually. A
        capped drain returns the applications gathered so far with incomplete=true
        rather than truncating silently.

        limit requests a total, gathered automatically in batches up to 200;
        _pageSize reports requested count, actual sent sizes per request,
        observed effective size and returned count, without capping the total.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Optional. DPI data is host-level, so a site does not narrow the result; when
                given it must name a site on the console (an unknown site is rejected with the
                valid site names).
            offset: Optional zero-based starting record; alone, fetch one page manually.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain all.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `name.like('*guest*')`). Omitted entirely when unset; applies when draining and
                when paging manually.
                Example: `name.eq('Zoom')`."""
        client, registry = deps_fn()
        await _validate_optional_site(registry, host, site)
        return await network_services_proxy.list_dpi_applications(
            client, registry, host, offset, limit, filter=filter
        )

    return {
        "list_users": list_users,
        "get_user": get_user,
        "update_user": update_user,
        "list_traffic_routes": list_traffic_routes,
        "create_traffic_route": create_traffic_route,
        "get_traffic_route": get_traffic_route,
        "update_traffic_route": update_traffic_route,
        "delete_traffic_route": delete_traffic_route,
        "list_settings": list_settings,
        "get_setting": get_setting,
        "update_setting": update_setting,
        "list_dynamic_dns": list_dynamic_dns,
        "get_dynamic_dns": get_dynamic_dns,
        "update_dynamic_dns": update_dynamic_dns,
        "list_port_profiles": list_port_profiles,
        "get_port_profile": get_port_profile,
        "update_port_profile": update_port_profile,
        "allow_network_on_port_profile": allow_network_on_port_profile,
        "exclude_network_on_port_profile": exclude_network_on_port_profile,
        "list_routing_entries": list_routing_entries,
        "list_wlan_configs": list_wlan_configs,
        "get_wlan_config": get_wlan_config,
        "update_wlan_config": update_wlan_config,
        "list_wlan_groups": list_wlan_groups,
        "get_wlan_group": get_wlan_group,
        "get_channel_plan": get_channel_plan,
        "list_rogue_aps": list_rogue_aps,
        "list_firewall_rules": list_firewall_rules,
        "get_firewall_rule": get_firewall_rule,
        "list_firewall_groups": list_firewall_groups,
        "get_firewall_group": get_firewall_group,
        "list_accounts": list_accounts,
        "get_account": get_account,
        "list_hotspot_packages": list_hotspot_packages,
        "get_hotspot_package": get_hotspot_package,
        "list_scheduled_tasks": list_scheduled_tasks,
        "get_scheduled_task": get_scheduled_task,
        "list_dpi_categories": list_dpi_categories,
        "list_dpi_applications": list_dpi_applications,
    }
