"""Network services tools — DNS, traffic lists, VPN, RADIUS, hotspot via connector proxy."""

from __future__ import annotations

from typing import Any, cast

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
    with_upstream_hint,
)
from ._results import (
    MISSING,
    UNVERIFIED_FIELDS_KEY,
    VERIFIED_KEY,
    leaf_equal,
    read_after_verdict,
    safe_read_after,
    short_circuit_no_op,
    with_read_after_error,
)
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


async def create_traffic_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """Create a traffic rule via the v2 API.

    Required fields (verified live): ``action``, ``matching_target`` and
    ``target_devices``. Note that ``target_devices`` — the devices/networks the rule
    applies to — is required by the API but was previously undocumented, while
    ``description`` and ``enabled`` are *not* API-required (the controller defaults
    ``enabled``); both are accepted as optional fields.
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
    return await with_upstream_hint(
        client.post(_v2_api(host_id, site_slug, "/trafficrules"), key=key, json=payload), hint
    )


async def _require_traffic_rule(
    client: UniFiClient, host_id: str, site_slug: str, rule_id: str, key: APIKeyConfig | None
) -> str:
    """The upstream ``_id`` of traffic rule ``rule_id`` (resolved in its list)."""
    record = await require_listed_record(
        client,
        _v2_api(host_id, site_slug, "/trafficrules"),
        rule_id,
        key=key,
        kind="Traffic rule",
        list_tool="list_traffic_rules",
        label_fields=("description", "name"),
    )
    return listed_record_id(record, "rule_id")


async def update_traffic_rule(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    rule_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Update a traffic rule via the v2 API (the id is resolved first)."""
    validate_id(rule_id, "rule_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    upstream_id = await _require_traffic_rule(client, host_id, site_slug, rule_id, key)
    return await client.put(
        _v2_api(host_id, site_slug, f"/trafficrules/{upstream_id}/"),
        key=key,
        json=strip_empty_list_values(addressed_body(payload, upstream_id)),
    )


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
    returned verbatim — handle them accordingly.
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

    Under ``UNIFI_DRY_RUN`` the PUT returns the dry-run preview; it is returned as is and
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
    # Under UNIFI_DRY_RUN the PUT is always issued to the preview (short_circuit_no_op).
    applied = all(_satisfies(pre_state.get(k, MISSING), v) for k, v in payload.items())
    if short_circuit_no_op(client, applied):
        return with_context(pre_response, {"_note": "no change needed"})

    # --- perform the write ---
    response = await client.put(url, key=key, json=payload)
    if is_dry_run_preview(response):
        # UNIFI_DRY_RUN: nothing was written, so there is nothing to verify.
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
# network, and the atomic allow_/exclude_ helpers do the whole fresh-read ->
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
        # UNIFI_DRY_RUN: nothing was written; the bare preview, no name-resolution read.
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
    """Atomically add/remove a network from a port profile's exclusion list.

    ``network_id`` may be either id of the network: the Classic networkconf ``_id`` or the
    Network Integration id (``list_networks`` data[].id / the id ``create_network``
    returns), which is mapped to its ``_id`` through the networkconf ``external_id``. It is
    validated against /rest/networkconf BEFORE the write; an unknown id fails listing every
    valid network (name, vlan, both ids).

    Fresh-reads the profile, mutates ``excluded_networkconf_ids``, PUTs the whole object
    back, and returns the controller's PUT envelope verbatim (each profile carrying the
    additive ``_resolved_networks``) plus the additive ``_tagged_networks`` (the derived
    tagged-VLAN set) and ``_network`` (the networkconf the id resolved to). Under
    ``UNIFI_DRY_RUN`` the bare dry-run preview is returned (none of those additive keys,
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
        # UNIFI_DRY_RUN: nothing was written, so there is no profile to derive
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
        (p for p in resp_data or [] if isinstance(p, dict) and same_id(upstream_id, p.get("_id"))),
        None,
    )
    result: dict[str, Any] = (
        dict(_envelope_with_resolution(response, name_map, error))
        if isinstance(response, dict)
        else {"response": response}
    )
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
    """Atomically allow (un-exclude) a network on a port profile after auto-exclusion.

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
    """Atomically exclude (untag) a network on a port profile.

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
