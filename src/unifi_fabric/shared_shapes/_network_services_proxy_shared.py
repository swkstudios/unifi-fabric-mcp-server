"""Names the network family's ``network_services_proxy`` shares with other families.

Used by network, vpn. Moved verbatim by ``scripts/move_family.py`` from
``families/network/network_services_proxy.py``, which import them back where they use them, so their
own code and import paths stay.
"""

from __future__ import annotations

from typing import Any

from ..client import UniFiClient
from ..config import APIKeyConfig
from ..registry import Registry, _assert_uuid
from ..shared_shapes._network_shared import _proxy
from ..shared_shapes._pagination import collect_offset, offset_list_result, validate_pagination


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
