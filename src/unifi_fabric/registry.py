"""Lazy-load host/site registry with per-key TTL-based caching for MSP multi-console support."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING, Any, cast

from cachetools import TTLCache

from .client import validate_host_id

if TYPE_CHECKING:
    from .client import UniFiClient
    from .config import APIKeyConfig

_DEFAULT_LABEL = "__default__"
_logger = logging.getLogger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_PROXY_SITES_PATH = "/v1/connector/consoles/{host_id}/proxy/network/integration/v1/sites"


def _assert_uuid(site_id: str) -> None:
    """Raise ValueError if site_id is not a valid UUID.

    Called at every proxy URL construction site as defense-in-depth so that
    ObjectId values from the legacy /ea/sites path can never slip into a
    proxy endpoint URL.
    """
    if not _UUID_RE.match(site_id):
        raise ValueError(
            f"site_id {site_id!r} is not a UUID — proxy endpoints require UUID site IDs. "
            "Pass the site name or UUID as returned by the console's /sites endpoint."
        )


class Registry:
    """Caches host and site mappings per API key with configurable TTL and bounded size.

    Each API key label gets its own independent cache so that MSP deployments
    with multiple keys (each seeing different consoles) return correct data.

    _sites uses a (label, host_id) tuple key because proxy site lists are
    per-console; _ea_sites uses a plain label key for the MSP /ea/sites list.

    All three caches are backed by cachetools.TTLCache which enforces both a
    maximum size (LRU eviction when full) and a per-entry TTL.
    """

    def __init__(
        self,
        client: UniFiClient,
        ttl_seconds: int = 900,
        cache_max_hosts: int = 512,
        cache_max_sites: int = 2048,
    ) -> None:
        self._client = client
        self._ttl = ttl_seconds
        self._hosts: TTLCache[str, list[dict[str, Any]]] = TTLCache(
            maxsize=cache_max_hosts, ttl=ttl_seconds
        )
        self._sites: TTLCache[tuple[str, str], list[dict[str, Any]]] = TTLCache(
            maxsize=cache_max_sites, ttl=ttl_seconds
        )
        self._ea_sites: TTLCache[str, list[dict[str, Any]]] = TTLCache(
            maxsize=cache_max_hosts, ttl=ttl_seconds
        )
        self._locks: dict[str, asyncio.Lock] = {}
        # Per-cache eviction pressure warning flags (sticky, re-armed below 50%)
        self._hosts_full_warned = False
        self._sites_full_warned = False
        self._ea_sites_full_warned = False

    def _key_label(self, key: APIKeyConfig | None) -> str:
        return key.label if key is not None else _DEFAULT_LABEL

    def _check_cache_pressure(self, cache: TTLCache, name: str, warned_attr: str) -> None:
        """Log WARNING once when cache first fills; log INFO when pressure drops below 50%."""
        if len(cache) >= cache.maxsize:
            if not getattr(self, warned_attr):
                setattr(self, warned_attr, True)
                _logger.warning(
                    "Registry %s cache is full (size=%d, maxsize=%d); LRU eviction in effect",
                    name,
                    len(cache),
                    cache.maxsize,
                )
        elif getattr(self, warned_attr) and len(cache) < cache.maxsize // 2:
            setattr(self, warned_attr, False)
            _logger.info(
                "Registry %s cache pressure relieved (size=%d, maxsize=%d)",
                name,
                len(cache),
                cache.maxsize,
            )

    def _get_lock(self, label: str) -> asyncio.Lock:
        if label not in self._locks:
            self._locks[label] = asyncio.Lock()
        return self._locks[label]

    async def get_hosts(self, *, key: APIKeyConfig | None = None) -> list[dict[str, Any]]:
        label = self._key_label(key)
        async with self._get_lock(label):
            if label not in self._hosts:
                self._check_cache_pressure(self._hosts, "hosts", "_hosts_full_warned")
                self._hosts[label] = await self._client.paginate("/ea/hosts", key=key)
            return self._hosts[label]

    async def get_ea_sites(self, *, key: APIKeyConfig | None = None) -> list[dict[str, Any]]:
        """Return sites from the MSP /ea/sites endpoint (for enumeration/display)."""
        label = self._key_label(key)
        async with self._get_lock(label):
            if label not in self._ea_sites:
                self._check_cache_pressure(self._ea_sites, "ea_sites", "_ea_sites_full_warned")
                self._ea_sites[label] = await self._client.paginate("/ea/sites", key=key)
            return self._ea_sites[label]

    async def get_sites(
        self, host_id: str, *, key: APIKeyConfig | None = None
    ) -> list[dict[str, Any]]:
        """Return sites from the per-console proxy endpoint.

        Items have ``id`` (UUID) and ``description`` fields.  This is the
        authoritative source for site IDs used in proxy endpoint URLs.
        """
        label = self._key_label(key)
        cache_key = (label, host_id)
        async with self._get_lock(label):
            if cache_key not in self._sites:
                self._check_cache_pressure(self._sites, "sites", "_sites_full_warned")
                path = _PROXY_SITES_PATH.format(host_id=host_id)
                resp = await self._client.get(path, key=key)
                self._sites[cache_key] = resp.get("data", []) if isinstance(resp, dict) else resp
            return self._sites[cache_key]

    async def resolve_host_id(self, name_or_id: str, *, key: APIKeyConfig | None = None) -> str:
        """Resolve a host name or ID to a host ID.

        Raises ValueError if the resolved host ID contains characters unsafe for use
        in an API URL path segment.
        """
        hosts = await self.get_hosts(key=key)
        for host in hosts:
            if host.get("id") == name_or_id:
                validate_host_id(name_or_id, "host_id")
                return name_or_id
            if host.get("reportedState", {}).get("hostname", "").lower() == name_or_id.lower():
                resolved = host["id"]
                validate_host_id(resolved, "host_id")
                return resolved
            if host.get("name", "").lower() == name_or_id.lower():
                resolved = host["id"]
                validate_host_id(resolved, "host_id")
                return resolved
        # assume it's a raw ID — validate before using in a URL path
        validate_host_id(name_or_id, "host_id")
        return name_or_id

    async def resolve_site_id(
        self, name_or_id: str, host_id: str, *, key: APIKeyConfig | None = None
    ) -> str:
        """Resolve a site name or UUID to a UUID site ID via the console proxy.

        Matches on ``id`` (exact UUID), ``description``, or ``name`` (both case-insensitive).
        The Network Integration API may return either ``description`` or ``name`` for the
        human-readable site label depending on the firmware version; both are checked.
        Raises ValueError if the site cannot be found or the resolved ID is not a valid UUID.
        """
        sites = await self.get_sites(host_id, key=key)
        for site in sites:
            site_id = cast(str, site.get("id") or site.get("_id", ""))
            if site_id == name_or_id:
                _assert_uuid(name_or_id)
                return name_or_id
            site_label = (site.get("description") or site.get("name") or "").lower()
            if site_label and site_label == name_or_id.lower():
                _assert_uuid(site_id)
                return site_id
        raise ValueError(
            f"Site {name_or_id!r} not found on host {host_id!r}. "
            "Pass the site name or UUID as shown in list_sites output."
        )

    async def resolve_site_slug(
        self, name_or_id: str, host_id: str, *, key: APIKeyConfig | None = None
    ) -> str:
        """Resolve a site name or UUID to its internalReference slug (e.g. 'default').

        Used for Classic REST and v2 API endpoints that require the site slug rather than
        the UUID. Looks up ``internalReference`` from the proxy sites data.
        Falls back to the lower-cased description/name if internalReference is absent.
        Raises ValueError if the site cannot be found.
        """
        from .client import validate_id

        sites = await self.get_sites(host_id, key=key)
        for site in sites:
            site_id = cast(str, site.get("id") or site.get("_id", ""))
            site_label = (site.get("description") or site.get("name") or "").lower()
            if site_id == name_or_id or (site_label and site_label == name_or_id.lower()):
                slug = cast(str, site.get("internalReference") or site_label or name_or_id)
                validate_id(slug, "site_slug")
                return slug
        raise ValueError(
            f"Site {name_or_id!r} not found on host {host_id!r}. "
            "Pass the site name or UUID as shown in list_sites output."
        )

    async def resolve_ea_site_id(self, name_or_id: str, *, key: APIKeyConfig | None = None) -> str:
        """Resolve a site name or ID using the EA sites list.

        Used for /v1/sites/ and /ea/sites based endpoints that do not require
        a specific host_id for resolution. Matches on id, siteId, or siteName/description.
        Falls back to returning name_or_id as-is if no match is found.
        """
        sites = await self.get_ea_sites(key=key)
        for site in sites:
            for id_field in ("id", "siteId"):
                if site.get(id_field) == name_or_id:
                    return name_or_id
            for name_field in ("description", "siteName"):
                val = site.get(name_field, "")
                if isinstance(val, str) and val.lower() == name_or_id.lower():
                    resolved = site.get("siteId") or site.get("id", name_or_id)
                    return cast(str, resolved)
        return name_or_id  # assume it's already an ID

    async def set_hosts(
        self, hosts: list[dict[str, Any]], *, key: APIKeyConfig | None = None
    ) -> None:
        """Update the hosts cache under the async lock."""
        label = self._key_label(key)
        async with self._get_lock(label):
            self._hosts[label] = hosts

    async def set_ea_sites(
        self, sites: list[dict[str, Any]], *, key: APIKeyConfig | None = None
    ) -> None:
        """Update the EA sites cache under the async lock."""
        label = self._key_label(key)
        async with self._get_lock(label):
            self._ea_sites[label] = sites

    async def set_sites(
        self, host_id: str, sites: list[dict[str, Any]], *, key: APIKeyConfig | None = None
    ) -> None:
        """Update the proxy sites cache for a specific host under the async lock."""
        label = self._key_label(key)
        async with self._get_lock(label):
            self._sites[(label, host_id)] = sites

    def invalidate(self, *, key: APIKeyConfig | None = None) -> None:
        """Force cache refresh on next access.

        If key is None, invalidates all cached entries.
        """
        if key is not None:
            label = self._key_label(key)
            self._hosts.pop(label, None)
            self._ea_sites.pop(label, None)
            for cache_key in [k for k in self._sites if k[0] == label]:
                del self._sites[cache_key]
        else:
            self._hosts.clear()
            self._ea_sites.clear()
            self._sites.clear()
