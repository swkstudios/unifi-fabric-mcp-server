"""Device management tools — adopted devices, actions, stats, and pending devices."""

from __future__ import annotations

import weakref
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

from cachetools import TTLCache

from ...client import (
    RateLimitError,
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    object_records,
    upstream_error_text,
    upstream_error_value,
    validate_id,
)
from ...config import APIKeyConfig
from ...header_credentials import (
    MAX_CREDENTIAL_IDENTITIES,
    full_key_digest,
    header_mode_enabled,
    request_key_configs,
)
from ...macs import colon_mac, is_mac, normalize_mac, record_mac
from ...matching import id_key, same_id
from ...registry import Registry, _assert_uuid
from ...resolution_state import note_incomplete_resolution
from ...shared_shapes._classic_objects import (
    checked_classic_response,
    device_tag_update_body,
    device_tag_update_hint,
    resolve_device_tag,
    resolve_device_tag_record,
    resolve_site_slug,
    v2_root,
    v2_site,
)
from ...shared_shapes._keys import with_context
from ...shared_shapes._pagination import collect_offset, offset_list_result, validate_pagination
from ...shared_shapes._payload import missing_fields_hint, with_upstream_hint
from ...shared_shapes._results import deletion_result
from ..network.network import _proxy
from .schemas import (  # the family's shapes (family-owned layout)
    _CLASSIC_DEVMGR,
    _CLASSIC_SITEMGR,
    _DEFAULT_MAC_CACHE_TTL,
)

# Session-scoped cache: "{host_id}:{site_id}:{normalized_mac}" -> UUID
#: MAC -> device UUID lookups, per client instance (so one deployment's keys never
#: answer another's) and bounded with a TTL (a replaced device's MAC re-resolves). The TTL
#: is UNIFI_CACHE_TTL_SECONDS (the registry cache TTL; default 900); 0 disables caching.
_mac_uuid_cache: weakref.WeakKeyDictionary[UniFiClient, TTLCache[str, str]] = (
    weakref.WeakKeyDictionary()
)
_mac_uuid_identity_cache: weakref.WeakKeyDictionary[
    UniFiClient, dict[tuple[tuple[str, str], ...], TTLCache[str, str]]
] = weakref.WeakKeyDictionary()


def _mac_cache_ttl(client: UniFiClient) -> int:
    """UNIFI_CACHE_TTL_SECONDS of the client's settings (900 when not configured)."""
    ttl = getattr(getattr(client, "_settings", None), "cache_ttl_seconds", None)
    if isinstance(ttl, int) and not isinstance(ttl, bool) and ttl >= 0:
        return ttl
    return _DEFAULT_MAC_CACHE_TTL


def _mac_cache_for(client: UniFiClient) -> TTLCache[str, str] | None:
    """The client's MAC -> UUID cache, or ``None`` when UNIFI_CACHE_TTL_SECONDS is 0."""
    ttl = _mac_cache_ttl(client)
    if ttl == 0:
        return None
    if header_mode_enabled():
        # Header mode: one MAC -> UUID cache per credential identity set of the call
        # (labels + full key digests), never shared across callers' keys.
        identity = tuple(
            (cfg.label, full_key_digest(cfg.key)) for cfg in (request_key_configs() or [])
        )
        if not identity:
            return None
        per_identity = _mac_uuid_identity_cache.setdefault(client, {})
        cache = per_identity.pop(identity, None)
        if cache is not None:
            per_identity[identity] = cache  # most recently used goes last (LRU bound)
        if cache is None or cache.ttl != ttl:
            cache = TTLCache(maxsize=4096, ttl=ttl)
            per_identity[identity] = cache
            while len(per_identity) > MAX_CREDENTIAL_IDENTITIES:
                per_identity.pop(next(iter(per_identity)))
        return cache
    cache = _mac_uuid_cache.get(client)
    if cache is None or cache.ttl != ttl:
        cache = TTLCache(maxsize=4096, ttl=ttl)
        _mac_uuid_cache[client] = cache
    return cache


# The one MAC validator (``unifi_fabric.macs``), under the names this package uses.
_is_mac = is_mac
_normalize_mac = normalize_mac


def _record_mac(record: dict[str, Any]) -> str | None:
    """A listed device's MAC normalized (12 lowercase hex), or ``None`` when it has no
    usable MAC (absent, null, not a string, or not a MAC)."""
    for field in ("macAddress", "mac"):
        found = record_mac(record.get(field))
        if found is not None:
            return found
    return None


_colon_mac = colon_mac


# Physical device actions (restart, PoE power cycle, locate, firmware upgrade, forget,
# unadopt) are sent once: the client never retries a non-GET request on 429 (one rule,
# client.UniFiClient.request), because a 429 does not prove the controller did not act.


def _validate_device_ref(device_id: str, name: str = "device_id") -> None:
    """A device reference (a MAC, or an id safe for a URL path) or raise naming ``name``.

    Runs before any resolution or request, so a malformed reference makes no upstream call.
    """
    if not _is_mac(device_id):
        validate_id(device_id, name)


def _forget_cached_device(
    client: UniFiClient, host_id: str, *, mac: str | None = None, device_id: str | None = None
) -> None:
    """Drop every cached MAC -> id entry of a console for ``mac`` and/or ``device_id``.

    Called after unadopt, forget and adopt (a re-adopted device gets a new id, so a cached
    id would address the old one) and when a cached id answers HTTP 404.

    Every cache the client holds is swept: the environment-mode cache and, in header mode,
    the cache of every credential identity. The device changed upstream, so an entry cached
    under any caller's keys is stale; dropping one only forces a fresh device-list lookup.
    """
    caches = [_mac_uuid_cache.get(client)]
    caches.extend(list(_mac_uuid_identity_cache.get(client, {}).values()))
    suffix = f":{_normalize_mac(mac)}" if mac and _is_mac(mac) else None
    for cache in caches:
        if not cache:
            continue
        for cache_key, cached_id in list(cache.items()):
            if not cache_key.startswith(f"{host_id}:"):
                continue
            if (suffix and cache_key.endswith(suffix)) or (
                device_id and same_id(device_id, cached_id)
            ):
                cache.pop(cache_key, None)


async def _resolve_device_id(
    client: UniFiClient,
    host_id: str,
    site_id: str,
    device_id: str,
    *,
    key: APIKeyConfig | None = None,
) -> str:
    """Resolve a device_id to a UUID, performing MAC lookup if needed.

    If device_id is a MAC address (bare 12-hex or colon/hyphen-separated),
    fetch the site device list and return the matching device UUID.
    Results are cached per client and (host, site, mac) for 15 minutes.
    """
    resolved, _cached = await _resolve_device_id_cached(
        client, host_id, site_id, device_id, key=key
    )
    return resolved


async def _resolve_device_id_cached(
    client: UniFiClient,
    host_id: str,
    site_id: str,
    device_id: str,
    *,
    key: APIKeyConfig | None = None,
) -> tuple[str, bool]:
    """``_resolve_device_id`` plus whether the id came from the MAC cache."""
    if not _is_mac(device_id):
        return device_id, False

    normalized = _normalize_mac(device_id)
    cache = _mac_cache_for(client)
    cache_key = f"{host_id}:{site_id}:{normalized}"
    # One read (never "in" then "[]": an entry can expire between the two).
    cached = cache.get(cache_key) if cache is not None else None
    if cached is not None:
        return cached, True

    # The device list is offset-paginated (25 per page by default): drain every page so a
    # device past the first page is never reported as "not found".
    collected = await collect_offset(client, _proxy(host_id, f"/sites/{site_id}/devices"), key=key)
    url = _proxy(host_id, f"/sites/{site_id}/devices")
    listed = object_records(collected["items"], f"GET {url}")
    devices = [d for d in listed if _record_mac(d) is not None]
    matches = [d for d in devices if _record_mac(d) == normalized]
    ids = []
    for d in matches:
        uuid = d.get("id", d.get("_id"))
        if not isinstance(uuid, str) or not uuid:
            raise UniFiConnectionError(
                f"Unexpected response shape from GET {url}: device with MAC {device_id!r} "
                f"needs a non-empty string native id; identifying fields: "
                f"name={upstream_error_text(d.get('name'), client)!r}, "
                f"macAddress={upstream_error_text(d.get('macAddress'), client)!r}, "
                f"mac={upstream_error_text(d.get('mac'), client)!r}, "
                f"id={upstream_error_text(d.get('id'), client)!r}, "
                f"_id={upstream_error_text(d.get('_id'), client)!r}"
            )
        ids.append(uuid)
    if len({id_key(i) for i in ids}) > 1:
        choices = "; ".join(
            f"{upstream_error_text(d.get('name'), client)!r} (id={upstream_error_value(i)}, "
            f"mac={_record_mac(d)})"
            for d, i in zip(matches, ids, strict=True)
        )
        raise ValueError(
            f"MAC {device_id!r} matches distinct device ids in site {site_id!r}: "
            f"{choices}. Pass the device id."
        )
    if ids:
        uuid = ids[0]
        if collected["incomplete"]:
            note_incomplete_resolution(collected["incompleteReason"])
        elif cache is not None:
            cache[cache_key] = uuid
        return uuid, False

    if collected["incomplete"]:
        evidence = [(d.get("name"), d.get("id"), _record_mac(d)) for d in devices]
        raise ValueError(
            f"Cannot resolve MAC {device_id!r} in site {site_id!r}: the device list is "
            f"incomplete ({upstream_error_value(collected['incompleteReason'])}). No id was "
            f"cached. Read so far: {upstream_error_text(evidence, client)}."
        )
    valid = "; ".join(
        f"{upstream_error_text(d.get('name'), client)} "
        f"(mac={upstream_error_text(d.get('macAddress') or d.get('mac'), client)}, "
        f"id={upstream_error_text(d.get('id'), client)})"
        for d in devices
    )
    skipped = len(listed) - len(devices)
    if skipped:
        valid = (
            f"{valid or '(none)'}; {skipped} listed entr{'y' if skipped == 1 else 'ies'} "
            "without a usable MAC skipped (address those by UUID)"
        )
    raise ValueError(
        f"Device with MAC {device_id!r} not found in site {site_id!r}; valid: "
        f"{valid or '(none)'}. Get it from list_site_devices (data[].macAddress or data[].id)."
    )


async def _call_with_device_id(
    client: UniFiClient,
    host_id: str,
    site_id: str,
    device_id: str,
    call: Callable[[str], Awaitable[Any]],
    *,
    key: APIKeyConfig | None,
    write: bool,
) -> Any:
    """Resolve ``device_id`` (UUID or MAC) and make ``call`` with the device UUID.

    When the UUID came from the MAC cache and the controller answers HTTP 404, the cached
    entry is dropped and the MAC is re-resolved once from the device list (a GET-side
    refresh). If the MAC still resolves to the same id the 404 is real: the original
    upstream error is raised unchanged and nothing is repeated. Otherwise a read is made
    again with the fresh id; a write is NEVER re-sent: the error names the stale and the
    fresh id so the caller can repeat the call.
    """
    resolved, cached = await _resolve_device_id_cached(client, host_id, site_id, device_id, key=key)
    validate_id(resolved, "device_id")
    try:
        return await call(resolved)
    except UniFiConnectionError as exc:
        if not (cached and str(exc).startswith("HTTP 404 from ")):
            raise
        _forget_cached_device(client, host_id, mac=device_id, device_id=resolved)
        try:
            fresh = await _resolve_device_id(client, host_id, site_id, device_id, key=key)
            validate_id(fresh, "device_id")
        except (ValueError, UniFiConnectionError, RateLimitError) as refresh_exc:
            raise UniFiConnectionError(
                f"{exc} -- MAC lookup refresh for {device_id!r} failed: {refresh_exc}"
            ) from exc
        if fresh == resolved:
            raise exc  # a real 404: the cache was not stale
        if not write:
            try:
                return await call(fresh)
            except (ValueError, UniFiConnectionError, RateLimitError) as retry_exc:
                raise UniFiConnectionError(
                    f"{exc} -- read retry with refreshed device id {fresh} failed: {retry_exc}"
                ) from exc
        raise UniFiConnectionError(
            f"{exc} -- the device id {resolved} came from the MAC lookup cache and is stale: "
            f"MAC {device_id} now resolves to {fresh}. The write was not re-sent; call the "
            "tool again to act on the current device."
        ) from None


async def _device_mac(
    client: UniFiClient,
    host_id: str,
    site_id: str,
    device_id: str,
    *,
    key: APIKeyConfig | None,
) -> str:
    """The MAC of an adopted device given its MAC (returned normalized) or Integration UUID.

    A MAC is resolved against the site device list first, so a MAC that is not an adopted
    device of the site fails listing the valid devices before any command is sent. A UUID
    is read with the Integration device GET; a body without ``macAddress`` raises with the
    shape received.
    """
    if _is_mac(device_id):
        await _resolve_device_id(client, host_id, site_id, device_id, key=key)
        return _colon_mac(device_id)
    validate_id(device_id, "device_id")
    path = _proxy(host_id, f"/sites/{site_id}/devices/{device_id}")
    device = await client.get(path, key=key)
    mac = device.get("macAddress") if isinstance(device, dict) else None
    normalized = record_mac(mac)
    if normalized is None:
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected a device object with a "
            f"valid 'macAddress', got {describe_shape(device)}; "
            f"received macAddress={upstream_error_value(mac, client)!r}"
        )
    return _colon_mac(normalized)


def _physical_preview(response: Any, consequence: str) -> Any:
    """Add a physical-action warning only to the client's dry-run preview."""
    if is_dry_run_preview(response):
        return with_context(response, {"_consequence": consequence})
    return response


async def _classic_devmgr(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    cmd: str,
) -> Any:
    """POST ``{"cmd": cmd, "mac": mac}`` (the device MAC) to the Classic device manager.

    Returns the controller's ``{meta, data}`` envelope verbatim.
    """
    _validate_device_ref(device_id)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    mac = await _device_mac(client, host_id, site_id, device_id, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    url = _CLASSIC_DEVMGR.format(host_id=host_id, site_slug=site_slug)
    response = checked_classic_response(
        await client.post(url, key=key, json={"cmd": cmd, "mac": mac}), url, client=client, key=key
    )
    if is_dry_run_preview(response):
        return with_context(
            response, {"_consequence": "Device actions may interrupt connectivity."}
        )
    return response


async def _classic_device_command(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    suffix: str,
    fields: dict[str, Any],
    *,
    plural: bool,
) -> Any:
    """Source-defined MAC-addressed command, sent once; preserve upstream bodies."""
    _validate_device_ref(device_id)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    mac = await _device_mac(client, host_id, site_id, device_id, key=key)
    slug = await registry.resolve_site_slug(site, host_id, key=key)
    path = _CLASSIC_DEVMGR.format(host_id=host_id, site_slug=slug) + suffix
    body = dict(fields)
    body["macs" if plural else "mac"] = [mac] if plural else mac
    response = await client.post(path, key=key, json=body)
    response = checked_classic_response(response, path, client=client, key=key)
    if is_dry_run_preview(response):
        return with_context(
            response,
            {"_consequence": "Reprovisioning or upgrading the device may disconnect clients."},
        )
    return response


# --- Adopted Devices ---


async def _list_site_devices(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    offset: int | None = None,
    limit: int | None = None,
    *,
    filter: str | None = None,
) -> dict[str, Any]:
    """List all adopted devices for a site.

    By default every offset page is drained and the complete device list is
    returned as ``{data, totalCount}``. Passing offset or limit selects manual
    paging: a single page is returned with the API's totalCount. A drain that
    hits the page cap returns the devices gathered so far with incomplete=true
    rather than truncating silently. ``filter`` is a server-side filter (not
    paging), forwarded unchanged as the Network Integration API ``filter`` query
    parameter and applied in either mode; when ``None`` it is omitted rather than
    sent as the string ``"None"``.
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    url = _proxy(host_id, f"/sites/{site_id}/devices")
    base: dict[str, Any] = {}
    if filter is not None:
        base["filter"] = filter
    collected = await collect_offset(
        client, url, key=key, params=base or None, offset=offset, limit=limit
    )
    return offset_list_result(collected)


async def _adopt_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: dict[str, Any],
) -> dict[str, Any]:
    """Adopt a device onto a site."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    try:
        response = await client.post(
            _proxy(host_id, f"/sites/{site_id}/devices"), key=key, json=device
        )
        return _physical_preview(
            response, "Adoption reprovisions the device and may disconnect clients."
        )
    finally:
        # An adopted device gets a new id: drop any id cached for its MAC.
        mac = device.get("macAddress") or device.get("mac") if isinstance(device, dict) else None
        _forget_cached_device(client, host_id, mac=mac if isinstance(mac, str) else None)


async def _get_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
) -> dict[str, Any]:
    """Get details for a single adopted device."""
    _validate_device_ref(device_id)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)

    async def _get(uuid: str) -> Any:
        return await client.get(_proxy(host_id, f"/sites/{site_id}/devices/{uuid}"), key=key)

    return await _call_with_device_id(
        client, host_id, site_id, device_id, _get, key=key, write=False
    )


async def _unadopt_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
) -> Any:
    """Unadopt (remove) a device from a site.

    ``device_id`` is the device UUID or its MAC (resolved to the UUID like get_device; an
    unknown MAC fails listing the site's devices). Not auto-retried on HTTP 429.
    """
    _validate_device_ref(device_id)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    target = device_id

    async def _delete(uuid: str) -> Any:
        try:
            response = await client.delete(
                _proxy(host_id, f"/sites/{site_id}/devices/{uuid}"),
                key=key,
            )
            return _physical_preview(
                response, "Unadopting removes device management from this site."
            )
        finally:
            # The device leaves the site (or may have: a 429 does not prove it did not):
            # a re-adopted device gets a new id, so the cached MAC -> id entry must go.
            _forget_cached_device(client, host_id, mac=target, device_id=uuid)

    return await _call_with_device_id(
        client, host_id, site_id, device_id, _delete, key=key, write=True
    )


async def _execute_device_action(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    action: dict[str, Any],
) -> dict[str, Any]:
    """Execute a device action via the Integration device-actions route (spec: RESTART).

    ``device_id`` is the device UUID or its MAC (resolved to the UUID; an unknown MAC fails
    listing the site's devices). Not auto-retried on HTTP 429 (a physical action).
    """
    _validate_device_ref(device_id)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)

    async def _act(uuid: str) -> Any:
        return await client.post(
            _proxy(host_id, f"/sites/{site_id}/devices/{uuid}/actions"),
            key=key,
            json=action,
        )

    response = await _call_with_device_id(
        client, host_id, site_id, device_id, _act, key=key, write=True
    )
    return _physical_preview(
        response, "Device actions may restart the device and disconnect clients."
    )


async def _get_device_statistics(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
) -> dict[str, Any]:
    """Get latest statistics for a device."""
    _validate_device_ref(device_id)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)

    async def _stats(uuid: str) -> Any:
        return await client.get(
            _proxy(host_id, f"/sites/{site_id}/devices/{uuid}/statistics/latest"), key=key
        )

    return await _call_with_device_id(
        client, host_id, site_id, device_id, _stats, key=key, write=False
    )


async def _execute_port_action(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    port_idx: int,
    action: dict[str, Any],
) -> dict[str, Any]:
    """Execute a device port action.

    ``device_id`` is the device UUID or its MAC (resolved to the UUID; an unknown MAC fails
    listing the site's devices). Not auto-retried on HTTP 429 (a PoE power cycle is a
    physical action).
    """
    _validate_device_ref(device_id)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)

    async def _port(uuid: str) -> Any:
        return await client.post(
            _proxy(
                host_id,
                f"/sites/{site_id}/devices/{uuid}/interfaces/ports/{port_idx}/actions",
            ),
            key=key,
            json=action,
        )

    response = await _call_with_device_id(
        client, host_id, site_id, device_id, _port, key=key, write=True
    )

    return _physical_preview(
        response, "Port actions may interrupt power or connectivity to attached devices."
    )


async def _restart_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    reboot_type: str | None = None,
) -> dict[str, Any]:
    """Restart an adopted device: Integration ``{"action": "RESTART"}`` (the spec's only value)."""
    if reboot_type is not None:
        return await _classic_device_command(
            client,
            registry,
            host,
            site,
            device_id,
            "",
            {"cmd": "restart", "reboot_type": reboot_type},
            plural=True,
        )
    return await _execute_device_action(
        client, registry, host, site, device_id, {"action": "RESTART"}
    )


async def _locate_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    enabled: bool = True,
) -> Any:
    """Toggle the locate LED via the Classic device manager (set-locate / unset-locate)."""
    cmd = "set-locate" if enabled else "unset-locate"
    return await _classic_devmgr(client, registry, host, site, device_id, cmd)


async def _upgrade_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    firmware_url: str | None = None,
) -> Any:
    """Trigger a firmware upgrade via the Classic device manager (``cmd: upgrade``)."""
    if firmware_url is not None and firmware_url != "":
        try:
            parsed = urlsplit(firmware_url)
            valid = parsed.scheme.lower() in {"http", "https"} and bool(parsed.hostname)
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise ValueError("firmware_url must be an http or https URL with a host.")
        return await _classic_device_command(
            client,
            registry,
            host,
            site,
            device_id,
            "/upgrade-external",
            {"url": firmware_url},
            plural=True,
        )
    return await _classic_devmgr(client, registry, host, site, device_id, "upgrade")


# --- Pending Devices ---


async def _list_pending_devices(
    client: UniFiClient,
    registry: Registry,
    host: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
    filter: str | None = None,
) -> dict[str, Any]:
    """List devices pending adoption on a console (``filter`` forwarded when given).

    Drains every page by default; ``offset`` / ``limit`` fetch one page (native envelope).
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    params = {"filter": filter} if filter is not None else None
    collected = await collect_offset(
        client,
        _proxy(host_id, "/pending-devices"),
        key=key,
        params=params,
        offset=offset,
        limit=limit,
    )
    return offset_list_result(collected)


# --- Device Tags ---


async def _create_device_tag(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    tag: dict[str, Any],
    /,
) -> Any:
    """Create a device tag on a site via the v2 API the controller UI uses.

    POST /v2/api/site/{site}/device-tags with the caller's body verbatim; the upstream
    body (the created tag, with its ``_id``) is returned verbatim. ``name`` and
    ``member_device_macs`` are required: the controller answers a bare HTTP 500 without
    the member list.
    """
    hint = missing_fields_hint(
        "create_device_tag",
        tag,
        ("name", "member_device_macs"),
        "the controller answers a bare HTTP 500 without the member list",
    )
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await with_upstream_hint(
        client.post(v2_site(host_id, site_slug, "/device-tags"), key=key, json=tag), hint
    )


async def _update_device_tag(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    tag_id: str,
    tag: dict[str, Any],
    /,
) -> Any:
    """Update a device tag via the v2 API.

    The tag is given by its v2 ``_id`` or its name (exact, then case-insensitive, then
    edge-whitespace stripped).

    PUT /v2/api/site/{site}/device-tags/{_id}; the upstream body (the updated tag) is
    returned verbatim. A caller ``_id`` must match the resolved tag and is then omitted
    (this PUT rejects it). ``tag`` is either the native body, which needs
    ``device_mac_additions`` and ``device_mac_removals`` (the controller answers a bare HTTP
    500 without them), or an edited list_device_tags entry, whose ``member_device_macs`` is
    turned into those two lists against the current tag (see device_tag_update_body).
    """
    key, host_id, site_slug, current = await resolve_device_tag_record(
        client, registry, host, site, tag_id
    )
    upstream_id = current["_id"]
    if "_id" in tag and not (isinstance(tag["_id"], str) and same_id(tag["_id"], upstream_id)):
        raise ValueError(
            f"device tag body _id {tag['_id']!r} does not match the resolved "
            f"record _id {upstream_error_value(upstream_id)!r}. Remove the body _id or use the "
            "resolved _id. No write was sent."
        )
    # This v2 PUT rejects _id; validate it before either payload form drops it.
    fields = {key: value for key, value in tag.items() if key != "_id"}
    body = device_tag_update_body(fields, current)
    return await with_upstream_hint(
        client.put(v2_site(host_id, site_slug, f"/device-tags/{upstream_id}"), key=key, json=body),
        device_tag_update_hint(tag),
    )


async def _delete_device_tag(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    tag_id: str,
) -> dict[str, Any]:
    """Delete a device tag via the v2 API.

    The tag is given by its v2 ``_id`` or its name (exact, then case-insensitive, then
    edge-whitespace stripped).

    DELETE /v2/api/device-tags/{_id}: the controller serves this delete without a site
    segment (the site-scoped path answers 405), after the tag is resolved in the site.
    """
    key, host_id, _site_slug, resolved = await resolve_device_tag(
        client, registry, host, site, tag_id
    )
    response = await client.delete(v2_root(host_id, f"/device-tags/{resolved}"), key=key)
    return deletion_result(f"Device tag {resolved} deleted.", response)


# --- Pending Device Actions ---


async def _approve_pending_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    ignore_device_limit: bool,
) -> dict[str, Any]:
    """Approve (adopt) a pending device onto a site via the spec's adoptDevice route.

    Pending devices are identified by MAC (the published "Device pending adoption" schema
    has no id field), so ``device_id`` is the pending device's ``macAddress``. The body is
    the spec's IntegrationDeviceAdoptionRequestDto, whose ``macAddress`` and
    ``ignoreDeviceLimit`` are both required.
    """
    if not _is_mac(device_id):
        raise ValueError(
            f"device_id {device_id!r} is not a MAC address: a pending device is identified by "
            "its macAddress (list_pending_devices data[].macAddress), e.g. "
            "'02:00:5e:00:00:a1'."
        )
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    try:
        response = await client.post(
            _proxy(host_id, f"/sites/{site_id}/devices"),
            key=key,
            json={"macAddress": _colon_mac(device_id), "ignoreDeviceLimit": ignore_device_limit},
        )
        return _physical_preview(
            response, "Adoption may restart the device and disconnect clients."
        )
    finally:
        # Adoption assigns a new id: drop any id cached for this MAC.
        _forget_cached_device(client, host_id, mac=device_id)


async def _forget_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    mac: str | list[str],
) -> Any:
    """Forget (remove) one or more devices from the controller via the Classic site manager.

    Sends ``{"cmd": "delete-device", "mac": mac}``, the request the controller UI's
    "Forget device" sends, once per MAC (the multi-MAC ``macs`` body is not proven to be
    read by the controller; see ``_CLASSIC_SITEMGR``). Works for adopted and pending
    devices (both are addressed by MAC).

    A single MAC (``mac`` a string): returns the controller's ``{meta, data}`` envelope
    verbatim; an upstream error (e.g. HTTP 400 ``api.err.UnknownDevice`` for a MAC the
    controller does not know) is raised with the full upstream body.

    A list (``mac`` a list, whatever its length, duplicates included): always returns
    ``{byMac, forgotten, errors}`` - ``byMac`` maps each MAC that succeeded (lowercase colon
    form, duplicates collapsed) to its envelope verbatim, ``forgotten`` lists those MACs in
    request order, and ``errors`` lists ``{mac, error}`` with the full upstream error for
    each MAC that failed (``[]`` when none did). It raises only when every MAC failed,
    quoting each MAC's error; a one-MAC list whose MAC fails therefore raises too.

    Under ``dry-run policy`` nothing is sent: a string returns the dry-run preview as is, and
    a list returns ``{status: "dry_run", byMac, errors}`` with each MAC's preview under
    ``byMac`` (no ``forgotten``: nothing was forgotten).

    Not auto-retried on HTTP 429 (no non-GET request is).
    """
    macs = [mac] if isinstance(mac, str) else list(mac)
    if not macs:
        raise ValueError(
            "mac is empty: pass one device MAC (e.g. 'aa:bb:cc:dd:ee:ff') or a non-empty list "
            "of MACs. Get them from list_site_devices (data[].macAddress) or "
            "list_pending_devices (data[].macAddress)."
        )
    bad = [m for m in macs if not isinstance(m, str) or not _is_mac(m)]
    if bad:
        raise ValueError(
            f"Not a MAC address: {bad!r}. Pass device MACs (any separator style, e.g. "
            "'aa:bb:cc:dd:ee:ff' or 'AABBCCDDEEFF'); get them from list_site_devices "
            "(data[].macAddress) or list_pending_devices (data[].macAddress)."
        )
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _assert_uuid(site_id)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    colon = list(dict.fromkeys(_colon_mac(m) for m in macs))
    url = _CLASSIC_SITEMGR.format(host_id=host_id, site_slug=site_slug)

    async def _forget_one(m: str) -> Any:
        try:
            response = checked_classic_response(
                await client.post(url, key=key, json={"cmd": "delete-device", "mac": m}),
                url,
                client=client,
                key=key,
            )
            return _physical_preview(response, "Forgetting removes the device from this site.")
        finally:
            # A forgotten device re-adopts under a new id: drop the cached MAC -> id.
            _forget_cached_device(client, host_id, mac=m)

    if isinstance(mac, str):
        return await _forget_one(colon[0])

    by_mac: dict[str, Any] = {}
    errors: list[dict[str, str]] = []
    for m in colon:
        try:
            by_mac[m] = await _forget_one(m)
        except (UniFiConnectionError, RateLimitError) as exc:
            errors.append({"mac": m, "error": str(exc)})
    if not by_mac:
        detail = "; ".join(f"{e['mac']}: {e['error']}" for e in errors)
        raise UniFiConnectionError(f"forget_device: every MAC failed ({len(errors)}): {detail}")
    if all(is_dry_run_preview(body) for body in by_mac.values()):
        return {"status": "dry_run", "byMac": by_mac, "errors": errors}
    return {"byMac": by_mac, "forgotten": list(by_mac), "errors": errors}
