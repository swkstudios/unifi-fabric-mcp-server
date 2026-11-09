"""Device management tools — adopted devices, actions, stats, and pending devices."""

from __future__ import annotations

import weakref
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

from cachetools import TTLCache
from fastmcp import FastMCP

from ..client import (
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
from ..config import APIKeyConfig
from ..header_credentials import (
    MAX_CREDENTIAL_IDENTITIES,
    full_key_digest,
    header_mode_enabled,
    request_key_configs,
)
from ..macs import colon_mac, is_mac, normalize_mac, record_mac
from ..matching import id_key, same_id
from ..registry import Registry, _assert_uuid
from ..resolution_state import note_incomplete_resolution
from ..tool_annotations import READ_ONLY, WRITE
from ._classic_objects import (
    checked_classic_response,
    device_tag_update_body,
    device_tag_update_hint,
    resolve_device_tag,
    resolve_device_tag_record,
    resolve_site_slug,
    v2_root,
    v2_site,
)
from ._keys import with_context
from ._pagination import collect_offset, offset_list_result, validate_pagination
from ._payload import missing_fields_hint, with_upstream_hint
from ._results import deletion_result
from .network import _proxy

# Session-scoped cache: "{host_id}:{site_id}:{normalized_mac}" -> UUID
#: MAC -> device UUID lookups, per client instance (so one deployment's keys never
#: answer another's) and bounded with a TTL (a replaced device's MAC re-resolves). The TTL
#: is UNIFI_CACHE_TTL_SECONDS (the registry cache TTL; default 900); 0 disables caching.
_mac_uuid_cache: weakref.WeakKeyDictionary[UniFiClient, TTLCache[str, str]] = (
    weakref.WeakKeyDictionary()
)
_DEFAULT_MAC_CACHE_TTL = 900
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


# Classic REST device manager: /proxy/network/api/s/{site_slug}/cmd/devmgr. The published
# Network Integration device-action schema (Network 11.0.97, "Device action request")
# lists only RESTART, and the controller rejects every other action there with HTTP 400
# api.request.unknown-type-id "valid values: 'RESTART'" (verified live on 11.x). Locate and
# firmware upgrade are therefore sent to the Classic device manager, addressed by MAC.
_CLASSIC_DEVMGR = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/cmd/devmgr"

# Classic REST site manager: /proxy/network/api/s/{site_slug}/cmd/sitemgr. Its
# delete-device command is what the controller UI's "Forget device" sends, addressed by
# one MAC ({"cmd": "delete-device", "mac": ...}). No published spec covers it; verified live
# on Network 11.0.81 (an unknown MAC answers HTTP 400 api.err.UnknownDevice). A multi-MAC
# {"macs": [...]} body has no live evidence: probed on 2026-10-10 with two absent MACs it
# answered exactly what the single-MAC form does (HTTP 400 api.err.UnknownDevice, data []),
# with nothing showing the field was read, so several MACs are sent one request each.
_CLASSIC_SITEMGR = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/cmd/sitemgr"

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


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all device management MCP tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def list_site_devices(
        host: str,
        site: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all adopted devices for a site via connector proxy.

        Returns {data, totalCount}: every page is drained; data holds the device records verbatim
        and totalCount is the upstream total (null when none was reported). The first page's other
        envelope fields are kept beside them, and incomplete / incompleteReason are added when a
        capped drain stopped short.

        By default every page is drained and the complete device list is returned.

        Required arguments: host, site (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            offset: Optional zero-based starting record; alone, fetch one page manually (the
                API's totalCount is surfaced so you can advance).
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain every page.
                Example: `25`.
            filter: optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `state.eq('ONLINE')`, `model.eq('U6 Pro')`); omitted entirely when unset. A capped
                drain returns the devices gathered so far with incomplete=true rather than
                truncating silently.
                Example: `name.eq('Office Switch')`.
        """
        client, registry = deps_fn()
        return await _list_site_devices(
            client, registry, host, site, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def adopt_device(
        host: str,
        site: str,
        device: dict[str, Any],
        confirm: bool = False,
    ) -> Any:
        """Adopt a device onto a site.

        Consequence: the site's controller takes over and provisions the device, which may restart
        while it applies its new configuration.

        Returns the upstream response body verbatim: the adopted device object the API answers with
        .

        Request body (Network 11.0.97, POST /v1/sites/{siteId}/devices (adoptDevice); schema
        "IntegrationDeviceAdoptionRequestDto") is passed in `device`. Required keys —
        ignoreDeviceLimit, macAddress.
        - ignoreDeviceLimit: boolean
        - macAddress: string

        Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#adopt_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device: Request body; spec IntegrationDeviceAdoptionRequestDto. Required:
                ignoreDeviceLimit, macAddress.
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
        """
        client, registry = deps_fn()
        return await _adopt_device(client, registry, host, site, device)

    @mcp.tool(annotations=READ_ONLY)
    async def get_device(
        host: str,
        site: str,
        device_id: str,
    ) -> Any:
        """Get details for a single adopted device.

        Returns the upstream device object verbatim, exactly as the API answers it.

        Example call (get_device):
            {
              "host": "my-console",
              "site": "Default",
              "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            device_id: Adopted device UUID or MAC (AA:BB:CC:DD:EE:FF, AABBCCDDEEFF, aa-bb-...). Get
                it from list_site_devices (data[].id). Network-app UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await _get_device(client, registry, host, site, device_id)

    @mcp.tool(annotations=WRITE)
    async def unadopt_device(
        host: str,
        site: str,
        device_id: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Unadopt (remove) a device from a site.

        Consequence: removes the device's association with the site; it must be re-adopted to be
        managed again.

        Returns {deleted: true, message, response}, with the upstream DELETE body in response (JSON,
        text or null). Under dry-run policy nothing is sent; returns {status: "dry_run", deleted:
        false, message, response: {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}, _consequence}}. Never automatically retried.

        Example: docs/TOOL-USAGE.md#unadopt_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC, not a Protect id.
                Get it from list_site_devices (data[].id or data[].macAddress).
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
        """
        client, registry = deps_fn()
        response = await _unadopt_device(client, registry, host, site, device_id)
        return deletion_result(f"Device {device_id} unadopted.", response)

    @mcp.tool(annotations=WRITE)
    async def execute_device_action(
        host: str,
        site: str,
        device_id: str,
        action: dict[str, Any],
        confirm: bool = False,
    ) -> Any:
        """Execute an action on an adopted device via the Network Integration actions route.

        Consequence: RESTART reboots the device, which is offline (and its clients or downstream
        devices interrupted) until it comes back.

        Returns the upstream response body verbatim: the action-result object the API answers with
        .

        `action` is the action body {"action": "RESTART"}; RESTART is the only variant in
        the published Device action request schema (Network 11.0.97), and the controller
        rejects any other value with HTTP 400 api.request.unknown-type-id (verified live).
        For the locate LED use locate_device and for firmware use upgrade_device (both use
        the Classic device manager, cmd/devmgr); adopt a pending device with adopt_device or
        approve_pending_device. Not auto-retried on HTTP 429: a retry could repeat the action.

        Request body (Network 11.0.97, POST /v1/sites/{siteId}/devices/{deviceId}/actions
        (executeAdoptedDeviceAction); schema "Device action request") is passed in `action`.
        Required keys — action.
        - action: string
        Variants by `action` — RESTART requires action.

        Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#execute_device_action.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC, not a Protect id.
                Get it from list_site_devices (data[].id or data[].macAddress).
            action: Action body; spec Device action request. Required: action. 'action' selects
                variant: RESTART.
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
        """
        client, registry = deps_fn()
        return await _execute_device_action(client, registry, host, site, device_id, action)

    @mcp.tool(annotations=READ_ONLY)
    async def get_device_statistics(
        host: str,
        site: str,
        device_id: str,
    ) -> Any:
        """Get latest statistics for a device.

        Returns the upstream latest-statistics object verbatim, exactly as the API answers it.

        Example call (get_device_statistics):
            {
              "host": "my-console",
              "site": "Default",
              "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            device_id: Adopted device UUID or MAC (AA:BB:CC:DD:EE:FF, AABBCCDDEEFF, aa-bb-...). Get
                it from list_site_devices (data[].id). Network-app UUID — not a Protect id.
        """
        client, registry = deps_fn()
        return await _get_device_statistics(client, registry, host, site, device_id)

    @mcp.tool(annotations=WRITE)
    async def execute_port_action(
        host: str,
        site: str,
        device_id: str,
        port_idx: int,
        action: dict[str, Any],
        confirm: bool = False,
    ) -> Any:
        """Execute a device port action.

        Consequence: POWER_CYCLE cuts port PoE power; the device reboots and is
        offline until it comes back.

        OPERATIONAL-ACTION-ONLY, NOT A CONFIG WRITER: this UniFi Network Integration API
        port-actions endpoint performs a transient operational action; it does NOT persist
        port configuration. `action` (shape {'action': str}) is forwarded verbatim. A PoE
        power cycle ({'action': 'POWER_CYCLE'}, the spec's only documented "Port action
        request" value) is the only valid action: it powers a PoE port off and back on (only
        meaningful on PoE-capable ports). The controller rejects every other value (e.g.
        'power-cycle', {'action': 'set-poe-mode'}) with HTTP 400 'unknown-type-id' and leaves
        the port unchanged (verified live). Never use it to set PoE mode, STP, VLAN, or any
        persistent port setting: there is no confirmed per-port persistent-config writer on
        this API, and a shared Ethernet Port Profile (update_port_profile) is a different,
        wide-blast-radius surface. Not auto-retried on HTTP 429: a retry could repeat the
        power cycle. Returns the upstream body verbatim.

        Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}, _consequence}.

        Request body (Network 11.0.97, POST
        /v1/sites/{siteId}/devices/{deviceId}/interfaces/ports/{portIdx}/actions
        (executePortAction); schema "Port action request") is passed in `action`. Required keys —
        action.
        - action: string
        Variants by `action` — POWER_CYCLE requires action.

        Example call (execute_port_action):
            {
              "host": "my-console",
              "site": "Default",
              "device_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "port_idx": 1,
              "action": {"action": "POWER_CYCLE"}
            }

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC, not a Protect id.
                Get it from list_site_devices (data[].id or data[].macAddress).
            port_idx: 1-based physical switch port number.
            action: Port action body; required field action must be "POWER_CYCLE".
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
        """
        client, registry = deps_fn()
        return await _execute_port_action(client, registry, host, site, device_id, port_idx, action)

    @mcp.tool(annotations=WRITE)
    async def restart_device(
        host: str,
        site: str,
        device_id: str,
        confirm: bool = False,
        reboot_type: str | None = None,
    ) -> Any:
        """Restart an adopted device.

        Consequence: the device reboots and is offline (and its clients or downstream devices
        interrupted) until it comes back.

        Omit reboot_type to use the Integration restart. Set reboot_type to soft or hard
        to use Classic cmd/devmgr with {cmd: restart, macs: [mac], reboot_type}.
        A hard restart also power-cycles PoE ports, interrupting powered downstream devices.
        Transport failure leaves the outcome unknown; read back before retrying.

        Sends {"action": "RESTART"} to the Network Integration device-actions route (Network
        11.0.97, POST /v1/sites/{siteId}/devices/{deviceId}/actions, executeAdoptedDeviceAction;
        schema "Device action request", whose only variant is RESTART). Returns the upstream body
        verbatim. Not auto-retried on HTTP 429: a retry could repeat the action.

        Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#restart_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC, not a Protect id.
                Get it from list_site_devices (data[].id or data[].macAddress).
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
            reboot_type: Optional Classic reboot type, e.g. "hard" or "soft"; omitted
                selects the existing Integration RESTART route.
        """
        client, registry = deps_fn()
        return await _restart_device(client, registry, host, site, device_id, reboot_type)

    @mcp.tool(annotations=WRITE)
    async def locate_device(
        host: str,
        site: str,
        device_id: str,
        enabled: bool = True,
        confirm: bool = False,
    ) -> Any:
        """Toggle the locate LED on an adopted device.

        Consequence: the device's LED flashes until locate is turned off (enabled=false).

        Locate is not in the published Network Integration device-action schema (its only
        variant is RESTART), so this uses the Classic REST device manager: POST
        network/api/s/{site}/cmd/devmgr with {"cmd": "set-locate", "mac": "aa:bb:cc:dd:ee:ff"}
        (enabled=true) or {"cmd": "unset-locate", "mac": ...} (enabled=false), where mac is the
        device MAC. A device UUID is resolved to its MAC with the Integration device GET. Returns
        the controller's Classic envelope {meta: {rc}, data: [...]} verbatim (verified live:
        {"meta": {"rc": "ok"}, "data": []}). Not auto-retried on HTTP 429: a retry could repeat
        the action.

        Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#locate_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC, not a Protect id.
                Get it from list_site_devices (data[].id or data[].macAddress).
            enabled: true = start locate LED blink, false = stop.
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
        """
        client, registry = deps_fn()
        return await _locate_device(client, registry, host, site, device_id, enabled)

    @mcp.tool(annotations=WRITE)
    async def upgrade_device(
        host: str,
        site: str,
        device_id: str,
        confirm: bool = False,
        firmware_url: str | None = None,
    ) -> Any:
        """Trigger a firmware upgrade on an adopted device.

        Consequence: the device installs the firmware and reboots, and is offline until it comes
        back.

        With firmware_url supplied, POST cmd/devmgr/upgrade-external sends
        {url: firmware_url, macs: [mac]}. Choose firmware compatible with the device;
        an incorrect image can prevent it from booting. Transport failure leaves the
        outcome unknown; read back before retrying. This route is source-defined and
        needs live testing.

        Upgrade is not in the published Network Integration device-action schema (its only
        variant is RESTART), so this uses the Classic REST device manager: POST
        network/api/s/{site}/cmd/devmgr with {"cmd": "upgrade", "mac": "aa:bb:cc:dd:ee:ff"}
        (mac is the device MAC), which upgrades the device to the controller's cached latest
        firmware. A device UUID is
        resolved to its MAC with the Integration device GET. Returns the controller's Classic
        envelope {meta: {rc}, data: [...]} verbatim. Not auto-retried on HTTP 429: a retry
        could repeat the action.

        Under dry-run policy nothing is sent; returns {status: "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#upgrade_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC, not a Protect id.
                Get it from list_site_devices (data[].id or data[].macAddress).
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
            firmware_url: Optional http or https firmware image URL; empty selects the standard
                upgrade.
                Omit to use the controller cached latest firmware.
        """
        client, registry = deps_fn()
        return await _upgrade_device(client, registry, host, site, device_id, firmware_url)

    @mcp.tool(annotations=READ_ONLY)
    async def list_pending_devices(
        host: str,
        offset: int | None = None,
        limit: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List devices pending adoption on a console.

        Returns {data, totalCount} with every page drained (the API pages at 25 by default).
        limit alone requests a total gathered from the start in pages of at most 200 (_pageSize
        reports the sizes); pass offset to fetch a single manual page (native envelope preserved).
        Pending devices are identified by data[].macAddress (pass it to approve_pending_device to
        adopt, or to forget_device to remove it from the pending list).

        Required arguments: host (see each parameter's description).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            offset: Optional zero-based offset for fetching one page manually (limit, if given, is
                its page size). Omit both offset and limit to drain every page.
                Example: `25`.
            limit: Without offset, the record count gathered from the start in pages of at
                most 200; fewer only when the collection ends. With offset, limit is sent
                unchanged as one page. The console clamps that page to 200, so fewer can
                return while more exist (compare _pageSize requested and returned). Omit
                offset and limit to drain every page.
                Example: `25`.
            filter: Optional Network Integration API filter expression, forwarded unchanged as the
                upstream `filter` query parameter for server-side filtering (e.g.
                `model.eq('U6 Pro')`). Omitted entirely when unset.
                Example: `model.eq('U7-Pro')`.
        """
        client, registry = deps_fn()
        return await _list_pending_devices(
            client, registry, host, offset=offset, limit=limit, filter=filter
        )

    @mcp.tool(annotations=WRITE)
    async def create_device_tag(
        host: str,
        site: str,
        tag: dict[str, Any],
    ) -> Any:
        """Create a device tag on a site. This is a write operation that modifies live config.

        Tags group devices (by MAC) in the UniFi UI. Uses the v2 route the controller's own UI
        uses, POST /proxy/network/v2/api/site/{site}/device-tags; the published Integration API
        serves device tags GET-only (POST answers HTTP 405 on Network 11.0.81). The body is sent
        verbatim; pass name and member_device_macs (the controller answers HTTP 500 when
        member_device_macs is missing, and that error gets a hint; pass [] for an empty tag).
        An existing name is not refused: the same name and members return the existing tag,
        and the same name with other members creates a second tag the controller renames
        "NAME - CONSOLE NAME" (Network 11.0.81). Check list_device_tags first.

        Returns: the upstream body verbatim, the created tag {_id, name, member_device_macs}.
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status:
        "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Example call (create_device_tag):
            {
              "host": "my-console",
              "site": "Default",
              "tag": {"name": "Cameras", "member_device_macs": ["aa:bb:cc:dd:ee:ff"]}
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            tag: Native v2 tag body, sent as given. Pass name (string) and member_device_macs
                (array of device MAC strings, lower-case colon form as the controller stores
                them; [] for none).
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await _create_device_tag(client, registry, host, site, tag)

    @mcp.tool(annotations=WRITE)
    async def update_device_tag(
        host: str,
        site: str,
        tag_id: str,
        tag: dict[str, Any],
    ) -> Any:
        """Update a device tag: rename it or add and remove member devices.

        Uses the v2 route the controller's own UI uses, PUT
        /proxy/network/v2/api/site/{site}/device-tags/{_id}; the published Integration API has no
        device-tag update (HTTP 404 "No endpoint" on Network 11.0.81). `tag` is either the native
        update body, sent verbatim, which needs device_mac_additions and device_mac_removals
        (the controller answers HTTP 500 without them, and that error gets a hint; pass [] for
        no membership change), or a list_device_tags entry edited in place: its
        member_device_macs (the desired members) is turned into additions and removals against
        the tag's current members and its _id is dropped, because the controller rejects both
        fields on update (HTTP 400 "Unrecognized field").

        Returns: the upstream body verbatim, the updated tag {_id, name, member_device_macs}.
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status:
        "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Example call (update_device_tag):
            {
              "host": "my-console",
              "site": "Default",
              "tag_id": "Cameras",
              "tag": {
                "name": "Outdoor cameras",
                "device_mac_additions": [],
                "device_mac_removals": []
              }
            }

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            tag_id: The tag's v2 _id or its name (exact, then case-insensitive, then
                edge-whitespace stripped). Get it from list_device_tags ([]._id; the result is a
                bare array) or from create_device_tag's result (_id). Resolved against the site's
                tags first; an unknown or ambiguous value fails listing every tag as name (_id).
            tag: Native v2 update body (device_mac_additions and device_mac_removals, arrays of
                device MAC strings, [] for none; optional name, the new name), or an edited
                list_device_tags entry {_id, name, member_device_macs} (member_device_macs = the
                desired members). Not both forms at once.
                Free-form JSON object; no fixed body shape is published.
        """
        client, registry = deps_fn()
        return await _update_device_tag(client, registry, host, site, tag_id, tag)

    @mcp.tool(annotations=WRITE)
    async def delete_device_tag(
        host: str,
        site: str,
        tag_id: str,
    ) -> dict[str, Any]:
        """Delete a device tag. This permanently removes the tag from the site.

        Consequence: the tag is removed from the site and from every member device; there is no
        undo.

        Uses the v2 route the controller's own UI uses, DELETE
        /proxy/network/v2/api/device-tags/{_id} (no site segment; the published Integration API
        has no device-tag delete). The tag is resolved in the site first, because the controller
        answers a DELETE for an unknown id with HTTP 200 and would otherwise report a deletion
        that never happened.

        Returns {deleted: true, message, response}; response is the upstream DELETE body verbatim
        (decoded JSON, the raw text of a non-JSON body, or null when the body is empty).
        Under dry-run policy nothing is deleted: {status: "dry_run", deleted: false, message,
        response (the preview)}.

        Example call (delete_device_tag):
            {
              "host": "my-console",
              "site": "Default",
              "tag_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
            }

        The dry-run preview contains method, path, params (query parameters), and body.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            tag_id: The tag's v2 _id or its name (exact, then case-insensitive, then
                edge-whitespace stripped). Get it from list_device_tags ([]._id; the result is a
                bare array) or from create_device_tag's result (_id). Resolved against the site's
                tags first; an unknown or ambiguous value fails listing every tag as name (_id).
        """
        client, registry = deps_fn()
        return await _delete_device_tag(client, registry, host, site, tag_id)

    @mcp.tool(annotations=WRITE)
    async def approve_pending_device(
        host: str,
        site: str,
        device_id: str,
        ignore_device_limit: bool,
        confirm: bool = False,
    ) -> Any:
        """Approve (adopt) a pending device onto a site.

        Consequence: the site's controller takes over and provisions the device, which may restart
        while it applies its new configuration.

        Uses the published adoptDevice route (Network 11.0.97, POST /v1/sites/{siteId}/devices;
        schema "IntegrationDeviceAdoptionRequestDto"), the same route as adopt_device, with the
        body built from the parameters: {"macAddress": device_id, "ignoreDeviceLimit":
        ignore_device_limit}. Both keys are required by the spec, so the caller chooses
        ignore_device_limit (no default is filled in). Returns the upstream body (the adopted
        device details) verbatim.
        Under dry-run policy nothing is sent: the result is the bare dry-run preview {status:
        "dry_run", dryRun: true, sent: false,
        message, preview: {method, path, params, body}} in place of the upstream body.

        Example call (approve_pending_device):
            {
              "host": "my-console",
              "site": "Default",
              "device_id": "02:00:5e:00:00:a1",
              "ignore_device_limit": false
            }

        Dry-run physical previews carry an additive _consequence warning.
        The preview includes status: "dry_run", dryRun: true, sent: false, message and
        preview: {method, path, params, body}.

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname
                or reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
            site: Network site name or UUID; resolved server-side. Get it from list_local_sites
                (name or id). Names like "Default" work.
            device_id: The pending device's MAC address (any separator style). Get it from
                list_pending_devices (data[].macAddress); pending devices have no id field.
            ignore_device_limit: Required. Sent as the spec's required ignoreDeviceLimit; true
                adopts even when the console's device limit is reached, false respects the limit.
            confirm: Ignored; accepted for backward compatibility. The call executes immediately
                when made unless the operator opted in to dry-run policy (then nothing
                is sent upstream and a preview of the request is returned).
        """
        client, registry = deps_fn()
        return await _approve_pending_device(
            client, registry, host, site, device_id, ignore_device_limit
        )

    @mcp.tool(annotations=WRITE)
    async def forget_device(
        host: str,
        site: str,
        mac: str | list[str],
        confirm: bool = False,
    ) -> Any:
        """Forget one or more devices through the Classic site manager.

        Consequence: an adopted device loses its controller configuration and must be
        adopted again. A pending device leaves the pending list but may reappear while
        it keeps broadcasting for adoption. Both are addressed by MAC.

        Sends one POST to network/api/s/{site}/cmd/sitemgr per distinct MAC, with
        {"cmd": "delete-device", "mac": "aa:bb:cc:dd:ee:ff"}. MACs are normalized.
        Returns the upstream Classic {meta, data} body verbatim; upstream
        errors are raised. An unknown MAC returns HTTP 400 api.err.UnknownDevice.
        A list returns {byMac, forgotten, errors}; each successful byMac value is the
        upstream body, and errors contains {mac, error}. It raises only if every MAC fails.

        UNIFI_WRITE_POLICY=deny blocks this write. Under dry-run policy nothing is sent; returns
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body}, _consequence}. A MAC list returns {status: "dry_run", byMac, errors}; byMac holds
        each MAC's preview, with no forgotten key. Never automatically retried.

        Example: docs/TOOL-USAGE.md#forget_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            mac: MAC address in any separator style, or a list of MACs. Get adopted MACs
                from list_site_devices and pending MACs from list_pending_devices.
                Shape: string|string[]
            confirm: Ignored; retained for compatibility. Read-only blocks execution; dry-run
                previews.
        """
        client, registry = deps_fn()
        return await _forget_device(client, registry, host, site, mac)
