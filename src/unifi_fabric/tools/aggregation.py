"""Cross-site aggregation tools — fleet-wide queries across all consoles and sites."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP

from ..argument_values import is_blank
from ..client import (
    PaginationAbortedError,
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    gather_or_cancel,
    log_reason,
    nullable_object_records,
    object_records,
    upstream_error_text,
    upstream_error_value,
    validate_host_id,
    validate_spec_id,
    wrong_type_error,
)
from ..config import APIKeyConfig
from ..matching import id_key
from ..registry import Registry, _assert_uuid, incomplete_reason
from ..tool_annotations import READ_ONLY
from ._device_wrappers import wrapper_devices
from ._keys import context_value, key_error, key_scopes, merge_first_key, report_keys, with_context
from ._pagination import collect_offset
from .network import _proxy

_logger = logging.getLogger(__name__)


async def _fleet_devices(
    client: UniFiClient,
    key_label: str | None,
    params: dict[str, Any] | None = None,
    envelopes: dict[str | None, dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[str], list[str], list[str]]:
    """Unwrapped /v1/devices across the covered keys.

    Returns ``(devices, answering labels, per-key errors, incomplete reasons)`` (the
    answering labels are the keys whose devices are included): a drain stopped
    by the opt-in ``UNIFI_PAGINATE_MAX_PAGES`` cap keeps the devices it gathered and is
    reported in the incomplete reasons (the caller flags ``incomplete: true``).

    Each device carries its wrapper's fields as additive ``_hostId`` / ``_hostName`` /
    ``_updatedAt`` (and ``_keyLabel`` when
    more than one key is covered). A key whose device list fails is reported in the
    errors list; ``RuntimeError`` only when every covered key fails. ``params`` are
    caller-supplied ``/v1/devices`` query parameters, sent verbatim on every page.
    ``envelopes``, when given, is filled with each answering key's upstream envelope
    (first-page top-level fields other than ``data``/``nextToken``), keyed by key label;
    a key is stored only after its records passed the shape check.
    """
    scopes = key_scopes(client, key_label)

    incomplete: list[str] = []

    async def _one(label: str | None, key: APIKeyConfig | None) -> tuple[list[Any], str | None]:
        # Unwrapping is inside the per-key try: one key's unexpected shape is that key's
        # error, never a failure of the whole call.
        try:
            try:
                # params only when the caller set one, so the default request is unchanged
                extra: dict[str, Any] = {"params": params} if params else {}
                raw = await client.paginate("/v1/devices", key=key, **extra)
            except PaginationAbortedError as exc:
                # opt-in page cap: keep what was gathered, flag the result incomplete
                unwrapped = _unwrap_ea_devices(exc.items)
                incomplete.append(f"{label}: {exc.reason}" if label is not None else exc.reason)
                if envelopes is not None:
                    envelopes[label] = dict(exc.envelope or {})
                return unwrapped, None
            # The envelope is stored only after the shape check passed, so a key reported
            # under errors never has a byKey entry (byKey keys == _key_labels).
            devices_of_key = _unwrap_ea_devices(raw)
            envelope = getattr(raw, "envelope", None)
            if envelopes is not None:
                # {} for a key whose body carried nothing beside the records.
                envelopes[label] = dict(envelope) if isinstance(envelope, dict) else {}
            return devices_of_key, None
        except Exception as exc:
            if len(scopes) == 1:
                raise
            return [], key_error(label, exc)

    results = await gather_or_cancel(*[_one(label, key) for label, key in scopes])
    errors = [err for _items, err in results if err]
    if len(scopes) > 1 and len(errors) == len(scopes):
        raise RuntimeError(f"All {len(scopes)} API keys failed: {'; '.join(errors)}")
    # A console visible to more than one key is counted once, under the first key in
    # configuration order (the one multi-key rule, _keys.merge_first_key), so its devices
    # never repeat.
    devices: list[dict[str, Any]] = merge_first_key(
        [
            (label, unwrapped)
            for (label, _key), (unwrapped, _err) in zip(scopes, results, strict=True)
        ],
        _device_host,
        multi=len(scopes) > 1,
    )
    answering = [
        label
        for (label, _key), (_items, err) in zip(scopes, results, strict=True)
        if label is not None and err is None
    ]
    return devices, answering, errors, incomplete


def _count_key(device: dict[str, Any], fields: tuple[str, str]) -> str:
    """The first set field of ``fields`` as a breakdown key ("unknown" when none is set);
    a field of another type (``status=["a"]``) is an actionable shape error."""
    for field in fields:
        value = device.get(field)
        if value is None or value == "":
            continue
        if not isinstance(value, str):
            raise wrong_type_error(f"device {field}", value)
        return value
    return "unknown"


def _device_host(device: Any) -> str | None:
    """The console a /v1/devices record came from (its wrapper's hostId, else its own)."""
    if not isinstance(device, dict):
        return None
    host = context_value(device, "_hostId") or device.get("hostId")
    return host if isinstance(host, str) and host else None


def _host_record_id(host: Any) -> str | None:
    """The console id of a /v1/hosts record."""
    value = host.get("id") if isinstance(host, dict) else None
    return value if isinstance(value, str) and value else None


def _site_host(site: Any) -> str | None:
    """The console a /v1/sites record belongs to."""
    value = site.get("hostId") if isinstance(site, dict) else None
    return value if isinstance(value, str) and value else None


def _unclaimed(
    items: list[Any], claimed: set[str], host_of: Callable[[Any], str | None]
) -> list[Any]:
    """The items whose console no earlier key returned.

    Multi-key de-duplication by console, first key in configuration order wins (the
    rule list_all_clients applies). Hexadecimal ids compare case-insensitively;
    the retained records keep their upstream spelling. Items without ids are kept.
    """
    return [
        item for item in items if (host := host_of(item)) is None or id_key(host) not in claimed
    ]


def _consoles(items: list[Any], host_of: Callable[[Any], str | None]) -> set[str]:
    """Canonical membership keys of the consoles the items belong to."""
    return {id_key(host) for item in items if (host := host_of(item)) is not None}


async def _get_all_host_site_pairs(
    registry: Registry,
    *,
    key: APIKeyConfig | None = None,
    skipped: list[dict[str, str]] | None = None,
    incomplete: list[str] | None = None,
    claimed_hosts: set[str] | None = None,
) -> list[dict[str, str]]:
    """Build a list of {hostId, siteId, hostName, siteName} for every site.

    Enumerates hosts from /v1/sites, then fetches UUID site IDs from the
    per-console proxy /sites endpoint. The /v1/sites ``siteId`` field is a
    Fabric ObjectId and cannot be used in proxy URLs — proxy endpoints require
    the UUID returned by the console's Network Integration /sites API.

    Every host or site that cannot be queried is appended to ``skipped`` (when given)
    as ``{hostId, hostName?, siteId?, reason}`` so callers report it instead of
    silently dropping it. When a site list the enumeration read stopped short (the
    Site Manager site list, or a console's site list, under the opt-in page cap) the
    reason is appended to ``incomplete`` (when given) so the caller flags its result.
    """
    skips: list[dict[str, str]] = skipped if skipped is not None else []
    partial: list[str] = incomplete if incomplete is not None else []
    ea_sites = await registry.get_ea_sites(key=key)
    ea_reason = incomplete_reason(ea_sites)
    if ea_reason:
        partial.append(f"Site Manager site list: {ea_reason}")

    # Real console names (the Site Manager site record carries only the hostId).
    names: dict[str, str] = {}
    try:
        for host in await registry.get_hosts(key=key):
            if isinstance(host, dict) and isinstance(host.get("id"), str):
                reported = host.get("reportedState")
                reported = reported if isinstance(reported, dict) else {}
                name = reported.get("hostname") or reported.get("name") or host.get("name")
                if isinstance(name, str) and name:
                    names.setdefault(id_key(host["id"]), name)
    except Exception as exc:  # names are context only; the sites are still queried
        # Status and reason code only: the upstream body is never logged.
        _logger.warning(
            "Could not list hosts for console names (GET /v1/hosts): %s", log_reason(exc)
        )

    # Collect unique hostId -> hostname from ea_sites
    host_map: dict[str, tuple[str, str]] = {}
    for site in ea_sites:
        host_id = site.get("hostId", "")
        if not host_id:
            skips.append(
                {
                    "hostId": "",
                    "siteId": site.get("siteId") or site.get("id") or "",
                    "reason": "Site Manager site record has no hostId",
                }
            )
            continue
        try:
            validate_host_id(host_id, "hostId", client=registry._client)
        except ValueError as exc:
            skips.append({"hostId": host_id, "reason": upstream_error_text(exc, registry._client)})
            continue
        host_map.setdefault(
            id_key(host_id),
            (host_id, names.get(id_key(host_id)) or site.get("hostname") or host_id),
        )

    pairs = []
    for host_id, host_name in host_map.values():
        if claimed_hosts is not None and id_key(host_id) in claimed_hosts:
            continue
        try:
            proxy_sites = await registry.get_sites(host_id, key=key)
        except Exception as exc:
            # Status and reason code only; the complete error is reported under skipped.
            _logger.warning(
                "Failed to fetch proxy sites for host %r (GET sites): %s",
                host_id,
                log_reason(exc),
            )
            skips.append(
                {
                    "hostId": host_id,
                    "hostName": host_name,
                    "reason": f"site list: {upstream_error_text(exc, registry._client)}",
                }
            )
            continue
        site_reason = incomplete_reason(proxy_sites)
        if site_reason:
            # The sites gathered are still queried; the rest of the console is reported.
            skips.append(
                {
                    "hostId": host_id,
                    "hostName": host_name,
                    "reason": f"site list incomplete: {site_reason}",
                }
            )
            partial.append(f"{host_id} ({host_name}) site list: {site_reason}")
        for proxy_site in proxy_sites:
            site_id = proxy_site.get("id") or proxy_site.get("_id", "")
            site_name = proxy_site.get("description") or proxy_site.get("name") or site_id
            if not site_id:
                skips.append({"hostId": host_id, "hostName": host_name, "reason": "site has no id"})
                continue
            try:
                _assert_uuid(site_id, client=registry._client)
            except ValueError as exc:
                skips.append(
                    {
                        "hostId": host_id,
                        "hostName": host_name,
                        "siteId": site_id,
                        "reason": upstream_error_text(exc, registry._client),
                    }
                )
                continue
            pairs.append(
                {
                    "hostId": host_id,
                    "siteId": site_id,
                    "hostName": host_name,
                    "siteName": site_name,
                }
            )
    return pairs


async def _list_all_devices_fleet(
    client: UniFiClient,
    *,
    status_filter: str | None = None,
    key_label: str | None = None,
    host_ids: list[str] | None = None,
    time: str | None = None,
) -> dict[str, Any]:
    """List all devices across the entire fleet using the /v1/devices endpoint.

    Optionally filter by status (e.g. 'offline', 'online', 'updating').
    key_label scopes the query to a specific API key for MSP multi-tenant use.
    host_ids / time are the spec's optional ``hostIds[]`` and ``time`` query parameters,
    forwarded verbatim to every covered key when given.
    """
    params: dict[str, Any] = {}
    # A blank status_filter applies no filter; host_ids is sent as given (an empty list
    # adds no hostIds[] parameter).
    if host_ids is not None:
        for index, host_id in enumerate(host_ids):
            # Query-only (hostIds[] items: string): spec rules, not path rules.
            validate_spec_id(host_id, f"host_ids[{index}]")
        params["hostIds[]"] = list(host_ids)
    if time is not None:
        params["time"] = time
    # /v1/devices returns one wrapper per console; filter and count the devices inside.
    envelopes: dict[str | None, dict[str, Any]] = {}
    all_devices, labels, key_errors, incomplete = await _fleet_devices(
        client, key_label, params or None, envelopes
    )
    multi = len(labels) + len(key_errors) > 1

    if status_filter is not None and not is_blank(status_filter):
        status_lower = status_filter.lower()
        all_devices = [
            d
            for d in all_devices
            if isinstance(d, dict)
            and str(d.get("status") or d.get("state") or "").lower() == status_lower
        ]

    result: dict[str, Any] = {"data": all_devices}
    if not multi and envelopes:
        # One key: its upstream envelope fields sit beside the records, as in list_devices.
        (envelope,) = envelopes.values()
        result = {**envelope, **result}
    # Server metadata goes beside the envelope: a colliding upstream field keeps its value.
    result = with_context(
        result, {"_count": len(all_devices), "_filter": status_filter, "_key_label": key_label}
    )
    if multi and envelopes:
        # Keep the historical envelope order: data, metadata, byKey, key coverage.
        result["byKey"] = {str(label): env for label, env in envelopes.items()}
    report_keys(result, labels, key_errors, multi=multi)
    if incomplete:
        result = with_context(
            result, {"incomplete": True, "incompleteReason": "; ".join(incomplete)}
        )
    return result


async def _list_all_clients_fleet(
    client: UniFiClient,
    registry: Registry,
    *,
    key_label: str | None = None,
    filter_expr: str | None = None,
) -> dict[str, Any]:
    """List all connected clients across all sites by fanning out proxy requests.

    ``filter_expr`` is forwarded verbatim as each site's ``filter`` query parameter
    (the Network Integration client-list filter) when given.

    key_label scopes the query to consoles visible to a specific API key; without it a
    multi-key deployment covers every key. Each site's client list is drained across
    every page.
    """
    scopes = key_scopes(client, key_label)
    multi = len(scopes) > 1
    skipped: list[dict[str, str]] = []
    errors: list[str] = []
    partial: list[str] = []
    jobs: list[tuple[dict[str, str], APIKeyConfig | None, str | None]] = []
    queued: set[tuple[str, str]] = set()
    answering: list[str | None] = []
    claimed_hosts: set[str] = set()
    for label, key in scopes:
        try:
            key_skipped: list[dict[str, str]] = []
            key_partial: list[str] = []
            pairs = await _get_all_host_site_pairs(
                registry,
                key=key,
                skipped=key_skipped,
                incomplete=key_partial,
                claimed_hosts=claimed_hosts,
            )
            if multi and label is not None:
                for item in key_skipped:
                    item["keyLabel"] = label
                key_partial = [f"{label}: {reason}" for reason in key_partial]
            skipped.extend(key_skipped)
            partial.extend(key_partial)
        except Exception as exc:
            if not multi:
                raise
            errors.append(key_error(label, exc))
            continue
        answering.append(label)
        claimed_hosts.update(id_key(pair["hostId"]) for pair in pairs)
        for pair in pairs:
            # A console visible to more than one key is queried once (first key in
            # configuration order), so its clients are never returned twice.
            site_ref = (id_key(pair["hostId"]), id_key(pair["siteId"]))
            if site_ref not in queued:
                queued.add(site_ref)
                jobs.append((pair, key, label))
    if multi and len(errors) == len(scopes):
        raise RuntimeError(f"All {len(scopes)} API keys failed: {'; '.join(errors)}")
    if not jobs and skipped:
        # Every skipped host/site with its reason, never a sample, and every key that
        # failed outright (its own error, e.g. its site list failing).
        reasons = "; ".join(
            errors
            + [
                (f"{upstream_error_value(s['keyLabel'], client)}: " if s.get("keyLabel") else "")
                + f"{upstream_error_value(s.get('hostId'), client)}"
                + (f" ({upstream_error_value(s['hostName'], client)})" if s.get("hostName") else "")
                + (f" site {upstream_error_value(s['siteId'], client)}" if s.get("siteId") else "")
                + f": {upstream_error_value(s.get('reason'), client)}"
                for s in skipped
            ]
        )
        raise RuntimeError(f"No site could be queried ({len(skipped)} skipped): {reasons}")

    async def _fetch_clients(
        pair: dict[str, str], key: APIKeyConfig | None, label: str | None
    ) -> dict[str, Any]:
        try:
            extra: dict[str, Any] = (
                {"params": {"filter": filter_expr}} if filter_expr is not None else {}
            )
            collected = await collect_offset(
                client, _proxy(pair["hostId"], f"/sites/{pair['siteId']}/clients"), key=key, **extra
            )
            object_records(collected["items"], f"clients of site {pair['siteId']}")
        except Exception as exc:
            error_prefix = f"{label}: " if multi else ""
            return {
                "clients": [],
                "error": f"{error_prefix}{upstream_error_value(pair['hostId'], client)}/"
                f"{upstream_error_value(pair['siteName'], client)}: "
                f"{upstream_error_text(exc, client)}",
            }
        envelope = collected.get("envelope") or {}
        context = {
            "_hostId": pair["hostId"],
            "_hostName": pair["hostName"],
            "_siteId": pair["siteId"],
            "_siteName": pair["siteName"],
            **({"_keyLabel": label} if multi else {}),
        }
        clients_list = [
            with_context(c, context) if isinstance(c, dict) else c for c in collected["items"]
        ]
        reason = (
            f"{f'{label}: ' if multi else ''}{pair['hostId']}/{pair['siteName']}: "
            f"{collected['incompleteReason']}"
            if collected["incomplete"]
            else None
        )
        # A capped site list is incomplete, not failed: it is reported under
        # incompleteReason and counted in sitesIncomplete.
        return {
            "clients": clients_list,
            "error": None,
            "incomplete": reason,
            "envelope": (f"{pair['hostId']}/{pair['siteId']}", envelope),
        }

    results = await gather_or_cancel(*[_fetch_clients(p, k, lbl) for p, k, lbl in jobs])

    all_clients: list[dict[str, Any]] = []
    site_errors: list[str] = []
    for r in results:
        all_clients.extend(r["clients"])
        if r["error"]:
            site_errors.append(r["error"])

    sites_incomplete = sum(1 for r in results if r.get("incomplete"))
    if jobs and len(site_errors) == len(jobs) and not all_clients:
        # Each failed key's own error (e.g. key A's site-list failure) comes first, then
        # every site error: the message carries every reason the call returned nothing.
        raise RuntimeError(
            f"All {len(jobs)} site(s) failed"
            + (f" and {len(errors)} API key(s) failed" if errors else "")
            + f": {'; '.join(errors + site_errors)}"
        )

    result: dict[str, Any] = {
        "data": all_clients,
        "_count": len(all_clients),
        "_sitesQueried": len(jobs),
        "_sitesSucceeded": len(jobs) - len(site_errors) - sites_incomplete,
        "_sitesFailed": len(site_errors),
        "_sitesIncomplete": sites_incomplete,
        "_key_label": key_label,
    }
    # One errors list (each failed key, then each failed site), placed once: a separate
    # site-error assignment would push the key errors into a collision bucket.
    report_keys(result, answering, errors + site_errors, multi=multi)
    if skipped:
        result["_skipped"] = skipped
    # Each site list's upstream envelope (totalCount ...), keyed "<hostId>/<siteId>".
    site_envelopes = {r["envelope"][0]: r["envelope"][1] for r in results if r.get("envelope")}
    if site_envelopes:
        result["_siteEnvelopes"] = site_envelopes
    incomplete_reasons = partial + [r["incomplete"] for r in results if r.get("incomplete")]
    if incomplete_reasons:
        result["incomplete"] = True
        result["incompleteReason"] = "; ".join(incomplete_reasons)
    return result


def _unwrap_ea_devices(raw: list[Any]) -> list[Any]:
    """/v1/devices returns host-wrapper objects: [{hostId, hostName, devices:[...]}, ...].

    Unwrap to a flat list of device objects. Each unwrapped device keeps every other
    wrapper field as an additive ``_<field>`` key (``_hostId``, ``_hostName``,
    ``_updatedAt``, and any field the API adds later), so nothing the wrapper carried is
    lost, and the device payload and the wrapper context are kept apart
    (:func:`~._keys.with_context`): ``_hostId`` / ``_hostName`` always name the wrapper's
    console (a device's own different value goes under ``_ownFields``), and any other
    field the device already carries keeps the device's value (the wrapper's goes under
    ``_wrapperFields``). A console wrapper whose ``devices``
    is null, missing or ``[]`` contributes no device and is never itself returned as one
    (:func:`wrapper_devices`); only an item that is not a console wrapper at all (neither
    ``devices`` nor ``hostId``) is passed through as-is.
    """
    devices: list[Any] = []
    for wrapper in raw:
        if wrapper is None:
            devices.append(wrapper)
            continue
        if not isinstance(wrapper, dict):
            raise UniFiConnectionError(
                "Unexpected /v1/devices item: expected a console wrapper object, got "
                f"{describe_shape(wrapper)}"
            )
        inner = wrapper_devices(wrapper)
        if inner is None:
            devices.append(wrapper)
            continue
        context = {f"_{k}": v for k, v in wrapper.items() if k != "devices"}
        for device in inner:
            devices.append(with_context(device, context) if isinstance(device, dict) else device)
    return nullable_object_records(devices, "GET /v1/devices device entries")


def _summary_counts(
    hosts: list[Any], sites: list[Any], devices: list[dict[str, Any]]
) -> dict[str, Any]:
    """{hosts, sites, devices: {total, byStatus, byType}} for the given records.

    The EA API may use "status" or "state" depending on the firmware version, and
    "productLine" (e.g. "network", "protect") rather than "type".
    """
    by_status: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for device in devices:
        status = _count_key(device, ("status", "state"))
        by_status[status] = by_status.get(status, 0) + 1
        product = _count_key(device, ("productLine", "type"))
        by_type[product] = by_type.get(product, 0) + 1
    return {
        "hosts": len(hosts),
        "sites": len(sites),
        "devices": {"total": len(devices), "byStatus": by_status, "byType": by_type},
    }


async def _fleet_summary(
    client: UniFiClient,
    registry: Registry,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Get a high-level summary of the entire fleet: host/site/device counts and status breakdown.

    key_label scopes the summary to consoles visible to a specific API key; without it a
    multi-key deployment covers every key (per-key failures under ``errors``) and
    ``_keyTotals`` breaks the totals down by the key each console is counted under.
    """
    scopes = key_scopes(client, key_label)
    hosts_data: list[Any] = []
    sites_data: list[Any] = []
    devices_data: list[dict[str, Any]] = []
    key_errors: list[str] = []
    summary_incomplete: list[str] = []
    # Consoles already counted under an earlier key (first key in configuration order
    # wins, as in list_all_clients): a console visible to two keys is counted once,
    # with its sites and devices.
    claimed: set[str] = set()
    answering: list[str | None] = []
    # Each answering key's share of the de-duplicated totals (the same per-key assignment
    # the totals use), so the per-key numbers sum to the top-level ones.
    key_totals: dict[str, dict[str, Any]] = {}
    for label, key in scopes:
        capped: list[str] = []

        async def _drain(
            path: str,
            key: APIKeyConfig | None = key,
            label: str | None = label,
            capped: list[str] = capped,
        ) -> list[Any]:
            try:
                return await client.paginate(path, key=key)
            except PaginationAbortedError as exc:
                # opt-in page cap: count what was gathered, flag the summary incomplete
                capped.append(path)
                summary_incomplete.append(
                    f"{path}: {exc.reason}" if label is None else f"{label}: {path}: {exc.reason}"
                )
                return exc.items

        try:
            # A failing list cancels (and awaits) its sibling drains: none outlives it.
            hosts, sites, devices = await gather_or_cancel(
                _drain("/v1/hosts"), _drain("/v1/sites"), _drain("/v1/devices")
            )
            # Unwrap per key, inside the try: a bad shape is this key's error.
            devices = _unwrap_ea_devices(devices)
            object_records(hosts, "GET /v1/hosts")
            nullable_object_records(sites, "GET /v1/sites")
            sites = [site for site in sites if site is not None]
            devices = [device for device in devices if device is not None]
            for device in devices:
                _count_key(device, ("status", "state"))
                _count_key(device, ("productLine", "type"))
            # Cache only keys whose entire summary data passed validation.
            if "/v1/hosts" not in capped:
                await registry.set_hosts(hosts, key=key)
            if "/v1/sites" not in capped:
                await registry.set_ea_sites(sites, key=key)
        except Exception as exc:
            if len(scopes) == 1:
                raise
            key_errors.append(key_error(label, exc))
            continue
        answering.append(label)
        own_hosts = _unclaimed(hosts, claimed, _host_record_id)
        own_sites = _unclaimed(sites, claimed, _site_host)
        own_devices = _unclaimed(devices, claimed, _device_host)
        hosts_data.extend(own_hosts)
        sites_data.extend(own_sites)
        devices_data.extend(own_devices)
        key_totals[str(label)] = _summary_counts(own_hosts, own_sites, own_devices)
        claimed |= (
            _consoles(hosts, _host_record_id)
            | _consoles(sites, _site_host)
            | _consoles(devices, _device_host)
        )
    if len(scopes) > 1 and len(key_errors) == len(scopes):
        raise RuntimeError(f"All {len(scopes)} API keys failed: {'; '.join(key_errors)}")

    summary: dict[str, Any] = {
        **_summary_counts(hosts_data, sites_data, devices_data),
        "_key_label": key_label,
    }
    multi = len(scopes) > 1
    report_keys(summary, answering, key_errors, multi=multi)
    if multi:
        summary = with_context(summary, {"_keyTotals": key_totals})
    if summary_incomplete:
        summary["incomplete"] = True
        summary["incompleteReason"] = "; ".join(summary_incomplete)
    return summary


async def _search_device(
    client: UniFiClient,
    query: str,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Search for a device by name or MAC address across the entire fleet.

    key_label scopes the search to consoles visible to a specific API key.
    """
    # /v1/devices returns host-wrapper objects; unwrap keeping _hostId/_hostName per device.
    fleet, labels, key_errors, incomplete = await _fleet_devices(client, key_label)
    multi = len(labels) + len(key_errors) > 1
    all_devices = [d for d in fleet if isinstance(d, dict)]

    query_lower = query.lower()

    matches = []
    for d in all_devices:
        reported = d.get("reportedState")
        reported = reported if isinstance(reported, dict) else {}
        searchable = [
            d.get("name", ""),
            d.get("mac", ""),
            d.get("model", ""),
            d.get("shortname", ""),
            d.get("hostname", ""),
            d.get("displayName", ""),
            d.get("ip", ""),
            reported.get("hostname", ""),
            reported.get("model", ""),
            reported.get("shortname", ""),
            reported.get("ip", ""),
            reported.get("mac", ""),
            reported.get("name", ""),
        ]
        # A blank query applies no filter: every device matches.
        if is_blank(query) or any(
            query_lower in field.lower() for field in searchable if isinstance(field, str)
        ):
            matches.append(d)

    result: dict[str, Any] = {
        "data": matches,
        "_count": len(matches),
        "_query": query,
        "_key_label": key_label,
    }
    report_keys(result, labels, key_errors, multi=multi)
    if incomplete:
        result["incomplete"] = True
        result["incompleteReason"] = "; ".join(incomplete)
    return result


async def _list_api_keys(client: UniFiClient) -> dict[str, Any]:
    """List all configured API keys with their labels and types.

    Returns key labels and whether each is an organization key, without
    exposing the actual key values.
    """
    configs = client._key_configs()
    keys = []
    for cfg in configs:
        keys.append(
            {
                "label": cfg.label,
                "is_org_key": cfg.is_org_key,
            }
        )
    return {
        "keys": keys,
        "count": len(keys),
    }


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all aggregation MCP tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def list_configured_api_keys() -> dict[str, Any]:
        """List all configured API keys with their labels and types.

        Result: {keys, count}: one entry per configured key, and how many.

        Shows which API keys are available for MSP multi-console queries.
        Returns labels and org-key status without exposing actual key values.
        """
        client, _ = deps_fn()
        return await _list_api_keys(client)

    @mcp.tool(annotations=READ_ONLY)
    async def list_all_devices(
        status_filter: str | None = None,
        key_label: str | None = None,
        host_ids: list[str] | None = None,
        time: str | None = None,
    ) -> dict[str, Any]:
        """List all devices across the entire fleet.

        Returns {data, _count, _filter, _key_label}: data holds the unwrapped device records
        verbatim plus additive _hostId / _hostName / _updatedAt; with one key the upstream envelope
        fields (httpStatusCode, traceId) sit beside them, with several keys they are under byKey
        with _key_labels. errors and incomplete / incompleteReason are added when they apply.

        Aggregates devices from all consoles (every configured API key unless key_label
        names one; per-key failures under errors): /v1/devices returns one wrapper per console,
        which is unwrapped so data[] holds the device objects (each carrying the wrapper's
        fields as additive _hostId / _hostName / _updatedAt naming its console); the additive
        _count is the number of devices, _filter echoes status_filter and _key_label the
        key_label argument (_key_labels lists the keys whose devices are included when several
        keys are covered; a key that fails is under errors). A
        console visible to more than one key is listed once, under the first key in
        configuration order (as list_all_clients does).
        Optionally filter by status
        (e.g. 'offline', 'online', 'updating') to find problem devices quickly.
        status_filter is applied LOCALLY by exact (case-insensitive) match against each
        device's status/state. WARNING: an unrecognised value is NOT rejected — it matches
        nothing and returns an EMPTY device list, so a typo (e.g. 'ofline') looks like a
        healthy fleet with zero problem devices rather than an error. Omit status_filter to
        get the full fleet, then read the real status values off the returned records.

        Args:
            status_filter: Optional status to match LOCALLY (exact, case-insensitive) against each
                device's status/state, e.g. 'offline', 'online', 'updating'. An unrecognised value
                is not rejected: it matches nothing and returns an empty list. An empty or
                whitespace value applies no filter.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to
                cover every configured key: results are merged, each record carries an additive
                _keyLabel, and a key that fails is reported under errors.
            host_ids: Optional console ids (list_hosts data[].id, the long MAC:numericId form),
                forwarded verbatim as the upstream hostIds[] query parameter to every covered key
                (an empty list sends no hostIds[] parameter).
                Shape: string[]
            time: Optional RFC3339 timestamp, forwarded verbatim as the upstream time query
                parameter (the spec's "last processed timestamp of devices").
        """
        client, _ = deps_fn()
        return await _list_all_devices_fleet(
            client, status_filter=status_filter, key_label=key_label, host_ids=host_ids, time=time
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_all_clients(
        key_label: str | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        """List all connected clients across all sites.

        Returns {data, _count, _sitesQueried, _sitesSucceeded, _sitesFailed, _sitesIncomplete,
        _key_label, _siteEnvelopes}: data holds every site's client records verbatim plus additive
        _hostId / _hostName / _siteId / _siteName (and _keyLabel with several keys); _siteEnvelopes
        maps "hostId/siteId" to that site list's upstream envelope fields (totalCount ...). errors,
        _skipped, _key_labels and incomplete / incompleteReason are added when they apply.

        Fans out requests to every site (of every configured API key unless key_label
        names one; a console visible to more than one key is queried once, under the first key
        in configuration order), drains each site's client list across all pages, and aggregates
        results with source host/site annotations on each client record, under data (with
        the additive _count). Reports the additive _sitesQueried, _sitesSucceeded,
        _sitesFailed and _sitesIncomplete, per-site errors, and _skipped (hosts/sites that
        could not be queried, each with its reason). A site whose client list stopped at the
        UNIFI_PAGINATE_MAX_PAGES cap counts in _sitesIncomplete, not as failed, and the result
        carries incomplete=true with the reasons.

        Args:
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to
                cover every configured key: results are merged, each record carries an additive
                _keyLabel, and a key that fails is reported under errors.
            filter: Optional Network Integration API filter expression, forwarded unchanged as
                each site's upstream `filter` query parameter. Omitted entirely when unset.
                Example: `type.eq('WIRED')`.
        """
        client, registry = deps_fn()
        return await _list_all_clients_fleet(
            client, registry, key_label=key_label, filter_expr=filter
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_fleet_summary(
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Get a high-level fleet summary: host, site, and device counts with status breakdowns.

        Useful for a quick overview of the entire UniFi deployment. Covers every
        configured API key unless key_label names one (per-key failures under errors). A
        console visible to more than one key is counted once, with its sites and devices,
        under the first key in configuration order (as list_all_clients does).

        Returns counts only, no records: {hosts, sites, devices: {total, byStatus, byType},
        _key_label}, plus, when several keys are covered, _key_labels (the keys whose consoles
        are counted) and _keyTotals (one entry per answering key label, each {hosts, sites,
        devices: {total, byStatus, byType}} over the consoles counted under that key, so the
        per-key numbers sum to the top-level totals; a shared console appears only under its
        first key and a key that failed has no entry). errors lists a key that failed (its
        label and reason), and incomplete/incompleteReason is added when a list stopped at
        the opt-in UNIFI_PAGINATE_MAX_PAGES cap.

        Args:
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to
                cover every configured key: every key's consoles, sites and devices are counted
                together, and a key that fails is reported under errors.
        """
        client, registry = deps_fn()
        return await _fleet_summary(client, registry, key_label=key_label)

    @mcp.tool(annotations=READ_ONLY)
    async def search_device_fleet(
        query: str,
        key_label: str | None = None,
    ) -> dict[str, Any]:
        """Search for a device by name, MAC address, or model across the entire fleet.

        Result: {data, _count, _query, _key_label}: _query and _key_label echo the arguments.

        Returns all matching devices from all consoles (every configured API key unless
        key_label names one; per-key failures under errors); each match carries the wrapper's
        fields as additive _hostId / _hostName / _updatedAt naming its console. A console
        visible to more than one key is searched once, under the first key in configuration
        order.

        Required arguments: query (see each parameter's description).

        Args:
            query: REQUIRED. Search string matched against device name, model, and MAC across the
                fleet. An empty or whitespace query applies no filter: every device is returned.
            key_label: Optional configured API-key label (see list_configured_api_keys). Omit to
                cover every configured key: results are merged, each record carries an additive
                _keyLabel, and a key that fails is reported under errors.
        """
        client, _ = deps_fn()
        return await _search_device(client, query, key_label=key_label)
