"""UniFi Network controller insights: configuration defaults, statistics, dashboards,
site health, warnings, reference data and UPS pairing.

Route choice (the official published API when it can do the job or
reach the same outcome, else the newer private v2 API, else the older Classic API). The
choice and the reason are recorded per tool in ``ROUTE_CHOICES``. In short:

* The official Network Integration API (pinned 11.0.97) has none of these capabilities
  (its ``/v1/info`` carries only ``applicationVersion``).
* The official Site Manager API was compared key by key on a live console:
  ``/v1/sites`` carries the same 16 per-site counts as the v2 sites overview but not the
  WiFi association success rate and has no search, sort or console-local paging (the
  existing ``list_sites`` tool is the official read); ``/v1/hosts/{id}`` reports a
  different application list, an application load level instead of the safe-mode flag,
  and capability flags instead of the cloud-access and cloud-backup settings.
* Every other tool uses the v2 route the Network web app (11.0.81) calls. Four use Classic
  routes because no newer route carries their fields: ``api/ui-data``, ``stat/sdn``,
  ``stat/anomalies`` and the controller part of ``list_site_warnings``
  (``stat/widget/warnings``: firmware, end-of-life, LTE subscription and disk warnings).

Every response body is passed through verbatim (server pass-through invariant); drained
lists add only ``_``-prefixed keys. Inputs are validated before any request with the
server's registered refusals only (selectors, path segments, integer epoch seconds,
pydantic choice validation, read-only mode). A Classic read succeeds only on HTTP 2xx with
``meta.rc == "ok"``.

``get_sites_overview`` reads through a POST (``/v2/api/sites/overview``). A read-type POST
stays a write until it is on the read-POST allowlist (its own change), so the tool is
annotated and gated as a write; it changes no state.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from inspect import Parameter, getdoc, signature
from types import SimpleNamespace
from typing import Any, Literal

from fastmcp import FastMCP
from pydantic import StrictBool, StrictInt, TypeAdapter

from ..._read_only_audit import derive_write_tools
from ...client import (
    UniFiClient,
    decode_body,
    path_segment,
    upstream_error_text,
    validate_selector,
)
from ...config import APIKeyConfig
from ...read_only import guard_action
from ...registry import Registry
from ...route_secrets import UPS_PAIRING_SECRET as UPS_PAIRING_SECRET
from ...selector_args import check_selector
from ...shared_shapes._classic_cmd import ClassicCommandError, classic_rc_failure
from ...shared_shapes._classic_objects import resolve_site_slug as _resolve_site_slug
from ...shared_shapes._classic_objects import v2_root, v2_site
from ...shared_shapes._history_common import (
    epoch_warnings,
    require_epoch_seconds,
    seconds_to_millis,
    with_warnings,
)
from ...shared_shapes._keys import with_context
from ...shared_shapes._number_window import collect_number_window
from ...shared_shapes._pagination import collect_batch, mark_incomplete, validate_pagination
from ...shared_shapes._payload import with_upstream_hint
from ...tool_annotations import for_tool

_CONSOLE = "/v1/connector/consoles/{host_id}/proxy/network"

#: Configuration-defaults kinds: kind -> (scope, v2 route). ``site`` kinds are
#: ``/v2/api/site/{site}/<route>``; ``console`` kinds are ``/v2/api/<route>``.
DEFAULTS_ROUTES: dict[str, tuple[str, str]] = {
    "port_profile": ("site", "/port-profiles/defaults"),
    "wan": ("site", "/wan/defaults"),
    "lan": ("site", "/lan/defaults"),
    "wlan": ("site", "/wlan/defaults"),
    "firewall_policy": ("site", "/firewall-policies/defaults"),
    "firewall_zone": ("site", "/firewall/zone/defaults"),
    "connectivity": ("site", "/settings/connectivity/defaults"),
    "doh": ("site", "/settings/doh/defaults"),
    "element_adopt": ("site", "/settings/element_adopt/defaults"),
    "global_switch": ("site", "/settings/global_switch/defaults"),
    "ips_advanced_filtering": ("site", "/settings/ips/advanced-filtering-defaults"),
    "netflow": ("site", "/settings/netflow/defaults"),
    "ntp": ("site", "/settings/ntp/defaults"),
    "usg": ("site", "/settings/usg/defaults"),
    "wifiai": ("site", "/settings/wifiai/defaults"),
    "ssl_inspection_profile": ("site", "/ssl-inspection/profiles/defaults"),
    "ssl_inspection_setting": ("site", "/ssl-inspection/setting/defaults"),
    "system_log_setting": ("site", "/system-log/setting/defaults"),
    "log_levels": ("console", "/log-levels/defaults"),
    "super_mgmt": ("console", "/settings/super-mgmt/defaults"),
}

DefaultsKind = Literal[
    "port_profile",
    "wan",
    "lan",
    "wlan",
    "firewall_policy",
    "firewall_zone",
    "connectivity",
    "doh",
    "element_adopt",
    "global_switch",
    "ips_advanced_filtering",
    "netflow",
    "ntp",
    "usg",
    "wifiai",
    "ssl_inspection_profile",
    "ssl_inspection_setting",
    "system_log_setting",
    "log_levels",
    "super_mgmt",
]

#: Statistics views and the v2 route each reads (``/v2/api/<route>``).
STATS_ROUTES: dict[str, str] = {
    "recent_series": "/stats/recent/series",
    "series": "/stats/series",
    "source": "/stats/source",
}
StatsView = Literal["recent_series", "series", "source"]

UpsAction = Literal["pair", "unpair"]
WarningsSource = Literal["all", "network", "controller"]

_DEFAULTS_KIND = TypeAdapter(DefaultsKind)
_STATS_VIEW = TypeAdapter(StatsView)
_UPS_ACTION = TypeAdapter(UpsAction)
_WARNINGS_SOURCE = TypeAdapter(WarningsSource)
_STRICT_BOOL = TypeAdapter(StrictBool)
_STRICT_INT = TypeAdapter(StrictInt)

#: Route choice per tool: (source, route, reason when not the official API).
ROUTE_CHOICES: dict[str, tuple[str, str, str]] = {
    "get_network_config_defaults": (
        "v2",
        "GET /v2/api/site/{site}/<kind>/defaults, /v2/api/{log-levels,settings/super-mgmt}"
        "/defaults",
        "no official route serves configuration defaults",
    ),
    "get_controller_stats": (
        "v2",
        "GET /v2/api/stats/recent/series (+ stats, stats/recent, stats/source)",
        "official device statistics are latest-only; no time-series query",
    ),
    "get_site_dpi_usage": (
        "v2",
        "GET /v2/api/stats/series (schema applicationTrafficBySite)",
        "official /v1/dpi lists reference applications and categories, not byte counters",
    ),
    "get_client_dpi_usage": (
        "v2",
        "GET /v2/api/stats/series (schema applicationTrafficBySiteByClient)",
        "official /v1/dpi lists reference applications and categories, not byte counters",
    ),
    "get_client_wifi_experience": (
        "v2",
        "GET /v2/api/site/{site}/wifiman/{client_ip}",
        "no official route; the Classic stat/sta record carries a different band vocabulary",
    ),
    "suggest_service_port": (
        "v2",
        "GET /v2/api/site/{site}/network/port-suggest",
        "no official route; network/suggest (suggest_network_settings) is a different route",
    ),
    "get_sites_overview": (
        "v2",
        "POST /v2/api/sites/overview",
        "official Site Manager /v1/sites (list_sites) lacks percentages."
        "successful_association and console-local search/sort/paging",
    ),
    "get_network_ui_data": ("classic", "GET /api/ui-data", "no v2 or official route"),
    "get_sdn_status": (
        "classic",
        "GET /api/s/{site}/stat/sdn",
        "v2 unifi-core/general-info lacks connected, is_udm, ubic_env",
    ),
    "list_installed_applications": (
        "v2",
        "GET /v2/api/system/installed-applications",
        "Site Manager host apps/controllers report a different application set",
    ),
    "get_console_general_info": (
        "v2",
        "GET /v2/api/unifi-core/general-info",
        "Site Manager host features are capability flags, not the enabled settings",
    ),
    "get_first_system_event": (
        "v2",
        "GET /v2/api/system/event/{event_type}/first",
        "no official route",
    ),
    "list_timezones": ("v2", "GET /v2/api/timezones", "no official route"),
    "list_ups_devices": (
        "v2",
        "GET /v2/api/ups/consoles",
        "Site Manager host features.ups is a capability flag set, not the pairings",
    ),
    "set_ups_pairing": ("v2", "POST /v2/api/ups/{pair,unpair}", "no official route"),
    "list_vendor_ids": ("v2", "GET /v2/api/site/{site}/vendor-ids", "no official route"),
    "list_device_models": (
        "v2",
        "GET /v2/api/site/{site}/models[/{id}]",
        "no official route",
    ),
    "get_device_fingerprint": (
        "v2",
        "GET /v2/api/fingerprint_devices/{source}",
        "no official route",
    ),
    "list_site_features": (
        "v2",
        "GET /v2/api/site/{site}/described-features, features/{name}/exists",
        "Site Manager statistics.features is a name list without enabled/limitations",
    ),
    "get_site_dashboard": (
        "v2",
        "GET /v2/api/site/{site}/aggregated-dashboard",
        "Site Manager /v1/sites statistics cover counts and WAN only",
    ),
    "list_site_warnings": (
        "v2+classic (SPLIT)",
        "GET /v2/api/site/{site}/warnings + /api/s/{site}/stat/widget/warnings",
        "v2 holds rogue client/DHCP and Defender warnings; firmware, EOL, LTE and disk "
        "warnings exist only in the Classic widget",
    ),
    "get_cybersecure_summary": (
        "v2",
        "GET /v2/api/site/{site}/cybersecure/summary",
        "Site Manager gateway ipsMode/ipsSignature lack threats and scanned bytes",
    ),
    "get_site_degradation_status": (
        "v2",
        "GET /v2/api/site/{site}/degradation-status",
        "Site Manager applicationDegradation is a load level, not safe_mode",
    ),
    "get_observability_site_health": (
        "v2",
        "GET /v2/api/site/{site}/observability/sitehealth",
        "official ISP metrics lack per-WAN client count, traffic and failover history",
    ),
    "get_observability_people": (
        "v2",
        "GET /v2/api/site/{site}/observability/people",
        "no official route",
    ),
    "list_ulp_user_groups": (
        "v2",
        "GET /v2/api/site/{site}/ulp/users_groups",
        "no official route",
    ),
    "list_network_anomalies": (
        "classic",
        "GET /api/s/{site}/stat/anomalies",
        "v2 port-anomalies covers switch ports only",
    ),
}


def _given(**params: Any) -> dict[str, Any]:
    """Only the parameters the caller actually gave (no invented defaults)."""
    return {k: v for k, v in params.items() if v is not None}


def _epoch_ms(value: int | None, name: str) -> int | None:
    """An optional epoch-seconds argument as epoch milliseconds (type-checked first)."""
    if value is None:
        return None
    return seconds_to_millis(require_epoch_seconds(value, name))


def _bool_text(value: bool | None) -> str | None:
    """An optional strict boolean as the ``true``/``false`` text the web app sends."""
    if value is None:
        return None
    return "true" if _STRICT_BOOL.validate_python(value) else "false"


async def _resolve_host(registry: Registry, host: str) -> tuple[APIKeyConfig | None, str]:
    """``(key, host_id)`` for a console selector (name or id), on its owning key."""
    validate_selector(host, "host")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    return key, host_id


async def resolve_site_slug(
    registry: Registry, host: str, site: str
) -> tuple[APIKeyConfig | None, str, str]:
    """Validate both selectors before even the cold registry's host lookup."""
    validate_selector(host, "host")
    validate_selector(site, "site")
    return await _resolve_site_slug(registry, host, site)


def _classic(host_id: str, path: str) -> str:
    """Connector URL of a Classic ``/api...`` path."""
    return _CONSOLE.format(host_id=host_id) + f"/api{path}"


async def _classic_get(
    client: UniFiClient,
    path: str,
    *,
    key: APIKeyConfig | None,
    params: dict[str, Any] | None = None,
) -> Any:
    """GET a Classic route and require ``meta.rc == "ok"``; the body verbatim on success.

    A Classic route can answer HTTP 2xx with ``meta.rc == "error"``; that is not success.
    The error carries the reason and the complete upstream body (secrets masked only under
    ``UNIFI_REDACT_SECRETS``). Non-2xx statuses are raised by the client as usual.
    """
    resp = await client.request("GET", path, key=key, params=params)
    body = decode_body(resp)
    reason = classic_rc_failure(resp.status_code, body)
    if reason is not None:
        text = upstream_error_text(resp.text, client)
        raise ClassicCommandError(f"Classic read error from GET {path}: {reason}: {text}")
    return body


# --- Configuration defaults and reference data -----------------------------------------


async def get_network_config_defaults(
    client: UniFiClient,
    registry: Registry,
    host: str,
    kind: str,
    site: str | None = None,
) -> Any:
    """GET the controller's default object for one configuration kind, verbatim."""
    if site is not None:
        validate_selector(site, "site")
    kind = _DEFAULTS_KIND.validate_python(kind)
    scope, route = DEFAULTS_ROUTES[kind]
    if scope == "site":
        check_selector("site", site)
        key, host_id, slug = await resolve_site_slug(registry, host, site)  # type: ignore[arg-type]
        return await client.get(v2_site(host_id, slug, route), key=key)
    key, host_id = await _resolve_host(registry, host)
    return await client.get(v2_root(host_id, route), key=key)


async def get_controller_stats(
    client: UniFiClient,
    registry: Registry,
    host: str,
    view: str = "recent_series",
    *,
    schema: str | None = None,
    period: str | None = None,
    start: int | None = None,
    end: int | None = None,
    bucket: str | None = None,
    filter: str | None = None,
    projection: list[str] | None = None,
    nested_projection: list[str] | None = None,
    no_gaps: bool | None = None,
) -> Any:
    """Query the controller statistics service (v2 ``/stats*``), verbatim."""
    view = _STATS_VIEW.validate_python(view)
    parts = []
    if projection is not None:
        parts.append(f"values({', '.join(projection)})")
    if nested_projection is not None:
        parts.append(f"nested({', '.join(nested_projection)})")
    params = _given(
        schema=schema,
        period=period,
        start=_epoch_ms(start, "start"),
        end=_epoch_ms(end, "end"),
        bucket=bucket,
        filter=filter,
        projection=",".join(parts) or None,
        noGaps=_bool_text(no_gaps),
    )
    key, host_id = await _resolve_host(registry, host)
    if view == "recent_series" and (schema is None or (period is None and start is None)):
        hint = (
            "recent_series needs schema and either period or start; "
            "for example schema=clientCountBySite and period=DAY."
        )
    elif view == "series" and (schema is None or bucket is None or start is None or end is None):
        hint = (
            "series needs schema, bucket, start and end (epoch seconds); for example "
            "schema=wanBySite, bucket=OF_1_HOUR, start=1760140800, end=1760227200 and "
            "filter=siteId.eq('<site uuid>')."
        )
    else:
        hint = None
    response = await with_upstream_hint(
        client.get(v2_root(host_id, STATS_ROUTES[view]), key=key, params=params or None), hint
    )
    return with_warnings(response, epoch_warnings(start=start, end=end))


async def get_sites_overview(
    client: UniFiClient,
    registry: Registry,
    host: str,
    *,
    search_text: str | None = None,
    sort_by_field: str | None = None,
    sort_direction: str | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> Any:
    """Sites of one console with device/client counts. Zero-based page: with page_size,
    returns exactly page_size records starting at record page * page_size, gathered across
    console pages whatever the console page size; resume with _nextPage and the same
    page_size. Without page_size, one request returns that console page verbatim.
    page_size alone is page 0: exactly page_size sites from the first (or all if fewer);
    with neither, every page is drained.
    """
    # The zero-based page is checked at entry, before host resolution or any request.
    validate_pagination(
        page_size=page_size, zero_page=page, names={"page_size": "page_size", "zero_page": "page"}
    )
    if page is not None:
        _STRICT_INT.validate_python(page)
    if page_size is not None:
        _STRICT_INT.validate_python(page_size)
    guard_action("POST")
    key, host_id = await _resolve_host(registry, host)
    path = v2_root(host_id, "/sites/overview")
    body = _given(
        searchText=search_text,
        sortByField=sort_by_field,
        sortDirection=sort_direction,
        pageSize=page_size,
    )
    if page is not None and page_size is None:
        return await client.post(path, key=key, json={**body, "pageNumber": page})

    async def fetch(paging: dict[str, Any]) -> Any:
        return await client.post(path, key=key, json={**body, **paging})

    if page_size is not None and page_size > 0 and (page or 0) >= 0:
        # The logical window [page*N, page*N + N), whatever the console page size;
        # page_size alone is window 0, so its _nextPage counts page_size windows.
        collected = await collect_number_window(
            fetch,
            page=page or 0,
            page_size=page_size,
            max_pages=client.paginate_max_pages,
            # page_size alone keeps the first page's envelope, as the drain from page 0 did.
            keep_console_keys=page is None,
        )
    else:
        collected = await collect_batch(
            fetch,
            requested=page_size,
            default_size=None,
            family="number",
            start=page or 0,
            max_pages=client.paginate_max_pages,
            allow_unpaged=True,
        )
    if "raw" in collected:
        return collected["raw"]
    items = collected["items"]
    result = mark_incomplete(
        with_context(
            {**collected["envelope"], "data": items},
            {"_count": len(items), "_pages": collected["pages"]},
        ),
        {**collected, "incomplete": False},
    )
    if collected.get("incomplete"):
        result = with_context(
            result,
            {"_incomplete": True, "_incompleteReason": collected["incompleteReason"]},
        )
    return result


async def get_network_ui_data(client: UniFiClient, registry: Registry, host: str) -> Any:
    """GET the Network app's UI bootstrap data (Classic ``/api/ui-data``), verbatim."""
    key, host_id = await _resolve_host(registry, host)
    return await _classic_get(client, _classic(host_id, "/ui-data"), key=key)


async def get_sdn_status(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """GET the controller's cloud (SDN) connection status (Classic ``stat/sdn``)."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await _classic_get(client, _classic(host_id, f"/s/{slug}/stat/sdn"), key=key)


async def list_installed_applications(client: UniFiClient, registry: Registry, host: str) -> Any:
    """GET the UniFi OS applications the Network app sees as installed, verbatim."""
    key, host_id = await _resolve_host(registry, host)
    return await client.get(v2_root(host_id, "/system/installed-applications"), key=key)


async def get_console_general_info(client: UniFiClient, registry: Registry, host: str) -> Any:
    """GET the console's cloud access and cloud backup settings (v2), verbatim."""
    key, host_id = await _resolve_host(registry, host)
    return await client.get(v2_root(host_id, "/unifi-core/general-info"), key=key)


async def get_first_system_event(
    client: UniFiClient, registry: Registry, host: str, event_type: str
) -> Any:
    """GET the first system event of one type (v2), verbatim (null when none)."""
    segment = path_segment(event_type, "event_type")
    key, host_id = await _resolve_host(registry, host)
    return await client.get(v2_root(host_id, f"/system/event/{segment}/first"), key=key)


async def list_timezones(client: UniFiClient, registry: Registry, host: str) -> Any:
    """GET every timezone the controller accepts, with its UTC offset, verbatim."""
    key, host_id = await _resolve_host(registry, host)
    return await client.get(v2_root(host_id, "/timezones"), key=key)


async def list_ups_devices(client: UniFiClient, registry: Registry, host: str) -> Any:
    """GET the consoles that can pair with a UniFi UPS and their pairing state, verbatim."""
    key, host_id = await _resolve_host(registry, host)
    return await client.get(v2_root(host_id, "/ups/consoles"), key=key)


async def set_ups_pairing(
    client: UniFiClient,
    registry: Registry,
    host: str,
    action: str,
    console_mac: str,
    *,
    ups_mac: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> Any:
    """Pair a console with a UniFi UPS, or unpair it (v2 ``/ups/pair`` / ``/ups/unpair``)."""
    action = _UPS_ACTION.validate_python(action)
    validate_selector(console_mac, "console_mac")
    if ups_mac is not None:
        validate_selector(ups_mac, "ups_mac")
    guard_action("POST")
    key, host_id = await _resolve_host(registry, host)
    body = {
        "console_mac": console_mac,
        **_given(username=username, password=password, ups_mac=ups_mac),
    }
    response = await client.post(v2_root(host_id, f"/ups/{action}"), key=key, json=body)
    return response


async def list_vendor_ids(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """GET the vendor ids the controller knows for client fingerprinting, verbatim."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.get(v2_site(host_id, slug, "/vendor-ids"), key=key)


async def list_device_models(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    model_id: str | None = None,
) -> Any:
    """GET the UniFi device model catalogue, or one model by id (v2), verbatim."""
    route = "/models"
    if model_id is not None:
        route += "/" + path_segment(model_id, "model_id")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.get(v2_site(host_id, slug, route), key=key)


async def get_device_fingerprint(
    client: UniFiClient, registry: Registry, host: str, source: int
) -> Any:
    """GET the client fingerprint definitions of one fingerprint source (v2), verbatim."""
    source = _STRICT_INT.validate_python(source)
    key, host_id = await _resolve_host(registry, host)
    return await client.get(v2_root(host_id, f"/fingerprint_devices/{source}"), key=key)


async def list_site_features(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    include_system_features: bool | None = None,
    feature: str | None = None,
) -> Any:
    """GET the site's described features, or whether one feature exists (v2)."""
    params = _given(includeSystemFeatures=_bool_text(include_system_features))
    if feature is not None:
        route = f"/features/{path_segment(feature, 'feature')}/exists"
    else:
        route = "/described-features"
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.get(v2_site(host_id, slug, route), key=key, params=params or None)


async def get_site_dashboard(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    history_seconds: int | None = None,
    radio_activity_ap_mac: str | None = None,
) -> Any:
    """GET the site dashboard (v2 aggregated-dashboard), verbatim."""
    if history_seconds is not None:
        _STRICT_INT.validate_python(history_seconds)
    params = _given(
        historySeconds=history_seconds,
        **{"radio_activity.access_point_mac": radio_activity_ap_mac},
    )
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.get(
        v2_site(host_id, slug, "/aggregated-dashboard"), key=key, params=params or None
    )


async def list_site_warnings(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    source: str = "all",
) -> Any:
    """GET the site's warnings: v2 network warnings, Classic controller warnings, or both."""
    source = _WARNINGS_SOURCE.validate_python(source)
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    network = controller = None
    if source in ("all", "network"):
        network = await client.get(v2_site(host_id, slug, "/warnings"), key=key)
    if source in ("all", "controller"):
        controller = await _classic_get(
            client, _classic(host_id, f"/s/{slug}/stat/widget/warnings"), key=key
        )
    if source == "network":
        return network
    if source == "controller":
        return controller
    return {"network": network, "controller": controller}


async def get_cybersecure_summary(
    client: UniFiClient, registry: Registry, host: str, site: str, period: str
) -> Any:
    """GET the CyberSecure (IPS) summary for one period (v2), verbatim."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.get(
        v2_site(host_id, slug, "/cybersecure/summary"), key=key, params={"period": period}
    )


async def get_site_degradation_status(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET whether the Network app runs in degraded (safe) mode (v2), verbatim."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.get(v2_site(host_id, slug, "/degradation-status"), key=key)


async def get_observability_site_health(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    start: int | None = None,
    end: int | None = None,
) -> Any:
    """GET the site's WAN health and activity history (v2 sitehealth), verbatim."""
    params = _given(start=_epoch_ms(start, "start"), end=_epoch_ms(end, "end"))
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    response = await client.get(
        v2_site(host_id, slug, "/observability/sitehealth"), key=key, params=params or None
    )
    return with_warnings(response, epoch_warnings(start=start, end=end))


async def get_observability_people(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET the people (identity owners and their client MACs) the site knows, verbatim."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.get(v2_site(host_id, slug, "/observability/people"), key=key)


async def list_ulp_user_groups(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET the UniFi Identity (ULP) users and groups the site can reference, verbatim."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.get(v2_site(host_id, slug, "/ulp/users_groups"), key=key)


async def list_network_anomalies(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    start: int | None = None,
    end: int | None = None,
    scale: str | None = None,
) -> Any:
    """GET the controller's detected client anomalies (Classic ``stat/anomalies``)."""
    params = _given(scale=scale, start=_epoch_ms(start, "start"), end=_epoch_ms(end, "end"))
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    response = await _classic_get(
        client, _classic(host_id, f"/s/{slug}/stat/anomalies"), key=key, params=params or None
    )
    return with_warnings(response, epoch_warnings(start=start, end=end))


# --- DPI usage, Wi-Fi experience and port suggestions -----------------------


STAT_SCHEMA_SITE_DPI = "applicationTrafficBySite"
STAT_SCHEMA_CLIENT_DPI = "applicationTrafficBySiteByClient"


async def get_site_dpi_usage(
    client: UniFiClient,
    registry: Registry,
    host: str,
    start: int,
    end: int,
    bucket: str | None = None,
    filter: str | None = None,
) -> Any:
    """GET per-application traffic of the site(s) from v2 ``stats/series``, verbatim."""
    require_epoch_seconds(start, "start")
    require_epoch_seconds(end, "end")
    return await get_controller_stats(
        client,
        registry,
        host,
        "series",
        schema=STAT_SCHEMA_SITE_DPI,
        start=start,
        end=end,
        bucket=bucket,
        filter=filter,
    )


async def get_client_dpi_usage(
    client: UniFiClient,
    registry: Registry,
    host: str,
    start: int,
    end: int,
    bucket: str | None = None,
    filter: str | None = None,
) -> Any:
    """GET per-client, per-application traffic from v2 ``stats/series``, verbatim."""
    require_epoch_seconds(start, "start")
    require_epoch_seconds(end, "end")
    return await get_controller_stats(
        client,
        registry,
        host,
        "series",
        schema=STAT_SCHEMA_CLIENT_DPI,
        start=start,
        end=end,
        bucket=bucket,
        filter=filter,
    )


def _client_ip(value: Any) -> str:
    """``value`` when it is one IPv4 or IPv6 address, as given; else raise before any request."""
    if not isinstance(value, str) or not value:
        raise ValueError(
            "'client_ip' must be a client IP address string, for example \"192.168.1.50\" "
            "(from list_active_clients_stats ip). Nothing was sent."
        )
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(
            f"'client_ip' {value!r} is not an IPv4 or IPv6 address (no whitespace, scope id or "
            'port); use the form "192.168.1.50" from list_active_clients_stats ip. '
            "Nothing was sent."
        ) from None
    if "%" in value:
        raise ValueError(
            f"'client_ip' {value!r} carries a scope id; pass the bare address. Nothing was sent."
        )
    return value


async def get_client_wifi_experience(
    client: UniFiClient, registry: Registry, host: str, site: str, client_ip: str
) -> Any:
    """GET one client's Wi-Fi experience (v2 ``wifiman/{client_ip}``), verbatim."""
    ip = _client_ip(client_ip)
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.get(v2_site(host_id, slug, f"/wifiman/{ip}"), key=key)


async def suggest_service_port(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    service: str | None = None,
    protocol: str | None = None,
) -> Any:
    """GET the controller's available ports for a service (v2 ``network/port-suggest``)."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    hint = (
        "port-suggest takes a service name, for example service=openvpn or wireguard; pass service."
        if service is None
        else None
    )
    return await with_upstream_hint(
        client.get(
            v2_site(host_id, slug, "/network/port-suggest"),
            key=key,
            params=_given(service=service, protocol=protocol),
        ),
        hint,
    )


# --- Registration -----------------------------------------------------------------------

_HOST = (
    'Console name or composite id from list_hosts; for example "Home UDM" (hostname or '
    "reportedState.name, case-insensitive)."
)
_SITE = 'Network site name or id from list_local_sites; for example "Default".'


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register this module's tools on ``mcp`` (called once by the server)."""

    def tool(fn: Callable[..., Any]) -> Any:
        # FastMCP exposes the prose before ``Args:`` as the tool description. Make
        # each required parameter visible there as well as in its detailed Args entry.
        # This keeps the catalog usable for clients that display only descriptions.
        required = [
            name
            for name, parameter in signature(fn).parameters.items()
            if parameter.default is Parameter.empty
        ]
        # Each tool states its own result in its docstring: no shared result line is added
        # here (one would contradict the tools that drain, wrap or add keys).
        doc = getdoc(fn)
        if required and doc:
            prose, marker, args = doc.partition("\n\nArgs:\n")
            required_line = f"Required inputs: {', '.join(required)}."
            fn.__doc__ = (
                f"{prose.rstrip()}\n\n{required_line}{marker}{args}"
                if marker
                else f"{doc.rstrip()}\n\n{required_line}"
            )
        # Derive hints from the complete implementation call graph at registration.
        writes = derive_write_tools([SimpleNamespace(name=fn.__name__, fn=fn)])
        return mcp.tool(annotations=for_tool(writes=fn.__name__ in writes))(fn)

    @tool
    async def get_network_config_defaults(
        host: str, kind: DefaultsKind, site: str | None = None
    ) -> Any:
        """Get the default object the Network app uses when it creates a configuration item.

        Shows the field values a new item starts with (for example a new LAN's DHCP
        settings or a new firewall policy's action). Returns the upstream body verbatim: an
        object, or an array for wlan, wifiai and firewall_zone. Kinds and routes (GET /v2/api/...):
        port_profile, wan, lan, wlan, firewall_policy, firewall_zone, connectivity, doh,
        element_adopt, global_switch, ips_advanced_filtering, netflow, ntp, usg (gateway
        timeouts), wifiai, ssl_inspection_profile, ssl_inspection_setting and
        system_log_setting are per site (site required); log_levels and super_mgmt
        (data retention) are console-wide (site not used).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            kind: Defaults kind from the list above; for example "lan".
            site: Network site name or id, required for per-site kinds; for example
                "Default".
        """
        client, registry = deps_fn()
        return await _impl_defaults(client, registry, host, kind, site)

    @tool
    async def get_controller_stats(
        host: str,
        view: StatsView = "recent_series",
        schema: str | None = None,
        period: str | None = None,
        start: int | None = None,
        end: int | None = None,
        bucket: str | None = None,
        filter: str | None = None,
        projection: list[str] | None = None,
        nested_projection: list[str] | None = None,
        no_gaps: bool | None = None,
    ) -> Any:
        """Query the controller's time-series statistics service, as the web app's graphs do.

        Returns the upstream body verbatim. View recent_series (GET
        /v2/api/stats/recent/series) answers an array of {siteId, deviceMac?, series: [...]};
        it needs schema and exactly one of period or start (end is optional), otherwise the
        console may return HTTP 400. View series (GET /v2/api/stats/series) reads history
        over an explicit window; it takes schema, bucket, start, end and filter (open-source
        clients send all five; a missing one adds a hint to the console's error). Open-source
        clients pad OF_1_MONTH window bounds to January 2nd; that is unverified here, so
        start and end are sent exactly as given. View source answers the active statistics
        backend as a string ("MODERN" or "LEGACY"). When start or end is negative or looks like
        epoch milliseconds, an object result gains an additive _warnings list and an array
        result is returned as {result, _warnings}. Only the arguments you pass are sent.
        filter uses the service's own grammar; a one-term and(...) is rejected
        (HTTP 400 InvalidStatQuery). Live dev GETs on Network 11.0.81 accepted and(...)
        with two and three terms (HTTP 200, empty arrays for synthetic MAC filters).
        A single term without and(...) also works.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            view: recent_series, series or source; for example "series".
            schema: Series schema, such as wanBySiteByDevice, wirelessBySiteByDevice,
                systemBySiteByDevice, clientCountBySite or portBySiteByDevice; for example
                "clientCountBySite".
            period: HOUR, DAY, WEEK or MONTH; for example "DAY".
            start: Window start, epoch SECONDS (sent as ms); for example 1760140800.
            end: Window end, epoch SECONDS (sent as ms); for example 1760227200.
            bucket: OF_5_MINUTES, OF_1_HOUR, OF_8_HOURS or OF_1_MONTH; for example
                "OF_5_MINUTES".
            filter: Filter expression sent as given; for example
                "deviceMac.eq('02:00:5e:00:53:01')".
            projection: Value fields, sent as values(...); for example ["rxBytes",
                "txBytes"].
                Shape: string[]
            nested_projection: Nested groupings, sent as nested(...); for example
                ["byNetworkGroup"].
                Shape: string[]
            no_gaps: Fill empty buckets, sent as noGaps; for example true.
        """
        client, registry = deps_fn()
        return await _impl_stats(
            client,
            registry,
            host,
            view,
            schema=schema,
            period=period,
            start=start,
            end=end,
            bucket=bucket,
            filter=filter,
            projection=projection,
            nested_projection=nested_projection,
            no_gaps=no_gaps,
        )

    @tool
    async def get_sites_overview(
        host: str,
        search_text: str | None = None,
        sort_by_field: str | None = None,
        sort_direction: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
        confirm: bool = False,
    ) -> Any:
        """Get every Network site on one console with its device, client and health counts.

        Reads POST /v2/api/sites/overview (a read-only query sent as a POST, so read-only
        mode refuses it). Consequence: none intended; it changes nothing. Each site carries
        id, name, description, counts (total/offline/wifi/wired/gateway devices,
        wifi/wired/guest clients, pending updates, critical notifications, LAN/WAN/WiFi
        configurations) and
        percentages (wan_uptime, successful_association). Every page is drained by
        default. Returns the first page's envelope as the upstream sent it (for example
        total_page_count, total_element_count, page_number) with data holding the sites of
        every page, plus _count (sites) and _pages (pages read); _incomplete and
        _incompleteReason are added when the drain stopped short (a UNIFI_PAGINATE_MAX_PAGES
        cap, a page without the paged envelope, or a page answered under another number).
        A first page without a data array is returned as received. Pass page alone (0-based)
        for that one page verbatim. page_size alone is window 0: exactly page_size sites
        from the first; _nextPage counts page_size windows, so resume with page=_nextPage
        and the same page_size. page with page_size returns that window of sites. _pageSize
        reports the requested count, sent (every pageSize sent, in request order), the
        effective console page size and the returned count. _nextPage is absent when no
        site follows the window or the call stopped short (_incomplete). For counts across
        every console use list_sites. With dry-run policy, returns {status: "dry_run",
        dryRun: true, sent: false, message, preview: {method, path, params, body}} and sends
        nothing.

        Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides
        the whole tool and discovery mode runs it through call_write_tool.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            search_text: Filter sites by text, sent as searchText; for example "branch".
            sort_by_field: Field to sort by, sent as sortByField; for example "name".
            sort_direction: ASCENDING or DESCENDING; for example "ASCENDING".
            page: Zero-based page. With page_size, returns exactly page_size records starting
                at record page * page_size, gathered across console pages whatever the console
                page size; resume with _nextPage and the same page_size. Without page_size, one
                request returns that console page verbatim. For example 0.
            page_size: Number of sites. Alone, window 0 (the first page_size sites); with
                page, the size of the window. Fewer if the collection ends. Omit to drain all.
                Example: 1000.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_overview(
            client,
            registry,
            host,
            search_text=search_text,
            sort_by_field=sort_by_field,
            sort_direction=sort_direction,
            page=page,
            page_size=page_size,
        )

    @tool
    async def get_network_ui_data(host: str) -> Any:
        """Get the Network app's UI bootstrap data (Classic GET /api/ui-data).

        Returns the Classic envelope {meta: {rc}, data: [...]} verbatim; data holds
        front-end service keys (map, payment and image providers) and LTE pricing.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
        """
        client, registry = deps_fn()
        return await _impl_ui_data(client, registry, host)

    @tool
    async def get_sdn_status(host: str, site: str) -> Any:
        """Get the controller's UniFi cloud (SDN) connection status.

        Returns the Classic envelope verbatim; data[0] has enabled, connected,
        has_sso_auth, is_udm, is_cloud_key and ubic_env (Classic GET stat/sdn).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
        """
        client, registry = deps_fn()
        return await _impl_sdn(client, registry, host, site)

    @tool
    async def list_installed_applications(host: str) -> Any:
        """List the UniFi OS applications the Network app sees as installed on the console.

        Returns the array verbatim, one {name} per application
        (GET /v2/api/system/installed-applications). For versions and run state see
        get_host (reportedState.controllers).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
        """
        client, registry = deps_fn()
        return await _impl_apps(client, registry, host)

    @tool
    async def get_console_general_info(host: str) -> Any:
        """Get whether remote (cloud) access and cloud backup are enabled on the console.

        Returns {cloud_access_enabled, cloud_backup_enabled} verbatim (GET
        /v2/api/unifi-core/general-info). A body that is not a JSON object arrives as {result:
        ...}.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
        """
        client, registry = deps_fn()
        return await _impl_general_info(client, registry, host)

    @tool
    async def get_first_system_event(host: str, event_type: str) -> Any:
        """Get the first recorded system event of one type, such as when setup completed.

        Returns the upstream body of GET /v2/api/system/event/{event_type}/first verbatim; null when
        the console has none. A body that is not a JSON object arrives as {result: ...}. An
        unknown type answers HTTP 400.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            event_type: System event type; for example "SETUP_COMPLETED".
        """
        client, registry = deps_fn()
        return await _impl_first_event(client, registry, host, event_type)

    @tool
    async def list_timezones(host: str) -> Any:
        """List every timezone the controller accepts, with its UTC offset.

        Returns the array verbatim, one {timezone, offset} per zone
        (GET /v2/api/timezones). Use a timezone value in site and schedule settings.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
        """
        client, registry = deps_fn()
        return await _impl_timezones(client, registry, host)

    @tool
    async def list_ups_devices(host: str) -> Any:
        """List the consoles that can pair with a UniFi UPS for safe shutdown, with state.

        Returns the array verbatim (GET /v2/api/ups/consoles): console_mac, name, model,
        state (paired, unpaired, upgrade_needed, token_invalid, offline), ups_mac (null
        when not paired), square_wave_incompatible and icon. Pair or unpair with
        set_ups_pairing.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
        """
        client, registry = deps_fn()
        return await _impl_ups(client, registry, host)

    @tool
    async def set_ups_pairing(
        host: str,
        action: UpsAction,
        console_mac: str,
        ups_mac: str | None = None,
        username: str | None = None,
        password: str | None = None,
        confirm: bool = False,
    ) -> Any:
        """Pair a console with a UniFi UPS for safe shutdown, or unpair it.

        Consequence: pair links the console to the UPS so the UPS can signal it to shut down
        safely on power loss; unpair removes that link and with it the shutdown signal.

        Action pair sends {console_mac, username, password, ups_mac} to
        POST /v2/api/ups/pair: the console logs in to the UPS with the UI account given.
        action unpair sends {console_mac} to POST /v2/api/ups/unpair. Only the
        arguments you pass are sent; the console reports a missing one. Returns the
        upstream body verbatim, whatever its type: a 204 response does not prove an unpair;
        an unpair can answer a bare true, and a
        body that is not a JSON object arrives as {result: ...}. The
        password is a credential: UNIFI_REDACT_SECRETS masks it. With dry-run policy,
        returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}} and sends nothing.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            action: "pair" or "unpair"; for example "unpair".
            console_mac: console_mac from list_ups_devices; for example
                "02:00:5e:00:53:01".
            ups_mac: MAC of the UPS to pair with (pair); for example "02:00:5e:00:53:02".
            username: UI account username or email for the UPS (pair); for example
                "admin@example.com".
            password: UI account password for the UPS (pair); for example "example-pass".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _impl_ups_pairing(
            client,
            registry,
            host,
            action,
            console_mac,
            ups_mac=ups_mac,
            username=username,
            password=password,
        )

    @tool
    async def list_vendor_ids(host: str, site: str) -> Any:
        """List the device vendor ids the controller's client fingerprinting knows.

        Returns the array of vendor id strings verbatim (GET /v2/api/site/{site}/vendor-ids).

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
        """
        client, registry = deps_fn()
        return await _impl_vendor_ids(client, registry, host, site)

    @tool
    async def list_device_models(host: str, site: str, model_id: str | None = None) -> Any:
        """List the UniFi device model catalogue, or get one model by id.

        Returns the upstream body verbatim (GET /v2/api/site/{site}/models[/{model_id}]): without
        model_id the catalogue object, whose model_list entries carry id, model_name,
        model_fullName, model_abbreviation, model_sysid, sku and image ids; with model_id that
        model's object. A body that is not a JSON object arrives as {result: ...}.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            model_id: Model id from model_list[].id; for example "UDMPRO".
        """
        client, registry = deps_fn()
        return await _impl_models(client, registry, host, site, model_id)

    @tool
    async def get_device_fingerprint(host: str, source: int) -> Any:
        """Get the client fingerprint definitions (id to name maps) of one source.

        Returns the upstream body of GET /v2/api/fingerprint_devices/{source} verbatim.
        The web app reads
        sources 0 (custom: dev_ids, vendor_ids, os_name_ids, family_ids, dev_type_ids,
        os_class_ids, ctag_ids), 1 (built-in maps) and 2 (extended dev_ids, several MB);
        source -1 answers HTTP 404 on Network 11.0.81. Use it to name the dev_id and
        vendor ids that client records carry.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            source: Fingerprint source id; for example 1.
        """
        client, registry = deps_fn()
        return await _impl_fingerprint(client, registry, host, source)

    @tool
    async def list_site_features(
        host: str,
        site: str,
        include_system_features: bool | None = None,
        feature: str | None = None,
    ) -> Any:
        """List the site's features with enabled state and limitations, or check one.

        Returns the upstream body verbatim. Without feature it is the array from GET
        .../described-features: name, enabled, feature_exists and limitations (device MACs
        and ports a feature cannot use); include_system_features true adds the system
        features, as the web app does. With feature it is the object from GET
        .../features/{feature}/exists, which carries feature_exists.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            include_system_features: Also list system features; for example true.
            feature: One feature name from the list; for example "ips".
        """
        client, registry = deps_fn()
        return await _impl_features(
            client,
            registry,
            host,
            site,
            include_system_features=include_system_features,
            feature=feature,
        )

    @tool
    async def get_site_dashboard(
        host: str,
        site: str,
        history_seconds: int | None = None,
        radio_activity_ap_mac: str | None = None,
    ) -> Any:
        """Get the site dashboard the Network web app opens with.

        Returns the upstream body of GET /v2/api/site/{site}/aggregated-dashboard verbatim. Without
        history_seconds it has internet, isp_metrics, wan_activity, radio_activity, wifi_channels,
        wifi_technology, most active APs and clients, traffic identification and upgradable devices.
        With history_seconds (as the web app sends) it also has gateway, system_status, speed_test,
        cybersecure, wifi_connectivity, wifi_activity, wan_history and degradation_status. A body
        that is not a JSON object arrives as {result: ...}.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            history_seconds: History window in seconds, sent as historySeconds; for
                example 86400.
            radio_activity_ap_mac: Limit radio activity to one AP, sent as
                radio_activity.access_point_mac; for example "02:00:5e:00:53:01".
        """
        client, registry = deps_fn()
        return await _impl_dashboard(
            client,
            registry,
            host,
            site,
            history_seconds=history_seconds,
            radio_activity_ap_mac=radio_activity_ap_mac,
        )

    @tool
    async def list_site_warnings(host: str, site: str, source: WarningsSource = "all") -> Any:
        """List the site's warnings from both places the controller keeps them.

        Returns, for source network, the body of GET /v2/api/site/{site}/warnings verbatim:
        rogue_clients, rogue_dhcps, missing_windows_defender_firewall_rules. For source
        controller, the Classic GET stat/widget/warnings envelope verbatim: firmware update
        state, end-of-life, LTS and unsupported device counts, LTE subscription problems
        and controller_low_disk_space. For source all (default), {network, controller}
        holding those two bodies.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            source: all, network or controller; for example "all".
        """
        client, registry = deps_fn()
        return await _impl_warnings(client, registry, host, site, source)

    @tool
    async def get_cybersecure_summary(host: str, site: str, period: str) -> Any:
        """Get the CyberSecure (IPS/IDS) summary for one period.

        Returns the upstream body of GET /v2/api/site/{site}/cybersecure/summary?period=...
        verbatim: ips_enabled, has_subscription, enterprise, is_activating, signatures,
        signature_capacity, threats, scanned_bytes, updated_timestamp. A body that is not a JSON
        object arrives as {result: ...}. The console requires period.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            period: HOUR, DAY, WEEK or MONTH; for example "DAY".
        """
        client, registry = deps_fn()
        return await _impl_cybersecure(client, registry, host, site, period)

    @tool
    async def get_site_degradation_status(host: str, site: str) -> Any:
        """Get whether the Network application runs in degraded (safe) mode.

        Returns {safe_mode} verbatim (GET /v2/api/site/{site}/degradation-status). A body that is
        not a JSON object arrives as {result: ...}.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
        """
        client, registry = deps_fn()
        return await _impl_degradation(client, registry, host, site)

    @tool
    async def get_observability_site_health(
        host: str, site: str, start: int | None = None, end: int | None = None
    ) -> Any:
        """Get the site's WAN health and traffic history.

        Returns the upstream body of GET /v2/api/site/{site}/observability/sitehealth
        verbatim: wan_activity (total and per-WAN history of rx/tx rate, latency, packet
        loss and client count) and wan_history (per WAN uptime, ISP, health and downtime
        history). Without start and end the console picks its default window. When start
        or end is negative or looks like epoch milliseconds, an object result gains an
        additive _warnings list and an array result is returned as {result, _warnings}.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            start: Window start, epoch SECONDS (sent as ms); for example 1760140800.
            end: Window end, epoch SECONDS (sent as ms); for example 1760227200.
        """
        client, registry = deps_fn()
        return await _impl_site_health(client, registry, host, site, start=start, end=end)

    @tool
    async def get_observability_people(host: str, site: str) -> Any:
        """List the people the site knows, each with the client MACs assigned to them.

        Returns the array verbatim (GET /v2/api/site/{site}/observability/people): id,
        name and client_macs per person.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
        """
        client, registry = deps_fn()
        return await _impl_people(client, registry, host, site)

    @tool
    async def list_ulp_user_groups(host: str, site: str) -> Any:
        """List the UniFi Identity users and groups the site can reference.

        Returns {users, groups} verbatim (GET /v2/api/site/{site}/ulp/users_groups); each user has
        unique_id, full_name and group_ids. A body that is not a JSON object arrives as {result:
        ...}.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
        """
        client, registry = deps_fn()
        return await _impl_ulp(client, registry, host, site)

    @tool
    async def list_network_anomalies(
        host: str,
        site: str,
        start: int | None = None,
        end: int | None = None,
        scale: str | None = None,
    ) -> Any:
        """List the client connectivity anomalies the controller detected.

        Returns the Classic envelope {meta, data} of GET stat/anomalies verbatim. When
        start or end is negative or looks like epoch milliseconds, the envelope gains an
        additive _warnings list. Only the arguments you pass are sent.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            start: Window start, epoch SECONDS (sent as ms); for example 1760140800.
            end: Window end, epoch SECONDS (sent as ms); for example 1760227200.
            scale: Aggregation scale; for example "hourly".
        """
        client, registry = deps_fn()
        return await _impl_anomalies(
            client, registry, host, site, start=start, end=end, scale=scale
        )

    @tool
    async def get_site_dpi_usage(
        host: str,
        start: int,
        end: int,
        bucket: str | None = None,
        filter: str | None = None,
    ) -> Any:
        """Get which applications use the bandwidth, per site, over a time window.

        Reads GET /v2/api/stats/series with schema applicationTrafficBySite. Returns the
        upstream body verbatim (a JSON array arrives as {result: [...]}): per site, per time
        bucket, rxOtherBytes, txOtherBytes and
        byApplication[] of {applicationId, categoryId, rxBytes, txBytes, activityS}. Names
        for the ids come from list_dpi_applications and list_dpi_categories; category totals
        are the sum of the applications with one categoryId. The series covers every site
        of the console unless filter narrows it. When start or end is negative or looks like
        epoch milliseconds, an object result gains an additive _warnings list and an array
        result is returned as {result, _warnings}. For one client at a time use
        get_client_dpi_usage.
        Simulated only: no recorded live console answer yet.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            start: Window start, epoch SECONDS (sent as ms); for example 1760140800.
            end: Window end, epoch SECONDS (sent as ms); for example 1760227200.
            bucket: Bucket size, sent as given: OF_5_MINUTES, OF_1_HOUR, OF_8_HOURS or
                OF_1_MONTH; omit it to let the console choose; for example "OF_1_HOUR".
            filter: Filter expression in the statistics service's grammar, sent as given; for
                example "siteId.eq('00000000-0000-4000-8000-0000000000aa')".
        """
        client, registry = deps_fn()
        return await _impl_site_dpi(
            client, registry, host, start, end, bucket=bucket, filter=filter
        )

    @tool
    async def get_client_dpi_usage(
        host: str,
        start: int,
        end: int,
        bucket: str | None = None,
        filter: str | None = None,
    ) -> Any:
        """Get which applications each client uses, over a time window.

        Reads GET /v2/api/stats/series with schema applicationTrafficBySiteByClient. Returns
        the upstream body verbatim (a JSON array arrives as {result: [...]}): one row per
        client (siteId, clientId) with, per
        time bucket, byApplication[] of {applicationId, categoryId, rxBytes, txBytes,
        activityS}. Names for the ids come from list_dpi_applications and
        list_dpi_categories. When start or end is negative or looks like epoch milliseconds,
        an object result gains an additive _warnings list and an array result is returned as
        {result, _warnings}. For the site as a whole use get_site_dpi_usage.
        Simulated only: no recorded live console answer yet.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            start: Window start, epoch SECONDS (sent as ms); for example 1760140800.
            end: Window end, epoch SECONDS (sent as ms); for example 1760227200.
            bucket: Bucket size, sent as given: OF_5_MINUTES, OF_1_HOUR, OF_8_HOURS or
                OF_1_MONTH; omit it to let the console choose; for example "OF_1_HOUR".
            filter: Filter expression in the statistics service's grammar, sent as given; for
                example "siteId.eq('00000000-0000-4000-8000-0000000000aa')".
        """
        client, registry = deps_fn()
        return await _impl_client_dpi(
            client, registry, host, start, end, bucket=bucket, filter=filter
        )

    @tool
    async def get_client_wifi_experience(host: str, site: str, client_ip: str) -> Any:
        """Get one wireless client's Wi-Fi experience (the web app's per-client WiFiman view).

        Returns the upstream body verbatim (a body that is not a JSON object arrives as
        {result: ...}) from GET /v2/api/site/{site}/wifiman/{client_ip}:
        channel, channel_width, link rates, signal, noise, wifi_experience, wlan_band,
        radio_protocol, nearest_neighbors[], statistics[] (experience over time) and
        uplink_devices[]. Band codes ("2.4g", "5g", "6g") differ from the "ng", "na" and "6e"
        of the Classic client record. An IP that is not a wireless client answers HTTP 404
        (api.err.ClientNotFound). The settings route is get_wifiman_settings.
        Simulated only: no recorded live console answer yet.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            client_ip: The client's IPv4 or IPv6 address, as in the ip field of
                list_active_clients_stats; for example "192.168.1.50". Anything else is
                refused before any request.
        """
        client, registry = deps_fn()
        return await _impl_wifi_experience(client, registry, host, site, client_ip)

    @tool
    async def suggest_service_port(
        host: str, site: str, service: str | None = None, protocol: str | None = None
    ) -> Any:
        """Suggest free ports for a service on the gateway, as the web app does for VPN servers.

        Returns the upstream body verbatim (a body that is not a JSON object arrives as
        {result: ...}) from GET /v2/api/site/{site}/network/port-suggest,
        for example {available_ports: [1194]} for openvpn. It is a different route from
        suggest_network_settings, which suggests network settings. Only the arguments you
        pass are sent; without service the console may answer an error, to which a hint is
        added.
        Simulated only: no recorded live console answer yet.

        Args:
            host: Console name or composite id from list_hosts; for example "Home UDM".
            site: Network site name or id from list_local_sites; for example "Default".
            service: The service to suggest ports for, sent as given: openvpn or wireguard;
                for example "openvpn".
            protocol: Optional transport protocol, sent as given; the web app sends "udp" with
                wireguard; for example "udp".
        """
        client, registry = deps_fn()
        return await _impl_port_suggest(client, registry, host, site, service, protocol)


# The registered tools share their names with the helpers above; keep module-level
# aliases so the closures inside register() call the helpers, not themselves.
_impl_defaults = get_network_config_defaults
_impl_stats = get_controller_stats
_impl_overview = get_sites_overview
_impl_ui_data = get_network_ui_data
_impl_sdn = get_sdn_status
_impl_apps = list_installed_applications
_impl_general_info = get_console_general_info
_impl_first_event = get_first_system_event
_impl_timezones = list_timezones
_impl_ups = list_ups_devices
_impl_ups_pairing = set_ups_pairing
_impl_vendor_ids = list_vendor_ids
_impl_models = list_device_models
_impl_fingerprint = get_device_fingerprint
_impl_features = list_site_features
_impl_dashboard = get_site_dashboard
_impl_warnings = list_site_warnings
_impl_cybersecure = get_cybersecure_summary
_impl_degradation = get_site_degradation_status
_impl_site_health = get_observability_site_health
_impl_people = get_observability_people
_impl_ulp = list_ulp_user_groups
_impl_anomalies = list_network_anomalies
_impl_site_dpi = get_site_dpi_usage
_impl_client_dpi = get_client_dpi_usage
_impl_wifi_experience = get_client_wifi_experience
_impl_port_suggest = suggest_service_port
