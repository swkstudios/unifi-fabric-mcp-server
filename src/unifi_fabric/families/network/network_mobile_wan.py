"""UniFi Network mobile broadband (LTE / 5G / eSIM) and WAN tools.

Route choice (official published API > private v2 API > Classic API), recorded per tool in
:data:`ROUTE_CHOICES`:

* The official Network Integration API (pinned 11.0.97) has no LTE, SIM, eSIM, WAN SLA,
  load-balancing, WAN insight, enriched-configuration or route-table operation; its only
  WAN route, ``GET /v1/sites/{siteId}/wans``, lists WAN ids and names (``list_wan_interfaces``).
  Site Manager ``isp-metrics`` reports per-site ISP latency and loss, not per-WAN-group
  insights or speed tests.
* The LTE and mobile-broadband (MBB) commands exist only as Classic command managers
  (``POST api/s/{site}/cmd/lte`` and ``cmd/mbb``) in the Network 11.0.81 web app, so those
  nine tools use the shared Classic command helper (``tools._classic_cmd``): success is
  HTTP 2xx AND ``meta.rc == "ok"``.
* Every WAN tool uses the v2 route the Network 11.0.81 web app calls.

Request bodies: where the 11.0.81 bundle builds a body from static keys (``auth-device``,
``check-subscription``, ``lte-verify-pin``) the tool takes those keys as typed arguments.
Where the bundle builds it dynamically (``activate-trial``, ``update-device``,
``lte-set-profile``, every ``cmd/mbb`` command, WAN SLA and load-balancing bodies, LTE
failover) the tool takes a free-form object and sends it as given; no required key is
invented.

Credentials: the SIM PIN, the UI account password and 2FA token, APN credentials and eSIM
activation codes are listed in ``route_secrets.ROUTE_SECRETS``. Error text, structured
results and dry-run previews carry them verbatim unless the operator sets
``UNIFI_REDACT_SECRETS``; logs and the audit log always mask them.

Every response body is passed through verbatim (server pass-through invariant); results
add only ``_``-prefixed keys. Every argument is checked before the first request
(resolution reads included). Under ``dry-run policy`` every write returns the client's
dry-run preview ``{status, dryRun, sent: false, message, preview}`` and sends nothing.
"""

from __future__ import annotations

from collections.abc import Awaitable, Mapping
from typing import Any, Literal

from pydantic import StrictBool, TypeAdapter

from ...client import (
    UniFiClient,
    describe_shape,
    is_dry_run_preview,
    object_records,
    path_segment,
    strip_additive_keys,
    upstream_error_value,
    validate_selector,
)
from ...config import APIKeyConfig
from ...macs import colon_mac, is_mac, record_mac
from ...matching import find_by_id
from ...redaction import drop_masked_fields, note_dropped_fields
from ...registry import Registry
from ...route_secrets import mask_request_body, mask_response_body, request_secrets
from ...secret_scrub import scrub
from ...selector_args import check_selector
from ...shared_shapes._classic_cmd import classic_cmd_path, classic_command, classic_command_body
from ...shared_shapes._classic_objects import resolve_site_slug, v2_site
from ...shared_shapes._keys import with_context
from ...shared_shapes._results import (
    UNVERIFIED_FIELDS_KEY,
    VERIFIED_KEY,
    deletion_result,
    leaf_equal,
    read_after_verdict,
    safe_read_after,
    with_read_after_error,
)
from ...write_body import require_update_fields
from .schemas import (  # the family's shapes (family-owned layout)
    _INSIGHT_ROUTES,
    EnrichedKind,
    EsimAction,
    LoadBalancingView,
    LteManager,
)

_CONSOLE = "/v1/connector/consoles/{host_id}/proxy/network"

InsightView = Literal["overview", "history", "speed_tests"]
_LTE_MANAGER = TypeAdapter(LteManager)
_ESIM_ACTION = TypeAdapter(EsimAction)
_LB_VIEW = TypeAdapter(LoadBalancingView)
_INSIGHT_VIEW = TypeAdapter(InsightView)
_ENRICHED_KIND = TypeAdapter(EnrichedKind)
_OPTIONAL_BOOL = TypeAdapter(StrictBool | None)

#: Route choice per tool: (source, route, reason the official API is not used).
ROUTE_CHOICES: dict[str, tuple[str, str, str]] = {
    "get_lte_subscription_status": (
        "classic",
        "POST /api/s/{site}/cmd/lte {cmd: check-subscription}",
        "no official or v2 route; Classic command only (11.0.81 bundle)",
    ),
    "activate_lte_trial": (
        "classic",
        "POST /api/s/{site}/cmd/lte {cmd: activate-trial}",
        "no official or v2 route",
    ),
    "authorize_lte_device": (
        "classic",
        "POST /api/s/{site}/cmd/lte {cmd: auth-device}",
        "no official or v2 route",
    ),
    "set_lte_apn_profile": (
        "classic",
        "POST /api/s/{site}/cmd/lte {cmd: lte-set-profile}",
        "no official or v2 route",
    ),
    "verify_sim_pin": (
        "classic",
        "POST /api/s/{site}/cmd/lte {cmd: lte-verify-pin} | cmd/mbb {cmd: verify-pin}",
        "no official or v2 route",
    ),
    "update_lte_device": (
        "classic",
        "POST /api/s/{site}/cmd/lte {cmd: update-device}",
        "no official or v2 route",
    ),
    "manage_esim_profile": (
        "classic",
        "POST /api/s/{site}/cmd/mbb {cmd: esim-add | esim-delete}",
        "no official or v2 route",
    ),
    "get_inactive_sim_slot": (
        "classic",
        "POST /api/s/{site}/cmd/mbb {cmd: read-inactive-slot-sim-card}",
        "no official or v2 route",
    ),
    "reset_mobile_data_usage": (
        "classic",
        "POST /api/s/{site}/cmd/mbb {cmd: reset-usage}",
        "no official or v2 route",
    ),
    "set_lte_failover": (
        "v2",
        "PUT /v2/api/site/{site}/lan/enable-lte-failover",
        "no official route",
    ),
    "get_wan_load_balancing": (
        "v2",
        "GET /v2/api/site/{site}/wan/load-balancing/{configuration,status}",
        "official GET /v1/sites/{id}/wans lists WAN ids and names only",
    ),
    "update_wan_load_balancing": (
        "v2",
        "PUT /v2/api/site/{site}/wan/load-balancing/configuration[?testConfigId]",
        "official WAN route is read-only and has no load-balancing fields",
    ),
    "list_wan_network_groups": (
        "v2",
        "GET /v2/api/site/{site}/wan/networkgroups[?uptime]",
        "official /v1/sites/{id}/wans has no network group or uptime",
    ),
    "get_wan_insights": (
        "v2",
        "GET /v2/api/site/{site}/wan/{group}/insights/{overview,history,speed-tests}",
        "Site Manager isp-metrics is per site, without WAN-group insights or speed tests",
    ),
    "list_wan_slas": ("v2", "GET /v2/api/site/{site}/wan-slas", "no official route"),
    "create_wan_sla": ("v2", "POST /v2/api/site/{site}/wan-slas", "no official route"),
    "update_wan_sla": ("v2", "PUT /v2/api/site/{site}/wan-slas/{id}", "no official route"),
    "delete_wan_sla": ("v2", "DELETE /v2/api/site/{site}/wan-slas/{id}", "no official route"),
    "get_enriched_configuration": (
        "v2",
        "GET /v2/api/site/{site}/{wan,lan,wlan}/enriched-configuration",
        "official networks / wifi / wans records lack the enriched usage fields",
    ),
    "list_gateway_routes": (
        "v2",
        "GET /v2/api/site/{site}/routes",
        "no official route-table operation (traffic routes are policy routes)",
    ),
}


# --- shared helpers ---------------------------------------------------------------------


def _check_site_args(host: str, site: str) -> None:
    """Both selectors, before any resolution request."""
    check_selector("host", host)
    check_selector("site", site)


def _check_mac(value: Any, name: str) -> str:
    """A device MAC argument in the controller's colon form (no request)."""
    validate_selector(value, name)
    if not is_mac(value):
        raise ValueError(
            f"Not a MAC address: {name!r} is {value!r}; pass the device MAC from "
            "list_devices, for example 02:00:5e:00:53:01."
        )
    return colon_mac(value)


def _check_macs(values: Any, name: str) -> list[str]:
    """A non-empty list of device MACs in the controller's colon form (no request)."""
    if isinstance(values, list) and not values:
        raise ValueError(
            f"Not a MAC address: {name!r} is an empty list; pass at least one device MAC from "
            "list_devices, for example 02:00:5e:00:53:01."
        )
    return [_check_mac(mac, f"{name}[{i}]") for i, mac in enumerate(values)]


def _reject_named_keys(argument: str, body: Mapping[str, Any], keys: tuple[str, ...]) -> None:
    """Refuse a free-form ``argument`` that also carries a key a typed argument sets.

    The typed value is the one sent, so the free-form key would be silently replaced.
    """
    twice = [key for key in keys if key in body]
    if twice:
        raise ValueError(
            f"{argument} must not contain {' or '.join(repr(k) for k in twice)}: the typed "
            f"argument of that name is the one sent (the {argument} key would be silently "
            "replaced). Nothing was sent."
        )


def _redacting(client: UniFiClient) -> bool:
    settings = getattr(client, "_settings", None)
    return bool(getattr(settings, "redact_secrets", False))


def _finish(client: UniFiClient, method: str, path: str, result: Any) -> Any:
    """The result verbatim; listed credentials masked ONLY under UNIFI_REDACT_SECRETS."""
    if not _redacting(client):
        return result
    if is_dry_run_preview(result):
        preview = dict(result["preview"])
        preview["body"] = mask_request_body(method, path, preview.get("body"), redact_secrets=True)
        return {**result, "preview": preview}
    return mask_response_body(method, path, result, redact_secrets=True)


async def _scrubbed[T](call: Awaitable[T], secrets: tuple[str, ...]) -> T:
    """Await ``call``; an error is scrubbed of ``secrets`` (empty: re-raised unchanged).

    ``_command`` passes the credentials this call sent only under ``UNIFI_REDACT_SECRETS``,
    the opt-in every error path follows; otherwise the error text is verbatim. The
    exception is re-raised with its own type and its scrubbed message; its cause chain is
    dropped only when it held one.
    """
    try:
        return await call
    except Exception as exc:
        values = tuple(s for s in secrets if s.strip())
        text = str(exc)
        clean = scrub(text, values) if values else text
        if clean != text:
            exc.args = (clean,)
            exc.__cause__ = None
            exc.__suppress_context__ = True
        raise


async def _device_macs(
    client: UniFiClient,
    host_id: str,
    slug: str,
    macs: tuple[str, ...],
    key: APIKeyConfig | None,
) -> None:
    """Fail fast when a device MAC is not a device of the site, listing the valid ones."""
    path = _CONSOLE.format(host_id=host_id) + f"/api/s/{slug}/stat/device-basic"
    body = await client.get(path, key=key)
    rows = object_records(body.get("data") if isinstance(body, dict) else body, f"GET {path}")
    known = {record_mac(r.get("mac")) for r in rows}
    for mac in macs:
        if record_mac(mac) not in known:
            choices = "; ".join(
                f"{upstream_error_value(r.get('name'))!r} ({upstream_error_value(r.get('mac'))}, "
                f"{upstream_error_value(r.get('model'))})"
                for r in rows
            )
            raise ValueError(
                f"Device MAC {mac!r} not found on this site; valid: {choices or '(none)'}. "
                "Pass a device MAC from list_devices. No command was sent."
            )


async def _command(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    manager: str,
    cmd: str,
    params: Mapping[str, Any],
    *,
    macs: tuple[str, ...] = (),
) -> Any:
    """Run one Classic LTE/MBB command after every local check, verbatim result."""
    _check_site_args(host, site)
    body = classic_command_body(cmd, params)
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    path = classic_cmd_path(host_id, slug, manager)
    # Sent credentials are masked in error text only under the redaction opt-in.
    secrets = request_secrets("POST", path, body) if _redacting(client) else ()
    if macs:
        await _device_macs(client, host_id, slug, macs, key)
    result = await _scrubbed(
        classic_command(client, host_id, slug, manager, cmd, params, key=key), secrets
    )
    return _finish(client, "POST", path, result)


def _given(**fields: Any) -> dict[str, Any]:
    """Only the fields the caller actually gave."""
    return {k: v for k, v in fields.items() if v is not None}


def _object_arg(value: Any, name: str) -> dict[str, Any]:
    """An optional free-form object argument (None is an empty object)."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(
            f"Classic command parameters must be an object: {name!r} is {describe_shape(value)}"
        )
    return dict(value)


# --- Classic LTE / MBB commands ---------------------------------------------------------


async def get_lte_subscription_status(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    macs: list[str],
    *,
    ubic_username: str | None = None,
    ubic_password: str | None = None,
    ubic_2fa_token: str | None = None,
) -> Any:
    """POST ``cmd/lte`` ``check-subscription`` for LTE devices, verbatim Classic envelope."""
    sent = _check_macs(macs, "macs")
    params = {
        "macs": sent,
        **_given(
            ubic_username=ubic_username,
            x_ubic_password=ubic_password,
            ubic_2fa_token=ubic_2fa_token,
        ),
    }
    return await _command(
        client, registry, host, site, "lte", "check-subscription", params, macs=tuple(sent)
    )


async def activate_lte_trial(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    params: dict[str, Any] | None = None,
) -> Any:
    """POST ``cmd/lte`` ``activate-trial`` with the free-form parameters given."""
    return await _command(
        client, registry, host, site, "lte", "activate-trial", _object_arg(params, "params")
    )


async def authorize_lte_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    mac: str,
    *,
    ubic_username: str | None = None,
    ubic_password: str | None = None,
    ubic_2fa_token: str | None = None,
) -> Any:
    """POST ``cmd/lte`` ``auth-device`` for one LTE device, verbatim Classic envelope."""
    sent = _check_mac(mac, "mac")
    params = {
        "mac": sent,
        **_given(
            ubic_username=ubic_username,
            x_ubic_password=ubic_password,
            ubic_2fa_token=ubic_2fa_token,
        ),
    }
    return await _command(client, registry, host, site, "lte", "auth-device", params, macs=(sent,))


async def set_lte_apn_profile(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    mac: str,
    profile: dict[str, Any],
) -> Any:
    """POST ``cmd/lte`` ``lte-set-profile`` ``{mac, **profile}`` for one LTE device."""
    sent = _check_mac(mac, "mac")
    fields = _object_arg(profile, "profile")
    _reject_named_keys("profile", fields, ("mac",))
    params = {**fields, "mac": sent}
    return await _command(
        client, registry, host, site, "lte", "lte-set-profile", params, macs=(sent,)
    )


async def verify_sim_pin(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    pin: str,
    *,
    mac: str | None = None,
    manager: str = "lte",
    params: dict[str, Any] | None = None,
) -> Any:
    """POST the SIM PIN to ``cmd/lte`` ``lte-verify-pin`` or ``cmd/mbb`` ``verify-pin``."""
    manager = _LTE_MANAGER.validate_python(manager)
    sent = _check_mac(mac, "mac") if mac is not None else None
    extra = _object_arg(params, "params")
    _reject_named_keys("params", extra, ("pin", "mac") if sent is not None else ("pin",))
    body = {**extra, **_given(mac=sent), "pin": pin}
    cmd = "lte-verify-pin" if manager == "lte" else "verify-pin"
    return await _command(
        client, registry, host, site, manager, cmd, body, macs=(sent,) if sent else ()
    )


async def update_lte_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    params: dict[str, Any],
) -> Any:
    """POST ``cmd/lte`` ``update-device`` with the free-form parameters given."""
    return await _command(
        client, registry, host, site, "lte", "update-device", _object_arg(params, "params")
    )


async def manage_esim_profile(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    action: str,
    params: dict[str, Any],
) -> Any:
    """POST ``cmd/mbb`` ``esim-add`` or ``esim-delete`` with the free-form parameters."""
    action = _ESIM_ACTION.validate_python(action)
    return await _command(
        client, registry, host, site, "mbb", f"esim-{action}", _object_arg(params, "params")
    )


async def get_inactive_sim_slot(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    params: dict[str, Any] | None = None,
) -> Any:
    """POST ``cmd/mbb`` ``read-inactive-slot-sim-card``, verbatim Classic envelope."""
    return await _command(
        client,
        registry,
        host,
        site,
        "mbb",
        "read-inactive-slot-sim-card",
        _object_arg(params, "params"),
    )


async def reset_mobile_data_usage(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    params: dict[str, Any] | None = None,
) -> Any:
    """POST ``cmd/mbb`` ``reset-usage``, verbatim Classic envelope."""
    return await _command(
        client, registry, host, site, "mbb", "reset-usage", _object_arg(params, "params")
    )


# --- v2 WAN ------------------------------------------------------------------------------


async def _v2_site(registry: Registry, host: str, site: str) -> tuple[Any, str, str]:
    _check_site_args(host, site)
    return await resolve_site_slug(registry, host, site)


async def set_lte_failover(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    body: dict[str, Any],
) -> Any:
    """PUT ``lan/enable-lte-failover`` with the free-form body given, verbatim."""
    key, host_id, slug = await _v2_site(registry, host, site)
    path = v2_site(host_id, slug, "/lan/enable-lte-failover")
    return await client.put(path, key=key, json=body)


async def get_wan_load_balancing(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    view: str = "configuration",
) -> Any:
    """GET the WAN load-balancing configuration or status, verbatim."""
    view = _LB_VIEW.validate_python(view)
    key, host_id, slug = await _v2_site(registry, host, site)
    return await client.get(v2_site(host_id, slug, f"/wan/load-balancing/{view}"), key=key)


def _merged(current: Any, changes: Any) -> Any:
    """``changes`` deep-merged over ``current`` (objects merge; anything else replaces)."""
    if isinstance(current, dict) and isinstance(changes, dict):
        out = dict(current)
        for name, value in changes.items():
            out[name] = _merged(current.get(name), value)
        return out
    return changes


def _unverified(requested: Any, actual: Any, where: str = "") -> list[str]:
    """Requested leaf paths the read-after does not hold, type-strict."""
    if isinstance(requested, dict):
        if not isinstance(actual, dict):
            return [where or "(root)"]
        out: list[str] = []
        for name, value in requested.items():
            path = f"{where}.{name}" if where else str(name)
            if name not in actual:
                out.append(path)
            else:
                out.extend(_unverified(value, actual[name], path))
        return out
    return [] if leaf_equal(requested, actual) else [where or "(root)"]


def _changes(body: dict[str, Any], what: str) -> dict[str, Any]:
    """The fields to change: refused when empty (before any request); additive ``_`` keys
    and fields holding the redaction mask are left out, and the masked ones are reported
    on the result (``_redactedFieldsNotSent``) so the stored value is kept."""
    require_update_fields(body, what)
    clean, dropped = drop_masked_fields(strip_additive_keys(body))
    if dropped:
        note_dropped_fields(dropped)
    return clean if isinstance(clean, dict) else {}


def _verdict_result(response: Any, requested: dict[str, Any], after: Any, error: str | None) -> Any:
    """The write response verbatim plus the additive read-after verdict."""
    wanted = strip_additive_keys(requested)
    missing: list[str] = []

    def check(actual: dict[str, Any]) -> bool:
        missing.extend(_unverified(wanted, actual))
        return not missing

    verdict, reason = read_after_verdict(after, error, check)
    extra: dict[str, Any] = {VERIFIED_KEY: verdict}
    if verdict is False:
        extra[UNVERIFIED_FIELDS_KEY] = missing
    base = response if isinstance(response, dict) else {"response": response}
    return with_read_after_error(with_context(base, extra), reason, additive=True)


async def update_wan_load_balancing(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    configuration: dict[str, Any],
    *,
    test_config_id: str | None = None,
) -> Any:
    """Read, merge and PUT the WAN load-balancing configuration, then verify it."""
    changes = _changes(configuration, "configuration")
    key, host_id, slug = await _v2_site(registry, host, site)
    path = v2_site(host_id, slug, "/wan/load-balancing/configuration")
    current = await client.get(path, key=key)
    # An object is merged; any other body has no fields to merge into, so the
    # configuration is sent as given and the read-back decides the verdict.
    merged = (
        _merged(strip_additive_keys(current), changes) if isinstance(current, dict) else changes
    )
    params = _given(testConfigId=test_config_id) or None
    response = await client.put(path, key=key, json=merged, params=params)
    if is_dry_run_preview(response):
        return response

    async def read() -> Any:
        return await client.get(path, key=key)

    after, error = await safe_read_after(read)
    return _verdict_result(response, changes, after, error)


async def list_wan_network_groups(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    uptime: bool | None = None,
) -> Any:
    """GET the site's WAN network groups (optionally with uptime), verbatim."""
    uptime = _OPTIONAL_BOOL.validate_python(uptime)
    key, host_id, slug = await _v2_site(registry, host, site)
    params = None if uptime is None else {"uptime": "true" if uptime else "false"}
    return await client.get(v2_site(host_id, slug, "/wan/networkgroups"), key=key, params=params)


async def get_wan_insights(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    wan_group: str,
    *,
    view: str = "overview",
    period: str | None = None,
) -> Any:
    """GET one WAN group's insight overview, history or speed-test history, verbatim."""
    group = path_segment(wan_group, "wan_group")
    route = _INSIGHT_ROUTES[_INSIGHT_VIEW.validate_python(view)]
    key, host_id, slug = await _v2_site(registry, host, site)
    path = v2_site(host_id, slug, f"/wan/{group}/insights/{route}")
    params = _given(period=period) or None
    return await client.get(path, key=key, params=params)


def _sla_records(body: Any, path: str) -> list[dict[str, Any]]:
    """The WAN SLA records of a list body (a bare array, or an object with ``data``)."""
    items = body.get("data") if isinstance(body, dict) else body
    return object_records(items, f"GET {path}")


async def _find_sla(
    client: UniFiClient, path: str, sla_id: str, key: APIKeyConfig | None
) -> tuple[dict[str, Any], str]:
    """``(record, id segment)`` of one WAN SLA read from the list, or fail listing them."""
    records = _sla_records(await client.get(path, key=key), path)
    record = find_by_id(records, sla_id, "_id", "id")
    if record is None:
        valid = "; ".join(
            f"{upstream_error_value(r.get('name'))!r} "
            f"(_id={upstream_error_value(r.get('_id', r.get('id')))})"
            for r in records
        )
        raise ValueError(
            f"WAN SLA {sla_id!r} not found; valid: {valid or '(none)'}. Pass an _id from "
            "list_wan_slas. No write was sent."
        )
    native = record.get("_id", record.get("id"))
    return record, path_segment(native, "sla_id")


async def list_wan_slas(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """GET the site's WAN SLA definitions, verbatim."""
    key, host_id, slug = await _v2_site(registry, host, site)
    return await client.get(v2_site(host_id, slug, "/wan-slas"), key=key)


async def create_wan_sla(
    client: UniFiClient, registry: Registry, host: str, site: str, sla: dict[str, Any]
) -> Any:
    """POST a new WAN SLA definition (free-form body), verbatim."""
    key, host_id, slug = await _v2_site(registry, host, site)
    return await client.post(v2_site(host_id, slug, "/wan-slas"), key=key, json=sla)


async def update_wan_sla(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    sla_id: str,
    changes: dict[str, Any],
) -> Any:
    """Read, merge and PUT one WAN SLA, then verify it from the list."""
    validate_selector(sla_id, "sla_id")
    wanted = _changes(changes, "changes")
    key, host_id, slug = await _v2_site(registry, host, site)
    collection = v2_site(host_id, slug, "/wan-slas")
    record, segment = await _find_sla(client, collection, sla_id, key)
    merged = _merged(strip_additive_keys(record), wanted)
    for identity in ("_id", "id"):
        if identity in record:
            merged[identity] = record[identity]  # the upstream spelling, never the caller's
    response = await client.put(f"{collection}/{segment}", key=key, json=merged)
    if is_dry_run_preview(response):
        return response

    async def read() -> Any:
        records = _sla_records(await client.get(collection, key=key), collection)
        return find_by_id(records, segment, "_id", "id")

    after, error = await safe_read_after(read)
    return _verdict_result(response, wanted, after, error)


async def delete_wan_sla(
    client: UniFiClient, registry: Registry, host: str, site: str, sla_id: str
) -> Any:
    """DELETE one WAN SLA read from the list first (an unknown id fails listing them)."""
    validate_selector(sla_id, "sla_id")
    key, host_id, slug = await _v2_site(registry, host, site)
    collection = v2_site(host_id, slug, "/wan-slas")
    _record, segment = await _find_sla(client, collection, sla_id, key)
    response = await client.delete(f"{collection}/{segment}", key=key)
    return deletion_result(f"WAN SLA {sla_id!r} deleted.", response)


async def get_enriched_configuration(
    client: UniFiClient, registry: Registry, host: str, site: str, kind: str = "wan"
) -> Any:
    """GET the WAN, LAN or WLAN enriched configuration, verbatim."""
    kind = _ENRICHED_KIND.validate_python(kind)
    key, host_id, slug = await _v2_site(registry, host, site)
    return await client.get(v2_site(host_id, slug, f"/{kind}/enriched-configuration"), key=key)


async def list_gateway_routes(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """GET the gateway's active route table, verbatim."""
    key, host_id, slug = await _v2_site(registry, host, site)
    return await client.get(v2_site(host_id, slug, "/routes"), key=key)


# --- Registration -----------------------------------------------------------------------


# The registered tools share their names with the helpers above; module-level aliases let
# the closures inside register() call the helpers, not themselves.
_impl_subscription = get_lte_subscription_status
_impl_trial = activate_lte_trial
_impl_authorize = authorize_lte_device
_impl_apn = set_lte_apn_profile
_impl_pin = verify_sim_pin
_impl_update_device = update_lte_device
_impl_esim = manage_esim_profile
_impl_inactive_slot = get_inactive_sim_slot
_impl_reset_usage = reset_mobile_data_usage
_impl_failover = set_lte_failover
_impl_lb_get = get_wan_load_balancing
_impl_lb_update = update_wan_load_balancing
_impl_groups = list_wan_network_groups
_impl_insights = get_wan_insights
_impl_sla_list = list_wan_slas
_impl_sla_create = create_wan_sla
_impl_sla_update = update_wan_sla
_impl_sla_delete = delete_wan_sla
_impl_enriched = get_enriched_configuration
_impl_routes = list_gateway_routes
