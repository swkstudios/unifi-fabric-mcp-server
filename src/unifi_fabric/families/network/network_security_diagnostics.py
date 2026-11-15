"""Network SSL inspection, IPS, system-log, diagnostics and IP/Thread topology tools.

Every route is a Network v2 frontend route (``/proxy/network/v2/api/site/{site}/...``)
from the Network 11.0.81 route inventory: the pinned Network spec (11.0.97) publishes no
operation for any of them, and v2 is preferred over the Classic ``rest/setting`` groups
(route preference official > v2 > classic). Request bodies the inventory marks dynamic
are free-form object arguments, passed through as given; no key is invented. Responses
are returned verbatim, with additive ``_``-prefixed keys only.
"""

from __future__ import annotations

from typing import Any, NoReturn

from ...client import (
    RateLimitError,
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    path_segment,
    upstream_error_text,
    upstream_error_value,
    validate_id,
)
from ...config import APIKeyConfig
from ...macs import record_mac
from ...matching import same_id
from ...read_only import ReadOnlyModeError, guard_action
from ...redaction import drop_masked_fields, note_dropped_fields
from ...registry import Registry
from ...selector_args import check_selector
from ...shared_shapes._classic_objects import resolve_site_slug, v2_site
from ...shared_shapes._keys import with_context
from ...shared_shapes._pagination import collect_offset, offset_list_result
from ...shared_shapes._results import (
    UNVERIFIED_FIELDS_KEY,
    VERIFIED_KEY,
    deletion_result,
    requested_leaves_match,
    requested_leaves_verdict,
    safe_read_after,
    with_read_after_error,
)
from ...switches import READ_ONLY_ENV
from ...write_body import IDENTITY_FIELDS, require_unmasked_fields, require_update_fields
from .schemas import (  # the family's shapes (family-owned layout)
    _CERTS,
    _ID_FIELDS,
    _LOG_SETTING,
    _PROFILES,
    _SSL_SETTING,
    _THREAD_EPOCH_FIELDS,
    _VERTEX_ID_FIELDS,
    SSL_CATALOGS,
)


def _grammar(message: str) -> NoReturn:
    """Raise an N11 argument-grammar refusal (``n11-argument-grammar`` in ``refusals.py``)."""
    raise ValueError(message)


def _wrong_type(message: str) -> NoReturn:
    """Raise an N11 argument-type refusal (``n11-argument-type`` in ``refusals.py``)."""
    raise ValueError(message)


def _choice(value: Any, name: str, choices: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in choices:
        _grammar(f"{name} must be one of {list(choices)}; got {value!r}")
    return value


def _body(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _wrong_type(f"{name} must be a JSON object; got {describe_shape(value)}")
    return value


def _optional_body(value: Any, name: str) -> dict[str, Any] | None:
    return None if value is None else _body(value, name)


def _flag(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        _wrong_type(f"{name} must be a boolean; got {describe_shape(value)}")
    return value


def _write_gate(client: UniFiClient, tool: str) -> None:
    """Refuse a write under ``UNIFI_WRITE_POLICY=deny`` before any resolution or read-before."""
    try:
        guard_action("POST")
    except ReadOnlyModeError:
        client.audit_refusal(tool=tool, reason=READ_ONLY_ENV)
        raise


async def _site(registry: Registry, host: str, site: str) -> tuple[APIKeyConfig | None, str, str]:
    check_selector("host", host)
    check_selector("site", site)
    return await resolve_site_slug(registry, host, site)


async def _get_list(client: UniFiClient, path: str, key: APIKeyConfig | None) -> Any:
    """GET a v2 collection and return it verbatim.

    The route inventory records no paging parameter for these collections, so a bare
    array is the whole collection. Should a controller answer an offset envelope
    (``data`` plus ``offset``/``limit``/``totalCount``), it is drained with the shared
    guard, which marks a drain that stops short ``incomplete``.
    """
    raw = await client.get(path, key=key)
    if isinstance(raw, dict) and isinstance(raw.get("data"), list):
        if any(field in raw for field in ("offset", "limit", "totalCount", "total")):
            return offset_list_result(await collect_offset(client, path, key=key))
    return raw


def _records(body: Any, path: str) -> list[dict[str, Any]]:
    items = body.get("data") if isinstance(body, dict) else body
    if not isinstance(items, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected a JSON array or an object "
            f"with a 'data' array, got {describe_shape(body)}"
        )
    return [item for item in items if isinstance(item, dict)]


def _stopped_short(body: Any) -> str | None:
    """Why a drained listing stopped before its end, or None when it is complete.

    A record missing from a listing that stopped short (a UNIFI_PAGINATE_MAX_PAGES
    cap, a repeated or empty page) may still exist past the records read, so a lookup
    that fails on such a listing says so instead of reporting the record as absent.
    """
    if isinstance(body, dict) and body.get("incomplete") is True:
        return str(upstream_error_value(body.get("incompleteReason") or "no reason given"))
    return None


def _ids(record: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for field in _ID_FIELDS:
        value = record.get(field)
        if isinstance(value, str) and value:
            out.append(value)
    return out


def _find(records: list[dict[str, Any]], wanted: str) -> dict[str, Any] | None:
    """The record whose ``_id`` or ``id`` names ``wanted`` (a hex id in any case)."""
    for record in records:
        if any(same_id(wanted, value) for value in _ids(record)):
            return record
    return None


def _fields(body: dict[str, Any], what: str, *, identity: frozenset[str]) -> dict[str, Any]:
    """The body to send: refused when it carries no field (before any request).

    When UNIFI_REDACT_SECRETS is enabled, fields holding the redaction mask are left out
    (the stored secret is kept) and reported on the result under ``_redactedFieldsNotSent``.
    """
    clean = require_update_fields(body, what, identity=identity)
    note_dropped_fields(drop_masked_fields(body)[1])
    return clean


async def _require_record(
    client: UniFiClient,
    path: str,
    wanted: str,
    key: APIKeyConfig | None,
    kind: str,
    list_tool: str,
) -> tuple[dict[str, Any], str]:
    """``(record, path id)`` of the record ``wanted`` (its ``_id`` or ``id``) at ``path``.

    The path id is the record's ``_id`` when it has one, else its ``id``.
    """
    body = await _get_list(client, path, key)
    records = _records(body, path)
    record = _find(records, wanted)
    if record is not None:
        return record, _ids(record)[0]
    valid = "; ".join(
        f"{upstream_error_value(r.get('name'))!r} (id={upstream_error_value(_ids(r)[0])})"
        for r in records
        if _ids(r)
    )
    reason = _stopped_short(body)
    short = (
        f" The listing stopped short after {len(records)} records ({reason}), so the "
        "record may exist past them."
        if reason is not None
        else ""
    )
    raise ValueError(
        f"{kind} {wanted!r} not found; valid: {valid or '(none)'}.{short} Get ids from "
        f"{list_tool}. No write was sent."
    )


def _merge(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge ``changes`` over ``current``: objects recurse, other values replace."""
    merged = dict(current)
    for name, value in changes.items():
        if isinstance(value, dict) and isinstance(merged.get(name), dict):
            merged[name] = _merge(merged[name], value)
        else:
            merged[name] = value
    return merged


def _verified_result(
    response: Any, changes: dict[str, Any], after: Any, error: str | None
) -> dict[str, Any]:
    """The upstream write body plus the additive read-after verdict."""
    verified, reason = requested_leaves_verdict(changes, after, error)
    # A non-object write body is kept whole under ``response`` (never dropped or reshaped).
    result = response if isinstance(response, dict) else {"response": response}
    context: dict[str, Any] = {"_readAfter": after, VERIFIED_KEY: verified}
    if verified is False and isinstance(after, dict):
        context[UNVERIFIED_FIELDS_KEY] = sorted(
            name
            for name, value in changes.items()
            if name not in after or not requested_leaves_match(value, after[name])
        )
    return with_read_after_error(with_context(result, context), reason, additive=True)


def _changes(changes: Any, what: str) -> dict[str, Any]:
    """The requested leaves of an update, without the keys that address the object (the
    stored record keeps its own ``_id`` / ``id``, in the upstream's spelling)."""
    wanted = _fields(_body(changes, "changes"), what, identity=IDENTITY_FIELDS)
    return {name: value for name, value in wanted.items() if name not in IDENTITY_FIELDS}


async def _get(
    client: UniFiClient, registry: Registry, host: str, site: str, suffix: str, **params: Any
) -> Any:
    key, host_id, slug = await _site(registry, host, site)
    query = {name: value for name, value in params.items() if value is not None}
    return await client.get(v2_site(host_id, slug, suffix), key=key, params=query or None)


# ------------------------------------------------------------------------ SSL inspection


async def list_ssl_inspection_catalog(
    client: UniFiClient, registry: Registry, host: str, site: str, catalog: str
) -> Any:
    suffix = SSL_CATALOGS[_choice(catalog, "catalog", tuple(SSL_CATALOGS))]
    return await _get(client, registry, host, site, suffix)


async def list_ssl_inspection_certificates(
    client: UniFiClient, registry: Registry, host: str, site: str, active_only: bool = False
) -> Any:
    active = _flag(active_only, "active_only")
    key, host_id, slug = await _site(registry, host, site)
    if active:
        return await client.get(v2_site(host_id, slug, _CERTS + "/active"), key=key)
    return await _get_list(client, v2_site(host_id, slug, _CERTS), key)


async def create_ssl_inspection_certificate(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    mode: str,
    certificate: dict[str, Any],
) -> Any:
    chosen = _choice(mode, "mode", ("upload", "generate"))
    body = _fields(_body(certificate, "certificate"), "certificate", identity=frozenset())
    _write_gate(client, "create_ssl_inspection_certificate")
    key, host_id, slug = await _site(registry, host, site)
    suffix = _CERTS if chosen == "upload" else _CERTS + "/generate"
    return await client.post(v2_site(host_id, slug, suffix), key=key, json=body)


async def delete_ssl_inspection_certificate(
    client: UniFiClient, registry: Registry, host: str, site: str, certificate_id: str
) -> Any:
    validate_id(certificate_id, "certificate_id")
    _write_gate(client, "delete_ssl_inspection_certificate")
    key, host_id, slug = await _site(registry, host, site)
    list_path = v2_site(host_id, slug, _CERTS)
    _record, target = await _require_record(
        client,
        list_path,
        certificate_id,
        key,
        "SSL inspection certificate",
        "list_ssl_inspection_certificates",
    )
    response = await client.delete(f"{list_path}/{path_segment(target, 'id')}", key=key)
    return deletion_result(f"SSL inspection certificate {target} deleted", response)


async def activate_ssl_inspection_certificate(
    client: UniFiClient, registry: Registry, host: str, site: str, certificate_id: str
) -> Any:
    validate_id(certificate_id, "certificate_id")
    _write_gate(client, "activate_ssl_inspection_certificate")
    key, host_id, slug = await _site(registry, host, site)
    list_path = v2_site(host_id, slug, _CERTS)
    _record, target = await _require_record(
        client,
        list_path,
        certificate_id,
        key,
        "SSL inspection certificate",
        "list_ssl_inspection_certificates",
    )
    # Sent once, never auto-retried (the client never retries a POST).
    return await client.post(f"{list_path}/{path_segment(target, 'id')}/activate", key=key)


async def list_ssl_inspection_profiles(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    key, host_id, slug = await _site(registry, host, site)
    return await _get_list(client, v2_site(host_id, slug, _PROFILES), key)


async def create_ssl_inspection_profile(
    client: UniFiClient, registry: Registry, host: str, site: str, profile: dict[str, Any]
) -> Any:
    body = _fields(_body(profile, "profile"), "profile", identity=frozenset())
    _write_gate(client, "create_ssl_inspection_profile")
    key, host_id, slug = await _site(registry, host, site)
    return await client.post(v2_site(host_id, slug, _PROFILES), key=key, json=body)


async def update_ssl_inspection_profile(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    profile_id: str,
    changes: dict[str, Any],
) -> Any:
    validate_id(profile_id, "profile_id")
    wanted = _changes(changes, "SSL inspection profile changes")
    _write_gate(client, "update_ssl_inspection_profile")
    key, host_id, slug = await _site(registry, host, site)
    list_path = v2_site(host_id, slug, _PROFILES)
    current, target = await _require_record(
        client, list_path, profile_id, key, "SSL inspection profile", "list_ssl_inspection_profiles"
    )
    response = await client.put(
        f"{list_path}/{path_segment(target, 'id')}", key=key, json=_merge(current, wanted)
    )
    if is_dry_run_preview(response):
        return response

    short: list[str] = []

    async def read_after() -> dict[str, Any] | None:
        body = await _get_list(client, list_path, key)
        found = _find(_records(body, list_path), target)
        reason = _stopped_short(body)
        if found is None and reason is not None:
            short.append(reason)
        return found

    after, error = await safe_read_after(read_after)
    if error is None and after is None:
        error = f"profile {target} is not in GET {list_path} after the update"
        if short:
            error += (
                f"; the listing stopped short ({short[0]}), so the profile may exist past "
                "the records read and the update is not shown to have failed"
            )
    return _verified_result(response, wanted, after, error)


async def delete_ssl_inspection_profile(
    client: UniFiClient, registry: Registry, host: str, site: str, profile_id: str
) -> Any:
    validate_id(profile_id, "profile_id")
    _write_gate(client, "delete_ssl_inspection_profile")
    key, host_id, slug = await _site(registry, host, site)
    list_path = v2_site(host_id, slug, _PROFILES)
    _record, target = await _require_record(
        client, list_path, profile_id, key, "SSL inspection profile", "list_ssl_inspection_profiles"
    )
    response = await client.delete(f"{list_path}/{path_segment(target, 'id')}", key=key)
    return deletion_result(f"SSL inspection profile {target} deleted", response)


async def get_ssl_inspection_settings(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    return await _get(client, registry, host, site, _SSL_SETTING)


def _setting_record(body: Any) -> dict[str, Any] | None:
    """The setting object of a v2 singleton GET: the object itself, or the one object of a
    one-record array (the form v2 list-style routes answer); otherwise None."""
    if isinstance(body, dict):
        return body
    if isinstance(body, list) and len(body) == 1 and isinstance(body[0], dict):
        return body[0]
    return None


async def _update_setting(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    suffix: str,
    changes: Any,
    tool: str,
) -> Any:
    """Read-merge-write of a v2 singleton setting, verified leaf by leaf by a read-back."""
    wanted = _changes(changes, "setting changes")
    _write_gate(client, tool)
    key, host_id, slug = await _site(registry, host, site)
    path = v2_site(host_id, slug, suffix)
    before = await client.get(path, key=key)
    current = _setting_record(before)
    if current is None:
        raise UniFiConnectionError(
            f"GET {path} answered {describe_shape(before)}, not one setting object (an "
            "object, or an array holding exactly one object); no write was sent"
        )
    response = await client.put(path, key=key, json=_merge(current, wanted))
    if is_dry_run_preview(response):
        return response

    async def read_after() -> Any:
        body = await client.get(path, key=key)
        record = _setting_record(body)
        return body if record is None else record

    after, error = await safe_read_after(read_after)
    return _verified_result(response, wanted, after, error)


async def update_ssl_inspection_settings(
    client: UniFiClient, registry: Registry, host: str, site: str, changes: dict[str, Any]
) -> Any:
    return await _update_setting(
        client, registry, host, site, _SSL_SETTING, changes, "update_ssl_inspection_settings"
    )


# ------------------------------------------------------------------------ IPS


async def list_ips_categories(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    memory_optimized: bool | None = None,
) -> Any:
    flag = None
    if memory_optimized is not None:
        flag = "true" if _flag(memory_optimized, "memory_optimized") else "false"
    return await _get(
        client,
        registry,
        host,
        site,
        "/settings/ips/available-categories",
        memoryOptimized=flag,
    )


async def get_ips_signature_status(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    return await _get(client, registry, host, site, "/settings/ips/suricata")


async def update_ips_signatures(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    _write_gate(client, "update_ips_signatures")
    key, host_id, slug = await _site(registry, host, site)
    # Sent once (the client never retries a POST): the upgrade acts on the gateway.
    return await client.post(v2_site(host_id, slug, "/settings/ips/suricata-upgrade"), key=key)


# ------------------------------------------------------------------------ system log


async def get_system_log_settings(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    return await _get(client, registry, host, site, _LOG_SETTING)


async def update_system_log_settings(
    client: UniFiClient, registry: Registry, host: str, site: str, changes: dict[str, Any]
) -> Any:
    return await _update_setting(
        client, registry, host, site, _LOG_SETTING, changes, "update_system_log_settings"
    )


async def mark_critical_logs_read(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    body: dict[str, Any] | None = None,
) -> Any:
    payload = _optional_body(body, "body")
    require_unmasked_fields(payload, "mark_critical_logs_read body")
    _write_gate(client, "mark_critical_logs_read")
    key, host_id, slug = await _site(registry, host, site)
    return await client.put(
        v2_site(host_id, slug, "/system-log/critical/mark-all-as-read"), key=key, json=payload
    )


async def acknowledge_critical_alert(
    client: UniFiClient, registry: Registry, host: str, site: str, alert_id: str
) -> Any:
    segment = path_segment(alert_id, "alert_id")
    _write_gate(client, "acknowledge_critical_alert")
    key, host_id, slug = await _site(registry, host, site)
    # An empty JSON object, exactly as the peer clients send it; one PUT, never retried.
    return await client.put(
        v2_site(host_id, slug, f"/system-log/critical/{segment}/mark-as-read"), key=key, json={}
    )


# ------------------------------------------------------------------------ diagnostics


async def control_packet_capture(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    action: str,
    capture_id: str | None = None,
    options: dict[str, Any] | None = None,
) -> Any:
    chosen = _choice(action, "action", ("start", "stop"))
    extra = _optional_body(options, "options")
    # A blank capture_id / an empty options object names nothing, so it never conflicts.
    named_id = capture_id if isinstance(capture_id, str) and capture_id.strip() else None
    if chosen == "start":
        if named_id is not None:
            _grammar("capture_id is for action='stop' only; pcap-start takes no capture id")
        if extra is not None and "cmd" in extra and extra["cmd"] != "pcap-start":
            _grammar("options must not override cmd; the start command is cmd='pcap-start'")
        suffix, body = "/pcap-start", {**(extra or {}), "cmd": "pcap-start"}
    else:
        if capture_id is None:
            _grammar("capture_id is required for action='stop'; read it from the start result")
        if extra:
            _grammar("options is for action='start' only; pcap-stop sends only cmd='pcap-stop'")
        segment = path_segment(capture_id, "capture_id")
        suffix, body = f"/pcap-stop/{segment}", {"cmd": "pcap-stop"}
    _write_gate(client, "control_packet_capture")
    key, host_id, slug = await _site(registry, host, site)
    # Sent once, never auto-retried: a capture start/stop acts on the gateway.
    return await client.post(v2_site(host_id, slug, suffix), key=key, json=body)


async def get_packet_capture_status(
    client: UniFiClient, registry: Registry, host: str, site: str, capture_id: str
) -> Any:
    segment = path_segment(capture_id, "capture_id")
    return await _get(client, registry, host, site, f"/pcap-status/{segment}")


async def control_ping_test(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    action: str,
    target: str,
    options: dict[str, Any] | None = None,
) -> Any:
    chosen = _choice(action, "action", ("start", "stop"))
    segment = path_segment(target, "target")
    payload = _optional_body(options, "options")
    require_unmasked_fields(payload, "control_ping_test options")
    _write_gate(client, "control_ping_test")
    key, host_id, slug = await _site(registry, host, site)
    # Sent once, never auto-retried: a ping test acts on the device.
    return await client.post(
        v2_site(host_id, slug, f"/ping-{chosen}/{segment}"), key=key, json=payload
    )


async def get_ping_test_results(
    client: UniFiClient, registry: Registry, host: str, site: str, target: str
) -> Any:
    segment = path_segment(target, "target")
    return await _get(client, registry, host, site, f"/ping/{segment}")


# ------------------------------------------------------------------------ IP / Thread topology


def _identity_text(value: Any) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _vertices(snapshot: Any) -> list[tuple[str, dict[str, Any]]] | None:
    """``(locator, vertex)`` pairs of a live snapshot, or None when unreadable."""
    if not isinstance(snapshot, dict):
        return None
    vertices = snapshot.get("vertices")
    if isinstance(vertices, list):
        return [(f"vertices[{i}]", v) for i, v in enumerate(vertices) if isinstance(v, dict)]
    if isinstance(vertices, dict):
        return [(f"vertices[{k!r}]", v) for k, v in vertices.items() if isinstance(v, dict)]
    return None


def _vertex_brief(locator: str, vertex: dict[str, Any], field: str | None) -> dict[str, Any]:
    return {
        "vertex": locator,
        "matchedField": field,
        "id": vertex.get("id"),
        "mac": vertex.get("mac"),
        "ip": vertex.get("ip"),
        "name": vertex.get("name"),
        "type": vertex.get("type"),
    }


def _match_vertex(
    identity: str, vertices: list[tuple[str, dict[str, Any]]]
) -> tuple[str, dict[str, Any], str] | None:
    wanted_mac = record_mac(identity)
    for field in _VERTEX_ID_FIELDS:
        for locator, vertex in vertices:
            value = vertex.get(field)
            if field == "mac":
                if wanted_mac is not None and record_mac(value) == wanted_mac:
                    return locator, vertex, field
            elif _identity_text(value) == identity:
                return locator, vertex, field
    return None


def _routers(networks: Any) -> list[dict[str, Any]] | None:
    if not isinstance(networks, list):
        return None
    routers: list[dict[str, Any]] = []
    for n_index, network in enumerate(networks):
        if not isinstance(network, dict):
            continue
        listed = network.get("border_routers")
        if not isinstance(listed, list):
            continue
        for r_index, router in enumerate(listed):
            if isinstance(router, dict):
                routers.append(
                    {
                        "router": f"[{n_index}].border_routers[{r_index}]",
                        "network": network.get("name"),
                        "extended_pan_id": network.get("extended_pan_id"),
                        "network_name": router.get("network_name"),
                        "mac": router.get("mac"),
                        "normalizedMac": record_mac(router.get("mac")),
                        "name": router.get("name"),
                        "ip": router.get("ip"),
                        "host": router.get("host"),
                        "state_bitmap": router.get("state_bitmap"),
                        "last_seen_at": router.get("last_seen_at"),
                    }
                )
    return routers


def _topology_join(nodes: Any, networks: Any, snapshot: Any) -> dict[str, Any]:
    """Join Matter nodes -> topology vertices -> Thread border routers (by normalized MAC)."""
    vertices = _vertices(snapshot)
    routers = _routers(networks)
    notes = [
        "Matter nodes join the topology by client_id (fallback node_id) against vertex "
        "client_id, id, _id, node_id and mac, in that order.",
        "Thread border routers join by normalized MAC; a router is linked to a Matter node "
        "only through a matched topology vertex, so an unlinked router is not a Matter node "
        "as far as this data shows (it is never assumed to be one).",
    ]
    by_mac: dict[str, dict[str, Any]] = {}
    for router in routers or []:
        if router["normalizedMac"] is not None:
            by_mac.setdefault(router["normalizedMac"], router)
    node_rows: list[dict[str, Any]] = []
    linked: dict[str, list[str]] = {}
    if isinstance(nodes, list):
        for index, node in enumerate(nodes):
            if not isinstance(node, dict):
                node_rows.append({"node": f"[{index}]", "joinState": "not_an_object"})
                continue
            client_id = _identity_text(node.get("client_id"))
            node_id = _identity_text(node.get("node_id"))
            identity, used = (
                (client_id, "client_id") if client_id is not None else (node_id, "node_id")
            )
            row: dict[str, Any] = {
                "node": f"[{index}]",
                "node_id": node.get("node_id"),
                "client_id": node.get("client_id"),
                "status": node.get("status"),
                "identityUsed": used if identity is not None else None,
                "topology": None,
                "threadBorderRouter": None,
            }
            if identity is None:
                row["joinState"] = "no_identity"
            elif vertices is None:
                row["joinState"] = "topology_unavailable"
            else:
                match = _match_vertex(identity, vertices)
                if match is None:
                    row["joinState"] = "no_topology_vertex"
                else:
                    locator, vertex, field = match
                    row["topology"] = _vertex_brief(locator, vertex, field)
                    vertex_mac = record_mac(vertex.get("mac"))
                    linked_router = by_mac.get(vertex_mac) if vertex_mac is not None else None
                    if linked_router is None:
                        row["joinState"] = "topology_matched"
                    else:
                        row["threadBorderRouter"] = linked_router["router"]
                        row["joinState"] = "topology_and_thread_matched"
                        linked.setdefault(linked_router["router"], []).append(row["node"])
            node_rows.append(row)
    router_rows: list[dict[str, Any]] = []
    for router in routers or []:
        row = dict(router)
        mac = router["normalizedMac"]
        found: tuple[str, dict[str, Any]] | None = None
        if mac is not None and vertices is not None:
            found = next(
                (
                    (locator, vertex)
                    for locator, vertex in vertices
                    if record_mac(vertex.get("mac")) == mac
                ),
                None,
            )
        row["topology"] = _vertex_brief(found[0], found[1], "mac") if found else None
        row["matterNodes"] = linked.get(router["router"], [])
        if mac is None:
            row["joinState"] = "no_mac"
        elif row["matterNodes"]:
            row["joinState"] = "matter_node_linked"
        elif found is not None:
            row["joinState"] = "topology_matched_no_matter_node"
        else:
            row["joinState"] = "unmatched"
        router_rows.append(row)
    return {
        "matterNodes": node_rows if isinstance(nodes, list) else None,
        "threadBorderRouters": router_rows if routers is not None else None,
        "summary": {
            "matterNodes": len(nodes) if isinstance(nodes, list) else None,
            "matterNodesInTopology": sum(1 for r in node_rows if r.get("topology")),
            "matterNodesOnThreadBorderRouter": sum(
                1 for r in node_rows if r.get("threadBorderRouter")
            ),
            "threadBorderRouters": len(routers) if routers is not None else None,
            "threadBorderRoutersInTopology": sum(1 for r in router_rows if r["topology"]),
            "threadBorderRoutersLinkedToMatterNode": sum(
                1 for r in router_rows if r["matterNodes"]
            ),
            "topologyVertices": len(vertices) if vertices is not None else None,
        },
        "notes": notes,
    }


async def get_unified_ip_thread_topology(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> dict[str, Any]:
    key, host_id, slug = await _site(registry, host, site)
    sources = {
        "matterNodes": "/matter/nodes",
        "threadNetworks": "/thread-networks",
        "topologySnapshot": "/topology/snapshot/live",
    }
    bodies: dict[str, Any] = {}
    provenance: dict[str, Any] = {}
    failures: list[Exception] = []
    for name, suffix in sources.items():
        path = v2_site(host_id, slug, suffix)
        try:
            raw = await client.get(path, key=key)
            if not isinstance(raw, list | dict):
                # Not a body the join can read: report its shape without echoing it.
                shape = UniFiConnectionError(
                    f"Unexpected response shape from GET {path}: expected a JSON array or "
                    f"object, got {describe_shape(raw)}"
                )
                failures.append(shape)
                bodies[name] = None
                provenance[name] = {
                    "method": "GET",
                    "path": path,
                    "ok": False,
                    "error": f"{type(shape).__name__}: {shape}",
                    "body": describe_shape(raw),
                }
                continue
            bodies[name] = raw
            provenance[name] = {"method": "GET", "path": path, "ok": True}
        except (UniFiConnectionError, RateLimitError) as exc:
            failures.append(exc)
            bodies[name] = None
            provenance[name] = {
                "method": "GET",
                "path": path,
                "ok": False,
                "error": f"{type(exc).__name__}: {upstream_error_text(exc, client)}",
            }
    if len(failures) == len(sources):
        raise failures[0]
    return {
        "_matterNodes": bodies["matterNodes"],
        "_threadNetworks": bodies["threadNetworks"],
        "_topologySnapshot": bodies["topologySnapshot"],
        "_sources": provenance,
        "_join": _topology_join(
            bodies["matterNodes"], bodies["threadNetworks"], bodies["topologySnapshot"]
        ),
        "_warnings": [
            {
                "code": "EPOCH_MILLISECONDS",
                "fields": [f"_threadNetworks[].{f}" for f in _THREAD_EPOCH_FIELDS]
                + [f"_threadNetworks[].border_routers[].{f}" for f in _THREAD_EPOCH_FIELDS],
                "message": "Thread timestamps are Unix epochs in milliseconds, e.g. 1791753474653.",
            }
        ],
    }


# ------------------------------------------------------------------------ registration
