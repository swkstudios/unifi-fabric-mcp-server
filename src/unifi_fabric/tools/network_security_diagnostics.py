"""Network SSL inspection, IPS, system-log, diagnostics and IP/Thread topology tools (GS3 N11).

Every route is a Network v2 frontend route (``/proxy/network/v2/api/site/{site}/...``)
from the Network 11.0.81 route inventory: the pinned Network spec (10.6.106) publishes no
operation for any of them, and v2 is preferred over the Classic ``rest/setting`` groups
(route preference official > v2 > classic). Request bodies the inventory marks dynamic
are free-form object arguments, passed through as given; no key is invented. Responses
are returned verbatim, with additive ``_``-prefixed keys only.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal, NoReturn, cast

from fastmcp import FastMCP

from ..client import (
    RateLimitError,
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    path_segment,
    upstream_error_text,
    validate_id,
)
from ..config import APIKeyConfig
from ..macs import record_mac
from ..matching import same_id
from ..read_only import ReadOnlyModeError, guard_action
from ..redaction import drop_masked_fields, note_dropped_fields
from ..registry import Registry
from ..selector_args import check_selector
from ..tool_annotations import READ_ONLY, WRITE
from ..write_body import IDENTITY_FIELDS, require_unmasked_fields, require_update_fields
from ._classic_objects import resolve_site_slug, v2_site
from ._keys import with_context
from ._pagination import collect_offset, offset_list_result
from ._results import (
    UNVERIFIED_FIELDS_KEY,
    VERIFIED_KEY,
    deletion_result,
    requested_leaves_match,
    requested_leaves_verdict,
    safe_read_after,
    with_read_after_error,
)

#: list_ssl_inspection_catalog: catalog name -> v2 route suffix (route inventory GETs).
SSL_CATALOGS: dict[str, str] = {
    "categories": "/ssl-inspection/categories",
    "file-extensions": "/ssl-inspection/file-extensions",
    "search-engines": "/ssl-inspection/search-engines",
    "profile-defaults": "/ssl-inspection/profiles/defaults",
    "profile-usage": "/ssl-inspection/profiles/usage",
    "setting-defaults": "/ssl-inspection/setting/defaults",
}

_CERTS = "/ssl-inspection/certificates"
_PROFILES = "/ssl-inspection/profiles"
_SSL_SETTING = "/ssl-inspection/setting"
_LOG_SETTING = "/system-log/setting"

#: Epoch-millisecond fields of the Thread network and border-router records.
_THREAD_EPOCH_FIELDS = ("first_seen_at", "last_fresh_at", "last_seen_at")

#: The record keys an SSL inspection object may be addressed by (v2 ``_id``, else ``id``).
_ID_FIELDS = ("_id", "id")


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
    """Refuse a write under ``UNIFI_READ_ONLY`` before any resolution or read-before."""
    try:
        guard_action(tool)
    except ReadOnlyModeError:
        client.audit_refusal(tool=tool, reason="UNIFI_READ_ONLY")
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
        return str(body.get("incompleteReason") or "no reason given")
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
    valid = "; ".join(f"{r.get('name')!r} (id={_ids(r)[0]})" for r in records if _ids(r))
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


_VERTEX_ID_FIELDS = ("client_id", "id", "_id", "node_id", "mac")


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


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the N11 security, diagnostics and IP/Thread topology tools."""

    def deps() -> tuple[UniFiClient, Registry]:
        return cast(tuple[UniFiClient, Registry], deps_fn())

    @mcp.tool(name="list_ssl_inspection_catalog", annotations=READ_ONLY)
    async def ssl_catalog(
        host: str,
        site: str,
        catalog: Literal[
            "categories",
            "file-extensions",
            "search-engines",
            "profile-defaults",
            "profile-usage",
            "setting-defaults",
        ],
    ) -> Any:
        """Read one SSL inspection reference catalog.

        Required arguments: host, site, catalog. Each catalog is one Network v2 GET under
        ssl-inspection/: categories, file-extensions, search-engines, profiles/defaults,
        profiles/usage or setting/defaults. Returns the upstream body verbatim (a JSON array arrives
        as {result: [...]}).

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            catalog: Required catalog to read, e.g. "categories".
        """
        return await list_ssl_inspection_catalog(*deps(), host, site, catalog)

    @mcp.tool(name="list_ssl_inspection_certificates", annotations=READ_ONLY)
    async def ssl_certificates(host: str, site: str, active_only: bool = False) -> Any:
        """List SSL inspection CA certificates, or only the active one.

        Required arguments: host, site. Returns the upstream body verbatim (a complete bare array,
        served as {result: [...]}). An offset envelope is drained to {data, totalCount}, with
        incomplete and incompleteReason when the drain stops short. Certificate material is returned
        as the upstream sends it.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            active_only: Read certificates/active instead of the list, e.g. true.
        """
        return await list_ssl_inspection_certificates(*deps(), host, site, active_only)

    @mcp.tool(name="create_ssl_inspection_certificate", annotations=WRITE)
    async def ssl_certificate_create(
        host: str,
        site: str,
        mode: Literal["upload", "generate"],
        certificate: dict[str, Any],
    ) -> Any:
        """Upload or generate an SSL inspection CA certificate.

        Required arguments: host, site, mode, certificate. mode "upload" POSTs
        ssl-inspection/certificates and "generate" POSTs ssl-inspection/certificates/generate.
        certificate is a free-form JSON object sent exactly as given: the route inventory records
        the body as dynamic, so no field is required or added by this tool. Private key and
        passphrase fields are route secrets: errors and logs never carry them and previews mask them
        only under UNIFI_REDACT_SECRETS. Returns the upstream body verbatim (a JSON array arrives as
        {result: [...]}). With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun,
        sent: false, message, preview: {method, path, params, body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            mode: Required upload or generate, e.g. "generate".
            certificate: Required free-form JSON object sent as the request body, as the
                Network UI builds it, e.g. {"name": "mcp-gs3-n11-ca"}.
        """
        return await create_ssl_inspection_certificate(*deps(), host, site, mode, certificate)

    @mcp.tool(name="delete_ssl_inspection_certificate", annotations=WRITE)
    async def ssl_certificate_delete(host: str, site: str, certificate_id: str) -> Any:
        """Delete an SSL inspection CA certificate.

        Consequence: irreversible; clients that trust this CA lose it for inspection. Required
        arguments: host, site, certificate_id. The id is resolved in the certificate list first: an
        unknown id fails listing the valid ids and sends no DELETE. Returns {deleted, message,
        response} with the upstream body. With UNIFI_DRY_RUN, returns {status: "dry_run", deleted:
        false, message, response} with the preview (method, path, params, body) under response.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            certificate_id: Required certificate id, e.g. "65f0c0ffee0000000000aa01".
        """
        return await delete_ssl_inspection_certificate(*deps(), host, site, certificate_id)

    @mcp.tool(name="activate_ssl_inspection_certificate", annotations=WRITE)
    async def ssl_certificate_activate(host: str, site: str, certificate_id: str) -> Any:
        """Make an SSL inspection CA certificate the active one.

        Consequence: inspected TLS sessions are re-signed with this CA; clients that do not trust it
        see certificate errors. Required arguments: host, site, certificate_id. The id is resolved
        in the certificate list first. Sent once and never retried. Returns the upstream body
        verbatim. With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun, sent:
        false, message,
        preview: {method, path, params, body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            certificate_id: Required certificate id, e.g. "65f0c0ffee0000000000aa01".
        """
        return await activate_ssl_inspection_certificate(*deps(), host, site, certificate_id)

    @mcp.tool(name="list_ssl_inspection_profiles", annotations=READ_ONLY)
    async def ssl_profiles(host: str, site: str) -> Any:
        """List SSL inspection profiles.

        Required arguments: host, site. Returns the upstream body verbatim (a complete bare array,
        served as {result: [...]}). An offset envelope is drained to {data, totalCount}, with
        incomplete and incompleteReason when the drain stops short.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
        """
        return await list_ssl_inspection_profiles(*deps(), host, site)

    @mcp.tool(name="create_ssl_inspection_profile", annotations=WRITE)
    async def ssl_profile_create(host: str, site: str, profile: dict[str, Any]) -> Any:
        """Create an SSL inspection profile.

        Required arguments: host, site, profile. profile is a free-form JSON object sent exactly as
        given (the route inventory records the body as dynamic); read list_ssl_inspection_catalog
        with catalog "profile-defaults" for the fields. Returns the upstream body verbatim (a JSON
        array arrives as {result: [...]}). With UNIFI_DRY_RUN, returns a dry-run preview {status:
        "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and sends
        nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            profile: Required free-form profile object, shaped like the profile-defaults
                catalog, e.g. {"name": "mcp-gs3-n11-profile"}.
        """
        return await create_ssl_inspection_profile(*deps(), host, site, profile)

    @mcp.tool(name="update_ssl_inspection_profile", annotations=WRITE)
    async def ssl_profile_update(
        host: str, site: str, profile_id: str, changes: dict[str, Any]
    ) -> Any:
        """Update an SSL inspection profile by read-merge-write, verified by a read-back.

        Required arguments: host, site, profile_id, changes. Reads the profile list, deep-merges
        changes over the stored profile and PUTs the merged object, then reads it back. An empty
        changes object is refused before any request. Returns the upstream write body (a non-object
        body under response) plus _readAfter, _verified (true only when every requested leaf matches
        type-strictly), _unverifiedFields when false and _readAfterError when the read-back failed;
        when UNIFI_REDACT_SECRETS is enabled, fields holding the redaction mask are not sent
        and are listed in _redactedFieldsNotSent.
        With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message, preview: {method, path, params, body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            profile_id: Required profile id, e.g. "65f0c0ffee0000000000bb01".
            changes: Required fields to change, e.g. {"name": "mcp-gs3-n11-profile-2"}.
                Free-form object.
        """
        return await update_ssl_inspection_profile(*deps(), host, site, profile_id, changes)

    @mcp.tool(name="delete_ssl_inspection_profile", annotations=WRITE)
    async def ssl_profile_delete(host: str, site: str, profile_id: str) -> Any:
        """Delete an SSL inspection profile.

        Consequence: irreversible; rules using the profile lose it. Required arguments: host, site,
        profile_id. The id is resolved in the profile list first: an unknown id fails listing the
        valid ids and sends no DELETE. Returns {deleted, message, response} with the upstream body.
        With UNIFI_DRY_RUN, returns {status: "dry_run", deleted: false, message, response} with the
        preview (method, path, params, body) under response.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            profile_id: Required profile id, e.g. "65f0c0ffee0000000000bb01".
        """
        return await delete_ssl_inspection_profile(*deps(), host, site, profile_id)

    @mcp.tool(name="get_ssl_inspection_settings", annotations=READ_ONLY)
    async def ssl_settings(host: str, site: str) -> Any:
        """Read the site SSL inspection setting.

        Required arguments: host, site. Returns the upstream body verbatim (a JSON array arrives as
        {result: [...]}).

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
        """
        return await get_ssl_inspection_settings(*deps(), host, site)

    @mcp.tool(name="update_ssl_inspection_settings", annotations=WRITE)
    async def ssl_settings_update(host: str, site: str, changes: dict[str, Any]) -> Any:
        """Update the SSL inspection setting by read-merge-write, verified by a read-back.

        Consequence: enabling inspection intercepts client TLS traffic. Required arguments: host,
        site, changes. Reads the setting, deep-merges changes and PUTs the merged object, then reads
        it back. An empty changes object is refused before any request. Returns the upstream write
        body (a non-object body under response) plus _readAfter, _verified (true only when every
        requested leaf matches type-strictly), _unverifiedFields when false and _readAfterError when
        the read-back failed; when UNIFI_REDACT_SECRETS is enabled, fields holding the redaction
        mask are not sent and are listed in _redactedFieldsNotSent. With UNIFI_DRY_RUN, returns
        a dry-run preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path,
        params, body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            changes: Required fields to change, e.g. {"enabled": false}. Free-form object.
        """
        return await update_ssl_inspection_settings(*deps(), host, site, changes)

    @mcp.tool(name="list_ips_categories", annotations=READ_ONLY)
    async def ips_categories(host: str, site: str, memory_optimized: bool | None = None) -> Any:
        """List the IPS threat categories available on the site.

        Required arguments: host, site. memory_optimized is sent as the memoryOptimized query
        parameter only when given. Returns the upstream body verbatim (a JSON array arrives as
        {result: [...]}).

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            memory_optimized: Optional memoryOptimized filter, e.g. true.
        """
        return await list_ips_categories(*deps(), host, site, memory_optimized)

    @mcp.tool(name="get_ips_signature_status", annotations=READ_ONLY)
    async def ips_signature_status(host: str, site: str) -> Any:
        """Read the IPS (Suricata) signature status.

        Required arguments: host, site. Returns the upstream body verbatim (a JSON array arrives as
        {result: [...]}).

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
        """
        return await get_ips_signature_status(*deps(), host, site)

    @mcp.tool(name="update_ips_signatures", annotations=WRITE)
    async def ips_signature_update(host: str, site: str) -> Any:
        """Start an IPS (Suricata) signature upgrade on the gateway.

        Consequence: the gateway downloads and loads new signatures; inspection can pause while the
        engine reloads. Required arguments: host, site. Sent once and never retried; read
        get_ips_signature_status for progress. Returns the upstream body verbatim (a JSON array
        arrives as {result: [...]}). With UNIFI_DRY_RUN, returns a dry-run preview {status:
        "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and sends
        nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
        """
        return await update_ips_signatures(*deps(), host, site)

    @mcp.tool(name="get_system_log_settings", annotations=READ_ONLY)
    async def log_settings(host: str, site: str) -> Any:
        """Read the system-log (syslog / activity log) setting.

        Required arguments: host, site. Returns the upstream body verbatim (a JSON array arrives as
        {result: [...]}).

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
        """
        return await get_system_log_settings(*deps(), host, site)

    @mcp.tool(name="update_system_log_settings", annotations=WRITE)
    async def log_settings_update(host: str, site: str, changes: dict[str, Any]) -> Any:
        """Update the system-log setting by read-merge-write, verified by a read-back.

        Required arguments: host, site, changes. Reads the setting, deep-merges changes and PUTs the
        merged object, then reads it back. An empty changes object is refused before any request.
        Returns the upstream write body (a non-object body under response) plus _readAfter,
        _verified (true only when every requested leaf matches type-strictly), _unverifiedFields
        when false and _readAfterError when the read-back failed; when UNIFI_REDACT_SECRETS is
        enabled, fields holding the redaction mask are not sent and are listed in
        _redactedFieldsNotSent. With UNIFI_DRY_RUN, returns a dry-run
        preview {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params,
        body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            changes: Required fields to change, e.g. {"debug_logging": true}. Free-form object.
        """
        return await update_system_log_settings(*deps(), host, site, changes)

    @mcp.tool(name="mark_critical_logs_read", annotations=WRITE)
    async def critical_logs_read(host: str, site: str, body: dict[str, Any] | None = None) -> Any:
        """Mark every critical system-log entry as read.

        Required arguments: host, site. body is an optional free-form JSON object sent exactly as
        given (the route inventory records the body as dynamic). Returns the upstream body verbatim
        (a JSON array arrives as {result: [...]}). With UNIFI_DRY_RUN, returns a dry-run preview
        {status: "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} and
        sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            body: Optional free-form JSON object sent as the request body, e.g. {}.
        """
        return await mark_critical_logs_read(*deps(), host, site, body)

    @mcp.tool(name="control_packet_capture", annotations=WRITE)
    async def packet_capture(
        host: str,
        site: str,
        action: Literal["start", "stop"],
        capture_id: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> Any:
        """Start or stop a gateway packet capture.

        Consequence: a capture runs on the gateway and uses its CPU and storage. Required arguments:
        host, site, action. start POSTs pcap-start with {cmd: "pcap-start"} plus options (free-form,
        sent as given); stop POSTs pcap-stop/{capture_id} with {cmd: "pcap-stop"}. Sent once and
        never retried. Returns the upstream body verbatim (a JSON array arrives as {result: [...]}).
        With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message, preview: {method, path, params, body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            action: Required start or stop, e.g. "start".
            capture_id: Capture id for stop, from the start result, e.g. "capture-0001".
            options: Optional free-form start fields merged under cmd, e.g. {}.
        """
        return await control_packet_capture(*deps(), host, site, action, capture_id, options)

    @mcp.tool(name="get_packet_capture_status", annotations=READ_ONLY)
    async def packet_capture_status(host: str, site: str, capture_id: str) -> Any:
        """Read a packet capture's status.

        Required arguments: host, site, capture_id. Returns the upstream body verbatim (a JSON array
        arrives as {result: [...]}).

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            capture_id: Required capture id from control_packet_capture, e.g. "capture-0001".
        """
        return await get_packet_capture_status(*deps(), host, site, capture_id)

    @mcp.tool(name="control_ping_test", annotations=WRITE)
    async def ping_test(
        host: str,
        site: str,
        action: Literal["start", "stop"],
        target: str,
        options: dict[str, Any] | None = None,
    ) -> Any:
        """Start or stop a ping test run by the console.

        Consequence: the device sends ICMP traffic until the test ends or is stopped. Required
        arguments: host, site, action, target. POSTs ping-start/{target} or ping-stop/{target};
        target is the path segment the Network UI uses for the test and is sent as one encoded
        segment. options is a free-form body sent as given. Sent once and never retried. Returns the
        upstream body verbatim. With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run",
        dryRun, sent: false, message, preview: {method, path, params, body}} and sends nothing.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            action: Required start or stop, e.g. "start".
            target: Required test path segment, e.g. "02:00:5e:00:00:a1".
            options: Optional free-form JSON body sent as given, e.g. {}.
        """
        return await control_ping_test(*deps(), host, site, action, target, options)

    @mcp.tool(name="get_ping_test_results", annotations=READ_ONLY)
    async def ping_results(host: str, site: str, target: str) -> Any:
        """Read a ping test's results.

        Required arguments: host, site, target. Returns the upstream body verbatim (a JSON array
        arrives as {result: [...]}).

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
            target: Required test path segment used to start it, e.g. "02:00:5e:00:00:a1".
        """
        return await get_ping_test_results(*deps(), host, site, target)

    @mcp.tool(name="get_unified_ip_thread_topology", annotations=READ_ONLY)
    async def ip_thread_topology(host: str, site: str) -> Any:
        """Project Matter nodes, Thread networks and the live IP topology into one view.

        Required arguments: host, site. Reads matter/nodes, thread-networks and
        topology/snapshot/live. Returns each body verbatim under _matterNodes, _threadNetworks and
        _topologySnapshot, with _sources (path and outcome of each GET), _join (matterNodes,
        threadBorderRouters, summary, notes) and _warnings (Thread timestamps are epoch
        milliseconds). The join maps each Matter node by client_id (node_id when absent) to a
        topology vertex, then to a Thread border router by normalized MAC, and gives every row a
        joinState. A border router is linked to a Matter node only through a matched vertex; an
        unlinked router is never reported as a Matter node. A failed source is reported in _sources
        and the others are still joined.

        Args:
            host: Required console name or id from list_hosts, e.g. "my-console".
            site: Required Network site name, id or slug from list_local_sites, e.g. "default".
        """
        return await get_unified_ip_thread_topology(*deps(), host, site)
