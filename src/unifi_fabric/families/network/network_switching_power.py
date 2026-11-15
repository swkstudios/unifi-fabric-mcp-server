"""Network switching, PoE power-supervisor and infrastructure-history tools.

These routes have no published Integration API. They are the Network controller's own
web-UI routes under ``/proxy/network/v2/api/site/{site}`` (Network 11.0.81 private-API
inventory, ``tests/fixtures/private_api/inventory_network_11.0.81.json``) and take the
site's short name (``default``), resolved from the caller's site name or UUID.

* None of these collections takes a paging parameter in the inventory, so list tools send
  one GET and return the upstream body verbatim (no drain, no cap).
* Updates read the record from its collection, merge only the requested leaves, PUT the
  merged record and read it back, comparing every requested leaf type-strictly
  (``_verified``; ``_readAfterError`` when the read-back failed).
* Updates and deletes resolve the id in its collection first (the controller answers a
  write on an unknown id without an error), failing with every valid id listed.
* The three log/MAC-table query routes are POSTs that are not on the read-POST allowlist,
  so they are writes: ``UNIFI_WRITE_POLICY=deny`` refuses them and ``dry-run policy`` previews them.
"""

from __future__ import annotations

from typing import Any, TypeGuard

from pydantic import Field

from ...client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    upstream_error_value,
    validate_id,
)
from ...config import APIKeyConfig
from ...redaction import drop_and_note_masked_fields
from ...registry import Registry
from ...shared_shapes._classic_objects import resolve_site_slug, v2_site
from ...shared_shapes._history_common import (
    epoch_warnings,
    require_epoch_seconds,
    seconds_to_millis,
    with_warnings,
)
from ...shared_shapes._keys import with_context
from ...shared_shapes._results import deletion_result, requested_leaves_verdict, safe_read_after
from ...write_body import IDENTITY_FIELDS, require_update_fields
from .schemas import (  # the family's shapes (family-owned layout)
    _ENERGY,
    _LINKS,
    _PORT_AUTOMATIONS,
    _SUPERVISORS,
)


def _update_body(tool: str, value: Any, name: str) -> dict[str, Any]:
    """The requested update leaves (masked and identity fields dropped), or raise."""
    clean = require_update_fields(drop_and_note_masked_fields(value), f"{tool} {name}")
    return {key: item for key, item in clean.items() if key not in IDENTITY_FIELDS}


def _merge(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge only the requested leaves into the current upstream record."""
    merged = dict(current)
    for key, value in changes.items():
        prior = merged.get(key)
        merged[key] = (
            _merge(prior, value) if isinstance(prior, dict) and isinstance(value, dict) else value
        )
    return merged


def _record_id(record: dict[str, Any]) -> str | None:
    for field in ("_id", "id"):
        value = record.get(field)
        if isinstance(value, str) and value:
            return value
    return None


def _by_value(choice: str) -> str:
    """Sort key of a field=value choice: the id value."""
    return choice.split("=", 1)[1]


def _record_choice(record: dict[str, Any], client: UniFiClient | None = None) -> str | None:
    """A listed record's id, named by its field (``_id=...`` or ``id=...``)."""
    for field in ("_id", "id"):
        value = record.get(field)
        if isinstance(value, str) and value:
            return f"{field}={upstream_error_value(value, client)}"
    return None


async def _listed_record(
    client: UniFiClient, path: str, key: APIKeyConfig | None, identifier: str, label: str
) -> dict[str, Any]:
    """The record of collection ``path`` whose ``_id`` or ``id`` is ``identifier``.

    The collection is a bare JSON array or a ``{data: [...]}`` envelope; any other shape,
    or a non-object row, raises with the shape received. An unknown id raises listing
    every valid id.
    """
    body = await client.get(path, key=key)
    rows = body.get("data") if isinstance(body, dict) else body
    if not isinstance(rows, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected a JSON array or an object "
            f"with a 'data' array, got {describe_shape(body)}"
        )
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise UniFiConnectionError(
                f"Unexpected response shape from GET {path}: row {index} expected an object, "
                f"got {describe_shape(row)}"
            )
    wanted = identifier.lower()
    for row in rows:
        if any(
            isinstance(row.get(field), str) and row[field].lower() == wanted
            for field in ("_id", "id")
        ):
            return row
    choices = sorted(filter(None, (_record_choice(row, client) for row in rows)), key=_by_value)
    raise ValueError(
        f"{label} {identifier!r} not found; valid choices: {', '.join(choices) or '(none)'}. "
        "No write was sent."
    )


async def _target_id(
    client: UniFiClient, path: str, key: APIKeyConfig | None, identifier: str, label: str
) -> tuple[dict[str, Any], str]:
    """The listed record and the upstream id it matched (its ``_id`` or ``id``)."""
    record = await _listed_record(client, path, key, identifier, label)
    wanted = identifier.lower()
    resolved = next(
        record[field]
        for field in ("_id", "id")
        if isinstance(record.get(field), str) and record[field].lower() == wanted
    )
    validate_id(resolved, "id")
    return record, resolved


async def _verified_update(
    client: UniFiClient,
    collection: str,
    key: APIKeyConfig | None,
    identifier: str,
    changes: dict[str, Any],
    label: str,
    *,
    list_only_fields: frozenset[str] = frozenset(),
) -> Any:
    """Read-merge-write, then read back every requested leaf with strict comparison.

    A non-object write body is kept whole under ``response`` so the verdict keys are never dropped.
    """
    current, resolved = await _target_id(client, collection, key, identifier, label)
    current = {
        name: value
        for name, value in current.items()
        if name not in list_only_fields or name in changes
    }
    response = await client.put(f"{collection}/{resolved}", key=key, json=_merge(current, changes))
    if is_dry_run_preview(response):
        return response
    after, error = await safe_read_after(
        lambda: _listed_record(client, collection, key, resolved, label)
    )
    verified, error = requested_leaves_verdict(changes, after, error)
    if not isinstance(response, dict):
        response = {"response": response}
    additions: dict[str, Any] = {"_verified": verified}
    if error is not None:
        additions["_readAfterError"] = error
    return with_context(response, additions)


async def _delete(
    client: UniFiClient, collection: str, key: APIKeyConfig | None, identifier: str, label: str
) -> Any:
    _record, resolved = await _target_id(client, collection, key, identifier, label)
    response = await client.delete(f"{collection}/{resolved}", key=key)
    return deletion_result(f"{label} {resolved} deleted.", response)


# --- Energy-saving policies ---


async def list_energy_saving_policies(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET the site's energy-saving policies. Returns the upstream body verbatim."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.get(v2_site(host_id, slug, _ENERGY), key=key)


async def create_energy_saving_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy: dict[str, Any]
) -> Any:
    """POST ``policy`` verbatim to the site's energy-saving policies."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.post(v2_site(host_id, slug, _ENERGY), key=key, json=policy)


async def update_energy_saving_policy(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    policy_id: str,
    policy: dict[str, Any],
) -> Any:
    """Merge ``policy`` into the listed policy, PUT it and verify the requested leaves."""
    validate_id(policy_id, "policy_id")
    changes = _update_body("update_energy_saving_policy", policy, "policy")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await _verified_update(
        client,
        v2_site(host_id, slug, _ENERGY),
        key,
        policy_id,
        changes,
        "energy-saving policy",
        list_only_fields=frozenset({"device_names", "estimated_energy_savings"}),
    )


async def delete_energy_saving_policy(
    client: UniFiClient, registry: Registry, host: str, site: str, policy_id: str
) -> Any:
    """Resolve ``policy_id`` in the list, then DELETE it."""
    validate_id(policy_id, "policy_id")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await _delete(
        client, v2_site(host_id, slug, _ENERGY), key, policy_id, "energy-saving policy"
    )


# --- Port automations (Network 11.1.47) ---


async def list_port_automations(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET the site's port automations. Returns the upstream body verbatim."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.get(v2_site(host_id, slug, _PORT_AUTOMATIONS), key=key)


async def get_port_automation(
    client: UniFiClient, registry: Registry, host: str, site: str, automation_id: str
) -> Any:
    """The listed port automation whose ``id`` is ``automation_id``, verbatim.

    The controller serves no single-record route (the web app reads the collection), so
    the record is picked from the list; an unknown id raises listing every valid id.
    """
    validate_id(automation_id, "automation_id")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await _listed_record(
        client, v2_site(host_id, slug, _PORT_AUTOMATIONS), key, automation_id, "port automation"
    )


async def create_port_automation(
    client: UniFiClient, registry: Registry, host: str, site: str, automation: dict[str, Any]
) -> Any:
    """POST ``automation`` verbatim to the site's port automations."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.post(v2_site(host_id, slug, _PORT_AUTOMATIONS), key=key, json=automation)


async def update_port_automation(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    automation_id: str,
    automation: dict[str, Any],
) -> Any:
    """Merge ``automation`` into the listed port automation, PUT it and verify the leaves."""
    validate_id(automation_id, "automation_id")
    changes = _update_body("update_port_automation", automation, "automation")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await _verified_update(
        client,
        v2_site(host_id, slug, _PORT_AUTOMATIONS),
        key,
        automation_id,
        changes,
        "port automation",
    )


async def delete_port_automation(
    client: UniFiClient, registry: Registry, host: str, site: str, automation_id: str
) -> Any:
    """Resolve ``automation_id`` in the list, then DELETE it."""
    validate_id(automation_id, "automation_id")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await _delete(
        client, v2_site(host_id, slug, _PORT_AUTOMATIONS), key, automation_id, "port automation"
    )


# --- Power supervisors and links ---


async def list_power_supervisors(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """GET the site's power supervisors. Returns the upstream body verbatim."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.get(v2_site(host_id, slug, _SUPERVISORS), key=key)


async def create_power_supervisor(
    client: UniFiClient, registry: Registry, host: str, site: str, supervisor: dict[str, Any]
) -> Any:
    """POST ``supervisor`` verbatim to the site's power supervisors."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.post(v2_site(host_id, slug, _SUPERVISORS), key=key, json=supervisor)


async def update_power_supervisor(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    supervisor_id: str,
    supervisor: dict[str, Any],
) -> Any:
    """Merge ``supervisor`` into the listed supervisor, PUT it and verify the leaves."""
    validate_id(supervisor_id, "supervisor_id")
    changes = _update_body("update_power_supervisor", supervisor, "supervisor")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await _verified_update(
        client,
        v2_site(host_id, slug, _SUPERVISORS),
        key,
        supervisor_id,
        changes,
        "power supervisor",
    )


async def delete_power_supervisor(
    client: UniFiClient, registry: Registry, host: str, site: str, supervisor_id: str
) -> Any:
    """Resolve ``supervisor_id`` in the list, then DELETE it."""
    validate_id(supervisor_id, "supervisor_id")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await _delete(
        client, v2_site(host_id, slug, _SUPERVISORS), key, supervisor_id, "power supervisor"
    )


async def create_power_supervisor_link(
    client: UniFiClient, registry: Registry, host: str, site: str, link: dict[str, Any]
) -> Any:
    """POST ``link`` verbatim to the site's power-supervisor links."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.post(v2_site(host_id, slug, _LINKS), key=key, json=link)


async def update_power_supervisor_link(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    link_id: str,
    link: dict[str, Any],
) -> Any:
    """Merge ``link`` into the listed link, PUT it and verify the requested leaves."""
    validate_id(link_id, "link_id")
    changes = _update_body("update_power_supervisor_link", link, "link")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await _verified_update(
        client, v2_site(host_id, slug, _LINKS), key, link_id, changes, "power-supervisor link"
    )


async def delete_power_supervisor_link(
    client: UniFiClient, registry: Registry, host: str, site: str, link_id: str
) -> Any:
    """Resolve ``link_id`` in the link list, then DELETE it."""
    validate_id(link_id, "link_id")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await _delete(
        client, v2_site(host_id, slug, _LINKS), key, link_id, "power-supervisor link"
    )


async def query_power_supervisor_logs(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    supervisor_id: str,
    query: dict[str, Any],
) -> Any:
    """POST ``query`` verbatim to one supervisor's system-logs route."""
    validate_id(supervisor_id, "supervisor_id")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.post(
        v2_site(host_id, slug, f"{_SUPERVISORS}/{supervisor_id}/system-logs"), key=key, json=query
    )


# --- Ports, links and history ---


async def get_port_history(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    at: int,
    device_id: str | None = None,
) -> Any:
    """GET the port history snapshot at ``at``, for the site or one device.

    ``at`` is epoch seconds; the route takes epoch milliseconds (live, Network 11.0.89: a
    seconds value answers HTTP 200 with an empty array).
    """
    at_ms = seconds_to_millis(require_epoch_seconds(at, "at"))
    if device_id is not None:
        validate_id(device_id, "device_id")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    device = f"/{device_id}" if device_id is not None else ""
    result = await client.get(v2_site(host_id, slug, f"/ports/history{device}/at/{at_ms}"), key=key)
    return with_warnings(result, epoch_warnings(at=at))


def _is_switch_query(query: object) -> TypeGuard[dict[str, Any]]:
    """Whether ``query`` is the legacy one-switch object ``{mac: str, ports: [...]}``."""
    return (
        isinstance(query, dict)
        and isinstance(query.get("mac"), str)
        and isinstance(query.get("ports"), list)
    )


async def query_switch_mac_tables(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    query: dict[str, Any] | list[dict[str, Any]] | None,
) -> Any:
    """POST ``query`` verbatim, a JSON array, to the site's switch MAC-table route.

    The route deserializes a list (Network 11.0.89 web app: ``ports/mac-tables`` is posted
    ``[{mac, ports: [port_idx, ...]}]``; an object answers HTTP 400 "Cannot deserialize
    value of type ArrayList from Object value"), so a non-list or empty list is refused
    before any request.
    """
    # Retain the legacy object input when it describes one switch; the route itself
    # always receives the array its web app sends. Other object shapes are ambiguous.
    if _is_switch_query(query):
        query = [query]
    if not isinstance(query, list):
        raise ValueError(
            "'query' must be a JSON array of {mac, ports} objects, e.g. "
            '[{"mac": "02:00:5e:00:53:01", "ports": [1, 2]}]; '
            f"got {describe_shape(query)}. Nothing was sent."
        )
    if not query:
        raise ValueError(
            "query must be a non-empty list: an empty list names no switch; nothing was sent."
        )
    for index, item in enumerate(query):
        if not isinstance(item, dict):
            raise ValueError(
                f"'query[{index}]' must be a JSON object such as "
                '{"mac": "02:00:5e:00:53:01", "ports": [1]}; '
                f"got {describe_shape(item)}. Nothing was sent."
            )
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.post(
        v2_site(host_id, slug, "/ports/mac-tables"), key=key, json=[dict(i) for i in query]
    )


async def list_port_anomalies(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """GET the site's port anomalies. Returns the upstream body verbatim."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.get(v2_site(host_id, slug, "/ports/port-anomalies"), key=key)


async def query_port_system_logs(
    client: UniFiClient, registry: Registry, host: str, site: str, query: dict[str, Any]
) -> Any:
    """POST ``query`` verbatim to the site's port system-logs route."""
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.post(v2_site(host_id, slug, "/ports/system-logs"), key=key, json=query)


async def list_wireless_links(
    client: UniFiClient, registry: Registry, host: str, site: str, device_id: str | None = None
) -> Any:
    """GET the site's wireless links, or one device's; returned verbatim."""
    if device_id is not None:
        validate_id(device_id, "device_id")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    path = (
        f"/device/{device_id}/wireless-links" if device_id is not None else "/device/wireless-links"
    )
    return await client.get(v2_site(host_id, slug, path), key=key)


async def get_device_tx_retries(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    params: dict[str, Any] | None = None,
) -> Any:
    """GET one device's 24-hour transmit retries, forwarding ``params`` as the query."""
    validate_id(device_id, "device_id")
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await client.get(
        v2_site(host_id, slug, f"/device/{device_id}/24hr-tx-retries"), key=key, params=params
    )


async def get_infrastructure_history(
    client: UniFiClient, registry: Registry, host: str, site: str, at: int
) -> Any:
    """GET the site's infrastructure history snapshot at ``at``.

    ``at`` is epoch seconds; the route takes epoch milliseconds (live, Network 11.0.89: a
    seconds value answers 404 "No infrastructure snapshot exists at or before").
    """
    at_ms = seconds_to_millis(require_epoch_seconds(at, "at"))
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    result = await client.get(
        v2_site(host_id, slug, f"/infrastructure/history/at/{at_ms}"), key=key
    )
    return with_warnings(result, epoch_warnings(at=at))


_QUERY_UNSET = object()
# A factory omits a JSON default and preserves the legacy non-null object schema.
_QUERY_DEFAULT: Any = Field(default_factory=lambda: _QUERY_UNSET)
