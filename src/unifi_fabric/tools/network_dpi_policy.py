"""Network policy-engine/application-block v2 tools and official predefined-policy updates.

Route references: Network FE 11.0.81 modules 222533, 248825 and 675092;
go-unifi c4ab115 network_members_group.go; aiounifi 21c8eb3
models/object_oriented_network_config.py. Preview was added in Network 11.1.11.
Private routes provide policy-engine objects and application-block lists; predefined
firewall-policy updates prefer the published Integration GET/PUT. Responses stay verbatim.

The typed batch-delete tools for ACL rules and firewall zones POST a bare
JSON array of private ``_id`` values to the v2 ``{collection}/batch-delete`` routes found in the
Network 11.0.81 frontend bundle (``tests/fixtures/private_api/inventory_network_11.0.81.json``).
The ids a caller holds are Integration ids, which the v2 records carry as ``external_id``, so
each id is resolved against the v2 list first and the collection is read back afterwards:
posted as Integration ids the ACL route answers 404 and the policy and zone routes answer 204
without removing anything (live-verified on Network 11.0.89). A v2 firewall policy carries no
Integration id at all, so the policy tool deletes each id through the Integration API instead.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, cast

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from ..client import (
    DRY_RUN_MESSAGE,
    RateLimitError,
    UniFiClient,
    UniFiConnectionError,
    UniFiHTTPError,
    describe_shape,
    is_dry_run_preview,
    strip_additive_keys,
    validate_id,
    validate_selector,
)
from ..matching import find_by_id, id_key
from ..read_only import guard_request
from ..registry import Registry
from ..tool_annotations import READ_ONLY, WRITE
from ..write_body import require_update_fields
from . import firewall_proxy as _fw
from ._classic_objects import _object_rows, resolve_site_slug, select_classic_record, v2_site
from ._keys import with_context
from ._payload import integration_update_body, upstream_hint
from ._results import deletion_readback_ids, deletion_result, safe_read_after, with_read_after_error
from .network import _proxy


def _body(value: Any, /, *, update: bool = False) -> dict[str, Any]:
    """Validate only the JSON-object contract; private fields are upstream-owned."""
    if not isinstance(value, dict):
        raise ValueError("body must be a JSON object")
    if not all(isinstance(k, str) for k in value):
        raise ValueError("body must contain JSON values with string object keys")
    clean = require_update_fields(value, "body")

    def json_value(item: Any) -> bool:
        if isinstance(item, dict):
            return all(isinstance(k, str) and json_value(v) for k, v in item.items())
        if isinstance(item, list):
            return all(json_value(v) for v in item)
        return item is None or type(item) in {str, bool, int, float}

    if not json_value(clean):
        raise ValueError("body must contain JSON values with string object keys")
    try:
        json.dumps(clean, allow_nan=False)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError("body must contain JSON values with finite numbers") from exc
    return clean


async def _context(
    registry: Registry, host: str, site: str, path: str, *, resource_id: str | None = None
) -> tuple[Any, str]:
    validate_selector(host, "host")
    validate_selector(site, "site")
    if resource_id is not None:
        validate_id(resource_id, "rule_id" if "object-oriented" in path else "group_id")
        path += f"/{resource_id}"
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return key, v2_site(host_id, slug, path)


def _merge(stored: dict[str, Any], update: dict[str, Any], /) -> dict[str, Any]:
    """Merge partial objects recursively; arrays and scalar leaves replace exactly."""

    def merge_native(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
        result = dict(current)
        for key, value in changes.items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = merge_native(result[key], value)
            else:
                result[key] = value
        return result

    return merge_native(strip_additive_keys(stored), update)


async def _collection_record(
    client: UniFiClient, key: Any, url: str, resource_id: str, /, *, list_tool: str
) -> dict[str, Any]:
    """Select an id from a complete unpaged private v2 collection, never a first row."""
    response = await client.get(url, key=key)
    if not isinstance(response, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {url}: expected an array, "
            f"got {describe_shape(response)}"
        )
    rows = _object_rows(response, url)
    # This selector handles both id and _id; use the native selector's choices error.
    selected = find_by_id(rows, resource_id, "id", "_id")
    if selected is not None:
        return selected
    return select_classic_record(rows, resource_id, "Network object", list_tool)


def _native_url(url: str, record: dict[str, Any]) -> str:
    """``url`` addressing ``record`` by its native id or _id, as the upstream spells it."""
    base, requested_id = url.rsplit("/", 1)
    natives = [n for n in (record.get("id"), record.get("_id")) if isinstance(n, str) and n]
    for native_id in natives:
        if id_key(native_id) == id_key(requested_id):
            return f"{base}/{native_id}"
    return f"{base}/{natives[0]}" if natives else url


async def _official_record(client: UniFiClient, key: Any, url: str, /) -> dict[str, Any]:
    response = await client.get(url, key=key)
    record = response.get("data", response) if isinstance(response, dict) else response
    if not isinstance(record, dict):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {url}: expected an object, "
            f"got {describe_shape(response)}"
        )
    return record


def _strict_leaves(requested: Any, actual: Any) -> bool:
    """Missing fields and any JSON type mismatch fail; compare each requested leaf."""
    if type(requested) is not type(actual):
        return False
    if isinstance(requested, dict):
        return all(k in actual and _strict_leaves(v, actual[k]) for k, v in requested.items())
    if isinstance(requested, list):
        return len(requested) == len(actual) and all(
            _strict_leaves(want, got) for want, got in zip(requested, actual, strict=True)
        )
    return bool(requested == actual)


async def _verified_put(
    client: UniFiClient,
    key: Any,
    url: str,
    requested: dict[str, Any],
    read: Callable[..., Any],
    /,
    *,
    official: bool = False,
) -> Any:
    """Read-merge-write, then compare requested leaves without hiding write errors."""
    guard_request("PUT", url)
    current = await read()
    if not official:
        requested = dict(requested)
        # Identity keys address the selected object; they never change its identity.
        for field in ("id", "_id"):
            if field in requested and field in current:
                requested[field] = current[field]
        requested_id = url.rsplit("/", 1)[1]
        for field in ("id", "_id"):
            native_id = current.get(field)
            if isinstance(native_id, str) and id_key(native_id) == id_key(requested_id):
                url = url.rsplit("/", 1)[0] + "/" + native_id
                break
    merged = _merge(current, requested)
    if official:
        merged = integration_update_body("update_firewall_policy", merged)
    response = await client.put(url, key=key, json=merged)
    if is_dry_run_preview(response):
        return response
    actual, error = await safe_read_after(read)
    context: dict[str, Any] = {"_verified": None if error else _strict_leaves(requested, actual)}
    if error:
        context["_readAfterError"] = error
    # Preserve every upstream value in the catalog's established nonobject envelope.
    record = response if isinstance(response, dict) else {"result": response}
    return with_context(record, context)


async def reset_dpi_counters(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """Erase DPI history and counters using v2 DELETE /dpi. This cannot be undone.

    Returns the upstream body unchanged; under UNIFI_DRY_RUN returns a dry-run preview.

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
    """
    key, url = await _context(registry, host, site, "/dpi")
    return await client.delete(url, key=key, json={"cmd": "reset-dpi"})


async def list_policy_engine_rules(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """List policy-engine objects, distinct from Integration firewall policies.

    Returns the complete unpaged v2 response unchanged, including ids for update/delete.

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
    """
    key, url = await _context(registry, host, site, "/object-oriented-network-configs")
    return await client.get(url, key=key)


async def create_policy_engine_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule: dict[str, Any]
) -> Any:
    """Create a private policy-engine object. Returns the upstream body unchanged.

    Body is free-form (no published request schema). Captured client fields include
    name, enabled, targets, target_type, secure, qos and route. Nested objects depend
    on the selected policy. Under UNIFI_DRY_RUN returns a dry-run preview.

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
        rule: Free-form JSON object, for example {'name': 'Test', 'enabled': False,
            'targets': [], 'secure': {'enabled': False}}; preserve private fields.
    """
    body = _body(rule)
    key, url = await _context(registry, host, site, "/object-oriented-network-config")
    return await client.post(url, key=key, json=body)


async def update_policy_engine_rule(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    rule_id: str,
    rule: dict[str, Any],
) -> Any:
    """PUT a policy-engine object using its native id, preserving private fields.

    Returns the upstream body unchanged; under UNIFI_DRY_RUN returns a dry-run preview.
    Reads the complete collection, merges partial fields, then verifies requested leaves.
    Object responses add _verified; a failed read-back adds _readAfterError.

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
        rule_id: Native id or _id from list_policy_engine_rules, for example 'test-rule'.
        rule: Nonempty free-form partial update object; unrequested fields are preserved, with a
            changed field such as {'name': 'Test updated', 'enabled': False}.
    """
    body = _body(rule, update=True)
    key, url = await _context(
        registry, host, site, "/object-oriented-network-config", resource_id=rule_id
    )
    return await _verified_put(
        client,
        key,
        url,
        body,
        lambda: _collection_record(
            client,
            key,
            url.rsplit("/", 1)[0] + "s",
            rule_id,
            list_tool="list_policy_engine_rules",
        ),
    )


async def delete_policy_engine_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule_id: str
) -> Any:
    """Delete one policy-engine object. Returns {deleted: true, message, response}.

    The upstream body is under response, verbatim. The id is resolved in the collection
    list first; an unknown id lists the valid ids and sends no write. Under UNIFI_DRY_RUN
    returns {status: "dry_run", deleted: false, message, response} with the dry-run preview
    as response.

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
        rule_id: Native id or _id from list_policy_engine_rules, for example 'test-rule'.
    """
    key, url = await _context(
        registry, host, site, "/object-oriented-network-config", resource_id=rule_id
    )
    guard_request("DELETE", url)
    record = await _collection_record(
        client,
        key,
        url.rsplit("/", 1)[0] + "s",
        rule_id,
        list_tool="list_policy_engine_rules",
    )
    response = await client.delete(_native_url(url, record), key=key)
    return deletion_result(f"Policy-engine rule {rule_id} deleted.", response)


async def preview_policy_engine_rule(
    client: UniFiClient, registry: Registry, host: str, site: str, rule: dict[str, Any]
) -> Any:
    """Preview an object-oriented policy using the Network 11.1.11 private endpoint.

    Returns the upstream body unchanged. This POST is classified as a write until an
    independently approved read-POST allowlist entry exists. Under UNIFI_DRY_RUN
    returns a dry-run preview.

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
        rule: Free-form policy JSON object, for example {'name': 'Test',
            'enabled': False, 'targets': [], 'secure': {'enabled': False}}.
    """
    body = _body(rule)
    key, url = await _context(registry, host, site, "/object-oriented-network-config/preview")
    try:
        return await client.post(url, key=key, json=body)
    except UniFiHTTPError as exc:
        if exc.status != 405:
            raise
        raise UniFiHTTPError(
            f"{exc}\nPolicy preview may be unavailable on this Network version: "
            "Network 11.0.89 returned HTTP 405; the Network 11.1.11 frontend references "
            "POST /object-oriented-network-config/preview. Check the controller version "
            "and its supported preview route.",
            status=exc.status,
            request_sent=exc.request_sent,
        ) from exc


async def list_network_members_groups(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """List network member groups. Returns the complete unpaged v2 body unchanged.

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
    """
    key, url = await _context(registry, host, site, "/network-members-groups")
    return await client.get(url, key=key)


async def create_network_members_group(
    client: UniFiClient, registry: Registry, host: str, site: str, group: dict[str, Any]
) -> Any:
    """Create a network member group. Returns the upstream body unchanged.

    Under UNIFI_DRY_RUN returns a dry-run preview. Private request has no published
    schema; source-client fields are name, members (strings) and type (string).

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
        group: Free-form group object. type is USERS or CLIENTS (live-verified: any other value,
            including IPV4, is rejected with HTTP 400), for example {'name': 'Test',
            'members': ['aa:bb:cc:dd:ee:01'], 'type': 'CLIENTS'}. Other private fields pass through.
    """
    body = _body(group)
    key, url = await _context(registry, host, site, "/network-members-group")
    return await client.post(url, key=key, json=body)


async def update_network_members_group(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    group_id: str,
    group: dict[str, Any],
) -> Any:
    """PUT a network member group. Returns the upstream body unchanged.

    Under UNIFI_DRY_RUN returns the merged-body preview without a read-back.
    Reads the complete collection, merges partial fields, then verifies requested leaves.
    Object responses add _verified; a failed read-back adds _readAfterError.

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
        group_id: Native id from list_network_members_groups, for example 'test-group'.
        group: Nonempty free-form partial update object. type is USERS or CLIENTS, for example
            {'name': 'Test', 'members': ['aa:bb:cc:dd:ee:01'], 'type': 'CLIENTS'}; preserve
            private fields.
    """
    body = _body(group, update=True)
    key, url = await _context(registry, host, site, "/network-members-group", resource_id=group_id)
    return await _verified_put(
        client,
        key,
        url,
        body,
        lambda: _collection_record(
            client,
            key,
            url.rsplit("/", 1)[0] + "s",
            group_id,
            list_tool="list_network_members_groups",
        ),
    )


async def delete_network_members_group(
    client: UniFiClient, registry: Registry, host: str, site: str, group_id: str
) -> Any:
    """Delete one network member group. Returns {deleted: true, message, response}.

    The upstream body is under response, verbatim. The id is resolved in the collection
    list first; an unknown id lists the valid ids and sends no write. Under UNIFI_DRY_RUN
    returns {status: "dry_run", deleted: false, message, response} with the dry-run preview
    as response.

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
        group_id: Native id from list_network_members_groups, for example 'test-group'.
    """
    key, url = await _context(registry, host, site, "/network-members-group", resource_id=group_id)
    guard_request("DELETE", url)
    record = await _collection_record(
        client,
        key,
        url.rsplit("/", 1)[0] + "s",
        group_id,
        list_tool="list_network_members_groups",
    )
    response = await client.delete(_native_url(url, record), key=key)
    return deletion_result(f"Network members group {group_id} deleted.", response)


async def list_firewall_app_blocks(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """Read application-block settings. Returns the unpaged private v2 body unchanged.

    Pass the complete returned array to set_firewall_app_blocks to restore it.

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
    """
    key, url = await _context(registry, host, site, "/firewall-app-blocks")
    return await client.get(url, key=key)


async def set_firewall_app_blocks(
    client: UniFiClient, registry: Registry, host: str, site: str, blocks: list[dict[str, Any]]
) -> Any:
    """Replace the complete application-block list by POST. Returns the upstream body unchanged.

    Under UNIFI_DRY_RUN returns a dry-run preview. Private body has no published schema;
    read list_firewall_app_blocks first and preserve every returned private field.

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
        blocks: Complete list of free-form JSON objects from list_firewall_app_blocks.
            Preserve existing entries and private fields. An empty list removes all blocks.
            Captured fields include name, enabled, source_type, source_networks,
            source_devices, target_type, app_ids and app_category_ids.
    """
    if not isinstance(blocks, list):
        raise ValueError("blocks must be a JSON array of objects")
    body = [_body(block) for block in blocks]
    key, url = await _context(registry, host, site, "/firewall-app-blocks")
    return await client.post(url, key=key, json=body)


async def preview_firewall_group(
    client: UniFiClient, registry: Registry, host: str, site: str, group: dict[str, Any]
) -> Any:
    """Preview a firewall group URL. Returns the upstream body unchanged.

    This POST is classified as a write until separately allowlisted. Under
    UNIFI_DRY_RUN returns a dry-run preview. Captured FE body uses url and group_type.

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
        group: Free-form JSON object; FE fields url (for example
            'https://example.invalid/list.txt') and group_type (controller string).
    """
    body = _body(group)
    key, url = await _context(registry, host, site, "/firewall-groups/preview")
    return await client.post(url, key=key, json=body)


#: The Integration error code a Network 11.0.89 controller answers (HTTP 400) to a PUT on a
#: policy whose ``metadata.origin`` is ``SYSTEM_DEFINED`` (live 2026-10-28, a "Block Invalid
#: Traffic" policy with ``metadata.configurable`` true).
_SYSTEM_DEFINED_POLICY_REFUSAL = "system-defined-firewall-policy-update-forbidden"
_SYSTEM_DEFINED_POLICY_HINT = (
    "this PUT replaces a whole policy and the controller refuses it for a SYSTEM_DEFINED "
    "policy (metadata.origin). The published Integration API patches only loggingEnabled "
    "on such a policy: use patch_firewall_policy with {loggingEnabled: true|false}. A "
    "USER_DEFINED policy takes this full update."
)


async def update_predefined_firewall_policy(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    policy_id: str,
    policy: dict[str, Any],
) -> Any:
    """Update a predefined firewall policy using the official Network Integration API.

    GET /firewall/policies/{id}, merge the caller's partial fields, then PUT the full
    writable object and GET again to verify requested leaves type-strictly. Returns
    the write body unchanged, adding _verified and, on read failure, _readAfterError.
    Under UNIFI_DRY_RUN returns the merged-body preview without a read-back. A policy with
    metadata.origin SYSTEM_DEFINED cannot be replaced (Network 11.0.89 answers HTTP 400
    system-defined-firewall-policy-update-forbidden, kept whole with a hint to
    patch_firewall_policy, which patches loggingEnabled).

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
        policy_id: Official UUID from list_firewall_policies or get_firewall_policy,
            for example 'bbbbbbbb-0000-4000-8000-000000000001'; not a private v2 _id.
        policy: Nonempty partial official policy object, for example {'enabled': False}.
            Fields use the published Network 10.6.106 shape; see its properties.
            Read-only id, index and metadata are not sent; all unrequested
            writable fields are preserved.
    """
    body = integration_update_body("update_firewall_policy", _body(policy, update=True))
    validate_selector(host, "host")
    validate_selector(site, "site")
    validate_id(policy_id, "policy_id")
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    url = _proxy(host_id, f"/sites/{site_id}/firewall/policies/{policy_id}")
    try:
        return await _verified_put(
            client, key, url, body, lambda: _official_record(client, key, url), official=True
        )
    except UniFiConnectionError as exc:
        if exc.status == 400 and _SYSTEM_DEFINED_POLICY_REFUSAL in str(exc):
            upstream_hint(exc, _SYSTEM_DEFINED_POLICY_HINT)
            raise
        raise


async def get_firewall_zone_matrix(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """Read the private firewall-zone matrix. Returns the upstream body unchanged.

    Args:
        host: Console name or id from list_hosts, for example 'my-console'.
        site: Network site name from list_local_sites, for example 'Default'.
    """
    key, url = await _context(registry, host, site, "/firewall/zone-matrix")
    return await client.get(url, key=key)


def _batch_ids(ids: Any, label: str) -> None:
    """Validate a batch-delete ``ids`` argument before any request."""
    if not isinstance(ids, list):
        raise ValueError(
            f"batch-delete ids must be a list of id strings, got {describe_shape(ids)}; "
            f"pass the {label} ids as a JSON array"
        )
    for item in ids:
        validate_selector(item, "ids")


async def _batch_delete(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    collection: str,
    label: str,
    list_tool: str,
    ids: Any,
) -> Any:
    """Translate Integration ids to private ``_id`` values, POST them to the v2 batch route,
    then read the collection back.

    The v2 ``{collection}/batch-delete`` routes key on the private ``_id``. The ids the list
    and create tools return are the Integration ids, which the v2 records carry as
    ``external_id``: posted as they are, ``acl-rules`` answers 404 ``AclRuleNotFound`` and the
    policy and zone routes answer 204 without removing anything. Every id is validated and
    resolved against the v2 list before the write (an unknown id fails with the valid ids and
    sends nothing); the array of ``_id`` values is POSTed once and the upstream body is
    returned verbatim under ``response``. ``deleted`` is true only when the read-back list no
    longer has any of them. An empty batch is posted as given without readback. Under
    ``UNIFI_DRY_RUN`` nothing is sent or read back.
    """
    _batch_ids(ids, label)
    validate_selector(host, "host")
    validate_selector(site, "site")
    key, url = await _context(registry, host, site, f"/{collection}")
    if not ids:
        response = await client.post(f"{url}/batch-delete", key=key, json=[])
        return deletion_result(
            f"Empty {label} batch accepted; no records were addressed.", response
        )
    rows = await _v2_rows(client, key, url)
    targets = [select_classic_record(rows, item, label, list_tool)["_id"] for item in ids]
    response = await client.post(f"{url}/batch-delete", key=key, json=cast(Any, targets))
    if is_dry_run_preview(response):
        return deletion_result("", response)

    async def read_after() -> set[str]:
        return deletion_readback_ids(await _v2_rows(client, key, url), "_id")

    after, read_error = await safe_read_after(read_after)
    if after is None:
        return with_read_after_error(
            {
                "deleted": False,
                "message": (
                    f"Batch-delete of {len(ids)} {label} id(s) was accepted but the read-back "
                    f"failed, so the removal is unverified: list the {label} records and check."
                ),
                "response": response,
            },
            read_error,
        )
    left = after
    remaining = [item for item, target in zip(ids, targets, strict=True) if target in left]
    if remaining:
        return {
            "deleted": False,
            "message": (
                f"The console accepted the batch-delete but {len(remaining)} of {len(ids)} "
                f"{label} id(s) are still listed: {', '.join(remaining)}."
            ),
            "response": response,
        }
    return deletion_result(
        f"Batch-delete of {len(ids)} {label} id(s) done; the read-back list no longer has them.",
        response,
    )


async def _v2_rows(client: UniFiClient, key: Any, url: str) -> list[dict[str, Any]]:
    """The complete unpaged v2 collection at ``url``, every row an object."""
    response = await client.get(url, key=key)
    if not isinstance(response, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {url}: expected an array, "
            f"got {describe_shape(response)}"
        )
    return _object_rows(response, url)


async def _batch_delete_acl_rules(
    client: UniFiClient, registry: Registry, host: str, site: str, ids: list[str]
) -> Any:
    """Batch-delete ACL rules (Integration ids translated to v2 _ids, one batch POST)."""
    return await _batch_delete(
        client, registry, host, site, "acl-rules", "ACL rule", "list_acl_rules", ids
    )


async def _batch_delete_firewall_policies(
    client: UniFiClient, registry: Registry, host: str, site: str, ids: list[str]
) -> Any:
    """Delete firewall policies one by one through the Integration API, then read the list back.

    A v2 policy record carries no Integration id (live-verified: no ``external_id`` and no
    other link), so the v2 ``firewall-policies/batch-delete`` route cannot be addressed from the
    ids the list and create tools return; it answers 204 and removes nothing. Each id is sent to
    the Integration DELETE the single-delete tool uses, then reads each id back: ``deleted`` is
    true only when every read answers not found. A failing DELETE raises, naming the ids already
    deleted and those not attempted. ``response`` is the upstream body when every DELETE
    answered the same body (an empty one), else the bodies in id order.
    Under ``UNIFI_DRY_RUN`` nothing is sent or read back.
    """
    _batch_ids(ids, "firewall policy")
    validate_selector(host, "host")
    validate_selector(site, "site")
    for item in ids:
        validate_id(item, "ids")
    if not ids:
        message = "No firewall policy ids supplied; no writes sent."
        if client.dry_run:
            return {
                "status": "dry_run",
                "deleted": False,
                "message": f"{DRY_RUN_MESSAGE} {message}",
                "response": [],
            }
        return deletion_result(message, [])
    # Bind the exact readback route before any write. Only a 404 from this
    # resource GET proves absence; a registry host/site-resolution 404 does not.
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_id = await registry.resolve_site_id(site, host_id, key=key)
    _fw._assert_uuid(site_id)
    policies = _fw._proxy(host_id, f"/sites/{site_id}/firewall/policies")

    async def read_policy(item: str) -> Any:
        return await client.get(f"{policies}/{item}", key=key)

    bodies: list[Any] = []
    for index, item in enumerate(ids):
        try:
            bodies.append(await client.delete(f"{policies}/{item}", key=key))
        except Exception as exc:
            if index == 0 and len(ids) == 1:
                raise
            deleted: list[str] = []
            present: list[str] = []
            unverified: list[str] = []
            not_attempted: list[str] = []
            for previous, body in zip(ids[:index], bodies, strict=True):
                if is_dry_run_preview(body):
                    not_attempted.append(previous)
                    continue
                try:
                    await read_policy(previous)
                except UniFiConnectionError as read_exc:
                    (deleted if read_exc.status == 404 else unverified).append(previous)
                except Exception:
                    unverified.append(previous)
                else:
                    present.append(previous)
            message = (
                f"{exc} Deleted before this failure: {deleted or 'none'}; "
                f"still present: {present or 'none'}; unverified: {unverified or 'none'}; "
                f"failed/uncertain: {[item]}; "
                f"not attempted: {not_attempted + ids[index + 1 :] or 'none'}."
            )
            if isinstance(exc, UniFiConnectionError):
                raise type(exc)(message, request_sent=exc.request_sent, status=exc.status) from exc
            if isinstance(exc, RateLimitError):
                raise type(exc)(message) from exc
            raise ToolError(message) from exc
    response = bodies[0] if bodies and all(b == bodies[0] for b in bodies) else bodies
    if any(is_dry_run_preview(b) for b in bodies):
        if len(bodies) == 1:
            return deletion_result("", bodies[0])
        return {
            "status": "dry_run",
            "deleted": False,
            "message": DRY_RUN_MESSAGE,
            "response": bodies,
        }

    async def still_listed() -> list[str]:
        left = []
        for item in ids:
            try:
                await read_policy(item)
            except UniFiConnectionError as exc:
                if exc.status != 404:
                    raise
            else:
                left.append(item)
        return left

    left, read_error = await safe_read_after(still_listed)
    if left == []:
        return deletion_result(
            f"Batch-delete of {len(ids)} firewall policy id(s) done; reading each back "
            "answers not found.",
            response,
        )
    if left is None:
        message = (
            f"Batch-delete of {len(ids)} firewall policy id(s) was accepted but the read-back "
            "failed, so the removal is unverified."
        )
    else:
        message = f"The console accepted the deletes but {', '.join(left)} are still listed."
    return with_read_after_error(
        {"deleted": False, "message": message, "response": response}, read_error
    )


async def _batch_delete_firewall_zones(
    client: UniFiClient, registry: Registry, host: str, site: str, ids: list[str]
) -> Any:
    """Batch-delete firewall zones (Integration ids translated to v2 _ids, one batch POST)."""
    return await _batch_delete(
        client,
        registry,
        host,
        site,
        "firewall/zone",
        "firewall zone",
        "list_firewall_zones_proxy",
        ids,
    )


_impl_reset_dpi_counters = reset_dpi_counters
_impl_list_policy_engine_rules = list_policy_engine_rules
_impl_create_policy_engine_rule = create_policy_engine_rule
_impl_update_policy_engine_rule = update_policy_engine_rule
_impl_delete_policy_engine_rule = delete_policy_engine_rule
_impl_preview_policy_engine_rule = preview_policy_engine_rule
_impl_list_network_members_groups = list_network_members_groups
_impl_create_network_members_group = create_network_members_group
_impl_update_network_members_group = update_network_members_group
_impl_delete_network_members_group = delete_network_members_group
_impl_list_firewall_app_blocks = list_firewall_app_blocks
_impl_set_firewall_app_blocks = set_firewall_app_blocks
_impl_preview_firewall_group = preview_firewall_group
_impl_update_predefined_firewall_policy = update_predefined_firewall_policy
_impl_get_firewall_zone_matrix = get_firewall_zone_matrix


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register all 18 lane tools in the real catalog and static family index."""

    @mcp.tool(
        annotations=WRITE,
    )
    async def reset_dpi_counters(host: str, site: str) -> Any:
        """Erase DPI history and counters using v2 DELETE /dpi. Consequence: permanently erases
        DPI history and counters. Returns the upstream body unchanged (nonobjects use result).
        Under UNIFI_DRY_RUN sends no mutation and returns {status: "dry_run", dryRun: true, sent:
        false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
        """
        client, registry = deps_fn()
        return await _impl_reset_dpi_counters(client, registry, host, site)

    @mcp.tool(
        annotations=READ_ONLY,
    )
    async def list_policy_engine_rules(host: str, site: str) -> Any:
        """List policy-engine objects, distinct from Integration firewall policies. Returns the
        complete unpaged array unchanged (nonobjects use result).

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
        """
        client, registry = deps_fn()
        return await _impl_list_policy_engine_rules(client, registry, host, site)

    @mcp.tool(
        annotations=WRITE,
    )
    async def create_policy_engine_rule(host: str, site: str, rule: dict[str, Any]) -> Any:
        """Create a private policy-engine object. Returns the upstream body unchanged; masked
        fields are reported in _redactedFieldsNotSent (nonobjects use result). Under
        UNIFI_DRY_RUN sends no mutation and returns {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            rule: Free-form JSON object, for example {'name': 'Test', 'enabled': False,
                'targets': [], 'secure': {'enabled': False}}; preserve private fields.
        """
        client, registry = deps_fn()
        return await _impl_create_policy_engine_rule(client, registry, host, site, rule)

    @mcp.tool(
        annotations=WRITE,
    )
    async def update_policy_engine_rule(
        host: str, site: str, rule_id: str, rule: dict[str, Any]
    ) -> Any:
        """Read-merge-write and type-strict requested-leaf verification. Returns the upstream
        write body with _verified and possible _readAfterError; nonobjects use result. Masked
        fields are omitted and reported in _redactedFieldsNotSent. Under UNIFI_DRY_RUN sends no
        mutation and returns {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}}; no read-back or verification.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            rule_id: Native id or _id from list_policy_engine_rules, for example 'test-rule'.
            rule: Nonempty free-form partial update object; unrequested fields are preserved, with a
                changed field such as {'name': 'Test updated', 'enabled': False}.
        """
        client, registry = deps_fn()
        return await _impl_update_policy_engine_rule(client, registry, host, site, rule_id, rule)

    @mcp.tool(
        annotations=WRITE,
    )
    async def delete_policy_engine_rule(host: str, site: str, rule_id: str) -> Any:
        """Delete one policy-engine object. Consequence: removes the selected policy and its
        enforcement. The id is resolved in the collection list first; an unknown id lists the valid
        ids and sends no write. Returns {deleted, message, response}: deleted is true, message
        summarizes the delete, and response is the upstream body verbatim (decoded JSON, raw text,
        or null when the body is empty). Under UNIFI_DRY_RUN sends no mutation and returns {status:
        "dry_run", deleted: false, message, response}, where response is the dry-run preview
        {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path, params,
        body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            rule_id: Native id or _id from list_policy_engine_rules, for example 'test-rule'.
        """
        client, registry = deps_fn()
        return await _impl_delete_policy_engine_rule(client, registry, host, site, rule_id)

    @mcp.tool(
        annotations=WRITE,
    )
    async def preview_policy_engine_rule(host: str, site: str, rule: dict[str, Any]) -> Any:
        """Preview an object-oriented policy using the Network 11.1.11 private endpoint.
        Consequence: submits the policy to the controller preview action, classified as a write.
        Network 11.0.89 returned HTTP 405; the 11.1.11 frontend references POST
        /object-oriented-network-config/preview, but that newer endpoint is not live-verified.
        Returns upstream body and _redactedFieldsNotSent when masked fields are omitted
        (nonobjects use result). Under UNIFI_DRY_RUN sends no mutation and returns {status:
        "dry_run", dryRun: true, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            rule: Free-form policy JSON object, for example {'name': 'Test',
                'enabled': False, 'targets': [], 'secure': {'enabled': False}}.
        """
        client, registry = deps_fn()
        return await _impl_preview_policy_engine_rule(client, registry, host, site, rule)

    @mcp.tool(
        annotations=READ_ONLY,
    )
    async def list_network_members_groups(host: str, site: str) -> Any:
        """List network member groups. Returns the complete unpaged array unchanged (nonobjects
        use result).

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
        """
        client, registry = deps_fn()
        return await _impl_list_network_members_groups(client, registry, host, site)

    @mcp.tool(
        annotations=WRITE,
    )
    async def create_network_members_group(host: str, site: str, group: dict[str, Any]) -> Any:
        """Create a network member group. Returns upstream body and _redactedFieldsNotSent when
        masked fields are omitted (nonobjects use result). Under UNIFI_DRY_RUN sends no mutation
        and returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            group: Free-form group object. type is USERS or CLIENTS (live-verified: any other value,
                including IPV4, is rejected with HTTP 400), for example {'name': 'Test',
                'members': ['aa:bb:cc:dd:ee:01'], 'type': 'CLIENTS'}. Other fields pass through.
        """
        client, registry = deps_fn()
        return await _impl_create_network_members_group(client, registry, host, site, group)

    @mcp.tool(
        annotations=WRITE,
    )
    async def update_network_members_group(
        host: str, site: str, group_id: str, group: dict[str, Any]
    ) -> Any:
        """Read-merge-write and type-strict requested-leaf verification. Returns the upstream
        write body with _verified and possible _readAfterError; nonobjects use result. Masked
        fields are omitted and reported in _redactedFieldsNotSent. Under UNIFI_DRY_RUN sends no
        mutation and returns {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}}; no read-back or verification.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            group_id: Native id from list_network_members_groups, for example 'test-group'.
            group: Nonempty free-form partial update object. type is USERS or CLIENTS, for example
                {'name': 'Test', 'members': ['aa:bb:cc:dd:ee:01'], 'type': 'CLIENTS'}; preserve
                private fields.
        """
        client, registry = deps_fn()
        return await _impl_update_network_members_group(
            client, registry, host, site, group_id, group
        )

    @mcp.tool(
        annotations=WRITE,
    )
    async def delete_network_members_group(host: str, site: str, group_id: str) -> Any:
        """Delete one network member group. Consequence: removes the selected member group; policies
        referencing it may be affected. The id is resolved in the collection list first; an unknown
        id lists the valid ids and sends no write. Returns {deleted, message, response}: deleted is
        true, message summarizes the delete, and response is the upstream body verbatim (decoded
        JSON, raw text, or null when the body is empty). Under UNIFI_DRY_RUN sends no mutation and
        returns {status: "dry_run", deleted: false, message, response}, where response is the
        dry-run preview {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            group_id: Native id from list_network_members_groups, for example 'test-group'.
        """
        client, registry = deps_fn()
        return await _impl_delete_network_members_group(client, registry, host, site, group_id)

    @mcp.tool(
        annotations=READ_ONLY,
    )
    async def list_firewall_app_blocks(host: str, site: str) -> Any:
        """Read application blocks. Returns the complete application-block array verbatim
        (nonobjects use result).

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
        """
        client, registry = deps_fn()
        return await _impl_list_firewall_app_blocks(client, registry, host, site)

    @mcp.tool(
        annotations=WRITE,
    )
    async def set_firewall_app_blocks(host: str, site: str, blocks: list[dict[str, Any]]) -> Any:
        """Replace application blocks with the complete returned array. Consequence: replaces
        the configured app blocks, removing omitted entries. Returns upstream body and
        _redactedFieldsNotSent when masked fields are omitted (nonobjects use result). Under
        UNIFI_DRY_RUN sends no mutation and returns {status: "dry_run", dryRun: true, sent: false,
        message,
        preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            blocks: Complete list of free-form JSON objects from list_firewall_app_blocks.
                Preserve existing entries and private fields. An empty list removes all blocks.
                Captured fields include name, enabled, source_type, source_networks,
                source_devices, target_type, app_ids and app_category_ids.
        """
        client, registry = deps_fn()
        return await _impl_set_firewall_app_blocks(client, registry, host, site, blocks)

    @mcp.tool(
        annotations=WRITE,
    )
    async def preview_firewall_group(host: str, site: str, group: dict[str, Any]) -> Any:
        """Preview a firewall group URL. Consequence: submits the URL to the controller preview
        action, classified as a write. Returns upstream body and _redactedFieldsNotSent when
        masked fields are omitted (nonobjects use result). Under UNIFI_DRY_RUN sends no mutation
        and returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
        params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            group: Free-form JSON object; FE fields url (for example
                'https://example.invalid/list.txt') and group_type (controller string).
        """
        client, registry = deps_fn()
        return await _impl_preview_firewall_group(client, registry, host, site, group)

    @mcp.tool(
        annotations=WRITE,
    )
    async def update_predefined_firewall_policy(
        host: str, site: str, policy_id: str, policy: dict[str, Any]
    ) -> Any:
        """Read-merge-write and type-strict requested-leaf verification. Returns the upstream
        write body with _verified and possible _readAfterError; nonobjects use result. Masked
        fields are omitted and reported in _redactedFieldsNotSent. Under UNIFI_DRY_RUN sends no
        mutation and returns {status: "dry_run", dryRun: true, sent: false, message, preview:
        {method, path, params, body}}; no read-back or verification.

        This is the full PUT of the Integration API. A policy whose metadata.origin is
        SYSTEM_DEFINED is refused by the controller (Network 11.0.89: HTTP 400
        system-defined-firewall-policy-update-forbidden, returned whole with a hint); change
        only its loggingEnabled with patch_firewall_policy instead.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            policy_id: Official UUID from list_firewall_policies or get_firewall_policy,
                for example 'bbbbbbbb-0000-4000-8000-000000000001'; not a private v2 _id.
            policy: Nonempty partial official policy object, for example {'enabled': False}.
                Fields use the published Network 10.6.106 shape; see its properties.
                Read-only id, index and metadata are not sent; all unrequested
                writable fields are preserved.
        """
        client, registry = deps_fn()
        return await _impl_update_predefined_firewall_policy(
            client, registry, host, site, policy_id, policy
        )

    @mcp.tool(
        annotations=READ_ONLY,
    )
    async def get_firewall_zone_matrix(host: str, site: str) -> Any:
        """Read the private firewall-zone matrix. Returns the upstream body unchanged
        (nonobjects use result).

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
        """
        client, registry = deps_fn()
        return await _impl_get_firewall_zone_matrix(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def batch_delete_acl_rules(host: str, site: str, ids: list[str]) -> Any:
        """Batch-delete ACL rules (v2 POST acl-rules/batch-delete, one call).
        Consequence: permanently removes every listed record; there is no undo. Each id is
        resolved against the v2 list first (an unknown id fails with the valid ids and sends
        nothing), then the list is read back. Returns {deleted, message, response}: deleted is
        true, message summarizes the delete, and response is the upstream body verbatim (decoded
        JSON, raw text, or null when the body is empty); deleted is false and message names the
        ids still listed when the read-back still has any, or says the removal is unverified
        when the read-back failed. Under UNIFI_DRY_RUN sends nothing and returns {status:
        "dry_run", deleted: false, message, response}, where response is {status: "dry_run",
        dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            ids: List of ACL rule id strings to delete, for example
                ["0b6e1d8a-2f4c-4d7e-9a31-5c8f7e2b1a90"], the ids the list and create tools
                return (the private _id is accepted too). Each id must be non-empty with no
                surrounding whitespace.
        """
        client, registry = deps_fn()
        return await _batch_delete_acl_rules(client, registry, host, site, ids)

    @mcp.tool(
        annotations=WRITE,
    )
    async def batch_delete_firewall_policies(host: str, site: str, ids: list[str]) -> Any:
        """Batch-delete firewall policies (DELETE firewall/policies/{id} per id, then read back).
        Consequence: permanently removes every listed record; there is no undo. The v2 batch
        route cannot be addressed with Integration ids, so each id goes to the Integration
        DELETE, then each id is read back. Returns {deleted, message, response}: deleted is true,
        message summarizes the delete, and response is the upstream body verbatim (decoded JSON,
        raw text, or null when the body is empty). With several differing bodies response is the
        list of them in id order. When a read-back still finds an id, deleted is false and
        message names it; when the read-back failed, readAfterError says why. A failing DELETE
        raises, naming the ids already deleted. Under UNIFI_DRY_RUN sends nothing and returns
        {status: "dry_run", deleted: false, message, response}, where response is {status:
        "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}} (a list
        of them for several ids).

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            ids: List of firewall policy ids to delete, for example
                ["0b6e1d8a-2f4c-4d7e-9a31-5c8f7e2b1a90"], the ids the list and create tools
                return. Each id must be letters, digits, hyphen or underscore only.
        """
        client, registry = deps_fn()
        return await _batch_delete_firewall_policies(client, registry, host, site, ids)

    @mcp.tool(
        annotations=WRITE,
    )
    async def batch_delete_firewall_zones(host: str, site: str, ids: list[str]) -> Any:
        """Batch-delete firewall zones (v2 POST firewall/zone/batch-delete, one call).
        Consequence: permanently removes every listed record; there is no undo. Each id is
        resolved against the v2 list first (an unknown id fails with the valid ids and sends
        nothing), then the list is read back. Returns {deleted, message, response}: deleted is
        true, message summarizes the delete, and response is the upstream body verbatim (decoded
        JSON, raw text, or null when the body is empty); deleted is false and message names the
        ids still listed when the read-back still has any, or says the removal is unverified
        when the read-back failed. Under UNIFI_DRY_RUN sends nothing and returns {status:
        "dry_run", deleted: false, message, response}, where response is {status: "dry_run",
        dryRun, sent: false, message, preview: {method, path, params, body}}.

        Args:
            host: Console name or id from list_hosts, for example 'my-console'.
            site: Network site name from list_local_sites, for example 'Default'.
            ids: List of firewall zone id strings to delete, for example
                ["0b6e1d8a-2f4c-4d7e-9a31-5c8f7e2b1a90"], the ids the list and create tools
                return (the private _id is accepted too). Each id must be non-empty with no
                surrounding whitespace.
        """
        client, registry = deps_fn()
        return await _batch_delete_firewall_zones(client, registry, host, site, ids)
