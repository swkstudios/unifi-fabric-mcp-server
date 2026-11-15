"""Names the network family's ``site_config`` shares with other families.

Used by network, vpn. Moved verbatim by ``scripts/move_family.py`` from
``families/network/network_services_proxy.py``, ``families/network/site_config.py``, which import
them back where they use them, so their own code and import paths stay.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from ..client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    strip_additive_keys,
    upstream_error_value,
    validate_id,
)
from ..config import APIKeyConfig
from ..matching import find_by_id, name_matches, same_id
from ..redaction import (
    REDACTION_MASK,
    drop_and_note_masked_fields,
    note_dropped_fields,
    write_redaction_enabled,
)
from ..registry import Registry
from ..shared_shapes._classic_objects import (
    _object_rows,
    classic_rest,
    listed_record_id,
    resolve_site_slug,
    v2_site,
)
from ..shared_shapes._keys import with_context
from ..shared_shapes._payload import strip_empty_list_values
from ..shared_shapes._results import deletion_result, leaf_equal


@dataclass(frozen=True)
class _Collection:
    """One controller collection: its route, its record kind and how a record is named."""

    path: str
    kind: str
    list_tool: str
    id_fields: tuple[str, ...] = ("_id",)
    label_fields: tuple[str, ...] = ("name",)
    v2: bool = False
    #: Written through v2 ``/batch_add``, ``/batch_update`` and ``/batch_delete`` POSTs of a
    #: JSON array (one element per call); the write answers a bare array of the records.
    batch: bool = False

    def url(self, host_id: str, site_slug: str, suffix: str = "") -> str:
        build = v2_site if self.v2 else classic_rest
        return build(host_id, site_slug, self.path + suffix)


RADIUS_PROFILES = _Collection(
    "/radiusprofile", "RADIUS profile", "list_radius_profiles", ("_id", "external_id")
)


async def _config_rows(
    client: UniFiClient, path: str, key: APIKeyConfig | None
) -> tuple[Any, list[dict[str, Any]]]:
    """``(body, records)`` of a collection GET: a Classic ``{meta, data}`` envelope or a v2
    bare array. Any other shape raises with the shape received."""
    body = await client.get(path, key=key)
    items = body.get("data") if isinstance(body, dict) else body
    if not isinstance(items, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected an object with a 'data' "
            f"array or a JSON array, got {describe_shape(body)}"
        )
    return body, _object_rows(items, path)


def _config_label(record: dict[str, Any], fields: tuple[str, ...]) -> Any:
    for name in fields:
        value = record.get(name)
        if value not in (None, ""):
            return value
    return None


def _valid_config_records(records: list[dict[str, Any]], coll: _Collection) -> str:
    def ids(r: dict[str, Any]) -> str:
        return ", ".join(
            f"{f}={upstream_error_value(r.get(f))}" for f in coll.id_fields if r.get(f) is not None
        )

    return (
        "; ".join(
            f"{upstream_error_value(_config_label(r, coll.label_fields))!r} ({ids(r)})"
            for r in records
        )
        or "(none)"
    )


def _select_config_record(
    records: list[dict[str, Any]],
    wanted: str,
    coll: _Collection,
    *,
    write: bool,
    by_name: bool = False,
) -> dict[str, Any]:
    """The record ``wanted`` names (an id field of ``coll``, then -- with ``by_name`` -- its
    name). An unknown or ambiguous selector fails listing every record (label and ids)."""
    match = find_by_id(records, wanted, *coll.id_fields)
    if match is None and by_name:
        named = name_matches(records, wanted, lambda r: r.get("name"))
        if len(named) > 1:
            raise ValueError(
                f"{coll.kind} name {wanted!r} matches {len(named)} records; pass the _id. "
                f"Valid: {_valid_config_records(records, coll)}."
            )
        match = named[0] if named else None
    if match is None:
        suffix = " No write was sent." if write else ""
        raise ValueError(
            f"{coll.kind} {wanted!r} not found; valid: "
            f"{_valid_config_records(records, coll)}. Get ids from {coll.list_tool} (_id).{suffix}"
        )
    listed_record_id(match, coll.id_fields[0])
    return match


async def _resolve_config_record(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    wanted: str,
    arg: str,
    coll: _Collection,
    *,
    write: bool = True,
) -> tuple[APIKeyConfig | None, str, str, dict[str, Any]]:
    """``(key, host_id, site_slug, record)`` for the record ``wanted`` names in ``coll``."""
    validate_id(wanted, arg)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    _body, records = await _config_rows(client, coll.url(host_id, site_slug), key)
    return key, host_id, site_slug, _select_config_record(records, wanted, coll, write=write)


async def _delete_config_record(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    coll: _Collection,
    wanted: str,
    arg: str,
    /,
) -> dict[str, Any]:
    """DELETE the record ``wanted`` names (resolved in the list first)."""
    key, host_id, site_slug, record = await _resolve_config_record(
        client, registry, host, site, wanted, arg, coll
    )
    response = await client.delete(coll.url(host_id, site_slug, f"/{record['_id']}"), key=key)
    return deletion_result(f"{coll.kind} {wanted} deleted.", response)


def _addressed_config_body(
    body: dict[str, Any], record: dict[str, Any], coll: _Collection, /
) -> dict[str, Any]:
    """Normalize a matching body identity; refuse an identity naming another record."""
    if "_id" not in body:
        return body
    given = body["_id"]
    if isinstance(given, str) and any(same_id(given, record.get(f)) for f in coll.id_fields):
        return {**body, "_id": record["_id"]}
    raise ValueError(
        f"{coll.kind} body _id {given!r} does not match the resolved record "
        f"_id {record['_id']!r}. Remove the body _id or use the resolved _id. "
        "No write was sent."
    )


def _merge_config_body(record: dict[str, Any], fields: dict[str, Any], /) -> dict[str, Any]:
    """Overlay explicit fields, retaining stored values wherever a mask was supplied."""
    stored = strip_empty_list_values(strip_additive_keys(record))
    missing = object()
    dropped: list[str] = []

    def keep(changes: Any, prior: Any, path: str) -> Any:
        if write_redaction_enabled() and isinstance(changes, str) and changes == REDACTION_MASK:
            dropped.append(path)
            return prior
        if isinstance(changes, dict):
            before = prior if isinstance(prior, dict) else {}
            out_dict = {}
            for key, value in changes.items():
                child = f"{path}.{key}" if path else str(key)
                kept = keep(value, before.get(key, missing), child)
                if kept is not missing:
                    out_dict[key] = kept
            return out_dict
        if isinstance(changes, list):
            before_list = prior if isinstance(prior, list) else []
            out_list = []
            for index, value in enumerate(changes):
                old = before_list[index] if index < len(before_list) else missing
                kept = keep(value, old, f"{path}[{index}]")
                if kept is not missing:
                    out_list.append(kept)
            return out_list
        return changes

    changes = keep(fields, stored, "")
    note_dropped_fields(dropped)
    return {**stored, **changes, "_id": record["_id"]}


def _written_config_record(response: Any, coll: _Collection) -> Any:
    """The record a write answered with: Classic ``data[0]``, the only element of a v2
    batch answer, or the v2 object itself."""
    if coll.batch:
        return response[0] if isinstance(response, list) and len(response) == 1 else None
    if coll.v2:
        return response
    data = response.get("data") if isinstance(response, dict) else None
    return data[0] if isinstance(data, list) and len(data) == 1 else None


#: Fields a write never compares: the record's identity, and the ``x_`` secrets (a
#: controller may answer them masked, so a difference proves nothing).
_UNCOMPARED = frozenset({"_id", "site_id", "external_id"})


def _readable_config_equal(sent: Any, stored: Any, /) -> bool:
    """Compare every readable leaf, excluding controller-masked x_ fields.

    Leaves use the shared :func:`leaf_equal`: JSON numbers compare by value (``1812``
    sent and ``1812.0`` stored are the same JSON number), a bool only equals a bool
    (``True`` is not ``1``), and a string never equals a number. RADIUS auth/acct
    server lists carry x_secret inside each server object. A masked or omitted secret
    cannot prove a mismatch; all other keys, values and list positions still
    participate in the comparison.
    """
    if isinstance(sent, dict) and isinstance(stored, dict):
        readable_sent = {k: v for k, v in sent.items() if not k.startswith("x_")}
        readable_stored = {k: v for k, v in stored.items() if not k.startswith("x_")}
        return readable_sent.keys() == readable_stored.keys() and all(
            _readable_config_equal(v, readable_stored[k]) for k, v in readable_sent.items()
        )
    if isinstance(sent, list) and isinstance(stored, list):
        return len(sent) == len(stored) and all(
            _readable_config_equal(a, b) for a, b in zip(sent, stored, strict=True)
        )
    return leaf_equal(sent, stored)


def _with_warning(created: dict[str, Any], warning: dict[str, Any]) -> dict[str, Any]:
    """The created object verbatim plus server warning context, preserving collisions."""
    return with_context(created, {"_warnings": [warning]})


def _with_config_write_warnings(response: Any, sent: dict[str, Any], coll: _Collection, /) -> Any:
    """The write's upstream body verbatim, plus additive ``_warnings`` when the record it
    answered with shows the write did not land as sent (a 200 is never trusted alone):

    * ``NO_ID_RETURNED``: the record has no ``_id``, so nothing was stored;
    * ``NOT_STORED_AS_SENT``: top-level fields whose stored value differs from the value
      sent (JSON numbers by value, bool and other types strict; names only, never
      values; ``x_`` secrets are not compared).

    A v2 batch answer is a bare one-element array, which has no place for a key: the
    warnings then go on that array's record, and the array is returned as received.
    """
    if is_dry_run_preview(response) or not isinstance(response, (dict, list)):
        return response
    record = _written_config_record(response, coll)
    if not isinstance(record, dict):
        return response
    warnings: list[dict[str, Any]] = []
    if not record.get("_id"):
        warnings.append(
            {
                "code": "NO_ID_RETURNED",
                "message": (
                    f"The controller answered success but returned the {coll.kind.lower()} "
                    f"without an _id, so nothing was stored. Check with {coll.list_tool}. "
                    "(Seen for legacy firewall rules on consoles that use zone-based firewall "
                    "policies: use create_firewall_policy there.)"
                ),
            }
        )
    differing = sorted(
        k
        for k, v in sent.items()
        if k not in _UNCOMPARED
        and not k.startswith(("_", "x_"))
        and (k not in record or not _readable_config_equal(v, record[k]))
    )
    if differing and record.get("_id"):
        warnings.append(
            {
                "code": "NOT_STORED_AS_SENT",
                "fields": differing,
                "message": (
                    f"The controller stored these fields with a value other than the one sent "
                    f"(or dropped them): {', '.join(differing)}. Read the record back with "
                    f"{coll.list_tool} and check the values this controller accepts."
                ),
            }
        )
    if coll.batch:
        for warning in warnings:
            record = _with_warning(record, warning)
        return [record]
    for warning in warnings:
        response = _with_warning(cast(dict[str, Any], response), warning)
    return response


async def _update_config_record(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    coll: _Collection,
    wanted: str,
    arg: str,
    body: dict[str, Any],
    /,
    *,
    merge: bool = False,
) -> Any:
    """PUT ``body`` on the record ``wanted`` names (resolved in the list first).

    With ``merge`` the stored record is read and ``body`` is laid over it, so a route that
    replaces the whole record (v2 AP groups) never loses a field the caller left out."""
    # A single-id collection has no aliases to resolve: reject conflicts before reads.
    if coll.id_fields == ("_id",):
        _addressed_config_body(body, {"_id": wanted}, coll)
    key, host_id, site_slug, record = await _resolve_config_record(
        client, registry, host, site, wanted, arg, coll
    )
    upstream_id = record["_id"]
    fields = _addressed_config_body(strip_additive_keys(body), record, coll)
    sent = _merge_config_body(record, fields) if merge else drop_and_note_masked_fields(fields)
    response = await client.put(coll.url(host_id, site_slug, f"/{upstream_id}"), key=key, json=sent)
    return _with_config_write_warnings(response, sent, coll)
