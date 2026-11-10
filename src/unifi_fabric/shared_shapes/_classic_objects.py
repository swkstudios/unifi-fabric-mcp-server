"""Classic REST networkconf and v2 device-tag helpers shared by write tools (not a tool module).

The published Network Integration API serves VPN servers, site-to-site tunnels, WAN
interfaces, RADIUS profiles and device tags GET-only: on Network 11.0.81 a POST on the
collection answers HTTP 405 and a PUT or DELETE on an item answers 404 "No endpoint".
The controller's own web UI writes them on other routes, and these helpers reach those:

* VPN servers, site-to-site tunnels and WAN interfaces are Classic REST ``networkconf``
  records (``/proxy/network/api/s/{site}/rest/networkconf``) told apart by ``purpose``
  (``remote-user-vpn``, ``site-vpn``, ``wan``). RADIUS profiles are ``rest/radiusprofile``.
  A Classic record carries its own ``_id`` and, as ``external_id``, the id the Integration
  list tools report, so either id selects the record.
* Device tags are v2 records: list and create on ``/v2/api/site/{site}/device-tags``,
  update on ``.../device-tags/{_id}``, delete on ``/v2/api/device-tags/{_id}`` (no site
  segment; the site-scoped DELETE answers 405).
"""

from __future__ import annotations

from typing import Any

from ..client import (
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    upstream_error_text,
    upstream_error_value,
    validate_id,
)
from ..config import APIKeyConfig
from ..matching import find_by_id, name_matches, same_id, with_upstream_id
from ..registry import Registry
from ..secret_scrub import configured_secrets, scrub
from ..selector_syntax import name_reason

_CONSOLE = "/v1/connector/consoles/{host_id}/proxy/network"


def checked_classic_response(
    response: Any, path: str, *, client: UniFiClient | None = None, key: APIKeyConfig | None = None
) -> Any:
    """Preserve a Classic envelope; a non-ok rc is an upstream error even on HTTP 200."""
    meta = response.get("meta") if isinstance(response, dict) else None
    if isinstance(meta, dict) and "rc" in meta and meta["rc"] != "ok":
        raise UniFiConnectionError(
            scrub(
                upstream_error_text(response, client),
                configured_secrets(
                    getattr(client, "_settings", None),
                    extra=(key.key,) if key else (),
                    include_call=bool(
                        getattr(getattr(client, "_settings", None), "redact_secrets", False)
                    ),
                ),
            )
        )
    return response


def classic_rest(host_id: str, site_slug: str, path: str) -> str:
    """Connector URL of a Classic REST ``rest/...`` path for one site."""
    return _CONSOLE.format(host_id=host_id) + f"/api/s/{site_slug}/rest{path}"


def v2_site(host_id: str, site_slug: str, path: str) -> str:
    """Connector URL of a site-scoped v2 path (``/v2/api/site/{site}...``)."""
    return _CONSOLE.format(host_id=host_id) + f"/v2/api/site/{site_slug}{path}"


def v2_root(host_id: str, path: str) -> str:
    """Connector URL of a v2 path that carries no site segment (``/v2/api...``)."""
    return _CONSOLE.format(host_id=host_id) + f"/v2/api{path}"


async def resolve_site_slug(
    registry: Registry, host: str, site: str
) -> tuple[APIKeyConfig | None, str, str]:
    """``(key, host_id, site_slug)`` for a console + Network site (Classic and v2 paths)."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    site_slug = await registry.resolve_site_slug(site, host_id, key=key)
    return key, host_id, site_slug


def _classic_data(
    response: Any, path: str, *, client: UniFiClient | None = None, key: APIKeyConfig | None = None
) -> list[dict[str, Any]]:
    checked_classic_response(response, path, client=client, key=key)
    data = response.get("data") if isinstance(response, dict) else None
    if not isinstance(data, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected an object with a 'data' "
            f"array, got {describe_shape(response)}"
        )
    return _object_rows(data, path)


def _object_rows(items: list[Any], path: str) -> list[dict[str, Any]]:
    """Require every collection row to be an object before attempting resolution."""
    for index, row in enumerate(items):
        if not isinstance(row, dict):
            raise UniFiConnectionError(
                f"Unexpected response shape from GET {path}: row {index} expected an "
                f"object, got {describe_shape(row)}"
            )
    return items


async def networkconf_records(
    client: UniFiClient,
    host_id: str,
    site_slug: str,
    purpose: str,
    *,
    key: APIKeyConfig | None,
) -> list[dict[str, Any]]:
    """Every Classic networkconf record of one ``purpose`` (the Classic list is unpaged)."""
    path = classic_rest(host_id, site_slug, "/networkconf")
    records = _classic_data(await client.get(path, key=key), path, client=client, key=key)
    return of_purpose(records, purpose)


def of_purpose(records: list[dict[str, Any]], purpose: str) -> list[dict[str, Any]]:
    """The networkconf records whose purpose is purpose, verbatim and in order."""
    return [r for r in records if r.get("purpose") == purpose]


def select_classic_record(
    records: list[dict[str, Any]], wanted: str, kind: str, list_tool: str
) -> dict[str, Any]:
    """The record whose ``_id`` or ``external_id`` (the Integration id) is ``wanted``.

    An unknown id fails listing every record of this kind with both ids, never a silent
    first match.
    """
    match = find_by_id(records, wanted, "_id", "external_id")
    if match is not None:
        return match
    valid = (
        "; ".join(
            f"{upstream_error_value(r.get('name'))!r}: "
            f"id={upstream_error_value(r.get('external_id'))}, "
            f"_id={upstream_error_value(r.get('_id'))}"
            for r in records
        )
        or "(none)"
    )
    raise ValueError(
        f"{kind} {wanted!r} not found; valid: {valid}. Pass the id from {list_tool} "
        "(Integration id) or the Classic _id."
    )


async def resolve_networkconf(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    wanted: str,
    purpose: str,
    kind: str,
    list_tool: str,
    arg_name: str,
) -> tuple[APIKeyConfig | None, str, str, str]:
    """``(key, host_id, site_slug, classic _id)`` of one networkconf record of ``purpose``."""
    key, host_id, site_slug, record = await resolve_networkconf_record(
        client, registry, host, site, wanted, purpose, kind, list_tool, arg_name
    )
    return key, host_id, site_slug, listed_record_id(record, "_id")


async def resolve_networkconf_record(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    wanted: str,
    purpose: str,
    kind: str,
    list_tool: str,
    arg_name: str,
) -> tuple[APIKeyConfig | None, str, str, dict[str, Any]]:
    """``(key, host_id, site_slug, record)`` of one networkconf record of ``purpose``; the
    record's ``_id`` is validated as a URL path id (the write addresses ``record["_id"]``,
    the upstream spelling, never ``wanted``)."""
    validate_id(wanted, arg_name)
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    records = await networkconf_records(client, host_id, site_slug, purpose, key=key)
    record = select_classic_record(records, wanted, kind, list_tool)
    classic_id = listed_record_id(record, "_id")
    return key, host_id, site_slug, {**record, "_id": classic_id}


async def resolve_device_tag(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    tag: str,
) -> tuple[APIKeyConfig | None, str, str, str]:
    """``(key, host_id, site_slug, tag _id)`` for a v2 device tag given by ``_id`` or name."""
    key, host_id, site_slug, record = await resolve_device_tag_record(
        client, registry, host, site, tag
    )
    return key, host_id, site_slug, listed_record_id(record, "tag_id")


async def resolve_device_tag_record(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    tag: str,
) -> tuple[APIKeyConfig | None, str, str, dict[str, Any]]:
    """``(key, host_id, site_slug, tag record)`` for a v2 device tag given by ``_id`` or name.

    The v2 list is read first because the controller answers a PUT on an unknown tag with
    a bare HTTP 500 and a DELETE on an unknown tag with HTTP 200, so a wrong id would
    otherwise fail opaquely or report a deletion that never happened. An id or name that
    matches no tag, or a name that matches several, fails listing every tag.
    """
    # An id or an upstream NAME: a name may carry edge whitespace, so only an empty value
    # or a control character is refused (the name rule, not the selector rule).
    name_problem = name_reason(tag) if isinstance(tag, str) else "must be a string"
    if name_problem is not None:
        raise ValueError(f"'tag_id' {name_problem}")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    path = v2_site(host_id, site_slug, "/device-tags")
    body = await client.get(path, key=key)
    if not isinstance(body, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected a JSON array, got "
            f"{describe_shape(body)}"
        )
    tags = _object_rows(body, path)
    valid = (
        "; ".join(
            f"{upstream_error_value(t.get('name'), client)!r} "
            f"(_id={upstream_error_value(t.get('_id'), client)})"
            for t in tags
        )
        or "(none)"
    )
    # The _id (case-insensitive hex), else the name in the shared name tiers (exact, NFC +
    # casefold, stripped), so a tag named "Fiber - " is selected.
    by_id = [t for t in tags if same_id(tag, t.get("_id"))]
    matches = by_id or name_matches(tags, tag, lambda t: t.get("name"))
    identities: list[str] = []
    for candidate in matches:
        identity = listed_record_id(candidate, "tag_id")
        if not any(same_id(identity, existing) for existing in identities):
            identities.append(identity)
    if len(identities) > 1:
        raise ValueError(
            f"Device tag name {tag!r} matches {len(matches)} tags; pass the _id. Tags: {valid}."
        )
    if not matches:
        raise ValueError(f"Device tag {tag!r} not found by _id or name; tags: {valid}.")
    listed_record_id(matches[0], "tag_id")
    return key, host_id, site_slug, matches[0]


_TAG_DELTA = ("device_mac_additions", "device_mac_removals")


#: The documented update_device_tag body forms, for the hint on an upstream error.
DEVICE_TAG_UPDATE_HINT = (
    "update_device_tag takes either a native body with device_mac_additions and "
    "device_mac_removals (the controller answers a bare HTTP 500 without them), or an "
    "edited list_device_tags entry whose member_device_macs (a list of MACs) is turned "
    "into those two lists, not both forms at once."
)


def device_tag_update_hint(tag: Any) -> str | None:
    """The documented body forms when ``tag`` is not one of them (None when it is)."""
    if not isinstance(tag, dict):
        return DEVICE_TAG_UPDATE_HINT
    if "member_device_macs" in tag:
        desired = tag["member_device_macs"]
        well_formed = isinstance(desired, list) and all(isinstance(m, str) for m in desired)
        if well_formed and not any(k in tag for k in _TAG_DELTA):
            return None
        return DEVICE_TAG_UPDATE_HINT
    return None if all(k in tag for k in _TAG_DELTA) else DEVICE_TAG_UPDATE_HINT


def consumed_string_array(record: dict[str, Any], field: str) -> list[str]:
    """Validate an upstream array before using it to derive write state.

    An absent field represents an empty optional array; an explicit null or any
    non-string element is malformed and must never be coerced into write data.
    """
    value = record.get(field, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise UniFiConnectionError(
            f"Unexpected upstream response shape: {field!r} expected an array of "
            f"strings, got {describe_shape(value)}. Re-read the upstream record "
            "and correct its response shape before deriving a mutation."
        )
    return value


def device_tag_update_body(tag: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """The v2 PUT body for ``tag``: a native update body, or an edited list entry.

    The v2 PUT takes ``name``, ``device_mac_additions`` and ``device_mac_removals`` and
    answers HTTP 400 "Unrecognized field" for ``_id`` or ``member_device_macs`` (Network
    11.0.81, verified on a synthetic tag), so a list_device_tags entry cannot be sent back
    as is. An entry carrying ``member_device_macs`` (the desired members) is translated
    into additions and removals against ``current``; its ``_id`` is dropped (``tag_id``
    selects the tag, as for every update tool). A native body is sent verbatim.

    Each desired MAC is normalised to the controller's lowercase colon form, so
    ``AA-BB-CC-DD-EE-FF`` and ``aabbccddeeff`` compare equal to the stored
    ``aa:bb:cc:dd:ee:ff`` (no spurious addition/removal pair); an entry that is not a MAC
    is sent as given (the controller judges it). A body that is neither form (both forms
    at once, or a ``member_device_macs`` that is not a list of strings) is sent verbatim
    for the controller to judge, and an upstream error gets :data:`DEVICE_TAG_UPDATE_HINT`.
    """
    # Imported here: device_mgmt imports this module at load time.
    from ..families.devices.device_mgmt import _colon_mac, _is_mac

    if "member_device_macs" not in tag or device_tag_update_hint(tag) is not None:
        return tag
    desired = tag["member_device_macs"]
    want = [_colon_mac(m) if _is_mac(m) else m for m in desired]
    have = [
        _colon_mac(m) if _is_mac(m) else m.lower()
        for m in consumed_string_array(current, "member_device_macs")
    ]
    body = {k: v for k, v in tag.items() if k not in ("_id", "member_device_macs")}
    body["device_mac_additions"] = [m for m in dict.fromkeys(want) if m not in have]
    body["device_mac_removals"] = [m for m in dict.fromkeys(have) if m not in want]
    return body


def with_purpose(tool: str, body: dict[str, Any], purpose: str) -> dict[str, Any]:
    """The caller's networkconf ``body`` with ``purpose`` pinned to ``purpose``.

    The one purpose rule of the purpose-scoped networkconf writes (VPN servers,
    site-to-site tunnels, WAN interfaces): an absent or null ``purpose`` is replaced by the
    tool's purpose, so ``purpose: null`` is never forwarded; any other value is sent as
    given for the controller to judge, and an upstream error gets :func:`purpose_hint`.
    """
    given = body.get("purpose")
    return {**body, "purpose": purpose if given is None else given}


def purpose_hint(tool: str, body: Any, purpose: str) -> str | None:
    """The hint for an upstream error of a purpose-scoped write whose body names another
    purpose (None when it does not)."""
    given = body.get("purpose") if isinstance(body, dict) else None
    if given is None or given == purpose:
        return None
    return (
        f"{tool} writes networkconf records of purpose {purpose!r}; the body's purpose "
        f"{given!r} was sent as given. Omit purpose or pass {purpose!r}."
    )


def listed_record_id(
    record: dict[str, Any], arg_name: str, *, client: UniFiClient | None = None
) -> str:
    """The upstream ``_id`` of a record :func:`require_listed_record` returned, validated
    as a URL path id (named ``arg_name``): the id a write sends in its URL and body."""
    value = record.get("_id")
    identifying = {
        k: upstream_error_value(record[k], client)
        for k in ("_id", "id", "external_id", "name", "mac")
        if k in record
    }
    if not isinstance(value, str) or not value:
        raise ValueError(
            f"Selected record has invalid native _id {upstream_error_text(value, client)}; "
            "expected a non-empty "
            f"string for {arg_name}. Identifying fields: "
            f"{upstream_error_text(identifying, client)}. "
            "No write was sent."
        )
    try:
        validate_id(value, arg_name)
    except ValueError:
        raise ValueError(
            f"Invalid {arg_name!r} {upstream_error_value(value, client)!r}: "
            "expected alphanumeric, hyphens, and underscores only. Identifying fields: "
            f"{upstream_error_text(identifying, client)}. No write was sent."
        ) from None
    return value


def addressed_body(body: dict[str, Any], *upstream_ids: object) -> dict[str, Any]:
    """A Classic / v2 write ``body`` whose ``_id`` names the target in another spelling,
    re-spelt as the upstream id it names (the record's ``_id``, or another id of the same
    record such as a networkconf ``external_id``;
    :func:`~unifi_fabric.matching.with_upstream_id`)."""
    return with_upstream_id(body, "_id", *upstream_ids)


def _record_label(record: dict[str, Any], fields: tuple[str, ...]) -> Any:
    """The first non-empty of ``fields`` in ``record`` (shown verbatim), else None."""
    for name in fields:
        value = record.get(name)
        if value not in (None, ""):
            return value
    return None


async def require_listed_record(
    client: UniFiClient,
    list_path: str,
    wanted: str,
    *,
    key: APIKeyConfig | None,
    kind: str,
    list_tool: str,
    label_fields: tuple[str, ...] = ("name",),
    read_after: bool = False,
) -> dict[str, Any]:
    """The record whose ``_id`` is ``wanted`` in the collection at ``list_path``.

    The write-target check of every update and delete on a Classic REST or v2
    collection. The controller answers a DELETE on an unknown id with HTTP 200, so a
    deletion that never happened would be reported; the id is therefore resolved in its
    own list first, for updates as for deletes: an id that is not there fails listing
    every record of the collection (label and ``_id``), and no write is sent.
    ``list_path`` is the collection route; the body is either a Classic
    ``{meta, data: [...]}`` envelope or a v2 bare JSON array, and any other shape raises
    with the shape received. Non-object entries raise a shape error before resolution.
    The id is matched by :func:`~unifi_fabric.matching.same_id` (a hex id ignores
    case) and the upstream record is returned: the caller addresses the write with the
    record's ``_id`` (:func:`listed_record_id`), never with ``wanted``, so an upper-case
    hex id sends the upstream spelling.
    """
    body = checked_classic_response(
        await client.get(list_path, key=key), list_path, client=client, key=key
    )
    items = body.get("data") if isinstance(body, dict) else body
    if not isinstance(items, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {list_path}: expected an object with a "
            f"'data' array or a JSON array, got {describe_shape(body)}"
        )
    records = _object_rows(items, list_path)
    record = find_by_id(records, wanted, "_id")
    if record is not None:
        listed_record_id(record, "_id")
        return record
    valid = (
        "; ".join(
            f"{upstream_error_value(_record_label(r, label_fields), client)!r} "
            f"(_id={upstream_error_value(r.get('_id'), client)})"
            for r in records
        )
        or "(none)"
    )
    raise ValueError(
        f"{kind} {wanted!r} not found; valid: {valid}. Get ids from {list_tool} (_id). "
        + (
            "The write was sent; read-back could not find the record."
            if read_after
            else "No write was sent."
        )
    )
