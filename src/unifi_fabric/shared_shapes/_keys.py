"""Multi-key routing for org-scoped (cloud) tools.

A deployment may configure several API keys, one per organization. Tools that take no
console (Site Manager ISP metrics and SD-WAN, Mobility, Carrier Fabric) used to ride
the first key unless a ``key_label`` was passed, so another organization's data was
silently out of reach. These helpers make every such tool cover every configured key:

* :func:`fan_out` — run a read on every covered key (list/aggregate tools); a failing
  key is reported as a per-key error and the rest still return. Raises only when every
  key fails.
* :func:`merge_first_key` — merge the per-key lists of a multi-key read, de-duplicated
  by stable id: a record (or console) an earlier key in configuration order already
  returned is not repeated, and every count is taken over the merged list. One rule for
  every multi-key list tool.
* :func:`first_success` — run a lookup on every covered key and use the first key (in
  configuration order) that answers (get-by-id tools, and the read-before that tells a
  write which organization owns the object). Raises with every key's error when none
  answers.

With a ``key_label`` (or a single configured key) exactly one key is used and its
error propagates unchanged.

Every multi-key result reports its key coverage the same way (:func:`report_keys`):
``_key_labels`` lists the keys whose results are included (the answering keys, in
configuration order) and each key that failed appears under ``errors`` with its reason
(:func:`key_error`).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Hashable, Iterable
from typing import Any

from ..client import UniFiClient, gather_or_cancel, upstream_error_text
from ..config import APIKeyConfig
from ..matching import id_key


def key_scopes(
    client: UniFiClient, key_label: str | None
) -> list[tuple[str | None, APIKeyConfig | None]]:
    """The keys a call covers: the named key, else every configured key in a multi-key
    deployment, else the single default key (``(None, None)``)."""
    if key_label is not None:
        return [(key_label, client.get_key_by_label(key_label))]
    labels = client.list_key_labels()
    if len(labels) > 1:
        return [(label, client.get_key_by_label(label)) for label in labels]
    return [(None, None)]


async def fan_out[T](
    client: UniFiClient,
    key_label: str | None,
    fetch: Callable[[APIKeyConfig | None], Awaitable[T]],
) -> tuple[list[tuple[str | None, T]], list[str], bool]:
    """Run ``fetch`` on every covered key -> ``(results, per-key errors, multi)``."""
    return await fan_out_scopes(key_scopes(client, key_label), fetch)


async def fan_out_scopes[T](
    scopes: list[tuple[str | None, APIKeyConfig | None]],
    fetch: Callable[[APIKeyConfig | None], Awaitable[T]],
) -> tuple[list[tuple[str | None, T]], list[str], bool]:
    """:func:`fan_out` over an explicit list of ``(label, key)`` scopes.

    Used when the caller has already chosen the keys (for example the keys that own
    the consoles a query names). One scope: its error propagates unchanged. Several:
    the scopes run concurrently, a failing scope is a per-key error, and
    ``RuntimeError`` (with every key's error) is raised only when all fail.
    """
    if len(scopes) == 1:
        label, key = scopes[0]
        return [(label, await fetch(key))], [], False

    async def _one(label: str | None, key: APIKeyConfig | None) -> tuple[Any, str | None]:
        try:
            return await fetch(key), None
        except Exception as exc:
            return None, f"{label}: {exc}"

    outcomes = await gather_or_cancel(*[_one(label, key) for label, key in scopes])
    errors = [err for _value, err in outcomes if err]
    if len(errors) == len(scopes):
        raise RuntimeError(f"All {len(scopes)} API keys failed: {'; '.join(errors)}")
    results = [
        (label, value)
        for (label, _key), (value, err) in zip(scopes, outcomes, strict=True)
        if err is None
    ]
    return results, errors, True


async def first_success[T](
    client: UniFiClient,
    key_label: str | None,
    fetch: Callable[[APIKeyConfig | None], Awaitable[T]],
) -> tuple[APIKeyConfig | None, T]:
    """Run ``fetch`` on every covered key; return ``(key, result)`` of the first key (in
    configuration order) that succeeds."""
    scopes = key_scopes(client, key_label)
    if len(scopes) == 1:
        _label, key = scopes[0]
        return key, await fetch(key)

    async def _one(key: APIKeyConfig | None) -> tuple[Any, BaseException | None]:
        try:
            return await fetch(key), None
        except Exception as exc:
            return None, exc

    outcomes = await gather_or_cancel(*[_one(key) for _label, key in scopes])
    for (_label, key), (value, err) in zip(scopes, outcomes, strict=True):
        if err is None:
            return key, value
    detail = "; ".join(
        f"{label}: {err}" for (label, _key), (_value, err) in zip(scopes, outcomes, strict=True)
    )
    raise RuntimeError(f"No configured API key could serve this request ({detail})")


def page_mode_scope(
    client: UniFiClient, key_label: str | None, *, tool: str, paging: str
) -> tuple[str | None, APIKeyConfig | None]:
    """The ONE key a manual page is read on: ``(label, key)``.

    A paging cursor belongs to the listing of the key that issued it, so a page-mode call
    (``paging`` names the tool's paging arguments) never guesses a key: with ``key_label``
    that key is used; with one configured key, the default key; with several keys and no
    ``key_label`` the call fails before any request, listing the configured labels.
    """
    if key_label is not None:
        return key_label, client.get_key_by_label(key_label)
    labels = client.list_key_labels()
    if len(labels) > 1:
        raise ValueError(
            f"{tool}: {paging} reads one page of ONE key's listing (a cursor belongs to the "
            f"key that issued it) and {len(labels)} API keys are configured: pass key_label, "
            f"one of: {', '.join(labels)}. Omit {paging} to list every key's records."
        )
    return None, None


def key_error(label: str | None, reason: object) -> str:
    """One failed key's entry under ``errors``: ``"<label>: <reason>"``.

    An exception reason is rendered with :func:`upstream_error_text`, so a response
    body it carries has its credential fields masked under ``UNIFI_REDACT_SECRETS``.
    """
    text = upstream_error_text(reason) if isinstance(reason, BaseException) else reason
    return f"{label}: {text}"


def report_keys(
    result: dict[str, Any],
    answering: Iterable[str | None],
    key_errors: Iterable[Any],
    *,
    multi: bool,
) -> dict[str, Any]:
    """Add server key coverage in place without changing upstream fields."""
    context: dict[str, Any] = {}
    if multi:
        context["_key_labels"] = list(answering)
    failed = list(key_errors)
    if failed:
        context["errors"] = failed
    result.update(with_context(result, context))
    return result


class _ContextRecord(dict[str, Any]):
    """In-process server provenance; serialized fields remain upstream-preserving."""

    _server_context: dict[str, Any]
    #: The fields :func:`with_context` placed itself (absent from the upstream body).
    _server_placed: set[str]

    def __init__(self, record: dict[str, Any], context: dict[str, Any]) -> None:
        super().__init__(record)
        if isinstance(record, _ContextRecord):
            self._server_context = dict(record._server_context)
            self._server_placed = set(record._server_placed)
        else:
            self._server_context = {}
            self._server_placed = set()
        self._server_context.update(context)


def context_value(
    record: dict[str, Any], field: str, default: Any = None, *, strict: bool = False
) -> Any:
    """Read trusted server context for routing, falling back to an ordinary record.

    Every reader of a field the server added through :func:`with_context` uses this,
    never ``.get()`` / ``[]``: a colliding upstream value stays in the serialized field
    while the server's own value is kept in private provenance. ``strict`` is for fields
    that only :func:`with_context` ever adds: a context record whose provenance lacks
    the field then yields ``default`` instead of an upstream value of that name.
    """
    if isinstance(record, _ContextRecord):
        if field in record._server_context:
            return record._server_context[field]
        if strict:
            return default
    return record.get(field, default)


def with_context(record: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Add context without changing any upstream field, including collision buckets.

    Colliding server fields go in a fresh _wrapperFields bucket (numbered from 2
    when occupied). Earlier buckets and their values remain untouched on later merges.
    Routing provenance is retained privately and never appears in serialized fields.
    """
    merged = _ContextRecord(record, context)
    collisions = {}
    for field, value in context.items():
        if field not in record:
            merged[field] = value
            merged._server_placed.add(field)
        elif record[field] != value:
            collisions[field] = value
    if collisions:
        bucket = "_wrapperFields"
        suffix = 2
        while bucket in merged:
            bucket = f"_wrapperFields_{suffix}"
            suffix += 1
        merged[bucket] = collisions
    return merged


def update_context(record: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """:func:`with_context`, except that a field the server placed itself is replaced.

    For a server marker recomputed later in the call (``incomplete`` /
    ``incompleteReason`` gaining a second reason): the server's own earlier value is
    superseded, while an upstream field of the same name still keeps its value and the
    server's goes in the ``_wrapperFields`` bucket.
    """
    placed = record._server_placed if isinstance(record, _ContextRecord) else set()
    own = {field: value for field, value in context.items() if field in placed}
    merged = with_context(record, {k: v for k, v in context.items() if k not in own})
    merged.update(own)
    if isinstance(merged, _ContextRecord):
        merged._server_context.update(own)
    return merged


def without_server_fields(record: dict[str, Any], fields: Iterable[str]) -> dict[str, Any]:
    """``record`` without those of ``fields`` that :func:`with_context` placed itself.

    A multi-key merge recomputes its own ``_count`` / ``incomplete`` markers and keeps
    each key's other body fields under ``byKey``: an upstream field of the same name
    is upstream data and stays.
    """
    placed = record._server_placed if isinstance(record, _ContextRecord) else set()
    drop = set(fields) & placed
    return {k: v for k, v in record.items() if k not in drop}


def tag_items(items: list[Any], label: str | None, multi: bool) -> list[Any]:
    """Copy dict items with an additive ``_keyLabel`` when more than one key is covered
    (:func:`with_context` preserves an upstream key-label collision)."""
    if not multi:
        return list(items)
    return [
        with_context(item, {"_keyLabel": label}) if isinstance(item, dict) else item
        for item in items
    ]


def stable_id(*fields: str) -> Callable[[Any], Hashable | None]:
    """An identity function: the record's values of ``fields`` (all present), else None.

    Identity-designated fields use :func:`id_key` for hexadecimal ids; ordinary
    fields in a composite identity (for example ``metricType``) keep their spelling.
    A record without every field (or not an object) has no stable id and is never
    de-duplicated away. Upstream records are never rewritten.
    """

    def _identity(item: Any) -> Hashable | None:
        if not isinstance(item, dict):
            return None
        values = tuple(
            id_key(value)
            if field in {"id", "hostId", "siteId", "workspace_id"} and isinstance(value, str)
            else value
            for field in fields
            for value in [item.get(field)]
        )
        if any(v is None or v == "" or not isinstance(v, Hashable) for v in values):
            return None
        return values

    return _identity


def first_id(*identities: Callable[[Any], Hashable | None]) -> Callable[[Any], Hashable | None]:
    """An identity function trying each of ``identities`` in turn (the first that yields
    an id wins), so a record keyed by another field than the usual one is still matched."""

    def _identity(item: Any) -> Hashable | None:
        for identity in identities:
            found = identity(item)
            if found is not None:
                return found
        return None

    return _identity


def merge_first_key(
    results: Iterable[tuple[str | None, list[Any]]],
    identity: Callable[[Any], Hashable | None],
    *,
    multi: bool,
) -> list[Any]:
    """Merge per-key record lists, de-duplicated by stable id, first key wins.

    ``results`` are ``(label, records)`` in configuration order (as :func:`fan_out`
    returns them). A record whose ``identity`` an EARLIER key already returned is
    dropped, so an object (or a console, for an identity that names the console) visible
    to several keys is listed once, under the first key in configuration order; a key's
    own records are never de-duplicated against each other. Records with no identity
    are always kept. With ``multi`` each kept object record carries an additive
    ``_keyLabel``. A count over the result is a count of the de-duplicated set.
    """
    merged: list[Any] = []
    claimed: set[Hashable] = set()
    for label, records in results:
        own: set[Hashable] = set()
        for record in records:
            ident = identity(record)
            # A scalar string identity returned by a custom helper designates an id
            # too (for example aggregation._device_host). Composite identities are
            # normalized by stable_id field by field so names retain their case.
            if isinstance(ident, str):
                ident = id_key(ident)
            if ident is not None:
                if ident in claimed:
                    continue
                own.add(ident)
            merged.extend(tag_items([record], label, multi))
        claimed |= own
    return merged
