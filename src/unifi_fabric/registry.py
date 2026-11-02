"""Lazy-load host/site registry with per-key TTL-based caching for MSP multi-console support."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from collections.abc import AsyncIterator, Callable
from typing import TYPE_CHECKING, Any

from cachetools import TTLCache

from .client import (
    PaginationAbortedError,
    ResponseShapeError,
    gather_or_cancel,
    nullable_object_records,
    object_records,
    upstream_error_text,
    validate_host_id,
    wrong_type_error,
)
from .macs import is_mac, record_mac
from .matching import id_key, name_keys, same_id, tiered_name_matches
from .selector_args import check_selector

if TYPE_CHECKING:
    from .client import UniFiClient
    from .config import APIKeyConfig

#: Fallback label when no key is configured; configured default requests use the
#: first configured label, exactly like UniFiClient.request.
_DEFAULT_LABEL: None = None
_logger = logging.getLogger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z",
    re.IGNORECASE,
)

_PROXY_SITES_PATH = "/v1/connector/consoles/{host_id}/proxy/network/integration/v1/sites"


def _all_objects(items: Any) -> bool:
    return isinstance(items, list) and all(isinstance(item, dict) for item in items)


def _assert_uuid(site_id: str) -> None:
    """Raise ValueError if site_id is not a valid UUID.

    Called at every proxy URL construction site as defense-in-depth so that
    ObjectId values from the Site Manager sites list (/v1/sites, formerly
    /ea/sites) can never slip into a proxy endpoint URL. The Site Manager
    siteId is a Fabric ObjectId on BOTH /ea and /v1 (live-verified); the
    UUID comes only from the per-console connector proxy /sites endpoint.
    """
    if not isinstance(site_id, str):
        raise wrong_type_error("site_id", site_id)
    if not _UUID_RE.match(site_id):
        raise ValueError(
            f"site_id {site_id!r} is not a UUID — proxy endpoints require UUID site IDs. "
            "Pass the site name or UUID as returned by the console's /sites endpoint."
        )


def ea_site_labels(site: dict[str, Any]) -> list[str]:
    """Return the human-readable labels for a Site Manager ``/v1/sites`` object.

    The Site Manager sites list nests the site name under ``meta.name`` and its
    description under ``meta.desc`` (live-verified field shape); it has NO
    top-level ``siteName``/``description``. Both meta fields are returned, plus
    any legacy top-level ``siteName``/``description``/``name`` as defensive
    fallbacks, so matching and "valid:" lists tolerate firmware variation.
    """
    meta = site.get("meta")
    if meta is None:
        meta = {}
    elif not isinstance(meta, dict):
        raise wrong_type_error(
            f"meta of site {site.get('siteId')!r}", meta, "an object ({name, desc})"
        )
    labels: list[str] = []
    for val in (
        meta.get("name"),
        meta.get("desc"),
        site.get("siteName"),
        site.get("description"),
        site.get("name"),
    ):
        if isinstance(val, str) and val:
            labels.append(val)
    return labels


class FetchedRecords(list[dict[str, Any]]):
    """A list the registry fetched, carrying why its drain stopped short.

    The incomplete state of a capped / stalled list lives WITH the list for the whole
    resolution that uses it: it is never a separate TTL marker, which a
    ``UNIFI_CACHE_TTL_SECONDS=0`` deployment expires before the name refusal reads it.
    """

    incomplete_reason: str | None = None

    def __init__(self, items: Any = (), incomplete_reason: str | None = None) -> None:
        super().__init__(items)
        self.incomplete_reason = incomplete_reason


def incomplete_reason(records: Any) -> str | None:
    """Why the registry list ``records`` stopped short, or ``None`` when it is complete."""
    reason = getattr(records, "incomplete_reason", None)
    return reason if isinstance(reason, str) and reason else None


def filter_records(records: Any, keep: Callable[[Any], bool]) -> FetchedRecords:
    """The items of ``records`` that ``keep`` accepts, as a :class:`FetchedRecords` that
    carries the source list's incomplete reason.

    The ONE way a registry list is narrowed: a comprehension or ``list(...)`` over a
    fetched list returns a plain list and drops the incomplete state, after which a name
    match on a capped list would be trusted. A lint in
    ``tests/test_core_strict_readers_and_name_tiers.py`` refuses such a comprehension over
    a registry list anywhere in the package.
    """
    return FetchedRecords((item for item in records if keep(item)), incomplete_reason(records))


def fetched(records: Any) -> FetchedRecords:
    """``records`` as a :class:`FetchedRecords` (the same object when it already is one)."""
    if isinstance(records, FetchedRecords):
        return records
    return FetchedRecords(records, incomplete_reason(records))


def _text(value: Any) -> str:
    """A host field as text: ``None`` / non-strings (e.g. a null reportedState.name) -> ''."""
    return value if isinstance(value, str) else ""


def _require_native_id(record: dict[str, Any], *fields: str) -> str:
    """A selected record must carry its upstream identity, never an invented target."""
    for field in fields:
        value = record.get(field)
        if isinstance(value, str) and value:
            return value
    identifying = {
        key: record[key]
        for key in (
            "id",
            "_id",
            "siteId",
            "name",
            "description",
            "meta",
            "reportedState",
            "mac",
            "hostId",
        )
        if key in record
    }
    raise ResponseShapeError(
        f"Selected record has no non-empty string native id ({', '.join(fields)}): "
        f"{upstream_error_text(identifying)}"
    )


def _host_labels(host: dict[str, Any]) -> tuple[str, str, str, str]:
    """(id, reportedState.hostname, top-level name, reportedState.name) as text."""
    reported = host.get("reportedState")
    reported = reported if isinstance(reported, dict) else {}
    return (
        _text(host.get("id")),
        _text(reported.get("hostname")),
        _text(host.get("name")),
        _text(reported.get("name")),
    )


def _describe_host(host: dict[str, Any]) -> str:
    host_id, hostname, name, display = _host_labels(host)
    parts = [f"id={host_id}"]
    if hostname:
        parts.append(f"hostname={hostname}")
    if display:
        parts.append(f"name={display}")
    elif name:
        parts.append(f"name={name}")
    return " ".join(parts)


def _host_name_groups(host: dict[str, Any]) -> list[list[str]]:
    _host_id, hostname, name, display = _host_labels(host)
    return [[hostname, name], [display]]


def _collapsed_host_name_groups(host: dict[str, Any]) -> list[list[str]]:
    """Host labels with internal whitespace collapsed for the final name fallback."""
    return [[re.sub(r"\s+", " ", label) for label in group] for group in _host_name_groups(host)]


def _host_mac_values(host: dict[str, Any]) -> list[str]:
    """Canonical MACs reported for a console, including those its composite id carries.

    A console id is ``<hex>:<number>``. When the hex part is exactly 12 digits it is the
    MAC; a longer hex part (a 30- or 64-digit id) starts with the MAC, so its first 12
    characters are read as one too. A console that reports no MAC in ``reportedState``
    is still found by the MAC its id carries.
    """
    reported = host.get("reportedState")
    reported = reported if isinstance(reported, dict) else {}
    hardware = reported.get("hardware")
    hardware = hardware if isinstance(hardware, dict) else {}
    host_id = _text(host.get("id"))
    composite_prefix = host_id.split(":", 1)[0]
    leading = host_id[:12]
    values: list[str] = []
    for value in (reported.get("mac"), hardware.get("mac"), composite_prefix, leading):
        mac = record_mac(value)
        if mac is not None and mac not in values:
            values.append(mac)
    return values


def match_host(hosts: list[dict[str, Any]], name_or_id: str) -> tuple[int, dict[str, Any]] | None:
    """Find the console ``name_or_id`` refers to, as ``(tier, host)``; ``None`` if none.

    Tier 0 is the host ``id`` (a hex console id matched case-insensitively,
    :func:`~unifi_fabric.matching.same_id`). The name tiers follow (the first tier with
    any match wins): exact, then NFC + casefold, then surrounding whitespace stripped
    (case kept, then casefolded) -- each tried on ``reportedState.hostname`` / top-level
    ``name`` before ``reportedState.name`` (the display name list_hosts shows), so an
    upstream console named ``"Lab  "`` is selected by ``Lab``. Missing or null fields
    never match and never raise. If more than one DISTINCT console matches in the winning
    tier the name is ambiguous: ``ValueError`` lists the matching consoles' ids, hostnames
    and names so the caller can pass the id instead.
    """
    dict_hosts = object_records(hosts, "host resolution")
    by_id: dict[str, dict[str, Any]] = {}
    for host in dict_hosts:
        if same_id(name_or_id, host.get("id")):
            by_id.setdefault(id_key(_text(host.get("id"))), host)
    tier, found = (0, list(by_id.values())) if by_id else (-1, [])
    if not found:
        name_tier, found = tiered_name_matches(dict_hosts, name_or_id, _host_name_groups)
        tier = name_tier + 1
    if not found:
        # Console names alone accept a visually equivalent internal-space spelling.
        collapsed = re.sub(r"\s+", " ", name_or_id)
        name_tier, found = tiered_name_matches(dict_hosts, collapsed, _collapsed_host_name_groups)
        tier = name_tier + 1
    if not found and is_mac(name_or_id):
        wanted_mac = record_mac(name_or_id)
        found = [host for host in dict_hosts if wanted_mac in _host_mac_values(host)]
        tier = 99
    distinct: dict[str, dict[str, Any]] = {}
    for host in found:
        distinct.setdefault(id_key(_require_native_id(host, "id")), host)
    if len(distinct) > 1:
        choices = "; ".join(_describe_host(h) for h in distinct.values())
        raise ValueError(
            f"ambiguous host {name_or_id!r}: it matches {len(distinct)} consoles "
            f"({choices}). Pass the console id instead."
        )
    if distinct:
        return tier, next(iter(distinct.values()))
    return None


def distinct_labels(labels: Any) -> list[str]:
    """The non-empty labels in order, once per selector they stand for.

    Names match case-insensitively (:func:`matching.name_keys`), so "Default" and
    "default" are one choice in a "valid:" list: the first spelling is kept.
    """
    seen: dict[str, str] = {}
    for label in labels:
        if isinstance(label, str) and label:
            seen.setdefault(name_keys(label)[3], label)
    return list(seen.values())


def valid_host_choices(hosts: list[dict[str, Any]]) -> str:
    """Every console as 'hostname (name, id)' for an unknown-host error."""
    out = []
    for host in hosts:
        if isinstance(host, dict):
            host_id, hostname, name, display = _host_labels(host)
            label = hostname or display or name or host_id
            extras = distinct_labels((label, display or name, host_id))[1:]
            out.append(f"{label} ({', '.join(extras)})" if extras else label)
    return ", ".join(out) if out else "(no consoles visible to the configured API key(s))"


def _proxy_site_id(site: dict[str, Any]) -> str:
    return _text(site.get("id")) or _text(site.get("_id"))


def _proxy_site_label(site: dict[str, Any]) -> str:
    """The label a site is shown by: its description, else its name."""
    return _text(site.get("description")) or _text(site.get("name"))


def _proxy_site_labels(site: dict[str, Any]) -> list[list[str]]:
    """Every label a console site answers to, as ONE name group: its ``description``
    AND its ``name``. A site that carries both (``description="Office"``,
    ``name="Office LAN"``) resolves by either; one alias never hides the other."""
    return [[_text(site.get("description")), _text(site.get("name"))]]


def _match_proxy_site(sites: list[dict[str, Any]], name_or_id: str) -> dict[str, Any] | None:
    """The console site ``name_or_id`` refers to: the id first (a UUID matched
    case-insensitively), then the labels -- ``description`` and ``name``, both checked,
    so a site carrying both resolves by either -- in the name tiers of
    :mod:`unifi_fabric.matching` (exact, NFC + casefold, stripped). Two DIFFERENT sites
    matching in the winning tier (through either label) raise ``ValueError`` listing
    them (name, id) instead of silently taking the first."""
    dict_sites = object_records(sites, "proxy site resolution")
    for site in dict_sites:
        if same_id(name_or_id, _proxy_site_id(site)):
            return site
    found: dict[str, dict[str, Any]] = {}
    for site in tiered_name_matches(dict_sites, name_or_id, _proxy_site_labels)[1]:
        found.setdefault(id_key(_require_native_id(site, "id", "_id")), site)
    # Site Manager keeps the stable Network slug in internalReference. Labels win.
    if not found:
        for site in tiered_name_matches(
            dict_sites, name_or_id, lambda item: [[_text(item.get("internalReference"))]]
        )[1]:
            found.setdefault(id_key(_require_native_id(site, "id", "_id")), site)
    if len(found) > 1:
        choices = "; ".join(f"{_proxy_site_label(s)} ({sid})" for sid, s in found.items())
        raise ValueError(
            f"ambiguous site {name_or_id!r}: {len(found)} sites share that name "
            f"({choices}). Pass the site id instead."
        )
    return next(iter(found.values()), None)


def _valid_site_choices(sites: list[dict[str, Any]]) -> str:
    """Every site on a console as 'label (id)' for a site-not-found error."""
    out = []
    for site in sites:
        if not isinstance(site, dict):
            continue
        # Both aliases a site resolves by (description and name), once each (case-folded).
        label = " / ".join(distinct_labels(_proxy_site_labels(site)[0]))
        site_id = _text(site.get("id")) or _text(site.get("_id"))
        out.append(f"{label} ({site_id})" if label and site_id else (label or site_id))
    return ", ".join(x for x in out if x) or "(no sites on this console)"


class PartialListingError(ValueError):
    """A selector refused only because the list it was matched against is incomplete.

    The list drain stopped short (an opt-in page cap or an aborted drain), so the selector
    may be valid past the end. This is a listing problem of that key, not an invalid
    selector: a multi-key caller scopes it to the key instead of failing every key.
    """


def incomplete_name_error(
    name: str, what: str, reasons: list[str], max_pages: Any, id_hint: str
) -> ValueError:
    """The error for a NAME matched against an incomplete (capped / stalled) list.

    A partial list can hide a second object with the same name past the cap, so a name
    match there is never trusted (it would silently pick the first); only an exact id
    resolves. ``what`` is ``site`` / ``host`` / ``console``.
    """
    cap = (
        f"UNIFI_PAGINATE_MAX_PAGES={max_pages}"
        if isinstance(max_pages, int) and not isinstance(max_pages, bool)
        else "the list drain stopped short"
    )
    detail = "; ".join(r for r in reasons if r)
    return PartialListingError(
        f"cannot resolve {name!r} unambiguously: the {what} list is incomplete ({cap}), "
        f"so another {what} with that name may exist past the cap. Pass the exact "
        f"{id_hint} instead" + (f" ({detail})." if detail else ".")
    )


def _ea_site_id(site: dict[str, Any]) -> str:
    return _text(site.get("siteId")) or _text(site.get("id"))


def match_ea_site(
    sites: list[dict[str, Any]],
    name_or_id: str,
    *,
    partial: list[str],
    max_pages: Any,
    failures: list[str] | None = None,
) -> dict[str, Any]:
    """The ONE Site Manager site matcher, shared by every resolver.

    An exact ``siteId`` resolves even when the list is incomplete (an id is unique, so a
    capped list cannot hide a second match); a NAME (``meta.name`` / ``meta.desc``,
    case-insensitive) matching several sites is ambiguous, and a name matched on an
    incomplete list (``partial`` holds why) is refused, as a twin may lie past the cap.
    No match raises listing the valid names, any key that failed to list its sites
    (``failures``) and why the list is incomplete.
    """
    object_records(sites, "Site Manager site resolution")
    partial_note = (
        f" (the Site Manager site list is incomplete: {'; '.join(partial)})" if partial else ""
    )
    for site in sites:
        if same_id(name_or_id, _ea_site_id(site)):
            return site
    # One malformed record (meta that is not an object) is skipped and reported, never
    # the failure of every other site's resolution.
    labels: dict[int, list[str]] = {}
    malformed: list[str] = []
    for index, site in enumerate(sites):
        try:
            labels[index] = ea_site_labels(site)
        except ValueError as exc:
            labels[index] = []
            malformed.append(f"skipped site {_ea_site_id(site) or index!r}: {exc}")
    indexed = list(enumerate(sites))
    _tier, matched = tiered_name_matches(indexed, name_or_id, lambda pair: [labels[pair[0]]])
    named: dict[str, tuple[int, dict[str, Any]]] = {}
    for index, site in matched:
        named.setdefault(id_key(_require_native_id(site, "siteId", "id")), (index, site))
    if len(named) > 1:
        choices = "; ".join(
            f"{(labels[i] or [sid])[0]} (siteId={sid}, hostId={_text(st.get('hostId'))})"
            for sid, (i, st) in named.items()
        )
        raise ValueError(
            f"ambiguous site {name_or_id!r}: {len(named)} sites share that name "
            f"({choices}). Pass the siteId instead (or scope it to one console).{partial_note}"
        )
    if named:
        if partial:
            raise incomplete_name_error(
                name_or_id, "site", partial, max_pages, "siteId (list_sites)"
            )
        return next(iter(named.values()))[1]
    valid_names = distinct_labels(sorted({label for found in labels.values() for label in found}))
    failed = "".join(f"; {e}" for e in [*(failures or []), *malformed])
    raise (PartialListingError if partial else ValueError)(
        f"Site {name_or_id!r} not found; valid: {', '.join(valid_names) or '(none)'}"
        f"{failed}{partial_note}"
    )


class _LockEntry:
    """One cache entry's lock and the number of tasks holding or waiting for it."""

    __slots__ = ("lock", "users")

    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.users = 0


class Registry:
    """Caches host and site mappings per API key with configurable TTL and bounded size.

    Each API key label gets its own independent cache so that MSP deployments
    with multiple keys (each seeing different consoles) return correct data.

    _sites uses a (label, host_id) tuple key because proxy site lists are
    per-console; _ea_sites uses a plain label key for the MSP /v1/sites list.

    All three caches are backed by cachetools.TTLCache which enforces both a
    maximum size (LRU eviction when full) and a per-entry TTL.
    """

    def __init__(
        self,
        client: UniFiClient,
        ttl_seconds: int = 900,
        cache_max_hosts: int = 512,
        cache_max_sites: int = 2048,
    ) -> None:
        self._client = client
        self._ttl = ttl_seconds
        self._hosts: TTLCache[str | None, list[dict[str, Any]]] = TTLCache(
            maxsize=cache_max_hosts, ttl=ttl_seconds
        )
        self._sites: TTLCache[tuple[str | None, str], list[dict[str, Any]]] = TTLCache(
            maxsize=cache_max_sites, ttl=ttl_seconds
        )
        self._ea_sites: TTLCache[str | None, list[dict[str, Any]]] = TTLCache(
            maxsize=cache_max_hosts, ttl=ttl_seconds
        )
        # One lock per cache entry: (cache, key label[, console id]). A console's site list
        # is fetched under its own (label, host) lock, so different consoles' site lists on
        # one key fetch concurrently while one console's list is still fetched once.
        # The caches are independent, so no lock guards two of them. An entry lives only
        # while a task holds or waits for it (_entry_lock): the map never grows with the
        # number of consoles ever seen.
        self._locks: dict[tuple[str, str | None, str], _LockEntry] = {}
        # Per-cache eviction pressure warning flags (sticky, re-armed below 50%)
        self._hosts_full_warned = False
        self._sites_full_warned = False
        self._ea_sites_full_warned = False

    def _key_label(self, key: APIKeyConfig | None) -> str | None:
        if key is not None:
            return key.label
        labels = self._client.list_key_labels()
        return labels[0] if labels else _DEFAULT_LABEL

    def _check_cache_pressure(self, cache: TTLCache, name: str, warned_attr: str) -> None:
        """Log WARNING once when cache first fills; log INFO when pressure drops below 50%."""
        if len(cache) >= cache.maxsize:
            if not getattr(self, warned_attr):
                setattr(self, warned_attr, True)
                _logger.warning(
                    "Registry %s cache is full (size=%d, maxsize=%d); LRU eviction in effect",
                    name,
                    len(cache),
                    cache.maxsize,
                )
        elif getattr(self, warned_attr) and len(cache) < cache.maxsize // 2:
            setattr(self, warned_attr, False)
            _logger.info(
                "Registry %s cache pressure relieved (size=%d, maxsize=%d)",
                name,
                len(cache),
                cache.maxsize,
            )

    @contextlib.asynccontextmanager
    async def _entry_lock(
        self, cache: str, label: str | None, host_id: str = ""
    ) -> AsyncIterator[None]:
        """Hold the lock of one cache entry; the lock is reclaimed when it goes idle.

        The entry counts the tasks holding or waiting for it. The count is changed only
        synchronously (no await between the lookup and the increment, nor between the
        decrement and the removal), so on the one event loop an entry is removed only when
        no task holds it or waits on it: the next caller creates a fresh lock, and two
        tasks can never hold different locks for one entry at once.
        """
        lock_key = (cache, label, host_id)
        entry = self._locks.get(lock_key)
        if entry is None:
            entry = self._locks[lock_key] = _LockEntry()
        entry.users += 1
        try:
            async with entry.lock:
                yield
        finally:
            entry.users -= 1
            if entry.users == 0 and self._locks.get(lock_key) is entry:
                del self._locks[lock_key]

    async def get_hosts(self, *, key: APIKeyConfig | None = None) -> FetchedRecords:
        label = self._key_label(key)
        async with self._entry_lock("hosts", label):
            cached = self._hosts.get(label)
            if cached is None:
                self._check_cache_pressure(self._hosts, "hosts", "_hosts_full_warned")
                try:
                    hosts = await self._client.paginate("/v1/hosts", key=key)
                except PaginationAbortedError as exc:
                    # A capped/stalled list is used for this call only, never cached
                    # (same policy as the per-console site list); it carries its reason.
                    return FetchedRecords(object_records(exc.items, "GET /v1/hosts"), exc.reason)
                cached = object_records(hosts, "GET /v1/hosts")
                # Returned from the local, never re-read from the cache: with
                # UNIFI_CACHE_TTL_SECONDS=0 the entry is already expired.
                self._hosts[label] = cached
            return fetched(cached)

    async def get_ea_sites(self, *, key: APIKeyConfig | None = None) -> FetchedRecords:
        """Return sites from the MSP Site Manager `/v1/sites` endpoint (for enumeration/display)."""
        label = self._key_label(key)
        async with self._entry_lock("ea_sites", label):
            cached = self._ea_sites.get(label)
            if cached is None:
                self._check_cache_pressure(self._ea_sites, "ea_sites", "_ea_sites_full_warned")
                try:
                    sites = await self._client.paginate("/v1/sites", key=key)
                except PaginationAbortedError as exc:
                    # A capped/stalled list is used for this call only, never cached
                    # (same policy as the per-console site list); it carries its reason.
                    return FetchedRecords(
                        [
                            site
                            for site in nullable_object_records(exc.items, "GET /v1/sites")
                            if site is not None
                        ],
                        exc.reason,
                    )
                # Null placeholders are spec-legal but cannot identify a site in the
                # routing cache. List tools retain them verbatim in their raw results.
                cached = [
                    site
                    for site in nullable_object_records(sites, "GET /v1/sites")
                    if site is not None
                ]
                self._ea_sites[label] = cached
            return fetched(cached)

    async def get_sites(self, host_id: str, *, key: APIKeyConfig | None = None) -> FetchedRecords:
        """Return sites from the per-console proxy endpoint.

        Items have ``id`` (UUID) and ``description`` fields.  This is the
        authoritative source for site IDs used in proxy endpoint URLs.

        The proxy sites endpoint is offset-paginated (verified live: it returns an
        ``{offset, limit, count, totalCount, data}`` envelope with a native default
        page size of only 25), so all pages are drained here. Fetching only page one
        would silently hide sites past the first page and break site-name resolution
        for consoles with many local sites. If a drain is capped, the sites gathered
        so far are returned for this call only (a partial list still resolves the exact
        site ids it contains; a name is refused) and never cached; the returned list is
        then a :class:`FetchedRecords` whose :func:`incomplete_reason` says why.
        """
        label = self._key_label(key)
        cache_key = (label, host_id)
        async with self._entry_lock("sites", label, host_id):
            cached = self._sites.get(cache_key)
            if cached is None:
                self._check_cache_pressure(self._sites, "sites", "_sites_full_warned")
                path = _PROXY_SITES_PATH.format(host_id=host_id)
                try:
                    sites = list(await self._client.paginate_offset(path, key=key))
                except PaginationAbortedError as exc:
                    # A capped/stalled list is used for this call only — never cached,
                    # so the next call fetches again instead of resolving against a
                    # partial list for the whole TTL. The list carries its reason.
                    return FetchedRecords(object_records(exc.items, f"GET {path}"), exc.reason)
                cached = object_records(sites, f"GET {path}")
                self._sites[cache_key] = cached
            return fetched(cached)

    def _max_pages(self) -> Any:
        return getattr(self._client, "paginate_max_pages", None)

    @staticmethod
    def _note(what: str, records: Any) -> str:
        reason = incomplete_reason(records)
        return f" (the {what} list is incomplete: {reason})" if reason else ""

    async def resolve_key_for_host(self, name_or_id: str) -> APIKeyConfig | None:
        """Find which configured API key's host list contains the given host.

        MSP deployments configure one API key per customer/org (see
        ``Settings.get_key_configs``); each key's ``/v1/hosts`` list only
        contains the consoles that key can see. Per-host tools must resolve
        against the key that actually owns the host, not just the first
        configured key — otherwise every host belonging to a non-first key
        fails with "403 forbidden: host not found" even though the host exists
        and the caller's key is valid (see public issue https://github.com/swkstudios/unifi-fabric-mcp-server/issues/19).

        Matching is identical to :meth:`resolve_host_id` (:func:`match_host`): exact id,
        then ``reportedState.hostname`` / top-level ``name``, then ``reportedState.name``
        (all case-insensitive). If different consoles behind different keys match the same
        name in the winning tier, ``ValueError`` lists them (pass the id instead).
        A name match is refused if any key could not enumerate its consoles or
        stopped at the page cap: an unseen console may share that name. This
        includes a sibling key when one key matched the name. An exact id still
        resolves against an answering key even if a sibling failed or was capped.
        Returns the matching key config. When NO configured key sees the host it raises
        ``ValueError`` listing every console across all keys (and any key that failed to
        list its consoles), instead of falling back to the default key.

        Single-key deployments (the common case) short-circuit immediately:
        there is nothing to disambiguate, so ``None`` is returned without any
        extra API calls. For multi-key deployments the per-key host lists are
        served from the registry's existing TTL cache (:meth:`get_hosts`), so
        repeated per-host tool calls do not re-fetch every key's hosts on every
        call. The keys are queried concurrently via
        :func:`~unifi_fabric.client.gather_or_cancel` (no key query outlives the
        call) and each key's failure is isolated: a single failing/unauthorized key does
        not abort resolution; a ``RuntimeError`` is raised only if *every*
        configured key fails to list its hosts.
        """
        check_selector("host", name_or_id)
        labels = self._client.list_key_labels()
        if len(labels) <= 1:
            return None

        hosts_by_label: dict[str, list[dict[str, Any]]] = {}

        async def _fetch(label: str) -> tuple[str, Exception | None]:
            key_config = self._client.get_key_by_label(label)
            try:
                hosts = await self.get_hosts(key=key_config)
            except Exception as exc:
                return label, exc
            hosts_by_label[label] = hosts
            return label, None

        results = await gather_or_cancel(*[_fetch(label) for label in labels])

        errors = [(label, exc) for label, exc in results if exc is not None]
        if len(errors) == len(labels):
            raise RuntimeError(
                f"Could not resolve host {name_or_id!r}: all {len(labels)} configured "
                "API keys failed to list hosts: "
                + "; ".join(f"{label}: {exc}" for label, exc in errors)
            )

        # Select the globally best tier BEFORE ambiguity is evaluated: a looser
        # ambiguous name on one key must not hide a better match on another.
        all_hosts = [h for label in labels for h in hosts_by_label.get(label, [])]
        match = match_host(all_hosts, name_or_id)
        if match is None:
            # Fail fast listing every console visible to ANY key — falling back to the
            # default key would report only that key's consoles as the valid choices.
            failed = "".join(
                f"; API key {label!r} could not list its consoles: {exc}" for label, exc in errors
            )
            # A key whose console list stopped short (opt-in page cap) may own the host
            # past the cap: say so per key, so the choices are not read as complete.
            partial = "".join(
                f"; API key {label!r}{note}"
                for label in labels
                if label in hosts_by_label
                and (note := self._note("console", hosts_by_label[label]))
            )
            raise ValueError(
                f"unknown host {name_or_id!r}; valid (all API keys): "
                f"{valid_host_choices(all_hosts)}{failed}{partial}"
            )
        if match[0] > 0:
            # A name (not an exact id): any key whose console list stopped short may hold
            # another console with that name past the cap, so the match is not trusted.
            capped = [
                f"API key {label!r}: {reason}"
                for label in labels
                if label in hosts_by_label and (reason := incomplete_reason(hosts_by_label[label]))
            ]
            failed_lists = [
                f"API key {label!r} could not list its consoles: {exc}" for label, exc in errors
            ]
            if capped or failed_lists:
                raise incomplete_name_error(
                    name_or_id,
                    "host",
                    capped + failed_lists,
                    self._max_pages(),
                    "console id (list_hosts)",
                )
        # The same console can be visible through several keys and hex-id
        # spellings; its first configured key owns the request deterministically.
        matched_id = _text(match[1].get("id"))
        for label in labels:
            if any(
                host is match[1] or same_id(matched_id, host.get("id"))
                for host in hosts_by_label.get(label, [])
            ):
                return self._client.get_key_by_label(label)
        return None

    async def resolve_host_id(self, name_or_id: str, *, key: APIKeyConfig | None = None) -> str:
        """Resolve a host name or ID to a host ID.

        Matches, in order: the exact host ``id``; ``reportedState.hostname`` or top-level
        ``name`` (case-insensitive); then ``reportedState.name`` (case-insensitive).

        Raises ValueError if the resolved host ID contains characters unsafe for use
        in an API URL path segment, or if *name_or_id* matches no known host
        (fail fast on an unknown host rather than passing it upstream raw).
        """
        check_selector("host", name_or_id)
        hosts = await self.get_hosts(key=key)
        match = match_host(hosts, name_or_id)
        if match is not None and match[0] > 0:
            reason = incomplete_reason(hosts)
            if reason:
                raise incomplete_name_error(
                    name_or_id, "host", [reason], self._max_pages(), "console id (list_hosts)"
                )
        if match is not None:
            resolved = _text(match[1].get("id"))
            validate_host_id(resolved, "host_id")
            from .audit import set_audit_resolution

            set_audit_resolution(host=resolved)
            return resolved
        # No match: fail fast rather than passing an unrecognised string through to the
        # upstream API. Input is validated here, *before* any upstream call, and upstream
        # responses are never rewritten. The valid list is built at runtime from the
        # fetched consoles — no hostnames are hardcoded.
        raise (PartialListingError if incomplete_reason(hosts) else ValueError)(
            f"unknown host {name_or_id!r}; valid: {valid_host_choices(hosts)}"
            f"{self._note('console', hosts)}"
        )

    def _refuse_name_on_partial_sites(
        self, site: dict[str, Any] | None, name_or_id: str, sites: list[dict[str, Any]]
    ) -> None:
        """Raise when ``site`` matched by NAME on a console site list that is incomplete."""
        if site is None or same_id(name_or_id, _proxy_site_id(site)):
            return
        reason = incomplete_reason(sites)
        if reason:
            raise incomplete_name_error(
                name_or_id, "site", [reason], self._max_pages(), "site id (UUID)"
            )

    async def resolve_site_id(
        self, name_or_id: str, host_id: str, *, key: APIKeyConfig | None = None
    ) -> str:
        """Resolve a site name or UUID to a UUID site ID via the console proxy.

        Matches on ``id`` (exact UUID), ``description``, or ``name`` (both case-insensitive).
        The Network Integration API may return either ``description`` or ``name`` for the
        human-readable site label depending on the firmware version; both are checked.
        Raises ValueError if the site cannot be found or the resolved ID is not a valid UUID.
        """
        check_selector("site", name_or_id)
        sites = await self.get_sites(host_id, key=key)
        site = _match_proxy_site(sites, name_or_id)
        self._refuse_name_on_partial_sites(site, name_or_id, sites)
        if site is not None:
            site_id = _proxy_site_id(site)
            _assert_uuid(site_id)
            from .audit import set_audit_resolution

            set_audit_resolution(site=site_id)
            return site_id
        raise ValueError(
            f"Site {name_or_id!r} not found on host {host_id!r}; valid: "
            f"{_valid_site_choices(sites)}{self._note("console's site", sites)}. "
            "Pass the site name or UUID."
        )

    async def resolve_site_slug(
        self, name_or_id: str, host_id: str, *, key: APIKeyConfig | None = None
    ) -> str:
        """Resolve a site name or UUID to its internalReference slug (e.g. 'default').

        Used for Classic REST and v2 API endpoints that require the site slug rather than
        the UUID. Returns the site's ``internalReference`` exactly; a site without one
        raises (the slug is never guessed from the display name). Raises ValueError if
        the site cannot be found.
        """
        from .client import validate_id

        check_selector("site", name_or_id)
        sites = await self.get_sites(host_id, key=key)
        site = _match_proxy_site(sites, name_or_id)
        self._refuse_name_on_partial_sites(site, name_or_id, sites)
        if site is not None:
            slug = _text(site.get("internalReference"))
            if not slug:
                raise ValueError(
                    f"Site {name_or_id!r} on host {host_id!r} has no internalReference, so "
                    "its Classic REST site slug is unknown; the console did not report it. "
                    f"Console sites: {_valid_site_choices(sites)}"
                    f"{self._note("console's site", sites)}."
                )
            validate_id(slug, "site_slug")
            from .audit import set_audit_resolution

            set_audit_resolution(site=_proxy_site_id(site))
            return slug
        raise ValueError(
            f"Site {name_or_id!r} not found on host {host_id!r}; valid: "
            f"{_valid_site_choices(sites)}{self._note("console's site", sites)}. "
            "Pass the site name or UUID."
        )

    async def resolve_ea_site_id(
        self,
        name_or_id: str,
        *,
        host_id: str | None = None,
        key: APIKeyConfig | None = None,
    ) -> str:
        """Resolve a site name or ID to its Fabric ObjectId via the Site Manager sites list.

        Used for Site Manager (non-proxy) `/v1/...` endpoints that take the Fabric
        ObjectId ``siteId`` (NOT the per-console proxy UUID). Matches case-insensitively
        on the site name/description (``meta.name`` / ``meta.desc`` in the live
        ``/v1/sites`` shape) or on the raw ``siteId``. When ``host_id`` is given, only
        sites on that console are considered, so a site name shared across consoles
        resolves unambiguously.

        Raises ValueError listing the valid site names if the value cannot be resolved,
        rather than forwarding an unrecognised value to the API — the Site Manager
        isp-metrics endpoint answers 200 with an empty result for a wrong siteId, so a
        silent pass-through would mask the error (see the ISP metrics site resolver).
        """
        check_selector("site", name_or_id)
        sites = await self.get_ea_sites(key=key)
        reason = incomplete_reason(sites)
        if host_id is not None:
            sites = filter_records(sites, lambda s: same_id(host_id, s.get("hostId")))
        site = match_ea_site(
            sites, name_or_id, partial=[reason] if reason else [], max_pages=self._max_pages()
        )
        return _ea_site_id(site)

    async def set_hosts(
        self, hosts: list[dict[str, Any]], *, key: APIKeyConfig | None = None
    ) -> None:
        """Update the hosts cache under the async lock (callers pass a complete list).

        A list holding a non-object item is not cached (the next read fetches and raises
        the shape error)."""
        if not _all_objects(hosts) or incomplete_reason(hosts):
            return
        label = self._key_label(key)
        async with self._entry_lock("hosts", label):
            self._hosts[label] = hosts

    async def set_ea_sites(self, sites: list[Any], *, key: APIKeyConfig | None = None) -> None:
        """Replace a complete Site Manager snapshot, omitting spec-legal null placeholders.

        Malformed non-null records and incomplete snapshots leave the prior cache intact.
        The tool response retains its original records, including nulls.
        """
        if (
            not isinstance(sites, list)
            or any(site is not None and not isinstance(site, dict) for site in sites)
            or incomplete_reason(sites)
        ):
            return
        records = [
            site for site in nullable_object_records(sites, "GET /v1/sites") if site is not None
        ]
        label = self._key_label(key)
        async with self._entry_lock("ea_sites", label):
            self._ea_sites[label] = records

    async def set_sites(
        self, host_id: str, sites: list[dict[str, Any]], *, key: APIKeyConfig | None = None
    ) -> None:
        """Update the proxy sites cache for a specific host under the async lock (a list
        holding a non-object item is not cached)."""
        if not _all_objects(sites) or incomplete_reason(sites):
            return
        label = self._key_label(key)
        async with self._entry_lock("sites", label, host_id):
            self._sites[(label, host_id)] = sites

    def invalidate(self, *, key: APIKeyConfig | None = None) -> None:
        """Force cache refresh on next access.

        If key is None, invalidates all cached entries.
        """
        if key is not None:
            label = self._key_label(key)
            self._hosts.pop(label, None)
            self._ea_sites.pop(label, None)
            for cache_key in [k for k in self._sites if k[0] == label]:
                self._sites.pop(cache_key, None)
        else:
            self._hosts.clear()
            self._ea_sites.clear()
            self._sites.clear()
