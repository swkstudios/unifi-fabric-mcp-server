"""System log tools: the Network application's event log, alerts and IPS threat events.

Network 11.x keeps its event history in the v2 system log, read with POST
``/proxy/network/v2/api/site/{site}/system-log/{class}`` and a JSON query body. These POSTs are
sent only through ``post_read``: the nine class routes are on the read-POST allowlist
(``read_post_routes``; the eight beyond ``all`` proven from Ubiquiti's server code), so these
tools are reads and any other class is refused before a request. The Classic routes
older controllers used are gone on Network 11.0.81: ``stat/event`` and ``stat/ips/event``
answer HTTP 404 ``api.err.NotFound`` and ``list/alarm`` answers HTTP 400
``api.err.InvalidObject`` (probed live), so these tools read the system log.

A class page is ``{data: [...], page_number, total_element_count, total_page_count}``
(``critical`` answers a bare JSON array). Pages are numbered from 0 with ``pageNumber`` /
``pageSize`` in the body. Some classes return nothing unless the body names the kinds of
entries wanted (on Network 11.0.81 ``threat-alert`` without ``threatTypes`` returned no
entries while the same query with ``threatTypes`` returned entries); for those the tools
send the full list the controller UI sends, and a caller's own value for that key
replaces it.
"""

from __future__ import annotations

from typing import Any, cast

from ...client import (
    RateLimitError,
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    path_segment,
    validate_id,
    validate_selector,
)
from ...config import APIKeyConfig
from ...read_only import is_write_request
from ...read_post_routes import is_read_post, post_read
from ...registry import Registry
from ...shared_shapes._classic_objects import resolve_site_slug, v2_site
from ...shared_shapes._history_common import epoch_warnings, require_epoch_seconds, with_warnings
from ...shared_shapes._incident_document import (
    NETWORK_RULES,
    PostStatusTap,
    SourceRead,
    SourceScope,
    build_document,
    capture_failure,
    evidence_selectors,
    evidence_window,
    must_raise,
    page_cap,
    unusable_answer,
)
from ...shared_shapes._number_window import collect_number_window
from ...shared_shapes._pagination import collect_batch, mark_incomplete, validate_pagination
from .schemas import (  # the family's shapes (family-owned layout)
    CLASS_DEFAULTS,
    DRAIN_PAGE_SIZE,
    EVIDENCE_DEFAULT_CLASSES,
    EVIDENCE_READ_CLASSES,
    SCOPED_LOG_ROUTES,
)
from .schemas import (
    KNOWN_CLASSES as KNOWN_CLASSES,
)
from .schemas import (
    SystemLogClass as SystemLogClass,
)


def _class_query(log_class: str, query: dict[str, Any] | None) -> dict[str, Any]:
    """The caller's query with the class's UI entry-kind lists added where it sets none."""
    body = dict(CLASS_DEFAULTS.get(log_class, {}))
    body.update(query or {})
    return body


async def _post_page_listed(
    client: UniFiClient,
    host_id: str,
    site_slug: str,
    log_class: str,
    body: dict[str, Any],
    key: APIKeyConfig | None,
) -> Any:
    """One system-log POST of a read-allowlisted class (``read_post_routes``), a read."""
    return await post_read(
        client, v2_site(host_id, site_slug, f"/system-log/{log_class}"), key=key, json=body
    )


def _page_rows(page: Any, label: str) -> list[Any]:
    rows = page.get("data") if isinstance(page, dict) else None
    if not isinstance(rows, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from POST {label}: expected an object with a 'data' "
            f"array, got {describe_shape(page)}"
        )
    return rows


def _paging_integer(name: str, value: Any, minimum: int) -> int:
    """Validate controls used in local paging arithmetic before sending the POST.

    ``minimum`` 0 is a zero-based page and 1 a count; the message names ``name``.
    """
    kind = "zero_page" if minimum == 0 else "page_size"
    # A JSON null in the query is not an integer either; the validator reads None as
    # "not given", so it is checked under its printed form.
    validate_pagination(**{kind: "None" if value is None else value}, names={kind: name})
    return int(value)


async def _read_system_log(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    log_class: str,
    query: dict[str, Any] | None,
    *,
    page: int | None = None,
    page_size: int | None = None,
) -> Any:
    """Read one system-log class with the read-allowlisted POST (``post_read``): a read, with
    no write guard and no dry-run preview. A class that is not on the allowlist is refused
    before any request.

    Zero-based page: with page_size, returns exactly page_size records starting at record
    page * page_size, gathered across console pages whatever the console page size; resume
    with _nextPage and the same page_size. Without page_size, one request returns that console
    page verbatim. page_size alone is page 0: exactly page_size records from record 0; with
    neither, all entries are drained.
    """
    validate_id(log_class, "log_class")
    require_read_class("log_class", log_class)
    return await _read_system_log_listed(
        client, registry, host, site, log_class, query, page=page, page_size=page_size
    )


async def _read_system_log_listed(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    log_class: str,
    query: dict[str, Any] | None,
    *,
    page: int | None = None,
    page_size: int | None = None,
) -> Any:
    """Read one read-allowlisted system-log class with ``post_read`` (a read: no write guard, no
    dry-run preview; a class that is not on the allowlist is refused before any request).
    Zero-based page: with page_size, returns exactly
    page_size records starting at record page * page_size, gathered across console pages
    whatever the console page size; resume with _nextPage and the same page_size. Without
    page_size, one request returns that console page verbatim. page_size alone is page 0:
    exactly page_size records from record 0; with neither, all entries are drained.
    """
    validate_id(log_class, "log_class")
    body = _class_query(log_class, query)
    # Paging keys in the query are honoured, never refused: a pageNumber counts as page
    # and a pageSize as page_size; the explicit arguments win.
    # Validate body controls even when explicit arguments override them. These
    # integers drive local paging arithmetic; other body fields stay free-form.
    in_number = (
        _paging_integer("query_body.pageNumber", body.pop("pageNumber"), 0)
        if "pageNumber" in body
        else None
    )
    in_size = (
        _paging_integer("query_body.pageSize", body.pop("pageSize"), 1)
        if "pageSize" in body
        else None
    )
    page = _paging_integer("page", page, 0) if page is not None else in_number
    page_size = _paging_integer("page_size", page_size, 1) if page_size is not None else in_size
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    label = f"system-log/{log_class}"

    async def fetch(paging: dict[str, Any]) -> Any:
        return await _post_page_listed(
            client, host_id, site_slug, log_class, {**body, **paging}, key
        )

    if page is not None or page_size is not None:
        if page_size is not None:
            # The logical window [page*N, page*N + N), whatever the console page size;
            # page_size alone is window 0 (a bare array included), so its _nextPage counts
            # page_size windows and page_size alone matches page=0 for the same console.
            window = await collect_number_window(
                fetch, page=page or 0, page_size=page_size, max_pages=client.paginate_max_pages
            )
            if "raw" not in window:
                return mark_incomplete({**window["envelope"], "data": window["items"]}, window)
            one = window["raw"]
        else:
            # Explicit paging: exactly one page, carrying only the paging parameters given.
            one = await fetch({"pageNumber": page})
        if not isinstance(one, dict):
            # Preserve a scalar response instead of reporting it as an envelope-shape failure.
            return one
        _page_rows(one, label)
        return one

    collected = await collect_batch(
        fetch,
        requested=page_size,
        default_size=DRAIN_PAGE_SIZE,
        family="number",
        max_pages=client.paginate_max_pages,
        strict_total=True,
        allow_unpaged=True,
    )
    if "raw" in collected:
        return collected["raw"]
    result = {
        k: v
        for k, v in collected["envelope"].items()
        if k not in ("page_number", "total_page_count")
    }
    result["data"] = collected["items"]
    return mark_incomplete(result, collected)


def _window(start: int | None, end: int | None) -> dict[str, Any]:
    """Epoch-second start / end as the system log's millisecond timestamps (only those given).

    A non-integer value is refused (the shared epoch-type rule); a negative value or one that
    looks like milliseconds is still multiplied by 1000 and reported by :func:`_epoch_hints`."""
    out: dict[str, Any] = {}
    if start is not None:
        out["timestampFrom"] = require_epoch_seconds(start, "start") * 1000
    if end is not None:
        out["timestampTo"] = require_epoch_seconds(end, "end") * 1000
    return out


def _epoch_hints(result: Any, start: int | None, end: int | None) -> Any:
    """``result`` with the shared ``_warnings`` entries for implausible start / end values."""
    warnings = epoch_warnings(start=start, end=end)
    for warning in warnings:
        warning["sent_as"] = warning["value"] * 1000
        warning["message"] = (
            f"{warning['argument']}={warning['value']} is interpreted as epoch seconds and "
            f"multiplied by 1000; sent as {warning['sent_as']} milliseconds. Pass epoch seconds."
        )
    return with_warnings(result, warnings)


async def _vpn_user_connection_log(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    vpn_user_id: str,
    *,
    start: int | None,
    end: int | None,
    view: str | None,
) -> Any:
    """One VPN user's connection log (GET ``system-log/vpn-user-connection?vpnUserId=``),
    verbatim. The route takes no class and no window, so a ``view``, ``start`` or ``end``
    given with it is refused before any request rather than silently dropped."""
    validate_selector(vpn_user_id, "vpn_user_id")
    given = [
        name
        for name, value in (("start", start), ("end", end), ("view", view))
        if value is not None and not (isinstance(value, str) and not value.strip())
    ]
    if given:
        raise ValueError(
            f"list_network_events scope conflict: {', '.join(given)} cannot be combined with "
            "vpn_user_id (the VPN-user connection log takes no class or time window); omit "
            "them or omit vpn_user_id."
        )
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    return await client.get(
        v2_site(host_id, site_slug, "/system-log/vpn-user-connection"),
        key=key,
        params={"vpnUserId": vpn_user_id},
    )


async def _get_scoped_system_log(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    scope: str,
    identifier: str,
    query: dict[str, Any] | None = None,
) -> Any:
    """GET ``system-log/{scope}/{identifier}`` verbatim (a plain read, no POST).

    ``scope`` must name one of :data:`SCOPED_LOG_ROUTES` (an unknown scope fails listing the
    choices); ``identifier`` is encoded as exactly one path segment (a MAC address is sent
    as given). ``query`` is sent as the query string when non-empty."""
    validate_selector(scope, "scope")
    if scope not in SCOPED_LOG_ROUTES:
        raise ValueError(
            f"get_scoped_system_log scope must be one of {', '.join(SCOPED_LOG_ROUTES)}; "
            f"got {scope!r}"
        )
    if scope in {"device", "client-connection"}:
        # The identifier is a caller MAC here: the one selector rule refuses an empty,
        # padded or control-character value (a padded MAC is never sent or stripped); its
        # spelling is otherwise the caller's, as the bundle route types it only as ``{}``.
        validate_selector(identifier, "identifier")
    # A MAC is sent with its colons as given (the probed form); every other reserved
    # character stays percent-encoded, so the value is still exactly one path segment.
    segment = path_segment(identifier, "identifier").replace("%3A", ":")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    path = v2_site(host_id, site_slug, f"/system-log/{scope}/{segment}")
    if query:
        return await client.get(path, key=key, params=query)
    return await client.get(path, key=key)


async def _list_network_events(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    start: int | None,
    end: int | None,
    *,
    view: str | None = None,
    vpn_user_id: str | None = None,
) -> Any:
    """Class ``view`` (default ``all``) of the system log, every page drained, with the
    start / end window; or, with ``vpn_user_id``, that VPN user's connection log."""
    if vpn_user_id is not None:
        return await _vpn_user_connection_log(
            client, registry, host, site, vpn_user_id, start=start, end=end, view=view
        )
    log_class = view.strip() if isinstance(view, str) and view.strip() else "all"
    query = _window(start, end)
    result = await _read_system_log(client, registry, host, site, log_class, query)
    return _epoch_hints(result, start, end)


def require_read_class(argument: str, log_class: str) -> None:
    """Refuse, before any request, a system-log class that is not a read-allowlisted route.

    Judged on a synthetic console and site (the route is exact in its class segment only)."""
    if not is_read_post("POST", v2_site("console", "site", f"/system-log/{log_class}")):
        raise ValueError(
            f"{argument} may name only a read-allowlisted system-log class "
            f"({', '.join(EVIDENCE_READ_CLASSES)}), got {log_class!r}"
        )


def _evidence_source(log_class: str, host_id: str, site_slug: str) -> SourceRead:
    return SourceRead(
        source_id=f"network.system_log.{log_class}",
        route=f"POST /proxy/network/v2/api/site/{{site}}/system-log/{log_class}",
        scope=SourceScope(
            host_id=host_id, site=site_slug, log_class=log_class, camera_id=None, event_types=None
        ),
    )


def _evidence_read(
    read: SourceRead,
    result: Any,
    client: UniFiClient,
    *,
    path: str,
    status: int | None,
) -> SourceRead:
    """One class's drained system-log result as an evidence source read. A 2xx answer with no
    listing (empty, scalar, non-JSON, or an object without ``data``) is ``parse_failed``."""
    rows = result.get("data") if isinstance(result, dict) else result
    if not isinstance(rows, list):
        read.failure = unusable_answer(result, client, method="POST", path=path, status=status)
        return read
    read.rows = rows
    if isinstance(result, dict):
        total = result.get("total_element_count")
        read.upstream_total = (
            total if isinstance(total, int) and not isinstance(total, bool) else None
        )
        read.incomplete = result.get("incomplete") is True
        reason = result.get("incompleteReason")
        read.incomplete_reason = reason if isinstance(reason, str) else None
    return read


async def _collect_network_incident_evidence(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    start: int,
    end: int,
    log_classes: list[str] | None = None,
) -> Any:
    """Normalized evidence from one or more system-log classes over [start, end).

    Each class is read with the same drain as ``get_system_log`` and is its own source. The
    system-log ``all`` POST is read-allowlisted (``read_post_routes``), so this tool is a
    read: it is not hidden by ``UNIFI_WRITE_POLICY=deny``, has no dry-run preview, and a
    class that is not allowlisted is refused before any request. A read has no uncertain
    outcome, so every failure is recorded as that source's failure and the other classes are
    still read. The error policy still keys on ``is_write_request``: should the route ever be
    classed a write again, a 5xx other than 501, a 429 or a transport error raises and stops
    the collection (see ``must_raise``)."""
    tool = "collect_network_incident_evidence"
    window = evidence_window(tool, start, end)
    classes = evidence_selectors(tool, "log_classes", log_classes) or list(EVIDENCE_DEFAULT_CLASSES)
    for log_class in classes:
        validate_id(log_class, "log_classes")
    for log_class in classes:
        # a class that is not allowlisted is refused before any request, resolution included
        require_read_class(f"{tool} log_classes", log_class)
    _key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    query = {"timestampFrom": window.start_epoch_ms, "timestampTo": window.end_epoch_ms}
    reads: list[SourceRead] = []
    for log_class in classes:
        path = v2_site(host_id, site_slug, f"/system-log/{log_class}")
        tap = PostStatusTap(client)
        read = _evidence_source(log_class, host_id, site_slug)
        try:
            result = await _read_system_log_listed(
                cast(UniFiClient, tap), registry, host, site, log_class, dict(query)
            )
        except (UniFiConnectionError, RateLimitError) as exc:
            if must_raise(exc, write=is_write_request("POST", path, query)):
                raise
            read.failure = capture_failure(
                exc, client, method="POST", path=path, answered=tap.last_status
            )
            reads.append(read)
            continue
        reads.append(_evidence_read(read, result, client, path=path, status=tap.last_status))
    return build_document(
        rules=NETWORK_RULES,
        host_id=host_id,
        site=site_slug,
        window=window,
        reads=reads,
        page_cap=page_cap(client),
        warnings=epoch_warnings(start=start, end=end),
    )
