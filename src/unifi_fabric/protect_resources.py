"""Protect MCP resources: recent events, an event summary, a camera snapshot index and
per-camera JPEG snapshots, readable through ``resources/list``,
``resources/templates/list`` and ``resources/read``.

Every resource read re-enters the registered read tool it is built on
(``list_hosts``, ``list_protect_events``, ``list_cameras``, ``get_camera_snapshot``)
through ``call_tool`` with the full middleware chain. A resource read therefore gets the
same credential selection (environment keys, or the request's ``X-UniFi-Api-Key`` header),
operator and request-header exposure, redaction setting, secret scrubbing and audit as a
direct call of that tool, and those tools are not changed.

Scope: Protect only. There is no Access resource, no ``resources/subscribe`` and no
``notifications/resources/updated``: every read is answered at read time. The event
resources read the console's event history (the Protect REST history route behind
``list_protect_events``); this server keeps no event stream, so no listener has to be
running for them to answer, and every event payload says where its data came from, when
it was read and which time window it covers.

URIs carry a console (``host``) and, for a snapshot, a camera id: never a key, a token or
any other credential. The console is a path segment, not the URI authority, because the
composite console id (``MAC:numericId``) contains ``:``.
"""

from __future__ import annotations

import base64
import binascii
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from fastmcp import FastMCP
from fastmcp.exceptions import ResourceError
from fastmcp.resources import ResourceContent, ResourceResult
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from mcp.shared.exceptions import MCPError
from mcp.types import Annotations

from . import policy as sp
from .client import describe_shape
from .contracts import TOOLS_LIST_POLICY_ERROR_CODE

SCHEME = "unifi-protect"
CONSOLES_URI = f"{SCHEME}://consoles"
EVENTS_TEMPLATE = SCHEME + "://hosts/{host}/events/recent{?window_seconds}"
SUMMARY_TEMPLATE = SCHEME + "://hosts/{host}/events/summary{?window_seconds}"
SNAPSHOT_INDEX_TEMPLATE = SCHEME + "://hosts/{host}/cameras/snapshots"
SNAPSHOT_TEMPLATE = SCHEME + "://hosts/{host}/cameras/{camera_id}/snapshot{?channel,high_quality}"

#: The window ``events/recent`` and ``events/summary`` cover when ``window_seconds`` is
#: omitted: the last hour, ending at the moment of the read.
DEFAULT_WINDOW_SECONDS = 3600

#: The registered read tool(s) each resource is built on. A resource is listed, and
#: readable, only while every tool it names is exposed to the caller.
BACKING_TOOLS: dict[str, tuple[str, ...]] = {
    CONSOLES_URI: ("list_hosts",),
    EVENTS_TEMPLATE: ("list_protect_events",),
    SUMMARY_TEMPLATE: ("list_protect_events",),
    SNAPSHOT_INDEX_TEMPLATE: ("list_cameras",),
    SNAPSHOT_TEMPLATE: ("get_camera_snapshot",),
}

EVENTS_ROUTE = "GET /v1/connector/consoles/{host_id}/proxy/protect/api/events"
_STREAMING = {
    "available": False,
    "reason": (
        "This server keeps no Protect event stream: the Protect event WebSocket is not "
        "reachable over the Fabric cloud connector. Every read queries the console's "
        "event history at read time, so no listener needs to be running."
    ),
}
_NO_PUSH = {"updateMode": "on-read", "subscribe": False, "listChanged": False}
_JPEG_MAGIC = b"\xff\xd8\xff"


def _segment(value: str) -> str:
    """A URI path segment for a console or camera reference (``:`` kept readable)."""
    return quote(value, safe=":")


def events_uri(host: str) -> str:
    return f"{SCHEME}://hosts/{_segment(host)}/events/recent"


def summary_uri(host: str) -> str:
    return f"{SCHEME}://hosts/{_segment(host)}/events/summary"


def snapshot_index_uri(host: str) -> str:
    return f"{SCHEME}://hosts/{_segment(host)}/cameras/snapshots"


def snapshot_uri(host: str, camera_id: str, channel: str | None = None) -> str:
    uri = f"{SCHEME}://hosts/{_segment(host)}/cameras/{_segment(camera_id)}/snapshot"
    return uri if channel is None else f"{uri}?channel={quote(channel, safe='')}"


def _iso(epoch_seconds: float) -> str:
    return datetime.fromtimestamp(epoch_seconds, UTC).isoformat().replace("+00:00", "Z")


def parse_window_seconds(value: str | None) -> int:
    """``window_seconds`` from the URI query: a positive whole number of seconds."""
    if value is None:
        return DEFAULT_WINDOW_SECONDS
    text = value.strip()
    if not text.isdigit() or int(text) < 1:
        raise ResourceError(
            f"window_seconds must be a positive whole number of seconds, got {value!r}; "
            f"omit it for the last {DEFAULT_WINDOW_SECONDS} seconds, e.g. "
            "?window_seconds=900. No request was sent."
        )
    return int(text)


def parse_high_quality(value: str | None) -> bool | None:
    """``high_quality`` from the URI query: ``true`` or ``false``."""
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    raise ResourceError(
        f"high_quality must be true or false, got {value!r}; omit it for the controller "
        "default. No request was sent."
    )


def _structured(result: Any) -> Any:
    """The structured result of a dispatched tool (its documented return value)."""
    content = getattr(result, "structured_content", None)
    meta = getattr(result, "meta", None) or {}
    if isinstance(content, dict) and set(content) == {"result"} and not meta.get("unwrapped"):
        # FastMCP wraps a non-object return as {"result": value}.
        return content["result"]
    return content


def _records(payload: Any) -> tuple[list[Any], dict[str, Any]]:
    """The record array of a list-tool result and its other top-level keys (verbatim)."""
    if isinstance(payload, list):
        return payload, {}
    if isinstance(payload, dict):
        for key in ("data", "result"):
            if isinstance(payload.get(key), list):
                return payload[key], {k: v for k, v in payload.items() if k != key}
    raise ResourceError(
        f"Unexpected result shape from the backing tool: {type(payload).__name__} "
        "with no record array"
    )


def _record(value: Any, source: str) -> dict[str, Any]:
    """An upstream record with a string ``id``; any other shape is an error naming it."""
    if not isinstance(value, dict) or not isinstance(value.get("id"), str):
        raise ResourceError(
            f"Unexpected record from {source}: expected an object with a string id, "
            f"got {describe_shape(value)}"
        )
    return value


def _object_field(record: dict[str, Any], key: str, source: str) -> dict[str, Any] | None:
    """``record[key]`` when it is an object or absent/null; any other shape is an error."""
    value = record.get(key)
    if value is not None and not isinstance(value, dict):
        raise ResourceError(
            f"Unexpected {key} in a {source} record: expected an object, "
            f"got {describe_shape(value)}"
        )
    return value


def _get(record: dict[str, Any] | None, key: str) -> Any:
    """``record[key]``, or None when the record itself is absent."""
    return None if record is None else record.get(key)


def _count(counts: dict[str, int], key: Any) -> None:
    label = key if isinstance(key, str) and key else "none"
    counts[label] = counts.get(label, 0) + 1


def summarize(events: Sequence[Any]) -> dict[str, Any]:
    """Counts of ``events`` by type, camera, smart-detect subtype and ongoing state.

    Keys are the upstream values; an event without one counts under ``none``.
    """
    by_type: dict[str, int] = {}
    by_camera: dict[str, int] = {}
    by_smart: dict[str, int] = {}
    ongoing = 0
    starts: list[int] = []
    for event in events:
        if not isinstance(event, dict):
            raise ResourceError(
                "Unexpected event record from list_protect_events: expected an object, "
                f"got {describe_shape(event)}"
            )
        _count(by_type, event.get("type"))
        _count(by_camera, event.get("camera"))
        for subtype in event.get("smartDetectTypes") or ():
            _count(by_smart, subtype)
        if "end" in event and event.get("end") is None:
            ongoing += 1
        if isinstance(event.get("start"), int) and not isinstance(event.get("start"), bool):
            starts.append(event["start"])
    return {
        "total_events": len(events),
        "by_type": by_type,
        "by_camera": by_camera,
        "by_smart_detect_type": by_smart,
        "ongoing_events": ongoing,
        "newest_event_start": max(starts) if starts else None,
        "oldest_event_start": min(starts) if starts else None,
    }


class ProtectResources:
    """The resource handlers, bound to the server whose tools they dispatch to."""

    def __init__(
        self,
        app: FastMCP,
        *,
        clock: Callable[[], float] | None = None,
        broker: Callable[[], Any] | None = None,
    ) -> None:
        self.app = app
        self._clock = clock
        self._broker = broker

    def clock(self) -> float:
        return self._clock() if self._clock is not None else time.time()

    async def call(self, name: str, arguments: dict[str, Any]) -> Any:
        """Call registered read tool ``name`` through the full middleware chain."""
        token = self._broker() if self._broker is not None else None
        try:
            return _structured(await self.app.call_tool(name, arguments))
        finally:
            if token is not None:
                token.var.reset(token)

    # ------------------------------------------------------------------ events
    async def _events(self, host: str, window_seconds: str | None) -> dict[str, Any]:
        window = parse_window_seconds(window_seconds)
        read_at = self.clock()
        end = int(read_at)
        if window > end:
            raise ResourceError(
                f"window_seconds is longer than the time since 1970-01-01 ({end} seconds), got "
                f"{window}; use a shorter window, e.g. ?window_seconds=900. No request was sent."
            )
        start = end - window
        window_start, window_end = _iso(start), _iso(end)
        payload = await self.call(
            "list_protect_events",
            {"host": host, "start": start, "end": end, "order_direction": "DESC"},
        )
        events, envelope = _records(payload)
        complete = envelope.get("incomplete") is not True
        return {
            "host": host,
            "events": events,
            "envelope": envelope,
            "source": {
                "kind": "rest-history",
                "tool": "list_protect_events",
                "route": EVENTS_ROUTE,
                "streaming": dict(_STREAMING),
            },
            "freshness": {
                "read_at": _iso(read_at),
                "read_at_epoch_seconds": end,
                "cached": False,
                **_NO_PUSH,
            },
            "coverage": {
                "window_seconds": window,
                "window_start_epoch_seconds": start,
                "window_end_epoch_seconds": end,
                "window_start": window_start,
                "window_end": window_end,
                "order": "newest first (orderDirection DESC)",
                "complete": complete,
                "event_count": len(events),
                "filters": None,
                "note": (
                    "Every event the console's event history returns for this window, all "
                    "pages read. complete is false only when an operator page cap "
                    "(UNIFI_PAGINATE_MAX_PAGES) stopped the read early; envelope then "
                    "carries incomplete and its reason."
                ),
            },
        }

    async def recent_events(self, host: str, window_seconds: str | None = None) -> ResourceResult:
        """Protect events of the last window (default one hour) for one console."""
        body = await self._events(host, window_seconds)
        return ResourceResult([ResourceContent(body, mime_type="application/json")])

    async def event_summary(self, host: str, window_seconds: str | None = None) -> ResourceResult:
        """Event counts for the same window as ``events/recent``."""
        body = await self._events(host, window_seconds)
        events = body.pop("events")
        body["summary"] = summarize(events)
        body["events_uri"] = events_uri(host)
        return ResourceResult([ResourceContent(body, mime_type="application/json")])

    # ---------------------------------------------------------------- consoles
    async def consoles(self) -> ResourceResult:
        """Every console the configured keys can see, with its Protect resource URIs."""
        read_at = self.clock()
        payload = await self.call("list_hosts", {})
        hosts, envelope = _records(payload)
        index = []
        for item in hosts:
            host = _record(item, "list_hosts")
            state = _object_field(host, "reportedState", "list_hosts")
            index.append(
                {
                    "host_id": host["id"],
                    "hostname": _get(state, "hostname"),
                    "name": _get(state, "name"),
                    "events_uri": events_uri(host["id"]),
                    "summary_uri": summary_uri(host["id"]),
                    "snapshot_index_uri": snapshot_index_uri(host["id"]),
                }
            )
        body = {
            "consoles": index,
            "envelope": envelope,
            "note": (
                "Protect resources answer only for consoles that run UniFi Protect; any "
                "other console returns the upstream error."
            ),
            "freshness": {"read_at": _iso(read_at), "cached": False, **_NO_PUSH},
            "coverage": {
                "complete": envelope.get("incomplete") is not True,
                "console_count": len(index),
            },
        }
        return ResourceResult([ResourceContent(body, mime_type="application/json")])

    # --------------------------------------------------------------- snapshots
    async def snapshot_index(self, host: str) -> ResourceResult:
        """The console's cameras, each with the URI of its JPEG snapshot."""
        read_at = self.clock()
        payload = await self.call("list_cameras", {"host": host})
        cameras, envelope = _records(payload)
        index = []
        for item in cameras:
            camera = _record(item, "list_cameras")
            flags = _object_field(camera, "featureFlags", "list_cameras")
            entry: dict[str, Any] = {
                "camera_id": camera["id"],
                "name": camera.get("name"),
                "state": camera.get("state"),
                "model": camera.get("modelKey"),
                "snapshot_uri": snapshot_uri(host, camera["id"]),
            }
            if _get(flags, "hasPackageCamera") is True:
                entry["package_snapshot_uri"] = snapshot_uri(host, camera["id"], "package")
            index.append(entry)
        body = {
            "host": host,
            "cameras": index,
            "freshness": {"read_at": _iso(read_at), "cached": False, **_NO_PUSH},
            "coverage": {
                "complete": envelope.get("incomplete") is not True,
                "camera_count": len(index),
            },
        }
        return ResourceResult([ResourceContent(body, mime_type="application/json")])

    async def snapshot(
        self,
        host: str,
        camera_id: str,
        channel: str | None = None,
        high_quality: str | None = None,
    ) -> ResourceResult:
        """One JPEG snapshot of a camera, as a binary resource."""
        quality = parse_high_quality(high_quality)
        arguments: dict[str, Any] = {"host": host, "camera_id": camera_id}
        if channel is not None:
            arguments["channel"] = channel
        if quality is not None:
            arguments["high_quality"] = quality
        read_at = self.clock()
        try:
            metadata = await self.call("get_camera_snapshot", arguments)
        except Exception as exc:
            text = str(exc)
            hint = f" Hint: read {snapshot_index_uri(host)} for this console's camera ids."
            raise ResourceError(text + hint) from None
        if not isinstance(metadata, dict) or not isinstance(metadata.get("image_base64"), str):
            raise ResourceError("Unexpected result shape from get_camera_snapshot: no image_base64")
        try:
            data = base64.b64decode(metadata["image_base64"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ResourceError(f"get_camera_snapshot returned invalid base64: {exc}") from None
        upstream_type = metadata.get("content_type")
        mime = upstream_type.split(";", 1)[0].strip() if isinstance(upstream_type, str) else ""
        if not mime:
            mime = "image/jpeg" if data.startswith(_JPEG_MAGIC) else "application/octet-stream"
        meta = {
            "upstreamContentType": upstream_type,
            "sizeBytes": len(data),
            "readAt": _iso(read_at),
            "cached": False,
        }
        return ResourceResult([ResourceContent(data, mime_type=mime, meta=meta)])


class ResourceExposureMiddleware(Middleware):
    """List a Protect resource only while every tool it is built on is exposed.

    The same facts the tool list uses: the operator's ``UNIFI_FAMILY_ALLOW`` /
    ``UNIFI_EXCLUDE`` and the request's policy headers. A read of a hidden resource is
    refused by the backing tool's own exposure check (``tool_not_exposed``).
    """

    def __init__(self, evaluator: Any) -> None:
        self.evaluator = evaluator

    def _visible(self, names: Iterable[str]) -> bool:
        excluded = sp.excluded_names()
        names = tuple(names)
        if any(name in excluded for name in names):
            return False
        try:
            effective, _ignored = self.evaluator.evaluate()
        except sp.PolicyHeaderError as exc:
            message = str(exc)
            raise MCPError(
                code=TOOLS_LIST_POLICY_ERROR_CODE,
                message=message,
                data={"error": {"code": "invalid_policy_header", "message": message}},
            ) from None
        catalog = self.evaluator.catalog()
        return all(
            (facts := catalog.tools.get(name)) is None or sp.is_exposed(effective, facts)
            for name in names
        )

    def _filter(self, items: Sequence[Any], key: Callable[[Any], str]) -> list[Any]:
        kept = []
        for item in items:
            backing = BACKING_TOOLS.get(key(item))
            if backing is None or self._visible(backing):
                kept.append(item)
        return kept

    async def on_list_resources(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        return self._filter(await call_next(context), lambda r: str(r.uri))

    async def on_list_resource_templates(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        return self._filter(await call_next(context), lambda t: str(t.uri_template))


_JSON = "application/json"


def register(
    app: FastMCP,
    *,
    evaluator: Any,
    broker: Callable[[], Any] | None = None,
) -> ProtectResources:
    """Register the Protect resources and their listing filter on ``app``."""
    handlers = ProtectResources(app, broker=broker)
    assistant = Annotations(audience=["assistant"], priority=0.6)
    both = Annotations(audience=["user", "assistant"], priority=0.7)

    def meta(uri: str, **extra: Any) -> dict[str, Any]:
        return {**_NO_PUSH, "backingTools": list(BACKING_TOOLS[uri]), **extra}

    app.resource(
        CONSOLES_URI,
        name="protect_consoles",
        title="Consoles and their Protect resources",
        description=(
            "JSON index of every console the configured API keys can see (list_hosts), each "
            "with its Protect resource URIs: events/recent, events/summary and "
            "cameras/snapshots. Start here to find the host value for the templates. Read "
            "at request time; never cached by the server."
        ),
        mime_type=_JSON,
        annotations=assistant,
        meta=meta(CONSOLES_URI),
    )(handlers.consoles)
    app.resource(
        EVENTS_TEMPLATE,
        name="protect_recent_events",
        title="Recent Protect events",
        description=(
            "Protect events of one console for the last window_seconds (default 3600, any "
            "positive whole number), newest first, read from the console's event history "
            "(list_protect_events, every page) at request time. host: console name or id "
            "from unifi-protect://consoles or list_hosts. JSON {host, events, envelope, "
            "source, freshness, coverage}: source.kind is rest-history and "
            "source.streaming.available is false (this server keeps no event stream); "
            "freshness.read_at is the read time; coverage gives the exact window and "
            "complete. Events are the upstream records verbatim. Example: "
            "unifi-protect://hosts/my-console/events/recent?window_seconds=900"
        ),
        mime_type=_JSON,
        annotations=both,
        meta=meta(EVENTS_TEMPLATE, source="rest-history"),
    )(handlers.recent_events)
    app.resource(
        SUMMARY_TEMPLATE,
        name="protect_event_summary",
        title="Protect event summary",
        description=(
            "Counts of one console's Protect events for the last window_seconds (default "
            "3600): total, by type, by camera id, by smart-detect type, ongoing events, "
            "newest and oldest start (epoch ms). Same source, freshness and coverage "
            "fields as events/recent, which it links as events_uri. Example: "
            "unifi-protect://hosts/my-console/events/summary"
        ),
        mime_type=_JSON,
        annotations=assistant,
        meta=meta(SUMMARY_TEMPLATE, source="rest-history"),
    )(handlers.event_summary)
    app.resource(
        SNAPSHOT_INDEX_TEMPLATE,
        name="protect_camera_snapshot_index",
        title="Protect camera snapshot index",
        description=(
            "JSON index of one console's Protect cameras (list_cameras): camera_id, name, "
            "state, model and snapshot_uri, plus package_snapshot_uri for a camera with a "
            "package camera. Read at request time. Example: "
            "unifi-protect://hosts/my-console/cameras/snapshots"
        ),
        mime_type=_JSON,
        annotations=assistant,
        meta=meta(SNAPSHOT_INDEX_TEMPLATE),
    )(handlers.snapshot_index)
    app.resource(
        SNAPSHOT_TEMPLATE,
        name="protect_camera_snapshot",
        title="Protect camera snapshot (JPEG)",
        description=(
            "A live snapshot of one Protect camera (get_camera_snapshot), returned as a "
            "binary blob with the upstream Content-Type (image/jpeg). camera_id: the "
            "24-hex Protect camera id from cameras/snapshots or list_cameras. Optional "
            "query: channel (main, or package for a package camera) and high_quality "
            "(true or false). A missing or inaccessible camera returns the upstream error. "
            "Example: unifi-protect://hosts/my-console/cameras/00000000000000000000010b/"
            "snapshot?high_quality=true"
        ),
        mime_type="image/jpeg",
        annotations=both,
        meta=meta(SNAPSHOT_TEMPLATE),
    )(handlers.snapshot)
    app.add_middleware(ResourceExposureMiddleware(evaluator))
    return handlers


def resource_read_cache_hint() -> Mapping[str, Any]:
    """The cache hint every ``resources/read`` carries: never reuse, never share.

    A resource read is per caller (its credentials and policy) and time-sensitive
    (events, snapshots), so the server-wide list hint (``UNIFI_MCP_CACHE_TTL``, public)
    does not apply to it.
    """
    from mcp.server.caching import CacheHint

    return {"resources/read": CacheHint(ttl_ms=0, scope="private")}
