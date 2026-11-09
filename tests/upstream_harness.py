"""Shape-faithful fake upstream for cross-tool property tests.

A real ``UniFiClient`` + ``Registry`` sit behind the tools. Normal transport
replays sanitized captures using method, path, normalized query, scenario and status,
without changing their bodies or pagination. A missing captured page raises rather
than manufacturing an answer. Explicit synthetic modes exercise property scenarios;
``replay_recordings=False`` selects generated records for tests requiring ARG_* ids.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

import httpx

from unifi_fabric import server
from unifi_fabric.client import UniFiClient, is_write_request
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.registry import Registry

RECORDED = Path(__file__).parent / "fixtures" / "recorded"
SYNTHETIC_RECORD = json.loads(
    (Path(__file__).parent / "fixtures" / "synthetic" / "harness_probe_record.json").read_text()
)

ARG_ID = "00000000-0000-4000-8000-0000000000aa"
ARG_HEX = "0000000000000000000000aa"
ARG_MAC = "02:00:5e:00:00:aa"
ARG_NAME = "probe-object"
#: The PTZ preset/patrol slot the harness passes; record 0 of a slot list carries it.
ARG_SLOT = 1
#: The recorded networkconf fixture's remote-user-vpn record (Integration id).
VPN_SERVER_EXTERNAL_ID = "00000000-0000-4000-9000-000000000038"
SITE = "Default"
NOW = int(time.time())
_PROBE_KEY = os.urandom(32)

# Upstream envelope/framing keys: transport metadata around the records, not record data.
FRAMING = frozenset(
    {
        "meta",
        "offset",
        "limit",
        "count",
        "totalCount",
        "nextToken",
        "httpStatusCode",
        "traceId",
        "links",
        "probeEnvelope",  # the envelope_probe mode's added top-level key
        # the Network v2 system-log page controls ({data, page_number,
        # total_element_count, total_page_count})
        "page_number",
        "total_element_count",
        "total_page_count",
    }
)
# ``envelope_probe`` mode: every list-shaped upstream body (resolution lists included)
# carries this extra top-level key, so a tool that drops upstream envelope keys shows.
ENVELOPE_PROBE_KEY = "probeEnvelope"
ENVELOPE_PROBE_VALUE = "probe-envelope-value"
# Site Manager lists the published spec pages with nextToken (v1.0.0); cursor_cycle
# applies only to these (/v1/hosts and /v1/sites are served as resolution lists).
NEXT_TOKEN_PATHS = frozenset({"/v1/devices", "/v1/hosts", "/v1/sites"})
JUNK_PATHS = frozenset({"/v1/hosts", "/v1/sites", "/v1/devices"})
RESOLUTION_SUFFIXES = ("/v1/hosts", "/v1/sites", "/proxy/network/integration/v1/sites")


NormalizedQuery = tuple[tuple[str, str], ...]
RecordedKey = tuple[str, str, NormalizedQuery, str, int]
_RECORDED_CACHE: dict[RecordedKey, dict[str, Any]] = {}


def normalized_query(query: Any) -> NormalizedQuery:
    """Compare decoded query multisets; retain repeated keys and empty values."""
    if isinstance(query, bytes):
        query = query.decode()
    if isinstance(query, str):
        pairs = parse_qsl(query, keep_blank_values=True)
    elif isinstance(query, dict):
        pairs = [
            (key, item)
            for key, value in query.items()
            for item in (value if isinstance(value, (list, tuple)) else [value])
        ]
    else:
        pairs = query or []
    return tuple(sorted((str(key), str(value)) for key, value in pairs))


def load_recorded() -> dict[RecordedKey, dict[str, Any]]:
    """Index every capture by method, path, query, scenario and HTTP status."""
    if _RECORDED_CACHE:
        return _RECORDED_CACHE
    for path in sorted(RECORDED.rglob("*.json")):
        entry = json.loads(path.read_text())
        entry["_file"] = path.relative_to(RECORDED).as_posix()
        request = entry["request"]
        key = (
            request["method"].upper(),
            request["path"],
            normalized_query(request.get("query", {})),
            entry.get("scenario", entry["_file"]),
            entry["status"],
        )
        if key in _RECORDED_CACHE:
            raise ValueError(f"duplicate recording selector: {key}")
        _RECORDED_CACHE[key] = entry
    return _RECORDED_CACHE


def entry_content_type(entry: dict[str, Any]) -> str:
    """The capture's content type; a lane capture that stores none gets the type its body
    kind implies (JSON body, text body, or binary size/type only)."""
    if entry.get("content_type"):
        return str(entry["content_type"])
    if "body" in entry:
        return "application/json"
    return "text/plain" if "text" in entry else "application/octet-stream"


def recorded(rel: str) -> dict[str, Any]:
    return json.loads((RECORDED / rel).read_text())


_HOSTS = recorded("site_manager/v1_hosts.json")["body"]
HOST_RECORD = _HOSTS["data"][0]
HOST_ID: str = HOST_RECORD["id"]
HOST = HOST_RECORD["reportedState"]["hostname"]
_PROXY_SITES = recorded("network_integration/network_integration_v1_sites.json")["body"]
SITE_ID: str = _PROXY_SITES["data"][0]["id"]


def family(path: str) -> str:
    if "/proxy/network/integration/" in path:
        return "integration"
    if "/proxy/network/api/" in path:
        return "classic"
    if "/proxy/network/v2/" in path:
        return "v2"
    if "/proxy/protect/integration/" in path:
        return "protect"
    if "/proxy/protect/" in path:
        return "protect_private"
    if "/proxy/innerspace/" in path:
        return "innerspace"
    if "/proxy/" in path:
        return "proxy_other"
    return "site_manager"


_ID_SEG = re.compile(
    r"^([0-9a-fA-F-]{20,}|[0-9a-fA-F]{24}|[0-9A-F]{12,}:\d+|\d+|" + re.escape(ARG_ID) + r")\Z"
)


def is_detail(path: str) -> bool:
    last = path.rstrip("/").rsplit("/", 1)[-1]
    # ``status``: Site Manager GET /v1/sd-wan-configs/{id}/status answers one object
    # ({"data": {...}}, Site Manager 1.0.0 spec example), not a list.
    return bool(_ID_SEG.match(last)) or last in {
        "latest",
        "status",
        "info",
        "ordering",
        "references",
        "settings",
        "ipsec",  # v2 settings/ipsec answers the site's one IPsec settings object
        "nvrs",
        "nvr",
        "rtsps-stream",
        ARG_NAME,
    }


def _innerspace_key(path: str) -> str:
    last = path.rstrip("/").rsplit("/", 1)[-1]
    return {"inventory": "devices"}.get(last, last)


def is_resolution(path: str) -> bool:
    return path.endswith(RESOLUTION_SUFFIXES)


def make_record(n: int, tag: str) -> dict[str, Any]:
    """A generic upstream record. Record 0 carries the identifiers the harness passes as
    arguments (so lookups by id / MAC / key / name succeed); later records are unique."""
    # Row zero owns ARG_MAC. Skip its suffix in later generated MACs so a large
    # catalogue never gives two distinct native IDs the selector's MAC.
    reserved_suffix = int(ARG_MAC.replace(":", ""), 16) & 0xFFFFFF
    mac_suffix = n + (n >= reserved_suffix)
    mac = (
        ARG_MAC
        if n == 0
        else f"02:00:5e:{(mac_suffix >> 16) & 255:02x}:"
        f"{(mac_suffix >> 8) & 255:02x}:{mac_suffix & 255:02x}"
    )
    return {
        **copy.deepcopy(SYNTHETIC_RECORD),
        "id": ARG_ID if n == 0 else f"00000000-0000-4000-8000-{n + 0x1000:012x}",
        "_id": ARG_HEX if n == 0 else f"{n + 0x1000:024x}",
        "mac": mac,
        "macAddress": mac,
        "probe": f"{tag}#{n}",
    }


# Bare (non-object) JSON bodies the ``get_body`` / ``write_body`` modes can answer with.
BARE_JSON_BODIES: dict[str, Any] = {"true": True, "int": 7, "list": []}

# Record-list shapes the ``item_shape`` mode serves on every JSON GET (resolution lists
# such as /v1/sites included): "scalars" replaces each record list with bare JSON values,
# "nulls" keeps the records and adds null entries around them.
SCALAR_ITEMS: list[Any] = ["probe-scalar-item", 7, True]
ITEM_SHAPES = ("scalars", "nulls")
# Wrong-typed fields INSIDE each record: every string field (top level and one
# level down, nested record lists included) becomes an int or a list, or every object
# field becomes a string.
FIELD_SHAPES = ("int_fields", "list_fields", "str_objects")


# Wrong-typed PAGINATION controls, served on every JSON GET (resolution lists
# included) in ``paged`` mode: each control present in a body is replaced by a value of
# the wrong JSON type. ``CONSUMED_PAGING_FIELDS`` are the controls a drain reads (a tool
# must raise a shape error naming one); the others are passed through or ignored.
PAGING_SHAPES = ("scalar", "container")
CONSUMED_PAGING_FIELDS = ("nextToken", "totalCount", "total", "links", "nextCursor", "hasMore")
_PAGING_POISON: dict[str, dict[str, Any]] = {
    "scalar": {
        "nextToken": 7,
        "totalCount": "5",
        "total": "5",
        "offset": "0",
        "limit": "200",
        "count": "3",
        "links": "probe-links",
        "nextCursor": 7,
        "hasMore": "false",
    },
    "container": {
        "nextToken": ["probe-token"],
        "totalCount": [5],
        "total": {"value": 5},
        "offset": {"value": 0},
        "limit": [200],
        "count": {"value": 3},
        "links": {"prev": None, "next": 7},
        "nextCursor": {"cursor": "c"},
        "hasMore": [True],
    },
}


def poison_paging(body: Any, shape: str) -> tuple[Any, set[str]]:
    """``body`` with every pagination control it carries wrong-typed, and the names of the
    controls poisoned."""
    if not isinstance(body, dict):
        return body, set()
    values = _PAGING_POISON[shape]
    out = dict(body)
    hit: set[str] = set()
    for name in ("nextToken", "totalCount", "total", "offset", "limit", "count", "links"):
        if name in out:
            out[name] = values[name]
            hit.add(name)
    meta = out.get("meta")
    if isinstance(meta, dict) and ({"nextCursor", "hasMore"} & set(meta)):
        meta = dict(meta)
        for name in ("nextCursor", "hasMore"):
            if name in meta:
                meta[name] = values[name]
                hit.add(name)
        out["meta"] = meta
    return out, hit


_PAGING_CONTROLS = frozenset(
    {"offset", "limit", "count", "totalCount", "total", "nextToken", "links"}
)


def bare_envelope(body: Any) -> Any:
    """A list envelope reduced to its record arrays and paging controls."""
    if not isinstance(body, dict) or not any(isinstance(v, list) for v in body.values()):
        return body
    return {k: v for k, v in body.items() if isinstance(v, list) or k in _PAGING_CONTROLS}


def _wrong_typed(record: Any, shape: str, depth: int = 0) -> Any:
    if not isinstance(record, dict):
        return record
    out: dict[str, Any] = {}
    for key, value in record.items():
        if shape == "str_objects" and isinstance(value, dict):
            out[key] = "probe-not-an-object"
        elif shape == "int_fields" and isinstance(value, str):
            out[key] = 123
        elif shape == "list_fields" and isinstance(value, str):
            out[key] = ["probe-list-field"]
        elif isinstance(value, dict) and depth < 1:
            out[key] = _wrong_typed(value, shape, depth + 1)
        elif isinstance(value, list) and depth < 1:
            # nested record lists (the /v1/devices host wrappers' ``devices``)
            out[key] = [_wrong_typed(item, shape, depth + 1) for item in value]
        else:
            out[key] = value
    return out


def reshape_items(body: Any, shape: str) -> Any:
    """``body`` with its record lists (top level, or one level inside ``data``) reshaped."""

    def lst(items: list[Any]) -> list[Any]:
        if shape in FIELD_SHAPES:
            return [_wrong_typed(item, shape) for item in items]
        return list(SCALAR_ITEMS) if shape == "scalars" else [None, *items, None]

    if isinstance(body, list):
        return lst(body)
    if not isinstance(body, dict):
        return body
    out = dict(body)
    for k, v in body.items():
        if k in FRAMING:
            continue
        if isinstance(v, list):
            out[k] = lst(v)
        elif k == "data" and isinstance(v, dict):
            out[k] = {ik: lst(iv) if isinstance(iv, list) else iv for ik, iv in v.items()}
    return out


# What each body mode decodes to on the client side (``client.decode_body``).
DECODED_BODIES: dict[str, Any] = {
    "empty": None,
    "text": "probe-write-text",
    **BARE_JSON_BODIES,
}


def request_json(req: Any) -> Any:
    """The decoded JSON body of an httpx request, or None (the write classifier
    is body-aware for metadata-only Classic commands)."""
    try:
        return json.loads(req.content) if req.content else None
    except (ValueError, UnicodeDecodeError):
        return None


@dataclass
class Served:
    method: str
    path: str
    status: int
    body: Any
    resolution: bool
    sent_json: Any = None
    query: str = ""
    api_key: str = ""
    #: The path as sent on the wire (percent-escapes kept); ``path`` is decoded.
    raw_path: str = ""


_PROTECT_BACKUP_LIST = "/proxy/protect/api/backups"
_PROTECT_BACKUP_ITEM = "/proxy/protect/api/backup/"


@dataclass
class FakeUpstream:
    """Callable transport handler; records every request it serves."""

    mode: str = "normal"  # normal | paged | big | error
    error_status: int = 500
    error_body: str = ""
    error_resolution: bool = False
    page_items: int = 3
    big_items: int = 10_000
    hosts_by_key: dict[str, list[dict[str, Any]]] | None = None
    clamp_limit: int | None = None  # paged mode: upstream serves at most this many per page
    ignore_offset: bool = False  # paged mode: upstream always answers the first page
    site_count: int = 1  # sites per console (and consoles per key) for fan-out tools
    repeat_pages: bool = False  # paged mode: every paging style keeps answering "more"
    # Page only the console / Site Manager site enumeration lists (/v1/hosts, /v1/sites),
    # so an opt-in cap that stops only the enumeration is exercised on its own.
    page_resolution: bool = False
    transport_error: bool = False  # non-resolution requests fail at the transport
    # What every write verb answers with: "json" (a record), "empty" (204, no body),
    # "text" (a non-JSON body), or a bare JSON value that is not an object: "true",
    # "int" (7) or "list" ([]). The write still lands in ``overlay``.
    write_body: str = "json"
    scalar_body: bool = False  # non-resolution JSON GETs answer a bare JSON string
    # What non-resolution JSON GETs answer with instead of a record body: "json" (normal),
    # "empty" (200 with no body, decoded to None), "text" (a non-JSON body), or a bare
    # JSON value that is not an object: "true", "int" (7) or "list" ([]).
    get_body: str = "json"
    cursor_cycle: bool = False  # paged mode: cursor protocols cycle A, B, A, B, ...
    # Every non-resolution list GET (not a detail read), and every query POST that asks
    # for a page in its JSON body (``pageNumber`` / ``page``), answers its records as a
    # bare JSON array of ``page_items`` records, with no envelope.
    bare_pages: bool = False
    # Resolution lists whose path ends with one of these suffixes answer their records
    # as a bare JSON array too (a tool whose own list is a resolution route).
    bare_resolution: tuple[str, ...] = ()
    missing_cursor: bool = False  # paged mode: cursor protocols say "more" with no cursor
    failing_keys: frozenset[str] = frozenset()
    # paged mode: offset envelopes omit totalCount (the upstream reports no total)
    omit_total: bool = False
    # keys whose Site Manager list endpoints (/v1/hosts, /v1/sites, /v1/devices) answer
    # with a non-object list item: one key's bad shape must stay that key's error
    junk_keys: frozenset[str] = frozenset()
    # Keys that do not hold the requested object: their non-resolution requests get 404.
    missing_keys: frozenset[str] = frozenset()
    # Non-resolution requests whose path contains one of these fragments answer 500
    # (an auxiliary read failing while the tool's own read succeeds).
    fail_paths: tuple[str, ...] = ()
    # Suffix each probe with a non-secret key fingerprint so a multi-key result shows
    # which key each record came from.
    tag_keys: bool = False
    # Big mode for the console / site enumeration lists themselves (list_hosts and
    # friends): 10,000 entries, one carrying a > 1 MB field.
    big_resolution: bool = False
    # Every write verb answers this status (with ``error_body``) instead of landing: a 429
    # here proves a write is sent once.
    write_status: int | None = None
    # Non-resolution GETs served AFTER the first write answer 500: a write's read-after
    # fails while the write itself succeeded.
    fail_reads_after_write: bool = False
    # Every list-shaped JSON body (a records array inside an object envelope) gains the
    # top-level ``ENVELOPE_PROBE_KEY``; ``envelope_extra`` adds further top-level keys.
    envelope_probe: bool = False
    envelope_extra: dict[str, Any] = field(default_factory=dict)
    # "scalars" / "nulls": every JSON GET answers its record lists reshaped (see
    # ``reshape_items``); resolution lists (/v1/hosts, /v1/sites, the console site list)
    # included.
    item_shape: str | None = None
    # A ``PAGING_SHAPES`` entry: every JSON GET body's pagination controls wrong-typed
    # (see ``poison_paging``); ``poisoned`` collects the control names served.
    paging_shape: str | None = None
    # Every JSON GET object body keeps only its record arrays and paging controls: no
    # ``traceId`` / ``httpStatusCode`` / other envelope fields (an envelope-less key).
    bare_envelope: bool = False
    paging_resolution: bool = True  # False: poison only the tool's own (non-resolution) reads
    # Every non-resolution Classic request (``/proxy/network/api/...``) answers HTTP 200
    # with this body (a Classic ``{meta: {rc: "error", msg}, data}`` rejection), sent as
    # compact JSON; ``classic_rc_methods`` limits it to those HTTP methods (None: all).
    classic_rc_body: Any = None
    classic_rc_methods: tuple[str, ...] | None = None
    # A complete documented InnerSpace project document for shape-specific
    # large-body checks.  This is kept separate from the generic list generator.
    project_body: dict[str, Any] | None = None
    poisoned: set[str] = field(default_factory=set)
    served: list[Served] = field(default_factory=list)
    recorded_routes: dict[RecordedKey, dict[str, Any]] = field(default_factory=load_recorded)
    recording_scenario: str | None = None
    recording_status: int | None = None
    # Synthetic property scenarios opt out explicitly; captures are never supplemented.
    replay_recordings: bool = True
    # Per-test named synthetic fixtures; never mixed into a captured response.
    synthetic_routes: dict[tuple[str, str], str] = field(default_factory=dict)
    # Fields written by PUT/PATCH/POST bodies, reflected by later reads of record 0 (so a
    # tool's read-after-write verification sees its write, like a real controller).
    overlay: dict[str, Any] = field(default_factory=dict)
    shortcut_overlays: dict[str, dict[str, Any]] = field(default_factory=dict)
    # paged mode: every multi-page query served, keyed (api key, path, non-paging
    # params) -> {"pages": page indices served, "last": the final page was served}.
    # Proves a drain reached the LAST page, not only that served records came back.
    page_log: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)

    # ---------------------------------------------------------------- helpers
    _PAGING_KEYS = frozenset({"offset", "limit", "cursor", "nextToken", "page", "pageSize"})

    def _note_page(self, req: httpx.Request, idx: Any, last: bool) -> None:
        params = parse_qsl(req.url.query.decode())
        rest = "&".join(f"{k}={v}" for k, v in sorted(params) if k not in self._PAGING_KEYS)
        entry = self.page_log.setdefault(
            (req.headers.get("x-api-key", ""), req.url.path, rest), {"pages": set(), "last": False}
        )
        entry["pages"].add(idx)
        entry["last"] = entry["last"] or last

    def undrained(self) -> list[str]:
        """Multi-page queries whose final page was never requested (a drain that
        stopped early). Meaningful for plain paged mode only."""
        return [
            f"{path}{'?' + rest if rest else ''}: stopped after page(s) "
            f"{sorted(map(str, e['pages']))}, final page never read"
            for (_key, path, rest), e in self.page_log.items()
            if not e["last"]
        ]

    def _rec(self, n: int, tag: str) -> dict[str, Any]:
        rec = make_record(n, tag)
        if "/rest/portconf" in tag:
            # Port profiles reference networks by networkconf id (as a real controller's
            # do), so a read resolves them under the additive ``_resolved_networks`` key.
            rec["native_networkconf_id"] = ARG_HEX
            rec["excluded_networkconf_ids"] = [f"{0x1001:024x}"]
        if n == 0 and tag.endswith("/rest/networkconf"):
            # A networkconf record carries the Integration id as external_id and a purpose
            # (as a real controller's do); record 0 stands in for a site-to-site tunnel so
            # the purpose-scoped tunnel writes resolve the harness id (VPN servers and WANs
            # resolve through the recorded networkconf fixture).
            rec["external_id"] = ARG_ID
            rec["purpose"] = "site-vpn"
        if n == 1 and tag.endswith("/rest/networkconf"):
            rec["external_id"] = VPN_SERVER_EXTERNAL_ID
            rec["purpose"] = "remote-user-vpn"
        elif n == 2 and tag.endswith("/rest/networkconf"):
            rec["external_id"] = "00000000-0000-4000-9000-0000000000c1"
            rec["purpose"] = "vpn-client"
        elif n == 3 and tag.endswith("/rest/networkconf"):
            rec["external_id"] = "00000000-0000-4000-b000-000000fa0040"
            rec["purpose"] = "wan"
        elif n > 3 and tag.endswith("/rest/networkconf"):
            rec["purpose"] = "vpn-client"
        if n == 0 and tag.endswith(
            ("/v2/api/site/default/acl-rules", "/v2/api/site/default/firewall/zone")
        ):
            # A v2 ACL rule or firewall zone carries the Integration id as external_id (live).
            rec["external_id"] = ARG_ID
        if "/stat/device" in tag or "/rest/device" in tag:
            # Capabilities/table are an exact live AP capture; keep generated identifiers
            # and probes so every property mode still exercises the generic invariants.
            ap = recorded("ap_radio_table.json")["body"]["data"][0]
            rec["radio_table"] = copy.deepcopy(ap["radio_table"])
            rec["radio_table_stats"] = copy.deepcopy(ap["radio_table_stats"])
        if tag.endswith(("/ptz/preset", "/ptz/patrol")):
            # A PTZ preset/patrol list identifies each record by its integer slot.
            rec["slot"] = ARG_SLOT + n
        if re.search(r"/proxy/protect/api/cameras/[^/]+$", tag):
            # A private camera object carries its shortcuts, each with a string id; the
            # ARG_ID shortcut reflects the written fields like record 0 does.
            rec["shortcuts"] = [
                {
                    "id": ARG_ID,
                    "name": ARG_NAME,
                    **copy.deepcopy(self.shortcut_overlays.get(tag, {})),
                }
            ]
        if n == 0 and self.overlay:
            rec.update(copy.deepcopy(self.overlay))
        return rec

    def _record(self, req: httpx.Request, status: int, body: Any, resolution: bool) -> None:
        sent = None
        if req.content:
            try:
                sent = json.loads(req.content)
            except ValueError:
                sent = None
        self.served.append(
            Served(
                req.method,
                req.url.path,
                status,
                body,
                resolution,
                sent,
                req.url.query.decode(),
                req.headers.get("x-api-key", ""),
                req.url.raw_path.decode("ascii").split("?", 1)[0],
            )
        )

    def primary(self) -> list[Served]:
        ok = [s for s in self.served if 200 <= s.status < 300]
        main = [s for s in ok if not s.resolution]
        return main or ok

    def writes(self) -> list[Served]:
        return [s for s in self.served if is_write_request(s.method, s.path, s.sent_json)]

    def _items(self, path: str, count: int) -> list[dict[str, Any]]:
        if path.endswith("/rest/networkconf"):
            # One collection resolves four different target kinds. A normal synthetic
            # response must include each kind just as the native capture does.
            count = max(count, 4)
        return [self._rec(i, path) for i in range(count)]

    # ---------------------------------------------------------------- bodies
    def _resolution_body(self, req: httpx.Request, key: str) -> Any:
        path = req.url.path
        if "/proxy/" in path:
            body = copy.deepcopy(_PROXY_SITES)
            for i in range(1, self.site_count):
                extra = copy.deepcopy(body["data"][0])
                extra["id"] = f"00000000-0000-4000-9000-{i:012x}"
                extra["name"] = extra["internalReference"] = f"fanout{i}"
                body["data"].append(extra)
            body["count"] = body["totalCount"] = len(body["data"])
            return body
        if path.endswith("/v1/hosts"):
            hosts = self.hosts_by_key.get(key, []) if self.hosts_by_key else _HOSTS["data"]
            hosts = copy.deepcopy(hosts)
            for i in range(1, self.site_count if hosts else 0):
                extra = copy.deepcopy(hosts[0])
                extra["id"] = f"{i:054X}FC{i:04X}:{i:010d}"
                extra["reportedState"] = dict(
                    extra["reportedState"], hostname=f"fanout-{i}", name=f"fanout-{i}"
                )
                hosts.append(extra)
            return {"data": hosts, "httpStatusCode": 200, "traceId": "t"}
        if path.endswith("/v1/sites"):
            body = copy.deepcopy(recorded("site_manager/v1_sites.json")["body"])
            if self.hosts_by_key:
                tmpl = body["data"][0]
                body["data"] = []
                for h in self.hosts_by_key.get(key, []):
                    site = copy.deepcopy(tmpl)
                    site["hostId"] = h["id"]
                    site["siteId"] = "aa" + h["id"][-22:].replace(":", "0").lower().rjust(22, "0")
                    body["data"].append(site)
            tmpl = body["data"][0] if body["data"] else None
            for i in range(1, self.site_count if tmpl else 0):
                site = copy.deepcopy(tmpl)
                site["siteId"] = f"{i:024x}"
                site["meta"] = dict(site.get("meta") or {}, name=f"fanout{i}", desc=f"fanout{i}")
                body["data"].append(site)
            return body
        return copy.deepcopy(_PROXY_SITES)

    def _replayed(self, req: httpx.Request) -> dict[str, Any] | None:
        """Select an exact capture. A recorded route never falls back to generated data."""
        route = (req.method, req.url.path)
        candidates = [
            (key, entry) for key, entry in self.recorded_routes.items() if key[:2] == route
        ]
        if len(candidates) > 1 and any("json" in e["request"] for _, e in candidates):
            # Several captures of one command route (Classic cmd/devmgr) differ only by
            # the request body: the recorded body keys select one, and a command no
            # capture recorded gets generated data like any unrecorded route.
            try:
                sent = json.loads(req.content) if req.content else None
            except ValueError:
                sent = None
            candidates = [
                (key, entry)
                for key, entry in candidates
                if "json" not in entry["request"]
                or (
                    isinstance(sent, dict)
                    and isinstance(entry["request"]["json"], dict)
                    and entry["request"]["json"].items() <= sent.items()
                )
            ]
        if not candidates:
            if self.recording_scenario is not None or self.recording_status is not None:
                raise LookupError(f"no recorded route for {route}")
            return None
        query = normalized_query(req.url.query)
        selected = [
            entry
            for key, entry in candidates
            if key[2] == query
            and (self.recording_scenario is None or key[3] == self.recording_scenario)
            and (
                key[4] == self.recording_status
                if self.recording_status is not None
                else 200 <= key[4] < 300
            )
        ]
        if len(selected) != 1:
            raise LookupError(
                f"recorded route {route} query {query} has {len(selected)} matches; "
                "select a captured query, recording_scenario and recording_status"
            )
        return selected[0]

    def _generic(self, req: httpx.Request) -> Any:
        path = req.url.path
        if req.method == "POST" and "/system-log/" in path:
            return self._system_log(req)
        fam = family(path)
        if fam == "protect_private" and path.endswith("/bootstrap"):
            # Synthetic bootstrap is the private user's/group's read surface.
            # Its arrays resolve ids; notifications and snooze settings live on users.
            record = self._rec(0, path)

            def member(array: str) -> dict[str, Any]:
                # One record per array (each with its own probe), all carrying the ids the
                # readers resolve: the bootstrap holds distinct objects, not one record
                # five times (a drain-dedup property would read that as repeated pages).
                return {**copy.deepcopy(record), "probe": f"{record['probe']}:{array}"}

            return {
                # The device arrays the Protect bootstrap carries for private-only types.
                "aiports": [member("aiports")],
                "aiprocessors": [member("aiprocessors")],
                "nvr": member("nvr"),
                "groups": [member("groups")],
                "users": [
                    {
                        **member("users"),
                        "notifications": {"name": "probe-object"},
                        "notificationSnoozeSettings": {"validUntil": None},
                    }
                ],
            }
        if fam == "innerspace" and req.method == "GET" and path.endswith("/project"):
            # A project is one document, not a list endpoint. Synthetic paging/fan-out
            # scenarios still need its documented arrays; captured bodies stay untouched.
            count = (
                self.big_items
                if self.mode == "big"
                else self.page_items
                if self.mode == "paged"
                else 1
            )
            shapes = [{**record, "type": "device"} for record in self._items(path, count)]
            if self.mode == "big":
                shapes[-1]["blob"] = "x" * (1024 * 1024 + 7)
            return {
                "data": {
                    "shapes": shapes,
                    "plans": [
                        {
                            **self._rec(0, path + "/plans"),
                            "id": "00000000-0000-4000-8000-000000fa01d6",
                        }
                    ],
                    "products": [],
                    "wallTypes": [],
                    "attenuationObjectTypes": [],
                    "project": {"id": "00000000-0000-4000-8000-000000fa0000", "title": ARG_NAME},
                }
            }
        params = dict(parse_qsl(req.url.query.decode()))
        detail = (
            is_detail(path)
            or path.endswith("/export/prepare")
            or (req.method != "GET" and not ("/stat/" in path or path.endswith("/query")))
        )
        if self.mode == "big":
            n = self.big_items
        elif self.mode == "paged":
            n = None
        else:
            n = 1
        if detail:
            rec = self._rec(0, path if req.method == "GET" else f"{req.method} {path}")
            if self.mode == "big":
                rec["blob"] = "x" * (1024 * 1024 + 7)
            if fam == "classic":
                return {"meta": {"rc": "ok"}, "data": [rec]}
            if fam == "site_manager":
                return {"data": rec, "httpStatusCode": 200, "traceId": "t"}
            return rec
        if fam == "site_manager" and req.method == "POST" and path.endswith("/query"):
            # POST /v1/isp-metrics/{type}/query answers {"data": {"metrics": [...]}} (spec
            # and the recorded fixture); it is not a paged endpoint.
            metrics = self._items(path, n or self.page_items)
            return {"data": {"metrics": metrics}, "httpStatusCode": 200, "traceId": "t"}
        if self.mode == "paged":
            return self._paged(req, fam, params)
        items = self._items(path, n or 1)
        if fam == "integration":
            return {
                "offset": 0,
                "limit": len(items),
                "count": len(items),
                "totalCount": len(items),
                "data": items,
            }
        if fam == "classic":
            return {"meta": {"rc": "ok"}, "data": items}
        if fam == "site_manager":
            return {"data": items, "httpStatusCode": 200, "traceId": "t"}
        if fam == "protect_private" and (
            "/recognition/" in path or "/cases/" in path and path.endswith("/activity-log")
        ):
            arr = (
                "activities"
                if path.endswith("/activity-log")
                else "detections"
                if path.endswith("/detections")
                else "groups"
            )
            return {arr: items, "links": {"prev": None, "next": None}}
        if fam == "innerspace":
            if path.endswith("/project"):
                # The native project is an object of record arrays, never a
                # collection called "project" (see the captured project body).
                return {"shapes": items, "plans": items, "products": items, "wallTypes": []}
            return {_innerspace_key(path): items}
        return items

    def _system_log(self, req: httpx.Request) -> Any:
        """The Network v2 system-log read-POST (``.../system-log/{class}``): one page
        ``{data, page_number, total_element_count, total_page_count}`` for the JSON body's
        ``pageNumber`` (page protocol in the body, not the query). A recorded system-log page
        is replayed by ``_serve`` before this point, so this serves generated pages only:
        one single-record page in normal mode, three pages in paged mode (every page
        answering page 0 under ``repeat_pages``) and one page of ``big_items`` in big mode."""
        path = req.url.path
        try:
            sent = json.loads(req.content or b"{}")
        except ValueError:
            sent = {}
        number = sent.get("pageNumber") if isinstance(sent, dict) else None
        number = number if isinstance(number, int) and not isinstance(number, bool) else 0
        if self.bare_pages:
            # the bare-page mode: one page of records as a bare JSON array, no envelope
            return self._items(path, self.page_items)
        pages = 3 if self.mode == "paged" else 1
        per = self.big_items if self.mode == "big" else (self.page_items if pages > 1 else 1)
        served = 0 if self.repeat_pages else number
        items = [self._rec(served * per + i, path) for i in range(per)]
        if self.mode == "paged":
            self._note_page(req, served, served + 1 >= pages and not self.repeat_pages)
        # a read-POST page is a list envelope like a GET page: the envelope probe applies
        return self._probe_envelope(
            {
                "data": items,
                "page_number": served,
                "total_element_count": per * (1000 if self.repeat_pages else pages),
                "total_page_count": 1000 if self.repeat_pages else pages,
            }
        )

    def _paged(self, req: httpx.Request, fam: str, params: dict[str, str]) -> Any:
        """Serve a list as >= 3 pages using the protocol that API family really uses."""
        path = req.url.path
        pages = 3
        if fam == "integration":
            limit = int(params.get("limit") or 25)
            offset = (
                0 if self.ignore_offset or self.repeat_pages else int(params.get("offset") or 0)
            )
            if self.clamp_limit is not None:
                limit = min(limit, self.clamp_limit)
            total = limit * (1000 if self.repeat_pages else pages) + 1
            items = [self._rec(i, path) for i in range(offset, min(offset + limit, total))]
            self._note_page(req, offset, offset + limit >= total)
            page = {
                "offset": offset,
                "limit": limit,
                "count": len(items),
                "totalCount": total,
                "data": items,
            }
            if self.omit_total:
                del page["totalCount"]
            return page
        if "offset" in params and fam != "integration":
            # offset/limit paging on a bare list (Protect events) or a Site Manager-style
            # envelope (Mobility collections)
            limit = int(params.get("limit") or 25)
            offset = 0 if self.ignore_offset or self.repeat_pages else int(params["offset"])
            total = limit * (1000 if self.repeat_pages else pages) + 1
            items = [self._rec(i, path) for i in range(offset, min(offset + limit, total))]
            self._note_page(req, offset, offset + limit >= total)
            if fam == "site_manager":
                envelope = {
                    "offset": offset,
                    "limit": limit,
                    "count": len(items),
                    "totalCount": total,
                    "data": items,
                }
                if self.omit_total:
                    del envelope["totalCount"]
                return envelope
            return items
        if path.endswith("/v1/carrier/subscribers"):  # service-plans is unpaginated
            cursor = params.get("cursor")
            per = self.page_items
            if self.cursor_cycle:
                idx = {None: 0, "cA": 1, "cB": 2}[cursor]
                nxt: str | None = "cB" if cursor == "cA" else "cA"
            elif self.repeat_pages:
                idx, nxt = 0, "c1"  # the same page and the same cursor, forever
            else:
                idx = int(cursor[1:]) if cursor else 0
                nxt = f"c{idx + 1}" if idx + 1 < pages else None
            meta: dict[str, Any] = {"limit": per, "hasMore": nxt is not None}
            if nxt is not None and not self.missing_cursor:
                meta["nextCursor"] = nxt
            items = [self._rec(idx * per + i, path) for i in range(per)]
            self._note_page(req, idx, nxt is None)
            return {"data": items, "meta": meta, "traceId": "t"}
        if fam == "site_manager" and path not in NEXT_TOKEN_PATHS:
            # the published specs page no other Site Manager-style list (isp-metrics,
            # sd-wan-configs, Mobility workspaces/admins, Carrier service-plans): one
            # complete body, so "drained to the final page" is only asked of real paging
            items = self._items(path, self.page_items * pages)
            return {"data": items, "httpStatusCode": 200, "traceId": "t"}
        if fam == "site_manager":
            token = params.get("nextToken") or "p0"
            per = self.page_items
            if self.cursor_cycle and path in NEXT_TOKEN_PATHS:  # p0 -> pA -> pB -> pA ...
                idx = {"p0": 0, "pA": 1, "pB": 2}[token]
                items = [self._rec(idx * per + i, path) for i in range(per)]
                nxt_token = "pB" if token == "pA" else "pA"
                return {"data": items, "nextToken": nxt_token, "httpStatusCode": 200}
            idx = 0 if self.repeat_pages else int(token[1:])
            items = [self._rec(idx * per + i, path) for i in range(per)]
            body: dict[str, Any] = {"data": items, "httpStatusCode": 200, "traceId": "t"}
            if self.repeat_pages:
                body["nextToken"] = "p1"  # the same cursor, forever
            elif idx + 1 < pages:
                body["nextToken"] = f"p{idx + 1}"
            self._note_page(req, idx, "nextToken" not in body)
            return body
        if fam == "protect_private" and (
            "/recognition/" in path
            and path.endswith(("/groups", "/detections"))
            or "/cases/" in path
            and path.endswith("/activity-log")
        ):
            page = 1 if self.repeat_pages else int(params.get("page") or 1)
            per = int(params.get("pageSize") or self.page_items)
            items = [self._rec((page - 1) * per + i, path) for i in range(per)]
            nxt = f"{path}?page={page + 1}" if page < pages or self.repeat_pages else None
            arr = (
                "activities"
                if path.endswith("/activity-log")
                else "detections"
                if path.endswith("/detections")
                else "groups"
            )
            self._note_page(req, page, nxt is None)
            return {arr: items, "links": {"prev": None, "next": nxt}}
        if fam == "protect_private" and "/recognition/" in path:
            # recognition reads with no page protocol (groups/counts): one complete body
            items = self._items(path, self.page_items * pages)
            return {"groups": items, "links": {"prev": None, "next": None}}
        # Families with no paging protocol (Classic REST, v2, Protect integration):
        # a single complete body.
        items = self._items(path, self.page_items * pages)
        if fam == "classic":
            return {"meta": {"rc": "ok"}, "data": items}
        if fam == "innerspace":
            return {_innerspace_key(path): items}
        return items

    # ---------------------------------------------------------------- transport
    def __call__(self, req: httpx.Request) -> httpx.Response:
        self._last_synthetic = False
        response = self._serve(req)
        if req.method == "GET" and self._last_synthetic:
            response = self._without_deleted_routing(req, response)
            response = self._without_deleted_batches(req, response)
            if req.url.path.endswith(_PROTECT_BACKUP_LIST):
                response = self._without_deleted_backups(response)
        return response

    def _without_deleted_batches(
        self, req: httpx.Request, response: httpx.Response
    ) -> httpx.Response:
        """Reflect successful synthetic QoS/WireGuard batch posts in their exact collection.

        Caller ids remain case-sensitive, as sent; captured responses are never altered.
        """
        match = re.fullmatch(
            r"(.*?/proxy/network/v2/api/site/[^/]+)/(qos-rules|wireguard/[^/]+/users)",
            req.url.path,
        )
        if not match or "json" not in response.headers.get("content-type", ""):
            return response
        route = req.url.path + ("/batch-delete" if match[2] == "qos-rules" else "/batch_delete")
        gone = set()
        for served in self.served:
            if served.method != "POST" or served.path != route or not 200 <= served.status < 300:
                continue
            if not isinstance(served.sent_json, list):
                continue
            for item in served.sent_json:
                identifier = item.get("_id") if isinstance(item, dict) else item
                if isinstance(identifier, str):
                    gone.add(identifier)
        if not gone:
            return response
        body = response.json()
        rows = body.get("data") if isinstance(body, dict) else body
        if not isinstance(rows, list):
            return response
        kept = [row for row in rows if not isinstance(row, dict) or row.get("_id") not in gone]
        filtered = {**body, "data": kept} if isinstance(body, dict) else kept
        self.served[-1].body = filtered
        return httpx.Response(response.status_code, json=filtered)

    def _without_deleted_routing(
        self, req: httpx.Request, response: httpx.Response
    ) -> httpx.Response:
        """Reflect successful synthetic routing deletes only in their own collection."""
        path = req.url.path
        match = re.fullmatch(
            r"(.*?/proxy/network/v2/api/site/[^/]+)/(bgp/config/all|bgp/config|ospf/router)", path
        )
        if not match or "json" not in response.headers.get("content-type", ""):
            return response
        base, collection = match.groups()
        gone: set[str] = set()
        for served in self.served:
            if served.method != "DELETE" or not 200 <= served.status < 300:
                continue
            if collection.startswith("bgp/"):
                prefix = base + "/bgp/config/"
                if served.path.startswith(prefix):
                    gone.add(served.path[len(prefix) :].lower())
                elif served.path == base + "/bgp/config":
                    # The singleton identity was read before its DELETE.
                    for read in self.served:
                        if read is served:
                            break
                        if read.method == "GET" and read.path == served.path and read.status < 300:
                            for row in upstream_records(read.body):
                                if isinstance(row, dict):
                                    gone.update(
                                        str(row[f]).lower() for f in ("_id", "id") if row.get(f)
                                    )
            else:
                prefix = base + "/ospf/router/"
                if served.path.startswith(prefix):
                    gone.add(served.path[len(prefix) :].lower())
        if not gone:
            return response
        body = response.json()

        def keep(rows: list[Any]) -> list[Any]:
            return [
                row
                for row in rows
                if not (
                    isinstance(row, dict)
                    and any(str(row.get(f, "")).lower() in gone for f in ("_id", "id"))
                )
            ]

        if isinstance(body, list):
            filtered = keep(body)
        elif isinstance(body, dict) and isinstance(body.get("data"), list):
            filtered = {**body, "data": keep(body["data"])}
        elif isinstance(body, dict):
            filtered = body if keep([body]) else []
        else:
            return response
        self.served[-1].body = filtered
        return httpx.Response(response.status_code, json=filtered)

    def _without_deleted_backups(self, response: httpx.Response) -> httpx.Response:
        """A Protect backup deleted with ``DELETE /backup/{id}`` (the route Protect 7.3.74
        serves; observed live 2026-10-28) is no longer listed by a synthetic ``GET /backups``.

        Captured responses are never altered; the served record holds the filtered body.
        """
        gone = {
            s.path.rsplit("/", 1)[1]
            for s in self.served
            if s.method == "DELETE" and _PROTECT_BACKUP_ITEM in s.path and s.status < 300
        }
        if not gone or "json" not in response.headers.get("content-type", ""):
            return response
        body = response.json()

        def keep(rows: Any) -> Any:
            if not isinstance(rows, list):
                return rows
            return [r for r in rows if not (isinstance(r, dict) and r.get("id") in gone)]

        if isinstance(body, dict):
            body = {k: keep(v) for k, v in body.items()}
        else:
            body = keep(body)
        self.served[-1].body = body
        return httpx.Response(response.status_code, json=body)

    def _serve(self, req: httpx.Request) -> httpx.Response:
        key = req.headers.get("x-api-key", "")
        path = req.url.path
        resolution = is_resolution(path) and req.method == "GET"
        if (
            self.classic_rc_body is not None
            and not resolution
            and family(path) == "classic"
            and (self.classic_rc_methods is None or req.method in self.classic_rc_methods)
        ):
            body = copy.deepcopy(self.classic_rc_body)
            self._record(req, 200, body, False)
            return httpx.Response(
                200,
                content=json.dumps(body, separators=(",", ":")).encode(),
                headers={"content-type": "application/json"},
            )
        if key in self.failing_keys:
            body = {"code": "forbidden", "message": f"key {key} lacks scope", "traceId": "t"}
            self._record(req, 403, body, resolution)
            return httpx.Response(403, json=body)
        if key in self.junk_keys and req.method == "GET" and path in JUNK_PATHS:
            body = {"data": ["probe-junk-item"], "httpStatusCode": 200, "traceId": "t"}
            self._record(req, 200, body, resolution)
            return httpx.Response(200, json=body)
        if not resolution and key in self.missing_keys:
            body = {"code": "not_found", "message": f"no such object under {key}", "traceId": "t"}
            self._record(req, 404, body, False)
            return httpx.Response(404, json=body)
        if (
            self.write_status is not None
            and not resolution
            and is_write_request(req.method, path, request_json(req))
        ):
            body = self.error_body or '{"error":"probe write status"}'
            self._record(req, self.write_status, body, False)
            return httpx.Response(
                self.write_status,
                content=body.encode(),
                headers={"content-type": "application/json"},
            )
        if (
            self.fail_reads_after_write
            and req.method == "GET"
            and not resolution
            and any(is_write_request(s.method, s.path, s.sent_json) for s in self.served)
        ):
            body = {"code": "server_error", "message": f"probe read-after failure on {path}"}
            self._record(req, 500, body, False)
            return httpx.Response(500, json=body)
        if not resolution and any(frag in path for frag in self.fail_paths):
            body = {"code": "server_error", "message": f"probe failure on {path}"}
            self._record(req, 500, body, False)
            return httpx.Response(500, json=body)
        if self.transport_error and (self.error_resolution or not resolution):
            self._record(req, 0, None, resolution)
            raise httpx.ConnectError("probe connect failure", request=req)
        if (
            self.project_body is not None
            and req.method == "GET"
            and path.endswith("/innerspace/integration/v1/project")
        ):
            body = copy.deepcopy(self.project_body)
            self._record(req, 200, body, False)
            return httpx.Response(200, json=body)
        if resolution and self.mode == "shape" and self.error_resolution:
            body = {"unexpectedShape": "probe-shape"}
            self._record(req, 200, body, True)
            return httpx.Response(200, json=body)
        explicit_capture = self.recording_scenario is not None or self.recording_status is not None
        synthetic_topology = (
            self.hosts_by_key is not None or self.site_count != 1 or self.page_resolution
        )
        synthetic_body = not resolution and (
            self.scalar_body or self.get_body != "json" or self.write_body != "json"
        )
        if explicit_capture or (
            self.replay_recordings
            and self.mode == "normal"
            and not synthetic_topology
            and not synthetic_body
        ):
            synthetic = self.synthetic_routes.get((req.method, req.url.path))
            if synthetic is not None and not explicit_capture:
                entry = json.loads(
                    (Path(__file__).parent / "fixtures" / "synthetic" / synthetic).read_text()
                )
            else:
                entry = self._replayed(req)
            if entry is not None:
                if "body" not in entry:
                    content = (
                        entry["text"].encode() if "text" in entry else b"\0" * entry["binary_len"]
                    )
                    self._record(req, entry["status"], content, is_resolution(req.url.path))
                    return httpx.Response(
                        entry["status"],
                        content=content,
                        headers={"content-type": entry_content_type(entry)},
                    )
                body = copy.deepcopy(entry["body"])
                resolution = is_resolution(req.url.path) and req.method == "GET"
                if req.method == "GET":
                    body = self._probe_envelope(body)
                    if self.item_shape:
                        body = reshape_items(body, self.item_shape)
                    if self.bare_envelope:
                        body = bare_envelope(body)
                    if self.paging_shape and (not resolution or self.paging_resolution):
                        body, hit = poison_paging(body, self.paging_shape)
                        self.poisoned |= hit
                if self.tag_keys:
                    _tag_probes(body, req.headers.get("x-api-key", ""))
                self._record(req, entry["status"], body, resolution)
                return httpx.Response(
                    entry["status"],
                    content=json.dumps(body),
                    headers={"content-type": entry_content_type(entry)},
                )
        if resolution and not (self.mode == "error" and self.error_resolution):
            if self.mode == "paged" or self.page_resolution:
                body = self._paged_resolution(req, key)
            else:
                body = self._resolution_body(req, key)
            if self.big_resolution:
                body = self._big_resolution(path, body)
            if self.bare_resolution and path.endswith(self.bare_resolution):
                body = upstream_records(body)
            body = self._probe_envelope(body)
            if self.item_shape:
                body = reshape_items(body, self.item_shape)
            if self.bare_envelope:
                body = bare_envelope(body)
            if self.paging_shape and self.paging_resolution:
                body, hit = poison_paging(body, self.paging_shape)
                self.poisoned |= hit
            self._record(req, 200, body, True)
            return httpx.Response(200, json=body)
        if self.mode == "error" and (self.error_resolution or not resolution):
            self._record(req, self.error_status, self.error_body, False)
            return httpx.Response(
                self.error_status,
                content=self.error_body.encode(),
                headers={"content-type": "application/json"},
            )
        if (
            # an asset download (InnerSpace GET /v1/assets/{planId}/{file}) is binary; a
            # JSON write to an asset record (PATCH/DELETE /cases/{id}/assets/{assetId})
            # falls through to the write-body/status contracts like any other write
            (req.method == "GET" and "/assets/" in path)
            or path.endswith(("/snapshot", "/thumbnail", "/video/export"))
            or (req.method == "GET" and path.endswith("/image"))
            or ("/thumbnails/" in path)
            or (req.method == "GET" and path.endswith("/recognition/vehicle/groups/template"))
            or (req.method == "GET" and "/protect/api/files/" in path)
        ):
            # every byte value, in order, so a dropped, altered or re-encoded byte shows
            content = b"\x89PNG\r\n" + bytes(range(256)) * (8192 if self.mode == "big" else 1)
            self._record(req, 200, content, False)
            return httpx.Response(
                200,
                content=content,
                headers={
                    "content-type": "video/mp4" if path.endswith("/video/export") else "image/png"
                },
            )
        if self.mode == "shape" and not resolution:
            body = {"unexpectedShape": "probe-shape"}
            self._record(req, 200, body, False)
            return httpx.Response(200, json=body)
        if self.scalar_body and not resolution and req.method == "GET":
            self._record(req, 200, "probe-scalar", False)
            return httpx.Response(200, json="probe-scalar")
        if (
            self.bare_pages
            and not resolution
            and not is_detail(path)
            and (req.method == "GET" or (req.method == "POST" and _asks_for_a_page(req)))
        ):
            page = self._items(path, self.page_items)
            self._record(req, 200, page, False)
            return httpx.Response(200, json=page)
        if self.get_body != "json" and not resolution and req.method == "GET":
            if self.get_body == "empty":
                self._record(req, 200, None, False)
                return httpx.Response(200)
            if self.get_body in BARE_JSON_BODIES:
                value = BARE_JSON_BODIES[self.get_body]
                self._record(req, 200, value, False)
                return httpx.Response(200, json=value)
            self._record(req, 200, "probe-get-text", False)
            return httpx.Response(200, text="probe-get-text")
        if self.write_body != "json" and is_write_request(req.method, path, request_json(req)):
            if req.content:
                try:
                    sent = json.loads(req.content)
                except ValueError:
                    sent = None
                if isinstance(sent, dict):
                    self.overlay.update({k: v for k, v in sent.items() if not isinstance(v, dict)})
            if self.write_body == "empty":
                self._record(req, 204, None, False)
                return httpx.Response(204)
            if self.write_body in BARE_JSON_BODIES:
                value = BARE_JSON_BODIES[self.write_body]
                self._record(req, 200, value, False)
                return httpx.Response(200, json=value)
            self._record(req, 200, "probe-write-text", False)
            return httpx.Response(200, text="probe-write-text")
        self._last_synthetic = True
        body = self._generic(req)
        if req.method == "GET":
            body = self._probe_envelope(body)
        if self.tag_keys:
            _tag_probes(body, key)
        if self.item_shape and req.method == "GET":
            body = reshape_items(body, self.item_shape)
        if self.bare_envelope and req.method == "GET":
            body = bare_envelope(body)
        if self.paging_shape and req.method == "GET":
            body, hit = poison_paging(body, self.paging_shape)
            self.poisoned |= hit
        self._record(req, 200, body, False)
        if req.method in ("PUT", "PATCH", "POST") and is_write_request(
            req.method, path, request_json(req)
        ):
            sent = self.served[-1].sent_json
            if isinstance(sent, dict):
                self.overlay.update({k: v for k, v in sent.items() if not isinstance(v, dict)})
            elif (
                req.method == "PATCH"
                and re.fullmatch(r".*/proxy/protect/api/cameras/[^/]+/shortcuts", path)
                and isinstance(sent, list)
            ):
                for shortcut in sent:
                    if isinstance(shortcut, dict) and shortcut.get("id") == ARG_ID:
                        self.shortcut_overlays[path.removesuffix("/shortcuts")] = copy.deepcopy(
                            shortcut
                        )
        return httpx.Response(200, json=body)

    def _probe_envelope(self, body: Any) -> Any:
        """``body`` with the envelope-probe keys added, when it is a list envelope."""
        if not (self.envelope_probe or self.envelope_extra) or not isinstance(body, dict):
            return body
        records = upstream_records(body)
        if len(records) == 1 and records[0] is body:
            return body  # an object body, not a list envelope
        extra = dict(self.envelope_extra)
        if self.envelope_probe:
            extra[ENVELOPE_PROBE_KEY] = ENVELOPE_PROBE_VALUE
        return {**body, **extra}

    def _big_resolution(self, path: str, body: Any) -> Any:
        """The enumeration list grown to ``big_items`` unique entries (each extra entry
        carrying a ``probe``), the last one holding a > 1 MB field."""
        if not isinstance(body, dict) or not body.get("data"):
            return body
        data = body["data"]
        tmpl = data[0]
        for i in range(len(data), self.big_items):
            # Retain one captured row for shape fidelity, then make filler rows
            # lean.  Some recordings contain large nested statistics trees; copying
            # those 10,000 times dwarfs the body under test and can exhaust workers.
            if "/proxy/" in path:
                extra = {
                    "id": f"00000000-0000-4000-a000-{i:012x}",
                    "name": f"bulk{i}",
                    "internalReference": f"bulk{i}",
                }
            elif path.endswith("/v1/sites"):
                extra = {
                    "hostId": tmpl.get("hostId"),
                    "siteId": f"{i:024x}",
                    "meta": {"name": f"bulk{i}", "desc": f"bulk{i}"},
                }
            else:
                extra = {
                    "id": f"{i:054X}FD{i:04X}:{i:010d}",
                    "reportedState": {"hostname": f"bulk-{i}", "name": f"bulk-{i}"},
                }
            extra["probe"] = f"{path}#{i}"
            data.append(extra)
        data[-1]["blob"] = "x" * (1024 * 1024 + 7)
        if "count" in body:
            body["count"] = body["totalCount"] = len(data)
        return body

    def _paged_resolution(self, req: httpx.Request, key: str) -> Any:
        """Resolution lists served across pages too (recorded record first)."""
        path = req.url.path
        params = dict(parse_qsl(req.url.query.decode()))
        base = self._resolution_body(req, key)
        if "/proxy/" not in path and base.get("data"):
            token = params.get("nextToken") or "p0"
            if self.cursor_cycle:  # p0 -> pA -> pB -> pA ... (spec nextToken lists)
                idx = {"p0": 0, "pA": 1, "pB": 2}[token]
            else:
                idx = int(token[1:])
            extra = copy.deepcopy(base["data"][0])
            if path.endswith("/v1/sites"):
                extra["siteId"] = f"{idx:024x}"
                extra["meta"] = dict(extra.get("meta") or {}, name=f"filler-{idx}", desc=f"f{idx}")
            else:
                extra["id"] = f"{idx:060X}:{idx:010d}"
                extra["reportedState"] = dict(
                    extra["reportedState"], hostname=f"filler-{idx}", name=f"filler-{idx}"
                )
            data = base["data"] if idx == 0 else [extra]
            body = {"data": data, "httpStatusCode": 200, "traceId": "t"}
            if self.cursor_cycle:
                body["nextToken"] = "pB" if token == "pA" else "pA"
            elif idx + 1 < 3:
                body["nextToken"] = f"p{idx + 1}"
            self._note_page(req, idx, "nextToken" not in body)
            return body
        # the per-console sites list is served complete (resolution only)
        return base


def key_probe_tag(key: str) -> str:
    """Return a per-run keyed fingerprint without exposing configured credentials."""
    return hashlib.blake2b(key.encode(), key=_PROBE_KEY).hexdigest()[:16]


def _tag_probes(node: Any, key: str) -> None:
    """Suffix every record probe with a non-secret per-key fingerprint (in place)."""
    stack = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            if isinstance(cur.get("probe"), str) and "@" not in cur["probe"]:
                cur["probe"] = f"{cur['probe']}@{key_probe_tag(key)}"
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)


def install(
    monkeypatch: Any,
    upstream: FakeUpstream,
    *,
    keys: list[APIKeyConfig] | None = None,
    **settings: Any,
) -> UniFiClient:
    """Install a real client/registry behind every tool, on the fake transport.

    dry_run=True / read_only=True set UNIFI_WRITE_POLICY (dry-run / deny) for
    the test, the write policy being read from the environment at call time.
    """
    if settings.pop("dry_run", False):
        monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    if settings.pop("read_only", False):
        monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    s = Settings(api_keys=keys) if keys else Settings(api_key="k-test", **settings)
    if keys and settings:
        s = Settings(api_keys=keys, **settings)
    client = UniFiClient(s)

    def _new_http_client(self: UniFiClient, key_config: APIKeyConfig) -> httpx.AsyncClient:
        # Only the transport is faked: the real ``_get_client`` still picks the client, so
        # environment keys are cached per (label, key fingerprint) and header mode
        # (UNIFI_KEY_MODE=header) goes through the real per-caller CredentialCache.
        return httpx.AsyncClient(
            base_url=self._settings.api_base_url,
            headers={"X-API-KEY": key_config.key, "Accept": "application/json"},
            transport=httpx.MockTransport(_yielding(upstream)),
            follow_redirects=False,
        )

    monkeypatch.setattr(UniFiClient, "_new_http_client", _new_http_client)
    monkeypatch.setattr(server, "_harness_upstream", upstream, raising=False)
    # Repeated installs (a module that installs at import) must not nest wrappers.
    real_call_tool = getattr(server.mcp.call_tool, "_harness_real", server.mcp.call_tool)

    async def call_tool(name: str, *args: Any, **kwargs: Any) -> Any:
        from tests import tool_args  # tool_args imports this module: resolve lazily

        tool_args.prepare_upstream(name, upstream)
        if args and isinstance(args[0], dict):
            args = (tool_args.resolve_placeholders(name, args[0]), *args[1:])
        elif isinstance(kwargs.get("arguments"), dict):
            kwargs["arguments"] = tool_args.resolve_placeholders(name, kwargs["arguments"])
        return await real_call_tool(name, *args, **kwargs)

    call_tool._harness_real = real_call_tool  # type: ignore[attr-defined]
    monkeypatch.setattr(server.mcp, "call_tool", call_tool)
    monkeypatch.setattr(server, "_settings", s)
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", Registry(client, ttl_seconds=s.cache_ttl_seconds))
    # never actually sleep in collectors / retries
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    return client


_real_sleep = asyncio.sleep


def _yielding(upstream: FakeUpstream) -> Any:
    """Async transport handler that yields to the loop like real network I/O, so
    concurrent fan-out (and any semaphore nesting) actually interleaves."""

    async def handler(req: httpx.Request) -> httpx.Response:
        await _real_sleep(0)
        resp = upstream(req)
        await _real_sleep(0)
        return resp

    return handler


async def _no_sleep(delay: float = 0, result: Any = None) -> Any:
    await _real_sleep(0)
    return result


def parse_query(query: str) -> dict[str, str]:
    """A served request's query string as ``{name: value}`` (last value wins)."""
    return dict(parse_qsl(query, keep_blank_values=True))


# --------------------------------------------------------------------------- results
def result_payload(res: Any) -> Any:
    """The JSON a client receives for a tool result (structured, else parsed text)."""
    sc = getattr(res, "structured_content", None)
    if sc is not None:
        return sc
    blocks = getattr(res, "content", None) or []
    texts = [getattr(b, "text", None) for b in blocks]
    texts = [t for t in texts if t is not None]
    if len(texts) == 1:
        try:
            return json.loads(texts[0])
        except ValueError:
            return texts[0]
    return texts


def _asks_for_a_page(req: httpx.Request) -> bool:
    """A POST whose JSON body selects a page (a paged query sent as POST)."""
    try:
        sent = json.loads(req.content) if req.content else None
    except ValueError:
        return False
    return isinstance(sent, dict) and bool({"pageNumber", "page"} & set(sent))


def upstream_records(body: Any) -> list[Any]:
    """The records an upstream body carries (envelope framing excluded)."""
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        payload_keys = [k for k in body if k not in FRAMING]
        if "data" in body and payload_keys == ["data"]:
            data = body["data"]
            return data if isinstance(data, list) else [data]
        lists = [k for k in payload_keys if isinstance(body[k], list)]
        if len(payload_keys) == 1 and lists:
            return body[lists[0]]
        return [body]
    return [body]


def strip_additive(node: Any, ref: Any) -> Any:
    """Drop documented additive ``_``-prefixed keys the upstream record did not carry."""
    if isinstance(node, dict) and isinstance(ref, dict):
        return {
            k: strip_additive(v, ref.get(k))
            for k, v in node.items()
            if not (k.startswith("_") and k not in ref)
        }
    if isinstance(node, list) and isinstance(ref, list) and len(node) == len(ref):
        return [strip_additive(a, b) for a, b in zip(node, ref, strict=True)]
    return node


_IDENTITY_KEYS = ("probe", "id", "_id", "mac", "key", "siteId")


class PayloadIndex:
    """Identity index over every object in a tool result (fast record lookup)."""

    def __init__(self, payload: Any) -> None:
        self.payload = payload
        self.by_key: dict[tuple[str, str], list[dict]] = {}
        stack = [payload]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for k in _IDENTITY_KEYS:
                    v = node.get(k)
                    if isinstance(v, str | int):
                        self.by_key.setdefault((k, str(v)), []).append(node)
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)

    def find(self, key: str, value: Any) -> list[dict]:
        return self.by_key.get((key, str(value)), [])

    def contains(self, record: Any) -> bool:
        if isinstance(record, dict):
            for k in _IDENTITY_KEYS:
                v = record.get(k)
                if isinstance(v, str | int):
                    return any(
                        c == record or strip_additive(c, record) == record for c in self.find(k, v)
                    )
        return contains_record(self.payload, record)


def contains_record(result: Any, record: Any) -> bool:
    """True if ``record`` appears byte-equal (modulo additive keys) anywhere in result."""
    stack = [result]
    while stack:
        node = stack.pop()
        if node == record or strip_additive(node, record) == record:
            return True
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return False


def contains_text(result: Any, text: str) -> bool:
    """Search string leaves without serializing a potentially huge result."""
    stack = [result]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            if text in node:
                return True
        elif isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return False


def all_strings(obj: Any) -> str:
    return json.dumps(obj, default=str)
