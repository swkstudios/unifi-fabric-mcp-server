# Pagination and filtering

How list tools page, how to ask for a single page, what a partial result looks like, and the server-side `filter` argument. Retry behaviour is in [RETRY.md](RETRY.md). The tool names below are domain tools: in the default `UNIFI_TOOL_MODE=discovery` call them through `call_read_tool` with the same arguments, or set `UNIFI_TOOL_MODE=full` to list them directly.

# Pagination Behavior

List tools return **all available results by default**. The server follows pagination
automatically, draining every page before returning to the caller. For typical queries
("list all sites", "list all clients") you receive a complete result set without any
manual page handling.

## Requesting a record count

A `page_size`, `pageSize` or `limit` on a tool that manages pagination asks for that
many records, or every available record if the collection is smaller. Offset lists, linked-page Protect windows
and logical traffic-flow pages return the exact requested count. Native cursor and
page-number lists retain the full final physical page when their
continuation cannot identify a position inside that page. Their returned count can
exceed the requested count; `_pageSize.returned` reports that count explicitly.
The server collects the result automatically in batches at the console's effective maximum.
For example, a request for 10000 records on a route with a 200-record page maximum
uses as many pages as needed to collect 10000 records or reach the end. The page
maximum limits each upstream request; it does not cap the requested result total.
Oversized page sizes are batched rather than refused by the spec-limit middleware.

Private Protect `/events` and `/detection-nls` have no measured size clamp. A caller's
`limit` is sent unchanged as one request over those live feeds. With no explicit
limit, their offset drains follow every nonempty page until an empty page or an
upstream total proves completion. The Network Integration 200-record maximum
does not apply to these private Protect routes.

The shared pagination helper sends the smaller of the requested size and the known
page maximum, then reads the effective size from the response: the Network
Integration envelope's `limit`, Protect's `links.next` `pageSize`, page-number
metadata and returned rows, or Site Manager's returned rows and `nextToken`.
Offsets advance by the number of records actually returned.

A page is final only on affirmative evidence: the declared total is reached, an echoed limit or size (`limit`, `meta.limit`, `links` pageSize) is larger than the rows returned, the page is empty, or the continuation (`nextToken`, `meta.hasMore`/`nextCursor`, `links.next`, `total_page_count`) is absent or terminal. The response shape is never evidence: an object envelope with neither a total nor a size echo is drained until an empty page exactly like a bare array; a page larger than the sent size is not terminal, and a repeated page is an abort unless the repeated page exceeded the sent size and nothing shows more records exist (no declared total above the records gathered and no continuation that is present and non-terminal), in which case a drain starting at zero may be complete. A requested offset window starting above zero cannot establish its origin from a repeated page, so it remains incomplete with no continuation even when the repeat is oversized; otherwise the repeat stays an abort that keeps the records gathered once, the upstream total verbatim, and a reason naming the evidence.

An offset requested window that fits in one response verifies its next boundary
before returning a numeric continuation when completion is unproven. It requests
one record at that boundary and compares the first probe record with the physical
prefix already delivered. An unconsumed oversized suffix is excluded from this
comparison. A repeated record makes the result incomplete with no continuation,
even if the probe is oversized; an empty probe proves the end; a distinct record
permits the original continuation. Records returned by the boundary check stay out of the data
and raw envelope, while the request counts in `pages` and `_pageSize.sent`. If an
existing page cap leaves no probe slot, the result is cap-incomplete with no
continuation. Network native-position calls remain one verbatim upstream page. Mobility uses
`offset` alone for a native page; with `limit`, it gathers that total starting at
`offset` (zero included), with boundary verification when needed.

Results for a requested size carry additive `_pageSize` metadata, for example:

<!-- doc-provenance: source=file:src/unifi_fabric/shared_shapes/_pagination.py@sha256:71356c581b786c28fdcc056684d1df68a3f58cfbc4f8827b607aa2a979649540 support=0.7.2 citation=file:src/unifi_fabric/shared_shapes/_pagination.py@sha256:71356c581b786c28fdcc056684d1df68a3f58cfbc4f8827b607aa2a979649540 -->
```json
{"_pageSize": {"requested": 275, "sent": [200, 75], "effective": 200, "returned": 275}}
```

`requested` is the caller's logical count. `sent` is the ordered list of actual
physical request sizes, including clamp probes and refetches; it never substitutes
a returned size for a sent size. `effective` is the observed console page size,
and `returned` is the number of records handed back. A deliberately smaller offset
tail does not lower the observed page ceiling. For example, requesting 275 on a
page-number route clamped to 200 can return 400 records with `sent: [275, 200]`,
`effective: 200`, and `returned: 400`. Every returned record is retained when
following its native next page; none is discarded behind that continuation.
With no requested size, list tools continue to drain every page; the general drain
page size is 200, and the system-log drain uses 1000.

For linked-page Protect lists, `page` with `page_size=N` selects the logical
record window `[(page-1)*N, page*N)`: exactly N when that many exist, fewer only
at the end, never more. Resume from `_nextPage` with the same `page_size`.
`page` without `page_size` returns one native console page. An incomplete
logical window has no `_nextPage`; its reason explains how to retry the window.
Traffic-flow continuations instead carry logical offsets and allow count changes.

### Page maxima

The following observations were captured on **2026-10-26**, including Network
11.0.97. Silent clamping means the console accepts the request and reports the
smaller size it actually used.

| API family | Maximum records per page | Evidence and continuation |
| --- | ---: | --- |
| Network Integration v1 list routes | 200 | Measured silent clamp; envelope `limit`, `offset` and `totalCount` |
| Network hotspot vouchers | 1000 | Measured page maximum; offset/limit |
| Protect recognition groups and detections, case activity log | 100 | Recognition groups measured with `links.next` carrying `pageSize=100`; the same helper uses this maximum for these Protect lists |
| Network v2 traffic flows | 5000 | Measured maximum; a larger upstream page size returns HTTP 400, so requests are batched before sending |
| Site Manager `/v1/hosts`, `/v1/sites`, `/v1/devices` | No clamp observed through 10000 | Small-scope measurement; follow `nextToken` rather than assume that 10000 is a guaranteed maximum |
| Carrier Fabric subscribers | 500 | Published spec maximum; not measured because the capture key received HTTP 403 |
| Mobility lists | 200 | Published spec maximum; not measured because the capture key received HTTP 403 |

Site Manager routes return a `nextToken` when another page is available.
A `page_size` request on `list_hosts`, `list_sites` or `list_devices` follows
`nextToken` until the requested count or the end, including when the first response
contains fewer rows than requested. A short or empty page with a fresh token
is followed until the requested count or true end. The default drain remains 200
records per request.

### Opaque cursor continuity

Site Manager `nextToken` and Carrier `meta.nextCursor` are opaque: a token may
encode a page index tied to its physical request size. Neither family sends a
smaller cursor-tail request. Both retain the full final physical page and its
unchanged native token. Sized collections keep the original physical request size
throughout the gather, even when the response reports a smaller effective size.

Both also return an additive `_continuation` opaque **string** that preserves the
native token and the actual wire size that produced it. Pass the entire string
back as `page_token` for Site Manager or `cursor` for Carrier. These tool inputs
remain `string | null`; they do not accept continuation objects. A follow-up may
change the logical `page_size` or `limit`: the stored physical size remains fixed,
so a page-index token cannot move the record boundary. Plain native upstream
strings remain supported for manual pages. Carrier collections may also expose
`_nextCursor`, the native cursor, when a result spans multiple physical pages.
Prefer `_continuation` for a follow-up because it preserves the wire size.

The server encoding is `ufpg1:` followed by unpadded URL-safe base64 of UTF-8 JSON
`{"v":1,"state":{...}}`. The state retains the native cursor and physical size
(`pageToken`/`pageSize` for Site Manager, `cursor`/`limit` for Carrier). Treat this
format as opaque and reuse the returned string. Malformed encoded tokens fail
locally with instructions before any upstream request.

| Endpoint | Continuation choice | Live status |
| --- | --- | --- |
| Site Manager `nextToken` (`list_hosts`, `list_sites`, `list_devices`) | Full final page, native token, and `_continuation` with its original wire size | live confirmation pending |
| Carrier subscribers `nextCursor` | Full final page, native cursor, and `_continuation` with its original wire size | live confirmation pending |

## Choosing a starting position or a single page

Positional paging arguments choose where collection begins:

- **Cursor lists** (Site Manager tools that return a `nextToken`): `page_token` selects
  that token; Carrier
  `list_carrier_subscribers` uses `cursor`. With several API keys, a cursor page
  needs `key_label`, because the cursor belongs to the key that issued it.
- **Offset lists:** `offset` selects the first record to return.
- **Page-number lists:** `page` or `page_number` selects the starting page using
  that tool's documented numbering convention.
- **Network v2 page-number queries** (`get_system_log`, `get_sites_overview`,
  `query_teleport_invitations`): `page` (or `page_number`) is zero-based. With
  `page_size`, the call returns exactly `page_size` records starting at record
  `page * page_size`, gathered across console pages whatever the console page size;
  resume with `_nextPage` and the same `page_size`. Without `page_size`, one request
  returns that console page verbatim. `page_size` alone is page 0: exactly `page_size`
  records from record 0 (fewer only when the collection ends), gathered and trimmed the
  same way. A `_nextPage` from a `page_size` call resumes with the same `page_size`.

A native `offset` or raw cursor selects one verbatim upstream page, with only the
paging arguments supplied by the caller. `limit` alone is a logical requested
total: it keeps batching when a clamp returns fewer records with a continuation,
and offset collectors verify an ambiguous single-response boundary as described
above. A page number or structured
cursor continuation together with a size gathers the logical count from that
position, retaining a full final page where necessary; the Network v2 page-number
queries above return the exact logical window instead. A position without a size
keeps manual single-page behavior and returns the upstream continuation marker.
A manually requested single page returned as a bare JSON array remains that
array.

Traffic-flow `_nextPage` is `{offset, pageSize}`, with `offset` pointing at the
first unreturned record. Pass the whole object as `body.pageNumber`; change
`body.pageSize` to request a different logical count, or omit it to reuse the
previous count. The server translates that offset after observing the console
clamp, including when the record boundary is inside a physical page.

## Partial results when a page cap is set

Requested record totals and default drains honour an explicitly configured
`UNIFI_PAGINATE_MAX_PAGES`, except `query_traffic_flows` and `export_traffic_flows`.
With the setting unset there is no page cap. When its cap is reached before the
requested count or the end, the response includes:

<!-- doc-provenance: source=file:src/unifi_fabric/client.py@sha256:2e872d718e089cb631886c2e3e24e52c7806c4fd464278ba259055c84a9ccd54 support=0.7.2 citation=file:src/unifi_fabric/client.py@sha256:2e872d718e089cb631886c2e3e24e52c7806c4fd464278ba259055c84a9ccd54 -->
```json
{
  "incomplete": true,
  "incompleteReason": "page cap of N reached",
  "data": [...]
}
```

Complete results carry no `incomplete` key. A capped or stopped result also carries a
resume marker (`_nextOffset`, `_nextPage`, `_nextCursor` or `_continuation`) when a
position is known. Check for `"incomplete": true` in results — when present, the data covers only a
subset of what the API holds. A console or site NAME is never resolved against a capped
list (another object with that name may lie past the cap): it fails with `cannot resolve
'<name>' unambiguously: the site/host list is incomplete (UNIFI_PAGINATE_MAX_PAGES=N)`;
an exact id still resolves. Raise or remove the cap (the default is no cap) to
retrieve the full dataset.

`query_traffic_flows` and `export_traffic_flows` are exempt from the cap: they drain
every page the console reports (`has_next` / `total_page_count`) even when
`UNIFI_PAGINATE_MAX_PAGES` is set, so a wide time window is bounded only by loop
detection and the console. To bound one, send `body.pageSize` (a record count) and
resume with the returned `_nextPage` ([MIGRATING-0.7.md](MIGRATING-0.7.md#change-097)).

Loop detection is always active regardless of the cap, and ends the drain with the
pages gathered so far plus `"incomplete": true` and an `incompleteReason` (never an
endless loop, never a result that claims to be complete):

- **Cursor lists** (`nextToken`): a `nextToken` equal to the one just requested (a
  stall), or equal to any cursor already requested in this drain (a cycle such as
  A, B, A).
- **Offset lists** (`offset`/`limit`): a non-empty page that repeats an earlier page, with
  the same record identities (`id`, `_id`, `uuid` or `mac`) or as its prefix (the server
  ignored `offset`), or an empty page before the reported `totalCount` is reached. A page
  that only overlaps gathered records keeps each record once.
- **Page-number lists** (`links.next`): a non-empty page whose records carry the same identities
  (`id`, `_id`, `uuid` or `mac`) as the previous page, even when live fields such as counters differ
  between the two answers; a page whose records have no identity must be identical to the previous one.

An empty page that carries a new, never-requested cursor is followed like any other
page; only the opt-in `UNIFI_PAGINATE_MAX_PAGES` cap bounds a run of such pages.

## Server-side filtering

These 27 Network tools accept an optional `filter` argument:
`get_client_dpi_usage`, `get_controller_stats`, `get_latest_firmware_versions`, `get_site_dpi_usage`,
`list_acl_rules`, `list_all_clients`, `list_clients`, `list_countries`,
`list_dns_policies`, `list_dpi_applications`, `list_dpi_categories`,
`list_firewall_policies`, `list_firewall_zones_proxy`, `list_hotspot_vouchers`,
`list_integration_device_tags`, `list_lags`, `list_local_sites`, `list_mc_lag_domains`, `list_networks`,
`list_pending_devices`, `list_radius_profiles`, `list_site_devices`,
`list_site_to_site_tunnels`, `list_switch_stacks`, `list_traffic_matching_lists`,
`list_vpn_servers` and `list_wifi_broadcasts` (`list_all_clients` sends it to every
site's client list). The expression is forwarded **unchanged** to the upstream
UniFi `filter` query parameter — the server implements no local filter language, so the
controller evaluates the documented grammar and returns its own error for a malformed
expression. Filtering is applied server-side in both full-drain and single-page modes,
so a narrowed query returns a smaller `totalCount`/result set without draining the
unfiltered collection first. When `filter` is omitted the parameter is not sent at all.

<!-- doc-provenance: source=file:src/unifi_fabric/client.py@sha256:2e872d718e089cb631886c2e3e24e52c7806c4fd464278ba259055c84a9ccd54 support=0.7.2 citation=file:src/unifi_fabric/client.py@sha256:2e872d718e089cb631886c2e3e24e52c7806c4fd464278ba259055c84a9ccd54 -->
```text
list_networks(host="HQ", site="Default", filter="vlanId.eq(100)")
list_clients(host="HQ", site="Default", filter="macAddress.eq('AA:BB:CC:DD:EE:FF')")
list_site_devices(host="HQ", site="Default", filter="state.eq('ONLINE')")
```

See the [Network v11.0.97 OpenAPI](https://developer.ui.com/network/v11.0.97/openapi.json)
for the filterable properties and grammar for each collection resource.
