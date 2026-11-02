# Recorded real-response fixtures

Sanitized captures of real upstream responses from a live UniFi console, recorded
with reads, an explicitly authorized voucher create/delete acceptance check and the explicitly
authorized, reversible camera-share round trip described below. One file per captured
request/scenario/status, grouped by API family (`site_manager`,
`network_integration`, `network_classic`, `network_v2`, `protect`, `innerspace`,
`errors`). Each file holds the request (`method`, `path`, `query`, and `json` for
read-POSTs), the response `status`, `content_type`, and the `body` (or `binary_len`
for binary assets, whose content is not stored).

All identifiers (MACs, IP addresses, UUIDs, ObjectIds, console ids, emails, URLs) are
replaced with stable fakes of the same format, and every free-text value is replaced
with a placeholder; keys, nesting and value types are exactly what the API returns.
Captured pages retain every row, their original row order, and verbatim pagination
controls (`count`, `totalCount`, continuation tokens and links). Lists must never be
trimmed or supplemented with synthetic objects. Capture every later page required
by a continuation; missing recorded queries fail replay rather than generate data.
Console and Integration site identifiers must resolve through the same canonical
host/site captures used by the test registry.

Replay keys include method, path, normalized query, scenario (the relative filename
by default), and status. Error captures are selected explicitly and cannot shadow a
successful response. Text captures retain their text; binary-only captures preserve
content type and length using explicitly synthetic placeholder bytes.

Synthetic lookup and relative-time scenarios live separately under
`tests/fixtures/synthetic/` and are selected only by tests that need those scenarios.

The cross-tool invariant suite (`tests/test_cross_tool_invariants.py`) serves these
bodies through a fake transport so every tool is checked against real response shapes.

Camera-share fixtures (protect/share_*.json) capture the authorized cloud-only
GET off / POST enable / GET on / DELETE disable / GET final off sequence. All five
responses were HTTP 200; final enabled=false. Every string value is a placeholder
or a stable fake, and expiry is synthetic. shareLink is always <redacted>;
redacted_lengths records only its observed length (59), never the bearer URL.
Typed tool wrappers are covered hermetically against these recorded shapes;
the live sequence exercised the dev connector routes before deploying the tools.
