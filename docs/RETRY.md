# Retry and backoff

What the server retries, how it backs off, and what it never retries. See [PAGINATION.md](PAGINATION.md) for paging.

# Retry & Backoff Behavior

**One rule:** only a read via `GET` is retried, and only on HTTP 429. Every other request
is sent **exactly once**, and a 429 is raised at once with the upstream body: `POST`, `PUT`,
`PATCH` and `DELETE` in every product area (the read-only query POSTs and the
`fabric_connector_*` relays included), and a `GET` of a route the upstream acts on. Those
state-changing `GET` routes are the Protect camera `enable-control` and `disable-control`
routes (`protect/api/cameras/{id}/enable-control` and
`protect/api/cameras/{id}/disable-control`); the server treats
such a `GET` as a write, whether `set_camera_control_enabled` or `fabric_connector_get`
sends it. A 429 does not prove the request was not acted on, so an automatic
retry could apply a write, an action or a physical actuation twice; no write is ever sent
twice. The rule is set in one place (`UniFiClient.request`); no tool raises it (the camera
control `GET` passes `max_retries=0`, the rule's own value for it). Retry a write yourself only once you know the first one did not take effect.

## Rate Limit Handling (HTTP 429) for a read via GET

When the UniFi API answers a read via `GET` with HTTP 429 (Too Many Requests), the server waits and retries. On a Site Manager route, if the response carries a usable `Retry-After` header the wait is exactly that long (up to 64 seconds); otherwise the server falls back to **exponential backoff + jitter**. A read through the Fabric connector (`/v1/connector/consoles/{id}/...`) follows [Connector pacing](#connector-pacing) instead: the `Retry-After` exactly, or one 60 second window, within 120 seconds per call.

- **`Retry-After`**: the pinned Site Manager API spec declares this header on the 429 response of 14 operations, the five `/v1/connector/consoles/{id}/*path` verbs among them. The value is either delay-seconds (`Retry-After: 7`) or an HTTP date (`Retry-After: Sun, 08 Nov 2026 12:00:30 GMT`; a date already past is a zero wait). It replaces the backoff and jitter for that wait, up to the server's own backoff ceiling of 64 seconds. A longer `Retry-After` is not slept: the read stops and the `RateLimitError` shows the header value so the caller can retry after it (on a Fabric connector route the wait follows [Connector pacing](#connector-pacing) instead). A missing, empty, negative or unparsable value is ignored and the backoff below applies. On a Site Manager route the attempt count is unchanged (6 attempts); a connector read follows [Connector pacing](#connector-pacing).
- **When the retries are used up**, or for any 429 on a request that is never retried, the `RateLimitError` message ends with the upstream body verbatim followed by a `Retry-After: <value>` line when the upstream sent one, so the caller knows how long to wait before trying again.

The backoff used on a Site Manager route when there is no usable `Retry-After` (a connector read waits one 60 second window instead, see [Connector pacing](#connector-pacing)):

- **Max retries**: 5 (6 total attempts)
- **Backoff formula**: `delay = min(2^attempt, 32) + random_jitter`, where `attempt` is 0-based (0 for the sleep before the 2nd request, 1 before the 3rd, etc.)
  - Attempt 1: immediate
  - Attempt 2: 1-2 seconds (`2^0=1` + jitter 0-1)
  - Attempt 3: 2-4 seconds (`2^1=2` + jitter 0-2)
  - Attempt 4: 4-8 seconds (`2^2=4` + jitter 0-4)
  - Attempt 5: 8-16 seconds (`2^3=8` + jitter 0-8)
  - Attempt 6: 16-32 seconds (`2^4=16` + jitter 0-16)

  > **Note:** With the default `max_retries=5` (6 total attempts), Attempt 6 is the final request. On a 429 at Attempt 6 the client raises `RateLimitError` immediately without sleeping. The highest sleep actually reached before exhaustion is therefore 16-32 seconds (the wait before Attempt 6, which is `base_delay=16` plus up to 16 seconds of jitter). The 32-second **base delay** cap requires `attempt>=5` and is only reachable if `max_retries` is increased beyond 5; however, the total sleep (base + jitter) already reaches 32 seconds with the default `max_retries=5` due to jitter.

- **Jitter**: Uniform random(0, base_delay) added to avoid "thundering herd" — coordinated retries from multiple clients hitting the API at the same moment.

After all retries are exhausted, a `RateLimitError` is raised. This is expected behavior when hitting API quotas; users should back off before retrying.

**Never auto-retried:** every non-GET request and every state-changing `GET`, by the one
rule above. That includes the
physical actions (`restart_device`, `execute_device_action`, `execute_port_action`,
`locate_device`, `upgrade_device`, `forget_device`, `unadopt_device`, the Protect PTZ,
talkback, siren, speaker, relay, alarm-hub and arm actions), the client actions
(`execute_client_action`, `reconnect_client`, ...), creates (`create_network`,
`create_hotspot_vouchers`, ...), updates and deletes, `pos_ingest_transaction`, the camera
control `GET` that `set_camera_control_enabled` sends, and every
`fabric_connector_*` mutation. A tool's read-before and read-after GETs keep the GET retry.

## Fabric connector limits (HTTP 408, 429, 502)

The pinned Site Manager API spec documents four limits on every `/v1/connector/consoles/{id}/*path` route (the GET, POST, PUT, PATCH and DELETE operations; sections Requirements, Rate Limit and Limits of each operation's description, and the 408, 429 and 502 responses). Every connector error keeps its upstream status and body verbatim; when it matches a limit, a hint follows the body (the relay carries it as `_hint`). Nothing is retried or rewritten.

| Limit (spec wording) | Status | Hint |
| --- | --- | --- |
| Each proxied request must complete within 25 seconds, otherwise it is terminated and a timeout error is returned | 408 | The request exceeded the connector's 25 second limit, or the console is offline or restarting, or its firmware is below the minimum; check the console with `list_hosts`; for a wide read send a smaller window or page size |
| Console firmware version must be 5.0.3 or later | 408 | Named in the same hint |
| Each console is limited to 100 requests per minute | 429 | The connector limits each console to 100 requests per minute; wait for the window to reopen and prefer fewer, larger requests (a bigger page size) |
| The upstream response body is limited to 10 MB; larger responses are not supported | 502 | A 502 on a connector route can mean the console is unreachable or the response is over the 10 MB limit; send a smaller window or page size. The spec names no status for this limit, so the hint says "possible" |

HTTP 408 is not retried. A 408 (or 502) on a write is reported as **outcome unknown**, like a 503 or 504: the connector may have forwarded the request, so the change may or may not have applied. The write is not retried; read the resource back (the error names the read to use) before sending it again. A 429 follows the rule above: a read waits the upstream `Retry-After` and retries, a write is sent once; the hint is appended to the raised error.

### Connector pacing

The server keeps one send log per console id, shared by every tool call in the process, and sends to a console only while fewer than `UNIFI_CONNECTOR_MAX_RPM` (default 95, allowed 1 to 100) requests went out in the trailing 60 seconds. A request is counted when it actually leaves, with its concurrency slot held, so a slow upstream cannot push more than the cap into one window. The budget is per process: another server process that sends to the same console has its own, and the caps of processes that run together must add up to 95 or less. There is no burst credit. A write (POST, PUT, PATCH or DELETE that is not a read-POST) starts only when the count is at most 5 below that cap and the console had no 429 in the last 60 seconds; while a write waits, reads stop at the same line. A write is still sent once, never retried. A call that needs more sends than the cap allows therefore takes longer, in steps of up to 60 seconds, instead of being answered with 429s.

A 429 backs the console off: the cap drops to the trailing count minus 10 (never below 60) and climbs 5 per minute back to the configured cap. A read via `GET` that gets a 429 waits the `Retry-After` value exactly (longer only if the trailing count needs more time to fall below 90), then retries. It never re-sends before that time: when the `Retry-After` is longer than what is left of the 120 seconds a call may wait, it raises `RateLimitError` at once, without sleeping, and the error shows the header. With no `Retry-After` the wait is at least one 60 second window (and at most 64 seconds), because a 429 at a low own count means another sender filled the console; it is never re-sent at once. A connector read that keeps getting 429 with no `Retry-After` therefore makes 3 sends (the first and two retries, 120 seconds of waiting) before it raises. Site Manager routes (`/v1/hosts`, `/v1/sites`) are not paced.

A caller may tag a call with `X-UF-Lane: <run-id>/<unit-id>`; the upstream request log line and the write audit record then carry `lane=<run-id>/<unit-id>` so live-test accounting can count writes per lane. The tag only labels: it changes no policy, credential or write gate. A malformed or repeated header refuses the call before any upstream request.

## HTTP 200 carrying an error (Network v2)

A Network v2 reply (`network/v2/api/...`) with a 2xx status and a body whose only member is an `error` object carrying a `code` and a `message`, for example `{"error": {"code": 400, "message": "api.err.InvalidPayload"}}`, is classified as an upstream error, never as a success: a typed tool raises with the complete body verbatim and a write is audited with outcome `upstream_error_body`. The generic `fabric_connector_*` relays keep reporting the status and body and add `_upstreamError` with the reason, and draw no `noOp` or `changed` verdict. The same rule covers Ubiquiti's bulk partial failure: a v2 reply with HTTP 207 and `{"success": [...], "errors": [non-empty]}` (the rolling-upgrade eligibility and time-estimate routes, `ucore/devices/update`) is an upstream error with the body untouched, while a 207 whose `errors` is empty is a success. Only those exact shapes are matched; a response that holds an `error` field beside other fields or deeper in a record is passed through unchanged. Nothing is retried. Ubiquiti's own code was checked and does not send the `{"error": {"code", "message"}}` envelope with a 2xx status: UniFi OS 6.0.17 sends it only with the same 4xx or 5xx status, and the Network 11.0.99 v2 API reports errors as a flat `{code, errorCode, message}` body with a 4xx or 5xx status, except a bulk partial failure, which answers HTTP 207 with `{success, errors}`. The Classic API answers one error with a 2xx: the pending two-factor check (`api.err.WaitingForUiVerifyAuthenticator`) is HTTP 202 with `meta.rc: error`, which the Classic `meta.rc` rule already treats as an error. The envelope guard therefore covers a proxy or middlebox that rewrites the status, and has not been seen to fire.

## Network Errors (No Retry)

The following errors are **not retried** and raise immediately:

- **Transport timeout**: A peer, proxy, or custom transport reports a timeout. The client does not impose an elapsed-time deadline.
- **Connection failed**: Network unreachable, DNS failure, refused connection
- **HTTP errors**: non-429 4xx (auth, not found), 408 and 5xx (server error) are raised immediately without retry

These are considered non-transient and retrying would not help. See the [configuration reference](CONFIGURATION.md) for related settings.

## Configuration

- **Request completion**: no application elapsed-time deadline; lifecycle cancellation remains available. `UNIFI_REQUEST_TIMEOUT_SECONDS` is removed; nonempty legacy values fail startup and must be deleted before upgrading.
- **Max retries**: 5 for a read via GET, 0 for a state-changing GET and every other method (the one rule above), set in the client
- **Max concurrency**: `UNIFI_MAX_CONCURRENCY` (default: `10`) — limits parallel requests to prevent overwhelming the API
