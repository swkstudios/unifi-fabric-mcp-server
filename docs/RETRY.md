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

When the UniFi API answers a read via `GET` with HTTP 429 (Too Many Requests), the server retries with **exponential backoff + jitter**:

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

## Network Errors (No Retry)

The following errors are **not retried** and raise immediately:

- **Transport timeout**: A peer, proxy, or custom transport reports a timeout. The client does not impose an elapsed-time deadline.
- **Connection failed**: Network unreachable, DNS failure, refused connection
- **HTTP errors**: non-429 4xx (auth, not found) and 5xx (server error) are raised immediately without retry

These are considered non-transient and retrying would not help. See the [configuration reference](CONFIGURATION.md) for related settings.

## Configuration

- **Request completion**: no application elapsed-time deadline; lifecycle cancellation remains available. `UNIFI_REQUEST_TIMEOUT_SECONDS` is removed; nonempty legacy values fail startup and must be deleted before upgrading.
- **Max retries**: 5 for a read via GET, 0 for a state-changing GET and every other method (the one rule above), set in the client
- **Max concurrency**: `UNIFI_MAX_CONCURRENCY` (default: `10`) — limits parallel requests to prevent overwhelming the API
