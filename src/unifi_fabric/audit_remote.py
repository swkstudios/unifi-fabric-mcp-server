"""The ``remote`` audit sink: audit records shipped to a log collector over HTTPS.

Selected with ``UNIFI_AUDIT_SINK=remote`` (JSON format only). With ``UNIFI_AUDIT_LOG``
also set the sink is additive: the audit stream writes the local file first, then hands
the same line to this sender, so nothing here can lose a local record. One delivery
contract (transport contract version 1.1.0):

* **Transport.** ``POST`` of an NDJSON batch (``application/x-ndjson``) over HTTP/1.1 and
  TLS 1.3. Each line is the audit record, serialized
  ``json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))`` and
  terminated by ``\\n``. Every request carries ``X-Audit-Schema-Version``,
  ``X-Audit-Stream-Id`` (one UUIDv4 per process), ``X-Audit-Batch-Id`` (one UUIDv4 per
  batch, reused on every attempt), ``X-Audit-First-Seq`` and ``X-Audit-Record-Count``.
  A 2xx response acknowledges the whole batch. Redirects are never followed.
* **TLS fails closed.** The collector certificate chain and host name are always verified
  (``UNIFI_AUDIT_REMOTE_CA_FILE`` pins the trusted CAs; unset means the platform trust
  store). Verification cannot be turned off. ``UNIFI_AUDIT_REMOTE_CERT_FILE`` and
  ``UNIFI_AUDIT_REMOTE_KEY_FILE`` add a client certificate (mutual TLS). A handshake or
  verification failure is a transport error of that attempt: the batch is retried and
  then dropped, never sent another way. Plain ``http://`` needs the explicit
  ``UNIFI_AUDIT_REMOTE_PLAINTEXT=true``.
* **Retry.** Transport errors, 408, 429 and 5xx are retried up to
  ``UNIFI_AUDIT_REMOTE_MAX_ATTEMPTS`` attempts per batch, waiting
  ``b * 2**(n-2)`` seconds before attempt ``n`` (``b`` =
  ``UNIFI_AUDIT_REMOTE_RETRY_BACKOFF_SECONDS``). Every other status drops the batch.
  ``Retry-After`` is ignored. Delivery is at-least-once; a collector deduplicates on
  (stream id, batch id). One batch is in flight at a time, in sequence order.
* **Bounded buffer, fail open.** Records wait in memory up to
  ``UNIFI_AUDIT_REMOTE_BUFFER_MAX_RECORDS`` / ``_BUFFER_MAX_BYTES``; when it is full the
  arriving record is dropped (drop-newest). Writing a record never blocks and never
  raises. Each drop is counted in an ``audit_remote_dropped`` record; the first
  acknowledgment after a failure writes an ``audit_remote_recovered`` record. While the
  sink is failing every tool response carries the ``audit_unavailable`` notice.
* **Stall signal (count, never a timer).** A collector that accepts a connection and
  never answers (or stalls the TLS handshake) holds the one in-flight batch. The sink
  is ``failing`` as soon as a full second batch (``UNIFI_AUDIT_REMOTE_BATCH_MAX_RECORDS``
  records) waits behind the in-flight one, long before the buffer fills.
* **No secrets out.** Errors, records and log lines name the collector as
  ``scheme://host:port`` only: never the URL path, the TLS file paths or their contents,
  request bodies or collector responses. A configuration error names the setting, never
  its value.

Records still buffered when the process exits are lost (no spool); closing the sink logs
how many (a count). With the local file sink they are already in the file.
"""

from __future__ import annotations

import http.client
import json
import logging
import math
import ssl
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .config import Settings

_logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1"
CONTENT_TYPE = "application/x-ndjson"
NOTICE = "audit_unavailable"
EVENT_DROPPED = "audit_remote_dropped"
EVENT_RECOVERED = "audit_remote_recovered"
#: The smallest ``UNIFI_AUDIT_REMOTE_BATCH_MAX_BYTES``: every transport record fits.
MIN_BATCH_BYTES = 1024

H_SCHEMA = "X-Audit-Schema-Version"
H_STREAM = "X-Audit-Stream-Id"
H_BATCH = "X-Audit-Batch-Id"
H_FIRST_SEQ = "X-Audit-First-Seq"
H_COUNT = "X-Audit-Record-Count"

#: Drop reasons of an ``audit_remote_dropped`` record.
DROP_REASONS = (
    "buffer_full",
    "record_too_large",
    "unserializable",
    "attempts_exhausted",
    "rejected",
)

#: Every remote-sink setting and its fixed default (``None``: unset).
DEFAULTS: dict[str, str | None] = {
    "UNIFI_AUDIT_REMOTE_URL": None,
    "UNIFI_AUDIT_REMOTE_PLAINTEXT": "false",
    "UNIFI_AUDIT_REMOTE_CA_FILE": None,
    "UNIFI_AUDIT_REMOTE_CERT_FILE": None,
    "UNIFI_AUDIT_REMOTE_KEY_FILE": None,
    "UNIFI_AUDIT_REMOTE_MAX_ATTEMPTS": "5",
    "UNIFI_AUDIT_REMOTE_RETRY_BACKOFF_SECONDS": "1",
    "UNIFI_AUDIT_REMOTE_BATCH_MAX_RECORDS": "100",
    "UNIFI_AUDIT_REMOTE_BATCH_MAX_BYTES": "1048576",
    "UNIFI_AUDIT_REMOTE_FLUSH_INTERVAL_SECONDS": "1",
    "UNIFI_AUDIT_REMOTE_BUFFER_MAX_RECORDS": "10000",
    "UNIFI_AUDIT_REMOTE_BUFFER_MAX_BYTES": "16777216",
}


class RemoteConfigError(ValueError):
    """An invalid remote-sink setting. The message names the setting, never its value."""


def check_url(url: str, *, plaintext: bool, tls_files: bool) -> None:
    """Refuse a collector URL the contract does not allow (naming the setting only)."""
    name = "UNIFI_AUDIT_REMOTE_URL"
    if not url or not url.strip():
        raise RemoteConfigError(f"{name} is required when UNIFI_AUDIT_SINK=remote")
    if url != url.strip() or any(not c.isprintable() or c.isspace() for c in url):
        raise RemoteConfigError(f"{name} must be one URL without spaces or control characters")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise RemoteConfigError(f"{name} must be an absolute http(s) URL with a host")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise RemoteConfigError(f"{name} must not carry credentials (user information)")
    if parts.query or "?" in url:
        raise RemoteConfigError(f"{name} must not carry a query string")
    if parts.fragment or "#" in url:
        raise RemoteConfigError(f"{name} must not carry a fragment")
    try:
        _ = parts.port
    except ValueError:
        raise RemoteConfigError(f"{name} has an invalid port") from None
    if parts.scheme == "http" and not plaintext:
        raise RemoteConfigError(
            f"an http:// {name} requires UNIFI_AUDIT_REMOTE_PLAINTEXT=true; "
            "use https:// for TLS (the default)"
        )
    if parts.scheme == "https" and plaintext:
        raise RemoteConfigError(f"UNIFI_AUDIT_REMOTE_PLAINTEXT=true requires an http:// {name}")
    if plaintext and tls_files:
        raise RemoteConfigError(
            "UNIFI_AUDIT_REMOTE_CA_FILE, _CERT_FILE and _KEY_FILE must be unset with "
            "UNIFI_AUDIT_REMOTE_PLAINTEXT=true"
        )


def endpoint(url: str) -> str:
    """``scheme://host:port`` of ``url``: the only part of it any output names."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{parts.scheme}://{host}:{port}"


@dataclass(frozen=True)
class RemoteConfig:
    """Validated remote-sink settings (built from :class:`~unifi_fabric.config.Settings`)."""

    url: str
    plaintext: bool = False
    ca_file: str | None = None
    cert_file: str | None = None
    key_file: str | None = None
    max_attempts: int = 5
    backoff: float = 1.0
    batch_max_records: int = 100
    batch_max_bytes: int = 1048576
    flush_interval: float = 1.0
    buffer_max_records: int = 10000
    buffer_max_bytes: int = 16777216

    def __post_init__(self) -> None:
        if (self.cert_file is None) != (self.key_file is None):
            raise RemoteConfigError(
                "UNIFI_AUDIT_REMOTE_CERT_FILE and UNIFI_AUDIT_REMOTE_KEY_FILE are set "
                "together or not at all"
            )
        check_url(
            self.url,
            plaintext=self.plaintext,
            tls_files=any((self.ca_file, self.cert_file, self.key_file)),
        )
        for name, value in (
            ("MAX_ATTEMPTS", self.max_attempts),
            ("BATCH_MAX_RECORDS", self.batch_max_records),
            ("BATCH_MAX_BYTES", self.batch_max_bytes),
            ("BUFFER_MAX_RECORDS", self.buffer_max_records),
            ("BUFFER_MAX_BYTES", self.buffer_max_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise RemoteConfigError(f"UNIFI_AUDIT_REMOTE_{name} must be a positive integer")
        for name, number in (
            ("RETRY_BACKOFF_SECONDS", self.backoff),
            ("FLUSH_INTERVAL_SECONDS", self.flush_interval),
        ):
            if isinstance(number, bool) or not math.isfinite(number) or not number > 0:
                raise RemoteConfigError(f"UNIFI_AUDIT_REMOTE_{name} must be a positive number")
        if self.batch_max_bytes < MIN_BATCH_BYTES:
            raise RemoteConfigError(
                f"UNIFI_AUDIT_REMOTE_BATCH_MAX_BYTES must be at least {MIN_BATCH_BYTES}"
            )

    @property
    def endpoint(self) -> str:
        return endpoint(self.url)

    @classmethod
    def from_settings(cls, settings: Settings) -> RemoteConfig:
        def path(value: str | None) -> str | None:
            return value if value and value.strip() else None

        return cls(
            url=settings.audit_remote_url,
            plaintext=bool(settings.audit_remote_plaintext),
            ca_file=path(settings.audit_remote_ca_file),
            cert_file=path(settings.audit_remote_cert_file),
            key_file=path(settings.audit_remote_key_file),
            max_attempts=settings.audit_remote_max_attempts,
            backoff=settings.audit_remote_retry_backoff_seconds,
            batch_max_records=settings.audit_remote_batch_max_records,
            batch_max_bytes=settings.audit_remote_batch_max_bytes,
            flush_interval=settings.audit_remote_flush_interval_seconds,
            buffer_max_records=settings.audit_remote_buffer_max_records,
            buffer_max_bytes=settings.audit_remote_buffer_max_bytes,
        )


def wire_line(record: Mapping[str, Any]) -> bytes:
    """The contract serialization of one record (strict: no NaN, strict UTF-8)."""
    return json.dumps(
        record, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _no_key_password() -> bytes:
    # An encrypted client key is a transport error, never an interactive prompt.
    return b""


@dataclass
class _Pending:
    first_seq: int | None
    last_seq: int | None
    count: int


#: An attempt observer receives ``{"attempt", "batch_id", "status", "error"}`` (status
#: ``None`` and ``error`` the exception class name for a transport error).
AttemptObserver = Callable[[dict[str, Any]], None]


class RemoteSender:
    """The delivery engine: :meth:`emit` buffers, :meth:`pump` delivers in strict order.

    :meth:`emit` is safe from any thread. :meth:`pump` runs on one thread at a time (the
    sink's worker; tests call it directly) and holds the lock only while it touches the
    buffer, never during a network attempt or a backoff wait.
    """

    def __init__(
        self,
        config: RemoteConfig,
        *,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], str] = _now,
        on_attempt: AttemptObserver | None = None,
        stream_id: str | None = None,
    ) -> None:
        self.config = config
        self.stream_id = stream_id or str(uuid.uuid4())
        self._sleep = sleep
        self._clock = clock
        self._on_attempt = on_attempt
        self._lock = threading.Lock()
        self._buf: deque[tuple[int, bytes]] = deque()
        self._buf_bytes = 0
        self._next_seq = 1
        self._pending: dict[str, _Pending] = {}
        #: Records of the batch being sent (still at the head of the buffer), else 0.
        self._inflight = 0
        self._failing = False
        self._episode_failed_attempts = 0
        self._episode_dropped = 0
        self._last_error: str | None = None

    # -- state
    @property
    def failing(self) -> bool:
        return self._failing

    @property
    def notice(self) -> str | None:
        return NOTICE if self._failing else None

    def buffered(self) -> int:
        with self._lock:
            return len(self._buf)

    def buffered_events(self) -> list[str]:
        with self._lock:
            return [json.loads(line)["event"] for _, line in self._buf]

    # -- emit (never blocks on the network, never raises)
    def emit(self, record: Mapping[str, Any]) -> None:
        try:
            line = wire_line(record)
        except (TypeError, ValueError, RecursionError):  # includes UnicodeEncodeError
            with self._lock:
                self._drop_locked("unserializable", None, None, 1)
            return
        self._accept(line)

    def emit_line(self, line: str) -> None:
        """Buffer one already-serialized JSON record (the audit stream's line)."""
        try:
            record = json.loads(line)
        except (TypeError, ValueError, RecursionError):
            record = None
        if not isinstance(record, dict):
            with self._lock:
                self._drop_locked("unserializable", None, None, 1)
            return
        try:
            wire_line(record)  # the strict contract check (no NaN, strict UTF-8)
        except (TypeError, ValueError, RecursionError):
            with self._lock:
                self._drop_locked("unserializable", None, None, 1)
            return
        # Ship the audit line itself: its bytes are what the chain mac covers.
        self._accept(line.encode("utf-8", errors="backslashreplace"))

    def _accept(self, line: bytes) -> None:
        size = len(line) + 1
        with self._lock:
            if size > self.config.batch_max_bytes:
                self._drop_locked("record_too_large", None, None, 1)
            elif (
                len(self._buf) >= self.config.buffer_max_records
                or self._buf_bytes + size > self.config.buffer_max_bytes
            ):
                self._drop_locked("buffer_full", None, None, 1)  # drop-newest
            else:
                self._enqueue_locked(line)
                self._check_stall_locked()

    def _check_stall_locked(self) -> None:
        """Count-based stall signal: a full batch of records waiting behind the batch in
        flight means the collector has not answered while a whole batch arrived. No
        timer: the bound is the record count (``BATCH_MAX_RECORDS``)."""
        if self._inflight and len(self._buf) - self._inflight >= self.config.batch_max_records:
            self._set_failing_locked()

    def _enqueue_locked(self, line: bytes) -> None:
        self._buf.append((self._next_seq, line))
        self._next_seq += 1
        self._buf_bytes += len(line) + 1

    def _drop_locked(self, reason: str, first: int | None, last: int | None, count: int) -> None:
        self._set_failing_locked()
        self._episode_dropped += count
        pend = self._pending.get(reason)
        if pend is None:
            self._pending[reason] = _Pending(first, last, count)
            return
        if first is not None:
            pend.first_seq = first if pend.first_seq is None else min(pend.first_seq, first)
            pend.last_seq = last
        pend.count += count

    def _set_failing_locked(self) -> None:
        if not self._failing:
            self._failing = True
            _logger.warning(
                "audit remote sink %s is failing; records are buffered or dropped and "
                "counted until the collector acknowledges again",
                self.config.endpoint,
            )

    # -- delivery
    def _materialize_drops_locked(self) -> None:
        for reason, pend in self._pending.items():  # first-drop order
            record: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION,
                "timestamp_utc": self._clock(),
                "event": EVENT_DROPPED,
                "reason": reason,
                "dropped_count": pend.count,
            }
            if pend.first_seq is not None:
                record["first_seq"] = pend.first_seq
                record["last_seq"] = pend.last_seq
            self._enqueue_locked(wire_line(record))  # exempt from the buffer limits
        self._pending.clear()

    def _take_batch_locked(self) -> list[tuple[int, bytes]]:
        batch: list[tuple[int, bytes]] = []
        size = 0
        for seq, line in self._buf:
            if (
                len(batch) >= self.config.batch_max_records
                or size + len(line) + 1 > self.config.batch_max_bytes
            ):
                break
            batch.append((seq, line))
            size += len(line) + 1
        return batch

    def frame(self, batch: list[tuple[int, bytes]]) -> tuple[bytes, dict[str, str]]:
        """The request body and the contract headers of ``batch``."""
        body = b"".join(line + b"\n" for _, line in batch)
        headers = {
            "Content-Type": CONTENT_TYPE,
            "Content-Length": str(len(body)),
            H_SCHEMA: SCHEMA_VERSION,
            H_STREAM: self.stream_id,
            H_FIRST_SEQ: str(batch[0][0]),
            H_COUNT: str(len(batch)),
        }
        return body, headers

    def _connection(self) -> http.client.HTTPConnection:
        """A new connection for one attempt. The TLS context is built per attempt, so a
        rotated or unreadable TLS file is that attempt's transport error."""
        parts = urlsplit(self.config.url)
        host = parts.hostname or ""
        if self.config.plaintext:
            return http.client.HTTPConnection(host, parts.port or 80)
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.config.ca_file)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        if self.config.cert_file and self.config.key_file:
            ctx.load_cert_chain(
                self.config.cert_file, self.config.key_file, password=_no_key_password
            )
        return http.client.HTTPSConnection(host, parts.port or 443, context=ctx)

    def _post(self, batch_id: str, batch: list[tuple[int, bytes]]) -> int:
        body, headers = self.frame(batch)
        headers[H_BATCH] = batch_id
        target = urlsplit(self.config.url).path or "/"
        conn = self._connection()
        try:
            conn.request("POST", target, body=body, headers=headers)
            response = conn.getresponse()
            while response.read(65536):  # drained, never kept or logged
                pass
            return response.status
        finally:
            conn.close()

    @staticmethod
    def retryable(status: int) -> bool:
        return status in {408, 429} or 500 <= status <= 599

    def _send(self, batch: list[tuple[int, bytes]]) -> str:
        batch_id = str(uuid.uuid4())
        for attempt in range(1, self.config.max_attempts + 1):
            if attempt > 1:
                self._sleep(self.config.backoff * 2 ** (attempt - 2))
            status: int | None
            error: str | None = None
            try:
                status = self._post(batch_id, batch)
            except (OSError, http.client.HTTPException, ValueError) as exc:
                # ssl.SSLError (handshake, verification, bad TLS file) is an OSError: the
                # attempt failed and nothing else is tried in its place (fail closed).
                status, error = None, type(exc).__name__
            if self._on_attempt is not None:
                self._on_attempt(
                    {"attempt": attempt, "batch_id": batch_id, "status": status, "error": error}
                )
            if status is not None and 200 <= status <= 299:
                return "acked"
            with self._lock:
                self._set_failing_locked()
                self._episode_failed_attempts += 1
            if error is not None and error != self._last_error:
                self._last_error = error
                _logger.warning(
                    "audit remote sink %s: attempt failed (%s)", self.config.endpoint, error
                )
            if status is not None and not self.retryable(status):
                return "rejected"
        return "attempts_exhausted"

    def pump(self, max_batches: int | None = None) -> bool:
        """Deliver buffered batches, one in flight, in sequence order. A round ends at
        the first batch that is not acknowledged (it is dropped and counted);
        ``max_batches`` bounds the batches sent. Returns ``False`` when a batch was
        dropped, else ``True``."""
        sent = 0
        while max_batches is None or sent < max_batches:
            with self._lock:
                self._materialize_drops_locked()
                batch = self._take_batch_locked()
            if not batch:
                return True
            sent += 1
            with self._lock:
                self._inflight = len(batch)
            try:
                outcome = self._send(batch)
            finally:
                with self._lock:
                    self._inflight = 0
            with self._lock:
                for _ in batch:
                    _, line = self._buf.popleft()
                    self._buf_bytes -= len(line) + 1
                if outcome != "acked":
                    self._drop_locked(outcome, batch[0][0], batch[-1][0], len(batch))
                    return False
                if self._failing:
                    self._failing = False
                    self._last_error = None
                    self._enqueue_locked(
                        wire_line(
                            {
                                "schema_version": SCHEMA_VERSION,
                                "timestamp_utc": self._clock(),
                                "event": EVENT_RECOVERED,
                                "failed_attempts": self._episode_failed_attempts,
                                "dropped_records": self._episode_dropped,
                            }
                        )
                    )
                    self._episode_failed_attempts = 0
                    self._episode_dropped = 0
                    _logger.info("audit remote sink %s recovered", self.config.endpoint)
        return True


class RemoteSink:
    """The audit stream's ``remote`` sink: a :class:`RemoteSender` driven by one daemon
    worker thread. :meth:`write` only buffers (fail open). Every
    ``UNIFI_AUDIT_REMOTE_FLUSH_INTERVAL_SECONDS`` the worker delivers what is buffered;
    the interval paces delivery rounds and never limits an attempt."""

    name = "remote"

    def __init__(
        self,
        config: RemoteConfig,
        *,
        start: bool = True,
        pace: Callable[[float], None] = time.sleep,
        **sender_kwargs: Any,
    ) -> None:
        self.config = config
        self.sender = RemoteSender(config, **sender_kwargs)
        self._pace = pace
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        if start:
            self.start()

    @property
    def endpoint(self) -> str:
        return self.config.endpoint

    @property
    def failing(self) -> bool:
        return self.sender.failing

    def write(self, line: str) -> None:
        self.sender.emit_line(line)

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._run, name="unifi-fabric-audit-remote", daemon=True
            )
            self._thread.start()

    def close(self) -> None:
        """Stop the worker (it exits at its next interval). Records still buffered are
        lost (the contract has no spool); their count, never their content, is logged
        once."""
        already = self._stop.is_set()
        self._stop.set()
        if already:
            return
        discarded = self.sender.buffered()
        if discarded:
            _logger.warning(
                "audit remote sink %s closed with %d unacknowledged record(s) discarded",
                self.endpoint,
                discarded,
            )

    def _run(self) -> None:
        # One delivery round per interval expiry; after a drop the next round also starts
        # at the next expiry.
        while True:
            self._pace(self.config.flush_interval)
            if self._stop.is_set():
                return
            try:
                self.sender.pump()
            except Exception:  # noqa: BLE001 - the worker never dies on a delivery bug
                _logger.warning("audit remote sink %s: delivery round failed", self.endpoint)
