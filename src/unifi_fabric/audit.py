"""One typed audit stream: startup, call, error and write-audit records.

OFF by default. The stream is configured by four settings:

* ``UNIFI_AUDIT_SINK`` -- ``none`` | ``stderr`` | ``file`` | ``remote``. Unset means
  ``file`` when ``UNIFI_AUDIT_LOG`` names a path and ``none`` otherwise, so an existing
  ``UNIFI_AUDIT_LOG`` deployment keeps writing its file. ``file`` requires
  ``UNIFI_AUDIT_LOG``; ``none`` or ``stderr`` with a path set is a startup error.
  ``remote`` ships JSON records to a log collector over HTTPS (TLS by default,
  verified, optional mutual TLS): :mod:`unifi_fabric.audit_remote`. ``remote`` with
  ``UNIFI_AUDIT_LOG`` set is additive: the local file is written first, synchronously,
  with the file sink's own fault semantics, and the same line is then handed to the
  remote buffer, so a collector outage or stall never loses a local record.
* ``UNIFI_AUDIT_LEVEL`` -- ``off`` | ``normal`` (default) | ``debug``. ``off`` writes
  nothing except the two policy records (:meth:`AuditStream.policy_record`);
  ``normal`` writes metadata only; ``debug`` adds the scrubbed request body of a write
  and the scrubbed arguments of a call record, and nothing else.
* ``UNIFI_AUDIT_CALLS`` -- per-call logging, off by default: one ``call`` record per
  tool call that completes and one ``error`` record per tool call that fails.
* ``UNIFI_AUDIT_LOG_FORMAT`` -- ``json`` (default) or ``text``.

Every JSON record carries ``schema_version`` (``"1"``), ``event`` (one of
:data:`EVENTS`) and ``timestamp_utc`` (``datetime.now(UTC).isoformat()``), and is
serialized ``json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",",
":"))``: the same canonical form as the policy records. The field set of each event
is fixed in :data:`EVENT_FIELDS` and tested in ``tests/test_audit_contract.py``. The
text format keeps the 0.7.0 key=value line for ``audit`` records (timestamp first, no
``event`` field) and writes ``event=<name>`` first for every other event.

A write attempt is an ``audit`` record (every POST/PUT/PATCH/DELETE classified as a
write at the shared HTTP chokepoint, and every refused write tool call, exactly once:
:mod:`unifi_fabric.refusal_audit`). Its outcome is one of :data:`OUTCOMES`.

Design notes:

* **Secret scrubbing.** String values are scrubbed of every configured secret before
  encoding; JSON keys, numbers and nulls keep their values. A write's query string and
  fragment are never recorded. A body or argument object is written only at ``debug``,
  with every credential-named field masked (:func:`redaction.redact_credentials`) and
  every configured secret scrubbed from its strings.
* **File creation.** A new audit file is created with mode ``UNIFI_AUDIT_LOG_MODE``
  (``0600`` default, ``0640`` for a group reader), set with ``fchmod`` so the umask
  cannot widen or narrow it. An existing file keeps its mode; the startup record
  reports it. The file is opened ``O_APPEND | O_NOFOLLOW`` for every record and closed
  again, so a host-owned rotation (logrotate ``create``/``copytruncate``) is followed
  and a symlink at the path is refused.
* **Fail open.** A write failure never breaks a tool call. Any ``OSError`` (``ENOSPC``,
  ``EACCES``, ``EPERM``, ``EROFS``, ``ENOENT`` and the rest) marks the stream
  unavailable: every tool response then carries the fixed notice
  :data:`AUDIT_UNAVAILABLE` until a later record is written again, and that first
  record after the fault is an ``audit.recovered`` record counting the records lost.
* **Tamper evidence (opt-in).** ``UNIFI_AUDIT_CHAIN`` (off by default) adds a keyed hash
  chain to the JSON file sink (:mod:`unifi_fabric.audit_chain`): ``chain``/``seq``/
  ``prev``/``mac`` on every record, an ``audit.chain_start`` record first and an
  ``audit.seal`` record after every policy line. Off, the stream is byte-identical to
  0.7.1. It is tamper-evident, not tamper-proof.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import re
import stat
import sys
import threading
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from time import perf_counter
from typing import TYPE_CHECKING, Any, TextIO

from .audit_chain import (
    CHAIN_FIELDS,
    CHAIN_START_EVENT,
    SEAL_EVENT,
    ChainState,
    sealed_digest,
)
from .redaction import REDACTION_MASK, redact_credentials
from .refusal_audit import note_refused_record
from .secret_scrub import configured_secrets, scrub, scrub_json_strings

if TYPE_CHECKING:
    from .audit_identifiers import IdentifierHasher
    from .audit_remote import RemoteSink
    from .config import Settings

_logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1"

#: Valid values of each setting (config.py keeps the same tuples for its validators).
SINKS = ("none", "stderr", "file", "remote")
LEVELS = ("off", "normal", "debug")
FORMATS = ("text", "json")
FILE_MODES = {"0600": 0o600, "0640": 0o640}

#: The fixed per-response notice while the sink cannot be written.
AUDIT_UNAVAILABLE = "audit_unavailable"
#: The ``_meta`` key of a tool result that carries the notice.
NOTICE_META_KEY = "unifi_fabric/audit"

#: Errnos the fault fixtures cover; every other ``OSError`` is handled the same way.
FAULT_ERRNOS = (errno.ENOSPC, errno.EACCES, errno.EPERM, errno.EROFS, errno.ENOENT)

#: Outcomes of an ``audit`` record (a write attempt): these tokens, or ``http_<status>``
#: for a non-2xx upstream status (:data:`OUTCOME_HTTP`).
OUTCOMES = (
    "success",
    "no_response",
    "rate_limited",
    "classic_rc_error",
    "upstream_error_body",
    "error",
    "dry_run",
    "refused",
)
OUTCOME_HTTP = r"http_[1-5][0-9][0-9]"
CALL_OUTCOMES = ("ok", "error")

_ENVELOPE = ("schema_version", "event", "timestamp_utc")
#: Field set of each event. ``optional`` fields are present only when they have a value.
EVENT_FIELDS: dict[str, dict[str, tuple[str, ...]]] = {
    "startup": {
        "required": (*_ENVELOPE, "version", "sink", "level", "format", "calls"),
        "optional": ("file_mode", "remote_endpoint", "identifiers"),
    },
    "audit": {
        "required": (*_ENVELOPE, "method", "path", "outcome", "status"),
        "optional": (
            "tool",
            "reason",
            "resolvedHost",
            "resolvedSite",
            "duration_ms",
            "body",
            "via",
        ),
    },
    "call": {
        "required": (*_ENVELOPE, "tool", "outcome", "duration_ms"),
        "optional": ("arguments",),
    },
    "error": {
        "required": (*_ENVELOPE, "tool", "error_type", "duration_ms"),
        "optional": ("message",),
    },
    "audit.recovered": {
        "required": (*_ENVELOPE, "lost_records", "fault"),
        "optional": (),
    },
    # Written only with UNIFI_AUDIT_CHAIN on (the first record of every chain).
    CHAIN_START_EVENT: {
        "required": (*_ENVELOPE, "kid", "prev_chain", "prev_seq", "prev_mac", *CHAIN_FIELDS),
        "optional": (),
    },
    # Written only with UNIFI_AUDIT_CHAIN on (right after every policy line).
    SEAL_EVENT: {
        "required": (*_ENVELOPE, "sealed_sha256", *CHAIN_FIELDS),
        "optional": (),
    },
}
#: Events written only when the chain is on; with it on, every record also carries
#: :data:`CHAIN_FIELDS` (``chain``, ``seq``, ``prev``, ``mac``).
CHAIN_EVENTS = (CHAIN_START_EVENT, SEAL_EVENT)
#: The two policy records the audit stream carries byte-identical (shapes: policy.py).
POLICY_EVENTS = ("policy.startup", "policy.refusal")
EVENTS = (*EVENT_FIELDS, *POLICY_EVENTS)

_AUDIT_VIA: ContextVar[str | None] = ContextVar("audit_via", default=None)
_AUDIT_TOOL: ContextVar[str | None] = ContextVar("audit_tool", default=None)
_AUDIT_HOST: ContextVar[str | None] = ContextVar("audit_host", default=None)
_AUDIT_SITE: ContextVar[str | None] = ContextVar("audit_site", default=None)
_AUDIT_START: ContextVar[float | None] = ContextVar("audit_start", default=None)


@contextmanager
def audit_call(tool: str | None):
    """Scope tool provenance and duration to its audit records."""
    parent = _AUDIT_TOOL.get()
    via_token = _AUDIT_VIA.set(
        parent if parent in {"call_read_tool", "call_write_tool", "execute"} else _AUDIT_VIA.get()
    )
    tokens = (
        _AUDIT_TOOL.set(tool),
        _AUDIT_HOST.set(None),
        _AUDIT_SITE.set(None),
        _AUDIT_START.set(perf_counter()),
    )
    try:
        yield
    finally:
        _AUDIT_START.reset(tokens[3])
        _AUDIT_SITE.reset(tokens[2])
        _AUDIT_HOST.reset(tokens[1])
        _AUDIT_TOOL.reset(tokens[0])
        _AUDIT_VIA.reset(via_token)


def current_tool() -> str | None:
    """The public name of the tool whose call is running now, else None."""
    return _AUDIT_TOOL.get()


def set_audit_resolution(*, host: str | None = None, site: str | None = None) -> None:
    if host is not None:
        _AUDIT_HOST.set(host)
    if site is not None:
        _AUDIT_SITE.set(site)


def elapsed_ms() -> float | None:
    """Milliseconds since the current tool call started (``None`` outside one)."""
    started = _AUDIT_START.get()
    return round((perf_counter() - started) * 1000, 3) if started is not None else None


#: Characters a canonical line escapes although ``ensure_ascii=False`` would keep them:
#: DEL, the C1 controls and the Unicode line/paragraph separators split lines in
#: splitlines()-based shippers or act on a terminal.
_LINE_UNSAFE = re.compile("[\x7f-\x9f\u2028\u2029]")


def canonical_json(obj: Mapping[str, Any]) -> str:
    """The one serialization of a JSON record (the policy record form, with DEL, C1
    and U+2028/U+2029 escaped so a record is always exactly one line)."""
    line = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return _LINE_UNSAFE.sub(lambda m: f"\\u{ord(m.group()):04x}", line)


#: Debug-only ceiling on one serialized ``body`` / ``arguments`` value; a larger value is
#: replaced by ``{"truncated": true, "bytes": <size>}``.
DEBUG_VALUE_MAX_BYTES = 65536
_MAX_DEPTH = 64

#: Debug bodies and arguments: a key containing one of these (case-insensitive) is a
#: credential field and its value is masked whatever its type (fail closed, in addition
#: to :func:`redaction.redact_credentials`). Cursor fields stay readable.
_AUDIT_CREDENTIAL_PARTS = (
    "pass",
    "password",
    "passwd",
    "community",
    "bearer",
    "jwt",
    "pwd",
    "passphrase",
    "secret",
    "token",
    "key",
    "pin",
    "otp",
    "code",
    "cred",
    "auth",
    "cookie",
    "psk",
    "private",
    "signature",
    "session",
)
_CURSOR_KEYS = frozenset({"nexttoken", "next_token", "pagetoken", "page_token", "cursor"})


def _mask_audit_credentials(obj: Any, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        return "[truncated: depth]"
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            lowered = str(k).lower()
            if (
                lowered not in _CURSOR_KEYS
                and any(p in lowered for p in _AUDIT_CREDENTIAL_PARTS)
                and v not in (None, "")
            ):
                out[str(k)] = REDACTION_MASK
            else:
                out[str(k)] = _mask_audit_credentials(v, depth + 1)
        return out
    if isinstance(obj, list):
        return [_mask_audit_credentials(v, depth + 1) for v in obj]
    return obj


# ------------------------------------------------------------------------------ sinks
class SinkWriteError(Exception):
    """A sink could not write a line; ``errno_name`` names the fault (``EIO`` if none)."""

    def __init__(self, exc: BaseException) -> None:
        super().__init__(type(exc).__name__)
        code = exc.errno if isinstance(exc, OSError) else None
        self.errno_name = errno.errorcode.get(code or 0, "EIO")


class NullSink:
    name = "none"

    def write(self, line: str) -> None:  # pragma: no cover - never called
        return None


@dataclass
class StderrSink:
    """One line per record to the process's standard error (never stdout: stdio MCP)."""

    stream: Callable[[], TextIO] = field(default=lambda: sys.stderr)
    name: str = "stderr"

    def write(self, line: str) -> None:
        try:
            out = self.stream()
            out.write(line + "\n")
            out.flush()
        except Exception as exc:  # noqa: BLE001 - every sink failure fails open
            raise SinkWriteError(exc) from None


def _ends_without_newline(path: str) -> bool:
    """True when ``path`` is a regular, non-empty file whose last byte is not a newline.

    Never follows a symlink and never opens a FIFO or device (it checks ``lstat`` first).
    """
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
        return False
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags | getattr(os, "O_NONBLOCK", 0))
    try:
        return os.pread(fd, 1, st.st_size - 1) != b"\n"
    finally:
        os.close(fd)


def _identity(st: os.stat_result) -> tuple[int, int, int]:
    return (st.st_dev, st.st_ino, st.st_rdev if stat.S_ISCHR(st.st_mode) else 0)


def _fd_identity(fd: int) -> tuple[int, int, int] | None:
    try:
        return _identity(os.fstat(fd))
    except OSError:
        return None


@dataclass
class FileSink:
    """Append-only file sink. A new file is created with ``mode`` exactly.

    Every decision is taken on the opened descriptor (``fstat``), never on the path, so
    a path swapped between a check and the open cannot redirect records:

    * a regular file is accepted only when it is not reached through a symlink and is
      owned by this process's user (else ``EPERM``);
    * a symlink is followed only to this process's own standard error (``/dev/stderr``
      in a container, whatever it is: pipe, terminal or file); never elsewhere
      (``ELOOP``); a FIFO or device named directly must belong to this user;
    * the target is never this process's standard output (the stdio MCP channel);
    * the open is non-blocking, so a FIFO with no reader is a fault (``ENXIO``), not a
      hang.
    """

    path: str
    mode: int = 0o600
    name: str = "file"
    _partial: bool = field(default=False, repr=False, compare=False)
    _wide_warned: bool = field(default=False, repr=False, compare=False)
    #: True when every byte of the last record (its newline aside) reached the file,
    #: even if the write then failed (a ``close`` error, a lost newline). The hash chain
    #: advances on this, never on the absence of an error.
    last_complete: bool = field(default=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        # A crash can leave the last record without its newline: the first record of this
        # process then starts on its own line instead of continuing the cut one.
        try:
            self._partial = _ends_without_newline(self.path)
        except OSError:
            pass

    def _open(self) -> int:
        flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        created = False
        try:
            fd = os.open(self.path, flags | nofollow | os.O_CREAT | os.O_EXCL, self.mode)
            created = True
        except FileExistsError:
            try:
                fd = os.open(self.path, flags | nofollow)
                via_link = False
            except OSError as exc:
                if exc.errno != errno.ELOOP:
                    raise
                fd = os.open(self.path, flags)  # a symlink: validated on the fd below
                via_link = True
        try:
            if created:
                os.fchmod(fd, self.mode)
            else:
                self._check_existing(fd, via_link)
            if hasattr(os, "set_blocking"):
                os.set_blocking(fd, True)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _check_existing(self, fd: int, via_link: bool) -> None:
        st = os.fstat(fd)
        ident = _identity(st)
        if ident == _fd_identity(1):
            raise OSError(errno.EPERM, "audit sink is standard output")
        if via_link:
            if ident != _fd_identity(2):
                raise OSError(errno.ELOOP, "audit path is a symlink to something else")
            return
        if stat.S_ISREG(st.st_mode):
            if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
                raise OSError(errno.EPERM, "audit file is owned by another user")
            if stat.S_IMODE(st.st_mode) & ~self.mode and not self._wide_warned:
                self._wide_warned = True
                _logger.warning(
                    "audit file permissions are wider than UNIFI_AUDIT_LOG_MODE; "
                    "tighten them or rotate the file"
                )
            return
        if not (stat.S_ISCHR(st.st_mode) or stat.S_ISFIFO(st.st_mode)):
            raise OSError(errno.EPERM, "audit path is not a file, device or FIFO")
        if ident != _fd_identity(2) and hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            raise OSError(errno.EPERM, "audit device or FIFO is owned by another user")

    def write(self, line: str) -> None:
        # A record that a fault cut short has no newline: start this one on its own line.
        prefix = "\n" if self._partial else ""
        data = (prefix + line + "\n").encode("utf-8", errors="backslashreplace")
        written = 0
        self.last_complete = False
        try:
            fd = self._open()
            try:
                view = memoryview(data)
                while view:
                    n = os.write(fd, view)
                    written += n
                    view = view[n:]
            finally:
                os.close(fd)
        except Exception as exc:  # noqa: BLE001 - every sink failure fails open
            if written:
                self._partial = True
            self.last_complete = written >= len(data) - 1
            raise SinkWriteError(exc) from None
        self._partial = False
        self.last_complete = True

    def existing_mode(self) -> str | None:
        """The octal permission bits of what the path resolves to (startup record)."""
        try:
            st = os.stat(self.path)
        except OSError:
            return None
        return f"{stat.S_IMODE(st.st_mode):04o}"


Sink = NullSink | StderrSink | FileSink


# ----------------------------------------------------------------------------- stream
@dataclass
class AuditStream:
    """The typed stream over one sink. Thread-safe; every write is best-effort and no
    exception of the stream ever reaches the caller (fail open)."""

    sink: Sink | RemoteSink
    #: The remote sink that ships every line after the primary ``sink`` (a file) has
    #: written it (``UNIFI_AUDIT_SINK=remote`` with ``UNIFI_AUDIT_LOG``); else ``None``.
    remote_copy: RemoteSink | None = field(default=None, repr=False, compare=False)
    fmt: str = "json"
    level: str = "normal"
    calls: bool = False
    #: Configured secrets each record is scrubbed of (never shown in repr).
    secrets: tuple[str, ...] = field(default=(), repr=False, compare=False)
    #: ``UNIFI_AUDIT_HMAC_IDENTIFIERS``: client MACs and user ids become HMAC tokens.
    identifiers: IdentifierHasher | None = field(default=None, repr=False, compare=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)
    _fault: str | None = field(default=None, repr=False, compare=False)
    _lost: int = field(default=0, repr=False, compare=False)
    #: The hash chain (``UNIFI_AUDIT_CHAIN``); ``None`` (the default) leaves every byte
    #: of the stream as 0.7.1 wrote it.
    chain: ChainState | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.fmt not in FORMATS:
            raise ValueError(
                f"UNIFI_AUDIT_LOG_FORMAT must be one of {', '.join(FORMATS)} "
                "(the value is not shown here)"
            )
        if self.level not in LEVELS:
            raise ValueError(f"UNIFI_AUDIT_LEVEL must be one of {', '.join(LEVELS)}")
        if self.chain is not None and (self.fmt != "json" or not isinstance(self.sink, FileSink)):
            raise ValueError(
                "UNIFI_AUDIT_CHAIN requires UNIFI_AUDIT_LOG_FORMAT=json and the file sink"
            )

    # -- state
    @property
    def enabled(self) -> bool:
        """True when records are written (a sink is set and the level is not off)."""
        return not isinstance(self.sink, NullSink) and self.level != "off"

    @property
    def unavailable(self) -> bool:
        """True while the sink cannot be written (the per-response notice is due); for
        the remote sink, while it is failing (a failed attempt or a drop, until the
        next acknowledgment)."""
        remote = self.remote
        if remote is not None and remote.failing:
            return True
        return self._fault is not None

    @property
    def remote(self) -> RemoteSink | None:
        """The remote sink in use, as the only sink or as the remote copy of the file."""
        return self.remote_copy if self.remote_copy is not None else _remote_sink(self.sink)

    @property
    def path(self) -> str | None:
        return self.sink.path if isinstance(self.sink, FileSink) else None

    def probe(self) -> bool:
        """While unavailable, try to write the ``audit.recovered`` record now (called
        once per tool response), so the notice clears as soon as the sink works again
        even when no other record is due. Returns :attr:`unavailable` afterwards."""
        if self._fault is None:
            return self.unavailable
        with self._lock:
            if self._fault is not None:
                self._write_locked(None, datetime.now(UTC).isoformat())
        return self.unavailable

    # -- records (each fails open: an exception is a lost record, never the caller's)
    def startup(self, version: str) -> None:
        self._guard(self._startup, version)

    def record(
        self,
        *,
        method: str | None,
        path: str | None,
        outcome: str,
        status: int | None,
        tool: str | None = None,
        reason: str | None = None,
        body: Any = None,
    ) -> None:
        """One ``audit`` record for a write attempt. ``body`` is written at debug only."""
        if outcome == "refused":
            note_refused_record()
        if not self.enabled:
            return
        self._guard(
            self._record,
            method=method,
            path=path,
            outcome=outcome,
            status=status,
            tool=tool or _AUDIT_TOOL.get(),
            reason=reason,
            body=body,
        )

    def call(self, tool: str | None, arguments: Any = None) -> None:
        """One ``call`` record for a completed tool call (per-call logging only)."""
        if self.calls and self.enabled:
            self._guard(self._call, tool, arguments)

    def error(self, tool: str | None, exc: BaseException) -> None:
        """One ``error`` record for a failed tool call (per-call logging only). The
        message, scrubbed, is written at debug only; normal carries the type alone."""
        if self.calls and self.enabled:
            self._guard(self._error, tool, exc)

    def policy_record(self, line: str) -> None:
        """Carry one policy record (``policy.startup`` / ``policy.refusal``),
        byte-identical, at every level including off. The policy module already writes it to
        stderr, so a stderr sink adds no second copy."""
        if isinstance(self.sink, NullSink | StderrSink):
            return
        if self.chain is not None:
            self._guard(self._write_chained, None, datetime.now(UTC).isoformat(), line)
            return
        self._guard(self._write, line, datetime.now(UTC).isoformat())

    def log_head(self, reason: str = "shutdown") -> None:
        """Log the chain head at INFO (best effort; no-op without the chain)."""
        if self.chain is None:
            return
        try:
            with self._lock:
                self.chain.log_head(reason)
        except Exception:  # noqa: BLE001, S110 - an anchor line never breaks shutdown
            pass

    # -- builders
    def _startup(self, version: str) -> None:
        rec: dict[str, Any] = {
            "version": version,
            "sink": "remote" if self.remote_copy is not None else self.sink.name,
            "level": self.level,
            "format": self.fmt,
            "calls": self.calls,
        }
        if isinstance(self.sink, FileSink):
            mode = self.sink.existing_mode()
            rec["file_mode"] = mode if mode is not None else f"{self.sink.mode:04o}"
        remote = self.remote
        if remote is not None:
            rec["remote_endpoint"] = remote.endpoint
        if self.identifiers is not None:
            rec["identifiers"] = "hmac"
        self._emit("startup", rec)

    def _record(self, *, method, path, outcome, status, tool, reason, body) -> None:  # noqa: ANN001
        secrets = self._secrets()
        rec: dict[str, Any] = {
            "method": method,
            "path": _safe_path(path, secrets) if path is not None else None,
            "outcome": outcome,
            "status": status,
        }
        optional = {
            "tool": tool,
            "via": _AUDIT_VIA.get(),
            "reason": _safe_reason(reason, secrets) if reason is not None else None,
            "resolvedHost": _AUDIT_HOST.get(),
            "resolvedSite": _AUDIT_SITE.get(),
            "duration_ms": elapsed_ms(),
        }
        rec.update({k: v for k, v in optional.items() if v is not None})
        if self.level == "debug" and body is not None:
            rec["body"] = self._scrub_object(body, secrets)
        self._emit("audit", rec, secrets=secrets)

    def _call(self, tool: str | None, arguments: Any) -> None:
        secrets = self._secrets()
        rec: dict[str, Any] = {"tool": tool, "outcome": "ok", "duration_ms": elapsed_ms()}
        if self.level == "debug" and arguments is not None:
            rec["arguments"] = self._scrub_object(arguments, secrets)
        self._emit("call", rec, secrets=secrets)

    def _error(self, tool: str | None, exc: BaseException) -> None:
        secrets = self._secrets()
        rec: dict[str, Any] = {
            "tool": tool,
            "error_type": type(exc).__name__,
            "duration_ms": elapsed_ms(),
        }
        if self.level == "debug":
            rec["message"] = _cap_text(_safe_reason(str(exc), secrets))
        self._emit("error", rec, secrets=secrets)

    # -- internals
    def _guard(self, fn: Callable[..., None], *args: Any, **kwargs: Any) -> None:
        try:
            fn(*args, **kwargs)
        except Exception:  # noqa: BLE001 - the audit stream never breaks a tool call
            with self._lock:
                if self._fault is None:
                    _logger.warning("audit record could not be built; it is dropped")
                self._fault = self._fault or "EIO"
                self._lost += 1

    def _secrets(self) -> tuple[str, ...]:
        return configured_secrets(extra=self.secrets)

    def _scrub_object(self, obj: Any, secrets: tuple[str, ...]) -> Any:
        """A debug value: JSON data only, credential fields masked, secrets scrubbed,
        capped at :data:`DEBUG_VALUE_MAX_BYTES`."""
        try:
            plain = json.loads(json.dumps(obj))
        except (TypeError, ValueError, RecursionError):
            return {"unserializable": type(obj).__name__}
        try:
            masked = _mask_audit_credentials(redact_credentials(plain))
            clean = scrub_json_strings(masked, secrets)
            size = len(canonical_json({"v": clean}).encode("utf-8", errors="backslashreplace"))
        except RecursionError:
            return {"unserializable": type(obj).__name__}
        if size > DEBUG_VALUE_MAX_BYTES:
            return {"truncated": True, "bytes": size}
        return clean

    def _emit(self, event: str, fields: dict[str, Any], *, secrets: tuple[str, ...] = ()) -> None:
        if not self.enabled:
            return
        if self.identifiers is not None and event != "startup":
            fields = self.identifiers.record_fields(fields)
        secrets = secrets or self._secrets()
        ts = datetime.now(UTC).isoformat()
        if self.fmt == "json":
            rec = {"schema_version": SCHEMA_VERSION, "event": event, "timestamp_utc": ts}
            rec.update(fields)
            # Scrub string values (recursively for body/arguments), never the serialized
            # line: a short secret that matches a digit of a number would break the JSON.
            rec = {k: _scrub_value(v, secrets) for k, v in rec.items()}
            if self.chain is not None:
                # The chain fields are added after scrubbing and are never scrubbed.
                self._write_chained(rec, ts)
                return
            line = canonical_json(rec)
        else:
            line = _text_line(event, ts, fields, secrets)
        self._write(line, ts)

    def _write(self, line: str, ts: str) -> None:
        with self._lock:
            self._write_locked(line, ts)

    def _write_locked(self, line: str | None, ts: str) -> None:
        """Write ``line`` (``None``: only the pending recovery record). After a fault the
        ``audit.recovered`` record goes first, stamped with the same time as the record
        that follows it; the loss count resets once it is written."""
        if self.chain is not None:
            # Chained, only a policy line (written byte-identical, then sealed) or the
            # pending recovery record (``line`` None, from :meth:`probe`) arrives here.
            self._chained_locked(None, ts, line)
            return
        try:
            if self._fault is not None:
                self._sink_write(self._recovered_line(ts))
                self._fault, self._lost = None, 0
            if line is not None:
                self._sink_write(line)
        except SinkWriteError as exc:
            if self._fault is None:
                _logger.warning(
                    "audit sink %s unavailable (%s); records are dropped until it recovers",
                    self.sink.name,
                    exc.errno_name,
                )
            self._fault = self._fault or exc.errno_name
            if line is not None:
                self._lost += 1

    # -- the hash chain (UNIFI_AUDIT_CHAIN; JSON file sink only)
    def _write_chained(
        self, rec: dict[str, Any] | None, ts: str, policy_line: str | None = None
    ) -> None:
        with self._lock:
            self._chained_locked(rec, ts, policy_line)

    def _chained_locked(self, rec: dict[str, Any] | None, ts: str, policy_line: str | None) -> None:
        """One chained write, inside one lock acquisition: ``audit.chain_start`` first
        if the chain has not started, then the pending ``audit.recovered``, then ``rec``
        (or a policy line, byte-identical, followed by its ``audit.seal``). Fails open
        exactly like :meth:`_write_locked`."""
        try:
            if self.chain is not None and not self.chain.started:
                self._put(self._envelope(CHAIN_START_EVENT, ts, self.chain.start_fields()))
            if self._fault is not None:
                fields = {"lost_records": self._lost, "fault": self._fault}
                self._put(self._envelope("audit.recovered", ts, fields))
                self._fault, self._lost = None, 0
            if policy_line is not None:
                self._sink_write(policy_line)
                seal = {"sealed_sha256": sealed_digest(policy_line)}
                self._put(self._envelope(SEAL_EVENT, ts, seal))
            elif rec is not None:
                self._put(rec)
        except SinkWriteError as exc:
            if self._fault is None:
                _logger.warning(
                    "audit sink %s unavailable (%s); records are dropped until it recovers",
                    self.sink.name,
                    exc.errno_name,
                )
            self._fault = self._fault or exc.errno_name
            if rec is not None or policy_line is not None:
                self._lost += 1

    @staticmethod
    def _envelope(event: str, ts: str, fields: dict[str, Any]) -> dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION, "event": event, "timestamp_utc": ts, **fields}

    def _put(self, rec: dict[str, Any]) -> None:
        """Write ``rec`` as the next chained record; the chain advances only when the
        whole line reached the file (:attr:`FileSink.last_complete`)."""
        chain, sink = self.chain, self.sink
        if chain is None or not isinstance(sink, FileSink):
            raise RuntimeError("the audit chain needs the file sink")
        line, mac = chain.seal(rec, canonical_json)
        try:
            self._sink_write(line)
        except SinkWriteError:
            if sink.last_complete:
                chain.advance(mac)
            raise
        chain.advance(mac)

    def _sink_write(self, line: str) -> None:
        """Write ``line`` to the primary sink, then hand the same line to the
        remote copy. The primary write comes first and keeps its fault semantics (it raises
        :class:`SinkWriteError`); the remote copy gets the line even when that write failed (a
        second copy never depends on the first) and never raises or blocks. Every write
        of the stream, a hash chain's included, goes through here."""
        try:
            self.sink.write(line)
        finally:
            if self.remote_copy is not None:
                try:
                    self.remote_copy.write(line)
                except Exception:  # noqa: BLE001, S110 - the remote copy fails open
                    pass

    def _recovered_line(self, ts: str) -> str:
        fields = {"lost_records": self._lost, "fault": self._fault}
        if self.fmt == "json":
            return canonical_json(
                {
                    "schema_version": SCHEMA_VERSION,
                    "event": "audit.recovered",
                    "timestamp_utc": ts,
                    **fields,
                }
            )
        return _text_line("audit.recovered", ts, fields, ())


#: Kept name: the 0.7.0 class every caller and test constructs.
class AuditSink(AuditStream):
    """An :class:`AuditStream` over a file path (the 0.7.0 constructor)."""

    def __init__(
        self,
        path: str,
        fmt: str = "json",
        secrets: tuple[str, ...] = (),
        *,
        level: str = "normal",
        calls: bool = False,
        mode: int = 0o600,
    ) -> None:
        super().__init__(
            sink=FileSink(path=path, mode=mode),
            fmt=fmt,
            level=level,
            calls=calls,
            secrets=secrets,
        )


def _scrub_value(value: Any, secrets: tuple[str, ...]) -> Any:
    if isinstance(value, str):
        return scrub(value, secrets)
    if isinstance(value, dict | list):
        return scrub_json_strings(value, secrets)
    return value


def _safe_path(path: str, secrets: tuple[str, ...]) -> str:
    """The path without query or fragment, scrubbed; ``***`` if a secret spans the cut."""
    prefix = path.partition("?")[0].partition("#")[0]
    safe_prefix = scrub(prefix, secrets)
    safe_path = scrub(path, secrets)
    # A secret can span the delimiter. Scrubbing the truncated prefix alone would expose
    # its leading fragment; fail closed if the boundary moved.
    if len(prefix) < len(path) and not safe_path.startswith(safe_prefix + path[len(prefix)]):
        return "***"
    return safe_prefix


#: A URL or path followed by a query inside free text (a refusal message that quotes
#: the request path): the query, and any fragment after it, is cut like the ``path``
#: field's. A bare ``#anchor`` (a documentation link) carries no request data and stays.
_QUERY_IN_TEXT = re.compile(r"(?P<p>(?:https?://[^\s'\"?#]*|/[^\s'\"?#]*))\?[^\s'\"]*")
#: A pydantic validation message echoes the rejected value as ``input_value=...``.
_INPUT_VALUE = re.compile(r"input_value=(?:.*(?=, input_type=\w+\])|.*)", re.S)
_TEXT_MAX = 4096


def _safe_reason(text: str, secrets: tuple[str, ...] = ()) -> str:
    """A free-text reason or error message: secrets scrubbed first (on the whole text, so
    the cap never cuts a secret or an escape chain around it), queries and fragments of
    quoted paths cut, echoed validation inputs masked, capped."""
    text = scrub(text, secrets)
    text = _QUERY_IN_TEXT.sub(lambda m: m.group("p"), text)
    return _cap_text(_INPUT_VALUE.sub("input_value=***", text))


def _cap_text(text: str) -> str:
    return text if len(text) <= _TEXT_MAX else text[:_TEXT_MAX] + "...[truncated]"


#: Characters that make a text-format value JSON-quoted (besides whitespace).
_QUOTED = frozenset('"=\\')


def _text_field(value: str) -> str:
    """A text-format field value: as is when it is one plain token, else JSON-quoted,
    so a free-text reason (spaces, newlines, quotes) stays one field of one line."""
    if value and all(c.isprintable() and not c.isspace() and c not in _QUOTED for c in value):
        return value
    return json.dumps(value, ensure_ascii=False)


_AUDIT_TEXT_ORDER = ("method", "path", "outcome", "status")


def _text_line(event: str, ts: str, fields: dict[str, Any], secrets: tuple[str, ...]) -> str:
    """The text form. Values are scrubbed before encoding, then the completed line too:
    a secret can span a label/value boundary or equal metadata, and text redaction takes
    precedence over preserving colliding field bytes."""

    def text(value: Any) -> str:
        if value is None:
            return "-"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int | float):
            return str(value)
        if isinstance(value, dict | list):
            return _text_field(canonical_json({"v": scrub_json_strings(value, secrets)})[5:-1])
        return _text_field(scrub(str(value), secrets))

    parts = [scrub(ts, secrets)]
    if event == "audit":
        # The 0.7.0 line: no event field; method/path/outcome/status first, in order.
        parts += [f"{k}={text(fields.get(k) or None)}" for k in _AUDIT_TEXT_ORDER[:2]]
        parts += [f"{k}={text(fields.get(k))}" for k in _AUDIT_TEXT_ORDER[2:]]
        rest = {k: v for k, v in fields.items() if k not in _AUDIT_TEXT_ORDER}
    else:
        parts.append(f"event={event}")
        rest = fields
    parts += [f"{k}={text(v)}" for k, v in rest.items() if v is not None]
    line = scrub(" ".join(parts), secrets)
    return _LINE_UNSAFE.sub(lambda m: f"\\u{ord(m.group()):04x}", line)


# ---------------------------------------------------------------------------- builder
def resolve_sink_name(settings: Settings) -> str:
    """The effective sink: ``UNIFI_AUDIT_SINK``, else ``file`` when a path is set."""
    sink = (getattr(settings, "audit_sink", "") or "").strip()
    if sink:
        return sink
    return "file" if (settings.audit_log or "").strip() else "none"


def build_audit_stream(settings: Settings) -> AuditStream | None:
    """The configured stream, or ``None`` when no sink is configured (the default)."""
    _warn_unused_chain_key(settings)
    sink_name = resolve_sink_name(settings)
    if sink_name == "none":
        return None
    fmt = (settings.audit_log_format or "json").strip().lower()
    level = (getattr(settings, "audit_level", "normal") or "normal").strip().lower()
    calls = bool(getattr(settings, "audit_calls", False))
    secrets = configured_secrets(settings)
    sink: Sink | RemoteSink
    remote_copy: RemoteSink | None = None
    path = (settings.audit_log or "").strip()
    if sink_name == "stderr":
        sink = StderrSink()
    elif sink_name == "remote":
        from .audit_remote import RemoteConfig, RemoteSink

        remote = RemoteSink(RemoteConfig.from_settings(settings))
        if path:  # additive: the local file first, the collector copy after it
            mode = FILE_MODES[(getattr(settings, "audit_log_mode", "0600") or "0600").strip()]
            sink, remote_copy = FileSink(path=path, mode=mode), remote
        else:
            sink = remote
    else:
        mode = FILE_MODES[(getattr(settings, "audit_log_mode", "0600") or "0600").strip()]
        sink = FileSink(path=settings.audit_log.strip(), mode=mode)
    chain = _build_chain(settings, sink)
    return AuditStream(
        sink=sink,
        remote_copy=remote_copy,
        fmt=fmt,
        level=level,
        calls=calls,
        secrets=secrets,
        chain=chain,
    )


def _build_chain(settings: Settings, sink: Sink | RemoteSink) -> ChainState | None:
    """The hash chain when ``UNIFI_AUDIT_CHAIN`` is on (Settings has already refused a
    text format, a non-file sink, a missing key and a key equal to
    ``UNIFI_AUDIT_HMAC_KEY``), else ``None``."""
    if not getattr(settings, "audit_chain", False):
        return None
    key = settings.audit_chain_key_bytes()
    if key is None or not isinstance(sink, FileSink):  # pragma: no cover - Settings refuses
        raise ValueError("UNIFI_AUDIT_CHAIN requires UNIFI_AUDIT_CHAIN_KEY and the file sink")
    level = logging.getLevelName((getattr(settings, "log_level", "INFO") or "INFO").upper())
    if isinstance(level, int) and level > logging.INFO:
        # Logged at the configured level when that is above WARNING, so it is never hidden.
        _logger.log(
            max(logging.WARNING, level),
            "warning: UNIFI_AUDIT_CHAIN is on but UNIFI_LOG_LEVEL is above INFO, so the "
            "INFO audit chain head lines (the anchors) are not logged",
        )
    return ChainState.from_key(key, sink.path)


def _warn_unused_chain_key(settings: Settings) -> None:
    if getattr(settings, "audit_chain_key", None) is not None and not getattr(
        settings, "audit_chain", False
    ):
        _logger.warning(
            "UNIFI_AUDIT_CHAIN_KEY is set but UNIFI_AUDIT_CHAIN is off; it has no effect"
        )


#: Kept name for 0.7.0 callers.
build_audit_sink = build_audit_stream


def configure_audit_stream(settings: Settings) -> AuditStream | None:
    """:func:`build_audit_stream` plus the opt-in HMAC identifiers
    (``UNIFI_AUDIT_HMAC_IDENTIFIERS`` with ``UNIFI_AUDIT_HMAC_KEY``). The server builds
    its stream here."""
    stream = build_audit_stream(settings)
    if stream is not None and getattr(settings, "audit_hmac_identifiers", False):
        key = settings.audit_hmac_key_bytes()
        if key is None:  # pragma: no cover - Settings refuses the flag without the key
            raise ValueError("UNIFI_AUDIT_HMAC_IDENTIFIERS=true requires UNIFI_AUDIT_HMAC_KEY")
        from .audit_identifiers import IdentifierHasher

        stream.identifiers = IdentifierHasher(key)
    return stream


def close_audit_stream(stream: AuditStream | None) -> None:
    """Stop a remote sink's delivery worker (no-op for the other sinks)."""
    remote = stream.remote if stream is not None else None
    if remote is not None:
        remote.close()


def _remote_sink(sink: object) -> RemoteSink | None:
    """``sink`` when it is the remote sink (imported on first use: the stream needs
    the remote transport only when it is configured)."""
    from .audit_remote import RemoteSink

    return sink if isinstance(sink, RemoteSink) else None
