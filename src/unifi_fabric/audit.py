"""Opt-in audit log for write operations.

OFF by default. When ``UNIFI_AUDIT_LOG`` names a file path, EVERY write/action a tool
sends through the shared HTTP chokepoint (``UniFiClient.request`` — i.e. every
POST/PUT/PATCH/DELETE that is classified as a write) is appended as a structured
record carrying: timestamp (UTC ISO-8601), HTTP method, the resolved request path,
the outcome, and the upstream status. Format is selectable via
``UNIFI_AUDIT_LOG_FORMAT`` (``text`` default, or ``json`` for one JSON object per line).

Because the chokepoint is below every tool, this covers all write surfaces uniformly
(network, protect, hotspot, device management, clients, carrier fabric, mobility, port
profiles, settings, the connector relay, ...) without per-tool wiring.

A write attempt refused before it reaches the upstream is audited too, with
``outcome=refused`` and a ``reason`` naming the gate: ``UNIFI_READ_ONLY`` (the read-only
mode, at the tool middleware or the chokepoint), the area opt-out variable
(``UNIFI_ENABLE_NETWORK_WRITE``, ``UNIFI_PROTECT_MUTATIONS_ENABLED``,
``UNIFI_ENABLE_MOBILITY_WRITE``, ``UNIFI_ENABLE_CARRIER_FABRIC_WRITE``,
``UNIFI_ENABLE_INNERSPACE_WRITE``,
``UNIFI_ENABLE_CONNECTOR_WRITE``; at the tool middleware or the chokepoint), or
``empty_update`` / ``required_body_fields`` (the empty-update guard). Every other refusal
of a write tool call, at any layer (an argument check, a guard inside the tool, a
list-first resolution that finds no such id, the chokepoint's unsafe-path and
mask-only-body checks, the connector relay's validation), is audited too, exactly once,
with the refusal message as ``reason`` (:mod:`unifi_fabric.refusal_audit`). A refusal
made before the request is resolved carries the ``tool`` name, and ``method`` / ``path``
are absent (``-`` in the text format, ``null`` in JSON). In the text format a reason that
is not one plain token is written JSON-quoted, so it stays one field of one line.

Design notes:

* **Opt-in / byte-identical when off.** With ``UNIFI_AUDIT_LOG`` unset,
  :func:`build_audit_sink` returns ``None`` and the request path is byte-identical to
  today — nothing is written.
* **Secret scrubbing.** Only the method, resolved path, outcome and status are
  recorded. The request BODY is deliberately NOT written (a write body can contain a
  passphrase/secret), and the API key only ever travels in a header, never the path.
  Text records also pass through the central secret scrubber after assembly.
  JSON string values are scrubbed before encoding. JSON keys and numeric metadata
  retain their original values, including when they equal a configured secret.
* **Fail fast on a bad format.** ``UNIFI_AUDIT_LOG_FORMAT`` is validated when the
  settings load; an unknown value is a startup error listing the formats, never a
  silent fallback.
* **Best-effort, never fatal.** A sink write failure is swallowed (logged at WARNING);
  an audit-log I/O error must never break a tool call.
"""

from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import TYPE_CHECKING

from .refusal_audit import note_refused_record
from .secret_scrub import configured_secrets, scrub

if TYPE_CHECKING:
    from .config import Settings

_logger = logging.getLogger(__name__)

_VALID_FORMATS = ("text", "json")
_AUDIT_TOOL: ContextVar[str | None] = ContextVar("audit_tool", default=None)
_AUDIT_HOST: ContextVar[str | None] = ContextVar("audit_host", default=None)
_AUDIT_SITE: ContextVar[str | None] = ContextVar("audit_site", default=None)
_AUDIT_START: ContextVar[float | None] = ContextVar("audit_start", default=None)


@contextmanager
def audit_call(tool: str | None):
    """Scope tool provenance and duration to its audit records."""
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


def set_audit_resolution(*, host: str | None = None, site: str | None = None) -> None:
    if host is not None:
        _AUDIT_HOST.set(host)
    if site is not None:
        _AUDIT_SITE.set(site)


@dataclass(frozen=True)
class AuditSink:
    """Append-only structured audit sink writing to a configured file path."""

    path: str
    fmt: str = "text"
    #: Configured secrets each line is scrubbed of (never shown in repr).
    secrets: tuple[str, ...] = field(default=(), repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.fmt not in _VALID_FORMATS:
            raise ValueError(
                f"UNIFI_AUDIT_LOG_FORMAT must be one of {', '.join(_VALID_FORMATS)} "
                "(the value is not shown here)"
            )

    def record(
        self,
        *,
        method: str | None,
        path: str | None,
        outcome: str,
        status: int | None,
        tool: str | None = None,
        reason: str | None = None,
    ) -> None:
        """Append one audit record for a write attempt. Best-effort — I/O errors swallowed.

        The request body is omitted and configured string values are scrubbed. ``tool``
        and ``reason`` (the gate that refused the attempt) are written only when given.
        JSON metadata is preserved as described above.
        """
        ts = datetime.now(UTC).isoformat()
        tool = tool or _AUDIT_TOOL.get()
        resolved_host, resolved_site = _AUDIT_HOST.get(), _AUDIT_SITE.get()
        started = _AUDIT_START.get()
        duration_ms = round((perf_counter() - started) * 1000, 3) if started is not None else None
        secrets = configured_secrets(extra=self.secrets)
        # Scrub the free-text values before they are encoded: JSON quoting doubles every
        # backslash, which would hide an escaped secret from the scrub of the whole line.
        if reason is not None:
            reason = scrub(reason, secrets)
        if path is not None:
            # Refusals can arrive before route validation; no query or fragment belongs
            # in either audit format, including values not registered as credentials.
            prefix = path.partition("?")[0].partition("#")[0]
            safe_prefix = scrub(prefix, secrets)
            safe_path = scrub(path, secrets)
            # A secret can span the delimiter. Scrubbing the truncated prefix alone
            # would expose its leading fragment; fail closed if the boundary moved.
            if len(prefix) < len(path) and not safe_path.startswith(
                safe_prefix + path[len(prefix)]
            ):
                path = "***"
            else:
                path = safe_prefix
        if self.fmt == "json":
            rec: dict[str, object] = {
                "timestamp": ts,
                "method": method,
                "path": path,
                "outcome": outcome,
                "status": status,
            }
            if tool is not None:
                rec["tool"] = tool
            if reason is not None:
                rec["reason"] = reason
            if resolved_host is not None:
                rec["resolvedHost"] = resolved_host
            if resolved_site is not None:
                rec["resolvedSite"] = resolved_site
            if duration_ms is not None:
                rec["duration_ms"] = duration_ms
            # Scrub the string values, never the serialized line: a short configured secret
            # that matches a digit of ``status`` or ``duration_ms`` would otherwise turn the
            # number into a mask and leave a line that is not valid JSON.
            rec = {k: scrub(v, secrets) if isinstance(v, str) else v for k, v in rec.items()}
            line = json.dumps(rec, separators=(",", ":"))
        else:
            # Scrub values before encoding, then the completed text line as well.
            # A configured secret can span a label/value boundary or equal metadata;
            # text redaction takes precedence over preserving colliding field bytes.
            def text(value: str) -> str:
                return _text_field(scrub(value, secrets))

            line = (
                f"{scrub(ts, secrets)} method={text(method or '-')} "
                f"path={text(path or '-')} outcome={text(outcome)} "
                f"status={status if status is not None else '-'}"
            )
            if tool is not None:
                line += f" tool={text(tool)}"
            if reason is not None:
                line += f" reason={text(reason)}"
            if resolved_host is not None:
                line += f" resolvedHost={text(resolved_host)}"
            if resolved_site is not None:
                line += f" resolvedSite={text(resolved_site)}"
            if duration_ms is not None:
                line += f" duration_ms={duration_ms}"
            line = scrub(line, secrets)
        if outcome == "refused":
            note_refused_record()
        try:
            with Path(self.path).open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:  # pragma: no cover - defensive, never fatal
            _logger.warning("audit-log write failed path=%s error=%s", self.path, exc)


#: Characters that make a text-format value JSON-quoted (besides whitespace).
_QUOTED = frozenset('"=\\')


def _text_field(value: str) -> str:
    """A text-format field value: as is when it is one plain token, else JSON-quoted,
    so a free-text reason (spaces, newlines, quotes) stays one field of one line."""
    if value and all(c.isprintable() and not c.isspace() and c not in _QUOTED for c in value):
        return value
    return json.dumps(value, ensure_ascii=False)


def build_audit_sink(settings: Settings) -> AuditSink | None:
    """Return an :class:`AuditSink` when ``UNIFI_AUDIT_LOG`` is set, else ``None``.

    ``None`` is the default (opt-in): the caller then writes nothing to disk. An
    unrecognised format raises ``ValueError`` listing the formats (the settings
    validator already rejects one at startup).
    """
    path = (settings.audit_log or "").strip()
    if not path:
        return None
    fmt = (settings.audit_log_format or "text").strip().lower()
    return AuditSink(path=path, fmt=fmt, secrets=configured_secrets(settings))
