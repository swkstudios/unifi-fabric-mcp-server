"""Opt-in tamper evidence for the JSON audit file: a keyed hash chain.

OFF by default (``UNIFI_AUDIT_CHAIN``). When on, every JSON record the file sink writes
carries four more fields and is bound to the record before it:

* ``chain`` -- 32 hex, random per process start (one chain per process);
* ``seq`` -- 0-based position in the chain;
* ``prev`` -- the ``mac`` of the record before it in the chain (64 zeros at ``seq`` 0);
* ``mac`` -- ``HMAC-SHA256(subkey, DOMAIN + line_bytes)``, where ``line_bytes`` are the
  exact UTF-8 bytes the sink writes for the record (``errors="backslashreplace"``) with
  the ``mac`` member left out. The verifier recovers them from the raw line bytes.

This is the Crosby & Wallach hash chain ``C_i = H(C_{i-1} || X_i)`` with a keyed ``H``.
It makes changes to the file *evident* to whoever holds the key; it does not prevent
them, and anyone holding the key can write a valid chain. ``docs/CONFIGURATION.md``
(Audit log, Tamper evidence) lists what it does not detect.

Stdlib only. This module never generates, stores or prints a key; the verifier
(:mod:`unifi_fabric.audit_verify`) is a separate, independent implementation that imports
no server code, and the server never calls it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

_logger = logging.getLogger("unifi_fabric.audit")

#: Context of the per-key subkey: the raw key is never used directly as a MAC key.
SUBKEY_CONTEXT = b"unifi-fabric/audit-chain/v1"
#: Fixed prefix of every MAC input (domain separation).
DOMAIN = b"unifi-fabric-audit-chain\x00v1\x00"
#: ``prev`` of the first record of a chain.
ZERO_MAC = "0" * 64
#: The chain head is logged at INFO at chain start, then every this many records.
HEAD_EVERY = 100
#: The startup read of the existing file's tail is bounded to this many bytes.
TAIL_BYTES = 65536
#: The four fields a chained record adds.
CHAIN_FIELDS = ("chain", "seq", "prev", "mac")
CHAIN_START_EVENT = "audit.chain_start"
SEAL_EVENT = "audit.seal"

_KEY_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_HEX32 = re.compile(r"[0-9a-f]{32}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def decode_key(text: str) -> bytes | None:
    """32 key bytes from canonical unpadded base64url, else ``None`` (never echoed)."""
    if not isinstance(text, str) or _KEY_RE.fullmatch(text) is None:
        return None
    try:
        raw = base64.b64decode(text + "=", altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != text:
        return None
    return raw


def derive_subkey(key: bytes) -> bytes:
    """The MAC key: ``HMAC-SHA256(key, SUBKEY_CONTEXT)``."""
    return hmac.digest(key, SUBKEY_CONTEXT, "sha256")


def key_id(subkey: bytes) -> str:
    """``kid``: 8 hex of a keyed fingerprint of the subkey (not key material)."""
    return hmac.digest(subkey, b"kid", "sha256").hex()[:8]


def line_bytes(line: str) -> bytes:
    """The bytes the file sink writes for ``line`` (without its newline)."""
    return line.encode("utf-8", errors="backslashreplace")


def record_mac(subkey: bytes, data: bytes) -> str:
    """The MAC of one record's line bytes (``mac`` member left out)."""
    return hmac.digest(subkey, DOMAIN + data, "sha256").hex()


def sealed_digest(line: str) -> str:
    """``sealed_sha256`` of a policy line: SHA-256 of its exact on-disk bytes."""
    return hashlib.sha256(line_bytes(line)).hexdigest()


def _chain_fields_valid(rec: Mapping[str, Any]) -> bool:
    seq = rec.get("seq")
    return (
        isinstance(rec.get("chain"), str)
        and _HEX32.fullmatch(rec["chain"]) is not None
        and isinstance(seq, int)
        and not isinstance(seq, bool)
        and seq >= 0
        and isinstance(rec.get("mac"), str)
        and _HEX64.fullmatch(rec["mac"]) is not None
    )


def read_tail_link(path: str) -> tuple[str, int, str] | None:
    """``(chain, seq, mac)`` of the last chained record in the final :data:`TAIL_BYTES`
    of ``path``, or ``None``.

    Read only from a regular file owned by this process's user, opened
    ``O_RDONLY | O_NOFOLLOW | O_NONBLOCK`` and judged on the descriptor, so a symlink
    (the ``/dev/stderr`` target), a FIFO or a device is never read (a read could block or
    consume a FIFO). Any failure fails open to ``None``.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOCTTY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            return None
        start = max(0, st.st_size - TAIL_BYTES)
        data = os.pread(fd, min(TAIL_BYTES, st.st_size), start)
    except OSError:
        return None
    finally:
        os.close(fd)
    lines = data.split(b"\n")
    if start > 0:
        lines = lines[1:]  # the first line may be cut by the window
    for raw in reversed(lines):
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if isinstance(rec, dict) and _chain_fields_valid(rec):
            return rec["chain"], rec["seq"], rec["mac"]
    return None


@dataclass
class ChainState:
    """The writer side of one chain (one per process). Not thread-safe by itself: the
    audit stream drives it under its own lock."""

    subkey: bytes = field(repr=False)
    kid: str = ""
    chain_id: str = field(default_factory=lambda: secrets.token_hex(16))
    #: The ``seq`` of the next record written.
    seq: int = 0
    #: The ``mac`` of the last record written (``prev`` of the next one).
    prev: str = ZERO_MAC
    #: The predecessor this chain links to (read once at startup), or ``None``.
    link: tuple[str, int, str] | None = None

    @classmethod
    def from_key(cls, key: bytes, path: str | None) -> ChainState:
        subkey = derive_subkey(key)
        return cls(
            subkey=subkey,
            kid=key_id(subkey),
            link=read_tail_link(path) if path else None,
        )

    @property
    def started(self) -> bool:
        return self.seq > 0

    @property
    def head(self) -> str | None:
        """``CHAIN:SEQ:MAC`` of the last record written (not secret), or ``None``."""
        if not self.started:
            return None
        return f"{self.chain_id}:{self.seq - 1}:{self.prev}"

    def start_fields(self) -> dict[str, Any]:
        """The fields of the ``audit.chain_start`` record."""
        chain, seq, mac = self.link if self.link is not None else (None, None, None)
        return {"kid": self.kid, "prev_chain": chain, "prev_seq": seq, "prev_mac": mac}

    def seal(
        self, rec: Mapping[str, Any], serialize: Callable[[Mapping[str, Any]], str]
    ) -> tuple[str, str]:
        """``(line, mac)`` for ``rec`` as the next record. The state is not advanced:
        call :meth:`advance` once the whole line is written."""
        body = {k: v for k, v in rec.items() if k not in CHAIN_FIELDS}
        body.update(chain=self.chain_id, seq=self.seq, prev=self.prev)
        mac = record_mac(self.subkey, line_bytes(serialize(body)))
        body["mac"] = mac
        return serialize(body), mac

    def advance(self, mac: str) -> None:
        written = self.seq
        self.seq += 1
        self.prev = mac
        if written % HEAD_EVERY == 0:
            self.log_head("chain start" if written == 0 else "periodic")

    def log_head(self, reason: str) -> None:
        """Log the head at INFO (an anchor for ``--expect-head``; not secret)."""
        head = self.head
        if head is not None:
            _logger.info("audit chain head (%s): %s", reason, head)
