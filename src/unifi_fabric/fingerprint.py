"""Keyed fingerprints of secret values: the one shared construction.

Why this is a keyed MAC and not a bare hash. CodeQL's ``py/weak-sensitive-data-hashing``
flags a bare fast hash (SHA-256, BLAKE2 without a key) of a secret: an attacker who sees
the digest can brute-force or dictionary-test candidate secrets offline at hash speed.
A keyed MAC, here HMAC-SHA256 under a per-process random key, is the accepted fix: the
digest cannot be checked against a guessed secret without the key, and the key lives only
in this process's memory. The scanner's concern is the construction, not the digest
length, so truncating a digest does not address it and a longer one is not needed.

The key is ``secrets.token_bytes(32)`` drawn once at import. It is never logged, never
persisted, and never derived from a configured secret. Consequences: a fingerprint is
stable within a process and differs across processes, so it can label, group and key an
in-process cache or memo but cannot be compared across restarts and is not a persistent
identifier. Nothing here is reversible; callers keep their existing log shapes by
choosing the truncation length.
"""

from __future__ import annotations

import hmac
import secrets

#: Per-process random MAC key. Deliberately private: never logged, persisted or derived.
_KEY = secrets.token_bytes(32)


def _material(value: str | bytes) -> bytes:
    return value if isinstance(value, bytes) else value.encode("utf-8", "surrogatepass")


def key_digest_bytes(value: str | bytes) -> bytes:
    """The 32-byte HMAC-SHA256 of ``value`` under the per-process key."""
    return hmac.digest(_KEY, _material(value), "sha256")


def key_digest(value: str | bytes) -> str:
    """The full lowercase 64-hex keyed digest of ``value`` (identity within a process)."""
    return key_digest_bytes(value).hex()


def key_fingerprint(value: str | bytes, length: int = 8) -> str:
    """The first ``length`` hex characters of :func:`key_digest` (default 8, at most 64)."""
    if not 1 <= length <= 64:
        raise ValueError("length must be between 1 and 64")
    return key_digest(value)[:length]
