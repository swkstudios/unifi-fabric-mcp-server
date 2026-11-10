"""The shared keyed fingerprint helper (CodeQL py/weak-sensitive-data-hashing fix)."""

from __future__ import annotations

import hashlib
import logging
import subprocess
import sys

from unifi_fabric import fingerprint
from unifi_fabric.fingerprint import key_digest, key_digest_bytes, key_fingerprint

SECRET = "synthetic-secret-value-for-fingerprint"


def test_stable_within_a_process_and_shaped_like_before():
    assert key_digest(SECRET) == key_digest(SECRET) == key_digest_bytes(SECRET.encode()).hex()
    assert len(key_digest(SECRET)) == 64
    assert key_fingerprint(SECRET) == key_digest(SECRET)[:8]
    assert len(key_fingerprint(SECRET, 16)) == 16
    assert len(key_digest_bytes(SECRET)) == 32
    assert key_fingerprint(SECRET) != key_fingerprint(SECRET + "x")


def test_never_equal_to_a_bare_hash_of_the_value():
    data = SECRET.encode()
    assert key_digest(SECRET) != hashlib.sha256(data).hexdigest()
    assert key_digest_bytes(SECRET) != hashlib.blake2b(data, digest_size=32).digest()
    assert key_fingerprint(SECRET) != hashlib.sha256(data).hexdigest()[:8]


def test_differs_across_processes():
    code = f"from unifi_fabric.fingerprint import key_digest;print(key_digest({SECRET!r}))"
    runs = {
        subprocess.run(  # noqa: S603 -- fixed interpreter, synthetic value
            [sys.executable, "-c", code], capture_output=True, text=True, check=True
        ).stdout.strip()
        for _ in range(2)
    }
    assert len(runs) == 2
    assert key_digest(SECRET) not in runs


def test_no_secret_or_key_bytes_in_repr_or_logs(caplog):
    caplog.set_level(logging.DEBUG)
    logging.getLogger("unifi_fabric").debug("fp=%s", key_fingerprint(SECRET))
    shown = repr(fingerprint) + caplog.text + key_fingerprint(SECRET)
    assert SECRET not in shown
    assert fingerprint._KEY.hex() not in shown


def test_length_is_validated():
    for bad in (0, 65):
        try:
            key_fingerprint(SECRET, bad)
        except ValueError:
            continue
        raise AssertionError("length was not validated")
