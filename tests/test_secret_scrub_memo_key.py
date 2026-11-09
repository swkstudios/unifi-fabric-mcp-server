"""Regression coverage for keyed memoization of scrub outcomes."""

import subprocess
import sys
from unittest.mock import patch

from unifi_fabric import secret_scrub


def test_repeated_input_hits_memo():
    secret_scrub._memo_clear()
    text = "x" * 4096 + "synthetic-secret"
    with patch.object(secret_scrub, "_scrub_rounds", wraps=secret_scrub._scrub_rounds) as rounds:
        first = secret_scrub._scrub_outcome(text, ("synthetic-secret",), False)
        assert secret_scrub._scrub_outcome(text, ("synthetic-secret",), False) == first
        assert rounds.call_count == 1
    secret_scrub._memo_clear()


def test_memo_digest_differs_between_processes():
    command = [
        sys.executable,
        "-c",
        "from unifi_fabric.secret_scrub import _memo_key; "
        "print(_memo_key('synthetic', (), False)[2].hex())",
    ]
    digests = [
        subprocess.check_output(command, text=True).strip()  # noqa: S603 -- fixed synthetic input
        for _ in range(2)
    ]
    assert all(len(digest) == 64 and bytes.fromhex(digest) for digest in digests)
    assert digests[0] != digests[1]
