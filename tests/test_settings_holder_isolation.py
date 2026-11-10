"""A client left alive by one test never scrubs a later test's log records.

Every ``UniFiClient`` registers in ``secret_scrub._live_settings_holders``, and log free
text is scrubbed of the keys of every client still registered there, including a secret
embedded in a larger word. Before ``tests/conftest.py::_forget_test_settings_holders``, a
``Settings(api_key="k")`` client that an earlier test left as cyclic garbage stayed
registered until the garbage collector ran, so on one xdist worker the key-file warning
read ``the ***ey file`` (v0.7.2 public-artifact dry-run). The first test below keeps its
client alive on purpose, which is the worst case of that garbage, so the second test
fails deterministically without the fixture. Both are pinned to one xdist group so they
run in this order on one worker.
"""

from __future__ import annotations

import logging

import pytest

from unifi_fabric import credential_providers, secret_scrub
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings

pytestmark = pytest.mark.xdist_group("settings-holder-isolation")

#: Kept alive across the two tests, like an uncollected client from an earlier test.
_KEPT: list[UniFiClient] = []


def _key_file_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    with caplog.at_level(logging.WARNING):
        credential_providers._warn_writable("UNIFI_API_KEY_FILE", "the key file", 0o620)
    return [r.getMessage() for r in caplog.records if "writable by group" in r.getMessage()]


def test_a_client_scrubs_log_records_of_its_one_letter_key_while_its_test_runs(caplog):
    """The precondition: while its client is registered, the key ``k`` is masked inside
    ``key`` in log free text (the strict log policy, not a scrubber defect)."""
    _KEPT.append(UniFiClient(Settings(api_key="k")))
    assert "k" in secret_scrub._log_secrets()
    assert _key_file_warnings(caplog)[0].startswith("UNIFI_API_KEY_FILE: the ***ey file")


def test_a_client_left_alive_by_an_earlier_test_does_not_scrub_this_tests_logs(caplog):
    try:
        assert "k" not in secret_scrub._log_secrets()
        warnings = _key_file_warnings(caplog)
        assert len(warnings) == 1
        assert warnings[0].startswith("UNIFI_API_KEY_FILE: the key file")
        assert warnings[0].endswith("as its API key. Restrict it to its owner")
    finally:
        _KEPT.clear()
