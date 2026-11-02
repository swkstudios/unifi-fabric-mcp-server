"""Properties for successful per-record logging dedup; core stays unchanged."""

from __future__ import annotations

import logging
import random
from io import StringIO

import pytest

import unifi_fabric.log_scrub_memo as memo
import unifi_fabric.secret_scrub as core
from tests import scrub_fuzz


def test_call_secret_never_enters_global_memo_with_retained_record(monkeypatch):
    core.install_log_scrubber()
    secret = "synthetic-call-only-memo-lifetime-361"
    monkeypatch.setattr(core, "_log_secrets", lambda: core.call_secret_values())
    stream = StringIO()
    retained = []

    class RetainingHandler(logging.StreamHandler):
        def emit(self, record):
            retained.append(record)
            super().emit(record)

    handler = RetainingHandler(stream)
    logger = logging.Logger("memo-call-lifetime")
    logger.addHandler(handler)
    with core.secret_scope((secret,)):
        logger.error("call value: %s", secret)
    assert retained  # Keep the production-created record alive across scope exit.
    assert stream.getvalue() == "call value: ***\n"
    assert secret not in repr(memo._entries)
    assert all(key[0] != id(retained[0]) for key in memo._entries)
    assert not core.call_secret_values()


def test_configured_only_logger_still_uses_global_memo(monkeypatch):
    core.install_log_scrubber()
    secret = "synthetic-configured-only-memo-361"
    monkeypatch.setattr(core, "_log_secrets", lambda: (secret,))
    stream = StringIO()
    retained = []

    class RetainingHandler(logging.StreamHandler):
        def emit(self, record):
            retained.append(record)
            super().emit(record)

    logger = logging.Logger("memo-configured-lifetime")
    logger.addHandler(RetainingHandler(stream))
    logger.error("configured value: %s", secret)
    assert stream.getvalue() == "configured value: ***\n"
    assert any(key[0] == id(retained[0]) for key in memo._entries)


@pytest.mark.parametrize("chunk", range(4))
@pytest.mark.parametrize("shallow", [False, True])
def test_memo_handler_matches_per_call_and_corpus_is_idempotent(chunk, shallow, monkeypatch):
    core.install_log_scrubber()
    rng = random.Random((36200 if shallow else 36100) + chunk)  # noqa: S311 - reproducible synthetic fuzz, no credentials
    cases = [scrub_fuzz.case(rng, max_depth=2 if shallow else 7) for _ in range(600)]
    cases.extend((text, [value]) for text, value in scrub_fuzz.REPORTED)
    for text, secrets in cases:
        values = tuple(sorted(set(secrets)))
        # Log free text uses the strict no-secret policy (core.scrub_log_text), which is what
        # the installed handler applies; the structured-data core.scrub is not the log path.
        expected = core.scrub_log_text(text, values)
        assert core.scrub_log_text(expected, values) == expected
        record = logging.LogRecord("memo-property", logging.ERROR, __file__, 1, text, (), None)
        monkeypatch.setattr(core, "_log_secrets", lambda values=values: values)
        handler = logging.StreamHandler()
        # Covers formatter -> handler formatter -> final emit repeated text.
        assert handler.format(record) == expected
        assert memo.scrub_record_text(record, text, values, core.scrub_log_text) == expected
        assert memo.scrub_record_text(record, expected, values, core.scrub_log_text) == expected


def test_memo_calls_once_registers_fixpoint_and_keys_values():
    record = logging.LogRecord("memo", 20, __file__, 1, "", (), None)
    calls = []

    def scrubber(text, values):
        calls.append((values, text))
        return core.scrub(text, values)

    assert memo.scrub_record_text(record, "secret", ("secret",), scrubber) == "***"
    assert memo.scrub_record_text(record, "secret", ("secret",), scrubber) == "***"
    assert memo.scrub_record_text(record, "***", ("secret",), scrubber) == "***"
    assert len(calls) == 1
    assert memo.scrub_record_text(record, "secret", ("other",), scrubber) == "secret"
    assert len(calls) == 2


def test_memo_never_populates_from_withheld_or_exception():
    record = logging.LogRecord("memo", 20, __file__, 1, "", (), None)
    calls = []

    def withheld(text, values):
        calls.append(text)
        return "<log record withheld: failure>"

    for _ in range(2):
        memo.scrub_record_text(record, "input", (), withheld)
        memo.scrub_record_text(record, "uncached", (), withheld, cacheable=False)
    assert len(calls) == 4

    def broken(text, values):
        calls.append(text)
        raise ValueError("synthetic")

    for _ in range(2):
        with pytest.raises(ValueError, match="synthetic"):
            memo.scrub_record_text(record, "broken", (), broken)
    assert calls.count("broken") == 2


def test_memo_lru_byte_cap_and_record_lifetime(monkeypatch):
    monkeypatch.setattr(memo, "_MAX_BYTES", 2048)
    record = logging.LogRecord("memo", 20, __file__, 1, "", (), None)
    for number in range(10):
        memo.scrub_record_text(record, str(number) * 64, (), core.scrub)
        assert memo._bytes <= memo._MAX_BYTES
    assert memo._entries
    del record
    assert not memo._entries
    assert memo._bytes == 0


@pytest.mark.parametrize("unhashable", [False, True])
def test_record_subclasses_never_hash_or_compare(unhashable):
    class HostileRecord(logging.LogRecord):
        def __hash__(self):
            raise AssertionError("record hash executed")

        def __eq__(self, other):
            raise AssertionError("record equality executed")

    class UnhashableRecord(HostileRecord):
        __hash__ = None

    cls = UnhashableRecord if unhashable else HostileRecord
    record = cls("memo", 20, __file__, 1, "", (), None)
    for _ in range(2):
        assert memo.scrub_record_text(record, "secret", ("secret",), core.scrub) == "***"
        assert memo.scrub_record_text(record, "***", ("secret",), core.scrub) == "***"
    del record  # Cleanup also never hashes or compares caller-controlled objects.
