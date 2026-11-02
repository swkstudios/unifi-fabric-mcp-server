"""Wire handoffs strip secrets from metadata and hidden Python object state."""

from __future__ import annotations

import logging
import logging.handlers
import pickle
from typing import Any

import pytest

import unifi_fabric.secret_scrub as module

SECRET = "731902"
# Built from parts at runtime (the tests/ sentinel convention, cf. test_fixtures_sanitization._CRED)
# so gitleaks generic-api-key does not flag a synthetic literal; leak assertions are unchanged.
HIDDEN_SECRET = "".join(("wire", "hidden", "marker", SECRET))


class _StatefulKey(str):
    def __new__(cls, value: str):
        key = super().__new__(cls, value)
        key.hidden = HIDDEN_SECRET
        return key


class _SlottedRecord(logging.LogRecord):
    __slots__ = ("hidden",)


@pytest.fixture(autouse=True)
def _wire_scrubber(monkeypatch):
    monkeypatch.setattr(module, "_log_secrets", lambda: (SECRET, HIDDEN_SECRET))
    module.install_log_scrubber()


def _record() -> logging.LogRecord:
    return logging.LogRecord("wire-test", logging.WARNING, __file__, 1, "safe", (), None)


def _handoff(record: logging.LogRecord, sink: str) -> tuple[dict[str, Any], bytes]:
    if sink in {"socket", "datagram"}:
        cls = (
            logging.handlers.SocketHandler if sink == "socket" else logging.handlers.DatagramHandler
        )
        handler = cls("localhost", 9)
        try:
            payload = handler.makePickle(record)[4:]
            return pickle.loads(payload), payload  # noqa: S301 - synthetic local payload
        finally:
            handler.close()
    if sink == "http":
        handler = logging.handlers.HTTPHandler("localhost", "/log")
        try:
            fields = handler.mapLogRecord(record)
            return fields, pickle.dumps(fields)
        finally:
            handler.close()
    handler = logging.handlers.QueueHandler(None)
    try:
        prepared = handler.prepare(record)
        payload = pickle.dumps(prepared)
        received = pickle.loads(payload)  # noqa: S301 - synthetic local payload
        return received.__dict__, payload
    finally:
        handler.close()


class TestNumericMetadataSecrets:
    @pytest.mark.parametrize("sink", ["socket", "datagram", "http", "queue"])
    @pytest.mark.parametrize("field", sorted(module._NUMERIC_RECORD_FIELDS))
    @pytest.mark.parametrize("number_type", [int, float])
    def test_numeric_secret_is_safe_and_keeps_receiver_type(self, sink, field, number_type):
        record = _record()
        record.__dict__[field] = number_type(SECRET)
        fields, payload = _handoff(record, sink)
        assert type(fields[field]) is number_type
        assert fields[field] == number_type(0)
        assert SECRET not in repr(fields)
        assert HIDDEN_SECRET.encode() not in payload

    @pytest.mark.parametrize("number_type", [int, float])
    def test_nonsecret_metadata_is_unchanged(self, number_type):
        fields = module._wire_fields({"lineno": number_type(42)})
        assert fields == {"lineno": number_type(42)}
        assert type(fields["lineno"]) is number_type


class TestStatefulMappingKeys:
    @pytest.mark.parametrize("sink", ["socket", "datagram", "http", "queue"])
    @pytest.mark.parametrize("field", sorted(module._MACHINE_RECORD_FIELDS))
    def test_schema_keys_are_plain_strings_before_serialization(self, sink, field):
        record = _record()
        value = record.__dict__.pop(field, None)
        record.__dict__[_StatefulKey(field)] = value
        fields, payload = _handoff(record, sink)
        assert all(type(key) is str for key in fields)
        assert HIDDEN_SECRET.encode() not in payload

    def test_nested_keys_and_values_lose_hidden_state(self):
        record = _record()
        record.extra = {_StatefulKey("safe"): _StatefulKey("value")}
        fields, payload = _handoff(record, "socket")
        assert type(next(iter(fields["extra"]))) is str
        assert type(fields["extra"]["safe"]) is str
        assert HIDDEN_SECRET.encode() not in payload


class TestSlottedQueueRecords:
    def test_queue_rebuilds_a_plain_record_without_hidden_slots(self):
        record = _SlottedRecord("wire-test", logging.WARNING, __file__, 1, "safe", (), None)
        record.hidden = HIDDEN_SECRET
        handler = logging.handlers.QueueHandler(None)
        try:
            prepared = handler.prepare(record)
            payload = pickle.dumps(prepared)
            received = pickle.loads(payload)  # noqa: S301 - synthetic local payload
            assert type(prepared) is logging.LogRecord
            assert type(received) is logging.LogRecord
            assert received.getMessage() == "safe"
            assert not hasattr(received, "hidden")
            assert HIDDEN_SECRET.encode() not in payload
            assert record.hidden == HIDDEN_SECRET
        finally:
            handler.close()
