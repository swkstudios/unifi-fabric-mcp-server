"""Wire handlers scrub metadata, mapping keys, and hidden serialized object state."""

import logging
import logging.handlers
import pickle
import queue
import struct
import urllib.parse

import pytest

import unifi_fabric.secret_scrub as module

SECRET = "wireSentinelL15"
STRING_METADATA = (
    "name",
    "levelname",
    "pathname",
    "filename",
    "module",
    "funcName",
    "threadName",
    "processName",
    "taskName",
)


class OpaqueCredential:
    def __init__(self):
        self.credential = SECRET


def wire_record(monkeypatch):
    monkeypatch.setattr(module, "_log_secrets", lambda: (SECRET,))
    module.install_log_scrubber()
    return logging.LogRecord("ordinary", logging.INFO, __file__, 12, "ordinary", (), None)


def wire_payload(kind, record):
    if kind in ("socket", "datagram"):
        handler_type = (
            logging.handlers.SocketHandler if kind == "socket" else logging.handlers.DatagramHandler
        )
        handler = handler_type("localhost", 1)
        payload = handler.makePickle(record)
        assert struct.unpack(">L", payload[:4])[0] == len(payload) - 4
        return payload, pickle.loads(payload[4:])  # noqa: S301 - synthetic bytes
    if kind == "http":
        fields = logging.handlers.HTTPHandler("localhost", "/").mapLogRecord(record)
        return urllib.parse.urlencode(fields).encode(), fields
    prepared = logging.handlers.QueueHandler(queue.Queue()).prepare(record)
    payload = pickle.dumps(prepared)
    return payload, pickle.loads(payload).__dict__  # noqa: S301 - synthetic bytes


@pytest.mark.parametrize("kind", ("socket", "datagram", "http", "queue"))
@pytest.mark.parametrize("field", STRING_METADATA)
def test_all_string_metadata_scrubbed_on_wire(monkeypatch, kind, field):
    record = wire_record(monkeypatch)
    setattr(record, field, SECRET)
    payload, fields = wire_payload(kind, record)
    assert SECRET.encode() not in payload
    assert fields[field] == "***"
    assert isinstance(fields["created"], float)
    assert isinstance(fields["levelno"], int)
    assert isinstance(fields["lineno"], int)


@pytest.mark.parametrize("kind", ("socket", "datagram", "http", "queue"))
def test_extra_and_nested_mapping_keys_scrubbed_on_wire(monkeypatch, kind):
    record = wire_record(monkeypatch)
    record.__dict__[SECRET] = "ordinary"
    record.nested = {SECRET: [{SECRET: "ordinary"}]}
    payload, fields = wire_payload(kind, record)
    assert SECRET.encode() not in payload
    assert fields["***"] == "ordinary"
    assert fields["nested"] == {"***": [{"***": "ordinary"}]}


@pytest.mark.parametrize("kind", ("socket", "datagram", "queue"))
@pytest.mark.parametrize("nested", (False, True))
def test_opaque_object_state_never_reaches_actual_pickle(monkeypatch, kind, nested):
    record = wire_record(monkeypatch)
    value = OpaqueCredential()
    assert SECRET not in repr(value)
    record.opaque = {"objects": [value]} if nested else value
    payload, fields = wire_payload(kind, record)
    assert SECRET.encode() not in payload
    cleaned = fields["opaque"]["objects"][0] if nested else fields["opaque"]
    assert isinstance(cleaned, str)


@pytest.mark.parametrize("kind", ("socket", "datagram", "http", "queue"))
def test_clean_wire_preserves_required_scalar_and_container_types(monkeypatch, kind):
    record = wire_record(monkeypatch)
    record.extra_values = {
        "integer": 42,
        "float": 0.25,
        "bool": True,
        "none": None,
        "tuple": ("clean", 1),
        "list": ["clean", 2],
    }
    _, fields = wire_payload(kind, record)
    assert fields["extra_values"] == record.extra_values
    assert type(fields["extra_values"]["tuple"]) is tuple
    assert type(fields["extra_values"]["list"]) is list


@pytest.mark.parametrize("kind", ("socket", "datagram", "http", "queue"))
def test_numeric_message_is_scrubbed_without_numeric_metadata_bypass(monkeypatch, kind):
    record = wire_record(monkeypatch)
    monkeypatch.setattr(module, "_log_secrets", lambda: ("731902",))
    record.msg = 731902
    _, fields = wire_payload(kind, record)
    assert fields["msg"] == "***"
    assert type(fields["levelno"]) is int
