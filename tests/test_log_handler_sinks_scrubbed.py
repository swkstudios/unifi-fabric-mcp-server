"""Every logging sink receives only scrubbed output, whatever its formatter.

The record factory keeps arguments typed (an ``int`` stays an ``int`` for formatters
such as uvicorn's access formatter), so a formatter that renders ``record.args`` itself
rebuilds a numeric secret. Completed formatter output must be scrubbed for EVERY
handler type, not only ``StreamHandler``: the property feeds a numeric and a string
secret through a custom formatter into each stdlib handler that formats records
(SysLog, SMTP, NTEventLog, Queue, file, rotating file, memory-buffered, socket,
datagram, HTTP), with fake transports capturing what would leave the process, and
asserts the captured bytes never hold the secret while the record's argument types are
unchanged.
"""

from __future__ import annotations

import io
import logging
import logging.handlers
import pickle
import smtplib
import urllib.parse
from pathlib import Path
from typing import Any

import pytest

import unifi_fabric.secret_scrub as module

SECRETS = ("731902", "sinkSecret73")


class _ArgsFormatter(logging.Formatter):
    """A custom formatter that renders the typed arguments itself (no base format)."""

    def format(self, record: logging.LogRecord) -> str:
        return f"custom args={record.args!r} first={record.args[0]}"  # type: ignore[index]


class _Captured:
    def __init__(self) -> None:
        self.chunks: list[bytes] = []

    def add(self, data: Any) -> None:
        if isinstance(data, str):
            data = data.encode("utf-8", "surrogatepass")
        self.chunks.append(bytes(data))

    def text(self) -> str:
        return b"\n".join(self.chunks).decode("utf-8", "replace")


class _FakeSocket:
    """Captures what a handler sends; ``pickled`` frames (Socket/Datagram handlers: a
    4-byte length, then a pickled record dict) are rendered so typed values are seen."""

    def __init__(self, captured: _Captured, *, pickled: bool = False) -> None:
        self.captured = captured
        self.pickled = pickled

    def _add(self, data: bytes) -> None:
        self.captured.add(data)
        if self.pickled:
            self.captured.add(repr(pickle.loads(data[4:])))  # noqa: S301 - our own bytes

    def sendto(self, data: bytes, address: Any) -> int:
        self._add(data)
        return len(data)

    def sendall(self, data: bytes) -> None:
        self._add(data)

    def send(self, data: bytes) -> int:
        self._add(data)
        return len(data)

    def close(self) -> None:
        pass


def _syslog(captured: _Captured, tmp_path: Path, monkeypatch: Any) -> logging.Handler:
    import socket

    handler = logging.handlers.SysLogHandler(address=("127.0.0.1", 9), socktype=socket.SOCK_DGRAM)
    handler.socket.close()
    handler.socket = _FakeSocket(captured)  # type: ignore[assignment]
    return handler


def _smtp(captured: _Captured, tmp_path: Path, monkeypatch: Any) -> logging.Handler:
    class _SMTP:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def send_message(self, msg: Any) -> None:
            captured.add(msg.as_string())

        def quit(self) -> None:
            pass

    monkeypatch.setattr(smtplib, "SMTP", _SMTP)
    return logging.handlers.SMTPHandler("localhost", "a@example.com", ["b@example.com"], "s")


def _nt_event_log(captured: _Captured, tmp_path: Path, monkeypatch: Any) -> logging.Handler:
    class _Welu:
        @staticmethod
        def ReportEvent(appname: str, event_id: int, cat: int, etype: int, msgs: list[str]):  # noqa: N802
            for msg in msgs:
                captured.add(msg)

    monkeypatch.setattr("builtins.print", lambda *a, **k: None)  # the no-win32 notice
    handler = logging.handlers.NTEventLogHandler("unifi-test")
    handler._welu = _Welu()  # type: ignore[attr-defined]
    handler.appname = "unifi-test"  # set only when the win32 extensions import
    handler.deftype = 0
    handler.typemap = {}
    return handler


def _queue(captured: _Captured, tmp_path: Path, monkeypatch: Any) -> logging.Handler:
    class _Queue:
        def put_nowait(self, item: Any) -> None:
            # What a multiprocessing queue would carry to the listener process.
            captured.add(repr(pickle.loads(pickle.dumps(item)).__dict__))  # noqa: S301
            captured.add(item.getMessage())

    return logging.handlers.QueueHandler(_Queue())


def _file(captured: _Captured, tmp_path: Path, monkeypatch: Any) -> logging.Handler:
    path = tmp_path / "plain.log"
    handler = logging.FileHandler(path, encoding="utf-8")
    handler._capture_path = path  # type: ignore[attr-defined]
    return handler


def _rotating(captured: _Captured, tmp_path: Path, monkeypatch: Any) -> logging.Handler:
    path = tmp_path / "rotating.log"
    handler = logging.handlers.RotatingFileHandler(path, maxBytes=1, backupCount=2)
    handler._capture_path = path  # type: ignore[attr-defined]
    return handler


def _memory(captured: _Captured, tmp_path: Path, monkeypatch: Any) -> logging.Handler:
    target = logging.StreamHandler(io.StringIO())
    target.setFormatter(_ArgsFormatter())
    handler = logging.handlers.MemoryHandler(1, target=target)
    handler._capture_stream = target.stream  # type: ignore[attr-defined]
    return handler


def _socket(captured: _Captured, tmp_path: Path, monkeypatch: Any) -> logging.Handler:
    handler = logging.handlers.SocketHandler("127.0.0.1", 9)
    handler.sock = _FakeSocket(captured, pickled=True)  # type: ignore[assignment]
    return handler


def _datagram(captured: _Captured, tmp_path: Path, monkeypatch: Any) -> logging.Handler:
    handler = logging.handlers.DatagramHandler("127.0.0.1", 9)
    handler.sock = _FakeSocket(captured, pickled=True)  # type: ignore[assignment]
    return handler


def _http(captured: _Captured, tmp_path: Path, monkeypatch: Any) -> logging.Handler:
    class _Conn:
        def putrequest(self, method: str, url: str) -> None:
            captured.add(urllib.parse.unquote_plus(url))

        def putheader(self, *args: Any) -> None:
            pass

        def endheaders(self) -> None:
            pass

        def send(self, data: bytes) -> None:
            captured.add(urllib.parse.unquote_plus(data.decode()))

        def getresponse(self) -> None:
            return None

    handler = logging.handlers.HTTPHandler("localhost:9", "/log", method="POST")
    handler.getConnection = lambda host, secure: _Conn()  # type: ignore[method-assign]
    return handler


SINKS = {
    "syslog": _syslog,
    "smtp": _smtp,
    "nt_event_log": _nt_event_log,
    "queue": _queue,
    "file": _file,
    "rotating_file": _rotating,
    "memory": _memory,
    "socket": _socket,
    "datagram": _datagram,
    "http": _http,
}


@pytest.mark.parametrize("secret", SECRETS)
@pytest.mark.parametrize("sink", sorted(SINKS))
def test_every_sink_receives_only_scrubbed_output(monkeypatch, tmp_path, sink, secret):
    monkeypatch.setattr(module, "_log_secrets", lambda: (secret,))
    module.install_log_scrubber()
    monkeypatch.setattr(logging, "raiseExceptions", True)
    diagnostic = io.StringIO()
    monkeypatch.setattr(module.sys, "stderr", diagnostic)
    captured = _Captured()
    handler = SINKS[sink](captured, tmp_path, monkeypatch)
    handler.setFormatter(_ArgsFormatter())
    argument: Any = int(secret) if secret.isdecimal() else secret
    record = logging.getLogRecordFactory()(
        "sink-test", logging.WARNING, __file__, 1, "value %s", (argument,), None
    )
    try:
        handler.handle(record)
        handler.flush()
    finally:
        handler.close()
    if hasattr(handler, "_capture_path"):
        for path in sorted(tmp_path.glob(Path(handler._capture_path).name + "*")):
            captured.add(path.read_bytes())
    if hasattr(handler, "_capture_stream"):
        captured.add(handler._capture_stream.getvalue())
    sent = captured.text()
    assert sent, f"{sink}: nothing reached the sink (the fake transport is not exercised)"
    assert "custom args=" in sent or sink in {"socket", "datagram", "http"}
    assert secret not in sent, f"{sink} received the secret: {sent!r}"
    assert secret not in diagnostic.getvalue()
    # The record's argument keeps its type (formatters that unpack typed args work).
    assert type(record.args[0]) is type(argument)  # type: ignore[index]


def test_handler_format_is_scrubbed_for_any_formatter_object(monkeypatch):
    """A formatter that is not a logging.Formatter at all is covered too."""
    monkeypatch.setattr(module, "_log_secrets", lambda: ("731902",))
    module.install_log_scrubber()

    class _Duck:
        def format(self, record: logging.LogRecord) -> str:
            return f"duck {record.args[0]}"  # type: ignore[index]

    handler = logging.Handler()
    handler.setFormatter(_Duck())  # type: ignore[arg-type]
    record = logging.getLogRecordFactory()("duck", 30, __file__, 1, "%d", (731902,), None)
    assert handler.format(record) == "duck ***"
