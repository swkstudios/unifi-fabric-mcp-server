"""Logging error-path diagnostics never print an unscrubbed argument.

stdlib ``Handler.handleError`` prints ``Message:`` and ``Arguments:`` reprs; every path that
reaches it (malformed format, failing formatter, failing stream, failing custom emit and the
``lastResort`` handler) must scrub the complete diagnostic, for numeric and string secrets.
"""

import io
import logging

import pytest

import unifi_fabric.secret_scrub as module


@pytest.mark.parametrize("secret", ["731902", "diagnosticKey73"])
@pytest.mark.parametrize("failure", ["malformed", "formatter", "stream", "emit", "last_resort"])
def test_every_logging_failure_scrubs_complete_diagnostic(monkeypatch, secret, failure):
    monkeypatch.setattr(module, "_log_secrets", lambda: (secret,))
    module.install_log_scrubber()
    monkeypatch.setattr(logging, "raiseExceptions", True)
    diagnostic = io.StringIO()
    monkeypatch.setattr(module.sys, "stderr", diagnostic)
    output = io.StringIO()
    argument = int(secret) if secret.isdecimal() else secret

    class BrokenFormatter(logging.Formatter):
        def format(self, record):
            raise ValueError("formatter " + secret)

    class BrokenStream:
        def write(self, text):
            raise OSError("stream " + secret)

    class BrokenHandler(logging.Handler):
        def emit(self, record):
            raise RuntimeError("emit " + secret)

    handler = logging.StreamHandler(output)
    message, args = "%s", (argument,)
    if failure == "malformed":
        message = "%s %s"
    elif failure == "formatter":
        handler.setFormatter(BrokenFormatter())
    elif failure == "stream":
        handler.setStream(BrokenStream())
    elif failure == "emit":
        handler = BrokenHandler()
    else:
        monkeypatch.setattr(logging, "lastResort", handler)
        message = "%s %s"
    record = logging.getLogRecordFactory()("diagnostic-test", 30, __file__, 1, message, args, None)
    if failure == "last_resort":
        logger = logging.Logger("isolated-last-resort", level=20)
        logger.callHandlers(record)
    else:
        handler.handle(record)
    report = diagnostic.getvalue()
    assert "--- Logging error ---" in report
    assert "Arguments:" in report
    assert secret not in report
    assert secret not in output.getvalue()


def test_custom_formatter_completed_output_is_scrubbed(monkeypatch):
    secret = "731902"
    monkeypatch.setattr(module, "_log_secrets", lambda: (secret,))
    module.install_log_scrubber()

    class CustomFormatter(logging.Formatter):
        def format(self, record):
            return f"custom numeric: {record.args[0]}"

    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.setFormatter(CustomFormatter())
    record = logging.getLogRecordFactory()("custom-output", 30, __file__, 1, "%d", (731902,), None)
    handler.handle(record)
    assert output.getvalue() == "custom numeric: ***\n"


def test_broken_diagnostic_stream_and_secret_provider_never_raise(monkeypatch):
    module.install_log_scrubber()

    def broken_provider():
        raise ValueError("synthetic provider error")

    class BrokenStream:
        def write(self, value):
            raise OSError("synthetic write failure")

    monkeypatch.setattr(module, "_log_secrets", broken_provider)
    monkeypatch.setattr(module.sys, "stderr", BrokenStream())
    record = logging.getLogRecordFactory()("broken-provider", 30, __file__, 1, "%d", ("abc",), None)
    handler = logging.StreamHandler(BrokenStream())
    handler.handle(record)
    assert record.args is None
    assert "withheld" in record.msg
