"""Log records stay safe and ordinary: a malformed logging call never raises at the call
site (stdlib reports it through ``Handler.handleError`` at emit time, and so do we, with
no secret in that report either), and a scrubbed record pickles and copies."""

from __future__ import annotations

import copy
import io
import logging
import pickle

import pytest

import unifi_fabric.secret_scrub as module

SECRET = "rec-0rd-S3cret!x"


@pytest.fixture
def scrubbing(monkeypatch):
    """A logger and its own handler. Records are handled by that handler directly:
    pytest attaches its capture handler (which raises on a formatting error, to fail a
    test that logs badly) to the root logger and to non-propagating loggers."""
    monkeypatch.setattr(module, "_log_secrets", lambda: (SECRET,))
    module.install_log_scrubber()
    monkeypatch.setattr(logging, "raiseExceptions", True)
    stream = io.StringIO()
    return logging.getLogger("l10a2.record"), logging.StreamHandler(stream), stream


def _log(logger: logging.Logger, handler: logging.Handler, msg: str, *args: object) -> None:
    """What ``logger.info(msg, *args)`` does for one handler: the record factory runs at
    the call site, the handler formats and emits."""
    record = logger.makeRecord(logger.name, logging.INFO, __file__, 1, msg, args, None)
    handler.handle(record)


class _Exploding:
    """An argument whose ``str`` fails with an error that names the secret."""

    def __str__(self) -> str:
        raise ValueError(f"cannot render {SECRET}")

    __repr__ = __str__


@pytest.mark.parametrize(
    ("msg", "args"),
    [
        ("%d", ("abc",)),
        ("%s %s", ("one",)),
        ("%d", (SECRET,)),
        ("%s %s", (SECRET,)),
        ("%(key)s", (SECRET,)),
        ("value %s", (_Exploding(),)),
    ],
)
def test_malformed_call_is_reported_like_stdlib_and_never_raises(scrubbing, capsys, msg, args):
    logger, handler, stream = scrubbing
    _log(logger, handler, msg, *args)  # must not raise at the call site
    report = capsys.readouterr().err
    assert "--- Logging error ---" in report  # stdlib's handleError report
    assert ("Message: " in report and "Arguments: " in report) or (
        "Unable to print the message and arguments" in report  # an argument that cannot
    )  # render even there: stdlib says so
    assert SECRET not in report
    assert SECRET not in stream.getvalue()


def test_record_factory_never_raises_on_a_malformed_record(scrubbing):
    factory = logging.getLogRecordFactory()
    record = factory("l10a2.record", logging.INFO, __file__, 1, "%d", ("abc",), None)
    with pytest.raises(TypeError):
        record.getMessage()  # still fails where stdlib fails: at format time
    record = factory("l10a2.record", logging.INFO, __file__, 1, "%d", (SECRET,), None)
    assert record.args == ("***",)
    built = logging.makeLogRecord({"msg": "%s %s", "args": (SECRET,)})
    module.SecretScrubFilter().filter(built)
    assert built.args == ("***",)


def test_well_formed_calls_are_unchanged(scrubbing, capsys):
    logger, handler, stream = scrubbing
    _log(logger, handler, "%d items, key %s", 3, SECRET)
    _log(logger, handler, "plain %s", "text")
    assert stream.getvalue() == "3 items, key ***\nplain text\n"
    assert capsys.readouterr().err == ""


def _split_record():
    half = len(SECRET) // 2
    factory = logging.getLogRecordFactory()
    return factory(
        "l10a2.record", logging.INFO, __file__, 1, "%s%s", (SECRET[:half], SECRET[half:]), None
    )


def _object_record():
    class Holder:
        def __str__(self) -> str:
            return f"holder({SECRET})"

        def __repr__(self) -> str:
            return f"Holder({SECRET!r})"

    factory = logging.getLogRecordFactory()
    return factory("l10a2.record", logging.INFO, __file__, 1, "%s / %r", (Holder(),) * 2, None)


@pytest.mark.parametrize("make", [_split_record, _object_record])
def test_scrubbed_records_pickle_and_copy(scrubbing, make):
    record = make()
    message = record.getMessage()
    assert SECRET not in message
    for clone in (
        pickle.loads(pickle.dumps(record)),  # noqa: S301 - our own record, round trip
        copy.deepcopy(record),
        copy.copy(record),
    ):
        assert clone.getMessage() == message
        assert SECRET not in repr(clone.args)
        assert type(clone.msg) is type(record.msg)


def test_split_secret_record_uses_the_completed_message(scrubbing):
    record = _split_record()
    assert type(record.msg).__name__ == "_CompletedLogMessage"
    assert record.getMessage() == "***"
