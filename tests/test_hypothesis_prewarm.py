"""The xdist controller prepares only Hypothesis codec data before workers start."""

from types import SimpleNamespace

from tests import conftest


def test_controller_warms_codec_cache(monkeypatch):
    calls = []
    monkeypatch.setattr(
        conftest.subprocess, "run", lambda *args, **kwargs: calls.append((args, kwargs))
    )
    config = SimpleNamespace(getoption=lambda *_args, **_kwargs: 2)
    conftest.pytest_sessionstart(SimpleNamespace(config=config))
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[0][-2:] == ["utf-8", "codec-v2-utf-8"]
    assert kwargs == {"check": True}


def test_worker_and_serial_run_do_not_prewarm(monkeypatch):
    def unexpected(*_args, **_kwargs):
        raise AssertionError("only the xdist controller should prewarm")

    monkeypatch.setattr(conftest.subprocess, "run", unexpected)
    serial = SimpleNamespace(getoption=lambda *_args, **_kwargs: 0)
    worker = SimpleNamespace(workerinput={}, getoption=lambda *_args, **_kwargs: 2)
    conftest.pytest_sessionstart(SimpleNamespace(config=serial))
    conftest.pytest_sessionstart(SimpleNamespace(config=worker))
