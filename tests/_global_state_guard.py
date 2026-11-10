"""Fail a test that leaves process-wide logging state changed.

``logging.disable``, the root logger's level and the root logger's handlers are global to
the process. A test that changes one and does not restore it changes every later test on
the same xdist worker, and which tests share a worker depends on the worker count and the
shard, so the damage moves from run to run (a test that left ``logging.disable(CRITICAL)``
emptied every later log capture on its worker). This guard compares the three before and
after each test, its fixtures included. A test that leaves any of them changed errors at
teardown with its node id and what it left; the guard then restores the state, so the
leak cannot spread to the next test.

``logging.basicConfig`` is the one deliberate exception. It is process start-up
configuration: the server lifespan runs ``basicConfig(force=True)`` at the configured log
level, which is right for a server process. When a test runs it in-process, the guard
undoes it (root level and handlers back as they were) instead of failing the test.

``os.environ`` and ``sys.path`` are not compared. A module imported for the first time
inside a test can change them (repository scripts put ``src`` and ``scripts`` on
``sys.path`` when loaded), and whether that first import happens inside a test depends on
what else the run collected, so such a check would itself depend on the selection: the
docs job, which runs one test file, would fail where the full suite passes.

Loaded from ``tests/conftest.py`` (``pytest_plugins``), so it is the outermost autouse
fixture of every test: it is set up before, and torn down after, every fixture the test
uses.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from _pytest.logging import LogCaptureHandler


def _is_phase_handler(handler: logging.Handler) -> bool:
    """pytest's per-phase capture handlers (caplog and the report capture). pytest adds and
    removes them around each setup, call and teardown phase, so they are not test state."""
    return isinstance(handler, LogCaptureHandler)


@dataclass(frozen=True)
class LoggingState:
    disable: int
    root_level: int
    root_handlers: tuple[logging.Handler, ...]


def logging_state() -> LoggingState:
    root = logging.getLogger()
    return LoggingState(
        disable=logging.root.manager.disable,
        root_level=root.level,
        root_handlers=tuple(h for h in root.handlers if not _is_phase_handler(h)),
    )


def restore(state: LoggingState) -> None:
    """Put ``state`` back. ``logging.disable`` also clears the loggers' level caches."""
    logging.disable(state.disable)
    root = logging.getLogger()
    root.setLevel(state.root_level)
    phase = [h for h in root.handlers if _is_phase_handler(h)]
    root.handlers[:] = [*state.root_handlers, *phase]


def _name(handler: logging.Handler) -> str:
    return type(handler).__name__


def differences(before: LoggingState, after: LoggingState) -> list[str]:
    found = []
    if before.disable != after.disable:
        found.append(
            f"logging.disable is {logging.getLevelName(after.disable)} "
            f"(was {logging.getLevelName(before.disable)})"
        )
    if before.root_level != after.root_level:
        found.append(
            f"root logger level is {logging.getLevelName(after.root_level)} "
            f"(was {logging.getLevelName(before.root_level)})"
        )
    added = [_name(h) for h in after.root_handlers if h not in before.root_handlers]
    removed = [_name(h) for h in before.root_handlers if h not in after.root_handlers]
    if added or removed:
        found.append(f"root logger handlers added {added}, removed {removed}")
    return found


@pytest.fixture(autouse=True)
def _global_state_guard(request: pytest.FixtureRequest) -> Iterator[None]:
    before = logging_state()
    configured: list[bool] = []
    basic_config = logging.basicConfig

    def recording_basic_config(*args: object, **kwargs: object) -> None:
        configured.append(True)
        basic_config(*args, **kwargs)  # type: ignore[arg-type]

    logging.basicConfig = recording_basic_config  # type: ignore[assignment]
    try:
        yield
    finally:
        logging.basicConfig = basic_config  # type: ignore[assignment]
    after = logging_state()
    if configured:
        # Process start-up configuration (the server lifespan): undone, not a failure.
        restore(LoggingState(after.disable, before.root_level, before.root_handlers))
        after = logging_state()
    problems = differences(before, after)
    if problems:
        restore(before)
        pytest.fail(
            f"{request.node.nodeid} left process-wide logging state changed: "
            + "; ".join(problems)
            + ". Restore it in a finally block or a fixture.",
            pytrace=False,
        )
