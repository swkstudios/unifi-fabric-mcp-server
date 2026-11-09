"""Every documented example call passes the tool's own argument validation.

Each ``Example call (<tool>):`` block in a tool description is run through the fake
upstream (its ``host`` / ``site`` swapped for the harness console and site, every other
argument as documented). The call must not fail with a pre-upstream argument refusal
(``unifi_fabric.refusals`` categories selector-syntax / spec / probed-enum /
json-validity, or the empty-body guard): an example the server itself refuses teaches the
caller a call that cannot work. A miss decided on upstream data (the example's ids are not
in the harness) is fine.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

import pytest

from tests import test_cross_tool_invariants as cti
from tests import test_spec_conformance as sc
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_classes import tool_batches
from unifi_fabric import refusals, server

TOOLS = cti.TOOLS


@functools.cache
def _lz_EXAMPLES():
    examples = {n: sc.documented_example(t) for n, t in TOOLS.items()}
    return {n: e for n, e in examples.items() if e is not None}


_ARGUMENT_REFUSALS = refusals.ARGUMENT_CATEGORIES | {refusals.RULED_KEEP}


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def test_examples_are_found():
    assert len(_lz_EXAMPLES()) >= 100, len(_lz_EXAMPLES())
    assert "get_client_link_diagnostics" in _lz_EXAMPLES()


def _args(name: str, example: dict[str, Any]) -> dict[str, Any]:
    args = dict(example)
    if "host" in args:
        args["host"] = uh.HOST
    if "site" in args:
        args["site"] = uh.SITE
    return args


@tool_batches("name", lambda: sorted(_lz_EXAMPLES()))
async def test_documented_example_passes_argument_validation(name):
    up = uh.FakeUpstream(replay_recordings=False)
    with pytest.MonkeyPatch.context() as mp:
        for k, v in tool_args.TOOL_ENV.get(name, {}).items():
            mp.setenv(k, v)
        uh.install(mp, up)
        if name in {"collect_protect_events", "collect_protect_device_changes"}:
            # Execute every requested poll; remove synthetic network pacing only.
            async def complete_pacing(_delay: float) -> None:
                pass

            mp.setattr(server.protect, "_sleep", complete_pacing)
        try:
            await server.mcp.call_tool(name, _args(name, _lz_EXAMPLES()[name]))
        except Exception as exc:  # noqa: BLE001 - classified below
            if isinstance(exc, TimeoutError):
                raise
            refusal = refusals.classify(str(exc))
            assert refusal is None or refusal.category not in _ARGUMENT_REFUSALS, (
                f"{name}: the documented example is refused ({refusal.id}): {exc}"
            )
            assert refusal is not None or any(not s.resolution for s in up.served), (
                f"{name}: unregistered refusal: {exc}"
            )
