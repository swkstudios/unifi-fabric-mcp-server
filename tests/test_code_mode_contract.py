"""Code Mode contract (UNIFI_TOOL_MODE=codemode): sandbox, limits, negatives, cancellation.

Code Mode is an opt-in, read-only experimental feature. These tests pin the Code Mode
contract: byte limits counted in UTF-8 bytes with strict encoding, the 32-call budget,
one script per process, slot release on every path, the read-only broker, the sandbox
negatives, and the single reviewed interpreter-CPU exception. Upstream is synthetic.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.tools import ToolResult
from mcp.types import TextContent
from pydantic import BaseModel

from unifi_fabric import code_mode
from unifi_fabric.code_mode import (
    BUSY,
    INVALID_SOURCE,
    INVALID_TEXT,
    LIMIT_EXCEEDED,
    MAX_AGGREGATE_BYTES,
    MAX_CALLS,
    MAX_OUTPUT_BYTES,
    MAX_RESULT_BYTES,
    MAX_SOURCE_BYTES,
    TRUNCATION_MARKER,
    CodeModeError,
    check_source,
    finish_output,
    run_script,
)
from unifi_fabric.tool_annotations import for_tool

ROOT = Path(__file__).resolve().parents[1]
DUMPS: dict[str, Any] = {"ensure_ascii": False, "allow_nan": False, "separators": (",", ":")}
TEST_AUDIT_HMAC_KEY = bytes(range(32))
TEST_AUDIT_HMAC_KEY_TEXT = base64.urlsafe_b64encode(TEST_AUDIT_HMAC_KEY).rstrip(b"=").decode()


def _size(value: Any) -> int:
    return len(json.dumps(value, **DUMPS).encode("utf-8"))


def _result(value: dict[str, Any]) -> ToolResult:
    return ToolResult(
        content=[TextContent(type="text", text=json.dumps(value, ensure_ascii=False))],
        structured_content=value,
    )


class FakeBroker:
    """A dispatch that records every call; ``responses`` maps a tool name to a factory."""

    def __init__(self, **responses: Any) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def __call__(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        self.calls.append((name, arguments))
        factory = self.responses.get(name)
        if factory is None:
            raise ToolError(
                json.dumps({"error": {"code": "write_denied", "message": f"{name} refused"}})
            )
        value = factory(arguments)
        if asyncio.iscoroutine(value):
            value = await value
        return value if isinstance(value, ToolResult) else _result(value)


def _error(exc: pytest.ExceptionInfo[CodeModeError]) -> dict[str, str]:
    return {"code": exc.value.code, "message": exc.value.message}


@pytest.fixture(autouse=True)
def _free_slot():
    assert not code_mode.SLOT.busy, "a previous test leaked the Code Mode slot"
    yield
    assert not code_mode.SLOT.busy, "the Code Mode slot was not released"


# --------------------------------------------------------------------------- experimental text


def test_experimental_notice_is_the_contract_text():
    assert code_mode.EXPERIMENTAL_NOTICE == (
        "Code Mode is an opt-in, read-only experimental feature. It may change without a "
        "deprecation cycle. There is no compatibility promise for execute()'s schema or "
        "output shape until graduation."
    )
    assert code_mode.EXPERIMENTAL_NOTICE in (code_mode.__doc__ or "").replace("\n", " ")


def test_limit_constants():
    assert MAX_SOURCE_BYTES == 32_768
    assert MAX_CALLS == 32
    assert MAX_RESULT_BYTES == 262_144
    assert MAX_AGGREGATE_BYTES == 2_097_152
    assert MAX_OUTPUT_BYTES == 65_536
    assert TRUNCATION_MARKER == "...[truncated]" and len(TRUNCATION_MARKER.encode()) == 14
    assert code_mode.MAX_MEMORY_BYTES == 64 * 1024 * 1024
    assert code_mode.MAX_RECURSION_DEPTH == 64
    assert code_mode.CPU_SECONDS_LIMIT == 30.0
    limits = code_mode.SANDBOX_LIMITS
    assert limits["max_memory"] == 64 * 1024 * 1024
    assert limits["max_recursion_depth"] == 64
    assert limits["max_suspensions"] == 1_000
    assert limits["max_feed_duration_secs"] == code_mode.CPU_SECONDS_LIMIT
    assert len(limits) == 4
    assert code_mode.SANDBOX_OS_POLICY["sleep"] == "zero"


# --------------------------------------------------------------------------- source bytes


@pytest.mark.parametrize(
    ("source", "accepted"),
    [
        ("a" * 32_768, True),
        ("a" * 32_769, False),
        ("a" * 32_766 + "é", True),  # 32,766 + 2 = 32,768
        ("a" * 32_767 + "é", False),  # 32,769
        ("a" * 32_765 + "😀", False),  # a 4-byte character straddling 32,768
        ("a" * 32_764 + "😀", True),  # exactly 32,768
    ],
)
def test_source_byte_limit(source, accepted):
    if accepted:
        assert check_source(source) is source
    else:
        with pytest.raises(CodeModeError) as exc:
            check_source(source)
        assert exc.value.code == INVALID_SOURCE


async def test_invalid_source_is_refused_before_slot_interpreter_and_upstream(monkeypatch):
    broker = FakeBroker(list_hosts=lambda _a: {"data": []})
    allocated = []
    acquired = []
    original = code_mode.SLOT.try_acquire
    monkeypatch.setattr(code_mode, "_run_sandbox", lambda *a: allocated.append(a))
    monkeypatch.setattr(code_mode.SLOT, "try_acquire", lambda: acquired.append(1) or original())
    for source in ("x = '\ud800'", "a" * 32_769, b"1 + 1", None):
        with pytest.raises(CodeModeError) as exc:
            await run_script(source, dispatch=broker)
        assert exc.value.code == INVALID_SOURCE
    assert acquired == []
    assert allocated == [] and broker.calls == []


# --------------------------------------------------------------------------- output bytes


def test_output_at_limit_is_unchanged_without_marker():
    text = "a" * 65_536
    assert finish_output(text) == text


def test_output_over_limit_is_cut_to_65522_plus_marker():
    out = finish_output("a" * 65_537)
    assert out == "a" * 65_522 + TRUNCATION_MARKER
    assert len(out.encode("utf-8")) == 65_536


@pytest.mark.parametrize(
    ("prefix", "char", "kept"),
    [(65_521, "é", 65_521), (65_520, "€", 65_520), (65_519, "😀", 65_519)],
)
def test_truncation_never_splits_a_code_point(prefix, char, kept):
    out = finish_output("a" * prefix + char + "tail" * 10)
    data = out.encode("utf-8")
    assert out == "a" * kept + TRUNCATION_MARKER
    assert len(data) == kept + 14
    assert data.decode("utf-8", errors="strict") == out
    assert out.endswith(TRUNCATION_MARKER)


def test_untruncated_output_ending_in_marker_is_unchanged():
    text = "a" * 100 + TRUNCATION_MARKER
    assert finish_output(text) == text
    exact = "a" * (65_536 - 14) + TRUNCATION_MARKER
    assert finish_output(exact) == exact


def test_host_output_check_refuses_lone_surrogate_naming_execute():
    # Host-side check. Monty itself maps a lone surrogate to U+FFFD inside the interpreter
    # (documented deviation), so a script cannot hand one to the host; see the next test.
    with pytest.raises(CodeModeError) as exc:
        finish_output("fine \ud800 text")
    assert exc.value.code == INVALID_TEXT
    assert exc.value.message.startswith("execute:")


async def test_sandbox_maps_lone_surrogate_to_replacement_character():
    out = await run_script('"a\\ud800b"', dispatch=FakeBroker())
    assert out == "a\ufffdb"
    out.encode("utf-8")  # strict UTF-8 by construction


async def test_huge_adversarial_output_is_cut_before_scrubbing(monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEY", "synthetic-code-mode-secret-0123456789")
    out = await run_script("'%2541&#38;#65;' * 1_000_000", dispatch=FakeBroker())
    assert len(out.encode()) == 65_536 and out.endswith(TRUNCATION_MARKER)


def test_bounded_output_forces_marker_when_input_was_cut():
    assert code_mode.bounded_output("a" * 10, forced=True) == "a" * 10 + TRUNCATION_MARKER
    big = code_mode.bounded_output("é" * 400_000)
    assert len(big.encode()) <= 65_536 and big.endswith(TRUNCATION_MARKER)


async def test_shared_reference_expansion_is_bounded_on_the_host(monkeypatch):
    broker = FakeBroker(list_hosts=lambda _a: {"data": []})
    records: list[dict[str, Any]] = []
    script = "a = ['x' * 1000] * 80\nb = [a] * 80\nc = [b] * 80\n"
    out = await run_script(script + "c", dispatch=broker)
    assert len(out.encode()) == 65_536 and out.endswith(TRUNCATION_MARKER)
    canonical_calls = 0

    def canonical_must_not_run(_value: object, _size: int) -> bytes:
        nonlocal canonical_calls
        canonical_calls += 1
        raise AssertionError("oversized arguments must not be materialized")

    monkeypatch.setattr(code_mode, "_canonical_argument_bytes", canonical_must_not_run)
    out = await run_script(
        script + "(await call_tool('list_hosts', {'x': c}))['error']['code']",
        dispatch=broker,
        audit=records.append,
        audit_hmac_key=TEST_AUDIT_HMAC_KEY,
    )
    assert out == "invalid_arguments" and broker.calls == []
    assert canonical_calls == 0
    assert records[0]["argument_hmacs"] == [code_mode.INVALID_ARGUMENT_HMAC]


def test_argument_json_preflight_is_exact_and_bounded(monkeypatch):
    limit = MAX_RESULT_BYTES
    exact = "a" * (limit - 2)
    assert code_mode._strict_argument_json_size(exact, limit) == limit
    assert code_mode._strict_argument_json_size(exact + "a", limit) is None

    escaped = '"\\\b\t\n\f\r\x00é'
    expected = json.dumps({"escaped": escaped}, sort_keys=True, **DUMPS).encode()
    assert code_mode._strict_argument_json_size({"escaped": escaped}, limit) == len(expected)

    calls = 0
    original = code_mode._json_string_size

    def counted(text: str, budget: int) -> int | None:
        nonlocal calls
        calls += 1
        return original(text, budget)

    monkeypatch.setattr(code_mode, "_json_string_size", counted)
    leaf = ["x" * 1000] * 80
    branch = [leaf] * 80
    fanout = [branch] * 80
    assert code_mode._strict_argument_json_size({"x": fanout}, limit) is None
    assert calls < 300, "shared logical references must be bounded by the byte budget"

    cycle: list[Any] = []
    cycle.append(cycle)
    assert code_mode._strict_argument_json_size(cycle, limit) is None
    deep: list[Any] = []
    for _ in range(10_000):
        deep = [deep]
    assert code_mode._strict_argument_json_size(deep, limit) == 20_002


def test_oversized_scalars_never_reach_canonical_materialization(monkeypatch):
    calls = 0

    def forbidden(_value: object, _size: int) -> bytes:
        nonlocal calls
        calls += 1
        raise AssertionError("oversized scalar reached canonical materialization")

    monkeypatch.setattr(code_mode, "_canonical_argument_bytes", forbidden)
    assert code_mode._argument_hmac(TEST_AUDIT_HMAC_KEY, {"x": "a" * 1_000_000}) == "invalid"
    assert code_mode._argument_hmac(TEST_AUDIT_HMAC_KEY, {"x": "\0" * 50_000}) == "invalid"
    assert calls == 0


def test_render_output_reports_a_cut():
    text, cut = code_mode.render_output("", list(range(200_000)))
    assert cut and len(text.encode()) <= code_mode.PRE_SCRUB_BYTES + 16


async def test_script_output_end_to_end():
    broker = FakeBroker()
    assert await run_script('print("hi")\n"there"', dispatch=broker) == "hi\nthere"
    assert await run_script("{'a': [1, 'é']}", dispatch=broker) == '{"a":[1,"é"]}'
    assert await run_script("None", dispatch=broker) == ""
    long = await run_script("'b' * 70000", dispatch=broker)
    assert long == "b" * 65_522 + TRUNCATION_MARKER


async def test_print_flood_does_not_grow_host_memory_and_truncates():
    out = await run_script("for i in range(100000):\n    print('x' * 100)", dispatch=FakeBroker())
    assert len(out.encode()) == 65_536 and out.endswith(TRUNCATION_MARKER)


# --------------------------------------------------------------------------- response bytes


def _sized_response(total: int) -> dict[str, Any]:
    """A tool response whose own serialization is exactly ``total`` bytes, mostly multibyte."""
    overhead = _size({"text": ""})
    room = total - overhead
    text = "é" * (room // 2) + "a" * (room % 2)
    value = {"text": text}
    assert _size(value) == total  # the tool response; the {"ok": ...} envelope is not counted
    return value


async def test_per_result_limit_counts_utf8_bytes():
    broker = FakeBroker(blob=lambda a: _sized_response(a["total"]))
    ok = await run_script(
        f"r = await call_tool('blob', {{'total': {MAX_RESULT_BYTES}}})\nlen(r['result']['text'])",
        dispatch=broker,
    )
    assert int(ok) > 0
    with pytest.raises(CodeModeError) as exc:
        await run_script(
            f"r = await call_tool('blob', {{'total': {MAX_RESULT_BYTES + 1}}})\n'partial'",
            dispatch=broker,
        )
    assert exc.value.code == LIMIT_EXCEEDED
    assert "call 1 (blob)" in exc.value.message
    assert "partial" not in exc.value.message


async def test_aggregate_limit_accumulates_across_calls_pages_and_refusals():
    per = MAX_RESULT_BYTES
    broker = FakeBroker(blob=lambda a: _sized_response(a["total"]))
    # 7 full responses (1,835,008) + 1 refusal + one that crosses 2,097,152.
    refusal_size = _size({"code": "write_denied", "message": "delete_thing refused"})
    remaining = MAX_AGGREGATE_BYTES - 7 * per - refusal_size
    script = textwrap.dedent(
        f"""
        out = []
        for i in range(7):
            out.append((await call_tool('blob', {{'total': {per}}}))['ok'])
        out.append((await call_tool('delete_thing', {{'id': 'x'}}))['ok'])
        out.append((await call_tool('blob', {{'total': {remaining}}}))['ok'])
        out
        """
    )
    expected = "[true,true,true,true,true,true,true,false,true]"
    assert await run_script(script, dispatch=broker) == expected
    with pytest.raises(CodeModeError) as exc:
        await run_script(
            script.replace(f"'total': {remaining}", f"'total': {remaining + 1}"),
            dispatch=broker,
        )
    assert exc.value.code == LIMIT_EXCEEDED
    assert "call 9 (blob)" in exc.value.message


async def test_aggregate_limit_holds_for_parallel_calls_in_one_script():
    gate = asyncio.Event()

    async def slow(a):
        await gate.wait()
        return _sized_response(a["total"])

    broker = FakeBroker(blob=slow)
    half = MAX_AGGREGATE_BYTES // 2 + 1  # two of these cannot both fit
    half = min(half, MAX_RESULT_BYTES)
    count = MAX_AGGREGATE_BYTES // half + 1
    script = textwrap.dedent(
        f"""
        import asyncio
        await asyncio.gather(*[call_tool('blob', {{'total': {half}}}) for _ in range({count})])
        """
    )
    task = asyncio.ensure_future(run_script(script, dispatch=broker))
    while len(broker.calls) < count and not task.done():
        await asyncio.sleep(0)
    gate.set()
    with pytest.raises(CodeModeError) as exc:
        await task
    assert exc.value.code == LIMIT_EXCEEDED


async def test_counters_reset_only_for_a_new_script():
    broker = FakeBroker(blob=lambda a: _sized_response(a["total"]))
    script = "\n".join(
        f"await call_tool('blob', {{'total': {MAX_RESULT_BYTES}}})" for _ in range(7)
    )
    for _ in range(3):  # 7 x 256 KiB fits once per script, every time
        assert await run_script(script + "\n'ok'", dispatch=broker) == "ok"


# --------------------------------------------------------------------------- strict encoding


async def test_response_with_lone_surrogate_is_invalid_text_naming_the_call():
    retained: list[Any] = []
    original_cleanup = code_mode._Run.cleanup

    async def spy_cleanup(self):
        retained.append(list(self.retained))
        await original_cleanup(self)
        retained.append(list(self.retained))

    broker = FakeBroker(
        good=lambda _a: {"text": "fine"},
        bad=lambda _a: {"text": "x\ud800y"},
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(code_mode._Run, "cleanup", spy_cleanup)
        with pytest.raises(CodeModeError) as exc:
            await run_script(
                "a = await call_tool('good', {})\nb = await call_tool('bad', {})\n'partial'",
                dispatch=broker,
            )
    assert exc.value.code == INVALID_TEXT
    assert "call 2 (bad)" in exc.value.message
    assert "partial" not in exc.value.message
    assert len(retained[0]) == 1 and retained[1] == []  # payloads cleared at cleanup


# --------------------------------------------------------------------------- call budget


async def test_32_attempts_including_refusals_and_the_33rd_ends_the_script():
    broker = FakeBroker(list_hosts=lambda _a: {"data": []})
    script_32 = "\n".join(
        "await call_tool('delete_thing', {})" if i % 2 else "await call_tool('list_hosts', {})"
        for i in range(32)
    )
    assert await run_script(script_32 + "\n'done'", dispatch=broker) == "done"
    assert len(broker.calls) == 32
    broker.calls.clear()
    records: list[dict[str, Any]] = []
    with pytest.raises(CodeModeError) as exc:
        await run_script(
            script_32 + "\ntry:\n    await call_tool('list_hosts', {})\nexcept Exception:\n"
            "    pass\n'swallowed'",
            dispatch=broker,
            audit=records.append,
            audit_hmac_key=TEST_AUDIT_HMAC_KEY,
        )
    assert exc.value.code == LIMIT_EXCEEDED
    assert "call 33 (list_hosts)" in exc.value.message
    assert len(broker.calls) == 32  # the 33rd never reached the broker
    assert len(records[0]["tools"]) == len(records[0]["argument_hmacs"]) == 33
    assert records[0]["argument_hmacs"][-1] == code_mode.INVALID_ARGUMENT_HMAC


async def test_invalid_names_and_arguments_count_and_never_dispatch():
    broker = FakeBroker(list_hosts=lambda _a: {"data": []})
    records: list[dict[str, Any]] = []
    out = await run_script(
        "[ (await call_tool(1, {}))['error']['code'],"
        "  (await call_tool('list_hosts', [1]))['error']['code'] ]",
        dispatch=broker,
        audit=records.append,
        audit_hmac_key=TEST_AUDIT_HMAC_KEY,
    )
    assert out == '["invalid_tool_name","invalid_arguments"]'
    assert broker.calls == []
    assert records[0]["argument_hmacs"][0] != code_mode.INVALID_ARGUMENT_HMAC
    assert records[0]["argument_hmacs"][1] == code_mode.INVALID_ARGUMENT_HMAC


# --------------------------------------------------------------------------- process slot


async def test_parallel_request_is_busy_with_zero_upstream_calls():
    gate = asyncio.Event()

    async def wait(_a):
        await gate.wait()
        return {"data": []}

    first = FakeBroker(list_hosts=wait)
    second = FakeBroker(list_hosts=lambda _a: {"data": []})
    task = asyncio.ensure_future(run_script("await call_tool('list_hosts', {})", dispatch=first))
    while not first.calls:
        await asyncio.sleep(0)
    with pytest.raises(CodeModeError) as exc:
        await run_script("await call_tool('list_hosts', {})", dispatch=second)
    assert exc.value.code == BUSY and second.calls == []
    gate.set()
    await task
    assert await run_script("await call_tool('list_hosts', {})\n'ok'", dispatch=second) == "ok"


@pytest.mark.parametrize("ending", ["success", "error", "limit", "script_error"])
async def test_slot_released_exactly_once_on_every_ending(ending, monkeypatch):
    releases = []
    original = code_mode.SlotLease.release

    def counted(self):
        released = original(self)
        releases.append(released)
        return released

    monkeypatch.setattr(code_mode.SlotLease, "release", counted)
    broker = FakeBroker(list_hosts=lambda _a: {"data": []})
    script = {
        "success": "1",
        "error": "raise ValueError('boom')",
        "limit": "\n".join("await call_tool('list_hosts', {})" for _ in range(33)),
        "script_error": "def f(:\n  pass",
    }[ending]
    if ending == "success":
        await run_script(script, dispatch=broker)
    else:
        with pytest.raises(CodeModeError):
            await run_script(script, dispatch=broker)
    assert releases == [True]
    assert not code_mode.SLOT.busy


async def test_cancellation_releases_slot_after_pending_callbacks_finish():
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def hang(_a):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    broker = FakeBroker(list_hosts=hang)
    task = asyncio.ensure_future(
        run_script(
            "import asyncio\nawait asyncio.gather(call_tool('list_hosts', {}), "
            "call_tool('list_hosts', {}))",
            dispatch=broker,
        )
    )
    await started.wait()
    assert code_mode.SLOT.busy
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled.is_set()
    assert not code_mode.SLOT.busy
    assert await run_script("2 + 2", dispatch=FakeBroker()) == "4"


async def test_cancelled_compute_loop_kills_its_worker_and_frees_the_slot():
    task = asyncio.ensure_future(run_script("while True:\n    pass", dispatch=FakeBroker()))
    while not code_mode.SLOT.busy:
        await asyncio.sleep(0)
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not code_mode.SLOT.busy
    assert await run_script("'next'", dispatch=FakeBroker()) == "next"


async def test_separate_process_has_an_independent_slot():
    lease = code_mode.SLOT.try_acquire()
    assert lease is not None
    try:
        child = textwrap.dedent(
            """
            import asyncio
            from unifi_fabric.code_mode import run_script

            async def dispatch(name, arguments):
                raise AssertionError("no call expected")

            print(asyncio.run(run_script("40 + 2", dispatch=dispatch)))
            """
        )
        done = subprocess.run(  # noqa: S603 - fixed interpreter and in-test script
            [sys.executable, "-c", child], capture_output=True, text=True, check=False
        )
        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == "42"
    finally:
        assert lease.release() is True
        assert lease.release() is False


# --------------------------------------------------------------------------- sandbox negatives


@pytest.mark.parametrize(
    "script",
    [
        "open('/etc/passwd').read()",
        "import os\nos.environ.get('HOME')",
        "import os\nos.getenv('UNIFI_API_KEY')",
        "import socket",
        "import subprocess",
        "import urllib.request",
        "__import__('os').system('true')",
    ],
)
async def test_sandbox_has_no_file_environment_network_or_process_access(script):
    broker = FakeBroker()
    with pytest.raises(CodeModeError) as exc:
        await run_script(script, dispatch=broker)
    assert exc.value.code == code_mode.SCRIPT_ERROR
    assert broker.calls == []


async def test_recursion_and_memory_bombs_are_limit_exceeded():
    for script in (
        "def f(n):\n    return f(n + 1)\nf(0)",
        "x = [0] * (200 * 1024 * 1024)",
        "s = 'a'\nwhile True:\n    s = s + s",
    ):
        with pytest.raises(CodeModeError) as exc:
            await run_script(script, dispatch=FakeBroker())
        assert exc.value.code == LIMIT_EXCEEDED


async def test_cpu_limit_counts_interpreter_time_not_waits_on_upstream(monkeypatch):
    # The reviewed exception is 30 s of interpreter time; shrink it for the test.
    monkeypatch.setitem(code_mode.SANDBOX_LIMITS, "max_feed_duration_secs", 0.5)
    with pytest.raises(CodeModeError) as exc:
        await run_script("while True:\n    pass", dispatch=FakeBroker())
    assert exc.value.code == LIMIT_EXCEEDED
    assert "execution-time" in exc.value.message

    async def slow(_a):
        await asyncio.sleep(1.5)  # a long upstream wait is never capped
        return {"data": []}

    out = await run_script(
        "r = await call_tool('list_hosts', {})\nr['ok']", dispatch=FakeBroker(list_hosts=slow)
    )
    assert out == "true"


async def test_sleep_returns_at_once():
    out = await run_script("import time\ntime.sleep(3600)\n'awake'", dispatch=FakeBroker())
    assert out == "awake"


async def test_secret_in_response_or_output_is_scrubbed(monkeypatch):
    secret = "synthetic-code-mode-secret-0123456789"
    monkeypatch.setenv("UNIFI_API_KEY", secret)
    broker = FakeBroker(leak=lambda _a: {"text": f"key={secret}"})
    out = await run_script(
        f"r = await call_tool('leak', {{}})\nprint(r['result']['text'])\n'{secret}'",
        dispatch=broker,
    )
    assert secret not in out


async def test_unavailable_runtime_is_a_typed_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "pydantic_monty", None)
    with pytest.raises(CodeModeError) as exc:
        await run_script("1", dispatch=FakeBroker())
    assert exc.value.code == code_mode.UNAVAILABLE


async def test_run_audit_has_digest_and_no_code_text():
    records: list[dict[str, Any]] = []
    source = "secret_marker = 'abc'\nawait call_tool('list_hosts', {'host': 'h'})\n'ok'"
    await run_script(
        source,
        dispatch=FakeBroker(list_hosts=lambda _a: {"data": []}),
        request_id="0" * 32,
        audit=records.append,
        audit_hmac_key=TEST_AUDIT_HMAC_KEY,
    )
    (record,) = records
    assert record["outcome"] == "ok" and record["calls"] == 1
    assert record["tools"] == ["<unregistered>"]  # no known-tool predicate given
    assert len(record["code_sha256"]) == 64
    assert record["argument_hmacs"] == [
        "c6959612f299b1a3b0e2b56538bff03ea965a63b8699c4cf29f4be30777dc1f0"
    ]
    canonical = json.dumps({"host": "h"}, sort_keys=True, **DUMPS).encode()
    bare = hashlib.sha256(canonical).hexdigest()
    serialized = json.dumps(record)
    assert record["argument_hmacs"][0] != bare
    assert "secret_marker" not in serialized and "'h'" not in serialized
    assert TEST_AUDIT_HMAC_KEY_TEXT not in serialized and "data" not in serialized


async def test_run_audit_refuses_to_start_without_a_hmac_key():
    records: list[dict[str, Any]] = []
    with pytest.raises(ValueError, match="32-byte argument HMAC key"):
        await run_script("1", dispatch=FakeBroker(), audit=records.append)
    assert records == []


async def test_argument_hmac_is_canonical_stable_and_rotates():
    async def digest(arguments: dict[str, Any], key: bytes) -> str:
        records: list[dict[str, Any]] = []
        await run_script(
            f"await call_tool('list_hosts', {arguments!r})",
            dispatch=FakeBroker(list_hosts=lambda _a: {"data": []}),
            audit=records.append,
            audit_hmac_key=key,
        )
        return records[0]["argument_hmacs"][0]

    first = await digest({"nested": {"b": [2, True], "a": "value"}}, TEST_AUDIT_HMAC_KEY)
    reordered = await digest({"nested": {"a": "value", "b": [2, True]}}, TEST_AUDIT_HMAC_KEY)
    changed = await digest({"nested": {"a": "other", "b": [2, True]}}, TEST_AUDIT_HMAC_KEY)
    rotated = await digest({"nested": {"b": [2, True], "a": "value"}}, bytes(range(1, 33)))
    assert first == reordered
    assert len({first, changed, rotated}) == 3
    assert code_mode._argument_hmac(TEST_AUDIT_HMAC_KEY, {"n": float("nan")}) == "invalid"
    assert code_mode._argument_hmac(TEST_AUDIT_HMAC_KEY, {"not_json": (1, 2)}) == "invalid"


def test_argument_hmac_is_stable_across_processes():
    script = textwrap.dedent(
        """
        import asyncio
        from fastmcp.tools import ToolResult
        from mcp.types import TextContent
        from unifi_fabric.code_mode import run_script

        async def dispatch(_name, _arguments):
            return ToolResult(
                content=[TextContent(type="text", text='{"data":[]}')],
                structured_content={"data": []},
            )

        records = []
        asyncio.run(run_script(
            "await call_tool('list_hosts', {'site': 'default', 'host': 'console'})",
            dispatch=dispatch,
            audit=records.append,
            audit_hmac_key=bytes(range(32)),
        ))
        print(records[0]["argument_hmacs"][0])
        """
    )
    outputs = [
        subprocess.run(  # noqa: S603 - this interpreter, hermetic synthetic dispatch
            [sys.executable, "-c", script], capture_output=True, check=True, text=True
        ).stdout.strip()
        for _ in range(2)
    ]
    assert len(outputs[0]) == 64 and outputs[0] == outputs[1]


async def test_pool_clocks_are_explicitly_off(monkeypatch):
    import pydantic_monty

    seen: dict[str, Any] = {}
    original = pydantic_monty.AsyncMonty

    def capture(**kwargs: Any) -> Any:
        seen.update(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(pydantic_monty, "AsyncMonty", capture)
    await run_script("1", dispatch=FakeBroker())
    for key in (
        "checkout_timeout",
        "request_timeout",
        "feed_duration_limit_grace",
        "turn_duration_limit_grace",
    ):
        assert key in seen and seen[key] is None, key


async def test_run_returns_only_after_the_runtime_thread_leaves_the_loop_wakeup(monkeypatch):
    """The sandbox runtime resolves each awaited call from its own thread through
    ``loop.call_soon_threadsafe``, which releases the GIL for its self-pipe write. A run
    that returned while such a thread was still inside that call let the process reach
    interpreter finalization first, and the thread then aborted the process (SIGABRT).
    Here the pool's last completion stays inside the call until the loop has turned a few
    times; run_script must not return before that thread has left it."""
    import _thread
    import threading

    import pydantic_monty

    loop = asyncio.get_running_loop()
    entered, release, left = threading.Event(), threading.Event(), threading.Event()
    wake = loop._write_to_self  # type: ignore[attr-defined]

    def slow_wake() -> None:  # the self-pipe write, GIL released, as a slow thread sees it
        entered.set()
        release.wait()
        wake()
        left.set()

    monkeypatch.setattr(loop, "_write_to_self", slow_wake)

    class Session:
        async def __aenter__(self) -> Session:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def feed_run(self, source: str, **kwargs: Any) -> int:
            return 42

    class Pool:
        def __init__(self, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> Pool:
            return self

        async def __aexit__(self, *exc: object) -> None:
            # A runtime (non-Python) thread resolves the pool's exit future.
            _thread.start_new_thread(loop.call_soon_threadsafe, (lambda: None,))
            entered.wait()

        def checkout(self, **kwargs: Any) -> Session:
            return Session()

    async def release_after_the_loop_turns() -> None:
        for _ in range(3):
            await asyncio.sleep(0)
        release.set()

    monkeypatch.setattr(pydantic_monty, "AsyncMonty", Pool)
    releaser = asyncio.ensure_future(release_after_the_loop_turns())
    try:
        assert await run_script("40 + 2", dispatch=FakeBroker()) == "42"
        assert left.is_set(), "run_script returned while a runtime thread was waking the loop"
    finally:
        release.set()
        await releaser


async def test_unspawnable_worker_is_code_mode_unavailable(monkeypatch):
    monkeypatch.setenv("MONTY_BIN", "/nonexistent/monty")
    with pytest.raises(CodeModeError) as exc:
        await run_script("1", dispatch=FakeBroker())
    assert exc.value.code == code_mode.UNAVAILABLE


async def test_audit_names_only_known_read_tools():
    records: list[dict[str, Any]] = []
    await run_script(
        "await call_tool('list_hosts', {})\nawait call_tool('abcdef0123456789secretvalue', {})",
        dispatch=FakeBroker(list_hosts=lambda _a: {"data": []}),
        known={"list_hosts"}.__contains__,
        audit=records.append,
        audit_hmac_key=TEST_AUDIT_HMAC_KEY,
    )
    assert records[0]["tools"] == ["list_hosts", "<unregistered>"]
    assert len(records[0]["argument_hmacs"]) == 2


# --------------------------------------------------------------------------- tool surface


def _synthetic_app() -> tuple[FastMCP, list[str]]:
    app = FastMCP("code-mode-contract")
    upstream: list[str] = []

    @app.tool(annotations=for_tool(writes=False))
    def list_things() -> dict[str, Any]:
        """List things."""
        upstream.append("list_things")
        return {"data": ["a", "b"]}

    @app.tool(annotations=for_tool(writes=True))
    def delete_thing(thing: str) -> dict[str, Any]:
        """Delete a thing."""
        upstream.append("delete_thing")
        return {"deleted": thing}

    return app, upstream


async def test_codemode_lists_exactly_three_tools_and_logs_experimental(caplog):
    from unifi_fabric.discovery import apply_tool_mode

    app, _ = _synthetic_app()
    caplog.set_level(logging.WARNING, logger="unifi_fabric.discovery")
    restore = await apply_tool_mode(app, "codemode", audit_hmac_key=TEST_AUDIT_HMAC_KEY)
    try:
        async with Client(app) as client:
            tools = {t.name: t for t in await client.list_tools()}
        assert set(tools) == {"search_tools", "describe_tool", "execute"}
        assert all(t.annotations.read_only_hint for t in tools.values())
        assert code_mode.EXPERIMENTAL_NOTICE in app.instructions
        assert any(code_mode.EXPERIMENTAL_NOTICE in r.getMessage() for r in caplog.records)
    finally:
        restore()
    assert {t.name for t in await app.list_tools()} == {"list_things", "delete_thing"}


async def test_codemode_search_and_describe_cover_reads_only():
    from unifi_fabric.discovery import apply_tool_mode

    app, _ = _synthetic_app()
    restore = await apply_tool_mode(app, "codemode", audit_hmac_key=TEST_AUDIT_HMAC_KEY)
    try:
        async with Client(app) as client:
            found = (await client.call_tool("search_tools", {"query": "", "limit": None})).data
            assert [row["name"] for row in found] == ["list_things"]
            with pytest.raises(ToolError, match="write_denied"):
                await client.call_tool("describe_tool", {"name": "delete_thing"})
    finally:
        restore()


class _RefFilter(BaseModel):
    """A nested model: its tool schema carries $defs/$ref that tools/list inlines."""

    name: str


async def test_codemode_describe_inlines_refs_like_tools_list():
    """A read tool whose schema uses $defs is described as tools/list lists it: inlined."""
    from unifi_fabric.discovery import apply_tool_mode

    app = FastMCP("code-mode-refs")

    @app.tool(annotations=for_tool(writes=False))
    def list_filtered(first: _RefFilter, second: _RefFilter | None = None) -> dict[str, Any]:
        """List things matching filters."""
        return {"data": [first.name]}

    (registered,) = await app.list_tools(run_middleware=False)
    assert "$defs" in registered.parameters
    async with Client(app) as client:
        (listed,) = await client.list_tools()
    listed_entry = listed.model_dump(by_alias=True, exclude_none=True)
    assert "$defs" not in listed_entry["inputSchema"]
    restore = await apply_tool_mode(app, "codemode", audit_hmac_key=TEST_AUDIT_HMAC_KEY)
    try:
        async with Client(app) as client:
            described = (await client.call_tool("describe_tool", {"name": "list_filtered"})).data
    finally:
        restore()
    assert described == listed_entry


async def test_codemode_never_dispatches_a_write_and_refuses_direct_calls(monkeypatch):
    from unifi_fabric.discovery import apply_tool_mode

    monkeypatch.delenv("UNIFI_WRITE_POLICY", raising=False)
    app, upstream = _synthetic_app()
    restore = await apply_tool_mode(app, "codemode", audit_hmac_key=TEST_AUDIT_HMAC_KEY)
    try:
        async with Client(app) as client:
            out = await client.call_tool(
                "execute",
                {
                    "code": "a = await call_tool('list_things', {})\n"
                    "b = await call_tool('delete_thing', {'thing': 'x'})\n"
                    "c = await call_tool('execute', {'code': '1'})\n"
                    "[a['result'], b['error']['code'], c['ok']]"
                },
            )
            assert out.structured_content is None
            assert json.loads(out.content[0].text) == [{"data": ["a", "b"]}, "write_denied", False]
            for name, args in (("delete_thing", {"thing": "x"}), ("list_things", {})):
                with pytest.raises(ToolError, match="tool_not_exposed"):
                    await client.call_tool(name, args)
    finally:
        restore()
    assert upstream == ["list_things"]


async def test_execute_wire_response_is_bounded_once():
    from unifi_fabric.discovery import apply_tool_mode

    app, _ = _synthetic_app()
    restore = await apply_tool_mode(app, "codemode", audit_hmac_key=TEST_AUDIT_HMAC_KEY)
    try:
        async with Client(app) as client:
            for size, marked in ((65_536, False), (65_537, True)):
                out = await client.call_tool("execute", {"code": f"'a' * {size}"})
                assert out.structured_content is None and len(out.content) == 1
                text = out.content[0].text
                assert len(text.encode()) == 65_536
                assert text.endswith(TRUNCATION_MARKER) is marked
    finally:
        restore()


async def test_surrogate_from_a_real_tool_ends_the_script_with_invalid_text():
    from unifi_fabric.discovery import apply_tool_mode

    app, _ = _synthetic_app()

    @app.tool(annotations=for_tool(writes=False))
    def odd_text() -> dict[str, Any]:
        """Return text decoded from an upstream lone-surrogate escape."""
        return {"text": json.loads('"x\\ud800y"')}

    restore = await apply_tool_mode(app, "codemode", audit_hmac_key=TEST_AUDIT_HMAC_KEY)
    try:
        async with Client(app) as client:
            with pytest.raises(ToolError) as exc:
                await client.call_tool(
                    "execute", {"code": "await call_tool('odd_text', {})\n'partial'"}
                )
        assert INVALID_TEXT in str(exc.value) and "call 1 (odd_text)" in str(exc.value)
        assert "partial" not in str(exc.value)
    finally:
        restore()


async def test_codemode_busy_across_sessions_with_zero_upstream_calls():
    from unifi_fabric.discovery import apply_tool_mode

    app, upstream = _synthetic_app()
    restore = await apply_tool_mode(app, "codemode", audit_hmac_key=TEST_AUDIT_HMAC_KEY)
    try:
        async with Client(app) as one, Client(app) as two:
            first = asyncio.ensure_future(
                one.call_tool("execute", {"code": "while True:\n    pass"})
            )
            while not code_mode.SLOT.busy:
                await asyncio.sleep(0)
            with pytest.raises(ToolError, match=BUSY):
                await two.call_tool("execute", {"code": "await call_tool('list_things', {})"})
            first.cancel()
            with pytest.raises((asyncio.CancelledError, Exception)):
                await first
    finally:
        restore()
    assert upstream == []


async def test_default_discovery_surface_is_unchanged():
    from unifi_fabric.discovery import META_TOOLS, apply_tool_mode

    app, _ = _synthetic_app()
    restore = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            assert {t.name for t in await client.list_tools()} == set(META_TOOLS)
            assert "execute" not in {t.name for t in await client.list_tools()}
    finally:
        restore()


def test_tool_mode_setting_accepts_codemode():
    from unifi_fabric.config import Settings

    settings = Settings(tool_mode="codemode", audit_hmac_key=TEST_AUDIT_HMAC_KEY_TEXT)
    assert settings.tool_mode == "codemode"
    assert settings.audit_hmac_key_bytes() == TEST_AUDIT_HMAC_KEY
    assert TEST_AUDIT_HMAC_KEY_TEXT not in repr(settings)
    assert (
        Settings(tool_mode=" CodeMode ", audit_hmac_key=TEST_AUDIT_HMAC_KEY_TEXT).tool_mode
        == "codemode"
    )
    assert Settings().tool_mode == "discovery"
    with pytest.raises(ValueError, match="discovery, full, codemode"):
        Settings(tool_mode="code")


def test_codemode_requires_a_canonical_32_byte_audit_hmac_key():
    from pydantic import ValidationError

    from unifi_fabric.config import Settings

    with pytest.raises(ValidationError, match="UNIFI_AUDIT_HMAC_KEY"):
        Settings(tool_mode="codemode")
    malformed = [
        TEST_AUDIT_HMAC_KEY_TEXT + "=",
        TEST_AUDIT_HMAC_KEY_TEXT[:-1],
        base64.b64encode(bytes([251]) * 32).rstrip(b"=").decode(),
    ]
    for value in malformed:
        with pytest.raises(ValidationError, match="UNIFI_AUDIT_HMAC_KEY") as exc:
            Settings(tool_mode="codemode", audit_hmac_key=value)
        assert value not in str(exc.value)
    # The key is optional outside Code Mode, but still validated if an operator sets it.
    assert Settings(tool_mode="discovery").audit_hmac_key_bytes() is None
    with pytest.raises(ValidationError, match="UNIFI_AUDIT_HMAC_KEY"):
        Settings(tool_mode="discovery", audit_hmac_key="not-a-key")


# --------------------------------------------------------------------------- duration policy


def test_cpu_exception_is_the_one_reviewed_allowlist_entry():
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import check_no_timeouts as checker
    finally:
        sys.path.pop(0)
    assert checker.check_allowlist(ROOT) == []
    entries = json.loads((ROOT / "docs/no-timeouts-allowlist.json").read_text())
    cpu = [e for e in entries if e["class"] == "sandbox-interpreter-cpu"]
    assert len(cpu) == 1 and cpu[0]["path"] == "src/unifi_fabric/code_mode.py"
    source = (ROOT / cpu[0]["path"]).read_text()
    assert source.count(cpu[0]["pattern"]) == 1
    findings = [
        f
        for f in checker.repository_findings(ROOT)
        if "code_mode" in f or "sandbox duration" in f or "allowlist" in f
    ]
    assert findings == []
    # Any other sandbox duration setting is a finding.
    flagged = checker.python_findings(
        Path("src/x.py"),
        "limits = {'max_turn_duration_secs': 5}\npool = AsyncMonty(request_timeout=5)\n",
    )
    assert any("sandbox duration limit" in f for f in flagged)
    assert any("sandbox duration argument" in f for f in flagged)
