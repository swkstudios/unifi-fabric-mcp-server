"""Opt-in, read-only, experimental Code Mode (``UNIFI_TOOL_MODE=codemode``).

Code Mode is an opt-in, read-only experimental feature. It may change without a
deprecation cycle. There is no compatibility promise for execute()'s schema or output
shape until graduation.

``execute(code)`` runs one Python script in a pydantic-monty sandbox worker. The script
reaches UniFi only through ``await call_tool(name, arguments)``, which the host serves with
the discovery read broker (:func:`unifi_fabric.discovery.apply_tool_mode`): the same
exposure, read-only, per-area opt-out, write-route and request-policy checks as
``call_read_tool``, and never a write. The sandbox gets no credentials, environment,
network, filesystem or other host function.

Limits (every byte limit counts UTF-8 bytes, never characters):

- script source 32,768 bytes, strictly UTF-8 encodable, else ``code_mode_invalid_source``
  before the process slot, the interpreter or any upstream call;
- one script at a time per server process, across all sessions and credential identities;
  a parallel request fails at once with ``code_mode_busy`` and no upstream call;
- 32 attempted tool calls per script, refusals included; the 33rd ends the script with
  ``code_mode_limit_exceeded``;
- each tool response 262,144 bytes and all responses together 2,097,152 bytes, measured on
  ``json.dumps(ensure_ascii=False, allow_nan=False, separators=(",", ":"))`` before any of
  it reaches the interpreter; overflow ends the script naming the call, with no partial
  answer;
- interpreter memory 64 MiB, recursion depth 64, and 30 seconds of interpreter execution
  time (the clock stops while a tool call waits on UniFi; waits on UniFi are never capped);
- output 65,536 bytes: longer output is cut on a code-point boundary to at most 65,522
  bytes and followed by the 14-byte marker ``...[truncated]``.

Text that cannot be strictly UTF-8 encoded (a lone surrogate) is refused with
``code_mode_invalid_text``: in a tool response, naming that call; in the output, naming the
execute call. It is never replaced, escaped or passed through.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import math
import re
import sys
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from types import FrameType
from typing import Any, Final

from fastmcp.exceptions import ToolError
from fastmcp.tools import ToolResult

from .secret_scrub import configured_secrets, scrub, scrub_json_strings

logger = logging.getLogger(__name__)

EXPERIMENTAL_NOTICE: Final = (
    "Code Mode is an opt-in, read-only experimental feature. It may change without a "
    "deprecation cycle. There is no compatibility promise for execute()'s schema or output "
    "shape until graduation."
)

#: The Code Mode tool surface: these three tools and nothing else are listed or callable.
EXECUTE_TOOL: Final = "execute"
CODE_MODE_TOOLS: Final = frozenset({"search_tools", "describe_tool", EXECUTE_TOOL})

# Result codes. code_mode_invalid_source and code_mode_busy are pre-dispatch refusals (closed
# list in policy.REFUSAL_CODES); the others are post-dispatch results of an admitted script.
INVALID_SOURCE: Final = "code_mode_invalid_source"
BUSY: Final = "code_mode_busy"
LIMIT_EXCEEDED: Final = "code_mode_limit_exceeded"
INVALID_TEXT: Final = "code_mode_invalid_text"
SCRIPT_ERROR: Final = "code_mode_script_error"
UNAVAILABLE: Final = "code_mode_unavailable"

MAX_SOURCE_BYTES: Final = 32_768
MAX_CALLS: Final = 32
MAX_RESULT_BYTES: Final = 262_144
MAX_AGGREGATE_BYTES: Final = 2_097_152
MAX_OUTPUT_BYTES: Final = 65_536
TRUNCATION_MARKER: Final = "...[truncated]"
TRUNCATED_PREFIX_BYTES: Final = MAX_OUTPUT_BYTES - len(TRUNCATION_MARKER.encode("ascii"))
MAX_MEMORY_BYTES: Final = 64 * 1024 * 1024
MAX_RECURSION_DEPTH: Final = 64
# Name lookups, external calls and futures the worker may suspend on per script. A tool call
# costs at most three (lookup, call, future), so this never binds before MAX_CALLS does.
MAX_SUSPENSIONS: Final = 1_000
#: Interpreter execution time, in seconds. The sandbox clock runs only while the script
#: executes, never while a tool call waits on UniFi.
CPU_SECONDS_LIMIT: Final = 30.0
ARGUMENT_HMAC_DOMAIN: Final = b"unifi-fabric/code-mode-arguments/v1\0"
INVALID_ARGUMENT_HMAC: Final = "invalid"

#: Worker resource limits. The one duration entry is the reviewed interpreter-CPU exception
#: in docs/no-timeouts-allowlist.json; no other limit in Code Mode is time-based.
SANDBOX_LIMITS: Final = {
    "max_memory": MAX_MEMORY_BYTES,
    "max_recursion_depth": MAX_RECURSION_DEPTH,
    "max_suspensions": MAX_SUSPENSIONS,
    "max_feed_duration_secs": CPU_SECONDS_LIMIT,
}
#: time.sleep/asyncio.sleep return at once; the sandbox clock is UTC and process time reads 0.
SANDBOX_OS_POLICY: Final = {"sleep": "zero", "timezone": "utc", "process_time": "zero"}


def _dumps(value: Any, default: Callable[[Any], Any] | None = None) -> str:
    """Strict compact JSON: ensure_ascii=False, allow_nan=False, (",", ":") separators."""
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), default=default
    )


_TOOL_NAME: Final = re.compile(r"[a-z][a-z0-9_]{0,127}")

Dispatch = Callable[[str, dict[str, Any]], Awaitable[ToolResult]]
RunAudit = Callable[[dict[str, Any]], None]


class CodeModeError(Exception):
    """A Code Mode failure: MCP isError with one ``{"error": {"code", "message"}}`` item."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def payload(self) -> str:
        return _dumps({"error": {"code": self.code, "message": self.message}})

    def tool_error(self) -> ToolError:
        return ToolError(self.payload())


# --------------------------------------------------------------------------- source


def check_source(source: object) -> str:
    """``source`` if admissible, else ``code_mode_invalid_source``.

    Runs before the process slot, the interpreter and any upstream call. The size is
    ``len(source.encode("utf-8"))`` under strict encoding: a lone surrogate is refused,
    never replaced or passed through ``surrogatepass``.
    """
    if not isinstance(source, str):
        raise CodeModeError(INVALID_SOURCE, "code must be a string of Python source.")
    try:
        size = len(source.encode("utf-8"))
    except UnicodeEncodeError:
        raise CodeModeError(
            INVALID_SOURCE,
            "code is not valid UTF-8 text (it contains an unpaired surrogate); no script ran.",
        ) from None
    if size > MAX_SOURCE_BYTES:
        raise CodeModeError(
            INVALID_SOURCE,
            f"code is {size} UTF-8 bytes; the limit is {MAX_SOURCE_BYTES}. No script ran.",
        )
    return source


# --------------------------------------------------------------------------- process slot


class ProcessSlot:
    """One Code Mode script at a time in this server process.

    Acquisition is atomic and never waits: a parallel request is refused at once. A
    separate server process has its own slot; there is no deployment-wide limit.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def try_acquire(self) -> SlotLease | None:
        return SlotLease(self._lock) if self._lock.acquire(blocking=False) else None

    @property
    def busy(self) -> bool:
        return self._lock.locked()


class SlotLease:
    """The held slot; :meth:`release` frees it exactly once."""

    def __init__(self, lock: threading.Lock) -> None:
        self._lock = lock
        self._released = False
        self._guard = threading.Lock()

    def release(self) -> bool:
        with self._guard:
            if self._released:
                return False
            self._released = True
        self._lock.release()
        return True


SLOT: Final = ProcessSlot()


# --------------------------------------------------------------------------- projection


def _error_object(text: str) -> dict[str, Any]:
    """The ``error`` object of a refused or failed tool call, from its ToolError text."""
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    if (
        isinstance(parsed, dict)
        and isinstance(parsed.get("error"), dict)
        and isinstance(parsed["error"].get("code"), str)
    ):
        error = parsed["error"]
        return {"code": error["code"], "message": str(error.get("message", ""))}
    return {"code": "tool_error", "message": text}


def project_result(result: ToolResult) -> dict[str, Any]:
    """The JSON-safe value a script receives for one successful tool call (experimental).

    ``{"ok": true, "result": <value>}``: the tool's structured result when it has one,
    else its text content (parsed as JSON when it is JSON). Live client and context
    objects never reach the interpreter.
    """
    structured = result.structured_content
    if structured is not None:
        value: Any = structured
        if isinstance(structured, dict) and set(structured) == {"result"}:
            value = structured["result"]
        return {"ok": True, "result": value}
    texts = [getattr(item, "text", None) for item in result.content]
    text = "".join(t for t in texts if isinstance(t, str))
    try:
        value = json.loads(text) if text else None
    except ValueError:
        value = text
    return {"ok": True, "result": value}


def project_error(exc: BaseException) -> dict[str, Any]:
    """The value a script receives for a refused or failed tool call."""
    return {"ok": False, "error": _error_object(str(exc))}


# --------------------------------------------------------------------------- output


def finish_output(text: str, *, forced: bool = False) -> str:
    """The execute tool's returned text: strict UTF-8, at most 65,536 bytes.

    At or under the limit ``text`` is returned unchanged (even when it already ends in the
    marker). Over it, the longest prefix of whole code points of at most 65,522 bytes is
    followed by ``...[truncated]``.
    """
    try:
        data = text.encode("utf-8")
    except UnicodeEncodeError:
        raise CodeModeError(
            INVALID_TEXT,
            f"{EXECUTE_TOOL}: the script output contains text that is not valid UTF-8 "
            "(an unpaired surrogate); no output is returned.",
        ) from None
    if len(data) <= MAX_OUTPUT_BYTES and not forced:
        return text
    if len(data) <= TRUNCATED_PREFIX_BYTES:
        return text + TRUNCATION_MARKER
    cut = TRUNCATED_PREFIX_BYTES
    # Back off to a code-point boundary: never split a multibyte sequence.
    while cut > 0 and (data[cut] & 0xC0) == 0x80:
        cut -= 1
    return data[:cut].decode("utf-8") + TRUNCATION_MARKER


#: Bytes of output kept before scrubbing: the scrub cost is bounded by this, never by what
#: the script produced. The slack past 65,522 exceeds any configured secret form, so a
#: secret straddling this cut lies beyond the final cut.
PRE_SCRUB_BYTES: Final = 4 * MAX_OUTPUT_BYTES


def _surrogate_failure(exc: BaseException) -> bool:
    """True when ``exc`` (or its cause chain) is a strict-UTF-8 failure on a surrogate."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if (
            isinstance(current, UnicodeEncodeError) and current.reason == "surrogates not allowed"
        ) or "surrogates not allowed" in str(current):
            return True
        current = current.__cause__ or current.__context__
    return False


def _arguments_too_large(arguments: object) -> bool:
    """True when arguments are not strict JSON or exceed their byte budget."""
    return _strict_argument_json_size(arguments or {}, MAX_RESULT_BYTES) is None


def _argument_hmac(key: bytes, arguments: object) -> str:
    """A stable, non-reversible digest for one admitted argument object.

    Invalid, non-strict-JSON and over-budget values share one fixed sentinel. The
    canonical argument bytes and key are never retained on :class:`_Run`.
    """
    if arguments is None:
        value: object = {}
    elif isinstance(arguments, dict) and all(isinstance(name, str) for name in arguments):
        value = arguments
    else:
        return INVALID_ARGUMENT_HMAC
    size = _strict_argument_json_size(value, MAX_RESULT_BYTES)
    if size is None:
        return INVALID_ARGUMENT_HMAC
    try:
        canonical = _canonical_argument_bytes(value, size)
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return INVALID_ARGUMENT_HMAC
    return hmac.new(key, ARGUMENT_HMAC_DOMAIN + canonical, hashlib.sha256).hexdigest()


def _json_string_size(text: str, budget: int) -> int | None:
    """Exact compact ``ensure_ascii=False`` JSON string bytes, bounded by ``budget``."""
    size = 2  # opening and closing quotes
    if size > budget:
        return None
    for char in text:
        codepoint = ord(char)
        if char in {'"', "\\"} or codepoint in {8, 9, 10, 12, 13}:
            width = 2
        elif codepoint < 0x20:
            width = 6
        elif 0xD800 <= codepoint <= 0xDFFF:
            return None
        elif codepoint < 0x80:
            width = 1
        elif codepoint < 0x800:
            width = 2
        elif codepoint < 0x10000:
            width = 3
        else:
            width = 4
        size += width
        if size > budget:
            return None
    return size


def _strict_argument_json_size(value: object, budget: int) -> int | None:
    """Exact strict compact-JSON byte size without recursion or large scalar encoding.

    Containers are revisited for shared logical references, as JSON serialization does,
    but every visit adds output bytes and work stops when ``budget`` is exceeded. Active
    container identities reject cycles. No escaped string or canonical JSON is built.
    """
    size = 0
    active: set[int] = set()
    stack: list[tuple[Any, ...]] = [("value", value)]
    while stack:
        event = stack.pop()
        kind = event[0]
        if kind == "leave":
            active.remove(event[1])
            continue
        if kind == "list-items":
            iterator, first = event[1], event[2]
            try:
                item = next(iterator)
            except StopIteration:
                continue
            if not first:
                size += 1
            if size > budget:
                return None
            stack.append(("list-items", iterator, False))
            stack.append(("value", item))
            continue
        if kind == "dict-items":
            iterator, first = event[1], event[2]
            try:
                name, item = next(iterator)
            except StopIteration:
                continue
            if not isinstance(name, str):
                return None
            if not first:
                size += 1
            name_size = _json_string_size(name, budget - size)
            if name_size is None:
                return None
            size += name_size + 1  # key plus colon
            if size > budget:
                return None
            stack.append(("dict-items", iterator, False))
            stack.append(("value", item))
            continue

        item = event[1]
        if item is None:
            width = 4
        elif isinstance(item, bool):
            width = 4 if item else 5
        elif isinstance(item, int):
            remaining = budget - size
            if item.bit_length() > max(1, remaining) * 4:
                return None
            try:
                width = len(str(item))
            except ValueError:
                return None
        elif isinstance(item, float):
            if not math.isfinite(item):
                return None
            width = len(repr(item))
        elif isinstance(item, str):
            string_size = _json_string_size(item, budget - size)
            if string_size is None:
                return None
            width = string_size
        elif isinstance(item, list | dict):
            marker = id(item)
            if marker in active:
                return None
            active.add(marker)
            size += 2  # both container delimiters
            if size > budget:
                return None
            stack.append(("leave", marker))
            if isinstance(item, list):
                stack.append(("list-items", iter(item), True))
            else:
                stack.append(("dict-items", iter(item.items()), True))
            continue
        else:
            return None
        size += width
        if size > budget:
            return None
    return size


def _canonical_argument_bytes(value: object, expected_size: int) -> bytes:
    """Materialize canonical JSON only after the bounded strict preflight passes."""
    canonical = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(canonical) != expected_size:
        raise AssertionError("argument JSON size changed after strict preflight")
    return canonical


def bounded_output(text: str, *, forced: bool = False) -> str:
    """Strict-check, pre-cut, scrub, then :func:`finish_output`.

    Output over :data:`PRE_SCRUB_BYTES` is cut on a code-point boundary before scrubbing
    and always ends in the marker; ``forced`` (print output was dropped) does the same.
    """
    try:
        data = text.encode("utf-8")
    except UnicodeEncodeError:
        return finish_output(text)  # raises code_mode_invalid_text
    if len(data) > PRE_SCRUB_BYTES:
        cut = PRE_SCRUB_BYTES
        while cut > 0 and (data[cut] & 0xC0) == 0x80:
            cut -= 1
        text, forced = data[:cut].decode("utf-8"), True
    return finish_output(scrub(text), forced=forced)


class _Printed:
    """The script's print() output, kept up to twice the output limit.

    Anything past that is beyond the returned text in every case (it is cut at 65,522
    bytes); the excess is counted, not stored, so a print loop cannot grow host memory.
    """

    _KEEP = 2 * MAX_OUTPUT_BYTES

    def __init__(self) -> None:
        self.parts: list[str] = []
        self.size = 0
        self.overflow = False

    def __call__(self, _stream: str, text: str) -> None:
        if self.size >= self._KEEP:
            self.overflow = True
            return
        self.parts.append(text)
        self.size += len(text.encode("utf-8", "surrogatepass"))

    def text(self) -> str:
        return "".join(self.parts)


def bounded_json(value: Any, budget: int) -> tuple[str, bool]:
    """``value`` as strict compact JSON, stopping once more than ``budget`` bytes are out.

    Returns the text and whether it was cut. Serialization stops after the first encoder
    chunk that crosses ``budget``. Argument handling uses
    :func:`_strict_argument_json_size` when a hard pre-materialization bound is required.
    """
    encoder = json.JSONEncoder(
        ensure_ascii=False, allow_nan=False, separators=(",", ":"), default=str
    )
    parts: list[str] = []
    size = 0
    for chunk in encoder.iterencode(value):
        parts.append(chunk)
        size += len(chunk.encode("utf-8", "surrogatepass"))
        if size > budget:
            return "".join(parts), True
    return "".join(parts), False


def render_output(printed: str, value: Any) -> tuple[str, bool]:
    """Printed output followed by the final expression's value, and whether it was cut.

    A string value is appended verbatim; any other non-None value as compact JSON,
    serialized only as far as the pre-scrub bound.
    """
    if value is None:
        return printed, False
    if isinstance(value, str):
        return printed + value, False
    try:
        text, cut = bounded_json(value, PRE_SCRUB_BYTES)
    except ValueError:
        raise CodeModeError(
            SCRIPT_ERROR, "The script's final value is not JSON-serializable (NaN or Infinity)."
        ) from None
    return printed + text, cut


# --------------------------------------------------------------------------- run


@dataclass
class _Run:
    """One admitted script: its counters, retained payloads and pending callbacks.

    Counters start at zero for each admitted script and are never shared.
    """

    dispatch: Dispatch
    known: Callable[[str], bool] = lambda _name: False
    audit_hmac_key: bytes | None = None
    calls: int = 0
    aggregate: int = 0
    names: list[str] = field(default_factory=list)
    argument_hmacs: list[str] = field(default_factory=list)
    retained: list[Any] = field(default_factory=list)
    pending: set[asyncio.Task[Any]] = field(default_factory=set)
    failure: CodeModeError | None = None
    feed: asyncio.Future[Any] | None = None

    def abort(self, error: CodeModeError) -> None:
        """End the script with ``error``: no partial answer, whatever the script does next."""
        if self.failure is None:
            self.failure = error
        if self.feed is not None and not self.feed.done():
            self.feed.cancel()

    async def call_tool(self, name: object = None, arguments: object = None) -> Any:
        """The sandbox's ``call_tool(name, arguments)``: one read through the broker."""
        if self.failure is not None:
            raise RuntimeError("the script has ended")
        task = asyncio.current_task()
        if task is not None:
            self.pending.add(task)
        try:
            return await self._call(name, arguments)
        finally:
            if task is not None:
                self.pending.discard(task)

    async def _call(self, name: object, arguments: object) -> Any:
        self.calls += 1
        index = self.calls
        label = name if isinstance(name, str) and _TOOL_NAME.fullmatch(name) else "<invalid>"
        # The audit record keeps a fixed vocabulary: only names of enabled read tools, so a
        # script cannot launder data into the log through made-up tool names.
        self.names.append(label if label == "<invalid>" or self.known(label) else "<unregistered>")
        where = f"call {index} ({label})"
        self.argument_hmacs.append(
            INVALID_ARGUMENT_HMAC
            if index > MAX_CALLS or self.audit_hmac_key is None
            else _argument_hmac(self.audit_hmac_key, arguments)
        )
        if index > MAX_CALLS:
            self.abort(
                CodeModeError(
                    LIMIT_EXCEEDED,
                    f"{where}: a script may attempt {MAX_CALLS} tool calls, refusals "
                    "included; the script was ended and no answer is returned.",
                )
            )
            raise RuntimeError("the script has ended")
        if label == "<invalid>":
            payload: dict[str, Any] = {
                "ok": False,
                "error": {
                    "code": "invalid_tool_name",
                    "message": "call_tool needs an exact read tool name from search_tools.",
                },
            }
        elif arguments is not None and not (
            isinstance(arguments, dict) and all(isinstance(k, str) for k in arguments)
        ):
            payload = {
                "ok": False,
                "error": {
                    "code": "invalid_arguments",
                    "message": "call_tool arguments must be a dict of argument name to value.",
                },
            }
        elif _arguments_too_large(arguments):
            payload = {
                "ok": False,
                "error": {
                    "code": "invalid_arguments",
                    "message": f"call_tool arguments serialize to more than {MAX_RESULT_BYTES} "
                    "bytes; no request was sent.",
                },
            }
        else:
            try:
                result = await self.dispatch(label, dict(arguments or {}))
            except CodeModeError:
                raise
            except Exception as exc:  # noqa: BLE001 - every tool failure reaches the script
                # Checked before any tool error is projected: FastMCP wraps a surrogate that
                # cannot be serialized in a ToolError whose text is the only signal left.
                if _surrogate_failure(exc):
                    self.abort(
                        CodeModeError(
                            INVALID_TEXT,
                            f"{where}: the response contains text that is not valid UTF-8 (an "
                            "unpaired surrogate); the script was ended and no answer "
                            "is returned.",
                        )
                    )
                    raise RuntimeError("the script has ended") from None
                if isinstance(exc, ToolError):
                    payload = project_error(exc)
                else:
                    payload = {"ok": False, "error": {"code": "tool_error", "message": str(exc)}}
            else:
                payload = project_result(result)
        return self._deliver(where, payload)

    def _deliver(self, where: str, payload: dict[str, Any]) -> Any:
        """Check and reserve ``payload`` against both byte limits, then hand it over.

        Synchronous between the check and the reservation, so parallel calls in one script
        cannot both pass a limit only one of them fits.
        """
        payload = scrub_json_strings(payload, configured_secrets())
        try:
            text = _dumps(payload)
            # The limits count the tool response itself (its result, or its error object),
            # serialized as below; the {"ok": ...} envelope Code Mode adds is not counted.
            response = _dumps(payload["result"] if payload.get("ok") else payload["error"])
        except ValueError:
            self.abort(
                CodeModeError(
                    INVALID_TEXT,
                    f"{where}: the response is not strict JSON (NaN or Infinity); "
                    "the script was ended and no answer is returned.",
                )
            )
            raise RuntimeError("the script has ended") from None
        try:
            text.encode("utf-8")
            size = len(response.encode("utf-8"))
        except UnicodeEncodeError:
            self.abort(
                CodeModeError(
                    INVALID_TEXT,
                    f"{where}: the response contains text that is not valid UTF-8 (an "
                    "unpaired surrogate); the script was ended and no answer is "
                    "returned.",
                )
            )
            raise RuntimeError("the script has ended") from None
        if size > MAX_RESULT_BYTES:
            self.abort(
                CodeModeError(
                    LIMIT_EXCEEDED,
                    f"{where}: the response is {size} bytes; one response may be at most "
                    f"{MAX_RESULT_BYTES}. Use the tool's continuation or a narrower request. "
                    "The script was ended and no answer is returned.",
                )
            )
            raise RuntimeError("the script has ended")
        if self.aggregate + size > MAX_AGGREGATE_BYTES:
            self.abort(
                CodeModeError(
                    LIMIT_EXCEEDED,
                    f"{where}: responses would total {self.aggregate + size} bytes; a script "
                    f"may receive at most {MAX_AGGREGATE_BYTES}. The script was ended and no "
                    "answer is returned.",
                )
            )
            raise RuntimeError("the script has ended")
        self.aggregate += size
        value = json.loads(text)
        self.retained.append(value)
        return value

    async def cleanup(self) -> None:
        """Cancel and wait for every pending callback; drop retained payloads."""
        current = asyncio.current_task()
        pending = [task for task in self.pending if not task.done() and task is not current]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self.pending.clear()
        self.retained.clear()


def _limit_error(exc: BaseException) -> CodeModeError | None:
    kind = type(exc).__name__
    if kind == "MemoryError":
        what = f"the interpreter memory limit ({MAX_MEMORY_BYTES // (1024 * 1024)} MiB)"
    elif kind == "RecursionError":
        what = f"the recursion depth limit ({MAX_RECURSION_DEPTH})"
    elif kind == "TimeoutError":
        what = f"the {int(CPU_SECONDS_LIMIT)}-second interpreter execution-time limit"
    else:
        return None
    return CodeModeError(
        LIMIT_EXCEEDED, f"{EXECUTE_TOOL}: the script exceeded {what} and was ended."
    )


def _script_error(exc: Exception) -> CodeModeError:
    import pydantic_monty as monty

    if isinstance(exc, monty.MontyRuntimeError):
        limit = _limit_error(exc.exception())
        if limit is not None:
            return limit
        text = exc.display("type-msg")
    elif isinstance(exc, monty.MontySyntaxError):
        text = exc.display("type-msg")
    elif isinstance(exc, monty.MontyCrashedError):
        text = "the sandbox worker exited before the script finished"
    else:
        text = type(exc).__name__
    return CodeModeError(SCRIPT_ERROR, bounded_output(f"{EXECUTE_TOOL}: {text}"))


async def _run_sandbox(source: str, run: _Run) -> str:
    try:
        import pydantic_monty as monty
    except ImportError:
        raise CodeModeError(
            UNAVAILABLE, "Code Mode needs the pydantic-monty package, which is not installed."
        ) from None
    printed = _Printed()
    try:
        return await _drive(monty, source, run, printed)
    except (OSError, RuntimeError) as exc:
        if run.failure is not None:
            raise run.failure from None
        raise CodeModeError(
            UNAVAILABLE,
            scrub(f"The Code Mode sandbox could not start: {type(exc).__name__}: {exc}"),
        ) from None


# asyncios thread-safe wakeup: how the sandbox runtimes threads resolve each awaited call.
_WAKEUP_CODE = asyncio.BaseEventLoop.call_soon_threadsafe.__code__


def _thread_in_loop_wakeup() -> bool:
    """Whether another thread is still inside ``call_soon_threadsafe``."""
    me = threading.get_ident()
    for ident, top in sys._current_frames().items():
        frame: FrameType | None = top
        while ident != me and frame is not None:
            if frame.f_code is _WAKEUP_CODE:
                return True
            frame = frame.f_back
    return False


async def _settle_runtime_threads() -> None:
    """Wait until no sandbox runtime thread is still waking the event loop.

    pydantic-monty resolves each awaited call from one of its own (tokio) threads through
    ``loop.call_soon_threadsafe``, whose self-pipe write releases the GIL. The awaiting
    coroutine can resume, and the process can exit, before that thread takes the GIL back;
    on Python 3.12 a thread that takes the GIL during interpreter finalization calls
    ``pthread_exit`` through Rust frames and the process aborts (SIGABRT, a core dump).
    Returning only once no other thread is inside that call closes the window.
    """
    while _thread_in_loop_wakeup():
        await asyncio.sleep(0.001)  # releases the GIL so the waking thread can finish


async def _drive(monty: Any, source: str, run: _Run, printed: _Printed) -> str:
    try:
        return await _drive_pool(monty, source, run, printed)
    finally:
        await _settle_runtime_threads()


async def _drive_pool(monty: Any, source: str, run: _Run, printed: _Printed) -> str:
    value: Any = None
    # One worker per script, never reused: no state crosses scripts, and leaving the pool
    # kills the worker on every path (success, error, limit, cancellation).
    async with monty.AsyncMonty(
        min_processes=1,
        max_processes=1,
        max_checkouts_per_worker=1,
        # No pool-side clocks: the interpreter-CPU limit above is the only duration limit,
        # enforced inside the worker. Waits on UniFi are never capped.
        checkout_timeout=None,
        request_timeout=None,
        feed_duration_limit_grace=None,
        turn_duration_limit_grace=None,
    ) as pool:
        async with pool.checkout(
            script_name="execute.py",
            limits=SANDBOX_LIMITS,  # type: ignore[arg-type]
            os_policy=SANDBOX_OS_POLICY,  # type: ignore[arg-type]
        ) as session:
            run.feed = asyncio.ensure_future(
                session.feed_run(
                    source,
                    external_lookup={"call_tool": run.call_tool},
                    print_callback=printed,
                )
            )
            try:
                value = await run.feed
            except asyncio.CancelledError:
                current = asyncio.current_task()
                if run.failure is not None and (current is None or not current.cancelling()):
                    raise run.failure from None
                raise
            except monty.MontyError as exc:
                if run.failure is not None:
                    raise run.failure from None
                raise _script_error(exc) from None
    if run.failure is not None:
        raise run.failure
    text, cut = render_output(printed.text(), value)
    return bounded_output(text, forced=printed.overflow or cut)


async def run_script(
    source: object,
    *,
    dispatch: Dispatch,
    known: Callable[[str], bool] | None = None,
    request_id: str | None = None,
    audit: RunAudit | None = None,
    audit_hmac_key: bytes | None = None,
    slot: ProcessSlot = SLOT,
) -> str:
    """Run one execute() call end to end; return its text or raise :class:`CodeModeError`.

    Order: source check (no slot, no interpreter, no upstream call), atomic slot
    acquisition (``code_mode_busy`` on contention), then the sandbox. The slot is held
    until every callback has finished and cleanup is complete, on success, error and
    cancellation, and released exactly once.
    """
    code = check_source(source)
    if audit is not None and (audit_hmac_key is None or len(audit_hmac_key) != 32):
        raise ValueError("Code Mode audit requires a 32-byte argument HMAC key")
    lease = slot.try_acquire()
    if lease is None:
        raise CodeModeError(
            BUSY,
            "Another Code Mode script is running in this server; one runs at a time. "
            "No request was sent; retry when it finishes.",
        )
    run = _Run(
        dispatch=dispatch,
        known=(lambda _name: False) if known is None else known,
        audit_hmac_key=audit_hmac_key,
    )
    outcome = "error"
    try:
        try:
            text = await _run_sandbox(code, run)
        except CodeModeError as exc:
            outcome = exc.code
            raise
        except asyncio.CancelledError:
            outcome = "cancelled"
            raise
        outcome = "ok"
        return text
    finally:
        try:
            await run.cleanup()
        finally:
            lease.release()
            if audit is not None:
                audit(_run_record(code, run, outcome, request_id))


def _run_record(code: str, run: _Run, outcome: str, request_id: str | None) -> dict[str, Any]:
    """The one run-level audit record: no code text, arguments or results."""
    return {
        "event": "code_mode.run",
        "request_id": request_id,
        "code_sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
        "calls": run.calls,
        "tools": list(run.names),
        "argument_hmacs": list(run.argument_hmacs),
        "response_bytes": run.aggregate,
        "outcome": outcome,
    }


def log_run(record: dict[str, Any]) -> None:
    """Default run audit: one INFO line of fixed fields."""
    logger.info("code_mode.run %s", _dumps(record))
