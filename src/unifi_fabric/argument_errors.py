"""Actionable errors for invalid tool arguments.

When a caller omits a required argument, passes an unknown one, or sends a value of
the wrong type, the framework rejects the call during argument parsing with a raw
pydantic report such as ``1 validation error for call[create_network] ... [type=
missing_argument, input_value={...}, input_type=dict]``. That text names the field but
not where its value comes from, and it echoes the caller's input back.

:class:`ArgumentErrorMiddleware` replaces only that report. It turns an
argument-parsing failure into a ``ToolError`` that names each missing or invalid
parameter, repeats the parameter's schema description (which says where to get the
value), lists the valid parameters, and shows an example call. Input values are never
echoed; a caller-supplied path component (a parameter name or dict key) is echoed whole,
never truncated, so the central secret scrubber always sees it in full.

Scope is deliberately narrow. The middleware converts an error only when it is the
framework's own argument validation; anything raised while the tool body runs — a
pydantic error from building a model, a ``ValueError`` from local checks, an upstream
HTTP error carrying the controller's response body — propagates exactly as before.
Tool *responses* are never touched: the server stays a faithful pass-through.

How a body error is told apart: FastMCP wraps an argument-parsing failure in
``fastmcp.exceptions.ValidationError`` (with the ``pydantic.ValidationError`` as its
cause) and re-raises a pydantic error from a tool body under a private marker type, so
only the former reaches this middleware as a validation error. As a second check the
cause's traceback is inspected: argument validation runs inside the framework and
pydantic before the tool function is entered, so a pydantic error whose traceback
passes through the tool function (or any wrapper around it) or through other code of
this package was raised by a tool body and is left alone.
"""

from __future__ import annotations

import json
import re
from decimal import Decimal
from pathlib import Path
from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.exceptions import ValidationError as FrameworkValidationError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from pydantic import ValidationError

_PACKAGE_DIR = Path(__file__).resolve().parent
_THIS_FILE = Path(__file__).resolve()

# The worked example block the tool docstrings carry ("Example call (name):" followed
# by an indented JSON object). Used to show a concrete call in the error.
_EXAMPLE_HEADER_RE = re.compile(r"^Example call \([A-Za-z0-9_]+\):\s*\Z")


def echoed_input(value: Any) -> str:
    """The caller's value, echoed whole: its ``repr`` with no length or item bound.

    Never truncated or abbreviated (Build rules 2 and 8): a cut echo of a configured
    secret keeps a prefix or suffix of it visible while the central scrubber, which
    matches whole secrets, no longer finds it. The full value reaches the scrubber
    (``SecretScrubMiddleware`` and the log filter), which masks every form of every
    configured secret in the message it ends up in.
    """
    try:
        return repr(value)
    except ValueError:
        # An int past the interpreter's str-conversion digit limit (alone or inside a
        # list or object): rendered with every digit instead.
        return _render_whole(value)


def _render_whole(value: Any) -> str:
    """``repr`` with ints rendered through Decimal, which has no digit limit."""
    if isinstance(value, int) and not isinstance(value, bool):
        return str(Decimal(value))
    if isinstance(value, dict):
        items = ", ".join(f"{_render_whole(k)}: {_render_whole(v)}" for k, v in value.items())
        return "{" + items + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_render_whole(item) for item in value) + "]"
    return repr(value)


def input_path_component(value: Any) -> str:
    """One caller-supplied argument-path component (a parameter name or dict key),
    verbatim and whole -- never truncated, so the scrubber sees any secret in full."""
    return str(value)


def _function_codes(fn: Any) -> set[Any]:
    """Code objects of ``fn`` and of every function it wraps (``__wrapped__`` chain)."""
    codes: set[Any] = set()
    seen: set[int] = set()
    while fn is not None and id(fn) not in seen:
        seen.add(id(fn))
        code = getattr(fn, "__code__", None)
        if code is not None:
            codes.add(code)
        fn = getattr(fn, "__wrapped__", None)
    return codes


def _raised_in_tool_body(exc: BaseException, tool_fn: Any = None) -> bool:
    """True when the traceback passes through the tool function or this package's code."""
    body_codes = _function_codes(tool_fn)
    tb = exc.__traceback__
    while tb is not None:
        code = tb.tb_frame.f_code
        if code in body_codes:
            return True
        try:
            path = Path(code.co_filename).resolve()
        except (OSError, ValueError):  # pragma: no cover - exotic frame filenames
            path = None
        if path is not None and path != _THIS_FILE and _PACKAGE_DIR in path.parents:
            return True
        tb = tb.tb_next
    return False


def argument_validation_error(exc: BaseException, tool_fn: Any = None) -> ValidationError | None:
    """Return the pydantic error if ``exc`` is an argument-parsing failure, else None.

    ``tool_fn`` is the called tool's function; a pydantic error raised while it runs is
    a body error, not an argument error.
    """
    if not isinstance(exc, FrameworkValidationError):
        return None
    candidate = exc.__cause__
    if not isinstance(candidate, ValidationError) or _raised_in_tool_body(candidate, tool_fn):
        return None
    errors = candidate.errors(include_url=False, include_context=False, include_input=False)
    if not errors or not all(err.get("loc") and isinstance(err["loc"][0], str) for err in errors):
        return None
    return candidate


def _example_from_description(description: str) -> str | None:
    """Extract the docstring's worked example as one line of compact JSON."""
    lines = description.splitlines()
    for idx, line in enumerate(lines):
        if not _EXAMPLE_HEADER_RE.match(line.strip()):
            continue
        block: list[str] = []
        for following in lines[idx + 1 :]:
            if not following.strip():
                break
            block.append(following)
        try:
            return json.dumps(json.loads("\n".join(block)), ensure_ascii=False)
        except ValueError:
            return None
    return None


def _type_label(schema: dict[str, Any]) -> str:
    if "type" in schema:
        return str(schema["type"])
    variants = schema.get("anyOf") or schema.get("oneOf") or []
    labels = [str(v.get("type")) for v in variants if isinstance(v, dict) and "type" in v]
    return " | ".join(labels) if labels else "value"


def _placeholder(schema: dict[str, Any]) -> str:
    """Upper-case type placeholder for the call-shape hint (for example ``STRING``).

    Written without angle brackets: some MCP gateways and clients treat ``<word>`` as
    HTML, so runtime error text follows the same placeholder style as descriptions.
    """
    return _type_label(schema).upper().replace(" | ", "_OR_")


def format_argument_error(tool_name: str, tool: Any, error: ValidationError) -> str:
    """Build the actionable message for one argument-parsing failure."""
    parameters = (getattr(tool, "parameters", None) or {}) if tool is not None else {}
    properties: dict[str, Any] = parameters.get("properties") or {}
    required = set(parameters.get("required") or [])
    lines = [f"Invalid arguments for tool '{tool_name}':"]
    seen: set[tuple[str, str]] = set()
    for err in error.errors(include_url=False, include_context=False, include_input=False):
        name = str(err["loc"][0])
        kind = str(err.get("type", ""))
        if (name, kind) in seen:
            continue
        seen.add((name, kind))
        prop = properties.get(name) or {}
        if kind in ("missing_argument", "missing"):
            problem = "missing required argument"
        elif kind == "unexpected_keyword_argument":
            problem = "not a parameter of this tool"
        else:
            where = input_path_component(name) if len(err["loc"]) > 1 else ""
            for part in err["loc"][1:]:
                where += f"[{part}]" if isinstance(part, int) else f".{input_path_component(part)}"
            problem = f"invalid value{' at ' + where if where else ''} — {err.get('msg', kind)}"
            if prop:
                problem += f" (expected {_type_label(prop)})"
        display_name = input_path_component(name)
        line = f"- {display_name}: {problem}."
        if prop.get("description"):
            line += " " + " ".join(str(prop["description"]).split())
        lines.append(line)
    if properties:
        listed = ", ".join(f"{p} (required)" if p in required else p for p in properties)
        lines.append(f"Valid parameters: {listed}.")
    example = _example_from_description(str(getattr(tool, "description", "") or ""))
    if example:
        lines.append(f"Example call: {example}")
    elif properties:
        shape = {p: _placeholder(properties[p]) for p in properties if p in required}
        lines.append(f"Call shape (required arguments): {json.dumps(shape)}")
    return "\n".join(lines)


class ArgumentErrorMiddleware(Middleware):
    """Rewrite argument-parsing failures into actionable ``ToolError`` messages."""

    def __init__(self, server: Any) -> None:
        self._server = server

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        try:
            return await call_next(context)
        except Exception as exc:
            if not isinstance(exc, FrameworkValidationError):
                raise
            name = str(getattr(context.message, "name", ""))
            try:
                tool = await self._server.get_tool(name)
            except Exception:  # lookup is best-effort context only
                tool = None
            error = argument_validation_error(exc, getattr(tool, "fn", None))
            if error is None:
                raise
            raise ToolError(format_argument_error(name, tool, error)) from None
