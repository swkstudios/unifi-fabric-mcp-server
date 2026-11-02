"""ARGUMENT-ECHO SECRET INVARIANT: a configured secret a caller passes in any argument
position never appears in the resulting error, whole or in part.

Two contract points together (secrets never in any error in any form; no truncation
of error text): an argument error may echo the caller's value, but whole, so
the central scrubber -- which matches whole secrets -- sees and masks it. A cut echo
(the earlier 200-character ``reprlib`` bound) left a prefix or suffix of a long secret
visible after scrubbing.

For every registered tool, a long configured secret (the API key in the settings, 640
characters, longer than any former echo bound) is supplied in every echoable argument
position: as each parameter's value
(an invalid enum value, a key label, an id, a number that is not one), inside a list, as
a dict key (an argument-path component) with a valid and with a non-finite value, and
as an unknown parameter name. The error text and every log line must carry no run of 6
or more consecutive characters of the secret. The echo helpers are also checked
directly, with a second long secret, for whole (never cut) echoes.
"""

from __future__ import annotations

import json
import logging
import secrets
import string
import traceback
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import LazyCatalog
from tests._tool_classes import tool_batches
from unifi_fabric import server
from unifi_fabric.argument_errors import echoed_input, input_path_component
from unifi_fabric.argument_values import non_finite_problem
from unifi_fabric.config import APIKeyConfig
from unifi_fabric.secret_scrub import scrub
from unifi_fabric.spec_limits import limit_problems

_ALPHABET = string.ascii_letters + string.digits
#: The shortest leaked fragment the invariant forbids.
MIN_FRAGMENT = 6


def _secret(length: int) -> str:
    # Random base62: a 6-character window of it matches no natural text, so any hit is
    # a real fragment of the secret.
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


KEY_SECRET = _secret(640)
BEARER_SECRET = _secret(610)
LONG_SECRETS = (KEY_SECRET, BEARER_SECRET)


def _fragments(value: str) -> frozenset[str]:
    return frozenset(value[i : i + MIN_FRAGMENT] for i in range(len(value) - MIN_FRAGMENT + 1))


_FRAGMENTS = _fragments(KEY_SECRET) | _fragments(BEARER_SECRET)


def fragment_leaks(text: str) -> list[str]:
    """Every run of >= MIN_FRAGMENT characters of a long secret found in ``text``."""
    return sorted(
        {
            text[i : i + MIN_FRAGMENT]
            for i in range(len(text) - MIN_FRAGMENT + 1)
            if text[i : i + MIN_FRAGMENT] in _FRAGMENTS
        }
    )


TOOLS = LazyCatalog()


def _json_types(schema: dict[str, Any]) -> set[str]:
    """The JSON types a parameter schema admits (empty: unconstrained)."""
    types: set[str] = set()
    declared = schema.get("type")
    types.update(declared if isinstance(declared, list) else [declared] if declared else [])
    for alt in (schema.get("anyOf") or []) + (schema.get("oneOf") or []):
        if isinstance(alt, dict):
            types |= _json_types(alt)
    return types


def _variants(name: str, secret: str) -> list[tuple[str, dict[str, Any]]]:
    """Every echoable position of ``secret`` in a call to tool ``name``.

    Every parameter gets the secret as its value (any type: a wrong-typed value is an
    echo position too); a parameter that admits a list also gets it as a list item, and
    one that admits an object (or is unconstrained) gets it as a dict key, with a plain
    and with a non-finite value (the argument-path echoes).
    """
    base = tool_args.generated_args(TOOLS[name])
    props = (TOOLS[name].parameters or {}).get("properties") or {}
    out: list[tuple[str, dict[str, Any]]] = [("unknown parameter name", {**base, secret: 1})]
    for prop, schema in props.items():
        types = _json_types(schema if isinstance(schema, dict) else {})
        out.append((f"{prop}=secret", {**base, prop: secret}))
        if not types or "array" in types:
            out.append((f"{prop}=[secret]", {**base, prop: [secret]}))
        if not types or "object" in types:
            out += [
                (f"{prop}={{secret: secret}}", {**base, prop: {secret: secret}}),
                (f"{prop}={{secret: NaN}}", {**base, prop: {secret: float("nan")}}),
            ]
    return out


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.lines: list[str] = []
        self.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


@pytest.fixture
def captured_logs():
    handler = _Capture()
    root = logging.getLogger()
    previous = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)


def _error_texts(exc: BaseException) -> str:
    return "\n".join([str(exc), repr(exc), "".join(traceback.format_exception(exc))])


# Every tool still runs; one-tool batches bound peak memory for each xdist work item.
# The argument variants for this invariant are especially allocation-heavy, so keep all
# of its tool items on one xdist worker while retaining the full four-worker suite.
@pytest.mark.xdist_group("secret-argument-echo")
@tool_batches("name", lambda: sorted(TOOLS), max_batch=1)
async def test_secret_in_any_argument_position_never_echoed(monkeypatch, captured_logs, name):
    for k, v in tool_args.TOOL_ENV.get(name, {}).items():
        monkeypatch.setenv(k, v)
    client = uh.install(
        monkeypatch, uh.FakeUpstream(), keys=[APIKeyConfig(key=KEY_SECRET, label="site")]
    )
    try:
        failures: list[str] = []
        errors = 0
        for where, args in _variants(name, KEY_SECRET):
            captured_logs.lines.clear()
            try:
                await server.mcp.call_tool(name, args)
            except ToolError as exc:
                errors += 1
                found = fragment_leaks(_error_texts(exc))
                if found:
                    failures.append(f"{where}: error carries {found[:3]}")
            found = fragment_leaks("\n".join(captured_logs.lines))
            if found:
                failures.append(f"{where}: logs carry {found[:3]}")
        assert errors, f"{name}: no variant produced an error; the sweep proved nothing"
        assert failures == [], f"{name}: secret fragments leaked:\n" + "\n".join(failures)
    finally:
        await client.close()


# ----------------------------------------------------------- the echo helpers themselves
@pytest.mark.parametrize(
    "value",
    [
        "x" * 10_000,
        ["a"] * 50,
        {f"k{i}": i for i in range(50)},
        [[[[["deep"]]]]],
        10**5000,
        [1, {"n": -(10**5000)}],
    ],
    ids=["long-str", "long-list", "big-dict", "deep", "huge-int", "nested-huge-int"],
)
def test_echoed_input_is_whole(value):
    """No length, item or depth bound and no abbreviation marker (no truncation)."""
    text = echoed_input(value)
    assert "..." not in text
    assert "truncated" not in text
    if isinstance(value, str):
        assert text == repr(value)
    if value == 10**5000:
        assert text == "1" + "0" * 5000


def test_input_path_component_is_verbatim():
    key = "k" * 10_000
    assert input_path_component(key) == key


@pytest.mark.parametrize("secret", LONG_SECRETS, ids=["key", "bearer"])
def test_helper_echoes_scrub_whole(secret):
    """Each echo helper's message, once scrubbed, carries no fragment of the secret."""
    messages = [
        non_finite_problem({secret: float("nan")}, "body"),
        non_finite_problem(float("inf"), secret),
        *limit_problems(secret, {"enum": ["a", "b"]}, "'mode'"),
        *limit_problems(secret, {"pattern": "^[0-9]+$"}, "'id'"),
        *limit_problems({secret: -1}, {"properties": {secret: {"minimum": 0}}}, "body"),
    ]
    for message in messages:
        assert message
        assert fragment_leaks(scrub(message, LONG_SECRETS)) == [], message
        assert secret in message  # echoed whole before scrubbing, never cut
    assert json.dumps(messages)  # all plain text
