"""SECRET-LEAK INVARIANT: no configured secret appears in any error text or log line.

Every secret-bearing setting -- ``UNIFI_API_KEY``, each ``key`` of ``UNIFI_API_KEYS``,
``MCP_BEARER_TOKEN`` and ``MCP_TLS_KEY_PASSWORD`` -- gets a sentinel value. The
configured sentinels are valid credentials built from the characters escaping and
URL-encoding change (backslash, quotes, ``/``, ``+``, ``=``, ``%``, ``&``; a space and a
non-ASCII letter in the TLS password). Values the configuration rejects (a newline, a
NUL, a tab, trailing spaces, non-ASCII in a key) are used two ways: the rejection must
never echo them, and a key built in code bypassing validation drives the real httpx
``Illegal header value b'...'`` error. Error paths are then driven across every
registered tool and the configuration:

* transport errors (a real h11 illegal-header failure, and a fake transport error
  quoting the request's key header in raw, repr and bytes-repr form),
* a real HTTP-transport server process: every uvicorn access line and log record,
* upstream 4xx/5xx bodies echoing every secret (raw, JSON-escaped, repr, base64),
* an upstream that echoes the key back for every key (multi-key fan-out errors),
* tool-argument validation errors carrying a secret,
* settings validation and startup errors (in-process and a real process start),
* the audit log and every log record,
* the placement-snapshot CLI.

Successful data is the other half of the invariant: a 2xx body holding a
credential-named field is returned BYTE-IDENTICAL by default, except that echoes of
the server's own configured secrets are scrubbed in every status -- while that call's
logs and audit lines stay clean. The
scrubber matches whole tokens of every configured secret, whatever its length,
where a complete escape sequence (``%20``, ``\\n``, ``\\x0a``, ``\\u00e9`` ...) directly
before or after a secret counts as a boundary (every upstream error body echoes
each secret after and before every escape form, so every tool's errors, logs and audit
lines are checked with them). Every pathological alphabet is exercised at 1 MB,
and deterministic Python work counts grow linearly from 8 KB to 32 KB.

No sentinel may appear in any form the scrubber claims: raw, repr/escaped,
JSON-escaped, URL-encoded (every variant), base64 (alone or embedded after a prefix, as
in ``Basic base64(user:secret)``), hexadecimal or UTF-16. Each sentinel starts with one
per-run random marker -- lowercase hex, which every escaping and URL-encoding leaves
intact and which no checkout path can contain -- so any escaping of a sentinel is caught
by an exact marker search; the base64, hex and UTF-16 forms of the marker are searched
explicitly.
"""

from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import json
import logging
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import traceback
import urllib.error
import urllib.request
import weakref
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, quote_plus

import httpx
import pytest
from fastmcp.exceptions import ToolError
from pydantic import ValidationError
from pydantic_settings import SettingsError

from tests import cpu_scaling, scrub_oracle, tool_args
from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from tests._tool_catalog import LazyCatalog
from tests._tool_classes import class_axis, tool_batches
from unifi_fabric import placement_snapshot_cli, secret_scrub, server
from unifi_fabric.audit import AuditSink
from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, MCPTransportSettings, Settings
from unifi_fabric.secret_scrub import contains_secret, scrub, scrub_bytes

# ----------------------------------------------------------------------------- sentinels
# A fresh 128-bit marker per run: a fixed word also matched any checkout path that
# contained it, failing the suite on a path rather than a leak.
MARKER = "m" + secrets.token_hex(16)
# Configured (valid) sentinels: each holds characters that repr/JSON escaping or
# URL-encoding change, so every escaped and encoded form is exercised.
KEY_ALPHA = f'{MARKER}-alpha-key\\"/+=-3c4d'  # backslash, double quote, slash, plus, equals
KEY_BETA = f"{MARKER}-beta-key'%&?-5e6f"  # single quote, percent, ampersand, question mark
KEY_SINGLE = f"{MARKER}-single-key-1a2b"
BEARER = f"{MARKER}-bearer/+=-7a8b"
TLS_PASSWORD = f"{MARKER}-tls pw \u00e9/+-9c0d"  # a password may hold spaces and non-ASCII

# Values the configuration rejects (each must be refused without being echoed). The
# key ones also drive the real httpx illegal-header error through a key built in code.
BAD_KEY_NEWLINE = f"{MARKER}-bad-key\n-3c4d"
BAD_KEY_NUL = f"{MARKER}-bad-key\x00-5e6f"  # constructor only: os.environ cannot hold NUL
BAD_KEY_TRAILING = f"{MARKER}-bad-key-trailing  "
BAD_KEY_TAB = f"{MARKER}-bad\tkey-7a8b"
BAD_KEY_NON_ASCII = f"{MARKER}-bad-key-\u00e9-9c0d"
TLS_PASSWORD_NUL = f"{MARKER}-tls-pw-nul\x00-0e1f"  # NUL (constructor only: env has none)
TLS_PASSWORD_NEWLINE = f"{MARKER}-tls-pw\n-9c0d"

BAD_KEYS = (BAD_KEY_NEWLINE, BAD_KEY_NUL, BAD_KEY_TRAILING, BAD_KEY_TAB, BAD_KEY_NON_ASCII)
ALL_SENTINELS = (
    KEY_ALPHA,
    KEY_BETA,
    KEY_SINGLE,
    BEARER,
    TLS_PASSWORD,
    *BAD_KEYS,
    TLS_PASSWORD_NUL,
    TLS_PASSWORD_NEWLINE,
)
#: The secrets configured while tools run (keys in settings, the rest in the environment).
CONFIGURED = (KEY_ALPHA, KEY_BETA, KEY_SINGLE, BEARER, TLS_PASSWORD)

_KEYS = [
    APIKeyConfig(key=KEY_ALPHA, label="alpha"),
    APIKeyConfig(key=KEY_BETA, label="beta", is_org_key=True),
]


def _b64_forms(value: str) -> set[str]:
    out: set[str] = set()
    for base in {value, value.strip()}:
        raw = base.encode()
        for enc in (base64.b64encode(raw), base64.urlsafe_b64encode(raw)):
            text = enc.decode()
            out |= {text, text.rstrip("=")}
    return out


def _embedded_b64_markers(marker: bytes) -> set[str]:
    """The base64 characters of ``marker`` after a prefix of each length mod 3, that do
    not depend on the prefix (what ``base64(b"user:" + secret)`` always contains)."""
    out: set[str] = set()
    for shift, prefix in enumerate((b"", b"u", b"us")):
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            text = enc(prefix + marker).decode()
            out.add(text[-(-8 * shift // 6) : (8 * (shift + len(marker))) // 6])
    return out


# The marker's leading 24 characters encode to 32 base64 characters with no padding,
# so every base64 encoding of a sentinel starts with this prefix; embedded after a
# prefix of any length, the prefix-independent characters of it are searched too.
_MARKER_HEAD = MARKER[:24]
_MARKER_B64 = {
    base64.b64encode(_MARKER_HEAD.encode()).decode(),
    base64.urlsafe_b64encode(_MARKER_HEAD.encode()).decode(),
}
_B64 = (
    {form for s in ALL_SENTINELS for form in _b64_forms(s)}
    | _MARKER_B64
    | _embedded_b64_markers(_MARKER_HEAD.encode())
)
#: Markers searched in ``text.lower()``: hex and UTF-16 (text and hex) of the marker.
_LOWER_MARKERS = {
    _MARKER_HEAD.encode().hex(),
    _MARKER_HEAD.encode("utf-16-le").hex(),
    _MARKER_HEAD.encode("utf-16-be").hex(),
    _MARKER_HEAD.encode("utf-16-le").decode("latin-1"),
    _MARKER_HEAD.encode("utf-16-be").decode("latin-1"),
}


def leaks(text: str) -> list[str]:
    """Every sentinel form found in ``text`` (empty when clean)."""
    found = []
    lower = text.lower()
    if MARKER in lower:
        idx = lower.index(MARKER)
        found.append(f"marker at {idx}: {text[max(0, idx - 40) : idx + 60]!r}")
    found.extend(f"base64 {form!r}" for form in _B64 if form in text)
    found.extend(f"hex/utf-16 {form!r}" for form in _LOWER_MARKERS if form in lower)
    return found


def _texts(obj: Any) -> str:
    """Every rendering of a result payload a client could see."""
    return json.dumps(obj, default=str) + json.dumps(obj, default=str, ensure_ascii=False)


def _exc_texts(exc: BaseException) -> str:
    parts = [str(exc), repr(exc), "".join(traceback.format_exception(exc))]
    if isinstance(exc, ValidationError):
        parts.append(json.dumps(exc.errors(include_input=False), default=str))
        parts.append(exc.json(include_input=False))
    return "\n".join(parts)


#: Every escape form a message can put directly before or after a secret --
#: percent-encoding (both cases, and %uXXXX), C / Python / JSON escapes (single letter,
#: \xNN, \uNNNN, \UNNNNNNNN, octal, an escaped backslash or quote) and HTML entities.
ESCAPE_FORMS = (
    "%20",
    "%0A",
    "%0a",
    "%2F",
    "%u00e9",
    "\\n",
    "\\t",
    "\\r",
    "\\\\",
    '\\"',
    "\\x0a",
    "\\u00e9",
    "\\U0001f600",
    "\\012",
    "&#10;",
    "&amp;",
    "%" + "25" * 64 + "20",
    "%" + "25" * 64 + "5Cn",
    "%" + "25" * 64 + "5Cu00e9",
)


def escaped_echoes(secret: str, forms: tuple[str, ...] = ESCAPE_FORMS) -> list[str]:
    """``secret`` placed after and before every escape form (both sides at once too)."""
    out: list[str] = []
    for esc in forms:
        out += [f"{esc}{secret}", f"{secret}{esc}", f"x{esc}{secret}{esc}y"]
    return out


def _echo_body(status: int, forms: tuple[str, ...] = ESCAPE_FORMS) -> str:
    """An upstream error body echoing every sentinel in every common form, and after and
    before every escape form."""
    return json.dumps(
        {
            "statusCode": status,
            "message": f"invalid credential {KEY_ALPHA}",
            "echo": {
                "X-API-KEY": [KEY_ALPHA, KEY_BETA, KEY_SINGLE],
                "authorization": f"Bearer {BEARER}",
                "tls": TLS_PASSWORD,
            },
            "reprs": [repr(s) for s in CONFIGURED],
            "bytes": [repr(s.encode()) for s in CONFIGURED],
            "b64": [base64.b64encode(s.encode()).decode() for s in CONFIGURED],
            "escaped": [form for s in CONFIGURED for form in escaped_echoes(s, forms)],
            "escapedPlain": " ".join(form for s in CONFIGURED for form in escaped_echoes(s, forms)),
        }
    )


#: The escape forms of ESCAPE_FORMS inside the D = 8 bound (all but the 64-deep chains).
SHALLOW_ESCAPE_FORMS = tuple(form for form in ESCAPE_FORMS if len(form) <= 64)


def _closed_echo_body(status: int) -> str:
    """:func:`_echo_body` without the 64-deep ``%25`` chains: every region of it reaches
    its full closure (no G5 bound), so scrubbing it is decoding only (R-433 M-2)."""
    return _echo_body(status, SHALLOW_ESCAPE_FORMS)


def _simple_echo_body(status: int) -> str:
    """The tools share client paths; keep one escape per family on both sides."""
    escapes = ("%20", "%u00e9", "\\n", "\\x0a", "\\u00e9", "\\U0001f600", "\\012", "&amp;", "&#10;")
    return json.dumps(
        {
            "statusCode": status,
            "raw": list(CONFIGURED),
            "repr": [repr(s) for s in CONFIGURED],
            "bytes": [repr(s.encode()) for s in CONFIGURED],
            "base64": [base64.b64encode(s.encode()).decode() for s in CONFIGURED],
            "escaped": [f"{esc}{s}{esc}" for s in CONFIGURED for esc in escapes],
        }
    )


class _EchoingTransportError(uh.FakeUpstream):
    """Every request fails at the transport, quoting the request's key header."""

    def __call__(self, req: httpx.Request) -> httpx.Response:
        raw = dict(req.headers.raw).get(b"x-api-key", b"")
        self._record(req, 0, None, uh.is_resolution(req.url.path))
        raise httpx.LocalProtocolError(
            f"Illegal header value {raw!r} ({raw.decode(errors='replace')}; "
            f"{base64.b64encode(raw).decode()})"
        )


TOOLS = LazyCatalog()


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


@pytest.fixture
def secret_env(monkeypatch):
    """Sentinels in the environment for the secrets the transport settings hold."""
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("MCP_BEARER_TOKEN", BEARER)
    monkeypatch.setenv("MCP_TLS_KEY_PASSWORD", TLS_PASSWORD)
    monkeypatch.setenv("UNIFI_API_KEY", KEY_SINGLE)
    monkeypatch.setattr(server, "_mcp_transport", MCPTransportSettings())


async def _drive(monkeypatch, name: str, up: uh.FakeUpstream, args: dict | None = None) -> str:
    for k, v in tool_args.TOOL_ENV.get(name, {}).items():
        monkeypatch.setenv(k, v)
    client = uh.install(monkeypatch, up, keys=_KEYS)
    try:
        call_args = tool_args.generated_args(TOOLS[name]) if args is None else args
        try:
            res = await server.mcp.call_tool(name, call_args)
        except ToolError as exc:
            return _exc_texts(exc)
        return _texts(uh.result_payload(res))
    finally:
        await client.close()


@pytest.mark.parametrize("outcome", ["success", "tool_error", "unexpected"])
async def test_drive_closes_installed_clients_on_every_exit(monkeypatch, outcome):
    """Every per-tool harness client releases its transports, including failures."""
    closed = []

    class Client:
        async def close(self):
            closed.append(True)

    async def call_tool(*args, **kwargs):
        if outcome == "tool_error":
            raise ToolError("synthetic tool failure")
        if outcome == "unexpected":
            raise RuntimeError("synthetic dispatch failure")
        return {"data": []}

    monkeypatch.setattr(uh, "install", lambda *args, **kwargs: Client())
    monkeypatch.setattr(server.mcp, "call_tool", call_tool)
    monkeypatch.setattr(uh, "result_payload", lambda result: result)
    if outcome == "unexpected":
        with pytest.raises(RuntimeError, match="synthetic dispatch failure"):
            await _drive(monkeypatch, "list_devices", uh.FakeUpstream(), args={})
    else:
        await _drive(monkeypatch, "list_devices", uh.FakeUpstream(), args={})
    assert closed == [True]


def _assert_clean(where: str, text: str) -> None:
    found = leaks(text)
    assert found == [], f"{where}: secret leaked: {found}"


# ============================================================ tools: every error path
_MODES = ("http_403", "http_500", "transport", "echoing_keys")


def _upstream(mode: str) -> uh.FakeUpstream:
    if mode.startswith("http_"):
        status = int(mode.removeprefix("http_"))
        return uh.FakeUpstream(
            mode="error",
            error_status=status,
            error_body=_simple_echo_body(status),
            error_resolution=True,
        )
    if mode == "transport":
        return _EchoingTransportError()
    # every key's every request answers 403 with the key echoed in the body
    return uh.FakeUpstream(failing_keys=frozenset({KEY_ALPHA, KEY_BETA}))


# Keep collection bounded on every xdist worker without dropping tool/mode cases.
# _run_each gives each tool fresh monkeypatch/server/temp state and clears both
# formatted captured_logs and pytest's raw caplog records before the next tool.
# _drive closes the installed client's transports even when dispatch fails.
_SECRET_ERROR_BATCH = 16


@class_axis("name", lambda: sorted(TOOLS), max_batch=_SECRET_ERROR_BATCH, mode=lambda: _MODES)
async def test_no_secret_in_any_tool_error(
    monkeypatch, tmp_path, secret_env, captured_logs, caplog, name, mode
):
    await _no_secret_in_any_tool_error(monkeypatch, tmp_path, captured_logs, name, mode)


async def test_secret_error_batch_resets_captured_records_and_server_state(
    monkeypatch, tmp_path, secret_env, captured_logs, caplog
):
    """Batching retains independent per-tool log assertions, temp paths and globals."""
    from tests._tool_classes import ToolBatch

    baseline = server._client
    visited = []

    async def probe(mp, path, logs, name, mode):
        assert logs.lines == []
        assert caplog.records == []
        assert server._client is baseline
        visited.append((name, path))
        logging.getLogger("unifi_fabric.test.batch_reset").warning("tool %s", name)
        mp.setattr(server, "_client", object())

    monkeypatch.setattr(sys.modules[__name__], "_no_secret_in_any_tool_error", probe)
    await test_no_secret_in_any_tool_error(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        secret_env=secret_env,
        captured_logs=captured_logs,
        caplog=caplog,
        name=ToolBatch("reset-proof", ("list_devices", "get_host")),
        mode="http_403",
    )
    assert [name for name, _ in visited] == ["list_devices", "get_host"]
    assert len({path for _, path in visited}) == 2
    assert server._client is baseline


def test_secret_error_items_partition_every_tool_mode_once():
    """Both surfaces partition the complete tool/mode product into bounded items."""
    code = """
import json
import pytest

class Partition:
    def pytest_collection_finish(self, session):
        rows = []
        for item in session.items:
            params = item.callspec.params
            batch = params["name"]
            rows.append({"nodeid": item.nodeid, "surface": item.path.name,
                         "tools": list(batch.names), "mode": params["mode"]})
        print("SECRET_PARTITION_JSON=" + json.dumps(rows))

raise SystemExit(pytest.main([
    "--collect-only", "-q", "-n", "0", "-o", "addopts=",
    "tests/test_secret_leak_invariant.py::test_no_secret_in_any_tool_error",
    "tests/test_discovery_properties.py::test_secret_leak_invariant__no_secret_in_any_tool_error",
], plugins=[Partition()]))
"""
    collected = subprocess.run(  # noqa: S603 - fixed interpreter and local collection plugin
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
    )
    reports = [
        line.removeprefix("SECRET_PARTITION_JSON=")
        for line in collected.stdout.splitlines()
        if line.startswith("SECRET_PARTITION_JSON=")
    ]
    assert len(reports) == 1, collected.stdout + collected.stderr
    rows = json.loads(reports[0])
    assert all(1 <= len(row["tools"]) <= _SECRET_ERROR_BATCH for row in rows)
    assert len({row["nodeid"] for row in rows}) == len(rows)
    surfaces = {"test_secret_leak_invariant.py", "test_discovery_properties.py"}
    assert {row["surface"] for row in rows} == surfaces
    actual = [(row["surface"], row["mode"], name) for row in rows for name in row["tools"]]
    expected = [
        (surface, mode, name) for surface in surfaces for mode in _MODES for name in sorted(TOOLS)
    ]
    assert sorted(actual) == sorted(expected)
    assert len(rows) < len(expected)


@pytest.mark.parametrize(("name", "mode"), [("adopt_device", "http_403")])
async def test_no_secret_in_any_tool_error_one_item(
    monkeypatch, tmp_path, secret_env, captured_logs, name, mode
):
    """A direct regression for the historical adopt-device secret-echo case."""
    await _no_secret_in_any_tool_error(monkeypatch, tmp_path, captured_logs, name, mode)


async def _no_secret_in_any_tool_error(monkeypatch, tmp_path, captured_logs, name, mode):
    audit = tmp_path / "audit.log"
    monkeypatch.setenv("UNIFI_AUDIT_LOG", str(audit))
    text = await _drive(monkeypatch, name, _upstream(mode))
    _assert_clean(f"{name} [{mode}] tool output", text)
    _assert_clean(f"{name} [{mode}] logs", "\n".join(captured_logs.lines))
    if audit.exists():
        _assert_clean(f"{name} [{mode}] audit log", audit.read_text())


@functools.cache
def _lz__HOST_TOOLS():
    return sorted(
        n for n, t in TOOLS.items() if "host" in (t.parameters or {}).get("properties", {})
    )


@tool_batches("name", lambda: _lz__HOST_TOOLS())
async def test_no_secret_in_argument_errors(monkeypatch, secret_env, name):
    """A secret passed as an argument (a pasted key) is never echoed in the error."""
    args = {**tool_args.generated_args(TOOLS[name]), "host": KEY_ALPHA}
    text = await _drive(monkeypatch, name, uh.FakeUpstream(), args=args)
    _assert_clean(f"{name} host=<secret>", text)


# ============================================================ 2xx: own secrets scrubbed
#: A 2xx record field echoing configured secrets (raw, and base64 as a Basic credential).
_ECHO_OVERLAY = {
    "rotatedKey": f"rotated to {KEY_ALPHA}",
    "basicAuth": "Basic " + base64.b64encode(b"user:" + KEY_BETA.encode()).decode(),
}


@tool_batches("name", lambda: cti.READ_TOOLS)
async def test_2xx_body_with_own_secrets_is_scrubbed(
    monkeypatch, tmp_path, secret_env, captured_logs, name
):
    audit = tmp_path / "audit.log"
    monkeypatch.setenv("UNIFI_AUDIT_LOG", str(audit))
    up = uh.FakeUpstream(overlay=dict(_ECHO_OVERLAY), replay_recordings=False)
    for k, v in tool_args.TOOL_ENV.get(name, {}).items():
        monkeypatch.setenv(k, v)
    uh.install(monkeypatch, up, keys=_KEYS)
    res = await server.mcp.call_tool(name, tool_args.generated_args(TOOLS[name]))
    payload = uh.result_payload(res)
    if name in cti.NO_UPSTREAM:
        # Local configuration reports have no upstream body to echo, but their
        # own key metadata, logs and audit output must still be secret-safe.
        assert not up.served, f"{name} unexpectedly contacted upstream"
    elif name in cti.DERIVED:
        # Computed views can discard the injected fields. Exercise the real
        # projection/rollup and check its output instead of skipping the tool.
        assert any(200 <= response.status < 300 for response in up.served), name
    _assert_clean(f"{name} 2xx output", _texts(payload))
    _assert_clean(f"{name} logs", "\n".join(captured_logs.lines))
    if audit.exists():
        _assert_clean(f"{name} audit log", audit.read_text())


async def test_2xx_own_secret_echo_is_scrubbed(monkeypatch, secret_env):
    """The sweep is not vacuous: echoed fields remain, with own secrets scrubbed."""
    up = uh.FakeUpstream(overlay=dict(_ECHO_OVERLAY), replay_recordings=False)
    uh.install(monkeypatch, up, keys=_KEYS)
    res = await server.mcp.call_tool(
        "list_devices", tool_args.generated_args(TOOLS["list_devices"])
    )
    leaves = set(_leaves(uh.result_payload(res)))
    assert {scrub(v, CONFIGURED) for v in _ECHO_OVERLAY.values()} <= leaves
    _assert_clean("2xx echo", _texts(uh.result_payload(res)))


def _leaves(obj: Any) -> list[str]:
    """Every string leaf of a result payload (keys and values)."""
    out: list[str] = []
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            out.append(node)
        elif isinstance(node, dict):
            stack.extend(node.keys())
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return out


# ============================================================ client: real transport
def _unvalidated_settings(base_url: str, key: str) -> Settings:
    """Settings holding a key the configuration would reject (built in code, bypassing
    validation): the client and the scrubber must still never expose it."""
    return Settings.model_construct(
        api_base_url=base_url,
        api_keys=[APIKeyConfig.model_construct(key=key, label="default", is_org_key=False)],
    )


# Stable ids: the values carry the per-run marker, and xdist workers must collect
# identical test ids.
@pytest.mark.parametrize(
    "key",
    [BAD_KEY_NEWLINE, BAD_KEY_NUL, BAD_KEY_TRAILING],
    ids=["newline", "nul", "trailing-spaces"],
)
async def test_real_illegal_header_error_is_scrubbed(key, captured_logs):
    """httpx/h11 quote an illegal header value (b'KEY\\n') in their error message."""
    srv = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    client = UniFiClient(_unvalidated_settings(f"http://127.0.0.1:{port}", key))
    try:
        for method in ("GET", "POST", "DELETE"):
            with pytest.raises(UniFiConnectionError) as exc:
                await client.request(method, "/v1/hosts")
            assert "Illegal header value" in str(exc.value)
            _assert_clean(f"{method} transport error", _exc_texts(exc.value))
            logging.getLogger("unifi_fabric.test").error("failed: %s", exc.value, exc_info=True)
    finally:
        await client.close()
        srv.close()
    _assert_clean("transport error log", "\n".join(captured_logs.lines))


async def test_relayed_error_body_is_scrubbed(monkeypatch):
    """An error body returned for the caller to inspect is scrubbed too."""
    up = uh.FakeUpstream(failing_keys=frozenset({KEY_ALPHA}))
    client = uh.install(monkeypatch, up, keys=_KEYS)
    resp = await client.request("GET", "/v1/hosts", key=_KEYS[0], raise_on_error=False)
    assert resp.status_code == 403 and "lacks scope" in resp.text
    _assert_clean("relayed body", resp.text)


async def test_redirect_and_rate_limit_errors_are_scrubbed(monkeypatch, secret_env):
    # A Location header carrying each secret after (and before) an escape.
    location = "/login?next=" + "&".join(
        f"k{i}=%20{quote(s, safe='')}%0A" for i, s in enumerate(CONFIGURED)
    )

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/redirect":
            return httpx.Response(302, headers={"Location": location}, text=_echo_body(302))
        return httpx.Response(429, text=_echo_body(429))

    client = UniFiClient(Settings(api_keys=_KEYS))

    async def _get_client(self, key_config):
        return httpx.AsyncClient(
            base_url="https://api.ui.com",
            headers={"X-API-KEY": "redacted-for-transport"},
            transport=httpx.MockTransport(handler),
        )

    monkeypatch.setattr(UniFiClient, "_get_client", _get_client)
    monkeypatch.setattr(asyncio, "sleep", uh._no_sleep)
    for path in ("/redirect", "/limited"):
        with pytest.raises(Exception) as exc:
            await client.request("GET", path)
        assert "HTTP" in str(exc.value)
        _assert_clean(path, _exc_texts(exc.value))


# ============================================================ config + startup
def _keys_env(*entries: dict) -> str:
    return json.dumps(list(entries))


_SETTINGS_CASES = {
    "duplicate labels": {
        "UNIFI_API_KEYS": _keys_env(
            {"key": KEY_ALPHA, "label": "a"}, {"key": KEY_BETA, "label": "a"}
        )
    },
    "bad is_org_key": {"UNIFI_API_KEYS": _keys_env({"key": KEY_ALPHA, "is_org_key": KEY_ALPHA})},
    "non-string label": {"UNIFI_API_KEYS": _keys_env({"key": KEY_BETA, "label": 5})},
    "non-string key": {"UNIFI_API_KEYS": _keys_env({"key": 5, "label": KEY_ALPHA})},
    "entry not an object": {"UNIFI_API_KEYS": json.dumps([KEY_ALPHA])},
    "object not a list": {"UNIFI_API_KEYS": json.dumps({"key": KEY_BETA})},
    "malformed JSON": {"UNIFI_API_KEYS": '[{"key": ' + json.dumps(KEY_ALPHA) + ", oops"},
    "bad bound with key set": {"UNIFI_API_KEY": KEY_SINGLE, "UNIFI_MAX_CONCURRENCY": "0"},
    "bad bool with key set": {"UNIFI_API_KEY": KEY_SINGLE, "UNIFI_REDACT_SECRETS": "maybe"},
    "bad write policy with key set": {"UNIFI_API_KEY": KEY_SINGLE, "UNIFI_WRITE_POLICY": KEY_ALPHA},
    "bad log level with key set": {"UNIFI_API_KEY": KEY_SINGLE, "UNIFI_LOG_LEVEL": "LOUD"},
    "bad audit format": {"UNIFI_API_KEY": KEY_SINGLE, "UNIFI_AUDIT_LOG_FORMAT": "xml"},
    "bad base url": {"UNIFI_API_KEY": KEY_SINGLE, "UNIFI_API_BASE_URL": f"x{KEY_ALPHA.strip()}"},
    # Credential values the configuration rejects (named, never echoed).
    "key with newline": {"UNIFI_API_KEY": BAD_KEY_NEWLINE},
    "key with trailing spaces": {"UNIFI_API_KEY": BAD_KEY_TRAILING},
    "key with tab": {"UNIFI_API_KEY": BAD_KEY_TAB},
    "key non-ASCII": {"UNIFI_API_KEY": BAD_KEY_NON_ASCII},
    "keys entry with NUL": {"UNIFI_API_KEYS": _keys_env({"key": BAD_KEY_NUL, "label": "a"})},
    "keys entry non-ASCII": {"UNIFI_API_KEYS": _keys_env({"key": BAD_KEY_NON_ASCII})},
    "keys entry trailing": {"UNIFI_API_KEYS": _keys_env({"key": BAD_KEY_TRAILING})},
    "keys entry empty label": {"UNIFI_API_KEYS": _keys_env({"key": KEY_ALPHA, "label": ""})},
    "same key two labels": {
        "UNIFI_API_KEYS": _keys_env(
            {"key": KEY_ALPHA, "label": "a"}, {"key": KEY_ALPHA, "label": "b"}
        )
    },
}


@pytest.mark.parametrize("case", sorted(_SETTINGS_CASES))
def test_settings_errors_never_echo_secrets(monkeypatch, captured_logs, case):
    for k, v in _SETTINGS_CASES[case].items():
        monkeypatch.setenv(k, v)
    with pytest.raises((ValidationError, SettingsError)) as exc:
        Settings()
    _assert_clean(case, _exc_texts(exc.value))
    logging.getLogger("unifi_fabric.startup").exception("startup failed", exc_info=exc.value)
    _assert_clean(f"{case} logged", "\n".join(captured_logs.lines))


_TRANSPORT_CASES = {
    "bearer on stdio": {"FASTMCP_TRANSPORT": "stdio", "MCP_BEARER_TOKEN": BEARER},
    "tls on stdio": {
        "FASTMCP_TRANSPORT": "stdio",
        "MCP_TLS_MODE": "https",
        "MCP_TLS_CERTFILE": "/c",
        "MCP_TLS_KEYFILE": "/k",
        "MCP_TLS_KEY_PASSWORD": TLS_PASSWORD,
    },
    "https missing cert": {
        "FASTMCP_TRANSPORT": "streamable-http",
        "MCP_TLS_MODE": "https",
        "MCP_TLS_KEY_PASSWORD": TLS_PASSWORD,
        "MCP_BEARER_TOKEN": BEARER,
    },
    "bad auth mode": {
        "FASTMCP_TRANSPORT": "streamable-http",
        "MCP_AUTH_MODE": "bogus",
        "MCP_BEARER_TOKEN": BEARER,
    },
    "oauth incomplete": {
        "FASTMCP_TRANSPORT": "streamable-http",
        "MCP_AUTH_MODE": "oauth",
        "MCP_BEARER_TOKEN": BEARER,
        "MCP_TLS_KEY_PASSWORD": TLS_PASSWORD,
    },
    "bad cache ttl": {"MCP_BEARER_TOKEN": BEARER, "UNIFI_MCP_CACHE_TTL": "-5"},
    "bearer with newline": {
        "FASTMCP_TRANSPORT": "streamable-http",
        "MCP_BEARER_TOKEN": BAD_KEY_NEWLINE,
    },
    "bearer with trailing spaces": {
        "FASTMCP_TRANSPORT": "streamable-http",
        "MCP_BEARER_TOKEN": BAD_KEY_TRAILING,
    },
    "bearer non-ASCII": {
        "FASTMCP_TRANSPORT": "streamable-http",
        "MCP_BEARER_TOKEN": BAD_KEY_NON_ASCII,
    },
    "tls password with newline": {
        "FASTMCP_TRANSPORT": "streamable-http",
        "MCP_TLS_MODE": "https",
        "MCP_TLS_CERTFILE": "/c",
        "MCP_TLS_KEYFILE": "/k",
        "MCP_TLS_KEY_PASSWORD": TLS_PASSWORD_NEWLINE,
    },
}


@pytest.mark.parametrize("case", sorted(_TRANSPORT_CASES))
def test_transport_settings_errors_never_echo_secrets(monkeypatch, case):
    for k, v in _TRANSPORT_CASES[case].items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ValidationError) as exc:
        MCPTransportSettings()
    _assert_clean(case, _exc_texts(exc.value))


def test_transport_settings_nul_password_never_echoed(monkeypatch):
    monkeypatch.setenv("FASTMCP_TRANSPORT", "stdio")
    with pytest.raises(ValidationError) as exc:
        MCPTransportSettings(
            tls_mode="https", tls_certfile="/c", tls_keyfile="/k", tls_key_password=TLS_PASSWORD_NUL
        )
    _assert_clean("nul tls password", _exc_texts(exc.value))


def test_models_repr_and_str_never_show_secrets(monkeypatch, tmp_path):
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    transport = MCPTransportSettings(bearer_token=BEARER, tls_key_password=TLS_PASSWORD)
    settings = Settings(api_key=KEY_SINGLE, api_keys=_KEYS)
    sink = AuditSink(path=str(tmp_path / "a"), secrets=ALL_SENTINELS, fmt="text")
    for obj in (transport, settings, *_KEYS, sink):
        _assert_clean(type(obj).__name__, repr(obj) + str(obj))


def test_server_startup_settings_error_is_clean(monkeypatch, captured_logs):
    monkeypatch.setenv("UNIFI_API_KEY", KEY_SINGLE)
    monkeypatch.setenv("UNIFI_MAX_CONCURRENCY", "0")
    monkeypatch.setattr(server, "_settings", None)
    with pytest.raises(ValidationError) as exc:
        server.get_settings()
    _assert_clean("get_settings", _exc_texts(exc.value))
    logging.getLogger("uvicorn.error").error("lifespan failed", exc_info=exc.value)
    _assert_clean("lifespan log", "\n".join(captured_logs.lines))


def _run(code: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    base = {k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "MCP_"))}
    return subprocess.run(  # noqa: S603 - fixed interpreter and code
        [sys.executable, "-c", code],
        env={**base, **env},
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    ("code", "fails"),
    [
        # Importing validates nothing environment-dependent (A-7): it must succeed.
        ("import unifi_fabric.server", False),
        (
            "import sys; sys.argv = ['unifi-fabric-mcp']; "
            "from unifi_fabric.entrypoint import main; main()",
            True,
        ),
    ],
)
def test_process_startup_error_never_prints_secrets(code, fails):
    """A real process start with an invalid transport config prints no secret: import
    succeeds silently, and the entrypoint reports one scrubbed configuration line."""
    proc = _run(
        code,
        {
            "FASTMCP_TRANSPORT": "stdio",
            "MCP_BEARER_TOKEN": BEARER,
            "MCP_TLS_KEY_PASSWORD": TLS_PASSWORD,
            "MCP_TLS_MODE": "https",
            "UNIFI_API_KEY": KEY_SINGLE,
        },
    )
    if fails:
        assert proc.returncode != 0
        lines = proc.stderr.strip().splitlines()
        assert len(lines) == 1, proc.stderr
        assert lines[0].startswith("unifi-fabric-mcp: invalid configuration: ")
        assert "MCP_TLS_CERTFILE" in lines[0]
        assert "Traceback" not in proc.stderr
    else:
        assert proc.returncode == 0, proc.stderr
    _assert_clean("process stderr", proc.stderr + proc.stdout)


# ============================================================ HTTP transport logging
def _listening_socket() -> socket.socket:
    """A loopback socket bound to an ephemeral port and already listening.

    The child server inherits this socket (``pass_fds``) and serves on it through
    Uvicorn's ``fd`` setting, so the port is never released between selection and the
    server owning it: no other process can take it in between.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    return sock


def _lower_hex(text: str) -> str:
    """Percent-encoding with lower-case hex digits (``%2f``), as some clients send it."""
    return re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), text)


def test_http_transport_access_logs_are_clean_and_unbroken():
    """A real streamable-http server process with configured secrets: requests whose
    path and query carry every secret (URL-encoded as a client would send them) leave
    access lines that format without a logging error, mask each secret, and no secret
    appears anywhere in the process output."""
    listener = _listening_socket()
    port = int(listener.getsockname()[1])
    base = {k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "MCP_", "FASTMCP_"))}
    env = {
        **base,
        "FASTMCP_TRANSPORT": "streamable-http",
        "FASTMCP_HOST": "127.0.0.1",
        "FASTMCP_PORT": str(port),
        "MCP_BEARER_TOKEN": BEARER,
        "MCP_TLS_KEY_PASSWORD": TLS_PASSWORD,
        "UNIFI_API_KEY": KEY_SINGLE,
        "UNIFI_API_KEYS": _keys_env(
            {"key": KEY_ALPHA, "label": "a"}, {"key": KEY_BETA, "label": "b"}
        ),
        "UNIFI_LOG_LEVEL": "DEBUG",
    }
    # Serve on the inherited, already-listening socket (Uvicorn's ``fd`` setting), so
    # the port is never free for another process to take. Signal readiness after
    # Uvicorn has completed startup, so requests never race startup and no
    # elapsed-time polling is needed. Drain stderr to a file while waiting for the
    # handshake: verbose startup logging cannot fill a pipe.
    code = f"""
import sys
import uvicorn
original_init = uvicorn.Config.__init__
def init(self, *args, **kwargs):
    original_init(self, *args, **{{**kwargs, "fd": {listener.fileno()}}})
uvicorn.Config.__init__ = init
original_startup = uvicorn.Server.startup
async def startup(self, *args, **kwargs):
    await original_startup(self, *args, **kwargs)
    if self.started:
        print("TEST_HTTP_READY", flush=True)
uvicorn.Server.startup = startup
sys.argv = ["unifi-fabric-mcp"]
from unifi_fabric.entrypoint import main
main()
"""
    stderr_file = tempfile.TemporaryFile(mode="w+t")
    # The child holds its own copy of the listening socket from the fork onward, so the
    # parent's copy is closed once the child exists; the port stays bound throughout.
    with listener:
        proc = subprocess.Popen(  # noqa: S603 - fixed interpreter and code
            [sys.executable, "-c", code],
            env=env,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            text=True,
            pass_fds=(listener.fileno(),),
        )
    consumed = []
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            consumed.append(line)
            if line.strip() == "TEST_HTTP_READY":
                break
        else:
            stderr_file.seek(0)
            pytest.fail("HTTP server exited before readiness: " + stderr_file.read())
        paths = [
            "/mcp",
            f"/mcp?token={quote(BEARER, safe='')}",
            f"/mcp?k={quote_plus(KEY_ALPHA)}&b={quote(KEY_BETA, safe='')}",
            f"/x/{quote(KEY_SINGLE)}",
            f"/x/{quote(TLS_PASSWORD)}?p={_lower_hex(quote(TLS_PASSWORD, safe=''))}",
        ]
        for path in paths:
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}{path}", headers={"Authorization": "Bearer wrong"}
            )
            try:
                with urllib.request.urlopen(request) as response:  # noqa: S310 - local test server
                    response.read()
            except urllib.error.HTTPError:
                pass
    finally:
        proc.terminate()
        out, _ = proc.communicate()
        stderr_file.seek(0)
        err = stderr_file.read()
        stderr_file.close()
    output = "".join(consumed) + out + err
    assert "--- Logging error ---" not in output, output[-3000:]
    access = [line for line in output.splitlines() if '"GET ' in line]
    assert len(access) == len(paths), output[-3000:]
    assert sum("***" in line for line in access) == len(paths) - 1, access
    _assert_clean("http transport process output", output)


# ============================================================ audit log
def test_audit_lines_are_scrubbed(tmp_path):
    log = tmp_path / "audit.log"
    for fmt in ("text", "json"):
        sink = AuditSink(path=str(log), fmt=fmt, secrets=(KEY_BETA, TLS_PASSWORD_NUL))
        sink.record(method="POST", path=f"/v1/x/{KEY_BETA}", outcome="success", status=200)
        sink.record(method="PUT", path=f"/v1/{TLS_PASSWORD_NUL}", outcome="http_500", status=500)
    _assert_clean("audit log", log.read_text())


# ============================================================ placement CLI
@pytest.mark.parametrize("command", ["main", "preflight_main"])
def test_cli_config_error_never_prints_secrets(monkeypatch, capsys, command):
    monkeypatch.setenv(
        "UNIFI_API_KEYS",
        _keys_env({"key": KEY_ALPHA, "label": "a"}, {"key": KEY_BETA, "label": "a"}),
    )
    monkeypatch.setenv("MCP_BEARER_TOKEN", BEARER)
    assert getattr(placement_snapshot_cli, command)(["--host", "h"]) == 1
    err = capsys.readouterr().err
    assert "duplicate key labels" in err
    _assert_clean("cli config error", err)


@pytest.mark.parametrize("command", ["main", "preflight_main"])
def test_cli_runtime_error_never_prints_secrets(monkeypatch, capsys, command):
    monkeypatch.setenv(
        "UNIFI_API_KEYS",
        _keys_env({"key": KEY_ALPHA, "label": "a"}, {"key": KEY_BETA, "label": "b"}),
    )
    monkeypatch.setenv("UNIFI_API_KEY", KEY_SINGLE)
    monkeypatch.setenv("MCP_BEARER_TOKEN", BEARER)
    monkeypatch.setenv("MCP_TLS_KEY_PASSWORD", TLS_PASSWORD)

    async def boom(host: str) -> dict:
        raise RuntimeError(_echo_body(500) + repr(KEY_ALPHA.encode()) + KEY_SINGLE.strip())

    monkeypatch.setattr(placement_snapshot_cli, "export_snapshot", boom)
    monkeypatch.setattr(placement_snapshot_cli, "preflight_snapshot_capabilities", boom)
    assert getattr(placement_snapshot_cli, command)(["--host", "h"]) == 1
    err = capsys.readouterr().err
    assert "RuntimeError" in err
    _assert_clean("cli runtime error", err)


def test_cli_malformed_keys_never_prints_secrets(monkeypatch, capsys):
    monkeypatch.setenv("UNIFI_API_KEYS", '[{"key": ' + json.dumps(KEY_ALPHA) + ", oops")
    assert placement_snapshot_cli.main(["--host", "h"]) == 1
    err = capsys.readouterr().err
    assert "UNIFI_API_KEYS is not valid JSON" in err and "a JSON list of" in err
    _assert_clean("cli malformed keys", err)


# ============================================================ the scrubber itself
_SENTINEL_IDS = [
    "key-alpha",
    "key-beta",
    "key-single",
    "bearer",
    "tls-pw",
    "bad-key-newline",
    "bad-key-nul",
    "bad-key-trailing",
    "bad-key-tab",
    "bad-key-non-ascii",
    "tls-pw-nul",
    "tls-pw-newline",
]


@pytest.mark.parametrize("secret", ALL_SENTINELS, ids=_SENTINEL_IDS)
def test_scrubber_masks_every_form(secret):
    raw = secret.encode()
    url = {quote(secret), quote(secret, safe=""), quote_plus(secret), quote_plus(secret, safe="")}
    url |= {_lower_hex(u) for u in url}
    forms = [
        secret,
        secret.strip(),
        repr(secret),
        repr(secret.encode()),
        json.dumps(secret),
        json.dumps(secret, ensure_ascii=False),
        json.dumps(repr(secret)),
        repr(repr(secret.encode())),
        *_b64_forms(secret),
        *sorted(url),
        raw.hex(),
        raw.hex().upper(),
        secret.encode("utf-16-le").decode("latin-1"),
        secret.encode("utf-16-be").decode("latin-1"),
        secret.encode("utf-16-le").hex(),
        secret.encode("utf-16-be").hex().upper(),
        # Bearer and Basic auth headers: base64 alone and after "user:" prefixes.
        "Bearer " + base64.b64encode(raw).decode(),
        "Basic " + base64.b64encode(b"user:" + raw).decode(),
        "Basic " + base64.b64encode(b"x-access-token:" + raw).decode(),
        "Basic " + base64.urlsafe_b64encode(b"ab:" + raw).decode().rstrip("="),
    ]
    for form in forms:
        out = scrub(f"before {form} after", [secret])
        assert leaks(out) == [], f"{form!r} -> {out!r}"
        # A secret's own surrounding whitespace is part of the secret and goes with it.
        assert out.startswith("before") and out.endswith("after")


def test_env_secrets_are_scrubbed_without_settings(monkeypatch):
    audit_hmac_key = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
    for name, value in (
        ("UNIFI_API_KEY", KEY_SINGLE),
        ("UNIFI_AUDIT_HMAC_KEY", audit_hmac_key),
        ("MCP_BEARER_TOKEN", BEARER),
        ("MCP_TLS_KEY_PASSWORD", TLS_PASSWORD),
    ):
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("UNIFI_API_KEYS", _keys_env({"key": KEY_BETA}))
    text = " | ".join(repr(s) for s in (KEY_SINGLE, audit_hmac_key, BEARER, TLS_PASSWORD, KEY_BETA))
    assert leaks(scrub(text)) == []


def test_audit_hmac_key_is_a_configured_secret():
    from unifi_fabric.secret_scrub import configured_secrets

    text = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
    settings = Settings(audit_hmac_key=text)
    assert text in configured_secrets(settings)
    assert scrub(f"key={text}", configured_secrets(settings)) == "key=***"


def test_scrubber_matches_whole_tokens_of_every_secret():
    """Whole tokens (no letter/digit next to the match) for secrets of under 12
    characters, anywhere for longer ones (SCRUBBER-SPEC G3); every configured secret is
    scrubbed whatever its length (1, 6 and 7 characters included)."""
    word = "Abcd1234efg"
    assert scrub(f"key={word}&x", [word]) == "key=***&x"
    assert scrub(f"({word})", [word]) == "(***)"
    assert scrub(f"_{word}_", [word]) == "_***_"
    # inside a longer alphanumeric token a secret of under 12 characters is not the secret
    assert scrub(f"x{word}", [word]) == f"x{word}"
    assert scrub(f"{word}9", [word]) == f"{word}9"
    # SCRUBBER-SPEC G3: a secret of 12 or more characters is matched anywhere
    long_word = word + "h"
    assert scrub(f"x{long_word}", [long_word]) == "x***"
    assert scrub(f"{long_word}9", [long_word]) == "***9"
    # short secrets are scrubbed too: 1, 6 and 7 characters
    assert scrub("the admin1 user and admin1", ["admin1"]) == "the *** user and ***"
    assert scrub("pw 1234567 here", ["1234567"]) == "pw *** here"
    assert scrub("pw 12345678 here", ["12345678"]) == "pw *** here"
    assert scrub("k=Q and Qx and xQ", ["Q"]) == "k=*** and Qx and xQ"
    for short in ("Q", "admin1", "1234567"):
        for text in escaped_echoes(short):
            out = scrub(text, [short])
            assert short not in out, (text, out)
            assert scrub_bytes(text.encode(), [short]).decode() == out
            assert contains_secret(text, [short])


@pytest.mark.parametrize("secret", CONFIGURED, ids=["alpha", "beta", "single", "bearer", "tls"])
def test_scrubber_masks_a_secret_next_to_every_escape(secret, captured_logs):
    """A secret after or before any escape form is masked in text, bytes and
    logs (message, arguments and exception text), and contains_secret sees it."""
    for text in escaped_echoes(secret):
        assert leaks(scrub(text, [secret])) == [], text
        assert leaks(scrub_bytes(text.encode(), [secret]).decode()) == [], text
        assert contains_secret(text, [secret]) and contains_secret(text.encode(), [secret])
    from unifi_fabric.secret_scrub import install_log_scrubber, set_secret_provider

    install_log_scrubber()
    set_secret_provider(lambda: [secret])
    try:
        log = logging.getLogger("unifi_fabric.test.escapes")
        for text in escaped_echoes(secret):
            log.error(text)
            log.error("upstream said %s (%r)", text, text)
            try:
                raise RuntimeError(text)
            except RuntimeError:
                log.exception("failed")
    finally:
        from unifi_fabric.secret_scrub import configured_secrets

        set_secret_provider(configured_secrets)
    _assert_clean("escaped secret logs", "\n".join(captured_logs.lines))


def test_short_secret_never_breaks_a_log_format_string(captured_logs):
    """A one-letter secret ``s`` must not turn ``%s`` into ``%***`` -- the record
    still formats, with the secret masked everywhere else."""
    from unifi_fabric.secret_scrub import (
        configured_secrets,
        install_log_scrubber,
        set_secret_provider,
    )

    install_log_scrubber()
    set_secret_provider(lambda: ["s", "d"])
    try:
        log = logging.getLogger("unifi_fabric.test.format")
        log.error("value %s count %d s d", "s", 3)
        log.error("%(s)s and %(d)s", {"s": "s", "d": "x"})
    finally:
        set_secret_provider(configured_secrets)
    lines = "\n".join(captured_logs.lines)
    assert "value *** count 3 *** ***" in lines
    # Log free text has the strict no-secret policy (scrub_log_text): the secret "d"
    # embedded in the literal word "and" is masked too, never left in the output.
    assert "*** an*** x" in lines
    assert "Logging error" not in lines


def test_conversion_letter_secret_keeps_mapping_format_specifiers(captured_logs):
    """Secrets equal to conversion letters (``s``, ``r``) inside mapping-style
    specifiers (``%(s)s``, ``%(r)r``): the scrubbed template keeps every specifier and
    its mapping keys, still formats with the scrubbed arguments, and no secret reaches
    the output."""
    from unifi_fabric.secret_scrub import (
        configured_secrets,
        install_log_scrubber,
        set_secret_provider,
    )

    records: list[logging.LogRecord] = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    keep = _Keep(level=logging.DEBUG)
    log = logging.getLogger("unifi_fabric.test.mapping")
    log.addHandler(keep)
    install_log_scrubber()
    set_secret_provider(lambda: ["s", "r"])
    try:
        log.error("%(s)s then %(r)r", {"s": "s", "r": "r"})
    finally:
        set_secret_provider(configured_secrets)
        log.removeHandler(keep)
    lines = "\n".join(captured_logs.lines)
    assert "*** then '***'" in lines
    assert "Logging error" not in lines
    (record,) = records
    assert str.__str__(record.msg) == "%(s)s then %(r)r"
    assert set(record.args) == {"s", "r"}
    assert str.__mod__(record.msg, record.args) == "*** then '***'"


def test_unencodable_secret_never_makes_the_scrubber_raise(captured_logs):
    """A configured value holding a lone surrogate never makes scrub(), byte
    scrubbing or a log call raise, and is still masked."""
    from unifi_fabric.secret_scrub import (
        configured_secrets,
        install_log_scrubber,
        set_secret_provider,
    )

    bad = f"{MARKER}-pw-\udc80-tail"
    assert leaks(scrub(f"error: {bad} here", [bad])) == []
    assert scrub_bytes(b"nothing here", [bad]) == b"nothing here"
    assert contains_secret(f"x {bad}", [bad])
    install_log_scrubber()
    set_secret_provider(lambda: [bad])
    try:
        logging.getLogger("unifi_fabric.test.surrogate").error("failed with %s", bad)
    finally:
        set_secret_provider(configured_secrets)
    assert MARKER not in "\n".join(captured_logs.lines)


@pytest.mark.parametrize(
    "env",
    ["UNIFI_API_KEY", "MCP_BEARER_TOKEN", "MCP_TLS_KEY_PASSWORD", "UNIFI_API_KEYS"],
)
def test_unencodable_credential_rejected_at_config_naming_the_variable(monkeypatch, env):
    """A credential that is not encodable as UTF-8 is a malformed value, refused
    at load naming the variable (never echoed)."""
    bad = f"{MARKER}-cred-\udc80"
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    kwargs: dict[str, Any] = {}
    if env == "UNIFI_API_KEYS":
        kwargs["api_keys"] = [{"key": bad, "label": "a"}]
        model: Any = Settings
        name = "UNIFI_API_KEYS entry 0"
    elif env == "UNIFI_API_KEY":
        kwargs["api_key"] = bad
        model, name = Settings, env
    elif env == "MCP_BEARER_TOKEN":
        kwargs["bearer_token"] = bad
        model, name = MCPTransportSettings, env
    else:
        kwargs.update(tls_mode="https", tls_certfile="/c", tls_keyfile="/k", tls_key_password=bad)
        model, name = MCPTransportSettings, env
    with pytest.raises(ValidationError) as exc:
        model(**kwargs)
    text = str(exc.value)
    assert name in text and "UTF-8" in text, text
    _assert_clean(env, _exc_texts(exc.value))


async def test_relayed_error_headers_with_escaped_secrets_are_scrubbed(monkeypatch):
    """A non-2xx response relayed with raise_on_error=False has every header
    (Location included) and its body scrubbed of secrets placed after escapes."""
    echo = " ".join(escaped_echoes(KEY_ALPHA))

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            headers={"Location": f"/x?k=%20{quote(KEY_ALPHA, safe='')}", "X-Echo": quote(echo)},
            text=echo,
        )

    client = UniFiClient(Settings(api_keys=_KEYS))

    async def _get_client(self, key_config):
        return httpx.AsyncClient(
            base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(UniFiClient, "_get_client", _get_client)
    resp = await client.request("GET", "/v1/hosts", raise_on_error=False)
    _assert_clean("relayed headers", json.dumps(dict(resp.headers)))
    _assert_clean("relayed body", resp.text)


# ---- The scrubber runs in linear time whatever an error body holds. The
# embedded-base64 match used to be a regex with an unbounded leading repeat (a 24 KB body
# took 8.6 s and blocked the event loop); it is now substring search plus linear
# expansion. 1 MB of each pathological alphabet, with several configured keys, is
# scrubbed, byte-scrubbed and checked for consistent results. Every run starts with
# the repeat-scrub memo empty, so the complete body is processed. Each case builds
# only its own body: building all of them for every case made each 1 MB case allocate
# the whole set again, and an xdist worker running the sweep under coverage grew
# toward the runner's memory limit (CI run 41203993296). A separate sweep
# counts executed Python lines on 8 KB and 32 KB: they must grow under 6x. Structural
# ReDoS lint covers regex backtracking shapes without elapsed-time measurements.
_PERF_KEYS = (
    *ALL_SENTINELS,
    secrets.token_urlsafe(32),
    secrets.token_hex(20),
    base64.b64encode(secrets.token_bytes(30)).decode(),
)


_PERF_SIZE = 1_000_000


def _pathological_bodies_reference(size: int = _PERF_SIZE) -> dict[str, str]:
    """Every pathological body at once: the builder the sweeps used before
    ``_pathological_body``, kept unchanged as the oracle that each lazily built body
    is byte-identical to it (``test_pathological_bodies_match_the_reference``)."""
    from unifi_fabric.secret_scrub import _fragments

    noise = base64.b64encode(secrets.token_bytes(size)).decode()[:size]
    fragment = sorted(_fragments(tuple(sorted(set(_PERF_KEYS)))))[0]
    near_key = _PERF_KEYS[-3][:-1]
    hex_key = _PERF_KEYS[-2]  # letters and digits only: the run-skipping path
    return {
        "A-run": "A" * size,
        "dash-run": "-" * size,
        "base64-noise": noise,
        "padding-run": "=" * size,
        "slash-plus": "+/" * (size // 2),
        "fragments-in-one-token": (fragment + "A") * (size // (len(fragment) + 1)),
        "fragments-spaced": (fragment + " ") * (size // (len(fragment) + 1)),
        "key-prefix-repeated": (near_key + "!") * (size // (len(near_key) + 1)),
        "noise-then-fail": noise[: size - 1] + "!",
        # Escape-dense bodies (every position an escape end, or an introducer).
        "percent-escapes": ("%41" * (size // 3)),
        "unicode-escapes": ("\\u0041" * (size // 6)),
        "backslash-run": "\\" * size,
        "percent-run": "%" * size,
        "escapes-then-near-key": ("%20" + near_key) * (size // (len(near_key) + 3)),
        # every candidate has a letter/digit before it (the escape check runs each time)
        "escape-dense-alnum-candidates": ("%41x" + hex_key) * (size // (len(hex_key) + 4)),
        "chained-escape-candidates": ("%2520" + hex_key + "z") * (size // (len(hex_key) + 6)),
        "unbounded-percent-chain": "%" + "25" * (size // 2) + "20" + hex_key,
        "unbounded-backslash-chain": "\\u005c" + "u005c" * (size // 5) + "n" + hex_key,
        "long-chain-failed-candidates": "%" + ("25" + hex_key + "z") * (size // (len(hex_key) + 3)),
        "entity-escape-candidates": ("&#37;20" + hex_key + "z") * (size // (len(hex_key) + 8)),
        "unbounded-entity-chain": "&" + "amp;" * (size // 4) + "#37;20" + hex_key,
        "unbounded-mixed-entity-chain": "%26%2337%3B" + "25" * (size // 2) + "5Cn" + hex_key,
        "entity-leading-zeroes": "&#" + "0" * size + "37;20" + hex_key,
        "entity-invalid-long-numeric": "&#" + "1" * size + "x",
        "entity-invalid-long-hex": "&#x" + "a" * size + "x",
        "entity-malformed-candidates": ("&amp;#x" + hex_key + "z") * (size // (len(hex_key) + 8)),
        "one-run-of-candidates": ("x" + hex_key) * (size // (len(hex_key) + 1)),
        # The decoding model: passes repeat to a fixed point, so these are its worst
        # shapes -- one change per pass (an octal escape waiting on the one after it, in
        # a cascade back to the start), pairing backslashes level by level, introducers
        # that decode to themselves, every character of a key under its own escapes.
        "deferred-octal-run": "\\1" * (size // 2),
        "deferred-octal-percent": "\\1%30" * (size // 5),
        "octal-backslash-chain": "\\134" * (size // 4) + "n" + hex_key,
        "entity-backslash-chain": "&#92;" * (size // 5) + "n" + hex_key,
        "percent-backslash-run": "%5c" * (size // 3),
        "escaped-backslash-pairs": "\\x5c\\x41" * (size // 8),
        "entity-digits-closed-late": "&#" + "0" * size + "%2533" + "7;" + hex_key,
        "key-per-character-depth-6": _nested_key(hex_key) * (size // len(_nested_key(hex_key))),
        "key-per-character-percent-25": ("".join(f"%25{ord(c):02x}" for c in hex_key) + " ")
        * (size // (5 * len(hex_key) + 1)),
        "reported-octal-shape": ("e\\1%301" + hex_key + "! ") * (size // (len(hex_key) + 10)),
        "out-of-range-units": "\\UFFFFFFFF&#99999999;&nosuchname;%u12" * (size // 37),
    }


def _nested_key(key: str) -> str:
    """``key`` with each character six escapes deep (each layer escapes the introducer
    the previous one starts with), then a space."""
    layers = {"%": ("&#37;", "%25", "\\x25"), "&": ("%26", "&amp;", "\\u0026")}
    layers["\\"] = ("%5c", "&#92;", "\\x5c")
    out = []
    for char in key:
        text = f"%{ord(char):02X}"
        for layer in range(5):
            text = layers[text[0]][layer % 3] + text[1:]
        out.append(text)
    return "".join(out) + " "


class _BodyParts:
    """The inputs the pathological bodies share, each made on first use: a body that
    does not use the base64 noise or the key fragment never builds them."""

    near_key = _PERF_KEYS[-3][:-1]
    hex_key = _PERF_KEYS[-2]  # letters and digits only: the run-skipping path

    def __init__(self, size: int) -> None:
        self.size = size

    @functools.cached_property
    def noise(self) -> str:
        return base64.b64encode(secrets.token_bytes(self.size)).decode()[: self.size]

    @functools.cached_property
    def fragment(self) -> str:
        from unifi_fabric.secret_scrub import _fragments

        return sorted(_fragments(tuple(sorted(set(_PERF_KEYS)))))[0]


#: One builder per pathological body (see ``_pathological_bodies_reference`` for the
#: shapes' rationale); ``_pathological_body`` runs only the one it is asked for.
_PATHOLOGICAL_BUILDERS: dict[str, Callable[[_BodyParts], str]] = {
    "A-run": lambda p: "A" * p.size,
    "dash-run": lambda p: "-" * p.size,
    "base64-noise": lambda p: p.noise,
    "padding-run": lambda p: "=" * p.size,
    "slash-plus": lambda p: "+/" * (p.size // 2),
    "fragments-in-one-token": lambda p: (p.fragment + "A") * (p.size // (len(p.fragment) + 1)),
    "fragments-spaced": lambda p: (p.fragment + " ") * (p.size // (len(p.fragment) + 1)),
    "key-prefix-repeated": lambda p: (p.near_key + "!") * (p.size // (len(p.near_key) + 1)),
    "noise-then-fail": lambda p: p.noise[: p.size - 1] + "!",
    "percent-escapes": lambda p: "%41" * (p.size // 3),
    "unicode-escapes": lambda p: "\\u0041" * (p.size // 6),
    "backslash-run": lambda p: "\\" * p.size,
    "percent-run": lambda p: "%" * p.size,
    "escapes-then-near-key": lambda p: ("%20" + p.near_key) * (p.size // (len(p.near_key) + 3)),
    "escape-dense-alnum-candidates": lambda p: (
        ("%41x" + p.hex_key) * (p.size // (len(p.hex_key) + 4))
    ),
    "chained-escape-candidates": lambda p: (
        ("%2520" + p.hex_key + "z") * (p.size // (len(p.hex_key) + 6))
    ),
    "unbounded-percent-chain": lambda p: "%" + "25" * (p.size // 2) + "20" + p.hex_key,
    "unbounded-backslash-chain": lambda p: "\\u005c" + "u005c" * (p.size // 5) + "n" + p.hex_key,
    "long-chain-failed-candidates": lambda p: (
        "%" + ("25" + p.hex_key + "z") * (p.size // (len(p.hex_key) + 3))
    ),
    "entity-escape-candidates": lambda p: (
        ("&#37;20" + p.hex_key + "z") * (p.size // (len(p.hex_key) + 8))
    ),
    "unbounded-entity-chain": lambda p: "&" + "amp;" * (p.size // 4) + "#37;20" + p.hex_key,
    "unbounded-mixed-entity-chain": lambda p: (
        "%26%2337%3B" + "25" * (p.size // 2) + "5Cn" + p.hex_key
    ),
    "entity-leading-zeroes": lambda p: "&#" + "0" * p.size + "37;20" + p.hex_key,
    "entity-invalid-long-numeric": lambda p: "&#" + "1" * p.size + "x",
    "entity-invalid-long-hex": lambda p: "&#x" + "a" * p.size + "x",
    "entity-malformed-candidates": lambda p: (
        ("&amp;#x" + p.hex_key + "z") * (p.size // (len(p.hex_key) + 8))
    ),
    "one-run-of-candidates": lambda p: ("x" + p.hex_key) * (p.size // (len(p.hex_key) + 1)),
    "deferred-octal-run": lambda p: "\\1" * (p.size // 2),
    "deferred-octal-percent": lambda p: "\\1%30" * (p.size // 5),
    "octal-backslash-chain": lambda p: "\\134" * (p.size // 4) + "n" + p.hex_key,
    "entity-backslash-chain": lambda p: "&#92;" * (p.size // 5) + "n" + p.hex_key,
    "percent-backslash-run": lambda p: "%5c" * (p.size // 3),
    "escaped-backslash-pairs": lambda p: "\\x5c\\x41" * (p.size // 8),
    "entity-digits-closed-late": lambda p: "&#" + "0" * p.size + "%2533" + "7;" + p.hex_key,
    "key-per-character-depth-6": lambda p: (
        _nested_key(p.hex_key) * (p.size // len(_nested_key(p.hex_key)))
    ),
    "key-per-character-percent-25": lambda p: (
        ("".join(f"%25{ord(c):02x}" for c in p.hex_key) + " ")
        * (p.size // (5 * len(p.hex_key) + 1))
    ),
    "reported-octal-shape": lambda p: (
        ("e\\1%301" + p.hex_key + "! ") * (p.size // (len(p.hex_key) + 10))
    ),
    "out-of-range-units": lambda p: "\\UFFFFFFFF&#99999999;&nosuchname;%u12" * (p.size // 37),
}

#: The sweeps' parametrization: every body's name, without building any body.
_PATHOLOGICAL_NAMES = sorted(_PATHOLOGICAL_BUILDERS)


def _pathological_body(name: str, size: int = _PERF_SIZE) -> str:
    """The pathological body ``name`` at ``size`` characters, built alone."""
    return _PATHOLOGICAL_BUILDERS[name](_BodyParts(size))


#: Every scrubber entry point, called on a body as text (``str``) and as bytes.
_ENTRY_POINTS = (
    ("scrub", lambda text, raw: scrub(text, _PERF_KEYS)),
    ("scrub_bytes", lambda text, raw: scrub_bytes(raw, _PERF_KEYS)),
    ("contains_secret(str)", lambda text, raw: contains_secret(text, _PERF_KEYS)),
    ("contains_secret(bytes)", lambda text, raw: contains_secret(raw, _PERF_KEYS)),
)


def _unremembered(call, text: str, raw: bytes):
    """One full scrub: the repeat-scrub memo is emptied first."""
    secret_scrub._memo_clear()
    return call(text, raw)


@pytest.mark.parametrize("name", _PATHOLOGICAL_NAMES)
def test_scrubber_completes_one_megabyte_of_pathological_input(name):
    text = _pathological_body(name)
    raw = text.encode("ascii")
    results = {label: _unremembered(call, text, raw) for label, call in _ENTRY_POINTS}
    assert isinstance(results["scrub"], str)
    assert isinstance(results["scrub_bytes"], bytes)
    assert results["scrub"].encode("ascii") == results["scrub_bytes"]
    assert isinstance(results["contains_secret(str)"], bool)
    assert results["contains_secret(str)"] == results["contains_secret(bytes)"]
    assert results["contains_secret(str)"] == (results["scrub"] != text)
    secret_scrub._memo_clear()
    assert not contains_secret(results["scrub"], _PERF_KEYS)


_COUNT_SIZE = 32_000


@pytest.mark.parametrize("name", _PATHOLOGICAL_NAMES)
def test_scrubber_work_count_is_linear_on_pathological_input(name):
    """The scrubber's executed Python lines (a deterministic count: runner load cannot
    change it) grow under 6x for a 4x larger body of each pathological alphabet, through
    every entry point. Linear work grows about 4x (measured: at most 4.6x); a quadratic
    loop over the text, its escapes, its candidates or the configured secrets' forms
    grows about 16x. Work inside C (``str.find``, a regex) is not counted here: the
    structural ReDoS lint checks regex shapes; the full-size sweep checks completion."""
    big = _pathological_body(name, _COUNT_SIZE)
    small = _pathological_body(name, _COUNT_SIZE // cpu_scaling.SCALE)
    scrub("warm", _PERF_KEYS)
    assert {label for label, _ in _ENTRY_POINTS} == {
        "scrub",
        "scrub_bytes",
        "contains_secret(str)",
        "contains_secret(bytes)",
    }
    for label, call in _ENTRY_POINTS:
        counts = [
            cpu_scaling.python_line_events(
                secret_scrub,
                functools.partial(_unremembered, call, body, body.encode("ascii")),
            )
            for body in (small, big)
        ]
        ratio = counts[1] / counts[0]
        assert ratio < 6, (
            f"{label} on {name}: {counts[1]} lines at {_COUNT_SIZE} characters vs "
            f"{counts[0]} at 1/{cpu_scaling.SCALE} the size (x{ratio:.2f}, limit x6)"
        )


@pytest.mark.parametrize("size", [1_000, _COUNT_SIZE // cpu_scaling.SCALE, _COUNT_SIZE, _PERF_SIZE])
def test_pathological_bodies_match_the_reference(monkeypatch, size):
    """Every lazily built body, at every size the sweeps use, is byte-identical (SHA-256)
    to the one the all-at-once reference builder makes, and the two name the same 38
    bodies. Both draw the base64 noise from the same random bytes here."""
    drawn = secrets.token_bytes(size)
    monkeypatch.setattr(secrets, "token_bytes", lambda count: drawn[:count])

    def digest(body: str) -> str:
        return hashlib.sha256(body.encode("ascii")).hexdigest()

    reference = {name: digest(body) for name, body in _pathological_bodies_reference(size).items()}
    assert len(reference) == 38
    assert _PATHOLOGICAL_NAMES == sorted(reference)
    assert {name: digest(_pathological_body(name, size)) for name in _PATHOLOGICAL_NAMES} == (
        reference
    )


def test_a_pathological_body_builds_only_what_it_uses(monkeypatch):
    """A body that is not base64 noise draws no noise: a case builds its body alone."""

    def no_noise(count: int) -> bytes:
        raise AssertionError(f"drew {count} bytes of noise")

    monkeypatch.setattr(secrets, "token_bytes", no_noise)
    for name in _PATHOLOGICAL_NAMES:
        if name not in {"base64-noise", "noise-then-fail"}:
            assert _pathological_body(name, 1_000)


def _scan_counter(monkeypatch) -> list[tuple[str, bool]]:
    """Record every scan (a decode, then a search) of a text of at least the memo's size,
    with its mode (str or bytes)."""
    scanned: list[tuple[str, bool]] = []
    real = secret_scrub._spans

    def counting(data, values, as_bytes=False, first_only=False, **kwargs):
        if len(data) >= secret_scrub._MEMO_MIN_CHARS:
            scanned.append((data, as_bytes))
        return real(data, values, as_bytes, first_only, **kwargs)

    monkeypatch.setattr(secret_scrub, "_spans", counting)
    return scanned


def test_a_large_text_is_decoded_once_on_its_way_out(monkeypatch, captured_logs):
    """A large escape-dense error text is scrubbed by several sinks in turn -- the log
    record factory, the formatter, the handler and the emitted line; an exception chain
    when it is checked and when its stand-in is built; a body by contains_secret and then
    scrub_bytes. Each distinct large text is scanned (decoded and searched: the cost of
    scrubbing it) once per mode, str or bytes: a sink that scrubs or checks the same text
    again gets the remembered outcome.
    Counted, not timed, so a loaded runner cannot make this pass or fail."""
    from unifi_fabric.secret_scrub import install_log_scrubber, set_secret_provider

    body = " ".join(
        "%" + "25" * 40 + "20" + form
        for value in CONFIGURED
        for form in secret_scrub.secret_forms(value)
    )
    assert len(body) > 2 * secret_scrub._MEMO_MIN_CHARS
    secret_scrub._memo_clear()
    # The log sinks scrub with the provider's secrets plus those of every client still
    # alive (_live_settings_holders); an earlier test's client awaiting garbage collection
    # would add its key, and a different secret set is rightly a separate scan. Pin the
    # log secret set to CONFIGURED, the set the direct calls below use.
    monkeypatch.setattr(secret_scrub, "_live_settings_holders", weakref.WeakSet())
    scanned = _scan_counter(monkeypatch)
    install_log_scrubber()
    set_secret_provider(lambda: CONFIGURED)
    try:
        log = logging.getLogger("unifi_fabric.test.decode_once")
        log.error("%s", body)
        try:
            raise RuntimeError(body)
        except RuntimeError:
            log.exception("upstream failed")
    finally:
        set_secret_provider(secret_scrub.configured_secrets)
    for _ in range(2):
        assert contains_secret(body, CONFIGURED)
        assert contains_secret(body.encode(), CONFIGURED)
        clean = scrub(body, CONFIGURED)
        clean_bytes = scrub_bytes(body.encode(), CONFIGURED)
        assert scrub(clean, CONFIGURED) == clean
        assert not contains_secret(clean, CONFIGURED)
        assert scrub_bytes(clean_bytes, CONFIGURED) == clean_bytes
    _assert_clean("decode-once logs", "\n".join(captured_logs.lines))
    _assert_clean("decode-once text", clean + clean_bytes.decode())
    assert (body, False) in scanned and (body.encode().decode("latin-1"), True) in scanned
    repeated = {(text[:40], mode) for text, mode in scanned if scanned.count((text, mode)) > 1}
    assert not repeated, f"scanned more than once: {sorted(repeated)}"


def test_repeat_scrub_memo_gives_the_full_result_and_keeps_no_secret():
    """A remembered result is exactly what a full scrub returns, for str and bytes and
    for every set of secrets; the memo holds digests of the inputs, never an input, and
    only scrubbed results; it stays within its entry bound."""
    body = " ".join(escaped_echoes(KEY_ALPHA) + escaped_echoes(BEARER)) * 3
    assert len(body) >= secret_scrub._MEMO_MIN_CHARS
    for secrets_ in ([KEY_ALPHA], [BEARER], list(CONFIGURED)):
        secret_scrub._memo_clear()
        full = scrub(body, secrets_)
        full_bytes = scrub_bytes(body.encode(), secrets_)
        found = contains_secret(body, secrets_)
        assert scrub(body, secrets_) == full  # remembered
        assert scrub_bytes(body.encode(), secrets_) == full_bytes
        assert contains_secret(body, secrets_) is found
        assert contains_secret(body.encode(), secrets_) is found
        secret_scrub._memo_clear()
        assert contains_secret(body, secrets_) is found  # remembered before any scrub
        assert scrub(body, secrets_) == full
        assert found
        assert all(value not in full + full_bytes.decode() for value in secrets_)
    for (_values, _as_bytes, digest), (_found, result) in secret_scrub._memo.items():
        assert isinstance(digest, bytes) and len(digest) == 32
        assert result is None or leaks(result) == []
    secret_scrub._memo_clear()
    for index in range(secret_scrub._MEMO_MAX_ENTRIES + 10):
        scrub(f"{index} " + body, [KEY_ALPHA])
    assert len(secret_scrub._memo) <= secret_scrub._MEMO_MAX_ENTRIES
    secret_scrub._memo_clear()


def test_linear_scrubber_still_masks_the_whole_embedded_token():
    """The rewrite keeps the embedded-base64 contract: the whole base64 token (and its
    padding) holding a secret embedded after any prefix is masked, nothing around it."""
    key = "Zq9-embedded-Secret_42"
    for prefix in (b"u:", b"user:", b"longer-user:"):
        token = base64.b64encode(prefix + key.encode()).decode()
        text = f"Authorization: Basic {token}, next"
        assert scrub(text, [key]) == "Authorization: Basic ***, next"
        assert scrub_bytes(text.encode(), [key]) == b"Authorization: Basic ***, next"
        assert contains_secret(text.encode(), [key])
    assert not contains_secret("A" * 100_000, [key])


@pytest.mark.parametrize("length", range(1, 65))
async def test_complete_escape_chain_matrix_all_error_sinks(
    monkeypatch, tmp_path, secret_env, captured_logs, length
):
    """Every configured-secret form crosses error, body, header and log sinks.

    Each configured secret is an independent batch. This retains every combination
    while avoiding four xdist workers holding five escape-dense bodies at once.
    """
    from unifi_fabric.secret_scrub import secret_forms

    prefixes = (
        "%" + "25" * length + "20",
        "%" + "25" * length + "u00e9",
        "%" + "25" * length + "5Cn",
        "%" + "25" * length + "5Cu00e9",
        "\\" * length + "n",
        "\\u005c" + "u005c" * length + "n",
        "&" + "amp;" * length + "#10;",
        "&#37;20",
        "&#x25;20",
        "&#37;25" * length + "20",
        "&#37;5Cn",
        "&#92;n",
        "&#x5c;n",
        "&#92;x41",
        "&#92;" * length + "n",
        "&" + "amp;" * length + "#37;20",
        "%26%2337%3B20",
        "&percnt;" + "25" * length + "20",
        "&bsol;" + "u005c" * length + "n",
        "%26%23x25%3b" + "25" * length + "20",
    )
    for batch, secret in enumerate(CONFIGURED):
        echoes = [prefix + form for form in secret_forms(secret) for prefix in prefixes]
        body = " ".join(echoes)
        location = " ".join(echo for echo in echoes if echo.isascii())
        state = {"body": body, "location": location, "transport_error": False}

        def handler(req, state=state):
            if state["transport_error"]:
                raise httpx.LocalProtocolError(state["body"])
            return httpx.Response(401, headers={"Location": state["location"]}, text=state["body"])

        async def get_client(self, key_config):
            return httpx.AsyncClient(
                base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
            )

        monkeypatch.setattr(UniFiClient, "_get_client", get_client)
        client = UniFiClient(Settings(api_keys=_KEYS))
        with pytest.raises(UniFiConnectionError) as exc:
            await client.request("GET", "/v1/hosts")
        _assert_clean("error chain matrix", str(exc.value))
        response = await client.request("GET", "/v1/hosts", raise_on_error=False)
        _assert_clean("relay chain matrix", response.text)
        _assert_clean("Location chain matrix", response.headers["Location"])

        state["transport_error"] = True
        with pytest.raises(UniFiConnectionError) as exc:
            await client.request("GET", "/v1/hosts")
        _assert_clean("transport chain matrix", str(exc.value))
        error = UniFiConnectionError(body)
        logging.getLogger("r17.chain").error(
            "synthetic transport failure", exc_info=(type(error), error, None)
        )
        logging.getLogger("r17.chain").error("%s", body)
        _assert_clean("log chain matrix", "\n".join(captured_logs.lines))
        assert not leaks(scrub(body, CONFIGURED))
        audit = tmp_path / f"chain-audit-{batch}.log"
        sink = AuditSink(path=str(audit), fmt="text", secrets=CONFIGURED)
        sink.record(method="POST", path="/synthetic", outcome="refused", status=401, reason=body)
        _assert_clean("audit chain matrix", audit.read_text())
        captured_logs.lines.clear()


def _assert_masked_at_any_depth(head: str, chain: str, secret: str, tail: str) -> None:
    """``head + chain + secret + tail`` never leaks ``secret`` at any escape depth.

    Within the SCRUBBER-SPEC bounds (depth 8, the size-scaled view budget) the result is
    exact: only the secret is masked. Past a bound the G5 fail-closed rule masks every
    escape component at the bound, so the chain is masked with the secret (the only
    accepted over-masking): ``head`` and ``tail`` are still kept, the secret is gone from
    every partial decoding of the output, and text and bytes agree."""
    text = head + chain + secret + tail
    out = scrub(text, [secret])
    assert scrub_bytes(text.encode(), [secret]) == out.encode()
    assert contains_secret(text, [secret]) and contains_secret(text.encode(), [secret])
    assert not scrub_oracle.reference_spans(out, [secret]), (text, out)
    if scrub_oracle.bound(text):
        assert out.startswith(head) and out.endswith("***" + tail), (text, out)
    else:
        assert out == head + chain + "***" + tail, (text, out)


def test_escape_chain_has_no_lookback_or_depth_limit():
    # Short synthetic key bypasses the embedded-base64 fallback.
    for length in (1, 7, 19, 64, 1024):
        for prefix in (
            "%" + "25" * length + "20",
            "%" + "25" * length + "5Cn",
            "\u005c" + "u005c" * length + "n",
        ):
            _assert_masked_at_any_depth("", prefix, "K", "!")
    # "%2x" never decodes, so K is inside the token "2xK": kept within the bounds; past
    # the depth bound the G5 fail-closed rule masks that whole escape component.
    for length in (1, 7, 64):
        text = "%" + "25" * length + "2xK!"
        out = scrub(text, ["K"])
        assert out.endswith("***!" if scrub_oracle.bound(text) else "2xK!"), (text, out)


@pytest.mark.parametrize(
    "prefix",
    [
        "&#37;20",
        "&#x25;20",
        "&#37;25" * 64 + "20",
        "&#37;5Cn",
        "&#92;n",
        "&#x5c;n",
        "&#92;x41",
        "&#92;&#92;n",
        "&amp;#37;20",
        "%26%2337%3B20",
        "&percnt;20",
        "&bsol;n",
        "&#X5C;n",
        "&" + "amp;" * 1024 + "#000037;20",
        "%26%2337%3B" + "25" * 1024 + "5C" + "u005c" * 1024 + "n",
    ],
)
def test_html_entity_escape_chain_boundaries(prefix):
    _assert_masked_at_any_depth("a ", prefix, "K", " b")


@pytest.mark.parametrize("length", (1, 19, 64, 1024))
@pytest.mark.parametrize("first", ("%", "\\", "&"))
def test_mixed_entity_percent_backslash_chains_have_no_depth_limit(length, first):
    unit = {
        "%": {"%": "25", "\\": "5C", "&": "26"},
        "\\": {"%": "u0025", "\\": "u005c", "&": "u0026"},
        "&": {"%": "#37;", "\\": "#x5C;", "&": "amp;"},
    }
    chain, intro = first, first
    for index in range(length):
        following = ("&", "%", "\\")[index % 3]
        chain += unit[intro][following]
        intro = following
    chain += {"%": "20", "\\": "n", "&": "#32;"}[intro]
    _assert_masked_at_any_depth("a ", chain, "K", " b")


@pytest.mark.parametrize("path", ["raised", "relayed", "json", "binary"])
async def test_dense_secret_echo_shared_client_paths(monkeypatch, secret_env, captured_logs, path):
    """Every dense form traverses each shared response consumer once."""
    status = 403 if path in {"raised", "relayed"} else 200
    body = _echo_body(status)
    client = UniFiClient(Settings(api_keys=_KEYS))

    transport_client = httpx.AsyncClient(
        base_url="https://api.ui.com",
        transport=httpx.MockTransport(lambda req: httpx.Response(status, text=body)),
    )

    async def get_client(self, key_config):
        return transport_client

    monkeypatch.setattr(UniFiClient, "_get_client", get_client)
    try:
        if path == "raised":
            with pytest.raises(UniFiConnectionError) as caught:
                await client.request("GET", "/dense", key=_KEYS[0])
            output = _exc_texts(caught.value)
        elif path == "relayed":
            response = await client.request("GET", "/dense", key=_KEYS[0], raise_on_error=False)
            output = response.text
        elif path == "json":
            output = _texts(await client.get("/dense", key=_KEYS[0]))
        else:
            raw, _ = await client.get_binary("/dense", key=_KEYS[0])
            output = raw.decode()
        _assert_clean(f"dense {path}", output)
        _assert_clean(f"dense {path} logs", "\n".join(captured_logs.lines))
    finally:
        await client.close()
        await transport_client.aclose()


@pytest.mark.parametrize("status", [302, 400, 403, 404, 429, 500])
async def test_matter_setup_code_sentinel_all_error_forms(monkeypatch, captured_logs, status):
    """Caller-supplied Matter secrets are always masked in logs, not default error data."""
    from unittest.mock import AsyncMock

    from pydantic import SecretStr

    from unifi_fabric.families.network import matter

    setup_code = MARKER + '-matter-setup/+=\\"%&'
    echoes = [
        setup_code,
        repr(setup_code),
        repr(setup_code.encode()),
        json.dumps(setup_code),
        *escaped_echoes(setup_code),
        *_b64_forms(setup_code),
        setup_code.encode().hex(),
    ]
    # The suite's configured keys: a client holding another key would widen the log
    # scrubber's secret set for later tests in the same worker.
    client = UniFiClient(Settings(api_keys=_KEYS))
    key = _KEYS[0]
    raw_client = await client._get_client(key)

    async def send(method, url, **kwargs):
        req = httpx.Request(method, raw_client.base_url.join(url))
        logging.getLogger("matter-sentinel").error("pairing %s", setup_code)
        return httpx.Response(
            status,
            text=" | ".join(echoes),
            headers={"Location": "https://example.invalid/" + quote(setup_code)},
            request=req,
        )

    monkeypatch.setattr(raw_client, "request", send)
    registry = AsyncMock(
        **{
            "resolve_key_for_host.return_value": key,
            "resolve_host_id.return_value": "console",
            "resolve_site_slug.return_value": "default",
        }
    )
    try:
        with pytest.raises(Exception) as caught:
            await matter.commission_matter_node(
                client, registry, "console", "default", SecretStr(setup_code)
            )
        assert f"HTTP {status}" in str(caught.value)
        exception_text = _exc_texts(caught.value)
        log_text = "\n".join(captured_logs.lines)
        _assert_clean("Matter setup code logs", log_text)
        assert MARKER not in log_text
        assert MARKER in exception_text
    finally:
        await client.close()
