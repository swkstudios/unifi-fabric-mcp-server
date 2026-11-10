"""Log scrubbing that keeps record arguments intact (uvicorn access
lines) and covers exception text in every handler (rich included), credential values
validated at config load by one validator shared with the placement CLI, every
returned response scrubbed (a relayed 3xx included), and verbatim upstream text in
redacted error bodies."""

from __future__ import annotations

import io
import json
import logging
import secrets

import httpx
import pytest
from pydantic import ValidationError
from rich.console import Console
from rich.logging import RichHandler

from unifi_fabric import placement_snapshot_cli as cli
from unifi_fabric.client import UniFiClient, UniFiConnectionError, error_body_text
from unifi_fabric.config import (
    APIKeyConfig,
    MCPTransportSettings,
    Settings,
    credential_problem,
)
from unifi_fabric.secret_scrub import MASK, install_log_scrubber

# A per-run random marker (a fixed word could match a checkout path in a traceback).
MARKER = "m" + secrets.token_hex(12)
SECRET = f"{MARKER}-Key/+=42"
_ENV = ("UNIFI_API_KEY", "UNIFI_API_KEYS", "MCP_BEARER_TOKEN", "MCP_TLS_KEY_PASSWORD")


@pytest.fixture
def clean_env(monkeypatch):
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")


@pytest.fixture
def secret_in_env(monkeypatch, clean_env):
    monkeypatch.setenv("UNIFI_API_KEY", SECRET)
    install_log_scrubber()


def _record(logger: logging.Logger, msg: object, *args: object, **kwargs: object):
    return logger.makeRecord(logger.name, logging.INFO, __file__, 1, msg, args, None, **kwargs)


# ============================================== record arguments keep their structure
def test_record_args_keep_type_and_arity(secret_in_env):
    logger = logging.getLogger("logscrub.args")
    record = _record(
        logger, '%s - "%s %s HTTP/%s" %d', "127.0.0.1:1", "GET", f"/x?t={SECRET}", "1.1", 401
    )
    assert isinstance(record.args, tuple) and len(record.args) == 5
    assert record.args[4] == 401 and type(record.args[4]) is int
    assert record.getMessage() == f'127.0.0.1:1 - "GET /x?t={MASK} HTTP/1.1" 401'


def test_mapping_args_and_objects_are_scrubbed(secret_in_env):
    logger = logging.getLogger("logscrub.args")
    record = _record(logger, "%(path)s %(code)d", {"path": SECRET, "code": 7})
    assert record.getMessage() == f"{MASK} 7"

    class Holder:
        def __repr__(self) -> str:
            return f"Holder({SECRET!r})"

    record = _record(logger, "%s | %r | %s", Holder(), Holder(), [SECRET])
    assert MARKER not in record.getMessage()
    assert "Holder(" in record.getMessage()


def test_uvicorn_access_formatter_formats_scrubbed_records(secret_in_env, capsys):
    """uvicorn's AccessFormatter unpacks the five record arguments; a scrubbed record
    must still format (no '--- Logging error ---') with the secret masked."""
    from uvicorn.logging import AccessFormatter

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(AccessFormatter('%(client_addr)s - "%(request_line)s" %(status_code)s'))
    logger = logging.getLogger("logscrub.uvicorn.access")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        logger.info(
            '%s - "%s %s HTTP/%s" %d', "127.0.0.1:5", "GET", f"/mcp?token={SECRET}", "1.1", 200
        )
    finally:
        logger.removeHandler(handler)
    assert "Logging error" not in capsys.readouterr().err
    line = stream.getvalue()
    assert f"GET /mcp?token={MASK} HTTP/1.1" in line and "200" in line
    assert MARKER not in line


# ============================================== exception text in every handler
def _raise_chain() -> None:
    try:
        raise KeyError(f"inner {SECRET}")
    except KeyError as inner:
        exc = RuntimeError(f"outer failure for {SECRET}")
        exc.add_note(f"note with {SECRET}")
        raise exc from inner


def test_plain_formatter_traceback_is_scrubbed(secret_in_env):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("logscrub.plain")
    logger.addHandler(handler)
    logger.propagate = False
    try:
        try:
            _raise_chain()
        except RuntimeError:
            logger.exception("failed")
    finally:
        logger.removeHandler(handler)
    text = stream.getvalue()
    assert MARKER not in text
    assert "RuntimeError: outer failure for ***" in text
    assert "KeyError" in text and "note with ***" in text


def test_rich_handler_traceback_is_scrubbed(secret_in_env):
    """RichHandler renders exc_info itself (rich Traceback), not exc_text."""
    console = Console(file=io.StringIO(), width=200, color_system=None)
    handler = RichHandler(console=console, rich_tracebacks=True)
    logger = logging.getLogger("logscrub.rich")
    logger.addHandler(handler)
    logger.propagate = False
    try:
        try:
            _raise_chain()
        except RuntimeError:
            logger.exception("failed")
        try:
            raise ExceptionGroup("group", [ValueError(SECRET), OSError(f"os {SECRET}")])
        except ExceptionGroup:
            logger.exception("group failed")
    finally:
        logger.removeHandler(handler)
    text = console.file.getvalue()  # type: ignore[attr-defined]
    assert MARKER not in text
    assert "RuntimeError" in text and "outer failure for ***" in text
    assert "ValueError" in text and "ExceptionGroup" in text


def test_fastmcp_rich_handlers_traceback_is_scrubbed(secret_in_env, capsys, monkeypatch):
    from fastmcp.utilities.logging import configure_logging

    # Rich sizes its console from COLUMNS (80 when captured); at 80 columns a long checkout
    # or test-file path squeezes the traceback panel until the exception line is elided.
    # A wide console keeps the assertion about scrubbing, not about the path length.
    monkeypatch.setenv("COLUMNS", "400")
    logger = logging.getLogger("logscrub.fastmcp")
    configure_logging(level="INFO", logger=logger, enable_rich_tracebacks=True)
    try:
        try:
            _raise_chain()
        except RuntimeError:
            logger.exception("tool failed")
        logger.info("plain line %s", SECRET)
    finally:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
    err = capsys.readouterr().err
    assert "RuntimeError" in err and "plain line ***" in err
    assert MARKER not in err


def test_original_exception_is_untouched(secret_in_env):
    logger = logging.getLogger("logscrub.plain")
    try:
        _raise_chain()
    except RuntimeError as exc:
        record = logger.makeRecord(
            logger.name, logging.ERROR, __file__, 1, "x", (), (type(exc), exc, exc.__traceback__)
        )
        assert SECRET in str(exc)
        assert record.exc_info is not None
        assert record.exc_info[1] is not exc and MARKER not in str(record.exc_info[1])
        assert type(record.exc_info[1]).__name__ == "RuntimeError"


def test_filter_on_existing_handlers_scrubs_records_built_without_factory(secret_in_env):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("logscrub.filter")
    logger.addHandler(handler)
    try:
        install_log_scrubber()  # attaches the filter to handlers that exist now
        logger.handle(
            logging.makeLogRecord(
                {"msg": "made %s", "args": (SECRET,), "levelno": logging.INFO, "levelname": "INFO"}
            )
        )
    finally:
        logger.removeHandler(handler)
    assert stream.getvalue().strip() == f"made {MASK}"


# ============================================== credential values at config load
_BAD_KEYS = {
    "leading space": " " + SECRET,
    "trailing newline": SECRET + "\n",
    "inner tab": SECRET.replace("/", "\t"),
    "control character": SECRET + "\x07",
    "non-ASCII": SECRET + "é",
}


@pytest.mark.parametrize("case", sorted(_BAD_KEYS))
def test_bad_api_key_is_rejected_naming_the_variable(clean_env, monkeypatch, case):
    monkeypatch.setenv("UNIFI_API_KEY", _BAD_KEYS[case])
    with pytest.raises(ValidationError) as exc:
        Settings()
    text = str(exc.value)
    assert "UNIFI_API_KEY " in text and "the value is not shown here" in text
    assert MARKER not in text


@pytest.mark.parametrize("case", sorted(_BAD_KEYS))
def test_bad_keys_entry_is_rejected_naming_entry_and_label(clean_env, monkeypatch, case):
    keys = [{"key": "good-key-1", "label": "ok"}, {"key": _BAD_KEYS[case], "label": "site-b"}]
    monkeypatch.setenv("UNIFI_API_KEYS", json.dumps(keys))
    with pytest.raises(ValidationError) as exc:
        Settings()
    text = str(exc.value)
    assert "UNIFI_API_KEYS entry 1" in text
    assert MARKER not in text and "'ok'" not in text


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ({"key": "", "label": "a"}, "UNIFI_API_KEYS entry 0 is empty"),
        ({"key": "   ", "label": "a"}, "UNIFI_API_KEYS entry 0 is whitespace-only"),
        ({"key": "good-key", "label": ""}, "UNIFI_API_KEYS[0].label must not be empty"),
        ({"key": "good-key", "label": "  "}, "UNIFI_API_KEYS[0].label must not be empty"),
    ],
)
def test_empty_key_or_label_is_rejected(clean_env, monkeypatch, entry, expected):
    monkeypatch.setenv("UNIFI_API_KEYS", json.dumps([entry]))
    with pytest.raises(ValidationError) as exc:
        Settings()
    assert expected in str(exc.value)


def test_same_key_under_two_labels_is_rejected_without_the_key(clean_env, monkeypatch):
    keys = [
        {"key": SECRET, "label": "east"},
        {"key": "other-key", "label": "mid"},
        {"key": SECRET, "label": "west"},
    ]
    monkeypatch.setenv("UNIFI_API_KEYS", json.dumps(keys))
    with pytest.raises(ValidationError) as exc:
        Settings()
    text = str(exc.value)
    assert "same key under different labels at entries 0, 2" in text
    assert MARKER not in text and "'mid'" not in text


def test_valid_keys_are_kept_exactly(clean_env, monkeypatch):
    keys = [{"key": SECRET, "label": "a"}, {"key": "k2-~!@#$%^&*()", "label": "b"}]
    monkeypatch.setenv("UNIFI_API_KEYS", json.dumps(keys))
    assert [cfg.key for cfg in Settings().api_keys] == [SECRET, "k2-~!@#$%^&*()"]


@pytest.mark.parametrize("case", sorted(_BAD_KEYS))
def test_bad_bearer_token_is_rejected(clean_env, monkeypatch, case):
    monkeypatch.setenv("MCP_BEARER_TOKEN", _BAD_KEYS[case])
    with pytest.raises(ValidationError) as exc:
        MCPTransportSettings()
    text = str(exc.value)
    assert "MCP_BEARER_TOKEN " in text and MARKER not in text


def test_tls_key_password_allows_spaces_and_unicode_but_not_control_chars(clean_env):
    ok = MCPTransportSettings(tls_key_password="pass phrase é with spaces")
    assert ok.tls_key_password == "pass phrase é with spaces"
    with pytest.raises(ValidationError) as exc:
        MCPTransportSettings(tls_key_password=f"{SECRET}\n")
    text = str(exc.value)
    assert "MCP_TLS_KEY_PASSWORD contains a control character" in text
    assert MARKER not in text


def test_credential_problem_never_strips():
    assert credential_problem(SECRET) is None
    assert credential_problem(f"{SECRET} ") is not None
    assert credential_problem("pass phrase", "password") is None


@pytest.mark.parametrize(
    "keys",
    [
        [{"key": " ", "label": "a"}],
        [{"key": f"{SECRET}\n", "label": "a"}],
        [{"key": "ok-key", "label": ""}],
        [{"key": SECRET, "label": "a"}, {"key": SECRET, "label": "b"}],
    ],
)
def test_server_and_cli_report_the_same_problem(clean_env, monkeypatch, capsys, keys):
    monkeypatch.setenv("UNIFI_API_KEYS", json.dumps(keys))
    with pytest.raises(ValidationError) as exc:
        Settings()
    server_message = exc.value.errors(include_url=False, include_input=False)[0]["msg"]
    assert cli.main(["--host", "h"]) == 1
    err = capsys.readouterr().err
    assert server_message in err
    assert MARKER not in err


async def test_non_ascii_key_built_in_code_is_an_actionable_error():
    settings = Settings.model_construct(
        api_keys=[APIKeyConfig.model_construct(key="café-key", label="lab", is_org_key=False)]
    )
    client = UniFiClient(settings)
    with pytest.raises(ValueError) as exc:
        await client.request("GET", "/v1/hosts")
    text = str(exc.value)
    assert "API key 'lab' contains a non-ASCII character" in text
    assert "caf" not in text and "position" not in text
    await client.close()


# ============================================== every returned response scrubbed
def _client_with(monkeypatch, handler) -> UniFiClient:
    client = UniFiClient(Settings(api_keys=[APIKeyConfig(key=SECRET, label="a")]))

    async def _get_client(self, key_config):
        return httpx.AsyncClient(
            base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(UniFiClient, "_get_client", _get_client)
    return client


@pytest.mark.parametrize("status", [301, 302, 307, 308, 404, 500])
async def test_relayed_response_body_and_headers_are_scrubbed(monkeypatch, clean_env, status):
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            headers={"Location": f"https://evil.example/?k={SECRET}", "X-Echo": SECRET},
            json={"echo": SECRET},
        )

    client = _client_with(monkeypatch, handler)
    resp = await client.request("GET", "/v1/hosts", raise_on_error=False)
    assert resp.status_code == status
    assert MARKER not in resp.text and MASK in resp.text
    assert resp.headers["location"] == f"https://evil.example/?k={MASK}"
    assert resp.headers["x-echo"] == MASK
    assert all(MARKER not in value for _, value in resp.headers.items())


@pytest.mark.parametrize("status", [200, 201, 204, 206])
async def test_2xx_response_own_secret_echo_is_scrubbed(monkeypatch, clean_env, status):
    """Own configured secrets are scrubbed from successful bodies and headers too."""
    body = json.dumps({"echo": SECRET}).encode() if status != 204 else b""
    sent: list[httpx.Response] = []

    def handler(req: httpx.Request) -> httpx.Response:
        resp = httpx.Response(status, headers={"X-Echo": SECRET}, content=body)
        sent.append(resp)
        return resp

    client = _client_with(monkeypatch, handler)
    resp = await client.request("GET", "/v1/hosts", raise_on_error=False)
    assert resp is not sent[0]
    assert resp.content == b"" if status == 204 else resp.json() == {"echo": MASK}
    assert resp.headers["x-echo"] == MASK


async def test_binary_error_body_is_scrubbed_bytewise_never_decoded(monkeypatch, clean_env):
    """A binary error body is scrubbed at the byte level; every other byte kept."""
    raw = b"\xff\xfe\x00\x80 " + SECRET.encode() + b" \xc3\x28\x00\xff"

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500, headers={"Content-Type": "application/octet-stream"}, content=raw
        )

    client = _client_with(monkeypatch, handler)
    resp = await client.request("GET", "/v1/hosts", raise_on_error=False)
    assert resp.content == raw.replace(SECRET.encode(), MASK.encode())


async def test_clean_response_is_returned_unchanged(monkeypatch, clean_env):
    original: list[httpx.Response] = []

    def handler(req: httpx.Request) -> httpx.Response:
        resp = httpx.Response(302, headers={"Location": "/elsewhere"}, json={"ok": True})
        original.append(resp)
        return resp

    client = _client_with(monkeypatch, handler)
    resp = await client.request("GET", "/v1/hosts", raise_on_error=False)
    assert resp.status_code == 302 and resp.headers["location"] == "/elsewhere"
    assert resp.json() == {"ok": True}


# ============================================== verbatim upstream text when redacting
def test_redacted_error_body_keeps_non_ascii_verbatim():
    body = json.dumps({"message": "Zugriff verweigert – café", "password": "x"})
    out = error_body_text(body, redact_secrets=True)
    assert "Zugriff verweigert – café" in out
    assert "\\u" not in out and '"password":"x"' not in out


async def test_redacted_error_message_keeps_non_ascii_verbatim(monkeypatch, clean_env):
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "accès refusé", "token": "t"})

    client = _client_with(monkeypatch, handler)
    client._settings.redact_secrets = True
    with pytest.raises(UniFiConnectionError) as exc:
        await client.request("GET", "/v1/hosts")
    assert "accès refusé" in str(exc.value) and "\\u00e8" not in str(exc.value)


@pytest.mark.parametrize("key", ["1", "true", "null", "{", '"'])
@pytest.mark.parametrize("enabled", [False, True])
async def test_short_own_credentials_preserve_json_syntax_and_scalar_types(
    monkeypatch, key, enabled
):
    body = {"count": 1, "flag": True, "empty": None, "echo": key}

    def handler(req):
        return httpx.Response(200, json=body)

    client = UniFiClient(Settings(api_key=key, redact_secrets=enabled))

    async def get_client(self, key_config):
        if key_config.label not in self._clients:
            self._clients[key_config.label] = httpx.AsyncClient(
                base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
            )
        return self._clients[key_config.label]

    monkeypatch.setattr(UniFiClient, "_get_client", get_client)
    try:
        response = await client.request("GET", "/v1/hosts")
        assert response.json() == {**body, "echo": MASK}
    finally:
        await client.close()


def test_json_scrubbing_preserves_colliding_object_keys():
    from unifi_fabric.secret_scrub import scrub_json_strings

    assert scrub_json_strings({SECRET: "first", MASK: "second"}, [SECRET]) == {
        MASK + "*": "first",
        MASK: "second",
    }


@pytest.mark.parametrize("key", ["1", "true", "null", "{"])
async def test_short_credential_does_not_change_nonstring_json_data(monkeypatch, key):
    body = b'{ "count": 1, "flag": true, "empty": null }'
    client = UniFiClient(Settings(api_key=key))
    response = httpx.Response(200, content=body, headers={"Content-Type": "application/json"})
    own_key = client._default_key()
    try:
        assert client._scrubbed_response(response, own_key) is response
        assert response.content == body
    finally:
        await client.close()


async def test_declared_binary_json_looking_body_uses_byte_scrubber():
    client = UniFiClient(Settings(api_key="1"))
    response = httpx.Response(
        200,
        content=b"1",
        headers={"Content-Type": "image/jpeg"},
        request=httpx.Request("GET", "https://example.test/v1/hosts"),
    )
    try:
        assert client._scrubbed_response(response, client._default_key()).content == MASK.encode()
    finally:
        await client.close()


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "latin-1"])
@pytest.mark.parametrize("media_type", ["application/json", "text/plain"])
def test_own_secret_json_scrub_preserves_declared_charset(encoding, media_type):
    from unifi_fabric.config import APIKeyConfig
    from unifi_fabric.families.connector.connector import _relay_body

    key = "1"
    body = {"count": 1, "label": "café", "echo": key}
    raw = json.dumps(body, ensure_ascii=False).encode(encoding)
    response = httpx.Response(
        200,
        content=raw,
        headers={"Content-Type": f"{media_type}; charset={encoding}"},
        request=httpx.Request("GET", "https://example.test/v1/hosts"),
    )
    client = UniFiClient(Settings(api_key=key))
    clean = client._scrubbed_response(response, APIKeyConfig(key=key))
    assert _relay_body(clean)["body"] == {**body, "echo": MASK}
    assert clean.headers["content-type"] == response.headers["content-type"]


def test_invalid_json_encoding_remains_binary_after_own_secret_scrub():
    import base64

    from unifi_fabric.families.connector.connector import _relay_body

    raw = b'{"name":"\xff","echo":"' + SECRET.encode() + b'"}'
    response = httpx.Response(
        200,
        content=raw,
        headers={"Content-Type": "application/json; charset=utf-8"},
        request=httpx.Request("GET", "https://example.test/v1/hosts"),
    )
    client = UniFiClient(Settings(api_key=SECRET))
    clean = client._scrubbed_response(response, client._default_key())
    expected = raw.replace(SECRET.encode(), MASK.encode())
    assert clean.content == expected
    relay = _relay_body(clean)
    assert relay["body"] is None
    assert base64.b64decode(relay["bodyBase64"]) == expected


@pytest.mark.parametrize("codec", ["base64", "rot13", "unicode_escape", "idna", "unknown-codec"])
def test_unusable_codec_keeps_binary_body_during_own_secret_scrubbing(codec):
    import base64

    from unifi_fabric.families.connector.connector import _relay_body

    raw = json.dumps({"echo": SECRET, "label": "literal\\n"}).encode()
    response = httpx.Response(
        200,
        content=raw,
        headers={"Content-Type": f"application/json; charset={codec}"},
        request=httpx.Request("GET", "https://example.test/v1/hosts"),
    )
    client = UniFiClient(Settings(api_key=SECRET))
    clean = client._scrubbed_response(response, client._default_key())
    expected = raw.replace(SECRET.encode(), MASK.encode())
    assert clean.content == expected
    relay = _relay_body(clean)
    assert relay["body"] is None
    assert base64.b64decode(relay["bodyBase64"]) == expected
