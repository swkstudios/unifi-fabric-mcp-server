"""Trusted startup credential providers: UNIFI_API_KEY(S)_FILE and UNIFI_API_KEY(S)_COMMAND.

Covers the acceptance checks of the feature:

* file and helper success with synthetic keys, including the whitespace rule (a trailing
  line break and a BOM are removed, nothing else);
* missing, unreadable, empty, non-regular and oversized files; malformed helper settings,
  helper failure and empty output, each an actionable error that names the setting and
  never shows a key, the content or the helper's arguments;
* precedence and conflicts across direct, file and command settings, with the existing
  UNIFI_API_KEY / UNIFI_API_KEYS behavior unchanged;
* resolved keys and helper output are absent from logs, exceptions, tracebacks and the
  central scrubber's secret set includes them (every diagnostic sink uses it);
* request headers cannot select or run a provider or change the process keys, and the
  existing header credentials still work.

Every key here is synthetic and built at run time.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import stat
import sys
import traceback
from pathlib import Path

import pytest
from pydantic import ValidationError

from unifi_fabric import credential_providers as cp
from unifi_fabric import entrypoint
from unifi_fabric import header_credentials as hc
from unifi_fabric.config import Settings, known_setting_names
from unifi_fabric.secret_scrub import configured_secrets


def _key(tag: str) -> str:
    # Synthetic, built at run time so no secret-shaped literal sits in the source.
    return "-".join(("synthetic", "provider", tag, "0" * 8))


KEY_FILE = _key("file")
KEY_CMD = _key("cmd")
KEY_DIRECT = _key("direct")


@pytest.fixture(autouse=True)
def _fresh_providers():
    cp.reset()
    yield
    cp.reset()


def _secret_file(tmp_path: Path, content: str | bytes, name: str = "key") -> Path:
    path = tmp_path / name
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8", newline="")
    else:
        path.write_bytes(content)
    path.chmod(0o600)
    return path


def _helper(tmp_path: Path, body: str, name: str = "helper") -> Path:
    """A POSIX helper script; ``body`` is its shell code. Counts its runs in ``runs``."""
    path = tmp_path / name
    counter = tmp_path / f"{name}.runs"
    path.write_text(f"#!/bin/sh\necho run >> '{counter}'\n{body}\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def _runs(tmp_path: Path, name: str = "helper") -> int:
    counter = tmp_path / f"{name}.runs"
    return len(counter.read_text().splitlines()) if counter.exists() else 0


def _error_text(exc: BaseException) -> str:
    return "".join(traceback.format_exception(exc))


posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX helper scripts")


# ----------------------------------------------------------------------------- success


@pytest.mark.parametrize(
    "content", [KEY_FILE, KEY_FILE + "\n", KEY_FILE + "\r\n", "﻿" + KEY_FILE + "\n"]
)
def test_file_provider_success_and_trailing_newline(tmp_path, monkeypatch, content):
    monkeypatch.setenv("UNIFI_API_KEY_FILE", str(_secret_file(tmp_path, content)))
    configs = Settings().get_key_configs()
    assert [(c.label, c.key) for c in configs] == [("default", KEY_FILE)]


@posix_only
def test_command_provider_success(tmp_path, monkeypatch):
    helper = _helper(tmp_path, f"printf '%s\\n' '{KEY_CMD}'")
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", str(helper))
    assert [c.key for c in Settings().get_key_configs()] == [KEY_CMD]


@posix_only
def test_command_argument_model_is_posix_words_without_shell(tmp_path, monkeypatch):
    """Arguments are split with POSIX quoting and passed verbatim: no expansion."""
    helper = _helper(tmp_path, 'printf "%s|" "$@" > "$0.args"; printf %s ' + f"'{KEY_CMD}'")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", f"{helper} 'two words' $HOME ~ '*' ;touch\\ x `id`")
    assert [c.key for c in Settings().get_key_configs()] == [KEY_CMD]
    args = Path(str(helper) + ".args").read_text()
    assert args == "two words|$HOME|~|*|;touch x|`id`|"
    assert not (tmp_path / "x").exists()


@posix_only
def test_command_runs_with_null_stdin_and_root_cwd(tmp_path, monkeypatch):
    """The helper never sees the server's standard input (the MCP stream under stdio)."""
    helper = _helper(tmp_path, 'pwd > "$0.cwd"; cat > "$0.stdin"; printf %s ' + f"'{KEY_CMD}'")
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", str(helper))
    read_end, write_end = os.pipe()
    os.write(write_end, b'{"jsonrpc": "2.0", "method": "tools/call"}\n')
    os.close(write_end)
    saved = os.dup(0)
    os.dup2(read_end, 0)
    try:
        Settings()
    finally:
        os.dup2(saved, 0)
        os.close(saved)
        os.close(read_end)
    assert Path(str(helper) + ".cwd").read_text().strip() == "/"
    assert Path(str(helper) + ".stdin").read_text() == ""


@posix_only
def test_bare_helper_name_resolves_on_path(tmp_path, monkeypatch):
    _helper(tmp_path, f"printf %s '{KEY_CMD}'", name="unifi-key-helper")
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", "unifi-key-helper --flag")
    assert [c.key for c in Settings().get_key_configs()] == [KEY_CMD]


@posix_only
def test_keys_list_providers_success(tmp_path, monkeypatch):
    keys = [
        {"key": _key("east"), "label": "east"},
        {"key": _key("west"), "label": "west", "is_org_key": True},
    ]
    monkeypatch.setenv(
        "UNIFI_API_KEYS_FILE", str(_secret_file(tmp_path, json.dumps(keys, indent=2) + "\n"))
    )
    got = [(c.label, c.key, c.is_org_key) for c in Settings().get_key_configs()]
    assert got == [("east", _key("east"), False), ("west", _key("west"), True)]
    monkeypatch.delenv("UNIFI_API_KEYS_FILE")
    helper = _helper(tmp_path, f"cat <<'EOF'\n{json.dumps(keys)}\nEOF")
    monkeypatch.setenv("UNIFI_API_KEYS_COMMAND", str(helper))
    assert [c.label for c in Settings().get_key_configs()] == ["east", "west"]


@posix_only
def test_provider_runs_once_per_process(tmp_path, monkeypatch):
    helper = _helper(tmp_path, f"printf %s '{KEY_CMD}'")
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", str(helper))
    for _ in range(3):
        assert Settings().get_key_configs()[0].key == KEY_CMD
    assert _runs(tmp_path) == 1


def test_provider_settings_are_known_names():
    names = known_setting_names()
    for var in cp.PROVIDER_VARIABLES:
        assert var in names


# ----------------------------------------------------------------------------- whitespace


@pytest.mark.parametrize(
    "content, fragment",
    [
        (" " + KEY_FILE + "\n", "contains whitespace"),
        (KEY_FILE + " \n", "contains whitespace"),
        (KEY_FILE + "\t", "contains whitespace"),
        (KEY_FILE + "\nsecond-line\n", "2 lines"),
        ("\n\n", "empty value"),
        ("", "empty value"),
    ],
)
def test_file_whitespace_is_reported_not_stripped(tmp_path, monkeypatch, content, fragment):
    monkeypatch.setenv("UNIFI_API_KEY_FILE", str(_secret_file(tmp_path, content)))
    with pytest.raises(ValidationError) as info:
        Settings()
    text = _error_text(info.value)
    assert fragment in text
    assert KEY_FILE not in text
    assert "second-line" not in text


# ----------------------------------------------------------------------------- failures


def _refusal(monkeypatch, var: str, value: str) -> str:
    monkeypatch.setenv(var, value)
    with pytest.raises(ValidationError) as info:
        Settings()
    return _error_text(info.value)


def test_missing_file_is_actionable(tmp_path, monkeypatch):
    path = tmp_path / "absent"
    text = _refusal(monkeypatch, "UNIFI_API_KEY_FILE", str(path))
    assert "UNIFI_API_KEY_FILE names a file that does not exist" in text
    assert str(path) not in text


def test_relative_file_path_refused(monkeypatch):
    text = _refusal(monkeypatch, "UNIFI_API_KEY_FILE", "secrets/key")
    assert "UNIFI_API_KEY_FILE must be an absolute path" in text


def test_directory_refused(tmp_path, monkeypatch):
    text = _refusal(monkeypatch, "UNIFI_API_KEY_FILE", str(tmp_path))
    assert "names a path that is a directory" in text


@posix_only
def test_fifo_refused_without_blocking(tmp_path, monkeypatch):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    text = _refusal(monkeypatch, "UNIFI_API_KEY_FILE", str(fifo))
    assert "not a regular file" in text


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="root reads every file")
def test_unreadable_file_is_actionable(tmp_path, monkeypatch):
    path = _secret_file(tmp_path, KEY_FILE)
    path.chmod(0)
    text = _refusal(monkeypatch, "UNIFI_API_KEY_FILE", str(path))
    assert "cannot read; grant it read access" in text
    assert KEY_FILE not in text


def test_oversized_file_refused(tmp_path, monkeypatch):
    path = _secret_file(tmp_path, b"a" * (cp.MAX_PROVIDER_BYTES + 1))
    text = _refusal(monkeypatch, "UNIFI_API_KEY_FILE", str(path))
    assert f"larger than {cp.MAX_PROVIDER_BYTES} bytes" in text


def test_non_utf8_file_refused(tmp_path, monkeypatch):
    path = _secret_file(tmp_path, b"\xff\xfe-binary")
    text = _refusal(monkeypatch, "UNIFI_API_KEY_FILE", str(path))
    assert "is not UTF-8 text" in text


def test_malformed_keys_json_names_variable_not_content(tmp_path, monkeypatch):
    leak = _key("json")
    path = _secret_file(tmp_path, '[{"key": "' + leak + '", ')
    text = _refusal(monkeypatch, "UNIFI_API_KEYS_FILE", str(path))
    assert "UNIFI_API_KEYS_FILE did not produce valid JSON" in text
    assert leak not in text


@pytest.mark.parametrize(
    "value, fragment",
    [
        ("/bin/echo 'unterminated", "cannot be split into words"),
        ("   ", None),  # whitespace-only means unset: no provider, so no key at all
        ("bin/key-helper", "is a relative path"),
        ("no-such-helper-833-xyz", "was not found on PATH"),
        ("/nonexistent/key-helper", "is not an executable file"),
    ],
)
def test_malformed_helper_settings(monkeypatch, value, fragment):
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", value)
    if fragment is None:
        assert Settings().get_key_configs() == []
        return
    with pytest.raises(ValidationError) as info:
        Settings()
    text = _error_text(info.value)
    assert "UNIFI_API_KEY_COMMAND" in text
    assert fragment in text


@posix_only
@pytest.mark.parametrize(
    "body, fragment",
    [
        (f"printf %s '{KEY_CMD}'; echo 'diagnostic {KEY_CMD}' >&2; exit 3", "exited with status 3"),
        ("kill -9 $$", "was stopped by signal 9"),
        ("exit 0", "produced an empty value"),
        ("printf '\\n'", "produced an empty value"),
        (f"printf '%s\\n%s\\n' '{KEY_CMD}' '{KEY_CMD}'", "produced 2 lines"),
        ("printf '\\377\\376'", "is not UTF-8 text"),
    ],
)
def test_helper_failures_are_actionable_and_hide_output(tmp_path, monkeypatch, body, fragment):
    helper = _helper(tmp_path, body, name="keytool-833x")
    text = _refusal(monkeypatch, "UNIFI_API_KEY_COMMAND", f"{helper} --secret-arg-833")
    assert "UNIFI_API_KEY_COMMAND" in text
    assert fragment in text
    assert KEY_CMD not in text
    assert "--secret-arg-833" not in text
    assert str(helper) not in text and "keytool-833x" not in text
    assert "diagnostic" not in text


@posix_only
def test_helper_output_overflow_refused(tmp_path, monkeypatch):
    helper = _helper(tmp_path, "head -c 2000000 /dev/zero | tr '\\0' a")
    text = _refusal(monkeypatch, "UNIFI_API_KEY_COMMAND", str(helper))
    assert f"printed more than {cp.MAX_PROVIDER_BYTES} bytes" in text


@posix_only
def test_entrypoint_renders_provider_error_and_exits(tmp_path, monkeypatch, capsys):
    helper = _helper(tmp_path, f"printf %s '{KEY_CMD}' >&2; exit 4")
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", str(helper))
    with pytest.raises(SystemExit) as info:
        entrypoint._validate_api_key_configuration()
    assert info.value.code == 1
    err = capsys.readouterr().err
    assert "invalid configuration: UNIFI_API_KEY_COMMAND: the helper exited with status 4" in err
    assert KEY_CMD not in err


# ----------------------------------------------------------------------------- precedence


@posix_only
@pytest.mark.parametrize(
    "variables, expected",
    [
        (
            ("UNIFI_API_KEY", "UNIFI_API_KEY_FILE"),
            "UNIFI_API_KEY and UNIFI_API_KEY_FILE are set together",
        ),
        (
            ("UNIFI_API_KEY", "UNIFI_API_KEY_COMMAND"),
            "UNIFI_API_KEY and UNIFI_API_KEY_COMMAND are set together",
        ),
        (
            ("UNIFI_API_KEY_FILE", "UNIFI_API_KEY_COMMAND"),
            "UNIFI_API_KEY_FILE and UNIFI_API_KEY_COMMAND are set together",
        ),
        (
            ("UNIFI_API_KEYS", "UNIFI_API_KEYS_FILE"),
            "UNIFI_API_KEYS and UNIFI_API_KEYS_FILE are set together",
        ),
        (
            ("UNIFI_API_KEYS_FILE", "UNIFI_API_KEYS_COMMAND"),
            "UNIFI_API_KEYS_FILE and UNIFI_API_KEYS_COMMAND are set together",
        ),
        (
            ("UNIFI_API_KEYS", "UNIFI_API_KEY_FILE"),
            "UNIFI_API_KEYS and UNIFI_API_KEY_FILE are set together",
        ),
        (
            ("UNIFI_API_KEYS_FILE", "UNIFI_API_KEY"),
            "UNIFI_API_KEYS_FILE and UNIFI_API_KEY are set together",
        ),
        (
            ("UNIFI_API_KEYS_COMMAND", "UNIFI_API_KEY_COMMAND"),
            "UNIFI_API_KEYS_COMMAND and UNIFI_API_KEY_COMMAND are set together",
        ),
    ],
)
def test_conflicts_refuse_before_any_provider_runs(tmp_path, monkeypatch, variables, expected):
    single = _helper(tmp_path, f"printf %s '{KEY_CMD}'", name="single")
    many = _helper(tmp_path, "printf '[]'", name="many")
    values = {
        "UNIFI_API_KEY": KEY_DIRECT,
        "UNIFI_API_KEY_FILE": str(_secret_file(tmp_path, KEY_FILE)),
        "UNIFI_API_KEY_COMMAND": str(single),
        "UNIFI_API_KEYS": json.dumps([{"key": KEY_DIRECT, "label": "d"}]),
        "UNIFI_API_KEYS_FILE": str(_secret_file(tmp_path, "[]", name="keys.json")),
        "UNIFI_API_KEYS_COMMAND": str(many),
    }
    for var in variables:
        monkeypatch.setenv(var, values[var])
    with pytest.raises(ValidationError) as info:
        Settings()
    text = _error_text(info.value)
    assert expected in text
    assert KEY_DIRECT not in text
    assert _runs(tmp_path, "single") == 0
    assert _runs(tmp_path, "many") == 0


def test_direct_keys_compatibility_unchanged(monkeypatch):
    """Without a provider, UNIFI_API_KEYS still wins over UNIFI_API_KEY (unchanged)."""
    monkeypatch.setenv("UNIFI_API_KEY", KEY_DIRECT)
    monkeypatch.setenv("UNIFI_API_KEYS", json.dumps([{"key": _key("multi"), "label": "m"}]))
    assert [(c.label, c.key) for c in Settings().get_key_configs()] == [("m", _key("multi"))]
    monkeypatch.delenv("UNIFI_API_KEYS")
    assert [(c.label, c.key) for c in Settings().get_key_configs()] == [("default", KEY_DIRECT)]


def test_constructor_key_with_env_provider_conflicts(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEY_FILE", str(_secret_file(tmp_path, KEY_FILE)))
    with pytest.raises(ValidationError) as info:
        Settings(api_key=KEY_DIRECT)
    assert "UNIFI_API_KEY and UNIFI_API_KEY_FILE are set together" in _error_text(info.value)


def test_keys_file_labels_validated_like_keys(tmp_path, monkeypatch):
    dup = [{"key": _key("a"), "label": "x"}, {"key": _key("b"), "label": "x"}]
    monkeypatch.setenv("UNIFI_API_KEYS_FILE", str(_secret_file(tmp_path, json.dumps(dup))))
    with pytest.raises(ValidationError) as info:
        Settings()
    text = _error_text(info.value)
    assert "duplicate key labels" in text
    assert _key("a") not in text and _key("b") not in text


# ----------------------------------------------------------------------------- secrecy


@posix_only
def test_resolved_keys_join_central_scrubber_without_settings(tmp_path, monkeypatch):
    helper = _helper(tmp_path, f"printf %s '{KEY_CMD}'")
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", str(helper))
    Settings()
    # Callers that pass no Settings (code mode, connector, audit, diagnostics) still mask it.
    assert KEY_CMD in configured_secrets()
    keys = [{"key": _key("listed"), "label": "l"}]
    cp.reset()
    monkeypatch.delenv("UNIFI_API_KEY_COMMAND")
    monkeypatch.setenv("UNIFI_API_KEYS_FILE", str(_secret_file(tmp_path, json.dumps(keys))))
    Settings()
    assert _key("listed") in configured_secrets()


@posix_only
def test_keys_absent_from_logs_reprs_and_tracebacks(tmp_path, monkeypatch, caplog):
    from unifi_fabric.secret_scrub import install_log_scrubber

    install_log_scrubber()
    caplog.set_level(logging.DEBUG)
    helper = _helper(tmp_path, f"printf %s '{KEY_CMD}'")
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", f"{helper} --arg")
    settings = Settings()
    log = logging.getLogger("unifi_fabric.test_833")
    log.warning("loaded %s", settings.get_key_configs()[0].key)
    try:
        raise RuntimeError(f"boom {settings.api_key}")
    except RuntimeError:
        log.exception("failure")
    rendered = "\n".join(logging.Formatter().format(r) for r in caplog.records)
    assert KEY_CMD not in rendered
    assert KEY_CMD not in repr(settings)
    assert KEY_CMD not in str(settings)
    assert KEY_CMD not in repr(settings.get_key_configs())


def test_provider_paths_not_in_repr_of_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_API_KEY_FILE", str(_secret_file(tmp_path, KEY_FILE)))
    settings = Settings()
    assert KEY_FILE not in repr(settings)
    assert "api_key_file" not in repr(settings)


# ----------------------------------------------------------------------------- isolation


@posix_only
def test_header_mode_never_reads_or_runs_a_provider(tmp_path, monkeypatch):
    helper = _helper(tmp_path, f"printf %s '{KEY_CMD}'")
    monkeypatch.setenv("UNIFI_KEY_MODE", "header")
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", str(helper))
    monkeypatch.setenv("UNIFI_API_KEYS_FILE", str(tmp_path / "absent.json"))
    settings = Settings()
    assert settings.get_key_configs() == []
    assert _runs(tmp_path) == 0
    assert KEY_CMD not in configured_secrets()


def _header_source(pairs):
    def source(name):
        return [v for n, v in pairs if n.lower() == name.lower()]

    return source


@posix_only
async def test_request_headers_cannot_run_provider_or_change_process_keys(tmp_path, monkeypatch):
    """Environment mode: provider-shaped and injection-shaped headers on tools/call never
    run a helper, never change the process keys and are refused as before."""
    from fastmcp import Client

    from unifi_fabric import server

    marker = tmp_path / "injected"
    helper = _helper(tmp_path, f"printf %s '{KEY_CMD}'")
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", str(helper))
    assert server.get_settings().get_key_configs()[0].key == KEY_CMD
    assert _runs(tmp_path) == 1
    pairs = [
        ("UNIFI_API_KEY_COMMAND", f"/bin/sh -c 'touch {marker}'"),
        ("UNIFI_API_KEY_FILE", "/etc/passwd"),
        ("X-UniFi-Api-Key", json.dumps({"x": f"$(touch {marker})"})),
    ]
    monkeypatch.setattr(hc, "_raw_header_values", _header_source(pairs))
    async with Client(server.mcp) as client:
        result = await client.call_tool("list_hosts", {}, raise_on_error=False)
    assert result.is_error
    assert json.loads(result.content[0].text)["error"]["code"] == "invalid_api_key_header"
    assert not marker.exists()
    assert _runs(tmp_path) == 1
    assert [c.key for c in server.get_settings().get_key_configs()] == [KEY_CMD]
    assert os.environ["UNIFI_API_KEY_COMMAND"] == str(helper)


@posix_only
async def test_header_mode_header_keys_still_work_with_provider_configured(tmp_path, monkeypatch):
    """Header mode with a provider configured: the request's own key is used, the provider
    never runs, and a provider-shaped header is just an unknown header."""
    import httpx
    from fastmcp import Client

    from unifi_fabric import server
    from unifi_fabric.client import UniFiClient

    helper = _helper(tmp_path, f"printf %s '{KEY_CMD}'")
    request_key = _key("request")
    monkeypatch.setenv("UNIFI_KEY_MODE", "header")
    hc.set_process_key_mode(None)
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", str(helper))
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("X-API-KEY", ""))
        return httpx.Response(200, json={"data": []}, request=request)

    def factory(self, key_config):
        return httpx.AsyncClient(
            base_url=self._settings.api_base_url,
            headers={"X-API-KEY": key_config.key, "Accept": "application/json"},
            transport=httpx.MockTransport(handler),
        )

    monkeypatch.setattr(UniFiClient, "_new_http_client", factory)
    pairs = [
        ("X-UniFi-Api-Key", json.dumps({"alpha": request_key})),
        ("UNIFI_API_KEY_COMMAND", f"/bin/sh -c 'touch {tmp_path / 'x'}'"),
    ]
    monkeypatch.setattr(hc, "_raw_header_values", _header_source(pairs))
    async with Client(server.mcp) as client:
        await client.call_tool("list_hosts", {}, raise_on_error=False)
    assert _runs(tmp_path) == 0
    assert not (tmp_path / "x").exists()
    assert KEY_CMD not in seen
    assert seen and set(seen) == {request_key}


@posix_only
@pytest.mark.parametrize("configured", ["UNIFI_API_KEY_COMMAND", "UNIFI_API_KEYS_FILE"])
def test_header_mode_startup_warning_names_ignored_providers(
    tmp_path, monkeypatch, caplog, configured
):
    """server.main under header mode logs the ignored provider setting and runs nothing."""
    import fastmcp

    from unifi_fabric import server
    from unifi_fabric.config import MCPTransportSettings

    helper = _helper(tmp_path, f"printf %s '{KEY_CMD}'")
    value = str(helper) if configured.endswith("COMMAND") else str(tmp_path / "absent.json")
    monkeypatch.setenv("UNIFI_KEY_MODE", "header")
    monkeypatch.setenv(configured, value)
    hc.set_process_key_mode(None)
    runs: list[dict] = []
    config = MCPTransportSettings()
    monkeypatch.setattr(server, "_configure_transport", lambda: config)
    monkeypatch.setattr(server, "_reconcile_stateless_http", lambda: None)
    monkeypatch.setattr(server, "_print_startup_warnings", lambda settings: None)
    monkeypatch.setattr(fastmcp.settings, "transport", "streamable-http")
    monkeypatch.setattr(server.mcp, "run", lambda **kwargs: runs.append(kwargs))
    caplog.set_level(logging.WARNING)
    server.main()
    assert len(runs) == 1
    warnings = [r.getMessage() for r in caplog.records if "UNIFI_KEY_MODE=header" in r.getMessage()]
    assert len(warnings) == 1
    assert configured in warnings[0]
    assert "no helper is run" in warnings[0]
    assert server.ignored_key_settings(server.get_settings()) == [configured]
    assert _runs(tmp_path) == 0


@pytest.mark.parametrize(
    ("content", "kind"),
    [
        ("123", "number"),
        ("true", "boolean"),
        ("null", "null"),
        ('"text"', "string"),
        ("{}", "object"),
    ],
)
def test_keys_provider_non_list_json_refused(tmp_path, monkeypatch, content, kind):
    path = _secret_file(tmp_path, content)
    text = _refusal(monkeypatch, "UNIFI_API_KEYS_FILE", str(path))
    assert f"UNIFI_API_KEYS_FILE produced a JSON {kind}, not a list" in text


def test_keys_provider_object_with_key_is_not_echoed(tmp_path, monkeypatch):
    leak = _key("object")
    path = _secret_file(tmp_path, json.dumps({"key": leak, "label": "x"}))
    text = _refusal(monkeypatch, "UNIFI_API_KEYS_FILE", str(path))
    assert "produced a JSON object, not a list" in text
    assert leak not in text


def test_helper_module_is_never_imported_by_request_paths():
    """Only the settings model calls the provider resolver (single entry point)."""
    root = Path(cp.__file__).parent
    callers = sorted(
        str(p.relative_to(root))
        for p in root.rglob("*.py")
        if p.name != "credential_providers.py" and "credential_providers" in p.read_text()
    )
    assert callers == ["config.py", "secret_scrub.py"]


def test_file_mode_is_untouched(tmp_path, monkeypatch):
    path = _secret_file(tmp_path, KEY_FILE)
    path.chmod(0o400)
    monkeypatch.setenv("UNIFI_API_KEY_FILE", str(path))
    Settings()
    assert stat.S_IMODE(path.stat().st_mode) == 0o400


@pytest.mark.parametrize("var", ["UNIFI_API_KEY_FILE", "UNIFI_API_KEYS_FILE"])
def test_file_errors_never_echo_the_path(tmp_path, monkeypatch, var):
    """A key pasted into a *_FILE variable must not come back in the error."""
    secret_shaped = _key("pasted")
    for value in (secret_shaped, f"/{secret_shaped}", str(tmp_path / secret_shaped)):
        text = _refusal(monkeypatch, var, value)
        assert secret_shaped not in text


@pytest.mark.parametrize("var", ["UNIFI_API_KEY_COMMAND", "UNIFI_API_KEYS_COMMAND"])
def test_command_errors_never_echo_the_helper(tmp_path, monkeypatch, var):
    secret_shaped = _key("pasted")
    for value in (secret_shaped, f"bin/{secret_shaped}", f"/{secret_shaped}", f"'{secret_shaped}"):
        text = _refusal(monkeypatch, var, value)
        assert secret_shaped not in text


# ----------------------------------------------------------------------------- Review fixes

_SECRET_NAMES = (
    "MCP_BEARER_TOKEN",
    "MCP_TLS_KEY_PASSWORD",
    "UNIFI_AUDIT_HMAC_KEY",
    "UNIFI_API_KEYS",
    "UNIFI_API_KEY_FILE",
    "UNIFI_API_KEYS_COMMAND",
    "UNIFI_API_KEY_EXTRA",
    "UNIFI_SOME_CLIENT_SECRET",
)


def _env_dump_names(tmp_path, monkeypatch) -> set[str]:
    """Run a helper that dumps its environment; return the variable names it saw."""
    helper = _helper(tmp_path, f"env > '{tmp_path}/env.dump'; printf %s '{KEY_CMD}'")
    for name in _SECRET_NAMES:
        monkeypatch.setenv(name, _key("envsecret"))
    # The audit key is validated as 32 bytes of base64url; built at run time.
    monkeypatch.setenv(
        "UNIFI_AUDIT_HMAC_KEY", base64.urlsafe_b64encode(bytes(32)).rstrip(b"=").decode()
    )
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", str(helper))
    monkeypatch.setenv("UNIFI_API_KEYS", "")  # blank = unset for the settings model
    monkeypatch.setenv("UNIFI_API_KEYS_COMMAND", "")
    monkeypatch.setenv("UNIFI_API_KEY_FILE", "")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("LANG", "C.UTF-8")
    monkeypatch.setenv("PWMANAGER_SESSION", "kept")
    Settings()
    lines = (tmp_path / "env.dump").read_text().splitlines()
    return {line.split("=", 1)[0] for line in lines if "=" in line}


@posix_only
def test_helper_environment_excludes_every_server_secret(tmp_path, monkeypatch):
    """The helper gets the server's environment minus its secrets."""
    seen = _env_dump_names(tmp_path, monkeypatch)
    dump = (tmp_path / "env.dump").read_text()
    leaked = seen & (set(_SECRET_NAMES) | {"UNIFI_API_KEY_COMMAND"})
    assert not leaked, f"helper environment holds {sorted(leaked)}"
    assert _key("envsecret") not in dump
    assert base64.urlsafe_b64encode(bytes(32)).rstrip(b"=").decode() not in dump
    # Everything the helper needs to run, and the helper's own variables, stay.
    assert {"PATH", "HOME", "LANG", "PWMANAGER_SESSION"} <= seen


@posix_only
def test_helper_environment_filter_is_what_protects_the_helper(tmp_path, monkeypatch):
    """Negative control: with the filtering removed the same check must fail."""
    monkeypatch.setattr(cp, "helper_environment", lambda environ=None: dict(os.environ))
    seen = _env_dump_names(tmp_path, monkeypatch)
    assert {"MCP_BEARER_TOKEN", "MCP_TLS_KEY_PASSWORD", "UNIFI_AUDIT_HMAC_KEY"} <= seen


def test_helper_environment_covers_the_scrubber_names(monkeypatch):
    from unifi_fabric import secret_scrub

    environ = {name: "x" for name in (*secret_scrub.SECRET_ENV_VARS, secret_scrub.KEYS_ENV_VAR)}
    environ.update({"PATH": "/usr/bin", "HOME": "/h", "TMPDIR": "/t", "LC_ALL": "C"})
    assert cp.helper_environment(environ) == {
        "PATH": "/usr/bin",
        "HOME": "/h",
        "TMPDIR": "/t",
        "LC_ALL": "C",
    }


@posix_only
@pytest.mark.parametrize("path_entry", ["", "."])
def test_bare_helper_found_via_relative_path_entry_is_refused(tmp_path, monkeypatch, path_entry):
    """A PATH with an empty or '.' entry must not resolve a helper in the cwd."""
    _helper(tmp_path, f"printf %s '{KEY_CMD}'", name="unifi-key-helper")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", f"{path_entry}{os.pathsep}/usr/bin")
    text = _refusal(monkeypatch, "UNIFI_API_KEY_COMMAND", "unifi-key-helper")
    assert "UNIFI_API_KEY_COMMAND" in text
    assert "relative PATH entry" in text
    assert _runs(tmp_path, "unifi-key-helper") == 0
    assert str(tmp_path) not in text


@posix_only
def test_invalid_key_mode_refused_before_any_provider_runs_on_server_main(
    tmp_path, monkeypatch, capsys
):
    """A mistyped UNIFI_KEY_MODE is refused by server.main before the helper runs."""
    from unifi_fabric import server

    helper = _helper(tmp_path, f"printf %s '{KEY_CMD}'")
    monkeypatch.setenv("UNIFI_KEY_MODE", "hedaer")
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", str(helper))
    monkeypatch.setattr(server, "_settings", None)
    with pytest.raises(SystemExit) as info:
        server.main()
    assert info.value.code == 1
    assert capsys.readouterr().err.strip().splitlines()[-1] == "startup:UNIFI_KEY_MODE"
    assert _runs(tmp_path) == 0


@posix_only
def test_explicit_environment_mode_still_runs_the_provider(tmp_path, monkeypatch):
    helper = _helper(tmp_path, f"printf %s '{KEY_CMD}'")
    monkeypatch.setenv("UNIFI_KEY_MODE", "environment")
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", str(helper))
    assert [c.key for c in Settings().get_key_configs()] == [KEY_CMD]
    assert _runs(tmp_path) == 1


@posix_only
@pytest.mark.parametrize("bits", [0o620, 0o602])
def test_key_file_writable_by_group_or_other_warns_once(tmp_path, monkeypatch, caplog, bits):
    """the warning names the variable only, and fires once per process."""
    path = _secret_file(tmp_path, KEY_FILE)
    path.chmod(bits)
    monkeypatch.setenv("UNIFI_API_KEY_FILE", str(path))
    with caplog.at_level(logging.WARNING):
        Settings()
        Settings()
    warnings = [r.getMessage() for r in caplog.records if "writable by group" in r.getMessage()]
    assert len(warnings) == 1
    assert warnings[0].startswith("UNIFI_API_KEY_FILE: the key file")
    assert str(tmp_path) not in warnings[0] and KEY_FILE not in warnings[0]


@posix_only
@pytest.mark.parametrize("mode", [0o400, 0o600, 0o644, 0o440])
def test_readable_key_file_does_not_warn(tmp_path, monkeypatch, caplog, mode):
    path = _secret_file(tmp_path, KEY_FILE)
    path.chmod(mode)
    monkeypatch.setenv("UNIFI_API_KEY_FILE", str(path))
    with caplog.at_level(logging.WARNING):
        Settings()
    assert not [r for r in caplog.records if "writable" in r.getMessage()]


@posix_only
def test_helper_writable_by_group_or_directory_open_warns(tmp_path, monkeypatch, caplog):
    helper = _helper(tmp_path, f"printf %s '{KEY_CMD}'")
    helper.chmod(0o770)
    tmp_path.chmod(0o770)
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", str(helper))
    try:
        with caplog.at_level(logging.WARNING):
            Settings()
    finally:
        tmp_path.chmod(0o700)
    text = " | ".join(r.getMessage() for r in caplog.records)
    assert "UNIFI_API_KEY_COMMAND: the helper executable is writable by group or others" in text
    assert "UNIFI_API_KEY_COMMAND: the helper's directory is writable by group or others" in text
    assert str(tmp_path) not in text and KEY_CMD not in text


@posix_only
def test_private_helper_does_not_warn(tmp_path, monkeypatch, caplog):
    helper = _helper(tmp_path, f"printf %s '{KEY_CMD}'")
    monkeypatch.setenv("UNIFI_API_KEY_COMMAND", str(helper))
    with caplog.at_level(logging.WARNING):
        Settings()
    assert not [r for r in caplog.records if "writable" in r.getMessage()]


def test_otlp_header_name_match_is_anchored_at_the_true_end() -> None:
    """``$`` also matches before a trailing newline; the name must end at ``\\Z``."""
    assert cp._OTLP_HEADERS.match("OTEL_EXPORTER_OTLP_HEADERS")
    assert cp._OTLP_HEADERS.match("OTEL_EXPORTER_OTLP_HEADERS\n") is None


def test_helper_environment_withholds_the_otlp_collector_headers() -> None:
    """OTEL_EXPORTER_OTLP_*HEADERS carry the collector credential (tracing docs)."""
    environ = {
        "OTEL_EXPORTER_OTLP_HEADERS": "authorization=x",
        "OTEL_EXPORTER_OTLP_TRACES_HEADERS": "authorization=x",
        "otel_exporter_otlp_metrics_headers": "authorization=x",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.test",
        "PATH": "/usr/bin",
    }
    assert cp.helper_environment(environ) == {
        "OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.test",
        "PATH": "/usr/bin",
    }
