"""Trusted startup credential providers: API keys read from a file or a helper command.

The operator who starts the server can keep UniFi API keys out of the server's own
configuration and point at where they live instead:

* ``UNIFI_API_KEY_FILE`` -- the absolute path of a file holding one API key;
* ``UNIFI_API_KEY_COMMAND`` -- a helper command whose standard output is one API key;
* ``UNIFI_API_KEYS_FILE`` / ``UNIFI_API_KEYS_COMMAND`` -- the same for the
  ``UNIFI_API_KEYS`` JSON list (multi-key setups).

They are resolved once per process, while the settings load at startup, and only from
the server's own configuration (its environment or the ``Settings`` constructor). Tool
arguments and request headers never reach this module: nothing here is called on a
request path, and ``UNIFI_KEY_MODE=header`` reads no provider at all.

Argument model of a ``*_COMMAND`` value: it is split with POSIX shell quoting rules
(:func:`shlex.split`: quotes and backslashes group words) and run directly, never by a
shell, so there is no variable, ``~``, glob, pipe or redirection expansion. The first
word is the helper: an absolute path, or a bare name looked up on ``PATH``. The helper
runs with the server's environment minus every secret the server holds (the UniFi API key
settings, the bearer token, the TLS key password, the audit HMAC key and any other
``UNIFI_`` / ``MCP_`` name that looks like a secret; see :func:`helper_environment`),
working directory ``/``, standard input from the
null device and standard error discarded (a helper may print the key to either stream).
It is awaited to completion: like every other operation of this server it has no
elapsed-time cap, so a helper that never exits keeps the server from starting.

Whitespace: a single-key file or helper output loses any number of trailing line breaks
(every ``\\r`` and ``\\n`` at the end, as editors and ``echo`` add) and a UTF-8 byte order
mark; nothing else is stripped. A value with a line break inside, or spaces around it,
is refused by the same credential check as ``UNIFI_API_KEY``. A JSON provider's text is
parsed as JSON as is.

Errors name the setting and the problem, never its value: not the path, the helper or its
arguments (a value set in the wrong variable may itself be a key), nor the file content or
the helper's output. Every resolved value is
registered with the central scrubber (:func:`resolved_secret_values`), so it is masked
in logs, errors and the audit log like a key set directly.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import stat
import subprocess
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

#: The single-key family: (direct setting, file provider, command provider).
API_KEY = "UNIFI_API_KEY"
API_KEY_FILE = "UNIFI_API_KEY_FILE"
API_KEY_COMMAND = "UNIFI_API_KEY_COMMAND"
#: The multi-key family.
API_KEYS = "UNIFI_API_KEYS"
API_KEYS_FILE = "UNIFI_API_KEYS_FILE"
API_KEYS_COMMAND = "UNIFI_API_KEYS_COMMAND"

#: Settings field name of each variable.
FIELD_OF = {
    API_KEY: "api_key",
    API_KEY_FILE: "api_key_file",
    API_KEY_COMMAND: "api_key_command",
    API_KEYS: "api_keys",
    API_KEYS_FILE: "api_keys_file",
    API_KEYS_COMMAND: "api_keys_command",
}
PROVIDER_VARIABLES = (API_KEY_FILE, API_KEY_COMMAND, API_KEYS_FILE, API_KEYS_COMMAND)

#: Largest provider content read. An input-safety bound on a startup read (a mistyped
#: path at a huge file or a helper that streams forever), not a response cap; an API
#: key is about 32 bytes and a JSON list of a thousand keys well under 1 MiB.
MAX_PROVIDER_BYTES = 1024 * 1024

_BOM = "﻿"


_log = logging.getLogger(__name__)

#: Names of this server's own settings that look like secrets: they are never passed on to
#: a helper (the helper reads the key from its own store, not from the server's secrets).
_SECRET_NAME = re.compile(
    r"^(?:UNIFI|MCP)_.*(?:KEY|TOKEN|SECRET|PASSWORD|PASSPHRASE)", re.IGNORECASE
)

#: The OTLP exporter header variables (``OTEL_EXPORTER_OTLP_HEADERS`` and the per-signal
#: forms) carry the collector credential.
_OTLP_HEADERS = re.compile(r"^OTEL_EXPORTER_OTLP(?:_[A-Z]+)?_HEADERS\Z", re.IGNORECASE)


def helper_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment a helper command runs with: the server's, minus its secrets.

    Removes every name the central scrubber treats as a secret variable
    (``secret_scrub.SECRET_ENV_VARS`` and ``UNIFI_API_KEYS``), every ``UNIFI_API_KEY*``
    name (the direct key and the file / command provider settings) and any ``UNIFI_*`` /
    ``MCP_*`` name containing KEY, TOKEN, SECRET, PASSWORD or PASSPHRASE, and the
    ``OTEL_EXPORTER_OTLP_*HEADERS`` collector credentials. Everything else
    (PATH, HOME, locale, TMPDIR, the password manager's own variables) is kept.
    """
    # Imported here: secret_scrub imports this module at load time.
    from .secret_scrub import KEYS_ENV_VAR, SECRET_ENV_VARS

    blocked = {name.upper() for name in (*SECRET_ENV_VARS, KEYS_ENV_VAR)}
    source = os.environ if environ is None else environ
    return {
        name: value
        for name, value in source.items()
        if name.upper() not in blocked
        and not name.upper().startswith(API_KEY)
        and not _SECRET_NAME.match(name)
        and not _OTLP_HEADERS.match(name)
    }


class ProviderError(ValueError):
    """An unusable provider setting; the message never holds a secret."""


@dataclass(frozen=True)
class _Family:
    direct: str
    file: str
    command: str
    is_list: bool


_KEY = _Family(API_KEY, API_KEY_FILE, API_KEY_COMMAND, is_list=False)
_KEYS = _Family(API_KEYS, API_KEYS_FILE, API_KEYS_COMMAND, is_list=True)

# Resolved values, keyed by (variable, configured value): a provider runs once per process
# even though settings load more than once at startup (entrypoint check, then the server).
_lock = threading.Lock()
_resolved: dict[tuple[str, str], Any] = {}
_secret_values: list[str] = []


def reset() -> None:
    """Forget every resolved provider value (tests; a process never needs this)."""
    with _lock:
        _resolved.clear()
        _secret_values.clear()


def resolved_secret_values() -> tuple[str, ...]:
    """Every key value a provider has produced in this process, for the scrubber."""
    with _lock:
        return tuple(_secret_values)


def _present(data: Mapping[str, Any], field: str) -> bool:
    value = data.get(field)
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value)
    return True


def configured_providers(data: Mapping[str, Any]) -> list[str]:
    """The provider variables set in ``data`` (Settings field names as keys)."""
    return [var for var in PROVIDER_VARIABLES if _present(data, FIELD_OF[var])]


def _check_conflicts(data: Mapping[str, Any]) -> None:
    problems: list[str] = []
    set_by_family: dict[str, list[str]] = {}
    for family in (_KEY, _KEYS):
        spellings = [
            var
            for var in (family.direct, family.file, family.command)
            if _present(data, FIELD_OF[var])
        ]
        set_by_family[family.direct] = spellings
        if len(spellings) > 1:
            problems.append(
                f"{_listed(spellings)} are set together; set exactly one of {family.direct}, "
                f"{family.file} or {family.command}"
            )
    one, many = set_by_family[API_KEY], set_by_family[API_KEYS]
    providers = [var for var in one + many if var in PROVIDER_VARIABLES]
    if one and many and providers:
        problems.append(
            f"{_listed(many + one)} are set together; a key file or helper command "
            f"cannot be combined with the other key setting. Use {API_KEYS} (or "
            f"{API_KEYS_FILE} / {API_KEYS_COMMAND}) for several keys, or {API_KEY} (or "
            f"{API_KEY_FILE} / {API_KEY_COMMAND}) for one"
        )
    if problems:
        raise ProviderError("; ".join(problems))


def _listed(names: list[str]) -> str:
    if len(names) <= 1:
        return "".join(names)
    return ", ".join(names[:-1]) + " and " + names[-1]


def resolve_into(data: dict[str, Any]) -> None:
    """Resolve the configured providers of ``data`` (Settings input, field names as
    keys) into ``api_key`` / ``api_keys``, in place; raise :class:`ProviderError`.

    Checks every conflict before reading any file or running any helper.
    """
    if not configured_providers(data):
        return
    _check_conflicts(data)
    for family in (_KEY, _KEYS):
        for var, reader in ((family.file, _read_file), (family.command, _run_command)):
            field = FIELD_OF[var]
            if not _present(data, field):
                continue
            setting = data[field]
            if not isinstance(setting, str):
                raise ProviderError(f"{var} must be text")
            data[FIELD_OF[family.direct]] = _resolve(var, setting, family, reader)


def _resolve(var: str, setting: str, family: _Family, reader: Any) -> Any:
    memo_key = (var, setting)
    with _lock:
        if memo_key in _resolved:
            return _resolved[memo_key]
    text = reader(var, setting)
    value = _parse(var, text, family)
    with _lock:
        _resolved[memo_key] = value
        if family.is_list:
            _secret_values.extend(
                item["key"]
                for item in value
                if isinstance(item, dict) and isinstance(item.get("key"), str)
            )
        else:
            _secret_values.append(value)
    return value


def _parse(var: str, text: str, family: _Family) -> Any:
    if text.startswith(_BOM):
        text = text[len(_BOM) :]
    if family.is_list:
        if not text.strip():
            raise ProviderError(f"{var} produced an empty value; expected a JSON list of keys")
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            # json's message holds a position only, never the document.
            raise ProviderError(
                f"{var} did not produce valid JSON ({_json_reason(exc)}); expected the "
                f"{API_KEYS} format, a JSON list of key objects. The content is not shown"
            ) from None
        if not isinstance(parsed, list):
            # Checked here, before the value reaches the settings model: a JSON object or
            # scalar is never echoed back, and every accepted key is registered for scrubbing.
            raise ProviderError(
                f"{var} produced a JSON {_json_kind(parsed)}, not a list; expected the "
                f"{API_KEYS} format, a JSON list of key objects. The content is not shown"
            )
        return parsed
    value = text.rstrip("\r\n")
    if not value:
        raise ProviderError(f"{var} produced an empty value; it must hold the API key on one line")
    lines = value.splitlines()
    if len(lines) > 1:
        raise ProviderError(
            f"{var} produced {len(lines)} lines; expected exactly one line holding the API "
            "key (only a trailing line break is removed). The content is not shown"
        )
    return value


def _json_kind(value: object) -> str:
    if isinstance(value, dict):
        return "object"
    if isinstance(value, str):
        return "string"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return "null"


def _json_reason(exc: ValueError) -> str:
    if isinstance(exc, json.JSONDecodeError):
        return f"{exc.msg} at line {exc.lineno} column {exc.colno}"
    return "not JSON"


# ----------------------------------------------------------------------------- file


def _read_file(var: str, setting: str) -> str:
    path = os.path.expanduser(setting)
    if not os.path.isabs(path):
        raise ProviderError(
            f"{var} must be an absolute path (got a relative path, which would depend on "
            "the directory the server starts in); give the full path of the key file"
        )
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise ProviderError(f"{var} names a file that does not exist") from None
    except PermissionError:
        raise ProviderError(
            f"{var} names a file this server's user cannot read; grant it read "
            "access (for example chmod 400 owned by that user)"
        ) from None
    except OSError as exc:
        raise ProviderError(f"{var} names a file that cannot be opened ({exc.strerror})") from None
    try:
        info = os.fstat(fd)
        if stat.S_ISREG(info.st_mode):
            _warn_writable(var, "the key file", info.st_mode)
        if not stat.S_ISREG(info.st_mode):
            kind = "a directory" if stat.S_ISDIR(info.st_mode) else "not a regular file"
            raise ProviderError(
                f"{var} names a path that is {kind}; point it at the file holding the key"
            )
        chunks: list[bytes] = []
        size = 0
        while size <= MAX_PROVIDER_BYTES:
            chunk = os.read(fd, MAX_PROVIDER_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except OSError as exc:
        raise ProviderError(f"{var} names a file that cannot be read ({exc.strerror})") from None
    finally:
        os.close(fd)
    if size > MAX_PROVIDER_BYTES:
        raise ProviderError(
            f"{var} names a file larger than {MAX_PROVIDER_BYTES} bytes; "
            "point it at the file holding only the key"
        )
    return _decode(var, b"".join(chunks), "the file")


def _decode(var: str, raw: bytes, what: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ProviderError(f"{var}: {what} is not UTF-8 text. The content is not shown") from None


# ----------------------------------------------------------------------------- command


def parse_command(var: str, setting: str) -> list[str]:
    """The helper argv of a ``*_COMMAND`` value (POSIX quoting, no shell); raise on a
    malformed value. The executable is resolved to an absolute path."""
    try:
        argv = shlex.split(setting, posix=True)
    except ValueError as exc:
        raise ProviderError(
            f"{var} cannot be split into words ({exc}); quote it with POSIX shell rules, for "
            "example /usr/local/bin/key-helper --item 'UniFi API key'"
        ) from None
    if not argv:
        raise ProviderError(f"{var} holds no command; give the helper and its arguments")
    program = argv[0]
    if os.path.isabs(program):
        resolved = program
    elif os.sep in program or (os.altsep and os.altsep in program):
        raise ProviderError(
            f"{var}: the helper (its first word) is a relative path; give its absolute path or a "
            "bare name found on PATH"
        )
    else:
        found = shutil.which(program)
        if found is None:
            raise ProviderError(
                f"{var}: the helper (its first word) was not found on PATH; give its absolute path "
                "or install it"
            )
        if not os.path.isabs(found):
            raise ProviderError(
                f"{var}: the helper (its first word) was found through a relative PATH entry "
                "(an empty or '.' entry); give the helper's absolute path or remove that PATH entry"
            )
        resolved = found
    if not os.path.isfile(resolved) or not os.access(resolved, os.X_OK):
        raise ProviderError(
            f"{var}: the helper (its first word) is not an executable file; check the path and its "
            "execute permission"
        )
    return [resolved, *argv[1:]]


def _warn_writable(var: str, what: str, mode: int) -> None:
    """Warn (the variable only, never a path or value) when ``what`` is open to others."""
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        _log.warning(
            "%s: %s is writable by group or others; anyone who can write it can change what "
            "the server runs or reads as its API key. Restrict it to its owner",
            var,
            what,
        )


def _warn_helper_permissions(var: str, program: str) -> None:
    try:
        _warn_writable(var, "the helper executable", os.stat(program).st_mode)
        parent = os.stat(os.path.dirname(program))
    except OSError:
        return
    if not parent.st_mode & stat.S_ISVTX:
        _warn_writable(var, "the helper's directory", parent.st_mode)


def _run_command(var: str, setting: str) -> str:
    argv = parse_command(var, setting)
    _warn_helper_permissions(var, argv[0])
    try:
        proc = subprocess.Popen(  # noqa: S603 - operator-configured argv, never a shell
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=os.sep,
            env=helper_environment(),
            close_fds=True,
            shell=False,
        )
    except OSError as exc:
        raise ProviderError(f"{var}: the helper could not start ({exc.strerror})") from None
    if proc.stdout is None:  # pragma: no cover - stdout=PIPE always provides it
        raise ProviderError(f"{var}: the helper has no output stream")
    with proc.stdout:
        raw = proc.stdout.read(MAX_PROVIDER_BYTES + 1)
        overflow = len(raw) > MAX_PROVIDER_BYTES
        if overflow:
            proc.kill()
    status = proc.wait()
    if overflow:
        raise ProviderError(
            f"{var}: the helper printed more than {MAX_PROVIDER_BYTES} bytes; it must "
            "print only the key. Its output is not shown"
        )
    if status != 0:
        how = f"was stopped by signal {-status}" if status < 0 else f"exited with status {status}"
        raise ProviderError(
            f"{var}: the helper {how}. Its output is not shown; run the helper "
            "yourself as the server's user to see why"
        )
    return _decode(var, raw, "the helper output")
