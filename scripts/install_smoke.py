#!/usr/bin/env python3
"""Run marked documentation launchers against local wheel/sdist and a synthetic upstream.

Only the documented launcher is executed. Interactive client install/setup instructions
remain explicitly non-executable. Package pins are substituted with local artifacts;
client configuration is parsed, then its declared command is probed over MCP stdio.
Docker uses the same local wheel, and is required on Linux only.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

import _install_probe
from extract_install_cases import (
    DOCKER_DEFERRED_REASON,
    PLATFORM_ONLY,
    PLATFORM_ONLY_REASON,
    ROOT,
    extract_cases,
)

PACKAGE = "unifi-fabric-mcp-server"
ENTRY = "unifi-fabric-mcp"
PUBLISHED_VERSION_FILE = ROOT / "scripts/published-version.txt"
WRONG_KEY = "install-test-invalid-key"
GOOD_MOCK_KEY = "install-test-synthetic-key"
# A documented path is taken literally, so any character a shell would expand or
# interpret (variables, command substitution, globs, braces, history, %VAR%) is rejected:
# the smoke must never create a literal "$HOME" directory and call it the documented one.
SHELL_EXPANSION = frozenset("$`~*?[]{}!%\\;|&<>()\"'")
WORK_HOME: Path | None = None


def clean_env() -> dict[str, str]:
    # Do not read or pass any service credential from the host.
    allowed = ("PATH", "LD_LIBRARY_PATH", "SYSTEMROOT", "COMSPEC", "WINDIR", "TEMP", "TMP")
    env = {name: os.environ[name] for name in allowed if name in os.environ}
    if WORK_HOME:
        env["HOME"] = str(WORK_HOME)
    return env


def docker_env() -> dict[str, str]:
    """Allow Docker connection settings only for the host Docker CLI."""
    env = clean_env()
    for name in ("DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


def start_mock() -> tuple[http.server.ThreadingHTTPServer, str]:
    """The synthetic Site Manager upstream (scripts/_install_probe.py), bound to
    every interface: a Docker container reaches it through the host gateway."""
    return _install_probe.start_mock(GOOD_MOCK_KEY, bind=_install_probe.ALL_INTERFACES)


# --------------------------------------------------------------------- MCP stdio probe
def _rpc(proc: subprocess.Popen, message: dict) -> dict | None:
    if proc.stdin is None or proc.stdout is None:
        raise RuntimeError("server pipes are not open")
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()
    if "id" not in message:
        return None
    while True:
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed stdout")
        reply = json.loads(line)
        if reply.get("id") == message["id"]:
            return reply


def session(
    cmd: list[str],
    env: dict[str, str],
    call: bool = True,
    *,
    base_env: dict[str, str] | None = None,
) -> dict:
    """Start ``cmd``, initialize, list tools, optionally call list_hosts; then stop it."""
    result: dict = {"started": False, "tools": None, "read": None, "stderr": "", "names": []}
    run_env = {
        **(clean_env() if base_env is None else base_env),
        **env,
        "FASTMCP_TRANSPORT": "stdio",
    }
    if "UNIFI_API_KEY" not in env:
        run_env.pop("UNIFI_API_KEY", None)
        run_env.pop("UNIFI_API_KEYS", None)
    proc = subprocess.Popen(  # noqa: S603 - argv built from the install path under test
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=run_env,
        cwd=Path(run_env["HOME"]),
        start_new_session=os.name != "nt",
    )
    stderr_lines = []

    def drain_stderr():
        if proc.stderr:
            stderr_lines.extend(proc.stderr.readlines())

    drain = threading.Thread(target=drain_stderr, daemon=True)
    drain.start()

    try:
        init = {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "matrix", "version": "1"},
        }
        reply = _rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": init})
        result["started"] = bool(reply and "result" in reply)
        result["version"] = (reply or {}).get("result", {}).get("serverInfo", {}).get("version")
        _rpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        names: list[str] = []
        cursor = None
        seen_cursors = set()
        for page in range(2, 50):
            params = {"cursor": cursor} if cursor else {}
            reply = _rpc(
                proc, {"jsonrpc": "2.0", "id": page, "method": "tools/list", "params": params}
            )
            body = (reply or {}).get("result", {})
            names += [t["name"] for t in body.get("tools", [])]
            cursor = body.get("nextCursor")
            if not cursor:
                break
            if cursor in seen_cursors:
                raise RuntimeError("tools/list cursor did not advance")
            seen_cursors.add(cursor)
        else:
            raise RuntimeError("tools/list did not exhaust")
        if len(names) != len(set(names)):
            raise RuntimeError("duplicate tool names")
        result["names"] = names
        result["tools"] = len(names)
        if call:
            reply = _rpc(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "tools/call",
                    "params": {"name": "list_hosts", "arguments": {}},
                },
            )
            body = (reply or {}).get("result", {})
            text = " ".join(
                c.get("text", "") for c in body.get("content", []) if isinstance(c, dict)
            )
            result["read"] = {
                "error": bool(body.get("isError")) or "error" in (reply or {}),
                "text": text,
            }
    except (RuntimeError, ValueError, OSError) as exc:
        result["error"] = str(exc)
    finally:
        # EOF is the stdio server's shutdown signal. On a protocol failure,
        # terminate the owned process explicitly rather than racing a watchdog.
        if proc.stdin:
            proc.stdin.close()
        if "error" in result and proc.poll() is None:
            if os.name != "nt":
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        proc.wait()
        drain.join()
        result["stderr"] = "".join(stderr_lines)
    return result


def missing_key(cmd: list[str], *, base_env: dict[str, str] | None = None) -> tuple[bool, str]:
    run_env = {**(clean_env() if base_env is None else base_env), "FASTMCP_TRANSPORT": "stdio"}
    proc = subprocess.run(  # noqa: S603 - argv built from the install path under test
        cmd,
        input="",
        capture_output=True,
        text=True,
        env=run_env,
        cwd=Path(run_env["HOME"]),
    )
    text = (proc.stdout + proc.stderr).strip()
    clean = (
        "Traceback" not in text
        and "UNIFI_API_KEY" in text
        and len(text.splitlines()) <= 3
        and proc.returncode != 0
    )
    return clean, text.splitlines()[-1][:120] if text else "(no message)"


def check_row(
    name: str,
    cmd: list[str],
    target: dict,
    expect: int,
    expected_names: set[str] | None = None,
    expected_version: str | None = None,
    *,
    base_env: dict[str, str] | None = None,
) -> dict:
    """Run the four server checks for one install path."""
    probe_options = {"base_env": base_env} if base_env is not None else {}
    good = session(cmd, target["good_env"], **probe_options)
    wrong = session(cmd, target["wrong_env"], **probe_options)
    read = good.get("read") or {}
    bad_read = wrong.get("read") or {}
    mk_ok, mk_text = missing_key(cmd, **probe_options)
    # The message the user sees is the tool result: the upstream 401 plus a key hint, no
    # traceback, never the key. A traceback in the server's own log is reported apart.
    wrong_ok = (
        bool(bad_read.get("error"))
        and "401" in bad_read.get("text", "")
        and "Traceback" not in bad_read.get("text", "")
        and WRONG_KEY not in bad_read.get("text", "") + wrong["stderr"]
    )
    log_note = "server log prints a traceback for the 401" if "Traceback" in wrong["stderr"] else ""
    return {
        "row": name,
        "starts": good["started"],
        "version": good.get("version"),
        "version_ok": expected_version is None
        or (good.get("version") == expected_version and wrong.get("version") == expected_version),
        "tools": good["tools"],
        "tools_ok": good["tools"] == expect
        and (expected_names is None or set(good.get("names", [])) == expected_names),
        "read": bool(read) and not read.get("error"),
        "missing_key": mk_ok,
        "missing_key_text": mk_text,
        "wrong_key": wrong_ok,
        "detail": good.get("error") or wrong.get("error") or log_note,
    }


def checked(argv: list[str], *, env: dict | None = None, cwd: Path | None = None) -> None:
    result = subprocess.run(argv, env=env or clean_env(), cwd=cwd, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{argv[0]} failed ({result.returncode}): {result.stderr[-1000:]}")


def published_version() -> str:
    return PUBLISHED_VERSION_FILE.read_text().strip()


def repin(argv: list[str], wheel: Path, version: str, *, published: str = "") -> list[str]:
    accepted = {version} | ({published} if published else set())
    found = False
    result = []
    for value in argv:
        if value.startswith(PACKAGE):
            if value not in {f"{PACKAGE}=={pin}" for pin in accepted}:
                raise ValueError(f"outdated or invalid package pin: {value}")
            result.append(str(wheel))
            found = True
        else:
            result.append(value)
    if not found or not result or Path(result[0]).name not in {"uvx", "uvx.exe"}:
        raise ValueError("expected a pinned uvx launcher")
    if result[-1] != ENTRY:
        raise ValueError("unexpected server entrypoint")
    result[0] = shutil.which("uvx") or result[0]
    return result


def validate_key_wiring(server: dict) -> dict[str, str]:
    env = server.get("env", {})
    forwarded = server.get("env_vars", [])
    if not isinstance(env, dict) or not isinstance(forwarded, list):
        raise ValueError("invalid client environment declaration")
    if "UNIFI_API_KEY" in env:
        if env["UNIFI_API_KEY"] not in {"your-api-key-here", "${user_config.unifi_api_key}"}:
            raise ValueError("client API key must use the documented placeholder")
    elif "UNIFI_API_KEY" not in forwarded:
        raise ValueError("client does not configure or forward UNIFI_API_KEY")
    if set(env) - {"UNIFI_API_KEY", "UNIFI_WRITE_POLICY", "FASTMCP_TRANSPORT", "UNIFI_TOOL_MODE"}:
        raise ValueError("unexpected client environment setting")
    if set(forwarded) - {"UNIFI_API_KEY", "UNIFI_WRITE_POLICY", "UNIFI_TOOL_MODE"}:
        raise ValueError("unexpected client environment forwarding")
    if env.get("FASTMCP_TRANSPORT", "stdio") != "stdio":
        raise ValueError("client launcher must declare stdio")
    out = {}
    if "UNIFI_WRITE_POLICY" in env:
        value = env["UNIFI_WRITE_POLICY"]
        if value == "${user_config.write_policy}":
            value = "deny"
        if value not in {"allow", "dry-run", "deny"}:
            raise ValueError("invalid client write policy setting")
        out["UNIFI_WRITE_POLICY"] = value
    return out


def client_settings(case: dict) -> dict[str, str]:
    if case["mode"] == "codex":
        servers = tomllib.loads(case["body"])["mcp_servers"]
    elif case["mode"] == "desktop":
        servers = json.loads(case["body"])["mcpServers"]
    elif case["mode"] == "plugin":
        servers = json.loads((ROOT / "plugins/claude/.claude-plugin/plugin.json").read_text())[
            "mcpServers"
        ]
    else:
        return {}
    return validate_key_wiring(next(iter(servers.values())))


def parsed_launcher(case: dict, wheel: Path, version: str, *, published: str = "") -> list[str]:
    body, mode = case["body"], case["mode"]
    if mode == "codex":
        config = tomllib.loads(body)
        servers = config["mcp_servers"]
    elif mode == "desktop":
        servers = json.loads(body)["mcpServers"]
    elif mode == "antigravity":
        config = json.loads((ROOT / "plugins/antigravity/mcp_config.json").read_text())
        servers = config["mcpServers"]
        for line in body.splitlines():
            if line.startswith("agy mcp add "):
                argv = shlex.split(line, comments=True)
                if "--" not in argv:
                    raise ValueError("Antigravity command must declare its MCP launcher")
                return repin(argv[argv.index("--") + 1 :], wheel, version, published=published)
    elif mode == "plugin":
        if not (
            "claude --plugin-dir ./plugins/claude" in body
            or "/plugin install unifi-fabric@unifi-fabric" in body
        ):
            raise ValueError("unrecognized plugin install command")
        config = json.loads((ROOT / "plugins/claude/.claude-plugin/plugin.json").read_text())
        servers = config["mcpServers"]
    else:
        raise ValueError("not a client configuration")
    if len(servers) != 1:
        raise ValueError("expected exactly one MCP server")
    server = next(iter(servers.values()))
    if mode != "antigravity":
        validate_key_wiring(server)
    elif server.get("env") or server.get("env_vars"):
        raise ValueError("Antigravity plugin must inherit the synthetic shell environment")
    return repin([server["command"], *server.get("args", [])], wheel, version, published=published)


def prepare(
    case: dict,
    wheel: Path,
    sdist: Path,
    version: str,
    work: Path,
    pipx: str,
    *,
    published: str = "",
) -> list[str]:
    mode, body = case["mode"], case["body"]
    if mode in {"desktop", "codex", "plugin", "antigravity"}:
        return parsed_launcher(case, wheel, version, published=published)
    if mode == "uvx":
        line = next((line for line in body.splitlines() if line.startswith("uvx ")), "")
        return repin(shlex.split(line), wheel, version, published=published)
    if mode == "pipx":
        line = next((line for line in body.splitlines() if line.startswith("pipx install ")), "")
        argv = shlex.split(line, comments=True)
        accepted = {version} | ({published} if published else set())
        if len(argv) != 3 or argv[-1] not in {f"{PACKAGE}=={pin}" for pin in accepted}:
            raise ValueError("expected documented pinned pipx install")
        home = (work / case["id"]).resolve()
        env = {
            **clean_env(),
            "PIPX_HOME": str(home),
            "PIPX_BIN_DIR": str(home / "bin"),
            "PIPX_DEFAULT_PYTHON": sys.executable,
        }
        launch = None
        for raw in body.splitlines():
            for part in raw.split("&&"):
                command = shlex.split(part, comments=True)
                if not command:
                    continue
                if launch is not None:
                    raise ValueError("unexpected command after documented launcher")
                if command[0] == "pipx":
                    if command != argv:
                        raise ValueError("unexpected documented pipx command")
                    continue  # the pinned install is replaced by the local wheel below
                launch = command
        if not launch or len(launch) != 1:
            raise ValueError("expected documented pipx launch command")
        checked([pipx, "install", str(wheel)], env=env)
        return [str(home / "bin" / launch[0])]
    if mode in {"pip", "source"}:
        return prepare_sequence(case, sdist, version, work, published=published)
    raise ValueError(f"unsupported executable mode {mode}")


def prepare_sequence(
    case: dict, sdist: Path, version: str, work: Path, *, published: str = ""
) -> list[str]:
    """Execute README setup argv, substituting only local source/package artifacts.

    The final argv is taken from the block itself and launched by the stdio probe.
    Environment/key exports are supplied by the probe; source checkout uses the local
    sdist so no public or credentialed checkout is performed during installation.
    """
    home = work / case["id"]
    home.mkdir()
    # Resolve once, then derive every path from resolved roots: a symlinked work
    # directory (macOS /var -> /private/var, Windows 8.3 short names) must not make a
    # resolved venv compare unequal to an unresolved cwd/home.
    home = home.resolve()
    cwd = home
    env = clean_env()
    bindir = None
    launch = None
    source = None
    clone_directory = None
    venv = None
    windows = platform.system() == "Windows"
    if case["mode"] == "source":
        if "pip install -e ." not in case["body"] or "git clone " not in case["body"]:
            raise ValueError("expected source checkout and editable install")
        unpack = home / "checkout"
        unpack.mkdir()
        with tarfile.open(sdist) as archive:
            archive.extractall(unpack, filter="data")
        projects = [p for p in unpack.iterdir() if p.is_dir() and (p / "pyproject.toml").is_file()]
        if len(projects) != 1:
            raise ValueError("source archive must contain one project")
        source = projects[0]
    for raw in case["body"].splitlines():
        for part in raw.split("&&"):
            argv = shlex.split(part, comments=True)
            if not argv:
                continue
            if launch is not None:
                raise ValueError("unexpected command after documented launcher")
            if argv[0] == "git" and argv[1:2] == ["clone"] and source:
                if len(argv) not in {3, 4}:
                    raise ValueError("invalid documented clone directory")
                clone_directory = Path(
                    argv[3]
                    if len(argv) == 4
                    else argv[2].rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
                )
                if clone_directory.is_absolute() or ".." in clone_directory.parts:
                    raise ValueError("invalid documented clone directory")
                continue  # checkout is the local artifact above
            if argv[0] == "cd":
                if (
                    not source
                    or clone_directory is None
                    or cwd != home
                    or len(argv) != 2
                    or Path(argv[1]) != clone_directory
                ):
                    raise ValueError("invalid documented source directory")
                cwd = source
                continue
            if argv[0] in {"source", "."}:
                activation = Path(argv[1]) if len(argv) == 2 else None
                if (
                    venv is None
                    or activation is None
                    or (cwd / activation.parent).resolve().parent != venv
                    or activation.name != "activate"
                    or activation.parent.name not in {"bin", "Scripts"}
                ):
                    raise ValueError("invalid documented virtualenv activation")
                continue  # virtualenv PATH is set explicitly
            if argv[0] == "export":
                continue  # synthetic key is supplied by the probe
            if argv[0] in {"python", "python3"} and argv[1:3] == ["-m", "venv"]:
                if len(argv) != 4:
                    raise ValueError("invalid documented venv command")
                destination = Path(argv[3])
                venv = (cwd / destination).resolve()
                if (
                    argv[3].startswith(("-", "~"))
                    or SHELL_EXPANSION.intersection(argv[3])
                    or destination.is_absolute()
                    or not venv.is_relative_to(home)
                    or venv == home
                ):
                    raise ValueError("invalid virtual environment destination")
                checked([sys.executable, *argv[1:]], cwd=cwd, env=env)
                bindir = venv / ("Scripts" if windows else "bin")
                python = bindir / ("python.exe" if windows else "python")
                env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
                checked(
                    [
                        str(python),
                        "-m",
                        "pip",
                        "install",
                        "--require-hashes",
                        "-r",
                        str(ROOT / "requirements-runtime.lock"),
                    ],
                    env=env,
                )
                continue
            if not bindir:
                raise ValueError("documented command must create a virtual environment first")
            executable = Path(argv[0])
            if (
                executable.parent != Path(".")
                and (cwd / executable.parent).resolve().parent == venv
                and executable.parent.name in {"bin", "Scripts"}
            ):
                executable = bindir / executable.name
            elif executable.parent == Path("."):
                executable = bindir / executable
            else:
                executable = cwd / executable
            if windows and executable.suffix != ".exe":
                executable = executable.with_name(executable.name + ".exe")
            if argv[0] == "pip":
                argv = [str(python), "-m", "pip", *argv[1:]]
            else:
                argv[0] = str(executable)
            if argv[1:4] == ["-m", "pip", "install"]:
                if argv[4:] == ["-e", "."] and source:
                    checked(argv, cwd=cwd, env=env)
                elif argv[4:] in [[f"{PACKAGE}=={pin}"] for pin in {version, published} if pin]:
                    checked([*argv[:4], str(sdist)], cwd=cwd, env=env)
                else:
                    raise ValueError("unexpected documented pip installation")
                continue
            launch = argv
    if launch is None:
        raise ValueError("documented sequence is missing its launch command")
    return launch


def docker_launcher(wheel: Path, work: Path) -> tuple[list[str], str]:
    if platform.system() != "Linux":
        raise ValueError("Docker is only permitted on Linux")
    image = "install-smoke:" + work.name.lower()
    # The build never installs this project from PyPI or from a source checkout.
    shutil.copy(wheel, work / wheel.name)
    shutil.copy(ROOT / "requirements-runtime.lock", work / "requirements-runtime.lock")
    base = re.search(r"ARG PYTHON_IMAGE=(\S+)", (ROOT / "Dockerfile").read_text())[1]
    (work / "Dockerfile").write_text(
        f"FROM {base}\nWORKDIR /smoke\nCOPY requirements-runtime.lock .\n"
        "RUN python -m pip install --require-hashes -r requirements-runtime.lock\n"
        f"COPY {wheel.name} .\nRUN python -m pip install --no-deps {wheel.name}\n"
        f'ENTRYPOINT ["{ENTRY}"]\n'
    )
    checked(["docker", "build", "-q", "-t", image, str(work)], env=docker_env())
    cmd = ["docker", "run", "--rm", "-i", "--network", "host"]
    # Host values are synthetic and overridden for each probe, including the missing-key case.
    for name in (
        "UNIFI_API_KEY",
        "UNIFI_API_BASE_URL",
        "UNIFI_WRITE_POLICY",
        "UNIFI_TOOL_MODE",
        "FASTMCP_TRANSPORT",
    ):
        cmd += ["-e", name]
    return [*cmd, image], image


def validate_docker_case(case: dict, version: str, published: str = "") -> bool:
    """Validate original run options; only image and test environment are substituted."""
    body = case["body"]
    if case["language"] == "json":
        config = json.loads(body)
        server = next(iter(config["mcpServers"].values()))
        if server.get("type") != "http" or server.get("url") != "http://localhost:3000/mcp":
            raise ValueError("unexpected HTTP client endpoint")
        headers = server.get("headers", {})
        if headers != {"Authorization": "Bearer ${MCP_BEARER_TOKEN}"}:
            raise ValueError("expected documented bearer HTTP client auth header")
        return True
    command = re.search(r"(?:^|\n)(docker run [^\n]+)", body.replace("\\\n", " "))
    if not command:
        raise ValueError("expected documented Docker run")
    argv = shlex.split(command[1].replace("\\\n", " "))
    if argv[-1] not in {
        f"ghcr.io/swkstudios/unifi-fabric-mcp-server:{pin}" for pin in {version, published} if pin
    }:
        raise ValueError("unexpected Docker image pin or entrypoint")
    opts = argv[2:-1]
    env = {}
    port = None
    while opts:
        flag = opts.pop(0)
        if flag not in {"-e", "-p"} or not opts:
            raise ValueError("unsupported Docker run option")
        value = opts.pop(0)
        if flag == "-p":
            port = value
        else:
            key, _, value = value.partition("=")
            env[key] = value
    if port != "127.0.0.1:3000:3000" or env.get("UNIFI_API_KEY") != "your-api-key-here":
        raise ValueError("unexpected Docker port or key placeholder")
    if set(env) - {"UNIFI_API_KEY", "MCP_AUTH_MODE", "MCP_BEARER_TOKEN"}:
        raise ValueError("unexpected Docker environment")
    authenticated = env.get("MCP_AUTH_MODE") == "bearer"
    if "MCP_AUTH_MODE" in env and not authenticated:
        raise ValueError("unexpected Docker authentication mode")
    if authenticated and env.get("MCP_BEARER_TOKEN") != "":
        raise ValueError("bearer token must be forwarded from the test environment")
    return authenticated


def http_rpc(url: str, method: str, params: dict, ident: int, bearer: str | None) -> dict:
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    request = urllib.request.Request(
        url,
        data=json.dumps(
            {"jsonrpc": "2.0", "id": ident, "method": method, "params": params}
        ).encode(),
        headers=headers,
    )
    with urllib.request.urlopen(request) as response:
        raw = response.read().decode()
    if raw.startswith("data:") or "\ndata:" in raw:
        raw = next(line[5:].strip() for line in raw.splitlines() if line.startswith("data:"))
    return json.loads(raw)


def docker_session(image: str, env: dict, authenticated: bool, expected_names: set[str]) -> dict:
    bearer = "install-test-only-bearer" if authenticated else None
    target = {
        **docker_env(),
        **env,
        "FASTMCP_TRANSPORT": "streamable-http",
        "FASTMCP_HOST": "0.0.0.0",  # noqa: S104 - isolated container, loopback publish
        "FASTMCP_PORT": "3000",
        "FASTMCP_STATELESS_HTTP": "true",
        "MCP_AUTH_MODE": "bearer" if bearer else "none",
    }
    if bearer:
        target["MCP_BEARER_TOKEN"] = bearer
    if "UNIFI_API_BASE_URL" in target:
        target["UNIFI_API_BASE_URL"] = target["UNIFI_API_BASE_URL"].replace(
            "http://127.0.0.1:", "http://host.docker.internal:"
        )
    cmd = [
        "docker",
        "run",
        "--add-host",
        "host.docker.internal:host-gateway",
        "-p",
        "127.0.0.1::3000",
    ]
    for name in target:
        if name.startswith(("UNIFI_", "MCP_", "FASTMCP_")):
            cmd += ["-e", name]
    name = "install-probe-" + os.urandom(8).hex()
    cmd += ["--name", name, image]
    with tempfile.TemporaryFile(mode="w+") as log:
        proc = subprocess.Popen(cmd, env=target, stdout=log, stderr=log)
        stage = "startup"
        started = time.monotonic()
        try:
            if "UNIFI_API_KEY" not in env:
                proc.wait()
                log.seek(0)
                message = log.read()
                return {
                    "missing_key": "UNIFI_API_KEY" in message
                    and "Traceback" not in message
                    and proc.returncode != 0
                }
            # Docker owns allocation until teardown; no reserve/close race.
            while True:
                published = subprocess.run(
                    ["docker", "port", name, "3000/tcp"],
                    env=docker_env(),
                    capture_output=True,
                    text=True,
                )
                match = re.fullmatch(r"127\.0\.0\.1:(\d+)\s*", published.stdout)
                if published.returncode == 0 and match:
                    port = int(match[1])
                    break
                if proc.poll() is not None:
                    raise RuntimeError("Docker did not publish the HTTP port")
                time.sleep(0.2)
            url = f"http://127.0.0.1:{port}/mcp"
            while True:
                try:
                    init = http_rpc(
                        url,
                        "initialize",
                        {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "install-http", "version": "1"},
                        },
                        1,
                        bearer,
                    )
                    break
                except urllib.error.HTTPError as error:
                    raise RuntimeError(
                        f"Docker HTTP initialization returned {error.code}"
                    ) from None
                except (OSError, urllib.error.URLError):
                    if proc.poll() is not None:
                        raise RuntimeError("Docker HTTP endpoint did not start") from None
                    time.sleep(0.2)
            stage = "tools/list"
            names, cursor, seen = [], None, set()
            for page in range(2, 50):
                reply = http_rpc(
                    url, "tools/list", {"cursor": cursor} if cursor else {}, page, bearer
                )
                result = reply.get("result", {})
                names += [tool["name"] for tool in result.get("tools", [])]
                cursor = result.get("nextCursor")
                if not cursor:
                    break
                if cursor in seen:
                    raise RuntimeError("HTTP tools/list cursor repeated")
                seen.add(cursor)
            else:
                raise RuntimeError("HTTP tools/list did not exhaust")
            stage = "tools/call:list_hosts"
            reply = http_rpc(url, "tools/call", {"name": "list_hosts", "arguments": {}}, 99, bearer)
            body = reply.get("result", {})
            text = " ".join(item.get("text", "") for item in body.get("content", []))
            return {
                "starts": "result" in init,
                "version": init.get("result", {}).get("serverInfo", {}).get("version"),
                "tools": len(names),
                "tools_ok": set(names) == expected_names and len(names) == len(set(names)),
                "read": {"error": bool(body.get("isError")) or "error" in reply, "text": text},
            }
        except Exception as exc:
            directory = ROOT / ".install-diagnostics"
            directory.mkdir(exist_ok=True)
            path = directory / f"{name}.log"
            log.seek(0)
            diagnostic = "=== docker client output ===\n" + log.read()
            for label, argv in (
                ("container logs", ["docker", "logs", name]),
                ("state and health", ["docker", "inspect", "--format", "{{json .State}}", name]),
                (
                    "port state",
                    ["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", name],
                ),
                ("published ports", ["docker", "port", name]),
            ):
                try:
                    probe = subprocess.run(argv, env=docker_env(), capture_output=True, text=True)
                    diagnostic += f"\n=== {label} (exit {probe.returncode}) ===\n"
                    diagnostic += probe.stdout + probe.stderr
                except OSError as error:
                    diagnostic += f"\n=== {label} ===\n{type(error).__name__}: {error}\n"
            for value in (GOOD_MOCK_KEY, WRONG_KEY, "install-test-only-bearer"):
                diagnostic = diagnostic.replace(value, "[synthetic-value]")
            path.write_text(diagnostic)
            raise RuntimeError(
                f"Docker HTTP {stage} failed after {time.monotonic() - started:.1f}s: "
                f"{type(exc).__name__}: {exc}; full diagnostics: {path}"
            ) from None
        finally:
            if proc.poll() is None:
                # Stop the owned container first; killing the docker client alone leaks it.
                subprocess.run(
                    ["docker", "stop", "-t", "-1", name],
                    env=docker_env(),
                    capture_output=True,
                )
                proc.wait()
            subprocess.run(["docker", "rm", "-f", name], env=docker_env(), capture_output=True)


def check_docker(
    case: dict,
    image: str,
    version: str,
    target: dict,
    expected_names: set[str],
    published: str = "",
) -> dict:
    authenticated = (
        validate_docker_case(case, version, published)
        if published
        else validate_docker_case(case, version)
    )
    good = docker_session(image, target["good_env"], authenticated, expected_names)
    wrong = docker_session(image, target["wrong_env"], authenticated, expected_names)
    missing = docker_session(image, {}, authenticated, expected_names)
    cmd = ["docker", "run", "--rm", "-i", "--network", "host"]
    for key in (
        "UNIFI_API_KEY",
        "UNIFI_API_BASE_URL",
        "UNIFI_WRITE_POLICY",
        "UNIFI_TOOL_MODE",
        "FASTMCP_TRANSPORT",
    ):
        cmd += ["-e", key]
    stdio = check_row(
        case["id"] + "-stdio",
        [*cmd, image],
        target,
        len(expected_names),
        expected_names,
        expected_version=version,
        base_env=docker_env(),
    )
    read = wrong["read"]
    return {
        "starts": good["starts"] and stdio["starts"],
        "tools": good["tools"],
        "tools_ok": good["tools_ok"] and stdio["tools_ok"],
        "version_ok": good.get("version") == version
        and wrong.get("version") == version
        and stdio["version_ok"],
        "read": not good["read"]["error"] and stdio["read"],
        "missing_key": missing["missing_key"] and stdio["missing_key"],
        "wrong_key": read["error"]
        and "401" in read["text"]
        and "Traceback" not in read["text"]
        and WRONG_KEY not in read["text"]
        and stdio["wrong_key"],
        "stdio": stdio,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--sdist", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--only", action="append", help="select case IDs for targeted verification")
    parser.add_argument(
        "--skip-docker",
        action="store_true",
        help="record Docker documentation cases as not tested without using a Docker runner",
    )
    args = parser.parse_args()
    wheel, sdist = args.wheel.resolve(), args.sdist.resolve()
    if not wheel.is_file() or not sdist.is_file():
        raise ValueError("both locally built artifacts are required")
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    published = published_version()
    expected_names = set(re.findall(r"^### `([^`]+)`", (ROOT / "docs/TOOLS.md").read_text(), re.M))
    expect = len(expected_names)
    cases = extract_cases()
    # Both client plugin formats are parsed even if CLI installation is a manual case.
    codex_plugin = json.loads((ROOT / "plugins/codex/.mcp.json").read_text())
    for server in codex_plugin["mcpServers"].values():
        validate_key_wiring(server)
        repin([server["command"], *server.get("args", [])], wheel, version, published=published)
    cases.append(
        {
            "id": "codex-plugin-manifest",
            "mode": "desktop",
            "language": "json",
            "body": json.dumps(codex_plugin),
            "path": "plugins/codex/.mcp.json",
        }
    )
    cases.append(
        {
            "id": "antigravity-plugin-manifest",
            "mode": "antigravity",
            "language": "json",
            "body": (ROOT / "plugins/antigravity/mcp_config.json").read_text(),
            "path": "plugins/antigravity/mcp_config.json",
        }
    )
    mock, base = start_mock()
    # This artifact probe compares the complete documented domain catalogue.
    # Runtime defaults remain discovery mode and are tested separately.
    common = {"UNIFI_API_BASE_URL": base, "UNIFI_TOOL_MODE": "full"}
    target = {
        "good_env": {**common, "UNIFI_API_KEY": GOOD_MOCK_KEY},
        "wrong_env": {**common, "UNIFI_API_KEY": WRONG_KEY},
    }
    results = []
    system = platform.system()
    # Executed-case claims excused on this platform (a platform-only mode elsewhere).
    doc_claims_not_tested: list[dict] = []

    def save_report():
        args.out.write_text(
            json.dumps(
                {
                    "version": version,
                    "platform": system,
                    "expected_tools": expect,
                    "expected_tool_names": sorted(expected_names),
                    "cases": results,
                    "doc_claims_not_tested": doc_claims_not_tested,
                },
                indent=2,
            )
            + "\n"
        )

    image = None
    try:
        with tempfile.TemporaryDirectory(prefix="install-smoke-") as tmp:
            # Resolved once (macOS /var -> /private/var): HOME, cwd and venv paths agree.
            work = Path(tmp).resolve()
            # HOME and all installer state are task-owned; never use a client credential store.
            global WORK_HOME
            WORK_HOME = work
            for case in cases:
                if args.only and case["id"] not in args.only:
                    continue
                if case["mode"] == "non-executable":
                    results.append(
                        {"id": case["id"], "status": "NON-EXECUTABLE", "reason": case["reason"]}
                    )
                    continue
                if args.skip_docker and case["mode"] == "docker":
                    results.append(
                        {
                            "id": case["id"],
                            "status": "NOT-TESTED",
                            "reason": DOCKER_DEFERRED_REASON,
                        }
                    )
                    continue
                required = PLATFORM_ONLY.get(case["mode"])
                if required is not None and system != required:
                    results.append(
                        {
                            "id": case["id"],
                            "status": "NOT-TESTED",
                            "reason": PLATFORM_ONLY_REASON[case["mode"]],
                        }
                    )
                    continue
                try:
                    if case["mode"] == "docker":
                        validate_docker_case(case, version, published)
                        if image is None:
                            _, image = docker_launcher(wheel, work)
                        result = check_docker(
                            case, image, version, target, expected_names, published
                        )
                    else:
                        cmd = prepare(
                            case,
                            wheel,
                            sdist,
                            version,
                            work,
                            shutil.which("pipx") or "pipx",
                            published=published,
                        )
                        settings = client_settings(case)
                        settings.pop("UNIFI_WRITE_POLICY", None)
                        configured_target = {
                            key: {**value, **settings} for key, value in target.items()
                        }
                        result = check_row(
                            case["id"],
                            cmd,
                            configured_target,
                            expect,
                            expected_names,
                            expected_version=version,
                        )
                    result["id"] = case["id"]
                    result["status"] = (
                        "TESTED-LIVE"
                        if all(
                            result[k]
                            for k in (
                                "starts",
                                "tools_ok",
                                "read",
                                "missing_key",
                                "wrong_key",
                                "version_ok",
                            )
                        )
                        else "FAIL"
                    )
                    results.append(result)
                    save_report()
                    print(case["id"], result["status"], flush=True)
                except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                    results.append({"id": case["id"], "status": "FAIL", "detail": str(exc)})
                    save_report()
                    print(case["id"], "FAIL", str(exc), flush=True)
    finally:
        mock.shutdown()
        mock.server_close()
        if image:
            checked(["docker", "image", "rm", image], env=docker_env())
    doc_failures: list[str] = []
    if not args.only:
        from check_doc_provenance import check_executed_cases

        doc_failures = check_executed_cases(
            ROOT,
            {"version": version, "platform": system, "cases": results},
            doc_claims_not_tested,
        )
    save_report()
    for entry in doc_claims_not_tested:
        print(
            f"{entry['id']} NOT-TESTED on {system}: {entry['reason']} "
            f"(executed-case claim checked on {entry['required_platform']} only)"
        )
    if doc_failures:
        for failure in doc_failures:
            print(failure, file=sys.stderr)
        return 1
    for result in results:
        print(result["id"], result["status"], result.get("detail", ""))
    return int(any(result["status"] == "FAIL" for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
