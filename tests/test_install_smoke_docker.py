"""Docker smoke gates exercise both transports and retain complete failure evidence."""

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "install_smoke_docker", ROOT / "scripts/install_smoke.py"
)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


@pytest.mark.parametrize("mutation", [None, "stdio-read", "stdio-version", "http-version"])
def test_docker_gate_rejects_transport_and_version_mutations(monkeypatch, mutation):
    monkeypatch.setenv("DOCKER_HOST", "tcp://docker:2376")
    monkeypatch.setattr(smoke, "validate_docker_case", lambda *args: False)
    replies = iter(
        [
            {
                "starts": True,
                "tools": 1,
                "tools_ok": True,
                "version": "broken" if mutation == "http-version" else "1.2.3",
                "read": {"error": False, "text": "ok"},
            },
            {"version": "1.2.3", "read": {"error": True, "text": "401 wrong key"}},
            {"missing_key": True},
        ]
    )
    monkeypatch.setattr(smoke, "docker_session", lambda *args: next(replies))
    calls = []

    def stdio(*args, **kwargs):
        calls.append((args, kwargs))
        return {
            "starts": True,
            "tools_ok": True,
            "read": mutation != "stdio-read",
            "version_ok": mutation != "stdio-version",
            "missing_key": True,
            "wrong_key": True,
        }

    monkeypatch.setattr(smoke, "check_row", stdio)
    result = smoke.check_docker(
        {"id": "docker"}, "test-image", "1.2.3", {"good_env": {}, "wrong_env": {}}, {"list_hosts"}
    )
    assert len(calls) == 1
    assert calls[0][0][1][:5] == ["docker", "run", "--rm", "-i", "--network"]
    argv = calls[0][0][1]
    assert "UNIFI_TOOL_MODE" in [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == "-e"]
    assert calls[0][1]["expected_version"] == "1.2.3"
    assert calls[0][1]["base_env"]["DOCKER_HOST"] == "tcp://docker:2376"
    assert all(
        result[key]
        for key in ("starts", "tools_ok", "version_ok", "read", "missing_key", "wrong_key")
    ) is (mutation is None)


def test_docker_failure_keeps_full_logs_health_ports_and_owned_allocation(monkeypatch, tmp_path):
    monkeypatch.setattr(smoke, "ROOT", tmp_path)
    monkeypatch.setattr(smoke, "WORK_HOME", tmp_path)
    commands = []
    connection = {
        "DOCKER_HOST": "tcp://docker:2376",
        "DOCKER_TLS_VERIFY": "1",
        "DOCKER_CERT_PATH": "/runner/certs/client",
    }
    for key, value in connection.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("DOCKER_CONFIG", "/host/docker-auth")
    monkeypatch.setenv("UNIFI_API_KEYS", "host-service-keys")

    def check_env(env):
        assert all(env.get(key) == value for key, value in connection.items())
        assert "DOCKER_CONFIG" not in env
        assert "UNIFI_API_KEYS" not in env

    log_tail = "END-OF-FULL-DIAGNOSTICS"
    full_log = "x" * 4096 + log_tail
    launch_env = {}

    class Process:
        returncode = 1

        def __init__(self, argv, **kwargs):
            commands.append(argv)
            check_env(kwargs["env"])
            launch_env.update(kwargs["env"])
            kwargs["stdout"].write(full_log)
            kwargs["stdout"].flush()

        def poll(self):
            return None

        def wait(self):
            return 1

    def run(argv, **kwargs):
        commands.append(argv)
        check_env(kwargs["env"])
        if argv[1] == "port":
            return SimpleNamespace(returncode=0, stdout="127.0.0.1:34567\n", stderr="")
        return SimpleNamespace(returncode=0, stdout=json.dumps({"health": "unhealthy"}), stderr="")

    monkeypatch.setattr(smoke.subprocess, "Popen", Process)
    monkeypatch.setattr(smoke.subprocess, "run", run)
    monkeypatch.setattr(
        smoke, "http_rpc", lambda *args: (_ for _ in ()).throw(ValueError("refused"))
    )
    with pytest.raises(RuntimeError, match="full diagnostics:"):
        smoke.docker_session(
            "test-image",
            {
                "UNIFI_API_KEY": smoke.GOOD_MOCK_KEY,
                "UNIFI_API_BASE_URL": "http://127.0.0.1:12345",
            },
            False,
            {"list_hosts"},
        )
    launch = commands[0]
    assert launch[launch.index("-p") + 1] == "127.0.0.1::3000"
    assert "--network" not in launch
    assert all(key not in launch for key in connection)
    assert any(argv[:2] == ["docker", "stop"] for argv in commands)
    assert launch_env["UNIFI_API_BASE_URL"] == "http://host.docker.internal:12345"
    evidence = next((tmp_path / ".install-diagnostics").glob("*.log")).read_text()
    assert log_tail in evidence
    for label in ("container logs", "state and health", "port state", "published ports"):
        assert label in evidence
    assert any(argv[:3] == ["docker", "rm", "-f"] for argv in commands)


def test_docker_build_uses_connection_env(monkeypatch, tmp_path):
    monkeypatch.setattr(smoke.platform, "system", lambda: "Linux")
    monkeypatch.setenv("DOCKER_HOST", "tcp://docker:2376")
    wheel = tmp_path / "package.whl"
    wheel.write_bytes(b"synthetic-wheel")
    work = tmp_path / "docker-work"
    work.mkdir()
    calls = []
    monkeypatch.setattr(smoke, "checked", lambda argv, **kwargs: calls.append((argv, kwargs)))
    smoke.docker_launcher(wheel, work)
    assert calls[0][0][:2] == ["docker", "build"]
    assert calls[0][1]["env"]["DOCKER_HOST"] == "tcp://docker:2376"


def test_stdio_docker_connection_reaches_valid_wrong_and_missing_key_probes(monkeypatch, tmp_path):
    monkeypatch.setattr(smoke, "WORK_HOME", tmp_path)
    monkeypatch.setenv("DOCKER_HOST", "tcp://docker:2376")
    base = smoke.docker_env()
    observed = []

    def popen(argv, **kwargs):
        observed.append(kwargs["env"])
        raise OSError("synthetic process boundary")

    monkeypatch.setattr(smoke.subprocess, "Popen", popen)
    for key in (smoke.GOOD_MOCK_KEY, smoke.WRONG_KEY):
        with pytest.raises(OSError, match="synthetic process boundary"):
            smoke.session(["docker", "run"], {"UNIFI_API_KEY": key}, base_env=base)
    assert [env["UNIFI_API_KEY"] for env in observed] == [smoke.GOOD_MOCK_KEY, smoke.WRONG_KEY]

    def run(argv, **kwargs):
        observed.append(kwargs["env"])
        return SimpleNamespace(returncode=1, stdout="", stderr="UNIFI_API_KEY required")

    monkeypatch.setattr(smoke.subprocess, "run", run)
    assert smoke.missing_key(["docker", "run"], base_env=base)[0]
    assert "UNIFI_API_KEY" not in observed[-1]
    assert all(env["DOCKER_HOST"] == "tcp://docker:2376" for env in observed)
    assert all(env["FASTMCP_TRANSPORT"] == "stdio" for env in observed)


@pytest.mark.parametrize("outcome", ["ready", "exited", "http-error"])
def test_docker_readiness_uses_response_or_exit_after_old_limit(monkeypatch, tmp_path, outcome):
    import urllib.error

    monkeypatch.setattr(smoke, "ROOT", tmp_path)
    ticks = iter(range(0, 10000, 301))
    monkeypatch.setattr(smoke.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(smoke.time, "sleep", lambda _: None)
    calls = 0

    class Process:
        def poll(self):
            return 1 if outcome == "exited" else None

        def wait(self):
            return 0

    def run(argv, **kwargs):
        assert "timeout" not in kwargs
        return SimpleNamespace(returncode=0, stdout="127.0.0.1:34567\n", stderr="")

    def rpc(url, method, params, ident, bearer):
        nonlocal calls
        calls += 1
        if outcome == "http-error":
            raise urllib.error.HTTPError(url, 401, "unauthorized", {}, None)
        if calls == 1:
            raise urllib.error.URLError("connection refused during startup")
        if method == "initialize":
            return {"result": {"serverInfo": {"version": "1.2.3"}}}
        if method == "tools/list":
            return {"result": {"tools": [{"name": "list_hosts"}]}}
        return {"result": {"content": [{"text": "ok"}]}}

    monkeypatch.setattr(smoke.subprocess, "Popen", lambda *a, **kw: Process())
    monkeypatch.setattr(smoke.subprocess, "run", run)
    monkeypatch.setattr(smoke, "http_rpc", rpc)
    args = ("test-image", {"UNIFI_API_KEY": smoke.GOOD_MOCK_KEY}, False, {"list_hosts"})
    if outcome == "ready":
        result = smoke.docker_session(*args)
        assert result["starts"] and result["tools_ok"] and not result["read"]["error"]
    else:
        message = "endpoint did not start" if outcome == "exited" else "returned 401"
        with pytest.raises(RuntimeError, match=message):
            smoke.docker_session(*args)
        assert calls == 1
