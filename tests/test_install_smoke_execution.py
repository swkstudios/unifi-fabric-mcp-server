"""Behavioral mutation tests for documented setup, version and Antigravity launchers."""

import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import install_smoke as smoke  # noqa: E402


def test_pip_executes_documented_setup_and_launcher(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(smoke, "checked", lambda argv, **kw: calls.append((argv, kw)))
    case = {
        "id": "pip",
        "mode": "pip",
        "body": (
            "python3 -m venv .venv\n"
            ".venv/bin/python -m pip install unifi-fabric-mcp-server==1.2.3\n"
            ".venv/bin/unifi-fabric-mcp\n"
        ),
    }
    cmd = smoke.prepare(case, tmp_path / "x.whl", tmp_path / "x.tar.gz", "1.2.3", tmp_path, "pipx")
    assert calls[0][0][1:] == ["-m", "venv", ".venv"]
    assert calls[-1][0][-1] == str(tmp_path / "x.tar.gz")
    assert cmd == [str(tmp_path / "pip/.venv/bin/unifi-fabric-mcp")]


@pytest.mark.parametrize("mode", ["pip", "pipx"])
def test_readme_broken_entrypoint_is_the_executable_and_fails(monkeypatch, tmp_path, mode):
    monkeypatch.setattr(smoke, "checked", lambda *a, **k: None)
    if mode == "pip":
        body = (
            "python3 -m venv .venv\n"
            ".venv/bin/python -m pip install unifi-fabric-mcp-server==1.2.3\n"
            ".venv/bin/broken-entrypoint"
        )
    else:
        body = "pipx install unifi-fabric-mcp-server==1.2.3\nbroken-entrypoint"
    cmd = smoke.prepare(
        {"id": mode, "mode": mode, "body": body},
        tmp_path / "x.whl",
        tmp_path / "x.tar.gz",
        "1.2.3",
        tmp_path,
        "pipx",
    )
    assert Path(cmd[0]).name == "broken-entrypoint"
    monkeypatch.setattr(smoke, "WORK_HOME", tmp_path)
    with pytest.raises(FileNotFoundError):
        smoke.session(cmd, {"UNIFI_API_KEY": smoke.GOOD_MOCK_KEY})


def test_version_mismatch_fails_an_otherwise_successful_launcher(monkeypatch):
    monkeypatch.setattr(smoke, "missing_key", lambda cmd: (True, "UNIFI_API_KEY required"))

    def row(version, error=False):
        return {
            "started": True,
            "tools": 1,
            "names": ["list_hosts"],
            "version": version,
            "read": {"error": error, "text": "HTTP 401" if error else "{}"},
            "stderr": "",
        }

    for reported, expected in [("1.2.3", True), ("0.0.0", False), (None, False)]:
        replies = iter([row(reported), row(reported, True)])
        monkeypatch.setattr(smoke, "session", lambda *a, replies=replies: next(replies))
        result = smoke.check_row(
            "version",
            [],
            {"good_env": {}, "wrong_env": {}},
            1,
            {"list_hosts"},
            expected_version="1.2.3",
        )
        assert result["version_ok"] is expected
        assert result["tools_ok"] and result["read"] and result["wrong_key"]


def test_antigravity_manifest_entrypoint_mutation_fails(monkeypatch, tmp_path):
    directory = tmp_path / "plugins/antigravity"
    directory.mkdir(parents=True)
    manifest = directory / "mcp_config.json"
    monkeypatch.setattr(smoke, "ROOT", tmp_path)
    server = {
        "command": "uvx",
        "args": ["--from", "unifi-fabric-mcp-server==1.2.3", "unifi-fabric-mcp"],
    }
    manifest.write_text(json.dumps({"mcpServers": {"unifi": server}}))
    case = {"mode": "antigravity", "body": ""}
    assert smoke.parsed_launcher(case, tmp_path / "x.whl", "1.2.3")[-1] == smoke.ENTRY
    server["args"][-1] = "broken-entrypoint"
    manifest.write_text(json.dumps({"mcpServers": {"unifi": server}}))
    with pytest.raises(ValueError, match="entrypoint"):
        smoke.parsed_launcher(case, tmp_path / "x.whl", "1.2.3")


def test_antigravity_readme_command_mutation_fails(monkeypatch, tmp_path):
    directory = tmp_path / "plugins/antigravity"
    directory.mkdir(parents=True)
    (directory / "mcp_config.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "unifi": {
                        "command": "uvx",
                        "args": ["--from", "unifi-fabric-mcp-server==1.2.3", "unifi-fabric-mcp"],
                    }
                }
            }
        )
    )
    monkeypatch.setattr(smoke, "ROOT", tmp_path)
    case = {
        "mode": "antigravity",
        "body": (
            "agy mcp add unifi-fabric -- uvx --from "
            "unifi-fabric-mcp-server==1.2.3 broken-entrypoint"
        ),
    }
    with pytest.raises(ValueError, match="entrypoint"):
        smoke.parsed_launcher(case, tmp_path / "x.whl", "1.2.3")


@pytest.fixture
def source_archive(tmp_path):
    import io
    import tarfile

    archive_path = tmp_path / "source.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        content = b'[project]\nname = "unifi-fabric-mcp-server"\n'
        member = tarfile.TarInfo("unifi-fabric-mcp-server-1.2.3/pyproject.toml")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return archive_path


@pytest.mark.parametrize(
    "setup",
    [
        "cd nonexistent-review-directory",
        "cd unifi-fabric-mcp-server ignored",
        "source nonexistent/bin/activate",
        "source .venv/bin/activate ignored",
        "source .venv/bin/python",
    ],
)
def test_source_rejects_discarded_setup_mutations(monkeypatch, tmp_path, source_archive, setup):
    monkeypatch.setattr(smoke, "checked", lambda *a, **k: None)
    body = (
        "git clone https://github.com/swkstudios/unifi-fabric-mcp-server.git\n"
        "cd unifi-fabric-mcp-server\npython3 -m venv .venv\n"
        f"{setup}\npip install -e .\nunifi-fabric-mcp\n"
    )
    with pytest.raises(ValueError, match="directory|activation"):
        smoke.prepare_sequence(
            {"id": "source", "mode": "source", "body": body}, source_archive, "1.2.3", tmp_path
        )


def test_windows_normalizes_documented_venv_paths(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(smoke.platform, "system", lambda: "Windows")
    monkeypatch.setattr(smoke, "checked", lambda argv, **kw: calls.append(argv))
    case = {
        "id": "pip",
        "mode": "pip",
        "body": (
            "python3 -m venv .venv\n"
            ".venv/bin/python -m pip install unifi-fabric-mcp-server==1.2.3\n"
            ".venv/bin/unifi-fabric-mcp\n"
        ),
    }
    command = smoke.prepare_sequence(case, tmp_path / "x.tar.gz", "1.2.3", tmp_path)
    bindir = tmp_path / "pip/.venv/Scripts"
    assert calls[1][0] == str(bindir / "python.exe")
    assert calls[2][0] == str(bindir / "python.exe")
    assert command == [str(bindir / "unifi-fabric-mcp.exe")]


def test_workflow_build_tooling_is_outside_source_inputs(tmp_path):
    import re
    import shlex

    workflow = (smoke.ROOT / ".github/workflows/install-smoke.yml").read_text()
    commands = re.findall(r"^ +python -m venv (.+)$", workflow, re.MULTILINE)
    assert len(commands) == 6
    workspace = tmp_path / "source"
    runner = tmp_path / "runner"
    workspace.mkdir()
    runner.mkdir()
    for command in commands:
        destination = shlex.split(command.replace("$RUNNER_TEMP", str(runner)))[0]
        assert not (workspace / destination).resolve().is_relative_to(workspace)


@pytest.mark.parametrize("mode", ["pip", "source"])
def test_windows_native_scripts_paths(monkeypatch, tmp_path, source_archive, mode):
    calls = []
    monkeypatch.setattr(smoke.platform, "system", lambda: "Windows")
    monkeypatch.setattr(smoke, "checked", lambda argv, **kw: calls.append(argv))
    prefix = ""
    if mode == "source":
        prefix = (
            "git clone https://github.com/swkstudios/unifi-fabric-mcp-server.git\n"
            "cd unifi-fabric-mcp-server\n"
        )
    install = "-e ." if mode == "source" else "unifi-fabric-mcp-server==1.2.3"
    case = {
        "id": mode,
        "mode": mode,
        "body": prefix
        + (
            "python3 -m venv .venv\nsource .venv/Scripts/activate\n"
            f".venv/Scripts/python.exe -m pip install {install}\n"
            ".venv/Scripts/unifi-fabric-mcp.exe\n"
        ),
    }
    command = smoke.prepare_sequence(case, source_archive, "1.2.3", tmp_path)
    assert calls[1][0].endswith("/.venv/Scripts/python.exe")
    assert calls[2][0] == calls[1][0]
    assert command[0].endswith("/.venv/Scripts/unifi-fabric-mcp.exe")


@pytest.mark.parametrize(
    "destination",
    [
        "/tmp/escape",  # noqa: S108 - rejected before execution
        "../escape",
        ".venv/../../escape",
        "-venv",
        "--system-site-packages",
        "~/.venv",
        "~venv",
        "$HOME/v",
        "${HOME}/v",
        "$(pwd)/v",
        "`pwd`/v",
        "v*",
        "v?",
        "v[0]",
        "{a,b}",
        "%USERPROFILE%/v",
        "v!",
    ],
)
def test_venv_destination_must_stay_inside_case_home_before_execution(
    monkeypatch, tmp_path, destination
):
    calls = []
    monkeypatch.setattr(smoke, "checked", lambda argv, **kw: calls.append(argv))
    case = {"id": "pip", "mode": "pip", "body": f"python3 -m venv {destination}\n"}
    with pytest.raises(ValueError, match="virtual environment destination"):
        smoke.prepare_sequence(case, tmp_path / "x.tar.gz", "1.2.3", tmp_path)
    assert calls == []


def test_install_after_launcher_is_rejected_before_execution(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(smoke, "checked", lambda argv, **kw: calls.append(argv))
    case = {
        "id": "pip",
        "mode": "pip",
        "body": (
            "python3 -m venv .venv\n"
            ".venv/bin/python -m pip install unifi-fabric-mcp-server==1.2.3\n"
            ".venv/bin/unifi-fabric-mcp\n"
            ".venv/bin/python -m pip install unifi-fabric-mcp-server==1.2.3\n"
        ),
    }
    with pytest.raises(ValueError, match="after documented launcher"):
        smoke.prepare_sequence(case, tmp_path / "x.tar.gz", "1.2.3", tmp_path)
    assert len(calls) == 3


@pytest.fixture
def symlinked_work(tmp_path):
    """A work directory reached through a symlink, like macOS /var -> /private/var."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    return link, real


@pytest.mark.parametrize("mode", ["pip", "source"])
def test_symlinked_work_dir_accepts_documented_venv_activation(
    monkeypatch, symlinked_work, source_archive, mode
):
    link, real = symlinked_work
    calls = []
    monkeypatch.setattr(smoke.platform, "system", lambda: "Linux")
    monkeypatch.setattr(smoke, "checked", lambda argv, **kw: calls.append((argv, kw)))
    prefix = ""
    install = "unifi-fabric-mcp-server==1.2.3"
    if mode == "source":
        prefix = (
            "git clone https://github.com/swkstudios/unifi-fabric-mcp-server.git\n"
            "cd unifi-fabric-mcp-server\n"
        )
        install = "-e ."
    case = {
        "id": mode,
        "mode": mode,
        "body": prefix
        + (
            "python3 -m venv .venv && source .venv/bin/activate\n"
            f".venv/bin/python -m pip install {install}\n"
            "unifi-fabric-mcp\n"
        ),
    }
    command = smoke.prepare_sequence(case, source_archive, "1.2.3", link)
    home = real / mode
    if mode == "pip":
        venv = home / ".venv"
    else:
        venv = home / "checkout/unifi-fabric-mcp-server-1.2.3/.venv"
    assert command == [str(venv / "bin/unifi-fabric-mcp")]
    # Every executed path and cwd derives from the resolved work directory.
    assert calls[2][0][0] == str(venv / "bin/python")
    for _argv, kw in calls:
        if kw.get("cwd") is not None:
            assert Path(kw["cwd"]).is_relative_to(real)
        assert str(link) not in kw["env"]["PATH"]


@pytest.mark.parametrize(
    "body",
    [
        "pipx install unifi-fabric-mcp-server==1.2.3\nunifi-fabric-mcp\npipx uninstall x\n",
        "pipx install unifi-fabric-mcp-server==1.2.3\nunifi-fabric-mcp && touch pwned\n",
        "pipx install unifi-fabric-mcp-server==1.2.3\nunifi-fabric-mcp\nunifi-fabric-mcp\n",
    ],
)
def test_pipx_command_after_launcher_is_rejected_before_execution(monkeypatch, tmp_path, body):
    calls = []
    monkeypatch.setattr(smoke, "checked", lambda argv, **kw: calls.append(argv))
    case = {"id": "pipx", "mode": "pipx", "body": body}
    with pytest.raises(ValueError, match="after documented launcher"):
        smoke.prepare(case, tmp_path / "x.whl", tmp_path / "x.tar.gz", "1.2.3", tmp_path, "pipx")
    assert calls == []


def test_pipx_unexpected_pipx_command_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(smoke, "checked", lambda *a, **k: None)
    body = "pipx install unifi-fabric-mcp-server==1.2.3\npipx inject x y\nunifi-fabric-mcp\n"
    with pytest.raises(ValueError, match="pipx command"):
        smoke.prepare(
            {"id": "pipx", "mode": "pipx", "body": body},
            tmp_path / "x.whl",
            tmp_path / "x.tar.gz",
            "1.2.3",
            tmp_path,
            "pipx",
        )


def _simulated_main(monkeypatch, tmp_path, system, docker_ok, *, skip_docker=False, targets=None):
    """Run main() over the real documentation with every launcher probe simulated."""
    passed = dict.fromkeys(
        ("starts", "tools_ok", "read", "missing_key", "wrong_key", "version_ok"), True
    )
    monkeypatch.setattr(smoke.platform, "system", lambda: system)
    monkeypatch.setattr(smoke, "prepare", lambda *a, **k: ["launcher"])

    def capture_row(_name, _cmd, target, *_args, **_kwargs):
        if targets is not None:
            targets.append(target)
        return dict(passed)

    monkeypatch.setattr(smoke, "check_row", capture_row)
    monkeypatch.setattr(smoke, "validate_docker_case", lambda *a: True)
    monkeypatch.setattr(smoke, "docker_launcher", lambda *a: ([], "local-image"))
    monkeypatch.setattr(smoke, "checked", lambda *a, **k: None)

    def capture_docker(_case, _image, _version, target, *_args):
        if targets is not None:
            targets.append(target)
        return {**passed, "read": docker_ok}

    monkeypatch.setattr(smoke, "check_docker", capture_docker)
    wheel = tmp_path / "unifi_fabric_mcp_server-0.0.0-py3-none-any.whl"
    sdist = tmp_path / "unifi_fabric_mcp_server-0.0.0.tar.gz"
    wheel.write_bytes(b"")
    sdist.write_bytes(b"")
    out = tmp_path / "install-results.json"
    argv = ["install_smoke.py", "--wheel", str(wheel), "--sdist", str(sdist), "--out", str(out)]
    if skip_docker:
        argv.append("--skip-docker")
    monkeypatch.setattr(sys, "argv", argv)
    return smoke.main(), json.loads(out.read_text())


def test_full_catalog_probe_does_not_enable_read_only(monkeypatch, tmp_path):
    targets = []
    code, _report = _simulated_main(monkeypatch, tmp_path, "Linux", docker_ok=True, targets=targets)
    assert code == 0
    assert targets
    assert all("UNIFI_WRITE_POLICY" not in target["good_env"] for target in targets)
    assert all("UNIFI_WRITE_POLICY" not in target["wrong_env"] for target in targets)


DOCKER_CLAIMS = {"readme-install-24", "readme-install-25", "readme-install-27"}


@pytest.mark.parametrize("system", ["Darwin", "Windows"])
def test_release_rehearsal_off_linux_passes_with_docker_claims_recorded(
    monkeypatch, tmp_path, capsys, system
):
    code, report = _simulated_main(monkeypatch, tmp_path, system, docker_ok=True)
    assert code == 0, capsys.readouterr().err
    assert report["platform"] == system
    rows = {row["id"]: row for row in report["cases"]}
    assert {rows[c]["status"] for c in DOCKER_CLAIMS} == {"NOT-TESTED"}
    recorded = report["doc_claims_not_tested"]
    assert {entry["id"] for entry in recorded} == DOCKER_CLAIMS
    for entry in recorded:
        assert entry["platform"] == system
        assert entry["reason"] == "Docker runs on the Linux job only"
    assert "readme-install-24" in capsys.readouterr().out


def test_linux_docker_claims_stay_strict(monkeypatch, tmp_path, capsys):
    code, report = _simulated_main(monkeypatch, tmp_path, "Linux", docker_ok=True)
    assert code == 0, capsys.readouterr().err
    assert report["doc_claims_not_tested"] == []
    code, report = _simulated_main(monkeypatch, tmp_path, "Linux", docker_ok=False)
    assert code == 1
    err = capsys.readouterr().err
    for case_id in DOCKER_CLAIMS:
        assert f"executed case {case_id} has no successful execution evidence" in err


def test_linux_pr_smoke_records_deferred_docker_claims(monkeypatch, tmp_path, capsys):
    code, report = _simulated_main(
        monkeypatch, tmp_path, "Linux", docker_ok=False, skip_docker=True
    )
    assert code == 0, capsys.readouterr().err
    rows = {row["id"]: row for row in report["cases"]}
    assert {rows[c]["status"] for c in DOCKER_CLAIMS} == {"NOT-TESTED"}
    assert {rows[c]["reason"] for c in DOCKER_CLAIMS} == {
        "Docker cases run only on a protected-ref manual dispatch or release path"
    }
    assert {entry["id"] for entry in report["doc_claims_not_tested"]} == DOCKER_CLAIMS


def test_clean_env_preserves_python_loader_path_without_host_service_settings(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(smoke, "WORK_HOME", tmp_path)
    monkeypatch.setenv("LD_LIBRARY_PATH", "/toolcache/python/lib")
    monkeypatch.setenv("UNIFI_API_KEY", "host-service-key")
    monkeypatch.setenv("MCP_BEARER_TOKEN", "host-bearer")
    monkeypatch.setenv("DOCKER_HOST", "tcp://docker:2376")
    env = smoke.clean_env()
    assert env["LD_LIBRARY_PATH"] == "/toolcache/python/lib"
    assert env["HOME"] == str(tmp_path)
    assert not {"UNIFI_API_KEY", "MCP_BEARER_TOKEN", "DOCKER_HOST"} & env.keys()


def test_linux_install_workflow_uses_plain_runner_and_defers_docker():
    install = yaml.safe_load((smoke.ROOT / ".github/workflows/install-smoke.yml").read_text())
    ci = yaml.safe_load((smoke.ROOT / ".github/workflows/ci.yml").read_text())
    # The plain runner is the one the required test job uses, in either tree: the
    # exact private label is pinned in the private-only workflow-forms test.
    assert install["jobs"]["linux"]["runs-on"] == ci["jobs"]["test"]["runs-on"]
    workflow = (smoke.ROOT / ".github/workflows/install-smoke.yml").read_text()
    linux = workflow.split("  linux:", 1)[1].split("  linux-docker:", 1)[0]
    assert "--skip-docker" in linux


def test_pull_request_docker_job_is_guarded_and_public_transform_uses_public_runner():
    workflow = yaml.safe_load((smoke.ROOT / ".github/workflows/ci.yml").read_text())
    job = workflow["jobs"]["docker-build-amd64"]
    runner = job["runs-on"]
    # The exact private runner label is pinned in the private-only workflow-forms test.
    if "self-hosted" in runner:
        assert runner[:3] == ["self-hosted", "Linux", "X64"] and len(runner) == 4
        assert "github.event.pull_request.head.repo.full_name == github.repository" in job["if"]
        build = next(
            step
            for step in job["steps"]
            if step.get("name") == "Build the image for linux/amd64 and linux/arm64 (no push)"
        )
        assert "push" not in build["with"]
        assert build["with"]["outputs"].startswith("type=oci,")
        assert "cache-to" in build["with"]
        assert "default_branch" in build["with"]["cache-to"]
        assert not any("login" in step.get("uses", "") for step in job["steps"])
        assert "packages" not in job.get("permissions", {})
    else:
        assert runner == "ubuntu-latest"
        assert "self-hosted" not in str(runner)


@pytest.mark.parametrize("module_name", ["install_smoke", "gen_catalog_figures"])
def test_progressing_stdio_step_outlives_former_limit(monkeypatch, tmp_path, module_name):
    """Advance virtual time past every old watchdog while replies keep arriving."""
    import importlib
    import io
    import threading

    module = importlib.import_module(module_name)
    elapsed = 0
    watchdogs = []

    class Watchdog:
        def __init__(self, delay, callback):
            self.at = elapsed + delay
            self.callback = callback

        def start(self):
            watchdogs.append(self)

        def cancel(self):
            if self in watchdogs:
                watchdogs.remove(self)

    class Replies(io.StringIO):
        def readline(self, *args):
            nonlocal elapsed
            elapsed += 301
            for watchdog in list(watchdogs):
                if elapsed >= watchdog.at:
                    watchdog.callback()
            if process.killed:
                return ""
            return super().readline(*args)

    replies = [
        {"id": 1, "result": {"serverInfo": {"version": "1.2.3"}}},
        {"id": 2, "result": {"tools": [{"name": "list_hosts"}]}},
    ]
    raw = "".join(json.dumps(reply) + "\n" for reply in replies)

    class Process:
        stdin = io.BytesIO() if module_name == "gen_catalog_figures" else io.StringIO()
        stdout = Replies(raw)
        stderr = io.StringIO("progress\n" * 10)
        killed = False
        returncode = None

        def kill(self):
            self.killed = True

        def poll(self):
            return self.returncode

        def wait(self):
            self.returncode = 0
            return 0

    process = Process()
    if module_name == "gen_catalog_figures":
        # The figure reader uses binary pipes.
        original_readline = process.stdout.readline
        process.stdout.readline = lambda: original_readline().encode()
    monkeypatch.setattr(threading, "Timer", Watchdog)
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **kw: process)
    if module_name == "install_smoke":
        monkeypatch.setattr(module, "WORK_HOME", tmp_path)
    if module_name == "gen_catalog_figures":
        assert module._measure(None)[0] == 1
    else:
        result = module.session(["fake-server"], {"UNIFI_API_KEY": "synthetic"}, call=False)
        assert result["started"] and result["tools"] == 1
        assert "error" not in result
        assert not process.killed
    assert elapsed > 300
    assert not watchdogs


@pytest.mark.parametrize("module_name", ["install_smoke"])
def test_stdio_closed_pipe_fails_without_waiting_for_clock(monkeypatch, tmp_path, module_name):
    import importlib
    import io

    module = importlib.import_module(module_name)

    class Process:
        stdin = io.StringIO()
        stdout = io.StringIO("")
        stderr = io.StringIO("server failed\n")
        killed = False

        def poll(self):
            return 1

        def wait(self):
            return 1

    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **kw: Process())
    if module_name == "install_smoke":
        monkeypatch.setattr(module, "WORK_HOME", tmp_path)
    result = module.session(["fake-server"], {"UNIFI_API_KEY": "synthetic"})
    assert not result["started"]
    assert result["error"] == "server closed stdout"
    assert "server failed" in result["stderr"]


@pytest.mark.parametrize("module_name", ["install_smoke"])
def test_missing_key_requires_failure_exit_and_has_no_wall_clock_limit(
    monkeypatch, tmp_path, module_name
):
    import importlib
    from types import SimpleNamespace

    module = importlib.import_module(module_name)
    if module_name == "install_smoke":
        monkeypatch.setattr(module, "WORK_HOME", tmp_path)
    for exit_code in (0, 1):

        def run(*args, exit_code=exit_code, **kwargs):
            assert "timeout" not in kwargs
            return SimpleNamespace(returncode=exit_code, stdout="", stderr="UNIFI_API_KEY required")

        monkeypatch.setattr(module.subprocess, "run", run)
        assert module.missing_key(["fake-server"])[0] is (exit_code != 0)


def test_install_command_waits_for_exit_and_preserves_real_failure(monkeypatch):
    from types import SimpleNamespace

    for exit_code in (0, 2):

        def run(*args, exit_code=exit_code, **kwargs):
            assert "timeout" not in kwargs
            return SimpleNamespace(returncode=exit_code, stderr="install failed")

        monkeypatch.setattr(smoke.subprocess, "run", run)
        if exit_code:
            with pytest.raises(RuntimeError, match="failed \\(2\\)"):
                smoke.checked(["fake-install"])
        else:
            smoke.checked(["fake-install"])


@pytest.mark.parametrize("script", ["install_smoke.py", "gen_catalog_figures.py"])
def test_local_ci_steps_have_no_elapsed_work_limits(script):
    import ast

    tree = ast.parse((Path(__file__).resolve().parents[1] / "scripts" / script).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            assert not any(kw.arg == "timeout" for kw in node.keywords), script
            if isinstance(node.func, ast.Attribute):
                assert node.func.attr != "Timer", script
        if isinstance(node, ast.Name):
            assert node.id not in {"deadline", "STEP_TIMEOUT"}, script


def test_full_artifact_catalog_smoke_explicitly_selects_full_mode(monkeypatch, tmp_path):
    targets = []
    code, report = _simulated_main(monkeypatch, tmp_path, "Linux", docker_ok=True, targets=targets)
    assert code == 0
    assert report["expected_tools"] > 5
    assert targets
    for target in targets:
        assert target["good_env"]["UNIFI_TOOL_MODE"] == "full"
        assert target["wrong_env"]["UNIFI_TOOL_MODE"] == "full"


def test_install_artifact_upload_preserves_hidden_failure_diagnostics():
    workflow = yaml.safe_load((smoke.ROOT / ".github/workflows/install-smoke.yml").read_text())
    for job in ("linux", "linux-docker"):
        upload = next(
            step
            for step in workflow["jobs"][job]["steps"]
            if step.get("uses", "").startswith("actions/upload-artifact@")
        )
        assert ".install-diagnostics/" in upload["with"]["path"]
        assert upload["with"]["include-hidden-files"] is True
        assert upload["if"] == "always()"
