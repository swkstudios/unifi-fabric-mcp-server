"""Extraction and launcher mutation checks for executable install examples."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import extract_install_cases as extraction  # noqa: E402
import install_smoke as smoke  # noqa: E402

# Every README install region's start and end heading; extraction fails closed when
# one is missing, so planted READMEs end with the full set.
REGION_HEADINGS = (
    "## Quick Start\n## Example Prompts\n## Set up your client\n"
    "## About this server\n## Docker Deployment\n## Contributing\n"
)


def tree(tmp_path: Path, content: str) -> Path:
    (tmp_path / "docs").mkdir()
    (tmp_path / "plugins").mkdir()
    (tmp_path / "README.md").write_text(content)
    return tmp_path


def marked(body: str, mode: str = "uvx") -> str:
    return f"<!-- install-case: sample mode={mode} -->\n```bash\n{body}\n```\n"


def test_repo_install_cases_have_unique_ids_and_all_core_paths():
    cases = extraction.extract_cases()
    assert len({c["id"] for c in cases}) == len(cases)
    assert {"uvx", "pipx", "pip", "desktop", "codex", "plugin", "source", "docker"} <= {
        c["mode"] for c in cases
    }


def test_removed_marker_fails(tmp_path):
    root = tree(
        tmp_path, "```bash\nuvx --from unifi-fabric-mcp-server==0.6.4 unifi-fabric-mcp\n```"
    )
    with pytest.raises(ValueError, match="unmarked"):
        extraction.extract_cases(root)


def test_non_executable_requires_reason(tmp_path):
    root = tree(tmp_path, marked("docker pull image", "non-executable"))
    with pytest.raises(ValueError, match="requires a reason"):
        extraction.extract_cases(root)


def test_duplicate_case_fails(tmp_path):
    content = marked("uvx --from unifi-fabric-mcp-server==0.6.4 unifi-fabric-mcp")
    with pytest.raises(ValueError, match="duplicate"):
        extraction.extract_cases(tree(tmp_path, content + content))


def test_unknown_mode_fails(tmp_path):
    with pytest.raises(ValueError, match="unknown execution mode"):
        extraction.extract_cases(tree(tmp_path, marked("uvx package", "typo")))


@pytest.mark.parametrize(
    "mutation",
    [
        ["uvx", "--from", "unifi-fabric-mcp-server==0.0.0", "unifi-fabric-mcp"],
        ["uvx", "--from", "unifi-fabric-mcp-server==0.6.4", "broken-entrypoint"],
        ["unexpected", "--from", "unifi-fabric-mcp-server==0.6.4", "unifi-fabric-mcp"],
    ],
)
def test_broken_launcher_or_pin_fails(mutation, tmp_path):
    with pytest.raises(ValueError):
        smoke.repin(mutation, tmp_path / "local.whl", "0.6.4")


def test_valid_pin_is_replaced_with_local_artifact(tmp_path):
    wheel = tmp_path / "local.whl"
    result = smoke.repin(
        ["uvx", "--from", "unifi-fabric-mcp-server==0.6.4", "unifi-fabric-mcp"], wheel, "0.6.4"
    )
    assert result[2] == str(wheel)


def test_broken_desktop_json_fails(tmp_path):
    with pytest.raises(ValueError):
        smoke.parsed_launcher(
            {"mode": "desktop", "body": "{broken"}, tmp_path / "local.whl", "0.6.4"
        )


def test_wrong_key_message_must_be_clean(monkeypatch):
    monkeypatch.setattr(smoke, "missing_key", lambda cmd: (True, "UNIFI_API_KEY required"))
    good = {"started": True, "tools": 2, "read": {"error": False, "text": "{}"}, "stderr": ""}
    wrong = {
        "started": True,
        "tools": 2,
        "read": {"error": True, "text": "401 Traceback"},
        "stderr": "",
    }
    replies = iter([good, wrong])
    monkeypatch.setattr(smoke, "session", lambda *args: next(replies))
    assert not smoke.check_row("mutation", [], {"good_env": {}, "wrong_env": {}}, 2)["wrong_key"]


def test_documentation_does_not_request_sudo_pip(tmp_path):
    with pytest.raises(ValueError, match="sudo pip"):
        extraction.extract_cases(tree(tmp_path, marked("sudo pip install example", "pip")))


def test_docker_never_runs_on_non_linux(monkeypatch, tmp_path):
    monkeypatch.setattr(smoke.platform, "system", lambda: "Darwin")
    with pytest.raises(ValueError, match="only permitted on Linux"):
        smoke.docker_launcher(tmp_path / "local.whl", tmp_path)


@pytest.mark.parametrize(
    "replacement",
    [
        "ghcr.io/swkstudios/unifi-fabric-mcp-server:0.0.0",
        "ghcr.io/swkstudios/unifi-fabric-mcp-server:0.6.4 broken-entrypoint",
    ],
)
def test_broken_docker_image_or_entrypoint_fails(replacement):
    case = {
        "language": "bash",
        "body": (
            'docker run -e UNIFI_API_KEY="your-api-key-here" -p 127.0.0.1:3000:3000 ' + replacement
        ),
    }
    with pytest.raises(ValueError, match="image pin or entrypoint"):
        smoke.validate_docker_case(case, "0.6.4")


def test_changed_docker_port_fails():
    case = {
        "language": "bash",
        "body": (
            'docker run -e UNIFI_API_KEY="your-api-key-here" '
            "-p 3000:3000 ghcr.io/swkstudios/unifi-fabric-mcp-server:0.6.4"
        ),
    }
    with pytest.raises(ValueError, match="port"):
        smoke.validate_docker_case(case, "0.6.4")


def test_source_install_typo_fails(tmp_path):
    case = {"id": "source", "mode": "source", "body": "git clone project\npip insatll -e ."}
    with pytest.raises(ValueError, match="editable install"):
        smoke.prepare(
            case, tmp_path / "local.whl", tmp_path / "local.tar.gz", "0.6.4", tmp_path, "pipx"
        )


def test_same_count_with_wrong_catalog_names_fails(monkeypatch):
    monkeypatch.setattr(smoke, "missing_key", lambda cmd: (True, "UNIFI_API_KEY required"))
    good = {
        "started": True,
        "tools": 2,
        "names": ["wrong_a", "wrong_b"],
        "read": {"error": False, "text": "{}"},
        "stderr": "",
    }
    wrong = {
        "started": True,
        "tools": 2,
        "read": {"error": True, "text": "HTTP 401 Unauthorized"},
        "stderr": "",
    }
    replies = iter([good, wrong])
    monkeypatch.setattr(smoke, "session", lambda *args: next(replies))
    row = smoke.check_row(
        "mutation", [], {"good_env": {}, "wrong_env": {}}, 2, {"list_hosts", "list_sites"}
    )
    assert not row["tools_ok"]


@pytest.mark.parametrize(
    "server",
    [
        {"env": {"MISSPELLED_API_KEY": "your-api-key-here"}},
        {"env_vars": ["MISSPELLED_API_KEY", "UNIFI_READ_ONLY"]},
        {"env": {"UNIFI_API_KEY": "your-api-key-here", "FASTMCP_TRANSPORT": "broken"}},
    ],
)
def test_client_key_wiring_mutations_fail(server):
    with pytest.raises(ValueError):
        smoke.validate_key_wiring(server)


def test_client_inline_key_and_forwarded_key_are_valid():
    assert smoke.validate_key_wiring({"env_vars": ["UNIFI_API_KEY"]}) == {}
    assert smoke.validate_key_wiring(
        {"env": {"UNIFI_API_KEY": "your-api-key-here", "UNIFI_READ_ONLY": "1"}}
    ) == {"UNIFI_READ_ONLY": "1"}


def test_removed_plugin_launcher_marker_fails(tmp_path):
    root = tree(tmp_path, "```bash\nclaude --plugin-dir ./plugins/claude\n```")
    with pytest.raises(ValueError, match="unmarked install"):
        extraction.extract_cases(root)


def test_any_install_section_fence_requires_marker(tmp_path):
    root = tree(
        tmp_path,
        "## Set up your client\n\n```bash\ncodex\n```\n\n## About this server\n" + REGION_HEADINGS,
    )
    with pytest.raises(ValueError, match="unmarked install"):
        extraction.extract_cases(root)


def test_missing_docker_json_bearer_header_fails():
    case = {
        "language": "json",
        "body": (
            '{"mcpServers":{"unifi-fabric":{"type":"http","url":"http://localhost:3000/mcp"}}}'
        ),
    }
    with pytest.raises(ValueError, match="bearer HTTP client auth header"):
        smoke.validate_docker_case(case, "0.6.4")
