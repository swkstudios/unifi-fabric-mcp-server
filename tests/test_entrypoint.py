"""The one-shot exporter must not import MCP transport/auth setup."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


def test_placement_snapshot_export_bypasses_invalid_inherited_mcp_auth_settings():
    """A bearer canary cannot reach a traceback or output through the export path."""
    root = Path(__file__).parents[1]
    # Preserve the runner's interpreter-loader environment (notably
    # LD_LIBRARY_PATH on self-hosted Python builds).  Strip configuration
    # namespaces explicitly so this subprocess cannot consume ambient secrets
    # or connect to a real Fabric service.
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("UNIFI_", "MCP_", "FASTMCP_"))
    }
    env.update(
        {
            "PYTHONPATH": str(root / "src"),
            "MCP_AUTH_MODE": "bearer",
            "MCP_BEARER_TOKEN": "mcp-bearer-canary-must-not-leak",
        }
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from unifi_fabric.entrypoint import main; main()",
            "placement-snapshot",
            "--host",
            "HQ-Unifi",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    # No API key in this environment: the reason is named, the MCP_* settings never read.
    assert result.stderr == (
        "placement snapshot export failed: placement snapshot export requires an API key: "
        'set UNIFI_API_KEY, or UNIFI_API_KEYS to a JSON list of {"key": ..., "label": ...} '
        "objects, or point UNIFI_API_KEY_FILE / UNIFI_API_KEY_COMMAND (UNIFI_API_KEYS_FILE / "
        "UNIFI_API_KEYS_COMMAND for the list) at where the key is kept\n"
    )
    assert "mcp-bearer-canary-must-not-leak" not in result.stderr


def _run_entrypoint(arg: str) -> subprocess.CompletedProcess[str]:
    root = Path(__file__).parents[1]
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("UNIFI_", "MCP_", "FASTMCP_"))
    }
    env["PYTHONPATH"] = str(root / "src")
    return subprocess.run(  # noqa: S603 - fixed interpreter + literal command; arg is a test-controlled flag
        [sys.executable, "-c", "from unifi_fabric.entrypoint import main; main()", arg],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_help_runs_and_reports_version():
    """`--help` exits 0, needs no config, and reports the version."""
    from importlib.metadata import version

    result = _run_entrypoint("--help")
    assert result.returncode == 0
    assert "unifi-fabric-mcp" in result.stdout
    assert version("unifi-fabric-mcp-server") in result.stdout


def test_version_runs_and_reports_version():
    """`--version` exits 0, needs no config, and prints the version."""
    from importlib.metadata import version

    result = _run_entrypoint("--version")
    assert result.returncode == 0
    assert version("unifi-fabric-mcp-server") in result.stdout


def test_placement_snapshot_preflight_bypasses_invalid_inherited_mcp_auth_settings():
    """The preflight has the same no-MCP-runtime and secret-safe boundary."""
    root = Path(__file__).parents[1]
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("UNIFI_", "MCP_", "FASTMCP_"))
    }
    env.update(
        {
            "PYTHONPATH": str(root / "src"),
            "MCP_AUTH_MODE": "bearer",
            "MCP_BEARER_TOKEN": "mcp-bearer-canary-must-not-leak",
        }
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from unifi_fabric.entrypoint import main; main()",
            "placement-snapshot-preflight",
            "--host",
            "HQ-Unifi",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == (
        "placement snapshot capability preflight failed: placement snapshot preflight "
        "requires an API key: set UNIFI_API_KEY, or UNIFI_API_KEYS to a JSON list of "
        '{"key": ..., "label": ...} objects, or point UNIFI_API_KEY_FILE / '
        "UNIFI_API_KEY_COMMAND (UNIFI_API_KEYS_FILE / UNIFI_API_KEYS_COMMAND for the list) "
        "at where the key is kept\n"
    )
    assert "mcp-bearer-canary-must-not-leak" not in result.stderr


def _run_entrypoint_args(*args: str) -> subprocess.CompletedProcess[str]:
    root = Path(__file__).parents[1]
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("UNIFI_", "MCP_", "FASTMCP_"))
    }
    env["PYTHONPATH"] = str(root / "src")
    return subprocess.run(  # noqa: S603 - fixed interpreter + literal command; args are test-controlled
        [sys.executable, "-c", "from unifi_fabric.entrypoint import main; main()", *args],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_unknown_subcommand_is_rejected_with_valid_commands():
    """A word that is not a subcommand exits 2 instead of starting the MCP server."""
    result = _run_entrypoint_args("snapshot-export")
    assert result.returncode == 2
    assert result.stdout == ""
    assert "unknown command (value not shown)" in result.stderr
    assert "snapshot-export" not in result.stderr
    assert "placement-snapshot, placement-snapshot-preflight" in result.stderr
    assert "--help" in result.stderr


def test_mistyped_subcommand_suggests_the_closest_one():
    result = _run_entrypoint_args("placement-snapsht", "--host", "x")
    assert result.returncode == 2
    assert "Did you mean 'placement-snapshot'?" in result.stderr


def test_positional_after_a_flag_value_is_rejected():
    """A word after a flag's value is not that flag's value: it is rejected."""
    result = _run_entrypoint_args("--transport", "stdio", "snapshot-export")
    assert result.returncode == 2
    assert "unknown command (value not shown)" in result.stderr
    assert "snapshot-export" not in result.stderr


def test_positional_after_an_inline_flag_value_is_rejected():
    result = _run_entrypoint_args("--transport=stdio", "snapshot-export")
    assert result.returncode == 2
    assert "unknown command (value not shown)" in result.stderr
    assert "snapshot-export" not in result.stderr


def test_positional_after_double_dash_is_rejected():
    result = _run_entrypoint_args("--", "snapshot-export")
    assert result.returncode == 2
    assert "unknown command (value not shown)" in result.stderr
    assert "snapshot-export" not in result.stderr


@pytest.mark.parametrize(
    ("args", "stray"),
    [
        ([], []),
        (["--transport", "stdio"], []),
        (["--transport=stdio"], []),
        (["--log-level", "debug", "-v"], []),
        (["-v", "--transport", "stdio", "--port", "3000"], []),
        (["--transport", "-"], []),
        (["snapshot-export"], ["snapshot-export"]),
        (["--transport", "stdio", "extra"], ["extra"]),
        (["--transport=stdio", "extra"], ["extra"]),
        (["--", "x"], ["x"]),
        (["-", "x"], ["-", "x"]),
    ],
)
def test_stray_positionals_keep_flag_values(args, stray):
    from unifi_fabric import entrypoint

    assert entrypoint._stray_positionals(args) == stray


def test_unknown_command_is_rejected_before_server_import():
    """Rejection happens before the MCP runtime is imported (no config needed)."""
    from unifi_fabric import entrypoint

    with pytest.raises(SystemExit) as exc:
        entrypoint._reject_unknown_command(["snapshot-export"])
    assert exc.value.code == 2


def test_flags_and_empty_argv_reach_the_server(monkeypatch):
    """No arguments, or only dash flags, still start the server as before."""
    import types

    from unifi_fabric import entrypoint

    calls: list[list[str]] = []
    fake = types.ModuleType("unifi_fabric.server")
    fake.main = lambda: calls.append(list(sys.argv))  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "unifi_fabric.server", fake)
    import unifi_fabric

    monkeypatch.setattr(unifi_fabric, "server", fake, raising=False)
    monkeypatch.setattr(entrypoint, "_validate_api_key_configuration", lambda: None)
    argvs = (
        ["unifi-fabric-mcp"],
        ["unifi-fabric-mcp", "--log-level", "-v"],
        ["unifi-fabric-mcp", "--transport", "stdio"],
        ["unifi-fabric-mcp", "--transport=stdio", "--port", "3000"],
    )
    for argv in argvs:
        monkeypatch.setattr(sys, "argv", list(argv))
        entrypoint.main()
    assert calls == [list(argv) for argv in argvs]
