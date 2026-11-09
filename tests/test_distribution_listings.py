"""Registry listing contract.

``server.json`` is what MCP registry clients build their configuration form from, so each
setting it declares must offer exactly the values the server accepts, and every setting a
client manifest exposes to the user must be declared there too.
"""

from __future__ import annotations

import json
import types
import typing
from pathlib import Path

import pytest

from unifi_fabric import policy
from unifi_fabric.config import MCPTransportSettings, Settings

ROOT = Path(__file__).resolve().parents[1]
SERVER_JSON = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
PACKAGES = SERVER_JSON["packages"]

# A setting whose model field is a plain string but whose grammar is a closed set.
_CLOSED_STRING_SETTINGS = {"UNIFI_WRITE_POLICY": tuple(policy.WRITE_POLICIES)}


def _accepted_values() -> dict[str, tuple[str, ...]]:
    """Env name -> accepted values for every closed-set setting of both settings models."""
    out: dict[str, tuple[str, ...]] = dict(_CLOSED_STRING_SETTINGS)
    for model in (Settings, MCPTransportSettings):
        prefix = str(model.model_config.get("env_prefix") or "")
        for name, field in model.model_fields.items():
            alias = field.validation_alias
            env = alias.upper() if isinstance(alias, str) else f"{prefix}{name}".upper()
            ann = field.annotation
            if typing.get_origin(ann) in (typing.Union, types.UnionType):
                ann = next(a for a in typing.get_args(ann) if a is not type(None))
            if typing.get_origin(ann) is typing.Literal:
                out[env] = tuple(str(a) for a in typing.get_args(ann))
    return out


ACCEPTED = _accepted_values()


def _declared() -> list[tuple[str, dict]]:
    return [
        (pkg["registryType"], var)
        for pkg in PACKAGES
        for var in pkg.get("environmentVariables", [])
    ]


@pytest.mark.parametrize(
    ("registry", "var"), _declared(), ids=lambda x: x if isinstance(x, str) else x["name"]
)
def test_declared_choices_equal_what_the_server_accepts(registry: str, var: dict) -> None:
    name = var["name"]
    if name not in ACCEPTED:
        assert "choices" not in var, f"{registry} {name}: choices for an open-ended setting"
        return
    assert sorted(var.get("choices", [])) == sorted(ACCEPTED[name]), (
        f"{registry} {name}: server.json choices {var.get('choices')} != accepted "
        f"{list(ACCEPTED[name])}"
    )
    if "default" in var:
        assert var["default"] in var["choices"], f"{registry} {name}: default not a choice"


def _manifest_env_names() -> set[str]:
    """Every env var a client manifest lets the user set (fixed values excluded)."""
    names: set[str] = set()
    desktop = json.loads((ROOT / "plugins/claude-desktop/manifest.json").read_text())
    claude = json.loads((ROOT / "plugins/claude/.claude-plugin/plugin.json").read_text())
    for env in (
        desktop["server"]["mcp_config"]["env"],
        *(s.get("env", {}) for s in claude["mcpServers"].values()),
    ):
        names |= {k for k, v in env.items() if "${user_config." in v}
    codex = json.loads((ROOT / "plugins/codex/.mcp.json").read_text())
    for server in codex["mcpServers"].values():
        names |= set(server.get("env_vars", []))
    gemini = json.loads((ROOT / "gemini-extension.json").read_text())
    names |= {s["envVar"] for s in gemini.get("settings", []) if "envVar" in s}
    return names


def test_manifests_expose_settings():
    # Guard against the helper silently finding nothing.
    assert {"UNIFI_API_KEY", "UNIFI_WRITE_POLICY", "UNIFI_TOOL_MODE"} <= _manifest_env_names()


@pytest.mark.parametrize("pkg", PACKAGES, ids=lambda p: p["registryType"])
def test_every_manifest_setting_is_declared_in_each_registry_package(pkg: dict) -> None:
    declared = {v["name"] for v in pkg.get("environmentVariables", [])}
    missing = sorted(_manifest_env_names() - declared)
    assert not missing, f"server.json {pkg['registryType']} package does not declare {missing}"
