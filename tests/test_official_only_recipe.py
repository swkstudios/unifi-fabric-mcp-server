"""The documented official-only catalog really lists official APIs only.

``UNIFI_EXCLUDE=unofficial`` removes every tool whose primary API source is private, but
the generic ``fabric_connector_*`` relays (``relay/generic``, API status ``local``) stay,
and they relay any console route, private APIs included. The recipe the docs give for an
official-only catalog is therefore ``unofficial,source:relay``. These tests start the
server over stdio with that recipe and check every listed tool's API sources, check that
each public doc states this recipe and never offers ``unofficial`` alone as official-only,
and check that every relay description says it can reach private routes.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from unifi_fabric import api_sources

ROOT = Path(__file__).resolve().parents[1]
RECIPE = "unofficial,source:relay"
RELAYS = frozenset(f"fabric_connector_{verb}" for verb in ("get", "post", "put", "patch", "delete"))
#: Every public doc that states the official-only configuration.
# The README links the configuration guide for catalog selection and states no recipe itself.
OFFICIAL_ONLY_DOCS = ("AGENTS.md", "llms.txt", "docs/CONFIGURATION.md")


def _listed(exclude: str, write_policy: str | None = None) -> list[str]:
    """Tool names ``tools/list`` returns from the stdio entry point in full mode."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "MCP_", "FASTMCP_"))}
    env["UNIFI_API_KEY"] = "official-only-test-key"
    env["UNIFI_TOOL_MODE"] = "full"
    env["UNIFI_EXCLUDE"] = exclude
    if write_policy is not None:
        env["UNIFI_WRITE_POLICY"] = write_policy
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "official-only-test", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    proc = subprocess.Popen(  # noqa: S603 - this interpreter running the package's entry point
        [sys.executable, "-c", "from unifi_fabric.entrypoint import main; main()"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    try:
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write((json.dumps(messages[0]) + "\n").encode())
        proc.stdin.flush()
        for wanted, message in ((1, None), (2, messages[1:])):
            if message:
                for item in message:
                    proc.stdin.write((json.dumps(item) + "\n").encode())
                proc.stdin.flush()
            for line in iter(proc.stdout.readline, b""):
                reply = json.loads(line)
                if reply.get("id") == wanted:
                    break
            else:
                err = proc.stderr.read().decode() if proc.stderr else ""
                pytest.fail(f"server exited before answering request {wanted}: {err[-2000:]}")
    finally:
        proc.kill()
        proc.wait()
    result = reply["result"]
    assert result.get("nextCursor") is None, "tools/list is paginated; read every page"
    return [tool["name"] for tool in result["tools"]]


def _non_official(names: list[str]) -> dict[str, tuple[str, ...]]:
    """Each name whose API sources include one that is neither official nor server/local."""
    table = api_sources.table()
    out = {}
    for name in names:
        pairs = tuple(table.get(name, ()))
        bad = tuple(p for p in pairs if p != "server/local" and p.split("/", 1)[-1] != "official")
        if bad or not pairs:
            out[name] = bad or ("unclassified",)
    return out


@pytest.mark.parametrize("write_policy", [None, "deny"])
def test_recipe_lists_only_official_api_sources(write_policy: str | None) -> None:
    names = _listed(RECIPE, write_policy)
    assert "list_integration_device_tags" in names
    assert names, "the official-only recipe must leave tools listed"
    assert not (RELAYS & set(names)), "the official-only recipe must remove every relay"
    assert _non_official(names) == {}, "the official-only recipe lists non-official API sources"


def test_unofficial_alone_keeps_the_relays() -> None:
    """Why the recipe needs source:relay: unofficial alone leaves the relays listed."""
    names = _listed("unofficial")
    assert set(_non_official(names)) == RELAYS


def test_generator_measures_the_documented_recipe() -> None:
    from scripts import gen_catalog_figures as gen

    assert gen.OFFICIAL_ONLY_EXCLUDE == RECIPE
    assert gen.official_only_leaks(["fabric_connector_get", "list_hosts"]) == [
        "fabric_connector_get: relay/generic"
    ]


@pytest.mark.parametrize("doc", OFFICIAL_ONLY_DOCS)
def test_docs_state_the_official_only_recipe(doc: str) -> None:
    text = (ROOT / doc).read_text()
    assert f"UNIFI_EXCLUDE={RECIPE}" in text or f"UNIFI_EXCLUDE='{RECIPE}'" in text, (
        f"{doc} must give the official-only recipe UNIFI_EXCLUDE={RECIPE}"
    )
    # A sentence offering `UNIFI_EXCLUDE=unofficial` on its own must say it is not enough.
    for sentence in re.split(r"(?<=[.;])\s", text):
        if re.search(r"UNIFI_EXCLUDE=unofficial`", sentence):
            assert "alone" in sentence, (
                f"{doc} offers UNIFI_EXCLUDE=unofficial without the relays caveat: {sentence!r}"
            )


def test_relay_descriptions_say_they_reach_private_routes() -> None:
    import asyncio

    import unifi_fabric.server as server

    tools = {t.name: t for t in asyncio.run(server.mcp.list_tools()) if t.name in RELAYS}
    assert set(tools) == RELAYS
    for name, tool in tools.items():
        description = tool.description or ""
        assert re.search(r"private (API|route)", description), (
            f"{name} must say it can reach private routes"
        )
    first_line = (tools["fabric_connector_get"].description or "").splitlines()[0]
    assert "official" not in first_line, "the GET relay summary must not read as official-only"
