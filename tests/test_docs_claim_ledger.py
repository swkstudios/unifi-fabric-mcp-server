"""The docs claim ledger passes and the corrected audit/auth/docker/paging claims hold."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import re
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from unifi_fabric import server, transport_security
from unifi_fabric.audit import build_audit_sink
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import APIKeyConfig, MCPTransportSettings, Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools import carrier_fabric, innerspace, mobility, site_manager

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "docs_claim_ledger.py"
MANUAL = ROOT / "scripts" / "docs_claim_ledger_manual.json"
README = (ROOT / "README.md").read_text(encoding="utf-8")
MIGRATING = (ROOT / "docs" / "MIGRATING-0.7.md").read_text(encoding="utf-8")
TOOL_USAGE = (ROOT / "docs" / "TOOL-USAGE.md").read_text(encoding="utf-8")


def test_claim_ledger_check_passes(tmp_path: Path) -> None:
    report = tmp_path / "ledger.json"
    done = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), "--check", "--report", str(report)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    data = json.loads(report.read_text())
    records = data["records"]
    fields = {"claim_id", "doc", "claim", "kind", "source", "disposition", "reviewer"}
    assert records and all(set(r) == fields for r in records)
    assert {r["disposition"] for r in records} <= {
        "verified",
        "corrected",
        "historical",
        "manual-accepted",
    }
    ids = [r["claim_id"] for r in records]
    assert len(ids) == len(set(ids))
    assert {r["claim_id"] for r in records if r["disposition"] == "corrected"} >= {
        "readme-relay-audit",
        "auth-tls-bearer-mode",
        "migrating-change-027",
        "tool-usage-list-paging",
    }
    # Each manual source is reported at the line its source_find text starts on now.
    by_id = {r["claim_id"]: r for r in records}
    for entry in json.loads(MANUAL.read_text(encoding="utf-8")):
        if entry["source"] == "manual":
            continue
        rel, line = by_id[entry["claim_id"]]["source"].rsplit(":", 1)
        assert rel == entry["source"]
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert text[: text.index(entry["source_find"])].count("\n") + 1 == int(line), entry


def _manual_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, entries: list[dict]) -> Any:
    spec = importlib.util.spec_from_file_location("docs_claim_ledger_manual_only", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manual = tmp_path / "manual.json"
    manual.write_text(json.dumps(entries), encoding="utf-8")
    monkeypatch.setattr(module, "MANUAL_FILE", manual)
    # manual() reads only the root and its two output lists; skip the source sweep.
    ledger = module.Ledger.__new__(module.Ledger)
    ledger.root, ledger.records, ledger.findings = tmp_path, [], []
    ledger.manual()
    return ledger


def test_manual_source_line_follows_its_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "DOC.md").write_text("intro\nThe claim.\n", encoding="utf-8")
    (tmp_path / "src.py").write_text("a = 1\n\n\ndef evidence():\n    pass\n", encoding="utf-8")
    entry = {
        "claim_id": "c",
        "doc": "DOC.md",
        "find": "The claim.",
        "claim": "claim",
        "kind": "manual",
        "disposition": "verified",
        "reviewer": "maintainer",
        "source_find": "def evidence",
    }
    ledger = _manual_only(monkeypatch, tmp_path, [{**entry, "source": "src.py"}])
    assert ledger.findings == []
    assert [(r["doc"], r["source"]) for r in ledger.records] == [("DOC.md:2", "src.py:4")]

    pinned = _manual_only(monkeypatch, tmp_path, [{**entry, "source": "src.py:1"}])
    unanchored = _manual_only(
        monkeypatch, tmp_path, [{**entry, "source": "src.py", "source_find": ""}]
    )
    for ledger in (pinned, unanchored):
        assert ledger.records == []
        assert [
            "must be a file path with a source_find" in f["problem"] for f in ledger.findings
        ] == [True]


def _passages() -> dict[str, str]:
    usage = (ROOT / "docs" / "TOOL-USAGE.md").read_text(encoding="utf-8")
    config = (ROOT / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    relay = next(line for line in usage.splitlines() if line.startswith("- **Verbatim bodies"))
    start = config.index("\n## Audit log\n")
    section = config[start : config.index("<!-- BEGIN GENERATED: audit-schema -->", start)]
    return {"relay (Verbatim bodies + audit)": relay, "Optional audit log": section}


def test_audit_passages_carry_best_effort_qualifier() -> None:
    for name, text in _passages().items():
        lowered = text.lower()
        assert "best-effort" in lowered, name
        assert "UNIFI_AUDIT_LOG" in text, name
        assert re.search(r"unset[^.]*writes no audit", lowered), name


@pytest.mark.asyncio
async def test_relayed_mutation_without_audit_log_writes_no_record(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from tests import test_cross_tool_invariants as cti
    from tests import upstream_harness as uh

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("UNIFI_AUDIT_LOG", raising=False)
    assert build_audit_sink(Settings(api_key="k-audit")) is None
    up = uh.FakeUpstream()
    args = {
        "host": uh.HOST,
        "site": uh.SITE,
        "path": "network/api/s/{site}/rest/probe/1",
        "body": {"a": 1},
    }
    await cti._call(
        monkeypatch, "fabric_connector_put", up, args, env={"UNIFI_WRITE_POLICY": "dry-run"}
    )
    assert not [s for s in up.served if s.method == "PUT"], "a PUT was sent under dry-run"
    assert not client_audit_enabled(server)
    assert list(tmp_path.iterdir()) == [], (
        "a relayed mutation wrote a file with the audit log unset"
    )


def client_audit_enabled(srv: Any) -> bool:
    client = srv._client
    return bool(client is not None and client.audit_enabled)


def _warnings(monkeypatch: pytest.MonkeyPatch, transport: str, **env: str) -> list[str]:
    # Settings validate against an HTTP transport; the transport argument is what the
    # server passes to startup_warnings when it starts.
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return transport_security.startup_warnings(MCPTransportSettings(), transport, "127.0.0.1", 8000)


def test_bearer_warning_threshold_and_conditions(monkeypatch: pytest.MonkeyPatch) -> None:
    limit = transport_security.MIN_BEARER_TOKEN_LENGTH
    doc = (ROOT / "docs" / "AUTH-TLS.md").read_text(encoding="utf-8")
    assert f"shorter than {limit} characters" in doc
    short, exact = "a" * (limit - 1), "a" * limit
    bearer = {"MCP_AUTH_MODE": "bearer"}
    (line,) = _warnings(monkeypatch, "streamable-http", MCP_BEARER_TOKEN=short, **bearer)
    assert f"shorter than {limit} characters" in line and short not in line
    assert _warnings(monkeypatch, "streamable-http", MCP_BEARER_TOKEN=exact, **bearer) == []
    # HTTP-only: stdio prints no startup warning even for a short token.
    stdio = _warnings(monkeypatch, "stdio", MCP_BEARER_TOKEN=short, **bearer)
    assert stdio == []
    # Bearer-only: with auth mode none the short token is not checked.
    none = _warnings(monkeypatch, "streamable-http", MCP_BEARER_TOKEN=short, MCP_AUTH_MODE="none")
    assert not [w for w in none if "MCP_BEARER_TOKEN is shorter" in w]


def test_auth_mode_none_with_token_runs_without_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    token = "t" * 40
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("MCP_BEARER_TOKEN", token)
    derived = MCPTransportSettings()
    assert derived.auth_mode == "bearer"  # unset mode: derived from the token
    assert server.build_auth(derived) is not None
    monkeypatch.setenv("MCP_AUTH_MODE", "none")
    explicit = MCPTransportSettings()
    assert explicit.auth_mode == "none"  # an explicit mode wins over the token
    assert server.build_auth(explicit) is None


CHANGE_027 = [
    "get_host",
    "get_sdwan_config",
    "get_sdwan_config_status",
    "get_carrier_subscriber",
    "get_carrier_service_plan",
    "get_mobility_device",
    "get_innerspace_project",
]


def test_change_027_text_names_every_tool_and_both_innerspace_shapes() -> None:
    section = MIGRATING[MIGRATING.index("### change-027") : MIGRATING.index("### change-028")]
    for tool in CHANGE_027:
        assert f"`{tool}`" in section
    assert "`{data, httpStatusCode, traceId}`" in section
    assert "legacy route" in section and "no `data` wrapper" in section


@pytest.fixture(scope="module")
def demo_mock() -> Any:
    spec = importlib.util.spec_from_file_location(
        "u_b_demo_mock", ROOT / "tests/support/tool_usage_mock/mock_api.py"
    )
    assert spec and spec.loader
    mock = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mock)
    mock.Handler.state = mock.build(json.loads(mock.FIXTURES.read_text()))
    mock.Handler.snapshot = mock.snapshot_image()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), mock.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield mock, f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def _change_027_call(tool: str, mock: Any, host: dict[str, Any]) -> tuple[Any, str]:
    """The coroutine factory for one change-027 read and the resource id it must return."""
    calls: dict[str, tuple[Any, str]] = {
        "get_host": (lambda c, r: site_manager.get_host(c, r, host["id"]), host["id"]),
        "get_sdwan_config": (
            lambda c, r: site_manager.get_sdwan_config(c, mock.SDWAN_CONFIG_ID),
            mock.SDWAN_CONFIG_ID,
        ),
        "get_sdwan_config_status": (
            lambda c, r: site_manager.get_sdwan_config_status(c, mock.SDWAN_CONFIG_ID),
            mock.SDWAN_CONFIG_ID,
        ),
        "get_carrier_subscriber": (
            lambda c, r: carrier_fabric.get_carrier_subscriber(c, mock.CARRIER_SUBSCRIBER_ID),
            mock.CARRIER_SUBSCRIBER_ID,
        ),
        "get_carrier_service_plan": (
            lambda c, r: carrier_fabric.get_carrier_service_plan(c, mock.CARRIER_PLAN_ID),
            mock.CARRIER_PLAN_ID,
        ),
        "get_mobility_device": (
            lambda c, r: mobility.get_mobility_device(
                c, mock.MOBILITY_WORKSPACE_ID, mock.MOBILITY_DEVICE_ID
            ),
            mock.MOBILITY_DEVICE_ID,
        ),
        "get_innerspace_project": (
            lambda c, r: innerspace.get_innerspace_project(c, r, host["id"]),
            mock.innerspace_project()["id"],
        ),
    }
    assert set(calls) == set(CHANGE_027)
    return calls[tool]


def _run_against_mock(mock: Any, base_url: str, call: Any) -> Any:
    settings = Settings(
        api_keys=[APIKeyConfig(key=mock.API_KEY, label="demo", is_org_key=False)],
        api_base_url=base_url,
    )

    async def run() -> Any:
        client = UniFiClient(settings)
        registry = Registry(client, ttl_seconds=60)
        try:
            return await call(client, registry)
        finally:
            await client.close()

    return asyncio.run(run())


@pytest.mark.parametrize("tool", CHANGE_027)
def test_change_027_shapes_match_mock(tool: str, demo_mock: Any) -> None:
    # Each parameter calls its own tool: the claim covers all seven, not get_host alone.
    mock, base_url = demo_mock
    host = mock.Handler.state["hosts"][0]
    call, resource_id = _change_027_call(tool, mock, host)
    result = _run_against_mock(mock, base_url, call)
    assert set(result) == {"data", "httpStatusCode", "traceId"}, tool
    assert result["data"]["id"] == resource_id


def test_change_027_innerspace_legacy_route_is_the_bare_project(demo_mock: Any) -> None:
    mock, base_url = demo_mock
    host = mock.Handler.state["hosts"][0]
    result = _run_against_mock(
        mock,
        base_url,
        lambda c, r: innerspace.get_innerspace_project(c, r, host["id"], site_id="default"),
    )
    assert "data" not in result
    assert result["id"] == mock.innerspace_project()["id"]


def test_every_list_tool_drains_pages_as_documented() -> None:
    tools = asyncio.run(server.mcp.list_tools())
    lists = [t for t in tools if t.name.startswith("list_")]
    assert len(lists) > 100
    paging = re.compile(r"page|limit|offset|cursor", re.I)
    capped: list[str] = []
    for tool in lists:
        for arg, schema in tool.parameters.get("properties", {}).items():
            if paging.search(arg) and schema.get("default") is not None:
                capped.append(f"{tool.name}.{arg}={schema['default']!r}")
    assert not capped, f"list tools with a default page cap: {capped}"
    assert Settings(api_key="k").paginate_max_pages is None
    assert "every list tool that pages upstream drains every page by default" in TOOL_USAGE
    assert "`list_configured_api_keys`" in TOOL_USAGE


def test_instructions_and_descriptions_within_stated_limit() -> None:
    stated = re.search(r"within ([\d,]+) characters", TOOL_USAGE)
    assert stated, "docs/TOOL-USAGE.md no longer states a description limit"
    limit = int(stated.group(1).replace(",", ""))
    assert limit == 2048
    assert len(server.INSTRUCTIONS) <= limit
    over = {
        t.name: len(t.description or "")
        for t in asyncio.run(server.mcp.list_tools())
        if len(t.description or "") > limit
    }
    assert not over, over


def test_docker_md_states_stateless_except_audit_file() -> None:
    text = (ROOT / "docs" / "DOCKER.md").read_text(encoding="utf-8")
    assert "stateless except the opt-in audit file" in text
    assert "No data loss risk" not in text
