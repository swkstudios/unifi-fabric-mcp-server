"""Opt-in operational features: tool-family allowlist, plus dry-run
preview and optional audit log implemented at the shared write chokepoint
(``UniFiClient.request``) so EVERY write/action tool is covered uniformly.

Binding invariants proven here:
* UNSET defaults == current behavior: full catalog registered, request path byte-identical.
* Dry-run suppresses EVERY classified write (zero upstream) and returns a labeled preview;
  read-only query POSTs (/stat/*, isp-metrics /query) still execute.
* The audit log records every write attempt (no body, no credential) and nothing when off.
* A systematically-derived test iterates every write call site in the tool layer, so a new
  uncovered write tool fails the suite.
"""

from __future__ import annotations

import ast
import inspect
import json
import os

import httpx
import pytest
import respx

from tests._tool_classes import tool_module_paths
from unifi_fabric.audit import _AUDIT_START, AuditStream, build_audit_sink
from unifi_fabric.client import UniFiClient, is_write_request
from unifi_fabric.config import Settings
from unifi_fabric.families import (
    ALL_FAMILIES,
    apply_tool_family_filter,
    build_family_index,
    parse_families_env,
)
from unifi_fabric.secret_scrub import secret_scope

BASE = "https://api.ui.com"


@pytest.fixture(autouse=True)
def _write_policy_env_reset(monkeypatch):
    """Start every test without a write policy; ``_modes`` sets one for a client's modes."""
    # setenv first so the teardown removes a value a helper set directly in os.environ
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "allow")
    monkeypatch.delenv("UNIFI_WRITE_POLICY")


def _modes(settings: dict) -> dict:
    """Express the retired ``dry_run`` / ``read_only`` client modes as the write policy."""
    settings = dict(settings)
    dry = settings.pop("dry_run", False)
    deny = settings.pop("read_only", False)
    if deny:
        os.environ["UNIFI_WRITE_POLICY"] = "deny"
    elif dry:
        os.environ["UNIFI_WRITE_POLICY"] = "dry-run"
    return settings


def _client(**kw) -> UniFiClient:
    kw = _modes(kw)
    return UniFiClient(Settings(api_key="k", api_base_url=BASE, **kw))


async def _registered_names(mcp) -> set[str]:
    result = mcp.list_tools()
    if inspect.isawaitable(result):
        result = await result
    return {t.name for t in result}


# --------------------------------------------------------------------------- #
# Family allowlist
# --------------------------------------------------------------------------- #


def test_family_index_covers_every_registered_tool() -> None:
    import asyncio

    import unifi_fabric.server as server

    names = asyncio.run(_registered_names(server.mcp))
    index = build_family_index()
    assert names - set(index) == set(), "unclassified registered tools"
    assert set(index.values()) <= set(ALL_FAMILIES)


def test_every_tool_module_is_mapped_to_a_family() -> None:
    """Every module that defines a registered tool names its family (class: module missing).

    A tool whose module is absent from MODULE_FAMILY is unclassified, and the allowlist
    never removes an unclassified tool, so UNIFI_FAMILY_ALLOW=protect would still list
    it (and the area write opt-outs, keyed by family, would skip it).
    """
    import asyncio

    import unifi_fabric.server as server
    from unifi_fabric.families import FAMILY_OVERRIDES, MODULE_FAMILY, firewall_route_tools

    index = build_family_index()
    firewall = firewall_route_tools()
    tools = asyncio.run(server.mcp.list_tools())
    modules: dict[str, set[str]] = {}
    for tool in tools:
        module = tool.fn.__module__.rsplit(".", 1)[-1]
        modules.setdefault(module, set()).add(tool.name)
    for module, names in sorted(modules.items()):
        if module == "server":
            continue  # inline wrappers are classified by the module they delegate to
        assert module in MODULE_FAMILY, f"tools module {module} has no family"
        # Split CRUD families override the module/route default, as in the catalog.
        # Every remaining firewall-route tool belongs to the firewall family.
        assert all(
            index.get(n)
            == FAMILY_OVERRIDES.get(n, "firewall" if n in firewall else MODULE_FAMILY[module])
            for n in names
        ), module
    assert {t.name for t in tools} - set(index) == set()


def test_registering_tool_modules_are_all_scanned() -> None:
    """Every tools/ module with a register function is scanned for family tools."""
    from unifi_fabric.families import _REGISTER_MODULES, MODULE_FAMILY

    registering = {
        path.stem
        for path in tool_module_paths()
        if any(
            isinstance(node, ast.FunctionDef) and node.name == "register"
            for node in ast.parse(path.read_text()).body
        )
    }
    assert registering - set(_REGISTER_MODULES) == set()
    assert set(_REGISTER_MODULES) - set(MODULE_FAMILY) == set()


@pytest.mark.asyncio
async def test_single_family_selection_leaves_only_that_family() -> None:
    """Exercise the actual filter for every family on a synthetic catalog."""
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    index = build_family_index()
    for family in ALL_FAMILIES:
        tools = {name: SimpleNamespace(name=name) for name in index}
        mcp = SimpleNamespace(
            list_tools=AsyncMock(side_effect=lambda tools=tools, **_kw: list(tools.values())),
            local_provider=SimpleNamespace(remove_tool=tools.pop),
        )
        removed = await apply_tool_family_filter(mcp, family)
        assert set(tools) == {name for name, selected in index.items() if selected == family}
        assert set(removed) == set(index) - set(tools)


def test_default_family_select_registers_full_catalog() -> None:
    import asyncio

    import unifi_fabric.server as server

    names = asyncio.run(_registered_names(server.mcp))
    index = build_family_index()
    families_present = {index[n] for n in names if n in index}
    assert families_present == set(ALL_FAMILIES)
    assert len(names) >= 280


def test_parse_families_env() -> None:
    assert parse_families_env(None) == set()
    assert parse_families_env("") == set()
    assert parse_families_env("  ") == set()
    assert parse_families_env("Network, Protect ,network") == {"network", "protect"}


@pytest.mark.asyncio
async def test_family_allowlist_registers_only_named_families() -> None:
    from fastmcp import FastMCP

    index = build_family_index()
    by_family: dict[str, list[str]] = {}
    for name, fam in index.items():
        by_family.setdefault(fam, []).append(name)
    sample = by_family["network"][:2] + by_family["protect"][:2] + by_family["firewall"][:2]

    mcp = FastMCP("synthetic")
    for name in sample:

        async def _stub() -> str:  # noqa: ANN202
            return "ok"

        from fastmcp.tools import Tool

        mcp.add_tool(Tool.from_function(_stub, name=name))

    before = await _registered_names(mcp)
    assert set(sample) <= before

    removed = await apply_tool_family_filter(mcp, "network,protect")
    after = await _registered_names(mcp)
    families_after = {index[n] for n in after if n in index}
    assert families_after == {"network", "protect"}
    assert set(by_family["firewall"][:2]) <= set(removed)
    assert after < before


@pytest.mark.asyncio
async def test_family_allowlist_unset_is_noop() -> None:
    from fastmcp import FastMCP

    mcp = FastMCP("x")

    @mcp.tool()
    def foo() -> str:
        return "a"

    before = await _registered_names(mcp)
    removed = await apply_tool_family_filter(mcp, None)
    assert removed == []
    assert await _registered_names(mcp) == before


@pytest.mark.asyncio
async def test_family_allowlist_unknown_name_fails_loud() -> None:
    from fastmcp import FastMCP

    mcp = FastMCP("x")
    with pytest.raises(ValueError, match="unknown families"):
        await apply_tool_family_filter(mcp, "nope-not-a-family")


# --------------------------------------------------------------------------- #
# Write classification — explicit and tested
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("method", "path", "is_write"),
    [
        ("PUT", "/v1/x", True),
        ("PATCH", "/v1/x", True),
        ("DELETE", "/v1/x", True),
        ("POST", "/v1/x/networks", True),
        ("POST", "/v1/x/cmd/devmgr", True),
        # read-only query POSTs are NOT writes
        ("POST", "/v1/connector/consoles/A/proxy/network/api/s/def/stat/session", False),
        (
            "POST",
            "/v1/connector/consoles/A/proxy/network/api/s/def/stat/report/5minutes.site",
            False,
        ),
        ("POST", "/v1/isp-metrics/5m/query", False),
        ("GET", "/v1/x", False),
    ],
)
def test_is_write_request_classification(method: str, path: str, is_write: bool) -> None:
    assert is_write_request(method, path) is is_write


# --------------------------------------------------------------------------- #
# Dry-run at the chokepoint
# --------------------------------------------------------------------------- #


@respx.mock
@pytest.mark.asyncio
async def test_dry_run_suppresses_write_zero_upstream(tmp_path) -> None:
    route = respx.post(f"{BASE}/v1/x/networks").mock(
        return_value=httpx.Response(200, json={"ok": 1})
    )
    f = tmp_path / "audit.jsonl"
    client = _client(dry_run=True, audit_log=str(f), audit_log_format="json")
    resp = await client.request("POST", "/v1/x/networks", json={"name": "n"})
    body = resp.json()
    assert route.called is False  # zero upstream writes
    assert body["dryRun"] is True
    assert "DRY RUN" in body["message"]
    assert body["preview"] == {
        "method": "POST",
        "path": "/v1/x/networks",
        "params": None,
        "body": {"name": "n"},
        "keyLabel": "default",
    }
    rec = json.loads(f.read_text().strip())
    assert rec["method"] == "POST" and rec["outcome"] == "dry_run"


@respx.mock
@pytest.mark.asyncio
async def test_dry_run_leaves_reads_and_readonly_posts_executing(tmp_path) -> None:
    stat_path = "/v1/connector/consoles/h1/proxy/network/api/s/default/stat/session"
    stat = respx.post(f"{BASE}{stat_path}").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    ispm = respx.post(f"{BASE}/v1/isp-metrics/5m/query").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    f = tmp_path / "audit.log"
    client = _client(dry_run=True, audit_log=str(f))
    await client.request("POST", stat_path, json={"type": "all"})
    await client.request("POST", "/v1/isp-metrics/5m/query", json={"sites": []})
    assert stat.called is True  # read-only POSTs execute under dry-run
    assert ispm.called is True
    assert not f.exists()  # and are never audited as writes


@respx.mock
@pytest.mark.asyncio
async def test_default_write_path_byte_identical(tmp_path) -> None:
    """dry-run OFF + audit OFF: the upstream request is byte-identical to a plain client."""
    captured: list[httpx.Request] = []

    def _cap(request):
        captured.append(request)
        return httpx.Response(200, json={"ok": 1})

    respx.post(f"{BASE}/v1/x/networks").mock(side_effect=_cap)
    baseline = _client()
    await baseline.request("POST", "/v1/x/networks", json={"name": "n"})
    client = _client(dry_run=False)  # defaults
    await client.request("POST", "/v1/x/networks", json={"name": "n"})
    assert len(captured) == 2
    assert captured[0].method == captured[1].method
    assert captured[0].url == captured[1].url
    assert captured[0].content == captured[1].content


# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #


def test_audit_sink_off_by_default() -> None:
    assert build_audit_sink(Settings()) is None


def test_audit_sink_text_and_json(tmp_path) -> None:
    t = tmp_path / "a.log"
    sink = build_audit_sink(Settings(audit_log=str(t), audit_log_format="text"))
    assert isinstance(sink, AuditStream) and sink.fmt == "text"
    sink.record(method="POST", path="/x", outcome="success", status=200)
    assert "method=POST path=/x outcome=success status=200" in t.read_text()

    j = tmp_path / "a.jsonl"
    sink = build_audit_sink(Settings(audit_log=str(j), audit_log_format="json"))
    sink.record(method="DELETE", path="/y/1", outcome="success", status=200)
    rec = json.loads(j.read_text().strip())
    assert rec["method"] == "DELETE" and rec["path"] == "/y/1" and "timestamp_utc" in rec


def test_audit_json_record_stays_valid_when_a_numeric_secret_matches_a_number(
    tmp_path, monkeypatch
) -> None:
    # A numeric credential argument (a device password of 42) is a call-bound secret "42";
    # a duration_ms of 3.42 holds that token and must not be masked into invalid JSON.
    monkeypatch.setattr("unifi_fabric.audit.perf_counter", lambda: 3.42 / 1000)
    j = tmp_path / "a.jsonl"
    sink = build_audit_sink(Settings(audit_log=str(j), audit_log_format="json"))
    assert sink is not None
    token = _AUDIT_START.set(0.0)
    try:
        with secret_scope(("42",)):
            sink.record(method="PATCH", path="/x", outcome="refused", status=None, reason="pw 42")
    finally:
        _AUDIT_START.reset(token)
    rec = json.loads(j.read_text().strip())
    assert rec["duration_ms"] == 3.42
    assert "42" not in rec["reason"]


@respx.mock
@pytest.mark.asyncio
async def test_audit_off_writes_nothing(tmp_path) -> None:
    respx.post(f"{BASE}/v1/x/networks").mock(return_value=httpx.Response(200, json={"ok": 1}))
    client = _client()  # no audit_log
    assert client._audit_sink is None
    await client.request("POST", "/v1/x/networks", json={"name": "n"})
    assert list(tmp_path.iterdir()) == []


@respx.mock
@pytest.mark.asyncio
async def test_audit_records_real_write(tmp_path) -> None:
    respx.post(f"{BASE}/v1/x/networks").mock(return_value=httpx.Response(200, json={"ok": 1}))
    f = tmp_path / "audit.log"
    client = _client(audit_log=str(f), audit_log_format="text")
    await client.request("POST", "/v1/x/networks", json={"name": "n"})
    assert "method=POST" in f.read_text() and "outcome=success" in f.read_text()


@respx.mock
@pytest.mark.asyncio
async def test_audit_never_records_body(tmp_path) -> None:
    respx.put(f"{BASE}/wlan/1").mock(return_value=httpx.Response(200, json={"ok": 1}))
    f = tmp_path / "audit.log"
    client = _client(audit_log=str(f))
    await client.request("PUT", "/wlan/1", json={"x_passphrase": "s3cr3t-password"})
    assert "s3cr3t-password" not in f.read_text()


# --------------------------------------------------------------------------- #
# Systematic coverage: every write call site in the tool layer is covered
# --------------------------------------------------------------------------- #

_WRITE_CLIENT_METHODS = {
    "post": "POST",
    "post_multipart": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
}


def _module_string_consts(tree: ast.Module) -> dict[str, str]:
    consts: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        consts[tgt.id] = node.value.value
    return consts


_STAT = "/api/s/X/stat/"


def _render(node: ast.expr, consts: dict[str, str]) -> str:
    """Reconstruct a representative path from a path expression.

    Handles string literals, f-strings (interpolations -> ``X``), module string constants,
    and path-building helper calls. A helper or attribute whose name carries ``stat`` is
    rendered under a site stat namespace (``/api/s/X/stat/``) so the Network Classic
    read-only stat query POSTs reconstruct to a path the classifier recognises as read-only.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(_render(v, consts) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return "X"
    if isinstance(node, ast.Name):
        if node.id in consts:
            return consts[node.id]
        if "stat" in node.id.lower():
            return _STAT
        return ""
    if isinstance(node, ast.Attribute):
        return _STAT if "stat" in node.attr.lower() else ""
    if isinstance(node, ast.Call):
        hint = ""
        if isinstance(node.func, ast.Name) and "stat" in node.func.id.lower():
            hint = _STAT
        return hint + "".join(_render(a, consts) for a in node.args)
    return ""


def _sample_path(arg: ast.expr, consts: dict[str, str]) -> str:
    """Build a representative request path from the first positional arg of a client call."""
    sample = _render(arg, consts)
    if not sample:
        sample = "/unknown-write"
    if not sample.startswith("/"):
        sample = "/" + sample
    if sample.startswith("/api/s/"):
        # A path built by a helper (statistics._classic_stat) renders without its base: the
        # Network application's Classic base on the console, which the read-POST
        # classification is anchored to.
        sample = "/v1/connector/consoles/X/proxy/network" + sample
    return sample


def _enumerate_write_callsites() -> list[tuple[str, str, int, str]]:
    """Return (module, http_method, lineno, sample_path) for every tool-layer write call."""
    sites: list[tuple[str, str, int, str]] = []
    for pyfile in sorted(tool_module_paths()):
        tree = ast.parse(pyfile.read_text())
        consts = _module_string_consts(tree)
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "client"
            ):
                continue
            # (a) convenience write methods: client.post/put/patch/delete/post_multipart(path, ...)
            if node.func.attr in _WRITE_CLIENT_METHODS:
                method = _WRITE_CLIENT_METHODS[node.func.attr]
                path_arg = node.args[0] if node.args else None
                sample = _sample_path(path_arg, consts) if path_arg else "/unknown-write"
                sites.append((pyfile.stem, method, node.lineno, sample))
            # (b) raw client.request("<METHOD>", path, ...) with a literal write method
            elif node.func.attr == "request" and len(node.args) >= 2:
                meth_node = node.args[0]
                if isinstance(meth_node, ast.Constant) and isinstance(meth_node.value, str):
                    m = meth_node.value.upper()
                    if m in ("POST", "PUT", "PATCH", "DELETE"):
                        sample = _sample_path(node.args[1], consts)
                        sites.append((pyfile.stem, m, node.lineno, sample))
    return sites


def test_write_callsites_enumeration_is_substantial() -> None:
    sites = _enumerate_write_callsites()
    assert len(sites) >= 40, f"expected many write call sites, found {len(sites)}"
    modules = {m for m, *_ in sites}
    # writes exist across the major product modules
    for expected in ("network", "protect", "device_mgmt", "clients", "carrier_fabric", "mobility"):
        assert expected in modules, f"no write call site enumerated for {expected}"


def test_read_only_post_callsites_are_only_the_known_endpoints() -> None:
    """Every ``client.post`` call site is a write: read-POSTs go through
    ``read_post_routes.post_read`` (exact allowlisted routes only), so a write tool can
    never match a read pattern by accident."""
    sites = _enumerate_write_callsites()
    reads = [s for s in sites if not is_write_request(s[1], s[3])]
    assert reads == [], reads


@pytest.mark.asyncio
async def test_every_write_callsite_zero_upstream_and_audited(tmp_path, monkeypatch) -> None:
    """Iterate EVERY tool-layer WRITE call site under dry-run: each produces zero upstream
    traffic (``_get_client`` is never reached) and is audited exactly once. A new uncovered
    write tool appears as a new call site here and is proven covered automatically."""
    sites = _enumerate_write_callsites()
    writes = [s for s in sites if is_write_request(s[1], s[3])]
    assert len(writes) >= 40

    f = tmp_path / "audit.jsonl"
    client = _client(dry_run=True, audit_log=str(f), audit_log_format="json")

    async def _no_upstream(*_a, **_k):
        raise AssertionError("dry-run contacted upstream (_get_client called)")

    monkeypatch.setattr(client, "_get_client", _no_upstream)

    for _module, method, _lineno, sample in writes:
        resp = await client.request(method, sample, json={"probe": 1})
        assert resp.json()["dryRun"] is True  # zero upstream + labeled preview

    recorded = [ln for ln in f.read_text().splitlines() if ln.strip()]
    assert len(recorded) == len(writes)
    assert all(json.loads(ln)["outcome"] == "dry_run" for ln in recorded)


@pytest.mark.asyncio
async def test_disabled_families_are_applied_after_allowlist() -> None:
    from fastmcp import FastMCP
    from fastmcp.tools import Tool

    index = build_family_index()
    by_family: dict[str, list[str]] = {}
    for name, family in index.items():
        by_family.setdefault(family, []).append(name)
    sample = by_family["network"][:2] + by_family["protect"][:2] + by_family["firewall"][:2]

    async def stub() -> str:
        return "ok"

    async def populated() -> FastMCP:
        mcp = FastMCP("families")
        for name in sample:
            mcp.add_tool(Tool.from_function(stub, name=name))
        return mcp

    mcp = await populated()
    await apply_tool_family_filter(mcp, "network,protect", "protect")
    assert {index[name] for name in await _registered_names(mcp)} == {"network"}

    mcp = await populated()
    await apply_tool_family_filter(mcp, None, "protect")
    assert "protect" not in {index[name] for name in await _registered_names(mcp)}
    assert "network" in {index[name] for name in await _registered_names(mcp)}

    mcp = FastMCP("families")
    with pytest.raises(ValueError, match="family exclusion list names unknown"):
        await apply_tool_family_filter(mcp, None, "not-a-family")
