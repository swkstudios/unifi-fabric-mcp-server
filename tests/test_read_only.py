"""Tests for the global opt-in read-only switch (``UNIFI_WRITE_POLICY``).

Covers three properties:

1. **Default OFF is byte-identical.** With the switch unset (or falsey) the write
   dispatch path reaches the HTTP transport exactly as before — the guard is a
   no-op, so existing behaviour is unchanged.
2. **ON refuses every write, before any upstream write, with an actionable message.**
   The guard lives at the single client chokepoint, so POST/PUT/PATCH/DELETE are
   refused and nothing is sent; reads (GET and the read-POST ``/stat`` / ISP-metrics
   query endpoints) still work. The generic connector relay refuses up-front.
3. **Coverage is systematic, not hand-picked.** The write/action tool set is derived
   from source (:mod:`unifi_fabric._read_only_audit`); this suite asserts the central
   guard refuses every verb every derived write tool can issue. A new write tool that
   routed its mutation outside the guard would make the coverage assertion fail.
"""

from __future__ import annotations

import asyncio
import inspect
import linecache
from types import FunctionType, SimpleNamespace

import httpx
import pytest
import respx
from httpx import Response

from unifi_fabric import _read_only_audit as audit
from unifi_fabric import read_only, server
from unifi_fabric import read_post_routes as rp
from unifi_fabric.client import UniFiClient
from unifi_fabric.client import is_write_request as client_is_write_request
from unifi_fabric.config import Settings
from unifi_fabric.families.connector import connector
from unifi_fabric.read_only import AreaOptOutError, ReadOnlyModeError

BASE = "https://api.ui.com"


@pytest.fixture
def client() -> UniFiClient:
    return UniFiClient(Settings(api_key="sk-test"))


def _registered_tools() -> list:
    res = server.mcp.list_tools()
    if inspect.isawaitable(res):
        res = asyncio.run(res)
    return list(res)


# ---------------------------------------------------------------------------
# is_read_only() parsing — opt-in, default OFF
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, "allow", "dry-run"])
def test_default_off(monkeypatch, value):
    # Only ``deny`` is read-only: unset (the default ``allow``), ``allow`` and ``dry-run``
    # (a preview, not a refusal) are not.
    if value is None:
        monkeypatch.delenv(read_only.ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(read_only.ENV_VAR, value)
    assert read_only.is_read_only() is False


def test_deny_is_on(monkeypatch):
    monkeypatch.setenv(read_only.ENV_VAR, "deny")
    assert read_only.is_read_only() is True


def test_blank_value_fails_closed(monkeypatch):
    # Settings drops a blank environment value; the call-time reader does not: a blank
    # UNIFI_WRITE_POLICY is not a policy, so every write is denied.
    monkeypatch.setenv(read_only.ENV_VAR, "")
    assert read_only.is_read_only() is True


@pytest.mark.parametrize(
    "value", ["1", "true", "TRUE", "yes", "on", "f", "N", " n ", "0", "Deny", "enabled"]
)
def test_malformed_value_fails_closed_and_names_the_variable(monkeypatch, value, capsys):
    # The retired boolean spellings and any other malformed value are not a policy:
    # Settings refuses them at startup naming the variable, and the call-time reader fails
    # closed (every write denied) instead of guessing that the switch is off.
    monkeypatch.setenv(read_only.ENV_VAR, value)
    with pytest.raises(ValueError, match=read_only.ENV_VAR):
        Settings(api_key="sk-test")
    assert read_only.is_read_only() is True


@pytest.mark.parametrize(
    "method,path,is_write",
    [
        ("GET", "/v1/hosts", False),
        ("POST", "/v1/connector/consoles/h/proxy/network/integration/v1/sites/s/networks", True),
        ("PUT", "/anything", True),
        ("PATCH", "/anything", True),
        ("DELETE", "/anything", True),
        # read-POST families stay reads
        ("POST", "/v1/connector/consoles/h/proxy/network/api/s/default/stat/report/5m.site", False),
        ("POST", "/v1/isp-metrics/5m/query", False),
        ("POST", "/v1/connector/consoles/h/proxy/network/api/s/default/stat/session", False),
        # route-exact: a bare /stat, an unlisted stat route or a trailing slash is a write
        ("POST", "/v1/connector/consoles/h/proxy/network/api/s/default/stat", True),
        ("POST", "/v1/connector/consoles/h/proxy/network/api/s/default/stat/", True),
        ("POST", "/v1/connector/consoles/h/proxy/network/api/s/default/stat/sta", True),
        ("POST", "/v1/isp-metrics/1h/query/", True),
        ("POST", "/v1/isp-metrics/5m/query?x=1", False),
        # only the isp-metrics query is a read: any other /isp-metrics/ POST is a write
        ("POST", "/v1/isp-metrics/5m", True),
        ("POST", "/v1/isp-metrics/5m/query/extra", True),
        ("POST", "/v1/isp-metrics/export", True),
        # "/stat" must be a whole segment
        ("POST", "/v1/connector/consoles/h/proxy/network/api/s/default/status", True),
        # ... and the site's own stat namespace: the Classic command cmd/stat
        # ({"cmd": "reset-dpi"}) resets counters and is a write
        ("POST", "/v1/connector/consoles/h/proxy/network/api/s/default/cmd/stat", True),
        ("POST", "/v1/connector/consoles/h/proxy/network/api/s/default/cmd/stat/", True),
        ("POST", "/v1/connector/consoles/h/proxy/network/v2/api/site/default/stat", True),
        ("POST", "/v1/connector/consoles/h/proxy/network/api/s/default/rest/stat", True),
        ("PUT", "/v1/connector/consoles/h/proxy/network/api/s/default/stat", True),
    ],
)
def test_is_write_request(method, path, is_write):
    assert read_only.is_write_request(method, path) is is_write
    # one classifier: the client's dry-run/audit decision is the same function
    assert client_is_write_request(method, path) is is_write


def test_client_uses_the_read_only_classifier():
    assert client_is_write_request is read_only.is_write_request


@pytest.mark.parametrize(
    "path",
    [
        "/v1/connector/consoles/h/proxy/network/api/s/default/stat/session",
        "/v1/connector/consoles/h/proxy/network/api/s/default/stat/report/hourly.site",
        "/v1/isp-metrics/5m/query",
    ],
)
def test_guard_allows_read_posts_under_read_only(monkeypatch, path):
    monkeypatch.setenv(read_only.ENV_VAR, "deny")
    read_only.guard_request("POST", path)  # no raise


@pytest.mark.parametrize("path", ["/v1/isp-metrics/5m", "/v1/isp-metrics/export"])
def test_guard_refuses_non_query_isp_metrics_posts_under_read_only(monkeypatch, path):
    monkeypatch.setenv(read_only.ENV_VAR, "deny")
    with pytest.raises(read_only.ReadOnlyModeError):
        read_only.guard_request("POST", path)


# ---------------------------------------------------------------------------
# Default OFF: write dispatch byte-identical (transport is reached)
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_write_proceeds_when_off(client, monkeypatch):
    monkeypatch.delenv(read_only.ENV_VAR, raising=False)
    route = respx.post(f"{BASE}/v1/sites/s/networks").mock(
        return_value=Response(200, json={"ok": 1})
    )
    resp = await client.request("POST", "/v1/sites/s/networks", json={"name": "vlan"})
    assert route.called
    sent = route.calls[0].request
    # Byte-identical dispatch: method, url and body are untouched by the (off) guard.
    assert sent.method == "POST"
    assert str(sent.url) == f"{BASE}/v1/sites/s/networks"
    assert sent.content == httpx.Request("POST", "x", json={"name": "vlan"}).content
    assert resp.status_code == 200


@respx.mock
@pytest.mark.asyncio
async def test_read_proceeds_when_on(client, monkeypatch):
    monkeypatch.setenv(read_only.ENV_VAR, "deny")
    route = respx.get(f"{BASE}/v1/hosts").mock(return_value=Response(200, json={"data": []}))
    await client.request("GET", "/v1/hosts")
    assert route.called


@respx.mock
@pytest.mark.asyncio
async def test_read_post_proceeds_when_on(client, monkeypatch):
    monkeypatch.setenv(read_only.ENV_VAR, "deny")
    stat = respx.post(
        f"{BASE}/v1/connector/consoles/h/proxy/network/api/s/default/stat/report/5m.site"
    ).mock(return_value=Response(200, json={"data": []}))
    isp = respx.post(f"{BASE}/v1/isp-metrics/5m/query").mock(
        return_value=Response(200, json={"data": []})
    )
    await client.request(
        "POST",
        "/v1/connector/consoles/h/proxy/network/api/s/default/stat/report/5m.site",
        json={"attrs": []},
    )
    await client.request("POST", "/v1/isp-metrics/5m/query", json={})
    assert stat.called and isp.called


# ---------------------------------------------------------------------------
# ON: every write verb refused before any upstream call
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_write_verb_refused_when_on(client, monkeypatch, method):
    monkeypatch.setenv(read_only.ENV_VAR, "deny")
    route = respx.route(method=method).mock(return_value=Response(200, json={}))
    with pytest.raises(ReadOnlyModeError) as exc:
        await client.request(method, "/v1/sites/s/networks", json={"x": 1})
    msg = str(exc.value)
    assert read_only.ENV_VAR in msg
    assert "environment:" in msg  # names where the switch lives (compose)
    assert "unset" in msg  # how to disable
    assert not route.called  # zero upstream writes


@pytest.mark.asyncio
async def test_connector_relay_refuses_before_network(monkeypatch):
    """The generic write relay refuses up-front, before resolving or reading anything."""
    monkeypatch.setenv(read_only.ENV_VAR, "deny")

    class _BoomClient:
        async def request(self, *a, **k):  # pragma: no cover - must never run
            raise AssertionError("upstream call made under read-only")

    class _BoomRegistry:
        async def resolve_key_for_host(self, *a, **k):  # pragma: no cover
            raise AssertionError("registry resolution under read-only")

    with pytest.raises(ReadOnlyModeError) as exc:
        await connector.connector_write(
            _BoomClient(),
            _BoomRegistry(),
            "host",
            "POST",
            "network/integration/v1/sites/s/networks",
            body={"n": 1},
        )
    assert read_only.ENV_VAR in str(exc.value)


# ---------------------------------------------------------------------------
# Precedence: read-only WINS over dry-run (no upstream call either way)
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_read_only_precedence_over_dry_run(monkeypatch):
    """With a dry-run global policy AND a deny exception, deny wins: refuse, no preview, no call.

    The global ``UNIFI_WRITE_POLICY=dry-run`` and the ``family:network=deny`` exception of
    ``UNIFI_WRITE_EXCEPTIONS`` both intercept writes at the single ``UniFiClient.request``
    chokepoint. The strictest wins (allow < dry-run < deny): the guard runs first, so a write
    raises the actionable refusal rather than returning a dry-run preview, and no upstream
    request is made under either setting. This pins that precedence so a future reorder of
    the chokepoint cannot silently turn a refusal into a dry-run "success".
    """
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", "family:network=deny")
    dry_run_client = UniFiClient(Settings(api_key="sk-test"))
    assert dry_run_client.dry_run is True  # the dry-run policy is genuinely active
    path = "/v1/connector/consoles/h/proxy/network/integration/v1/sites/s/networks"
    route = respx.post(f"{BASE}{path}").mock(return_value=Response(200, json={}))
    with pytest.raises(AreaOptOutError) as exc:
        await dry_run_client.request("POST", path, json={"x": 1})
    # The refusal is the area's denial, not a preview.
    assert "family:network=deny" in exc.value.env
    assert not route.called  # zero upstream traffic from either setting


# ---------------------------------------------------------------------------
# Systematic enumeration: the guard covers the FULL derived write-tool set
# ---------------------------------------------------------------------------

# Floor: the 0.7.0 catalog derives well over 100 write/action tools. A regression
# that silently drops the whole set (e.g. classifier returns empty) fails here.
_WRITE_TOOL_FLOOR = 100

#: Read-named tools whose only upstream route is a POST that is not on the read-POST
#: allowlist, so they are writes by rule (the controller issues something on each call).
READ_NAMED_POST_WRITES = frozenset(
    {
        "get_remote_access_turn_credentials",
        # NET-B read-named query POSTs (not on the read-POST allowlist, so writes).
        "get_system_log",
        "list_network_events",
        "list_ips_events",
        "list_guests",
        # Classic query commands (cmd/lte check-subscription, cmd/mbb
        # read-inactive-slot-sim-card) and v2 query POSTs (sites/overview, the multicast
        # clients/history queries, the rolling-upgrade time estimate) not on the read-POST
        # allowlist; their descriptions say UNIFI_WRITE_POLICY refuses them.
        "get_lte_subscription_status",
        "get_inactive_sim_slot",
        "get_sites_overview",
        "get_multicast_insights",
        "get_rolling_upgrade_plan",
    }
)


def test_write_tool_set_is_nonempty_and_systematic():
    tools = _registered_tools()
    writes = audit.derive_write_tools(tools)
    assert len(writes) >= _WRITE_TOOL_FLOOR
    # Names do not override the route classifier: these query POSTs are unallowlisted.
    read_named = {
        w for w in writes if w.startswith(("list_", "get_", "search_", "collect_", "compare_"))
    }
    assert read_named - READ_NAMED_POST_WRITES == set()
    # The Classic read commands (read_post_routes.READ_COMMANDS) are reads, not writes.
    read_commands = {name for command in rp.READ_COMMANDS for name in command.tools}
    assert read_commands == {"list_backups", "list_device_firmware", "get_speedtest_status"}
    assert read_commands.isdisjoint(writes)


def test_source_analysis_reuses_syntax_across_fresh_registered_callables(monkeypatch):
    def register():
        async def write(client):
            return await client.post("/synthetic")

        return write

    first, second = register(), register()
    assert first is not second
    original = audit.ast.parse
    parses = 0

    def counted(source):
        nonlocal parses
        if "/synthetic" in source:
            parses += 1
        return original(source)

    monkeypatch.setattr(audit.ast, "parse", counted)
    for fn in (first, second):
        assert audit.derive_write_tools([SimpleNamespace(name="write", fn=fn)]) == {"write"}
    # A different callable/catalog recomputes classification, but reuses syntax.
    assert parses == 1


def test_source_cache_separates_equal_code_from_different_sources(monkeypatch):
    sources = {
        "first_synthetic.py": "def call(client):\n    return client.get()  # client.post()\n",
        "second_synthetic.py": "def call(client):\n    return client.get()  # client.read()\n",
    }
    functions = []
    for filename, source in sources.items():
        code = compile(source, filename, "exec").co_consts[0]
        functions.append(FunctionType(code, {}))
    assert functions[0].__code__ == functions[1].__code__
    original = inspect.getsource

    def getsource(source):
        return sources.get(getattr(source, "co_filename", None)) or original(source)

    monkeypatch.setattr(inspect, "getsource", getsource)
    assert audit.derive_write_tools([SimpleNamespace(name="call", fn=functions[0])]) == {"call"}
    assert audit.derive_write_tools([SimpleNamespace(name="call", fn=functions[1])]) == set()
    # Virtual sources can change without stat metadata or even a new code object.
    sources["first_synthetic.py"] = sources["second_synthetic.py"]
    fresh = FunctionType(functions[0].__code__, {})
    assert audit.derive_write_tools([SimpleNamespace(name="call", fn=fresh)]) == set()


def test_source_cache_recomputes_when_source_file_changes(tmp_path):
    path = tmp_path / "reloaded.py"

    def load(comment):
        source = f"def call(client):\n    return client.get()  # {comment}\n"
        path.write_text(source)
        # Equal-length rapid writes can keep the line cache's mtime/size key.
        # Ensure inspect supplies the changed text this regression intends to test.
        linecache.cache.pop(str(path), None)
        code = compile(source, str(path), "exec").co_consts[0]
        return FunctionType(code, {})

    first = load("client.post()")
    assert audit.derive_write_tools([SimpleNamespace(name="call", fn=first)]) == {"call"}
    second = load("client.read()")
    assert first.__code__ == second.__code__
    assert audit.derive_write_tools([SimpleNamespace(name="call", fn=second)]) == set()


def test_source_cache_resolves_current_helpers_and_function_markers(monkeypatch):
    async def read(client):
        return await client.get("/synthetic")

    async def write(client):
        return await client.post("/synthetic")

    read.__module__ = write.__module__ = "unifi_fabric.synthetic"

    def register():
        async def call(client):
            return await connector._source_cache_delegate(client)

        return call

    monkeypatch.setattr(connector, "_source_cache_delegate", read, raising=False)
    first = register()
    assert audit.derive_write_tools([SimpleNamespace(name="call", fn=first)]) == set()
    monkeypatch.setattr(connector, "_source_cache_delegate", write)
    second = register()
    assert first.__code__ == second.__code__
    assert audit.derive_write_tools([SimpleNamespace(name="call", fn=second)]) == {"call"}

    assert audit.write_verbs_for(read) == set()
    audit.state_changing_get(read)
    assert audit.write_verbs_for(read) == {"POST"}
    assert audit.write_verbs_for(write) == {"POST"}
    write.__unifi_read_post__ = True
    assert audit.write_verbs_for(write) == set()


def test_source_cache_preserves_unavailable_source_fallback(monkeypatch):
    async def write(client):
        return await client.post("/synthetic")

    write.__name__ = "connector_write"
    original = inspect.getsource

    def unavailable(source):
        if source == write.__code__:
            raise OSError("source temporarily unavailable")
        return original(source)

    monkeypatch.setattr(inspect, "getsource", unavailable)
    assert audit.write_verbs_for(write) == set()
    audit.state_changing_get(write)
    assert audit.write_verbs_for(write) == {"POST"}
    monkeypatch.setattr(inspect, "getsource", original)
    # Failed source lookups are not cached; the existing relay rule now applies.
    assert audit.write_verbs_for(write) == {"POST", "PUT", "PATCH", "DELETE"}


def test_derived_write_cache_reuses_catalog_without_sharing_mutable_results(monkeypatch):
    def read(client):
        return client.get("/read")

    def write(client):
        return client.post("/write")

    tools = [SimpleNamespace(name="read", fn=read), SimpleNamespace(name="write", fn=write)]
    expected = {name for name, verbs in audit.classify_tool_verbs(tools).items() if verbs}
    calls = []
    original = audit.write_verbs_for

    def counted(fn):
        calls.append(fn)
        return original(fn)

    monkeypatch.setattr(audit, "write_verbs_for", counted)
    assert audit.derive_write_tools(tools) == expected == {"write"}
    assert len(calls) == 2
    # Reordered/copied tool containers are the same catalog. Callers cannot poison it.
    result = audit.derive_write_tools(list(reversed(tools)))
    assert result == expected
    result.clear()
    assert audit.derive_write_tools(tools) == expected
    assert len(calls) == 2
    assert audit.derive_write_tools([tools[0]]) == set()
    assert len(calls) == 3
    assert audit.derive_write_tools(tools) == expected
    assert len(calls) == 3


def test_derived_write_cache_recomputes_changed_catalog(monkeypatch):
    def read(client):
        return client.get("/read")

    def write(client):
        return client.post("/write")

    calls = []
    original = audit.write_verbs_for

    def counted(fn):
        calls.append(fn)
        return original(fn)

    monkeypatch.setattr(audit, "write_verbs_for", counted)
    tool = SimpleNamespace(name="same_name", fn=read)
    assert audit.derive_write_tools([tool]) == set()
    assert len(calls) == 1
    tool.fn = write
    assert audit.derive_write_tools([tool]) == {"same_name"}
    assert len(calls) == 2
    tool.name = "renamed"
    assert audit.derive_write_tools([tool]) == {"renamed"}
    assert len(calls) == 3
    assert audit.derive_write_tools([]) == set()
    assert audit.derive_write_tools([SimpleNamespace(name="same_name", fn=read)]) == set()
    assert len(calls) == 3


def test_every_derived_write_verb_classified_on_representative_path():
    """Every derived write verb is classified as a write on a representative path."""
    tools = _registered_tools()
    verbmap = audit.classify_tool_verbs(tools)
    writes = {n for n, v in verbmap.items() if v}
    non_read_path = "/v1/sites/s/networks"
    covered = {
        name
        for name, verbs in verbmap.items()
        if verbs and all(read_only.is_write_request(v, non_read_path) for v in verbs)
    }
    assert covered == writes
    assert len(covered) == len(writes)


def test_no_tool_issues_outbound_http_outside_client():
    """Anti-bypass: a new write must route through UniFiClient (where the guard lives).

    Any direct ``httpx`` egress in a tool module would sidestep the chokepoint, so a
    write added that way would escape read-only coverage. Forbid it.
    """
    import pathlib
    import re

    # Outbound egress = constructing an httpx client or calling an httpx verb.
    # References to httpx *exception types* (httpx.HTTPError) are fine.
    egress = re.compile(r"httpx\.(AsyncClient|Client|stream|request|get|post|put|patch|delete)\b")
    tools_dir = pathlib.Path(connector.__file__).parent
    offenders = [py.name for py in tools_dir.glob("*.py") if egress.search(py.read_text())]
    assert offenders == [], f"tool modules must not make outbound httpx calls directly: {offenders}"
