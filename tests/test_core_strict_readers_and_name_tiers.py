"""Strict readers, request-path guards, name tiers and settings validation.

The scrubber classes (escape-aware boundaries, secrets of any length, secrets not
encodable as UTF-8) are proven in ``test_secret_leak_invariant`` -- every upstream error
body there echoes each secret after and before every escape form, across every tool.
This file holds the other core invariants and the specific behaviours:

* a fetched registry list keeps its incomplete state through every narrowing
  (``filter_records``; a lint refuses a plain comprehension over one), and the four tools
  that map a Site Manager site to its console site refuse a LABEL match on a capped
  console site list;
* the request chokepoint refuses absolute / scheme-relative URLs and
  percent-encoded traversal, and classifies read vs write on the decoded path;
* one strict total reader; non-finite upstream numbers are shape errors;
* an unknown key_label fails listing the valid labels on every tool, any key count;
* a page_token-only call sends no pageSize;
* name tiers (exact, NFC + casefold, stripped) and case-insensitive hex ids
  everywhere ids and upstream names are matched locally;
* every UNIFI_* / MCP_* setting is validated at load, naming its variable;
* different consoles' site lists on one key fetch concurrently, each once.
"""

from __future__ import annotations

import ast
import asyncio
import functools
import math
import pathlib
import re
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError
from pydantic import ValidationError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from tests._tool_classes import tool_batches
from unifi_fabric import registry as registry_module
from unifi_fabric import server
from unifi_fabric.client import PaginationAbortedError, ResponseShapeError, UniFiClient
from unifi_fabric.config import APIKeyConfig, MCPTransportSettings, Settings
from unifi_fabric.families.innerspace import placement_snapshot
from unifi_fabric.families.site_manager import site_manager
from unifi_fabric.matching import name_keys, same_id, tiered_name_matches
from unifi_fabric.read_only import is_write_request
from unifi_fabric.read_post_routes import is_read_post
from unifi_fabric.registry import FetchedRecords, Registry, filter_records, incomplete_reason
from unifi_fabric.shared_shapes._classic_objects import select_classic_record
from unifi_fabric.shared_shapes._pagination import verbatim_list_result

SRC = pathlib.Path(registry_module.__file__).parent
TOOLS = cti.TOOLS

# ============================================================== FetchedRecords


def test_filter_records_keeps_the_incomplete_reason():
    capped = FetchedRecords([{"id": 1}, {"id": 2}, "x"], "page cap 1")
    narrowed = filter_records(capped, lambda r: isinstance(r, dict))
    assert isinstance(narrowed, FetchedRecords)
    assert list(narrowed) == [{"id": 1}, {"id": 2}]
    assert incomplete_reason(narrowed) == "page cap 1"
    assert incomplete_reason(filter_records([{"id": 1}], bool)) is None


#: Registry accessors whose result is a FetchedRecords.
_REGISTRY_LISTS = {"get_hosts", "get_sites", "get_ea_sites"}


def _registry_list_names(func: ast.AST) -> set[str]:
    """Names bound in ``func`` to ``await <x>.get_hosts/get_sites/get_ea_sites(...)``."""
    names: set[str] = set()
    for node in ast.walk(func):
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign | ast.NamedExpr):
            targets, value = [node.target], node.value
        if value is not None and _is_registry_list_call(value):
            names |= {t.id for t in targets if isinstance(t, ast.Name)}
    return names


def _is_registry_list_call(node: ast.AST) -> bool:
    if isinstance(node, ast.Await):
        node = node.value
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _REGISTRY_LISTS
    )


def _list_building_offenders(tree: ast.AST, where: str) -> list[str]:
    """A list comprehension / ``list()`` / ``sorted()`` / ``filter()`` whose iterable is
    a registry list (a call or a name bound to one): it would drop the incomplete state."""
    out: list[str] = []
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        bound = _registry_list_names(func)

        def is_fetched(expr: ast.expr, bound: set[str] = bound) -> bool:
            return _is_registry_list_call(expr) or (isinstance(expr, ast.Name) and expr.id in bound)

        for node in ast.walk(func):
            if (
                isinstance(node, ast.ListComp)
                and isinstance(node.elt, ast.Name)  # the records themselves, narrowed
                and any(
                    is_fetched(g.iter)
                    and isinstance(g.target, ast.Name)
                    and g.target.id == node.elt.id
                    for g in node.generators
                )
            ):
                out.append(f"{where}:{node.lineno} list comprehension over a registry list")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"list", "sorted", "filter"}
                and any(is_fetched(arg) for arg in node.args)
            ):
                out.append(f"{where}:{node.lineno} {node.func.id}() over a registry list")
    return out


def test_no_registry_list_is_narrowed_into_a_plain_list():
    """Lint: a registry list is narrowed only through ``filter_records`` (which keeps
    the incomplete state), never a comprehension or ``list(...)`` over it."""
    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        offenders += _list_building_offenders(ast.parse(path.read_text()), path.name)
    assert offenders == []


def test_the_lint_catches_a_plain_comprehension():
    code = (
        "async def f(registry):\n"
        "    sites = await registry.get_sites('h')\n"
        "    a = [s for s in sites if s]\n"
        "    b = [s for s in await registry.get_hosts() if s]\n"
        "    return list(sites), a, b\n"
    )
    assert len(_list_building_offenders(ast.parse(code), "probe")) == 3


_UUID_A = "11111111-1111-4111-8111-111111111111"
_EA_SITE = {"siteId": "650000000000000000000001", "hostId": "AA:1", "meta": {"name": "branch"}}


class _M1Client:
    """One key; the Site Manager site list is complete, the console's site list is capped
    and holds a site whose LABEL matches the Site Manager site (its internalReference
    does not): a second site with that label may lie past the cap."""

    paginate_max_pages = 1

    def __init__(self, internal_reference: str = "other") -> None:
        self.internal_reference = internal_reference
        self.gets: list[str] = []

    def list_key_labels(self) -> list[str]:
        return ["default"]

    def get_key_by_label(self, label: str) -> APIKeyConfig:
        return APIKeyConfig(key="k-test", label=label)

    async def paginate(self, path: str, **_: Any) -> list[dict[str, Any]]:
        assert path == "/v1/sites", path
        return [dict(_EA_SITE, meta={"name": "branch", "desc": "Main Office"})]

    async def paginate_offset(self, path: str, **_: Any) -> list[dict[str, Any]]:
        site = {"id": _UUID_A, "description": "Main Office", "name": "x"}
        site["internalReference"] = self.internal_reference
        raise PaginationAbortedError(path, 1, "page cap 1", items=[site])

    async def get(self, path: str, **_: Any) -> Any:
        self.gets.append(path)
        return {"meta": {"rc": "ok"}, "data": []}

    async def gather(self, coros: Any) -> list[Any]:
        return list(await asyncio.gather(*coros))


@pytest.mark.parametrize(
    "tool", ["get_site_health_summary", "get_site_inventory", "compare_site_performance"]
)
async def test_label_match_on_a_capped_console_site_list_is_refused(tool):
    """The console list's incomplete state survives the mapping; a label-only match
    on it is refused (naming the cap) and no data request is sent."""
    client = _M1Client()
    reg = Registry(client, ttl_seconds=0)  # type: ignore[arg-type]
    func = getattr(site_manager, tool)
    site_arg: Any = ["branch"] if tool == "compare_site_performance" else "branch"
    with pytest.raises((ValueError, RuntimeError)) as exc:
        await func(client, reg, site_arg)
    assert "label only" in str(exc.value) and "page cap 1" in str(exc.value), exc.value
    assert client.gets == []


async def test_search_across_sites_skips_a_label_match_on_a_capped_list():
    client = _M1Client()
    reg = Registry(client, ttl_seconds=0)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError) as exc:
        await site_manager.search_across_sites(client, reg, "probe")  # type: ignore[arg-type]
    assert "label only" in str(exc.value) and "page cap 1" in str(exc.value)
    assert client.gets == []


async def test_internal_reference_maps_on_a_capped_list():
    """An exact internal reference resolves completely even on a capped list."""
    client = _M1Client(internal_reference="branch")
    reg = Registry(client, ttl_seconds=0)  # type: ignore[arg-type]
    result = await site_manager.get_site_health_summary(client, reg, "branch")  # type: ignore[arg-type]
    assert result == {
        "meta": {"rc": "ok"},
        "data": [],
    }
    assert client.gets and client.gets[0].endswith("/api/s/branch/stat/health")


# ============================================================== request path guard


def _guard_client(monkeypatch) -> tuple[UniFiClient, list[httpx.Request]]:
    sent: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        sent.append(req)
        return httpx.Response(200, json={"data": []})

    client = UniFiClient(Settings(api_key="k-test"))

    async def _get_client(self, key_config):
        return httpx.AsyncClient(
            base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(UniFiClient, "_get_client", _get_client)
    return client, sent


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.example/v1/hosts",
        "http:/v1/hosts",
        "javascript:alert(1)",
        "//evil.example/v1/hosts",
        "/%2Fevil.example/x",
        "v1/hosts",
        "/v1/hosts/%2e%2e/sites",
        "/v1/hosts/%2E%2E%2Fsites",
        "/v1/hosts/%252e%252e/sites",
        "/v1/hosts/.%2e/sites",
        "/v1/hosts/%2e/sites",
        "/v1/hosts/%0a",
        "/v1/hosts/%00",
        "/v1/hosts/%250d",
        "/v1/x?next=/../y",
    ],
)
async def test_unsafe_request_paths_are_refused_before_sending(monkeypatch, path):
    client, sent = _guard_client(monkeypatch)
    with pytest.raises(ValueError, match="Unsafe API path"):
        await client.request("GET", path)
    assert sent == []


@pytest.mark.parametrize(
    "path",
    [
        "/v1/hosts/AA:1",
        "/v1/protect/cameras/a%2E%2Eb",  # path_segment encodes an id holding ".."
        "/v1/x/%20name",
        "/v1/x?q=a:b",
    ],
)
async def test_safe_request_paths_still_pass(monkeypatch, path):
    client, sent = _guard_client(monkeypatch)
    await client.request("GET", path)
    assert len(sent) == 1


@pytest.mark.parametrize(
    ("path", "write"),
    [
        ("/v1/connector/consoles/H/proxy/network/api/s/default/stat/session", False),
        # only the raw, exact route is a read: a percent-encoded literal is a write
        ("/v1/connector/consoles/H/proxy/network/api/s/default/st%61t/session", True),
        ("/v1/connector/consoles/H/proxy/network/api/s/default/%73tat/session", True),
        ("/v1/connector/consoles/H/proxy/network/api/s/default/stat/report/hourly%2Esite", True),
        # route-exact allowlist: an unlisted stat route or a bare stat is a write
        ("/v1/connector/consoles/H/proxy/network/api/s/default/stat/health", True),
        ("/v1/connector/consoles/H/proxy/network/api/s/default/%73tat", True),
        ("/v1/isp-metrics/5m/qu%65ry", True),
        ("/v1/isp-metrics/5m/query", False),
        # an encoded ? is never split off: the path is not the route
        ("/v1/isp-metrics/5m/query%3F", True),
        ("/v1/isp-metrics/5m/query%253Fx", True),
        ("/v1/connector/consoles/H/proxy/network/api/s/default/cmd/stat", True),
        ("/v1/connector/consoles/H/proxy/network/api/s/default/cmd%2Fstat", True),
        # an encoded separator is part of one segment: never the stat route of site "x"
        ("/v1/connector/consoles/H/proxy/network/api/s/x%2Fstat", True),
        ("/v1/connector/consoles/H/proxy/network/api/s/x%252Fstat", True),
        ("/v1/connector/consoles/H/proxy/network/api/s/x%5Cstat", True),
    ],
)
def test_write_classification_judges_the_raw_path(path, write):
    assert is_write_request("POST", path) is write
    # post_read judges the same raw path the same way
    assert is_read_post("POST", path) is (not write)


# ================================================================== strict readers


@pytest.mark.parametrize("total", ["5", True, -1, 2.5])
def test_single_get_list_total_is_read_strictly(total):
    with pytest.raises(ResponseShapeError, match="GET /v1/probe"):
        verbatim_list_result({"data": [], "total": total}, [], "/v1/probe")


def test_single_get_list_total_still_flags_a_partial_page():
    result = verbatim_list_result({"data": [1], "totalCount": 3}, [1], "/v1/probe")
    assert result["incomplete"] is True


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_placement_numbers_reject_non_finite_values_naming_the_field(bad):
    with pytest.raises(ResponseShapeError, match="ordering"):
        placement_snapshot._floor({"id": "p1", "name": "Floor", "ordering": bad})
    with pytest.raises(ResponseShapeError, match=r"position\.x"):
        placement_snapshot._position({"x": bad, "y": 1})


def test_placement_numbers_keep_finite_values_and_skip_non_numbers():
    assert placement_snapshot._number(3, "f") == 3
    assert placement_snapshot._number("3", "f") is None
    assert placement_snapshot._number(True, "f") is None


def test_innerspace_scale_skips_non_finite_candidates():
    from unifi_fabric.families.innerspace import innerspace

    plan = {"id": "p", "scale": math.nan, "planScale": {"scale": 2.5}}
    assert innerspace._plan_scale(plan) == 2.5
    shapes = [{"type": "scale", "planId": "p", "scale": math.inf, "computedScale": 4}]
    assert innerspace._scale_by_plan(shapes)["p"]["scale"] == 4


# ============================================================== key_label everywhere
@functools.cache
def _lz__KEY_LABEL_TOOLS():
    return sorted(
        n for n, t in TOOLS.items() if "key_label" in ((t.parameters or {}).get("properties") or {})
    )


@lazy_parametrize("name", lambda: _lz__KEY_LABEL_TOOLS())
async def test_unknown_key_label_fails_on_a_single_key_server(monkeypatch, name):
    """With ONE configured key (host given where the tool takes one), an unknown
    key_label fails listing the valid labels, before any request."""
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(TOOLS[name]), "key_label": "nope"}
    with pytest.raises(ToolError) as exc:
        await cti._call(monkeypatch, name, up, args)
    assert "No API key with label 'nope'; valid labels: default" in str(exc.value)
    assert up.served == []


async def test_list_devices_with_host_validates_key_label_directly(monkeypatch):
    up = uh.FakeUpstream(replay_recordings=False)
    client = uh.install(monkeypatch, up)
    with pytest.raises(ValueError, match="valid labels: default"):
        await site_manager.list_devices(client, server._registry, host=uh.HOST, key_label="x")
    await site_manager.list_devices(client, server._registry, host=uh.HOST, key_label="default")


# ============================================================== exact paging args


@pytest.mark.parametrize("tool", ["list_hosts", "list_sites", "list_devices"])
async def test_page_token_only_sends_no_page_size(monkeypatch, tool):
    up = uh.FakeUpstream(replay_recordings=False)
    await cti._call(monkeypatch, tool, up, {"page_token": "tok-1"})
    paged = [s for s in up.served if s.path in ("/v1/hosts", "/v1/sites", "/v1/devices")]
    assert paged, up.served
    for served in paged:
        assert "nextToken=tok-1" in served.query and "pageSize" not in served.query, served.query


async def test_page_size_only_still_sends_page_size(monkeypatch):
    up = uh.FakeUpstream(replay_recordings=False)
    await cti._call(monkeypatch, "list_hosts", up, {"page_size": 7})
    served = [s for s in up.served if s.path == "/v1/hosts"]
    assert served and "pageSize=7" in served[0].query


# ================================================================== names and ids


def test_name_tiers_select_padded_and_unnormalized_upstream_names():
    items = ["Lab  ", "Fiber - ", "Café"]
    assert tiered_name_matches(items, "Lab", lambda s: [[s]])[1] == ["Lab  "]
    assert tiered_name_matches(items, "Fiber -", lambda s: [[s]])[1] == ["Fiber - "]
    assert tiered_name_matches(items, "CAFÉ", lambda s: [[s]])[1] == ["Café"]
    # an exact match beats a looser one
    assert tiered_name_matches(["Lab", "lab"], "lab", lambda s: [[s]])[1] == ["lab"]
    assert name_keys(" A ") == (" A ", " a ", "A", "a")


def test_hex_ids_match_case_insensitively_and_others_exactly():
    assert same_id(_UUID_A.upper(), _UUID_A)
    assert same_id("650000000000000000000001".upper(), "650000000000000000000001")
    assert same_id("70a7:123", "70A7:123")
    assert not same_id("Garage", "garage")
    assert not same_id("", "")


async def test_console_with_padded_name_is_selectable_and_ids_any_case():
    hosts = [
        {"id": "70A741000000000000000000ABCDEF:1", "reportedState": {"hostname": "Lab  "}},
        {"id": "BB:2", "reportedState": {"hostname": "gw"}},
    ]

    class _Hosts:
        paginate_max_pages = None

        def list_key_labels(self) -> list[str]:
            return ["default"]

        async def paginate(self, path: str, **_: Any) -> list[dict[str, Any]]:
            return hosts

    reg = Registry(_Hosts(), ttl_seconds=0)  # type: ignore[arg-type]
    assert await reg.resolve_host_id("Lab") == hosts[0]["id"]
    assert await reg.resolve_host_id(hosts[0]["id"].lower()) == hosts[0]["id"]
    with pytest.raises(ValueError, match="surrounding whitespace"):
        await reg.resolve_host_id("Lab ")  # the caller's own padding is still refused


async def test_console_site_with_padded_name_and_uppercase_uuid_resolve():
    sites = [{"id": _UUID_A, "description": "Fiber - ", "internalReference": "fiber"}]

    class _Sites:
        paginate_max_pages = None

        def list_key_labels(self) -> list[str]:
            return ["default"]

        async def paginate_offset(self, path: str, **_: Any) -> list[dict[str, Any]]:
            return sites

    reg = Registry(_Sites(), ttl_seconds=0)  # type: ignore[arg-type]
    assert await reg.resolve_site_id("Fiber -", "AA:1") == _UUID_A
    assert await reg.resolve_site_id(_UUID_A.upper(), "AA:1") == _UUID_A
    assert await reg.resolve_site_slug("fiber -", "AA:1") == "fiber"


def test_classic_record_selection_ignores_hex_id_case():
    records = [{"_id": "650000000000000000000001", "external_id": _UUID_A, "name": "n"}]
    assert select_classic_record(records, _UUID_A.upper(), "x", "list_x") is records[0]
    assert select_classic_record(records, records[0]["_id"].upper(), "x", "list_x") is records[0]


_LOWER_HEX_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24}"
)


def _uppercased(value: Any) -> Any:
    if isinstance(value, str) and _LOWER_HEX_ID.fullmatch(value):
        return value.upper()
    if isinstance(value, list):
        return [_uppercased(v) for v in value]
    return value


@functools.cache
def _lz__ID_ARG_TOOLS():
    return sorted(
        name
        for name, tool in TOOLS.items()
        if any(_uppercased(v) != v for v in tool_args.generated_args(tool).values())
    )


async def _eligible_every_tool_accepts_an_uppercase_form_of_a_uuid_it_accepts(name):
    """Invariant: a tool that succeeds with a lower-case UUID / ObjectId argument
    succeeds with the same id in upper case (ids are matched case-insensitively wherever
    they are compared locally; the upstream's spelling is what is sent)."""
    if name in cti.NO_UPSTREAM:
        return False
    return True


@tool_batches(
    "name",
    lambda: _lz__ID_ARG_TOOLS(),
    eligible=_eligible_every_tool_accepts_an_uppercase_form_of_a_uuid_it_accepts,
)
async def test_every_tool_accepts_an_uppercase_form_of_a_uuid_it_accepts(monkeypatch, name):
    """Invariant: a tool that succeeds with a lower-case UUID / ObjectId argument
    succeeds with the same id in upper case (ids are matched case-insensitively wherever
    they are compared locally; the upstream's spelling is what is sent)."""
    if name in cti.NO_UPSTREAM:
        raise AssertionError("inapplicable case was not filtered before batching")
    up = uh.FakeUpstream(replay_recordings=False)
    uh.install(monkeypatch, up)
    args = cti.sc.conformance_args(name)
    try:
        await cti._call(monkeypatch, name, up, args)
    except ToolError:
        raise AssertionError("unexpected baseline call error") from None
    upper = {k: _uppercased(v) for k, v in args.items()}
    try:
        await cti._call(monkeypatch, name, uh.FakeUpstream(replay_recordings=False), upper)
    except ToolError as exc:
        pytest.fail(f"{name}: an upper-case id was refused: {exc}")


# ============================================================== every setting validated
#: One malformed value per setting, keyed by the model field; the error must name the
#: environment variable. The keys must be every field of both settings models.
_BAD_SETTINGS: dict[str, tuple[str, str]] = {
    # Settings (UNIFI_*)
    "api_base_url": ("UNIFI_API_BASE_URL", "ftp://x"),
    "api_keys": ("UNIFI_API_KEYS", "not json"),
    "api_key": ("UNIFI_API_KEY", "a b"),
    "api_key_file": ("UNIFI_API_KEY_FILE", "relative/key.txt"),
    "api_key_command": ("UNIFI_API_KEY_COMMAND", "relative/helper"),
    "api_keys_file": ("UNIFI_API_KEYS_FILE", "relative/keys.json"),
    "api_keys_command": ("UNIFI_API_KEYS_COMMAND", "relative/helper"),
    "cache_ttl_seconds": ("UNIFI_CACHE_TTL_SECONDS", "-1"),
    "cache_max_hosts": ("UNIFI_CACHE_MAX_HOSTS", "0"),
    "cache_max_sites": ("UNIFI_CACHE_MAX_SITES", "x"),
    "max_concurrency": ("UNIFI_MAX_CONCURRENCY", "0"),
    "request_timeout_seconds": ("UNIFI_REQUEST_TIMEOUT_SECONDS", "30"),
    "paginate_max_pages": ("UNIFI_PAGINATE_MAX_PAGES", "0"),
    "log_level": ("UNIFI_LOG_LEVEL", "LOUD"),
    "redact_secrets": ("UNIFI_REDACT_SECRETS", "maybe"),
    "audit_log": ("UNIFI_AUDIT_LOG", "audit.log\n"),
    "audit_log_format": ("UNIFI_AUDIT_LOG_FORMAT", "xml"),
    "audit_sink": ("UNIFI_AUDIT_SINK", "syslog"),
    "audit_remote_url": ("UNIFI_AUDIT_REMOTE_URL", "https://collector.example/a\n"),
    "audit_remote_plaintext": ("UNIFI_AUDIT_REMOTE_PLAINTEXT", "maybe"),
    "audit_remote_ca_file": ("UNIFI_AUDIT_REMOTE_CA_FILE", "/ca\x7f.pem"),
    "audit_remote_cert_file": ("UNIFI_AUDIT_REMOTE_CERT_FILE", " /c.pem"),
    "audit_remote_key_file": ("UNIFI_AUDIT_REMOTE_KEY_FILE", "/k.pem\t"),
    "audit_remote_max_attempts": ("UNIFI_AUDIT_REMOTE_MAX_ATTEMPTS", "0"),
    "audit_remote_retry_backoff_seconds": ("UNIFI_AUDIT_REMOTE_RETRY_BACKOFF_SECONDS", "0"),
    "audit_remote_batch_max_records": ("UNIFI_AUDIT_REMOTE_BATCH_MAX_RECORDS", "x"),
    "audit_remote_batch_max_bytes": ("UNIFI_AUDIT_REMOTE_BATCH_MAX_BYTES", "-1"),
    "audit_remote_flush_interval_seconds": ("UNIFI_AUDIT_REMOTE_FLUSH_INTERVAL_SECONDS", "nan"),
    "audit_remote_buffer_max_records": ("UNIFI_AUDIT_REMOTE_BUFFER_MAX_RECORDS", "0"),
    "audit_remote_buffer_max_bytes": ("UNIFI_AUDIT_REMOTE_BUFFER_MAX_BYTES", "1.5"),
    "audit_hmac_identifiers": ("UNIFI_AUDIT_HMAC_IDENTIFIERS", "maybe"),
    "audit_level": ("UNIFI_AUDIT_LEVEL", "verbose"),
    "audit_calls": ("UNIFI_AUDIT_CALLS", "maybe"),
    "audit_log_mode": ("UNIFI_AUDIT_LOG_MODE", "0644"),
    "audit_hmac_key": ("UNIFI_AUDIT_HMAC_KEY", "invalid"),
    "audit_chain": ("UNIFI_AUDIT_CHAIN", "maybe"),
    "audit_chain_key": ("UNIFI_AUDIT_CHAIN_KEY", "invalid"),
    "tool_mode": ("UNIFI_TOOL_MODE", "discovery,full"),
    "write_policy": ("UNIFI_WRITE_POLICY", "maybe"),
    "write_exceptions": ("UNIFI_WRITE_EXCEPTIONS", "family:network=allow"),
    "family_allow": ("UNIFI_FAMILY_ALLOW", "networkk"),
    "exclude": ("UNIFI_EXCLUDE", "netwrk"),
    # MCPTransportSettings (MCP_*; cache_ttl is UNIFI_MCP_CACHE_TTL)
    "bearer_token": ("MCP_BEARER_TOKEN", "a b"),
    "auth_mode": ("MCP_AUTH_MODE", "basic"),
    "oauth_issuer": ("MCP_OAUTH_ISSUER", "auth.example.com"),
    "oauth_jwks_uri": ("MCP_OAUTH_JWKS_URI", "https://user:pw@auth.example.com/jwks"),
    "oauth_audience": ("MCP_OAUTH_AUDIENCE", "aud\n"),
    "oauth_required_scopes": ("MCP_OAUTH_REQUIRED_SCOPES", 'read,bad"scope'),
    "oauth_algorithm": ("MCP_OAUTH_ALGORITHM", "HS256"),
    "oauth_base_url": ("MCP_OAUTH_BASE_URL", "ftp://mcp.example.com"),
    "oauth_authorization_servers": ("MCP_OAUTH_AUTHORIZATION_SERVERS", "https://a.example,x"),
    "tls_mode": ("MCP_TLS_MODE", "ssl"),
    "tls_certfile": ("MCP_TLS_CERTFILE", " /c.pem"),
    "tls_keyfile": ("MCP_TLS_KEYFILE", "/k.pem\t"),
    "tls_ca_certs": ("MCP_TLS_CA_CERTS", "/ca\x7f.pem"),
    "tls_key_password": ("MCP_TLS_KEY_PASSWORD", "pw\n"),
    "tls_cert_reqs": ("MCP_TLS_CERT_REQS", "always"),
    "cache_ttl": ("UNIFI_MCP_CACHE_TTL", "-5"),
    "host_origin_protection": ("MCP_HOST_ORIGIN_PROTECTION", "maybe"),
    "health_route": ("MCP_HEALTH_ROUTE", "maybe"),
    "allowed_hosts": ("MCP_ALLOWED_HOSTS", "https://not-a-host.example"),
    "allowed_origins": ("MCP_ALLOWED_ORIGINS", "not-an-origin"),
    "oauth_write_scope": ("MCP_OAUTH_WRITE_SCOPE", "two scopes"),
}


def test_the_settings_table_covers_every_field():
    fields = set(Settings.model_fields) | set(MCPTransportSettings.model_fields)
    assert set(_BAD_SETTINGS) == fields


@pytest.mark.parametrize("field", sorted(_BAD_SETTINGS))
def test_every_setting_is_validated_at_load_naming_its_variable(monkeypatch, field):
    env, value = _BAD_SETTINGS[field]
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv(env, value)
    model = Settings if field in Settings.model_fields else MCPTransportSettings
    with pytest.raises((ValidationError, ValueError)) as exc:
        model()
    assert env in str(exc.value), f"{field}: {exc.value}"


@pytest.mark.parametrize(
    ("env", "value"),
    [
        ("MCP_OAUTH_ALGORITHM", "ES256"),
        ("MCP_OAUTH_ISSUER", "https://auth.example.com/realms/x"),
        ("MCP_OAUTH_JWKS_URI", "https://auth.example.com/jwks?kid=1"),
        ("MCP_OAUTH_REQUIRED_SCOPES", "read:x, write:y"),
        ("MCP_TLS_CERTFILE", "/etc/certs/server cert.pem"),
        ("UNIFI_FAMILY_ALLOW", "network, protect"),
        ("UNIFI_AUDIT_LOG", "/var/log/unifi audit.log"),
    ],
)
def test_valid_settings_still_load(monkeypatch, env, value):
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv(env, value)
    model = MCPTransportSettings if env.startswith("MCP_") else Settings
    model()


# ============================================================== per-console site locks


class _SlowSites:
    paginate_max_pages = None

    def list_key_labels(self) -> list[str]:
        return ["one"]

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.in_flight = 0
        self.peak = 0

    async def paginate_offset(self, path: str, **_: Any) -> list[dict[str, Any]]:
        self.calls.append(path)
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        await asyncio.sleep(0.01)
        self.in_flight -= 1
        return [{"id": _UUID_A, "description": "Default"}]


async def test_different_consoles_site_lists_fetch_concurrently_on_one_key():
    client = _SlowSites()
    reg = Registry(client, ttl_seconds=900)  # type: ignore[arg-type]
    key = APIKeyConfig(key="k", label="one")
    await asyncio.gather(reg.get_sites("AA:1", key=key), reg.get_sites("BB:2", key=key))
    assert client.peak == 2  # both in flight at once
    assert len(client.calls) == 2


async def test_one_consoles_site_list_is_fetched_once_under_concurrency():
    client = _SlowSites()
    reg = Registry(client, ttl_seconds=900)  # type: ignore[arg-type]
    key = APIKeyConfig(key="k", label="one")
    results = await asyncio.gather(*(reg.get_sites("AA:1", key=key) for _ in range(5)))
    assert len(client.calls) == 1
    assert all(list(r) == list(results[0]) for r in results)


# ================================================================== device tags


async def test_device_tag_with_padded_upstream_name_is_selectable(monkeypatch):
    """A device tag literally named "Fiber - " is selected by that name (the name rule:
    edge whitespace allowed) and by its visible text; its _id in any case."""
    from unifi_fabric.shared_shapes import _classic_objects

    tags = [{"_id": "650000000000000000000aa1", "name": "Fiber - ", "member_table": []}]

    async def _slug(registry: Any, host: str, site: str) -> tuple[None, str, str]:
        return None, "AA:1", "default"

    class _Client:
        async def get(self, path: str, **_: Any) -> Any:
            return tags

    monkeypatch.setattr(_classic_objects, "resolve_site_slug", _slug)
    for selector in ("Fiber - ", "Fiber -", "fiber -", tags[0]["_id"].upper()):
        *_rest, record = await _classic_objects.resolve_device_tag_record(
            _Client(),
            None,
            "h",
            "s",
            selector,  # type: ignore[arg-type]
        )
        assert record is tags[0], selector
    for bad in ("", "Fiber\n"):
        with pytest.raises(ValueError, match="tag_id"):
            await _classic_objects.resolve_device_tag_record(
                _Client(),
                None,
                "h",
                "s",
                bad,  # type: ignore[arg-type]
            )
