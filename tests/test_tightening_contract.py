"""Request-tightening contract: request policy tightening by request headers.

- The full operator x header x route matrix for X-UniFi-Write-Policy (3 x 7 x 9 cells),
  plus the X-UniFi-Family-Allow and X-UniFi-Exclude matrices and scoped exceptions,
  each checked against an independent oracle.
- The header cells of the unset/blank/empty truth table.
- tests/fixtures/contracts/t/v1: every envelope runs against the real server middleware
  chain (credential ingress, request policy, tool guards) on the hermetic fake upstream,
  including the refusal-order pair fixtures; each pair also runs with its earlier cause
  removed, which must yield the later code (both members live). ``input.upstream`` is
  served (tests/contract_upstream.py); an accept fixture passes only when the call
  succeeds, and each zero-mutation accept also runs as a control without its dry-run
  source, which must mutate.
- tools/list: the JSON-RPC error code constant and refusal data; list narrowing; the
  API key header is never read.
- Discovery: listing, search and describe follow the request policy.
- Dry-run: zero upstream mutation under a request dry-run, against a control that mutates.
- Concurrency: per-request policy and dry-run state never leak between concurrent calls.
"""

from __future__ import annotations

import asyncio
import contextvars
import copy
import json
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest
from fastmcp.exceptions import ToolError
from mcp.shared.exceptions import MCPError

from tests import contract_upstream as cu
from tests import upstream_harness as uh
from unifi_fabric import header_credentials as hc
from unifi_fabric import policy as sp
from unifi_fabric import request_policy as rp
from unifi_fabric import server
from unifi_fabric.contracts import TOOLS_LIST_POLICY_ERROR_CODE, EffectivePolicy
from unifi_fabric.discovery import META_TOOLS as DISCOVERY_TOOLS
from unifi_fabric.discovery import DiscoveryMiddleware, apply_tool_mode
from unifi_fabric.families import ALL_FAMILIES

FIXTURES = Path(__file__).parent / "fixtures" / "contracts" / "t" / "v1"
FAMILIES = frozenset(ALL_FAMILIES)
READ_PATH = "/proxy/network/integration/v1/sites"
MUTATING_GET = "/proxy/protect/api/cameras/cam-1/enable-control"
KEY_HEADER = ("X-UniFi-Api-Key", '{"alpha":"synthetic-key-a"}')
REFUSAL_ORDER = (
    "invalid_api_key_header",
    "invalid_policy_header",
    "missing_api_key_header",
    "key_label_not_allowed",
    "tool_not_exposed",
    "write_denied",
    "code_mode_invalid_source",
    "code_mode_busy",
    "credential_cache_saturated",
)

_HEADERS: contextvars.ContextVar[Sequence[tuple[str, str]]] = contextvars.ContextVar(
    "t_headers", default=()
)


def _source(pairs: Sequence[tuple[str, str]]) -> rp.HeaderSource:
    def values(name: str) -> list[str] | None:
        found = [v for k, v in pairs if k.lower() == name.lower()]
        return found or None

    return values


def _task_source(name: str) -> list[str] | None:
    return _source(_HEADERS.get())(name)


def _middleware(kind: type) -> Any:
    found = [m for m in server.mcp.middleware if isinstance(m, kind)]
    assert len(found) == 1, kind
    return found[0]


def _live_evaluator() -> rp.RequestPolicy:
    """The evaluator wired into the live chain (a module reload by an earlier test can leave
    ``server._request_policy`` pointing at another generation's evaluator)."""
    return _middleware(rp.RequestPolicyMiddleware).evaluator


@pytest.fixture(scope="module")
def evaluator() -> rp.RequestPolicy:
    return _live_evaluator()


@pytest.fixture(scope="module")
def catalog(evaluator) -> sp.Catalog:
    return evaluator.catalog()


@pytest.fixture()
def wired(monkeypatch: pytest.MonkeyPatch) -> Iterator[rp.RequestPolicy]:
    """The ingress and the request evaluator read headers from a task-local variable."""
    monkeypatch.setattr(_middleware(hc.HeaderCredentialMiddleware), "_headers", _task_source)
    live = _live_evaluator()
    monkeypatch.setattr(live, "_headers", _task_source)
    hooked = getattr(hc._request_policy_hook, "__self__", None)
    if isinstance(hooked, rp.RequestPolicy) and hooked is not live:
        monkeypatch.setattr(hooked, "_headers", _task_source)
    yield live


def _policy(write="allow", families=FAMILIES, exclusions=(), exceptions=()) -> EffectivePolicy:
    return EffectivePolicy(write, tuple(exceptions), frozenset(families), frozenset(exclusions))  # type: ignore[arg-type]


def _tighten(operator: EffectivePolicy, catalog, *pairs: tuple[str, str]):
    return rp.tighten(_source(pairs), operator, catalog)


# --------------------------------------------------------------------------- constants/wiring


def test_tools_list_policy_error_code_constant() -> None:
    # Fixed as a contract constant: JSON-RPC -32602, the request's parameters
    # (here its policy headers) are not acceptable.
    assert TOOLS_LIST_POLICY_ERROR_CODE == -32602


def test_middleware_order_matches_refusal_order() -> None:
    names = [type(m).__name__ for m in server.mcp.middleware]
    h, t = names.index("HeaderCredentialMiddleware"), names.index("RequestPolicyMiddleware")
    assert h < t  # (1)-(4) before (5)-(6)
    for guard in ("ArgumentErrorMiddleware", "ReadOnlyToolMiddleware", "AreaOptOutMiddleware"):
        assert t < names.index(guard), guard
    assert names[-1] == "CredentialLeaseMiddleware"  # (9) innermost


def test_hook_registered() -> None:
    assert hc._request_policy_hook == server._request_policy.hook


def test_catalog_classifies_every_registered_tool(catalog) -> None:
    assert {f.family for f in catalog.tools.values()} <= FAMILIES | {sp.META_FAMILY}
    assert catalog.domain_names and not catalog.domain_names & sp.META_TOOL_NAMES


# --------------------------------------------------------------------------- header grammars


@pytest.mark.parametrize("value", ["allow", "dry-run", "deny", " deny\t", "\tallow "])
def test_write_policy_header_accepts(value, catalog) -> None:
    policy, _ = _tighten(_policy(), catalog, ("X-UniFi-Write-Policy", value))
    assert policy.write_policy == value.strip(" \t")


@pytest.mark.parametrize(
    ("header", "value"),
    [
        ("X-UniFi-Write-Policy", "Deny"),
        ("X-UniFi-Write-Policy", "dry_run"),
        ("X-UniFi-Write-Policy", "deny,allow"),
        ("X-UniFi-Write-Policy", "loud"),
        ("X-UniFi-Family-Allow", "meta"),
        ("X-UniFi-Family-Allow", "Network"),
        ("X-UniFi-Family-Allow", "network,"),
        ("X-UniFi-Family-Allow", ",network"),
        ("X-UniFi-Family-Allow", "network,,protect"),
        ("X-UniFi-Family-Allow", "network protect"),
        ("X-UniFi-Family-Allow", "protect,network,protect"),
        ("X-UniFi-Family-Allow", "nope"),
        ("X-UniFi-Exclude", "family:meta"),
        ("X-UniFi-Exclude", "family:Network"),
        ("X-UniFi-Exclude", "tool:search_tools"),
        ("X-UniFi-Exclude", "tool:list_configured_api_keys"),
        ("X-UniFi-Exclude", "tool:no_such_tool"),
        ("X-UniFi-Exclude", "source:*"),
        ("X-UniFi-Exclude", "source:Network"),
        ("X-UniFi-Exclude", "source:nowhere"),
        ("X-UniFi-Exclude", "Unofficial"),
        ("X-UniFi-Exclude", "family:"),
        ("X-UniFi-Exclude", "network"),
        ("X-UniFi-Exclude", "family:network,"),
    ],
)
def test_malformed_policy_header_refuses(header, value, catalog) -> None:
    with pytest.raises(sp.PolicyHeaderError) as info:
        _tighten(_policy(), catalog, (header, value))
    assert info.value.code == "invalid_policy_header"


@pytest.mark.parametrize(
    "value",
    [
        "family:network",
        "tool:list_cameras",
        "source:relay",
        "source:network/private.v2",
        "source:*/local",
        "source:protect/write",
        "unofficial",
        "family:protect, unofficial ,tool:create_network",
    ],
)
def test_exclude_header_accepts(value, catalog) -> None:
    policy, ignored = _tighten(_policy(), catalog, ("X-UniFi-Exclude", value))
    assert policy.exclusions == {t.strip() for t in value.split(",")}
    assert ignored == ()  # X-UniFi-Exclude only unites: never loosening


@pytest.mark.parametrize(
    "header", ["X-UniFi-Write-Policy", "X-UniFi-Family-Allow", "X-UniFi-Exclude"]
)
def test_repeated_policy_header_refuses_never_merged(header, catalog) -> None:
    value = {"X-UniFi-Write-Policy": "deny", "X-UniFi-Family-Allow": "network"}.get(
        header, "family:vpn"
    )
    with pytest.raises(sp.PolicyHeaderError):
        _tighten(_policy(), catalog, (header, value), (header, value))


# --------------------------------------------------------------------------- write matrix

OPERATOR_WRITE = ("allow", "dry-run", "deny")
HEADER_WRITE: dict[str, tuple[str, ...]] = {
    "absent": (),
    "allow": ("allow",),
    "dry-run": ("dry-run",),
    "deny": ("deny",),
    "blank": (" \t ",),
    "malformed": ("Deny",),
    "repeated": ("deny", "deny"),
}
ROUTES: dict[str, tuple[str, dict[str, Any]]] = {
    "read-tool": ("list_cameras", {"host": "h"}),
    "write-tool": ("create_network", {"host": "h", "site": "s", "network_config": {}}),
    "relay-post": ("fabric_connector_post", {"host": "h", "path": READ_PATH}),
    "relay-get-read": ("fabric_connector_get", {"host": "h", "path": READ_PATH}),
    "relay-get-mutating": ("fabric_connector_get", {"host": "h", "path": MUTATING_GET}),
    "call-read-tool": ("call_read_tool", {"name": "list_cameras", "arguments": {"host": "h"}}),
    "call-write-tool": ("call_write_tool", {"name": "create_network", "arguments": {"host": "h"}}),
    "describe-write": ("describe_tool", {"name": "create_network"}),
    "tools/list": ("tools/list", {}),
}
WRITE_ROUTES = {"write-tool", "relay-post", "relay-get-mutating", "call-write-tool"}
_RANK = {"allow": 0, "dry-run": 1, "deny": 2}


def _oracle(operator: str, header: str, route: str) -> dict[str, Any]:
    """Independent statement of the contract for one write-matrix cell."""
    if header in ("blank", "malformed", "repeated"):
        return {"code": "invalid_policy_header"}
    request = None if header == "absent" else header
    effective = operator if request is None or _RANK[operator] >= _RANK[request] else request
    loose = request is not None and _RANK[request] < _RANK[operator]
    out: dict[str, Any] = {
        "code": None,
        "write_policy": effective,
        "ignored": [f"x-unifi-write-policy={request}"] if loose else [],
        "mode": "allow",
    }
    if route in WRITE_ROUTES:
        out["mode"] = effective
        if effective == "deny":
            out["code"] = "write_denied"
    return out


@pytest.mark.parametrize("route", list(ROUTES))
@pytest.mark.parametrize("header", list(HEADER_WRITE))
@pytest.mark.parametrize("operator", OPERATOR_WRITE)
def test_write_policy_matrix(operator, header, route, catalog, evaluator) -> None:
    expected = _oracle(operator, header, route)
    pairs = [("X-UniFi-Write-Policy", v) for v in HEADER_WRITE[header]]
    try:
        policy, ignored = _tighten(_policy(operator), catalog, *pairs)
    except sp.PolicyHeaderError as exc:
        assert expected["code"] == exc.code == "invalid_policy_header"
        return
    assert policy.write_policy == expected["write_policy"]
    assert list(ignored) == expected["ignored"]
    if route == "tools/list":
        return
    name, arguments = ROUTES[route]
    code, _message, mode = rp.decide(
        name=name, arguments=arguments, policy=policy, catalog=catalog, is_write=evaluator.is_write
    )
    assert code == expected["code"]
    if code is None:
        assert mode == expected["mode"]


def test_write_matrix_has_every_cell() -> None:
    assert len(OPERATOR_WRITE) * len(HEADER_WRITE) * len(ROUTES) == 189


@pytest.mark.parametrize(
    ("exceptions", "header", "expected"),
    [
        ((("tool:create_network", "deny"),), None, "deny"),
        ((("family:network", "dry-run"),), None, "dry-run"),
        ((("family:network", "dry-run"),), "deny", "deny"),
        ((("tool:create_network", "dry-run"),), "allow", "dry-run"),
        ((("family:protect", "deny"),), None, "allow"),
    ],
)
def test_scoped_write_exceptions_with_header(
    exceptions, header, expected, catalog, evaluator
) -> None:
    op = _policy("allow", exceptions=exceptions)
    pairs = [("X-UniFi-Write-Policy", header)] if header else []
    policy, _ = _tighten(op, catalog, *pairs)
    assert policy.write_exceptions == op.write_exceptions  # requests add no exceptions
    code, _, mode = rp.decide(
        name="create_network",
        arguments={},
        policy=policy,
        catalog=catalog,
        is_write=evaluator.is_write,
    )
    assert (code, mode) == (("write_denied", "deny") if expected == "deny" else (None, expected))


@pytest.mark.parametrize(
    ("exceptions", "entry"),
    [
        ((("family:network", "deny"),), "family:network=deny"),
        ((("tool:create_network", "deny"),), "tool:create_network=deny"),
        # a non-matching deny and a matching dry-run are never the named entry
        (
            (
                ("family:network", "dry-run"),
                ("family:protect", "deny"),
                ("tool:create_network", "deny"),
            ),
            "tool:create_network=deny",
        ),
    ],
)
def test_write_denied_message_names_the_denying_exception_entry(
    exceptions, entry, catalog, evaluator
) -> None:
    code, message, mode = rp.decide(
        name="create_network",
        arguments={},
        policy=_policy("allow", exceptions=exceptions),
        catalog=catalog,
        is_write=evaluator.is_write,
    )
    assert (code, mode) == ("write_denied", "deny")
    assert f"The UNIFI_WRITE_EXCEPTIONS entry {entry} denies it." in message
    assert "No upstream call was made." in message
    for other in ("family:protect=deny", "family:network=dry-run"):
        if other != entry:
            assert other not in message


def test_write_denied_message_names_no_entry_when_the_global_policy_denies(
    catalog, evaluator
) -> None:
    code, message, _mode = rp.decide(
        name="create_network",
        arguments={},
        policy=_policy("deny"),
        catalog=catalog,
        is_write=evaluator.is_write,
    )
    assert code == "write_denied"
    assert "UNIFI_WRITE_POLICY" in message
    assert "UNIFI_WRITE_EXCEPTIONS entry" not in message


# --------------------------------------------------------------------------- family / exclusion

OPERATOR_FAMILIES = {
    "all": FAMILIES,
    "protect": frozenset({"protect"}),
    "network+protect": frozenset({"network", "protect"}),
}
HEADER_FAMILIES = {
    "absent": None,
    "network": "network",
    "protect": "protect",
    "network,protect": "network,protect",
    "vpn": "vpn",
}
TARGETS = {"list_cameras": "protect", "create_network": "network", "list_vpn_users": "vpn"}


@pytest.mark.parametrize("target", list(TARGETS))
@pytest.mark.parametrize("header", list(HEADER_FAMILIES))
@pytest.mark.parametrize("operator", list(OPERATOR_FAMILIES))
def test_family_allow_matrix(operator, header, target, catalog) -> None:
    assert catalog.tools[target].family == TARGETS[target]
    op_fams = OPERATOR_FAMILIES[operator]
    raw = HEADER_FAMILIES[header]
    requested = None if raw is None else raw.split(",")
    exposed = set(op_fams) if requested is None else set(op_fams) & set(requested)
    ignored = [f"x-unifi-family-allow={f}" for f in (requested or []) if f not in op_fams]
    pairs = [("X-UniFi-Family-Allow", raw)] if raw is not None else []
    policy, got_ignored = _tighten(_policy(families=op_fams), catalog, *pairs)
    assert policy.exposed_families == frozenset(exposed)
    assert list(got_ignored) == ignored
    want = None if TARGETS[target] in exposed else "tool_not_exposed"
    for name, arguments in (
        (target, {"host": "h"}),
        ("call_read_tool", {"name": target, "arguments": {}}),
        ("describe_tool", {"name": target}),
    ):
        code, _, _ = rp.decide(
            name=name,
            arguments=arguments,
            policy=policy,
            catalog=catalog,
            is_write=lambda *_: False,
        )
        assert code == want, name


CANDIDATES = (
    "create_network",
    "list_cameras",
    "fabric_connector_get",
    "fabric_connector_post",
    "list_protect_cases",
    "list_vpn_users",
)


@pytest.mark.parametrize(
    ("operator_excl", "header", "blocked"),
    [
        ((), "family:network", {"create_network"}),
        (
            ("family:protect",),
            "family:network",
            {"create_network", "list_cameras", "list_protect_cases"},
        ),
        ((), "tool:list_cameras", {"list_cameras"}),
        ((), "source:relay", {"fabric_connector_get", "fabric_connector_post"}),
        ((), "source:protect/official", {"list_cameras"}),
        ((), "unofficial", {"list_protect_cases", sp.UNOFFICIAL}),
        (("unofficial",), "family:vpn", {"list_protect_cases", "list_vpn_users", sp.UNOFFICIAL}),
    ],
)
def test_exclusion_union_matrix(operator_excl, header, blocked, catalog) -> None:
    fams = FAMILIES - {t.split(":")[1] for t in operator_excl if t.startswith("family:")}
    policy, _ = _tighten(
        _policy(families=fams, exclusions=operator_excl), catalog, ("X-UniFi-Exclude", header)
    )
    assert policy.exclusions == frozenset(operator_excl) | {header}
    if sp.UNOFFICIAL in blocked:
        # Every candidate whose primary API source is private is unofficial.
        blocked = (blocked - {sp.UNOFFICIAL}) | {
            n for n in CANDIDATES if catalog.tools[n].api_status == sp.UNOFFICIAL
        }
    for name in CANDIDATES:
        code, _, _ = rp.decide(
            name=name,
            arguments={"host": "h", "path": READ_PATH},
            policy=policy,
            catalog=catalog,
            is_write=lambda *_: False,
        )
        assert code == ("tool_not_exposed" if name in blocked else None), name
    for meta in sp.META_TOOL_NAMES - rp.TARGETED_META_TOOLS:
        code, _, _ = rp.decide(
            name=meta, arguments={}, policy=policy, catalog=catalog, is_write=lambda *_: True
        )
        assert code is None, meta


@pytest.mark.parametrize(
    "token",
    ["source:server", "source:server/local", "source:*/local", "source:relay", "unofficial"],
)
def test_exclusions_never_remove_meta_tools(token, catalog) -> None:
    policy, _ = _tighten(_policy(), catalog, ("X-UniFi-Exclude", token))
    for name in catalog.meta_names:
        assert sp.is_exposed(policy, catalog.tools[name])


# --------------------------------------------------------------------------- truth table (headers)


def test_truth_table_headers_absent_keep_operator(catalog) -> None:
    op = _policy("dry-run", families={"protect", "network"}, exclusions={"tool:list_cameras"})
    policy, ignored = _tighten(op, catalog)
    assert policy == op and ignored == ()


@pytest.mark.parametrize(
    "header", ["X-UniFi-Write-Policy", "X-UniFi-Family-Allow", "X-UniFi-Exclude"]
)
@pytest.mark.parametrize("blank", ["", " ", "\t", " \t\r\n "])
def test_truth_table_header_blank_refuses(header, blank, catalog) -> None:
    with pytest.raises(sp.PolicyHeaderError) as info:
        _tighten(_policy(), catalog, (header, blank))
    assert header.lower() in str(info.value).lower()


def test_truth_table_family_allow_empty_intersection(catalog) -> None:
    policy, ignored = _tighten(
        _policy(families={"protect"}), catalog, ("X-UniFi-Family-Allow", "network")
    )
    assert policy.exposed_families == frozenset()
    assert ignored == ("x-unifi-family-allow=network",)
    assert sp.exposed_names(policy, catalog) == catalog.meta_names
    code, _, _ = rp.decide(
        name="list_cameras", arguments={}, policy=policy, catalog=catalog, is_write=lambda *_: False
    )
    assert code == "tool_not_exposed"


def test_truth_table_exclude_removing_every_domain_tool(catalog) -> None:
    header = ",".join(f"family:{f}" for f in sorted(FAMILIES))
    policy, _ = _tighten(_policy(), catalog, ("X-UniFi-Exclude", header))
    assert policy.exposed_families == frozenset()
    assert sp.exposed_names(policy, catalog) == catalog.meta_names


def test_header_value_never_echoed(catalog) -> None:
    secret = "synthetic-secret-value-zz9"
    for header in ("X-UniFi-Write-Policy", "X-UniFi-Family-Allow", "X-UniFi-Exclude"):
        with pytest.raises(sp.PolicyHeaderError) as info:
            _tighten(_policy(), catalog, (header, secret))
        assert secret not in str(info.value)


# --------------------------------------------------------------------------- fixture envelopes


def _fixture_files() -> list[Path]:
    return sorted(FIXTURES.glob("*.json"))


_ENVELOPE_KEYS = {"schema_version", "contract", "name", "description", "kind", "input", "expected"}
_INPUT_KEYS = {"env", "headers", "arguments", "route", "transport", "upstream"}
_ACCEPT_KEYS = {
    "effective_policy",
    "ignored_loosening",
    "selected_labels",
    "listed_tools",
    "upstream_calls",
    "upstream_mutations",
}


@pytest.mark.parametrize("path", _fixture_files(), ids=lambda p: p.stem)
def test_fixture_envelope_shape(path: Path) -> None:
    fx = json.loads(path.read_text(encoding="utf-8"))
    assert set(fx) == _ENVELOPE_KEYS
    assert fx["schema_version"] == "1" and fx["contract"] == "t" and fx["name"] == path.stem
    assert fx["description"].strip() and set(fx["input"]) <= _INPUT_KEYS
    if fx["kind"] == "reject":
        assert set(fx["expected"]) == {"code", "upstream_calls"}
        assert fx["expected"]["upstream_calls"] == 0 and fx["expected"]["code"] in REFUSAL_ORDER
    else:
        assert fx["kind"] == "accept" and set(fx["expected"]) <= _ACCEPT_KEYS


def test_refusal_order_pair_fixtures_present() -> None:
    names = {p.stem for p in _fixture_files()}
    for pair in ("1-2", "2-3", "3-4", "4-5", "5-6", "3-6-nonadjacent", "2-5-nonadjacent"):
        assert f"reject-pair-{pair}" in names


async def _discovery_app() -> Any:
    """A discovery-mode app over the registered tools, with the ingress and request middleware."""
    from fastmcp import FastMCP

    app = FastMCP("t-discovery-fixture")
    for tool in rp.local_tools(server.mcp).values():
        app.add_tool(tool)
    app.add_middleware(_middleware(hc.HeaderCredentialMiddleware))
    evaluator = rp.RequestPolicy(lambda: rp.local_tools(app), headers=_task_source)
    app.add_middleware(rp.RequestPolicyMiddleware(evaluator))
    await apply_tool_mode(app, "discovery")
    app.add_middleware(DiscoveryMiddleware(app))
    return app


async def _run(fx: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    inp = fx["input"]
    for name, value in inp.get("env", {}).items():
        monkeypatch.setenv(name, value)
    upstream = uh.FakeUpstream()
    uh.install(monkeypatch, upstream)
    contract: cu.ContractUpstream | None = None
    if "upstream" in inp:
        # The fixture's own consoles, on the production client path.
        contract = cu.install(monkeypatch, inp["upstream"])
        monkeypatch.setattr(uh.UniFiClient, "_get_client", cu.REAL_GET_CLIENT)
    headers = [] if inp.get("transport") == "stdio" else [tuple(p) for p in inp.get("headers", [])]
    seen: list[tuple[EffectivePolicy, tuple[str, ...]]] = []
    real_decide = rp.decide

    def spy(**kwargs: Any) -> Any:
        context = hc.current_request_context()
        seen.append((kwargs["policy"], context.ignored_loosening if context else ()))
        return real_decide(**kwargs)

    monkeypatch.setattr(rp, "decide", spy)
    out: dict[str, Any] = {}
    token = _HEADERS.set(headers)
    try:
        if inp["route"] == "tools/list":
            try:
                if inp.get("env", {}).get("UNIFI_TOOL_MODE") == "discovery":
                    listed = await (await _discovery_app()).list_tools()
                else:
                    listed = await server.mcp.list_tools()
            except MCPError as exc:
                out["code"] = exc.data["error"]["code"]
                out["rpc_code"] = exc.code
            else:
                out["listed"] = sorted(t.name for t in listed)
                policy, ignored = _live_evaluator().evaluate()
                out["effective_policy"] = sp.canonical_policy_object(policy)
                out["ignored_loosening"] = list(ignored)
        else:
            try:
                await server.mcp.call_tool(inp["route"], copy.deepcopy(inp.get("arguments", {})))
            except ToolError as exc:
                try:
                    out["code"] = json.loads(str(exc))["error"]["code"]
                except (ValueError, KeyError, TypeError):
                    out["tool_error"] = str(exc)[:300]
            except Exception as exc:  # noqa: BLE001 - recorded; an accept fixture then fails
                out["tool_error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
            if seen:
                out["effective_policy"] = sp.canonical_policy_object(seen[0][0])
                out["ignored_loosening"] = list(seen[0][1])
    finally:
        _HEADERS.reset(token)
    if contract is not None:
        out["upstream_calls"] = len(contract.calls)
        out["upstream_mutations"] = len(contract.mutations())
    else:
        out["upstream_calls"] = len(upstream.served)
        out["upstream_mutations"] = len(upstream.writes())
    return out


@pytest.mark.parametrize("path", _fixture_files(), ids=lambda p: p.stem)
async def test_fixture(path: Path, monkeypatch: pytest.MonkeyPatch, wired) -> None:
    fx = json.loads(path.read_text(encoding="utf-8"))
    result = await _run(fx, monkeypatch)
    expected = fx["expected"]
    if fx["kind"] == "reject":
        assert result.get("code") == expected["code"], result
        assert result["upstream_calls"] == 0
        if fx["input"]["route"] == "tools/list":
            assert result["rpc_code"] == TOOLS_LIST_POLICY_ERROR_CODE
        return
    # An accept passes only when the call succeeds: a tool error (a missing argument, an
    # unresolvable host) sends no mutation and would satisfy upstream_mutations == 0.
    assert "code" not in result and "tool_error" not in result, result
    for key in ("effective_policy", "ignored_loosening", "upstream_calls", "upstream_mutations"):
        if key in expected:
            assert result[key] == expected[key], key
    if "listed_tools" in expected:
        assert result["listed"] == expected["listed_tools"]


def _replace_headers(*keep_out: str, add: Sequence[tuple[str, str]] = ()):
    def mutate(inp: dict[str, Any]) -> None:
        inp["headers"] = [h for h in inp.get("headers", []) if h[0] not in keep_out] + [
            list(a) for a in add
        ]

    return mutate


#: For each pair fixture: the change that removes the earlier cause and the later code.
PAIR_PARTNERS: dict[str, tuple[Any, str]] = {
    "reject-pair-1-2": (
        _replace_headers("X-UniFi-Api-Key", add=[KEY_HEADER]),
        "invalid_policy_header",
    ),
    "reject-pair-2-3": (_replace_headers("X-UniFi-Write-Policy"), "missing_api_key_header"),
    "reject-pair-3-4": (_replace_headers(add=[KEY_HEADER]), "key_label_not_allowed"),
    "reject-pair-4-5": (lambda i: i["arguments"].pop("key_label"), "tool_not_exposed"),
    "reject-pair-5-6": (lambda i: i["env"].pop("UNIFI_EXCLUDE"), "write_denied"),
    "reject-pair-3-6-nonadjacent": (_replace_headers(add=[KEY_HEADER]), "write_denied"),
    "reject-pair-2-5-nonadjacent": (_replace_headers("X-UniFi-Family-Allow"), "tool_not_exposed"),
}


#: For each zero-mutation accept on a tool route: the change that removes every dry-run
#: source. The control must succeed and mutate, so the fixture's zero is dry-run's doing.
DRY_RUN_CONTROLS: dict[str, Any] = {
    "accept-dry-run-header-relay-post": _replace_headers("X-UniFi-Write-Policy"),
    "accept-header-allow-under-operator-dry-run-relay-post": lambda i: i["env"].pop(
        "UNIFI_WRITE_POLICY"
    ),
}


def test_every_zero_mutation_accept_has_a_control() -> None:
    zero = set()
    for path in _fixture_files():
        fx = json.loads(path.read_text(encoding="utf-8"))
        if (
            fx["kind"] == "accept"
            and fx["input"]["route"] != "tools/list"
            and fx["expected"].get("upstream_mutations") == 0
        ):
            zero.add(fx["name"])
    assert zero == set(DRY_RUN_CONTROLS)


@pytest.mark.parametrize("name", list(DRY_RUN_CONTROLS))
async def test_dry_run_accept_control_mutates(
    name: str, monkeypatch: pytest.MonkeyPatch, wired
) -> None:
    fx = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    DRY_RUN_CONTROLS[name](fx["input"])
    result = await _run(fx, monkeypatch)
    assert "code" not in result and "tool_error" not in result, result
    assert result["upstream_mutations"] >= 1, result


@pytest.mark.parametrize("name", list(PAIR_PARTNERS))
async def test_refusal_pair_partner(name: str, monkeypatch: pytest.MonkeyPatch, wired) -> None:
    fx = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    mutate, later = PAIR_PARTNERS[name]
    mutate(fx["input"])
    result = await _run(fx, monkeypatch)
    assert result.get("code") == later, result
    assert result["upstream_calls"] == 0
    assert REFUSAL_ORDER.index(fx["expected"]["code"]) < REFUSAL_ORDER.index(later)


# --------------------------------------------------------------------------- live routes


async def test_tools_list_narrowed_and_rpc_error(monkeypatch, wired, catalog) -> None:
    monkeypatch.setenv("UNIFI_API_KEY", "synthetic-key-a")
    token = _HEADERS.set([("X-UniFi-Family-Allow", "vpn")])
    try:
        listed = {t.name for t in await server.mcp.list_tools()}
    finally:
        _HEADERS.reset(token)
    assert listed and {catalog.tools[n].family for n in listed} <= {"vpn", sp.META_FAMILY}
    token = _HEADERS.set([("X-UniFi-Exclude", "family:vpn"), ("X-UniFi-Exclude", "family:vpn")])
    try:
        with pytest.raises(MCPError) as info:
            await server.mcp.list_tools()
    finally:
        _HEADERS.reset(token)
    assert info.value.code == TOOLS_LIST_POLICY_ERROR_CODE
    assert info.value.data == {
        "error": {"code": "invalid_policy_header", "message": info.value.message}
    }


async def test_tools_list_never_reads_api_key_header(monkeypatch, wired) -> None:
    monkeypatch.setenv("UNIFI_API_KEY", "synthetic-key-a")
    base = {t.name for t in await server.mcp.list_tools()}
    token = _HEADERS.set([("X-UniFi-Api-Key", "not-json"), ("X-UniFi-Api-Key", "{}")])
    try:
        assert {t.name for t in await server.mcp.list_tools()} == base
    finally:
        _HEADERS.reset(token)


async def test_discovery_listing_search_and_describe_follow_policy(monkeypatch, wired) -> None:
    from fastmcp import FastMCP

    monkeypatch.setenv("UNIFI_API_KEY", "synthetic-key-a")
    uh.install(monkeypatch, uh.FakeUpstream())
    app = FastMCP("t-discovery")
    for tool in rp.local_tools(server.mcp).values():
        app.add_tool(tool)
    app.add_middleware(_middleware(hc.HeaderCredentialMiddleware))
    evaluator = rp.RequestPolicy(lambda: rp.local_tools(app), headers=_task_source)
    app.add_middleware(rp.RequestPolicyMiddleware(evaluator))
    await apply_tool_mode(app, "discovery")
    app.add_middleware(DiscoveryMiddleware(app))
    catalog = evaluator.catalog()
    token = _HEADERS.set([("X-UniFi-Family-Allow", "vpn")])
    try:
        listed = sorted(t.name for t in await app.list_tools())
        result = await app.call_tool("search_tools", {"query": "", "limit": None})
        names = {item["name"] for item in result.structured_content["result"]}
        with pytest.raises(ToolError) as info:
            await app.call_tool("describe_tool", {"name": "list_cameras"})
    finally:
        _HEADERS.reset(token)
    assert listed == sorted(DISCOVERY_TOOLS)
    families = {catalog.tools[n].family for n in names}
    assert "vpn" in families and families <= {"vpn", sp.META_FAMILY}
    assert json.loads(str(info.value))["error"]["code"] == "tool_not_exposed"


def _relay_post() -> dict[str, Any]:
    return {"host": uh.HOST, "path": READ_PATH, "body": {"name": "lab"}}


async def test_dry_run_header_sends_no_mutation_with_control(monkeypatch, wired) -> None:
    upstream = uh.FakeUpstream()
    uh.install(monkeypatch, upstream)
    token = _HEADERS.set([])
    try:
        await server.mcp.call_tool("fabric_connector_post", _relay_post())
    finally:
        _HEADERS.reset(token)
    control = len(upstream.writes())
    assert control >= 1  # without the header the relay POST reaches upstream
    token = _HEADERS.set([("X-UniFi-Write-Policy", "dry-run")])
    try:
        result = await server.mcp.call_tool("fabric_connector_post", _relay_post())
    finally:
        _HEADERS.reset(token)
    assert len(upstream.writes()) == control  # zero new mutations
    assert "dry_run" in json.dumps(uh.result_payload(result), default=str)
    assert not rp.request_dry_run_active()


async def test_concurrent_requests_keep_their_own_policy(monkeypatch, wired) -> None:
    upstream = uh.FakeUpstream()
    uh.install(monkeypatch, upstream)
    plan = ["allow", "dry-run", "deny"] * 8

    async def one(value: str) -> str:
        _HEADERS.set([("X-UniFi-Write-Policy", value)])
        try:
            await server.mcp.call_tool("fabric_connector_post", _relay_post())
        except ToolError as exc:
            return json.loads(str(exc))["error"]["code"]
        return "ok"

    outcomes = await asyncio.gather(*(asyncio.create_task(one(v)) for v in plan))
    assert outcomes == ["ok", "ok", "write_denied"] * 8
    assert len([s for s in upstream.writes() if s.method == "POST"]) == 8
    assert not rp.request_dry_run_active()


async def test_context_carries_tightened_policy(monkeypatch, wired) -> None:
    uh.install(monkeypatch, uh.FakeUpstream())
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    captured: list[Any] = []
    real = rp.decide

    def spy(**kwargs: Any) -> Any:
        captured.append(hc.current_request_context())
        return real(**kwargs)

    monkeypatch.setattr(rp, "decide", spy)
    token = _HEADERS.set(
        [("X-UniFi-Write-Policy", "allow"), ("X-UniFi-Family-Allow", "protect,vpn")]
    )
    try:
        await server.mcp.call_tool("list_cameras", {"host": uh.HOST})
    finally:
        _HEADERS.reset(token)
    context = captured[0]
    assert context.effective_policy.write_policy == "dry-run"
    assert context.effective_policy.exposed_families == {"protect", "vpn"}
    assert context.ignored_loosening == ("x-unifi-write-policy=allow",)


def test_refusal_shape() -> None:
    body = json.loads(str(rp.refusal_error("write_denied", "m")))
    assert body == {"error": {"code": "write_denied", "message": "m"}}


async def test_code_mode_search_filters_before_limit(monkeypatch, wired) -> None:
    from fastmcp import FastMCP

    monkeypatch.setenv("UNIFI_API_KEY", "synthetic-key-a")
    uh.install(monkeypatch, uh.FakeUpstream())
    app = FastMCP("t-code-search")
    for tool in rp.local_tools(server.mcp).values():
        app.add_tool(tool)
    app.add_middleware(_middleware(hc.HeaderCredentialMiddleware))
    evaluator = rp.RequestPolicy(lambda: rp.local_tools(app), headers=_task_source)
    app.add_middleware(rp.RequestPolicyMiddleware(evaluator))
    catalog = evaluator.catalog()
    await apply_tool_mode(app, "codemode", audit_hmac_key=bytes(range(32)))
    token = _HEADERS.set([("X-UniFi-Family-Allow", "vpn")])
    try:
        result = await app.call_tool("search_tools", {"query": "", "limit": 2})
        names = [item["name"] for item in result.structured_content["result"]]
    finally:
        _HEADERS.reset(token)
    assert len(names) == 2
    assert all(catalog.tools[name].family == "vpn" for name in names)
