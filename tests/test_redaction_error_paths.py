"""Opt-in error evidence stays useful without exposing credential values."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from unifi_fabric import client as client_module
from unifi_fabric import server
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.matching import find_by_id
from unifi_fabric.registry import _require_native_id
from unifi_fabric.tools import (
    _classic_cmd,
    _classic_objects,
    _device_config,
    _device_wrappers,
    _keys,
    client_records,
    clients,
    connector,
    device_radios,
    innerspace_internal,
    matter,
    network_controller_admin,
    network_controller_insights,
    network_device_operations,
    network_nat_qos_traffic,
    network_proav_sandbox,
    network_services_proxy,
    network_wifi_radio,
    protect_private,
    site_admin,
    site_config,
    site_manager,
    statistics,
    vpn,
)
from unifi_fabric.tools.site_manager import _unique_proxy_sites

SENTINEL = "synthetic-error-path-SENTINEL"
PAYLOAD = {"password": SENTINEL, "reason": "synthetic upstream failure"}


@pytest.fixture
async def rig(monkeypatch):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1")
    settings = Settings(api_key="synthetic-test-key", redact_secrets=True)
    client = UniFiClient(settings)
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(200, json=state["body"])

    transport_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handle),
        base_url="https://synthetic.invalid",
        timeout=None,  # noqa: S113 -- in-memory transport
    )
    monkeypatch.setattr(client, "_get_client", AsyncMock(return_value=transport_client))
    state = {"body": PAYLOAD}
    try:
        yield client, calls, state
    finally:
        await transport_client.aclose()
        await client.close()


@pytest.mark.parametrize(
    "site",
    [
        "client-shape",
        "client-rc",
        "client-msg",
        "classic-rc",
        "classic-msg",
        "classic-data",
        "classic-object",
        "device-shape",
        "device-rc",
        "radio-missing",
        "radio-duplicate",
        "connector-classic",
        "connector-status",
        "record-id",
        "record-identifying",
        "registry-id",
        "console-id",
        "console-invalid-id",
    ],
)
async def test_error_sites_mask_transport_evidence(rig, site):
    client, calls, state = rig
    body = await client.get("/v1/test")
    assert body == PAYLOAD and calls
    envelope = {"meta": {"rc": "error"}, "data": body}

    def drive():
        if site == "client-shape":
            raise client_module.wrong_type_error("data", body)
        if site in {"client-rc", "client-msg", "classic-rc", "classic-msg"}:
            field = "rc" if site.endswith("-rc") else "msg"
            fn = (
                client_module.classic_rc_error
                if site.startswith("client")
                else _classic_cmd.classic_rc_failure
            )
            args = (200, {"meta": {"rc": "error", field: body}})
            return (
                fn(
                    "/v1/connector/consoles/synthetic/proxy/network/api/s/default/stat/device",
                    *args,
                )
                if site.startswith("client")
                else fn(*args)
            )
        if site == "classic-data":
            return _classic_cmd.command_data(body)
        if site == "classic-object":
            return _classic_objects.checked_classic_response(envelope, "/test", client=client)
        if site == "device-shape":
            return _device_config.require_classic_success([body], "/test")
        if site == "device-rc":
            return _device_config.require_classic_success(envelope, "/test")
        if site == "radio-missing":
            return device_radios._radio_rows({"_id": body}, "radio_table")
        if site == "radio-duplicate":
            band = json.dumps(body)
            return device_radios._radios_by_band([{"radio": band}, {"radio": band}])
        if site.startswith("connector-"):
            response = {"body": body, "status": 503}
            if site == "connector-classic":
                response[connector.CLASSIC_RC_ERROR_KEY] = "synthetic failure"
            return connector._read_after_error(client, response)
        if site == "registry-id":
            return _require_native_id({"id": body, "reportedState": body}, "id")
        if site.startswith("console-"):
            return _unique_proxy_sites(
                [{"id": body if site == "console-id" else "bad/id", "name": body}]
            )
        record = {"_id": body if site == "record-id" else "bad/id", "name": body}
        return _classic_objects.listed_record_id(record, "record_id")

    try:
        text = str(drive())
    except (ValueError, client_module.UniFiConnectionError) as exc:
        text = str(exc)
    assert text and SENTINEL not in text
    assert "REDACTED" in text


@pytest.mark.parametrize("site", ["classic-command", "controller-post"])
async def test_classic_http_error_sites(rig, monkeypatch, site):
    client, calls, state = rig
    state["body"] = {"meta": {"rc": "error", "msg": PAYLOAD}, "data": PAYLOAD}
    if site == "classic-command":
        # Isolate the tool's own defensive check, which also supports duck-typed clients.
        transport_client = await client._get_client(None)

        async def request(method, path, **kwargs):
            kwargs.pop("key", None)
            return await transport_client.request(method, path, **kwargs)

        monkeypatch.setattr(client, "request", request)
    with pytest.raises(_classic_cmd.ClassicCommandError) as caught:
        if site == "classic-command":
            await _classic_cmd.classic_command(
                client, "synthetic-host", "default", "stamgr", "block-sta"
            )
        else:
            await network_controller_admin._classic_post(client, None, "/v1/test", {"cmd": "test"})
    assert calls
    assert SENTINEL not in str(caught.value)
    assert "REDACTED" in str(caught.value)


@pytest.mark.parametrize("site", ["port-forward-stats", "device-operation", "controller-read"])
async def test_classic_rc_sites_mask_without_client_settings(monkeypatch, site):
    """A client without ``_settings`` (duck-typed) still follows the redaction opt-in."""
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1")
    body = {"meta": {"rc": "error", "msg": PAYLOAD}, "data": PAYLOAD}
    path = "/v1/connector/consoles/synthetic/proxy/network/api/s/default/stat/test"
    resp = httpx.Response(200, json=body, request=httpx.Request("GET", "https://x.invalid"))
    client = SimpleNamespace(request=AsyncMock(return_value=resp))
    monkeypatch.setattr(
        network_proav_sandbox, "_site", AsyncMock(return_value=(None, "synthetic", "default"))
    )
    with pytest.raises(client_module.UniFiConnectionError) as caught:
        if site == "port-forward-stats":
            await network_proav_sandbox.get_port_forward_statistics(
                client, AsyncMock(), "synthetic", "default"
            )
        elif site == "device-operation":
            network_device_operations._classic_ok(client, resp, "GET", path)
        else:
            await network_controller_insights._classic_get(client, path, key=None)
    assert SENTINEL not in str(caught.value)
    assert "REDACTED" in str(caught.value)


@pytest.mark.parametrize("site", ["update", "unadopt", "tamper"])
async def test_protect_error_sites(rig, monkeypatch, site):
    client, calls, state = rig
    evidence = await client.get("/v1/test")
    read = {"status": 503, "body": evidence}
    monkeypatch.setattr(protect_private.connector, "connector_get", AsyncMock(return_value=read))
    monkeypatch.setattr(
        protect_private.connector,
        "connector_write",
        AsyncMock(return_value={"status": 200, "readAfter": read}),
    )
    monkeypatch.setattr(
        protect_private, "_device_path", AsyncMock(return_value="protect/api/sensors/synthetic")
    )
    monkeypatch.setattr(
        protect_private, "_action", AsyncMock(return_value={"status": 200, "readAfter": read})
    )
    registry = AsyncMock()
    if site == "update":
        protect_private.connector.connector_get.return_value = {"status": 200, "body": {}}
        result = await protect_private._update(
            client, registry, "synthetic", "protect/api/nvr", {"enabled": True}
        )
    elif site == "unadopt":
        result = await protect_private.unadopt_protect_device(
            client, registry, "synthetic", "camera", "synthetic"
        )
    else:
        result = await protect_private.clear_sensor_tamper(
            client, registry, "synthetic", "synthetic"
        )
    assert calls
    assert SENTINEL not in result["readAfterError"]
    assert "REDACTED" in result["readAfterError"]


async def test_protect_listing_error_masks_upstream_body(rig, monkeypatch):
    client, calls, state = rig
    evidence = await client.get("/v1/test")
    monkeypatch.setattr(
        protect_private.connector,
        "connector_get",
        AsyncMock(return_value={"status": 503, "body": evidence}),
    )
    with pytest.raises(client_module.UniFiConnectionError) as caught:
        await protect_private._resolve(client, AsyncMock(), "synthetic", "cameras", "Front Door")
    assert calls
    assert str(caught.value).startswith("GET protect/api/cameras: HTTP 503: ")
    assert SENTINEL not in str(caught.value)
    assert "REDACTED" in str(caught.value)


OTHER_ID = "0123456789abcdef01234567"
WANTED_ID = "fedcba9876543210fedcba98"


@pytest.mark.parametrize(
    "site",
    [
        "classic-select",
        "device-tag",
        "listed-record",
        "traffic-route",
        "networks",
        "wlan-group",
        "nat-choice",
        "ambiguous-id",
    ],
)
async def test_not_found_listings_mask_upstream_fields(rig, monkeypatch, site):
    """Unknown-id errors list upstream records; their fields render through the masking."""
    client, calls, state = rig
    listed = {"_id": OTHER_ID, "external_id": PAYLOAD, "name": PAYLOAD, "description": PAYLOAD}
    state["body"] = {"meta": {"rc": "ok"}, "data": [listed]}
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "synthetic-host"
    registry.resolve_site_slug.return_value = "default"
    monkeypatch.setattr(
        _classic_objects,
        "resolve_site_slug",
        AsyncMock(return_value=(None, "synthetic-host", "default")),
    )
    records = (await client.get("/v1/test"))["data"]
    with pytest.raises(ValueError) as caught:
        if site == "classic-select":
            _classic_objects.select_classic_record(records, WANTED_ID, "Thing", "list_things")
        elif site == "device-tag":
            state["body"] = records
            await _classic_objects.resolve_device_tag_record(
                client, registry, "synthetic", "default", WANTED_ID
            )
        elif site == "listed-record":
            await _classic_objects.require_listed_record(
                client, "/v1/test", WANTED_ID, key=None, kind="Thing", list_tool="list_things"
            )
        elif site == "traffic-route":
            state["body"] = records
            await network_services_proxy.get_traffic_route(
                client, registry, "synthetic", "default", WANTED_ID
            )
        elif site == "networks":
            raise ValueError(network_services_proxy._valid_networks(records))
        elif site == "wlan-group":
            await network_services_proxy.get_wlan_group(
                client, registry, "synthetic", "default", WANTED_ID
            )
        elif site == "nat-choice":
            rows = [{"_id": json.dumps(PAYLOAD)}]
            raise ValueError(network_nat_qos_traffic._nc_unknown("Rule", WANTED_ID, rows, "list"))
        else:
            twins = [{**listed, "_id": i, "external_id": "shared"} for i in (OTHER_ID, WANTED_ID)]
            find_by_id(twins, "shared", "_id", "external_id")
    assert calls
    assert SENTINEL not in str(caught.value)
    assert "REDACTED" in str(caught.value)


def test_not_found_listing_scalars_render_as_before():
    """Plain upstream names, ids and absent fields keep their exact rendering."""
    records = [{"_id": OTHER_ID, "name": "Office"}, {"_id": WANTED_ID}]
    with pytest.raises(ValueError) as caught:
        _classic_objects.select_classic_record(records, "ab" * 12, "Thing", "list_things")
    assert f"valid: 'Office': id=None, _id={OTHER_ID}; None: id=None, _id={WANTED_ID}." in str(
        caught.value
    )
    twin = [{"_id": OTHER_ID, "id": "dup", "name": "A"}, {"_id": WANTED_ID, "id": "dup"}]
    with pytest.raises(ValueError) as caught:
        find_by_id(twin, "dup", "_id", "id")
    assert str(caught.value) == (
        "ambiguous id 'dup': matches distinct records: "
        f"{{'_id': '{OTHER_ID}', 'id': 'dup', 'name': 'A', 'mac': None, 'macAddress': None}}; "
        f"{{'_id': '{WANTED_ID}', 'id': 'dup', 'name': None, 'mac': None, 'macAddress': None}}"
    )


# Input command names are caller data, not upstream bodies.
REPR_ALLOWLIST = {
    # Pydantic model field names are defined by the server, never supplied upstream.
    ("config.py", "', '.join((repr(k) for k in APIKeyConfig.model_fields))"),
    # These are caller ids validated by validate_id before any request or readback.
    ("tools/network_dpi_policy.py", "present or 'none'"),
    ("tools/network_dpi_policy.py", "unverified or 'none'"),
    ("tools/network_dpi_policy.py", "[item]"),
    ("tools/network_dpi_policy.py", "not_attempted + ids[index + 1:] or 'none'"),
    ("_catalog_audit.py", "item"),  # Local catalog snapshot, not an upstream response.
    ("tools/network_controller_admin.py", "body.get('cmd')"),  # Caller command selector.
    ("tools/site_config.py", "record['_id']"),  # Validated native id before body comparison.
    ("tools/device_mgmt.py", "resolved"),  # Device id string, validate_id() checked first.
    # Proven scalar/caller values discovered by the stronger field-flow guard.
    ("transport_security.py", "digits"),  # length_digits admits only ASCII decimal digits.
    ("request_policy.py", "header"),  # Three server-defined policy header constants.
    ("policy.py", "names"),  # Operator environment setting names.
    ("policy.py", "', '.join(unknown)"),  # Operator environment setting names.
    ("tools/_pagination.py", "name"),  # Caller's argument name from names.
    ("tools/_pagination.py", "named['page']"),
    ("tools/_pagination.py", "named['zero_page']"),
    ("tools/_pagination.py", "named['offset']"),
    ("tools/network_nat_qos_traffic.py", "number"),  # Integer page counter.
    # Positions and argument names this server computes, not upstream values.
    ("api_sources.py", "str(i)"),  # Index into the operator's selector list.
    ("client.py", "first"),  # Index of the first non-object item.
    ("tools/clients.py", "name"),  # The argument's own name (client_id).
    # Caller input echoed back, not an upstream record.
    ("tools/device_mgmt.py", "tag['_id']"),  # Caller's tag body _id.
    ("tools/device_mgmt.py", "e['mac']"),  # Caller's MAC, colon-normalized.
    ("tools/device_radios.py", "fields['channel']"),  # Caller's radio channel.
    ("tools/device_radios.py", "str(channel)"),  # Caller's channel, normalized.
    ("tools/device_radios.py", "fields['ht']"),  # Caller's channel width.
    ("tools/device_radios.py", "power"),  # Caller's tx_power.
    ("tools/network_mobile_wan.py", "repr(k)"),  # Typed argument names found in the body.
    ("tools/network_vpn_dns.py", "repr(m)"),  # Caller's WireGuard user refs.
    ("tools/protect.py", "txn_type"),  # Caller's POS transaction type.
    ("tools/protect.py", "amount"),  # Caller's POS transaction amount.
    ("tools/protect_ptz_doorbell.py", "missing[0]"),  # Caller's shortcut id.
    ("tools/protect_ptz_doorbell.py", "kind"),  # Caller's shortcut type, one of three names.
    ("tools/site_config.py", "given"),  # Caller's body _id.
    # The caller's id, rebound later to the upstream id only when that is a string equal to it.
    ("tools/carrier_fabric.py", "subscriber_id"),
    # Text already rendered through upstream_error_text where it was recorded.
    ("tools/device_mgmt.py", "e['error']"),  # str() of an error whose body was rendered.
    ("tools/site_manager.py", "entry['error']"),  # upstream_error_text(exc, client).
    # Not upstream values: names this server or its operator chose, and integers.
    ("catalog.py", "sorted(unknown)"),  # Tool names of a C fixture overlay.
    ("policy.py", "canonical"),  # An environment variable name, upper-cased.
    ("tools/device_radios.py", "sorted(widths)"),  # Integer MHz widths (int-checked).
    ("tools/innerspace.py", "sorted(project)"),  # Document key names, never their values.
    # Per-site error text rendered through upstream_error_text where it was recorded.
    ("tools/aggregation.py", "'; '.join(errors + site_errors)"),
}
#: Modules whose errors format caller arguments, the published OpenAPI documents or the
#: server's own catalog, never a controller response.
NON_UPSTREAM_MODULES = {
    "argument_errors.py",  # Pydantic validation of the caller's arguments.
    "spec_limits.py",  # Caller's arguments against the published spec limits.
    "write_body.py",  # Caller's write bodies.
    "_spec_drift.py",  # Published OpenAPI documents.
    "_catalog_audit.py",  # The server's own tool catalog.
}
UPSTREAM_NAMES = {
    "item",
    "row",
    "r",
    "native_id",
    "body",
    "record",
    "response",
    "decoded",
    "data",
    "identifying",
    "resolved",
    "read_after",
    "after",
    "before",
}


#: Helpers that render upstream evidence through the opt-in credential masking.
SANITIZERS = {"upstream_error_text", "upstream_error_value", "error_body_text"}
#: Calls that render their argument verbatim: an upstream value passed to one is raw.
SERIALIZERS = {"repr", "str", "ascii", "format", "dumps"}
#: Calls whose result holds their arguments' values as is (``sorted(r['id'] for r in rows)``).
PASSTHROUGH = {"sorted", "list", "tuple", "set", "frozenset", "reversed", "id_key"}
#: String methods whose result is still the upstream text.
STRING_METHODS = {"lower", "upper", "casefold", "strip", "lstrip", "rstrip", "title"}
#: Keys whose value is an HTTP status integer, never a body.
STATUS_KEYS = {"status", "status_code"}


def _call_name(node):
    func = node.func
    return func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)


def _sanitized(call):
    return isinstance(call, ast.Call) and _call_name(call) in SANITIZERS


def _status_key(node):
    return isinstance(node, ast.Constant) and node.value in STATUS_KEYS


def _clean_names(function):
    """Upstream-named locals of ``function`` that only ever hold a sanitizer's output."""
    args = function.args
    params = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    params |= {a.arg for a in (args.vararg, args.kwarg) if a is not None}
    assigned: dict[str, bool] = {}
    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign | ast.NamedExpr):
            targets, value = [node.target], node.value
        elif isinstance(node, ast.AugAssign):
            targets, value = [node.target], None  # Appends to the old value.
        elif isinstance(node, ast.For | ast.AsyncFor | ast.comprehension):
            targets, value = [node.target], None
        elif isinstance(node, ast.With | ast.AsyncWith):
            targets = [item.optional_vars for item in node.items if item.optional_vars]
            value = None
        else:
            continue
        for target in targets:
            for name in ast.walk(target):
                if isinstance(name, ast.Name):
                    safe = isinstance(target, ast.Name) and _sanitized(value)
                    assigned[name.id] = assigned.get(name.id, True) and safe
    return {name for name, safe in assigned.items() if safe and name not in params}


_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _own_nodes(scope):
    """The nodes of ``scope`` outside its nested functions (whose bodies are their own)."""
    for child in ast.iter_child_nodes(scope):
        if isinstance(child, _FUNCTIONS):
            yield from child.decorator_list  # Decorators run in the enclosing scope.
            continue
        yield child
        yield from _own_nodes(child)


def _unsanitized_nodes(node, text=False):
    """``node`` and its descendants that can reach message text: not a sanitizer's
    arguments, and not a comparison or a comprehension filter (they yield a bool).
    With ``text``, not a comprehension's iterable either: only its element is text."""
    yield node
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.Compare) or _sanitized(child):
            continue
        if isinstance(node, ast.comprehension) and (
            child in node.ifs or (text and child is node.iter)
        ):
            continue
        yield from _unsanitized_nodes(child, text)


def _names_in(node):
    return {n.id for n in _unsanitized_nodes(node) if isinstance(n, ast.Name)}


def _empty_container(node):
    if isinstance(node, ast.List | ast.Set):
        return not node.elts
    if isinstance(node, ast.Dict):
        return not node.keys
    return (
        isinstance(node, ast.Call) and _call_name(node) in {"list", "dict", "set"} and not node.args
    )


def _bindings(scope):
    """``(targets, value or None, iterated expression or None)`` of each binding."""
    nodes = list(_own_nodes(scope))
    empty = {
        target.id
        for node in nodes
        if isinstance(node, ast.Assign | ast.AnnAssign) and _empty_container(node.value)
        for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
        if isinstance(target, ast.Name)
    }
    for node in nodes:
        if isinstance(node, ast.Assign):
            yield node.targets, node.value, None
        elif isinstance(node, ast.AnnAssign | ast.NamedExpr | ast.AugAssign):
            yield [node.target], node.value, None  # AugAssign adds to the old value.
        elif isinstance(node, ast.For | ast.AsyncFor | ast.comprehension):
            target, iterated = node.target, node.iter
            if (
                isinstance(iterated, ast.Call)
                and _call_name(iterated) == "enumerate"
                and isinstance(target, ast.Tuple)
                and target.elts
            ):
                # ``for index, row in enumerate(rows)``: the index is a position.
                target = ast.Tuple(elts=target.elts[1:], ctx=ast.Store())
            yield [target], None, iterated
        elif isinstance(node, ast.With | ast.AsyncWith):
            yield [i.optional_vars for i in node.items if i.optional_vars], None, None
        elif isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in {"append", "extend", "insert", "add", "setdefault", "update"}
                and isinstance(func.value, ast.Name)
            ):
                # ``out.append(f"...")`` builds ``out`` from its argument.
                yield [func.value], ast.Tuple(elts=list(node.args), ctx=ast.Load()), None
            if _reads_only(node):
                continue
            for arg in (k.value for k in node.keywords):
                if isinstance(arg, ast.Name) and arg.id in empty:
                    # ``helper(..., skipped=skipped)`` fills an empty local list with
                    # records (here: upstream hosts and sites with their reasons). A
                    # positional list (``report_keys(result, labels, errors)``) is read.
                    yield [arg], None, ast.Name(id="data", ctx=ast.Load())


#: Builtins that read their arguments and never fill a list handed to them.
READERS = {"len", "any", "all", "bool", "enumerate", "zip", "isinstance", "min", "max", "sum"}


def _reads_only(call):
    """Whether ``call`` only reads its arguments (``"; ".join(problems)``, ``len(out)``)."""
    if isinstance(call.func, ast.Attribute) and call.func.attr == "join":
        return True
    return _call_name(call) in READERS | PASSTHROUGH | SERIALIZERS | SANITIZERS


def _target_names(target):
    return [n.id for n in ast.walk(target) if isinstance(n, ast.Name)]


class _Scope:
    """Taint of one function: which locals hold upstream records, values or message text.

    * ``rows``: names whose fields (``x.get(k)``, ``x[k]``) are upstream values: the
      upstream names, the parameters (records handed to a helper), every local derived
      from them and every loop or comprehension target iterating one of them.
    * ``whole``: names whose own value is upstream (formatted as is it leaks): the
      upstream names, a local assigned a raw upstream value (``label = r.get('name')``),
      and a target iterating upstream data that did not come in as a parameter.
    * ``text``: locals holding message text that formats raw upstream values, mapped to
      the raw expressions (``valid = "; ".join(f"{r.get('name')}" for r in rows)``).
    """

    def __init__(self, scope, helpers, outer=None, raw_helpers=frozenset(), *, raw_params=False):
        self.helpers = helpers
        self.raw_helpers = raw_helpers
        self.clean = _clean_names(scope) if not isinstance(scope, ast.Module) else set()
        params = set()
        if not isinstance(scope, ast.Module):
            args = scope.args
            params = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
            params |= {a.arg for a in (args.vararg, args.kwarg) if a is not None}
        inherited_rows = outer.rows if outer else set()
        inherited_whole = outer.whole if outer else set()
        upstream = UPSTREAM_NAMES - self.clean
        derived = set(upstream) | (inherited_whole - params)
        if raw_params:
            derived |= params
        self.rows = derived | params | (inherited_rows - params)
        self.whole = set(derived)
        self.text: dict[str, list[ast.expr]] = dict(outer.text) if outer else {}
        bindings = list(_bindings(scope))
        changed = True
        while changed:
            changed = False
            for targets, value, iterated in bindings:
                names = [n for t in targets for n in _target_names(t)]
                new_rows = new_whole = False
                if iterated is not None:
                    source = _names_in(iterated)
                    new_rows = bool(source & self.rows) or self._raw(iterated)
                    new_whole = bool(source & derived) or self._raw(iterated)
                elif value is not None:
                    source = _names_in(value)
                    new_rows = bool(source & self.rows)
                    fresh = {n for n in names if n not in self.clean} - derived
                    if source & derived and fresh:
                        derived.update(fresh)
                        changed = True
                    new_whole = self._raw(value)
                    found = list(self.unsafe(value))
                    for name in names:
                        if found and name not in self.clean:
                            known = self.text.setdefault(name, [])
                            extra = [f for f in found if f not in known]
                            if extra:
                                known.extend(extra)
                                changed = True
                for name in names:
                    if name in self.clean:
                        continue
                    if new_rows and name not in self.rows:
                        self.rows.add(name)
                        changed = True
                    if new_whole and name not in self.whole:
                        self.whole.add(name)
                        changed = True

    def _record(self, node):
        """Whether ``node`` is an upstream record (or collection) whose fields are upstream."""
        if isinstance(node, ast.Name):
            return node.id in self.rows and node.id not in self.clean
        return self._raw(node)

    def _raw(self, node):
        """Whether ``node`` evaluates to (part of) an upstream value no helper rendered."""
        if isinstance(node, ast.Name):
            return node.id in self.whole and node.id not in self.clean
        if isinstance(node, ast.Subscript):
            if _status_key(node.slice) or isinstance(node.slice, ast.Slice):
                return False
            return self._record(node.value)
        if isinstance(node, ast.Attribute):
            return self._raw(node.value)
        if isinstance(node, ast.Call):
            if _sanitized(node):
                return False
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                return not (node.args and _status_key(node.args[0])) and self._record(
                    node.func.value
                )
            if _call_name(node) == "context_value":
                return bool(node.args) and self._record(node.args[0])
            if _call_name(node) in SERIALIZERS | PASSTHROUGH:
                return any(self._raw(arg) for arg in node.args)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
                return any(self._raw(arg) for arg in node.args)  # ``", ".join(names)``.
            if isinstance(node.func, ast.Attribute) and node.func.attr in STRING_METHODS:
                return self._raw(node.func.value)  # ``r.get('name').lower()``.
            if isinstance(node.func, ast.Name) and node.func.id in self.raw_helpers:
                return any(
                    (self._record(arg) if self.raw_helpers[node.func.id] else self._raw(arg))
                    for arg in node.args
                )
            return False  # Any other helper derives text (a shape, a label) from the value.
        if isinstance(node, ast.IfExp):  # The condition only picks a branch.
            return self._raw(node.body) or self._raw(node.orelse)
        if isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp):
            return self._raw(node.elt)  # Its targets over upstream rows are rows already.
        if isinstance(node, ast.DictComp):
            return self._raw(node.key) or self._raw(node.value)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self._raw(elt) for elt in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._raw(part) for part in (*node.keys, *node.values) if part)
        if isinstance(node, ast.BoolOp | ast.BinOp | ast.Starred):
            return any(self._raw(child) for child in ast.iter_child_nodes(node))
        return False

    def unsafe(self, node):
        """The raw upstream expression nodes message text built from ``node`` carries."""
        covered: set[int] = set()  # Inside an expression already reported.
        for found in self._unsafe(node):
            if id(found) not in covered:
                covered.update(id(part) for part in ast.walk(found))
                yield found

    def _unsafe(self, node):
        for value in _unsanitized_nodes(node, text=True):
            if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
                # ``"valid: " + name``: each operand is message text as is.
                for part in (value.left, value.right):
                    if not isinstance(part, ast.BinOp) and self._raw(part):
                        yield part
            elif (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and value.func.attr == "join"
                and self._raw(value)
            ):
                yield value  # ``", ".join(r.get('name') for r in rows)``.
            elif isinstance(value, ast.FormattedValue):
                if self._raw(value.value):
                    yield value.value
            elif (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and value.func.attr == "format"
            ):
                yield from (
                    part
                    for part in [*value.args, *(k.value for k in value.keywords)]
                    if self._raw(part)
                )
            elif isinstance(value, ast.Call) and _call_name(value) in SERIALIZERS:
                if self._raw(value):
                    yield value
            elif (
                isinstance(value, ast.BinOp)
                and isinstance(value.op, ast.Mod)
                and isinstance(value.left, ast.Constant)
                and isinstance(value.left.value, str)
            ):
                parts = value.right.elts if isinstance(value.right, ast.Tuple) else [value.right]
                yield from (p for p in parts if self._raw(p))
            elif isinstance(value, ast.Name) and value.id in self.text:
                yield from self.text[value.id]
            elif isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
                yield from self.helpers.get(value.func.id, ())


def _functions(tree):
    """Every function with its enclosing function (``None`` at module level), outer first."""

    def visit(node, outer):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, _FUNCTIONS):
                yield child, outer
                yield from visit(child, child)
            else:
                yield from visit(child, outer)

    return list(visit(tree, None))


def _returns_text(function):
    """Whether ``function`` is annotated to return message text or an error to raise
    (``-> str | None``, ``-> ValueError``)."""

    def text(node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return text(node.left) or text(node.right)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return text(ast.parse(node.value, mode="eval").body)
        return isinstance(node, ast.Name) and (
            node.id == "str" or node.id.endswith(("Error", "Exception"))
        )

    return function.returns is not None and text(function.returns)


def unsafe_upstream_nodes(source):
    """Upstream evidence (expression nodes) a raised message formats unmasked.

    Flags an f-string part that repr()s an upstream name (``{record!r}``), and an
    upstream value rendered raw by plain formatting (``{body}``, ``{record.get('name')}``),
    ``json.dumps``/``repr``/``str`` or ``%`` (inside or outside an f-string). The message
    is followed from the ``raise`` through the locals it formats (``valid = "; ".join(...)``)
    and the same-module ``-> str`` helpers whose return it formats
    (``_describe_sites(sites)``), and a
    record's fields are upstream when the record is an upstream name, a parameter or a
    loop or comprehension target over one. A value a helper derives text from
    (``describe_shape(body)``), an HTTP status, and a local that only ever holds a
    sanitizer's output are not evidence.
    """
    tree = ast.parse(source)
    nested = list(_functions(tree))
    helpers: dict[str, list[ast.expr]] = {}
    raw_helpers: dict[str, bool] = {}
    # A helper's message can come from another helper: iterate to a fixed point.
    scopes = {}
    for _ in range(len(nested) + 1):
        before = ({k: list(v) for k, v in helpers.items()}, dict(raw_helpers))
        scopes = {}
        for function, outer in nested:
            scope = _Scope(function, helpers, scopes.get(outer), raw_helpers)
            scopes[function] = scope
            returns = [
                node.value
                for node in _own_nodes(function)
                if isinstance(node, ast.Return) and node.value is not None
            ]
            raw_scope = _Scope(function, helpers, scopes.get(outer), raw_helpers, raw_params=True)
            if any(raw_scope._raw(value) for value in returns):
                # Field readers accept records; pure passthrough helpers only carry
                # taint when the argument itself is raw (a caller path is not a row).
                raw_helpers[function.name] = any(
                    isinstance(n, ast.Subscript)
                    or (
                        isinstance(n, ast.Call)
                        and isinstance(n.func, ast.Attribute)
                        and n.func.attr == "get"
                    )
                    or (
                        isinstance(n, ast.Call)
                        and isinstance(n.func, ast.Name)
                        and raw_helpers.get(n.func.id, False)
                    )
                    for n in _own_nodes(function)
                )
            if not _returns_text(function):
                continue
            found = []
            for node in _own_nodes(function):
                if isinstance(node, ast.Return) and node.value is not None:
                    found.extend(f for f in scope.unsafe(node.value) if f not in found)
            if found:
                known = helpers.setdefault(function.name, [])
                known.extend(f for f in found if f not in known)
        if (helpers, raw_helpers) == before:
            break  # These scopes saw the final helpers.
    scopes[None] = _Scope(tree, helpers, None, raw_helpers)
    seen = []
    for function, scope in scopes.items():
        for node in _own_nodes(function if function is not None else tree):
            if isinstance(node, ast.Raise) and node.exc is not None:
                for found in scope.unsafe(node.exc):
                    if found not in seen:
                        seen.append(found)
                        yield found


def unsafe_upstream_reprs(source):
    """The source text of each :func:`unsafe_upstream_nodes` expression, once."""
    seen = set()
    for node in unsafe_upstream_nodes(source):
        text = ast.unparse(node)
        if text not in seen:
            seen.add(text)
            yield text


def test_no_raises_repr_upstream_records():
    root = Path(__file__).resolve().parents[1] / "src/unifi_fabric"
    failures = []
    for path in root.rglob("*.py"):
        if path.relative_to(root).as_posix() in NON_UPSTREAM_MODULES:
            continue
        for expression in unsafe_upstream_reprs(path.read_text()):
            entry = (path.relative_to(root).as_posix(), expression)
            if entry not in REPR_ALLOWLIST:
                failures.append(entry)
    assert not failures, f"Use upstream_error_value for upstream evidence: {failures}"


def test_guard_detects_new_raise():
    assert list(unsafe_upstream_reprs("raise ValueError(f\"unexpected {item.get('name')}\")"))
    assert list(unsafe_upstream_reprs("raise ValueError(f\"unexpected {row.get('name')}\")"))
    assert list(unsafe_upstream_reprs('raise ValueError(f"unexpected {record!r}")')) == ["record"]
    assert not list(
        unsafe_upstream_reprs('raise ValueError(f"unexpected {upstream_error_text(record)!r}")')
    )


@pytest.mark.parametrize(
    "source",
    [
        "raise E(f\"HTTP: {json.dumps(response.get('body'), separators=(',', ':'))}\")",
        'raise E(f"unexpected {record}")',
        "raise E(f\"unexpected {body['data']}\")",
        'raise E(f"unexpected {str(decoded)}")',
        'raise E("unexpected " + json.dumps(body))',
        'raise E("unexpected %s" % repr(data))',
        'def f(body):\n    raise E(f"{body}")',
        'def f(resp):\n    body = resp.text\n    raise E(f"{body}")',
    ],
)
def test_guard_detects_plain_and_serialized_upstream_text(source):
    assert list(unsafe_upstream_reprs(source))


@pytest.mark.parametrize(
    "source",
    [
        "raise E(f\"HTTP {response.get('status')}: {upstream_error_text(response, c)}\")",
        'raise E(f"got {describe_shape(body)}")',
        'raise E(f"got {type(response).__name__}")',
        'raise E(f"got {upstream_error_text(json.dumps(body), c)}")',
        "raise E(f\"got {upstream_error_value(record.get('name'))!r}\")",
        "def f(resp):\n    body = error_body_text(resp.text, redact_secrets=True)\n"
        '    raise E(f"{body}")',
    ],
)
def test_guard_accepts_rendered_upstream_text(source):
    assert not list(unsafe_upstream_reprs(source))


def test_guard_flags_raw_protect_listing_error():
    """The pre-fix Protect listing error (raw ``json.dumps`` of the body) is caught."""
    source = (
        "async def _resolve(client, registry, host, collection, ref):\n"
        "    response = await connector.connector_get(client, registry, host, collection)\n"
        "    if response.get('status') != 200:\n"
        "        raise UniFiConnectionError(\n"
        "            f\"GET protect/api/{collection}: HTTP {response.get('status')}: \"\n"
        "            f\"{json.dumps(response.get('body'), separators=(',', ':'))}\"\n"
        "        )\n"
    )
    assert list(unsafe_upstream_reprs(source)) == [
        "json.dumps(response.get('body'), separators=(',', ':'))"
    ]


@pytest.mark.parametrize(
    "source",
    [
        # Message text built in a local first, from a comprehension over upstream rows.
        "def pick(result, wanted):\n"
        "    records = _object_rows(result.get('data'), 'VPN server')\n"
        "    valid = ', '.join(f\"{r.get('name')} ({r.get('id')})\" for r in records)\n"
        "    raise ValueError(f'{wanted!r} not found; valid: {valid}')\n",
        # A row field bound to a local, then formatted.
        "def choices(records):\n"
        "    out = []\n"
        "    for r in records:\n"
        "        label = r.get('name') or '(unnamed)'\n"
        "        out.append(f'{label} (mac={r.get(\"mac\")})')\n"
        "    raise ValueError('; '.join(out))\n",
        # A same-module helper returning the listing text.
        "def _describe(sites: list) -> str:\n"
        "    return '; '.join(f\"{s.get('desc')!r}\" for s in sites)\n"
        "def select(sites, wanted):\n"
        "    raise ValueError(f'{wanted!r} not found; valid: {_describe(sites)}')\n",
        # A helper returning the error to raise.
        "def _unknown(rows) -> ValueError:\n"
        "    return ValueError(f\"valid: {[r['id'] for r in rows]} {rows[0]['name']}\")\n"
        "def select(rows):\n"
        "    raise _unknown(rows)\n",
        # An empty list a helper fills with upstream records.
        "def run(registry):\n"
        "    skipped = []\n"
        "    scan(registry, skipped=skipped)\n"
        "    reasons = '; '.join(f\"{s['hostName']}: {s.get('reason')}\" for s in skipped)\n"
        "    raise RuntimeError(reasons)\n",
        "raise E('valid: %s' % record.get('name'))",
        # Upstream values reaching the message without an f-string.
        "def f(rows):\n    raise E('valid: ' + ', '.join(r.get('name') for r in rows))\n",
        "def f(record):\n    raise E('unknown ' + record.get('name'))\n",
        "def f(rows):\n    raise E(', '.join(sorted(r['id'] for r in rows)))\n",
        "def f(rows):\n    valid = ', '.join(r['name'] for r in rows)\n"
        "    raise E(f'valid: {valid}')\n",
        # A list of upstream fields formatted whole, bound first or inline.
        "def f(rows):\n    ids = [g.get('id') for g in rows]\n    raise E(f'valid: {ids}')\n",
        "def f(rows):\n    raise E(f\"valid: {[r.get('name') for r in rows]}\")\n",
        "def f(rows):\n    raise E(f\"valid: {sorted(r['name'].lower() for r in rows)}\")\n",
    ],
)
def test_guard_follows_message_text_to_its_upstream_fields(source):
    assert list(unsafe_upstream_reprs(source))


@pytest.mark.parametrize(
    "source",
    [
        "def pick(result, wanted):\n"
        "    records = _object_rows(result.get('data'), 'VPN server')\n"
        "    valid = ', '.join(\n"
        "        f\"{upstream_error_value(r.get('name'))} ({upstream_error_value(r.get('id'))})\"\n"
        "        for r in records\n"
        "    )\n"
        "    raise ValueError(f'{wanted!r} not found; valid: {valid}')\n",
        # Positions, comparisons and filters carry no upstream text.
        "def check(rows):\n"
        "    bad = [i for i, row in enumerate(rows) if row.get('x') != 1]\n"
        "    raise ValueError(f'rows {bad} are wrong')\n",
        "def check(rows, refs):\n"
        "    by_id = {str(r.get('_id')): r for r in rows}\n"
        "    missing = [ref for ref in refs if ref not in by_id]\n"
        "    raise ValueError(f'{missing} not found')\n",
        # A helper that returns a record (not message text) is not message text.
        "def fetch(site) -> dict:\n"
        "    slug = site.get('internalReference')\n"
        "    return {'url': f'/s/{slug}'}\n"
        "def run(site):\n"
        "    raise ValueError(f'failed: {fetch(site)[\"status\"]}')\n",
        # Server-built text lists, read (not filled) by the helpers they are passed to.
        "def f(config):\n    problems = []\n    problems.append(check(config))\n"
        "    raise ValueError('; '.join(problems))\n",
        "def f(rows, labels):\n    errors = []\n    errors.append(key_error(labels[0], 'x'))\n"
        "    report_keys(rows, labels, errors)\n    raise RuntimeError('; '.join(errors))\n",
        # The iterable of a comprehension is not message text; only its element is.
        "def f(record, a, b):\n"
        "    raise E('; '.join(upstream_error_value(e['reason']) for e in a + b))\n",
        "def f(rows):\n"
        "    ids = [upstream_error_value(g.get('id')) for g in rows]\n"
        "    raise E(f'valid: {ids}')\n",
    ],
)
def test_guard_accepts_masked_or_derived_message_text(source):
    assert not list(unsafe_upstream_reprs(source))


SECRET_OBJECT = {"x_passphrase": SENTINEL}
ROW_FIELDS = (
    "name",
    "desc",
    "description",
    "hostname",
    "mac",
    "_id",
    "id",
    "external_id",
    "model",
    "purpose",
    "end",
    "expired",
    "internalReference",
)


def _listing_rows(value):
    return [{field: value for field in ROW_FIELDS}, {field: value for field in ROW_FIELDS}]


@pytest.mark.parametrize("value", [SECRET_OBJECT, json.dumps(SECRET_OBJECT)])
@pytest.mark.parametrize(
    "render",
    [
        pytest.param(
            lambda rows: vpn._select_by_id(
                {"data": rows}, "zzz", "VPN server", "list_vpn_servers", "VPN server"
            ),
            id="vpn-select-by-id",
        ),
        pytest.param(lambda rows: network_wifi_radio._select_wan(rows, None), id="wifi-wan"),
        pytest.param(site_admin._describe_sites, id="site-admin-sites"),
        pytest.param(statistics._valid_choices, id="statistics-choices"),
        pytest.param(lambda rows: clients._describe_clients(rows, None), id="clients"),
        pytest.param(lambda rows: client_records._describe_users(rows, None), id="known-clients"),
        pytest.param(lambda rows: client_records._describe_guests(rows, None), id="guests"),
        pytest.param(lambda rows: network_device_operations._device_label(rows[0]), id="device"),
        pytest.param(
            lambda rows: site_config._valid_config_records(rows, site_config.USER_GROUPS),
            id="site-config",
        ),
        pytest.param(
            lambda rows: site_manager._console_site_choices(None, "synthetic", None, rows),
            id="console-sites",
        ),
        pytest.param(
            lambda rows: innerspace_internal._select_plan(rows, "zzz", "synthetic"),
            id="innerspace-plans",
        ),
    ],
)
def test_not_found_listings_mask_credential_fields(monkeypatch, render, value):
    """Every listing an unknown-id error carries renders upstream fields masked."""
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1")
    try:
        text = render(_listing_rows(value))
    except ValueError as exc:
        text = str(exc)
    assert SENTINEL not in text
    assert "REDACTED" in text


def test_not_found_listing_plain_values_render_as_before():
    """Scalar names and ids keep their exact rendering in the Integration listing."""
    rows = [{"name": "Office VPN", "id": "aaa"}, {"name": None, "id": "bbb"}]
    with pytest.raises(ValueError) as caught:
        vpn._select_by_id({"data": rows}, "zzz", "VPN server", "list_vpn_servers", "VPN server")
    assert "valid: Office VPN (aaa), None (bbb)." in str(caught.value)


@pytest.mark.parametrize("site", ["missing-mac", "identity-changed"])
async def test_radio_write_error_sites(rig, monkeypatch, site):
    client, calls, state = rig
    first = {"_id": "synthetic-device", "password": SENTINEL}
    if site == "identity-changed":
        first["mac"] = "02:00:5e:00:00:a1"
    state["body"] = {"meta": {"rc": "ok"}, "data": [first]}
    monkeypatch.setattr(
        device_radios,
        "resolve_site_slug",
        AsyncMock(return_value=(None, "synthetic-host", "default")),
    )
    monkeypatch.setattr(
        device_radios, "_read_device", AsyncMock(return_value=({}, {"_id": PAYLOAD}))
    )
    with pytest.raises((ValueError, client_module.UniFiConnectionError)) as caught:
        await device_radios._update_device_radio(
            client,
            AsyncMock(),
            "synthetic-host",
            "default",
            "synthetic-device",
            {"na": {"channel": 44}},
        )
    assert calls
    assert SENTINEL not in str(caught.value)
    assert "REDACTED" in str(caught.value)


@pytest.mark.parametrize("status", [400, 200])
async def test_client_error_envelopes(rig, monkeypatch, status):
    client, calls, state = rig
    state["body"] = {"meta": {"rc": "error", "msg": PAYLOAD}, "data": PAYLOAD}
    if status == 400:
        transport_client = await client._get_client(None)
        transport_client._transport = httpx.MockTransport(
            lambda request: httpx.Response(400, json=state["body"])
        )
    with pytest.raises(client_module.UniFiConnectionError) as caught:
        await client.get("/v1/connector/consoles/synthetic/proxy/network/api/s/default/stat/device")
    assert SENTINEL not in str(caught.value)
    assert "REDACTED" in str(caught.value)


def test_per_key_error_masks_exception_body(monkeypatch):
    """A failed key's ``errors`` entry renders the exception's response body masked."""
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1")
    exc = client_module.UniFiConnectionError(f"GET /v1/hosts: HTTP 500 {json.dumps(SECRET_OBJECT)}")
    text = _keys.key_error("primary", exc)
    assert text.startswith("primary: GET /v1/hosts: HTTP 500 ")
    assert SENTINEL not in text
    assert "REDACTED" in text
    assert _keys.key_error("primary", "plain reason") == "primary: plain reason"


@pytest.mark.parametrize("prefix", ["", "it's", 'a"b'])
async def test_registry_renderings_mask_json_strings(monkeypatch, prefix):
    from unifi_fabric.registry import (
        Registry,
        _describe_host,
        _match_proxy_site,
        _valid_site_choices,
        match_ea_site,
        valid_host_choices,
    )

    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1")
    secret = json.dumps({"password": prefix + SENTINEL})
    assert SENTINEL not in _describe_host({"id": secret, "reportedState": {"hostname": secret}})
    assert SENTINEL not in _valid_site_choices(
        [{"id": secret, "description": secret, "name": "Office"}]
    )
    assert SENTINEL not in valid_host_choices(
        [{"id": secret, "name": secret, "reportedState": {"hostname": "console", "name": secret}}]
    )
    registry = Registry.__new__(Registry)
    registry.get_sites = AsyncMock(
        return_value=[{"id": secret, "description": secret, "name": "Office"}]
    )
    with pytest.raises(ValueError) as not_found:
        await registry.resolve_site_id("missing", "synthetic-host")
    assert SENTINEL not in str(not_found.value)
    assert "REDACTED" in str(not_found.value)
    with pytest.raises(ValueError) as proxy_error:
        _match_proxy_site([{"id": secret, "name": "same"}, {"id": "other", "name": "same"}], "same")
    assert SENTINEL not in str(proxy_error.value)
    with pytest.raises(ValueError) as ea_error:
        match_ea_site(
            [
                {"siteId": secret, "hostId": secret, "meta": {"name": "same"}},
                {"siteId": "other", "meta": {"name": "same"}},
            ],
            "same",
            partial=[],
            max_pages=None,
        )
    assert SENTINEL not in str(ea_error.value)
    with pytest.raises(ValueError) as missing:
        match_ea_site(
            [{"siteId": "other", "meta": {"name": secret}}], "missing", partial=[], max_pages=None
        )
    assert SENTINEL not in str(missing.value)


@pytest.mark.parametrize("method", ["setdefault", "update"])
@pytest.mark.parametrize("style", ["fstring", "percent", "format", "repr"])
def test_guard_tracks_passthrough_and_mutated_dicts(method, style):
    messages = {
        "fstring": "f\"{_text(row.get('name'))!r}\"",
        "percent": '"%s" % _text(row.get("name"))',
        "format": '"{}".format(_text(row.get("name")))',
        "repr": 'repr(_text(row.get("name")))',
    }
    mutation = (
        'found.setdefault(site["id"], site)'
        if method == "setdefault"
        else 'found.update({site["id"]: site})'
    )
    source = (
        "def _text(value):\n"
        "    if isinstance(value, str):\n"
        "        return value\n"
        "    return ''\n"
        "def select(sites):\n"
        "    found = {}\n"
        "    for site in sites:\n"
        f"        {mutation}\n"
        "    for row in found.values():\n"
        f"        raise ValueError({messages[style]})\n"
    )
    assert list(unsafe_upstream_reprs(source))


def test_guard_does_not_hide_raw_sibling_of_sanitizer():
    source = "raise E(f\"{upstream_error_value(record.get('name')) + record.get('id')}\")"
    assert list(unsafe_upstream_reprs(source))


async def test_client_resolution_masks_invalid_upstream_id(rig, monkeypatch):
    client, _, _ = rig
    rows = [{"macAddress": "02:00:5e:00:00:a1", "id": PAYLOAD}]
    monkeypatch.setattr(clients, "collect_offset", AsyncMock(return_value={"items": rows}))
    with pytest.raises(client_module.UniFiConnectionError) as error:
        await clients._resolve_client(client, "host", "site", "02:00:5e:00:00:a1", None)
    assert SENTINEL not in str(error.value)
    assert "REDACTED" in str(error.value)


async def test_matter_resolution_masks_invalid_upstream_id(rig, monkeypatch):
    client, _, _ = rig
    rows = [{"_id": "target", "id": PAYLOAD}]
    monkeypatch.setattr(matter, "_list", AsyncMock(return_value={"data": rows}))
    with pytest.raises(ValueError) as error:
        await matter._matter_node_id(client, "/synthetic", None, "target")
    assert SENTINEL not in str(error.value)
    assert "REDACTED" in str(error.value)


async def test_known_client_resolution_masks_upstream_fields(rig, monkeypatch):
    client, _, _ = rig
    monkeypatch.setattr(
        site_config, "resolve_site_slug", AsyncMock(return_value=(None, "host", "site"))
    )
    monkeypatch.setattr(
        site_config,
        "_config_rows",
        AsyncMock(side_effect=[({}, [{}]), ({}, [{"_id": "other", "name": PAYLOAD}])]),
    )
    monkeypatch.setattr(site_config, "_select_config_record", lambda *args, **kwargs: {})
    with pytest.raises(ValueError) as error:
        await site_config._set_client_user_group(client, None, "host", "site", "missing", "group")
    assert SENTINEL not in str(error.value)
    assert "REDACTED" in str(error.value)


def test_device_wrapper_masks_upstream_host_id(monkeypatch):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1")
    with pytest.raises(client_module.UniFiConnectionError) as error:
        _device_wrappers.wrapper_devices({"hostId": PAYLOAD, "devices": 1})
    assert SENTINEL not in str(error.value)
    assert "REDACTED" in str(error.value)


@pytest.mark.parametrize("tool", ["rename_matter_node", "remove_matter_node"])
@pytest.mark.parametrize("redact", [True, False])
async def test_mcp_matter_json_native_id_validation(rig, monkeypatch, tool, redact):
    client, calls, state = rig
    client._settings.redact_secrets = redact
    monkeypatch.setattr(server, "_settings", client._settings)
    state["body"] = [{"_id": "target", "id": json.dumps(PAYLOAD)}]
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "host"
    registry.resolve_site_slug.return_value = "default"
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", registry)
    args = {"host": "host", "site": "default", "node_id": "target"}
    if tool == "rename_matter_node":
        args["name"] = "new name"
    with pytest.raises(Exception) as error:
        await server.mcp.call_tool(tool, args)
    assert (SENTINEL not in str(error.value)) is redact
    assert ("REDACTED" in str(error.value)) is redact
    assert [call.method for call in calls] == ["GET"]


@pytest.mark.parametrize("tool", ["get_client", "execute_client_action"])
@pytest.mark.parametrize("redact", [True, False])
async def test_mcp_client_json_native_id_validation(rig, monkeypatch, tool, redact):
    client, calls, state = rig
    client._settings.redact_secrets = redact
    monkeypatch.setattr(server, "_settings", client._settings)
    state["body"] = {
        "data": [{"macAddress": "02:00:5e:00:00:a1", "id": json.dumps(PAYLOAD)}],
        "totalCount": 1,
    }
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "host"
    registry.resolve_site_id.return_value = "11111111-0000-0000-0000-000000000001"
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", registry)
    args = {"host": "host", "site": "default", "client_id": "02:00:5e:00:00:a1"}
    if tool == "execute_client_action":
        args["action"] = {"action": "UNAUTHORIZE_GUEST_ACCESS"}
    with pytest.raises(Exception) as error:
        await server.mcp.call_tool(tool, args)
    assert (SENTINEL not in str(error.value)) is redact
    assert ("REDACTED" in str(error.value)) is redact
    assert calls and all(call.method == "GET" for call in calls)


@pytest.mark.parametrize("tool", ["authorize_guest", "revoke_guest_access"])
@pytest.mark.parametrize("redact", [True, False])
@pytest.mark.parametrize(
    "reason",
    [
        "synthetic upstream failure",
        "synthetic upstream's failure",
        'synthetic upstream\'s "failure" with \\ slash',
    ],
)
async def test_mcp_guest_json_native_id_validation(rig, monkeypatch, tool, redact, reason):
    client, calls, state = rig
    client._settings.redact_secrets = redact
    monkeypatch.setattr(server, "_settings", client._settings)
    mac = "02:00:5e:00:00:a1"
    state["body"] = {
        "data": [{"macAddress": mac, "id": json.dumps({**PAYLOAD, "reason": reason})}],
        "totalCount": 1,
    }
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "host"
    registry.resolve_site_slug.return_value = "default"
    registry.resolve_site_id.return_value = "11111111-0000-0000-0000-000000000001"
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", registry)
    with pytest.raises(Exception) as error:
        selector = "client" if tool == "authorize_guest" else "guest"
        await server.mcp.call_tool(tool, {"host": "host", "site": "default", selector: mac})
    text = str(error.value)
    assert "not a UUID" in text
    assert "synthetic upstream" in text and "failure" in text
    if not redact:
        assert repr(json.dumps({**PAYLOAD, "reason": reason})) in text
    assert (SENTINEL not in text) is redact
    assert ("REDACTED" in text) is redact
    assert calls and all(call.method == "GET" for call in calls)


@pytest.mark.parametrize("redact", [True, False])
@pytest.mark.parametrize(
    "reason",
    [
        "synthetic upstream failure",
        "synthetic upstream's failure",
        'synthetic upstream\'s "failure" with \\ slash',
    ],
)
async def test_mcp_selected_client_json_native_id_validation(rig, monkeypatch, redact, reason):
    client, calls, state = rig
    client._settings.redact_secrets = redact
    monkeypatch.setattr(server, "_settings", client._settings)
    mac = "02:00:5e:00:00:a1"
    groups = {"meta": {"rc": "ok"}, "data": [{"_id": "group", "name": "test group"}]}
    users = {
        "meta": {"rc": "ok"},
        "data": [
            {"_id": json.dumps({**PAYLOAD, "reason": reason}), "mac": mac, "name": "test client"}
        ],
    }
    transport_client = await client._get_client(None)

    def handle(request):
        calls.append(request)
        body = groups if request.url.path.endswith("/usergroup") else users
        return httpx.Response(200, json=body)

    transport_client._transport = httpx.MockTransport(handle)
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "host"
    registry.resolve_site_slug.return_value = "default"
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", registry)
    with pytest.raises(Exception) as error:
        await server.mcp.call_tool(
            "set_client_user_group",
            {"host": "host", "site": "default", "client": mac, "group": "group"},
        )
    text = str(error.value)
    assert "expected alphanumeric" in text
    assert "Identifying fields" in text
    assert "test client" in text and mac in text
    assert "synthetic upstream" in text and "failure" in text
    if not redact:
        assert repr(json.dumps({**PAYLOAD, "reason": reason})) in text
    assert (SENTINEL not in text) is redact
    assert ("REDACTED" in text) is redact
    assert [call.method for call in calls] == ["GET", "GET"]


@pytest.mark.parametrize("redact", [True, False])
def test_incomplete_listing_reason_respects_redaction_scope(redact):
    from unifi_fabric.redaction import write_redaction_scope
    from unifi_fabric.registry import incomplete_name_error

    reason = f"listing failed: {json.dumps(PAYLOAD)}"
    with write_redaction_scope(redact):
        text = str(incomplete_name_error("Office", "site", [reason], 1, "site_id"))
    assert "listing failed" in text and "synthetic upstream failure" in text
    assert (SENTINEL not in text) is redact
    assert ("REDACTED" in text) is redact
