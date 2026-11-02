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
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.matching import find_by_id
from unifi_fabric.registry import _require_native_id
from unifi_fabric.tools import (
    _classic_cmd,
    _classic_objects,
    _device_config,
    connector,
    device_radios,
    network_controller_admin,
    network_controller_insights,
    network_device_operations,
    network_nat_qos_traffic,
    network_proav_sandbox,
    network_services_proxy,
    protect_private,
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
    ("tools/network_controller_admin.py", "body.get('cmd')"),  # Caller command selector.
    ("tools/site_manager.py", "_ea_slug(record)"),  # _ea_slug returns a string label.
    ("tools/site_manager.py", "context_value(record, '_resolvedSiteId')"),  # Internal resolved id.
    ("tools/site_config.py", "record['_id']"),  # Validated native id before body comparison.
    ("tools/device_mgmt.py", "resolved"),  # Device id string, validate_id() checked first.
}
UPSTREAM_NAMES = {
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
#: Keys whose value is an HTTP status integer, never a body.
STATUS_KEYS = {"status", "status_code"}


def _call_name(node):
    func = node.func
    return func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)


def _sanitized(call):
    return isinstance(call, ast.Call) and _call_name(call) in SANITIZERS


def _status_key(node):
    return isinstance(node, ast.Constant) and node.value in STATUS_KEYS


def _raw_upstream(node, clean):
    """Whether ``node`` evaluates to (part of) an upstream value that no helper rendered."""
    if isinstance(node, ast.Name):
        return node.id in UPSTREAM_NAMES and node.id not in clean
    if isinstance(node, ast.Subscript):
        return not _status_key(node.slice) and _raw_upstream(node.value, clean)
    if isinstance(node, ast.Attribute):
        return _raw_upstream(node.value, clean)
    if isinstance(node, ast.Call):
        if _sanitized(node):
            return False
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            return not (node.args and _status_key(node.args[0])) and _raw_upstream(
                node.func.value, clean
            )
        if _call_name(node) in SERIALIZERS:
            return any(_raw_upstream(arg, clean) for arg in node.args)
        return False  # Any other helper derives text (a shape, a label) from the value.
    if isinstance(node, ast.BoolOp | ast.IfExp | ast.BinOp | ast.Starred):
        return any(_raw_upstream(child, clean) for child in ast.iter_child_nodes(node))
    return False


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


def _scopes(tree):
    """Each raise with the sanitized local names of its innermost enclosing function."""
    stack = [(tree, set())]
    while stack:
        node, clean = stack.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                inner = _clean_names(child) if not isinstance(child, ast.Lambda) else set()
                stack.append((child, inner))
                continue
            if isinstance(child, ast.Raise) and child.exc is not None:
                yield child, clean
            stack.append((child, clean))


def _unsanitized_nodes(node):
    """``node`` and its descendants, not descending into a sanitizer's arguments."""
    yield node
    for child in ast.iter_child_nodes(node):
        if not _sanitized(child):
            yield from _unsanitized_nodes(child)


def unsafe_upstream_reprs(source):
    """Upstream evidence a raise formats without :func:`upstream_error_text`.

    Flags an f-string part that repr()s an upstream name (``{record!r}``), and an
    upstream value rendered raw by plain formatting (``{body}``, ``{record.get('name')}``),
    ``json.dumps``/``repr``/``str`` (inside or outside an f-string). A value a helper
    derives text from (``describe_shape(body)``), an HTTP status, and a local that only
    ever holds a sanitizer's output are not evidence.
    """
    for node, clean in _scopes(ast.parse(source)):
        seen = set()
        for value in _unsanitized_nodes(node.exc):
            expression = None
            if isinstance(value, ast.FormattedValue):
                if any(_sanitized(part) for part in ast.walk(value.value)):
                    continue
                if value.conversion == ord("r"):
                    if any(
                        isinstance(part, ast.Name) and part.id in UPSTREAM_NAMES
                        for part in ast.walk(value.value)
                    ):
                        expression = value.value
                elif _raw_upstream(value.value, clean):
                    expression = value.value
            elif (
                isinstance(value, ast.Call)
                and _call_name(value) in SERIALIZERS
                and _raw_upstream(value, clean)
            ):
                expression = value
            if expression is not None:
                text = ast.unparse(expression)
                if text not in seen:
                    seen.add(text)
                    yield text


def test_no_raises_repr_upstream_records():
    root = Path(__file__).resolve().parents[1] / "src/unifi_fabric"
    failures = []
    for path in root.rglob("*.py"):
        for expression in unsafe_upstream_reprs(path.read_text()):
            entry = (path.relative_to(root).as_posix(), expression)
            if entry not in REPR_ALLOWLIST:
                failures.append(entry)
    assert not failures, f"Use upstream_error_text for upstream evidence: {failures}"


def test_guard_detects_new_raise():
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
