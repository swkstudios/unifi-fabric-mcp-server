"""Every result shape a tool description states matches what the code returns.

A description states a result shape as a brace list after a return verb ("Returns
{deleted, message, response}", "Dry-run returns {status: "dry_run", dryRun: true,
message, preview: {method, path, params, body}}"). Each such claim is parsed into its keys
(nested braces become nested keys) and checked against the code, key by key and case by
case:

* the claim is satisfied when it embeds in a result the tool actually produced (driven
  through the shape-faithful fake upstream with recorded and with sparse records, and,
  for a write tool, under ``dry-run policy``): every claimed key is present, in that case,
  at that nesting level, at the top level or at any depth;
* otherwise the claim fails: a key appearing only in request bodies or other
  unexercised code does not establish the documented result shape.

A claim about the upstream body itself (its sentence says ``upstream`` or ``verbatim``
before the brace, or the brace is followed by ``verbatim``) names keys only the upstream
owns and is not checked here; what sits under a claimed ``response`` is the upstream
body for the same reason. ``{field: ...}`` and ``{subsystem: ...}`` are map
placeholders (any key), not keys.

A tool that returns the upstream body unchanged (``PASS_THROUGH_SPEC``) produces the keys
of that body, so its claims are also matched against a body built from the pinned spec's
200 response schema, once a separate test has shown that the tool returns the body it was
served, unchanged.

The second property: a description's result statements are the tool's own. A
registration wrapper may add the one pass-through line only to a docstring that states
no result at all (any case: "returns" counts), so an injected blanket line never sits
next to the tool's own, contradicting a branch of it.
"""

from __future__ import annotations

import ast
import contextlib
import functools
import inspect
import json
import logging
import re
import textwrap
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize, tools_by_name
from unifi_fabric import server
from unifi_fabric.catalog_descriptions import DELETION_RESULT
from unifi_fabric.client import UniFiClient
from unifi_fabric.shared_shapes import _results

#: The pass-through line ``FabricMCP.tool`` adds to a docstring that states no result.
FOOTER = "Returns: the upstream response body verbatim."
#: Keys that stand for any key of a map (``{field: {from, to}}``), not result keys.
PLACEHOLDERS = frozenset({"field", "subsystem"})
#: A claimed key whose value is the upstream body: what is claimed under it is upstream.
UPSTREAM_CARRIERS = frozenset({"response"})
#: Tools whose result is the upstream body unchanged, with the pinned spec operation that
#: body follows: (OpenAPI fixture, path, method).
PASS_THROUGH_SPEC = {
    "get_network_references": (
        "network-11.0.97.json",
        "/v1/sites/{siteId}/networks/{networkId}/references",
        "get",
    ),
}
OPENAPI = Path(__file__).parent / "fixtures" / "openapi"
_RETURN = re.compile(r"\breturn(?:s|ed)?\b", re.I)
_UPSTREAM_LEAD = re.compile(r"\b(?:upstream|verbatim)\b", re.I)
_KEY = re.compile(r'^"?([A-Za-z_][A-Za-z0-9_]*)"?(?:\s*\([^)]*\))?(?:\s*:\s*(.*))?$', re.S)
Claim = dict[str, "Claim | None"]


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _flat(text: str | None) -> str:
    return " ".join((text or "").split())


# --------------------------------------------------------------------------- claims
def _closing(text: str, start: int) -> int:
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _items(inner: str) -> list[str]:
    out, depth, cur = [], 0, []
    for ch in inner:
        depth += ch in "{[("
        depth -= ch in "}])"
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return [item.strip() for item in out if item.strip()]


def parse_shape(shape: str) -> Claim | None:
    """``{a, b: 1, c: {d}}`` -> ``{"a": None, "b": None, "c": {"d": None}}``.

    ``None`` when the braces hold prose rather than a key list.
    """
    out: Claim = {}
    for item in _items(shape[1:-1]):
        if item in ("...", "…"):
            continue
        match = _KEY.match(item)
        if match is None:
            return None
        value = (match.group(2) or "").strip()
        nested = value.startswith("{") and value.endswith("}")
        out[match.group(1)] = parse_shape(value) if nested else None
    return out or None


def result_claims(description: str) -> list[tuple[str, str, Claim]]:
    """``(sentence lead, brace text, parsed claim)`` for every result-shape claim.

    A top-level brace list is a claim when its sentence has a return verb before it or it
    holds the dry-run status literal. Route templates (``/sites/{site}``) are not claims.
    """
    text = _flat(description)
    out = []
    i = 0
    while (i := text.find("{", i)) >= 0:
        end = _closing(text, i)
        if end < 0:
            break
        brace = text[i : end + 1]
        if i and (text[i - 1] == "/" or text[i - 1].isalnum()):
            i = end + 1
            continue
        start = max(text.rfind(". ", 0, i), text.rfind("; ", 0, i)) + 1
        lead = text[start:i].strip()
        claim = parse_shape(brace)
        if claim and (_RETURN.search(lead) or '"dry_run"' in brace):
            after = text[end + 1 : end + 11]
            upstream = _UPSTREAM_LEAD.search(lead) or after.lstrip().startswith("verbatim")
            if not upstream or '"dry_run"' in brace:
                out.append((lead, brace, claim))
        i = end + 1
    return out


# --------------------------------------------------------------------------- code keys
def _scope(fn: Any) -> dict[str, Any]:
    scope = dict(fn.__globals__)
    for name, cell in zip(fn.__code__.co_freevars, fn.__closure__ or (), strict=True):
        try:
            scope[name] = cell.cell_contents
        except ValueError:  # an unassigned cell
            continue
    return scope


def _resolve(expr: ast.expr, scope: dict[str, Any]) -> Any:
    if isinstance(expr, ast.Name):
        return scope.get(expr.id)
    if isinstance(expr, ast.Attribute):
        base = _resolve(expr.value, scope)
        return None if base is None else getattr(base, expr.attr, None)
    return None


def _str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _source_tree(fn: Any) -> ast.AST | None:
    try:
        return ast.parse(textwrap.dedent(inspect.getsource(fn)))
    except (OSError, TypeError, SyntaxError):  # no Python source
        return None


def _key_params(fn: Any) -> list[str]:
    """Parameters ``fn`` uses as a dict-display key (``{field: value}``)."""
    tree = _source_tree(fn)
    if tree is None:
        return []
    params = list(inspect.signature(fn).parameters)
    used = {
        key.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Dict)
        for key in node.keys
        if isinstance(key, ast.Name)
    }
    return [p if p in used else "" for p in params]


def _code_keys(fn: Any, seen: set[Any]) -> set[str]:
    fn = inspect.unwrap(getattr(fn, "__func__", fn))
    if not inspect.isfunction(fn) or fn.__code__ in seen:
        return set()
    if not (fn.__module__ or "").startswith("unifi_fabric"):
        return set()
    seen.add(fn.__code__)
    tree = _source_tree(fn)
    if tree is None:
        return set()
    scope = _scope(fn)
    keys: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            keys |= {k for k in map(_str, node.keys) if k}
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store):
            if key := _str(node.slice):
                keys.add(key)
        elif isinstance(node, ast.Call):
            func = node.func
            if (isinstance(func, ast.Name) and func.id == "dict") or (
                isinstance(func, ast.Attribute) and func.attr == "update"
            ):
                keys |= {kw.arg for kw in node.keywords if kw.arg}
            if isinstance(func, ast.Attribute) and func.attr == "setdefault" and node.args:
                if key := _str(node.args[0]):
                    keys.add(key)
            callee = _resolve(func, scope)
            if callee is not None:
                keys |= _code_keys(callee, seen)
                # A helper that takes the key name: _media(raw, ct, "image_base64").
                target = inspect.unwrap(getattr(callee, "__func__", callee))
                if inspect.isfunction(target) and (target.__module__ or "").startswith(
                    "unifi_fabric"
                ):
                    params = _key_params(target)
                    for index, arg in enumerate(node.args):
                        if index < len(params) and params[index] and (key := _str(arg)):
                            keys.add(key)
                    for kw in node.keywords:
                        if kw.arg in params and (key := _str(kw.value)):
                            keys.add(key)
            for arg in node.args:  # a function handed over as a callback
                passed = _resolve(arg, scope)
                if callable(passed):
                    keys |= _code_keys(passed, seen)
    return keys


@functools.cache
def code_keys(name: str) -> frozenset[str]:
    """Keys appearing in tool/helper code; diagnostic only, never a result witness."""
    return frozenset(_code_keys(tools_by_name()[name].fn, set()))


@functools.cache
def dry_run_keys() -> frozenset[str]:
    """Keys of the client's dry-run preview and the shared helpers that wrap it."""
    keys: set[str] = set()
    for fn in (UniFiClient._dry_run_response, *vars(_results).values()):
        if inspect.isfunction(fn):
            keys |= _code_keys(fn, set())
    return frozenset(keys)


# --------------------------------------------------------------------------- matching
def _embeds(claim: Claim, node: Any) -> bool:
    if not isinstance(node, dict):
        return False
    for key, sub in claim.items():
        if key in PLACEHOLDERS:
            continue
        if key not in node:
            return False
        if sub is None or key in UPSTREAM_CARRIERS:
            continue
        value = node[key]
        if isinstance(value, list) and value:
            if not all(_embeds(sub, item) for item in value):
                return False
        elif not _embeds(sub, value):
            return False
    return True


def embeds_anywhere(claim: Claim, payload: Any) -> bool:
    stack = [payload]
    while stack:
        node = stack.pop()
        if _embeds(claim, node):
            return True
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return False


def claimed_keys(claim: Claim) -> set[str]:
    out: set[str] = set()
    for key, sub in claim.items():
        if key in PLACEHOLDERS:
            continue
        out.add(key)
        if sub and key not in UPSTREAM_CARRIERS:
            out |= claimed_keys(sub)
    return out


async def _payloads(monkeypatch, name: str) -> list[Any]:
    """The results the tool produces: recorded records, sparse generic records (a tool
    that needs a recorded shape may refuse those), and its dry-run preview."""
    out = []
    with monkeypatch.context() as mp:
        out.append(uh.result_payload(await cti._call(mp, name, uh.FakeUpstream())))
    with monkeypatch.context() as mp, contextlib.suppress(ToolError):
        sparse = uh.FakeUpstream(recorded_routes={})
        out.append(uh.result_payload(await cti._call(mp, name, sparse)))
    if name in cti._lz_WRITE_TOOLS():
        with monkeypatch.context() as mp:
            dry = {"UNIFI_WRITE_POLICY": "dry-run"}
            out.append(uh.result_payload(await cti._call(mp, name, uh.FakeUpstream(), env=dry)))
    if name == "list_carrier_subscribers":
        records = [{"id": uh.ARG_ID, "name": "synthetic subscriber"}]
        requests = []

        class BareCursorPage(uh.FakeUpstream):
            def __call__(self, request: httpx.Request) -> httpx.Response:
                if request.method == "GET" and request.url.path.endswith("/v1/carrier/subscribers"):
                    requests.append(request)
                    return httpx.Response(200, json=records)
                return super().__call__(request)

        args = cti.tool_args.generated_args(tools_by_name()[name])
        args["cursor"] = "c1"
        with monkeypatch.context() as mp:
            result = uh.result_payload(await cti._call(mp, name, BareCursorPage(), args))
            assert len(requests) == 1
            assert requests[0].url.params["cursor"] == "c1"
            assert result == {"result": records}
            out.append(result)
    if name in {
        "get_controller_stats",
        "get_observability_site_health",
        "get_protect_stream_url",
        "get_site_dpi_usage",
        "get_client_dpi_usage",
    }:
        args = cti.tool_args.generated_args(tools_by_name()[name])
        args["start"] = 1700000000000
        with monkeypatch.context() as mp:
            result = await cti._call(mp, name, uh.FakeUpstream(get_body="list"), args)
            out.append(uh.result_payload(result))
    if name in {
        "update_camera",
        "update_chime",
        "update_light",
        "update_liveview",
        "update_sensor",
        "update_viewer",
    }:

        class MatchingRecord(uh.FakeUpstream):
            def __call__(self, request: httpx.Request) -> httpx.Response:
                requests.append(request)
                if request.method == "GET" and request.url.path.endswith("/" + item_id):
                    return httpx.Response(200, json={"id": item_id, "name": "same"})
                return super().__call__(request)

        args = cti.tool_args.generated_args(tools_by_name()[name])
        args["settings"] = {"name": "same"}
        item_id = next(value for key, value in args.items() if key.endswith("_id"))
        with monkeypatch.context() as mp:
            upstream = MatchingRecord(replay_recordings=False)
            requests = []
            result = uh.result_payload(await cti._call(mp, name, upstream, args))
            assert result["status"] == "noop"
            assert requests and all(call.method == "GET" for call in requests)
            out.append(result)
    if name in {
        "update_camera_shortcut",
        "update_protect_case",
        "update_protect_case_asset",
        "update_ptz_patrol",
        "update_ptz_preset",
    }:
        args = cti.tool_args.generated_args(tools_by_name()[name])
        record = {"id": uh.ARG_ID, "name": "same", "note": "same", "slot": args.get("slot", 1)}
        if name == "update_protect_case":
            record["id"] = args["case_id"]
            args["name"] = "same"
        elif name == "update_protect_case_asset":
            record["id"] = args["asset_id"]
            args["note"] = "same"
        elif name == "update_camera_shortcut":
            record["id"] = args["body"]["id"]
            args["body"] = {"id": record["id"], "name": "same"}
        else:
            args["fields"] = {"name": "same"}

        class NoopRecords(uh.FakeUpstream):
            def __call__(self, request: httpx.Request) -> httpx.Response:
                requests.append(request)
                if request.method == "GET":
                    path = request.url.path
                    if path.endswith("/cases"):
                        return httpx.Response(200, json=[{**record, "id": args["case_id"]}])
                    if path.endswith("/assets") or "/ptz/" in path:
                        return httpx.Response(200, json=[record])
                    if path.endswith("/" + args.get("camera_id", "")):
                        return httpx.Response(
                            200, json={"id": args["camera_id"], "shortcuts": [record]}
                        )
                return super().__call__(request)

        upstream = NoopRecords(replay_recordings=False)
        requests = []
        with monkeypatch.context() as mp:
            result = uh.result_payload(await cti._call(mp, name, upstream, args))
            assert result["status"] == "noop"
            assert requests and all(call.method == "GET" for call in requests)
            out.append(result)
    if name == "set_protect_event_favorite":

        class EventReadback(uh.FakeUpstream):
            def __call__(self, request: httpx.Request) -> httpx.Response:
                if request.method == "GET" and "/events/" in request.url.path:
                    return httpx.Response(200, json={"id": uh.ARG_ID, "isFavorite": True})
                return super().__call__(request)

        args = cti.tool_args.generated_args(tools_by_name()[name])
        args.update(event_ids=uh.ARG_ID, favorite=True)
        with monkeypatch.context() as mp:
            result = await cti._call(mp, name, EventReadback(), args)
            out.append(uh.result_payload(result))
    if name == "enhance_face_detection_image":

        class ImageUpstream(uh.FakeUpstream):
            def __call__(self, request: httpx.Request) -> httpx.Response:
                if request.method == "POST" and request.url.path.endswith("/image/enhance"):
                    return httpx.Response(
                        200, content=b"synthetic image", headers={"content-type": "image/jpeg"}
                    )
                return super().__call__(request)

        with monkeypatch.context() as mp:
            out.append(uh.result_payload(await cti._call(mp, name, ImageUpstream())))
    if name == "manage_mclag_group":
        args = cti.tool_args.generated_args(tools_by_name()[name])
        args["action"] = "delete"
        args.pop("group", None)
        for env in ({}, {"UNIFI_WRITE_POLICY": "dry-run"}):
            with monkeypatch.context() as mp:
                result = await cti._call(mp, name, uh.FakeUpstream(), args, env)
                out.append(uh.result_payload(result))
    if name == "forget_device":

        class PartialFailure(uh.FakeUpstream):
            def __call__(self, request: httpx.Request) -> httpx.Response:
                if request.method == "POST" and b"02:00:5e:00:00:b2" in request.content:
                    return httpx.Response(400, json={"error": "synthetic unknown device"})
                return super().__call__(request)

        args = cti.tool_args.generated_args(tools_by_name()[name])
        args["mac"] = ["02:00:5e:00:00:a1", "02:00:5e:00:00:b2"]
        for env in ({}, {"UNIFI_WRITE_POLICY": "dry-run"}):
            with monkeypatch.context() as mp:
                result = await cti._call(mp, name, PartialFailure(), args, env)
                out.append(uh.result_payload(result))
    return out


@pytest.mark.parametrize(
    ("name", "keys"),
    [
        ("forget_device", {"byMac", "forgotten", "errors"}),
        ("manage_mclag_group", {"deleted", "message", "response"}),
        ("enhance_face_detection_image", {"image_base64", "content_type", "size_bytes"}),
        ("get_controller_stats", {"result", "_warnings"}),
        ("list_carrier_subscribers", {"result"}),
    ],
)
async def test_nondefault_result_scenarios_are_exercised(monkeypatch, name, keys):
    payloads = await _payloads(monkeypatch, name)
    assert any(isinstance(payload, dict) and keys <= payload.keys() for payload in payloads)
    if name == "forget_device":
        assert any(isinstance(payload, dict) and payload.get("errors") for payload in payloads)
    if name == "manage_mclag_group":
        assert any(
            isinstance(payload, dict)
            and payload.get("status") == "dry_run"
            and {"deleted", "message", "response"} <= payload.keys()
            for payload in payloads
        )


def _schema_body(schema: Any, spec: dict[str, Any], seen: frozenset[str] = frozenset()) -> Any:
    """A body with every property the schema declares (one item per array)."""
    if not isinstance(schema, dict):
        return None
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in seen:
            return None
        node: Any = spec
        for part in ref.removeprefix("#/").split("/"):
            node = node[part]
        return _schema_body(node, spec, seen | {ref})
    parts = schema.get("allOf") or schema.get("oneOf") or schema.get("anyOf")
    if parts:
        merged: dict[str, Any] = {}
        for part in parts:
            body = _schema_body(part, spec, seen)
            if isinstance(body, dict):
                merged.update(body)
        return merged
    if schema.get("type") == "array" or "items" in schema:
        return [_schema_body(schema.get("items"), spec, seen)]
    if schema.get("type") == "object" or "properties" in schema:
        return {
            key: _schema_body(value, spec, seen)
            for key, value in schema.get("properties", {}).items()
        }
    return "value"


@functools.cache
def spec_body(name: str) -> Any:
    """The 200 body the pinned spec declares for a ``PASS_THROUGH_SPEC`` tool."""
    fixture, path, method = PASS_THROUGH_SPEC[name]
    spec = json.loads((OPENAPI / fixture).read_text())
    response = spec["paths"][path][method]["responses"]["200"]
    return _schema_body(response["content"]["application/json"]["schema"], spec)


def _claiming_tools() -> list[str]:
    return [
        name
        for name, tool in sorted(tools_by_name().items())
        if result_claims(tool.description or "")
    ]


# --------------------------------------------------------------------------- tests
def test_the_claim_parser_reads_nested_and_quoted_keys():
    claims = result_claims(
        'Dry-run returns {status: "dry_run", dryRun: true, message, '
        "preview: {method, path, params, body}}. Sends GET /sites/{site}/x. "
        "Returns {action, console_mac, response (verbatim)}."
    )
    assert [c for _, _, c in claims] == [
        {
            "status": None,
            "dryRun": None,
            "message": None,
            "preview": {"method": None, "path": None, "params": None, "body": None},
        },
        {"action": None, "console_mac": None, "response": None},
    ]


def test_code_keys_follow_helpers_and_key_name_arguments():
    # deletion_result is reached through the tool's helper; _media takes its key by name.
    assert {"deleted", "message", "response"} <= code_keys("remove_matter_node")
    assert "image_base64" in code_keys("enhance_face_detection_image")
    assert {"status", "dryRun", "message", "preview"} <= dry_run_keys()


def _unqualified_conditional_keys(
    description: str, brace: str, claim: Claim, payloads: list[Any]
) -> list[str]:
    """A claim that is this result but for one key states that key unconditionally while
    the code leaves it out here: the description must say when the key is present."""
    text = _flat(description)
    top = [key for key in claim if key not in PLACEHOLDERS]
    out = []
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        absent = [key for key in top if key not in payload]
        if len(absent) != 1 or len(top) - 1 < 2:
            continue
        key = absent[0]
        qualified = re.search(rf"(?<!\w){re.escape(key)}(?!\w)[^.;]*\b(?:when|if|unless)\b", text)
        if qualified is None:
            out.append(f"{brace}: {key!r} is absent from a result; say when it is present")
    return out


@lazy_parametrize("name", _claiming_tools)
async def test_every_result_claim_names_keys_the_code_produces(monkeypatch, name):
    description = tools_by_name()[name].description or ""
    payloads = await _payloads(monkeypatch, name)
    if name in PASS_THROUGH_SPEC:
        payloads.append(spec_body(name))
    problems = []
    for lead, brace, claim in result_claims(description):
        if any(embeds_anywhere(claim, payload) for payload in payloads):
            continue
        problems.append(f"{lead[-50:]!r} {brace}: no exercised result carries this claim")
        problems.extend(_unqualified_conditional_keys(description, brace, claim, payloads))
    assert problems == [], (name, problems)


@pytest.mark.parametrize("name", sorted(PASS_THROUGH_SPEC))
async def test_pass_through_tools_return_the_served_body_unchanged(monkeypatch, name):
    up = uh.FakeUpstream()
    with monkeypatch.context() as mp:
        payload = uh.result_payload(await cti._call(mp, name, up))
    own = [served for served in up.served if not served.resolution]
    assert own, name
    assert payload == own[-1].body, name


def test_spec_body_holds_every_declared_key():
    assert spec_body("get_network_references") == {
        "referenceResources": [
            {
                "referenceCount": "value",
                "references": [{"referenceId": "value"}],
                "resourceType": "value",
            }
        ]
    }


def _own_docstring(name: str) -> str:
    """The tool function's docstring as written in its source, before any registration
    wrapper edited ``__doc__``."""
    fn = inspect.unwrap(tools_by_name()[name].fn)
    tree = _source_tree(fn)
    assert tree is not None, name
    node = tree.body[0]
    assert isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef), name
    return _flat(ast.get_docstring(node))


@lazy_parametrize("name", lambda: sorted(tools_by_name()))
def test_result_statements_are_the_tools_own(name):
    """Every result statement in a description is in the tool's own docstring, apart from
    the shared deletion wording and the pass-through line on a docstring stating none."""
    description = _flat(tools_by_name()[name].description)
    own = _own_docstring(name)
    injected = []
    for match in re.finditer(r"\bReturns?\b:?[^.]*\.", description, re.I):
        statement = match.group(0)
        if statement in own or statement in DELETION_RESULT:
            continue
        if statement == FOOTER and not _RETURN.search(own):
            continue
        injected.append(statement)
    assert injected == [], (name, injected)


def test_the_pass_through_line_is_added_only_without_a_result_statement():
    async def lower_case(host: str) -> Any:
        """Do a thing.

        Action delete returns {deleted, message, response}.

        Args:
            host: a console.
        """

    async def silent(host: str) -> Any:
        """Do a thing.

        Args:
            host: a console.
        """

    probe = server.FabricMCP("probe")
    probe.tool(lower_case)
    probe.tool(silent)
    assert FOOTER not in _flat(lower_case.__doc__)
    assert FOOTER in _flat(silent.__doc__)


def test_carrier_cursor_envelope_is_documented():
    from pathlib import Path

    from unifi_fabric.shared_shapes._pagination import mark_incomplete

    cursor = "opaque-cursor"
    result = mark_incomplete({}, {"nextCursor": cursor, "pages": 2})
    assert result["_nextCursor"] == cursor
    docs = (Path(__file__).resolve().parents[1] / "docs/PAGINATION.md").read_text()
    assert "`_nextCursor`" in docs
