"""Every refused write is audited exactly once, at whatever layer refuses it.

With ``UNIFI_AUDIT_LOG`` set, a write tool call the server refuses before its write is
sent (a middleware gate, an argument check, an in-tool guard such as the update-field
check or a list-first resolution miss, a chokepoint check, the connector relay's own
validation) writes exactly one ``outcome=refused`` record with a non-empty ``reason``.

Local argument refusals send zero requests, including resolution reads. Only registry
entries with an explicit upstream dependency reason may read before refusing.

The refusals are found by behaviour, not from a list: every write tool of the catalog is
called with perturbed arguments (each required argument missing, blank and padded
strings, path-unsafe strings, empty lists, out-of-range numbers, empty and mask-only
bodies, credential values a refusal may quote, unknown hosts / sites / key labels /
ids) and with read-only mode on, against a
fake upstream that answers every request 200. No audit record ever holds a credential
argument value. A call that raises without any write
reaching the upstream, for a reason other than an upstream response it could not use, is
a refusal by this server, whichever layer made it; a call that completes has no refused
record. A refusal added or removed anywhere is covered the
moment it exists.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from tests import test_cross_tool_invariants as cti
from tests import test_refusal_policy as policy
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_classes import tool_batches
from unifi_fabric import read_only_tools, refusals
from unifi_fabric.redaction import REDACTION_MASK, is_credential_field
from unifi_fabric.refusal_audit import upstream_caused
from unifi_fabric.spec_limits import argument_problems
from unifi_fabric.write_body import (
    REQUIRED_BODY_KEYS,
    body_argument,
    missing_required_keys,
    update_problem,
)

TOOLS = cti.TOOLS

_UNKNOWN_UUID = "00000000-0000-4000-8000-0000000000ee"
#: A credential argument value; it must never appear in any audit record.
_CREDENTIAL = "pw7Qz"
_UNKNOWN_HEX = "0000000000000000000000ee"
_SELECTORS = ("host", "site", "key_label")


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _types(spec: dict[str, Any]) -> set[str]:
    out = {spec.get("type")} | {s.get("type") for s in spec.get("anyOf", [])}
    return {t for t in out if t}


def _perturbations(name: str) -> list[tuple[str, dict[str, Any]]]:
    """Argument sets for one write tool, each likely to meet some refusal."""
    tool = TOOLS[name]
    schema = tool.parameters or {}
    props: dict[str, Any] = schema.get("properties", {})
    base = tool_args.generated_args(tool)
    cases: list[tuple[str, dict[str, Any]]] = []
    for req in schema.get("required", []):
        cases.append((f"missing {req}", {k: v for k, v in base.items() if k != req}))
    for param, spec in props.items():
        if param == "confirm":
            continue
        types = _types(spec)
        values: list[Any] = []
        if "string" in types:
            values += ["", "   ", f" {base.get(param, uh.ARG_NAME)} ", "probe/../x?#y"]
            if param in _SELECTORS:
                values.append(f"probe-unknown-{param}")
            if param.endswith("_id") or param.endswith("id"):
                given = str(base.get(param, ""))
                values.append(_UNKNOWN_HEX if len(given) == 24 else _UNKNOWN_UUID)
        if "array" in types:
            values += [[], [""]]
        if "integer" in types or "number" in types:
            values += [-1, 10**15]
        if "object" in types:
            values += [{}, {"x_passphrase": REDACTION_MASK}]
            # a credential the refusal may quote: too short for any passphrase limit
            values.append({"x_passphrase": _CREDENTIAL, "name": 7})
        if "string" in types and is_credential_field(param):
            values += [_CREDENTIAL, f" {_CREDENTIAL}"]
        values += [42] if "string" in types else ["wrong-json-type"]
        if spec.get("enum"):
            values.append("invalid-enum-member")
        if "object" in types and isinstance(base.get(param), dict):
            values += [
                {k: v for k, v in base[param].items() if k != omitted} for omitted in base[param]
            ]
        for value in values:
            cases.append((f"{param}={value!r}", {**base, param: value}))
    body_arg = body_argument(tool)
    if body_arg is not None and isinstance(base.get(body_arg), dict):
        for key in REQUIRED_BODY_KEYS.get(name, ()):
            cases.append(
                (
                    f"without-required-body-{key}",
                    {**base, body_arg: {k: v for k, v in base[body_arg].items() if k != key}},
                )
            )
    optional = policy.all_optional(tool)
    for arg, label, value in policy.perturbations(tool):
        cases.append((f"all-optional+{arg}={label}", {**optional, arg: value}))
    cases.extend(policy.combinations(tool))
    return cases


def _expected_invalid(name: str, args: dict[str, Any]) -> bool:
    # Known local invalidity from declared schema and central body/spec rules.
    tool = TOOLS[name]
    schema = tool.parameters or {}
    if not set(schema.get("required", [])) <= args.keys():
        return True
    if argument_problems(name, args):
        return True
    for param, spec in schema.get("properties", {}).items():
        if param not in args or param == "confirm":
            continue
        value = args[param]
        types = _types(spec)
        if value == "wrong-json-type" and "string" not in types:
            return True
        if isinstance(value, int) and "string" in types and not types & {"integer", "number"}:
            return True
        if spec.get("enum") and value not in spec["enum"]:
            return True
    arg = body_argument(tool)
    if arg is not None and isinstance(args.get(arg), dict):
        _, _, reason = update_problem(args[arg], f"{name} {arg!r}")
        if reason is not None or missing_required_keys(name, args[arg]):
            return True
    return False


def _records(path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


async def _run(monkeypatch, tmp_path, name, args, env=None):
    log = tmp_path / "audit.jsonl"
    log.unlink(missing_ok=True)
    up = uh.FakeUpstream()
    full_env = {"UNIFI_AUDIT_LOG": str(log), "UNIFI_AUDIT_LOG_FORMAT": "json", **(env or {})}
    error: Exception | None = None
    try:
        await cti._call(monkeypatch, name, up, args, env=full_env)
    except Exception as exc:  # noqa: BLE001 - any refusal shape is classified below
        error = exc
    return up, error, _records(log)


def _problem(label: str, up: uh.FakeUpstream, error, records, *, is_write: bool) -> str | None:
    refused = [r for r in records if r.get("outcome") == "refused"]
    leaked = [r for r in records if _CREDENTIAL in json.dumps(r)]
    if leaked:
        return f"{label}: a credential argument value reached the audit log: {leaked}"
    if error is None:
        if refused:
            return f"{label}: completed call has refused record(s) {refused}"
        return None
    registered = refusals.classify(str(error))
    if registered is not None and registered.category != refusals.UPSTREAM_JUDGED and up.served:
        return (
            f"{label}: local refusal {registered.id!r} sent {len(up.served)} "
            f"upstream requests: {str(error)[:160]!r}"
        )
    if up.writes():
        return None  # upstream/write-readback errors after a sent write are not local refusals
    if registered is None:
        return f"{label}: unregistered refusal: {str(error)[:160]!r}"
    if registered.category == refusals.UPSTREAM_JUDGED:
        if not registered.upstream_reason:
            return f"{label}: upstream refusal {registered.id!r} has no registered reason"
        if not up.served:
            return f"{label}: upstream refusal {registered.id!r} occurred without a request"
        if upstream_caused(error):
            return None  # registered response-shape failure is not a refused write
    elif up.served:
        return (
            f"{label}: local refusal {registered.id!r} sent {len(up.served)} "
            f"upstream requests: {str(error)[:160]!r}"
        )
    expected = 1 if is_write else 0
    if len(refused) != expected:
        return f"{label}: refusal ({str(error)[:160]!r}) wrote {len(refused)} refused record(s)"
    if not is_write:
        return None
    reason = refused[0].get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return f"{label}: refused record without a reason: {refused[0]}"
    return None


@tool_batches("name", lambda: cti.WRITE_TOOLS)
async def test_every_refused_write_is_audited_exactly_once(monkeypatch, tmp_path, name):
    problems: list[str] = []
    refusal_count = 0
    local_refusal_count = 0
    cases = _perturbations(name)
    cases.append(("UNIFI_READ_ONLY=1", None))
    for label, args in cases:
        env = {"UNIFI_READ_ONLY": "1"} if args is None else None
        call_args = tool_args.generated_args(TOOLS[name]) if args is None else args
        if args is None and name == "fabric_connector_get":
            # The generic GET tool can also read. Exercise a state-changing route so
            # its read-only policy case must refuse, without restricting ordinary GETs.
            call_args = {
                **call_args,
                "path": f"protect/api/cameras/{uh.ARG_ID}/enable-control",
            }
        up, error, records = await _run(monkeypatch, tmp_path, name, call_args, env)
        if args is None and (error is None or up.served):
            problems.append(
                f"{label}: read-only mutation was not refused before any upstream request"
            )
        if error is not None and not up.writes() and not upstream_caused(error):
            refusal_count += 1
        problem = _problem(
            label,
            up,
            error,
            records,
            is_write=read_only_tools.is_write_tool_call(TOOLS[name], name, call_args),
        )
        if problem:
            problems.append(problem)
        registered = refusals.classify(str(error)) if error is not None else None
        if _expected_invalid(name, call_args) and (
            error is None
            or up.served
            or registered is None
            or registered.category == refusals.UPSTREAM_JUDGED
        ):
            problems.append(
                f"{label}: known invalid local input was not refused before any request"
            )
        if registered is not None and registered.category not in {
            refusals.UPSTREAM_JUDGED,
            refusals.OPERATOR_POLICY,
        }:
            local_refusal_count += 1
        # A lookup miss must never mask another locally invalid argument. Establish
        # the local refusal on the valid-host case, then pair it with an unknown host.
        if (
            registered is not None
            and registered.category != refusals.UPSTREAM_JUDGED
            and isinstance(call_args.get("host"), str)
            and call_args["host"] == tool_args.generated_args(TOOLS[name]).get("host")
        ):
            paired_label = f"unknown-host+{label}"
            paired_up, paired_error, paired_records = await _run(
                monkeypatch, tmp_path, name, {**call_args, "host": "probe-unknown-host"}, env
            )
            paired_refusal = (
                refusals.classify(str(paired_error)) if paired_error is not None else None
            )
            if (
                paired_up.served
                or paired_refusal is None
                or paired_refusal.category == refusals.UPSTREAM_JUDGED
            ):
                problems.append(
                    f"{paired_label}: unknown host masked local refusal {registered.id!r}"
                )
            paired_problem = _problem(
                paired_label,
                paired_up,
                paired_error,
                paired_records,
                is_write=read_only_tools.is_write_tool_call(
                    TOOLS[name], name, {**call_args, "host": "probe-unknown-host"}
                ),
            )
            if paired_problem:
                problems.append(paired_problem)
    # Non-vacuous: every write tool meets at least one refusal (read-only mode always).
    assert local_refusal_count >= 1, f"{name}: no locally invalid argument was refused"
    assert refusal_count >= 1, f"{name}: no perturbation was refused"
    assert problems == [], f"{name}: " + "\n".join(problems)


async def test_chokepoint_refusals_are_audited_with_method_and_path(tmp_path):
    """The HTTP chokepoint's own refusals (an unsafe path, a body of nothing but masked
    secrets) are audited there, with the request's method and path."""
    from unifi_fabric.client import UniFiClient
    from unifi_fabric.config import Settings

    log = tmp_path / "audit.jsonl"
    client = UniFiClient(
        Settings(
            api_key="K" * 20,
            audit_log=str(log),
            audit_log_format="json",
            redact_secrets=True,
        )
    )
    unsafe = "/v1/connector/consoles/abc/../x"
    with pytest.raises(ValueError):
        await client.delete(unsafe)
    masked = "/v1/connector/consoles/abc/proxy/network/integration/v1/sites/s/networks/n"
    with pytest.raises(ValueError):
        await client.put(masked, json={"x_passphrase": REDACTION_MASK})
    await client.close()
    recs = _records(log)
    assert [(r["method"], r["path"], r["outcome"]) for r in recs] == [
        ("DELETE", unsafe, "refused"),
        ("PUT", masked, "refused"),
    ], recs
    assert all(r.get("reason") for r in recs), recs


def test_text_format_reason_is_one_parseable_field(tmp_path):
    """A free-text reason stays one field of one line in the text format."""
    from unifi_fabric.audit import AuditSink

    log = tmp_path / "audit.log"
    sink = AuditSink(path=str(log))
    sink.record(method=None, path=None, outcome="refused", status=None, tool="t", reason='a b\n"c"')
    lines = log.read_text().splitlines()
    assert len(lines) == 1, lines
    assert lines[0].endswith(' reason="a b\\n\\"c\\""'), lines[0]


async def test_a_refusal_quoting_a_credential_is_audited_without_it():
    """The refusal message is the reason, minus the call's credential argument values
    (top-level or inside a body), even when the refusal quotes them."""
    from fastmcp import FastMCP

    from unifi_fabric.refusal_audit import RefusedWriteAuditMiddleware

    app = FastMCP("probe")

    @app.tool
    def set_probe_secret(password: str, body: dict) -> dict:
        raise ValueError(f"refused {password} and {body.get('x_passphrase')}")

    seen: list[tuple[str, str]] = []
    app.add_middleware(
        RefusedWriteAuditMiddleware(app, lambda: True, lambda t, r: seen.append((t, r)))
    )
    with pytest.raises(Exception, match="refused"):
        await app.call_tool(
            "set_probe_secret", {"password": "pw-top-9Q", "body": {"x_passphrase": "pw-deep-7Z"}}
        )
    assert len(seen) == 1, seen
    tool, reason = seen[0]
    assert tool == "set_probe_secret" and "refused" in reason, seen
    assert "pw-top-9Q" not in reason and "pw-deep-7Z" not in reason, reason


@pytest.mark.parametrize("method,resolution", [("GET", False), ("GET", True), ("POST", False)])
def test_local_refusal_rejects_even_one_request(method, resolution):
    up = uh.FakeUpstream()
    up.served.append(uh.Served(method, "/v1/hosts", 200, {}, resolution))
    error = ValueError("No fields provided")
    problem = _problem(
        "local", up, error, [{"outcome": "refused", "reason": str(error)}], is_write=True
    )
    assert problem is not None and "sent 1 upstream requests" in problem


def test_upstream_refusal_requires_a_request():
    problem = _problem("lookup", uh.FakeUpstream(), ValueError("Unknown host"), [], is_write=True)
    assert problem is not None and "without a request" in problem


def test_upstream_refusal_requires_an_explicit_reason(monkeypatch):
    from dataclasses import replace

    entry = replace(refusals.BY_ID["lookup-miss"], upstream_reason=None)
    monkeypatch.setattr(refusals, "classify", lambda message: entry)
    up = uh.FakeUpstream()
    up.served.append(uh.Served("GET", "/v1/hosts", 200, {}, True))
    problem = _problem("lookup", up, ValueError("Unknown host"), [], is_write=True)
    assert problem is not None and "no registered reason" in problem


def test_registered_lookup_refusal_is_audited_after_resolution():
    up = uh.FakeUpstream()
    up.served.append(uh.Served("GET", "/v1/hosts", 200, {}, True))
    error = ValueError("Unknown host")
    assert _problem("lookup", up, error, [], is_write=True) is not None
    assert (
        _problem("lookup", up, error, [{"outcome": "refused", "reason": str(error)}], is_write=True)
        is None
    )


@tool_batches("name", lambda: cti.WRITE_TOOLS)
def test_every_write_has_a_known_invalid_local_case(name):
    assert any(_expected_invalid(name, args) for _, args in _perturbations(name)), name
