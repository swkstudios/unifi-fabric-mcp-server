"""collect_network_incident_evidence (system_log module): normalized Network evidence.

Each system-log class is one source read with the shared system-log drain; the document is
validated against the closed incident-evidence schema.
"""

from __future__ import annotations

import asyncio
import copy
import json
import re
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric import read_only, server
from unifi_fabric import read_post_routes as rp
from unifi_fabric._read_only_audit import derive_write_tools
from unifi_fabric.client import (
    RateLimitError,
    UniFiConnectionError,
    UniFiHTTPError,
)
from unifi_fabric.families.statistics import system_log
from unifi_fabric.secret_scrub import secret_scope
from unifi_fabric.shared_shapes import _incident_document as ie

HOST_ID = "host-001"
V2 = f"/v1/connector/consoles/{HOST_ID}/proxy/network/v2/api/site/default"
RECORDED = Path(__file__).resolve().parent / "fixtures" / "recorded" / "network_v2"
START_S = 1_791_744_000  # the recorded entries fall in [START_S, END_S)
END_S = 1_791_747_600


def _recorded(name: str) -> Any:
    return json.loads((RECORDED / name).read_text())["body"]


ALL = _recorded("network_v2_api_site_SITE_system_log_all.json")
THREATS = _recorded("network_v2_api_site_SITE_system_log_threat_alert.json")
CRITICAL = _recorded("network_v2_api_site_SITE_system_log_critical.json")


def _single_page(body: dict[str, Any]) -> dict[str, Any]:
    """The recorded page as the only page of its class (total = its rows)."""
    rows = body["data"]
    return {**body, "page_number": 0, "total_page_count": 1, "total_element_count": len(rows)}


@pytest.fixture()
def client():
    c = AsyncMock()
    c.paginate_max_pages = None
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_slug = AsyncMock(return_value="default")
    return r


_EXTRA_CLASSES = ("critical", "threat-alert", "triggers")


@pytest.fixture()
def extra_listed_classes(monkeypatch):
    """The allowlist as it would be once more system-log classes are listed (each its own
    entry with its own live evidence): lets the multi-class behavior be tested today."""
    listed = next(r for r in rp.READ_POST_ROUTES if r.name == "network-v2-system-log-all")
    template = listed.template.rsplit("/", 1)[0]
    extra = tuple(
        rp.ReadPostRoute(
            name=f"test-system-log-{name}",
            method="POST",
            template=f"{template}/{name}",
            tools=frozenset({"collect_network_incident_evidence"}),
            evidence=("test only",),
            sample=listed.sample.rsplit("/", 1)[0] + f"/{name}",
        )
        for name in _EXTRA_CLASSES
    )
    monkeypatch.setattr(rp, "READ_POST_ROUTES", (*rp.READ_POST_ROUTES, *extra))


@pytest.fixture()
def write_classified_route(monkeypatch, extra_listed_classes):
    """The route as a write again (the classifier says so), for the write error policy."""
    monkeypatch.setattr(system_log, "is_write_request", lambda *a, **k: True)


def _by_class(table: dict[str, Any]):
    """A ``client.request`` stand-in: the table maps a class to a JSON body (answered 200), an
    ``httpx.Response`` (answered as given) or an exception (raised)."""

    async def request(method: str, path: str, **_: Any) -> Any:
        assert method == "POST"
        log_class = path.rsplit("/", 1)[-1]
        body = table[log_class]
        if isinstance(body, Exception):
            raise body
        if isinstance(body, httpx.Response):
            return body
        return httpx.Response(200, json=copy.deepcopy(body))

    return request


async def _collect(client: Any, registry: Any, **kw: Any) -> Any:
    args = {"start": START_S, "end": END_S, **kw}
    return await system_log._collect_network_incident_evidence(
        client, registry, "h", "Default", args.pop("start"), args.pop("end"), **args
    )


async def test_recorded_network_fixture_validates_against_the_closed_schema(client, registry):
    client.request.side_effect = _by_class({"all": _single_page(ALL)})
    doc = await _collect(client, registry)
    ie.validate_document(doc)
    assert (doc["schema_name"], doc["schema_version"]) == ("unifi-fabric-incident-evidence", 1)
    assert (doc["product"], doc["status"], doc["causality"]) == (
        "network",
        "complete",
        "not_assessed",
    )
    assert doc["scope"] == {"host_id": HOST_ID, "site": "default"}
    path = client.request.await_args.args[1]
    body = client.request.await_args.kwargs["json"]
    assert path == f"{V2}/system-log/all"
    assert body["timestampFrom"] == START_S * 1000
    assert body["timestampTo"] == END_S * 1000
    assert [r["provenance"]["record_id"] for r in doc["records"]] == [
        row["id"] for row in sorted(ALL["data"], key=lambda r: r["timestamp"])
    ]
    assert all(r["time"]["status"] == "in_window" for r in doc["records"])
    threat = next(r for r in doc["records"] if r["provenance"]["record_id"] == ALL["data"][0]["id"])
    assert threat["identity"]["status"] == "exact"
    assert threat["attributes"]["key"] == "THREAT_DETECTED_KNOWN_SOURCE_CLIENT"
    assert threat["attributes"]["severity"] == "HIGH"
    # Free text and raw parameters never reach the document.
    text = json.dumps(doc)
    assert "message_raw" not in text and "title_raw" not in text and "parameters" not in text


@pytest.mark.usefixtures("extra_listed_classes")
async def test_bare_array_class_and_several_classes_are_separate_sources(client, registry):
    client.request.side_effect = _by_class(
        {"threat-alert": _single_page(THREATS), "critical": CRITICAL}
    )
    doc = await _collect(client, registry, log_classes=["threat-alert", "critical", "threat-alert"])
    ie.validate_document(doc)
    assert [s["source_id"] for s in doc["sources"]] == [
        "network.system_log.threat-alert",
        "network.system_log.critical",
    ]
    assert client.request.await_count == 2


async def test_repeated_collection_yields_identical_ids_and_order(client, registry):
    client.request.side_effect = _by_class({"all": _single_page(ALL)})
    first = await _collect(client, registry)
    reordered = _single_page(ALL)
    reordered["data"] = list(reversed(reordered["data"]))
    client.request.side_effect = _by_class({"all": reordered})
    second = await _collect(client, registry)
    first.pop("collected_at")
    second.pop("collected_at")
    assert first == second


@pytest.mark.usefixtures("extra_listed_classes")
async def test_one_unsupported_class_yields_explicit_partial_evidence(client, registry):
    not_found = UniFiHTTPError(
        'HTTP 404 from POST system-log/triggers: {"meta":{"rc":"error","msg":"api.err.NotFound"}}',
        status=404,
    )
    client.request.side_effect = _by_class({"all": _single_page(ALL), "triggers": not_found})
    doc = await _collect(client, registry, log_classes=["all", "triggers"])
    ie.validate_document(doc)
    assert doc["status"] == "partial"
    good, failed = doc["sources"]
    assert good["outcome"] == "complete"
    assert failed["outcome"] == "unsupported"
    assert failed["failure"]["http_status"] == 404
    assert failed["failure"]["message"].endswith(str(not_found))
    assert f"POST {V2}/system-log/triggers" in failed["failure"]["message"]
    assert failed["coverage"]["window_coverage"] == "not_covered"
    assert {r["source_id"] for r in doc["records"]} == {"network.system_log.all"}


async def test_every_class_failing_is_failed_never_empty(client, registry):
    client.request.side_effect = _by_class({"all": UniFiHTTPError("HTTP 403", status=403)})
    doc = await _collect(client, registry)
    assert (doc["status"], doc["sources"][0]["outcome"], doc["records"]) == (
        "failed",
        "permission_denied",
        [],
    )


PATH_ALL = f"{V2}/system-log/all"


@pytest.mark.parametrize(
    ("answer", "said"),
    [
        (httpx.Response(200, json="ok"), "a text answer (not JSON, or a JSON string): ok"),
        (httpx.Response(200, json=42), "a JSON scalar: 42"),
        (httpx.Response(200, json=None), "an empty body"),
        (httpx.Response(204), "an empty body"),
        (httpx.Response(200, content=b""), "an empty body"),
        (
            httpx.Response(202, text="queued for later"),
            "a text answer (not JSON, or a JSON string): queued for later",
        ),
    ],
)
async def test_a_2xx_answer_with_no_listing_is_parse_failed_with_the_body_verbatim(
    client, registry, answer, said
):
    client.request.side_effect = _by_class({"all": answer})
    doc = await _collect(client, registry)
    ie.validate_document(doc)
    source = doc["sources"][0]
    assert source["outcome"] == "parse_failed"
    # The upstream answered: its 2xx status is carried (it is not null), never raised.
    assert source["failure"]["http_status"] == answer.status_code
    assert said in source["failure"]["message"]
    assert f"POST {PATH_ALL}" in source["failure"]["message"]
    assert doc["status"] == "failed" and doc["records"] == []


async def test_an_object_of_unexpected_shape_is_described_by_shape_only(client, registry):
    private = "".join(["priv", "ate-event", "-text"])
    drifted = {"events": [{"message": private}], "count": 1}
    client.request.side_effect = _by_class({"all": drifted})
    doc = await _collect(client, registry)
    failure = doc["sources"][0]["failure"]
    assert doc["sources"][0]["outcome"] == "parse_failed"
    assert failure["http_status"] == 200
    assert "events" in failure["message"] and private not in failure["message"]
    assert f"POST {PATH_ALL}" in failure["message"]


async def test_a_scalar_answer_is_scrubbed_of_configured_secrets(client, registry):
    secret = "".join(["s3", "cr3t", "-valu", "e-for-scrub", "-test-0003"])
    client.request.side_effect = _by_class({"all": httpx.Response(200, text=f"accepted {secret}")})
    with secret_scope([secret]):
        doc = await _collect(client, registry)
    message = doc["sources"][0]["failure"]["message"]
    assert "accepted " in message and secret not in message


async def test_page_cap_truncation_is_reported(client, registry):
    client.paginate_max_pages = 1
    page = {
        "data": [{"id": f"e{i}", "timestamp": START_S * 1000 + i} for i in range(1000)],
        "page_number": 0,
        "total_page_count": 3,
        "total_element_count": 2500,
    }
    client.request.side_effect = _by_class({"all": page})
    doc = await _collect(client, registry)
    ie.validate_document(doc)
    source = doc["sources"][0]
    assert source["outcome"] == "partial"
    assert "truncated" in source["partial_reasons"]
    assert source["pagination"]["truncated"] == "truncated"
    assert source["pagination"]["page_cap"] == 1
    assert source["pagination"]["upstream_total"] == 2500
    assert source["coverage"]["window_coverage"] == "unknown"
    # The repo-wide truncation signal is on the document, naming the source.
    assert doc["incomplete"] is True
    assert doc["incompleteReason"].startswith("network.system_log.all: ")


async def test_an_uncapped_drain_is_never_incomplete(client, registry):
    client.request.side_effect = _by_class({"all": _single_page(ALL)})
    doc = await _collect(client, registry)
    assert doc["incomplete"] is False and "incompleteReason" not in doc


async def test_missing_and_ambiguous_times_and_identities_stay_uncertain(client, registry):
    rows = [
        {"id": "t1", "key": "K", "timestamp": START_S * 1000 + 10},
        {"id": "t2", "key": "K"},
        {"id": "t3", "key": "K", "timestamp": "2026-10-11T00:00:00"},
        {"id": "t4", "key": "K", "timestamp": START_S * 1000 + 20, "parameters": {}},
        {
            "id": "t5",
            "key": "K",
            "timestamp": START_S * 1000 + 30,
            "parameters": {"PEER": {"id": "02:00:5e:00:00:42", "name": "peer"}},
        },
    ]
    page = {"data": rows, "page_number": 0, "total_page_count": 1, "total_element_count": 5}
    client.request.side_effect = _by_class({"all": page})
    doc = await _collect(client, registry)
    by_id = {r["provenance"]["record_id"]: r for r in doc["records"]}
    assert by_id["t2"]["time"]["status"] == "missing"
    assert by_id["t3"]["time"]["status"] == "ambiguous_timezone"
    assert by_id["t3"]["time"]["epoch_ms"] is None
    assert by_id["t4"]["identity"]["status"] == "missing"
    assert by_id["t5"]["identity"]["status"] == "ambiguous"
    assert [r["provenance"]["record_id"] for r in doc["records"]][-2:] == ["t2", "t3"]
    assert doc["sources"][0]["partial_reasons"] == ["untimed_records"]


async def test_the_collector_is_a_read_neither_hidden_by_deny_nor_previewed_by_dry_run(
    client, registry, monkeypatch
):
    monkeypatch.setenv(read_only.ENV_VAR, "deny")
    client.request.side_effect = _by_class({"all": _single_page(ALL)})
    doc = await _collect(client, registry)  # no ReadOnlyModeError: the system-log POST is a read
    ie.validate_document(doc)
    assert doc["status"] == "complete"
    assert client.request.await_count == 1
    assert "dry_run" not in doc and "dryRun" not in doc


def test_only_the_listed_system_log_route_is_a_read():
    prefix = f"/v1/connector/consoles/{HOST_ID}/proxy/network/v2/api/site/default"
    assert read_only.is_write_request("POST", f"{prefix}/system-log/all") is False
    # the read-allowlist covers exactly this route: every other POST stays a write
    for path in (
        f"{prefix}/system-log/critical",
        f"{prefix}/system-log/threat-alert",
        f"{prefix}/system-log/all/extra",
        f"{prefix}/system-log/critical/mark-all-as-read",
        f"{prefix}/system-log",
        f"{prefix}/ports/system-logs",
        f"{prefix}/networks",
    ):
        assert read_only.is_write_request("POST", path) is True, path


async def test_a_class_that_is_not_allowlisted_is_refused_before_any_request(client, registry):
    with pytest.raises(ValueError, match="log_classes may name only a read-allowlisted"):
        await _collect(client, registry, log_classes=["all", "critical"])
    client.request.assert_not_awaited()


@pytest.mark.parametrize(
    ("kw", "match"),
    [
        ({"start": END_S, "end": START_S}, "must be after start"),
        ({"start": END_S, "end": START_S}, "nothing was sent"),
        ({"start": END_S, "end": END_S}, "swap start and end"),
        ({"log_classes": []}, "names no source"),
        ({"log_classes": ["../all"]}, "log_classes"),
    ],
)
async def test_invalid_input_is_refused_before_any_request(client, registry, kw, match):
    with pytest.raises(ValueError, match=match):
        await _collect(client, registry, **kw)
    registry.resolve_key_for_host.assert_not_awaited()
    client.request.assert_not_awaited()


EPOCH_CASES = [
    ({"start": -1, "end": START_S}, [("EPOCH_SECONDS_NEGATIVE", "start", -1)]),
    (
        {"start": START_S, "end": 1_700_000_000_000},
        [("EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS", "end", 1_700_000_000_000)],
    ),
    (
        {"start": START_S * 1000, "end": END_S * 1000},
        [
            ("EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS", "start", START_S * 1000),
            ("EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS", "end", END_S * 1000),
        ],
    ),
]


@pytest.mark.parametrize(("kw", "expected"), EPOCH_CASES)
async def test_a_negative_or_millisecond_bound_is_sent_with_a_warning(
    client, registry, kw, expected
):
    client.request.side_effect = _by_class({"all": _single_page(ALL)})
    doc = await _collect(client, registry, **kw)
    ie.validate_document(doc)
    body = client.request.await_args.kwargs["json"]
    assert (body["timestampFrom"], body["timestampTo"]) == (kw["start"] * 1000, kw["end"] * 1000)
    assert [(w["code"], w["argument"], w["value"]) for w in doc["_warnings"]] == expected


async def test_a_year_55840_bound_is_sent_and_the_document_validates(client, registry):
    client.request.side_effect = _by_class({"all": _single_page(ALL)})
    doc = await _collect(client, registry, end=1_700_000_000_000)
    ie.validate_document(doc)
    window = doc["requested_window"]
    assert window["end"] is None and window["end_epoch_ms"] == 1_700_000_000_000_000
    assert doc["_warnings"][0]["argument"] == "end"


async def test_a_plausible_window_has_no_warnings_key(client, registry):
    client.request.side_effect = _by_class({"all": _single_page(ALL)})
    assert "_warnings" not in await _collect(client, registry)


async def test_routes_to_the_owning_key(multikey_client, multikey_registry):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_host_id = AsyncMock(return_value="console-beta-1")
    multikey_registry.resolve_site_slug = AsyncMock(return_value="default")
    keys: list[Any] = []

    async def _request(method: str, path: str, *, key: Any = None, **_: Any) -> Any:
        keys.append(key)
        page = {"data": [], "page_number": 0, "total_page_count": 0, "total_element_count": 0}
        return httpx.Response(200, json=page)

    multikey_client.request = AsyncMock(side_effect=_request)
    doc = await system_log._collect_network_incident_evidence(
        multikey_client, multikey_registry, "Beta-Branch", "Default", START_S, END_S
    )
    assert [k.label for k in keys] == ["beta"]
    assert doc["status"] == "empty"
    assert doc["scope"]["host_id"] == "console-beta-1"


def _tool(name: str) -> Any:
    tools = asyncio.run(server.mcp.list_tools())
    return {t.name: t for t in tools}[name]


def test_tool_is_registered_with_derived_read_annotations_and_described_params():
    tool = _tool("collect_network_incident_evidence")
    # The system-log all POST is read-POST allowlisted and the collector sends it only through
    # post_read, so the hints are derived from source as a read's (never hand-listed).
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.destructive_hint is False
    props = tool.parameters["properties"]
    assert set(props) == {"host", "site", "start", "end", "log_classes"}
    assert all(p.get("description") for p in props.values())
    assert tool.parameters["required"] == ["host", "site", "start", "end"]


def test_derivation_counts_the_collector_as_a_read_and_the_other_system_log_posts_as_writes():
    from tests.test_read_only import _registered_tools

    writes = derive_write_tools(_registered_tools())
    assert "collect_network_incident_evidence" not in writes
    # the same route sent with client.post stays a write tool, and so does every other class
    assert {"get_system_log", "list_network_events", "list_ips_events"} <= writes


def test_description_claims_no_causality():
    text = _tool("collect_network_incident_evidence").description or ""
    assert "claims no cause" in text
    assert "not_assessed" in text
    assert not re.search(r"\b(caused by|root cause|correlat\w*)\b", text, re.IGNORECASE)


# ---------------------------------------------------------------- the write-classified route


def _error_for(status: int | None) -> Exception:
    if status is None:
        return UniFiConnectionError("connection reset by peer", request_sent=True)
    if status == 429:
        return RateLimitError(f"Rate limited on POST {PATH_ALL}: HTTP 429: slow down")
    return UniFiHTTPError(f"HTTP {status} from POST {PATH_ALL}: upstream said no", status=status)


@pytest.mark.parametrize("status", [500, 502, 503, 504, 599, 429, None])
async def test_a_read_has_no_uncertain_outcome_every_failure_is_recorded(client, registry, status):
    client.request.side_effect = _by_class({"all": _error_for(status)})
    doc = await _collect(client, registry)
    ie.validate_document(doc)
    assert doc["sources"][0]["outcome"] == "unavailable"
    assert doc["status"] == "failed"
    assert f"POST {PATH_ALL}" in doc["sources"][0]["failure"]["message"]
    assert client.request.await_count == 1


@pytest.mark.usefixtures("write_classified_route")
@pytest.mark.parametrize("status", [500, 502, 503, 504, 599, 429, None])
async def test_an_uncertain_write_outcome_raises_and_sends_no_further_post(
    client, registry, status
):
    boom = _error_for(status)
    client.request.side_effect = _by_class({"all": boom, "critical": CRITICAL})
    with pytest.raises(type(boom)) as raised:
        await _collect(client, registry, log_classes=["all", "critical"])
    assert raised.value is boom  # the client's own error, verbatim
    # The first POST is the only one sent: the second class is never requested.
    assert client.request.await_count == 1


@pytest.mark.usefixtures("write_classified_route")
@pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 422, 501])
async def test_a_definite_write_answer_is_recorded_and_the_next_class_is_still_read(
    client, registry, status
):
    client.request.side_effect = _by_class({"all": _error_for(status), "critical": CRITICAL})
    doc = await _collect(client, registry, log_classes=["all", "critical"])
    ie.validate_document(doc)
    failed, good = doc["sources"]
    assert failed["failure"]["http_status"] == status
    assert f"POST {PATH_ALL}" in failed["failure"]["message"]
    assert good["outcome"] != "unavailable"
    assert client.request.await_count == 2


async def test_the_raise_policy_keys_off_the_write_classifier(client, registry, monkeypatch):
    # The route is a read today, so a 500 is recorded as the source's failure ...
    client.request.side_effect = _by_class({"all": _error_for(500)})
    doc = await _collect(client, registry)
    assert doc["sources"][0]["outcome"] == "unavailable"
    # ... and should the classifier call it a write again, the same failure raises, with no
    # change to the collector.
    seen: list[tuple[str, str]] = []

    def classify(method: str, path: str, body: Any = None) -> bool:
        seen.append((method, path))
        return True

    monkeypatch.setattr(system_log, "is_write_request", classify)
    with pytest.raises(UniFiHTTPError):
        await _collect(client, registry)
    assert seen == [("POST", PATH_ALL)]


async def test_a_shape_failure_after_a_2xx_is_recorded_not_raised(client, registry):
    # The upstream answered 200 with a count that cannot prove completeness: the POST was
    # applied, so this is a parse failure of an answered request, not an unknown outcome.
    page = {"data": [{"id": "a"}], "total_element_count": "many", "total_page_count": 1}
    client.request.side_effect = _by_class({"all": page})
    doc = await _collect(client, registry)
    failure = doc["sources"][0]["failure"]
    assert doc["sources"][0]["outcome"] == "parse_failed"
    assert failure["http_status"] == 200
    assert f"POST {PATH_ALL}" in failure["message"]


async def test_id_less_rows_are_one_record_each_and_bad_rows_are_counted(client, registry):
    rows = [
        {"key": "A", "timestamp": START_S * 1000 + 5, "message_raw": "one"},
        {"key": "A", "timestamp": START_S * 1000 + 5, "message_raw": "two"},
        "not-an-object",
    ]
    page = {"data": rows, "page_number": 0, "total_page_count": 1, "total_element_count": 3}
    client.request.side_effect = _by_class({"all": page})
    doc = await _collect(client, registry)
    ie.validate_document(doc)
    counts = doc["sources"][0]["counts"]
    assert (counts["retrieved"], counts["records"], counts["malformed"]) == (3, 2, 1)
    assert "malformed_rows" in doc["sources"][0]["partial_reasons"]


def test_the_read_post_allowlist_is_pinned_literally():
    """Pinned by name, not from the source constants under test: only the system-log ``all``
    route is a read among the system-log routes, and the other listed routes are unchanged."""
    assert {r.name for r in rp.READ_POST_ROUTES} == {
        "network-v2-traffic-flows",
        "network-v2-system-log-all",
        "network-classic-stat-session",
        "network-classic-stat-report",
        "site-manager-isp-metrics-query",
    }
    assert [r.template for r in rp.READ_POST_ROUTES if "system-log" in r.template] == [
        "/v1/connector/consoles/{console}/proxy/network/v2/api/site/{site}/system-log/all"
    ]
    assert system_log.EVIDENCE_READ_CLASSES == ("all",)
    prefix = f"/v1/connector/consoles/{HOST_ID}/proxy/network/v2/api/site/default/system-log"
    for log_class in (
        "device-alert",
        "client-alert",
        "admin-activity",
        "update-alert",
        "threat-alert",
        "next-ai-alert",
        "vpn-alert",
        "critical",
        "triggers",
        "count",
    ):
        assert read_only.is_write_request("POST", f"{prefix}/{log_class}") is True, log_class


@pytest.mark.parametrize(
    ("name", "extra"),
    [
        ("get_system_log", {}),
        ("get_system_log", {"log_class": "all"}),
        ("get_system_log", {"log_class": "device-alert"}),
        ("list_network_events", {}),
        ("list_network_events", {"view": "all"}),
        ("list_network_events", {"view": "device-alert"}),
        ("list_ips_events", {}),
    ],
)
async def test_native_system_log_writes_preview_under_dry_run_on_every_class(
    monkeypatch, name, extra
):
    """The native readers are 0.7.1 writes on every class, ``all`` included although that route
    is read-allowlisted for the collector: under dry-run policy they send 0 upstream POSTs and
    return the preview (the write audit and the area guards see a write, as before)."""
    from tests import tool_args
    from tests import upstream_harness as uh

    upstream = uh.FakeUpstream(replay_recordings=False)
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    client = uh.install(monkeypatch, upstream)
    try:
        tool = {t.name: t for t in await server.mcp.list_tools()}[name]
        args = {k: v for k, v in tool_args.generated_args(tool).items() if k in ("host", "site")}
        result = await server.mcp.call_tool(name, {**args, **extra})
    finally:
        await client.close()
    payload = uh.result_payload(result)
    assert payload["status"] == "dry_run" and payload["sent"] is False, payload
    assert [row.path for row in upstream.served if row.method == "POST"] == []
