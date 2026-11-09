"""Apps behaviours (asset paths, manual paging, write results) not already covered by an
invariant in
``tests/test_invariants_paging_ids_and_relays.py``."""

from __future__ import annotations

import logging
from urllib.parse import parse_qs

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric.tools._continuation import encode_continuation

TOOLS = cti.TOOLS
_call = cti._call


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _args(name: str, **over):
    return {**tool_args.generated_args(TOOLS[name]), **over}


# --- InnerSpace asset filename: a '.'/'..' segment fails locally, before the host lookup ---
# (the spec's {filename} is any 1-255 character string; a '..' run inside one segment
# is sent percent-encoded, never refused.)
@pytest.mark.parametrize("filename", ["x/../y.png", "..", "%2E%2E"])
async def test_asset_filename_traversal_segment_fails_before_any_request(monkeypatch, filename):
    up = uh.FakeUpstream()
    with pytest.raises(ToolError, match="path traversal"):
        await _call(
            monkeypatch,
            "get_innerspace_asset",
            up,
            _args("get_innerspace_asset", filename=filename),
        )
    assert up.served == [], [f"{s.method} {s.path}" for s in up.served]


@pytest.mark.parametrize("filename", ["a b.png", "a%2Fb.png", "a\\b.png", "a..png", "plan.."])
async def test_asset_filename_spec_strings_are_sent_as_one_segment(monkeypatch, filename):
    up = uh.FakeUpstream()
    await _call(
        monkeypatch,
        "get_innerspace_asset",
        up,
        _args("get_innerspace_asset", filename=filename),
    )
    assert [s.path.rsplit("/", 1)[-1] for s in up.served if "/assets/" in s.path] == [filename]


async def test_asset_filename_with_single_dots_is_fetched(monkeypatch):
    up = uh.FakeUpstream()
    await _call(
        monkeypatch,
        "get_innerspace_asset",
        up,
        _args("get_innerspace_asset", filename="floor.plan.v2.png"),
    )
    assert any(s.path.endswith("/floor.plan.v2.png") for s in up.served)


# --- collect_protect_device_changes names the real key -------------------------------------
def test_collect_protect_device_changes_names_the_truncated_key():
    desc = TOOLS["collect_protect_device_changes"].description or ""
    params = str(TOOLS["collect_protect_device_changes"].parameters)
    assert "`truncated=true`" not in desc + params
    assert "_truncated=true" in params


# --- connector PUT/PATCH/DELETE: changed is present only when noOp is non-null -------------
@pytest.mark.parametrize(
    "name", ["fabric_connector_put", "fabric_connector_patch", "fabric_connector_delete"]
)
async def test_connector_changed_presence_is_documented_and_true(monkeypatch, name):
    desc = " ".join((TOOLS[name].description or "").split())
    assert "changed (= not noOp) is present only when noOp is non-null" in desc
    up = uh.FakeUpstream()
    args = {"host": uh.HOST, "path": "access/api/probe/thing"}
    payload = uh.result_payload(
        await _call(monkeypatch, name, up, args, env={"UNIFI_WRITE_POLICY": "dry-run"})
    )
    assert payload["noOp"] is None and "changed" not in payload, payload


# --- POS ingest amount follows posTransactionRequest.amount (number, minimum 0) -------------
def _txn(amount):
    return {"type": "sale", "externalId": "probe-txn-1", "amount": amount}


@pytest.mark.parametrize("amount", [None, "12.50", True, -1])
async def test_pos_amount_off_spec_fails_before_any_request(monkeypatch, amount):
    up = uh.FakeUpstream()
    args = _args("pos_ingest_transaction", transaction=_txn(amount))
    with pytest.raises(ToolError, match=r"amount.* >= 0"):
        await _call(monkeypatch, "pos_ingest_transaction", up, args)
    assert up.served == []


@pytest.mark.parametrize("amount", [0, 12.5, 7])
async def test_pos_amount_on_spec_is_sent(monkeypatch, amount):
    up = uh.FakeUpstream()
    await _call(
        monkeypatch,
        "pos_ingest_transaction",
        up,
        _args("pos_ingest_transaction", transaction=_txn(amount)),
    )
    assert [w.sent_json["amount"] for w in up.writes()] == [amount]


# --- Upload: the spec's file part has no minLength and the body is not required ------------
async def test_upload_empty_file_content_is_sent(monkeypatch):
    up = uh.FakeUpstream()
    args = _args("upload_protect_file", filename="empty.png", file_content_base64="")
    await _call(monkeypatch, "upload_protect_file", up, args)
    assert [w.method for w in up.writes()] == ["POST"]


# --- list_carrier_subscribers: spec limit/cursor pass-through, default drain ----------------
@pytest.mark.parametrize(
    ("paging", "query", "physical", "expected_requests"),
    [
        ({"limit": 10}, {"limit": ["10"]}, 3, 3),
        ({"limit": 10}, {"limit": ["10"]}, 10, 1),
        ({"cursor": "c-2"}, {"cursor": ["c-2"]}, 3, 1),
    ],
)
async def test_carrier_subscribers_manual_page_is_one_verbatim_page(
    monkeypatch, paging, query, physical, expected_requests
):
    up = uh.FakeUpstream(mode="paged", page_items=physical)
    payload = uh.result_payload(await _call(monkeypatch, "list_carrier_subscribers", up, paging))
    reads = [s for s in up.served if s.path.endswith("/v1/carrier/subscribers")]
    # The old one-request assertion encoded truncation when the fixture clamped limit10 to3.
    assert len(reads) == expected_requests, [s.query for s in reads]
    sent = parse_qs(reads[0].query)
    assert all(sent.get(k) == v for k, v in query.items()), sent
    if "cursor" in paging:
        assert payload == reads[0].body, "a native manual cursor page stays verbatim"
    else:
        records = [record for read in reads for record in read.body["data"]]
        expected = {
            **reads[0].body,
            "data": records,
            "_count": len(records),
            "meta": reads[-1].body["meta"],
            "_pageSize": {
                "requested": 10,
                "sent": [10] * expected_requests,
                "effective": physical,
                "returned": len(records),
            },
        }
        if expected_requests == 1:
            expected["_continuation"] = encode_continuation(
                {"cursor": reads[0].body["meta"]["nextCursor"], "limit": 10}
            )
        assert payload == expected  # Exact ordered records and every native envelope field.
        assert [parse_qs(read.query) for read in reads] == [
            {"limit": ["10"], **({"cursor": [f"c{i}"]} if i else {})}
            for i in range(expected_requests)
        ]


async def test_carrier_subscribers_default_still_drains(monkeypatch):
    up = uh.FakeUpstream(mode="paged")
    await _call(monkeypatch, "list_carrier_subscribers", up, {})
    assert len([s for s in up.served if s.path.endswith("/v1/carrier/subscribers")]) >= 3
    assert up.undrained() == []


# --- search_across_sites: each errors entry carries key and a reason string ---------------
async def test_search_across_sites_errors_carry_key_and_reason(monkeypatch):
    up = uh.FakeUpstream(hosts_by_key=cti._two_key_hosts(), failing_keys=frozenset({"k-beta"}))
    payload = uh.result_payload(
        await _call(monkeypatch, "search_across_sites", up, {"query": "probe"}, keys=cti._KEYS)
    )
    beta = next(k.label for k in cti._KEYS if k.key == "k-beta")
    errors = payload["errors"]
    assert errors and all(set(e) == {"key", "siteId", "scope", "reason"} for e in errors), errors
    assert all(isinstance(e["reason"], str) for e in errors), errors
    assert [e for e in errors if e["scope"] == "sites"][0]["key"] == beta, errors


# --- Mobility: verified is null when the read-after fails ----------------------------------
async def test_mobility_verified_is_null_when_the_read_after_fails(monkeypatch):
    up = uh.FakeUpstream(fail_reads_after_write=True)
    name = "update_mobility_device_name"
    payload = uh.result_payload(await _call(monkeypatch, name, up))
    assert payload["status"] == "updated" and payload["verified"] is None, payload
    assert payload.get("readAfterError"), payload
