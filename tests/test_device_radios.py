"""Recorded AP-radio round trips; all HTTP replaced, real resolution/guards retained."""

from __future__ import annotations

import copy
import ipaddress
import re

import httpx
import pytest

from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.tools.device_radios import _get_device_radios, _update_device_radio


@pytest.fixture
def radio_upstream():
    # These cases intentionally select generated ARG_* AP identities rather than
    # a recorded device, so opt into the synthetic fixture mode explicitly.
    return uh.FakeUpstream(replay_recordings=False)


def install(mp, up, **settings):
    client = uh.install(mp, up, **settings)
    return client, server._registry


def table():
    return copy.deepcopy(uh.recorded("ap_radio_table.json")["body"]["data"][0]["radio_table"])


async def test_full_table_preserves_order_and_every_unrequested_field(monkeypatch, radio_upstream):
    c, r = install(monkeypatch, radio_upstream)
    original = table()
    changes = {"na": {"channel": 44, "ht": 40}, "ng": {"tx_power_mode": "low"}}
    result = await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, changes)
    expected = copy.deepcopy(original)
    for row in expected:
        row.update(changes.get(row["radio"], {}))
        row["channel"] = str(row["channel"])
    writes = radio_upstream.writes()
    assert len(writes) == 1
    assert writes[0].path.endswith("/rest/device/" + uh.ARG_HEX)
    assert writes[0].sent_json == {"radio_table": expected}
    assert result["readBefore"] == original
    assert result["readAfter"] == expected
    assert result["changed"]["na"]["channel"] == {"before": "auto", "after": "44"}
    assert result["noOp"] is False
    assert result["response"] == writes[0].body
    assert result["radio_table_stats"]
    reads = [s.path for s in radio_upstream.served if s.method == "GET"]
    assert not any("/rest/device" in p for p in reads)
    assert sum(p.endswith("/stat/device/" + uh.ARG_MAC) for p in reads) == 2
    await c.close()


async def test_get_preserves_device_and_exposes_each_band(monkeypatch, radio_upstream):
    c, r = install(monkeypatch, radio_upstream)
    out = await _get_device_radios(c, r, uh.HOST, uh.SITE, uh.ARG_HEX)
    assert out["_radio_table"] == table()
    assert set(out["_radios"]) == {"ng", "na", "6e"}
    assert out["_device"]["radio_table"] == table()
    assert out["_device"] in out["data"]
    assert not radio_upstream.writes()
    await c.close()


@pytest.mark.parametrize("global_dry", [False, True])
async def test_dry_run_exact_full_body_and_diff(monkeypatch, radio_upstream, global_dry):
    c, r = install(monkeypatch, radio_upstream, dry_run=global_dry)
    out = await _update_device_radio(
        c, r, uh.HOST, uh.SITE, uh.ARG_MAC, {"na": {"ht": 40}}, dry_run=not global_dry
    )
    assert not radio_upstream.writes()
    assert out["preview"]["body"]["radio_table"] == [
        dict(row, ht=40) if row["radio"] == "na" else row for row in table()
    ]
    assert out["diff"]["na"]["ht"] == {"before": 80, "after": 40}
    await c.close()


async def test_noop_reads_fresh_without_put(monkeypatch, radio_upstream):
    c, r = install(monkeypatch, radio_upstream)
    out = await _update_device_radio(
        c, r, uh.HOST, uh.SITE, uh.ARG_MAC, {"na": {"channel": "auto", "ht": 80}}
    )
    assert out["noOp"] is True
    assert out["changed"] == {}
    assert out["readBefore"] == out["readAfter"] == table()
    assert not radio_upstream.writes()
    await c.close()


@pytest.mark.parametrize(
    "changes",
    [
        {"bad": {"ht": 40}},
        {"ng": {"channel": 44}},
        {"na": {"channel": 6}},
        {"6e": {"channel": 44}},
        {"ng": {"ht": 80}},
        {"na": {"ht": 320}},
        {"ng": {"tx_power": 5}},
        {"ng": {"tx_power": 24}},
        {"ng": {"tx_power_mode": "loud"}},
        {"ng": {"min_rssi": "-70"}},
        {"ng": {"ht": True}},
        {"ng": {"min_rssi_enabled": 1}},
        {"ng": {"channel": None}},
        {"ng": {"unsupported": 42}},
    ],
)
async def test_invalid_changes_never_put(monkeypatch, radio_upstream, changes):
    c, r = install(monkeypatch, radio_upstream)
    with pytest.raises(Exception):
        await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, changes)
    assert not radio_upstream.writes()
    await c.close()


@pytest.mark.parametrize(
    "changes",
    [
        {"na": {"ht": 160}},
        {"na": {"ht": 240}},
        {"6e": {"ht": 320}},
        {"ng": {"min_rssi": -70, "min_rssi_enabled": False}},
        {"ng": {"tx_power": 23, "tx_power_mode": "custom"}},
        {"6e": {"channel": "69"}},
    ],
)
async def test_reported_capabilities_allow_changes(monkeypatch, radio_upstream, changes):
    c, r = install(monkeypatch, radio_upstream)
    await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, changes)
    assert len(radio_upstream.writes()) == 1
    await c.close()


@pytest.mark.parametrize("changes", [{"na": {"ht": 40}}, {"na": {"ht": 80}}])
async def test_read_only_blocks_changes_and_noop(monkeypatch, radio_upstream, changes):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    c, r = install(monkeypatch, radio_upstream, read_only=True)
    with pytest.raises(Exception, match="(?i)read.only"):
        await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, changes)
    assert not radio_upstream.writes()
    await c.close()


async def test_unknown_device_lists_choices(monkeypatch, radio_upstream):
    c, r = install(monkeypatch, radio_upstream)
    with pytest.raises(Exception) as err:
        await _update_device_radio(c, r, uh.HOST, uh.SITE, "02:00:5e:00:ff:ff", {"na": {"ht": 40}})
    assert uh.ARG_MAC in str(err.value) or uh.ARG_HEX in str(err.value)
    assert not radio_upstream.writes()
    await c.close()


async def test_registered_new_tools_driven_automatically(monkeypatch, radio_upstream):
    tools = await server.mcp.list_tools()
    selected = {t.name: t for t in tools if t.name in {"get_device_radios", "update_device_radio"}}
    assert set(selected) == {"get_device_radios", "update_device_radio"}
    c, _ = install(monkeypatch, radio_upstream)
    for name, t in selected.items():
        await server.mcp.call_tool(name, tool_args.generated_args(t))
    assert radio_upstream.writes()
    await c.close()


async def test_owned_host_routes_reads_and_writes_to_second_key(
    monkeypatch, multikey_client, multikey_registry
):
    up = uh.FakeUpstream(hosts_by_key={"k-alpha": [], "k-beta": [copy.deepcopy(uh.HOST_RECORD)]})

    async def http_session(key):
        if key.label not in multikey_client._clients:
            multikey_client._clients[key.label] = httpx.AsyncClient(
                base_url=multikey_client._settings.api_base_url,
                headers={"X-API-KEY": key.key},
                transport=httpx.MockTransport(up),
            )
        return multikey_client._clients[key.label]

    monkeypatch.setattr(multikey_client, "_get_client", http_session)
    await _update_device_radio(
        multikey_client, multikey_registry, uh.HOST, uh.SITE, uh.ARG_MAC, {"na": {"ht": 40}}
    )
    nonresolution = [s for s in up.served if not s.resolution]
    assert nonresolution and all(s.api_key == "k-beta" for s in nonresolution)
    await multikey_client.close()


@pytest.mark.parametrize(
    "band,width,cap",
    [("na", 160, "has_ht160"), ("na", 240, "has_eht240"), ("6e", 320, "has_eht320")],
)
async def test_missing_reported_width_cap_never_put(monkeypatch, radio_upstream, band, width, cap):
    original = radio_upstream._rec

    def without_cap(n, tag):
        row = original(n, tag)
        for radio in row.get("radio_table", []):
            if radio["radio"] == band:
                radio.pop(cap, None)
        return row

    monkeypatch.setattr(radio_upstream, "_rec", without_cap)
    c, r = install(monkeypatch, radio_upstream)
    with pytest.raises(Exception):
        await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, {band: {"ht": width}})
    assert not radio_upstream.writes()
    await c.close()


async def test_ambiguous_device_never_selects_first(monkeypatch, radio_upstream):
    original = radio_upstream._generic

    def ambiguous(req):
        body = original(req)
        if req.method == "GET" and req.url.path.endswith("/stat/device"):
            duplicate = copy.deepcopy(
                next(row for row in body["data"] if row.get("mac") == uh.ARG_MAC)
            )
            duplicate["_id"] = "0000000000000000000000bb"
            duplicate["id"] = "00000000-0000-4000-8000-0000000000bb"
            body["data"].append(duplicate)
        return body

    monkeypatch.setattr(radio_upstream, "_generic", ambiguous)
    c, r = install(monkeypatch, radio_upstream)
    with pytest.raises(Exception, match="(?i)ambiguous"):
        await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, {"na": {"ht": 40}})
    assert not radio_upstream.writes()
    await c.close()


async def test_timeout_reports_unknown_outcome_and_never_retries(monkeypatch, radio_upstream):
    c, r = install(monkeypatch, radio_upstream)
    requests = []
    original = c._get_client

    async def timed(key):
        session = await original(key)

        async def handler(req):
            if req.method == "PUT":
                requests.append(req)
                raise httpx.ReadTimeout("probe radio timeout", request=req)
            return radio_upstream(req)

        session._transport = httpx.MockTransport(handler)
        return session

    monkeypatch.setattr(c, "_get_client", timed)
    # client.unknown_outcome_hint (52bf03a4): "... outcome unknown: the write may have been
    # applied; it was not retried. Verify with <read tool> before retrying."
    with pytest.raises(
        Exception, match=r"outcome unknown.*Verify with .* before retrying"
    ) as raised:
        await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, {"na": {"ht": 40}})
    assert str(raised.value).count("outcome unknown") == 1
    assert getattr(raised.value, "request_sent", None) is True
    assert len(requests) == 1
    await c.close()


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("changes", [{"na": {"ht": 40}}, {"na": {"ht": 80}}])
async def test_connector_optout_blocks_before_reads(monkeypatch, radio_upstream, dry_run, changes):
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", "family:connector=deny")
    c, r = install(monkeypatch, radio_upstream)
    with pytest.raises(Exception, match="family:connector=deny"):
        await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, changes, dry_run=dry_run)
    assert not radio_upstream.served
    await c.close()


async def test_classic_id_targets_same_mac_full_table(monkeypatch, radio_upstream):
    c, r = install(monkeypatch, radio_upstream)
    await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_HEX, {"na": {"ht": 40}})
    assert radio_upstream.writes()[0].path.endswith("/rest/device/" + uh.ARG_HEX)
    assert len(radio_upstream.writes()[0].sent_json["radio_table"]) == len(table())
    assert any(s.path.endswith("/stat/device/" + uh.ARG_MAC) for s in radio_upstream.served)
    await c.close()


@pytest.mark.parametrize("changes", [{}, {"na": {}}])
async def test_empty_radio_update_rejected_before_any_reads(monkeypatch, radio_upstream, changes):
    c, r = install(monkeypatch, radio_upstream)
    with pytest.raises(Exception, match="(?i)empty|at least one|no fields"):
        await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, changes)
    assert not radio_upstream.served
    await c.close()


def test_diff_distinguishes_boolean_from_integer_readback():
    from unifi_fabric.tools.device_radios import _diff

    before = [{"radio": "na", "min_rssi_enabled": True}]
    after = [{"radio": "na", "min_rssi_enabled": 1}]
    assert _diff(before, after) == {"na": {"min_rssi_enabled": {"before": True, "after": 1}}}


@pytest.mark.parametrize("band,channel", [("ng", 44), ("na", "banana"), ("6e", 44)])
async def test_invalid_intrinsic_channel_rejected_before_any_reads(
    monkeypatch, radio_upstream, band, channel
):
    c, r = install(monkeypatch, radio_upstream)
    with pytest.raises(Exception, match="(?i)channel"):
        await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, {band: {"channel": channel}})
    assert not radio_upstream.served
    await c.close()


def test_recorded_response_has_consistent_identifiers_and_anonymized_ssids():
    fixture = uh.recorded("ap_radio_table.json")
    row = fixture["body"]["data"][0]
    assert fixture["request"]["path"].endswith("/" + row["mac"])
    assert fixture["body"]["meta"]["rc"] == "ok"
    assert "reconstructed" not in fixture["source"]

    def eui64_from_anonymized_mac(text):
        # A link-local whose interface id carries ff:fe in the middle is an EUI-64 and
        # encodes a hardware MAC; it must come from an anonymized 02:00:5e MAC.
        for token in re.findall(r"fe80:[0-9a-f:]*", text, re.IGNORECASE):
            iid = ipaddress.IPv6Address(token.rstrip(":")).packed[8:]
            if iid[3:5] != b"\xff\xfe":
                continue
            mac = bytes([iid[0] ^ 0x02]) + iid[1:3] + iid[5:]
            if mac[:3] != b"\x02\x00\x5e":
                return False
        return True

    def placeholder(text):
        # Secret-like x_* strings are zero-filled with at most a two-digit counter.
        body = text.removeprefix("SHA256:")
        return re.fullmatch(r"0*[0-9a-f]{0,2}", body) is not None and body.startswith("0")

    def anonymized(value, key=None):
        if isinstance(value, dict):
            return all(
                (not isinstance(v, str) or not v or v.startswith("name-"))
                if k in {"essid", "ssid"}
                else anonymized(v, k)
                for k, v in value.items()
            )
        if isinstance(value, list):
            return all(anonymized(v, key) for v in value)
        if isinstance(value, str):
            if isinstance(key, str) and key.startswith("x_") and value and not placeholder(value):
                return False
            return eui64_from_anonymized_mac(value)
        return True

    assert anonymized(fixture)


async def test_noop_requires_distinct_successful_read_after(monkeypatch, radio_upstream):
    c, r = install(monkeypatch, radio_upstream)
    original = radio_upstream._generic
    calls = []

    def fail_after(req):
        result = original(req)
        if req.method == "GET" and req.url.path.endswith("/stat/device/" + uh.ARG_MAC):
            calls.append(req)
            if len(calls) == 2:
                result["meta"] = {"rc": "error", "msg": "read-after rejected"}
        return result

    monkeypatch.setattr(radio_upstream, "_generic", fail_after)
    out = await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, {"na": {"ht": 80}})
    assert len(calls) == 2
    assert out["noOp"] is None
    assert out.get("_verified") is not True
    assert "read-after rejected" in out["readAfterError"]
    assert not radio_upstream.writes()
    await c.close()


async def test_write_needs_affirmative_classic_read_success(monkeypatch, radio_upstream):
    c, r = install(monkeypatch, radio_upstream)
    original = radio_upstream._generic

    def fail_after(req):
        result = original(req)
        if (
            req.method == "GET"
            and radio_upstream.writes()
            and req.url.path.endswith("/stat/device/" + uh.ARG_MAC)
        ):
            result["meta"] = {"rc": "error", "msg": "read-after rejected"}
        return result

    monkeypatch.setattr(radio_upstream, "_generic", fail_after)
    out = await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, {"na": {"ht": 40}})
    assert out["noOp"] is None
    assert out.get("_verified") is not True
    assert "read-after rejected" in out["readAfterError"]
    assert len(radio_upstream.writes()) == 1
    await c.close()


async def test_invalid_channel_lists_valid_choices(monkeypatch, radio_upstream):
    c, r = install(monkeypatch, radio_upstream)
    with pytest.raises(ValueError, match="44"):
        await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, {"na": {"channel": 6}})
    assert not radio_upstream.served
    await c.close()


@pytest.mark.parametrize("mode", ["duplicate_band", "changed_identity", "ignored_write"])
async def test_unsuccessful_verification_keeps_write_evidence(monkeypatch, radio_upstream, mode):
    c, r = install(monkeypatch, radio_upstream)
    original = radio_upstream._generic

    def alter_after(req):
        result = original(req)
        if (
            req.method == "GET"
            and radio_upstream.writes()
            and req.url.path.endswith("/stat/device/" + uh.ARG_MAC)
        ):
            record = result["data"][0]
            if mode == "duplicate_band":
                record["radio_table"].append(copy.deepcopy(record["radio_table"][0]))
            elif mode == "changed_identity":
                record["_id"] = "0000000000000000000000bb"
            else:
                next(row for row in record["radio_table"] if row["radio"] == "na")["ht"] = 80
        return result

    monkeypatch.setattr(radio_upstream, "_generic", alter_after)
    out = await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, {"na": {"ht": 40}})
    assert out["response"] == radio_upstream.writes()[0].body
    assert len(radio_upstream.writes()) == 1
    assert out["_verified"] is not True
    if mode == "ignored_write":
        assert out["_verified"] is False
        assert out["noOp"] is True
        assert out["changed"] == {}
    else:
        assert out["changed"] is None
        assert out["noOp"] is None
        assert out["readAfterError"]
    await c.close()


@pytest.mark.parametrize("bad", [None, [], "bad", 42])
def test_classic_success_rejects_malformed_shapes(bad):
    from unifi_fabric.client import UniFiConnectionError
    from unifi_fabric.tools._device_config import require_classic_success

    with pytest.raises(UniFiConnectionError):
        require_classic_success(bad, "/stat/device")


@pytest.mark.parametrize(
    "changes",
    [
        {"na": {"ht": -1}},
        {"na": {"ht": 0}},
        {"unknown": {"ht": 40}},
        {"na": {"channel": []}},
        {"na": {"tx_power": "low"}},
        {"na": {"tx_power": True}},
        {"na": {"ht": "40"}},
    ],
)
async def test_radio_syntax_rejected_before_resolution(monkeypatch, radio_upstream, changes):
    c, r = install(monkeypatch, radio_upstream)
    with pytest.raises(ValueError):
        await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, changes)
    assert not radio_upstream.served
    await c.close()


async def test_radio_read_preserves_all_records_and_colliding_envelope_fields(
    monkeypatch, radio_upstream
):
    radio_upstream.mode = "big"
    radio_upstream.big_items = 7
    radio_upstream.envelope_extra = {
        "radio_table": {"upstream": "table"},
        "radio_table_stats": ["upstream stats"],
        "traceId": "unchanged-trace",
    }
    c, r = install(monkeypatch, radio_upstream)
    out = await _get_device_radios(c, r, uh.HOST, uh.SITE, uh.ARG_HEX)
    raw = [s.body for s in radio_upstream.served if s.path.endswith("/stat/device")][-1]
    assert len(raw["data"]) == 7
    assert {k: out[k] for k in raw} == raw
    assert out["_device"] in raw["data"]
    assert out["_radio_table"] == table()
    await c.close()


@pytest.mark.parametrize("failure", ["429", "runtime", "classic_error"])
async def test_ap_write_response_survives_every_read_after_failure(
    monkeypatch, radio_upstream, failure
):
    original = radio_upstream.__class__.__call__

    def fail_after(self, req):
        if req.method == "GET" and self.writes():
            if failure == "runtime":
                raise RuntimeError("unexpected verification failure")
            body = {"meta": {"rc": "error", "msg": "read-after rejected"}, "data": []}
            status = 429 if failure == "429" else 200
            self._record(req, status, body, False)
            return httpx.Response(status, json=body)
        return original(self, req)

    monkeypatch.setattr(radio_upstream.__class__, "__call__", fail_after)
    c, r = install(monkeypatch, radio_upstream)
    out = await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, {"na": {"ht": 40}})
    assert out["response"] == radio_upstream.writes()[0].body
    assert out["readAfterError"]
    assert out["_noOp"] is out["_verified"] is out["noOp"] is None
    if failure == "429":
        assert len([s for s in radio_upstream.served if s.status == 429]) == 6
    await c.close()


@pytest.mark.parametrize("rc", ["error", None, "unexpected"])
async def test_classic_put_requires_affirmative_success(monkeypatch, radio_upstream, rc):
    from unifi_fabric.client import UniFiConnectionError

    original = radio_upstream.__class__.__call__

    def reject_put(self, req):
        response = original(self, req)
        if req.method == "PUT":
            body = {
                "meta": {"rc": rc, "msg": "put-rejected"},
                "data": [],
                "traceId": "complete-put-rejection",
            }
            self.served[-1].body = body
            return httpx.Response(200, json=body)
        return response

    monkeypatch.setattr(radio_upstream.__class__, "__call__", reject_put)
    c, r = install(monkeypatch, radio_upstream)
    with pytest.raises(UniFiConnectionError, match="complete-put-rejection"):
        await _update_device_radio(c, r, uh.HOST, uh.SITE, uh.ARG_MAC, {"na": {"ht": 40}})
    assert len(radio_upstream.writes()) == 1
    assert radio_upstream.served[-1].method == "PUT"
    await c.close()


@pytest.mark.parametrize("changes", [{}, {"na": {}}])
async def test_registered_empty_radio_update_sends_zero_requests(
    monkeypatch, radio_upstream, changes
):
    c, _ = install(monkeypatch, radio_upstream)
    try:
        with pytest.raises(Exception, match="(?i)empty|at least one|no fields"):
            await server.mcp.call_tool(
                "update_device_radio",
                {
                    "host": uh.HOST,
                    "site": uh.SITE,
                    "device": uh.ARG_MAC,
                    "radios": changes,
                },
            )
        assert not radio_upstream.served
    finally:
        await c.close()


async def test_registered_radio_width_schema_matches_positive_runtime_constraint():
    from unifi_fabric.tools.device_radios import RadioChanges

    tool = await server.mcp.get_tool("update_device_radio")
    schema = tool.parameters["$defs"]["RadioChanges"]["properties"]["ht"]
    assert schema.get("minimum") == 1, schema
    with pytest.raises(ValueError):
        RadioChanges.model_validate({"ht": 0})
    assert RadioChanges.model_validate({"ht": 1}).ht == 1


@pytest.mark.parametrize("name", ["update_network", "update_wlan_config", "update_camera"])
async def test_registered_sibling_empty_update_sends_zero_requests(
    monkeypatch, radio_upstream, name
):
    from unifi_fabric.write_body import body_argument

    tool = await server.mcp.get_tool(name)
    arg = body_argument(tool)
    assert arg is not None
    args = {**tool_args.generated_args(tool), arg: {}}
    c, _ = install(monkeypatch, radio_upstream)
    try:
        with pytest.raises(Exception, match="(?i)empty|at least one|no fields"):
            await server.mcp.call_tool(name, args)
        assert not radio_upstream.served
    finally:
        await c.close()


@pytest.mark.parametrize("redact", [False, True])
def test_malformed_radio_record_redacts_interpolated_credentials_when_enabled(redact):
    from unifi_fabric.client import UniFiConnectionError
    from unifi_fabric.redaction import write_redaction_scope
    from unifi_fabric.tools.device_radios import _radio_rows, _radios_by_band

    secret = "RADIO_SECRET_SENTINEL"
    identifier = f'{{"password":"{secret}"}}'
    row = {"_id": identifier, "radio": identifier}
    with write_redaction_scope(redact):
        with pytest.raises(UniFiConnectionError) as exc:
            _radio_rows(row, "radio_table")
        assert (secret in str(exc.value)) is not redact
        with pytest.raises(ValueError) as exc:
            _radios_by_band([row, row])
        assert (secret in str(exc.value)) is not redact


@pytest.mark.parametrize(
    "body",
    [
        [{"password": "CLASSIC_SECRET_SENTINEL"}],
        {"meta": {"rc": "error"}, "data": [{"password": "CLASSIC_SECRET_SENTINEL"}]},
    ],
)
def test_classic_device_error_uses_shared_credential_formatter(body):
    from unifi_fabric.client import UniFiConnectionError
    from unifi_fabric.redaction import write_redaction_scope
    from unifi_fabric.tools._device_config import require_classic_success

    with write_redaction_scope(True), pytest.raises(UniFiConnectionError) as exc:
        require_classic_success(body, "/stat/device")
    assert "CLASSIC_SECRET_SENTINEL" not in str(exc.value)


async def test_classic_success_accepts_body_without_meta():
    from unittest.mock import AsyncMock

    from unifi_fabric.tools._device_config import update_device_config

    client = AsyncMock()
    client.dry_run = False
    client.put.return_value = {"data": []}
    read_after = AsyncMock(return_value=({"meta": {"rc": "ok"}}, {"a": 2}, {}))
    result = await update_device_config(
        client,
        "/synthetic",
        {"a": 1},
        {"a": 2},
        {"a": 2},
        read_after,
        lambda a, b: {} if a == b else {"a": b["a"]},
        key=None,
    )
    assert result["_verified"] is True
    read_after.assert_awaited_once()
