"""A read-merge-write never loses a stored secret under ``UNIFI_REDACT_SECRETS``.

The whole-record writes read the stored record, lay the caller's change over it and
send the record back. Their internal read must not go through the opt-in response mask:
a masked leaf would be dropped from the write (the documented rule for a
``***REDACTED***`` value in a write body), so the stored secret would be sent absent and a
replace-semantics route would clear it. The write body under redaction must equal the
body without it, and nothing the caller sees may carry the stored secret.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import tools_by_name
from unifi_fabric import refusals, route_secrets, server
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.network import network_routing_topology as rt
from unifi_fabric.families.protect import protect_automation_backup as pab
from unifi_fabric.families.vpn import network_vpn_dns as vd
from unifi_fabric.redaction import REDACTION_MASK, mask_error_text

HOST_ID = "host-1"
SECRET = "synthetic-stored-secret-0001"
SECRET_2 = "synthetic-stored-secret-0002"
RECORD = "65f1c0ffee0123456789abcd"
SERVER = "65f1c0ffee0123456789abc0"
V2 = f"/v1/connector/consoles/{HOST_ID}/proxy/network/v2/api/site/default"
PROTECT = f"/v1/connector/consoles/{HOST_ID}/proxy/protect/api"


class Upstream:
    """Serves fixed GET bodies and records every write body."""

    def __init__(self, reads: dict[str, Any]) -> None:
        self.reads = reads
        self.writes: list[tuple[str, str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET":
            return httpx.Response(200, json=self.reads[path])
        body = json.loads(request.content) if request.content else None
        self.writes.append((request.method, path, body))
        return httpx.Response(200, json={"ok": True})


def _client(upstream: Upstream, *, redact: bool) -> UniFiClient:
    client = UniFiClient(Settings(api_key="k" * 24, redact_secrets=redact))
    http = httpx.AsyncClient(
        base_url=client._settings.api_base_url, transport=httpx.MockTransport(upstream)
    )

    async def get_client(_key: Any) -> httpx.AsyncClient:
        return http

    client._get_client = get_client  # type: ignore[method-assign]
    return client


@pytest.fixture
def resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    async def site(_registry: Any, _host: str, _site: str) -> tuple[None, str, str]:
        return None, HOST_ID, "default"

    async def vpn_server(*_args: Any) -> tuple[None, str, str, str]:
        return None, HOST_ID, "default", SERVER

    async def protect(_registry: Any, _host: str) -> tuple[None, str]:
        return None, HOST_ID

    monkeypatch.setattr(vd, "_site", site)
    monkeypatch.setattr(vd, "_vpn_server", vpn_server)
    monkeypatch.setattr(rt, "_site", site)
    monkeypatch.setattr(pab, "_resolve", protect)


def _ipsec() -> tuple[dict[str, Any], Any]:
    reads = {
        f"{V2}/settings/ipsec": {"enabled": False, "mode": "a", "x_ipsec_pre_shared_key": SECRET}
    }

    async def call(client: UniFiClient) -> Any:
        return await vd.update_ipsec_settings(client, None, "h", "s", {"enabled": True})

    return reads, call


def _wireguard() -> tuple[dict[str, Any], Any]:
    user = {"_id": RECORD, "name": "laptop", "private_key": SECRET, "preshared_key": SECRET_2}
    reads = {f"{V2}/wireguard/{SERVER}/users": [user]}

    async def call(client: UniFiClient) -> Any:
        return await vd.update_wireguard_users(
            client, None, "h", "s", SERVER, [{"_id": RECORD, "name": "laptop-2"}]
        )

    return reads, call


def _routing(kind: str) -> tuple[dict[str, Any], Any]:
    record = {"_id": RECORD, "name": "r", "enabled": False, "password": SECRET}
    if kind == "bgp":
        reads = {f"{V2}/bgp/config/all": [record], f"{V2}/bgp/config": [record]}

        async def call(client: UniFiClient) -> Any:
            return await rt.update_bgp_config(client, None, "h", "s", RECORD, {"enabled": True})

    else:
        reads = {f"{V2}/ospf/router": [record]}

        async def call(client: UniFiClient) -> Any:
            return await rt.update_ospf_router(client, None, "h", "s", RECORD, {"enabled": True})

    return reads, call


def _automation() -> tuple[dict[str, Any], Any]:
    automation = {
        "id": RECORD,
        "name": "a",
        "enabled": True,
        "actions": [
            {
                "type": "webhook",
                "metadata": {
                    "url": "https://x.invalid",
                    "headers": {"X-Token": SECRET},
                    "auth": {"user": "u", "password": SECRET_2},
                },
            }
        ],
    }
    reads = {f"{PROTECT}/automations": [automation]}

    async def call(client: UniFiClient) -> Any:
        return await pab._update_protect_automation(client, None, "h", RECORD, {"enabled": False})

    return reads, call


CASES = {
    "update_ipsec_settings": _ipsec,
    "update_wireguard_users": _wireguard,
    "update_bgp_config": lambda: _routing("bgp"),
    "update_ospf_router": lambda: _routing("ospf"),
    "update_protect_automation": _automation,
}


async def _run(case: str, *, redact: bool) -> tuple[Upstream, Any]:
    reads, call = CASES[case]()
    upstream = Upstream(reads)
    client = _client(upstream, redact=redact)
    try:
        result = await call(client)
    finally:
        await client.close()
    return upstream, result


@pytest.mark.parametrize("case", sorted(CASES))
async def test_redacted_read_merge_write_keeps_the_stored_secret(resolved: None, case: str) -> None:
    plain, _ = await _run(case, redact=False)
    redacted, result = await _run(case, redact=True)
    assert len(plain.writes) == len(redacted.writes) == 1
    # The write under redaction is the write without it: the stored secret is sent back.
    assert redacted.writes == plain.writes
    assert SECRET in json.dumps(redacted.writes[0][2])
    # ... and never as the mask, and no field is reported as dropped.
    assert REDACTION_MASK not in json.dumps(redacted.writes[0][2])
    rendered = json.dumps(result)
    assert "_redactedFieldsNotSent" not in rendered
    # Nothing the caller sees carries the stored secret.
    assert SECRET not in rendered and SECRET_2 not in rendered


async def test_protect_automation_before_stays_masked(resolved: None) -> None:
    _, result = await _run("update_protect_automation", redact=True)
    metadata = result["_before"]["actions"][0]["metadata"]
    assert metadata["headers"] == REDACTION_MASK
    assert metadata["auth"] == REDACTION_MASK


async def test_redacted_read_merge_write_dry_run_preview_stays_masked(
    resolved: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    upstream, result = await _run("update_ipsec_settings", redact=True)
    assert upstream.writes == []
    assert result["preview"]["body"]["x_ipsec_pre_shared_key"] == REDACTION_MASK
    assert SECRET not in json.dumps(result)


def test_every_case_route_registers_its_response_secret() -> None:
    # The cases above exercise a registered response secret; a registry change that
    # drops one would make the test vacuous.
    for method, path, field in (
        ("GET", f"{V2}/settings/ipsec", "x_ipsec_pre_shared_key"),
        ("GET", f"{V2}/wireguard/{SERVER}/users", "private_key"),
        ("GET", f"{V2}/bgp/config/all", "password"),
        ("GET", f"{V2}/ospf/router", "password"),
        ("GET", f"{PROTECT}/automations", "headers"),
    ):
        fields = {f for e in route_secrets.matching(method, path) for f in e.response_fields}
        assert field in fields, (method, path)


# --------------------------------------------------------------------------- round trip
# The documented round trip: read the object redacted, edit one field, pass the whole
# object back. Every leaf the caller passes back as the mask keeps the stored value, in
# nested objects and in elements of a replaced array alike.


async def _round_trip(case: str) -> tuple[Upstream, Any]:
    from unifi_fabric.redaction import _make_redacting_fn

    reads, _call = CASES[case]()
    upstream = Upstream(reads)
    client = _client(upstream, redact=True)
    try:
        if case == "update_ipsec_settings":
            read = await client.get(f"{V2}/settings/ipsec")
            fn, args = vd.update_ipsec_settings, ("h", "s", {**read, "enabled": True})
        elif case == "update_wireguard_users":
            read = (await client.get(f"{V2}/wireguard/{SERVER}/users"))[0]
            fn, args = vd.update_wireguard_users, ("h", "s", SERVER, [{**read, "name": "x"}])
        elif case == "update_bgp_config":
            read = (await client.get(f"{V2}/bgp/config/all"))[0]
            fn, args = rt.update_bgp_config, ("h", "s", RECORD, {**read, "enabled": True})
        elif case == "update_ospf_router":
            read = (await client.get(f"{V2}/ospf/router"))[0]
            fn, args = rt.update_ospf_router, ("h", "s", RECORD, {**read, "enabled": True})
        else:
            read = (await client.get(f"{PROTECT}/automations"))[0]
            fn = pab._update_protect_automation
            args = ("h", RECORD, {**read, "enabled": False})
        assert REDACTION_MASK in json.dumps(read)  # the caller really holds a masked read
        upstream.writes.clear()
        # Through the server's own wrapper: the redaction scope and the dropped-field report.
        wrapped = _make_redacting_fn(fn, lambda: True)
        result = await wrapped(client, None, *args)
    finally:
        await client.close()
    return upstream, result


@pytest.mark.parametrize("case", sorted(CASES))
async def test_a_redacted_read_passed_back_keeps_the_stored_secret(
    resolved: None, case: str
) -> None:
    upstream, result = await _round_trip(case)
    assert len(upstream.writes) == 1
    sent = json.dumps(upstream.writes[0][2])
    assert SECRET in sent
    if case in {"update_wireguard_users", "update_protect_automation"}:
        assert SECRET_2 in sent
    assert REDACTION_MASK not in sent
    rendered = json.dumps(result)
    # Sent as stored, so not reported as left out; and never shown to the caller.
    assert "_redactedFieldsNotSent" not in rendered
    assert SECRET not in rendered and SECRET_2 not in rendered


# --------------------------------------------------------------------------- the helper
# keep_stored_secrets restores only the stored value at the SAME path, and only where the
# caller's value is EXACTLY the mask string. It never invents or moves a value.


class _Redacting:
    def __init__(self, redact: bool = True) -> None:
        self._settings = Settings(api_key="k" * 24, redact_secrets=redact)


def _keep(body: Any, stored: Any, requested: Any, *, redact: bool = True) -> Any:
    from unifi_fabric.client import keep_stored_secrets

    return keep_stored_secrets(_Redacting(redact), body, stored, requested)


def test_only_the_exact_mask_string_is_restored() -> None:
    stored = {"a": SECRET, "b": SECRET_2, "c": SECRET}
    requested = {"a": REDACTION_MASK, "b": REDACTION_MASK + " ", "c": "***redacted***"}
    body = dict(requested)
    out = _keep(body, stored, requested)
    assert out == {"a": SECRET, "b": REDACTION_MASK + " ", "c": "***redacted***"}


def test_a_value_is_restored_only_from_the_same_path() -> None:
    stored = {"x": {"key": SECRET}, "y": {"other": SECRET_2}, "list": [{"k": SECRET}]}
    requested = {
        "x": {"key": REDACTION_MASK},  # same path holds a stored value: restored
        "y": {"key": REDACTION_MASK},  # no stored value at y.key: never moved from x or y.other
        "z": REDACTION_MASK,  # no stored value at all: never invented
    }
    body = {"x": {}, "y": {}}  # the caller's masks were dropped upstream
    out = _keep(body, stored, requested)
    assert out == {"x": {"key": SECRET}, "y": {}}
    assert "z" not in out


def test_a_stored_mask_or_a_non_mask_change_is_left_alone() -> None:
    stored = {"a": REDACTION_MASK, "b": SECRET}
    requested = {"a": REDACTION_MASK, "b": "new-value"}
    body = {"a": REDACTION_MASK, "b": "new-value"}
    assert _keep(body, stored, requested) == body  # a caller's real change always wins


def test_with_redaction_off_a_mask_is_a_literal_value() -> None:
    stored = {"a": SECRET}
    body = {"a": REDACTION_MASK}
    assert _keep(body, stored, {"a": REDACTION_MASK}, redact=False) is body


# --------------------------------------------------------------------------- list elements
# A masked leaf is restored only into the SAME list element: matched by id/_id, else by all
# its non-mask fields, one to one. An element holding a mask that matches no single stored
# element refuses the write (named paths, nothing sent); it is never restored from another
# element and the mask is never dropped silently.

A = {"url": "https://a.invalid", "headers": {"X-Token": SECRET}}
B = {"url": "https://b.invalid", "headers": {"X-Token": SECRET_2}}


def _masked(element: dict[str, Any]) -> dict[str, Any]:
    return {**element, "headers": {"X-Token": REDACTION_MASK}}


def _dropped(element: dict[str, Any]) -> dict[str, Any]:
    return {**element, "headers": {}}  # what the write path keeps of a masked leaf


def test_an_unchanged_element_is_restored() -> None:
    requested = {"actions": [_masked(A), _masked(B)]}
    body = {"actions": [_dropped(A), _dropped(B)]}
    out = _keep(body, {"actions": [A, B]}, requested)
    assert out == {"actions": [A, B]}


def test_a_reorder_without_ids_restores_each_secret_to_its_own_element() -> None:
    # Distinct non-mask fields identify each element wherever it now stands.
    requested = {"actions": [_masked(B), _masked(A)]}
    body = {"actions": [_dropped(B), _dropped(A)]}
    out = _keep(body, {"actions": [A, B]}, requested)
    assert out == {"actions": [B, A]}  # never A's token with B's url


def test_a_reordered_edited_element_without_ids_is_refused_naming_the_path() -> None:
    edited = {**_masked(B), "url": "https://moved.invalid"}  # matches no stored element
    requested = {"actions": [edited, _masked(A)]}
    with pytest.raises(ValueError) as exc:
        _keep({"actions": [_dropped(edited), _dropped(A)]}, {"actions": [A, B]}, requested)
    text = str(exc.value)
    assert "actions[0].headers.X-Token" in text and "No write was sent" in text
    assert "actions[1]" not in text  # the unchanged element matched
    assert SECRET not in text and SECRET_2 not in text


def test_a_removal_without_ids_restores_the_remaining_element() -> None:
    requested = {"actions": [_masked(B)]}  # A removed
    out = _keep({"actions": [_dropped(B)]}, {"actions": [A, B]}, requested)
    assert out == {"actions": [B]}


def test_duplicate_non_mask_fields_are_refused() -> None:
    twin = {"url": "https://a.invalid", "headers": {"X-Token": SECRET_2}}  # same url as A
    requested = {"actions": [_masked(A)]}
    with pytest.raises(ValueError, match=r"actions\[0\]\.headers\.X-Token"):
        _keep({"actions": [_dropped(A)]}, {"actions": [A, twin]}, requested)


def test_two_elements_claiming_one_stored_element_are_refused() -> None:
    requested = {"list": [{"k": REDACTION_MASK}, {"k": REDACTION_MASK}]}
    with pytest.raises(ValueError, match=r"list\[0\]\.k, list\[1\]\.k"):
        _keep({"list": [{}, {}]}, {"list": [{"k": SECRET}]}, requested)


def test_an_id_matched_reorder_restores_each_secret_to_its_own_element() -> None:
    stored = {"peers": [{"_id": "p1", "key": SECRET}, {"_id": "p2", "key": SECRET_2}]}
    requested = {
        "peers": [{"_id": "p2", "key": REDACTION_MASK}, {"_id": "p1", "key": REDACTION_MASK}]
    }
    out = _keep({"peers": [{"_id": "p2"}, {"_id": "p1"}]}, stored, requested)
    assert out == {"peers": [{"_id": "p2", "key": SECRET_2}, {"_id": "p1", "key": SECRET}]}


def test_an_unknown_id_is_refused_even_when_other_fields_match() -> None:
    stored = {"peers": [{"_id": "p1", "key": SECRET}]}
    requested = {"peers": [{"_id": "p9", "key": REDACTION_MASK}]}
    with pytest.raises(ValueError, match=r"peers\[0\]\.key"):
        _keep({"peers": [{"_id": "p9"}]}, stored, requested)


def test_an_element_without_a_mask_is_sent_as_given() -> None:
    new = {"url": "https://new.invalid", "headers": {"X-Token": "caller-value"}}
    out = _keep({"actions": [new]}, {"actions": [A]}, {"actions": [new]})
    assert out == {"actions": [new]}


def test_list_matching_with_redaction_off_is_unchanged() -> None:
    requested = {"actions": [_masked(B), _masked(A)]}
    body = {"actions": [_masked(B), _masked(A)]}
    assert _keep(body, {"actions": [A, B]}, requested, redact=False) is body


async def _automation_round_trip(edit: Any) -> tuple[Upstream, Any]:
    """update_protect_automation with two webhook actions: read redacted, edit, write."""
    from unifi_fabric.redaction import _make_redacting_fn

    def action(url: str, token: str, password: str) -> dict[str, Any]:
        return {
            "type": "webhook",
            "metadata": {
                "url": url,
                "headers": {"X-Token": token},
                "auth": {"user": "u", "password": password},
            },
        }

    record = {
        "id": RECORD,
        "name": "a",
        "enabled": True,
        "actions": [
            action("https://one.invalid", SECRET, SECRET),
            action("https://two.invalid", SECRET_2, SECRET_2),
        ],
    }
    upstream = Upstream({f"{PROTECT}/automations": [record]})
    client = _client(upstream, redact=True)
    try:
        read = (await client.get(f"{PROTECT}/automations"))[0]
        wrapped = _make_redacting_fn(pab._update_protect_automation, lambda: True)
        try:
            result: Any = await wrapped(client, None, "h", RECORD, edit(read))
        except ValueError as exc:
            result = exc
    finally:
        await client.close()
    return upstream, result


async def test_protect_reordered_actions_without_ids_keep_each_secret(resolved: None) -> None:
    upstream, result = await _automation_round_trip(
        lambda read: {**read, "actions": read["actions"][::-1]}
    )
    assert not isinstance(result, Exception)
    sent = upstream.writes[0][2]["actions"]
    assert sent[0]["metadata"]["url"] == "https://two.invalid"
    assert sent[0]["metadata"]["headers"]["X-Token"] == SECRET_2  # its own, not action one's
    assert sent[1]["metadata"]["headers"]["X-Token"] == SECRET


async def test_protect_an_edited_reordered_action_is_refused_with_no_write(resolved: None) -> None:
    def edit(read: dict[str, Any]) -> dict[str, Any]:
        first, second = read["actions"]
        moved = {**second, "metadata": {**second["metadata"], "url": "https://moved.invalid"}}
        return {**read, "actions": [moved, first]}

    upstream, result = await _automation_round_trip(edit)
    assert isinstance(result, ValueError)
    # The route masks the whole headers and auth objects of a webhook action.
    assert "actions[0].metadata.headers" in str(result)
    assert "actions[0].metadata.auth" in str(result)
    assert "actions[1]" not in str(result)  # the unchanged action matched
    assert SECRET not in str(result) and SECRET_2 not in str(result)
    assert upstream.writes == []  # refused after the read, before any write


async def test_protect_a_removed_action_keeps_the_remaining_secret(resolved: None) -> None:
    upstream, result = await _automation_round_trip(
        lambda read: {**read, "actions": read["actions"][1:]}
    )
    assert not isinstance(result, Exception)
    sent = upstream.writes[0][2]["actions"]
    assert len(sent) == 1 and sent[0]["metadata"]["url"] == "https://two.invalid"
    assert sent[0]["metadata"]["headers"]["X-Token"] == SECRET_2
    assert sent[0]["metadata"]["auth"]["password"] == SECRET_2


# --------------------------------------------------------------------------- no mask is sent
# The write path drops a masked object field, never a masked list element. With redaction
# on, no exact mask may stay in a list element of the body: an unresolved one refuses the
# write before it is sent (G3W2-OAI-01); with redaction off the literal is sent as given.


async def _ipsec_with(
    stored: dict[str, Any], fields: dict[str, Any], *, redact: bool = True
) -> tuple[Upstream, Any]:
    from unifi_fabric.redaction import _make_redacting_fn

    upstream = Upstream({f"{V2}/settings/ipsec": stored})
    client = _client(upstream, redact=redact)
    try:
        wrapped = _make_redacting_fn(vd.update_ipsec_settings, lambda: redact)
        try:
            result: Any = await wrapped(client, None, "h", "s", fields)
        except ValueError as exc:
            result = exc
    finally:
        await client.close()
    return upstream, result


@pytest.mark.parametrize(
    ("case", "stored", "peers"),
    [
        ("report-repro: stored peers is []", {"enabled": False, "peers": []}, [REDACTION_MASK]),
        (
            "absent array index",
            {"enabled": False, "peers": ["p"]},
            [REDACTION_MASK, REDACTION_MASK],
        ),
        ("absent parent", {"enabled": False}, [REDACTION_MASK]),
        ("null parent", {"enabled": False, "peers": None}, [REDACTION_MASK]),
        ("mismatched parent type", {"enabled": False, "peers": {"k": "v"}}, [REDACTION_MASK]),
        (
            "object element, mismatched parent type",
            {"enabled": False, "peers": {"k": "v"}},
            [{"psk": REDACTION_MASK}],
        ),
        (
            "object element, stored elements exist but none matches",
            {"enabled": False, "peers": [{"name": "one", "psk": SECRET}]},
            [{"name": "edited", "psk": REDACTION_MASK}],
        ),
        (
            "mask as an element inside an object element, absent parent",
            {"enabled": False},
            [{"name": "one", "keys": [REDACTION_MASK]}],
        ),
    ],
)
async def test_an_unresolved_masked_list_element_is_refused_and_never_sent(
    resolved: None, case: str, stored: dict[str, Any], peers: list[Any]
) -> None:
    upstream, result = await _ipsec_with(stored, {"enabled": True, "peers": peers})
    assert isinstance(result, ValueError), case
    assert "peers[" in str(result) and "No write was sent" in str(result)
    assert upstream.writes == []  # zero writes, so none carrying the mask


# Nothing stored at the parent list (absent, null or []): no stored secret can be moved or
# cleared there, so a masked OBJECT FIELD inside such a list element is dropped by the write
# path, reported, and the write is sent.
_NOTHING_STORED: dict[str, dict[str, Any]] = {
    "absent": {"enabled": False},
    "null": {"enabled": False, "peers": None},
    "empty": {"enabled": False, "peers": []},
}


@pytest.mark.parametrize("parent", sorted(_NOTHING_STORED))
@pytest.mark.parametrize(
    ("element", "sent", "reported"),
    [
        ({"name": "one", "psk": REDACTION_MASK}, {"name": "one"}, ["peers[0].psk"]),
        ({"psk": REDACTION_MASK}, {}, ["peers[0].psk"]),
        (
            {"name": "one", "auth": {"password": REDACTION_MASK}},
            {"name": "one", "auth": {}},
            ["peers[0].auth.password"],
        ),
    ],
)
async def test_a_masked_field_in_an_element_of_a_list_with_nothing_stored_is_dropped_and_sent(
    resolved: None, parent: str, element: dict[str, Any], sent: dict[str, Any], reported: list[str]
) -> None:
    upstream, result = await _ipsec_with(
        _NOTHING_STORED[parent], {"enabled": True, "peers": [element]}
    )
    assert not isinstance(result, Exception), (parent, result)
    assert [w[2] for w in upstream.writes] == [{"enabled": True, "peers": [sent]}]
    assert REDACTION_MASK not in json.dumps(upstream.writes)
    assert result["_redactedFieldsNotSent"] == reported


async def test_a_masked_list_element_with_one_stored_match_is_restored(resolved: None) -> None:
    upstream, _ = await _ipsec_with(
        {"enabled": False, "peers": ["p-secret"]}, {"enabled": True, "peers": [REDACTION_MASK]}
    )
    assert upstream.writes[0][2]["peers"] == ["p-secret"]
    assert REDACTION_MASK not in json.dumps(upstream.writes)


async def test_a_masked_object_field_with_no_stored_value_is_still_dropped(resolved: None) -> None:
    upstream, result = await _ipsec_with(
        {"enabled": False}, {"enabled": True, "x_psk": REDACTION_MASK}
    )
    assert not isinstance(result, Exception)
    assert upstream.writes[0][2] == {"enabled": True}  # dropped and reported, as documented
    assert "x_psk" in json.dumps(result)  # under _redactedFieldsNotSent


async def test_with_redaction_off_the_literal_mask_is_sent_as_given(resolved: None) -> None:
    upstream, _ = await _ipsec_with(
        {"enabled": False, "peers": []}, {"enabled": True, "peers": [REDACTION_MASK]}, redact=False
    )
    assert upstream.writes[0][2]["peers"] == [REDACTION_MASK]


# --------------------------------------------------------------------------- identity
# Element identity is the non-mask projection (G3W3-OAI-01): a key holding only masks takes
# no part in matching, so a uniquely matched element whose masked field has nothing stored
# drops and reports that field, as a top-level field and an id-matched element do.


async def test_a_matched_element_drops_and_reports_a_masked_field_with_nothing_stored(
    resolved: None,
) -> None:
    upstream, result = await _ipsec_with(
        {"enabled": False, "peers": [{"name": "one"}]},
        {"enabled": True, "peers": [{"name": "one", "psk": REDACTION_MASK}]},
    )
    assert not isinstance(result, Exception)
    assert [w[2] for w in upstream.writes] == [{"enabled": True, "peers": [{"name": "one"}]}]
    assert result["_redactedFieldsNotSent"] == ["peers[0].psk"]


async def test_a_nested_object_only_mask_with_nothing_stored_is_dropped_not_sent(
    resolved: None,
) -> None:
    # The write path drops the masked nested field; its now-empty parent object stays.
    upstream, result = await _ipsec_with(
        {"enabled": False, "peers": [{"name": "one"}]},
        {"enabled": True, "peers": [{"name": "one", "auth": {"password": REDACTION_MASK}}]},
    )
    assert not isinstance(result, Exception)
    assert [w[2] for w in upstream.writes] == [
        {"enabled": True, "peers": [{"name": "one", "auth": {}}]}
    ]
    assert REDACTION_MASK not in json.dumps(upstream.writes)
    assert result["_redactedFieldsNotSent"] == ["peers[0].auth.password"]


def test_an_empty_object_is_a_real_value_in_identity() -> None:
    stored = {"peers": [{"name": "one", "opts": {"a": 1}, "psk": SECRET}]}
    requested = {"peers": [{"name": "one", "opts": {}, "psk": REDACTION_MASK}]}
    with pytest.raises(ValueError, match=r"peers\[0\]\.psk"):
        _keep({"peers": [{"name": "one", "opts": {}}]}, stored, requested)


# --------------------------------------------------------------------------- model test
# Every permutation of every subset of a stored list, each element's secret masked,
# omitted or new, plus a variant with a non-secret field edited; through the helper and
# the write path's own mask drop. Pure, deterministic, no time cap.


def _families() -> dict[str, list[dict[str, Any]]]:
    return {
        "ids": [
            {"id": "a", "name": "one", "secret": "S-a"},
            {"id": "b", "name": "two", "secret": "S-b"},
            {"id": "c", "name": "three", "secret": "S-c"},
        ],
        "no-ids": [
            {"name": "one", "secret": "S-1"},
            {"name": "two", "secret": "S-2"},
            {"name": "three", "secret": "S-3"},
        ],
        "shared-name": [
            {"name": "same", "secret": "S-x"},
            {"name": "same", "secret": "S-y"},
            {"name": "other", "secret": "S-z"},
        ],
        "nothing-stored": [{"name": "one"}, {"name": "two"}],
    }


def _passed_back(stored: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    from itertools import permutations, product

    cases: list[list[dict[str, Any]]] = []
    for size in range(len(stored) + 1):
        for order in permutations(range(len(stored)), size):
            for modes in product(("mask", "omit", "new"), repeat=size):
                elements = []
                for index, mode in zip(order, modes, strict=True):
                    element = {k: v for k, v in stored[index].items() if k != "secret"}
                    if mode == "mask":
                        element["secret"] = REDACTION_MASK
                    elif mode == "new":
                        element["secret"] = f"N-{index}"
                    elements.append(element)
                cases.append(elements)
                if elements:
                    cases.append([{**elements[0], "name": "edited"}, *elements[1:]])
    return cases


def _oracle(element: dict[str, Any], stored: list[dict[str, Any]]) -> list[int]:
    """Indices of the stored elements ``element`` IS: same id, else same non-mask fields."""
    if "id" in element:
        return [i for i, s in enumerate(stored) if s.get("id") == element["id"]]
    shown = {k: v for k, v in element.items() if v != REDACTION_MASK}
    return [
        i for i, s in enumerate(stored) if all(s.get(k, object()) == v for k, v in shown.items())
    ]


_NO_PARENT: Any = object()  # the stored record has no ``items`` key at all


def _write(stored: Any, passed: list[dict[str, Any]], *, redact: bool):
    """(sent body or None, error or None, reported paths): the tool flow in miniature."""
    from unifi_fabric import redaction

    record = {} if stored is _NO_PARENT else {"items": stored}
    fields = {"items": passed}
    sink: list[str] = []
    token = redaction._dropped_masked_fields.set(sink)
    try:
        with redaction.write_redaction_scope(redact):
            changes = redaction.drop_and_note_masked_fields(fields)  # the tool's _update_body
            merged = {**record, **changes}  # a list the caller sends replaces the stored list
            try:
                body = _keep(merged, record, fields, redact=redact)
            except ValueError as exc:
                return None, exc, list(sink)
            return redaction.drop_and_note_masked_fields(body), None, list(sink)  # write path
    finally:
        redaction._dropped_masked_fields.reset(token)


def test_the_model_holds_every_invariant() -> None:
    checked = 0
    for family, stored in _families().items():
        secrets = {s["secret"] for s in stored if "secret" in s}
        for passed in _passed_back(stored):
            sent, error, reported = _write(stored, passed, redact=True)
            checked += 1
            where = (family, passed)
            masked = [i for i, e in enumerate(passed) if e.get("secret") == REDACTION_MASK]
            claims = {i: _oracle(passed[i], stored) for i in masked}
            unique = all(len(c) == 1 for c in claims.values())
            one_to_one = len({c[0] for c in claims.values() if len(c) == 1}) == len(masked)
            if error is not None:
                # (I3) a refusal sends nothing, and its message holds no secret value.
                assert not any(v in str(error) for v in secrets), where
                assert not (unique and one_to_one), (where, "refused a resolvable write")
                continue
            assert unique and one_to_one, (where, "sent an unresolvable write")
            # (I1) no mask string anywhere in the sent body.
            assert REDACTION_MASK not in json.dumps(sent), where
            for index, element in enumerate(sent["items"]):
                asked = passed[index]
                if asked.get("secret") == REDACTION_MASK:
                    owner = stored[claims[index][0]]
                    if "secret" in owner:
                        # (I2) the stored secret of the ONE element it is, never another's.
                        assert element.get("secret") == owner["secret"], where
                    else:
                        # (I4) nothing stored: sent without the field, path reported.
                        assert "secret" not in element, where
                        assert f"items[{index}].secret" in reported, where
                elif "secret" in asked:
                    assert element["secret"] == asked["secret"], where  # (I2) the caller's
                else:
                    assert "secret" not in element, where  # omitted: the list replaces
            # (I5) with redaction off the body is sent as given.
            plain, plain_error, _ = _write(stored, passed, redact=False)
            assert plain_error is None and plain == {"items": passed}, where
    assert checked == 1402  # 4 families, every subset and order, 3 modes, edited variants


@pytest.mark.parametrize("parent", ["absent", "null", "empty"])
def test_the_model_holds_every_invariant_where_nothing_is_stored_at_the_list(parent: str) -> None:
    # The same passed-back lists, over a stored record whose list is absent, null or [].
    stored = {"absent": _NO_PARENT, "null": None, "empty": []}[parent]
    checked = 0
    for family, shapes in _families().items():
        foreign = {s["secret"] for s in shapes if "secret" in s}  # stored nowhere here
        for passed in _passed_back(shapes):
            sent, error, reported = _write(stored, passed, redact=True)
            checked += 1
            where = (parent, family, passed)
            # (I3) no stored secret can be moved or cleared, so nothing here is refused.
            assert error is None, (where, "refused a write with nothing stored at the list")
            # (I1) no mask string anywhere in the sent body.
            assert REDACTION_MASK not in json.dumps(sent), where
            assert len(sent["items"]) == len(passed), where
            masked = []
            for index, (element, asked) in enumerate(zip(sent["items"], passed, strict=True)):
                shown = {k: v for k, v in asked.items() if k != "secret"}
                assert {k: v for k, v in element.items() if k != "secret"} == shown, where
                if asked.get("secret") == REDACTION_MASK:
                    # (I4) nothing stored: sent without the field, path reported.
                    assert "secret" not in element, where
                    masked.append(f"items[{index}].secret")
                elif "secret" in asked:
                    assert element["secret"] == asked["secret"], where  # (I2) the caller's
                else:
                    assert "secret" not in element, where
            assert sorted(reported) == sorted(masked), where
            # (I2) no secret is invented or moved in from anywhere else.
            assert not any(value in json.dumps(sent) for value in foreign), where
            # (I5) with redaction off the body is sent as given.
            plain, plain_error, _ = _write(stored, passed, redact=False)
            assert plain_error is None and plain == {"items": passed}, where
    assert checked == 1402  # the same 1402 passed-back lists


@pytest.mark.parametrize("stored", [_NO_PARENT, None, []], ids=["absent", "null", "empty"])
def test_a_mask_that_is_itself_an_element_is_refused_where_nothing_is_stored(stored: Any) -> None:
    record = {} if stored is _NO_PARENT else {"items": stored}
    for passed in ([REDACTION_MASK], [{"name": "one"}, REDACTION_MASK], [[REDACTION_MASK]]):
        with pytest.raises(ValueError, match=r"No write was sent.*items\[\d\]"):
            _keep({**record, "items": passed}, record, {"items": passed})


# --------------------------------------------------------------------------- refusal text
# The refusal must reach the caller whole. Every tool error passes the error-text mask
# under UNIFI_REDACT_SECRETS (server.SecretScrubMiddleware), which reads "<credential
# field>: <text>" as a credential pair and withholds the rest of the message; a mask path
# ends in exactly such a name. The message therefore gives the reason first and the paths
# last, and is checked here through the mask and through the real tool boundary.

_REFUSAL = next(r for r in refusals.REFUSALS if r.id == "masked-element-unmatched")
_LEAVES = [
    "private_key",
    "psk",
    "password",
    "x_secret",
    "x_passphrase",
    "X-Token",
    "auth.password",
    "headers.X-Token",
    "tunnel.auth.x_private_key",
]
_TOOL_HEADER = "Error calling tool 'update_ipsec_settings': "


def _at(leaf: str, value: Any) -> dict[str, Any]:
    """``{"a": {"b": value}}`` for the dotted ``leaf`` ``a.b``."""
    out: Any = value
    for key in reversed(leaf.split(".")):
        out = {key: out}
    return out


def _unmatched(leaf: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """(stored peers, passed-back peers, mask paths): two masked elements, neither stored."""
    stored = [{"name": "one", **_at(leaf, SECRET)}, {"name": "two", **_at(leaf, SECRET_2)}]
    passed = [
        {"name": "edited", **_at(leaf, REDACTION_MASK)},
        {"name": "added", **_at(leaf, REDACTION_MASK)},
    ]
    return stored, passed, [f"peers[0].{leaf}", f"peers[1].{leaf}"]


def _assert_actionable(text: str, paths: list[str]) -> None:
    assert _REFUSAL.matches(text), text  # the reason, as the registry names it
    assert "Send the real value at each mask path, or pass the element back unchanged" in text
    assert "No write was sent" in text
    assert text.endswith("Mask paths: " + ", ".join(paths)), text  # every path, readable
    assert SECRET not in text and SECRET_2 not in text
    assert "***" not in text, text  # nothing in it was masked, scrubbed or withheld


@pytest.mark.parametrize("leaf", _LEAVES)
def test_the_refusal_text_is_left_whole_by_the_error_text_mask(leaf: str) -> None:
    stored, passed, paths = _unmatched(leaf)
    with pytest.raises(ValueError) as exc:
        _keep({"peers": passed}, {"peers": stored}, {"peers": passed})
    text = str(exc.value)
    _assert_actionable(text, paths)
    assert mask_error_text(text) == text
    assert mask_error_text(_TOOL_HEADER + text) == _TOOL_HEADER + text
    assert mask_error_text(mask_error_text(_TOOL_HEADER + text)) == _TOOL_HEADER + text


async def _refused_through_the_tool_boundary(
    monkeypatch: pytest.MonkeyPatch, name: str, arg: str, leaf: str
) -> tuple[uh.FakeUpstream, str, list[str]]:
    stored, passed, paths = _unmatched(leaf)
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    upstream = uh.FakeUpstream()
    upstream.overlay["peers"] = stored  # the record the tool reads holds these elements
    uh.install(monkeypatch, upstream)
    tool_args.prepare_upstream(name, upstream)
    args = {**tool_args.generated_args(tools_by_name()[name]), arg: {"peers": passed}}
    with pytest.raises(ToolError) as exc:
        await server.mcp.call_tool(name, args)
    return upstream, str(exc.value), paths


@pytest.mark.parametrize("leaf", _LEAVES)
async def test_the_refusal_reaches_the_caller_whole_through_the_tool_boundary(
    monkeypatch: pytest.MonkeyPatch, leaf: str
) -> None:
    upstream, text, paths = await _refused_through_the_tool_boundary(
        monkeypatch, "update_ipsec_settings", "fields", leaf
    )
    _assert_actionable(text, paths)
    assert upstream.writes() == []
    # Exactly the text the helper raised, behind the tool header: nothing lost on the way.
    stored, passed, _ = _unmatched(leaf)
    with pytest.raises(ValueError) as raised:
        _keep({"peers": passed}, {"peers": stored}, {"peers": passed})
    assert text == _TOOL_HEADER + str(raised.value)


@pytest.mark.parametrize(
    ("name", "arg"),
    [
        ("update_bgp_config", "config"),
        ("update_ospf_router", "router"),
        ("update_protect_automation", "changes"),
    ],
)
async def test_every_whole_record_tool_gives_the_same_whole_refusal(
    monkeypatch: pytest.MonkeyPatch, name: str, arg: str
) -> None:
    upstream, text, paths = await _refused_through_the_tool_boundary(
        monkeypatch, name, arg, "private_key"
    )
    _assert_actionable(text, paths)
    assert upstream.writes() == []
