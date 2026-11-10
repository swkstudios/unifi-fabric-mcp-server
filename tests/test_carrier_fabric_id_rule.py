"""Carrier Fabric writes follow the shared id rule for plan, host and subscriber ids.

Ids made only of hex digits and ``-`` / ``:`` match case-insensitively
(:func:`unifi_fabric.matching.same_id`). The no-op check and the read-after
verification of every plan / host id a write sends use that rule, and every subscriber
write (and its read-back) addresses the subscriber by the id its read-before reported.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import respx
from httpx import Response

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.carrier.carrier_fabric import (
    CARRIER_BASE,
    assign_carrier_subscriber_plan,
    attach_carrier_subscriber_host,
    detach_carrier_subscriber_host,
    resume_carrier_subscriber,
    suspend_carrier_subscriber,
    update_carrier_subscriber,
)

SID = "aaaaaaaa-1111-4111-8111-111111111111"
PID = "bbbbbbbb-2222-4222-8222-222222222222"
OTHER_PID = "cccccccc-3333-4333-8333-333333333333"
HOST = "70a7410000000000000000000000000000000000000000000000:123456789"
BASE = f"https://api.ui.com{CARRIER_BASE}/subscribers"


@pytest.fixture()
def client():
    return UniFiClient(Settings(api_key="sk-carrier-id-rule"))


def _sub(**fields: Any) -> dict[str, Any]:
    return {"data": {"id": SID, "suspended": False, "hostId": None, "planId": None, **fields}}


# (call, current subscriber fields): the caller's value is an upper-case spelling of the
# current id, so the write is already applied.
NO_OP_CASES = {
    "assign_plan": (
        lambda c: assign_carrier_subscriber_plan(c, SID, PID.upper()),
        {"planId": PID},
    ),
    "attach_host": (
        lambda c: attach_carrier_subscriber_host(c, SID, HOST.upper()),
        {"hostId": HOST},
    ),
    "update_plan_id": (
        lambda c: update_carrier_subscriber(c, SID, plan_id=PID.upper()),
        {"planId": PID},
    ),
}


@respx.mock
@pytest.mark.parametrize("case", sorted(NO_OP_CASES))
async def test_upper_case_spelling_of_current_id_is_a_no_op(client, case):
    call, current = NO_OP_CASES[case]
    respx.get(f"{BASE}/{SID}").mock(return_value=Response(200, json=_sub(**current)))
    writes = respx.route(method__in=["PUT", "PATCH", "POST", "DELETE"]).mock(
        return_value=Response(500)
    )
    result = await call(client)
    assert result["status"] == "no_op"
    assert writes.call_count == 0


# (call, method, path suffix, stored after the write): the caller sends an upper-case
# id the subscriber is not on; the upstream stores and reports its own spelling.
VERIFY_CASES = {
    "assign_plan": (
        lambda c: assign_carrier_subscriber_plan(c, SID, OTHER_PID.upper()),
        "PUT",
        "/plan",
        {"planId": OTHER_PID},
    ),
    "attach_host": (
        lambda c: attach_carrier_subscriber_host(c, SID, HOST.upper()),
        "PUT",
        "/host",
        {"hostId": HOST},
    ),
    "update_plan_id": (
        lambda c: update_carrier_subscriber(c, SID, plan_id=OTHER_PID.upper()),
        "PATCH",
        "",
        {"planId": OTHER_PID},
    ),
}


@respx.mock
@pytest.mark.parametrize("case", sorted(VERIFY_CASES))
async def test_write_stored_in_upstream_spelling_verifies(client, case):
    call, method, suffix, stored = VERIFY_CASES[case]
    respx.get(f"{BASE}/{SID}").mock(return_value=Response(200, json=_sub(planId=PID)))
    write = respx.route(method=method, url=f"{BASE}/{SID}{suffix}").mock(
        return_value=Response(200, json=_sub(**stored))
    )
    result = await call(client)
    assert write.call_count == 1
    assert result["verified"] is True


# Every subscriber write: the caller names the subscriber in upper case; the write and
# its read-back address the id the read-before reported.
ADDRESS_CASES = {
    "update": (lambda c, s: update_carrier_subscriber(c, s, name="n2"), "PATCH", ""),
    "attach_host": (lambda c, s: attach_carrier_subscriber_host(c, s, HOST), "PUT", "/host"),
    "detach_host": (lambda c, s: detach_carrier_subscriber_host(c, s), "DELETE", "/host"),
    "assign_plan": (lambda c, s: assign_carrier_subscriber_plan(c, s, OTHER_PID), "PUT", "/plan"),
    "suspend": (lambda c, s: suspend_carrier_subscriber(c, s), "POST", "/suspend"),
    "resume": (lambda c, s: resume_carrier_subscriber(c, s), "POST", "/resume"),
}


@respx.mock
@pytest.mark.parametrize("case", sorted(ADDRESS_CASES))
async def test_write_addresses_the_upstream_subscriber_id(client, case):
    call, method, suffix = ADDRESS_CASES[case]
    current = {"hostId": "h-old", "suspended": case == "resume", "name": "n1"}
    respx.get(f"{BASE}/{SID.upper()}").mock(return_value=Response(200, json=_sub(**current)))
    respx.get(f"{BASE}/{SID}").mock(return_value=Response(200, json=_sub(**current)))
    write = respx.route(method=method, url=f"{BASE}/{SID}{suffix}").mock(
        return_value=Response(200, text="")
    )
    await call(client, SID.upper())
    assert write.call_count == 1
    assert str(write.calls[0].request.url) == f"{BASE}/{SID}{suffix}"
    # The read-back (the write answered with no resource) GETs the upstream spelling.
    read_backs = [
        c.request.url.path
        for c in respx.calls
        if c.request.method == "GET" and c.request.url.path.endswith(SID)
    ]
    assert read_backs, "the read-back must address the upstream subscriber id"
    if method != "DELETE" and suffix in ("/plan",):
        assert json.loads(write.calls[0].request.content) == {"planId": OTHER_PID}
