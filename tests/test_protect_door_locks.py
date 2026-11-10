"""Protect 7.x door-lock reads: get_door_lock and list_door_lock_unlock_events.

Every call runs against the real ``UniFiClient`` with only the HTTP transport mocked (a fake
Protect console). The route and query shapes come from the Protect 7.3.74 route table (the
unlock-events handler takes limit 1..100, default 50, and offset 0..10000, and answers a bare
array); no lock exists on the estate, so nothing here is a recorded response: the fixture
records are synthetic and carry the fields that route table's schema lists.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from fastmcp import FastMCP

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric._read_only_audit import classify_tool_verbs
from unifi_fabric.client import UniFiClient, UniFiConnectionError, _key_fingerprint
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.families.protect import protect_door_locks as pdk

HOST = "console-dl"
PRIV = f"/v1/connector/consoles/{HOST}/proxy/protect/api"
LOCK = "000000000000000000dc0701"
LOCK2 = "000000000000000000dc0702"
LOCKS = [
    {"id": LOCK, "name": "Front door", "modelKey": "lock", "state": "CONNECTED"},
    {"id": LOCK2, "name": "Back door", "modelKey": "lock", "state": "DISCONNECTED"},
]


def unlock_request(n: int) -> dict[str, Any]:
    """A synthetic unlock request with every field the route table's schema lists."""
    return {
        "requestId": str(n),
        "eventId": f"000000000000000000e{n:07d}",
        "lockId": LOCK,
        "userId": None if n % 2 else f"000000000000000000b{n:07d}",
        "userName": None if n % 2 else "Synthetic Admin",
        "method": "api",
        "mac": "00:00:5e:00:53:07",
        "sysid": "0000000000000007",
        "holdExtraSec": None,
        "state": "acknowledged",
        "createdAt": "2026-11-01T00:00:00.000Z",
        "updatedAt": "2026-11-01T00:00:01.000Z",
        "acknowledgedAt": "2026-11-01T00:00:01.000Z",
        "futureField": {"kept": n},
    }


def registry(key: APIKeyConfig | None = None) -> AsyncMock:
    return AsyncMock(
        **{
            "resolve_key_for_host.return_value": key or APIKeyConfig(key="test-key", label="beta"),
            "resolve_host_id.return_value": HOST,
        }
    )


def client(handler, **settings: Any) -> UniFiClient:
    c = UniFiClient(Settings(api_key="test-key", **settings))
    c._clients[("beta", _key_fingerprint("test-key"))] = httpx.AsyncClient(
        base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
    )
    return c


class Console:
    """A fake Protect 7.x console: /locks, /locks/{id} and a paged unlock-events feed."""

    def __init__(self, locks=None, events: int = 0, overrides=None):
        self.locks = LOCKS if locks is None else locks
        self.events = [unlock_request(n) for n in range(events, 0, -1)]  # newest first
        self.overrides = overrides or {}
        self.seen: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        if (req.method, req.url.path) in self.overrides:
            return self.overrides[(req.method, req.url.path)](req)
        path = req.url.path
        if path == f"{PRIV}/locks":
            return httpx.Response(200, json=self.locks)
        for lock in self.locks:
            if path == f"{PRIV}/locks/{lock['id']}":
                return httpx.Response(200, json=lock)
            if path == f"{PRIV}/locks/{lock['id']}/unlock/events":
                q = dict(req.url.params)
                if set(q) - {"limit", "offset"}:
                    return httpx.Response(400, json={"error": "unknown query"})
                limit = int(q.get("limit", 50))
                offset = int(q.get("offset", 0))
                if not 1 <= limit <= 100 or not 0 <= offset <= 10000:
                    return httpx.Response(400, json={"error": "query out of range"})
                return httpx.Response(200, json=self.events[offset : offset + limit])
        return httpx.Response(404, json={"error": "not found"})

    def paths(self) -> list[str]:
        return [r.url.path.removeprefix(PRIV) for r in self.seen]

    def queries(self, suffix: str) -> list[dict[str, str]]:
        return [dict(r.url.params) for r in self.seen if r.url.path.endswith(suffix)]


async def run(handler, fn, *args, settings: dict[str, Any] | None = None, **kwargs):
    c = client(handler, **(settings or {}))
    try:
        return await fn(c, registry(), HOST, *args, **kwargs)
    finally:
        await c.close()


# ------------------------------------------------------------------ get_door_lock


@pytest.mark.asyncio
async def test_get_door_lock_reads_the_lock_verbatim_after_resolving_it_in_the_list():
    console = Console()
    result = await run(console, pdk.get_door_lock, LOCK)
    assert result == LOCKS[0]
    assert console.paths() == ["/locks", f"/locks/{LOCK}"]
    assert all(r.method == "GET" for r in console.seen)


@pytest.mark.asyncio
async def test_get_door_lock_keeps_unknown_upstream_fields_and_sends_no_extra_query():
    lock = {**LOCKS[0], "futureField": {"nested": [1, 2]}, "thread": {"rloc": "0x1c00"}}
    console = Console(locks=[lock, LOCKS[1]])
    result = await run(console, pdk.get_door_lock, LOCK)
    assert result == lock
    assert all(not r.url.params for r in console.seen)


@pytest.mark.asyncio
async def test_get_door_lock_uses_the_listed_spelling_of_a_case_different_id():
    console = Console()
    result = await run(console, pdk.get_door_lock, LOCK.upper())
    assert result["id"] == LOCK
    assert console.paths()[-1] == f"/locks/{LOCK}"


@pytest.mark.asyncio
async def test_unknown_lock_fails_listing_the_valid_locks_before_the_per_lock_request():
    console = Console()
    with pytest.raises(ValueError) as caught:
        await run(console, pdk.get_door_lock, "000000000000000000dc0999")
    message = str(caught.value)
    assert message.startswith("Unknown door lock '000000000000000000dc0999'")
    assert f"valid choices: {LOCK} (Front door), {LOCK2} (Back door)" in message
    assert console.paths() == ["/locks"]


@pytest.mark.asyncio
async def test_unknown_lock_on_a_console_with_no_locks_says_so():
    console = Console(locks=[])
    with pytest.raises(ValueError, match=r"valid choices: none \(GET /locks returned an empty"):
        await run(console, pdk.get_door_lock, LOCK)
    assert console.paths() == ["/locks"]


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["", "..", "../x", "%2e%2e", "x\ny"])
async def test_invalid_lock_ids_fail_before_any_request(bad):
    console = Console()
    for fn in (pdk.get_door_lock, pdk.list_door_lock_unlock_events):
        with pytest.raises((ValueError, UniFiConnectionError)):
            await run(console, fn, bad)
    assert console.seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize("odd", ["a/b", "a?b=1", "a#b", "a b", "Front door"])
async def test_an_id_that_is_a_valid_segment_but_unlisted_never_reaches_a_lock_route(odd):
    console = Console()
    with pytest.raises(ValueError, match="valid choices"):
        await run(console, pdk.get_door_lock, odd)
    assert console.paths() == ["/locks"]


@pytest.mark.asyncio
async def test_get_door_lock_upstream_error_keeps_the_full_body_and_adds_a_hint():
    long_reason = "lock record unavailable: " + "x" * 3000
    console = Console(
        overrides={
            ("GET", f"{PRIV}/locks/{LOCK}"): lambda r: httpx.Response(
                503, json={"error": long_reason}
            )
        }
    )
    with pytest.raises(UniFiConnectionError) as caught:
        await run(console, pdk.get_door_lock, LOCK)
    assert long_reason in str(caught.value)
    assert "Protect 7.x" in str(caught.value)
    assert caught.value.status == 503


@pytest.mark.asyncio
async def test_a_console_without_the_locks_route_gets_the_availability_hint():
    console = Console(overrides={("GET", f"{PRIV}/locks"): lambda r: httpx.Response(404, json={})})
    with pytest.raises(UniFiConnectionError) as caught:
        await run(console, pdk.get_door_lock, LOCK)
    assert "older than Protect 7.x" in str(caught.value)
    assert console.paths() == ["/locks"]


@pytest.mark.asyncio
async def test_get_door_lock_refuses_a_non_object_body_naming_the_shape():
    console = Console(
        overrides={("GET", f"{PRIV}/locks/{LOCK}"): lambda r: httpx.Response(200, json=[1])}
    )
    with pytest.raises(UniFiConnectionError, match="expected an object"):
        await run(console, pdk.get_door_lock, LOCK)


@pytest.mark.asyncio
async def test_a_list_in_an_unexpected_shape_raises_instead_of_reading_as_no_locks():
    console = Console(
        overrides={("GET", f"{PRIV}/locks"): lambda r: httpx.Response(200, json={"oops": 1})}
    )
    with pytest.raises(UniFiConnectionError, match="Unexpected Protect response shape"):
        await run(console, pdk.get_door_lock, LOCK)


# ------------------------------------------------------- list_door_lock_unlock_events


@pytest.mark.asyncio
async def test_unlock_events_drain_every_page_in_pages_of_the_route_maximum():
    console = Console(events=250)
    result = await run(console, pdk.list_door_lock_unlock_events, LOCK)
    assert result["_count"] == 250
    assert [e["requestId"] for e in result["result"]] == [str(n) for n in range(250, 0, -1)]
    assert "incomplete" not in result
    sizes = {q["limit"] for q in console.queries("/unlock/events")}
    assert sizes == {"100"}
    assert console.paths()[0] == "/locks"
    assert all(r.method == "GET" for r in console.seen)


@pytest.mark.asyncio
async def test_unlock_events_are_verbatim_including_unknown_fields_and_nulls():
    console = Console(events=3)
    result = await run(console, pdk.list_door_lock_unlock_events, LOCK)
    assert result["result"] == list(reversed([unlock_request(n) for n in (1, 2, 3)]))
    assert result["result"][0]["userId"] is None


@pytest.mark.asyncio
async def test_a_lock_with_no_unlock_requests_returns_an_empty_list_not_an_error():
    console = Console(events=0)
    result = await run(console, pdk.list_door_lock_unlock_events, LOCK)
    assert result["result"] == [] and result["_count"] == 0


@pytest.mark.asyncio
async def test_a_limit_gathers_that_many_events_across_pages():
    console = Console(events=300)
    result = await run(console, pdk.list_door_lock_unlock_events, LOCK, limit=130)
    assert result["_count"] == 130
    assert result["data"][0]["requestId"] == "300"
    assert result["data"][-1]["requestId"] == "171"
    assert result["_pageSize"]["requested"] == 130 and result["_pageSize"]["returned"] == 130
    assert max(int(q["limit"]) for q in console.queries("/unlock/events")) <= 100


@pytest.mark.asyncio
async def test_an_offset_selects_one_native_page_returned_as_the_bare_array():
    console = Console(events=300)
    result = await run(console, pdk.list_door_lock_unlock_events, LOCK, offset=100, limit=20)
    assert isinstance(result, list) and len(result) == 20
    assert result[0]["requestId"] == "200"
    assert console.queries("/unlock/events") == [{"offset": "100", "limit": "20"}]


@pytest.mark.asyncio
async def test_an_offset_alone_sends_only_the_offset():
    console = Console(events=5)
    result = await run(console, pdk.list_door_lock_unlock_events, LOCK, offset=2)
    assert [e["requestId"] for e in result] == ["3", "2", "1"]
    assert console.queries("/unlock/events") == [{"offset": "2"}]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs", [{"limit": 0}, {"limit": -1}, {"offset": -1}, {"limit": True}, {"offset": "1"}]
)
async def test_invalid_paging_fails_before_any_request(kwargs):
    console = Console(events=3)
    with pytest.raises((ValueError, UniFiConnectionError)):
        await run(console, pdk.list_door_lock_unlock_events, LOCK, **kwargs)
    assert console.seen == []


@pytest.mark.asyncio
async def test_a_page_limit_above_the_route_maximum_is_the_consoles_to_judge():
    console = Console(events=3)
    with pytest.raises(UniFiConnectionError) as caught:
        await run(console, pdk.list_door_lock_unlock_events, LOCK, offset=0, limit=101)
    assert "query out of range" in str(caught.value)


@pytest.mark.asyncio
async def test_a_capped_drain_is_flagged_incomplete_never_passed_off_as_complete():
    console = Console(events=350)
    result = await run(
        console, pdk.list_door_lock_unlock_events, LOCK, settings={"paginate_max_pages": 2}
    )
    assert result["incomplete"] is True
    assert result["incompleteReason"]
    assert result["_count"] == len(result["result"]) == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("kwargs", [{"limit": 5}, {"offset": 0, "limit": 5}, {"offset": 0}])
async def test_a_paged_read_uses_the_lock_id_as_the_console_lists_it(kwargs):
    console = Console(events=5)
    result = await run(console, pdk.list_door_lock_unlock_events, LOCK.upper(), **kwargs)
    events = result if isinstance(result, list) else result["data"]
    assert [e["requestId"] for e in events] == ["5", "4", "3", "2", "1"]
    assert console.paths()[-1] == f"/locks/{LOCK}/unlock/events"
    assert f"/locks/{LOCK.upper()}/unlock/events" in console.paths()


@pytest.mark.asyncio
async def test_a_paged_read_of_a_listed_lock_keeps_the_upstream_error():
    console = Console(
        events=3,
        overrides={
            ("GET", f"{PRIV}/locks/{LOCK}/unlock/events"): lambda r: httpx.Response(
                500, json={"error": "boom"}
            )
        },
    )
    with pytest.raises(UniFiConnectionError, match="boom"):
        await run(console, pdk.list_door_lock_unlock_events, LOCK, limit=5)
    assert console.paths() == [f"/locks/{LOCK}/unlock/events", "/locks"]


@pytest.mark.asyncio
async def test_unlock_events_for_an_unknown_lock_list_the_valid_locks_and_stop():
    console = Console(events=3)
    with pytest.raises(ValueError, match="valid choices: .*Front door"):
        await run(console, pdk.list_door_lock_unlock_events, "nope")
    assert console.paths() == ["/locks"]


@pytest.mark.asyncio
async def test_unlock_events_upstream_failure_keeps_the_body_and_adds_the_hint():
    console = Console(
        events=3,
        overrides={
            ("GET", f"{PRIV}/locks/{LOCK}/unlock/events"): lambda r: httpx.Response(
                502, json={"error": "thread service unreachable"}
            )
        },
    )
    with pytest.raises(UniFiConnectionError) as caught:
        await run(console, pdk.list_door_lock_unlock_events, LOCK)
    assert "thread service unreachable" in str(caught.value)
    assert "Protect 7.x" in str(caught.value)


@pytest.mark.asyncio
async def test_a_console_that_ignores_offset_is_flagged_incomplete_with_the_first_page_kept():
    page = [unlock_request(n) for n in range(100, 0, -1)]
    console = Console(
        events=5,
        overrides={
            ("GET", f"{PRIV}/locks/{LOCK}/unlock/events"): lambda r: httpx.Response(200, json=page)
        },
    )
    result = await run(console, pdk.list_door_lock_unlock_events, LOCK)
    assert result["_count"] == 100 and result["incomplete"] is True
    assert "ignores offset" in result["incompleteReason"]


@pytest.mark.asyncio
async def test_the_consoles_offset_limit_is_reported_not_hit_as_an_error():
    console = Console(events=10_150)
    result = await run(console, pdk.list_door_lock_unlock_events, LOCK)
    assert result["incomplete"] is True and "offset 10000" in result["incompleteReason"]
    assert result["_count"] == 10_100
    assert all(int(q["offset"]) <= 10_000 for q in console.queries("/unlock/events"))


# ------------------------------------------------ modes, multi-key, registration


@pytest.mark.asyncio
async def test_reads_work_under_read_only_mode_and_the_protect_write_opt_out():
    console = Console(events=2)
    settings = {"write_policy": "deny"}
    assert (await run(console, pdk.get_door_lock, LOCK, settings=settings))["id"] == LOCK
    events = await run(console, pdk.list_door_lock_unlock_events, LOCK, settings=settings)
    assert events["_count"] == 2


@pytest.mark.asyncio
async def test_requests_ride_the_owning_key_on_a_multikey_estate(
    multikey_client, multikey_registry
):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_host_id = AsyncMock(return_value="console-beta-1")
    seen: list[str | None] = []

    async def capture(path, *a, key=None, **kw):
        seen.append(key.label if key else None)
        if path.endswith("/locks"):
            return LOCKS
        if path.endswith("/unlock/events"):
            return []
        return LOCKS[0]

    multikey_client.get = AsyncMock(side_effect=capture)
    seen.clear()
    await pdk.get_door_lock(multikey_client, multikey_registry, "Beta-Branch", LOCK)
    assert seen == ["beta", "beta"]
    seen.clear()
    await pdk.list_door_lock_unlock_events(multikey_client, multikey_registry, "Beta-Branch", LOCK)
    assert seen and set(seen) == {"beta"}


def _registered() -> dict[str, Any]:
    import asyncio

    mcp = FastMCP("t")
    pdk.register(mcp, lambda: (None, None))
    return {tool.name: tool for tool in asyncio.run(mcp.list_tools())}


def test_both_tools_are_registered_read_only_with_derived_annotations():
    tools = _registered()
    assert set(tools) == {"get_door_lock", "list_door_lock_unlock_events"}
    for name, tool in tools.items():
        hints = tool.annotations.model_dump(by_alias=True)
        assert hints["readOnlyHint"] is True and hints["destructiveHint"] is False, name
    verbs = classify_tool_verbs(list(tools.values()))
    assert {name for name, v in verbs.items() if v} == set()


def test_schema_properties_are_described_with_examples_and_required_args_are_marked():
    tools = _registered()
    for name, tool in tools.items():
        text = tool.description or ""
        assert text and len(text) <= 2048 and "Args:" not in text, name
        assert "Required arguments: host, lock_id" in text, name
        assert set((tool.parameters or {}).get("required", [])) == {"host", "lock_id"}, name
        for prop, schema in tool.parameters["properties"].items():
            flat = " ".join(schema.get("description", "").split())
            assert flat and ("for example" in flat or "Example: `" in flat), f"{name}.{prop}"
    props = tools["list_door_lock_unlock_events"].parameters["properties"]
    assert set(props) == {"host", "lock_id", "offset", "limit"}


def test_the_descriptions_state_the_route_the_id_check_and_the_7x_scope():
    tools = _registered()
    one = " ".join(tools["get_door_lock"].description.split())
    many = " ".join(tools["list_door_lock_unlock_events"].description.split())
    assert "GET /locks/{lock_id}" in one and "GET /locks" in one and "Protect 7.x" in one
    assert "GET /locks/{lock_id}/unlock/events" in many and "newest first" in many
    assert "pages of 100" in many and "incomplete=true" in many


def test_the_module_raises_the_unknown_lock_refusal_from_its_registered_site():
    from unifi_fabric.refusals import REFUSALS

    entry = next(r for r in REFUSALS if r.id == "protect-lock-lookup")
    assert entry.sites == ("families/protect/protect_door_locks.py:_require_known_lock",)
    assert entry.matches("Unknown door lock 'x' on 'h'; valid choices: a (b)")
    assert json.dumps(entry.category)
