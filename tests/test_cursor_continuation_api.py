"""Public cursor wrappers preserve physical page sizes across changed logical totals."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.shared_shapes._continuation import decode_continuation, encode_continuation


@dataclass
class PageIndexTokens(uh.FakeUpstream):
    """A native token denotes page index, interpreted using the request's physical size."""

    total: int = 450
    requests: list[dict[str, Any]] = field(default_factory=list)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        self.requests.append({"path": request.url.path, **params})
        carrier = request.url.path == "/v1/carrier/subscribers"
        size_key, token_key = ("limit", "cursor") if carrier else ("pageSize", "nextToken")
        size = min(int(params.get(size_key, "50")), 200)
        number = int(params.get(token_key, "0"))
        start = number * size
        end = min(start + size, self.total)
        following = str(number + 1) if end < self.total else None
        rows = [{"id": str(n)} for n in range(start, end)]
        if request.url.path == "/v1/devices":
            rows = [{"hostId": str(n), "devices": [{"id": str(n)}]} for n in range(start, end)]
        result: dict[str, Any] = {"data": rows, "traceId": "cursor-api-test"}
        if carrier:
            result["meta"] = {
                "limit": size,
                "hasMore": following is not None,
                "nextCursor": following,
            }
        else:
            result.update({"limit": size, "nextToken": following})
        return httpx.Response(200, json=result)


CASES = [
    ("list_hosts", "/v1/hosts", "page_token", "page_size", "pageToken", "pageSize"),
    ("list_sites", "/v1/sites", "page_token", "page_size", "pageToken", "pageSize"),
    ("list_devices", "/v1/devices", "page_token", "page_size", "pageToken", "pageSize"),
    ("list_carrier_subscribers", "/v1/carrier/subscribers", "cursor", "limit", "cursor", "limit"),
]


MANUAL_CASES = [
    *CASES,
    (
        "list_sdwan_configs",
        "/v1/sd-wan-configs",
        "page_token",
        "page_size",
        "pageToken",
        "pageSize",
    ),
]


def _ids(result: dict[str, Any], tool: str) -> list[int]:
    field_name = "hostId" if tool == "list_devices" else "id"
    return [int(row[field_name]) for row in result["data"]]


@pytest.mark.parametrize(
    ("tool", "path", "argument", "logical_size", "token_key", "wire_size"), CASES
)
async def test_public_opaque_continuation_changes_logical_size_without_gaps(
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    path: str,
    argument: str,
    logical_size: str,
    token_key: str,
    wire_size: str,
) -> None:
    up = PageIndexTokens()
    uh.install(monkeypatch, up)
    first = uh.result_payload(await server.mcp.call_tool(tool, {logical_size: 275}))
    assert _ids(first, tool) == list(range(400))
    assert isinstance(first["_continuation"], str)
    assert decode_continuation(first["_continuation"]) == {token_key: "2", wire_size: 275}
    assert first["_pageSize"] == {
        "requested": 275,
        "sent": [275, 275],
        "effective": 200,
        "returned": 400,
    }
    native = first["meta"]["nextCursor"] if argument == "cursor" else first["nextToken"]
    assert native == "2"
    following = uh.result_payload(
        await server.mcp.call_tool(
            tool,
            {argument: first["_continuation"], logical_size: 25},
        )
    )
    assert _ids(following, tool) == list(range(400, 450))
    assert _ids(first, tool) + _ids(following, tool) == list(range(450))
    assert following["_pageSize"] == {
        "requested": 25,
        "sent": [275],
        "effective": 200,
        "returned": 50,
    }
    assert "_continuation" not in following
    native_key = "cursor" if argument == "cursor" else "nextToken"
    assert up.requests == [
        {"path": path, wire_size: "275"},
        {"path": path, wire_size: "275", native_key: "1"},
        {"path": path, wire_size: "275", native_key: "2"},
    ]


@pytest.mark.parametrize(
    ("tool", "path", "argument", "logical_size", "token_key", "wire_size"), MANUAL_CASES
)
async def test_opaque_continuation_without_logical_size_returns_one_native_page(
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    path: str,
    argument: str,
    logical_size: str,
    token_key: str,
    wire_size: str,
) -> None:
    up = PageIndexTokens(total=1000)
    uh.install(monkeypatch, up)
    result = uh.result_payload(
        await server.mcp.call_tool(
            tool,
            {argument: encode_continuation({token_key: "2", wire_size: 200})},
        )
    )
    assert _ids(result, tool) == list(range(400, 600))
    assert isinstance(result["_continuation"], str)
    assert decode_continuation(result["_continuation"]) == {token_key: "3", wire_size: 200}
    native_key = "cursor" if argument == "cursor" else "nextToken"
    assert up.requests == [{"path": path, wire_size: "200", native_key: "2"}]


@pytest.mark.parametrize(
    ("tool", "path", "argument", "logical_size", "token_key", "wire_size"), MANUAL_CASES
)
@pytest.mark.parametrize("bad_size", [0, -1, True, "200", None])
async def test_malformed_public_cursor_continuation_fails_before_upstream(
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    path: str,
    argument: str,
    logical_size: str,
    token_key: str,
    wire_size: str,
    bad_size: Any,
) -> None:
    up = PageIndexTokens()
    uh.install(monkeypatch, up)
    with pytest.raises(ToolError, match="_continuation"):
        await server.mcp.call_tool(
            tool, {argument: encode_continuation({token_key: "2", wire_size: bad_size})}
        )
    assert up.requests == []


@pytest.mark.parametrize("tool,path,argument,logical_size,token_key,wire_size", MANUAL_CASES)
@pytest.mark.parametrize("token", ["ufpg1:", "ufpg1:!", "ufpg1:e30", "ufpg1:YWJj", "ufpg1:_w"])
async def test_invalid_opaque_encoding_fails_before_upstream(
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    path: str,
    argument: str,
    logical_size: str,
    token_key: str,
    wire_size: str,
    token: str,
) -> None:
    up = PageIndexTokens()
    uh.install(monkeypatch, up)
    with pytest.raises(ToolError, match="Malformed _continuation token"):
        await server.mcp.call_tool(tool, {argument: token})
    assert up.requests == []


def test_opaque_continuation_transport_round_trip_and_native_compatibility() -> None:
    state = {"pageToken": "native:opaque/世界", "pageSize": 275, "offset": 400}
    token = encode_continuation(state)
    assert token.startswith("ufpg1:")
    assert "=" not in token
    assert decode_continuation(token) == state
    assert decode_continuation("native:opaque/世界") == "native:opaque/世界"
    assert decode_continuation(None) is None
