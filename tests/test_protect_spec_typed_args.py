"""Protect arguments accept every form the pinned spec types them with.

* ``outputId`` (relay activate / alarm-hub trigger) is a spec integer 0 or 1: the
  integer itself is accepted, and the decimal string form still works.
* ``removedQualities`` (``delete_rtsps_stream``) is ``anyOf`` a ``channelQuality``
  scalar or a non-empty array: one channel as a string is accepted as well as a list.
  ``createdQualities`` (``create_rtsps_stream``) is array-only and stays a list.

Out-of-spec values still fail before any request.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from unifi_fabric import server
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.registry import Registry

H = "host-typed-001"
PROT = f"https://api.ui.com/v1/connector/consoles/{H}/proxy/protect/integration/v1"
DEV = "66d025b301ebc903e80003ea"


@pytest.fixture()
def tools(monkeypatch):
    settings = Settings(api_key="sk-typed-args")
    client = UniFiClient(settings)
    monkeypatch.setattr(server, "_settings", settings)
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", Registry(client, ttl_seconds=60))


def _router() -> respx.MockRouter:
    router = respx.mock(assert_all_called=False)
    router.get("https://api.ui.com/v1/hosts").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"id": H, "type": "console", "reportedState": {"hostname": "c1"}}]},
        )
    )
    return router


async def _call(name: str, args: dict[str, Any]) -> Any:
    return (await server.mcp.call_tool(name, args)).structured_content


OUTPUT_TOOLS = {
    "relay_activate_output": ("relay_id", "relays", "activate"),
    "alarm_hub_trigger_output": ("alarm_hub_id", "alarm-hubs", "trigger"),
}


@pytest.mark.parametrize("tool", sorted(OUTPUT_TOOLS))
@pytest.mark.parametrize(("output_id", "sent"), [(0, 0), (1, 1), ("0", 0), ("1", 1)])
async def test_output_id_integer_and_string_forms(tools, tool, output_id, sent):
    arg, family, action = OUTPUT_TOOLS[tool]
    with _router() as router:
        route = router.post(f"{PROT}/{family}/{DEV}/outputs/{sent}/{action}").mock(
            return_value=httpx.Response(200, json={})
        )
        result = await _call(tool, {"host": H, arg: DEV, "output_id": output_id})
    assert route.call_count == 1
    assert result["status"] == "sent"


@pytest.mark.parametrize("tool", sorted(OUTPUT_TOOLS))
@pytest.mark.parametrize("output_id", [2, -1, "2", "-1", "x", "", " 0"])
async def test_output_id_out_of_spec_fails_before_any_request(tools, tool, output_id):
    arg, _family, _action = OUTPUT_TOOLS[tool]
    with _router() as router:
        writes = router.route(method="POST").mock(return_value=httpx.Response(200, json={}))
        with pytest.raises(ToolError, match="output_id"):
            await _call(tool, {"host": H, arg: DEV, "output_id": output_id})
    assert writes.call_count == 0


@pytest.mark.parametrize(
    ("qualities", "query"),
    [
        ("high", "qualities=high"),
        (["high"], "qualities=high"),
        (["high", "low"], "qualities=high&qualities=low"),
    ],
)
async def test_delete_rtsps_qualities_scalar_and_list(tools, qualities, query):
    with _router() as router:
        route = router.delete(f"{PROT}/cameras/{DEV}/rtsps-stream").mock(
            return_value=httpx.Response(204)
        )
        result = await _call(
            "delete_rtsps_stream", {"host": H, "camera_id": DEV, "qualities": qualities}
        )
    assert route.call_count == 1
    assert route.calls[0].request.url.query.decode() == query
    assert result["deleted"] is True


@pytest.mark.parametrize("qualities", ["", "HIGH", "highest", [], ["HIGH"], [" high"]])
async def test_delete_rtsps_out_of_spec_qualities_fail_before_any_request(tools, qualities):
    with _router() as router:
        route = router.delete(f"{PROT}/cameras/{DEV}/rtsps-stream").mock(
            return_value=httpx.Response(204)
        )
        with pytest.raises(ToolError, match="qualities"):
            await _call(
                "delete_rtsps_stream", {"host": H, "camera_id": DEV, "qualities": qualities}
            )
    assert route.call_count == 0


async def test_create_rtsps_qualities_stays_array_only(tools):
    with _router() as router:
        route = router.post(f"{PROT}/cameras/{DEV}/rtsps-stream").mock(
            return_value=httpx.Response(200, json={})
        )
        with pytest.raises(ToolError):
            await _call("create_rtsps_stream", {"host": H, "camera_id": DEV, "qualities": "high"})
    assert route.call_count == 0


@pytest.mark.parametrize(
    ("value", "ok"),
    [("high", True), (["low"], True), ("HIGH", False), (["HIGH"], False), ([], False)],
)
def test_mixed_type_alternatives_bind_their_own_type(value, ok):
    from unifi_fabric._spec_limits_table import SPEC_LIMITS
    from unifi_fabric.spec_limits import limit_problems

    limits = SPEC_LIMITS["delete_rtsps_stream"]["qualities"]
    assert [alt.get("type") for alt in limits["anyOf"]] == ["array", "string"]
    assert (limit_problems(value, limits, "'qualities'") == []) is ok
