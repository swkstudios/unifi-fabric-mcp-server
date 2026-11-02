"""Length limits the spec counts AFTER trimming are not applied to the raw value.

Carrier Fabric ``SubscriberPatch.subscriberNumber`` is "1-32 characters after trimming"
(pinned carrier-fabric-1.0.0): a raw-length ``minLength`` / ``maxLength`` would refuse
``"<32 chars>  "``, which the upstream accepts. The generator drops those keywords for
every :data:`tests.spec_limits_gen.TRIMMED_LENGTH_ARGS` entry and the tool checks the
trimmed length; ``SubscriberCreate.subscriberNumber`` states no trimming, so create keeps
counting the value as given.
"""

from __future__ import annotations

import json

import pytest
import respx
from fastmcp.exceptions import ToolError
from httpx import Response

from tests import spec_limits_gen as gen
from tests import test_spec_conformance as sc
from unifi_fabric import server
from unifi_fabric._spec_limits_table import SPEC_LIMITS
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.tools.carrier_fabric import CARRIER_BASE

SID = "11111111-1111-4111-8111-111111111111"
SUBS = f"https://api.ui.com{CARRIER_BASE}/subscribers"
SUB = f"{SUBS}/{SID}"


@pytest.mark.parametrize(("tool", "arg"), sorted(gen.TRIMMED_LENGTH_ARGS))
def test_trimmed_length_is_quoted_from_the_spec_and_left_out_of_the_table(tool, arg):
    service, schema, prop, sentence = gen.TRIMMED_LENGTH_ARGS[(tool, arg)]
    node = sc.specs()[service].doc["components"]["schemas"][schema]["properties"][prop]
    assert sentence in node["description"]
    assert {"minLength", "maxLength"} & set(node), "spec carries the raw keywords"
    assert not {"minLength", "maxLength"} & set(SPEC_LIMITS.get(tool, {}).get(arg, {}))


@pytest.fixture()
def tools(monkeypatch):
    client = UniFiClient(Settings(api_key="sk-trim-test"))
    monkeypatch.setattr(server, "_require", lambda: (client, object()))


def _sub(number: str) -> dict:
    return {"data": {"id": SID, "subscriberNumber": number, "suspended": False}}


async def _call(name: str, args: dict) -> dict:
    result = await server.mcp.call_tool(name, args)
    return result.structured_content


@respx.mock
@pytest.mark.parametrize("number", ["x" * 32 + "  ", "  " + "x" * 32, "\t" + "y" * 32 + "\n"])
async def test_update_accepts_32_trimmed_chars_with_surrounding_whitespace(tools, number):
    respx.get(SUB).mock(return_value=Response(200, json=_sub("old")))
    patch = respx.patch(SUB).mock(return_value=Response(200, json=_sub(number.strip())))
    await _call("update_carrier_subscriber", {"subscriber_id": SID, "subscriber_number": number})
    assert patch.call_count == 1
    # Sent as given (the upstream trims), never rewritten.
    assert json.loads(patch.calls[0].request.content) == {"subscriberNumber": number}


@respx.mock
@pytest.mark.parametrize("number", ["x" * 33, " " + "x" * 33 + " ", "   ", ""])
async def test_update_refuses_values_out_of_range_after_trimming(tools, number):
    route = respx.route().mock(return_value=Response(200, json=_sub("old")))
    with pytest.raises(ToolError, match="subscriber_number"):
        await _call(
            "update_carrier_subscriber", {"subscriber_id": SID, "subscriber_number": number}
        )
    assert route.call_count == 0


@respx.mock
async def test_create_counts_the_value_as_given(tools):
    route = respx.route().mock(return_value=Response(201, json=_sub("x")))
    with pytest.raises(ToolError, match="subscriber_number"):
        await _call("create_carrier_subscriber", {"subscriber_number": "x" * 32 + " "})
    assert route.call_count == 0
    assert SPEC_LIMITS["create_carrier_subscriber"]["subscriber_number"] == {
        "minLength": 1,
        "maxLength": 32,
    }
