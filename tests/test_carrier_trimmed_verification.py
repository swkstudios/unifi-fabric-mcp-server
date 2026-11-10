"""A SubscriberPatch's upstream trimming is verified without rewriting the request."""

from __future__ import annotations

import json

import respx
from httpx import Response

from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.families.carrier.carrier_fabric import CARRIER_BASE

SID = "11111111-1111-4111-8111-111111111111"
SUB = f"https://api.ui.com{CARRIER_BASE}/subscribers/{SID}"


@respx.mock
async def test_trimmed_subscriber_number_verifies_and_preserves_the_submitted_body(
    monkeypatch, multikey_client, multikey_registry
):
    number = "  " + "x" * 32 + "  "
    before = {"data": {"id": SID, "subscriberNumber": "old", "suspended": False}}
    after = {"data": {"id": SID, "subscriberNumber": number.strip(), "suspended": False}}
    respx.get(SUB).mock(side_effect=[Response(200, json=before), Response(200, json=after)])
    patch = respx.patch(SUB).mock(return_value=Response(200, json=after))
    monkeypatch.setattr(server, "_client", multikey_client)
    monkeypatch.setattr(server, "_registry", multikey_registry)
    try:
        result = await server.mcp.call_tool(
            "update_carrier_subscriber",
            {"subscriber_id": SID, "subscriber_number": number, "key_label": "beta"},
        )
        payload = uh.result_payload(result)
        assert patch.call_count == 1
        assert json.loads(patch.calls[0].request.content) == {"subscriberNumber": number}
        assert patch.calls[0].request.headers["X-API-KEY"] == "k-beta"
        assert payload["response"] == after
        assert payload["subscriber"] == after
        assert payload["changed"]["subscriberNumber"]["to"] == number.strip()
        assert payload["verified"] is True
    finally:
        await multikey_client.close()
