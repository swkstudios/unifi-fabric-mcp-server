"""Partial firewall policy deletion failures report only verified outcomes."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastmcp.exceptions import ToolError

from unifi_fabric.client import DRY_RUN_MESSAGE, UniFiConnectionError, UniFiHTTPError
from unifi_fabric.tools import network_dpi_policy as lane


def bound_context(get):
    registry = SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="host-id"),
        resolve_site_id=AsyncMock(return_value="00000000-0000-3000-a000-000000000016"),
    )
    return SimpleNamespace(get=get), registry


@pytest.mark.parametrize(
    "error",
    [
        UniFiConnectionError("unsent", request_sent=False),
        UniFiConnectionError("sent", request_sent=True),
        UniFiHTTPError("http failure", request_sent=True, status=500),
        RuntimeError("unexpected failure"),
        ToolError("tool failure"),
    ],
)
async def test_partial_failure_reports_verified_and_uncertain_ids(monkeypatch, error):
    ids = ["gone", "present", "unknown", "failed", "later"]
    delete = AsyncMock(side_effect=[None, None, None, error])
    get = AsyncMock(
        side_effect=[
            UniFiHTTPError("not found", status=404),
            {"id": "present"},
            UniFiConnectionError("read failed"),
        ]
    )
    client, registry = bound_context(get)
    client.delete = delete

    expected_type = type(error) if isinstance(error, UniFiConnectionError) else ToolError
    with pytest.raises(expected_type) as caught:
        await lane._batch_delete_firewall_policies(client, registry, "host", "site", ids)

    message = str(caught.value)
    assert "Deleted before this failure: ['gone']" in message
    assert "still present: ['present']" in message
    assert "unverified: ['unknown']" in message
    assert "failed/uncertain: ['failed']" in message
    assert "not attempted: ['later']" in message
    assert delete.await_count == 4
    assert [call.args[0].rsplit("/", 1)[-1] for call in get.await_args_list] == ids[:3]
    if isinstance(error, UniFiConnectionError):
        assert caught.value.request_sent is error.request_sent
        assert caught.value.status == error.status
    assert caught.value.__cause__ is error


async def test_prior_dry_run_preview_was_not_attempted(monkeypatch):
    preview = {"dryRun": True, "message": DRY_RUN_MESSAGE, "preview": {}}
    delete = AsyncMock(side_effect=[preview, RuntimeError("failure")])
    get = AsyncMock()
    client, registry = bound_context(get)
    client.delete = delete

    with pytest.raises(ToolError) as caught:
        await lane._batch_delete_firewall_policies(
            client, registry, "host", "site", ["a", "b", "c"]
        )

    assert "Deleted before this failure: none" in str(caught.value)
    assert "failed/uncertain: ['b']" in str(caught.value)
    assert "not attempted: ['a', 'c']" in str(caught.value)
    get.assert_not_awaited()
