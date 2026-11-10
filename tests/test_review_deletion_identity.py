"""Post-write evidence must identify records and the exact resource request."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from tests.test_network_dpi_policy_batch_delete import (
    IDS,
    IMPLS,
    TOOLS,
    V2,
    FakeConsole,
    real_client,
)
from tests.test_network_dpi_policy_review_failures import bound_context
from unifi_fabric.client import UniFiConnectionError, UniFiHTTPError
from unifi_fabric.families.devices import device_commands
from unifi_fabric.families.network import network_dpi_policy as dpi
from unifi_fabric.families.network import network_routing_topology as routing
from unifi_fabric.families.protect import protect_automation_backup as backups
from unifi_fabric.shared_shapes._payload import upstream_hint
from unifi_fabric.shared_shapes._results import deletion_readback_ids


@pytest.mark.parametrize(
    "rows", [[{}], [{"_id": None}], [{"id": ""}], [None], ["opaque"], [{"id": 3}]]
)
def test_unidentified_rows_cannot_prove_absence(rows):
    with pytest.raises(UniFiConnectionError, match="no usable identity") as caught:
        deletion_readback_ids(rows, "_id", "id")
    assert "got " in str(caught.value)


@pytest.mark.parametrize("tool,collection,_list_tool", TOOLS)
@pytest.mark.parametrize("identity", [None, "", 7])
async def test_acl_zone_identity_loss_is_unverified(tool, collection, _list_tool, identity):
    console = FakeConsole(collection, kind="stuck")

    def handler(request):
        response = console(request)
        if request.method == "POST":
            console.rows = [{"_id": identity, "external_id": IDS[0]}]
        return response

    reg = SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="test-host"),
        resolve_site_slug=AsyncMock(return_value="default"),
    )
    client, transport = real_client(handler)
    async with transport:
        result = await IMPLS[tool](client, reg, "host", "site", IDS)
    assert result["deleted"] is not True
    assert "no usable identity" in result["readAfterError"]
    assert len(console.posts()) == 1
    assert console.requests[-1].url.path == f"{V2}/{collection}"


@pytest.mark.parametrize(
    "suffix,write_suffix",
    [
        ("/bgp/config/all", "/bgp/config"),
        ("/ospf/router", "/ospf/router"),
        ("/mclag-groups", "/mclag-groups"),
    ],
)
@pytest.mark.parametrize("row", [{}, {"id": None}, {"_id": 7}])
async def test_routing_identity_loss_is_unverified(monkeypatch, suffix, write_suffix, row):
    monkeypatch.setattr(routing, "_site", AsyncMock(return_value=(None, "host-id", "default")))
    monkeypatch.setattr(
        routing, "_listed_record", AsyncMock(return_value=({"_id": "known"}, "known"))
    )
    monkeypatch.setattr(routing, "_bgp_write_suffix", AsyncMock(return_value="/bgp/config/known"))
    client = SimpleNamespace(
        get=AsyncMock(return_value=[row]), delete=AsyncMock(return_value={"accepted": True})
    )
    result = await routing._delete_listed(
        client,
        None,
        "host",
        "site",
        list_suffix=suffix,
        write_suffix=write_suffix,
        identifier="known",
        label="record",
    )
    assert result["deleted"] is None
    assert "no usable identity" in result["readAfterError"]
    assert result["response"] == {"accepted": True}
    client.delete.assert_awaited_once()


@pytest.mark.parametrize("row", [{}, {"id": None}, {"id": 7}, None, "opaque"])
async def test_backup_identity_loss_is_unverified(monkeypatch, row):
    monkeypatch.setattr(backups, "_require_mutations", lambda: None)
    monkeypatch.setattr(backups, "guard_action", lambda *_: None)
    monkeypatch.setattr(backups, "_resolve", AsyncMock(return_value=(None, "host-id")))
    monkeypatch.setattr(backups, "_known", AsyncMock(return_value={"id": "backup-fixture"}))
    client = SimpleNamespace(get=AsyncMock(return_value=[row]), delete=AsyncMock(return_value=None))
    result = await backups._delete_protect_backup(client, None, "host", "backup-fixture")
    assert result["deleted"] is None
    assert "no usable identity" in result["readAfterError"]
    client.delete.assert_awaited_once()


@pytest.mark.parametrize("step", ["resolve_key_for_host", "resolve_host_id", "resolve_site_id"])
async def test_resolution_404_never_confirms_policy_deletion(monkeypatch, step):
    client, registry = bound_context(AsyncMock())
    failure = UniFiHTTPError("resolution endpoint not found", request_sent=True, status=404)
    getattr(registry, step).side_effect = failure
    delete = AsyncMock()
    client.delete = delete
    with pytest.raises(UniFiHTTPError) as caught:
        await dpi._batch_delete_firewall_policies(client, registry, "host", "site", ["policy"])
    assert caught.value is failure
    delete.assert_not_awaited()
    client.get.assert_not_awaited()


async def test_partial_policy_reads_do_not_resolve_registry_again(monkeypatch):
    reads = AsyncMock(side_effect=[UniFiHTTPError("policy absent", status=404)])
    client, registry = bound_context(reads)

    async def delete(_path, **_kwargs):
        if delete.calls == 0:
            delete.calls += 1
            registry.resolve_site_id.side_effect = UniFiHTTPError("site disappeared", status=404)
            return None
        raise UniFiHTTPError("delete failed", status=500)

    delete.calls = 0
    client.delete = delete
    with pytest.raises(UniFiHTTPError) as caught:
        await dpi._batch_delete_firewall_policies(
            client, registry, "host", "site", ["first", "second", "later"]
        )
    assert "Deleted before this failure: ['first']" in str(caught.value)
    assert caught.value.status == 500
    assert reads.await_args.args[0].endswith("/firewall/policies/first")
    registry.resolve_site_id.assert_awaited_once()


@pytest.mark.parametrize("kind", [UniFiHTTPError, UniFiConnectionError])
def test_upstream_hint_preserves_exception_class_and_metadata(kind):
    failure = kind("upstream 404", request_sent=True, status=404)
    hinted = upstream_hint(failure, "documented guidance")
    assert type(hinted) is kind
    assert hinted.request_sent is True and hinted.status == 404
    assert str(failure) in str(hinted)


@pytest.mark.parametrize("kind", [UniFiHTTPError, UniFiConnectionError])
async def test_export_hint_preserves_exception_class_metadata_and_cause(monkeypatch, kind):
    failure = kind("api.err.BackupFailed", request_sent=True, status=400)
    monkeypatch.setattr(device_commands, "_command", AsyncMock(side_effect=failure))
    with pytest.raises(kind) as caught:
        await device_commands.export_site(None, None, "host", "site")
    assert type(caught.value) is kind
    assert caught.value.status == 400 and caught.value.request_sent is True
    assert caught.value.__cause__ is failure
