from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import ClassicApiError, UniFiConnectionError
from unifi_fabric.tools import _classic_cmd, carrier_fabric, device_mgmt, mobility
from unifi_fabric.tools import network_clients_guests as clients
from unifi_fabric.tools import network_dpi_policy as dpi
from unifi_fabric.tools import network_proav_sandbox as proav
from unifi_fabric.tools import network_security_diagnostics as diagnostics


async def test_classic_preserves_failure_metadata():
    client = SimpleNamespace(
        request=AsyncMock(side_effect=ClassicApiError("bad", request_sent=True, status=503))
    )
    with pytest.raises(ClassicApiError) as error:
        await _classic_cmd.classic_command(client, "host", "default", "devmgr", "restart")
    assert error.value.request_sent and error.value.status == 503


@pytest.mark.parametrize("module, args", [(mobility, ()), (carrier_fabric, ("POST",))])
def test_direct_write_guard_respects_read_only(module, args, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    with pytest.raises(Exception, match="(?i)read.only"):
        module._require_writes(*args)


async def test_client_multicast_rejects_body_before_resolution():
    with pytest.raises(ValueError, match="body"):
        await proav.get_multicast_insights(
            None, None, "host", "site", "client", "02:00:5e:00:00:a1", body={}
        )


async def test_connected_client_without_id_falls_back_to_mac(monkeypatch):
    monkeypatch.setattr(
        clients,
        "collect_offset",
        AsyncMock(
            return_value={"incomplete": False, "items": [{"macAddress": "02:00:5e:00:00:a1"}]}
        ),
    )
    assert await clients._write_client_target(
        None, "host", "site", "default", "02:00:5e:00:00:a1", None
    ) == (None, "02:00:5e:00:00:a1")


async def test_empty_batch_delete_makes_no_request(monkeypatch):
    client = SimpleNamespace(get=AsyncMock(return_value=[]), post=AsyncMock(return_value=[]))
    registry = SimpleNamespace()
    context = AsyncMock(return_value=("key", "/acl-rules"))
    monkeypatch.setattr(dpi, "_context", context)
    result = await dpi._batch_delete_acl_rules(client, registry, "host", "site", [])
    assert result["deleted"] is False
    assert result["response"] is None
    context.assert_not_awaited()
    client.get.assert_not_awaited()
    client.post.assert_not_awaited()


async def test_device_error_redacts_identifying_fields(monkeypatch):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    monkeypatch.setattr(
        device_mgmt,
        "collect_offset",
        AsyncMock(
            return_value={
                "items": [
                    {"macAddress": "02:00:5e:00:00:a1", "name": '{"password": "syntheticsecret"}'}
                ],
                "incomplete": False,
            }
        ),
    )
    with pytest.raises(UniFiConnectionError) as error:
        await device_mgmt._resolve_device_id(
            SimpleNamespace(_settings=SimpleNamespace(cache_ttl_seconds=0)),
            "host",
            "site",
            "02:00:5e:00:00:a1",
            key=None,
        )
    assert "syntheticsecret" not in str(error.value)


async def test_scalar_topology_failure_does_not_echo_body(monkeypatch):
    monkeypatch.setattr(diagnostics, "_site", AsyncMock(return_value=(None, "host", "default")))
    client = SimpleNamespace(get=AsyncMock(side_effect=["syntheticsecret", [], {}]))
    result = await diagnostics.get_unified_ip_thread_topology(client, None, "host", "site")
    assert "syntheticsecret" not in str(result)


async def test_qos_case_mismatch_does_not_claim_delete(monkeypatch):
    from unifi_fabric.tools import network_nat_qos_traffic as qos

    monkeypatch.setattr(qos, "_nc_site", AsyncMock(return_value=(None, "host", "default")))
    client = SimpleNamespace(
        get=AsyncMock(return_value=[{"_id": "abc"}]), post=AsyncMock(return_value=None)
    )
    result = await qos.delete_qos_rule(client, None, "host", "site", ["ABC"])
    assert client.post.call_args.kwargs["json"] == ["ABC"]
    assert result["deleted"] is False


async def test_wireguard_case_mismatch_does_not_claim_delete(monkeypatch):
    from unifi_fabric.tools import network_vpn_dns as vpn

    monkeypatch.setattr(
        vpn, "_vpn_server", AsyncMock(return_value=(None, "host", "default", "server"))
    )
    client = SimpleNamespace(
        get=AsyncMock(return_value=[{"_id": "abc"}]), post=AsyncMock(return_value=None)
    )
    payload = [{"_id": "ABC"}]
    result = await vpn.delete_wireguard_users(client, None, "host", "site", "server", payload)
    assert client.post.call_args.kwargs["json"] == payload
    assert result["deleted"] is False


@pytest.mark.parametrize("readback", [[], RuntimeError("read failed")])
@pytest.mark.parametrize("kind", ["qos", "wireguard"])
async def test_delete_readback_success_and_error(monkeypatch, kind, readback):
    from unifi_fabric.tools import network_nat_qos_traffic as qos
    from unifi_fabric.tools import network_vpn_dns as vpn

    client = SimpleNamespace(
        get=AsyncMock(side_effect=[[{"_id": "abc"}], readback]),
        post=AsyncMock(return_value={"upstream": "kept"}),
    )
    if kind == "qos":
        monkeypatch.setattr(qos, "_nc_site", AsyncMock(return_value=(None, "host", "default")))
        result = await qos.delete_qos_rule(client, None, "host", "site", ["abc"])
    else:
        monkeypatch.setattr(
            vpn, "_vpn_server", AsyncMock(return_value=(None, "host", "default", "server"))
        )
        result = await vpn.delete_wireguard_users(client, None, "host", "site", "server", ["abc"])
    assert result["response"] == {"upstream": "kept"}
    assert result["deleted"] is (not isinstance(readback, Exception))


async def test_batch_delete_rejects_missing_private_id(monkeypatch):
    client = SimpleNamespace(post=AsyncMock())
    monkeypatch.setattr(dpi, "_context", AsyncMock(return_value=("key", "/acl-rules")))
    monkeypatch.setattr(dpi, "_v2_rows", AsyncMock(return_value=[{"external_id": "external"}]))
    with pytest.raises(ValueError, match="ids"):
        await dpi._batch_delete_acl_rules(client, None, "host", "site", ["external"])
    client.post.assert_not_awaited()


async def test_traffic_period_error_uses_supported_example():
    from unifi_fabric.tools import network_nat_qos_traffic as qos

    with pytest.raises(ValueError, match='e.g. "DAY"'):
        await qos.get_latest_traffic_flow_stats(None, None, "host", "site", 1)


async def test_wan_health_error_redacts_credentials(monkeypatch):
    from unifi_fabric.tools import network

    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    monkeypatch.setattr(network, "_assert_uuid", lambda _: None)
    monkeypatch.setattr(network, "collect_offset", AsyncMock(return_value={}))
    monkeypatch.setattr(network, "offset_list_result", lambda _: {"data": []})
    client = SimpleNamespace(get=AsyncMock(side_effect=Exception('{"password":"syntheticsecret"}')))
    registry = SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value="host-id"),
        resolve_site_id=AsyncMock(return_value="site-id"),
        resolve_site_slug=AsyncMock(return_value="default"),
    )
    result = await network.list_wan_interfaces(client, registry, "host", "site")
    assert "syntheticsecret" not in result["_wanHealthError"]
