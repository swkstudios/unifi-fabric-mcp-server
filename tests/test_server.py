"""Tests for server.py — main(), lifespan(), _require(), and @mcp.tool() wrappers."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import unifi_fabric.server as server_module
from unifi_fabric import server

# ---------------------------------------------------------------------------
# _require()
# ---------------------------------------------------------------------------


class TestRequire:
    def setup_method(self):
        # Save originals
        self._orig_client = server_module._client
        self._orig_registry = server_module._registry

    def teardown_method(self):
        # Restore originals
        server_module._client = self._orig_client
        server_module._registry = self._orig_registry

    def test_raises_when_not_initialized(self):
        server_module._client = None
        server_module._registry = None
        with pytest.raises(RuntimeError, match="Server not initialized"):
            server._require()

    def test_raises_when_client_none(self):
        server_module._client = None
        server_module._registry = MagicMock()
        with pytest.raises(RuntimeError, match="Server not initialized"):
            server._require()

    def test_raises_when_registry_none(self):
        server_module._client = MagicMock()
        server_module._registry = None
        with pytest.raises(RuntimeError, match="Server not initialized"):
            server._require()

    def test_returns_client_and_registry_when_initialized(self):
        mock_client = MagicMock()
        mock_registry = MagicMock()
        server_module._client = mock_client
        server_module._registry = mock_registry

        client, registry = server._require()
        assert client is mock_client
        assert registry is mock_registry


class TestPlacementSnapshotNoWriteFence:
    """The GET-only placement collector runs under every connector-write setting: no
    refusal gate; writes are on by default."""

    @pytest.mark.parametrize("exceptions", [None, "family:connector=deny"])
    async def test_uses_snapshot_collector_whatever_the_write_setting(
        self, exceptions, monkeypatch
    ):
        if exceptions is not None:
            monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", exceptions)
        client = MagicMock()
        registry = MagicMock()
        expected = {"schema_version": "unifi.placement-snapshot/v1"}
        with (
            patch(
                "unifi_fabric.server.get_settings",
                return_value=SimpleNamespace(api_key="synthetic"),
            ),
            patch("unifi_fabric.server._require", return_value=(client, registry)),
            patch(
                "unifi_fabric.server.placement_snapshot.get_unifi_placement_snapshot",
                AsyncMock(return_value=expected),
            ) as collector,
        ):
            assert await server.get_unifi_placement_snapshot("HQ-Unifi") == expected
        collector.assert_awaited_once_with(client, registry, "HQ-Unifi")


# ---------------------------------------------------------------------------
# lifespan()
# ---------------------------------------------------------------------------


class TestLifespan:
    @staticmethod
    def _lifespan_app() -> MagicMock:
        """Minimal FastMCP double for the lifecycle's discovery-mode setup."""
        app = MagicMock()
        app.list_tools = AsyncMock(return_value=[])
        # The lifespan also records prompt names for trace export (awaited like list_tools).
        app.list_prompts = AsyncMock(return_value=[])
        return app

    def setup_method(self):
        self._orig_client = server_module._client
        self._orig_registry = server_module._registry

    def teardown_method(self):
        server_module._client = self._orig_client
        server_module._registry = self._orig_registry

    async def test_initializes_globals_on_enter(self):
        server_module._client = None
        server_module._registry = None

        mock_client = AsyncMock()
        mock_registry = MagicMock()

        with (
            patch("unifi_fabric.config.Settings.get_key_configs", return_value=[{"key": "test"}]),
            patch("unifi_fabric.server.UniFiClient", return_value=mock_client) as mock_client_cls,
            patch("unifi_fabric.server.Registry", return_value=mock_registry) as mock_registry_cls,
        ):
            async with server.lifespan(self._lifespan_app()):
                assert server_module._client is mock_client
                assert server_module._registry is mock_registry
                mock_client_cls.assert_called_once()
                mock_registry_cls.assert_called_once_with(
                    mock_client, ttl_seconds=900, cache_max_hosts=512, cache_max_sites=2048
                )

    async def test_clears_globals_on_exit(self):
        server_module._client = None
        server_module._registry = None

        mock_client = AsyncMock()

        with (
            patch("unifi_fabric.config.Settings.get_key_configs", return_value=[{"key": "test"}]),
            patch("unifi_fabric.server.UniFiClient", return_value=mock_client),
            patch("unifi_fabric.server.Registry", return_value=MagicMock()),
        ):
            async with server.lifespan(self._lifespan_app()):
                pass  # inside context

        assert server_module._client is None
        assert server_module._registry is None

    async def test_calls_client_close_on_exit(self):
        server_module._client = None
        server_module._registry = None

        mock_client = AsyncMock()
        mock_client.close = AsyncMock()

        with (
            patch("unifi_fabric.config.Settings.get_key_configs", return_value=[{"key": "test"}]),
            patch("unifi_fabric.server.UniFiClient", return_value=mock_client),
            patch("unifi_fabric.server.Registry", return_value=MagicMock()),
        ):
            async with server.lifespan(self._lifespan_app()):
                pass

        mock_client.close.assert_awaited_once()

    @pytest.mark.parametrize("body_error", [False, True])
    async def test_closes_oauth_jwks_client_on_exit(self, body_error, monkeypatch):
        from unifi_fabric.config import MCPTransportSettings

        monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
        auth = server.build_auth(
            MCPTransportSettings(
                auth_mode="oauth",
                oauth_issuer="https://issuer.example/",
                oauth_jwks_uri="https://issuer.example/jwks",
                oauth_audience="https://resource.example/",
                oauth_base_url="https://resource.example/",
            )
        )
        jwks_client = auth.token_verifier._http_client
        app = self._lifespan_app()
        app.auth = auth
        mock_client = AsyncMock()
        with (
            patch("unifi_fabric.config.Settings.get_key_configs", return_value=[{"key": "test"}]),
            patch("unifi_fabric.server.UniFiClient", return_value=mock_client),
            patch("unifi_fabric.server.Registry", return_value=MagicMock()),
        ):
            try:
                async with server.lifespan(app):
                    assert not jwks_client.is_closed
                    if body_error:
                        raise ValueError("synthetic lifecycle failure")
            except ValueError:
                assert body_error
        assert jwks_client.is_closed
        mock_client.close.assert_awaited_once()

    async def test_clears_globals_even_on_error(self):
        server_module._client = None
        server_module._registry = None

        mock_client = AsyncMock()

        with (
            patch("unifi_fabric.config.Settings.get_key_configs", return_value=[{"key": "test"}]),
            patch("unifi_fabric.server.UniFiClient", return_value=mock_client),
            patch("unifi_fabric.server.Registry", return_value=MagicMock()),
        ):
            with pytest.raises(ValueError):
                async with server.lifespan(self._lifespan_app()):
                    raise ValueError("boom")

        assert server_module._client is None
        assert server_module._registry is None


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_calls_mcp_run(self, monkeypatch):
        monkeypatch.setenv("UNIFI_API_KEY", "synthetic-test-key")
        with patch.object(server_module.mcp, "run") as mock_run:
            server.main()
            mock_run.assert_called_once_with()


# ---------------------------------------------------------------------------
# Helpers — fixtures for tool wrapper tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_globals():
    """Patch _client and _registry globals, yield (mock_client, mock_registry)."""
    orig_client = server_module._client
    orig_registry = server_module._registry

    mock_client = AsyncMock()
    mock_registry = AsyncMock()
    server_module._client = mock_client
    server_module._registry = mock_registry

    yield mock_client, mock_registry

    server_module._client = orig_client
    server_module._registry = orig_registry


# ---------------------------------------------------------------------------
# @mcp.tool() wrappers — site_manager group
# ---------------------------------------------------------------------------


class TestListHostsWrapper:
    async def test_delegates_to_site_manager(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        target = "unifi_fabric.server.site_manager.list_hosts"
        with patch(target, new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_hosts(page_token="tok")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, page_token="tok", page_size=None, key_label=None
        )
        assert result is expected


class TestGetHostWrapper:
    async def test_delegates_to_site_manager(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "h1"}

        with patch("unifi_fabric.server.site_manager.get_host", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_host("my-console")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "my-console")
        assert result is expected


class TestListSitesWrapper:
    async def test_delegates_to_site_manager(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": [{"id": "s1"}]}

        target = "unifi_fabric.server.site_manager.list_sites"
        with patch(target, new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_sites(page_token=None)

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, page_token=None, page_size=None, key_label=None
        )
        assert result is expected


class TestGetIspMetricsWrapper:
    async def test_delegates_with_client_only(self, mock_globals):
        mock_client, _ = mock_globals
        expected = {"wan": []}

        with patch(
            "unifi_fabric.server.site_manager.get_isp_metrics", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_isp_metrics("wan")

        # get_isp_metrics only uses client, not registry
        mock_fn.assert_awaited_once_with(
            mock_client, "wan", duration=None, begin_timestamp=None, end_timestamp=None
        )
        assert result is expected


class TestListDevicesWrapper:
    async def test_delegates_to_site_manager(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.site_manager.list_devices", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_devices(host="h1", page_token="p")

        mock_fn.assert_awaited_once_with(
            mock_client,
            mock_registry,
            host="h1",
            page_token="p",
            time=None,
            page_size=None,
            key_label=None,
        )
        assert result is expected


# ---------------------------------------------------------------------------
# @mcp.tool() wrappers — network group
# ---------------------------------------------------------------------------


class TestGetNetworkApplicationInfoWrapper:
    async def test_delegates_to_network(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"applicationVersion": "10.4.57"}

        with patch(
            "unifi_fabric.server.network.get_network_application_info",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_network_application_info("myhost")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "myhost")
        assert result is expected


class TestListLocalSitesWrapper:
    async def test_delegates_to_network(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.network.list_local_sites", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_local_sites(
                "myhost", offset=10, limit=50, filter="name.like('lab*')"
            )

        mock_fn.assert_awaited_once_with(
            mock_client,
            mock_registry,
            "myhost",
            offset=10,
            limit=50,
            filter="name.like('lab*')",
        )
        assert result is expected

    async def test_drains_by_default(self, mock_globals):
        # No offset/limit → the wrapper forwards None/None so the tool drains all pages.
        mock_client, mock_registry = mock_globals
        with patch(
            "unifi_fabric.server.network.list_local_sites", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = {"data": [], "totalCount": 0}
            await server.list_local_sites("myhost")
        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "myhost", offset=None, limit=None, filter=None
        )


class TestListNetworksWrapper:
    async def test_delegates_to_network(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = [{"id": "net-1"}]

        with patch("unifi_fabric.server.network.list_networks", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_networks("myhost", "mysite")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "myhost", "mysite", offset=None, limit=None, filter=None
        )
        assert result is expected

    async def test_forwards_filter_to_network(self, mock_globals):
        mock_client, mock_registry = mock_globals
        with patch("unifi_fabric.server.network.list_networks", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = {"data": []}
            await server.list_networks(
                "myhost", "mysite", offset=5, limit=25, filter="metadata.origin.eq('USER')"
            )
        mock_fn.assert_awaited_once_with(
            mock_client,
            mock_registry,
            "myhost",
            "mysite",
            offset=5,
            limit=25,
            filter="metadata.origin.eq('USER')",
        )


class TestCreateNetworkWrapper:
    async def test_delegates_to_network(self, mock_globals):
        mock_client, mock_registry = mock_globals
        cfg = {"name": "VLAN10", "vlan": 10}
        expected = {"id": "net-new"}

        # networkconf links the created Integration id to its Classic _id; the same body
        # served for portconf holds no custom-tagged profile, so no D12 warning is added.
        mock_client.get = AsyncMock(
            return_value={
                "meta": {"rc": "ok"},
                "data": [{"_id": "65f1c0ffee00000000000009", "external_id": "net-new"}],
            }
        )
        with patch("unifi_fabric.server.network.create_network", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.create_network("h1", "s1", cfg)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", cfg)
        assert result is expected


# ---------------------------------------------------------------------------
# @mcp.tool() wrappers — site_manager extended group
# ---------------------------------------------------------------------------


class TestQueryIspMetricsWrapper:
    async def test_delegates_with_client_only(self, mock_globals):
        mock_client, mock_registry = mock_globals
        mock_registry.resolve_key_for_host.return_value = None
        mock_registry.resolve_host_id.return_value = "h1"
        mock_registry.resolve_ea_site_id.return_value = "s1"
        expected = {"latency": []}

        with patch(
            "unifi_fabric.server.site_manager.query_isp_metrics", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.query_isp_metrics(
                "5m",
                sites=[{"hostId": "h1", "siteId": "s1"}],
                start_time="2024-01-01T00:00:00Z",
                end_time=None,
            )

        mock_fn.assert_awaited_once_with(
            mock_client,
            "5m",
            sites=[{"hostId": "h1", "siteId": "s1"}],
            start_time="2024-01-01T00:00:00Z",
            end_time=None,
            key=None,
        )
        assert result is expected

    async def test_sites_only_scoping(self, mock_globals):
        # A raw sites[] hostId given as a console name is resolved to its id, and the
        # siteId is checked against that console's Site Manager sites before forwarding.
        mock_client, mock_registry = mock_globals
        mock_registry.resolve_key_for_host.return_value = None
        mock_registry.resolve_host_id.return_value = "h9"
        mock_registry.resolve_ea_site_id.return_value = "s9"
        with patch(
            "unifi_fabric.server.site_manager.query_isp_metrics", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = {"latency": []}
            await server.query_isp_metrics(
                "5m",
                sites=[{"hostId": "my-console", "siteId": "s9", "beginTimestamp": "T0"}],
            )

        mock_fn.assert_awaited_once_with(
            mock_client,
            "5m",
            sites=[{"hostId": "h9", "siteId": "s9", "beginTimestamp": "T0"}],
            start_time=None,
            end_time=None,
            key=None,
        )
        mock_registry.resolve_key_for_host.assert_awaited_once_with("my-console")
        mock_registry.resolve_host_id.assert_awaited_once_with("my-console", key=None)
        mock_registry.resolve_ea_site_id.assert_awaited_once_with("s9", host_id="h9", key=None)

    @pytest.mark.parametrize("invalid_selector", ["host", "site"])
    async def test_all_key_selectors_resolve_before_any_query(self, mock_globals, invalid_selector):
        _mock_client, registry = mock_globals
        alpha, beta = SimpleNamespace(label="alpha"), SimpleNamespace(label="beta")
        registry.resolve_key_for_host.side_effect = [alpha, beta]

        async def resolve_host(value, *, key):
            if value == "bad-host" and invalid_selector == "host":
                raise ValueError("Host 'bad-host' not found; valid: alpha-host, beta-host")
            return value

        async def resolve_site(value, *, host_id, key):
            if value == "bad-site" and invalid_selector == "site":
                raise ValueError("Site 'bad-site' not found; valid: Default, Office")
            return value

        registry.resolve_host_id.side_effect = resolve_host
        registry.resolve_ea_site_id.side_effect = resolve_site
        with patch(
            "unifi_fabric.server.site_manager.query_isp_metrics", new_callable=AsyncMock
        ) as query:
            with pytest.raises(ValueError, match="not found; valid:"):
                await server.query_isp_metrics(
                    "5m",
                    sites=[
                        {"hostId": "alpha-host", "siteId": "Office"},
                        {"hostId": "bad-host", "siteId": "bad-site"},
                    ],
                )
        query.assert_not_awaited()

    async def test_sites_unknown_site_fails_before_the_query(self, mock_globals):
        _mock_client, mock_registry = mock_globals
        mock_registry.resolve_key_for_host.return_value = None
        mock_registry.resolve_host_id.return_value = "h9"
        mock_registry.resolve_ea_site_id.side_effect = ValueError(
            "Site 'nope' not found; valid: Default, Office"
        )
        with patch(
            "unifi_fabric.server.site_manager.query_isp_metrics", new_callable=AsyncMock
        ) as mock_fn:
            with pytest.raises(ValueError, match="valid: Default, Office"):
                await server.query_isp_metrics("5m", sites=[{"hostId": "h9", "siteId": "nope"}])
        mock_fn.assert_not_awaited()

    @pytest.mark.parametrize(
        "entry", [{"siteId": "s9"}, {"hostId": "h9"}, {"hostId": "", "siteId": "s9"}, "h9"]
    )
    async def test_sites_entry_missing_ids_fails_before_the_query(self, mock_globals, entry):
        with patch(
            "unifi_fabric.server.site_manager.query_isp_metrics", new_callable=AsyncMock
        ) as mock_fn:
            with pytest.raises(
                ValueError,
                match=r"sites\[0\] needs a (hostId|siteId)|'sites\[0\]\.hostId' must not be empty"
                r"|sites\[0\] must be a \{hostId, siteId\} object",
            ):
                await server.query_isp_metrics("5m", sites=[entry])
        mock_fn.assert_not_awaited()

    async def test_host_site_only_scoping_resolves(self, mock_globals):
        # host+site must resolve the siteId via the Site Manager ObjectId resolver
        # (resolve_ea_site_id), NOT the per-console proxy UUID resolver.
        mock_client, mock_registry = mock_globals
        mock_registry.resolve_key_for_host.return_value = None
        mock_registry.resolve_host_id.return_value = "hid"
        object_id = "000000000000000000000501"
        mock_registry.resolve_ea_site_id.return_value = object_id
        with patch(
            "unifi_fabric.server.site_manager.query_isp_metrics", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = {"latency": []}
            await server.query_isp_metrics("5m", host="console", site="Office")

        mock_registry.resolve_key_for_host.assert_awaited_once_with("console")
        mock_registry.resolve_host_id.assert_awaited_once_with("console", key=None)
        # resolved via /v1/sites ObjectId resolver, scoped to the resolved host + owning key
        mock_registry.resolve_ea_site_id.assert_awaited_once_with("Office", host_id="hid", key=None)
        mock_registry.resolve_site_id.assert_not_called()
        # the ObjectId (not a proxy UUID) is what lands in the request body
        mock_fn.assert_awaited_once_with(
            mock_client,
            "5m",
            sites=[{"hostId": "hid", "siteId": object_id}],
            start_time=None,
            end_time=None,
            key=None,
        )

    async def test_host_site_unknown_site_no_upstream_call(self, mock_globals):
        # unknown site -> resolver fails fast, isp-metrics query is never issued.
        mock_client, mock_registry = mock_globals
        mock_registry.resolve_host_id.return_value = "hid"
        mock_registry.resolve_ea_site_id.side_effect = ValueError(
            "Site 'Nope' not found; valid: HQ, Branch"
        )
        with patch(
            "unifi_fabric.server.site_manager.query_isp_metrics", new_callable=AsyncMock
        ) as mock_fn:
            with pytest.raises(ValueError, match="not found; valid:"):
                await server.query_isp_metrics("5m", host="console", site="Nope")
        mock_fn.assert_not_awaited()

    async def test_no_scoping_raises(self, mock_globals):
        with pytest.raises(ValueError, match="requires scoping"):
            await server.query_isp_metrics("5m")


class TestListSdwanConfigsWrapper:
    async def test_delegates_with_client_only(self, mock_globals):
        mock_client, _ = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.site_manager.list_sdwan_configs", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_sdwan_configs(page_token="tok")

        mock_fn.assert_awaited_once_with(mock_client, page_token="tok", key_label=None)
        assert result is expected


class TestGetSdwanConfigWrapper:
    async def test_delegates_with_client_only(self, mock_globals):
        mock_client, _ = mock_globals
        expected = {"id": "cfg1"}

        with patch(
            "unifi_fabric.server.site_manager.get_sdwan_config", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_sdwan_config("cfg1")

        mock_fn.assert_awaited_once_with(mock_client, "cfg1")
        assert result is expected


class TestGetSdwanConfigStatusWrapper:
    async def test_delegates_with_client_only(self, mock_globals):
        mock_client, _ = mock_globals
        expected = {"status": "ok"}

        with patch(
            "unifi_fabric.server.site_manager.get_sdwan_config_status", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_sdwan_config_status("cfg1")

        mock_fn.assert_awaited_once_with(mock_client, "cfg1")
        assert result is expected


class TestListAllSitesAggregatedWrapper:
    async def test_delegates_to_site_manager(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.site_manager.list_all_sites_aggregated", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_all_sites_aggregated()

        mock_fn.assert_awaited_once_with(mock_client, mock_registry)
        assert result is expected


class TestGetSiteHealthSummaryWrapper:
    async def test_delegates_to_site_manager(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"uptime": 99.9}

        with patch(
            "unifi_fabric.server.site_manager.get_site_health_summary", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_site_health_summary("mysite")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "mysite")
        assert result is expected


class TestCompareSitePerformanceWrapper:
    async def test_delegates_to_site_manager(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"comparison": []}

        with patch(
            "unifi_fabric.server.site_manager.compare_site_performance", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.compare_site_performance(["s1", "s2"])

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, ["s1", "s2"])
        assert result is expected


class TestSearchAcrossSitesWrapper:
    async def test_delegates_to_site_manager(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"results": []}

        with patch(
            "unifi_fabric.server.site_manager.search_across_sites", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.search_across_sites("router")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "router")
        assert result is expected


class TestGetSiteInventoryWrapper:
    async def test_delegates_to_site_manager(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"devices": [], "clients": []}

        with patch(
            "unifi_fabric.server.site_manager.get_site_inventory", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_site_inventory("mysite")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "mysite", device_filter=None, client_filter=None
        )
        assert result is expected


# ---------------------------------------------------------------------------
# @mcp.tool() wrappers — network extended group
# ---------------------------------------------------------------------------


class TestGetNetworkWrapper:
    async def test_delegates_to_network(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "net-1"}

        with patch("unifi_fabric.server.network.get_network", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_network("h1", "s1", "net-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "net-1")
        assert result is expected


class TestUpdateNetworkWrapper:
    async def test_delegates_to_network(self, mock_globals):
        mock_client, mock_registry = mock_globals
        cfg = {"name": "updated"}
        expected = {"id": "net-1"}

        with patch("unifi_fabric.server.network.update_network", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.update_network("h1", "s1", "net-1", cfg)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "net-1", cfg)
        assert result is expected


class TestDeleteNetworkWrapper:
    async def test_returns_deletion_result_and_delegates(self, mock_globals):
        mock_client, mock_registry = mock_globals

        with patch("unifi_fabric.server.network.delete_network", new_callable=AsyncMock) as mock_fn:
            result = await server.delete_network("h1", "s1", "net-1")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", "net-1", force=None
        )
        assert result == {
            "deleted": True,
            "message": "Network net-1 deleted.",
            "response": mock_fn.return_value,
        }


class TestListWifiBroadcastsWrapper:
    async def test_delegates_to_network(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.network.list_wifi_broadcasts", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_wifi_broadcasts("h1", "s1")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", offset=None, limit=None, filter=None
        )
        assert result is expected

    async def test_forwards_filter_to_network(self, mock_globals):
        mock_client, mock_registry = mock_globals
        with patch(
            "unifi_fabric.server.network.list_wifi_broadcasts", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = {"data": []}
            await server.list_wifi_broadcasts("h1", "s1", filter="enabled.eq(true)")
        mock_fn.assert_awaited_once_with(
            mock_client,
            mock_registry,
            "h1",
            "s1",
            offset=None,
            limit=None,
            filter="enabled.eq(true)",
        )


class TestCreateWifiBroadcastWrapper:
    async def test_delegates_to_network(self, mock_globals):
        mock_client, mock_registry = mock_globals
        bc = {"name": "SSID1"}
        expected = {"id": "bc-1"}

        with patch(
            "unifi_fabric.server.network.create_wifi_broadcast", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.create_wifi_broadcast("h1", "s1", bc)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", bc)
        assert result is expected


class TestGetWifiBroadcastWrapper:
    async def test_delegates_to_network(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "bc-1"}

        with patch(
            "unifi_fabric.server.network.get_wifi_broadcast", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_wifi_broadcast("h1", "s1", "bc-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "bc-1")
        assert result is expected


class TestUpdateWifiBroadcastWrapper:
    async def test_delegates_to_network(self, mock_globals):
        mock_client, mock_registry = mock_globals
        bc = {"name": "updated"}
        expected = {"id": "bc-1"}

        with patch(
            "unifi_fabric.server.network.update_wifi_broadcast", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.update_wifi_broadcast("h1", "s1", "bc-1", bc)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "bc-1", bc)
        assert result is expected


class TestDeleteWifiBroadcastWrapper:
    async def test_returns_deletion_result_and_delegates(self, mock_globals):
        mock_client, mock_registry = mock_globals

        with patch(
            "unifi_fabric.server.network.delete_wifi_broadcast", new_callable=AsyncMock
        ) as mock_fn:
            result = await server.delete_wifi_broadcast("h1", "s1", "bc-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "bc-1", force=None)
        assert result == {
            "deleted": True,
            "message": "WiFi broadcast bc-1 deleted.",
            "response": mock_fn.return_value,
        }


@pytest.mark.parametrize(
    ("wrapper_name", "implementation_name"),
    [
        ("list_lags", "list_lags"),
        ("list_mc_lag_domains", "list_mc_lag_domains"),
        ("list_switch_stacks", "list_switch_stacks"),
    ],
)
async def test_list_switching_wrapper(wrapper_name, implementation_name, mock_globals):
    mock_client, mock_registry = mock_globals
    expected = {"data": []}
    with patch(
        f"unifi_fabric.server.network.{implementation_name}", new_callable=AsyncMock
    ) as mock_fn:
        mock_fn.return_value = expected
        result = await getattr(server, wrapper_name)(
            "h1",
            "s1",
            offset=10,
            limit=50,
            filter="metadata.origin.eq('USER')",
        )
    mock_fn.assert_awaited_once_with(
        mock_client,
        mock_registry,
        "h1",
        "s1",
        offset=10,
        limit=50,
        filter="metadata.origin.eq('USER')",
    )
    assert result is expected


@pytest.mark.parametrize(
    "wrapper_name",
    ["list_lags", "list_mc_lag_domains", "list_switch_stacks"],
)
async def test_list_switching_wrapper_drains_by_default(wrapper_name, mock_globals):
    # No offset/limit → the wrapper forwards None/None so the tool drains all pages.
    mock_client, mock_registry = mock_globals
    with patch(f"unifi_fabric.server.network.{wrapper_name}", new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = {"data": [], "totalCount": 0}
        await getattr(server, wrapper_name)("h1", "s1")
    mock_fn.assert_awaited_once_with(
        mock_client, mock_registry, "h1", "s1", offset=None, limit=None, filter=None
    )


class TestListDpiWrappers:
    @pytest.mark.parametrize(
        ("wrapper_name", "implementation_name"),
        [
            ("list_dpi_categories", "list_dpi_categories"),
            ("list_dpi_applications", "list_dpi_applications"),
        ],
    )
    async def test_drains_by_default(self, wrapper_name, implementation_name, mock_globals):
        mock_client, mock_registry = mock_globals
        with patch(
            f"unifi_fabric.server.network_services_proxy.{implementation_name}",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = {"data": [], "totalCount": 0}
            await getattr(server, wrapper_name)("h1")
        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", None, None, filter=None)

    @pytest.mark.parametrize(
        ("wrapper_name", "implementation_name"),
        [
            ("list_dpi_categories", "list_dpi_categories"),
            ("list_dpi_applications", "list_dpi_applications"),
        ],
    )
    async def test_explicit_paging(self, wrapper_name, implementation_name, mock_globals):
        mock_client, mock_registry = mock_globals
        with patch(
            f"unifi_fabric.server.network_services_proxy.{implementation_name}",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = {"data": [], "totalCount": 9}
            await getattr(server, wrapper_name)("h1", offset=5, limit=25)
        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", 5, 25, filter=None)


@pytest.mark.parametrize(
    ("wrapper_name", "implementation_name"),
    [
        ("get_lag", "get_lag"),
        ("get_mc_lag_domain", "get_mc_lag_domain"),
        ("get_switch_stack", "get_switch_stack"),
    ],
)
async def test_get_switching_wrapper(wrapper_name, implementation_name, mock_globals):
    mock_client, mock_registry = mock_globals
    expected = {"id": "resource-1"}
    with patch(
        f"unifi_fabric.server.network.{implementation_name}", new_callable=AsyncMock
    ) as mock_fn:
        mock_fn.return_value = expected
        result = await getattr(server, wrapper_name)("h1", "s1", "resource-1")
    mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "resource-1")
    assert result is expected


class TestListWanInterfacesWrapper:
    async def test_delegates_to_network(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.network.list_wan_interfaces", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_wan_interfaces("h1", "s1")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", offset=None, limit=None
        )
        assert result is expected


# ---------------------------------------------------------------------------
# @mcp.tool() wrappers — firewall_proxy group
# ---------------------------------------------------------------------------


class TestListFirewallPoliciesWrapper:
    async def test_delegates_to_firewall_proxy_drains_by_default(self, mock_globals):
        # No offset/limit → the wrapper passes None/None so the tool drains all pages.
        mock_client, mock_registry = mock_globals
        expected = {"data": [], "totalCount": 0}

        with patch(
            "unifi_fabric.server.firewall_proxy.list_firewall_policies", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_firewall_policies("h1", "s1")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", None, None, filter=None
        )
        assert result is expected

    async def test_delegates_to_firewall_proxy_explicit_paging(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": [], "totalCount": 5}

        with patch(
            "unifi_fabric.server.firewall_proxy.list_firewall_policies", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_firewall_policies("h1", "s1", offset=50, limit=50)

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", 50, 50, filter=None
        )
        assert result is expected

    async def test_forwards_filter_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        with patch(
            "unifi_fabric.server.firewall_proxy.list_firewall_policies", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = {"data": []}
            await server.list_firewall_policies("h1", "s1", filter="action.eq('ALLOW')")
        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", None, None, filter="action.eq('ALLOW')"
        )


class TestCreateFirewallPolicyWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        policy = {"name": "block-all"}
        expected = {"id": "fp-1"}

        with patch(
            "unifi_fabric.server.firewall_proxy.create_firewall_policy", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.create_firewall_policy("h1", "s1", policy)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", policy)
        assert result is expected


class TestGetFirewallPolicyWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "fp-1"}

        with patch(
            "unifi_fabric.server.firewall_proxy.get_firewall_policy", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_firewall_policy("h1", "s1", "fp-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "fp-1")
        assert result is expected


class TestUpdateFirewallPolicyWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        policy = {"name": "updated"}
        expected = {"id": "fp-1"}

        with patch(
            "unifi_fabric.server.firewall_proxy.update_firewall_policy", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.update_firewall_policy("h1", "s1", "fp-1", policy)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "fp-1", policy)
        assert result is expected


class TestPatchFirewallPolicyWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        fields = {"enabled": False}
        expected = {"id": "fp-1"}

        with patch(
            "unifi_fabric.server.firewall_proxy.patch_firewall_policy", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.patch_firewall_policy("h1", "s1", "fp-1", fields)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "fp-1", fields)
        assert result is expected


class TestDeleteFirewallPolicyWrapper:
    async def test_returns_deletion_result_and_delegates(self, mock_globals):
        mock_client, mock_registry = mock_globals

        with patch(
            "unifi_fabric.server.firewall_proxy.delete_firewall_policy", new_callable=AsyncMock
        ) as mock_fn:
            result = await server.delete_firewall_policy("h1", "s1", "fp-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "fp-1")
        assert result == {
            "deleted": True,
            "message": "Firewall policy fp-1 deleted.",
            "response": mock_fn.return_value,
        }


class TestGetFirewallPolicyOrderingWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"order": []}

        with patch(
            "unifi_fabric.server.firewall_proxy.get_firewall_policy_ordering",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_firewall_policy_ordering(
                "h1", "s1", "zone-uuid-1", "zone-uuid-2"
            )

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", "zone-uuid-1", "zone-uuid-2"
        )
        assert result is expected


class TestSetFirewallPolicyOrderingWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        ordering = {"ids": ["fp-1", "fp-2"]}
        expected = {"order": ["fp-1", "fp-2"]}

        with patch(
            "unifi_fabric.server.firewall_proxy.set_firewall_policy_ordering",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.set_firewall_policy_ordering(
                "h1", "s1", "src-zone", "dst-zone", ordering
            )

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", "src-zone", "dst-zone", ordering
        )
        assert result is expected


class TestListFirewallZonesProxyWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.firewall_proxy.list_firewall_zones", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_firewall_zones_proxy("h1", "s1")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", offset=None, limit=None, filter=None
        )
        assert result is expected


class TestCreateFirewallZoneProxyWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        zone = {"name": "dmz"}
        expected = {"id": "z-1"}

        with patch(
            "unifi_fabric.server.firewall_proxy.create_firewall_zone", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.create_firewall_zone_proxy("h1", "s1", zone)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", zone)
        assert result is expected


class TestGetFirewallZoneProxyWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "z-1"}

        with patch(
            "unifi_fabric.server.firewall_proxy.get_firewall_zone", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_firewall_zone_proxy("h1", "s1", "z-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "z-1")
        assert result is expected


class TestUpdateFirewallZoneProxyWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        zone = {"name": "updated-dmz"}
        expected = {"id": "z-1"}

        with patch(
            "unifi_fabric.server.firewall_proxy.update_firewall_zone", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.update_firewall_zone_proxy("h1", "s1", "z-1", zone)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "z-1", zone)
        assert result is expected


class TestDeleteFirewallZoneProxyWrapper:
    async def test_returns_deletion_result_and_delegates(self, mock_globals):
        mock_client, mock_registry = mock_globals

        with patch(
            "unifi_fabric.server.firewall_proxy.delete_firewall_zone", new_callable=AsyncMock
        ) as mock_fn:
            result = await server.delete_firewall_zone_proxy("h1", "s1", "z-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "z-1")
        assert result == {
            "deleted": True,
            "message": "Firewall zone z-1 deleted.",
            "response": mock_fn.return_value,
        }


class TestListAclRulesWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.firewall_proxy.list_acl_rules", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_acl_rules("h1", "s1")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", offset=None, limit=None, filter=None
        )
        assert result is expected


class TestCreateAclRuleWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        rule = {"name": "allow-lan"}
        expected = {"id": "acl-1"}

        with patch(
            "unifi_fabric.server.firewall_proxy.create_acl_rule", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.create_acl_rule("h1", "s1", rule)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", rule)
        assert result is expected


class TestGetAclRuleWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "acl-1"}

        with patch(
            "unifi_fabric.server.firewall_proxy.get_acl_rule", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_acl_rule("h1", "s1", "acl-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "acl-1")
        assert result is expected


class TestUpdateAclRuleWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        rule = {"name": "updated"}
        expected = {"id": "acl-1"}

        with patch(
            "unifi_fabric.server.firewall_proxy.update_acl_rule", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.update_acl_rule("h1", "s1", "acl-1", rule)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "acl-1", rule)
        assert result is expected


class TestDeleteAclRuleWrapper:
    async def test_returns_deletion_result_and_delegates(self, mock_globals):
        mock_client, mock_registry = mock_globals

        with patch(
            "unifi_fabric.server.firewall_proxy.delete_acl_rule", new_callable=AsyncMock
        ) as mock_fn:
            result = await server.delete_acl_rule("h1", "s1", "acl-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "acl-1")
        assert result == {
            "deleted": True,
            "message": "ACL rule acl-1 deleted.",
            "response": mock_fn.return_value,
        }


class TestGetAclRuleOrderingWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"order": []}

        with patch(
            "unifi_fabric.server.firewall_proxy.get_acl_rule_ordering", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_acl_rule_ordering("h1", "s1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1")
        assert result is expected


class TestSetAclRuleOrderingWrapper:
    async def test_delegates_to_firewall_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        ordering = {"ids": ["acl-1"]}
        expected = {"order": ["acl-1"]}

        with patch(
            "unifi_fabric.server.firewall_proxy.set_acl_rule_ordering", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.set_acl_rule_ordering("h1", "s1", ordering)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", ordering)
        assert result is expected


# ---------------------------------------------------------------------------
# @mcp.tool() wrappers — network_services_proxy group
# ---------------------------------------------------------------------------


class TestListDnsPoliciesWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.network_services_proxy.list_dns_policies",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_dns_policies("h1", "s1")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", offset=None, limit=None, filter=None
        )
        assert result is expected


class TestCreateDnsPolicyWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        policy = {"name": "strict"}
        expected = {"id": "dns-1"}

        with patch(
            "unifi_fabric.server.network_services_proxy.create_dns_policy",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.create_dns_policy("h1", "s1", policy)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", policy)
        assert result is expected


class TestGetDnsPolicyWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "dns-1"}

        with patch(
            "unifi_fabric.server.network_services_proxy.get_dns_policy", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_dns_policy("h1", "s1", "dns-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "dns-1")
        assert result is expected


class TestUpdateDnsPolicyWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        policy = {"name": "updated"}
        expected = {"id": "dns-1"}

        with patch(
            "unifi_fabric.server.network_services_proxy.update_dns_policy",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.update_dns_policy("h1", "s1", "dns-1", policy)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "dns-1", policy)
        assert result is expected


class TestDeleteDnsPolicyWrapper:
    async def test_returns_deletion_result_and_delegates(self, mock_globals):
        mock_client, mock_registry = mock_globals

        with patch(
            "unifi_fabric.server.network_services_proxy.delete_dns_policy",
            new_callable=AsyncMock,
        ) as mock_fn:
            result = await server.delete_dns_policy("h1", "s1", "dns-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "dns-1")
        assert result == {
            "deleted": True,
            "message": "DNS policy dns-1 deleted.",
            "response": mock_fn.return_value,
        }


class TestListTrafficMatchingListsWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.network_services_proxy.list_traffic_matching_lists",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_traffic_matching_lists("h1", "s1")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", offset=None, limit=None, filter=None
        )
        assert result is expected


class TestCreateTrafficMatchingListWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        tl = {"name": "gaming"}
        expected = {"id": "tl-1"}

        with patch(
            "unifi_fabric.server.network_services_proxy.create_traffic_matching_list",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.create_traffic_matching_list("h1", "s1", tl)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", tl)
        assert result is expected


class TestGetTrafficMatchingListWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "tl-1"}

        with patch(
            "unifi_fabric.server.network_services_proxy.get_traffic_matching_list",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_traffic_matching_list("h1", "s1", "tl-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "tl-1")
        assert result is expected


class TestUpdateTrafficMatchingListWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        tl = {"name": "updated"}
        expected = {"id": "tl-1"}

        with patch(
            "unifi_fabric.server.network_services_proxy.update_traffic_matching_list",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.update_traffic_matching_list("h1", "s1", "tl-1", tl)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "tl-1", tl)
        assert result is expected


class TestDeleteTrafficMatchingListWrapper:
    async def test_returns_deletion_result_and_delegates(self, mock_globals):
        mock_client, mock_registry = mock_globals

        with patch(
            "unifi_fabric.server.network_services_proxy.delete_traffic_matching_list",
            new_callable=AsyncMock,
        ) as mock_fn:
            result = await server.delete_traffic_matching_list("h1", "s1", "tl-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "tl-1")
        assert result == {
            "deleted": True,
            "message": "Traffic matching list tl-1 deleted.",
            "response": mock_fn.return_value,
        }


class TestListVpnServersWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.network_services_proxy.list_vpn_servers",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_vpn_servers("h1", "s1")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", offset=None, limit=None, filter=None
        )
        assert result is expected


class TestListSiteToSiteTunnelsWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.network_services_proxy.list_site_to_site_tunnels",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_site_to_site_tunnels("h1", "s1")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", offset=None, limit=None, filter=None
        )
        assert result is expected


class TestListRadiusProfilesWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.network_services_proxy.list_radius_profiles",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_radius_profiles("h1", "s1")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", offset=None, limit=None, filter=None
        )
        assert result is expected


class TestListHotspotVouchersWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.network_services_proxy.list_hotspot_vouchers",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_hotspot_vouchers("h1", "s1")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "s1", offset=None, limit=None, filter=None
        )
        assert result is expected


class TestCreateHotspotVouchersWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        cfg = {"count": 5, "duration": 60}
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.network_services_proxy.create_hotspot_vouchers",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.create_hotspot_vouchers("h1", "s1", cfg)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", cfg)
        assert result is expected


class TestGetHotspotVoucherWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "v-1"}

        with patch(
            "unifi_fabric.server.network_services_proxy.get_hotspot_voucher",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_hotspot_voucher("h1", "s1", "v-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "v-1")
        assert result is expected


class TestDeleteHotspotVoucherWrapper:
    async def test_returns_deletion_result_and_delegates(self, mock_globals):
        mock_client, mock_registry = mock_globals

        with patch(
            "unifi_fabric.server.network_services_proxy.delete_hotspot_voucher",
            new_callable=AsyncMock,
        ) as mock_fn:
            result = await server.delete_hotspot_voucher("h1", "s1", "v-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "v-1")
        assert result == {
            "deleted": True,
            "message": "Hotspot voucher v-1 deleted.",
            "response": mock_fn.return_value,
        }


class TestBulkDeleteHotspotVouchersWrapper:
    async def test_returns_deletion_result_and_delegates(self, mock_globals):
        mock_client, mock_registry = mock_globals
        fp = {"expired": True}

        with patch(
            "unifi_fabric.server.network_services_proxy.bulk_delete_hotspot_vouchers",
            new_callable=AsyncMock,
        ) as mock_fn:
            result = await server.bulk_delete_hotspot_vouchers("h1", "s1", fp, confirm=True)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", fp)
        assert result == {
            "deleted": True,
            "message": "Hotspot vouchers deleted.",
            "response": mock_fn.return_value,
        }


class TestListDeviceTagsWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.network_services_proxy.list_device_tags",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_device_tags("h1", "s1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1")
        assert result is expected


class TestListCountriesWrapper:
    async def test_delegates_to_network_services_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch(
            "unifi_fabric.server.network_services_proxy.list_countries",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_countries("h1")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", offset=None, limit=None, filter=None
        )
        assert result is expected


# ---------------------------------------------------------------------------
# @mcp.tool() wrappers — protect group
# ---------------------------------------------------------------------------


class TestListCamerasWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch("unifi_fabric.server.protect.list_cameras", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_cameras("h1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1")
        assert result is expected


class TestGetCameraWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "cam-1"}

        with patch("unifi_fabric.server.protect.get_camera", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_camera("h1", "cam-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "cam-1")
        assert result is expected


class TestUpdateCameraWrapper:
    async def test_delegates_to_protect_with_kwargs(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "cam-1"}

        with patch("unifi_fabric.server.protect.update_camera", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.update_camera("h1", "cam-1", {"name": "FrontDoor"})

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "cam-1", name="FrontDoor"
        )
        assert result is expected


class TestGetCameraSnapshotWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"image_base64": "dW5pdA==", "content_type": "image/jpeg", "size_bytes": 4}

        with patch(
            "unifi_fabric.server.protect.get_camera_snapshot", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_camera_snapshot("h1", "cam-1")

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "cam-1", channel=None, high_quality=None, ts=None
        )
        assert result.structured_content == expected
        assert result.content[0].type == "image"


class TestGetRtspsStreamWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"url": "rtsps://example.com/stream"}

        with patch(
            "unifi_fabric.server.protect.get_rtsps_stream", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_rtsps_stream("h1", "cam-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "cam-1")
        assert result is expected


class TestCreateRtspsStreamWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"url": "rtsps://example.com/stream"}
        qualities = ["HIGHEST", "HIGH"]

        with patch(
            "unifi_fabric.server.protect.create_rtsps_stream", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.create_rtsps_stream("h1", "cam-1", qualities)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "cam-1", qualities)
        assert result is expected


class TestDeleteRtspsStreamWrapper:
    async def test_returns_deletion_result_and_delegates(self, mock_globals):
        mock_client, mock_registry = mock_globals
        qualities = ["HIGHEST", "HIGH"]

        with patch(
            "unifi_fabric.server.protect.delete_rtsps_stream", new_callable=AsyncMock
        ) as mock_fn:
            result = await server.delete_rtsps_stream("h1", "cam-1", qualities)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "cam-1", qualities)
        assert result == {
            "deleted": True,
            "message": "RTSPS stream for camera cam-1 deleted.",
            "response": mock_fn.return_value,
        }


class TestStartTalkbackSessionWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"session": "tok"}

        with patch("unifi_fabric.server.protect.talkback_start", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.start_talkback_session("h1", "cam-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "cam-1", confirm=False)
        assert result is expected


class TestDisableCameraMicPermanentlyWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "cam-1"}

        with patch(
            "unifi_fabric.server.protect.disable_mic_permanently", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.disable_camera_mic_permanently("h1", "cam-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "cam-1", confirm=False)
        assert result is expected


class TestPtzGotoPresetWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"status": "ok"}

        with patch("unifi_fabric.server.protect.ptz_goto", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.ptz_goto_preset("h1", "cam-1", 3)

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "cam-1", 3, confirm=False
        )
        assert result is expected


class TestPtzPatrolStartWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"status": "ok"}

        with patch(
            "unifi_fabric.server.protect.ptz_patrol_start", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.ptz_patrol_start("h1", "cam-1", 2)

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "cam-1", 2, confirm=False
        )
        assert result is expected


class TestPtzPatrolStopWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"status": "ok"}

        with patch(
            "unifi_fabric.server.protect.ptz_patrol_stop", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.ptz_patrol_stop("h1", "cam-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "cam-1", confirm=False)
        assert result is expected


class TestListSensorsWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch("unifi_fabric.server.protect.list_sensors", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_sensors("h1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1")
        assert result is expected


class TestGetSensorWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "sensor-1"}

        with patch("unifi_fabric.server.protect.get_sensor", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_sensor("h1", "sensor-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "sensor-1")
        assert result is expected


class TestUpdateSensorWrapper:
    async def test_delegates_to_protect_with_kwargs(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "sensor-1"}

        with patch("unifi_fabric.server.protect.update_sensor", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.update_sensor("h1", "sensor-1", {"sensitivity": 5})

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "sensor-1", sensitivity=5
        )
        assert result is expected


class TestListLightsWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch("unifi_fabric.server.protect.list_lights", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_lights("h1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1")
        assert result is expected


class TestGetLightWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "light-1"}

        with patch("unifi_fabric.server.protect.get_light", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_light("h1", "light-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "light-1")
        assert result is expected


class TestUpdateLightWrapper:
    async def test_delegates_to_protect_with_kwargs(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "light-1"}

        with patch("unifi_fabric.server.protect.update_light", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.update_light("h1", "light-1", {"brightness": 80})

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "light-1", brightness=80)
        assert result is expected


class TestListChimesWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch("unifi_fabric.server.protect.list_chimes", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_chimes("h1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1")
        assert result is expected


class TestGetChimeWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "chime-1"}

        with patch("unifi_fabric.server.protect.get_chime", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_chime("h1", "chime-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "chime-1")
        assert result is expected


class TestUpdateChimeWrapper:
    async def test_delegates_to_protect_with_kwargs(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "chime-1"}

        with patch("unifi_fabric.server.protect.update_chime", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.update_chime("h1", "chime-1", {"volume": 50})

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "chime-1", volume=50)
        assert result is expected


class TestListViewersWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch("unifi_fabric.server.protect.list_viewers", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_viewers("h1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1")
        assert result is expected


class TestGetViewerWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "viewer-1"}

        with patch("unifi_fabric.server.protect.get_viewer", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_viewer("h1", "viewer-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "viewer-1")
        assert result is expected


class TestUpdateViewerWrapper:
    async def test_delegates_to_protect_with_kwargs(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "viewer-1"}

        with patch("unifi_fabric.server.protect.update_viewer", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.update_viewer("h1", "viewer-1", {"liveviewId": "lv-1"})

        mock_fn.assert_awaited_once_with(
            mock_client, mock_registry, "h1", "viewer-1", liveviewId="lv-1"
        )
        assert result is expected


class TestListLiveviewsWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"data": []}

        with patch("unifi_fabric.server.protect.list_liveviews", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_liveviews("h1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1")
        assert result is expected


class TestGetLiveviewWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "lv-1"}

        with patch("unifi_fabric.server.protect.get_liveview", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_liveview("h1", "lv-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "lv-1")
        assert result is expected


class TestCreateLiveviewWrapper:
    async def test_delegates_to_protect_with_kwargs(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "lv-1"}

        with patch(
            "unifi_fabric.server.protect.create_liveview", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.create_liveview("h1", "MyView", {"layout": 1})

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "MyView", layout=1)
        assert result is expected

    async def test_delegates_with_no_settings(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "lv-2"}

        with patch(
            "unifi_fabric.server.protect.create_liveview", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.create_liveview("h1", "AnotherView")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "AnotherView")
        assert result is expected


class TestUpdateLiveviewWrapper:
    async def test_delegates_to_protect_with_kwargs(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "lv-1"}

        with patch(
            "unifi_fabric.server.protect.update_liveview", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.update_liveview("h1", "lv-1", {"name": "Updated"})

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "lv-1", name="Updated")
        assert result is expected


class TestGetNvrWrapper:
    async def test_delegates_to_protect(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "nvr-1"}

        with patch("unifi_fabric.server.protect.get_nvr", new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = expected
            result = await server.get_nvr("h1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1")
        assert result is expected


class TestTriggerAlarmWebhookWrapper:
    async def test_delegates_to_protect_when_confirmed(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"status": "triggered"}

        with patch(
            "unifi_fabric.server.protect.trigger_alarm_webhook", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.trigger_alarm_webhook("h1", "wh-1", confirm=True)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "wh-1")
        assert result is expected

    async def test_delegates_to_protect_without_confirm(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"status": "triggered"}

        with patch(
            "unifi_fabric.server.protect.trigger_alarm_webhook", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.trigger_alarm_webhook("h1", "wh-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "wh-1")
        assert result is expected


# ---------------------------------------------------------------------------
# @mcp.tool() wrappers — routing group
# ---------------------------------------------------------------------------


class TestListPortForwardsWrapper:
    async def test_delegates_to_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = [{"id": "pf-1"}]

        with patch(
            "unifi_fabric.server.network_services_proxy.list_port_forwards", new_callable=AsyncMock
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.list_port_forwards(host="h1", site="s1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1")
        assert result is expected


class TestCreatePortForwardWrapper:
    async def test_delegates_to_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        expected = {"id": "pf-1"}
        payload = {"name": "Web Server", "dstPort": "80"}

        with patch(
            "unifi_fabric.server.network_services_proxy.create_port_forward",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.create_port_forward("h1", "s1", payload)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", payload)
        assert result is expected


class TestUpdatePortForwardWrapper:
    async def test_delegates_to_proxy(self, mock_globals):
        mock_client, mock_registry = mock_globals
        payload = {"enabled": False}
        expected = {"id": "pf-1"}

        with patch(
            "unifi_fabric.server.network_services_proxy.update_port_forward",
            new_callable=AsyncMock,
        ) as mock_fn:
            mock_fn.return_value = expected
            result = await server.update_port_forward("h1", "s1", "pf-1", payload)

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "pf-1", payload)
        assert result is expected


class TestDeletePortForwardWrapper:
    async def test_returns_deletion_result_and_delegates(self, mock_globals):
        mock_client, mock_registry = mock_globals

        with patch(
            "unifi_fabric.server.network_services_proxy.delete_port_forward",
            new_callable=AsyncMock,
        ) as mock_fn:
            result = await server.delete_port_forward("h1", "s1", "pf-1")

        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "s1", "pf-1")
        assert result == {
            "deleted": True,
            "message": "Port forward pf-1 deleted.",
            "response": mock_fn.return_value,
        }


# ---------------------------------------------------------------------------
# trigger_alarm_webhook confirm gate
# ---------------------------------------------------------------------------


class TestTriggerAlarmWebhookNoGate:
    async def test_without_confirm_calls_api(self, mock_globals):
        mock_client, mock_registry = mock_globals
        with patch(
            "unifi_fabric.server.protect.trigger_alarm_webhook",
            new_callable=AsyncMock,
            return_value={"status": "triggered"},
        ) as mock_fn:
            result = await server.trigger_alarm_webhook("h1", "wh-1")
        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "wh-1")
        assert result["status"] == "triggered"

    async def test_confirm_false_still_calls_api(self, mock_globals):
        mock_client, mock_registry = mock_globals
        with patch(
            "unifi_fabric.server.protect.trigger_alarm_webhook",
            new_callable=AsyncMock,
            return_value={"status": "triggered"},
        ) as mock_fn:
            result = await server.trigger_alarm_webhook("h1", "wh-1", confirm=False)
        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "wh-1")
        assert result["status"] == "triggered"

    async def test_with_confirm_true_calls_api(self, mock_globals):
        mock_client, mock_registry = mock_globals
        with patch(
            "unifi_fabric.server.protect.trigger_alarm_webhook",
            new_callable=AsyncMock,
            return_value={"status": "triggered"},
        ) as mock_fn:
            result = await server.trigger_alarm_webhook("h1", "wh-1", confirm=True)
        mock_fn.assert_awaited_once_with(mock_client, mock_registry, "h1", "wh-1")
        assert result["status"] == "triggered"


# ---------------------------------------------------------------------------
