"""Tests for Registry: resolution, cache TTL, bounded size, and per-key isolation."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.config import APIKeyConfig
from unifi_fabric.registry import Registry, _assert_uuid

HOSTS = [
    {"id": "host-aaa", "name": "MyRouter", "reportedState": {"hostname": "router.local"}},
    {"id": "host-bbb", "name": "Switch01", "reportedState": {"hostname": "switch01.local"}},
]

EA_SITES = [
    {"siteId": "site-111", "siteName": "HQ", "meta": {"desc": "Headquarters"}},
    {"siteId": "site-222", "siteName": "Branch", "meta": {"desc": "Branch Office"}},
]

# Proxy sites use UUID id + description fields (as returned by the console proxy)
PROXY_SITES = [
    {"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "description": "Default"},
    {"id": "b2c3d4e5-f6a7-8901-bcde-f12345678901", "description": "Branch Office"},
]

_HOST_ID = "host-aaa"
_PROXY_PATH = f"/v1/connector/consoles/{_HOST_ID}/proxy/network/integration/v1/sites"


@pytest.fixture
def mock_client():
    client = AsyncMock()
    client.paginate = AsyncMock(side_effect=_paginate_side_effect)
    client.get = AsyncMock(side_effect=_get_side_effect)
    return client


async def _paginate_side_effect(path, *, key=None):
    if path == "/ea/hosts":
        return list(HOSTS)
    if path == "/ea/sites":
        return list(EA_SITES)
    return []


async def _get_side_effect(path, *, key=None, params=None):
    if "/proxy/network/integration/v1/sites" in path:
        return {"data": list(PROXY_SITES)}
    return {}


@pytest.fixture
def registry(mock_client):
    return Registry(mock_client, ttl_seconds=900)


# --- resolve_host_id ---


class TestResolveHostId:
    @pytest.mark.asyncio
    async def test_resolve_host_id_by_exact_id(self, registry):
        result = await registry.resolve_host_id("host-aaa")
        assert result == "host-aaa"

    @pytest.mark.asyncio
    async def test_resolve_host_id_by_hostname(self, registry):
        result = await registry.resolve_host_id("router.local")
        assert result == "host-aaa"

    @pytest.mark.asyncio
    async def test_resolve_host_id_by_hostname_case_insensitive(self, registry):
        result = await registry.resolve_host_id("ROUTER.LOCAL")
        assert result == "host-aaa"

    @pytest.mark.asyncio
    async def test_resolve_host_id_by_name(self, registry):
        result = await registry.resolve_host_id("Switch01")
        assert result == "host-bbb"

    @pytest.mark.asyncio
    async def test_resolve_host_id_by_name_case_insensitive(self, registry):
        result = await registry.resolve_host_id("switch01")
        assert result == "host-bbb"

    @pytest.mark.asyncio
    async def test_resolve_host_id_fallback(self, registry):
        result = await registry.resolve_host_id("unknown-value")
        assert result == "unknown-value"


# --- resolve_site_id (proxy path) ---


class TestResolveSiteId:
    @pytest.mark.asyncio
    async def test_resolve_site_id_by_uuid(self, registry):
        result = await registry.resolve_site_id("a1b2c3d4-e5f6-7890-abcd-ef1234567890", _HOST_ID)
        assert result == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    @pytest.mark.asyncio
    async def test_resolve_site_id_by_description(self, registry):
        result = await registry.resolve_site_id("Default", _HOST_ID)
        assert result == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    @pytest.mark.asyncio
    async def test_resolve_site_id_by_description_case_insensitive(self, registry):
        result = await registry.resolve_site_id("branch office", _HOST_ID)
        assert result == "b2c3d4e5-f6a7-8901-bcde-f12345678901"

    @pytest.mark.asyncio
    async def test_resolve_site_id_not_found_raises(self, registry):
        with pytest.raises(ValueError, match="not found"):
            await registry.resolve_site_id("no-such-site", _HOST_ID)

    @pytest.mark.asyncio
    async def test_resolve_site_id_uses_proxy_endpoint(self, registry, mock_client):
        await registry.resolve_site_id("Default", _HOST_ID)
        mock_client.get.assert_called_once()
        call_path = mock_client.get.call_args[0][0]
        assert "/proxy/network/integration/v1/sites" in call_path
        assert _HOST_ID in call_path


class TestResolveSiteIdNameField:
    """Regression tests for site resolution when the API returns 'name' instead of 'description'.

    Some firmware versions return {'id': uuid, 'name': 'Default'} rather than
    {'id': uuid, 'description': 'Default'}.  resolve_site_id must handle both.
    """

    @pytest.fixture
    def mock_client_name_field(self):
        """Return proxy sites using 'name' field instead of 'description'."""
        client = AsyncMock()
        client.paginate = AsyncMock(side_effect=_paginate_side_effect)

        async def _get(path, *, key=None, params=None):
            if "/proxy/network/integration/v1/sites" in path:
                return {
                    "data": [
                        {"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "name": "Default"},
                        {"id": "b2c3d4e5-f6a7-8901-bcde-f12345678901", "name": "Branch Office"},
                    ]
                }
            return {}

        client.get = AsyncMock(side_effect=_get)
        return client

    @pytest.fixture
    def registry_name(self, mock_client_name_field):
        return Registry(mock_client_name_field, ttl_seconds=900)

    @pytest.mark.asyncio
    async def test_resolve_by_name_field(self, registry_name):
        result = await registry_name.resolve_site_id("Default", _HOST_ID)
        assert result == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    @pytest.mark.asyncio
    async def test_resolve_by_name_field_case_insensitive(self, registry_name):
        result = await registry_name.resolve_site_id("default", _HOST_ID)
        assert result == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    @pytest.mark.asyncio
    async def test_resolve_by_name_multi_word(self, registry_name):
        result = await registry_name.resolve_site_id("Branch Office", _HOST_ID)
        assert result == "b2c3d4e5-f6a7-8901-bcde-f12345678901"

    @pytest.fixture
    def mock_client_underscore_id(self):
        """Return proxy sites using '_id' field instead of 'id'."""
        client = AsyncMock()
        client.paginate = AsyncMock(side_effect=_paginate_side_effect)

        async def _get(path, *, key=None, params=None):
            if "/proxy/network/integration/v1/sites" in path:
                return {
                    "data": [
                        {"_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "name": "Default"},
                    ]
                }
            return {}

        client.get = AsyncMock(side_effect=_get)
        return client

    @pytest.fixture
    def registry_underscore(self, mock_client_underscore_id):
        return Registry(mock_client_underscore_id, ttl_seconds=900)

    @pytest.mark.asyncio
    async def test_resolve_by_underscore_id_and_name(self, registry_underscore):
        result = await registry_underscore.resolve_site_id("Default", _HOST_ID)
        assert result == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


# --- _assert_uuid ---


class TestAssertUuid:
    def test_valid_uuid_passes(self):
        _assert_uuid("a1b2c3d4-e5f6-7890-abcd-ef1234567890")  # no exception

    def test_invalid_objectid_raises(self):
        with pytest.raises(ValueError, match="not a UUID"):
            _assert_uuid("5f4dcc3b5aa765d61d8327de")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            _assert_uuid("")

    def test_random_string_raises(self):
        with pytest.raises(ValueError):
            _assert_uuid("my-site")


# --- get_ea_sites ---


class TestGetEaSites:
    @pytest.mark.asyncio
    async def test_returns_ea_sites(self, registry):
        result = await registry.get_ea_sites()
        assert result == EA_SITES

    @pytest.mark.asyncio
    async def test_calls_ea_path(self, registry, mock_client):
        await registry.get_ea_sites()
        mock_client.paginate.assert_called_once_with("/ea/sites", key=None)


# --- Cache TTL / invalidation ---


class TestCacheTtl:
    @pytest.mark.asyncio
    async def test_cache_used_on_second_call(self, registry, mock_client):
        await registry.get_hosts()
        await registry.get_hosts()
        assert mock_client.paginate.call_count == 1

    @pytest.mark.asyncio
    async def test_cache_ttl_expiry_triggers_refetch(self, registry, mock_client):
        await registry.get_hosts()
        assert mock_client.paginate.call_count == 1

        registry.invalidate()

        await registry.get_hosts()
        assert mock_client.paginate.call_count == 2

    @pytest.mark.asyncio
    async def test_invalidate_specific_key_only_affects_that_key(self, registry, mock_client):
        key_a = APIKeyConfig(key="sk-a", label="a")
        key_b = APIKeyConfig(key="sk-b", label="b")

        await registry.get_hosts(key=key_a)
        await registry.get_hosts(key=key_b)
        assert mock_client.paginate.call_count == 2

        registry.invalidate(key=key_a)

        await registry.get_hosts(key=key_a)  # re-fetches
        await registry.get_hosts(key=key_b)  # still cached
        assert mock_client.paginate.call_count == 3

    @pytest.mark.asyncio
    async def test_proxy_sites_cache_keyed_by_host(self, registry, mock_client):
        await registry.get_sites("host-aaa")
        await registry.get_sites("host-bbb")
        assert mock_client.get.call_count == 2

        # Second calls hit cache
        await registry.get_sites("host-aaa")
        await registry.get_sites("host-bbb")
        assert mock_client.get.call_count == 2

    @pytest.mark.asyncio
    async def test_invalidate_clears_proxy_sites_for_key(self, registry, mock_client):
        key_a = APIKeyConfig(key="sk-a", label="a")
        await registry.get_sites("host-aaa", key=key_a)
        registry.invalidate(key=key_a)
        await registry.get_sites("host-aaa", key=key_a)
        assert mock_client.get.call_count == 2


# --- Per-key isolation ---


class TestPerKeyIsolation:
    @pytest.mark.asyncio
    async def test_two_keys_get_separate_cache_entries(self, registry, mock_client):
        key_a = APIKeyConfig(key="sk-a", label="alpha")
        key_b = APIKeyConfig(key="sk-b", label="beta")

        await registry.get_hosts(key=key_a)
        await registry.get_hosts(key=key_b)

        assert "alpha" in registry._hosts
        assert "beta" in registry._hosts
        assert registry._hosts["alpha"] is not registry._hosts["beta"]

    @pytest.mark.asyncio
    async def test_none_key_uses_default_label(self, registry):
        await registry.get_hosts(key=None)
        assert "__default__" in registry._hosts

    @pytest.mark.asyncio
    async def test_two_keys_independent_ea_site_paginate_calls(self, registry, mock_client):
        key_a = APIKeyConfig(key="sk-a", label="alpha")
        key_b = APIKeyConfig(key="sk-b", label="beta")

        await registry.get_ea_sites(key=key_a)
        await registry.get_ea_sites(key=key_b)

        assert mock_client.paginate.call_count == 2
        calls = mock_client.paginate.call_args_list
        assert calls[0].kwargs["key"] == key_a
        assert calls[1].kwargs["key"] == key_b

    @pytest.mark.asyncio
    async def test_proxy_sites_keyed_by_label_and_host(self, registry, mock_client):
        key_a = APIKeyConfig(key="sk-a", label="alpha")
        key_b = APIKeyConfig(key="sk-b", label="beta")

        await registry.get_sites("host-aaa", key=key_a)
        await registry.get_sites("host-aaa", key=key_b)

        assert ("alpha", "host-aaa") in registry._sites
        assert ("beta", "host-aaa") in registry._sites
        assert mock_client.get.call_count == 2


# --- Bounded cache (TTLCache size limits and eviction warnings) ---


class TestBoundedCache:
    @pytest.mark.asyncio
    async def test_cache_stays_bounded_when_full(self):
        """Filling past maxsize evicts LRU entries; size never exceeds maxsize."""
        client = AsyncMock()
        client.paginate = AsyncMock(return_value=[])
        reg = Registry(client, ttl_seconds=900, cache_max_hosts=5)

        for i in range(8):
            key = APIKeyConfig(key=f"sk-{i}", label=f"label-{i}")
            await reg.get_hosts(key=key)

        assert len(reg._hosts) <= 5

    @pytest.mark.asyncio
    async def test_full_warning_logged_once(self, caplog):
        """WARNING is emitted exactly once on first cache-full, not on every eviction."""
        client = AsyncMock()
        client.paginate = AsyncMock(return_value=[])
        reg = Registry(client, ttl_seconds=900, cache_max_hosts=3)

        with caplog.at_level(logging.WARNING, logger="unifi_fabric.registry"):
            for i in range(6):
                key = APIKeyConfig(key=f"sk-{i}", label=f"label-{i}")
                await reg.get_hosts(key=key)

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert "full" in warnings[0].message

    @pytest.mark.asyncio
    async def test_no_warning_when_cache_not_full(self, caplog):
        """No WARNING logged if cache never reaches maxsize."""
        client = AsyncMock()
        client.paginate = AsyncMock(return_value=[])
        reg = Registry(client, ttl_seconds=900, cache_max_hosts=10)

        with caplog.at_level(logging.WARNING, logger="unifi_fabric.registry"):
            for i in range(5):
                key = APIKeyConfig(key=f"sk-{i}", label=f"label-{i}")
                await reg.get_hosts(key=key)

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 0

    @pytest.mark.asyncio
    async def test_rearm_after_pressure_relief(self, caplog):
        """Warning flag re-arms once cache drops below 50%; INFO logged on re-arm."""
        client = AsyncMock()
        client.paginate = AsyncMock(return_value=[])
        reg = Registry(client, ttl_seconds=900, cache_max_hosts=4)

        # Fill past maxsize to trigger warning
        for i in range(6):
            key = APIKeyConfig(key=f"sk-{i}", label=f"label-{i}")
            await reg.get_hosts(key=key)

        assert reg._hosts_full_warned is True

        # Drop below 50% of maxsize (maxsize=4, 50%=2)
        reg._hosts.clear()

        with caplog.at_level(logging.INFO, logger="unifi_fabric.registry"):
            key_new = APIKeyConfig(key="sk-new", label="label-new")
            await reg.get_hosts(key=key_new)

        assert reg._hosts_full_warned is False
        info_msgs = [
            r
            for r in caplog.records
            if r.levelno == logging.INFO and "pressure relieved" in r.message
        ]
        assert len(info_msgs) == 1

    @pytest.mark.asyncio
    async def test_per_cache_limits_are_independent(self):
        """Hosts and sites caches enforce their own independent size limits."""
        client = AsyncMock()
        client.paginate = AsyncMock(return_value=[])
        client.get = AsyncMock(return_value={"data": []})
        reg = Registry(client, ttl_seconds=900, cache_max_hosts=2, cache_max_sites=10)

        # Fill hosts cache to capacity
        for i in range(2):
            key = APIKeyConfig(key=f"sk-{i}", label=f"label-{i}")
            await reg.get_hosts(key=key)

        assert len(reg._hosts) == 2

        # Sites cache can grow independently (different maxsize)
        for i in range(7):
            await reg.get_sites(f"host-{i}")

        assert len(reg._sites) == 7
        assert len(reg._hosts) <= 2

    @pytest.mark.asyncio
    async def test_sites_cache_bounded(self):
        """Sites TTLCache stays within cache_max_sites."""
        client = AsyncMock()
        client.get = AsyncMock(return_value={"data": []})
        reg = Registry(client, ttl_seconds=900, cache_max_sites=4)

        for i in range(8):
            await reg.get_sites(f"host-{i}")

        assert len(reg._sites) <= 4


# --- Per-label locking ---


class TestPerLabelLocking:
    @pytest.mark.asyncio
    async def test_separate_locks_created_per_label(self, registry):
        key_a = APIKeyConfig(key="sk-a", label="alpha")
        key_b = APIKeyConfig(key="sk-b", label="beta")

        await registry.get_hosts(key=key_a)
        await registry.get_hosts(key=key_b)

        assert "alpha" in registry._locks
        assert "beta" in registry._locks
        assert registry._locks["alpha"] is not registry._locks["beta"]

    @pytest.mark.asyncio
    async def test_default_label_gets_own_lock(self, registry):
        await registry.get_hosts(key=None)
        assert "__default__" in registry._locks

    @pytest.mark.asyncio
    async def test_concurrent_reads_different_labels_do_not_serialize(self, registry, mock_client):
        """Two cold-cache reads for different labels must be able to run concurrently."""
        import asyncio as _asyncio

        key_a = APIKeyConfig(key="sk-a", label="alpha")
        key_b = APIKeyConfig(key="sk-b", label="beta")

        # Both labels have independent locks — gathering them should succeed without deadlock.
        results = await _asyncio.gather(
            registry.get_hosts(key=key_a),
            registry.get_hosts(key=key_b),
        )
        assert len(results) == 2
        assert mock_client.paginate.call_count == 2
