"""Tests for Registry: resolution, cache TTL, bounded size, and per-key isolation."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock, call

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.config import APIKeyConfig
from unifi_fabric.registry import Registry, _assert_uuid

HOSTS = [
    {"id": "host-aaa", "name": "MyRouter", "reportedState": {"hostname": "router.local"}},
    {"id": "host-bbb", "name": "Switch01", "reportedState": {"hostname": "switch01.local"}},
]

# Real Site Manager /v1/sites shape (live-verified): name/description live under
# meta.name / meta.desc, with hostId + a 24-char Fabric ObjectId siteId. There is
# NO top-level siteName/description field.
EA_SITES = [
    {
        "siteId": "aaaaaaaaaaaaaaaaaaaaaaa1",
        "hostId": "host-aaa",
        "meta": {"name": "hq", "desc": "HQ"},
    },
    {
        "siteId": "bbbbbbbbbbbbbbbbbbbbbbb2",
        "hostId": "host-bbb",
        "meta": {"name": "branch", "desc": "Branch"},
    },
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
    client.list_key_labels = MagicMock(return_value=["default"])
    client.paginate = AsyncMock(side_effect=_paginate_side_effect)
    client.get = AsyncMock(side_effect=_get_side_effect)
    # get_sites drains the offset-paginated proxy sites endpoint; match the
    # get side-effect's payload as the drained (unwrapped) item list.
    client.paginate_offset = AsyncMock(side_effect=_make_offset_from_get(_get_side_effect))
    return client


async def _paginate_side_effect(path, *, key=None):
    if path == "/v1/hosts":
        return list(HOSTS)
    if path == "/v1/sites":
        return list(EA_SITES)
    return []


async def _get_side_effect(path, *, key=None, params=None):
    if "/proxy/network/integration/v1/sites" in path:
        return {"data": list(PROXY_SITES)}
    return {}


def _make_offset_from_get(get_fn):
    """Build a paginate_offset side-effect that drains what the get mock returns.

    Registry.get_sites now drains the offset-paginated proxy sites endpoint via
    paginate_offset (which returns the unwrapped item list), so tests mock it by
    unwrapping the ``data`` envelope their get side-effect already defines.
    """

    async def _offset(path, *, key=None, params=None, page_size=200):
        data = await get_fn(path, key=key, params=params)
        return data.get("data", []) if isinstance(data, dict) else data

    return _offset


@pytest.fixture
def registry(mock_client):
    return Registry(mock_client, ttl_seconds=900)


# --- resolve_host_id ---


class TestResolveHostIdDisplayName:
    """list_hosts shows the short console name at reportedState.name (usually equal to the
    hostname); it is accepted as a fallback after id / hostname / name matches."""

    _HOSTS = [
        {
            "id": "AABBCC:111",
            "name": "",
            "reportedState": {"hostname": "udm-a", "name": "Main Office"},
        },
        {"id": "DDEEFF:222", "reportedState": {"hostname": "Main Office", "name": "Other"}},
    ]

    def _registry(self):
        client = AsyncMock()
        client.list_key_labels = MagicMock(return_value=["default"])
        client.paginate = AsyncMock(return_value=list(self._HOSTS))
        return Registry(client, ttl_seconds=900)

    @pytest.mark.asyncio
    async def test_resolves_by_reported_state_name_case_insensitive(self):
        assert await self._registry().resolve_host_id("other") == "DDEEFF:222"

    @pytest.mark.asyncio
    async def test_exact_hostname_match_wins_over_display_name(self):
        # "Main Office" is host 1's display name but host 2's hostname: hostname wins.
        assert await self._registry().resolve_host_id("main office") == "DDEEFF:222"

    @pytest.mark.asyncio
    async def test_unknown_still_raises(self):
        with pytest.raises(ValueError, match="unknown host"):
            await self._registry().resolve_host_id("nope")


class TestUnknownSiteListsChoices:
    @pytest.mark.asyncio
    async def test_resolve_site_id_lists_valid_sites(self, registry):
        with pytest.raises(ValueError) as exc:
            await registry.resolve_site_id("nope", "host-aaa")
        msg = str(exc.value)
        assert "Site 'nope' not found on host 'host-aaa'; valid:" in msg
        assert "Default (a1b2c3d4-e5f6-7890-abcd-ef1234567890)" in msg
        assert "Branch Office (b2c3d4e5-f6a7-8901-bcde-f12345678901)" in msg

    @pytest.mark.asyncio
    async def test_resolve_site_slug_lists_valid_sites(self, registry):
        with pytest.raises(ValueError, match=r"valid: Default \(a1b2c3d4"):
            await registry.resolve_site_slug("nope", "host-aaa")


class TestIncompleteSiteList:
    @pytest.mark.asyncio
    async def test_not_found_says_site_list_was_incomplete(self):
        from unifi_fabric.client import PaginationAbortedError

        client = AsyncMock()
        client.list_key_labels = MagicMock(return_value=["default"])
        client.paginate_offset = AsyncMock(
            side_effect=PaginationAbortedError(
                "/sites", 3, "page cap of 3 reached", items=[{"id": "x", "description": "A"}]
            )
        )
        reg = Registry(client, ttl_seconds=900)
        with pytest.raises(ValueError) as exc:
            await reg.resolve_site_id("Z", "host-aaa")
        assert "site list is incomplete: page cap of 3 reached" in str(exc.value)


class TestDuplicateSiteNames:
    """Two different sites with the same name fail fast listing (name, id)."""

    _SITES = [
        {"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "description": "Office"},
        {"id": "b2c3d4e5-f6a7-8901-bcde-f12345678901", "description": "office"},
        {
            "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
            "description": "Lab",
            "internalReference": "lab",
        },
    ]

    def _registry(self):
        client = AsyncMock()
        client.list_key_labels = MagicMock(return_value=["default"])
        client.paginate_offset = AsyncMock(return_value=list(self._SITES))
        return Registry(client, ttl_seconds=900)

    @pytest.mark.asyncio
    async def test_resolve_site_id_ambiguous(self):
        with pytest.raises(ValueError) as exc:
            await self._registry().resolve_site_id("OFFICE", "host-aaa")
        msg = str(exc.value)
        assert "ambiguous site 'OFFICE'" in msg
        assert "Office (a1b2c3d4-e5f6-7890-abcd-ef1234567890)" in msg
        assert "office (b2c3d4e5-f6a7-8901-bcde-f12345678901)" in msg

    @pytest.mark.asyncio
    async def test_resolve_site_slug_ambiguous(self):
        # The exact name wins first ("office" is one site); with no exact match the
        # casefolded tier holds both, so the name is ambiguous.
        with pytest.raises(ValueError, match="ambiguous site 'OFFICE'"):
            await self._registry().resolve_site_slug("OFFICE", "host-aaa")

    @pytest.mark.asyncio
    async def test_id_still_resolves_and_unique_name_works(self):
        reg = self._registry()
        sid = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
        assert await reg.resolve_site_id(sid, "host-aaa") == sid
        assert await reg.resolve_site_slug("lab", "host-aaa") == "lab"

    @pytest.mark.asyncio
    async def test_resolve_ea_site_id_ambiguous_across_consoles(self):
        client = AsyncMock()
        client.list_key_labels = MagicMock(return_value=["default"])
        client.paginate = AsyncMock(
            return_value=[
                {"hostId": "h1", "siteId": "s-1", "meta": {"name": "default", "desc": "Default"}},
                {"hostId": "h2", "siteId": "s-2", "meta": {"name": "default", "desc": "Default"}},
            ]
        )
        reg = Registry(client, ttl_seconds=900)
        with pytest.raises(ValueError) as exc:
            await reg.resolve_ea_site_id("Default")
        msg = str(exc.value)
        assert "siteId=s-1, hostId=h1" in msg and "siteId=s-2, hostId=h2" in msg
        assert await reg.resolve_ea_site_id("Default", host_id="h2") == "s-2"


class TestHostMatchingEdgeCases:
    """Null fields never crash; a name shared by two consoles fails fast with choices."""

    def _registry(self, hosts):
        client = AsyncMock()
        client.list_key_labels = MagicMock(return_value=["default"])
        client.paginate = AsyncMock(return_value=list(hosts))
        return Registry(client, ttl_seconds=900)

    @pytest.mark.asyncio
    async def test_null_hostname_and_name_do_not_raise_attribute_error(self):
        hosts = [
            {"id": "AA:1", "name": None, "reportedState": {"hostname": None, "name": None}},
            {"id": "BB:2", "reportedState": None},
            {"id": "CC:3", "name": "Office", "reportedState": {"hostname": "office-gw"}},
        ]
        reg = self._registry(hosts)
        assert await reg.resolve_host_id("office-gw") == "CC:3"
        with pytest.raises(ValueError, match=r"unknown host 'nope'; valid: AA:1, BB:2, office-gw"):
            await reg.resolve_host_id("nope")

    @pytest.mark.asyncio
    async def test_duplicate_display_name_is_ambiguous(self):
        hosts = [
            {"id": "AA:1", "reportedState": {"hostname": "gw-a", "name": "Branch"}},
            {"id": "BB:2", "reportedState": {"hostname": "gw-b", "name": "branch"}},
        ]
        reg = self._registry(hosts)
        # An exact display name selects its console; "BRANCH" matches both in
        # the casefolded tier and is ambiguous.
        assert await reg.resolve_host_id("Branch") == "AA:1"
        with pytest.raises(ValueError) as exc:
            await reg.resolve_host_id("BRANCH")
        msg = str(exc.value)
        assert "ambiguous host 'BRANCH'" in msg
        assert "id=AA:1 hostname=gw-a name=Branch" in msg
        assert "id=BB:2 hostname=gw-b name=branch" in msg
        assert "Pass the console id instead" in msg
        # each console stays reachable by id or hostname
        assert await reg.resolve_host_id("gw-b") == "BB:2"
        assert await reg.resolve_host_id("AA:1") == "AA:1"

    @pytest.mark.asyncio
    async def test_unique_higher_tier_match_beats_display_name(self):
        hosts = [
            {"id": "AA:1", "reportedState": {"hostname": "x", "name": "core"}},
            {"id": "BB:2", "reportedState": {"hostname": "core", "name": "y"}},
        ]
        assert await self._registry(hosts).resolve_host_id("core") == "BB:2"


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
    async def test_resolve_host_id_unknown_host_raises(self, registry):
        # Fail fast on an unrecognised host: exact message + a valid list built at
        # runtime from the (synthetic) fixture consoles: hostname (name, id).
        with pytest.raises(
            ValueError,
            match=(
                r"^unknown host 'bogus-host'; valid: router\.local \(MyRouter, host-aaa\), "
                r"switch01\.local \(Switch01, host-bbb\)\Z"
            ),
        ):
            await registry.resolve_host_id("bogus-host")

    @pytest.mark.asyncio
    async def test_resolve_host_id_unknown_host_valid_still_resolves(self, registry):
        # A valid host still resolves after the unknown-host fail-fast change.
        assert await registry.resolve_host_id("router.local") == "host-aaa"

    @pytest.mark.asyncio
    async def test_resolve_host_id_empty_string(self, registry):
        with pytest.raises(ValueError, match="must not be empty"):
            await registry.resolve_host_id("")

    @pytest.mark.asyncio
    async def test_resolve_host_id_whitespace(self, registry):
        with pytest.raises(ValueError, match="must not be empty"):
            await registry.resolve_host_id("   ")


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
    async def test_resolve_site_id_empty_string(self, registry):
        with pytest.raises(ValueError, match="must not be empty"):
            await registry.resolve_site_id("", _HOST_ID)

    @pytest.mark.asyncio
    async def test_resolve_site_id_whitespace(self, registry):
        with pytest.raises(ValueError, match="must not be empty"):
            await registry.resolve_site_id("   ", _HOST_ID)

    @pytest.mark.asyncio
    async def test_resolve_site_id_uses_proxy_endpoint(self, registry, mock_client):
        await registry.resolve_site_id("Default", _HOST_ID)
        mock_client.paginate_offset.assert_called_once()
        call_path = mock_client.paginate_offset.call_args[0][0]
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
        client.list_key_labels = MagicMock(return_value=["default"])
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
        client.paginate_offset = AsyncMock(side_effect=_make_offset_from_get(_get))
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
        client.list_key_labels = MagicMock(return_value=["default"])
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
        client.paginate_offset = AsyncMock(side_effect=_make_offset_from_get(_get))
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
            _assert_uuid("000000000000000000000503")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            _assert_uuid("")

    def test_random_string_raises(self):
        with pytest.raises(ValueError):
            _assert_uuid("my-site")


# --- get_ea_sites ---


class TestResolveEaSiteId:
    """resolve_ea_site_id resolves against /v1/sites and fails fast on unknown sites."""

    async def test_resolves_name_to_ea_site_id(self, registry):
        # site name -> Fabric ObjectId siteId (from the Site Manager /v1/sites list)
        assert await registry.resolve_ea_site_id("HQ") == "aaaaaaaaaaaaaaaaaaaaaaa1"

    async def test_resolves_known_id_passthrough(self, registry):
        assert (
            await registry.resolve_ea_site_id("bbbbbbbbbbbbbbbbbbbbbbb2")
            == "bbbbbbbbbbbbbbbbbbbbbbb2"
        )

    async def test_resolves_by_meta_name_case_insensitive(self, registry):
        # meta.name (the slug) also resolves, case-insensitively, to the ObjectId
        assert await registry.resolve_ea_site_id("BRANCH") == "bbbbbbbbbbbbbbbbbbbbbbb2"

    async def test_host_id_scopes_resolution(self, registry):
        # With host_id given, only that console's sites are considered
        assert (
            await registry.resolve_ea_site_id("HQ", host_id="host-aaa")
            == "aaaaaaaaaaaaaaaaaaaaaaa1"
        )
        with pytest.raises(ValueError, match="not found"):
            await registry.resolve_ea_site_id("HQ", host_id="host-bbb")

    async def test_unknown_site_raises_with_valid_names(self, registry, mock_client):
        with pytest.raises(ValueError) as exc:
            await registry.resolve_ea_site_id("Nonexistent")
        msg = str(exc.value)
        assert "not found" in msg
        # valid-names list is built at runtime from the sites payload
        assert "HQ" in msg and "Branch" in msg
        assert "Nonexistent" in msg
        # resolver never forwards an unrecognised value to a metrics endpoint:
        # the only upstream call is the /v1/sites list fetch used for resolution.
        assert mock_client.paginate.await_args_list == [call("/v1/sites", key=None)]

    async def test_empty_site_raises(self, registry):
        with pytest.raises(ValueError, match="must not be empty"):
            await registry.resolve_ea_site_id("   ")


class TestGetEaSites:
    @pytest.mark.asyncio
    async def test_returns_ea_sites(self, registry):
        result = await registry.get_ea_sites()
        assert result == EA_SITES

    @pytest.mark.asyncio
    async def test_calls_ea_path(self, registry, mock_client):
        await registry.get_ea_sites()
        mock_client.paginate.assert_called_once_with("/v1/sites", key=None)


# --- Cache TTL / invalidation ---


class TestCacheTtl:
    @pytest.mark.asyncio
    async def test_cache_used_on_second_call(self, registry, mock_client):
        await registry.get_hosts()
        await registry.get_hosts()
        assert mock_client.paginate.call_count == 1

    @pytest.mark.asyncio
    async def test_cache_ttl_expiry_triggers_refetch(self, registry, mock_client):
        from cachetools import TTLCache

        clock = [0]
        registry._hosts = TTLCache(maxsize=512, ttl=900, timer=lambda: clock[0])
        await registry.get_hosts()
        assert mock_client.paginate.call_count == 1

        clock[0] = 901

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
        assert mock_client.paginate_offset.call_count == 2

        # Second calls hit cache
        await registry.get_sites("host-aaa")
        await registry.get_sites("host-bbb")
        assert mock_client.paginate_offset.call_count == 2

    @pytest.mark.asyncio
    async def test_invalidate_clears_proxy_sites_for_key(self, registry, mock_client):
        key_a = APIKeyConfig(key="sk-a", label="a")
        await registry.get_sites("host-aaa", key=key_a)
        registry.invalidate(key=key_a)
        await registry.get_sites("host-aaa", key=key_a)
        assert mock_client.paginate_offset.call_count == 2


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
        # The default path shares the first configured key label.
        assert "default" in registry._hosts
        assert None not in registry._hosts
        assert "__default__" not in registry._hosts

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
        assert mock_client.paginate_offset.call_count == 2


# --- Bounded cache (TTLCache size limits and eviction warnings) ---


class TestBoundedCache:
    @pytest.mark.asyncio
    async def test_cache_stays_bounded_when_full(self):
        """Filling past maxsize evicts LRU entries; size never exceeds maxsize."""
        client = AsyncMock()
        client.list_key_labels = MagicMock(return_value=["default"])
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
        client.list_key_labels = MagicMock(return_value=["default"])
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
        client.list_key_labels = MagicMock(return_value=["default"])
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
        client.list_key_labels = MagicMock(return_value=["default"])
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
        client.list_key_labels = MagicMock(return_value=["default"])
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
        client.list_key_labels = MagicMock(return_value=["default"])
        client.get = AsyncMock(return_value={"data": []})
        reg = Registry(client, ttl_seconds=900, cache_max_sites=4)

        for i in range(8):
            await reg.get_sites(f"host-{i}")

        assert len(reg._sites) <= 4


# --- Per-label locking ---


class TestPerLabelLocking:
    @pytest.mark.asyncio
    async def test_separate_locks_created_per_label(self, registry, mock_client):
        import asyncio as _asyncio

        key_a = APIKeyConfig(key="sk-a", label="alpha")
        key_b = APIKeyConfig(key="sk-b", label="beta")
        release = _asyncio.Event()

        async def slow(path, *, key=None):
            await release.wait()
            return list(HOSTS)

        mock_client.paginate = AsyncMock(side_effect=slow)
        tasks = [
            _asyncio.create_task(registry.get_hosts(key=key_a)),
            _asyncio.create_task(registry.get_hosts(key=key_b)),
        ]
        await _asyncio.sleep(0)

        # One lock per cache entry while it is in use: (cache, key label, console id).
        assert ("hosts", "alpha", "") in registry._locks
        assert ("hosts", "beta", "") in registry._locks
        assert registry._locks[("hosts", "alpha", "")] is not registry._locks[("hosts", "beta", "")]
        release.set()
        await _asyncio.gather(*tasks)
        # Idle entries are reclaimed: the map does not grow with every label ever seen.
        assert registry._locks == {}

    @pytest.mark.asyncio
    async def test_default_label_shares_first_configured_lock(self, registry):
        named = APIKeyConfig(key="sk-default", label="default")
        default_label = registry._key_label(None)
        assert default_label == registry._key_label(named) == "default"
        async with registry._entry_lock("hosts", default_label):
            assert ("hosts", "default", "") in registry._locks
            assert ("hosts", None, "") not in registry._locks
        assert registry._locks == {}

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


# --- resolve_key_for_host (MSP multi-key ownership resolution, issue #19) ---


def _make_multikey_client(
    hosts_by_label: dict[str, list[dict]],
    *,
    fail_labels: tuple[str, ...] = (),
) -> MagicMock:
    """Build a client mock whose /v1/hosts list differs per API key label.

    ``list_key_labels`` / ``get_key_by_label`` are the real (synchronous) client
    contract; ``paginate`` is async and returns each label's own host list, or
    raises for labels in ``fail_labels`` (to exercise per-key failure isolation).
    """
    client = MagicMock()
    labels = list(hosts_by_label.keys())
    client.list_key_labels.return_value = labels
    client.get_key_by_label.side_effect = lambda label: APIKeyConfig(key=f"sk-{label}", label=label)

    async def _paginate(path: str, *, key: APIKeyConfig | None = None) -> list[dict]:
        assert key is not None
        if path == "/v1/hosts":
            if key.label in fail_labels:
                raise UniFiConnectionError(f"HTTP 401 from GET /v1/hosts ({key.label})")
            return list(hosts_by_label[key.label])
        return []

    client.paginate = AsyncMock(side_effect=_paginate)
    return client


_ALPHA_HOSTS = [{"id": "host-a1", "name": "Alpha-Router", "reportedState": {"hostname": "a.local"}}]
_BETA_HOSTS = [{"id": "host-b1", "name": "Beta-Switch", "reportedState": {"hostname": "b.local"}}]


class TestResolveKeyForHost:
    @pytest.mark.asyncio
    async def test_selects_correct_key_by_id(self):
        client = _make_multikey_client({"alpha": _ALPHA_HOSTS, "beta": _BETA_HOSTS})
        reg = Registry(client, ttl_seconds=900)
        result = await reg.resolve_key_for_host("host-b1")
        assert result is not None
        assert result.label == "beta"

    @pytest.mark.asyncio
    async def test_selects_correct_key_by_hostname(self):
        client = _make_multikey_client({"alpha": _ALPHA_HOSTS, "beta": _BETA_HOSTS})
        reg = Registry(client, ttl_seconds=900)
        result = await reg.resolve_key_for_host("B.LOCAL")  # case-insensitive
        assert result is not None
        assert result.label == "beta"

    @pytest.mark.asyncio
    async def test_selects_correct_key_by_name(self):
        client = _make_multikey_client({"alpha": _ALPHA_HOSTS, "beta": _BETA_HOSTS})
        reg = Registry(client, ttl_seconds=900)
        result = await reg.resolve_key_for_host("alpha-router")  # case-insensitive
        assert result is not None
        assert result.label == "alpha"

    @pytest.mark.asyncio
    async def test_selects_correct_key_by_display_name(self):
        """Same identifiers as resolve_host_id, including reportedState.name."""
        beta = [{"id": "host-b1", "reportedState": {"hostname": "b.local", "name": "Beta Site"}}]
        client = _make_multikey_client({"alpha": _ALPHA_HOSTS, "beta": beta})
        reg = Registry(client, ttl_seconds=900)
        result = await reg.resolve_key_for_host("beta site")
        assert result is not None
        assert result.label == "beta"

    @pytest.mark.asyncio
    async def test_null_fields_in_any_key_do_not_raise(self):
        nulls = [{"id": "host-n1", "name": None, "reportedState": {"hostname": None}}]
        client = _make_multikey_client({"alpha": nulls, "beta": _BETA_HOSTS})
        reg = Registry(client, ttl_seconds=900)
        result = await reg.resolve_key_for_host("b.local")
        assert result is not None and result.label == "beta"

    @pytest.mark.asyncio
    async def test_same_name_on_two_keys_is_ambiguous(self):
        a = [{"id": "host-a1", "reportedState": {"hostname": "gw", "name": "HQ"}}]
        b = [{"id": "host-b1", "reportedState": {"hostname": "gw2", "name": "HQ"}}]
        client = _make_multikey_client({"alpha": a, "beta": b})
        reg = Registry(client, ttl_seconds=900)
        with pytest.raises(ValueError, match=r"ambiguous host 'HQ'.*host-a1.*host-b1"):
            await reg.resolve_key_for_host("HQ")

    @pytest.mark.asyncio
    async def test_same_console_on_two_keys_is_not_ambiguous(self):
        both = [{"id": "host-s1", "reportedState": {"hostname": "shared"}}]
        client = _make_multikey_client({"alpha": both, "beta": both})
        reg = Registry(client, ttl_seconds=900)
        result = await reg.resolve_key_for_host("shared")
        assert result is not None and result.label == "alpha"

    @pytest.mark.asyncio
    async def test_single_key_short_circuits_without_api_calls(self):
        """The common case: one key means nothing to disambiguate, no host fan-out."""
        client = _make_multikey_client({"alpha": _ALPHA_HOSTS})
        reg = Registry(client, ttl_seconds=900)
        result = await reg.resolve_key_for_host("host-a1")
        assert result is None
        client.paginate.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_match_fails_fast_listing_all_keys(self):
        client = _make_multikey_client({"alpha": _ALPHA_HOSTS, "beta": _BETA_HOSTS})
        reg = Registry(client, ttl_seconds=900)
        with pytest.raises(ValueError) as exc:
            await reg.resolve_key_for_host("host-does-not-exist")
        msg = str(exc.value)
        assert "a.local (Alpha-Router, host-a1)" in msg
        assert "b.local (Beta-Switch, host-b1)" in msg

    @pytest.mark.asyncio
    async def test_no_match_names_keys_that_failed_to_list(self):
        client = _make_multikey_client(
            {"alpha": _ALPHA_HOSTS, "beta": _BETA_HOSTS}, fail_labels=("beta",)
        )
        reg = Registry(client, ttl_seconds=900)
        with pytest.raises(ValueError) as exc:
            await reg.resolve_key_for_host("host-does-not-exist")
        msg = str(exc.value)
        assert "host-a1" in msg
        assert "API key 'beta' could not list its consoles: HTTP 401" in msg

    @pytest.mark.asyncio
    async def test_malformed_input_is_rejected_before_any_request(self):
        """An empty, whitespace-only or control-character host is a selector error, never
        "no host" (which would route the call on the default key)."""
        client = _make_multikey_client({"alpha": _ALPHA_HOSTS, "beta": _BETA_HOSTS})
        reg = Registry(client, ttl_seconds=900)
        for bad in ("", "   ", "host-b1\n", " host-b1"):
            with pytest.raises(ValueError, match="'host'"):
                await reg.resolve_key_for_host(bad)
        client.paginate.assert_not_called()

    @pytest.mark.asyncio
    async def test_one_key_fails_others_still_resolve(self):
        """A failing/unauthorized key must not abort resolution for a healthy key."""
        client = _make_multikey_client(
            {"alpha": _ALPHA_HOSTS, "beta": _BETA_HOSTS}, fail_labels=("alpha",)
        )
        reg = Registry(client, ttl_seconds=900)
        result = await reg.resolve_key_for_host("host-b1")
        assert result is not None
        assert result.label == "beta"

    @pytest.mark.asyncio
    async def test_all_keys_fail_raises(self):
        client = _make_multikey_client(
            {"alpha": _ALPHA_HOSTS, "beta": _BETA_HOSTS}, fail_labels=("alpha", "beta")
        )
        reg = Registry(client, ttl_seconds=900)
        with pytest.raises(RuntimeError, match="all 2 configured"):
            await reg.resolve_key_for_host("host-b1")

    @pytest.mark.asyncio
    async def test_uses_registry_cache_no_refetch_per_call(self):
        """Repeated per-host resolution must reuse the TTL-cached host lists."""
        client = _make_multikey_client({"alpha": _ALPHA_HOSTS, "beta": _BETA_HOSTS})
        reg = Registry(client, ttl_seconds=900)
        await reg.resolve_key_for_host("host-a1")
        await reg.resolve_key_for_host("host-b1")
        # One /v1/hosts fetch per key, regardless of how many resolutions happen.
        assert client.paginate.call_count == 2


class TestGetHostsPath:
    """Pin the exact Site Manager hosts path the registry drains."""

    @pytest.mark.asyncio
    async def test_get_hosts_calls_v1_path(self, registry, mock_client):
        await registry.get_hosts()
        mock_client.paginate.assert_called_once_with("/v1/hosts", key=None)


def test_match_host_mac_forms_and_ambiguity() -> None:
    from unifi_fabric.registry import match_host

    hosts = [
        {"id": "host-a", "reportedState": {"mac": "AA:BB:CC:DD:EE:01"}},
        {"id": "host-b", "reportedState": {"hardware": {"mac": "aa-bb-cc-dd-ee-02"}}},
    ]
    for selector in ("aabbccddee01", "AA:BB:CC:DD:EE:01", "aa-bb-cc-dd-ee-01"):
        assert match_host(hosts, selector)[1]["id"] == "host-a"
    assert match_host(hosts, "aabbccddee02")[1]["id"] == "host-b"
    with pytest.raises(ValueError, match="ambiguous host"):
        match_host(
            [*hosts, {"id": "host-c", "reportedState": {"mac": "aabbccddee01"}}], "aabbccddee01"
        )


@pytest.mark.parametrize(
    ("host_id", "selector"),
    [
        # a composite id whose hex part is exactly the 12-digit MAC
        ("001122334455:123456789", "00:11:22:33:44:55"),
        # a longer composite id (30 hex digits) that starts with the MAC
        ("0A0001000000000000000000ABCDEF:1", "0a:00:01:00:00:00"),
        # a 64-hex-digit composite id that starts with the MAC
        ("0A0001000002" + "0" * 52 + ":1234567890", "0a0001000002"),
    ],
)
def test_match_host_mac_from_composite_id_without_reported_mac(host_id: str, selector: str) -> None:
    from unifi_fabric.registry import match_host

    hosts = [
        {"id": host_id, "reportedState": {"hostname": "lab"}},
        {"id": "AABBCCDDEEFF" + "1" * 52 + ":1", "reportedState": {"hostname": "other"}},
    ]
    found = match_host(hosts, selector)
    assert found is not None and found[1]["id"] == host_id


def test_match_host_composite_prefix_and_reported_mac_are_one_console() -> None:
    from unifi_fabric.registry import _host_mac_values

    host = {"id": "001122334455:1", "reportedState": {"mac": "00:11:22:33:44:55"}}
    assert _host_mac_values(host) == ["001122334455"]


def test_match_host_collapses_internal_whitespace_and_site_slug_fallback() -> None:
    from unifi_fabric.registry import _match_proxy_site, match_host

    assert (
        match_host(
            [{"id": "host-a", "reportedState": {"hostname": "Main   Office"}}], "main office"
        )[1]["id"]
        == "host-a"
    )
    site = {
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "description": "Renamed",
        "internalReference": "default",
    }
    assert _match_proxy_site([site], "default") is site
