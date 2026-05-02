"""Tests for the UniFi httpx client wrapper."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from unifi_fabric.client import (
    PaginationAbortedError,
    RateLimitError,
    UniFiClient,
    validate_host_id,
    validate_id,
)
from unifi_fabric.config import APIKeyConfig, Settings

BASE = "https://api.ui.com"


@pytest.fixture
def single_key_settings():
    return Settings(api_key="sk-single-test")


@pytest.fixture
def multi_key_settings():
    return Settings(
        api_keys=[
            APIKeyConfig(key="sk-acme", label="acme"),
            APIKeyConfig(key="sk-globex", label="globex", is_org_key=True),
        ]
    )


@pytest.fixture
def client(single_key_settings):
    return UniFiClient(single_key_settings)


@pytest.fixture
def multi_client(multi_key_settings):
    return UniFiClient(multi_key_settings)


# --- API key injection ---


class TestAPIKeyHeader:
    @respx.mock
    @pytest.mark.asyncio
    async def test_default_key_injected(self, client):
        route = respx.get(f"{BASE}/ea/hosts").mock(return_value=Response(200, json={"data": []}))
        await client.get("/ea/hosts")
        assert route.called
        req = route.calls[0].request
        assert req.headers["x-api-key"] == "sk-single-test"

    @respx.mock
    @pytest.mark.asyncio
    async def test_explicit_key_used(self, multi_client):
        route = respx.get(f"{BASE}/ea/hosts").mock(return_value=Response(200, json={"data": []}))
        acme_key = multi_client.get_key_by_label("acme")
        await multi_client.get("/ea/hosts", key=acme_key)
        assert route.calls[0].request.headers["x-api-key"] == "sk-acme"

    @respx.mock
    @pytest.mark.asyncio
    async def test_different_keys_different_clients(self, multi_client):
        route = respx.get(f"{BASE}/ea/hosts").mock(return_value=Response(200, json={"data": []}))
        acme = multi_client.get_key_by_label("acme")
        globex = multi_client.get_key_by_label("globex")
        await multi_client.get("/ea/hosts", key=acme)
        await multi_client.get("/ea/hosts", key=globex)
        assert route.calls[0].request.headers["x-api-key"] == "sk-acme"
        assert route.calls[1].request.headers["x-api-key"] == "sk-globex"


# --- Multi-key management ---


class TestMultiKey:
    def test_get_key_by_label(self, multi_client):
        key = multi_client.get_key_by_label("globex")
        assert key.key == "sk-globex"
        assert key.is_org_key is True

    def test_get_key_by_label_missing(self, multi_client):
        with pytest.raises(KeyError, match="nope"):
            multi_client.get_key_by_label("nope")

    def test_list_key_labels(self, multi_client):
        assert multi_client.list_key_labels() == ["acme", "globex"]

    def test_list_key_labels_single(self, client):
        assert client.list_key_labels() == ["default"]

    def test_no_keys_raises(self):
        empty = UniFiClient(Settings(api_key="", api_keys=[]))
        with pytest.raises(ValueError, match="No API key configured"):
            empty._default_key()


# --- Backoff / rate-limit ---


class TestBackoff:
    @respx.mock
    @pytest.mark.asyncio
    async def test_retries_on_429_then_succeeds(self, client):
        route = respx.get(f"{BASE}/ea/hosts")
        route.side_effect = [
            Response(429),
            Response(429),
            Response(200, json={"data": [{"id": "h1"}]}),
        ]
        result = await client.get("/ea/hosts")
        assert result["data"][0]["id"] == "h1"
        assert route.call_count == 3

    @respx.mock
    @pytest.mark.asyncio
    async def test_raises_after_max_retries(self, client):
        respx.get(f"{BASE}/ea/hosts").mock(return_value=Response(429))
        with pytest.raises(RateLimitError, match="Rate limited after"):
            await client.request("GET", "/ea/hosts", max_retries=1)

    @respx.mock
    @pytest.mark.asyncio
    async def test_non_429_error_raises_immediately(self, client):
        respx.get(f"{BASE}/ea/hosts").mock(return_value=Response(500))
        with pytest.raises(Exception):
            await client.get("/ea/hosts")


# --- Error body surfacing ---


class TestErrorBodySurfacing:
    @respx.mock
    @pytest.mark.asyncio
    async def test_400_includes_response_body(self, client):
        error_body = '{"errorCode": "INVALID_FIELD", "message": "vlan must be 1-4094"}'
        respx.post(f"{BASE}/ea/networks").mock(return_value=Response(400, text=error_body))
        with pytest.raises(Exception, match="INVALID_FIELD"):
            await client.post("/ea/networks", json={"name": "bad"})

    @respx.mock
    @pytest.mark.asyncio
    async def test_422_includes_response_body(self, client):
        error_body = '{"error": "unprocessable", "field": "name"}'
        respx.post(f"{BASE}/ea/networks").mock(return_value=Response(422, text=error_body))
        with pytest.raises(Exception, match="unprocessable"):
            await client.post("/ea/networks", json={"name": ""})

    @respx.mock
    @pytest.mark.asyncio
    async def test_error_message_includes_status_code_and_path(self, client):
        respx.post(f"{BASE}/ea/networks").mock(
            return_value=Response(400, text='{"error": "bad request"}')
        )
        with pytest.raises(Exception, match="400"):
            await client.post("/ea/networks", json={})


# --- Pagination ---


class TestPagination:
    @respx.mock
    @pytest.mark.asyncio
    async def test_single_page(self, client):
        respx.get(f"{BASE}/ea/hosts").mock(
            return_value=Response(200, json={"data": [{"id": "h1"}, {"id": "h2"}]})
        )
        items = await client.paginate("/ea/hosts")
        assert len(items) == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_multi_page(self, client):
        route = respx.get(f"{BASE}/ea/hosts")
        route.side_effect = [
            Response(200, json={"data": [{"id": "h1"}], "nextToken": "tok2"}),
            Response(200, json={"data": [{"id": "h2"}]}),
        ]
        items = await client.paginate("/ea/hosts")
        assert [i["id"] for i in items] == ["h1", "h2"]
        assert route.call_count == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_page_size_sent_as_limit_param(self, client):
        route = respx.get(f"{BASE}/ea/hosts").mock(
            return_value=Response(200, json={"data": [{"id": "h1"}]})
        )
        await client.paginate("/ea/hosts", page_size=50)
        assert route.called
        assert route.calls[0].request.url.params["limit"] == "50"

    @respx.mock
    @pytest.mark.asyncio
    async def test_custom_params_not_overridden_by_limit(self, client):
        route = respx.get(f"{BASE}/ea/hosts").mock(
            return_value=Response(200, json={"data": [{"id": "h1"}]})
        )
        await client.paginate("/ea/hosts", params={"limit": "10"}, page_size=200)
        assert route.called
        assert route.calls[0].request.url.params["limit"] == "10"

    @respx.mock
    @pytest.mark.asyncio
    async def test_stall_detection_raises(self, client):
        """Same nextToken returned twice → PaginationAbortedError after 2 pages."""
        route = respx.get(f"{BASE}/ea/hosts")
        route.side_effect = [
            Response(200, json={"data": [{"id": "h1"}], "nextToken": "tok-stuck"}),
            Response(200, json={"data": [{"id": "h2"}], "nextToken": "tok-stuck"}),
        ]
        with pytest.raises(PaginationAbortedError, match="stall detected"):
            await client.paginate("/ea/hosts")
        assert route.call_count == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_large_result_set_not_truncated(self, client):
        """100 pages of distinct tokens must all be returned without truncation."""
        pages = [
            Response(200, json={"data": [{"id": f"h{i}"}], "nextToken": f"tok{i + 1}"})
            for i in range(99)
        ]
        pages.append(Response(200, json={"data": [{"id": "h99"}]}))
        respx.get(f"{BASE}/ea/hosts").side_effect = pages
        items = await client.paginate("/ea/hosts")
        assert len(items) == 100

    @respx.mock
    @pytest.mark.asyncio
    async def test_page_cap_raises(self):
        """When UNIFI_PAGINATE_MAX_PAGES is set and reached, PaginationAbortedError is raised."""
        capped_settings = Settings(api_key="sk-test", paginate_max_pages=3)
        capped_client = UniFiClient(capped_settings)
        route = respx.get(f"{BASE}/ea/hosts")
        # Each response provides a distinct new token — no stall, just many pages
        route.side_effect = [
            Response(200, json={"data": [{"id": f"h{i}"}], "nextToken": f"tok{i + 1}"})
            for i in range(10)
        ]
        with pytest.raises(PaginationAbortedError, match="page cap of 3"):
            await capped_client.paginate("/ea/hosts")
        assert route.call_count == 3


# --- HTTP method helpers ---


class TestHTTPMethods:
    @respx.mock
    @pytest.mark.asyncio
    async def test_put(self, client):
        route = respx.put(f"{BASE}/ea/networks/n1").mock(
            return_value=Response(200, json={"id": "n1", "name": "updated"})
        )
        result = await client.put("/ea/networks/n1", json={"name": "updated"})
        assert result["name"] == "updated"
        assert route.called

    @respx.mock
    @pytest.mark.asyncio
    async def test_patch(self, client):
        route = respx.patch(f"{BASE}/ea/networks/n1").mock(
            return_value=Response(200, json={"id": "n1", "vlan": 100})
        )
        result = await client.patch("/ea/networks/n1", json={"vlan": 100})
        assert result["vlan"] == 100
        assert route.called

    @respx.mock
    @pytest.mark.asyncio
    async def test_delete(self, client):
        route = respx.delete(f"{BASE}/ea/networks/n1").mock(return_value=Response(204))
        await client.delete("/ea/networks/n1")
        assert route.called


# --- Lifecycle ---


class TestGather:
    @pytest.mark.asyncio
    async def test_gather_runs_concurrently(self, client):
        """Gather should run coroutines bounded by semaphore and return all results."""
        import asyncio

        results = []

        async def fake_task(value: int) -> int:
            await asyncio.sleep(0)
            results.append(value)
            return value * 10

        gathered = await client.gather([fake_task(1), fake_task(2), fake_task(3)])
        assert gathered == [10, 20, 30]
        assert sorted(results) == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_gather_empty(self, client):
        """Gather with no coroutines returns empty list."""
        assert await client.gather([]) == []


class TestValidateId:
    def test_accepts_alphanumeric(self):
        validate_id("abc123", "some_id")  # should not raise

    def test_accepts_hyphens_and_underscores(self):
        validate_id("my-id_value", "some_id")  # should not raise

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must not be empty"):
            validate_id("", "some_id")

    def test_rejects_colon(self):
        with pytest.raises(ValueError, match="Invalid"):
            validate_id("aabbccdd:12345", "some_id")

    def test_rejects_dot_dot(self):
        with pytest.raises(ValueError, match="Invalid"):
            validate_id("../etc", "some_id")


class TestValidateHostId:
    def test_accepts_alphanumeric(self):
        validate_host_id("abc123", "host_id")  # should not raise

    def test_accepts_hyphens_and_underscores(self):
        validate_host_id("my-host_name", "host_id")  # should not raise

    def test_accepts_composite_host_id_with_colon(self):
        # UniFi composite hostId format: {MAC}0000...:{numericId}
        validate_host_id("aabbccdd00000000000000000000000000000000000000000000:12345", "host_id")

    def test_accepts_simple_colon_separated(self):
        validate_host_id("test-console:67890", "host_id")  # should not raise

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must not be empty"):
            validate_host_id("", "host_id")

    def test_rejects_dot_dot(self):
        with pytest.raises(ValueError, match="unsafe characters"):
            validate_host_id("../etc", "host_id")

    def test_rejects_null_byte(self):
        with pytest.raises(ValueError, match="unsafe characters"):
            validate_host_id("abc\x00def", "host_id")

    def test_rejects_newline(self):
        with pytest.raises(ValueError, match="unsafe characters"):
            validate_host_id("abc\ndef", "host_id")

    def test_rejects_slash(self):
        with pytest.raises(ValueError, match="Invalid"):
            validate_host_id("abc/def", "host_id")

    def test_rejects_space(self):
        with pytest.raises(ValueError, match="Invalid"):
            validate_host_id("abc def", "host_id")


class TestLifecycle:
    @respx.mock
    @pytest.mark.asyncio
    async def test_close_clears_clients(self, client):
        respx.get(f"{BASE}/ea/hosts").mock(return_value=Response(200, json={"data": []}))
        await client.get("/ea/hosts")
        assert len(client._clients) == 1
        await client.close()
        assert len(client._clients) == 0
