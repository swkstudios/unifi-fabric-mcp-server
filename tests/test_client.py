"""Tests for the UniFi httpx client wrapper."""

from __future__ import annotations

import httpx
import pytest
import respx
from httpx import Response

from unifi_fabric.client import (
    PaginationAbortedError,
    RateLimitError,
    UniFiClient,
    UniFiConnectionError,
    UniFiHTTPError,
    decode_body,
    error_body_text,
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

    @respx.mock
    @pytest.mark.asyncio
    async def test_same_label_different_key_never_shares_a_pool(self, client):
        """The HTTP client cache is keyed by label AND key fingerprint, so a second
        config that reuses a label still sends its own X-API-KEY."""
        route = respx.get(f"{BASE}/ea/hosts").mock(return_value=Response(200, json={"data": []}))
        await client.get("/ea/hosts", key=APIKeyConfig(key="sk-first", label="dup"))
        await client.get("/ea/hosts", key=APIKeyConfig(key="sk-second", label="dup"))
        assert route.calls[0].request.headers["x-api-key"] == "sk-first"
        assert route.calls[1].request.headers["x-api-key"] == "sk-second"

    @respx.mock
    @pytest.mark.asyncio
    async def test_client_cache_key_never_holds_the_raw_key(self, client):
        respx.get(f"{BASE}/ea/hosts").mock(return_value=Response(200, json={"data": []}))
        await client.get("/ea/hosts", key=APIKeyConfig(key="sk-raw-canary", label="a"))
        assert client._clients, "no client was cached (vacuous)"  # noqa: SLF001
        for label, fingerprint in client._clients:  # noqa: SLF001
            assert label == "a"
            assert "sk-raw-canary" not in fingerprint


# --- Multi-key management ---


class TestMultiKey:
    def test_get_key_by_label(self, multi_client):
        key = multi_client.get_key_by_label("globex")
        assert key.key == "sk-globex"
        assert key.is_org_key is True

    def test_get_key_by_label_missing(self, multi_client):
        with pytest.raises(ValueError, match="nope"):
            multi_client.get_key_by_label("nope")

    def test_list_key_labels(self, multi_client):
        assert multi_client.list_key_labels() == ["acme", "globex"]

    def test_list_key_labels_single(self, client):
        assert client.list_key_labels() == ["default"]

    def test_no_keys_raises(self):
        empty = UniFiClient(Settings(api_key="", api_keys=[]))
        with pytest.raises(ValueError, match="No API key configured"):
            empty._default_key()


# --- Binary responses ---


class TestGetBinary:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_bytes_and_content_type(self, client):
        payload = b"\x89PNG\r\n\x1a\nsynthetic"
        respx.get(f"{BASE}/asset.png").mock(
            return_value=Response(200, content=payload, headers={"Content-Type": "image/png"})
        )
        content, content_type = await client.get_binary("/asset.png")
        assert content == payload
        assert content_type == "image/png"

    @respx.mock
    @pytest.mark.asyncio
    async def test_content_type_is_none_when_absent(self, client):
        respx.get(f"{BASE}/asset.bin").mock(return_value=Response(200, content=b"raw"))
        content, content_type = await client.get_binary("/asset.bin")
        assert content == b"raw"
        assert content_type is None  # never invented


# --- Backoff / rate-limit ---


async def _no_sleep(_delay: float) -> None:
    return None


class TestBackoff:
    @respx.mock
    @pytest.mark.asyncio
    async def test_retries_on_429_then_succeeds(self, client, monkeypatch):
        monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", _no_sleep)
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
    async def test_raises_after_max_retries(self, client, monkeypatch):
        monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", _no_sleep)
        respx.get(f"{BASE}/ea/hosts").mock(return_value=Response(429))
        with pytest.raises(RateLimitError, match="Rate limited after"):
            await client.request("GET", "/ea/hosts", max_retries=1)

    @respx.mock
    @pytest.mark.asyncio
    async def test_final_429_carries_the_last_upstream_body(self, client, monkeypatch):
        monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", _no_sleep)
        respx.get(f"{BASE}/v1/x").mock(
            side_effect=[
                Response(429, json={"message": "first"}),
                Response(429, json={"message": "quota: retry after 60s", "code": "rl"}),
            ]
        )
        with pytest.raises(RateLimitError) as exc_info:
            await client.request("GET", "/v1/x", max_retries=1)
        msg = str(exc_info.value)
        assert "GET /v1/x" in msg and "HTTP 429" in msg
        assert "quota: retry after 60s" in msg and '"code":"rl"' in msg
        assert "first" not in msg

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    @respx.mock
    @pytest.mark.asyncio
    async def test_a_write_is_sent_once_whatever_max_retries_says(
        self, client, monkeypatch, method
    ):
        monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", _no_sleep)
        route = respx.route(method=method, url=f"{BASE}/v1/x").mock(
            side_effect=[Response(429, json={"message": "slow down"}), Response(200, json={})]
        )
        with pytest.raises(RateLimitError):
            await client.request(method, "/v1/x", json={"a": 1}, max_retries=3)
        assert route.call_count == 1

    @respx.mock
    @pytest.mark.asyncio
    async def test_a_read_post_is_sent_once_whatever_max_retries_says(self, client, monkeypatch):
        from unifi_fabric.read_only import is_write_request
        from unifi_fabric.read_post_routes import READ_POST_ROUTES

        monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", _no_sleep)
        path = next(r.sample for r in READ_POST_ROUTES if r.name == "network-classic-stat-session")
        assert not is_write_request("POST", path, {})  # a read, yet not a GET
        route = respx.post(f"{BASE}{path}").mock(
            side_effect=[Response(429), Response(200, json={})]
        )
        with pytest.raises(RateLimitError):
            await client.request("POST", path, json={}, max_retries=3)
        assert route.call_count == 1

    @respx.mock
    @pytest.mark.asyncio
    async def test_a_state_changing_get_is_sent_once_whatever_max_retries_says(
        self, client, monkeypatch
    ):
        monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", _no_sleep)
        path = "/v1/connector/consoles/h1/proxy/protect/api/cameras/c1/enable-control"
        route = respx.get(f"{BASE}{path}").mock(side_effect=[Response(429), Response(200, json={})])
        with pytest.raises(RateLimitError):
            await client.request("GET", path, max_retries=3)
        assert route.call_count == 1

    @respx.mock
    @pytest.mark.asyncio
    async def test_non_429_error_raises_immediately(self, client):
        route = respx.get(f"{BASE}/ea/hosts").mock(return_value=Response(500))
        with pytest.raises(UniFiHTTPError) as exc_info:
            await client.get("/ea/hosts")
        assert exc_info.value.status == 500
        assert route.call_count == 1


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
        with pytest.raises(UniFiConnectionError, match="400") as exc_info:
            await client.post("/ea/networks", json={})
        msg = str(exc_info.value)
        assert "/ea/networks" in msg
        assert "bad request" in msg


# --- Error messages: complete and actionable ---


class TestErrorMessages:
    """Upstream errors carry the full body and the real path: identifiers are not
    secrets. Credential fields are masked only with UNIFI_REDACT_SECRETS on."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_error_message_keeps_console_id_and_site_uuid(self, client):
        console_id = "aabbccddee00000000000000"
        site_uuid = "550e8400-e29b-41d4-a716-446655440000"
        path = f"/ea/sites/{console_id}/devices/{site_uuid}"
        respx.get(f"{BASE}{path}").mock(return_value=Response(404, text="not found"))
        with pytest.raises(UniFiConnectionError) as exc_info:
            await client.get(path)
        msg = str(exc_info.value)
        assert console_id in msg and site_uuid in msg
        assert "[REDACTED]" not in msg

    @respx.mock
    @pytest.mark.asyncio
    async def test_error_body_complete_and_not_truncated(self, client):
        uuid_in_body = "00000000-0000-5000-8000-557766551111"
        long_detail = "d" * 5000
        body = f'{{"error": "not found", "id": "{uuid_in_body}", "detail": "{long_detail}"}}'
        respx.get(f"{BASE}/ea/hosts").mock(return_value=Response(404, text=body))
        with pytest.raises(UniFiConnectionError) as exc_info:
            await client.get("/ea/hosts")
        msg = str(exc_info.value)
        assert msg.endswith(body)
        assert uuid_in_body in msg

    @respx.mock
    @pytest.mark.asyncio
    async def test_error_body_secret_kept_when_redaction_off(self, client):
        body = '{"error": "bad", "x_passphrase": "pw-value"}'
        respx.post(f"{BASE}/ea/networks").mock(return_value=Response(400, text=body))
        with pytest.raises(UniFiConnectionError) as exc_info:
            await client.post("/ea/networks", json={})
        assert "pw-value" in str(exc_info.value)

    @respx.mock
    @pytest.mark.asyncio
    async def test_error_body_secret_masked_when_redaction_on(self):
        on = UniFiClient(Settings(api_key="sk-single-test", redact_secrets=True))
        body = '{"error": "bad", "x_passphrase": "pw-value", "id": "net-1"}'
        respx.post(f"{BASE}/ea/networks").mock(return_value=Response(400, text=body))
        with pytest.raises(UniFiConnectionError) as exc_info:
            await on.post("/ea/networks", json={})
        msg = str(exc_info.value)
        assert "pw-value" not in msg
        assert "net-1" in msg and "bad" in msg  # the reason survives

    def test_error_body_text_helper(self):
        assert error_body_text("plain text", redact_secrets=True) == "plain text"
        assert error_body_text('{"password": "p"}', redact_secrets=False) == '{"password": "p"}'
        assert "p" not in error_body_text('{"password": "p"}', redact_secrets=True).split(":")[1]

    @respx.mock
    @pytest.mark.asyncio
    async def test_non_json_success_body_returned_verbatim(self, client):
        text = "<html>" + "x" * 3000 + "</html>"
        respx.get(f"{BASE}/ea/hosts").mock(return_value=Response(200, text=text))
        assert await client.get("/ea/hosts") == text

    @respx.mock
    @pytest.mark.asyncio
    async def test_non_json_page_raises_with_shape_when_draining(self, client):
        respx.get(f"{BASE}/ea/hosts").mock(return_value=Response(200, text="<html>"))
        with pytest.raises(UniFiConnectionError, match="got str"):
            await client.paginate("/ea/hosts")


# --- Body decoding: one pass-through rule for every method ---

_DECODE_METHODS = ["get", "post", "put", "patch", "delete"]


class TestDecodeBody:
    """Every client method decodes a 2xx body through the one decode_body rule."""

    @staticmethod
    async def _call(client, method):
        if method == "get":
            return await client.get("/ea/x")
        return await getattr(client, method)("/ea/x", json={"a": 1})

    @pytest.mark.parametrize("method", _DECODE_METHODS)
    @pytest.mark.parametrize(
        ("response", "expected"),
        [
            (Response(200, json={"data": [1]}), {"data": [1]}),
            (Response(200, json=[{"id": "a"}]), [{"id": "a"}]),
            (Response(200, text="OK done"), "OK done"),
            (Response(200, content=b""), None),
            (Response(204), None),
            (Response(201, json={"id": "n"}), {"id": "n"}),
        ],
    )
    @respx.mock
    @pytest.mark.asyncio
    async def test_success_body(self, client, method, response, expected):
        respx.route(method=method.upper(), url=f"{BASE}/ea/x").mock(return_value=response)
        assert await self._call(client, method) == expected

    @pytest.mark.parametrize("method", _DECODE_METHODS)
    @respx.mock
    @pytest.mark.asyncio
    async def test_error_status_still_raises(self, client, method):
        respx.route(method=method.upper(), url=f"{BASE}/ea/x").mock(
            return_value=Response(400, text="bad thing")
        )
        with pytest.raises(UniFiConnectionError, match=f"HTTP 400 from {method.upper()}"):
            await self._call(client, method)

    @respx.mock
    @pytest.mark.asyncio
    async def test_post_multipart_empty_body(self, client):
        respx.post(f"{BASE}/ea/x").mock(return_value=Response(204))
        assert await client.post_multipart("/ea/x", files={"f": ("a", b"x")}) is None

    def test_helper_is_public(self):
        req = httpx.Request("GET", f"{BASE}/x")
        assert decode_body(Response(200, text="plain", request=req)) == "plain"
        assert decode_body(Response(204, request=req)) is None
        assert decode_body(Response(200, json={"k": None}, request=req)) == {"k": None}


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
    async def test_page_size_sent_as_page_size_param(self, client):
        """Site Manager /v1 lists take ``pageSize`` (published spec), not ``limit``."""
        route = respx.get(f"{BASE}/ea/hosts").mock(
            return_value=Response(200, json={"data": [{"id": "h1"}]})
        )
        await client.paginate("/ea/hosts", page_size=50)
        assert route.called
        assert route.calls[0].request.url.params["pageSize"] == "50"
        assert "limit" not in route.calls[0].request.url.params

    @respx.mock
    @pytest.mark.asyncio
    async def test_custom_params_not_overridden_by_page_size(self, client):
        route = respx.get(f"{BASE}/ea/hosts").mock(
            return_value=Response(200, json={"data": [{"id": "h1"}]})
        )
        await client.paginate("/ea/hosts", params={"pageSize": "10"}, page_size=200)
        assert route.called
        assert route.calls[0].request.url.params["pageSize"] == "10"

    @respx.mock
    @pytest.mark.asyncio
    async def test_bare_list_response_is_one_complete_page(self, client):
        route = respx.get(f"{BASE}/ea/hosts").mock(
            return_value=Response(200, json=[{"id": "h1"}, {"id": "h2"}])
        )
        assert await client.paginate("/ea/hosts") == [{"id": "h1"}, {"id": "h2"}]
        assert route.call_count == 1

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
    async def test_non_consecutive_cursor_cycle_stops_with_pages_gathered(self, client):
        """A -> B -> A: the cycle is detected on the first revisit, never looped."""
        route = respx.get(f"{BASE}/ea/hosts")
        route.side_effect = [
            Response(200, json={"data": [{"id": "h1"}], "nextToken": "A"}),
            Response(200, json={"data": [{"id": "h2"}], "nextToken": "B"}),
            Response(200, json={"data": [{"id": "h3"}], "nextToken": "A"}),
            Response(500, text="looped past the cycle"),
        ]
        with pytest.raises(PaginationAbortedError, match="cursor cycle detected") as exc:
            await client.paginate("/ea/hosts")
        assert route.call_count == 3
        assert exc.value.items == [{"id": "h1"}, {"id": "h2"}, {"id": "h3"}]

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


def _assert_transport_chain_hidden(error: BaseException) -> None:
    """The httpx exception (whose request carries the API key header) is not chained.

    ``raise ... from None`` sets ``__suppress_context__``, so a traceback, log record or
    error reporter that honours it never renders the httpx error or its request;
    ``__cause__`` alone is None with or without ``from None``.
    """
    import traceback

    assert error.__cause__ is None
    assert error.__suppress_context__ is True
    rendered = "".join(traceback.format_exception(error))
    assert "httpx" not in rendered and "During handling" not in rendered, rendered
    assert "sk-single-test" not in rendered


class TestAuthHeaderNotLeaked:
    """Authorization headers must never appear in exception messages or repr output."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_http_error_does_not_contain_api_key(self, client):
        """A 4xx/5xx response must not expose the API key in the exception message."""
        respx.get(f"{BASE}/ea/hosts").mock(
            return_value=Response(403, text='{"error": "forbidden"}')
        )
        with pytest.raises(UniFiHTTPError) as exc_info:
            await client.get("/ea/hosts")
        assert exc_info.value.status == 403
        assert "sk-single-test" not in str(exc_info.value)
        assert "Authorization" not in str(exc_info.value)

    @respx.mock
    @pytest.mark.asyncio
    async def test_http_error_does_not_contain_authorization_header(self, client):
        """Stringified exception must not include the Authorization header name/value."""
        respx.post(f"{BASE}/ea/networks").mock(return_value=Response(500, text="server error"))
        with pytest.raises(UniFiHTTPError) as exc_info:
            await client.post("/ea/networks", json={})
        assert exc_info.value.status == 500
        exc_str = str(exc_info.value)
        assert "sk-single-test" not in exc_str
        # The error message should contain useful context (status + path)
        assert "500" in exc_str

    def test_api_key_config_repr_redacts_key(self):
        """APIKeyConfig repr must not expose the raw key value."""
        cfg = APIKeyConfig(key="super-secret-key-abc123", label="prod")
        r = repr(cfg)
        assert "super-secret-key-abc123" not in r
        assert "***" in r
        assert "prod" in r

    def test_api_key_config_repr_org_key(self):
        cfg = APIKeyConfig(key="org-secret-key", label="org", is_org_key=True)
        r = repr(cfg)
        assert "org-secret-key" not in r
        assert "is_org_key=True" in r

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout_exception_chain_stripped(self, client):
        respx.get(f"{BASE}/ea/hosts").mock(side_effect=httpx.TimeoutException("timed out"))
        with pytest.raises(UniFiConnectionError) as exc_info:
            await client.get("/ea/hosts")
        _assert_transport_chain_hidden(exc_info.value)
        assert "sk-single-test" not in str(exc_info.value)
        assert "sk-single-test" not in repr(exc_info.value)

    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_error_chain_stripped(self, client):
        respx.get(f"{BASE}/ea/hosts").mock(side_effect=httpx.ConnectError("connection refused"))
        with pytest.raises(UniFiConnectionError) as exc_info:
            await client.get("/ea/hosts")
        _assert_transport_chain_hidden(exc_info.value)
        assert "sk-single-test" not in str(exc_info.value)
        assert "sk-single-test" not in repr(exc_info.value)

    @respx.mock
    @pytest.mark.asyncio
    async def test_network_error_chain_stripped(self, client):
        respx.get(f"{BASE}/ea/hosts").mock(side_effect=httpx.NetworkError("network failure"))
        with pytest.raises(UniFiConnectionError) as exc_info:
            await client.get("/ea/hosts")
        _assert_transport_chain_hidden(exc_info.value)
        assert "sk-single-test" not in str(exc_info.value)
        assert "sk-single-test" not in repr(exc_info.value)

    @respx.mock
    @pytest.mark.asyncio
    async def test_network_error_message_preserves_context(self, client):
        respx.get(f"{BASE}/ea/hosts").mock(side_effect=httpx.TimeoutException("timed out"))
        with pytest.raises(UniFiConnectionError) as exc_info:
            await client.get("/ea/hosts")
        msg = str(exc_info.value)
        assert "GET" in msg
        assert "/ea/hosts" in msg


class TestLifecycle:
    @respx.mock
    @pytest.mark.asyncio
    async def test_close_clears_clients(self, client):
        respx.get(f"{BASE}/ea/hosts").mock(return_value=Response(200, json={"data": []}))
        await client.get("/ea/hosts")
        assert len(client._clients) == 1
        await client.close()
        assert len(client._clients) == 0


class TestRouteSecretWiring:
    """Opt-in masking of text response bodies and dry-run request fields."""

    OVPN = "/network/v2/api/site/default/vpn/openvpn/0000000000000000000000aa/configuration"

    @respx.mock
    @pytest.mark.asyncio
    async def test_text_body_route_masked_under_opt_in(self):
        from unifi_fabric.redaction import REDACTION_MASK

        respx.get(f"{BASE}{self.OVPN}").mock(
            return_value=Response(200, text="client\n<key>SENTINEL-OVPN-KEY</key>")
        )
        on = UniFiClient(Settings(api_key="sk-single-test", redact_secrets=True))
        resp = await on.request("GET", self.OVPN)
        assert "SENTINEL-OVPN-KEY" not in resp.text
        assert REDACTION_MASK in resp.text

    @respx.mock
    @pytest.mark.asyncio
    async def test_text_body_route_verbatim_without_opt_in(self):
        respx.get(f"{BASE}{self.OVPN}").mock(
            return_value=Response(200, text="client\n<key>SENTINEL-OVPN-KEY</key>")
        )
        off = UniFiClient(Settings(api_key="sk-single-test"))
        resp = await off.request("GET", self.OVPN)
        assert "SENTINEL-OVPN-KEY" in resp.text

    @pytest.mark.asyncio
    async def test_dry_run_preview_masks_registered_request_fields(self, monkeypatch):
        monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
        path = "/network/v2/api/site/default/matter/nodes"
        body = {"setup_code": "SENTINEL-SETUP-CODE", "name": "visible"}
        on = UniFiClient(Settings(api_key="sk-t", redact_secrets=True))
        text = (await on.request("POST", path, json=body)).text
        assert "SENTINEL-SETUP-CODE" not in text and "visible" in text
        off = UniFiClient(Settings(api_key="sk-t"))
        assert "SENTINEL-SETUP-CODE" in (await off.request("POST", path, json=body)).text


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("only_mask", [False, True])
@respx.mock
async def test_write_mask_interpretation_requires_explicit_redaction(method, redact, only_mask):
    import json

    body = {"note": "***REDACTED***"}
    if not only_mask:
        body["enabled"] = True
    route = respx.route(method=method, url=f"{BASE}/v1/connector/consoles/H/proxy/network/x")
    route.mock(return_value=Response(200, json={"ok": True}))
    async_client = UniFiClient(Settings(api_key="synthetic-key", redact_secrets=redact))
    try:
        if redact and only_mask:
            with pytest.raises(ValueError, match="redaction mask"):
                await async_client.request(
                    method, "/v1/connector/consoles/H/proxy/network/x", json=body
                )
            assert not route.called
        else:
            await async_client.request(
                method, "/v1/connector/consoles/H/proxy/network/x", json=body
            )
            assert json.loads(route.calls[0].request.content) == (
                {"enabled": True} if redact else body
            )
    finally:
        await async_client.close()
