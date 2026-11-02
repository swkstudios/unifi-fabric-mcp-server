"""Offset completion evidence avoids unnecessary terminal requests."""

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.tools._pagination import collect_offset


@pytest.mark.parametrize("helper", ["collect", "client"])
@pytest.mark.parametrize(
    "page",
    [
        {"data": [{"id": "only"}], "totalCount": 1},
        {"data": [{"id": "only"}], "limit": 200},
    ],
)
async def test_network_completion_requires_no_terminal_probe(helper, page):
    client = UniFiClient(Settings(api_key="synthetic-completion-test"))
    client.get = AsyncMock(return_value=page)
    path = "/v1/connector/consoles/synthetic/proxy/network/integration/v1/sites/site/networks"
    if helper == "collect":
        result = await collect_offset(client, path)
        assert result["items"] == [{"id": "only"}]
        assert not result["incomplete"]
    else:
        result = await client.paginate_offset(path)
        assert result == [{"id": "only"}]
    client.get.assert_awaited_once_with(path, key=None, params={"offset": 0, "limit": 200})


@pytest.mark.parametrize("helper", ["collect", "client"])
async def test_bare_page_without_total_or_size_echo_drains_until_empty(helper):
    client = UniFiClient(Settings(api_key="synthetic-completion-test"))
    client.get = AsyncMock(side_effect=[[{"id": "only"}], []])
    path = "/v1/connector/consoles/synthetic/proxy/network/integration/v1/sites/site/networks"
    if helper == "collect":
        result = await collect_offset(client, path)
        assert result["items"] == [{"id": "only"}]
        assert not result["incomplete"]
    else:
        result = await client.paginate_offset(path)
        assert result == [{"id": "only"}]
    assert client.get.await_count == 2
    assert client.get.await_args_list[0].kwargs["params"] == {"offset": 0, "limit": 200}
    assert client.get.await_args_list[1].kwargs["params"] == {"offset": 1, "limit": 200}


@pytest.mark.parametrize("helper", ["collect", "client"])
async def test_unreported_clamp_requires_empty_page(helper):
    client = UniFiClient(Settings(api_key="synthetic-completion-test"))

    async def fetch(path, *, key, params):
        offset = params["offset"]
        return {"data": list(range(offset, min(offset + 100, 300)))}

    client.get = AsyncMock(side_effect=fetch)
    path = "/synthetic"
    if helper == "collect":
        result = await collect_offset(client, path)
        assert result["items"] == list(range(300))
        assert not result["incomplete"]
    else:
        result = await client.paginate_offset(path)
        assert result == list(range(300))
    assert client.get.await_count == 4
