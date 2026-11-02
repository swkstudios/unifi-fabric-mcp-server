"""paginate_offset refuses a None page_size or offset as a pagination error.

validate_pagination reads None as "not given", so before the fix both values passed
validation and the drain crashed with a TypeError (``max(None, 0)`` and the page-size
comparison) instead of the registered logical-pagination-integer refusal.
"""

from __future__ import annotations

from typing import Any

import pytest

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.refusals import BY_ID


def _client(calls: list[dict[str, Any]]) -> UniFiClient:
    client = UniFiClient(Settings(api_key="k"))

    async def get(path, *, key=None, params=None):
        calls.append(dict(params or {}))
        return {"data": [], "totalCount": 0}

    client.get = get  # type: ignore[method-assign]
    return client


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"page_size": None}, "page_size must be a positive integer (1 or more); got None"),
        ({"params": {"offset": None}}, "offset must be 0 or more; got None"),
    ],
)
async def test_none_is_refused_before_any_request(kwargs, message):
    calls: list[dict[str, Any]] = []
    with pytest.raises(ValueError) as exc:
        await _client(calls).paginate_offset("/probe", **kwargs)
    assert str(exc.value).startswith(message)
    assert BY_ID["logical-pagination-integer"].matches(str(exc.value))
    assert calls == []


async def test_omitted_offset_still_starts_at_zero():
    calls: list[dict[str, Any]] = []
    assert list(await _client(calls).paginate_offset("/probe", params={})) == []
    assert calls == [{"offset": 0, "limit": 200}]
