"""Helpers for Protect write-tool unit tests that mock ``UniFiClient``.

Every Protect write and action goes through ``client.request`` (via ``protect._post``
and ``protect._patch``, which decode the body with ``client.decode_body``), so the mocks
answer with real ``httpx.Response`` objects and the assertions check the request that
was sent.
"""

from __future__ import annotations

from typing import Any

import httpx

_UNSET: Any = object()


def resp(body: Any = _UNSET, *, status: int = 200, text: str | None = None) -> httpx.Response:
    """An upstream response: a JSON body, a text body, or (no body given) an empty 204."""
    if text is not None:
        return httpx.Response(status, text=text)
    if body is _UNSET:
        return httpx.Response(204)
    return httpx.Response(status, json=body)


def assert_write(
    client: Any,
    method: str,
    path: str,
    *,
    key: Any = None,
    json: Any = None,
    files: Any = None,
) -> None:
    """Assert exactly one write was sent, with this method, path, key and body.

    No tool passes a retry count: the client's one retry rule sends every non-GET once.
    """
    client.request.assert_called_once_with(method, path, key=key, json=json, files=files)
