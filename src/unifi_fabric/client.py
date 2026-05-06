"""Async HTTP client for UniFi Site Manager API with backoff, pagination, and multi-key support."""

from __future__ import annotations

import asyncio
import json
import random
import re
from typing import Any, cast

import httpx

from .config import APIKeyConfig, Settings

_secure_random = random.SystemRandom()


class UniFiConnectionError(Exception):
    """Raised when a network-level error prevents reaching the UniFi API."""


class RateLimitError(Exception):
    """Raised when rate limit is exceeded after all retries."""


_ID_SAFE_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
_HOST_ID_SAFE_RE = re.compile(r"^[a-zA-Z0-9_:-]+$")
_UNSAFE_PATH_RE = re.compile(r"\.\.|[\x00\r\n]")
_CONSOLE_ID_RE = re.compile(r"[A-Fa-f0-9]{12,}(?::[0-9]+)?")
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_OBJECTID_RE = re.compile(r"[0-9a-f]{24}")


def _sanitize_path(path: str) -> str:
    path = _UUID_RE.sub("[REDACTED]", path)
    path = _CONSOLE_ID_RE.sub("[REDACTED]", path)
    return path


def _sanitize_body(body: str) -> str:
    body = _UUID_RE.sub("[REDACTED]", body)
    body = _OBJECTID_RE.sub("[REDACTED]", body)
    body = _CONSOLE_ID_RE.sub("[REDACTED]", body)
    return body


def validate_id(value: str, name: str) -> None:
    """Validate an ID string is safe for use in an API URL path segment.

    Accepts alphanumeric characters, hyphens, and underscores only.
    Raises ValueError if the value is empty or contains characters that could
    enable path traversal or injection attacks.
    """
    if not value:
        raise ValueError(f"{name!r} must not be empty")
    if not _ID_SAFE_RE.match(value):
        raise ValueError(
            f"Invalid {name!r} {value!r}: expected alphanumeric, hyphens, and underscores only"
        )


def validate_host_id(value: str, name: str) -> None:
    """Validate a host ID string is safe for use in an API URL path segment.

    Extends validate_id to also allow colons, which appear in UniFi composite
    hostId values of the form ``{MAC}:{numericId}`` (e.g. ``aabbccdd...0000:12345``).
    The colon character is safe in URL path segments — only disallowed in the
    scheme portion of a URL.
    Raises ValueError if the value is empty or contains characters that could
    enable path traversal or injection attacks.
    """
    if not value:
        raise ValueError(f"{name!r} must not be empty")
    if _UNSAFE_PATH_RE.search(value):
        raise ValueError(f"Invalid {name!r} {value!r}: contains unsafe characters")
    if not _HOST_ID_SAFE_RE.match(value):
        raise ValueError(
            f"Invalid {name!r} {value!r}: expected alphanumeric, hyphens, underscores, and colons"
        )


class PaginationAbortedError(Exception):
    """Raised when pagination is aborted due to stall detection or page cap.

    Attributes:
        path: The API path being paginated.
        page_count: Number of pages fetched before abort.
        reason: Human-readable reason for the abort.
    """

    def __init__(self, path: str, page_count: int, reason: str) -> None:
        self.path = path
        self.page_count = page_count
        self.reason = reason
        super().__init__(f"Pagination aborted on {path!r} after {page_count} pages: {reason}")


class UniFiClient:
    """Async HTTP client wrapping httpx with backoff, pagination, and multi-key support."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._semaphore = asyncio.Semaphore(settings.max_concurrency)

    async def _get_client(self, key_config: APIKeyConfig) -> httpx.AsyncClient:
        if key_config.label not in self._clients:
            self._clients[key_config.label] = httpx.AsyncClient(
                base_url=self._settings.api_base_url,
                headers={
                    "X-API-KEY": key_config.key,
                    "Accept": "application/json",
                },
                timeout=float(self._settings.request_timeout_seconds),
            )
        return self._clients[key_config.label]

    def get_key_by_label(self, label: str) -> APIKeyConfig:
        """Look up an API key config by its label."""
        for cfg in self._settings.get_key_configs():
            if cfg.label == label:
                return cfg
        raise KeyError(f"No API key with label {label!r}")

    def list_key_labels(self) -> list[str]:
        """Return the labels of all configured API keys."""
        return [cfg.label for cfg in self._settings.get_key_configs()]

    def _default_key(self) -> APIKeyConfig:
        configs = self._settings.get_key_configs()
        if not configs:
            raise ValueError("No API key configured. Set UNIFI_API_KEY or UNIFI_API_KEYS.")
        return configs[0]

    async def request(
        self,
        method: str,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        max_retries: int = 5,
    ) -> httpx.Response:
        """Make an HTTP request with exponential backoff + jitter on rate limits.

        Automatically retries HTTP 429 (Too Many Requests) responses using exponential
        backoff with jitter to avoid thundering herd problems. Network errors
        (timeouts, connection failures) raise immediately without retry.

        Args:
            method: HTTP method (GET, POST, PATCH, DELETE, etc.)
            path: API path (without base URL; e.g., "/v1/sites")
            key: API key config to use; defaults to the configured key
            params: Query string parameters
            json: JSON request body
            files: Form files for multipart uploads
            max_retries: Maximum number of retry attempts (default: 5, total 6 attempts)

        Returns:
            httpx.Response with HTTP status 2xx or 3xx (or 4xx/5xx non-rate-limit errors)

        Raises:
            UniFiConnectionError: Network error (timeout, connection, DNS), or HTTP error
                with body (400, 401, 403, 404, 500, etc.). Non-retryable.
            RateLimitError: HTTP 429 persists after max_retries attempts.
            ValueError: Invalid/unsafe API path (path traversal attempt).

        Retry Strategy (429 only):
            - Attempt 1: immediate
            - Attempt 2: wait 1 + jitter(0-1) seconds
            - Attempt 3: wait 2 + jitter(0-2) seconds
            - Attempt 4: wait 4 + jitter(0-4) seconds
            - Attempt 5: wait 8 + jitter(0-8) seconds
            - Attempt 6: wait 16 + jitter(0-16) seconds
            - Attempt 7: wait 32 + jitter(0-32) seconds (if max_retries > 5)
            - Capped at 32 seconds base delay

            Jitter is random uniform(0, base_delay) to spread load.
        """
        if _UNSAFE_PATH_RE.search(path):
            raise ValueError(
                f"Unsafe API path {path!r}: contains traversal sequences or control characters"
            )
        key = key or self._default_key()
        client = await self._get_client(key)

        for attempt in range(max_retries + 1):
            try:
                async with self._semaphore:
                    resp = await client.request(method, path, params=params, json=json, files=files)
            except httpx.TimeoutException:
                safe = _sanitize_path(path)
                raise UniFiConnectionError(f"Request timed out: {method} {safe}") from None
            except httpx.ConnectError:
                safe = _sanitize_path(path)
                raise UniFiConnectionError(f"Connection failed: {method} {safe}") from None
            except httpx.NetworkError:
                safe = _sanitize_path(path)
                raise UniFiConnectionError(f"Network error: {method} {safe}") from None

            if resp.status_code != 429:
                if resp.is_error:
                    body = resp.text[:500]
                    # Raise UniFiConnectionError (not httpx.HTTPStatusError) so that
                    # the request object — which contains the Authorization header —
                    # is never embedded in the exception and cannot leak into logs.
                    raise UniFiConnectionError(
                        f"HTTP {resp.status_code} from {method} {_sanitize_path(path)}: "
                        f"{_sanitize_body(body)}"
                    )
                return resp

            if attempt == max_retries:
                raise RateLimitError(
                    f"Rate limited after {max_retries + 1} attempts on {method} {path}"
                )

            base_delay = min(2**attempt, 32)
            jitter = _secure_random.uniform(0, base_delay)
            await asyncio.sleep(base_delay + jitter)

        raise RateLimitError("Unreachable")  # pragma: no cover

    def _decode_json(self, resp: httpx.Response) -> dict[str, Any]:
        """Decode JSON from response, raising UniFiConnectionError on parse failure."""
        try:
            return cast(dict[str, Any], resp.json())
        except json.JSONDecodeError as exc:
            raise UniFiConnectionError(
                f"Non-JSON response (HTTP {resp.status_code}) from {resp.url}: {resp.text[:200]!r}"
            ) from exc

    async def get(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """GET request, return JSON body."""
        resp = await self.request("GET", path, key=key, params=params)
        return self._decode_json(resp)

    async def get_bytes(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        params: dict[str, Any] | None = None,
    ) -> bytes:
        """GET request, return raw response bytes (for binary responses such as images)."""
        resp = await self.request("GET", path, key=key, params=params)
        return resp.content

    async def post(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """POST request, return JSON body."""
        resp = await self.request("POST", path, key=key, json=json, params=params)
        return self._decode_json(resp)

    async def post_multipart(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        files: dict[str, Any],
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """POST multipart/form-data request, return JSON body."""
        resp = await self.request("POST", path, key=key, files=files, params=params)
        return self._decode_json(resp)

    async def put(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """PUT request, return JSON body."""
        resp = await self.request("PUT", path, key=key, json=json, params=params)
        return self._decode_json(resp)

    async def patch(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """PATCH request, return JSON body."""
        resp = await self.request("PATCH", path, key=key, json=json, params=params)
        return self._decode_json(resp)

    async def delete(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> None:
        """DELETE request, no body returned."""
        await self.request("DELETE", path, key=key, json=json, params=params)

    async def paginate(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        params: dict[str, Any] | None = None,
        page_size: int = 200,
    ) -> list[dict[str, Any]]:
        """Auto-paginate a list endpoint using nextToken cursor.

        Two-layer runaway-loop defense:
        1. Stall detection (primary): if the same nextToken is returned twice in a
           row, the API is looping — raises PaginationAbortedError immediately.
        2. Absolute page cap (backstop): if UNIFI_PAGINATE_MAX_PAGES is set and the
           page count reaches it, raises PaginationAbortedError.
        """
        all_items: list[dict[str, Any]] = []
        req_params = dict(params or {})
        req_params.setdefault("limit", page_size)
        max_pages = self._settings.paginate_max_pages
        prev_token: str | None = None
        page_count = 0

        while True:
            data = await self.get(path, key=key, params=req_params)
            page_count += 1

            items = data.get("data", [])
            all_items.extend(items)

            next_token = data.get("nextToken")
            if not next_token:
                break

            if next_token == prev_token:
                raise PaginationAbortedError(
                    path,
                    page_count,
                    f"stall detected — nextToken {next_token!r} repeated",
                )

            if max_pages is not None and page_count >= max_pages:
                raise PaginationAbortedError(
                    path,
                    page_count,
                    f"page cap of {max_pages} reached",
                )

            prev_token = next_token
            req_params["nextToken"] = next_token

        return all_items

    async def gather(
        self,
        coros: list[Any],
    ) -> list[Any]:
        """Run coroutines concurrently, bounded by the client semaphore.

        Wraps asyncio.gather with the configured semaphore (default 10) so
        cross-site aggregation doesn't overwhelm the API.
        """

        async def _bounded(coro: Any) -> Any:
            async with self._semaphore:
                return await coro

        return list(await asyncio.gather(*[_bounded(c) for c in coros]))

    async def close(self) -> None:
        """Close all HTTP clients."""
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()
