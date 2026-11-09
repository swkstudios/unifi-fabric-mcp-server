"""A stalled JWKS download must not stop other authentications.

The JWKS client has no elapsed-time deadline, by design. FastMCP's verifier holds one
refresh lock for the whole download, so a download that never answers kept the lock and
every later authentication that needed a refresh waited behind it until a restart, even
after the identity provider recovered. These tests run the verifier against an identity
provider that accepts the connection and never answers (a loopback socket), and check
that a later refresh still runs and that no caller depends on another caller's download.

Progress is driven with ``asyncio.sleep(0)`` turns, never a clock: the answering
downloads are in-memory, so a bounded number of turns finishes them.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx2
import pytest

from tests.test_transport_security import _AUDIENCE, _ISSUER, _jwks, _jwt

# Event-loop turns given to work that does no network I/O (a mock answer plus one RSA key).
_TURNS = 2000


async def _turns_until(task: asyncio.Future[Any]) -> bool:
    for _ in range(_TURNS):
        if task.done():
            return True
        await asyncio.sleep(0)
    return task.done()


class _StalledIdP:
    """A loopback HTTP server that reads each request and never answers it."""

    def __init__(self) -> None:
        self.received = asyncio.Event()
        self.closed = asyncio.Event()
        self._server: asyncio.Server | None = None
        self._writers: list[asyncio.StreamWriter] = []

    async def __aenter__(self) -> _StalledIdP:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self

    @property
    def url(self) -> str:
        assert self._server is not None
        host, port = self._server.sockets[0].getsockname()[:2]
        return f"http://{host}:{port}/jwks"

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.append(writer)
        await reader.readuntil(b"\r\n\r\n")
        self.received.set()
        await reader.read()  # never answer; returns when the client closes the socket
        self.closed.set()

    async def __aexit__(self, *exc: object) -> None:
        for writer in self._writers:
            writer.close()
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()


class _Routed(httpx2.AsyncBaseTransport):
    """The first download goes to ``first`` (the stalled socket); later ones are answered."""

    def __init__(self, first: httpx2.AsyncBaseTransport, answer: httpx2.AsyncBaseTransport):
        self._first, self._answer, self.calls = first, answer, 0

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        self.calls += 1
        inner = self._first if self.calls == 1 else self._answer
        return await inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._first.aclose()


def _answering() -> httpx2.MockTransport:
    return httpx2.MockTransport(lambda request: httpx2.Response(200, json=_jwks()))


def _verifier(uri: str, transport: httpx2.AsyncBaseTransport, *, interval: float):
    from unifi_fabric.transport_security import StrictJWTVerifier, capped_jwks_client

    return StrictJWTVerifier(
        jwks_uri=uri,
        issuer=_ISSUER,
        audience=_AUDIENCE,
        http_client=capped_jwks_client(transport),
        jwks_refresh_interval=interval,
    )


@pytest.fixture
async def tasks() -> AsyncIterator[list[asyncio.Task[Any]]]:
    started: list[asyncio.Task[Any]] = []
    yield started
    for task in started:
        task.cancel()
    await asyncio.gather(*started, return_exceptions=True)


async def test_a_stalled_download_does_not_block_a_later_refresh(tasks):
    """The IdP stalls the first download and then recovers: the next authentication
    refreshes from it and verifies, and the caller stuck on the stalled download is
    answered from that refresh too. The stalled connection is then closed."""
    async with _StalledIdP() as idp:
        transport = _Routed(httpx2.AsyncHTTPTransport(), _answering())
        verifier = _verifier(idp.url, transport, interval=0)
        first = asyncio.create_task(verifier.verify_token(_jwt()))
        tasks.append(first)
        await idp.received.wait()

        second = asyncio.create_task(verifier.verify_token(_jwt()))
        tasks.append(second)
        assert await _turns_until(second), "a later refresh waited behind the stalled download"
        assert second.result() is not None
        assert await _turns_until(first)
        assert first.result() is not None
        await idp.closed.wait()
        assert transport.calls == 2


async def test_a_cancelled_caller_leaves_the_download_to_the_others(tasks):
    """The caller that started a download goes away; the download carries on and the
    caller waiting on it (inside the refresh interval, so no new download) is answered."""
    release = asyncio.Event()
    calls = 0

    async def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        await release.wait()
        return httpx2.Response(200, content=json.dumps(_jwks()).encode())

    verifier = _verifier("https://idp.test/jwks", httpx2.MockTransport(handler), interval=3600)
    first = asyncio.create_task(verifier.verify_token(_jwt()))
    tasks.append(first)
    while calls == 0:
        await asyncio.sleep(0)
    second = asyncio.create_task(verifier.verify_token(_jwt()))
    tasks.append(second)
    await asyncio.sleep(0)
    first.cancel()
    await asyncio.gather(first, return_exceptions=True)

    release.set()
    assert await _turns_until(second)
    assert second.result() is not None
    assert calls == 1


async def test_a_failed_download_still_honours_the_refresh_interval():
    """Unchanged behaviour: a failed download is a rejection, and an immediate retry
    inside the refresh interval is rejected without another download."""
    calls = 0

    def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal calls
        calls += 1
        raise httpx2.ConnectError("refused", request=request)

    verifier = _verifier("https://idp.test/jwks", httpx2.MockTransport(handler), interval=3600)
    assert await verifier.verify_token(_jwt()) is None
    assert await verifier.verify_token(_jwt()) is None
    assert calls == 1


async def test_pending_downloads_are_bounded_and_all_callers_answered(tasks):
    """While the IdP stalls, each refresh interval may start a new download, but no more
    than JWKS_MAX_PENDING_DOWNLOADS stay open; the oldest is closed to make room. When
    the IdP answers, every waiting caller is answered."""
    from unifi_fabric.transport_security import JWKS_MAX_PENDING_DOWNLOADS

    release = asyncio.Event()
    started = 0
    open_now = 0
    most_open = 0

    async def handler(request: httpx2.Request) -> httpx2.Response:
        nonlocal started, open_now, most_open
        started += 1
        open_now += 1
        most_open = max(most_open, open_now)
        try:
            await release.wait()
        finally:
            open_now -= 1
        return httpx2.Response(200, json=_jwks())

    verifier = _verifier("https://idp.test/jwks", httpx2.MockTransport(handler), interval=0)
    callers = JWKS_MAX_PENDING_DOWNLOADS + 3
    for n in range(1, callers + 1):
        tasks.append(asyncio.create_task(verifier.verify_token(_jwt())))
        while started < n:
            await asyncio.sleep(0)
    assert most_open == JWKS_MAX_PENDING_DOWNLOADS

    release.set()
    everyone = asyncio.gather(*tasks)
    assert await _turns_until(everyone)
    assert all(result is not None for result in everyone.result())
    assert open_now == 0


async def test_a_sibling_cancelled_before_it_starts_leaves_no_download_in_flight(
    tasks, monkeypatch
):
    """A download answers in the same event-loop turn that another caller starts the next
    one: the winner cancels that sibling before its body ever runs, so the sibling cannot
    remove itself. It must still leave the in-flight list, or a caller FastMCP refuses
    inside the refresh interval (an unknown ``kid``) waits on a round no download will
    settle, where it should get its 401 straight away."""
    from fastmcp.server.auth.providers.jwt import JWTVerifier
    from joserfc import jwt

    from tests.test_transport_security import _KEY

    release = asyncio.Event()
    calls = 0
    verifier = _verifier("https://idp.test/jwks", _answering(), interval=3600)

    async def fetch(self: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        await release.wait()
        # A new caller starts the next download in this same turn; it has not run yet
        # when this download returns and cancels it.
        verifier._start_jwks_download()
        return _jwks()

    monkeypatch.setattr(JWTVerifier, "_fetch_jwks", fetch)
    first = asyncio.create_task(verifier.verify_token(_jwt()))
    tasks.append(first)
    while calls == 0:
        await asyncio.sleep(0)
    release.set()
    assert await _turns_until(first)
    assert first.result() is not None
    assert calls == 1
    assert verifier._jwks_downloads == []

    claims = json.loads(json.dumps(jwt.decode(_jwt(), _KEY).claims))
    unknown = jwt.encode({"alg": "RS256", "kid": "k2"}, claims, _KEY)
    refused = asyncio.create_task(verifier.verify_token(unknown))
    tasks.append(refused)
    assert await _turns_until(refused), "an unknown kid waited on a download not in flight"
    assert refused.result() is None
    assert calls == 1
