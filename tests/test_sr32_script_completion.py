"""I/O completion, cancellation, and safety guards without elapsed-time deadlines."""

from __future__ import annotations

import asyncio
import importlib.util
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.transport_security import capped_jwks_client

ROOT = Path(__file__).resolve().parents[1]


def script(name, relative):
    sys.path.insert(0, str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def assert_no_deadline(request):
    assert request.extensions["timeout"] == {
        "connect": None,
        "read": None,
        "write": None,
        "pool": None,
    }


async def test_runtime_request_completion_and_lifecycle_cancellation(monkeypatch):
    entered = asyncio.Event()
    held = asyncio.Event()

    async def handle(request):
        assert_no_deadline(request)
        assert request.headers["x-api-key"] == "synthetic-key"
        entered.set()
        await held.wait()
        return httpx.Response(200, json={"data": []})

    original = httpx.AsyncClient
    transport = httpx.MockTransport(handle)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(transport=transport, **kw))
    client = UniFiClient(Settings(api_key="synthetic-key"))
    task = asyncio.create_task(client.get("/v1/hosts"))
    try:
        await entered.wait()
        assert not task.done()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await client.close()


async def test_jwks_client_has_no_hidden_httpx_deadlines():
    async def handle(request):
        assert_no_deadline(request)
        return httpx.Response(200, json={"keys": []})

    async with capped_jwks_client(httpx.MockTransport(handle)) as client:
        response = await client.get("https://issuer.example/jwks")
    assert response.json() == {"keys": []}


@pytest.mark.parametrize(
    ("relative", "function", "kwargs"),
    [
        ("scripts/check_spec_drift.py", "fetch_live_snapshot", {}),
        ("scripts/check_spec_drift.py", "fetch_pinned_schema_keywords", {"baseline": None}),
        (
            "scripts/check_catalog_regression.py",
            "fetch_deployed_catalog_names",
            {"endpoint": "https://gateway.example/mcp"},
        ),
        ("scripts/vendor_openapi_specs.py", "vendor", {}),
    ],
)
def test_script_clients_explicitly_disable_httpx_defaults(
    monkeypatch, tmp_path, relative, function, kwargs
):
    module = script("sr32_" + function, relative)
    if function == "vendor":
        monkeypatch.setattr(module, "VENDOR_DIR", tmp_path)

    class ObservedFactory(Exception):
        pass

    def factory(**options):
        assert options["timeout"] is None
        raise ObservedFactory

    monkeypatch.setattr(httpx, "Client", factory)
    with pytest.raises(ObservedFactory):
        getattr(module, function)(**kwargs)


def test_reference_network_failure_remains_a_failure_without_deadline():
    relative = Path("scripts") / ("check_reference" + "_drift.py")
    if not (ROOT / relative).is_file():
        pytest.skip("private reference checker is excluded from the public tree")
    module = script("sr32_reference", relative)
    fetcher = module.PublicFetcher()

    def opened(request, timeout):
        assert timeout is None
        raise module.urllib.error.URLError("connection refused")

    fetcher.opener = SimpleNamespace(open=opened)
    with pytest.raises(module.urllib.error.URLError):
        fetcher.get("https://developer.ui.com/network")


def test_doc_link_http_failure_preserves_classification(monkeypatch):
    module = script("sr32_links", "scripts/check_doc_links.py")

    def opened(request, timeout):
        assert timeout is None
        raise module.HTTPError(request.full_url, 404, "missing", {}, io.BytesIO())

    monkeypatch.setattr(module, "urlopen", opened)
    assert module.probe("https://docs.example/missing") == {
        "url": "https://docs.example/missing",
        "status": 404,
        "ok": False,
        "moved": False,
    }


def test_private_canary_waits_for_process_exit_and_sanitizes_failures(monkeypatch):
    relative = Path("scripts") / ("private" + "_api") / ("can" + "ary.py")
    if not (ROOT / relative).is_file():
        pytest.skip("private API canary is excluded from the public tree")
    module = script("sr32_canary", relative)

    def completed(command, **options):
        assert "timeout" not in options
        assert options["input"] and options["capture_output"]
        return SimpleNamespace(
            stdout='{"meta":"resolved","console_selected":true}\n',
            returncode=7,
            stderr="private remote diagnostics",
        )

    monkeypatch.setattr(module.subprocess, "run", completed)
    result = module.run({"probes": []}, remote_cmd="synthetic-remote", allow=frozenset())
    assert result["exit"] == 7 and result["stderr_bytes"] == len("private remote diagnostics")
    assert "private remote diagnostics" not in json.dumps(result)
    assert "request_timeout_seconds=" not in module.remote_source({"probes": []})
    compile(module.remote_source({"probes": []}), "remote-canary", "exec")


@pytest.mark.parametrize("collector", ["events", "device_changes"])
async def test_protect_poll_boundary_never_cancels_active_poll(monkeypatch, collector):
    from unifi_fabric.families.protect import protect

    entered = asyncio.Event()
    release = asyncio.Event()
    monkeypatch.setattr(protect, "_resolve", AsyncMock(return_value=(None, "host")))

    async def poll(*args, **kwargs):
        entered.set()
        await release.wait()
        if collector == "events":
            return {"items": [], "incomplete": False}
        return {}, [], {}, {}

    monkeypatch.setattr(
        protect, "collect_offset" if collector == "events" else "_poll_device_snapshot", poll
    )
    call = getattr(protect, "collect_protect_" + collector)
    task = asyncio.create_task(call(None, None, "host", poll_count=1))
    try:
        await entered.wait()
        assert not task.done()
        release.set()
        result = await task
        assert result["_polls"] == 1 and result["_poll_count"] == 1
        assert not result["_truncated"]
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
