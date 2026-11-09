"""The route detector never sends writes and identifies the connector refusal."""

import asyncio
import importlib.util
from pathlib import Path

import httpx
import pytest

spec = importlib.util.spec_from_file_location(
    "route_audit", Path(__file__).resolve().parents[1] / "scripts/route_audit.py"
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

BASELINE = {
    "baseline": dict.fromkeys(
        ("integration", "internal", "site-manager", "local-only"), "AVAILABLE"
    ),
    "tools": {
        **{
            name: [
                {
                    "method": "GET",
                    "path": path.replace("{host_id}", "{console_id}"),
                    "route_class": kind,
                }
            ]
            for kind, (name, _, path) in audit.CANARIES.items()
        },
        "list_configured_api_keys": [{"method": None, "path": None, "route_class": "local-only"}],
    },
}


def test_signature_requires_exact_status_and_body():
    signature = audit.CONNECTOR_REFUSAL_SIGNATURE
    assert audit.verdict(403, signature) == "REFUSED"
    assert audit.verdict(401, signature) == "ERROR"
    assert audit.verdict(403, "different refusal") == "ERROR"
    assert audit.verdict(200, signature) == "AVAILABLE"


@pytest.mark.parametrize("refused", [False, True])
def test_canaries_are_get_only_and_refusal_fails(monkeypatch, refused):
    requests = []

    def handle(request):
        requests.append(request)
        is_internal = "/proxy/innerspace/" in request.url.path
        if refused and is_internal:
            return httpx.Response(403, text=audit.CONNECTOR_REFUSAL_SIGNATURE)
        return httpx.Response(200, json={})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        audit.httpx,
        "AsyncClient",
        lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw),
    )
    settings = audit.Settings(api_key="test-key", api_base_url="https://example.invalid")
    rows, code = asyncio.run(audit.audit("aa:bb:cc:dd:ee:ff:123456", settings, BASELINE))
    assert [row["class"] for row in rows] == [
        "integration",
        "internal",
        "site-manager",
        "local-only",
    ]
    assert [row["verdict"] for row in rows] == [
        "AVAILABLE",
        "REFUSED" if refused else "AVAILABLE",
        "AVAILABLE",
        "AVAILABLE",
    ]
    assert rows[-1]["status"] is None
    assert code == int(refused)
    assert len(requests) == 3
    assert all(request.method == "GET" for request in requests)
    assert all(
        request.extensions["timeout"] == dict.fromkeys(("connect", "read", "write", "pool"))
        for request in requests
    )


def test_get_guard_refuses_other_paths():
    class NoNetwork:
        async def get(self, *args, **kwargs):
            raise AssertionError("request escaped guard")

    client = audit.GetOnlyClient(NoNetwork(), "/allowed")
    with pytest.raises(ValueError):
        asyncio.run(client.get("/other"))


@pytest.mark.parametrize("host_id", [".", "..", "a/b", "a%2fb", "a?b", "a#b", ""])
def test_invalid_host_ids_never_send_requests(host_id):
    settings = audit.Settings(api_key="test-key", api_base_url="https://example.invalid")
    with pytest.raises(ValueError):
        asyncio.run(audit.audit(host_id, settings, BASELINE))
