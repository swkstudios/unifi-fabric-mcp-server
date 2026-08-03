"""Shared pytest fixtures for the auth / transport / TLS matrix test suite.

Re-exports the Phase 1 streamable-http auth harness so any test module can request
``auth_http_client`` as a fixture without importing it directly. Phase 1
(``test_auth_http.py``) deliberately built that factory as "the reusable substrate
later phases extend"; surfacing it through ``conftest`` is how pytest shares a fixture
across modules cleanly (a direct import would shadow the parameter name and trip F811).

The fixture itself still lives in ``test_auth_http.py`` next to the bearer tests that
first introduced it; this module only makes it importable suite-wide.

Multi-key MSP substrate
-----------------------
``multikey_client`` / ``multikey_registry`` model the production reality that a single
server instance is configured with *several* API keys (200+ sites across multiple keys).
They are the shared substrate for every multi-key test: with a single configured key
``UniFiClient._default_key()`` always returns the correct key, so ``request(key=None)``
and ``request(key=<correct>)`` are indistinguishable and the multi-key routing bug class
is *structurally unrepresentable*. Two keys owning **disjoint** host sets
(``MULTIKEY_HOSTS_BY_LABEL``) make wrong-key routing produce a visibly wrong result, so a
test can actually fail when a request rides the wrong key.
"""

from __future__ import annotations

import os
import sys

import pytest

from tests.test_auth_http import auth_http_client  # noqa: F401 -- re-exported as a shared fixture
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.registry import Registry


@pytest.fixture(autouse=True)
def _hermetic_credentials_env(request, monkeypatch):
    """Unit tests MUST be hermetic — never read a live credential from the ambient env.

    A real ``UNIFI_API_KEY`` / ``UNIFI_API_KEYS`` / ``MCP_BEARER_TOKEN`` in the process
    environment is otherwise silently pulled into ``Settings()`` / ``MCPTransportSettings()``
    (init kwargs do NOT stop pydantic-settings from populating *unset* fields like ``api_keys``
    from the environment). On an assertion failure the value is then printed to the log — which
    is exactly how a live key once leaked to disk (SR-8). Stripping the credential/config
    namespaces before every unit test makes it impossible for a unit test to read them,
    regardless of how or where the suite is invoked.

    Integration tests (``@pytest.mark.integration``) are the deliberate exception: they exist to
    talk to a live console and must keep the real environment intact.
    """
    if request.node.get_closest_marker("integration"):
        return
    for var in list(os.environ):
        if var.startswith(("UNIFI_", "MCP_", "FASTMCP_")):
            monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _reset_server_singletons():
    """Reset ``server.py`` module-level singletons after every test.

    ``get_settings()`` caches a process-wide ``Settings`` in ``server._settings``
    (lazy, so importing the module never reads the environment). Because that cache
    is global, a test that triggers construction — via ``lifespan`` or a direct
    ``get_settings`` call — would otherwise leak its Settings/client/registry into
    later tests. Clearing them on teardown keeps the lazy cache from breaking the
    hermetic guarantee. No-op when the server module was never imported.
    """
    yield
    mod = sys.modules.get("unifi_fabric.server")
    if mod is not None:
        mod._settings = None
        mod._client = None
        mod._registry = None


# Two API keys owning DISJOINT host sets. "alpha" is a personal key (first/default),
# "beta" is an organization key that owns a NON-FIRST host — the case a single-key
# fixture can never exercise. Host ids/hostnames/names are all synthetic.
MULTIKEY_HOSTS_BY_LABEL: dict[str, list[dict]] = {
    "alpha": [
        {
            "id": "console-alpha-1",
            "name": "Alpha-HQ",
            "reportedState": {"hostname": "alpha-hq.example"},
        }
    ],
    "beta": [
        {
            "id": "console-beta-1",
            "name": "Beta-Branch",
            "reportedState": {"hostname": "beta-branch.example"},
        }
    ],
}


@pytest.fixture
def multikey_client() -> UniFiClient:
    """Real ``UniFiClient`` configured with two distinct keys; HTTP layer mocked per test.

    ``alpha`` is a personal key (the first/default key); ``beta`` is an organization key
    that owns a non-first host. The keys and labels are distinct so a request that rides
    the wrong key is observable.
    """
    settings = Settings(
        api_keys=[
            APIKeyConfig(key="k-alpha", label="alpha", is_org_key=False),
            APIKeyConfig(key="k-beta", label="beta", is_org_key=True),
        ]
    )
    return UniFiClient(settings)


@pytest.fixture
def multikey_registry(multikey_client: UniFiClient) -> Registry:
    """Registry bound to the two-key ``multikey_client``."""
    return Registry(multikey_client, ttl_seconds=900)
