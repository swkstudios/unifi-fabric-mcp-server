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

import copy
import json
import os
import subprocess
import sys
import weakref
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastmcp.utilities.logging import configure_logging

from tests import upstream_harness as uh
from tests.test_auth_http import auth_http_client  # noqa: F401 -- re-exported as a shared fixture
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.registry import Registry

pytest_plugins = [
    "tests._global_state_guard",
    "tests._worker_diagnostics",
    "tests._report_retention",
    "tests._server_import_isolation",
    "tests._sharding",
]

# Tests that run repository scripts which call ``ruff format`` call the tools installed
# beside this interpreter by name. CI installs them on PATH; a venv run
# (``.venv/bin/python -m pytest``, or scripts/prepush.sh with PREPUSH_PYTHON) does not
# activate the venv, so its bin directory goes first on PATH, as activation would put it.
_INTERPRETER_BIN = str(Path(sys.executable).parent)
if _INTERPRETER_BIN not in os.environ.get("PATH", "").split(os.pathsep):
    os.environ["PATH"] = os.pathsep.join(
        part for part in (_INTERPRETER_BIN, os.environ.get("PATH", "")) if part
    )

# Synthetic upstream probes deliberately exercise many errors. Rendering their
# tracebacks through Rich/Pygments dominates those tests; retain ordinary exception
# logging and pytest's failure tracebacks. Explicit Rich scrubber tests opt in on
# their own logger. Configure the existing handler too (FastMCP configures at import).
configure_logging(enable_rich_tracebacks=False)


@pytest.fixture(scope="session", autouse=True)
def _warm_tool_catalog() -> None:
    """Resolve the lazy async catalog before any test starts its event loop."""
    from tests._tool_catalog import tools

    tools()


@pytest.fixture(scope="module")
def large_body_cache() -> Iterator[None]:
    """Reuse the latest immutable big responses without retaining every route."""
    cached_items: dict[tuple[str, int], list[dict[str, Any]]] = {}
    cached_resolutions: dict[tuple[str, str], Any] = {}
    original_items = uh.FakeUpstream._items
    original_resolution = uh.FakeUpstream._big_resolution

    def items(self: uh.FakeUpstream, path: str, count: int) -> list[dict[str, Any]]:
        if self.mode != "big":
            return original_items(self, path, count)
        key = (path, count)
        if key not in cached_items:
            # Tool batches revisit a route, but the entire module visits hundreds.
            # Keep reuse local instead of retaining all large fixture bodies.
            cached_items.clear()
            cached_items[key] = original_items(self, path, count)
        return copy.deepcopy(cached_items[key])

    def resolution(self: uh.FakeUpstream, path: str, body: Any) -> Any:
        key = (path, json.dumps(body, sort_keys=True, default=str))
        if key not in cached_resolutions:
            cached_resolutions.clear()
            cached_resolutions[key] = original_resolution(self, path, body)
        return copy.deepcopy(cached_resolutions[key])

    uh.FakeUpstream._items = items
    uh.FakeUpstream._big_resolution = resolution
    try:
        yield
    finally:
        uh.FakeUpstream._items = original_items
        uh.FakeUpstream._big_resolution = original_resolution


@pytest.fixture(autouse=True)
def _hermetic_credentials_env(request, monkeypatch):
    """Unit tests MUST be hermetic — never read a live credential from the ambient env.

    A real ``UNIFI_API_KEY`` / ``UNIFI_API_KEYS`` / ``MCP_BEARER_TOKEN`` in the process
    environment is otherwise silently pulled into ``Settings()`` / ``MCPTransportSettings()``
    (init kwargs do NOT stop pydantic-settings from populating *unset* fields like ``api_keys``
    from the environment). On an assertion failure the value is then printed to the log — which
    is exactly how a live key once leaked to disk (a previously documented failure mode).
    Stripping the credential/config
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
def _reset_credential_providers():
    """Forget keys resolved from a key file or helper command: they are per process
    (resolved once at startup), so every test starts with none."""
    from unifi_fabric import credential_providers

    credential_providers.reset()
    yield
    credential_providers.reset()


@pytest.fixture(autouse=True)
def _forget_test_settings_holders():
    """Stop scrubbing log records of the keys of clients a test created, once it ends.

    Every ``UniFiClient`` registers itself in the process-wide
    ``secret_scrub._live_settings_holders`` WeakSet, and log free text is scrubbed of the
    keys of every client still alive there (``scrub_log_text`` masks a secret embedded in
    a larger word, by design). A client a test leaves behind as cyclic garbage stays
    registered until the garbage collector happens to run, so the one-letter key of a
    ``Settings(api_key="k")`` client masked the ``k`` of ``key`` in a later test's log
    message on one xdist worker and not on another. Holders registered before the test
    starts (session- or module-scoped clients) are kept.
    """
    from unifi_fabric import secret_scrub

    before = weakref.WeakSet(secret_scrub._live_settings_holders)
    yield
    for holder in list(secret_scrub._live_settings_holders):
        if holder not in before:
            secret_scrub._live_settings_holders.discard(holder)


@pytest.fixture(autouse=True)
def _reset_policy_state():
    """Forget the startup policy, exclusions and catalog a test's server lifespan installed.

    ``policy.current()`` fails closed to the startup exposure when one is recorded, so a
    lifespan run by one test must not change what a later test's fail-closed policy is.
    """
    yield
    from unifi_fabric import policy

    policy.clear_exposure()


@pytest.fixture(autouse=True)
def _reset_server_singletons(_hermetic_credentials_env, monkeypatch):
    """Keep import-time transport/auth construction local to the test that reloads it.

    Bearer, auth HTTP, transport-security and FastMCP adoption tests reload server
    under temporary environment values. Clearing only the lazy Settings/client/
    registry leaves the rebuilt MCP auth provider and transport config behind.
    Restore the entire module namespace together: reload redefines middleware
    classes and handler functions as well as mcp. Restoring only mcp would pair
    old middleware instances with new class identities. Re-imports must also
    restore external callbacks and the original module in both Python import
    bindings so collected references and subsequent imports share one namespace.
    """
    import unifi_fabric
    from unifi_fabric import header_credentials, policy, secret_scrub, server

    record_listener = policy._record_listener
    secret_provider = secret_scrub._provider
    process_key_mode = header_credentials._header_mode_process
    import_state = vars(server).copy()
    for name in ("_settings", "_client", "_registry"):
        setattr(server, name, None)
    yield
    # Undo test patches first, otherwise their finalizers can resurrect a dirty
    # binding after this fixture resets it. This also rolls back temporary env.
    monkeypatch.undo()
    header_credentials._header_mode_process = process_key_mode
    vars(server).clear()
    vars(server).update(import_state)
    sys.modules[server.__name__] = server
    unifi_fabric.server = server
    policy.set_record_listener(record_listener)
    secret_scrub.set_secret_provider(secret_provider)
    for name in ("_settings", "_client", "_registry"):
        setattr(server, name, None)


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


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "lazy_parametrize(argnames, thunk, **kw): parametrize with values computed by "
        "thunk() at generate time (tests/_tool_catalog.lazy_parametrize).",
    )
    config.addinivalue_line(
        "markers",
        "tool_where(predicate): restrict the ``tool`` argument's catalog parametrization "
        "to tools for which predicate(tool) is true.",
    )


@pytest.hookimpl(tryfirst=True)
def pytest_sessionstart(session):
    # Hypothesis builds its UTF-8 codec table by enumerating every Unicode
    # code point. On a cold cache this briefly costs ~200 MiB per worker. Build
    # it once before local xdist workers start, in a short-lived process, so the
    # allocations do not persist in the controller. Hypothesis retains its own
    # fallback if its cache is unavailable (e.g. on remote workers).
    config = session.config
    if hasattr(config, "workerinput") or not config.getoption("numprocesses", default=0):
        return
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from hypothesis.internal.charmap import "
            "charmap_file, intervals_from_codec; intervals_from_codec(sys.argv[1]); "
            'print("Hypothesis UTF-8 cache unavailable; workers will build it locally", '
            "file=sys.stderr) if not charmap_file(sys.argv[2]).is_file() else None",
            "utf-8",
            "codec-v2-utf-8",
        ],
        check=True,
    )


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    """Refuse an unauthorized live mutation before any of the item's fixtures run.

    Every ``@pytest.mark.mutating`` test in every module passes this one gate
    (``tests/_live_gates.py``); a class- or module-scoped fixture that creates live state
    is never set up for a refused item.
    """
    from tests import _live_gates

    _live_gates.authorize_live_mutation(item)


def pytest_collection_finish(session):
    # Persist behaviour-derived selections for the next pytest process (xdist workers,
    # later steps and shards) and release the producer lock (tests/_selection_cache).
    from tests import _selection_cache

    _selection_cache.flush()


def pytest_unconfigure(config):
    from tests import _selection_cache

    _selection_cache.flush()


def pytest_generate_tests(metafunc):
    """Lazy, catalog-derived parametrization.

    * ``lazy_parametrize`` marks are expanded here, in decorator order, with the same
      ``argnames`` / ``argvalues`` / keyword arguments ``parametrize`` would get, so ids and
      ordering are those of an eager ``@pytest.mark.parametrize``.
    * A test that requests a ``tool`` argument is parametrized over the whole catalog
      (sorted by name, ids = tool names), optionally narrowed by ``@pytest.mark.tool_where``.
    """
    from tests import _tool_catalog

    marks = list(metafunc.definition.iter_markers(name="lazy_parametrize"))
    eager = {
        n.strip()
        for m in metafunc.definition.iter_markers(name="parametrize")
        for n in (m.args[0] if isinstance(m.args[0], str) else ",".join(m.args[0])).split(",")
    }
    eager |= {
        n.strip()
        for m in marks
        for n in (m.args[0] if isinstance(m.args[0], str) else ",".join(m.args[0])).split(",")
    }
    wants_tool = (
        "tool" in metafunc.fixturenames
        and "tool" not in eager
        and "tool" not in metafunc._arg2fixturedefs  # no fixture of that name defined
    )
    if not marks and not wants_tool:
        return
    if os.environ.get("COLLECT_GUARD_OUT"):
        # tests/test_collect_guard.py measures IMPORT-time catalog builds only; skip the
        # (intended, deferred) generate-time expansion to keep that collection cheap.
        for marker in marks:
            metafunc.parametrize(
                marker.args[0],
                [],
                **{k: v for k, v in marker.kwargs.items() if k != "ids"},
            )
        if wants_tool:
            metafunc.parametrize("tool", [])
        return
    _tool_catalog.GENERATING = True
    try:
        for marker in marks:
            argnames, thunk = marker.args
            kwargs = {
                k: (v.thunk() if isinstance(v, _tool_catalog.LazyIds) else v)
                for k, v in marker.kwargs.items()
            }
            metafunc.parametrize(argnames, thunk(), **kwargs)
        if wants_tool:
            catalog = sorted(_tool_catalog.tools(), key=lambda t: t.name)
            for pred in metafunc.definition.iter_markers(name="tool_where"):
                catalog = [t for t in catalog if pred.args[0](t)]
            metafunc.parametrize("tool", catalog, ids=[t.name for t in catalog])
    finally:
        _tool_catalog.GENERATING = False
