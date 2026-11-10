"""Tests for get_server_diagnostic_bundle (the sanitized MCP-server diagnostic bundle).

Every synthetic secret is built at run time (never a literal in this file), and every
representation the tool produces is searched: the helper result, its JSON, the MCP
tools/call content text and structuredContent, the log records, and the working
directory (the tool persists nothing).
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import fastmcp
import httpx
import pytest
import respx
from fastmcp import Client, FastMCP

from tests._synthetic_secrets import (
    PROVIDER_SETTINGS,
    SECRET_SETTINGS,
    build_corpus,
    synth,
)
from unifi_fabric import _read_only_audit, diagnostic_bundle
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.families.site_manager import site_manager
from unifi_fabric.families.site_manager.aggregation import register
from unifi_fabric.registry import Registry

TOOL = "get_server_diagnostic_bundle"


def _sentinel(tag: str) -> str:
    return synth(tag)


def _two_key_settings(**extra: Any) -> Settings:
    return Settings(
        api_keys=[
            APIKeyConfig(key=_sentinel("k1"), label="alpha", is_org_key=False),
            APIKeyConfig(key=_sentinel("k2"), label="beta", is_org_key=True),
        ],
        **extra,
    )


def _tool_server(settings: Settings) -> tuple[FastMCP, UniFiClient, Registry]:
    client = UniFiClient(settings)
    registry = Registry(client, ttl_seconds=900)
    mcp = FastMCP("diagnostic-bundle-test")
    register(mcp, lambda: (client, registry))
    return mcp, client, registry


async def _call(mcp: FastMCP, **arguments: Any) -> dict[str, Any]:
    tool = await mcp.get_tool(TOOL)
    result: dict[str, Any] = await tool.fn(**arguments)
    return result


class _Upstream:
    """A respx router whose requests stay readable after the mock exits.

    respx resets its recorded calls when the mock context closes, so a request count
    read after the block would always be zero; this keeps a copy.
    """

    def __init__(self, router: respx.MockRouter) -> None:
        self._router = router
        self.calls: list[httpx.Request] = []

    def route(self) -> respx.Route:
        return self._router.route()

    def snapshot(self) -> None:
        self.calls = [call.request for call in self._router.calls]


@contextmanager
def _upstream() -> Iterator[_Upstream]:
    with respx.mock(assert_all_called=False) as router:
        recorder = _Upstream(router)
        try:
            yield recorder
        finally:
            recorder.snapshot()


def _requests(router: _Upstream) -> list[tuple[str, str]]:
    return [(request.method, request.url.path) for request in router.calls]


class TestDefaultCollectionIsLocalOnly:
    async def test_default_bundle_sends_zero_controller_requests(self, multikey_client):
        registry = Registry(multikey_client, ttl_seconds=900)
        mcp = FastMCP("t")
        register(mcp, lambda: (multikey_client, registry))
        with _upstream() as router:
            router.route().mock(return_value=httpx.Response(200, json={"data": []}))
            bundle = await _call(mcp)
            empty = await _call(mcp, live_probes=[])
        assert _requests(router) == []
        for result in (bundle, empty):
            assert result["collection"]["mode"] == "local"
            assert result["collection"]["upstreamRequests"] == 0
            assert result["collection"]["liveProbesRequested"] == []
            assert result["sections"]["liveProbes"]["status"] == "unavailable"

    async def test_default_bundle_has_useful_local_summaries(self, multikey_client):
        registry = Registry(multikey_client, ttl_seconds=900)
        await registry.set_hosts(
            [{"id": "h-1"}, {"id": "h-2"}], key=multikey_client._key_configs()[0]
        )
        mcp = FastMCP("t")
        register(mcp, lambda: (multikey_client, registry))
        with _upstream() as router:
            router.route().mock(return_value=httpx.Response(500))
            bundle = await _call(mcp)
        assert len(router.calls) == 0
        sections = bundle["sections"]
        assert sections["server"]["data"]["package"] == "unifi-fabric-mcp-server"
        assert sections["server"]["data"]["version"]
        assert sections["configuration"]["data"]["apiKeys"] == {
            "count": 2,
            "organizationKeys": 1,
            "providers": {
                "keyFile": False,
                "keysFile": False,
                "keyCommand": False,
                "keysCommand": False,
            },
        }
        assert sections["configuration"]["data"]["toolMode"] == "discovery"
        assert sections["policy"]["data"]["effectivePolicy"]["write_policy"] == "allow"
        assert len(sections["policy"]["data"]["digest"]) == 64
        assert sections["transport"]["data"]["authMode"] == "none"
        assert sections["cache"]["data"]["hostListsCached"] == 1
        assert sections["cache"]["data"]["hostsCached"] == 2
        assert sections["runtime"]["data"]["registeredTools"] >= 1


class TestProvenance:
    async def test_every_section_reports_status_and_source(self):
        mcp, _, _ = _tool_server(_two_key_settings())
        with _upstream() as router:
            router.route().mock(return_value=httpx.Response(200, json={"data": []}))
            bundle = await _call(mcp, live_probes=["hosts", "sites"])
        assert bundle["schemaVersion"] == diagnostic_bundle.SCHEMA_VERSION
        assert bundle["generatedAt"].endswith("Z")
        assert "Review this bundle before sharing it" in bundle["review"]
        assert set(bundle["sections"]) == {
            "server",
            "configuration",
            "policy",
            "transport",
            "cache",
            "runtime",
            "liveProbes",
        }
        for name, section in bundle["sections"].items():
            assert section["status"] in diagnostic_bundle.SECTION_STATUSES, name
            assert isinstance(section["source"], str) and section["source"], name
        assert bundle["sections"]["liveProbes"]["source"] == "live:site-manager"
        assert bundle["sanitization"]["status"] == "complete"
        assert bundle["neverCollected"] == list(diagnostic_bundle.NEVER_COLLECTED)

    async def test_a_failing_section_is_reported_failed_without_its_message(self, monkeypatch):
        leak = _sentinel("msg")

        def broken() -> dict[str, Any]:
            raise ValueError(f"rejected input {leak}")

        monkeypatch.setattr(diagnostic_bundle, "_transport", broken)
        mcp, _, _ = _tool_server(_two_key_settings())
        bundle = await _call(mcp)
        assert bundle["sections"]["transport"] == {
            "status": "failed",
            "source": "local:transport-settings",
            "reason": "ValueError",
        }
        assert bundle["sections"]["server"]["status"] == "complete"
        assert leak not in json.dumps(bundle)


class TestLiveProbes:
    async def test_probes_send_only_the_allowlisted_read_routes_once_per_key(self):
        mcp, client, _ = _tool_server(_two_key_settings())
        with _upstream() as router:
            router.route().mock(return_value=httpx.Response(200, json={"data": [{"id": "x"}]}))
            bundle = await _call(mcp, live_probes=["sites", "hosts"])
        sent = _requests(router)
        assert sorted(sent) == sorted([("GET", "/v1/hosts")] * 2 + [("GET", "/v1/sites")] * 2)
        assert {method for method, _ in sent} == {"GET"}
        assert bundle["collection"]["upstreamRequests"] == 4
        assert bundle["collection"]["mode"] == "local+live"
        # Allowlist order, whatever order was asked.
        assert bundle["collection"]["liveProbesRequested"] == ["hosts", "sites"]
        live = bundle["sections"]["liveProbes"]
        assert live["status"] == "complete"
        assert [p["probe"] for p in live["probes"]] == ["hosts", "sites"]
        for probe in live["probes"]:
            assert probe["tool"] in {"list_hosts", "list_sites"}
            assert [k["key"] for k in probe["keys"]] == [1, 2]
            assert all(k["status"] == "complete" and k["records"] == 1 for k in probe["keys"])

    async def test_each_key_is_probed_with_its_own_key(self):
        settings = _two_key_settings()
        mcp, _, _ = _tool_server(settings)
        with _upstream() as router:
            router.route().mock(return_value=httpx.Response(200, json={"data": []}))
            await _call(mcp, live_probes=["hosts"])
        sent_keys = [request.headers.get("X-API-KEY") for request in router.calls]
        assert sorted(sent_keys) == sorted(cfg.key for cfg in settings.api_keys)

    async def test_unknown_probe_fails_before_any_request_listing_valid_probes(self):
        mcp, _, _ = _tool_server(_two_key_settings())
        with _upstream() as router:
            router.route().mock(return_value=httpx.Response(200, json={"data": []}))
            with pytest.raises(ValueError, match=r"valid probes: \['hosts', 'sites'\]"):
                await _call(mcp, live_probes=["hosts", "devices"])
        assert len(router.calls) == 0

    async def test_schema_offers_only_the_allowlist(self):
        mcp, _, _ = _tool_server(_two_key_settings())
        tool = await mcp.get_tool(TOOL)
        prop = tool.parameters["properties"]["live_probes"]
        assert prop["description"]
        items = [s for s in prop["anyOf"] if s.get("type") == "array"][0]["items"]
        assert items["enum"] == ["hosts", "sites"]
        assert tool.annotations.readOnlyHint is True

    async def test_mcp_call_rejects_an_unlisted_probe_before_any_request(self):
        mcp, _, _ = _tool_server(_two_key_settings())
        with _upstream() as router:
            router.route().mock(return_value=httpx.Response(200, json={"data": []}))
            async with Client(mcp) as session:
                result = await session.call_tool(
                    TOOL, {"live_probes": ["devices"]}, raise_on_error=False
                )
        assert result.is_error
        assert len(router.calls) == 0

    async def test_one_key_failing_gives_a_useful_partial_bundle(self):
        mcp, _, _ = _tool_server(_two_key_settings())

        def answer(request: httpx.Request) -> httpx.Response:
            if request.headers.get("X-API-KEY", "").startswith("synth-k2"):
                return httpx.Response(401, json={"message": "unauthorized"})
            return httpx.Response(200, json={"data": [{"id": "a"}, {"id": "b"}]})

        with _upstream() as router:
            router.route().mock(side_effect=answer)
            bundle = await _call(mcp, live_probes=["hosts"])
        live = bundle["sections"]["liveProbes"]
        assert live["status"] == "partial"
        keys = live["probes"][0]["keys"]
        assert keys[0]["status"] == "complete" and keys[0]["records"] == 2
        assert keys[1]["status"] == "failed" and keys[1]["reason"] == "HTTP 401"
        assert "records" not in keys[1]
        assert all(isinstance(k["durationMs"], int) for k in keys)
        assert bundle["sections"]["server"]["status"] == "complete"
        assert bundle["sections"]["configuration"]["status"] == "complete"

    async def test_every_probe_failing_still_returns_the_local_bundle(self):
        mcp, _, _ = _tool_server(_two_key_settings())
        with _upstream() as router:
            router.route().mock(side_effect=httpx.ConnectError("refused"))
            bundle = await _call(mcp, live_probes=["hosts", "sites"])
        live = bundle["sections"]["liveProbes"]
        assert live["status"] == "failed"
        for probe in live["probes"]:
            assert probe["status"] == "failed"
            for key in probe["keys"]:
                assert key["status"] == "failed"
                assert key["reason"] and "refused" not in key["reason"]
        assert bundle["sections"]["server"]["status"] == "complete"

    async def test_unexpected_shape_and_incomplete_drain_are_reported(self):
        async def wrong_shape(label: str) -> Any:
            return {"data": "not-a-list"}

        async def capped(label: str) -> Any:
            return {"data": [{"id": 1}], "incomplete": True}

        result = await diagnostic_bundle._probe("hosts", ["a"], wrong_shape)
        assert result["keys"][0] | {"durationMs": 0} == {
            "key": 1,
            "status": "failed",
            "reason": "unexpected-shape",
            "durationMs": 0,
        }
        result = await diagnostic_bundle._probe("hosts", ["a", "b"], capped)
        assert result["status"] == "partial"
        assert {k["reason"] for k in result["keys"]} == {"incomplete"}


class TestSyntheticSecretsNeverLeave:
    """Keys, labels, tokens, headers, URLs, paths and nested error content: none survive."""

    async def test_no_synthetic_credential_reaches_any_representation(
        self, monkeypatch, tmp_path, caplog
    ):
        corpus = build_corpus()
        key_a, key_b = corpus["key_alpha"], corpus["key_beta"]
        label_a, label_b = corpus["label_alpha"], corpus["label_beta"]
        bearer = corpus["bearer"]
        unrelated = corpus["unrelated_env"]
        url_secret = corpus["url_secret"]
        host_secret = corpus["url_host"]
        path_secret = corpus["audit_path"]
        body_secret = corpus["error_body"]
        header_secret = corpus["echoed_header"]
        nested_secret = corpus["nested_error"]
        allowed_host = corpus["allowed_host"]
        # Bearer auth is valid only on an HTTP transport (stdio refuses it at startup).
        monkeypatch.setattr(fastmcp.settings, "transport", "streamable-http")
        monkeypatch.setenv("MCP_BEARER_TOKEN", bearer)
        monkeypatch.setenv("MCP_ALLOWED_HOSTS", f"{allowed_host}.example")
        monkeypatch.setenv("SOME_UNRELATED_TOKEN", unrelated)
        monkeypatch.chdir(tmp_path)
        settings = Settings(
            api_keys=[
                APIKeyConfig(key=key_a, label=label_a),
                APIKeyConfig(key=key_b, label=label_b, is_org_key=True),
            ],
            api_base_url=f"https://{host_secret}.example:8443/{url_secret}",
            audit_log=str(tmp_path / path_secret / "audit.jsonl"),
            audit_hmac_key=corpus["hmac"],
        )
        # Credential-provider settings (a file path and a helper command per form). They
        # are set on the instance so the test holds whether or not this build defines
        # them as fields; the bundle must report only that each is set.
        for env_name, category in PROVIDER_SETTINGS.items():
            object.__setattr__(settings, env_name.removeprefix("UNIFI_").lower(), corpus[category])
        monkeypatch.setenv("MCP_TLS_KEY_PASSWORD", corpus["tls_password"])
        mcp, _, _ = _tool_server(settings)

        def answer(request: httpx.Request) -> httpx.Response:
            api_key = request.headers.get("X-API-KEY", "")
            if request.url.path.endswith("/v1/sites"):
                raise httpx.ConnectError(f"cannot reach {request.url} with {api_key}")
            return httpx.Response(
                403,
                headers={"X-Echo": f"{api_key} {header_secret}"},
                json={
                    "message": f"denied {api_key} {body_secret}",
                    "error": {"detail": {"inner": [nested_secret, api_key]}},
                },
            )

        caplog.set_level(logging.DEBUG)
        before = sorted(p.name for p in tmp_path.iterdir())
        with _upstream() as router:
            router.route().mock(side_effect=answer)
            direct = await _call(mcp, live_probes=["hosts", "sites"])
            async with Client(mcp) as session:
                called = await session.call_tool(TOOL, {"live_probes": ["hosts", "sites"]})
        assert len(router.calls) == 8, "the probes did not run (vacuous)"
        assert sorted(p.name for p in tmp_path.iterdir()) == before, "the tool wrote a file"

        representations = [
            json.dumps(direct),
            repr(direct),
            str(called.structured_content),
            json.dumps(called.structured_content),
            "".join(getattr(block, "text", "") for block in called.content),
            caplog.text,
        ]
        forbidden = {
            "api key": key_a,
            "second api key": key_b,
            "key label": label_a,
            "second key label": label_b,
            "bearer token": bearer,
            "unrelated environment value": unrelated,
            "URL path secret": url_secret,
            "URL host": host_secret,
            "audit path": path_secret,
            "error body": body_secret,
            "echoed header": header_secret,
            "nested error content": nested_secret,
            "allowed host": allowed_host,
            "audit HMAC key": corpus["hmac"],
            "TLS key password": corpus["tls_password"],
            "key file path": corpus["key_file_path"],
            "keys file path": corpus["keys_file_path"],
            "key helper argv": corpus["key_helper_argv"],
            "keys helper argv": corpus["keys_helper_argv"],
            "key file content": corpus["key_file_content"],
        }
        for index, text in enumerate(representations):
            assert text, f"representation {index} is empty (vacuous)"
            if index == len(representations) - 1:
                # Log records are scrubbed of configured secrets by the server's log
                # filter in production; the bundle itself must not log anything new.
                continue
            for what, value in forbidden.items():
                assert value not in text, f"{what} leaked into representation {index}"
        for what in ("api key", "second api key", "bearer token"):
            assert forbidden[what] not in caplog.text, f"{what} logged"
        live = direct["sections"]["liveProbes"]
        reasons = {k["reason"] for p in live["probes"] for k in p["keys"]}
        # The 403 keeps only its status; the transport failure only an exception type name.
        assert "HTTP 403" in reasons
        assert all(re.fullmatch(r"HTTP \d{3}|[A-Za-z]*Error", reason) for reason in reasons)
        assert len(reasons) == 2, reasons
        assert direct["sections"]["configuration"]["data"]["customApiBaseUrl"] is True
        assert direct["sections"]["configuration"]["data"]["audit"]["logFileConfigured"] is True
        assert direct["sections"]["transport"]["data"]["authMode"] == "bearer"
        assert direct["sections"]["transport"]["data"]["allowedHostsCount"] == 1
        providers = direct["sections"]["configuration"]["data"]["apiKeys"]["providers"]
        assert providers == {
            "keyFile": True,
            "keysFile": True,
            "keyCommand": True,
            "keysCommand": True,
        }

    async def test_a_secret_in_an_allowlisted_field_is_scrubbed(self, monkeypatch):
        """Defence in depth: the central scrubber runs over the whole result."""
        settings = _two_key_settings()
        key = settings.api_keys[0].key
        monkeypatch.setattr(diagnostic_bundle, "_policy", lambda: {"leak": f"x {key} y"})
        mcp, _, _ = _tool_server(settings)
        bundle = await _call(mcp)
        assert key not in json.dumps(bundle)
        assert bundle["sections"]["policy"]["data"]["leak"] == "x *** y"
        assert bundle["sanitization"]["valuesMasked"] is True
        assert bundle["sanitization"]["status"] == "complete"

    async def test_scrubber_miss_withholds_every_section(self, monkeypatch):
        settings = _two_key_settings()
        key = settings.api_keys[0].key
        monkeypatch.setattr(diagnostic_bundle, "scrub_json_strings", lambda obj, _s: obj)
        monkeypatch.setattr(diagnostic_bundle, "_policy", lambda: {"leak": key})
        mcp, _, _ = _tool_server(settings)
        bundle = await _call(mcp)
        assert key not in json.dumps(bundle)
        assert bundle["sanitization"]["status"] == "failed"
        assert {s["reason"] for s in bundle["sections"].values()} == {"withheld"}


class TestProviderSettingsAreBooleansOnly:
    """The key-file and helper-command settings show as set/unset, whether or not defined."""

    async def test_unset_and_absent_settings_report_false(self):
        mcp, _, _ = _tool_server(_two_key_settings())
        bundle = await _call(mcp)
        providers = bundle["sections"]["configuration"]["data"]["apiKeys"]["providers"]
        assert providers == dict.fromkeys(
            ("keyFile", "keysFile", "keyCommand", "keysCommand"), False
        )

    async def test_a_set_setting_reports_true_and_never_its_value(self):
        corpus = build_corpus()
        settings = _two_key_settings()
        object.__setattr__(settings, "api_key_command", corpus["key_helper_argv"])
        object.__setattr__(settings, "api_keys_file", corpus["keys_file_path"])
        mcp, _, _ = _tool_server(settings)
        bundle = await _call(mcp)
        providers = bundle["sections"]["configuration"]["data"]["apiKeys"]["providers"]
        assert providers == {
            "keyFile": False,
            "keysFile": True,
            "keyCommand": True,
            "keysCommand": False,
        }
        text = json.dumps(bundle)
        assert corpus["key_helper_argv"] not in text
        assert corpus["keys_file_path"] not in text

    async def test_a_blank_value_is_unset(self):
        settings = _two_key_settings()
        object.__setattr__(settings, "api_key_file", "   ")
        mcp, _, _ = _tool_server(settings)
        bundle = await _call(mcp)
        assert (
            bundle["sections"]["configuration"]["data"]["apiKeys"]["providers"]["keyFile"] is False
        )


class TestSyntheticCorpus:
    def test_every_secret_environment_variable_has_a_corpus_entry(self):
        """A new secret-bearing setting must be added to the corpus (and so to the tests)."""
        from unifi_fabric.secret_scrub import KEYS_ENV_VAR, SECRET_ENV_VARS

        assert set(SECRET_SETTINGS) == {*SECRET_ENV_VARS, KEYS_ENV_VAR}

    def test_values_are_built_at_runtime_and_unique_per_build(self):
        first, second = build_corpus(), build_corpus()
        assert set(first) == set(second)
        assert all(
            re.fullmatch(r"synth-[a-z0-9]+-[0-9a-f-]{36}", value)
            for name, value in first.items()
            if name not in ("hmac", "chain_key")
        )
        assert re.fullmatch(r"[A-Za-z0-9_-]{43}", first["hmac"])
        assert re.fullmatch(r"[A-Za-z0-9_-]{43}", first["chain_key"])
        assert len(set(first.values())) == len(first)
        assert not set(first.values()) & set(second.values())


# ---------------------------------------------------------------- closed shape

_TOP_KEYS = {
    "bundle",
    "schemaVersion",
    "generatedAt",
    "review",
    "collection",
    "sections",
    "neverCollected",
    "sanitization",
}
_COLLECTION_KEYS = {"mode", "liveProbesRequested", "liveProbesAvailable", "upstreamRequests"}
_SANITIZATION_KEYS = {"method", "configuredSecretsChecked", "valuesMasked", "status"}
_SECTION_KEYS = {"status", "source", "data"}
_DATA_KEYS: dict[str, set[str]] = {
    "server": {
        "package",
        "version",
        "python",
        "pythonImplementation",
        "os",
        "architecture",
        "dependencies",
    },
    "configuration": {
        "toolMode",
        "apiKeys",
        "customApiBaseUrl",
        "redactSecrets",
        "cacheTtlSeconds",
        "cacheMaxHosts",
        "cacheMaxSites",
        "maxConcurrency",
        "paginateMaxPages",
        "logLevel",
        "audit",
        "keyMode",
    },
    "policy": {"effectivePolicy", "digest"},
    "transport": {
        "transport",
        "authMode",
        "tlsMode",
        "healthRoute",
        "hostOriginProtection",
        "allowedHostsCount",
        "allowedOriginsCount",
        "oauthWriteScopeConfigured",
    },
    "cache": {
        "hostListsCached",
        "hostsCached",
        "siteListsCached",
        "sitesCached",
        "consoleSiteListsCached",
        "consoleSitesCached",
        "ttlSeconds",
    },
    "runtime": {"registeredTools"},
}
_API_KEYS_KEYS = {"count", "organizationKeys", "providers"}
_PROVIDER_KEYS = {"keyFile", "keysFile", "keyCommand", "keysCommand"}
_AUDIT_KEYS = {"logFileConfigured", "format", "sink", "level", "calls"}
_PROBE_ENTRY_KEYS = {"key", "status", "records", "reason", "durationMs"}
#: The closed vocabulary of a probe ``reason``: an upstream status, an exception type
#: name, or one of these fixed tokens.
_NOT_REQUESTED = "no live probe requested; pass live_probes to run one"
_REASON = re.compile(
    r"HTTP \d{3}|[A-Za-z_][A-Za-z0-9_]*|unexpected-shape|incomplete|no-api-key|withheld"
)


def _assert_closed_shape(bundle: dict[str, Any]) -> None:
    """Every key the bundle may carry; anything else (a new field) fails."""
    assert set(bundle) == _TOP_KEYS
    assert set(bundle["collection"]) == _COLLECTION_KEYS
    assert set(bundle["sanitization"]) == _SANITIZATION_KEYS
    sections = bundle["sections"]
    assert set(sections) == set(_DATA_KEYS) | {"liveProbes"}
    for name, expected in _DATA_KEYS.items():
        section = sections[name]
        assert set(section) == _SECTION_KEYS, name
        assert set(section["data"]) == expected, name
    configuration = sections["configuration"]["data"]
    assert set(configuration["apiKeys"]) == _API_KEYS_KEYS
    assert set(configuration["apiKeys"]["providers"]) == _PROVIDER_KEYS
    assert all(isinstance(v, bool) for v in configuration["apiKeys"]["providers"].values())
    assert set(configuration["audit"]) == _AUDIT_KEYS
    live = sections["liveProbes"]
    assert set(live) <= {"status", "source", "reason", "probes"}
    for probe in live.get("probes", []):
        assert set(probe) == {"probe", "tool", "route", "status", "keys"}
        for entry in probe["keys"]:
            assert set(entry) <= _PROBE_ENTRY_KEYS
            assert {"key", "status", "durationMs"} <= set(entry)
    for reason in _all_reasons(bundle):
        assert reason == _NOT_REQUESTED or _REASON.fullmatch(reason), reason


def _all_reasons(bundle: dict[str, Any]) -> list[str]:
    live = bundle["sections"]["liveProbes"]
    reasons = [live["reason"]] if "reason" in live else []
    for probe in live.get("probes", []):
        reasons += [e["reason"] for e in probe["keys"] if "reason" in e]
    for section in bundle["sections"].values():
        if section is not live and "reason" in section:
            reasons.append(section["reason"])
    return reasons


class TestClosedShape:
    async def test_every_section_has_exactly_the_documented_fields(self):
        mcp, _, _ = _tool_server(_two_key_settings())

        def answer(request: httpx.Request) -> httpx.Response:
            if request.headers.get("X-API-KEY", "").startswith("synth-k2"):
                return httpx.Response(401, json={"message": "nope"})
            return httpx.Response(200, json={"data": [{"id": "x"}]})

        with _upstream() as router:
            router.route().mock(side_effect=answer)
            probed = await _call(mcp, live_probes=["hosts", "sites"])
        local = await _call(mcp)
        for bundle in (local, probed):
            _assert_closed_shape(bundle)
        assert "HTTP 401" in _all_reasons(probed)

    async def test_the_local_bundle_reason_is_the_only_free_text(self):
        """The one fixed sentence (not requested) is the only reason outside the closed set."""
        mcp, _, _ = _tool_server(_two_key_settings())
        bundle = await _call(mcp)
        live = bundle["sections"]["liveProbes"]
        assert live["reason"] == _NOT_REQUESTED
        others = [r for r in _all_reasons(bundle) if r != live["reason"]]
        assert all(_REASON.fullmatch(r) for r in others)

    async def test_every_reason_token_is_in_the_closed_vocabulary(self, monkeypatch):
        no_keys = _tool_server(Settings(api_keys=[]))[0]
        assert (await _call(no_keys, live_probes=["hosts"]))["sections"]["liveProbes"][
            "reason"
        ] == "no-api-key"
        mcp, _, _ = _tool_server(_two_key_settings())
        monkeypatch.setattr(diagnostic_bundle, "scrub_json_strings", lambda obj, _s: obj)
        monkeypatch.setattr(diagnostic_bundle, "_policy", lambda: {"leak": "x"})
        monkeypatch.setattr(diagnostic_bundle, "contains_secret", lambda *_a: True)
        withheld = await _call(mcp)
        assert {s["reason"] for s in withheld["sections"].values()} == {"withheld"}

    async def test_negative_control_an_added_configuration_field_is_caught(self, monkeypatch):
        """If someone adds a field (here a URL), the closed-shape check must go red."""
        original = diagnostic_bundle._configuration

        def widened(client: UniFiClient) -> dict[str, Any]:
            data = original(client)
            data["apiBaseUrl"] = client._settings.api_base_url  # noqa: SLF001
            return data

        monkeypatch.setattr(diagnostic_bundle, "_configuration", widened)
        mcp, _, _ = _tool_server(_two_key_settings())
        bundle = await _call(mcp)
        with pytest.raises(AssertionError):
            _assert_closed_shape(bundle)

    async def test_negative_control_a_free_text_reason_is_caught(self):
        mcp, _, _ = _tool_server(_two_key_settings())
        bundle = await _call(mcp)
        bundle["sections"]["transport"] = {
            "status": "failed",
            "source": "local:transport-settings",
            "reason": "boom at /etc/secret.conf",
        }
        with pytest.raises(AssertionError):
            _assert_closed_shape(bundle)


# ------------------------------------------------- page cap on the real probe path


def _two_page_answer(pages: list[list[dict[str, str]]]):
    """Serve ``pages`` through nextToken, the way the Site Manager API pages a list."""

    def answer(request: httpx.Request) -> httpx.Response:
        token = request.url.params.get("nextToken")
        index = int(token) if token else 0
        body: dict[str, Any] = {"data": pages[index]}
        if index + 1 < len(pages):
            body["nextToken"] = str(index + 1)
        return httpx.Response(200, json=body)

    return answer


class TestPageCapOnTheRealProbePath:
    _PAGES = [[{"id": "a"}, {"id": "b"}, {"id": "c"}], [{"id": "d"}, {"id": "e"}]]

    async def test_a_capped_drain_is_partial_incomplete_with_the_served_count(self):
        settings = _two_key_settings(paginate_max_pages=1)
        mcp, _, _ = _tool_server(settings)
        with _upstream() as router:
            router.route().mock(side_effect=_two_page_answer(self._PAGES))
            bundle = await _call(mcp, live_probes=["hosts", "sites"])
        live = bundle["sections"]["liveProbes"]
        assert live["status"] == "partial"
        assert len(router.calls) == 4, "the cap stops each drain after its first page"
        for probe in live["probes"]:
            assert probe["tool"] in {"list_hosts", "list_sites"}
            assert probe["status"] == "partial"
            for entry in probe["keys"]:
                assert entry["status"] == "partial"
                assert entry["reason"] == "incomplete"
                assert entry["records"] == 3, "the first page only, not the full 5"
        _assert_closed_shape(bundle)

    async def test_an_uncapped_drain_is_complete_with_every_served_record(self):
        mcp, _, _ = _tool_server(_two_key_settings())
        with _upstream() as router:
            router.route().mock(side_effect=_two_page_answer(self._PAGES))
            bundle = await _call(mcp, live_probes=["hosts", "sites"])
        live = bundle["sections"]["liveProbes"]
        assert live["status"] == "complete"
        assert len(router.calls) == 8, "two pages per key per probe"
        for probe in live["probes"]:
            for entry in probe["keys"]:
                assert entry["status"] == "complete"
                assert entry["records"] == 5
                assert "reason" not in entry


# --------------------------------------- the read-only audit sees the probe path


def _writing_probe(client: Any) -> Any:
    """A probe helper that issues a write (the negative control's stand-in)."""
    return client.post("/v1/hosts", json={})


_writing_probe.__module__ = "unifi_fabric.families.site_manager.site_manager"


class TestReadOnlyAuditSeesTheProbePath:
    async def test_the_audit_walk_reaches_the_probe_helpers(self):
        mcp, _, _ = _tool_server(_two_key_settings())
        tool = await mcp.get_tool(TOOL)
        reached = _read_only_audit._called_package_functions(tool.fn)
        assert site_manager.list_hosts in reached
        assert site_manager.list_sites in reached
        assert _read_only_audit.write_verbs_for(tool.fn) == set()
        assert tool.annotations.readOnlyHint is True

    async def test_negative_control_a_write_in_a_probe_flips_the_classification(self, monkeypatch):
        mcp, _, _ = _tool_server(_two_key_settings())
        tool = await mcp.get_tool(TOOL)
        assert _read_only_audit.write_verbs_for(tool.fn) == set()
        monkeypatch.setattr(site_manager, "list_hosts", _writing_probe)
        assert _read_only_audit.write_verbs_for(tool.fn) == {"POST"}
        assert TOOL in _read_only_audit.derive_write_tools([tool])


class TestSupportFileToolsUnchanged:
    def test_controller_support_file_tools_are_separate(self):
        import inspect

        from unifi_fabric.families.innerspace import innerspace_internal
        from unifi_fabric.families.network import network_controller_admin

        for module in (network_controller_admin, innerspace_internal):
            assert "diagnostic_bundle" not in inspect.getsource(module)


def test_the_bundle_names_every_audit_sink_the_server_accepts(tmp_path) -> None:
    """The remote sink is reported as itself, never as the catch-all ``other``."""
    from unifi_fabric import audit

    for sink in audit.SINKS:
        extra: dict[str, Any] = {}
        if sink in {"file", "remote"}:
            extra["audit_log"] = str(tmp_path / "audit.jsonl")
        if sink == "remote":
            extra["audit_remote_url"] = "https://localhost:1/x"
        settings = _two_key_settings(audit_sink=sink, **extra)
        data = diagnostic_bundle._configuration(UniFiClient(settings))
        assert data["audit"]["sink"] == sink
