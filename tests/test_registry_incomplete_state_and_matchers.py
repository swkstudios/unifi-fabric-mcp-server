"""Registry incomplete state, strict numbers, matchers and error reasons.

The class-wide invariants live in the cross-tool batteries and the dedicated lint tests:
the linear-time scrubber in ``test_secret_leak_invariant`` and every regex in
``test_redos_lint``; a capped-list name refused at UNIFI_CACHE_TTL_SECONDS 0 and 900
in ``h2``; wrong-typed pagination controls on every list and drain path in ``w``;
string and list selector forms in ``bt``; ``byKey == _key_labels`` for
envelope-less keys in ``i``; the empty-body guard on every single-object write in
``bq``. This file pins the specific behaviours.
"""

from __future__ import annotations

import ast
import pathlib
import re
from typing import Any

import httpx
import pytest
import respx
from pydantic import ValidationError

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from tests.test_key_labels_and_capped_name_resolution import _REFUSED, _CappedClient
from unifi_fabric import registry as registry_module
from unifi_fabric.client import (
    ResponseShapeError,
    UniFiClient,
    page_has_more,
    page_has_next_link,
    page_total,
    read_page_token,
    wrong_type_error,
)
from unifi_fabric.config import APIKeyConfig, MCPTransportSettings, Settings, whole_number
from unifi_fabric.registry import Registry, match_ea_site
from unifi_fabric.tools import site_manager

SRC = pathlib.Path(registry_module.__file__).parent


# ============================================== incomplete state lives with the list
@pytest.mark.parametrize("ttl", [0, 900])
async def test_capped_lists_refuse_names_at_every_cache_ttl(ttl):
    reg = Registry(_CappedClient(), ttl_seconds=ttl)  # type: ignore[arg-type]
    for _ in range(2):  # a second call must not resolve against a stale/expired marker
        with pytest.raises(ValueError) as exc:
            await reg.resolve_host_id("hq")
        assert _REFUSED.format("hq", "host") in str(exc.value)
        for resolve in (reg.resolve_site_id, reg.resolve_site_slug):
            with pytest.raises(ValueError) as exc:
                await resolve("Default", "AA:1")
            assert _REFUSED.format("Default", "site") in str(exc.value)
        with pytest.raises(ValueError) as exc:
            await reg.resolve_ea_site_id("Default")
        assert _REFUSED.format("Default", "site") in str(exc.value)
        with pytest.raises(ValueError) as exc:
            await site_manager._resolve_ea_site_record(reg, "Default")
        assert _REFUSED.format("Default", "site") in str(exc.value)
    multi = Registry(_CappedClient(["alpha", "beta"]), ttl_seconds=ttl)  # type: ignore[arg-type]
    with pytest.raises(ValueError) as exc:
        await multi.resolve_key_for_host("hq")
    assert _REFUSED.format("hq", "host") in str(exc.value)


class _CompleteClient:
    paginate_max_pages = None

    def list_key_labels(self) -> list[str]:
        return ["default"]

    async def paginate(self, path: str, *, key: Any = None) -> list[dict[str, Any]]:
        return [{"id": "AA:1", "reportedState": {"hostname": "hq"}}]

    async def paginate_offset(self, path: str, *, key: Any = None) -> list[dict[str, Any]]:
        return [{"id": "00000000-0000-4000-8000-000000000001", "name": "Default"}]


async def test_no_cache_mode_never_rereads_an_expired_entry():
    """UNIFI_CACHE_TTL_SECONDS=0: a fetched list is returned directly (it used to be
    stored and read back from a cache whose entry had already expired: KeyError)."""
    reg = Registry(_CompleteClient(), ttl_seconds=0)  # type: ignore[arg-type]
    assert await reg.resolve_host_id("hq") == "AA:1"
    assert await reg.resolve_site_id("Default", "AA:1") == "00000000-0000-4000-8000-000000000001"


# ============================================== wrong-typed paging controls
@pytest.mark.parametrize("value", [7, ["t"], {"t": 1}, True])
def test_next_token_of_the_wrong_type_is_a_shape_error_naming_it(value):
    with pytest.raises(ResponseShapeError, match="'nextToken of GET /v1/hosts'"):
        read_page_token({"nextToken": value}, "nextToken", "/v1/hosts")
    assert read_page_token({"nextToken": None}, "nextToken", "/p") is None
    assert read_page_token({"nextToken": ""}, "nextToken", "/p") is None
    assert read_page_token({}, "nextToken", "/p") is None


@pytest.mark.parametrize("value", ["5", [5], {"v": 5}, True, -1, 1.5])
def test_total_of_the_wrong_type_is_a_shape_error_naming_it(value):
    with pytest.raises(ResponseShapeError, match="'totalCount of GET /p'"):
        page_total({"totalCount": value}, "/p")
    with pytest.raises(ResponseShapeError, match="'total of GET /p'"):
        page_total({"total": value}, "/p")
    assert page_total({"totalCount": None}, "/p") is None
    assert page_total({"totalCount": 0}, "/p") == 0


def test_links_and_has_more_of_the_wrong_type_are_shape_errors():
    with pytest.raises(ResponseShapeError, match="'links of GET /p'"):
        page_has_next_link({"links": "x"}, "/p")
    with pytest.raises(ResponseShapeError, match="'links.next of GET /p'"):
        page_has_next_link({"links": {"next": 7}}, "/p")
    assert page_has_next_link({"links": {"next": "?page=2"}}, "/p") is True
    assert page_has_next_link({"links": None}, "/p") is False
    with pytest.raises(ResponseShapeError, match="'meta.hasMore of GET /p'"):
        page_has_more({"hasMore": "false"}, "/p")
    assert page_has_more({"hasMore": False}, "/p") is False


@respx.mock
async def test_cursor_drain_with_an_int_next_token_raises_naming_it():
    client = UniFiClient(Settings(api_key="sk-test"))
    respx.get("https://api.ui.com/v1/hosts").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "a"}], "nextToken": 5})
    )
    with pytest.raises(ResponseShapeError, match="nextToken of GET /v1/hosts"):
        await client.paginate("/v1/hosts")


# ============================================== the default-path sentinel
async def test_a_key_labelled_like_the_old_sentinel_shares_the_default_cache():
    calls: list[Any] = []

    class _Client:
        paginate_max_pages = None

        def list_key_labels(self) -> list[str]:
            return ["__default__"]

        async def paginate(self, path: str, *, key: Any = None) -> list[dict[str, Any]]:
            calls.append(key)
            label = key.label if key is not None else self.list_key_labels()[0]
            return [{"id": f"host-of-{label}"}]

    reg = Registry(_Client())  # type: ignore[arg-type]
    named = APIKeyConfig(key="k-default-key-1", label="__default__")
    default_hosts = await reg.get_hosts(key=None)
    named_hosts = await reg.get_hosts(key=named)
    assert default_hosts == named_hosts == [{"id": "host-of-__default__"}]
    assert len(calls) == 1
    assert list(reg._hosts) == ["__default__"]
    assert reg._key_label(None) == reg._key_label(named) == "__default__"


# ============================================== strict numbers, validated base URL
@pytest.mark.parametrize("raw", ["1_000", "+5", "٣", "５", "1.0", "1e3", "0x10", "5 5"])
def test_numbers_are_ascii_digits_only(monkeypatch, raw):
    assert whole_number(raw) is None
    monkeypatch.setenv("UNIFI_API_KEY", "sk-test-key-0001")
    monkeypatch.setenv("UNIFI_MAX_CONCURRENCY", raw)
    with pytest.raises(ValidationError) as exc:
        Settings()
    assert "UNIFI_MAX_CONCURRENCY" in str(exc.value)
    assert "ASCII digits" in str(exc.value)
    monkeypatch.delenv("UNIFI_MAX_CONCURRENCY")
    monkeypatch.setenv("UNIFI_MCP_CACHE_TTL", raw)
    with pytest.raises(ValidationError) as exc:
        MCPTransportSettings()
    assert "UNIFI_MCP_CACHE_TTL" in str(exc.value)


@pytest.mark.parametrize("raw", ["8", " 8 ", "0008"])
def test_plain_digits_are_accepted(monkeypatch, raw):
    assert whole_number(raw) == 8
    monkeypatch.setenv("UNIFI_API_KEY", "sk-test-key-0001")
    monkeypatch.setenv("UNIFI_MAX_CONCURRENCY", raw)
    assert Settings().max_concurrency == 8


@pytest.mark.parametrize(
    ("url", "why"),
    [
        ("ftp://api.ui.com", "http:// or https://"),
        ("api.ui.com", "http:// or https://"),
        ("https://", "has no host"),
        ("https://:443", "has no host"),
        ("https://user:pw@api.ui.com", "user info"),
        ("https://api.ui.com?x=1", "query string"),
        ("https://api.ui.com/#frag", "fragment"),
        ("https://api.ui .com", "whitespace"),
        (" https://api.ui.com", "whitespace"),
        ("https://api.ui.com\n", "whitespace"),
        ("https://api.ui.com:99999", "not a valid URL"),
    ],
)
def test_api_base_url_is_validated_at_startup(monkeypatch, url, why):
    monkeypatch.setenv("UNIFI_API_KEY", "sk-test-key-0001")
    monkeypatch.setenv("UNIFI_API_BASE_URL", url)
    with pytest.raises(ValidationError) as exc:
        Settings()
    msg = str(exc.value)
    assert "UNIFI_API_BASE_URL" in msg and why in msg, msg
    assert "pw@" not in msg  # the value (which may carry credentials) is never echoed


@pytest.mark.parametrize(
    "url", ["https://api.ui.com", "http://127.0.0.1:8080", "https://proxy.example/base/"]
)
def test_valid_api_base_urls_are_accepted(monkeypatch, url):
    monkeypatch.setenv("UNIFI_API_KEY", "sk-test-key-0001")
    monkeypatch.setenv("UNIFI_API_BASE_URL", url)
    assert Settings().api_base_url == url


# ============================================== one Site Manager matcher
async def test_exact_site_id_on_a_capped_list_is_complete():
    reg = Registry(_CappedClient())  # type: ignore[arg-type]
    record = await site_manager._resolve_ea_site_record(reg, "a" * 24)
    assert record["_resolvedSiteId"] == "a" * 24
    assert "_incomplete" not in record
    assert "_incompleteReason" not in record
    assert {key: value for key, value in record.items() if not key.startswith("_")} == {
        "siteId": "a" * 24,
        "hostId": "AA:1",
        "meta": {"name": "Default"},
    }
    assert not reg._ea_sites  # the partial enumeration stays uncached


async def test_both_site_manager_resolvers_use_the_one_matcher(monkeypatch):
    seen: list[str] = []
    real = match_ea_site

    def spy(*args: Any, **kwargs: Any) -> Any:
        seen.append(args[1])
        return real(*args, **kwargs)

    monkeypatch.setattr(registry_module, "match_ea_site", spy)
    monkeypatch.setattr(site_manager, "match_ea_site", spy)
    reg = Registry(_CappedClient())  # type: ignore[arg-type]
    await reg.resolve_ea_site_id("a" * 24)
    await site_manager._resolve_ea_site_record(reg, "a" * 24)
    assert seen == ["a" * 24, "a" * 24]


# ============================================== a malformed site record is skipped
def test_matcher_skips_a_malformed_record_and_reports_it():
    sites = [
        {"siteId": "b" * 24, "hostId": "AA:1", "meta": 123},
        {"siteId": "c" * 24, "hostId": "AA:1", "meta": {"name": "Branch"}},
    ]
    assert match_ea_site(sites, "Branch", partial=[], max_pages=None)["siteId"] == "c" * 24
    with pytest.raises(ValueError) as exc:
        match_ea_site(sites, "Nowhere", partial=[], max_pages=None)
    assert "skipped site" in str(exc.value) and "meta" in str(exc.value)


class _MalformedSiteUpstream(uh.FakeUpstream):
    """The Site Manager site list carries one record whose ``meta`` is not an object."""

    def _resolution_body(self, req: httpx.Request, key: str) -> Any:
        body = super()._resolution_body(req, key)
        if req.url.path.endswith("/v1/sites") and isinstance(body, dict):
            bad = {"siteId": "f" * 24, "hostId": uh.HOST_ID, "meta": 123}
            body = {**body, "data": [bad, *body.get("data", [])]}
        return body


async def test_search_across_sites_skips_a_malformed_site_record(monkeypatch):
    # Generated data: the malformed record is added to the generated site list, and a
    # replayed capture of /v1/sites never passes through _resolution_body.
    up = _MalformedSiteUpstream(replay_recordings=False)
    res = await cti._call(monkeypatch, "search_across_sites", up, {"query": "probe"})
    text = uh.all_strings(uh.result_payload(res))
    assert "f" * 24 in text and "meta" in text, text[:400]
    assert "skipped" in text


# ============================================== error reasons are never truncated
def test_wrong_type_error_carries_the_whole_value():
    value = "x" * 500
    assert value in str(wrong_type_error("field", value, "an object"))


def test_no_error_text_is_truncated_by_a_format_precision():
    """No f-string format spec with a precision (``{v!r:.80}``) and no ``%.Ns`` in src."""
    found = []
    for path in sorted(SRC.rglob("*.py")):
        source = path.read_text()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.FormattedValue) and node.format_spec is not None:
                spec = "".join(
                    v.value
                    for v in node.format_spec.values
                    if isinstance(v, ast.Constant) and isinstance(v.value, str)
                )
                precision = re.search(r"\.\d+", spec)
                numeric = spec[-1:] in tuple("fFeEgG%")
                if precision and not numeric:
                    found.append(f"{path.name}:{node.lineno}: {spec}")
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if re.search(r"%\.\d+[sr]", node.value):
                    found.append(f"{path.name}:{node.lineno}: %-precision")
    assert found == [], found
