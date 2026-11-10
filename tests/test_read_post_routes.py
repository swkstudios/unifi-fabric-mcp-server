"""The route-exact read-POST allowlist (read_post_routes.READ_POST_ROUTES).

Properties:

* every allowlisted route classifies read (and passes UNIFI_WRITE_POLICY); every mutation of
  it (extra or missing segment, changed literal, other method, encoded separator, trailing
  slash) and every not-listed sample classifies write and is refused under read-only;
* the routes the catalog sends as read-POSTs are exactly the allowlisted ones, sent only by
  the tools each entry names;
* a tool mixing an allowlisted read-POST with any write is derived a write tool, and a tool
  whose only POSTs are allowlisted is derived a read tool;
* ``post_read`` refuses an unlisted route before any request;
* only the raw, exact route is a read: case variants, doubled or trailing slashes,
  percent-encoded literals, an encoded ``?`` / ``#`` (which must never be split off a
  second time), a dot segment or an encoded separator in a placeholder are writes, and
  ``post_read`` and the classifier always judge the same raw path the same way;
* ``post_read`` is the only function carrying the read-POST marker.
"""

from __future__ import annotations

import ast
import asyncio
import importlib
import inspect
import pkgutil
from pathlib import Path

import pytest
import respx
from httpx import Response

import unifi_fabric
from unifi_fabric import _read_only_audit as audit
from unifi_fabric import read_only, server
from unifi_fabric import read_post_routes as rp
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings

BASE = "https://api.ui.com"
SAMPLES = [r.sample for r in rp.READ_POST_ROUTES]
IDS = [r.name for r in rp.READ_POST_ROUTES]


def _mutations(path: str) -> list[tuple[str, str]]:
    """(method, path) variants of an allowlisted route that are NOT that route."""
    head, _, last = path.rpartition("/")
    segments = path.split("/")
    out = [
        ("POST", path + "/extra"),
        ("POST", path + "/"),
        ("POST", head),
        ("POST", head + "/" + last + "x"),
        ("POST", head + "/x" + last),
        ("POST", path.replace("/proxy/network/", "/proxy/protect/")),
        ("POST", path.replace("/v1/", "/ea/", 1)),
    ]
    for i, segment in enumerate(segments):
        if segment and i < len(segments) - 1:
            changed = [*segments]
            changed[i] = segment + "-x"
            out.append(("POST", "/".join(changed)))
    # an encoded separator keeps a value in ONE segment: never a route boundary
    out.append(("POST", head + "%2F" + last))
    out += [(m, path) for m in ("PUT", "PATCH", "DELETE")]
    return [(m, p) for m, p in out if not (m == "POST" and rp.is_read_post(m, p))]


@pytest.mark.parametrize("route", rp.READ_POST_ROUTES, ids=IDS)
def test_listed_route_is_a_read_and_passes_read_only(route, monkeypatch):
    monkeypatch.setenv(read_only.ENV_VAR, "deny")
    assert route.matches("POST", route.sample)
    assert rp.read_post_route("post", route.sample + "?x=1") is route
    assert rp.read_post_route("POST", route.sample + "?x=1?y#z") is route
    # matches() takes a query-free path and never splits a second time
    assert not route.matches("POST", route.sample + "?x=1")
    assert not read_only.is_write_request("POST", route.sample)
    read_only.guard_request("POST", route.sample)  # no raise


@pytest.mark.parametrize("route", rp.READ_POST_ROUTES, ids=IDS)
def test_every_mutation_of_a_listed_route_is_a_refused_write(route, monkeypatch):
    monkeypatch.setenv(read_only.ENV_VAR, "deny")
    variants = _mutations(route.sample)
    assert len(variants) >= 10
    for method, path in variants:
        assert read_only.is_write_request(method, path), (method, path)
        with pytest.raises(read_only.ReadOnlyModeError):
            read_only.guard_request(method, path)


_C = (
    "/v1/connector/consoles/"
    "000000000000000000000000000000000000000000000000000000FA0001:0000000001/proxy"
)
_SESSION = _C + "/network/api/s/default/stat/session"
_REPORT = _C + "/network/api/s/default/stat/report/hourly.site"
_ISP = "/v1/isp-metrics/1h/query"

#: Ambiguous spellings of the listed routes: every one is a write (never a read).
AMBIGUOUS: tuple[str, ...] = (
    # case variants of literals
    _C + "/network/api/s/default/STAT/session",
    _C + "/network/api/s/default/stat/Session",
    _C + "/NETWORK/api/s/default/stat/session",
    _C.replace("/proxy", "/Proxy") + "/network/api/s/default/stat/session",
    _C + "/network/api/s/default/stat/report/hourly.site".replace("report", "Report"),
    "/V1/isp-metrics/1h/query",
    "/v1/ISP-metrics/1h/query",
    "/v1/isp-metrics/1h/Query",
    # double slashes
    _C + "/network/api/s/default//stat/session",
    _C + "/network/api/s//default/stat/session",
    _C + "//network/api/s/default/stat/session",
    "//v1/isp-metrics/1h/query",
    "/v1//isp-metrics/1h/query",
    "/v1/isp-metrics//1h/query",
    # trailing slash
    _SESSION + "/",
    _REPORT + "/",
    _ISP + "/",
    _ISP + "/?x=1",
    # encoded ? (single, double, lower case) left in the path: never split a second time
    _SESSION + "%3F",
    _SESSION + "%3f",
    _SESSION + "%3Fx=1",
    _SESSION + "%253Fx=1",
    _SESSION + "%25253F",
    _SESSION + "/extra%3F",
    _REPORT + "%3F",
    _ISP + "%3F",
    _ISP + "%3Fx=1",
    _ISP + "%253Fx",
    _ISP + "/extra%3F/../query",
    _C + "/network/api/s/default%3F/stat/session",
    _C + "/network/api/s/default%253F/stat/session",
    "/v1/isp-metrics/1h%3F/query",
    # encoded # (single, double)
    _SESSION + "%23",
    _SESSION + "%23x",
    _SESSION + "%2523x",
    _ISP + "%23x",
    _C + "/network/api/s/default%23/stat/session",
    _C + "/network/api/s/default%2523/stat/session",
    # raw # in the path
    _SESSION + "#x",
    _C + "/network/api/s/de#fault/stat/session",
    # .. and %2e%2e as site and as console
    _C + "/network/api/s/../stat/session",
    _C + "/network/api/s/./stat/session",
    _C + "/network/api/s/%2e%2e/stat/session",
    _C + "/network/api/s/%2E%2E/stat/session",
    _C + "/network/api/s/.%2e/stat/session",
    _C + "/network/api/s/%252e%252e/stat/session",
    _C + "/network/api/s/%2e/stat/session",
    _C + "/network/api/s/../stat/report/hourly.site",
    "/v1/connector/consoles/../proxy/network/api/s/default/stat/session",
    "/v1/connector/consoles/%2e%2e/proxy/network/api/s/default/stat/session",
    "/v1/connector/consoles/%252e%252e/proxy/network/api/s/default/stat/session",
    "/v1/isp-metrics/../query",
    "/v1/isp-metrics/%2e%2e/query",
    # %2F / %5C (single, double, lower case) inside a placeholder
    _C + "/network/api/s/de%2Ffault/stat/session",
    _C + "/network/api/s/de%2ffault/stat/session",
    _C + "/network/api/s/de%252Ffault/stat/session",
    _C + "/network/api/s/de%5Cfault/stat/session",
    _C + "/network/api/s/de%5cfault/stat/session",
    _C + "/network/api/s/de%255Cfault/stat/session",
    _C + "/network/api/s/de\\fault/stat/session",
    "/v1/connector/consoles/a%2Fb/proxy/network/api/s/default/stat/session",
    "/v1/connector/consoles/a%5Cb/proxy/network/api/s/default/stat/session",
    _C + "/network/api/s/default/stat/report/hourly%2F.site",
    "/v1/isp-metrics/1h%2Fx/query",
    "/v1/isp-metrics/1h%5Cx/query",
    # percent-encoded literal characters (strict: never the route)
    _C + "/network/api/s/default/st%61t/session",
    _C + "/network/api/s/default/%73tat/session",
    _C + "/network/api/s/default/stat/sessio%6E",
    _C + "/network/api/s/default/stat%2Fsession",
    _C + "/network/api/s/default/stat/report/hourly%2Esite",
    _C + "/network/api/s/default/stat/report/hourly%2esite",
    _C + "/network/api/s/default/stat/report/hourly.si%74e",
    _C + "/network/api/s/default/stat/report/%68ourly.site",
    "/v1/isp-metrics/1h/qu%65ry",
    "/v1/isp-metrics/%31h/query",
    "/v1/isp%2Dmetrics/1h/query",
    _C.replace("/proxy", "/pro%78y") + "/network/api/s/default/stat/session",
)


@pytest.mark.parametrize("path", AMBIGUOUS)
def test_ambiguous_spellings_are_refused_writes(path, monkeypatch):
    monkeypatch.setenv(read_only.ENV_VAR, "deny")
    assert rp.read_post_route("POST", path) is None, path
    assert not rp.is_read_post("POST", path)
    assert read_only.is_write_request("POST", path)
    with pytest.raises(read_only.ReadOnlyModeError):
        read_only.guard_request("POST", path)


def test_ambiguous_spellings_are_in_the_post_deploy_refusal_samples():
    refused = {s["path"] for s in rp.refusal_samples() if s["expect"] == "refused"}
    must = {
        _C + "/network/api/s/default/STAT/session",
        _C + "/network/api/s/default/stat/Session",
        _C + "/network/api/s/default//stat/session",
        _SESSION + "/",
        _SESSION + "%3Fx=1",
        _SESSION + "%253Fx=1",
        _SESSION + "%23x",
        _C + "/network/api/s/../stat/session",
        _C + "/network/api/s/%2e%2e/stat/session",
        "/v1/connector/consoles/%2e%2e/proxy/network/api/s/default/stat/session",
        _C + "/network/api/s/de%2Ffault/stat/session",
        _C + "/network/api/s/de%5Cfault/stat/session",
        _C + "/network/api/s/default/st%61t/session",
        _C + "/network/api/s/default/stat/report/hourly%2Esite",
        "/v1/isp-metrics/1h/query%3F",
        "/v1/isp-metrics/1h/query%253Fx",
        "/v1/isp-metrics/1h/query%23x",
        "/v1/isp-metrics/1h/Query",
        "/v1//isp-metrics/1h/query",
        "/v1/isp-metrics/1h/query/",
        "/v1/isp-metrics/1h/qu%65ry",
    }
    assert must <= refused, sorted(must - refused)


#: Placeholder values that stay reads: an encoded id (path_segment output) is fine as
#: long as no decoding round holds a separator, ``?``, ``#`` or a dot segment.
ENCODED_ID_READS: tuple[str, ...] = (
    _C + "/network/api/s/a%2E%2Eb/stat/session",
    _C + "/network/api/s/my%20site/stat/session",
    _C + "/network/api/s/caf%C3%A9/stat/session",
    _C + "/network/api/s/default/stat/report/5minutes.ap",
    "/v1/connector/consoles/AA%3A1/proxy/network/api/s/default/stat/session",
)


@pytest.mark.parametrize("path", ENCODED_ID_READS)
def test_encoded_id_placeholders_stay_reads(path):
    assert rp.is_read_post("POST", path)
    assert not read_only.is_write_request("POST", path)


@pytest.mark.parametrize("path", AMBIGUOUS + ENCODED_ID_READS + tuple(SAMPLES))
def test_post_read_and_classifier_judge_the_same_raw_path(path):
    # one function, one raw path: they can never disagree
    for suffix in ("", "?x=1", "?a=%3F#b"):
        p = path + suffix
        assert rp.is_read_post("POST", p) is not read_only.is_write_request("POST", p), p


@respx.mock
async def test_post_read_refuses_ambiguous_paths_before_any_request(monkeypatch):
    monkeypatch.delenv(read_only.ENV_VAR, raising=False)
    route = respx.route().mock(return_value=Response(200, json={}))
    client = UniFiClient(Settings(api_key="sk-test"))
    for path in AMBIGUOUS:
        with pytest.raises(ValueError, match="read-POST allowlist"):
            await rp.post_read(client, path, json={})
    assert not route.called


@pytest.mark.parametrize("path", rp.NOT_LISTED_SAMPLES)
def test_not_listed_posts_are_refused_writes(path, monkeypatch):
    monkeypatch.setenv(read_only.ENV_VAR, "deny")
    assert not rp.is_read_post("POST", path)
    assert read_only.is_write_request("POST", path)
    with pytest.raises(read_only.ReadOnlyModeError):
        read_only.guard_request("POST", path)


def test_refusal_samples_cover_both_sides():
    samples = rp.refusal_samples()
    reads = [s for s in samples if s["expect"] == "read"]
    refused = [s for s in samples if s["expect"] == "refused"]
    assert len(reads) == len(rp.READ_POST_ROUTES) and refused
    for s in samples:
        assert read_only.is_write_request(s["method"], s["path"]) is (s["expect"] == "refused")


def test_relay_post_to_a_listed_route_stays_a_write(monkeypatch):
    # the relay passes always_write: its caller picks the path
    monkeypatch.setenv(read_only.ENV_VAR, "deny")
    with pytest.raises(read_only.ReadOnlyModeError):
        read_only.guard_request("POST", SAMPLES[0], always_write=True)


def test_each_entry_is_route_exact_and_evidenced():
    names = [r.name for r in rp.READ_POST_ROUTES]
    assert len(names) == len(set(names))
    for route in rp.READ_POST_ROUTES:
        assert route.method == "POST" and route.tools and route.evidence
        assert "*" not in route.template and not route.template.endswith("/")
    with pytest.raises(ValueError):
        rp.ReadPostRoute("x", "PUT", "/v1/x", frozenset({"t"}), ("e",), "/v1/x")


def test_speedtest_archive_route_metadata_names_its_read_tool():
    path = (
        rp._SAMPLE_CONSOLE  # noqa: SLF001 - the allowlist's synthetic console prefix
        + "/network/api/s/default/stat/report/archive.speedtest"
    )
    route = rp.read_post_route("POST", path)
    assert route is not None
    assert route.name == "network-classic-stat-report"
    assert "list_speedtest_results" in route.tools


def _tools() -> list:
    return list(asyncio.run(server.mcp.list_tools()))


def test_listed_tools_are_read_tools_and_the_only_post_read_senders():
    tools = {t.name: t for t in _tools()}
    writes = audit.derive_write_tools(list(tools.values()))
    listed = {name for r in rp.READ_POST_ROUTES for name in r.tools}
    assert listed <= set(tools)
    for name in listed:
        assert name not in writes, f"{name} sends only allowlisted read-POSTs"
        ann = tools[name].annotations.model_dump(by_alias=True)
        assert ann["readOnlyHint"] is True, name


def test_mixed_read_post_and_write_is_a_write_tool():
    async def only_read(client):
        return await rp.post_read(client, SAMPLES[0], json={})

    async def mixed(client):
        await rp.post_read(client, SAMPLES[0], json={})
        return await client.put("/v1/x", json={})

    async def unlisted_post(client):
        return await client.post(SAMPLES[0], json={})

    only_read.__module__ = mixed.__module__ = unlisted_post.__module__ = "unifi_fabric.tests"
    assert audit.write_verbs_for(only_read) == set()
    assert audit.write_verbs_for(mixed) == {"PUT"}
    # client.post is a write even to an allowlisted path: read-POSTs use post_read
    assert audit.write_verbs_for(unlisted_post) == {"POST"}


@respx.mock
async def test_post_read_refuses_unlisted_route_before_any_request(monkeypatch):
    monkeypatch.delenv(read_only.ENV_VAR, raising=False)
    route = respx.route().mock(return_value=Response(200, json={}))
    client = UniFiClient(Settings(api_key="sk-test"))
    for path in rp.NOT_LISTED_SAMPLES:
        with pytest.raises(ValueError, match="read-POST allowlist"):
            await rp.post_read(client, path, json={})
    assert not route.called


@respx.mock
async def test_post_read_sends_listed_route_under_read_only(monkeypatch):
    monkeypatch.setenv(read_only.ENV_VAR, "deny")
    sent = respx.post(f"{BASE}/v1/isp-metrics/1h/query").mock(
        return_value=Response(200, json={"data": {}})
    )
    client = UniFiClient(Settings(api_key="sk-test"))
    assert await rp.post_read(client, "/v1/isp-metrics/1h/query", json={"sites": []}) == {
        "data": {}
    }
    assert sent.called


def _marked_functions() -> set[str]:
    """Every function in the package carrying the read-POST marker (qualified name)."""
    found: set[str] = set()
    for info in pkgutil.walk_packages(unifi_fabric.__path__, "unifi_fabric."):
        module = importlib.import_module(info.name)
        for owner in [module, *(v for _, v in inspect.getmembers(module, inspect.isclass))]:
            for name, value in vars(owner).items():
                fn = getattr(value, "__func__", value)
                if callable(fn) and getattr(fn, "__unifi_read_post__", False) is True:
                    qualname = getattr(fn, "__qualname__", name)
                    found.add(f"{getattr(fn, '__module__', '?')}.{qualname}")
    return found


def test_post_read_is_the_only_marked_read_post_sender():
    # post_read, and the incident-evidence status tap, which refuses (before any request) a
    # POST that is not on the allowlist, so it too sends nothing but listed read-POSTs.
    assert _marked_functions() == {
        "unifi_fabric.read_post_routes.post_read",
        "unifi_fabric.shared_shapes._incident_document.PostStatusTap",
    }
    # and in source: the decorator on a function is applied exactly once, to post_read
    src = Path(unifi_fabric.__file__).resolve().parent
    decorated: list[str] = []
    for file in sorted(src.rglob("*.py")):
        tree = ast.parse(file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    target = dec.func if isinstance(dec, ast.Call) else dec
                    name = getattr(target, "id", None) or getattr(target, "attr", None)
                    if name == "read_post":
                        decorated.append(f"{file.relative_to(src)}:{node.name}")
            if isinstance(node, ast.Attribute) and node.attr == "__unifi_read_post__":
                assert file.name in ("read_post_routes.py", "_read_only_audit.py"), file
    assert decorated == ["read_post_routes.py:post_read"]
