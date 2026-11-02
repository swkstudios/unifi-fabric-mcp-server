"""Captured HTTP responses are replayed without generated record contamination."""

import copy
import json

import httpx
import pytest

from tests import upstream_harness as uh


def request(entry):
    req = entry["request"]
    return httpx.Request(
        req["method"],
        "https://api.ui.com" + req["path"],
        params=req.get("query", {}),
        **({"json": req["json"]} if "json" in req else {}),
    )


@pytest.mark.parametrize(
    "path", sorted(uh.RECORDED.rglob("*.json")), ids=lambda p: p.relative_to(uh.RECORDED).as_posix()
)
def test_every_recording_is_reachable_verbatim(path):
    entry = json.loads(path.read_text())
    up = uh.FakeUpstream(
        recording_scenario=entry.get("scenario", path.relative_to(uh.RECORDED).as_posix()),
        recording_status=entry["status"],
    )
    response = up(request(entry))
    assert response.status_code == entry["status"]
    # Lane captures may store no content_type; the harness then derives it from the body kind.
    assert response.headers["content-type"] == uh.entry_content_type(entry)
    if "body" in entry:
        assert response.json() == entry["body"]
    elif "text" in entry:
        assert response.text == entry["text"]
    else:
        # The capture stores size/type only; bytes are explicitly synthetic.
        assert len(response.content) == entry["binary_len"]


def test_recording_index_keeps_every_capture():
    assert len(uh.load_recorded()) == len(list(uh.RECORDED.rglob("*.json")))


def entry(query, body, status=200, scenario="success"):
    return {
        "request": {"method": "GET", "path": "/v1/probe", "query": query},
        "status": status,
        "body": body,
        "scenario": scenario,
    }


def install_captures(monkeypatch, tmp_path, entries):
    for idx, item in enumerate(entries):
        (tmp_path / f"{idx}.json").write_text(json.dumps(item))
    monkeypatch.setattr(uh, "RECORDED", tmp_path)
    monkeypatch.setattr(uh, "_RECORDED_CACHE", {})
    return uh.load_recorded()


def test_success_and_error_have_independent_selectors(monkeypatch, tmp_path):
    success = entry({}, {"data": []})
    error = entry({}, {"message": "upstream error"}, 403, "forbidden")
    routes = install_captures(monkeypatch, tmp_path, [error, success])
    assert uh.FakeUpstream(recorded_routes=routes)(request(success)).json() == success["body"]
    response = uh.FakeUpstream(
        recorded_routes=routes, recording_scenario="forbidden", recording_status=403
    )(request(error))
    assert response.status_code == 403
    assert response.json() == error["body"]


def test_query_normalization_preserves_repeated_and_blank_values(monkeypatch, tmp_path):
    capture = entry({"hostIds[]": ["b", "a"], "blank": ""}, {"data": []})
    routes = install_captures(monkeypatch, tmp_path, [capture])
    req = httpx.Request("GET", "https://api.ui.com/v1/probe?blank=&hostIds%5B%5D=a&hostIds%5B%5D=b")
    assert uh.FakeUpstream(recorded_routes=routes)(req).json() == capture["body"]


def test_missing_recorded_query_never_generates_a_response(monkeypatch, tmp_path):
    capture = entry({"offset": "0"}, {"data": []})
    routes = install_captures(monkeypatch, tmp_path, [capture])
    with pytest.raises(LookupError, match="recorded.*query"):
        uh.FakeUpstream(recorded_routes=routes)(request(entry({"offset": "25"}, {})))


def test_method_is_part_of_recording_identity(monkeypatch, tmp_path):
    capture = entry({}, {"data": []})
    routes = install_captures(monkeypatch, tmp_path, [capture])
    req = httpx.Request("POST", "https://api.ui.com/v1/probe")
    assert uh.FakeUpstream(recorded_routes=routes)(req).json() != capture["body"]


@pytest.mark.parametrize(
    "first,last",
    [
        ({"data": [{"id": "first"}], "nextToken": "next"}, {"data": [{"id": "last"}]}),
        (
            {"data": [{"id": "first"}], "offset": 0, "limit": 1, "count": 1, "totalCount": 2},
            {"data": [{"id": "last"}], "offset": 1, "limit": 1, "count": 1, "totalCount": 2},
        ),
        (
            {"groups": [{"id": "first"}], "links": {"next": "/v1/probe?page=2", "prev": None}},
            {"groups": [{"id": "last"}], "links": {"next": None, "prev": "/v1/probe?page=1"}},
        ),
    ],
)
def test_captured_pages_keep_controls_counts_and_records(monkeypatch, tmp_path, first, last):
    captures = [entry({"page": "1"}, first), entry({"page": "2"}, last)]
    routes = install_captures(monkeypatch, tmp_path, captures)
    up = uh.FakeUpstream(recorded_routes=routes)
    for capture in captures:
        original = copy.deepcopy(capture["body"])
        assert up(request(capture)).json() == original
        assert capture["body"] == original


def test_null_capture_is_not_a_missing_recording(monkeypatch, tmp_path):
    capture = entry({}, None)
    routes = install_captures(monkeypatch, tmp_path, [capture])
    assert uh.FakeUpstream(recorded_routes=routes)(request(capture)).json() is None


@pytest.mark.parametrize(
    "tool,param,fixture",
    [
        ("get_camera", "camera_id", "protect/protect_integration_v1_cameras_ID.json"),
        (
            "get_device",
            "device_id",
            "network_integration/network_integration_v1_sites_ID_devices_ID.json",
        ),
        (
            "get_port_profile",
            "profile_id",
            "network_classic/network_api_s_SITE_rest_portconf_ID.json",
        ),
    ],
)
def test_recorded_tool_arguments_use_actual_capture_identifiers(monkeypatch, tool, param, fixture):
    from tests import tool_args

    up = uh.FakeUpstream()
    monkeypatch.setattr(uh.server, "_harness_upstream", up, raising=False)
    original = {param: uh.ARG_ID}
    capture = uh.recorded(fixture)
    expected = capture["request"]["path"].rsplit("/", 1)[-1]
    assert tool_args._recorded_args(tool, original)[param] == expected
    assert original == {param: uh.ARG_ID}


def test_synthetic_tool_arguments_keep_the_explicit_probe_selector(monkeypatch):
    from tests import tool_args

    monkeypatch.setattr(
        uh.server, "_harness_upstream", uh.FakeUpstream(mode="paged"), raising=False
    )
    assert tool_args._recorded_args("get_camera", {"camera_id": uh.ARG_ID}) == {
        "camera_id": uh.ARG_ID
    }


def test_synthetic_record_is_separate_and_never_appended_to_capture():
    capture = uh.recorded("protect/protect_integration_v1_cameras.json")
    synthetic = uh.make_record(0, "explicit-synthetic")
    assert synthetic["id"] == uh.ARG_ID
    response = uh.FakeUpstream()(request(capture))
    assert response.json() == capture["body"]
    assert all(row.get("id") != uh.ARG_ID for row in response.json())


@pytest.mark.parametrize(
    "tool,route_suffix,fixture",
    [
        (
            "collect_protect_events",
            "/proxy/protect/api/events",
            "relative_time_protect_events.json",
        ),
        ("get_traffic_route", "/trafficroutes", "empty_traffic_routes_lookup.json"),
    ],
)
def test_needed_synthetic_routes_are_selected_explicitly(monkeypatch, tool, route_suffix, fixture):
    from tests import tool_args

    up = uh.FakeUpstream()
    monkeypatch.setattr(uh.server, "_harness_upstream", up, raising=False)
    tool_args._recorded_args(tool, {"route_id": uh.ARG_HEX})
    assert [
        name
        for (method, path), name in up.synthetic_routes.items()
        if method == "GET" and path.endswith(route_suffix)
    ] == [fixture]
    assert uh.FakeUpstream().synthetic_routes == {}


def test_synthetic_override_does_not_change_default_recorded_replay():
    capture = uh.recorded("network_v2/network_v2_api_site_SITE_trafficroutes.json")
    req = request(capture)
    assert uh.FakeUpstream()(req).json() == capture["body"]
    up = uh.FakeUpstream(
        synthetic_routes={(req.method, req.url.path): "empty_traffic_routes_lookup.json"}
    )
    assert up(req).json()[0]["_id"] == uh.ARG_HEX
    assert capture["body"] == []


@pytest.mark.parametrize("mode", ["empty", "text", "true", "int", "list"])
def test_explicit_synthetic_body_scenarios_still_override_read_bodies(mode):
    capture = uh.recorded("protect/protect_integration_v1_cameras.json")
    response = uh.FakeUpstream(get_body=mode)(request(capture))
    if mode == "empty":
        assert response.content == b""
    elif mode == "text":
        assert response.text == "probe-get-text"
    else:
        assert response.json() == uh.BARE_JSON_BODIES[mode]


def test_console_and_site_recordings_resolve_through_canonical_registry_ids():
    import re

    console_count = site_count = 0
    for entry in uh.load_recorded().values():
        # Error scenarios deliberately include invalid site aliases/identifiers.
        # Only successful requests must resolve through the canonical registry.
        if not 200 <= entry["status"] < 300:
            continue
        path = entry["request"]["path"]
        console = re.search(r"/(?:connector/consoles|v1/hosts)/([^/]+)", path)
        if console:
            console_count += 1
            assert console.group(1) == uh.HOST_ID, entry["_file"]
        site = re.search(r"/proxy/network/integration/v1/sites/([^/]+)", path)
        if site:
            site_count += 1
            assert site.group(1) == uh.SITE_ID, entry["_file"]
    assert console_count and site_count


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("status", [200, 201, 400, 403, 404, 500])
def test_recording_identity_property_across_verbs_statuses(monkeypatch, tmp_path, method, status):
    captures = []
    for verb in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
        for code in [200, 201, 400, 403, 404, 500]:
            capture = entry(
                {"selector": ["one", "two"], "blank": ""},
                {"verb": verb, "status": code},
                code,
                "matrix",
            )
            capture["request"]["method"] = verb
            captures.append(capture)
    routes = install_captures(monkeypatch, tmp_path, captures)
    capture = next(
        e for e in captures if e["request"]["method"] == method and e["status"] == status
    )
    up = uh.FakeUpstream(
        recorded_routes=routes, recording_status=status, recording_scenario="matrix"
    )
    response = up(request(capture))
    assert response.status_code == status
    assert response.json() == capture["body"]


def test_duplicate_recording_selector_is_rejected(monkeypatch, tmp_path):
    capture = entry({}, {"data": []})
    with pytest.raises(ValueError, match="duplicate recording selector"):
        install_captures(monkeypatch, tmp_path, [capture, copy.deepcopy(capture)])


def test_ambiguous_success_scenarios_require_explicit_selection(monkeypatch, tmp_path):
    captures = [entry({}, {"variant": n}, scenario=str(n)) for n in range(2)]
    routes = install_captures(monkeypatch, tmp_path, captures)
    with pytest.raises(LookupError, match="2 matches"):
        uh.FakeUpstream(recorded_routes=routes)(request(captures[0]))
    for capture in captures:
        assert (
            uh.FakeUpstream(recorded_routes=routes, recording_scenario=capture["scenario"])(
                request(capture)
            ).json()
            == capture["body"]
        )


@pytest.mark.parametrize("protocol", ["nextToken", "offset", "links"])
@pytest.mark.asyncio
async def test_native_captured_paging_drains_without_rewriting(monkeypatch, tmp_path, protocol):
    captures = []
    for n in range(3):
        body = {
            "data": [{"id": f"native-{n}"}],
            "untouched": {"defaultSchedule": "default", "images": {"default": "original"}},
        }
        if protocol == "nextToken":
            query = {"pageSize": "1", **({"nextToken": f"p{n}"} if n else {})}
            if n < 2:
                body["nextToken"] = f"p{n + 1}"
        elif protocol == "offset":
            query = {"offset": str(n), "limit": "1"}
            body.update(offset=n, limit=1, count=1, totalCount=3)
        else:
            query = {"page": str(n + 1), "pageSize": "1"}
            body["groups"] = body.pop("data")
            body["links"] = {"prev": None, "next": f"/v1/probe?page={n + 2}" if n < 2 else None}
        captures.append(entry(query, body))
    routes = install_captures(monkeypatch, tmp_path, captures)
    up = uh.FakeUpstream(recorded_routes=routes)
    client = uh.install(monkeypatch, up)
    try:
        if protocol == "nextToken":
            result = await client.paginate("/v1/probe", page_size=1)
        elif protocol == "offset":
            result = await client.paginate_offset("/v1/probe", page_size=1)
        else:
            result = await client.paginate_links("/v1/probe", "groups", page_size=1)
        assert list(result) == [{"id": f"native-{n}"} for n in range(3)]
        assert len(up.served) == 3
        assert [s.body for s in up.served] == [e["body"] for e in captures]
        assert [uh.normalized_query(s.query) for s in up.served] == [
            uh.normalized_query(e["request"]["query"]) for e in captures
        ]
    finally:
        await client.close()


@pytest.mark.parametrize("protocol", ["nextToken", "offset", "links"])
def test_missing_native_continuation_never_falls_back_to_synthetic(monkeypatch, tmp_path, protocol):
    capture = entry({}, {"data": [{"id": "native-first"}]})
    routes = install_captures(monkeypatch, tmp_path, [capture])
    query = (
        {"nextToken": "p1"}
        if protocol == "nextToken"
        else {"offset": "1"}
        if protocol == "offset"
        else {"page": "2"}
    )
    with pytest.raises(LookupError, match="0 matches"):
        uh.FakeUpstream(recorded_routes=routes)(request(entry(query, {})))


@pytest.mark.parametrize(
    "path", sorted(uh.RECORDED.rglob("*.json")), ids=lambda p: p.relative_to(uh.RECORDED).as_posix()
)
def test_capture_replay_is_isolated_and_immutable_across_requests(path):
    capture = json.loads(path.read_text())
    if "body" not in capture:
        return
    up = uh.FakeUpstream(
        recording_scenario=capture.get("scenario", path.relative_to(uh.RECORDED).as_posix()),
        recording_status=capture["status"],
    )
    original = copy.deepcopy(capture["body"])
    up(request(capture))
    served = up.served[-1].body
    if isinstance(served, dict):
        served["probeContamination"] = uh.make_record(0, "consumer-mutation")
    elif isinstance(served, list):
        served.append(uh.make_record(0, "consumer-mutation"))
    assert up(request(capture)).json() == original
    assert capture["body"] == original


def _registered_tool_names() -> set[str]:
    import asyncio

    return {tool.name for tool in asyncio.run(uh.server.mcp.list_tools())}


def test_every_tool_runs_with_valid_arguments_on_captures_or_a_named_opt_out():
    """The cross-tool suite captures every tool at import; one that cannot be served by a
    native capture must be named in SYNTHETIC_RECORD_TOOLS (class: a lane tool that resolves
    its target against a list the captures do not hold broke collection of the whole suite)."""
    from tests import test_spec_conformance as sc

    assert set(sc.captured_all()) == _registered_tool_names()


def test_synthetic_record_opt_outs_name_real_tools_that_still_need_them(monkeypatch):
    """No stale opt-out: each named tool fails on the native captures without its entry."""
    from tests import test_spec_conformance as sc
    from tests import tool_args

    named = tool_args.SYNTHETIC_RECORD_TOOLS
    assert named <= _registered_tool_names(), sorted(named - _registered_tool_names())
    monkeypatch.setattr(tool_args, "SYNTHETIC_RECORD_TOOLS", frozenset())
    not_needed = []
    for name in sorted(named):
        try:
            sc.capture(name)
            not_needed.append(name)
        except Exception as exc:  # noqa: BLE001 - any failure to serve it natively is the need
            assert str(exc), name
    assert not_needed == [], f"served natively; remove from SYNTHETIC_RECORD_TOOLS: {not_needed}"


def test_synthetic_record_opt_out_is_per_tool_and_only_in_normal_mode(monkeypatch):
    from tests import tool_args

    up = uh.FakeUpstream()
    monkeypatch.setattr(uh.server, "_harness_upstream", up, raising=False)
    tool_args._recorded_args("get_camera", {"camera_id": uh.ARG_ID})
    assert up.replay_recordings is True
    tool_args._recorded_args("adopt_protect_device", {"device_id": uh.ARG_ID})
    assert up.replay_recordings is False
    paged = uh.FakeUpstream(mode="paged")
    monkeypatch.setattr(uh.server, "_harness_upstream", paged, raising=False)
    tool_args._recorded_args("adopt_protect_device", {"device_id": uh.ARG_ID})
    assert paged.replay_recordings is True


def test_host_filtered_devices_query_is_served_from_the_native_capture_body(monkeypatch):
    from tests import tool_args

    up = uh.FakeUpstream()
    monkeypatch.setattr(uh.server, "_harness_upstream", up, raising=False)
    tool_args._recorded_args("get_unifi_placement_snapshot", {"host": uh.HOST})
    fixture = up.synthetic_routes[("GET", "/v1/devices")]
    served = json.loads((uh.Path(__file__).parent / "fixtures" / "synthetic" / fixture).read_text())
    capture = uh.recorded("site_manager/v1_devices.json")
    assert served["body"] == capture["body"] and served["status"] == capture["status"]


def test_repeated_installs_do_not_nest_the_call_tool_wrapper():
    """A module that installs the harness at import many times must not recurse at call time."""
    mp = pytest.MonkeyPatch()
    try:
        for _ in range(1200):
            uh.install(mp, uh.FakeUpstream())
        real = uh.server.mcp.call_tool._harness_real
        assert not hasattr(real, "_harness_real")
    finally:
        mp.undo()
    assert not hasattr(uh.server.mcp.call_tool, "_harness_real")
