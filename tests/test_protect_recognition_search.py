"""Hermetic coverage for the 15 P07 and 3 NL-1 Protect recognition-write and detection-search tools.

Synthetic fixtures under tests/fixtures/protect_recognition_search (no real faces, plates,
names or identifiers); no estate access.
"""

from __future__ import annotations

import base64
import inspect
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from httpx import Response

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric import refusals, server
from unifi_fabric.client import DRY_RUN_MESSAGE, UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.protect import protect_recognition_search as tools
from unifi_fabric.families.protect.protect import PROTECT_PRIVATE_BASE

FIXTURES = Path(__file__).parent / "fixtures" / "protect_recognition_search"
PREFIX = "/v1/connector/consoles/host-1/proxy/protect/api"
GROUP_ID = "face_1"
DETECTION_ID = "00000000000000000000d001"
EVENT_ID = "00000000000000000000e001"
CAMERA_ID = "00000000000000000000c001"
PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(16))
PNG_B64 = base64.b64encode(PNG).decode()
CSV = (FIXTURES / "vehicle_template.csv").read_bytes()


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


class Registry:
    async def resolve_key_for_host(self, host):
        return None

    async def resolve_host_id(self, host, *, key):
        return "host-1"


UPLOAD = ("reference.png", PNG_B64)
#: (tool, positional args after host, method, route, client method the impl calls)
CASES = [
    (
        "create_recognition_group",
        ("face", {"name": "mcp-gs3-p07"}),
        "POST",
        "/recognition/face/groups",
        "post",
    ),
    (
        "update_recognition_group",
        ("face", GROUP_ID, {"name": "mcp-gs3-p07"}),
        "PATCH",
        f"/recognition/face/groups/{GROUP_ID}",
        "patch",
    ),
    (
        "delete_recognition_group",
        ("face", GROUP_ID),
        "DELETE",
        f"/recognition/face/groups/{GROUP_ID}",
        "delete",
    ),
    (
        "assign_detections_to_recognition_group",
        ("face", [DETECTION_ID], GROUP_ID),
        "POST",
        "/recognition/face/assign-group",
        "post",
    ),
    (
        "enhance_face_detection_image",
        (DETECTION_ID,),
        "POST",
        f"/recognition/face/detections/{DETECTION_ID}/image/enhance",
        "request",
    ),
    (
        "search_recognition_group_candidates",
        ("face", {"groupId": GROUP_ID}),
        "GET",
        "/recognition/face/groups/search-candidates",
        "get",
    ),
    (
        "set_recognition_group_image",
        ("face", GROUP_ID, *UPLOAD),
        "POST",
        f"/recognition/face/groups/{GROUP_ID}/image",
        "request",
    ),
    (
        "merge_recognition_groups",
        ("face", GROUP_ID, ["face_2"]),
        "POST",
        "/recognition/face/merge-group",
        "post",
    ),
    ("recognize_image", UPLOAD, "POST", "/recognition/recognize-image", "request"),
    (
        "bulk_upload_vehicle_groups",
        ("vehicles.csv", base64.b64encode(CSV).decode(), "text/csv"),
        "POST",
        "/recognition/vehicle/groups/batch-upload",
        "request",
    ),
    (
        "get_vehicle_group_upload_template",
        (),
        "GET",
        "/recognition/vehicle/groups/template",
        "get_binary",
    ),
    ("search_detections", ("synthetic van",), "GET", "/detection-nls", "get"),
    ("get_detection_search_metadata", ("labels",), "GET", "/detection-search/labels", "get"),
    (
        "get_detection_statistics",
        (1718000000, 1718086400, 900),
        "GET",
        "/statistics/detections",
        "get",
    ),
    (
        "report_ai_false_positive",
        (EVENT_ID, ["synthetic-thumbnail-1"]),
        "POST",
        "/report/ai-false-positive",
        "post",
    ),
    (
        "hide_face_detection_enhanced_image",
        (DETECTION_ID, True),
        "PATCH",
        f"/recognition/face/detections/{DETECTION_ID}/enhanced-image",
        "patch",
    ),
    (
        "apply_recognized_image",
        ({"free": "form", "nested": {"n": 1}},),
        "POST",
        "/recognition/recognize-image/apply",
        "post",
    ),
    (
        "create_recognition_object_group",
        (["00000000000000000000b001", "00000000000000000000b002"],),
        "POST",
        "/recognition/objects/groups",
        "post",
    ),
]
IDS = [c[0] for c in CASES]
WRITES = [c for c in CASES if c[2] != "GET"]
WRITE_IDS = [c[0] for c in WRITES]


def impl(name: str) -> Any:
    return getattr(tools, f"_{name}")


def http(body: Any, *, content_type: str = "application/json", status: int = 200) -> Response:
    request = httpx.Request("POST", "https://api.ui.com/x")
    if isinstance(body, bytes):
        return Response(
            status, content=body, headers={"content-type": content_type}, request=request
        )
    return Response(status, json=body, request=request)


def client_for(body: Any, groups: list[Any] | None = None) -> AsyncMock:
    """A fake GET upstream serves recognition groups; writes answer body."""
    client = AsyncMock()
    client.dry_run = False
    client.paginate_max_pages = None
    client.recognition_pages.return_value = fixture("groups.json") if groups is None else groups
    client.get.return_value = body
    client.search_pages.return_value = {"data": []}

    async def get_page(path, **kwargs):
        if "/recognition/" in path and path.endswith("/groups"):
            return {"groups": await client.recognition_pages(), "links": {"next": None}}
        if path.endswith("/detection-nls"):
            return await client.search_pages()
        return client.get.return_value

    client.get.side_effect = get_page
    for method in ("post", "patch", "delete", "post_multipart"):
        getattr(client, method).return_value = body
    client.request.return_value = http(body)
    client.get_binary.return_value = (CSV, "text/csv")
    client.search_pages.return_value = {"data": []}
    return client


def calls_to(client: AsyncMock, method: str) -> list[str]:
    calls = getattr(client, method).await_args_list
    if method == "request":
        return [call.args[1] for call in calls]
    return [call.args[0] for call in calls]


# --------------------------------------------------------------------------- pass-through


@pytest.mark.parametrize("name,args,method,route,attr", CASES, ids=IDS)
@pytest.mark.parametrize("body", [{"native": True, "metadata": {"revision": 7}}, ["native"], None])
async def test_every_tool_sends_its_route_and_preserves_the_upstream_body(
    name, args, method, route, attr, body
):
    client = client_for(body)
    result = await impl(name)(client, Registry(), "console", *args)
    assert PREFIX + route in calls_to(client, attr)
    if name == "get_vehicle_group_upload_template":
        assert base64.b64decode(result["content_base64"]) == CSV
        assert result["content_type"] == "text/csv"
    elif name == "update_recognition_group":
        upstream = {k: v for k, v in result.items() if not k.startswith("_")}
        assert upstream == (body if isinstance(body, dict) else {"response": body})
        assert result["_before"] == fixture("groups.json")[0]
    elif name == "search_detections":
        assert result == {"data": [], "_count": 0}
    elif name.startswith("delete_"):
        assert result["deleted"] is True
        assert result["response"] == body
        assert set(result) == {"deleted", "message", "response"}
    else:
        assert result == body


@pytest.mark.parametrize("name,args,method,route,attr", WRITES, ids=WRITE_IDS)
async def test_every_write_returns_the_standard_dry_run_preview(name, args, method, route, attr):
    preview = {
        "status": "dry_run",
        "dryRun": True,
        "message": DRY_RUN_MESSAGE,
        "preview": {"method": method, "path": PREFIX + route, "body": None, "params": None},
    }
    client = client_for(preview)
    client.dry_run = True
    result = await impl(name)(client, Registry(), "console", *args)
    if name == "delete_recognition_group":
        # A delete returns the deletion_result dry-run shape with the preview under response.
        assert set(result) == {"status", "deleted", "message", "response"}
        assert result["status"] == "dry_run" and result["deleted"] is False
        assert result["message"] == DRY_RUN_MESSAGE
        result = result["response"]
    assert result == preview
    assert result.get("_verified") is None


@pytest.mark.parametrize("name,args,method,route,attr", WRITES, ids=WRITE_IDS)
@pytest.mark.parametrize(
    "switch,value",
    [("UNIFI_WRITE_POLICY", "deny"), ("UNIFI_WRITE_EXCEPTIONS", "family:protect=deny")],
)
async def test_every_write_obeys_the_operator_opt_out_before_any_request(
    monkeypatch, name, args, method, route, attr, switch, value
):
    monkeypatch.setenv(switch, value)
    client = client_for({})
    with pytest.raises(Exception):  # noqa: B017 - ReadOnlyModeError or ValueError
        await impl(name)(client, Registry(), "console", *args)
    assert not client.mock_calls


@pytest.mark.parametrize(
    "name,args,match",
    [
        ("create_recognition_group", ("face", {}), "No fields provided"),
        ("create_recognition_group", ("face", ["x"]), "must be a JSON object"),
        ("create_recognition_group", ("../x", {"name": "a"}), "alphanumeric"),
        ("update_recognition_group", ("face", GROUP_ID, {}), "No fields provided"),
        ("update_recognition_group", ("face", "a/b", {"name": "a"}), "alphanumeric"),
        ("delete_recognition_group", ("face", ""), "must not be empty"),
        ("assign_detections_to_recognition_group", ("face", [], GROUP_ID), "non-empty list"),
        (
            "assign_detections_to_recognition_group",
            ("face", {"groupId": GROUP_ID}, GROUP_ID),
            "'detection_ids' must be a list of detection id strings; got object",
        ),
        (
            "assign_detections_to_recognition_group",
            ("face", [7], GROUP_ID),
            r"'detection_ids\[0\]' must be a string; got int",
        ),
        ("assign_detections_to_recognition_group", ("face", [DETECTION_ID], ""), "must not be"),
        (
            "assign_detections_to_recognition_group",
            ("face", [DETECTION_ID], 5),
            "'group_id' must be a string; got int",
        ),
        ("merge_recognition_groups", ("face", GROUP_ID, []), "non-empty list"),
        (
            "merge_recognition_groups",
            ("face", GROUP_ID, "face_2"),
            "'from_group_ids' must be a list of group to merge id strings",
        ),
        (
            "merge_recognition_groups",
            ("face", GROUP_ID, [GROUP_ID]),
            "must not contain to_group_id",
        ),
        (
            "merge_recognition_groups",
            ("face", None, ["face_2"]),
            "'to_group_id' must be a string; got",
        ),
        ("enhance_face_detection_image", ("x?y",), "alphanumeric"),
        ("search_recognition_group_candidates", ("face", "text"), "must be a JSON object"),
        ("set_recognition_group_image", ("face", GROUP_ID, "a.png", "%%%"), "not valid base64"),
        ("recognize_image", ("photo", PNG_B64), "Cannot tell the upload's MIME type"),
        ("recognize_image", ("a.png", PNG_B64, "not a mime"), "must be a MIME type"),
        ("bulk_upload_vehicle_groups", ("v.csv", "!!"), "MIME type|base64"),
        ("search_detections", ("van", "1718000000"), "epoch-seconds"),
        ("get_detection_statistics", (True, 1718086400, 900), "epoch-seconds"),
        ("get_detection_statistics", (1718000000, 1718086400, True), "period must be an"),
        ("get_detection_search_metadata", ("everything",), "Invalid section"),
        ("report_ai_false_positive", ("e1\n", []), "control character"),
        ("get_detection_statistics", (1718000000, 1718086400, 900, " face_1"), "whitespace"),
        ("hide_face_detection_enhanced_image", ("x?y", True), "alphanumeric"),
        ("hide_face_detection_enhanced_image", (DETECTION_ID, "true"), "must be a boolean"),
        ("hide_face_detection_enhanced_image", (DETECTION_ID, 1), "must be a boolean"),
        ("apply_recognized_image", ({},), "No fields provided"),
        ("apply_recognized_image", (["x"],), "must be a JSON object"),
        ("create_recognition_object_group", ([],), "non-empty list"),
        ("create_recognition_object_group", ("b1",), "must be a list"),
        ("create_recognition_object_group", ([""],), "must not be empty"),
        (
            "create_recognition_object_group",
            ([123],),
            r"'object_ids\[0\]' must be a string; got int",
        ),
        ("create_recognition_object_group", (["b1", {"a": 1}],), "got object with keys"),
        ("report_ai_false_positive", (123, ["t"]), "'event_id' must be a string; got int"),
        ("create_recognition_object_group", (["b1\n"],), "control character"),
    ],
)
async def test_invalid_input_raises_a_registered_refusal_before_any_request(name, args, match):
    client = client_for({})
    with pytest.raises(ValueError, match=match) as info:
        await impl(name)(client, Registry(), "console", *args)
    assert not client.mock_calls
    refusal = refusals.classify(str(info.value))
    assert refusal is not None and refusal.category != refusals.UPSTREAM_JUDGED


# --------------------------------------------------------------------------- group lookups


@pytest.mark.parametrize(
    "name,args",
    [
        ("delete_recognition_group", ("face", "face_404")),
        ("update_recognition_group", ("face", "face_404", {"name": "a"})),
        ("set_recognition_group_image", ("face", "face_404", *UPLOAD)),
    ],
)
async def test_unknown_group_fails_listing_choices_before_any_write(name, args):
    client = client_for({"ok": True})
    with pytest.raises(ValueError, match=r"not found.*valid: \['face_1', 'face_2'\]") as info:
        await impl(name)(client, Registry(), "console", *args)
    assert refusals.classify(str(info.value)).id == "lookup-miss"
    for method in ("post", "patch", "delete", "request"):
        getattr(client, method).assert_not_awaited()


async def test_group_id_matches_case_insensitively_and_sends_the_upstream_spelling():
    groups = [{"id": "00000000000000000000abcd", "name": "synthetic"}]
    client = client_for({"ok": True}, groups)
    await tools._delete_recognition_group(
        client, Registry(), "console", "face", "00000000000000000000ABCD"
    )
    assert (
        client.delete.await_args.args[0]
        == PREFIX + "/recognition/face/groups/00000000000000000000abcd"
    )


async def test_body_ids_are_not_held_to_path_rules():
    client = client_for({"ok": True})
    await tools._report_ai_false_positive(client, Registry(), "console", "probe.id:zz~9", ["t-1"])
    assert client.post.await_args.kwargs["json"]["eventId"] == "probe.id:zz~9"


async def test_lookup_reuses_the_recognition_list_drain():
    client = client_for({"ok": True})
    await tools._delete_recognition_group(client, Registry(), "console", "face", GROUP_ID)
    client.get.assert_awaited_once_with(
        PREFIX + "/recognition/face/groups",
        key=None,
        params={"pageSize": 100, "page": 1},
    )
    client.recognition_pages.assert_awaited_once()


async def test_incomplete_group_drain_is_named_in_the_lookup_miss(monkeypatch):
    listed = {"groups": [{"id": "face_2"}], "incomplete": True, "incompleteReason": "page cap"}
    monkeypatch.setattr(tools, "list_recognition_groups", AsyncMock(return_value=listed))
    with pytest.raises(ValueError, match="incomplete \\(page cap\\)"):
        await tools._delete_recognition_group(
            client_for({}), Registry(), "console", "face", GROUP_ID
        )


async def test_unexpected_group_list_shape_raises_naming_it(monkeypatch):
    monkeypatch.setattr(tools, "list_recognition_groups", AsyncMock(return_value=["face_1"]))
    client = client_for({})
    with pytest.raises(Exception, match="Unexpected response shape") as info:
        await tools._delete_recognition_group(client, Registry(), "console", "face", GROUP_ID)
    assert refusals.classify(str(info.value)).id == "upstream-shape"
    client.delete.assert_not_awaited()


# --------------------------------------------------------------------------- update verify


async def test_update_sends_only_the_changes_and_verifies_the_requested_leaf():
    applied = [{**fixture("groups.json")[0], "name": "mcp-gs3-p07"}, fixture("groups.json")[1]]
    client = client_for({"id": GROUP_ID})
    client.recognition_pages.side_effect = [fixture("groups.json"), applied]
    result = await tools._update_recognition_group(
        client, Registry(), "console", "face", GROUP_ID, {"name": "mcp-gs3-p07"}
    )
    assert client.patch.await_args.kwargs["json"] == {"name": "mcp-gs3-p07"}
    assert result["id"] == GROUP_ID
    assert result["_verified"] is True
    assert result["_after"]["name"] == "mcp-gs3-p07"


async def test_update_unapplied_leaf_is_not_verified():
    client = client_for({"id": GROUP_ID})
    result = await tools._update_recognition_group(
        client, Registry(), "console", "face", GROUP_ID, {"name": "mcp-gs3-p07"}
    )
    assert result["_verified"] is False


async def test_update_type_strict_bool_over_int_is_a_change():
    client = client_for({"id": GROUP_ID})
    result = await tools._update_recognition_group(
        client, Registry(), "console", "face", GROUP_ID, {"settings": {"notificationEnabled": 1}}
    )
    client.patch.assert_awaited_once()
    assert result["_verified"] is False


async def test_update_already_applied_is_a_noop_without_write():
    client = client_for({"id": GROUP_ID})
    result = await tools._update_recognition_group(
        client, Registry(), "console", "face", GROUP_ID, {"settings": {"notificationEnabled": True}}
    )
    assert result["status"] == "noop"
    client.patch.assert_not_awaited()


async def test_update_failed_read_after_keeps_the_write_and_reports_unknown():
    client = client_for({"id": GROUP_ID})
    client.recognition_pages.side_effect = [fixture("groups.json"), RuntimeError("synthetic down")]
    result = await tools._update_recognition_group(
        client, Registry(), "console", "face", GROUP_ID, {"name": "mcp-gs3-p07"}
    )
    assert result["id"] == GROUP_ID
    assert result["_verified"] is None
    assert "synthetic down" in result["_readAfterError"]


# --------------------------------------------------------------------------- binary


async def test_enhance_returns_an_image_body_as_base64_with_its_content_type():
    client = client_for(None)
    client.request.return_value = http(PNG, content_type="image/jpeg")
    result = await tools._enhance_face_detection_image(client, Registry(), "console", DETECTION_ID)
    assert result == {
        "image_base64": PNG_B64,
        "content_type": "image/jpeg",
        "size_bytes": len(PNG),
    }
    assert client.request.await_args.args[0] == "POST"


@pytest.mark.parametrize(
    "content,content_type,expected",
    [
        (b'{"enhanced": true}', "application/json; charset=utf-8", {"enhanced": True}),
        (b"queued", "text/plain", "queued"),
        (b"", "image/jpeg", None),
    ],
)
async def test_enhance_returns_a_text_body_verbatim(content, content_type, expected):
    client = client_for(None)
    client.request.return_value = http(content, content_type=content_type)
    result = await tools._enhance_face_detection_image(client, Registry(), "console", DETECTION_ID)
    assert result == expected


def test_binary_detection_without_a_content_type():
    assert tools._is_text(None, b'{"a": 1}') is True
    assert tools._is_text(None, PNG) is False


async def test_template_is_returned_complete_with_the_upstream_content_type():
    client = client_for(None)
    client.get_binary.return_value = (PNG, None)
    result = await tools._get_vehicle_group_upload_template(client, Registry(), "console")
    assert result == {"content_base64": PNG_B64, "content_type": None, "size_bytes": len(PNG)}


async def test_uploads_decode_wrapped_base64_and_send_a_typed_file_part():
    client = client_for({"ok": True})
    wrapped = PNG_B64[:8] + "\n" + PNG_B64[8:]
    await tools._recognize_image(client, Registry(), "console", "photo.jpeg", wrapped)
    files = client.request.await_args.kwargs["files"]
    filename, stream, part_type = files["file"]
    assert (filename, stream.getvalue(), part_type) == ("photo.jpeg", PNG, "image/jpeg")


async def test_upload_form_field_and_content_type_are_used_as_given():
    client = client_for({"ok": True})
    await tools._bulk_upload_vehicle_groups(
        client,
        Registry(),
        "console",
        "vehicles.csv",
        base64.b64encode(CSV).decode(),
        "text/csv",
        "upload",
    )
    files = client.request.await_args.kwargs["files"]
    assert list(files) == ["upload"]
    assert files["upload"][2] == "text/csv"


async def test_upload_dry_run_end_to_end_previews_the_part_and_sends_nothing(monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    client = UniFiClient(Settings(api_key="synthetic-test-key"))
    try:
        with respx.mock(base_url="https://api.ui.com", assert_all_called=False) as mock:
            route = mock.post(url__regex=r".*").mock(return_value=Response(200, json={}))
            result = await tools._recognize_image(client, Registry(), "console", *UPLOAD)
        assert not route.called
        assert result["status"] == "dry_run"
        assert result["message"] == DRY_RUN_MESSAGE
        assert result["preview"]["path"] == PREFIX + "/recognition/recognize-image"
        assert result["preview"]["multipart"] == [
            {
                "field": "file",
                "filename": "reference.png",
                "contentType": "image/png",
                "sizeBytes": len(PNG),
            }
        ]
    finally:
        await client.close()


async def test_upload_reaches_the_upstream_as_multipart():
    client = UniFiClient(Settings(api_key="synthetic-test-key"))
    try:
        with respx.mock(base_url="https://api.ui.com") as mock:
            route = mock.post(PREFIX + "/recognition/recognize-image").mock(
                return_value=Response(200, json={"faces": []})
            )
            result = await tools._recognize_image(client, Registry(), "console", *UPLOAD)
        assert result == {"faces": []}
        sent = route.calls.last.request
        assert sent.headers["content-type"].startswith("multipart/form-data")
        assert PNG in sent.content
    finally:
        await client.close()


async def test_enhance_end_to_end_binary_response():
    client = UniFiClient(Settings(api_key="synthetic-test-key"))
    path = PREFIX + f"/recognition/face/detections/{DETECTION_ID}/image/enhance"
    try:
        with respx.mock(base_url="https://api.ui.com") as mock:
            mock.post(path).mock(
                return_value=Response(200, content=PNG, headers={"content-type": "image/png"})
            )
            result = await tools._enhance_face_detection_image(
                client, Registry(), "console", DETECTION_ID
            )
        assert base64.b64decode(result["image_base64"]) == PNG
        assert result["content_type"] == "image/png"
    finally:
        await client.close()


# --------------------------------------------------------------------------- detections


async def test_search_detections_drains_with_offset_and_warns_on_epoch_units():
    client = client_for([{"id": CAMERA_ID, "name": "synthetic-camera"}])
    client.search_pages.return_value = fixture("detection_search_page.json")
    result = await tools._search_detections(
        client,
        Registry(),
        "console",
        "synthetic van",
        start=1718000000000,
        end=1718003600,
        cameras=[CAMERA_ID],
        min_similarity=0.25,
        order_by="similarity",
        ignore_time_filter_from_text=True,
    )
    params = client.get.await_args.kwargs["params"]
    assert params == {
        "searchText": "synthetic van",
        "offset": 0,
        "limit": 200,
        "start": 1718000000000000,
        "end": 1718003600000,
        "minSimilarity": 0.25,
        "orderBy": "similarity",
        "ignoreTimeFilterFromText": True,
        "cameras": [CAMERA_ID],
    }
    assert result["data"] == fixture("detection_search_page.json")["data"]
    assert result["_count"] == 2
    assert [w["code"] for w in result["_warnings"]] == ["EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS"]


async def test_search_detections_requested_total_preserves_rows_and_metadata():
    page = fixture("detection_search_page.json")
    client = client_for(page)
    client.search_pages.return_value = page
    result = await tools._search_detections(
        client, Registry(), "console", "synthetic van", limit=2, offset=0
    )
    assert result == {
        **page,
        "_count": 2,
        "_pageSize": {"requested": 2, "sent": [2], "effective": 2, "returned": 2},
    }
    assert client.get.await_args.kwargs["params"] == {
        "searchText": "synthetic van",
        "offset": 0,
        "limit": 2,
    }


async def test_search_detections_sized_bare_page_preserves_native_array():
    client = client_for(["d1", "d2"])
    client.search_pages.return_value = ["d1", "d2"]
    result = await tools._search_detections(client, Registry(), "console", "van", limit=2)
    # The aggregate wrapper assumed a clamp; a sized private feed stays one native page.
    assert result == ["d1", "d2"]
    client.get.assert_awaited_once()
    assert client.get.await_args.kwargs["params"] == {"searchText": "van", "limit": 2}


async def test_search_detections_incomplete_drain_is_marked():
    client = client_for(None)
    client.paginate_max_pages = 3
    client.search_pages.side_effect = [
        {"data": [{"id": f"d{i}"}], "totalCount": 4, "limit": 1} for i in range(3)
    ]
    result = await tools._search_detections(client, Registry(), "console", "van")
    assert result["incomplete"] is True
    assert "page cap of 3 reached" in result["incompleteReason"]
    assert result["data"] == [{"id": "d0"}, {"id": "d1"}, {"id": "d2"}]
    assert client.get.await_count == 3


async def test_search_detections_resolves_camera_names(monkeypatch):
    resolve = AsyncMock(return_value=[CAMERA_ID])
    monkeypatch.setattr(tools, "_resolve_camera_refs", resolve)
    client = client_for(None)
    client.search_pages.return_value = {"data": []}
    await tools._search_detections(client, Registry(), "console", "van", cameras=["Driveway"])
    assert resolve.await_args.args[1:] == ("host-1", ["Driveway"])
    assert client.get.await_args.kwargs["params"]["cameras"] == [CAMERA_ID]


async def test_detection_statistics_sends_window_and_period_in_ms_and_warns():
    body = fixture("detection_statistics.json")
    client = client_for(body)
    result = await tools._get_detection_statistics(
        client, Registry(), "console", 1718000000, -5, 900, GROUP_ID
    )
    assert client.get.await_args.kwargs["params"] == {
        "start": 1718000000000,
        "end": -5000,
        "period": 900000,
        "groupId": GROUP_ID,
    }
    assert {k: v for k, v in result.items() if k != "_warnings"} == body
    assert result["_warnings"][0]["code"] == "EPOCH_SECONDS_NEGATIVE"
    client = client_for(body)
    assert (
        await tools._get_detection_statistics(
            client, Registry(), "console", 1718000000, 1718086400, 900
        )
        == body
    )
    assert client.get.await_args.kwargs["params"] == {
        "start": 1718000000000,
        "end": 1718086400000,
        "period": 900000,
    }


async def test_detection_statistics_optional_window_and_legacy_period():
    """Window inputs stay optional even when upstream usually requires them."""
    registered = server.mcp.list_tools()
    registered = await registered if inspect.isawaitable(registered) else registered
    schema = {tool.name: tool for tool in registered}["get_detection_statistics"].parameters
    assert set(schema["required"]) == {"host"}
    for name in ("start", "end", "period"):
        assert "null" in {b["type"] for b in schema["properties"][name]["anyOf"]}, name
    body = fixture("detection_statistics.json")
    client = client_for(body)
    await tools._get_detection_statistics(
        client, Registry(), "console", 1793196305, 1793199905, 900
    )
    params = client.get.await_args.kwargs["params"]
    assert params == {"start": 1793196305000, "end": 1793199905000, "period": 900000}
    assert all(type(value) is int for value in params.values())
    for arguments, expected in (({}, None), ({"period": "day"}, {"period": "day"})):
        assert (
            await tools._get_detection_statistics(client, Registry(), "console", **arguments)
            == body
        )
        assert client.get.await_args.kwargs["params"] == expected


@pytest.mark.parametrize("section", sorted(tools.METADATA_ROUTES))
async def test_detection_search_metadata_reads_each_route(section):
    body = fixture("search_labels.json")
    client = client_for(body)
    assert (
        await tools._get_detection_search_metadata(client, Registry(), "console", section) == body
    )
    assert client.get.await_args.args[0] == PREFIX + tools.METADATA_ROUTES[section]


async def test_candidates_empty_query_sends_no_params():
    client = client_for({"candidates": []})
    await tools._search_recognition_group_candidates(client, Registry(), "console", "face", {})
    assert client.get.await_args.kwargs["params"] is None


async def test_false_positive_report_sends_the_frontend_keys():
    client = client_for({"ok": True})
    await tools._report_ai_false_positive(
        client, Registry(), "console", EVENT_ID, ["synthetic-thumbnail-1", {"id": "t2"}]
    )
    assert client.post.await_args.kwargs["json"] == {
        "eventId": EVENT_ID,
        "reportedThumbnails": ["synthetic-thumbnail-1", {"id": "t2"}],
    }


# --------------------------------------------------------------------------- catalog


async def test_all_15_tools_have_typed_documented_schemas():
    registered = server.mcp.list_tools()
    registered = await registered if inspect.isawaitable(registered) else registered
    by_name = {tool.name: tool for tool in registered}
    for name, _args, method, _route, _attr in CASES:
        tool = by_name[name]
        assert "host" in tool.parameters["required"]
        assert "confirm" not in tool.parameters["properties"], name
        assert "Args:" in inspect.getdoc(tool.fn)
        assert len(tool.description) <= 2048
        for parameter, schema in tool.parameters["properties"].items():
            assert schema.get("description"), (name, parameter)
        hints = tool.annotations.model_dump(by_alias=True)
        assert hints["readOnlyHint"] is (method == "GET"), name
        assert hints["destructiveHint"] is (method != "GET"), name
    private = {
        name[1:]
        for name, func in vars(tools).items()
        if inspect.iscoroutinefunction(func)
        and name.startswith("_")
        and not name.startswith("__")
        and func.__module__ == tools.__name__
        and name not in ("_find_group", "_post_files")
    }
    assert private == set(IDS)


async def test_multikey_routing_rides_the_owning_non_first_key(multikey_client, multikey_registry):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    beta_host = "console-beta-1"
    base = PROTECT_PRIVATE_BASE.format(host_id=beta_host)
    try:
        async with respx.mock(base_url="https://api.ui.com") as mock:
            stats = mock.get(f"{base}/statistics/detections").mock(
                return_value=Response(200, json=fixture("detection_statistics.json"))
            )
            groups = mock.get(f"{base}/recognition/face/groups").mock(
                return_value=Response(
                    200, json={"groups": fixture("groups.json"), "links": {"next": None}}
                )
            )
            deleted = mock.delete(f"{base}/recognition/face/groups/{GROUP_ID}").mock(
                return_value=Response(204)
            )
            result = await tools._get_detection_statistics(
                multikey_client, multikey_registry, "Beta-Branch", 1718000000, 1718086400, 900
            )
            assert result == fixture("detection_statistics.json")
            deleted_result = await tools._delete_recognition_group(
                multikey_client, multikey_registry, "Beta-Branch", "face", GROUP_ID
            )
            assert deleted_result["deleted"] is True and deleted_result["response"] is None
        for route in (stats, groups, deleted):
            assert route.calls.last.request.headers["X-API-KEY"] == "k-beta"
    finally:
        await multikey_client.close()


# --------------------------------------------------------------------------- NL-1 bodies


@pytest.mark.parametrize("hide", [True, False])
async def test_hide_enhanced_image_sends_exactly_the_hide_flag(hide):
    client = client_for({"ok": True})
    await tools._hide_face_detection_enhanced_image(
        client, Registry(), "console", DETECTION_ID, hide
    )
    call = client.patch.await_args
    assert call.args[0] == f"{PREFIX}/recognition/face/detections/{DETECTION_ID}/enhanced-image"
    assert call.kwargs["json"] == {"hide": hide}
    assert call.kwargs["json"]["hide"] is hide


async def test_apply_recognized_image_sends_the_free_form_body_verbatim():
    body = {"native": {"nested": [1, "two", None]}, "flag": False}
    client = client_for({"ok": True})
    await tools._apply_recognized_image(client, Registry(), "console", body)
    assert client.post.await_args.kwargs["json"] == body
    assert client.post.await_args.args[0] == PREFIX + "/recognition/recognize-image/apply"


async def test_assign_sends_the_web_app_body_object_ids_and_group_id():
    client = client_for({"ok": True})
    ids = ["00000000000000000000d002", "00000000000000000000d001"]
    await tools._assign_detections_to_recognition_group(
        client, Registry(), "console", "face", ids, GROUP_ID
    )
    assert client.post.await_args.args[0] == PREFIX + "/recognition/face/assign-group"
    # Protect UI 5.3.18 assignObjectsToSmartDetectObjectGroup: {objectIds, groupId}.
    assert client.post.await_args.kwargs["json"] == {"objectIds": ids, "groupId": GROUP_ID}


async def test_merge_sends_the_web_app_body_from_group_ids_and_to_group_id():
    client = client_for({"ok": True})
    await tools._merge_recognition_groups(
        client, Registry(), "console", "face", GROUP_ID, ["face_2", "face_3"]
    )
    assert client.post.await_args.args[0] == PREFIX + "/recognition/face/merge-group"
    # Protect UI 5.3.18 merge dialog: {fromGroupIds, toGroupId}.
    assert client.post.await_args.kwargs["json"] == {
        "fromGroupIds": ["face_2", "face_3"],
        "toGroupId": GROUP_ID,
    }


async def test_create_object_group_sends_object_ids_in_order_without_rewriting():
    ids = ["b-2", "B-1", "b-2"]
    client = client_for({"id": "obj_1"})
    result = await tools._create_recognition_object_group(client, Registry(), "console", ids)
    assert client.post.await_args.kwargs["json"] == {"objectIds": ids}
    assert result == {"id": "obj_1"}


@pytest.mark.parametrize(
    "name,args",
    [
        ("hide_face_detection_enhanced_image", (DETECTION_ID, True)),
        ("apply_recognized_image", ({"a": 1},)),
        ("create_recognition_object_group", (["b1"],)),
    ],
)
async def test_nl1_errors_from_upstream_pass_through_untruncated(name, args):
    client = client_for({})
    reason = "upstream said no: " + "x" * 3000
    for method in ("post", "patch"):
        getattr(client, method).side_effect = RuntimeError(reason)
    with pytest.raises(RuntimeError) as info:
        await impl(name)(client, Registry(), "console", *args)
    assert str(info.value) == reason


def test_nl1_tools_are_registered_writes_in_the_protect_family():
    from unifi_fabric.families import build_family_index

    index = build_family_index()
    names = (
        "hide_face_detection_enhanced_image",
        "apply_recognized_image",
        "create_recognition_object_group",
    )
    for name in names:
        assert index[name] == "protect"


@pytest.mark.asyncio
async def test_search_detections_search_host_404_names_the_cause_and_the_alternative():
    """Protect answers 404 ``Entity 'searchHost' not found`` when the console has no search
    host for natural-language detection search; the upstream text stays verbatim."""
    from unifi_fabric.client import UniFiConnectionError

    upstream = "HTTP 404 from GET /proxy/protect/api/detection-nls: Entity 'searchHost' not found"
    client = AsyncMock()
    error = UniFiConnectionError(upstream, status=404)
    client.get.side_effect = error
    with pytest.raises(UniFiConnectionError) as caught:
        await tools._search_detections(client, Registry(), "host-1", "person")
    assert caught.value is error
    message = str(caught.value)
    assert message.startswith(upstream + " -- Hint: ")
    hint = message.split(" -- Hint: ", 1)[1]
    assert "no search host for natural-language detection search" in hint
    assert "list_recognition_detections" in hint
    assert "Check detection search service" not in hint


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "function,args,status,message,hint",
    [
        (
            tools._get_detection_statistics,
            (),
            400,
            "missing start end period",
            "start, end and period",
        ),
        (
            tools._search_detections,
            ("person",),
            404,
            "Entity searchHost not found",
            "no search host",
        ),
    ],
)
async def test_read_failure_has_context_and_preserves_upstream(
    function, args, status, message, hint
):
    from unifi_fabric.client import UniFiConnectionError

    client = AsyncMock()
    error = UniFiConnectionError(message, status=status)
    client.get.side_effect = error
    with pytest.raises(UniFiConnectionError) as caught:
        await function(client, Registry(), "host-1", *args)
    assert caught.value is error
    assert str(caught.value).startswith(message + " -- Hint: ")
    assert hint in str(caught.value)
    assert caught.value.status == status
