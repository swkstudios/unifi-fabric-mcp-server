"""Protect events, event media, favorites, cases and stream URLs (GS3 lane P04).

Every tool is exercised against the real ``UniFiClient`` with only the HTTP transport
mocked: routes, query parameters and bodies sent, verbatim pass-through, binary media as
base64, dry-run previews, the Protect write opt-out and read-only mode (zero requests),
zero-request input validation, multi-key routing, the registration contract (annotations
derived from source, described properties) and the recorded live fixtures.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import inspect
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from fastmcp import FastMCP
from pydantic import ValidationError

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric._read_only_audit import classify_tool_verbs
from unifi_fabric.client import RateLimitError, UniFiClient, UniFiConnectionError, _key_fingerprint
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.redaction import REDACTION_MASK
from unifi_fabric.tools import protect_events_cases as pec

HOST = "console-p04"
BASE = f"/v1/connector/consoles/{HOST}/proxy/protect/api"
EVENT = "000000000000000000fa0101"
CAMERA = "000000000000000000fa0201"
CASE = "000000000000000000fa0301"
ASSET = "000000000000000000fa0401"
EXPORT = "000000000000000000fa0501"
OBJECT = "00000000-0000-4000-8000-000000000001"
FIXTURES = Path(__file__).parent / "fixtures" / "recorded" / "protect" / "events_cases"

READ_TOOLS = {
    "get_protect_event",
    "get_protect_event_media",
    "list_protect_cases",
    "get_protect_case_activity",
    "list_protect_case_assets",
    "export_protect_case",
    "get_protect_case_asset_snapshot",
    "get_protect_stream_url",
}
WRITE_TOOLS = {
    "set_protect_event_favorite",
    "create_protect_case",
    "update_protect_case",
    "delete_protect_case",
    "add_protect_case_asset",
    "update_protect_case_asset",
    "remove_protect_case_asset",
}


def registry(key: APIKeyConfig | None = None) -> AsyncMock:
    return AsyncMock(
        **{
            "resolve_key_for_host.return_value": key or APIKeyConfig(key="test-key", label="beta"),
            "resolve_host_id.return_value": HOST,
        }
    )


def client(handler, **settings: Any) -> UniFiClient:
    c = UniFiClient(Settings(api_key="test-key", **settings))
    c._clients[("beta", _key_fingerprint("test-key"))] = httpx.AsyncClient(
        base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
    )
    return c


class Upstream:
    """Route table: (method, path) -> response factory; records every request."""

    def __init__(self, routes: dict[tuple[str, str], Any]):
        self.routes = routes
        self.seen: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        entry = self.routes.get((req.method, req.url.path))
        if entry is None:
            return httpx.Response(404, json={"error": "no route in test", "name": "NOT_FOUND"})
        if callable(entry):
            entry = entry(req)
        if isinstance(entry, httpx.Response):
            return entry
        return httpx.Response(200, json=entry)

    def writes(self) -> list[httpx.Request]:
        return [r for r in self.seen if r.method != "GET"]


def body_of(req: httpx.Request) -> Any:
    return json.loads(req.content) if req.content else None


async def run(handler, coro_fn, *args, settings: dict[str, Any] | None = None, **kwargs):
    c = client(handler, **(settings or {}))
    try:
        return await coro_fn(c, registry(), HOST, *args, **kwargs)
    finally:
        await c.close()


# --------------------------------------------------------------------------- events


async def test_get_event_verbatim_one_get():
    event = {"id": EVENT, "type": "motion", "unknownFuture": {"kept": [1, None]}}
    up = Upstream({("GET", f"{BASE}/events/{EVENT}"): event})
    assert await run(up, pec.get_protect_event, EVENT) == event
    assert len(up.seen) == 1 and not up.seen[0].url.query


async def test_get_event_non_object_is_a_shape_error():
    up = Upstream({("GET", f"{BASE}/events/{EVENT}"): [1, 2]})
    with pytest.raises(UniFiConnectionError, match="expected an object"):
        await run(up, pec.get_protect_event, EVENT)


async def test_get_event_upstream_404_reason_kept_in_full():
    reason = {"error": "Entity 'event' not found", "name": "NOT_FOUND", "id": EVENT}
    up = Upstream({("GET", f"{BASE}/events/{EVENT}"): httpx.Response(404, json=reason)})
    with pytest.raises(UniFiConnectionError) as exc:
        await run(up, pec.get_protect_event, EVENT)
    assert "Entity 'event' not found" in str(exc.value) and "NOT_FOUND" in str(exc.value)


@pytest.mark.parametrize(
    "kind,suffix,ctype",
    [
        ("thumbnail", "thumbnail", "image/jpeg"),
        ("animated_thumbnail", "animated-thumbnail", "image/gif"),
        ("heatmap", "heatmap", "image/png"),
    ],
)
async def test_binary_media_is_base64_with_upstream_content_type(kind, suffix, ctype):
    raw = bytes(range(256)) * 3  # not valid UTF-8: must never be decoded as text
    up = Upstream(
        {
            ("GET", f"{BASE}/events/{EVENT}/{suffix}"): httpx.Response(
                200, content=raw, headers={"content-type": ctype}
            )
        }
    )
    result = await run(up, pec.get_protect_event_media, EVENT, kind)
    assert result == {
        "image_base64": base64.b64encode(raw).decode(),
        "content_type": ctype,
        "size_bytes": len(raw),
    }
    assert not up.seen[0].url.query


async def test_media_sends_only_given_params_with_upstream_names():
    up = Upstream(
        {
            ("GET", f"{BASE}/events/{EVENT}/animated-thumbnail"): httpx.Response(
                200, content=b"GIF89a", headers={"content-type": "image/gif"}
            )
        }
    )
    await run(
        up,
        pec.get_protect_event_media,
        EVENT,
        "animated_thumbnail",
        width=320,
        height=180,
        key_frame_only=True,
        speedup=10,
        start=1_760_000_000,
        end=1_760_000_060,
    )
    assert dict(up.seen[0].url.params) == {
        "w": "320",
        "h": "180",
        "keyFrameOnly": "true",
        "speedup": "10",
        "start": "1760000000000",
        "end": "1760000060000",
    }


async def test_thumbnail_full_fov_param():
    up = Upstream(
        {
            ("GET", f"{BASE}/events/{EVENT}/thumbnail"): httpx.Response(
                200, content=b"\xff\xd8", headers={"content-type": "image/jpeg"}
            )
        }
    )
    await run(up, pec.get_protect_event_media, EVENT, "thumbnail", full_fov=False)
    assert dict(up.seen[0].url.params) == {"isFullfov": "false"}


@pytest.mark.parametrize(
    "kind,suffix,body",
    [
        ("smart_detect_track", "smartDetectTrack", {"id": "t", "payload": [{"zones": [1]}]}),
        ("transcriptions", "transcriptions", []),
    ],
)
async def test_json_media_verbatim(kind, suffix, body):
    up = Upstream({("GET", f"{BASE}/events/{EVENT}/{suffix}"): body})
    kwargs = {"camera_id": CAMERA} if kind == "transcriptions" else {}
    assert await run(up, pec.get_protect_event_media, EVENT, kind, **kwargs) == body
    if kind == "transcriptions":
        assert dict(up.seen[0].url.params) == {"camera": CAMERA}


async def test_transcriptions_without_camera_is_the_upstreams_to_judge():
    reason = {
        "error": "Failed to parse 'request-query'",
        "name": "AJV_PARSE_ERROR",
        "issues": [{"message": "must have required property 'camera'"}],
    }
    up = Upstream(
        {("GET", f"{BASE}/events/{EVENT}/transcriptions"): httpx.Response(400, json=reason)}
    )
    with pytest.raises(UniFiConnectionError, match="must have required property 'camera'"):
        await run(up, pec.get_protect_event_media, EVENT, "transcriptions")
    assert len(up.seen) == 1


async def test_media_millisecond_epoch_is_sent_with_a_warning():
    up = Upstream({("GET", f"{BASE}/events/{EVENT}/smartDetectTrack"): {"payload": []}})
    result = await run(
        up, pec.get_protect_event_media, EVENT, "smart_detect_track", start=1_760_000_000_000
    )
    assert result["payload"] == []
    assert result["_warnings"][0]["code"] == "EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS"


# ------------------------------------------------------------------------- favorites


@pytest.mark.parametrize("favorite,verb", [(True, "favorite"), (False, "unfavorite")])
async def test_single_favorite_posts_then_verifies(favorite, verb):
    event_after = {"id": EVENT, "isFavorite": favorite, "favoriteObjectIds": None}
    up = Upstream(
        {
            ("POST", f"{BASE}/{verb}-events/{EVENT}"): httpx.Response(204),
            ("GET", f"{BASE}/events/{EVENT}"): event_after,
        }
    )
    result = await run(up, pec.set_protect_event_favorite, EVENT, favorite)
    assert result == {
        "status": "favorited" if favorite else "unfavorited",
        "response": None,
        "verified": True,
        "event": event_after,
    }
    assert [r.method for r in up.seen] == ["POST", "GET"]
    assert not up.seen[0].content and not up.seen[0].url.query


async def test_single_favorite_object_sends_object_id_and_verifies_object_list():
    up = Upstream(
        {
            ("POST", f"{BASE}/favorite-events/{EVENT}"): httpx.Response(204),
            ("GET", f"{BASE}/events/{EVENT}"): {"isFavorite": True, "favoriteObjectIds": [OBJECT]},
        }
    )
    result = await run(up, pec.set_protect_event_favorite, EVENT, True, object_id=OBJECT)
    assert dict(up.seen[0].url.params) == {"objectId": OBJECT}
    assert result["verified"] is True


async def test_single_favorite_not_applied_is_reported_unverified():
    up = Upstream(
        {
            ("POST", f"{BASE}/favorite-events/{EVENT}"): httpx.Response(204),
            ("GET", f"{BASE}/events/{EVENT}"): {"isFavorite": False},
        }
    )
    assert (await run(up, pec.set_protect_event_favorite, EVENT, True))["verified"] is False


async def test_single_favorite_failed_read_after_keeps_write_result():
    up = Upstream(
        {
            ("POST", f"{BASE}/favorite-events/{EVENT}"): httpx.Response(204),
            ("GET", f"{BASE}/events/{EVENT}"): httpx.Response(500, json={"error": "boom"}),
        }
    )
    result = await run(up, pec.set_protect_event_favorite, EVENT, True)
    assert result["status"] == "favorited" and result["verified"] is None
    assert "boom" in result["readAfterError"]


@pytest.mark.parametrize("favorite,verb", [(True, "favorite"), (False, "unfavorite")])
async def test_list_favorite_uses_batch_route_and_returns_body_verbatim(favorite, verb):
    ids = [EVENT, "00000000-0000-4000-8000-000000000002"]
    response = {ids[0]: True, ids[1]: True}
    up = Upstream({("POST", f"{BASE}/{verb}-events"): response})
    objects = [{"eventId": ids[0], "objectId": OBJECT}]
    result = await run(up, pec.set_protect_event_favorite, ids, favorite, objects=objects)
    assert result == {"status": f"{verb}d", "response": response}
    assert body_of(up.seen[0]) == {"ids": ids, "idsWithObject": objects}
    assert len(up.seen) == 1


async def test_list_of_one_still_uses_the_batch_route():
    up = Upstream({("POST", f"{BASE}/favorite-events"): {EVENT: True}})
    result = await run(up, pec.set_protect_event_favorite, [EVENT], True)
    assert body_of(up.seen[0]) == {"ids": [EVENT], "idsWithObject": []}
    assert result["response"] == {EVENT: True}


async def test_favorite_must_be_a_real_bool():
    up = Upstream({})
    with pytest.raises(ValidationError):
        await run(up, pec.set_protect_event_favorite, EVENT, 1)
    assert up.seen == []


# --------------------------------------------------------------------------- cases


def case(**overrides: Any) -> dict[str, Any]:
    base = {"id": CASE, "name": "name-0001", "summary": "", "active": True, "assetCount": 1}
    return {**base, **overrides}


async def test_list_cases_returns_every_case_with_count():
    cases = [case(), case(id="000000000000000000fa0302", extra={"x": 1})]
    up = Upstream({("GET", f"{BASE}/cases"): cases})
    assert await run(up, pec.list_protect_cases) == {"result": cases, "_count": 2}


async def test_list_cases_unexpected_shape_raises():
    up = Upstream({("GET", f"{BASE}/cases"): {"cases": "nope"}})
    with pytest.raises(UniFiConnectionError, match="Unexpected Protect response shape"):
        await run(up, pec.list_protect_cases)


async def test_create_case_body_and_result():
    created = case(name="mcp-case")
    up = Upstream({("POST", f"{BASE}/cases"): created})
    result = await run(
        up, pec.create_protect_case, "mcp-case", summary="s", fields={"location": "Garage"}
    )
    assert result == {"status": "created", "response": created}
    assert body_of(up.seen[0]) == {"name": "mcp-case", "location": "Garage", "summary": "s"}


async def test_create_case_conflicting_name_fails_before_any_request():
    up = Upstream({})
    with pytest.raises(ValueError, match="'name' was given twice"):
        await run(up, pec.create_protect_case, "a", fields={"name": "b"})
    assert up.seen == []


def _patch_routes(before: list[Any], after: list[Any], path: str, list_path: str):
    lists = iter([before, after])
    routes = {
        ("GET", list_path): lambda _req: httpx.Response(200, json=next(lists)),
        ("PATCH", path): lambda req: httpx.Response(200, json={"patched": body_of(req)}),
    }
    if list_path.endswith("/assets"):
        parent_id = list_path.rsplit("/cases/", 1)[1].split("/", 1)[0]
        routes[("GET", f"{BASE}/cases")] = [{"id": parent_id}]
    return Upstream(routes)


async def test_update_case_verified_through_the_list():
    up = _patch_routes(
        [case()], [case(name="renamed", active=False)], f"{BASE}/cases/{CASE}", f"{BASE}/cases"
    )
    result = await run(up, pec.update_protect_case, CASE, name="renamed", active=False)
    assert result["status"] == "updated" and result["verified"] is True
    assert result["before"] == case() and result["after"] == case(name="renamed", active=False)
    assert body_of(up.writes()[0]) == {"name": "renamed", "active": False}
    assert result["response"] == {"patched": {"name": "renamed", "active": False}}


async def test_update_case_bool_vs_int_is_type_strict():
    up = _patch_routes(
        [case(active=1)], [case(active=False)], f"{BASE}/cases/{CASE}", f"{BASE}/cases"
    )
    result = await run(up, pec.update_protect_case, CASE, active=True)
    assert result["status"] == "updated"  # 1 is not True: the write is sent
    assert result["verified"] is False


async def test_update_case_noop_sends_no_patch():
    up = _patch_routes([case(summary="same")], [], f"{BASE}/cases/{CASE}", f"{BASE}/cases")
    result = await run(up, pec.update_protect_case, CASE, summary="same")
    assert result["status"] == "noop" and up.writes() == []


async def test_update_case_unknown_id_is_sent_and_judged_upstream():
    up = Upstream(
        {
            ("GET", f"{BASE}/cases"): [],
            ("PATCH", f"{BASE}/cases/{CASE}"): httpx.Response(
                404, json={"error": "Entity 'case' not found"}
            ),
        }
    )
    with pytest.raises(UniFiConnectionError, match="Entity 'case' not found"):
        await run(up, pec.update_protect_case, CASE, name="x")
    assert len(up.writes()) == 1


async def test_update_case_missing_after_write_is_unverified_false():
    up = _patch_routes([case()], [], f"{BASE}/cases/{CASE}", f"{BASE}/cases")
    result = await run(up, pec.update_protect_case, CASE, name="x")
    assert result["verified"] is False and result["after"] is None


async def test_update_case_refuses_a_fields_key_a_named_argument_sets():
    up = _patch_routes([case()], [case(name="arg")], f"{BASE}/cases/{CASE}", f"{BASE}/cases")
    with pytest.raises(ValueError, match="fields must not contain 'name'"):
        await run(up, pec.update_protect_case, CASE, name="arg", fields={"name": "f", "x": 1})
    assert up.writes() == []


@pytest.mark.parametrize("fields", [None, {}, {"_note": "additive"}, {"id": CASE}])
async def test_update_case_without_fields_fails_before_any_request(fields):
    up = Upstream({})
    with pytest.raises(ValueError, match="No fields provided"):
        await run(up, pec.update_protect_case, CASE, fields=fields)
    assert up.seen == []


async def test_delete_case_returns_deletion_result():
    up = Upstream({("DELETE", f"{BASE}/cases/{CASE}"): httpx.Response(204)})
    result = await run(up, pec.delete_protect_case, CASE)
    assert result == {
        "deleted": True,
        "message": f"Protect case {CASE} deleted.",
        "response": None,
    }


async def test_activity_log_drains_links_pages():
    pages = {
        "1": {"activities": [{"id": "a1"}], "links": {"prev": None, "next": "/x?page=2"}},
        "2": {"activities": [{"id": "a2"}], "links": {"prev": "/x?page=1", "next": None}},
    }
    up = Upstream(
        {
            ("GET", f"{BASE}/cases/{CASE}/activity-log"): lambda req: httpx.Response(
                200, json=pages[req.url.params["page"]]
            )
        }
    )
    result = await run(up, pec.get_protect_case_activity, CASE)
    assert result["activities"] == [{"id": "a1"}, {"id": "a2"}] and result["_count"] == 2
    assert [r.url.params["page"] for r in up.seen] == ["1", "2"]


async def test_activity_log_single_page_reports_next_page():
    page = {"activities": [{"id": "a1"}], "links": {"prev": None, "next": "/x?page=2"}}
    up = Upstream({("GET", f"{BASE}/cases/{CASE}/activity-log"): page})
    result = await run(up, pec.get_protect_case_activity, CASE, page=1, page_size=1)
    assert result["_nextPage"] == 2 and result["links"] == page["links"]
    assert dict(up.seen[0].url.params) == {"page": "1", "pageSize": "1"}


async def test_activity_log_repeated_page_is_marked_incomplete():
    page = {"activities": [{"id": "a1"}], "links": {"prev": None, "next": "/x?page=2"}}
    up = Upstream({("GET", f"{BASE}/cases/{CASE}/activity-log"): page})
    result = await run(up, pec.get_protect_case_activity, CASE)
    assert result["incomplete"] is True and "same page" in result["incompleteReason"]


async def test_list_case_assets():
    assets = [{"id": ASSET, "type": "clip"}, {"id": "p", "type": "pdfReport"}]
    up = Upstream({("GET", f"{BASE}/cases/{CASE}/assets"): assets})
    assert await run(up, pec.list_protect_case_assets, CASE) == {"result": assets, "_count": 2}


async def test_add_asset_body_ms_and_result():
    response = {"main": {"success": True, "data": {"id": ASSET, "type": "clip"}}}
    up = Upstream({("POST", f"{BASE}/cases/{CASE}/assets"): response})
    result = await run(
        up,
        pec.add_protect_case_asset,
        CASE,
        CAMERA,
        1_760_000_000,
        1_760_000_030,
        note="n",
        lens=["main"],
        fields={"title": "t"},
    )
    assert result == {"status": "created", "response": response}
    assert body_of(up.seen[0]) == {
        "title": "t",
        "camera": CAMERA,
        "type": "clip",
        "start": 1_760_000_000_000,
        "end": 1_760_000_030_000,
        "note": "n",
        "lens": ["main"],
    }


async def test_add_asset_epoch_must_be_integer_before_any_request():
    up = Upstream({})
    with pytest.raises(ValueError, match="integer epoch-seconds"):
        await run(up, pec.add_protect_case_asset, CASE, CAMERA, 1.5, 2)
    assert up.seen == []


async def test_update_asset_echoes_current_type_when_omitted():
    before = [{"id": ASSET, "type": "clip", "note": "a"}]
    after = [{"id": ASSET, "type": "clip", "note": "b"}]
    path = f"{BASE}/cases/{CASE}/assets/{ASSET}"
    up = _patch_routes(before, after, path, f"{BASE}/cases/{CASE}/assets")
    result = await run(up, pec.update_protect_case_asset, CASE, ASSET, note="b")
    assert body_of(up.writes()[0]) == {"type": "clip", "note": "b"}
    assert result["verified"] is True


async def test_update_asset_explicit_type_is_sent_as_given():
    path = f"{BASE}/cases/{CASE}/assets/{ASSET}"
    up = _patch_routes(
        [{"id": ASSET, "type": "clip"}],
        [{"id": ASSET, "type": "clip", "title": "t"}],
        path,
        f"{BASE}/cases/{CASE}/assets",
    )
    await run(up, pec.update_protect_case_asset, CASE, ASSET, title="t", asset_type="externalFile")
    assert body_of(up.writes()[0]) == {"title": "t", "type": "externalFile"}


async def test_update_asset_unknown_asset_sends_without_invented_type():
    path = f"{BASE}/cases/{CASE}/assets/{ASSET}"
    up = Upstream(
        {
            ("GET", f"{BASE}/cases"): [case()],
            ("GET", f"{BASE}/cases/{CASE}/assets"): [],
            ("PATCH", path): httpx.Response(400, json={"error": "ZOD_PARSE_ERROR"}),
        }
    )
    with pytest.raises(UniFiConnectionError, match="ZOD_PARSE_ERROR"):
        await run(up, pec.update_protect_case_asset, CASE, ASSET, include_in_export=False)
    assert body_of(up.writes()[0]) == {"includeInExport": False}


@pytest.mark.parametrize("asset", [False, True], ids=["case", "case_asset"])
@pytest.mark.parametrize(
    "reply,expected",
    [
        (lambda: httpx.Response(200), None),
        (lambda: httpx.Response(200, json=7), 7),
        (lambda: httpx.Response(200, json=True), True),
        (lambda: httpx.Response(200, json=[]), []),
        (lambda: httpx.Response(200, text="plain-ack"), "plain-ack"),
    ],
    ids=["empty", "int", "true", "list", "text"],
)
async def test_verified_patch_relays_a_primitive_write_body_verbatim(asset, reply, expected):
    """A non-object PATCH answer is passed through unchanged under ``response`` beside the
    additive verification fields, for the case and the case-asset writer alike."""
    if asset:
        record, list_path = (
            {"id": ASSET, "type": "clip", "note": "a"},
            f"{BASE}/cases/{CASE}/assets",
        )
        path, call = f"{list_path}/{ASSET}", (pec.update_protect_case_asset, CASE, ASSET)
        kwargs = {"note": "b"}
    else:
        record, list_path = case(), f"{BASE}/cases"
        path, call, kwargs = f"{BASE}/cases/{CASE}", (pec.update_protect_case, CASE), {"name": "b"}
    lists = iter([[record], [{**record, **kwargs}]])
    routes = {
        ("GET", list_path): lambda _req: httpx.Response(200, json=next(lists)),
        ("PATCH", path): lambda _req: reply(),
    }
    if asset:
        routes[("GET", f"{BASE}/cases")] = [case()]
    up = Upstream(routes)
    result = await run(up, *call, **kwargs)
    assert len(up.writes()) == 1
    assert result["status"] == "updated" and result["verified"] is True
    assert "response" in result and type(result["response"]) is type(expected)
    assert result["response"] == expected


async def test_remove_asset_returns_deletion_result():
    up = Upstream({("DELETE", f"{BASE}/cases/{CASE}/assets/{ASSET}"): httpx.Response(204)})
    result = await run(up, pec.remove_protect_case_asset, CASE, ASSET)
    assert result["deleted"] is True and ASSET in result["message"]


async def test_export_prepare_returns_job_verbatim():
    job = {"id": EXPORT, "type": "CaseExport", "status": "Initial", "progressRatio": 0}
    up = Upstream({("GET", f"{BASE}/cases/{CASE}/export/prepare"): job})
    assert await run(up, pec.export_protect_case, "prepare", case_id=CASE) == job


async def test_export_download_is_base64_zip():
    raw = b"PK\x03\x04" + bytes(200)
    up = Upstream(
        {
            ("GET", f"{BASE}/cases/export/download/{EXPORT}"): httpx.Response(
                200, content=raw, headers={"content-type": "application/zip"}
            )
        }
    )
    result = await run(up, pec.export_protect_case, "download", export_id=EXPORT)
    assert base64.b64decode(result["content_base64"]) == raw
    assert result["content_type"] == "application/zip" and result["size_bytes"] == len(raw)


@pytest.mark.parametrize(
    "action,kwargs,name",
    [("prepare", {}, "case_id"), ("download", {}, "export_id")],
)
async def test_export_missing_id_fails_before_any_request(action, kwargs, name):
    up = Upstream({})
    with pytest.raises(ValueError, match=f"'{name}' must not be empty"):
        await run(up, pec.export_protect_case, action, **kwargs)
    assert up.seen == []


async def test_case_asset_snapshot_binary_and_upstream_404():
    path = f"{BASE}/cases/{CASE}/assets/{ASSET}/snapshot"
    up = Upstream(
        {
            ("GET", path): httpx.Response(
                200, content=b"\x89PNG", headers={"content-type": "image/png"}
            )
        }
    )
    result = await run(up, pec.get_protect_case_asset_snapshot, CASE, ASSET)
    assert result["image_base64"] == base64.b64encode(b"\x89PNG").decode()
    html = "<pre>Cannot GET /api/cases/x/assets/y/snapshot</pre>"
    up = Upstream({("GET", path): httpx.Response(404, text=html)})
    with pytest.raises(UniFiConnectionError, match="Cannot GET"):
        await run(up, pec.get_protect_case_asset_snapshot, CASE, ASSET)


# ---------------------------------------------------------------------- stream URLs


@pytest.mark.parametrize(
    "kind,path,kwargs,query",
    [
        ("livestream", "/ws/livestream", {"channel": 0}, {"channel": "0"}),
        (
            "playback",
            "/ws/playback",
            {"channel": 0, "start": 1_760_000_000, "end": 1_760_000_060, "stream_format": "FMP4"},
            {"channel": "0", "start": "1760000000000", "end": "1760000060000", "format": "FMP4"},
        ),
        ("timelapse", "/ws/timelapse", {"start": 1, "end": 2}, {"start": "1000", "end": "2000"}),
        (
            "heatmap",
            "/ws/heatmap",
            {"frame_duration_ms": 1000, "label": "person"},
            {"frameDurationMs": "1000", "label": "person"},
        ),
        ("live_detect_track", "/ws/liveDetectTrack", {}, {}),
        ("live_alias", "/video/live", {"channel": 1}, {"channel": "1"}),
        (
            "video_prepare",
            "/tcp/video/prepare",
            {"stream_type": "rotating", "fps": 0, "filename": "c.mp4", "lens": 0},
            {"type": "rotating", "fps": "0", "filename": "c.mp4", "lens": "0"},
        ),
    ],
)
async def test_stream_url_routes_and_only_given_params(kind, path, kwargs, query):
    body = {"url": "ws://host1.example.invalid/path1?uniqid=token-0001", "future": True}
    up = Upstream({("GET", BASE + path): body})
    assert await run(up, pec.get_protect_stream_url, kind, CAMERA, **kwargs) == body
    assert dict(up.seen[0].url.params) == {"camera": CAMERA, **query}


def _livestream_needs_channel(request: httpx.Request) -> httpx.Response:
    """Protect 7.3.70 as observed live (2026-10-28): GET ws/livestream without channel
    answers 400 {"error": "Channel is not defined"}; with channel=0 it answers 200."""
    if "channel" not in request.url.params:
        return httpx.Response(400, json={"error": "Channel is not defined"})
    return httpx.Response(200, json={"url": "wss://host1.example.invalid/ws/livestream?t=1"})


async def test_livestream_without_channel_sends_the_web_apps_default_channel_0():
    up = Upstream({("GET", f"{BASE}/ws/livestream"): _livestream_needs_channel})
    result = await run(up, pec.get_protect_stream_url, "livestream", CAMERA)
    assert result == {"url": "wss://host1.example.invalid/ws/livestream?t=1"}
    assert dict(up.seen[0].url.params) == {"camera": CAMERA, "channel": "0"}


async def test_livestream_given_channel_is_sent_unchanged():
    up = Upstream({("GET", f"{BASE}/ws/livestream"): _livestream_needs_channel})
    await run(up, pec.get_protect_stream_url, "livestream", CAMERA, channel=2)
    assert dict(up.seen[0].url.params) == {"camera": CAMERA, "channel": "2"}


async def test_only_livestream_gets_a_default_channel():
    body = {"alias": "synthetic-alias"}
    up = Upstream({("GET", f"{BASE}/video/live"): body})
    assert await run(up, pec.get_protect_stream_url, "live_alias", CAMERA) == body
    assert dict(up.seen[0].url.params) == {"camera": CAMERA}


# ------------------------------------------------------------ cross-tool properties

# One valid call per tool: (function, args, kwargs).
CALLS: dict[str, tuple[Any, tuple[Any, ...], dict[str, Any]]] = {
    "get_protect_event": (pec.get_protect_event, (EVENT,), {}),
    "get_protect_event_media": (pec.get_protect_event_media, (EVENT, "thumbnail"), {}),
    "set_protect_event_favorite": (pec.set_protect_event_favorite, (EVENT, True), {}),
    "list_protect_cases": (pec.list_protect_cases, (), {}),
    "create_protect_case": (pec.create_protect_case, ("mcp-case",), {}),
    "update_protect_case": (pec.update_protect_case, (CASE,), {"name": "n"}),
    "delete_protect_case": (pec.delete_protect_case, (CASE,), {}),
    "get_protect_case_activity": (pec.get_protect_case_activity, (CASE,), {}),
    "list_protect_case_assets": (pec.list_protect_case_assets, (CASE,), {}),
    "add_protect_case_asset": (pec.add_protect_case_asset, (CASE, CAMERA, 1, 2), {}),
    "update_protect_case_asset": (pec.update_protect_case_asset, (CASE, ASSET), {"note": "n"}),
    "remove_protect_case_asset": (pec.remove_protect_case_asset, (CASE, ASSET), {}),
    "export_protect_case": (pec.export_protect_case, ("prepare",), {"case_id": CASE}),
    "get_protect_case_asset_snapshot": (pec.get_protect_case_asset_snapshot, (CASE, ASSET), {}),
    "get_protect_stream_url": (pec.get_protect_stream_url, ("livestream", CAMERA), {}),
}


class GenericUpstream(Upstream):
    """Answers every route a tool in this module calls, shaped like the live console."""

    def __init__(self) -> None:
        super().__init__({})

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        path = req.url.path
        if req.method != "GET":
            return httpx.Response(200, json={"ok": True})
        if path.endswith("/activity-log"):
            return httpx.Response(200, json={"activities": [], "links": {"next": None}})
        if path.endswith(("/cases", "/assets")):
            return httpx.Response(200, json=[{"id": CASE, "type": "clip"}])
        if path.endswith(("/thumbnail", "/snapshot")) or "/download/" in path:
            return httpx.Response(200, content=b"\x00", headers={"content-type": "image/jpeg"})
        return httpx.Response(200, json={"id": EVENT, "isFavorite": True})


def generic_upstream() -> GenericUpstream:
    return GenericUpstream()


def test_calls_cover_every_tool():
    assert set(CALLS) == READ_TOOLS | WRITE_TOOLS


@pytest.mark.parametrize("name", sorted(CALLS))
async def test_every_tool_valid_call_reaches_upstream(name):
    fn, args, kwargs = CALLS[name]
    up = generic_upstream()
    await run(up, fn, *args, **kwargs)
    assert up.seen, name
    if name in WRITE_TOOLS:
        assert up.writes(), f"{name} sent no write"
    else:
        assert not up.writes(), f"read tool {name} sent a write"


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
async def test_dry_run_previews_every_write_and_sends_none(name):
    fn, args, kwargs = CALLS[name]
    up = generic_upstream()
    result = await run(up, fn, *args, settings={"dry_run": True}, **kwargs)
    assert up.writes() == [], name
    assert result["status"] == "dry_run", result
    assert result.get("deleted") in (None, False)
    assert "verified" not in result


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
async def test_protect_write_opt_out_refuses_with_zero_requests(name, monkeypatch):
    monkeypatch.setenv("UNIFI_PROTECT_MUTATIONS_ENABLED", "false")
    fn, args, kwargs = CALLS[name]
    up = generic_upstream()
    with pytest.raises(ValueError, match="UNIFI_PROTECT_MUTATIONS_ENABLED"):
        await run(up, fn, *args, **kwargs)
    assert up.seen == []


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
async def test_read_only_mode_refuses_every_write_before_any_request(name, monkeypatch):
    monkeypatch.setenv("UNIFI_READ_ONLY", "1")
    fn, args, kwargs = CALLS[name]
    up = generic_upstream()
    with pytest.raises(Exception, match="read-only mode"):
        await run(up, fn, *args, **kwargs)
    assert up.writes() == []
    if name.startswith("update_"):
        assert up.seen == []  # the read-before is not sent either


@pytest.mark.parametrize("name", sorted(READ_TOOLS))
async def test_read_only_mode_leaves_reads_working(name, monkeypatch):
    monkeypatch.setenv("UNIFI_READ_ONLY", "1")
    fn, args, kwargs = CALLS[name]
    up = generic_upstream()
    await run(up, fn, *args, **kwargs)
    assert up.seen


def _id_positions(name: str) -> list[int]:
    fn, args, _ = CALLS[name]
    return [i for i, a in enumerate(args) if a in (EVENT, CASE, ASSET)]


@pytest.mark.parametrize("bad", ["", "../etc", "a/b", "x y"])
@pytest.mark.parametrize("name", sorted(n for n in CALLS if _id_positions(n)))
async def test_unsafe_ids_fail_before_any_request(name, bad):
    fn, args, kwargs = CALLS[name]
    for pos in _id_positions(name):
        broken = list(args)
        broken[pos] = bad
        up = generic_upstream()
        with pytest.raises(ValueError):
            await run(up, fn, *broken, **kwargs)
        assert up.seen == [], (name, pos)


@pytest.mark.parametrize(
    "fn,args",
    [
        (pec.get_protect_event_media, (EVENT, "thumbnails")),
        (pec.get_protect_stream_url, ("ws_livestream", CAMERA)),
        (pec.export_protect_case, ("zip",)),
    ],
)
async def test_closed_choices_fail_listing_valid_values_before_any_request(fn, args):
    up = generic_upstream()
    with pytest.raises(ValidationError, match="Input should be"):
        await run(up, fn, *args)
    assert up.seen == []


async def test_multikey_data_requests_ride_the_owning_key(multikey_client, multikey_registry):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_host_id = AsyncMock(return_value="console-beta-1")
    seen: list[str | None] = []

    async def capture(path, *a, key=None, **kw):
        seen.append(key.label if key else None)
        if path.endswith("/activity-log"):
            return {"activities": [], "links": {"next": None}}
        if path.endswith(("/cases", "/assets")):
            return []
        return {}

    async def capture_binary(path, *a, key=None, **kw):
        seen.append(key.label if key else None)
        return b"\x00", "image/jpeg"

    for method in ("get", "post", "patch", "delete"):
        setattr(multikey_client, method, AsyncMock(side_effect=capture))
    multikey_client.get_binary = AsyncMock(side_effect=capture_binary)
    assert "get_protect_event" in CALLS
    for name, (fn, args, kwargs) in sorted(CALLS.items()):
        seen.clear()
        await fn(multikey_client, multikey_registry, "Beta-Branch", *args, **kwargs)
        assert seen and set(seen) == {"beta"}, (name, seen)


# --------------------------------------------------------------- registration contract


def _registered() -> dict[str, Any]:
    mcp = FastMCP("p04-test")
    pec.register(mcp, lambda: (None, None))
    res = mcp.list_tools()
    tools = asyncio.run(res) if inspect.isawaitable(res) else res
    return {t.name: t for t in tools}


def test_register_adds_exactly_the_fifteen_tools():
    assert set(_registered()) == READ_TOOLS | WRITE_TOOLS


def test_annotations_match_the_source_derived_write_set():
    tools = _registered()
    verbs = classify_tool_verbs(list(tools.values()))
    derived_writes = {name for name, v in verbs.items() if v}
    assert derived_writes == WRITE_TOOLS
    for name, tool in tools.items():
        writes = name in WRITE_TOOLS
        hints = tool.annotations.model_dump(by_alias=True)
        assert hints["readOnlyHint"] is (not writes), name
        assert hints["destructiveHint"] is writes, name


def test_every_property_is_described_and_descriptions_fit():
    tools = _registered()
    assert set(tools) == READ_TOOLS | WRITE_TOOLS
    for name, tool in tools.items():
        assert tool.description and len(tool.description) <= 2048, name
        props = (tool.parameters or {}).get("properties", {})
        assert props, name
        for prop, schema in props.items():
            assert schema.get("description"), f"{name}.{prop} has no description"


def test_object_parameters_have_a_shape():
    objects = _registered()["set_protect_event_favorite"].parameters["properties"]["objects"]
    text = json.dumps(objects)
    assert "eventId" in text and "objectId" in text


def test_write_tools_accept_and_ignore_confirm():
    tools = _registered()
    for name in WRITE_TOOLS:
        assert "confirm" in tools[name].parameters["properties"], name
    for name in READ_TOOLS:
        assert "confirm" not in tools[name].parameters["properties"], name


def test_module_has_no_unregistered_raise_sites():
    """Every pre-upstream refusal here comes from an already-registered helper
    (validate_id, require_epoch_seconds, the empty-update guard, the Protect opt-out,
    read-only mode, pydantic choice validation) or from ``_argument_grammar`` (registered
    in refusals.py), so no other function raises."""
    tree = ast.parse(Path(pec.__file__).read_text())
    raising = {
        fn.name
        for fn in ast.walk(tree)
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef)
        and any(isinstance(n, ast.Raise) for n in ast.walk(fn))
    }
    assert raising == {"_argument_grammar"}


# ------------------------------------------------------------------- secret registry


def test_stream_secret_fields_are_registry_listed():
    from unifi_fabric.route_secrets import matching

    assert pec.SECRET_RESPONSE_FIELDS == {
        "get_protect_stream_url": frozenset({"url", "directUrl", "alias"})
    }
    for path in pec._STREAM_PATH.values():
        entries = matching("GET", f"{BASE}{path}")
        assert {field for entry in entries for field in entry.response_fields} == set(
            pec.SECRET_RESPONSE_FIELDS["get_protect_stream_url"]
        )


async def test_stream_url_is_verbatim_without_redaction_opt_in():
    body = {"url": "ws://host1.example.invalid/ws/livestream?uniqid=token-0001"}
    up = Upstream({("GET", f"{BASE}/ws/heatmap"): body})
    assert await run(up, pec.get_protect_stream_url, "heatmap", CAMERA) == body


async def test_stream_url_secrets_masked_under_redact_secrets(monkeypatch):
    body = {
        "url": "ws://host.invalid/x?uniqid=token-0001",
        "directUrl": "ws://h/y",
        "alias": "p04-synthetic-alias",
    }
    up = Upstream({("GET", f"{BASE}/ws/livestream"): body})
    c, reg = await _review_real(up, redact=True)
    try:
        result = await _review_catalog_call(
            monkeypatch, c, reg, "get_protect_stream_url", kind="livestream", camera_id=CAMERA
        )
    finally:
        await c.close()
    assert all(
        result[field] == REDACTION_MASK
        for field in pec.SECRET_RESPONSE_FIELDS["get_protect_stream_url"]
    )


# ------------------------------------------------------------------ recorded fixtures


def _fixture_files() -> list[Path]:
    return sorted(FIXTURES.glob("*.json"))


def test_recorded_fixtures_exist_for_every_live_read_route():
    names = {p.stem for p in _fixture_files()}
    for required in (
        "event",
        "event_smart_detect_track",
        "cases",
        "case_activity",
        "case_assets",
        "case_export_prepare",
        "stream_livestream",
        "stream_playback",
        "stream_live_alias",
    ):
        assert required in names, required


LIST_TOOLS = {"list_protect_cases", "list_protect_case_assets"}


def _replay(rec: dict[str, Any], response: httpx.Response) -> tuple[Upstream, Any, tuple, dict]:
    route = rec["request"]["path"].split("/proxy/protect/api", 1)[1]
    up = Upstream({(rec["request"]["method"], BASE + route): response})
    return up, getattr(pec, rec["recorded_by_tool"]), tuple(rec["args"]), rec.get("kwargs", {})


@pytest.mark.parametrize("path", _fixture_files(), ids=lambda p: p.stem)
async def test_recorded_fixture_replays_through_its_tool(path):
    """Every recorded live exchange replays through the tool that recorded it: a 200 JSON
    body comes back verbatim (list tools add only result/_count), a binary body as base64
    of the same length, and an error with the upstream status and reason in the message."""
    rec = json.loads(path.read_text())
    status = rec["status"]
    if status == 200 and "body" in rec:
        up, fn, args, kwargs = _replay(rec, httpx.Response(200, json=rec["body"]))
        result = await run(up, fn, *args, **kwargs)
        body = rec["body"]
        if rec["recorded_by_tool"] in LIST_TOOLS:
            assert result == {"result": body, "_count": len(body)}
        elif rec["recorded_by_tool"] == "get_protect_case_activity":
            assert result["activities"] == body["activities"]
            assert result["_count"] == len(body["activities"])
        else:
            assert result == body
    elif status == 200:
        raw = bytes(rec["binary_len"])
        response = httpx.Response(200, content=raw, headers={"content-type": rec["content_type"]})
        up, fn, args, kwargs = _replay(rec, response)
        result = await run(up, fn, *args, **kwargs)
        assert result["size_bytes"] == rec["binary_len"]
        assert result["content_type"] == rec["content_type"]
    else:
        if "body" in rec:
            response = httpx.Response(status, json=rec["body"])
            needles = [f'"{k}"' for k in rec["body"]] if isinstance(rec["body"], dict) else []
        else:
            response = httpx.Response(status, text=rec.get("text", ""))
            needles = [rec.get("text", "").strip()[:20]]
        up, fn, args, kwargs = _replay(rec, response)
        with pytest.raises(UniFiConnectionError) as exc:
            await run(up, fn, *args, **kwargs)
        message = str(exc.value)
        assert f"HTTP {status}" in message
        for needle in needles:
            assert needle in message, needle


# Review regressions use the real production catalog and Registry. Only HTTP is mocked.
async def _review_real(up, *, redact=False, cold=False):
    from unifi_fabric.registry import Registry

    c = UniFiClient(
        Settings(api_keys=[APIKeyConfig(key="test-key", label="beta")], redact_secrets=redact)
    )
    c._clients[("beta", _key_fingerprint("test-key"))] = httpx.AsyncClient(
        base_url="https://api.ui.com", transport=httpx.MockTransport(up)
    )
    reg = Registry(c)
    if not cold:
        await reg.set_hosts([{"id": HOST, "name": "P04 NVR"}])
    return c, reg


async def _review_catalog_call(monkeypatch, c, reg, tool_name, **kwargs):
    from unifi_fabric import server

    monkeypatch.setattr(server, "_client", c)
    monkeypatch.setattr(server, "_registry", reg)
    monkeypatch.setattr(server, "_settings", c._settings)
    component = next(
        comp
        for comp in server.mcp._local_provider._components.values()
        if getattr(comp, "name", None) == tool_name
    )
    return await component.fn(host="P04 NVR", **kwargs)


async def test_review_real_server_tools_list(monkeypatch):
    from fastmcp import Client

    from unifi_fabric import server

    # tools/list advertises the domain tools in full mode; discovery (the default since
    # fe400517) advertises only the meta-tools.
    monkeypatch.setattr(server, "_settings", Settings(api_key="p04-catalog-test", tool_mode="full"))
    async with Client(server.mcp) as mcp_client:
        listed = {tool.name for tool in await mcp_client.list_tools()}
    assert READ_TOOLS | WRITE_TOOLS <= listed


@pytest.mark.parametrize("name", sorted(CALLS))
async def test_review_every_tool_uses_real_catalog_and_registry(name, monkeypatch):
    fn, args, kwargs = CALLS[name]
    up = generic_upstream()
    c, reg = await _review_real(up)
    arguments = dict(inspect.signature(fn).bind(c, reg, HOST, *args, **kwargs).arguments)
    for arg in ("client", "registry", "host"):
        arguments.pop(arg)
    try:
        await _review_catalog_call(monkeypatch, c, reg, name, **arguments)
    finally:
        await c.close()
    assert up.seen and all(req.url.path.startswith(BASE) for req in up.seen)


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
@pytest.mark.parametrize("catalog", [False, True])
async def test_review_read_only_cold_registry_has_zero_requests(name, catalog, monkeypatch):
    monkeypatch.setenv("UNIFI_READ_ONLY", "1")
    fn, args, kwargs = CALLS[name]
    up = generic_upstream()
    c, reg = await _review_real(up, cold=True)
    arguments = dict(inspect.signature(fn).bind(c, reg, HOST, *args, **kwargs).arguments)
    for arg in ("client", "registry", "host"):
        arguments.pop(arg)
    try:
        with pytest.raises(Exception, match="read-only mode"):
            if catalog:
                await _review_catalog_call(monkeypatch, c, reg, name, **arguments)
            else:
                await fn(c, reg, "P04 NVR", *args, **kwargs)
    finally:
        await c.close()
    assert up.seen == []


@pytest.mark.parametrize("kind,path", sorted(pec._STREAM_PATH.items()))
@pytest.mark.parametrize("redact", [False, True])
async def test_review_stream_fields_follow_opt_in(kind, path, redact, monkeypatch):
    body = {
        "url": "ws://synthetic.invalid/ws?uniqid=p04-url",
        "nested": {"directUrl": "ws://synthetic.invalid/direct/p04-direct", "alias": "p04-alias"},
        "ordinary": {"url": None},
        "kept": 7,
    }
    up = Upstream({("GET", f"{BASE}{path}"): body})
    c, reg = await _review_real(up, redact=redact)
    try:
        result = await _review_catalog_call(
            monkeypatch, c, reg, "get_protect_stream_url", kind=kind, camera_id=CAMERA
        )
    finally:
        await c.close()
    expected = {
        **body,
        "url": REDACTION_MASK,
        "nested": {"directUrl": REDACTION_MASK, "alias": REDACTION_MASK},
    }
    assert result == (expected if redact else body)


@pytest.mark.parametrize("kind,path", sorted(pec._STREAM_PATH.items()))
@pytest.mark.parametrize("status", [302, 400, 429, 500])
@pytest.mark.parametrize("redact", [False, True])
async def test_review_stream_http_errors_respect_redaction_policy_and_logs_mask(
    kind, path, status, redact, monkeypatch, caplog
):
    import logging

    from unifi_fabric.secret_scrub import SecretScrubFilter, secret_scope

    monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", AsyncMock())
    values = (
        "ws://synthetic.invalid/p04-url",
        "ws://synthetic.invalid/p04-direct",
        "p04-alias",
        "ws://synthetic.invalid/p04-header-only",
    )
    body = {
        "url": values[0],
        "nested": {"directUrl": values[1], "alias": values[2]},
        "error": "synthetic upstream failure",
        "echo": " ".join(values),
    }
    response = httpx.Response(status, json=body, headers={"Location": values[3]})
    up = Upstream({("GET", f"{BASE}{path}"): response})
    c, reg = await _review_real(up, redact=redact)
    try:
        with pytest.raises((UniFiConnectionError, RateLimitError)) as exc:
            await _review_catalog_call(
                monkeypatch, c, reg, "get_protect_stream_url", kind=kind, camera_id=CAMERA
            )
        logger = logging.getLogger("p04.review")
        scrub_filter = SecretScrubFilter()
        logger.addFilter(scrub_filter)
        try:
            with secret_scope(values):
                logger.warning("stream failed: %s", exc.value)
        finally:
            logger.removeFilter(scrub_filter)
        message = str(exc.value)
        assert "synthetic upstream failure" in message
        assert (not any(value in message for value in values)) is redact
        assert not any(value in caplog.text for value in values)
    finally:
        await c.close()


@pytest.mark.parametrize("redact", [False, True])
async def test_review_stream_redirect_location_only(redact, monkeypatch, caplog):
    import logging

    from unifi_fabric.secret_scrub import SecretScrubFilter, secret_scope

    secret = "ws://synthetic.invalid/p04-location-only"
    up = Upstream(
        {("GET", f"{BASE}/video/live"): httpx.Response(302, headers={"Location": secret})}
    )
    c, reg = await _review_real(up, redact=redact)
    try:
        with pytest.raises((UniFiConnectionError, RateLimitError)) as exc:
            await _review_catalog_call(
                monkeypatch, c, reg, "get_protect_stream_url", kind="live_alias", camera_id=CAMERA
            )
        logger = logging.getLogger("p04.review")
        scrub_filter = SecretScrubFilter()
        logger.addFilter(scrub_filter)
        try:
            with secret_scope((secret,)):
                logger.warning("redirect: %s", exc.value)
        finally:
            logger.removeFilter(scrub_filter)
        assert (secret not in str(exc.value)) is redact
        assert secret not in caplog.text
    finally:
        await c.close()


@pytest.mark.parametrize("asset", [False, True])
@pytest.mark.parametrize(
    "readback", ["preserved", "lost", "wrong_type", "missing_null", "wrong_number_type"]
)
async def test_review_nested_patch_preserves_and_verifies_leaves(asset, readback, monkeypatch):
    from copy import deepcopy

    before = {
        "id": ASSET if asset else CASE,
        "type": "clip",
        "otherTopLevel": 9,
        "options": {"kept": 1, "changed": 1, "deep": {"kept": None, "changed": 1}},
    }
    requested = {"options": {"changed": 2, "deep": {"changed": 2}}}
    expected = {"options": {"kept": 1, "changed": 2, "deep": {"kept": None, "changed": 2}}}
    after = {**deepcopy(before), **deepcopy(expected)}
    if readback == "lost":
        after["options"].pop("kept")
    elif readback == "wrong_type":
        after["options"]["kept"] = True
    elif readback == "missing_null":
        after["options"]["deep"].pop("kept")
    elif readback == "wrong_number_type":
        after["options"]["kept"] = 1.0
    collection = f"{BASE}/cases/{CASE}/assets" if asset else f"{BASE}/cases"
    item = f"{collection}/{ASSET if asset else CASE}"
    up = _patch_routes([before], [after], item, collection)
    c, reg = await _review_real(up)
    original_before, original_requested = deepcopy(before), deepcopy(requested)
    try:
        result = await _review_catalog_call(
            monkeypatch,
            c,
            reg,
            "update_protect_case_asset" if asset else "update_protect_case",
            case_id=CASE,
            **({"asset_id": ASSET} if asset else {}),
            fields=requested,
        )
    finally:
        await c.close()
    assert body_of(up.writes()[0]) == ({"type": "clip", **expected} if asset else expected)
    assert result["verified"] is (readback == "preserved")
    assert result["before"] == original_before and before == original_before
    assert requested == original_requested


@pytest.mark.parametrize("kind,path", sorted(pec._STREAM_PATH.items()))
@pytest.mark.parametrize("status", [302, 400, 500])
@pytest.mark.parametrize("redact", [False, True])
async def test_review_raw_error_responses_respect_redaction_policy(kind, path, status, redact):
    values = (
        "ws://synthetic.invalid/p04-raw-url",
        "p04-raw-alias",
        "ws://synthetic.invalid/p04-raw-location",
    )
    up = Upstream(
        {
            ("GET", f"{BASE}{path}"): httpx.Response(
                status,
                json={"url": values[0], "alias": values[1], "error": "synthetic failure"},
                headers={"Location": values[2]},
            )
        }
    )
    c, reg = await _review_real(up, redact=redact)
    try:
        key = await reg.resolve_key_for_host("P04 NVR")
        host = await reg.resolve_host_id("P04 NVR", key=key)
        response = await c.request(
            "GET",
            f"/v1/connector/consoles/{host}/proxy/protect/api{path}",
            key=key,
            raise_on_error=False,
            max_retries=0,
        )
    finally:
        await c.close()
    assert response.status_code == status
    assert response.json()["error"] == "synthetic failure"
    assert (
        not any(value in response.text or value in str(response.headers) for value in values)
    ) is redact


@pytest.mark.parametrize("asset", [False, True])
async def test_review_nested_noop_and_atomic_replacements(asset, monkeypatch):
    before = {
        "id": ASSET if asset else CASE,
        "type": "clip",
        "options": {"kept": 1, "array": [1, 2], "nullable": {"old": 1}, "same": 2},
    }
    requested = {"options": {"array": [3], "nullable": None}}
    after = {**before, "options": {**before["options"], "array": [3], "nullable": None}}
    collection = f"{BASE}/cases/{CASE}/assets" if asset else f"{BASE}/cases"
    item = f"{collection}/{ASSET if asset else CASE}"
    up = _patch_routes([before], [after], item, collection)
    c, reg = await _review_real(up)
    name = "update_protect_case_asset" if asset else "update_protect_case"
    ids = {"case_id": CASE, **({"asset_id": ASSET} if asset else {})}
    try:
        result = await _review_catalog_call(monkeypatch, c, reg, name, **ids, fields=requested)
        assert result["verified"] is True
        assert body_of(up.writes()[0])["options"] == after["options"]
        up.routes[("GET", collection)] = [after]
        up.seen.clear()
        result = await _review_catalog_call(
            monkeypatch, c, reg, name, **ids, fields={"options": {"same": 2}}
        )
        assert result["status"] == "noop" and up.writes() == []
    finally:
        await c.close()


@pytest.mark.parametrize("kind,path", sorted(pec._STREAM_PATH.items()))
@pytest.mark.parametrize("status", [302, 400, 429, 500])
@pytest.mark.parametrize("redact", [False, True])
async def test_review_transport_debug_headers_never_leak(
    kind, path, status, redact, monkeypatch, caplog
):
    import asyncio
    import logging
    from unittest.mock import AsyncMock

    sentinel = "ws://synthetic.invalid/p04-transport-location"
    payload = json.dumps({"error": "synthetic upstream failure"}).encode()

    async def upstream(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            f"HTTP/1.1 {status} Synthetic\r\nLocation: {sentinel}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n"
            "Connection: close\r\n\r\n".encode()
            + payload
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    listener = await asyncio.start_server(upstream, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    c, reg = await _review_real(Upstream({}), redact=redact)
    await c.close()
    c._clients[("beta", _key_fingerprint("test-key"))] = httpx.AsyncClient(
        base_url=f"http://127.0.0.1:{port}", trust_env=False
    )
    monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", AsyncMock())
    caplog.set_level(logging.DEBUG, logger="httpcore")
    try:
        with pytest.raises((UniFiConnectionError, RateLimitError)):
            await _review_catalog_call(
                monkeypatch, c, reg, "get_protect_stream_url", camera_id=CAMERA, kind=kind
            )
    finally:
        await c.close()
        listener.close()
        await listener.wait_closed()
    assert "receive_response_headers.complete" in caplog.text
    assert sentinel not in caplog.text


@pytest.mark.parametrize("value", ["probe.id:zz~9", "../etc", "a/b", "x y"])
@pytest.mark.parametrize(
    "case", ["media_camera", "stream_camera", "asset_camera", "batch_ids", "object_id"]
)
async def test_review_body_and_query_ids_pass_verbatim(case, value, monkeypatch):
    up = generic_upstream()
    c, reg = await _review_real(up)
    calls = {
        "media_camera": (
            "get_protect_event_media",
            {"event_id": EVENT, "kind": "smart_detect_track", "camera_id": value},
        ),
        "stream_camera": ("get_protect_stream_url", {"kind": "livestream", "camera_id": value}),
        "asset_camera": (
            "add_protect_case_asset",
            {"case_id": CASE, "camera_id": value, "start": 1, "end": 2},
        ),
        "batch_ids": ("set_protect_event_favorite", {"event_ids": [value], "favorite": True}),
        "object_id": (
            "set_protect_event_favorite",
            {"event_ids": EVENT, "favorite": True, "object_id": value},
        ),
    }
    name, args = calls[case]
    try:
        await _review_catalog_call(monkeypatch, c, reg, name, **args)
    finally:
        await c.close()
    sent = next(req for req in up.seen if req.url.path != "/v1/hosts")
    if case == "asset_camera":
        assert body_of(sent)["camera"] == value
    elif case == "batch_ids":
        assert body_of(sent)["ids"] == [value]
    else:
        assert sent.url.params["objectId" if case == "object_id" else "camera"] == value


@pytest.mark.parametrize("asset", [False, True])
@pytest.mark.parametrize("readback", ["replaced", "ignored"])
async def test_review_object_arrays_replace_and_verify_exactly(asset, readback, monkeypatch):
    from copy import deepcopy

    before = {
        "id": ASSET if asset else CASE,
        "type": "clip",
        "options": {
            "sibling": 3,
            "array": [{"kept": 1, "remove": 2, "nested": {"kept": 1, "remove": 2}}],
        },
    }
    requested = {"options": {"array": [{"kept": 1, "nested": {"kept": 1}}]}}
    expected = {"options": {"sibling": 3, **deepcopy(requested["options"])}}
    after = {**deepcopy(before), **deepcopy(expected)} if readback == "replaced" else before
    collection = f"{BASE}/cases/{CASE}/assets" if asset else f"{BASE}/cases"
    item = f"{collection}/{ASSET if asset else CASE}"
    up = _patch_routes([before], [after], item, collection)
    c, reg = await _review_real(up)
    try:
        result = await _review_catalog_call(
            monkeypatch,
            c,
            reg,
            "update_protect_case_asset" if asset else "update_protect_case",
            case_id=CASE,
            **({"asset_id": ASSET} if asset else {}),
            fields=requested,
        )
    finally:
        await c.close()
    assert len(up.writes()) == 1, "an object-array key removal must not be a no-op"
    assert body_of(up.writes()[0]) == ({"type": "clip", **expected} if asset else expected)
    assert result["status"] == "updated"
    assert result["verified"] is (readback == "replaced")


@pytest.mark.parametrize("asset", [False, True])
@pytest.mark.parametrize("changed", [False, True])
async def test_addressing_body_id_case_preserves_noop_and_write_verification(asset, changed):
    identity = ASSET if asset else CASE
    collection = f"{BASE}/cases/{CASE}/assets" if asset else f"{BASE}/cases"
    before = {"id": identity, "name": "same", **({"type": "clip"} if asset else {})}
    requested = {"id": identity.upper(), "name": "changed" if changed else "same"}
    after = {**before, "name": requested["name"]}
    up = _patch_routes([before], [after], f"{collection}/{identity}", collection)
    result = await run(
        up,
        pec.update_protect_case_asset if asset else pec.update_protect_case,
        CASE,
        *([ASSET.upper()] if asset else []),
        fields=requested,
    )
    if changed:
        assert result["verified"] is True
        assert body_of(up.writes()[0]) == {
            **requested,
            "id": identity,
            **({"type": "clip"} if asset else {}),
        }
    else:
        assert result["status"] == "noop" and up.writes() == []
    assert requested["id"] == identity.upper()
    assert result.get("before", result.get("resource")) == before


async def test_case_body_identity_normalization_leaves_unknown_and_nested_strings_strict():
    before = {"id": CASE, "nested": {"id": CASE}, "name": "same"}
    requested = {"id": ASSET.upper(), "nested": {"id": CASE.upper()}}
    up = _patch_routes([before], [before], f"{BASE}/cases/{CASE}", f"{BASE}/cases")
    result = await run(up, pec.update_protect_case, CASE, fields=requested)
    assert result["status"] == "updated" and result["verified"] is False
    assert body_of(up.writes()[0]) == requested


@pytest.mark.parametrize("asset", [False, True], ids=["case", "case_asset"])
@pytest.mark.parametrize("caller_uppercase", [False, True])
async def test_patch_matches_hex_ids_across_case_and_uses_upstream_spelling(
    asset, caller_uppercase
):
    item_id = ASSET if asset else CASE
    before = {"id": item_id, "note": "before", **({"type": "clip"} if asset else {})}
    after = {**before, "id": item_id.upper(), "note": "after"}
    list_path = f"{BASE}/cases/{CASE}/assets" if asset else f"{BASE}/cases"
    up = _patch_routes([before], [after], f"{list_path}/{item_id}", list_path)
    caller_id = item_id.upper() if caller_uppercase else item_id
    if asset:
        result = await run(up, pec.update_protect_case_asset, CASE, caller_id, note="after")
    else:
        result = await run(up, pec.update_protect_case, caller_id, fields={"note": "after"})
    assert result["before"] == before
    assert result["after"] == after
    assert result["verified"] is True
    assert up.writes()[0].url.path == f"{list_path}/{item_id}"
    assert body_of(up.writes()[0]) == {"note": "after", **({"type": "clip"} if asset else {})}


@pytest.mark.parametrize("favorite", [False, True])
async def test_favorite_object_verification_matches_hex_id_case(favorite):
    object_id = "00000000-0000-4000-8000-0000000000af"
    verb = "favorite" if favorite else "unfavorite"
    after = {"id": EVENT, "favoriteObjectIds": [object_id.upper()]}
    up = Upstream(
        {
            ("POST", f"{BASE}/{verb}-events/{EVENT}"): httpx.Response(204),
            ("GET", f"{BASE}/events/{EVENT}"): after,
        }
    )
    result = await run(up, pec.set_protect_event_favorite, EVENT, favorite, object_id=object_id)
    assert result["verified"] is favorite
    assert result["event"] == after


@pytest.mark.parametrize("upstream_parent_uppercase", [False, True])
@pytest.mark.parametrize("caller_asset_uppercase", [False, True])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_asset_patch_resolves_parent_case_independently_of_asset_spelling(
    upstream_parent_uppercase, caller_asset_uppercase, dry_run
):
    parent_id = CASE.upper() if upstream_parent_uppercase else CASE
    caller_parent = CASE if upstream_parent_uppercase else CASE.upper()
    caller_asset = ASSET.upper() if caller_asset_uppercase else ASSET
    collection = f"{BASE}/cases/{parent_id}/assets"
    item = f"{collection}/{ASSET}"
    before = {"id": ASSET, "type": "clip", "note": "before"}
    after = {**before, "note": "after"}
    reads = iter([[before], [after]])
    up = Upstream(
        {
            ("GET", f"{BASE}/cases"): [{"id": parent_id, "name": "synthetic-parent"}],
            ("GET", collection): lambda _req: httpx.Response(200, json=next(reads)),
            ("PATCH", item): {"ack": "verbatim"},
        }
    )
    result = await run(
        up,
        pec.update_protect_case_asset,
        caller_parent,
        caller_asset,
        fields={"note": "after"},
        settings={"dry_run": dry_run},
    )
    assert up.seen[0].url.path == f"{BASE}/cases"
    assert all(caller_parent not in req.url.path for req in up.seen)
    assert result["before"] == before
    if dry_run:
        assert result["status"] == "dry_run"
        assert up.writes() == []
        assert result["response"]["preview"]["path"] == item
        assert result["response"]["preview"]["body"] == {"type": "clip", "note": "after"}
        assert [req.url.path for req in up.seen] == [f"{BASE}/cases", collection]
    else:
        assert result["verified"] is True
        assert result["after"] == after
        assert result["response"] == {"ack": "verbatim"}
        assert [req.url.path for req in up.seen] == [f"{BASE}/cases", collection, item, collection]
        assert body_of(up.writes()[0]) == {"type": "clip", "note": "after"}


async def test_asset_patch_unknown_parent_is_sent_unchanged_for_upstream_judgment():
    unknown = "000000000000000000FA03FF"
    collection = f"{BASE}/cases/{unknown}/assets"
    item = f"{collection}/{ASSET}"
    reason = {"error": "synthetic case does not exist", "id": unknown, "detail": {"kept": True}}
    up = Upstream(
        {
            ("GET", f"{BASE}/cases"): [case()],
            ("GET", collection): [],
            ("PATCH", item): httpx.Response(404, json=reason),
        }
    )
    with pytest.raises(UniFiConnectionError) as exc:
        await run(up, pec.update_protect_case_asset, unknown, ASSET, fields={"note": "after"})
    assert "HTTP 404" in str(exc.value)
    assert "synthetic case does not exist" in str(exc.value)
    assert unknown in str(exc.value)
    assert up.writes()[0].url.path == item
    assert body_of(up.writes()[0]) == {"note": "after"}


@pytest.mark.parametrize(
    "lookup",
    [
        httpx.Response(503, json={"error": "synthetic collection unavailable"}),
        {"data": "unexpected"},
        [None],
        None,
        [],
    ],
    ids=["http_error", "wrong_envelope", "wrong_row", "null", "unlisted"],
)
async def test_asset_patch_parent_lookup_failure_falls_back_without_refusing(lookup):
    caller_parent = CASE.upper()
    collection = f"{BASE}/cases/{caller_parent}/assets"
    item = f"{collection}/{ASSET}"
    before = {"id": ASSET, "type": "clip", "note": "before"}
    after = {**before, "note": "after"}
    reads = iter([[before], [after]])
    response = {"ack": "verbatim", "future": {"kept": [None, 1]}}
    up = Upstream(
        {
            ("GET", f"{BASE}/cases"): lookup,
            ("GET", collection): lambda _req: httpx.Response(200, json=next(reads)),
            ("PATCH", item): response,
        }
    )
    result = await run(
        up, pec.update_protect_case_asset, caller_parent, ASSET.upper(), fields={"note": "after"}
    )
    assert result["verified"] is True
    assert result["response"] == response
    assert result["before"] == before and result["after"] == after
    assert [req.url.path for req in up.seen] == [f"{BASE}/cases", collection, item, collection]
    assert body_of(up.writes()[0]) == {"type": "clip", "note": "after"}


async def test_case_export_prepare_executes_in_read_only_and_dry_run(monkeypatch):
    monkeypatch.setenv("UNIFI_READ_ONLY", "1")
    path = f"{BASE}/cases/{CASE}/export/prepare"
    up = Upstream({("GET", path): {"id": EXPORT}})
    result = await run(
        up, pec.export_protect_case, "prepare", case_id=CASE, settings={"dry_run": True}
    )
    assert result == {"id": EXPORT}
    assert [req.url.path for req in up.seen] == [path]


def test_case_export_prepare_is_annotated_read_only():
    assert (
        _registered()["export_protect_case"].annotations.model_dump(by_alias=True)["readOnlyHint"]
        is True
    )
