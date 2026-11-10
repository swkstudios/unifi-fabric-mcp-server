"""Tests for the InnerSpace internal-route tools (``families/innerspace/innerspace_internal.py``).

Every tool is called through the MCP surface against a mocked ``api.ui.com`` (respx):
its console-proxy route and method, the body and query it sends, the upstream body
returned verbatim, the dry-run preview of every write, ``UNIFI_WRITE_POLICY``, and argument
validation that refuses before any request (host resolution included). All ids, titles
and values are synthetic (``tests/fixtures/innerspace_internal/synthetic.json``).
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

import tests.upstream_harness as uh
from unifi_fabric import route_secrets, server
from unifi_fabric.client import DRY_RUN_MESSAGE, UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.innerspace import innerspace_internal
from unifi_fabric.redaction import REDACTION_MASK
from unifi_fabric.registry import Registry

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "innerspace_internal" / "synthetic.json").read_text()
)
H = "console-is2-0001"
API = "https://api.ui.com"
CONSOLE = f"/v1/connector/consoles/{H}/proxy/innerspace"
IS = f"{API}{CONSOLE}"
PLAN = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
OTHER_PLAN = "4fa85f64-5717-4562-b3fc-2c963f66afa7"
TOKEN = "00000000-0000-4000-8000-000000000001"
PNG = b"\x89PNG\r\n\x1a\nsynthetic"
PNG_B64 = base64.b64encode(PNG).decode()


@pytest.fixture()
def serve(monkeypatch):
    """Install a real client and registry on the server; ``serve(dry_run=True)`` for dry-run."""

    def _install(*, dry_run: bool = False) -> None:
        if dry_run:
            monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
        settings = Settings(api_key="sk-innerspace-internal")
        client = UniFiClient(settings)
        monkeypatch.setattr(server, "_settings", settings)
        monkeypatch.setattr(server, "_client", client)
        monkeypatch.setattr(server, "_registry", Registry(client, ttl_seconds=60))

    _install()
    return _install


def _hosts(router: respx.Router) -> respx.Route:
    return router.get(f"{API}/v1/hosts").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"id": H, "type": "console", "reportedState": {"hostname": "is2-c1"}}]},
        )
    )


def _payload(res: Any) -> Any:
    """What a client receives, with FastMCP's ``{"result": ...}`` wrapper undone."""
    body = uh.result_payload(res)
    if isinstance(body, dict) and set(body) == {"result"}:
        return body["result"]
    return body


async def _call(tool: str, args: dict[str, Any]) -> Any:
    return _payload(await server.mcp.call_tool(tool, args))


def _json(request: httpx.Request) -> Any:
    return json.loads(request.content) if request.content else None


# --------------------------------------------------------------------------- route table

READS: list[tuple[str, str, Any]] = [
    ("list_innerspace_doors", "/api/access/doors", FIXTURE["doors"]),
    ("get_innerspace_stats", "/api/stats", FIXTURE["stats"]),
    ("get_innerspace_ucore_manifest", "/api/ucore/manifest", FIXTURE["ucore_manifest"]),
    ("get_innerspace_ucore_status", "/api/ucore/status", FIXTURE["ucore_status"]),
    ("get_innerspace_health", "/health", FIXTURE["health"]),
]

CAPTURES = [
    {
        "title": "Synthetic lobby",
        "files": {"topView": "top.png", "3d.gltf": "scan.gltf"},
        "devices": [{"id": "device-synthetic-1", "sku": "SKU-SYNTHETIC"}],
    }
]

# (tool, args, method, route, sent body, sent query)
WRITES: list[tuple[str, dict[str, Any], str, str, Any, dict[str, str] | None]] = [
    (
        "import_innerspace_captures",
        {"title": "Synthetic project", "site_id": "default", "captures": CAPTURES},
        "POST",
        "/api/project/import",
        {"title": "Synthetic project", "siteId": "default", "captures": CAPTURES},
        None,
    ),
    (
        "create_innerspace_plan",
        {"plan": {"type": "image", "title": "Synthetic floor", "siteId": "default"}},
        "POST",
        "/api/project/plan",
        {"type": "image", "title": "Synthetic floor", "siteId": "default"},
        None,
    ),
    (
        "reorder_innerspace_plans",
        {"plans": [{"id": PLAN, "ordering": 1}, {"id": OTHER_PLAN, "ordering": 0}]},
        "PATCH",
        "/api/project/plan/order",
        [{"id": PLAN, "ordering": 1}, {"id": OTHER_PLAN, "ordering": 0}],
        None,
    ),
    (
        "update_innerspace_project",
        {"fields": {"title": "Synthetic renamed"}},
        "PATCH",
        "/api/project",
        {"title": "Synthetic renamed"},
        None,
    ),
    (
        "update_innerspace_wall_type",
        {"wall_type": {"id": "synthetic-wall", "attenuation": 3}},
        "POST",
        "/api/project/wall-type",
        {"id": "synthetic-wall", "attenuation": 3},
        None,
    ),
    (
        "update_innerspace_attenuation_type",
        {"attenuation_type": {"id": "synthetic-cabinet", "attenuation": 6}},
        "POST",
        "/api/project/attenuation-object-type",
        {"id": "synthetic-cabinet", "attenuation": 6},
        None,
    ),
    (
        "import_innerspace_dc_shapes",
        {"site_id": "default", "body": {"shapes": []}},
        "POST",
        "/api/import/dc-shapes",
        {"shapes": []},
        {"siteId": "default"},
    ),
    (
        "retry_innerspace_plan_maps",
        {"site_id": "default"},
        "POST",
        "/api/import/retry-maps",
        None,
        {"siteId": "default"},
    ),
    (
        "import_innerspace_shared_project",
        {"token": TOKEN, "site_id": "default"},
        "POST",
        f"/api/import/projects/{TOKEN}",
        None,
        {"siteId": "default"},
    ),
    (
        "transform_innerspace_shapes",
        {"transform": {"ids": ["shape-synthetic-1"]}, "mode": "3D", "socket_id": "sock-syn-1"},
        "POST",
        "/api/shape/change",
        {"ids": ["shape-synthetic-1"], "mode": "3D"},
        {"socketId": "sock-syn-1"},
    ),
    (
        "export_innerspace_backup",
        {"directory": "/data/synthetic-backup"},
        "POST",
        "/api/ucore/backup/export",
        {"dir": "/data/synthetic-backup"},
        None,
    ),
    (
        "import_innerspace_backup",
        {"directory": "/data/synthetic-backup"},
        "POST",
        "/api/ucore/backup/import",
        {"dir": "/data/synthetic-backup"},
        None,
    ),
    (
        "create_innerspace_support_dump",
        {"directory": "/data/synthetic-support"},
        "POST",
        "/api/ucore/support-dump",
        {"dir": "/data/synthetic-support"},
        None,
    ),
    ("clean_innerspace_storage", {}, "POST", "/api/ucore/storage/clean", None, None),
]
WRITE_IDS = [w[0] for w in WRITES]

# Every tool the module registers, with one valid argument set.
VALID_ARGS: dict[str, dict[str, Any]] = {
    **{name: {} for name, _route, _body in READS},
    **{w[0]: w[1] for w in WRITES},
    "delete_innerspace_plan": {"plan_id": PLAN},
    "update_innerspace_plan_map": {"plan_id": PLAN, "fields": {"rotation": 90}},
    "update_innerspace_plan": {"plan_id": PLAN, "fields": {"title": "Synthetic renamed"}},
    "upload_innerspace_plan_asset": {
        "filename": "synthetic-floor.png",
        "content_base64": PNG_B64,
        "assets_dir": "plans",
        "content_type": "image/png",
    },
}


async def test_route_table_covers_every_module_tool():
    names = {
        tool.name
        for tool in await server_tools()
        if tool.fn.__module__ == innerspace_internal.__name__
    }
    assert names == set(VALID_ARGS)
    assert len(names) == 23


async def server_tools() -> list[Any]:
    return list(await server.mcp.list_tools())


# --------------------------------------------------------------------------- reads


@pytest.mark.parametrize(("tool", "route", "body"), READS, ids=[r[0] for r in READS])
async def test_read_returns_upstream_body_verbatim(serve, tool, route, body):
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        upstream = router.get(f"{IS}{route}").mock(return_value=httpx.Response(200, json=body))
        result = await _call(tool, {"host": H})
    assert result == body
    assert upstream.call_count == 1
    assert upstream.calls.last.request.url.query == b""


@pytest.mark.parametrize(("tool", "route", "body"), READS, ids=[r[0] for r in READS])
async def test_read_upstream_error_is_raised_in_full(serve, tool, route, body):
    reason = "synthetic upstream failure " + "x" * 600
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        router.get(f"{IS}{route}").mock(return_value=httpx.Response(503, json={"message": reason}))
        with pytest.raises(ToolError) as info:
            await _call(tool, {"host": H})
    message = str(info.value)
    assert f"{CONSOLE}{route}" in message
    assert reason in message  # never truncated


async def test_read_runs_under_read_only(serve, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        router.get(f"{IS}/api/stats").mock(return_value=httpx.Response(200, json=FIXTURE["stats"]))
        assert await _call("get_innerspace_stats", {"host": H}) == FIXTURE["stats"]


# --------------------------------------------------------------------------- writes


@pytest.mark.parametrize(
    ("tool", "args", "method", "route", "sent", "query"), WRITES, ids=WRITE_IDS
)
async def test_write_sends_route_body_query_and_returns_body_verbatim(
    serve, tool, args, method, route, sent, query
):
    answer = {"data": {"synthetic": tool}, "extra": [1, None, True]}
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        upstream = router.route(method=method, url=f"{IS}{route}").mock(
            return_value=httpx.Response(200, json=answer)
        )
        result = await _call(tool, {"host": H, **copy.deepcopy(args)})
    assert result == answer
    assert upstream.call_count == 1  # sent once
    request = upstream.calls.last.request
    assert _json(request) == sent
    assert dict(httpx.QueryParams(request.url.query)) == (query or {})


@pytest.mark.parametrize(
    ("tool", "args", "method", "route", "sent", "query"), WRITES, ids=WRITE_IDS
)
async def test_write_dry_run_returns_preview_with_body_and_query(
    serve, tool, args, method, route, sent, query
):
    serve(dry_run=True)
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        result = await _call(tool, {"host": H, **copy.deepcopy(args)})
        assert [c.request.method for c in router.calls] == ["GET"]  # host resolution only
    assert result == {
        "status": "dry_run",
        "dryRun": True,
        "sent": False,
        "message": DRY_RUN_MESSAGE,
        "preview": {
            "method": method,
            "path": f"{CONSOLE}{route}",
            "params": query,
            "body": sent,
            "keyLabel": "default",
        },
    }


@pytest.mark.parametrize("tool", sorted(set(VALID_ARGS) - {r[0] for r in READS}))
async def test_write_under_read_only_makes_zero_requests(serve, monkeypatch, tool):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    with respx.mock(assert_all_called=False) as router:
        with pytest.raises(ToolError, match="write_denied.*UNIFI_WRITE_POLICY"):
            await _call(tool, {"host": H, **copy.deepcopy(VALID_ARGS[tool])})
        assert router.calls.call_count == 0


@pytest.mark.parametrize(
    ("tool", "args", "method", "route", "sent", "query"), WRITES, ids=WRITE_IDS
)
async def test_write_upstream_error_keeps_full_reason_and_is_not_retried(
    serve, tool, args, method, route, sent, query
):
    reason = "synthetic rejection " + "y" * 700
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        upstream = router.route(method=method, url=f"{IS}{route}").mock(
            return_value=httpx.Response(500, json={"error": reason})
        )
        with pytest.raises(ToolError) as info:
            await _call(tool, {"host": H, **copy.deepcopy(args)})
    assert upstream.call_count == 1
    assert reason in str(info.value)


@pytest.mark.parametrize("tool", ["export_innerspace_backup", "import_innerspace_backup"])
@pytest.mark.parametrize("status", [401, 403])
async def test_ucore_backup_auth_rejection_passes_upstream_reason(serve, tool, status):
    reason = "synthetic: console session required for ucore backup"
    route = "export" if tool.startswith("export") else "import"
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        router.post(f"{IS}/api/ucore/backup/{route}").mock(
            return_value=httpx.Response(status, json={"code": "unauthorized", "message": reason})
        )
        with pytest.raises(ToolError) as info:
            await _call(tool, {"host": H, "directory": "/data/synthetic-backup"})
    assert reason in str(info.value)
    assert str(status) in str(info.value)


async def test_import_backup_is_never_refused_by_the_server(serve):
    """No confirm gate: a restore is sent when called, ``confirm`` accepted and ignored."""
    for confirm in (False, True):
        with respx.mock(assert_all_called=False) as router:
            _hosts(router)
            upstream = router.post(f"{IS}/api/ucore/backup/import").mock(
                return_value=httpx.Response(200, json={"ok": True})
            )
            result = await _call(
                "import_innerspace_backup",
                {"host": H, "directory": "/data/synthetic-backup", "confirm": confirm},
            )
        assert result == {"ok": True}
        assert upstream.call_count == 1


async def test_write_non_json_body_is_returned_verbatim(serve):
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        router.post(f"{IS}/api/ucore/storage/clean").mock(
            return_value=httpx.Response(200, text="cleaned 0 files (synthetic)")
        )
        assert await _call("clean_innerspace_storage", {"host": H}) == (
            "cleaned 0 files (synthetic)"
        )


# --------------------------------------------------------------------------- delete


def _project_read(router: respx.Router) -> respx.Route:
    """The plan collection read a list-first delete resolves the plan id in."""
    return router.get(f"{IS}/integration/v1/project").mock(
        return_value=httpx.Response(200, json=_project())
    )


async def test_delete_plan_returns_canonical_deletion_result(serve):
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        _project_read(router)
        upstream = router.delete(f"{IS}/api/project/plan/{PLAN}").mock(
            return_value=httpx.Response(200, json=FIXTURE["plan_deleted"])
        )
        result = await _call("delete_innerspace_plan", {"host": H, "plan_id": PLAN})
    assert upstream.call_count == 1
    assert result == {
        "deleted": True,
        "message": f"InnerSpace plan {PLAN} deleted.",
        "response": FIXTURE["plan_deleted"],
    }


async def test_delete_plan_empty_body_is_canonical_with_none_response(serve):
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        _project_read(router)
        router.delete(f"{IS}/api/project/plan/{PLAN}").mock(return_value=httpx.Response(204))
        result = await innerspace_internal.delete_innerspace_plan(
            server._client, server._registry, H, PLAN
        )
    assert result == {
        "deleted": True,
        "message": f"InnerSpace plan {PLAN} deleted.",
        "response": None,
    }


async def test_delete_plan_dry_run_is_the_preview_never_deleted(serve):
    serve(dry_run=True)
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        _project_read(router)
        result = await _call("delete_innerspace_plan", {"host": H, "plan_id": PLAN})
    # A delete returns the deletion_result dry-run shape with the preview under response.
    assert result["status"] == "dry_run" and result["deleted"] is False and result["message"]
    preview = result["response"]
    assert preview["status"] == "dry_run" and preview["dryRun"] is True
    assert preview["preview"]["method"] == "DELETE"
    assert preview["preview"]["path"] == f"{CONSOLE}/api/project/plan/{PLAN}"
    assert "_deleted" not in result and "_deleted" not in preview


async def test_delete_plan_unknown_plan_lists_valid_ids_without_writing(serve):
    missing = "6fa85f64-5717-4562-b3fc-2c963f66afa9"
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        _project_read(router)
        delete = router.delete(url__regex=rf"{IS}/api/project/plan/.*")
        with pytest.raises(ToolError) as info:
            await _call("delete_innerspace_plan", {"host": H, "plan_id": missing})
    assert delete.call_count == 0
    assert missing in str(info.value)
    assert PLAN in str(info.value) and OTHER_PLAN in str(info.value)


async def test_delete_plan_deletes_the_upstream_id_spelling(serve):
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        _project_read(router)
        delete = router.delete(f"{IS}/api/project/plan/{PLAN}").mock(
            return_value=httpx.Response(200, json=FIXTURE["plan_deleted"])
        )
        await _call("delete_innerspace_plan", {"host": H, "plan_id": PLAN.upper()})
    assert delete.call_count == 1


# ------------------------------------------------------- plan map (list-first)


async def test_plan_map_resolves_the_plan_then_sends_fields_verbatim(serve):
    answer = {"data": {"synthetic": "map"}, "extra": [1, None, True]}
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        read = _project_read(router)
        upstream = router.patch(f"{IS}/api/project/plan/{PLAN}/map").mock(
            return_value=httpx.Response(200, json=answer)
        )
        result = await _call(
            "update_innerspace_plan_map", {"host": H, "plan_id": PLAN, "fields": {"rotation": 90}}
        )
    assert result == answer
    assert read.call_count == 1 and upstream.call_count == 1  # resolved, then sent once
    assert _json(upstream.calls.last.request) == {"rotation": 90}


async def test_plan_map_dry_run_is_the_preview_after_the_resolution_read(serve):
    serve(dry_run=True)
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        _project_read(router)
        result = await _call(
            "update_innerspace_plan_map", {"host": H, "plan_id": PLAN, "fields": {"rotation": 90}}
        )
        assert {c.request.method for c in router.calls} == {"GET"}  # reads only
    assert result == {
        "status": "dry_run",
        "dryRun": True,
        "sent": False,
        "message": DRY_RUN_MESSAGE,
        "preview": {
            "method": "PATCH",
            "path": f"{CONSOLE}/api/project/plan/{PLAN}/map",
            "params": None,
            "body": {"rotation": 90},
            "keyLabel": "default",
        },
    }


async def test_plan_map_upstream_error_keeps_full_reason_and_is_not_retried(serve):
    reason = "synthetic rejection " + "y" * 700
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        _project_read(router)
        upstream = router.patch(f"{IS}/api/project/plan/{PLAN}/map").mock(
            return_value=httpx.Response(500, json={"error": reason})
        )
        with pytest.raises(ToolError) as info:
            await _call(
                "update_innerspace_plan_map",
                {"host": H, "plan_id": PLAN, "fields": {"rotation": 90}},
            )
    assert upstream.call_count == 1
    assert reason in str(info.value)


async def test_plan_map_unknown_plan_lists_valid_ids_without_writing(serve):
    missing = "6fa85f64-5717-4562-b3fc-2c963f66afa9"
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        _project_read(router)
        patch = router.patch(url__regex=rf"{IS}/api/project/plan/.*")
        with pytest.raises(ToolError) as info:
            await _call(
                "update_innerspace_plan_map",
                {"host": H, "plan_id": missing, "fields": {"rotation": 90}},
            )
    assert patch.call_count == 0
    assert missing in str(info.value)
    assert PLAN in str(info.value) and OTHER_PLAN in str(info.value)


async def test_plan_map_patches_the_upstream_id_spelling(serve):
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        _project_read(router)
        patch = router.patch(f"{IS}/api/project/plan/{PLAN}/map").mock(
            return_value=httpx.Response(200, json={})
        )
        await _call(
            "update_innerspace_plan_map",
            {"host": H, "plan_id": PLAN.upper(), "fields": {"rotation": 90}},
        )
    assert patch.call_count == 1


# --------------------------------------------------------------------------- upload


async def test_upload_sends_decoded_file_and_assets_dir(serve):
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        upstream = router.post(f"{IS}/api/project/plan/upload").mock(
            return_value=httpx.Response(200, json={"data": {"url": "/assets/synthetic.png"}})
        )
        result = await _call(
            "upload_innerspace_plan_asset",
            {"host": H, **VALID_ARGS["upload_innerspace_plan_asset"]},
        )
    assert result == {"data": {"url": "/assets/synthetic.png"}}
    request = upstream.calls.last.request
    assert request.headers["content-type"].startswith("multipart/form-data")
    content = request.content
    assert PNG in content  # the decoded bytes, not the base64 text
    assert PNG_B64.encode() not in content
    assert b'name="files"; filename="synthetic-floor.png"' in content
    assert b"Content-Type: image/png" in content
    assert b'name="assetsDir"' in content and b"plans" in content


async def test_upload_accepts_line_broken_base64(serve):
    wrapped = "\n".join(PNG_B64[i : i + 8] for i in range(0, len(PNG_B64), 8))
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        upstream = router.post(f"{IS}/api/project/plan/upload").mock(
            return_value=httpx.Response(200, json={})
        )
        await _call(
            "upload_innerspace_plan_asset",
            {"host": H, "filename": "f.png", "content_base64": wrapped, "assets_dir": "plans"},
        )
    assert PNG in upstream.calls.last.request.content


async def test_upload_dry_run_previews_parts_without_content(serve):
    serve(dry_run=True)
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        result = await _call(
            "upload_innerspace_plan_asset",
            {"host": H, **VALID_ARGS["upload_innerspace_plan_asset"]},
        )
    assert result["status"] == "dry_run" and result["dryRun"] is True
    assert result["preview"]["path"] == f"{CONSOLE}/api/project/plan/upload"
    assert result["preview"]["params"] is None
    parts = {part["field"]: part for part in result["preview"]["multipart"]}
    assert parts["files"] == {
        "field": "files",
        "filename": "synthetic-floor.png",
        "contentType": "image/png",
        "sizeBytes": len(PNG),
    }
    assert result["_form"] == {"assetsDir": "plans"}
    assert PNG_B64 not in json.dumps(result)


@pytest.mark.parametrize("bad", ["not base64!", "abc", "data:image/png;base64,iVBORw0KGgo="])
async def test_upload_rejects_non_base64_before_any_request(serve, bad):
    with respx.mock(assert_all_called=False) as router:
        with pytest.raises(ToolError, match="content_base64 is not valid base64"):
            await _call(
                "upload_innerspace_plan_asset",
                {"host": H, "filename": "f.png", "content_base64": bad, "assets_dir": "plans"},
            )
        assert router.calls.call_count == 0


# --------------------------------------------------------------------------- validation


UUID_ARGS = [
    ("delete_innerspace_plan", "plan_id"),
    ("update_innerspace_plan_map", "plan_id"),
    ("update_innerspace_plan", "plan_id"),
    ("import_innerspace_shared_project", "token"),
]


@pytest.mark.parametrize(("tool", "arg"), UUID_ARGS)
@pytest.mark.parametrize(
    "bad",
    [
        "not-a-uuid",
        "../plan",
        f"{PLAN}/extra",
        f"{PLAN}\n",
        "",
        "3fa85f64571745621b3fc2c963f66afa6",
    ],
)
async def test_path_ids_must_be_uuids_before_any_request(serve, tool, arg, bad):
    args = {"host": H, **copy.deepcopy(VALID_ARGS[tool]), arg: bad}
    with respx.mock(assert_all_called=False) as router:
        with pytest.raises(ToolError) as info:
            await _call(tool, args)
        assert router.calls.call_count == 0
    assert f"Invalid InnerSpace '{arg}': expected a UUID" in str(info.value)
    if bad:
        assert bad.strip() not in str(info.value).split("(got ", 1)[1]  # never echoed


EMPTY_UPDATES = [
    ("create_innerspace_plan", "plan", {}),
    ("update_innerspace_plan_map", "fields", {}),
    ("update_innerspace_project", "fields", {}),
    ("update_innerspace_plan", "fields", {}),
    ("update_innerspace_wall_type", "wall_type", {}),
    ("update_innerspace_attenuation_type", "attenuation_type", {}),
    ("transform_innerspace_shapes", "transform", {}),
    ("update_innerspace_project", "fields", {"_note": "additive only"}),
]


@pytest.mark.parametrize(("tool", "arg", "empty"), EMPTY_UPDATES)
async def test_empty_update_is_refused_before_any_request(serve, tool, arg, empty):
    args = {"host": H, **copy.deepcopy(VALID_ARGS[tool]), arg: empty}
    with respx.mock(assert_all_called=False) as router:
        with pytest.raises(ToolError, match="No fields provided"):
            await _call(tool, args)
        assert router.calls.call_count == 0


SITE_ARGS = [
    ("import_innerspace_captures", "site_id"),
    ("import_innerspace_dc_shapes", "site_id"),
    ("retry_innerspace_plan_maps", "site_id"),
    ("import_innerspace_shared_project", "site_id"),
    ("transform_innerspace_shapes", "socket_id"),
]


@pytest.mark.parametrize(("tool", "arg"), SITE_ARGS)
@pytest.mark.parametrize("bad", ["", "   ", "default\n", " default"])
async def test_selector_query_values_are_checked_before_any_request(serve, tool, arg, bad):
    args = {"host": H, **copy.deepcopy(VALID_ARGS[tool]), arg: bad}
    with respx.mock(assert_all_called=False) as router:
        with pytest.raises(ToolError) as info:
            await _call(tool, args)
        assert router.calls.call_count == 0
    assert repr(arg) in str(info.value)  # names the tool argument, not the wire name


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("import_innerspace_captures", {"captures": ["not-an-object"]}),
        ("reorder_innerspace_plans", {"plans": "not-a-list"}),
        ("create_innerspace_plan", {"plan": ["not", "an", "object"]}),
        ("export_innerspace_backup", {"directory": 7}),
    ],
)
async def test_mistyped_arguments_are_refused_before_any_request(serve, tool, args):
    with respx.mock(assert_all_called=False) as router:
        with pytest.raises(ToolError):
            await _call(tool, {"host": H, **copy.deepcopy(VALID_ARGS[tool]), **args})
        assert router.calls.call_count == 0


async def test_unknown_host_fails_listing_choices_without_a_write(serve):
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        write = router.post(f"{IS}/api/ucore/storage/clean")
        with pytest.raises(ToolError) as info:
            await _call("clean_innerspace_storage", {"host": "no-such-console"})
    assert write.call_count == 0
    assert "is2-c1" in str(info.value) or H in str(info.value)


@pytest.mark.parametrize("tool", sorted(VALID_ARGS))
async def test_confirm_is_accepted_and_ignored(serve, tool):
    tools = {t.name: t for t in await server_tools()}
    props = tools[tool].parameters.get("properties", {})
    if tool in {r[0] for r in READS}:
        assert "confirm" not in props
        return
    assert props["confirm"]["default"] is False
    serve(dry_run=True)
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        router.get(f"{IS}/integration/v1/project").mock(
            return_value=httpx.Response(200, json=copy.deepcopy(FIXTURE["project"]))
        )
        for confirm in (False, True):
            result = await _call(
                tool, {"host": H, **copy.deepcopy(VALID_ARGS[tool]), "confirm": confirm}
            )
            assert result["status"] == "dry_run"


# --------------------------------------------------------------------------- shared token


def test_shared_project_token_is_a_registered_tool_credential():
    """The share token is listed once, centrally, so the call-scoped scrub covers it."""
    entries = [
        e for e in route_secrets.ROUTE_SECRETS if e.name == "innerspace-shared-project-token"
    ]
    assert len(entries) == 1
    entry = entries[0]
    assert entry.matches("POST", f"{CONSOLE}/api/import/projects/{TOKEN}?siteId=default")
    assert not entry.matches("GET", f"{CONSOLE}/api/import/projects/{TOKEN}")
    args = {"host": H, "token": TOKEN, "site_id": "default"}
    assert route_secrets.tool_call_secrets("import_innerspace_shared_project", args) == (TOKEN,)


# --------------------------------------------------------------------------- update plan


def _project(**plan_changes: Any) -> dict[str, Any]:
    project = copy.deepcopy(FIXTURE["project"])
    project["data"]["plans"][0].update(plan_changes)
    return project


async def test_update_plan_reads_merges_patches_and_verifies(serve):
    before = _project(location={"lat": 0, "lng": 0, "label": "synthetic"})
    after = _project(title="Synthetic renamed", location={"lat": 0, "lng": 0, "label": "new"})
    answer = {"data": {"id": PLAN, "title": "Synthetic renamed"}}
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        read = router.get(f"{IS}/integration/v1/project").mock(
            side_effect=[httpx.Response(200, json=before), httpx.Response(200, json=after)]
        )
        patch = router.patch(f"{IS}/api/project/plan/{PLAN}").mock(
            return_value=httpx.Response(200, json=answer)
        )
        result = await _call(
            "update_innerspace_plan",
            {
                "host": H,
                "plan_id": PLAN,
                "fields": {"title": "Synthetic renamed", "location": {"label": "new"}},
            },
        )
    assert read.call_count == 2
    sent = _json(patch.calls.last.request)
    expected = copy.deepcopy(before["data"]["plans"][0])
    expected.update(title="Synthetic renamed", location={"lat": 0, "lng": 0, "label": "new"})
    assert sent == expected  # whole plan, nested object merged key by key
    assert result == {**answer, "_verified": True}


async def test_update_plan_reports_unverified_when_the_read_after_differs(serve):
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        router.get(f"{IS}/integration/v1/project").mock(
            side_effect=[
                httpx.Response(200, json=_project()),
                httpx.Response(200, json=_project(visible=1)),
            ]
        )
        router.patch(f"{IS}/api/project/plan/{PLAN}").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        result = await _call(
            "update_innerspace_plan",
            {"host": H, "plan_id": PLAN, "fields": {"visible": False}},
        )
    assert result == {"ok": True, "_verified": False}


async def test_update_plan_read_after_failure_is_unknown_with_reason(serve):
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        router.get(f"{IS}/integration/v1/project").mock(
            side_effect=[
                httpx.Response(200, json=_project()),
                httpx.Response(500, json={"message": "synthetic read-after failure"}),
            ]
        )
        router.patch(f"{IS}/api/project/plan/{PLAN}").mock(
            return_value=httpx.Response(200, json=[1, 2])
        )
        result = await _call(
            "update_innerspace_plan", {"host": H, "plan_id": PLAN, "fields": {"title": "X"}}
        )
    assert result["response"] == [1, 2]
    assert result["_verified"] is None
    assert "synthetic read-after failure" in result["_readAfterError"]


async def test_update_plan_already_applied_is_a_no_op_without_writing(serve):
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        router.get(f"{IS}/integration/v1/project").mock(
            return_value=httpx.Response(200, json=_project())
        )
        patch = router.patch(f"{IS}/api/project/plan/{PLAN}")
        result = await _call(
            "update_innerspace_plan", {"host": H, "plan_id": PLAN, "fields": {"title": "Ground"}}
        )
    assert patch.call_count == 0
    assert result == {
        **FIXTURE["project"]["data"]["plans"][0],
        "_noOp": True,
        "_verified": True,
        "_note": "no change needed",
    }


async def test_update_plan_type_strict_bool_over_int_is_a_change(serve):
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        router.get(f"{IS}/integration/v1/project").mock(
            side_effect=[
                httpx.Response(200, json=_project(visible=1)),
                httpx.Response(200, json=_project(visible=True)),
            ]
        )
        patch = router.patch(f"{IS}/api/project/plan/{PLAN}").mock(
            return_value=httpx.Response(200, json={})
        )
        result = await _call(
            "update_innerspace_plan", {"host": H, "plan_id": PLAN, "fields": {"visible": True}}
        )
    assert patch.call_count == 1
    assert result["_verified"] is True


async def test_update_plan_unknown_plan_lists_valid_ids_without_writing(serve):
    missing = "6fa85f64-5717-4562-b3fc-2c963f66afa9"
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        router.get(f"{IS}/integration/v1/project").mock(
            return_value=httpx.Response(200, json=_project())
        )
        patch = router.patch(url__regex=rf"{IS}/api/project/plan/.*")
        with pytest.raises(ToolError) as info:
            await _call(
                "update_innerspace_plan", {"host": H, "plan_id": missing, "fields": {"title": "X"}}
            )
    assert patch.call_count == 0
    assert PLAN in str(info.value) and OTHER_PLAN in str(info.value)


async def test_update_plan_patches_the_upstream_id_spelling(serve):
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        router.get(f"{IS}/integration/v1/project").mock(
            side_effect=[
                httpx.Response(200, json=_project()),
                httpx.Response(200, json=_project(title="Synthetic renamed")),
            ]
        )
        patch = router.patch(f"{IS}/api/project/plan/{PLAN}").mock(
            return_value=httpx.Response(200, json={})
        )
        result = await _call(
            "update_innerspace_plan",
            {"host": H, "plan_id": PLAN.upper(), "fields": {"title": "Synthetic renamed"}},
        )
        assert patch.call_count == 1
    assert result["_verified"] is True


async def test_update_plan_falls_back_to_the_legacy_project_route(serve):
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        router.get(f"{IS}/integration/v1/project").mock(
            return_value=httpx.Response(403, json={"message": "forbidden: host not found"})
        )
        legacy = router.get(f"{IS}/api/project").mock(
            side_effect=[
                httpx.Response(200, json=_project()),
                httpx.Response(200, json=_project(title="Synthetic renamed")),
            ]
        )
        router.patch(f"{IS}/api/project/plan/{PLAN}").mock(
            return_value=httpx.Response(200, json={})
        )
        result = await _call(
            "update_innerspace_plan",
            {"host": H, "plan_id": PLAN, "fields": {"title": "Synthetic renamed"}},
        )
        assert legacy.call_count == 2
    assert result["_verified"] is True


async def test_update_plan_masked_field_is_not_sent_and_is_reported(serve, monkeypatch):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")
    serve()
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        router.get(f"{IS}/integration/v1/project").mock(
            side_effect=[
                httpx.Response(200, json=_project()),
                httpx.Response(200, json=_project(title="Synthetic renamed")),
            ]
        )
        patch = router.patch(f"{IS}/api/project/plan/{PLAN}").mock(
            return_value=httpx.Response(200, json={})
        )
        result = await _call(
            "update_innerspace_plan",
            {
                "host": H,
                "plan_id": PLAN,
                "fields": {"title": "Synthetic renamed", "password": REDACTION_MASK},
            },
        )
        sent = _json(patch.calls.last.request)
    assert "password" not in sent and sent["title"] == "Synthetic renamed"
    assert result["_redactedFieldsNotSent"] == ["password"]


async def test_reorder_refuses_an_empty_list_before_any_request(serve):
    with respx.mock(assert_all_called=False) as router:
        upstream = router.patch(f"{IS}/api/project/plan/order").mock(
            return_value=httpx.Response(200, json={"data": []})
        )
        with pytest.raises(ToolError, match="plans is an empty list"):
            await _call("reorder_innerspace_plans", {"host": H, "plans": []})
        assert not upstream.called


async def test_update_plan_unexpected_project_shape_names_it(serve):
    with respx.mock(assert_all_called=False) as router:
        _hosts(router)
        router.get(f"{IS}/integration/v1/project").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {"plans": "synthetic", "shapes": [], "products": [], "wallTypes": []}
                },
            )
        )
        with pytest.raises(ToolError, match="expected 'plans' to be an array"):
            await _call(
                "update_innerspace_plan", {"host": H, "plan_id": PLAN, "fields": {"title": "X"}}
            )


async def test_update_plan_dry_run_previews_the_merged_patch(serve):
    serve(dry_run=True)
    with respx.mock(assert_all_called=True) as router:
        _hosts(router)
        read = router.get(f"{IS}/integration/v1/project").mock(
            return_value=httpx.Response(200, json=_project())
        )
        result = await _call(
            "update_innerspace_plan",
            {"host": H, "plan_id": PLAN, "fields": {"title": "Ground"}},  # already applied
        )
    assert read.call_count == 1  # read-before only; no read-after under dry-run
    assert result["status"] == "dry_run"
    assert result["preview"]["method"] == "PATCH"
    assert result["preview"]["body"] == FIXTURE["project"]["data"]["plans"][0]
    assert "_verified" not in result


# --------------------------------------------------------------------------- multi-key


def _wire_hosts(multikey_client: UniFiClient) -> None:
    async def _paginate(path, *, key=None):
        return {
            "alpha": [{"id": "console-alpha-1", "name": "Alpha-HQ"}],
            "beta": [{"id": "console-beta-1", "name": "Beta-Branch"}],
        }[key.label]

    multikey_client.paginate = AsyncMock(side_effect=_paginate)  # type: ignore[method-assign]


async def test_read_routes_beta_host_on_beta_key(multikey_client, multikey_registry):
    _wire_hosts(multikey_client)
    captured: dict[str, Any] = {}

    async def _get(path, *, key=None, params=None):
        captured.update(key=key.label, path=path)
        return FIXTURE["doors"]

    multikey_client.get = AsyncMock(side_effect=_get)  # type: ignore[method-assign]
    result = await innerspace_internal.list_innerspace_doors(
        multikey_client, multikey_registry, "Beta-Branch"
    )
    assert result == FIXTURE["doors"]
    assert captured == {
        "key": "beta",
        "path": "/v1/connector/consoles/console-beta-1/proxy/innerspace/api/access/doors",
    }


async def test_write_routes_beta_host_on_beta_key(multikey_client, multikey_registry):
    _wire_hosts(multikey_client)
    captured: dict[str, Any] = {}

    async def _post(path, *, key=None, json=None, params=None):
        captured.update(key=key.label, path=path, json=json, params=params)
        return {"ok": True}

    multikey_client.post = AsyncMock(side_effect=_post)  # type: ignore[method-assign]
    result = await innerspace_internal.retry_innerspace_plan_maps(
        multikey_client, multikey_registry, "Beta-Branch", "default"
    )
    assert result == {"ok": True}
    assert captured["key"] == "beta"
    assert "console-beta-1" in captured["path"]
    assert captured["params"] == {"siteId": "default"}


async def test_update_plan_routes_beta_host_on_beta_key(multikey_client, multikey_registry):
    _wire_hosts(multikey_client)
    keys: list[tuple[str, str]] = []
    project = copy.deepcopy(FIXTURE["project"])

    async def _get(path, *, key=None, params=None):
        keys.append(("GET", key.label))
        return project

    async def _patch(path, *, key=None, json=None, params=None):
        keys.append(("PATCH", key.label))
        assert "console-beta-1" in path
        project["data"]["plans"][0].update(json)
        return {"ok": True}

    multikey_client.get = AsyncMock(side_effect=_get)  # type: ignore[method-assign]
    multikey_client.patch = AsyncMock(side_effect=_patch)  # type: ignore[method-assign]
    result = await innerspace_internal.update_innerspace_plan(
        multikey_client, multikey_registry, "Beta-Branch", PLAN, {"title": "Synthetic renamed"}
    )
    assert result == {"ok": True, "_verified": True}
    assert keys == [("GET", "beta"), ("PATCH", "beta"), ("GET", "beta")]


async def test_doors_502_preserves_upstream_error_and_adds_hint():
    client = AsyncMock()
    registry = AsyncMock()
    from unifi_fabric.client import UniFiHTTPError

    client.get.side_effect = UniFiHTTPError("HTTP 502 from GET /api/access/doors: []", status=502)
    with pytest.raises(UniFiHTTPError) as caught:
        await innerspace_internal.list_innerspace_doors(client, registry, "example")
    assert caught.value.status == 502
    assert str(caught.value) == (
        "HTTP 502 from GET /api/access/doors: []; "
        "door listing requires the UniFi Access app on the console"
    )


async def test_manifest_403_preserves_error_and_explains_console_access():
    from unifi_fabric.client import UniFiHTTPError

    client = AsyncMock()
    registry = AsyncMock()
    client.get.side_effect = UniFiHTTPError("HTTP 403: access denied", status=403)
    with pytest.raises(UniFiHTTPError) as caught:
        await innerspace_internal.get_innerspace_ucore_manifest(client, registry, "example")
    # A 403 without errors.ucore.access is not the proxy refusal: no claim about the proxy.
    assert str(caught.value) == "HTTP 403: access denied"
    assert caught.value.status == 403


async def test_manifest_403_ucore_access_names_the_proxy_refusal_not_the_key():
    """Network/InnerSpace console: GET innerspace/api/ucore/manifest answers 403
    errors.ucore.access 'Access denied for proxy' while ucore/status answers 200."""
    from unifi_fabric.client import UniFiHTTPError

    upstream = (
        "HTTP 403 from GET /api/ucore/manifest: "
        '{"error":{"type":"access","code":"errors.ucore.access",'
        '"message":"Access denied for proxy","errors":[]}}'
    )
    client = AsyncMock()
    registry = AsyncMock()
    client.get.side_effect = UniFiHTTPError(upstream, status=403)
    with pytest.raises(UniFiHTTPError) as caught:
        await innerspace_internal.get_innerspace_ucore_manifest(client, registry, "example")
    message = str(caught.value)
    assert message.startswith(upstream + "; ")
    assert "refuses this route via the connector proxy" in message
    assert "the key is not the cause and you cannot fix it here" in message
    assert "ignore the key hint" not in message
    assert "get_innerspace_ucore_status" in message
    assert "check console permissions" not in message
    assert caught.value.status == 403
