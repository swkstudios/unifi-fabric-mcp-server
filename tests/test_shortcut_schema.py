"""Per-type shortcut wire contracts; all upstream requests are hermetic.

Linked bodies and type literals: official unifi-protect apt package 5.3.48
(SHA256 cd2f88e273e89161e1a9a742b4da9f8c2f708f53c415d6bf36b200164f10d454),
UI 5.3.18 f5afa0f4eccbb98bfb70.531.js Shortcuts builder at offset 2741234.
Webhook timeout: Protect 7.3.74 rr070 AJV required-property error. The complete
webhook recipe retains its explicit nullable headers/body/auth and name/url/method.
"""

from contextlib import asynccontextmanager
from copy import deepcopy

import pytest
import respx
from httpx import Response

from tests.test_protect_ptz_doorbell import CAM, PRIVATE, SC1, _client, _registry, _sent
from unifi_fabric.families.protect import protect_ptz_doorbell as p02

LINKED_CAMERA = {"type": "linkedCamera", "linkedCameraId": "0000000000000000000000c2"}
LINKED_DOOR = {"type": "linkedDoor", "linkedDoorId": "0000000000000000000000d2"}
WEBHOOK = {
    "type": "webhook",
    "name": "probe-inert",
    "url": "https://example.invalid/",
    "method": "GET",
    "headers": None,
    "body": None,
    "auth": None,
    "timeout": 1,
}
SHAPES = [LINKED_CAMERA, LINKED_DOOR, WEBHOOK]


@asynccontextmanager
async def _test_client():
    client = _client()
    try:
        yield client
    finally:
        await client.close()


def _element(inner):
    return {"placement": {"x": 0, "y": 1}, "shortcut": deepcopy(inner)}


@pytest.mark.parametrize("inner", SHAPES, ids=lambda x: x["type"])
async def test_create_each_type_exact_wire_body(inner):
    element = _element(inner)
    original = deepcopy(element)
    async with _test_client() as client:
        with respx.mock as router:
            route = router.post(f"{PRIVATE}/cameras/{CAM}/shortcuts").respond(200, json=[element])
            result = await p02.create_camera_shortcut(
                client, _registry(), "probe-console", CAM, element, validate_schema=True
            )
    assert _sent(route) == [original]
    assert element == original
    assert result == {"status": "created", "response": [original]}


@pytest.mark.parametrize("inner", SHAPES, ids=lambda x: x["type"])
async def test_update_each_type_exact_wire_body(inner):
    before = {"id": SC1, **_element(inner)}
    after = {**before, "placement": {"x": 2, "y": 3}}
    async with _test_client() as client:
        with respx.mock as router:
            router.get(f"{PRIVATE}/cameras/{CAM}").mock(
                side_effect=[
                    Response(200, json={"id": CAM, "shortcuts": [before]}),
                    Response(200, json={"id": CAM, "shortcuts": [after]}),
                ]
            )
            route = router.patch(f"{PRIVATE}/cameras/{CAM}/shortcuts").respond(200, json=[after])
            result = await p02.update_camera_shortcut(
                client, _registry(), "probe-console", CAM, after, validate_schema=True
            )
    assert _sent(route) == [after]
    assert result["verified"] is True
    assert result["response"] == [after]


@pytest.mark.parametrize("inner", SHAPES, ids=lambda x: x["type"])
async def test_trigger_each_type_exact_bodyless_route(inner):
    camera = {"id": CAM, "shortcuts": [{"id": SC1, **_element(inner)}]}
    async with _test_client() as client:
        with respx.mock as router:
            router.get(f"{PRIVATE}/cameras/{CAM}").respond(200, json=camera)
            route = router.post(f"{PRIVATE}/cameras/{CAM}/shortcuts/{SC1}/click").respond(
                200, json={"accepted": True}
            )
            result = await p02.trigger_camera_shortcut(
                client, _registry(), "probe-console", CAM, SC1
            )
    assert route.call_count == 1
    assert route.calls.last.request.content == b""
    assert result == {"status": "sent", "response": {"accepted": True}}


@pytest.mark.parametrize("inner", SHAPES, ids=lambda x: x["type"])
async def test_delete_each_type_exact_bodyless_query_route(inner):
    camera = {"id": CAM, "shortcuts": [{"id": SC1, **_element(inner)}]}
    async with _test_client() as client:
        with respx.mock as router:
            router.get(f"{PRIVATE}/cameras/{CAM}").respond(200, json=camera)
            route = router.delete(f"{PRIVATE}/cameras/{CAM}/shortcuts").respond(204)
            result = await p02.delete_camera_shortcut(
                client, _registry(), "probe-console", CAM, [SC1]
            )
    assert route.calls.last.request.url.params.multi_items() == [("shortcutIds", SC1)]
    assert route.calls.last.request.content == b""
    assert result["deleted"] is True


@pytest.mark.parametrize("inner", SHAPES, ids=lambda x: x["type"])
@pytest.mark.parametrize("update", [False, True])
async def test_missing_per_type_fields_refused_before_any_request(inner, update):
    element = _element(inner)
    fields = [field for field in inner if field != "type"]
    for field in fields:
        element["shortcut"].pop(field)
    if update:
        element["id"] = SC1
    async with _test_client() as client:
        with respx.mock as router:
            function = p02.update_camera_shortcut if update else p02.create_camera_shortcut
            with pytest.raises(ValueError) as error:
                await function(
                    client, _registry(), "probe-console", CAM, element, validate_schema=True
                )
            assert not router.calls
    assert all(field in str(error.value) for field in fields)


@pytest.mark.parametrize(
    "element,match",
    [
        ({}, "placement, shortcut"),
        ({"placement": None, "shortcut": LINKED_CAMERA}, "placement"),
        ({"placement": {}, "shortcut": LINKED_CAMERA}, "placement.x, placement.y"),
        ({"placement": {"x": True, "y": 1}, "shortcut": LINKED_CAMERA}, "placement.x"),
        ({"placement": {"x": 0, "y": 0}, "shortcut": None}, "type"),
        (_element({"type": "unknown"}), "linkedCamera, linkedDoor, or webhook"),
        (_element({**LINKED_CAMERA, "linkedCameraId": ""}), "linkedCameraId"),
        (_element({**WEBHOOK, "timeout": True}), "timeout"),
    ],
)
def test_invalid_complete_requests_report_fields(element, match):
    with pytest.raises(ValueError, match=match):
        p02._validate_shortcut_element(element)


def test_validated_partial_update_requires_id_but_no_unmodified_fields():
    with pytest.raises(ValueError, match="id"):
        p02._validate_shortcut_element({"placement": {"x": 1, "y": 0}}, update=True)
    p02._validate_shortcut_element({"id": SC1, "placement": {"x": 1, "y": 0}}, update=True)


def test_validated_unknown_fields_are_preserved():
    element = _element({**WEBHOOK, "futureField": {"nested": [1, 2]}})
    original = deepcopy(element)
    p02._validate_shortcut_element(element)
    assert element == original
