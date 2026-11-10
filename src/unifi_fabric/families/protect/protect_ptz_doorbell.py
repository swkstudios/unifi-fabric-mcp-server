"""UniFi Protect PTZ control, PTZ presets and patrols, camera shortcuts, camera calibration
and doorbell ringtone / credential (NFC card, fingerprint) enrollment.

Route choice (official > private). The official Protect Integration API pinned in
``tests/fixtures/spec_drift/baseline_snapshot.json`` (protect 7.3.74) has exactly three PTZ
routes: ``POST /v1/cameras/{id}/ptz/goto/{slot}``, ``.../ptz/patrol/start/{slot}`` and
``.../ptz/patrol/stop``, already served by ``ptz_goto_preset`` / ``ptz_patrol_start`` /
``ptz_patrol_stop`` (``families/protect/protect.py``). ``ptz_home`` reuses that official goto helper with
the home slot -1. No other capability here has an official route, so every other tool uses
the private ``/proxy/protect/api`` route the Protect web app calls (route inventory
``tests/fixtures/private_api/inventory_protect_5.3.18.json``, Protect UI bundle 5.3.18,
module ``f5afa0f4eccbb98bfb70.531.js``).

Request bodies the bundle builds dynamically (PTZ move, preset and patrol create/update,
shortcut create/update, NFC assign) accept free-form objects sent as given. Shortcut
create/update also offer opt-in validation of known per-type shapes without adding keys.
The bundle names the keys of
two bodies: ``{open}`` for the event PTZ control window and ``{fingerprintId, ulpId}`` for a
fingerprint assignment.

Every response body is passed through verbatim (server pass-through invariant). Physical
actions (move, home, calibrate, ringtone test, shortcut trigger) are sent once and never
auto-retried on HTTP 429 (the client's one retry rule: only a GET is retried).

Validation before any request uses only the server's registered refusals (path-safe ids,
the empty-update guard, the Protect write opt-out and read-only mode, and pydantic
validation of the closed ``credential_type`` / ``step`` choices). A preset or patrol slot,
or a shortcut id, that the camera's own list does not contain fails after that list is read,
listing the valid choices (the upstream-judged ``lookup-miss`` refusal). Shortcut schema
checks run locally only when the caller opts in with ``validate_schema=True``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from fastmcp import FastMCP
from pydantic import StrictBool, TypeAdapter

from ...client import UniFiClient, is_dry_run_preview, path_segment
from ...config import APIKeyConfig
from ...matching import same_id, with_upstream_id
from ...read_only import guard_action
from ...registry import Registry
from ...selector_args import check_selector
from ...shared_shapes._results import (
    deletion_result,
    requested_leaves_match,
    safe_read_after,
    short_circuit_no_op,
)
from ...tool_annotations import WRITE
from .protect import (
    _as_list,
    _dry_run_result,
    _fields_to_send,
    _private,
    _require_mutations,
    _require_object,
    _resolve,
    _updated,
    _write_result,
    ptz_goto,
)

#: The PTZ home position is preset slot -1 on the official goto route (Protect 7.3.74
#: ``POST /v1/cameras/{id}/ptz/goto/{slot}``; ``ptz_goto_preset`` documents -1 as home).
PTZ_HOME_SLOT = -1

CredentialType = Literal["nfc", "fingerprint"]
EnrollStep = Literal["enroll", "assign", "cancel"]

_CREDENTIAL_TYPE = TypeAdapter(CredentialType)
_ENROLL_STEP = TypeAdapter(EnrollStep)
_STRICT_BOOL = TypeAdapter(StrictBool)


def _camera(camera_id: str) -> str:
    """``camera_id`` validated and encoded as one path segment (no request is made)."""
    return path_segment(camera_id, "camera_id")


def _start_write(method: str) -> None:
    """The Protect write opt-out and read-only mode, before any resolution or request."""
    _require_mutations()
    guard_action(method)


def _merge(current: Any, requested: Any) -> Any:
    """Read-merge-write: requested object leaves over the current object, recursively.

    Objects merge key by key so a partial nested update keeps the current siblings;
    arrays, null and scalars replace the current value as given."""
    if isinstance(current, dict) and isinstance(requested, dict):
        merged = dict(current)
        for key, value in requested.items():
            merged[key] = _merge(current.get(key), value)
        return merged
    return requested


def _merged_body(before: dict[str, Any] | None, fields: dict[str, Any]) -> dict[str, Any]:
    """The PATCH body: each requested field merged over the current record's value."""
    if before is None:
        return fields
    return {key: _merge(before.get(key), value) for key, value in fields.items()}


# --- PTZ slots (presets and patrols) ----------------------------------------------------


def _is_slot(value: Any, slot: int) -> bool:
    """True for an integer slot equal to ``slot`` (a bool is never a slot)."""
    return type(value) is int and value == slot


def _slot_of(record: Any) -> int | None:
    """A record's integer ``slot`` (a bool is never a slot), or None when it has none."""
    slot = record.get("slot") if isinstance(record, dict) else None
    return slot if type(slot) is int else None


def _slot_record(records: list[Any], slot: int) -> dict[str, Any] | None:
    """The record whose ``slot`` is ``slot``, or None."""
    for record in records:
        if isinstance(record, dict) and _is_slot(record.get("slot"), slot):
            return record
    return None


def _require_slot(records: list[Any], slot: int, kind: str, camera_id: str) -> dict[str, Any]:
    """The listed record of ``slot``; an unlisted slot fails listing the valid slots.

    Only records that carry an integer ``slot`` count as choices. When the list carries
    none (no slot to compare against), nothing is refused here and the upstream judges
    the slot: an empty dict is returned so the caller sends the write without a
    read-before record.
    """
    record = _slot_record(records, slot)
    if record is not None:
        return record
    slots = [slot for slot in map(_slot_of, records) if slot is not None]
    if slots:
        raise ValueError(
            f"PTZ {kind} slot {slot} not found on camera {camera_id!r}; valid: {slots}. "
            f"List them with GET cameras/{{id}}/ptz/{kind} (the slot field)."
        )
    return {}


async def _ptz_list(
    client: UniFiClient, key: APIKeyConfig | None, host_id: str, camera_seg: str, kind: str
) -> tuple[str, list[Any]]:
    """GET the camera's PTZ preset or patrol list (a bare array): (path, records)."""
    path = _private(host_id, f"/cameras/{camera_seg}/ptz/{kind}")
    return path, _as_list(await client.get(path, key=key), f"GET {path}")


async def _verified_update(
    client: UniFiClient,
    key: APIKeyConfig | None,
    read_path: str,
    write_path: str,
    before: dict[str, Any] | None,
    fields: dict[str, Any],
    locate: Callable[[Any], dict[str, Any] | None],
    what: str,
    *,
    array_body: bool = False,
) -> dict[str, Any]:
    """PATCH with read-before / no-op / read-merge-write / type-strict read-after verify.

    ``before`` is the record read before the write (None when it could not be located;
    the write is then sent as given and the read-after may still locate it). Every
    requested leaf already equal skips the write (``status: "noop"``). The PATCH body is
    the requested fields merged over the current record (current nested siblings kept).
    The read-after GETs ``read_path`` and ``locate`` picks the record; ``verified`` is true
    only when every requested leaf matches, type-strict, null with ``readAfterError``
    when the read-after failed or the record could not be located.
    """
    if before is not None and short_circuit_no_op(client, requested_leaves_match(fields, before)):
        return {
            "status": "noop",
            "reason": "all requested fields already match the current values; no write sent",
            "resource": before,
        }
    body = fields if array_body else _merged_body(before, fields)
    response = await client.patch(write_path, key=key, json=[body] if array_body else body)
    if is_dry_run_preview(response):
        return _dry_run_result(before, response)

    async def _read() -> dict[str, Any]:
        found = locate(await client.get(read_path, key=key))
        if found is None:
            raise LookupError(f"{what} not found in the read-after of GET {read_path}")
        return found

    after, error = await safe_read_after(_read)
    return _updated(fields, before, after, response, error)


async def move_ptz_camera(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    movement: dict[str, Any],
) -> dict[str, Any]:
    """Move a PTZ camera (private ``POST /cameras/{id}/move``); the body is sent as given."""
    camera_seg = _camera(camera_id)
    _start_write("POST")
    key, host_id = await _resolve(registry, host)
    path = _private(host_id, f"/cameras/{camera_seg}/move")
    response = await client.post(path, key=key, json=movement)
    return _write_result("sent", response)


async def ptz_home(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> dict[str, Any]:
    """Move a PTZ camera to its home position: the official goto route with slot -1."""
    _camera(camera_id)
    _start_write("POST")
    return await ptz_goto(client, registry, host, camera_id, PTZ_HOME_SLOT)


async def set_ptz_event_control_window(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, open_window: bool
) -> dict[str, Any]:
    """Open or close the camera's event PTZ control window (``{open}``)."""
    camera_seg = _camera(camera_id)
    open_window = _STRICT_BOOL.validate_python(open_window)
    _start_write("POST")
    key, host_id = await _resolve(registry, host)
    path = _private(host_id, f"/cameras/{camera_seg}/ptz/eventPtzControlWindow")
    response = await client.post(path, key=key, json={"open": open_window})
    return _write_result("sent", response)


async def _create_ptz_slot(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    kind: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    """Create a PTZ preset or patrol (``POST /cameras/{id}/ptz/{kind}``), body as given."""
    camera_seg = _camera(camera_id)
    _start_write("POST")
    key, host_id = await _resolve(registry, host)
    path = _private(host_id, f"/cameras/{camera_seg}/ptz/{kind}")
    response = await client.post(path, key=key, json=body)
    return _write_result("created", response)


async def _update_ptz_slot(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    kind: str,
    slot: int,
    fields: dict[str, Any],
) -> dict[str, Any]:
    """Update a PTZ preset or patrol by slot, verified through the camera's slot list."""
    camera_seg = _camera(camera_id)
    _start_write("PATCH")
    fields = _fields_to_send(fields, f"PTZ {kind}")
    key, host_id = await _resolve(registry, host)
    list_path, records = await _ptz_list(client, key, host_id, camera_seg, kind)
    before = _require_slot(records, slot, kind, camera_id) or None

    def _locate(body: Any) -> dict[str, Any] | None:
        return _slot_record(_as_list(body, f"GET {list_path}"), slot)

    return await _verified_update(
        client,
        key,
        list_path,
        _private(host_id, f"/cameras/{camera_seg}/ptz/{kind}/{slot}"),
        before,
        fields,
        _locate,
        f"PTZ {kind} slot {slot}",
    )


async def _delete_ptz_slot(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    kind: str,
    slot: int,
) -> dict[str, Any]:
    """Delete a PTZ preset or patrol by slot (``DELETE /cameras/{id}/ptz/{kind}/{slot}``)."""
    camera_seg = _camera(camera_id)
    _start_write("DELETE")
    key, host_id = await _resolve(registry, host)
    _list_path, records = await _ptz_list(client, key, host_id, camera_seg, kind)
    _require_slot(records, slot, kind, camera_id)
    response = await client.delete(
        _private(host_id, f"/cameras/{camera_seg}/ptz/{kind}/{slot}"), key=key
    )
    return deletion_result(f"PTZ {kind} slot {slot} deleted from camera {camera_id}.", response)


async def create_ptz_patrol(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, patrol: dict[str, Any]
) -> dict[str, Any]:
    """Create a PTZ patrol (``POST /cameras/{id}/ptz/patrol``)."""
    return await _create_ptz_slot(client, registry, host, camera_id, "patrol", patrol)


async def update_ptz_patrol(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    slot: int,
    fields: dict[str, Any],
) -> dict[str, Any]:
    """Update a PTZ patrol (``PATCH /cameras/{id}/ptz/patrol/{slot}``), verified."""
    return await _update_ptz_slot(client, registry, host, camera_id, "patrol", slot, fields)


async def delete_ptz_patrol(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, slot: int
) -> dict[str, Any]:
    """Delete a PTZ patrol (``DELETE /cameras/{id}/ptz/patrol/{slot}``)."""
    return await _delete_ptz_slot(client, registry, host, camera_id, "patrol", slot)


async def create_ptz_preset(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, preset: dict[str, Any]
) -> dict[str, Any]:
    """Create a PTZ preset (``POST /cameras/{id}/ptz/preset``)."""
    return await _create_ptz_slot(client, registry, host, camera_id, "preset", preset)


async def update_ptz_preset(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    slot: int,
    fields: dict[str, Any],
) -> dict[str, Any]:
    """Update a PTZ preset (``PATCH /cameras/{id}/ptz/preset/{slot}``), verified."""
    return await _update_ptz_slot(client, registry, host, camera_id, "preset", slot, fields)


async def delete_ptz_preset(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, slot: int
) -> dict[str, Any]:
    """Delete a PTZ preset (``DELETE /cameras/{id}/ptz/preset/{slot}``)."""
    return await _delete_ptz_slot(client, registry, host, camera_id, "preset", slot)


# --- Camera shortcuts ---------------------------------------------------------------------


def _shortcut_list(camera: Any) -> list[Any] | None:
    """The camera's ``shortcuts`` array, or None when the camera object carries none."""
    if isinstance(camera, dict) and isinstance(camera.get("shortcuts"), list):
        return list(camera["shortcuts"])
    return None


def _shortcut_record(records: list[Any] | None, shortcut_id: Any) -> dict[str, Any] | None:
    """The shortcut whose ``id`` names ``shortcut_id`` (:func:`same_id`), or None."""
    if not isinstance(shortcut_id, str):
        return None
    for record in records or []:
        if isinstance(record, dict) and same_id(shortcut_id, record.get("id")):
            return record
    return None


def _shortcut_id_of(record: Any) -> str | None:
    """A shortcut record's string ``id``, or None when it has none."""
    sid = record.get("id") if isinstance(record, dict) else None
    return sid if isinstance(sid, str) else None


def _require_shortcuts(
    records: list[Any] | None, shortcut_ids: list[str], camera_id: str
) -> list[str]:
    """``shortcut_ids`` in the upstream spelling, each a listed shortcut of the camera, or
    fail listing them.

    Ids match by :func:`same_id` (a hex/UUID id in another case names the same shortcut)
    and are returned as the camera lists them. Only a camera object that carries a
    ``shortcuts`` array with ids can refuse; without one nothing is refused, the ids are
    returned as given and the upstream judges them."""
    known = [sid for sid in map(_shortcut_id_of, records or []) if sid is not None]
    if not known:
        return list(shortcut_ids)
    upstream = {sid: next((k for k in known if same_id(sid, k)), None) for sid in shortcut_ids}
    missing = [sid for sid, match in upstream.items() if match is None]
    if missing:
        raise ValueError(
            f"Camera shortcut {missing[0]!r} not found on camera {camera_id!r}; valid: {known}. "
            "Read the camera with GET cameras/{id} (its shortcuts[].id)."
        )
    return [upstream[sid] or sid for sid in shortcut_ids]


def _listed_camera_seg(camera: dict[str, Any], camera_id: str, camera_seg: str) -> str:
    """The camera path segment in the spelling the camera object reports for its own id
    (:func:`same_id`), else ``camera_seg`` unchanged."""
    listed = camera.get("id")
    if isinstance(listed, str) and listed != camera_id and same_id(camera_id, listed):
        return path_segment(listed, "camera_id")
    return camera_seg


async def _read_camera(
    client: UniFiClient, key: APIKeyConfig | None, host_id: str, camera_seg: str
) -> tuple[str, dict[str, Any]]:
    """GET the private camera object (``/cameras/{id}``): (path, camera)."""
    path = _private(host_id, f"/cameras/{camera_seg}")
    return path, _require_object(await client.get(path, key=key), f"GET {path}")


def _validate_shortcut_element(element: dict[str, Any], *, update: bool = False) -> None:
    """Check known per-type requests without rewriting caller data.

    Linked types: Protect UI 5.3.18, f5afa0f4eccbb98bfb70.531.js, linked enum
    and Shortcuts create/onSelect builders (official apt package 5.3.48).
    Webhook: Protect 7.3.74 schema-validation rejection identifies timeout; the complete
    acceptance recipe supplies name/url/method/headers/body/auth as well.
    """
    if not isinstance(element, dict):
        raise ValueError("camera shortcut must be an object")
    missing = []
    if update and "id" not in element:
        missing.append("id")
    if not update and "placement" not in element:
        missing.append("placement")
    if not update and "shortcut" not in element:
        missing.append("shortcut")
    if missing:
        raise ValueError(f"camera shortcut is missing required fields: {', '.join(missing)}")
    if update and (not isinstance(element["id"], str) or not element["id"]):
        raise ValueError("camera shortcut id must be a non-empty string")
    if "placement" in element:
        placement = element["placement"]
        if not isinstance(placement, dict):
            raise ValueError("shortcut.placement must be an object with x and y")
        missing = [f"placement.{axis}" for axis in ("x", "y") if axis not in placement]
        if missing:
            raise ValueError(f"camera shortcut is missing required fields: {', '.join(missing)}")
        for axis in ("x", "y"):
            if type(placement[axis]) not in (int, float):
                raise ValueError(f"shortcut.placement.{axis} must be a number")
    if "shortcut" not in element:
        return
    inner = element["shortcut"]
    if not isinstance(inner, dict):
        raise ValueError("shortcut.shortcut must be an object with a type")
    kind = inner.get("type")
    required = {
        "linkedCamera": ("linkedCameraId",),
        "linkedDoor": ("linkedDoorId",),
        "webhook": ("name", "url", "method", "headers", "body", "auth", "timeout"),
    }
    if not isinstance(kind, str) or kind not in required:
        raise ValueError("shortcut.shortcut.type must be linkedCamera, linkedDoor, or webhook")
    missing = [field for field in required[kind] if field not in inner]
    if missing:
        raise ValueError(f"{kind} shortcut is missing required fields: {', '.join(missing)}")
    string_fields = {
        "linkedCamera": ("linkedCameraId",),
        "linkedDoor": ("linkedDoorId",),
        "webhook": ("name", "url", "method"),
    }
    for field in string_fields[kind]:
        if not isinstance(inner[field], str) or not inner[field]:
            raise ValueError(f"{kind} shortcut {field} must be a non-empty string")
    if kind == "webhook" and type(inner["timeout"]) not in (int, float):
        raise ValueError("webhook shortcut timeout must be a number")


async def create_camera_shortcut(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    shortcut: dict[str, Any],
    validate_schema: bool = False,
) -> dict[str, Any]:
    """Create a camera shortcut (``POST /cameras/{id}/shortcuts``), wrapped in an array."""
    if validate_schema:
        _validate_shortcut_element(shortcut)
    camera_seg = _camera(camera_id)
    _start_write("POST")
    key, host_id = await _resolve(registry, host)
    path = _private(host_id, f"/cameras/{camera_seg}/shortcuts")
    response = await client.post(path, key=key, json=[shortcut])
    return _write_result("created", response)


def _shortcut_label(shortcut_id: Any) -> str:
    """How a read-after names the shortcut it looks for."""
    if isinstance(shortcut_id, str):
        return f"Camera shortcut {shortcut_id!r}"
    return "Camera shortcut (the body carries no string id to locate it by)"


async def update_camera_shortcut(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    body: dict[str, Any],
    validate_schema: bool = False,
) -> dict[str, Any]:
    """Update camera shortcuts (``PATCH /cameras/{id}/shortcuts``), verified when locatable."""
    if validate_schema:
        _validate_shortcut_element(body, update=True)
    camera_seg = _camera(camera_id)
    _start_write("PATCH")
    body = _fields_to_send(body, "camera shortcut")
    key, host_id = await _resolve(registry, host)
    camera_path, camera = await _read_camera(client, key, host_id, camera_seg)
    camera_seg = _listed_camera_seg(camera, camera_id, camera_seg)
    camera_path = _private(host_id, f"/cameras/{camera_seg}")
    records = _shortcut_list(camera)
    shortcut_id = body.get("id")
    if isinstance(shortcut_id, str):
        shortcut_id = _require_shortcuts(records, [shortcut_id], camera_id)[0]
        # A body id naming the shortcut in another spelling is sent as the camera lists it.
        body = with_upstream_id(body, "id", shortcut_id)
    before = _shortcut_record(records, shortcut_id)

    def _locate(read: Any) -> dict[str, Any] | None:
        return _shortcut_record(
            _shortcut_list(_require_object(read, f"GET {camera_path}")), shortcut_id
        )

    return await _verified_update(
        client,
        key,
        camera_path,
        _private(host_id, f"/cameras/{camera_seg}/shortcuts"),
        before,
        body,
        _locate,
        _shortcut_label(shortcut_id),
        array_body=True,
    )


async def delete_camera_shortcut(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, shortcut_ids: list[str]
) -> dict[str, Any]:
    """Delete camera shortcuts (``DELETE /cameras/{id}/shortcuts?shortcutIds=...``).

    An empty ``shortcut_ids`` list is rejected before any request (it would address no shortcut).
    """
    if not isinstance(shortcut_ids, list) or not shortcut_ids:
        raise ValueError(
            "shortcut_ids must be a non-empty list of shortcut ids (the camera's shortcuts[].id "
            "from get_camera); nothing was sent."
        )
    camera_seg = _camera(camera_id)
    ids = list(shortcut_ids)
    for index, shortcut_id in enumerate(ids):
        check_selector(f"shortcut_ids[{index}]", shortcut_id)
    _start_write("DELETE")
    key, host_id = await _resolve(registry, host)
    _path, camera = await _read_camera(client, key, host_id, camera_seg)
    camera_seg = _listed_camera_seg(camera, camera_id, camera_seg)
    ids = _require_shortcuts(_shortcut_list(camera), ids, camera_id)
    response = await client.delete(
        _private(host_id, f"/cameras/{camera_seg}/shortcuts"),
        key=key,
        params={"shortcutIds": ids},
    )
    return deletion_result(f"Shortcut(s) {ids} deleted from camera {camera_id}.", response)


async def trigger_camera_shortcut(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, shortcut_id: str
) -> dict[str, Any]:
    """Run a camera shortcut (``POST /cameras/{id}/shortcuts/{shortcutId}/click``)."""
    camera_seg = _camera(camera_id)
    shortcut_seg = path_segment(shortcut_id, "shortcut_id")
    _start_write("POST")
    key, host_id = await _resolve(registry, host)
    _path, camera = await _read_camera(client, key, host_id, camera_seg)
    camera_seg = _listed_camera_seg(camera, camera_id, camera_seg)
    listed = _require_shortcuts(_shortcut_list(camera), [shortcut_id], camera_id)[0]
    if listed != shortcut_id:
        shortcut_seg = path_segment(listed, "shortcut_id")
    response = await client.post(
        _private(host_id, f"/cameras/{camera_seg}/shortcuts/{shortcut_seg}/click"), key=key
    )
    return _write_result("sent", response)


# --- Calibration and doorbell ---------------------------------------------------------------


async def _camera_action(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, action: str
) -> dict[str, Any]:
    """POST a body-less camera action (``/cameras/{id}/<action>``), sent once."""
    camera_seg = _camera(camera_id)
    _start_write("POST")
    key, host_id = await _resolve(registry, host)
    response = await client.post(_private(host_id, f"/cameras/{camera_seg}/{action}"), key=key)
    return _write_result("sent", response)


async def calibrate_camera(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> dict[str, Any]:
    """Start a camera calibration (``POST /cameras/{id}/calibrate``)."""
    return await _camera_action(client, registry, host, camera_id, "calibrate")


async def test_doorbell_ringtone(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> dict[str, Any]:
    """Play the doorbell's ringtone once (``POST /cameras/{id}/test-ringtone``)."""
    return await _camera_action(client, registry, host, camera_id, "test-ringtone")


# The name starts with ``test_``: keep pytest from collecting it when a test module
# imports this function directly.
test_doorbell_ringtone.__test__ = False  # type: ignore[attr-defined]


async def enroll_doorbell_credential(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    credential_type: str,
    step: str = "enroll",
    fingerprint_id: str | None = None,
    ulp_id: str | None = None,
    fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Doorbell NFC / fingerprint enrollment: start, assign the read credential, or cancel."""
    camera_seg = _camera(camera_id)
    kind = _CREDENTIAL_TYPE.validate_python(credential_type)
    stage = _ENROLL_STEP.validate_python(step)
    assign_only = [
        name
        for name, value in (
            ("fingerprint_id", fingerprint_id),
            ("ulp_id", ulp_id),
            ("fields", fields),
        )
        if value is not None
    ]
    if stage != "assign" and assign_only:
        raise ValueError(
            f"{', '.join(assign_only)} only apply to step 'assign', not step {stage!r}; "
            "nothing was sent."
        )
    for name, value in (("fingerprint_id", fingerprint_id), ("ulp_id", ulp_id)):
        if value is not None:
            check_selector(name, value)
    _start_write("POST")
    body: dict[str, Any] | None = None
    if stage == "assign":
        body = dict(fields or {})
        if fingerprint_id is not None:
            body["fingerprintId"] = fingerprint_id
        if ulp_id is not None:
            body["ulpId"] = ulp_id
    key, host_id = await _resolve(registry, host)
    path = _private(host_id, f"/cameras/{camera_seg}/{kind}/{stage}")
    response = await client.post(path, key=key, json=body)
    status = {"enroll": "enrolling", "assign": "assigned", "cancel": "cancelled"}[stage]
    return _write_result(status, response)


async def delete_doorbell_credential(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    credential_type: str,
    credential_id: str,
) -> dict[str, Any]:
    """Delete an enrolled NFC card or fingerprint (``DELETE /cameras/{id}/{type}/{credId}``)."""
    camera_seg = _camera(camera_id)
    kind = _CREDENTIAL_TYPE.validate_python(credential_type)
    credential_seg = path_segment(credential_id, "credential_id")
    _start_write("DELETE")
    key, host_id = await _resolve(registry, host)
    response = await client.delete(
        _private(host_id, f"/cameras/{camera_seg}/{kind}/{credential_seg}"), key=key
    )
    return deletion_result(f"Doorbell {kind} credential deleted from camera {camera_id}.", response)


# Module-level aliases: the registered tools below shadow these names inside register().
_move_ptz_camera = move_ptz_camera
_ptz_home = ptz_home
_set_ptz_event_control_window = set_ptz_event_control_window
_create_ptz_patrol = create_ptz_patrol
_update_ptz_patrol = update_ptz_patrol
_delete_ptz_patrol = delete_ptz_patrol
_create_ptz_preset = create_ptz_preset
_update_ptz_preset = update_ptz_preset
_delete_ptz_preset = delete_ptz_preset
_create_camera_shortcut = create_camera_shortcut
_update_camera_shortcut = update_camera_shortcut
_delete_camera_shortcut = delete_camera_shortcut
_trigger_camera_shortcut = trigger_camera_shortcut
_calibrate_camera = calibrate_camera
_test_doorbell_ringtone = test_doorbell_ringtone
_enroll_doorbell_credential = enroll_doorbell_credential
_delete_doorbell_credential = delete_doorbell_credential


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register this module's tools on ``mcp`` (called once by the server)."""

    @mcp.tool(annotations=WRITE)
    async def move_ptz_camera(
        host: str, camera_id: str, movement: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Move a PTZ camera (pan, tilt, zoom), as the Protect web app's PTZ joystick does.

        Sends movement as given to POST cameras/{camera_id}/move on the Protect console
        host. The web app builds this body at run time and no published schema documents
        it, so no key is required or added; the console validates it and its error is
        returned in full. To go to a saved position use ptz_goto_preset; to return home use
        ptz_home. Returns {status: "sent", response}. Sent once, never auto-retried on 429.
        With dry-run policy, returns {status: "dry_run", response (the preview)} and sends no
        write.

        Dry-run response previews include body and params.

        Consequence: the camera physically moves, so its view and any running patrol or
        auto-tracking change at once.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            movement: Movement object sent as given (free-form; shape not published); for
                example {"type": "continuous", "payload": {"x": 10, "y": 0, "z": 0}}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _move_ptz_camera(client, registry, host, camera_id, movement)

    @mcp.tool(annotations=WRITE)
    async def ptz_home(host: str, camera_id: str, confirm: bool = False) -> dict[str, Any]:
        """Move a PTZ camera to its home position.

        Uses the official Protect Integration route POST /v1/cameras/{camera_id}/ptz/goto/-1 (slot
        -1 is the home preset), the same call as ptz_goto_preset with slot -1, on the Protect
        console host. Returns {status: "sent", response}. Sent once, never auto-retried on 429. With
        dry-run policy, returns {status: "dry_run", response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: the camera physically moves to its home position, interrupting any
        manual view or running patrol.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _ptz_home(client, registry, host, camera_id)

    @mcp.tool(annotations=WRITE)
    async def set_ptz_event_control_window(
        host: str, camera_id: str, open_window: bool, confirm: bool = False
    ) -> dict[str, Any]:
        """Open or close a PTZ camera's event PTZ control window.

        Sends {open: open_window} to POST cameras/{camera_id}/ptz/eventPtzControlWindow on
        the Protect console host, the call the Protect web app makes (UI bundle 5.3.18 names
        the open key). Returns {status: "sent", response} with the console's answer
        verbatim. With dry-run policy, returns {status: "dry_run", response (the preview)} and
        sends no write.

        Dry-run response previews include body and params.

        Consequence: changes how the PTZ camera reacts to events while the window is open
        (the console defines the effect); close it with open_window false.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            open_window: true opens the window, false closes it (sent as open); for example
                true.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _set_ptz_event_control_window(client, registry, host, camera_id, open_window)

    @mcp.tool(annotations=WRITE)
    async def create_ptz_patrol(
        host: str, camera_id: str, patrol: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Create a PTZ patrol (a tour through saved presets) on a PTZ camera.

        Sends patrol as given to POST cameras/{camera_id}/ptz/patrol on the Protect console host. No
        published schema documents the body; patrol records the console lists carry name, slot
        (0-4), presets (preset slots), presetDurationSeconds and presetMovementSpeed. Returns
        {status: "created", response}. Start it with ptz_patrol_start. With dry-run policy, returns
        {status: "dry_run", response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            patrol: Patrol object sent as given (free-form); for example {"name": "Yard
                tour", "slot": 0, "presets": [0, 1], "presetDurationSeconds": 10}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _create_ptz_patrol(client, registry, host, camera_id, patrol)

    @mcp.tool(annotations=WRITE)
    async def update_ptz_patrol(
        host: str, camera_id: str, slot: int, fields: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Update a PTZ patrol by its patrol slot, verified by reading it back.

        Reads the camera's patrols (GET cameras/{camera_id}/ptz/patrol on the Protect
        console host); a slot the list does not hold fails listing the valid slots. Every
        requested field already equal returns {status: "noop", resource} with no write.
        Otherwise fields are merged over the current patrol (nested siblings kept) and sent
        to PATCH cameras/{camera_id}/ptz/patrol/{slot}, then read back. Returns {status:
        "updated", verified, before, after, response}; verified is true only when every
        requested leaf matches, type-strict, and null with readAfterError when the read-back
        fails or lacks the slot. Passing no field fails before any request.
        With dry-run policy, returns {status: "dry_run", before, response (the preview)}.

        Dry-run response previews include body and params.

        Consequence: the camera's next run of this patrol follows the new settings.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            slot: Patrol slot 0-4 (the patrol's slot field); for example 0.
            fields: Patrol fields to change (free-form); for example {"name": "Yard tour",
                "presetDurationSeconds": 15}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _update_ptz_patrol(client, registry, host, camera_id, slot, fields)

    @mcp.tool(annotations=WRITE)
    async def delete_ptz_patrol(
        host: str, camera_id: str, slot: int, confirm: bool = False
    ) -> dict[str, Any]:
        """Delete a PTZ patrol by its patrol slot.

        Reads the camera's patrols first (GET cameras/{camera_id}/ptz/patrol on the Protect
        console host); a slot the list does not hold fails listing the valid slots, with no
        delete sent. Then sends DELETE cameras/{camera_id}/ptz/patrol/{slot}. Returns
        {deleted: true, message, response}. With dry-run policy, returns {status: "dry_run",
        deleted: false, message, response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: the patrol is removed permanently (its presets stay); there is no undo.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            slot: Patrol slot 0-4 (the patrol's slot field); for example 0.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _delete_ptz_patrol(client, registry, host, camera_id, slot)

    @mcp.tool(annotations=WRITE)
    async def create_ptz_preset(
        host: str, camera_id: str, preset: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Create a PTZ preset (a saved pan/tilt/zoom position) on a PTZ camera.

        Sends preset as given to POST cameras/{camera_id}/ptz/preset on the Protect console
        host. No published schema documents the body; preset records the console lists
        carry name, slot and ptz {pan, tilt, zoom}. Returns {status: "created", response}.
        Go to it with ptz_goto_preset. With dry-run policy, returns {status: "dry_run",
        response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            preset: Preset object sent as given (free-form); for example {"name": "Gate",
                "slot": 1}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _create_ptz_preset(client, registry, host, camera_id, preset)

    @mcp.tool(annotations=WRITE)
    async def update_ptz_preset(
        host: str, camera_id: str, slot: int, fields: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Update a PTZ preset by its slot (rename it or change its position), verified.

        Reads the camera's presets (GET cameras/{camera_id}/ptz/preset on the Protect
        console host); a slot the list does not hold fails listing the valid slots. Every
        requested field already equal returns {status: "noop", resource} with no write.
        Otherwise fields are merged over the current preset (nested siblings such as the
        other ptz axes kept) and sent to PATCH cameras/{camera_id}/ptz/preset/{slot}, then
        read back. Returns {status: "updated", verified, before, after, response}; verified
        is true only when every requested leaf matches, type-strict, and null with
        readAfterError when the read-back fails or lacks the slot. Passing no field fails
        before any request. With dry-run policy, returns {status: "dry_run", before,
        response (the preview)}.

        Dry-run response previews include body and params.

        Consequence: ptz_goto_preset and patrols using this slot go to the new position.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            slot: Preset slot (the preset's slot field; -1 is home); for example 1.
            fields: Preset fields to change (free-form); for example {"name": "Front gate"}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _update_ptz_preset(client, registry, host, camera_id, slot, fields)

    @mcp.tool(annotations=WRITE)
    async def delete_ptz_preset(
        host: str, camera_id: str, slot: int, confirm: bool = False
    ) -> dict[str, Any]:
        """Delete a PTZ preset by its slot.

        Reads the camera's presets first (GET cameras/{camera_id}/ptz/preset on the Protect
        console host); a slot the list does not hold fails listing the valid slots, with no
        delete sent. Then sends DELETE cameras/{camera_id}/ptz/preset/{slot}. Returns
        {deleted: true, message, response}. With dry-run policy, returns {status: "dry_run",
        deleted: false, message, response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: the saved position is removed permanently and patrols that use it lose
        that stop; there is no undo.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: PTZ camera id from list_cameras; for example "000000000000000000000103".
            slot: Preset slot (the preset's slot field); for example 1.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _delete_ptz_preset(client, registry, host, camera_id, slot)

    @mcp.tool(annotations=WRITE)
    async def create_camera_shortcut(
        host: str,
        camera_id: str,
        shortcut: dict[str, Any],
        confirm: bool = False,
        validate_schema: bool = False,
    ) -> dict[str, Any]:
        """Create a camera shortcut (a one-click action shown on the camera's live view).

        Sends shortcut as a single-item array to POST cameras/{camera_id}/shortcuts on the
        Protect console host. With validate_schema=true, checks placement x/y and the nested
        shortcut type: linkedCamera needs linkedCameraId; linkedDoor needs linkedDoorId; webhook
        needs name, url, method, headers, body, auth and timeout. Missing fields fail locally.
        Legacy calls pass their body unchanged. Returns {status: "created", response}
        on success. With dry-run policy, returns {status: "dry_run",
        response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            shortcut: One shortcut object, sent inside an array (free-form); for example
                {"placement": {"x": 0, "y": 0}, "shortcut": {"type": "webhook", "name":
                "Gate view", "url": "http://192.0.2.1/", "method": "GET", "headers": null,
                "body": null, "auth": null, "timeout": 1}}.
            confirm: Accepted and ignored for compatibility; for example false.
            validate_schema: Opt in to local per-type shape checks; for example true.
        """
        client, registry = deps_fn()
        return await _create_camera_shortcut(
            client, registry, host, camera_id, shortcut, validate_schema
        )

    @mcp.tool(annotations=WRITE)
    async def update_camera_shortcut(
        host: str,
        camera_id: str,
        body: dict[str, Any],
        confirm: bool = False,
        validate_schema: bool = False,
    ) -> dict[str, Any]:
        """Update a camera's shortcuts (PATCH cameras/{camera_id}/shortcuts).

        The route has no shortcut id in its path. The camera is read first (GET
        cameras/{camera_id} on the Protect console host); when body carries an id that the
        camera's shortcuts array lists, a no-op returns
        {status: "noop", resource}, and the read-back verifies every requested leaf
        (type-strict). An id the array does not list fails listing the valid ids. Without a
        locatable id the body is sent and verified is null with readAfterError. The body is
        sent as a single-item array. validate_schema=true checks id, any placement x/y, and any
        complete nested shortcut using the same per-type rules as create_camera_shortcut.
        Returns {status: "updated", verified, before, after, response}. An empty body fails
        before any request. With dry-run policy, returns {status: "dry_run", before,
        response (the preview)}.

        Dry-run response previews include body and params.

        Consequence: a successful request can change the shortcut buttons shown for this camera.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            body: One shortcut update, sent inside an array (free-form): the shortcut's id plus
                the parts to change; for example {"id": "000000000000000000000109",
                "placement": {"x": 0, "y": 0}}. Protect 7.3.74 rejected anything but an
                array of {id, placement?, shortcut?} with an AJV 400.
            confirm: Accepted and ignored for compatibility; for example false.
            validate_schema: Opt in to local per-type shape checks; for example true.
        """
        client, registry = deps_fn()
        return await _update_camera_shortcut(
            client, registry, host, camera_id, body, validate_schema
        )

    @mcp.tool(annotations=WRITE)
    async def delete_camera_shortcut(
        host: str, camera_id: str, shortcut_ids: list[str], confirm: bool = False
    ) -> dict[str, Any]:
        """Delete one or more camera shortcuts.

        Reads the camera first (GET cameras/{camera_id} on the Protect console host); an id its
        shortcuts array does not list fails listing the valid ids, with no delete sent. Then sends
        DELETE cameras/{camera_id}/shortcuts with shortcut_ids as the shortcutIds query parameter
        (one per id). An empty shortcut_ids list fails before any request. Returns {deleted:
        true, message, response}. With dry-run policy, returns {status: "dry_run", deleted:
        false, message, response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: a successful deletion permanently removes shortcuts; there is no undo.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            shortcut_ids: Non-empty list of shortcut ids (the camera's shortcuts[].id); for example
                ["000000000000000000000109"].
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _delete_camera_shortcut(client, registry, host, camera_id, shortcut_ids)

    @mcp.tool(annotations=WRITE)
    async def trigger_camera_shortcut(
        host: str, camera_id: str, shortcut_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Run a camera shortcut, as clicking it in the Protect web app does.

        Reads the camera first (GET cameras/{camera_id} on the Protect console host); an id
        its shortcuts array does not list fails listing the valid ids, with nothing sent.
        Then sends POST cameras/{camera_id}/shortcuts/{shortcut_id}/click once (never
        auto-retried on 429). Returns {status: "sent", response}. With dry-run policy,
        returns {status: "dry_run", response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: a successful request can run the shortcut's action (for example a PTZ move
        or an output); it is not undone automatically.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            shortcut_id: Shortcut id (the camera's shortcuts[].id); for example
                "000000000000000000000109".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _trigger_camera_shortcut(client, registry, host, camera_id, shortcut_id)

    @mcp.tool(annotations=WRITE)
    async def calibrate_camera(host: str, camera_id: str, confirm: bool = False) -> dict[str, Any]:
        """Start a camera calibration (PTZ / motorised lens), as the Protect web app does.

        Sends POST cameras/{camera_id}/calibrate (no body) once on the Protect console host,
        never auto-retried on 429. Returns {status: "sent", response} with the console's
        answer verbatim; a camera without calibration answers with its error. With
        dry-run policy, returns {status: "dry_run", response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: the camera moves through its full range while it calibrates, so its
        view is interrupted until calibration ends.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "000000000000000000000103".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _calibrate_camera(client, registry, host, camera_id)

    @mcp.tool(annotations=WRITE)
    async def test_doorbell_ringtone(
        host: str, camera_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Play a doorbell's ringtone once to test it.

        Sends POST cameras/{camera_id}/test-ringtone (no body) once on the Protect console
        host, never auto-retried on 429. camera_id is the doorbell's camera id. Returns
        {status: "sent", response}. With dry-run policy, returns {status: "dry_run",
        response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: the doorbell and its paired chimes ring audibly.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Doorbell camera id from list_cameras; for example
                "000000000000000000000103".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _test_doorbell_ringtone(client, registry, host, camera_id)

    @mcp.tool(annotations=WRITE)
    async def enroll_doorbell_credential(
        host: str,
        camera_id: str,
        credential_type: CredentialType,
        step: EnrollStep = "enroll",
        fingerprint_id: str | None = None,
        ulp_id: str | None = None,
        fields: dict[str, Any] | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Enroll an NFC card or fingerprint on a doorbell (G4/G6 Pro class) for a user.

        The credential_type is nfc or fingerprint. step enroll (POST cameras/{camera_id}/
        {credential_type}/enroll) puts the doorbell on the Protect console host into enrollment
        mode; present the card or finger. step assign (POST .../{credential_type}/assign) assigns
        the read credential to a user: the body is fields plus fingerprintId and ulpId when given
        (the bundle's fingerprint keys; the NFC body is not published, pass its keys in fields).
        step cancel (POST .../{credential_type}/cancel) leaves enrollment mode. fingerprint_id,
        ulp_id and fields apply to step assign only; giving any of them with another step fails
        before any request. Returns {status, response}: status: "enrolling" for step enroll,
        status: "assigned" for assign and status: "cancelled" for cancel. Credential
        identifiers are registered secrets, masked only under UNIFI_REDACT_SECRETS. With
        dry-run policy, returns {status: "dry_run", response (the preview)} and sends no write.

        Dry-run response previews include body and params.

        Consequence: an assigned card or fingerprint can unlock or identify the user at the
        doorbell until it is deleted with delete_doorbell_credential.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Doorbell camera id from list_cameras; for example
                "000000000000000000000103".
            credential_type: nfc or fingerprint; for example "fingerprint".
            step: enroll, assign or cancel; for example "enroll".
            fingerprint_id: assign only: the read fingerprint id, sent as fingerprintId;
                for example "3".
            ulp_id: assign only: the UniFi user id, sent as ulpId (list_ulp_users); for
                example "0f6a1c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b".
            fields: assign only: other body keys sent as given (free-form); for example
                {"name": "Front door card"}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _enroll_doorbell_credential(
            client,
            registry,
            host,
            camera_id,
            credential_type,
            step=step,
            fingerprint_id=fingerprint_id,
            ulp_id=ulp_id,
            fields=fields,
        )

    @mcp.tool(annotations=WRITE)
    async def delete_doorbell_credential(
        host: str,
        camera_id: str,
        credential_type: CredentialType,
        credential_id: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Delete an enrolled NFC card or fingerprint from a doorbell.

        Sends DELETE cameras/{camera_id}/{credential_type}/{credential_id} on the Protect console
        host (credential_type nfc or fingerprint). The id is a registered secret, masked only under
        UNIFI_REDACT_SECRETS. Returns {deleted: true, message, response}. With dry-run policy,
        returns {status: "dry_run", deleted: false, message, response (the preview)} and sends no
        write.

        Dry-run response previews include body and params.

        Consequence: the card or fingerprint stops working at this doorbell at once; it
        must be enrolled again to restore it.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Doorbell camera id from list_cameras; for example
                "000000000000000000000103".
            credential_type: nfc or fingerprint; for example "nfc".
            credential_id: The enrolled card or fingerprint id; for example
                "00000000000000000000010a".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _delete_doorbell_credential(
            client, registry, host, camera_id, credential_type, credential_id
        )
