---
name: protect-camera-event-review
description: Load when reviewing UniFi Protect cameras, their events in a time window, or a camera snapshot, without changing any camera or recording setting.
---

# Protect camera and event review

This workflow is read-only. Camera ids are Protect ids, not Network device ids. Treat
images, links and recognition details as sensitive evidence. In discovery mode (the
default) run each tool below through `call_read_tool` with `name` and `arguments`; in
full mode call it directly. For anything else, including recognition detections and
their crops, use `search_tools` and `describe_tool`.

1. Call `list_cameras` with `{"host":"<console>"}`; note each camera's `id`, name and
   state from `result`.
2. Call `list_protect_events` with `host` and integer epoch-second `start` and `end`
   (not ISO strings or milliseconds). Narrow with `cameras` or `types`;
   `smart_detect_types` needs `types` too. Omit `limit` and `offset` to get every
   event, and read `_warnings`.
3. Call `get_camera_snapshot` with `host` and `camera_id` for the live frame; add
   `channel` or `high_quality` only when needed. `ts` asks a private route for a past
   frame and is unverified, so a failure there is not evidence.
4. Report camera health, the event chronology and the evidence with the window used.
   Keep an empty window apart from incomplete or failed reads (`incomplete`, errors).

Changing camera or recording settings is a separate task: find its tool with
`search_tools`, then read, show the change, write and read back.

## Tool contracts checked against code (paths under `src/unifi_fabric/`)

| Tool | Mode | Required arguments (optional) | Return shape and source |
|---|---|---|---|
| `list_cameras` | read | `host` | `{result, _count}` with cameras verbatim; `families/protect/protect.py::list_cameras` → `families/protect/protect.py::list_cameras`; `readOnlyHint: true` |
| `list_protect_events` | read | `host`, `start`, `end` (`cameras`, `types`, `smart_detect_types`, `limit`, `offset`, others) | events with envelope, `_count`, `_warnings`; `families/protect/protect.py::list_protect_events` → `families/protect/protect.py::list_protect_events`; `readOnlyHint: true` |
| `get_camera_snapshot` | read | `host`, `camera_id` (`channel`, `high_quality`, `ts`) | image plus `{image_base64, content_type, size_bytes}`; `families/protect/protect.py::get_camera_snapshot` → `families/protect/protect.py::get_camera_snapshot`; `readOnlyHint: true` |
