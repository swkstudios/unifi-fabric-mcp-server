"""Behavioral regression coverage for Protect client surfaces."""

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools import protect


@pytest.mark.parametrize("collector", ["collect_protect_events", "collect_protect_device_changes"])
@pytest.mark.parametrize("interval", [10.0, 0.0])
async def test_collector_pacing_occurs_between_exact_completed_polls(
    monkeypatch, collector, interval
):
    registry = AsyncMock()
    registry.resolve_host_id.return_value = "host-abc"
    registry.resolve_key_for_host.return_value = None
    sleep = AsyncMock()
    monkeypatch.setattr(protect, "_sleep", sleep)
    poll = AsyncMock(return_value={"items": [], "incomplete": False})
    snapshots = AsyncMock(return_value=({}, [], {}, {}))
    monkeypatch.setattr(protect, "collect_offset", poll)
    monkeypatch.setattr(protect, "_poll_device_snapshot", snapshots)
    result = await getattr(protect, collector)(
        AsyncMock(), registry, "host", poll_count=2, poll_interval_seconds=interval
    )
    sleep.assert_awaited_once_with(interval)
    assert result["_polls"] == result["_poll_count"] == 2
    assert (poll if collector.endswith("events") else snapshots).await_count == 2


@pytest.mark.parametrize("collector", ["collect_protect_events", "collect_protect_device_changes"])
def test_collectors_document_work_boundary_and_zero_cadence(collector):
    description = getattr(protect, collector).__doc__
    assert "0 means" in description
    assert "never" in description and "elapsed time" in description
    assert "poll_count" in description and "default 6" in description


@pytest.mark.parametrize("collector", ["collect_protect_events", "collect_protect_device_changes"])
@pytest.mark.parametrize(
    "poll_count,poll_interval_seconds,message",
    [
        (0, 0.0, "poll_count must be a positive integer"),
        (-1, 0.0, "poll_count must be a positive integer"),
        (1.5, 0.0, "poll_count must be a positive integer"),
        (True, 0.0, "poll_count must be a positive integer"),
        (1, -0.1, "poll_interval_seconds must be at least 0 seconds"),
    ],
)
async def test_collectors_reject_invalid_work_or_cadence_before_resolution(
    collector, poll_count, poll_interval_seconds, message
):
    registry = AsyncMock()
    with pytest.raises(ValueError, match=message):
        await getattr(protect, collector)(
            AsyncMock(),
            registry,
            "host",
            poll_count=poll_count,
            poll_interval_seconds=poll_interval_seconds,
        )
    registry.resolve_host_id.assert_not_awaited()
    registry.resolve_key_for_host.assert_not_awaited()


def test_large_requested_work_count_is_admitted_without_an_arbitrary_cap():
    # Admission is independent of executing the requested trillion polls. Exact
    # execution and completion are covered above with a two-poll workload.
    protect._validate_collector_controls(10**12, 0)


@pytest.mark.parametrize(
    "name,args,module",
    [
        ("get_camera_snapshot", {"host": "host", "camera_id": "camera-1"}, "protect"),
        ("get_thumbnail", {"host": "host", "thumbnail_id": "thumbnail-1"}, "recognition"),
        (
            "get_recognition_group_image",
            {"host": "host", "type": "face", "group_id": "face_90"},
            "recognition",
        ),
    ],
)
@pytest.mark.parametrize("mime", ["image/png", "image/jpeg; charset=binary", None])
async def test_image_tools_expose_mcp_image_and_metadata(monkeypatch, name, args, module, mime):
    import base64
    import json

    from mcp.types import ImageContent, TextContent

    from unifi_fabric import server

    metadata = {
        "image_base64": base64.b64encode(b"synthetic-image").decode(),
        "content_type": mime,
        "size_bytes": 15,
    }
    monkeypatch.setattr(server, "_client", AsyncMock())
    monkeypatch.setattr(server, "_registry", AsyncMock())
    monkeypatch.setattr(getattr(server, module), name, AsyncMock(return_value=metadata))
    result = await server.mcp.call_tool(name, args)
    images = [part for part in result.content if isinstance(part, ImageContent)]
    texts = [part for part in result.content if isinstance(part, TextContent)]
    assert len(images) == 1
    assert images[0].data == metadata["image_base64"]
    assert images[0].mime_type == (mime.split(";", 1)[0] if mime else "image/jpeg")
    assert result.structured_content == metadata
    assert any(json.loads(part.text) == metadata for part in texts)
