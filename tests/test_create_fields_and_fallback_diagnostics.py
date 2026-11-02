"""Create tools send the actual spec fields; fallbacks keep their diagnostics."""

import json

import pytest
import respx

from unifi_fabric import placement_snapshot_cli
from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings
from unifi_fabric.tools import carrier_fabric, innerspace, protect, recognition
from unifi_fabric.tools.placement_snapshot import _capability_outcome


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields",
    [{"service_address": None}, {"metadata": {}}, {"service_address": None, "metadata": {}}],
)
async def test_create_changed_covers_every_sent_field(fields):
    client = UniFiClient(Settings(api_key="synthetic-test-key"))
    try:
        with respx.mock as mock:
            route = mock.post("https://api.ui.com/v1/carrier/subscribers").respond(
                201, json={"data": {"id": "11111111-1111-4111-8111-111111111111"}}
            )
            result = await carrier_fabric.create_carrier_subscriber(client, "SN-test", **fields)
        sent = json.loads(route.calls[0].request.content)
        assert result["changed"] == {
            key: {"from": None, "to": value} for key, value in sent.items()
        }
    finally:
        await client.close()


def _noted_error():
    cause = ValueError("earlier failure")
    cause.add_note("integration 403 reason")
    cause.add_note("cause-only note")
    exc = UniFiConnectionError("HTTP 500 from legacy: upstream reason")
    exc.add_note("integration 403 reason")
    exc.__cause__ = cause
    cause.__cause__ = exc
    return exc


def test_snapshot_outcome_preserves_deduplicated_cause_notes():
    result = _capability_outcome(_noted_error())
    assert result == {
        "outcome": "unavailable",
        "error": "UniFiConnectionError: HTTP 500 from legacy: upstream reason"
        "\n\nintegration 403 reason\n\ncause-only note",
    }


def test_cli_preserves_notes_then_scrubs(monkeypatch):
    monkeypatch.setattr(placement_snapshot_cli, "_secret_values", lambda: ("synthetic-secret",))
    exc = _noted_error()
    exc.add_note("fallback synthetic-secret")
    result = placement_snapshot_cli._failure_message("export", exc)
    assert result == (
        "export: UniFiConnectionError: HTTP 500 from legacy: upstream reason"
        "\n\nintegration 403 reason\n\nfallback ***\n\ncause-only note"
    )


@pytest.mark.parametrize(
    ("tool", "object_page"),
    [
        (protect.list_protect_events, "An object page preserves every upstream top-level field"),
        (recognition.list_recognition_detections, "An object page is returned as"),
    ],
)
def test_explicit_page_warning_exception_is_documented(tool, object_page):
    text = " ".join((tool.__doc__ or "").split())
    assert "follows the upstream page's shape" in text
    assert "A bare-list page is returned" in text
    assert object_page in text
    assert "as a drained result does" in text


@pytest.mark.asyncio
async def test_real_innerspace_fallback_note_survives_snapshot_and_cli(monkeypatch):
    class Registry:
        async def resolve_key_for_host(self, host):
            return None

        async def resolve_host_id(self, host, *, key):
            return "synthetic-host"

    class Client:
        calls = 0

        async def get(self, path, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise UniFiConnectionError("HTTP 403 from integration: host not found")
            raise UniFiConnectionError("HTTP 500 from legacy: backend failed")

    client = Client()
    with pytest.raises(UniFiConnectionError) as caught:
        await innerspace.fetch_project(client, Registry(), "synthetic-host", "3D")
    assert client.calls == 2
    monkeypatch.setattr(placement_snapshot_cli, "_secret_values", lambda: ())
    for message in (
        _capability_outcome(caught.value)["error"],
        placement_snapshot_cli._failure_message("export", caught.value),
    ):
        assert "HTTP 500 from legacy: backend failed" in message
        assert "HTTP 403 from integration: host not found" in message
        assert "This was the legacy fallback" in message
