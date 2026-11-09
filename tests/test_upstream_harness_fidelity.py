"""The fake upstream behaves like the code it stands in for, and says so accurately.

* ``install`` fakes the transport only: the real ``UniFiClient._get_client`` keeps one
  client per (label, key fingerprint) for environment keys and routes header mode
  (``UNIFI_KEY_MODE=header``) through the real per-caller credential cache.
* A recorded system-log page is replayed as captured; with replay off, the system-log
  route serves a generated page and no capture.
* A deleted Protect backup is dropped from the synthetic backup list, the served record
  holds the body the tool received, and a captured backup list is never rewritten.
"""

from __future__ import annotations

import json

import httpx

from tests import upstream_harness as uh
from unifi_fabric import header_credentials
from unifi_fabric.config import APIKeyConfig

SHARED_A = APIKeyConfig(label="shared", key="synthetic-key-a")
SHARED_B = APIKeyConfig(label="shared", key="synthetic-key-b")


async def test_same_label_keys_get_their_own_client(monkeypatch):
    monkeypatch.setattr(header_credentials, "_header_mode_process", False)
    # Settings refuses duplicate labels; a key built in code can still share one.
    client = uh.install(monkeypatch, uh.FakeUpstream(), keys=[SHARED_A])
    first = await client._get_client(SHARED_A)
    second = await client._get_client(SHARED_B)
    assert first is not second
    assert first.headers["X-API-KEY"] == SHARED_A.key
    assert second.headers["X-API-KEY"] == SHARED_B.key
    assert await client._get_client(SHARED_A) is first
    assert len(client._clients) == 2
    await client.close()


async def test_header_mode_clients_come_from_the_real_credential_cache(monkeypatch):
    monkeypatch.setattr(header_credentials, "_header_mode_process", True)
    client = uh.install(monkeypatch, uh.FakeUpstream())
    first = await client._get_client(SHARED_A)
    second = await client._get_client(SHARED_B)
    assert first is not second
    assert second.headers["X-API-KEY"] == SHARED_B.key
    assert len(client._credential_cache) == 2
    assert client._clients == {}  # header keys never enter the environment pool
    await client.close()


def _system_log_request(entry: dict) -> httpx.Request:
    req = entry["request"]
    return httpx.Request("POST", "https://api.ui.com" + req["path"], json=req["json"])


def test_system_log_replays_the_capture_or_serves_a_generated_page():
    path = uh.RECORDED / "network_v2/network_v2_api_site_SITE_system_log_all.json"
    entry = json.loads(path.read_text())
    assert uh.FakeUpstream()(_system_log_request(entry)).json() == entry["body"]

    generated = uh.FakeUpstream(replay_recordings=False)(_system_log_request(entry)).json()
    recorded_ids = {row["id"] for row in entry["body"]["data"]}
    assert len(generated["data"]) == 1
    assert not recorded_ids & {row.get("id") for row in generated["data"]}
    assert generated["total_page_count"] == 1


PROTECT = "https://api.ui.com/v1/connector/consoles/console-1/proxy/protect/api"


def test_deleted_backup_leaves_the_synthetic_list_and_its_served_record():
    up = uh.FakeUpstream()
    listed = up(httpx.Request("GET", PROTECT + "/backups")).json()
    gone = listed[0]["id"]
    assert up(httpx.Request("DELETE", PROTECT + "/backup/" + gone)).status_code == 200
    after = up(httpx.Request("GET", PROTECT + "/backups")).json()
    assert gone not in {row["id"] for row in after}
    assert up.served[-1].body == after


def test_captured_backup_list_is_never_rewritten(monkeypatch, tmp_path):
    rows = [{"id": "backup-kept"}, {"id": "backup-deleted"}]
    capture = {
        "request": {
            "method": "GET",
            "path": "/v1/connector/consoles/console-1/proxy/protect/api/backups",
            "query": {},
        },
        "status": 200,
        "body": rows,
        "scenario": "captured-backups",
    }
    (tmp_path / "backups.json").write_text(json.dumps(capture))
    monkeypatch.setattr(uh, "RECORDED", tmp_path)
    monkeypatch.setattr(uh, "_RECORDED_CACHE", {})
    up = uh.FakeUpstream(recorded_routes=uh.load_recorded())
    up(httpx.Request("DELETE", PROTECT + "/backup/backup-deleted"))
    assert up(httpx.Request("GET", PROTECT + "/backups")).json() == rows
