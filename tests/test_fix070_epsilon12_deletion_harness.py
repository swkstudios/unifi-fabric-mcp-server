"""Synthetic batch-delete state follows successful requests and exact caller ids."""

import httpx
import pytest

from tests import upstream_harness as uh


@pytest.mark.parametrize("kind", ["qos", "wireguard-string", "wireguard-object"])
def test_batch_delete_harness_reflects_only_successful_exact_target_deletes(kind):
    base = "https://example.test/v1/connector/consoles/host/proxy/network/v2/api/site/default"
    collection = base + ("/qos-rules" if kind == "qos" else "/wireguard/server/users")
    route = collection + ("/batch-delete" if kind == "qos" else "/batch_delete")
    other = collection.replace("/site/default", "/site/other")
    up = uh.FakeUpstream(replay_recordings=False)

    def ids(path):
        rows = uh.upstream_records(up(httpx.Request("GET", path)).json())
        return {row["_id"] for row in rows}

    def body(identifier):
        return (
            [{"_id": identifier, "future": "preserved"}]
            if kind.endswith("object")
            else [identifier]
        )

    before = ids(collection)
    assert uh.ARG_HEX in before
    original_other = ids(other)
    up.write_status = 403
    assert up(httpx.Request("POST", route, json=body(uh.ARG_HEX))).status_code == 403
    assert ids(collection) == before
    up.write_status = None
    assert up(httpx.Request("POST", route, json=body(uh.ARG_HEX.upper()))).is_success
    assert ids(collection) == before
    assert up(httpx.Request("POST", route, json=body(uh.ARG_HEX))).is_success
    assert ids(collection) == before - {uh.ARG_HEX}
    assert ids(other) == original_other
    assert up.served[-2].body == up(httpx.Request("GET", collection)).json()
