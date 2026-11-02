"""Identity and masked-secret regressions for the read/merge/write class."""

from unittest.mock import AsyncMock

import pytest

from tests.test_site_config import HOST_ID, RADIUS_USERS
from unifi_fabric.redaction import (
    MASKED_FIELDS_KEY,
    REDACTION_MASK,
    _make_redacting_fn,
    _with_dropped_report,
)
from unifi_fabric.tools import site_config as sc

COLLECTIONS = [
    sc.USER_GROUPS,
    sc.STATIC_ROUTES,
    sc.RADIUS_ACCOUNTS,
    sc.RADIUS_PROFILES,
    sc.PORT_PROFILES,
    sc.DYNAMIC_DNS,
    sc.AP_GROUPS,
]


def dependencies():
    client = AsyncMock()
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = HOST_ID
    registry.resolve_site_slug.return_value = "default"
    return client, registry


@pytest.mark.parametrize("coll", COLLECTIONS, ids=lambda c: c.kind)
@pytest.mark.parametrize("given", ["different-record", None, "", 42])
async def test_conflicting_body_identity_never_writes(coll, given):
    client, registry = dependencies()
    record = {"_id": "record-a", "name": "Account A", "x_password": "synthetic-value"}
    client.get.return_value = [record] if coll.v2 else {"data": [record]}
    with pytest.raises(ValueError, match="does not match.*resolved"):
        if coll.batch:
            await sc._update_batch_record(
                client,
                registry,
                "h",
                "Default",
                coll,
                "record-a",
                "account_id",
                {"_id": given, "vlan": 30},
            )
        else:
            await sc._update_config_record(
                client,
                registry,
                "h",
                "Default",
                coll,
                "record-a",
                "record_id",
                {"_id": given, "vlan": 30},
                merge=True,
            )
    client.put.assert_not_awaited()
    client.post.assert_not_awaited()
    if coll.id_fields == ("_id",):
        client.get.assert_not_awaited()
        registry.resolve_key_for_host.assert_not_awaited()


@pytest.mark.parametrize("coll", [sc.AP_GROUPS, sc.RADIUS_ACCOUNTS], ids=lambda c: c.kind)
@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("nested", [False, True])
async def test_masked_secret_roundtrip_keeps_stored_value_and_return_shape(coll, redact, nested):
    client, registry = dependencies()
    record = {
        **RADIUS_USERS[0],
        "_warnings": ["read metadata"],
        "radius": {"x_secret": "synthetic-nested", "port": 1812},
    }
    client.get.return_value = [record]
    answer = {**record, "vlan": 30}
    client.post.return_value = [answer]
    client.put.return_value = answer
    changes = {"vlan": 30, "x_password": REDACTION_MASK}
    if nested:
        changes["radius"] = {"x_secret": REDACTION_MASK, "port": 1813}

    async def tool():
        if coll.batch:
            return await sc._update_batch_record(
                client,
                registry,
                "h",
                "Default",
                coll,
                record["_id"],
                "account_id",
                changes,
            )
        return await sc._update_config_record(
            client,
            registry,
            "h",
            "Default",
            coll,
            record["_id"],
            "group_id",
            changes,
            merge=True,
        )

    out = await _make_redacting_fn(tool, lambda: redact)()
    sent = (
        client.post.await_args.kwargs["json"][0]
        if coll.batch
        else (client.put.await_args.kwargs["json"])
    )
    assert sent["x_password"] == (record["x_password"] if redact else REDACTION_MASK)
    assert sent["_id"] == record["_id"]
    assert sent["vlan"] == 30
    assert "_warnings" not in sent
    if nested:
        assert sent["radius"] == {
            "x_secret": "synthetic-nested" if redact else REDACTION_MASK,
            "port": 1813,
        }
    if coll.batch:
        assert isinstance(out, list) and len(out) == 1
        returned = out[0]
    else:
        assert isinstance(out, dict)
        returned = out
    assert returned["x_password"] == (REDACTION_MASK if redact else record["x_password"])
    expected = ["x_password", "radius.x_secret"] if nested else ["x_password"]
    if redact:
        assert returned[MASKED_FIELDS_KEY] == expected
    else:
        assert MASKED_FIELDS_KEY not in returned


@pytest.mark.parametrize(
    "answer",
    [
        [{"_id": "a"}, {"_id": "b"}],
        [{"_id": "a"}, None, "scalar"],
        [],
        [1, 2],
    ],
)
def test_redaction_metadata_never_changes_bare_array_shape(answer):
    out = _with_dropped_report(answer, ["x_password"])
    assert isinstance(out, list)
    assert len(out) == len(answer)
    for before, after in zip(answer, out, strict=True):
        if isinstance(before, dict):
            assert after == {**before, MASKED_FIELDS_KEY: ["x_password"]}
        else:
            assert after == before
    assert all(MASKED_FIELDS_KEY not in row for row in answer if isinstance(row, dict))


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("given", ["different-record", None, "", 42])
async def test_device_tag_merge_rejects_conflicting_identity(native, given):
    from unifi_fabric.tools.device_mgmt import _update_device_tag

    client, registry = dependencies()
    client.get.return_value = [{"_id": "record-a", "name": "Cameras", "member_device_macs": []}]
    body = (
        {"device_mac_additions": [], "device_mac_removals": []}
        if native
        else {"member_device_macs": []}
    )
    with pytest.raises(ValueError, match="does not match.*resolved"):
        await _update_device_tag(
            client, registry, "h", "Default", "Cameras", {**body, "_id": given}
        )
    client.put.assert_not_awaited()


@pytest.mark.parametrize("native", [False, True])
async def test_device_tag_merge_validates_then_removes_matching_identity(native):
    from unifi_fabric.tools.device_mgmt import _update_device_tag

    client, registry = dependencies()
    client.get.return_value = [{"_id": "aabbccdd", "name": "Cameras", "member_device_macs": []}]
    body = (
        {"device_mac_additions": [], "device_mac_removals": []}
        if native
        else {"member_device_macs": []}
    )
    await _update_device_tag(
        client, registry, "h", "Default", "Cameras", {**body, "_id": "AABBCCDD"}
    )
    assert client.put.await_args.args[0].endswith("/device-tags/aabbccdd")
    assert "_id" not in client.put.await_args.kwargs["json"]
