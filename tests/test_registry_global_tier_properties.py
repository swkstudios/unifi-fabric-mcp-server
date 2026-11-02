"""Class properties: select globally before ambiguity; identities preserve first sighting."""

from itertools import combinations

import pytest

from tests.test_registry import _make_multikey_client
from unifi_fabric.registry import Registry, _match_proxy_site, match_ea_site, match_host

# All eight name tiers (normalization tier x host label group), plus exact id.
LABELS = ("Café", "CAFÉ", "Café  ", "CAFÉ  ")
TIERS = [-1, *range(8)]


def host_at(tier, identity):
    if tier == -1:
        return {"id": "Café"}
    field = "hostname" if tier % 2 == 0 else "name"
    return {"id": identity, "reportedState": {field: LABELS[tier // 2]}}


@pytest.mark.parametrize("better,worse", list(combinations(TIERS, 2)))
@pytest.mark.parametrize("first_label", ["alpha", "beta"])
async def test_best_global_tier_survives_another_keys_ambiguity(better, worse, first_label):
    bad = [host_at(worse, "11"), host_at(worse, "22")]
    good = [host_at(better, "33")]
    groups = {first_label: bad, "winner": good}
    reg = Registry(_make_multikey_client(groups))
    key = await reg.resolve_key_for_host("Café")
    assert key.label == "winner"


@pytest.mark.parametrize("selector", ["Lab", "AA:11", "aa:11"])
@pytest.mark.parametrize("ids", [("AA:11", "aa:11"), ("aa:11", "AA:11"), ("AA:11", "AA:11")])
async def test_duplicate_console_selects_first_key_and_upstream_record(selector, ids):
    records = [{"id": identity, "name": "Lab", "marker": i} for i, identity in enumerate(ids)]
    assert match_host(records, selector)[1] is records[0]
    reg = Registry(_make_multikey_client({"first": [records[0]], "last": [records[1]]}))
    assert (await reg.resolve_key_for_host(selector)).label == "first"


@pytest.mark.parametrize("kind", ["host", "proxy", "ea"])
@pytest.mark.parametrize(
    "identity", ["ABCDEF0123456789ABCDEF01", "ABCDEF01-ABCD-4000-8000-ABCDEF012345"]
)
@pytest.mark.parametrize("name", LABELS)
def test_every_registry_identity_map_collapses_hex_case_preserving_first(kind, identity, name):
    records = [
        {"id": identity, "siteId": identity, "name": name, "description": name},
        {"id": identity.lower(), "siteId": identity.lower(), "name": name, "description": name},
    ]
    if kind == "host":
        result = match_host(records, "Café")[1]
    elif kind == "proxy":
        result = _match_proxy_site(records, "Café")
    else:
        result = match_ea_site(records, "Café", partial=[], max_pages=None)
    assert result is records[0]


@pytest.mark.parametrize("kind", ["host", "proxy", "ea"])
def test_nonhex_identifiers_remain_distinct(kind):
    records = [{"id": value, "siteId": value, "name": "Lab"} for value in ("HOST-G", "host-g")]
    with pytest.raises(ValueError, match="ambiguous"):
        if kind == "host":
            match_host(records, "Lab")
        elif kind == "proxy":
            _match_proxy_site(records, "Lab")
        else:
            match_ea_site(records, "Lab", partial=[], max_pages=None)


async def test_all_failed_keys_report_each_failure():
    reg = Registry(_make_multikey_client({"first": [], "last": []}, fail_labels=("first", "last")))
    with pytest.raises(RuntimeError, match="all 2 configured") as error:
        await reg.resolve_key_for_host("Lab")
    assert "first" in str(error.value) and "last" in str(error.value)


async def test_one_failed_key_refuses_name_but_keeps_exact_id_resolution():
    reg = Registry(
        _make_multikey_client(
            {"first": [], "last": [{"id": "11", "name": "Lab"}]}, fail_labels=("first",)
        )
    )
    with pytest.raises(ValueError, match="could not list its consoles"):
        await reg.resolve_key_for_host("Lab")
    assert (await reg.resolve_key_for_host("11")).label == "last"


async def test_single_key_short_circuit_does_not_list_hosts():
    client = _make_multikey_client({"single": [{"id": "11", "name": "Lab"}]})
    assert await Registry(client).resolve_key_for_host("Lab") is None
    client.paginate.assert_not_awaited()


@pytest.mark.parametrize("tier", TIERS)
def test_single_host_match_preserves_tier(tier):
    record = host_at(tier, "33")
    match = match_host([record], "Café")
    assert match == (tier + 1, record)


@pytest.mark.parametrize("tier", range(8))
async def test_same_best_tier_distinct_consoles_remain_ambiguous(tier):
    reg = Registry(
        _make_multikey_client({"first": [host_at(tier, "11")], "last": [host_at(tier, "22")]})
    )
    with pytest.raises(ValueError, match="ambiguous host"):
        await reg.resolve_key_for_host("Café")
