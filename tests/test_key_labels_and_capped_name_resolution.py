"""Key labels, argument validation and name resolution on capped lists.

The cross-tool batteries carry the class-wide invariants (nested selectors in ``bt``,
identity-only update bodies in ``bq``, ``byKey == _key_labels`` in ``i`` / ``r``,
wrong-typed record fields in ``w``, refusal of a name on a capped list in ``h``, the
2xx own-secret scrub half of the secret-leak invariant in ``test_secret_leak_invariant``). This
file pins the specific behaviours: key labels validated with the ``key_label`` selector
rule at config load, ``query_isp_metrics`` argument validation, name resolution against
an incomplete list with duplicate names, and the shape errors for wrong-typed fields.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastmcp.exceptions import ToolError
from pydantic import ValidationError

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.client import (
    PaginationAbortedError,
    ResponseShapeError,
    validate_host_id,
    validate_id,
)
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.families.site_manager import aggregation, site_manager
from unifi_fabric.registry import Registry, _assert_uuid, ea_site_labels
from unifi_fabric.selector_args import selector_problem

# ============================================== key labels use the key_label rule
_LABELS = [
    "alpha",
    "Ops Team",
    "café",
    "a/b:c",
    "x-1_2",
    "日本",
    " pad",
    "pad ",
    "",
    "   ",
    "a\nb",
    "a\tb",
    "x\x7f",
    "nul\x00",
    " nbsp",
]


@pytest.mark.parametrize("label", _LABELS, ids=[repr(x) for x in _LABELS])
def test_config_accepts_exactly_the_labels_key_label_accepts(label):
    keys = [
        APIKeyConfig(key="k-first-key-1", label="zz"),
        APIKeyConfig(key="k-second-key-2", label=label),
    ]
    selectable = selector_problem("key_label", label) is None
    if selectable:
        Settings(api_keys=keys)
        return
    with pytest.raises(ValidationError) as exc:
        Settings(api_keys=keys)
    assert "UNIFI_API_KEYS[1].label" in str(exc.value)
    assert "k-second-key-2" not in str(exc.value)


def test_label_error_names_the_entry_from_the_environment(monkeypatch):
    monkeypatch.delenv("UNIFI_API_KEY", raising=False)
    monkeypatch.setenv(
        "UNIFI_API_KEYS",
        json.dumps([{"key": "k-first-key-1", "label": "a"}, {"key": "k-b-22", "label": "b "}]),
    )
    with pytest.raises(ValidationError) as exc:
        Settings()
    assert "UNIFI_API_KEYS[1].label has surrounding whitespace" in str(exc.value)


def test_duplicate_labels_are_exact_after_validation():
    """'a' and 'A' are distinct labels (and both selectable); 'a' twice is a duplicate."""
    Settings(
        api_keys=[
            APIKeyConfig(key="k-one-1111", label="a"),
            APIKeyConfig(key="k-two-2222", label="A"),
        ]
    )
    with pytest.raises(ValidationError, match="duplicate key labels at entries 0, 1"):
        Settings(
            api_keys=[
                APIKeyConfig(key="k-one-1111", label="a"),
                APIKeyConfig(key="k-two-2222", label="a"),
            ]
        )


_KEY_LABEL_TOOL = "list_all_devices"


@pytest.mark.parametrize(
    "label",
    [x for x in _LABELS if selector_problem("key_label", x) is None],
    ids=lambda x: repr(x),
)
async def test_every_accepted_label_is_selectable_via_key_label(monkeypatch, label):
    """Invariant: every label config accepts is selectable via key_label (and routes)."""
    keys = [
        APIKeyConfig(key="k-first-key-1", label="zz"),
        APIKeyConfig(key="k-second-key-2", label=label),
    ]
    Settings(api_keys=keys)
    assert "key_label" in (cti.TOOLS[_KEY_LABEL_TOOL].parameters.get("properties") or {})
    up = uh.FakeUpstream()
    uh.install(monkeypatch, up, keys=keys)
    await server.mcp.call_tool(_KEY_LABEL_TOOL, {"key_label": label})
    assert up.served and {s.api_key for s in up.served} == {"k-second-key-2"}


# ============================================== query_isp_metrics arguments
async def _isp(monkeypatch, **args: Any):
    up = uh.FakeUpstream()
    uh.install(monkeypatch, up)
    try:
        return await server.mcp.call_tool("query_isp_metrics", {"interval": "1h", **args}), up
    except ToolError as exc:
        return exc, up


_ENTRY = {"hostId": uh.HOST, "siteId": uh.SITE}


@pytest.mark.parametrize("field", ["start_time", "end_time"])
@pytest.mark.parametrize("value", ["", "   ", "\t"])
async def test_isp_empty_or_blank_time_is_an_error(monkeypatch, field, value):
    res, up = await _isp(monkeypatch, host=uh.HOST, site=uh.SITE, **{field: value})
    assert isinstance(res, ToolError) and f"{field} must not be empty" in str(res), res
    assert up.served == []


async def test_isp_sites_and_host_site_together_is_an_error(monkeypatch):
    res, up = await _isp(monkeypatch, host=uh.HOST, site=uh.SITE, sites=[_ENTRY])
    assert isinstance(res, ToolError) and "not both" in str(res), res
    assert up.served == []


@pytest.mark.parametrize("field", ["beginTimestamp", "endTimestamp"])
async def test_isp_null_entry_timestamp_is_absent_and_the_window_applies(monkeypatch, field):
    window = {"beginTimestamp": "2026-07-23T00:00:00Z", "endTimestamp": "2026-07-24T00:00:00Z"}
    res, up = await _isp(
        monkeypatch,
        sites=[{**_ENTRY, field: None}],
        start_time=window["beginTimestamp"],
        end_time=window["endTimestamp"],
    )
    assert not isinstance(res, ToolError), res
    sent = [s.sent_json for s in up.served if s.method == "POST"]
    assert sent and sent[0]["sites"][0][field] == window[field], sent


async def test_isp_null_entry_timestamp_without_a_window_is_not_sent(monkeypatch):
    res, up = await _isp(monkeypatch, sites=[{**_ENTRY, "beginTimestamp": None}])
    assert not isinstance(res, ToolError), res
    sent = [s.sent_json for s in up.served if s.method == "POST"]
    assert sent and "beginTimestamp" not in sent[0]["sites"][0], sent


@pytest.mark.parametrize("field", ["hostId", "siteId"])
@pytest.mark.parametrize("bad", ["", "  ", "x\n", " x", 5, ["x"]])
async def test_isp_nested_selector_is_checked_before_any_request(monkeypatch, field, bad):
    res, up = await _isp(monkeypatch, sites=[_ENTRY, {**_ENTRY, field: bad}])
    assert isinstance(res, ToolError) and f"sites[1].{field}" in str(res), res
    assert up.served == []


def test_isp_core_validator_applies_the_same_rules():
    with pytest.raises(ValueError, match=r"sites\[0\]\.hostId' has surrounding whitespace"):
        site_manager.validate_isp_sites([{"hostId": " h", "siteId": "s"}], None, None)
    with pytest.raises(ValueError, match="end_time must not be empty"):
        site_manager.validate_isp_query("1h", None, "   ")


@pytest.mark.parametrize("bad", ["", "  ", "x\n", "\tDefault"])
async def test_compare_site_performance_nested_site_checked_first(monkeypatch, bad):
    up = uh.FakeUpstream()
    uh.install(monkeypatch, up)
    with pytest.raises(ToolError, match=r"sites\[1\]"):
        await server.mcp.call_tool("compare_site_performance", {"sites": ["Default", bad]})
    assert up.served == []


# ============================================== names on an incomplete list
class _CappedClient:
    """A client whose host / site lists stop at a page cap; a duplicate name lies past it."""

    paginate_max_pages = 2

    def __init__(self, labels: list[str] | None = None) -> None:
        self._labels = labels or ["default"]

    def list_key_labels(self) -> list[str]:
        return list(self._labels)

    def get_key_by_label(self, label: str) -> APIKeyConfig:
        return APIKeyConfig(key=f"k-{label}-key", label=label)

    async def paginate(self, path: str, *, key: Any = None) -> list[dict[str, Any]]:
        if path == "/v1/hosts":
            items = [{"id": "AA:1", "reportedState": {"hostname": "hq"}}]
        else:
            items = [{"siteId": "a" * 24, "hostId": "AA:1", "meta": {"name": "Default"}}]
        # the twin ("hq" / "Default" again) is on page 3, never read
        raise PaginationAbortedError(path, 2, "page cap of 2 reached", items=items)

    async def paginate_offset(self, path: str, *, key: Any = None) -> list[dict[str, Any]]:
        items = [
            {
                "id": "00000000-0000-4000-8000-000000000001",
                "name": "Default",
                "internalReference": "default",
            }
        ]
        raise PaginationAbortedError(path, 2, "page cap of 2 reached", items=items)


_REFUSED = (
    "cannot resolve {!r} unambiguously: the {} list is incomplete (UNIFI_PAGINATE_MAX_PAGES=2)"
)


async def test_capped_lists_refuse_names_and_resolve_exact_ids():
    reg = Registry(_CappedClient())  # type: ignore[arg-type]
    with pytest.raises(ValueError) as exc:
        await reg.resolve_host_id("hq")
    assert _REFUSED.format("hq", "host") in str(exc.value)
    assert await reg.resolve_host_id("AA:1") == "AA:1"

    uuid = "00000000-0000-4000-8000-000000000001"
    for resolve in (reg.resolve_site_id, reg.resolve_site_slug):
        with pytest.raises(ValueError) as exc:
            await resolve("Default", "AA:1")
        assert _REFUSED.format("Default", "site") in str(exc.value)
    assert await reg.resolve_site_id(uuid, "AA:1") == uuid
    assert await reg.resolve_site_slug(uuid, "AA:1") == "default"

    with pytest.raises(ValueError) as exc:
        await reg.resolve_ea_site_id("Default")
    assert _REFUSED.format("Default", "site") in str(exc.value)
    assert await reg.resolve_ea_site_id("a" * 24) == "a" * 24

    with pytest.raises(ValueError) as exc:
        await site_manager._resolve_ea_site_record(reg, "Default")
    assert _REFUSED.format("Default", "site") in str(exc.value)
    record = await site_manager._resolve_ea_site_record(reg, "a" * 24)
    assert record["_resolvedSiteId"] == "a" * 24


async def test_capped_key_lists_refuse_a_name_for_key_routing():
    reg = Registry(_CappedClient(["alpha", "beta"]))  # type: ignore[arg-type]
    with pytest.raises(ValueError) as exc:
        await reg.resolve_key_for_host("hq")
    assert _REFUSED.format("hq", "host") in str(exc.value)
    key = await reg.resolve_key_for_host("AA:1")
    assert key is not None and key.label == "alpha"


# ============================================== wrong-typed fields -> shape errors
@pytest.mark.parametrize("meta", [123, "probe", ["x"]])
def test_ea_site_labels_wrong_typed_meta_is_a_shape_error(meta):
    with pytest.raises(ResponseShapeError, match="Unexpected response shape"):
        ea_site_labels({"siteId": "s1", "meta": meta})


@pytest.mark.parametrize("value", [123, ["x"], {"a": 1}])
def test_wrong_typed_ids_are_shape_errors(value):
    for check in (
        lambda: validate_host_id(value, "hostId"),
        lambda: validate_id(value, "id"),
        lambda: _assert_uuid(value),
    ):
        with pytest.raises(ResponseShapeError, match="Unexpected response shape"):
            check()
    # a shape error is also a ValueError, so per-record skips keep working
    assert issubclass(ResponseShapeError, ValueError)


@pytest.mark.parametrize("status", [["a"], 7, {"x": 1}])
def test_fleet_breakdown_wrong_typed_status_is_a_shape_error(status):
    with pytest.raises(ResponseShapeError, match="device status"):
        aggregation._count_key({"status": status}, ("status", "state"))
    assert aggregation._count_key({"status": None, "state": "online"}, ("status", "state")) == (
        "online"
    )
    assert aggregation._count_key({}, ("status", "state")) == "unknown"
