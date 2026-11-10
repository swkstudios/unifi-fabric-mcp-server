"""Two pre-upstream behaviours: no unasked-for default, refusals only where the spec says.

1. ``orderDirection`` on the private Protect events endpoint (no spec, so no default is
   backed by a published contract): neither event tool sends it unless the caller passes one,
   and a passed value is sent as given.
2. ``_validate_ipv4`` refuses a leading-zero octet only for fields the pinned Mobility
   spec declares ``format: ipv4``; every caller is such a field (checked from source).
"""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric.families.mobility import mobility

EVENT_TOOLS = ("list_protect_events", "collect_protect_events")
SPEC = Path(__file__).parent / "fixtures" / "openapi" / "mobility-1.0.0.json"
IPV4_TOOL = "update_mobility_device_network"


def _args(name: str, **over: Any) -> dict[str, Any]:
    args = {**tool_args.generated_args(cti.TOOLS[name]), **over}
    if name == "collect_protect_events":
        args["poll_count"] = 1  # one poll
    return args


def _event_queries(up: uh.FakeUpstream) -> list[dict[str, list[str]]]:
    reads = [s for s in up.served if "/protect/api/events" in s.path]
    assert reads, "no events read reached the transport"
    return [parse_qs(s.query, keep_blank_values=True) for s in reads]


# --------------------------------------------------------------------------- 1. order
@pytest.mark.parametrize("name", EVENT_TOOLS)
async def test_no_order_direction_is_sent_unless_the_caller_passes_one(monkeypatch, name):
    up = uh.FakeUpstream()
    args = _args(name)
    args.pop("order_direction", None)
    await cti._call(monkeypatch, name, up, args)
    for query in _event_queries(up):
        assert "orderDirection" not in query, query


@pytest.mark.parametrize("name", EVENT_TOOLS)
@pytest.mark.parametrize("value", ["ASC", "DESC", "desc"])
async def test_a_passed_order_direction_is_sent_as_given(monkeypatch, name, value):
    up = uh.FakeUpstream()
    await cti._call(monkeypatch, name, up, _args(name, order_direction=value))
    for query in _event_queries(up):
        assert query["orderDirection"] == [value], query


@pytest.mark.parametrize("name", EVENT_TOOLS)
def test_order_direction_is_optional_with_no_default(name):
    prop = cti.TOOLS[name].parameters["properties"]["order_direction"]
    assert prop.get("default") is None
    assert "order_direction" not in cti.TOOLS[name].parameters.get("required", [])


# --------------------------------------------------------------------------- 2. ipv4
def _ipv4_fields_in_spec() -> set[str]:
    spec = json.loads(SPEC.read_text())
    props = spec["components"]["schemas"]["UpdateNetworkReq"]["properties"]
    return {name for name, schema in props.items() if schema.get("format") == "ipv4"}


def _validated_fields_in_source() -> set[str]:
    source = inspect.getsource(mobility)
    return set(re.findall(r'_validate_ipv4\(\s*\w+,\s*"(\w+)"\s*\)', source))


def test_every_ipv4_refusal_is_backed_by_the_pinned_spec():
    validated = _validated_fields_in_source()
    assert validated == {"host_address", "dhcp_range_start", "dhcp_range_stop"}
    # each validated field is format: ipv4 in the spec, and each such field is validated
    assert validated == _ipv4_fields_in_spec()
    assert len(re.findall(r"_validate_ipv4\(", inspect.getsource(mobility))) == len(validated) + 1


@pytest.mark.parametrize("field", ["host_address", "dhcp_range_start", "dhcp_range_stop"])
@pytest.mark.parametrize("value", ["192.168.01.1", "010.0.0.1", "10.0.0.256", "10.0.0"])
async def test_spec_ipv4_field_refuses_a_non_dotted_quad_before_any_request(
    monkeypatch, field, value
):
    up = uh.FakeUpstream()
    with pytest.raises(ToolError) as exc:
        await cti._call(monkeypatch, IPV4_TOOL, up, _args(IPV4_TOOL, **{field: value}))
    assert field in str(exc.value) and value in str(exc.value), str(exc.value)
    assert up.served == [], [(s.method, s.path) for s in up.served]


@pytest.mark.parametrize("field", ["host_address", "dhcp_range_start", "dhcp_range_stop"])
async def test_spec_ipv4_field_sends_a_valid_address_verbatim(monkeypatch, field):
    up = uh.FakeUpstream()
    await cti._call(monkeypatch, IPV4_TOOL, up, _args(IPV4_TOOL, **{field: "192.168.10.1"}))
    writes = [s for s in up.served if s.method == "PUT"]
    assert writes, "the write did not reach the transport"
    assert writes[-1].sent_json[field] == "192.168.10.1"
