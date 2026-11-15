"""Follow-ups to the 11.1.47 coverage: threat_signature and the critical-operation error path.

* ``query_traffic_flows(threat_signature=...)`` sends the body key ``ips_signature_id`` as an
  array, the key the Network 11.1.47 web app filters flows by IPS signature with
  (request-key enum next to ``risk``, ``action``, ``direction``); an explicit body key wins
  and nothing is sent when it is unset.
* The 11.1.47 web app sends no override key with upgrade, restart or reboot commands (its
  critical-upgrade guard is a confirm dialog and a disabled button); an upstream refusal
  therefore reaches the caller verbatim, is sent once, and no tool offers an override argument.
  The 409 and its message are synthetic: no console-side refusal is confirmed.
"""

from __future__ import annotations

import contextlib
import json

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric.families.network import network_nat_qos_traffic as nc


def test_threat_signature_becomes_the_ips_signature_id_array() -> None:
    assert nc._traffic_flow_body(None, None, None, None, None, 2027750) == {
        "ips_signature_id": [2027750]
    }
    assert nc._traffic_flow_body(None, None, None, None, None, "sig-1") == {
        "ips_signature_id": ["sig-1"]
    }
    assert nc._traffic_flow_body(None, None, None, None, None, [1, "2"]) == {
        "ips_signature_id": [1, "2"]
    }


def test_threat_signature_is_absent_when_unset_and_loses_to_an_explicit_body_key() -> None:
    assert nc._traffic_flow_body(None, None, None, None, None) is None
    assert nc._traffic_flow_body({"pageSize": 5}, None, None, None, None) == {"pageSize": 5}
    body = {"ips_signature_id": ["caller"]}
    assert nc._traffic_flow_body(body, None, None, None, None, 7) == {
        "ips_signature_id": ["caller"]
    }


async def test_threat_signature_reaches_the_flows_request(monkeypatch) -> None:
    up = uh.FakeUpstream()
    args = {
        **tool_args.generated_args(cti.TOOLS["query_traffic_flows"]),
        "threat_signature": 2027750,
        "body": {"pageSize": 1},
    }
    # The synthetic flows page is not the console's paged envelope, so the drain may refuse
    # the reply; the request that was sent is what this test reads.
    with contextlib.suppress(ToolError):
        await cti._call(monkeypatch, "query_traffic_flows", up, args=args)
    posts = [s for s in up.served if s.method == "POST" and s.path.endswith("/traffic-flows")]
    assert posts and posts[0].sent_json["ips_signature_id"] == [2027750]


_CRITICAL_REFUSAL = json.dumps({"meta": {"rc": "error", "msg": "api.err.UpgradeInProgress"}})
_UPGRADE_RESTART_TOOLS = (
    "restart_device",
    "upgrade_device",
    "upgrade_all_devices",
    "start_rolling_upgrade",
    "reboot_unifi_os_console",
)


@pytest.mark.parametrize("name", _UPGRADE_RESTART_TOOLS)
async def test_an_upstream_refusal_of_a_critical_operation_reaches_the_caller_once(
    monkeypatch, name
) -> None:
    up = uh.FakeUpstream(write_status=409, error_body=_CRITICAL_REFUSAL)
    with pytest.raises(ToolError) as exc:
        await cti._call(monkeypatch, name, up)
    text = str(exc.value)
    assert "api.err.UpgradeInProgress" in text and "409" in text
    assert len(up.writes()) == 1, f"{name}: a refused write must be sent exactly once"


@pytest.mark.parametrize("name", _UPGRADE_RESTART_TOOLS)
def test_no_upgrade_or_restart_tool_offers_an_override_argument(name) -> None:
    properties = set((cti.TOOLS[name].parameters or {}).get("properties") or {})
    assert not {p for p in properties if p.startswith(("force", "override", "ignore"))}, name
