"""Opted-out (read-only) refusal messages are actionable.

Each per-area write opt-out, when an operator sets it to a falsey value for a
read-only deployment, must name the env var, the value that re-enables it, and
WHERE the knob lives (the service `environment:` block in the deploy
docker-compose). Connector write stays ON by default (no default change) — the
default-ON behaviour is covered in tests/test_connector.py.

Every switch is read from the server process's environment when the call is made
(``switches.env_flag``), so a shell ``export`` in the shell that starts the server works;
only a host export is invisible inside a container. No message may say otherwise.
"""

from __future__ import annotations

import pytest

from unifi_fabric import switches
from unifi_fabric.tools import connector
from unifi_fabric.tools.carrier_fabric import DISABLED_MSG as CARRIER_MSG
from unifi_fabric.tools.mobility import DISABLED_MSG as MOBILITY_MSG
from unifi_fabric.tools.protect import MUTATIONS_DISABLED_REASON as PROTECT_MSG


def _assert_actionable(msg: str, var: str) -> None:
    assert var in msg, f"message must name the env var {var}"
    # value that re-enables the area
    assert "1/true/yes/on" in msg, "message must state the value to re-enable"
    # where the knob lives
    assert "environment:" in msg, "message must name the compose environment: location"
    assert "docker-compose" in msg, "message must point at the deploy docker-compose"
    # a shell export works when the server is started from that shell (env_flag reads
    # the process environment); only a host export does not reach a container
    assert "not a shell export" not in msg, "a shell export does reach the server process"
    assert "the environment of the shell that starts the server" in msg, msg


async def test_connector_optout_message_is_actionable():
    # Opted out (UNIFI_ENABLE_CONNECTOR_WRITE=0 -> write_enabled=False): refused
    # before any network call, with an actionable message.
    with pytest.raises(ValueError) as ei:
        await connector.connector_write(
            None,  # client unused before the gate raise
            None,  # registry unused before the gate raise
            "h",
            "PUT",
            "network/api/s/{site}/rest/device/x",
            site="Office",
            write_enabled=False,
        )
    _assert_actionable(str(ei.value), "UNIFI_ENABLE_CONNECTOR_WRITE")


def test_carrier_optout_message_is_actionable():
    _assert_actionable(CARRIER_MSG, "UNIFI_ENABLE_CARRIER_FABRIC_WRITE")


def test_mobility_optout_message_is_actionable():
    _assert_actionable(MOBILITY_MSG, "UNIFI_ENABLE_MOBILITY_WRITE")


def test_protect_optout_message_is_actionable():
    _assert_actionable(PROTECT_MSG, "UNIFI_PROTECT_MUTATIONS_ENABLED")


@pytest.mark.parametrize("switch", switches.AREA_WRITE_SWITCHES, ids=lambda sw: sw.env)
def test_every_relay_area_optout_message_is_actionable(switch):
    _assert_actionable(connector._AREA_REASONS[switch.env], switch.env)


def test_connector_refusal_text_is_actionable():
    _assert_actionable(connector.connector_write_refusal("POST"), "UNIFI_ENABLE_CONNECTOR_WRITE")


@pytest.mark.parametrize(
    "env", [connector.CONNECTOR_WRITE_ENV, *(sw.env for sw in switches.AREA_WRITE_SWITCHES)]
)
def test_an_exported_switch_is_read_from_the_process_environment(monkeypatch, env):
    # What a shell export does: the variable is in the server process's environment.
    monkeypatch.setenv(env, "0")
    assert switches.env_flag(env, True) is False
    monkeypatch.setenv(env, "1")
    assert switches.env_flag(env, True) is True
