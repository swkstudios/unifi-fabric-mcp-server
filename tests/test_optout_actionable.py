"""Opted-out (read-only) refusal messages are actionable.

Each per-area write opt-out, when an operator sets its ``family:<area>=deny`` entry in
``UNIFI_WRITE_EXCEPTIONS`` for a read-only deployment, must name the env var, the value
that re-enables it, and WHERE the knob lives (the service `environment:` block in the deploy
docker-compose). Connector write stays ON by default (no default change) — the
default-ON behaviour is covered in tests/test_connector.py.

Every switch is read from the server process's environment when the call is made
(``unifi_fabric.policy.current``), so a shell ``export`` in the shell that starts the server works;
only a host export is invisible inside a container. No message may say otherwise.
"""

from __future__ import annotations

import pytest

from unifi_fabric import switches
from unifi_fabric.families.carrier.carrier_fabric import DISABLED_MSG as CARRIER_MSG
from unifi_fabric.families.connector import connector
from unifi_fabric.families.mobility.mobility import DISABLED_MSG as MOBILITY_MSG
from unifi_fabric.families.protect.protect import MUTATIONS_DISABLED_REASON as PROTECT_MSG


def _assert_actionable(msg: str, var: str) -> None:
    assert var in msg, f"message must name the exception {var}"
    # the setting that holds it, and how to allow writes again
    assert "UNIFI_WRITE_EXCEPTIONS" in msg, "message must name the setting"
    assert "remove that item" in msg, "message must state how to allow writes"
    # where the knob lives
    assert "environment:" in msg, "message must name the compose environment: location"
    assert "docker-compose" in msg, "message must point at the deploy docker-compose"
    # a shell export works when the server is started from that shell (env_flag reads
    # the process environment); only a host export does not reach a container
    assert "not a shell export" not in msg, "a shell export does reach the server process"
    assert "the environment of the shell that starts the server" in msg, msg


async def test_connector_optout_message_is_actionable():
    # Opted out (family:connector=deny -> write_enabled=False): refused
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
    _assert_actionable(str(ei.value), "family:connector=deny")


def test_carrier_optout_message_is_actionable():
    _assert_actionable(CARRIER_MSG, "family:carrier=deny")


def test_mobility_optout_message_is_actionable():
    _assert_actionable(MOBILITY_MSG, "family:mobility=deny")


def test_protect_optout_message_is_actionable():
    _assert_actionable(PROTECT_MSG, "family:protect=deny")


@pytest.mark.parametrize("switch", switches.AREA_WRITE_SWITCHES, ids=lambda sw: sw.env)
def test_every_relay_area_optout_message_is_actionable(switch):
    _assert_actionable(connector._AREA_REASONS[switch.env], switch.env)


def test_connector_refusal_text_is_actionable():
    _assert_actionable(connector.connector_write_refusal("POST"), "family:connector=deny")


@pytest.mark.parametrize(
    "env", [connector.CONNECTOR_WRITE_ENV, *(sw.env for sw in switches.AREA_WRITE_SWITCHES)]
)
def test_an_exported_exception_is_read_from_the_process_environment(monkeypatch, env):
    # What a shell export does: the setting is in the server process's environment.
    family = env.split(":", 1)[1].split("=", 1)[0]
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", env)
    assert switches.family_denied(family) is True
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", env.replace("=deny", "=dry-run"))
    assert switches.family_denied(family) is False
