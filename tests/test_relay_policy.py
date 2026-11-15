"""unifi_fabric.relay_policy: the connector relay's write policy, moved out of the family."""

from __future__ import annotations

from unifi_fabric import relay_policy, switches
from unifi_fabric.families.carrier import carrier_fabric
from unifi_fabric.families.connector import connector
from unifi_fabric.families.mobility import mobility
from unifi_fabric.families.protect import protect


def test_area_reasons_equal_each_family_own_text():
    """The relay rebuilds the per-area refusal texts from ``switches`` so core code never
    imports a family; each must stay equal to the family's own text (design review C4)."""
    assert relay_policy._AREA_REASONS[protect.PROTECT_MUTATIONS_ENV] == (  # noqa: SLF001
        protect.MUTATIONS_DISABLED_REASON
    )
    assert relay_policy._AREA_REASONS[mobility.WRITE_ENABLED_ENV] == mobility.DISABLED_MSG  # noqa: SLF001
    assert relay_policy._AREA_REASONS[carrier_fabric.WRITE_ENABLED_ENV] == (  # noqa: SLF001
        carrier_fabric.DISABLED_MSG
    )
    assert set(relay_policy._AREA_REASONS) == {  # noqa: SLF001
        switch.env for switch in switches.AREA_WRITE_SWITCHES
    }


def test_connector_reexports_the_same_objects():
    for name in relay_policy.__all__:
        assert getattr(connector, name) is getattr(relay_policy, name), name
