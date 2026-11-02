"""N06: the advertised delete descriptions state the deletion_result dry-run shape."""

from __future__ import annotations

import pytest

from tests import test_cross_tool_invariants as cti


@pytest.mark.parametrize("name", ["delete_policy_engine_rule", "delete_network_members_group"])
def test_delete_description_states_the_deletion_result_dry_run_shape(name):
    # The advertised text is the docstring; compare across its line wraps.
    description = " ".join((cti.TOOLS[name].description or "").split())
    assert "deleted: false" in description, description
    assert "response" in description, description
    # the bare client preview is no longer the advertised dry-run result
    assert "message, preview:" not in description.split("UNIFI_DRY_RUN", 1)[1].split("response")[0]
