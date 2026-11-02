"""N01: advertised text matches the code, and no argument is silently overridden or dropped."""

from __future__ import annotations

import pytest

from tests import test_cross_tool_invariants as cti

VERIFIED_UPDATES = ["update_my_admin_profile"]


@pytest.mark.parametrize("name", VERIFIED_UPDATES)
def test_verified_update_text_states_the_non_object_wrapping(name):
    """A non-object update body comes back under ``response`` beside _verified; the advertised
    description and the docstring say so."""
    description = cti.TOOLS[name].description or ""
    assert "under response" in description, description
