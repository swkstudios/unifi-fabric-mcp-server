"""Direct helper validation preserves complete echoed caller data."""

import pytest

from unifi_fabric.tools import carrier_fabric, mobility, site_manager


@pytest.mark.parametrize(
    "validate",
    [
        lambda: mobility._validate_ipv4("x" * 10000, "address"),
        lambda: site_manager.validate_isp_query("x" * 10000, None, None),
    ],
)
def test_invalid_input_echo_is_complete(validate):
    with pytest.raises(ValueError) as caught:
        validate()
    assert "x" * 10000 in str(caught.value)
    assert "truncated" not in str(caught.value)


def test_metadata_cycle_names_circular_reference():
    value = {}
    value["child"] = value
    with pytest.raises(ValueError, match="Circular reference"):
        carrier_fabric._validate_metadata(value)
