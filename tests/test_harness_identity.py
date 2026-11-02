"""Generated upstream catalogues reserve the selector MAC for record zero."""

import pytest

from tests import upstream_harness as uh


@pytest.mark.parametrize("count", [171, 10000])
def test_catalogue_has_unique_mac_identities(count):
    rows = [uh.make_record(n, "catalogue") for n in range(count)]
    macs = [row["mac"] for row in rows]
    assert len(set(macs)) == count
    assert macs.count(uh.ARG_MAC) == 1
    assert all(row["macAddress"] == row["mac"] for row in rows)


def test_catalogue_preserves_argument_row_and_native_id_sequence():
    first = uh.make_record(0, "catalogue")
    assert (first["id"], first["_id"], first["mac"]) == (uh.ARG_ID, uh.ARG_HEX, uh.ARG_MAC)
    for n in (1, 169, 170, 171, 9999):
        row = uh.make_record(n, "catalogue")
        assert row["id"] == f"00000000-0000-4000-8000-{n + 0x1000:012x}"
        assert row["_id"] == f"{n + 0x1000:024x}"
        assert row["probe"] == f"catalogue#{n}"
