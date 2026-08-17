"""Tests for the shared write-payload sanitizer (``tools/_payload.py``).

These assert the *fixed* behavior: empty-string padding that the UniFi APIs add
to list fields is removed before a write, while every legitimate value — scalar
empty strings, numbers, booleans, order — survives. Each test names what it
proves so a future reader cannot mistake a padding-preserving regression for a
pass. See issue #164 (split from public #17).
"""

from __future__ import annotations

import pytest

from unifi_fabric.tools._payload import (
    require_fields,
    sanitize_integration_write,
    strip_empty_list_values,
    strip_readonly_fields,
)


class TestRequireFields:
    """The shared create/write required-field guard (issue #173)."""

    def test_passes_when_all_present(self):
        require_fields("create_x", {"a": 1, "b": 2, "extra": 3}, {"a", "b"})

    def test_names_missing_fields_sorted(self):
        with pytest.raises(ValueError) as exc:
            require_fields("create_x", {"a": 1}, {"a", "b", "c"})
        assert str(exc.value) == "create_x requires: b, c"

    def test_presence_not_value(self):
        # An explicit falsy/empty value still counts as present.
        require_fields("create_x", {"a": None, "b": ""}, {"a", "b"})

    def test_non_dict_payload_rejected(self):
        with pytest.raises(ValueError) as exc:
            require_fields("create_x", None, {"b", "a"})
        assert str(exc.value) == "create_x requires a JSON object with fields: a, b"


class TestStripEmptyListValues:
    def test_removes_empty_strings_from_list(self):
        """The reported failure: a padded IPv4 list loses only the placeholders."""
        assert strip_empty_list_values({"dns_servers": ["192.168.1.1", "", ""]}) == {
            "dns_servers": ["192.168.1.1"]
        }

    def test_preserves_real_values_in_order(self):
        """Surviving entries keep their original order — no reordering or dedup."""
        assert strip_empty_list_values({"dns_servers": ["1.1.1.1", "", "8.8.8.8", ""]}) == {
            "dns_servers": ["1.1.1.1", "8.8.8.8"]
        }

    def test_all_empty_list_becomes_empty_list(self):
        """A list that was pure padding collapses to ``[]`` (a valid 'no entries'
        value under PUT replace semantics) — the key is NOT dropped, so the
        caller's intent to clear the field is preserved."""
        result = strip_empty_list_values({"dns_servers": ["", "", ""]})
        assert result == {"dns_servers": []}
        assert "dns_servers" in result

    def test_scalar_empty_string_is_untouched(self):
        """A scalar field set to '' is a legitimate cleared value, not padding —
        it must survive. Only empty-string *list elements* are dropped."""
        assert strip_empty_list_values({"name": "", "note": ""}) == {"name": "", "note": ""}

    def test_non_string_list_elements_survive(self):
        """Numbers, booleans, and zero are not padding and must not be dropped —
        guards against a naive falsy check (``0``/``False`` are falsy but valid)."""
        assert strip_empty_list_values({"vlans": [0, 1, 2], "flags": [False, True]}) == {
            "vlans": [0, 1, 2],
            "flags": [False, True],
        }

    def test_recurses_into_nested_objects(self):
        """Padding buried inside a sub-object is cleaned too (e.g. a DHCP block),
        not just top-level list fields."""
        payload = {"ipV4Configuration": {"dhcp": {"dnsServers": ["10.0.0.1", "", ""]}}}
        assert strip_empty_list_values(payload) == {
            "ipV4Configuration": {"dhcp": {"dnsServers": ["10.0.0.1"]}}
        }

    def test_recurses_into_list_of_objects(self):
        """List elements that are objects are recursed into; their own padded
        lists are cleaned while the objects themselves are preserved."""
        payload = {"rules": [{"ports": ["80", "", "443"]}, {"ports": ["", "22"]}]}
        assert strip_empty_list_values(payload) == {
            "rules": [{"ports": ["80", "443"]}, {"ports": ["22"]}]
        }

    def test_does_not_mutate_input(self):
        """The caller's dict is never mutated in place — a fresh structure is
        returned so upstream state (e.g. a cached get_network result) is intact."""
        original = {"dns_servers": ["1.1.1.1", "", ""]}
        strip_empty_list_values(original)
        assert original == {"dns_servers": ["1.1.1.1", "", ""]}

    def test_noop_when_no_padding(self):
        """A payload with no padding is returned equal — the guard is a safe
        no-op, which is why it can sit on every round-trip write tool."""
        clean = {"name": "Guest", "vlan": 100, "dns_servers": ["1.1.1.1"]}
        assert strip_empty_list_values(clean) == clean


class TestStripReadonlyFields:
    """The Integration API rejects its own server-managed top-level fields on write
    with HTTP 400 ``unknown-property``. These assert they are removed so a
    ``get_* -> update_*`` round-trip of a whole object succeeds."""

    def test_strips_id_and_metadata(self):
        """id and metadata appear in every Integration get_* response and are
        rejected verbatim on PUT — both must go."""
        assert strip_readonly_fields({"id": "zone-1", "metadata": {"x": 1}, "name": "LAN"}) == {
            "name": "LAN"
        }

    def test_strips_default_and_index(self):
        """default (networks) and index (ordered firewall/ACL rules) are
        server-managed too — a policy round-trip 400s on $.index otherwise."""
        assert strip_readonly_fields(
            {"id": "p", "index": 3, "default": False, "action": "ALLOW"}
        ) == {"action": "ALLOW"}

    def test_only_top_level_removed(self):
        """A nested object may legitimately carry a field named ``id`` (a
        reference); only the document-root read-only fields are dropped."""
        payload = {"id": "net-1", "source": {"id": "grp-9", "kind": "network"}}
        assert strip_readonly_fields(payload) == {"source": {"id": "grp-9", "kind": "network"}}

    def test_keeps_unrelated_fields(self):
        """No writable field is touched — a clean create payload is unchanged."""
        clean = {"name": "Guest", "networkIds": ["n1"], "enabled": True}
        assert strip_readonly_fields(clean) == clean

    def test_non_dict_returned_unchanged(self):
        """Applied unconditionally, so a non-dict value passes straight through."""
        assert strip_readonly_fields(["a", "b"]) == ["a", "b"]

    def test_does_not_mutate_input(self):
        original = {"id": "z", "metadata": {}, "name": "LAN"}
        strip_readonly_fields(original)
        assert original == {"id": "z", "metadata": {}, "name": "LAN"}


class TestSanitizeIntegrationWrite:
    """The combined round-trip guard used by every Integration update tool."""

    def test_strips_readonly_and_padding_together(self):
        """A real read-modify-write body: the object's read-only fields AND the
        list padding are both gone; the actual edit survives."""
        body = {
            "id": "net-1",
            "metadata": {"created": 1},
            "default": False,
            "name": "Guest",
            "dns_servers": ["1.1.1.1", "", ""],
        }
        assert sanitize_integration_write(body) == {
            "name": "Guest",
            "dns_servers": ["1.1.1.1"],
        }
