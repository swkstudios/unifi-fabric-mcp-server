"""Hermetic contract tests for the bounded UniFi placement snapshot."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools.placement_snapshot import (
    APPROVED_READ_SOURCES,
    CAPABILITY_OUTCOMES,
    DEVICE_TYPES,
    FRESHNESS_TTL_SECONDS,
    PLACEMENT_SNAPSHOT_CAPABILITY_SCHEMA_VERSION,
    SCHEMA_VERSION,
    _capability_outcome,
    _derive_device_type,
    _fingerprint_icon,
    build_snapshot,
    get_unifi_placement_snapshot,
    preflight_placement_snapshot_capabilities,
)


def _source_payloads() -> dict[str, dict]:
    return {
        "project": {
            "mode": "3D",
            "project": {
                "project": {"updatedAt": "2026-08-20T14:00:00Z"},
                "products": [],
                "wallTypes": [],
                "plans": [
                    {"id": "floor-two", "name": "Floor 2", "ordering": 2, "scale": 57.2},
                    {"id": "floor-one", "name": "Floor 1", "ordering": 1, "scale": 60.0},
                ],
                "shapes": [
                    {
                        "type": "device",
                        "id": "placement-camera-1",
                        "title": "Office Camera",
                        "productId": "uvc-g5-bullet",
                        "mount": "wall",
                        "planId": "floor-two",
                        "position": [{"x": 1.5, "y": -2.0, "z": 2.4}],
                        "rotation": {
                            "pov": {"x": 0, "y": 0, "z": 0, "w": 1},
                            "base": {"x": 0, "y": 0, "z": 0, "w": 1},
                        },
                        "meta": {
                            "mac": "aa:bb:cc:dd:ee:ff",
                            "ip": "192.0.2.42",
                            "serial": "SERIAL-SECRET",
                            "browserId": "browser-secret",
                            "accessToken": "token-secret",
                        },
                    },
                    {
                        "type": "wall",
                        "planId": "floor-two",
                        "variant": "drywall_heavy",
                        "position": [{"x": 0, "y": 0}, {"x": 3, "y": 0}],
                    },
                ],
            },
        },
        "cameras": {
            "result": [
                {
                    "id": "camera-1",
                    "name": "Office Camera",
                    "model": "UVC G5 Bullet",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "ip": "192.0.2.42",
                    "accessToken": "token-secret",
                }
            ]
        },
        "sensors": {
            "result": [
                {
                    "id": "sensor-1",
                    "name": "Hall Sensor",
                    "model": "UP-Sense",
                    "serial": "SERIAL-SECRET",
                }
            ]
        },
        "devices": {
            "data": [
                {
                    "id": "network-1",
                    "name": "Office Switch",
                    "model": "USW Lite 8 PoE",
                    "mac": "00:11:22:33:44:55",
                    "ip": "192.0.2.3",
                    "cookie": "cookie-secret",
                }
            ]
        },
    }


class TestBuildSnapshot:
    def test_schema_freshness_provenance_and_safe_projection(self):
        payloads = _source_payloads()
        result = build_snapshot(
            project_result=payloads["project"],
            cameras_result=payloads["cameras"],
            sensors_result=payloads["sensors"],
            devices_result=payloads["devices"],
            generated_at=datetime(2026, 8, 20, 15, 0, tzinfo=UTC),
        )

        assert result["schema_version"] == SCHEMA_VERSION
        assert result["generated_at"] == "2026-08-20T15:00:00Z"
        assert result["freshness"] == {
            "observed_at": "2026-08-20T15:00:00Z",
            "max_age_seconds": FRESHNESS_TTL_SECONDS,
            "cache": "none",
        }
        assert result["provenance"]["approved_read_sources"] == list(APPROVED_READ_SOURCES)
        assert result["provenance"]["read_only"] is True
        # no write-fence claim: the collector runs under any connector-write setting
        assert "connector_write_required_setting" not in result["provenance"]
        assert result["provenance"]["innerspace_project_updated_at"] == "2026-08-20T14:00:00Z"

        assert [floor["source_id"] for floor in result["floors"]] == ["floor-one", "floor-two"]
        assert result["placed_devices"] == [
            {
                "source_id": "placement-camera-1",
                "display_name": "Office Camera",
                "product_id": "uvc-g5-bullet",
                "mount": "wall",
                "floor_source_id": "floor-two",
                "position": {"x": 1.5, "y": -2.0, "z": 2.4},
                "rotation": {
                    "pov": {"x": 0, "y": 0, "z": 0, "w": 1},
                    "base": {"x": 0, "y": 0, "z": 0, "w": 1},
                },
                # additive v1 keys, verbatim by default (UNIFI_REDACT_SECRETS off)
                "ip": "192.0.2.42",
                "mac": "aa:bb:cc:dd:ee:ff",
            }
        ]
        assert result["placement_links"] == [
            {
                "inventory_source_id": "camera-1",
                "placement_source_id": "placement-camera-1",
                "match_method": "unique_exact_display_name",
            }
        ]
        cams = [t for t in result["topology"] if t["kind"] == "protect_camera"]
        assert (cams[0]["mac"], cams[0]["ip"]) == ("aa:bb:cc:dd:ee:ff", "192.0.2.42")
        assert "_withheld" not in result

        # The closed field selection still copies no unknown upstream key (opt-in
        # withholding does not change field selection).
        serialized = repr(result).lower()
        for not_selected in ("serial-secret", "token-secret", "browser-secret", "cookie-secret"):
            assert not_selected not in serialized

    def test_redaction_on_withholds_the_address_fields(self):
        payloads = _source_payloads()
        result = build_snapshot(
            project_result=payloads["project"],
            cameras_result=payloads["cameras"],
            sensors_result=payloads["sensors"],
            devices_result=payloads["devices"],
            generated_at=datetime(2026, 8, 20, 15, 0, tzinfo=UTC),
            redact_secrets=True,
        )
        serialized = repr(result).lower()
        for forbidden in (
            "aa:bb:cc",
            "192.0.2.",
            "serial-secret",
            "token-secret",
            "browser-secret",
            "cookie-secret",
        ):
            assert forbidden not in serialized
        withheld = result["_withheld"]
        assert withheld["placed_devices.mac"] == {"hardware_address": 1}
        assert withheld["placed_devices.ip"] == {"network_address": 1}
        assert withheld["topology.mac"] == {"hardware_address": 2}
        assert withheld["topology.ip"] == {"network_address": 2}
        assert set(result["_withheld_how_to_obtain"]) == set(withheld)

    def test_ambiguous_names_are_not_used_as_identity_links(self):
        payloads = _source_payloads()
        payloads["cameras"]["result"].append(
            {"id": "camera-duplicate", "name": "Office Camera", "model": "UVC G5 Bullet"}
        )
        result = build_snapshot(
            project_result=payloads["project"],
            cameras_result=payloads["cameras"],
            sensors_result=payloads["sensors"],
            devices_result=payloads["devices"],
        )
        assert result["placement_links"] == []

    def test_site_manager_host_wrappers_are_flattened(self):
        """Site-Manager groups devices by console; every wrapped device must surface.

        Regression: ``/v1/devices`` returns ``{hostId, hostName, devices:[...]}``
        wrappers, not bare devices. Projecting the wrapper found no id/name and
        collapsed the whole network-device category to one identity-less node.
        """
        payloads = _source_payloads()
        # Real Site-Manager shape: host-grouped wrappers carrying nested devices.
        payloads["devices"]["data"] = [
            {
                "hostId": "console-uuid-alpha",
                "hostName": "HQ-Unifi",
                "devices": [
                    {
                        "id": "dev-uuid-switch",
                        "name": "Office Switch",
                        "model": "USW Pro 24 PoE",
                        "mac": "aa:bb:cc:00:00:01",
                        "ipAddress": "192.0.2.11",
                    },
                    {
                        "id": "dev-uuid-ap-1",
                        "name": "AP North",
                        "model": "U6 Pro",
                        "mac": "aa:bb:cc:00:00:02",
                        "ipAddress": "192.0.2.12",
                    },
                    {
                        "id": "dev-uuid-ap-2",
                        "name": "AP South",
                        "model": "U6 Pro",
                        "mac": "aa:bb:cc:00:00:03",
                        "ipAddress": "192.0.2.13",
                    },
                ],
            },
            {
                "hostId": "console-uuid-beta",
                "hostName": "HQ-Unifi-Edge",
                "devices": [
                    {
                        "id": "dev-uuid-gateway",
                        "name": "Site Gateway",
                        "model": "UXG Pro",
                        "mac": "aa:bb:cc:00:00:04",
                        "ipAddress": "192.0.2.1",
                    }
                ],
            },
        ]
        # A placement whose display name matches a flattened device proves links resolve.
        payloads["project"]["project"]["shapes"].append(
            {
                "type": "device",
                "id": "placement-switch-1",
                "title": "Office Switch",
                "productId": "usw-pro-24-poe",
                "mount": "rack",
                "planId": "floor-one",
                "position": [{"x": 4.0, "y": 5.0, "z": 0.0}],
            }
        )

        result = build_snapshot(
            project_result=payloads["project"],
            cameras_result=payloads["cameras"],
            sensors_result=payloads["sensors"],
            devices_result=payloads["devices"],
            generated_at=datetime(2026, 8, 20, 15, 0, tzinfo=UTC),
        )

        network_nodes = [n for n in result["topology"] if n["kind"] == "network_device"]
        # Four wrapped devices across two consoles -> four distinct nodes (not one).
        assert [n["source_id"] for n in network_nodes] == [
            "dev-uuid-switch",
            "dev-uuid-ap-1",
            "dev-uuid-ap-2",
            "dev-uuid-gateway",
        ]
        # Every node carries a kind and a stable source_id.
        assert all(
            n.get("kind") == "network_device" and isinstance(n.get("source_id"), str)
            for n in network_nodes
        )
        # All topology source_ids are unique (cameras + sensors + network devices).
        topology_ids = [n["source_id"] for n in result["topology"]]
        assert len(topology_ids) == len(set(topology_ids))
        # The network-device placement link resolves through the flattened records.
        assert {
            "inventory_source_id": "dev-uuid-switch",
            "placement_source_id": "placement-switch-1",
            "match_method": "unique_exact_display_name",
        } in result["placement_links"]
        # Each device's own MAC is its additive ``mac`` key, verbatim; the console
        # wrapper's fields (hostId / hostName) are not copied into any node.
        assert [n["mac"] for n in network_nodes] == [
            "aa:bb:cc:00:00:01",
            "aa:bb:cc:00:00:02",
            "aa:bb:cc:00:00:03",
            "aa:bb:cc:00:00:04",
        ]
        serialized = repr(result).casefold()
        for not_selected in ("console-uuid", "hq-unifi-edge"):
            assert not_selected not in serialized

    def test_infra_devices_get_stable_ids_and_protect_duplicates_are_dropped(self):
        """Both post-flatten defects: null infra ids, and Protect hardware listed twice.

        Regression for the two residual emitter defects observed on live prod output
        (0.6.4-dev.2):

        (a) Site Manager infrastructure records (gateway/switch/AP) carry only a
            ``mac`` — no ``id``/``deviceId`` — so ``source_id`` came out null.
        (b) Site Manager also lists the Protect cameras/sensors, so every Protect
            device was emitted twice: once under its real kind and again as a
            ``network_device`` with the identical ``source_id``.
        """
        payloads = _source_payloads()
        payloads["cameras"]["result"] = [
            {"id": "protect-camera-1", "name": "Office Camera", "model": "UVC G5 Bullet"}
        ]
        payloads["sensors"]["result"] = [
            {"id": "protect-sensor-1", "name": "Hall Sensor", "model": "UP-Sense"}
        ]
        payloads["devices"]["data"] = [
            {
                "hostId": "console-uuid-alpha",
                "hostName": "HQ-Unifi",
                "devices": [
                    # Infra devices: MAC-only, no id/deviceId (defect a).
                    {
                        "name": "HQ",
                        "model": "UDM Pro",
                        "mac": "aa:bb:cc:00:00:01",
                        "ipAddress": "192.0.2.1",
                    },
                    {
                        "name": "USW Pro 24 PoE",
                        "model": "USW Pro 24 PoE",
                        "mac": "aa:bb:cc:00:00:02",
                    },
                    {
                        "name": "AP01-Office",
                        "model": "U6 Pro",
                        "mac": "aa:bb:cc:00:00:03",
                    },
                    # Protect hardware re-listed by Site Manager with the SAME id the
                    # Protect pass already emitted (defect b).
                    {
                        "id": "protect-camera-1",
                        "name": "Office Camera",
                        "model": "UVC G5 Bullet",
                        "mac": "aa:bb:cc:00:00:04",
                    },
                    {
                        "id": "protect-sensor-1",
                        "name": "Hall Sensor",
                        "model": "UP-Sense",
                        "mac": "aa:bb:cc:00:00:05",
                    },
                ],
            }
        ]

        result = build_snapshot(
            project_result=payloads["project"],
            cameras_result=payloads["cameras"],
            sensors_result=payloads["sensors"],
            devices_result=payloads["devices"],
            generated_at=datetime(2026, 8, 20, 15, 0, tzinfo=UTC),
        )
        topology = result["topology"]
        source_ids = [n["source_id"] for n in topology]

        # No null source_ids and no duplicates across the whole collection.
        assert all(isinstance(n.get("source_id"), str) for n in topology)
        assert None not in source_ids
        assert len(source_ids) == len(set(source_ids))

        # Every kind of node keeps a stable, non-empty source_id.
        by_kind: dict[str, list[dict]] = {}
        for node in topology:
            by_kind.setdefault(node["kind"], []).append(node)

        # Protect devices appear exactly once, under their real kind.
        assert [n["source_id"] for n in by_kind["protect_camera"]] == ["protect-camera-1"]
        assert [n["source_id"] for n in by_kind["protect_sensor"]] == ["protect-sensor-1"]
        assert "protect-camera-1" not in [n["source_id"] for n in by_kind["network_device"]]
        assert "protect-sensor-1" not in [n["source_id"] for n in by_kind["network_device"]]

        # The three MAC-only infra devices survive with derived, stable ids.
        infra_ids = [n["source_id"] for n in by_kind["network_device"]]
        assert len(infra_ids) == 3
        assert all(sid.startswith("smdev-") for sid in infra_ids)
        assert [n["display_name"] for n in by_kind["network_device"]] == [
            "HQ",
            "USW Pro 24 PoE",
            "AP01-Office",
        ]

        # Derived ids are deterministic: a second build yields identical ids.
        again = build_snapshot(
            project_result=payloads["project"],
            cameras_result=payloads["cameras"],
            sensors_result=payloads["sensors"],
            devices_result=payloads["devices"],
            generated_at=datetime(2026, 8, 20, 15, 0, tzinfo=UTC),
        )
        assert [n["source_id"] for n in again["topology"]] == source_ids

        # The derived id is a digest, not the MAC; the MAC is the separate ``mac`` key.
        for node in by_kind["network_device"]:
            assert "aa:bb:cc" not in node["source_id"]
        assert [n["mac"] for n in by_kind["network_device"]] == [
            "aa:bb:cc:00:00:01",
            "aa:bb:cc:00:00:02",
            "aa:bb:cc:00:00:03",
        ]
        # the same ids with redaction on: source_id does not depend on the setting
        redacted = build_snapshot(
            project_result=payloads["project"],
            cameras_result=payloads["cameras"],
            sensors_result=payloads["sensors"],
            devices_result=payloads["devices"],
            generated_at=datetime(2026, 8, 20, 15, 0, tzinfo=UTC),
            redact_secrets=True,
        )
        assert [n["source_id"] for n in redacted["topology"]] == source_ids
        assert "aa:bb:cc" not in repr(redacted).casefold()
        serialized = repr(result).casefold()
        assert "console-uuid" not in serialized

    @staticmethod
    def _adversarial_payloads() -> dict[str, dict]:
        payloads = _source_payloads()
        project = payloads["project"]["project"]
        placed = project["shapes"][0]
        placed.update(
            {
                "id": "aa:bb:cc:dd:ee:ff",
                "title": "Office access_token_marker",
                "productId": "https://example.invalid/product",
                "mount": "192.0.2.91",
                "planId": "browser-id-marker",
            }
        )
        project["plans"][0].update(
            {
                "id": "cookie-value-marker",
                "name": "Floor 2001:db8::1",
            }
        )
        project["shapes"][1].update(
            {"variant": "serial-number-marker", "planId": "00:11:22:33:44:55"}
        )
        payloads["cameras"]["result"][0].update(
            {
                "id": "203.0.113.11",
                "name": "Camera bearer-marker",
                "model": "data:text/plain,opaque",
            }
        )
        payloads["sensors"]["result"][0].update(
            {
                "id": "session-id-marker",
                "name": "Sensor password-marker",
                "model": "access-key-marker",
            }
        )
        payloads["devices"]["data"][0].update(
            {
                "id": "aabbccddeeff",
                "name": "Switch private-key-marker",
                "model": "cookie-value-marker",
            }
        )
        return payloads

    _ADVERSARIAL = (
        "aa:bb:cc:dd:ee:ff",
        "access_token_marker",
        "https://example.invalid/product",
        "192.0.2.91",
        "browser-id-marker",
        "cookie-value-marker",
        "2001:db8::1",
        "serial-number-marker",
        "00:11:22:33:44:55",
        "203.0.113.11",
        "bearer-marker",
        "data:text/plain,opaque",
        "session-id-marker",
        "password-marker",
        "access-key-marker",
        "aabbccddeeff",
        "private-key-marker",
    )

    def test_sensitive_looking_values_are_verbatim_by_default(self):
        """Withholding is opt-in (UNIFI_REDACT_SECRETS); the default is verbatim."""
        payloads = self._adversarial_payloads()
        result = build_snapshot(
            project_result=payloads["project"],
            cameras_result=payloads["cameras"],
            sensors_result=payloads["sensors"],
            devices_result=payloads["devices"],
        )
        serialized = repr(result).casefold()
        for value in self._ADVERSARIAL:
            assert value.casefold() in serialized, value
        assert "_withheld" not in result
        assert "_withheld_how_to_obtain" not in result
        placed = result["placed_devices"][0]
        assert placed["source_id"] == "aa:bb:cc:dd:ee:ff"
        assert placed["display_name"] == "Office access_token_marker"
        assert placed["product_id"] == "https://example.invalid/product"
        assert placed["mount"] == "192.0.2.91"

    def test_sensitive_values_in_allowed_snapshot_fields_are_withheld_under_redaction(self):
        """With UNIFI_REDACT_SECRETS on, adversarial values are withheld and reported."""
        payloads = self._adversarial_payloads()
        result = build_snapshot(
            project_result=payloads["project"],
            cameras_result=payloads["cameras"],
            sensors_result=payloads["sensors"],
            devices_result=payloads["devices"],
            redact_secrets=True,
        )

        serialized = repr(result).casefold()
        for sensitive_value in (
            "aa:bb:cc:dd:ee:ff",
            "access_token_marker",
            "https://example.invalid/product",
            "192.0.2.91",
            "browser-id-marker",
            "cookie-value-marker",
            "2001:db8::1",
            "serial-number-marker",
            "00:11:22:33:44:55",
            "203.0.113.11",
            "bearer-marker",
            "data:text/plain,opaque",
            "session-id-marker",
            "password-marker",
            "access-key-marker",
            "aabbccddeeff",
            "private-key-marker",
        ):
            assert sensitive_value not in serialized
        assert result["placement_links"] == []
        # every value left out is counted (never dropped silently), values never echoed
        withheld = result["_withheld"]
        assert withheld["placed_devices.source_id"] == {"hardware_address": 1}
        assert withheld["placed_devices.display_name"] == {"credential_marker": 1}
        assert withheld["placed_devices.product_id"] == {"url": 1}
        assert withheld["placed_devices.mount"] == {"network_address": 1}
        assert withheld["topology.display_name"]["credential_marker"] == 3
        assert "access_token_marker" not in json.dumps(withheld)
        assert "192.0.2.91" not in json.dumps(withheld)
        how = result["_withheld_how_to_obtain"]
        assert set(how) == set(withheld)
        assert "UNIFI_REDACT_SECRETS" in how["placed_devices.source_id"]
        assert "list_cameras, list_sensors or list_devices" in how["topology.display_name"]

    @pytest.mark.parametrize(
        "name",
        [
            "Hallway Passage",
            "Overpass Garage Cam",
            "Bypass Closet AP",
            "Serial Studio",
            "Mountain Pass Cam",
            "Keyhole Tokenizer Lab",
            "Passwordless Entry",
            "Front " + "Porch " * 60 + "Camera",  # > 160 chars: no length limit
        ],
    )
    @pytest.mark.parametrize("redact", [False, True])
    def test_ordinary_names_are_kept_and_linked(self, name, redact):
        payloads = _source_payloads()
        project = payloads["project"]["project"]
        project["shapes"][0]["title"] = name
        payloads["cameras"]["result"][0]["name"] = name
        result = build_snapshot(
            project_result=payloads["project"],
            cameras_result=payloads["cameras"],
            sensors_result=payloads["sensors"],
            devices_result=payloads["devices"],
            redact_secrets=redact,
        )
        assert result["placed_devices"][0]["display_name"] == name
        cams = [t for t in result["topology"] if t["kind"] == "protect_camera"]
        assert cams[0]["display_name"] == name
        assert any(
            link["placement_source_id"] == result["placed_devices"][0]["source_id"]
            for link in result["placement_links"]
        )
        assert not any(key.endswith("display_name") for key in result.get("_withheld", {}))
        if not redact:
            assert "_withheld" not in result

    @pytest.mark.parametrize(
        "name",
        [
            "lobby password",
            "api_key cam",
            "my_api_key",
            "Serial-Number shelf",
            "access-token door",
            "session_id 7",
        ],
    )
    def test_whole_word_credential_markers_are_withheld_and_reported(self, name):
        payloads = _source_payloads()
        payloads["cameras"]["result"][0]["name"] = name
        default = build_snapshot(
            project_result=payloads["project"],
            cameras_result=payloads["cameras"],
            sensors_result=payloads["sensors"],
            devices_result=payloads["devices"],
        )
        cams = [t for t in default["topology"] if t["kind"] == "protect_camera"]
        assert cams[0]["display_name"] == name  # verbatim unless redaction is on
        result = build_snapshot(
            project_result=payloads["project"],
            cameras_result=payloads["cameras"],
            sensors_result=payloads["sensors"],
            devices_result=payloads["devices"],
            redact_secrets=True,
        )
        assert name.casefold() not in repr(result).casefold()
        assert result["_withheld"]["topology.display_name"] == {"credential_marker": 1}

    def test_naive_timestamp_is_rejected(self):
        payloads = _source_payloads()
        with pytest.raises(ValueError, match="timezone-aware"):
            build_snapshot(
                project_result=payloads["project"],
                cameras_result=payloads["cameras"],
                sensors_result=payloads["sensors"],
                devices_result=payloads["devices"],
                generated_at=datetime(2026, 8, 20, 15, 0),
            )


class TestSnapshotReadOnlyBoundary:
    async def test_uses_only_get_backed_routes(self):
        payloads = _source_payloads()
        client = AsyncMock()
        # UniFiClient.list_key_labels is synchronous (one configured key here).
        client.list_key_labels = MagicMock(return_value=["default"])
        registry = AsyncMock()
        registry.resolve_key_for_host.return_value = None
        registry.resolve_host_id.return_value = "host-001"
        client.paginate_max_pages = None

        async def get(path, *, key=None, params=None):
            assert key is None
            if path.endswith("/project"):
                assert params == {"mode": "3D"}
                return payloads["project"]["project"]
            if path == "/v1/devices":
                assert params == {"hostIds[]": ["host-001"], "pageSize": 200}
                return payloads["devices"]
            assert params is None
            if path.endswith("/cameras"):
                return payloads["cameras"]["result"]
            if path.endswith("/sensors"):
                return payloads["sensors"]["result"]
            raise AssertionError(f"unexpected GET route {path}")

        client.get.side_effect = get
        result = await get_unifi_placement_snapshot(client, registry, "HQ-Unifi")

        assert client.get.await_count == 4
        assert [call.args[0] for call in client.get.await_args_list].count("/v1/devices") == 1
        client.paginate.assert_not_awaited()
        client.post.assert_not_called()
        client.put.assert_not_called()
        client.patch.assert_not_called()
        client.delete.assert_not_called()
        assert result["provenance"]["read_only"] is True


class TestSnapshotCapabilityPreflight:
    async def test_uses_only_existing_get_backed_collectors(self):
        payloads = _source_payloads()
        client = AsyncMock()
        # UniFiClient.list_key_labels is synchronous (one configured key here).
        client.list_key_labels = MagicMock(return_value=["default"])
        registry = AsyncMock()
        registry.resolve_key_for_host.return_value = None
        registry.resolve_host_id.return_value = "host-001"
        client.paginate_max_pages = None

        async def get(path, *, key=None, params=None):
            assert key is None
            if path.endswith("/project"):
                assert params == {"mode": "3D"}
                return payloads["project"]["project"]
            if path == "/v1/devices":
                assert params == {"hostIds[]": ["host-001"], "pageSize": 200}
                return payloads["devices"]
            assert params is None
            if path.endswith("/cameras"):
                return payloads["cameras"]["result"]
            if path.endswith("/sensors"):
                return payloads["sensors"]["result"]
            raise AssertionError(f"unexpected GET route {path}")

        client.get.side_effect = get
        report = await preflight_placement_snapshot_capabilities(client, registry, "HQ-Unifi")

        assert client.get.await_count == 4
        assert [call.args[0] for call in client.get.await_args_list].count("/v1/devices") == 1
        client.paginate.assert_not_awaited()
        client.post.assert_not_called()
        client.put.assert_not_called()
        client.patch.assert_not_called()
        client.delete.assert_not_called()
        assert {item["outcome"] for item in report["capabilities"]} <= CAPABILITY_OUTCOMES

    async def test_reports_only_closed_names_and_outcomes(self, monkeypatch):
        calls: list[str] = []

        async def project(*args, **kwargs):
            del args, kwargs
            calls.append("innerspace.project.3d")
            return {"shapes": []}

        async def cameras(*args, **kwargs):
            del args, kwargs
            calls.append("protect.cameras")
            return {"result": [], "_count": 0}

        async def sensors(*args, **kwargs):
            del args, kwargs
            calls.append("protect.sensors")
            return {"result": [], "_count": 0}

        async def devices(*args, **kwargs):
            del args, kwargs
            calls.append("site_manager.devices")
            return {"data": [], "_count": 0}

        monkeypatch.setattr(
            "unifi_fabric.tools.placement_snapshot.innerspace.fetch_project", project
        )
        monkeypatch.setattr("unifi_fabric.tools.placement_snapshot.protect.list_cameras", cameras)
        monkeypatch.setattr("unifi_fabric.tools.placement_snapshot.protect.list_sensors", sensors)
        monkeypatch.setattr(
            "unifi_fabric.tools.placement_snapshot.site_manager.list_devices", devices
        )

        report = await preflight_placement_snapshot_capabilities(object(), object(), "host-canary")

        assert sorted(calls) == sorted(APPROVED_READ_SOURCES)
        assert report == {
            "schema_version": PLACEMENT_SNAPSHOT_CAPABILITY_SCHEMA_VERSION,
            "read_only": True,
            "required_capabilities": list(APPROVED_READ_SOURCES),
            "capabilities": [{"name": name, "outcome": "ok"} for name in APPROVED_READ_SOURCES],
        }

    async def test_classifies_failures_and_carries_their_error_text(self, monkeypatch):
        canary = "api_key=super-secret host=host-123 https://api.example.test/hidden"

        async def denied(*args, **kwargs):
            del args, kwargs
            raise UniFiConnectionError(f"HTTP 403 from GET {canary}")

        async def unavailable(*args, **kwargs):
            del args, kwargs
            raise UniFiConnectionError(f"HTTP 502 from GET {canary}")

        async def unexpected(*args, **kwargs):
            del args, kwargs
            raise ValueError(canary)

        async def good(*args, **kwargs):
            del args, kwargs
            return {"devices": [{"a": "response payload must be discarded"}]}

        monkeypatch.setattr(
            "unifi_fabric.tools.placement_snapshot.innerspace.fetch_project", denied
        )
        monkeypatch.setattr(
            "unifi_fabric.tools.placement_snapshot.protect.list_cameras", unavailable
        )
        monkeypatch.setattr(
            "unifi_fabric.tools.placement_snapshot.protect.list_sensors", unexpected
        )
        monkeypatch.setattr("unifi_fabric.tools.placement_snapshot.site_manager.list_devices", good)

        report = await preflight_placement_snapshot_capabilities(object(), object(), "host-canary")
        serialized = json.dumps(report)

        assert [item["outcome"] for item in report["capabilities"]] == [
            "auth_denied",
            "unavailable",
            "error",
            "ok",
        ]
        # every failure carries its complete error text (verbatim, nothing masked) ...
        assert [item.get("error") for item in report["capabilities"]] == [
            f"UniFiConnectionError: HTTP 403 from GET {canary}",
            f"UniFiConnectionError: HTTP 502 from GET {canary}",
            f"ValueError: {canary}",
            None,
        ]
        # ... and a successful source's response payload is still not included
        assert "response payload must be discarded" not in serialized


class TestDeviceTypeAndIcon:
    """The device-type iconography contract (2026-09-07).

    ``device_type`` is a closed-enum coarse category the panel maps to a bundled
    MDI glyph (always-correct primary). ``icon`` is an optional UniFi-fingerprint
    descriptor for the curated estate models the panel caches locally; unknown
    models omit it and fall back to the MDI glyph.
    """

    @pytest.mark.parametrize(
        ("kind", "item", "expected"),
        [
            ("protect_camera", {"model": "UVC G4 Instant"}, "camera"),
            ("protect_camera", {"model": "UVC G5 Bullet"}, "camera"),
            ("protect_camera", {"model": "UVC G4 Doorbell", "name": "Front Doorbell"}, "doorbell"),
            ("protect_sensor", {"model": "USL-Entry-US", "name": "Front Door"}, "sensor"),
            ("protect_sensor", {"model": "UP-Sense", "name": "Motion Hall"}, "motion_sensor"),
            ("protect_sensor", {"model": "UP-EP-Presence"}, "presence_sensor"),
            ("network_device", {"model": "U7 Pro XGS", "name": "AP-1"}, "access_point"),
            ("network_device", {"model": "U6 Pro"}, "access_point"),
            ("network_device", {"model": "USW Pro 24 PoE"}, "switch"),
            ("network_device", {"model": "UDM Pro", "name": "HQ"}, "gateway"),
            ("network_device", {"model": "SuperLink Gateway"}, "gateway"),
            ("network_device", {"model": "U5G Max Outdoor", "name": "5G Modem"}, "gateway"),
            ("network_device", {"model": "Siren PoE", "name": "UP Siren PoE"}, "chime"),
            ("network_device", {"model": "Totally Unknown Widget"}, "unknown"),
            ("network_device", {}, "unknown"),
        ],
    )
    def test_derivation_matches_estate_and_heuristics(self, kind, item, expected):
        assert _derive_device_type(item, kind) == expected

    def test_every_derived_type_is_a_closed_enum_member(self):
        samples = [
            ("protect_camera", {"model": "x"}),
            ("protect_sensor", {"model": "x"}),
            ("network_device", {"model": "x"}),
            ("network_device", {}),
        ]
        for kind, item in samples:
            assert _derive_device_type(item, kind) in DEVICE_TYPES

    @pytest.mark.parametrize(
        ("model", "expected_id"),
        [
            ("UVC G4 Instant", 4987),
            ("UVC G4 Dome", 4395),
            ("USW Pro 24 PoE", 3344),
            ("UDM Pro", 3522),
            ("U6 Pro", 4981),
            ("  udm pro  ", 3522),  # normalized/casefolded
        ],
    )
    def test_curated_models_get_fingerprint_icon(self, model, expected_id):
        assert _fingerprint_icon({"model": model}) == {
            "kind": "unifi_fingerprint",
            "id": expected_id,
        }

    @pytest.mark.parametrize(
        "item",
        [
            {"model": "UVC G5 Bullet"},  # no fingerprint match -> MDI fallback
            {"model": "U7 Pro XGS"},
            {"model": 12345},  # non-string
            {},  # missing model
        ],
    )
    def test_uncurated_models_omit_icon(self, item):
        assert _fingerprint_icon(item) is None

    @pytest.mark.parametrize(
        ("item", "expected_id"),
        [
            # Live Protect camera/sensor shape: the model string is under ``type``,
            # there is no ``model`` key. Reading only ``model`` (the old bug) left
            # every Protect device icon-less even with a curated match.
            ({"type": "UVC G4 Instant", "modelKey": "camera"}, 4987),
            ({"type": "UVC G4 Dome", "modelKey": "camera"}, 4395),
            # marketName-only fallback also resolves.
            ({"marketName": "U6 Pro"}, 4981),
        ],
    )
    def test_fingerprint_resolves_from_non_model_fields(self, item, expected_id):
        assert _fingerprint_icon(item) == {"kind": "unifi_fingerprint", "id": expected_id}

    def test_live_protect_camera_shape_gets_icon_via_type(self):
        """Regression for the deploy defect: Protect cameras carry the model under
        ``type`` (verified against a representative snapshot export), so the fingerprint must
        resolve from ``type`` and the camera must gain an ``icon``, not just a
        ``device_type``."""
        payloads = _source_payloads()
        # Mirror the live raw Protect camera object: model under ``type``, no ``model``.
        payloads["cameras"]["result"] = [
            {
                "id": "protect-cam-live",
                "name": "Camera 1",
                "type": "UVC G4 Instant",
                "modelKey": "camera",
                "mac": "aa:bb:cc:00:00:aa",
            }
        ]
        payloads["sensors"]["result"] = []
        payloads["devices"]["data"] = []
        result = build_snapshot(
            project_result=payloads["project"],
            cameras_result=payloads["cameras"],
            sensors_result=payloads["sensors"],
            devices_result=payloads["devices"],
            generated_at=datetime(2026, 8, 20, 15, 0, tzinfo=UTC),
        )
        cam = next(n for n in result["topology"] if n["source_id"] == "protect-cam-live")
        assert cam["model"] == "UVC G4 Instant"  # projected from ``type``
        assert cam["device_type"] == "camera"
        assert cam["icon"] == {"kind": "unifi_fingerprint", "id": 4987}

    def test_build_snapshot_emits_device_type_and_icon(self):
        payloads = _source_payloads()
        payloads["cameras"]["result"] = [
            {"id": "cam-1", "name": "Office Cam", "model": "UVC G4 Instant"}
        ]
        payloads["sensors"]["result"] = [
            {"id": "sen-1", "name": "Front Door", "model": "USL-Entry-US"}
        ]
        payloads["devices"]["data"] = [
            {
                "hostId": "console-uuid-alpha",
                "hostName": "HQ-Unifi",
                "devices": [
                    {"name": "HQ", "model": "UDM Pro", "mac": "aa:bb:cc:00:00:01"},
                    {"name": "AP01", "model": "U7 Pro XGS", "mac": "aa:bb:cc:00:00:02"},
                ],
            }
        ]
        result = build_snapshot(
            project_result=payloads["project"],
            cameras_result=payloads["cameras"],
            sensors_result=payloads["sensors"],
            devices_result=payloads["devices"],
            generated_at=datetime(2026, 8, 20, 15, 0, tzinfo=UTC),
        )
        by_id = {n["source_id"]: n for n in result["topology"]}

        # Every node carries a closed-enum device_type.
        assert all(n["device_type"] in DEVICE_TYPES for n in result["topology"])
        assert by_id["cam-1"]["device_type"] == "camera"
        assert by_id["cam-1"]["icon"] == {"kind": "unifi_fingerprint", "id": 4987}
        assert by_id["sen-1"]["device_type"] == "sensor"
        assert "icon" not in by_id["sen-1"]  # USL-Entry-US -> MDI fallback

        udm = next(n for n in result["topology"] if n["display_name"] == "HQ")
        assert udm["device_type"] == "gateway"
        assert udm["icon"] == {"kind": "unifi_fingerprint", "id": 3522}

        ap = next(n for n in result["topology"] if n["display_name"] == "AP01")
        assert ap["device_type"] == "access_point"
        assert "icon" not in ap  # U7 Pro XGS not in curated table yet


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("HTTP 401 from GET /capabilities: expired", "auth_denied"),
        ("HTTP 403 from GET /capabilities: denied", "auth_denied"),
        ("http 403 from GET /capabilities: denied", "auth_denied"),
        ("HTTP 500 from GET /capabilities: unauthorized", "unavailable"),
        ("HTTP 502 from GET /capabilities: forbidden", "unavailable"),
        ("HTTP 400 from GET /capabilities: upstream mentioned HTTP 401", "unavailable"),
        ("HTTP 404 from GET /capabilities: upstream mentioned HTTP 403", "unavailable"),
        ("unauthorized capability response", "unavailable"),
        ("forbidden capability response", "unavailable"),
        ("HTTP 4010 from GET /capabilities", "unavailable"),
        ("HTTP 4030 from GET /capabilities", "unavailable"),
    ],
)
def test_capability_auth_outcome_uses_only_leading_http_status(message, expected):
    exc = UniFiConnectionError(message)

    assert _capability_outcome(exc) == {
        "outcome": expected,
        "error": f"UniFiConnectionError: {message}",
    }


@pytest.mark.parametrize("message", ["unauthorized body", "forbidden body", "body HTTP 403"])
def test_capability_body_text_preserves_non_connection_error_outcome(message):
    exc = ValueError(message)

    assert _capability_outcome(exc) == {
        "outcome": "error",
        "error": f"ValueError: {message}",
    }
