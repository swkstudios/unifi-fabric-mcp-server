"""Protect private-API device-type enum and route mapper."""

from __future__ import annotations

import pytest

from unifi_fabric.tools import _protect_device_types as pdt

EXPECTED = (
    "aiport",
    "aiprocessor",
    "bridge",
    "camera",
    "chime",
    "doorlock",
    "light",
    "linkstation",
    "sensor",
    "speaker",
    "viewer",
    "nvr",
)


def test_enum_is_the_twelve_types():
    assert pdt.DEVICE_TYPES == EXPECTED
    assert set(pdt.DEVICE_ROUTES) == set(pdt.ProtectDeviceType)


def test_collections_are_unique_plurals():
    collections = [r.collection for r in pdt.DEVICE_ROUTES.values()]
    assert len(set(collections)) == len(collections)
    for device_type, routes in pdt.DEVICE_ROUTES.items():
        expected = "nvr" if device_type is pdt.ProtectDeviceType.NVR else device_type.value + "s"
        assert routes.collection == expected
        assert all(m in {"GET", "POST", "PUT", "PATCH", "DELETE"} for m in routes.actions.values())


@pytest.mark.parametrize("value", ["camera", " Camera ", "CHIME", pdt.ProtectDeviceType.NVR])
def test_parse_accepts(value):
    assert pdt.parse_device_type(value).value == str(value).strip().lower()


@pytest.mark.parametrize("value", ["cameras", "", None, 3, "doorbell"])
def test_parse_rejects_listing_choices(value):
    with pytest.raises(ValueError) as exc:
        pdt.parse_device_type(value)
    assert "aiport" in str(exc.value) and "nvr" in str(exc.value)


def test_paths():
    assert pdt.device_path("camera", "abc") == "/cameras/abc"
    assert pdt.device_path("chime", "abc", "play-buzzer") == "/chimes/abc/play-buzzer"
    assert pdt.device_path("nvr") == "/nvr"
    assert pdt.device_path("nvr", None, "device-password") == "/nvr/device-password"
    assert pdt.device_path("sensor", "a/b") == "/sensors/a%2Fb"
    assert (
        pdt.protect_private_path("H:1", "light", "x", "locate")
        == "/v1/connector/consoles/H:1/proxy/protect/api/lights/x/locate"
    )


@pytest.mark.parametrize(
    ("args", "needle"),
    [
        (("camera",), "device id is required"),
        (("nvr", "x"), "singleton"),
        (("camera", ".."), "traversal"),
        (("camera", ""), "empty"),
        (("bridge", "x", "reboot"), "sourced actions"),
        (("doorbell", "x"), "expected one of"),
    ],
)
def test_path_errors(args, needle):
    with pytest.raises(ValueError) as exc:
        pdt.device_path(*args)
    assert needle in str(exc.value)


def test_lifecycle_actions_lookup():
    readopt = {t.value for t in pdt.device_types_with_action("readopt")}
    assert readopt == {
        "aiport",
        "aiprocessor",
        "camera",
        "chime",
        "doorlock",
        "light",
        "linkstation",
        "sensor",
        "speaker",
        "viewer",
    }
    assert all(pdt.action_method(t, "readopt") == "POST" for t in readopt)
    unadopt = {t.value for t in pdt.device_types_with_action("unadopt")}
    assert {
        "aiprocessor",
        "bridge",
        "chime",
        "doorlock",
        "light",
        "sensor",
        "speaker",
        "viewer",
    } <= unadopt
    assert pdt.action_method("sensor", "readings") == "GET"
