"""The fixtures sanitization gate flags real-looking numeric identifiers."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "scripts"
_SPEC = importlib.util.spec_from_file_location(
    "check_fixtures_sanitization", _SCRIPT / "check_fixtures_sanitization.py"
)
assert _SPEC is not None and _SPEC.loader is not None
gate = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gate)


def _with_luhn_check_digit(body: str) -> str:
    """``body`` plus the digit that makes the whole number Luhn-valid."""
    for d in "0123456789":
        if gate.luhn_valid(body + d):
            return body + d
    raise AssertionError("unreachable")


# Synthetic identifiers built at runtime, so no Luhn-valid literal ships in the tree.
_IMEI_EXAMPLE = _with_luhn_check_digit("35" + "0" * 12)
_ICCID_LUHN = _with_luhn_check_digit("89" + "0" * 16)
_EID_EXAMPLE = "89" + "0" * 30
# ICCIDs are 18-22 digits starting 89; flagged whether or not the Luhn digit is right.
_ICCID_18 = "89" + "1" * 16
_ICCID_22_NOT_LUHN = next(
    c for c in ("89" + "1" * 19 + d for d in "0123456789") if not gate.luhn_valid(c)
)
# IMEISV: 14 IMEI digits + a 2-digit software version, no check digit.
_IMEISV_EXAMPLE = "35" + "1" * 12 + "07"
# Well-known public ASNs with no tie to any recorded estate, built at runtime so no public
# ASN literal ships (the pre-publish identifier sweep reads tuple values too).
_PUBLIC_ASNS = (15000 + 169, 13000 + 335)
# The same as text, for planted records (concatenated so no keyed literal ships).
_ASN = str(_PUBLIC_ASNS[0])


@pytest.mark.parametrize(
    "line",
    [
        f'"imei": "{_IMEI_EXAMPLE}",',
        f'"value": {_IMEI_EXAMPLE},',
        f'"eid": "{_EID_EXAMPLE}",',
        f'"iccid": "{_ICCID_LUHN}",',
        f'"asn": {_PUBLIC_ASNS[0]},',
        f'"asn": {_PUBLIC_ASNS[1]},',
        f'"ispAsn": "{_PUBLIC_ASNS[0]}",',
        f'"isp_asn": {_PUBLIC_ASNS[1]},',
        f'"iccid": "{_ICCID_18}",',
        f'"value": {_ICCID_22_NOT_LUHN},',
        f'"imeisv": "{_IMEISV_EXAMPLE}",',
        f'"x": {_IMEISV_EXAMPLE},',
        # ASN keys in every spelling, and AS-prefixed values
        f'"ASN": {_PUBLIC_ASNS[0]},',
        f'"Asn": {_PUBLIC_ASNS[0]},',
        f'"peer_asn": {_PUBLIC_ASNS[1]},',
        f'"peerAsn": "{_PUBLIC_ASNS[1]}",',
        f'"remoteASN": {_PUBLIC_ASNS[0]},',
        f'"wan-asn": {_PUBLIC_ASNS[0]},',
        f'"asn": "AS{_PUBLIC_ASNS[0]}",',
        # "AS<digits>" string values under any key
        f'"org": "AS{_PUBLIC_ASNS[0]}",',
        f'"isp": "AS{_PUBLIC_ASNS[1]} Example Net",',
    ],
)
def test_real_looking_identifiers_are_flagged(line):
    assert gate.numeric_identifier_hits(line), line


@pytest.mark.parametrize(
    "line",
    [
        '"imei": "000000000000002",',  # zero-padded fake, Luhn-invalid
        '"rx_bytes-r": 1.234567890123456,',  # float fraction digits
        '"sfp_rxpower": -2.345678901234567,',
        '"start_connected_millis": 1700000000000,',  # 13-digit ms timestamp
        '"asn": 65534,',
        '"asn": 64496,',
        '"ispAsn": "64511",',
        '"asn": 65551,',
        '"asn": 4200000000,',
        '"asn": ' + str(0) + ",",
        '"iccid": "000000000000000002",',  # zero-padded fake (does not start 89)
        '"imeisv": "0000000000000003",',  # zero-padded 16-digit fake
        '"featuredGroupOrder": 9007199254740991,',  # 2**53 - 1 sentinel
        '"POST /v1/sites/{siteId}/lists": "1451818909878594",',  # spec-drift hash
        '"ASN": 64500,',
        '"peerAsn": "AS65000",',
        '"org": "AS64512 Example",',
        '"model": "UAS-XG",',
        '"basin": 15169,',  # ends in "asin", not an ASN key
        '"plan": "ASAP",',
    ],
)
def test_fakes_and_allowed_values_pass(line):
    assert gate.numeric_identifier_hits(line) == [], line


def test_luhn():
    assert len(_IMEI_EXAMPLE) == 15 and gate.luhn_valid(_IMEI_EXAMPLE)
    assert len(_ICCID_LUHN) == 19 and gate.luhn_valid(_ICCID_LUHN)
    assert not gate.luhn_valid("000000000000002")


@pytest.mark.parametrize("key", ["asn", "ASN", "Asn", "isp_asn", "ispAsn", "peerASN", "wan-asn"])
def test_asn_key_spellings(key):
    assert gate.is_asn_key(key)


@pytest.mark.parametrize("key", ["basin", "casino", "reason"])
def test_non_asn_keys(key):
    assert not gate.is_asn_key(key)


def test_committed_fixtures_are_clean():
    assert gate.main() == 0


# ------------------------------------------------------------ recorded captures
# Real-shaped identifiers built from public/generic values (a public vendor OUI with
# an arbitrary suffix, a generic city's coordinates), never values from any estate.
_REAL_MAC = "24:5a:4c:" + "12:34:56"
_REAL_HEX24 = "6a" + "1b2c3d4e5f60718293a4b5"
_REAL_CONSOLE = "A1B2C3D4E5F6" * 5 + ":1234567890"
# A cloud-access device_id is <uuid>:<number>; the number alone identifies the device, so
# a fake UUID with a real-shaped number is a leak (built at runtime, no estate value).
_FAKE_UUID = "00000000-0000-4000-a000-000000fa00f4"
_REAL_DEVICE_NUMBER = str(7 * 10**8 + 1234567)
_REAL_DEVICE_ID = f"{_FAKE_UUID}:{_REAL_DEVICE_NUMBER}"


@pytest.mark.parametrize(
    "line",
    [
        f'"mac": "{_REAL_MAC}",',
        f'"mac": "{_REAL_MAC.upper()}",',
        f'"mac": "{_REAL_MAC.replace(":", "-")}",',
        f'"mac": "{_REAL_MAC.replace(":", "")}",',
        f'"serial": "{_REAL_MAC.replace(":", "").upper()}",',
        f'"_id": "{_REAL_HEX24}",',
        f'"owner": "{_REAL_HEX24}",',
        '"id": "3f2a9c1e-7b4d-4e8a-9c2f-1a2b3c4d5e6f",',
        f'"hostId": "{_REAL_CONSOLE}",',
        f'"hostId": "{"0" * 54}FA0001:{_REAL_DEVICE_NUMBER}",',
        f'"hostId": "{_REAL_CONSOLE.lower()}",',
        f'"device_id": "{_REAL_DEVICE_ID}",',
        f'"device_id": "{_REAL_DEVICE_ID.upper()}",',
        f'"url": "/connect/{_REAL_DEVICE_ID}/status",',
        '"email": "someone@mail.example-isp.net",',
        '"owner": "Jane Doe <jane@example.org>",',
        '"latitude": 51.507351,',
        '"long": -0.127758,',
        '"lat": "48.8566",',
        '"ip": "10.99.7.183",',
        '"wan_ip": "192.168.251.40",',
        '"gw": "172.20.0.1",',
        '"cgnat": "100.72.3.4",',
        '"name": "Garage Camera",',
        '"hostname": "office-nas",',
        '"fullName": "Jane Doe",',
    ],
)
def test_recorded_real_identifiers_are_flagged(line):
    assert gate.recorded_identifier_hits(line), line


@pytest.mark.parametrize(
    "line",
    [
        '"mac": "02:00:5e:00:00:2a",',
        '"mac": "02:00:5E:00:00:2A",',
        '"mac": "00:00:00:00:00:00",',
        '"serial": "000000FA0002",',
        '"serialno": "000000fa0002",',
        '"mac": "02005e00002a",',
        '"_id": "0000000000000000000000aa",',
        '"owner": "000000000000000000fa01c5",',  # an ObjectId fake, not free text
        '"id": "00000000-0000-4000-8000-000000000004",',
        '"hostId": "000000000000000000000000000000000000000000000000000000FA0001:0000000001",',
        f'"device_id": "{_FAKE_UUID}:000000001",',
        f'"device_id": "{_FAKE_UUID}:7",',
        '"time": "12:30:45",',  # a clock time is not a UUID:number id
        '"latitude": 12.345678,',
        '"longitude": -98.765432,',
        '"lat": 0,',
        '"ip": "10.0.3.7",',
        '"wan_ip": "203.0.113.9",',
        '"mask": "255.255.255.0",',
        '"name": "name-0039",',
        '"hostname": "hostname-0013",',
        '"email": "email-0001",',
        '"name": "",',
        '"name": "Default",',
        '"name": "Internal",',
        '"name": "Dmz",',
        '"name": "TCP_UDP",',  # the firewall protocol preset enum, not free text
        '"rx_bytes": 123456789012,',  # all-digit 12-character value is a number
        '"version": "UVC.SAV530q.v5.5.31.67.66558b0.261001.1419",',
    ],
)
def test_recorded_fakes_pass(line):
    assert gate.recorded_identifier_hits(line) == [], line


def test_main_flags_a_planted_recorded_capture(tmp_path, monkeypatch, capsys):
    rec = tmp_path / "tests" / "fixtures" / "recorded" / "site_manager"
    rec.mkdir(parents=True)
    (rec / "v1_devices.json").write_text(
        f'{{\n  "mac": "{_REAL_MAC}",\n  "name": "Garage Camera",\n  "ip": "10.99.7.183"\n}}\n'
    )
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.main() == 1
    out = capsys.readouterr().out
    assert "MAC address outside" in out and "free-text" in out and "private IPv4" in out
    assert _REAL_MAC not in out and "Garage Camera" not in out  # values never echoed


def test_main_flags_a_planted_uuid_number_device_id(tmp_path, monkeypatch, capsys):
    rec = tmp_path / "tests" / "fixtures" / "recorded" / "network_classic"
    rec.mkdir(parents=True)
    (rec / "network_api_s_SITE_rest_setting.json").write_text(
        json.dumps({"data": [{"key": "super_cloudaccess", "device_id": _REAL_DEVICE_ID}]}, indent=1)
    )
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.main() == 1
    out = capsys.readouterr().out
    assert "UUID:number device id" in out
    assert _REAL_DEVICE_NUMBER not in out  # values never echoed


def test_recorded_checks_apply_only_to_recorded_captures(tmp_path, monkeypatch):
    other = tmp_path / "tests" / "fixtures" / "spec_drift"
    other.mkdir(parents=True)
    (other / "x.json").write_text('{"name": "Garage Camera"}\n')
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.main() == 0


# ------------------------------------------------- vendor MACs on every target
# A vendor-OUI MAC built at runtime (a public OUI plus an arbitrary suffix), so no
# globally unique MAC literal ships in the tree for the leak scan to trip on.
_VENDOR_MAC = ":".join(["24", "5a", "4c", "12", "34", "56"])


@pytest.mark.parametrize(
    "line",
    [
        f'"mac": "{_VENDOR_MAC}"',
        f'"mac": "{_VENDOR_MAC.upper()}"',
        f'"mac": "{_VENDOR_MAC.replace(":", "-")}"',
        # dotted (xxxx.xxxx.xxxx) form
        '"mac": "' + ".".join(["245a", "4c12", "3456"]) + '"',
        f"device_id={_VENDOR_MAC} trailing text",
    ],
)
def test_vendor_macs_are_flagged(line):
    assert gate.mac_hits(line), line


@pytest.mark.parametrize(
    "line",
    [
        '"mac": "02:00:5e:00:00:a1"',  # locally administered (the fixtures' fakes)
        '"mac": "02-00-5E-00-00-A1"',
        '"mac": "aa:bb:cc:dd:ee:ff"',  # locally administered documentation style
        '"mac": "de:ad:be:ef:00:01"',  # locally administered
        '"mac": "00:00:5e:00:53:01"',  # RFC 7042 documentation block (IANA OUI)
        '"mac": "00:00:00:00:00:00"',
        '"mac": "ff:ff:ff:ff:ff:ff"',
        '"mac": "11:22:33:44:55:66"',  # allowlisted documentation values
        '"mac": "00:11:22:33:44:55"',
        '"mac": "00:1a:2b:3c:4d:5e"',
        '"version": "1.2.3.4"',  # not a MAC
        '"ipv6": "fe80::1"',
        '"time": "12:34:56"',
        # an 8-group run that is a valid IPv6 literal (not all 2-hex) is not a MAC
        '"x": "' + ":".join(["2001", "db8", "24", "5a", "4c", "12", "34", "56"]) + '"',
    ],
)
def test_documentation_macs_pass(line):
    assert gate.mac_hits(line) == [], line


def test_mac_is_documentation():
    assert gate.mac_is_documentation("02005e0000a1")
    assert gate.mac_is_documentation("AABBCCDDEEFF")
    assert not gate.mac_is_documentation(_VENDOR_MAC.replace(":", ""))


def test_main_flags_a_vendor_mac_outside_recorded_captures(tmp_path, monkeypatch, capsys):
    other = tmp_path / "tests" / "fixtures" / "spec_drift"
    other.mkdir(parents=True)
    (other / "x.json").write_text(f'{{"mac": "{_VENDOR_MAC}"}}\n')
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.main() == 1
    out = capsys.readouterr().out
    assert "vendor MAC address" in out
    assert _VENDOR_MAC not in out  # values never echoed


# ------------------------------------- identifiers next to ".", "-" or ":"
@pytest.mark.parametrize(
    "line",
    [
        f"the modem IMEI is {_IMEI_EXAMPLE}.",
        f"imei.{_IMEI_EXAMPLE}",
        f"the eSIM EID is {_EID_EXAMPLE}.",
        f"eid.{_EID_EXAMPLE}",
        f"the SIM ICCID is {_ICCID_18}.",
        f"sim.{_ICCID_18}.",
        f"iccid:{_ICCID_18}-",
    ],
)
def test_numeric_identifier_next_to_punctuation_is_flagged(line):
    assert gate.numeric_identifier_hits(line), line


@pytest.mark.parametrize(
    "line",
    [
        f"x = 1.{_IMEI_EXAMPLE}",
        f"x = {_IMEI_EXAMPLE}.5",
        f"x = -2.{_ICCID_18}",
    ],
)
def test_decimal_fraction_digits_pass(line):
    assert gate.numeric_identifier_hits(line) == [], line


@pytest.mark.parametrize(
    "line",
    [
        f"mac:{_VENDOR_MAC}",
        f"uplink-{_VENDOR_MAC}",
        f"host.{_VENDOR_MAC}",
        f"the uplink is {_VENDOR_MAC}.",
        f"seen {_VENDOR_MAC}: online",
        f"{_VENDOR_MAC}-eth0",
        f"uplink-{_VENDOR_MAC.replace(':', '-')}.",
        f"mac:{_VENDOR_MAC.replace(':', '-')}:",
        "id." + ".".join(["245a", "4c12", "3456"]) + ".",
        "mac:" + ".".join(["245a", "4c12", "3456"]) + "-",
    ],
)
def test_vendor_mac_next_to_punctuation_is_flagged(line):
    assert gate.mac_hits(line), line


@pytest.mark.parametrize(
    "line",
    [
        f'"mac": "mac:{_REAL_MAC}"',
        f'"x": "uplink-{_REAL_MAC}"',
        f'"x": "{_REAL_MAC}."',
        f'"x": "{_REAL_MAC.replace(":", "-")}:"',
    ],
)
def test_recorded_mac_next_to_punctuation_is_flagged(line):
    assert any("MAC address outside" in h for h in gate.recorded_identifier_hits(line)), line


@pytest.mark.parametrize(
    "line",
    [
        '"x": "2001:db8:' + _VENDOR_MAC + '"',
        '"x": "' + "-".join(["24", "5a", "4c", "12", "34", "56", "78"]) + '"',
        '"x": "' + ".".join(["245a", "4c12", "3456", "7890"]) + '"',
    ],
)
def test_mac_shaped_run_inside_a_longer_hex_group_passes(line):
    assert gate.mac_hits(line) == [], line


# A vendor MAC with an extra 1-4 hex group before or after escaped the bounded pattern
# (taken for IPv6 / EUI-64). Inside a longer colon run it is flagged unless the whole
# run is a valid IPv6 literal.
@pytest.mark.parametrize(
    "line",
    [
        f'"x": "{_VENDOR_MAC}:1"',
        f'"x": "1:{_VENDOR_MAC}"',
        f'"x": "abcd:{_VENDOR_MAC}"',
        f'"x": "{_VENDOR_MAC.upper()}:beef"',
        '"x": "' + ":".join(["24", "5a", "4c", "12", "34", "56", "78"]) + '"',
    ],
)
def test_vendor_mac_inside_a_longer_colon_run_is_flagged(line):
    assert any("longer colon run" in h for h in gate.mac_hits(line)), line


@pytest.mark.parametrize(
    "line",
    [
        f'"x": "2001:db8:{_VENDOR_MAC}"',
        f'"x": "fe80:{_VENDOR_MAC}:1"',
        '"x": "2001:db8::1"',
        '"x": "02:00:5e:00:00:01:1"',
        '"x": "1:00:00:5e:00:53:01"',
    ],
)
def test_ipv6_literal_or_allowed_window_in_a_colon_run_passes(line):
    assert gate.mac_hits(line) == [], line


@pytest.mark.parametrize(
    "line",
    [f'"x": "{_REAL_MAC}:1"', f'"x": "1:{_REAL_MAC}"'],
)
def test_recorded_mac_inside_a_longer_colon_run_is_flagged(line):
    hits = gate.recorded_identifier_hits(line)
    assert any("longer colon run" in h for h in hits), line


def test_recorded_fake_mac_inside_a_colon_run_passes():
    assert gate.recorded_identifier_hits('"x": "02:00:5e:00:00:01:1"') == []
    assert gate.recorded_identifier_hits('"x": "2001:db8:' + _REAL_MAC + '"') == []


# Eight 2-hex groups parse as IPv6, but with a vendor first octet the run is an
# EUI-64 MAC and is flagged. Real IPv6 literals (and a locally administered or
# documentation EUI-64) still pass. Values are built at runtime.
_EUI64 = ":".join(["ac", "8b", "a9", "12", "34", "56", "78", "9a"])


@pytest.mark.parametrize(
    "line",
    [
        f'"x": "{_EUI64}"',
        f'"x": "{_EUI64.upper()}"',
        '"x": "' + ":".join(["00", "24", "5a", "4c", "12", "34", "56", "78"]) + '"',
    ],
)
def test_vendor_eui64_is_flagged(line):
    assert any("longer colon run" in h for h in gate.mac_hits(line)), line


@pytest.mark.parametrize(
    "line",
    [
        '"x": "2001:db8::1"',
        '"x": "2001:db8:0:0:0:0:0:1"',
        '"x": "fe80::1ff:fe23:4567:890a"',
        '"x": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"',
        '"x": "' + ":".join(["02", "8b", "a9", "12", "34", "56", "78", "9a"]) + '"',
        '"x": "' + ":".join(["00", "00", "5e", "00", "53", "01", "02", "03"]) + '"',
    ],
)
def test_ipv6_and_non_vendor_eui64_pass(line):
    assert gate.mac_hits(line) == [], line


def test_recorded_eui64_outside_the_fakes_is_flagged():
    hits = gate.recorded_identifier_hits(f'"x": "{_EUI64}"')
    assert any("longer colon run" in h for h in hits)


@pytest.mark.parametrize(
    "key",
    [
        "mac",
        "MAC",
        "deviceMac",
        "device_mac",
        "device-mac",
        "serial",
        "serialNumber",
        "serial_number",
        "serial-number",
    ],
)
@pytest.mark.parametrize("number", [False, True])
@pytest.mark.parametrize("recorded", [False, True])
def test_json_digit_only_hardware_identifiers(key, number, recorded, tmp_path, monkeypatch):
    import json

    value = "708041" + "000001"
    data = {"nested": [{key: int(value) if number else value}]}
    path = tmp_path / ("tests/fixtures/recorded/probe.json" if recorded else "config/probe.json")
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(data, indent=2))
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.main() == 1


@pytest.mark.parametrize("key", ["asn", "ASN", "ispAsn", "isp_asn", "peerASN", "peer-asn"])
@pytest.mark.parametrize("value", [15169, "13335", "AS" + str(15169)])
def test_multiline_json_asn(key, value, tmp_path, monkeypatch):
    import json

    path = tmp_path / "config/probe.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"nested": [{key: value}]}).replace(": ", ":\n"))
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.main() == 1


@pytest.mark.parametrize("recorded", [False, True])
def test_structural_json_negative_controls(recorded, tmp_path, monkeypatch):
    import json

    data = {
        "timestamp": "708041000001",
        "count": 708041000001,
        "basin": 15169,
        "mac": "02005e000001",
        "serialNumber": "000000000002",
        "nested": [{"peerASN": "AS64512", "asn": 65534}],
    }
    path = tmp_path / ("tests/fixtures/recorded/probe.json" if recorded else "config/probe.json")
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(data, indent=2))
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.main() == 0


@pytest.mark.parametrize(
    "key",
    [
        "serialno",
        "serial_no",
        "serialNo",
        "sn",
        "member_device_macs",
        "macAddresses",
        "serialNumbers",
    ],
)
def test_json_hardware_field_siblings(key, tmp_path, monkeypatch):
    import json

    value = "708041" + "000001"
    data = {
        key: [value] if key in {"member_device_macs", "macAddresses", "serialNumbers"} else value
    }
    path = tmp_path / "config/probe.json"
    path.parent.mkdir()
    path.write_text(json.dumps(data, indent=2))
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.main() == 1


@pytest.mark.parametrize("key", ["ispasn", "ISP_ASN", "peerAsN", "remoteasn"])
def test_asn_case_siblings(key):
    assert gate.is_asn_key(key)


def test_every_committed_hardware_key_checks_digit_only_values(tmp_path, monkeypatch):
    import json
    import re

    keys = set()

    def visit(value):
        if isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, dict):
            for key, item in value.items():
                if re.search(
                    r"mac|bssid|hwaddr|chassis|serial|^sn\Z",
                    key,
                    re.I,
                ):
                    keys.add(key)
                visit(item)

    for path in gate.iter_target_files():
        try:
            visit(json.loads(path.read_text()))
        except (ValueError, UnicodeError):
            pass
    assert keys, "fixture catalog must contain hardware identifiers"
    path = tmp_path / "config/probe.json"
    path.parent.mkdir()
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    for key in sorted(keys):
        for value in ("708041" + "000001", ["708041" + "000001"]):
            path.write_text(json.dumps({key: value}, indent=2))
            assert gate.main() == 1, key
        path.write_text(json.dumps({key: "02005e000001"}, indent=2))
        # A field can have both hardware and credential meaning. The MAC fake
        # remains valid for identifier checks, but is not a credential placeholder.
        if gate._credential_key(key):
            assert gate.json_identifier_hits({key: "02005e000001"}) == [], key
            assert gate.main() == 1, key
            path.write_text(json.dumps({key: False}, indent=2))
        assert gate.main() == 0, key


@pytest.mark.parametrize(
    "key", ["bssid", "mac_filter_list", "chassis_id", "hwaddr", "serial_number_text", "sn"]
)
@pytest.mark.parametrize("wrapped", [False, True])
def test_hardware_substring_and_list_controls(key, wrapped):
    value = "708041" + "000001"
    assert gate.json_identifier_hits({key: [value] if wrapped else value})
    assert not gate.json_identifier_hits({key: ["02005e000001"] if wrapped else "02005e000001"})


@pytest.mark.parametrize("key", ["asn", "asns", "asn_number", "isp_asn_info", "asns_total"])
@pytest.mark.parametrize(
    "wrap", [lambda v: v, lambda v: {"value": v}, lambda v: [v], lambda v: {"values": [[v]]}]
)
def test_nested_asn_container_controls(key, wrap):
    assert gate.json_identifier_hits({key: wrap(8075)})
    assert not gate.json_identifier_hits({key: wrap(64512)})
    assert not gate.json_identifier_hits({key: wrap("AS65534")})
    assert not gate.json_identifier_hits({key: wrap(True)})
    assert not gate.json_identifier_hits({"counter": wrap(8075)})


@pytest.mark.parametrize("extension", ["jsonl", "ndjson", "txt", "md"])
@pytest.mark.parametrize(
    "text",
    [
        '{"bssid": "708041000001"}\n{"counter": 42}\n',
        '{"mac_filter_list": ["708041000001"]}\n{"counter": 42}\n',
        '{"asn": {"value": ' + _ASN + '}}\n{"counter": 42}\n',
        'JSON capture:\n```json\n{\n  "asn_number":\n  ' + _ASN + "\n}\n```\n",
        '{\n  "asn":\n  ' + _ASN + '\n}\n{\n  "counter": 42\n}\n',
        # Inline records in prose, not at a line start.
        'see {"asn": {"v": ' + _ASN + "}} here\n",
        'peers: [{"peerASN": ' + _ASN + "}] (captured)\n",
    ],
)
def test_json_records_in_text_fixtures(extension, text, tmp_path, monkeypatch):
    path = tmp_path / f"config/probe.{extension}"
    path.parent.mkdir()
    path.write_text(text)
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.main() == 1


@pytest.mark.parametrize("extension", ["jsonl", "ndjson", "txt", "md"])
def test_json_records_negative_controls(extension, tmp_path, monkeypatch):
    path = tmp_path / f"config/probe.{extension}"
    path.parent.mkdir()
    path.write_text(
        '{"bssid": "02005e000001", "mac_filter_list": ["000000000001"]}\n'
        'JSON capture:\n{\n"asns": {"value": [64512, "AS65534"]},\n'
        '"counter": 8075, "timestamp": 708041000001, "sn": true\n}\n'
    )
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.main() == 0


# ------------------------------------------------- credentials in embedded captures
# A capture embedded in prose ("Example: {...}"), a pretty-printed record after a label,
# or a fenced block in a Markdown fixture is checked like a standalone document.
_CRED = "-".join(["synthetic", "sensitive", "value"])


@pytest.mark.parametrize(
    "text",
    [
        'Example: {"password": "' + _CRED + '"}\n',
        'Example: {"auth": {"apiKey": "' + _CRED + '"}} (captured)\n',
        'Response:\n{\n  "data": [{"x_passphrase":\n    "' + _CRED + '"}]\n}\n',
        '# Capture\n\n```json\n{\n  "token": "' + _CRED + '"\n}\n```\n',
        '# Capture\n\n```toml\n[auth]\nclient_secret = "' + _CRED + '"\n```\n',
        "# Capture\n\n```yaml\nauth:\n  password: " + _CRED + "\n```\n",
        'Example: [{"secret": "' + _CRED + '"}]\n',
    ],
)
def test_credentials_in_embedded_json_and_markdown_captures_are_flagged(
    text, tmp_path, monkeypatch, capsys
):
    assert gate.credential_hits(text), text
    path = tmp_path / "tests/fixtures/capture.md"
    path.parent.mkdir(parents=True)
    path.write_text(text)
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.main() == 1
    out = capsys.readouterr().out
    assert "structured credential" in out and _CRED not in out


@pytest.mark.parametrize(
    "text",
    [
        'Example: {"password": "<your-password>"}\n',
        'Example: {"token": "${API_TOKEN}"} and {"tokenCount": 3}\n',
        '```json\n{"apiKey": "***REDACTED***"}\n```\n',
        "Example: {not json} [1, 2]\n",
    ],
)
def test_placeholders_in_embedded_captures_pass(text):
    assert gate.credential_hits(text) == []


@pytest.mark.parametrize(
    "expression",
    [
        "$(echo -fixture)",
        "$(echo -n -fixture)",
        "$(echo -ne -fixture)",
        "$(echo -- -fixture)",
        "$(echo ${PASSWORD} -n)",
        "$(echo ${PASSWORD} --)",
        "$(printf %s -fixture)",
        "$(printf -- %s -fixture)",
        "$(printf %s %s)",
        "$(printf -- %s --)",
        "$(printf -fixture)",
        "$(/usr/bin/echo -fixture)",
        "$(/usr/bin/printf -- %s -fixture)",
        # Separator-attached command words still emit literal data.
        "$(true;echo -fixture)",
        "$(true||echo -fixture)",
        "$(true|echo x)",
        "$(true&&echo -fixture)",
        "$(true&echo -fixture)",
        "$(true;/usr/bin/printf %s -fixture)",
        "$(true;echo ${PASSWORD};echo x)",
        # Quoted operator characters are data, not separators.
        "$(echo ';')",
        "$(echo '|')",
        # Backticks open an evaluated nested substitution.
        "$(`echo -fixture`)",
    ],
)
def test_shell_substitution_literal_data_is_flagged(expression):
    assert gate.credential_hits("password: " + expression + "\n")


@pytest.mark.parametrize(
    "expression",
    [
        "$(echo ${PASSWORD})",
        "$(echo -n ${PASSWORD})",
        "$(echo -neE ${PASSWORD})",
        "$(echo -n -e ${PASSWORD})",
        "$(echo -n <your-password>)",
        "$(printf %s ${PASSWORD})",
        "$(printf -- %s ${PASSWORD})",
        "$(printf '%s\\n' ${PASSWORD})",
        "$(printf -- %b <your-password>)",
        "$(/usr/bin/echo -n ${PASSWORD})",
        "$(/usr/bin/printf -- %s ${PASSWORD})",
        "$(true;echo ${PASSWORD})",
        "$(true&&printf %s ${PASSWORD})",
    ],
)
def test_shell_substitution_options_and_placeholders_pass(expression):
    assert gate.credential_hits("password: " + expression + "\n") == []


# --------------------------------------- device-identity classes beyond MAC fields
# A capture whose MAC fields are faked can still carry the device identity in an
# EUI-64 IPv6 interface id, an SSH host-key fingerprint, a UniFi x_* secret field or
# a serial number. Every value below is built at runtime from a public vendor OUI or
# generic bytes, so no device-shaped literal ships in the tree.
def _eui64_ll(mac_hex12, prefix="fe80::"):
    """The modified EUI-64 IPv6 address for a MAC (universal/local bit flipped)."""
    b = bytes.fromhex(mac_hex12)
    iid = bytes([b[0] ^ 0x02]) + b[1:3] + b"\xff\xfe" + b[3:]
    groups = [iid[i : i + 2].hex() for i in range(0, 8, 2)]
    return prefix + ":".join(g.lstrip("0") or "0" for g in groups)


_VENDOR_HEX = "245a4c" + "123456"
_VENDOR_EUI64_LL = _eui64_ll(_VENDOR_HEX)
_VENDOR_EUI64_GLOBAL = _eui64_ll(_VENDOR_HEX, prefix="2001:db8:1:2:")
_FAKE_EUI64_LL = _eui64_ll("02005e" + "000003")
_DOC_EUI64_LL = _eui64_ll("00005e" + "005301")
_SHA256_FP = "SHA256:" + ("Ab3+" * 11)[:43]
_MD5_FP = ":".join(["9f", "3c"] * 8)
_SSH_PUBKEY = "ssh-" + "ed25519 " + "AAAA" + "C3NzaC1lZDI1NTE5AAAAI" + "Qx" * 12


@pytest.mark.parametrize(
    "line",
    [
        f'"ipv6": ["{_VENDOR_EUI64_LL}"],',
        f'"ipv6": "{_VENDOR_EUI64_LL.upper()}",',
        f'"addr": "{_VENDOR_EUI64_LL}%br0",',
        f'"addr": "{_VENDOR_EUI64_LL}/64",',
        f"ipv6:{_VENDOR_EUI64_LL}",
        f'"global": "{_VENDOR_EUI64_GLOBAL}",',
    ],
)
@pytest.mark.parametrize("recorded", [False, True])
def test_vendor_eui64_ipv6_in_any_form_is_flagged(line, recorded):
    hits = gate.ipv6_hits(line, recorded)
    assert any("EUI-64" in h for h in hits), (line, hits)
    assert all(_VENDOR_EUI64_LL not in h for h in hits)


@pytest.mark.parametrize("line", [f'"ipv6": "{_FAKE_EUI64_LL}"', '"ipv6": "fe80::3"'])
@pytest.mark.parametrize("recorded", [False, True])
def test_fake_eui64_and_recorder_link_locals_pass(line, recorded):
    assert gate.ipv6_hits(line, recorded) == [], line


def test_documentation_eui64_passes_outside_recorded_captures():
    assert gate.ipv6_hits(f'"ipv6": "{_DOC_EUI64_LL}"') == []
    assert gate.ipv6_hits(f'"ipv6": "{_DOC_EUI64_LL}"', recorded=True)


@pytest.mark.parametrize(
    "line",
    [
        '"wan_ipv6": "2600:1f18:' + "abcd:1234::7" + '"',
        '"prefix": "2a02:' + "6b8::" + '/48"',
    ],
)
def test_public_ipv6_outside_the_documentation_prefix_is_flagged(line):
    assert any("public IPv6" in h for h in gate.ipv6_hits(line)), line


@pytest.mark.parametrize(
    "line",
    [
        '"x": "2001:db8::1"',
        '"x": "::"',
        '"x": "::1"',
        '"x": "ff02::1"',
        '"ipv6Address": "cafe::babe"',  # outside 2000::/3: not a routable address
        '"time": "12:30:45"',
        '"mac": "02:00:5e:00:00:01"',
    ],
)
def test_documentation_and_non_routable_ipv6_pass(line):
    assert gate.ipv6_hits(line) == [], line
    assert gate.ipv6_hits(line, recorded=True) == [], line


@pytest.mark.parametrize(
    "line",
    ['"ll": "fe80::' + "1c2d:3e4f:5a6b:7c8d" + '"', '"ula": "fd12:' + "3456:789a::1" + '"'],
)
def test_recorded_non_fake_link_local_and_ula_are_flagged(line):
    assert gate.ipv6_hits(line, recorded=True), line
    assert gate.ipv6_hits(line) == [], line  # outside captures only EUI-64/public count


@pytest.mark.parametrize(
    "line, label",
    [
        (f'"x_ssh_hostkey_fingerprint": "{_SHA256_FP}",', "SHA256"),
        (f"fingerprint {_SHA256_FP} (ED25519)", "SHA256"),
        (f'"fp": "{_MD5_FP}",', "MD5"),
        (f'"fp": "MD5:{_MD5_FP}",', "MD5"),
        (f'"key": "{_SSH_PUBKEY} comment",', "public key"),
    ],
)
def test_ssh_host_key_material_is_flagged(line, label):
    labels = [name for name, pattern in gate.DENYLIST if pattern.search(line)]
    assert any(label in name for name in labels), (line, labels)


@pytest.mark.parametrize(
    "line",
    [
        '"x_ssh_hostkey_fingerprint": "SHA256:xxxxxxxx",',
        '"x_ssh_hostkey_fingerprint": "SHA256:' + "0" * 42 + '1",',
        '"fp": "' + ":".join(["00"] * 15 + ["01"]) + '",',
        '"fingerprint": "xxxxxxxx",',
        '"type": "ssh-ed25519",',
        '"mac": "02:00:5e:00:00:01",',
    ],
)
def test_ssh_placeholders_pass(line):
    assert [name for name, pattern in gate.DENYLIST if pattern.search(line)] == [], line


_X_REAL = "".join(["7d", "1e", "a9"] * 6)


@pytest.mark.parametrize(
    "record",
    [
        {"x_authkey": _X_REAL},
        {"x_vwirekey": _X_REAL},
        {"x_iapp_key": _X_REAL},
        {"x_passphrase": "correct horse battery"},
        {"x_ssh_hostkey_fingerprint": "fp" + _X_REAL},
        {"x_ssh_keys": [{"key": _X_REAL, "type": "ssh-ed25519"}]},
        {"radio_table": [{"name": "ra0", "x_mgmt_key": _X_REAL}]},
    ],
)
def test_x_fields_with_non_placeholder_values_are_flagged(record):
    assert gate.x_field_hits(record), record


@pytest.mark.parametrize(
    "record",
    [
        {"x_authkey": "xxxxxxxx", "x_vwirekey": "0" * 31 + "1", "x_iapp_key": ""},
        {"x_passphrase": "x-passphrase-0001", "x_has_ssh_hostkey": True},
        {"x_ssh_hostkey_fingerprint": "SHA256:" + "0" * 42 + "3"},
        {"x_ssh_hostkey_fingerprint": "SHA256:xxxxxxxx"},
        {"x_ssh_keys": [{"key": "key-0001", "date": "2026-07-31", "type": "ssh-ed25519"}]},
        {"x_secret": "<your-secret>", "x_api_token": "${API_TOKEN}", "x_hash": "0" * 34 + "fa0001"},
        {"tx_rate": "anything goes", "rx_bytes": 7},  # tx_/rx_ are not x_ fields
    ],
)
def test_x_field_placeholders_pass(record):
    assert gate.x_field_hits(record) == [], record


def test_x_named_json_schema_properties_define_fields_not_secrets():
    schema = {
        "properties": {
            "x_uplink_password": {
                "type": "string",
                "default": None,
                "description": "Uplink password supplied by the caller.",
            }
        }
    }
    assert gate.x_field_hits(schema) == []


@pytest.mark.parametrize(
    "schema",
    [
        {"properties": {"x_password": _X_REAL}},
        {"properties": {"x_password": {"default": _X_REAL}}},
        {"properties": {"x_password": {"enum": [_X_REAL]}}},
        {"properties": {"outer": {"properties": {"x_inner": _X_REAL}}}},
    ],
)
def test_x_named_schema_properties_still_flag_literal_secret_values(schema):
    assert gate.x_field_hits(schema)


def test_x_fields_in_text_files_are_flagged():
    assert gate.x_field_line_hits(f"x_authkey = '{_X_REAL}'")
    assert gate.x_field_line_hits(f'  x_passphrase: "{_X_REAL}"')
    assert gate.x_field_line_hits("x_authkey = 'xxxxxxxx'") == []
    assert gate.x_field_line_hits(f"tx_rate: '{_X_REAL}'") == []


@pytest.mark.parametrize(
    "record",
    [
        {"serial": "F" + "CE" + "U12345678"},
        {"serialNumber": "1234" + "56789012"},
        {"sfp_serial": "AC" + "21" + "09A12345"},
        {"sn": "S" + "N9" + "87654321"},
        {"board_serial": ["SN" + "1234567"]},
    ],
)
def test_serial_fields_that_are_not_placeholders_are_flagged(record):
    assert gate.serial_hits(record), record


@pytest.mark.parametrize(
    "record",
    [
        {"serial": "02005e000003"},
        {"serialno": "000000000017"},
        {"sfp_serial": "sfp-serial-0001"},
        {"serialNumber": ""},
        {"serial_enabled": True, "sn": "<serial>"},
    ],
)
def test_serial_placeholders_pass(record):
    assert gate.serial_hits(record) == [], record


def test_estate_names_are_flagged_in_fixture_data(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(gate, "FORBIDDEN_NAMES", [re.compile(r"\bseeded-estate-name\b", re.I)])
    fx = tmp_path / "tests" / "fixtures"
    (fx / "battery_seed").mkdir(parents=True)
    (fx / "capture.json").write_text('{"hostname": "seeded-estate-name"}\n')
    (fx / "battery_seed" / "seed.txt").write_text("seeded-estate-name\n")
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "service.example.json").write_text('{"upstream": "seeded-estate-name"}\n')
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.main() == 1
    out = capsys.readouterr().out
    assert "tests/fixtures/capture.json:1: estate" in out
    assert "battery_seed" not in out and "config/" not in out
    assert "seeded-estate-name" not in out


def test_forbidden_names_are_loaded_from_the_release_battery_list():
    if gate.FORBIDDEN_NAMES_FILE.is_file():  # private tree only (stripped from public)
        assert gate.FORBIDDEN_NAMES
        assert all(hasattr(p, "search") for p in gate.FORBIDDEN_NAMES)
    else:
        assert gate.FORBIDDEN_NAMES == []


def test_docs_evidence_is_in_scope(tmp_path, monkeypatch, capsys):
    ev = tmp_path / "docs" / "evidence" / "lane"
    ev.mkdir(parents=True)
    (ev / "probe.json").write_text(f'{{"host_ipv6": "{_VENDOR_EUI64_LL}"}}\n')
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.main() == 1
    out = capsys.readouterr().out
    assert "docs/evidence/lane/probe.json:1: EUI-64" in out
    assert _VENDOR_EUI64_LL not in out


def test_main_flags_a_hand_sanitized_capture_with_only_macs_faked(tmp_path, monkeypatch, capsys):
    """A hand-sanitized capture with every MAC field faked, where the device
    identity survives in an EUI-64 link-local, an SSH host-key fingerprint, x_* keys
    and a serial."""
    rec = tmp_path / "tests" / "fixtures" / "recorded"
    rec.mkdir(parents=True)
    capture = {
        "body": {
            "data": [
                {
                    "mac": "02:00:5e:00:00:03",
                    "ipv6": [_VENDOR_EUI64_LL],
                    "x_authkey": _X_REAL,
                    "x_vwirekey": _X_REAL,
                    "x_ssh_hostkey_fingerprint": _SHA256_FP,
                    "serial": "F" + "CE" + "U12345678",
                }
            ]
        }
    }
    (rec / "ap_capture.json").write_text(json.dumps(capture, indent=1) + "\n")
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.main() == 1
    out = capsys.readouterr().out
    for label in (
        "EUI-64",
        "SSH host-key fingerprint (SHA256)",
        "x_* secret field",
        "serial-number",
    ):
        assert label in out, label
    for value in (_VENDOR_EUI64_LL, _SHA256_FP, _X_REAL):
        assert value not in out


def test_every_committed_fixture_and_evidence_file_is_a_gate_target():
    root = gate.REPO_ROOT
    targets = set(gate.iter_target_files())
    for base in ("tests/fixtures", "docs/evidence"):
        for path in (root / base).rglob("*"):
            if path.is_file():
                assert path in targets, path


@pytest.mark.parametrize("key", ["ppsk", "wlanPsk", "authkey", "vwirekey", "meshPsk"])
def test_wifi_and_device_key_suffixes_are_credentials(key):
    assert gate._credential_key(key)
    assert gate.credential_hits(json.dumps({key: "synthetic-credential"}))
    assert gate.credential_hits(json.dumps({key: "<psk>"})) == []


@pytest.mark.parametrize("key", ["x_mesh_psk", "x_authkey", "x_vwirekey"])
def test_x_prefixed_keys_stay_on_the_strict_x_field_rule(key):
    assert gate.x_field_hits({key: "synthetic-credential"})
    assert gate.x_field_hits({key: "000000fa0001"}) == []


def test_voucher_codes_ship_only_as_all_zero_placeholders():
    rel = "tests/fixtures/recorded/network_integration/x_hotspot_vouchers__create.json"
    real = {"body": {"vouchers": [{"code": "4821937560", "name": "guest"}]}}
    placeholder = {"body": {"vouchers": [{"code": "00000000"}, {"code": "00000-00000"}]}}
    assert gate.voucher_code_hits(rel, real)
    assert gate.voucher_code_hits(rel, {"code": 4821937560})
    assert gate.voucher_code_hits(rel, placeholder) == []
    # "code" elsewhere (error codes, country codes) is not a voucher.
    assert gate.voucher_code_hits("tests/fixtures/recorded/errors/x__400.json", real) == []
    assert any("voucher code" in finding for finding in gate.scan_text(rel, json.dumps(real)))


# ------------------------------------------------- free text in recorded captures
_REC = "tests/fixtures/recorded/network/example.json"


@pytest.mark.parametrize(
    "value",
    [
        {"message": "Device kitchen-ap.home.lan disconnected"},
        {"status": "uplink via core-sw.corp.acme.com"},
        {"note": "seen at fw1.internal"},
        {"host": "nas.acme.ch"},
        {"message": "reach acme.co.nz"},
        {"message": "host acme.club"},
        {"message": "host my_host.lan"},
        {"messageRaw": "Case created by 'Jane Smith'"},
        {"message": "Device “Living Room AP” restarted"},
        {"nested": [{"statusMessage": 'adopted "Garage Cam"'}]},
        {"message": "renamed to 'kitchen-ap'"},
        {"message": "user 'jsmith' signed in"},
        {"message": "user 'jane.smith' signed in"},
        {"message": "site 'acme-hq' added"},
        {"message": "Jane's AP restarted"},
        {"message": "Acme-HQ’s switch is offline"},
        {"message": "reach api.acme.com"},
        {"message": "reach nas.management.lan"},
        {"acme.management": True},
        {"message": "reach nas.acme.md"},
        {"message": "reach x.acme.sh"},
        {"message": "reach myNas.lt"},
        {"message": "renamed to 'Garage-2'"},
        {"message": 'renamed to "O\'Brien AP"'},
        {"message": "renamed to 'Jane's Cam'"},
        {"message": "Jane Smith's AP restarted"},
        {"message": "Living Room's AP restarted"},
        {"message": "Jane name-0001's AP restarted"},
        {"acme-nas.local": 1},
    ],
)
def test_recorded_free_text_identifiers_are_flagged(value):
    findings = gate.scan_text(_REC, json.dumps(value))
    assert findings, value
    assert all("acme" not in f and "Smith" not in f and "Garage" not in f for f in findings)


@pytest.mark.parametrize(
    "value",
    [
        {"message": "must have required property 'camera'"},
        {"messageRaw": "{userLink} closed the case"},
        {"messageRaw": "Case created by {userLink}"},
        {"message": "Device 'name-0003' restarted"},
        {"message": "can't reach host; didn't respond"},
        {"message": "It's offline and that's expected"},
        {"message": "Device name-0001's uplink and Today's report"},
        {"fw_version": "UVC.SAV539g.v5"},
        {"code": "api.err.MatterNodeNotFound"},
        {"code": "api.request.invalid-filter"},
        {"url": "host3.example.invalid"},
        {"inform_url": "example.com"},
        {"path": "hourly.site"},
        {"path": "2DPreview.svg"},
        {"filter": "deviceMac.eq"},
        {"network.management": True, "system.management.location": True, "cpu.id": 1},
        {"host": "unifi.ui.com"},
        {"text": '<meta charset="utf-8" lang="en">'},
    ],
)
def test_recorded_free_text_fakes_and_codes_pass(value):
    assert gate.scan_text(_REC, json.dumps(value)) == []


def test_free_text_rules_apply_only_to_recorded_captures():
    value = {"message": "Device kitchen-ap.home.lan said 'Jane Smith'"}
    assert gate.scan_text("docs/evidence/example.json", json.dumps(value)) == []


@pytest.mark.parametrize("value", ["synthetic-key-a", "synthetic-key-z"])
def test_the_contract_fixture_synthetic_key_convention_passes(value):
    assert gate.credential_hits(json.dumps({"input": {"env": {"UNIFI_API_KEY": value}}})) == []


@pytest.mark.parametrize(
    "value",
    [
        "synthetic-key-ab",
        "synthetic-key-",
        "synthetic-key-a1",
        "Xsynthetic-key-a",
        "prod-key-abcdef",
    ],
)
def test_other_credential_material_is_still_flagged(value):
    assert gate.credential_hits(json.dumps({"UNIFI_API_KEY": value}))


def test_serialize_is_not_a_serial_number_key_but_serial_fields_still_are():
    assert gate.serial_hits({"ast-serialize": "0.13.1", "serialization": "x"}) == []
    assert gate.serial_hits({"serialNumber": "00005E005301"})
    assert gate.serial_hits({"serial": "00005E005301"})
    assert gate.serial_hits({"sn": "00005E005301"})
    assert gate.serial_hits({"serialIssuer": "00005E005301"})
    assert gate.serial_hits({"serial_isolation": "00005E005301"})
    assert gate.serial_hits({"deviceSerial": "00005E005301"})
    assert gate.serial_hits({"ast-serialise": "0.13.1"}) == []


class _CountingSpans(list):
    """``taken`` spans that count how many span visits a caller makes."""

    visits = 0

    def __iter__(self):
        for span in super().__iter__():
            self.visits += 1
            yield span


def _colon_runs_line(count):
    # One long single-line record: vendor MACs (bounded matches, so ``taken`` spans)
    # interleaved with JSON key colons and MACs embedded in longer colon runs.
    parts = []
    for i in range(count):
        parts.append(f'"m{i}": "{_VENDOR_MAC}"')
        parts.append(f'"e{i}": "{_VENDOR_MAC}:{i % 9 + 1}"')
    return "{" + ", ".join(parts) + "}"


def test_colon_run_overlap_check_is_linear_on_a_long_line():
    """A long single-line capture is scanned in one pass over the bounded-MAC spans,
    not one pass per colon run (quadratic: a multi-MB recorded fixture stalled the gate)."""
    line = _colon_runs_line(400)
    taken = _CountingSpans(m.span() for m in gate.MAC_ANY_RE.finditer(line))
    assert len(taken) == 400
    assert gate.embedded_colon_macs(line, gate.mac_is_documentation, taken) == 400
    assert taken.visits <= len(taken), taken.visits


def test_colon_run_overlap_check_matches_the_pairwise_rule():
    """The sweep skips exactly the colon runs that overlap a ``taken`` span."""
    line = _colon_runs_line(25)
    taken = [m.span() for m in gate.MAC_ANY_RE.finditer(line)]
    expected = 0
    for match in gate.COLON_RUN_RE.finditer(line):
        if any(s < match.end() and match.start() < e for s, e in taken):
            continue
        groups = match.group(0).split(":")
        if any(
            all(len(g) == 2 for g in groups[i : i + 6])
            and not gate.mac_is_documentation("".join(groups[i : i + 6]))
            for i in range(len(groups) - 5)
        ) and not gate._ipv6_literal(match.group(0)):
            expected += 1
    assert expected == 25
    for spans in (taken, list(reversed(taken)), taken[::2]):
        pairwise = sum(
            1
            for match in gate.COLON_RUN_RE.finditer(line)
            if not any(s < match.end() and match.start() < e for s, e in spans)
            and gate.embedded_colon_macs(match.group(0), gate.mac_is_documentation, [])
        )
        assert gate.embedded_colon_macs(line, gate.mac_is_documentation, spans) == pairwise


# ------------------------------------------------------------ live-plausible ObjectIds
# Built at runtime from a timestamp and an arbitrary tail, so no live-shaped literal ships.
def _object_id(year: int, tail: str = "5a3c91e7d24b08f6") -> str:
    import datetime

    seconds = int(datetime.datetime(year, 10, 28, tzinfo=datetime.UTC).timestamp())
    return f"{seconds:08x}{tail}"


@pytest.mark.parametrize("year", [2016, 2024, 2026, 2039])
def test_live_plausible_object_id_is_flagged_in_any_context(year: int) -> None:
    value = _object_id(year)
    for line in (
        f'LIVE_BACKUP_ID = "{value}"',
        f'    {{"type": "manual", "id": {value!r}}},',
        f"Case id from list_protect_cases; for example {value}.",
        f"/backup/{value}",
        f'"siteId": "{value.upper()}"',
    ):
        hits = gate.live_object_id_hits(line)
        assert hits == ["ObjectId with a live-plausible timestamp that is not a synthetic id"]
        assert value not in hits[0] and value.upper() not in hits[0]


@pytest.mark.parametrize(
    "value",
    [
        "000000000000000000000b01",  # the recorder's zero-padded fake (1970)
        "000000000000000000000e01",
        _object_id(2014),  # before UniFi Network/Protect could have minted it
        "f" * 24,  # far-future timestamp
        _object_id(2026, "0" * 12 + "aa01"),  # a ten-zero run after the timestamp
        _object_id(2026, "ee0000000000ffff"),
        # Listed hand-made families keep working.
        gate.SYNTHETIC_OBJECT_ID_PREFIXES[0] + "b",
        "66d025b301ebc903e80003ea",
    ],
)
def test_synthetic_object_ids_pass(value: str) -> None:
    assert len(value) == 24
    assert gate.live_object_id_hits(f'"id": "{value}"') == []


def test_longer_hex_runs_are_not_object_ids() -> None:
    value = _object_id(2026)
    # A hash, a longer hex run or an id glued to a word is not a standalone ObjectId.
    for line in (f"sha256:{value}{value}", f"{value}0", f"x{value}", f"{value}g"):
        assert gate.live_object_id_hits(line) == [], line
    # Punctuation is a boundary: an id in a URL path or an identifier suffix still counts.
    for line in (f"/backups/{value}", f"{value}_suffix", f"({value})"):
        assert len(gate.live_object_id_hits(line)) == 1, line


def test_live_object_id_scope_covers_published_paths(tmp_path: Path) -> None:
    value = _object_id(2026)
    published = [
        "tests/test_module.py",
        "tests/fixtures/example-upgrade/unifi.env",
        "tests/fixtures/example-upgrade/result.stdout",
        "skills/example/SKILL.md",
        "tools/example-migrator.py",
        "plugins/example/.claude-plugin/plugin.json",
        "plugins/codex/.mcp.json",
        "changelog.d/example.md",
        ".hidden/config",
    ]
    for rel in [
        *published,
        gate.OBJECT_ID_PRIVATE_DIRS[-1] + "private.py",
        "tests/fixtures/binary.dat",
    ]:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\xff\x00" if rel.endswith(".dat") else value.encode())
    scanned = {
        p.relative_to(tmp_path).as_posix() for p in gate.iter_object_id_target_files(tmp_path)
    }
    assert scanned == set(published)
    findings = gate.scan_object_ids(published[0], value)
    label = "ObjectId with a live-plausible timestamp that is not a synthetic id"
    assert findings == [f"{published[0]}:1: {label}"]


def test_object_id_scope_includes_all_tracked_publishable_text() -> None:
    root = gate.REPO_ROOT
    tracked = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])  # noqa: S603, S607
    scanned = set(gate.iter_object_id_target_files(root))
    for name in tracked.decode().split("\0"):
        if not name or name.startswith(gate.OBJECT_ID_PRIVATE_DIRS):
            continue
        path = root / name
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        assert path in scanned, name


def test_public_tree_carries_no_live_plausible_object_id() -> None:
    """Every published text file holds only synthetic ObjectIds (real Protect backup ids once
    sat in a test module and real event and case ids in tool descriptions)."""
    findings = []
    for path in gate.iter_object_id_target_files():
        rel = path.relative_to(gate.REPO_ROOT).as_posix()
        findings.extend(
            gate.scan_object_ids(rel, path.read_text(encoding="utf-8", errors="replace"))
        )
    assert findings == []


# ---------------------------------------------------------- decode-aware literal scan
# Synthetic markers only, every one built at runtime: no secret-shaped literal ships here.
_SYNTH_PEM = "-----" + "BEGIN " + "SYNTHETIC TEST " + "PRIVATE KEY" + "-----"
_SYNTH_BEARER = "Bearer " + "SYNTHMARKER" + "x" * 24
_SYNTH_NAME = "synthetic" + "-estate-" + "marker"


def _encode(text: str, layers: list[str]) -> str:
    """``text`` under ``layers``, innermost first (each layer wraps the previous)."""
    import base64
    import urllib.parse

    for layer in layers:
        if layer == "base64":
            text = base64.b64encode(text.encode()).decode()
        elif layer == "urlsafe":
            text = base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
        elif layer == "hex":
            text = text.encode().hex()
        elif layer == "url":
            text = urllib.parse.quote(text, safe="")
        else:
            raise AssertionError(layer)
    return text


_LAYER_CHAINS = [
    ["base64"],
    ["urlsafe"],
    ["hex"],
    ["url"],
    ["url", "base64"],
    ["url", "base64", "hex"],
]


def _secret_cases():
    for secret in (_SYNTH_PEM, _SYNTH_BEARER):
        for layers in _LAYER_CHAINS:
            line = f'"payload": "{_encode(secret, layers)}",'
            # A layer that leaves the secret readable is not a hidden case (percent-
            # encoding keeps "-----BEGIN" as is): the raw check already covers it.
            if not any(p.search(line) for _, p in gate.DENYLIST):
                yield pytest.param(secret, layers, id=f"{secret.split()[0][:9]}-{'+'.join(layers)}")


@pytest.mark.parametrize(("secret", "layers"), list(_secret_cases()))
def test_encoded_synthetic_secret_is_caught(secret, layers):
    line = f'"payload": "{_encode(secret, layers)}",'
    findings = gate.scan_text("tests/fixtures/example.json", line)
    # The label lists the layers outermost first.
    chain = ">".join(reversed(layers)).replace("urlsafe", "base64")
    assert any(
        f.startswith("tests/fixtures/example.json:1: ") and f.endswith(f" inside {chain} encoding")
        for f in findings
    ), findings
    # file:line:category only: neither the secret nor its encoded form is echoed.
    joined = "\n".join(findings)
    assert "SYNTH" not in joined and secret not in joined and line not in joined


def test_every_layer_chain_is_exercised():
    covered = {"+".join(layers) for _, layers in (c.values for c in _secret_cases())}
    assert covered == {"+".join(layers) for layers in _LAYER_CHAINS}


def test_encoded_estate_name_is_caught_in_fixture_scope(monkeypatch):
    monkeypatch.setattr(gate, "FORBIDDEN_NAMES", [re.compile(_SYNTH_NAME, re.I)])
    line = f'"note": "{_encode("host " + _SYNTH_NAME + " uplink", ["base64"])}",'
    findings = gate.scan_text("tests/fixtures/example.json", line)
    assert any("forbidden-names.txt inside base64 encoding" in f for f in findings), findings
    # Example configs may name private services: names stay fixture/evidence scoped.
    assert gate.scan_text("config/example.json", line) == []


def test_raw_hit_is_not_repeated_for_an_encoded_view(monkeypatch):
    monkeypatch.setattr(gate, "FORBIDDEN_NAMES", [re.compile(_SYNTH_NAME, re.I)])
    # A percent escape elsewhere on the line makes the whole line a URL view that still
    # holds the raw name: the raw check already reports it, the decoded pass must not.
    line = f'"note": "{_SYNTH_NAME}", "q": "a%20b"'
    findings = gate.scan_text("tests/fixtures/example.json", line)
    assert len(findings) == 1 and "encoding" not in findings[0], findings


@pytest.mark.parametrize(
    "line",
    [
        # Prose under each layer decodes to printable text with no secret shape.
        '"d": "' + _encode("Restart the client after the install completes.", ["base64"]) + '"',
        '"d": "' + _encode("Restart the client after the install completes.", ["hex"]) + '"',
        '"q": "' + _encode("name=Living room&page=2", ["url"]) + '"',
        # Opaque tokens: digests and ObjectIds decode to non-printable bytes.
        '"sha256": "' + "9f" * 32 + '"',
        '"sha1": "' + "ab" * 20 + '"',
        '"_id": "' + "0" * 23 + "1" + '"',
        '"blob": "' + "+/" * 20 + "AAAA" + '"',
        # Short tokens are below MIN_ENCODED_TOKEN and are never decoded.
        '"k": "' + _encode("Bearer x", ["base64"]) + '"',
    ],
)
def test_benign_encoded_text_is_not_flagged(line):
    assert gate.scan_text("tests/fixtures/example.json", line) == [], line


def test_decode_depth_bound_is_honoured():
    deep = _encode(_SYNTH_PEM, ["base64"] * (gate.MAX_DECODE_DEPTH + 1))
    at_bound = _encode(_SYNTH_PEM, ["base64"] * gate.MAX_DECODE_DEPTH)
    assert gate.decoded_hits(at_bound), "a secret exactly MAX_DECODE_DEPTH layers deep is caught"
    assert gate.decoded_hits(deep) == [], "one layer past the bound is not decoded"
    assert all(len(layers) <= 1 for layers, _ in gate.decoded_views(at_bound, depth=1))
    assert not any(_SYNTH_PEM in text for _, text in gate.decoded_views(at_bound, depth=2))
    assert gate.decoded_views(at_bound, depth=0) == []


def test_decoded_views_are_capped_per_line():
    tokens = " ".join(
        _encode(f"plain printable token number {i:04d}", ["base64"]) for i in range(200)
    )
    assert len(gate.decoded_views(tokens)) == gate.MAX_DECODED_VIEWS
