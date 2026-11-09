#!/usr/bin/env python3
"""Fixtures-sanitization gate.

Fail CI if real secrets or PII appear in committed test fixtures or example
configuration files. The fixtures under tests/fixtures/recorded/ are sanitized
captures of REAL upstream responses, so this gate must recognise every identifier
class those captures carry; it complements the `gitleaks` job with denylist checks
tuned to this repo's data shapes.

Scope (intentionally excludes src/ and the test *code* under tests/*.py -- those
are covered by gitleaks; this job only inspects data/config files):
  - tests/fixtures/**
  - docs/evidence/** (committed probe / live-run evidence)
  - config/**
  - repo-root .mcp.json
  - any *.example.* / *.sample.* / .env.example / .env.sample anywhere in tree

Checks on every target: secrets (PEM, JWT, bearer, API key), numeric hardware and
subscriber identifiers (IMEI, IMEISV, EID, ICCID, ASN), public IPv4 addresses, and
vendor MAC addresses (colon, dash or dotted form) that are not locally administered,
not in the IANA 00:00:5e OUI and not a listed documentation value (DOC_MACS), also
inside a longer colon run unless that run is a valid IPv6 literal (a vendor EUI-64 of
eight 2-hex groups is flagged even though it parses as IPv6). Also on every target:
IPv6 addresses in any form whose modified EUI-64 interface id encodes a MAC the MAC
rule rejects (fe80::xxxx:xxff:fexx:xxxx), public IPv6 outside 2001:db8::/32, SSH
host-key fingerprints (SHA256:..., MD5 colon hex) and public keys, UniFi x_* secret
fields (x_authkey, x_vwirekey, x_ssh_hostkey_fingerprint, ...) holding anything but a
placeholder, serial-number fields that are not placeholders/fakes, and the release
battery's estate / internal names (.github/forbidden-names.txt; the battery seed
fixtures are exempt). Captures recorded by hand (not by the recorder) get the same
checks: the rule is on the data, not on the tool that produced it.
Checks on recorded captures (tests/fixtures/recorded/), whose identifiers are all
replaced with stable fakes: MAC addresses (any separator or none) outside the fake
02:00:5e / 00:00:00 prefixes, ObjectIds, UUIDs and console host ids that are not the
zero-padded fakes, email addresses, latitude/longitude values other than the fake
pair, private IPv4 addresses outside the fake 10.0.0.0/16 range, free-text name
fields (name, hostname, email, owner, first/last/full name) that are not placeholders,
and identifiers inside free text under ANY key: host / domain names ending in a
dotted name with an alphabetic last label that is not a known non-host shape or a
reserved example domain, quoted spans ('Living Room', 'jsmith') that are not a
placeholder or a listed schema word, and capitalised possessives ("Jane's AP").

On every published text file (source, test code, public docs and fixtures alike):
ObjectId literals whose embedded timestamp is live-plausible (2015-2039) and that are not
zero-padded or a listed synthetic family.

Findings print only "<file>:<line>: <category>" -- never the matched value --
so no secret is echoed to CI logs.
"""

from __future__ import annotations

# Keep this import block in its current order (isort is disabled for it).
# isort: off
import ipaddress
import json
import tomllib
import re
import shlex
import subprocess
import sys
from pathlib import Path
# isort: on

REPO_ROOT = Path(__file__).resolve().parents[2]

# Public IPv4 literals explicitly allowed as documentation placeholders.
ALLOWED_PUBLIC_IPS = {"8.8.8.8", "1.1.1.1", "1.2.3.4"}

# Denylist of regexes matching real-looking secret material. Placeholder forms
# (e.g. "Bearer ${ENV_VAR}", "X-API-KEY: <your-key>") fall below the length /
# charset thresholds and do not match.
DENYLIST = [
    ("PEM header (private key / certificate)", re.compile(r"-----BEGIN")),
    (
        "JWT-shaped token",
        re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"),
    ),
    (
        "Bearer token (real-looking)",
        re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}"),
    ),
    (
        "UniFi / api.ui.com API key",
        re.compile(r"(?i)(?:x-api-key|api[_-]?key)\s*[:=]\s*[\"']?[A-Za-z0-9]{30,}"),
    ),
    # SSH host-key material identifies one physical device as surely as its MAC does.
    # Zero-padded fakes (SHA256:0000...0001, 00:00:...:01) carry no identity and pass.
    (
        "SSH host-key fingerprint (SHA256)",
        re.compile(r"SHA256:(?![0A]{20})[A-Za-z0-9+/]{43}(?![A-Za-z0-9+/])"),
    ),
    (
        "SSH host-key fingerprint (MD5 colon hex)",
        re.compile(
            r"(?<![0-9A-Fa-f:])(?:MD5:)?(?!(?:00:){10})"
            r"(?:[0-9A-Fa-f]{2}:){15}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])"
        ),
    ),
    (
        "SSH public key",
        re.compile(
            r"\b(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d{3}|sk-ssh-ed25519@openssh\.com)"
            r"\s+AAAA[A-Za-z0-9+/]{16,}"
        ),
    ),
]

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Numeric hardware / subscriber identifiers. A digit run is only a candidate when it
# is not part of a longer number or a decimal fraction: a digit-dot-digit adjacency
# on either side (so the fraction digits of a float such as 1.234567890123456 are
# never read as an identifier, while a run that ends a sentence or follows a
# non-digit dot is).
DIGIT_RUN_RE = re.compile(r"(?<!\d)(?<!\d\.)\d{15,32}(?!\d)(?!\.\d)")
# Well-known numeric sentinels that are not identifiers (2**53 - 1 / 2**53: the largest
# integers a JSON double holds exactly, used as "unbounded" markers).
SENTINEL_NUMBERS = {"9007199254740991", "9007199254740992"}
# A line whose JSON key is an endpoint ("/v1/..." or "GET /v1/...") maps that endpoint
# to a 16-hex-digit spec hash (the spec-drift baseline), never to a hardware identifier.
PATH_KEY_RE = re.compile(r'^\s*"(?:[A-Z]+ )?/[^"]*"\s*:')
# Autonomous system numbers are matched by key name, never by digit count (an ASN can
# be 1-10 digits): any key containing ``asn`` in any case (``ispAsn``,
# ``asns``, ``asn_number``). The value may carry an ``AS`` prefix.
# Values in the private / documentation ranges are allowed.
KEYED_NUMBER_RE = re.compile(r'"([A-Za-z0-9_-]+)"\s*:\s*"?((?:[Aa][Ss])?)(\d+)"?')
# "AS<digits>" string values (whole string, or the leading word of one such as
# "AS64500 Example Net"), under any key.
AS_STRING_RE = re.compile(r'"AS(\d{1,10})(?=["\s])')
ALLOWED_ASN_RANGES = (
    (0, 0),
    (64496, 65534),
    (65536, 65551),
    (4200000000, 4294967294),
)


def is_asn_key(key):
    """True for an autonomous-system-number key name in any of its spellings."""
    return "asn" in re.sub(r"[^a-z0-9]", "", key.lower())


def asn_allowed(value):
    return any(lo <= value <= hi for lo, hi in ALLOWED_ASN_RANGES)


def luhn_valid(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def numeric_identifier_hits(line):
    """Categories of real-looking numeric identifiers on ``line`` (values never returned)."""
    hits = []
    if not PATH_KEY_RE.match(line):
        for match in DIGIT_RUN_RE.finditer(line):
            run = match.group(0)
            if run in SENTINEL_NUMBERS:
                continue
            if len(run) == 15 and luhn_valid(run):
                hits.append("15-digit Luhn-valid number (IMEI-shaped)")
            elif len(run) == 16 and not run.startswith("000"):
                hits.append("16-digit number (IMEISV-shaped)")
            elif len(run) == 32 and run.startswith("89"):
                hits.append("32-digit number starting 89 (eSIM EID-shaped)")
            elif 18 <= len(run) <= 22 and run.startswith("89"):
                hits.append("18-22 digit number starting 89 (ICCID-shaped)")
    for match in KEYED_NUMBER_RE.finditer(line):
        if is_asn_key(match.group(1)) and not asn_allowed(int(match.group(3))):
            hits.append("ASN outside the private/documentation ranges")
    for match in AS_STRING_RE.finditer(line):
        if not asn_allowed(int(match.group(1))):
            hits.append("AS-number string outside the private/documentation ranges")
    return hits


# ---------------------------------------------------------------- recorded captures
RECORDED_DIR = "tests/fixtures/recorded/"
# The recorder's fakes: MACs 02:00:5e:xx:xx:xx (or all-zero), ids zero-padded, the
# coordinate pair 12.345678 / -98.765432, private addresses in 10.0.0.0/16.
FAKE_MAC_PREFIXES = ("02005e", "000000")
# A bare 12-hex string value (MAC without separators, or a device serial: UniFi
# serials are the device MAC). Digit-only values are checked structurally by key.
MAC_BARE_RE = re.compile(r'"([0-9A-Fa-f]{12})"')
OBJECT_ID_RE = re.compile(r'"([0-9a-fA-F]{24})"')
UUID_RE = re.compile(
    r"\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b"
)
# Site Manager console host id: <hardware hex>:<number>.
CONSOLE_ID_RE = re.compile(r"\b([0-9A-Fa-f]{40,}):(\d+)\b")
# A UUID with a numeric suffix (the cloud-access setting's device_id). UUID_RE checks only
# the UUID half; the number identifies the device too.
DEVICE_ID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}:(\d+)\b"
)
# The recorder's numeric-suffix fakes: zero-padded, at most four significant digits.
FAKE_ID_NUMBER_RE = re.compile(r"0*\d{1,4}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
COORD_KEYS = {"lat", "latitude", "lng", "lon", "long", "longitude"}
COORD_RE = re.compile(r'"([A-Za-z_]+)"\s*:\s*"?(-?\d+(?:\.\d+)?)"?')
FAKE_COORDS = {"12.345678", "-98.765432", "0", "0.0"}
FAKE_PRIVATE_NET = ipaddress.ip_network("10.0.0.0/16")
PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT (a WAN address)
)
# Free-text fields the recorder replaces with "<key>-NNNN" placeholders. Values the
# controller itself assigns (system zone and network names) are allowed as-is.
NAME_KEYS = {
    "name",
    "hostname",
    "displayname",
    "email",
    "owner",
    "firstname",
    "lastname",
    "fullname",
    "username",
}
NAME_RE = re.compile(r'"([A-Za-z_]+)"\s*:\s*"([^"]*)"')
ID_VALUE_RE = re.compile(
    r"^(?:[0-9a-fA-F]{24}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})\Z"
)
PLACEHOLDER_RE = re.compile(r"^[A-Za-z_]+-\d+\Z")
CONTROLLER_NAMES = {
    "default",
    "internal",
    "external",
    "gateway",
    "hotspot",
    "vpn",
    "dmz",
    # A published enum constant named "name", not free text: the firewall-policy
    # protocol preset (Network 11.0.97 ...ProtocolPresetTcpUdpDto, the only preset).
    "tcp_udp",
}


# Free text. The recorder and the fixtures check carry this block verbatim
# (tests/test_recorder_sanitizer.py asserts the two copies are equal).
# A dotted name whose last label is alphabetic (2+ letters) names a host, under any
# top-level domain, unless it is one of the exact non-host shapes seen in real
# captures (error codes, permission-scope keys, a stats report path, a filter, a file
# name) or a reserved example / vendor service domain. Firmware strings such as
# UVC.SAV539g.v5 end in a digit label and never match.
HOSTNAME_RE = re.compile(r"(?<![\w.@-])(?:\w[\w-]*\.)+[^\W\d_]{2,}(?![\w-]|\.\w)")
# Extensions that are not also top-level domains; exempt only on a single-dot name.
FILE_EXTENSIONS = frozenset(
    "json js css html htm svg png jpg jpeg gif webp ico txt yaml yml xml csv pdf "
    "log gz tar bin mp4 wav mp3 crt pem".split()
)
PERMISSION_SCOPES = frozenset(
    "access calculus connect drive fabric innerspace led network olympus protect talk "
    "talk-relay".split()
)
NON_HOST_RES = (
    re.compile(r"^api\.(?:err|request)\.\w+\Z"),
    re.compile(r"^system\.management\.(?:location|user)\Z"),
    re.compile(r"^(?:5minutes|hourly|daily|monthly)\.(?:site|ap|user|gw|sw)\Z"),
    re.compile(r"^cpu\.id\Z"),
    re.compile(r"^deviceMac\.eq\Z"),
)
SAFE_HOST_SUFFIXES = (
    "example.com",
    "example.net",
    "example.org",
    "example",
    "invalid",
    "test",
    "localhost",
    "ui.com",
    "ubnt.com",
)
# A quoted span in free text ('Living Room', "O'Brien AP") is usually a user-chosen
# name. An ASCII quote pairs with the same quote at word boundaries (so a contraction
# such as can't opens nothing) and the shortest such span wins; it may hold quotes. A span is kept
# only when it is a recorder fake (word-NNNN, hostN.example.invalid, a fake MAC), a
# {template} slot, or one of the schema words seen in real captures.
QUOTED_RE = re.compile(
    "(?<!\\w)(?P<q>['\"])(?P<a>[^\\n]{1,200}?)(?P=q)(?!\\w)"
    "|(?P<o>[\\u201c\\u2018])(?P<b>[^\\u201d\\u2019\\n]{1,200})(?P<c>[\\u201d\\u2019])"
)
SAFE_QUOTED_WORDS = frozenset({"camera", "en", "utf-8", "text/css"})
SAFE_QUOTED_RE = re.compile(
    r"^(?:[A-Za-z_]+-\d{4}|\{[A-Za-z_]+\}|host\d+\.example\.invalid"
    r"|02:00:5e(?::[0-9a-f]{2}){3}|00:00:00(?::[0-9a-f]{2}){3})\Z"
)
# A capitalised possessive, one or more words ("Jane's AP", "Jane Smith's AP",
# "Living Room's AP"), names a person or place. A capitalised word left directly in
# front of a recorder fake possessive ("Jane name-0001's") is a partial scrub.
POSSESSIVE_RE = re.compile("\\b((?:[A-Z][\\w-]*[ \\t]+)*[A-Z][\\w-]*)['\\u2019]s\\b")
PARTIAL_POSSESSIVE_RE = re.compile("\\b([A-Z][\\w-]*)[ \\t]+[A-Za-z_]+-\\d{4}['\\u2019]s\\b")
NON_NAME_POSSESSIVES = frozenset(
    "It That There What Here Who Let He She Where This When Why How Today Tomorrow "
    "Yesterday Everything Everyone Everybody Nothing Nobody Something Someone Somebody "
    "Anyone Anything One Each Device Camera Site Network Gateway Switch Console "
    "Controller System User Client Admin Server".split()
)


def is_identifying_host(name):
    """True for a host/domain name that may name a real site (not a non-host shape)."""
    lo = name.lower().rstrip(".")
    if lo.count(".") == 1 and lo.rsplit(".", 1)[-1] in FILE_EXTENSIONS:
        return False
    head, _, tail = lo.rpartition(".")
    if tail == "management" and head in PERMISSION_SCOPES:
        return False
    if any(rx.search(name) for rx in NON_HOST_RES):
        return False
    return not any(lo == sfx or lo.endswith("." + sfx) for sfx in SAFE_HOST_SUFFIXES)


def quoted_body(mo):
    """The text inside one QUOTED_RE match."""
    return mo.group("a") if mo.group("a") is not None else mo.group("b")


def is_safe_quoted(body):
    return body in SAFE_QUOTED_WORDS or bool(SAFE_QUOTED_RE.match(body))


def possessive_name_words(mo):
    """The name words of a POSSESSIVE_RE match, leading non-name words dropped."""
    words = mo.group(1).split()
    while words and words[0] in NON_NAME_POSSESSIVES:
        words.pop(0)
    return words


def is_name_possessive(mo):
    return bool(possessive_name_words(mo))


def is_partial_possessive(mo):
    return mo.group(1) not in NON_NAME_POSSESSIVES


def free_text_hits(value):
    """Identifiers inside free-text string values under any key (recorded captures)."""
    hits = []
    if isinstance(value, list):
        for item in value:
            hits.extend(free_text_hits(item))
    elif isinstance(value, dict):
        for key, item in value.items():
            hits.extend(free_text_hits(key))
            hits.extend(free_text_hits(item))
    elif isinstance(value, str):
        if any(is_identifying_host(m.group(0)) for m in HOSTNAME_RE.finditer(value)):
            hits.append("host/domain name in free text outside the reserved example domains")
        if any(not is_safe_quoted(quoted_body(m)) for m in QUOTED_RE.finditer(value)):
            hits.append("quoted free-text span that is not a placeholder")
        if any(is_name_possessive(m) for m in POSSESSIVE_RE.finditer(value)):
            hits.append("possessive name in free text")
        if any(is_partial_possessive(m) for m in PARTIAL_POSSESSIVE_RE.finditer(value)):
            hits.append("name word left before a scrubbed possessive")
    return hits


def _mac_is_fake(hex12):
    return hex12.lower().startswith(FAKE_MAC_PREFIXES)


# ------------------------------------------------------------ MACs on every target
# A MAC in colon, dash or dotted (xxxx.xxxx.xxxx) form. Outside the recorded captures
# (which carry only the recorder's fakes) a MAC is allowed only when it can never name
# a real device: a locally administered address (second-lowest bit of the first octet
# set: 02:..., aa:bb:cc:dd:ee:ff, ...), the IANA OUI 00:00:5e (RFC 7042 reserves
# 00:00:5e:00:53:xx for documentation), or one of the documentation values below.
# Anything else is a vendor (globally unique) address and may be a real device.
_HEX = "[0-9A-Fa-f]"
_WORD = "[0-9A-Za-z_]"


def _mac_form(body, sep, widths):
    # A MAC must not sit inside a longer hex token, and a separator next to it is
    # excluded only when it continues a longer hex group (a standalone hex group of
    # one of ``widths`` digits, as in an IPv6 address or an EUI-64): "mac:<MAC>",
    # "uplink-<MAC>", ".<MAC>" and "<MAC>." are all still matched.
    before = "".join(f"(?<!(?<!{_WORD}){_HEX}{{{n}}}{sep})" for n in widths)
    after = f"(?!{sep}{_HEX}{{{min(widths)},{max(widths)}}}(?!{_WORD}))"
    return f"(?:{before}(?<!{_HEX}){body}(?!{_HEX}){after})"


MAC_ANY_RE = re.compile(
    "("
    + _mac_form(f"(?:{_HEX}{{2}}:){{5}}{_HEX}{{2}}", ":", (1, 2, 3, 4))
    + "|"
    + _mac_form(f"(?:{_HEX}{{2}}-){{5}}{_HEX}{{2}}", "-", (2,))
    + "|"
    + _mac_form(f"{_HEX}{{4}}\\.{_HEX}{{4}}\\.{_HEX}{{4}}", "\\.", (4,))
    + ")"
)
# The recorded-capture check covers the colon and dash forms (the recorder writes no
# dotted MACs) with the same boundary rule.
MAC_SEP_RE = re.compile(
    "("
    + _mac_form(f"(?:{_HEX}{{2}}:){{5}}{_HEX}{{2}}", ":", (1, 2, 3, 4))
    + "|"
    + _mac_form(f"(?:{_HEX}{{2}}-){{5}}{_HEX}{{2}}", "-", (2,))
    + ")"
)
DOC_MAC_PREFIXES = ("00005e",)
DOC_MACS = {
    "000000000000",  # all-zero (unset)
    "ffffffffffff",  # broadcast
    "112233445566",
    "001122334455",
    "001a2b3c4d5e",
}


def mac_is_documentation(hex12):
    """True for a MAC (12 hex digits, no separators) that cannot name a real device."""
    value = hex12.lower()
    return (
        bool(int(value[:2], 16) & 0x02) or value in DOC_MACS or value.startswith(DOC_MAC_PREFIXES)
    )


# A MAC inside a longer colon run ("<MAC>:1", "1:<MAC>") escapes the bounded patterns
# above (the neighbouring group looks like IPv6 / EUI-64). Every maximal colon run is
# therefore also checked: a window of exactly six 2-hex groups whose address the rule
# does not allow is flagged, unless the whole run is a valid IPv6 literal. A run of
# exactly eight 2-hex groups with a vendor first octet is an EUI-64 MAC and is flagged
# even though it parses as IPv6 (real IPv6 literals almost never have all-2-hex groups).
COLON_RUN_RE = re.compile(r"[0-9A-Fa-f:]*:[0-9A-Fa-f:]*")


def _ipv6_literal(run):
    for cand in (run, run.strip(":")):
        try:
            ipaddress.ip_address(cand)
            return True
        except ValueError:
            pass
    return False


def _eui64(run, allowed):
    """True for exactly eight 2-hex groups whose leading six-octet address ``allowed``
    rejects (a vendor EUI-64), even though the run parses as IPv6."""
    groups = run.strip(":").split(":")
    return (
        len(groups) == 8 and all(len(g) == 2 for g in groups) and not allowed("".join(groups[:6]))
    )


def embedded_colon_macs(line, allowed, taken):
    """Number of colon runs on ``line`` holding a six-group MAC window that ``allowed``
    rejects, not already matched by a bounded MAC pattern (``taken`` spans) and not a
    valid IPv6 literal, or that are a vendor EUI-64 (see ``_eui64``).

    Runs and ``taken`` spans are each in line order and do not overlap among themselves,
    so one forward sweep finds the overlaps: linear in the line, where testing every run
    against every span was quadratic on a long single-line capture."""
    count = 0
    spans = sorted(taken)
    index = 0
    for match in COLON_RUN_RE.finditer(line):
        start, end = match.span()
        while index < len(spans) and spans[index][1] <= start:
            index += 1
        if index < len(spans) and spans[index][0] < end:
            continue
        groups = match.group(0).split(":")
        bad = any(
            all(len(g) == 2 for g in groups[i : i + 6]) and not allowed("".join(groups[i : i + 6]))
            for i in range(len(groups) - 5)
        )
        if (bad and not _ipv6_literal(match.group(0))) or _eui64(match.group(0), allowed):
            count += 1
    return count


# ------------------------------------------------------------ IPv6 on every target
# An IPv6 address in any textual form (compressed "fe80::...", zone or prefix suffix
# stripped by the run boundary). Its interface identifier may be a modified EUI-64
# (ff:fe in bytes 11-12), which encodes the device MAC (universal/local bit flipped):
# that MAC must pass the same rule as a literal MAC. Public addresses (2000::/3) must
# sit in the documentation prefix 2001:db8::/32. In recorded captures, link-local
# addresses must be the recorder's fakes (fe80::<small n>) and unique-local (fc00::/7)
# addresses never appear (the recorder maps every non-link-local address into
# 2001:db8::/32).
DOC_IPV6 = ipaddress.ip_network("2001:db8::/32")
GLOBAL_UNICAST_IPV6 = ipaddress.ip_network("2000::/3")
LINK_LOCAL_IPV6 = ipaddress.ip_network("fe80::/10")
UNIQUE_LOCAL_IPV6 = ipaddress.ip_network("fc00::/7")
RECORDED_FAKE_LL_MAX = 0xFFFF


def _ipv6_in_run(run):
    """The IPv6 address a colon run holds, also after a leading key ("ipv6:fe80::1")."""
    candidates = [run, run.strip(":")]
    for index, char in enumerate(run):
        if char == ":":
            candidates.append(run[index + 1 :])
            candidates.append(run[index:])
    for candidate in candidates:
        if candidate.count(":") < 2:
            continue
        try:
            return ipaddress.IPv6Address(candidate)
        except ValueError:
            continue
    return None


def eui64_mac(ip):
    """The 12-hex MAC a modified EUI-64 interface id encodes, or None."""
    iid = ip.packed[8:]
    if iid[3] == 0xFF and iid[4] == 0xFE:
        return bytes([iid[0] ^ 0x02]).hex() + iid[1:3].hex() + iid[5:].hex()
    return None


def ipv6_hits(line, recorded=False):
    """Categories of real-looking IPv6 addresses on ``line`` (values never returned)."""
    hits = []
    allowed = _mac_is_fake if recorded else mac_is_documentation
    for match in COLON_RUN_RE.finditer(line):
        ip = _ipv6_in_run(match.group(0))
        if ip is None:
            continue
        mac = eui64_mac(ip)
        if mac and not allowed(mac):
            hits.append(
                "EUI-64 IPv6 address encoding a MAC outside the synthetic/documentation values"
            )
        if ip in GLOBAL_UNICAST_IPV6 and ip not in DOC_IPV6:
            hits.append("public IPv6 address outside the documentation prefix 2001:db8::/32")
        elif recorded and ip in UNIQUE_LOCAL_IPV6:
            hits.append("unique-local IPv6 address in a recorded capture (not a recorder fake)")
        elif (
            recorded
            and ip in LINK_LOCAL_IPV6
            and not mac
            and int(ip) & ((1 << 64) - 1) > RECORDED_FAKE_LL_MAX
        ):
            hits.append("link-local IPv6 address that is not a recorder fake (fe80::<n>)")
    return hits


# ------------------------------------------------- UniFi x_* fields on every target
# UniFi prefixes every secret-bearing setting with "x_" (x_passphrase, x_authkey,
# x_vwirekey, x_iapp_key, x_ssh_hostkey_fingerprint, x_ssh_keys, ...). Every string
# under such a key (and inside any list / record it holds) must be a placeholder.
X_FIELD_RE = re.compile(
    r"""(?<![A-Za-z0-9_])["']?(x_[A-Za-z0-9_]+)["']?\s*[:=]\s*["']([^"']*)["']"""
)
X_PLACEHOLDER_RE = re.compile(
    r"^(?:|[xX*]+|REDACTED|redacted|<[^<>]*>|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|"
    r"[A-Za-z][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*-\d{1,6}|"  # recorder placeholder (key-0001)
    r"0+|0{6,}(?:fa)?[0-9a-fA-F]{1,6}|"  # zero-padded fakes (recorder: 0...0fa0001)
    r"\d{4}-\d{2}-\d{2}(?:[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)?|"  # ISO date/time
    r"ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d{3}|"  # SSH key type
    r"SHA256:(?:x+|[0A]{20,}[A-Za-z0-9+/]{0,23}=?)|MD5:x+)\Z"  # fingerprint fakes
)


def x_field_hits(value, inside=False):
    """Categories of non-placeholder strings held by UniFi x_* keys (structured)."""
    hits = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "properties" and isinstance(item, dict):
                for name, schema in item.items():
                    if str(name).startswith("x_") and isinstance(schema, dict):
                        for literal in ("default", "const", "enum", "examples"):
                            if literal in schema:
                                hits.extend(x_field_hits(schema[literal], True))
                        for child_key, child in schema.items():
                            if child_key not in {"default", "const", "enum", "examples"}:
                                hits.extend(x_field_hits(child, inside))
                    else:
                        hits.extend(x_field_hits(schema, inside or str(name).startswith("x_")))
                continue
            hits.extend(x_field_hits(item, inside or str(key).startswith("x_")))
    elif isinstance(value, list):
        for item in value:
            hits.extend(x_field_hits(item, inside))
    elif inside and isinstance(value, str) and not X_PLACEHOLDER_RE.fullmatch(value):
        hits.append("UniFi x_* secret field holds a non-placeholder value")
    return hits


def x_field_line_hits(line):
    """The text form of ``x_field_hits`` for files that are not JSON documents."""
    return [
        "UniFi x_* secret field holds a non-placeholder value"
        for match in X_FIELD_RE.finditer(line)
        if not X_PLACEHOLDER_RE.fullmatch(match.group(2))
    ]


# ----------------------------------------------------- serial numbers on every target
SERIAL_PLACEHOLDER_RE = re.compile(
    r"^(?:|[xX*]+|REDACTED|<[^<>]*>|[A-Za-z][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*-\d{1,6}|"
    r"0+\d{0,6}|(?:02005e|000000)[0-9a-fA-F]{6})\Z"
)


def _serial_key(key):
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    # "serialize"/"serialization" name a package or a codec, not a device serial number.
    return normalized == "sn" or re.search(r"serial(?!iz[ae]|is[ae])", normalized) is not None


def serial_hits(value):
    """Categories of serial-number fields whose value is not a placeholder/fake."""
    hits = []
    if isinstance(value, dict):
        for key, item in value.items():
            if _serial_key(key):
                scalars = item if isinstance(item, list) else [item]
                for scalar in scalars:
                    if isinstance(scalar, str) and not SERIAL_PLACEHOLDER_RE.fullmatch(scalar):
                        hits.append("serial-number field that is not a placeholder or fake")
            hits.extend(serial_hits(item))
    elif isinstance(value, list):
        for item in value:
            hits.extend(serial_hits(item))
    return hits


# ------------------------------------------- estate names in fixture data
# The release battery's forbidden names (.github/forbidden-names.txt: estate console,
# site and people names, estate device MACs, internal service names) must not appear
# in any fixture or committed evidence either. When the list file is absent the check
# is a no-op. The battery seed fixtures carry the names on purpose (they prove the
# battery fires) and are exempt.
FORBIDDEN_NAMES_FILE = REPO_ROOT / ".github" / "forbidden-names.txt"
FORBIDDEN_SCOPE_PREFIXES = ("tests/fixtures/", "docs/evidence/")
FORBIDDEN_EXEMPT_PREFIXES = ("tests/fixtures/battery_seed/",)


def _load_forbidden_names():
    patterns = []
    if FORBIDDEN_NAMES_FILE.is_file():
        for raw in FORBIDDEN_NAMES_FILE.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if raw and not raw.startswith("#"):
                patterns.append(re.compile(raw, re.I))
    return patterns


FORBIDDEN_NAMES = _load_forbidden_names()


def estate_name_hits(line):
    return [
        "estate / internal name from forbidden-names.txt" for p in FORBIDDEN_NAMES if p.search(line)
    ]


# ------------------------------- ObjectIds with a live-plausible timestamp (all public text)
# A MongoDB ObjectId opens with its creation time (4-byte big-endian epoch seconds), and the
# Network and Protect applications mint one for every record: a site, backup, event, case,
# camera. A 24-hex literal whose timestamp falls in the years a UniFi console could have
# created it may therefore be the id of a real console's record. Unlike the checks above,
# this rule runs on test CODE and source too, because those files are published as well:
# real Protect backup ids once sat in a test module and real event and case ids in tool
# descriptions, where neither the fixture scope nor gitleaks looks.
# Synthetic ids pass when they are zero-padded (the recorder's form, which decodes to 1970),
# carry a run of ten zeros after the timestamp, or belong to one of the hand-made families
# below. Published paths are scanned regardless of extension or hidden components.
OBJECT_ID_LITERAL_RE = re.compile(r"(?<![0-9A-Za-z])([0-9a-fA-F]{24})(?![0-9A-Za-z])")
LIVE_OBJECT_ID_FROM = 1420070400  # 2015-01-01T00:00:00Z
LIVE_OBJECT_ID_UNTIL = 2208988800  # 2040-01-01T00:00:00Z
# Hand-made example families: each prefix plus any final hex digits is synthetic. They are
# ascending/descending digit patterns ("a1b2c3d4", "0123456789", "c0ffee") or, for
# 66d025b301ebc903e80003, one timestamp with consecutive counters (...3ea-...3f0) reused
# across unrelated object types (camera, sensor, user, liveview), which no console mints.
SYNTHETIC_OBJECT_ID_PREFIXES = (
    "5f0c4d2e8b1a2c3d4e5f6a7",
    "5f1e3c2a9b8d7e6f5a4b3c2d",
    "64b1f0c2e4b0a1b2c3d4e5f6",
    "6512a0b1c2d3e4f5a6b7c8d",
    "6523f0c1e4b0a1b2c3d4e5f",
    "65a1b2c3d4e5f60718293a4b",
    "65d4f1e2a1b2c3d4e5f6071",
    "65f1c0ffee0123456789ab",
    "6605abcd1234567890abcdef",
    "66a1b2c3d4e5f60718293a4b",
    "66b2c3d4e5f60718293a4b5c",
    "66d025b301ebc903e80003",
    "66f1a2b3c4d5e6f7a8b9c0d",
    "68f1d2c3b4a5968778695a4",
)
# Private-only directories are omitted from the published-file scan.
OBJECT_ID_PRIVATE_DIRS = (
    "docs/hero/",
    "tests/fixtures/battery_seed/",
    "tests/fixtures/audit/remote/",
    "tests/fixtures/private_api/",
    "tests/fixtures/reference_drift/",
    "tests/conformance/",
    "scripts/private_api/",
)


def object_id_is_synthetic(value):
    """True when a 24-hex ObjectId-shaped ``value`` cannot be a live record id."""
    value = value.lower()
    seconds = int(value[:8], 16)
    if not LIVE_OBJECT_ID_FROM <= seconds < LIVE_OBJECT_ID_UNTIL:
        return True
    return "0" * 10 in value[8:] or value.startswith(SYNTHETIC_OBJECT_ID_PREFIXES)


def live_object_id_hits(line):
    """Categories of ObjectId literals on ``line`` that may be live (values never returned)."""
    return [
        "ObjectId with a live-plausible timestamp that is not a synthetic id"
        for match in OBJECT_ID_LITERAL_RE.finditer(line)
        if not object_id_is_synthetic(match.group(1))
    ]


def iter_object_id_target_files(root=None):
    """Every published text file the live-ObjectId rule reads."""
    root = REPO_ROOT if root is None else root
    if (root / ".git").exists():
        tracked = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])  # noqa: S603, S607
        paths = (root / name for name in tracked.decode("utf-8").split("\0") if name)
    else:
        # Source archives and isolated test trees have no Git index.
        paths = root.rglob("*")
    targets = []
    for path in paths:
        rel = path.relative_to(root).as_posix()
        if not path.is_file() or rel.startswith(OBJECT_ID_PRIVATE_DIRS):
            continue
        try:
            data = path.read_bytes()
            if b"\0" in data:
                continue
            data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        targets.append(path)
    return sorted(targets)


def scan_object_ids(rel, text):
    """Live-ObjectId findings for one file (path, line and category only)."""
    return [
        f"{rel}:{lineno}: {label}"
        for lineno, line in enumerate(text.splitlines(), start=1)
        for label in live_object_id_hits(line)
    ]


def mac_hits(line):
    """Categories of vendor (globally unique) MACs on ``line`` (values never returned)."""
    hits = []
    taken = []
    for match in MAC_ANY_RE.finditer(line):
        taken.append(match.span())
        if not mac_is_documentation(re.sub(r"[:.-]", "", match.group(1))):
            hits.append("vendor MAC address (not locally administered, not a documentation value)")
    for _ in range(embedded_colon_macs(line, mac_is_documentation, taken)):
        hits.append("vendor MAC address inside a longer colon run (not IPv6, or a vendor EUI-64)")
    return hits


def recorded_identifier_hits(line):
    """Categories of real-looking identifiers on a recorded-capture line (values never
    returned). Recorded captures carry only the recorder's fakes, so anything else is
    a sanitization miss."""
    hits = []
    taken = []
    for match in MAC_SEP_RE.finditer(line):
        taken.append(match.span())
        if not _mac_is_fake(re.sub(r"[:-]", "", match.group(1))):
            hits.append("MAC address outside the fake 02:00:5e / 00:00:00 prefixes")
    for _ in range(embedded_colon_macs(line, _mac_is_fake, taken)):
        hits.append("MAC address outside the fake prefixes inside a longer colon run")
    for match in MAC_BARE_RE.finditer(line):
        value = match.group(1)
        if not value.isdigit() and not _mac_is_fake(value):
            hits.append("12-hex MAC/serial outside the fake 02005e / 000000 prefixes")
    for match in OBJECT_ID_RE.finditer(line):
        if not match.group(1).startswith("0000000000"):
            hits.append("ObjectId that is not a zero-padded fake")
    for match in UUID_RE.finditer(line):
        if not match.group(1).startswith("00000000-"):
            hits.append("UUID that is not a zero-padded fake")
    for match in CONSOLE_ID_RE.finditer(line):
        if not match.group(1).startswith("0" * 40) or not FAKE_ID_NUMBER_RE.fullmatch(
            match.group(2)
        ):
            hits.append("console host id that is not a zero-padded fake")
    for match in DEVICE_ID_RE.finditer(line):
        if not FAKE_ID_NUMBER_RE.fullmatch(match.group(1)):
            hits.append("UUID:number device id whose number is not a zero-padded fake")
    if EMAIL_RE.search(line):
        hits.append("email address")
    for match in COORD_RE.finditer(line):
        if match.group(1).lower() in COORD_KEYS and match.group(2) not in FAKE_COORDS:
            hits.append("latitude/longitude other than the fake pair")
    for match in IPV4_RE.finditer(line):
        try:
            ip = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if any(ip in net for net in PRIVATE_NETS) and ip not in FAKE_PRIVATE_NET:
            hits.append("private IPv4 address outside the fake 10.0.0.0/16 range")
    for match in NAME_RE.finditer(line):
        key, value = match.group(1).lower(), match.group(2)
        if (
            key in NAME_KEYS
            and value
            and not PLACEHOLDER_RE.match(value)
            and not ID_VALUE_RE.match(value)  # an id (owner = ObjectId); id checks cover it
            and value.lower() not in CONTROLLER_NAMES
        ):
            hits.append(f"free-text {match.group(1)!r} value that is not a placeholder")
    return hits


def json_identifier_hits(value, recorded=False, hardware=False, asn=False):
    """Check identifiers structurally, carrying key meaning through containers.

    Hardware keys establish identifier meaning even for all-digit values; unrelated
    counters and timestamps do not. ASN containers inherit the enclosing ASN key.
    Findings contain categories only, never identifier values.
    """
    hits = []
    if isinstance(value, list):
        for item in value:
            hits.extend(json_identifier_hits(item, recorded, hardware, asn))
    elif isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            hardware_key = normalized == "sn" or any(
                part in normalized for part in ("mac", "bssid", "hwaddr", "chassis", "serial")
            )
            hits.extend(
                json_identifier_hits(
                    item, recorded, hardware or hardware_key, asn or is_asn_key(key)
                )
            )
    elif isinstance(value, (str, int)) and not isinstance(value, bool):
        text = str(value)
        if asn and re.fullmatch(r"(?:[Aa][Ss])?\d+", text):
            number = int(re.sub(r"^[Aa][Ss]", "", text))
            if not asn_allowed(number):
                hits.append("ASN outside the private/documentation ranges")
        if hardware:
            hex12 = re.sub(r"[:.-]", "", text)
            if re.fullmatch(r"[0-9a-fA-F]{12}", hex12):
                allowed = _mac_is_fake(hex12) or (not recorded and mac_is_documentation(hex12))
                if not allowed:
                    hits.append("MAC/serial field outside the synthetic/documentation values")
    return hits


def iter_json_records(text):
    """Parse JSON regardless of extension, including JSONL and fenced captures.

    Decode a complete record at every ``{`` / ``[`` offset (a line start, or inline in
    prose such as ``see {"asn": 64500} here``), allowing pretty-printed multiline records.
    Consume each record once so nested objects are not repeated.
    The ordinary text checks still inspect lines that are not valid JSON.
    """
    try:
        yield json.loads(text)
        return
    except (ValueError, TypeError):
        pass
    decoder = json.JSONDecoder()
    consumed = 0
    for match in re.finditer(r"[\[{]", text):
        start = match.start()
        if start < consumed:
            continue
        try:
            value, end = decoder.raw_decode(text, start)
        except ValueError:
            continue
        consumed = end
        yield value


GLOBS = [
    "tests/fixtures/**/*",
    # Captured evidence committed beside docs (probe output, live-run records) is
    # fixture data too.
    "docs/evidence/**/*",
    "config/**/*",
    "**/*.example.*",
    "**/*.sample.*",
    "**/.env.example",
    "**/.env.sample",
]

EXPLICIT_FILES = [".mcp.json"]


def iter_target_files():
    seen = set()
    for pattern in GLOBS:
        for path in REPO_ROOT.glob(pattern):
            if path.is_file() and ".git/" not in str(path.as_posix()):
                seen.add(path)
    for rel in EXPLICIT_FILES:
        path = REPO_ROOT / rel
        if path.is_file():
            seen.add(path)
    return sorted(seen)


def public_ip_hits(text):
    hits = []
    for match in IPV4_RE.finditer(text):
        token = match.group(0)
        try:
            ip = ipaddress.ip_address(token)
        except ValueError:
            continue
        if ip.version == 4 and ip.is_global and token not in ALLOWED_PUBLIC_IPS:
            hits.append(token)
    return hits


# Credential keys are checked as structured fields, independently of value shape.
# Normalize case/separators so JSON camelCase, HTTP headers and env spellings agree.
_CREDENTIAL_NAMES = {
    "accesstoken",
    "apikey",
    "apitoken",
    "authorization",
    "authtoken",
    "bearertoken",
    "clientsecret",
    "deviceauth",
    "idtoken",
    "ipsecpresharedkey",
    "openvpnconfiguration",
    "passphrase",
    "passwd",
    "password",
    "presharedkey",
    "privatekey",
    "psk",
    "radiussecret",
    "refreshtoken",
    "saepsk",
    "secret",
    "servercertificatekey",
    "sshpassword",
    "syslogkey",
    "token",
    "wpapsk",
    "xapikey",
    "xapitoken",
    "xauthtoken",
    "xcacrt",
    "xcakey",
    "xcertificatecrt",
    "xcertificatekey",
    "xiappkey",
    "xipsecpresharedkey",
    "xmeshpsk",
    "xpassphrase",
    "xpassword",
    "xprivatekey",
    "xpsk",
    "xradiussecret",
    "xsecret",
    "xsshpassword",
    "xsshsudopassword",
    "xwep",
}

_CREDENTIAL_FIELD_RE = re.compile(
    r"""^\s*(?:export\s+|[-]\s*)?["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[:=]\s*(.*?)\s*\Z"""
)
# Match whole values only. Command substitutions need a separate literal check.
_CREDENTIAL_PLACEHOLDER_RE = re.compile(
    r"""^(?:<[^<>]+>|\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*|"""
    # A VS Code input reference (`${input:<id>}`): the editor prompts for the value.
    r"""\$\{input:[A-Za-z_][A-Za-z0-9_]*\}|"""
    r"""YOUR_[A-Z][A-Z0-9_]*|your-api-key-here|"""
    r"""example-(?:api-key|token|secret|password)|"""
    r"""synthetic-key-[a-z]|"""
    r"""\*{3}REDACTED\*{3}|(?:token|secret|api-key|access-key|private-key|placeholder|fake|example)-\d+)\Z"""
)


_SHELL_SUBSTITUTION_RE = re.compile(r"^\$\(([^()\r\n]*)\)\Z")
_SHELL_CREDENTIAL_LITERAL_RE = re.compile(r"[A-Za-z0-9._~+/-]{16,}={0,2}")
# Command separators and pipes delimit commands even without surrounding spaces
# ("true;echo x", "true||echo x", "true|echo x"). Angle brackets stay word
# characters so "<your-password>" placeholders remain a single word.
_SHELL_OPERATOR_CHARS = ";|&"


def _is_shell_operator(token):
    return bool(token) and all(char in _SHELL_OPERATOR_CHARS for char in token)


def _shell_operator_tokens(expression):
    """Tokenize with control operators split off as their own tokens."""
    lexer = shlex.shlex(expression, posix=True, punctuation_chars=_SHELL_OPERATOR_CHARS)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _emits_literal_data(tokens, *, segmented):
    """True when an echo/printf command word emits a non-placeholder argument.

    In the segmented view an unquoted control operator ends the command. The
    plain view never trusts operator-looking words, which may be quoted data.
    """
    # These commands emit literal arguments, even short/low-entropy passwords.
    # Options belong only to the initial option position; a leading hyphen in
    # emitted data never makes that data safe.
    for index, word in enumerate(tokens):
        if segmented and _is_shell_operator(word):
            continue
        command = word.rsplit("/", 1)[-1]
        if command not in {"echo", "printf"}:
            continue
        arguments = []
        for token in tokens[index + 1 :]:
            if segmented and _is_shell_operator(token):
                break
            arguments.append(token)
        if command == "echo":
            while arguments and re.fullmatch(r"-[neE]+", arguments[0]):
                arguments = arguments[1:]
            # echo does not recognize -- as an end-of-options delimiter.
        else:
            if arguments and arguments[0] == "--":
                arguments = arguments[1:]
            if arguments and arguments[0] in {"%s", "%s\\n", "%b"}:
                arguments = arguments[1:]
        for argument in arguments:
            if _CREDENTIAL_PLACEHOLDER_RE.fullmatch(argument):
                continue
            return True
    return False


def _safe_shell_substitution(value):
    """Allow unevaluated expressions only when their words contain no credentials."""
    match = _SHELL_SUBSTITUTION_RE.fullmatch(value)
    if not match:
        return False
    expression = match.group(1)
    if any(pattern.search(expression) for _, pattern in DENYLIST):
        return False
    # A backtick opens a nested, evaluated substitution: never a placeholder.
    if "`" in expression:
        return False
    try:
        words = shlex.split(expression)
        segmented = _shell_operator_tokens(expression)
    except ValueError:
        return False
    for word in words:
        # Angle brackets cannot disguise embedded token-shaped material.
        if not word.startswith("<") and _CREDENTIAL_PLACEHOLDER_RE.fullmatch(word):
            continue
        if _SHELL_CREDENTIAL_LITERAL_RE.search(word):
            return False
    # Both views must be clean: plain words keep quoted operator characters as
    # data ("echo ';'"), while the segmented view exposes command words that are
    # attached to a separator ("true;echo -fixture"). Either finding fails closed.
    if _emits_literal_data(words, segmented=False) or _emits_literal_data(
        segmented, segmented=True
    ):
        return False
    return bool(words)


def _credential_key(key):
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    # Custom prefixes occur in env/config keys; match credential endings only.
    return (
        normalized in _CREDENTIAL_NAMES
        or normalized.endswith(
            (
                "token",
                "secret",
                "password",
                "passphrase",
                "apikey",
                "secretkey",
                "accesskey",
                "privatekey",
            )
        )
        # Wi-Fi and device keys (ppsk, wlanPsk, authkey, vwirekey). The x_* forms are
        # already held to the stricter x_field_hits placeholder rule.
        or (not str(key).startswith("x_") and normalized.endswith(("psk", "authkey", "vwirekey")))
        or (normalized.startswith("x") and normalized[1:] in _CREDENTIAL_NAMES)
    )


def voucher_code_hits(rel, parsed):
    """A hotspot voucher ``code`` is a guest credential: only all-zero codes may ship."""
    if "voucher" not in rel.lower():
        return []
    hits = []

    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).lower() == "code" and not isinstance(child, (dict, list, bool)):
                    text = str(child).strip()
                    if child is not None and set(text) - {"0", "-"} and _credential_value(text):
                        hits.append("voucher code is not an all-zero placeholder")
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(parsed)
    return hits


def _credential_value(value):
    if not isinstance(value, str):
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    value = value.strip()
    if value.startswith("Bearer "):
        value = value[7:].strip()
    if value in {"REDACTED", "xxxxxxxx"}:
        return False
    return bool(value) and not (
        _CREDENTIAL_PLACEHOLDER_RE.fullmatch(value) or _safe_shell_substitution(value)
    )


_FENCED_BLOCK_RE = re.compile(
    r"^ {0,3}(?:```|~~~)[^\n]*\n(.*?)^ {0,3}(?:```|~~~)[ \t]*$", re.M | re.S
)


def credential_hits(text):
    """Find credential fields in JSON/JSONL, TOML, YAML and env/text fixtures.

    Return categories only; neither keys nor sensitive values reach logs.
    The text fallback also handles configuration snippets in Markdown.
    """
    hits = []

    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                synthetic_cursor = (
                    key == "nextToken"
                    and isinstance(child, str)
                    and re.fullmatch(r"fixture-page-cursor-[0-9]{8,}", child) is not None
                )
                if _credential_key(key) and _credential_value(child) and not synthetic_cursor:
                    hits.append("credential-like field contains non-placeholder material")
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    try:
        walk(json.loads(text))
        return hits
    except (ValueError, TypeError):
        pass
    try:
        walk(tomllib.loads(text))
        return hits
    except tomllib.TOMLDecodeError:
        pass
    # Records embedded in prose or Markdown: a capture after a label ("Example: {...}"),
    # a pretty-printed record spanning lines, or a fenced block. Each is checked as a
    # structured document; the line checks below still see everything else.
    for record in iter_json_records(text):
        walk(record)
    for block in _FENCED_BLOCK_RE.findall(text):
        try:
            walk(tomllib.loads(block))
        except tomllib.TOMLDecodeError:
            pass
    lines = text.splitlines()
    for index, line in enumerate(lines):
        try:
            walk(json.loads(line))
            continue
        except (ValueError, TypeError):
            pass
        match = _CREDENTIAL_FIELD_RE.match(line)
        if not match or not _credential_key(match.group(1)):
            continue
        value = match.group(2).strip()
        if value in {"|", "|-", "|+", ">", ">-", ">+"}:
            # A YAML block scalar belongs to this field until indentation returns.
            indent = len(line) - len(line.lstrip())
            parts = []
            for following in lines[index + 1 :]:
                if following.strip() and len(following) - len(following.lstrip()) <= indent:
                    break
                parts.append(following.strip())
            value = " ".join(parts)
        else:
            value = value.removesuffix(",").strip()
            if value[:1] in {'"', "'"} and value[-1:] == value[:1]:
                value = value[1:-1]
            else:
                value = value.split(" #", 1)[0].strip()
            if value in {"null", "None", "~"}:
                continue
        if _credential_value(value):
            hits.append("credential-like field contains non-placeholder material")
    return hits


def inventory_build_version_line(rel, line):
    """The pinned Network CDN build is a release version, not an estate IP.

    Exempt only these three complete metadata records in this one inventory.
    Other keys, files, versions and addresses appended to a record stay scanned.
    CDN URLs must retain the upstream release path for reproducible provenance.
    """
    if rel != "tests/fixtures/private_api/inventory_network_11.0.81.json":
        return False
    cdn = "https://net-fe-static-assets.network-controller.svc.ui.com/release/11.0.81.0"
    return line.strip().removesuffix(",") in {
        '"build": "11.0.81.0"',
        f'"base_url": "{cdn}"',
        f'"entry": "{cdn}/unifi/react/js/swai.2a25194af20cf3b62663.js"',
    }


def scan_text(rel, text, recorded=None):
    """Every finding for one file's text (``rel`` is its repo-relative path).

    ``recorded`` forces the recorded-capture rules (the recorder runs this on its own
    output before it is committed); by default they apply under tests/fixtures/recorded/.
    Findings carry the path, line and category only, never a matched value.
    """
    if recorded is None:
        recorded = rel.startswith(RECORDED_DIR)
    findings = []
    for label in credential_hits(text):
        findings.append(f"{rel}: structured credential: {label}")
    try:
        json.loads(text)
        whole_json = True
    except (ValueError, TypeError):
        whole_json = False
    for parsed in iter_json_records(text):
        for label in json_identifier_hits(parsed, recorded):
            findings.append(f"{rel}: {label}")
        for label in x_field_hits(parsed) + serial_hits(parsed):
            findings.append(f"{rel}: {label}")
        for label in voucher_code_hits(rel, parsed):
            findings.append(f"{rel}: {label}")
        if recorded:
            for label in free_text_hits(parsed):
                findings.append(f"{rel}: {label}")
    # Fixture data only: example configs and the private-only .mcp.json (stripped from
    # the public tree) may name the private services they configure.
    check_names = rel.startswith(FORBIDDEN_SCOPE_PREFIXES) and not rel.startswith(
        FORBIDDEN_EXEMPT_PREFIXES
    )
    for lineno, line in enumerate(text.splitlines(), start=1):
        for label, pattern in DENYLIST:
            if pattern.search(line):
                findings.append(f"{rel}:{lineno}: {label}")
        for label in numeric_identifier_hits(line):
            findings.append(f"{rel}:{lineno}: {label}")
        if recorded:
            # The stricter recorded-capture rule (fake prefixes only) covers MACs.
            for label in recorded_identifier_hits(line):
                findings.append(f"{rel}:{lineno}: {label}")
        else:
            for label in mac_hits(line):
                findings.append(f"{rel}:{lineno}: {label}")
        for label in ipv6_hits(line, recorded):
            findings.append(f"{rel}:{lineno}: {label}")
        if not whole_json:
            for label in x_field_line_hits(line):
                findings.append(f"{rel}:{lineno}: {label}")
        if check_names:
            for label in estate_name_hits(line):
                findings.append(f"{rel}:{lineno}: {label}")
        if public_ip_hits(line) and not inventory_build_version_line(rel, line):
            findings.append(f"{rel}:{lineno}: public IP not in placeholder allowlist")
    return findings


def main() -> int:
    findings = []
    targets = iter_target_files()
    for path in targets:
        rel = path.relative_to(REPO_ROOT).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            findings.append(f"{rel}: unreadable ({exc})")
            continue
        findings.extend(scan_text(rel, text))
    object_id_targets = iter_object_id_target_files()
    for path in object_id_targets:
        rel = path.relative_to(REPO_ROOT).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            findings.append(f"{rel}: unreadable ({exc})")
            continue
        findings.extend(scan_object_ids(rel, text))

    print(f"Scanned {len(targets)} fixture/example-config file(s).")
    print(f"Scanned {len(object_id_targets)} public text file(s) for live ObjectIds.")
    if findings:
        print("FAIL: potential real secret/PII detected:")
        for finding in findings:
            print(f"  - {finding}")
        print(
            "\nFixtures and example configs must contain only synthetic or "
            "documented-placeholder values. Replace the flagged material."
        )
        return 1

    print("OK: no real secrets/PII found in fixtures or example configs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
