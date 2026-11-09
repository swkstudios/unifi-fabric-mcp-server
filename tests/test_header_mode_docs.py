"""Header key mode and the request policy headers are documented where operators look.

The header names, key modes, refusal codes, the startup token and the credential-cache
bound are read from the code, so a new header, mode or code fails here until the public
configuration reference names it, and the trust-model pages (security policy, privacy
policy, OAuth guide, MSP guide) cannot keep describing a server that only ever uses its
configured keys.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from unifi_fabric import config
from unifi_fabric import header_credentials as hc
from unifi_fabric import request_policy as rp

ROOT = Path(__file__).resolve().parent.parent
CONFIGURATION = ROOT / "docs" / "CONFIGURATION.md"
SECURITY = ROOT / ".github" / "SECURITY.md"
PRIVACY = ROOT / "PRIVACY.md"
AUTH_OAUTH = ROOT / "docs" / "AUTH-OAUTH.md"
MSP = ROOT / "docs" / "MSP.md"
CHATGPT = ROOT / "docs" / "CHATGPT.md"
AUTH_TLS = ROOT / "docs" / "AUTH-TLS.md"

#: Every request header the server reads for credentials or policy.
HEADERS = (hc.API_KEY_HEADER, *hc.POLICY_HEADERS)

#: Every refusal code a header can produce before any console call.
CODES = (
    hc.INVALID_API_KEY_HEADER,
    hc.INVALID_POLICY_HEADER,
    hc.MISSING_API_KEY_HEADER,
    hc.KEY_LABEL_NOT_ALLOWED,
    hc.CREDENTIAL_CACHE_SATURATED,
    rp.TOOL_NOT_EXPOSED,
    rp.WRITE_DENIED,
)

HEADER_MODE_SETTING = f"{hc.KEY_MODE_ENV}={hc.HEADER_MODE}"
KEY_MODE_LINK = "CONFIGURATION.md#header-key-mode-unifi_key_mode"
POLICY_LINK = "CONFIGURATION.md#request-policy-headers"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _mentions(text: str, needle: str) -> bool:
    """HTTP header names compare case-insensitively; everything else exactly."""
    if needle.lower().startswith("x-unifi-"):
        return needle.lower() in text.lower()
    return needle in text


def test_configuration_documents_key_modes_headers_and_codes() -> None:
    text = _text(CONFIGURATION)
    for mode in hc.KEY_MODES:
        assert f"`{hc.KEY_MODE_ENV}={mode}`" in text, f"CONFIGURATION.md: key mode {mode!r}"
    for header in HEADERS:
        pattern = rf"`{re.escape(header)}(?::[^`]*)?`"
        assert re.search(pattern, text, re.IGNORECASE), f"CONFIGURATION.md: header {header}"
    for code in CODES:
        assert f"`{code}`" in text, f"CONFIGURATION.md: refusal code {code}"
    assert f"`startup:{hc.KEY_MODE_ENV}`" in text
    assert f"{hc.MAX_CREDENTIAL_IDENTITIES} key identities" in text
    assert "## Header key mode (`UNIFI_KEY_MODE`)" in text
    assert "## Request policy headers" in text


def test_every_direct_setting_has_a_configuration_row() -> None:
    """Settings read outside the settings models never reach the generated table."""
    text = _text(CONFIGURATION)
    for name in sorted(config._DIRECT_SETTINGS):
        assert f"\n| `{name}` |" in text, f"CONFIGURATION.md: no table row for {name}"


@pytest.mark.parametrize(
    ("path", "required"),
    [
        (
            SECURITY,
            (HEADER_MODE_SETTING, "MCP_TLS_MODE", str(hc.MAX_CREDENTIAL_IDENTITIES), *HEADERS),
        ),
        (PRIVACY, (HEADER_MODE_SETTING, str(hc.MAX_CREDENTIAL_IDENTITIES), hc.API_KEY_HEADER)),
        (AUTH_OAUTH, (HEADER_MODE_SETTING, hc.POLICY_HEADERS[0], KEY_MODE_LINK, POLICY_LINK)),
        (MSP, (HEADER_MODE_SETTING, hc.POLICY_HEADERS[0], KEY_MODE_LINK, POLICY_LINK)),
        (CHATGPT, (HEADER_MODE_SETTING, KEY_MODE_LINK)),
        (AUTH_TLS, (HEADER_MODE_SETTING, hc.API_KEY_HEADER, KEY_MODE_LINK)),
    ],
    ids=["security", "privacy", "auth-oauth", "msp", "chatgpt", "auth-tls"],
)
def test_trust_model_pages_cover_header_mode(path: Path, required: tuple[str, ...]) -> None:
    text = _text(path)
    for needle in required:
        assert _mentions(text, needle), f"{path.relative_to(ROOT)}: does not mention {needle}"


def test_no_page_claims_every_caller_uses_the_configured_keys() -> None:
    """The pre-header-mode wording is false once ``UNIFI_KEY_MODE=header`` is set."""
    stale = "All admitted clients use the deployment's configured UniFi"
    for path in (SECURITY, AUTH_OAUTH, CHATGPT):
        assert stale not in " ".join(_text(path).split()), f"{path.relative_to(ROOT)}"
