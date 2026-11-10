"""Shared synthetic-secret corpus for the secrecy tests.

Every value is built at run time as ``synth-<tag>-<uuid4>`` (never a literal), so no
secret-shaped string sits in the repository and a fresh, unguessable value is used on
every run. ``<tag>`` names the category, so a failing assertion says what leaked.

This module is owned by the diagnostic-bundle tests. ``SECRET_SETTINGS`` lists every
secret-bearing setting name, ``CATEGORIES`` adds the non-secret-but-private material a
sanitized output must also never carry (labels, URLs, paths, hosts, helper arguments,
upstream error content, trace and protocol identifiers). The credential-provider and
trace-export secrecy tests switch to this corpus when they merge after the diagnostic
bundle branch, instead of keeping private sentinel helpers of their own.

``build_corpus`` returns a new set of values on each call; build one per test. The one
exception to the ``synth-`` shape is the audit HMAC key, whose setting demands canonical
base64url of 32 random bytes.
"""

from __future__ import annotations

import secrets
import uuid

#: Every setting that holds a secret value: environment name -> corpus category.
SECRET_SETTINGS: dict[str, str] = {
    "UNIFI_API_KEY": "key_single",
    "UNIFI_API_KEYS": "key_alpha",
    "UNIFI_AUDIT_HMAC_KEY": "hmac",
    "UNIFI_AUDIT_CHAIN_KEY": "chain_key",
    "MCP_BEARER_TOKEN": "bearer",
    "MCP_TLS_KEY_PASSWORD": "tls_password",
}

#: Credential-provider settings: environment name -> corpus category. The setting is
#: itself secret-adjacent (a path or helper command), reported only as set or unset.
PROVIDER_SETTINGS: dict[str, str] = {
    "UNIFI_API_KEY_FILE": "key_file_path",
    "UNIFI_API_KEYS_FILE": "keys_file_path",
    "UNIFI_API_KEY_COMMAND": "key_helper_argv",
    "UNIFI_API_KEYS_COMMAND": "keys_helper_argv",
}

#: Every corpus category (one fresh value each).
CATEGORIES: tuple[str, ...] = (
    *SECRET_SETTINGS.values(),
    *PROVIDER_SETTINGS.values(),
    "key_beta",
    "label_alpha",
    "label_beta",
    "unrelated_env",
    "url_secret",
    "url_host",
    "audit_path",
    "error_body",
    "echoed_header",
    "nested_error",
    "allowed_host",
    "key_file_content",
    "unknown_method",
    "unknown_tool",
    "unknown_prompt",
    "resource_uri",
    "tracestate",
)


def synth(tag: str) -> str:
    """One fresh synthetic value for ``tag``: ``synth-<tag>-<uuid4>``."""
    return f"synth-{tag}-{uuid.uuid4()}"


def hex_marker(nbytes: int = 12) -> str:
    """A fresh random hex marker, for tests that need an unguessable fragment."""
    return secrets.token_hex(nbytes)


def build_corpus() -> dict[str, str]:
    """A fresh value for every category in :data:`CATEGORIES`."""
    corpus = {category: synth(category.replace("_", "")) for category in CATEGORIES}
    # The audit HMAC key must be canonical unpadded base64url of 32 random bytes, so it
    # cannot carry the ``synth-<tag>-`` prefix; it is still fresh random bytes per build.
    corpus["hmac"] = secrets.token_urlsafe(32)
    # The audit hash-chain key has the same canonical form (and must differ from it).
    corpus["chain_key"] = secrets.token_urlsafe(32)
    return corpus
