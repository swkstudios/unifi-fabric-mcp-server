"""Opaque string transport for pagination state, preserving public input schemas."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

_PREFIX = "ufpg1:"


def encode_continuation(state: dict[str, Any]) -> str:
    """Encode native cursor and physical-size state in a versioned opaque string."""
    payload = json.dumps({"v": 1, "state": state}, separators=(",", ":"), sort_keys=True)
    encoded = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    return _PREFIX + encoded


def decode_continuation(token: str | None) -> str | dict[str, Any] | None:
    """Decode our token; leave a plain native upstream token unchanged.

    This validation is local and must run before resolving or requesting upstream
    resources. The opaque payload is pagination state, never authentication data.
    """
    if token is None:
        return None
    message = (
        "Malformed _continuation token: reuse the complete returned ufpg1: string "
        "as page_token or cursor, or supply a plain native upstream token"
    )
    if not isinstance(token, str):
        raise ValueError(message)
    if not token.startswith(_PREFIX):
        return token
    encoded = token[len(_PREFIX) :]
    try:
        if not encoded or any(
            char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for char in encoded
        ):
            raise ValueError(message)
        payload = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
        value = json.loads(payload)
    except (ValueError, UnicodeDecodeError, binascii.Error, RecursionError) as exc:
        raise ValueError(message) from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"v", "state"}
        or type(value["v"]) is not int
        or value["v"] != 1
        or not isinstance(value["state"], dict)
    ):
        raise ValueError(message)
    return value["state"]
