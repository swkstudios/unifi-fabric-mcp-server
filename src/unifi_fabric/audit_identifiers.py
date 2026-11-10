"""Optional pseudonymised identifiers in audit records (``UNIFI_AUDIT_HMAC_IDENTIFIERS``).

Off by default. When on, client MAC addresses and user identifiers in an audit record are
replaced by ``hmac:<32 hex>``: the first 128 bits of HMAC-SHA256 under the
per-installation key ``UNIFI_AUDIT_HMAC_KEY``. The same identifier always maps to the same
token within one installation, so records still correlate, and the clear value is never
written. The key is operator-provisioned; the server never generates, stores or logs it.

What is replaced, in every record field, in the JSON and text formats and on every sink:

* **MAC addresses** anywhere in a string value or object key, in the ``aa:bb:cc:dd:ee:ff``,
  ``aa-bb-cc-dd-ee-ff``, ``aabb.ccdd.eeff`` and URL-encoded ``aa%3Abb%3A...`` forms, in
  any letter case. A bare ``aabbccddeeff`` is replaced when it is a whole path segment or
  the value of a MAC-named field (``mac``, ``clientMac``, ``sta_mac`` ...). Every form of
  one address gives the same token.
* **User identifiers**: the value of a user-named field (``user``, ``user_id``,
  ``username``, ``admin_id``, ``email`` ...) and the path segment after ``user``,
  ``users``, ``admin`` or ``admins`` when it is an identifier (contains a digit or ``@``).

Free-text fields (``reason``, ``message``) are covered for MAC shapes only; a user
identifier in prose has no reliable shape. The HMAC input is domain-separated
(``unifi-fabric/audit-identifier/v1``), so a token never equals a Code Mode argument HMAC
made with the same key.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from .macs import MAC_IN_TEXT_RE, is_mac, normalize_mac

DOMAIN = b"unifi-fabric/audit-identifier/v1\x00"
PREFIX = "hmac:"
_TOKEN_HEX = 32
_MAX_DEPTH = 64

#: Field names (lower-cased, ``_`` and ``-`` removed) whose value is a user identifier.
USER_KEYS = frozenset(
    {
        "user",
        "userid",
        "username",
        "useremail",
        "admin",
        "adminid",
        "adminname",
        "email",
    }
)
#: Path segments after which an identifier-shaped segment is a user identifier.
USER_SEGMENTS = frozenset({"user", "users", "admin", "admins"})


def _norm_key(key: str) -> str:
    return key.lower().replace("_", "").replace("-", "")


def _mac_key(key: str) -> bool:
    k = _norm_key(key)
    return k in {"mac", "macs", "macaddress", "macaddresses"} or k.endswith("mac")


class IdentifierHasher:
    """Replaces client MACs and user identifiers in an audit record's fields."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("UNIFI_AUDIT_HMAC_KEY must provide 32 decoded bytes")
        self._key = key

    def __repr__(self) -> str:
        return "IdentifierHasher(<key hidden>)"

    def token(self, kind: str, value: str) -> str:
        digest = hmac.new(
            self._key, DOMAIN + kind.encode() + b"\x00" + value.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return PREFIX + digest[:_TOKEN_HEX]

    def mac_token(self, text: str) -> str:
        return self.token("mac", normalize_mac(text.replace("%3A", "").replace("%3a", "")))

    # -- strings
    def text(self, value: str) -> str:
        """Every separated MAC in ``value`` replaced."""
        if not value:
            return value
        return MAC_IN_TEXT_RE.sub(lambda m: self.mac_token(m.group()), value)

    def _mac_value(self, value: str) -> str:
        if is_mac(value):
            return self.mac_token(value)
        return self.text(value)

    def path(self, value: str) -> str:
        """A request path: MACs anywhere, bare MAC segments and user-id segments."""
        segments = value.split("/")
        out: list[str] = []
        previous = ""
        for segment in segments:
            if is_mac(segment):
                out.append(self.mac_token(segment))
            elif previous.lower() in USER_SEGMENTS and (
                any(c.isdigit() for c in segment) or "@" in segment
            ):
                out.append(self.token("user", segment))
            else:
                out.append(self.text(segment))
            previous = segment
        return "/".join(out)

    # -- structured values
    def value(self, obj: Any, depth: int = 0) -> Any:
        if depth > _MAX_DEPTH:
            return obj
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, list):
            return [self.value(v, depth + 1) for v in obj]
        if isinstance(obj, dict):
            out: dict[Any, Any] = {}
            for k, v in obj.items():
                key = self._mac_value(k) if isinstance(k, str) else k
                out[key] = self._field(str(k), v, depth + 1)
            return out
        return obj

    def _field(self, key: str, value: Any, depth: int) -> Any:
        if _norm_key(key) in USER_KEYS:
            if isinstance(value, str) and value:
                return self.token("user", value)
            if isinstance(value, int) and not isinstance(value, bool):
                return self.token("user", str(value))
        if _mac_key(key):
            if isinstance(value, str):
                return self._mac_value(value)
            if isinstance(value, list):
                return [self._mac_value(v) if isinstance(v, str) else v for v in value]
        return self.value(value, depth)

    def record_fields(self, fields: dict[str, Any]) -> dict[str, Any]:
        """The fields of one audit record with identifiers replaced (``path`` is a
        request path; every other field is structured or free text)."""
        out: dict[str, Any] = {}
        for k, v in fields.items():
            if k == "path" and isinstance(v, str):
                out[k] = self.path(v)
            else:
                out[k] = self._field(k, v, 0)
        return out
