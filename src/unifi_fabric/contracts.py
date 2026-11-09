"""Shared contract types for registration, policy and per-request credentials.

These four types are the contract that the catalog, the header-credential ingress,
the policy evaluator, the request-policy hook, the audit stream and Code Mode use:

* :class:`Dependencies` -- the ``(client, registry)`` pair that tool logic receives,
  returned by the zero-argument provider passed to ``register_tool``.
* :class:`EffectivePolicy` -- the net write/family/exclusion policy that the policy
  evaluator (:mod:`unifi_fabric.policy`) fills, with :func:`canonical_policy_json` and
  :func:`policy_digest`.
* :class:`CredentialHandle` -- an opaque, identity-compared credential reference that
  the header-credential ingress issues. It never carries key material.
* :class:`RequestContext` -- the per-request context the header-credential ingress fills, with one
  derivation method, :meth:`RequestContext.child`.

Any new field, type change or second derivation method changes the contract for
every consumer. ``tests/test_contract_c0.py`` pins the
exact field sets.

``TOOLS_LIST_POLICY_ERROR_CODE`` is the JSON-RPC error code that a ``tools/list``
request carrying a malformed policy header (``invalid_policy_header``) receives.
``tests/test_tightening_contract.py`` asserts its value.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from .client import UniFiClient
    from .registry import Registry

__all__ = [
    "META_FAMILY_ID",
    "TOOLS_LIST_POLICY_ERROR_CODE",
    "WRITE_POLICIES",
    "CredentialHandle",
    "Dependencies",
    "EffectivePolicy",
    "RequestContext",
    "WritePolicy",
    "canonical_policy_json",
    "credentials_index",
    "policy_digest",
    "require_selected_credential",
]

#: JSON-RPC error code for a ``tools/list`` request whose policy header is malformed
#: (refusal code ``invalid_policy_header``). -32602 is JSON-RPC "Invalid params".
TOOLS_LIST_POLICY_ERROR_CODE: int = -32602

#: The reserved family ID of the six meta tools. It is never an exposed family.
META_FAMILY_ID = "meta"

WritePolicy = Literal["allow", "dry-run", "deny"]
WRITE_POLICIES: tuple[str, ...] = ("allow", "dry-run", "deny")
_WRITE_EXCEPTION_VALUES = frozenset({"deny", "dry-run"})
_FINGERPRINT = re.compile(r"[0-9a-f]{8}")


@dataclass(frozen=True, slots=True)
class Dependencies:
    """The client and registry that tool logic receives (baseline ``_require()``)."""

    client: UniFiClient
    registry: Registry


@dataclass(frozen=True, slots=True)
class EffectivePolicy:
    """The net policy for one request; the policy evaluator fills it.

    ``write_policy`` is the strictest of the operator and request values;
    ``write_exceptions`` holds the ``(target, "deny" | "dry-run")`` pairs of
    ``UNIFI_WRITE_EXCEPTIONS`` sorted by target; ``exposed_families`` holds frozen family
    IDs (never ``meta``) net of every ``family:`` exclusion; ``exclusions`` is the raw
    union of the operator and request exclusion tokens.
    """

    write_policy: WritePolicy
    write_exceptions: tuple[tuple[str, str], ...]
    exposed_families: frozenset[str]
    exclusions: frozenset[str]

    def __post_init__(self) -> None:
        if self.write_policy not in WRITE_POLICIES:
            raise ValueError(f"write_policy must be one of {WRITE_POLICIES}")
        if not isinstance(self.write_exceptions, tuple):
            raise TypeError("write_exceptions must be a tuple of (target, value) pairs")
        for pair in self.write_exceptions:
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or not all(isinstance(part, str) for part in pair)
            ):
                raise TypeError("each write exception must be a (target, value) str pair")
            if pair[1] not in _WRITE_EXCEPTION_VALUES:
                raise ValueError("a write exception value must be 'deny' or 'dry-run'")
        targets = [target for target, _ in self.write_exceptions]
        if targets != sorted(targets):
            raise ValueError("write_exceptions must be sorted by target")
        if not isinstance(self.exposed_families, frozenset) or not isinstance(
            self.exclusions, frozenset
        ):
            raise TypeError("exposed_families and exclusions must be frozensets")
        if META_FAMILY_ID in self.exposed_families:
            raise ValueError("the meta family is never an exposed family")


def canonical_policy_json(policy: EffectivePolicy) -> str:
    """Return the canonical JSON serialization of ``policy``.

    A fixture's ``expected.effective_policy`` is exactly this object, and
    :func:`policy_digest` hashes this string.
    """
    obj = {
        "write_policy": policy.write_policy,
        "write_exceptions": [[target, value] for target, value in policy.write_exceptions],
        "exposed_families": sorted(policy.exposed_families),
        "exclusions": sorted(policy.exclusions),
    }
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def policy_digest(policy: EffectivePolicy) -> str:
    """Lowercase SHA256 hex of the UTF-8 canonical policy JSON (the header-mode cache digest)."""
    return hashlib.sha256(canonical_policy_json(policy).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True, eq=False)
class CredentialHandle:
    """An opaque credential reference the header-credential ingress issues.

    Equality and hashing are by object identity: two handles with the same label and
    fingerprint are different handles. Only ``label`` and the 8-hex ``key_fingerprint``
    are exposed; the ingress keeps the key material in its own transport, keyed by
    handle identity.
    """

    label: str
    key_fingerprint: str

    def __post_init__(self) -> None:
        if not isinstance(self.label, str) or not self.label:
            raise ValueError("a credential label must be a non-empty string")
        if not isinstance(self.key_fingerprint, str) or not _FINGERPRINT.fullmatch(
            self.key_fingerprint
        ):
            raise ValueError("key_fingerprint must be 8 lowercase hex characters")


def credentials_index(
    credentials: tuple[CredentialHandle, ...],
) -> MappingProxyType[str, CredentialHandle]:
    """Build the read-only ``credentials_by_label`` mapping for ``credentials``."""
    index: dict[str, CredentialHandle] = {}
    for handle in credentials:
        if handle.label in index:
            raise ValueError(f"duplicate credential label {handle.label!r}")
        index[handle.label] = handle
    return MappingProxyType(index)


def _is_member(handle: CredentialHandle, credentials: tuple[CredentialHandle, ...]) -> bool:
    return any(member is handle for member in credentials)


@dataclass(frozen=True, slots=True)
class RequestContext:
    """The per-request context. The header-credential ingress fills it; consumers only read it.

    ``child()`` is the only way to build a child call's context. RequestContext is
    never hashed or used as a cache key.
    """

    present_arguments: frozenset[str]
    credentials: tuple[CredentialHandle, ...]
    credentials_by_label: Mapping[str, CredentialHandle]
    selected_credential: CredentialHandle | None
    effective_policy: EffectivePolicy
    request_id: str
    ignored_loosening: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.credentials, tuple) or not self.credentials:
            raise ValueError("credentials must be a non-empty tuple")
        if not isinstance(self.credentials_by_label, MappingProxyType):
            raise TypeError("credentials_by_label must be a types.MappingProxyType")
        if list(self.credentials_by_label) != [h.label for h in self.credentials] or any(
            self.credentials_by_label[h.label] is not h for h in self.credentials
        ):
            raise ValueError("credentials_by_label must map each label to its handle")
        if self.selected_credential is not None and not _is_member(
            self.selected_credential, self.credentials
        ):
            raise ValueError("selected_credential is not a member of credentials")

    def child(
        self,
        raw_arguments: Mapping[str, Any],
        *,
        selected_credential: CredentialHandle | None = None,
    ) -> RequestContext:
        """Derive a child call's context.

        Keeps credentials, credentials_by_label, effective_policy, request_id and
        ignored_loosening; builds present_arguments from ``raw_arguments``; sets
        selected_credential to the given handle, or keeps the parent's when the keyword
        is omitted. A handle that is not, by identity, a member of credentials raises
        ``ValueError``.
        """
        selected = self.selected_credential if selected_credential is None else selected_credential
        if selected is not None and not _is_member(selected, self.credentials):
            raise ValueError("selected_credential is not a member of this request's credentials")
        return replace(
            self,
            present_arguments=frozenset(raw_arguments),
            selected_credential=selected,
        )


def require_selected_credential(context: RequestContext) -> CredentialHandle:
    """Return the handle an upstream call uses; fail before the call when none is set.

    An upstream call with ``selected_credential`` None is a programming error.
    """
    handle = context.selected_credential
    if handle is None:
        raise RuntimeError(
            "upstream call without a selected credential: derive the call's context "
            "with RequestContext.child(..., selected_credential=...)"
        )
    return handle
