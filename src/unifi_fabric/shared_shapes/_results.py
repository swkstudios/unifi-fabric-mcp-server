"""Shared result shapes for write tools (not a tool module)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from ..client import (
    DRY_RUN_MESSAGE,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    strip_additive_keys,
)
from ._keys import with_context


def deletion_readback_ids(rows: list[Any], *fields: str) -> set[str]:
    """Identities from a complete deletion readback, or an unverified-shape error.

    A row without an identity cannot establish that the target is absent. This
    validates only post-write evidence and never prevents the upstream write.
    """
    ids: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise UniFiConnectionError(
                f"Deletion readback row {index} has no usable identity "
                f"({', '.join(fields)}): got {describe_shape(row)}"
            )
        usable: set[str] = set()
        for field in fields:
            value = row.get(field)
            if isinstance(value, str) and value.strip():
                usable.add(value)
        if not usable:
            raise UniFiConnectionError(
                f"Deletion readback row {index} has no usable identity "
                f"({', '.join(fields)}): got {describe_shape(row)}"
            )
        ids.update(usable)
    return ids


def deletion_result(message: str, response: Any) -> dict[str, Any]:
    """Result of a delete: a confirmation plus the upstream response body, verbatim.

    ``response`` is whatever the upstream returned for the DELETE (decoded JSON, raw
    text, or ``None`` when it sent no body) - never dropped, so a body that carries
    information (for example how many vouchers a bulk delete removed) reaches the caller.

    Under ``dry-run policy`` the DELETE was never sent and ``response`` is the client's
    dry-run preview: the result is then ``{status: "dry_run", deleted: false, message,
    response}`` with the preview under ``response`` and the dry-run message, never
    ``deleted: true`` or the would-be confirmation (nothing was deleted).
    """
    if is_dry_run_preview(response):
        return {
            "status": "dry_run",
            "deleted": False,
            "message": DRY_RUN_MESSAGE,
            "response": response,
        }
    return {"deleted": True, "message": message, "response": response}


def dry_run_or_verbatim(response: Any) -> Any:
    """A verbatim write result, or ``{status: "dry_run", response}`` under ``dry-run policy``.

    Used by the hotspot operator writes (``create_hotspot_operator``,
    ``update_hotspot_operator``). A write whose result is the upstream body verbatim
    returns that body unchanged. Under dry-run nothing was sent and ``response`` is the
    client's preview: the result is then ``{status: "dry_run", response}``, the shape the
    Protect writes also use.

    This is not the shape of the other Network writes: ``update_setting``, the
    port-profile writes and every other Network create/update/action return the client's
    bare preview ``{status: "dry_run", dryRun: true, sent: false, message, preview: {method, path,
    params (query parameters), body}}`` in place of the upstream body. Deletes use
    :func:`deletion_result`, ``forget_device`` with a list returns
    ``{status, byMac, errors}``, and Mobility and Carrier Fabric writes add their
    ``device`` / ``subscriber`` key (see the CHANGELOG dry-run entry).
    """
    if is_dry_run_preview(response):
        return {"status": "dry_run", "response": response}
    return response


#: Absent read-back fields are distinct from an explicitly returned JSON null.
MISSING: Any = object()


# Pinned response schemas omit these unset values instead of returning JSON null.
# serviceAddress is nullable in SubscriberCreate/Patch, suspendReason is cleared by
# resume, and wifi_experience is nullable but omitted for wired DeviceClient records.
# Scope exceptions to their schema/path; identical field names elsewhere stay strict.
OMITTED_NULL_FIELDS: dict[tuple[str, str], frozenset[tuple[str, ...]]] = {
    ("carrier-fabric-1.0.0.json", "Subscriber"): frozenset(
        {("serviceAddress",), ("suspendReason",)}
    ),
    ("mobility-1.0.0.json", "DeviceClient"): frozenset({("wifi_experience",)}),
}


def response_field(record: dict[str, Any], wire: str, *, spec: str, schema: str) -> Any:
    """Read a field using its pinned omission contract; otherwise retain MISSING."""
    value = record.get(wire, MISSING)
    if value is MISSING and (wire,) in OMITTED_NULL_FIELDS.get((spec, schema), ()):
        return None
    return value


def requested_leaves_match(
    requested: Any,
    actual: Any,
    *,
    spec: str = "",
    schema: str = "",
    _path: tuple[str, ...] = (),
) -> bool:
    """Compare requested partial leaves, using only documented schema omissions.

    Nested objects recurse without comparing unrequested siblings. Missing differs
    from explicit null, except at the exact spec/schema/path listed above. Lists
    and scalars use type-strict leaf equality, including bool versus int. The same
    comparison serves verification and no-op checks; unknown fields stay strict.
    """
    if isinstance(requested, dict):
        if not isinstance(actual, dict):
            return False
        omitted = OMITTED_NULL_FIELDS.get((spec, schema), ())
        for key, value in requested.items():
            path = (*_path, key)
            if key not in actual:
                if value is None and path in omitted:
                    continue
                return False
            if not requested_leaves_match(value, actual[key], spec=spec, schema=schema, _path=path):
                return False
        return True
    return leaf_equal(requested, actual)


def leaf_equal(a: Any, b: Any) -> bool:
    """``a == b``, except that a ``bool`` only equals a ``bool``, at any depth.

    Python's ``True == 1`` / ``False == 0`` (and ``1.0 == True``) would make a write of
    ``1`` over ``true`` look already applied. Lists compare element by element and
    objects key by key (whole-value, as a leaf), with the same rule.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a is b
    if isinstance(a, list | tuple) and isinstance(b, list | tuple):
        return len(a) == len(b) and all(leaf_equal(x, y) for x, y in zip(a, b, strict=True))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(leaf_equal(v, b[k]) for k, v in a.items())
    return bool(a == b)


#: The additive verification verdict on a result that IS the upstream body
#: (``update_setting``): true, false, or null when the read-after could not confirm it.
VERIFIED_KEY = "_verified"
#: The requested leaves a read-after found changed, but not to the requested value.
UNVERIFIED_FIELDS_KEY = "_unverifiedFields"
#: The result key that carries why a read-after failed after an applied write.
READ_AFTER_ERROR_KEY = "readAfterError"
#: The same report on a result that IS the upstream body (a Classic envelope, a created
#: object): an additive ``_`` key, so the upstream body stays verbatim (pass-through).
ADDITIVE_READ_AFTER_ERROR_KEY = "_" + READ_AFTER_ERROR_KEY


async def safe_read_after[T](read: Callable[[], Awaitable[T]]) -> tuple[T | None, str | None]:
    """Run the read-after of a write that has ALREADY been applied; never raise.

    Returns ``(body, None)`` on success, or ``(None, "Type: reason")`` when the read
    fails (an HTTP error, a 429, a transport error or an unexpected shape). The write
    happened, so a failing re-read must never turn into a tool error: the caller reports
    the write as done with ``verified`` unknown (``None``) and the reason under
    :data:`READ_AFTER_ERROR_KEY`. Every write tool that reads after it writes routes its
    read-after through here (the connector relay included).
    """
    try:
        return await read(), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def with_read_after_error(
    result: dict[str, Any], error: str | None, *, additive: bool = False
) -> dict[str, Any]:
    """``result`` plus ``readAfterError`` when the read-after failed (else unchanged).

    ``additive=True`` for a result that is the upstream body itself: the report is the
    additive ``_readAfterError`` key, so the body stays verbatim.
    """
    if error is not None:
        if additive:
            return with_context(result, {ADDITIVE_READ_AFTER_ERROR_KEY: error})
        result[READ_AFTER_ERROR_KEY] = error
    return result


def read_after_verdict[V](
    after: Any, error: str | None, check: Callable[[dict[str, Any]], V]
) -> tuple[V | None, str | None]:
    """The verification verdict of an applied write from its read-after, never raised.

    The one rule every verifying write follows (Build rules 1 and 11): a write is
    reported verified only when a read-after confirms it. The verdict is unknown
    (``None``) with the reason, never ``True`` and never a raised error, when:

    - the read-after failed (``error`` is passed through unchanged);
    - it returned no object, or something other than an object (an unexpected shape);
    - ``check`` raised while comparing it (an envelope or field that cannot be matched).

    Otherwise the verdict is ``check(after)`` with ``after`` stripped of the additive
    ``_``-prefixed top-level keys this server adds (``_id`` is a real field and is kept).
    ``check`` returns a bool for a single verdict, or a per-field map for the tools that
    report one; it must compare type-strictly (:func:`leaf_equal`). The caller keeps the
    write response verbatim beside the verdict and reports the reason under
    :data:`READ_AFTER_ERROR_KEY` (:func:`with_read_after_error`).
    """
    if error is not None:
        return None, error
    if not isinstance(after, dict):
        return None, (
            f"Unexpected read-after shape: expected an object, got {describe_shape(after)}; "
            "the write was sent but could not be verified"
        )
    try:
        return check(strip_additive_keys(after)), None
    except Exception as exc:
        return None, f"Read-after could not be compared: {type(exc).__name__}: {exc}"


def requested_leaves_verdict(
    requested: dict[str, Any],
    after: Any,
    error: str | None,
    *,
    spec: str = "",
    schema: str = "",
) -> tuple[bool | None, str | None]:
    """:func:`read_after_verdict` over every requested leaf (:func:`requested_leaves_match`).

    ``True`` only when every requested leaf is in the read-after with the requested
    value, type-strict (``True`` is not ``1``); a missing leaf or a different value is
    ``False``; unrequested siblings are never compared. The additive ``_`` keys are
    stripped from the request too, so a read result fed back in compares only the fields
    that were written.
    """
    wanted = strip_additive_keys(requested)
    return read_after_verdict(
        after,
        error,
        lambda actual: requested_leaves_match(wanted, actual, spec=spec, schema=schema),
    )


def short_circuit_no_op(client: Any, already_applied: bool) -> bool:
    """Whether a verifying write may answer "no-op" without writing.

    Only when the change is already applied AND opt-in ``dry-run policy`` is off. Under
    dry-run the write is always issued to the client's preview, so the tool returns
    ``status: "dry_run"`` with the preview of what it would send, already applied or not.
    """
    return already_applied and getattr(client, "dry_run", False) is not True
