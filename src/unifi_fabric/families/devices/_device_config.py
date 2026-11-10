"""Reusable full-object device PUT and affirmative read-after verification core."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from ...client import (
    UniFiClient,
    UniFiConnectionError,
    is_dry_run_preview,
    strip_additive_keys,
    upstream_error_text,
)
from ...config import APIKeyConfig
from ...redaction import drop_and_note_masked_fields
from ...shared_shapes._keys import with_context
from ...shared_shapes._results import leaf_equal
from ...write_body import require_unmasked_fields


def require_classic_success(response: Any, path: str) -> None:
    """A Classic HTTP 200 with meta.rc=error is not a successful state read."""
    if not isinstance(response, dict):
        raise UniFiConnectionError(
            f"Unexpected Classic response at {path}: {upstream_error_text(response)}"
        )
    meta = response.get("meta")
    if not isinstance(meta, dict) or meta.get("rc") != "ok":
        raise UniFiConnectionError(
            f"Classic operation failed at {path}: {upstream_error_text(response)}"
        )


async def update_device_config(
    client: UniFiClient,
    path: str,
    before: Any,
    desired: Any,
    body: dict[str, Any],
    read_after: Callable[[], Awaitable[tuple[dict[str, Any], Any, dict[str, Any]]]],
    diff: Callable[[Any, Any], dict[str, Any]],
    /,
    *,
    key: APIKeyConfig | None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """PUT once, or skip an identical PUT; both paths require a new successful read.

    Callers own resolution, capability checks and merging the entire writable object.
    read_after must reject failed envelopes and returns (raw response, config, views).
    This core also serves full-device updates without knowing the radio schema.
    """
    requested = diff(before, desired)
    base = {"readBefore": before, "_diff": requested}
    if dry_run or client.dry_run:
        body = strip_additive_keys(body)
        require_unmasked_fields(body, "PUT body")
        body = drop_and_note_masked_fields(body)
        client._audit_write("PUT", path, "dry_run", None, body=body)
        configs = client._key_configs()
        preview_key = key or (configs[0] if configs else None)
        return {
            **client._dry_run_response("PUT", path, body, key=preview_key).json(),
            "diff": requested,
            **base,
            "changed": None,
            "noOp": None,
            "_noOp": None,
            "_verified": None,
        }
    write_result: dict[str, Any] = {}
    if not leaf_equal(before, desired):
        response = await client.put(path, key=key, json=body)
        if is_dry_run_preview(response):
            return with_context(
                response,
                {
                    "diff": requested,
                    **base,
                    "changed": None,
                    "noOp": None,
                    "_noOp": None,
                    "_verified": None,
                },
            )
        if isinstance(response, dict) and "meta" in response:
            require_classic_success(response, path)
        write_result["response"] = response
    try:
        after_response, after, views = await read_after()
        changed = diff(before, after)
    except Exception as exc:
        return {
            **base,
            **write_result,
            "changed": None,
            "noOp": None,
            "_noOp": None,
            "_verified": None,
            "readAfterError": str(exc),
        }
    return {
        **base,
        **write_result,
        **views,
        "readAfter": after,
        "changed": changed,
        "noOp": leaf_equal(before, after),
        "_noOp": leaf_equal(before, after),
        "_verified": leaf_equal(desired, after),
        "_readAfterResponse": after_response,
    }
