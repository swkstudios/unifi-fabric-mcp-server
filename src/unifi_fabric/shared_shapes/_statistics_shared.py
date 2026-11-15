"""Names the statistics family's ``statistics`` shares with other families.

Used by site_manager, statistics. Moved verbatim by ``scripts/move_family.py`` from
``families/statistics/statistics.py``, which import them back where they use them, so their own code
and import paths stay.
"""

from __future__ import annotations

from typing import Any

from ..shared_shapes._keys import with_context


def health_summary(response: Any) -> dict[str, Any] | None:
    """A compact digest of a Classic ``/stat/health`` body, or ``None`` when it has none.

    ``{subsystems: {subsystem: status}, notOk: [subsystem...], allOk}`` from the ``data[]``
    records that carry a string ``subsystem`` (first record wins for a repeated name);
    ``status`` is copied verbatim (``None`` when a record has none) and ``notOk`` lists, in
    upstream order, every subsystem whose status is not exactly ``"ok"``. It is derived
    from the body only: the body itself is never changed.
    """
    data = response.get("data") if isinstance(response, dict) else None
    if not isinstance(data, list):
        return None
    statuses: dict[str, Any] = {}
    for record in data:
        if isinstance(record, dict) and isinstance(record.get("subsystem"), str):
            statuses.setdefault(record["subsystem"], record.get("status"))
    if not statuses:
        return None
    not_ok = [name for name, status in statuses.items() if status != "ok"]
    return {"subsystems": statuses, "notOk": not_ok, "allOk": not not_ok}


def with_health_summary(response: Any) -> Any:
    """``response`` plus the additive ``_healthSummary`` digest (unchanged when it has none)."""
    summary = health_summary(response)
    if summary is None or not isinstance(response, dict):
        return response
    return with_context(response, {"_healthSummary": summary})
