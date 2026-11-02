"""One rule for matching a caller selector against upstream ids and names.

**Ids.** :func:`same_id` compares an id the caller passed with one the upstream reports.
An id made only of hexadecimal digits and the separators ``-`` / ``:`` (a UUID, a Fabric
ObjectId, a console id) is matched case-insensitively -- ``6F1C...`` and ``6f1c...`` are
one UUID; any other id is matched exactly. A resolver returns and sends the upstream
form, never the caller's spelling: a write addresses the record it matched by the id the
upstream reported (the URL segment, and any identity field of the body that names the
same record, :func:`with_upstream_id`), never by the id the caller typed.

**Names.** :func:`name_keys` gives the match keys of a name, tried in tiers (the first
tier with a match wins, so an exact match always beats a looser one): the exact name;
the NFC-normalized, casefolded name (a composed ``Café`` matches a decomposed upstream
one, and case does not matter); then with surrounding whitespace stripped, case kept
first and casefolded last. The stripped tiers let an upstream name that carries edge
whitespace (a console named ``"Lab  "``, a WAN named ``"Fiber - "``) be selected by its
visible text. A caller's own padding is still refused by the selector rule for console,
site, key-label and id selectors (:mod:`unifi_fabric.selector_syntax`).

Dependency-free so the registry, the selector checks and every tool module share it.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Callable, Iterable, Sequence
from typing import Any

#: The characters of an id the upstream mints from hexadecimal digits (UUID, ObjectId,
#: console id).
_HEX_ID_CHARS = frozenset("0123456789abcdefABCDEF:-")


def _is_hex_id(value: str) -> bool:
    return bool(value) and all(ch in _HEX_ID_CHARS for ch in value)


#: Number of name tiers :func:`name_keys` yields.
NAME_TIERS = 4


def same_id(wanted: object, actual: object) -> bool:
    """True when the caller's ``wanted`` id names the upstream ``actual`` id.

    Both must be non-empty strings: exact equality, or -- for ids made only of hex digits
    and ``-`` / ``:`` -- equality ignoring case.
    """
    if not isinstance(wanted, str) or not isinstance(actual, str) or not wanted or not actual:
        return False
    if wanted == actual:
        return True
    return (
        len(wanted) == len(actual)
        and _is_hex_id(wanted)
        and _is_hex_id(actual)
        and wanted.lower() == actual.lower()
    )


def id_key(value: str) -> str:
    """The index key of an id (lower-case for a hex id), so a dict lookup follows
    :func:`same_id`."""
    return value.lower() if _is_hex_id(value) else value


def with_upstream_id(body: dict[str, Any], field: str, *upstream_ids: object) -> dict[str, Any]:
    """``body`` with its identity ``field`` re-spelt in the upstream form when it names one
    of the matched record's ``upstream_ids`` in another spelling (:func:`same_id`: a hex
    id in another case).

    Any other value (absent, an upstream spelling already, or a different id) is left as
    the caller sent it; ``body`` itself is never mutated.
    """
    given = body.get(field)
    if not isinstance(given, str):
        return body
    for upstream_id in upstream_ids:
        if isinstance(upstream_id, str) and same_id(given, upstream_id):
            return body if given == upstream_id else {**body, field: upstream_id}
    return body


def find_by_id(
    records: Iterable[dict[str, Any]], wanted: object, *fields: str
) -> dict[str, Any] | None:
    """The unique native-id record in the first matching id-field tier.

    Repeated rows for one native id are one choice; distinct records sharing an alias
    raise with identifying fields rather than silently picking an upstream target.
    """
    from .client import object_records, upstream_error_value

    items = object_records(list(records), "id resolution")
    for field in fields:
        matches = [record for record in items if same_id(wanted, record.get(field))]
        if not matches:
            continue
        distinct: dict[object, dict[str, Any]] = {}
        for index, record in enumerate(matches):
            native = record.get(fields[0])
            identity = id_key(native) if isinstance(native, str) and native else ("row", index)
            distinct.setdefault(identity, record)
        if len(distinct) > 1:
            choices = "; ".join(
                repr(
                    {
                        key: upstream_error_value(record.get(key))
                        for key in (*fields, "name", "mac", "macAddress")
                    }
                )
                for record in distinct.values()
            )
            raise ValueError(f"ambiguous id {wanted!r}: matches distinct records: {choices}")
        return next(iter(distinct.values()))
    return None


def name_keys(name: str) -> tuple[str, str, str, str]:
    """The tiered match keys of ``name``: exact; NFC + casefold; stripped (case kept);
    stripped + NFC + casefold."""
    composed = unicodedata.normalize("NFC", name)
    folded = composed.casefold()
    return name, folded, composed.strip(), folded.strip()


def tiered_name_matches[T](
    items: Iterable[T],
    needle: str,
    labels: Callable[[T], Sequence[Sequence[Any]]],
) -> tuple[int, list[T]]:
    """``(tier, matches)``: the items whose labels match ``needle`` in the first tier with
    any match; ``(-1, [])`` when no tier matches.

    ``labels(item)`` returns the item's label GROUPS in priority order (for a console:
    hostname / name first, then the display name). The tier index is
    ``name_tier * groups + group``: a looser name tier never beats a stricter one, and
    within one name tier an earlier group wins. Empty and non-string labels never match.
    Linear in the number of items and labels.
    """
    want = name_keys(needle)
    prepared: list[tuple[T, list[list[tuple[str, str, str, str]]]]] = []
    groups = 0
    for item in items:
        item_groups = [
            [name_keys(label) for label in group if isinstance(label, str) and label]
            for group in labels(item)
        ]
        groups = max(groups, len(item_groups))
        prepared.append((item, item_groups))
    for tier in range(NAME_TIERS):
        if not want[tier]:
            continue
        for group in range(groups):
            found = [
                item
                for item, item_groups in prepared
                if group < len(item_groups)
                and any(keys[tier] == want[tier] for keys in item_groups[group])
            ]
            if found:
                return tier * groups + group, found
    return -1, []


def name_matches[T](items: Iterable[T], needle: str, label: Callable[[T], Any]) -> list[T]:
    """The items whose one label (``label(item)``) matches ``needle`` in the first name
    tier with any match (see :func:`tiered_name_matches`)."""

    def _groups(item: T) -> list[list[Any]]:
        return [[label(item)]]

    return tiered_name_matches(items, needle, _groups)[1]
