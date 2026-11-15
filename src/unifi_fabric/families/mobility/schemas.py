"""The mobility family's shapes: parameter types, routes and limits (the family-owned layout).

Moved verbatim by ``scripts/move_family.py`` from the family's modules, which import them back.
"""

from __future__ import annotations

#: Cloud gateway base for the Mobility resource family (served from api.ui.com).
MOBILITY_BASE = "/v1/mobility"
_WORKSPACES = f"{MOBILITY_BASE}/workspaces"

#: Documented page-size cap for the offset-paginated device/client collections.
_MAX_PAGE_SIZE = 200

#: Keys a multi-key merge sets itself (the rest of each key's body goes under byKey). The
#: merge drops a key's own value only where the server placed it (``without_server_fields``):
#: an upstream field of the same name stays under byKey.
_MERGE_OWNED = frozenset({"_count", "incomplete", "incompleteReason"})
