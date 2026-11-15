"""The carrier family's shapes: parameter types, routes and limits (the family-owned layout).

Moved verbatim by ``scripts/move_family.py`` from the family's modules, which import them back.
"""

from __future__ import annotations

from typing import Any

#: Cloud gateway base for the Carrier / ISP Fabric family (served from api.ui.com).
CARRIER_BASE = "/v1/carrier"
_SUBSCRIBERS = f"{CARRIER_BASE}/subscribers"
_SERVICE_PLANS = f"{CARRIER_BASE}/service-plans"

#: Documented ``limit`` bound for the cursor-paginated subscriber collection
#: (OpenAPI: minimum 1, maximum 500, default 50). The drainer requests the max.
_MAX_PAGE_SIZE = 500

#: Documented ``sort`` enum for listSubscribers.
_SORT_VALUES = ("createdAt", "-createdAt", "name", "-name", "subscriberNumber", "-subscriberNumber")

#: Metadata is cleared with {} and omitted by the pinned Subscriber response.
_OMITTED_WHEN_EMPTY: dict[str, Any] = {"metadata": {}}

#: SubscriberCreate / SubscriberPatch ``metadata``: "The serialized JSON object must not
#: exceed 8192 bytes (8 KiB); a larger object is rejected with 400."
METADATA_MAX_BYTES = 8192

#: Body fields that carry an id: compared with the shared id rule (exact, or ignoring
#: case for an id made of hex digits and ``-`` / ``:``), never case-sensitively.
_ID_FIELDS = frozenset({"planId", "hostId"})
