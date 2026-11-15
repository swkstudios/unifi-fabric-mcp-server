"""Names the network family's ``network`` shares with other families.

Used by clients, devices, network, site_manager. Moved verbatim by ``scripts/move_family.py`` from
``families/network/network.py``, which import them back where they use them, so their own code and
import paths stay.
"""

from __future__ import annotations

PROXY_BASE = "/v1/connector/consoles/{host_id}/proxy/network/integration/v1"


def _proxy(host_id: str, path: str) -> str:
    return PROXY_BASE.format(host_id=host_id) + path
