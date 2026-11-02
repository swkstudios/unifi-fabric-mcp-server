"""Install generated advisory body properties without changing accepted inputs."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from unifi_fabric._tool_shapes_table import TOOL_SHAPES


def install_tool_shapes(mcp: Any) -> int:
    """Enrich advertised schemas only; function annotations/parsing stay unchanged."""
    components = mcp._local_provider._components  # noqa: SLF001
    count = 0
    for component in components.values():
        shapes = TOOL_SHAPES.get(getattr(component, "name", ""))
        if not shapes:
            continue
        parameters = deepcopy(component.parameters)
        for arg, shape in shapes.items():
            prop = parameters["properties"][arg]
            branch = (
                prop
                if prop.get("type") == "object"
                else next(b for b in prop["anyOf"] if b.get("type") == "object")
            )
            # Retain every original validator keyword, including object/null unions.
            # Each generated child accepts every JSON value, so properties adds no
            # refusal and unknown body keys remain accepted.
            prop["description"] = prop.get("description", "") + "\n" + shape["description"]
            if component.name in ("create_wifi_broadcast", "update_wifi_broadcast"):
                prop["description"] += (
                    "\nFor OPEN securityConfiguration, supply an explicit network reference: "
                    'network: {type: "SPECIFIC", networkId: UUID from list_networks}. '
                    "The live controller requires it although the spec marks network optional."
                )
            branch["properties"] = deepcopy(shape["properties"])
            branch["additionalProperties"] = True
            count += 1
        component.parameters = parameters
    return count
