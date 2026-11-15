"""The explicit family loader map (public #42): every registration step, in order.

GENERATED once by ``scripts/gen_loaders.py --generate`` from the ``register`` calls of
``server.py``; committed since then, and never derived at runtime. A family move edits
only its own entries (``module`` and ``function``) and keeps each ``origin``.
``python scripts/gen_loaders.py --check`` compares this file with the family directories.

:data:`LOADERS` is the one registration path of every profile: the server runs
:func:`load` once, so the registration order (the ``tools/list`` order) is the order of
the entries. Family selection removes tools afterwards (:mod:`unifi_fabric.policy`); it
never takes a different path. Each entry names:

* ``family``: the family directory under ``unifi_fabric/families/``;
* ``module``, ``function``: the module in that directory and its ``register`` /
  ``register_<n>`` function, called as ``function(mcp, deps_fn)``;
* ``deps``: the ``deps_fn`` it is given: ``late`` is ``lambda: server._require()``, read
  at call time, so a patched ``server._require`` applies; ``bound`` is
  ``server._require`` itself. Each step keeps the form it was registered with;
* ``origin``: the tools module stem its tools are indexed under (``MODULE_INDEX``, which
  keys the discovery search vocabulary). It is an index key only: a family move or a
  split step keeps it, so one origin may span family directories, and it never decides a
  family (the step's ``family`` directory does). While the origin's module exists,
  ``server.<origin>`` stays bound to it.

:data:`FAMILY_DEPENDENCIES` declares, per catalog family, the other families its steps'
modules depend on (``FamilySpec.dependencies``).
"""

from __future__ import annotations

import importlib
import importlib.util
from collections.abc import Callable, Mapping
from types import ModuleType
from typing import Any, Literal, NamedTuple

#: The package of the family directories.
FAMILIES_PACKAGE = "unifi_fabric.families"

#: The common package: code that two or more families use lives here, outside every
#: family directory, so a family's modules never need another family's (public #41: a
#: disabled family is never imported). A helper only one family uses stays in that family
#: as a private ``_*.py`` module. No loader entry names this package.
COMMON_PACKAGE = "unifi_fabric.shared_shapes"

#: Module stems of the family-owned layout (public #42): any family may have each one, so
#: their module key is qualified by the family (:func:`module_key`).
LAYOUT_STEMS: tuple[str, ...] = ("handlers", "schemas", "registrar")


def module_key(family: str, module: str) -> str:
    """The key of a family module: its stem, or ``<family>/<stem>`` for a layout stem."""
    return f"{family}/{module}" if module in LAYOUT_STEMS else module


class Loader(NamedTuple):
    """One registration step of the loader map."""

    family: str
    module: str
    function: str
    deps: Literal["late", "bound"]
    origin: str

    @property
    def module_path(self) -> str:
        """The dotted module path."""
        return f"{FAMILIES_PACKAGE}.{self.family}.{self.module}"

    @property
    def ref(self) -> str:
        """``<module path>:<function>``, the form of ``FamilySpec.loader``."""
        return f"{self.module_path}:{self.function}"

    @property
    def key(self) -> str:
        """The module key (:func:`module_key`)."""
        return module_key(self.family, self.module)


#: The registration steps, in registration (``tools/list``) order.
LOADERS: tuple[Loader, ...] = (
    Loader(
        family="site_manager",
        module="registrar",
        function="register",
        deps="late",
        origin="site_manager",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register",
        deps="late",
        origin="network",
    ),
    Loader(
        family="protect",
        module="registrar",
        function="register",
        deps="bound",
        origin="protect_private",
    ),
    Loader(
        family="devices",
        module="registrar",
        function="register",
        deps="bound",
        origin="device_mgmt",
    ),
    Loader(
        family="devices",
        module="registrar",
        function="register_2",
        deps="bound",
        origin="device_commands",
    ),
    Loader(
        family="devices",
        module="registrar",
        function="register_3",
        deps="bound",
        origin="scheduled_tasks",
    ),
    Loader(
        family="devices",
        module="registrar",
        function="register_4",
        deps="bound",
        origin="device_radios",
    ),
    Loader(
        family="devices",
        module="registrar",
        function="register_5",
        deps="bound",
        origin="switch_port_overrides",
    ),
    Loader(
        family="devices",
        module="registrar",
        function="register_6",
        deps="bound",
        origin="wifi_diagnosis",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_2",
        deps="bound",
        origin="network_wifi_radio",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_3",
        deps="bound",
        origin="network_nat_qos_traffic",
    ),
    Loader(
        family="clients",
        module="registrar",
        function="register",
        deps="bound",
        origin="clients",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_4",
        deps="bound",
        origin="network_clients_guests",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_5",
        deps="bound",
        origin="network_switching_power",
    ),
    Loader(
        family="protect",
        module="registrar",
        function="register_2",
        deps="bound",
        origin="protect_camera_recording",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_6",
        deps="bound",
        origin="network_controller_admin",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_7",
        deps="bound",
        origin="network_routing_topology",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_8",
        deps="bound",
        origin="matter",
    ),
    Loader(
        family="firewall",
        module="registrar",
        function="register",
        deps="late",
        origin="firewall_proxy",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_9",
        deps="late",
        origin="network_services_proxy",
    ),
    Loader(
        family="protect",
        module="registrar",
        function="register_3",
        deps="late",
        origin="protect",
    ),
    Loader(
        family="protect",
        module="registrar",
        function="register_4",
        deps="late",
        origin="recognition",
    ),
    Loader(
        family="protect",
        module="registrar",
        function="register_5",
        deps="late",
        origin="protect",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_10",
        deps="late",
        origin="network_services_proxy",
    ),
    Loader(
        family="vpn",
        module="registrar",
        function="register",
        deps="bound",
        origin="vpn",
    ),
    Loader(
        family="vpn",
        module="registrar",
        function="register_2",
        deps="bound",
        origin="network_vpn_dns",
    ),
    Loader(
        family="vpn",
        module="registrar",
        function="register_3",
        deps="bound",
        origin="network_vpn_dns",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_11",
        deps="bound",
        origin="site_config",
    ),
    Loader(
        family="vpn",
        module="registrar",
        function="register_4",
        deps="bound",
        origin="radius_profiles",
    ),
    Loader(
        family="hotspot",
        module="registrar",
        function="register",
        deps="bound",
        origin="hotspot",
    ),
    Loader(
        family="site_manager",
        module="registrar",
        function="register_2",
        deps="bound",
        origin="aggregation",
    ),
    Loader(
        family="statistics",
        module="registrar",
        function="register",
        deps="bound",
        origin="statistics",
    ),
    Loader(
        family="protect",
        module="registrar",
        function="register_6",
        deps="bound",
        origin="protect_events_cases",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_12",
        deps="bound",
        origin="network_controller_insights",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_13",
        deps="late",
        origin="network_dpi_policy",
    ),
    Loader(
        family="firewall",
        module="registrar",
        function="register_2",
        deps="late",
        origin="network_dpi_policy",
    ),
    Loader(
        family="protect",
        module="registrar",
        function="register_7",
        deps="bound",
        origin="protect_users_assets",
    ),
    Loader(
        family="protect",
        module="registrar",
        function="register_8",
        deps="bound",
        origin="protect_automation_backup",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_14",
        deps="bound",
        origin="network_security_diagnostics",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_15",
        deps="bound",
        origin="network_proav_sandbox",
    ),
    Loader(
        family="protect",
        module="registrar",
        function="register_9",
        deps="bound",
        origin="protect_ptz_doorbell",
    ),
    Loader(
        family="protect",
        module="registrar",
        function="register_10",
        deps="bound",
        origin="protect_recognition_search",
    ),
    Loader(
        family="protect",
        module="registrar",
        function="register_11",
        deps="bound",
        origin="protect_device_lifecycle",
    ),
    Loader(
        family="protect",
        module="registrar",
        function="register_12",
        deps="bound",
        origin="protect_door_locks",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_16",
        deps="bound",
        origin="network_mobile_wan",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_17",
        deps="bound",
        origin="network_device_operations",
    ),
    Loader(
        family="clients",
        module="registrar",
        function="register_2",
        deps="bound",
        origin="client_records",
    ),
    Loader(
        family="statistics",
        module="registrar",
        function="register_2",
        deps="bound",
        origin="system_log",
    ),
    Loader(
        family="statistics",
        module="registrar",
        function="register_3",
        deps="bound",
        origin="event_streams",
    ),
    Loader(
        family="vpn",
        module="registrar",
        function="register_5",
        deps="bound",
        origin="vpn_clients",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_18",
        deps="bound",
        origin="site_admin",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_19",
        deps="late",
        origin="network_services_proxy",
    ),
    Loader(
        family="firewall",
        module="registrar",
        function="register_3",
        deps="late",
        origin="network_services_proxy",
    ),
    Loader(
        family="network",
        module="registrar",
        function="register_20",
        deps="late",
        origin="network_services_proxy",
    ),
    Loader(
        family="innerspace",
        module="registrar",
        function="register",
        deps="late",
        origin="placement_snapshot",
    ),
    Loader(
        family="innerspace",
        module="registrar",
        function="register_2",
        deps="late",
        origin="innerspace",
    ),
    Loader(
        family="innerspace",
        module="registrar",
        function="register_3",
        deps="bound",
        origin="innerspace_internal",
    ),
    Loader(
        family="carrier",
        module="registrar",
        function="register",
        deps="late",
        origin="carrier_fabric",
    ),
    Loader(
        family="connector",
        module="registrar",
        function="register",
        deps="late",
        origin="connector",
    ),
    Loader(
        family="mobility",
        module="registrar",
        function="register",
        deps="late",
        origin="mobility",
    ),
)

#: The other families each catalog family's steps depend on (declared, sorted).
FAMILY_DEPENDENCIES: Mapping[str, tuple[str, ...]] = {
    "carrier": (),
    "clients": ("network",),
    "connector": ("carrier", "mobility", "protect"),
    "devices": ("connector", "network", "statistics"),
    "firewall": ("network",),
    "hotspot": (),
    "innerspace": ("protect", "site_manager"),
    "mobility": (),
    "network": ("clients", "connector", "devices", "site_manager"),
    "protect": ("connector",),
    "site_manager": ("network", "statistics"),
    "statistics": ("clients",),
    "vpn": ("network",),
    "meta": ("network", "site_manager"),
}


def refs() -> tuple[str, ...]:
    """Every step's ``<module path>:<function>``, in order."""
    return tuple(entry.ref for entry in LOADERS)


def origin_module(entry: Loader) -> ModuleType | None:
    """The module named by ``entry.origin``, while it exists, else None.

    Looked for in the step's own directory first, then in the other family directories
    of the map, in map order (an origin may span directories); a found module is
    imported. Module stems outside the layout are unique across families
    (``gen_loaders.py --check``), so at most one directory has it.
    """
    for family in dict.fromkeys((entry.family, *(e.family for e in LOADERS))):
        name = f"{FAMILIES_PACKAGE}.{family}.{entry.origin}"
        if importlib.util.find_spec(name) is not None:
            return importlib.import_module(name)
    return None


def load(mcp: Any, *, late: Callable[[], Any], bound: Callable[[], Any]) -> dict[str, Any]:
    """Run every step in order and return the server's names for them.

    The names are each step's returned wrappers by tool name (the ``server.<tool>``
    re-exports), each non-layout module of the map by stem (``server.<module>``), and each
    step's origin module while it exists (``server.<origin>``, so moving a step out of a
    module keeps that attribute). A name bound to two different objects fails.
    """
    names: dict[str, Any] = {}

    def add(name: str, value: Any) -> None:
        if names.setdefault(name, value) is not value:
            raise RuntimeError(f"loader map: the name {name!r} is given twice")

    for entry in LOADERS:
        module = importlib.import_module(entry.module_path)
        if entry.module not in LAYOUT_STEMS:
            add(entry.module, module)
        if entry.origin != entry.module or entry.module in LAYOUT_STEMS:
            origin = origin_module(entry)
            if origin is not None:
                add(entry.origin, origin)
        returned = getattr(module, entry.function)(mcp, late if entry.deps == "late" else bound)
        for name, wrapper in (returned or {}).items():
            add(name, wrapper)
    return names
