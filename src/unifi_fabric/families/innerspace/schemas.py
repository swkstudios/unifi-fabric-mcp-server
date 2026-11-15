"""The innerspace family's shapes: parameter types, routes and limits (the family-owned layout).

Moved verbatim by ``scripts/move_family.py`` from the family's modules, which import them back.
"""

from __future__ import annotations

# Documented "UniFi InnerSpace Integration API" (v1.3.23) connector base. This is
# the officially published, GET-only surface
# (https://developer.ui.com/innerspace/.../openapi.json) and is tried FIRST.
INNERSPACE_INTEGRATION_BASE = "/v1/connector/consoles/{host_id}/proxy/innerspace/integration"

# Legacy, UNDOCUMENTED connector base (``/proxy/innerspace/api/*``). The connector
# may answer 403 ``host not found`` for it while relaying the documented integration
# base, so it is used only as a fallback for ``/project``.
INNERSPACE_PROXY_BASE = "/v1/connector/consoles/{host_id}/proxy/innerspace/api"

_VALID_MODES = ("2D", "3D")

#: Arrays every project document carries; each must be a JSON array.
_PROJECT_ARRAYS = ("shapes", "plans", "products", "wallTypes")

#: The InnerSpace application root on the console proxy.
INNERSPACE_APP_BASE = "/v1/connector/consoles/{host_id}/proxy/innerspace"

SCHEMA_VERSION = "unifi.placement-snapshot/v1"
FRESHNESS_TTL_SECONDS = 120

#: The only ``_withheld`` reasons; all are produced only under ``UNIFI_REDACT_SECRETS``
#: (value withholding). Structural reasons (the record cannot be represented in schema v1)
#: are counted under ``_unprojected`` instead.
REDACTION_REASONS = frozenset({"url", "hardware_address", "network_address", "credential_marker"})

# Where each snapshot section's values can be read verbatim. Used to tell the caller, for
# every ``_withheld`` / ``_unprojected`` entry, how to obtain what the snapshot left out.
_VERBATIM_SOURCES = {
    "floors": "get_innerspace_project (plans[], and the plan's map shape in shapes[])",
    "shapes": "get_innerspace_project (shapes[])",
    "walls": "get_innerspace_project (the wall shapes in shapes[])",
    "placed_devices": "get_innerspace_project (the device shapes in shapes[]) or "
    "list_innerspace_devices",
    "topology": "list_cameras, list_sensors or list_devices",
    "provenance": "get_innerspace_project (project.updatedAt)",
}

# This explicit, closed list is part of the snapshot's security contract.  The
# called helpers use GET only; no generic connector route or mutating helper is
# accepted here.
APPROVED_READ_SOURCES = (
    "innerspace.project.3d",
    "protect.cameras",
    "protect.sensors",
    "site_manager.devices",
)

# The preflight is intentionally coupled to the collector's closed source set.
# Adding a new snapshot input must therefore also add a capability probe; a key
# may not be declared ready merely because a subset of the collector works.
PLACEMENT_SNAPSHOT_CAPABILITY_SCHEMA_VERSION = "unifi.placement-snapshot-preflight/v1"
CAPABILITY_OUTCOMES = frozenset({"ok", "auth_denied", "unavailable", "error"})

# Floor-plan asset URLs on an InnerSpace ``map`` shape (spec ``/v1/project`` shapes[]
# oneOf ``type: "map"``) and the snapshot ``floors[]`` key each one is projected to.
_MAP_ASSET_FIELDS = (
    ("urlImage", "image_url"),
    ("urlModel", "model_url"),
    ("additionalZipUrl", "additional_zip_url"),
    ("additionalBinUrl", "additional_bin_url"),
)

_QUATERNION_AXES = ("x", "y", "z", "w")

# Closed display-safe device-type enum for consumer marker iconography.
# ``device_type`` is a coarse, non-identifying category the
# panel maps to a bundled MDI glyph — the always-correct primary. It is NOT derived
# from any network/browser identity field, only from ``kind`` plus the human-facing
# model/name text, so it carries no more information than ``model`` already does.
# The consumer's v1 topology validator must accept ``device_type``/``icon`` as
# optional BEFORE this producer emits them (deploy order: validator, then producer).
DEVICE_TYPES = frozenset(
    {
        "camera",
        "doorbell",
        "access_point",
        "switch",
        "gateway",
        "motion_sensor",
        "presence_sensor",
        "chime",
        "sensor",
        "client",
        "unknown",
    }
)

# Curated exact-model -> UniFi fingerprint id table for common UniFi models. The
# id resolves to https://static.ui.com/fingerprint/0/<id>_257x257.png, the public
# UniFi product render a consumer may cache locally. Only models with a verified
# fingerprint match are listed; anything absent omits ``icon`` and the consumer
# falls back to its own glyph for the ``device_type``. Keys are casefolded.
_MODEL_FINGERPRINT_IDS: dict[str, int] = {
    "uvc g4 instant": 4987,  # UniFi Protect G4 Instant
    "uvc g4 dome": 4395,  # UniFi Protect G4 Dome
    "usw pro 24 poe": 3344,  # UniFi Switch Pro 24 PoE Gen 2
    "udm pro": 3522,  # UniFi Dream Machine Pro
    "u6 pro": 4981,  # UniFi U6 Pro
}

# Fields an upstream record may carry the product model under. Protect camera and
# sensor objects expose the model string under ``type`` (not ``model``) — which is
# why the ``model`` projection already falls back to ``type`` — while Site Manager
# infrastructure records use ``model``. Device-type derivation and fingerprint-icon
# resolution both scan this same ordered set so the two stay consistent.
_MODEL_LOOKUP_KEYS = ("model", "type", "name", "displayName", "title", "marketName")
