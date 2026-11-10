"""Bounded, read-only UniFi placement snapshots for floor-plan and map consumers.

The general UniFi Fabric MCP server is intentionally broad and can expose
controller management tools.  A placement consumer (a floor-plan panel, map, or
dashboard) should not consume that surface directly: it needs a small snapshot
of the current physical layout in one stable shape.  This module builds it.  It
performs only the four approved GET-backed reads and projects them onto the
closed ``unifi.placement-snapshot/v1`` schema (selected, renamed and derived
fields); raw controller payloads are not copied whole.

Withholding is opt-in, like every other credential mask on this server: by
default each projected string is the upstream value verbatim, and the address
and floor-plan asset-URL fields are included.  Only with ``UNIFI_REDACT_SECRETS``
on does the projection leave out URLs, IP / MAC addresses and credential-marker
text, counting each one under ``_withheld`` and saying under
``_withheld_how_to_obtain`` where to read the value instead; with redaction off
``_withheld`` is never present.  Records that schema v1 cannot represent (a
non-object entry, a device without a position, ...) are a separate matter, counted
in either mode under ``_unprojected`` with ``_unprojected_how_to_obtain`` naming
the verbatim read tool.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import ipaddress
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from fastmcp import FastMCP

from ... import output_schemas
from ...client import (
    RateLimitError,
    UniFiClient,
    UniFiConnectionError,
    finite_number,
    gather_or_cancel,
)
from ...registry import Registry
from ...shared_shapes._device_wrappers import wrapper_devices
from ...shared_shapes._keys import context_value
from ...tool_annotations import READ_ONLY
from ..protect import protect
from ..site_manager import site_manager
from . import innerspace

SCHEMA_VERSION = "unifi.placement-snapshot/v1"
FRESHNESS_TTL_SECONDS = 120

_MAC_ADDRESS_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")
_BARE_MAC_ADDRESS_RE = re.compile(r"(?i)^[0-9a-f]{12}\Z")
_IPV4_CANDIDATE_RE = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
_IPV6_CANDIDATE_RE = re.compile(r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2}[0-9a-f:]+")
# Credential / identity markers, matched as whole words: the marker must not be part of a
# longer word (letters and digits bound it; ``_`` / ``-`` / space / punctuation do not), so
# ordinary names such as "Hallway Passage", "Overpass Garage Cam", "Bypass Closet AP" or
# "Serial Studio" are kept while "api_key", "Sensor password" or "serial-number" are not.
_SENSITIVE_TEXT_RE = re.compile(
    r"(?i)(?<![a-z0-9])(?:"
    r"(?:api|access)[_-]?(?:key|token)s?|"
    r"bearer|cookies?|credentials?|passwords?|passwd|passphrases?|private[_-]?keys?|"
    r"browser[_-]?ids?|session[_-]?ids?|serial[_-]?(?:ids?|numbers?|no|values?)|"
    r"(?:token|secret)[_-]?(?:ids?|keys?|values?|markers?|secrets?)"
    r")(?![a-z0-9])"
)

# Per-snapshot record of the values UNIFI_REDACT_SECRETS left out ({"<section>.<field>":
# {"<reason>": count}}). Reported under the additive ``_withheld`` key so a value is never
# dropped silently; the values themselves are never reported. Populated only under
# redaction: with it off, ``_withheld`` is never present.
_WITHHELD: contextvars.ContextVar[dict[str, dict[str, int]] | None] = contextvars.ContextVar(
    "placement_snapshot_withheld", default=None
)

# Per-snapshot record of the records schema v1 cannot represent (same shape as
# ``_withheld``), in either mode. Reported under the additive ``_unprojected`` key.
_UNPROJECTED: contextvars.ContextVar[dict[str, dict[str, int]] | None] = contextvars.ContextVar(
    "placement_snapshot_unprojected", default=None
)

# Whether the current snapshot build withholds sensitive-looking values. Off unless the
# operator opted in with UNIFI_REDACT_SECRETS (``Settings.redact_secrets``).
_REDACT: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "placement_snapshot_redact", default=False
)

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


def _withhold_reason(candidate: str) -> str | None:
    """Why ``candidate`` (non-empty, stripped) is withheld under ``UNIFI_REDACT_SECRETS``,
    or None. Consulted only when redaction is on."""
    if candidate.casefold().startswith(("http:", "https:", "data:")):
        return "url"
    if _MAC_ADDRESS_RE.search(candidate) or _BARE_MAC_ADDRESS_RE.fullmatch(candidate):
        return "hardware_address"
    if _SENSITIVE_TEXT_RE.search(candidate):
        return "credential_marker"
    for match in _IPV4_CANDIDATE_RE.finditer(candidate):
        try:
            ipaddress.ip_address(match.group())
        except ValueError:
            continue
        return "network_address"
    for match in _IPV6_CANDIDATE_RE.finditer(candidate):
        try:
            if isinstance(ipaddress.ip_address(match.group()), ipaddress.IPv6Address):
                return "network_address"
        except ValueError:
            continue
    try:
        if ":" in candidate and isinstance(ipaddress.ip_address(candidate), ipaddress.IPv6Address):
            return "network_address"
    except ValueError:
        pass
    return None


def _count(collector: dict[str, dict[str, int]] | None, field: str, reason: str) -> None:
    if collector is None:
        return
    per_field = collector.setdefault(field, {})
    per_field[reason] = per_field.get(reason, 0) + 1


def _note_withheld(field: str, reason: str) -> None:
    """Count one value left out under ``UNIFI_REDACT_SECRETS`` for the current snapshot
    (no-op outside a build, and never counted with redaction off)."""
    if not _REDACT.get():
        return
    _count(_WITHHELD.get(), field, reason)


@contextmanager
def _pending_withheld() -> Iterator[dict[str, dict[str, int]]]:
    """Collect the ``_withheld`` counts made inside the block into a scratch tally instead
    of the snapshot's, so a caller can keep them (:func:`_commit_withheld`) only once it
    knows the record they belong to is reported, not dropped as a duplicate."""
    pending: dict[str, dict[str, int]] = {}
    token = _WITHHELD.set(pending)
    try:
        yield pending
    finally:
        _WITHHELD.reset(token)


def _commit_withheld(pending: dict[str, dict[str, int]]) -> None:
    """Add a :func:`_pending_withheld` tally to the current snapshot's ``_withheld``."""
    collector = _WITHHELD.get()
    if collector is None:
        return
    for field, reasons in pending.items():
        per_field = collector.setdefault(field, {})
        for reason, count in reasons.items():
            per_field[reason] = per_field.get(reason, 0) + count


def _note_unprojected(field: str, reason: str) -> None:
    """Count one record schema v1 cannot represent for the current snapshot, in either
    mode (no-op outside a build)."""
    _count(_UNPROJECTED.get(), field, reason)


def _objects(items: object, section: str) -> list[dict[str, Any]]:
    """The object entries of a source array; every entry that is not an object is counted
    under ``_unprojected`` as ``<section>.record`` / ``not_an_object`` (never dropped silently).
    """
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            out.append(item)
        else:
            _note_unprojected(f"{section}.record", "not_an_object")
    return out


def _safe_snapshot_text(value: object, field: str | None = None) -> str | None:
    """Return a snapshot string field: the upstream string verbatim by default.

    A non-string or blank value is absent (``None``). Otherwise the upstream string is
    returned exactly as sent. Only with ``UNIFI_REDACT_SECRETS`` on is a value that is a
    URL, carries a literal network or hardware address, or carries a whole-word
    credential/browser marker left out instead; when ``field`` is given, that value is
    counted under ``_withheld`` (its text is never reported). There is no length limit.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if not _REDACT.get():
        return value
    reason = _withhold_reason(candidate)
    if reason is None:
        return value
    if field is not None:
        _note_withheld(field, reason)
    return None


def _address_field(value: object, field: str, reason: str) -> str | None:
    """An address or asset-URL field (``mac``, ``ip``, floor-plan map URLs): the upstream
    string verbatim by default; under ``UNIFI_REDACT_SECRETS`` the whole field is left out
    and counted under ``_withheld`` as ``field`` / ``reason``. Non-string or blank is absent.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    if _REDACT.get():
        _note_withheld(field, reason)
        return None
    return value


def _verbatim_source(field: str) -> str:
    return _VERBATIM_SOURCES.get(field.split(".", 1)[0], "the source tools")


def _withheld_how_to_obtain(withheld: dict[str, dict[str, int]]) -> dict[str, str]:
    """For every ``_withheld`` entry, where to get the value (keyed like ``_withheld``)."""
    return {
        field: (
            "Withheld because UNIFI_REDACT_SECRETS is on: unset it (the default is off) "
            f"to receive the value in this snapshot, or read it verbatim with "
            f"{_verbatim_source(field)}."
        )
        for field in withheld
    }


def _unprojected_how_to_obtain(unprojected: dict[str, dict[str, int]]) -> dict[str, str]:
    """For every ``_unprojected`` entry, the verbatim read tool (keyed like ``_unprojected``)."""
    return {
        field: (
            f"Not representable in {SCHEMA_VERSION} ({', '.join(sorted(reasons))}): read the "
            f"record verbatim with {_verbatim_source(field)}."
        )
        for field, reasons in unprojected.items()
    }


def _string(value: object, field: str | None = None) -> str | None:
    """Shorthand for :func:`_safe_snapshot_text` (``field`` names it in ``_withheld``)."""
    return _safe_snapshot_text(value, field)


def _number(value: object, field: str) -> int | float | None:
    """A finite JSON number without coercing upstream strings; NaN / Infinity is a shape
    error naming ``field`` (:func:`~unifi_fabric.client.finite_number`)."""
    return finite_number(value, field)


def _position(value: object, field: str = "position") -> dict[str, int | float] | None:
    """Project an InnerSpace point onto x/y/z only."""
    point = value[0] if isinstance(value, list) and value else value
    if not isinstance(point, dict):
        return None
    output = {axis: _number(point.get(axis), f"{field}.{axis}") for axis in ("x", "y", "z")}
    if output["x"] is None or output["y"] is None:
        return None
    return {axis: number for axis, number in output.items() if number is not None}


def _display_name(item: dict[str, Any], section: str) -> str | None:
    """The first non-blank label of title, name, displayName, hostname, label (verbatim).

    Under ``UNIFI_REDACT_SECRETS`` a label that would be withheld is skipped for the next
    one; when every candidate label was left out, the first reason is counted under
    ``_withheld`` as ``<section>.display_name``.
    """
    first_reason: str | None = None
    for key in ("title", "name", "displayName", "hostname", "label"):
        raw = item.get(key)
        value = _string(raw)
        if value:
            return value
        if first_reason is None and isinstance(raw, str) and raw.strip():
            first_reason = _withhold_reason(raw.strip())
    if first_reason is not None:
        _note_withheld(f"{section}.display_name", first_reason)
    return None


def _scale_shapes_by_plan(shapes: list[dict[str, Any]]) -> dict[str, int | float]:
    """Map each plan id to the scale its ``scale``-type shape carries.

    The documented InnerSpace ``/v1/project`` schema publishes no scale on the plan
    object itself: per-plan scale lives on a ``scale`` shape (``planId``, ``scale``,
    ``computedScale``), the same source ``get_innerspace_summary`` reads. ``scale`` is
    preferred and ``computedScale`` is the fallback; a shape whose ``planId`` is null
    names no plan and is skipped.
    """
    out: dict[str, int | float] = {}
    for shape in shapes:
        if shape.get("type") != "scale":
            continue
        plan_id = shape.get("planId")
        if plan_id is None:  # spec: planId is nullable; a null one names no plan
            continue
        value = _number(shape.get("scale"), "shapes[].scale")
        if value is None:
            value = _number(shape.get("computedScale"), "shapes[].computedScale")
        if value is not None:
            out.setdefault(str(plan_id), value)
    return out


# Floor-plan asset URLs on an InnerSpace ``map`` shape (spec ``/v1/project`` shapes[]
# oneOf ``type: "map"``) and the snapshot ``floors[]`` key each one is projected to.
_MAP_ASSET_FIELDS = (
    ("urlImage", "image_url"),
    ("urlModel", "model_url"),
    ("additionalZipUrl", "additional_zip_url"),
    ("additionalBinUrl", "additional_bin_url"),
)


def _map_shapes_by_plan(shapes: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Map each plan id to its first ``map`` shape (the floor-plan image/model asset)."""
    out: dict[str, dict[str, Any]] = {}
    for shape in shapes:
        if shape.get("type") != "map" or shape.get("planId") is None:
            continue
        out.setdefault(str(shape.get("planId")), shape)
    return out


def _floor(
    plan: dict[str, Any],
    scale_by_plan: dict[str, int | float] | None = None,
    map_by_plan: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Project a floor-plan record onto the fields a consumer needs to align floors.

    ``scale`` comes from the plan itself when it carries one (the legacy ``scale`` /
    ``planScale`` / ``planScales``, a number or an object with ``scale``: read by the one
    shared reader :func:`unifi_fabric.families.innerspace.innerspace._plan_scale`, as
    ``get_innerspace_summary`` reads it), otherwise from the plan's ``scale`` shape in
    ``scale_by_plan``. A NaN / Infinity in any of those fields is a shape error.
    The plan's ``map`` shape (``map_by_plan``) supplies the floor-plan asset URLs
    ``image_url`` / ``model_url`` / ``additional_zip_url`` / ``additional_bin_url``
    (verbatim; left out and counted under ``_withheld`` with ``UNIFI_REDACT_SECRETS`` on).
    """
    output: dict[str, Any] = {
        "source_id": _string(plan.get("id"), "floors.source_id")
        or _string(plan.get("planId"), "floors.source_id"),
        "display_name": _string(plan.get("name"), "floors.display_name")
        or _string(plan.get("title"), "floors.display_name"),
        "ordering": _number(plan.get("ordering"), "plans[].ordering"),
    }
    for legacy in ("scale", "planScale", "planScales"):
        # A non-finite number in a legacy field is a shape error (the shared reader skips
        # it); a non-number is not a scale and is never coerced.
        value = plan.get(legacy)
        if isinstance(value, dict):
            _number(value.get("scale"), f"plans[].{legacy}.scale")
        else:
            _number(value, f"plans[].{legacy}")
    scale = innerspace._plan_scale(plan)
    if scale is None and scale_by_plan and plan.get("id") is not None:
        scale = scale_by_plan.get(str(plan.get("id")))
    output["scale"] = scale
    plan_id = plan.get("id")
    map_shape = map_by_plan.get(str(plan_id)) if map_by_plan and plan_id is not None else None
    if map_shape is not None:
        for upstream_key, snapshot_key in _MAP_ASSET_FIELDS:
            output[snapshot_key] = _address_field(
                map_shape.get(upstream_key), f"floors.{snapshot_key}", "url"
            )
    return {key: value for key, value in output.items() if value is not None}


_QUATERNION_AXES = ("x", "y", "z", "w")


def _quaternion(value: object, field: str) -> dict[str, int | float] | list[Any] | None:
    """A rotation component as numbers: the spec object form ``{x, y, z, w}`` (every
    axis a finite number; projected onto those four keys) or a list of finite numbers
    (returned as sent).  Anything else is ``None``."""
    if isinstance(value, dict):
        axes = {axis: _number(value.get(axis), f"{field}.{axis}") for axis in _QUATERNION_AXES}
        kept = {axis: number for axis, number in axes.items() if number is not None}
        return kept if len(kept) == len(_QUATERNION_AXES) else None
    if isinstance(value, list) and all(_number(v, field) is not None for v in value):
        return value
    return None


def _placed_device(shape: dict[str, Any]) -> dict[str, Any] | None:
    position = _position(shape.get("position"), "shapes[].position")
    if position is None:
        return None
    output: dict[str, Any] = {
        "source_id": _string(shape.get("id"), "placed_devices.source_id"),
        "display_name": _display_name(shape, "placed_devices"),
        "product_id": _string(shape.get("productId"), "placed_devices.product_id"),
        "mount": _string(shape.get("mount"), "placed_devices.mount"),
        "floor_source_id": _string(shape.get("planId"), "placed_devices.floor_source_id"),
        "position": position,
    }
    # The device's network identity as InnerSpace records it (spec device shape ``meta``:
    # ``ip``, ``mac``): verbatim by default, withheld under UNIFI_REDACT_SECRETS.
    meta = shape.get("meta")
    if isinstance(meta, dict):
        output["ip"] = _address_field(meta.get("ip"), "placed_devices.ip", "network_address")
        output["mac"] = _address_field(meta.get("mac"), "placed_devices.mac", "hardware_address")
    rotation = shape.get("rotation")
    if isinstance(rotation, dict):
        # Rotation is geometry, not browser/controller identity.  Copy only the
        # numeric quaternions instead of arbitrary nested upstream metadata.  The
        # InnerSpace spec shape is an object per component ({"x", "y", "z", "w"}, all
        # required numbers); a list of numbers is accepted as well.  A present
        # component in neither shape is counted under _unprojected.
        kept: dict[str, Any] = {}
        for name in ("pov", "base"):
            if name not in rotation:
                continue
            quaternion = _quaternion(rotation[name], f"shapes[].rotation.{name}")
            if quaternion is not None:
                kept[name] = quaternion
            else:
                _note_unprojected(f"placed_devices.rotation.{name}", "not_numeric")
        output["rotation"] = kept
    return {key: value for key, value in output.items() if value is not None and value != {}}


def _wall(shape: dict[str, Any]) -> dict[str, Any] | None:
    points = shape.get("position")
    if not isinstance(points, list) or len(points) < 2:
        return None
    start = _position(points[:1], "shapes[].position[0]")
    end = _position(points[1:2], "shapes[].position[1]")
    if start is None or end is None:
        return None
    output: dict[str, Any] = {"start": start, "end": end}
    variant = _string(shape.get("variant"), "walls.material")
    plan_id = _string(shape.get("planId"), "walls.floor_source_id")
    if variant:
        output["material"] = variant
    if plan_id:
        output["floor_source_id"] = plan_id
    return output


def _derived_source_id(item: dict[str, Any], kind: str) -> str | None:
    """Derive a stable, display-safe id for a device that lacks ``id``/``deviceId``.

    Site Manager ``/v1/devices`` records for infrastructure hardware (gateway,
    switches, APs) frequently carry only a ``mac`` — no top-level UUID. A MAC used as the
    ``source_id`` would be withheld under ``UNIFI_REDACT_SECRETS``, so the node's id
    would appear and vanish with that setting; the MAC is therefore not the
    ``source_id`` directly. Instead hash ``kind`` + the
    normalized MAC with SHA-256 and expose a short, prefixed slice of the digest. This
    is deterministic (same MAC -> same id, stable across snapshots). The
    ``smdev-`` prefix guarantees the value is never a bare 12-hex string and makes its
    derived origin explicit. The MAC itself is the node's separate ``mac`` field.

    The digest is unkeyed, so it is only a display form of the MAC, not a secret: a MAC
    has 24 unknown bits once its OUI is guessed, and anyone holding the id can recover
    the MAC by hashing every candidate. It is therefore emitted only with redaction off,
    when the MAC itself is in the snapshot too; :func:`_inventory_item` withholds the
    whole record under ``UNIFI_REDACT_SECRETS`` instead.
    """
    mac = item.get("mac")
    if not isinstance(mac, str):
        return None
    normalized = mac.strip().casefold()
    if not normalized:
        return None
    digest = hashlib.sha256(f"{kind}\x00{normalized}".encode()).hexdigest()
    return f"smdev-{digest[:24]}"


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


def _device_type_text(item: dict[str, Any]) -> str:
    """Casefolded model+name text used only for device-type/icon classification.

    Uses the raw model/name fields (not the sanitized snapshot values) so a model
    string is still classifiable even if sanitization would elide it; the output is
    a closed enum member, so no controller identity can leak through this path.
    """
    parts: list[str] = []
    for key in _MODEL_LOOKUP_KEYS:
        value = item.get(key)
        if isinstance(value, str):
            parts.append(value)
    return " ".join(parts).casefold()


def _derive_device_type(item: dict[str, Any], kind: str) -> str:
    """Derive a closed-enum device type from ``kind`` plus model/name heuristics.

    Deterministic and total: an unrecognized device resolves to ``"unknown"`` and
    the panel still renders a generic marker. The heuristics are ordered so the
    most specific token wins; they intentionally match on product-family tokens
    (USW, UDM, U6/U7, G4, ...) rather than any identity field.
    """
    text = _device_type_text(item)
    if kind == "protect_camera":
        return "doorbell" if "doorbell" in text else "camera"
    if kind == "protect_sensor":
        if "motion" in text:
            return "motion_sensor"
        if "presence" in text or "mmwave" in text or "-ep" in text or " ep " in text:
            return "presence_sensor"
        return "sensor"
    # network_device (Site Manager infrastructure) and any other kind.
    if "doorbell" in text:
        return "doorbell"
    if "siren" in text or "chime" in text:
        return "chime"
    if "usw" in text or "us-" in text or "switch" in text:
        return "switch"
    if (
        "udm" in text
        or "uxg" in text
        or "usg" in text
        or "ucg" in text
        or "u5g" in text
        or "gateway" in text
        or "dream machine" in text
        or "dream router" in text
        or "5g modem" in text
    ):
        return "gateway"
    if "u6" in text or "u7" in text or "uap" in text or "uwb" in text or "uwe" in text:
        return "access_point"
    camera_tokens = ("uvc", "g3 ", "g4 ", "g5 ", "g6 ", " ai ", "ai bullet", "ai dsm")
    if any(token in text for token in camera_tokens):
        return "camera"
    return "unknown"


def _fingerprint_icon(item: dict[str, Any]) -> dict[str, Any] | None:
    """Return the ``unifi_fingerprint`` icon descriptor for a curated deployment model.

    Shape is ``{"kind": "unifi_fingerprint", "id": <int>}`` — the id is a UniFi
    product fingerprint the consumer resolves to a locally cached PNG. Unknown
    models omit the icon so the MDI fallback (keyed on ``device_type``) is used.

    Resolves the model from the same ordered field set as ``_device_type_text``:
    Protect cameras/sensors expose their model under ``type`` (not ``model``), so
    reading only ``model`` left every Protect device without an icon even though
    the curated table had a match. Each candidate is exact-matched (casefolded)
    against the table, so a mere display name never fabricates an icon.
    """
    for key in _MODEL_LOOKUP_KEYS:
        value = item.get(key)
        if not isinstance(value, str):
            continue
        fingerprint_id = _MODEL_FINGERPRINT_IDS.get(value.strip().casefold())
        if fingerprint_id is not None:
            return {"kind": "unifi_fingerprint", "id": fingerprint_id}
    return None


def _unredacted_source_id(item: dict[str, Any], kind: str) -> str | None:
    """The ``source_id`` :func:`_inventory_item` gives ``item`` with redaction off: its
    ``id``, else its ``deviceId`` (verbatim, non-blank strings), else the
    :func:`_derived_source_id`. Used only to recognise duplicates, never emitted."""
    for key in ("id", "deviceId"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return _derived_source_id(item, kind)


def _id_withhold_reason(plain_id: str | None) -> str | None:
    """Why the redaction-off ``plain_id`` (:func:`_unredacted_source_id`) is withheld in
    the current snapshot, or None (always None with redaction off)."""
    if plain_id is None or not _REDACT.get():
        return None
    return _withhold_reason(plain_id.strip())


def _inventory_item(item: object, kind: str) -> dict[str, Any] | None:
    """Project an inventory item onto a v1 topology record.

    ``mac`` (Protect cameras/sensors and Site Manager devices) and ``ip`` (Site Manager
    devices) are the upstream strings verbatim; under ``UNIFI_REDACT_SECRETS`` they are
    left out and counted under ``_withheld``.

    A record whose only identity is its MAC gets the :func:`_derived_source_id` with
    redaction off. Under ``UNIFI_REDACT_SECRETS`` that id would reveal the withheld MAC
    (it is an unkeyed hash of it) and schema v1 requires a ``source_id``, so the whole
    record is left out and counted under ``_withheld`` as ``topology.record`` /
    ``hardware_address``.
    """
    if not isinstance(item, dict):
        _note_unprojected("topology.record", "not_an_object")
        return None
    if (
        _REDACT.get()
        and _string(item.get("id")) is None
        and _string(item.get("deviceId")) is None
        and _derived_source_id(item, kind) is not None
    ):
        # One count for the whole record; its fields are not counted again.
        _note_withheld("topology.record", "hardware_address")
        return None
    source_id = _string(item.get("id"), "topology.source_id") or _string(
        item.get("deviceId"), "topology.source_id"
    )
    if source_id is None:
        source_id = _string(_derived_source_id(item, kind))
    output: dict[str, Any] = {
        "kind": kind,
        "source_id": source_id,
        "display_name": _display_name(item, "topology"),
        "model": _string(item.get("model"), "topology.model")
        or _string(item.get("type"), "topology.model"),
        "device_type": _derive_device_type(item, kind),
        "mac": _address_field(item.get("mac"), "topology.mac", "hardware_address"),
        "ip": _address_field(item.get("ip"), "topology.ip", "network_address"),
    }
    icon = _fingerprint_icon(item)
    if icon is not None:
        output["icon"] = icon
    return {key: value for key, value in output.items() if value is not None}


def _topology_inventory(
    *,
    cameras: object,
    sensors: object,
    network_devices: list[Any],
) -> list[dict[str, Any]]:
    """Project the three inventory sources into a de-duplicated topology list.

    Protect cameras and sensors are emitted first under their real kind. Site
    Manager also lists that same Protect hardware, so a ``network_device`` whose
    ``source_id`` was already emitted by the Protect pass is a duplicate of a
    real-kind node and is dropped. A unique normalized MAC in each source also
    identifies the same hardware; ambiguous MAC collisions stay separate.
    The v1 schema requires ``source_id``
    to be unique within the collection. A ``network_device`` that yields no stable
    ``source_id`` is likewise left out (counted under ``_unprojected`` as ``topology.record`` /
    ``no_source_id``) rather than emitted with a null id. An inventory entry that is not an
    object is counted as ``topology.record`` / ``not_an_object``.

    Nothing disappears silently under ``UNIFI_REDACT_SECRETS``: a ``network_device`` that
    is in the topology with redaction off but has to be left out under it (its id is
    withheld with no usable fallback, or the id it falls back to is already emitted) is
    counted once under ``_withheld`` as ``topology.record``, with the reason its own id
    is withheld or, when its own id is kept but another record's ``deviceId`` fallback
    took it, the reason that record's id is withheld.
    """

    def normalized_mac(item: Any) -> str | None:
        mac = item.get("mac") if isinstance(item, dict) else None
        if not isinstance(mac, str):
            return None
        mac = mac.strip()
        if not (_MAC_ADDRESS_RE.fullmatch(mac) or _BARE_MAC_ADDRESS_RE.fullmatch(mac)):
            return None
        return mac.replace(":", "").replace("-", "").casefold()

    protect_counts: dict[str, int] = {}
    network_counts: dict[str, int] = {}
    for source, counts in (
        (cameras, protect_counts),
        (sensors, protect_counts),
        (network_devices, network_counts),
    ):
        if isinstance(source, list):
            for item in source:
                mac = normalized_mac(item)
                if mac:
                    counts[mac] = counts.get(mac, 0) + 1
    inventory: list[dict[str, Any]] = []
    # Duplicates are decided on the id each record gets with redaction off, so the same
    # records are dropped in either mode. Under redaction a MAC-only record is never
    # emitted (it is withheld whole), and its id still has to be remembered here, or a
    # second listing of the same MAC would be counted as a second withheld record.
    seen_source_ids: set[str] = set()
    # The ids actually emitted, which can differ from the redaction-off id under
    # redaction (a withheld ``id`` falls back to ``deviceId``); schema v1 requires them
    # to be unique within the collection. Each maps to why its record's redaction-off id
    # is withheld (None when the record is emitted under that id).
    emitted_source_ids: dict[str, str | None] = {}
    for kind, source in (
        ("protect_camera", cameras),
        ("protect_sensor", sensors),
        ("network_device", network_devices),
    ):
        if not isinstance(source, list):
            continue
        for item in source:
            with _pending_withheld() as pending:
                record = _inventory_item(item, kind)
            plain_id = _unredacted_source_id(item, kind) if isinstance(item, dict) else None
            source_id = record.get("source_id") if record is not None else None
            mac = normalized_mac(item)
            if kind == "network_device" and (
                (plain_id is not None and plain_id in seen_source_ids)
                or (mac and protect_counts.get(mac) == 1 and network_counts.get(mac) == 1)
            ):
                # The same hardware, already reported (e.g. under its Protect kind). This
                # is decided on raw data only, so the record is dropped with redaction off
                # too and its withheld counts are discarded: "unset UNIFI_REDACT_SECRETS to
                # receive the value" would be false for it.
                continue
            if plain_id is not None:
                seen_source_ids.add(plain_id)
            if (
                kind == "network_device"
                and record is not None
                and plain_id is not None
                and (not isinstance(source_id, str) or source_id in emitted_source_ids)
            ):
                # Present with redaction off (under ``plain_id``), but under redaction its
                # id is withheld with no usable fallback, or the id it is emitted under
                # collides with one already emitted. Count the whole record once, as a
                # MAC-only record is; its per-field counts are not counted again. A kept
                # own id can only collide with another record's fallback (an id emitted
                # as-is is in seen_source_ids), so a reason is always found.
                reason = _id_withhold_reason(plain_id)
                if reason is None and isinstance(source_id, str):
                    reason = emitted_source_ids.get(source_id)
                _note_withheld("topology.record", reason or "network_address")
                continue
            _commit_withheld(pending)
            if record is None:
                continue  # not an object, or a MAC-only record withheld whole
            if kind == "network_device" and not isinstance(source_id, str):
                _note_unprojected("topology.record", "no_source_id")
                continue
            if isinstance(source_id, str):
                emitted_source_ids[source_id] = _id_withhold_reason(plain_id)
            inventory.append(record)
    return inventory


def _list_records(list_result: Any) -> list[Any]:
    """The records of a list tool's result: ``result`` (a bare upstream array, e.g. the
    Protect camera and sensor lists) or ``data`` (an enveloped one, e.g. the Site Manager
    device list)."""
    if not isinstance(list_result, dict):
        return []
    for key in ("result", "data"):
        records = list_result.get(key)
        if isinstance(records, list):
            return records
    return []


def _network_devices(devices_result: dict[str, Any]) -> list[Any]:
    """Flatten Site-Manager host-grouped device wrappers into individual records.

    The Site Manager ``/v1/devices`` endpoint groups devices by console: each item
    is a wrapper of the shape ``{"hostId": ..., "hostName": ..., "devices": [...]}``,
    not a device.  Projecting the wrapper directly finds no ``id``/name/model on it,
    so the whole network-device category collapses to a single identity-less node.
    Iterate the nested ``devices`` list so every real device becomes its own
    topology record.  Wrappers are read through the one shared reading
    (:func:`_device_wrappers.wrapper_devices`): a wrapper whose ``devices`` is null or
    absent contributes no device (it is never projected as a node), and a non-array
    ``devices`` raises naming the shape. An entry that is not a wrapper (a bare device) is
    passed through unchanged, so a flat upstream shape still works.
    """
    flattened: list[Any] = []
    for entry in _list_records(devices_result):
        inner = wrapper_devices(entry)
        if inner is None:
            flattened.append(entry)
        else:
            flattened.extend(inner)
    return flattened


def _unique_name_links(
    placed: list[dict[str, Any]], inventory: list[dict[str, Any]]
) -> list[dict[str, str]]:
    """Link only unique exact display-name matches; do not infer network identity."""
    placed_by_name: dict[str, list[dict[str, Any]]] = {}
    inventory_by_name: dict[str, list[dict[str, Any]]] = {}
    for item in placed:
        if isinstance(item.get("display_name"), str):
            placed_by_name.setdefault(item["display_name"].casefold(), []).append(item)
    for item in inventory:
        if isinstance(item.get("display_name"), str):
            inventory_by_name.setdefault(item["display_name"].casefold(), []).append(item)

    links: list[dict[str, str]] = []
    for name in sorted(set(placed_by_name) & set(inventory_by_name)):
        left, right = placed_by_name[name], inventory_by_name[name]
        if len(left) != 1 or len(right) != 1:
            continue
        source_id, placed_id = right[0].get("source_id"), left[0].get("source_id")
        if isinstance(source_id, str) and isinstance(placed_id, str):
            links.append(
                {
                    "inventory_source_id": source_id,
                    "placement_source_id": placed_id,
                    "match_method": "unique_exact_display_name",
                }
            )
    return links


def build_snapshot(
    *,
    project_result: dict[str, Any],
    cameras_result: dict[str, Any],
    sensors_result: dict[str, Any],
    devices_result: dict[str, Any],
    generated_at: datetime | None = None,
    redact_secrets: bool = False,
) -> dict[str, Any]:
    """Build the stable placement snapshot schema from four already-read source payloads.

    This is deliberately a pure projection onto a closed field selection (unknown
    upstream keys are not copied). By default every projected string is the upstream
    value verbatim, including the address (``mac``, ``ip``) and floor-plan asset-URL
    fields. With ``redact_secrets`` (``UNIFI_REDACT_SECRETS``) those fields, and any
    string that is a URL, carries an IP / MAC address or a credential marker, are left
    out and counted under ``_withheld``.

    ``_withheld`` (``{"<section>.<field>": {"<reason>": count}}``) is present only under
    redaction; ``_withheld_how_to_obtain`` then carries, for each of its keys, how to get
    the value: turn ``UNIFI_REDACT_SECRETS`` off, or read it verbatim from the named
    source tool. Records that cannot be represented in schema v1 (a non-object entry, a
    device without a position, ...) are counted, in either mode, under the separate
    additive ``_unprojected`` key (same shape), with ``_unprojected_how_to_obtain`` naming
    the verbatim read tool for each of its keys.
    """
    observed = generated_at or datetime.now(UTC)
    if observed.tzinfo is None:
        raise ValueError("generated_at must be timezone-aware")
    withheld: dict[str, dict[str, int]] = {}
    unprojected: dict[str, dict[str, int]] = {}
    token = _WITHHELD.set(withheld)
    unprojected_token = _UNPROJECTED.set(unprojected)
    redact_token = _REDACT.set(bool(redact_secrets))
    try:
        snapshot = _project_snapshot(
            observed,
            project_result=project_result,
            cameras_result=cameras_result,
            sensors_result=sensors_result,
            devices_result=devices_result,
        )
    finally:
        _REDACT.reset(redact_token)
        _UNPROJECTED.reset(unprojected_token)
        _WITHHELD.reset(token)
    if unprojected:
        snapshot["_unprojected"] = unprojected
        snapshot["_unprojected_how_to_obtain"] = _unprojected_how_to_obtain(unprojected)
    if withheld:
        snapshot["_withheld"] = withheld
        snapshot["_withheld_how_to_obtain"] = _withheld_how_to_obtain(withheld)
    return snapshot


def _project_snapshot(
    observed: datetime,
    *,
    project_result: dict[str, Any],
    cameras_result: dict[str, Any],
    sensors_result: dict[str, Any],
    devices_result: dict[str, Any],
) -> dict[str, Any]:
    """The projection itself; values it leaves out are counted by the caller's collector."""
    project = project_result.get("project") if isinstance(project_result, dict) else None
    project = project if isinstance(project, dict) else {}

    shapes = _objects(project.get("shapes", []), "shapes")
    scale_by_plan = _scale_shapes_by_plan(shapes)
    map_by_plan = _map_shapes_by_plan(shapes)
    floors = [
        _floor(plan, scale_by_plan, map_by_plan)
        for plan in _objects(project.get("plans", []), "floors")
    ]
    floors.sort(key=lambda floor: (floor.get("ordering", 0), floor.get("display_name", "")))
    placed: list[dict[str, Any]] = []
    walls: list[dict[str, Any]] = []
    for shape in shapes:
        if shape.get("type") == "device":
            record = _placed_device(shape)
            if record is None:
                _note_unprojected("placed_devices.record", "no_position")
            else:
                placed.append(record)
        elif shape.get("type") == "wall":
            record = _wall(shape)
            if record is None:
                _note_unprojected("walls.record", "no_geometry")
            else:
                walls.append(record)
    inventory = _topology_inventory(
        cameras=_list_records(cameras_result),
        sensors=_list_records(sensors_result),
        network_devices=_network_devices(devices_result),
    )

    observed_at = observed.astimezone(UTC).isoformat().replace("+00:00", "Z")
    project_meta_raw = project.get("project")
    project_meta: dict[Any, Any] = project_meta_raw if isinstance(project_meta_raw, dict) else {}
    upstream_updated_at = _string(
        project_meta.get("updatedAt"), "provenance.innerspace_project_updated_at"
    )
    provenance: dict[str, Any] = {
        "source": "unifi-fabric-mcp-server",
        "approved_read_sources": list(APPROVED_READ_SOURCES),
        "read_only": True,
    }
    if upstream_updated_at:
        provenance["innerspace_project_updated_at"] = upstream_updated_at

    snapshot: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": observed_at,
        "freshness": {
            "observed_at": observed_at,
            "max_age_seconds": FRESHNESS_TTL_SECONDS,
            "cache": "none",
        },
        "provenance": provenance,
        "floors": floors,
        "walls": walls,
        "placed_devices": placed,
        "topology": inventory,
        "placement_links": _unique_name_links(placed, inventory),
    }
    # A source list that stopped short (opt-in page cap, repeated or cycling cursor) makes
    # the snapshot partial: say so instead of presenting it as complete.
    reasons = [
        f"{name}: {context_value(result, 'incompleteReason') or 'incomplete'}"
        for name, result in (
            ("innerspace.project.3d", project_result),
            ("protect.cameras", cameras_result),
            ("protect.sensors", sensors_result),
            ("site_manager.devices", devices_result),
        )
        if isinstance(result, dict) and context_value(result, "incomplete")
    ]
    if reasons:
        snapshot["incomplete"] = True
        snapshot["incompleteReason"] = "; ".join(reasons)
    return snapshot


async def _innerspace_project(client: UniFiClient, registry: Registry, host: str) -> dict[str, Any]:
    """The 3D InnerSpace project in the shape :func:`build_snapshot` takes.

    ``{"project": <project object>}``: the object out of its ``data`` envelope, read with
    the same GET-only fetch (and shape check) the InnerSpace tools use.
    """
    return {"project": await innerspace.fetch_project(client, registry, host, "3D")}


async def get_unifi_placement_snapshot(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """Fetch the four approved GET-only sources and return one placement snapshot.

    Withholding follows the client's own settings: on only with ``UNIFI_REDACT_SECRETS``
    (the same switch the MCP tool and both CLI subcommands load).
    """
    # A failing source cancels (and awaits) the others: no request outlives the call.
    project, cameras, sensors, devices = await gather_or_cancel(
        _innerspace_project(client, registry, host),
        protect.list_cameras(client, registry, host),
        protect.list_sensors(client, registry, host),
        site_manager.list_devices(client, registry, host=host),
    )
    return build_snapshot(
        project_result=project,
        cameras_result=cameras,
        sensors_result=sensors,
        devices_result=devices,
        redact_secrets=_redact_enabled(client),
    )


def _redact_enabled(client: UniFiClient) -> bool:
    """Whether the client's settings opt in to ``UNIFI_REDACT_SECRETS`` (exactly ``True``)."""
    settings = getattr(client, "_settings", None)
    return getattr(settings, "redact_secrets", False) is True


def _capability_outcome(exc: BaseException) -> dict[str, str]:
    """Classify a failed approved read and carry its complete error text.

    ``outcome`` is the coarse, stable class a scheduler gate branches on
    (``auth_denied`` / ``unavailable`` / ``error``); ``error`` is the exception's type and
    full message (for a UniFi client error: the request, the HTTP status and the upstream
    body, credential fields masked only under ``UNIFI_REDACT_SECRETS``), so an operator can
    see why the source failed.
    """
    message = innerspace.exception_message(exc).casefold()
    status_code = getattr(exc, "status_code", None)
    if (
        getattr(exc, "status", None) in (401, 403)
        or status_code in (401, 403)
        or re.match(r"^http (?:401|403)\b", message)
    ):
        outcome = "auth_denied"
    elif isinstance(exc, (UniFiConnectionError, RateLimitError)):
        outcome = "unavailable"
    else:
        outcome = "error"
    return {
        "outcome": outcome,
        "error": f"{type(exc).__name__}: {innerspace.exception_message(exc)}",
    }


async def preflight_placement_snapshot_capabilities(
    client: UniFiClient,
    registry: Registry,
    host: str,
) -> dict[str, Any]:
    """Inspect every approved placement snapshot source using its existing GET-only collector.

    Each capability is ``{name, outcome}``; a failed one adds ``error`` with the complete
    error text (see :func:`_capability_outcome`). No successful response payload is
    included. This is deliberately not a best-effort snapshot: an unavailable source
    remains a failed capability and never triggers a direct inventory or controller
    fallback.
    """
    reads = (
        (
            "innerspace.project.3d",
            _innerspace_project(client, registry, host),
        ),
        ("protect.cameras", protect.list_cameras(client, registry, host)),
        ("protect.sensors", protect.list_sensors(client, registry, host)),
        ("site_manager.devices", site_manager.list_devices(client, registry, host=host)),
    )
    results = await asyncio.gather(*(request for _name, request in reads), return_exceptions=True)
    capabilities = [
        {"name": name, "outcome": "ok"}
        if not isinstance(result, BaseException)
        else {"name": name, **_capability_outcome(result)}
        for (name, _request), result in zip(reads, results, strict=True)
    ]
    return {
        "schema_version": PLACEMENT_SNAPSHOT_CAPABILITY_SCHEMA_VERSION,
        "read_only": True,
        "required_capabilities": list(APPROVED_READ_SOURCES),
        "capabilities": capabilities,
    }


# Tool modules the wrappers below delegate to, imported after this module's
# own definitions so a module importing from this one never sees it half-built.
from . import placement_snapshot  # noqa: E402


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> dict[str, Callable[..., Any]]:
    """Register the placement_snapshot tool wrappers moved from server.py, in order.

    Returns the registered wrapper functions by name; server.py re-exports them.
    """

    @mcp.tool(
        annotations=READ_ONLY,
        output_schema=output_schemas.SELF_BUILT["get_unifi_placement_snapshot"],
    )
    async def get_unifi_placement_snapshot(host: str) -> dict[str, Any]:
        """Return a bounded, read-only UniFi topology and placement projection
        (unifi.placement-snapshot/v1).

        Unlike the other tools' whole upstream bodies, this closed schema selects, renames and
        derives fields: a MAC-only device gets a SHA-256 source_id (withheld under redaction);
        device_type is a closed enum.
        Projected strings retain upstream values. GET-backed sources are InnerSpace 3D placement,
        Protect cameras/sensors and Site Manager inventory; no connector writes occur. Provenance
        includes a 120-second freshness contract.

        Returns schema_version, generated_at, freshness, provenance, floors, walls,
        placed_devices, topology and placement_links, plus incomplete/incompleteReason if a source
        list stops short. Address/asset fields are included by default (topology/placed_devices
        ip/mac and floor image/model/zip/bin URLs). Only opt-in UNIFI_REDACT_SECRETS removes
        address/asset fields and strings identified as URL/IP/MAC/credential markers. Every removed
        value is counted in _withheld (section.field/reason); _withheld_how_to_obtain names its
        source tool or instructs disabling redaction. Both are absent with redaction off.

        In either mode, records outside schema v1 (not_an_object, no_position, no_geometry,
        no_source_id, not_numeric) are counted in _unprojected; _unprojected_how_to_obtain names the
        full source read tool. Duplicate Network devices are merged onto Protect nodes; their
        Network-only fields are omitted. For full payloads use
        get_innerspace_project, list_innerspace_devices, list_cameras, list_sensors or list_devices.
        Full field reference: docs/TOOL-USAGE.md#get_unifi_placement_snapshot.

        Required arguments: host (see parameter descriptions for identifiers).

        Args:
            host: Console name or id: the short name from list_hosts (data[].reportedState.hostname or
                reportedState.name, case-insensitive, e.g. "my-console") or the long data[].id
                (MAC:numericId composite). One console serves both Network and Protect.
        """
        client, registry = deps_fn()
        return await placement_snapshot.get_unifi_placement_snapshot(client, registry, host)

    return {"get_unifi_placement_snapshot": get_unifi_placement_snapshot}
