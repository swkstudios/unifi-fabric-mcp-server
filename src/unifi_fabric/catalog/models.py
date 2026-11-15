"""Typed catalog metadata: :class:`ToolSpec`, :class:`FamilySpec` and :class:`CallPolicy`.

These are the records of the catalog inventory (:mod:`unifi_fabric.catalog.inventory`).
They sit alongside the current registration and change nothing at runtime: the server
still registers every tool through the family ``register`` functions that ``server.py``
calls, and no runtime module reads these records.

A :class:`ToolSpec` declares one public tool: its name, family, title, description, input
and output schema (as ``tools/list`` emits them), annotations, handler target, the
registration step that registers it, and its call-sensitive :class:`CallPolicy`. A
:class:`FamilySpec` declares one family: its stable identifier, its tools, the other
families its registration steps import, and its loader (those registration steps, in
order).

This is not the row of the committed ``catalog.json`` build output
(:class:`unifi_fabric.catalog.ToolSpec`); the inventory records that row's ``handler``
and ``family`` and is checked against it.

Call-sensitive policy. A policy decision about a call can depend on its arguments, so
:class:`CallPolicy` never flattens a tool to a family-wide label:

* ``access`` is ``read`` or ``write`` when every call of the tool is one or the other, and
  ``by_argument`` when the call's arguments decide (``rule`` and ``decided_by`` say how):

  - ``state_changing_get_route``: the generic GET relay reads unless its ``path`` is a
    route the upstream acts on (:func:`unifi_fabric.read_only.is_write_request`);
  - ``dispatch_target``: a discovery dispatcher's call is judged as the call it makes,
    the tool its ``name`` argument names with its ``arguments``.

* ``target_argument`` names the argument whose tool's exposure and write policy apply to
  the call (the targeted discovery meta tools).
* ``confirmation_required`` is true only for a tool whose schema requires a ``confirm``
  argument that reaches it. ``confirm_argument`` says whether the schema declares
  ``confirm`` at all; a declared one is ``ignored`` (the call runs when made).
* ``dry_run_argument`` names a write tool's own preview argument, if it has one. Every
  write also follows the ``dry-run`` write policy.
* ``write_families`` are the ``family:<id>`` write exceptions that reach the tool's
  writes, its own family first (:func:`unifi_fabric.switches.governing_families`).

Nothing here is hand-set: :mod:`unifi_fabric.catalog.inventory` derives every field from
the source verb audit, the registered schemas and the runtime policy tables, then checks
each spec against the runtime's own write decision.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from . import META_FAMILY, _freeze, _thaw

Access = Literal["read", "write", "by_argument"]
ACCESS_VALUES: tuple[str, ...] = ("read", "write", "by_argument")

ArgumentRule = Literal["state_changing_get_route", "dispatch_target"]
ARGUMENT_RULES: tuple[str, ...] = ("state_changing_get_route", "dispatch_target")

ConfirmArgument = Literal["absent", "ignored"]

#: Whether a client may run the tool as an MCP background task (public #45): ``optional``
#: for the long multi-site reads (:data:`unifi_fabric.background_tasks.TASK_OPTIONAL_TOOLS`),
#: ``forbidden`` for every other tool. No tool is ``required``.
TaskMode = Literal["forbidden", "optional", "required"]
TASK_MODES: tuple[str, ...] = ("forbidden", "optional", "required")

#: The ``tools/list`` fields every :meth:`ToolSpec.listed` entry carries, in order, and the
#: two it carries where the tool has them. Together, every field ``tools/list`` emits.
LISTED_KEYS: tuple[str, ...] = ("name", "description", "inputSchema", "outputSchema", "annotations")
LISTED_OPTIONAL_KEYS: tuple[str, ...] = ("title", "_meta")

#: Why an inventory failed validation, in the order :func:`inventory.validate_inventory`
#: checks them.
INVENTORY_REASONS: tuple[str, ...] = (
    "invalid_spec",
    "duplicate_tool",
    "missing_tool",
    "unknown_tool",
    "field_mismatch",
    "family_mismatch",
    "policy_mismatch",
)

#: Resolves a public tool name to its spec (None for an unknown name).
Resolver = Callable[[str], "ToolSpec | None"]


class InventoryError(ValueError):
    """An inventory failed validation; ``reason`` is one of :data:`INVENTORY_REASONS`."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"catalog:inventory:{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True, slots=True)
class CallPolicy:
    """The policy facts of one tool's calls, which may depend on the call's arguments."""

    access: Access
    write_verbs: tuple[str, ...] = ()
    rule: ArgumentRule | None = None
    decided_by: tuple[str, ...] = ()
    target_argument: str | None = None
    confirmation_required: bool = False
    confirm_argument: ConfirmArgument = "absent"
    dry_run_argument: str | None = None
    write_families: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        problem = self.problem()
        if problem:
            raise InventoryError("invalid_spec", problem)

    def problem(self) -> str | None:
        """Why this policy is not well formed, or None."""
        if self.access not in ACCESS_VALUES:
            return f"access {self.access!r} is not one of {', '.join(ACCESS_VALUES)}"
        if (self.access == "by_argument") != (self.rule is not None):
            return "a rule is set exactly when access is by_argument"
        if self.rule is not None and self.rule not in ARGUMENT_RULES:
            return f"rule {self.rule!r} is not one of {', '.join(ARGUMENT_RULES)}"
        if (self.rule is None) == bool(self.decided_by):
            return "decided_by names the deciding arguments exactly when a rule is set"
        if self.access == "read" and (self.write_verbs or self.write_families):
            return "a read has no write verbs and no write exceptions"
        if self.access == "read" and self.dry_run_argument is not None:
            return "a read has no dry-run argument"
        if self.access == "write" and not self.write_verbs:
            return "a write issues at least one write verb"
        if self.confirm_argument not in ("absent", "ignored"):
            return f"confirm_argument {self.confirm_argument!r} is not absent or ignored"
        if self.confirmation_required and self.confirm_argument == "ignored":
            return "an ignored confirm argument cannot be required"
        if tuple(sorted(self.write_verbs)) != self.write_verbs:
            return "write_verbs are sorted"
        return None

    def writes(self, arguments: Mapping[str, Any], resolve: Resolver) -> bool:
        """Whether a call with ``arguments`` is a write, by this policy.

        ``resolve`` finds the spec of a dispatcher's target. An unknown or meta target is
        not a write here: the policy step leaves it to the dispatcher's own error.
        """
        if self.access != "by_argument":
            return self.access == "write"
        if self.rule == "state_changing_get_route":
            from ..read_only import is_write_request

            path = arguments.get(self.decided_by[0])
            return isinstance(path, str) and is_write_request("GET", path)
        target = arguments.get(self.decided_by[0])
        if not isinstance(target, str):
            return False
        spec = resolve(target)
        if spec is None or spec.family == META_FAMILY:
            return False
        inner = arguments.get(self.decided_by[1]) if len(self.decided_by) > 1 else None
        return spec.policy.writes(inner if isinstance(inner, Mapping) else {}, resolve)

    def to_dict(self) -> dict[str, Any]:
        """The policy as a JSON-ready object (field order fixed)."""
        return {
            "access": self.access,
            "write_verbs": list(self.write_verbs),
            "rule": self.rule,
            "decided_by": list(self.decided_by),
            "target_argument": self.target_argument,
            "confirmation_required": self.confirmation_required,
            "confirm_argument": self.confirm_argument,
            "dry_run_argument": self.dry_run_argument,
            "write_families": list(self.write_families),
        }


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """One public tool, as the catalog inventory declares it (immutable).

    ``input_schema``, ``output_schema`` (None where the tool declares none), ``title``,
    ``description``, ``annotations`` and ``meta`` (the ``_meta`` object) are what
    full-mode ``tools/list`` emits (discovery mode for the five discovery meta tools).
    ``handler`` is the catalog's HandlerRef; ``loader`` is the registration step,
    ``<module>:<function>``. ``task_mode`` says whether a client may run the tool as an MCP
    background task (:data:`TaskMode`): ``optional`` for the long multi-site reads, else
    ``forbidden``.
    """

    name: str
    family: str
    title: str | None
    description: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any] | None
    annotations: Mapping[str, Any]
    meta: Mapping[str, Any] | None
    handler: str
    loader: str
    policy: CallPolicy
    task_mode: TaskMode = "forbidden"

    @classmethod
    def build(
        cls,
        *,
        name: str,
        family: str,
        title: str | None,
        description: str,
        input_schema: Mapping[str, Any],
        output_schema: Mapping[str, Any] | None,
        annotations: Mapping[str, Any],
        meta: Mapping[str, Any] | None,
        handler: str,
        loader: str,
        policy: CallPolicy,
        task_mode: TaskMode = "forbidden",
    ) -> ToolSpec:
        """A spec whose mappings are frozen copies of the given ones."""
        return cls(
            name=name,
            family=family,
            title=title,
            description=description,
            input_schema=_freeze(input_schema),
            output_schema=None if output_schema is None else _freeze(output_schema),
            annotations=_freeze(annotations),
            meta=None if meta is None else _freeze(meta),
            handler=handler,
            loader=loader,
            policy=policy,
            task_mode=task_mode,
        )

    def to_dict(self) -> dict[str, Any]:
        """The spec as a JSON-ready object (field order fixed)."""
        return {
            "name": self.name,
            "family": self.family,
            "title": self.title,
            "description": self.description,
            "input_schema": _thaw(self.input_schema),
            "output_schema": None if self.output_schema is None else _thaw(self.output_schema),
            "annotations": _thaw(self.annotations),
            "meta": None if self.meta is None else _thaw(self.meta),
            "handler": self.handler,
            "loader": self.loader,
            "policy": self.policy.to_dict(),
            "task_mode": self.task_mode,
        }

    def listed(self) -> dict[str, Any]:
        """The tool's ``tools/list`` entry: :data:`LISTED_KEYS`, then ``title`` and
        ``_meta`` where the tool has them (the behaviour baseline's entry shape)."""
        entry: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "inputSchema": _thaw(self.input_schema),
            "outputSchema": None if self.output_schema is None else _thaw(self.output_schema),
            "annotations": _thaw(self.annotations),
        }
        if self.title is not None:
            entry["title"] = self.title
        if self.meta is not None:
            entry["_meta"] = _thaw(self.meta)
        return entry


@dataclass(frozen=True, slots=True)
class FamilySpec:
    """One family: stable id, tools, dependencies and loader (immutable).

    ``tools`` are the family's public names in registration order. ``loader`` is the
    ordered registration steps (``<module>:<function>``) that register them; a step may
    register tools of several families (the firewall tools are split out of network
    modules by route). ``dependencies`` are the other families whose packages those steps'
    modules live in or import directly, sorted. ``selectable`` is false only for the
    reserved ``meta`` family, which no profile selects.
    """

    id: str
    tools: tuple[str, ...]
    dependencies: tuple[str, ...]
    loader: tuple[str, ...]
    selectable: bool = True

    def to_dict(self) -> dict[str, Any]:
        """The family as a JSON-ready object (field order fixed)."""
        return {
            "id": self.id,
            "tools": list(self.tools),
            "dependencies": list(self.dependencies),
            "loader": list(self.loader),
            "selectable": self.selectable,
        }


@dataclass(frozen=True, slots=True)
class Inventory:
    """The catalog inventory: every public tool once, and every family.

    ``tools`` are in registration order: full-mode ``tools/list`` order, then the five
    discovery meta tools in discovery-mode order. ``families`` are the 13 families in
    sorted order, then ``meta``.
    """

    tools: tuple[ToolSpec, ...]
    families: tuple[FamilySpec, ...] = field(default_factory=tuple)

    def by_name(self) -> dict[str, ToolSpec]:
        """Specs keyed by public tool name (the last one wins for a duplicate name)."""
        return {spec.name: spec for spec in self.tools}

    def resolver(self) -> Resolver:
        """A :data:`Resolver` over this inventory."""
        return self.by_name().get

    def family(self, family_id: str) -> FamilySpec:
        """The family ``family_id`` (KeyError when the inventory has none)."""
        for spec in self.families:
            if spec.id == family_id:
                return spec
        raise KeyError(family_id)

    def to_dict(self) -> dict[str, Any]:
        """The inventory as a JSON-ready object."""
        return {
            "tools": [spec.to_dict() for spec in self.tools],
            "families": [spec.to_dict() for spec in self.families],
        }
