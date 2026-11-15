"""The per-tool security facts frozen before the public #42 step 6 switch.

The step 6 switch moves catalog membership from the source derivation to the explicit
inventory (``catalog/membership.py``) and adds the ``module:`` exclusion. It must not move
any security decision. This module captures, for every registered tool (full mode plus the
five discovery meta tools), the facts those decisions read:

* ``family`` and ``module``: the selection family (``UNIFI_FAMILY_ALLOW``, ``family:``
  exclusions, write exceptions and the ``tool_id`` of every policy record) and the
  sub-area module key;
* ``annotations``: the four MCP hints, which decide read-only hiding;
* ``policy``: the call-sensitive policy of the catalog inventory (read or write, by
  argument, confirmation, ``dry_run`` and the write families), itself proved against the
  runtime write decision by :func:`unifi_fabric.catalog.inventory.validate_inventory`;
* ``redacted``: the handler carries the opt-in credential-redaction wrapper;
* ``connector_write``: the tool is governed by ``family:connector=deny``.

``tests/fixtures/security_equivalence.json`` holds them as captured on the pre-switch head
(the parent of the switch commit); ``tests/test_security_equivalence.py`` captures
them again and requires equality.

Regenerate only for a reviewed, intended change::

    python -m tests.security_equivalence --write
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "security_equivalence.json"
HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


def capture() -> dict[str, Any]:
    """The security facts of every registered tool, by name, in registration order."""
    from unifi_fabric import families
    from unifi_fabric.catalog import META_FAMILY
    from unifi_fabric.catalog.inventory import inventory_from, runtime_view
    from unifi_fabric.redaction import _WRAPPED_FLAG

    view = asyncio.run(runtime_view())
    inventory = inventory_from(view)
    family_index = families.build_family_index()
    module_index = families.build_module_index()
    connector = families.connector_write_tools()
    tools: dict[str, Any] = {}
    for spec in inventory.tools:
        annotations = json.loads(json.dumps(spec.listed().get("annotations") or {}))
        tools[spec.name] = {
            "family": family_index.get(spec.name, META_FAMILY),
            "module": module_index.get(spec.name),
            "annotations": {hint: annotations.get(hint) for hint in HINTS},
            "policy": spec.policy.to_dict(),
            "redacted": bool(getattr(view.tools[spec.name].fn, _WRAPPED_FLAG, False)),
            "connector_write": spec.name in connector,
        }
    return {"tools": tools}


def dumps(facts: dict[str, Any]) -> str:
    """One line per tool, in registration order, so a difference reads as one line."""
    rows = [
        f"  {json.dumps(name)}: {json.dumps(row, ensure_ascii=False, separators=(',', ':'))}"
        for name, row in facts["tools"].items()
    ]
    return '{"tools": {\n' + ",\n".join(rows) + "\n}}\n"


def load_fixture() -> dict[str, Any]:
    """The frozen pre-switch capture."""
    result: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return result


def differences(base: dict[str, Any], head: dict[str, Any]) -> list[str]:
    """Each tool whose facts differ, with the differing keys; added and removed tools."""
    out: list[str] = []
    a, b = base["tools"], head["tools"]
    out += [f"{name}: removed" for name in a if name not in b]
    out += [f"{name}: added" for name in b if name not in a]
    for name in a:
        if name in b and a[name] != b[name]:
            keys = sorted(k for k in {*a[name], *b[name]} if a[name].get(k) != b[name].get(k))
            out += [f"{name}: {k} was {a[name].get(k)!r}, is {b[name].get(k)!r}" for k in keys]
    if not out and list(a) != list(b):
        out.append("the registration order differs")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tests.security_equivalence")
    parser.add_argument("--write", action="store_true", help="rewrite the frozen fixture")
    args = parser.parse_args(argv)
    text = dumps(capture())
    if args.write:
        FIXTURE.write_text(text, encoding="utf-8")
        return 0
    if FIXTURE.read_text(encoding="utf-8") != text:
        print("security facts differ from the frozen fixture", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
