"""Within one collection, every update and delete resolves the target id the same way.

Some collections are written only after the target id is found in the collection's list
(the list-first families: Protect arm profiles, v2 device tags, Classic / v2 routes,
networkconf purposes ...); there an unknown id fails listing the valid ids and no write
is sent. Others forward the id and let the upstream decide. The two must never mix in one
collection: a delete that skips the lookup its update makes writes an id the update
would refuse.

Derived by behaviour over the whole catalog: every ``update_*`` / ``delete_*`` /
``patch_*`` tool is
called with its generated (known) target id, which locates the collection it writes, and
with an unknown id of the same form. Tools are grouped by (target id argument, written
collection). In every group either every tool sends no write for the unknown id (and
names the valid ids) and never writes a known id in the caller's spelling, or every tool
forwards it.
"""

from __future__ import annotations

import collections
import functools
import logging

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh

TOOLS = cti.TOOLS
_SCOPE_IDS = {"host_id", "site_id", "workspace_id", "console_id"}
_UNKNOWN_UUID = "00000000-0000-4000-8000-0000000000ee"
_UNKNOWN_HEX = "0000000000000000000000ee"


def _target(name: str) -> str | None:
    params = TOOLS[name].parameters or {}
    req = params.get("required", [])
    ids = [p for p in params.get("properties", {}) if p.endswith("_id") and p in req]
    ids = [p for p in ids if p not in _SCOPE_IDS]
    return ids[-1] if ids else None


@functools.cache
def _lz_ID_WRITES():
    return sorted(
        n
        for n in cti.WRITE_TOOLS
        if n.startswith(("update_", "delete_", "patch_")) and _target(n) is not None
    )


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _collection(path: str, ident: str) -> str:
    """The written collection: the path up to the target id segment (case-insensitive)."""
    parts = path.split("/")
    for i, seg in enumerate(parts):
        if seg.lower() == ident.lower():
            return "/".join(parts[:i])
    return path


async def _probe(monkeypatch, name: str) -> tuple[str, str]:
    """(collection, mode) for one tool; mode is ``list-first`` or ``forwards``."""
    arg = _target(name)
    assert arg is not None
    up = uh.FakeUpstream()
    uh.install(monkeypatch, up)
    args = tool_args.generated_args(TOOLS[name])
    known = str(args[arg])
    await cti._call(monkeypatch, name, up, args)
    writes = up.writes()
    assert writes, f"{name}: the known id sent no write (cannot locate its collection)"
    coll = _collection(writes[0].path, known)
    unknown = _UNKNOWN_HEX if len(known) == 24 else _UNKNOWN_UUID
    up = uh.FakeUpstream()
    try:
        await cti._call(monkeypatch, name, up, {**args, arg: unknown})
    except ToolError as exc:
        if not up.writes():
            assert unknown in str(exc) or "not found" in str(exc).lower(), (name, str(exc))
            # A list-first write addresses the record by the id the upstream listed, never
            # by the caller's (upper-case) spelling.
            up = uh.FakeUpstream()
            await cti._call(monkeypatch, name, up, {**args, arg: known.upper()})
            sent = [w.raw_path for w in up.writes()]
            assert sent, f"{name}: a known id in upper case sent no write"
            if known.upper() != known:
                assert all(known.upper() not in p for p in sent), f"{name}: sent {sent}"
            return coll, "list-first"
        raise
    assert up.writes(), f"{name}: the unknown id neither failed nor was written"
    return coll, "forwards"


async def test_update_and_delete_resolve_ids_alike_per_collection(monkeypatch):
    groups: dict[tuple[str, str], dict[str, str]] = collections.defaultdict(dict)
    for name in _lz_ID_WRITES():
        coll, mode = await _probe(monkeypatch, name)
        groups[(_target(name) or "", coll)][name] = mode
    assert any(len(g) > 1 for g in groups.values()), "no collection has two writers (vacuous)"
    assert any("list-first" in g.values() for g in groups.values()), "no list-first family"
    mixed = {
        f"{arg} @ {coll}": modes
        for (arg, coll), modes in groups.items()
        if len(set(modes.values())) > 1
    }
    assert mixed == {}, mixed


def test_the_sweep_covers_every_update_and_delete_with_an_id():
    assert len(_lz_ID_WRITES()) >= 50, _lz_ID_WRITES()
    assert {"delete_arm_profile", "update_arm_profile", "delete_device_tag"} <= set(_lz_ID_WRITES())
