"""The behaviour baseline of the tool surface and the comparator that guards it (public #42 step 1).

``tests/fixtures/behavior_baseline/`` freezes, per family, the full-mode ``tools/list``
entries, the discovery-mode ``describe_tool`` output and fixture-driven calls (a read, a
write with dry-run and with confirm, a validation error and a ``tool_not_exposed``
refusal), plus the tool order and the hashes of the operator docs the tools cite.
``scripts/dump_tool_baseline.py`` writes the files from the runtime and compares them.

What this module proves:

* On an unchanged head the runtime equals the committed files (every family, the order and
  the docs): the comparator passes.
* A seeded change makes the comparison fail with a readable diff: a reordered
  registration, a changed annotation and a changed error string.
* The three comparison modes allow exactly what they promise: an L1 move may not change a
  file, an L3 PR may regenerate only its own family, an L2 PR may change only descriptions.
* When a PR's base is named (``BEHAVIOR_BASELINE_MODE`` with ``BEHAVIOR_BASELINE_BASE_REF``
  or ``BEHAVIOR_BASELINE_BASE_DIR``, and ``BEHAVIOR_BASELINE_FAMILY`` for l3), the files on
  the PR's head are compared with the files at its base under that mode. Unset, the head is
  compared with itself.
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import subprocess
import sys
from functools import cache
from pathlib import Path
from typing import Any

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from scripts import dump_tool_baseline as dump
from unifi_fabric.families import ALL_FAMILIES

SCRIPT = dump.ROOT / "scripts" / "dump_tool_baseline.py"
SEEDED_FAMILY = "site_manager"  # the smallest family with a read tool and no write tool


@cache
def _committed() -> dump.Baseline:
    committed = dump.read_baseline_dir(dump.BASELINE_DIR)
    assert committed, f"no baseline files in {dump.BASELINE_DIR}; run scripts/dump_tool_baseline.py"
    return committed


def _readable(result: subprocess.CompletedProcess[str]) -> str:
    return (
        "the runtime differs from the committed baseline (regenerate with "
        "scripts/dump_tool_baseline.py only if the change is intended):\n"
        + result.stdout[-6000:]
        + result.stderr[-2000:]
    )


def test_one_file_per_family_plus_order_and_docs():
    expected = {f"{family}.json" for family in ALL_FAMILIES} | {dump.ORDER_FILE, dump.DOCS_FILE}
    assert set(_committed()) == expected
    for family in ALL_FAMILIES:
        assert set(_committed()[f"{family}.json"]) == {"tools", "describe", "calls"}
        assert dump.FAMILY_CALLS[family]["read"]
    assert set(dump.FAMILY_CALLS) == set(ALL_FAMILIES)


def _verify(*args: str) -> subprocess.CompletedProcess[str]:
    """``dump_tool_baseline.py --verify`` in a fresh interpreter (its capture order rule)."""
    return subprocess.run(  # noqa: S603 - this interpreter, this repository's script
        [sys.executable, str(SCRIPT), "--verify", *args],
        capture_output=True,
        text=True,
        cwd=dump.ROOT,
        check=False,
    )


def test_runtime_matches_the_committed_baseline():
    """Every family file, the order and the docs: one fresh interpreter, about a minute."""
    result = _verify()
    assert result.returncode == 0, _readable(result)
    assert result.stdout.strip().endswith("baseline matches"), result.stdout


def test_every_registered_tool_is_in_exactly_one_family_file_and_the_order():
    committed = _committed()
    in_files = [t["name"] for fam in ALL_FAMILIES for t in committed[f"{fam}.json"]["tools"]]
    assert len(in_files) == len(set(in_files))
    assert sorted(in_files) == sorted(committed[dump.ORDER_FILE])
    for fam in ALL_FAMILIES:
        file = committed[f"{fam}.json"]
        names = [t["name"] for t in file["tools"]]
        assert list(file["describe"]) == names
        positions = [committed[dump.ORDER_FILE].index(n) for n in names]
        assert positions == sorted(positions), f"{fam}: file order differs from order.json"


def test_head_files_against_the_pr_base_by_mode():
    head = _committed()
    mode = os.environ.get("BEHAVIOR_BASELINE_MODE")
    family = os.environ.get("BEHAVIOR_BASELINE_FAMILY") or None
    if not mode:
        assert dump.compare(head, head, "l1") == []
        return
    ref = os.environ.get("BEHAVIOR_BASELINE_BASE_REF")
    directory = os.environ.get("BEHAVIOR_BASELINE_BASE_DIR")
    assert ref or directory, "name the PR's base: BEHAVIOR_BASELINE_BASE_REF or _BASE_DIR"
    base = dump.read_baseline_dir(Path(directory)) if directory else dump.read_baseline_ref(ref)
    problems = dump.compare(base, head, mode, family)
    assert not problems, f"mode {mode} does not allow:\n{dump.report(problems)}"


# ----------------------------------------------------------------------------- seeded changes
async def _seeded_app(*, reorder: str | None = None, flip_read_only: str | None = None) -> FastMCP:
    """A clone of the server's registered tools, with one deliberate change.

    ``reorder`` re-registers that tool last; ``flip_read_only`` flips that tool's read-only
    annotation. The middleware is the server's, so the clone lists as the server does.
    """
    from unifi_fabric import server

    app = FastMCP("baseline-seed")
    # The baseline's order, not the registry's: a session that hid tools re-registers them last.
    position = {name: i for i, name in enumerate(_committed()[dump.ORDER_FILE])}
    tools = sorted(
        await server.mcp.list_tools(run_middleware=False), key=lambda t: position[t.name]
    )
    if reorder:
        tools = [t for t in tools if t.name != reorder] + [t for t in tools if t.name == reorder]
    for tool in tools:
        if tool.name == flip_read_only:
            hint = tool.annotations.read_only_hint
            tool = tool.model_copy(
                update={
                    "annotations": tool.annotations.model_copy(update={"read_only_hint": not hint})
                }
            )
        app.add_tool(tool)
    app.middleware = list(server.mcp.middleware)
    return app


def _head_with_tools(entries: list[dict[str, Any]]) -> dump.Baseline:
    """The committed baseline with the family's tools and the order taken from ``entries``."""
    head = copy.deepcopy(_committed())
    names = {t["name"] for t in head[f"{SEEDED_FAMILY}.json"]["tools"]}
    head[f"{SEEDED_FAMILY}.json"]["tools"] = [e for e in entries if e["name"] in names]
    head[dump.ORDER_FILE] = [e["name"] for e in entries]
    return head


def test_an_unseeded_clone_matches_the_baseline():
    """The control: the clone the seeded cases start from lists exactly as the baseline."""
    entries, _index = asyncio.run(dump.capture_tools(asyncio.run(_seeded_app())))
    assert dump.compare(_committed(), _head_with_tools(entries), "l1") == []


def test_a_reordered_registration_fails_with_a_readable_diff():
    first = _committed()[dump.ORDER_FILE][0]
    entries, _index = asyncio.run(dump.capture_tools(asyncio.run(_seeded_app(reorder=first))))
    problems = dump.compare(_committed(), _head_with_tools(entries), "l1")
    text = dump.report(problems)
    print(text)
    assert any(p.startswith("order.json:") and "order changed" in p for p in problems), text
    assert f"base {first!r}" in text and "first at index 0" in text
    assert any(p.startswith(f"{SEEDED_FAMILY}.json:") and "order changed" in p for p in problems)
    # the L3 rule too: a reorder in a family a PR does not own is not allowed
    assert dump.compare(_committed(), _head_with_tools(entries), "l3", family="network")
    # and an L2 pass may not reorder
    assert dump.compare(_committed(), _head_with_tools(entries), "l2")


def test_a_changed_annotation_fails_with_a_readable_diff():
    name = "get_host"
    app = asyncio.run(_seeded_app(flip_read_only=name))
    entries, _index = asyncio.run(dump.capture_tools(app))
    problems = dump.compare(_committed(), _head_with_tools(entries), "l1")
    text = dump.report(problems)
    print(text)
    expected = f"{SEEDED_FAMILY}.json: tools[{name}].annotations.readOnlyHint: true -> false"
    assert expected in problems, text
    assert len(problems) == 1, text
    # an L2 (description-only) pass may not change an annotation either
    assert dump.compare(_committed(), _head_with_tools(entries), "l2") == [expected]


def test_a_changed_error_string_fails_with_a_readable_diff(monkeypatch):
    from unifi_fabric import read_only_tools

    real = read_only_tools.not_exposed

    def reworded(target: str) -> ToolError:
        return ToolError(str(real(target)).replace("is not exposed", "is hidden from this profile"))

    monkeypatch.setattr(read_only_tools, "not_exposed", reworded)
    head = copy.deepcopy(_committed())
    head[f"{SEEDED_FAMILY}.json"]["calls"] = asyncio.run(dump.capture_calls(SEEDED_FAMILY))
    problems = dump.compare(_committed(), head, "l1")
    text = dump.report(problems)
    print(text)
    assert len(problems) == 1, text
    (line,) = problems
    assert line.startswith(
        f"{SEEDED_FAMILY}.json: calls.tool_not_exposed.result.content[0].text.error.message:"
    )
    assert "is not exposed: the operator's" in line and "is hidden from this profile" in line
    assert dump.compare(_committed(), head, "l2"), "an L2 pass may not change an error string"
    assert dump.compare(_committed(), head, "l3", family="network"), "not this family's PR"
    assert dump.compare(_committed(), head, "l3", family=SEEDED_FAMILY) == []


# ------------------------------------------------------------------------------- the modes
def _small() -> dump.Baseline:
    def tool(name: str, description: str = "d", read_only: bool = True) -> dict[str, Any]:
        return {
            "name": name,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": {"host": {"type": "string", "description": "the console"}},
            },
            "outputSchema": None,
            "annotations": {"readOnlyHint": read_only},
        }

    def envelope(text: str) -> dict[str, Any]:
        return {"isError": False, "content": [{"type": "text", "text": text}]}

    def family(*tools: dict[str, Any]) -> dict[str, Any]:
        return {
            "tools": list(tools),
            "describe": {
                t["name"]: envelope(
                    json.dumps({"name": t["name"], "description": t["description"]})
                )
                for t in tools
            },
            "calls": {"read": {"tool": tools[0]["name"], "result": envelope("{}")}},
        }

    return {
        dump.ORDER_FILE: ["a1", "b1", "a2", "b2"],
        dump.DOCS_FILE: {"docs/TOOLS.md": {"sha256": "x", "sections": {}, "cited_by": []}},
        "alpha.json": family(tool("a1"), tool("a2")),
        "beta.json": family(tool("b1"), tool("b2")),
    }


def test_l1_allows_nothing():
    base = _small()
    assert dump.compare(base, copy.deepcopy(base), "l1") == []
    for change in (
        lambda b: b["alpha.json"]["tools"][0].update(description="new"),
        lambda b: b[dump.ORDER_FILE].reverse(),
        lambda b: b[dump.DOCS_FILE]["docs/TOOLS.md"].update(sha256="y"),
        lambda b: b["beta.json"]["calls"]["read"]["result"].update(isError=True),
    ):
        head = copy.deepcopy(base)
        change(head)
        assert dump.compare(base, head, "l1"), change


def test_l2_allows_only_descriptions_and_doc_hashes():
    base = _small()
    head = copy.deepcopy(base)
    head["alpha.json"]["tools"][0]["description"] = "a better description"
    head["alpha.json"]["tools"][0]["inputSchema"]["properties"]["host"]["description"] = "reworded"
    head["alpha.json"]["describe"]["a1"] = {
        "isError": False,
        "content": [
            {
                "type": "text",
                "text": json.dumps({"name": "a1", "description": "a better description"}),
            }
        ],
    }
    head[dump.DOCS_FILE]["docs/TOOLS.md"]["sha256"] = "changed"
    assert dump.compare(base, head, "l2") == []
    for change in (
        lambda b: b["alpha.json"]["tools"][0]["annotations"].update(readOnlyHint=False),
        lambda b: b["alpha.json"]["tools"][0]["inputSchema"]["properties"].update(
            extra={"type": "string"}
        ),
        lambda b: b[dump.ORDER_FILE].reverse(),
        lambda b: b["beta.json"]["calls"]["read"]["result"].update(isError=True),
        lambda b: b["beta.json"]["tools"].append(
            {
                "name": "b2",
                "description": "d",
                "inputSchema": {},
                "outputSchema": None,
                "annotations": {},
            }
        ),
    ):
        seeded = copy.deepcopy(head)
        change(seeded)
        assert dump.compare(base, seeded, "l2"), change


def test_l3_allows_only_its_own_family():
    base = _small()
    head = copy.deepcopy(base)
    head["alpha.json"]["tools"].append(
        {
            "name": "a3",
            "description": "new",
            "inputSchema": {},
            "outputSchema": None,
            "annotations": {},
        }
    )
    head["alpha.json"]["describe"]["a3"] = {"isError": False, "content": []}
    head[dump.ORDER_FILE] = ["a1", "b1", "a2", "b2", "a3"]
    head[dump.DOCS_FILE]["docs/TOOLS.md"]["sha256"] = "regenerated"
    assert dump.compare(base, head, "l3", family="alpha") == []
    assert dump.compare(base, head, "l3", family="beta"), "alpha changed: not beta's PR"
    assert dump.compare(base, head, "l1")
    other = copy.deepcopy(head)
    other["beta.json"]["tools"][0]["annotations"]["readOnlyHint"] = False
    assert dump.compare(base, other, "l3", family="alpha")
    reordered = copy.deepcopy(head)
    reordered[dump.ORDER_FILE] = ["a1", "b2", "a2", "b1", "a3"]
    assert dump.compare(base, reordered, "l3", family="alpha"), "beta's tool moved in the order"
    with pytest.raises(ValueError):
        dump.compare(base, head, "l3")
    with pytest.raises(ValueError):
        dump.compare(base, head, "l4")


def test_a_family_that_drops_a_file_is_reported():
    base = _small()
    head = copy.deepcopy(base)
    del head["beta.json"]
    assert dump.compare(base, head, "l1") == ["beta.json: missing from the head"]


# ------------------------------------------------------------------- the public-tree docs pin
def _doc_tree(tmp_path: Path, body: str = "# T\n\n## Sec\n\ntext\n") -> tuple[Path, Path]:
    """A tiny tree with one doc and a docs.json that pins it (the file and one section)."""
    root = tmp_path / "tree"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "A.md").write_text(body, encoding="utf-8")
    directory = root / "baseline"
    directory.mkdir()
    pinned = {
        "docs/A.md": {
            "sha256": dump._sha(body.encode()),
            "sections": {"sec": dump._sha(b"## Sec\n\ntext")},
            "cited_by": ["a1"],
        }
    }
    (directory / dump.DOCS_FILE).write_text(dump.dumps(pinned), encoding="utf-8")
    return root, directory


def test_docs_drift_is_empty_for_the_docs_it_pins(tmp_path):
    root, directory = _doc_tree(tmp_path)
    assert dump.docs_drift(directory, root) == []


def test_docs_drift_names_a_changed_doc_and_a_missing_one(tmp_path):
    root, directory = _doc_tree(tmp_path)
    (root / "docs" / "A.md").write_text("# T\n\n## Sec\n\nchanged\n", encoding="utf-8")
    problems = dump.docs_drift(directory, root)
    assert any("docs/A.md.sha256" in p for p in problems), problems
    assert any("docs/A.md.sections.sec" in p for p in problems), problems
    (root / "docs" / "A.md").unlink()
    assert dump.docs_drift(directory, root) == [
        "docs/A.md: listed in docs.json but not in the tree"
    ]


def test_rehash_docs_pins_the_rewritten_doc_and_keeps_what_else_it_lists(tmp_path):
    root, directory = _doc_tree(tmp_path)
    before = json.loads((directory / dump.DOCS_FILE).read_text(encoding="utf-8"))
    rewritten = "# T\n\n## Sec\n\ntext in the public form\n"
    (root / "docs" / "A.md").write_text(rewritten, encoding="utf-8")
    assert dump.docs_drift(directory, root), "the rewrite is a drift until it is re-pinned"
    assert dump.rehash_docs(directory, root) == []
    after = json.loads((directory / dump.DOCS_FILE).read_text(encoding="utf-8"))
    assert dump.docs_drift(directory, root) == []
    assert after["docs/A.md"]["sha256"] == dump._sha(rewritten.encode())
    assert after["docs/A.md"]["sha256"] != before["docs/A.md"]["sha256"]
    assert after["docs/A.md"]["cited_by"] == before["docs/A.md"]["cited_by"]
    assert set(after["docs/A.md"]["sections"]) == {"sec"}


def test_rehash_docs_fails_closed_and_writes_nothing(tmp_path):
    root, directory = _doc_tree(tmp_path)
    pinned = (directory / dump.DOCS_FILE).read_text(encoding="utf-8")
    # a pinned section the rewrite removed
    (root / "docs" / "A.md").write_text("# T\n\nno sections now\n", encoding="utf-8")
    assert dump.rehash_docs(directory, root) == [
        "docs/A.md: section #sec is pinned but not in the file"
    ]
    # a pinned file the rewrite removed
    (root / "docs" / "A.md").unlink()
    assert dump.rehash_docs(directory, root) == [
        "docs/A.md: listed in docs.json but not in the tree"
    ]
    assert (directory / dump.DOCS_FILE).read_text(encoding="utf-8") == pinned


def test_check_docs_passes_on_the_committed_baseline():
    """The private tree's own docs.json is true: the transform's pre-check starts clean."""
    assert dump.docs_drift() == []
    result = subprocess.run(  # noqa: S603 - this interpreter, this repository's script
        [sys.executable, str(SCRIPT), "--check-docs"],
        capture_output=True,
        text=True,
        cwd=dump.ROOT,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
