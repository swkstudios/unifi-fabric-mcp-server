"""README.md contracts: the inventory, the pre-push lint, and a prose-only edit.

* The inventory in ``scripts/readme_contracts.py`` is complete (every script or test that reads
  the repository README is listed) and real (every owner path exists).
* The lint names the contract layer a README diff touches: all four layers the issue lists
  (generated block, install case, figure phrase, public-release-transform anchor), the
  documentation-contract phrases and the headings and links; and says "prose-only" otherwise.
* A prose-only edit passes every check that reads the README with no test, generator or source
  edit; each of the four breakages fails the check that owns it. Those run against a copy of
  the tree, so the real README is never touched.
"""

# ruff: noqa: S603
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import doc_blocks
from scripts import readme_contracts as rc
from scripts.markdown_blocks import FENCE

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"


def _lint(old: str, new: str) -> dict[str, list[rc.Touch]]:
    by_layer: dict[str, list[rc.Touch]] = {}
    for touch in rc.touched(old, new, root=ROOT):
        by_layer.setdefault(touch.layer, []).append(touch)
    return by_layer


# --- the inventory ------------------------------------------------------------------------------


def test_inventory_layers_are_known_and_names_unique():
    assert {c.layer for c in rc.INVENTORY} == set(rc.LAYERS)
    names = [c.name for c in rc.INVENTORY]
    assert len(names) == len(set(names))
    assert set(rc.LAYER_ADVICE) == set(rc.LAYERS)


def _readers_of_the_readme() -> set[str]:
    paths = [
        *sorted((ROOT / "tests").glob("*.py")),
        *sorted((ROOT / "scripts").glob("*.py")),
        *sorted((ROOT / "scripts").glob("*.sh")),
        *sorted((ROOT / ".github" / "scripts").glob("*.py")),
    ]
    return {
        p.relative_to(ROOT).as_posix()
        for p in paths
        if rc.READS_ROOT_README.search(p.read_text(encoding="utf-8", errors="ignore"))
    }


def test_every_reader_of_the_readme_is_in_the_inventory():
    listed = {o for c in rc.INVENTORY for o in c.owners}
    unlisted = sorted(_readers_of_the_readme() - listed - set(rc.NOT_THE_REPOSITORY_README))
    assert unlisted == [], (
        "these read README.md but no inventory row in scripts/readme_contracts.py names "
        f"them; add one (or say why they read a copy): {unlisted}"
    )


def test_the_inventory_renders_every_contract_under_its_layer():
    page = rc.inventory_markdown()
    for layer in rc.LAYERS:
        assert f"\n## {layer}\n" in page
    for contract in rc.INVENTORY:
        assert contract.name in page and all(f"`{o}`" in page for o in contract.owners)


# --- the lint, on edits of the real README ------------------------------------------------------


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def _replace_line(text: str, needle: str, edit) -> str:
    lines = text.split("\n")
    index = next(i for i, line in enumerate(lines) if needle in line)
    lines[index] = edit(lines[index])
    return "\n".join(lines)


def _free_prose_line(text: str) -> int:
    """A plain sentence outside every block, fence, comment, heading and table."""
    roles = rc._line_roles(text)
    for i, line in enumerate(text.split("\n")):
        if (
            roles[i][0] == "prose"
            and len(line) > 70
            and line[0].isalpha()
            and not re.search(r"[\d`|<>\[\]*_]", line)
        ):
            return i
    raise AssertionError("no free prose line in README.md")


def _reword(text: str) -> str:
    lines = text.split("\n")
    i = _free_prose_line(text)
    words = lines[i].split(" ")
    lines[i] = " ".join([*words[:-1], "really", words[-1]])
    return "\n".join(lines)


def test_a_prose_only_edit_touches_no_contract():
    old = _readme()
    new = _reword(old)
    assert new != old
    assert _lint(old, new) == {}
    assert "prose-only" in rc.report(rc.touched(old, new, root=ROOT))


def test_an_unchanged_readme_reports_nothing_to_lint(tmp_path):
    path = tmp_path / "README.md"
    path.write_text(_readme(), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "readme_contracts.py"),
            "--old",
            str(path),
            "--new",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "unchanged" in result.stdout


def test_an_edit_inside_a_generated_block_names_the_block():
    old = _readme()
    block = next(m for m in doc_blocks.BLOCK_RE.finditer(old) if m["name"] == "tool-families")
    body_line = next(line for line in block["body"].split("\n") if line.startswith("| "))
    new = old.replace(body_line, body_line + " edited by hand", 1)
    touches = _lint(old, new)
    assert "block" in touches
    assert any("tool-families" in t.detail for t in touches["block"])
    assert "regen_docs.py" in rc.report(rc.touched(old, new, root=ROOT))


def test_an_edit_inside_an_install_example_names_the_install_case():
    old = _readme()
    lines = old.split("\n")
    comment = next(i for i, line in enumerate(lines) if "<!-- install-case: " in line)
    fence = next(i for i in range(comment, len(lines)) if FENCE.match(lines[i]))
    lines[fence + 1] += " --changed"
    touches = _lint(old, "\n".join(lines))
    assert "install-case" in touches
    assert any("readme-install-" in t.detail for t in touches["install-case"])


def test_dropping_an_install_case_comment_names_the_install_case():
    old = _readme()
    lines = [
        line for line in old.split("\n") if "<!-- install-case: readme-install-30 " not in line
    ]
    assert len(lines) < len(old.split("\n"))
    touches = _lint(old, "\n".join(lines))
    assert any("readme-install-30" in t.detail for t in touches.get("install-case", []))


def test_a_changed_figure_phrase_names_the_figure_layer():
    old = _readme()
    new = _replace_line(
        old, " tools", lambda s: re.sub(r"\b(\d{2,3}) tools", r"\g<1>0 tools", s, count=1)
    )
    assert new != old
    touches = _lint(old, new)
    assert "figure-phrase" in touches
    assert "gen_catalog_figures.py" in rc.report(rc.touched(old, new, root=ROOT))


def test_rewording_a_pinned_phrase_names_the_test_that_asserts_it():
    old = _readme()
    phrase = "connects your AI assistant to your UniFi network"
    assert phrase in old
    touches = _lint(old, old.replace(phrase, "links your AI assistant to your UniFi network", 1))
    assert any("test_front_page_docs.py" in t.detail for t in touches.get("doc-contract-test", []))


def test_renaming_a_heading_names_the_link_layer():
    old = _readme()
    heading = next(line for line in old.split("\n") if line.startswith("## "))
    touches = _lint(old, old.replace(heading, heading + " (renamed)", 1))
    assert any(heading in t.detail for t in touches.get("link-anchor", []))


def test_prepush_runs_the_lint_before_the_jobs():
    text = (ROOT / "scripts" / "prepush.sh").read_text(encoding="utf-8")
    lint = text.index('"$python" scripts/readme_contracts.py')
    jobs = text.index('"$python" scripts/ci_fast_jobs.py')
    assert lint < jobs
    assert '--base "$base"' in text[lint:jobs] and '--head "$head"' in text[lint:jobs]


# --- end to end, on a copy of the tree -----------------------------------------------------------

IGNORE = shutil.ignore_patterns(
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
    "build",
    "*.egg-info",
    ".coverage*",
)


@pytest.fixture(scope="module")
def _tree(tmp_path_factory):
    dest = tmp_path_factory.mktemp("readme-contracts") / "repo"
    shutil.copytree(ROOT, dest, ignore=IGNORE)
    return dest


@pytest.fixture
def tree(_tree):
    original = (_tree / "README.md").read_text(encoding="utf-8")
    yield _tree
    (_tree / "README.md").write_text(original, encoding="utf-8")


def _run(tree: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(tree / "src"), str(tree)])}
    return subprocess.run(
        [sys.executable, *args],
        cwd=tree,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _edit(tree: Path, edit) -> tuple[str, str]:
    path = tree / "README.md"
    old = path.read_text(encoding="utf-8")
    new = edit(old)
    assert new != old
    path.write_text(new, encoding="utf-8")
    return old, new


def _tail(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stdout + result.stderr)[-1500:]


#: The checks that read the README and run without a network, with the README they see.
PROSE_TESTS = [
    name
    for name in (
        "tests/test_front_page_docs.py",
        "tests/test_docs_currency.py",
        "tests/test_install_cases_extracted.py",
        "tests/test_pypi_readme.py",
    )
    if (ROOT / name).is_file()
]
PROSE_CHECKS = (
    ("scripts/check_markdown.py",),
    ("scripts/check_doc_provenance.py",),
    ("scripts/gen_reference_blocks.py", "--check"),
    ("-m", "pytest", "-q", "-p", "no:cacheprovider", *PROSE_TESTS),
)


def test_a_prose_only_edit_passes_every_readme_check_with_no_other_edit(tree):
    old, new = _edit(tree, _reword)
    assert rc.touched(old, new, root=ROOT) == []
    failed = {
        " ".join(check): _tail(result)
        for check in PROSE_CHECKS
        if (result := _run(tree, *check)).returncode != 0
    }
    assert failed == {}


def test_control_stale_figure_fails_the_prose_count_oracle(tree):
    """A tool count typed into prose that disagrees with the registry."""
    _edit(
        tree,
        lambda text: text.replace("## More info", "The catalog holds 77 tools.\n\n## More info", 1),
    )
    result = _run(
        tree,
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "tests/test_docs_currency.py::test_prose_tool_counts_equal_registry",
    )
    assert result.returncode != 0, _tail(result)
    assert "stale tool counts" in result.stdout


def test_control_broken_install_case_fails_the_provenance_check(tree):
    """An install example whose install-case marker was deleted."""
    _edit(
        tree,
        lambda text: re.sub(r"<!-- install-case: readme-install-30 [^\n]*-->\n", "", text, count=1),
    )
    result = _run(tree, "scripts/check_doc_provenance.py")
    assert result.returncode != 0, _tail(result)


def test_control_edited_generated_block_fails_the_generator_check(tree):
    """A hand edit inside a generated block."""

    def edit(text: str) -> str:
        block = next(m for m in doc_blocks.BLOCK_RE.finditer(text) if m["name"] == "tool-families")
        row = next(line for line in block["body"].split("\n") if line.startswith("| "))
        return text.replace(row, row + " edited by hand", 1)

    _edit(tree, edit)
    result = _run(tree, "scripts/gen_reference_blocks.py", "--check")
    assert result.returncode != 0, _tail(result)
    assert "tool-families" in result.stdout + result.stderr


@pytest.mark.parametrize(
    "control",
    [
        "stale figure",
        "broken install case",
        "edited generated block",
    ],
)
def test_the_lint_names_what_each_control_breaks(control):
    old = _readme()
    if control == "stale figure":
        new = old.replace("## More info", "The catalog holds 77 tools.\n\n## More info", 1)
        layer = "figure-phrase"
    elif control == "broken install case":
        new = re.sub(r"<!-- install-case: readme-install-30 [^\n]*-->\n", "", old, count=1)
        layer = "install-case"
    else:
        block = next(m for m in doc_blocks.BLOCK_RE.finditer(old) if m["name"] == "tool-families")
        row = next(line for line in block["body"].split("\n") if line.startswith("| "))
        new = old.replace(row, row + " edited by hand", 1)
        layer = "block"
    assert layer in _lint(old, new)
