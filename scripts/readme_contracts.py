#!/usr/bin/env python3
"""The contracts that read README.md, and a pre-push lint that names the ones a diff touches.

``INVENTORY`` is the one list of every tool and test that reads the repository's
``README.md``, grouped by the layer it reads: a generated block, an install case, a figure
phrase, a public-release-transform anchor, a documentation-contract test, a link or heading.
``python3 scripts/readme_contracts.py --inventory`` prints it as Markdown;
``tests/test_readme_contracts.py`` keeps every owner path real and fails when a script or test
reads the README without being listed.

The lint compares two revisions of the README and reports, per layer, which contract a changed
line sits in. It is advice for the person pushing, wired into ``scripts/prepush.sh``; it never
fails a push (exit 0), because the checks it names are the gate:

* ``block``: a line inside a generated region (``scripts/doc_blocks.py``). Never edit one by
  hand; run ``python3 scripts/regen_docs.py``.
* ``install-case``: a fenced example, or its ``install-case`` / ``doc-provenance`` comment.
* ``figure-phrase``: a tool count, a catalog size or an install pin. A generator owns it.
* ``transform-anchor``: a line the public-release transform anchors on.
* ``doc-contract-test``: a line that held a phrase a documentation-contract test asserts and
  the new README no longer contains. The phrases are read from the tests' own string
  literals and from ``docs/doc-facts.toml``, so this list cannot drift.
* ``link-anchor``: a heading (a link target) or a link.

A change that touches none of these is prose: it needs no test, generator or source edit.

Stdlib only; ``scripts/ci_fast_jobs.py`` supplies the documentation-contract test list.
"""

from __future__ import annotations

import argparse
import ast
import difflib
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ci_fast_jobs  # noqa: E402
import doc_blocks  # noqa: E402
from markdown_blocks import FENCE  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
README = "README.md"

LAYERS = (
    "block",
    "install-case",
    "figure-phrase",
    "transform-anchor",
    "doc-contract-test",
    "link-anchor",
)

#: What to run for a layer, and what to do about a failure.
LAYER_ADVICE = {
    "block": (
        "python3 scripts/regen_docs.py --check",
        "edit the source the block is rendered from, then run python3 scripts/regen_docs.py",
    ),
    "install-case": (
        "python3 scripts/check_doc_provenance.py && "
        "python3 -m pytest tests/test_install_cases_extracted.py tests/test_install_pins.py",
        "keep the install-case and doc-provenance comments with the example; "
        "python3 scripts/regen_docs.py repins the versions",
    ),
    "figure-phrase": (
        "python3 scripts/gen_catalog_figures.py --check",
        "run python3 scripts/regen_docs.py; do not retype a count",
    ),
    "transform-anchor": (
        "python3 -m pytest tests/test_public_release_transform_version.py",
        "the public-release transform anchors on this line: change both in one pull request",
    ),
    "doc-contract-test": (
        "python3 scripts/ci_fast_jobs.py --docs-contract",
        "the named test asserts this phrase: update it in the same pull request",
    ),
    "link-anchor": (
        "python3 scripts/check_markdown.py",
        "a renamed heading breaks every link to its anchor: search the repository for it",
    ),
}


@dataclass(frozen=True)
class Contract:
    """One thing that reads README.md: ``owner`` files fail when it is broken."""

    layer: str
    name: str
    owners: tuple[str, ...]
    reads: str


def _c(layer: str, name: str, reads: str, *owners: str) -> Contract:
    return Contract(layer, name, tuple(owners), reads)


INVENTORY: tuple[Contract, ...] = (
    # --- generated blocks ------------------------------------------------------------------
    _c(
        "block",
        "Block registry",
        "every BEGIN/END GENERATED pair: present, once, in order, registered",
        "scripts/doc_blocks.py",
        "tests/test_doc_blocks.py",
        "tests/test_generator_markers.py",
    ),
    _c(
        "block",
        "Catalog blocks",
        "catalog-headline, how-it-works-catalog, verification-status: counts, sizes, live evidence",
        "scripts/gen_catalog_figures.py",
        "tests/test_readme_catalog_size.py",
        "tests/test_distribution_listings.py",
    ),
    _c(
        "block",
        "Reference blocks",
        "tool-families and the opt-out/write-switch tables, rendered from the code",
        "scripts/gen_reference_blocks.py",
        "tests/test_tool_families_renderer.py",
        "tests/test_families_selection.py",
        "tests/test_optout_guidance_text.py",
    ),
    _c(
        "block",
        "Family table sums",
        "the family table adds up to the registry",
        "tests/test_docs_currency.py",
    ),
    _c(
        "block",
        "Site statistics",
        "the figures of the verification block",
        "scripts/site_stats.py",
        "tests/test_site_stats.py",
    ),
    _c(
        "block",
        "Release package",
        "the simulated-upstream tool count of the verification row",
        "scripts/release_package.py",
        "tests/test_release_package.py",
    ),
    # --- install cases ---------------------------------------------------------------------
    _c(
        "install-case",
        "Install-case extraction",
        "fenced examples under the install headings and their install-case comments",
        "scripts/extract_install_cases.py",
        "scripts/markdown_blocks.py",
        "tests/test_install_cases_extracted.py",
        "tests/test_markdown_blocks.py",
    ),
    _c(
        "install-case",
        "Doc provenance",
        "every install example carries a doc-provenance pin of the extractor",
        "scripts/check_doc_provenance.py",
        "tests/test_doc_provenance.py",
    ),
    _c(
        "install-case",
        "Install smoke",
        "the README setup argv, executed against local artifacts",
        "scripts/install_smoke.py",
    ),
    _c(
        "install-case",
        "Install pins",
        "versions in the install badges, deeplinks and image tags",
        "scripts/prepare_release.py",
        "tests/test_install_pins.py",
        "tests/test_dependency_versions_docs.py",
    ),
    _c(
        "install-case",
        "Install credentials",
        "install examples carry no key value",
        "tests/test_install_doc_credentials.py",
    ),
    _c(
        "install-case",
        "Launcher settings",
        "settings the install examples set are accepted by the pinned launcher",
        "scripts/check_launcher_settings.py",
    ),
    # --- figure phrases --------------------------------------------------------------------
    _c(
        "figure-phrase",
        "Prose tool counts",
        "any N tools in the prose equals the registry",
        "tests/test_docs_currency.py",
        "tests/test_doc_tool_counts.py",
    ),
    _c(
        "figure-phrase",
        "Claim ledger",
        "env names, defaults, tool names and links the prose states",
        "scripts/docs_claim_ledger.py",
        "tests/test_docs_claim_ledger.py",
        "tests/test_docs_references.py",
        "tests/test_docs_usage_claims.py",
        "tests/test_docs_facts.py",
    ),
    _c(
        "figure-phrase",
        "Pagination text",
        "the pagination paragraph matches the code",
        "tests/test_api_keys_and_env_contract.py",
    ),
    # --- public release transform ----------------------------------------------------------
    _c(
        "transform-anchor",
        "Public release transform",
        "the heading the image-verification pointer is injected before",
        "scripts/public_release_transform.sh",
        "tests/test_public_release_transform_version.py",
    ),
    _c(
        "transform-anchor",
        "Public release verify",
        "the transformed README names nothing private",
        "scripts/public_release_verify.sh",
        "tests/test_public_release_verify.py",
        "tests/test_release_sanitizer_docs.py",
    ),
    # --- documentation-contract tests ------------------------------------------------------
    _c(
        "doc-contract-test",
        "Front page",
        "the hook, quick start, table of contents, badges and linked guides",
        "tests/test_front_page_docs.py",
        "docs/doc-facts.toml",
    ),
    _c(
        "doc-contract-test",
        "Agent and AI files",
        "badges, wording shared with CONTRIBUTING and the agent files",
        "tests/test_docs_ai_files.py",
    ),
    _c(
        "doc-contract-test",
        "Registry listing",
        "the mcp-name line the registry reads",
        "tests/test_review_registry_release_note.py",
    ),
    # --- links, headings, packaging ---------------------------------------------------------
    _c(
        "link-anchor",
        "Markdown and link checks",
        "relative links, anchors and headings",
        "scripts/check_markdown.py",
        "tests/test_markdown_lint.py",
    ),
    _c(
        "link-anchor",
        "PyPI long description",
        "relative links rewritten to absolute for the package page",
        "scripts/pypi_readme.py",
        "tests/test_pypi_readme.py",
        "tests/test_release_tooling.py",
    ),
    _c(
        "link-anchor",
        "Package contents",
        "README.md ships in the sdist and the bundle",
        "tests/test_sdist_contents.py",
    ),
    _c(
        "link-anchor",
        "Testing-doc coverage",
        "the testing documents the README points at",
        "tests/test_testing_doc_coverage.py",
    ),
)

#: A script or test that reads the repository README is found by one of these shapes. A file
#: that matches and is in no ``INVENTORY`` row fails the completeness test.
READS_ROOT_README = re.compile(
    r"""(?x)
      (?:ROOT|root|REPO|repo)\s*/\s*["']README\.md["']
    | \bREADME\s*=\s*(?:ROOT|Path)\b
    | _text\(\s*["']README\.md["']
    """
)

#: Matching files that read a copy or a synthetic README, not the repository's.
NOT_THE_REPOSITORY_README = {
    "tests/test_ci_classify_changes.py": "classifies the path README.md; reads no content",
    "tests/test_install_cases.py": "plants its own README in a tmp tree",
    "tests/test_doc_provenance.py": "plants its own README in a tmp tree",
    "tests/test_release_scripts.py": "plants a tap README in a tmp tree",
    "tests/test_check_doc_links.py": "plants its own README in a tmp tree",
    "tests/test_check_doc_links_offline.py": "plants its own README in a tmp tree",
    "tests/test_readme_contracts.py": "this lint's own tests",
}

# --- inventory rendering ----------------------------------------------------------------------


def inventory_markdown() -> str:
    """The inventory as Markdown, one table per layer."""
    lines = [
        "# Contracts that read README.md",
        "",
        "<!-- Generated by `python3 scripts/readme_contracts.py --inventory`; do not edit. -->",
        "",
        "Every tool and test that reads the repository README, by the layer it reads. A",
        "prose-only edit (no generated block, install example, figure, anchor, heading, link or",
        "pinned phrase) touches none of them. Before you push a README change,",
        "`scripts/prepush.sh` runs `python3 scripts/readme_contracts.py` and names the ones your",
        "diff touches.",
        "",
    ]
    for layer in LAYERS:
        check, fix = LAYER_ADVICE[layer]
        lines += [
            f"## {layer}",
            "",
            f"Check: `{check}`. Fix: {fix}.",
            "",
            "| Contract | Reads | Owners |",
            "|---|---|---|",
        ]
        for c in (c for c in INVENTORY if c.layer == layer):
            owners = ", ".join(f"`{o}`" for o in c.owners)
            lines.append(f"| {c.name} | {c.reads} | {owners} |")
        lines.append("")
    return "\n".join(lines)


# --- the diff lint ----------------------------------------------------------------------------

FIGURE_PATTERNS = (
    ("tool count", re.compile(r"\b\d{2,3}(?:[- ](?:MCP )?tools?\b| tool names\b)")),
    ("catalog size", re.compile(r"\b\d[\d,.]*\s?(?:KB|MB|bytes)\b")),
    ("install pin", re.compile(r"==\d+\.\d+\.\d+|[:/]v?\d+\.\d+\.\d+\b|%3D%3D\d")),
)
MARKER_COMMENT = re.compile(r"<!--\s*(install-case|doc-provenance)\b")
CASE_ID = re.compile(r"install-case:\s*(\S+)")
HEADING = re.compile(r"^ {0,3}#{1,6}[ \t]")
LINK = re.compile(r"\]\([^)]*\)")
#: ``anchor = '## More info'`` in the transform: the line the README is split on.
ANCHOR_ASSIGNMENT = re.compile(r"^anchor\s*=\s*(['\"])(.+?)\1\s*$", re.M)
MIN_PHRASE = 20


@dataclass(frozen=True)
class Touch:
    layer: str
    line: int
    side: str  # "old" or "new"
    detail: str


def _line_roles(text: str) -> list[tuple[str, str]]:
    """Per line: (role, detail) with role one of block, fence, marker, prose."""
    lines = text.split("\n")
    roles = [("prose", "")] * len(lines)
    for m in doc_blocks.BLOCK_RE.finditer(text):
        first = text.count("\n", 0, m.start())
        last = text.count("\n", 0, m.end())
        for i in range(first, last + 1):
            roles[i] = ("block", m["name"])
    fence_close = ""
    case = ""
    for i, line in enumerate(lines):
        if roles[i][0] == "block":
            continue
        if MARKER_COMMENT.match(line.strip()):
            found = CASE_ID.search(line)
            case = found[1] if found else case
            roles[i] = ("marker", case)
            continue
        opening = FENCE.match(line)
        if fence_close:
            roles[i] = ("fence", case)
            if opening and opening[2].startswith(fence_close) and not opening[3].strip():
                fence_close = ""
        elif opening:
            fence_close = opening[2]
            roles[i] = ("fence", case)
    return roles


def _transform_anchors(root: Path) -> set[str]:
    script = root / "scripts" / "public_release_transform.sh"
    if not script.is_file():
        return set()
    return {m[2] for m in ANCHOR_ASSIGNMENT.finditer(script.read_text(encoding="utf-8"))}


def _fact_phrases(root: Path) -> dict[str, str]:
    """phrase -> docs/doc-facts.toml, the data file the front-page test reads its phrases from."""
    path = root / "docs" / "doc-facts.toml"
    if not path.is_file():
        return {}
    try:
        readme = tomllib.loads(path.read_text(encoding="utf-8")).get("readme", {})
    except tomllib.TOMLDecodeError:
        return {}
    phrases: dict[str, str] = {}
    for value in readme.values():
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, str) and item.strip():
                phrases[" ".join(item.split())] = (
                    "docs/doc-facts.toml (tests/test_front_page_docs.py)"
                )
    return phrases


def _asserted_phrases(root: Path) -> dict[str, str]:
    """phrase -> the documentation-contract test that spells it out."""
    phrases: dict[str, str] = _fact_phrases(root)
    for rel in ci_fast_jobs.docs_contract(root):
        try:
            tree = ast.parse((root / rel).read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = " ".join(node.value.split())
                if len(value) >= MIN_PHRASE and "\n" not in node.value.strip():
                    phrases.setdefault(value, rel)
    return phrases


def touched(old: str, new: str, *, root: Path = ROOT) -> list[Touch]:
    """Every contract layer a change from ``old`` to ``new`` touches, with the line."""
    old_lines, new_lines = old.split("\n"), new.split("\n")
    old_roles, new_roles = _line_roles(old), _line_roles(new)
    anchors = _transform_anchors(root)
    phrases = _asserted_phrases(root)
    flat_new = " ".join(new.split())
    new_stripped = [line.strip() for line in new_lines]
    found: list[Touch] = []

    def classify(side: str, no: int, line: str, role: tuple[str, str]) -> None:
        kind, detail = role
        text = line.strip()
        if kind == "block":
            owner = next((b.owner for b in doc_blocks.BLOCKS if b.name == detail), "its generator")
            found.append(
                Touch(
                    "block", no, side, f"generated block {detail} (written by scripts/{owner}.py)"
                )
            )
        elif kind in ("fence", "marker"):
            found.append(
                Touch("install-case", no, side, f"install example {detail or '(unmarked)'}")
            )
        # The transform splits on the anchor line and asserts it appears exactly once.
        if side == "old" and text in anchors and new_stripped.count(text) != 1:
            found.append(Touch("transform-anchor", no, side, f"the transform anchors on {text!r}"))
        if kind == "prose" or kind == "block":
            for label, pattern in FIGURE_PATTERNS:
                if pattern.search(line):
                    found.append(
                        Touch("figure-phrase", no, side, f"{label}: {pattern.search(line)[0]}")
                    )
        if kind == "prose" and HEADING.match(line):
            found.append(Touch("link-anchor", no, side, f"heading {text!r}"))
        elif kind == "prose" and LINK.search(line):
            found.append(Touch("link-anchor", no, side, "a link"))
        if side == "old":
            flat = " ".join(line.split())
            for phrase, test in phrases.items():
                if phrase in flat and phrase not in flat_new:
                    found.append(Touch("doc-contract-test", no, side, f"{test} asserts {phrase!r}"))

    matcher = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if tag in ("replace", "delete"):
            for i in range(i1, i2):
                classify("old", i + 1, old_lines[i], old_roles[i])
        if tag in ("replace", "insert"):
            for j in range(j1, j2):
                classify("new", j + 1, new_lines[j], new_roles[j])
    unique = dict.fromkeys(found)
    return list(unique)


def report(touches: list[Touch]) -> str:
    """The lint's text: one section per layer touched, or the prose-only statement."""
    if not touches:
        return (
            "readme-contracts: README.md changed and touches no generated block, install "
            "example, figure, transform anchor, heading, link or pinned phrase: a prose-only "
            "edit. It needs no test, generator or source edit."
        )
    out = ["readme-contracts: this README.md change touches:"]
    for layer in LAYERS:
        items = [t for t in touches if t.layer == layer]
        if not items:
            continue
        check, fix = LAYER_ADVICE[layer]
        out.append(f"  [{layer}]  check: {check}")
        out.append(f"      fix: {fix}")
        owners = sorted({o for c in INVENTORY if c.layer == layer for o in c.owners})
        out.append(f"      owners: {', '.join(owners[:6])}{' ...' if len(owners) > 6 else ''}")
        for t in items[:8]:
            out.append(f"      README.md:{t.line} ({t.side}): {t.detail}")
        if len(items) > 8:
            out.append(f"      ... and {len(items) - 8} more")
    return "\n".join(out)


def _show(rev: str, path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{rev}:{path}"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    return result.stdout if result.returncode == 0 else ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", help="base revision (the README before the change)")
    parser.add_argument("--head", default="HEAD", help="head revision (default HEAD)")
    parser.add_argument("--old", type=Path, help="compare these files instead of revisions")
    parser.add_argument("--new", type=Path)
    parser.add_argument("--json", action="store_true", help="print the touches as JSON")
    parser.add_argument("--inventory", action="store_true", help="print the inventory as Markdown")
    args = parser.parse_args(argv)
    if args.inventory:
        sys.stdout.write(inventory_markdown())
        return 0
    if args.old and args.new:
        old, new = args.old.read_text(encoding="utf-8"), args.new.read_text(encoding="utf-8")
    elif args.base:
        old, new = _show(args.base, README), _show(args.head, README)
    else:
        parser.error("give --base REV (and optionally --head REV), or --old FILE --new FILE")
    if old == new:
        print("readme-contracts: README.md unchanged")
        return 0
    found = touched(old, new)
    if args.json:
        print(json.dumps([t.__dict__ for t in found], indent=2))
    else:
        print(report(found))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
