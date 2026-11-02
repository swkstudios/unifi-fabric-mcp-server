"""Selection policy is executable without collecting the project catalog."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("selector", ROOT / "scripts/select_pr_tests.py")
selector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(selector)


@pytest.fixture(autouse=True)
def _isolate_git_environment(monkeypatch):
    for name in list(os.environ):
        if name.startswith("GIT_"):
            monkeypatch.delenv(name, raising=False)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def tree(self, files):
        for name, content in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        return self.root

    def select(self, changed, **kw):
        return selector.select_tests(self.root, changed, **kw)

    def test_explicit_review_and_release_readers(self):
        doc_readers = set(selector.DOC_READER_PATTERNS.get("docs/*/testing/*.md", ()))
        release_readers = set(selector.RELEASE_SANITIZATION_READERS)
        self.tree({name: "def test_reader(): pass" for name in release_readers | doc_readers})
        for name in (
            "docs/private/testing/README.md",
            "docs/private/testing/ref/review-lenses.md",
        ):
            with self.subTest(name=name):
                self.assertTrue(doc_readers <= set(self.select([name])))
        for name in (
            "src/unifi_fabric/redaction.py",
            ".github/scripts/check_fixtures_sanitization.py",
            "changelog.d/nested/input.json",
            "changelog.d/new.fixed.md",
        ):
            with self.subTest(name=name):
                self.assertTrue(release_readers <= set(self.select([name])))

    def test_spec_and_recorded_changes_select_redaction_name_coverage(self):
        target = "tests/test_redaction_name_coverage.py"
        self.tree({target: "def test_names(): pass"})
        for name in (
            "tests/fixtures/openapi/future-service.json",
            "tests/fixtures/recorded/new-service/response.json",
            "tests/fixtures/spec_drift/baseline_snapshot.json",
            "scripts/vendor_openapi_specs.py",
            "src/unifi_fabric/redaction.py",
            "src/unifi_fabric/redaction_nonsecrets.py",
        ):
            with self.subTest(name=name):
                targets = {}
                self.assertIn(target, self.select([name], targets=targets))
                self.assertIn("*", targets[target])

    def test_paging_implementation_always_selects_complete_property_campaign(self):
        target = "tests/test_pagination_properties.py"
        self.tree({target: "def test_generated_contract(): pass"})
        for source in (
            "src/unifi_fabric/_paging_identity.py",
            "src/unifi_fabric/client.py",
            "src/unifi_fabric/tools/_pagination.py",
        ):
            with self.subTest(source=source):
                members = {}
                self.assertIn(target, self.select([source], targets=members))
                self.assertIn("*", members[target])

    def test_flow_implementation_and_shared_paging_select_flow_regressions(self):
        target = "tests/test_pagination_flows_regression.py"
        self.tree({target: "def test_flow_contract(): pass"})
        for source in (
            "src/unifi_fabric/_paging_identity.py",
            "src/unifi_fabric/client.py",
            "src/unifi_fabric/tools/_pagination.py",
            "src/unifi_fabric/tools/network_nat_qos_traffic.py",
        ):
            with self.subTest(source=source):
                members = {}
                self.assertIn(target, self.select([source], targets=members))
                self.assertIn("*", members[target])

    def test_prose_never_runs_pytest_even_when_test_reads_changelog(self):
        self.tree(
            {
                "tests/test_reader.py": 'def test_text():\n open("CHANGELOG.md")',
                "tests/test_invariants.py": "def test_i(): pass",
            }
        )
        for name in ("CHANGELOG.md", "README.md", "notes/intro.md"):
            self.assertEqual(self.select([name]), [])

    def test_every_changelog_d_markdown_file_selects_its_readers(self):
        readers = selector.CHANGELOG_D_READERS
        self.tree(
            {
                **{name: "def test_section(): pass" for name in readers},
                "tests/test_other.py": "def test_x(): pass",
                "tests/test_invariants.py": "def test_i(): pass",
            }
        )
        for name in ("changelog.d/lane-1.changed.md", "changelog.d/README.md"):
            self.assertEqual(self.select([name]), sorted(readers), name)
        self.assertEqual(
            self.select(["changelog.d/1.rst"]),
            sorted(set(readers) & set(selector.RELEASE_SANITIZATION_READERS)),
        )

    def test_changelog_d_readme_alone_selects_the_doc_reference_check(self):
        # The README's example bullet names tools; the doc-reference check reads it.
        self.assertIn("tests/test_docs_references.py", selector.CHANGELOG_D_READERS)
        selected = selector.select_tests(ROOT, ["changelog.d/README.md"])
        self.assertIn("tests/test_docs_references.py", selected)

    def test_docs_only_select_their_readers_without_smoke(self):
        self.tree(
            {
                "tests/test_docs.py": 'def test_doc():\n open("docs/API.md")',
                "tests/test_other.py": "def test_x(): pass",
                "tests/test_invariants.py": "def test_i(): pass",
            }
        )
        self.assertEqual(self.select(["docs/API.md"]), ["tests/test_docs.py"])
        self.assertEqual(self.select(["docs/unread.txt"]), [])

    def test_source_tracks_transitive_relative_symbol_imports(self):
        self.tree(
            {
                "src/pkg/core.py": "VALUE = 1",
                "src/pkg/helper.py": "from .core import VALUE\ndef f(): return VALUE",
                "tests/test_one.py": "from pkg.helper import f\ndef test_f(): f()",
                "tests/test_other.py": "def test_o(): pass",
            }
        )
        self.assertEqual(self.select(["src/pkg/core.py"]), ["tests/test_one.py"])

    def test_barrel_module_import_does_not_infect_unrelated_symbols(self):
        self.tree(
            {
                "src/pkg/discovery.py": "def find(): pass",
                "src/pkg/server.py": (
                    "from . import discovery\nmcp = 1\ndef search(): return discovery.find()"
                ),
                "tests/test_find.py": "from pkg import server\ndef test_f(): server.search()",
                "tests/test_other.py": "from pkg import server\ndef test_o(): return server.mcp",
            }
        )
        self.assertEqual(self.select(["src/pkg/discovery.py"]), ["tests/test_find.py"])

    def test_unknown_and_deleted_executables_do_not_expand(self):
        self.tree({"tests/test_other.py": "def test_o(): pass"})
        self.assertEqual(self.select(["scripts/new.py", "src/pkg/deleted.py", "scripts/a.sh"]), [])

    def test_deleted_imported_module_keeps_importer(self):
        self.tree(
            {
                "tests/test_old.py": "from pkg.deleted import f\ndef test_f(): f()",
                "tests/test_other.py": "def test_o(): pass",
            }
        )
        self.assertEqual(self.select(["src/pkg/deleted.py"]), ["tests/test_old.py"])

    def test_reference_drift_fingerprint_inputs_select_its_test_for_pr_500_paths(self):
        # PR 500 changed paths (git diff --name-only 9b0164c3..9476cbdc), pinned so
        # the test runs in a shallow checkout that lacks those revisions.
        changed = [
            ".github/PULL_REQUEST_TEMPLATE.md",
            "CHANGELOG.md",
            "CONTRIBUTING.md",
            "docs/MIGRATING-0.7.md",
            "pyproject.toml",
            "tests/fixtures/v0_6_2_lock_pins.json",
            "tests/test_dependency_versions_docs.py",
            "tests/test_front_page_docs.py",
        ]
        reasons = {}
        # With full history the PR 500 pyproject.toml edit classifies as non-testing
        # (targeted); pin that result instead of reading the two revisions from git.
        with patch.object(selector, "_pyproject_test_config_changed", return_value=False):
            selected = selector.select_tests(
                ROOT, changed, reasons=reasons, base="9b0164c3", head="9476cbdc"
            )
        drift_test = selector.DRIFT_TEST
        if (ROOT / selector.DRIFT_CHECKER).exists() and (ROOT / drift_test).exists():
            assert "pyproject.toml" in selector.coverage_fingerprint_inputs(ROOT)
            assert drift_test in selected
            assert reasons[drift_test] == {
                "reference-drift coverage fingerprint input: pyproject.toml"
            }
        else:
            # Public tree: the checker and its test are stripped, the rule selects nothing.
            assert selector.coverage_fingerprint_inputs(ROOT) == frozenset()
            assert drift_test not in selected

    def test_reference_drift_fingerprint_input_selects_its_test_in_any_tree(self):
        drift_test = selector.DRIFT_TEST
        self.tree(
            {
                "pyproject.toml": "[project]\nname = 'x'\n",
                "src/pkg/mod.py": "VALUE = 1\n",
                selector.DRIFT_CHECKER: (
                    "def coverage_fingerprint(root):\n"
                    "    return (root / 'pyproject.toml').read_bytes()\n"
                ),
                drift_test: "def test_drift(): pass\n",
                "tests/test_other.py": "def test_other(): pass\n",
            }
        )
        assert selector.coverage_fingerprint_inputs(self.root) == {"pyproject.toml"}
        reasons = {}
        with patch.object(selector, "_pyproject_test_config_changed", return_value=False):
            selected = self.select(["pyproject.toml"], reasons=reasons, base="a", head="b")
            assert drift_test in selected
            assert reasons[drift_test] == {
                "reference-drift coverage fingerprint input: pyproject.toml"
            }
            # Without the checker (the public tree) the rule selects nothing.
            (self.root / selector.DRIFT_CHECKER).unlink()
            assert selector.coverage_fingerprint_inputs(self.root) == frozenset()
            assert drift_test not in self.select(["pyproject.toml"], base="a", head="b")

    def test_pages_read_through_a_mapping_select_their_reader(self):
        """Regression: a manifest test read its pages through a dict constant
        (``{name: path.read_text() for name, path in PAGES.items()}``), so a change to
        one page alone selected nothing and the stale section hash failed only later."""
        reader = "tests/test_manual_pages.py"
        self.tree(
            {
                "docs/manual/guide/README.md": "# Guide\n",
                "docs/manual/guide/ref/one.md": "# One\n",
                "docs/manual/other.md": "# Other\n",
                "tests/test_unrelated.py": "def test_unrelated(): pass\n",
                reader: (
                    "from pathlib import Path\n"
                    "import pytest\n"
                    "ROOT = Path(__file__).resolve().parents[1]\n"
                    "PAGES = {\n"
                    "    'README.md': ROOT / 'docs/manual/guide/README.md',\n"
                    "    'ref/one.md': ROOT / 'docs/manual/guide/ref/one.md',\n"
                    "}\n"
                    "@pytest.fixture\n"
                    "def pages():\n"
                    "    return {name: path.read_text() for name, path in PAGES.items()}\n"
                    "def test_sections(pages):\n"
                    "    assert pages\n"
                    "def test_each_page():\n"
                    "    for path in sorted(PAGES.values()):\n"
                    "        assert path.read_text()\n"
                ),
            }
        )
        for page in ("docs/manual/guide/README.md", "docs/manual/guide/ref/one.md"):
            with self.subTest(page=page):
                targets = {}
                self.assertEqual(self.select([page], targets=targets), [reader])
                self.assertEqual(targets[reader], {"test_sections", "test_each_page"})
        self.assertEqual(self.select(["docs/manual/other.md"]), [])

    def test_deleted_fingerprint_input_under_a_searched_directory_selects_its_test(self):
        # A deleted file is no longer in the tree to be read, but the fingerprint hashed
        # it: the checker's rglob searches cover it.
        drift_test = selector.DRIFT_TEST
        self.tree(
            {
                selector.DRIFT_CHECKER: (
                    "def coverage_fingerprint(root):\n"
                    "    paths = [root / 'pyproject.toml', *sorted((root / 'src').rglob('*.py'))]\n"
                    "    return b''.join(path.read_bytes() for path in paths)\n"
                ),
                drift_test: "def test_drift(): pass\n",
                "src/pkg/kept.py": "VALUE = 1\n",
                "src/pkg/notes.txt": "not hashed\n",
            }
        )
        files, globs = selector.coverage_fingerprint_observed(self.root)
        self.assertEqual(files, {"pyproject.toml", "src/pkg/kept.py"})
        self.assertEqual(globs, {("src", "*.py")})
        for name in ("src/pkg/kept.py", "src/pkg/deleted.py", "src/deep/er/gone.py"):
            with self.subTest(name=name):
                reasons = {}
                with patch.object(selector, "_pyproject_test_config_changed", return_value=False):
                    self.assertIn(drift_test, self.select([name], reasons=reasons))
                self.assertEqual(
                    reasons[drift_test], {f"reference-drift coverage fingerprint input: {name}"}
                )
        for name in ("src/pkg/notes.txt", "scripts/pkg/gone.py", "srcx/gone.py"):
            with self.subTest(name=name):
                self.assertNotIn(drift_test, self.select([name]))

    def test_stale_fingerprint_fixture_after_an_input_change_selects_its_test(self):
        """Regression (integration/0.7.0 cf9a531): source files the drift checker hashes
        changed, its stored fingerprint fixture went stale, and four of its tests failed
        only in CI's full suite. Every input change, including a deleted source file,
        must select the test file. The checker is the real one: the inputs are what its
        own coverage_fingerprint reads and searches, never a copy of its list."""
        drift_test = selector.DRIFT_TEST
        real_checker = ROOT / selector.DRIFT_CHECKER
        if not real_checker.exists():
            # Public tree: the checker is stripped and the rule selects nothing.
            self.assertEqual(
                selector.coverage_fingerprint_observed(ROOT), (frozenset(), frozenset())
            )
            return
        self.tree(
            {
                selector.DRIFT_CHECKER: real_checker.read_text(),
                drift_test: "def test_drift(): pass\n",
                "src/unifi_fabric/kept.py": "VALUE = 1\n",
                "src/unifi_fabric/removed.py": "VALUE = 2\n",
                "docs/UNRELATED.md": "prose\n",
            }
        )
        # Create every declared input the fingerprint reads, as the checker names them.
        for name in selector.coverage_fingerprint_inputs(self.root):
            path = self.root / name
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"{name}\n")
        spec = importlib.util.spec_from_file_location(
            "drift_checker_copy", self.root / selector.DRIFT_CHECKER
        )
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        catalog = checker.TOOL_CATALOG
        catalog.parent.mkdir(parents=True, exist_ok=True)

        def store_fixture():
            catalog.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "fingerprint": checker.coverage_fingerprint(self.root),
                        "coverage": [{"verb": "GET", "route": "/v1/sites"}],
                    }
                )
            )
            checker.load_tool_coverage(self.root, catalog)  # current

        for change, edit in (
            ("src/unifi_fabric/kept.py", lambda p: p.write_text("VALUE = 3\n")),
            ("src/unifi_fabric/removed.py", lambda p: p.unlink()),
        ):
            with self.subTest(change=change):
                store_fixture()
                edit(self.root / change)
                with self.assertRaisesRegex(ValueError, "stale hermetic tool coverage"):
                    checker.load_tool_coverage(self.root, catalog)
                reasons = {}
                with patch.object(selector, "_pyproject_test_config_changed", return_value=False):
                    self.assertIn(drift_test, self.select([change], reasons=reasons))
                self.assertIn(
                    f"reference-drift coverage fingerprint input: {change}", reasons[drift_test]
                )
        # A file outside the fingerprint leaves the fixture current and selects nothing.
        store_fixture()
        (self.root / "docs/UNRELATED.md").write_text("edited\n")
        checker.load_tool_coverage(self.root, catalog)
        self.assertNotIn(drift_test, self.select(["docs/UNRELATED.md"]))

    def test_dependency_environment_changes_are_full_tier_with_reasons(self):
        self.tree({"tests/test_one.py": "pass", "tests/test_two.py": "pass"})
        for name in ("pyproject.toml", "requirements.lock", "requirements-dev.txt", "uv.lock"):
            why = {}
            self.assertEqual(len(self.select([name], reasons=why)), 2)
            self.assertTrue(all(f"full tier: {name}" in r for r in why.values()))

    def test_workflow_test_config_selector_and_transform_changes_are_full_tier(self):
        self.tree({"tests/test_one.py": "pass", "tests/test_two.py": "pass"})
        for name in (
            ".github/workflows/ci.yml",
            "tests/conftest.py",
            "conftest.py",
            "pytest.ini",
            "tox.ini",
            "setup.cfg",
            "scripts/select_pr_tests.py",
        ):
            why = {}
            self.assertEqual(len(self.select([name], reasons=why)), 2, name)
            self.assertTrue(all(f"full tier: {name}" in r for r in why.values()), name)
            self.assertTrue(selector._full_config(name), name)

    def test_nested_conftest_and_other_scripts_stay_targeted(self):
        for name in (
            "tests/unit/conftest.py",
            ".github/scripts/check_fixtures_sanitization.py",
            "scripts/prepush.sh",
            "docs/workflows.md",
        ):
            self.assertFalse(selector._full_config(name), name)

    def test_full_tier_includes_catalog_without_changes(self):
        self.tree({"tests/test_catalog.py": "pass", "tests/test_one.py": "pass"})
        self.assertEqual(len(self.select([], tier="full")), 2)

    def test_changed_test_and_fast_smoke_without_catalog(self):
        self.tree(
            {
                "tests/test_changed.py": "def test_c(): pass",
                "tests/test_secret_leak_invariant.py": "def test_i(): pass",
                "tests/test_cross_tool_chokepoints.py": "def test_x(): pass",
                "tests/test_catalog.py": "def test_cat(): pass",
            }
        )
        why = {}
        self.assertEqual(
            self.select(["tests/test_changed.py"], reasons=why),
            [
                "tests/test_changed.py",
                "tests/test_cross_tool_chokepoints.py",
                "tests/test_secret_leak_invariant.py",
            ],
        )
        self.assertIn("changed test: tests/test_changed.py", why["tests/test_changed.py"])
        self.assertTrue(any("smoke:" in r for r in why["tests/test_secret_leak_invariant.py"]))

    def test_selector_releases_file_asts_during_repository_indexing(self):
        import weakref

        self.tree(
            {
                "src/pkg/core.py": "VALUE = 1",
                "tests/conftest.py": "import pytest\n@pytest.fixture\ndef value(): return 1",
                "tests/test_reader.py": (
                    "from pkg.core import VALUE\ndef test_value(value): assert value == VALUE"
                ),
                **{f"src/pkg/extra_{i}.py": f"VALUE = {i}" for i in range(12)},
            }
        )
        parse = selector.ast.parse
        previous_nodes = []
        parsed = 0

        def measured_parse(*args, **kwargs):
            nonlocal parsed
            # Both module roots and definition subtrees must die before the
            # next file is parsed; retaining either recreates catalog-scale RSS.
            self.assertFalse(any(ref() is not None for ref in previous_nodes))
            tree = parse(*args, **kwargs)
            previous_nodes[:] = [weakref.ref(tree), *(weakref.ref(n) for n in tree.body)]
            parsed += 1
            return tree

        with patch.object(selector.ast, "parse", side_effect=measured_parse):
            self.assertEqual(self.select(["src/pkg/core.py"]), ["tests/test_reader.py"])
        self.assertGreater(parsed, 12)
        self.assertFalse(any(ref() is not None for ref in previous_nodes))

    def test_every_invariant_suite_is_in_the_explicit_smoke_set(self):
        invariant_files = {
            str(p.relative_to(ROOT)) for p in (ROOT / "tests").glob("*invariant*.py")
        }
        self.assertTrue(invariant_files)
        self.assertFalse(invariant_files - selector.SMOKE_TEST_FILES)
        self.assertTrue(all((ROOT / name).is_file() for name in selector.SMOKE_TEST_FILES))
        why = {}
        selected = selector.select_tests(ROOT, ["scripts/arbitrary_executable.py"], reasons=why)
        self.assertTrue(selector.SMOKE_TEST_FILES.issubset(selected))
        self.assertTrue(
            all(any("smoke:" in r for r in why[name]) for name in selector.SMOKE_TEST_FILES)
        )

    def test_unbatched_catalog_audits_are_in_the_explicit_smoke_set(self):
        # These inspect all registered tools or all matching catalog schemas
        # without importing the batching decorators caught by the next guard.
        audits = {
            "tests/test_argument_errors.py",
            "tests/test_explicit_page_and_purpose_docs.py",
            "tests/test_protect_body_docs.py",
        }
        self.assertFalse(audits - selector.SMOKE_TEST_FILES)

    def test_catalog_batching_siblings_are_in_the_explicit_smoke_set(self):
        # These decorators define cross-catalog properties even when their file
        # names omit "invariant" (spec conformance, refusal policy, discovery...).
        import ast

        siblings = set()
        for path in (ROOT / "tests").glob("test_*.py"):
            tree = ast.parse(path.read_text())
            if any(
                isinstance(node, ast.ImportFrom)
                and node.module == "tests._tool_classes"
                and any(alias.name in {"tool_batches", "class_axis"} for alias in node.names)
                for node in ast.walk(tree)
            ):
                siblings.add(path.relative_to(ROOT).as_posix())
        self.assertTrue(siblings)
        self.assertFalse(siblings - selector.SMOKE_TEST_FILES)

    def test_conftest_selects_fixture_users_transitively_and_usefixtures(self):
        self.tree(
            {
                "tests/unit/conftest.py": (
                    "import pytest\n"
                    "@pytest.fixture\n"
                    "def base(): pass\n"
                    "@pytest.fixture\n"
                    "def client(base): pass"
                ),
                "tests/unit/test_one.py": "def test_o(client): pass",
                "tests/unit/test_mark.py": (
                    'import pytest\n@pytest.mark.usefixtures("base")\ndef test_m(): pass'
                ),
                "tests/unit/test_other.py": "def test_x(): pass",
            }
        )
        self.assertEqual(
            self.select(
                ["tests/unit/conftest.py"], definitions={"tests/unit/conftest.py": {"base"}}
            ),
            ["tests/unit/test_mark.py", "tests/unit/test_one.py"],
        )

    def test_reexported_fixture_tracks_helper_symbol(self):
        self.tree(
            {
                "tests/helper.py": "import pytest\n@pytest.fixture\ndef shared(): pass",
                "tests/conftest.py": "from tests.helper import shared",
                "tests/test_one.py": "def test_o(shared): pass",
                "tests/test_other.py": "def test_x(): pass",
            }
        )
        self.assertEqual(self.select(["tests/helper.py"]), ["tests/test_one.py"])

    def test_conftest_source_import_without_fixture_usage_is_not_full(self):
        self.tree(
            {
                "src/pkg/core.py": "VALUE = 1",
                "tests/conftest.py": "from pkg.core import VALUE",
                "tests/test_other.py": "def test_x(): pass",
            }
        )
        self.assertEqual(self.select(["src/pkg/core.py"]), [])

    def test_nested_fixture_scope(self):
        self.tree(
            {
                "tests/nested/conftest.py": "import pytest\n@pytest.fixture\ndef shared(): pass",
                "tests/nested/test_one.py": "def test_o(shared): pass",
                "tests/test_other.py": "def test_x(shared): pass",
            }
        )
        self.assertEqual(self.select(["tests/nested/conftest.py"]), ["tests/nested/test_one.py"])

    def test_autouse_fixture_is_an_implicit_scoped_request(self):
        self.tree(
            {
                "tests/nested/conftest.py": (
                    "import pytest\n@pytest.fixture(autouse=True)\ndef setup(): pass"
                ),
                "tests/nested/test_a.py": "def test_a(): pass",
                "tests/test_b.py": "def test_b(): pass",
            }
        )
        self.assertEqual(self.select(["tests/nested/conftest.py"]), ["tests/nested/test_a.py"])

    def test_named_fixture_and_module_usefixtures(self):
        self.tree(
            {
                "tests/unit/conftest.py": (
                    'from pytest import fixture as fx\n@fx(name="shared")\ndef internal(): pass'
                ),
                "tests/unit/test_a.py": (
                    'import pytest\npytestmark = pytest.mark.usefixtures("shared")\n'
                    "def test_a(): pass"
                ),
                "tests/unit/test_b.py": "def test_b(): pass",
            }
        )
        self.assertEqual(self.select(["tests/unit/conftest.py"]), ["tests/unit/test_a.py"])

    def test_autouse_reset_only_depends_on_reflected_literal_attributes(self):
        self.tree(
            {
                "src/pkg/discovery.py": "def find(): pass",
                "src/pkg/server.py": "from .discovery import find\nmcp = 1",
                "tests/conftest.py": (
                    "import pytest\nfrom pkg import server\n@pytest.fixture(autouse=True)\n"
                    "def reset():\n for name in ('mcp', '_settings'):\n  getattr(server, name)"
                ),
                "tests/test_a.py": "def test_a(): pass",
            }
        )
        self.assertEqual(self.select(["src/pkg/discovery.py"]), [])
        self.assertEqual(
            self.select(["src/pkg/server.py"], definitions={"src/pkg/server.py": {"mcp"}}),
            ["tests/test_a.py"],
        )

    def test_literal_dynamic_fixture_request(self):
        self.tree(
            {
                "tests/unit/conftest.py": "import pytest\n@pytest.fixture\ndef shared(): pass",
                "tests/unit/test_one.py": 'def test_o(request): request.getfixturevalue("shared")',
            }
        )
        self.assertEqual(self.select(["tests/unit/conftest.py"]), ["tests/unit/test_one.py"])

    def test_helper_symbol_change_selects_only_importing_consumer(self):
        self.tree(
            {
                "tests/helper.py": "def a(): pass\ndef b(): pass",
                "tests/test_a.py": "from tests.helper import a\ndef test_a(): a()",
                "tests/test_b.py": "from tests.helper import b\ndef test_b(): b()",
            }
        )
        self.assertEqual(
            self.select(["tests/helper.py"], definitions={"tests/helper.py": {"a"}}),
            ["tests/test_a.py"],
        )

    def test_fixture_asset_readers_do_not_include_sibling_paths(self):
        self.tree(
            {
                "tests/test_a.py": 'def test_a():\n open("tests/fixtures/a.json")',
                "tests/test_b.py": 'def test_b():\n open("tests/fixtures/b.json")',
            }
        )
        self.assertEqual(self.select(["tests/fixtures/a.json"]), ["tests/test_a.py"])

    def test_module_constant_path_reader(self):
        self.tree(
            {
                "tests/test_a.py": (
                    "from pathlib import Path\n"
                    'FILE=Path("docs") / "API.md"\n'
                    "def test_a(): FILE.read_text()"
                )
            }
        )
        self.assertEqual(self.select(["docs/API.md"]), ["tests/test_a.py"])

    def test_generate_hook_selects_lazy_and_tool_readers(self):
        self.tree(
            {
                "tests/unit/conftest.py": "def pytest_generate_tests(metafunc): pass",
                "tests/unit/test_a.py": (
                    "import pytest\n"
                    '@pytest.mark.lazy_parametrize("name", lambda: [])\n'
                    "def test_a(name): pass"
                ),
                "tests/unit/test_b.py": "def test_b(tool): pass",
                "tests/unit/test_c.py": "def test_c(): pass",
            }
        )
        self.assertEqual(
            self.select(["tests/unit/conftest.py"]),
            ["tests/unit/test_a.py", "tests/unit/test_b.py"],
        )

    def test_module_attribute_patching_is_not_wildcard_dependency(self):
        self.tree(
            {
                "src/pkg/discovery.py": "def find(): pass",
                "src/pkg/server.py": (
                    "from .discovery import find\ndef lifespan(): find()\n_client=None"
                ),
                "tests/helper.py": (
                    "from pkg import server\ndef install(mp): mp.setattr(server, '_client', None)"
                ),
                "tests/test_patch.py": (
                    "from tests.helper import install\ndef test_patch(mp): install(mp)"
                ),
                "tests/test_life.py": (
                    "from pkg.server import lifespan\ndef test_life(): lifespan()"
                ),
            }
        )
        self.assertEqual(self.select(["src/pkg/discovery.py"]), ["tests/test_life.py"])

    def test_callback_registration_does_not_execute_callback(self):
        self.tree(
            {
                "src/pkg/core.py": "def find(): pass",
                "src/pkg/server.py": (
                    "from .core import find\ndef lifespan(): find()\napp=Factory(lifespan=lifespan)"
                ),
                "tests/test_app.py": "from pkg.server import app\ndef test_app(): app.tools()",
                "tests/test_life.py": (
                    "from pkg.server import lifespan\ndef test_life(): lifespan()"
                ),
            }
        )
        self.assertEqual(self.select(["src/pkg/core.py"]), ["tests/test_life.py"])

    def test_wildcard_helper_import_has_consumers(self):
        self.tree(
            {
                "tests/helper.py": "def helper(): pass",
                "tests/test_one.py": "from tests.helper import *\ndef test_h(): helper()",
            }
        )
        self.assertEqual(self.select(["tests/helper.py"]), ["tests/test_one.py"])

    def test_subprocess_script_reader(self):
        self.tree(
            {
                "tests/test_one.py": (
                    'import subprocess\ndef test_cli(): subprocess.run(["python", "scripts/do.py"])'
                )
            }
        )
        self.assertEqual(self.select(["scripts/do.py"]), ["tests/test_one.py"])

    def test_glob_reader_keeps_directory_depth(self):
        self.tree(
            {
                "tests/test_docs.py": (
                    "from pathlib import Path\ndef test_docs():\n"
                    ' for p in (Path("docs")).glob("*.md"): p.read_text()'
                )
            }
        )
        self.assertEqual(self.select(["docs/API.md"]), ["tests/test_docs.py"])
        self.assertEqual(self.select(["docs/archive/note.md"]), [])
        self.tree({"tests/test_root.py": 'def test_root(): open("README.md")'})
        self.assertEqual(self.select(["docs/archive/README.md"]), [])

    def test_doc_dynamic_readers_are_explicit_and_public_only(self):
        self.tree({"tests/test_docs_references.py": "def test_docs(): pass"})
        self.assertEqual(self.select(["docs/TOOLS.md"]), ["tests/test_docs_references.py"])
        self.assertEqual(self.select(["docs/archive/note.md"]), [])

    def test_rename_keeps_old_and_new_paths(self):
        self.assertEqual(
            selector.changed_paths("R100\tsrc/old.py\tsrc/new.py\nD\ttests/old.py\nM\tREADME.md"),
            ["src/old.py", "src/new.py", "tests/old.py", "README.md"],
        )

    def changed_symbols(self, before, after, hunks):
        from types import SimpleNamespace

        with (
            patch.object(subprocess, "check_output", return_value=hunks),
            patch.object(
                subprocess,
                "run",
                side_effect=[
                    SimpleNamespace(returncode=0, stdout=before),
                    SimpleNamespace(returncode=0, stdout=after),
                ],
            ),
        ):
            return selector.changed_definitions(self.root, "base", "head", ["tests/conftest.py"])[
                "tests/conftest.py"
            ]

    def test_changed_definitions_does_not_parse_python_outside_the_source_graph(self):
        with patch.object(subprocess, "check_output") as command:
            self.assertEqual(
                selector.changed_definitions(
                    self.root, "base", "head", ["docs/archive/example.py"]
                ),
                {},
            )
        command.assert_not_called()

    def test_import_hunk_does_not_change_untouched_autouse_fixtures(self):
        before = "import pytest\n@pytest.fixture(autouse=True)\ndef clean(): pass\n"
        after = "from logging import basicConfig\n" + before + "basicConfig()\n"
        self.assertEqual(
            self.changed_symbols(before, after, "@@ -0,0 +1 @@\n@@ -3,0 +5 @@\n"), {"basicConfig"}
        )

    def test_import_hunk_changes_only_the_modified_alias(self):
        self.assertEqual(
            self.changed_symbols(
                "from pkg import keep, old\n", "from pkg import keep, new\n", "@@ -1 +1 @@\n"
            ),
            {"old", "new"},
        )

    def test_changed_decorator_and_removed_definition_keep_their_names(self):
        self.assertEqual(
            self.changed_symbols(
                "@fixture(autouse=False)\ndef shared(): pass\ndef gone(): pass\n",
                "@fixture(autouse=True)\ndef shared(): pass\n",
                "@@ -1 +1 @@\n@@ -3 +2,0 @@\n",
            ),
            {"shared", "gone"},
        )

    def test_hunks_do_not_select_adjacent_unchanged_definition_or_formatting(self):
        self.assertEqual(
            self.changed_symbols(
                "def keep(): return 1\ndef change(): return 2\n",
                "def keep(): return 1\ndef change(): return 3\n",
                "@@ -2 +2 @@\n",
            ),
            {"change"},
        )
        self.assertEqual(
            self.changed_symbols(
                "def keep(): return 1\n", "def keep():  return 1\n", "@@ -1 +1 @@\n"
            ),
            set(),
        )

    def test_changed_import_binding_selects_only_calling_fixture_users(self):
        self.tree(
            {
                "tests/unit/conftest.py": (
                    "import pytest\nfrom external import value\n"
                    "@pytest.fixture\ndef changed(): return value()\n"
                    "@pytest.fixture(autouse=True)\ndef clean(): pass\n"
                ),
                "tests/unit/test_user.py": "def test_user(changed): pass\n",
                "tests/unit/test_other.py": "def test_other(): pass\n",
            }
        )
        self.assertEqual(
            self.select(
                ["tests/unit/conftest.py"], definitions={"tests/unit/conftest.py": {"value"}}
            ),
            ["tests/unit/test_user.py"],
        )

    def test_member_targets_keep_only_changed_dependency_users(self):
        self.tree(
            {
                "src/pkg/core.py": "def value(): return 1\n",
                "tests/test_members.py": (
                    "from pkg.core import value\nclass TestMembers:\n"
                    " def test_user(self): value()\n def test_other(self): pass\n"
                ),
            }
        )
        targets = {}
        selected = self.select(["src/pkg/core.py"], targets=targets)
        self.assertEqual(
            selector.pytest_targets(selected, targets),
            ["tests/test_members.py::TestMembers::test_user"],
        )

    def test_method_hunk_does_not_change_the_class_or_sibling_method(self):
        self.assertEqual(
            self.changed_symbols(
                "class TestMembers:\n def test_one(self): return 1\n def test_two(self): pass\n",
                "class TestMembers:\n def test_one(self): return 2\n def test_two(self): pass\n",
                "@@ -2 +2 @@\n",
            ),
            {"TestMembers::test_one"},
        )

    def test_member_targets_follow_helpers_class_marks_and_lifecycle_methods(self):
        self.tree(
            {
                "src/pkg/core.py": "def value(): return 1\n",
                "tests/test_members.py": (
                    "from pkg.core import value\nclass TestMembers:\n"
                    " def helper(self): value()\n def test_user(self): self.helper()\n"
                    " def test_other(self): pass\n"
                ),
            }
        )
        targets = {}
        selected = self.select(["src/pkg/core.py"], targets=targets)
        self.assertEqual(
            selector.pytest_targets(selected, targets),
            ["tests/test_members.py::TestMembers::test_user"],
        )
        self.tree(
            {
                "tests/test_members.py": (
                    "from pkg.core import value\nclass TestMembers:\n"
                    " def setup_method(self): value()\n def test_user(self): pass\n"
                    " def test_other(self): pass\n"
                )
            }
        )
        targets = {}
        selected = self.select(["src/pkg/core.py"], targets=targets)
        self.assertEqual(len(selector.pytest_targets(selected, targets)), 2)

    def test_nested_class_member_targets_follow_their_parent_headers(self):
        self.tree(
            {
                "src/pkg/core.py": "def value(): return 1\n",
                "tests/test_members.py": (
                    "from pkg.core import value\nclass TestOuter:\n class TestInner:\n"
                    "  def test_user(self): value()\n  def test_other(self): pass\n"
                ),
            }
        )
        targets = {}
        selected = self.select(["src/pkg/core.py"], targets=targets)
        self.assertEqual(
            selector.pytest_targets(selected, targets),
            ["tests/test_members.py::TestOuter::TestInner::test_user"],
        )

    def test_same_named_autouse_fixtures_keep_their_class_scope(self):
        self.tree(
            {
                "src/pkg/core.py": "def value(): return 1\n",
                "tests/test_members.py": (
                    "import pytest\nfrom pkg.core import value\nclass TestOne:\n"
                    " @pytest.fixture(autouse=True)\n def setup(self): value()\n"
                    " def test_one(self): pass\nclass TestTwo:\n"
                    " @pytest.fixture(autouse=True)\n def setup(self): pass\n"
                    " def test_two(self): pass\n"
                ),
            }
        )
        targets = {}
        selected = self.select(["src/pkg/core.py"], targets=targets)
        self.assertEqual(
            selector.pytest_targets(selected, targets), ["tests/test_members.py::TestOne"]
        )

    def test_file_reader_targets_do_not_include_other_functions_with_calls(self):
        self.tree(
            {
                "tests/test_members.py": (
                    "def test_reader(): open('tests/fixtures/record.json')\n"
                    "def test_other(): other()\n"
                )
            }
        )
        targets = {}
        selected = self.select(["tests/fixtures/record.json"], targets=targets)
        self.assertEqual(
            selector.pytest_targets(selected, targets), ["tests/test_members.py::test_reader"]
        )

    def test_manifest_stays_a_complete_file_and_class_target_deduplicates_methods(self):
        self.assertEqual(
            selector.pytest_targets(
                ["tests/test_one.py"], {"tests/test_one.py": {"*", "test_one"}}
            ),
            ["tests/test_one.py"],
        )
        self.assertEqual(
            selector.pytest_targets(
                ["tests/test_one.py"], {"tests/test_one.py": {"TestOne", "TestOne::test_one"}}
            ),
            ["tests/test_one.py::TestOne"],
        )

    def test_cli_compares_definitions_from_the_same_merge_base_as_paths(self):
        with (
            patch.object(sys, "argv", ["selector", "--base", "base", "--head", "head"]),
            patch.object(
                subprocess,
                "check_output",
                side_effect=["M\ttests/conftest.py\n", "merge-base-sha\n"],
            ),
            patch.object(selector, "changed_definitions", return_value={}) as changed,
            patch.object(selector, "select_tests", return_value=[]),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            selector.main()
        self.assertEqual(changed.call_args.args[1:3], ("merge-base-sha", "head"))

    def test_cli_reasons_are_stderr_one_line_per_selected_file(self):
        # Exercise CLI without shell or credentials; use the real source tree.
        with (
            patch.object(sys, "argv", ["selector", "--base", "base", "--head", "head"]),
            patch.object(subprocess, "check_output", return_value="M\tpyproject.toml\n"),
            patch.object(selector, "changed_definitions", return_value={}),
            contextlib.redirect_stdout(io.StringIO()) as stdout,
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            selector.main()
        files = stdout.getvalue().splitlines()
        reasons = stderr.getvalue().splitlines()
        self.assertEqual(len(files), len(reasons))
        self.assertTrue(
            all(
                line.startswith(path + ": full tier: pyproject.toml")
                for path, line in zip(files, reasons, strict=True)
            )
        )


if __name__ == "__main__":
    unittest.main()


def test_fixture_import_family_selects_only_the_fixture_user(tmp_path):
    """Identical regression case exercised on the base and both selector policies."""
    import subprocess
    from types import SimpleNamespace
    from unittest.mock import patch

    before = (
        "import pytest\nfrom external_old import value\n"
        "@pytest.fixture\ndef shared(): return value()\n"
        "@pytest.fixture(autouse=True)\ndef clean(): pass\n"
    )
    after = before.replace("external_old", "external_new")
    for path, text in {
        "tests/unit/conftest.py": after,
        "tests/unit/test_user.py": "def test_user(shared): pass\n",
        "tests/unit/test_other.py": "def test_other(): pass\n",
    }.items():
        destination = tmp_path / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)
    options = {}
    if hasattr(selector, "changed_definitions"):
        with (
            patch.object(subprocess, "check_output", return_value="@@ -2 +2 @@\n"),
            patch.object(
                subprocess,
                "run",
                side_effect=[
                    SimpleNamespace(returncode=0, stdout=before),
                    SimpleNamespace(returncode=0, stdout=after),
                ],
            ),
        ):
            options["definitions"] = selector.changed_definitions(
                tmp_path, "old", "new", ["tests/unit/conftest.py"]
            )
    assert selector.select_tests(tmp_path, ["tests/unit/conftest.py"], **options) == [
        "tests/unit/test_user.py"
    ]


def test_targets_drop_nodes_the_checked_out_file_no_longer_defines(tmp_path):
    test = tmp_path / "tests" / "test_members.py"
    test.parent.mkdir()
    test.write_text("class TestKept:\n    def test_a(self): pass\ndef test_kept(): pass\n")
    path = "tests/test_members.py"
    members = {path: {"test_kept", "test_deleted", "TestKept::test_a", "TestGone::test_b"}}
    assert selector.pytest_targets([path], members, tmp_path) == [
        "tests/test_members.py::TestKept::test_a",
        "tests/test_members.py::test_kept",
    ]
    members = {path: {"test_deleted"}}
    assert selector.pytest_targets([path], members, tmp_path) == [path]


def test_unparsable_base_side_selects_the_head_bindings(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)  # noqa: S603, S607
    git = ["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@t"]
    module = tmp_path / "tests" / "helper_markers.py"
    module.parent.mkdir()
    module.write_text("<<<<<<< ours\ndef probe(): return 1\n=======\n>>>>>>> theirs\n")
    subprocess.run([*git, "add", "-A"], check=True)  # noqa: S603
    subprocess.run([*git, "commit", "-qm", "base"], check=True)  # noqa: S603
    module.write_text("def probe(): return 1\n")
    subprocess.run([*git, "commit", "-qam", "head"], check=True)  # noqa: S603
    changed = selector.changed_definitions(tmp_path, "HEAD~1", "HEAD", ["tests/helper_markers.py"])
    assert changed == {"tests/helper_markers.py": {"probe"}}


def _pyproject_repo(tmp_path, before, after):
    git = ["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)  # noqa: S603, S607
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("def test_a(): pass\n")
    (tmp_path / "pyproject.toml").write_text(before)
    subprocess.run([*git, "add", "-A"], check=True)  # noqa: S603
    subprocess.run([*git, "commit", "-qm", "base"], check=True)  # noqa: S603
    (tmp_path / "pyproject.toml").write_text(after)
    subprocess.run([*git, "commit", "-qam", "head"], check=True)  # noqa: S603
    return tmp_path


_PYPROJECT = """[project]
name = "p"
dependencies = ["httpx"]

[project.optional-dependencies]
dev = [
    "pytest",
]
"""


def test_comment_only_pyproject_edit_stays_targeted(tmp_path):
    after = _PYPROJECT.replace(
        '    "pytest",\n', '    # pytest plugins are pinned in CI\n    "pytest",\n'
    )
    root = _pyproject_repo(tmp_path, _PYPROJECT, after)
    assert not selector._full_config("pyproject.toml", root, "HEAD~1", "HEAD")
    assert selector.select_tests(root, ["pyproject.toml"], base="HEAD~1", head="HEAD") == []


def test_ruff_only_pyproject_edit_stays_targeted(tmp_path):
    after = _PYPROJECT + "\n[tool.ruff]\nline-length = 100\n"
    root = _pyproject_repo(tmp_path, _PYPROJECT, after)
    assert not selector._full_config("pyproject.toml", root, "HEAD~1", "HEAD")


def test_coverage_change_in_pyproject_selects_the_full_tier(tmp_path):
    after = _PYPROJECT + "\n[tool.coverage.report]\nfail_under = 90\n"
    root = _pyproject_repo(tmp_path, _PYPROJECT, after)
    assert selector._full_config("pyproject.toml", root, "HEAD~1", "HEAD")


def test_unknown_pyproject_table_selects_the_full_tier(tmp_path):
    after = _PYPROJECT + "\n[tool.future]\noption = true\n"
    root = _pyproject_repo(tmp_path, _PYPROJECT, after)
    assert selector._full_config("pyproject.toml", root, "HEAD~1", "HEAD")


def test_dependency_change_in_pyproject_selects_the_full_tier(tmp_path):
    after = _PYPROJECT.replace('"pytest",', '"pytest",\n    "pytest-xdist",')
    root = _pyproject_repo(tmp_path, _PYPROJECT, after)
    assert selector._full_config("pyproject.toml", root, "HEAD~1", "HEAD")
    assert selector.select_tests(root, ["pyproject.toml"], base="HEAD~1", head="HEAD") == [
        "tests/test_a.py"
    ]


def test_unparseable_pyproject_selects_the_full_tier(tmp_path):
    root = _pyproject_repo(tmp_path, _PYPROJECT, "[project\n")
    assert selector._full_config("pyproject.toml", root, "HEAD~1", "HEAD")


#: The source files of the delete-result change set (all 20 of its src/ paths). It
#: changed src/unifi_fabric/tools/protect_automation_backup.py and merged with six
#: failing cases of test_every_tool_preserves_upstream_body in
#: tests/test_protect_automation_backup.py: the selector chose that file, but smoke
#: mode sampled the function down to two of its 63 cases (one tool per class, first
#: harness row), so no delete case ran.
DELETE_RESULT_CHANGE_SET = (
    "src/unifi_fabric/catalog_descriptions.py",
    "src/unifi_fabric/client.py",
    "src/unifi_fabric/secret_scrub.py",
    "src/unifi_fabric/server.py",
    "src/unifi_fabric/tools/_classic_cmd.py",
    "src/unifi_fabric/tools/_classic_objects.py",
    "src/unifi_fabric/tools/client_records.py",
    "src/unifi_fabric/tools/connector.py",
    "src/unifi_fabric/tools/innerspace_internal.py",
    "src/unifi_fabric/tools/matter.py",
    "src/unifi_fabric/tools/network_clients_guests.py",
    "src/unifi_fabric/tools/network_controller_admin.py",
    "src/unifi_fabric/tools/network_dpi_policy.py",
    "src/unifi_fabric/tools/network_routing_topology.py",
    "src/unifi_fabric/tools/network_switching_power.py",
    "src/unifi_fabric/tools/protect_automation_backup.py",
    "src/unifi_fabric/tools/protect_camera_recording.py",
    "src/unifi_fabric/tools/protect_recognition_search.py",
    "src/unifi_fabric/tools/protect_users_assets.py",
    "src/unifi_fabric/tools/scheduled_tasks.py",
)


def test_a_changed_tool_module_runs_every_case_of_its_own_tests(tmp_path):
    from tests.test_protect_automation_backup import IDS

    changed = list(DELETE_RESULT_CHANGE_SET)
    path = "tests/test_protect_automation_backup.py"
    reasons, targets = {}, {}
    selected = selector.select_tests(ROOT, changed, reasons=reasons, targets=targets)
    assert path in selected
    assert "*" in targets[path]
    assert any(
        why.startswith("imports changed tool module:") and "protect_automation_backup" in why
        for why in reasons[path]
    )
    focus = selector.focus_modules(ROOT, changed)
    assert "protect_automation_backup" in focus
    focus_file = tmp_path / "pr-focus.txt"
    focus_file.write_text("".join(f"{module}\n" for module in focus))
    node = f"{path}::test_every_tool_preserves_upstream_body"
    collected = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "tests._pr_smoke",
            "--pr-smoke",
            "--pr-smoke-focus",
            str(focus_file),
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            node,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert collected.returncode == 0, collected.stdout + collected.stderr
    nodes = {line for line in collected.stdout.splitlines() if line.startswith(node + "[")}
    expected = {f"{node}[{body}-{name}]" for body in ("body0", "body1", "None") for name in IDS}
    assert nodes == expected
    assert {
        f"{node}[{body}-{name}]"
        for body in ("body0", "body1", "None")
        for name in ("delete_protect_automation", "delete_protect_backup")
    } <= nodes


def _tools_tree(root, modules):
    package = root / "src" / "unifi_fabric" / "tools"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    for name, body in modules.items():
        (package / f"{name}.py").write_text(body)
    return root


def test_focus_names_changed_tool_modules_and_their_importers(tmp_path):
    root = _tools_tree(
        tmp_path,
        {
            "_base": "VALUE = 1\n",
            "_wrap": "from ._base import VALUE\n",
            "alpha": "from unifi_fabric.tools._wrap import VALUE\n",
            "beta": "from . import _base\n",
            "gamma": "import json\n",
            "delta": "from unifi_fabric.tools import alpha\n",
        },
    )
    tools = "src/unifi_fabric/tools"
    assert selector.focus_modules(root, [f"{tools}/gamma.py"]) == ["gamma"]
    # A helper names every tool module that runs it, directly or through a helper.
    assert selector.focus_modules(root, [f"{tools}/_base.py"]) == ["alpha", "beta", "delta"]
    assert selector.focus_modules(root, [f"{tools}/alpha.py"]) == ["alpha", "delta"]
    assert selector.focus_modules(root, ["src/unifi_fabric/server.py"]) == ["server"]
    # A deleted module has no tools left; package init, docs and tests name nothing.
    assert selector.focus_modules(root, [f"{tools}/removed.py"]) == []
    assert selector.focus_modules(root, [f"{tools}/__init__.py", "README.md"]) == []


def test_a_test_importing_a_changed_tool_module_is_selected_whole(tmp_path):
    root = _tools_tree(
        tmp_path, {"alpha": "def run():\n    return 1\n\ndef other():\n    return 2\n"}
    )
    (root / "tests").mkdir()
    (root / "tests" / "test_alpha.py").write_text(
        "from unifi_fabric.tools import alpha\n"
        "def test_run():\n    assert alpha.run() == 1\n"
        "def test_catalog():\n    assert True\n"
    )
    (root / "tests" / "test_unrelated.py").write_text("def test_x():\n    assert True\n")
    reasons, targets = {}, {}
    selected = selector.select_tests(
        root,
        ["src/unifi_fabric/tools/alpha.py"],
        definitions={"src/unifi_fabric/tools/alpha.py": {"other"}},
        reasons=reasons,
        targets=targets,
    )
    assert selected == ["tests/test_alpha.py"]
    assert targets["tests/test_alpha.py"] == {"*"}
    assert reasons["tests/test_alpha.py"] == {
        "imports changed tool module: unifi_fabric.tools.alpha"
    }


def test_a_changed_test_is_listed_for_every_case(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_cases.py").write_text(
        "MESSAGES = {'a': 1}\n"
        "def test_uses_messages():\n    assert MESSAGES\n"
        "def test_edited():\n    assert True\n"
        "def test_untouched():\n    assert True\n"
        "class TestGroup:\n    def test_member(self):\n        assert True\n"
    )
    unsampled = set()
    selector.select_tests(
        tmp_path,
        ["tests/test_cases.py"],
        definitions={"tests/test_cases.py": {"MESSAGES", "test_edited", "TestGroup::test_member"}},
        unsampled=unsampled,
    )
    assert unsampled == {
        "tests/test_cases.py::test_uses_messages",
        "tests/test_cases.py::test_edited",
        "tests/test_cases.py::TestGroup::test_member",
    }


def test_targets_decorated_classes_fall_back_to_collectable_file(tmp_path, monkeypatch):
    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    test = tmp_path / "test_decorated.py"
    test.write_text(
        "import respx\n"
        "@respx.mock\n"
        "class TestWrapped:\n"
        "    def test_member(self): assert True\n"
        "def test_survivor(): assert True\n"
    )
    path = test.name
    for symbol in ("TestWrapped", "TestWrapped::test_member"):
        assert selector.pytest_targets([path], {path: {symbol}}, tmp_path) == [path]
    targets = selector.pytest_targets([path], {path: {"TestWrapped", "test_survivor"}}, tmp_path)
    assert targets == [path]
    assert selector.pytest_targets([path], {path: {"test_survivor"}}, tmp_path) == [
        f"{path}::test_survivor"
    ]
    result = subprocess.run(  # noqa: S603 — fixed interpreter and synthetic test targets
        [sys.executable, "-m", "pytest", *targets, "-q", "-n", "2"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        env={k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed" in result.stdout
