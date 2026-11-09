"""Failing mutations exercise each documentation gate without upstream writes."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import check_doc_images as images  # noqa: E402
import check_doc_links as links  # noqa: E402
import check_doc_provenance as provenance  # noqa: E402
import check_markdown as markdown  # noqa: E402

# Every README install region's start and end heading; extraction fails closed when
# one is missing, so planted READMEs end with the full set.
REGION_HEADINGS = (
    "## Quick Start\n## Example Prompts\n## Set up your client\n"
    "## About this server\n## Docker Deployment\n## Contributing\n"
)


class DocumentationMutations(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        (self.root / "docs").mkdir()
        (self.root / "README.md").write_text("# Test docs\n")
        (self.root / "pyproject.toml").write_text('[project]\nversion = "0.6.4"\n')
        self.doc = self.root / "docs/INSTALL.md"
        (self.root / "source.py").write_text("# implementation\n")
        self.git = shutil.which("git")
        self.assertIsNotNone(self.git)
        for command in (
            [self.git, "init", "--quiet"],
            [self.git, "add", "README.md", "pyproject.toml", "source.py"],
            [
                self.git,
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
        ):
            subprocess.run(command, cwd=self.root, check=True, capture_output=True)  # noqa: S603
        self.pin = subprocess.check_output(  # noqa: S603
            [self.git, "rev-parse", "HEAD"],
            cwd=self.root,
            text=True,
        ).strip()
        self.marker = f"<!-- doc-provenance: source=git:{self.pin} support=0.6.4 case=pip-wheel -->"
        self.valid = (
            self.marker
            + "\n<!-- install-case: pip-wheel mode=pip -->\n```bash\npip install package.whl\n```\n"
        )
        self.doc.write_text(self.valid)
        # A citation may replace the case only where nothing is executed.
        self.cited_valid = self.valid.replace(
            "mode=pip", "mode=non-executable reason=client-interaction"
        )

    def test_content_hash_source_survives_without_private_git_history(self):
        digest = hashlib.sha256((self.root / "source.py").read_bytes()).hexdigest()
        source = f"file:source.py@sha256:{digest}"
        self.doc.write_text(self.valid.replace(f"git:{self.pin}", source))
        shutil.rmtree(self.root / ".git")
        self.assertEqual(provenance.check(self.root, {"pip-wheel"}), [])
        (self.root / "source.py").write_text("# changed implementation\n")
        self.assertTrue(provenance.check(self.root, {"pip-wheel"}))

    def test_content_hash_citation_checks_bytes_and_path(self):
        digest = hashlib.sha256((self.root / "source.py").read_bytes()).hexdigest()
        citation = f"file:source.py@sha256:{digest}"
        self.doc.write_text(self.cited_valid.replace("case=pip-wheel", f"citation={citation}"))
        self.assertEqual(provenance.check(self.root, set()), [])
        for target in ("missing.py", "../source.py", "/source.py"):
            self.doc.write_text(
                self.doc.read_text().replace(citation, f"file:{target}@sha256:{digest}")
            )
            self.assertTrue(provenance.check(self.root, set()))
            self.doc.write_text(self.cited_valid.replace("case=pip-wheel", f"citation={citation}"))
        (self.root / "source.py").write_text("# changed\n")
        self.assertTrue(provenance.check(self.root, set()))

    def test_invalid_closing_fences_remain_in_same_example_and_hash(self):
        from extract_install_cases import fenced_blocks

        for opening, invalid, closing in (
            ("```bash", "``` trailing", "```"),
            ("~~~bash", "~~~ trailing", "~~~"),
            ("````bash", "```", "````"),
            ("```bash", "    ```", "```"),
        ):
            text = f"{opening}\none\n{invalid}\ntwo\n{closing}\n"
            self.doc.write_text(self.marker + "\n" + text)
            self.assertEqual(len(list(provenance.examples(self.doc, self.root))), 1)
            expected = next(fenced_blocks(text))[2]
            self.assertEqual(
                provenance.example_identity(self.doc, 2, self.root)[2],
                hashlib.sha256(expected.encode()).hexdigest(),
            )

    def test_non_commonmark_opening_is_not_an_example(self):
        for opening in ("    ```bash", "```ba`sh"):
            self.doc.write_text(self.marker + "\n" + opening + "\nbody\n")
            self.assertEqual(list(provenance.examples(self.doc, self.root)), [])

    def test_current_changelog_install_bullets_are_unique_and_current(self):
        changelog = (SCRIPTS.parent / "CHANGELOG.md").read_text()
        current = changelog.split("## [0.7.0]", 1)[1].split("\n## [", 1)[0]
        self.assertEqual(current.count("- Claude Code plugin (`plugins/claude/`)"), 1)
        self.assertEqual(current.count("- Setup for more MCP clients"), 1)
        self.assertNotIn("unifi-fabric-mcp-server==0.6.4", current)

    def test_remove_provenance_marker(self):
        self.assertEqual(provenance.check(self.root, {"pip-wheel"}), [])
        self.doc.write_text(self.valid.replace(self.marker, ""))
        self.assertTrue(
            any("missing doc-provenance" in f for f in provenance.check(self.root, {"pip-wheel"}))
        )
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(SCRIPTS / "check_doc_provenance.py"), "--root", str(self.root)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing doc-provenance", result.stdout)

    def test_readme_headings_inside_fences_and_comments_do_not_end_install_section(self):
        for fake_heading in (
            "```bash\n## Example Prompts\n```\n",
            "<!-- ## Example Prompts -->\n",
        ):
            readme = self.root / "README.md"
            readme.write_text(
                "## Quick Start\n"
                + self.valid
                + fake_heading
                + "```json\n{}\n```\n"
                + REGION_HEADINGS
            )
            second_fence_line = readme.read_text().splitlines().index("```json") + 1
            example_lines = [line for line, _ in provenance.examples(readme, self.root)]
            self.assertIn(second_fence_line, example_lines)
            failures = provenance.check(self.root, {"pip-wheel"})
            self.assertTrue(
                any(
                    "README.md" in failure and "missing doc-provenance" in failure
                    for failure in failures
                ),
                failures,
            )

    def test_section_identity_ignores_headings_inside_fences_and_comments(self):
        readme = self.root / "README.md"
        readme.write_text(
            "## Quick Start\n<!-- ## Commented heading -->\n"
            "```bash\n## Fenced heading\n```\n```bash\nexport TIMEOUT=60\n```\n"
        )
        self.assertEqual(provenance.example_identity(readme, 6, self.root)[1], "Quick Start")
        self.assertEqual(
            provenance.markdown_h2_headings(
                "## Quick Start\n```bash\n<!-- literal in code\n## Fenced fake\n```\n"
                "## Example Prompts\n<!-- ## Commented fake -->\n"
            ),
            ["Quick Start", "Example Prompts"],
        )

    def test_marked_readme_example_outside_install_sections_is_still_checked(self):
        """A doc-provenance marker is verified wherever it appears, not only in scope."""
        digest = hashlib.sha256((self.root / "source.py").read_bytes()).hexdigest()
        pin = f"file:source.py@sha256:{digest}"
        example = (
            f"<!-- doc-provenance: source={pin} support=0.6.4 citation={pin} -->\n"
            "```yaml\nservices: {}\n```\n"
        )
        readme = self.root / "README.md"
        readme.write_text("# t\n" + REGION_HEADINGS + "## Read-only mode\n" + example)
        self.assertEqual(provenance.check(self.root, {"pip-wheel"}), [])
        readme.write_text(
            "# t\n" + REGION_HEADINGS + "## Read-only mode\n" + example.replace(digest, "0" * 64)
        )
        failures = provenance.check(self.root, {"pip-wheel"})
        self.assertTrue(any(f.startswith("README.md:") and "hash" in f for f in failures))

    def test_unknown_case_is_rejected(self):
        self.doc.write_text(self.valid.replace("case=pip-wheel", "case=unknown"))
        self.assertTrue(
            any("unknown install case" in f for f in provenance.check(self.root, {"pip-wheel"}))
        )

    def test_unpinned_source_is_rejected(self):
        self.doc.write_text(self.valid.replace(f"git:{self.pin}", "git:HEAD"))
        self.assertTrue(any("immutable" in f for f in provenance.check(self.root, {"pip-wheel"})))

    def test_mutable_url_fragment_is_not_a_source_pin(self):
        self.doc.write_text(
            self.valid.replace(f"git:{self.pin}", "https://example.org/docs#install")
        )
        self.assertTrue(any("immutable" in f for f in provenance.check(self.root, {"pip-wheel"})))

    def test_cited_source_can_replace_case(self):
        (self.root / "source.py").write_text("# implementation\n")
        self.doc.write_text(
            self.cited_valid.replace("case=pip-wheel", f"citation=git:source.py@{self.pin}")
        )
        self.assertEqual(provenance.check(self.root, set()), [])

    def test_executed_install_example_requires_case_not_only_citation(self):
        cited = self.valid.replace("case=pip-wheel", f"citation=git:source.py@{self.pin}")
        self.doc.write_text(cited)
        self.assertTrue(
            any("requires case=" in f for f in provenance.check(self.root, {"pip-wheel"}))
        )
        readme = self.root / "README.md"
        readme.write_text("## Quick Start\n" + cited)
        self.doc.write_text(self.valid)
        self.assertTrue(
            any(
                f.startswith("README.md") and "requires case=" in f
                for f in provenance.check(self.root, {"pip-wheel"})
            )
        )

    def test_case_must_match_adjacent_install_case_marker(self):
        self.doc.write_text(self.valid.replace("case=pip-wheel", "case=other-case"))
        failures = provenance.check(self.root, {"pip-wheel", "other-case"})
        self.assertTrue(any("does not match install-case pip-wheel" in f for f in failures))

    def test_unmarked_install_example_with_citation_is_not_accepted(self):
        self.doc.write_text(
            f"<!-- doc-provenance: source=git:{self.pin} support=0.6.4 "
            f"citation=git:source.py@{self.pin} -->\n```bash\npip install package.whl\n```\n"
        )
        self.assertTrue(
            any("requires case=" in f for f in provenance.check(self.root, {"pip-wheel"}))
        )

    def test_nonexistent_source_commit_is_rejected(self):
        self.doc.write_text(self.valid.replace(f"git:{self.pin}", "git:" + "f" * 40))
        self.assertTrue(
            any("does not resolve" in f for f in provenance.check(self.root, {"pip-wheel"}))
        )

    def test_nonexistent_citation_commit_is_rejected(self):
        self.doc.write_text(
            self.cited_valid.replace("case=pip-wheel", "citation=git:source.py@" + "f" * 40)
        )
        self.assertTrue(
            any("existing source at a commit" in f for f in provenance.check(self.root, set()))
        )

    def test_citation_file_must_exist_at_cited_commit(self):
        (self.root / "uncommitted.py").write_text("# not in cited commit\n")
        self.doc.write_text(
            self.cited_valid.replace("case=pip-wheel", f"citation=git:uncommitted.py@{self.pin}")
        )
        self.assertTrue(
            any("existing source at a commit" in f for f in provenance.check(self.root, set()))
        )
        self.doc.write_text(
            self.cited_valid.replace("case=pip-wheel", f"citation=git:source.py@{self.pin}")
        )
        (self.root / "source.py").unlink()
        self.assertEqual(provenance.check(self.root, set()), [])

    def test_executed_table_requires_successful_execution(self):
        guide = self.root / "docs/INSTALL-AGENT.md"
        guide.write_text(
            "| Path | Executed case | Setup |\n|---|---|---|\n| pip | `pip-wheel` | local |\n"
        )
        row = {
            "id": "pip-wheel",
            "status": "TESTED-LIVE",
            **dict.fromkeys(
                ("starts", "tools_ok", "read", "missing_key", "wrong_key", "version_ok"), True
            ),
        }
        self.assertEqual(provenance.check_executed_cases(self.root, {"cases": [row]}), [])
        guide.write_text(guide.read_text().replace("`pip-wheel`", "`nonexistent-case`"))
        self.assertTrue(provenance.check_executed_cases(self.root, {"cases": [row]}))
        guide.write_text(guide.read_text().replace("`nonexistent-case`", "`pip-wheel`"))
        for mutation in ({"status": "FAIL"}, {"version_ok": False}, {"read": False}):
            self.assertTrue(
                provenance.check_executed_cases(self.root, {"cases": [{**row, **mutation}]})
            )
        self.assertTrue(provenance.check_executed_cases(self.root, {"cases": []}))

    def _platform_guide(self):
        """An agent guide claiming one local and one Docker case, both documented."""
        self.doc.write_text(
            self.valid
            + "<!-- install-case: docker-http mode=docker -->\n"
            + "```bash\ndocker run --rm ghcr.io/example/server:0.6.4\n```\n"
        )
        (self.root / "docs/INSTALL-AGENT.md").write_text(
            "| Path | Executed case | Setup |\n|---|---|---|\n"
            "| pip | `pip-wheel` | local |\n| Docker | `docker-http` | local |\n"
        )
        passed = {
            "status": "TESTED-LIVE",
            **dict.fromkeys(
                ("starts", "tools_ok", "read", "missing_key", "wrong_key", "version_ok"), True
            ),
        }
        not_tested = {
            "id": "docker-http",
            "status": "NOT-TESTED",
            "reason": "Docker runs on the Linux job only",
        }
        return {"id": "pip-wheel", **passed}, {"id": "docker-http", **passed}, not_tested

    def test_executed_claims_skip_only_platform_limited_cases_off_linux(self):
        local, docker, not_tested = self._platform_guide()
        skipped = []
        # Off Linux, a Docker case is legitimately NOT-TESTED; the skip is recorded.
        for system in ("Darwin", "Windows"):
            skipped.clear()
            report = {"platform": system, "cases": [local, not_tested]}
            self.assertEqual(provenance.check_executed_cases(self.root, report, skipped), [])
            self.assertEqual(len(skipped), 1)
            self.assertEqual(
                skipped[0],
                {
                    "id": "docker-http",
                    "line": 4,
                    "platform": system,
                    "required_platform": "Linux",
                    "reason": "Docker runs on the Linux job only",
                },
            )
        # On Linux the same report fails: nothing is excused there.
        report = {"platform": "Linux", "cases": [local, not_tested]}
        self.assertTrue(provenance.check_executed_cases(self.root, report))
        # A report without its platform is never excused.
        self.assertTrue(provenance.check_executed_cases(self.root, {"cases": [local, not_tested]}))
        self.assertEqual(
            provenance.check_executed_cases(
                self.root, {"platform": "Linux", "cases": [local, docker]}
            ),
            [],
        )
        # Off Linux, a missing or failed Docker row is still a failure.
        for rows in ([local], [local, {**not_tested, "status": "FAIL"}]):
            self.assertTrue(
                provenance.check_executed_cases(self.root, {"platform": "Darwin", "cases": rows})
            )
        # A non-Docker case cannot be excused off Linux, whatever its row claims.
        report = {
            "platform": "Darwin",
            "cases": [{**local, "status": "NOT-TESTED", "reason": "x"}, not_tested],
        }
        self.assertTrue(
            any("pip-wheel" in f for f in provenance.check_executed_cases(self.root, report))
        )
        # A Docker case the guide documents as another mode is not excused either.
        self.doc.write_text(self.doc.read_text().replace("mode=docker", "mode=uvx"))
        report = {"platform": "Darwin", "cases": [local, not_tested]}
        self.assertTrue(provenance.check_executed_cases(self.root, report))

    def test_invalid_platform_never_excuses_untested_cases(self):
        local, _, not_tested = self._platform_guide()
        for system in ("Linuz", "", " ", "\t\n", "linux", " Darwin ", None, 1, []):
            with self.subTest(platform=system):
                skipped = []
                report = {"platform": system, "cases": [local, not_tested]}
                self.assertTrue(provenance.check_executed_cases(self.root, report, skipped))
                self.assertEqual(skipped, [])

    def test_invalid_platform_report_fails_cli(self):
        local, _, not_tested = self._platform_guide()
        self.doc.write_text(
            self.doc.read_text().replace(
                "<!-- install-case: docker-http",
                self.marker.replace("case=pip-wheel", "case=docker-http")
                + "\n<!-- install-case: docker-http",
            )
        )
        report = self.root / "install-results.json"
        report.write_text(json.dumps({"platform": "Linuz", "cases": [local, not_tested]}))
        result = subprocess.run(  # noqa: S603 - owned synthetic fixture
            [
                sys.executable,
                str(SCRIPTS / "check_doc_provenance.py"),
                "--root",
                str(self.root),
                "--install-results",
                str(report),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("docker-http has no successful execution evidence", result.stdout)

    def test_duplicate_execution_ids_are_rejected_before_any_excuse(self):
        local, docker, not_tested = self._platform_guide()
        for first, second in (
            (not_tested, {**not_tested, "status": "FAIL"}),
            (docker, {**docker, "status": "FAIL"}),
            (docker, not_tested),
            (docker, docker),
            (not_tested, not_tested),
            (local, local),
            ({"id": "unclaimed", "status": "FAIL"}, {"id": "unclaimed", "status": "NOT-TESTED"}),
        ):
            base = [] if first["id"] == local["id"] else [local]
            for pair in ([first, second], [second, first]):
                with self.subTest(rows=pair):
                    skipped = []
                    report = {"platform": "Darwin", "cases": [*base, *pair]}
                    failures = provenance.check_executed_cases(self.root, report, skipped)
                    self.assertTrue(any("duplicate execution case" in f for f in failures))
                    self.assertEqual(skipped, [])

    def test_tools_examples_require_provenance_but_skip_links_and_images(self):
        tools = self.root / "docs/TOOLS.md"
        tools.write_text(
            "```json\n{}\n```\n"
            "[external](https://example.invalid/generated-tools)\n"
            "ghcr.io/example/unifi-fabric-mcp-server:0.0.1\n"
        )
        failures = provenance.check(self.root, {"pip-wheel"})
        self.assertTrue(any("docs/TOOLS.md:1: missing doc-provenance" in f for f in failures))
        tools.write_text(self.cited_valid + tools.read_text().split("```\n", 1)[1])
        self.assertEqual(provenance.check(self.root, {"pip-wheel"}), [])
        self.assertNotIn("https://example.invalid/generated-tools", links.urls(self.root))
        self.assertEqual(images.check(self.root), [])

    def test_break_table_and_unescaped_pipe(self):
        self.doc.write_text("| A | B |\n| --- | --- |\n| one | two |\n")
        self.assertEqual(markdown.check([self.doc]), [])
        self.doc.write_text("| A | B |\n| --- | --- |\n| one | `two|three` |\n")
        self.assertTrue(any("table row" in f for f in markdown.check([self.doc])))

    def test_break_internal_anchor(self):
        self.doc.write_text("# Target\n\n[valid](#target)\n")
        self.assertEqual(markdown.check([self.doc]), [])
        self.doc.write_text("# Target\n\n[broken](#missing)\n")
        self.assertTrue(any("fragment" in f for f in markdown.check([self.doc])))

    def test_new_unmarked_readme_client_and_troubleshooting_examples(self):
        for heading in ("Set up your client", "Troubleshooting", "Quick Start"):
            readme = self.root / "README.md"
            readme.write_text("## " + heading + "\n" + self.valid + REGION_HEADINGS)
            self.assertEqual(provenance.check(self.root, {"pip-wheel"}), [])
            readme.write_text("## " + heading + "\n```json\n{}\n```\n" + REGION_HEADINGS)
            self.assertTrue(
                any(
                    "README.md" in f and "missing" in f
                    for f in provenance.check(self.root, {"pip-wheel"})
                )
            )

    def test_exact_sidecar_removal_or_changed_body_fails(self):
        readme = self.root / "README.md"
        readme.write_text("## Troubleshooting\n```bash\nexport TIMEOUT=60\n```\n" + REGION_HEADINGS)
        (self.root / "source.py").write_text("# source\n")
        (self.root / "scripts").mkdir()
        identity = provenance.example_identity(readme, 2, self.root)
        sidecar = self.root / "scripts/doc_provenance.json"
        sidecar.write_text(
            json.dumps(
                {
                    "examples": [
                        {
                            "file": identity[0],
                            "section": identity[1],
                            "body_sha256": identity[2],
                            "source": f"git:{self.pin}",
                            "support": "0.6.4",
                            "citation": f"git:source.py@{self.pin}",
                        }
                    ]
                }
            )
        )
        self.assertEqual(provenance.check(self.root, {"pip-wheel"}), [])
        original = sidecar.read_text()
        sidecar.unlink()
        self.assertTrue(provenance.check(self.root, {"pip-wheel"}))
        sidecar.write_text(original)
        readme.write_text(readme.read_text().replace("TIMEOUT=60", "TIMEOUT=90"))
        self.assertTrue(provenance.check(self.root, {"pip-wheel"}))
        readme.write_text(
            "## Troubleshooting\n```bash\nexport TIMEOUT=60\n```\n```bash\nexport TIMEOUT=60\n```\n"
            + REGION_HEADINGS
        )
        self.assertTrue(provenance.check(self.root, {"pip-wheel"}))

    def test_authenticated_ui_exception_is_exact_and_reported(self):
        (self.root / "scripts").mkdir()
        (self.root / "scripts/doc_links.toml").write_text(
            '[[anonymous_blocked]]\nurl="https://chatgpt.com/plugins"\n'
            'reason="Authenticated UI endpoint; NOT-TESTED anonymously"\n'
        )
        self.doc.write_text(
            "[UI](https://chatgpt.com/plugins)\n"
            "[docs](https://developers.openai.com/apps-sdk/build/auth)\n"
            "[other](https://chatgpt.com/other)\n"
        )
        targets, excluded = links.discovery(self.root)
        self.assertIn("https://developers.openai.com/apps-sdk/build/auth", targets)
        self.assertIn("https://chatgpt.com/other", targets)
        self.assertEqual(len(excluded), 1)
        self.assertEqual(excluded[0]["status"], "NOT-TESTED")

    def test_stale_image_tag(self):
        self.doc.write_text("docker run ghcr.io/example/unifi-fabric-mcp-server:0.6.4\n")
        self.assertEqual(images.check(self.root), [])
        self.doc.write_text("docker run ghcr.io/example/unifi-fabric-mcp-server:0.1.0\n")
        self.assertTrue(any("stale image tag" in f for f in images.check(self.root)))
        (self.root / "pyproject.toml").write_text('[project]\nversion = "0.7.0"\n')
        self.doc.write_text("docker run ghcr.io/example/unifi-fabric-mcp-server:0.6.4\n")
        self.assertTrue(images.check(self.root))
        (self.root / "scripts").mkdir(exist_ok=True)
        (self.root / "scripts/published-version.txt").write_text("0.6.4\n")
        self.assertEqual(images.check(self.root), [])

    def test_migration_guide_image_tag_names_the_release_it_migrates_to(self):
        """A migration guide is version history: its example runs the release it migrates
        to (check_launcher_settings.py checks that release accepts what it passes)."""
        guide = self.root / "docs/MIGRATING-0.7.md"
        guide.write_text("docker run ghcr.io/example/unifi-fabric-mcp-server:0.7.0\n")
        self.assertEqual(images.check(self.root), [])
        self.doc.write_text("docker run ghcr.io/example/unifi-fabric-mcp-server:0.7.0\n")
        self.assertTrue(
            any("docs/INSTALL.md:1: stale image tag" in f for f in images.check(self.root))
        )

    def test_break_external_link_and_report_redirect(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/moved":
                    self.send_response(302)
                    self.send_header("Location", "/valid")
                else:
                    self.send_response(
                        200
                        if self.path == "/valid"
                        else (403 if self.path == "/forbidden" else 404)
                    )
                self.end_headers()

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            self.doc.write_text(f"[reference]({base}/valid)\n")
            self.assertEqual(links.urls(self.root), [base + "/valid"])
            self.assertTrue(all(r["ok"] for r in links.check(self.root, retries=0, external=True)))
            self.doc.write_text(f"[reference]({base}/broken)\n")
            self.assertEqual(links.urls(self.root), [base + "/broken"])
            self.assertTrue(
                any(not r["ok"] for r in links.check(self.root, retries=0, external=True))
            )
            for reference in (f"<{base}/valid>", f"{base}/valid"):
                self.doc.write_text(reference + "\n")
                self.assertEqual(links.urls(self.root), [base + "/valid"])
                self.assertTrue(
                    all(r["ok"] for r in links.check(self.root, retries=0, external=True))
                )
                self.doc.write_text(reference.replace("/valid", "/broken") + "\n")
                self.assertTrue(
                    any(not r["ok"] for r in links.check(self.root, retries=0, external=True))
                )
            result = links.probe(base + "/broken", retries=0)
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], 404)
            forbidden = links.probe(base + "/forbidden", retries=0)
            self.assertFalse(forbidden["ok"])
            self.assertEqual(forbidden["status"], 403)
            self.assertTrue(links.probe(base + "/moved", retries=0)["moved"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
            self.assertFalse(thread.is_alive())


def test_pagination_doc_incomplete_reason_matches_the_client_message():
    """docs/PAGINATION.md's page-cap example must be text the client can emit."""
    import re

    root = SCRIPTS.parent
    code = (root / "src/unifi_fabric/client.py").read_text()
    templates = set(re.findall(r'f"(page cap[^"]*)"', code))
    assert templates, "client.py no longer emits a page-cap reason"
    patterns = [re.escape(re.sub(r"\{[^}]*\}", "\0", t)).replace("\0", r"\S+") for t in templates]
    doc = (root / "docs/PAGINATION.md").read_text()
    reasons = re.findall(r'"incompleteReason": "(page cap[^"]*)"', doc)
    assert reasons, "docs/PAGINATION.md no longer shows a page-cap incompleteReason"
    for reason in reasons:
        assert any(re.fullmatch(p, reason) for p in patterns), (reason, templates)


if __name__ == "__main__":
    unittest.main()
