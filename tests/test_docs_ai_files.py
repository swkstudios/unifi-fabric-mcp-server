"""AI-readability and fork files: llms.txt, FORKING, AI-CHANGES, AGENTS and pointer files.

Each test reads the repository text and checks it against the code or configuration that owns
the fact, so the docs cannot drift from the files they cite.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())
SERVER_JSON = json.loads((ROOT / "server.json").read_text())


def _text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    rest = text[start + len(heading) :]
    match = re.search(r"\n## ", rest)
    return rest[: match.start()] if match else rest


# --- B1: forking identity matrix -------------------------------------------------------

_ROW = re.compile(
    r"^\| (?P<surface>[^|]+) \| `(?P<value>[^`]+)` \| `(?P<path>[^`:]+):(?P<line>\d+)` \|$"
)


def _matrix() -> list[tuple[str, str, str, int]]:
    rows = []
    for line in _text("docs/FORKING.md").splitlines():
        m = _ROW.match(line)
        if m:
            rows.append((m["surface"].strip(), m["value"], m["path"], int(m["line"])))
    return rows


def test_forking_identity_matrix_cites_the_line_that_owns_each_value():
    rows = _matrix()
    assert len(rows) >= 20, "the identity matrix lost rows"
    for surface, value, path, number in rows:
        lines = _text(path).splitlines()
        assert number <= len(lines), (surface, path, number)
        assert value in lines[number - 1], f"{surface}: {value!r} is not on {path}:{number}"


def test_forking_identity_matrix_matches_package_registry_and_image_identity():
    # Re-points to the release-identity source (the single fork-editable public identity)
    # when that source lands; until then the matrix is compared with the files directly.
    by_surface = {surface: value for surface, value, _p, _n in _matrix()}
    project = PYPROJECT["project"]
    assert by_surface["Package name"] == project["name"]
    scripts = list(project["scripts"])
    assert by_surface["Console entry point"] == scripts[0]
    assert by_surface["Console entry point (long form)"] == scripts[1]
    assert by_surface["Registry ID"] == SERVER_JSON["name"]
    pypi = [p for p in SERVER_JSON["packages"] if p["registryType"] == "pypi"][0]
    assert by_surface["Registry package identifier (PyPI)"] == pypi["identifier"]
    oci = [p for p in SERVER_JSON["packages"] if p["registryType"] == "oci"][0]
    assert oci["identifier"].startswith(
        "ghcr.io/" + by_surface["Image name (registry OCI identifier)"] + ":"
    )
    label = re.search(
        r'LABEL io\.modelcontextprotocol\.server\.name="([^"]+)"', _text("Dockerfile")
    )
    assert label and by_surface["Docker label (registry ownership)"] == label[1]
    assert label[1] == SERVER_JSON["name"]
    entry = re.search(r'ENTRYPOINT \[.*"([^"]+)"\]', _text("Dockerfile"))
    assert entry and by_surface["Docker entry point"] == entry[1]
    assert by_surface["Public URL (package homepage)"] == project["urls"]["Homepage"]
    assert by_surface["Public URL (registry repository)"] == SERVER_JSON["repository"]["url"]


def test_forking_names_every_identity_surface():
    text = _text("docs/FORKING.md")
    for surface in (
        "Package name",
        "Registry ID",
        "Image name",
        "Docker label",
        "entry point",
        "Client configuration example",
        "Generated install text",
        "Public URL",
    ):
        assert surface in text, surface
    assert "## Rename a fork" in text


# --- B2/B3: AI-CHANGES recipe and generator table --------------------------------------

_PATH = re.compile(r"`((?:scripts|tests|src|changelog\.d|docs|\.github)/[\w./-]+)`")
_COMMAND = re.compile(r"`(?:python3?|\.venv/bin/python|pytest)[^`]*`")


def _referenced_paths(text: str) -> set[str]:
    found = set()
    for m in _PATH.finditer(text):
        path = m[1].rstrip(".")
        if "<" in path or "*" in path:
            continue
        found.add(path)
    return found


def test_ai_changes_commands_exist_and_names_three_invariants():
    text = _text("docs/AI-CHANGES.md")
    missing = [p for p in sorted(_referenced_paths(text)) if not (ROOT / p).exists()]
    assert not missing, f"AI-CHANGES names paths that do not exist: {missing}"
    for command in _COMMAND.findall(text):
        for token in re.findall(r"(?:scripts|tests)/[\w./-]+\.py", command):
            assert (ROOT / token).exists(), (command, token)
        module = re.search(r"-m (tests\.\w+)", command)
        if module:
            assert (ROOT / (module[1].replace(".", "/") + ".py")).exists(), command
    invariants = _section(text, "## The three invariants")
    assert "omitted" in invariants and "absent" in invariants
    assert "_pagination.py" in invariants and "_continuation.py" in invariants
    assert "full" in invariants and "drain" in invariants
    assert "api_source_id" in invariants and "_api_source_table.py" in invariants
    order = [
        "**Implement.**",
        "**Register.**",
        "**Schema and annotation derivation.**",
        "**Focused and invariant tests.**",
        "**Changelog fragment.**",
        "**Regenerate.**",
    ]
    positions = [text.index(step) for step in order]
    assert positions == sorted(positions)


def _generator_rows() -> list[list[str]]:
    section = _section(
        _text("docs/AI-CHANGES.md"), "## Generated files: sources, outputs and checks"
    )
    rows = []
    for line in section.splitlines():
        if line.startswith("| `"):
            rows.append([cell.strip() for cell in line.strip("|").split("|")])
    return rows


def test_generated_outputs_have_listed_generator_with_check_mode_and_ci_job():
    rows = _generator_rows()
    assert len(rows) >= 6
    table_text = _section(
        _text("docs/AI-CHANGES.md"), "## Generated files: sources, outputs and checks"
    )
    for generator, _sources, outputs, check, ci_job in rows:
        script = generator.strip("`")
        assert (ROOT / script).exists(), script
        source = _text(script)
        if check.startswith("none"):
            assert "--check" not in source, f"{script} has --check but the table says none"
        elif script.startswith("scripts/"):
            assert '"--check"' in source, f"{script} has no --check mode"
        for path in re.findall(r"`((?:docs|src|tests|plugins|packaging)/[\w./-]+)`", outputs):
            assert (ROOT / path).exists(), (script, path)
        if ci_job.startswith("`"):
            workflow = re.search(r"in `(\.github/workflows/[\w.-]+)`", ci_job)
            job = re.match(r"`(\w[\w-]*)`", ci_job)
            assert workflow and job, ci_job
            assert re.search(rf"^  {job[1]}:", _text(workflow[1]), re.M), ci_job
    # Every generated artifact in the tree is an output of a listed generator.
    for generated in (
        "docs/TOOLS.md",
        "docs/site-stats.json",
        "src/unifi_fabric/_api_source_table.py",
        "tests/fixtures/tool_input_schemas_baseline.json",
        "tests/fixtures/discovery_queries.json",
    ):
        assert generated in table_text, generated
    # That every `scripts/<name>.py --check` a shipped workflow runs is described here is
    # checked against the transformed artifact, which alone knows which workflows ship.


def test_ai_changes_covers_lock_files_fragments_and_release_metadata():
    text = _text("docs/AI-CHANGES.md")
    for needle in ("Lock files", "Changelog fragments", "Maintainer-only release metadata"):
        assert needle in text, needle
    for lock in ("requirements.lock", "requirements-runtime.lock", "requirements-build.lock"):
        assert (ROOT / lock).exists() and lock in text


# --- B4: AGENTS.md setup and no-commit route -------------------------------------------

_INSTALL = (
    "python3.12 -m venv .venv",
    ".venv/bin/python -m pip install --require-hashes -r requirements.lock",
    ".venv/bin/python -m pip install --no-deps -e .",
)


def test_agents_and_contributing_name_same_install_commands_and_no_commit_route_exists():
    agents, contributing = _text("AGENTS.md"), _text("CONTRIBUTING.md")
    for command in _INSTALL:
        assert command in agents, command
        assert command in contributing, command
    assert 'pip install -e ".[dev]"' not in contributing
    # The install matches CI's hash-locked install: ci.yml builds the shared dev
    # environment through .github/actions/setup-dev.
    assert "uses: ./.github/actions/setup-dev" in _text(".github/workflows/ci.yml")
    assert "--require-hashes -r requirements.lock" in _text(".github/actions/setup-dev/action.yml")
    route = _section(agents, "## Verify without committing")
    block = re.search(r"```bash\n(.*?)```", route, re.S)
    assert block
    commands = [line.split("#")[0].strip() for line in block[1].splitlines() if line.strip()]
    assert len(commands) >= 6
    checks = 0
    for command in commands:
        for token in re.findall(r"scripts/[\w./-]+\.py", command):
            assert (ROOT / token).exists(), command
            if "--check" in command:
                checks += 1
                assert '"--check"' in _text(token), command
        module = re.search(r"-m (tests\.\w+)\b", command)
        if module:
            assert (ROOT / (module[1].replace(".", "/") + ".py")).exists(), command
        for token in re.findall(r"tests/test_\w+\.py", command):
            assert (ROOT / token).exists(), command
    assert checks >= 4
    assert "scripts/check_markdown.py" in route and "-m pytest" in route
    assert (ROOT / "scripts/prepush.sh").exists() and "scripts/prepush.sh" in route


def test_agents_full_suite_wording_reconciled_with_prepush_full():
    agents = _text("AGENTS.md")
    assert "never run locally" not in agents
    assert "scripts/prepush.sh --full" in agents and "advisory" in agents
    assert "--full" in _text("scripts/prepush.sh")
    # No hand-entered release version to go stale in the closer example.
    assert "--version 0.7.0" not in agents
    # Operational constraints come before product prose.
    assert agents.index("## Operational constraints") < agents.index("## What this repo is")
    assert agents.index("## Setup") < agents.index("## What this repo is")


def test_claude_md_keeps_agents_import():
    assert "\n@AGENTS.md\n" in _text("CLAUDE.md")


# --- B5: pointer files and llms.txt ----------------------------------------------------

POINTERS = [".github/copilot-instructions.md", ".cursor/rules/repo.mdc"]


@pytest.mark.parametrize("pointer", POINTERS)
def test_pointer_files_exist_link_agents_and_repeat_no_rule_text(pointer: str):
    text = _text(pointer)
    assert "AGENTS.md" in text
    assert len(text.splitlines()) <= 15
    if pointer.endswith(".md"):
        assert "(../AGENTS.md)" in text
    rule_lines = {
        line.strip().lstrip("-* ").strip()
        for line in _text("AGENTS.md").splitlines()
        if len(line.strip()) >= 40
    }
    for line in text.splitlines():
        assert line.strip().lstrip("-* ").strip() not in rule_lines, line


def test_llms_txt_is_version_aware_and_indexes_the_required_commands():
    text = _text("llms.txt")
    version = PYPROJECT["project"]["version"]
    name = PYPROJECT["project"]["name"]
    published = (ROOT / "scripts" / "published-version.txt").read_text().strip()
    assert f"Version {version}." in text
    # Install pins name the latest published release (scripts/published-version.txt).
    assert f"{name}=={published} unifi-fabric-mcp" in text
    for needle in (
        "UNIFI_WRITE_POLICY=deny",
        "docs/AI-CHANGES.md",
        "CONTRIBUTING.md",
        "scripts/prepush.sh",
        "--check",
        "_api_source_table.py",
        "ci.yml",
    ):
        assert needle in text, needle
    for path in _referenced_paths(text.replace("](", "`](`")):
        assert (ROOT / path).exists(), path
    for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", text):
        assert (ROOT / target).exists(), target
    assert not (ROOT / "llms-full.txt").exists()
    assert "llms-full" in text  # states it is absent


def test_no_llms_full_file_anywhere():
    assert not list(ROOT.glob("**/llms-full.txt"))


# --- CONTRIBUTING, COVERAGE, README, DOCKER --------------------------------------------


def test_contributing_regeneration_guidance_never_touches_released_sections():
    section = _section(_text("CONTRIBUTING.md"), "## If you add or change tools")
    flat = " ".join(section.split())
    assert "Never commit a change to a released section" in flat
    assert "git restore CHANGELOG.md" in flat
    assert "refreshes the catalog sizes and tool counts in the README and in the docs" in flat
    assert "tool counts in the README and CHANGELOG" not in flat
    assert "Worked example: add a read tool" in section


def test_coverage_live_evidence_rendered_or_marked_historical():
    text = _text("docs/COVERAGE.md")
    marker = re.search(
        r"<!-- live-evidence: passed=(\d+) writes=(\d+) total=(\d+) "
        r"build=([0-9a-f]+) date=(\d{4}-\d{2}-\d{2}) -->",
        text,
    )
    assert marker
    build, date = marker[4], marker[5]
    historical = re.search(r"historical[^\n]*", text, re.I)
    assert historical, "live-evidence figures are neither rendered nor marked historical"
    assert (
        build in text.split("\n\n")[1]
        and date in text.split("\n\n")[1]
        or (build in historical[0] and date in historical[0])
    )
    assert "build `cde04b5c1520`" in text and "2026-10-28" in text


def test_hosted_discovery_and_base_url_guidance_current():
    config = " ".join(_text("docs/CONFIGURATION.md").split())
    setup = " ".join(_text("docs/CLIENT-SETUP.md").split())
    # Discovery meta-tools named in the guidance exist in the code.
    discovery = _text("src/unifi_fabric/discovery.py")
    for tool in ("search_tools", "describe_tool", "call_read_tool", "call_write_tool"):
        assert f"def {tool}(" in discovery, tool
        assert f"`{tool}`" in config, tool
    assert "def list_tool_families(" in discovery and "`list_tool_families`" in config
    assert "pin `UNIFI_TOOL_MODE=full`" in config
    assert "mock or a private endpoint" in setup
    assert "A redirect from the configured URL is not followed" in setup
    client = _text("src/unifi_fabric/client.py")
    assert "redirects are not followed" in client and "Check UNIFI_API_BASE_URL" in client
    for text in (config, setup, " ".join(_text("README.md").split())):
        assert "do not change this unless you have a private Ubiquiti API endpoint" not in text


def test_docker_http_client_entry_current():
    docker = _text("docs/DOCKER.md")
    block = re.search(r"readme-install-25 mode=docker -->.*?```json\n(.*?)```", docker, re.S)
    assert block
    entry = json.loads(block[1])["mcpServers"]["unifi-fabric"]
    assert entry["type"] == "http" and entry["url"].endswith(":3000/mcp")
    assert entry["headers"] == {"Authorization": "Bearer ${MCP_BEARER_TOKEN}"}
    flat = " ".join(docker.split())
    assert "The entry holds no credential value" in flat
    dockerfile = _text("Dockerfile")
    assert "ENV FASTMCP_PORT=3000" in dockerfile and "EXPOSE 3000" in dockerfile
