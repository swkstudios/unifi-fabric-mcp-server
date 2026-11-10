"""Release state contract: one VERSION renders every version field, nothing historical.

scripts/prepare_release.py is the only writer of the version fields and the current install
pins. These tests run it against a copy of this tree (no network, no Git history): a bump
changes exactly the field set, the published flip moves the pins and
scripts/published-version.txt together, historical text stays byte-identical, a second run
changes nothing, bad versions are refused, and release-identity.json agrees with server.json.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "prepare_release.py"

_spec = importlib.util.spec_from_file_location("prepare_release", SCRIPT)
assert _spec and _spec.loader
pr = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = pr  # dataclasses resolve their module
_spec.loader.exec_module(pr)

import check_server_json_version  # noqa: E402  (scripts/ is on sys.path via prepare_release)

# The version fields a bump renders, and nothing else (plus refreshed provenance hashes
# and, when it does not exist yet, scripts/published-version.txt). Derived from the one
# registry, VERSION_FIELDS: a holder outside it and pin_files() is caught by
# test_no_version_holder_outside_the_rendered_set, not by a second hand-kept list.
FIELD_FILES = {field.path for field in pr.VERSION_FIELDS}
PIN_RE = re.compile(r"unifi-fabric-mcp-server==(\d+\.\d+\.\d+)")
_IGNORE = shutil.ignore_patterns(
    ".git",
    ".venv",
    "src",
    "tests",
    "__pycache__",
    "*.pyc",
    ".coverage*",
    ".*_cache",
    "node_modules",
    "*.png",
    "*.jpg",
    "*.gif",
    "*.mp4",
    "*.webm",
    "*.webp",
)


def test_pristine_copy_excludes_runtime_artifacts(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    for name in (".coverage", ".coverage.host.pid123.random", "module.pyc"):
        (source / name).write_text("runtime")
    for name in ("__pycache__", ".pytest_cache", ".ruff_cache"):
        (source / name).mkdir()
        (source / name / "entry").write_text("runtime")
    (source / "tracked.txt").write_text("working tree change")
    copy = tmp_path / "copy"
    shutil.copytree(source, copy, ignore=_IGNORE)
    assert sorted(p.name for p in copy.iterdir()) == ["tracked.txt"]
    assert (copy / "tracked.txt").read_text() == "working tree change"


def _bump(version: str) -> str:
    major, minor, patch = pr.parse_version(version)
    return f"{major}.{minor}.{patch + 1}"


CURRENT = pr.current_version(ROOT)
NEXT = _bump(CURRENT)


@pytest.fixture(scope="module")
def pristine(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tree = tmp_path_factory.mktemp("pristine") / "tree"
    shutil.copytree(ROOT, tree, ignore=_IGNORE)
    return tree


@pytest.fixture
def tree(pristine: Path, tmp_path: Path) -> Path:
    copy = tmp_path / "tree"
    shutil.copytree(pristine, copy)
    return copy


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def _historical(root: Path) -> list[str]:
    return [rel for rel in _snapshot(root) if pr.is_historical(rel)]


def _norm(line: str) -> str:
    """A line with its versions and digests blanked: what a render may not change."""
    return re.sub(r"[0-9a-f]{64}", "H", re.sub(r"\d+\.\d+\.\d+", "X", line))


def _published_mode_pins(root: Path) -> set[str]:
    return {
        pin
        for rel in pr.pin_files(root)
        for line in (root / rel).read_text().splitlines()
        if not pr.HISTORICAL.search(line)
        for pin in PIN_RE.findall(line)
    }


# ------------------------------------------------------------------ version parity


def test_this_tree_is_rendered_for_its_own_version() -> None:
    """Every version field and current pin already agrees (only a missing
    published-version.txt, before the pin policy lands, may be pending)."""
    result = pr.plan(ROOT, CURRENT)
    assert set(result.changes) <= {pr.PUBLISHED_FILE}, sorted(result.changes)
    if (ROOT / pr.PUBLISHED_FILE).is_file():
        assert not result.changes


def test_version_fields_agree_offline() -> None:
    """Archive, install and version parity of the checked-in tree."""
    server = json.loads((ROOT / "server.json").read_text())
    assert check_server_json_version.version_problems(server, CURRENT) == []
    for rel in FIELD_FILES - {"pyproject.toml", "server.json", "docs/site-stats.json"}:
        if rel.endswith(".json"):
            assert json.loads((ROOT / rel).read_text())["version"] == CURRENT, rel
    stats = json.loads((ROOT / "docs/site-stats.json").read_text())
    assert stats["version"] == f"v{CURRENT}"
    formula = (ROOT / "packaging/homebrew/unifi-fabric-mcp-server.rb").read_text()
    assert re.findall(r"archive/refs/tags/v(\d+\.\d+\.\d+)\.tar\.gz", formula) == [CURRENT]
    published = pr.published_version(ROOT) or CURRENT
    assert _published_mode_pins(ROOT) == {published}


# --------------------------------------------------------------------- the bump


def test_bump_changes_exactly_the_field_set(tree: Path) -> None:
    before = _snapshot(tree)
    result = pr.plan(tree, NEXT)
    changed = set(result.changes)
    assert FIELD_FILES <= changed
    extra = changed - FIELD_FILES
    if (tree / pr.PUBLISHED_FILE).is_file():
        assert pr.PUBLISHED_FILE not in extra
    else:
        assert result.changes[pr.PUBLISHED_FILE] == ("", f"{CURRENT}\n")
        extra.discard(pr.PUBLISHED_FILE)
    # Anything else is a refreshed provenance hash of a changed manifest, nothing more.
    for rel in extra:
        old, new = result.changes[rel]
        assert old.splitlines() != new.splitlines()
        for a, b in zip(old.splitlines(), new.splitlines(), strict=True):
            if a != b:
                assert "doc-provenance" in a and re.sub(r"[0-9a-f]{64}", "H", a) == re.sub(
                    r"[0-9a-f]{64}", "H", b
                ), (rel, a, b)
    # Each field file changes only version tokens (and the formula's archive digest).
    for rel in FIELD_FILES:
        old, new = result.changes[rel]
        pairs = list(zip(old.splitlines(), new.splitlines(), strict=True))
        moved = [(a, b) for a, b in pairs if a != b]
        assert moved, rel
        for a, b in moved:
            assert _norm(a) == _norm(b), (rel, a, b)
            assert NEXT in b or re.search(r'sha256 "0{64}"', b), (rel, b)
    # A bump leaves every install pin on the published release.
    pr.apply(tree, result)
    assert _published_mode_pins(tree) == {pr.published_version(tree)}
    after = _snapshot(tree)
    assert {rel for rel in after if after[rel] != before.get(rel)} == changed


def test_bump_leaves_historical_text_byte_identical(tree: Path) -> None:
    history = {rel: (tree / rel).read_bytes() for rel in _historical(tree)}
    assert "CHANGELOG.md" in history
    assert any(rel.startswith("docs/MIGRATING-") for rel in history)
    for published in (False, True):
        pr.apply(tree, pr.plan(tree, NEXT, published=published))
        for rel, data in history.items():
            assert (tree / rel).read_bytes() == data, rel


def test_historical_lines_keep_their_version(tree: Path) -> None:
    lines = {
        rel: [line for line in (tree / rel).read_text().splitlines() if pr.HISTORICAL.search(line)]
        for rel in pr.pin_files(tree)
    }
    pr.apply(tree, pr.plan(tree, NEXT, published=True))
    for rel, kept in lines.items():
        text = (tree / rel).read_text().splitlines()
        for line in kept:
            assert line in text, (rel, line)


def test_render_is_idempotent(tree: Path) -> None:
    for published in (False, True):
        first = pr.plan(tree, NEXT, published=published)
        pr.apply(tree, first)
        snapshot = _snapshot(tree)
        again = pr.plan(tree, NEXT, published=published)
        assert again.changes == {}, sorted(again.changes)
        pr.apply(tree, again)
        assert _snapshot(tree) == snapshot


def test_publication_flips_pins_and_published_version_together(tree: Path) -> None:
    pr.apply(tree, pr.plan(tree, NEXT))
    assert _published_mode_pins(tree) == {pr.published_version(tree)} != {NEXT}
    result = pr.plan(tree, NEXT, published=True)
    assert result.pinned_after == NEXT
    pr.apply(tree, result)
    assert (tree / pr.PUBLISHED_FILE).read_text() == f"{NEXT}\n"
    assert _published_mode_pins(tree) == {NEXT}
    # Image tags in the documentation move with the pins.
    images = re.compile(r"ghcr\.io/[^/\s]+/unifi-fabric-mcp-server:(\d+\.\d+\.\d+)")
    tags = {
        tag
        for rel in pr.pin_files(tree)
        for line in (tree / rel).read_text().splitlines()
        if not pr.HISTORICAL.search(line)
        for tag in images.findall(line)
    }
    assert tags == {NEXT}


def test_provenance_hashes_follow_the_changed_manifests(tree: Path) -> None:
    import hashlib

    pr.apply(tree, pr.plan(tree, NEXT, published=True))
    pins = re.compile(r"file:([^@\s]+)@sha256:([0-9a-f]{64})")
    checked = 0
    for rel in pr.provenance_files(tree):
        for source, digest in pins.findall((tree / rel).read_text()):
            if source in FIELD_FILES or source in pr.PIN_MANIFESTS:
                checked += 1
                assert hashlib.sha256((tree / source).read_bytes()).hexdigest() == digest, (
                    rel,
                    source,
                )
    assert checked


# ----------------------------------------------------------------------- refusals


@pytest.mark.parametrize(
    "bad", ["", "v0.7.1", "0.7", "0.7.1rc1", "0.07.1", "1.2.3.4", " 0.7.1", "0.7.1-dev", "x.y.z"]
)
def test_bad_versions_are_refused(tree: Path, bad: str) -> None:
    before = _snapshot(tree)
    with pytest.raises(pr.PrepareError, match="clean X.Y.Z"):
        pr.plan(tree, bad)
    if bad:
        assert pr.main([bad, "--write", "--root", str(tree)]) == 2
    assert _snapshot(tree) == before


def test_older_versions_are_refused(tree: Path) -> None:
    major, minor, patch = pr.parse_version(pr.published_version(tree) or CURRENT)
    older = f"{major}.{minor - 1}.0" if minor else f"{major - 1}.99.0"
    if major == 0 and minor == 0:  # pragma: no cover - no older release exists
        pytest.fail("no older version to try")
    with pytest.raises(pr.PrepareError, match="older"):
        pr.plan(tree, older)


def test_archive_checksum_is_never_invented(tree: Path) -> None:
    formula = "packaging/homebrew/unifi-fabric-mcp-server.rb"
    digest = re.compile(r'url "[^"]+/archive/refs/tags/v[^"]+"\n  sha256 "([0-9a-f]{64})"')
    result = pr.plan(tree, NEXT)
    assert digest.findall(result.changes[formula][1]) == [pr.ZERO_SHA256]
    real = "ab" * 32
    with pytest.raises(pr.PrepareError, match="post-tag only"):
        pr.plan(tree, NEXT, archive_sha256=real)
    for bad in ("AB" * 32, "ab" * 31, pr.ZERO_SHA256, "sha256:" + real):
        with pytest.raises(pr.PrepareError, match="64 lowercase hex"):
            pr.plan(tree, NEXT, published=True, archive_sha256=bad)
    pr.apply(tree, pr.plan(tree, NEXT, published=True, archive_sha256=real))
    assert digest.findall((tree / formula).read_text()) == [real]
    # A later run without the checksum keeps it: the url did not move.
    assert pr.plan(tree, NEXT, published=True).changes == {}


def test_layout_drift_is_refused(tree: Path) -> None:
    path = tree / "gemini-extension.json"
    path.write_text(path.read_text().replace('"version"', '"Version"', 1))
    with pytest.raises(pr.PrepareError, match="layout changed"):
        pr.plan(tree, NEXT)


# ------------------------------------------------------------------------ identity


def test_release_identity_agrees_with_server_json() -> None:
    identity = pr.load_identity(ROOT)
    assert pr.identity_problems(ROOT, identity) == []
    server = json.loads((ROOT / "server.json").read_text())
    assert server["name"] == identity.registry_name == f"io.github.{identity.owner}/{identity.repo}"
    name = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["name"]
    assert identity.pypi == name


@pytest.mark.parametrize(
    "edit",
    [
        lambda s: s.update(name="io.github.someone-else/unifi-fabric-mcp-server"),
        lambda s: s["repository"].update(url="https://github.com/someone-else/fork"),
        lambda s: s["packages"][0].update(identifier="another-package"),
        lambda s: s["packages"][1].update(
            identifier=s["packages"][1]["identifier"].replace("ghcr.io/", "docker.io/")
        ),
    ],
)
def test_identity_disagreement_fails_before_writing(tree: Path, edit) -> None:
    path = tree / "server.json"
    server = json.loads(path.read_text())
    edit(server)
    path.write_text(json.dumps(server, indent=2) + "\n")
    before = _snapshot(tree)
    with pytest.raises(pr.PrepareError, match="release identity disagrees"):
        pr.plan(tree, NEXT)
    assert pr.main([NEXT, "--write", "--root", str(tree)]) == 2
    assert pr.main(["--identity", "--root", str(tree)]) == 2
    assert _snapshot(tree) == before


def _identity(tree: Path, **data: object) -> Path:
    path = tree / pr.IDENTITY_FILE
    current = json.loads(path.read_text())
    current.update(data)
    path.write_text(json.dumps(current))
    return path


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"overrides": {"tap": "x/homebrew-y"}}, "unknown overrides"),
        ({"overrides": {"image": "GHCR.io/Owner/Repo"}}, "overrides.image"),
        ({"overrides": {"image": "ghcr.io/owner/repo:1.0.0"}}, "overrides.image"),
        ({"overrides": {"registry_name": "io.github.other/repo"}}, "another GitHub account"),
        ({"overrides": {"registry_name": "no-namespace"}}, "overrides.registry_name"),
        ({"overrides": {"pypi": "-bad-"}}, "overrides.pypi"),
        ({"overrides": {"homebrew_tap": "owner/tap"}}, "overrides.homebrew_tap"),
        ({"owner": "bad owner"}, "owner"),
        ({"repo": ".."}, "repo"),
        ({"schema": 2}, "schema"),
        ({"extra": 1}, "unknown keys"),
    ],
)
def test_identity_overrides_are_validated(tree: Path, data: dict, message: str) -> None:
    _identity(tree, **data)
    with pytest.raises(pr.PrepareError, match=message):
        pr.load_identity(tree)


def test_fork_identity_derives_every_field(tree: Path) -> None:
    _identity(tree, owner="Example-Fork", repo="my-fabric")
    identity = pr.load_identity(tree)
    assert identity.image == "ghcr.io/example-fork/my-fabric"
    assert identity.registry_name == "io.github.Example-Fork/my-fabric"
    assert identity.pypi == "my-fabric"
    assert identity.homebrew_tap == "Example-Fork/homebrew-tap"
    assert identity.repository_url == "https://github.com/Example-Fork/my-fabric"
    # The fork has not edited server.json yet: the tool refuses to render.
    with pytest.raises(pr.PrepareError, match="release identity disagrees"):
        pr.plan(tree, NEXT)
    _identity(tree, overrides={"registry_name": "com.example/my-fabric"})
    assert pr.load_identity(tree).registry_name == "com.example/my-fabric"


# ----------------------------------------------------------------------------- CLI


def test_dry_run_writes_nothing_and_check_reports_stale(tree: Path, capsys) -> None:
    before = _snapshot(tree)
    assert pr.main([NEXT, "--root", str(tree)]) == 0
    out = capsys.readouterr().out
    assert f'+version = "{NEXT}"' in out and "dry run" in out
    assert _snapshot(tree) == before
    assert pr.main([NEXT, "--check", "--root", str(tree)]) == 1
    assert pr.main([NEXT, "--write", "--root", str(tree)]) == 0
    assert pr.main([NEXT, "--check", "--root", str(tree)]) == 0


def test_server_json_version_problems() -> None:
    server = json.loads((ROOT / "server.json").read_text())
    assert check_server_json_version.version_problems(server, CURRENT) == []
    assert check_server_json_version.version_problems(server, NEXT)
    oci = next(p for p in server["packages"] if p["registryType"] == "oci")
    oci["identifier"] = oci["identifier"].rsplit(":", 1)[0] + f":v{CURRENT}"
    assert any(
        "leading 'v'" in p for p in check_server_json_version.version_problems(server, CURRENT)
    )
    server["packages"] = [p for p in server["packages"] if p["registryType"] != "oci"]
    assert any("no OCI" in p for p in check_server_json_version.version_problems(server, CURRENT))


def test_server_json_pypi_version_is_checked() -> None:
    server = json.loads((ROOT / "server.json").read_text())
    pypi = next(p for p in server["packages"] if p["registryType"] == "pypi")
    pypi["version"] = "0.6.9"
    problems = check_server_json_version.version_problems(server, CURRENT)
    assert problems == [
        f"PyPI package {pypi['identifier']!r} version '0.6.9' != version {CURRENT!r}."
    ]
    server["packages"] = [p for p in server["packages"] if p["registryType"] != "pypi"]
    assert any("no PyPI" in p for p in check_server_json_version.version_problems(server, CURRENT))


def test_pin_corpus_covers_every_image_tag_the_docs_check_reads() -> None:
    """Every file the image-tag check reads that names a release image tag is rendered by the
    published flip, so dating a release never leaves a stale pull command behind (0.7.1:
    the flip skipped .github/ISSUE_TEMPLATE/bug_report.md, CA-20261107-293)."""
    from tests import test_docs_references as references

    # server.json's OCI tag is a version field (VERSION_FIELDS), rendered on every prepare.
    rendered = set(pr.pin_files(ROOT)) | {field.path for field in pr.VERSION_FIELDS}
    assert "server.json" in rendered
    image = re.compile(r"ghcr\.io/[\w.-]+/unifi-fabric-mcp-server:v?\d+\.\d+")
    holders = {
        f.relative_to(ROOT).as_posix()
        for f in references.FILES
        if image.search(f.read_text()) and not pr.is_historical(f.relative_to(ROOT).as_posix())
    }
    assert ".github/ISSUE_TEMPLATE/bug_report.md" in holders
    assert holders <= rendered, sorted(holders - rendered)


def test_pin_corpus_covers_the_docs_currency_corpus() -> None:
    """Every file the docs-currency guard reads is rendered here, by the same rule."""
    from tests import test_docs_currency as currency

    assert pr.HISTORICAL.pattern == currency.HISTORICAL.pattern
    assert pr.HISTORICAL.flags == currency.HISTORICAL.flags
    wanted = {
        p.relative_to(ROOT).as_posix()
        for p in currency.SNIPPET_FILES
        if p.is_file() and p.name != "server.json" and not p.name.startswith("MIGRATING-")
    }
    assert wanted <= set(pr.pin_files(ROOT)), sorted(wanted - set(pr.pin_files(ROOT)))


# ------------------------------------------------------------ holders outside the render


def _published() -> str:
    return pr.published_version(ROOT) or CURRENT


def test_no_version_holder_outside_the_rendered_set() -> None:
    """Every non-historical line naming the release or the published pin is in a file the
    render writes (VERSION_FIELDS or pin_files()), or is excused in NOT_HOLDERS_FILE: no literal
    can go stale silently, wherever it lives (scripts, workflows, manifests, src/)."""
    strays = pr.unrendered_holders(ROOT, {CURRENT, _published()})
    assert strays == [], "\n".join(strays)


def test_a_stray_version_holder_stops_the_render(tree: Path) -> None:
    """A generator that embeds the release instead of reading it fails the bump, naming
    the file and line, and nothing is written."""
    stray = tree / "scripts" / "stray_generator.sh"
    stray.write_text(f"#!/bin/sh\necho '<!-- support={_published()} -->'\n")
    before = _snapshot(tree)
    with pytest.raises(pr.PrepareError, match=r"scripts/stray_generator\.sh:2"):
        pr.plan(tree, NEXT)
    assert pr.main([NEXT, "--write", "--root", str(tree)]) == 2
    assert pr.main([NEXT, "--check", "--root", str(tree)]) == 2
    assert _snapshot(tree) == before
    # A line that says it is historical keeps its version and is not a holder.
    stray.write_text(f"#!/bin/sh\n# docs-currency: historical: added in {_published()}\n")
    assert pr.plan(tree, NEXT).changes


def test_excused_holders_are_exact_and_still_needed() -> None:
    """Each excuse names one version in one file, and that file still names it."""
    excused = pr.not_holders(ROOT)
    assert excused, f"{pr.NOT_HOLDERS_FILE} is missing or empty"
    for (rel, version), reason in excused.items():
        pr.parse_version(version)
        assert reason.strip(), rel
        path = ROOT / rel
        if not path.is_file():  # stripped from this tree (the public tree drops private files)
            continue
        assert pr.version_lines(path.read_text(), version), (
            f"{rel} no longer names {version}: delete its entry in {pr.NOT_HOLDERS_FILE}"
        )


def test_every_version_field_is_rendered_and_skipped_by_the_scan() -> None:
    """Every VERSION_FIELDS path exists; the scan skips exactly the rendered files."""
    for field in pr.VERSION_FIELDS:
        assert (ROOT / field.path).is_file(), field.path
    rendered = pr.rendered_files(ROOT)
    assert {field.path for field in pr.VERSION_FIELDS} <= rendered
    assert set(pr.pin_files(ROOT)) <= rendered


@pytest.mark.parametrize(
    "state_dir", [".hypothesis", ".pytest_cache", ".mypy_cache", ".some_tool_state"]
)
def test_tool_state_folders_are_never_version_holders(tree: Path, state_dir: str) -> None:
    """Tool state (hypothesis constants, caches) names whatever version the last run saw."""
    folder = tree / state_dir / "constants"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "entry").write_text(f"unifi-fabric-mcp-server=={CURRENT}\nv{CURRENT}\n")
    if state_dir == ".some_tool_state":
        (tree / state_dir / "CACHEDIR.TAG").write_text(
            "Signature: 8a477f597d28d172789f06886806bc55\n"
        )
    assert not [
        found for found in pr.unrendered_holders(tree, {CURRENT}) if found.startswith(state_dir)
    ]
    (tree / "docs" / "stray.txt").write_text(f"pinned at {CURRENT}\n")
    assert any(f.startswith("docs/stray.txt") for f in pr.unrendered_holders(tree, {CURRENT}))
