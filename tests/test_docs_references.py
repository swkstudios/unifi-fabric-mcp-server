"""Every user-facing doc names real things: tools, environment variables, image tags.

Offline and deterministic. Covers every tracked public Markdown file (README, docs/*.md,
plugins/, .github/, CONTRIBUTING, PRIVACY, LAST_AUDITED, CLAUDE.md) and the client
integration manifests, wider than the per-file lists in test_docs_currency.py and
test_api_keys_and_env_contract.py, whose rules are reused here.

* A backticked name shaped like a tool (``list_sites``, ``get_site(...)``) is a
  registered tool, a parameter of one, or is explicitly negated on its line ("there
  is no ``list_vouchers``").
* Every ``UNIFI_*`` / ``MCP_*`` / ``FASTMCP_*`` variable is read by the code.
* Every ``ghcr.io/<org>/unifi-fabric-mcp-server:<tag>`` names the current release or
  ``latest`` (historical lines marked as in test_docs_currency.py excepted).

The doc set is listed at collection time. ``git ls-files`` answers when this tree is its
own git work tree; otherwise (no git binary, or git refusing a read-only mount owned by
another user, as in the Tier-2 ``python:3.12-slim`` container) a walk of the tree lists
the same files. ``test_tree_walk_matches_git_listing`` holds the two equal.
"""

from __future__ import annotations

import asyncio
import functools
import os
import re
import subprocess
from fnmatch import fnmatchcase
from pathlib import Path

import pytest

from tests.removed_tools import is_history_surface, removed_since_release
from tests.retired_names import migration_table_names
from tests.test_api_keys_and_env_contract import _ENV_NAME, SRC, _is_read, _source_text
from tests.test_docs_currency import HISTORICAL, IMAGE_RE, PACKAGE, PUBLISHED_VERSION, VERSION
from unifi_fabric.redaction import CREDENTIAL_FIELDS

ROOT = Path(__file__).resolve().parents[1]
_PRIVATE = ("tests/", "src/", "schemas/")


def _private(rel: str) -> bool:
    """Code, fixtures and the private notes under a docs/ subfolder (stripped publicly)."""
    return rel.startswith(_PRIVATE) or (rel.startswith("docs/") and rel.count("/") > 1)


# The shipped documentation surface as git pathspecs. A git pathspec's ``*`` also
# matches ``/`` (no FNM_PATHNAME), which is what ``fnmatchcase`` does in the walk.
DOC_PATHSPECS = ("*.md", "plugins/*", "*.json", "config/*")
# What the walk never enters or lists: git metadata and the environment, cache and build
# output this repository's .gitignore files exclude (none of it is ever tracked here).
_WALK_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "build",
        "dist",
        "__pycache__",
        ".ruff_cache",
        ".pytest_cache",
        ".mypy_cache",
        ".hypothesis",
        ".tox",
        "htmlcov",
    }
)
_WALK_SKIP_DIR_SUFFIXES = (".egg-info",)
_WALK_SKIP_PATHS = frozenset()
_WALK_SKIP_FILES = ("*.py[cod]", "*.egg", ".env*", ".coverage", ".coverage.*", "coverage.xml")


def git_listed(root: Path, *pathspecs: str, untracked: bool = False) -> list[str] | None:
    """``git ls-files`` for ``root``, or None when git cannot answer for this tree.

    None when git is not installed, refuses the repository (for example a read-only
    mount owned by another user), or ``root`` is not the top of its own work tree (a
    tree exported without ``.git`` inside some other checkout). ``untracked`` adds the
    untracked files git does not ignore.
    """
    git = ("git", "-C", str(root))
    extra = ("--others", "--exclude-standard") if untracked else ()
    try:
        top = subprocess.run(  # noqa: S603 - fixed argv, read-only
            [*git, "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
        ).stdout.strip()
        if Path(top).resolve() != root.resolve():
            return None
        out = subprocess.run(  # noqa: S603 - fixed argv, read-only
            [*git, "ls-files", "-z", "--cached", *extra, "--", *pathspecs],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return sorted(name for name in out.split("\0") if name)


def walked(root: Path, *pathspecs: str) -> list[str]:
    """The files under ``root`` matching ``pathspecs``, found by walking the tree."""
    found = []
    for directory, subdirs, names in os.walk(root):
        here = Path(directory).relative_to(root)
        subdirs[:] = [
            d
            for d in subdirs
            if d not in _WALK_SKIP_DIRS
            and not d.endswith(_WALK_SKIP_DIR_SUFFIXES)
            and (here / d).as_posix() not in _WALK_SKIP_PATHS
        ]
        for name in names:
            rel = (here / name).as_posix()
            if any(fnmatchcase(name, skip) for skip in _WALK_SKIP_FILES):
                continue
            if any(fnmatchcase(rel, spec) for spec in pathspecs):
                found.append(rel)
    return sorted(found)


def _public(root: Path, listed: list[str]) -> list[Path]:
    return [
        root / f for f in listed if not _private(f) and f != "CHANGELOG.md" and (root / f).is_file()
    ]


def public_doc_files(root: Path = ROOT) -> list[Path]:
    listed = git_listed(root, *DOC_PATHSPECS)
    return _public(root, walked(root, *DOC_PATHSPECS) if listed is None else listed)


FILES = public_doc_files()


def _tools() -> tuple[set[str], set[str]]:
    """Every name a client can see: the full domain catalog plus the discovery meta-tools.

    Discovery is the default mode, so its meta-tools (``search_tools``, ``describe_tool``,
    ``call_read_tool``, ``call_write_tool``, ``list_tool_families``) are registered tools
    in a default deployment. ``apply_tool_mode`` adds them at server start, not at import,
    so they are read from a real discovery-mode application rather than a hand list.
    """
    from fastmcp import FastMCP

    from unifi_fabric import server
    from unifi_fabric.discovery import META_TOOLS, apply_tool_mode

    async def surface() -> list:
        listed = list(await server.mcp.list_tools())
        probe = FastMCP("docs-reference-discovery-surface")
        restore = await apply_tool_mode(probe, "discovery")
        try:
            meta = [t for t in await probe.list_tools() if t.name in META_TOOLS]
        finally:
            restore()
        assert {t.name for t in meta} == META_TOOLS, sorted(t.name for t in meta)
        return listed + meta

    listed = asyncio.run(surface())
    names = {t.name for t in listed}
    params = {p for t in listed for p in (t.parameters or {}).get("properties", {})}
    return names, params


@functools.cache
def _surface() -> tuple[set[str], set[str]]:
    return _tools()


@functools.cache
def _removed() -> frozenset[str]:
    """Tools a release record shows as removed (derived, never a hand list)."""
    return frozenset(removed_since_release(_surface()[0]))


#: Documented response fields whose names start with a tool verb.
PAYLOAD_FIELDS = frozenset({"read_at"})


@functools.cache
def _lz__VERBS():
    return sorted({name.split("_", 1)[0] for name in _surface()[0]})


@functools.cache
def _lz_TOOL_NAME_RE():
    return re.compile(
        rf"`(?:mcp__[\w-]+__)?((?:{'|'.join(_lz__VERBS())})_[a-z0-9_]+)(?:\([^`]*\))?`"
    )


def unknown_tool_names(text: str, rel: str = "") -> list[tuple[int, str]]:
    bad = []
    for number, line in enumerate(text.splitlines(), 1):
        for match in _lz_TOOL_NAME_RE().finditer(line):
            name = match.group(1)
            if name in _surface()[0] or name in _surface()[1] or name == "query_string":
                continue
            if is_history_surface(rel) and name in _removed():
                # A tool an earlier release shipped and a later one removed, named where
                # that history is recorded: its migration guide, changelog or coverage
                # notes (tests/removed_tools.py derives the set and says which surfaces are
                # history). A current doc naming it as live, or a misspelling, still fails.
                continue
            if name in PAYLOAD_FIELDS:
                # A documented response field (``read_at``), not a tool: the ``read_`` verb
                # (read_recent_events) must not claim it.
                continue
            if name in CREDENTIAL_FIELDS:
                # A documented redaction field name (``refresh_token``), not a tool: a tool
                # verb such as ``refresh_`` (refresh_sso_session) must not claim it.
                continue
            if re.search(rf"\bno\b[^.]*`{re.escape(name)}`", line, re.I):
                continue  # an explicit negation: "there is no `list_vouchers`"
            bad.append((number, name))
    return bad


def test_scope_is_the_whole_public_doc_set():
    rel = {f.relative_to(ROOT).as_posix() for f in FILES}
    for expected in (
        "README.md",
        "docs/TOOLS.md",
        ".github/SECURITY.md",
        "plugins/claude/README.md",
        "plugins/claude-desktop/manifest.json",
        "LAST_AUDITED.md",
    ):
        assert expected in rel, expected
    assert not any(_private(r) for r in rel)


def test_tree_walk_matches_git_listing():
    """The no-git fallback lists exactly the files git lists for this checkout.

    git's answer includes untracked files it does not ignore, so a new doc not yet added
    counts on both sides; in a clean checkout it is exactly ``git ls-files``. Where git
    cannot answer (the Tier-2 container), collection used the walk, and that is checked.
    """
    walk = walked(ROOT, *DOC_PATHSPECS)
    listed = git_listed(ROOT, *DOC_PATHSPECS, untracked=True)
    if listed is None:
        assert FILES == _public(ROOT, walk)
    else:
        on_disk = [f for f in listed if (ROOT / f).is_file()]
        walk_on_disk = [f for f in walk if (ROOT / f).is_file()]
        assert walk_on_disk == on_disk, {
            "walk only (add the directory to _WALK_SKIP_DIRS?)": sorted(set(walk) - set(on_disk)),
            "git only (the walk skips a shipped file)": sorted(set(on_disk) - set(walk)),
        }
        tracked = git_listed(ROOT, *DOC_PATHSPECS)
        assert tracked is not None
        assert set(_public(ROOT, tracked)) <= set(_public(ROOT, walk))


@pytest.mark.parametrize("git", ["not-installed", "refuses-the-repository"])
def test_collection_falls_back_to_the_walk_without_a_usable_git(tmp_path, monkeypatch, git):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    if git == "refuses-the-repository":
        fake = bin_dir / "git"
        fake.write_text(
            "#!/bin/sh\necho 'fatal: detected dubious ownership in repository at /src' >&2\n"
            "exit 128\n"
        )
        fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    assert git_listed(ROOT, *DOC_PATHSPECS) is None
    files = public_doc_files()
    assert files == _public(ROOT, walked(ROOT, *DOC_PATHSPECS))
    assert ROOT / "README.md" in files
    assert ROOT / "docs" / "TOOLS.md" in files


def test_tree_walk_skips_environment_and_build_output(tmp_path):
    keep = [
        ".github/SECURITY.md",
        ".mcp.json",
        "README.md",
        "config/defaults.yaml",
        "docs/TOOLS.md",
        "plugins/claude/bin/run.sh",
        "server.json",
        "tests/fixtures/sample.json",
    ]
    drop = [
        ".git/description.md",
        ".hypothesis/examples.json",
        ".mypy_cache/cache.json",
        ".pytest_cache/README.md",
        ".ruff_cache/CACHEDIR.json",
        ".tox/py312/README.md",
        ".venv/lib/python3.12/site-packages/pkg/README.md",
        "build/lib/README.md",
        "dist/meta.json",
        "htmlcov/status.json",
        "node_modules/pkg/package.json",
        "plugins/.env.json",
        "src/pkg/__pycache__/cache.json",
        "src/pkg/notes.txt",
        "src/unifi_fabric.egg-info/README.md",
        "venv/pyvenv.json",
    ]
    for rel in keep + drop:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x\n")
    assert walked(tmp_path, *DOC_PATHSPECS) == sorted(keep)
    assert public_doc_files(tmp_path) == [
        tmp_path / rel for rel in sorted(keep) if not rel.startswith("tests/")
    ]


def test_every_documented_tool_name_is_registered():
    bad = [
        f"{f.relative_to(ROOT)}:{n}: {name}"
        for f in FILES
        for n, name in unknown_tool_names(
            f.read_text(encoding="utf-8"), f.relative_to(ROOT).as_posix()
        )
    ]
    assert bad == [], bad


def test_removed_tool_names_are_derived_and_a_misspelling_still_fails():
    removed = _removed()
    assert {"reboot_nvr", "create_traffic_rule"} <= removed
    assert not removed & _surface()[0]
    history = "docs/MIGRATING-0.7.2.md"
    assert [n for _n, n in unknown_tool_names("Use `create_traffic_rule`.", history)] == []
    assert [n for _n, n in unknown_tool_names("Use `create_traffic_rulez`.", history)] == [
        "create_traffic_rulez"
    ]
    assert [n for _n, n in unknown_tool_names("Use `reboot_nvrs`.", history)] == ["reboot_nvrs"]


@pytest.mark.parametrize(
    "rel",
    ["README.md", "docs/TOOLS.md", "docs/CONFIGURATION.md", "plugins/claude/README.md"],
)
def test_a_current_doc_naming_a_removed_tool_as_live_is_flagged(rel):
    """The removed-tool exemption is for history surfaces only."""
    assert [n for _n, n in unknown_tool_names("Call `reboot_nvr` to restart.", rel)] == [
        "reboot_nvr"
    ]


@pytest.mark.parametrize(
    "rel",
    [
        "CHANGELOG.md",
        "changelog.d/protect-7x-routes.removed.md",
        "docs/MIGRATING-0.7.2.md",
        "docs/COVERAGE.md",
        "docs/notes/removals.md",
    ],
)
def test_a_history_surface_may_name_a_removed_tool(rel):
    assert unknown_tool_names("`reboot_nvr` was removed.", rel) == []


@pytest.mark.parametrize(
    ("line", "flagged"),
    [
        ("Call `list_sites` first.", []),
        ("ASGI supplies the `query_string` field.", []),
        ("Call `list_sitez(host_id)` first.", ["list_sitez"]),
        ("Pass `host_id` to `list_hosts`.", []),
        ("There is no `list_vouchers` alias.", []),
        ("Use `mcp__unifi__get_sitex`.", ["get_sitex"]),
        ("Call `search_tools`, then `describe_tool(name)`.", []),
        ("Call `call_read_tool` or `call_write_tool`.", []),
        ("Call `list_tool_families()` first.", []),
        ("Call `describe_tools` or `call_tool_now` first.", ["describe_tools", "call_tool_now"]),
    ],
)
def test_tool_name_rule(line, flagged):
    assert [name for _n, name in unknown_tool_names(line)] == flagged


def test_every_documented_env_var_is_read_by_the_code():
    src = _source_text(SRC)
    tests = _source_text(ROOT / "tests")
    unread = sorted(
        f"{f.relative_to(ROOT)}: {name}"
        for f in FILES
        for text in [f.read_text(encoding="utf-8")]
        for name in set(_ENV_NAME.findall(text)) - migration_table_names(f, text)
        if not _is_read(name, src, tests)
    )
    assert unread == [], unread


def stale_image_tags(text: str) -> list[str]:
    bad = []
    for number, line in enumerate(text.splitlines(), 1):
        for m in IMAGE_RE.finditer(line):
            if (
                m["name"] != PACKAGE
                or m["sep"] != ":"
                or m["ref"] in {VERSION, PUBLISHED_VERSION, "latest"}
            ):
                continue
            if not HISTORICAL.search(line):
                bad.append(f"{number}: {m.group(0)}")
    return bad


def test_every_image_tag_names_the_current_release():
    bad = [
        f"{f.relative_to(ROOT)}:{item}" for f in FILES for item in stale_image_tags(f.read_text())
    ]
    assert bad == [], bad


def test_image_tag_rule():
    old = f"ghcr.io/swkstudios/{PACKAGE}:0.0.1"
    assert stale_image_tags(f"docker pull {old}\n") == [f"1: {old}"]
    assert stale_image_tags(f"docker pull ghcr.io/swkstudios/{PACKAGE}:{VERSION}\n") == []
    assert stale_image_tags(f"upgrading from {old}\n") == []
