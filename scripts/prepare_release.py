#!/usr/bin/env python3
"""Render every release version field and current install pin from one input: VERSION.

    python3 scripts/prepare_release.py X.Y.Z                  # dry run: print the diff
    python3 scripts/prepare_release.py X.Y.Z --write          # apply it
    python3 scripts/prepare_release.py X.Y.Z --check          # exit 1 if anything is stale
    python3 scripts/prepare_release.py X.Y.Z --published --write
    python3 scripts/prepare_release.py X.Y.Z --published --archive-sha256 <hex> --write
    python3 scripts/prepare_release.py --identity             # print and check the identity

VERSION (a clean ``X.Y.Z``) is the only version input. Two sets of fields follow it:

Version fields always name VERSION: ``pyproject.toml`` ``[project] version``;
``server.json`` ``version``, the PyPI package ``version`` and the OCI image tag; the
``version`` of the Claude Code plugin, the Codex plugin, the Claude Desktop bundle manifest
and the Gemini CLI extension; the Homebrew formula's tagged-archive ``url``; the
``version`` tag in ``docs/site-stats.json``; the ``Version X.Y.Z.`` statement in the
``llms.txt`` agent index; the "describes X.Y.Z source" notes in ``README.md`` and
``docs/CLIENT-SETUP.md``. The Dockerfile carries no version label.

Install pins (``unifi-fabric-mcp-server==X.Y.Z``, image tags, bundle links, ``support=``
markers and every other current mention in the documentation set and the client
manifests) name the latest PUBLISHED release, recorded in ``scripts/published-version.txt``.
A bump leaves them alone, so an install never points at an unpublished package. At
publication, ``--published`` flips the pins and ``published-version.txt`` to VERSION
together. When ``published-version.txt`` does not exist yet, the currently pinned version
is the ``pyproject.toml`` version before the change, and the file is created with it.
After the flip, ``scripts/check_launcher_settings.py --record`` records the settings the
new published release accepts; its check fails on a launcher pinned to a release older
than a setting the launcher passes (the ``MIGRATING-*`` guides included).

Historical text is never rendered: the CHANGELOG, ``changelog.d/``, the ``MIGRATING-*``
guides, the private documentation directory and any line that says it is historical (an
upgrade note, a recorded sweep, a ``docs-currency: historical`` marker). A
``doc-provenance`` content hash that names a file this tool changes is refreshed with it.

Nothing else may hold the version. Before rendering, every run scans the tree (all but
``tests/``, ``tools/``, lock and requirements files and caches) for a line that names the
current version or the published release in a file neither set above renders. Such a line
would go stale at the next release, so the run refuses it (exit 2, nothing written) and
names it: a generator reads ``pyproject.toml`` or ``scripts/published-version.txt`` when it
runs instead of embedding the version, a manifest field joins ``VERSION_FIELDS``, and a line
that must keep its own version says so (``docs-currency: historical``) or, where no marker
fits, is listed in ``scripts/not-version-holders.toml`` for that one version with the reason.

The formula's ``sha256`` is the checksum of the public tagged archive, which exists only
after the tag: this tool never computes, fetches or invents it. A new archive URL resets it
to the all-zero placeholder; ``--archive-sha256`` (with ``--published``) sets it.

``release-identity.json`` holds the fork-editable public identity (owner, repository,
image, registry name, PyPI name, Homebrew tap). ``server.json`` stays the authoritative
registry identity: every run fails when the two disagree, and nothing is written.

Exit status: 0 on success (``--check``: nothing stale), 1 when ``--check`` finds a stale
field, 2 on a usage, identity or repository-layout error.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_server_json_version  # noqa: E402
import site_stats  # noqa: E402
from extract_install_cases import public_documents  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
IDENTITY_FILE = "release-identity.json"
PUBLISHED_FILE = "scripts/published-version.txt"
ZERO_SHA256 = "0" * 64

_VERSION_RE = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
# The same rule tests/test_docs_currency.py applies: a line that says it is historical
# keeps the version it names.
HISTORICAL = re.compile(
    r"docs-currency: historical|upgrading from|recorded (live )?sweep|sweep", re.I
)
# Released history and dated documents: never rendered, never scanned.
_HISTORY_NAMES = ("CHANGELOG", "MIGRATING-")
_HISTORY_DIRS = ("changelog.d", "docs/internal")


def read_text(path: Path) -> str:
    """UTF-8 text with line endings kept as they are on disk (provenance hashes bytes)."""
    with path.open(encoding="utf-8", newline="") as handle:
        return handle.read()


def write_text(path: Path, text: str) -> None:
    """Write ``text`` as UTF-8 without translating line endings."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)


class PrepareError(Exception):
    """A request or repository state the tool refuses to render."""


def parse_version(text: str) -> tuple[int, int, int]:
    """``"1.2.3"`` -> ``(1, 2, 3)``; anything but a clean ``X.Y.Z`` is refused."""
    match = _VERSION_RE.fullmatch(text or "")
    if match is None:
        raise PrepareError(
            f"version {text!r} is not a clean X.Y.Z release (no 'v', no suffix, no leading zeros)"
        )
    major, minor, patch = (int(g) for g in match.groups())
    return major, minor, patch


# --------------------------------------------------------------------------- identity


@dataclass(frozen=True)
class Identity:
    owner: str
    repo: str
    image: str
    registry_name: str
    pypi: str
    homebrew_tap: str

    @property
    def repository_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}"


_OWNER_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_REPO_RE = re.compile(r"[A-Za-z0-9._-]{1,100}")
_OVERRIDE_RULES: dict[str, tuple[re.Pattern[str], str]] = {
    "image": (
        re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::\d+)?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+"),
        "a lowercase image reference without a tag (registry/namespace/name)",
    ),
    "registry_name": (
        re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/[A-Za-z0-9._-]+"),
        "a reverse-DNS MCP registry name (namespace/name)",
    ),
    "pypi": (
        re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"),
        "a PEP 508 distribution name",
    ),
    "homebrew_tap": (
        re.compile(r"[A-Za-z0-9-]+/homebrew-[A-Za-z0-9._-]+"),
        "an owner/homebrew-<name> tap repository",
    ),
}


def load_identity(root: Path = ROOT) -> Identity:
    """Read and validate ``release-identity.json``.

    ``owner`` and ``repo`` name the public GitHub repository; every other field derives
    from them unless ``overrides`` names it, and each override is validated. A registry
    name in the ``io.github.`` namespace must belong to ``owner`` (the registry
    authenticates that namespace against the GitHub account).
    """
    path = root / IDENTITY_FILE
    try:
        data = json.loads(read_text(path))
    except FileNotFoundError as exc:
        raise PrepareError(f"{IDENTITY_FILE} is missing") from exc
    except json.JSONDecodeError as exc:
        raise PrepareError(f"{IDENTITY_FILE} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise PrepareError(f"{IDENTITY_FILE} is not a JSON object")
    known = {"$comment", "schema", "owner", "repo", "overrides"}
    if unknown := sorted(set(data) - known):
        raise PrepareError(f"{IDENTITY_FILE}: unknown keys {unknown}")
    if data.get("schema") != 1:
        raise PrepareError(f"{IDENTITY_FILE}: schema must be 1")
    owner, repo = data.get("owner"), data.get("repo")
    if not isinstance(owner, str) or not _OWNER_RE.fullmatch(owner):
        raise PrepareError(f"{IDENTITY_FILE}: owner {owner!r} is not a GitHub account name")
    if not isinstance(repo, str) or not _REPO_RE.fullmatch(repo) or repo in {".", ".."}:
        raise PrepareError(f"{IDENTITY_FILE}: repo {repo!r} is not a GitHub repository name")
    overrides = data.get("overrides", {})
    if not isinstance(overrides, dict):
        raise PrepareError(f"{IDENTITY_FILE}: overrides must be an object")
    if unknown := sorted(set(overrides) - set(_OVERRIDE_RULES)):
        raise PrepareError(
            f"{IDENTITY_FILE}: unknown overrides {unknown}; allowed {sorted(_OVERRIDE_RULES)}"
        )
    for key, value in overrides.items():
        rule, meaning = _OVERRIDE_RULES[key]
        if not isinstance(value, str) or not rule.fullmatch(value):
            raise PrepareError(f"{IDENTITY_FILE}: overrides.{key} {value!r} is not {meaning}")
    identity = Identity(
        owner=owner,
        repo=repo,
        image=overrides.get("image", f"ghcr.io/{owner.lower()}/{repo.lower()}"),
        registry_name=overrides.get("registry_name", f"io.github.{owner}/{repo}"),
        pypi=overrides.get("pypi", repo),
        homebrew_tap=overrides.get("homebrew_tap", f"{owner}/homebrew-tap"),
    )
    namespace = identity.registry_name.split("/", 1)[0]
    if namespace.lower().startswith("io.github.") and namespace[10:].lower() != owner.lower():
        raise PrepareError(
            f"{IDENTITY_FILE}: registry name {identity.registry_name!r} is in another GitHub "
            f"account's namespace (owner is {owner!r})"
        )
    return identity


def identity_problems(root: Path, identity: Identity) -> list[str]:
    """Every way the repository disagrees with ``identity`` (server.json is authoritative)."""
    problems: list[str] = []
    server = json.loads(read_text(root / "server.json"))
    if server.get("name") != identity.registry_name:
        problems.append(
            f"server.json name {server.get('name')!r} != {IDENTITY_FILE} registry name "
            f"{identity.registry_name!r}"
        )
    url = (server.get("repository") or {}).get("url")
    if url != identity.repository_url:
        problems.append(
            f"server.json repository.url {url!r} != {IDENTITY_FILE} {identity.repository_url!r}"
        )
    packages = server.get("packages") or []
    for pkg in packages:
        kind, ident = pkg.get("registryType"), str(pkg.get("identifier", ""))
        if kind == "pypi" and ident != identity.pypi:
            problems.append(f"server.json PyPI identifier {ident!r} != {identity.pypi!r}")
        if kind == "oci" and ident.rsplit(":", 1)[0] != identity.image:
            problems.append(f"server.json OCI identifier {ident!r} is not {identity.image}:<tag>")
    if {p.get("registryType") for p in packages} != {"pypi", "oci"}:
        problems.append("server.json must list exactly the pypi and oci packages")
    name = tomllib.loads(read_text(root / "pyproject.toml"))["project"]["name"]
    if name != identity.pypi:
        problems.append(f"pyproject.toml name {name!r} != {IDENTITY_FILE} PyPI name")
    labels = re.findall(
        r'io\.modelcontextprotocol\.server\.name="([^"]*)"', read_text(root / "Dockerfile")
    )
    if labels != [identity.registry_name]:
        problems.append(
            f"Dockerfile io.modelcontextprotocol.server.name labels {labels} != "
            f"[{identity.registry_name!r}]"
        )
    return problems


# ----------------------------------------------------------------------- version fields


@dataclass(frozen=True)
class VersionField:
    """One rendered field: ``pattern`` group 2 is the version, groups 1 and 3 its frame."""

    path: str
    label: str
    pattern: re.Pattern[str]
    count: int = 1


def _json_version(path: str, label: str) -> VersionField:
    return VersionField(path, label, re.compile(r'(?m)^(\s*"version": ")([^"]*)(")'))


VERSION_FIELDS: tuple[VersionField, ...] = (
    VersionField(
        "pyproject.toml", "[project] version", re.compile(r'(?m)^(version = ")([^"]*)(")')
    ),
    VersionField(
        "server.json",
        "version and PyPI package version",
        re.compile(r'("version": ")([^"]*)(")'),
        count=2,
    ),
    VersionField(
        "server.json",
        "OCI image tag",
        re.compile(r'("identifier": "[^"\s]+/[^"\s:]+:)([^"]*)(")'),
    ),
    _json_version("plugins/claude/.claude-plugin/plugin.json", "Claude Code plugin version"),
    _json_version("plugins/codex/.codex-plugin/plugin.json", "Codex plugin version"),
    _json_version("plugins/antigravity/plugin.json", "Antigravity plugin version"),
    _json_version("plugins/claude-desktop/manifest.json", "Claude Desktop bundle version"),
    _json_version("gemini-extension.json", "Gemini CLI extension version"),
    VersionField(
        "packaging/homebrew/unifi-fabric-mcp-server.rb",
        "tagged-archive url",
        re.compile(
            r'(?m)^(  url "https://github\.com/[^/"]+/[^/"]+/archive/refs/tags/v)'
            r'([^"]*)(\.tar\.gz")'
        ),
    ),
    VersionField("docs/site-stats.json", "version tag", re.compile(r'("version": "v)([^"]*)(")')),
    VersionField(
        "llms.txt",
        "agent-index version statement",
        re.compile(r"(?m)^(> .*\bVersion )(\d+\.\d+\.\d+)(\.)"),
    ),
    # The notes that say which source the document describes. They sit beside an upgrade
    # note, which is historical text and so is never pin-rendered; the source they describe is
    # always VERSION, whatever release is published.
    VersionField(
        "README.md",
        "install note: source described",
        re.compile(r"(?m)^(> describes )(\d+\.\d+\.\d+)( source\.)"),
    ),
    VersionField(
        "docs/CLIENT-SETUP.md",
        "setup guide: source described",
        re.compile(
            r"(?m)^(The package commands in this guide install .*the guide describes )"
            r"(\d+\.\d+\.\d+)( source\.)"
        ),
    ),
)
FORMULA = "packaging/homebrew/unifi-fabric-mcp-server.rb"
_FORMULA_SHA = re.compile(
    r'(?m)^(  url "[^"]+/archive/refs/tags/v[^"]+\.tar\.gz"\n  sha256 ")([^"]*)(")'
)
# Client manifests: install pins only (their "version" lines are version fields).
PIN_MANIFESTS = (
    "plugins/claude/.claude-plugin/plugin.json",
    "plugins/codex/.codex-plugin/plugin.json",
    "plugins/codex/.mcp.json",
    ".agents/plugins/marketplace.json",
    "plugins/antigravity/plugin.json",
    "plugins/antigravity/mcp_config.json",
    "plugins/claude-desktop/manifest.json",
    "gemini-extension.json",
    "Dockerfile",
)
_VERSION_FIELD_LINE = re.compile(r'^\s*"version":')


def is_historical(rel: str) -> bool:
    """Released history and dated documents (never rendered)."""
    name = rel.rsplit("/", 1)[-1]
    return name.startswith(_HISTORY_NAMES) or any(
        rel == d or rel.startswith(d + "/") for d in _HISTORY_DIRS
    )


def pin_files(root: Path) -> list[str]:
    """The documentation set and client manifests whose current mentions follow the pins.

    The public documentation set every documentation gate reads (README, docs/ and
    plugins/), AGENTS, CONTRIBUTING, PRIVACY and the ``llms.txt`` agent index, the client
    manifests, the Dockerfile, config/ and the GitHub issue templates (the bug report names
    the image tag a reporter should pull), minus historical documents.
    """
    docs = [p.relative_to(root).as_posix() for p in public_documents(root)]
    extra = ["AGENTS.md", "CONTRIBUTING.md", "PRIVACY.md", "llms.txt", *PIN_MANIFESTS]
    for folder in ("config", ".github/ISSUE_TEMPLATE"):
        path = root / folder
        if path.is_dir():
            extra += sorted(p.relative_to(root).as_posix() for p in path.iterdir() if p.is_file())
    found = dict.fromkeys(rel for rel in [*docs, *extra] if (root / rel).is_file())
    return [rel for rel in found if not is_historical(rel)]


# ----------------------------------------------------------- holders outside the render

#: Written by a generator from the version source, so they name it by construction.
GENERATED_RECORDS = (PUBLISHED_FILE, "scripts/published-settings.txt")
#: Top-level folders that pin versions on purpose: tests and their fixtures, and the
#: versioned migration kits in tools/.
_SCAN_SKIP_TOP = frozenset({"tests", "tools"})
_SCAN_SKIP_DIRS = frozenset(
    {".git", "node_modules", "__pycache__", ".tox", "dist", "build", ".hypothesis"}
)
_SCAN_SKIP_SUFFIXES = (".lock", ".in", ".png", ".jpg", ".gif", ".mp4", ".webm", ".webp", ".ico")
#: Lines outside the render that keep their own version on purpose, one table per
#: (path, version) with the reason. The file is the excuse list, so it is never scanned.
NOT_HOLDERS_FILE = "scripts/not-version-holders.toml"


def not_holders(root: Path) -> dict[tuple[str, str], str]:
    """(path, version) -> why that file's lines keep that version.

    One entry excuses one version in one file, never the file: a line there naming another
    release is still a holder. tests/test_release_state_contract.py fails on an entry whose
    file no longer names its version.
    """
    path = root / NOT_HOLDERS_FILE
    if not path.is_file():
        return {}
    try:
        entries = tomllib.loads(read_text(path)).get("excuse", [])
    except tomllib.TOMLDecodeError as exc:
        raise PrepareError(f"{NOT_HOLDERS_FILE} is not valid TOML: {exc}") from exc
    excused: dict[tuple[str, str], str] = {}
    for entry in entries:
        rel, version, reason = (entry.get(k) for k in ("path", "version", "reason"))
        if not (isinstance(rel, str) and isinstance(reason, str) and reason.strip()):
            raise PrepareError(f"{NOT_HOLDERS_FILE}: every excuse needs a path and a reason")
        parse_version(version)
        excused[(rel, version)] = reason
    return excused


def _token(version: str) -> re.Pattern[str]:
    """``version`` as a whole release token (``v`` allowed; not ``0.7.10``, not a suffix)."""
    return re.compile(r"(?<![\w.])v?" + re.escape(version) + r"(?![\w.]*\d)")


def version_lines(text: str, version: str) -> list[tuple[int, str]]:
    """The non-historical lines of ``text`` naming ``version``, numbered from 1."""
    token = _token(version)
    return [
        (number, line)
        for number, line in enumerate(text.splitlines(), 1)
        if token.search(line) and not HISTORICAL.search(line)
    ]


def rendered_files(root: Path) -> set[str]:
    """Every file a run writes a version into: the version fields and the pin corpus."""
    return {field.path for field in VERSION_FIELDS} | {FORMULA} | set(pin_files(root))


def _is_tool_state(directory: Path) -> bool:
    """A folder a tool keeps for itself, never release content.

    Tools mark their own state: a ``CACHEDIR.TAG`` (pytest, ruff, mypy, pip) or a
    ``.gitignore`` inside the folder. ``.hypothesis`` constants name whatever version the
    last run saw, so they are skipped by this rule and by ``_SCAN_SKIP_DIRS``.
    """
    return (directory / "CACHEDIR.TAG").is_file() or (directory / ".gitignore").is_file()


def _git_ignored(root: Path, rels: list[str]) -> set[str]:
    """The paths ``git`` ignores, when ``root`` is a work tree; none otherwise."""
    if not rels or not (root / ".git").exists():
        return set()
    try:
        done = subprocess.run(
            ["git", "check-ignore", "-z", "--stdin"],
            cwd=root,
            input="\0".join(rels).encode(),
            capture_output=True,
            check=False,
        )
    except OSError:
        return set()
    return {item.decode() for item in done.stdout.split(b"\0") if item}


def _scanned_files(root: Path):
    candidates: list[tuple[str, Path]] = []
    state_dirs: dict[Path, bool] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        parts = rel.parts
        if (
            parts[0] in _SCAN_SKIP_TOP
            or any(
                part in _SCAN_SKIP_DIRS
                or part.startswith(".venv")
                or part.endswith(("_cache", ".egg-info"))
                for part in parts[:-1]
            )
            or not path.is_file()
            or path.name.endswith(_SCAN_SKIP_SUFFIXES)
            or "requirements" in path.name
        ):
            continue
        if any(
            state_dirs.setdefault(parent, _is_tool_state(parent))
            for parent in path.parents
            if parent != root and root in parent.parents
        ):
            continue
        candidates.append((rel.as_posix(), path))
    ignored = _git_ignored(root, [rel for rel, _ in candidates])
    for rel, path in candidates:
        if rel not in ignored:
            yield rel, path


def unrendered_holders(root: Path, versions: set[str]) -> list[str]:
    """``path:line: text`` for every line outside the render that names one of ``versions``.

    Historical documents and lines, generated records and ``not_holders()`` excuses are
    skipped; whatever is left would go stale at the next release.
    """
    skip = rendered_files(root) | set(GENERATED_RECORDS) | {NOT_HOLDERS_FILE}
    excused = not_holders(root)
    found: list[str] = []
    for rel, path in _scanned_files(root):
        if rel in skip or is_historical(rel):
            continue
        try:
            text = read_text(path)
        except (UnicodeDecodeError, OSError):
            continue
        for version in sorted(versions):
            if (rel, version) in excused:
                continue
            found += [f"{rel}:{n}: {line.strip()}" for n, line in version_lines(text, version)]
    return sorted(set(found))


def provenance_files(root: Path) -> list[str]:
    """Where ``file:<path>@sha256:<digest>`` provenance pins live."""
    docs = [p.relative_to(root).as_posix() for p in public_documents(root)]
    sidecar = "scripts/doc_provenance.json"
    rels = [*docs, sidecar] if (root / sidecar).is_file() else docs
    return [rel for rel in rels if not is_historical(rel)]


def current_version(root: Path) -> str:
    version = tomllib.loads(read_text(root / "pyproject.toml"))["project"]["version"]
    parse_version(version)
    return version


def published_version(root: Path) -> str | None:
    path = root / PUBLISHED_FILE
    if not path.is_file():
        return None
    text = read_text(path).strip()
    parse_version(text)
    return text


def _sub_pin_line(line: str, old: str, new: str) -> str:
    pattern = re.compile(r"(?<![\w.])(v?)" + re.escape(old) + r"(?![\w.]*\d)")
    return pattern.sub(lambda m: m[1] + new, line)


def render_pins(text: str, rel: str, old: str, new: str) -> str:
    """Move every current mention of ``old`` in ``text`` to ``new``, line by line.

    Historical lines keep their version; JSON ``"version"`` lines are version fields,
    rendered separately.
    """
    if old == new:
        return text
    out = []
    for line in text.splitlines(keepends=True):
        if (
            HISTORICAL.search(line)
            or "clientInfo" in line
            or (rel.endswith(".json") and _VERSION_FIELD_LINE.match(line))
        ):
            out.append(line)
        else:
            out.append(_sub_pin_line(line, old, new))
    return "".join(out)


@dataclass
class Plan:
    version: str
    pinned_before: str
    pinned_after: str
    changes: dict[str, tuple[str, str]]  # rel -> (old text, new text)
    notes: list[str]

    def diff(self) -> str:
        return "".join(
            "".join(
                difflib.unified_diff(
                    old.splitlines(keepends=True),
                    new.splitlines(keepends=True),
                    fromfile=f"a/{rel}",
                    tofile=f"b/{rel}",
                )
            )
            for rel, (old, new) in sorted(self.changes.items())
        )


def _render_field(text: str, field: VersionField, value: str) -> str:
    def repl(match: re.Match[str]) -> str:
        if not _VERSION_RE.fullmatch(match[2]):
            raise PrepareError(f"{field.path} {field.label} holds {match[2]!r}, not X.Y.Z")
        return match[1] + value + match[3]

    new, count = field.pattern.subn(repl, text)
    if count != field.count:
        raise PrepareError(
            f"{field.path}: expected {field.count} {field.label} field(s), found {count}; "
            "the file layout changed, update VERSION_FIELDS"
        )
    return new


def _validate(version: str, files: Callable[[str], str]) -> None:
    """Re-read the rendered files through the shared checks."""
    if tomllib.loads(files("pyproject.toml"))["project"]["version"] != version:
        raise PrepareError("pyproject.toml [project] version did not render")
    server = json.loads(files("server.json"))
    problems = check_server_json_version.version_problems(server, version)
    for field in VERSION_FIELDS:
        if field.path.endswith(".json") and field.path not in {"server.json", site_stats_path()}:
            if json.loads(files(field.path)).get("version") != version:
                problems.append(f"{field.path} version did not render")
    problems += site_stats.validate(json.loads(files(site_stats_path())), version)
    if problems:
        raise PrepareError("rendered fields fail their checks: " + "; ".join(problems))


def site_stats_path() -> str:
    return site_stats.SITE_STATS.as_posix()


def _refresh_provenance(
    root: Path,
    texts: dict[str, str],
    originals: dict[str, str],
    read: Callable[[str], str],
) -> None:
    """Move ``file:<path>@sha256:<old>`` pins of every changed file to its new digest.

    A refreshed document can itself be a pinned source, so repeat until nothing moves.
    """

    def digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    earlier: dict[str, set[str]] = {}  # every digest a changed file has had
    for _ in range(5):
        current = {}
        for rel in texts:
            if rel in originals and texts[rel] != originals[rel]:
                current[rel] = digest(texts[rel])
                earlier.setdefault(rel, {digest(originals[rel])}).add(current[rel])
        moved = False
        for rel in provenance_files(root):
            text = new = read(rel)
            for source, now in current.items():
                for old in earlier[source] - {now}:
                    new = new.replace(f"file:{source}@sha256:{old}", f"file:{source}@sha256:{now}")
            if new != text:
                texts[rel] = new
                moved = True
        if not moved:
            return
    raise PrepareError("provenance hashes did not settle")  # pragma: no cover


def plan(
    root: Path,
    version: str,
    *,
    published: bool = False,
    archive_sha256: str | None = None,
) -> Plan:
    """Compute every change for ``version`` without writing anything."""
    target = parse_version(version)
    if archive_sha256 is not None:
        if not published:
            raise PrepareError(
                "--archive-sha256 is post-tag only: pass it with --published, once the "
                "public tag archive exists"
            )
        if not _SHA256_RE.fullmatch(archive_sha256) or archive_sha256 == ZERO_SHA256:
            raise PrepareError(
                "--archive-sha256 must be the 64 lowercase hex digits of the archive"
            )
    identity = load_identity(root)
    if problems := identity_problems(root, identity):
        raise PrepareError("release identity disagrees: " + "; ".join(problems))

    before = current_version(root)
    recorded = published_version(root)
    pinned_before = recorded or before
    if strays := unrendered_holders(root, {before, pinned_before}):
        raise PrepareError(
            f"{len(strays)} line(s) name the release outside the rendered files and would go "
            "stale: read the version at generate time, add a VERSION_FIELDS entry, or mark the "
            "line docs-currency: historical: " + "; ".join(strays[:20])
        )
    if target < parse_version(pinned_before):
        raise PrepareError(f"{version} is older than the published release {pinned_before}")
    if target < parse_version(before):
        raise PrepareError(f"{version} is older than the current version {before}")
    pinned_after = version if published else pinned_before

    texts: dict[str, str] = {}
    originals: dict[str, str] = {}

    def read(rel: str) -> str:
        if rel not in texts:
            path = root / rel
            if not path.is_file():
                raise PrepareError(f"{rel} is missing")
            originals[rel] = texts[rel] = read_text(path)
        return texts[rel]

    notes = ["Dockerfile: no version label to render"]
    for field in VERSION_FIELDS:
        texts[field.path] = _render_field(read(field.path), field, version)

    formula = read(FORMULA)
    url_changed = formula != originals[FORMULA]
    shas = _FORMULA_SHA.findall(formula)
    if len(shas) != 1:
        raise PrepareError(f"{FORMULA}: expected one tagged-archive sha256, found {len(shas)}")
    new_sha = archive_sha256 or (ZERO_SHA256 if url_changed else shas[0][1])
    texts[FORMULA] = _FORMULA_SHA.sub(lambda m: m[1] + new_sha + m[3], formula)
    if archive_sha256 is None and url_changed:
        notes.append(f"{FORMULA}: archive url moved to v{version}; sha256 reset to the placeholder")

    for rel in pin_files(root):
        texts[rel] = render_pins(read(rel), rel, pinned_before, pinned_after)

    if recorded != pinned_after:
        path = root / PUBLISHED_FILE
        originals[PUBLISHED_FILE] = read_text(path) if path.is_file() else ""
        texts[PUBLISHED_FILE] = f"{pinned_after}\n"

    _refresh_provenance(root, texts, originals, read)
    _validate(version, lambda rel: texts[rel] if rel in texts else read_text(root / rel))
    changes = {rel: (originals[rel], texts[rel]) for rel in texts if texts[rel] != originals[rel]}
    return Plan(version, pinned_before, pinned_after, changes, notes)


def apply(root: Path, result: Plan) -> None:
    for rel, (_old, new) in sorted(result.changes.items()):
        write_text(root / rel, new)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version", nargs="?", help="The release version, X.Y.Z.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="Apply the changes.")
    mode.add_argument("--check", action="store_true", help="Exit 1 when anything is stale.")
    mode.add_argument("--identity", action="store_true", help="Print and check the identity.")
    parser.add_argument(
        "--published",
        action="store_true",
        help="VERSION is published: flip install pins and published-version.txt to it.",
    )
    parser.add_argument(
        "--archive-sha256",
        help="Post-tag only (with --published): the public tagged archive's SHA-256.",
    )
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        if args.identity:
            identity = load_identity(root)
            for key, value in vars(identity).items():
                print(f"{key}: {value}")
            print(f"repository_url: {identity.repository_url}")
            problems = identity_problems(root, identity)
            for problem in problems:
                print(f"prepare_release: {problem}", file=sys.stderr)
            return 2 if problems else 0
        if not args.version:
            parser.error("VERSION is required")
        result = plan(
            root, args.version, published=args.published, archive_sha256=args.archive_sha256
        )
    except PrepareError as exc:
        print(f"prepare_release: {exc}", file=sys.stderr)
        return 2
    summary = (
        f"version {result.version}; install pins {result.pinned_before} -> "
        f"{result.pinned_after}; {len(result.changes)} file(s) change"
    )
    if args.check:
        for rel in sorted(result.changes):
            print(f"stale: {rel}")
        print(summary)
        return 1 if result.changes else 0
    if args.write:
        apply(root, result)
        for rel in sorted(result.changes):
            print(f"wrote {rel}")
    else:
        sys.stdout.write(result.diff())
        print("dry run: pass --write to apply")
    for note in result.notes:
        print(f"note: {note}")
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
