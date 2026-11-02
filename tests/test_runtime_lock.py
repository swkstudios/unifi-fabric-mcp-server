"""The runtime lock (image, Homebrew formula, user installs) carries no dev-only package."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "requirements-runtime.lock"
DEV = ROOT / "requirements.lock"

# Test, lint, type-check and build tooling and its transitive packages stay out of runtime.
DEV_ONLY = frozenset(
    {
        "ast-serialize", "brotli", "coverage", "editables", "execnet", "hatchling", "hypothesis",
        "iniconfig", "librt",
        "mypy", "mypy-extensions", "pathspec", "pluggy", "pytest", "pytest-asyncio",
        "pytest-cov", "pytest-xdist", "respx", "ruff", "sortedcontainers",
        "tomlkit", "trove-classifiers", "trustme",
        "types-cachetools",
    }
)  # fmt: skip


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pins(path: Path) -> dict[str, tuple[str, tuple[str, ...]]]:
    """name -> (version, hashes) for every requirement of a uv-compiled lock."""
    pins: dict[str, tuple[str, list[str]]] = {}
    current = None
    for line in path.read_text().splitlines():
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==(\S+)", line)
        if match:
            current = _norm(match.group(1))
            pins[current] = (match.group(2), [])
        elif "--hash=sha256:" in line and current:
            pins[current][1].append(line.split()[0])
    return {name: (version, tuple(hashes)) for name, (version, hashes) in pins.items()}


def test_runtime_lock_has_no_dev_only_package() -> None:
    runtime = _pins(RUNTIME)
    assert runtime
    assert not DEV_ONLY & set(runtime), sorted(DEV_ONLY & set(runtime))


def test_runtime_lock_has_no_dev_extra_package() -> None:
    extras = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"][
        "optional-dependencies"
    ]
    declared = {_norm(re.split(r"[<>=!~\[ ;]", spec, maxsplit=1)[0]) for spec in extras["dev"]}
    assert not declared & set(_pins(RUNTIME)), sorted(declared & set(_pins(RUNTIME)))


def test_runtime_lock_is_hash_locked_and_matches_the_dev_lock() -> None:
    runtime, dev = _pins(RUNTIME), _pins(DEV)
    assert all(hashes for _, hashes in runtime.values())
    # Same versions and hashes as the dev lock: the split removes packages, never re-resolves.
    assert {name: pin for name, pin in dev.items() if name in runtime} == runtime
    # The dev lock is the runtime lock plus exactly the dev-only packages.
    assert set(dev) - set(runtime) == DEV_ONLY
    assert "--all-extras" in DEV.read_text().splitlines()[1]
    assert "--all-extras" not in RUNTIME.read_text().splitlines()[1]


def test_runtime_lock_covers_the_declared_runtime_dependencies() -> None:
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    names = {_norm(re.split(r"[<>=!~\[ ;]", spec, maxsplit=1)[0]) for spec in deps}
    assert names <= set(_pins(RUNTIME))


def test_image_and_formula_install_the_runtime_lock_only() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "requirements-runtime.lock" in dockerfile
    assert not re.search(r"requirements\.lock", dockerfile)
    formula = (ROOT / "packaging/homebrew/unifi-fabric-mcp-server.rb").read_text()
    formula_names = {_norm(n) for n in re.findall(r"resource \"([^\"]+)\" do", formula)}
    assert formula_names == set(_pins(RUNTIME))
    assert not DEV_ONLY & formula_names
