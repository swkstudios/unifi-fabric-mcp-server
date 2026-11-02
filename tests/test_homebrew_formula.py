"""The Homebrew formula installs exactly the dependency set pinned in requirements-runtime.lock."""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORMULA = ROOT / "packaging" / "homebrew" / "unifi-fabric-mcp-server.rb"
LOCK = ROOT / "requirements-runtime.lock"

_spec = importlib.util.spec_from_file_location(
    "gen_homebrew_resources", ROOT / "scripts" / "gen_homebrew_resources.py"
)
assert _spec and _spec.loader
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

_RESOURCE_RE = re.compile(
    r'resource "(?P<name>[^"]+)" do\s+url "(?P<url>[^"]+)"\s+sha256 "(?P<sha>[0-9a-f]+)"\s+end'
)


def _resources() -> list[re.Match[str]]:
    return list(_RESOURCE_RE.finditer(FORMULA.read_text()))


def _url_version(url: str) -> str:
    match = re.search(r"/[^/]+?-(?P<version>[0-9][^/]*?)\.(?:tar\.gz|zip)\Z", url)
    assert match, url
    return match.group("version")


def test_formula_resources_match_requirements_lock() -> None:
    pins = gen.locked_pins(LOCK.read_text())
    resources = {m["name"]: _url_version(m["url"]) for m in _resources()}
    assert resources == pins


def test_resources_are_pypi_sdists_with_sha256() -> None:
    resources = _resources()
    assert resources
    names = [m["name"] for m in resources]
    assert names == sorted(names)
    assert len(names) == len(set(names))
    for m in resources:
        assert m["url"].startswith("https://files.pythonhosted.org/packages/"), m["name"]
        assert gen.normalize(m["url"].rsplit("/", 1)[1].rsplit("-", 1)[0]) == m["name"]
        assert len(m["sha"]) == 64, m["name"]


def test_key_runtime_pins() -> None:
    resources = {m["name"]: _url_version(m["url"]) for m in _resources()}
    assert resources["fastmcp"] == "4.1.4"
    assert resources["fastmcp-slim"] == "4.1.4"
    assert resources["mcp"] == "2.3.0"
    assert "httpx-sse" not in resources


def test_locked_pins_parses_extras_and_normalizes() -> None:
    text = "fastmcp-slim[client,server]==4.1.0 \\\n    --hash=sha256:ab\njaraco.classes==3.4.0\n"
    assert gen.locked_pins(text) == {"fastmcp-slim": "4.1.0", "jaraco-classes": "3.4.0"}


def _lock_hashes() -> dict[str, set[str]]:
    hashes: dict[str, set[str]] = {}
    current = None
    for line in LOCK.read_text().splitlines():
        match = gen._PIN_RE.match(line)
        if match:
            current = gen.normalize(match.group(1))
            hashes[current] = set()
        for digest in re.findall(r"--hash=sha256:([0-9a-f]{64})", line):
            if current:
                hashes[current].add(digest)
    return hashes


def test_resource_sha256_is_a_locked_artifact_hash() -> None:
    """Each sdist checksum is one of the hashes pip verifies for that pin in the lock."""
    hashes = _lock_hashes()
    bad = [m["name"] for m in _resources() if m["sha"] not in hashes.get(m["name"], set())]
    assert bad == []


def _formula_sdists() -> dict[str, tuple[str, str]]:
    return {m["name"]: (m["url"], m["sha"]) for m in _resources()}


def test_help_does_not_write_or_fetch(tmp_path: Path) -> None:
    before = FORMULA.read_bytes()
    result = subprocess.run(  # noqa: S603 - fixed interpreter and repo script
        [sys.executable, str(ROOT / "scripts" / "gen_homebrew_resources.py"), "--help"],
        capture_output=True,
        text=True,
        check=False,
        # Inherit the environment (the interpreter may need its library path) but
        # route HTTPS to a dead proxy, so any PyPI fetch would fail the run.
        env={
            **os.environ,
            "https_proxy": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
        },
    )
    assert result.returncode == 0
    assert "--check" in result.stdout
    assert FORMULA.read_bytes() == before


def test_check_mode_reports_current_formula_without_writing(monkeypatch, tmp_path, capsys) -> None:
    formula = tmp_path / "f.rb"
    formula.write_text(FORMULA.read_text())
    sdists = _formula_sdists()
    monkeypatch.setattr(gen, "sdist", lambda name, version: sdists[name])
    assert gen.main(["--check", "--formula", str(formula)]) == 0
    assert formula.read_text() == FORMULA.read_text()
    count = len(gen.locked_pins(LOCK.read_text()))
    assert f"{count} resources match" in capsys.readouterr().out


def test_check_mode_diffs_stale_formula_without_writing(monkeypatch, tmp_path, capsys) -> None:
    stale = FORMULA.read_text().replace("fastmcp-4.1.4.tar.gz", "fastmcp-4.0.11.tar.gz", 1)
    assert stale != FORMULA.read_text()
    formula = tmp_path / "f.rb"
    formula.write_text(stale)
    sdists = _formula_sdists()
    monkeypatch.setattr(gen, "sdist", lambda name, version: sdists[name])
    assert gen.main(["--check", "--formula", str(formula)]) == 1
    out = capsys.readouterr().out
    assert "-    url" in out and "fastmcp-4.0.11.tar.gz" in out
    assert "+    url" in out and "fastmcp-4.1.4.tar.gz" in out
    assert formula.read_text() == stale


def test_write_mode_regenerates_stale_formula(monkeypatch, tmp_path) -> None:
    formula = tmp_path / "f.rb"
    formula.write_text(
        FORMULA.read_text().replace("fastmcp-4.1.4.tar.gz", "fastmcp-4.0.11.tar.gz", 1)
    )
    sdists = _formula_sdists()
    monkeypatch.setattr(gen, "sdist", lambda name, version: sdists[name])
    assert gen.main(["--formula", str(formula)]) == 0
    assert formula.read_text() == FORMULA.read_text()


def test_depends_on_has_linuxbrew_build_deps_in_audit_order() -> None:
    """pkgconf (openssl-sys finds OpenSSL via pkg-config) and libyaml are declared,
    build deps first, then runtime deps, each group alphabetical (brew audit order)."""
    deps = re.findall(r'^  depends_on "([^"]+)"(?: => :(\w+))?$', FORMULA.read_text(), re.M)
    assert deps == [
        ("pkgconf", "build"),
        ("rust", "build"),
        ("libyaml", ""),
        ("openssl@3", ""),
        ("python@3.12", ""),
    ]
    names = [n for n, _ in deps]
    assert names.index("libyaml") < names.index("python@3.12")
    assert names.index("pkgconf") < names.index("python@3.12")


def test_depends_on_block_is_generated(monkeypatch, tmp_path) -> None:
    """A hand-edited depends_on block is restored by regeneration (and flagged by --check)."""
    formula = tmp_path / "f.rb"
    formula.write_text(FORMULA.read_text().replace('  depends_on "pkgconf" => :build\n', "", 1))
    sdists = _formula_sdists()
    monkeypatch.setattr(gen, "sdist", lambda name, version: sdists[name])
    assert gen.main(["--check", "--formula", str(formula)]) == 1
    assert gen.main(["--formula", str(formula)]) == 0
    assert formula.read_text() == FORMULA.read_text()
