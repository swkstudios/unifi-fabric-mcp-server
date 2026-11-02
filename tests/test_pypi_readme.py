"""scripts/pypi_readme.py: the PyPI long description has no relative link or image."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("pypi_readme", ROOT / "scripts" / "pypi_readme.py")
assert _SPEC and _SPEC.loader
pypi_readme = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(pypi_readme)

REPO = "https://github.com/example/project"


def test_relative_links_and_images_become_absolute_on_main():
    text = (
        "![Banner](docs/banner.png)\n"
        'See [`docs/TOOLS.md`](docs/TOOLS.md) and [policy](.github/SECURITY.md "t").\n'
        "[![CI](https://ci.example/badge.svg)](https://ci.example/run)\n"
        "[up](#configuration) [mail](mailto:a@example.com) [x](./LICENSE)\n"
    )
    out = pypi_readme.absolutize(text, REPO)
    assert (
        "![Banner](https://raw.githubusercontent.com/example/project/main/docs/banner.png)" in out
    )
    assert f"[`docs/TOOLS.md`]({REPO}/blob/main/docs/TOOLS.md)" in out
    assert f'[policy]({REPO}/blob/main/.github/SECURITY.md "t")' in out
    assert "[![CI](https://ci.example/badge.svg)](https://ci.example/run)" in out
    assert "[up](#configuration)" in out and "[mail](mailto:a@example.com)" in out
    assert f"[x]({REPO}/blob/main/LICENSE)" in out
    assert pypi_readme.relative_targets(out) == []
    assert pypi_readme.relative_targets(text) == [
        "docs/banner.png",
        "docs/TOOLS.md",
        ".github/SECURITY.md",
        "./LICENSE",
    ]


def test_the_readme_has_no_relative_target_after_the_rewrite():
    readme = (ROOT / "README.md").read_text()
    assert pypi_readme.relative_targets(readme), "README has no relative link to rewrite"
    out = pypi_readme.absolutize(readme, pypi_readme.repository_url())
    assert pypi_readme.relative_targets(out) == []
    assert out.startswith("![UniFi Fabric MCP Server](https://raw.githubusercontent.com/")
