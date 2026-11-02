#!/usr/bin/env python3
"""Make README.md's relative links absolute for the PyPI long description.

PyPI renders the long description outside the repository, so a relative link
(``docs/TOOLS.md``) or image (the banner) does not resolve there. This rewrites every
relative Markdown link and image target to an absolute URL on the repository's main
branch (pages under ``/blob/main/``, images from ``raw.githubusercontent.com``), taking
the repository from ``[project.urls] Repository`` in pyproject.toml. Absolute URLs,
in-page anchors and ``mailto:`` links are left alone.

publish-pypi.yml (and the public-artifact dry run) run it on the build workspace right
before ``python -m build``; the repository's README itself keeps its relative links.

Usage:
  python scripts/pypi_readme.py [README.md]          rewrite the file in place
  python scripts/pypi_readme.py --check [README.md]  exit 1 if a relative target remains
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# ``[label](target)`` and ``![alt](target)``; the label may hold one nested image (a
# linked badge), and the target ends at whitespace (an optional "title") or ")".
LINK = re.compile(r"(!?)\[((?:[^\[\]]|\[[^\[\]]*\])*)\]\(([^)\s]+)((?:\s+\"[^\"]*\")?)\)")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")


def repository_url(pyproject: Path = ROOT / "pyproject.toml") -> str:
    urls = tomllib.loads(pyproject.read_text())["project"]["urls"]
    url = urls["Repository"].rstrip("/")
    if not re.fullmatch(r"https://github\.com/[^/\s]+/[^/\s]+", url):
        raise SystemExit(f"[project.urls] Repository is not a GitHub repository URL: {url!r}")
    return url


def is_relative(target: str) -> bool:
    return not (_SCHEME.match(target) or target.startswith(("#", "//")))


def absolutize(text: str, repo: str) -> str:
    owner_repo = repo.removeprefix("https://github.com/")
    blob = f"{repo}/blob/main/"
    raw = f"https://raw.githubusercontent.com/{owner_repo}/main/"

    def fix(target: str, image: bool) -> str:
        if not is_relative(target):
            return target
        return (raw if image else blob) + target.removeprefix("./").lstrip("/")

    def sub(m: re.Match[str]) -> str:
        bang, label, target, title = m.groups()
        label = LINK.sub(sub, label)  # a linked badge: the image inside the label
        return f"{bang}[{label}]({fix(target, bool(bang))}{title})"

    return LINK.sub(sub, text)


def relative_targets(text: str) -> list[str]:
    found: list[str] = []

    def walk(s: str) -> None:
        for m in LINK.finditer(s):
            walk(m.group(2))
            if is_relative(m.group(3)):
                found.append(m.group(3))

    walk(text)
    return found


def main(argv: list[str]) -> int:
    check = "--check" in argv
    args = [a for a in argv if a != "--check"]
    path = Path(args[0]) if args else ROOT / "README.md"
    text = path.read_text(encoding="utf-8")
    if check:
        left = relative_targets(text)
        for target in left:
            print(f"relative link target left in {path}: {target}")
        return 1 if left else 0
    path.write_text(absolutize(text, repository_url()), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
