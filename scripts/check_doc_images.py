#!/usr/bin/env python3
"""Fail obsolete server image tags in public documentation (offline).

Version tags must match project.version. The documented moving latest channel and
content-addressed digests intentionally remain valid; published-tag existence is a
post-publication release check, not a prerequisite for documenting an upcoming tag.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

from check_doc_provenance import ROOT, public_reference_docs

IMAGE = re.compile(r"ghcr\.io/[\w-]+/unifi-fabric-mcp-server:([\w.+-]+)")


def check(root: Path = ROOT) -> list[str]:
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    failures = []
    for path in public_reference_docs(root):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            for match in IMAGE.finditer(line):
                if match.group(1) not in {version, ".".join(version.split(".")[:2]), "latest"}:
                    failures.append(
                        f"{path.relative_to(root)}:{number}: stale image tag "
                        f"{match.group(1)}; expected {version} or latest"
                    )
    return failures


if __name__ == "__main__":
    findings = check()
    print("\n".join(findings) if findings else "image tag currency: PASS")
    sys.exit(bool(findings))
