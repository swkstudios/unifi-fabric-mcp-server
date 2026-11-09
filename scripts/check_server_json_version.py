#!/usr/bin/env python3
"""Guard: server.json version/identifier must agree with pyproject [project].version.

Asserts four things and exits non-zero (with a clear ::error:: line) on any failure:

  1. server.json ``version`` == pyproject ``[project].version``.
  2. Every PyPI package ``version`` equals that same version.
  3. The OCI package ``identifier`` tag (the part after the final ``:``) equals
     that same version.
  4. The identifier tag carries NO leading ``v`` (``0.7.0``, never ``v0.7.0``).

Background: docker/metadata-action's ``{{version}}`` placeholder strips a leading
``v`` from the git tag, so an image is published as ``:0.7.0``. A ``server.json``
that hard-codes ``:v0.7.0`` would therefore point at an image that never exists.
This check fails the build before such a mismatch can ship.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


def fail(msg: str) -> None:
    print(f"::error::{msg}")
    sys.exit(1)


def version_problems(server: dict, version: str) -> list[str]:
    """Every way ``server`` disagrees with ``version`` (empty when it agrees).

    Shared with scripts/prepare_release.py, which renders server.json from one version
    and re-reads the result through this check.
    """
    problems: list[str] = []
    server_version = server.get("version")
    if server_version != version:
        problems.append(
            f"server.json version {server_version!r} != pyproject [project].version {version!r}."
        )

    packages = server.get("packages") or []
    pypi = [p for p in packages if p.get("registryType") == "pypi"]
    if not pypi:
        problems.append("server.json has no PyPI package entry to validate.")
    for pkg in pypi:
        if pkg.get("version") != version:
            problems.append(
                f"PyPI package {pkg.get('identifier')!r} version {pkg.get('version')!r} "
                f"!= version {version!r}."
            )

    oci = [p for p in packages if p.get("registryType") == "oci"]
    if not oci:
        problems.append("server.json has no OCI package entry to validate.")

    for pkg in oci:
        identifier = pkg.get("identifier", "")
        if ":" not in identifier:
            problems.append(f"OCI identifier {identifier!r} has no ':<tag>' suffix.")
            continue
        tag = identifier.rsplit(":", 1)[1]
        if tag.startswith("v"):
            problems.append(
                f"OCI identifier tag {tag!r} has a leading 'v'. "
                f"docker/metadata-action's {{{{version}}}} strips it — use {version!r}."
            )
        elif tag != version:
            problems.append(
                f"OCI identifier tag {tag!r} != version {version!r} (identifier={identifier!r})."
            )
    return problems


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server-json", default="server.json", type=Path)
    ap.add_argument("--pyproject", default="pyproject.toml", type=Path)
    args = ap.parse_args()

    with args.pyproject.open("rb") as f:
        pyproject_version = tomllib.load(f)["project"]["version"]

    server = json.loads(args.server_json.read_text())
    problems = version_problems(server, pyproject_version)
    if problems:
        fail(problems[0])

    print(
        f"server.json consistent: version=={pyproject_version}, "
        f"PyPI version=={pyproject_version}, OCI tag=={pyproject_version} (no leading 'v'). OK"
    )


if __name__ == "__main__":
    main()
