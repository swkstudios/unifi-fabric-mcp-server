#!/usr/bin/env python3
"""Guard: server.json version/identifier must agree with pyproject [project].version.

Asserts three things and exits non-zero (with a clear ::error:: line) on any failure:

  1. server.json ``version`` == pyproject ``[project].version``.
  2. The OCI package ``identifier`` tag (the part after the final ``:``) equals
     that same version.
  3. The identifier tag carries NO leading ``v`` (``0.7.0``, never ``v0.7.0``).

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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server-json", default="server.json", type=Path)
    ap.add_argument("--pyproject", default="pyproject.toml", type=Path)
    args = ap.parse_args()

    with args.pyproject.open("rb") as f:
        pyproject_version = tomllib.load(f)["project"]["version"]

    server = json.loads(args.server_json.read_text())
    server_version = server.get("version")

    if server_version != pyproject_version:
        fail(
            f"server.json version {server_version!r} != "
            f"pyproject [project].version {pyproject_version!r}."
        )

    packages = server.get("packages") or []
    oci = [p for p in packages if p.get("registryType") == "oci"]
    if not oci:
        fail("server.json has no OCI package entry to validate.")

    for pkg in oci:
        identifier = pkg.get("identifier", "")
        if ":" not in identifier:
            fail(f"OCI identifier {identifier!r} has no ':<tag>' suffix.")
        tag = identifier.rsplit(":", 1)[1]
        if tag.startswith("v"):
            fail(
                f"OCI identifier tag {tag!r} has a leading 'v'. "
                f"docker/metadata-action's {{{{version}}}} strips it — use {pyproject_version!r}."
            )
        if tag != pyproject_version:
            fail(
                f"OCI identifier tag {tag!r} != version {pyproject_version!r} "
                f"(identifier={identifier!r})."
            )

    print(
        f"server.json consistent: version=={pyproject_version}, "
        f"OCI tag=={pyproject_version} (no leading 'v'). OK"
    )


if __name__ == "__main__":
    main()
