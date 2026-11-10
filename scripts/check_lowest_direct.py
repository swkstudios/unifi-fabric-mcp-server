#!/usr/bin/env python3
"""Install the built wheel with every direct dependency at its declared floor, then smoke it.

``uv pip install --resolution lowest-direct`` picks the lowest version each direct
requirement allows, so a floor that no longer works (the code needs an API the floor
release lacks) fails here instead of in a user's environment. A local wheel's own
requirements are transitive for the resolver, so they are read from the wheel metadata and
installed as direct requirements first; the wheel itself is then installed with ``--no-deps``.

The smoke is an import of the server module and ``unifi-fabric-mcp --version`` from the
lowest-direct environment. Exit 0 only when the install and both smoke steps pass.
"""

from __future__ import annotations

import argparse
import email.parser
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

SMOKE_IMPORT = "import unifi_fabric.server, unifi_fabric.entrypoint"


def wheel_requirements(wheel: Path) -> list[str]:
    """The wheel's unconditional-extra ``Requires-Dist`` lines, markers kept."""
    with zipfile.ZipFile(wheel) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        metadata = email.parser.Parser().parsestr(archive.read(name).decode())
    return [r for r in metadata.get_all("Requires-Dist", []) if "extra ==" not in r]


def run(argv: list[str]) -> int:
    print("+", " ".join(argv), flush=True)
    return subprocess.run(argv, check=False).returncode  # noqa: S603 - fixed argv list


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--uv", default="uv")
    parser.add_argument("--python", default=sys.executable, help="interpreter for the venv")
    args = parser.parse_args(argv)

    requirements = wheel_requirements(args.wheel)
    if not requirements:
        print("::error::the wheel declares no dependencies; nothing to check", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="lowest-direct-") as work:
        venv = Path(work) / "venv"
        bindir = venv / ("Scripts" if (venv / "Scripts").exists() else "bin")
        req_file = Path(work) / "requirements.in"
        req_file.write_text("\n".join(requirements) + "\n")
        steps = [
            [args.uv, "venv", "--python", args.python, str(venv)],
        ]
        for step in steps:
            if run(step):
                return 1
        python = str((venv / "Scripts" if (venv / "Scripts").exists() else venv / "bin") / "python")
        steps = [
            [
                args.uv,
                "pip",
                "install",
                "--python",
                python,
                "--resolution",
                "lowest-direct",
                "-r",
                str(req_file),
            ],
            [args.uv, "pip", "install", "--python", python, "--no-deps", str(args.wheel)],
            [python, "-c", SMOKE_IMPORT],
            [str(bindir / "unifi-fabric-mcp"), "--version"],
        ]
        for step in steps:
            if run(step):
                print(
                    f"::error::lowest-direct check failed at: {' '.join(step[:4])}", file=sys.stderr
                )
                return 1
    print("lowest-direct install and smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
