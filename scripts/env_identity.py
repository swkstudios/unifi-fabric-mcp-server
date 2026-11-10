#!/usr/bin/env python3
"""Identity of the installed Python environment, and its check against requirements.lock.

Standard library only. ``identity()`` is the Python version plus a sha256 over the sorted
``name==version`` lines of every installed distribution (``importlib.metadata``). The shard
reports of ``test-locked`` carry it, and ``scripts/shard_partition.py verify`` fails unless
the shards and the anchor all carry the same value. ``check_lock()`` asserts the installed
set equals the lock pins plus the editable project, so "the same in every shard" also means
"the locked set".

CLI: ``env_identity.py record [--lock FILE] [--out FILE]`` prints (or writes) a JSON record
``{"identity": {...}, "lock_errors": [...]}``; it exits 1 when ``lock_errors`` is not empty.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import sys
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
#: Installers that are in every venv but are not part of the locked set.
TOOLING = frozenset({"pip", "setuptools", "wheel"})
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s\;]+)\s*(;.*?)?\s*(?:\\)?$")


def normalize(name: str) -> str:
    """PEP 503 name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def installed() -> dict[str, str]:
    """Normalised name -> version of every installed distribution."""
    found: dict[str, str] = {}
    for dist in metadata.distributions():
        name = dist.metadata["Name"]
        if name:
            found[normalize(name)] = dist.version
    return found


def digest(dists: Mapping[str, str]) -> str:
    """sha256 over the sorted ``name==version`` lines."""
    lines = sorted(f"{name}=={version}" for name, version in dists.items())
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def identity(dists: Mapping[str, str] | None = None) -> dict[str, object]:
    """``{"python", "dist_sha256", "count"}`` of this environment."""
    dists = installed() if dists is None else dists
    return {
        "python": platform.python_version(),
        "dist_sha256": digest(dists),
        "count": len(dists),
    }


def parse_lock(text: str) -> tuple[dict[str, str], dict[str, str]]:
    """``(required, conditional)`` pins of a requirements.lock. A pin with an environment
    marker is conditional: it must match when installed but need not be installed."""
    required: dict[str, str] = {}
    conditional: dict[str, str] = {}
    for line in text.splitlines():
        match = _PIN.match(line.strip())
        if match:
            target = conditional if match.group(3) else required
            target[normalize(match.group(1))] = match.group(2)
    return required, conditional


def project_name(root: Path = ROOT) -> str:
    return normalize(tomllib.loads((root / "pyproject.toml").read_text())["project"]["name"])


def check_lock(
    dists: Mapping[str, str],
    lock_text: str,
    project: str,
    ignore: Iterable[str] = TOOLING,
) -> list[str]:
    """Differences between the installed set and the lock pins plus the editable project
    (empty means they are equal)."""
    required, conditional = parse_lock(lock_text)
    errors: list[str] = []
    if not required:
        errors.append("the lock file has no pins")
    for name, version in sorted(required.items()):
        if name not in dists:
            errors.append(f"locked {name}=={version} is not installed")
        elif dists[name] != version:
            errors.append(f"{name} is {dists[name]}, the lock pins {version}")
    for name, version in sorted(conditional.items()):
        if name in dists and dists[name] != version:
            errors.append(f"{name} is {dists[name]}, the lock pins {version}")
    if project not in dists:
        errors.append(f"the project {project} is not installed")
    allowed = set(required) | set(conditional) | {project} | {normalize(i) for i in ignore}
    for name in sorted(set(dists) - allowed):
        errors.append(f"{name}=={dists[name]} is installed but not in the lock")
    return errors


def record(lock: Path | None = None, root: Path = ROOT) -> dict[str, object]:
    """The identity of this environment and its lock differences (a report fragment)."""
    lock = lock or root / "requirements.lock"
    dists = installed()
    try:
        errors = check_lock(dists, lock.read_text(), project_name(root))
    except OSError as exc:
        errors = [f"cannot read {lock}: {exc.strerror or exc}"]
    return {"identity": identity(dists), "lock_errors": errors}


def _main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    rec = sub.add_parser("record", help="print the identity record of this environment")
    rec.add_argument("--lock", type=Path, help="requirements.lock (default: the repository one)")
    rec.add_argument("--out", type=Path, help="write the JSON here instead of stdout")
    args = parser.parse_args(argv)
    data = record(args.lock)
    text = json.dumps(data, indent=1)
    if args.out:
        args.out.write_text(text)
    else:
        print(text)
    for error in data["lock_errors"]:  # type: ignore[attr-defined]
        print(f"env identity: {error}", file=sys.stderr)
    return 1 if data["lock_errors"] else 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
