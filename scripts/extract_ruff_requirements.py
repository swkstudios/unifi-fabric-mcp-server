"""Write the hash-pinned ruff requirement taken from requirements.lock.

    python scripts/extract_ruff_requirements.py --lock requirements.lock --out <file>

CI's lint job and the public-artifact dry run install ruff alone (no dev environment)
with ``pip install --require-hashes --only-binary :all: --no-deps -r <file>``. The
version and every hash come from the lock's ``ruff==`` entry, so the lock is the single
pin: the lint jobs, the local pre-push check and the dev environment run the same ruff.
Standard library only (it runs before anything is installed).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PACKAGE = "ruff"
_ENTRY = re.compile(rf"^{PACKAGE}==(?P<version>[^\s\;]+)\s*\\$")
_HASH = re.compile(r"^\s+--hash=(?P<hash>sha256:[0-9a-f]{64})\s*(?P<more>\\)?$")


class LockError(ValueError):
    """The lock has no single, fully hashed ruff entry."""


def ruff_requirement(lock: str) -> str:
    """The lock's ruff entry as a requirements file: one version, every hash."""
    lines = lock.splitlines()
    count = sum(line.startswith(f"{PACKAGE}==") for line in lines)
    if count != 1:
        raise LockError(f"expected one hashed {PACKAGE}== entry in the lock, found {count}")
    entries = [(i, m) for i, m in enumerate(map(_ENTRY.match, lines)) if m is not None]
    if len(entries) != 1:
        raise LockError(f"expected one hashed {PACKAGE}== entry in the lock, found {len(entries)}")
    start, match = entries[0]
    hashes: list[str] = []
    for line in lines[start + 1 :]:
        found = _HASH.match(line)
        if found is None:
            raise LockError(f"unexpected line in the {PACKAGE} entry: {line!r}")
        hashes.append(found.group("hash"))
        if not found.group("more"):
            break
    else:
        raise LockError(f"the {PACKAGE} entry ends inside its hash list")
    if len(set(hashes)) != len(hashes):
        raise LockError(f"the {PACKAGE} entry repeats a hash")
    body = " \\\n".join(
        [f"{PACKAGE}=={match.group('version')}", *(f"    --hash={h}" for h in hashes)]
    )
    return body + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--lock", required=True, type=Path, help="requirements.lock")
    parser.add_argument("--out", required=True, type=Path, help="requirements file to write")
    args = parser.parse_args(argv)
    try:
        requirement = ruff_requirement(args.lock.read_text())
    except LockError as error:
        print(f"extract_ruff_requirements: {args.lock}: {error}", file=sys.stderr)
        return 1
    args.out.write_text(requirement)
    return 0


if __name__ == "__main__":
    sys.exit(main())
