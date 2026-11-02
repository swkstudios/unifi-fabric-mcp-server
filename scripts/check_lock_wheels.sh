#!/usr/bin/env bash
# Check that every package in requirements-runtime.lock and requirements-build.lock has
# a CPython 3.12 wheel (or a pure-Python wheel) for linux x86_64 and linux aarch64.
#
# The image is published for linux/amd64 and linux/arm64, and its build installs wheels
# only (pip --only-binary=:all: for the target platform). The accepted platform tags are
# manylinux2014 and manylinux 2.17 through 2.36, the glibc of the image's Debian bookworm
# base. pip downloads each locked file with its locked hash; a package with no matching
# wheel fails the check. Run it from the repository root; it needs network access to PyPI.
set -euo pipefail

PYTHON="${PYTHON:-python3}"
WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK:?}"' EXIT

for arch in x86_64 aarch64; do
  platforms=(--platform "manylinux2014_${arch}")
  for minor in $(seq 17 36); do
    platforms+=(--platform "manylinux_2_${minor}_${arch}")
  done
  for lock in requirements-runtime.lock requirements-build.lock; do
    "$PYTHON" -m pip download --quiet --disable-pip-version-check --require-hashes \
      --only-binary=:all: --no-deps "${platforms[@]}" --python-version 3.12 \
      --implementation cp --abi cp312 -r "$lock" -d "$WORK/$arch"
  done
  echo "linux ${arch}: every package in requirements-runtime.lock and requirements-build.lock has a CPython 3.12 wheel ($(find "$WORK/$arch" -name '*.whl' | wc -l) wheels)"
done
