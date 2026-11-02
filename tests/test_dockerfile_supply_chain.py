"""The image build is reproducible, needs no emulation, and the runtime has no installer.

Security review F8: ``pip install --no-deps .`` fetched ``hatchling`` unpinned and
unhashed through build isolation, and the runtime image kept the base image's pip (with
known CVEs). The Dockerfile builds the wheel in a builder stage with a hash-pinned
hatchling (``requirements-build.lock``) and removes pip from the runtime filesystem.

The image is published for linux/amd64 and linux/arm64. Every RUN step is in the builder
stage, which runs on the build host's platform (``$BUILDPLATFORM``) and installs the
target platform's locked wheels, and the final stage only copies the assembled runtime
filesystem. Either platform therefore builds on any host without QEMU.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "Dockerfile").read_text()
BUILD_LOCK = (ROOT / "requirements-build.lock").read_text()


def _stages() -> dict[str, str]:
    """Stage name (``final`` for the unnamed last stage) -> its instructions."""
    stages = {}
    for body in re.split(r"^FROM ", DOCKERFILE, flags=re.MULTILINE)[1:]:
        header = body.splitlines()[0]
        match = re.search(r" AS (\S+)$", header)
        stages[match.group(1) if match else "final"] = body
    return stages


def _instructions(stage: str) -> list[str]:
    return [line.split()[0] for line in stage.splitlines()[1:] if re.match(r"^[A-Z]+\s", line)]


def _requirements(text: str) -> dict[str, list[str]]:
    """``name==version`` -> its hashes, for every requirement of a pip-compile lock."""
    out: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+==[^ ]+) \\$", line)
        if match:
            current = match.group(1)
            out[current] = []
        elif current and (h := re.search(r"--hash=sha256:([0-9a-f]{64})", line)):
            out[current].append(h.group(1))
    return out


def test_stages_and_pinned_base():
    stages = _stages()
    assert list(stages) == ["base", "builder", "final"]
    assert stages["base"].startswith("${PYTHON_IMAGE} AS base")
    assert stages["builder"].startswith("--platform=$BUILDPLATFORM ${PYTHON_IMAGE} AS builder")
    assert stages["final"].startswith("scratch")
    assert re.search(r"^ARG PYTHON_IMAGE=python:[^@\s]+@sha256:[0-9a-f]{64}$", DOCKERFILE, re.M)


def test_only_the_build_platform_stage_runs_commands():
    """No RUN outside the builder: a cross-platform build needs no emulation."""
    stages = _stages()
    assert "RUN" in _instructions(stages["builder"])
    assert "RUN" not in _instructions(stages["base"])
    assert "RUN" not in _instructions(stages["final"])
    assert re.search(r"^COPY --from=base / /rootfs/$", stages["builder"], re.M)
    assert re.search(r"^COPY --from=builder /rootfs/ /$", stages["final"], re.M)


def test_target_platform_wheels_only():
    builder = _stages()["builder"]
    assert "ARG TARGETARCH" in builder
    assert "amd64) WHEEL_ARCH=x86_64" in builder and "arm64) WHEEL_ARCH=aarch64" in builder
    for flag in (
        "--only-binary=:all:",
        "--python-version 3.12",
        "--implementation cp",
        "--abi cp312",
        "--target",
    ):
        assert flag in builder, flag
    assert "manylinux_2_${minor}_${WHEEL_ARCH}" in builder and "$(seq 17 36)" in builder


def test_hatchling_is_pinned_with_hashes_and_build_isolation_is_off():
    reqs = _requirements(BUILD_LOCK)
    assert any(name.startswith("hatchling==") for name in reqs)
    assert reqs and all(hashes for hashes in reqs.values())
    builder = _stages()["builder"]
    assert "--require-hashes -r requirements-build.lock" in builder
    assert "--require-hashes --no-deps --only-binary=:all:" in builder
    assert "-r requirements-runtime.lock" in builder
    assert "requirements.lock" not in builder.replace("requirements-runtime.lock", "")
    assert "--no-build-isolation" in builder
    assert "venv --without-pip" in builder


def test_pyproject_backend_is_the_locked_one():
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert 'build-backend = "hatchling.build"' in pyproject


def test_dev_sdist_backend_matches_build_lock():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    build = _requirements(BUILD_LOCK)
    dev_lock = _requirements((ROOT / "requirements.lock").read_text())
    backend = next(name for name in build if name.startswith("hatchling=="))
    assert backend in project["project"]["optional-dependencies"]["dev"]
    assert set(dev_lock[backend]) == set(build[backend])


def test_runtime_filesystem_has_no_pip():
    builder = _stages()["builder"]
    for removed in (
        "/rootfs/usr/local/lib/python3.12/site-packages/pip ",
        "/rootfs/usr/local/lib/python3.12/site-packages/pip-*.dist-info",
        "/rootfs/usr/local/bin/pip /rootfs/usr/local/bin/pip3 /rootfs/usr/local/bin/pip3.12",
    ):
        assert removed in builder, removed
    assert "cp -a /venv /rootfs/venv" in builder
    assert not re.search(r"\bpip (install|wheel)\b", _stages()["final"])


def test_runtime_stays_non_root_with_tini():
    builder, final = _stages()["builder"], _stages()["final"]
    assert 'apt-get download "tini:$TARGETARCH"' in builder
    assert "mcp:x:10001:10001::/nonexistent:/sbin/nologin" in builder
    assert re.search(r"^USER mcp$", final, re.M)
    assert 'ENTRYPOINT ["/usr/bin/tini", "--", "unifi-fabric-mcp"]' in final


def test_healthcheck_uses_configured_fastmcp_port(monkeypatch):
    import ast
    import socket

    line = next(line for line in DOCKERFILE.splitlines() if "socket.create_connection" in line)
    command = line.split('python3 -c "', 1)[1].split('"', 1)[0]
    targets = []

    class Connection:
        def close(self):
            pass

    monkeypatch.setenv("FASTMCP_PORT", "4567")
    monkeypatch.setattr(
        socket, "create_connection", lambda target: targets.append(target) or Connection()
    )
    exec(compile(ast.parse(command), "<healthcheck>", "exec"), {})  # noqa: S102
    assert targets == [("localhost", 4567)]
