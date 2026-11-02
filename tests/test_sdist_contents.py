"""Test sdist contents and file list assertions."""

from __future__ import annotations

import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_sdist_file_list(tmp_path):
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()

    cmd = [sys.executable, "-m", "hatchling", "build", "-t", "sdist", "-d", str(dist_dir)]
    proc = subprocess.run(  # noqa: S603 - fixed command args
        cmd, cwd=ROOT, capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, f"hatch build failed: {proc.stderr}"

    archives = list(dist_dir.glob("*.tar.gz"))
    assert len(archives) == 1, f"Expected 1 sdist archive, found: {archives}"

    with tarfile.open(archives[0], "r:gz") as tar:
        names = tar.getnames()

    # Strip top-level directory (e.g. unifi_fabric_mcp_server-0.7.0/)
    rel_names = {name.split("/", 1)[1] for name in names if "/" in name}

    assert "pyproject.toml" in rel_names
    assert "README.md" in rel_names
    assert "LICENSE" in rel_names
    assert "PKG-INFO" in rel_names
    assert any(name.startswith("src/unifi_fabric/") for name in rel_names)

    # Assert excluded files are NOT in the sdist
    assert not any(name.startswith("tests/") for name in rel_names)
    assert not any(name.startswith("docs/") for name in rel_names)
    assert not any(name.startswith(".github/") for name in rel_names)
    assert not any(name.startswith("scripts/") for name in rel_names)
    assert ".gitleaksignore" not in rel_names
    assert "Dockerfile" not in rel_names
    # Hatchling automatically includes license/notice and VCS exclusion metadata.
    assert all(
        name in {"pyproject.toml", "README.md", "LICENSE", "NOTICE", ".gitignore", "PKG-INFO"}
        or name.startswith("src/unifi_fabric/")
        for name in rel_names
    )
    install_dir = tmp_path / "installed"
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--no-index",
            "--no-build-isolation",
            "--target",
            str(install_dir),
            str(archives[0]),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert (install_dir / "unifi_fabric" / "entrypoint.py").is_file()
