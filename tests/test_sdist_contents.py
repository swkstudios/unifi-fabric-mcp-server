"""Test sdist contents and file list assertions."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tarfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_sdist_file_list(tmp_path, monkeypatch):
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
    # uv-created development environments need not contain pip. Bootstrap an
    # isolated installer using the interpreter's bundled pip, with the locked
    # build backend available through the parent import path; no network is used.
    installer_dir = tmp_path / "installer"
    venv.EnvBuilder(with_pip=True).create(installer_dir)
    installer_python = installer_dir / (
        "Scripts/python.exe" if sys.platform == "win32" else "bin/python"
    )
    install_dir = tmp_path / "installed"
    # The full suite can leave a huge sys.path. Pass only locked build-backend
    # directories, and exercise the actual install with an oversized unrelated entry.
    monkeypatch.setattr(sys, "path", [*sys.path, "x" * 140_000])
    backend_dirs = set()
    for module in ("hatchling", "packaging", "pathspec", "pluggy", "tomlkit", "trove_classifiers"):
        spec = importlib.util.find_spec(module)
        assert spec is not None and spec.origin is not None, module
        origin = Path(spec.origin).resolve()
        backend_dirs.add(
            str(origin.parent.parent if origin.name == "__init__.py" else origin.parent)
        )
    installed = subprocess.run(  # noqa: S603
        [
            str(installer_python),
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
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(sorted(backend_dirs))},
    )
    assert installed.returncode == 0, installed.stderr
    assert (install_dir / "unifi_fabric" / "entrypoint.py").is_file()
