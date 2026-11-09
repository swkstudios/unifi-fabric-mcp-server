"""Each CI tool pin has one source.

- gitleaks: ``.github/gitleaks.pin`` (version and archive sha256), read only by
  ``scripts/install_gitleaks.sh``; every workflow that scans installs through it.
- ruff: ``requirements.lock``; ``scripts/extract_ruff_requirements.py`` generates the
  hash-pinned ruff-only requirement the lint-only jobs install.
- Python: ``.python-version``; every ``actions/setup-python`` step reads it and every
  cache key takes the interpreter from that step's output.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PIN = ROOT / ".github" / "gitleaks.pin"
INSTALL_GITLEAKS = ROOT / "scripts" / "install_gitleaks.sh"
EXTRACTOR = ROOT / "scripts" / "extract_ruff_requirements.py"
PYTHON_VERSION_FILE = ROOT / ".python-version"
BASH = shutil.which("bash") or "/bin/bash"

_spec = importlib.util.spec_from_file_location("extract_ruff_requirements", EXTRACTOR)
assert _spec and _spec.loader
extractor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(extractor)


def _workflows():
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        yield path.name, path.read_text(), yaml.safe_load(path.read_text()) or {}


def _steps():
    for name, _, workflow in _workflows():
        for job_name, job in (workflow.get("jobs") or {}).items():
            for index, step in enumerate(job.get("steps") or []):
                yield name, job_name, job, index, step


def _pin():
    values = {}
    for line in PIN.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


# --- gitleaks ---------------------------------------------------------------------------


def test_gitleaks_pin_single_source():
    pin = _pin()
    assert set(pin) == {"version", "sha256"}
    assert re.fullmatch(r"\d+\.\d+\.\d+", pin["version"])
    assert re.fullmatch(r"[0-9a-f]{64}", pin["sha256"])
    # No workflow carries its own copy of the pin or of the download.
    for name, text, _ in _workflows():
        for copy in (pin["version"], pin["sha256"], "GITLEAKS_VERSION", "GITLEAKS_SHA256"):
            assert copy not in text, (name, copy)
        assert "gitleaks/releases/download" not in text, name
    # The installer is the one reader of the pin and the one download in the tree.
    script = INSTALL_GITLEAKS.read_text()
    assert '"$root/.github/gitleaks.pin"' in script
    assert "sha256sum -c -" in script
    assert script.index("sha256sum -c -") < script.index("tar -xzf")
    downloaders = {
        path.relative_to(ROOT).as_posix()
        for directory in ("scripts", ".github")
        for path in (ROOT / directory).rglob("*")
        if path.is_file() and "gitleaks/releases/download" in path.read_text(errors="ignore")
    }
    assert downloaders == {"scripts/install_gitleaks.sh"}
    # Every job that runs gitleaks installs it through the script first.
    scans = 0
    for name, job_name, job, index, step in _steps():
        run = str(step.get("run", ""))
        if not re.search(r"(^|[\s/\"])gitleaks\"? detect", run, re.M):
            continue
        scans += 1
        earlier = [str(s.get("run", "")) for s in job["steps"][: index + 1]]
        assert any("scripts/install_gitleaks.sh" in r for r in earlier), (name, job_name)
    assert scans >= 2  # ci.yml gitleaks job and publish-pypi bundle scan ship publicly.
    callers = {
        (name, job_name)
        for name, job_name, _, _, step in _steps()
        if "scripts/install_gitleaks.sh" in str(step.get("run", ""))
    }
    assert {("ci.yml", "gitleaks"), ("publish-pypi.yml", "build")} <= callers


def _fake_release(tmp_path, *, sha256=None):
    """A copy of the installer and a pin over a fake release archive served by a fake curl."""
    tree = tmp_path / "tree"
    (tree / "scripts").mkdir(parents=True)
    (tree / ".github").mkdir()
    shutil.copy2(INSTALL_GITLEAKS, tree / "scripts" / "install_gitleaks.sh")
    binary = b'#!/bin/sh\necho fake-gitleaks "$@"\n'
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("gitleaks")
        info.size, info.mode = len(binary), 0o755
        archive.addfile(info, io.BytesIO(binary))
    release = tmp_path / "release.tar.gz"
    release.write_bytes(gzip.compress(buffer.getvalue(), mtime=0))
    digest = sha256 or hashlib.sha256(release.read_bytes()).hexdigest()
    (tree / ".github" / "gitleaks.pin").write_text(f"# test\nversion=9.8.7\nsha256={digest}\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "curl.log"
    curl = bin_dir / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{log}"\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "-o" ]; then out="$2"; shift; fi\n'
        "  shift\n"
        "done\n"
        f'cp "{release}" "$out"\n'
    )
    curl.chmod(0o755)
    env = {**os.environ, "PATH": os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")])}
    return tree, env, log


def test_install_gitleaks_installs_the_pinned_verified_archive(tmp_path):
    assert shutil.which("sha256sum"), "sha256sum is required"
    tree, env, log = _fake_release(tmp_path)
    dest = tmp_path / "dest"
    done = subprocess.run(  # noqa: S603 - fixed shell and copied repository script
        [BASH, str(tree / "scripts" / "install_gitleaks.sh"), "--dest", str(dest)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert "fake-gitleaks version" in done.stdout
    assert (dest / "gitleaks").stat().st_mode & 0o111
    assert (
        "https://github.com/gitleaks/gitleaks/releases/download/v9.8.7/"
        "gitleaks_9.8.7_linux_x64.tar.gz"
    ) in log.read_text()


def test_install_gitleaks_refuses_a_checksum_mismatch_and_a_bad_pin(tmp_path):
    assert shutil.which("sha256sum"), "sha256sum is required"
    tree, env, _ = _fake_release(tmp_path, sha256="0" * 64)
    dest = tmp_path / "dest"
    script = str(tree / "scripts" / "install_gitleaks.sh")
    done = subprocess.run(  # noqa: S603 - fixed shell and copied repository script
        [BASH, script, "--dest", str(dest)], env=env, capture_output=True, text=True, check=False
    )
    assert done.returncode != 0
    assert not (dest / "gitleaks").exists()
    (tree / ".github" / "gitleaks.pin").write_text("version=latest\nsha256=" + "0" * 64 + "\n")
    done = subprocess.run(  # noqa: S603 - fixed shell and copied repository script
        [BASH, script, "--dest", str(dest)], env=env, capture_output=True, text=True, check=False
    )
    assert done.returncode == 1 and "version" in done.stderr
    done = subprocess.run(  # noqa: S603 - fixed shell and copied repository script
        [BASH, script, "--dest"], env=env, capture_output=True, text=True, check=False
    )
    assert done.returncode == 2 and "usage" in done.stderr


# --- ruff -------------------------------------------------------------------------------


def test_ruff_subset_matches_lock(tmp_path):
    lock = (ROOT / "requirements.lock").read_text()
    # Independent read of the lock's ruff entry: its version and every hash.
    entry = re.search(r"(?m)^ruff==(\S+) \\\n((?:[ \t]+--hash=sha256:[0-9a-f]{64}.*\n)+)", lock)
    assert entry
    locked_hashes = re.findall(r"sha256:([0-9a-f]{64})", entry.group(2))
    out = tmp_path / "ruff-requirements.txt"
    done = subprocess.run(  # noqa: S603 - this interpreter and the repository script
        [
            sys.executable,
            str(EXTRACTOR),
            "--lock",
            str(ROOT / "requirements.lock"),
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    generated = out.read_text()
    assert generated.splitlines()[0] == f"ruff=={entry.group(1)} \\"
    assert re.findall(r"sha256:([0-9a-f]{64})", generated) == locked_hashes
    assert len(generated.splitlines()) == 1 + len(locked_hashes)
    # Only ruff: no other requirement leaks into the subset.
    assert re.findall(r"(?m)^(\S+)==", generated) == ["ruff"]
    # Every workflow that installs ruff alone installs the generated subset, with hashes.
    installers = set()
    for name, job_name, _, _, step in _steps():
        run = str(step.get("run", ""))
        assert "ruff==" not in run, (name, job_name)
        if str(step.get("name", "")).startswith("Install ruff (hash-pinned"):
            assert "extract_ruff_requirements.py" in run, (name, job_name)
            installers.add((name, job_name))
            assert "--lock requirements.lock" in run
            assert "pip install --quiet --require-hashes" in run or (
                "pip install --require-hashes" in run
            )
            assert "--only-binary :all: --no-deps" in run
    assert ("ci.yml", "lint") in installers


@pytest.mark.parametrize(
    ("lock", "message"),
    [
        ("anyio==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n", "found 0"),
        (
            "ruff==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n" * 2 + "ruff==1.1 \\\n"
            "    --hash=sha256:" + "b" * 64 + "\n",
            "found 2",
        ),
        ("ruff==1.0 \\\n    --hash=sha256:" + "a" * 64 + " \\\n", "ends inside"),
        ("ruff==1.0 \\\n    --hash=md5:abc\n", "unexpected line"),
    ],
)
def test_ruff_extractor_rejects_a_lock_without_one_hashed_entry(lock, message):
    with pytest.raises(extractor.LockError, match=message):
        extractor.ruff_requirement(lock)


@pytest.mark.parametrize("extra", ["ruff==1.1", "ruff==1.1 ; python_version >= '3.12'"])
def test_ruff_extractor_rejects_an_unhashed_duplicate(extra):
    lock = "ruff==1.0 " + chr(92) + "\n    --hash=sha256:" + "a" * 64 + "\n" + extra + "\n"
    with pytest.raises(extractor.LockError, match="found 2"):
        extractor.ruff_requirement(lock)


# --- Python -----------------------------------------------------------------------------


def test_python_version_single_source():
    version = PYTHON_VERSION_FILE.read_text()
    assert re.fullmatch(r"3\.\d+\n", version), version
    version = version.strip()
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert f'requires-python = ">={version}"' in pyproject
    assert f'target-version = "py{version.replace(".", "")}"' in pyproject
    seen = 0
    for name, job_name, job, index, step in _steps():
        if not str(step.get("uses", "")).startswith("actions/setup-python@"):
            continue
        seen += 1
        options = step.get("with") or {}
        assert options.get("python-version-file") == ".python-version", (name, job_name)
        assert "python-version" not in options, (name, job_name)
        checkout = [
            i
            for i, s in enumerate(job["steps"][:index])
            if str(s.get("uses", "")).startswith("actions/checkout@")
            and "path" not in (s.get("with") or {})
        ]
        assert checkout, f"{name}:{job_name} reads .python-version before any checkout"
    assert seen, "no setup-python steps found"
    # Cache keys take the interpreter from the job's setup-python output, never a literal.
    for name, text, workflow in _workflows():
        assert not re.search(r"(?m)^\s+key:.*\bpy3\.?\d", text), name
        for job_name, job in (workflow.get("jobs") or {}).items():
            ids = {
                s.get("id")
                for s in job.get("steps") or []
                if str(s.get("uses", "")).startswith("actions/setup-python@")
            }
            for step in job.get("steps") or []:
                key = str((step.get("with") or {}).get("key", ""))
                for used in re.findall(r"steps\.([\w-]+)\.outputs\.python-version", key):
                    assert used in ids, (name, job_name, key)
