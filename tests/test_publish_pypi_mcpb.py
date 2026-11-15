"""The public PyPI build packs the Claude Desktop bundle and attaches it to the release."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-pypi.yml"
PUBLIC_REPO = "swkstudios/unifi-fabric-mcp-server"


def _jobs() -> dict[str, Any]:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def _step(job: str, needle: str) -> dict[str, Any]:
    (step,) = [s for s in _jobs()[job]["steps"] if needle in s.get("run", "") + s.get("uses", "")]
    return step


def test_build_packs_and_validates_with_a_pinned_mcpb():
    step = _step("build", "npm ci --ignore-scripts")
    assert re.fullmatch(r"@anthropic-ai/mcpb@\d+\.\d+\.\d+", step["env"]["MCPB"])
    manifest = json.loads((ROOT / "tools/mcpb/package.json").read_text())
    lock = json.loads((ROOT / "tools/mcpb/package-lock.json").read_text())
    assert step["env"]["MCPB"] == (
        "@anthropic-ai/mcpb@" + manifest["dependencies"]["@anthropic-ai/mcpb"]
    )
    assert lock["packages"][""]["dependencies"] == manifest["dependencies"]
    assert all("integrity" in value for key, value in lock["packages"].items() if key)
    run = step["run"]
    assert "tools/mcpb/node_modules/.bin/mcpb validate plugins/claude-desktop/manifest.json" in run
    assert (
        "tools/mcpb/node_modules/.bin/mcpb pack plugins/claude-desktop "
        '"mcpb/unifi-fabric-${VERSION}.mcpb"' in run
    )
    assert "dist/" not in run  # never next to the PyPI artifacts
    node = _step("build", "actions/setup-node@")
    assert re.fullmatch(r"actions/setup-node@[0-9a-f]{40}", node["uses"])


def test_release_asset_job_is_public_only_and_idempotent():
    job = _jobs()["release-asset"]
    guard = " ".join(job["if"].split())
    assert guard == " ".join(_jobs()["upload"]["if"].split())  # same public/tag guard
    assert f"github.repository == '{PUBLIC_REPO}'" in guard
    assert job["needs"] == "build"
    assert job["permissions"] == {"contents": "write"}
    run = _step("release-asset", "gh release upload")["run"]
    assert '"mcpb/unifi-fabric-${RELEASE_TAG#v}.mcpb"' in run
    assert "--clobber" in run and "cmp " in run
    assert "id-token" not in json.dumps(job)
    assert "secrets." not in WORKFLOW.read_text()


# What the bundle carries: the manifest, its README and the twelve icons the manifest names.
BUNDLE_FILES = [
    "README.md",
    "icon-128.png",
    "icon-16.png",
    "icon-256.png",
    "icon-32.png",
    "icon-64.png",
    "icon-light-128.png",
    "icon-light-16.png",
    "icon-light-256.png",
    "icon-light-32.png",
    "icon-light-64.png",
    "icon-light.png",
    "icon.png",
    "manifest.json",
]


def test_the_bundle_packs_exactly_the_manifest_readme_and_icons(tmp_path):
    """Offline stand-in for the pack step: the folder holds only what the bundle ships."""
    folder = ROOT / "plugins" / "claude-desktop"
    assert sorted(p.name for p in folder.iterdir()) == BUNDLE_FILES
    manifest = json.loads((folder / "manifest.json").read_text())
    assert manifest["name"] == "unifi-fabric"
    bundle = tmp_path / "b.mcpb"
    with zipfile.ZipFile(bundle, "w") as out:
        for name in BUNDLE_FILES:
            out.write(folder / name, name)
    script = _step("build", "npm ci --ignore-scripts")["run"]
    check = script.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    check = "\n".join(line.removeprefix("          ") for line in check.splitlines())
    subprocess.run(  # noqa: S603 - in-repo check script, temp file
        [sys.executable, "-c", check, str(bundle)], cwd=ROOT, check=True
    )


def test_packed_bundle_is_scanned_before_upload():
    job = _jobs()["build"]
    steps = job["steps"]
    scan = next(
        i
        for i, step in enumerate(steps)
        if step.get("name") == "Scan the packed Claude Desktop bundle for secrets"
    )
    upload = next(i for i, step in enumerate(steps) if step.get("with", {}).get("name") == "mcpb")
    assert scan < upload
    run = steps[scan]["run"]
    assert "python -m zipfile -e" in run
    assert 'gitleaks" detect --no-git' in run
    assert "--redact --exit-code 1" in run
    # The pinned, checksum-verified binary (.github/gitleaks.pin) in the scan directory.
    assert 'bash scripts/install_gitleaks.sh --dest "${scan_dir}"' in run
    assert run.index("install_gitleaks.sh") < run.index('gitleaks" detect')
    assert "GITLEAKS_VERSION" not in str(job.get("env", {}))


def test_bundle_supports_macos_and_windows():
    manifest = json.loads((ROOT / "plugins/claude-desktop/manifest.json").read_text())
    assert set(manifest["compatibility"]["platforms"]) == {"darwin", "win32"}
    assert manifest["server"]["mcp_config"]["command"] == "uvx"


# Lowest fixed release of every advisory that has hit the bundle toolchain lock
# (tools/mcpb/package-lock.json). The pinned packer still asks for older ranges, so
# tools/mcpb/package.json overrides them; this keeps a lock refresh from regressing.
_MCPB_LOCK_FLOORS = {
    "zod": (4, 6, 6),  # GHSA-mrhx-c7xc-m3w5
    "tmp": (0, 2, 6),  # GHSA-ph9p-34f9-6g65, GHSA-52f5-9888-hmc6
}


def _semver(text: str) -> tuple[int, ...]:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", text)
    assert match, text
    return tuple(int(part) for part in match.groups())


def test_mcpb_toolchain_lock_has_no_known_vulnerable_versions():
    manifest = json.loads((ROOT / "tools/mcpb/package.json").read_text())
    lock = json.loads((ROOT / "tools/mcpb/package-lock.json").read_text())
    locked = {
        key.rsplit("node_modules/", 1)[1]: value["version"]
        for key, value in lock["packages"].items()
        if key
    }
    for name, floor in _MCPB_LOCK_FLOORS.items():
        assert name in locked, name
        assert _semver(locked[name]) >= floor, (name, locked[name])
        # Exact override, so npm ci cannot resolve anything but the locked fixed release.
        assert re.fullmatch(r"\d+\.\d+\.\d+", manifest["overrides"][name]), name
        assert manifest["overrides"][name] == locked[name], name
    # Every copy of a floored package in the lock (nested ones too) is the fixed one.
    for key, value in lock["packages"].items():
        name = key.rsplit("node_modules/", 1)[-1]
        if name in _MCPB_LOCK_FLOORS:
            assert _semver(value["version"]) >= _MCPB_LOCK_FLOORS[name], (key, value["version"])


# Dependabot alerts on tools/mcpb/package-lock.json: the package, the first patched
# release GitHub reports, and the severity. All three alerts read "fixed" once the lock held the
# patched versions; this pins them so a lock refresh cannot take a patched package back.
MCPB_ALERT_FLOORS = {
    "tmp": ((0, 2, 6), "alerts 2 (low) and 3 (high)"),
    "zod": ((4, 6, 6), "alert 4 (high)"),
}


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("-")[0].split("."))


def test_mcpb_lock_holds_the_patched_dependency_versions():
    manifest = json.loads((ROOT / "tools/mcpb/package.json").read_text())
    lock = json.loads((ROOT / "tools/mcpb/package-lock.json").read_text())
    for name, (floor, alerts) in MCPB_ALERT_FLOORS.items():
        # The override forces the patched release for every dependent, whatever the
        # @anthropic-ai/mcpb range asks for ...
        assert _version(manifest["overrides"][name]) >= floor, (name, alerts)
        # ... and no copy of the package in the lock is older than the first patched release.
        copies = {
            path: entry["version"]
            for path, entry in lock["packages"].items()
            if path == f"node_modules/{name}" or path.endswith(f"/node_modules/{name}")
        }
        assert copies, name
        assert all(_version(v) >= floor for v in copies.values()), (name, alerts, copies)


def test_the_claude_desktop_manifest_stays_the_second_distribution():
    # Decision (keep): the MCPB manifest is shipped and validated by the pinned mcpb in the
    # public PyPI build, so the alerts above are fixed rather than the manifest dropped.
    assert (ROOT / "plugins/claude-desktop/manifest.json").is_file()
    assert "mcpb pack plugins/claude-desktop" in _step("build", "npm ci --ignore-scripts")["run"]


def _bundle_check() -> str:
    script = _step("build", "npm ci --ignore-scripts")["run"]
    check = script.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    return "\n".join(line.removeprefix("          ") for line in check.splitlines())


def _packed(tmp_path: Path, names: list[str]) -> Path:
    folder = ROOT / "plugins" / "claude-desktop"
    bundle = tmp_path / "c.mcpb"
    with zipfile.ZipFile(bundle, "w") as out:
        for name in names:
            out.write(folder / name, name)
    return bundle


def test_the_bundle_check_fails_closed_on_a_missing_or_extra_file(tmp_path):
    """The workflow's expected list is the exact list: one icon short, or one file over, fails."""
    check = _bundle_check()
    for missing in BUNDLE_FILES:
        if missing == "manifest.json":
            continue  # the check reads the manifest first; a bundle without it fails earlier
        bundle = _packed(tmp_path, [n for n in BUNDLE_FILES if n != missing])
        done = subprocess.run(  # noqa: S603 - in-repo check script, temp file
            [sys.executable, "-c", check, str(bundle)], cwd=ROOT, capture_output=True
        )
        assert done.returncode != 0, f"a bundle without {missing} passed the check"
    extra = _packed(tmp_path, BUNDLE_FILES)
    with zipfile.ZipFile(extra, "a") as out:
        out.writestr("icon-48.png", b"x")
    done = subprocess.run(  # noqa: S603 - in-repo check script, temp file
        [sys.executable, "-c", check, str(extra)], cwd=ROOT, capture_output=True
    )
    assert done.returncode != 0, "a bundle with an extra file passed the check"


def test_the_bundle_check_fails_closed_on_a_changed_manifest(tmp_path):
    """The packed manifest must equal the one in the tree: a different manifest fails."""
    check = _bundle_check()
    folder = ROOT / "plugins" / "claude-desktop"
    ok = _packed(tmp_path, BUNDLE_FILES)
    done = subprocess.run(  # noqa: S603 - in-repo check script, temp file
        [sys.executable, "-c", check, str(ok)], cwd=ROOT, capture_output=True
    )
    assert done.returncode == 0, done.stderr  # control: the right bundle passes
    changed = json.loads((folder / "manifest.json").read_text())
    changed["version"] = "9.9.9"
    bundle = tmp_path / "d.mcpb"
    with zipfile.ZipFile(bundle, "w") as out:
        for name in BUNDLE_FILES:
            if name == "manifest.json":
                out.writestr(name, json.dumps(changed))
            else:
                out.write(folder / name, name)
    done = subprocess.run(  # noqa: S603 - in-repo check script, temp file
        [sys.executable, "-c", check, str(bundle)], cwd=ROOT, capture_output=True
    )
    assert done.returncode != 0, "a bundle with a changed manifest passed the check"
