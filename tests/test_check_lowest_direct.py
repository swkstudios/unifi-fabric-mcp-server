"""scripts/check_lowest_direct.py: the lowest-direct install check."""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_lowest_direct as cld  # noqa: E402

METADATA = (
    "Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n"
    "Requires-Dist: alpha>=1.2\n"
    'Requires-Dist: beta>=2,<3; python_version >= "3.10"\n'
    'Requires-Dist: gamma>=1; extra == "dev"\n'
)


def _wheel(tmp_path: Path, metadata: str = METADATA) -> Path:
    path = tmp_path / "demo-1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("demo-1.0.dist-info/METADATA", metadata)
    return path


def _record(monkeypatch, fail_on: str | None = None) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake(argv: list[str]) -> int:
        calls.append(argv)
        return 1 if fail_on and fail_on in " ".join(argv) else 0

    monkeypatch.setattr(cld, "run", fake)
    return calls


def test_requirements_are_the_unconditional_dependencies(tmp_path):
    assert cld.wheel_requirements(_wheel(tmp_path)) == [
        "alpha>=1.2",
        'beta>=2,<3; python_version >= "3.10"',
    ]


def test_installs_direct_requirements_lowest_then_wheel_then_smokes(tmp_path, monkeypatch):
    wheel = _wheel(tmp_path)
    calls = _record(monkeypatch)
    assert cld.main(["--wheel", str(wheel), "--uv", "UV"]) == 0
    flat = [" ".join(c) for c in calls]
    assert flat[0].startswith("UV venv ")
    assert "--resolution lowest-direct -r " in flat[1]
    assert "--no-deps" in flat[2] and flat[2].endswith(str(wheel))
    assert "--resolution" not in flat[2]
    assert "import unifi_fabric.server" in flat[3]
    assert flat[4].endswith("unifi-fabric-mcp --version")
    assert len(calls) == 5


@pytest.mark.parametrize("fail_on", ["lowest-direct", "--no-deps", "-c import", "--version"])
def test_any_failing_step_fails_the_check_and_stops(tmp_path, monkeypatch, fail_on):
    calls = _record(monkeypatch, fail_on)
    assert cld.main(["--wheel", str(_wheel(tmp_path))]) == 1
    assert fail_on in " ".join(calls[-1])  # nothing ran after the failing step


def test_a_wheel_without_dependencies_is_an_error(tmp_path, monkeypatch):
    calls = _record(monkeypatch)
    wheel = _wheel(tmp_path, "Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n")
    assert cld.main(["--wheel", str(wheel)]) == 1
    assert calls == []


def test_install_smoke_runs_the_check_against_the_built_wheel():
    workflow = yaml.safe_load((ROOT / ".github/workflows/install-smoke.yml").read_text())
    steps = workflow["jobs"]["linux"]["steps"]
    run = [s["run"] for s in steps if "check_lowest_direct.py" in s.get("run", "")]
    assert len(run) == 1
    assert "--wheel .install-dist/*.whl" in run[0]
    names = [s.get("name") for s in steps]
    built = names.index("Build local artifacts and install only smoke tooling")
    mine = next(i for i, s in enumerate(steps) if "check_lowest_direct.py" in s.get("run", ""))
    assert built < mine
