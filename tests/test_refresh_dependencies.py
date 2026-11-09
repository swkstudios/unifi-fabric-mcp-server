"""The seven managed pin files come from one manifest-driven refresh.

Offline checks of dependencies/manifest.toml, scripts/refresh_dependencies.py and the
committed outputs. The network half (re-resolution and pip-audit) is the
``refresh-check`` and ``pip-audit`` jobs of .github/workflows/dependency-refresh.yml.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "refresh_dependencies", ROOT / "scripts" / "refresh_dependencies.py"
)
assert _SPEC and _SPEC.loader
refresh = importlib.util.module_from_spec(_SPEC)
sys.modules["refresh_dependencies"] = refresh
_SPEC.loader.exec_module(refresh)

PUBLIC_FILES = {
    "requirements.lock",
    "requirements-runtime.lock",
    "requirements-build.lock",
    ".github/install-tooling-requirements.txt",
    ".github/install-build-requirements.txt",
    ".github/publish-pypi-requirements.txt",
}
# Source-repository-only files, absent in published trees.
_PRIVATE_KIND = "private"
_POLICY_TOPIC = "dependabot"
PRIVATE_MANIFEST = ROOT / "dependencies" / f"manifest.{_PRIVATE_KIND}.toml"
DEPENDABOT_POLICY = ROOT / "tests" / f"test_{_POLICY_TOPIC}_policy.py"
WORKFLOW = ROOT / ".github" / "workflows" / "dependency-refresh.yml"


@pytest.fixture(scope="module")
def manifest() -> refresh.Manifest:
    return refresh.load_manifest()


def test_manifest_declares_exactly_the_managed_files(manifest) -> None:
    declared = {str(o.path) for o in manifest.outputs}
    assert PUBLIC_FILES <= declared
    if PRIVATE_MANIFEST.exists():
        # The source repository: the Dependabot pause lists the same seven files.
        spec = importlib.util.spec_from_file_location("dependabot_policy", DEPENDABOT_POLICY)
        assert spec and spec.loader
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        assert declared == policy.MANAGED_FILES
        assert len(declared) == 7
    else:
        assert declared == PUBLIC_FILES


def test_every_output_is_generated_and_every_input_exists(manifest) -> None:
    assert refresh.generated_problems(manifest) == []
    for output in manifest.outputs:
        for path in (*output.inputs, *output.constraints):
            assert (ROOT / path).is_file(), (output.path, path)


def test_shared_packages_have_one_version_and_one_hash_set(manifest) -> None:
    texts = {o.path: (ROOT / o.path).read_text() for o in manifest.outputs}
    assert refresh.shared_pin_problems(texts) == []


def test_runtime_and_dev_locks_share_every_runtime_pin(manifest) -> None:
    dev = refresh.parse_pins((ROOT / "requirements.lock").read_text())
    runtime = refresh.parse_pins((ROOT / "requirements-runtime.lock").read_text())
    assert runtime and set(runtime) <= set(dev)
    assert {name: dev[name] for name in runtime} == runtime


def test_backend_is_pinned_once(manifest) -> None:
    assert refresh.backend_problems(manifest) == []


def test_target_policy_consumers_match_the_manifest(manifest) -> None:
    assert refresh.target_problems(manifest) == []


@pytest.mark.parametrize("workflow_index", range(3))
@pytest.mark.parametrize(
    ("setting", "version_text", "expected_problem"),
    [
        ('python-version: "3.12"', None, None),
        ("python-version: '3.12'", None, None),
        ("python-version-file: .python-version", "3.12\n", None),
        ('python-version-file: "config/python-version" # shared pin', " 3.12\n", None),
        ("python-version-file: 'config/python-version'", "3.12\n", None),
        ("python-version-file: .python-version", "3.13\n", "is not 3.12"),
        ("python-version-file: .python-version", "", "is not 3.12"),
        ("python-version-file: .python-version", None, "cannot read python-version-file"),
        ("python-version: 3.13", None, "is not 3.12"),
        (
            "python-version: 3.12\n          python-version-file: .python-version",
            "3.13\n",
            "is not 3.12",
        ),
        (
            "python-version: 3.12\n          python-version-file: .python-version",
            None,
            "cannot read python-version-file",
        ),
    ],
)
def test_target_policy_resolves_workflow_python_version_files(
    manifest,
    tmp_path: Path,
    workflow_index: int,
    setting: str,
    version_text: str | None,
    expected_problem: str | None,
) -> None:
    workflows = manifest.target["python_workflows"]
    for relative in (
        refresh.DOCKERFILE,
        refresh.WHEEL_CHECK,
        refresh.HOMEBREW_GENERATOR,
        *(Path(workflow) for workflow in workflows),
    ):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text((ROOT / relative).read_text())
    (tmp_path / ".python-version").write_text("3.12\n")
    workflow = workflows[workflow_index]
    (tmp_path / workflow).write_text(
        "jobs:\n  check:\n    steps:\n      - uses: actions/setup-python@v5\n"
        f"        with:\n          {setting}\n"
    )
    version_file = tmp_path / (
        "config/python-version" if "config/python-version" in setting else ".python-version"
    )
    if version_text is None:
        if version_file.exists():
            version_file.unlink()
        # Other workflows keep their valid single-source setting.
        for other in workflows:
            if other != workflow:
                (tmp_path / other).write_text('python-version: "3.12"\n')
    else:
        version_file.parent.mkdir(parents=True, exist_ok=True)
        version_file.write_text(version_text)
        for other in workflows:
            if other != workflow:
                (tmp_path / other).write_text('python-version: "3.12"\n')
    problems = refresh.target_problems(manifest, root=tmp_path)
    if expected_problem is None:
        assert problems == []
    else:
        assert any(workflow in problem and expected_problem in problem for problem in problems)


def test_constraints_must_name_earlier_outputs(tmp_path: Path) -> None:
    (tmp_path / "dependencies").mkdir()
    (tmp_path / "dependencies" / "manifest.toml").write_text(
        '[target]\npython = "3.12"\n[resolution]\nexclude_newer = "2026-01-01T00:00:00Z"\n'
        '[backend]\nname = "hatchling"\nversion = "1"\n'
        '[[output]]\npath = "a.lock"\npurpose = "a"\ninputs = ["a.in"]\n'
        'constraints = ["b.lock"]\n'
        '[[output]]\npath = "b.lock"\npurpose = "b"\ninputs = ["b.in"]\n'
    )
    for name in ("a.lock", "b.lock"):
        (tmp_path / name).write_text("")
    with pytest.raises(ValueError, match="not an earlier manifest output"):
        refresh.load_manifest(tmp_path)


def test_private_manifest_outputs_are_appended_and_must_exist(tmp_path: Path) -> None:
    (tmp_path / "dependencies").mkdir()
    (tmp_path / "a.lock").write_text("")
    (tmp_path / "dependencies" / "manifest.toml").write_text(
        '[target]\npython = "3.12"\n[resolution]\nexclude_newer = "2026-01-01T00:00:00Z"\n'
        '[backend]\nname = "hatchling"\nversion = "1"\n'
        '[[output]]\npath = "a.lock"\npurpose = "a"\ninputs = ["a.in"]\n'
    )
    (tmp_path / PRIVATE_MANIFEST.relative_to(ROOT)).write_text(
        '[[output]]\npath = "p.txt"\npurpose = "p"\ninputs = ["p.in"]\nconstraints = ["a.lock"]\n'
    )
    with pytest.raises(ValueError, match="p.txt does not exist"):
        refresh.load_manifest(tmp_path)
    (tmp_path / "p.txt").write_text("")
    assert [str(o.path) for o in refresh.load_manifest(tmp_path).outputs] == ["a.lock", "p.txt"]


def test_resolution_uses_the_index_cutoff_and_no_source_builds(manifest) -> None:
    args = refresh.resolution_args(manifest)
    assert args[args.index("--index-url") + 1] == "https://pypi.org/simple"
    assert args[args.index("--exclude-newer") + 1] == manifest.resolution["exclude_newer"]
    assert "--no-build" in args
    assert manifest.resolution["cooldown_days"] >= 3


def test_cooldown_cutoff_is_days_back_on_the_hour() -> None:
    from datetime import UTC, datetime

    now = datetime(2026, 11, 4, 1, 37, 12, tzinfo=UTC)
    assert refresh.cooldown_cutoff(3, now) == "2026-11-01T01:00:00Z"


def test_no_managed_file_pins_below_an_advisory_floor(manifest) -> None:
    # Published advisories that pip-audit's PyPI data can miss: the image, the wheel and
    # the Homebrew formula must not ship an affected release of any managed package.
    floors = refresh.advisory_floors(manifest)
    assert {"authlib", "dnspython"} <= set(floors)
    texts = {o.path: (ROOT / o.path).read_text() for o in manifest.outputs}
    assert refresh.advisory_problems(manifest, texts) == []


def _floor_manifest(**floors: str) -> refresh.Manifest:
    return refresh.Manifest(
        target={},
        resolution={
            "advisory_floor": {
                name: {"version": version, "advisories": [f"GHSA-{name}"]}
                for name, version in floors.items()
            }
        },
        backend_name="hatchling",
        backend_version="1",
        outputs=(),
    )


@pytest.mark.parametrize(
    ("pinned", "below"),
    [
        ("1.9.1", True),
        ("1.9.4rc1", True),
        ("1.9.4.dev0", True),
        ("1.9.4", False),
        ("1.9.4.0", False),
        ("1.9.4.post1", False),
        ("1.10.0", False),
        ("2", False),
    ],
)
def test_advisory_floor_orders_versions(pinned: str, below: bool) -> None:
    manifest = _floor_manifest(Authlib="1.9.4")
    text = f"authlib=={pinned} \\\n    --hash=sha256:aa\nother==0.1 \\\n    --hash=sha256:bb\n"
    problems = refresh.advisory_problems(manifest, {Path("a.lock"): text})
    assert bool(problems) is below
    if below:
        assert problems == [
            f"a.lock: authlib=={pinned} is below the advisory floor 1.9.4 (GHSA-Authlib): "
            "allow the fixed release in [resolution.exclude_newer_package] and refresh"
        ]


def test_advisory_floor_needs_a_version_and_advisory_ids() -> None:
    manifest = refresh.Manifest(
        target={},
        resolution={"advisory_floor": {"authlib": {"version": "1.9.4"}}},
        backend_name="hatchling",
        backend_version="1",
        outputs=(),
    )
    with pytest.raises(ValueError, match="advisory_floor.authlib needs"):
        refresh.advisory_floors(manifest)


def test_refresh_lifts_only_the_pins_below_a_floor(tmp_path: Path, monkeypatch) -> None:
    # Without --upgrade uv keeps every existing pin, so a floor alone would never move one.
    (tmp_path / "a.lock").write_text(
        "authlib==1.9.1 \\\n    --hash=sha256:aa\n"
        "dnspython==2.9.2 \\\n    --hash=sha256:bb\n"
        "anyio==4.15.1 \\\n    --hash=sha256:cc\n"
    )
    output = refresh.Output(Path("a.lock"), "a", (Path("a.in"),), (), ())
    manifest = _floor_manifest(authlib="1.9.4", dnspython="2.9.2")
    manifest = refresh.Manifest(
        target={"python": "3.12", "resolve_platform": "x86_64-manylinux_2_28"},
        resolution={
            **manifest.resolution,
            "index_url": "https://pypi.org/simple",
            "exclude_newer": "2026-11-01T01:00:00Z",
        },
        backend_name="hatchling",
        backend_version="1",
        outputs=(output,),
    )
    calls: list[list[str]] = []

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        return type("Proc", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(refresh, "uv_command", lambda: ["uv"])
    monkeypatch.setattr(refresh.subprocess, "run", fake_run)
    refresh.compile_output(tmp_path, manifest, output, upgrade=False)
    refresh.compile_output(tmp_path, manifest, output, upgrade=True)
    keep, upgrade = calls
    lifted = [keep[i + 1] for i, arg in enumerate(keep) if arg == "--upgrade-package"]
    assert lifted == ["authlib"]
    assert "--upgrade" not in keep
    assert "--upgrade" in upgrade and "--upgrade-package" not in upgrade


def test_shared_pin_check_catches_version_and_hash_drift() -> None:
    a = "pkg==1.0 \\\n    --hash=sha256:aa \\\n    --hash=sha256:bb\n"
    b_version = "pkg==1.1 \\\n    --hash=sha256:aa\n"
    b_hash = "pkg==1.0 \\\n    --hash=sha256:aa\n"
    unhashed = "pkg==1.0\n"
    assert "pins 1.0 but" in refresh.shared_pin_problems({Path("a"): a, Path("b"): b_version})[0]
    assert "hash sets differ" in refresh.shared_pin_problems({Path("a"): a, Path("b"): b_hash})[0]
    assert "has no --hash" in refresh.shared_pin_problems({Path("c"): unhashed})[0]


@pytest.mark.parametrize(
    ("spec", "relaxed"),
    [
        ("fastmcp>=4.0,<5.0", "fastmcp>=4.0"),
        ("hatchling==1.33.0", "hatchling>=1.33.0"),
        ("editables==0.6", "editables>=0.6"),
        ("pytest>=8.0", "pytest>=8.0"),
        ("foo~=1.2", "foo>=1.2"),
        ('bar<2; python_version < "3.13"', 'bar; python_version < "3.13"'),
    ],
)
def test_relax_lifts_caps_and_exact_pins(spec: str, relaxed: str) -> None:
    assert refresh.relax(spec) == relaxed


def test_generated_headers_fit_the_line_length(manifest) -> None:
    for output in manifest.outputs:
        assert all(len(line) <= 88 for line in refresh.header(output).splitlines())


def test_refresh_check_runs_for_every_pull_request_push_and_queue_entry() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    on = workflow[True] if True in workflow else workflow["on"]
    assert "paths" not in (on["pull_request"] or {})
    # Built from fragments: the codeql workflow greps src/ tests/ .github/ for the literal.
    assert "-".join(("paths", "ignore")) not in (on["pull_request"] or {})
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    ci_on = ci[True] if True in ci else ci["on"]
    assert on["pull_request"]["branches"] == ci_on["pull_request"]["branches"]
    assert on["push"]["branches"] == ci_on["push"]["branches"]
    assert on.get("merge_group") == ci_on.get("merge_group")
    assert on["schedule"]
    for job, flag in (("refresh-check", "--check"), ("pip-audit", "--audit")):
        runs = [s.get("run", "") for s in workflow["jobs"][job]["steps"]]
        assert any(f"scripts/refresh_dependencies.py {flag}" in run for run in runs), job
