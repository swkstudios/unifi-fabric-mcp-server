"""PyPI publishing: Trusted Publishing (OIDC) from the public repository's releases."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-pypi.yml"
PUBLIC_REPO = "swkstudios/unifi-fabric-mcp-server"


def _workflow() -> dict[str, Any]:
    data = yaml.safe_load(WORKFLOW.read_text())
    # YAML 1.1 reads the bare key `on` as True.
    data["on"] = data.pop(True, data.get("on"))
    return data


def _steps(job: str) -> list[dict[str, Any]]:
    return _workflow()["jobs"][job]["steps"]


def test_published_release_triggers_and_dispatch_defaults_to_dry_run() -> None:
    on = _workflow()["on"]
    assert on["release"] == {"types": ["published"]}
    upload = on["workflow_dispatch"]["inputs"]["upload"]
    assert upload["type"] == "boolean" and upload["default"] is False
    assert set(on) == {"release", "workflow_dispatch"}  # no push / tag trigger


def test_upload_job_is_guarded_to_the_public_repo_and_a_release_tag() -> None:
    upload = _workflow()["jobs"]["upload"]
    guard = " ".join(upload["if"].split())
    assert guard.startswith(f"github.repository == '{PUBLIC_REPO}' && (")
    assert "github.event_name == 'release'" in guard
    assert "inputs.upload" in guard and "github.ref_type == 'tag'" in guard
    assert upload["needs"] == "build"


def test_upload_uses_oidc_in_the_registered_environment() -> None:
    upload = _workflow()["jobs"]["upload"]
    assert upload["environment"] == "pypi-upload"
    assert upload["permissions"] == {"id-token": "write", "contents": "read"}
    assert _workflow()["permissions"] == {"contents": "read"}
    assert "id-token" not in _workflow()["jobs"]["build"].get("permissions", {})
    (publish,) = [s for s in _steps("upload") if "gh-action-pypi-publish" in s.get("uses", "")]
    ref = publish["uses"].split("@", 1)[1]
    assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref), ref
    # v1.14.2 and earlier carry GHSA-5xjx-3w67-w9x9; the pin comment names the tag the SHA is.
    line = next(x for x in WORKFLOW.read_text().splitlines() if publish["uses"] in x)
    version = line.split("# v", 1)[1].split()[0]
    assert tuple(int(n) for n in version.split(".")) >= (1, 14, 3), line
    assert "with" not in publish or not {"password", "user"} & set(publish["with"])
    text = WORKFLOW.read_text()
    for token_path in ("PYPI_API_TOKEN", "TWINE_PASSWORD", "twine upload", "secrets."):
        assert token_path not in text, token_path


def test_build_checks_out_the_release_tag_and_checks_strictly() -> None:
    (checkout,) = [s for s in _steps("build") if s.get("uses", "").startswith("actions/checkout@")]
    ref = checkout["with"]["ref"]
    assert "github.event_name == 'release'" in ref
    assert "format('refs/tags/{0}', github.event.release.tag_name)" in ref
    assert "main" not in ref
    runs = [s.get("run", "") for s in _steps("build")]
    assert any("twine check --strict dist/*" in r for r in runs), runs
    tag_check = [s for s in _steps("build") if s.get("name") == "Tag matches the package version"]
    assert tag_check and "RELEASE_TAG" in tag_check[0]["env"]
