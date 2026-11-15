"""The PyPI publisher identity decisions stay true (no company tier, attestations on)."""

from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/publish-pypi.yml").read_text())


def test_project_metadata_claims_no_company_tier():
    assert PYPROJECT["authors"] == [{"name": "SWK Studios"}]
    assert "maintainers" not in PYPROJECT
    blob = repr(PYPROJECT).lower()
    assert "organization" not in blob and "company" not in blob


def test_the_upload_keeps_trusted_publishing_attestations_on():
    upload = WORKFLOW["jobs"]["upload"]
    assert upload["environment"] == "pypi-upload"
    assert upload["permissions"]["id-token"] == "write"
    (publish,) = [s for s in upload["steps"] if "gh-action-pypi-publish" in s.get("uses", "")]
    with_ = publish.get("with") or {}
    assert str(with_.get("attestations", "true")).lower() == "true"  # the action's default
    assert "password" not in with_ and "user" not in with_  # no token, only OIDC
