"""The image's CA bundle must not trust the roots named in the eMudhra CA incident.

FastMCP 4.1.3 notice: upgrading FastMCP alone is insufficient because FastMCP 4 uses the
system trust store. ``httpx2`` loads the image's ``/etc/ssl/certs/ca-certificates.crt``;
``httpx`` (the api.ui.com client) loads certifi. The Dockerfile build runs
``scripts/check_ca_bundle.py`` on the runtime rootfs, so a stale base digest fails the build.
"""

from __future__ import annotations

import base64
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_ca_bundle.py"
sys.path.insert(0, str(ROOT / "scripts"))
import check_ca_bundle as checker  # noqa: E402


def _pem(der_seed: bytes) -> str:
    body = base64.encodebytes(der_seed).decode()
    return f"-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n"


def _run(bundle: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- fixed interpreter and repo script
        [sys.executable, "-I", str(SCRIPT), str(bundle)], capture_output=True, text=True
    )


def test_bundle_with_a_compromised_root_is_reported(monkeypatch):
    bad, good = b"incident-root", b"other-root"
    monkeypatch.setitem(
        checker.COMPROMISED_ROOTS, hashlib.sha256(bad).hexdigest(), "AAA Certificate Services"
    )
    text = _pem(good) + _pem(bad)
    assert checker.trusted_compromised_roots(text) == ["AAA Certificate Services"]
    assert checker.trusted_compromised_roots(_pem(good)) == []


def test_cli_exit_codes(tmp_path):
    empty = tmp_path / "empty.crt"
    empty.write_text("")
    assert _run(empty).returncode == 2
    assert _run(tmp_path / "missing.crt").returncode == 2


def test_cli_passes_a_clean_real_bundle(tmp_path):
    """certifi's bundle (locked at 2026.10.23) holds none of the incident roots."""
    import certifi

    result = _run(Path(certifi.where()))
    assert result.returncode == 0, result.stderr


def test_every_incident_fingerprint_is_a_sha256():
    assert len(checker.COMPROMISED_ROOTS) == 4
    assert all(re.fullmatch(r"[0-9a-f]{64}", fp) for fp in checker.COMPROMISED_ROOTS)


def test_dockerfile_checks_the_runtime_rootfs_bundle():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "COPY scripts/check_ca_bundle.py /check/check_ca_bundle.py" in dockerfile
    assert (
        "python /check/check_ca_bundle.py /rootfs/etc/ssl/certs/ca-certificates.crt" in dockerfile
    )
    # The check sits after the base filesystem is copied in and before the final stage.
    assert dockerfile.index("COPY --from=base / /rootfs/") < dockerfile.index("check_ca_bundle.py")


def test_certifi_lock_is_past_the_incident_floor():
    lock = (ROOT / "requirements-runtime.lock").read_text()
    version = re.search(r"^certifi==(\d+)\.(\d+)\.(\d+) ", lock, re.M)
    assert version, "certifi is not in the runtime lock"
    assert tuple(map(int, version.groups())) >= (2026, 10, 19)
