#!/usr/bin/env python3
"""Fail when a CA bundle still trusts a root named in the eMudhra CA incident.

The image build runs this on the runtime rootfs bundle (``/rootfs/etc/ssl/certs/
ca-certificates.crt``), so a base image whose ``ca-certificates`` package predates the fix
cannot be built. ``httpx2`` (the JWKS download and FastMCP clients) loads that bundle;
``httpx`` (the api.ui.com client) loads certifi, whose lock pin is checked by the tests.

Usage: ``check_ca_bundle.py [BUNDLE]`` (default ``/etc/ssl/certs/ca-certificates.crt``).
Exit 0 when none of the roots is present, 1 when one is, 2 when the bundle is unusable.
Fingerprints: https://emudhra.we-have-a-problem.com/roots.json
"""

from __future__ import annotations

import hashlib
import re
import ssl
import sys
from pathlib import Path

#: SHA-256 of the DER certificate -> name: the direct emSign issuers and the Sectigo/AAA and
#: emSign ECC cross-signing roots, which the incident notice says must all be distrusted.
COMPROMISED_ROOTS = {
    "7dd78d5f4f13459a83dff9abbba62edbaf6f2d102bf257fd712f4d9f2746ed8d": "emSign Root TLS CA - G3",
    "f2edaaff3d9b701fb4d14c9f285f8c0bad90fc3bcc1fa07d47f4718edaba34a5": "emSign Root CS CA - G3",
    "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4": "AAA Certificate Services",
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b": "emSign ECC Root CA - G3",
}

_PEM = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


def trusted_compromised_roots(bundle_text: str) -> list[str]:
    """Names of the incident roots present in a PEM bundle (empty text yields none)."""
    found = []
    for pem in _PEM.findall(bundle_text):
        digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
        if digest in COMPROMISED_ROOTS:
            found.append(COMPROMISED_ROOTS[digest])
    return found


def main(argv: list[str]) -> int:
    path = Path(argv[1] if len(argv) > 1 else "/etc/ssl/certs/ca-certificates.crt")
    try:
        text = path.read_text()
    except OSError as exc:
        print(f"cannot read CA bundle {path}: {exc}", file=sys.stderr)
        return 2
    count = len(_PEM.findall(text))
    if count == 0:
        print(f"CA bundle {path} holds no certificates", file=sys.stderr)
        return 2
    found = trusted_compromised_roots(text)
    if found:
        print(
            f"CA bundle {path} still trusts compromised roots: {', '.join(found)}. Move the "
            "PYTHON_IMAGE digest in the Dockerfile to a python:3.12-slim-bookworm build whose "
            "ca-certificates is 20250419~deb12u2 or later.",
            file=sys.stderr,
        )
        return 1
    print(f"CA bundle {path}: {count} roots, none from the eMudhra incident")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
