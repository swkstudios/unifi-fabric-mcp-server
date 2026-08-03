#!/usr/bin/env python3
"""Phase G fixtures-sanitization gate.

Fail CI if real secrets or PII appear in committed test fixtures or example
configuration files. The point is to keep the (currently synthetic) fixtures
clean so real secret material can never reach the public release
boundary via example data. This complements the `gitleaks` job with denylist
checks tuned to this repo's data shapes.

Scope (intentionally excludes src/ and the test *code* under tests/*.py -- those
are covered by gitleaks; this job only inspects data/config files):
  - tests/fixtures/**
  - config/**
  - repo-root .mcp.json
  - any *.example.* / *.sample.* / .env.example / .env.sample anywhere in tree

Findings print only "<file>:<line>: <category>" -- never the matched value --
so no secret is echoed to CI logs.
"""
from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Public IPv4 literals explicitly allowed as documentation placeholders.
ALLOWED_PUBLIC_IPS = {"8.8.8.8", "1.1.1.1", "1.2.3.4"}

# Denylist of regexes matching real-looking secret material. Placeholder forms
# (e.g. "Bearer ${ENV_VAR}", "X-API-KEY: <your-key>") fall below the length /
# charset thresholds and do not match.
DENYLIST = [
    ("PEM header (private key / certificate)", re.compile(r"-----BEGIN")),
    (
        "JWT-shaped token",
        re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"),
    ),
    (
        "Bearer token (real-looking)",
        re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}"),
    ),
    (
        "UniFi / api.ui.com API key",
        re.compile(r"(?i)(?:x-api-key|api[_-]?key)\s*[:=]\s*[\"']?[A-Za-z0-9]{30,}"),
    ),
]

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

GLOBS = [
    "tests/fixtures/**/*",
    "config/**/*",
    "**/*.example.*",
    "**/*.sample.*",
    "**/.env.example",
    "**/.env.sample",
]

EXPLICIT_FILES = [".mcp.json"]


def iter_target_files():
    seen = set()
    for pattern in GLOBS:
        for path in REPO_ROOT.glob(pattern):
            if path.is_file() and ".git/" not in str(path.as_posix()):
                seen.add(path)
    for rel in EXPLICIT_FILES:
        path = REPO_ROOT / rel
        if path.is_file():
            seen.add(path)
    return sorted(seen)


def public_ip_hits(text):
    hits = []
    for match in IPV4_RE.finditer(text):
        token = match.group(0)
        try:
            ip = ipaddress.ip_address(token)
        except ValueError:
            continue
        if ip.version == 4 and ip.is_global and token not in ALLOWED_PUBLIC_IPS:
            hits.append(token)
    return hits


def main() -> int:
    findings = []
    targets = iter_target_files()
    for path in targets:
        rel = path.relative_to(REPO_ROOT).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            findings.append(f"{rel}: unreadable ({exc})")
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for label, pattern in DENYLIST:
                if pattern.search(line):
                    findings.append(f"{rel}:{lineno}: {label}")
            if public_ip_hits(line):
                findings.append(
                    f"{rel}:{lineno}: public IP not in placeholder allowlist"
                )

    print(f"Scanned {len(targets)} fixture/example-config file(s).")
    if findings:
        print("FAIL: potential real secret/PII detected:")
        for finding in findings:
            print(f"  - {finding}")
        print(
            "\nFixtures and example configs must contain only synthetic or "
            "documented-placeholder values. Replace the flagged material."
        )
        return 1

    print("OK: no real secrets/PII found in fixtures or example configs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
