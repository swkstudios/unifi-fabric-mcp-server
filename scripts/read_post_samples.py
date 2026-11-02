#!/usr/bin/env python3
"""Print the read-POST samples for a read-only deployment's post-deploy refusal check.

    python3 scripts/read_post_samples.py

Prints JSON ``[{method, path, expect}]`` from ``unifi_fabric.read_post_routes``:
``expect: read`` for every allowlisted route (must NOT be refused under
``UNIFI_READ_ONLY``) and ``expect: refused`` for not-listed POSTs (must be refused before
any upstream call). A read-only deployment's post-deploy check samples both sides from
this output, so the check follows the allowlist without a second copy. Paths carry
synthetic ids; substitute the instance's console id and site before a live run. The
Classic ``READ_COMMANDS`` are not sampled: each is a read only with its exact body, and
these samples carry none.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from unifi_fabric.read_post_routes import refusal_samples  # noqa: E402

if __name__ == "__main__":
    sys.stdout.write(json.dumps(refusal_samples(), indent=2) + "\n")
