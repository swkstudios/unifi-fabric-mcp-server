"""The generated inventory of tool requests and route availability baseline."""

import json
from pathlib import Path

MANIFEST = json.loads(Path(__file__).with_name("route_manifest.json").read_text())
