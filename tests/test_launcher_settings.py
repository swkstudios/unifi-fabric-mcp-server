"""No launcher pins a release older than a setting it passes.

A server older than a setting ignores it: ``uvx --from unifi-fabric-mcp-server==0.7.0`` with
``UNIFI_WRITE_POLICY=deny`` starts with every write tool live. scripts/check_launcher_settings.py
reads every pinned launcher (documentation blocks and lines, the ``MIGRATING-*`` guides
included, and the client manifests) and the published release's settings record.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cls = _load("check_launcher_settings")
prep = _load("prepare_release")

RETIRED = ("UNIFI_OLD_SWITCH",)
RECORD = cls.Record("1.0.0", frozenset({"UNIFI_API_KEY", "UNIFI_TOOL_MODE"}))


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    tree = tmp_path / "tree"
    for rel, text in files.items():
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree / rel).write_text(text)
    return tree


def _block(pin: str, *settings: str) -> str:
    env = "".join(f" -e {name}=1" for name in settings)
    launch = f"uvx{env} --from unifi-fabric-mcp-server=={pin} unifi-fabric-mcp"
    return f"Install:\n\n```bash\n{launch}\n```\n"


def test_shipped_launchers_accept_their_settings(tmp_path: Path) -> None:
    """The tree as it ships (install pins flipped to this version by
    ``prepare_release.py VERSION --published``) has no launcher pinned below a setting it
    passes. The migration guides are never rendered, so their pins are checked as written."""
    tree = tmp_path / "tree"
    shutil.copytree(
        ROOT,
        tree,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            "src",
            "tests",
            "__pycache__",
            "*.pyc",
            ".coverage*",
            ".pytest_cache",
            ".ruff_cache",
            "*.png",
        ),
    )
    version = prep.current_version(tree)
    prep.apply(tree, prep.plan(tree, version, published=True))
    retired = cls.check_retired_settings.retired_names(ROOT)
    assert cls.problems(tree, version, cls.load_record(ROOT), retired) == []


def test_record_names_the_published_release() -> None:
    """The record's release is scripts/published-version.txt, and it lists only current
    settings (all of them once the published release is the current version)."""
    sys.path.insert(0, str(ROOT / "src"))
    from unifi_fabric.config import known_setting_names

    record = cls.load_record(ROOT)
    assert record is not None
    published = (SCRIPTS / "published-version.txt").read_text().strip()
    assert record.release == published, (
        f"{cls.RECORD} names {record.release}, the published release is {published}: run "
        "python3 scripts/check_launcher_settings.py --record"
    )
    current = known_setting_names()
    assert record.names <= current, sorted(record.names - current)
    if published == prep.current_version(ROOT):
        assert record.names == current, sorted(current - record.names)


@pytest.mark.parametrize(
    ("rel", "text", "expected"),
    [
        # The reported case: a published-release pin passing a setting it predates.
        (
            "README.md",
            _block("1.0.0", "UNIFI_API_KEY", "UNIFI_WRITE_POLICY"),
            ["README.md:3 pins 1.0.0 does not accept UNIFI_WRITE_POLICY"],
        ),
        # The migration guides are launchers too (an image tag in a compose block).
        (
            "docs/MIGRATING-2.0.0.md",
            "```yaml\nimage: ghcr.io/o/unifi-fabric-mcp-server:1.0.0\nenvironment:\n"
            "  - UNIFI_WRITE_EXCEPTIONS=family:protect=deny\n```\n",
            ["docs/MIGRATING-2.0.0.md:1 pins 1.0.0 does not accept UNIFI_WRITE_EXCEPTIONS"],
        ),
        # A prose line is a launcher of its own.
        (
            "docs/X.md",
            "Run `uvx --from unifi-fabric-mcp-server==1.0.0` with `UNIFI_EXCLUDE` set.\n",
            ["docs/X.md:1 pins 1.0.0 does not accept UNIFI_EXCLUDE"],
        ),
        # A client manifest is read whole.
        (
            "gemini-extension.json",
            json.dumps(
                {
                    "mcpServers": {
                        "u": {
                            "args": ["--from", "unifi-fabric-mcp-server==1.0.0"],
                            "env": {"UNIFI_WRITE_POLICY": "deny"},
                        }
                    }
                }
            ),
            ["gemini-extension.json:1 pins 1.0.0 does not accept UNIFI_WRITE_POLICY"],
        ),
        # The agent index is a launcher file too.
        (
            "llms.txt",
            "- Run `uvx --from unifi-fabric-mcp-server==1.0.0` with `UNIFI_WRITE_POLICY=deny`.\n",
            ["llms.txt:1 pins 1.0.0 does not accept UNIFI_WRITE_POLICY"],
        ),
        # An earlier release with no record may pass no setting at all.
        (
            "README.md",
            _block("0.9.0", "UNIFI_API_KEY"),
            [
                "README.md:3 pins 0.9.0 has no settings record (scripts/published-settings.txt)"
                ", so it may pass no UNIFI_API_KEY"
            ],
        ),
        # Recorded and retired names on the published pin, and anything on the cut version.
        ("README.md", _block("1.0.0", "UNIFI_API_KEY", "UNIFI_OLD_SWITCH"), []),
        ("README.md", _block("2.0.0", "UNIFI_WRITE_POLICY", "UNIFI_EXCLUDE"), []),
    ],
)
def test_launcher_pinned_below_a_setting_is_reported(
    tmp_path: Path, rel: str, text: str, expected: list[str]
) -> None:
    tree = _tree(tmp_path, {rel: text})
    assert cls.problems(tree, "2.0.0", RECORD, RETIRED) == expected


def test_one_launcher_file_list_for_the_flip_and_the_checks() -> None:
    """The check reads every manifest and top-level document the published flip renders,
    so a launcher the flip moves is also one the check reads, and the reverse."""
    assert cls.MANIFESTS == prep.PIN_MANIFESTS
    rendered = set(prep.pin_files(ROOT))
    for rel in cls.TOP_LEVEL_DOCS:
        assert rel in rendered, rel


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("UNIFI_API_KEY\n", "no release line"),
        ("release 1.0\n", "is not X.Y.Z"),
        ("release 1.0.0\nrelease 1.0.1\n", "more than one release line"),
        ("release 1.0.0\nunifi_api_key\n", "unexpected line"),
    ],
)
def test_malformed_record_is_refused(text: str, message: str) -> None:
    with pytest.raises(cls.RecordError, match=message):
        cls.parse_record(text)


def test_record_round_trips() -> None:
    text = cls.record_text("1.0.0", ["UNIFI_TOOL_MODE", "UNIFI_API_KEY"])
    assert cls.parse_record(text) == RECORD
