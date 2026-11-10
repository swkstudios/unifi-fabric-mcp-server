"""The key file / helper command documentation says what the code does.

Each statement the section makes about a helper's lifetime, output and arguments is pinned
to behaviour here, so the page cannot drift from :mod:`unifi_fabric.credential_providers`.
"""

from __future__ import annotations

import os
import re
import sys
import threading
from pathlib import Path

import pytest

from unifi_fabric import credential_providers as cp

ROOT = Path(__file__).resolve().parents[1]
CONFIGURATION = ROOT / "docs" / "CONFIGURATION.md"

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX helper scripts")


@pytest.fixture(autouse=True)
def _fresh_providers():
    cp.reset()
    yield
    cp.reset()


def _section() -> str:
    text = CONFIGURATION.read_text(encoding="utf-8")
    start = text.index("## Key files and helper commands")
    return text[start : text.index("\n### ", start)]


def _bullet(label: str) -> str:
    """The text of the section's bullet that opens with ``**label.**``."""
    body = _section()
    start = body.index(f"- **{label}.**")
    nxt = re.search(r"\n- \*\*", body[start + 1 :])
    return body[start : start + 1 + nxt.start()] if nxt else body[start:]


def _helper(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "helper"
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o700)
    return path


# ------------------------------------------------- F5: a lingering child holds stdout open


@posix_only
def test_a_background_child_holding_stdout_is_read_after_the_helper_exits(tmp_path):
    """The read waits for end of file: output a child prints after the helper exited counts.

    The child blocks on ``gate`` while it holds the helper's standard output; the test opens
    ``gate`` only after the helper reported its last line, so the child's ``TAIL`` is printed
    when the helper has exited or is about to. Returning ``KEYTAIL`` shows the server did not
    stop at the helper's exit. Nothing here measures elapsed time.
    """
    gate = tmp_path / "gate"
    exited = tmp_path / "exited"
    os.mkfifo(gate)
    os.mkfifo(exited)
    key = "-".join(("synthetic", "docs", "key", "0" * 8))
    helper = _helper(
        tmp_path,
        f"( read _ < '{gate}'; printf TAIL ) &\nprintf %s '{key}'\necho done > '{exited}'",
    )
    result: list[str] = []
    runner = threading.Thread(
        target=lambda: result.append(cp._run_command("UNIFI_API_KEY_COMMAND", str(helper)))
    )
    runner.start()
    with open(exited, encoding="utf-8") as seen:  # blocks until the helper's last line
        seen.read()
    with open(gate, "w", encoding="utf-8") as release:  # lets the lingering child print
        release.write("go\n")
    runner.join()
    assert result == [key + "TAIL"]


def test_the_page_says_a_lingering_child_holding_stdout_blocks_startup():
    text = " ".join(_bullet("Helper commands").split())
    assert "background process" in text
    assert "standard output" in text and "open" in text
    assert "even after the helper itself exits" in text


# ------------------------------------------------- F7: what a trailing line break means


@pytest.mark.parametrize(
    ("content", "expected"),
    [("KEY\n", "KEY"), ("KEY\r\n", "KEY"), ("KEY\n\n", "KEY"), ("KEY\r\n\r\n", "KEY")],
)
def test_every_trailing_line_break_is_removed_from_a_key(content, expected):
    """The code strips a run of trailing CR / LF characters, not exactly one line break."""
    assert cp._parse("UNIFI_API_KEY_FILE", content, cp._KEY) == expected


def test_the_page_describes_the_run_of_trailing_line_breaks_the_code_removes():
    text = " ".join(_bullet("What the value must look like").split())
    assert "any number of trailing line breaks" in text
    assert "a trailing line break (`\\n` or `\\r\\n`)" not in text


def test_the_module_docstring_matches_the_page():
    doc = " ".join((cp.__doc__ or "").split())
    assert "any number of trailing line breaks" in doc


# ------------------------------------------------- F8: helper arguments show in ps


@posix_only
def test_helper_arguments_are_visible_to_other_processes(tmp_path):
    """The helper's argv is in the process table while it runs; it is not a secret store."""
    seen = tmp_path / "cmdline"
    dump = f"cat /proc/$$/cmdline > '{seen}' 2>/dev/null || ps -ww -o args= -p $$ > '{seen}'"
    body = f"{dump}\nprintf %s KEY"
    helper = _helper(tmp_path, body)
    marker = "visible-marker-argument"
    assert cp._run_command("UNIFI_API_KEY_COMMAND", f"{helper} {marker}") == "KEY"
    assert marker in seen.read_text()


def test_the_page_says_helper_arguments_show_in_ps_and_are_not_secret():
    text = " ".join(_bullet("Helper commands").split())
    assert "`ps`" in text
    assert "not secret" in text
    assert "no credential" in text
