"""The install pins in the docs: every position, every suffix, padding, badges and messages.

Covers the pin handling of ``scripts/gen_catalog_figures.py``: a pre-release or post-release
suffix on any pin is re-rendered (so ``--check`` fails on it), a Cursor badge keeps valid
base64 padding when a version bump changes the config length, a missing or unpinned encoded
badge fails the generator itself, and a stale pin is named by its position and value.
Hermetic: synthetic text, no console, no network.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import re
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return sys.modules[spec.name]


gen = _load("gen_catalog_figures")
CURRENT = gen.PUBLISHED_VERSION
SUFFIXES = ["rc1", ".post1", ".1", "-dev.1", "+local", "%2Blocal"]
#: One sample line per plain-text pin position (the labels are PIN_KINDS' own).
POSITIONS = {
    "package pin": "uvx unifi-fabric-mcp-server=={v} --help",
    "VS Code install-badge pin": "x?config=%22unifi-fabric-mcp-server%3D%3D{v}%22",
    "container image tag": "docker pull ghcr.io/swkstudios/unifi-fabric-mcp-server:{v}",
    "release download link": "https://github.com/o/r/releases/download/v{v}/unifi-fabric-{v}.mcpb",
    "extension bundle file name": "https://example.test/dl/unifi-fabric-{v}.mcpb",
}


def _cursor_link(config: str, *, urlsafe: bool = False, pad: bool = True) -> str:
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    payload = encode(config.encode()).decode()
    return "https://cursor.com/en/install-mcp?name=x&config=" + (
        payload if pad else payload.rstrip("=")
    )


def _config(version: str, lead: int = 0) -> str:
    return json.dumps({"command": "x" * lead + f"uvx unifi-fabric-mcp-server=={version} run"})


def _payload(link: str) -> str:
    return link.split("config=", 1)[1]


# --- suffixed pins (issue 859) ------------------------------------------------------------


@pytest.mark.parametrize("suffix", SUFFIXES)
@pytest.mark.parametrize("position", sorted(POSITIONS))
def test_a_suffixed_pin_is_rerendered_in_every_position(position: str, suffix: str) -> None:
    stale = POSITIONS[position].format(v=CURRENT + suffix)
    fresh = POSITIONS[position].format(v=CURRENT)
    assert gen.render_install_versions(stale, CURRENT) == fresh, position
    assert gen.render_install_versions(fresh, CURRENT) == fresh


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_a_suffixed_cursor_pin_is_rerendered(suffix: str) -> None:
    stale = _cursor_link(_config(CURRENT + suffix))
    assert gen.render_install_versions(stale, CURRENT) == _cursor_link(_config(CURRENT))


def test_text_after_a_pin_is_not_swallowed() -> None:
    pin = f"unifi-fabric-mcp-server=={CURRENT}"
    text = f"pin {pin}. Next sentence, and ({pin})"
    assert gen.render_install_versions(text, CURRENT) == text


# --- Cursor base64 padding (issue 860) ----------------------------------------------------


@pytest.mark.parametrize("lead", [0, 1, 2])
@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("0.10.0", "1.0.0"),
        ("1.0.0", "0.10.0"),
        ("0.7.1", "0.10.1"),
        ("0.10.1", "0.7.1"),
        ("9.9.9", "10.10.10"),
    ],
)
@pytest.mark.parametrize("urlsafe", [False, True])
def test_a_length_changing_bump_keeps_valid_padding(
    lead: int, old: str, new: str, urlsafe: bool
) -> None:
    link = _cursor_link(_config(old, lead), urlsafe=urlsafe)
    out = gen.render_install_versions(link, new)
    assert out == _cursor_link(_config(new, lead), urlsafe=urlsafe)
    assert len(_payload(out).rstrip("=")) % 4 == 0 or _payload(out).endswith("=")


@pytest.mark.parametrize("lead", [0, 1, 2])
def test_an_unpadded_payload_stays_unpadded(lead: int) -> None:
    # An author who dropped the "=" of a payload that needs it keeps that style. A payload whose
    # length needs no padding says nothing about its style (the test above covers it).
    link = _cursor_link(_config("0.7.1", lead), pad=False)
    if len(_payload(link)) % 4 == 0:
        pytest.skip("this length needs no padding, so it carries no style")
    out = gen.render_install_versions(link, "0.7.2")
    assert out == _cursor_link(_config("0.7.2", lead), pad=False)
    assert "=" not in _payload(out)


# --- a missing or unpinned encoded badge fails the generator (issue 861) -------------------

#: The real install link, not just a pin-shaped token: the guard needs the link itself.
VSCODE = "https://insiders.vscode.dev/redirect/mcp/install?name=x&config=" + POSITIONS[
    "VS Code install-badge pin"
].format(v=CURRENT)


def _readme(*, vscode: str | None = VSCODE, cursor: str | None = None) -> str:
    cursor = _cursor_link(_config(CURRENT)) if cursor is None else cursor
    return "\n".join(part for part in (vscode, cursor) if part) + "\n"


def test_the_real_readme_has_both_pinned_badges() -> None:
    gen.require_install_badges((ROOT / "README.md").read_text(), "README.md")


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        (_readme(vscode=None), "no VS Code install badge"),
        (_readme(vscode="unifi-fabric-mcp-server%3D%3D"), "no VS Code install badge"),
        (_readme(cursor=""), "no Cursor install badge"),
        (_readme(cursor="cursor.com/en/install-mcp?name=x&config=!!!"), "no Cursor install badge"),
        (_readme(cursor=_cursor_link('{"command": "uvx other"}')), "pins no package version"),
        (_readme(cursor="https://cursor.com/en/install-mcp?name=x&config=A"), "does not decode"),
    ],
)
def test_a_missing_or_unpinned_badge_fails_the_generator(text: str, fragment: str) -> None:
    with pytest.raises(gen.MarkerError, match=re.escape(fragment)) as err:
        gen.require_install_badges(text, "README.md")
    assert "README.md" in str(err.value)
    # render_readme runs the same gate before it renders anything.
    with pytest.raises(gen.MarkerError, match=re.escape(fragment)):
        gen.render_readme(text, None)


def test_a_vscode_badge_replaced_by_plain_text_fails_the_generator() -> None:
    orphan = "see unifi-fabric-mcp-server%3D%3D" + CURRENT + " in the badge"
    with pytest.raises(gen.MarkerError, match="no VS Code install badge"):
        gen.require_install_badges(_readme(vscode=orphan), "README.md")


def test_a_complete_pair_of_badges_passes() -> None:
    gen.require_install_badges(_readme(), "README.md")


# --- the failure names the pin (issue 862) ------------------------------------------------


def test_pin_findings_name_the_line_the_position_and_the_values() -> None:
    old = "0.0.1"
    text = "\n".join(
        [
            "intro",
            POSITIONS["package pin"].format(v=old),
            POSITIONS["container image tag"].format(v=CURRENT),
            POSITIONS["extension bundle file name"].format(v=old + "rc1"),
            _cursor_link(_config(old)),
            POSITIONS["VS Code install-badge pin"].format(v=old),
        ]
    )
    found = gen.pin_findings(text, CURRENT, "README.md")
    tail = f", expected {CURRENT}"
    assert found == [
        f"README.md:2: package pin (unifi-fabric-mcp-server==VERSION) is {old}{tail}",
        f"README.md:4: extension bundle file name (unifi-fabric-VERSION.mcpb) is {old}rc1{tail}",
        f"README.md:5: Cursor install-badge pin (base64 config) is {old}{tail}",
        "README.md:6: VS Code install-badge pin (unifi-fabric-mcp-server%3D%3DVERSION) "
        f"is {old}{tail}",
    ]
    assert gen.pin_findings(_readme(), CURRENT, "README.md") == []


def test_check_prints_the_stale_pin_not_just_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fresh = _readme()
    stale = fresh.replace(f"%3D%3D{CURRENT}", "%3D%3D0.0.1")
    readme = tmp_path / "README.md"
    readme.write_text(stale)
    monkeypatch.setattr(gen, "ROOT", tmp_path)
    monkeypatch.setattr(gen, "render_outputs", lambda: ({readme: fresh}, _FIG))
    monkeypatch.setattr(sys, "argv", ["gen_catalog_figures.py", "--check"])
    assert gen.main() == 1
    err = capsys.readouterr().err
    assert (
        "stale pin: README.md:1: VS Code install-badge pin (unifi-fabric-mcp-server%3D%3DVERSION) "
        f"is 0.0.1, expected {CURRENT}"
    ) in err
    assert readme.read_text() == stale  # --check writes nothing


class _Fig:
    tools, full_kb, modes, shaped, free, shape_bytes = 1, 1, {}, 0, 0, 0


_FIG = _Fig()


# --- a long non-matching token must not blow up the pin grammar ----------------------------


@pytest.mark.parametrize("position", sorted(POSITIONS))
def test_a_long_near_miss_token_is_rejected_in_linear_time(position: str) -> None:
    # The old tail made a mismatch cost double per extra character: a 26-character near miss
    # took about twelve seconds and a 40-character one never returned. The sample is a pin
    # followed by a long alphanumeric run and a character no pin may contain.
    sample = POSITIONS[position].format(v=CURRENT + "a" * 26 + "!")
    start = time.perf_counter()
    gen.render_install_versions(sample, CURRENT)
    gen.pin_findings(sample, CURRENT, "x")
    assert time.perf_counter() - start < 1.0, "the pin grammar backtracks exponentially"
