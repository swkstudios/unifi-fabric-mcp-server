"""Usage-guide claims that must agree with the runtime defaults and behaviour.

Covers the write opt-out default (TOOL-USAGE.md), the boolean-coercion claim in the 0.7.0
migration guide, the verbatim-credential default for reads, the blank-argument note, the
relay 429 and audit sentences, and the COVERAGE.md InnerSpace and key_label statements.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from tests import upstream_harness as uh
from tests._tool_catalog import tools_by_name
from unifi_fabric import policy, server
from unifi_fabric.config import Settings
from unifi_fabric.families.statistics.statistics import SESSION_TYPES

ROOT = Path(__file__).resolve().parents[1]


def _doc(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _settings() -> Settings:
    return Settings(api_key="k-test")


def test_write_opt_out_intro_matches_the_runtime_default() -> None:
    settings = _settings()
    assert settings.write_exceptions is None
    assert settings.write_policy is None
    assert policy.DEFAULT_WRITE_POLICY == "allow"
    for rel in ("README.md", "docs/CONFIGURATION.md", "docs/TOOL-USAGE.md"):
        text = _doc(rel)
        for match in re.finditer(r"<!-- BEGIN GENERATED: write-switches -->", text):
            before = text[: match.start()].rstrip().rsplit("\n\n", 1)[-1]
            assert not re.search(r"\bon by default\b", before), (rel, before)
    opt_out_on = re.compile(r"`family:[a-z]+=deny` is on by default")
    for path in [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]:
        hits = opt_out_on.findall(_flat(path.read_text(encoding="utf-8")))
        assert not hits, (path.relative_to(ROOT), hits)
    intro = _doc("docs/TOOL-USAGE.md").split("<!-- BEGIN GENERATED: write-switches -->")[0]
    expected = "Writes are enabled by default; each area has its own write opt-out:"
    assert intro.rstrip().endswith(expected)


def test_migration_guide_makes_no_boolean_refusal_claim() -> None:
    text = _flat(_doc("docs/MIGRATING-0.7.md"))
    assert "a number for a boolean parameter is the one now refused" not in text
    assert "no longer matches `true`" not in text


@pytest.mark.asyncio
async def test_server_accepts_a_number_or_yes_for_a_boolean_parameter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Why the claim above was removed: the server coerces 1/0/"yes" for a boolean."""
    up = uh.FakeUpstream()
    uh.install(monkeypatch, up, tool_mode="full")
    async with Client(server.mcp) as client:
        for value in (1, 0, "yes"):
            before = len(up.primary())
            result = await client.call_tool(
                "list_carrier_subscribers", {"suspended": value}, raise_on_error=False
            )
            assert "Invalid arguments" not in str(result.content), value
            assert len(up.primary()) > before, value
        refused = await client.call_tool(
            "list_carrier_subscribers", {"suspended": "maybe"}, raise_on_error=False
        )
        assert refused.is_error and "Invalid arguments" in str(refused.content)


def test_read_only_note_states_credentials_are_returned_verbatim() -> None:
    assert _settings().redact_secrets is False
    text = _doc("docs/TOOL-USAGE.md")
    note = _flat(text[text.index("- **Read-only tools**") : text.index("- **Read-only mode**")])
    assert "safe to call freely" not in note
    assert "verbatim" in note and "UNIFI_REDACT_SECRETS" in note
    assert "CONFIGURATION.md#credential-redaction" in note
    assert "## Credential redaction" in _doc("docs/CONFIGURATION.md")
    catalog = tools_by_name()
    for name in re.findall(r"`((?:get|list)_[a-z_]+)`", note):
        assert name in catalog, name
        assert catalog[name].annotations.readOnlyHint is True, name


def test_blank_argument_note_names_the_checked_exception() -> None:
    assert "" not in SESSION_TYPES
    note = _flat(_doc("docs/TOOL-USAGE.md"))
    assert "A blank string or an empty list is never refused" not in note
    assert "`session_type` of `list_client_sessions`" in note
    assert "session_type" in tools_by_name()["list_client_sessions"].parameters["properties"]


def test_relay_status_and_audit_sentences_are_qualified() -> None:
    assert _settings().audit_log == ""
    text = _flat(_doc("docs/TOOL-USAGE.md"))
    for match in re.finditer(r"4xx/5xx[^.;]*?(?:reported|returned), not raised", text):
        assert "other than 429" in match.group(0), match.group(0)
    assert "Every attempt is written to the structured audit log" not in text
    assert _settings().audit_sink == ""
    assert "only when the opt-in audit stream is configured (`UNIFI_AUDIT_LOG` or " in text


def test_coverage_innerspace_and_key_label_statements_match_the_catalog() -> None:
    text = _flat(_doc("docs/COVERAGE.md"))
    innerspace = text[text.index("- **InnerSpace:**") : text.index("- **Access:**")]
    assert "All eight Integration-API InnerSpace read tools" in innerspace
    assert "deprecated" not in innerspace

    catalog: dict[str, Any] = tools_by_name()
    msp = text[text.index("**Multi-key MSP:**") :]
    msp = msp[: msp.index("See [Multi-key MSP setup]")]
    listed, rest = msp.split("iterate all keys unless a `key_label` argument names one", 1)
    with_label = re.findall(r"`([a-z_]+)`", listed[listed.index("The multi-key tools") :])
    without_label = re.findall(r"`([a-z_]+)`", rest[: rest.index("always iterate all keys")])
    assert with_label and without_label
    with_label = [n for n in with_label if n != "host"]
    for name in with_label:
        assert "key_label" in catalog[name].parameters["properties"], name
    for name in without_label:
        if name == "key_label":
            continue
        assert "key_label" not in catalog[name].parameters["properties"], name
