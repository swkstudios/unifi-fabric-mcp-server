"""scripts/docs_impact.py: extraction and doc matching from fixture diffs, no network."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("docs_impact", ROOT / "scripts" / "docs_impact.py")
assert _spec and _spec.loader
di = importlib.util.module_from_spec(_spec)
sys.modules["docs_impact"] = di
_spec.loader.exec_module(di)

OLD_TOOL = """import x


@mcp.tool(annotations=WRITE)
async def reorder_firewall_policies(host: str) -> dict:
    if not host:
        raise ValueError("host is required to reorder firewall policies")
    return {}


class PolicyCursor:
    pass
"""
NEW_TOOL = """import x


@mcp.tool(annotations=READ_ONLY)
async def reorder_firewall_policies(host: str) -> dict:
    if not host:
        raise ValueError("host must name a known console before reordering policies")
    return {"annotations": {"readOnlyHint": True}}


class PolicyCursor:
    pass
"""
TOOL_DIFF = """\
diff --git a/src/unifi_fabric/tools/fw.py b/src/unifi_fabric/tools/fw.py
--- a/src/unifi_fabric/tools/fw.py
+++ b/src/unifi_fabric/tools/fw.py
@@ -4 +4 @@
-@mcp.tool(annotations=WRITE)
+@mcp.tool(annotations=READ_ONLY)
@@ -7,2 +7,2 @@
-        raise ValueError("host is required to reorder firewall policies")
-    return {}
+        raise ValueError("host must name a known console before reordering policies")
+    return {"annotations": {"readOnlyHint": True}}
"""
OLD_CONFIG = """from pydantic import Field


class Settings:
    page_size: int = Field(default=100, description="Rows per page.")
    log_level: str = "INFO"
    api_key: str = Field(default="", repr=False)
"""
NEW_CONFIG = OLD_CONFIG.replace("default=100", "default=250").replace('"INFO"', '"INFO"')
CONFIG_DIFF = """\
diff --git a/src/unifi_fabric/config.py b/src/unifi_fabric/config.py
--- a/src/unifi_fabric/config.py
+++ b/src/unifi_fabric/config.py
@@ -4 +4 @@ class Settings:
-    page_size: int = Field(default=100, description="Rows per page.")
+    page_size: int = Field(default=250, description="Rows per page.")
"""
ENV_DIFF = """\
diff --git a/src/unifi_fabric/other.py b/src/unifi_fabric/other.py
--- a/src/unifi_fabric/other.py
+++ b/src/unifi_fabric/other.py
@@ -1 +1,2 @@
+# UNIFI_IGNORED_IN_COMMENT
+TOKEN = os.environ["UNIFI_NEW_SWITCH"]
diff --git a/tests/test_other.py b/tests/test_other.py
--- a/tests/test_other.py
+++ b/tests/test_other.py
@@ -1 +1,2 @@
+X = "UNIFI_ONLY_IN_TESTS"
"""


def files(mapping):
    def read(side, path):
        return mapping.get((side, path))

    return read


def tool_files():
    return files(
        {
            ("old", "src/unifi_fabric/tools/fw.py"): OLD_TOOL,
            ("new", "src/unifi_fabric/tools/fw.py"): NEW_TOOL,
        }
    )


def labels(extraction):
    return {s.label for s in extraction.symbols}


def test_parse_diff_numbers_each_side():
    lines = di.parse_diff(TOOL_DIFF)
    assert [(d.side, d.number) for d in lines] == [
        ("old", 4),
        ("new", 4),
        ("old", 7),
        ("old", 8),
        ("new", 7),
        ("new", 8),
    ]
    assert all(d.path == "src/unifi_fabric/tools/fw.py" for d in lines)


def test_extracts_function_message_and_annotation_changes():
    found = di.extract(TOOL_DIFF, tool_files())
    got = labels(found)
    assert "function:reorder_firewall_policies" in got
    assert "class:PolicyCursor" not in got  # untouched class
    assert "annotation:readOnlyHint" in got
    assert "annotation:READ_ONLY on reorder_firewall_policies" in got
    assert "annotation:WRITE on reorder_firewall_policies" in got
    assert "message:host is required to reorder firewall policies" in got
    assert "message:host must name a known console before reordering policies" in got
    assert "env:UNIFI_API_KEY" not in got


def test_changed_default_names_the_variable_and_both_values():
    found = di.extract(
        CONFIG_DIFF,
        files(
            {
                ("old", "src/unifi_fabric/config.py"): OLD_CONFIG,
                ("new", "src/unifi_fabric/config.py"): NEW_CONFIG,
            }
        ),
    )
    default = next(s for s in found.symbols if s.kind == "default")
    assert default.name == "UNIFI_PAGE_SIZE"
    assert {"100", "250"} <= set(default.needs_any)
    assert "env:UNIFI_PAGE_SIZE" in labels(found)
    assert "env:UNIFI_LOG_LEVEL" not in labels(found)  # unchanged default


def test_env_vars_come_from_code_lines_in_source_only():
    got = labels(di.extract(ENV_DIFF, files({})))
    assert got == {"env:UNIFI_NEW_SWITCH"}


def test_removed_and_renamed_tools_are_found_on_the_old_side():
    diff = """\
diff --git a/src/unifi_fabric/tools/fw.py b/src/unifi_fabric/tools/fw.py
--- a/src/unifi_fabric/tools/fw.py
+++ b/src/unifi_fabric/tools/fw.py
@@ -5,4 +4,0 @@
-async def reorder_firewall_policies(host: str) -> dict:
-    if not host:
-        return {}
"""
    found = di.extract(diff, files({("old", "src/unifi_fabric/tools/fw.py"): OLD_TOOL}))
    assert "function:reorder_firewall_policies" in labels(found)


def test_private_generic_and_prose_names_do_not_match():
    symbols = di.Extraction()
    for name in ("_private_helper", "setup", "run"):
        assert not di._usable_name(name)
    symbols.add(di.Symbol("function", "wait_until"), "x")
    symbols.add(di.Symbol("function", "Reorder"), "x")
    docs = {
        "a.md": [
            "Wait until the console answers.",
            "Call `wait_until` for it.",
            "wait_until is mentioned bare",
            "Reorder the list, then `Reorder(` is code",
            "Reorder the list.",
        ]
    }
    hits = {(h.line, h.symbol.name) for h in di.find_hits(symbols, docs)}
    assert hits == {(2, "wait_until"), (3, "wait_until"), (4, "Reorder")}


def test_default_hits_need_the_variable_and_a_value():
    symbols = di.Extraction()
    symbols.add(di.Symbol("default", "UNIFI_PAGE_SIZE", ("100", "250")), "x")
    docs = {
        "d.md": [
            "`UNIFI_PAGE_SIZE` defaults to 100.",
            "`UNIFI_PAGE_SIZE` sets the page size.",
            "The limit is 100 rows.",
        ]
    }
    assert [h.line for h in di.find_hits(symbols, docs)] == [1]


def test_message_and_annotation_hits():
    found = di.extract(TOOL_DIFF, tool_files())
    docs = {
        "m.md": [
            "Error: `host is required to reorder firewall policies`",
            "reorder_firewall_policies has readOnlyHint false.",
            "unrelated line",
        ]
    }
    got = {(h.line, h.symbol.label) for h in di.find_hits(found, docs)}
    assert (1, "message:host is required to reorder firewall policies") in got
    assert (2, "annotation:readOnlyHint") in got
    assert (2, "annotation:WRITE on reorder_firewall_policies") in got
    assert (2, "function:reorder_firewall_policies") in got
    assert not any(line == 3 for line, _ in got)


def test_markdown_scope_skips_history():
    tracked = ["README.md", "CHANGELOG.md", "changelog.d/x.md", "docs/a.MD", "src/a.py"]
    assert di.markdown_files(ROOT, tracked) == ["README.md", "docs/a.MD"]


def test_json_and_text_group_by_doc_then_symbol():
    found = di.extract(TOOL_DIFF, tool_files())
    docs = {"docs/T.md": ["`reorder_firewall_policies` reorders."], "docs/U.md": ["none"]}
    hits = di.find_hits(found, docs)
    data = json.loads(json.dumps(di.to_json("b", "h", found, hits)))
    assert data["counts"] == {"docs/T.md": 1}
    assert data["docs"]["docs/T.md"]["function:reorder_firewall_policies"] == [
        {"line": 1, "text": "`reorder_firewall_policies` reorders."}
    ]
    text = di.to_text("b", "h", found, hits)
    assert "docs/T.md (1)" in text and "  function:reorder_firewall_policies" in text
    assert "No Markdown line" in di.to_text("b", "h", found, [])


class FakeClient:
    def __init__(self, answer, fail=False):
        self.answer, self.fail, self.prompts = answer, fail, []
        self.messages = self

    def create(self, **kwargs):
        self.prompts.append(kwargs["messages"][0]["content"])
        assert kwargs["model"] == "claude-haiku-5-5"
        if self.fail:
            raise RuntimeError("secret-looking message must not be printed")

        class Block:
            text = self.answer

        class Reply:
            content = [Block()]

        return Reply()


def _adjudication_inputs():
    found = di.extract(TOOL_DIFF, tool_files())
    docs = {"docs/T.md": ["`reorder_firewall_policies` is a write tool."]}
    hits = [
        h
        for h in di.find_hits(found, docs)
        if h.symbol.label == "function:reorder_firewall_policies"
    ]
    return found, docs, hits, di.parse_diff(TOOL_DIFF)


def test_adjudication_accepts_only_a_quoted_diff_line():
    found, docs, hits, diff = _adjudication_inputs()
    good = FakeClient(
        json.dumps(
            {
                "verdict": "stale",
                "evidence": "@mcp.tool(annotations=READ_ONLY)",
                "reason": "now a read tool",
            }
        )
    )
    (line,) = di.adjudicate(hits, docs, found, diff, good)
    assert line.startswith("docs/T.md:1 [function:reorder_firewall_policies]: stale")
    assert "READ_ONLY" in good.prompts[0] and "is a write tool" in good.prompts[0]
    bad = FakeClient('{"verdict": "matches", "evidence": "invented line", "reason": "r"}')
    (line,) = di.adjudicate(hits, docs, found, diff, bad)
    assert "unverified matches" in line


def test_adjudication_failures_are_reported_without_the_message():
    found, docs, hits, diff = _adjudication_inputs()
    (line,) = di.adjudicate(hits, docs, found, diff, FakeClient("", fail=True))
    assert "adjudication unavailable (RuntimeError)" in line
    assert "secret" not in line
    (line,) = di.adjudicate(hits, docs, found, diff, FakeClient("not json"))
    assert "unclear" in line


def test_make_client_needs_the_environment_key_only(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client, why = di.make_client()
    assert client is None and "ANTHROPIC_API_KEY" in why


def test_main_is_advisory_and_runs_on_a_real_repository(capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert di.main(["--base", "HEAD", "--head", "HEAD", "--adjudicate"]) == 0
    out = capsys.readouterr().out
    assert "0 changed symbols" in out and "Adjudication skipped" in out


def test_whole_file_deletion_reports_symbol_and_doc_hit():
    diff = """diff --git a/src/unifi_fabric/demo.py b/src/unifi_fabric/demo.py
--- a/src/unifi_fabric/demo.py
+++ /dev/null
@@ -1,2 +0,0 @@
-def important_tool():
-    pass
"""
    extraction = di.extract(
        diff, files({("old", "src/unifi_fabric/demo.py"): "def important_tool():\n    pass\n"})
    )
    assert "function:important_tool" in labels(extraction)
    assert di.find_hits(extraction, {"docs/demo.md": ["Use important_tool here."]})
