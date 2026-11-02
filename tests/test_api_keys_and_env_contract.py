"""Strict API-key entries, documented environment variables that the
code really reads, ``\\Z``-anchored validation regexes, the README pagination contract,
and the singular / upper-cased rate-limit message.

The empty-update guard on the sanitized body (bq), selector syntax before any request
(bt) and the ``_key_labels`` semantics (i) are cross-tool invariants in
``test_cross_tool_chokepoints`` / ``test_cross_tool_invariants``; the INSTRUCTIONS scope
buckets are checked against required-vs-optional in ``test_instructions_audit``.
"""

from __future__ import annotations

import ast
import inspect
import io
import json
import pathlib
import re
import tokenize

import fastmcp
import pytest
import respx
from httpx import Response
from pydantic import BaseModel, ValidationError

from unifi_fabric import config
from unifi_fabric.client import RateLimitError, UniFiClient
from unifi_fabric.config import APIKeyConfig, MCPTransportSettings, Settings

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "unifi_fabric"
BASE = "https://api.ui.com"


# ================================================================ 5: strict key entries
def test_api_key_config_forbids_unknown_fields():
    with pytest.raises(ValidationError, match="lbl"):
        APIKeyConfig(key="k-test", lbl="alpha")


def test_unknown_field_in_unifi_api_keys_names_the_entry_not_the_field(monkeypatch):
    """The entry and the allowed fields are named; the unknown field name is only
    counted (a key pasted as a mapping key must not be printed)."""
    monkeypatch.delenv("UNIFI_API_KEY", raising=False)
    monkeypatch.setenv(
        "UNIFI_API_KEYS",
        json.dumps(
            [
                {"key": "k-first", "label": "a"},
                {"key": "k-second-value", "label": "b", "is_org": True},
            ]
        ),
    )
    with pytest.raises(ValidationError) as exc:
        Settings()
    text = str(exc.value)
    assert "UNIFI_API_KEYS[1] has 1 unknown field(s)" in text, text
    assert "'is_org'" not in text, "the unknown field name is never echoed"
    assert "'is_org_key'" in text, "the allowed fields are named"
    assert "k-second-value" not in text, "the key value is never echoed"


def test_every_config_model_forbids_unknown_fields():
    models = [
        obj
        for _name, obj in inspect.getmembers(config, inspect.isclass)
        if issubclass(obj, BaseModel) and obj.__module__ == config.__name__
    ]
    assert {APIKeyConfig, Settings, MCPTransportSettings} <= set(models), models
    loose = [m.__name__ for m in models if m.model_config.get("extra") != "forbid"]
    assert loose == [], f"config models that silently ignore unknown fields: {loose}"


# ============================================ 7: every documented env var is really read
# Public docs only: internal docs are removed from the public artifact and keep historical
# diagnosis notes that name variables on purpose (a removed switch, a gateway secret).
_PUBLIC_DOCS = [ROOT / "README.md", ROOT / "CONTRIBUTING.md", *sorted((ROOT / "docs").glob("*.md"))]
_ENV_NAME = re.compile(r"\b((?:UNIFI|MCP|FASTMCP)_[A-Z0-9_]*[A-Z0-9_])")


def _documented_env_names() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for doc in _PUBLIC_DOCS:
        for name in _ENV_NAME.findall(doc.read_text()):
            found.setdefault(name, []).append(doc.name)
    return found


def _without_comments(source: str) -> str:
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    return tokenize.untokenize(token for token in tokens if token.type != tokenize.COMMENT)


def test_env_read_scan_ignores_comments():
    source = _without_comments('# UNIFI_SYNTHETIC_UNUSED\nvalue = "UNIFI_ACTUAL_LITERAL"\n')
    assert not _is_read("UNIFI_SYNTHETIC_UNUSED", source, "")
    assert _is_read("UNIFI_ACTUAL_LITERAL", source, "")


def _source_text(*roots: pathlib.Path) -> str:
    return "\n".join(
        _without_comments(p.read_text())
        for root in roots
        for p in sorted(root.rglob("*.py"))
        if ".venv" not in p.parts
    )


def _is_read(name: str, src: str, tests: str) -> bool:
    """True when the code reads ``name`` (a settings field, or the literal name)."""
    prefix_family = name.endswith("_")  # e.g. MCP_TLS_* in prose
    if re.search(rf"\b{re.escape(name)}" + ("" if prefix_family else r"\b"), src):
        return True
    if name.startswith("UNIFI_TEST_"):  # the live-test console/site, read by the tests
        return bool(re.search(rf"\b{re.escape(name)}\b", tests))
    for prefix, fields in (
        ("UNIFI_", Settings.model_fields),
        ("MCP_", MCPTransportSettings.model_fields),
        ("FASTMCP_", type(fastmcp.settings).model_fields),
    ):
        if name.startswith(prefix):
            field = name[len(prefix) :].lower()
            if prefix_family:
                return any(f.startswith(field) for f in fields)
            return field in fields
    return False


def test_documented_env_vars_are_found():
    names = _documented_env_names()
    assert {"UNIFI_API_KEY", "UNIFI_API_KEYS", "MCP_BEARER_TOKEN", "FASTMCP_TRANSPORT"} <= set(
        names
    ), sorted(names)


def test_every_documented_env_var_is_read_by_the_code():
    src = _source_text(SRC)
    tests = _source_text(ROOT / "tests")
    unread = {
        name: docs
        for name, docs in sorted(_documented_env_names().items())
        if not _is_read(name, src, tests)
    }
    assert unread == {}, f"documented environment variables nothing reads: {unread}"


def test_the_removed_verify_ssl_switch_is_not_documented():
    assert "UNIFI_API_VERIFY_SSL" not in _documented_env_names()


# =========================================== 7: README pagination text matches the code
def test_readme_names_the_real_cursor_field():
    readme = (ROOT / "README.md").read_text()
    paging = (ROOT / "docs" / "PAGINATION.md").read_text()
    assert "nextPageToken" not in readme and "nextPageToken" not in paging
    assert "return a `nextToken`" in paging


def _settings() -> Settings:
    return Settings(api_key="sk-env-contract-test")


@respx.mock
async def test_an_empty_page_with_a_new_cursor_is_followed():
    """README: an empty page carrying a new, never-requested cursor is followed."""
    pages = [
        Response(200, json={"data": [{"id": "a"}], "nextToken": "t1"}),
        Response(200, json={"data": [], "nextToken": "t2"}),
        Response(200, json={"data": [{"id": "b"}]}),
    ]
    respx.get(f"{BASE}/v1/hosts").mock(side_effect=pages)
    items = await UniFiClient(_settings()).paginate("/v1/hosts")
    assert [i["id"] for i in items] == ["a", "b"]


@respx.mock
@pytest.mark.parametrize(
    ("tokens", "reason"),
    [(["t1", "t1"], "stall detected"), (["t1", "t2", "t1"], "cursor cycle detected")],
)
async def test_stall_and_cycle_end_with_the_pages_gathered(tokens, reason):
    from unifi_fabric.client import PaginationAbortedError

    pages = [
        Response(200, json={"data": [{"id": f"r{i}"}], "nextToken": t})
        for i, t in enumerate(tokens)
    ]
    respx.get(f"{BASE}/v1/hosts").mock(side_effect=pages)
    with pytest.raises(PaginationAbortedError) as exc:
        await UniFiClient(_settings()).paginate("/v1/hosts")
    assert reason in exc.value.reason and exc.value.items, exc.value.reason


# ============================================= 8: no `$`-anchored validation regex
_RE_FUNCS = {
    "compile",
    "match",
    "fullmatch",
    "search",
    "sub",
    "subn",
    "findall",
    "finditer",
    "split",
}
_DOLLAR = re.compile(r"(?<!\\)\$")
_CHAR_CLASS = re.compile(r"\[(?:\\.|[^\]\\])*\]")


def _anchors_with_dollar(pattern: str) -> bool:
    """True when ``pattern`` uses ``$`` as an anchor (a ``$`` inside ``[...]`` is a literal)."""
    return "(?m" not in pattern and bool(_DOLLAR.search(_CHAR_CLASS.sub("", pattern)))


def _string_parts(node: ast.AST) -> list[ast.Constant]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node]
    if isinstance(node, ast.BinOp):
        return _string_parts(node.left) + _string_parts(node.right)
    if isinstance(node, ast.JoinedStr):
        return [p for v in node.values for p in _string_parts(v)]
    if isinstance(node, ast.Tuple | ast.List):
        return [p for e in node.elts for p in _string_parts(e)]
    return []


def _multiline(call: ast.Call) -> bool:
    flags = " ".join(ast.unparse(a) for a in [*call.args[1:], *(k.value for k in call.keywords)])
    return bool(re.search(r"re\.(M|MULTILINE)\b", flags))


def _dollar_anchored_patterns() -> list[str]:
    """Package-code regex literals (re.* calls and ``"^..." + ... + "$"`` pattern
    strings) that use ``$`` without MULTILINE: ``$`` also matches before a trailing
    newline, so ``"value\\n"`` would pass a ``$``-anchored validation."""
    # Test regexes can parse release-note prose; only package code validates callers.
    hits: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        if {".venv", "__pycache__", ".git"} & set(path.parts):
            continue
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            parts: list[ast.Constant] = []
            if isinstance(node, ast.Call):
                f = node.func
                if (
                    isinstance(f, ast.Attribute)
                    and f.attr in _RE_FUNCS
                    and isinstance(f.value, ast.Name)
                    and f.value.id == "re"
                    and node.args
                    and not _multiline(node)
                ):
                    parts += _string_parts(node.args[0])
                parts += [
                    p for k in node.keywords if k.arg == "match" for p in _string_parts(k.value)
                ]
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                pieces = _string_parts(node)
                if pieces and pieces[0].value.startswith("^") and pieces[-1].value == "$":
                    parts.append(pieces[-1])
            for part in parts:
                if _anchors_with_dollar(part.value):
                    hits.append(f"{path.relative_to(ROOT)}:{part.lineno}: {part.value[-40:]!r}")
    return sorted(set(hits))


def test_no_validation_regex_is_anchored_with_dollar():
    assert _dollar_anchored_patterns() == [], "use \\Z, not $, to anchor a validation regex"


def test_the_dollar_scan_catches_the_defect_class(tmp_path):
    sample = (
        'import re\nX = re.compile(r"^[a-f0-9]{8}$")\nY = re.compile(r"^a$", re.M)\n'
        'Z = re.compile(r"^[a$b]+\\Z")\n'
    )
    tree = ast.parse(sample)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.args]
    flagged = [
        c
        for c in calls
        if not _multiline(c)
        and any(_anchors_with_dollar(p.value) for p in _string_parts(c.args[0]))
    ]
    assert len(flagged) == 1


class TestCallerValidationRegexGate:
    def test_changelog_prose_regex_is_not_caller_validation(self, tmp_path, monkeypatch):
        source = tmp_path / "src" / "unifi_fabric"
        source.mkdir(parents=True)
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_release_notes.py").write_text(
            'import re\nre.search(r"Affected tools: (.*?)\\.(?: |$)", changelog)\n'
        )
        monkeypatch.setitem(_dollar_anchored_patterns.__globals__, "ROOT", tmp_path)
        monkeypatch.setitem(_dollar_anchored_patterns.__globals__, "SRC", source)
        assert _dollar_anchored_patterns() == []

    def test_caller_validation_dollar_anchor_still_fails(self, tmp_path, monkeypatch):
        source = tmp_path / "src" / "unifi_fabric"
        source.mkdir(parents=True)
        (source / "validation.py").write_text(
            'import re\nBAD = re.compile(r"^SYNTHETIC_SENTINEL_731902$")\n'
            'GOOD = re.compile(r"^SYNTHETIC_SENTINEL_731902\\Z")\n'
            'MULTILINE = re.compile(r"^SYNTHETIC_SENTINEL_731902$", re.M)\n'
        )
        monkeypatch.setitem(_dollar_anchored_patterns.__globals__, "ROOT", tmp_path)
        monkeypatch.setitem(_dollar_anchored_patterns.__globals__, "SRC", source)
        hits = _dollar_anchored_patterns()
        assert len(hits) == 1
        assert hits[0].startswith("src/unifi_fabric/validation.py:2:")


def test_uuid_validation_rejects_a_trailing_newline():
    from unifi_fabric.registry import _assert_uuid

    with pytest.raises(ValueError, match="not a UUID"):
        _assert_uuid("3fa85f64-5717-4562-b3fc-2c963f66afa6\n")


# ============================================================ NITs: rate-limit message
@respx.mock
async def test_rate_limit_message_is_singular_and_upper_cased():
    respx.post(f"{BASE}/v1/x").mock(return_value=Response(429, text="slow down"))
    with pytest.raises(RateLimitError) as exc:
        await UniFiClient(_settings()).request("post", "/v1/x", json={"a": 1})
    assert "after 1 attempt on POST /v1/x" in str(exc.value), str(exc.value)


@respx.mock
async def test_rate_limit_message_plural_for_several_attempts(monkeypatch):
    async def _no_sleep(_delay):
        return None

    monkeypatch.setattr("asyncio.sleep", _no_sleep)
    respx.get(f"{BASE}/v1/x").mock(return_value=Response(429))
    with pytest.raises(RateLimitError) as exc:
        await UniFiClient(_settings()).request("get", "/v1/x", max_retries=2)
    assert "after 3 attempts on GET /v1/x" in str(exc.value), str(exc.value)
