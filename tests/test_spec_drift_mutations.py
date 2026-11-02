"""Prove each compatibility regression rejects its original defect class."""

import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType

import pytest

from tests import test_spec_drift_review as review

_MUTATIONS = [
    (
        "unsupported-keyword",
        "return {\n        key\n        for key in (schema_keywords(old) | schema_keywords(new))\n"
        "        - SUPPORTED_KEYWORDS\n        - {_RAW_REVIEW_MARKER}\n        - _ANNOTATIONS\n"
        '        if not key.startswith("x-")\n    }',
        "return set()",
    ),
    (
        "optional-parameter-introduction",
        'if name not in before_params and not param.get("required"):',
        "if False:",
    ),
    (
        "inapplicable-restriction",
        "return {key: value for key, value in schema.items() if key not in ignored}",
        "return dict(schema)",
    ),
    (
        "removed-tuple-position",
        "for index in range(count):",
        "for index in range(len(after)):",
    ),
    (
        "reference-siblings",
        'return {"allOf": [expanded, sibling_schema]}',
        "return {**expanded, **sibling_schema}",
    ),
    (
        "tightening",
        "if _json(old) == _json(new) or old is False or new is True:",
        "if True:",
    ),
    (
        "response-direction",
        'return _tightens(new, old) if direction == "response" else _tightens(old, new)',
        "return _tightens(old, new)",
    ),
    (
        "literal-mapping-keys",
        "return {\n"
        "            key: _normalize_schema(child, document, trail, depth=depth + 1)\n"
        "            for key, child in value.items()\n"
        "        }",
        "return {key: _normalize_schema(child, document, trail, depth=depth + 1) "
        "for key, child in value.items() if key not in _ANNOTATIONS}",
    ),
    (
        "response-headers",
        'if isinstance(response, Mapping) and isinstance(response.get("headers"), Mapping):',
        "if False and isinstance(response, Mapping) "
        'and isinstance(response.get("headers"), Mapping):',
    ),
    (
        "request-widening",
        'if key == "allOf":\n            if len(after_left)',
        'if key == "allOf":\n            if len(before_left) > len(after_left):\n'
        "                return True\n            if len(after_left)",
    ),
]


def _case(name):
    if name == "unsupported-keyword":
        return review._document({}), review._document({"contains": True}), True
    if name == "optional-parameter-introduction":
        old = review._document({})
        new = deepcopy(old)
        new["paths"]["/widgets"]["post"]["parameters"] = [
            {"name": "q", "in": "query", "schema": {"type": "string"}}
        ]
        return old, new, False
    if name == "inapplicable-restriction":
        return (
            review._document({"type": "string"}),
            review._document({"type": "string", "minimum": 1}),
            False,
        )
    if name == "removed-tuple-position":
        return (
            review._document({"prefixItems": [{"type": "integer"}], "items": False}),
            review._document({"items": False}),
            True,
        )
    if name == "reference-siblings":
        old = review._document({"$ref": "#/components/schemas/Base", "minLength": 1})
        old["components"] = {"schemas": {"Base": {"type": "string", "minLength": 2}}}
        new = deepcopy(old)
        new["components"]["schemas"]["Base"]["minLength"] = 3
        return old, new, True
    if name == "tightening":
        return review._document({"minimum": 0}), review._document({"minimum": 1}), True
    if name == "response-direction":
        return (
            review._document({"enum": ["a"]}, "response"),
            review._document({"enum": ["a", "b"]}, "response"),
            True,
        )
    if name == "literal-mapping-keys":
        return (
            review._document({"properties": {"description": {"minLength": 1}}}),
            review._document({"properties": {"description": {"minLength": 2}}}),
            True,
        )
    if name == "response-headers":
        return (
            review._document({"enum": ["a"]}, "header"),
            review._document({"enum": ["a", "b"]}, "header"),
            True,
        )
    return (
        review._document({"allOf": [{"minimum": 0}, {"maximum": 10}]}),
        review._document({"allOf": [{"minimum": 0}]}),
        False,
    )


@pytest.mark.parametrize(
    ("name", "anchor", "replacement"), _MUTATIONS, ids=[m[0] for m in _MUTATIONS]
)
def test_source_mutation_is_killed_and_reverted(name, anchor, replacement, monkeypatch):
    source = Path(__file__).resolve().parents[1] / "src/unifi_fabric/_spec_drift.py"
    original = source.read_text()
    assert original.count(anchor) == 1, "Update the mutation anchor after a source refactor."
    old, new, breaks = _case(name)
    review._assert_delta(old, new, breaks)

    # Execute a source mutant in an isolated module. No on-disk source or shared
    # services change; the same public-API behavioral assertion must kill it.
    module = ModuleType("unifi_fabric._spec_drift_mutant")
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, module.__name__, module)
        exec(  # noqa: S102 -- isolated mutation of repository-owned source.
            compile(original.replace(anchor, replacement, 1), str(source), "exec"), module.__dict__
        )
        # Isolate directional semantics from the independently mutation-tested
        # raw-document safety net, which intentionally catches several old misses.
        patch.setattr(module, "_document_findings", lambda *args: [])
        patch.setattr(review, "build_service_spec", module.build_service_spec)
        patch.setattr(review, "diff_service", module.diff_service)
        with pytest.raises(AssertionError):
            review._assert_delta(old, new, breaks)

    review._assert_delta(old, new, breaks)
    assert source.read_text() == original
