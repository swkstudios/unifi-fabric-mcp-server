"""scripts/check_family_imports.py: AST resolver, allowlist, cycle and real-tree checks."""

from __future__ import annotations

import importlib.util
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "check_family_imports", ROOT / "scripts" / "check_family_imports.py"
)
assert _spec and _spec.loader
cfi = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cfi  # dataclasses resolve their module
_spec.loader.exec_module(cfi)

FAM = "unifi_fabric.families"


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    """Write a synthetic repo: files keyed by path under src/unifi_fabric."""
    base = tmp_path / "src" / "unifi_fabric"
    base.mkdir(parents=True)
    (base / "__init__.py").write_text("")
    (base / "families").mkdir()
    (base / "families" / "__init__.py").write_text("FAMILY_HELPER = 1\n")
    for fam in ("alpha", "beta", "gamma"):
        (base / "families" / fam).mkdir()
        (base / "families" / fam / "__init__.py").write_text("")
        (base / "families" / fam / f"{fam}.py").write_text("")
    for rel, text in files.items():
        path = base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return tmp_path


def _edges(tmp_path: Path, files: dict[str, str]) -> list:
    return cfi.scan(_tree(tmp_path, files))


def test_relative_from_import_is_family_to_family(tmp_path):
    edges = _edges(tmp_path, {"families/alpha/a.py": "from ..beta import beta\n"})
    assert [(e.kind, e.imported, e.names, e.level) for e in edges] == [
        ("family-to-family", f"{FAM}.beta.beta", (), "module")
    ] or [(e.kind, e.imported, e.names) for e in edges] == [
        ("family-to-family", f"{FAM}.beta.beta", ())
    ]


def test_relative_from_import_names_of_a_module(tmp_path):
    edges = _edges(tmp_path, {"families/alpha/a.py": "from ..beta.beta import x, y\n"})
    assert len(edges) == 1
    assert edges[0].kind == "family-to-family"
    assert edges[0].imported == f"{FAM}.beta.beta"
    assert edges[0].names == ("x", "y")
    assert edges[0].importer_family == "alpha"


def test_function_level_import_is_flagged_function(tmp_path):
    src = "class C:\n    def m(self):\n        if True:\n            from ..beta import beta\n"
    edges = _edges(tmp_path, {"families/alpha/a.py": src})
    assert [e.level for e in edges] == ["function"]
    result = cfi.evaluate(edges, Counter())
    assert len(result.violations) == 1


def test_function_level_family_edge_is_not_allowlistable(tmp_path):
    edges = _edges(tmp_path, {"families/alpha/a.py": "def f():\n    from ..beta.beta import x\n"})
    allow = cfi.parse_allowlist(cfi.render_allowlist(edges))
    assert len(cfi.evaluate(edges, allow).violations) == 1


def test_importlib_literal(tmp_path):
    src = (
        "import importlib\n"
        "importlib.import_module('unifi_fabric.families.beta.beta')\n"
        "def f():\n    return importlib.import_module('..beta.beta', package=__name__)\n"
        "def g():\n"
        "    return importlib.import_module('..beta.beta', 'unifi_fabric.families.alpha')\n"
    )
    edges = _edges(tmp_path, {"families/alpha/a.py": src})
    # the package=__name__ call is not a literal, so it is not resolved
    assert [(e.lineno, e.via, e.imported) for e in edges] == [
        (2, "importlib", f"{FAM}.beta.beta"),
        (6, "importlib", f"{FAM}.beta.beta"),
    ]


def test_dunder_import_literal(tmp_path):
    edges = _edges(tmp_path, {"core.py": "x = __import__('unifi_fabric.families.alpha.alpha')\n"})
    assert [(e.kind, e.via, e.imported) for e in edges] == [
        ("core-to-family", "importlib", f"{FAM}.alpha.alpha")
    ]


def test_plain_import_statement(tmp_path):
    edges = _edges(tmp_path, {"families/alpha/a.py": "import unifi_fabric.families.beta.beta\n"})
    assert [(e.via, e.imported, e.names) for e in edges] == [("import", f"{FAM}.beta.beta", ())]


def test_from_dotdot_import_family_package(tmp_path):
    edges = _edges(tmp_path, {"families/alpha/a.py": "from .. import beta, gamma\n"})
    assert sorted((e.kind, e.imported) for e in edges) == [
        ("family-to-family", f"{FAM}.beta"),
        ("family-to-family", f"{FAM}.gamma"),
    ]


def test_same_family_import_is_intra(tmp_path):
    files = {
        "families/alpha/a.py": "from . import b\nfrom .b import z\n",
        "families/alpha/b.py": "",
    }
    edges = _edges(tmp_path, files)
    assert {e.kind for e in edges} == {"intra-family"}
    assert cfi.evaluate(edges, Counter()).ok


def test_non_family_to_family(tmp_path):
    files = {
        "server.py": "from .families import alpha\n",
        "sub/pkg.py": "from ..families.beta.beta import thing\n",
    }
    edges = _edges(tmp_path, files)
    assert sorted((e.importer, e.kind, e.imported) for e in edges) == [
        ("unifi_fabric.server", "core-to-family", f"{FAM}.alpha"),
        ("unifi_fabric.sub.pkg", "core-to-family", f"{FAM}.beta.beta"),
    ]
    assert len(cfi.evaluate(edges, Counter()).violations) == 2


def test_families_package_root_attribute_is_not_an_edge(tmp_path):
    files = {
        "server.py": "from .families import FAMILY_HELPER\n",
        "families/alpha/a.py": (
            "from .. import FAMILY_HELPER\nfrom unifi_fabric.families import FAMILY_HELPER\n"
        ),
    }
    assert _edges(tmp_path, files) == []


def test_exemptions_are_honored(tmp_path):
    files = {
        "catalog/loaders.py": "from ..families.alpha import alpha\n",
        "placement_snapshot_cli.py": "from .families.beta.beta import x\n",
        "other.py": "from .families.beta.beta import x\n",
    }
    edges = _edges(tmp_path, files)
    assert [e.importer for e in edges] == ["unifi_fabric.other"]


def test_real_exemption_paths_exist():
    for rel in cfi.EXEMPT_FILES:
        assert (ROOT / rel).is_file(), rel


def test_cycle_detection(tmp_path):
    files = {
        "families/alpha/a.py": "from ..beta import b\n",
        "families/beta/b.py": "from ..alpha import a\n",
    }
    edges = _edges(tmp_path, files)
    assert cfi.disallowed_cycles(edges) == [frozenset({f"{FAM}.alpha.a", f"{FAM}.beta.b"})]


def test_function_level_import_does_not_make_a_cycle(tmp_path):
    files = {
        "families/alpha/a.py": "from ..beta import b\n",
        "families/beta/b.py": "def f():\n    from ..alpha import a\n",
    }
    assert cfi.disallowed_cycles(_edges(tmp_path, files)) == []


def test_allowed_network_cycle_pair(tmp_path, monkeypatch):
    files = {
        "families/alpha/a.py": "from . import b\n",
        "families/alpha/b.py": "from . import a\n",
    }
    edges = _edges(tmp_path, files)
    pair = frozenset({f"{FAM}.alpha.a", f"{FAM}.alpha.b"})
    assert cfi.find_cycles(edges) == [pair]
    monkeypatch.setattr(cfi, "ALLOWED_CYCLES", frozenset({pair}))
    assert cfi.disallowed_cycles(edges) == []


def test_allowlist_matches_without_line_numbers(tmp_path):
    root = _tree(tmp_path, {"families/alpha/a.py": "from ..beta.beta import x\n"})
    allow = cfi.parse_allowlist(cfi.render_allowlist(cfi.scan(root)))
    (root / "src/unifi_fabric/families/alpha/a.py").write_text(
        "\n\n# moved\nfrom ..beta.beta import x\n"
    )
    assert cfi.evaluate(cfi.scan(root), allow).ok


def test_allowlist_line_format(tmp_path):
    edges = _edges(tmp_path, {"families/alpha/a.py": "from ..beta.beta import y, x\n"})
    assert cfi.render_allowlist(edges).splitlines()[-1] == (
        f"{FAM}.alpha.a -> {FAM}.beta.beta: x,y  # L1-C alpha"
    )


def test_stale_allowlist_entry_fails(tmp_path):
    root = _tree(tmp_path, {"families/alpha/a.py": "from ..beta.beta import x\n"})
    allow = cfi.parse_allowlist(cfi.render_allowlist(cfi.scan(root)))
    (root / "src/unifi_fabric/families/alpha/a.py").write_text("")
    result = cfi.evaluate(cfi.scan(root), allow)
    assert not result.ok
    assert result.stale == [(f"{FAM}.alpha.a", f"{FAM}.beta.beta", ("x",))]
    assert result.violations == []


def test_new_edge_not_in_allowlist_fails(tmp_path):
    edges = _edges(tmp_path, {"families/alpha/a.py": "from ..beta.beta import x\n"})
    result = cfi.evaluate(edges, Counter())
    assert [e.imported for e in result.violations] == [f"{FAM}.beta.beta"]


def test_main_strict_exit_codes(tmp_path):
    root = _tree(tmp_path, {"families/alpha/a.py": "from ..beta.beta import x\n"})
    allow = root / "allow.txt"
    assert cfi.main(["--root", str(root), "--allowlist", str(allow)]) == 1
    assert cfi.main(["--root", str(root), "--allowlist", str(allow), "--write-allowlist"]) == 0
    assert cfi.main(["--root", str(root), "--allowlist", str(allow)]) == 0
    assert cfi.main(["--root", str(root), "--report"]) == 0


@pytest.fixture(scope="module")
def real_edges():
    return cfi.scan(ROOT)


def test_real_tree_family_edges_are_allowlisted_and_acyclic(real_edges):
    edges = real_edges
    allow = cfi.parse_allowlist((ROOT / cfi.ALLOWLIST).read_text(encoding="utf-8"))
    result = cfi.evaluate(edges, allow)
    family_violations = [e for e in result.violations if e.kind != "core-to-family"]
    assert family_violations == []
    assert result.stale == []
    assert result.cycles == []


def test_real_tree_has_no_core_to_family_imports(real_edges):
    edges = real_edges
    core = [f"{e.file}:{e.lineno}" for e in edges if e.kind == "core-to-family"]
    assert core == []


# Review R-L1B C6: the seven seeded import forms. `check_family_imports.py` is the only D1
# gate, so each form must fail strict mode on its own, even with the top-level form's
# entry allowlisted (an L1-C edge that is still pending).
_ALLOWED_TOP_LEVEL = "from ..beta.beta import x\n"
SEEDED_FORMS = {
    "top-level": "from ..beta.beta import x, z\n",
    "function-level": "def f():\n    from ..beta.beta import x\n",
    "second-imported-name": "from ..beta.beta import x, y\n",
    "absolute": "from unifi_fabric.families.beta.beta import x\n",
    "families-package": "from ...families import beta\n",
    "importlib": "import importlib\n\nimportlib.import_module('unifi_fabric.families.beta.beta')\n",
    "type-checking": (
        "from typing import TYPE_CHECKING\n\nif TYPE_CHECKING:\n    from ..beta.beta import x\n"
    ),
}


@pytest.mark.parametrize("form", sorted(SEEDED_FORMS))
def test_seeded_form_fails_strict(tmp_path, form):
    root = _tree(tmp_path, {"families/alpha/a.py": _ALLOWED_TOP_LEVEL})
    allow = cfi.parse_allowlist(cfi.render_allowlist(cfi.scan(root)))
    assert cfi.evaluate(cfi.scan(root), allow).ok  # the pending edge alone passes
    (root / "src/unifi_fabric/families/alpha/b.py").write_text(SEEDED_FORMS[form])
    result = cfi.evaluate(cfi.scan(root), allow)
    assert not result.ok, form
    seeded = [e for e in result.violations if e.importer.endswith(".alpha.b")]
    assert seeded, form
    assert {e.kind for e in seeded} == {"family-to-family"}, form
    assert {e.imported_family for e in seeded} == {"beta"}, form


def test_seeded_forms_cover_all_seven():
    assert len(SEEDED_FORMS) == 7


def test_seeded_forms_from_core_also_fail(tmp_path):
    """The same forms from a non-family module are core-to-family violations."""
    for index, (form, text) in enumerate(sorted(SEEDED_FORMS.items())):
        text = text.replace("...families", ".families").replace("..beta", ".families.beta")
        root = _tree(tmp_path / str(index), {"core.py": text})
        result = cfi.evaluate(cfi.scan(root), Counter())
        assert [e.kind for e in result.violations] and {e.kind for e in result.violations} == {
            "core-to-family"
        }, form


# Review C3: an aliased import_module and a computed module path fail closed.
@pytest.mark.parametrize(
    ("rel", "text", "kind"),
    [
        (
            "families/alpha/b.py",
            "from importlib import import_module as _im\n\n"
            "_im('unifi_fabric.families.beta.beta')\n",
            "family-to-family",
        ),
        (
            "families/alpha/b.py",
            "import importlib as il\n\nil.import_module('unifi_fabric.families.beta.beta')\n",
            "family-to-family",
        ),
        (
            "families/alpha/b.py",
            "import importlib\n\nx = 'beta'\n"
            "importlib.import_module(f'unifi_fabric.families.{x}.beta')\n",
            "dynamic-import",
        ),
        (
            "core.py",
            "from importlib import import_module as _im\n\ndef f(name):\n    return _im(name)\n",
            "dynamic-import",
        ),
        ("core.py", "def f(name):\n    return __import__(name)\n", "dynamic-import"),
    ],
)
def test_aliased_and_computed_dynamic_imports_fail_closed(tmp_path, rel, text, kind):
    root = _tree(tmp_path, {rel: text})
    result = cfi.evaluate(cfi.scan(root), Counter())
    assert not result.ok
    assert {e.kind for e in result.violations} == {kind}


def test_computed_dynamic_import_is_allowed_only_in_named_files(tmp_path):
    text = "import importlib\n\ndef f(name):\n    return importlib.import_module(name)\n"
    root = _tree(tmp_path, {"registration.py": text, "catalog/deferred.py": text})
    assert cfi.evaluate(cfi.scan(root), Counter()).ok
    assert "src/unifi_fabric/registration.py" in cfi.DYNAMIC_EXEMPT_FILES


def test_real_tree_has_no_unreviewed_dynamic_import(real_edges):
    assert [e for e in real_edges if e.kind == cfi.DYNAMIC_KIND] == []


def test_a_common_shared_shapes_module_may_serve_families_but_import_none(tmp_path):
    """The L1-C layout where a helper set moves into the common package (the site_manager
    multi-key engine to shared_shapes/_site_manager_shared.py): families importing it
    add no edge, and the common module importing a family fails as core-to-family."""
    common = "shared_shapes/_site_manager_shared.py"
    users = {
        "shared_shapes/__init__.py": "",
        common: "def list_devices():\n    return []\n",
        "families/alpha/a.py": "from ...shared_shapes._site_manager_shared import list_devices\n",
        "families/beta/b.py": "from ...shared_shapes import _site_manager_shared\n",
    }
    assert cfi.evaluate(cfi.scan(_tree(tmp_path / "ok", users)), Counter()).ok
    bad = {**users, common: "from ..families.alpha import alpha\n"}
    result = cfi.evaluate(cfi.scan(_tree(tmp_path / "bad", bad)), Counter())
    assert [e.kind for e in result.violations] == ["core-to-family"]
