"""Two-tier, explainable PR selection (stdlib only; no pytest collection)."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import importlib.util
import re
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath

# Reviewed cross-catalog smoke suites. Keep this explicit: the selector tests
# fail when a new invariant suite is added without a smoke-policy decision.
SMOKE_TEST_FILES = frozenset(
    {
        "tests/test_api_sources.py",
        "tests/test_area_opt_out_chokepoint.py",
        "tests/test_argument_errors.py",
        "tests/test_argument_spec_strictness.py",
        "tests/test_blank_filters_and_hints.py",
        "tests/test_catalog_additive_preservation.py",
        "tests/test_catalog_audit.py",
        "tests/test_catalog_cli_shipped.py",
        "tests/test_catalog_load_timing.py",
        "tests/test_catalog_size_budget.py",
        "tests/test_classic_resolution.py",
        "tests/test_collector_partial_results.py",
        "tests/test_confirm_accept_and_ignore.py",
        "tests/test_core_strict_readers_and_name_tiers.py",
        "tests/test_cross_tool_chokepoints.py",
        "tests/test_cross_tool_invariants.py",
        "tests/test_discovery_acceptance.py",
        "tests/test_discovery_properties.py",
        "tests/test_documented_examples.py",
        "tests/test_empty_body_wording.py",
        "tests/test_explicit_page_and_purpose_docs.py",
        "tests/test_explicit_page_catalog.py",
        "tests/test_invariants_argument_echo_secrets.py",
        "tests/test_invariants_arrays_numbers_and_path_ids.py",
        "tests/test_invariants_carrier_devices_and_relay_writes.py",
        "tests/test_invariants_carrier_read_after.py",
        "tests/test_invariants_classic_rc.py",
        "tests/test_invariants_envelopes_and_previews.py",
        "tests/test_invariants_delta15_body_selectors.py",
        "tests/test_invariants_delta15_full_errors.py",
        "tests/test_invariants_delta15_write_outcomes.py",
        "tests/test_invariants_paging_ids_and_relays.py",
        "tests/test_invariants_protect_private_verification.py",
        "tests/test_invariants_read_after.py",
        "tests/test_invariants_response_redaction.py",
        "tests/test_list_first_resolution_catalog.py",
        "tests/test_list_results.py",
        "tests/test_network_id_resolution_before_write.py",
        "tests/test_network_purpose_and_client_ids.py",
        "tests/test_offset_bare_array_page.py",
        "tests/test_optin_features.py",
        "tests/test_protect_body_docs.py",
        "tests/test_readme_catalog_size.py",
        "tests/test_redaction.py",
        "tests/test_refusal_audit_catalog.py",
        "tests/test_refusal_policy.py",
        "tests/test_refused_write_audit.py",
        "tests/test_registry_resolution.py",
        "tests/test_scrub_regional_invariants.py",
        "tests/test_secret_leak_invariant.py",
        "tests/test_spec_conformance.py",
        "tests/test_tool_schema_contract.py",
        "tests/test_upstream_additive_key_collisions.py",
        "tests/test_upstream_error_bodies_never_logged.py",
        "tests/test_verify_missing_null_catalog.py",
    }
)

SOURCE_ROOTS = {"src", "scripts", "tests"}
SOURCE_DIRECTORIES = ("src", "scripts", "tests", ".github/scripts")
# These readers enumerate tracked/public Markdown dynamically, rather than
# carrying individual file paths in read_text calls. Direct readers use AST paths.
DOC_READER_PATTERNS = {
    "docs/*/testing/*.md": (
        # Removed automatically from public reader lists with its private test.
    ),
    "docs/*/testing/ref/*.md": (
        # Removed automatically from public reader lists with its private test.
    ),
    "docs/*.md": ("tests/test_api_keys_and_env_contract.py", "tests/test_docs_references.py"),
    **{
        f"docs/{name}.md": ("tests/test_transport_config_regressions.py",)
        for name in ("CONFIGURATION", "AUTH-TLS", "AUTH-OAUTH")
    },
}


def _module_for_path(path: Path) -> str | None:
    """Return the import name represented by a project Python path."""
    parts = path.with_suffix("").parts
    if parts[:2] == (".github", "scripts"):
        parts = parts[2:]
    elif not parts or parts[0] not in SOURCE_ROOTS:
        return None
    elif parts[0] == "src":
        parts = parts[1:]
    if not parts:
        return None
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) or None


def _import_names(tree: ast.AST, module: str, is_package: bool) -> tuple[set[str], bool]:
    """Collect import names and whether the file has computed dynamic imports."""
    names: set[str] = set()
    unknown_dynamic = False
    package = module.split(".") if is_package else module.split(".")[:-1]
    importlib_aliases = {"importlib"}
    import_module_aliases = set()
    spec_loader_aliases = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_aliases.add(alias.asname or "importlib")
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    import_module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib.util":
            for alias in node.names:
                if alias.name == "spec_from_file_location":
                    spec_loader_aliases.add(alias.asname or alias.name)

    def add_from(imported: str | None, level: int, aliases: list[ast.alias]) -> None:
        if level:
            # Relative import level 1 means the containing package.
            keep = max(0, len(package) - level + 1)
            prefix = ".".join(package[:keep])
        else:
            prefix = ""
        root = ".".join(part for part in (prefix, imported or "") if part)
        if root:
            names.add(root)
        for alias in aliases:
            if alias.name != "*":
                candidate = ".".join(part for part in (root, alias.name) if part)
                if candidate:
                    names.add(candidate)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            add_from(node.module, node.level, node.names)
        elif isinstance(node, ast.Call):
            # Literal dynamic imports are common in plugin and test loaders.
            func = node.func
            dynamic = isinstance(func, ast.Name) and func.id == "__import__"
            dynamic |= isinstance(func, ast.Name) and func.id in import_module_aliases
            dynamic |= (
                isinstance(func, ast.Attribute)
                and func.attr == "import_module"
                and isinstance(func.value, ast.Name)
                and func.value.id in importlib_aliases
            )
            if dynamic:
                if (
                    node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                ):
                    value = node.args[0].value
                    if value.startswith("."):
                        try:
                            from importlib.util import resolve_name

                            names.add(resolve_name(value, ".".join(package)))
                        except (ImportError, ValueError):
                            unknown_dynamic = True
                    else:
                        names.add(value)
                else:
                    unknown_dynamic = True
    return names, unknown_dynamic


def _module_prefixes(module: str) -> set[str]:
    parts = module.split(".")
    return {".".join(parts[:index]) for index in range(1, len(parts) + 1)}


#: The package whose modules define the registered tools.
TOOLS_PACKAGE = "src/unifi_fabric/tools"


def _tools_module_path(name: str) -> bool:
    path = Path(name)
    return (
        path.parent.as_posix() == TOOLS_PACKAGE
        and path.suffix == ".py"
        and path.name != "__init__.py"
    )


def focus_modules(root: Path, changed: list[str]) -> list[str]:
    """Tool modules whose tools keep every parametrized case under the smoke plugin.

    Smoke mode samples one tool per (area, read/write, envelope) class from a tool
    parameter axis and keeps one harness row (body, status, flag) for that class. A
    tool that belongs to a changed module must never be sampled out: its own module's
    tests would otherwise run only the lexically first tool of each class, in one
    harness row, and a regression in any other tool of the module would reach the
    integration branch. The names returned match the values of
    tests._tool_classes.runtime_module_index.

    A changed tool module names itself. A changed module that other modules of the
    tools package import (a private helper or a shared base module) also names every
    module that imports it, directly or through another module of the package, because
    their tools run its code. A changed server.py names "server", the module of the
    inline wrappers registered there. Shared modules outside the tools package reach
    the catalog through the class sample, and the full tier runs every case.
    """
    root = Path(root)
    changed_paths = {Path(n).as_posix().removeprefix("./") for n in changed}
    imports = {}
    for path in sorted((root / TOOLS_PACKAGE).glob("*.py")):
        rel = path.relative_to(root).as_posix()
        if not _tools_module_path(rel):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports[path.stem], _ = _import_names(tree, _module_for_path(Path(rel)) or "", False)
    pending = sorted(
        Path(n).stem for n in changed_paths if _tools_module_path(n) and Path(n).stem in imports
    )
    reached = set(pending)
    while pending:
        dotted = _module_for_path(Path(TOOLS_PACKAGE) / f"{pending.pop()}.py")
        for stem, names in sorted(imports.items()):
            if stem not in reached and dotted in names:
                reached.add(stem)
                pending.append(stem)
    focus = {stem for stem in reached if not stem.startswith("_")}
    if "src/unifi_fabric/server.py" in changed_paths:
        focus.add("server")
    return sorted(focus)


def _file_read_literals(tree: ast.AST, context: ast.AST | None = None) -> set[str]:
    """Find path expressions passed to file-reading or file-inspection APIs."""
    result: set[str] = set()
    path_variables: dict[str, set[str]] = {}
    spec_loader_aliases = {
        alias.asname or alias.name
        for node in [*getattr(context, "body", []), *ast.walk(tree)]
        if isinstance(node, ast.ImportFrom) and node.module == "importlib.util"
        for alias in node.names
        if alias.name == "spec_from_file_location"
    }

    def path_parts(node: ast.AST) -> set[str]:
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and len(node.value) < 512
            and "\n" not in node.value
        ):
            return {node.value.replace("\\", "/")}
        if isinstance(node, ast.Name):
            return path_variables.get(node.id, set())
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left, right = path_parts(node.left), path_parts(node.right)
            if left and right:
                return {
                    "/".join((left_part.rstrip("/"), right_part.lstrip("/")))
                    for left_part in left
                    for right_part in right
                }
            return left or right
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"Path", "sorted", "list", "tuple", "set"}
            and node.args
        ):
            return path_parts(node.args[0])
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"items", "values"}
            and not node.args
        ):
            # PAGES.items() / PAGES.values(): the paths a mapping of files holds.
            return path_parts(node.func.value)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return set().union(*(path_parts(item) for item in node.elts))
        if isinstance(node, ast.Dict):
            return set().union(*(path_parts(value) for value in node.values))
        return set()

    def target_names(target: ast.AST) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, ast.Tuple | ast.List):
            return [name for item in target.elts for name in target_names(item)]
        return []

    # Resolve path constants through assignments such as WORKFLOW = ROOT / "..."
    # so later WORKFLOW.read_text() calls stay connected to the changed file.
    assignments = [
        node
        for node in [*getattr(context, "body", []), *getattr(tree, "body", [])]
        if isinstance(node, ast.Assign | ast.AnnAssign)
    ]
    # Loop and comprehension variables over such a constant carry its paths too:
    # ``for name, path in PAGES.items(): path.read_text()`` reads every page PAGES names.
    # A loop over a literal collection stays unbound: its items are usually path parts
    # (``for directory in ("openapi", "recorded")``), and binding them would only narrow
    # a read that is resolved conservatively today.
    loops = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.For | ast.comprehension)
        and not isinstance(node.iter, ast.List | ast.Tuple | ast.Set | ast.Dict)
    ]
    for _ in range(3):
        changed = False
        bindings = [
            (
                assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target],
                assignment.value,
            )
            for assignment in assignments
        ] + [([loop.target], loop.iter) for loop in loops]
        for targets, value in bindings:
            if value is None:
                continue
            paths = set(sorted(path_parts(value))[:32])
            for target in targets:
                for name in target_names(target):
                    if paths - path_variables.get(name, set()):
                        path_variables.setdefault(name, set()).update(paths)
                        changed = True
        if not changed:
            break

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        attr = func.attr if isinstance(func, ast.Attribute) else ""
        name = func.id if isinstance(func, ast.Name) else ""
        if (name == "open" or attr in {"run", "call", "check_output", "check_call"}) and node.args:
            result.update(path_parts(node.args[0]))
        elif attr in {"glob", "rglob"} and node.args:
            roots = path_parts(func.value)
            patterns = path_parts(node.args[0])
            result.update(
                "/".join((root.rstrip("/"), "**" if attr == "rglob" else "", pattern)).replace(
                    "//", "/"
                )
                for root in roots
                for pattern in patterns
            )
        elif attr in {"read_text", "read_bytes", "exists", "is_file"}:
            result.update(path_parts(func.value))
        elif (attr == "spec_from_file_location" or name in spec_loader_aliases) and len(
            node.args
        ) > 1:
            result.update(path_parts(node.args[1]))
    return result


def _reads_path(name, literal):
    # A root README is not every nested README; a directory prefix is not a file read.
    return bool(literal) and (
        name == literal
        or fnmatch.fnmatch(name, literal)
        and ("**" in literal or name.count("/") == literal.count("/"))
    )


def _test_class(node):
    return isinstance(node, ast.ClassDef) and any(
        (
            isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
            and child.name.startswith("test")
        )
        or _test_class(child)
        for child in node.body
    )


def _definition_body(node):
    # A method edit changes that method, not its siblings or the class header.
    if _test_class(node):
        return ast.ClassDef(
            name=node.name,
            bases=node.bases,
            keywords=node.keywords,
            body=[
                n
                for n in node.body
                if not isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and not _test_class(n)
            ],
            decorator_list=node.decorator_list,
            type_params=getattr(node, "type_params", []),
        )
    return node


def _definitions(tree):
    result = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            result[node.name] = node
            if _test_class(node):
                for child in node.body:
                    if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef) or _test_class(
                        child
                    ):
                        result[f"{node.name}::{child.name}"] = child
                        if _test_class(child):
                            result.update(
                                {
                                    f"{node.name}::{key}": value
                                    for key, value in _definitions(node).items()
                                    if key.startswith(child.name + "::")
                                }
                            )
        elif isinstance(node, ast.TypeAlias):
            result[node.name.id] = node
        elif isinstance(node, ast.Assign | ast.AnnAssign):
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                if isinstance(target, ast.Name):
                    result[target.id] = node
    return result


def _fixtures(tree):
    """List (public fixture name, definition, autouse), preserving class overrides."""
    aliases = {"fixture"}
    aliases.update(
        a.asname or a.name
        for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) and n.module == "pytest"
        for a in n.names
        if a.name == "fixture"
    )
    fixtures = []
    for name, node in _definitions(tree).items():
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            func = call.func if call else decorator
            if not (
                isinstance(func, ast.Attribute)
                and func.attr == "fixture"
                or isinstance(func, ast.Name)
                and func.id in aliases
            ):
                continue
            options = (
                {
                    kw.arg: kw.value.value
                    for kw in call.keywords
                    if isinstance(kw.value, ast.Constant)
                }
                if call
                else {}
            )
            fixtures.append(
                (options.get("name", name.rsplit("::", 1)[-1]), name, options.get("autouse", False))
            )
    return fixtures


def _requested(node):
    names = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.FunctionDef | ast.AsyncFunctionDef):
            names.update(a.arg for a in sub.args.args + sub.args.kwonlyargs)
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Attribute) and func.attr in {"usefixtures", "getfixturevalue"}:
                names.update(
                    a.value
                    for a in sub.args
                    if isinstance(a, ast.Constant) and isinstance(a.value, str)
                )
    return names


def _attribute_names(expression, scope):
    """Resolve literal names in reflection, including reset-fixture name loops."""
    if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
        return {expression.value}
    names = set()
    if isinstance(expression, ast.Name):
        for sub in ast.walk(scope):
            if isinstance(sub, ast.For | ast.comprehension):
                if isinstance(sub.target, ast.Name) and sub.target.id == expression.id:
                    if isinstance(sub.iter, ast.Tuple | ast.List | ast.Set):
                        names.update(
                            v.value
                            for v in sub.iter.elts
                            if isinstance(v, ast.Constant) and isinstance(v.value, str)
                        )
    return names


def _changed_ranges(diff):
    """Old/new zero-context hunk ranges (empty sides do not overlap a definition)."""
    ranges = ([], [])
    for old, old_count, new, new_count in re.findall(
        r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", diff, re.MULTILINE
    ):
        for side, start, count in ((0, old, old_count), (1, new, new_count)):
            length = int(count or 1)
            if length:
                ranges[side].append((int(start), int(start) + length - 1))
    return ranges


def _bindings(tree):
    result = _definitions(tree)
    for node in tree.body:
        if isinstance(node, ast.Import | ast.ImportFrom):
            for alias in node.names:
                name = alias.asname or (
                    alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name
                )
                binding = (
                    ast.Import(names=[alias])
                    if isinstance(node, ast.Import)
                    else ast.ImportFrom(module=node.module, names=[alias], level=node.level)
                )
                result[name] = ast.copy_location(binding, node)
    return result


def changed_definitions(root, base, head, names):
    """Map changed hunks to executable bindings, including removed names/decorators.

    An added import or module-level logging setup does not change every fixture.
    Import bindings propagate only to definitions that actually reference them.
    """
    result = {}
    for name in names:
        if not name.endswith(".py") or not any(
            Path(name).is_relative_to(directory) for directory in SOURCE_DIRECTORIES
        ):
            continue
        diff = subprocess.check_output(
            ["git", "diff", "--no-ext-diff", "--unified=0", base, head, "--", name],
            cwd=root,
            text=True,
        )
        ranges = _changed_ranges(diff)
        versions = []
        touched = set()
        unparsable = False
        for side, ref in enumerate((base, head)):
            blob = subprocess.run(
                ["git", "show", f"{ref}:{name}"],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
            try:
                tree = ast.parse(blob.stdout if blob.returncode == 0 else "")
            except SyntaxError:
                # One side cannot be parsed (e.g. the base still holds merge-conflict
                # markers): hunks cannot be mapped, so every binding on the parsable
                # side counts as changed.
                tree = ast.parse("")
                unparsable = True
            bindings = _bindings(tree)
            if unparsable:
                touched.update(bindings)
            versions.append(
                {
                    n: ast.dump(_definition_body(v), include_attributes=False)
                    for n, v in bindings.items()
                }
            )
            for symbol, node in bindings.items():
                start = min([node.lineno, *(d.lineno for d in getattr(node, "decorator_list", []))])
                if any(start <= end and node.end_lineno >= begin for begin, end in ranges[side]):
                    touched.add(symbol)
        old, new = versions
        result[name] = {n for n in touched if old.get(n) != new.get(n)}
    return result


def _doc_only(name):
    return name.endswith(".md") or name.startswith(("docs/", "changelog.d/"))


#: Tests that read every changelog.d Markdown file, README included: the release-section
#: checks fold pending fragments into the in-flight CHANGELOG section
#: (tests/changelog_section.py), so a fragment that would break the section fails them
#: before the integrator folds it, and the tracked-Markdown scanners check every public
#: Markdown file (tool names, fences) without naming it.
CHANGELOG_D_READERS = (
    "tests/test_release_sanitizer_docs.py",
    "tests/test_changelog_input_schemas.py",
    "tests/test_docs_references.py",
    "tests/test_markdown_blocks.py",
)


def _changelog_d(name):
    return name.startswith("changelog.d/") and name.endswith(".md")


def _prose(name):
    """Markdown or changelog text that schedules no pytest (docs/ and changelog.d/ do)."""
    return _doc_only(name) and not name.startswith(("docs/", "changelog.d/"))


#: Release-sanitization readers: they check every credential name and changelog fragment.
#: Public stripping may remove private readers from this tuple.
RELEASE_SANITIZATION_READERS = (
    "tests/test_release_sanitizer_docs.py",
)


#: Parsed pyproject.toml tables known not to affect which tests run or how.
_PYPROJECT_NON_TESTING_KEYS = (
    ("project", "urls"),
    ("tool", "ruff"),
)


def _pyproject_test_config(text):
    """Return parsed configuration after removing known non-test tables."""
    data = tomllib.loads(text)
    for parent, key in _PYPROJECT_NON_TESTING_KEYS:
        table = data.get(parent)
        if isinstance(table, dict):
            table.pop(key, None)
            if not table:
                data.pop(parent)
    return data


def _pyproject_test_config_changed(root, base, head):
    """True unless both sides parse and all test-relevant config is equal."""
    try:
        before, after = (
            subprocess.check_output(["git", "show", f"{rev}:pyproject.toml"], cwd=root, text=True)
            for rev in (base, head)
        )
        return _pyproject_test_config(before) != _pyproject_test_config(after)
    except (OSError, subprocess.CalledProcessError, tomllib.TOMLDecodeError):
        return True


#: Files whose change alters how the suite is collected, configured, selected or run
#: in CI, or what the public tree contains. A change to any of them runs the full tier.
FULL_TIER_FILES = frozenset(
    {
        "conftest.py",
        "tests/conftest.py",
        "pytest.ini",
        "tox.ini",
        "setup.cfg",
        "scripts/select_pr_tests.py",
    }
)


#: Inputs of the 210,000-case scrubber acceptance corpus (tests/test_secret_scrub_oracle.py).
#: A PR into the integration branch that changes any of them also runs the scrub-oracle
#: job, which the targeted tier never would (the corpus is opt-in inside the test module).
SCRUB_ORACLE_FILES = frozenset(
    {
        "tests/test_secret_scrub_oracle.py",
        "tests/scrub_oracle.py",
        "tests/scrub_fuzz.py",
        "tests/scrub_spec_v2_cases.json",
    }
)


def scrub_oracle_required(changed):
    """True when a changed path is a scrub-oracle input or a secret_scrub source file."""
    for name in changed:
        path = Path(name)
        if name in SCRUB_ORACLE_FILES:
            return True
        if path.parent == Path("src/unifi_fabric") and path.name.startswith("secret_scrub"):
            if path.suffix == ".py":
                return True
    return False


#: The reference-drift checker and its test are private: the public tree omits both.
#: Their names are assembled from parts so the public selector carries no literal path
#: to a stripped file; every use checks that the file exists, and the rule selects
#: nothing in a tree without them.
_DRIFT_STEM = "reference" + "_drift"
DRIFT_CHECKER = f"scripts/check_{_DRIFT_STEM}.py"
DRIFT_TEST = f"tests/test_{_DRIFT_STEM}.py"


def coverage_fingerprint_observed(root):
    """Observe the drift checker’s declared catalog inputs without duplicating them.

    Runs the checker's own ``coverage_fingerprint`` and returns ``(files, globs)``: every
    file it reads, and every ``(directory, pattern)`` it searches with ``rglob``. The
    globs also cover a deleted or renamed-away file, which is no longer in the tree to
    be read but changes the fingerprint all the same. A declared file that is missing
    is recorded and hashed as empty. Both are empty when the checker is absent (the
    public tree).
    """
    root = Path(root).resolve()
    source = root / DRIFT_CHECKER
    if not source.is_file():  # absent in the public tree
        return frozenset(), frozenset()
    spec = importlib.util.spec_from_file_location("reference_drift_selector_inputs", source)
    if spec is None or spec.loader is None:
        return frozenset(), frozenset()
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original_read_bytes = Path.read_bytes
    original_rglob = Path.rglob
    inputs = set()
    globs = set()

    def relative(path):
        try:
            return Path(path).resolve().relative_to(root).as_posix()
        except ValueError:
            return None

    def record_input(path):
        name = relative(path)
        if name is not None:
            inputs.add(name)
        try:
            return original_read_bytes(path)
        except FileNotFoundError:
            return b""

    def record_glob(path, pattern, *args, **kwargs):
        directory = relative(path)
        if directory is not None:
            globs.add((directory, str(pattern)))
        return original_rglob(path, pattern, *args, **kwargs)

    Path.read_bytes = record_input
    Path.rglob = record_glob
    try:
        module.coverage_fingerprint(root)
    finally:
        Path.read_bytes = original_read_bytes
        Path.rglob = original_rglob
    return frozenset(inputs), frozenset(globs)


def coverage_fingerprint_inputs(root):
    """The files the drift checker's coverage fingerprint reads in this tree."""
    return coverage_fingerprint_observed(root)[0]


def is_coverage_fingerprint_input(name, observed):
    """Whether a changed path (added, modified, deleted or renamed) is a fingerprint
    input: a file the fingerprint reads, or one its ``rglob`` searches would match."""
    files, globs = observed
    if name in files:
        return True
    path = PurePosixPath(name)
    for directory, pattern in globs:
        base = PurePosixPath(directory)
        if base.parts and not path.is_relative_to(base):
            continue
        inside = path.relative_to(base) if base.parts else path
        if inside.parts and inside.match(pattern):
            return True
    return False


def _full_config(name, root=None, base=None, head=None):
    """Changes that can affect testing escalate to the full tier.

    Dependency locks, workflows and every file in FULL_TIER_FILES escalate. A
    pyproject.toml edit stays targeted only when parsed
    data differs solely in explicitly non-testing tables; without both revisions any
    edit escalates.
    """
    path = Path(name)
    if name == "pyproject.toml":
        if root is None or base is None or head is None:
            return True
        return _pyproject_test_config_changed(root, base, head)
    if name in FULL_TIER_FILES or name.startswith(".github/workflows/"):
        return True
    return path.name.startswith("requirements") or path.suffix == ".lock"


def select_tests(
    root: Path,
    changed: list[str],
    *,
    tier="targeted",
    definitions=None,
    reasons=None,
    targets=None,
    base=None,
    head=None,
    unsampled=None,
) -> list[str]:
    """Use symbol dependencies, fixture requests and actual file readers.

    ``unsampled`` (a set) receives ``path::symbol`` for every test function or class
    that a changed test file defines and the change touched, directly or through a
    helper, fixture or constant of that file: the smoke plugin runs every case of
    these, because a changed test is the test under review.

    No unknown-path or conftest-import full-suite fallback. Release/full events and
    the changes _full_config names are the only full-tier escalations.
    """
    root = root.resolve()
    tests = sorted(p.relative_to(root).as_posix() for p in (root / "tests").rglob("test*.py"))
    output = reasons if reasons is not None else {}

    members = targets if targets is not None else {}

    def add(path, why, symbol=None):
        if path in tests:
            output.setdefault(path, set()).add(why)
            members.setdefault(path, set())
            if symbol is not None:
                members[path].add(symbol)

    changed = sorted({Path(n).as_posix().removeprefix("./") for n in changed})
    config = next((n for n in changed if _full_config(n, root, base, head)), None)
    if tier == "full" or config:
        for test in tests:
            add(test, f"full tier: {config or 'release event / explicit full-ci'}", "*")
        return sorted(output)
    if all(_prose(n) for n in changed):
        return []
    if any(
        name
        in {
            "src/unifi_fabric/_paging_identity.py",
            "src/unifi_fabric/client.py",
            "src/unifi_fabric/tools/_pagination.py",
        }
        for name in changed
    ):
        add(
            "tests/test_pagination_properties.py",
            "shared pagination contract: exercise every generated family and resume",
            "*",
        )
    if any(
        name
        in {
            "src/unifi_fabric/_paging_identity.py",
            "src/unifi_fabric/client.py",
            "src/unifi_fabric/tools/_pagination.py",
            "src/unifi_fabric/tools/network_nat_qos_traffic.py",
        }
        for name in changed
    ):
        add(
            "tests/test_pagination_flows_regression.py",
            "traffic-flow paging depends on the shared paging contract",
            "*",
        )
    if (root / DRIFT_TEST).exists():
        drift_inputs = coverage_fingerprint_observed(root)
        for name in changed:
            if is_coverage_fingerprint_input(name, drift_inputs):
                add(DRIFT_TEST, f"reference-drift coverage fingerprint input: {name}", "*")
    for name in changed:
        if name.startswith(("tests/fixtures/openapi/", "tests/fixtures/recorded/")) or name in {
            "tests/fixtures/spec_drift/baseline_snapshot.json",
            "scripts/vendor_openapi_specs.py",
            "src/unifi_fabric/redaction.py",
            "src/unifi_fabric/redaction_nonsecrets.py",
        }:
            add(
                "tests/test_redaction_name_coverage.py",
                f"spec-derived credential-name classification input: {name}",
                "*",
            )
    # Keep compact cross-file metadata, never the whole repository's ASTs.
    # A catalog-sized source tree costs hundreds of MiB even without imports.
    paths = [
        path.relative_to(root).as_posix()
        for directory in SOURCE_DIRECTORIES
        for path in sorted((root / directory).rglob("*.py"))
    ]
    defs = {}
    fixture_metadata = {}
    test_classes = set()
    modules = {}

    def metadata(path):
        tree = ast.parse((root / path).read_text(encoding="utf-8"))
        definitions_in_file = _definitions(tree)
        return (
            set(definitions_in_file),
            _fixtures(tree),
            {symbol for symbol, node in definitions_in_file.items() if _test_class(node)},
        )

    for name in paths:
        defs[name], fixture_metadata[name], classes = metadata(name)
        test_classes.update((name, symbol) for symbol in classes)
        module = _module_for_path(Path(name))
        if module:
            modules[module] = name

    # Symbols, rather than whole modules, prevent a discovery import in server
    # from infecting every test that only uses server.mcp or server._client.
    reverse = {}

    def edge(dependency, consumer):
        reverse.setdefault(dependency, set()).add(consumer)

    fixture_defs = {}
    for path in paths:
        for fixture, symbol, _ in fixture_metadata[path]:
            fixture_defs.setdefault(fixture, []).append((path, symbol))
    conftest_scopes = {
        p: [
            c
            for c in paths
            if Path(c).name == "conftest.py" and Path(p).is_relative_to(Path(c).parent)
        ]
        for p in paths
    }
    literals_by_symbol = {}
    imports_by_path = {}
    hook_readers = {}
    changed_tool_modules = sorted(
        module
        for name in changed
        if _tools_module_path(name) and (module := _module_for_path(Path(name)))
    )
    need_imports = bool(changed_tool_modules) or any(
        name.endswith(".py") and name not in defs for name in changed
    )
    need_hook_readers = any(
        Path(name).name == "conftest.py"
        and "pytest_generate_tests" in (definitions or {}).get(name, defs.get(name, set()))
        for name in changed
    )

    def index_file(path):
        # Every AST and node-derived temporary belongs to this one call. Only
        # string edges, file literals and symbol names survive its return.
        tree = ast.parse((root / path).read_text(encoding="utf-8"))
        definitions_in_file = _definitions(tree)
        if need_imports:
            imports_by_path[path], _ = _import_names(
                tree, _module_for_path(Path(path)) or "", False
            )
        hook_readers[path] = {
            symbol
            for symbol, node in definitions_in_file.items()
            if need_hook_readers
            and (
                "lazy_parametrize" in ast.dump(_definition_body(node))
                or "tool" in _requested(_definition_body(node))
            )
            and (symbol.rsplit("::", 1)[-1].startswith("test") or _test_class(node))
        }
        module = _module_for_path(Path(path)) or ""
        package = module.split(".") if Path(path).name == "__init__.py" else module.split(".")[:-1]
        aliases = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    aliases[a.asname or a.name.split(".")[0]] = (a.name, None)
            elif isinstance(node, ast.ImportFrom):
                prefix = ".".join(package[: len(package) - node.level + 1]) if node.level else ""
                imported = ".".join(p for p in (prefix, node.module or "") if p)
                for a in node.names:
                    candidate = f"{imported}.{a.name}"
                    aliases[a.asname or a.name] = (
                        (candidate, None) if candidate in modules else (imported, a.name)
                    )
        for alias, (mod, sym) in aliases.items():
            if mod in modules:
                edge((modules[mod], sym or alias), (path, alias))
        for symbol, definition in definitions_in_file.items():
            node = _definition_body(definition)
            consumer = (path, symbol)
            if "::" in symbol:
                owner, method = symbol.rsplit("::", 1)
                edge((path, owner), consumer)
                if any(provider == symbol for _, provider, _ in fixture_metadata[path]):
                    edge(consumer, (path, owner))
                for lifecycle in (
                    "setup_method",
                    "teardown_method",
                    "setup_class",
                    "teardown_class",
                ):
                    if method.startswith("test") and f"{owner}::{lifecycle}" in defs[path]:
                        edge((path, f"{owner}::{lifecycle}"), consumer)
            for mod, imported_symbol in aliases.values():
                if imported_symbol == "*" and mod in modules:
                    for dep in defs[modules[mod]]:
                        edge((modules[mod], dep), consumer)
            parents = {
                id(c): parent for parent in ast.walk(node) for c in ast.iter_child_nodes(parent)
            }
            called_ids = {id(c.func) for c in ast.walk(node) if isinstance(c, ast.Call)}
            attrs = {id(sub.value) for sub in ast.walk(node) if isinstance(sub, ast.Attribute)}
            for sub in ast.walk(node):
                ref = None
                if (
                    isinstance(sub, ast.Name)
                    and isinstance(sub.ctx, ast.Load)
                    and sub.id in aliases
                ):
                    edge((path, sub.id), consumer)
                if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
                    alias = aliases.get(sub.value.id)
                    if "::" in symbol and sub.value.id in {"self", "cls"}:
                        owner = symbol.rsplit("::", 1)[0]
                        edge((path, f"{owner}::{sub.attr}"), consumer)
                    if alias:
                        ref = (alias[0], alias[1] or sub.attr)
                elif (
                    isinstance(sub, ast.Name)
                    and isinstance(sub.ctx, ast.Load)
                    and id(sub) not in attrs
                ):
                    if sub.id in aliases:
                        mod, imported_symbol = aliases[sub.id]
                        parent = parents.get(id(sub))
                        literal_attribute = (
                            isinstance(parent, ast.Call)
                            and len(parent.args) > 1
                            and parent.args[0] is sub
                            and (
                                (
                                    isinstance(parent.func, ast.Name)
                                    and parent.func.id
                                    in {"getattr", "setattr", "hasattr", "delattr"}
                                )
                                or (
                                    isinstance(parent.func, ast.Attribute)
                                    and parent.func.attr
                                    in {"getattr", "setattr", "delattr", "object"}
                                )
                            )
                        )
                        reflected = (
                            _attribute_names(parent.args[1], node) if literal_attribute else set()
                        )
                        if reflected and not imported_symbol and mod in modules:
                            for attribute in reflected:
                                edge((modules[mod], attribute), consumer)
                        else:
                            ref = (mod, imported_symbol or "*")
                    elif sub.id in defs[path]:
                        # Binding a lifecycle callback to a global registry does
                        # not execute it for every registry consumer. Direct calls
                        # still propagate; callback behavior has its own tests and smoke.
                        callback_binding = isinstance(
                            node, ast.Assign | ast.AnnAssign
                        ) and isinstance(
                            definitions_in_file[sub.id], ast.FunctionDef | ast.AsyncFunctionDef
                        )
                        called = id(sub) in called_ids
                        if not callback_binding or called:
                            edge((path, sub.id), consumer)
                if ref and ref[0] in modules:
                    dependency = modules[ref[0]]
                    if ref[1] == "*":
                        for s in defs[dependency]:
                            edge((dependency, s), consumer)
                    else:
                        edge((dependency, ref[1]), consumer)
            # Autouse fixtures are implicit requests in their pytest scope.
            requested = _requested(node)
            requested.update(
                fixture
                for provider in [path, *conftest_scopes[path]]
                for fixture, fixture_symbol, autouse in fixture_metadata[provider]
                if autouse
                and (
                    "::" not in fixture_symbol
                    or (
                        provider == path
                        and symbol.startswith(fixture_symbol.rsplit("::", 1)[0] + "::")
                    )
                )
            )
            # Module-level pytestmark applies to every test in the module.
            if "pytestmark" in defs[path]:
                if symbol != "pytestmark":
                    edge((path, "pytestmark"), consumer)
                requested.update(_requested(definitions_in_file["pytestmark"]))
            # Fixture requests, usefixtures and literal request.getfixturevalue.
            for fixture in requested:
                for dep in fixture_defs.get(fixture, []):
                    provider = Path(dep[0])
                    if "::" in dep[1] and not (
                        dep[0] == path and symbol.startswith(dep[1].rsplit("::", 1)[0] + "::")
                    ):
                        continue
                    if provider.name != "conftest.py" and dep[0] != path:
                        continue
                    if provider.name == "conftest.py" and not Path(path).is_relative_to(
                        provider.parent
                    ):
                        continue
                    edge(dep, consumer)
            # Imported fixtures re-exported by conftest have no local definition.
            for fixture in requested:
                for conf in conftest_scopes[path]:
                    edge((conf, fixture), consumer)

        for symbol, node in definitions_in_file.items():
            literals_by_symbol[path, symbol] = _file_read_literals(_definition_body(node), tree)

    for path in paths:
        index_file(path)

    executable = any(not _doc_only(n) for n in changed)
    if executable:
        for test in tests:
            if test in SMOKE_TEST_FILES:
                add(test, "smoke: deterministic tool-class sample, every invariant family", "*")
    # A test file that imports a changed tool module runs whole: its tests can
    # exercise the module through the registered catalog as well as through the
    # symbols the change touched, and static symbol edges do not see the catalog.
    for test in tests:
        imported = [m for m in changed_tool_modules if m in imports_by_path.get(test, ())]
        if imported:
            add(test, f"imports changed tool module: {', '.join(imported)}", "*")
    for name in changed:
        if name in {
            "src/unifi_fabric/redaction.py",
            ".github/scripts/check_fixtures_sanitization.py",
        } or name.startswith("changelog.d/"):
            for reader in RELEASE_SANITIZATION_READERS:
                add(reader, f"release sanitization input: {name}", "*")
        # Policy: Markdown/changelog never schedule pytest. Explicit docs readers
        # are computed below only for docs/ (excluding changelog prose); a changelog.d
        # Markdown file schedules the tests that read it.
        if _changelog_d(name):
            for reader in CHANGELOG_D_READERS:
                add(reader, f"changelog.d reader: {name}")
            continue
        if _doc_only(name) and not name.startswith("docs/"):
            continue
        seeds = set()
        if name.startswith("docs/"):
            for pattern, readers in DOC_READER_PATTERNS.items():
                if fnmatch.fnmatch(name, pattern) and name.count("/") == pattern.count("/"):
                    for reader in readers:
                        add(reader, f"explicit parsed-doc reader: {name}")
        if name in defs and not _doc_only(name):
            affected = (
                definitions.get(name, set(defs[name]))
                if definitions is not None
                else set(defs[name])
            )
            seeds.update((name, s) for s in affected)
            if Path(name).name == "conftest.py":
                # Hooks are implicit consumers, not imports. Only their readers.
                if "pytest_generate_tests" in affected:
                    for test in tests:
                        for symbol in hook_readers[test]:
                            add(test, f"hook reader: {name}:pytest_generate_tests", symbol)
        elif name.endswith(".py"):
            missing = _module_for_path(Path(name))
            for path, imported in imports_by_path.items():
                if missing and missing in imported:
                    seeds.update((path, s) for s in defs[path])
        if name in tests:
            add(name, f"changed test: {name}")
        # Exact path/glob readers; never broaden fixtures to the whole directory.
        for (path, symbol), literals in literals_by_symbol.items():
            if any(_reads_path(name, literal) for literal in literals):
                seeds.add((path, symbol))
        closure = set(seeds)
        origin = {seed: seed for seed in seeds}
        pending = sorted(seeds)
        while pending:
            dependency = pending.pop()
            for consumer in sorted(reverse.get(dependency, ())):
                if consumer not in closure:
                    closure.add(consumer)
                    origin[consumer] = origin[dependency]
                    pending.append(consumer)
        explained = set()
        for path, symbol in sorted(closure):
            leaf = symbol.rsplit("::", 1)[-1]
            if leaf.startswith("test") or (path, symbol) in test_classes:
                if unsampled is not None and path == name and name in tests:
                    unsampled.add(f"{path}::{symbol}")
                seed_path, seed_symbol = origin[path, symbol]
                if path not in explained:
                    add(
                        path,
                        f"dependency/fixture/file reader: {name} "
                        f"({seed_path}:{seed_symbol}) -> {symbol}",
                        symbol,
                    )
                    explained.add(path)
                else:
                    members.setdefault(path, set()).add(symbol)
    return sorted(output)


def _head_nodes(root, path):
    """Test functions, classes and Class::method names defined in the checked-out file."""
    try:
        tree = ast.parse((root / path).read_text())
    except (OSError, SyntaxError):
        return None
    names, decorated_classes = set(), set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
            if isinstance(node, ast.ClassDef):
                if node.decorator_list:
                    decorated_classes.add(node.name)
                names.update(
                    f"{node.name}::{item.name}"
                    for item in node.body
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                )
    return names, decorated_classes


def pytest_targets(selected, members, root=None):
    """Pass affected nodes directly to pytest; no skip/deselection hook is used.

    Symbols come from both sides of the diff, so a test the change deleted or
    renamed can be named here, and pytest rejects a node id that does not exist.
    Keep only nodes the checked-out file defines; run the whole file if none remain.
    """
    result = []
    for path in selected:
        symbols = members.get(path, set())
        if root is not None and symbols and "*" not in symbols:
            nodes = _head_nodes(root, path)
            if nodes is not None:
                present, decorated_classes = nodes
                if any(s.split("::", 1)[0] in decorated_classes for s in symbols):
                    # A decorator may replace a syntactic class with a non-collectable
                    # wrapper (e.g. respx.mock). Let pytest collect the complete file
                    # rather than emitting a node that aborts all selected tests.
                    symbols = {"*"}
                else:
                    symbols = {s for s in symbols if s in present}
        if not symbols or "*" in symbols:
            result.append(path)
        else:
            # A selected class already contains all selected descendant methods.
            result.extend(
                f"{path}::{s}"
                for s in sorted(symbols)
                if not any(s.startswith(other + "::") for other in symbols)
            )
    return result


def changed_paths(name_status: str) -> list[str]:
    result = []
    for line in name_status.splitlines():
        status, *paths = line.split("\t")
        result.extend(paths if status.startswith("R") else paths[-1:])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--tier", choices=("targeted", "full"), default="targeted")
    parser.add_argument(
        "--tier-output", type=Path, help="write effective tier for the pytest runner"
    )
    parser.add_argument(
        "--scrub-oracle-output",
        type=Path,
        help="write true when the change needs the scrub-oracle job, else false",
    )
    parser.add_argument(
        "--targets-output",
        type=Path,
        help="write affected pytest node targets; complete invariant files stay in smoke",
    )
    parser.add_argument(
        "--focus-output",
        type=Path,
        help=(
            "write what the smoke plugin never samples: changed tool modules, one per line, "
            "and changed test nodes (path::name)"
        ),
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    status = subprocess.check_output(
        ["git", "diff", "--name-status", "--diff-filter=ACDMRT", f"{args.base}...{args.head}"],
        cwd=root,
        text=True,
    )
    changed = changed_paths(status)
    merge_base = subprocess.check_output(
        ["git", "merge-base", args.base, args.head], cwd=root, text=True
    ).strip()
    definitions = changed_definitions(root, merge_base, args.head, changed)
    reasons, targets, unsampled = {}, {}, set()
    selected = select_tests(
        root,
        changed,
        tier=args.tier,
        definitions=definitions,
        reasons=reasons,
        targets=targets,
        base=merge_base,
        head=args.head,
        unsampled=unsampled,
    )
    if args.targets_output:
        args.targets_output.write_text("\n".join(pytest_targets(selected, targets, root)) + "\n")
    full = args.tier == "full" or any(_full_config(n, root, merge_base, args.head) for n in changed)
    if args.tier_output:
        args.tier_output.write_text("full" if full else "targeted")
    if args.scrub_oracle_output:
        args.scrub_oracle_output.write_text("true" if scrub_oracle_required(changed) else "false")
    if args.focus_output:
        # The full tier never loads the smoke plugin, so it needs no focus list.
        focus = [] if full else [*focus_modules(root, changed), *sorted(unsampled)]
        args.focus_output.write_text("".join(f"{entry}\n" for entry in focus))
    for path in selected:
        print(f"{path}: {'; '.join(sorted(reasons[path]))}", file=sys.stderr)
    if not selected:
        print("No pytest: non-executable or no mapped consumers", file=sys.stderr)
    print("\n".join(selected))


if __name__ == "__main__":
    main()
