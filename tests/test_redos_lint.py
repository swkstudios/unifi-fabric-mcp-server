"""ReDoS lint: every regular expression in ``src`` is free of catastrophic backtracking.

The secret scrubber's embedded-base64 pattern (an unanchored search starting with
an unbounded repeat, ``[A-Za-z0-9+/_-]*(?:frag)...``) took 8.6 s on a 24 KB error body
and blocked the event loop. The class is closed two ways, over EVERY pattern in ``src``:

* statically: no unbounded repeat nested in an unbounded repeat (or over an alternation
  whose branches share a first character), no two adjacent unbounded repeats over
  overlapping characters (only optional items between them), and no unanchored pattern
  that starts with an unbounded repeat unless it is only ever matched at a position
  (``MATCH_ONLY``, each with its reason);
* dynamically: each pattern is run against adversarial input built from its own
  characters (long runs, alternating pairs and repeated literals, then a failing tail);
  all generated subjects must complete search/match/fullmatch with consistent spans.
  Structural lint above supplies the deterministic backtracking safety check;
  Python tracing cannot count the regex engine's C-level work.

Patterns are collected from every module's globals (containers included) and every
``re.<function>(...)`` call site in the source (AST), so a new pattern is covered the
moment it is written; a call whose pattern is neither a literal nor a module global must
be listed in ``DYNAMIC`` with its reason.
"""

from __future__ import annotations

import ast
import importlib
import itertools
import pathlib
import pkgutil
import re
import re._compiler as sre_compile  # type: ignore[import-not-found]
import re._constants as sre_constants  # type: ignore[import-not-found]
import re._parser as sre_parse  # type: ignore[import-not-found]
from typing import Any

import pytest

import unifi_fabric
from unifi_fabric import _spec_drift, read_post_routes, refusals, route_secrets, switches

SRC = pathlib.Path(unifi_fabric.__file__).parent
_RE_FUNCS = {
    "compile",
    "search",
    "match",
    "fullmatch",
    "sub",
    "subn",
    "findall",
    "finditer",
    "split",
}

#: Unanchored patterns starting with an unbounded repeat that are only ever matched AT a
#: position (``.match`` / ``.fullmatch``), where the leading repeat cannot be retried
#: from every later start.
MATCH_ONLY = {
    r"[A-Za-z0-9]*": "secret_scrub: matched at a found position to skip a letter/digit run",
    r"[A-Za-z0-9+/_-]*": "secret_scrub: matched at a found position to expand a base64 token",
    r"=*": "secret_scrub: matched at the token end to take its padding",
    r"\s*\d+(\.\d+)?\s*": "site_manager: an epoch string, only ever fullmatch()ed",
    r"\s*+([+-]?[0-9]+(?:_[0-9]+)*)(?:\.0*)?\s*+": "argument_values: only ever fullmatch()ed",
    r"[0-9]*": "secret_scrub: matched at a found position to take an entity's digit run",
    r"[0-9A-Fa-f]*": "secret_scrub: matched at a found position to take an entity's hex run",
    r"\s+": (
        "registry: console-name whitespace collapse by re.sub; a lone class with nothing "
        "after it, so each start consumes its whole run or fails at once"
    ),
    r"[a-z0-9]+": (
        "discovery: a lone character class with nothing after it, scanned by findall; each "
        "start consumes its whole run or fails at once, so no start is retried against a "
        "later failure (the adversarial-input completion test below still runs on it)"
    ),
}


def _expression(source: str) -> str:
    return ast.dump(ast.parse(source, mode="eval").body, include_attributes=False)


#: Exact nonliteral call expressions, scoped to the function that owns the proof.
#: A new Name/Attribute expression, even in one of these files, fails closed.
DYNAMIC = {
    (
        "_instructions_audit.py",
        "_name_in_text",
        "search",
        _expression(r"r'\b' + re.escape(name) + r'\b'"),
    ): "escaped literal between word boundaries; no repeat",
    (
        "spec_limits.py",
        "",
        "compile",
        _expression("_ecma(p)"),
    ): "every generated table pattern is compiled into linted module globals",
    (
        "spec_limits.py",
        "_compile_other",
        "compile",
        _expression("_ecma(pattern)"),
    ): "direct schema-fragment compiler; existing specification-pattern tests cover it",
    (
        "read_post_routes.py",
        "_compile",
        "compile",
        _expression(r"'^' + ''.join(parts) + r'\Z'"),
    ): "escaped anchored templates interpolate constant single-segment classes",
    (
        "route_secrets.py",
        "RouteSecret.__post_init__",
        "compile",
        _expression("self.route"),
    ): "every ROUTE_SECRETS constant is collected and linted",
    (
        "switches.py",
        "AreaWriteSwitch.owns_route",
        "search",
        _expression("pattern"),
    ): "every AREA_WRITE_SWITCHES route is collected with IGNORECASE and linted",
    (
        "refusals.py",
        "Refusal.matches",
        "search",
        _expression("self.pattern"),
    ): "every REFUSALS constant is collected and linted",
    (
        "refusals.py",
        "classify",
        "search",
        _expression("refusal.pattern"),
    ): "same exhaustive REFUSALS registry; both dispatch paths are exercised",
}

# Dynamic schema inputs are not a closed finite runtime registry. Exercise the
# comparator's supported literal-prefix, anchored-name and escaped-literal cases.
SCHEMA_DYNAMIC_PATTERNS = (r"^a", r"^foo$", r"^prefix_", r"foo\.bar\Z")


def _finite_patterns() -> list[re.Pattern[Any]]:
    return (
        [re.compile(refusal.pattern) for refusal in refusals.REFUSALS]
        + [
            re.compile(route, re.IGNORECASE)
            for switch in switches.AREA_WRITE_SWITCHES
            for route in switch.routes
        ]
        + [entry._pattern for entry in route_secrets.ROUTE_SECRETS]
        + [entry._pattern for entry in read_post_routes.READ_POST_ROUTES]
        + [entry._pattern for entry in read_post_routes.READ_COMMANDS]
        + [re.compile(pattern) for pattern in SCHEMA_DYNAMIC_PATTERNS]
    )


def _modules() -> list[Any]:
    out = [unifi_fabric]
    for info in pkgutil.walk_packages(unifi_fabric.__path__, "unifi_fabric."):
        out.append(importlib.import_module(info.name))
    return out


def _patterns_in(value: Any, depth: int = 0) -> list[re.Pattern[Any]]:
    if isinstance(value, re.Pattern):
        return [value]
    if depth > 3:
        return []
    if isinstance(value, dict):
        value = list(value.keys()) + list(value.values())
    if isinstance(value, list | tuple | set | frozenset):
        return [p for item in value for p in _patterns_in(item, depth + 1)]
    return []


def _global_patterns() -> dict[tuple[str, int, bool], re.Pattern[Any]]:
    found: dict[tuple[str, int, bool], re.Pattern[Any]] = {}
    for module in _modules():
        for value in vars(module).values():
            for pattern in _patterns_in(value):
                key = (str(pattern.pattern), pattern.flags, isinstance(pattern.pattern, bytes))
                found[key] = pattern
    return found


def _call_sites() -> list[tuple[str, str, ast.Call]]:
    sites = []

    def walk(node: ast.AST, filename: str, scope: tuple[str, ...] = ()) -> None:
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            scope = (*scope, node.name)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "re"
            and node.func.attr in _RE_FUNCS
        ):
            node.regex_scope = ".".join(scope)
            sites.append((filename, node.func.attr, node))
        for child in ast.iter_child_nodes(node):
            walk(child, filename, scope)

    for path in sorted(SRC.rglob("*.py")):
        walk(ast.parse(path.read_text(), filename=str(path)), path.name)
    return sites


def _literal(node: ast.AST) -> str | bytes | None:
    try:
        value = ast.literal_eval(node)
    except ValueError:
        return None
    return value if isinstance(value, str | bytes) else None


_FLAG_POS = {
    "compile": 1,
    "search": 2,
    "match": 2,
    "fullmatch": 2,
    "findall": 2,
    "finditer": 2,
    "split": 3,
    "sub": 4,
    "subn": 4,
}


def _flags_of(func: str, node: ast.Call) -> int:
    expr = None
    pos = _FLAG_POS[func]
    if len(node.args) > pos:
        expr = node.args[pos]
    for kw in node.keywords:
        if kw.arg == "flags":
            expr = kw.value
    if expr is None:
        return 0
    source = ast.unparse(expr)
    assert re.fullmatch(r"[A-Za-z_. |]+", source), source
    return int(eval(source, {"re": re}))  # noqa: S307 - re.FLAG | re.FLAG only (checked above)


def _pattern_arg(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    return next((kw.value for kw in node.keywords if kw.arg == "pattern"), None)


def _pattern_key(pattern: re.Pattern[Any]) -> str:
    return f"{pattern.pattern!r} flags={pattern.flags}"


def _all_patterns() -> dict[str, re.Pattern[Any]]:
    patterns = {_pattern_key(p): p for p in _global_patterns().values()}
    for pattern in _finite_patterns():
        patterns[_pattern_key(pattern)] = pattern
    for _filename, func, node in _call_sites():
        first = _pattern_arg(node)
        literal = _literal(first) if first is not None else None
        if literal is not None:
            compiled = re.compile(literal, _flags_of(func, node))
            patterns.setdefault(_pattern_key(compiled), compiled)
    return patterns


PATTERNS = _all_patterns()


def _uncovered(sites: list[tuple[str, str, ast.Call]]) -> list[str]:
    uncovered = []
    for filename, func, node in sites:
        first = _pattern_arg(node)
        if first is not None and _literal(first) is not None:
            compiled = re.compile(_literal(first), _flags_of(func, node))
            assert _pattern_key(compiled) in PATTERNS, (filename, node.lineno)
            continue
        key = (
            filename,
            getattr(node, "regex_scope", ""),
            func,
            ast.dump(first, include_attributes=False) if first is not None else "",
        )
        if key not in DYNAMIC:
            uncovered.append(f"{filename}:{node.lineno} re.{func}")
    return uncovered


def test_every_re_call_site_is_covered() -> None:
    """No unregistered runtime pattern is accepted based on its AST node type."""
    uncovered = _uncovered(_call_sites())
    assert not uncovered, f"re calls with a run-time pattern, not in DYNAMIC: {uncovered}"
    assert len(PATTERNS) >= 40


@pytest.mark.parametrize(
    "source",
    [
        "re.search(pattern, text)",
        "re.search(holder.pattern, text)",
        "re.search(pattern=pattern, string=text)",
        "re.search(**kwargs)",
    ],
)
def test_unregistered_nonliteral_pattern_mutations_fail(source):
    node = ast.parse(source).body[0].value
    # Even a file/function containing a reviewed dynamic call cannot smuggle in
    # another Name/Attribute expression under the same filename-level exemption.
    node.regex_scope = "AreaWriteSwitch.owns_route"
    assert _uncovered([("mutation.py", "search", node)])
    if "holder.pattern" in source:
        assert _uncovered([("switches.py", "search", node)])


@pytest.mark.parametrize(
    ("filename", "scope", "expression"),
    [
        ("switches.py", "AreaWriteSwitch.owns_route", "pattern"),
        ("refusals.py", "Refusal.matches", "self.pattern"),
        ("refusals.py", "classify", "refusal.pattern"),
    ],
)
def test_removing_nonliteral_registration_exposes_the_real_callsite(
    monkeypatch, filename, scope, expression
):
    monkeypatch.delitem(DYNAMIC, (filename, scope, "search", _expression(expression)))
    uncovered = _uncovered(_call_sites())
    assert any(site.startswith(filename + ":") for site in uncovered), uncovered


def test_finite_registry_patterns_are_exhaustively_linted():
    expected = {_pattern_key(re.compile(refusal.pattern)) for refusal in refusals.REFUSALS} | {
        _pattern_key(re.compile(route, re.IGNORECASE))
        for switch in switches.AREA_WRITE_SWITCHES
        for route in switch.routes
    }
    expected |= {
        _pattern_key(entry._pattern)
        for entry in (*route_secrets.ROUTE_SECRETS, *read_post_routes.READ_POST_ROUTES)
    }
    assert expected and expected <= PATTERNS.keys()


@pytest.mark.parametrize("pattern", SCHEMA_DYNAMIC_PATTERNS)
def test_dynamic_schema_patterns_on_adversarial_names(pattern):
    constraint = {"type": "string"}
    schema = {"patternProperties": {pattern: constraint}, "additionalProperties": False}
    for name in ("a" * 5000 + "!", "foo", "foo" * 5000, "prefix_valid", "prefix_" + "a" * 5000):
        expected = constraint if re.search(pattern, name) is not None else False
        assert _spec_drift._property_schema(schema, name) == expected
    assert _spec_drift._property_schema({"patternProperties": {"[": constraint}}, "a") is None


@pytest.mark.parametrize(
    "pattern",
    [
        r"(a+)+$",
        r"(?:a|aa)+$",
        r"\d+\d*x",
        r"[a-z]*a$",
        r"^prefix_[A-Za-z0-9_]{1,64}$",
        r"(?=a)a",
        "[",
        "\\",
    ],
)
def test_unsafe_or_unsupported_dynamic_schema_patterns_are_unknown(monkeypatch, pattern):
    def forbidden_search(*args, **kwargs):
        raise AssertionError("schema pattern reached the backtracking engine")

    monkeypatch.setattr(_spec_drift.re, "search", forbidden_search)
    schema = {"patternProperties": {pattern: {"type": "string"}}}
    assert _spec_drift._property_schema(schema, "a" * 5000 + "!") is None


@pytest.mark.parametrize(
    "pattern",
    [
        "",
        "foo",
        "^foo",
        "foo$",
        "^foo$",
        r"foo\Z",
        r"^foo\Z",
        r"foo\.bar",
        r"\^foo\$",
        r"foo\\bar",
        "^$",
        r"^\Z",
        "\n$",
    ],
)
@pytest.mark.parametrize(
    "name",
    [
        "",
        "\n",
        "foo",
        "foo\n",
        "xfoo",
        "foox",
        "foo.bar",
        "^foo$",
        "foo\\bar",
        "x\n",
    ],
)
def test_supported_schema_pattern_subset_matches_regex_semantics(pattern, name):
    assert _spec_drift._property_pattern_matches(pattern, name) == (
        re.search(pattern, name) is not None
    )


@pytest.mark.parametrize("name", ["a" * 5000 + "!", "/proxy/network/" + "a" * 5000])
def test_finite_registry_dispatch_on_adversarial_inputs(name):
    for switch in switches.AREA_WRITE_SWITCHES:
        assert switch.owns_route(name) == any(
            re.search(pattern, name, re.IGNORECASE) is not None for pattern in switch.routes
        )
    for refusal in refusals.REFUSALS:
        assert refusal.matches(name) == (re.search(refusal.pattern, name) is not None)
    assert refusals.classify(name) is None


# --------------------------------------------------------------------------- static
_ALPHA_STR = [chr(i) for i in range(128)] + ["é", " ", " ", "١", "０"]
_ALPHA_BYTES = [bytes([i]) for i in range(256)]
_REPEATS = {sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT}
_ZERO_WIDTH = {sre_constants.AT, sre_constants.ASSERT, sre_constants.ASSERT_NOT}


class _Ctx:
    def __init__(self, pattern: re.Pattern[Any]) -> None:
        self.flags = pattern.flags
        self.is_bytes = isinstance(pattern.pattern, bytes)
        self.state = sre_parse.State()
        self.state.flags = pattern.flags


def _atom_chars(item: Any, ctx: _Ctx) -> frozenset[Any]:
    """The sample characters one atom (or any sub-pattern) can consume, over-approximated."""
    op, av = item
    if op in _REPEATS or op == sre_constants.POSSESSIVE_REPEAT:
        return _seq_chars(av[2], ctx)
    if op == sre_constants.SUBPATTERN:
        return _seq_chars(av[3], ctx)
    if op == sre_constants.ATOMIC_GROUP:
        return _seq_chars(av, ctx)
    if op == sre_constants.BRANCH:
        return frozenset().union(*(_seq_chars(b, ctx) for b in av[1]))
    if op in _ZERO_WIDTH or op == sre_constants.GROUPREF:
        return frozenset()
    sub = sre_parse.SubPattern(ctx.state, [item])
    compiled = sre_compile.compile(sub, ctx.flags)
    alphabet = _ALPHA_BYTES if ctx.is_bytes else _ALPHA_STR
    return frozenset(c for c in alphabet if compiled.fullmatch(c))


def _seq_chars(seq: Any, ctx: _Ctx) -> frozenset[Any]:
    return frozenset().union(*(_atom_chars(item, ctx) for item in seq)) if len(seq) else frozenset()


def _edge_chars(seq: Any, ctx: _Ctx, last: bool) -> frozenset[Any]:
    """The sample characters a match of ``seq`` can start (or, ``last``, end) with."""
    out: frozenset[Any] = frozenset()
    for item in reversed(list(seq)) if last else seq:
        op, av = item
        if op in _ZERO_WIDTH:
            continue
        if op in _REPEATS or op == sre_constants.POSSESSIVE_REPEAT:
            out |= _edge_chars(av[2], ctx, last)
            optional = av[0] == 0
        elif op == sre_constants.SUBPATTERN:
            out |= _edge_chars(av[3], ctx, last)
            optional = False
        elif op == sre_constants.BRANCH:
            out |= frozenset().union(*(_edge_chars(b, ctx, last) for b in av[1]))
            optional = False
        else:
            out |= _atom_chars(item, ctx)
            optional = False
        if not optional:
            break
    return out


def _first_chars(seq: Any, ctx: _Ctx) -> frozenset[Any]:
    return _edge_chars(seq, ctx, last=False)


def _last_chars(seq: Any, ctx: _Ctx) -> frozenset[Any]:
    return _edge_chars(seq, ctx, last=True)


def _unbounded(item: Any) -> bool:
    op, av = item
    return op in _REPEATS and av[1] == sre_constants.MAXREPEAT


def _has_unbounded(seq: Any) -> bool:
    for op, av in seq:
        if op in _REPEATS:
            if av[1] == sre_constants.MAXREPEAT or _has_unbounded(av[2]):
                return True
        elif op == sre_constants.SUBPATTERN and _has_unbounded(av[3]):
            return True
        elif op == sre_constants.BRANCH and any(_has_unbounded(b) for b in av[1]):
            return True
    return False


def _variable_branches_overlap(seq: Any, ctx: _Ctx) -> bool:
    for op, av in seq:
        if op == sre_constants.SUBPATTERN and _variable_branches_overlap(av[3], ctx):
            return True
        if op == sre_constants.BRANCH:
            firsts = [_first_chars(b, ctx) for b in av[1]]
            if any(a & b for a, b in itertools.combinations(firsts, 2)):
                return True
    return False


def _problems(seq: Any, ctx: _Ctx, top: bool = False) -> list[str]:
    out: list[str] = []
    items = list(seq)
    for i, item in enumerate(items):
        op, av = item
        if op in _REPEATS:
            body = av[2]
            # One iteration's tail can be the next one's head: the split between
            # iterations is ambiguous, so a failing match retries every split.
            if (
                _unbounded(item)
                and _has_unbounded(body)
                and _last_chars(body, ctx) & _first_chars(body, ctx)
            ):
                out.append("unbounded repeat nested in an unbounded repeat")
            if _unbounded(item) and _variable_branches_overlap(body, ctx):
                out.append("unbounded repeat over overlapping alternatives")
            out += _problems(body, ctx)
            if _unbounded(item):
                mine = _last_chars([item], ctx)
                for later in items[i + 1 :]:
                    if _unbounded(later) and mine & _first_chars([later], ctx):
                        out.append("adjacent unbounded repeats over overlapping characters")
                        break
                    lop, lav = later
                    if lop in _ZERO_WIDTH or (lop in _REPEATS and lav[0] == 0):
                        continue
                    break
        elif op == sre_constants.SUBPATTERN:
            out += _problems(av[3], ctx)
        elif op == sre_constants.BRANCH:
            for branch in av[1]:
                out += _problems(branch, ctx)
        elif op in (sre_constants.ASSERT, sre_constants.ASSERT_NOT):
            out += _problems(av[1], ctx)
    if top:
        lead = [it for it in items if it[0] not in (sre_constants.ASSERT, sre_constants.ASSERT_NOT)]
        anchored = bool(lead) and lead[0][0] == sre_constants.AT
        if lead and not anchored and _unbounded(lead[0]):
            out.append("unanchored pattern starting with an unbounded repeat")
    return out


@pytest.mark.parametrize("key", sorted(PATTERNS))
def test_no_catastrophic_backtracking_shape(key: str) -> None:
    pattern = PATTERNS[key]
    ctx = _Ctx(pattern)
    parsed = sre_parse.parse(pattern.pattern, pattern.flags)
    problems = _problems(parsed, ctx, top=True)
    text = pattern.pattern.decode("latin-1") if ctx.is_bytes else pattern.pattern
    if problems == ["unanchored pattern starting with an unbounded repeat"] and text in MATCH_ONLY:
        return
    assert not problems, f"{text!r}: {problems}"


def test_the_old_scrubber_shape_is_caught() -> None:
    """The lint flags the old scrubber pattern (a leading unbounded repeat, unanchored)."""
    old = re.compile(r"[A-Za-z0-9+/_-]*(?:QUJD|REVG)[A-Za-z0-9+/_-]*=*")
    assert "unanchored pattern starting with an unbounded repeat" in _problems(
        sre_parse.parse(old.pattern), _Ctx(old), top=True
    )
    for bad in (r"(a+)+$", r"(?:a|ab)*c", r"\d+\d*x"):
        compiled = re.compile(bad)
        assert _problems(sre_parse.parse(bad), _Ctx(compiled), top=True), bad


# --------------------------------------------------------------------------- dynamic
def text_of(pattern: re.Pattern[Any]) -> str:
    raw = pattern.pattern
    return raw.decode("latin-1") if isinstance(raw, bytes) else raw


_N = 5000


def _samples(pattern: re.Pattern[Any]) -> list[Any]:
    ctx = _Ctx(pattern)
    parsed = sre_parse.parse(pattern.pattern, pattern.flags)
    chars: list[Any] = []

    def walk(seq: Any) -> None:
        for item in seq:
            op, av = item
            if op in _REPEATS or op == sre_constants.POSSESSIVE_REPEAT:
                walk(av[2])
            elif op == sre_constants.SUBPATTERN:
                walk(av[3])
            elif op == sre_constants.BRANCH:
                for branch in av[1]:
                    walk(branch)
            elif op in (sre_constants.ASSERT, sre_constants.ASSERT_NOT):
                walk(av[1])
            elif op not in _ZERO_WIDTH:
                matched = sorted(_atom_chars(item, ctx))
                for c in (matched[:1] + matched[len(matched) // 2 : len(matched) // 2 + 1])[:2]:
                    if c not in chars:
                        chars.append(c)

    walk(parsed)
    return chars[:10]


def _literals(pattern: re.Pattern[Any]) -> list[str]:
    text = (
        pattern.pattern.decode("latin-1") if isinstance(pattern.pattern, bytes) else pattern.pattern
    )
    return [m for m in re.findall(r"[A-Za-z0-9/:._-]{3,}", text)][:6]


@pytest.mark.parametrize("key", sorted(PATTERNS))
def test_adversarial_inputs_complete_with_consistent_matches(key: str) -> None:
    pattern = PATTERNS[key]
    is_bytes = isinstance(pattern.pattern, bytes)
    samples = _samples(pattern)
    tails = ["!", "\x00", " ", "\n"]
    # (unit, divisor): every body is ``unit`` repeated n // divisor times.
    units: list[tuple[str, int]] = []
    for c in samples:
        units.append((c.decode("latin-1") if is_bytes else c, 1))
    for a, b in itertools.permutations(samples[:6], 2):
        pair = (a + b).decode("latin-1") if is_bytes else a + b
        units.append((pair, 2))
    for lit in _literals(pattern):
        units.append((lit, len(lit)))
    search = text_of(pattern) not in MATCH_ONLY

    completed = 0
    for unit, divisor in units:
        for tail in tails:
            text = unit * (_N // divisor) + tail
            subject: Any = text.encode("latin-1") if is_bytes else text
            matched = pattern.match(subject)
            full = pattern.fullmatch(subject)
            if search:
                found = pattern.search(subject)
                if matched is not None:
                    assert found is not None and found.span() == matched.span()
                if found is not None:
                    assert 0 <= found.start() <= found.end() <= len(subject)
            if matched is not None:
                assert matched.start() == 0
                assert matched.end() <= len(subject)
            if full is not None:
                assert full.span() == (0, len(subject))
                assert matched is not None
            completed += 1
    assert completed == len(units) * len(tails)
