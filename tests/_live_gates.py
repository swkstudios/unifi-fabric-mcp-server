"""The one authorization gate for every live-mutation test (``@pytest.mark.mutating``).

``tests/conftest.py`` calls :func:`authorize_live_mutation` from ``pytest_runtest_setup``
for every collected item, so a test module cannot forget the gate. It runs before any
fixture of the item is set up: a class- or module-scoped fixture that creates live state
(``TestVLANCRUDIntegration.created_vlan`` creates a VLAN) is never reached when the run
is not authorized. A function-scoped autouse fixture would run after those wider-scoped
fixtures, which is too late.

A ``mutating`` test runs only when all of these hold (the ``mutating`` marker contract in
``pyproject.toml``):

* it is also marked ``integration``;
* the ``-m`` expression selects it because it is marked ``mutating`` (``-m mutating`` or
  ``-m 'integration and mutating'``). ``-m integration`` replaces the default
  ``-m 'not mutating'`` and would otherwise collect every live write;
* ``UNIFI_TEST_ALLOW_MUTATIONS=1`` is set;
* the effective write policy is ``allow``: a dry-run policy cannot verify a live write.
"""

from __future__ import annotations

import os

import pytest

#: The marker of a test that writes to, or physically actuates, the live console.
MUTATING = "mutating"
#: The environment opt-in a live mutation run needs on top of explicit marker selection.
ALLOW_ENV = "UNIFI_TEST_ALLOW_MUTATIONS"


def selected_as_mutating(markexpr: str, item: pytest.Item) -> bool:
    """True when ``markexpr`` selects ``item`` and would not select it without ``mutating``.

    Uses pytest's own marker-expression evaluator (pinned in ``requirements.lock``), so the
    answer is the one pytest's ``-m`` deselection gives.
    """
    if not markexpr.strip():
        return False
    from _pytest.mark import MarkMatcher
    from _pytest.mark.expression import Expression

    expression = Expression.compile(markexpr)
    marks = list(item.iter_markers())
    with_mark = MarkMatcher.from_markers(marks)
    without_mark = MarkMatcher.from_markers(m for m in marks if m.name != MUTATING)
    return expression.evaluate(with_mark) and not expression.evaluate(without_mark)


def authorize_live_mutation(item: pytest.Item) -> None:
    """Fail ``item`` before its fixtures run unless its live mutation is authorized."""
    if item.get_closest_marker(MUTATING) is None:
        return
    if item.get_closest_marker("integration") is None:
        pytest.fail(
            f"{item.nodeid}: a mutating test must also be marked integration", pytrace=False
        )
    if not selected_as_mutating(item.config.option.markexpr or "", item):
        pytest.fail(
            f"{item.nodeid} performs a live mutation: select it explicitly with -m mutating "
            "(or -m 'integration and mutating'); -m integration alone does not authorize it",
            pytrace=False,
        )
    if os.environ.get(ALLOW_ENV) != "1":
        pytest.fail(f"Set {ALLOW_ENV}=1 to authorize live mutations", pytrace=False)
    from unifi_fabric import policy

    if policy.current().write_policy != "allow":
        pytest.fail(
            "a dry-run policy cannot verify a live mutation; set UNIFI_WRITE_POLICY=allow",
            pytrace=False,
        )
