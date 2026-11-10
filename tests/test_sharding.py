"""The shard partition (scripts/shard_partition.py), its verifier and the --shard plugin."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests import _sharding

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "shard_partition", ROOT / "scripts" / "shard_partition.py"
)
assert _spec and _spec.loader
part = importlib.util.module_from_spec(_spec)
sys.modules.setdefault(_spec.name, part)
_spec.loader.exec_module(part)

N = 4
COMMIT = "a" * 40
IDS = [f"tests/test_mod_{i % 7}.py::test_case[{i}]" for i in range(200)]


SUITE_NAME = "test"
RUN = "7"
IDENTITY = {"python": "3.12.1", "dist_sha256": "d" * 64, "count": 87}


def make_reports(ids=IDS, n=N, commit=COMMIT, suite=SUITE_NAME):
    """Consistent shard reports for ``ids`` (what the plugin would write)."""
    placement = part.assign(ids, {}, n)
    digest = part.ids_digest(ids)
    reports = []
    for k in range(1, n + 1):
        selected = [i for i in ids if placement[i] == k]
        reports.append(
            {
                "format": 1,
                "suite": suite,
                "k": k,
                "n": n,
                "commit": commit,
                "run": RUN,
                "attempt": "1",
                "full_sha256": digest,
                "groups": [f"group-{k}"],
                "selected": selected,
                "outcomes": {i: "passed" for i in selected},
                "identity": dict(IDENTITY),
                "lock_errors": [],
            }
        )
    return reports


ANCHOR_IDENTITY = {"identity": dict(IDENTITY), "lock_errors": []}


def check(reports, ids=IDS, n=N, coverage=None, commit=COMMIT, **options):
    coverage = [f"s{k}/.coverage" for k in range(1, n + 1)] if coverage is None else coverage
    options = {"suite": SUITE_NAME, "run": RUN, **options}
    return part.verify(ids, reports, n=n, commit=commit, coverage_files=coverage, **options)


def check_locked(reports, anchor=ANCHOR_IDENTITY, **options):
    return check(reports, require_identity=True, anchor_identity=anchor, **options)


# -- assign: determinism, stability, groups, balance ------------------------------------


def test_assign_is_deterministic_and_covers_every_unit():
    first = part.assign(IDS, {}, N)
    assert first == part.assign(reversed(IDS), {}, N)
    assert set(first) == set(IDS)
    assert set(first.values()) <= set(range(1, N + 1))
    assert len(set(first.values())) == N  # 200 units reach every shard


def test_assign_uses_the_documented_hash():
    unit = "tests/test_x.py::test_y"
    expected = int(hashlib.sha256(("unifi-shard-v1:" + unit).encode()).hexdigest(), 16) % 5 + 1
    assert part.assign([unit], {}, 5) == {unit: expected}


def test_adding_one_unit_moves_only_that_unit():
    before = part.assign(IDS, {}, N)
    after = part.assign([*IDS, "tests/test_new.py::test_added"], {}, N)
    assert {u: s for u, s in after.items() if u != "tests/test_new.py::test_added"} == before


def test_heavy_units_go_longest_first_with_name_tie_break():
    weights = {"b": 100, "a": 100, "c": 50, "d": 10}
    placed = part.assign(["a", "b", "c", "d", "light"], weights, 2)
    # a and b weigh the same, so the name orders them: a takes shard 1, b the empty shard 2.
    # c then finds both at 100 and takes the lower number; d takes the lighter shard 2.
    assert (placed["a"], placed["b"], placed["c"], placed["d"]) == (1, 2, 1, 2)
    assert placed["light"] == part.hash_shard("light", 2)


def test_the_committed_heavy_list_spreads_its_units_and_names_real_tests():
    weights = _sharding.heavy_weights()
    assert {
        "tests/test_fastgate.py::test_fastgate_controls[clean-registry]",
        "protocol-conformance",
        "catalog-contract",
    } <= set(weights)
    placed = part.assign(weights, weights, N)
    assert len(set(placed.values())) == N or len(weights) < N
    assert placed[max(weights, key=weights.get)] == 1  # the longest unit leads
    # The private tree names every unit. The public tree shares the heavy list but not the
    # private-only tests the transform removes (test_fastgate.py, ...), so a unit whose test
    # is gone there is a stale entry, which costs balance only, never correctness.
    # joined at runtime: the public tree strips the transform, so a literal path would fail
    # the removed-file reference check there
    private_tree = (ROOT / "scripts" / ("public_release_" + "transform.sh")).is_file()
    all_tests = "".join(p.read_text() for p in (ROOT / "tests").glob("test_*.py"))
    for unit in weights:
        if "::" in unit:
            path, _, name = unit.partition("::")
            if not private_tree and not (ROOT / path).is_file():
                continue
            assert name.split("[")[0] in (ROOT / path).read_text(), unit
        elif private_tree:
            assert (
                f'xdist_group("{unit}")' in all_tests or f'xdist_group(name="{unit}")' in all_tests
            ), unit


@pytest.mark.parametrize("text", ["0/4", "5/4", "1/0", "a/4", "1", "1/4/5", "-1/4", ""])
def test_parse_shard_refuses_a_malformed_shard(text):
    with pytest.raises(ValueError):
        part.parse_shard(text)
    assert part.parse_shard("2/4") == (2, 4)


# -- verify: the proof holds, and every defect fails it ----------------------------------


def test_a_complete_proof_passes():
    assert check(make_reports()) == []


def test_negative_dropped_shard():
    reports = make_reports()[:-1]
    errors = check(reports)
    assert any("expected 4 shard reports" in e for e in errors)
    assert any("shard 4/4 appears 0 times" in e for e in errors)
    assert any("ids missing from every shard" in e for e in errors)


def test_negative_empty_shard():
    reports = make_reports()
    victim = reports[1]
    victim["selected"], victim["outcomes"] = [], {}
    errors = check(reports)
    assert any("shard 2 selected nothing" in e for e in errors)
    assert any("ids missing from every shard" in e for e in errors)


def test_negative_duplicate_id_in_two_shards():
    reports = make_reports()
    dup = reports[0]["selected"][0]
    reports[1]["selected"].append(dup)
    reports[1]["outcomes"][dup] = "passed"
    errors = check(reports)
    assert any("repeats ids of another shard" in e and dup in e for e in errors)


def test_negative_duplicate_id_inside_one_shard():
    reports = make_reports()
    reports[0]["selected"].append(reports[0]["selected"][0])
    assert any("more than once" in e for e in check(reports))


def test_negative_extra_id_is_listed():
    reports = make_reports()
    reports[2]["selected"].append("tests/test_ghost.py::test_extra")
    reports[2]["outcomes"]["tests/test_ghost.py::test_extra"] = "passed"
    errors = check(reports)
    assert any("not in the anchor list" in e and "test_ghost.py::test_extra" in e for e in errors)


def test_negative_missing_id_is_listed():
    reports = make_reports()
    lost = reports[3]["selected"].pop()
    del reports[3]["outcomes"][lost]
    errors = check(reports)
    assert any("ids missing from every shard" in e and lost in e for e in errors)


def test_negative_hash_mismatch():
    reports = make_reports()
    reports[1]["full_sha256"] = "0" * 64
    assert any("shard 2: full-list hash differs" in e for e in check(reports))


def test_negative_anchor_differs_from_what_the_shards_collected():
    errors = check(make_reports(), ids=[*IDS, "tests/test_late.py::test_new"])
    assert any("hash differs" in e for e in errors)
    assert any("test_late.py::test_new" in e for e in errors)


def test_negative_failing_test():
    reports = make_reports()
    victim = reports[0]["selected"][3]
    reports[0]["outcomes"][victim] = "failed"
    assert any("did not pass or skip" in e and victim in e for e in check(reports))


def test_negative_selected_test_never_ran():
    reports = make_reports()
    victim = reports[0]["selected"][3]
    del reports[0]["outcomes"][victim]
    assert any("no outcome" in e and victim in e for e in check(reports))


def test_negative_executed_outside_the_selection():
    reports = make_reports()
    reports[0]["outcomes"][reports[1]["selected"][0]] = "passed"
    assert any("outside the selection" in e for e in check(reports))


def test_negative_incomplete_outcome():
    reports = make_reports()
    reports[0]["outcomes"][reports[0]["selected"][0]] = "incomplete"
    assert any("did not pass or skip" in e for e in check(reports))


def test_negative_missing_coverage_file():
    errors = check(make_reports(), coverage=[".coverage"] * 3)
    assert any("expected 4 coverage data files, found 3" in e for e in errors)
    assert any("found 5" in e for e in check(make_reports(), coverage=[".coverage"] * 5))


def test_negative_repeated_shard_number_and_wrong_n_commit_run():
    reports = make_reports()
    reports[3]["k"] = 3
    errors = check(reports)
    assert any("two reports for attempt 1" in e for e in errors)
    assert any("shard 4/4 appears 0 times" in e for e in errors)
    reports = make_reports()
    reports[0]["n"] = 8
    assert any("report an n other than 4" in e for e in check(reports))
    reports = make_reports()
    reports[1]["commit"] = "b" * 40
    assert any("commit other than" in e for e in check(reports))
    mixed = reports_with(commit="c")
    assert any("disagree on commit" in e for e in check(mixed, commit=None))


def test_negative_uniform_wrong_n_on_every_leg():
    # Matrix, reports and each report's n agree with one another (3) but not with the
    # constant (4): the verifier takes N from its argument only.
    three = make_reports(n=3)
    assert check(three, n=3) == []
    errors = check(three, n=4)
    assert any("expected 4 shard reports, found 3" in e for e in errors)
    assert any("shard 4/4 appears 0 times" in e for e in errors)
    assert any("report an n other than 4" in e for e in errors)
    # ... and the other way: the constant says 3, four legs ran.
    assert any("expected 3 shard reports, found 4" in e for e in check(make_reports(), n=3))


def test_negative_stale_attempt_report():
    reports = make_reports()
    stale = copy.deepcopy(reports[1])
    stale["attempt"] = "1"
    stale["selected"] = stale["selected"][:-1]  # an older attempt that ran less
    for r in reports:
        r["attempt"] = "2"
    # The newest attempt per shard counts; the older report of shard 2 is dropped.
    assert check(reports + [stale]) == []
    # A shard whose only report is from another run is rejected, not counted.
    other = make_reports()
    other[2]["run"] = "6"
    errors = check(other)
    assert any("is from run '6', not '7'" in e for e in errors)
    assert any("expected 4 shard reports, found 3" in e for e in errors)
    # The stale attempt can never stand in for a missing newest one: a report without an
    # attempt is rejected too, and two reports of one attempt are a defect.
    missing = make_reports()
    del missing[0]["attempt"]
    assert any("has no run attempt" in e for e in check(missing))
    twice = make_reports()
    assert any("two reports for attempt 1" in e for e in check(twice + [copy.deepcopy(twice[0])]))


def test_a_newer_attempt_replaces_a_failed_older_one():
    reports = make_reports()
    old = copy.deepcopy(reports[0])
    old["outcomes"][old["selected"][0]] = "failed"
    for r in reports:
        r["attempt"] = "2"
    assert check([old, *reports]) == []


def test_negative_cross_suite_artifact():
    reports = make_reports()
    reports[2] = make_reports(suite="test-locked")[2]
    errors = check(reports)
    assert any("is for suite 'test-locked', not 'test'" in e for e in errors)
    assert any("expected 4 shard reports, found 3" in e for e in errors)
    assert any("shard 3/4 appears 0 times" in e for e in errors)


@pytest.mark.parametrize("outcome", ["failed", "error", "incomplete"])
def test_negative_failed_outcome_in_any_report(outcome):
    reports = make_reports()
    reports[2]["outcomes"][reports[2]["selected"][1]] = outcome
    assert any("did not pass or skip" in e for e in check(reports))


def test_xfailed_and_xpassed_are_not_defects():
    reports = make_reports()
    reports[0]["outcomes"][reports[0]["selected"][0]] = "xfailed"
    reports[1]["outcomes"][reports[1]["selected"][0]] = "xpassed"
    assert check(reports) == []


def test_negative_split_xdist_group():
    reports = make_reports()
    reports[0]["groups"] = ["shared-group", "group-1"]
    reports[2]["groups"] = ["shared-group", "group-3"]
    errors = check(reports)
    assert any(
        "xdist_group names that span two shards: " in e and "shared-group" in e for e in errors
    )


def test_outcome_totals_are_summed_over_the_kept_reports():
    reports = make_reports()
    reports[0]["outcomes"][reports[0]["selected"][0]] = "skipped"
    reports[1]["outcomes"][reports[1]["selected"][0]] = "xfailed"
    total = part.totals(reports)
    assert total["total"] == len(IDS)
    assert total["skipped"] == 1 and total["xfailed"] == 1
    assert total["passed"] == len(IDS) - 2
    record = part.proof(IDS, reports, N, COMMIT, SUITE_NAME, RUN)
    assert record["totals"] == total and record["suite"] == SUITE_NAME
    assert sum(s["totals"]["total"] for s in record["shards"]) == len(IDS)


# -- environment identity (test-locked) ----------------------------------------------------


def test_proof_record_carries_ok_and_errors():
    reports = make_reports()
    clean = part.proof(IDS, reports, N, COMMIT, SUITE_NAME, RUN)
    assert clean["ok"] is True and clean["errors"] == []
    failed = part.proof(
        IDS, reports, N, COMMIT, SUITE_NAME, RUN, errors=["shard 2 selected nothing"]
    )
    assert failed["ok"] is False and failed["errors"] == ["shard 2 selected nothing"]


def test_identity_that_matches_everywhere_passes():
    assert check_locked(make_reports()) == []


def test_negative_identity_mismatch_between_shards():
    reports = make_reports()
    reports[1]["identity"] = {**IDENTITY, "dist_sha256": "e" * 64}
    assert any("identity differs" in e for e in check_locked(reports))
    other_python = make_reports()
    other_python[3]["identity"] = {**IDENTITY, "python": "3.12.2"}
    assert any("identity differs" in e for e in check_locked(other_python))


def test_negative_anchor_identity_differs_from_the_shards():
    anchor = {"identity": {**IDENTITY, "count": 88}, "lock_errors": []}
    assert any("identity differs" in e for e in check_locked(make_reports(), anchor=anchor))


def test_negative_identity_missing():
    reports = make_reports()
    del reports[2]["identity"]
    assert any("shards 3 carry no environment identity" in e for e in check_locked(reports))
    assert any(
        "anchor carries no environment identity" in e
        for e in check_locked(make_reports(), anchor=None)
    )
    no_lock_check = make_reports()
    del no_lock_check[0]["lock_errors"]
    assert any("did not check its environment" in e for e in check_locked(no_lock_check))


def test_negative_a_shard_that_differs_from_the_lock():
    reports = make_reports()
    reports[0]["lock_errors"] = ["httpx is 0.28.0, the lock pins 0.28.1"]
    assert any("shard 1 differs from the lock" in e for e in check_locked(reports))
    anchor = {
        "identity": dict(IDENTITY),
        "lock_errors": ["extra==1 is installed but not in the lock"],
    }
    assert any(
        "anchor differs from the lock" in e for e in check_locked(make_reports(), anchor=anchor)
    )


def test_the_unlocked_suite_does_not_demand_an_identity():
    reports = make_reports()
    for r in reports:
        del r["identity"]
    assert check(reports) == []


def reports_with(**changes):
    reports = make_reports()
    reports[0].update(changes)
    return reports


# -- check_needs: the exact toJson(needs) shapes -----------------------------------------

REQUIRED = ("test-shard", "test-collect")


def needs(**results):
    return {job: {"result": r, "outputs": {}} for job, r in results.items()}


def test_needs_all_success_passes():
    assert (
        part.check_needs(needs(**{"test-shard": "success", "test-collect": "success"}), REQUIRED)
        == []
    )


@pytest.mark.parametrize("bad", ["failure", "cancelled", "skipped", None])
def test_negative_a_shard_matrix_that_did_not_succeed(bad):
    # A matrix reports failure or cancelled when any leg does; skipped and a missing
    # result must fail as well.
    shapes = needs(**{"test-shard": bad, "test-collect": "success"})
    if bad is None:
        shapes["test-shard"] = {"outputs": {}}
    errors = part.check_needs(shapes, REQUIRED)
    assert errors and "test-shard" in errors[0]


def test_negative_a_missing_job_and_a_malformed_entry():
    assert part.check_needs(needs(**{"test-shard": "success"}), REQUIRED)
    assert part.check_needs({"test-shard": "success", "test-collect": None}, REQUIRED)


def test_negative_cancelled_collect_anchor():
    shapes = needs(**{"test-shard": "success", "test-collect": "cancelled"})
    assert part.check_needs(shapes, REQUIRED)


# -- parse_collect_only ------------------------------------------------------------------


def test_parse_collect_only_keeps_ids_with_spaces_and_drops_the_summary():
    text = textwrap.dedent(
        """\
        tests/test_a.py::test_one[a b]
        tests/test_a.py::TestC::test_two

        2 tests collected in 0.10s
        """
    )
    assert part.parse_collect_only(text) == [
        "tests/test_a.py::test_one[a b]",
        "tests/test_a.py::TestC::test_two",
    ]


# -- the plugin, against a small real suite ----------------------------------------------

SUITE = {
    "test_alpha.py": """
        import pytest
        pytestmark = pytest.mark.xdist_group("alpha-group")
        @pytest.mark.parametrize("i", range(5))
        def test_a(i):
            assert True
    """,
    "test_beta.py": """
        import pytest
        @pytest.mark.parametrize("i", range(9))
        def test_b(i):
            assert i != 99
        @pytest.mark.xdist_group(name="beta-group")
        def test_grouped():
            pass
        def test_skipped():
            pytest.skip("x")
        @pytest.mark.slow
        def test_deselected_by_marker():
            pass
    """,
    "test_gamma.py": """
        def test_c1(): pass
        def test_c2(): pass
        def test_c3(): pass
    """,
}


@pytest.fixture
def suite(tmp_path):
    for name, body in SUITE.items():
        (tmp_path / name).write_text(textwrap.dedent(body))
    (tmp_path / "pytest.ini").write_text("[pytest]\nmarkers = slow\naddopts = -m 'not slow'\n")
    return tmp_path


def run_pytest(cwd, *args, check=True):
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTEST_DISABLE_PLUGIN_AUTOLOAD": ""}
    env.pop("PYTEST_DISABLE_PLUGIN_AUTOLOAD")
    env.pop("COVERAGE_PROCESS_START", None)
    env.update(GITHUB_RUN_ID=RUN, GITHUB_RUN_ATTEMPT="1")
    result = subprocess.run(  # noqa: S603 - this interpreter, test-built arguments
        [sys.executable, "-m", "pytest", "-p", "tests._sharding", "-p", "no:cacheprovider", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if check:
        assert result.returncode == 0, result.stdout + result.stderr
    return result


def collected(cwd, *args):
    out = run_pytest(cwd, "--collect-only", "-q", *args).stdout
    return part.parse_collect_only(out)


def test_the_plugin_is_inert_without_shard(suite):
    plain = collected(suite)
    assert len(plain) == len(set(plain)) == 5 + 9 + 1 + 1 + 3
    assert not any("test_deselected_by_marker" in i for i in plain)
    assert (
        run_pytest(
            suite, "--collect-only", "-q", "--shard-report", "x.json", check=False
        ).returncode
        == 4
    )


def test_shards_are_disjoint_complete_and_never_split_a_group(suite):
    plain = collected(suite)
    shards = [collected(suite, "--shard", f"{k}/3") for k in (1, 2, 3)]
    assert sorted(i for s in shards for i in s) == sorted(plain)
    assert all(shards)
    alpha = [{i for i in s if "test_alpha.py" in i} for s in shards]
    assert sorted(len(a) for a in alpha) == [0, 0, 5]  # one group, one shard
    assert collected(suite, "--shard", "2/3") == shards[1]  # deterministic


def test_a_bad_shard_is_a_usage_error(suite):
    for bad in ("0/3", "4/3", "x"):
        result = run_pytest(suite, "--collect-only", "-q", "--shard", bad, check=False)
        assert result.returncode == 4
        assert "--shard" in result.stderr


def shard_args(k, n, report):
    return ["--shard", f"{k}/{n}", "--shard-suite", SUITE_NAME, "--shard-report", str(report)]


def verify_args(**options):
    return {"n": 3, "suite": SUITE_NAME, "run": RUN, **options}


@pytest.mark.parametrize(
    "workers", [[], ["-n", "2", "--dist", "loadgroup", "--max-worker-restart=0"]]
)
def test_reports_pass_the_verifier_end_to_end(suite, workers):
    anchor = collected(suite)
    reports = []
    for k in (1, 2, 3):
        path = suite / f"r{k}.json"
        run_pytest(suite, "-q", *workers, *shard_args(k, 3, path))
        reports.append(json.loads(path.read_text()))
    assert part.verify(anchor, reports, coverage_files=["a", "b", "c"], **verify_args()) == []
    assert {o for r in reports for o in r["outcomes"].values()} == {"passed", "skipped"}
    assert all("@" not in i for r in reports for i in r["selected"] + list(r["outcomes"]))
    # Every report is bound to its run and carries the group names and the environment.
    assert {(r["suite"], r["run"], r["attempt"]) for r in reports} == {(SUITE_NAME, RUN, "1")}
    assert sorted(g for r in reports for g in r["groups"]) == ["alpha-group", "beta-group"]
    assert len({json.dumps(r["identity"], sort_keys=True) for r in reports}) == 1
    assert isinstance(reports[0]["lock_errors"], list)
    # Dropping one shard's report, a failing test or a wrong N must fail the same proof.
    assert part.verify(anchor, reports[:2], **verify_args())
    broken = copy.deepcopy(reports)
    broken[0]["outcomes"][broken[0]["selected"][0]] = "failed"
    assert part.verify(anchor, broken, **verify_args())
    assert part.verify(anchor, reports, **verify_args(n=4))
    assert part.verify(anchor, reports, **verify_args(suite="test-locked"))


def test_a_report_needs_a_suite_and_a_shard(suite):
    path = suite / "r.json"
    result = run_pytest(suite, "-q", "--shard", "1/1", "--shard-report", str(path), check=False)
    assert result.returncode == 4 and "--shard-suite" in result.stderr
    result = run_pytest(suite, "-q", "--shard-suite", "test", check=False)
    assert result.returncode == 4


def test_a_failing_test_is_recorded_as_failed(suite):
    (suite / "test_beta.py").write_text("def test_b():\n    assert False\n")
    path = suite / "r.json"
    result = run_pytest(suite, "-q", *shard_args(1, 1, path), check=False)
    assert result.returncode == 1
    report = json.loads(path.read_text())
    assert "failed" in report["outcomes"].values()
    anchor = collected(suite)
    assert part.verify(anchor, [report], **verify_args(n=1))


def test_setup_errors_and_xfail_outcomes_are_recorded(suite):
    (suite / "test_beta.py").write_text(
        textwrap.dedent(
            """
            import pytest
            @pytest.fixture
            def broken():
                raise RuntimeError("setup")
            def test_error(broken): pass
            @pytest.mark.xfail
            def test_expected(): assert False
            @pytest.mark.xfail
            def test_unexpected(): pass
            """
        )
    )
    path = suite / "r.json"
    run_pytest(suite, "-q", *shard_args(1, 1, path), check=False)
    outcomes = {
        i.rsplit("::", 1)[1]: o for i, o in json.loads(path.read_text())["outcomes"].items()
    }
    assert outcomes["test_error"] == "error"
    assert outcomes["test_expected"] == "xfailed"
    assert outcomes["test_unexpected"] == "xpassed"


def test_command_line_verify_exits_nonzero_on_a_defect(suite):
    anchor_file = suite / "anchor.txt"
    anchor_file.write_text("\n".join(collected(suite)))
    reports = suite / "reports"
    reports.mkdir()
    for k in (1, 2, 3):
        path = reports / f"r{k}.json"
        run_pytest(suite, "-q", *shard_args(k, 3, path))
        data = json.loads(path.read_text())
        data["lock_errors"] = []  # the dev checkout need not be the locked set
        path.write_text(json.dumps(data))
    cov = suite / "cov"
    for k in (1, 2, 3):
        (cov / f"s{k}").mkdir(parents=True)
        (cov / f"s{k}" / ".coverage").write_text("x")
    identity = suite / "anchor-identity.json"
    identity.write_text(
        json.dumps(
            {
                "identity": json.loads((reports / "r1.json").read_text())["identity"],
                "lock_errors": [],
            }
        )
    )
    proof_file = suite / "proof.json"
    base = [
        sys.executable,
        str(ROOT / "scripts" / "shard_partition.py"),
        "verify",
        "--anchor",
        str(anchor_file),
        "--reports",
        str(reports),
        "--shards",
        "3",
        "--job-total",
        "3",
        "--suite",
        SUITE_NAME,
        "--run-id",
        RUN,
        "--coverage",
        str(cov),
        "--locked",
        "--anchor-identity",
        str(identity),
        "--proof",
        str(proof_file),
    ]

    def run(args):
        return subprocess.run(args, capture_output=True, text=True, check=False)  # noqa: S603

    ok = run(base)
    assert ok.returncode == 0, ok.stderr
    record = json.loads(proof_file.read_text())
    assert record["totals"]["total"] == len(collected(suite)) and record["totals"]["passed"]
    assert record["suite"] == SUITE_NAME and len(record["shards"]) == 3
    assert record["shards"][0]["identity"]["dist_sha256"]
    assert record["ok"] is True and record["errors"] == []

    # N comes from the argument: a uniformly wrong N, a wrong matrix size, a wrong suite.
    def with_value(flag, value):
        args = list(base)
        args[args.index(flag) + 1] = value
        return args

    assert run(with_value("--shards", "4")).returncode == 1
    failed = json.loads(proof_file.read_text())  # a failed proof is recorded, not omitted
    assert failed["ok"] is False
    assert any("the matrix has 3 jobs but N is 4" in error for error in failed["errors"])
    assert "matrix has 4 jobs" in run(with_value("--job-total", "4")).stderr
    assert run(with_value("--suite", "test-locked")).returncode == 1
    no_identity = [a for a in base if a not in ("--anchor-identity", str(identity))]
    assert "anchor carries no environment identity" in run(no_identity).stderr
    (reports / "r2.json").unlink()
    bad = run(base)
    assert bad.returncode == 1
    assert "expected 3 shard reports" in bad.stderr


# -- environment identity helper ------------------------------------------------------------

_spec_id = importlib.util.spec_from_file_location(
    "env_identity", ROOT / "scripts" / "env_identity.py"
)
assert _spec_id and _spec_id.loader
ident = importlib.util.module_from_spec(_spec_id)
sys.modules.setdefault(_spec_id.name, ident)
_spec_id.loader.exec_module(ident)

LOCK = """\
# header
Alpha_Pkg==1.0 \\
    --hash=sha256:aa
    # via beta
beta[extra, more]==2.1 \\
    --hash=sha256:bb
only-linux==3.0 ; sys_platform == 'nonexistent' \\
    --hash=sha256:cc
"""
INSTALLED = {"alpha-pkg": "1.0", "beta": "2.1", "unifi-fabric-mcp-server": "0.7.1", "pip": "26.0"}
PROJECT = "unifi-fabric-mcp-server"


def test_lock_parsing_normalises_names_and_splits_conditional_pins():
    required, conditional = ident.parse_lock(LOCK)
    assert required == {"alpha-pkg": "1.0", "beta": "2.1"}
    assert conditional == {"only-linux": "3.0"}


def test_identity_matches_the_lock_pins_plus_the_project():
    assert ident.check_lock(INSTALLED, LOCK, PROJECT) == []


def test_identity_mismatch_is_listed():
    changed = {**INSTALLED, "beta": "2.2", "stray": "1"}
    errors = ident.check_lock(changed, LOCK, PROJECT)
    assert "beta is 2.2, the lock pins 2.1" in errors
    assert "stray==1 is installed but not in the lock" in errors
    wrong_conditional = {**INSTALLED, "only-linux": "9"}
    assert any("only-linux is 9" in e for e in ident.check_lock(wrong_conditional, LOCK, PROJECT))


def test_identity_missing_pin_or_project_is_listed():
    gone = {k: v for k, v in INSTALLED.items() if k != "beta"}
    assert "locked beta==2.1 is not installed" in ident.check_lock(gone, LOCK, PROJECT)
    no_project = {k: v for k, v in INSTALLED.items() if k != PROJECT}
    assert f"the project {PROJECT} is not installed" in ident.check_lock(no_project, LOCK, PROJECT)
    assert "the lock file has no pins" in ident.check_lock(INSTALLED, "# nothing\n", PROJECT)


def test_identity_is_python_plus_a_hash_of_the_sorted_distributions():
    one = ident.identity(INSTALLED)
    reordered = ident.identity(dict(reversed(INSTALLED.items())))
    assert one == reordered and one["count"] == 4
    expected = hashlib.sha256(
        "\n".join(f"{n}=={v}" for n, v in sorted(INSTALLED.items())).encode()
    ).hexdigest()
    assert one["dist_sha256"] == expected
    assert ident.identity({**INSTALLED, "beta": "2.2"})["dist_sha256"] != one["dist_sha256"]


def test_record_reads_this_environment_and_reports_an_unreadable_lock(tmp_path):
    here = ident.record(ROOT / "requirements.lock")
    assert here["identity"]["python"] and len(here["identity"]["dist_sha256"]) == 64
    assert isinstance(here["lock_errors"], list)
    missing = ident.record(tmp_path / "nope.lock")
    assert missing["identity"] == here["identity"] and "cannot read" in missing["lock_errors"][0]


def test_record_cli_writes_json_and_exits_one_on_a_difference(tmp_path):
    lock = tmp_path / "x.lock"
    lock.write_text("zzz-not-installed==1.0 \\\n    --hash=sha256:aa\n")
    out = tmp_path / "id.json"
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts" / "env_identity.py"),
            "record",
            "--lock",
            str(lock),
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1 and "zzz-not-installed==1.0 is not installed" in result.stderr
    assert json.loads(out.read_text())["lock_errors"]


# -- coverage data checks ---------------------------------------------------------------------


def coverage_file(path, rows):
    import sqlite3
    from contextlib import closing

    with closing(sqlite3.connect(path)) as db, db:
        db.execute("CREATE TABLE line_bits (file_id integer, context_id integer, numbits blob)")
        db.execute(
            "CREATE TABLE arc (file_id integer, context_id integer, fromno integer, tono integer)"
        )
        for _ in range(rows):
            db.execute("INSERT INTO line_bits VALUES (1, 1, x'01')")
    return path


def test_coverage_data_must_hold_measured_lines(tmp_path):
    assert part.coverage_has_data(coverage_file(tmp_path / "full", 1))
    assert not part.coverage_has_data(coverage_file(tmp_path / "empty", 0))
    (tmp_path / "junk").write_text("not sqlite")
    assert not part.coverage_has_data(tmp_path / "junk")
    assert not part.coverage_has_data(tmp_path / "absent")


def test_coverage_summary_keeps_percent_statements_and_missed():
    report = {
        "totals": {
            "percent_covered": 97.5,
            "num_statements": 400,
            "missing_lines": 10,
            "covered_lines": 390,
            "num_branches": 20,
        }
    }
    assert part.coverage_summary(report) == {
        "percent": 97.5,
        "statements": 400,
        "missed": 10,
        "covered": 390,
        "num_branches": 20,
    }


# -- the aggregate's artifact choice (select-artifacts) and the CI helper (shard_ci.sh) ----

SHARD_CI = ROOT / "scripts" / "shard_ci.sh"
BASH = shutil.which("bash") or "/bin/bash"


def _artifacts(*names):
    return part.select_artifacts(names, prefix="test-shard", run=RUN, n=3)


def test_select_artifacts_keeps_the_newest_attempt_of_each_shard():
    chosen, stale, errors = _artifacts(
        "test-shard-1-7-1", "test-shard-2-7-1", "test-shard-2-7-2", "test-shard-3-7-1"
    )
    assert errors == []
    assert chosen == {1: "test-shard-1-7-1", 2: "test-shard-2-7-2", 3: "test-shard-3-7-1"}
    assert stale == ["test-shard-2-7-1"]


@pytest.mark.parametrize(
    ("names", "expected"),
    [
        (("test-shard-1-7-1", "test-shard-2-7-1"), "shard 3/3 has no artifact"),
        (("test-shard-1-7-1", "test-shard-2-7-1", "test-shard-3-8-1"), "from run 8, not 7"),
        (
            ("test-shard-1-7-1", "test-shard-2-7-1", "test-shard-3-7-1", "test-shard-4-7-1"),
            "outside 1..3",
        ),
        (
            ("test-shard-1-7-1", "test-shard-2-7-1", "test-shard-3-7-1", "test-locked-shard-1-7-1"),
            "unexpected artifact",
        ),
        (
            ("test-shard-1-7-1", "test-shard-2-7-1", "test-shard-3-7-1", "test-shard-x-7-1"),
            "unexpected artifact",
        ),
    ],
)
def test_select_artifacts_fails_closed(names, expected):
    _, _, errors = _artifacts(*names)
    assert any(expected in error for error in errors), errors


def _cli(*args, env=None):
    return subprocess.run(  # noqa: S603 - repository script, test-built arguments
        [sys.executable, str(ROOT / "scripts" / "shard_partition.py"), *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_select_artifacts_cli_copies_one_directory_per_shard(tmp_path):
    root = tmp_path / "shards"
    for name in ("test-shard-1-7-1", "test-shard-2-7-1", "test-shard-2-7-2"):
        (root / name).mkdir(parents=True)
        (root / name / "report.json").write_text(json.dumps({"name": name}))
        (root / name / ".coverage").write_text("")
    out = tmp_path / "selected"
    args = ["select-artifacts", "--root", str(root), "--prefix", "test-shard"]
    result = _cli(*args, "--run-id", RUN, "--shards", "2", "--out", str(out))
    assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in out.iterdir()) == ["1", "2"]
    assert json.loads((out / "2" / "report.json").read_text())["name"] == "test-shard-2-7-2"
    assert "test-shard-2-7-1 replaced by a newer attempt" in result.stdout
    # A chosen artifact without its coverage data fails, and nothing is copied.
    (root / "test-shard-2-7-2" / ".coverage").unlink()
    again = _cli(*args, "--run-id", RUN, "--shards", "2", "--out", str(tmp_path / "again"))
    assert again.returncode == 1
    assert "test-shard-2-7-2 has no .coverage" in again.stderr
    assert not (tmp_path / "again").exists()


def _shard_ci(*args, env=None):
    return subprocess.run(  # noqa: S603 - repository script, test-built arguments
        [BASH, str(SHARD_CI), *args],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, **(env or {})},
    )


def test_shard_ci_plan_prints_the_matrix_and_refuses_a_bad_count():
    result = _shard_ci("plan", "4")
    assert result.returncode == 0
    assert result.stdout.splitlines() == ["shards=4", "list=[1,2,3,4]"]
    assert _shard_ci("plan", "20").stdout.splitlines()[1] == f"list={list(range(1, 21))}".replace(
        " ", ""
    )
    for bad in ("0", "257", "four", "", "-1"):
        assert _shard_ci("plan", bad).returncode == 2, bad


def test_shard_ci_check_requires_the_matrix_to_match_the_count(tmp_path):
    env = {"RUNNER_TEMP": str(tmp_path)}
    assert _shard_ci("check", "3", "4", "4", env=env).returncode == 0
    assert (tmp_path / "shard-out").is_dir()
    wrong_total = _shard_ci("check", "3", "4", "5", env=env)
    assert wrong_total.returncode == 1 and "the matrix has 5 jobs" in wrong_total.stderr
    assert _shard_ci("check", "5", "4", "4", env=env).returncode == 1
    assert _shard_ci("check", "0", "4", "4", env=env).returncode == 1


def test_shard_ci_aggregate_refuses_a_count_other_than_the_planned_one(tmp_path):
    env = {
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_RUN_ID": RUN,
        "GITHUB_SHA": COMMIT,
        "SHARD_NEEDS": "{}",
        "SHARD_REQUIRE": "classify,x-prep,x-shard",
    }
    result = _shard_ci("aggregate", "test", "python", "20", "8", env=env)
    assert result.returncode == 1
    assert "planned '8' shards, but the count is 20" in result.stderr
    assert _shard_ci("aggregate", "other", "python", "4", "4", env=env).returncode == 2
    assert _shard_ci("aggregate", "test", "python", "4", "4", "--fast", env=env).returncode == 2


def test_shard_ci_aggregate_refuses_a_missing_prep_anchor(tmp_path):
    env = {
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_RUN_ID": RUN,
        "GITHUB_SHA": COMMIT,
        "SHARD_NEEDS": "{}",
        "SHARD_REQUIRE": "classify,x-prep,x-shard",
    }
    result = _shard_ci("aggregate", "test", "python", "4", "4", env=env)
    assert result.returncode == 1
    assert "no anchor list from test-prep" in result.stderr
    (tmp_path / "anchor").mkdir()
    (tmp_path / "anchor" / "anchor.txt").write_text("tests/test_a.py::test_a\n")
    locked = _shard_ci("aggregate", "test-locked", "python", "4", "4", "--locked", env=env)
    assert locked.returncode == 1
    assert "no anchor identity from test-locked-prep" in locked.stderr


def test_summary_markdown_lists_every_shard():
    record = {
        "suite": "test-locked",
        "n": 2,
        "anchor_count": 3,
        "anchor_sha256": "f" * 64,
        "totals": {"passed": 2, "skipped": 1, "total": 3},
        "shards": [
            {"k": 1, "attempt": "1", "selected": 2, "totals": {"passed": 2}, "install_seconds": 31},
            {"k": 2, "attempt": "2", "selected": 1, "totals": {"skipped": 1}},
        ],
    }
    text = part.summary_markdown(record, {"percent": 97.5, "statements": 10, "missed": 1})
    assert "### Shard proof: test-locked (2 shards)" in text
    assert "Combined coverage 97.5000% of 10 statements, 1 missed." in text
    assert "| 1 | 1 | 2 | 2 | 0 | 31 |" in text and "| 2 | 2 | 1 | 0 | 1 | - |" in text


# -- scrub oracle: chunk evidence, the floor's junit, scrub-aggregate --------------------

SCRUB_CHUNK = "tests/test_secret_scrub_oracle.py::test_slow[{}]"
SCRUB_FLOOR = "tests/test_secret_scrub_oracle.py::test_slow_coverage_floor"


def scrub_shards(per_shard=((0, 1), (2, 3))):
    """K -> (report, evidence files) for shards that each ran ``per_shard[K-1]`` chunks."""
    shards = {}
    for k, chunks in enumerate(per_shard, start=1):
        outcomes = {SCRUB_CHUNK.format(c): "passed" for c in chunks}
        files = {f"slow-{72000 + c}.json": {"corpus": "slow", "seed": 72000 + c} for c in chunks}
        shards[k] = ({"outcomes": outcomes}, files)
    return shards


def test_scrub_evidence_one_file_per_chunk_passes():
    shards = scrub_shards()
    # The floor test is collected in one shard too, where it skips; it is not a chunk.
    shards[2][0]["outcomes"][SCRUB_FLOOR] = "skipped"
    assert part.scrub_evidence(shards) == []


def _drop(shards, k, name):
    del shards[k][1][name]


def _add(shards, k, name, data):
    shards[k][1][name] = data


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda s: _drop(s, 2, "slow-72003.json"), "shard 2 ran 2 chunks but left 1 evidence"),
        (
            lambda s: _add(s, 1, "slow-72099.json", {"corpus": "slow", "seed": 72099}),
            "shard 1 ran 2 chunks but left 3 evidence",
        ),
        (
            lambda s: _add(s, 2, "slow-72000.json", {"corpus": "slow", "seed": 72000}),
            "seed 72000 has evidence from shards 1 and 2",
        ),
        (
            lambda s: s[1][1]["slow-72000.json"].update(seed=72001),
            "slow-72000.json does not hold the slow corpus seed 72000",
        ),
        (
            lambda s: s[1][1]["slow-72001.json"].update(corpus="fast"),
            "slow-72001.json does not hold the slow corpus seed 72001",
        ),
        (lambda s: _add(s, 1, "notes.json", {}), "unexpected evidence file 'notes.json'"),
        (
            lambda s: s[2][0]["outcomes"].update({SCRUB_CHUNK.format(3): "failed"}),
            "shard 2: chunks that did not pass: 1",
        ),
    ],
    ids=["missing", "extra", "duplicate", "wrong-seed", "wrong-corpus", "stray", "failed"],
)
def test_scrub_evidence_fails_closed(mutate, expected):
    shards = scrub_shards()
    mutate(shards)
    errors = part.scrub_evidence(shards)
    assert any(expected in error for error in errors), errors


JUNIT = """<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest">
<testcase classname="tests.test_secret_scrub_oracle" name="test_slow_coverage_floor" time="0.5"
>{body}</testcase></testsuite></testsuites>"""


@pytest.mark.parametrize(
    ("body", "passed"),
    [
        ("", True),
        ('<skipped message="aggregate step"/>', False),
        ('<failure message="below the floor"/>', False),
        ('<error message="setup"/>', False),
    ],
    ids=["passed", "skipped", "failed", "error"],
)
def test_junit_passed_counts_only_a_case_that_ran_and_passed(tmp_path, body, passed):
    name = "tests.test_secret_scrub_oracle::test_slow_coverage_floor"
    assert part.junit_passed(JUNIT.format(body=body)) == (([name], []) if passed else ([], [name]))
    report = tmp_path / "floor.xml"
    report.write_text(JUNIT.format(body=body))
    result = _cli("junit-passed", str(report), "--count", "1")
    assert result.returncode == (0 if passed else 1), result.stderr
    assert _cli("junit-passed", str(report), "--count", "2").returncode == 1


def _scrub_selected(tmp_path, shards):
    selected = tmp_path / "selected"
    for k, (report, files) in shards.items():
        (selected / str(k) / "evidence").mkdir(parents=True)
        (selected / str(k) / "report.json").write_text(json.dumps(report))
        for name, data in files.items():
            (selected / str(k) / "evidence" / name).write_text(json.dumps(data))
    return selected


def test_scrub_evidence_cli_merges_one_file_per_chunk(tmp_path):
    selected = _scrub_selected(tmp_path, scrub_shards())
    out = tmp_path / "merged"
    result = _cli(
        "scrub-evidence", "--shards-dir", str(selected), "--shards", "2", "--out", str(out)
    )
    assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in out.iterdir()) == [f"slow-{72000 + c}.json" for c in range(4)]
    assert "4 chunk files from 2 shards, one per chunk" in result.stdout


def test_scrub_evidence_cli_fails_closed_and_merges_nothing(tmp_path):
    shards = scrub_shards()
    _drop(shards, 1, "slow-72001.json")
    selected = _scrub_selected(tmp_path, shards)
    (selected / "3").mkdir()
    out = tmp_path / "merged"
    result = _cli(
        "scrub-evidence", "--shards-dir", str(selected), "--shards", "2", "--out", str(out)
    )
    assert result.returncode == 1
    assert "unexpected shard directories ['3']" in result.stderr
    assert "shard 1 ran 2 chunks but left 1 evidence files" in result.stderr
    assert not out.exists()
    missing = _cli(
        "scrub-evidence", "--shards-dir", str(selected), "--shards", "4", "--out", str(out)
    )
    assert missing.returncode == 1 and "shard 4 has no report" in missing.stderr


def test_select_artifacts_cli_requires_the_named_files(tmp_path):
    root = tmp_path / "shards"
    for k in (1, 2):
        (root / f"scrub-oracle-shard-{k}-7-1").mkdir(parents=True)
        (root / f"scrub-oracle-shard-{k}-7-1" / "report.json").write_text("{}")
    args = ["select-artifacts", "--root", str(root), "--prefix", "scrub-oracle-shard"]
    args += ["--run-id", RUN, "--shards", "2"]
    # The default also requires coverage data, which the scrub shards do not produce.
    assert _cli(*args, "--out", str(tmp_path / "a")).returncode == 1
    result = _cli(*args, "--out", str(tmp_path / "b"), "--files", "report.json")
    assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in (tmp_path / "b").iterdir()) == ["1", "2"]


def test_shard_ci_scrub_aggregate_refuses_a_count_other_than_the_planned_one(tmp_path):
    env = {
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_RUN_ID": RUN,
        "GITHUB_SHA": COMMIT,
        "SHARD_NEEDS": "{}",
        "SHARD_REQUIRE": "classify,x-prep,x-shard",
    }
    result = _shard_ci("scrub-aggregate", "python", "25", "20", env=env)
    assert result.returncode == 1
    assert "scrub-oracle-prep planned '20' shards, but the count is 25" in result.stderr
    assert _shard_ci("scrub-aggregate", "python", "0", "0", env=env).returncode == 1
    assert _shard_ci("scrub-aggregate", "python", "25", env=env).returncode == 2


def test_shard_ci_scrub_aggregate_fails_closed_on_a_missing_shard(tmp_path):
    """Real anchor collection; one shard's artifact is absent, so selection fails before
    any evidence or floor step runs."""
    shards = tmp_path / "shards"
    (shards / "scrub-oracle-shard-1-7-1").mkdir(parents=True)
    (shards / "scrub-oracle-shard-1-7-1" / "report.json").write_text("{}")
    env = {
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_RUN_ID": RUN,
        "GITHUB_SHA": COMMIT,
        "SHARD_NEEDS": "{}",
        "SHARD_REQUIRE": "classify,x-prep,x-shard",
        "GITHUB_STEP_SUMMARY": "",
    }
    result = _shard_ci("scrub-aggregate", sys.executable, "2", "2", env=env)
    assert result.returncode == 1
    assert "shard 2/2 has no artifact" in result.stderr
    anchor = part.parse_collect_only((tmp_path / "proof" / "anchor.txt").read_text())
    child = [i for i in anchor if i.startswith("tests/test_secret_scrub_child_breaks_split.py::")]
    assert len(child) >= 24, child  # the split differential's slow cases are in the anchor too
    rest = [i for i in anchor if i not in child]
    assert sorted(rest) == sorted([SCRUB_CHUNK.format(c) for c in range(50)] + [SCRUB_FLOOR])
    assert not (tmp_path / "scrub-evidence").exists()
    assert not (tmp_path / "proof" / "floor.xml").exists()
