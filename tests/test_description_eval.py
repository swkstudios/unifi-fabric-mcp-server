"""The tool-description eval: its task set, its committed baseline and its scoring.

The model part of the eval (``claude -p``) never runs here. These tests keep the 120-task set
honest (every family covered, weighted by tool count, at least 20 near-duplicate pairs, at least
60 tasks whose values the description must supply, an expected tool and its required arguments on
every task), keep the committed baseline tied to that task set, re-run the deterministic selection
(``search_tools``) against the committed floor, and test the scoring, batching and token-budget
code with fake answers.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "eval_descriptions", ROOT / "scripts" / "eval_descriptions.py"
)
assert SPEC is not None and SPEC.loader is not None
ev = importlib.util.module_from_spec(SPEC)
sys.modules["eval_descriptions"] = ev
SPEC.loader.exec_module(ev)

TASKS = ev.load_tasks()
BASELINE = json.loads(ev.BASELINE.read_text())
HARD_CATEGORIES = {"enum_words", "unit", "similar_params", "implied", "body_shape"}


@pytest.fixture(scope="module")
def catalog():
    from tests._tool_catalog import tools

    return {t.name: t for t in tools()}


@pytest.fixture(scope="module")
def families():
    from unifi_fabric.families import build_family_index

    return build_family_index()


def test_task_set_has_120_unique_tasks():
    assert len(TASKS) == 120
    assert len({t["id"] for t in TASKS}) == 120
    assert len({t["task"] for t in TASKS}) == 120


def test_every_task_names_a_registered_tool_and_states_its_required_arguments(catalog):
    for task in TASKS:
        tool = catalog[task["expected_tool"]]
        props = tool.parameters.get("properties", {})
        required = set(tool.parameters.get("required", []))
        args = task["required_args"]
        assert required <= set(args), (task["id"], sorted(required - set(args)))
        assert set(args) <= set(props), (task["id"], sorted(set(args) - set(props)))


def test_tasks_do_not_embed_the_name_of_their_tool():
    leaks = [
        t["id"]
        for t in TASKS
        if " ".join(t["expected_tool"].split("_")).casefold() in t["task"].casefold()
        or t["expected_tool"] in t["task"]
    ]
    assert not leaks, leaks


def test_at_least_sixty_tasks_need_the_description_to_get_the_arguments_right():
    hard = [t for t in TASKS if t.get("hard")]
    assert len(hard) >= 60
    assert {t["hard"] for t in hard} <= HARD_CATEGORIES
    assert Counter(t["hard"] for t in hard).keys() == HARD_CATEGORIES  # every kind is present
    for task in hard:
        # a hard task asks for something beyond host, site and ids
        assert set(task["required_args"]) - {"host", "site"}, task["id"]


def test_family_of_every_task_matches_the_family_index(families):
    wrong = [t["id"] for t in TASKS if families.get(t["expected_tool"]) != t["family"]]
    assert not wrong, wrong


def test_every_family_has_a_task_and_the_share_follows_the_tool_count(families):
    tools_per_family = Counter(families.values())
    tasks_per_family = Counter(t["family"] for t in TASKS)
    total_tools = sum(tools_per_family.values())
    assert set(tasks_per_family) == set(tools_per_family), "a family has no task"
    for family, count in tools_per_family.items():
        want = len(TASKS) * count / total_tools
        assert abs(tasks_per_family[family] - want) <= 6, (family, tasks_per_family[family], want)
        assert abs(tasks_per_family[family] / len(TASKS) - count / total_tools) <= 0.05, family


def test_at_least_twenty_near_duplicate_pairs_of_two_different_tools():
    pairs: dict[str, list[dict]] = {}
    for task in TASKS:
        if task["pair"]:
            pairs.setdefault(task["pair"], []).append(task)
    assert len(pairs) >= 20
    for name, members in pairs.items():
        assert len(members) == 2, name
        assert members[0]["expected_tool"] != members[1]["expected_tool"], name


def test_baseline_belongs_to_this_task_set_and_this_protocol():
    assert BASELINE["tasks_sha256"] == ev.tasks_sha256(), (
        "tasks.json changed: re-measure and write the baseline"
    )
    assert BASELINE["model"] == "claude-haiku-5-5"
    assert BASELINE["runs"] == 3 and BASELINE["tasks"] == 120
    assert BASELINE["hard_tasks"] == sum(1 for t in TASKS if t.get("hard")) >= 60
    tokens = BASELINE["tokens"]
    assert tokens["total"] <= tokens["budget"] <= 3_000_000
    assert tokens["search_mode"] + tokens["full_mode"] == tokens["total"]
    overall = BASELINE["selection"]["overall"]
    assert overall["top1"] <= overall["top5"] <= overall["tasks"] == 120
    assert sum(f["tasks"] for f in BASELINE["selection"]["by_family"].values()) == 120
    for mode in ("search_mode", "full_mode"):
        report = BASELINE[mode]
        assert len(report["per_run_arguments"]) == 3
        for key in ("selection_accuracy", "argument_accuracy_end_to_end"):
            spread = report[key]
            assert spread["min"] <= spread["mean"] <= spread["max"]
            assert spread["range"] == pytest.approx(spread["max"] - spread["min"], abs=1e-4)
        assert set(report["by_hard_category"]) == HARD_CATEGORIES


def test_the_baseline_shows_that_a_worse_description_lowers_the_score():
    worse = BASELINE["sensitivity_degraded_descriptions"]
    for mode in ("search_mode", "full_mode"):
        good = BASELINE[mode]["argument_accuracy_end_to_end"]["min"]
        bad = worse[mode]["argument_accuracy_end_to_end"]["max"]
        assert bad < good - 0.05, (mode, bad, good)


def test_selection_through_search_tools_stays_above_the_committed_floor():
    selection = asyncio.run(ev.run_selection())
    assert selection["tasks_sha256"] == BASELINE["tasks_sha256"]
    assert all(1 <= len(row["top"]) <= ev.TOP_N for row in selection["rows"])
    assert set(selection["tools"]) == set(selection["family_of"])
    now = ev.selection_numbers(TASKS, selection["rows"])["overall"]
    floor = BASELINE["selection"]["overall"]["top5"] - ev.CHECK_SLACK_TASKS
    assert now["top5"] >= floor, (now, floor, "a description change made tools harder to find")


@pytest.fixture(scope="module")
def fake_selection():
    tasks_by_family = {}
    for task in TASKS:
        tasks_by_family.setdefault(task["family"], []).append(task)
    tools, family_of = {}, {}
    for family, members in tasks_by_family.items():
        for task in members:
            name = task["expected_tool"]
            tools[name] = {
                "name": name,
                "description": f"Does {name}. Second sentence.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"x": {"type": "string", "description": "the x"}},
                },
            }
            family_of[name] = family
    for i in range(3):  # tools no task expects
        tools[f"other_{i}"] = {"name": f"other_{i}", "description": "Other.", "inputSchema": {}}
        family_of[f"other_{i}"] = "network"
    rows = [
        {"id": t["id"], "top": [t["expected_tool"], "other_0", "other_1", "other_2", "other_0"][:5]}
        for t in TASKS
    ]
    return {"rows": rows, "tools": tools, "family_of": family_of}


def test_search_batches_hold_tasks_of_one_family_with_their_own_candidates(fake_selection):
    batches = ev.make_batches(fake_selection, "search")
    seen = [t["id"] for b in batches for t in b["tasks"]]
    assert sorted(seen) == sorted(t["id"] for t in TASKS)
    for batch in batches:
        assert len(batch["tasks"]) <= ev.SEARCH_BATCH
        assert len({t["family"] for t in batch["tasks"]}) == 1
        for task in batch["tasks"]:
            assert batch["candidates"][task["id"]][0] == task["expected_tool"]
            assert set(batch["candidates"][task["id"]]) <= set(batch["tools"])


def test_full_batches_send_every_tool_of_the_family_once_and_no_candidate_limit(fake_selection):
    batches = ev.make_batches(fake_selection, "full")
    assert len(batches) == len({t["family"] for t in TASKS})
    for batch in batches:
        family = batch["tasks"][0]["family"]
        want = sorted(n for n, f in fake_selection["family_of"].items() if f == family)
        assert batch["tools"] == want
        assert all(v is None for v in batch["candidates"].values())


def test_the_prompt_lists_each_task_with_its_candidates_and_the_tools_once(fake_selection):
    batch = ev.make_batches(fake_selection, "search")[0]
    prompt = ev.build_prompt(batch, fake_selection["tools"])
    for task in batch["tasks"]:
        assert (
            f"{task['id']} | candidates: {', '.join(batch['candidates'][task['id']])} | " in prompt
        )
    for name in batch["tools"]:
        assert prompt.count(f'"name":"{name}"') == 1
    assert "any tool above" in ev.build_prompt(
        ev.make_batches(fake_selection, "full")[0], fake_selection["tools"]
    )
    assert "_meta" not in prompt and '"title"' not in prompt


def test_the_degraded_entry_keeps_the_name_and_loses_the_help():
    entry = {
        "name": "t",
        "description": "First sentence. Second one with details.",
        "inputSchema": {
            "type": "object",
            "properties": {"a": {"type": "string", "description": "help"}},
        },
    }
    worse = ev.degrade(entry)
    assert worse["name"] == "t" and worse["description"] == "First sentence."
    assert "description" not in json.dumps(worse["inputSchema"])
    assert worse["inputSchema"]["properties"]["a"] == {"type": "string"}


@pytest.mark.parametrize(
    ("expected", "got", "ok"),
    [
        ("Home UDM", "home udm", True),
        (5, "5", True),
        (5, 6, False),
        (True, True, True),
        (True, "true", False),
        ({"$contains": ["IoT", "30"]}, {"name": "iot", "vlan": 30}, True),
        ({"$contains": ["IoT", "30"]}, {"name": "iot"}, False),
        ({"$contains": []}, {"anything": 1}, True),
        ({"$subset": {"vlanId": 30, "name": "IoT"}}, {"vlanId": "30", "name": "iot", "x": 1}, True),
        ({"$subset": {"vlanId": 30}}, {"vlanId": 31}, False),
        ({"$subset": {"a": {"$subset": {"b": 1}}}}, {"a": {"b": 1, "c": 2}}, True),
        ({"$subset": {"a": 1}}, "not an object", False),
        ({"$any_of": ["unlock", "open"]}, "open", True),
        ({"$any_of": ["x", ["x"]]}, ["x"], True),
        (["high", "low"], ["low", "medium", "high"], True),
        (["high", "low"], ["high"], False),
    ],
)
def test_argument_values_are_compared_as_documented(expected, got, ok):
    assert ev.value_matches(expected, got) is ok


def test_parse_answers_reads_an_array_of_objects_by_task_id():
    reply = (
        'Here you go.\n```json\n[{"id": "t001", "tool": "list_networks",'
        ' "arguments": {"host": "h"}},'
        ' {"id": "t002", "tool": "get_x", "arguments": {"body": {"a": [1, 2]}}}]\n```'
    )
    found = ev.parse_answers(reply)
    assert set(found) == {"t001", "t002"}
    assert found["t002"]["arguments"] == {"body": {"a": [1, 2]}}
    assert ev.parse_answers('{"nope": 1}') == {}
    assert ev.parse_answers("no json at all") == {}


def test_a_tool_outside_the_offered_candidates_never_counts():
    task = {"expected_tool": "get_x", "required_args": {"host": "h"}}
    answer = {"tool": "get_x", "arguments": {"host": "h"}}
    assert ev.score_answer(task, answer, ["get_x", "get_y"]) == {"tool": True, "args": True}
    assert ev.score_answer(task, answer, None) == {"tool": True, "args": True}
    assert ev.score_answer(task, answer, ["get_y"]) == {"tool": False, "args": False}
    assert ev.score_answer(task, {"tool": "get_x", "arguments": {}}, ["get_x"]) == {
        "tool": True,
        "args": False,
    }
    assert ev.score_answer(task, None, ["get_x"]) == {"tool": False, "args": False}


def test_the_token_ledger_refuses_a_call_that_would_pass_the_budget():
    ledger = ev.Ledger(1000)
    assert ledger.reserve(600)
    assert not ledger.reserve(500)  # 600 reserved + 500 > 1000
    ledger.settle(600, 450)
    assert ledger.reserve(500) and ledger.spent == 450
