# Tool-description eval

A fixed set of 120 tasks that measures whether an agent finds the right tool from its
description and then fills in its arguments correctly. It is the yardstick for description changes.
Run it before and after, and keep a change when the numbers stay inside the run-to-run
spread recorded in `baseline.json`.

- `tasks.json`: the task set. Every task has the tool that does it (`expected_tool`), the
  arguments it needs (`required_args`) and its family. 44 tasks form 22 near-duplicate pairs whose
  two tools are easy to confuse. Every family has at least one task and the share of tasks follows
  the share of tools. 62 tasks carry a `hard` category: the task says a value in plain words
  (`enum_words`, "only 5 GHz"), in another unit (`unit`, "2 days" for minutes), by choosing between
  similar parameters (`similar_params`), by implication (`implied`, "leave alignment mode" is
  `enabled: false`), or as a request body whose shape only the description gives (`body_shape`).
  A worse description lowers the score on these tasks; the plain-value tasks keep a floor under it.
  Argument matching: a string is compared without case; `{"$contains": [...]}` needs each string
  inside the value; `{"$subset": {...}}` needs each key (nested objects the same way);
  `{"$any_of": [...]}` accepts any one alternative.
- `baseline.json`: the committed numbers, measured on the `dev` head named in `measured_on`:
  the deterministic selection (top-1 and top-5 of `search_tools`), and for each of the two model
  modes the selection and argument accuracy over three runs, the spread, the hard tasks on their
  own, and the tokens spent. `sensitivity_degraded_descriptions` is the same protocol with every
  tool cut to its first sentence and no parameter descriptions; the gap to the baseline is the
  signal strength of the eval.
- `scripts/eval_descriptions.py`: the runner.
  - `select` (deterministic): each task goes through `search_tools` of the discovery-mode server;
    top-1 and top-5 are recorded, and every tool's `describe_tool` entry is saved.
  - `llm`, search mode: `claude -p --model claude-haiku-5-5` gets the task and the entries of its
    five search results, picks one and writes the arguments.
  - `llm`, full mode: the same model gets the task and the full `tools/list` entries (name,
    description, input schema) of the task's whole family and picks from those, with no search.
  - Three runs per mode, tasks sent in batches (up to 20 per call in search mode, a whole family
    per call in full mode) so that a full run stays under 3,000,000 tokens. The runner estimates
    first, refuses to start over the budget, and reserves tokens per call.
- `tests/test_description_eval.py` guards the task set, the baseline file and the deterministic
  selection floor in CI. It never calls a model.

Re-measure after a description pass:

```bash
python3 scripts/eval_descriptions.py select --out /tmp/selection.json
python3 scripts/eval_descriptions.py llm --selection /tmp/selection.json --out /tmp/llm.json
python3 scripts/eval_descriptions.py report --selection /tmp/selection.json --llm /tmp/llm.json
```

Add `--write-baseline` to `report` (and `--degraded` with the output of
`llm --degrade --runs 1`) only when the catalog or the task set changed on purpose.
