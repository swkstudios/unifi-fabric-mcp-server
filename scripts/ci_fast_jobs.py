"""Run CI's fast jobs locally, reading the steps from the workflows themselves.

``scripts/prepush.sh`` is the entry point. The workflow files are the single step list:
every workflow that runs for a pull request is classified in ``CI_ONLY``, and every
``run`` step of every job it does not keep in CI executes here, ``ci.yml`` first and then
the others by file name, in workflow order, as it would for a pull request from HEAD
into the base branch. Job and step ``if`` conditions are evaluated with that pull
request's context, so a job runs locally exactly when CI would run it. A workflow's
``pull_request`` branch filter is not applied: a change that targets a release
integration branch reaches ``dev`` through the release pull request, where those
workflows gate it. Only the environment-provisioning steps in ``SETUP_STEPS`` are
replaced by the local development environment, whose Python version must match the
workflow's, and the steps in ``CI_ONLY_STEPS`` stay in CI with a stated reason. A
construct this runner cannot reproduce (an unknown expression context, a matrix,
another shell) or a pull-request workflow missing from ``CI_ONLY`` stops the run with
an error; no step is dropped silently.

After the workflows, the test files in ``PREPUSH_GUARDS`` run on every pre-push.

``--full`` (``scripts/prepush.sh --full``, opt-in and advisory: it never stands in for
CI) also runs the full suite, last: the ``FULL_SUITE_JOB`` job is lifted out of
``CI_ONLY`` with its ``if`` forced, so its one full-suite step runs exactly as read from
ci.yml.
Only the xdist worker count may differ (``PREPUSH_XDIST_WORKERS``; default the
workflow's), and the step runs without any credential variable (``is_credential``).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
WORKFLOW = WORKFLOWS / "ci.yml"

#: Every workflow that runs for a pull request, mapped to the jobs that stay in CI and
#: why. Every other job of these workflows is a fast job and runs here. A listed
#: workflow the tree does not carry is not run (the public tree has no private-only
#: workflows); ci.yml is required.
CI_ONLY: dict[str, dict[str, str]] = {
    "ci.yml": {
        "test": "full suite with the coverage gate",
        "test-locked": "full suite in the exact locked environment",
        "scrub-oracle": "210,000-case scrubber acceptance corpus and its coverage floor",
        "gitleaks": "pinned secret-scanner binary over the full history",
        "docker-build": "container image build",
        "divergence-gate": "compares remote branch lineage with a repository token",
        "notify-matrix": "failure notification",
        "lint-public-language": "public repository text scan",
    },
    "changelog-size.yml": {},
    "dependabot-auto-merge.yml": {
        "dependabot-auto-merge": "approves and merges dependency updates with a repository token",
    },
    "docs-checks.yml": {
        "reference-report": "scheduled external reference report, never run for a pull request",
    },
    "install-smoke.yml": {
        "linux": "installs the built package through every documented launcher "
        "(about 13 minutes measured locally)",
        "linux-docker": "Docker install paths, run for a release or a protected manual run",
        "release-rehearsal": "hosted macOS install rehearsal, manual runs only",
    },
    "lint-public-language.yml": {"lint-public-language": "public repository text scan"},
    "public-artifact-dry-run.yml": {
        "public-artifact-dry-run": "installs a secret scanner with root rights and resolves "
        "issue references with the repository token",
    },
}

#: The ci.yml jobs that stay in CI.
CI_ONLY_JOBS = CI_ONLY["ci.yml"]

#: Steps of fast jobs that stay in CI, keyed by (workflow, job, step name).
CI_ONLY_STEPS: dict[tuple[str, str, str], str] = {
    ("docs-checks.yml", "docs-checks", "External reference links"): (
        "requests every external documentation URL; a third-party outage is not a "
        "property of the commit"
    ),
}

#: Test files that run on every pre-push, whatever the change. Each checks a committed
#: artifact against inputs spread over the tree (a stored source fingerprint, a strip
#: list), so a stale artifact can sit on the base branch while the changed-path
#: selection never names it, and a change the selector escalates to the full tier runs
#: no test locally at all. Without this, the first full-suite run fails instead of the
#: pre-push of the commit that made the artifact stale.
PREPUSH_GUARDS: tuple[str, ...] = ()
GUARD_PYTEST = ("-m", "pytest", "-q", "-n", "4", "--max-worker-restart=0")

#: Events that start a workflow for a pull request.
PULL_REQUEST_EVENTS = frozenset({"pull_request", "pull_request_target"})

#: ``--full``: the ci.yml job whose full-suite step runs locally.
FULL_SUITE_JOB = "test"
#: Variables never passed to the ``--full`` suite: the server's credential namespaces
#: (``UNIFI_*`` holds the console API keys and live-test targets, ``MCP_*`` the bearer
#: token and TLS key password) and any credential-shaped name.
CREDENTIAL_PREFIXES = ("UNIFI_", "MCP_")
CREDENTIAL_NAME = re.compile(r"API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|CREDENTIAL")
_WORKERS = re.compile(r"(?<=\s)-n\s+(\S+)(?=\s|$)")

#: Steps that provision the CI runner's environment. Locally the development
#: environment (installed from requirements.lock) takes their place.
SETUP_STEPS = frozenset({"Install ruff (hash-pinned)", "Cache key", "Install dev environment"})

_STATUS_FUNCTIONS = ("success()", "always()", "cancelled()", "failure()")
_SHELLS = {
    None: ["bash", "-e"],
    "bash": ["bash", "--noprofile", "--norc", "-eo", "pipefail"],
}


class WorkflowError(Exception):
    """The workflow uses something this local runner cannot reproduce faithfully."""


class StepFailed(Exception):
    def __init__(self, job: str, step: str, code: int) -> None:
        super().__init__(f"job {job}, step {step!r} exited {code}")


# --------------------------------------------------------------------------------------
# Expressions (the subset of the GitHub Actions expression language the workflow uses)
# --------------------------------------------------------------------------------------


class Strict(dict):
    """A context object whose missing keys are an error, not a silent null."""

    def __init__(self, name: str, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.name = name


def strict(name: str, value: Any) -> Any:
    """Recursively wrap mappings so a property the local run does not model is an error."""
    if isinstance(value, dict):
        return Strict(name, {k: strict(f"{name}.{k}", v) for k, v in value.items()})
    if isinstance(value, list):
        return [strict(name, v) for v in value]
    return value


class _Filtered(list):
    """Result of an object filter (``a.*``); property access maps over the elements."""


_TOKEN = re.compile(
    r"\s*(?:(?P<number>\d+(?:\.\d+)?)|'(?P<string>(?:[^']|'')*)'"
    r"|(?P<op>==|!=|<=|>=|&&|\|\||[!<>().\[\],*])|(?P<name>[A-Za-z_][A-Za-z0-9_-]*))"
)


def _tokens(text: str) -> list[tuple[str, Any]]:
    result, position = [], 0
    while position < len(text):
        if text[position:].strip() == "":
            break
        match = _TOKEN.match(text, position)
        if not match:
            raise WorkflowError(f"cannot parse expression near {text[position:]!r}")
        position = match.end()
        if match.group("number") is not None:
            result.append(("literal", float(match.group("number"))))
        elif match.group("string") is not None:
            result.append(("literal", match.group("string").replace("''", "'")))
        elif match.group("op") is not None:
            result.append(("op", match.group("op")))
        else:
            name = match.group("name")
            keyword = {"true": True, "false": False, "null": None}
            result.append(("literal", keyword[name]) if name in keyword else ("name", name))
    return result


def _truthy(value: Any) -> bool:
    if isinstance(value, float) and math.isnan(value):
        return False
    return value not in (None, False, 0, "")


def _number(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip() or 0)
        except ValueError:
            return math.nan
    return math.nan


def _equal(left: Any, right: Any) -> bool:
    if isinstance(left, str) and isinstance(right, str):
        return left.casefold() == right.casefold()
    if type(left) is type(right) or (left is None and right is None):
        return left == right
    if isinstance(left, (dict, list)) or isinstance(right, (dict, list)):
        return left is right
    return _number(left) == _number(right)


def to_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else repr(value)
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2)
    return str(value)


def _contains(search: Any, item: Any) -> bool:
    if isinstance(search, list):
        return any(_equal(element, item) for element in search)
    return to_string(item).casefold() in to_string(search).casefold()


def _format(template: Any, *args: Any) -> str:
    def replace(match: re.Match[str]) -> str:
        if match.group(0) in ("{{", "}}"):
            return match.group(0)[0]
        return to_string(args[int(match.group(1))])

    return re.sub(r"\{\{|\}\}|\{(\d+)\}", replace, to_string(template))


_FUNCTIONS: dict[str, Callable[..., Any]] = {
    "contains": _contains,
    "startswith": lambda s, p: to_string(s).casefold().startswith(to_string(p).casefold()),
    "endswith": lambda s, p: to_string(s).casefold().endswith(to_string(p).casefold()),
    "format": _format,
    "join": lambda items, sep=",": to_string(sep).join(
        to_string(i) for i in (items if isinstance(items, list) else [items])
    ),
    "tojson": lambda value: json.dumps(value, indent=2),
    "fromjson": lambda value: json.loads(to_string(value)),
    # The run stops at the first failure, so every evaluation happens while the
    # run is succeeding and has not been cancelled.
    "success": lambda: True,
    "always": lambda: True,
    "cancelled": lambda: False,
    "failure": lambda: False,
}


class _Parser:
    def __init__(self, text: str, context: dict[str, Any]) -> None:
        self.text = text
        self.tokens = _tokens(text)
        self.index = 0
        self.context = context

    def peek(self) -> tuple[str, Any] | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self, op: str | None = None) -> tuple[str, Any]:
        token = self.peek()
        if token is None or (op is not None and token != ("op", op)):
            raise WorkflowError(f"malformed expression {self.text!r}")
        self.index += 1
        return token

    def at(self, *ops: str) -> str | None:
        token = self.peek()
        return token[1] if token and token[0] == "op" and token[1] in ops else None

    def parse(self) -> Any:
        value = self.or_()
        if self.peek() is not None:
            raise WorkflowError(f"malformed expression {self.text!r}")
        return value

    def or_(self) -> Any:
        value = self.and_()
        while self.at("||"):
            self.take()
            right = self.and_()
            value = value if _truthy(value) else right
        return value

    def and_(self) -> Any:
        value = self.equality()
        while self.at("&&"):
            self.take()
            right = self.equality()
            value = right if _truthy(value) else value
        return value

    def equality(self) -> Any:
        value = self.comparison()
        while op := self.at("==", "!="):
            self.take()
            equal = _equal(value, self.comparison())
            value = equal if op == "==" else not equal
        return value

    def comparison(self) -> Any:
        value = self.unary()
        while op := self.at("<", ">", "<=", ">="):
            self.take()
            left, right = _number(value), _number(self.unary())
            value = {
                "<": left < right,
                ">": left > right,
                "<=": left <= right,
                ">=": left >= right,
            }[op]
        return value

    def unary(self) -> Any:
        if self.at("!"):
            self.take()
            return not _truthy(self.unary())
        return self.postfix()

    def postfix(self) -> Any:
        value, path = self.primary()
        while op := self.at(".", "["):
            self.take()
            if op == ".":
                kind, key = self.take()
                if (kind, key) == ("op", "*"):
                    value = _Filtered(value.values() if isinstance(value, dict) else value or [])
                    path += ".*"
                    continue
                if kind != "name":
                    raise WorkflowError(f"malformed expression {self.text!r}")
            else:
                key = self.or_()
                self.take("]")
            path += f".{key}"
            value = self.member(value, key, path)
        return value

    def member(self, value: Any, key: Any, path: str) -> Any:
        if isinstance(value, _Filtered):
            return _Filtered(item[key] for item in value if isinstance(item, dict) and key in item)
        if isinstance(value, Strict):
            if key not in value:
                raise WorkflowError(f"{path} is not available to the local run")
            return value[key]
        if isinstance(value, dict):
            return value.get(key)
        if isinstance(value, list) and isinstance(key, float) and key.is_integer():
            return value[int(key)] if 0 <= key < len(value) else None
        return None

    def primary(self) -> tuple[Any, str]:
        kind, value = self.take()
        if kind == "literal":
            return value, "literal"
        if (kind, value) == ("op", "("):
            inner = self.or_()
            self.take(")")
            return inner, "(...)"
        if kind != "name":
            raise WorkflowError(f"malformed expression {self.text!r}")
        if self.at("("):
            self.take()
            args = []
            while not self.at(")"):
                args.append(self.or_())
                if self.at(","):
                    self.take()
            self.take(")")
            function = _FUNCTIONS.get(value.lower())
            if function is None:
                raise WorkflowError(f"function {value}() is not available to the local run")
            return function(*args), f"{value}()"
        if value not in self.context:
            raise WorkflowError(f"context {value!r} is not available to the local run")
        return self.context[value], value


def evaluate(expression: str, context: dict[str, Any]) -> Any:
    """Evaluate one expression body (without the ``${{ }}`` delimiters)."""
    return _Parser(expression, context).parse()


_TEMPLATE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)


def substitute(text: str, context: dict[str, Any]) -> str:
    """Replace every ``${{ expression }}`` in a string, as the runner does."""
    return _TEMPLATE.sub(lambda m: to_string(evaluate(m.group(1), context)), text)


def condition(value: Any, context: dict[str, Any]) -> bool:
    """Evaluate a job or step ``if`` (always an expression, delimiters optional)."""
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    text = str(value).strip()
    whole = _TEMPLATE.fullmatch(text)
    return _truthy(evaluate(whole.group(1) if whole else text, context))


def uses_status_function(value: Any) -> bool:
    return any(function in str(value or "") for function in _STATUS_FUNCTIONS)


# --------------------------------------------------------------------------------------
# Workflow model
# --------------------------------------------------------------------------------------


def load_workflow(path: Path = WORKFLOW) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def triggers(workflow: dict[str, Any]) -> set[str]:
    """The events that start a workflow (YAML 1.1 reads the ``on`` key as ``True``)."""
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on}
    return set(on or ())


def pull_request_workflows(directory: Path = WORKFLOWS) -> list[str]:
    """The workflows the local run executes: ci.yml, then the other workflows that run
    for a pull request, by file name. One missing from ``CI_ONLY`` is an error."""
    if not (directory / "ci.yml").is_file():
        raise WorkflowError(f"{directory / 'ci.yml'} not found")
    names = ["ci.yml"]
    for path in sorted(directory.glob("*.yml")):
        if path.name == "ci.yml" or not triggers(load_workflow(path)) & PULL_REQUEST_EVENTS:
            continue
        if path.name not in CI_ONLY:
            raise WorkflowError(
                f"{path.name} runs for pull requests but is not classified in CI_ONLY "
                "(scripts/ci_fast_jobs.py): list its CI-only jobs, or none"
            )
        names.append(path.name)
    return names


def ci_only_jobs(name: str, full: bool = False) -> dict[str, str]:
    """The jobs of workflow ``name`` that stay in CI (``--full`` runs FULL_SUITE_JOB)."""
    ci_only = dict(CI_ONLY.get(name, {}))
    if full and name == "ci.yml":
        ci_only.pop(FULL_SUITE_JOB)
    return ci_only


def fast_jobs(workflow: dict[str, Any], name: str = "ci.yml", full: bool = False) -> list[str]:
    """Every workflow job that runs locally, in an order that satisfies ``needs``."""
    jobs = workflow["jobs"]
    ci_only = ci_only_jobs(name, full)
    names = [job for job in jobs if job not in ci_only]
    ordered: list[str] = []

    def visit(name: str, chain: tuple[str, ...]) -> None:
        if name in ordered:
            return
        if name in chain:
            raise WorkflowError(f"job dependency cycle through {name}")
        for need in _needs(jobs[name]):
            if need in ci_only:
                raise WorkflowError(f"fast job {name} needs CI-only job {need}")
            visit(need, (*chain, name))
        ordered.append(name)

    for job in names:
        visit(job, ())
    return ordered


def _needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def fast_job_steps(
    workflow: dict[str, Any], name: str = "ci.yml", full: bool = False
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Every (job, step) the local run executes: all ``run`` steps of every fast job
    except the environment-provisioning steps in ``SETUP_STEPS`` and the steps in
    ``CI_ONLY_STEPS``."""
    for job_name in fast_jobs(workflow, name, full):
        job = workflow["jobs"][job_name]
        unsupported = {
            "uses",
            "strategy",
            "container",
            "services",
            "defaults",
            "continue-on-error",
        } & set(job)
        if unsupported:
            raise WorkflowError(f"{name} fast job {job_name} uses {sorted(unsupported)}")
        for step in job.get("steps", []):
            if "run" not in step or step.get("name") in SETUP_STEPS:
                continue
            if (name, job_name, step.get("name")) in CI_ONLY_STEPS:
                continue
            yield job_name, step


def step_label(step: dict[str, Any]) -> str:
    return step.get("name") or str(step["run"]).strip().splitlines()[0]


def full_suite_step(workflow: dict[str, Any]) -> dict[str, Any]:
    """The one step of FULL_SUITE_JOB that is not environment provisioning."""
    job = workflow["jobs"].get(FULL_SUITE_JOB)
    if job is None:
        raise WorkflowError(f"ci.yml has no {FULL_SUITE_JOB} job")
    steps = [s for s in job.get("steps", []) if "run" in s and s.get("name") not in SETUP_STEPS]
    if len(steps) != 1:
        raise WorkflowError(f"ci.yml job {FULL_SUITE_JOB} has {len(steps)} test steps, not one")
    return steps[0]


def full_suite_workers(script: str, override: str | None) -> tuple[str, str]:
    """The full-suite command with its xdist worker count, and that count.

    The command keeps CI's count unless ``override`` (``PREPUSH_XDIST_WORKERS``) names
    another; nothing else in the command changes."""
    found = _WORKERS.findall(script)
    if len(found) != 1:
        raise WorkflowError(f"the full-suite step names {len(found)} worker counts, not one")
    workers = found[0] if override is None else override
    if not re.fullmatch(r"[1-9][0-9]*", workers):
        raise WorkflowError(f"worker count {workers!r} is not a positive integer")
    return _WORKERS.sub(f"-n {workers}", script), workers


def is_credential(name: str) -> bool:
    return name.upper().startswith(CREDENTIAL_PREFIXES) or bool(
        CREDENTIAL_NAME.search(name.upper())
    )


def without_credentials(environ: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """``environ`` without any credential variable, and the names removed.

    The full suite then runs with exactly this mapping as its environment. A credential
    that cannot be removed is one the workflow step itself declares; ``_run_workflow``
    refuses to start that step before it gets here."""
    removed = sorted(key for key in environ if is_credential(key))
    return {key: value for key, value in environ.items() if key not in removed}, removed


# --------------------------------------------------------------------------------------
# Local run
# --------------------------------------------------------------------------------------


def _repository() -> str:
    try:
        url = subprocess.check_output(
            ["git", "remote", "get-url", "origin"], cwd=ROOT, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "local/checkout"
    match = re.search(r"[:/]([^/:]+/[^/]+?)(?:\.git)?/?$", url)
    return match.group(1) if match else "local/checkout"


def pull_request_event(
    repository: str, base: str, base_ref: str, head: str, head_ref: str, labels: list[str]
) -> dict[str, Any]:
    repo = {"full_name": repository}
    return {
        "action": "synchronize",
        "repository": {"full_name": repository, "default_branch": "main"},
        "pull_request": {
            "base": {"sha": base, "ref": base_ref, "repo": repo},
            "head": {"sha": head, "ref": head_ref, "repo": repo},
            "labels": [{"name": label} for label in labels],
        },
    }


def _parse_key_values(path: Path) -> dict[str, str]:
    """Parse a GITHUB_OUTPUT / GITHUB_ENV file (``k=v`` and ``k<<DELIM`` forms)."""
    values: dict[str, str] = {}
    lines = path.read_text().splitlines() if path.exists() else []
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if "<<" in line and ("=" not in line or line.index("<<") < line.index("=")):
            key, delimiter = line.split("<<", 1)
            body = []
            while index < len(lines) and lines[index] != delimiter:
                body.append(lines[index])
                index += 1
            index += 1
            values[key] = "\n".join(body)
        elif "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def _python_version(python: Path) -> str:
    return subprocess.check_output(
        [str(python), "-c", "import sys; print('%d.%d' % sys.version_info[:2])"], text=True
    ).strip()


def run(
    *,
    base: str,
    base_ref: str,
    head: str,
    head_ref: str,
    labels: list[str],
    venv: Path,
    workflows: Path = WORKFLOWS,
    execute: bool = True,
    full: bool = False,
    workers: str | None = None,
    out: Callable[[str], None] = lambda line: print(line, flush=True),
) -> list[tuple[str, str, str, bool]]:
    """Run (or, with ``execute=False``, only resolve) every fast-job step of every
    pull-request workflow, then the ``PREPUSH_GUARDS``. With ``full``, ci.yml's
    FULL_SUITE_JOB runs too, with ``workers`` xdist workers when given.

    Returns one ``(workflow, job, step, ran)`` record per fast-job step. A dry run
    resolves every condition and expression of every fast-job step, including steps
    whose job would not run, and executes nothing; job outputs are then empty.
    """
    names = pull_request_workflows(workflows)
    repository = _repository()
    event = pull_request_event(repository, base, base_ref, head, head_ref, labels)
    local_python = _python_version(venv / "bin" / "python") if execute else None
    work = Path(tempfile.mkdtemp(prefix="prepush-"))
    event_path = work / "event.json"
    event_path.write_text(json.dumps(event))
    github = strict(
        "github",
        {
            "event_name": "pull_request",
            "event": event,
            "repository": repository,
            "base_ref": base_ref,
            "head_ref": head_ref,
            "workspace": str(ROOT),
        },
    )
    records: list[tuple[str, str, str, bool]] = []
    common: dict[str, Any] = {
        "github": github,
        "event_path": event_path,
        "repository": repository,
        "base_ref": base_ref,
        "head_ref": head_ref,
        "venv": venv,
        "local_python": local_python,
        "execute": execute,
        "workers": workers,
        "out": out,
    }
    for name in names:
        records += _run_workflow(workflows / name, work=work / Path(name).stem, **common)
    _run_guards(execute=execute, venv=venv, out=out)
    if full:
        # Last, so every fast check has passed before the long run starts.
        records += _run_workflow(workflows / "ci.yml", work=work / "full", only=True, **common)
    return records


def _run_guards(*, execute: bool, venv: Path, out: Callable[[str], None]) -> None:
    guards = [ROOT / guard for guard in PREPUSH_GUARDS]
    if guards:
        out(f"== guards: {' '.join(PREPUSH_GUARDS)}")
        missing = [str(guard) for guard in guards if not guard.is_file()]
        if missing:
            raise WorkflowError(f"pre-push guard not found: {', '.join(missing)}")
        if execute:
            command = [str(venv / "bin" / "python"), *GUARD_PYTEST, *PREPUSH_GUARDS]
            code = subprocess.call(command, cwd=ROOT)
            if code != 0:
                raise StepFailed("guards", " ".join(PREPUSH_GUARDS), code)


def _run_workflow(
    workflow_path: Path,
    *,
    github: dict[str, Any],
    event_path: Path,
    repository: str,
    base_ref: str,
    head_ref: str,
    venv: Path,
    local_python: str | None,
    work: Path,
    execute: bool,
    workers: str | None,
    out: Callable[[str], None],
    only: bool = False,
) -> list[tuple[str, str, str, bool]]:
    """Run one workflow's fast jobs; with ``only``, ci.yml's FULL_SUITE_JOB alone."""
    workflow = load_workflow(workflow_path)
    wf = workflow_path.name
    full = only
    steps = list(fast_job_steps(workflow, wf, full))
    suite = full_suite_step(workflow) if full else None
    # The full suite's job runs whatever its CI condition, so the outputs of the jobs it
    # needs (run in the fast pass) are not consulted.
    needs: dict[str, dict[str, Any]] = (
        {
            need: {"result": "success", "outputs": {}}
            for need in _needs(workflow["jobs"][FULL_SUITE_JOB])
        }
        if full
        else {}
    )
    records: list[tuple[str, str, str, bool]] = []
    jobs = [FULL_SUITE_JOB] if full else fast_jobs(workflow, wf)
    if full:
        out(f"prepush: --full: the {FULL_SUITE_JOB} job from {wf} (advisory, never instead of CI)")
    else:
        out(f"prepush: {len(steps)} fast-job steps from {wf}")
    for name in jobs:
        job = workflow["jobs"][name]
        temp = work / name
        temp.mkdir(parents=True)
        env = Strict("env")
        context: dict[str, Any] = {
            "github": github,
            "runner": Strict("runner", os="Linux", arch="X64", temp=str(temp)),
            "env": env,
            "needs": {need: needs[need] for need in _needs(job)},
            "steps": {},
            "inputs": Strict("inputs"),
            "vars": Strict("vars"),
        }
        for key, value in (workflow.get("env") or {}).items():
            env[key] = substitute(str(value), context)
        env["DEV_VENV"] = str(venv)
        for key, value in (job.get("env") or {}).items():
            env[key] = substitute(str(value), context)
        blocked = [need for need in _needs(job) if needs[need]["result"] != "success"]
        job_runs = not (blocked and not uses_status_function(job.get("if"))) and condition(
            job.get("if"), context
        )
        if full and name == FULL_SUITE_JOB:
            job_runs = True  # --full: the full suite runs whatever its CI condition
        if job_runs:
            out(f"== {name}")
        else:
            out(f"== {name}: not run (its CI condition is false for this change)")
        path_entries = [str(venv / "bin")]
        job_env: dict[str, str] = {}
        selected = [step for job_name, step in steps if job_name == name]
        for index, step in enumerate(job.get("steps", [])):
            if "uses" in step:
                action = str(step["uses"]).split("@", 1)[0]
                wanted = str((step.get("with") or {}).get("python-version", ""))
                if job_runs and execute and action == "actions/setup-python" and wanted:
                    if wanted != local_python:
                        raise WorkflowError(
                            f"{name} runs Python {wanted}; the local environment is "
                            f"Python {local_python}"
                        )
                continue
            reason = CI_ONLY_STEPS.get((wf, name, step.get("name")))
            if reason is not None:
                if job_runs:
                    out(f"   - {step_label(step)}: CI only ({reason})")
                continue
            if not any(step is chosen for chosen in selected):
                continue  # environment provisioning (SETUP_STEPS)
            label = step_label(step)
            unsupported = {"working-directory", "continue-on-error"} & set(step)
            shell = step.get("shell")
            if unsupported or shell not in _SHELLS:
                raise WorkflowError(f"{name} step {label!r} uses {sorted(unsupported) or shell}")
            step_runs = condition(step.get("if"), context) and job_runs
            step_env = dict(job_env)
            for key, value in (step.get("env") or {}).items():
                step_env[key] = substitute(str(value), context)
            script = substitute(str(step["run"]), context)
            is_suite = step is suite
            if is_suite:
                script, count = full_suite_workers(script, workers)
                label = f"{label} (workers {count})"
                declared = sorted(key for key in {**env, **step_env} if is_credential(key))
                if declared:
                    raise WorkflowError(
                        f"refusing to run the full suite: the workflow sets {declared}"
                    )
            records.append((wf, name, label, step_runs))
            if not job_runs:
                continue
            if not step_runs:
                out(f"   - {label}: not run (its CI condition is false)")
                continue
            out(f"   - {label}")
            if not execute:
                continue
            output_file = temp / f"output-{index}"
            path_file = temp / f"path-{index}"
            env_file = temp / f"env-{index}"
            script_file = temp / f"step-{index}.sh"
            script_file.write_text(script)
            process_env = {
                **os.environ,
                **env,
                **step_env,
                "CI": "true",
                "GITHUB_ACTIONS": "true",
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_EVENT_PATH": str(event_path),
                "GITHUB_REPOSITORY": repository,
                "GITHUB_BASE_REF": base_ref,
                "GITHUB_HEAD_REF": head_ref,
                "GITHUB_WORKSPACE": str(ROOT),
                "GITHUB_OUTPUT": str(output_file),
                "GITHUB_PATH": str(path_file),
                "GITHUB_ENV": str(env_file),
                "GITHUB_STEP_SUMMARY": str(temp / "summary.md"),
                "RUNNER_TEMP": str(temp),
                "PATH": os.pathsep.join([*path_entries, os.environ.get("PATH", "")]),
            }
            if is_suite:
                process_env, removed = without_credentials(process_env)
                out(f"     without {len(removed)} credential variable(s): {' '.join(removed)}")
            code = subprocess.call([*_SHELLS[shell], str(script_file)], cwd=ROOT, env=process_env)
            if code != 0:
                raise StepFailed(name if wf == "ci.yml" else f"{wf} {name}", label, code)
            if path_file.exists():
                added = [p for p in path_file.read_text().splitlines() if p]
                path_entries = [*reversed(added), *path_entries]
            job_env.update(_parse_key_values(env_file))
            if "id" in step:
                context["steps"][step["id"]] = {
                    "outputs": _parse_key_values(output_file),
                    "outcome": "success",
                    "conclusion": "success",
                }
        outputs = {
            key: substitute(str(value), context)
            for key, value in (job.get("outputs") or {}).items()
        }
        needs[name] = {"result": "success" if job_runs else "skipped", "outputs": outputs}
    if not full:
        for name, reason in CI_ONLY.get(wf, {}).items():
            if name in workflow["jobs"]:
                out(f"== {name}: CI only ({reason})")
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="base branch commit (the PR base)")
    parser.add_argument("--base-ref", required=True, help="base branch name")
    parser.add_argument("--head", required=True, help="commit under test")
    parser.add_argument("--head-ref", required=True, help="branch name of the commit")
    parser.add_argument("--labels", default="", help="comma-separated pull request labels")
    parser.add_argument(
        "--full",
        action="store_true",
        help="also run ci.yml's full suite (advisory; never a substitute for CI)",
    )
    parser.add_argument(
        "--full-workers-output",
        type=Path,
        help="with --full, write the full suite's xdist worker count here",
    )
    parser.add_argument(
        "--venv",
        type=Path,
        default=Path(sys.executable).parent.parent,
        help="development environment (default: the running interpreter's)",
    )
    args = parser.parse_args(argv)
    venv = args.venv.absolute()
    if not (venv / "bin" / "python").exists():
        print(
            f"prepush: {venv}/bin/python not found; run with the development environment's "
            "interpreter (PREPUSH_PYTHON=<venv>/bin/python), installed from requirements.lock",
            file=sys.stderr,
        )
        return 2
    try:
        workers = None
        if args.full:
            script = str(full_suite_step(load_workflow())["run"])
            _, workers = full_suite_workers(script, os.environ.get("PREPUSH_XDIST_WORKERS"))
            if args.full_workers_output:
                args.full_workers_output.write_text(f"{workers}\n")
        run(
            base=args.base,
            base_ref=args.base_ref,
            head=args.head,
            head_ref=args.head_ref,
            labels=[label.strip() for label in args.labels.split(",") if label.strip()],
            venv=venv,
            full=args.full,
            workers=workers,
        )
    except (WorkflowError, StepFailed) as exc:
        print(f"prepush: FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
