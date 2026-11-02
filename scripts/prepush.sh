#!/usr/bin/env bash
# Pre-push check: run CI's fast jobs locally before every push.
#
#   PREPUSH_PYTHON=<venv>/bin/python scripts/prepush.sh
#
# The steps are read from the workflows themselves (scripts/ci_fast_jobs.py), so this
# check and CI's fast jobs cannot drift: from ci.yml lint, typecheck, docs, the version,
# fixture and changelog checks, and the changed-path test selection
# (scripts/select_pr_tests.py) with CI's pytest flags; then the fast jobs of the other
# workflows that run for a pull request (documentation checks, changelog size). Each job
# runs when its CI condition holds for a pull request from HEAD into the base branch; a
# change that the selector escalates to the full tier runs the full suite in CI's test
# and test-locked jobs, not in this default run (see --full below). The secret scan,
# the image build and the other jobs scripts/ci_fast_jobs.py lists in CI_ONLY also stay
# in CI. The test files in its PREPUSH_GUARDS run on every pre-push, whatever the change.
#
# The venv must be installed from requirements.lock, as CI's is:
#   python3.12 -m venv .venv
#   .venv/bin/python -m pip install --require-hashes -r requirements.lock
#   .venv/bin/python -m pip install --no-deps -e .
#
# Settings: PREPUSH_BASE_BRANCH (the pull request's base branch; the default is this
# tree's lane target, printed on the first line), PREPUSH_REMOTE (default origin),
# PREPUSH_LABELS (comma-separated pull request labels, e.g. full-ci).
#
# Push only after it prints "Pre-push: scripts/prepush.sh pass (head <sha7>)" for the
# commit you push, and cite that line in the pull request. This is not a git hook.
#
#   PREPUSH_PYTHON=<venv>/bin/python scripts/prepush.sh --full
#
# Opt-in: also runs ci.yml's full suite (the test job's "Run full suite with coverage"
# step as read from the workflow, with CI's worker count unless PREPUSH_XDIST_WORKERS
# names another, and without any UNIFI_*, MCP_* or other credential variable). It is
# advisory and never stands in for CI: cite it only as "local full suite (advisory)".
# It prints "Pre-push: scripts/prepush.sh --full pass (head <sha7>, workers <n>)"
# instead of the line above. Nothing requires it.
set -euo pipefail

full=false
case "${1-}:$#" in
  :0) ;;
  --full:1) full=true ;;
  *)
    echo "usage: scripts/prepush.sh [--full]" >&2
    exit 2
    ;;
esac

root="$(git rev-parse --show-toplevel)"
cd "$root"
python="${PREPUSH_PYTHON:-python3}"
remote="${PREPUSH_REMOTE:-origin}"
base_branch="${PREPUSH_BASE_BRANCH:-main}"

tracked_changes() { git status --porcelain --untracked-files=no; }

if [ -n "$(tracked_changes)" ]; then
  echo "prepush: commit or stash tracked changes first; the pass line names a commit." >&2
  tracked_changes >&2
  exit 1
fi

head="$(git rev-parse HEAD)"
head_ref="$(git rev-parse --abbrev-ref HEAD)"
git fetch --quiet "$remote" "$base_branch"
base="$(git rev-parse FETCH_HEAD)"
echo "prepush: head ${head} (${head_ref}), base ${remote}/${base_branch} ${base}"
echo "prepush: merge base $(git merge-base "$base" "$head")"

mode=()
if [ "$full" = true ]; then
  workers_file="$(mktemp)"
  trap 'rm -f -- "$workers_file"' EXIT
  mode=(--full --full-workers-output "$workers_file")
fi
"$python" scripts/ci_fast_jobs.py \
  --base "$base" --base-ref "$base_branch" \
  --head "$head" --head-ref "$head_ref" \
  --labels "${PREPUSH_LABELS:-}" ${mode[@]+"${mode[@]}"}

if [ "$(git rev-parse HEAD)" != "$head" ] || [ -n "$(tracked_changes)" ]; then
  echo "prepush: the checkout changed during the run; rerun on a clean commit." >&2
  tracked_changes >&2
  exit 1
fi
if [ "$full" = true ]; then
  echo "Pre-push: scripts/prepush.sh --full pass (head ${head:0:7}, workers $(cat "$workers_file"))"
else
  echo "Pre-push: scripts/prepush.sh pass (head ${head:0:7})"
fi
