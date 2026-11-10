#!/usr/bin/env bash
# CI steps of the sharded full suites (the ci.yml test-*, test-locked-* and scrub-oracle-*
# jobs).
#
#   scripts/shard_ci.sh plan N
#       Print the GITHUB_OUTPUT lines shards=N and list=[1,...,N]. N is 1..256 (the
#       Actions matrix limit); anything else exits 2.
#   scripts/shard_ci.sh record
#       Print where this job runs: runner name, CPUs, memory, load, CPU model and the
#       names (never the values) of its environment variables.
#   scripts/shard_ci.sh anchor PYTHON [--locked]
#       The prep job's plain collection through scripts/run_full_suite.sh --collect-only:
#       the anchor list (what an unsharded run executes) goes to $RUNNER_TEMP/anchor/anchor.txt
#       and the behaviour-derived selection it computes stays in the selection cache for the
#       shards. --locked also records the environment identity (anchor-identity.json).
#   scripts/shard_ci.sh selection PYTHON
#       Print the selection cache entries this job holds (tests/_selection_cache.py) and a
#       digest of each part of the fingerprint (interpreter, distributions, each environment
#       name with an 8-character digest of its value, files), so two jobs' parts can be
#       compared when a shard collects cold. No value is printed. The suite's own fingerprint
#       also includes what tests/conftest.py sets before collection, so it is not computed
#       here.
#   scripts/shard_ci.sh check K N JOB_TOTAL
#       Fail unless the matrix has exactly N jobs (strategy.job-total) and 1 <= K <= N;
#       then create $RUNNER_TEMP/shard-out for the shard's report and coverage data.
#   scripts/shard_ci.sh aggregate SUITE PYTHON N PLANNED [--locked]
#       The aggregate job of SUITE (test, test-locked). N comes from the TEST_SHARDS
#       constant (or the dispatch input), never from the shards; PLANNED is the count the
#       suite's prep job gave the matrix, and must equal N. It reads the prep job's anchor
#       from $RUNNER_TEMP/anchor, keeps this run's newest artifact
#       per shard (shard_partition.py select-artifacts), proves the shards against the
#       anchor (shard_partition.py verify, with the jobs' results from $SHARD_NEEDS), then
#       combines the coverage data and applies the one threshold (run_full_suite.sh
#       --combine). --locked requires every shard to carry the anchor's environment
#       identity, equal to the lock. Artifacts are read from $RUNNER_TEMP/shards; the proof,
#       anchor and coverage summary go to $RUNNER_TEMP/proof.
#   scripts/shard_ci.sh scrub-aggregate PYTHON N PLANNED
#       The scrub-oracle aggregate. N comes from the SCRUB_ORACLE_SHARDS constant; PLANNED
#       (scrub-oracle-prep's count) must equal it. The anchor is this job's own plain
#       collection of the unsharded command. It keeps this run's newest artifact per shard,
#       proves the shards against the anchor (every chunk exactly once, passed; the jobs'
#       results from $SHARD_NEEDS), requires exactly one evidence file per chunk run
#       (shard_partition.py scrub-evidence), then runs the aggregate coverage floor over the
#       merged evidence and requires it to pass (not skip). Artifacts are read from
#       $RUNNER_TEMP/shards; the proof goes to $RUNNER_TEMP/proof.
set -euo pipefail

usage() {
  sed -n '2,45p' "$0" >&2
  exit 2
}

is_count() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ "$#" -ge 1 ] || usage
command="$1"
shift

case "$command" in
  plan)
    [ "$#" -eq 1 ] || usage
    n="$1"
    if ! is_count "$n" || [ "$n" -gt 256 ]; then
      echo "shard_ci: shard count '$n' is not an integer from 1 to 256" >&2
      exit 2
    fi
    echo "shards=$n"
    echo "list=[$(seq -s, 1 "$n")]"
    ;;
  record)
    [ "$#" -eq 0 ] || usage
    echo "runner: ${RUNNER_NAME:-unknown}"
    echo "cpus: $(nproc)"
    awk '/^MemTotal:/ {printf "memory: %.1f GiB\n", $2 / 1048576}
         /^MemAvailable:/ {printf "memory available: %.1f GiB\n", $2 / 1048576}' /proc/meminfo
    echo "load: $(cut -d' ' -f1-3 /proc/loadavg)"
    echo "cpu model:$(grep -m1 '^model name' /proc/cpuinfo | cut -d: -f2- || true)"
    echo "environment names: $(compgen -e | LC_ALL=C sort | tr '\n' ' ')"
    if [ -r /sys/fs/cgroup/cpu.max ]; then
      echo "cgroup cpu.max: $(cat /sys/fs/cgroup/cpu.max)"
    fi
    ;;
  anchor)
    [ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
    python="$1"
    out="${RUNNER_TEMP:?}/anchor"
    mkdir -p "$out"
    collect=(bash scripts/run_full_suite.sh "$python" --collect-only)
    if [ "$#" -eq 2 ]; then
      [ "$2" = "--locked" ] || usage
      collect+=(--identity-out "$out/anchor-identity.json")
    fi
    cd "$root"
    start=$SECONDS
    "${collect[@]}" > "$out/anchor.txt"
    echo "anchor collection: $((SECONDS - start)) s"
    tail -n 1 "$out/anchor.txt"
    ;;
  selection)
    [ "$#" -eq 1 ] || usage
    cd "$root"
    "$1" - <<'PY'
import hashlib
import importlib.metadata
import sys

from tests import _selection_cache as cache


def digest(text):
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()[:8]


held = sorted(p.stem for p in cache.cache_dir().glob("*.json")) if cache.cache_dir().is_dir() else []
print(f"selection cache: held {[h[:12] for h in held]}")
dists = sorted(f"{d.metadata['Name']}=={d.version}" for d in importlib.metadata.distributions())
files = cache._files()
print(f"selection parts: python {digest(sys.version)}, {len(dists)} dists {digest(chr(10).join(dists))},"
      f" {len(files)} files {digest(chr(10).join(files))}")
print("selection env: " + " ".join(f"{k}={digest(v)}" for k, v in cache._fingerprint_env()))
PY
    ;;
  check)
    [ "$#" -eq 3 ] || usage
    k="$1" n="$2" total="$3"
    if ! is_count "$k" || ! is_count "$n" || ! is_count "$total"; then
      echo "shard_ci: shard '$k', count '$n' and job total '$total' must be positive integers" >&2
      exit 1
    fi
    if [ "$total" -ne "$n" ]; then
      echo "shard_ci: the matrix has $total jobs but the shard count is $n" >&2
      exit 1
    fi
    if [ "$k" -gt "$n" ]; then
      echo "shard_ci: shard $k is outside 1..$n" >&2
      exit 1
    fi
    mkdir -p "${RUNNER_TEMP:?}/shard-out"
    echo "shard $k of $n"
    ;;
  aggregate)
    [ "$#" -ge 4 ] && [ "$#" -le 5 ] || usage
    suite="$1" python="$2" n="$3" planned="$4"
    locked=false
    if [ "$#" -eq 5 ]; then
      [ "$5" = "--locked" ] || usage
      locked=true
    fi
    case "$suite" in test | test-locked) ;; *) usage ;; esac
    if ! is_count "$n"; then
      echo "shard_ci: shard count '$n' is not a positive integer" >&2
      exit 1
    fi
    if [ "$planned" != "$n" ]; then
      echo "shard_ci: the $suite-prep job planned '$planned' shards, but the count is $n" >&2
      exit 1
    fi
    : "${RUNNER_TEMP:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_SHA:?}" "${SHARD_NEEDS:?}" "${SHARD_REQUIRE:?}"
    proof="$RUNNER_TEMP/proof"
    selected="$RUNNER_TEMP/selected"
    mkdir -p "$proof" "$RUNNER_TEMP/shards"
    rm -rf "$selected"
    printf '%s' "$SHARD_NEEDS" > "$proof/needs.json"
    cd "$root"
    # The anchor: the prep job's plain collection (the same command as every shard, without
    # the shard and coverage options), from the suite's own fresh environment.
    anchor="$RUNNER_TEMP/anchor"
    [ -s "$anchor/anchor.txt" ] || { echo "shard_ci: no anchor list from $suite-prep" >&2; exit 1; }
    cp "$anchor/anchor.txt" "$proof/anchor.txt"
    verify_locked=()
    if [ "$locked" = true ]; then
      [ -s "$anchor/anchor-identity.json" ] || {
        echo "shard_ci: no anchor identity from $suite-prep" >&2
        exit 1
      }
      cp "$anchor/anchor-identity.json" "$proof/anchor-identity.json"
      verify_locked=(--locked --anchor-identity "$proof/anchor-identity.json")
    fi
    "$python" scripts/shard_partition.py select-artifacts --root "$RUNNER_TEMP/shards" \
      --prefix "$suite-shard" --run-id "$GITHUB_RUN_ID" --shards "$n" --out "$selected"
    status=0
    "$python" scripts/shard_partition.py verify --anchor "$proof/anchor.txt" \
      --reports "$selected" --shards "$n" --suite "$suite" --run-id "$GITHUB_RUN_ID" \
      --commit "$GITHUB_SHA" --coverage "$selected" --needs "$proof/needs.json" \
      --require "$SHARD_REQUIRE" --proof "$proof/proof.json" \
      ${verify_locked[@]+"${verify_locked[@]}"} || status=$?
    if [ "$status" -eq 0 ]; then
      bash scripts/run_full_suite.sh "$python" --combine "$selected" --shards "$n" \
        --summary "$proof/coverage.json" || status=$?
    fi
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "$proof/proof.json" ]; then
      "$python" scripts/shard_partition.py summary "$proof/proof.json" "$proof/coverage.json" \
        >> "$GITHUB_STEP_SUMMARY" || true
    fi
    exit "$status"
    ;;
  scrub-aggregate)
    [ "$#" -eq 3 ] || usage
    python="$1" n="$2" planned="$3"
    if ! is_count "$n"; then
      echo "shard_ci: shard count '$n' is not a positive integer" >&2
      exit 1
    fi
    if [ "$planned" != "$n" ]; then
      echo "shard_ci: scrub-oracle-prep planned '$planned' shards, but the count is $n" >&2
      exit 1
    fi
    : "${RUNNER_TEMP:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_SHA:?}" "${SHARD_NEEDS:?}" "${SHARD_REQUIRE:?}"
    proof="$RUNNER_TEMP/proof"
    selected="$RUNNER_TEMP/selected"
    evidence="$RUNNER_TEMP/scrub-evidence"
    mkdir -p "$proof" "$RUNNER_TEMP/shards"
    rm -rf "$selected" "$evidence"
    printf '%s' "$SHARD_NEEDS" > "$proof/needs.json"
    cd "$root"
    # The anchor: the shards' command without the shard options, collected here.
    "$python" -m pytest tests/test_secret_scrub_oracle.py \
      tests/test_secret_scrub_child_breaks_split.py -m slow -q --collect-only \
      -p no:cacheprovider > "$proof/anchor.txt"
    "$python" scripts/shard_partition.py select-artifacts --root "$RUNNER_TEMP/shards" \
      --prefix scrub-oracle-shard --run-id "$GITHUB_RUN_ID" --shards "$n" --out "$selected" \
      --files report.json
    status=0
    "$python" scripts/shard_partition.py verify --anchor "$proof/anchor.txt" \
      --reports "$selected" --shards "$n" --suite scrub-oracle --run-id "$GITHUB_RUN_ID" \
      --commit "$GITHUB_SHA" --needs "$proof/needs.json" \
      --require "$SHARD_REQUIRE" \
      --proof "$proof/proof.json" || status=$?
    # The split differential's slow cases ran in the shards too (verify proved every anchor id
    # passed exactly once). Fewer than the floor means the file left the selection.
    child_floor=24
    child=$(grep -c '^tests/test_secret_scrub_child_breaks_split\.py::' "$proof/anchor.txt" || true)
    if [ "$status" -eq 0 ] && [ "${child:-0}" -lt "$child_floor" ]; then
      echo "shard_ci: only ${child:-0} split-differential slow cases were collected, the floor is $child_floor" >&2
      status=1
    fi
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      echo "scrub split-differential slow cases proven: ${child:-0} (floor $child_floor)" >> "$GITHUB_STEP_SUMMARY"
    fi
    if [ "$status" -eq 0 ]; then
      "$python" scripts/shard_partition.py scrub-evidence --shards-dir "$selected" \
        --shards "$n" --out "$evidence" || status=$?
    fi
    if [ "$status" -eq 0 ]; then
      UNIFI_SCRUB_CORPUS_AGGREGATE=1 UNIFI_SCRUB_CORPUS_EVIDENCE="$evidence" \
        "$python" -m pytest "tests/test_secret_scrub_oracle.py::test_slow_coverage_floor" \
        -m slow -q -p no:cacheprovider --junitxml="$proof/floor.xml" || status=$?
    fi
    if [ "$status" -eq 0 ]; then
      "$python" scripts/shard_partition.py junit-passed "$proof/floor.xml" --count 1 ||
        status=$?
    fi
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "$proof/proof.json" ]; then
      "$python" scripts/shard_partition.py summary "$proof/proof.json" \
        >> "$GITHUB_STEP_SUMMARY" || true
    fi
    exit "$status"
    ;;
  *)
    usage
    ;;
esac
