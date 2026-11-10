#!/usr/bin/env bash
# Run the whole test suite the way CI's test and test-locked jobs run it.
#
#   scripts/run_full_suite.sh PYTHON [--workers N|auto] [--print-command]
#                             [--] [extra pytest arguments...]
#
# PYTHON is the interpreter of the environment under test (test: "$DEV_VENV/bin/python",
# test-locked: python). The suite runs from the repository root. The command is
#
#   PYTHON -m pytest tests/ -v -n <N> --dist loadgroup --max-worker-restart=0
#          --cov=src/unifi_fabric --cov-report=term --cov-fail-under=97
#
# Private checkouts also collect docs/internal; the public transform removes that directory.
# With N = 4 unless --workers names another positive count, or "auto": the job's CPU
# share, so shards placed side by side on one runner do not oversubscribe it.
# auto resolves to CI_JOB_CPUS when that is set, else 2 on a host with at most 12 CPUs
# and 4 otherwise, and always to between 1 and 4 (4 is the ceiling per job). Shard
# assignment hashes the unit, not the worker, so the count changes speed only.
# Any other argument, or every argument after "--", is passed to pytest after these.
# --print-command prints the composed command, one shell-quoted word per argument, and
# exits without running it.
#
# Sharded runs (one slice of the suite per job, proved by scripts/shard_partition.py):
#
#   scripts/run_full_suite.sh PYTHON --shard K/N --shard-suite NAME [--shard-report PATH] ...
#   scripts/run_full_suite.sh PYTHON --collect-only [--identity-out PATH] [--workers N] ...
#   scripts/run_full_suite.sh PYTHON --combine DIR --shards N [--summary PATH] [--print-command]
#
# --shard runs shard K of N with the same -n/--dist/--max-worker-restart options. It drops
# --cov-fail-under and the terminal coverage report (no shard can pass or fail the
# threshold alone) and writes the shard report to PATH (default shard-K-of-N.json). Each
# shard leaves its own .coverage file.
# --shard-suite names the suite (test, test-locked) the report belongs to; the report also
# carries the run id and attempt, the environment identity and its lock differences.
# --collect-only is the anchor: the same command and arguments without the coverage options,
# plus --collect-only -q (without -v, which would print a tree instead of IDs), so the node-ID list it prints is what an unsharded run executes.
# --identity-out PATH also writes the interpreter's environment identity record there.
# --combine counts exactly N .coverage files under DIR, refuses any without measured data,
# runs coverage combine, writes the combined percent / statements / missed to the summary
# JSON (default coverage-combined.json in the current directory) and then coverage report
# with the one threshold below.
#
# Coverage threshold: calibrated just below the measured full-suite line coverage (see
# ci.yml's test job). Raise it as coverage grows; never lower it to make a run pass.
set -euo pipefail

# The one place the coverage threshold lives (the whole run, or the combined shards).
COVERAGE_FAIL_UNDER=97

usage() {
  echo "usage: scripts/run_full_suite.sh PYTHON [--workers N] [--print-command] [--shard K/N --shard-suite NAME [--shard-report PATH]] [--] [pytest args...]" >&2
  echo "       scripts/run_full_suite.sh PYTHON --collect-only [--identity-out PATH] [--workers N] [--] [pytest args...]" >&2
  echo "       scripts/run_full_suite.sh PYTHON --combine DIR --shards N [--summary PATH] [--print-command]" >&2
  exit 2
}

[ "$#" -ge 1 ] || usage
python="$1"
shift
case "$python" in
  "" | -*) usage ;;
  /*) ;;
  */*) python="$PWD/$python" ;; # a relative path keeps working from the repository root
esac

workers=4
print_command=false
shard=""
shard_report=""
shard_suite=""
collect_only=false
identity_out=""
summary=""
combine=""
shard_count=""
extra=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --workers)
      [ "$#" -ge 2 ] || usage
      workers="$2"
      shift 2
      ;;
    --workers=*)
      workers="${1#--workers=}"
      shift
      ;;
    --print-command)
      print_command=true
      shift
      ;;
    --shard)
      [ "$#" -ge 2 ] || usage
      shard="$2"
      shift 2
      ;;
    --shard=*)
      shard="${1#--shard=}"
      shift
      ;;
    --shard-report)
      [ "$#" -ge 2 ] || usage
      shard_report="$2"
      shift 2
      ;;
    --shard-report=*)
      shard_report="${1#--shard-report=}"
      shift
      ;;
    --shard-suite)
      [ "$#" -ge 2 ] || usage
      shard_suite="$2"
      shift 2
      ;;
    --shard-suite=*)
      shard_suite="${1#--shard-suite=}"
      shift
      ;;
    --collect-only)
      collect_only=true
      shift
      ;;
    --identity-out)
      [ "$#" -ge 2 ] || usage
      identity_out="$2"
      shift 2
      ;;
    --identity-out=*)
      identity_out="${1#--identity-out=}"
      shift
      ;;
    --summary)
      [ "$#" -ge 2 ] || usage
      summary="$2"
      shift 2
      ;;
    --summary=*)
      summary="${1#--summary=}"
      shift
      ;;
    --combine)
      [ "$#" -ge 2 ] || usage
      combine="$2"
      shift 2
      ;;
    --combine=*)
      combine="${1#--combine=}"
      shift
      ;;
    --shards)
      [ "$#" -ge 2 ] || usage
      shard_count="$2"
      shift 2
      ;;
    --shards=*)
      shard_count="${1#--shards=}"
      shift
      ;;
    --)
      shift
      extra+=("$@")
      break
      ;;
    *)
      extra+=("$1")
      shift
      ;;
  esac
done

if [ "$workers" = auto ]; then
  if [ -n "${CI_JOB_CPUS:-}" ]; then
    if ! [[ "$CI_JOB_CPUS" =~ ^[1-9][0-9]*$ ]]; then
      echo "run_full_suite: CI_JOB_CPUS '${CI_JOB_CPUS}' is not a positive integer" >&2
      exit 2
    fi
    workers="$CI_JOB_CPUS"
  elif [ "$(nproc)" -le 12 ]; then
    workers=2
  else
    workers=4
  fi
  if [ "$workers" -gt 4 ]; then
    workers=4
  fi
fi
if ! [[ "$workers" =~ ^[1-9][0-9]*$ ]]; then
  echo "run_full_suite: worker count '${workers}' is not a positive integer" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -n "$combine" ] || [ -n "$shard_count" ] || [ -n "$summary" ]; then
  if [ -n "$shard" ] || [ -n "$shard_report" ] || [ -n "$shard_suite" ] || [ "$collect_only" = true ] \
    || [ -n "$identity_out" ] || [ -z "$combine" ] \
    || ! [[ "$shard_count" =~ ^[1-9][0-9]*$ ]] || [ "${#extra[@]}" -gt 0 ]; then
    usage
  fi
  : "${summary:=$PWD/coverage-combined.json}"
  case "$summary" in /*) ;; *) summary="$PWD/$summary" ;; esac
  check_command=("$python" scripts/shard_partition.py coverage-data)
  combine_command=("$python" -m coverage combine --keep)
  json_command=("$python" -m coverage json --pretty-print -o)
  summary_command=("$python" scripts/shard_partition.py coverage-summary)
  report_command=("$python" -m coverage report "--fail-under=$COVERAGE_FAIL_UNDER")
  if [ "$print_command" = true ]; then
    printf '%q ' "${check_command[@]}"
    printf '<the %s .coverage files under %s>\n' "$shard_count" "$combine"
    printf '%q ' "${combine_command[@]}"
    printf '<the %s .coverage files under %s>\n' "$shard_count" "$combine"
    printf '%q ' "${json_command[@]}"
    printf '<json> && %q <json> %q\n' "${summary_command[*]}" "$summary"
    printf '%q\n' "${report_command[@]}"
    exit 0
  fi
  [ -d "$combine" ] || { echo "run_full_suite: $combine is not a directory" >&2; exit 2; }
  files=()
  while IFS= read -r file; do files+=("$file"); done \
    < <(find "$combine" -type f -name .coverage | LC_ALL=C sort)
  if [ "${#files[@]}" -ne "$shard_count" ]; then
    echo "run_full_suite: expected $shard_count coverage data files under $combine, found ${#files[@]}" >&2
    exit 1
  fi
  cd "$root"
  "${check_command[@]}" "${files[@]}" || {
    echo "run_full_suite: refusing to combine a coverage data file with no measured data" >&2
    exit 1
  }
  "${combine_command[@]}" "${files[@]}"
  json_tmp="$(mktemp)"
  trap 'rm -f "$json_tmp"' EXIT
  "${json_command[@]}" "$json_tmp"
  "${summary_command[@]}" "$json_tmp" "$summary"
  "${report_command[@]}"
  exit $?
fi
if [ "$collect_only" = true ] && [ -n "$shard$shard_report$shard_suite" ]; then
  usage
fi
if [ -n "$identity_out" ] && [ "$collect_only" != true ]; then
  usage
fi
if { [ -n "$shard_report" ] || [ -n "$shard_suite" ]; } && [ -z "$shard" ]; then
  usage
fi
if [ -n "$shard" ]; then
  if ! [[ "$shard" =~ ^([1-9][0-9]*)/([1-9][0-9]*)$ ]] || [ "${BASH_REMATCH[1]}" -gt "${BASH_REMATCH[2]}" ]; then
    echo "run_full_suite: shard '${shard}' is not K/N with 1 <= K <= N" >&2
    exit 2
  fi
  [ -n "$shard_suite" ] || usage
  : "${shard_report:=shard-${BASH_REMATCH[1]}-of-${BASH_REMATCH[2]}.json}"
fi

command=("$python" -m pytest tests/ -v -n "$workers" --dist loadgroup --max-worker-restart=0)
if [ "$collect_only" = true ]; then
  # -v would turn the --collect-only listing into a tree; -q alone prints one node ID per line.
  command=("$python" -m pytest tests/ -n "$workers" --dist loadgroup --max-worker-restart=0)
fi
if [ "$collect_only" = true ]; then
  :  # the anchor lists the tests; it measures nothing
elif [ -n "$shard" ]; then
  command+=(--cov=src/unifi_fabric --cov-report=)
else
  command+=(--cov=src/unifi_fabric --cov-report=term "--cov-fail-under=$COVERAGE_FAIL_UNDER")
fi
if [ -d "$root/docs/internal" ]; then
  command+=(docs/internal)
fi
if [ -n "$shard" ]; then
  command+=(--shard "$shard" --shard-suite "$shard_suite" --shard-report "$shard_report")
fi
if [ "$collect_only" = true ]; then
  command+=(--collect-only -q)
fi
command+=(${extra[@]+"${extra[@]}"})

if [ "$print_command" = true ]; then
  printf '%q\n' "${command[@]}"
  exit 0
fi

cd "$root"
if [ -n "$identity_out" ]; then
  # The identity is recorded in the interpreter the anchor collects with. A difference
  # from the lock is carried in the record for the verifier to judge; it does not stop here.
  "$python" scripts/env_identity.py record --out "$identity_out" || true
fi
exec "${command[@]}"
