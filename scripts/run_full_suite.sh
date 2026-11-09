#!/usr/bin/env bash
# Run the whole test suite the way CI's test and test-locked jobs run it.
#
#   scripts/run_full_suite.sh PYTHON [--workers N] [--print-command]
#                             [--] [extra pytest arguments...]
#
# PYTHON is the interpreter of the environment under test (test: "$DEV_VENV/bin/python",
# test-locked: python). The suite runs from the repository root. The command is
#
#   PYTHON -m pytest tests/ -v -n <N> --dist loadgroup --max-worker-restart=0
#          --cov=src/unifi_fabric --cov-report=term --cov-fail-under=97
#
# Private checkouts also collect docs/internal; the public transform removes that directory.
# With N = 4 unless --workers names another positive count.
# Any other argument, or every argument after "--", is passed to pytest after these.
# --print-command prints the composed command, one shell-quoted word per argument, and
# exits without running it.
#
# Coverage threshold: calibrated just below the measured full-suite line coverage (see
# ci.yml's test job). Raise it as coverage grows; never lower it to make a run pass.
set -euo pipefail

usage() {
  echo "usage: scripts/run_full_suite.sh PYTHON [--workers N] [--print-command] [--] [pytest args...]" >&2
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

if ! [[ "$workers" =~ ^[1-9][0-9]*$ ]]; then
  echo "run_full_suite: worker count '${workers}' is not a positive integer" >&2
  exit 2
fi

command=("$python" -m pytest tests/ -v -n "$workers" --dist loadgroup --max-worker-restart=0
  --cov=src/unifi_fabric --cov-report=term)
command+=(--cov-fail-under=97)
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -d "$root/docs/internal" ]; then
  command+=(docs/internal)
fi
command+=(${extra[@]+"${extra[@]}"})

if [ "$print_command" = true ]; then
  printf '%q\n' "${command[@]}"
  exit 0
fi

cd "$root"
exec "${command[@]}"
