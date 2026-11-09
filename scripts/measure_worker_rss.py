#!/usr/bin/env python3
"""Measure controller and xdist-worker RSS for one foreground pytest command.

The command runs with credential/config namespaces removed. Samples are appended every
five seconds so evidence survives a cgroup kill. The final summary records the exact git
head, host fingerprint, cgroup limit, process high-water values, and the per-worker
capacity ceiling derived from the cgroup memory limit, which sizes the xdist worker count.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SAMPLE_SECONDS = 5
MIB = 1024 * 1024
EXPECTED_WORKERS = 4
EXPECTED_WORKER_IDS = frozenset(f"gw{index}" for index in range(EXPECTED_WORKERS))
_CREDENTIAL_PREFIXES = ("UNIFI_", "MCP_", "FASTMCP_")
_PEAK_RE = re.compile(r"worker peak RSS: (gw\d+) ru_maxrss=([0-9.]+) MiB")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout.strip()


def _cgroup_path() -> Path:
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0":
            return Path("/sys/fs/cgroup") / parts[2].lstrip("/")
    raise RuntimeError("unified cgroup path not found")


def _memory_limit(path: Path) -> int:
    raw = (path / "memory.max").read_text().strip()
    if not raw.isdigit() or int(raw) <= 0:
        raise RuntimeError(f"cgroup memory.max is not a positive integer: {raw!r}")
    return int(raw)


def _key_values(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        for line in path.read_text().splitlines():
            key, value = line.split()
            values[key] = int(value)
    except (FileNotFoundError, PermissionError, ValueError):
        return {}
    return values


def _capacity_ceiling_mib(memory_max: int) -> int:
    ceiling = math.floor(((memory_max / MIB - 1024) * 0.80) / 4)
    if ceiling <= 0:
        raise RuntimeError(f"capacity ceiling is not positive: {ceiling}")
    return ceiling


def _proc_stat(pid: int) -> tuple[int, int] | None:
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    close = text.rfind(")")
    if close < 0:
        return None
    fields = text[close + 2 :].split()
    return int(fields[1]), int(fields[19])  # ppid, process start time


def _proc_memory(pid: int) -> tuple[int, int] | None:
    values: dict[str, int] = {}
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            name, separator, rest = line.partition(":")
            if separator and name in {"VmRSS", "VmHWM"}:
                values[name] = int(rest.strip().split()[0]) * 1024
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
        return None
    if "VmRSS" not in values:
        return None
    return values["VmRSS"], values.get("VmHWM", values["VmRSS"])


def _worker_id(pid: int) -> str | None:
    try:
        entries = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    prefix = b"PYTEST_XDIST_WORKER="
    for entry in entries:
        if entry.startswith(prefix):
            return entry[len(prefix) :].decode("ascii", "replace")
    return None


def _process_identity(
    pid: int,
    ppid: int,
    launcher_pid: int,
    worker_ids: dict[int, str | None],
) -> tuple[str, str | None]:
    if pid == launcher_pid:
        return "controller", None
    worker = worker_ids.get(pid)
    if ppid == launcher_pid and worker in EXPECTED_WORKER_IDS:
        return "worker", worker
    return "child", None


def _worker_instance(worker: str, pid: int, start_ticks: int) -> str:
    return f"{worker}@{pid}:{start_ticks}"


def _descendants(root: int) -> list[int]:
    children: dict[int, list[int]] = {}
    for item in Path("/proc").iterdir():
        if not item.name.isdigit():
            continue
        stat = _proc_stat(int(item.name))
        if stat is not None:
            children.setdefault(stat[0], []).append(int(item.name))
    found: list[int] = []
    stack = list(children.get(root, []))
    while stack:
        pid = stack.pop()
        found.append(pid)
        stack.extend(children.get(pid, []))
    return sorted(found)


def _sample(controller_pid: int, cgroup: Path, started: float) -> dict[str, Any]:
    processes: list[dict[str, Any]] = []
    snapshots: list[tuple[int, tuple[int, int], tuple[int, int]]] = []
    for pid in [controller_pid, *_descendants(controller_pid)]:
        stat = _proc_stat(pid)
        memory = _proc_memory(pid)
        if stat is None or memory is None:
            continue
        snapshots.append((pid, stat, memory))
    worker_ids = {pid: _worker_id(pid) for pid, _, _ in snapshots}
    for pid, stat, memory in snapshots:
        role, worker = _process_identity(pid, stat[0], controller_pid, worker_ids)
        processes.append(
            {
                "pid": pid,
                "ppid": stat[0],
                "start_ticks": stat[1],
                "role": role,
                "worker": worker,
                "worker_instance": (
                    _worker_instance(worker, pid, stat[1]) if role == "worker" else None
                ),
                "rss_bytes": memory[0],
                "hwm_bytes": memory[1],
            }
        )
    workers = [process for process in processes if process["role"] == "worker"]
    try:
        cgroup_current = int((cgroup / "memory.current").read_text().strip())
    except (OSError, ValueError):
        cgroup_current = None
    return {
        "utc": _utc_now(),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "cgroup_current_bytes": cgroup_current,
        "worker_aggregate_rss_bytes": sum(process["rss_bytes"] for process in workers),
        "processes": processes,
    }


def _late_growth(samples: list[dict[str, Any]]) -> dict[str, float]:
    if not samples:
        return {}
    late = samples[max(0, math.floor(len(samples) * 0.75)) :]
    by_worker: dict[str, list[int]] = {}
    for sample in late:
        for process in sample["processes"]:
            worker_instance = process.get("worker_instance")
            if process.get("role") == "worker" and worker_instance:
                by_worker.setdefault(worker_instance, []).append(process["rss_bytes"])
    return {
        worker: round((values[-1] - values[0]) / MIB, 3)
        for worker, values in sorted(by_worker.items())
        if len(values) >= 2
    }


def _reported_peaks(log: Path) -> dict[str, float]:
    peaks: dict[str, float] = {}
    with log.open(errors="replace") as stream:
        for line in stream:
            match = _PEAK_RE.search(line)
            if match is not None:
                worker, value = match.groups()
                peaks[worker] = max(float(value), peaks.get(worker, 0.0))
    return dict(sorted(peaks.items()))


def _child_environment(output_dir: Path, ambient: dict[str, str]) -> dict[str, str]:
    environment = {
        key: value for key, value in ambient.items() if not key.startswith(_CREDENTIAL_PREFIXES)
    }
    environment.pop("PYTEST_ADDOPTS", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["UNIFI_TEST_SELECTION_CACHE"] = "1"
    environment["UNIFI_TEST_SELECTION_CACHE_DIR"] = str(output_dir / "selection-cache")
    return environment


def _worker_metrics(
    samples: list[dict[str, Any]],
    reported_peaks: dict[str, float],
    ceiling_mib: int | None,
) -> dict[str, Any]:
    worker_rows = [
        process
        for sample in samples
        for process in sample["processes"]
        if process.get("role") == "worker"
    ]
    sampled_max_hwm_mib = max((process["hwm_bytes"] for process in worker_rows), default=0) / MIB
    max_worker_mib = max(sampled_max_hwm_mib, max(reported_peaks.values(), default=0.0))
    aggregate_mib = (
        max((sample["worker_aggregate_rss_bytes"] for sample in samples), default=0) / MIB
    )
    worker_instances = sorted(
        {
            process["worker_instance"]
            for process in worker_rows
            if process.get("worker_instance") is not None
        }
    )
    observed_worker_ids = sorted(
        {process["worker"] for process in worker_rows if process.get("worker") is not None}
    )
    return {
        "worker_observations": len(worker_rows),
        "worker_process_count": len(worker_instances),
        "worker_instances": worker_instances,
        "observed_worker_ids": observed_worker_ids,
        "sampled_max_worker_hwm_mib": round(sampled_max_hwm_mib, 3),
        "max_worker_hwm_mib": round(max_worker_mib, 3),
        "sampled_max_worker_aggregate_rss_mib": round(aggregate_mib, 3),
        "worker_peak_within_acceptance_ceiling": (
            None if ceiling_mib is None else max_worker_mib <= ceiling_mib
        ),
        "aggregate_peak_within_acceptance_ceiling": (
            None if ceiling_mib is None else aggregate_mib <= 4 * ceiling_mib
        ),
    }


def _measurement_verdict(
    phase: str,
    exit_code: int,
    received_signal: int | None,
    metrics: dict[str, Any],
    reported_peaks: dict[str, float],
    memory_events_delta: dict[str, int],
) -> tuple[bool, bool | None, list[str]]:
    reasons: list[str] = []
    if exit_code != 0:
        reasons.append(f"suite-exit-code:{exit_code}")
    if received_signal is not None:
        reasons.append(f"relayed-signal:{received_signal}")
    if set(metrics["observed_worker_ids"]) != EXPECTED_WORKER_IDS:
        reasons.append("observed-worker-ids")
    if metrics["worker_process_count"] != EXPECTED_WORKERS:
        reasons.append("worker-instances")
    if set(reported_peaks) != EXPECTED_WORKER_IDS:
        reasons.append("reported-worker-ids")
    if any(value <= 0 for value in reported_peaks.values()):
        reasons.append("nonpositive-reported-worker-peak")
    for key in ("oom", "oom_kill", "oom_group_kill"):
        if memory_events_delta.get(key, 0) != 0:
            reasons.append(f"cgroup-{key}")
    if reasons:
        return False, False, reasons
    if phase == "baseline":
        return True, None, []
    accepted = bool(
        metrics["worker_peak_within_acceptance_ceiling"]
        and metrics["aggregate_peak_within_acceptance_ceiling"]
    )
    return True, accepted, []


class _SignalRelay:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self.received_signal: int | None = None
        self._previous: dict[int, Any] = {}

    def __enter__(self) -> _SignalRelay:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            self._previous[signum] = signal.getsignal(signum)
            signal.signal(signum, self._handle)
        return self

    def _handle(self, signum: int, _frame: Any) -> None:
        if self.received_signal is None:
            self.received_signal = signum
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signum)
            except ProcessLookupError:
                pass

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        for signum, previous in self._previous.items():
            signal.signal(signum, previous)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--phase", choices=("baseline", "after"), required=True)
    parser.add_argument("--rss-ceiling-mib", type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    if args.phase == "after" and (args.rss_ceiling_mib is None or args.rss_ceiling_mib <= 0):
        parser.error("--rss-ceiling-mib must be positive for the after phase")
    return args


def main() -> int:
    args = _arguments()
    root = Path.cwd()
    args.output_dir = args.output_dir.resolve()
    if _git("status", "--porcelain", "--untracked-files=no"):
        raise RuntimeError("tracked worktree must be clean")
    head = _git("rev-parse", "HEAD")
    requirements = root / "requirements.lock"
    cgroup = _cgroup_path()
    memory_max = _memory_limit(cgroup)
    memory_events_start = _key_values(cgroup / "memory.events")
    capacity_ceiling = _capacity_ceiling_mib(memory_max)

    args.output_dir.mkdir(parents=True, exist_ok=False)
    samples_path = args.output_dir / "samples.jsonl"
    log_path = args.output_dir / "suite.log"
    summary_path = args.output_dir / "summary.json"
    environment = _child_environment(args.output_dir, dict(os.environ))
    metadata = {
        "phase": args.phase,
        "head": head,
        "tracked_clean": True,
        "host": platform.node(),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "platform": platform.platform(),
        "python": sys.version,
        "requirements_lock_sha256": _sha256(requirements),
        "image_digest": None,
        "image_digest_status": "not-applicable-bare-host",
        "cgroup": str(cgroup.relative_to("/sys/fs/cgroup")),
        "memory_max_bytes": memory_max,
        "memory_swap_max": (cgroup / "memory.swap.max").read_text().strip(),
        "capacity_ceiling_mib": capacity_ceiling,
        "sample_interval_seconds": SAMPLE_SECONDS,
        "selection_cache": "enabled-empty-dedicated-directory",
        "pythonpath": environment.get("PYTHONPATH"),
        "command": args.command,
        "started_utc": _utc_now(),
    }
    (args.output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")

    samples: list[dict[str, Any]] = []
    started = time.monotonic()
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            args.command,
            cwd=root,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            with _SignalRelay(process) as relay:
                with samples_path.open("a", encoding="utf-8") as stream:
                    while process.poll() is None:
                        sample = _sample(process.pid, cgroup, started)
                        samples.append(sample)
                        stream.write(json.dumps(sample, sort_keys=True) + "\n")
                        stream.flush()
                        os.fsync(stream.fileno())
                        time.sleep(SAMPLE_SECONDS)
                    sample = _sample(process.pid, cgroup, started)
                    samples.append(sample)
                    stream.write(json.dumps(sample, sort_keys=True) + "\n")
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            process.wait()
            raise

    reported_peaks = _reported_peaks(log_path)
    memory_events_end = _key_values(cgroup / "memory.events")
    memory_events_delta = {
        key: value - memory_events_start.get(key, 0)
        for key, value in sorted(memory_events_end.items())
    }
    metrics = _worker_metrics(samples, reported_peaks, args.rss_ceiling_mib)
    max_worker_mib = metrics["max_worker_hwm_mib"]
    proposed_ceiling = min(capacity_ceiling, math.floor(0.70 * max_worker_mib))
    measurement_valid, acceptance_passed, invalid_reasons = _measurement_verdict(
        args.phase,
        process.returncode,
        relay.received_signal,
        metrics,
        reported_peaks,
        memory_events_delta,
    )
    summary = {
        **metadata,
        "finished_utc": _utc_now(),
        "exit_code": process.returncode,
        "received_signal": relay.received_signal,
        "samples": len(samples),
        **metrics,
        "sampled_max_cgroup_current_mib": round(
            max(
                (
                    sample["cgroup_current_bytes"]
                    for sample in samples
                    if sample["cgroup_current_bytes"] is not None
                ),
                default=0,
            )
            / MIB,
            3,
        ),
        "reported_worker_peaks_mib": reported_peaks,
        "memory_events_start": memory_events_start,
        "memory_events_end": memory_events_end,
        "memory_events_delta": memory_events_delta,
        "late_quartile_worker_rss_delta_mib": _late_growth(samples),
        "proposed_rss_ceiling_mib": proposed_ceiling,
        "acceptance_rss_ceiling_mib": args.rss_ceiling_mib,
        "measurement_valid": measurement_valid,
        "measurement_invalid_reasons": invalid_reasons,
        "acceptance_passed": acceptance_passed,
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    if relay.received_signal is not None:
        return 128 + relay.received_signal
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
