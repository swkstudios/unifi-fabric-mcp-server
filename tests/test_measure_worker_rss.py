from __future__ import annotations

import json
import signal
from pathlib import Path
from typing import Any

import pytest

from scripts import measure_worker_rss as measure


def test_capacity_ceiling_uses_reserved_memory_and_headroom() -> None:
    assert measure._capacity_ceiling_mib(20 * 1024**3) == 3891


def test_capacity_ceiling_refuses_nonpositive_result() -> None:
    with pytest.raises(RuntimeError, match="not positive"):
        measure._capacity_ceiling_mib(1024**3)


def test_key_values_reads_cgroup_events(tmp_path: Path) -> None:
    events = tmp_path / "memory.events"
    events.write_text("low 0\nhigh 2\noom_kill 1\n")

    assert measure._key_values(events) == {"low": 0, "high": 2, "oom_kill": 1}


def test_reported_peaks_streams_worker_summary(tmp_path: Path) -> None:
    log = tmp_path / "suite.log"
    log.write_text(
        "worker peak RSS: gw1 ru_maxrss=201.2 MiB\n"
        "unrelated output\n"
        "worker peak RSS: gw0 ru_maxrss=199.7 MiB\n"
        "worker peak RSS: gw1 ru_maxrss=202.4 MiB\n"
    )

    assert measure._reported_peaks(log) == {"gw0": 199.7, "gw1": 202.4}


def test_process_identity_uses_only_controller_direct_children_as_workers() -> None:
    worker_ids = {
        100: None,
        101: "gw2",
        102: "gw2",
        103: None,
        104: "gw2",
        105: None,
        106: "gw3",
        107: "gw9",
    }

    assert measure._process_identity(100, 10, 100, worker_ids) == ("controller", None)
    assert measure._process_identity(101, 100, 100, worker_ids) == ("worker", "gw2")
    assert measure._process_identity(102, 101, 100, worker_ids) == ("child", None)
    assert measure._process_identity(103, 100, 100, worker_ids) == ("child", None)
    assert measure._process_identity(104, 999, 100, worker_ids) == ("child", None)
    assert measure._process_identity(105, 100, 100, worker_ids) == ("child", None)
    assert measure._process_identity(106, 105, 100, worker_ids) == ("child", None)
    assert measure._process_identity(107, 100, 100, worker_ids) == ("child", None)
    assert measure._worker_instance("gw2", 101, 9876) == "gw2@101:9876"


def test_sample_excludes_worker_spawned_process_with_inherited_xdist_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stats = {100: (10, 1), 101: (100, 2), 102: (101, 3)}
    memory = {
        100: (10 * measure.MIB, 20 * measure.MIB),
        101: (100 * measure.MIB, 200 * measure.MIB),
        102: (900 * measure.MIB, 999 * measure.MIB),
    }
    cgroup = tmp_path / "cgroup"
    cgroup.mkdir()
    (cgroup / "memory.current").write_text(str(1010 * measure.MIB))
    monkeypatch.setattr(measure, "_descendants", lambda _pid: [101, 102])
    monkeypatch.setattr(measure, "_proc_stat", lambda pid: stats[pid])
    monkeypatch.setattr(measure, "_proc_memory", lambda pid: memory[pid])
    monkeypatch.setattr(measure, "_worker_id", lambda pid: "gw0" if pid in {101, 102} else None)

    sample = measure._sample(100, cgroup, measure.time.monotonic())
    by_pid = {process["pid"]: process for process in sample["processes"]}

    assert by_pid[101]["role"] == "worker"
    assert by_pid[101]["worker_instance"] == "gw0@101:2"
    assert by_pid[102]["role"] == "child"
    assert by_pid[102]["worker_instance"] is None
    assert sample["worker_aggregate_rss_bytes"] == 100 * measure.MIB


def test_late_growth_uses_last_quartile_worker_rss() -> None:
    samples = []
    for index in range(8):
        samples.append(
            {
                "processes": [
                    {"worker": "gw0", "rss_bytes": (100 + index) * measure.MIB},
                    {
                        "role": "worker",
                        "worker_instance": "gw1@12:2",
                        "rss_bytes": (200 - index) * measure.MIB,
                    },
                ]
            }
        )

    for sample in samples:
        sample["processes"][0].update({"role": "worker", "worker_instance": "gw0@11:1"})

    assert measure._late_growth(samples) == {"gw0@11:1": 1.0, "gw1@12:2": -1.0}


def test_child_environment_strips_config_and_uses_fresh_selection_cache(tmp_path: Path) -> None:
    ambient = {
        "PATH": "/usr/bin",
        "UNIFI_API_KEY": "not-a-real-secret",
        "MCP_BEARER_TOKEN": "not-a-real-secret",
        "FASTMCP_SERVER_AUTH": "not-a-real-secret",
        "PYTEST_ADDOPTS": "--lf",
    }

    first = measure._child_environment(tmp_path / "one", ambient)
    second = measure._child_environment(tmp_path / "two", ambient)

    assert first["PATH"] == "/usr/bin"
    assert "UNIFI_API_KEY" not in first
    assert "MCP_BEARER_TOKEN" not in first
    assert "FASTMCP_SERVER_AUTH" not in first
    assert "PYTEST_ADDOPTS" not in first
    assert first["PYTHONDONTWRITEBYTECODE"] == "1"
    assert first["UNIFI_TEST_SELECTION_CACHE"] == "1"
    assert first["UNIFI_TEST_SELECTION_CACHE_DIR"] == str(tmp_path / "one/selection-cache")
    assert second["UNIFI_TEST_SELECTION_CACHE_DIR"] == str(tmp_path / "two/selection-cache")


def test_worker_metrics_exclude_inherited_helper_and_use_reported_peak() -> None:
    samples = [
        {
            "worker_aggregate_rss_bytes": 100 * measure.MIB,
            "processes": [
                {
                    "role": "worker",
                    "worker": "gw0",
                    "worker_instance": "gw0@101:50",
                    "hwm_bytes": 200 * measure.MIB,
                },
                {
                    "role": "child",
                    "worker": None,
                    "worker_instance": None,
                    "hwm_bytes": 999 * measure.MIB,
                },
            ],
        }
    ]

    metrics = measure._worker_metrics(samples, {"gw0": 250.5}, 300)

    assert metrics == {
        "worker_observations": 1,
        "worker_process_count": 1,
        "worker_instances": ["gw0@101:50"],
        "observed_worker_ids": ["gw0"],
        "sampled_max_worker_hwm_mib": 200.0,
        "max_worker_hwm_mib": 250.5,
        "sampled_max_worker_aggregate_rss_mib": 100.0,
        "worker_peak_within_acceptance_ceiling": True,
        "aggregate_peak_within_acceptance_ceiling": True,
    }


def test_failed_or_signalled_measurement_is_never_a_pass() -> None:
    metrics = {
        "worker_process_count": 4,
        "observed_worker_ids": ["gw0", "gw1", "gw2", "gw3"],
        "worker_peak_within_acceptance_ceiling": True,
        "aggregate_peak_within_acceptance_ceiling": True,
    }
    peaks = {worker: 200.0 for worker in measure.EXPECTED_WORKER_IDS}

    assert measure._measurement_verdict("baseline", 0, None, metrics, peaks, {}) == (
        True,
        None,
        [],
    )
    assert measure._measurement_verdict("after", 0, None, metrics, peaks, {}) == (
        True,
        True,
        [],
    )
    assert measure._measurement_verdict("after", 1, None, metrics, peaks, {}) == (
        False,
        False,
        ["suite-exit-code:1"],
    )
    assert measure._measurement_verdict(
        "after", -signal.SIGTERM, signal.SIGTERM, metrics, peaks, {}
    ) == (
        False,
        False,
        [f"suite-exit-code:{-signal.SIGTERM}", f"relayed-signal:{signal.SIGTERM}"],
    )


def test_replaced_worker_or_incomplete_peak_set_invalidates_measurement() -> None:
    metrics = {
        "worker_process_count": 5,
        "observed_worker_ids": ["gw0", "gw1", "gw2", "gw3"],
        "worker_peak_within_acceptance_ceiling": True,
        "aggregate_peak_within_acceptance_ceiling": True,
    }
    missing_peak = {"gw0": 200.0, "gw1": 201.0, "gw2": 202.0}

    assert measure._measurement_verdict("baseline", 0, None, metrics, missing_peak, {}) == (
        False,
        False,
        ["worker-instances", "reported-worker-ids"],
    )

    metrics["worker_process_count"] = 4
    extra_peak = {**missing_peak, "gw3": 203.0, "gw4": 204.0}
    assert measure._measurement_verdict("baseline", 0, None, metrics, extra_peak, {}) == (
        False,
        False,
        ["reported-worker-ids"],
    )

    zero_peak = {worker: 200.0 for worker in measure.EXPECTED_WORKER_IDS}
    zero_peak["gw3"] = 0.0
    assert measure._measurement_verdict("baseline", 0, None, metrics, zero_peak, {}) == (
        False,
        False,
        ["nonpositive-reported-worker-peak"],
    )

    metrics["observed_worker_ids"] = ["gw0", "gw1", "gw2"]
    assert measure._measurement_verdict("baseline", 0, None, metrics, zero_peak, {}) == (
        False,
        False,
        ["observed-worker-ids", "nonpositive-reported-worker-peak"],
    )


@pytest.mark.parametrize("oom_key", ["oom", "oom_kill", "oom_group_kill"])
def test_cgroup_oom_delta_invalidates_measurement(oom_key: str) -> None:
    metrics = {
        "worker_process_count": 4,
        "observed_worker_ids": ["gw0", "gw1", "gw2", "gw3"],
        "worker_peak_within_acceptance_ceiling": True,
        "aggregate_peak_within_acceptance_ceiling": True,
    }
    peaks = {worker: 200.0 for worker in measure.EXPECTED_WORKER_IDS}

    assert measure._measurement_verdict("baseline", 0, None, metrics, peaks, {oom_key: 1}) == (
        False,
        False,
        [f"cgroup-{oom_key}"],
    )


def test_signal_relay_forwards_and_restores_handlers(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeProcess:
        pid = 404

        @staticmethod
        def poll() -> None:
            return None

    handlers: dict[int, Any] = {}
    forwarded: list[tuple[int, int]] = []
    monkeypatch.setattr(signal, "getsignal", lambda signum: f"old-{signum}")
    monkeypatch.setattr(
        signal, "signal", lambda signum, handler: handlers.__setitem__(signum, handler)
    )
    monkeypatch.setattr(measure.os, "killpg", lambda pid, signum: forwarded.append((pid, signum)))

    relay = measure._SignalRelay(FakeProcess())  # type: ignore[arg-type]
    with relay:
        relay._handle(signal.SIGTERM, None)

    assert relay.received_signal == signal.SIGTERM
    assert forwarded == [(404, signal.SIGTERM)]
    assert handlers == {
        signal.SIGTERM: f"old-{signal.SIGTERM}",
        signal.SIGINT: f"old-{signal.SIGINT}",
        signal.SIGHUP: f"old-{signal.SIGHUP}",
    }


def test_samples_are_json_serializable() -> None:
    sample = {
        "utc": "2026-11-06T00:00:00Z",
        "elapsed_seconds": 5.0,
        "cgroup_current_bytes": 10,
        "worker_aggregate_rss_bytes": 8,
        "processes": [],
    }

    assert json.loads(json.dumps(sample)) == sample
