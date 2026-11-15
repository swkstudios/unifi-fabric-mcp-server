"""Deferred tool loading (public #41): every acceptance line of the issue, tested.

The probes that need an empty ``sys.modules`` or a cold server run in a fresh interpreter
(``tests/deferred_probe.py``); the rest are in-process unit tests. No live console: calls
go to the fake upstream of ``tests/upstream_harness.py``.
"""

from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from fastmcp.exceptions import NotFoundError, ToolError

from unifi_fabric.catalog import deferred, loaders

ROOT = Path(__file__).resolve().parents[1]


def probe(*args: str, env: dict[str, str] | None = None) -> dict[str, Any]:
    """Run one ``tests/deferred_probe.py`` scenario in a fresh interpreter."""
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "MCP_"))}
    clean.update(env or {})
    done = subprocess.run(  # noqa: S603 - fixed interpreter and module, test-controlled args
        [sys.executable, "-m", "tests.deferred_probe", *args],
        cwd=ROOT,
        env=clean,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-4000:]
    return json.loads(done.stdout.strip().splitlines()[-1])


# ------------------------------------------------------------- acceptance 1 and 2: parity


def test_cold_listing_describe_and_calls_equal_warm_and_import_no_family() -> None:
    """Full-mode tools/list and discovery describe_tool are byte-equal cold (stubs) and
    warm (every step loaded); each family's pinned read call is equal cold and warm; and
    importing the server and listing its tools imports no family module."""
    out = probe("parity")
    assert out["imported_at_import"] == []
    assert out["imported_after_list"] == []
    assert out["listed"] == len(deferred.read_snapshot()["tools"])
    assert out["full_equal"] is True
    assert out["describe_equal"] is True
    assert out["calls_equal"] is True
    assert out["calls_errors"] == []
    assert out["loaded"] == len(loaders.LOADERS)


# ------------------------------------------------------- acceptance 3: disabled families

#: Family modules still imported while the family is excluded, through a cross-family
#: import an L1-C move removes (scripts/family_import_allowlist.txt) or a step that mixes
#: families (design review C2: firewall, and the devices/vpn tools of two network steps; the meta
#: tool list_configured_api_keys in the site_manager aggregation step). Each L1-C PR
#: shrinks this table with its allowlist entries; the test fails on a stale entry too, so
#: it reaches exactly empty when D1 is complete.
PENDING_IMPORTS: dict[str, list[str]] = {
    "clients": [
        "unifi_fabric.families.clients.clients",
        "unifi_fabric.families.clients.schemas",
    ],
    "connector": ["unifi_fabric.families.connector.connector"],
    "devices": [
        "unifi_fabric.families.devices.device_mgmt",
        "unifi_fabric.families.devices.schemas",
    ],
    "network": [
        "unifi_fabric.families.network.firewall_proxy",
        "unifi_fabric.families.network.matter",
        "unifi_fabric.families.network.network",
        "unifi_fabric.families.network.network_clients_guests",
        "unifi_fabric.families.network.network_controller_admin",
        "unifi_fabric.families.network.network_controller_insights",
        "unifi_fabric.families.network.network_device_operations",
        "unifi_fabric.families.network.network_dpi_policy",
        "unifi_fabric.families.network.network_mobile_wan",
        "unifi_fabric.families.network.network_nat_qos_traffic",
        "unifi_fabric.families.network.network_proav_sandbox",
        "unifi_fabric.families.network.network_routing_topology",
        "unifi_fabric.families.network.network_security_diagnostics",
        "unifi_fabric.families.network.network_services_proxy",
        "unifi_fabric.families.network.network_switching_power",
        "unifi_fabric.families.network.network_wifi_radio",
        "unifi_fabric.families.network.registrar",
        "unifi_fabric.families.network.schemas",
        "unifi_fabric.families.network.site_admin",
        "unifi_fabric.families.network.site_config",
    ],
    "site_manager": [
        "unifi_fabric.families.site_manager.aggregation",
        "unifi_fabric.families.site_manager.registrar",
        "unifi_fabric.families.site_manager.site_manager",
    ],
    "statistics": [
        "unifi_fabric.families.statistics.schemas",
        "unifi_fabric.families.statistics.statistics",
    ],
}

#: Steps that ran although their directory's family was excluded, because they hold
#: another family's exposed tools (design review C2; L1-C splits them).
PENDING_STEPS: dict[str, list[str]] = {
    "network": [
        "unifi_fabric.families.network.registrar:register_20",
        "unifi_fabric.families.network.registrar:register_9",
    ],
    "site_manager": ["unifi_fabric.families.site_manager.registrar:register_2"],
}

#: Steps holding some of an excluded family's tools that load for their other families'
#: exposed tools (design review C2; and the meta tool list_configured_api_keys, which is never
#: excluded, in the site_manager aggregation step). The excluded family's tools in them
#: stay unregistered and refused.
PENDING_MIXED: dict[str, list[str]] = {
    "devices": [
        "unifi_fabric.families.network.registrar:register_20",
        "unifi_fabric.families.network.registrar:register_9",
    ],
    "network": [
        "unifi_fabric.families.network.registrar:register_20",
        "unifi_fabric.families.network.registrar:register_9",
    ],
    "site_manager": ["unifi_fabric.families.site_manager.registrar:register_2"],
    "vpn": ["unifi_fabric.families.network.registrar:register_9"],
}


def _families() -> list[str]:
    from unifi_fabric.families import ALL_FAMILIES

    return sorted(ALL_FAMILIES)


@pytest.mark.parametrize("family", _families())
def test_disabled_family_never_imports_or_runs(family: str) -> None:
    """``UNIFI_EXCLUDE=family:F`` with ``UNIFI_PRELOAD=all``, one read call of every other
    family: no module of F is imported and no step of F runs (beyond the pending L1-C
    table), F's own call is refused tool_not_exposed, and every other family works."""
    out = probe("disabled", family)
    assert out["own_call_refused"] is True
    assert out["own_call_code"] == "tool_not_exposed"
    assert out["other_calls_error"] == []
    assert out["imported"] == PENDING_IMPORTS.get(family, [])
    assert out["steps_of_family_ran"] == PENDING_STEPS.get(family, [])
    assert sorted(out["steps_with_family_tools_loaded"]) == PENDING_MIXED.get(family, [])


def test_concurrent_first_loads_register_once() -> None:
    """20 parallel first calls of one cold tool, 30 on two other tools of its step, and 8
    threads resolving its server re-export: one register call, one load, equal results."""
    out = probe("concurrent")
    assert out["parallel_same_tool"] == 20
    assert out["total_calls"] == 50
    assert out["register_calls"] == 1
    assert out["load_events"] == 1
    assert out["outcomes"] == ["loaded"]
    assert out["same_results"] is True
    assert out["errors"] == 0
    assert out["threads_same_object"] is True
    assert out["registered_type"] == "FunctionTool"


@pytest.mark.parametrize("preload", ["none", "all", "family:hotspot,statistics"])
def test_import_and_registration_failures_are_isolated_and_secret_free(preload: str) -> None:
    """A seeded import error and a seeded register that raises after registering its tools
    on staging: family_load_failed for that step (reads, writes, and again), nothing
    half-registered, tools/list unchanged, other families still work (and the poisoned
    module's own family fails closed, its steps sharing one registrar), and the load
    record carries its fixed keys only (acceptance 5)."""
    out = probe("failure", preload)
    # The server started (every later call below was answered) and every other step loaded
    # where the preload selected it; the failed steps are recorded with their trigger.
    assert out["triggers"] == (["call"] if preload == "none" else ["preload"])
    if preload == "all":
        # The raising step, and every step sharing the poisoned module (a family registrar).
        assert out["loaded_steps"] == len(loaders.LOADERS) - 1 - out["poisoned_steps"]
    assert out["import_code"] == deferred.FAMILY_LOAD_FAILED
    assert out["register_code"] == deferred.FAMILY_LOAD_FAILED
    assert out["write_code"] == deferred.FAMILY_LOAD_FAILED
    assert out["again_code"] == deferred.FAMILY_LOAD_FAILED
    assert out["states"] == {"import": "failed", "register": "failed"}
    assert out["hotspot_registered_types"] == ["DeferredTool"]
    assert out["listed_unchanged"] is True
    # A family's steps share one registrar module, so the import error fails them all (a
    # family_load_failed refusal); other families are untouched (below).
    assert out["same_family_code"] == deferred.FAMILY_LOAD_FAILED
    assert out["other_family_ok"] is True
    assert out["record_keys"] == sorted(deferred.EVENT_FIELDS)
    assert {r["error_type"] for r in out["failed_records"]} == {
        "ModuleNotFoundError",
        "RuntimeError",
    }
    assert {r["outcome"] for r in out["failed_records"]} == {"failed"}
    assert out["secret_in_stderr"] is False
    assert out["host_in_stderr"] is False
    assert out["secret_in_events"] is False
    assert out["host_in_events"] is False

    from unifi_fabric.secret_scrub import scrub

    for record in out["failed_records"]:
        line = json.dumps(record)
        assert scrub(line) == line


@pytest.mark.parametrize("kind", ["wire", "verbs"])
def test_stub_mismatch_fails_closed(kind: str) -> None:
    """A stale snapshot (a wire difference, or a write tool recorded as a read) fails its
    step closed: the call is refused family_load_failed and nothing is sent upstream."""
    out = probe("mismatch", kind)
    assert out["outcomes"] == ["inventory_mismatch"]
    assert out["state"] == "failed"
    assert out["write_code"] == deferred.FAMILY_LOAD_FAILED
    assert out["sibling_code"] == deferred.FAMILY_LOAD_FAILED
    assert out["upstream_writes"] == 0


# ------------------------------------------------------------------ the safety floor


@pytest.mark.parametrize("path", ["call", "backstop", "attribute", "adapter", "preload"])
def test_safety_floor_every_load_path(path: str) -> None:
    """Whichever path loads a step (a call through get_tool, the stub's run backstop, the
    server re-export, a generated adapter, or UNIFI_PRELOAD), every live tool of it carries
    the resolution-state and redaction wrappers, no stub of it is left, and a cold write
    under UNIFI_WRITE_POLICY=dry-run sends nothing upstream."""
    out = probe("floor", path)
    assert out["state"] == "loaded"
    assert out["tools"] > 0
    assert out["deferred_left"] == 0
    assert out["redaction_wrapped"] is True
    assert out["resolution_wrapped"] is True
    assert out["upstream_writes"] == 0
    if path != "backstop":
        assert out["dry_run_preview"] is True


def test_cancelling_one_cold_caller_never_cancels_the_shared_load() -> None:
    """Review N1: one of two concurrent cold first calls of a step is cancelled while the
    step loads. The other still gets the real tool, the shared load is not cancelled, and
    later synchronous (adapter, ``server.<name>``) and async loads of the step succeed."""
    out = probe("cancelwaiter")
    assert out["loading_when_cancelled"] is True
    assert out["cancelled_caller"] == "CancelledError"
    assert out["other_caller"] == "FunctionTool"
    assert out["shared_future_cancelled"] is False
    assert out["state"] == "loaded"
    assert out["later_sync_ensure"] == "ok"
    assert out["later_attribute"] == "ok"
    assert out["later_async"] == "ok"


def test_sync_load_on_the_event_loop_thread_never_deadlocks() -> None:
    """Design review C1: a synchronous load of a step an async owner has claimed, on the
    event-loop thread, waits for the build the owner already submitted."""
    out = probe("syncloop")
    assert out["claimed"] is True
    assert out["submitted"] is True
    assert out["sync_returned"] is True
    assert out["state_after_sync"] == "loaded"
    assert out["state"] == "loaded"


def test_a_stub_never_runs_without_loading() -> None:
    """DeferredTool has no fn and both entry points go through the load."""
    assert "fn" not in deferred.DeferredTool.model_fields
    for method in ("run", "_run"):
        source = inspect.getsource(getattr(deferred.DeferredTool, method))
        assert "_backstop" in source
    source = inspect.getsource(deferred.DeferredTool._backstop)  # noqa: SLF001
    assert "controller.resolve" in source and "app.get_tool" in source


def test_load_failure_is_a_tool_error_not_not_found() -> None:
    """The write guards read NotFoundError and None as "not a write": a failed load must
    be neither (design review C5)."""
    error = deferred.DeferredLoadError("hotspot", "x:register")
    assert isinstance(error, ToolError)
    assert not isinstance(error, NotFoundError)
    assert json.loads(str(error))["error"]["code"] == deferred.FAMILY_LOAD_FAILED


def test_verify_runs_before_loaded_in_one_place() -> None:
    """``loaded`` is set only in the build, after verification (design review C5)."""
    source = inspect.getsource(deferred.Controller)
    assert source.count('step.state = "loaded"') == 1
    build = inspect.getsource(deferred.Controller._build)  # noqa: SLF001
    assert build.index("self._verify(") < build.index('step.state = "loaded"')


# ------------------------------------------------------------------ snapshot and policy


def test_snapshot_is_current() -> None:
    """``scripts/gen_deferred_catalog.py --check``: the committed snapshot equals one
    regenerated from the real registration and verb audit (every PR touching src/)."""
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import gen_deferred_catalog
    finally:
        sys.path.remove(str(ROOT / "scripts"))
    assert gen_deferred_catalog.build() == deferred.SNAPSHOT_PATH.read_text(encoding="utf-8")


def test_snapshot_steps_match_the_loader_map() -> None:
    snapshot = deferred.read_snapshot()
    assert [step["ref"] for step in snapshot["steps"]] == list(loaders.refs())
    names = [tool["name"] for tool in snapshot["tools"]]
    assert names == [n for step in snapshot["steps"] for n in step["tools"]]
    assert len(names) == len(set(names))


def test_snapshot_order_is_the_baseline_order() -> None:
    order = json.loads((ROOT / "tests/fixtures/behavior_baseline/order.json").read_text())
    order = order if isinstance(order, list) else order.get("order", order)
    assert [tool["name"] for tool in deferred.read_snapshot()["tools"]] == order


def test_environment_mismatch_registers_eagerly(tmp_path: Path, monkeypatch, capsys) -> None:
    """A snapshot generated under another Python/fastmcp/pydantic/-O is not trusted: the
    server registers every step eagerly with one warning (design review C10/S11)."""
    snapshot = deferred.read_snapshot()
    snapshot["environment"] = {**snapshot["environment"], "optimize": 2}
    path = tmp_path / "deferred.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    calls: list[str] = []
    monkeypatch.setattr(deferred.loaders, "load", lambda app, **kw: calls.append("load") or {})
    monkeypatch.setattr(deferred, "run_passes", lambda app, redact: calls.append("passes"))

    class App:
        pass

    app = App()
    names = deferred.install(
        app,
        late=lambda: None,
        bound=lambda: None,
        should_redact=lambda: False,
        prepare=None,
        snapshot_path=path,
    )
    assert names == {}
    assert calls == ["load", "passes"]
    assert deferred.controller_for(app) is None
    assert "every tool family loads at startup" in capsys.readouterr().err


def test_stale_step_list_registers_eagerly(tmp_path: Path, monkeypatch, capsys) -> None:
    """A snapshot whose steps no longer match catalog/loaders.py never breaks startup."""
    snapshot = deferred.read_snapshot()
    snapshot["steps"] = snapshot["steps"][:-1]
    path = tmp_path / "deferred.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    calls: list[str] = []
    monkeypatch.setattr(deferred.loaders, "load", lambda app, **kw: calls.append("load") or {})
    monkeypatch.setattr(deferred, "run_passes", lambda app, redact: calls.append("passes"))

    class App:
        pass

    app = App()
    kwargs = {"late": lambda: None, "bound": lambda: None, "should_redact": lambda: False}
    assert deferred.install(app, prepare=None, snapshot_path=path, **kwargs) == {}
    assert calls == ["load", "passes"]
    assert deferred.controller_for(app) is None
    assert "does not match catalog/loaders.py" in capsys.readouterr().err


def test_environment_is_recorded() -> None:
    env = deferred.read_snapshot()["environment"]
    assert set(env) == {"python", "optimize", "fastmcp", "pydantic"}


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("", "none"),
        ("none", "none"),
        ("all", "all"),
        ("family:protect", "family"),
        ("family:network,firewall", "family"),
    ],
)
def test_preload_values(value: str, kind: str) -> None:
    assert deferred.parse_preload(value)[0] == kind


@pytest.mark.parametrize("value", ["yes", "family:", "family:nope", "ALL", "family:protect,"])
def test_preload_invalid_refuses(value: str) -> None:
    with pytest.raises(ValueError, match="UNIFI_PRELOAD"):
        deferred.parse_preload(value)


def test_preload_setting_default_and_validation(monkeypatch) -> None:
    from pydantic import ValidationError

    from unifi_fabric.config import Settings, known_setting_names

    monkeypatch.delenv("UNIFI_PRELOAD", raising=False)
    assert Settings(api_key="k-test").preload == "none"
    monkeypatch.setenv("UNIFI_PRELOAD", "all")
    assert Settings(api_key="k-test").preload == "all"
    monkeypatch.setenv("UNIFI_PRELOAD", "sometimes")
    with pytest.raises(ValidationError):
        Settings(api_key="k-test")
    assert "UNIFI_PRELOAD" in known_setting_names()


def test_container_image_preloads_all() -> None:
    """D2: stdio and pip installs default to none; the image sets all."""
    assert "ENV UNIFI_PRELOAD=all" in (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_write_names_uses_snapshot_verbs_for_stubs() -> None:
    snapshot = deferred.read_snapshot()
    stubs = [deferred.stub_from_record(r) for r in snapshot["tools"]]
    writes = deferred.write_names(stubs)
    assert writes == {r["name"] for r in snapshot["tools"] if r["write_verbs"]}
    assert "create_network" in writes and "list_networks" not in writes


# ------------------------------------------------------------- stop-condition checks


def test_runtime_view_and_catalog_build_load_every_step() -> None:
    """The build-time readers of ``fn`` load every deferred step first."""
    from unifi_fabric import catalog_build
    from unifi_fabric.catalog import inventory

    assert "load_all" in inspect.getsource(inventory.runtime_view)
    assert "load_all" in inspect.getsource(catalog_build)


def test_docs_say_startup_and_memory_only() -> None:
    """C9: lazy loading is never described as reducing the model's tool context."""
    text = (ROOT / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    line = next(row for row in text.splitlines() if row.startswith("| `UNIFI_PRELOAD`"))
    assert "Startup time and memory only" in line
    notes = _lazy_loading_release_notes()
    assert notes, "no release-note bullet about lazy loading (UNIFI_PRELOAD) was found"
    assert "tool context" not in notes.replace("not the model's tool context", "")


def _lazy_loading_release_notes() -> str:
    """The lazy-loading bullets of the in-flight release section, pending or folded.

    ``changelog_section.current_release`` is the section as the integrator publishes it: a
    pending ``changelog.d`` fragment is folded in, and once the release fold has deleted the
    fragment the bullets are read from CHANGELOG.md. The rule is the same in both places.
    """
    from tests import changelog_section

    _version, body = changelog_section.current_release()
    bullets: list[list[str]] = []
    open_bullet = False
    for line in body.splitlines():
        if line.startswith("- "):
            bullets.append([line])
            open_bullet = True
        elif open_bullet and line.startswith("  "):
            bullets[-1].append(line)
        else:
            open_bullet = False  # a heading or blank line ends the bullet
    kept = ["\n".join(b) for b in bullets]
    return "\n".join(b for b in kept if "UNIFI_PRELOAD" in b or "load on first call" in b)
