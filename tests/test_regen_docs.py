"""``scripts/regen_docs.py`` runs every generator and generated-file check in order, in one command.

Hermetic: stub generators in ``tmp_path``, and one end-to-end case that runs the real
``gen_reference_blocks.py`` against a temporary copy of a document with a stale block.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location("regen_docs", ROOT / "scripts" / "regen_docs.py")
assert _spec is not None and _spec.loader is not None
regen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(regen)

STUB = """import json, sys
from pathlib import Path
with Path(__file__).with_name("calls.jsonl").open("a") as log:
    log.write(json.dumps([Path(__file__).name, *sys.argv[1:]]) + "\\n")
raise SystemExit({code})
"""


def _stubs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, codes: list[int]) -> Path:
    (tmp_path / "scripts").mkdir()
    names = []
    for i, code in enumerate(codes):
        name = f"scripts/gen_{i}.py"
        (tmp_path / name).write_text(STUB.format(code=code))
        names.append(name)
    monkeypatch.setattr(regen, "ROOT", tmp_path)
    monkeypatch.setattr(regen, "GENERATORS", tuple(names))
    return tmp_path / "scripts" / "calls.jsonl"


def _calls(log: Path) -> list[list[str]]:
    import json

    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def test_the_generators_are_the_former_ci_steps_in_order() -> None:
    """The first thirteen are in every tree. The entries after the private-entries comment exist
    in the private tree only (the public-release transform removes those lines); every listed
    script must exist."""
    assert regen.GENERATORS[:13] == (
        "scripts/gen_membership.py",
        "scripts/gen_tools_doc.py",
        "scripts/gen_catalog_figures.py",
        "scripts/gen_reference_blocks.py",
        "scripts/gen_tool_catalog.py",
        "scripts/gen_tool_index.py",
        "scripts/gen_loaders.py",
        "scripts/gen_handler_adapters.py",
        "scripts/gen_tool_input_schemas.py",
        "scripts/check_retired_settings.py",
        "scripts/docs_claim_ledger.py",
        "scripts/gen_route_manifest.py",
        "scripts/gen_deferred_catalog.py",
    )
    for script in regen.GENERATORS:
        assert (ROOT / script).is_file(), script


def test_the_explicit_inventory_is_checked_first() -> None:
    """It is check-only (written by hand) and runs before any generator imports the server."""
    assert regen.GENERATORS[0] == "scripts/gen_membership.py"
    assert "scripts/gen_membership.py" in regen.CHECK_ONLY


#: Plants a tool in the first loader step that the explicit inventory does not list, then runs
#: ``regen_docs.py --check`` in this fresh interpreter (no conftest, no loaded server).
_PLANTED = """
import importlib, runpy, sys
from unifi_fabric.catalog import loaders

entry = loaders.LOADERS[0]
module = importlib.import_module(entry.module_path)
original = getattr(module, entry.function)


def planted(mcp, deps):
    out = original(mcp, deps)

    def rv_planted_unlisted_tool() -> str:
        return "planted"

    rv_planted_unlisted_tool.__module__ = entry.module_path
    rv_planted_unlisted_tool.__qualname__ = f"{entry.function}.<locals>.rv_planted_unlisted_tool"
    mcp.tool()(rv_planted_unlisted_tool)
    return out


setattr(module, entry.function, planted)
sys.argv = ["scripts/regen_docs.py", "--check"]
runpy.run_path("scripts/regen_docs.py", run_name="__main__")
"""


def test_an_unlisted_tool_fails_at_the_inventory_with_its_remedy() -> None:
    """A stale inventory stopped the run at gen_tools_doc with the regeneration command, the
    wrong advice for a file written by hand. It must stop at gen_membership, naming the tool."""
    import os
    import subprocess
    import sys

    env = {k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "MCP_", "FASTMCP_"))}
    done = subprocess.run(  # noqa: S603 - this interpreter and test-controlled code
        [sys.executable, "-c", _PLANTED],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 1, done.stderr[-4000:]
    assert "unknown tool: rv_planted_unlisted_tool" in done.stdout, done.stdout[-4000:]
    script = "scripts/gen_membership.py"
    assert f"regen_docs: {script} failed; {regen.REMEDIES[script]}" in done.stderr
    assert regen.FIX_COMMAND not in done.stderr
    assert "regen_docs: scripts/gen_tools_doc.py" not in done.stderr


def test_every_check_only_script_has_its_own_remedy() -> None:
    assert set(regen.REMEDIES) == regen.CHECK_ONLY
    for script, remedy in regen.REMEDIES.items():
        assert "regen_docs" not in remedy and script not in remedy, script


def test_a_failing_check_only_script_gets_its_remedy_not_the_regeneration_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Regeneration skips a lint, so telling the reader to run it would send them in a circle."""
    _stubs(tmp_path, monkeypatch, [0, 1])
    monkeypatch.setattr(regen, "CHECK_ONLY", frozenset({"scripts/gen_1.py"}))
    monkeypatch.setattr(regen, "REMEDIES", {"scripts/gen_1.py": "edit the claim by hand"})
    assert regen.main(["--check"]) == 1
    err = capsys.readouterr().err
    assert "scripts/gen_1.py failed; edit the claim by hand" in err
    assert regen.FIX_COMMAND not in err
    # A generator that is not check-only still names the regeneration command.
    (tmp_path / "again").mkdir()
    _stubs(tmp_path / "again", monkeypatch, [1])
    monkeypatch.setattr(regen, "CHECK_ONLY", frozenset())
    assert regen.main(["--check"]) == 1
    assert regen.FIX_COMMAND in capsys.readouterr().err


def test_write_flags_and_lints_name_listed_generators() -> None:
    assert set(regen.WRITE_FLAGS) <= set(regen.GENERATORS)
    assert regen.CHECK_ONLY <= set(regen.GENERATORS)
    assert not set(regen.WRITE_FLAGS) & regen.CHECK_ONLY, "a lint has no write mode"


@pytest.mark.parametrize("check", [True, False])
def test_every_generator_runs_in_order_with_the_mode_flag(
    check: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = _stubs(tmp_path, monkeypatch, [0, 0, 0])
    assert regen.main(["--check"] if check else []) == 0
    flag = ["--check"] if check else []
    assert _calls(log) == [[f"gen_{i}.py", *flag] for i in range(3)]


def test_check_stops_at_the_first_stale_generator_and_names_the_fix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    log = _stubs(tmp_path, monkeypatch, [0, 1, 0])
    assert regen.main(["--check"]) == 1
    assert [call[0] for call in _calls(log)] == ["gen_0.py", "gen_1.py"]
    err = capsys.readouterr().err
    assert "scripts/gen_1.py" in err and regen.FIX_COMMAND in err


def test_write_mode_uses_the_write_flag_and_skips_a_lint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = _stubs(tmp_path, monkeypatch, [0, 0, 0])
    monkeypatch.setattr(regen, "WRITE_FLAGS", {"scripts/gen_1.py": "--write"})
    monkeypatch.setattr(regen, "CHECK_ONLY", frozenset({"scripts/gen_2.py"}))
    assert regen.main([]) == 0
    assert _calls(log) == [["gen_0.py"], ["gen_1.py", "--write"]]
    assert regen.main(["--check"]) == 0
    assert _calls(log)[2:] == [[f"gen_{i}.py", "--check"] for i in range(3)]


def test_a_check_runs_in_this_interpreter_and_leaves_no_trace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A check shares the process (one server import, one capture), so it must restore the
    arguments, the working directory and the import path, and map every way a script ends
    (return, SystemExit(int), SystemExit(text), no SystemExit) to an exit code."""
    import os
    import sys

    (tmp_path / "scripts").mkdir()
    marker = tmp_path / "scripts" / "seen.txt"
    for name, body in {
        "ok_return": "pass",
        "bad_code": "raise SystemExit(3)",
        "bad_text": "raise SystemExit('stale thing')",
        "none_code": "raise SystemExit(None)",
    }.items():
        (tmp_path / "scripts" / f"{name}.py").write_text(
            "import os, sys\n"
            "from pathlib import Path\n"
            f"seen = [os.getcwd(), ' '.join(sys.argv[1:]), sys.path[0]]\n"
            f"Path({str(marker)!r}).write_text('|'.join(seen))\n"
            f"{body}\n"
        )
    monkeypatch.setattr(regen, "ROOT", tmp_path)
    argv, cwd, path = sys.argv[:], os.getcwd(), sys.path[:]
    codes = {
        name: regen.run(f"scripts/{name}.py", check=True)
        for name in ("ok_return", "bad_code", "bad_text", "none_code")
    }
    assert codes == {"ok_return": 0, "bad_code": 3, "bad_text": 1, "none_code": 0}
    assert "stale thing" in capsys.readouterr().err
    assert marker.read_text() == f"{tmp_path.resolve()}|--check|{tmp_path / 'scripts'}"
    assert (sys.argv, os.getcwd(), sys.path) == (argv, cwd, path)


def test_check_fails_with_a_diff_on_a_stale_block_and_the_command_fixes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    """End to end through the real reference-block generator, on a temporary copy."""
    doc = tmp_path / "docs" / "TOOL-USAGE.md"
    doc.parent.mkdir()
    current = (ROOT / "docs" / "TOOL-USAGE.md").read_text()
    assert "The 13 families" in current
    stale = current.replace("The 13 families", "The 99 families", 1)
    doc.write_text(stale)
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "gen_blocks.py").write_text(
        "import importlib.util, sys\n"
        "from pathlib import Path\n"
        f"path = Path({str(ROOT / 'scripts' / 'gen_reference_blocks.py')!r})\n"
        "spec = importlib.util.spec_from_file_location('gen_reference_blocks', path)\n"
        "gen = importlib.util.module_from_spec(spec)\n"
        "sys.modules[spec.name] = gen\n"
        "spec.loader.exec_module(gen)\n"
        f"gen.ROOT = Path({str(tmp_path)!r})\n"
        "gen.BLOCKS = {gen.ROOT / 'docs' / 'TOOL-USAGE.md': gen.BLOCKS[gen.TOOL_USAGE]}\n"
        "gen.DEFAULT_TABLES = {}\n"
        "sys.argv = ['gen_reference_blocks.py', *sys.argv[1:]]\n"
        "raise SystemExit(gen.main())\n"
    )
    monkeypatch.setattr(regen, "ROOT", tmp_path)
    monkeypatch.setattr(regen, "GENERATORS", ("scripts/gen_blocks.py",))
    assert regen.main(["--check"]) == 1
    err = capfd.readouterr().err
    assert "-The 99 families" in err and "+The 13 families" in err
    assert regen.FIX_COMMAND in err
    assert doc.read_text() == stale, "--check wrote to the file"
    assert regen.main([]) == 0
    assert doc.read_text() == current
    assert regen.main(["--check"]) == 0
