"""``scripts/regen_docs.py`` runs every documentation generator in order, in one command.

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
    assert regen.GENERATORS == (
        "scripts/gen_tools_doc.py",
        "scripts/gen_catalog_figures.py",
        "scripts/gen_reference_blocks.py",
    )
    for script in regen.GENERATORS:
        assert (ROOT / script).is_file(), script


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
