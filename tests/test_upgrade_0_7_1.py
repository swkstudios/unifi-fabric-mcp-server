"""The 0.7.0 -> 0.7.1 settings upgrade: the hard cut at startup and the one-shot migrator.

The retired names live only in the migration kit (``docs/MIGRATING-0.7.1.md``,
``tools/migrate-0.7.1-env.py``) and in ``tests/fixtures/upgrade-0.7.1/``; this module
reads them from there, and the server carries none. Remove this module, the fixtures and
the kit together in 0.7.2.

* Server: each retired name refuses startup before anything binds, with exit status 2, a
  stderr line naming it and linking the migration guide, and the token as the last line.
* Migrator: golden output per surface (client JSON, Codex TOML, Compose, env_file,
  shell), ``--write`` keeps a ``.bak``, no value other than a new 0.7.1 value is printed,
  and every migrated block is accepted by the real 0.7.1 startup gate and settings model
  (a block kept for a manual decision is still refused).
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from unifi_fabric import api_sources, policy
from unifi_fabric.families import ALL_FAMILIES

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "upgrade-0.7.1"
SCRIPT = ROOT / "tools" / "migrate-0.7.1-env.py"
RETIRED: dict[str, str] = json.loads((FIXTURES / "retired-settings.json").read_text())["settings"]
CASES: dict[str, dict] = json.loads((FIXTURES / "cases.json").read_text())["cases"]
REWRITTEN = {"json", "env", "compose"}
#: The documented placeholder the fixtures use for the API key (never printed back).
SYNTHETIC_KEY = "your-api-key-here"


def _load_migrator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migrate_071_env", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


migrator = _load_migrator()


# --------------------------------------------------------------------------- kit facts


def test_fixture_migrator_and_changelog_name_the_same_retired_settings() -> None:
    lint = importlib.util.spec_from_file_location(
        "check_retired_settings", ROOT / "scripts" / "check_retired_settings.py"
    )
    module = importlib.util.module_from_spec(lint)
    assert lint.loader is not None
    lint.loader.exec_module(module)
    changelog = set(module.retired_names(ROOT))
    assert set(RETIRED) == changelog
    assert set(migrator.RETIRED) == changelog
    assert {row[0] for row in migrator.MAPPING_ROWS} == changelog


def test_migrator_vocabularies_equal_the_server() -> None:
    assert tuple(migrator.NEW_SETTINGS) == tuple(policy.POLICY_SETTINGS)
    assert set(migrator.FAMILIES) == set(ALL_FAMILIES) == set(policy.FAMILIES)
    assert set(migrator.SELECTORS) == set(api_sources.valid_selectors())
    assert set(migrator.FAMILY_WRITE_FLAGS.values()) <= set(ALL_FAMILIES)


def test_server_code_names_no_retired_setting() -> None:
    pattern = re.compile(r"\b(" + "|".join(map(re.escape, RETIRED)) + r")\b", re.I)
    hits = [
        str(path.relative_to(ROOT))
        for path in (ROOT / "src").rglob("*")
        if path.is_file()
        and path.suffix in {".py", ".json", ".toml", ".txt", ".md"}
        and pattern.search(path.read_text(encoding="utf-8", errors="replace"))
    ]
    assert hits == []


def test_migrator_is_not_packaged() -> None:
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    build = project["tool"]["hatch"]["build"]["targets"]
    assert build["wheel"]["packages"] == ["src/unifi_fabric"]
    assert not any(p.startswith("tools") for p in build["sdist"]["only-include"])
    source = SCRIPT.read_text()
    assert "delete this file in 0.7.2, and no later than 2026-12-03" in source.lower()
    imports = re.findall(r"^\s*(?:from|import)\s+([\w.]+)", source, re.M)
    assert all(name.split(".")[0] in sys.stdlib_module_names for name in imports), imports


# --------------------------------------------------------------------------- server


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start(extra: dict[str, str], port: int) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(ROOT),
        "PYTHONPATH": str(ROOT / "src"),
        "UNIFI_API_KEY": SYNTHETIC_KEY,
        "FASTMCP_TRANSPORT": "streamable-http",
        "FASTMCP_HOST": "127.0.0.1",
        "FASTMCP_PORT": str(port),
        **extra,
    }
    return subprocess.run(  # noqa: S603 - this interpreter, the package's own entry point
        [sys.executable, "-m", "unifi_fabric"],
        env=env,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )


def _assert_refused(proc: subprocess.CompletedProcess[str], names: list[str]) -> str:
    assert proc.returncode == 2, proc.stderr
    assert proc.stdout == ""
    # Exactly the migration line and the token: nothing started, so nothing bound.
    message, token = proc.stderr.splitlines()
    assert token == f"startup:retired:{sorted(names)[0]}"
    assert f"unrecognized settings: {', '.join(sorted(names))}." in message
    assert "Settings were renamed in 0.7.1 and the old names are not accepted." in message
    assert f"Migrate: {policy.MIGRATION_URL} " in message
    assert f"(one command: {policy.MIGRATION_COMMAND})" in message
    assert SYNTHETIC_KEY not in proc.stderr
    return message


@pytest.mark.parametrize("name", sorted(RETIRED))
def test_each_retired_setting_refuses_startup_before_binding(name: str) -> None:
    port = _free_port()
    proc = _start({name: RETIRED[name]}, port)
    _assert_refused(proc, [name])
    with socket.socket() as sock, pytest.raises(OSError):
        sock.connect(("127.0.0.1", port))


def test_every_retired_setting_is_named_in_one_refusal() -> None:
    proc = _start(dict(RETIRED), _free_port())
    message = _assert_refused(proc, list(RETIRED))
    assert all(name in message for name in RETIRED)


def test_a_migrated_environment_passes_the_startup_gate() -> None:
    from unifi_fabric.config import startup_gate

    plan = migrator.plan_block(RETIRED)
    assert plan.manual == []
    assert set(plan.removed) == set(RETIRED)
    startup_gate({"UNIFI_API_KEY": SYNTHETIC_KEY, **plan.new})


# --------------------------------------------------------------------------- migrator


def _run(argv: list[str], capsys) -> tuple[int, str]:
    code = migrator.main(argv)
    return code, capsys.readouterr().out


@pytest.mark.parametrize("name", sorted(CASES))
def test_migrator_golden_output(name: str, tmp_path, monkeypatch, capsys) -> None:
    case = CASES[name]
    original = (FIXTURES / name).read_bytes()
    for companion in [name, *case.get("with", [])]:  # a Compose service env_file
        shutil.copy(FIXTURES / companion, tmp_path / companion)
    monkeypatch.chdir(tmp_path)

    code, out = _run([name], capsys)
    assert code == case["exit"]
    assert out == (FIXTURES / f"{name}.stdout").read_text()
    assert (tmp_path / name).read_bytes() == original, "a dry run wrote the file"

    code, _ = _run(["--write", name], capsys)
    assert code == case["exit"]
    if case["surface"] in REWRITTEN:
        assert (tmp_path / name).read_text() == (FIXTURES / f"{name}.expected").read_text()
        assert (tmp_path / f"{name}.bak").read_bytes() == original
    else:
        assert (tmp_path / name).read_bytes() == original
        assert not (tmp_path / f"{name}.bak").exists()


@pytest.mark.parametrize("name", sorted(CASES))
def test_migrator_never_prints_a_value_it_did_not_build(name: str) -> None:
    out = (FIXTURES / f"{name}.stdout").read_text()
    assert SYNTHETIC_KEY not in out
    for line in out.splitlines():
        if line.startswith("  - "):
            assert "=" not in line, line  # a removed setting is shown by name only


def test_unreadable_values_are_kept_and_never_echoed(capsys) -> None:
    secret = "value-that-looks-like-a-credential"
    plan = migrator.plan_block(
        {
            migrator.READ_ONLY: secret,
            migrator.DRY_RUN: None,
            migrator.TOOL_FAMILIES: f"network {secret}",
            "UNIFI_API_KEY": secret,
        }
    )
    report = migrator.Report()
    report.block("env", plan)
    out = capsys.readouterr().out
    assert secret not in out
    assert sorted(plan.kept) == sorted(
        [migrator.READ_ONLY, migrator.DRY_RUN, migrator.TOOL_FAMILIES]
    )
    assert plan.removed == [] and plan.new == {}
    assert out.count("# MANUAL: ") == 3


def test_exception_merge_keeps_one_entry_per_target_strictest_wins() -> None:
    network = next(n for n, f in migrator.FAMILY_WRITE_FLAGS.items() if f == "network")
    existing = "family:network=dry-run;family:vpn=dry-run"
    plan = migrator.plan_block({migrator.WRITE_EXCEPTIONS: existing, network: "0"})
    merged = "family:network=deny;family:vpn=dry-run"
    assert plan.new == {migrator.WRITE_EXCEPTIONS: merged}
    effective = policy.operator_policy(plan.new, None)  # 0.7.1 refuses a repeated target
    assert len(effective.write_exceptions) == 2
    unchanged = migrator.plan_block(
        {migrator.WRITE_EXCEPTIONS: "family:network=deny", network: "0"}
    )
    assert unchanged.new == {} and unchanged.removed == [network]


_NETWORK_FLAG = next(n for n, f in migrator.FAMILY_WRITE_FLAGS.items() if f == "network")


@pytest.mark.parametrize(
    ("setting", "old"),
    [
        (migrator.WRITE_POLICY, {migrator.DRY_RUN: "true"}),
        (migrator.WRITE_POLICY, {migrator.READ_ONLY: "1"}),
        (migrator.WRITE_EXCEPTIONS, {_NETWORK_FLAG: "false"}),
        (migrator.EXCLUDE, {migrator.DISABLED_TOOL_FAMILIES: "vpn"}),
        (migrator.EXCLUDE, {migrator.DISABLE_API_SOURCES: "protect/write"}),
        (migrator.FAMILY_ALLOW, {migrator.TOOL_FAMILIES: "protect"}),
    ],
)
def test_an_unreadable_0_7_1_setting_is_never_merged_or_replaced(setting, old) -> None:
    # None is a value the script cannot read: a ${VAR} reference or a value-less pass-through.
    plan = migrator.plan_block({setting: None, **old})
    assert setting not in plan.new
    assert plan.new == {} and plan.removed == []
    assert sorted(plan.kept) == sorted(old)
    assert all(f"{setting} has a value this script cannot read" in m for m in plan.manual)


def test_unreadable_0_7_1_settings_in_args_keep_the_old_flags(capsys) -> None:
    args = ["run", "-e", migrator.WRITE_POLICY, "-e", f"{migrator.DRY_RUN}=true", "image"]
    report = migrator.Report()
    assert migrator._migrate_args(list(args), "args", report) == args
    assert report.manual
    assert f"{migrator.WRITE_POLICY}=" not in capsys.readouterr().out


def test_separator_only_lists_are_removed_not_left_blank() -> None:
    plan = migrator.plan_block(
        {
            migrator.TOOL_FAMILIES: ",",
            migrator.DISABLED_TOOL_FAMILIES: " , ",
            migrator.DISABLE_API_SOURCES: ",",
        }
    )
    assert plan.new == {} and plan.manual == []
    assert len(plan.removed) == 3


def test_wrong_case_names_are_flagged_not_skipped(tmp_path, monkeypatch, capsys) -> None:
    lower = migrator.READ_ONLY.lower()
    plan = migrator.plan_block({lower: "1"})
    assert plan.kept == [lower] and plan.new == {} and len(plan.manual) == 1
    (tmp_path / "x.env").write_text(f"{lower}=1\n")
    monkeypatch.chdir(tmp_path)
    code, out = _run(["--write", "x.env"], capsys)
    assert code == 3
    assert f"# MANUAL: {lower} is spelled in lower or mixed case" in out
    assert (tmp_path / "x.env").read_text().splitlines()[-1] == f"{lower}=1"


def test_export_lines_in_an_env_file_are_shell_quoted(tmp_path, monkeypatch, capsys) -> None:
    flags = list(migrator.FAMILY_WRITE_FLAGS)[:2]
    (tmp_path / "a.env").write_text("".join(f"export {flag}=0\n" for flag in flags))
    monkeypatch.chdir(tmp_path)
    assert _run(["--write", "a.env"], capsys)[0] == 0
    value = "family:connector=deny;family:network=deny"
    assert (tmp_path / "a.env").read_text() == f"export UNIFI_WRITE_EXCEPTIONS='{value}'\n"
    sourced = subprocess.run(  # noqa: S603 - fixed argv, the test's own temp file
        ["/bin/sh", "-c", '. ./a.env && printf %s "$UNIFI_WRITE_EXCEPTIONS"'],  # noqa: S607
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert sourced.stdout == value and sourced.stderr == ""


def test_shell_continuation_lines_are_read_as_one_command(tmp_path, monkeypatch, capsys) -> None:
    script = (
        "docker run --rm -i \\\n"
        f"  -e {migrator.READ_ONLY}=1 \\\n"
        "  -e UNIFI_API_KEY \\\n"
        "  ghcr.io/swkstudios/unifi-fabric-mcp-server:0.7.0\n"
    )
    (tmp_path / "run.sh").write_text(script)
    monkeypatch.chdir(tmp_path)
    code, out = _run(["run.sh"], capsys)
    assert code == 0
    assert "line 1: -e flags:" in out
    assert f"  - {migrator.READ_ONLY}" in out
    assert "replace the removed -e flags with: -e UNIFI_WRITE_POLICY=deny" in out
    assert "nothing to migrate" not in out


def test_write_keeps_an_existing_backup(tmp_path, monkeypatch, capsys) -> None:
    shutil.copy(FIXTURES / "unifi.env", tmp_path / "unifi.env")
    (tmp_path / "unifi.env.bak").write_text("an older backup\n")
    monkeypatch.chdir(tmp_path)
    assert _run(["--write", "unifi.env"], capsys)[0] == 0
    assert (tmp_path / "unifi.env.bak").read_text() == "an older backup\n"
    assert (tmp_path / "unifi.env.bak.1").read_bytes() == (FIXTURES / "unifi.env").read_bytes()


def test_environment_mode_prints_shell_lines(monkeypatch, capsys) -> None:
    for name in list(os.environ):
        if name.startswith("UNIFI_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv(migrator.READ_ONLY, "1")
    monkeypatch.setenv("UNIFI_API_KEY", SYNTHETIC_KEY)
    for flag in list(migrator.FAMILY_WRITE_FLAGS)[:2]:
        monkeypatch.setenv(flag, "0")
    code, out = _run(["--env"], capsys)
    assert code == 0
    assert f"unset {migrator.READ_ONLY}" in out
    assert "export UNIFI_WRITE_POLICY=deny" in out
    assert "export UNIFI_WRITE_EXCEPTIONS='family:connector=deny;family:network=deny'" in out
    assert SYNTHETIC_KEY not in out


#: The 0.7.0 per-area write flag by the family it guarded, so no retired name is spelt here.
_WRITE_FLAG = {family: flag for flag, family in migrator.FAMILY_WRITE_FLAGS.items()}
_NET = _WRITE_FLAG["network"]
_NET_OFF = f"{_NET}=0"
_DISABLED = migrator.DISABLED_TOOL_FAMILIES
#: Compose ``environment:`` list items indented under the key, or at the key's own indent
#: (valid YAML that Compose accepts).
_LAYOUTS = ["      - ", "    - "]


def _compose(service: str, environment: str, item: str = _LAYOUTS[0]) -> str:
    return (
        "services:\n  s:\n    image: x\n"
        + "".join(f"    {line}\n" for line in service.splitlines())
        + "    environment:\n"
        + "".join(f"{item}{line}\n" for line in environment.splitlines())
    )


@pytest.mark.parametrize(
    ("env_file", "environment", "setting", "value"),
    [
        # The env_file already holds a tightening; the new entry must keep it.
        ("UNIFI_WRITE_EXCEPTIONS=family:vpn=deny", _NET_OFF,
         "UNIFI_WRITE_EXCEPTIONS", "family:vpn=deny;family:network=deny"),
        ("UNIFI_EXCLUDE=family:vpn", f"{_DISABLED}=protect",
         "UNIFI_EXCLUDE", "family:vpn,family:protect"),
        ("UNIFI_WRITE_POLICY=deny", f"{migrator.DRY_RUN}=1", "UNIFI_WRITE_POLICY", "deny"),
        # A 0.7.0 setting in the env_file counts as the value it migrates to.
        (f"{_WRITE_FLAG['protect']}=0", _NET_OFF,
         "UNIFI_WRITE_EXCEPTIONS", "family:protect=deny;family:network=deny"),
        (f"{migrator.DISABLE_API_SOURCES}=network/private", f"{_DISABLED}=vpn",
         "UNIFI_EXCLUDE", "source:network/private,family:vpn"),
    ],
)  # fmt: skip
@pytest.mark.parametrize(
    "reference",
    [
        "env_file: unifi.env",
        "env_file: [unifi.env]",
        "env_file:\n  - path: unifi.env\n    required: true",
        "env_file:\n- path: unifi.env\n  required: true",
    ],
)
@pytest.mark.parametrize("item", _LAYOUTS)
def test_compose_entries_keep_what_the_service_env_file_sets(
    env_file: str, environment: str, setting: str, value: str, reference: str, item: str,
    tmp_path, monkeypatch, capsys,
) -> None:  # fmt: skip
    """Compose applies a service env_file first and an ``environment:`` entry replaces
    the value it sets, so a new entry carries the env_file's value merged in."""
    (tmp_path / "unifi.env").write_text(env_file + "\n")
    (tmp_path / "compose.yaml").write_text(_compose(reference, environment, item))
    monkeypatch.chdir(tmp_path)
    code, out = _run(["--write", "compose.yaml"], capsys)
    assert code == 0, out
    assert f"  + {setting}={value}" in out
    assert _text_blocks((tmp_path / "compose.yaml").read_text()) == [{setting: value}]
    # Layer the two files the way Compose does, after the env_file is migrated too.
    assert _run(["--write", "unifi.env"], capsys)[0] == 0
    layered = {
        **_text_blocks((tmp_path / "unifi.env").read_text())[0],
        **_text_blocks((tmp_path / "compose.yaml").read_text())[0],
    }
    assert layered[setting] == value
    policy.operator_policy(layered, None)


@pytest.mark.parametrize(
    ("service", "env_file", "environment", "kept"),
    [
        # The env_file is read, but a value the new entry would replace is unknown.
        ("env_file: unifi.env", "UNIFI_WRITE_EXCEPTIONS=${X}", _NET_OFF, _NET),
        ("env_file: unifi.env", f"{migrator.READ_ONLY}=maybe", f"{migrator.DRY_RUN}=1",
         migrator.DRY_RUN),
        ("env_file: unifi.env", "UNIFI_EXCLUDE=family:vpn;bad", f"{_DISABLED}=vpn", _DISABLED),
        ("env_file: unifi.env", "UNIFI_FAMILY_ALLOW=network",
         f"{migrator.TOOL_FAMILIES}=network,vpn", migrator.TOOL_FAMILIES),
    ],
)  # fmt: skip
@pytest.mark.parametrize("item", _LAYOUTS)
def test_compose_entries_that_would_replace_an_unknown_env_file_value_are_manual(
    service: str, env_file: str | None, environment: str, kept: str, item: str,
    tmp_path, monkeypatch, capsys,
) -> None:  # fmt: skip
    if env_file is not None:
        (tmp_path / "unifi.env").write_text(env_file + "\n")
    text = _compose(service, environment, item)
    (tmp_path / "compose.yaml").write_text(text)
    monkeypatch.chdir(tmp_path)
    code, out = _run(["--write", "compose.yaml"], capsys)
    assert code == 3, out
    assert f"# MANUAL: {kept} cannot be merged: " in out
    assert "  + " not in out
    after = (tmp_path / "compose.yaml").read_text()
    assert f"\n{item.removesuffix('- ')}# MANUAL: {kept} cannot be merged: " in after
    assert _text_blocks(after) == _text_blocks(text), "the old settings are kept as they were"
    assert "${X}" not in out


#: An env_file that tightens policy: a new entry must not drop the tightening.
_VPN_DENY = "UNIFI_WRITE_EXCEPTIONS=family:vpn=deny\n"
_SERVICES = "services:\n  s:\n    image: x\n"


def _env(item: str = "      - ") -> str:
    return f"    environment:\n{item}{_NET_OFF}\n"


#: (compose text, files beside it, the construct the # MANUAL: line names). Each case is
#: a source of the service's environment this script does not resolve, or one of the
#: same class.
_UNRESOLVED = {
    # env_file lines in a form Compose reads but this script does not.
    **{
        f"env_file line {line!r}": (
            _SERVICES + "    env_file: unifi.env\n" + _env(),
            {"unifi.env": line + "\n"},
            "has a line this script does not parse (line 1",
        )
        for line in (
            "UNIFI_WRITE_EXCEPTIONS: family:vpn=deny",
            "UNIFI_WRITE_EXCEPTIONS = family:vpn=deny",
            "  export UNIFI_WRITE_EXCEPTIONS : family:vpn=deny",
            "UNIFI_WRITE_EXCEPTIONS",
            f"{_WRITE_FLAG['protect']}: 0",
            'X="a\nUNIFI_WRITE_EXCEPTIONS=family:vpn=allow\n"',
        )
    },
    "env_file missing": (
        _SERVICES + "    env_file: missing.env\n" + _env(), {}, "missing.env cannot be read"
    ),
    "env_file path interpolated": (
        _SERVICES + "    env_file: ${ENV_FILE}\n" + _env(), {}, "path uses interpolation"
    ),
    "env_file format raw": (
        _SERVICES + "    env_file:\n      - path: unifi.env\n        format: raw\n" + _env(),
        {"unifi.env": _VPN_DENY},
        "uses format:",
    ),
    # An environment: inherited through an anchor and a merge
    # key, or from a base service through extends:, by a service with its own env_file.
    "anchor and merge key": (
        f"x-common: &common\n  environment:\n    - {_NET_OFF}\n"
        + _SERVICES + "    <<: *common\n    env_file: unifi.env\n",
        {"unifi.env": _VPN_DENY},
        "a YAML anchor & on line 1",
    ),
    "extends": (
        f"services:\n  base:\n    image: x\n{_env()}"
        "  s:\n    extends: base\n    env_file: unifi.env\n",
        {"unifi.env": _VPN_DENY},
        "extends: on line 7",
    ),
    "extends from another file": (
        _SERVICES + "    extends:\n      file: base.yaml\n      service: b\n" + _env(),
        {"base.yaml": "services:\n  b:\n    env_file: unifi.env\n", "unifi.env": _VPN_DENY},
        "extends: on line 4",
    ),
    "merge key in the service": (
        "x-files: &files\n  env_file: unifi.env\n" + _SERVICES + "    <<: *files\n" + _env(),
        {"unifi.env": _VPN_DENY},
        "a << merge key on line 6",
    ),
    "alias of an environment": (
        f"x-env: &env\n  - {_NET_OFF}\n" + _SERVICES
        + "    env_file: unifi.env\n    environment: *env\n",
        {"unifi.env": _VPN_DENY},
        "a YAML alias * on line 7",
    ),
    "anchor on an environment": (
        f"{_SERVICES}{_env().replace('environment:', 'environment: &env')}"
        "  t:\n    image: x\n    env_file: unifi.env\n    environment: *env\n",
        {"unifi.env": _VPN_DENY},
        "a YAML anchor & on line 4",
    ),
    "tag": (
        _SERVICES + "    env_file: unifi.env\n"
        + _env().replace("environment:", "environment: !override"),
        {"unifi.env": _VPN_DENY},
        "a YAML tag such as !reset or !override on line 5",
    ),
    "include": (
        "include:\n  - other.yaml\n" + _SERVICES + _env(), {}, "include: on line 1"
    ),
    "environment outside a service": (
        f"x-env:\n  environment:\n    - {_NET_OFF}\n", {}, "not the environment: of a service"
    ),
    "override file beside it": (
        _SERVICES + _env(),
        {"compose.override.yaml": "services:\n  s:\n    env_file: unifi.env\n",
         "unifi.env": _VPN_DENY},
        "Compose also reads compose.override.yaml over this file",
    ),
    "second YAML document": (
        _SERVICES + _env() + "---\nservices:\n  s:\n    env_file: unifi.env\n",
        {"unifi.env": _VPN_DENY},
        "the file has more than one YAML document",
    ),
    "document end then second document": (
        _SERVICES + _env() + "...\n---\nservices:\n  s:\n    env_file: unifi.env\n",
        {"unifi.env": _VPN_DENY},
        "the file has more than one YAML document",
    ),
    "explicit key": (
        _SERVICES + _env() + "    ? env_file\n    : unifi.env\n",
        {"unifi.env": _VPN_DENY},
        "an explicit ? key",
    ),
    "escaped quoted key": (
        _SERVICES + _env() + '    "env\\x5ffile": unifi.env\n',
        {"unifi.env": _VPN_DENY},
        "a quoted key with an escape sequence",
    ),
    "service builds its image": (
        _SERVICES + "    build: .\n" + _env(),
        {"Dockerfile": "FROM scratch\nENV UNIFI_EXCLUDE=family:vpn\n"},
        "build: (an ENV in the built image is not read)",
    ),
    "COMPOSE_FILE in .env": (
        _SERVICES + _env(),
        {".env": "COMPOSE_FILE=compose.yaml:prod.yaml\n",
         "prod.yaml": "services:\n  s:\n    env_file: unifi.env\n",
         "unifi.env": _VPN_DENY},
        "Compose reads the files COMPOSE_FILE names (set in .env) with this file",
    ),
    "override file under the other default name": (
        _SERVICES + _env(),
        {"docker-compose.override.yml": "services:\n  s:\n    env_file: unifi.env\n",
         "unifi.env": _VPN_DENY},
        "Compose also reads docker-compose.override.yml over this file",
    ),
}  # fmt: skip
#: Where the # MANUAL: line says the settings are, when not service s.
_OWNER = {
    "extends": "service base",
    "anchor and merge key": "this block",
    "alias of an environment": "this block",
    "environment outside a service": "this block",
}


@pytest.mark.parametrize("case", sorted(_UNRESOLVED))
def test_compose_service_whose_environment_is_not_fully_resolved_is_left_unchanged(
    case: str, tmp_path, monkeypatch, capsys
) -> None:
    """Fail closed: the migrator rewrites a service's environment: only when it resolves
    every source of that environment. Otherwise the file stays byte for byte as it was,
    and a # MANUAL: line names the service (where there is one), the construct and the
    0.7.0 settings left in place; the exit status is 3, as for any other manual item."""
    text, companions, construct = _UNRESOLVED[case]
    owner = _OWNER.get(case, "service s")
    for name, content in companions.items():
        (tmp_path / name).write_text(content)
    (tmp_path / "compose.yaml").write_bytes(text.encode())
    monkeypatch.chdir(tmp_path)
    code, out = _run(["--write", "compose.yaml"], capsys)
    assert code == 3, out
    assert "  + " not in out and "  - " not in out, out
    manual = [line for line in out.splitlines() if line.startswith("  # MANUAL: ")]
    assert len(manual) == 1, out
    assert manual[0].startswith(f"  # MANUAL: {_NET} left unchanged in {owner}: "), out
    assert construct in manual[0], out
    assert (tmp_path / "compose.yaml").read_bytes() == text.encode()
    assert not list(tmp_path.glob("compose.yaml.bak*")), "nothing was written"


def test_compose_override_file_itself_is_left_unchanged(tmp_path, monkeypatch, capsys) -> None:
    text = _SERVICES + _env()
    (tmp_path / "compose.override.yaml").write_text(text)
    monkeypatch.chdir(tmp_path)
    code, out = _run(["--write", "compose.override.yaml"], capsys)
    assert code == 3, out
    assert "compose.override.yaml is an override file" in out
    assert (tmp_path / "compose.override.yaml").read_text() == text


@pytest.mark.parametrize(
    "environment",
    [f"environment: [{_NET_OFF}]", f'environment: {{{_NET}: "0"}}'],
)
def test_compose_settings_in_a_flow_collection_are_manual(
    environment: str, tmp_path, monkeypatch, capsys
) -> None:
    text = f"{_SERVICES}    {environment}\n"
    (tmp_path / "compose.yaml").write_text(text)
    monkeypatch.chdir(tmp_path)
    code, out = _run(["--write", "compose.yaml"], capsys)
    assert code == 3, out
    assert f"# MANUAL: {_NET} on line 4 is in a form this script does not rewrite" in out
    assert (tmp_path / "compose.yaml").read_text() == text


def test_compose_constructs_in_quotes_comments_or_block_scalars_do_not_block(
    tmp_path, monkeypatch, capsys
) -> None:
    """``&``, ``*``, ``!`` and ``<<`` in quoted values, comments and ``|`` scalars are
    text, not YAML structure, so the service is still migrated."""
    text = (
        "services:  # x: &not-an-anchor\n  s:\n    image: x\n"
        '    command: ["sh", "-c", "a && *b"]\n'
        "    entrypoint: |\n      *alias &anchor <<: !tag\n"
        f"    environment:\n      - {_NET_OFF}\n      - 'X=!a'\n"
    )
    (tmp_path / "compose.yaml").write_text(text)
    monkeypatch.chdir(tmp_path)
    code, out = _run(["--write", "compose.yaml"], capsys)
    assert code == 0, out
    assert "  + UNIFI_WRITE_EXCEPTIONS=family:network=deny" in out


def test_compose_service_with_an_unreadable_env_file_leaves_its_siblings_migrated(
    tmp_path, monkeypatch, capsys
) -> None:
    text = (
        f"services:\n  a:\n    image: x\n    env_file: missing.env\n{_env()}"
        f"  b:\n    image: x\n{_env()}"
    )
    (tmp_path / "compose.yaml").write_text(text)
    monkeypatch.chdir(tmp_path)
    code, out = _run(["--write", "compose.yaml"], capsys)
    assert code == 3, out
    assert f"# MANUAL: {_NET} left unchanged in service a: " in out
    after = (tmp_path / "compose.yaml").read_text()
    assert after.splitlines()[:6] == text.splitlines()[:6], "service a is unchanged"
    assert _text_blocks(after)[1] == {"UNIFI_WRITE_EXCEPTIONS": "family:network=deny"}


@pytest.mark.parametrize("item", _LAYOUTS)
def test_compose_service_without_env_file_is_unchanged_by_a_sibling_env_file(
    item: str, tmp_path, monkeypatch, capsys
) -> None:
    text = (
        "services:\n"
        "  a:\n    env_file: missing.env\n    image: x\n"
        f"  b:\n    image: x\n    environment:\n{item}{_NET_OFF}\n"
    )
    (tmp_path / "compose.yaml").write_text(text)
    monkeypatch.chdir(tmp_path)
    code, out = _run(["compose.yaml"], capsys)
    assert code == 0, out
    assert "  + UNIFI_WRITE_EXCEPTIONS=family:network=deny" in out
    assert "line 7: environment" in out, "the block is the environment key, not the service"


def test_docker_env_flags_next_to_an_env_file_are_manual(tmp_path, monkeypatch, capsys) -> None:
    """``docker run -e`` replaces a value from ``--env-file``, which the script cannot
    read (Docker resolves it from the client's working directory)."""
    args = ["run", "--rm", "-i", "--env-file", "unifi.env", "-e", _NET_OFF, "image"]
    config = {"mcpServers": {"unifi": {"command": "docker", "args": args}}}
    (tmp_path / "mcp.json").write_text(json.dumps(config, indent=2) + "\n")
    shell = f"docker {' '.join(args)}\n".replace("--env-file ", "--env-file=")
    (tmp_path / "run.sh").write_text(shell)
    monkeypatch.chdir(tmp_path)
    for name in ("mcp.json", "run.sh"):
        code, out = _run(["--write", name], capsys)
        assert code == 3, out
        assert f"# MANUAL: {_NET} cannot be merged: " in out
        assert "may also be set by the --env-file file" in out
        assert "  + " not in out and "replace the removed" not in out
    assert json.loads((tmp_path / "mcp.json").read_text()) == config


# --------------------------------------------------------------------------- 0.7.1 loader


def _json_blocks(node: object) -> list[dict[str, str]]:
    blocks: list[dict[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "env" and isinstance(value, dict):
                blocks.append({k: str(v) for k, v in value.items()})
            elif key == "args" and isinstance(value, list):
                pairs = [
                    str(value[i + 1]) for i in range(len(value) - 1) if value[i] in ("-e", "--env")
                ]
                blocks.append(dict(p.split("=", 1) for p in pairs if "=" in p))
            else:
                blocks.extend(_json_blocks(value))
    elif isinstance(node, list):
        for item in node:
            blocks.extend(_json_blocks(item))
    return blocks


_SETTING = re.compile(
    r"""^\s*(?:-\s+|export\s+)?["']?(UNIFI_[A-Z0-9_]+)(?:=|["']?\s*:\s*)["']?([^"'#]*)["']?"""
)


def _text_blocks(text: str) -> list[dict[str, str]]:
    """Settings per ``environment:`` block (Compose), or one block (env_file)."""
    blocks: list[dict[str, str]] = [{}]
    for line in text.splitlines():
        if line.strip() == "environment:":
            blocks.append({})
            continue
        match = _SETTING.match(line)
        if match:
            blocks[-1][match[1]] = match[2].strip()
    return [b for b in blocks if b]


def _printed_blocks(out: str) -> list[dict[str, str]]:
    """The 0.7.1 settings a print-only run tells the user to set, plus the names it kept."""
    blocks: list[dict[str, str]] = []
    for line in out.splitlines():
        if not line.startswith(" ") and line.endswith(":"):
            blocks.append({})
        elif line.startswith("  + "):
            name, _, value = line[4:].partition("=")
            blocks[-1][name] = value
        elif line.startswith("  # MANUAL: "):
            blocks[-1][line.split()[2]] = "kept"
    return [b for b in blocks if b]


def _migrated_blocks(name: str) -> list[dict[str, str]]:
    surface = CASES[name]["surface"]
    if surface == "json":
        return _json_blocks(json.loads((FIXTURES / f"{name}.expected").read_text()))
    if surface in REWRITTEN:
        return _text_blocks((FIXTURES / f"{name}.expected").read_text())
    return _printed_blocks((FIXTURES / f"{name}.stdout").read_text())


@pytest.mark.parametrize("name", sorted(CASES))
def test_migrated_output_is_accepted_by_the_0_7_1_loader(name: str, monkeypatch) -> None:
    from unifi_fabric.config import Settings, startup_gate

    blocks = [b for b in _migrated_blocks(name) if any(k.startswith("UNIFI_") for k in b)]
    assert blocks, name
    for block in blocks:
        env = {k: v for k, v in block.items() if k.startswith("UNIFI_")}
        env["UNIFI_API_KEY"] = SYNTHETIC_KEY
        kept = sorted(set(env) & set(RETIRED))
        if kept:
            # A setting kept for a manual decision still refuses startup, by name.
            with pytest.raises(policy.StartupRefusal) as info:
                policy.check_retired_settings(env, set(env) - set(RETIRED))
            assert info.value.token == f"startup:retired:{kept[0]}"
            env = {k: v for k, v in env.items() if k not in kept}
            if name == "compose-references.yaml":
                # Compose substitutes these defaults when their variables are unset.
                env = {
                    key: re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}]*)}", r"\1", value)
                    for key, value in env.items()
                }
        startup_gate(env)
        for existing in list(os.environ):
            if existing.upper().startswith("UNIFI_"):
                monkeypatch.delenv(existing)
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        Settings()
        policy.operator_policy(env, None)


@pytest.mark.parametrize(
    ("main", "override"),
    [
        ("docker-compose.yml", "compose.override.yml"),
        ("compose.yml", "docker-compose.override.yaml"),
        ("docker-compose.yaml", "docker-compose.override.yml"),
    ],
)
def test_any_default_override_name_beside_any_main_file_is_manual(
    tmp_path, monkeypatch, capsys, main, override
) -> None:
    monkeypatch.chdir(tmp_path)
    text = _SERVICES + _env()
    (tmp_path / main).write_text(text)
    (tmp_path / override).write_text("services:\n  s:\n    env_file: unifi.env\n")
    (tmp_path / "unifi.env").write_text(_VPN_DENY)
    code, out = _run(["--write", main], capsys)
    assert f"Compose also reads {override} over this file" in out
    assert "# MANUAL:" in out
    assert (tmp_path / main).read_text() == text
    assert code == 3, out


def test_compose_file_in_the_environment_is_manual(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("COMPOSE_FILE", "compose.yaml:prod.yaml")
    text = _SERVICES + _env()
    (tmp_path / "compose.yaml").write_text(text)
    (tmp_path / "prod.yaml").write_text("services:\n  s:\n    env_file: unifi.env\n")
    (tmp_path / "unifi.env").write_text(_VPN_DENY)
    code, out = _run(["--write", "compose.yaml"], capsys)
    assert "COMPOSE_FILE names (set in the environment)" in out
    assert "# MANUAL:" in out
    assert (tmp_path / "compose.yaml").read_text() == text
    assert code == 3, out


def test_compose_env_files_in_the_environment_is_manual(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("COMPOSE_FILE", raising=False)
    monkeypatch.setenv("COMPOSE_ENV_FILES", "cfg/stack.env")
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "stack.env").write_text("COMPOSE_FILE=compose.yaml:prod.yaml\n")
    text = _SERVICES + _env()
    (tmp_path / "compose.yaml").write_text(text)
    (tmp_path / "prod.yaml").write_text("services:\n  s:\n    env_file: unifi.env\n")
    (tmp_path / "unifi.env").write_text(_VPN_DENY)
    code, out = _run(["--write", "compose.yaml"], capsys)
    assert "COMPOSE_ENV_FILES" in out
    assert "# MANUAL:" in out
    assert (tmp_path / "compose.yaml").read_text() == text
    assert code == 3, out


@pytest.mark.parametrize("empty", ["", " null", " ~"])
def test_map_entry_with_no_value_is_filled_by_compose_so_it_is_manual(
    tmp_path, monkeypatch, capsys, empty
) -> None:
    """``NAME:`` in a map-form environment takes its value from the shell or .env, like a
    bare ``- NAME`` list item; the script cannot see it, so it must not replace it."""
    monkeypatch.chdir(tmp_path)
    text = (
        _SERVICES + f'    environment:\n      {_NET}: "0"\n      UNIFI_WRITE_EXCEPTIONS:{empty}\n'
    )
    (tmp_path / "compose.yaml").write_text(text)
    code, out = _run(["--write", "compose.yaml"], capsys)
    assert "+ UNIFI_WRITE_EXCEPTIONS=" not in out, out
    assert "# MANUAL:" in out, out
    assert "UNIFI_WRITE_EXCEPTIONS=" not in (tmp_path / "compose.yaml").read_text()
    assert code == 3, out
