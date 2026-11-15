"""The explicit family loader map (catalog/loaders.py) and its --check (public #42 step 4)."""

from __future__ import annotations

import ast
import importlib.util
import inspect
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from unifi_fabric import families
from unifi_fabric.catalog import loaders
from unifi_fabric.catalog.loaders import FAMILY_DEPENDENCIES, LOADERS, Loader, module_key

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "src" / "unifi_fabric"


def _gen():
    spec = importlib.util.spec_from_file_location(
        "gen_loaders", ROOT / "scripts" / "gen_loaders.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("gen_loaders", module)
    spec.loader.exec_module(module)
    return module


GEN = _gen()
KNOWN = [*families.ALL_FAMILIES, "meta"]
TEXT = (PKG / "catalog" / "loaders.py").read_text()


def _problems(entries=LOADERS, deps=FAMILY_DEPENDENCIES, text=None, root=None):
    text = GEN.render(entries, deps) if text is None else text
    kwargs = {"families": root} if root is not None else {}
    return GEN.check(entries, deps, text, known_families=KNOWN, **kwargs)


def test_committed_map_matches_the_family_directories():
    assert GEN.check(LOADERS, FAMILY_DEPENDENCIES, TEXT, known_families=KNOWN) == []


def test_seeded_stale_entry_fails():
    n = len(LOADERS)
    ghost = Loader(family="vpn", module="vpn", function="register_9", deps="bound", origin="vpn")
    problems = _problems(entries=(*LOADERS, ghost))
    assert problems == [
        f"stale entry: entry {n} (vpn/vpn:register_9): the module has no top-level register_9"
    ]
    gone = Loader(family="vpn", module="gone", function="register", deps="bound", origin="gone")
    assert _problems(entries=(*LOADERS, gone)) == [
        f"stale entry: entry {n} (vpn/gone:register): no module file vpn/gone.py"
    ]


def test_missing_duplicate_and_hand_edited_entries_fail():
    n = len(LOADERS)
    first = LOADERS[0]  # whichever step comes first, wherever a family move put it
    assert _problems(entries=LOADERS[1:]) == [
        f"missing entry: families/{first.family}/{first.module}.py:{first.function} registers "
        "tools but is not in the loader map"
    ]
    assert _problems(entries=(*LOADERS, LOADERS[0]))[0].startswith(f"duplicate entry: entry {n}")
    bad = LOADERS[0]._replace(deps="eager")
    assert any("deps 'eager'" in p for p in _problems(entries=(bad, *LOADERS[1:])))
    edited = TEXT.replace('    "carrier": (),', '    "carrier": ( ),')
    assert _problems(text=edited) == [
        "catalog/loaders.py is not what scripts/gen_loaders.py renders"
    ]


def test_unregistered_register_function_in_a_family_directory_fails(tmp_path):
    root = tmp_path / "families"
    shutil.copytree(PKG / "families", root)
    # Scratch directories, not real families: a real family gains a committed registrar
    # when it moves, which would make this test depend on move order.
    for scratch in ("scratch_one", "scratch_two"):
        (root / scratch).mkdir()
        (root / scratch / "__init__.py").write_text("")
    (root / "scratch_one" / "registrar.py").write_text(
        "def register(mcp, deps_fn):\n    return {}\n"
    )
    assert _problems(root=root) == [
        "missing entry: families/scratch_one/registrar.py:register registers tools but is not "
        "in the loader map"
    ]
    (root / "scratch_two" / "registrar.py").write_text(
        "def register(mcp, deps_fn):\n    return {}\n"
    )
    entries = (
        *LOADERS,
        Loader(
            family="scratch_one", module="registrar", function="register", deps="bound", origin="x"
        ),
        Loader(
            family="scratch_two", module="registrar", function="register", deps="late", origin="y"
        ),
    )
    # The layout stem is family-qualified, so two registrars are two module keys.
    assert _problems(entries=entries, root=root) == []


def test_layout_modules_are_keyed_by_family():
    assert module_key("vpn", "registrar") == "vpn/registrar"
    assert module_key("protect", "registrar") == "protect/registrar"
    assert module_key("vpn", "network_vpn_dns") == "network_vpn_dns"
    assert families.module_key_of("unifi_fabric.families.vpn.registrar") == "vpn/registrar"
    assert families.module_key_of("unifi_fabric.families.vpn.vpn") == "vpn"
    assert families.module_key_of("unifi_fabric.discovery") == "discovery"


def test_an_origin_is_an_index_key_that_may_span_directories():
    # The firewall steps split out of the network modules keep those modules' origins: an
    # origin is an index key only, so each is a network module indexed from families/firewall.
    split = [e for e in LOADERS if e.family == "firewall"]
    assert [e.origin for e in split] == [
        "firewall_proxy",
        "network_dpi_policy",
        "network_services_proxy",
    ]
    for entry in split:
        assert (PKG / "families" / "network" / f"{entry.origin}.py").is_file(), entry.origin
        assert not (PKG / "families" / "firewall" / f"{entry.origin}.py").exists(), entry.origin
    assert _problems() == []
    i = LOADERS.index(split[-1])
    bad = (*LOADERS[:i], split[-1]._replace(origin="Not A Stem"), *LOADERS[i + 1 :])
    assert _problems(entries=bad) == [
        f"invalid entry: entry {i} (firewall/registrar:register_3): origin "
        "'Not A Stem' is not a stem"
    ]


def test_declared_dependencies_are_known_sorted_and_keep_connector_for_protect():
    assert list(FAMILY_DEPENDENCIES) == KNOWN
    assert "connector" in FAMILY_DEPENDENCIES["protect"]
    wrong = {**FAMILY_DEPENDENCIES, "vpn": ("vpn",)}
    assert any("FAMILY_DEPENDENCIES['vpn']" in p for p in _problems(deps=wrong))


def test_module_family_is_derived_from_the_map():
    # Module keys only: an origin is an index key and never decides a family.
    assert families.MODULE_FAMILY == {e.key: e.family for e in LOADERS}
    assert families._REGISTER_MODULES == tuple(dict.fromkeys(e.key for e in LOADERS))
    for key in families._REGISTER_MODULES:
        assert (PKG / families._module_rel(key)).is_file(), key
    private = {p.stem for p in (PKG / "families").glob("*/_*.py")} - {"__init__"}
    assert private == {"_device_config", "_protect_device_types", "_v2_records"}
    assert not private & set(families.MODULE_FAMILY)


def test_server_has_no_family_register_lines():
    tree = ast.parse((PKG / "server.py").read_text())
    family_imports = [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("families")
    ]
    # No family module is imported by the server (public #41, D1): the relay body middleware
    # it installs lives in unifi_fabric.relay_policy.
    assert family_imports == []
    registers = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and GEN._REGISTER_RE.fullmatch(node.func.attr)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id != "protect_resources"
    ]
    assert registers == []


def test_registration_follows_the_map_order_and_deps_forms():
    # A fresh process: an exposure session earlier in this one re-adds tools at the end.
    probe = (
        "import asyncio\n"
        "from unifi_fabric import server\n"
        "from unifi_fabric.catalog import deferred\n"
        "from unifi_fabric.catalog.inventory import loader_ref\n"
        "deferred.load_all(server.mcp)\n"
        "tools = asyncio.run(server.mcp.list_tools(run_middleware=False))\n"
        "print('\\n'.join(loader_ref(tool.fn) for tool in tools))\n"
    )
    out = subprocess.run(  # noqa: S603 - this interpreter, a fixed import probe
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    steps = out.stdout.split()
    position = {entry.ref: index for index, entry in enumerate(LOADERS)}
    indexed = [position[step] for step in steps if step in position]
    assert indexed == sorted(indexed)
    assert set(indexed) == set(range(len(LOADERS)))
    # 15 before the firewall split; it adds firewall register_2/_3 and network register_21.
    assert sum(entry.deps == "late" for entry in LOADERS) == 18
    # 41 bound steps from server.py (diagnose_wifi's registration is the newest), plus the
    # vpn registrar (DNS pilot).
    assert sum(entry.deps == "bound" for entry in LOADERS) == 42


def test_load_passes_each_step_its_deps_form_and_rejects_a_name_twice(monkeypatch):
    calls: list[tuple[str, object]] = []

    class FakeModule:
        def __init__(self, name):
            self.name = name

        def register(self, mcp, deps_fn):
            calls.append((self.name, deps_fn))
            return {f"tool_{self.name}": object()}

    late, bound = object(), object()
    modules = {f"{loaders.FAMILIES_PACKAGE}.f.{m}": FakeModule(m) for m in ("a", "registrar")}
    monkeypatch.setattr(loaders.importlib, "import_module", modules.__getitem__)
    monkeypatch.setattr(loaders, "origin_module", lambda entry: None)
    monkeypatch.setattr(
        loaders,
        "LOADERS",
        (
            Loader(family="f", module="a", function="register", deps="late", origin="a"),
            Loader(family="f", module="registrar", function="register", deps="bound", origin="b"),
        ),
    )
    names = loaders.load(None, late=late, bound=bound)  # type: ignore[arg-type]
    assert calls == [("a", late), ("registrar", bound)]
    # A layout module is not re-exported by stem (two families may both have one).
    assert set(names) == {"a", "tool_a", "tool_registrar"}
    monkeypatch.setattr(loaders, "LOADERS", (*loaders.LOADERS, loaders.LOADERS[0]))
    with pytest.raises(RuntimeError, match="given twice"):
        loaders.load(None, late=object(), bound=bound)  # type: ignore[arg-type]


def test_server_re_exports_every_returned_wrapper():
    from unifi_fabric import server

    for name in ("list_hosts", "list_dns_policies", "list_cameras", "list_mobility_admins"):
        assert inspect.iscoroutinefunction(getattr(server, name)), name
    assert server.network_vpn_dns.__name__ == "unifi_fabric.families.vpn.network_vpn_dns"


def test_load_keeps_server_origin_bound_while_the_origin_module_exists(monkeypatch):
    """A step moved to a layout module keeps ``server.<origin>`` while the origin module exists."""

    class FakeModule:
        def register(self, mcp, deps_fn):
            return None

    origin, registrar = FakeModule(), FakeModule()
    modules = {f"{loaders.FAMILIES_PACKAGE}.f.registrar": registrar}
    monkeypatch.setattr(loaders.importlib, "import_module", modules.__getitem__)
    monkeypatch.setattr(
        loaders,
        "LOADERS",
        (Loader(family="f", module="registrar", function="register", deps="late", origin="old"),),
    )
    monkeypatch.setattr(loaders, "origin_module", lambda entry: origin)
    assert loaders.load(None, late=object(), bound=object()) == {"old": origin}  # type: ignore[arg-type]
    # Once the origin module is gone, nothing is bound under its name.
    monkeypatch.setattr(loaders, "origin_module", lambda entry: None)
    assert loaders.load(None, late=object(), bound=object()) == {}  # type: ignore[arg-type]


def test_origin_module_finds_the_origin_in_any_family_directory():
    from unifi_fabric.families.network import network_services_proxy
    from unifi_fabric.families.vpn import network_vpn_dns

    vpn = next(e for e in LOADERS if e.family == "vpn" and e.origin == "network_vpn_dns")
    assert loaders.origin_module(vpn) is network_vpn_dns
    split = vpn._replace(family="vpn", origin="network_services_proxy")
    assert loaders.origin_module(split) is network_services_proxy
    assert loaders.origin_module(vpn._replace(origin="no_such_module")) is None


def test_the_common_package_is_named_and_outside_the_families():
    assert loaders.COMMON_PACKAGE == "unifi_fabric.shared_shapes"
    assert not loaders.COMMON_PACKAGE.startswith(loaders.FAMILIES_PACKAGE)
    assert not hasattr(GEN, "cross_family_imports")  # the family-import gate is not here


@pytest.mark.parametrize(
    "origin", ["firewall_proxy", "network_dpi_policy", "network_services_proxy", "network_vpn_dns"]
)
def test_deferred_origin_resolves_after_steps_leave_directory(origin):
    from unifi_fabric import server
    from unifi_fabric.catalog import deferred

    entry = next(e for e in LOADERS if e.origin == origin)
    expected = loaders.origin_module(entry)
    assert expected is not None
    controller = deferred.controller_for(server.mcp)
    assert controller is not None
    assert controller.attribute(origin) is expected
