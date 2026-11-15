"""Registry listing contract.

``server.json`` is what MCP registry clients build their configuration form from, so each
setting it declares must offer exactly the values the server accepts, and every setting a
client manifest exposes to the user must be declared there too.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import tomllib
import types
import typing
from pathlib import Path

import pytest

from unifi_fabric import policy
from unifi_fabric.config import MCPTransportSettings, Settings

ROOT = Path(__file__).resolve().parents[1]
SERVER_JSON = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
PACKAGES = SERVER_JSON["packages"]

# A setting whose model field is a plain string but whose grammar is a closed set.
_CLOSED_STRING_SETTINGS = {"UNIFI_WRITE_POLICY": tuple(policy.WRITE_POLICIES)}


def _accepted_values() -> dict[str, tuple[str, ...]]:
    """Env name -> accepted values for every closed-set setting of both settings models."""
    out: dict[str, tuple[str, ...]] = dict(_CLOSED_STRING_SETTINGS)
    for model in (Settings, MCPTransportSettings):
        prefix = str(model.model_config.get("env_prefix") or "")
        for name, field in model.model_fields.items():
            alias = field.validation_alias
            env = alias.upper() if isinstance(alias, str) else f"{prefix}{name}".upper()
            ann = field.annotation
            if typing.get_origin(ann) in (typing.Union, types.UnionType):
                ann = next(a for a in typing.get_args(ann) if a is not type(None))
            if typing.get_origin(ann) is typing.Literal:
                out[env] = tuple(str(a) for a in typing.get_args(ann))
    return out


ACCEPTED = _accepted_values()


def _declared() -> list[tuple[str, dict]]:
    return [
        (pkg["registryType"], var)
        for pkg in PACKAGES
        for var in pkg.get("environmentVariables", [])
    ]


@pytest.mark.parametrize(
    ("registry", "var"), _declared(), ids=lambda x: x if isinstance(x, str) else x["name"]
)
def test_declared_choices_equal_what_the_server_accepts(registry: str, var: dict) -> None:
    name = var["name"]
    if name not in ACCEPTED:
        assert "choices" not in var, f"{registry} {name}: choices for an open-ended setting"
        return
    assert sorted(var.get("choices", [])) == sorted(ACCEPTED[name]), (
        f"{registry} {name}: server.json choices {var.get('choices')} != accepted "
        f"{list(ACCEPTED[name])}"
    )
    if "default" in var:
        assert var["default"] in var["choices"], f"{registry} {name}: default not a choice"


def _manifest_env_names() -> set[str]:
    """Every env var a client manifest lets the user set (fixed values excluded)."""
    names: set[str] = set()
    desktop = json.loads((ROOT / "plugins/claude-desktop/manifest.json").read_text())
    claude = json.loads((ROOT / "plugins/claude/.claude-plugin/plugin.json").read_text())
    for env in (
        desktop["server"]["mcp_config"]["env"],
        *(s.get("env", {}) for s in claude["mcpServers"].values()),
    ):
        names |= {k for k, v in env.items() if "${user_config." in v}
    codex = json.loads((ROOT / "plugins/codex/.mcp.json").read_text())
    for server in codex["mcpServers"].values():
        names |= set(server.get("env_vars", []))
    gemini = json.loads((ROOT / "gemini-extension.json").read_text())
    names |= {s["envVar"] for s in gemini.get("settings", []) if "envVar" in s}
    return names


def test_manifests_expose_settings():
    # Guard against the helper silently finding nothing.
    assert {"UNIFI_API_KEY", "UNIFI_WRITE_POLICY", "UNIFI_TOOL_MODE"} <= _manifest_env_names()


@pytest.mark.parametrize("pkg", PACKAGES, ids=lambda p: p["registryType"])
def test_every_manifest_setting_is_declared_in_each_registry_package(pkg: dict) -> None:
    declared = {v["name"] for v in pkg.get("environmentVariables", [])}
    missing = sorted(_manifest_env_names() - declared)
    assert not missing, f"server.json {pkg['registryType']} package does not declare {missing}"


# --- listing metadata and icons ------------------------------------------------------------------
#
# The icon is the "T" set (a dot-matrix globe, light and dark variants) in docs/assets/icon/. The
# table pins every file by sha256 and byte size, so a re-render or a swapped file fails here; the
# PNG pixel size comes from the file name and is checked against the file's header. Hosts that
# need the file inside their own folder carry byte copies, and each copy is pinned to its source.

PUBLIC_REPO_URL = "https://github.com/swkstudios/unifi-fabric-mcp-server"
RAW_ICON_BASE = (
    "https://raw.githubusercontent.com/swkstudios/unifi-fabric-mcp-server/main/docs/assets/icon/"
)
ICON_DIR = ROOT / "docs" / "assets" / "icon"
PROJECT_VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
    "version"
]

# name -> (sha256, size in bytes)
ICON_PINS = {
    "T-dark-1024.png": ("5465c6ccacc80146bc6d57e7ba840b82afb960970e4cc4b9794bddd7a58366a9", 492369),
    "T-dark-128.png": ("1dd6f55381eab93dd34f5afd498821d2a78f989e350544d2ba02b559dc3d04f6", 1748),
    "T-dark-128.svg": ("18a8eb4db2e64c0975cd448a291179dfb67fd3bd91ed121ae2a3db25c60ddc16", 39037),
    "T-dark-16.png": ("52a3e88664a257cf56bc4b5fd7b44752a2c0dc42df8b5c7c12a21295c65fa439", 211),
    "T-dark-16.svg": ("447652e722efc9653054f588cb3efb3b588427c2655ac1736aea18df473c3182", 1774),
    "T-dark-256.png": ("739e792523cf46244b706b452e4bdf95b964f278ee96881d1e5b913ed745764f", 56446),
    "T-dark-32.png": ("6c7e675087eb8259f1a68142c0a1277f2dd4ec7716e41b19b5be73a3c47798f5", 423),
    "T-dark-32.svg": ("21cb2f0b3be63126df3ab667d293bffaa9970fd92b3f8fb3c18fd1287dc00ee0", 5867),
    "T-dark-48.png": ("97fb751b7bc343e4302ba11f2c06fbf8dde5b651975a9c23fec40a4d6019af78", 635),
    "T-dark-48.svg": ("0e41c4aebad848b5111ff76e7a8bff1211e2e373cee692975d634513a06f7b82", 8717),
    "T-dark-512.png": ("6c381c482c9fc8253b033180382b4479765a9562968ea85407a063eb0c55e38d", 180382),
    "T-dark-64.png": ("4e4123e5f5fe03718a84f322b5d52982243ad7b430acf57fec6801895763921b", 748),
    "T-dark-64.svg": ("be70830cedc0e3b9564c15ecce911336dd4f2a8bdb0e5ec3e276513d5cab1dd2", 13501),
    "T-dark-small.svg": ("21cb2f0b3be63126df3ab667d293bffaa9970fd92b3f8fb3c18fd1287dc00ee0", 5867),
    "T-dark.svg": ("00d532e34d6f359625f64c5da5eab1bf65fe3b77b93a3378b8c563d9a594b32b", 14283),
    "T-light-1024.png": (
        "16a484f80df89c6101a7e0ee6a9a4bfd0fc9a5c15d39fd8d9be3461eca901e7b",
        400166,
    ),
    "T-light-128.png": ("14c668cbb581f7d65a27c2ffe3e92b6150417de6cec62ea874d9bcc58074bbf6", 1747),
    "T-light-128.svg": ("ec2335d0c32cd6c00b22a3fe0e3cda10edfd3f2f61590970828c3c11b4bcabf4", 39025),
    "T-light-16.png": ("852d568b03f9112761b04b9044f09ce4fe65b5d8380debeba58beef89e8aa632", 233),
    "T-light-16.svg": ("0fdaccc36d7e3e13a2aa8cf3c793d3040281a01fc6f3772cbe2a60c89375685b", 1941),
    "T-light-256.png": ("9a6e785d858667d9580abedb4cea69b90692b2cb10ce6ab70eb18f8d313a26ad", 48689),
    "T-light-32.png": ("9c3fecc2a212e4f06cb02f8b8c9f805a8b0f2f234c03c8ef38b404cb1b780fad", 442),
    "T-light-32.svg": ("370e84e73c9f5655c91a4892cfb1043b2ff91ff53c175d1e98ccd68847c81567", 5855),
    "T-light-48.png": ("ae3a32c4c1edfd34ccac3a5966883ca6c5c5722221fd92f8c84b446829f99265", 635),
    "T-light-48.svg": ("dac0e3fb01ed301fb1c19933c9e3eb3032da9f78985dbd6bbaff368121914f97", 8705),
    "T-light-512.png": ("9d9354683fe052ad96a452b4d4434e450c963767bf129dc9ebb403aab02ff58f", 153697),
    "T-light-64.png": ("c1370d3010de964db29f36082250490954e49a694683ea9d3ac647620b984db5", 751),
    "T-light-64.svg": ("2683866998aab6ef2f9d6948d47427a9af737ee418bc215a4875ebd2641118a0", 13489),
    "T-light-small.svg": ("370e84e73c9f5655c91a4892cfb1043b2ff91ff53c175d1e98ccd68847c81567", 5855),
    "T-light.svg": ("ff4dcc2cae4b7acc80253fd7c31c6a8cf6866482005c99f3437cdae0a4ef2bc2", 14264),
    "favicon.ico": ("3faffd35a5e871e779adf4bb30689ad9ac729c5a2b3fdad47ffaa4127434ecbe", 1323),
}
ICON_DIR_EXTRAS: set[str] = set()  # the folder holds the pinned files and nothing else
# Where a host needs the file inside its own folder: copy -> source in ICON_DIR.
ICON_COPIES = {
    # Claude Code plugin: the directory listing needs a square PNG of 512-2048 px (see the test).
    "plugins/claude/.claude-plugin/icon.png": "T-dark-512.png",
    # Claude Desktop bundle: the 512 and 256 px renders and the native 16-128 px glyphs.
    "plugins/claude-desktop/icon.png": "T-dark-512.png",
    "plugins/claude-desktop/icon-light.png": "T-light-512.png",
    **{
        f"plugins/claude-desktop/icon{tag}-{px}.png": f"T-{theme}-{px}.png"
        for tag, theme in (("", "dark"), ("-light", "light"))
        for px in (16, 32, 64, 128, 256)
    },
    # Codex: the logo is the 512 render, the composer icon the native 32 px glyph.
    "plugins/codex/assets/logo.png": "T-dark-512.png",
    "plugins/codex/assets/composer-icon.png": "T-dark-32.png",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", f"{path} is not a PNG"
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def test_server_json_listing_has_a_title_and_a_public_website():
    assert SERVER_JSON["title"] == "UniFi Fabric MCP Server"
    assert SERVER_JSON["websiteUrl"] == PUBLIC_REPO_URL
    assert 1 <= len(SERVER_JSON["title"]) <= 100  # the schema's bounds
    assert "tekno" not in json.dumps(SERVER_JSON).lower()  # nothing private reaches the registry


def test_the_icon_folder_holds_exactly_the_pinned_png_svg_and_ico_files():
    names = {p.name for p in ICON_DIR.iterdir()}
    assert names == set(ICON_PINS) | ICON_DIR_EXTRAS, sorted(
        names ^ (set(ICON_PINS) | ICON_DIR_EXTRAS)
    )
    assert all(
        name.endswith((".png", ".svg", ".ico")) for name in ICON_PINS
    )  # no .blend, no scripts


@pytest.mark.parametrize("name", sorted(ICON_PINS))
def test_each_icon_file_matches_its_pinned_hash_and_size(name):
    path = ICON_DIR / name
    digest, size = ICON_PINS[name]
    assert path.stat().st_size == size, f"{name}: {path.stat().st_size} bytes, pinned {size}"
    assert _sha256(path) == digest, f"{name} changed: re-render the set and re-pin it"
    if name.endswith(".png"):
        pixels = int(re.search(r"-(\d+)\.png$", name).group(1))
        assert _png_size(path) == (pixels, pixels), name


def test_every_icon_variant_exists_at_every_size():
    for theme in ("light", "dark"):
        for pixels in (16, 32, 48, 64, 128, 256, 512, 1024):
            assert f"T-{theme}-{pixels}.png" in ICON_PINS
        for pixels in (16, 32, 48, 64, 128):
            assert f"T-{theme}-{pixels}.svg" in ICON_PINS
    assert "favicon.ico" in ICON_PINS


def test_server_json_icons_list_both_themes_and_point_at_the_pinned_files():
    icons = SERVER_JSON["icons"]
    assert {(i["theme"], i["sizes"][0]) for i in icons} == {
        (theme, f"{px}x{px}") for theme in ("light", "dark") for px in (512, 128, 64)
    }
    for icon in icons:
        src = icon["src"]
        assert src.startswith(RAW_ICON_BASE), src  # public https, the main branch
        assert len(src) <= 255, src  # the schema's maxLength
        name = src.removeprefix(RAW_ICON_BASE)
        assert name in ICON_PINS, name
        assert icon["mimeType"] == "image/png", icon
        pixels = int(icon["sizes"][0].split("x")[0])
        assert icon["sizes"] == [f"{pixels}x{pixels}"]
        assert name == f"T-{icon['theme']}-{pixels}.png", icon  # theme and size match the file


@pytest.mark.parametrize(("copy", "source"), sorted(ICON_COPIES.items()))
def test_icon_copies_are_byte_identical_to_their_source(copy, source):
    assert (ROOT / copy).read_bytes() == (ICON_DIR / source).read_bytes()


def test_claude_plugin_icon_meets_the_directory_rules():
    plugin = ROOT / "plugins" / "claude"
    manifest = json.loads((plugin / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    declared = manifest.get("icon")
    # the directory reads this field, so it must be declared (not left to the default location)
    assert declared == "./.claude-plugin/icon.png"
    icon = plugin / declared
    assert icon.is_file(), "the Claude plugin has no icon (validator ICON_MISSING)"
    width, height = _png_size(icon)  # SVG and WebP are not accepted
    assert width == height, f"icon must be square, not {width}x{height}"
    assert 512 <= width <= 2048, f"icon must be 512-2048 px on a side, not {width}"
    assert icon.stat().st_size < 2 * 1024 * 1024, "icon must be under 2 MB"


def test_mcpb_manifest_names_its_icons_and_they_are_in_the_bundle_folder():
    bundle = ROOT / "plugins" / "claude-desktop"
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["icon"] == "icon.png"
    # Every size and both themes: a host that shows the extension at 16-32 px picks a native
    # glyph, never a downscaled render. MCPB icons are {src, size, theme}.
    expected = [
        {
            "src": f"icon{tag}-{px}.png" if px != 512 else f"icon{tag}.png",
            "size": f"{px}x{px}",
            "theme": theme,
        }
        for tag, theme in (("", "dark"), ("-light", "light"))
        for px in (16, 32, 64, 128, 256, 512)
    ]
    assert manifest["icons"] == expected
    for entry in manifest["icons"]:
        pixels = int(entry["size"].split("x")[0])
        assert _png_size(bundle / entry["src"]) == (pixels, pixels), entry
        # the file is the pinned source of the same theme and size
        source = ICON_COPIES[f"plugins/claude-desktop/{entry['src']}"]
        assert source == f"T-{entry['theme']}-{pixels}.png", entry


def test_codex_plugin_names_its_icons():
    plugin = ROOT / "plugins" / "codex"
    interface = json.loads((plugin / ".codex-plugin" / "plugin.json").read_text())["interface"]
    assert interface["composerIcon"] == "./assets/composer-icon.png"  # native 32 px
    assert interface["logo"] == "./assets/logo.png"
    for key in ("composerIcon", "logo"):
        assert (plugin / interface[key]).is_file(), key


def test_readme_hero_pairs_each_theme_with_its_variant():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    head = text.split('<h1 align="center">', 1)[0]
    dark = 'srcset="docs/assets/icon/T-dark-512.png 1x, docs/assets/icon/T-dark-1024.png 2x"'
    assert '<source media="(prefers-color-scheme: dark)" ' + dark in head
    assert 'src="docs/assets/icon/T-light-512.png"' in head
    assert (
        'srcset="docs/assets/icon/T-light-512.png 1x, docs/assets/icon/T-light-1024.png 2x"' in head
    )
    assert 'alt="UniFi Fabric MCP Server' in head
    for name in re.findall(r"docs/assets/icon/(T-[a-z]+-\d+\.png)", head):
        assert name in ICON_PINS, name


def test_the_old_banner_image_is_gone_and_nothing_names_it():
    assert not (ROOT / "docs" / "banner.png").exists()
    for rel in ("README.md", "server.json", "llms.txt"):
        path = ROOT / rel
        if path.exists():
            assert "docs/banner.png" not in path.read_text(encoding="utf-8"), rel


def test_antigravity_plugin_declares_the_release_version():
    manifest = json.loads(
        (ROOT / "plugins" / "antigravity" / "plugin.json").read_text(encoding="utf-8")
    )
    assert re.fullmatch(r"\d+\.\d+\.\d+", manifest["version"])
    assert manifest["version"] == PROJECT_VERSION
