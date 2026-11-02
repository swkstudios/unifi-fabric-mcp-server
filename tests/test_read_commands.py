"""The Classic read commands (read_post_routes.READ_COMMANDS): one table, both safety modes.

Properties:

* every listed (route, command) pair is a read: under UNIFI_DRY_RUN, under UNIFI_READ_ONLY
  and under both it is sent exactly once and its result is returned verbatim, at the client
  chokepoint and through the registered tool (read-only and dry-run agree on every entry);
* every other command on the same routes, every other body (an extra key, a changed
  spelling, a non-string command, a non-dict body) and every other spelling of the path is
  a write: dry-run previews it and read-only refuses it, both with zero upstream requests;
* the generic relay stays a write whatever its body;
* the tools that send a read command are read tools, and the table is the one list every
  consumer reads.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from fastmcp import Client, FastMCP
from hypothesis import given
from hypothesis import strategies as st

from tests import test_cross_tool_invariants as cti
from unifi_fabric import _read_only_audit as audit
from unifi_fabric import read_only
from unifi_fabric import read_post_routes as rp
from unifi_fabric.client import UniFiClient, is_dry_run_preview
from unifi_fabric.config import Settings
from unifi_fabric.read_only_tools import ReadOnlyToolMiddleware
from unifi_fabric.tools import device_commands

IDS = [c.name for c in rp.READ_COMMANDS]
ROUTES = sorted({c.route for c in rp.READ_COMMANDS})
LISTED = {(c.route, c.command) for c in rp.READ_COMMANDS}

#: Every other command documented on, or sent to, the read commands' routes: the pinned
#: references (Art-of-WiFi Client.php, the community API wiki) and this server's tools.
OTHER_COMMANDS = (
    "adopt",
    "adv-adopt",
    "backup",
    "cancel-backup",
    "cancel-migrate",
    "check-firmware-update",
    "delete-backup",
    "export-site",
    "force-provision",
    "migrate",
    "power-cycle",
    "reboot",
    "restart",
    "restore",
    "set-locate",
    "set-rollupgrade",
    "spectrum-scan",
    "speedtest",
    "unset-locate",
    "unset-rollupgrade",
    "upgrade",
    "upgrade-all",
    "upgrade-external",
)

#: Every (route, command) pair on the read commands' routes that is not listed: the other
#: commands, and each listed command on a route it is not listed for.
UNLISTED_PAIRS = sorted(
    {(route, command) for route in ROUTES for command in OTHER_COMMANDS}
    | {(route, c.command) for route in ROUTES for c in rp.READ_COMMANDS} - LISTED
)


class _Str(str):
    __slots__ = ()


def _body_variants(command: str) -> list[Any]:
    """Bodies that carry a listed command but are not exactly ``{"cmd": command}``."""
    return [
        {"cmd": command, "mac": "02:00:5e:00:00:01"},
        {"cmd": command, "macs": []},
        {"cmd": command, "days": 7},
        {"cmd": command.upper()},
        {"cmd": command.capitalize()},
        {"cmd": " " + command},
        {"cmd": command + " "},
        {"cmd": command.replace("-", "_")},
        {"cmd": [command]},
        {"cmd": None},
        {"cmd": _Str(command)},
        {"CMD": command},
        {"command": command},
        {},
        OrderedDict(cmd=command),
        [command],
        [{"cmd": command}],
        command,
        None,
    ]


def _path_variants(sample: str) -> list[str]:
    """Spellings of a read command's route that are not the route."""
    head, _, last = sample.rpartition("/")
    return [
        sample + "/",
        sample + "/extra",
        sample + "%3F",
        sample + "%3Fx=1",
        sample + "%253Fx=1",
        sample + "%23x",
        head + "/" + last.upper(),
        head + "/" + last.capitalize(),
        head + "/" + last[:-1] + "%" + format(ord(last[-1]), "02X"),
        head + "%2F" + last,
        head + "/" + last + "x",
        head.replace("/cmd", "/CMD") + "/" + last,
        head.replace("/cmd", "//cmd") + "/" + last,
        sample.replace("/api/s/default/", "/api/s/../"),
        sample.replace("/api/s/default/", "/api/s/%2e%2e/"),
        sample.replace("/api/s/default/", "/api/s/de%2Ffault/"),
        sample.replace("/api/s/default/", "/api/s/default%3F/"),
        sample.replace("/api/s/default/", "/v2/api/site/default/"),
        sample.replace("/proxy/network/", "/proxy/protect/"),
        sample.replace("/v1/", "/ea/", 1),
        sample.replace("/proxy/", "/Proxy/"),
    ]


def _client(received: list, envelope: Any, **settings: Any) -> UniFiClient:
    async def upstream(request: httpx.Request) -> httpx.Response:
        received.append(request)
        return httpx.Response(200, json=envelope)

    client = UniFiClient(Settings(api_key="synthetic-test-api-key", **settings))
    transport = httpx.AsyncClient(
        base_url="https://example.invalid", transport=httpx.MockTransport(upstream)
    )
    client._get_client = AsyncMock(return_value=transport)  # type: ignore[method-assign]
    return client


#: The safety modes a read command must pass: dry-run, read-only, and both at once.
MODES = [
    pytest.param({"dry_run": True}, False, id="dry-run"),
    pytest.param({}, True, id="read-only"),
    pytest.param({"dry_run": True}, True, id="dry-run+read-only"),
]


def _set_read_only(monkeypatch: pytest.MonkeyPatch, on: bool) -> None:
    if on:
        monkeypatch.setenv(read_only.ENV_VAR, "1")
    else:
        monkeypatch.delenv(read_only.ENV_VAR, raising=False)


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------


def test_the_table_is_the_exact_read_command_list():
    assert LISTED == {
        ("firmware", "list-available"),
        ("firmware", "list-cached"),
        ("backup", "list-backups"),
        ("devmgr", "speedtest-status"),
    }
    assert len(rp.READ_COMMANDS) == len(LISTED) == len(set(IDS))
    for command in rp.READ_COMMANDS:
        assert command.tools and command.evidence, command.name
        assert command.body == {"cmd": command.command}
        assert command.template.endswith("/network/api/s/{site}/cmd/" + command.route)


@pytest.mark.parametrize(
    ("route", "command"),
    [
        ("Backup", "list-backups"),
        ("backup", "list_backups"),
        ("backup/x", "list-backups"),
        ("", "list-backups"),
        ("backup", ""),
        ("backup", "list--backups"),
        ("backup", "-list"),
    ],
)
def test_entries_are_lowercase_tokens(route, command):
    with pytest.raises(ValueError):
        rp.ReadCommand(route, command, frozenset({"t"}), ("e",))


# ---------------------------------------------------------------------------
# Listed pairs are reads in every mode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", rp.READ_COMMANDS, ids=IDS)
def test_listed_command_is_a_read_and_passes_read_only(command, monkeypatch):
    monkeypatch.setenv(read_only.ENV_VAR, "1")
    for path in (command.sample, command.sample + "?x=1", command.sample + "?a=%3F#b"):
        assert rp.read_command("POST", path, command.body) is command
        assert rp.read_command("post", path, dict(command.body)) is command
        assert rp.is_read_post("POST", path, command.body)
        assert not read_only.is_write_request("POST", path, command.body)
        read_only.guard_request("POST", path, body=command.body)  # no raise
        read_only.guard_area_write("POST", path, body=command.body)  # no raise
    # matches() takes a query-free path and never splits a second time
    assert not command.matches("POST", command.sample + "?x=1", command.body)


@pytest.mark.parametrize("command", rp.READ_COMMANDS, ids=IDS)
@pytest.mark.parametrize(("settings", "read_only_on"), MODES)
async def test_read_only_and_dry_run_agree_on_every_listed_command(
    command, settings, read_only_on, monkeypatch
):
    """Each mode sends the read command exactly once and returns its result verbatim,
    through ``post_read`` and through the client chokepoint itself."""
    _set_read_only(monkeypatch, read_only_on)
    envelope = {"meta": {"rc": "ok"}, "data": [{"read": command.name}], "future": [1]}
    for send in ("post_read", "client.post"):
        received: list[httpx.Request] = []
        client = _client(received, envelope, **settings)
        if send == "post_read":
            result = await rp.post_read(client, command.sample, json=command.body)
        else:
            result = await client.post(command.sample, json=command.body)
        assert result == envelope, send
        assert not is_dry_run_preview(result)
        assert [(r.method, r.url.path) for r in received] == [("POST", command.sample)]
        assert json.loads(received[0].content) == command.body
        await client.close()


# ---------------------------------------------------------------------------
# Everything else on the same routes is a write in every mode
# ---------------------------------------------------------------------------


async def _assert_write_everywhere(path: str, body: Any, monkeypatch) -> None:
    """Dry-run previews it and read-only refuses it; neither sends a request."""
    assert read_only.is_write_request("POST", path, body), (path, body)
    assert rp.read_command("POST", path, body) is None
    received: list[httpx.Request] = []
    monkeypatch.delenv(read_only.ENV_VAR, raising=False)
    client = _client(received, {"meta": {"rc": "ok"}}, dry_run=True)
    preview = await client.post(path, json=body)
    assert is_dry_run_preview(preview) and preview["preview"]["method"] == "POST", preview
    monkeypatch.setenv(read_only.ENV_VAR, "1")
    with pytest.raises(read_only.ReadOnlyModeError):
        read_only.guard_request("POST", path, body=body)
    with pytest.raises(read_only.ReadOnlyModeError):
        await client.post(path, json=body)
    assert received == []
    await client.close()


@pytest.mark.parametrize(("route", "command"), UNLISTED_PAIRS)
async def test_every_other_command_on_a_read_route_previews_and_is_refused(
    route, command, monkeypatch
):
    path = rp.READ_COMMANDS[0].sample.rsplit("/", 1)[0] + "/" + route
    await _assert_write_everywhere(path, {"cmd": command}, monkeypatch)


@pytest.mark.parametrize("command", rp.READ_COMMANDS, ids=IDS)
async def test_every_other_body_of_a_listed_command_previews_and_is_refused(command, monkeypatch):
    variants = _body_variants(command.command)
    assert len(variants) >= 15
    for body in variants:
        await _assert_write_everywhere(command.sample, body, monkeypatch)


@pytest.mark.parametrize("command", rp.READ_COMMANDS, ids=IDS)
def test_every_other_spelling_of_a_listed_route_is_a_refused_write(command, monkeypatch):
    monkeypatch.setenv(read_only.ENV_VAR, "1")
    variants = _path_variants(command.sample)
    assert len(variants) >= 20
    for path in variants:
        assert not rp.is_read_post("POST", path, command.body), path
        assert read_only.is_write_request("POST", path, command.body), path
        with pytest.raises(read_only.ReadOnlyModeError):
            read_only.guard_request("POST", path, body=command.body)
    for method in ("PUT", "PATCH", "DELETE"):
        assert read_only.is_write_request(method, command.sample, command.body)


@given(
    route=st.sampled_from(ROUTES),
    body=st.dictionaries(st.sampled_from(["cmd", "mac", "days"]), st.text(max_size=20)),
)
def test_only_an_exact_listed_body_is_a_read(route, body):
    path = rp.READ_COMMANDS[0].sample.rsplit("/", 1)[0] + "/" + route
    expected_read = list(body) == ["cmd"] and (route, body["cmd"]) in LISTED
    assert read_only.is_write_request("POST", path, body) is (not expected_read)


def test_relayed_read_command_stays_a_write(monkeypatch):
    # the relay passes always_write: its caller picks the path and the body
    monkeypatch.setenv(read_only.ENV_VAR, "1")
    for command in rp.READ_COMMANDS:
        with pytest.raises(read_only.ReadOnlyModeError):
            read_only.guard_request("POST", command.sample, always_write=True, body=command.body)


async def test_relayed_read_command_previews_under_dry_run(monkeypatch):
    monkeypatch.delenv(read_only.ENV_VAR, raising=False)
    received: list[httpx.Request] = []
    client = _client(received, {"meta": {"rc": "ok"}}, dry_run=True)
    for command in rp.READ_COMMANDS:
        response = await client.request(
            "POST", command.sample, json=command.body, always_write=True
        )
        assert is_dry_run_preview(response.json())
    assert received == []
    await client.close()


async def test_post_read_refuses_an_unlisted_command_before_any_request(monkeypatch):
    monkeypatch.delenv(read_only.ENV_VAR, raising=False)
    received: list[httpx.Request] = []
    client = _client(received, {"meta": {"rc": "ok"}})
    for command in rp.READ_COMMANDS:
        for body in [*_body_variants(command.command), {"cmd": "backup"}]:
            with pytest.raises(ValueError, match="read-POST allowlist"):
                await rp.post_read(client, command.sample, json=body)
    assert received == []
    await client.close()


# ---------------------------------------------------------------------------
# The tools
# ---------------------------------------------------------------------------


def test_read_command_tools_are_read_tools_and_command_writes_stay_writes():
    listed = {name for c in rp.READ_COMMANDS for name in c.tools}
    assert listed == {"list_device_firmware", "get_speedtest_status", "list_backups"}
    writes = audit.derive_write_tools(list(cti.TOOLS.values()))
    for name in listed:
        assert name not in writes, f"{name} sends only a listed read command"
        hint = cti.TOOLS[name].annotations.model_dump(by_alias=True)["readOnlyHint"]
        assert hint is True, name
    for name in ("run_speedtest", "create_backup", "export_site", "cancel_rolling_upgrade"):
        assert name in writes, name


def _tool_app(client: UniFiClient) -> FastMCP:
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "console"
    registry.resolve_site_slug.return_value = "default"
    app = FastMCP("read-commands")
    device_commands.register(app, lambda: (client, registry))
    app.add_middleware(ReadOnlyToolMiddleware(app))
    return app


TOOL_CALLS = [
    ("list_device_firmware", {}, "firmware", {"cmd": "list-available"}),
    ("list_device_firmware", {"cached": True}, "firmware", {"cmd": "list-cached"}),
    ("get_speedtest_status", {}, "devmgr", {"cmd": "speedtest-status"}),
    ("list_backups", {}, "backup", {"cmd": "list-backups"}),
]


@pytest.mark.parametrize(("name", "extra", "route", "body"), TOOL_CALLS)
@pytest.mark.parametrize(("settings", "read_only_on"), MODES)
async def test_registered_read_command_tool_runs_in_every_mode(
    name, extra, route, body, settings, read_only_on, monkeypatch
):
    _set_read_only(monkeypatch, read_only_on)
    envelope = {"meta": {"rc": "ok"}, "data": [{"read": name}]}
    received: list[httpx.Request] = []
    client = _client(received, envelope, **settings)
    async with Client(_tool_app(client)) as mcp:
        result = await mcp.call_tool(name, {"host": "h", "site": "s", **extra})
    assert not result.is_error
    assert json.loads(result.content[0].text) == envelope
    path = "/v1/connector/consoles/console/proxy/network/api/s/default/cmd/" + route
    assert [(r.method, r.url.path) for r in received] == [("POST", path)]
    assert json.loads(received[0].content) == body
    await client.close()


@pytest.mark.parametrize("name", ["run_speedtest", "create_backup", "export_site"])
async def test_registered_write_command_tool_on_a_read_route_is_refused(name, monkeypatch):
    monkeypatch.setenv(read_only.ENV_VAR, "1")
    received: list[httpx.Request] = []
    client = _client(received, {"meta": {"rc": "ok"}}, dry_run=True)
    async with Client(_tool_app(client)) as mcp:
        result = await mcp.call_tool(name, {"host": "h", "site": "s"}, raise_on_error=False)
    assert result.is_error
    assert read_only.ENV_VAR in " ".join(getattr(b, "text", "") for b in result.content)
    assert received == []
    await client.close()
