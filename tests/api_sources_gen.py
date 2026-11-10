"""Derive every tool's API sources from the routes it calls; write the generated table.

Run ``python -m tests.api_sources_gen --write`` after adding or re-routing a tool.
``tests/test_api_sources.py`` runs :func:`derive` and fails when the committed table
differs, so the classification can never be hand-edited or go stale.

Each registered tool is called normally and with its first non-resolution route
forbidden (403), so conditional fallback routes count too. Both use the shared generated arguments
(``tests/tool_args.py``) against the hermetic fake upstream (``tests/upstream_harness.py``);
every request path it sends (resolution GETs included) is classified with
:func:`unifi_fabric.api_sources.route_source`. Nothing leaves the process.
Port-reset MAC and device-name inputs are both exercised so its optional Classic
lookup remains in the source union when a MAC skips resolution.
``PAIR_OVERRIDES`` records explicit per-tool conservative
classification policy in addition to the exercised routes.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric import api_sources, server

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "src/unifi_fabric/generated_api_facts/_api_source_table.py"

#: Opt-in switches that would change which requests a tool sends.
_NEUTRAL_ENV = ("UNIFI_WRITE_POLICY", "UNIFI_WRITE_EXCEPTIONS", api_sources.DISABLE_ENV)

#: Conservative per-tool policy overrides, applied in addition to exercised routes.
#: Assets belong to the same InnerSpace project surface, which may be served privately;
#: disable the associated asset tool with that surface too (GS3 Wave 0 review M4).
PAIR_OVERRIDES: dict[str, tuple[str, ...]] = {
    "get_innerspace_asset": ("innerspace/private",),
    "authorize_guest": ("network/private.classic",),
    "revoke_guest_access": ("network/private.classic",),
}

#: Optional arguments that switch a tool to another route. Each tool is also called with
#: each override set merged over its generated arguments, so the branch it selects counts
#: towards the tool's sources (get_camera_snapshot with ts reads the private
#: cameras/{id}/recording-snapshot route, not the Integration snapshot).
ARG_VARIANTS: dict[str, tuple[dict[str, object], ...]] = {
    "get_camera_snapshot": ({"ts": 1_700_000_000_000},),
    # source="v2" (and the include_* / v2 filters) reads the private v2 history list.
    "list_known_clients": ({"source": "v2"},),
    # reboot_type sends the Classic cmd/devmgr restart instead of the Integration action.
    "restart_device": ({"reboot_type": "soft"},),
    # live_probes runs the allowlisted Site Manager reads; the default sends no request.
    "get_server_diagnostic_bundle": ({"live_probes": ["hosts", "sites"]},),
}


class _AttemptRecording(uh.FakeUpstream):
    """Also remember every request path the tool sent, served or not.

    A route the harness holds no capture for raises inside the fake upstream before it is
    recorded as served; the tool still called it, so it counts towards the tool's sources
    (list_active_clients reaches clients/active, which has no default capture).
    """

    def __init__(self) -> None:
        super().__init__()
        self.attempted: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.attempted.append(request.url.path)
        return super().__call__(request)


class _FirstPathForbidden(_AttemptRecording):
    """Deny the first application route once; retain successful selector resolution."""

    def __init__(self) -> None:
        super().__init__()
        self._forbidden = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if not self._forbidden and not uh.is_resolution(request.url.path):
            self._forbidden = True
            self.attempted.append(request.url.path)
            body = {"code": "forbidden", "message": "host not found"}
            self._record(request, 403, body, False)  # noqa: SLF001 - harness fault injection
            return httpx.Response(403, json=body)
        return super().__call__(request)


async def _paths(
    name: str,
    tool: object,
    *,
    fail_first_path: bool = False,
    overrides: dict[str, object] | None = None,
) -> list[str]:
    upstream = _FirstPathForbidden() if fail_first_path else _AttemptRecording()
    with pytest.MonkeyPatch.context() as mp:
        for var in _NEUTRAL_ENV:
            mp.delenv(var, raising=False)
        for var, value in tool_args.TOOL_ENV.get(name, {}).items():
            mp.setenv(var, value)
        client = uh.install(mp, upstream)
        try:
            args = tool_args.generated_args(tool)
            args.update(overrides or {})
            # Source derivation bootstraps the classifications consumed by the
            # request-policy middleware. Run the registered tool directly so a new tool
            # can reveal its routes before it exists in the previous generated table.
            await server.mcp.call_tool(name, args, run_middleware=False)
        except Exception:  # noqa: BLE001, S110 - a refused call still shows its routes
            pass
        finally:
            await client.close()
    return [*(served.path for served in upstream.served), *upstream.attempted]


async def iter_derived_async() -> AsyncIterator[tuple[str, tuple[str, ...]]]:
    """Exercise listed descriptors in order, releasing each after its routes."""
    # Preserve the listed schemas used by generated_args, then release processed tools.
    # This generator produces the source classifications consumed by tools/list policy.
    # Bypass that middleware while bootstrapping so a new tool can be classified before
    # it exists in the previous generated table.
    tools = sorted(
        await server.mcp.list_tools(run_middleware=False),
        key=lambda tool: tool.name,
        reverse=True,
    )
    while tools:
        tool = tools.pop()
        name = tool.name
        paths = await _paths(name, tool)
        paths.extend(await _paths(name, tool, fail_first_path=True))
        if name == "reset_switch_port":
            # MACs bypass resolution; names and Classic ids still require stat/device.
            device = uh.recorded("network_classic/network_api_s_SITE_stat_device.json")["body"][
                "data"
            ][0]["name"]
            paths.extend(await _paths(name, tool, overrides={"device": device}))
        for variant in ARG_VARIANTS.get(name, ()):
            paths.extend(await _paths(name, tool, overrides=variant))
        pairs = tuple(
            dict.fromkeys((*api_sources.tool_pairs(name, paths), *PAIR_OVERRIDES.get(name, ())))
        )
        yield name, pairs


async def derive_async() -> dict[str, tuple[str, ...]]:
    """``tool -> app/source pairs`` for every registered tool."""
    return {name: pairs async for name, pairs in iter_derived_async()}


def derive() -> dict[str, tuple[str, ...]]:
    return asyncio.run(derive_async())


def render(table: dict[str, tuple[str, ...]]) -> str:
    lines = [
        '"""GENERATED by python -m tests.api_sources_gen --write; do not edit."""',
        "",
        "from __future__ import annotations",
        "",
        "#: tool -> the app/source pairs it touches (unifi_fabric.api_sources), derived",
        "#: from the routes each tool calls against the hermetic fake upstream.",
        "TOOL_API_SOURCES: dict[str, tuple[str, ...]] = {",
    ]
    for name, pairs in sorted(table.items()):
        items = ", ".join(f'"{p}"' for p in pairs) + ("," if len(pairs) == 1 else "")
        lines.append(f'    "{name}": ({items}),')
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    derived = derive()
    if "--write" in argv:
        # Then run ``ruff format`` on the file; the check compares data, not text.
        OUTPUT.write_text(render(derived), encoding="utf-8")
        return 0
    if api_sources.table() != derived:
        sys.stderr.write(f"{OUTPUT} is stale: run python -m tests.api_sources_gen --write\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
