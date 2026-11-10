"""Process entrypoint that selects a command before importing MCP runtime code."""

from __future__ import annotations

import difflib
import sys


def _validate_api_key_configuration() -> None:
    """Exit before catalog import when upstream key configuration is invalid."""
    from pydantic import ValidationError

    from .config import Settings
    from .header_credentials import HEADER_MODE, StartupRefusal, key_mode

    try:
        if key_mode() == HEADER_MODE:
            # Header mode starts without a stored key; server.main checks the transport.
            return
    except StartupRefusal as refusal:
        print(refusal.token, file=sys.stderr)
        raise SystemExit(1) from None
    try:
        key_configs = Settings().get_key_configs()
    except ValueError as exc:
        if isinstance(exc, ValidationError):
            reasons = [
                str(err.get("msg", "")).removeprefix("Value error, ")
                for err in exc.errors(include_url=False, include_context=False, include_input=False)
            ]
        else:
            reasons = [str(exc)]
        reason = "; ".join(" ".join(item.split()) for item in reasons if item.strip())
        print(
            f"unifi-fabric-mcp: invalid configuration: {reason or type(exc).__name__}. "
            "See docs/CONFIGURATION.md",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
    if key_configs:
        return
    print(
        "UNIFI_API_KEY is not set — get a key at https://unifi.ui.com "
        "(Site Manager > API Keys) and set UNIFI_API_KEY or UNIFI_API_KEYS (or read it "
        "from a file or helper with UNIFI_API_KEY_FILE / UNIFI_API_KEY_COMMAND); "
        "see README#1-join-your-fabric-and-create-an-api-key",
        file=sys.stderr,
    )
    raise SystemExit(1)


def _version() -> str:
    """Resolve the installed package version (falls back to 'unknown')."""
    try:
        from importlib.metadata import version

        return version("unifi-fabric-mcp-server")
    except Exception:  # pragma: no cover - packaging-metadata absence is rare
        return "unknown"


_USAGE = """\
unifi-fabric-mcp {ver}
MCP server for the UniFi Fabric API (Network, Protect, Site Manager, InnerSpace,
Carrier Fabric, Mobility and ISP tools).

Usage:
  unifi-fabric-mcp                                 Run the MCP server (configured via environment)
  unifi-fabric-mcp placement-snapshot …            Run the one-shot placement snapshot exporter
  unifi-fabric-mcp placement-snapshot-preflight …  Check the snapshot's GET-only source capabilities
  unifi-fabric-mcp --help                          Show this help and exit
  unifi-fabric-mcp --version                       Print the version and exit

Configuration is via environment variables (UNIFI_API_KEY, MCP_AUTH_MODE,
MCP_BEARER_TOKEN, MCP_TLS_MODE, FASTMCP_TRANSPORT, …). See the README for the
full reference.
"""


_SUBCOMMANDS = ("placement-snapshot", "placement-snapshot-preflight")


def _unknown_command_message(command: str) -> str:
    """Build the actionable error for a positional argument that is not a subcommand."""
    lines = ["unifi-fabric-mcp: unknown command (value not shown)."]
    close = difflib.get_close_matches(command, _SUBCOMMANDS, n=1)
    if close:
        lines.append(f"Did you mean {close[0]!r}?")
    lines.append(
        "Valid commands: "
        + ", ".join(_SUBCOMMANDS)
        + ". Run with no command to start the MCP server (configured via environment)."
    )
    lines.append("Run 'unifi-fabric-mcp --help' for usage.")
    return "\n".join(lines)


def _stray_positionals(args: list[str]) -> list[str]:
    """Return the bare words in ``args`` that are not the value of a preceding flag.

    The server takes no positional arguments of its own, but it has always accepted
    (and ignored) dash flags, including flags written with a separate value such as
    ``--transport stdio``. A bare word directly after a dash flag that carries no
    inline ``=value`` is therefore treated as that flag's value and left alone. Any
    other bare word -- the first argument, a second word after a flag's value, a word
    after ``--flag=value``, or any word after a ``--`` separator -- is a stray
    positional (for example a mistyped or retired subcommand).
    """
    stray: list[str] = []
    value_allowed = False
    options_ended = False
    for arg in args:
        if options_ended:
            stray.append(arg)
        elif arg == "--":
            options_ended = True
        elif arg.startswith("-") and arg != "-":
            # ``--flag value`` may consume the next word; ``--flag=value`` may not.
            value_allowed = "=" not in arg
        elif value_allowed:
            value_allowed = False
        else:
            stray.append(arg)
    return stray


def _reject_unknown_command(args: list[str]) -> None:
    """Exit 2 if a stray positional argument is given without a recognised subcommand.

    The server itself takes no positional arguments, so a stray word (a mistyped or
    retired subcommand) must not silently start the MCP server. Dash flags, and the
    value word that follows a dash flag, reach the server exactly as before.
    """
    stray = _stray_positionals(args)
    if stray:
        print(_unknown_command_message(stray[0]), file=sys.stderr)
        raise SystemExit(2)


def main() -> None:
    """Run the isolated placement snapshot exporter or the normal MCP server.

    The exporter must be selected before importing :mod:`unifi_fabric.server`:
    server import constructs FastMCP transport/auth settings, which are neither
    required nor safe to parse for a one-shot read-only export command.
    """
    # Lightweight --help/--version handling BEFORE importing MCP runtime code, so
    # `unifi-fabric-mcp --help`/`--version` run without needing any configuration.
    if len(sys.argv) > 1 and sys.argv[1] in ("--help", "-h"):
        print(_USAGE.format(ver=_version()))
        raise SystemExit(0)
    if len(sys.argv) > 1 and sys.argv[1] in ("--version", "-V"):
        print(f"unifi-fabric-mcp {_version()}")
        raise SystemExit(0)
    # The one startup gate, before any settings model loads (every command below reads
    # the settings): a retired name or a blank/malformed policy setting prints its startup
    # token as the last stderr line (a retired name also the migration line) and exits 2.
    from .config import startup_gate

    startup_gate()

    if len(sys.argv) > 1 and sys.argv[1] == "placement-snapshot":
        from .placement_snapshot_cli import main as placement_snapshot_main

        raise SystemExit(placement_snapshot_main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "placement-snapshot-preflight":
        from .placement_snapshot_cli import preflight_main

        raise SystemExit(preflight_main(sys.argv[2:]))

    _reject_unknown_command(sys.argv[1:])

    _validate_api_key_configuration()

    from .server import main as server_main

    server_main()
