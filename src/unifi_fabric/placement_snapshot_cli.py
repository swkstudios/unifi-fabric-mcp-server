"""One-shot, read-only UniFi placement snapshot export command.

This command is deliberately part of the server package rather than a second
service.  It runs with the same authenticated image environment as the MCP
server, calls the already-bounded collector, and writes exactly one JSON value
to stdout.  It is intended for an atomic snapshot publisher.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from typing import Any, NoReturn

from pydantic import ValidationError
from pydantic_settings import SettingsError

from .client import UniFiClient
from .config import Settings
from .registry import Registry
from .secret_scrub import configured_secrets, install_log_scrubber, scrub
from .tools.innerspace import exception_message
from .tools.placement_snapshot import (
    get_unifi_placement_snapshot,
    preflight_placement_snapshot_capabilities,
)


async def export_snapshot(host: str) -> dict[str, Any]:
    """Collect a snapshot with the authenticated server configuration.

    The collector is GET-only, so it runs whatever the connector-write setting is; a
    deployment that wants its publisher image read-only sets that itself. Withholding
    follows the same ``UNIFI_REDACT_SECRETS`` setting as the MCP tool: off by default
    (upstream strings and the address / asset-URL fields verbatim).
    """
    settings = _settings_with_keys("export")

    client = UniFiClient(settings)
    registry = Registry(
        client,
        ttl_seconds=settings.cache_ttl_seconds,
        cache_max_hosts=settings.cache_max_hosts,
        cache_max_sites=settings.cache_max_sites,
    )
    try:
        return await get_unifi_placement_snapshot(client, registry, host)
    finally:
        await client.close()


async def preflight_snapshot_capabilities(host: str) -> dict[str, Any]:
    """Run the snapshot source capability probe (GET-only) with the server configuration."""
    settings = _settings_with_keys("preflight")

    client = UniFiClient(settings)
    registry = Registry(
        client,
        ttl_seconds=settings.cache_ttl_seconds,
        cache_max_hosts=settings.cache_max_hosts,
        cache_max_sites=settings.cache_max_sites,
    )
    try:
        return await preflight_placement_snapshot_capabilities(client, registry, host)
    finally:
        await client.close()


class SnapshotConfigError(RuntimeError):
    """A configuration problem the operator fixes in the deploy environment."""


def _settings_with_keys(what: str) -> Settings:
    """Load the server settings and require at least one API key.

    Every key value and label is validated by the settings themselves -- the same check
    the server runs at startup (:func:`unifi_fabric.config.credential_problem`): an
    empty, whitespace-only, whitespace-carrying, control-character or non-ASCII key, an
    empty label and one key under two labels each fail naming the variable or label,
    never the value. Raises :class:`SnapshotConfigError` when no key is configured.
    """
    settings = Settings()
    if not settings.get_key_configs():
        raise SnapshotConfigError(
            f"placement snapshot {what} requires an API key: set UNIFI_API_KEY, or "
            'UNIFI_API_KEYS to a JSON list of {"key": ..., "label": ...} objects'
        )
    return settings


def _secret_values() -> tuple[str, ...]:
    """Every configured secret (API keys, bearer token, TLS key password), best effort."""
    try:
        return configured_secrets(Settings())
    except Exception:  # noqa: BLE001 - unreadable config: the raw environment's secrets
        return configured_secrets()


def _failure_message(prefix: str, exc: BaseException) -> str:
    """One actionable stderr line for a failed run; it never contains an API key value.

    Configuration errors list each invalid setting and why (input values are never
    included); host-resolution errors carry the valid choices; upstream errors carry
    their request and status. Every configured secret, in any form (raw, escaped,
    base64), is replaced by ``***`` by the central scrubber.
    """
    if isinstance(exc, KeyboardInterrupt):
        return f"{prefix}: interrupted"
    if isinstance(exc, ValidationError):
        problems = "; ".join(
            f"{'.'.join(str(part) for part in err['loc']) or 'settings'}: {err['msg']}"
            for err in exc.errors(include_url=False, include_input=False)
        )
        detail = f"invalid configuration: {problems}"
    elif isinstance(exc, SettingsError):
        detail = f"invalid configuration: {exception_message(exc)}"
    elif isinstance(exc, SnapshotConfigError):
        detail = exception_message(exc)
    else:
        detail = f"{type(exc).__name__}: {exception_message(exc)}"
    return f"{prefix}: {scrub(detail, _secret_values())}"


class _SafeArgumentParser(argparse.ArgumentParser):
    """Never echo arbitrary CLI input into stderr diagnostics."""

    def error(self, message: str) -> NoReturn:
        del message
        self.print_usage(sys.stderr)
        self.exit(2, "invalid arguments\n")


def _parser(*, command: str, description: str) -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog=f"unifi-fabric-mcp {command}",
        description=description,
    )
    parser.add_argument(
        "--host",
        required=True,
        help="UniFi console name, ID, or composite ID; no implicit host default exists.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the explicit snapshot command and return a shell exit status.

    The only successful stdout output is one compact JSON document. A failure prints
    one actionable stderr line (see :func:`_failure_message`): an unknown host lists the
    valid choices, a missing or empty key is named by label, and no API key value is
    ever printed.
    """
    install_log_scrubber()
    args = _parser(
        command="placement-snapshot",
        description="Emit one bounded, read-only UniFi placement snapshot.",
    ).parse_args(argv)
    try:
        snapshot = asyncio.run(export_snapshot(args.host))
        encoded = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (Exception, KeyboardInterrupt) as exc:
        print(_failure_message("placement snapshot export failed", exc), file=sys.stderr)
        return 1
    print(encoded)
    return 0


def preflight_main(argv: Sequence[str] | None = None) -> int:
    """Emit a source capability report for a publisher scheduler gate.

    A completed probe with a non-``ok`` capability deliberately exits nonzero,
    so an automation cannot enable or run the snapshot publisher on a partial
    Fabric authorization grant. The report remains available on stdout: each
    capability's coarse ``outcome`` and, for a failed one, its complete ``error``
    text. No successful source response payload is included.
    """
    install_log_scrubber()
    args = _parser(
        command="placement-snapshot-preflight",
        description="Inspect required GET-only placement snapshot source capabilities.",
    ).parse_args(argv)
    try:
        report = asyncio.run(preflight_snapshot_capabilities(args.host))
        encoded = json.dumps(report, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (Exception, KeyboardInterrupt) as exc:
        print(
            _failure_message("placement snapshot capability preflight failed", exc),
            file=sys.stderr,
        )
        return 1
    print(encoded)
    return 0 if all(item["outcome"] == "ok" for item in report["capabilities"]) else 3
