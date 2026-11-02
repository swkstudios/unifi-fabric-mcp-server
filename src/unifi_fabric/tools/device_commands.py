"""Source-defined Classic Network commands; action requests are sent exactly once.

Payload sources: Art-of-WiFi UniFi API Client.php and the UniFi community API wiki.
No command downloads or reads backup file contents. The read commands (firmware and backup
listings, speed-test status) are the exact (route, command) pairs of
``read_post_routes.READ_COMMANDS`` and are sent through ``post_read``; every other command is
a write sent through ``client.post``.
"""

from __future__ import annotations

from typing import Any

from ..client import UniFiClient, UniFiConnectionError, is_dry_run_preview, validate_selector
from ..macs import is_mac
from ..read_post_routes import post_read
from ..refusal_audit import credential_values
from ..registry import Registry
from ..secret_scrub import request_secret_scope
from ..tool_annotations import READ_ONLY, WRITE
from ._classic_objects import checked_classic_response
from ._keys import with_context
from .device_mgmt import _colon_mac, _device_mac, _validate_device_ref

_COMMAND_CONSEQUENCES = {
    "force-provision": "Configuration is reapplied; clients may disconnect.",
    "devmgr/upgrade-all": "Fleet devices upgrade and reboot; clients may disconnect.",
    "devmgr/set-rollupgrade": "Selected device types upgrade and reboot in sequence.",
    "unset-rollupgrade": "Cancellation does not stop devices already upgrading or rebooting.",
    "migrate": "Devices move to another controller and may lose connectivity.",
    "adv-adopt": "SSH adoption changes device management and may interrupt connectivity.",
    "move-device": "Moving sites reprovisions the device and may disconnect clients.",
    "speedtest": "Speed testing consumes WAN bandwidth and can affect client throughput.",
}


# Network 11.0.97 answers HTTP 400 ``api.err.BackupFailed`` to ``{"cmd": "export-site"}`` on a
# console whose site export cannot be built, whatever the body: the same answer came back
# with extra ``days``, ``site`` and ``site_id`` fields, and ``{"cmd": "export-site"}`` is
# exactly what the web UI's Export Site button sends (swai and modal chunks, ``cmd/backup``).
_EXPORT_FAILED_HINT = (
    "The Network application refused to build the site export. The request sent, "
    '{"cmd": "export-site"} on cmd/backup, is the one the Network 11.0.97 web UI sends, and '
    "the console gave the same answer when extra body fields were added, so a different "
    "body will not help. Open the Network application log on the console around the "
    "request time for the cause, then retry."
)


def _command_url(host_id: str, slug: str, route: str) -> str:
    return f"/v1/connector/consoles/{host_id}/proxy/network/api/s/{slug}/cmd/{route}"


async def _read_command(
    client: UniFiClient, registry: Registry, host: str, site: str, route: str, command: str
) -> Any:
    """Send one Classic read command (``read_post_routes.READ_COMMANDS``), body verbatim."""
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    slug = await registry.resolve_site_slug(site, host_id, key=key)
    url = _command_url(host_id, slug, route)
    response = await post_read(client, url, key=key, json={"cmd": command})
    return checked_classic_response(response, url, client=client, key=key)


async def _command(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    route: str,
    body: Any,
    *,
    device_id: str | None = None,
    mac_field: str = "mac",
) -> Any:
    if device_id is not None:
        _validate_device_ref(device_id)
    key = await registry.resolve_key_for_host(host)
    host_id = await registry.resolve_host_id(host, key=key)
    slug = await registry.resolve_site_slug(site, host_id, key=key)
    if device_id is not None:
        site_id = await registry.resolve_site_id(site, host_id, key=key)
        mac = await _device_mac(client, host_id, site_id, device_id, key=key)
        body = {**body, mac_field: [mac] if mac_field == "macs" else mac}
    url = _command_url(host_id, slug, route)
    with request_secret_scope(credential_values(body)):
        response = checked_classic_response(
            await client.post(url, key=key, json=body), url, client=client, key=key
        )
    if is_dry_run_preview(response):
        consequence = _COMMAND_CONSEQUENCES.get(
            (body.get("cmd") or route) if isinstance(body, dict) else route
        )
        if consequence is not None:
            return with_context(response, {"_consequence": consequence})
    return response


async def provision_device(
    client: UniFiClient, registry: Registry, host: str, site: str, device_id: str
) -> Any:
    """Force provision an adopted device. Physical consequence: configuration is reapplied and
        clients may disconnect.

    Returns the upstream body verbatim. Sent once, never automatically retried.

    Consequence: reapplies device configuration and may disconnect clients.

        Args:
        host: Console name or id from list_hosts; for example my-console.
        site: Network site name or UUID from list_local_sites; for example Default.
        device_id: Adopted device UUID or MAC from list_site_devices; for example aa:bb:cc:dd:ee:ff.
    """
    return await _command(
        client,
        registry,
        host,
        site,
        "devmgr",
        {"cmd": "force-provision"},
        device_id=device_id,
        mac_field="macs",
    )


async def cancel_rolling_upgrade(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """Cancel the current rolling firmware upgrade. Devices already upgrading may continue and
        reboot.

    Returns the upstream body verbatim. Sent once, never automatically retried.

    Consequence: cancels queued upgrades; devices already upgrading may continue and reboot.

        Args:
        host: Console name or id from list_hosts; for example my-console.
        site: Network site name or UUID from list_local_sites; for example Default.
    """
    return await _command(client, registry, host, site, "devmgr", {"cmd": "unset-rollupgrade"})


async def list_device_firmware(
    client: UniFiClient, registry: Registry, host: str, site: str, cached: bool = False
) -> Any:
    """List available or cached device firmware through a controller command.

    A read: ``cmd/firmware`` ``list-available`` / ``list-cached`` is a listed read command,
    so UNIFI_READ_ONLY and UNIFI_DRY_RUN both send it once and return its result.
    Returns the upstream body verbatim. Commands are never automatically retried.

    Args:
        host: Console name or id from list_hosts; for example my-console.
        site: Network site name or UUID from list_local_sites; for example Default.

        cached: False lists available firmware; true lists cached firmware.
    """
    return await _read_command(
        client, registry, host, site, "firmware", "list-cached" if cached else "list-available"
    )


async def migrate_device(
    client: UniFiClient, registry: Registry, host: str, site: str, device_id: str, inform_url: str
) -> Any:
    """Migrate a device to another controller. Physical consequence: the device leaves
        controller management and may lose connectivity.

    Returns the upstream body verbatim. Sent once, never automatically retried.

    Consequence: moves management to another controller and may interrupt device connectivity.

        Args:
        host: Console name or id from list_hosts; for example my-console.
        site: Network site name or UUID from list_local_sites; for example Default.
        device_id: Adopted device UUID or MAC from list_site_devices.
        inform_url: Destination controller inform URL; for example
            http://controller.example:8080/inform.
    """
    return await _command(
        client,
        registry,
        host,
        site,
        "devmgr",
        {"cmd": "migrate", "inform_url": inform_url},
        device_id=device_id,
        mac_field="macs",
    )


async def advanced_adopt_device(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    mac: str,
    ip: str,
    username: str,
    password: str,
    inform_url: str,
    port: int = 22,
    ssh_key_verify: bool = True,
) -> Any:
    """Adopt a device through SSH. Physical consequence: controller management and device
        connectivity may change.

    Returns the upstream body verbatim. Sent once, never automatically retried.

    Consequence: uses SSH to change device management and may interrupt connectivity.

        Args:
        host: Console name or id from list_hosts; for example my-console.
        site: Network site name or UUID from list_local_sites; for example Default.
        mac: Unadopted device MAC; for example aa:bb:cc:dd:ee:ff.
        ip: Device SSH IP address; for example 192.0.2.10.
        username: Existing device SSH username.
        password: Existing device SSH password; transmitted to the controller for adoption.
        inform_url: Controller inform URL; for example http://controller.example:8080/inform.
        port: Device SSH port, default 22.
        ssh_key_verify: Whether the controller verifies the device SSH key; default true.
    """
    if not is_mac(mac):
        raise ValueError("mac must be a device MAC, for example aa:bb:cc:dd:ee:ff")
    mac = _colon_mac(mac)
    return await _command(
        client,
        registry,
        host,
        site,
        "devmgr",
        {
            "cmd": "adv-adopt",
            "mac": mac,
            "ip": ip,
            "username": username,
            "password": password,
            "url": inform_url,
            "port": port,
            "sshKeyVerify": ssh_key_verify,
        },
    )


async def run_speedtest(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """Run a gateway speed test. Physical consequence: test traffic consumes WAN bandwidth and
        may affect clients.

    Returns the upstream body verbatim. Sent once, never automatically retried.

    Consequence: consumes WAN bandwidth and may affect client throughput.

        Args:
        host: Console name or id from list_hosts; for example my-console.
        site: Network site name or UUID from list_local_sites; for example Default.
    """
    return await _command(client, registry, host, site, "devmgr", {"cmd": "speedtest"})


async def get_speedtest_status(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """Get gateway speed-test status through a controller command.

    A read: ``cmd/devmgr`` ``speedtest-status`` is a listed read command, so
    UNIFI_READ_ONLY and UNIFI_DRY_RUN both send it once and return its result.
    Returns the upstream body verbatim. Commands are never automatically retried.

    Args:
        host: Console name or id from list_hosts; for example my-console.
        site: Network site name or UUID from list_local_sites; for example Default.
    """
    return await _read_command(client, registry, host, site, "devmgr", "speedtest-status")


async def upgrade_all_devices(
    client: UniFiClient, registry: Registry, host: str, site: str, device_type: str = "uap"
) -> Any:
    """Upgrade every device of a family. Physical consequence: devices reboot and clients or
        downstream equipment lose connectivity.

    Returns the upstream body verbatim. Sent once, never automatically retried.

    Consequence: upgrades and reboots fleet devices, disconnecting their clients.

        Args:
        host: Console name or id from list_hosts; for example my-console.
        site: Network site name or UUID from list_local_sites; for example Default.
        device_type: Controller device family, documented values uap, usw, ugw; for example usw.
    """
    return await _command(client, registry, host, site, "devmgr/upgrade-all", {"type": device_type})


async def start_rolling_upgrade(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_types: list[str] | None = None,
) -> Any:
    """Start a rolling firmware upgrade. Physical consequence: devices reboot in sequence and
        clients may disconnect.

    Returns the upstream body verbatim. Sent once, never automatically retried.

    Consequence: upgrades and reboots selected device types in sequence.

        Args:
        host: Console name or id from list_hosts; for example my-console.
        site: Network site name or UUID from list_local_sites; for example Default.
        device_types: Complete family array, for example ["uap", "usw"]. When omitted sends
            ["uap", "usw", "ugw", "uxg"]. The whole supplied array is sent verbatim.
    """
    body = ["uap", "usw", "ugw", "uxg"] if device_types is None else device_types
    return await _command(client, registry, host, site, "devmgr/set-rollupgrade", body)


async def move_device_to_site(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device_id: str,
    destination_site_id: str,
) -> Any:
    """Move a device into another controller site. Physical consequence: destination
        configuration is provisioned and connectivity may be interrupted.

    Returns the upstream body verbatim. Sent once, never automatically retried.

    Consequence: moves and reprovisions the device in another site; clients may disconnect.

        Args:
        host: Console name or id from list_hosts; for example my-console.
        site: Network site name or UUID from list_local_sites; for example Default.
        device_id: Adopted device UUID or MAC from list_site_devices.
        destination_site_id: Destination Classic site _id from the controller self/sites
            endpoint, typically 24 hexadecimal characters. This is not an Integration UUID or
            site slug.
    """
    # Body-only value: only the server's own selector syntax is checked (non-empty, no
    # control character, no surrounding whitespace); the controller judges the rest.
    validate_selector(destination_site_id, "destination_site_id")
    return await _command(
        client,
        registry,
        host,
        site,
        "sitemgr",
        {"cmd": "move-device", "site": destination_site_id},
        device_id=device_id,
    )


async def list_backups(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """List backup metadata; never download or read backup file contents.

    A read: ``cmd/backup`` ``list-backups`` is a listed read command, so
    UNIFI_READ_ONLY and UNIFI_DRY_RUN both send it once and return its result.
    Returns the upstream body verbatim. Commands are never automatically retried.

    Args:
        host: Console name or id from list_hosts; for example my-console.
        site: Network site name or UUID from list_local_sites; for example Default.
    """
    return await _read_command(client, registry, host, site, "backup", "list-backups")


async def create_backup(
    client: UniFiClient, registry: Registry, host: str, site: str, days: int = -1
) -> Any:
    """Create a controller backup and return the controller's answer. Backups may contain
        secrets; this command never downloads a backup.

    Returns the upstream body verbatim: on Network 11.0.97 ``{"meta": {"rc": "ok"}, "data":
    [{"url": "/dl/backup/{version}.unf"}]}``, the console path of the backup file. The file is
    one transient export that the next backup overwrites; it is not a stored backup, so
    list_backups, cancel_controller_backup and delete_controller_backup never see it. Sent
    once, never automatically retried.

    Consequence: creates a controller backup without downloading its contents.

        Args:
        host: Console name or id from list_hosts; for example my-console.
        site: Network site name or UUID from list_local_sites; for example Default.
        days: Number of days for which the backup is generated; -1 is the source client default,
            forwarded unchanged.
    """
    return await _command(client, registry, host, site, "backup", {"cmd": "backup", "days": days})


async def export_site(client: UniFiClient, registry: Registry, host: str, site: str) -> Any:
    """Create a site export and return controller metadata. Exports may contain secrets; this
        command never downloads export contents.

    Returns the upstream body verbatim. Sent once, never automatically retried. A console that
    cannot build the export answers HTTP 400 api.err.BackupFailed; the error then names the
    next step.

    Consequence: prepares a site export without downloading its contents.

        Args:
        host: Console name or id from list_hosts; for example my-console.
        site: Network site name or UUID from list_local_sites; for example Default.
    """
    try:
        return await _command(client, registry, host, site, "backup", {"cmd": "export-site"})
    except UniFiConnectionError as exc:
        if "api.err.BackupFailed" not in str(exc):
            raise
        raise type(exc)(
            f"{exc} {_EXPORT_FAILED_HINT}", request_sent=exc.request_sent, status=exc.status
        ) from exc


_provision_device = provision_device

_cancel_rolling_upgrade = cancel_rolling_upgrade

_list_device_firmware = list_device_firmware

_migrate_device = migrate_device

_advanced_adopt_device = advanced_adopt_device

_run_speedtest = run_speedtest

_get_speedtest_status = get_speedtest_status

_upgrade_all_devices = upgrade_all_devices

_start_rolling_upgrade = start_rolling_upgrade

_move_device_to_site = move_device_to_site

_list_backups = list_backups

_create_backup = create_backup

_export_site = export_site


def register(mcp, deps_fn) -> None:
    """Register Classic commands; a read command is an exact (route, command) pair of
    ``read_post_routes.READ_COMMANDS`` and its tool is a read tool; every other command
    tool is a write tool."""

    @mcp.tool(annotations=WRITE)
    async def provision_device(host: str, site: str, device_id: str) -> Any:
        """Force provision an adopted device. Consequence: configuration is reapplied
            and clients may disconnect.

        Returns the upstream body verbatim. Never automatically retried. UNIFI_DRY_RUN sends no
        write; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#provision_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC from list_site_devices; not a Protect id.
        """
        client, registry = deps_fn()
        return await _provision_device(client, registry, host, site, device_id)

    @mcp.tool(annotations=WRITE)
    async def cancel_rolling_upgrade(host: str, site: str) -> Any:
        """Cancel the current rolling firmware upgrade. Consequence: devices already upgrading
            may continue and reboot.

        Returns the upstream body verbatim. Never automatically retried. UNIFI_DRY_RUN sends no
        write; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#cancel_rolling_upgrade.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
        """
        client, registry = deps_fn()
        return await _cancel_rolling_upgrade(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def list_device_firmware(host: str, site: str, cached: bool = False) -> Any:
        """List available or cached device firmware through a controller command.

        A read: it only reports firmware and upgrades nothing. Sends Classic POST
        api/s/{site}/cmd/firmware with exactly {"cmd": "list-available"}, or
        {"cmd": "list-cached"} when cached is true. UNIFI_READ_ONLY and UNIFI_DRY_RUN both
        send it and return its result.

        Returns the upstream body verbatim. Sent once, never automatically retried.

        Example: docs/TOOL-USAGE.md#list_device_firmware.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            cached: False lists available firmware; true lists cached firmware.
        """
        client, registry = deps_fn()
        return await _list_device_firmware(client, registry, host, site, cached)

    @mcp.tool(annotations=WRITE)
    async def migrate_device(host: str, site: str, device_id: str, inform_url: str) -> Any:
        """Migrate a device to another controller. Consequence: the device leaves
            controller management and may lose connectivity.

        Returns the upstream body verbatim. Never automatically retried. UNIFI_DRY_RUN sends no
        write; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#migrate_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC from list_site_devices; not a Protect id.
            inform_url: Destination controller inform URL; for example
                http://controller.example:8080/inform.
        """
        client, registry = deps_fn()
        return await _migrate_device(client, registry, host, site, device_id, inform_url)

    @mcp.tool(annotations=WRITE)
    async def advanced_adopt_device(
        host: str,
        site: str,
        mac: str,
        ip: str,
        username: str,
        password: str,
        inform_url: str,
        port: int = 22,
        ssh_key_verify: bool = True,
    ) -> Any:
        """Adopt a device through SSH. Consequence: controller management and device
            connectivity may change.

        Returns the upstream body verbatim. Never automatically retried. UNIFI_DRY_RUN sends no
        write; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#advanced_adopt_device.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            mac: Unadopted device MAC; for example aa:bb:cc:dd:ee:ff.
            ip: Device SSH IP address; for example 192.0.2.10.
            username: Existing device SSH username.
            password: Existing device SSH password; transmitted to the controller for adoption.
            inform_url: Controller inform URL; for example http://controller.example:8080/inform.
            port: Device SSH port, default 22.
            ssh_key_verify: Whether the controller verifies the device SSH key; default true.
        """
        client, registry = deps_fn()
        return await _advanced_adopt_device(
            client,
            registry,
            host,
            site,
            mac,
            ip,
            username,
            password,
            inform_url,
            port,
            ssh_key_verify,
        )

    @mcp.tool(annotations=WRITE)
    async def run_speedtest(host: str, site: str) -> Any:
        """Run a gateway speed test. Consequence: test traffic consumes WAN bandwidth
            and may affect clients.

        Returns the upstream body verbatim. Never automatically retried. UNIFI_DRY_RUN sends no
        write; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#run_speedtest.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
        """
        client, registry = deps_fn()
        return await _run_speedtest(client, registry, host, site)

    @mcp.tool(annotations=READ_ONLY)
    async def get_speedtest_status(host: str, site: str) -> Any:
        """Get gateway speed-test status through a controller command.

        A read: it only reports status and starts no test (run_speedtest starts one).
        Sends Classic POST api/s/{site}/cmd/devmgr with exactly {"cmd": "speedtest-status"}.
        UNIFI_READ_ONLY and UNIFI_DRY_RUN both send it and return its result.

        Returns the upstream body verbatim. Sent once, never automatically retried.

        Example: docs/TOOL-USAGE.md#get_speedtest_status.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
        """
        client, registry = deps_fn()
        return await _get_speedtest_status(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def upgrade_all_devices(host: str, site: str, device_type: str = "uap") -> Any:
        """Upgrade every device of a family. Consequence: devices reboot and clients or
            downstream equipment lose connectivity.

        Returns the upstream body verbatim. Never automatically retried. UNIFI_DRY_RUN sends no
        write; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#upgrade_all_devices.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_type: Controller device family, documented values uap, usw, ugw; for example usw.
        """
        client, registry = deps_fn()
        return await _upgrade_all_devices(client, registry, host, site, device_type)

    @mcp.tool(annotations=WRITE)
    async def start_rolling_upgrade(
        host: str, site: str, device_types: list[str] | None = None
    ) -> Any:
        """Start a rolling firmware upgrade. Consequence: devices reboot in sequence
            and clients may disconnect.

        Returns the upstream body verbatim. Never automatically retried. UNIFI_DRY_RUN sends no
        write; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#start_rolling_upgrade.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_types: Complete family array, for example ["uap", "usw"]. When omitted sends
                ["uap", "usw", "ugw", "uxg"]. The whole supplied array is sent verbatim.
                Shape: string[]
        """
        client, registry = deps_fn()
        return await _start_rolling_upgrade(client, registry, host, site, device_types)

    @mcp.tool(annotations=WRITE)
    async def move_device_to_site(
        host: str, site: str, device_id: str, destination_site_id: str
    ) -> Any:
        """Move a device into another controller site. Consequence: destination
            configuration is provisioned and connectivity may be interrupted.

        Returns the upstream body verbatim. Never automatically retried. UNIFI_DRY_RUN sends no
        write; returns {status: "dry_run", dryRun: true, sent: false, message, preview: {method,
        path, params, body}, _consequence}.

        Example: docs/TOOL-USAGE.md#move_device_to_site.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            device_id: Adopted Network device UUID or MAC from list_site_devices; not a Protect id.
            destination_site_id: Destination Classic site _id from the controller self/sites
                endpoint, typically 24 hexadecimal characters. This is not an Integration UUID
                or site slug.
        """
        client, registry = deps_fn()
        return await _move_device_to_site(
            client, registry, host, site, device_id, destination_site_id
        )

    @mcp.tool(annotations=READ_ONLY)
    async def list_backups(host: str, site: str) -> Any:
        """List backup metadata; never download or read backup file contents.

        A read: it only reads backup metadata. Sends Classic POST api/s/{site}/cmd/backup
        with exactly {"cmd": "list-backups"}. UNIFI_READ_ONLY and UNIFI_DRY_RUN both send it
        and return its result.

        Returns the upstream body verbatim. Sent once, never automatically retried.

        Example: docs/TOOL-USAGE.md#list_backups.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
        """
        client, registry = deps_fn()
        return await _list_backups(client, registry, host, site)

    @mcp.tool(annotations=WRITE)
    async def create_backup(host: str, site: str, days: int = -1) -> Any:
        """Create a controller backup and return the controller's answer. Backups may contain
            secrets; this command never downloads a backup.

        Returns the upstream body verbatim: on Network 11.0.97 {"meta": {"rc": "ok"}, "data":
        [{"url": "/dl/backup/{version}.unf"}]}, the console path of the backup file. The file is
        one transient export that the next backup overwrites; it is not a stored backup, so
        list_backups, cancel_controller_backup and delete_controller_backup never see it. Never
        automatically retried. UNIFI_DRY_RUN sends no write; returns {status: "dry_run", dryRun:
        true, sent: false, message, preview: {method, path, params, body}}.

        Example: docs/TOOL-USAGE.md#create_backup.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
            days: Number of days for which the backup is generated; -1 is the source client
                default, forwarded unchanged.
        """
        client, registry = deps_fn()
        return await _create_backup(client, registry, host, site, days)

    @mcp.tool(annotations=WRITE)
    async def export_site(host: str, site: str) -> Any:
        """Create a site export and return controller metadata. Exports may contain secrets;
            this command never downloads export contents.

        Consequence: the controller prepares a site export file (Classic cmd/backup
        export-site); site configuration is unchanged and the contents are not downloaded.

        Returns the upstream body verbatim. Never automatically retried. A console that cannot
        build the export answers HTTP 400 api.err.BackupFailed, whatever the body; the error
        names the next step. UNIFI_DRY_RUN sends no write; returns {status: "dry_run", dryRun:
        true, sent: false, message, preview: {method, path, params, body}}.

        Example: docs/TOOL-USAGE.md#export_site.

        Args:
            host: Console name or id from list_hosts.
            site: Network site name or UUID from list_local_sites.
        """
        client, registry = deps_fn()
        return await _export_site(client, registry, host, site)
