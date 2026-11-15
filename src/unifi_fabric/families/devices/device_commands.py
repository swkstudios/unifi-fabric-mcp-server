"""Source-defined Classic Network commands; action requests are sent exactly once.

Payload sources: Art-of-WiFi UniFi API Client.php and the UniFi community API wiki.
No command downloads or reads backup file contents. The read commands (firmware and backup
listings, speed-test status) are the exact (route, command) pairs of
``read_post_routes.READ_COMMANDS`` and are sent through ``post_read``; every other command is
a write sent through ``client.post``.
"""

from __future__ import annotations

from typing import Any

from ...client import (
    UniFiClient,
    UniFiConnectionError,
    is_dry_run_preview,
    validate_selector,
)
from ...macs import is_mac
from ...read_post_routes import post_read
from ...refusal_audit import credential_values
from ...registry import Registry
from ...secret_scrub import request_secret_scope
from ...shared_shapes._classic_objects import checked_classic_response
from ...shared_shapes._keys import with_context
from .device_mgmt import _colon_mac, _device_mac, _validate_device_ref
from .schemas import (  # the family's shapes (family-owned layout)
    _COMMAND_CONSEQUENCES,
    _EXPORT_FAILED_HINT,
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
    so UNIFI_WRITE_POLICY=deny and dry-run policy both send it once and return its result.
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
    UNIFI_WRITE_POLICY=deny and dry-run policy both send it once and return its result.
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
            site slug. Read it with fabric_connector_get, path "network/api/self/sites"
            (data[]._id).
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
    UNIFI_WRITE_POLICY=deny and dry-run policy both send it once and return its result.
    Returns the upstream body verbatim. Commands are never automatically retried.

    Args:
        host: Console name or id from list_hosts; for example my-console.
        site: Network site name or UUID from list_local_sites; for example Default.
    """
    return await _read_command(client, registry, host, site, "backup", "list-backups")


async def create_backup(
    client: UniFiClient, registry: Registry, host: str, site: str, days: int = -1
) -> Any:
    """Generate a one-off controller backup file and return its console download path; no
        stored backup is added. Backups may contain secrets; this command never downloads one.

    Returns the upstream body verbatim: on Network 11.0.97 ``{"meta": {"rc": "ok"}, "data":
    [{"url": "/dl/backup/{version}.unf"}]}``, the console path of the backup file. The file is
    one transient export that the next backup overwrites; it is not a stored backup, so
    list_backups, cancel_controller_backup and delete_controller_backup never see it, and the
    answer carries no filename or backup_id. Sent once, never automatically retried.

    Consequence: writes one transient backup file on the console, replacing the previous one;
    no stored backup is added and nothing is downloaded.

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
