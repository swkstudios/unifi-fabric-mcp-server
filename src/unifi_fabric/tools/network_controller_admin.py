"""Network controller administration: backups, remote access, SSO, support, firmware.

None of these capabilities is in the published Network Integration API, except the
firmware-update flags :func:`get_latest_firmware_versions` reads (the official
Integration ``devices[].firmwareUpdatable`` and the Site Manager ``GET /v1/devices``
``devices[].{version, firmwareStatus, updateAvailable}``). Everything else uses the
controller's own web-UI routes, taken from the Network 11.0.81 private-API inventory
(``tests/fixtures/private_api/inventory_network_11.0.81.json``, built from the public
11.0.81 front-end bundles), with v2 preferred over Classic where both exist:

* Classic command managers (``POST /proxy/network/api/s/{site}/cmd/<manager>`` with
  ``{"cmd": ...}``) go through :mod:`._classic_cmd`, so success is HTTP 2xx AND
  ``meta.rc == "ok"`` and a rejection raises with the complete upstream body.
* Body keys are the keys the bundle sends for that command (cited per tool). Where the
  bundle builds the body at runtime the tool takes a free-form ``body`` object that is
  sent as given; no key is invented and no key is required locally.
* Every POST here is a write (none is on the read-POST allowlist): ``UNIFI_READ_ONLY``
  refuses it and ``UNIFI_DRY_RUN`` returns the client's dry-run preview. No POST is ever
  retried automatically.
* Credentials (SMTP, Ubiquiti account and SSO passwords, 2FA tokens, MFA cookies, admin
  passwords, TURN credentials) are listed in :data:`unifi_fabric.route_secrets.ROUTE_SECRETS`:
  they are always scrubbed from logs and the audit log, and masked in errors and results
  only when the operator opts in with ``UNIFI_REDACT_SECRETS``.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Any, Literal, cast

from fastmcp import FastMCP

from ..client import (
    UniFiClient,
    UniFiConnectionError,
    decode_body,
    describe_shape,
    is_dry_run_preview,
    path_segment,
    upstream_error_text,
)
from ..config import APIKeyConfig
from ..macs import colon_mac, is_mac, record_mac
from ..redaction import drop_and_note_masked_fields
from ..registry import Registry
from ..selector_args import check_selector
from ..tool_annotations import READ_ONLY, WRITE
from ..write_body import IDENTITY_FIELDS, require_unmasked_fields, require_update_fields
from . import device_mgmt, site_manager
from ._classic_cmd import (
    ClassicCommandError,
    classic_command,
    classic_command_body,
    classic_rc_failure,
)
from ._classic_objects import resolve_site_slug, v2_root, v2_site
from ._keys import context_value, update_context, with_context
from ._results import deletion_result, requested_leaves_verdict, safe_read_after

_CONSOLE = "/v1/connector/consoles/{host_id}/proxy/network"

CLOUD_ACCESS_ACTIONS = ("register", "unregister")
FIRMWARE_CACHE_ACTIONS = ("download", "remove")

ParamValue = str | int | float | bool


# --------------------------------------------------------------------------- helpers


def _choice(value: Any, name: str, choices: tuple[str, ...]) -> str:
    """``value`` when it is one of the tool's own ``choices`` (each names one command)."""
    if value not in choices:
        raise ValueError(f"'{name}' must be one of {', '.join(choices)}; got {value!r}")
    return cast(str, value)


def _mac(value: Any, name: str = "mac") -> str:
    """A caller's device MAC in the controller's lowercase colon form."""
    if not is_mac(value):
        raise ValueError(
            f"'{name}' must be a MAC address such as '02:00:5e:00:00:a1'; got {value!r}"
        )
    return colon_mac(cast(str, value))


def _given(**values: Any) -> dict[str, Any]:
    """The body keys the caller gave (an omitted argument is not sent)."""
    return {key: value for key, value in values.items() if value is not None}


async def _site(registry: Registry, host: str, site: str) -> tuple[APIKeyConfig | None, str, str]:
    check_selector("host", host)
    check_selector("site", site)
    return await resolve_site_slug(registry, host, site)


async def _host(registry: Registry, host: str) -> tuple[APIKeyConfig | None, str]:
    check_selector("host", host)
    key = await registry.resolve_key_for_host(host)
    return key, await registry.resolve_host_id(host, key=key)


async def _command(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    manager: str,
    cmd: str,
    params: dict[str, Any],
    *,
    allow_empty_success: bool = False,
) -> Any:
    """Validate every input, resolve the site, then run one Classic command."""
    check_selector("host", host)
    check_selector("site", site)
    classic_command_body(cmd, params)
    key, host_id, slug = await resolve_site_slug(registry, host, site)
    return await classic_command(
        client,
        host_id,
        slug,
        manager,
        cmd,
        params,
        key=key,
        allow_empty_success=allow_empty_success,
    )


async def _classic_post(
    client: UniFiClient, key: APIKeyConfig | None, path: str, body: dict[str, Any]
) -> Any:
    """POST a Classic body that is not a ``cmd/<manager>`` route; require ``meta.rc == ok``."""
    resp = await client.request("POST", path, key=key, json=body)
    decoded = decode_body(resp)
    if is_dry_run_preview(decoded):
        return decoded
    reason = classic_rc_failure(resp.status_code, decoded)
    if reason is not None:
        text = upstream_error_text(resp.text, client)
        raise ClassicCommandError(
            f"Classic command error from POST {path} (cmd {body.get('cmd')!r}): {reason}: {text}"
        )
    return decoded


def _rows(body: Any, path: str) -> list[dict[str, Any]]:
    """The object rows of a Classic ``{meta, data: [...]}`` body or a bare array."""
    rows = body.get("data") if isinstance(body, dict) else body
    if not isinstance(rows, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected a JSON array or an object "
            f"with a 'data' array, got {describe_shape(body)}"
        )
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise UniFiConnectionError(
                f"Unexpected response shape from GET {path}: row {index} expected an object, "
                f"got {describe_shape(row)}"
            )
    return rows


async def _device_mac(
    client: UniFiClient, key: APIKeyConfig | None, host_id: str, slug: str, mac: str
) -> str:
    """``mac`` when a device of the site's ``stat/device-basic`` list carries it."""
    path = _CONSOLE.format(host_id=host_id) + f"/api/s/{slug}/stat/device-basic"
    rows = _rows(await client.get(path, key=key), path)
    known = {found for row in rows if (found := record_mac(row.get("mac"))) is not None}
    if mac.replace(":", "") in known:
        return mac
    raise ValueError(
        f"Unknown device MAC {mac!r} on site {slug!r}; valid: "
        f"{', '.join(sorted(colon_mac(m) for m in known)) or '(none)'}"
    )


def _merge(current: Any, changes: Any) -> Any:
    """Recursively merge only the requested leaves into the current upstream value."""
    if not isinstance(current, dict) or not isinstance(changes, dict):
        return changes
    merged = dict(current)
    for key, value in changes.items():
        merged[key] = _merge(merged.get(key), value)
    return merged


def _update_body(tool: str, value: Any, name: str) -> dict[str, Any]:
    """The requested update leaves (masked and identity fields dropped), or raise."""
    clean = require_update_fields(drop_and_note_masked_fields(value), f"{tool} {name}")
    return {key: item for key, item in clean.items() if key not in IDENTITY_FIELDS}


def _verified(response: Any, verified: bool | None, error: str | None) -> Any:
    """The write response verbatim plus ``_verified`` (and ``_readAfterError`` on failure).

    A non-object write body is kept whole under ``response`` so the verdict keys are never dropped.
    """
    if not isinstance(response, dict):
        response = {"response": response}
    additions: dict[str, Any] = {"_verified": verified}
    if error is not None:
        additions["_readAfterError"] = error
    return with_context(response, additions)


# --------------------------------------------------------------------------- backups


async def cancel_controller_backup(
    client: UniFiClient, registry: Registry, host: str, site: str, backup_id: str
) -> Any:
    """``cmd/backup`` ``cancel-backup`` with ``backup_id`` (bundle 52695.js:2003)."""
    return await _command(
        client, registry, host, site, "backup", "cancel-backup", {"backup_id": backup_id}
    )


async def delete_controller_backup(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    filename: str,
    device_id: str | None = None,
) -> Any:
    """``cmd/backup`` ``delete-backup`` with ``filename`` (and ``device_id`` when given)."""
    params = {"filename": filename, **_given(device_id=device_id)}
    response = await _command(
        client,
        registry,
        host,
        site,
        "backup",
        "delete-backup",
        params,
        allow_empty_success=True,
    )
    return deletion_result(f"Backup {filename} deleted.", response)


async def restore_controller_backup(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    filename: str | None = None,
    body: dict[str, Any] | None = None,
) -> Any:
    """Optionally ``choose-backup`` ``{filename}``, then ``restore`` with ``body``."""
    restore = dict(body or {})
    classic_command_body("restore", restore)
    choose = {"filename": filename} if filename is not None else None
    if choose is not None:
        classic_command_body("choose-backup", choose)
    key, host_id, slug = await _site(registry, host, site)
    chosen = None
    if choose is not None:
        chosen = await classic_command(
            client, host_id, slug, "backup", "choose-backup", choose, key=key
        )
    result = await classic_command(client, host_id, slug, "backup", "restore", restore, key=key)
    if chosen is not None and isinstance(result, dict):
        return with_context(result, {"_chooseBackup": chosen})
    return result


async def import_site_configuration(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    backup_id: str,
    site_desc: str,
) -> Any:
    """``cmd/backup`` ``import-site`` with ``backup_id`` and ``site_desc`` (swai.js)."""
    params = {"backup_id": backup_id, "site_desc": site_desc}
    return await _command(client, registry, host, site, "backup", "import-site", params)


# --------------------------------------------------------------------------- notifications


async def send_test_email(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    email: str,
    smtp_host: str | None = None,
    port: int | None = None,
    sender: str | None = None,
    use_auth: bool | None = None,
    use_sender: bool | None = None,
    use_ssl: bool | None = None,
    username: str | None = None,
    x_password: str | None = None,
) -> Any:
    """``cmd/cfgmgr`` ``test_mail`` with the SMTP form keys the caller gave."""
    params = {
        "email": email,
        **_given(
            host=smtp_host,
            port=port,
            sender=sender,
            use_auth=use_auth,
            use_sender=use_sender,
            use_ssl=use_ssl,
            username=username,
            x_password=x_password,
        ),
    }
    return await _command(client, registry, host, site, "cfgmgr", "test_mail", params)


# --------------------------------------------------------------------------- remote access


async def get_remote_access_turn_credentials(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """``cmd/cloudaccess`` ``get-turn-credentials``; the credentials come back verbatim."""
    return await _command(client, registry, host, site, "cloudaccess", "get-turn-credentials", {})


async def set_cloud_access_registration(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    action: str,
    ubic_username: str | None = None,
    ubic_password: str | None = None,
    ubic_2fa_token: str | None = None,
    mfa_cookie: str | None = None,
    poll_login: bool | None = None,
) -> Any:
    """``cmd/cloudaccess`` ``register`` (account keys given) or ``unregister``."""
    cmd = _choice(action, "action", CLOUD_ACCESS_ACTIONS)
    params = _given(
        ubic_username=ubic_username,
        ubic_password=ubic_password,
        ubic_2fa_token=ubic_2fa_token,
        mfa_cookie=mfa_cookie,
        poll_login=poll_login,
    )
    return await _command(client, registry, host, site, "cloudaccess", cmd, params)


# --------------------------------------------------------------------------- SSO and self


async def refresh_sso_session(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    sso_username: str | None = None,
    sso_password: str | None = None,
    sso_2fa_token: str | None = None,
    mfa_cookie: str | None = None,
    poll_login: bool | None = None,
) -> Any:
    """``cmd/productinfo/refresh-sso`` ``refresh-sso`` with the keys the caller gave."""
    params = _given(
        sso_username=sso_username,
        sso_password=sso_password,
        sso_2fa_token=sso_2fa_token,
        mfa_cookie=mfa_cookie,
        poll_login=poll_login,
    )
    return await _command(
        client, registry, host, site, "productinfo/refresh-sso", "refresh-sso", params
    )


async def link_ubiquiti_sso_account(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    command: str,
    ubic_username: str | None = None,
    x_ubic_password: str | None = None,
    ubic_2fa_token: str | None = None,
    mfa_cookie: str | None = None,
    poll_login: bool | None = None,
) -> Any:
    """POST ``api/s/{site}/self/ubic_sso`` ``{"cmd": command, ...}`` (swai.js:2726631)."""
    params = _given(
        ubic_username=ubic_username,
        x_ubic_password=x_ubic_password,
        ubic_2fa_token=ubic_2fa_token,
        mfa_cookie=mfa_cookie,
        poll_login=poll_login,
    )
    body = classic_command_body(command, params)
    key, host_id, slug = await _site(registry, host, site)
    path = _CONSOLE.format(host_id=host_id) + f"/api/s/{slug}/self/ubic_sso"
    return await _classic_post(client, key, path, body)


async def update_my_admin_profile(
    client: UniFiClient, registry: Registry, host: str, profile: dict[str, Any]
) -> Any:
    """Read ``GET api/self``, merge ``profile`` leaves into it, PUT them and verify."""
    changes = _update_body("update_my_admin_profile", profile, "profile")
    key, host_id = await _host(registry, host)
    path = _CONSOLE.format(host_id=host_id) + "/api/self"

    async def read() -> dict[str, Any]:
        body = await client.get(path, key=key)
        rows = [body] if isinstance(body, dict) and "data" not in body else _rows(body, path)
        if len(rows) != 1:
            raise UniFiConnectionError(
                f"GET {path} returned {len(rows)} admin records; expected exactly one (the "
                "calling admin)"
            )
        return rows[0]

    current = await read()
    sent = {name: _merge(current.get(name), value) for name, value in changes.items()}
    response = await client.put(path, key=key, json=sent)
    if is_dry_run_preview(response):
        return response
    after, error = await safe_read_after(read)
    verified, error = requested_leaves_verdict(changes, after, error)
    return _verified(response, verified, error)


async def resend_mfa_code(
    client: UniFiClient,
    registry: Registry,
    host: str,
    mfa_type: str,
    mfa_id: str,
    body: dict[str, Any] | None = None,
) -> Any:
    """POST ``v2/api/mfa/{mfa_type}/{mfa_id}/send`` ``{"cmd": "resend-mfa-code", ...}``."""
    first = path_segment(mfa_type, "mfa_type")
    second = path_segment(mfa_id, "mfa_id")
    payload = classic_command_body("resend-mfa-code", dict(body or {}))
    key, host_id = await _host(registry, host)
    return await client.post(v2_root(host_id, f"/mfa/{first}/{second}/send"), key=key, json=payload)


# --------------------------------------------------------------------------- system


async def set_controller_system_parameter(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    key: str,
    value: ParamValue,
) -> Any:
    """``cmd/system`` ``set-param`` with ``key`` and ``value`` (settings-system-general.js)."""
    params = {"key": key, "value": value}
    return await _command(client, registry, host, site, "system", "set-param", params)


async def generate_support_file(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    mac: str,
    body: dict[str, Any] | None = None,
) -> Any:
    """POST ``v2/api/site/{site}/support/{mac}/generation`` with ``body`` as given."""
    device = _mac(mac)
    require_unmasked_fields(body, "generate_support_file body")
    key, host_id, slug = await _site(registry, host, site)
    await _device_mac(client, key, host_id, slug, device)
    return await client.post(
        v2_site(host_id, slug, f"/support/{device}/generation"), key=key, json=dict(body or {})
    )


async def get_support_file(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    mac: str,
    download: bool = False,
) -> Any:
    """GET ``support/{mac}`` (status) or ``support/{mac}/download`` (file, base64)."""
    device = _mac(mac)
    key, host_id, slug = await _site(registry, host, site)
    path = v2_site(host_id, slug, f"/support/{device}")
    if not download:
        return await client.get(path, key=key)
    raw, content_type = await client.get_binary(path + "/download", key=key)
    return {
        "content_base64": base64.b64encode(raw).decode(),
        "contentType": content_type,
        "sizeBytes": len(raw),
    }


# --------------------------------------------------------------------------- firmware


async def check_controller_firmware_update(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    """``cmd/productinfo`` ``check-firmware-update`` (modal-root.js:24051)."""
    return await _command(client, registry, host, site, "productinfo", "check-firmware-update", {})


async def manage_firmware_cache(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    action: str,
    device: str,
    version: str,
) -> Any:
    """``cmd/firmware`` ``download`` / ``remove`` with ``device`` and ``version``."""
    cmd = _choice(action, "action", FIRMWARE_CACHE_ACTIONS)
    params = {"device": device, "version": version}
    return await _command(client, registry, host, site, "firmware", cmd, params)


async def get_latest_firmware_versions(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    filter: str | None = None,
    time: str | None = None,
) -> Any:
    """The official firmware-update view of one site's devices, from two sources.

    The result is the drained Integration device list of the site, verbatim
    (``data[].firmwareVersion``, ``data[].firmwareUpdatable``; ``filter`` forwarded), plus
    the additive ``_siteManagerDevices``: ``list_devices(host=..., time=...)`` (each console
    wrapper's ``devices[].version``, ``firmwareStatus``, ``updateAvailable``), verbatim.
    ``incomplete`` / ``incompleteReason`` are set when either drain stopped short.
    """
    check_selector("host", host)
    check_selector("site", site)
    integration = await device_mgmt._list_site_devices(client, registry, host, site, filter=filter)
    managed = await site_manager.list_devices(client, registry, host=host, time=time)
    if not isinstance(integration, dict):
        return integration
    result = with_context(integration, {"_siteManagerDevices": managed})
    if isinstance(managed, dict) and context_value(managed, "incomplete"):
        reasons = [
            f"{label}: {context_value(body, 'incompleteReason')}"
            for label, body in (("Integration devices", integration), ("Site Manager", managed))
            if context_value(body, "incomplete")
        ]
        # The combined marker replaces the server's own earlier one, never an upstream
        # field of the same name (that keeps its value; the marker goes in _wrapperFields).
        result = update_context(
            result, {"incomplete": True, "incompleteReason": "; ".join(reasons)}
        )
    return result


# --------------------------------------------------------------------------- registration


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the 17 Network controller administration tools."""

    def deps() -> tuple[UniFiClient, Registry]:
        return cast(tuple[UniFiClient, Registry], deps_fn())

    @mcp.tool(name="cancel_controller_backup", annotations=WRITE)
    async def cancel_controller_backup_tool(host: str, site: str, backup_id: str) -> Any:
        """Cancel a running controller backup (Classic cmd/backup cancel-backup).

        Required arguments: host, site, backup_id.

        POST /proxy/network/api/s/{site}/cmd/backup {"cmd": "cancel-backup", "backup_id"}.
        Consequence: the running backup stops and leaves no backup file.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            backup_id: Id of the running backup the controller reported, e.g.
                "65f1c0ffee0123456789abcd".
        """
        return await cancel_controller_backup(*deps(), host, site, backup_id)

    @mcp.tool(name="delete_controller_backup", annotations=WRITE)
    async def delete_controller_backup_tool(
        host: str, site: str, filename: str, device_id: str | None = None
    ) -> Any:
        """Delete a stored controller backup file (Classic cmd/backup delete-backup).

        Required arguments: host, site, filename.

        POST /proxy/network/api/s/{site}/cmd/backup {"cmd": "delete-backup", "filename",
        "device_id" when given}. Consequence: the backup file is removed permanently and
        cannot be restored afterwards.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns {deleted, message, response}: deleted is true, message summarizes the delete, and
        response is the upstream body verbatim (decoded JSON, raw text, or null when the body is
        empty).

        Under UNIFI_DRY_RUN nothing is sent and the tool returns {status: "dry_run",
        deleted: false, message, response}, where response is the dry-run preview (status,
        dryRun, sent: false, message and preview with method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            filename: Backup file name as the controller lists it, e.g.
                "autobackup_11.0.81_20261001_0000_1759276800000.unf".
            device_id: Optional console device id the backup belongs to, e.g.
                "65f1c0ffee0123456789abcd".
        """
        return await delete_controller_backup(*deps(), host, site, filename, device_id)

    @mcp.tool(name="restore_controller_backup", annotations=WRITE)
    async def restore_controller_backup_tool(
        host: str, site: str, filename: str | None = None, body: dict[str, Any] | None = None
    ) -> Any:
        """Restore the Network application from a backup (Classic cmd/backup restore).

        Required arguments: host, site.

        With filename, first POST cmd/backup {"cmd": "choose-backup", "filename"} (the
        controller's backup-selection step; its body is returned under _chooseBackup),
        then POST cmd/backup {"cmd": "restore", **body}. The 11.0.81 front end builds the
        restore body at runtime, so body is free-form and sent as given. Consequence:
        replaces the controller's whole configuration with the backup and restarts the
        Network application; clients and devices may disconnect.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            filename: Optional backup file to select first, e.g.
                "autobackup_11.0.81_20261001_0000_1759276800000.unf".
            body: Optional free-form restore body (never "cmd"), e.g. {}.
        """
        return await restore_controller_backup(*deps(), host, site, filename, body)

    @mcp.tool(name="import_site_configuration", annotations=WRITE)
    async def import_site_configuration_tool(
        host: str, site: str, backup_id: str, site_desc: str
    ) -> Any:
        """Import an exported site into the controller (Classic cmd/backup import-site).

        Required arguments: host, site, backup_id, site_desc.

        POST /proxy/network/api/s/{site}/cmd/backup {"cmd": "import-site", "backup_id",
        "site_desc"}. Consequence: creates a site from the export and may adopt its
        devices.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            backup_id: Id of the uploaded site export, e.g. "65f1c0ffee0123456789abcd".
            site_desc: Name for the imported site, e.g. "Branch Office".
        """
        return await import_site_configuration(*deps(), host, site, backup_id, site_desc)

    @mcp.tool(name="send_test_email", annotations=WRITE)
    async def send_test_email_tool(
        host: str,
        site: str,
        email: str,
        smtp_host: str | None = None,
        port: int | None = None,
        sender: str | None = None,
        use_auth: bool | None = None,
        use_sender: bool | None = None,
        use_ssl: bool | None = None,
        username: str | None = None,
        x_password: str | None = None,
    ) -> Any:
        """Send a test email through SMTP settings (Classic cmd/cfgmgr test_mail).

        Required arguments: host, site, email.

        POST /proxy/network/api/s/{site}/cmd/cfgmgr {"cmd": "test_mail", "email", and the
        SMTP keys given: host (smtp_host), port, sender, use_auth, use_sender, use_ssl,
        username, x_password}. x_password is a credential: scrubbed from logs, and from
        errors only under UNIFI_REDACT_SECRETS.
        Consequence: the controller sends one email.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            email: Recipient address, e.g. "admin@example.com".
            smtp_host: Optional SMTP server (sent as host), e.g. "smtp.example.com".
            port: Optional SMTP port, e.g. 587.
            sender: Optional From address, e.g. "unifi@example.com".
            use_auth: Optional SMTP authentication flag, e.g. true.
            use_sender: Optional use-sender flag, e.g. true.
            use_ssl: Optional TLS flag, e.g. true.
            username: Optional SMTP user, e.g. "unifi@example.com".
            x_password: Optional SMTP password, e.g. "example-smtp-password".
        """
        return await send_test_email(
            *deps(),
            host,
            site,
            email,
            smtp_host,
            port,
            sender,
            use_auth,
            use_sender,
            use_ssl,
            username,
            x_password,
        )

    @mcp.tool(name="get_remote_access_turn_credentials", annotations=WRITE)
    async def get_remote_access_turn_credentials_tool(host: str, site: str) -> Any:
        """Get remote-access TURN credentials (Classic cmd/cloudaccess).

        Required arguments: host, site.

        POST /proxy/network/api/s/{site}/cmd/cloudaccess {"cmd": "get-turn-credentials"}.
        The credentials are returned verbatim (masked only under UNIFI_REDACT_SECRETS).
        This POST is not on the read-POST allowlist, so it is classified as a write.
        Consequence: the controller issues TURN credentials.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        return await get_remote_access_turn_credentials(*deps(), host, site)

    @mcp.tool(name="set_cloud_access_registration", annotations=WRITE)
    async def set_cloud_access_registration_tool(
        host: str,
        site: str,
        action: Literal["register", "unregister"],
        ubic_username: str | None = None,
        ubic_password: str | None = None,
        ubic_2fa_token: str | None = None,
        mfa_cookie: str | None = None,
        poll_login: bool | None = None,
    ) -> Any:
        """Register or unregister cloud remote access (Classic cmd/cloudaccess).

        Required arguments: host, site, action.

        POST /proxy/network/api/s/{site}/cmd/cloudaccess {"cmd": action, and the account
        keys given}. ubic_password, ubic_2fa_token and mfa_cookie are credentials.
        Consequence: unregister ends cloud remote access to this controller.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            action: Command to send, e.g. "register".
            ubic_username: Optional Ubiquiti account user, e.g. "admin@example.com".
            ubic_password: Optional Ubiquiti account password, e.g. "example-password".
            ubic_2fa_token: Optional 2FA code, e.g. "123456".
            mfa_cookie: Optional MFA cookie from an earlier reply, e.g. "example-cookie".
            poll_login: Optional poll-login flag, e.g. true.
        """
        return await set_cloud_access_registration(
            *deps(),
            host,
            site,
            action,
            ubic_username,
            ubic_password,
            ubic_2fa_token,
            mfa_cookie,
            poll_login,
        )

    @mcp.tool(name="refresh_sso_session", annotations=WRITE)
    async def refresh_sso_session_tool(
        host: str,
        site: str,
        sso_username: str | None = None,
        sso_password: str | None = None,
        sso_2fa_token: str | None = None,
        mfa_cookie: str | None = None,
        poll_login: bool | None = None,
    ) -> Any:
        """Refresh the controller's Ubiquiti SSO session (Classic cmd/productinfo).

        Required arguments: host, site.

        POST /proxy/network/api/s/{site}/cmd/productinfo/refresh-sso {"cmd":
        "refresh-sso", and the keys given}. sso_password, sso_2fa_token and mfa_cookie are
        credentials. Consequence: replaces the controller's SSO session.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            sso_username: Optional SSO user, e.g. "admin@example.com".
            sso_password: Optional SSO password, e.g. "example-password".
            sso_2fa_token: Optional 2FA code, e.g. "123456".
            mfa_cookie: Optional MFA cookie from an earlier reply, e.g. "example-cookie".
            poll_login: Optional poll-login flag, e.g. true.
        """
        return await refresh_sso_session(
            *deps(), host, site, sso_username, sso_password, sso_2fa_token, mfa_cookie, poll_login
        )

    @mcp.tool(name="link_ubiquiti_sso_account", annotations=WRITE)
    async def link_ubiquiti_sso_account_tool(
        host: str,
        site: str,
        command: str,
        ubic_username: str | None = None,
        x_ubic_password: str | None = None,
        ubic_2fa_token: str | None = None,
        mfa_cookie: str | None = None,
        poll_login: bool | None = None,
    ) -> Any:
        """Link the signed-in admin to a Ubiquiti SSO account (Classic self/ubic_sso).

        Required arguments: host, site, command.

        POST /proxy/network/api/s/{site}/self/ubic_sso {"cmd": command, and the keys
        given}. The 11.0.81 front end chooses the command name at runtime, so command is
        sent as given. x_ubic_password, ubic_2fa_token and mfa_cookie are credentials.
        Consequence: changes how this admin signs in.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            command: Command name the SSO form sends (lower-case), e.g. "link".
            ubic_username: Optional Ubiquiti account user, e.g. "admin@example.com".
            x_ubic_password: Optional account password, e.g. "example-password".
            ubic_2fa_token: Optional 2FA code, e.g. "123456".
            mfa_cookie: Optional MFA cookie from an earlier reply, e.g. "example-cookie".
            poll_login: Optional poll-login flag, e.g. true.
        """
        return await link_ubiquiti_sso_account(
            *deps(),
            host,
            site,
            command,
            ubic_username,
            x_ubic_password,
            ubic_2fa_token,
            mfa_cookie,
            poll_login,
        )

    @mcp.tool(name="update_my_admin_profile", annotations=WRITE)
    async def update_my_admin_profile_tool(host: str, profile: dict[str, Any]) -> Any:
        """Update the calling admin's own profile (Classic PUT api/self).

        Required arguments: host, profile.

        Reads GET /proxy/network/api/self, merges only the given leaves into the named
        top-level keys (the front end sends ui_settings), PUTs those keys and reads back.
        Returns the upstream PUT body verbatim plus _verified (true only when every
        requested leaf reads back equal, type-strict) and _readAfterError when the
        read-back failed; a non-object body is returned whole under response with those
        keys beside it. An object with nothing to change fails before any request.
        Consequence: changes this admin's own settings.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            profile: Leaves to change, e.g. {"ui_settings": {"preferences": {"theme": "dark"}}}.
                Free-form object.
        """
        return await update_my_admin_profile(*deps(), host, profile)

    @mcp.tool(name="resend_mfa_code", annotations=WRITE)
    async def resend_mfa_code_tool(
        host: str, mfa_type: str, mfa_id: str, body: dict[str, Any] | None = None
    ) -> Any:
        """Resend an MFA code for an SSO sign-in (Network v2 route).

        Required arguments: host, mfa_type, mfa_id.

        POST /proxy/network/v2/api/mfa/{mfa_type}/{mfa_id}/send {"cmd": "resend-mfa-code",
        **body}; the 11.0.81 front end builds the two path segments and the rest of the
        body from the MFA challenge of a refresh_sso_session reply. Returns the upstream
        body verbatim. Consequence: a new code is sent to the account.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            mfa_type: First path segment, the challenge's MFA type, e.g. "email".
            mfa_id: Second path segment, the challenge's MFA id, e.g. "example-mfa-id".
            body: Optional free-form extra body keys (never "cmd"), e.g.
                {"mfa_cookie": "example-cookie"}.
        """
        return await resend_mfa_code(*deps(), host, mfa_type, mfa_id, body)

    @mcp.tool(name="set_controller_system_parameter", annotations=WRITE)
    async def set_controller_system_parameter_tool(
        host: str, site: str, key: str, value: ParamValue
    ) -> Any:
        """Set one controller system parameter (Classic cmd/system set-param).

        Required arguments: host, site, key, value.

        POST /proxy/network/api/s/{site}/cmd/system {"cmd": "set-param", "key", "value"},
        both sent as given. Consequence: changes controller-wide behaviour.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            key: Parameter name, e.g. "debug.mgmt".
            value: Parameter value, e.g. "warn".
        """
        return await set_controller_system_parameter(*deps(), host, site, key, value)

    @mcp.tool(name="generate_support_file", annotations=WRITE)
    async def generate_support_file_tool(
        host: str, site: str, mac: str, body: dict[str, Any] | None = None
    ) -> Any:
        """Start generating a device support file (Network v2 route).

        Required arguments: host, site, mac.

        The MAC is checked against GET .../stat/device-basic first (an unknown MAC fails
        listing the site's device MACs), then POST
        /proxy/network/v2/api/site/{site}/support/{mac}/generation with body as given (the
        front end builds it at runtime; free-form). Returns the upstream body verbatim.
        Poll get_support_file, then fetch it with download=true. Consequence: the device
        collects diagnostics.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            mac: Device MAC, e.g. "02:00:5e:00:00:a1".
            body: Optional free-form body, e.g. {}.
        """
        return await generate_support_file(*deps(), host, site, mac, body)

    @mcp.tool(name="get_support_file", annotations=READ_ONLY)
    async def get_support_file_tool(host: str, site: str, mac: str, download: bool = False) -> Any:
        """Get a device support file's status, or download it (Network v2 route).

        Required arguments: host, site, mac.

        GET /proxy/network/v2/api/site/{site}/support/{mac}: Returns the upstream status
        body verbatim, an object or an array as sent (an unknown MAC is the upstream's own
        error). With download=true,
        GET .../support/{mac}/download: Returns content_base64 (the file), contentType
        (the upstream Content-Type) and sizeBytes.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            mac: Device MAC, e.g. "02:00:5e:00:00:a1".
            download: Download the file instead of the status, e.g. true.
        """
        return await get_support_file(*deps(), host, site, mac, download)

    @mcp.tool(name="check_controller_firmware_update", annotations=WRITE)
    async def check_controller_firmware_update_tool(host: str, site: str) -> Any:
        """Ask the controller to check for a Network application update (Classic).

        Required arguments: host, site.

        POST /proxy/network/api/s/{site}/cmd/productinfo {"cmd": "check-firmware-update"}.
        This POST is not on the read-POST allowlist, so it is classified as a write.
        Consequence: refreshes the controller's update state; installs nothing.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
        """
        return await check_controller_firmware_update(*deps(), host, site)

    @mcp.tool(name="manage_firmware_cache", annotations=WRITE)
    async def manage_firmware_cache_tool(
        host: str,
        site: str,
        action: Literal["download", "remove"],
        device: str,
        version: str,
    ) -> Any:
        """Download or remove a cached device firmware (Classic cmd/firmware).

        Required arguments: host, site, action, device, version.

        POST /proxy/network/api/s/{site}/cmd/firmware {"cmd": action, "device",
        "version"}, both sent as given. Consequence: changes the controller's firmware
        cache; no device is upgraded.

        Success is HTTP 2xx with meta.rc "ok"; anything else raises with the full upstream body.
        Returns the upstream body verbatim.

        Under UNIFI_DRY_RUN nothing is sent and the tool returns a dry-run preview: status
        "dry_run", dryRun, sent: false, message and preview (method, path, params, body). Never
        auto-retried.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            action: Command to send, e.g. "download".
            device: Device model the firmware is for, e.g. "U7PG2".
            version: Firmware version, e.g. "6.6.77.15402".
        """
        return await manage_firmware_cache(*deps(), host, site, action, device, version)

    @mcp.tool(name="get_latest_firmware_versions", annotations=READ_ONLY)
    async def get_latest_firmware_versions_tool(
        host: str, site: str, filter: str | None = None, time: str | None = None
    ) -> Any:
        """Report the devices' current firmware and update availability (official APIs).

        Required arguments: host, site.

        Returns the site's drained Integration device list verbatim (data[].firmwareVersion,
        data[].firmwareUpdatable, totalCount) plus _siteManagerDevices: Site Manager GET
        /v1/devices for this console, verbatim (data[].devices[].version, firmwareStatus,
        updateAvailable). incomplete=true with incompleteReason when either drain stopped
        short.

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            filter: Optional Integration device filter, sent as given, e.g.
                "firmwareUpdatable.eq(true)". Example: `name.eq('Office Switch')`.
            time: Optional Site Manager last-processed RFC3339 time, e.g.
                "2026-10-01T00:00:00Z".
        """
        return await get_latest_firmware_versions(*deps(), host, site, filter, time)
