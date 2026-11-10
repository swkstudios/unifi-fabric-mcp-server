# Migrating to 0.7.2

0.7.2 removes tools whose routes the current UniFi applications no longer serve, and points `restore_protect_database` and the door lock tools at the Protect 7.x routes. No 0.7.1 setting is renamed or retired; 0.7.2 adds opt-in settings, listed in the [configuration guide](CONFIGURATION.md). Callers that use none of the tools below need no change, with one exception for read-only servers.

**If you run with `UNIFI_WRITE_POLICY=deny`:** two things now behave differently. Reads that send a POST outside the read allowlist are treated as writes, so they are hidden and refused. And `fabric_connector_get` refuses the Protect camera `enable-control` and `disable-control` routes, because those change state on a GET. See [the configuration guide](CONFIGURATION.md#read-only-mode-details).

## Protect 7.x route changes

Protect 7.3.74 serves different routes from the ones these tools called, so six tools are removed, `restore_protect_database` moves to its new route, and the door lock tools change.

| Removed in 0.7.2 | Use instead |
| --- | --- |
| `get_camera_adoption_qr` | no replacement; Protect 7.3.74 has no QR route |
| `calibrate_door_lock`, `set_door_lock_auto_close` | no replacement; Protect 7.3.74 has no matching route |
| `get_protect_case_asset_snapshot` | `list_protect_case_assets`, then `get_thumbnail` with the asset's snapshot thumbnail id (`snapshot` on a presentation asset, `thumbnail` on a clip). Not identical: Protect 7.x has no snapshot asset type, so this returns that asset's thumbnail image |
| `reboot_nvr` | `reboot_unifi_os_console` |
| `update_protect_user_notifications` | no direct replacement. Protect 7.x keeps notification channels per automation and changes only the calling user's (`PATCH /automations/{id}/system-notifications/receivers`); no tool sends that per-automation route. `set_protect_notification_receivers` sends the batch form, `PATCH /automations/system-notifications/receivers`, which also changes only the calling user's receivers, never another user's. `set_protect_notifications_muted` still mutes or unmutes notifications |

Changed: `restore_protect_database` stays and now sends `POST protect/api/nvr/restore-database-backup` with no body, the route Protect 7.x serves for the former `nvr/restore-pg-dump` (same server action). It restores a foreign Postgres dump already staged on the console, then Protect restarts; with no dump staged, Protect is expected to refuse with HTTP 400 (hermetic tests only; not run against a console), and the tool passes the upstream answer through unchanged. To restore a stored backup, use `restore_protect_backup`.

`list_door_locks` reads the `/locks` route and `set_door_lock_state` requests `unlock` (`open` is accepted as the older name). `lock` and `close` are refused before any request.

## Network traffic rule changes

The Network application answers HTTP 501 `api.err.NotImplemented` when a traffic rule is created, replaced or deleted on the v2 `trafficrules` route, and the Network 11.0.99 web app no longer shows traffic rules. The three write tools are removed. `list_traffic_rules` stays and reads the rules carried over from earlier Network versions.

| Removed in 0.7.2 | Use instead |
| --- | --- |
| `create_traffic_rule` | `create_firewall_policy` (block or allow, matching a list from `create_traffic_matching_list`), `create_qos_rule` (rate limit or queue) or `create_traffic_route` (send traffic through a chosen WAN or VPN) |
| `update_traffic_rule` | no replacement; the console does not implement changing traffic rules |
| `delete_traffic_rule` | no replacement; the console does not implement deleting traffic rules |

## The 0.7.1 settings migration kit is removed

0.7.2 no longer ships the 0.7.1 settings migrator or its guide. To upgrade from 0.7.0, first follow the guide and run the migrator at the [v0.7.1 tag](https://github.com/swkstudios/unifi-fabric-mcp-server/blob/v0.7.1/docs/MIGRATING-0.7.1.md), then upgrade to 0.7.2. The server still refuses to start with a retired 0.7.0 setting and links that guide.
