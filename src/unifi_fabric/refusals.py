"""The refusal registry: every place a tool may refuse a call before its upstream request.

The policy (pre-upstream validation): a tool refuses a call before the upstream request
ONLY for

1. ``selector-syntax`` -- the server's OWN argument grammar: a host / site / key label /
   id / MAC selector it resolves itself, a value it interpolates into a URL path, the
   connector relay's path grammar, and combinations of its own arguments that name one
   thing twice or nothing at all;
2. ``spec`` -- a constraint the pinned vendored OpenAPI spec states (a schema keyword, a
   ``required`` list, a ``format``, or the prose of a description, quoted);
3. ``probed-enum`` -- a closed set of values probed live on a real controller (recorded
   with the controller version), for a parameter the upstream would otherwise silently
   ignore;
4. ``json-validity`` -- a value JSON cannot carry (NaN / Infinity) or one of the wrong JSON
   type for the argument's declared schema.

Everything else passes through: the upstream judges the value, and the server may append
a hint to the upstream's error. Two additional categories cover the
operator's own write switches (``operator-policy``: ``UNIFI_WRITE_POLICY=deny`` and the per-area
write opt-outs) and explicit policy exceptions (``ruled-keep``): the empty-update
guard, AP radio channel validation required by the L15-AP dispatch, the collectors' work
and pacing bounds, and the camera-shortcut shape checks a caller opts into.
``upstream-judged`` entries are NOT pre-upstream refusals: they are
decisions taken on data the tool read from the upstream (an unknown id after the list was
read, an unexpected response shape); they are listed so the whole-catalog property test
can tell them apart from a refusal.

Every entry names the functions that raise it (``module.py:qualname``, relative to the
package) and a ``pattern`` that matches its message. ``tests/test_refusal_policy.py``
feeds every tool blank strings, empty lists, out-of-range numbers and bodies with keys
missing, and fails when a call neither reaches the upstream nor raises a registered
refusal; it also fails when a function in the package raises from a site this registry
(or the test's inventory of non-refusal raise sites) does not name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SELECTOR_SYNTAX = "selector-syntax"
SPEC = "spec"
PROBED_ENUM = "probed-enum"
JSON_VALIDITY = "json-validity"
OPERATOR_POLICY = "operator-policy"
RULED_KEEP = "ruled-keep"
UPSTREAM_JUDGED = "upstream-judged"

#: The four categories a pre-upstream argument refusal may have.
ARGUMENT_CATEGORIES = frozenset({SELECTOR_SYNTAX, SPEC, PROBED_ENUM, JSON_VALIDITY})
CATEGORIES = ARGUMENT_CATEGORIES | {OPERATOR_POLICY, RULED_KEEP, UPSTREAM_JUDGED}


@dataclass(frozen=True)
class Refusal:
    """One registered refusal: its category, its citation, the functions raising it and
    a regular expression its message matches (searched, case-sensitive)."""

    id: str
    category: str
    citation: str
    pattern: str
    sites: tuple[str, ...]
    tools: frozenset[str] = field(default_factory=frozenset)
    #: Exact registry entries with this reason may read before refusing; local refusals may not.
    upstream_reason: str | None = None

    def matches(self, message: str) -> bool:
        return re.search(self.pattern, message) is not None


#: Body fields (or a query parameter) a create / action tool refuses to send without, each
#: REQUIRED by the pinned spec's request schema of the operation the tool calls:
#: {label: (tool, fields, citation)}, keyed by the label the tool passes to
#: ``tools._payload.require_fields`` (which refuses only for these labels). A tool without
#: a published request schema passes its body through and appends the documented guidance
#: to an upstream error instead (``tools._payload.missing_fields_hint``).
SPEC_REQUIRED_FIELDS: dict[str, tuple[str, frozenset[str], str]] = {
    "create_network": (
        "create_network",
        frozenset({"management"}),
        "network-11.0.97 POST /v1/sites/{siteId}/networks: required management "
        "(the discriminator of the Network create schema)",
    ),
    "create_wifi_broadcast": (
        "create_wifi_broadcast",
        frozenset({"type"}),
        "network-11.0.97 POST /v1/sites/{siteId}/wifi/broadcasts: required type (discriminator)",
    ),
    "create_dns_policy": (
        "create_dns_policy",
        frozenset({"type"}),
        "network-11.0.97 POST /v1/sites/{siteId}/dns/policies: required type (discriminator)",
    ),
    "create_traffic_matching_list": (
        "create_traffic_matching_list",
        frozenset({"type"}),
        "network-11.0.97 POST /v1/sites/{siteId}/traffic-matching-lists: required type "
        "(discriminator)",
    ),
    "create_hotspot_vouchers": (
        "create_hotspot_vouchers",
        frozenset({"name", "timeLimitMinutes"}),
        "network-11.0.97 POST /v1/sites/{siteId}/hotspot/vouchers: required name, timeLimitMinutes",
    ),
    "bulk_delete_hotspot_vouchers filter_params": (
        "bulk_delete_hotspot_vouchers",
        frozenset({"filter"}),
        "network-11.0.97 DELETE /v1/sites/{siteId}/hotspot/vouchers: query filter required: true",
    ),
    "create_firewall_policy": (
        "create_firewall_policy",
        frozenset(
            {"action", "destination", "enabled", "ipProtocolScope", "loggingEnabled", "name"}
            | {"source"}
        ),
        "network-11.0.97 POST /v1/sites/{siteId}/firewall/policies: required action, "
        "destination, enabled, ipProtocolScope, loggingEnabled, name, source",
    ),
    "create_firewall_zone": (
        "create_firewall_zone_proxy",
        frozenset({"name", "networkIds"}),
        "network-11.0.97 POST /v1/sites/{siteId}/firewall/zones: required name, networkIds",
    ),
    "create_acl_rule": (
        "create_acl_rule",
        frozenset({"type"}),
        "network-11.0.97 POST /v1/sites/{siteId}/acl-rules: required type (discriminator)",
    ),
}

#: The labels :data:`SPEC_REQUIRED_FIELDS` registers (the ``require_fields`` refusal
#: message starts with one).
SPEC_REQUIRED_LABELS = frozenset(SPEC_REQUIRED_FIELDS)

_NETWORK_PROBE = "live probe, Network 11.0.81 (kept by the refusal policy)"

REFUSALS: tuple[Refusal, ...] = (
    Refusal(
        "incident-evidence-window",
        SELECTOR_SYNTAX,
        "the incident-evidence collectors' own argument grammar: the window is integer epoch "
        "seconds the server converts to a half-open millisecond window (end after start, so an "
        "empty window names nothing; a negative or millisecond-size bound is not refused, it "
        "is sent with a warning), and a source list (log_classes, cameras, types) is a list "
        "of strings naming at least one source "
        "(the Network collector's log_classes may name only a class on the read-POST allowlist)",
        r"^collect_(?:network|protect)_incident_evidence (?:window: |\w+ names no source"
        r"|\w+ must be a list of strings|log_classes may name only a read-allowlisted)",
        (
            "shared_shapes/_incident_document.py:evidence_window",
            "shared_shapes/_incident_document.py:evidence_selectors",
            "families/statistics/system_log.py:_collect_network_incident_evidence",
        ),
        tools=frozenset({"collect_network_incident_evidence", "collect_protect_incident_evidence"}),
    ),
    Refusal(
        "event-stream-site-selector",
        SELECTOR_SYNTAX,
        "The event-stream tools' own key grammar: a Network buffer is per console and site, "
        "a Protect buffer per console, so site is required for network and refused for "
        "protect (an argument naming nothing, or naming a selector the product does not have)",
        r"^site is a Network selector; Protect events are per console|"
        r"^site is required for product 'network'",
        ("families/statistics/event_streams.py:_check_site_selector",),
        frozenset({"read_recent_events"}),
    ),
    Refusal(
        "event-stream-product",
        SELECTOR_SYNTAX,
        "The event-stream products are the server's own closed set (network, protect); the "
        "tool schemas already restrict product to it",
        r"^Unknown event-stream product ",
        ("stream_buffers.py:compatibility", "stream_buffers.py:StreamManager.compatibility"),
        frozenset({"get_event_stream_status", "read_recent_events"}),
    ),
    Refusal(
        "event-stream-cursor",
        SELECTOR_SYNTAX,
        "The buffer cursor is the server's own sequence number: a value beyond the newest seq "
        "this process issued names no position (a restarted server starts again at 0)",
        r"^after_seq \d+ is beyond this buffer's newest seq ",
        ("stream_buffers.py:EventBuffer.read",),
        frozenset({"read_recent_events"}),
    ),
    Refusal(
        "network-batch-delete-ids-type",
        JSON_VALIDITY,
        "the v2 batch-delete tools send a bare JSON array of id strings; a value that is "
        "not a list cannot be that body (an empty list is accepted)",
        r"^batch-delete ids must be a list of id strings",
        ("families/network/network_dpi_policy.py:_batch_ids",),
    ),
    Refusal(
        "network-client-write-json",
        JSON_VALIDITY,
        "Network client write bodies must be JSON-serialisable before selector resolution.",
        r"^The write body must be JSON-serialisable",
        ("families/network/network_clients_guests.py:_validate_json_body",),
    ),
    Refusal(
        "protect-assets-json-types",
        JSON_VALIDITY,
        "Protect assets tool declared JSON argument types: object, boolean, integer, string",
        r"^body must be a JSON object|^muted must be a boolean|"
        r"^valid_until must be an epoch-milliseconds integer|^device_password must be a string|"
        r"^ignore_file_extension must be a boolean|^filename must be a string|"
        r"^content_type must be a string|^content_base64 must be a base64 string",
        (
            "families/protect/protect_users_assets.py:_body",
            "families/protect/protect_users_assets.py:set_protect_notifications_muted",
            "families/protect/protect_users_assets.py:update_protect_device_password",
            "families/protect/protect_users_assets.py:delete_protect_file",
            "families/protect/protect_users_assets.py:upload_ringtone",
        ),
    ),
    Refusal(
        "protect-assets-base64",
        SELECTOR_SYNTAX,
        "Server binary-upload encoding: content_base64 is parsed locally into multipart bytes",
        r"^content_base64 must be valid base64",
        ("families/protect/protect_users_assets.py:upload_ringtone",),
    ),
    Refusal(
        "protect-assets-lookup",
        UPSTREAM_JUDGED,
        "Resolve a Protect asset id against the upstream collection "
        "before selecting its native spelling",
        r"^Unknown Protect .*valid choices:",
        ("families/protect/protect_users_assets.py:_find",),
        upstream_reason="missing-target",
    ),
    Refusal(
        "protect-lock-lookup",
        UPSTREAM_JUDGED,
        "Resolve a Protect door lock id against the console's GET /locks list before the "
        "per-lock request; the error lists the valid locks",
        r"^Unknown door lock .*valid choices:",
        ("families/protect/protect_door_locks.py:_require_known_lock",),
        upstream_reason="the lock is identified from the upstream GET /locks list",
    ),
    Refusal(
        "protect-assets-incomplete-target",
        UPSTREAM_JUDGED,
        "An upstream incomplete collection cannot identify a unique safe write target",
        r"^Cannot select a Protect write target from an incomplete collection",
        ("families/protect/protect_users_assets.py:_complete",),
        upstream_reason="incomplete-list",
    ),
    Refusal(
        "protect-resource-uri-query",
        SELECTOR_SYNTAX,
        "The Protect resource URI query options the server parses itself: window_seconds "
        "(a positive whole number of seconds) and high_quality (true or false)",
        r"^window_seconds must be a positive whole number|^high_quality must be true or false"
        r"|^window_seconds is longer than the time since 1970-01-01",
        (
            "protect_resources.py:parse_window_seconds",
            "protect_resources.py:parse_high_quality",
            "protect_resources.py:ProtectResources._events",
        ),
    ),
    Refusal(
        "switch-port-override-selection",
        SELECTOR_SYNTAX,
        "update_switch_port_overrides' own port selection: each port named once, never both "
        "updated and removed, remove_ports entries are 1-based port numbers, and explicit "
        "empty ports/remove_ports lists that name no port at all",
        r"^Ambiguous port selection: |^remove_ports entry must be a positive integer port"
        r"|^No port selected: ports and remove_ports are both empty",
        (
            "families/devices/switch_port_overrides.py:_port_number",
            "families/devices/switch_port_overrides.py:_validate_request",
        ),
    ),
    Refusal(
        "switch-port-override-device",
        UPSTREAM_JUDGED,
        "the switch's ports, current overrides and port profiles are read from stat/device "
        "rest/portconf and rest/networkconf before the merged array is built",
        r"^Unknown port_idx \d+ on this switch; valid ports: |^Unknown \w+_port_idx .* "
        r"valid ports: |^Port \d+ has no override to remove; |it is not a switch\. Choose a "
        r"switch|^Unknown portconf_id .* valid port profiles"
        r"|^Unknown \w+_networkconf_ids? .* valid networks from list_networks"
        r"|^port \d+ field \w+_networkconf_ids? must be a ",
        (
            "families/devices/switch_port_overrides.py:_check_against_device",
            "families/devices/switch_port_overrides.py:_check_networks",
            "families/devices/switch_port_overrides.py:_overrides",
            "families/devices/switch_port_overrides.py:_update_switch_port_overrides",
        ),
        upstream_reason="the selection is checked against the switch read from the upstream",
    ),
    # ------------------------------------------------------------ 1. selector syntax
    Refusal(
        "selector-argument",
        SELECTOR_SYNTAX,
        "host / site / key_label / device / client / MAC / camera selectors the server "
        "resolves itself: empty, surrounding whitespace or a control character "
        "(kept by the refusal policy)",
        r"'[\w\[\].]+' (must not be empty|contains a control character|has surrounding "
        r"whitespace|must be a string)[^\n]*; pass |must not be empty or whitespace; pass "
        r"|No API key with label ",
        (
            "selector_args.py:check_selector",
            "selector_args.py:SelectorArgumentMiddleware.on_call_tool",
            "client.py:validate_selector",
            "client.py:UniFiClient.get_key_by_label",
            "families/statistics/statistics.py:_select_one_record",
        ),
    ),
    Refusal(
        "n09-upstream-record-selection",
        UPSTREAM_JUDGED,
        "an update or delete target is resolved in its v2 collection first",
        r"^Unknown (energy-saving policy|power supervisor|power-supervisor link) ",
        ("families/network/network_switching_power.py:_listed_record",),
        upstream_reason="the target is identified from the upstream collection",
    ),
    Refusal(
        "discovery-meta-tool-argument",
        SELECTOR_SYNTAX,
        "the discovery meta-tools' own grammar (UNIFI_TOOL_MODE=discovery): a family slug or "
        "tool name the server resolves in its own enabled catalog, a positive search limit, "
        "a query with a searchable term, and a write tool named to call_read_tool. These "
        "tools send no upstream request themselves",
        r"Unknown or unavailable (family|tool) |limit must be a positive integer, or null "
        r"|Your query has no searchable terms|No enabled tools match "
        r"|is a write tool\. Use call_write_tool",
        (
            "discovery.py:SearchIndex.search",
            "discovery.py:apply_tool_mode.require_tool",
            "discovery.py:apply_tool_mode.dispatch_read",
        ),
    ),
    Refusal(
        "device-port-index",
        SELECTOR_SYNTAX,
        "get_device_port_state port_idx: the server selects the port_table row of the "
        "/stat/device record itself (port_idx is never sent upstream), and a negative "
        "index names no row",
        r"^'port_idx' must be a non-negative port number",
        ("families/statistics/statistics.py:_get_device_port_state",),
    ),
    Refusal(
        "client-ip-selector",
        SELECTOR_SYNTAX,
        "get_client_wifi_experience client_ip: the value is interpolated into the URL path "
        "(wifiman/{client_ip}), so only one bare IPv4 or IPv6 address is sent",
        r"^'client_ip' ",
        ("families/network/network_controller_insights.py:_client_ip",),
    ),
    Refusal(
        "path-segment",
        SELECTOR_SYNTAX,
        "a value the server interpolates into a URL path segment: empty, a control "
        "character, '?', '#', '/', '.' / '..' or a character outside the id alphabet "
        "would change the route",
        r"'[\w\[\].]+' must not be empty$|: expected alphanumeric, hyphens|contains unsafe "
        r"characters|is a path traversal, not an id|contains a control character$"
        r"|contains a control character or surrounding whitespace"
        r"|Pass the asset filename exactly",
        (
            "client.py:validate_id",
            "client.py:path_segment",
            "client.py:validate_host_id",
            "families/innerspace/innerspace.py:_asset_filename_segment",
        ),
    ),
    Refusal(
        "unsafe-api-path",
        SELECTOR_SYNTAX,
        "the HTTP chokepoint's own path rule: a request path with traversal or a "
        "scheme is never sent",
        r"^Unsafe API path ",
        ("client.py:UniFiClient._request",),
    ),
    Refusal(
        "firmware-url-scheme",
        SELECTOR_SYNTAX,
        "an upgrade_device firmware_url, or a non-empty update_device_battery_settings url, "
        "that is not an http or https URL with a host: the console would be told to fetch "
        "firmware from it, so any other scheme is never sent (an empty battery url is the "
        "console default and passes through)",
        r"^(firmware_)?url must be an http or https URL with a host",
        (
            "families/devices/device_mgmt.py:_upgrade_device",
            "families/network/network_device_operations.py:update_device_battery_settings",
        ),
    ),
    Refusal(
        "protect-ptz-doorbell-argument-combinations",
        SELECTOR_SYNTAX,
        "combinations of the server's own arguments that name nothing or that name one step's "
        "fields for another step: delete_camera_shortcut with an empty shortcut_ids list (no "
        "shortcut is named, so no DELETE could address one) and enroll_doorbell_credential "
        "with fingerprint_id / ulp_id / fields for a step other than 'assign' (those keys "
        "exist only in the assign body, so the call would silently drop them)",
        r"^shortcut_ids must be a non-empty list|only apply to step 'assign'",
        (
            "families/protect/protect_ptz_doorbell.py:delete_camera_shortcut",
            "families/protect/protect_ptz_doorbell.py:enroll_doorbell_credential",
        ),
    ),
    Refusal(
        "relay-path",
        SELECTOR_SYNTAX,
        "the connector relay's path grammar (relay-relative path, placeholders "
        "{site}/{site_id}, scope device/site/global checked against the route class read from "
        "the resource segments after the site prefix, never a site name or id, the method a "
        "relay tool sends)",
        r"[Cc]onnector path |resolved path |^'path' must not be empty|site placeholder "
        r"|^Invalid scope |^scope=|connector_write does not handle|Unresolved placeholder",
        (
            "families/connector/connector.py:_check_raw_charset",
            "families/connector/connector.py:_check_placeholders",
            "families/connector/connector.py:_check_final_charset",
            "families/connector/connector.py:_validate_relay_path",
            "families/connector/connector.py:_check_site_given",
            "families/connector/connector.py:_substitute_site",
            "families/connector/connector.py:_check_scope",
            "families/connector/connector.py:connector_write",
        ),
    ),
    Refusal(
        "argument-grammar",
        SELECTOR_SYNTAX,
        "combinations of the server's own arguments that name one value twice, name "
        "nothing, or pick a key/console the other argument contradicts",
        r"Provide exactly one of client_id|`host` and `site` go together|pass ONE of "
        r"`sites` or `host`|requires scoping: pass `sites`|'name' was given twice"
        r"|clear_fields names .* but a value was also given|client_type and filter are "
        r"mutually exclusive|^client_type must be one of|belongs to API key .*omit key_label"
        r"|reads one page of ONE key's listing|organization is ambiguous: pass key_label"
        r"| source must be one of | source conflict: |^list_network_events scope conflict: "
        r"|^get_scoped_system_log scope must be one of ",
        (
            "families/clients/clients.py:resolve_list_source",
            "families/clients/client_records.py:_guest_source",
            "families/statistics/system_log.py:_vpn_user_connection_log",
            "families/statistics/system_log.py:_get_scoped_system_log",
            "families/statistics/statistics.py:_get_client_link_diagnostics",
            "families/site_manager/site_manager.py:validate_isp_sites",
            "families/protect/protect.py:_body_with_name",
            "families/carrier/carrier_fabric.py:register.update_carrier_subscriber",
            "families/clients/clients.py:_resolve_client_filter",
            "families/site_manager/site_manager.py:list_devices",
            "shared_shapes/_keys.py:page_mode_scope",
            "families/carrier/carrier_fabric.py:_create_key",
        ),
    ),
    Refusal(
        "client-observability-view-arguments",
        SELECTOR_SYNTAX,
        "combinations of get_client_observability's own arguments that name a time the chosen "
        "view does not use: start / end with view topology (a snapshot), timestamp with "
        "logs-all / timeline / timestamps (a window); the argument would be silently dropped",
        r"^Client observability view ",
        ("families/network/network_clients_guests.py:_check_observability_arguments",),
    ),
    Refusal(
        "n08-routing-argument-grammar",
        SELECTOR_SYNTAX,
        "N08 routing/topology tools: the view / action / target value selects the v2 route "
        "the server builds, and an id argument is required by (or meaningless for) the "
        "chosen action, and a reservations list that names nothing to import (empty)",
        r"^(view|action|target) must be one of |^(group_id|virtual_network_id) is "
        r"(required for|not used with) action |^group is not used with action "
        r"|^reservations is an empty list",
        (
            "families/network/network_routing_topology.py:import_dhcp_reservations",
            "families/network/network_routing_topology.py:_choice",
            "families/network/network_routing_topology.py:_paired_id",
            "families/network/network_routing_topology.py:manage_mclag_group",
        ),
    ),
    Refusal(
        "n04-typed-argument-named-twice",
        SELECTOR_SYNTAX,
        "a free-form profile / params object that also carries a key a typed argument sets "
        "(mac, pin): the typed value is sent, so the object's key would be silently replaced",
        r"^(profile|params) must not contain ",
        ("families/network/network_mobile_wan.py:_reject_named_keys",),
    ),
    Refusal(
        "mac-or-id-selector",
        SELECTOR_SYNTAX,
        "an id-or-MAC selector the server parses itself (client UUID or MAC; a pending "
        "device's MAC; forget_device's and forget_client's MAC lists; the MAC a client "
        "reservation is created for)",
        r"is neither a client id \(UUID\) nor a MAC|is not a MAC address: a pending device"
        r"|^mac is empty: pass one (device|client) MAC|^Not a MAC address( in [a-z_]+)?: "
        r"|^ap_mac must be a MAC address|^mac must be a device MAC",
        (
            "families/clients/clients.py:_validate_client_ref",
            "families/network/network_clients_guests.py:authorize_guest",
            "families/network/network_mobile_wan.py:_check_mac",
            "families/network/network_mobile_wan.py:_check_macs",
            "families/devices/device_mgmt.py:_approve_pending_device",
            "families/devices/device_mgmt.py:_forget_device",
            "families/clients/client_records.py:_require_macs",
            "families/clients/client_records.py:_create_client_reservation",
            "families/devices/device_commands.py:advanced_adopt_device",
        ),
    ),
    Refusal(
        "protect-private-selector",
        SELECTOR_SYNTAX,
        "a private Protect camera / sensor / device NAME-or-id selector the server matches "
        "itself (selector_syntax.name_reason): empty or a control character; surrounding "
        "whitespace is a legal name and is looked up",
        r"^(camera_id|sensor_id|device_id) (must not be empty|contains a control character)",
        ("families/protect/protect_private.py:_resolve",),
    ),
    Refusal(
        "protect-private-device-type",
        SELECTOR_SYNTAX,
        "the private Protect device actions' device_type (declared enum camera / sensor) "
        "selects the cameras / sensors path segment the server interpolates into the route; "
        "checked again on the direct call path, where no schema validation runs",
        r"^device_type must be camera or sensor",
        (
            "families/protect/protect_private.py:reboot_protect_device",
            "families/protect/protect_private.py:adopt_protect_device",
            "families/protect/protect_private.py:unadopt_protect_device",
        ),
    ),
    Refusal(
        "camera-shortcut-opt-in-shape",
        RULED_KEEP,
        "create_camera_shortcut / update_camera_shortcut run local per-type shape checks only "
        "when the caller opts in with validate_schema=true (default off: the body passes "
        "through and the upstream judges it). Shapes: Protect UI 5.3.18 bundle "
        "f5afa0f4eccbb98bfb70.531.js linked-type enum and Shortcuts create/onSelect builders; "
        "Protect 7.3.74 rejects a webhook without timeout",
        r"^camera shortcut (must be an object|is missing required fields: "
        r"|id must be a non-empty string)|^shortcut\.placement(\.[xy])? must be "
        r"|^shortcut\.shortcut(\.type)? must be "
        r"|^(linkedCamera|linkedDoor|webhook) shortcut (is missing required fields: "
        r"|\w+ must be a non-empty string|timeout must be a number)",
        ("families/protect/protect_ptz_doorbell.py:_validate_shortcut_element",),
    ),
    Refusal(
        "innerspace-internal-arguments",
        SELECTOR_SYNTAX,
        "the InnerSpace internal-route tools' own argument grammar: a plan id or share token "
        "the server interpolates into the route path must be a UUID, and an upload's "
        "content must be base64, an empty captures / plans list names nothing, and a mode "
        "given both as an argument and a transform key would be silently replaced "
        "(families/innerspace/innerspace_internal.py)",
        r"^Invalid InnerSpace '(plan_id|token)': expected a UUID|^content_base64 is not "
        r"valid base64|^InnerSpace arguments: ",
        (
            "families/innerspace/innerspace_internal.py:_argument_grammar",
            "families/innerspace/innerspace_internal.py:_uuid",
            "families/innerspace/innerspace_internal.py:_decode_upload",
        ),
    ),
    # ------------------------------------------------------------ 2. pinned spec
    Refusal(
        "spec-limits",
        SPEC,
        "SPEC_LIMITS (tests/spec_limits_gen.py): every schema value keyword the vendored "
        "specs state for a value a tool argument carries, plus the prose limits in "
        "DESCRIBED_LIMITS, each quoted from the spec",
        r"\(spec (minimum|maximum|exclusiveMinimum|exclusiveMaximum|minLength|maxLength"
        r"|pattern|enum|minItems|maxItems|type)\b|matches none of the allowed forms|\(the "
        r"spec type is integer\)",
        ("spec_limits.py:check_arguments", "spec_limits.py:SpecLimitMiddleware.on_call_tool"),
    ),
    Refusal(
        "spec-required-fields",
        SPEC,
        "SPEC_REQUIRED_FIELDS: a create/action body without a field the published request "
        "schema requires",
        r"^(?P<tool>[\w ]+) requires: ",
        ("shared_shapes/_payload.py:require_fields",),
        SPEC_REQUIRED_LABELS,
    ),
    Refusal(
        "spec-required-body-keys",
        SPEC,
        "write_body.REQUIRED_BODY_KEYS: orderedAclRuleIds / orderedFirewallPolicyIds, "
        "required by the full-replace ordering operations (network-11.0.97)",
        r"^Missing required field\(s\) .* the published request schema requires",
        ("write_body.py:EmptyUpdateMiddleware.on_call_tool",),
    ),
    Refusal(
        "spec-id",
        SPEC,
        "an id the spec types as format: uuid or with a maxLength (carrier planId / hostId, "
        "Integration client / zone ids, Site Manager hostIds[] items: string)",
        r"must be a non-empty string \(got |the spec requires a UUID \(format: uuid\)|the "
        r"spec allows at most \d+",
        ("client.py:validate_spec_id", "client.py:path_segment"),
    ),
    Refusal(
        "carrier-subscriber-fields",
        SPEC,
        "carrier-fabric-1.0.0 SubscriberCreate / SubscriberPatch: subscriberNumber 1-32 "
        "('A value is 1-32 characters after trimming.' on the patch), name/email/notes/"
        "serviceAddress 'The N limit is bytes of UTF-8', metadata type object and 'The "
        "serialized JSON object must not exceed 8192 bytes', name 'non-empty after "
        "trimming', clearable fields = the nullable SubscriberPatch properties, suspend "
        "reason maxLength 1024, list sort enum, suspended type boolean",
        r"^'subscriber_number' must|bytes of UTF-8|serializes to \d+ bytes of JSON"
        r"|^'metadata' must|^'[\w]+' must be an "
        r"object \(mapping\)|must be non-empty after trimming|cannot be cleared\. Clearable"
        r"|^'[\w]+' must be \d+-\d+ characters|^'[\w]+' must be a string$|^Invalid sort "
        r"|^suspended must be a boolean",
        (
            "families/carrier/carrier_fabric.py:_validate_len",
            "families/carrier/carrier_fabric.py:_validate_subscriber_number",
            "families/carrier/carrier_fabric.py:_validate_bytes",
            "families/carrier/carrier_fabric.py:_validate_metadata",
            "families/carrier/carrier_fabric.py:update_carrier_subscriber",
            "families/carrier/carrier_fabric.py:list_carrier_subscribers",
            "families/carrier/carrier_fabric.py:register.update_carrier_subscriber",
        ),
    ),
    Refusal(
        "mobility-fields",
        SPEC,
        "mobility-1.0.0: UpdateNetworkReq host_address / dhcp_range_* format ipv4, "
        "dhcp_mode enum [dhcp, none], dhcp_lease_time type integer minimum 0; "
        "UpdateDeviceNameReq 'New device name (1-32 characters).'; wireless ssid / password "
        "lengths",
        r"expected an IPv4 address|^Invalid dhcp_mode |^dhcp_lease_time must|^'[\w]+' must "
        r"be \d+-\d+ characters|^'[\w]+' must be a string$",
        (
            "families/mobility/mobility.py:_validate_ipv4",
            "families/mobility/mobility.py:_validate_len",
            "families/mobility/mobility.py:update_mobility_device_network",
        ),
    ),
    Refusal(
        "protect-request-fields",
        SPEC,
        "protect-7.3.74: posTransactionRequest required [type, externalId, amount], type "
        "enum [sale, refund], externalId minLength 1, amount minimum 0; createArmProfile "
        "name minLength 1; RTSPS qualities minItems 1 (create body, delete query); "
        "{outputId} type integer; POST /v1/files/{fileType} accepted media types "
        "(the upload extension check is kept by the refusal policy)",
        r"^'transaction' must be a posTransactionRequest|^transaction '\w+' (must|is "
        r"required)|^'name' must not be empty$|^'qualities' (must be a non-empty list|entries "
        r"must be non-empty)|^'output_id' must be an integer|^content_type must be a MIME "
        r"type|^Cannot tell the upload's MIME type|^file_content_base64 is not valid base64",
        (
            "families/protect/protect.py:pos_ingest_transaction",
            "families/protect/protect.py:create_arm_profile",
            "families/protect/protect.py:require_nonempty_qualities",
            "families/protect/protect.py:_output_channel",
            "families/protect/protect.py:upload_content_type",
            "families/protect/protect.py:upload_protect_file",
            "families/protect/protect_recognition_search.py:_upload_files",
        ),
    ),
    Refusal(
        "client-action",
        SPEC,
        "network-11.0.97 executeConnectedClientAction: the action discriminator "
        "[AUTHORIZE_GUEST_ACCESS, UNAUTHORIZE_GUEST_ACCESS]",
        r"^action\.action must be one of ",
        ("families/clients/clients.py:_check_client_action",),
    ),
    Refusal(
        "innerspace-mode",
        SPEC,
        "innerspace-1.3.23: the render mode enum [2D, 3D] (the argument is normalised "
        "case-insensitively first)",
        r"^Invalid mode .*: expected one of 2D, 3D",
        ("families/innerspace/innerspace.py:_normalize_mode",),
    ),
    Refusal(
        "isp-query",
        SPEC,
        "site-manager-1.0.0 /v1/isp-metrics/{type}: 'Specifies whether metrics are "
        "returned using `5m` or `1h` intervals'; the query body sites[] items required "
        "[hostId, siteId], beginTimestamp / endTimestamp type string format date-time",
        r"^interval must be '5m' or '1h'|must be an ISO 8601 UTC timestamp string|must "
        r"not be empty or whitespace \(.*\); pass an ISO 8601|^sites\[\d+\] (must be a|"
        r"needs a )|must be a non-empty ISO 8601",
        (
            "families/site_manager/site_manager.py:get_isp_metrics",
            "families/site_manager/site_manager.py:validate_isp_query",
            "families/site_manager/site_manager.py:validate_isp_sites",
        ),
    ),
    # ------------------------------------------------------------ 3. live-probed enums
    Refusal(
        "stat-enums",
        PROBED_ENUM,
        f"statistics SESSION_TYPES / REPORT_INTERVALS / REPORT_SCOPES ({_NETWORK_PROBE}): "
        "the Classic stat endpoints ignore an unknown value and answer the full set",
        r"is not a session class; valid: |^Invalid interval .*: expected one of |^Invalid "
        r"scope .*: expected one of ",
        (
            "families/statistics/statistics.py:_list_client_sessions",
            "families/statistics/statistics.py:_get_historical_stats",
        ),
    ),
    # ------------------------------------------------------------ 4. JSON validity
    Refusal(
        "integer-not-boolean",
        JSON_VALIDITY,
        "a JSON boolean given for an argument the input schema types as an integer (true "
        "and false are not JSON integers)",
        r"^'[A-Za-z_][A-Za-z_.]*' must be an integer, not a boolean",
        ("argument_values.py:ArgumentValueMiddleware.on_call_tool",),
    ),
    Refusal(
        "finite-number",
        JSON_VALIDITY,
        "NaN / Infinity are not JSON numbers",
        r"numbers must be finite",
        (
            "argument_values.py:require_finite",
            "argument_values.py:ArgumentValueMiddleware.on_call_tool",
        ),
    ),
    Refusal(
        "argument-schema",
        JSON_VALIDITY,
        "the tool's declared input schema (type, required, unknown argument), checked by "
        "the framework",
        r"^Invalid arguments for tool |^Text arguments must be strings\.$",
        (
            "argument_errors.py:ArgumentErrorMiddleware.on_call_tool",
            "families/devices/device_radios.py:RadioChanges._no_null_fields",
            "families/devices/switch_port_overrides.py:PortOverrideChange._fields_present",
            "families/protect/protect_automation_backup.py:_text",
        ),
    ),
    Refusal(
        "paging-continuation-grammar",
        SELECTOR_SYNTAX,
        "Opaque cursor continuation strings carry native token/size state; page-number "
        "continuation objects carry an offset/size pair so local paging resumes at "
        "the returned position; plain upstream cursor strings remain pass-through",
        r"^Use the returned opaque _continuation string|^_continuation token "
        r"|^Malformed _continuation token"
        r"|^body\.pageNumber continuation requires|^body\.pageSize must be a positive integer "
        r"when following _nextPage",
        (
            "shared_shapes/_continuation.py:decode_continuation",
            "shared_shapes/_pagination.py:cursor_continuation",
            "families/network/network_nat_qos_traffic.py:_flow_page_batch",
        ),
    ),
    Refusal(
        "logical-pagination-integer",
        SELECTOR_SYNTAX,
        "Logical pagination controls drive local window arithmetic: counts (limit, "
        "page_size, query_body.pageSize) are strict positive integers, a one-based page is "
        "1 or more, and a zero-based page (page_number, the number-family page, "
        "query_body.pageNumber) and an offset are strict nonnegative integers, without an "
        "upper bound; every message names the argument the caller passed",
        r"^[A-Za-z_][A-Za-z_.]* must be a positive integer \(1 or more\); got "
        r"|^[A-Za-z_][A-Za-z_.]* is 1-based and must be 1 or more; got "
        r"|^[A-Za-z_][A-Za-z_.]* is zero-based and must be 0 or more; got "
        r"|^[A-Za-z_][A-Za-z_.]* must be 0 or more; got ",
        (
            "shared_shapes/_pagination.py:validate_pagination",
            "client.py:UniFiClient.paginate_offset",
        ),
    ),
    Refusal(
        "body-not-object",
        JSON_VALIDITY,
        "a request body argument that is not a JSON object",
        r"requires a JSON object with fields: |must be an object\.$|' must be a JSON object; got "
        r"|^create_firewall_rule requires a JSON object$",
        (
            "shared_shapes/_payload.py:require_fields",
            "families/network/network_services_proxy.py:create_firewall_rule",
            "families/protect/protect_automation_backup.py:_body",
            "families/protect/protect_recognition_search.py:_object",
        ),
    ),
    Refusal(
        "report-false-positive-thumbnails",
        SELECTOR_SYNTAX,
        "report_ai_false_positive with an empty reported_thumbnails list: no thumbnail is "
        "named, so there is nothing to report",
        r"^reported_thumbnails must be a non-empty list",
        ("families/protect/protect_recognition_search.py:_report_ai_false_positive",),
    ),
    Refusal(
        "recognition-object-ids-empty",
        SELECTOR_SYNTAX,
        "create_recognition_object_group with an empty or non-list object_ids: no recognized "
        "object is named, so there is nothing to group",
        r"^object_ids must be a non-empty list|^'object_ids' must be a list of object id strings",
        ("families/protect/protect_recognition_search.py:_create_recognition_object_group",),
    ),
    Refusal(
        "recognition-id-list",
        SELECTOR_SYNTAX,
        "assign_detections_to_recognition_group or merge_recognition_groups with an empty or "
        "non-list detection_ids / from_group_ids: no detection or group is named, so nothing "
        "would move",
        r"^(detection_ids|from_group_ids) must be a non-empty list"
        r"|^'(detection_ids|from_group_ids)' must be a list of ",
        ("families/protect/protect_recognition_search.py:_id_list",),
    ),
    Refusal(
        "recognition-merge-into-itself",
        SELECTOR_SYNTAX,
        "merge_recognition_groups whose from_group_ids names to_group_id: a group cannot be "
        "merged into itself",
        r"^from_group_ids must not contain to_group_id ",
        ("families/protect/protect_recognition_search.py:_merge_recognition_groups",),
    ),
    Refusal(
        "mac-table-query-array",
        JSON_VALIDITY,
        "query_switch_mac_tables with a query that is not a non-empty JSON array of objects: "
        "the route deserializes a list of {mac, ports}",
        r"^'query' must be a JSON array of \{mac, ports\} objects|^query must be a non-empty "
        r"list|^'query\[\d+\]' must be a JSON object",
        ("families/network/network_switching_power.py:query_switch_mac_tables",),
    ),
    Refusal(
        "port-reset-list",
        JSON_VALIDITY,
        "reset_switch_port with ports that is not a non-empty JSON array of {port_idx, "
        "unit_id?} objects: the route takes the list of ports whose last connection is cleared",
        r"^'ports' must be a JSON array of \{port_idx|^ports must be a non-empty list"
        r"|^'ports\[\d+\]' must be an object with an integer port_idx"
        r"|^'ports\[\d+\]\.unit_id' must be an integer, got ",
        ("families/network/network_device_operations.py:_port_list",),
    ),
    Refusal(
        "hide-flag-type",
        JSON_VALIDITY,
        "hide_face_detection_enhanced_image with a hide value that is not a JSON boolean",
        r"^'hide' must be a boolean \(true to hide, false to show\)",
        ("families/protect/protect_recognition_search.py:_hide_face_detection_enhanced_image",),
    ),
    Refusal(
        "recognition-selector-type",
        JSON_VALIDITY,
        "a recognition tool's event_id, group_id or object_ids item that is not a JSON string: "
        "the error names the shape received instead of calling it empty",
        r"^'(event_id|group_id|to_group_id|(object_ids|detection_ids|from_group_ids)\[\d+\])'"
        r" must be a string; got ",
        ("families/protect/protect_recognition_search.py:_selector",),
    ),
    Refusal(
        "detection-statistics-period-type",
        JSON_VALIDITY,
        "get_detection_statistics period that is neither an integer nor a string",
        r"^period must be an integer or string",
        ("families/protect/protect_recognition_search.py:_get_detection_statistics",),
    ),
    Refusal(
        "epoch-type",
        JSON_VALIDITY,
        "an epoch-seconds argument that is not a JSON integer",
        r"must be an integer epoch-seconds timestamp",
        ("shared_shapes/_history_common.py:require_epoch_seconds",),
    ),
    Refusal(
        "radio-channel-grammar",
        RULED_KEEP,
        "BRIEF-L15-master.md, L15-AP Behaviour 1: validate band/channel combinations "
        "as required by the L15-AP dispatch; channel auto or a "
        "primary channel within ng/na/6e (hardware bounds are checked only "
        "after reading device capabilities)",
        r"Invalid channel .* for radio band",
        ("families/devices/device_radios.py:_validate_channel",),
    ),
    Refusal(
        "collector-control-bounds",
        RULED_KEEP,
        "Collectors validate positive poll counts, finite nonnegative pacing and positive "
        "optional result limits (max_events / max_changes; None collects every result) "
        "before I/O",
        r"^(poll_count must be a positive integer|"
        r"poll_interval_seconds must be (a finite number|at least 0 seconds)|"
        r"(max_events|max_changes) must be a positive integer or None)",
        (
            "families/protect/protect.py:_validate_collector_controls",
            "families/protect/protect.py:_validate_collector_limit",
        ),
    ),
    Refusal(
        "n06-json-body",
        JSON_VALIDITY,
        "private v2 object/array JSON body contract; finite JSON leaves only",
        r"^body must |^blocks must ",
        (
            "families/network/network_dpi_policy.py:_body",
            "families/network/network_dpi_policy.py:set_firewall_app_blocks",
        ),
    ),
    # ------------------------------------------------------------ operator policy
    Refusal(
        "read-only",
        OPERATOR_POLICY,
        "UNIFI_WRITE_POLICY=deny (an operator switch, default off)",
        r"UNIFI_WRITE_POLICY=deny|read-only mode|effective write policy for this request denies",
        (
            "request_policy.py:RequestPolicyMiddleware.on_call_tool",
            "read_only_tools.py:ReadOnlyToolMiddleware.on_call_tool",
            "read_only.py:guard_request",
            "read_only.py:guard_action",
            "families/network/network_wifi_radio.py:_post",
            "families/network/network_wifi_radio.py:start_spectrum_scan",
            "families/network/network_wifi_radio.py:configure_wifi_wan",
        ),
    ),
    # Before area-write-opt-out: its message names the active opt-out variable(s).
    Refusal(
        "relay-namespace",
        OPERATOR_POLICY,
        "a relayed mutation on an unclassified route (a path in no mapped UniFi namespace) "
        "while a per-area write opt-out is active: its area cannot be proven "
        "(relay design, families/connector/connector.py); GETs, and "
        "mutations with no opt-out set, relay",
        r"unclassified route is refused while a per-area write opt-out is active",
        ("families/connector/connector.py:_check_unclassified_mutation",),
    ),
    Refusal(
        "area-write-opt-out",
        OPERATOR_POLICY,
        "the per-area write opt-outs family:connector=deny / "
        "family:network=deny / family:carrier=deny / "
        "family:mobility=deny / family:innerspace=deny / "
        "family:protect=deny (operator "
        "switches, default on)",
        r"family:(?:connector|network|carrier|mobility|innerspace|protect)=deny|opts this area out",
        (
            "read_only_tools.py:AreaOptOutMiddleware.on_call_tool",
            "read_only.py:guard_area_write",
            "read_only.py:guard_tool_write",
            "families/connector/connector.py:_check_area_opt_out",
            "families/connector/connector.py:connector_get",
            "families/carrier/carrier_fabric.py:_require_writes",
            "families/mobility/mobility.py:_require_writes",
            "families/protect/protect.py:_require_mutations",
            "families/protect/protect_private.py:_guard",
            "families/network/network_wifi_radio.py:_post",
            "families/network/network_wifi_radio.py:start_spectrum_scan",
            "families/network/network_wifi_radio.py:configure_wifi_wan",
            "families/network/matter.py:_write_guard",
        ),
    ),
    Refusal(
        "tool-not-exposed",
        OPERATOR_POLICY,
        "the operator's UNIFI_FAMILY_ALLOW / UNIFI_EXCLUDE and a request's narrowing "
        "headers: a call to a tool the effective policy does not expose is refused with "
        "tool_not_exposed before dispatch",
        r"is not exposed",
        (
            "read_only_tools.py:ExposureMiddleware.on_call_tool",
            "request_policy.py:RequestPolicyMiddleware.on_call_tool",
        ),
    ),
    Refusal(
        "invalid-policy-header",
        OPERATOR_POLICY,
        "the X-UniFi-Write-Policy / X-UniFi-Family-Allow / X-UniFi-Exclude request headers: "
        "a repeated, blank or malformed policy header is refused with invalid_policy_header "
        "before dispatch",
        r"(?i)x-unifi-(?:write-policy|family-allow|exclude)",
        (
            "request_policy.py:RequestPolicy.hook",
            "request_policy.py:tighten",
        ),
    ),
    Refusal(
        "header-credential",
        OPERATOR_POLICY,
        "UNIFI_KEY_MODE (an operator setting): in header mode a call must carry a valid "
        "X-UniFi-Api-Key header and no key_label; in environment mode the header is refused. "
        "The pre-dispatch refusals invalid_api_key_header, missing_api_key_header, "
        "key_label_not_allowed and credential_cache_saturated name no value",
        r"X-UniFi-Api-Key|header mode|UNIFI_KEY_MODE|key_label is not accepted"
        r"|credential slots are serving",
        (
            "header_credentials.py:HeaderCredentialMiddleware.on_call_tool",
            "header_credentials.py:evaluate_call",
            "header_credentials.py:parse_api_key_header",
            "header_credentials.py:_reject_duplicates",
            "header_credentials.py:CredentialCache.acquire",
        ),
    ),
    Refusal(
        "oauth-write-scope",
        OPERATOR_POLICY,
        "MCP_OAUTH_WRITE_SCOPE (an operator setting for MCP_AUTH_MODE=oauth, default unset): "
        "a write tool called with an access token that lacks the scope",
        r"MCP_OAUTH_WRITE_SCOPE",
        ("transport_security.py:WriteScopeMiddleware.on_call_tool",),
    ),
    # ------------------------------------------------------------ ruled keep
    Refusal(
        "empty-update",
        RULED_KEEP,
        "an empty PATCH/PUT/create body, except a literal empty create body with "
        "unpublished upstream-judged provenance (kept by the refusal policy)",
        r"^No fields provided",
        (
            "write_body.py:require_update_fields",
            "write_body.py:require_unmasked_fields",
            "families/devices/device_radios.py:_update_device_radio",
            "families/devices/switch_port_overrides.py:_validate_request",
            "write_body.py:EmptyUpdateMiddleware.on_call_tool",
            "families/protect/protect.py:_fields_to_send",
            "families/protect/protect_private.py:_settings_body",
            "client.py:UniFiClient._request",
            "families/network/network_device_operations.py:_empty",
        ),
    ),
    # ------------------------------------------------------------ upstream-judged
    Refusal(
        "classic-upstream-error",
        UPSTREAM_JUDGED,
        "Classic API envelope meta.rc other than ok is an upstream error even at HTTP 200",
        r'"meta"\s*:\s*\{',
        ("shared_shapes/_classic_objects.py:checked_classic_response",),
        upstream_reason="The Classic envelope rc is judged from the upstream response.",
    ),
    Refusal(
        "command-outcome-unknown",
        UPSTREAM_JUDGED,
        "a transport timeout after the command was sent; its outcome cannot be inferred "
        "without reading controller/device state",
        r"[Oo]utcome (is )?unknown|Request timed out:",
        ("client.py:UniFiClient._request",),
        upstream_reason="The command was sent upstream; only its outcome is unknown.",
    ),
    Refusal(
        "scheduled-task-incomplete-lookup",
        UPSTREAM_JUDGED,
        "a capped upstream scheduled-task enumeration cannot safely resolve an id",
        r"Scheduled-task lookup is incomplete",
        ("families/devices/scheduled_tasks.py:_resolve",),
        upstream_reason="Id resolution requires the upstream scheduled-task enumeration.",
    ),
    Refusal(
        "lookup-miss",
        UPSTREAM_JUDGED,
        "a selector that matches no record (or several) in the list the tool READ from "
        "the upstream; the error lists the valid choices",
        r"not found|[Uu]nknown host|ambiguous|matches \d+ |valid: |[Vv]alid \w+ values"
        r"|No connected client with MAC|was not among|has no port_idx|No /stat/sta client "
        r"matched|No \w+ matching |is neither a networkconf _id|no MAC; |does not map to "
        r"exactly one site|has no internalReference|not a UUID|valid choices: "
        r"|^(Unknown|Ambiguous) (camera|sensor|\w+) '.*'; valid choices: "
        r"|^Incomplete Protect .* list; no write target can be resolved\.$",
        (
            "registry.py:match_host",
            "registry.py:_match_proxy_site",
            "registry.py:match_ea_site",
            "registry.py:Registry.resolve_key_for_host",
            "registry.py:Registry.resolve_host_id",
            "registry.py:Registry._refuse_name_on_partial_sites",
            "registry.py:Registry.resolve_site_id",
            "registry.py:Registry.resolve_site_slug",
            "registry.py:_assert_uuid",
            "matching.py:find_by_id",
            "families/network/network_mobile_wan.py:_device_macs",
            "families/network/network_mobile_wan.py:_find_sla",
            "shared_shapes/_classic_objects.py:select_classic_record",
            "families/network/network_wifi_radio.py:_select_wan",
            "families/network/network_security_diagnostics.py:_require_record",
            "shared_shapes/_classic_objects.py:require_listed_record",
            "shared_shapes/_classic_objects.py:resolve_device_tag_record",
            "families/network/network_device_operations.py:_match_device",
            "families/vpn/vpn.py:_select_by_id",
            "families/vpn/network_vpn_dns.py:_select_users",
            "families/network/network_services_proxy.py:get_traffic_route",
            "families/network/network_services_proxy.py:get_wlan_group",
            "families/network/network_services_proxy.py:_mutate_port_profile_exclusion",
            "families/network/network_services_proxy.py:_classic_networkconf_id",
            "families/protect/protect.py:_resolve_camera_refs",
            "families/protect/protect.py:delete_arm_profile",
            "families/protect/protect.py:get_arm_profile",
            "families/protect/protect.py:update_arm_profile",
            "families/protect/protect.py:update_arm_profile_settings",
            "families/protect/protect_private.py:_resolve",
            "families/protect/protect_automation_backup.py:_known",
            "families/protect/protect_automation_backup.py:_rows",
            "families/protect/protect_ptz_doorbell.py:_require_slot",
            "families/protect/protect_ptz_doorbell.py:_require_shortcuts",
            "families/protect/protect_recognition_search.py:_find_group",
            "families/clients/clients.py:_resolve_client",
            "families/clients/clients.py:_client_mac",
            "families/network/network_clients_guests.py:_write_client_target",
            "families/network/network_clients_guests.py:_write_client_mac_for",
            "families/network/network_clients_guests.py:authorize_guest",
            "families/devices/device_mgmt.py:_resolve_device_id_cached",
            "families/statistics/statistics.py:_get_device_port_state",
            "families/statistics/statistics.py:_get_client_link_diagnostics",
            "families/statistics/statistics.py:_matching_record",
            "families/statistics/statistics.py:_select_one_record",
            "families/site_manager/site_manager.py:_proxy_site_for_ea",
            "families/site_manager/site_manager.py:_resolve_ea_site_record",
            "families/site_manager/site_manager.py:get_site_health_summary",
            "families/innerspace/innerspace_internal.py:_select_plan",
            "families/clients/client_records.py:_resolve_user",
            "families/clients/client_records.py:_resolve_network_id",
            "families/clients/client_records.py:_extend_guest",
            "families/network/site_admin.py:_select_site",
            "families/network/site_config.py:_select_config_record",
            "families/network/site_config.py:_set_client_user_group",
        ),
        upstream_reason="Selector lookup requires upstream records and valid choices.",
    ),
    Refusal(
        "body-id-mismatch",
        UPSTREAM_JUDGED,
        "a body _id that names another record than the one the id argument resolved in the "
        "collection the tool READ from the upstream (device tags, site configuration "
        "records)",
        r"body _id .* does not match the resolved record _id ",
        (
            "families/devices/device_mgmt.py:_update_device_tag",
            "families/network/site_config.py:_addressed_config_body",
        ),
        upstream_reason="The body _id is compared with the record resolved upstream.",
    ),
    Refusal(
        "matter-node-selection",
        UPSTREAM_JUDGED,
        "a Matter node update or delete target is resolved in the node list the tool READ "
        "from the upstream: an unknown id lists the valid nodes; a listed node without a "
        "usable native id, or a list of the wrong shape, is an upstream record problem",
        r"^Matter node '.*' not found; valid: |^Selected Matter node has invalid native id "
        r"|^Unexpected response shape from GET .*/matter/nodes",
        ("families/network/matter.py:_matter_node_id",),
        upstream_reason="The node is identified from the upstream node list.",
    ),
    Refusal(
        "carrier-subscriber-read-before-identity",
        UPSTREAM_JUDGED,
        "update_carrier_subscriber reads the addressed subscriber before its PATCH; a "
        "read-before record whose id is another subscriber stops the call before any write "
        "(a decision on the upstream record, not on an argument)",
        r"^Read-before subscriber identity does not match the addressed subscriber",
        ("families/carrier/carrier_fabric.py:update_carrier_subscriber",),
        upstream_reason="The subscriber identity is read from the upstream before the write.",
    ),
    Refusal(
        "n08-upstream-record-selection",
        UPSTREAM_JUDGED,
        "an N08 update, delete, migrate or detach target is resolved in its v2 / Classic "
        "collection first; the error lists every valid id",
        r"^(BGP config|OSPF router|MC-LAG group|switch stack|network) '.*' not found; valid: ",
        ("families/network/network_routing_topology.py:_listed_record",),
        upstream_reason="the target is identified from the upstream collection",
    ),
    Refusal(
        "upstream-shape",
        UPSTREAM_JUDGED,
        "an upstream response the tool cannot read (unexpected shape, a field of the wrong "
        "type): raised naming the request",
        r"[Uu]nexpected (\w+ )?response shape|must be (a|an) .* \(got |of GET |expected an "
        r"(array|object)|^Unexpected Protect \w+ response: |^Read-before GET .* needs an "
        r"object, received |connected client list is incomplete",
        (
            "families/network/network_clients_guests.py:_write_client_target",
            "families/protect/protect_automation_backup.py:_rows",
            "families/vpn/network_vpn_dns.py:update_ipsec_settings",
            "families/protect/protect_recognition_search.py:_find_group",
            "families/network/network_routing_topology.py:_rows",
            "families/network/network_routing_topology.py:_singleton",
            "families/network/network_device_operations.py:_site_devices",
            "families/network/network_device_operations.py:_match_device",
            "families/network/network_device_operations.py:_id_of",
            "families/statistics/system_log.py:_page_rows",
        ),
        upstream_reason="Response shape requires an upstream response.",
    ),
    # ------------------------------------------------------------ shared tool-layer helpers
    Refusal(
        "classic-command-grammar",
        SELECTOR_SYNTAX,
        "the Classic command helper's own grammar: the manager name it interpolates into "
        "the cmd/<manager> path, the command name it sends as cmd, and parameters that must "
        "be an object that does not override cmd (shared_shapes/_classic_cmd.py)",
        r"^Invalid Classic command (manager|name) |^Classic command parameters must ",
        (
            "shared_shapes/_classic_cmd.py:validate_manager",
            "shared_shapes/_classic_cmd.py:validate_command",
            "shared_shapes/_classic_cmd.py:classic_command_body",
            "families/network/network_mobile_wan.py:_object_arg",
        ),
    ),
    Refusal(
        "classic-command-json",
        JSON_VALIDITY,
        "a Classic command parameter JSON cannot carry (NaN, Infinity, a non-string key, a "
        "non-JSON object)",
        r"^Classic command parameters are not JSON: ",
        ("shared_shapes/_classic_cmd.py:classic_command_body",),
    ),
    Refusal(
        "protect-events-cases-argument-grammar",
        SELECTOR_SYNTAX,
        "combinations of the P04 event / case tools' own arguments that name nothing or that "
        "name an argument for a form that takes none: an empty event_ids list, objects with "
        "one event id, object_id with a list, export_id with action 'prepare', case_id with "
        "action 'download', and a fields key a typed argument also sets (each would be "
        "silently dropped or replaced)",
        r"^Protect events and cases arguments: ",
        ("families/protect/protect_events_cases.py:_argument_grammar",),
    ),
    Refusal(
        "protect-edge-export-arguments",
        SELECTOR_SYNTAX,
        "combinations of export_edge_recording's own arguments that name a window for a step "
        "that takes none: start or end with action 'download' (they would be silently "
        "dropped; only prepare sends them)",
        r"^start and end only apply to action 'prepare'",
        ("families/protect/protect_camera_recording.py:export_edge_recording",),
    ),
    Refusal(
        "protect-device-route",
        SELECTOR_SYNTAX,
        "the Protect private-API route mapper's own grammar: a device type outside the "
        "enum, an action not sourced for the type, a missing id, or an id on the nvr "
        "singleton, or an empty camera_ids list that names no camera to pair "
        "(families/protect/_protect_device_types.py)",
        r"^Invalid device_type |^Invalid action .* for Protect |is a singleton and takes no "
        r"device id|^A device id is required for Protect "
        r"|^camera_ids must be a non-empty list of camera ids",
        (
            "families/protect/_protect_device_types.py:require_camera_ids",
            "families/protect/_protect_device_types.py:parse_device_type",
            "families/protect/_protect_device_types.py:action_method",
            "families/protect/_protect_device_types.py:device_path",
        ),
    ),
    Refusal(
        "n10-radio-argument-grammar",
        PROBED_ENUM,
        (
            "N10 WiFi radio routes accept only documented views, actions and WiFi-WAN enums; "
            "MACs and epochs are local path/query grammar"
        ),
        (
            r"must be a MAC address|must be an integer Unix epoch|"
            r"calculation_id, a non-empty radios|radios must be a non-empty|"
            r"view (must be|is timeline)|view 'at' takes only start|action must be|"
            r"radio_band must be|"
            r"is_wifi_tethering and enabled|port must be|"
            r"(x_)?uplink_(security|band|ssid|password|identity) "
        ),
        (
            "families/network/network_wifi_radio.py:_mac",
            "families/network/network_wifi_radio.py:_epoch",
            "families/network/network_wifi_radio.py:_wifi_security",
            "families/network/network_wifi_radio.py:_wifi_band",
            "families/network/network_wifi_radio.py:_wifi_string",
            "families/network/network_wifi_radio.py:preview_radio_ai_optimization",
            "families/network/network_wifi_radio.py:apply_radio_ai_optimization",
            "families/network/network_wifi_radio.py:get_radio_history",
            "families/network/network_wifi_radio.py:control_wifi_doctor_optimization",
            "families/network/network_wifi_radio.py:get_wifi_stats",
            "families/network/network_wifi_radio.py:start_wifi_quick_scan",
            "families/network/network_wifi_radio.py:configure_wifi_wan",
        ),
    ),
    Refusal(
        "n11-argument-grammar",
        SELECTOR_SYNTAX,
        "the N11 tools' own argument grammar: the catalog / mode / action value that selects "
        "the v2 route (route inventory, Network 11.0.81), and the packet-capture arguments "
        "that belong to one action only (pcap-start takes no id; pcap-stop takes the id and "
        "sends only cmd='pcap-stop'; the start body's cmd is the route's own)",
        r"^(catalog|mode|action) must be one of |^capture_id is (required )?for action="
        r"|^options (must not override cmd|is for action='start' only)",
        ("families/network/network_security_diagnostics.py:_grammar",),
    ),
    Refusal(
        "n11-argument-type",
        JSON_VALIDITY,
        "an N11 body argument that is not a JSON object, or a flag that is not a JSON boolean",
        r"^(certificate|profile|changes|body|options) must be a JSON object; got "
        r"|^(active_only|memory_optimized) must be a boolean; got ",
        ("families/network/network_security_diagnostics.py:_wrong_type",),
    ),
    Refusal(
        "n07-argument-grammar",
        SELECTOR_SYNTAX,
        (
            "N07 VPN tools: a WireGuard users item must name the user by _id (the server's "
            "own selector for the batch), and a site VPN action maps to the sourced "
            "enable-site-vpn / disable-site-vpn / rebuild-site-vpn command names; an empty "
            "users list names no user, and a name / site given both as a typed argument and "
            "as a params key would be silently replaced"
        ),
        r"names no WireGuard user|^Invalid site VPN action |^Site VPN arguments name ",
        (
            "families/vpn/network_vpn_dns.py:_require_user_refs",
            "families/vpn/network_vpn_dns.py:_require_items",
            "families/vpn/network_vpn_dns.py:control_site_vpn",
        ),
    ),
    Refusal(
        "n12-route-grammar",
        SELECTOR_SYNTAX,
        (
            "N12 route segments interpolated into the request path: the Network 11.0.81 "
            "route inventory's ProAV kinds (audio, video), Shadow Mode views/actions, "
            "TV-wall set/unset, test-config apply/commit and multicast views; a client MAC "
            "path segment; which multicast view takes client_mac; and that the client view "
            "is a GET, so a body given with it would be silently dropped"
        ),
        (
            r"^(kind|action|view) must be one of |^client_mac must be a MAC address|"
            r"^client_mac (is required for view|applies only to view) "
            r"|^body is not supported for client view"
        ),
        (
            "families/network/network_proav_sandbox.py:_choice",
            "families/network/network_proav_sandbox.py:_mac",
            "families/network/network_proav_sandbox.py:_multicast_route",
            "families/network/network_proav_sandbox.py:get_multicast_insights",
        ),
    ),
    Refusal(
        "n12-json-types",
        JSON_VALIDITY,
        (
            "N12 free-form body and query arguments of the wrong JSON type (an object is "
            "required; query values are strings, numbers or booleans) and an epoch "
            "argument that is not a JSON integer"
        ),
        (
            r"^(group|calibration|body|test_config|layout|query_params) must be a JSON object, "
            r"got |"
            r"^query_params values must be strings, numbers or booleans|"
            r"must be an integer epoch-milliseconds timestamp"
        ),
        (
            "families/network/network_proav_sandbox.py:_object",
            "families/network/network_proav_sandbox.py:_query",
            "families/network/network_proav_sandbox.py:_epoch_ms",
        ),
    ),
    Refusal(
        "n01-admin-argument-grammar",
        SELECTOR_SYNTAX,
        (
            "N01 controller-administration tools: the tool's own action argument picks the "
            "Classic command it sends (cloudaccess register/unregister, firmware "
            "download/remove), and a device MAC is a selector interpolated into the v2 "
            "support/{mac} path"
        ),
        r"^'action' must be one of |^'mac' must be a MAC address such as ",
        (
            "families/network/network_controller_admin.py:_choice",
            "families/network/network_controller_admin.py:_mac",
        ),
    ),
    Refusal(
        "n01-upstream-record-selection",
        UPSTREAM_JUDGED,
        (
            "a device MAC is resolved in the list the tool read first (stat/device-basic, "
            "api/self); the error lists the valid choices"
        ),
        r"^Unknown device MAC |^Unexpected response shape from GET "
        r"|returned \d+ admin records; expected exactly one",
        (
            "families/network/network_controller_admin.py:_device_mac",
            "families/network/network_controller_admin.py:_rows",
            "families/network/network_controller_admin.py:update_my_admin_profile.read",
        ),
        upstream_reason="the target is identified from the upstream collection",
    ),
    Refusal(
        "detection-search-section",
        SELECTOR_SYNTAX,
        "the server's own section selector of get_detection_search_metadata, which picks one "
        "of the three GET routes under /proxy/protect/api/detection-search "
        "(inventory_protect_5.3.18: detection-search, /labels, /progress)",
        r"^Invalid section .* for detection search metadata",
        ("families/protect/protect_recognition_search.py:_get_detection_search_metadata",),
    ),
    Refusal(
        "classic-rc-not-ok",
        UPSTREAM_JUDGED,
        "a Classic command the controller answered HTTP 2xx without meta.rc == ok, or with "
        "a body that is not the Classic envelope; the error carries the full upstream body",
        r"^Classic command error from POST |^Unexpected Classic command response shape"
        r"|^Classic read error from GET ",
        (
            "shared_shapes/_classic_cmd.py:classic_command",
            "shared_shapes/_classic_cmd.py:command_data",
            "families/network/network_controller_insights.py:_classic_get",
            "families/network/network_controller_admin.py:_classic_post",
        ),
        upstream_reason="Classic success (meta.rc) requires an upstream response.",
    ),
    # ------------------------------------------- NAT, QoS and traffic-observability tools
    Refusal(
        "nc-argument-type",
        JSON_VALIDITY,
        "NC v2 routes: a body / query argument that is not the JSON object (or array) its "
        "declared schema names, an epoch or count that is not a JSON integer, a period "
        "that is not a string (values themselves pass through to the upstream)",
        r"^\w+ must be a JSON object(, got| or array, got)|^\w+ must be an integer Unix "
        r"epoch in milliseconds|^top must be an integer, e\.g\.|^period must be a string",
        (
            "families/network/network_nat_qos_traffic.py:_nc_object",
            "families/network/network_nat_qos_traffic.py:_nc_object_or_array",
            "families/network/network_nat_qos_traffic.py:_nc_epoch_ms",
            "families/network/network_nat_qos_traffic.py:_nc_integer",
            "families/network/network_nat_qos_traffic.py:get_latest_traffic_flow_stats",
        ),
    ),
    Refusal(
        "nc-empty-batch",
        SELECTOR_SYNTAX,
        "NC QoS batch routes (batch-delete, batch-reorder): an empty list names no rule, so "
        "there is nothing to delete or reorder",
        r"^\w+ is an empty list, so it names no QoS rule",
        ("families/network/network_nat_qos_traffic.py:_nc_object_or_array",),
    ),
    Refusal(
        "nc-topology-view",
        SELECTOR_SYNTAX,
        "the topology-snapshot route selector the server builds itself: view picks one of "
        "four inventoried routes (snapshot/live, history/timeline, history/timestamps, "
        "history/at/{at}) and each route takes exactly its own path/query arguments",
        r"^view must be one of |^view 'live' takes no start|^view 'at' requires at"
        r"|^view '(timeline|timestamps)' requires start and end",
        ("families/network/network_nat_qos_traffic.py:get_topology_snapshot",),
    ),
    Refusal(
        "nc-upstream-record-selection",
        UPSTREAM_JUDGED,
        "an NC update or delete target is resolved in its v2 collection first; a v2 "
        "collection or traffic-flow page of an unexpected shape is raised naming the request",
        r"^Unknown (NAT rule|QoS rule|content filter) |[Uu]nexpected response shape from "
        r"(GET|POST) |has no string _id or id",
        (
            "families/network/network_nat_qos_traffic.py:_nc_rows",
            "families/network/network_nat_qos_traffic.py:_nc_listed",
            "families/network/network_nat_qos_traffic.py:_nc_target",
            "families/network/network_nat_qos_traffic.py:delete_qos_rule",
            "families/network/network_nat_qos_traffic.py:_nc_page_items",
            "families/network/network_nat_qos_traffic.py:_nc_has_more",
            "families/network/network_nat_qos_traffic.py:_nc_drain",
        ),
        upstream_reason="the target and the page controls are read from the upstream",
    ),
    Refusal(
        "device-operations-argument-type",
        JSON_VALIDITY,
        "a GS3 N03 device-operation argument of the wrong JSON type for its declared schema "
        "(integer, boolean, string, object, array); checked again on the direct call path",
        r"^'[\w\[\]]+' must be (an integer|a boolean|a string|an object \(mapping\)|an "
        r"array), got ",
        (
            "families/network/network_device_operations.py:_check_int",
            "families/network/network_device_operations.py:_check_bool",
            "families/network/network_device_operations.py:_check_str",
            "families/network/network_device_operations.py:_check_object",
            "families/network/network_device_operations.py:_require_object",
            "families/network/network_device_operations.py:_check_list",
        ),
    ),
    Refusal(
        "device-operations-argument-grammar",
        SELECTOR_SYNTAX,
        "combinations of the GS3 N03 device-operation tools' own arguments that name "
        "nothing or contradict each other (unit_id without port_idx, prefer1/prefer2 when "
        "clearing, estimate_body without time_estimate, an outlet index given twice, an empty "
        "battery_ids list, an empty bulk payload list)",
        r"^Device operation arguments: ",
        ("families/network/network_device_operations.py:_grammar",),
    ),
    Refusal(
        "device-operations-classic-rc",
        UPSTREAM_JUDGED,
        "a Classic device list or bulk PUT the controller answered HTTP 2xx without "
        "meta.rc == ok; the error carries the full upstream body",
        r"^Classic error from (GET|PUT) ",
        ("families/network/network_device_operations.py:_classic_ok",),
        upstream_reason="Classic success (meta.rc) requires an upstream response.",
    ),
)

#: Registered refusals by id.
BY_ID: dict[str, Refusal] = {r.id: r for r in REFUSALS}


_FRAMEWORK_PREFIX = re.compile(r"^Error calling tool '[^']*': ")


def classify(message: str) -> Refusal | None:
    """The first registered refusal whose pattern matches ``message`` (argument-validation
    entries are tried before the upstream-judged ones), else None.

    A ``spec-required-fields`` match counts only for a tool in
    :data:`SPEC_REQUIRED_FIELDS`. The framework's ``Error calling tool '<name>': `` prefix
    is not part of the message."""
    message = _FRAMEWORK_PREFIX.sub("", message, count=1)
    for refusal in sorted(REFUSALS, key=lambda r: r.category == UPSTREAM_JUDGED):
        match = re.search(refusal.pattern, message)
        if match is None:
            continue
        if refusal.tools and "tool" in match.groupdict():
            if match.group("tool") not in refusal.tools:
                continue
        return refusal
    return None


def registered_sites() -> frozenset[str]:
    """Every ``module.py:qualname`` the registry names."""
    return frozenset(site for refusal in REFUSALS for site in refusal.sites)
