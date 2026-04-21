# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.17] - 2026-04-21

### Fixed

- Resolved critical dead-endpoint and schema-mismatch bugs across multiple tools (SWK-309).
- Added pagination to `list_clients` and `list_firewall_policies`; added `type` filter to `list_clients`.
- Clarified `list_rogue_aps` behavior: returns all neighboring APs by default with new `rogue_only` filter.
- Enriched `list_wan_interfaces` response; fixed `get_channel_plan` empty-message edge case; improved
  `query_isp_metrics` name resolution.
- Fixed `UniFiClient.delete` missing `json` parameter (mypy typecheck error).

### Security

- Replaced real Ubiquiti MAC/OUI values in test fixtures and code comments with synthetic placeholders.
- Redacted `x_passphrase` and `x_password` fields by default in API responses.

### Changed

- Moved `list_hotspot_operators` to host+site required scope in INSTRUCTIONS.
- Pre-publish cleanup: removed internal references; promoted CHANGELOG; pinned CI action SHAs.

## [0.2.16] - 2026-04-21

### Added

- CHANGELOG.md, SECURITY.md, CODEOWNERS, Dependabot config, and pre-commit hooks
  as part of the repo governance hygiene bundle (SWK-138).
- GitHub Actions steps now pinned to full commit SHAs for supply-chain safety.

## [0.2.2] through [0.2.14] - 2026-04-01 to 2026-04-20

See git history for detailed commits. Key additions in this release cycle:
- FastMCP transport abstraction with support for stdio, SSE, and streamable-http (FASTMCP_TRANSPORT)
- Extensive Protect tools: cameras, lights, sensors, PTZ control, liveviews, RTSPS streams, snapshots
- Dynamic DNS, traffic routing, and port forwarding tools
- Network device management, client blocking, and device tagging
- ISP metrics queries with per-site filtering
- Comprehensive test coverage with respx mocking
- Docker image with health checks and tini PID 1 initialization
- INSTRUCTIONS constant documentation and parameter scope reference guide

## [0.2.1] - 2026-04-14

### Fixed

- Use `tini` as PID 1 in the Docker image so that SIGTERM is forwarded to the
  Python process and zombie processes are reaped correctly.  Previously the
  server ran as PID 1 directly and Python ignored SIGTERM, causing Docker to
  wait the full `StopTimeout` (10 s) before sending SIGKILL — which interrupted
  in-flight tool calls mid-stream.

## [0.2.0] - 2026-04-13

### Added

- Bounded TTL cache for the site/host registry with per-key expiry and eviction
  pressure warnings (SWK-135).
- Search-across-sites fan-out now bounded by a semaphore (`UNIFI_MAX_CONCURRENCY`,
  default 10) to prevent runaway concurrency against the API (SWK-117).
- ObjectId-to-UUID site resolution hardening in registry and proxy tools
  (SWK-113, SWK-114).
- Production `Dockerfile` (python:3.12-slim, non-root `mcp` user, health-check
  via TCP probe) and `.dockerignore` (SWK-115).

## [0.1.0] - 2026-04-01

### Added

- Initial release with FastMCP server wrapping the UniFi Site Manager cloud API.
- Tools for site management, networks, devices, clients, firewall, VPN, Protect,
  hotspot, routing, and cross-site aggregation.
- Multi-key MSP support with per-key registry cache.

[0.2.16]: https://github.com/swkstudios/unifi-fabric-mcp-server/compare/v0.2.15...v0.2.16
