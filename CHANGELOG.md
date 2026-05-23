# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.154] — Unreleased

### Fixed
- Pagination: preserve explicit zero params (#87)
- Validate network service path IDs

### Changed
- `fastmcp` dependency now `>=3.2,<3.4`
- Bump `actions/create-github-app-token` to v3

### Docs
- Clarify dispatch-based public publish flow (#85)
- Regenerate TOOLS.md from runtime metadata

## [0.3.153] — 2026-05-04

### Added
- Optional `MCP_BEARER_TOKEN` env var for bearer auth on HTTP transport (#50)
- `UNIFI_LOG_LEVEL` env var for log verbosity control

### Changed
- IP redaction in `UniFiConnectionError` messages

### Removed
- `update_radius_profile` and `delete_radius_profile` (404 upstream — endpoints no longer exist)

---

## Earlier releases

v0.2.0 — v0.3.152: Initial features and iterative fixes. See git history for details.
