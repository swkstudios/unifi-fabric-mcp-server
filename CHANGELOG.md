# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.14] — 2026-04-29

### Added
- Optional `MCP_BEARER_TOKEN` env var for bearer-token authentication on HTTP transport
- When set, all incoming MCP requests require `Authorization: Bearer <token>` header
- Backward compatible: server runs without transport auth when unset (existing behavior)

## [0.3.13] — 2026-04-22

### Added
- Banner image for README and social sharing

## [0.3.12] — 2026-04-22

### Fixed
- Docker container now binds to port 3000 (was defaulting to 8000)
- Documentation accuracy improvements across all internal and public docs

## [0.3.11] — 2026-04-22

### Changed
- Expanded API key setup guide with Fabric-specific steps
- Added TLS/reverse proxy guidance for network deployments
- Pinned Dockerfile base image to Debian Bookworm (stable)
- Improved contributor documentation

### Fixed
- Docker image cleanup and hygiene improvements
