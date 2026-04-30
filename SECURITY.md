# Security Policy

To report a security vulnerability, please use GitHub's private vulnerability reporting feature: navigate to the Security tab of this repository and click "Report a vulnerability."

We will respond as quickly as feasible.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | No        |

Only the current major version receives security fixes. Users on older versions should upgrade.

## Important Security Note: Bearer Token Authentication

The optional bearer token feature (HTTP transport with `--bearer-token`) is **not intended for production use**, consistent with FastMCP's own guidance on this transport mode.

**Recommended hardening:**

- Run the server on `localhost` or a private interface only.
- Gate all external access behind network-level controls (firewall rules, VPN, or use a reverse proxy with authentication).
- Do not expose the MCP server directly to the public internet regardless of whether a bearer token is configured.
