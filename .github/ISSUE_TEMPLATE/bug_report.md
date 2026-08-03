---
name: Bug report
about: Something is not working correctly
labels: bug
---

## What happened

<!-- A clear and concise description of the bug. -->

## What did you expect to happen

<!-- What should the tool or server have done instead? -->

## Steps to reproduce

1. Tool name and parameters used:
   ```
   # example: list_clients(host="MyConsole", site="Default")
   ```
2. Error message or unexpected output:
   ```
   # paste the full error or response here
   ```

## Environment

| Item | Value |
|------|-------|
| Server version / image tag | <!-- e.g. v0.5.0 or ghcr.io/…:latest --> |
| Transport | <!-- stdio / streamable-http / sse --> |
| Auth mode | <!-- none / bearer / oauth --> |
| Python version (if not Docker) | <!-- python3 --version --> |
| OS | <!-- macOS 14 / Ubuntu 22.04 / etc. --> |

## Relevant logs

<!-- Set `UNIFI_LOG_LEVEL=DEBUG` and paste relevant stderr output. Redact your API key and any sensitive IP addresses before posting. -->

```
```

## Anything else?

<!-- Firmware versions, network topology details, or anything else that might help diagnose this. -->
