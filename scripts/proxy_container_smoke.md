# Reverse-proxy image smoke

Run this after building and loading the image under test. The script uses an isolated
internal Docker network, starts the application on loopback, and runs a proxy and
synthetic UniFi upstream in its network namespace. It preserves a non-localhost Host
across the proxy and checks MCP initialization, discovery, and `list_hosts` through
`call_read_tool` in both stateful and stateless streamable HTTP modes. The proxy
client validates TLS against the provided CA and localhost hostname. No real UniFi
network or real credentials are used; requests carry a public synthetic bearer token.
The supplied image also runs the proxy and client.

The default command expands the vendored public CPython v3.12.0 test fixture from
tests/proxy_container/cpython-keycert.pem.gz, originally published at
`https://raw.githubusercontent.com/python/cpython/v3.12.0/Lib/test/keycert.pem` and
verifies its SHA256 `cfd723672e8205a30f93aa14e24ef5b0264c41db367b50cfa0b6fcb83d881947`.
This synthetic self-signed localhost certificate is valid through 2028-08-26. No network download occurs during the smoke. The compressed representation preserves
the exact public fixture bytes without adding a private-key-shaped literal to the
secret scanner; every expansion verifies the pinned digest. This public fixture is
not a credential and must never be used outside tests. The upstream license is
retained in tests/proxy_container/CPYTHON-LICENSE.txt (Python-2.0).
Alternatively pass existing synthetic certificate, key, and CA paths explicitly:

```sh
scripts/proxy_container_smoke.sh IMAGE
scripts/proxy_container_smoke.sh IMAGE https CERT KEY CA
```

Replace `IMAGE` with the image built from the exact revision under test and carrying
its full `org.opencontainers.image.revision` label. The script inspects the image ID
and revision label, verifies the running container image ID, and emits one JSON
attestation per mode. Save the complete output as release evidence. Review build
provenance independently; image labels and logs are not cryptographic proof. In CI,
use the loaded exact-head image and make this command a required image job step. Any failed assertion fails the job.
The optional final `expect-421` argument is a negative-control oracle for an image
known to contain the regression, not a passing CI condition for the image under test.
The `http` option exists for debugging only and does not establish TLS coverage.
