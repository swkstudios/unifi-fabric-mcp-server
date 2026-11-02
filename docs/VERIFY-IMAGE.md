# Verify the image

Release images are signed keylessly with [Sigstore Cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
by this repository's `publish.yml` workflow, which also attaches an SPDX SBOM attestation and a
GitHub build-provenance attestation. Verify the digest, not a mutable tag. The expected workflow
identity and the GitHub Actions OIDC issuer make these checks reject images that were not built
and signed by a release tag of this repository.

<!-- install-case: verify-image-01 mode=non-executable reason=verification requires a published digest -->
<!-- doc-provenance: source=file:.github/workflows/publish.yml@sha256:ab38e562f9226e30204bf31eeb39b7a1c4d0ab315fa213a06c622e1207128fba support=0.7.0 case=verify-image-01 -->
```bash
IMAGE=ghcr.io/swkstudios/unifi-fabric-mcp-server@sha256:<digest>
IDENTITY='^https://github\.com/swkstudios/unifi-fabric-mcp-server/\.github/workflows/publish\.yml@refs/tags/v.*$'
ISSUER='https://token.actions.githubusercontent.com'

cosign verify --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$IMAGE"
cosign verify-attestation --type spdxjson --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$IMAGE"
gh attestation verify "oci://${IMAGE}" --repo swkstudios/unifi-fabric-mcp-server --cert-identity-regex "$IDENTITY" --cert-oidc-issuer "$ISSUER"
```

Each command exits non-zero if the image was not signed by this repository's release workflow.

## Platforms and per-platform digests

Each release tag points to one image index that holds a `linux/amd64` and a `linux/arm64`
image, each built natively on its own platform. The signature, the SBOM attestation and the
provenance attestation are attached to the index digest: the digest a tag resolves to, and
the one `docker inspect --format='{{index .RepoDigests 0}}'` reports after pulling a tag.
The per-platform images carry no signature of their own. To check a per-platform digest,
verify the index digest with the commands above, then list the images that index holds;
the per-platform digest must appear next to its platform:

<!-- install-case: verify-image-02 mode=non-executable reason=verification requires a published digest -->
<!-- doc-provenance: source=file:.github/workflows/publish.yml@sha256:ab38e562f9226e30204bf31eeb39b7a1c4d0ab315fa213a06c622e1207128fba support=0.7.0 case=verify-image-02 -->
```bash
docker buildx imagetools inspect "$IMAGE"
```

The SBOM attestation lists the packages of the `linux/amd64` image; the `linux/arm64` image
installs the same locked package versions.
