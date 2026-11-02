# Multi-platform image (linux/amd64, linux/arm64) built without emulation: every RUN step
# executes in the builder stage on the build host's own platform ($BUILDPLATFORM), which
# installs the locked wheels for the TARGET platform and assembles the runtime filesystem.
# The final stage only copies that filesystem, so building the arm64 image on an amd64
# host (or the reverse) needs no QEMU. The runtime image has no pip and no build tools.
# Base digest: python:3.12-slim-bookworm with ca-certificates 20250419~deb12u2 or later, which
# distrusts the eMudhra incident roots; the builder fails the build if the bundle trusts one.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337

# The base filesystem of the target platform. Nothing runs in it; the builder copies it.
FROM ${PYTHON_IMAGE} AS base

FROM --platform=$BUILDPLATFORM ${PYTHON_IMAGE} AS builder
ARG TARGETARCH

WORKDIR /build

# Dependency layer first: it installs the runtime lock (no test or lint packages), so a
# source-only change reuses it. pip installs the target platform's wheels (manylinux 2.17
# through 2.36, the glibc of Debian bookworm) into the virtualenv's site-packages; a
# locked package without such a wheel fails the build. The virtualenv's interpreter is a
# link to /usr/local/bin/python, which the runtime filesystem provides for its platform.
COPY requirements-runtime.lock requirements-build.lock ./
RUN case "$TARGETARCH" in \
      amd64) WHEEL_ARCH=x86_64 ;; \
      arm64) WHEEL_ARCH=aarch64 ;; \
      *) echo "unsupported target architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && PLATFORMS="--platform manylinux2014_${WHEEL_ARCH}" \
    && for minor in $(seq 17 36); do PLATFORMS="$PLATFORMS --platform manylinux_2_${minor}_${WHEEL_ARCH}"; done \
    && pip install --no-cache-dir --require-hashes -r requirements-build.lock \
    && python -m venv --without-pip /venv \
    && SITE=/venv/lib/python3.12/site-packages \
    && pip install --no-cache-dir --require-hashes --no-deps --only-binary=:all: \
       $PLATFORMS --python-version 3.12 --implementation cp --abi cp312 \
       --target "$SITE" -r requirements-runtime.lock \
    && if [ -d "$SITE/bin" ]; then \
         for script in "$SITE"/bin/*; do sed -i '1s|^#!.*python.*$|#!/venv/bin/python|' "$script"; done \
         && mv "$SITE"/bin/* /venv/bin/ && rmdir "$SITE/bin"; \
       fi

# Source layer: build the wheel with the hash-pinned hatchling (no build isolation, so
# nothing unpinned is fetched) and install only the project (pure Python) into the
# virtualenv.
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip wheel --no-cache-dir --no-deps --no-build-isolation --wheel-dir /wheels . \
    && pip --python /venv/bin/python install --no-cache-dir --no-deps /wheels/*.whl

# Runtime filesystem: the target base without pip, setuptools or wheel; tini from the
# Debian archive for the target architecture; the unprivileged mcp user; the virtualenv.
COPY --from=base / /rootfs/
RUN rm -rf /rootfs/usr/local/lib/python3.12/site-packages/pip \
      /rootfs/usr/local/lib/python3.12/site-packages/pip-*.dist-info \
      /rootfs/usr/local/lib/python3.12/site-packages/setuptools \
      /rootfs/usr/local/lib/python3.12/site-packages/setuptools-*.dist-info \
      /rootfs/usr/local/lib/python3.12/site-packages/_distutils_hack \
      /rootfs/usr/local/lib/python3.12/site-packages/distutils-precedence.pth \
      /rootfs/usr/local/lib/python3.12/site-packages/wheel \
      /rootfs/usr/local/lib/python3.12/site-packages/wheel-*.dist-info \
      /rootfs/usr/local/bin/pip /rootfs/usr/local/bin/pip3 /rootfs/usr/local/bin/pip3.12 \
      /rootfs/usr/local/bin/wheel \
    && sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && dpkg --add-architecture "$TARGETARCH" \
    && apt-get update \
    && cd /tmp && apt-get download "tini:$TARGETARCH" \
    && dpkg --root=/rootfs --force-architecture --force-depends --force-script-chrootless \
       --log=/dev/null -i /tmp/tini_*.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/tini_*.deb /rootfs/var/log/dpkg.log \
    && echo 'mcp:x:10001:' >> /rootfs/etc/group \
    && echo 'mcp:!::' >> /rootfs/etc/gshadow \
    && echo 'mcp:x:10001:10001::/nonexistent:/sbin/nologin' >> /rootfs/etc/passwd \
    && echo 'mcp:!:20000::::::' >> /rootfs/etc/shadow \
    && mkdir -p /rootfs/app \
    && cp -a /venv /rootfs/venv

# Fail the build when the runtime CA bundle (loaded by httpx2 for the JWKS download and
# FastMCP clients) still trusts a root named in the eMudhra CA incident.
COPY scripts/check_ca_bundle.py /check/check_ca_bundle.py
RUN python /check/check_ca_bundle.py /rootfs/etc/ssl/certs/ca-certificates.crt

FROM scratch

COPY --from=builder /rootfs/ /
COPY LICENSE NOTICE /usr/share/doc/unifi-fabric-mcp-server/

# MCP registry OCI ownership verification (must match server.json name).
LABEL io.modelcontextprotocol.server.name="io.github.swkstudios/unifi-fabric-mcp-server"

WORKDIR /app

ENV PATH=/venv/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
ENV LANG=C.UTF-8
ENV UNIFI_API_BASE_URL=https://api.ui.com
ENV UNIFI_CACHE_TTL_SECONDS=900
ENV UNIFI_MAX_CONCURRENCY=10
# FastMCP transport protocol; override at docker run time with -e FASTMCP_TRANSPORT=sse|stdio
ENV FASTMCP_TRANSPORT=streamable-http
# Stateless streamable HTTP: every request is served on its own, with no MCP session to
# keep, so any replica behind a load balancer can answer any request and a restart
# drops no client state. SSE is session-based and ignores this. Override with
# -e FASTMCP_STATELESS_HTTP=false to restore per-client sessions.
ENV FASTMCP_STATELESS_HTTP=true
# Bind to all interfaces on port 3000 to match EXPOSE and HEALTHCHECK. With no
# MCP_AUTH_MODE / MCP_BEARER_TOKEN set the server logs a startup WARNING: set a bearer
# token (openssl rand -hex 32) for any deployment reachable from a network.
ENV FASTMCP_HOST=0.0.0.0
ENV FASTMCP_PORT=3000

EXPOSE 3000

# FastMCP does not expose a /health HTTP endpoint by default; use a TCP-probe instead.
# Docker governs the probe runtime; the socket operation adds no inner deadline.
# https://docs.docker.com/reference/dockerfile/#healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python3 -c "import os, socket; s=socket.create_connection(('localhost', int(os.environ.get('FASTMCP_PORT', 3000)))); s.close()" || exit 1

USER mcp

ENTRYPOINT ["/usr/bin/tini", "--", "unifi-fabric-mcp"]
