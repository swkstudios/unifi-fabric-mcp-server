FROM python:3.12-slim@sha256:804ddf3251a60bbf9c92e73b7566c40428d54d0e79d3428194edf40da6521286

WORKDIR /app

COPY requirements.lock pyproject.toml ./
COPY src/ ./src/

RUN apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --require-hashes -r requirements.lock \
    && pip install --no-cache-dir --no-deps . \
    && groupadd --gid 10001 mcp \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /sbin/nologin mcp

ENV UNIFI_API_BASE_URL=https://api.ui.com
ENV UNIFI_CACHE_TTL_SECONDS=900
ENV UNIFI_MAX_CONCURRENCY=10
# FastMCP transport protocol; override at docker run time with -e FASTMCP_TRANSPORT=sse|stdio
ENV FASTMCP_TRANSPORT=streamable-http

EXPOSE 3000

# FastMCP 3.x does not expose a /health HTTP endpoint; use a TCP-probe instead.
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python3 -c "import socket; s=socket.create_connection(('localhost', 3000), timeout=5); s.close()" || exit 1

USER mcp

ENTRYPOINT ["/usr/bin/tini", "--", "unifi-fabric-mcp"]
