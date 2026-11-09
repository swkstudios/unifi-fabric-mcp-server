"""HTTP transport hardening: findings F1-F5 and F7 of the security review, each on its live path.

- F1 / F5 / F7 and the plain-http JWKS URI: startup WARNINGs that name the variables and
  a fix (the server still starts).
- F2: Origin validation on by default (no Origin passes, an unlisted or ``null`` Origin
  is 403 naming the variable, an allowlisted one passes, ``MCP_HOST_ORIGIN_PROTECTION=off``
  turns it off) and FastMCP's Host check once ``MCP_ALLOWED_HOSTS`` is set.
- F3: a JWT without ``exp``, or with ``nbf`` / ``iat`` beyond the 60 s leeway, is 401 and
  the 401 names the claim.
- F4: the opt-in ``MCP_OAUTH_WRITE_SCOPE`` refuses write tools for a token without it.
- F7: the bearer check uses ``hmac.compare_digest``.
- The JWKS download is capped at 1 MiB.

Every request runs in-process (``httpx.ASGITransport``); hostnames are ``.test``.
"""

from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier
from joserfc import jws, jwt
from joserfc.jwk import RSAKey

from tests.test_auth_http import post_initialize

# A 64-character synthetic bearer secret (long enough not to draw the F7 warning).
_TOKEN = "f" * 64  # noqa: S105 -- test-only value, not a credential
_ISSUER = "https://idp.test/realms/unifi"
_AUDIENCE = "unifi-fabric-mcp"
_BASE_URL = "https://mcp.example.test"
_KEY = RSAKey.generate_key(2048, parameters={"kid": "k1"})


def _oauth_env(**extra: str) -> dict[str, str]:
    env = {
        "MCP_OAUTH_ISSUER": _ISSUER,
        "MCP_OAUTH_JWKS_URI": "https://idp.test/jwks",
        "MCP_OAUTH_AUDIENCE": _AUDIENCE,
        "MCP_OAUTH_BASE_URL": _BASE_URL,
        "MCP_OAUTH_REQUIRED_SCOPES": "unifi.read",
    }
    env.update(extra)
    return env


def _jwt(**claims: Any) -> str:
    now = int(time.time())
    body: dict[str, Any] = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "sub": "agent",
        "scope": "unifi.read",
        "iat": now,
        "exp": now + 600,
    }
    body.update(claims)
    body = {k: v for k, v in body.items() if v is not None}
    return jwt.encode({"alg": "RS256", "kid": "k1"}, body, _KEY)


def _jwt_with_raw_claim(name: str, literal: str) -> str:
    """A signed JWT whose ``name`` claim is the raw JSON number ``literal``: json.dumps
    cannot write an integer past the 4300-digit conversion limit, so splice it in."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "sub": "agent",
        "scope": "unifi.read",
        "iat": now,
        "exp": now + 600,
    }
    claims[name] = "__RAW__"
    payload = json.dumps(claims).replace('"__RAW__"', literal).encode()
    return jws.serialize_compact({"alg": "RS256", "kid": "k1"}, payload, _KEY)


def _jwks() -> dict[str, Any]:
    return {"keys": [_KEY.as_dict(private=False)]}


async def _post(client, *, headers: dict[str, str] | None = None, authorization=None):
    hdrs = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if authorization:
        hdrs["Authorization"] = authorization
    hdrs.update(headers or {})
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"},
        },
    }
    return await client.post("/mcp", json=body, headers=hdrs)


# =================================================================== F2: Origin / Host


class TestOriginValidation:
    """The five Origin cases the review asked for, plus loopback and the Host check."""

    async def test_no_origin_passes(self, auth_http_client):
        async with auth_http_client("none") as client:
            resp = await _post(client)
        assert resp.status_code == 200

    async def test_evil_origin_is_403_naming_the_variable(self, auth_http_client):
        async with auth_http_client("none") as client:
            resp = await _post(client, headers={"Origin": "http://evil.example.test"})
        assert resp.status_code == 403
        assert "MCP_ALLOWED_ORIGINS" in resp.text
        assert "MCP_HOST_ORIGIN_PROTECTION=off" in resp.text

    async def test_null_origin_is_403(self, auth_http_client):
        async with auth_http_client("none") as client:
            resp = await _post(client, headers={"Origin": "null"})
        assert resp.status_code == 403

    async def test_allowlisted_origin_passes(self, auth_http_client):
        env = {"MCP_ALLOWED_ORIGINS": "https://app.example.test, https://other.example.test:8443"}
        async with auth_http_client("none", env=env) as client:
            ok = await _post(client, headers={"Origin": "https://app.example.test"})
            ported = await _post(client, headers={"Origin": "https://other.example.test:8443"})
            wrong_port = await _post(client, headers={"Origin": "https://app.example.test:8443"})
        assert ok.status_code == 200
        assert ported.status_code == 200
        assert wrong_port.status_code == 403

    async def test_opt_out_passes_any_origin(self, auth_http_client):
        env = {"MCP_HOST_ORIGIN_PROTECTION": "off"}
        async with auth_http_client("none", env=env) as client:
            evil = await _post(client, headers={"Origin": "http://evil.example.test"})
            null = await _post(client, headers={"Origin": "null"})
        assert evil.status_code == 200
        assert null.status_code == 200

    @pytest.mark.parametrize(
        "origin", ["http://localhost:6274", "http://127.0.0.1:3000", "https://[::1]:8443"]
    )
    async def test_loopback_origins_pass(self, auth_http_client, origin):
        async with auth_http_client("none") as client:
            resp = await _post(client, headers={"Origin": origin})
        assert resp.status_code == 200

    async def test_oauth_base_url_origin_passes(self, auth_http_client):
        with patch.object(JWTVerifier, "_fetch_jwks", new=AsyncMock(return_value=_jwks())):
            async with auth_http_client("oauth", env=_oauth_env()) as client:
                resp = await _post(
                    client, headers={"Origin": _BASE_URL}, authorization=f"Bearer {_jwt()}"
                )
        assert resp.status_code == 200

    async def test_origin_refusal_comes_before_authentication(self, auth_http_client):
        env = {"MCP_BEARER_TOKEN": _TOKEN}
        async with auth_http_client("bearer", env=env) as client:
            resp = await _post(client, headers={"Origin": "http://evil.example.test"})
        assert resp.status_code == 403

    async def test_allowed_hosts_turns_the_host_check_on(self, auth_http_client):
        env = {"MCP_ALLOWED_HOSTS": "mcp.example.test"}
        async with auth_http_client("none", env=env) as client:
            evil = await _post(client, headers={"Host": "evil.example.test"})
            good = await _post(client, headers={"Host": "mcp.example.test"})
            loop = await _post(client, headers={"Host": "localhost:3000"})
        assert evil.status_code == 421
        assert good.status_code == 200
        assert loop.status_code == 200

    async def test_opt_out_also_disables_the_host_check(self, auth_http_client):
        env = {"MCP_ALLOWED_HOSTS": "mcp.example.test", "MCP_HOST_ORIGIN_PROTECTION": "off"}
        async with auth_http_client("none", env=env) as client:
            evil = await _post(client, headers={"Host": "evil.example.test"})
        assert evil.status_code == 200


class TestOriginHelpers:
    @pytest.mark.parametrize(
        "origin, expected",
        [
            ("https://App.Example.test", "https://app.example.test:443"),
            ("http://a.test:80", "http://a.test:80"),
            ("http://[::1]:3000", "http://[::1]:3000"),
            ("null", None),
            ("", None),
            ("file://x", None),
            ("https://a.test/path", None),
            ("https://u:p@a.test", None),
            ("https://a.test:99999", None),
        ],
    )
    def test_normalize_origin(self, origin, expected):
        from unifi_fabric.transport_security import normalize_origin

        assert normalize_origin(origin) == expected

    @pytest.mark.parametrize(
        "value", ["app.example.test", "https://a.test/x", "ftp://a.test", "null"]
    )
    def test_bad_allowed_origin_is_a_config_error_naming_the_variable(self, monkeypatch, value):
        from unifi_fabric.config import MCPTransportSettings

        monkeypatch.setenv("MCP_ALLOWED_ORIGINS", value)
        with pytest.raises(ValueError, match="MCP_ALLOWED_ORIGINS item 0"):
            MCPTransportSettings()

    @pytest.mark.parametrize("value", ["a b.test", "https://a.test", "a.test/x"])
    def test_bad_allowed_host_is_a_config_error_naming_the_variable(self, monkeypatch, value):
        from unifi_fabric.config import MCPTransportSettings

        monkeypatch.setenv("MCP_ALLOWED_HOSTS", value)
        with pytest.raises(ValueError, match="MCP_ALLOWED_HOSTS item 0"):
            MCPTransportSettings()

    @pytest.mark.parametrize(
        "value, expected", [("off", False), ("OFF", False), ("0", False), ("on", True), ("", True)]
    )
    def test_protection_switch(self, monkeypatch, value, expected):
        from unifi_fabric.config import MCPTransportSettings

        monkeypatch.setenv("MCP_HOST_ORIGIN_PROTECTION", value)
        assert MCPTransportSettings().host_origin_protection is expected

    def test_protection_switch_rejects_a_typo(self, monkeypatch):
        from unifi_fabric.config import MCPTransportSettings

        monkeypatch.setenv("MCP_HOST_ORIGIN_PROTECTION", "of")
        with pytest.raises(ValueError, match="MCP_HOST_ORIGIN_PROTECTION"):
            MCPTransportSettings()


# ========================================================== F1 / F5 / F7 / JWKS: warnings


def _settings(monkeypatch, **env: str):
    from unifi_fabric.config import MCPTransportSettings

    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return MCPTransportSettings()


def _warnings(monkeypatch, host="0.0.0.0", transport="streamable-http", **env: str) -> list[str]:  # noqa: S104
    from unifi_fabric.transport_security import startup_warnings

    return startup_warnings(_settings(monkeypatch, **env), transport, host, 3000)


class TestStartupWarnings:
    def test_f1_no_auth_on_a_public_bind_warns_with_a_fix(self, monkeypatch):
        (line,) = _warnings(monkeypatch)
        assert line.startswith("WARNING:")
        for needle in ("FASTMCP_HOST=0.0.0.0", "MCP_AUTH_MODE", "MCP_BEARER_TOKEN"):
            assert needle in line
        assert "openssl rand -hex 32" in line

    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
    def test_f1_no_auth_on_loopback_is_quiet(self, monkeypatch, host):
        assert _warnings(monkeypatch, host=host) == []

    def test_f1_stdio_is_quiet(self, monkeypatch):
        assert _warnings(monkeypatch, transport="stdio") == []

    def test_f5_mtls_optional_without_auth_warns(self, monkeypatch, tmp_path):
        lines = _warnings(
            monkeypatch,
            host="127.0.0.1",
            MCP_TLS_MODE="mtls",
            MCP_TLS_CERTFILE=str(tmp_path / "c.pem"),
            MCP_TLS_KEYFILE=str(tmp_path / "k.pem"),
            MCP_TLS_CA_CERTS=str(tmp_path / "ca.pem"),
            MCP_TLS_CERT_REQS="optional",
        )
        assert len(lines) == 1
        assert "MCP_TLS_CERT_REQS=required" in lines[0]

    def test_f5_mtls_required_is_quiet(self, monkeypatch, tmp_path):
        assert (
            _warnings(
                monkeypatch,
                host="127.0.0.1",
                MCP_TLS_MODE="mtls",
                MCP_TLS_CERTFILE=str(tmp_path / "c.pem"),
                MCP_TLS_KEYFILE=str(tmp_path / "k.pem"),
                MCP_TLS_CA_CERTS=str(tmp_path / "ca.pem"),
            )
            == []
        )

    def test_f7_short_bearer_token_warns_without_the_value(self, monkeypatch):
        (line,) = _warnings(monkeypatch, MCP_BEARER_TOKEN="x")
        assert "MCP_BEARER_TOKEN is shorter than 32 characters" in line
        assert "openssl rand -hex 32" in line
        assert "'x'" not in line

    def test_f7_32_character_token_is_quiet(self, monkeypatch):
        assert _warnings(monkeypatch, MCP_BEARER_TOKEN="a" * 32) == []

    def test_plain_http_jwks_to_a_remote_host_warns(self, monkeypatch):
        lines = _warnings(
            monkeypatch,
            MCP_AUTH_MODE="oauth",
            **_oauth_env(MCP_OAUTH_JWKS_URI="http://idp.test/jwks"),
        )
        assert len(lines) == 1
        assert "MCP_OAUTH_JWKS_URI" in lines[0] and "https://" in lines[0]

    @pytest.mark.parametrize("uri", ["https://idp.test/jwks", "http://127.0.0.1:8080/jwks"])
    def test_https_or_loopback_jwks_is_quiet(self, monkeypatch, uri):
        lines = _warnings(monkeypatch, MCP_AUTH_MODE="oauth", **_oauth_env(MCP_OAUTH_JWKS_URI=uri))
        assert lines == []

    def test_main_prints_the_warnings_to_stderr(self, monkeypatch, capsys):
        import importlib

        import fastmcp

        monkeypatch.setenv("UNIFI_API_KEY", "sk-test")
        monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
        monkeypatch.setenv("MCP_BEARER_TOKEN", "short")
        monkeypatch.setattr(fastmcp.settings, "host", "0.0.0.0")  # noqa: S104
        import unifi_fabric.server as srv

        importlib.reload(srv)
        monkeypatch.setattr(srv.mcp, "run", lambda **_: None)
        srv.main()
        err = capsys.readouterr().err
        assert "unifi-fabric-mcp: WARNING: MCP_BEARER_TOKEN is shorter" in err
        assert "short" not in err.replace("shorter", "")


# =============================================================== F3: JWT time claims


async def _oauth_initialize(auth_http_client, token: str, **env: str):
    with patch.object(JWTVerifier, "_fetch_jwks", new=AsyncMock(return_value=_jwks())):
        async with auth_http_client("oauth", env=_oauth_env(**env)) as client:
            return await post_initialize(client, authorization=f"Bearer {token}")


class TestJWTTimeClaims:
    async def test_valid_token_is_accepted(self, auth_http_client):
        resp = await _oauth_initialize(auth_http_client, _jwt())
        assert resp.status_code == 200

    @pytest.mark.parametrize(
        "claims, claim",
        [
            ({"exp": None}, "exp"),
            ({"nbf": int(time.time()) + 86400}, "nbf"),
            ({"iat": int(time.time()) + 365 * 86400}, "iat"),
        ],
        ids=["no-exp", "nbf-tomorrow", "iat-next-year"],
    )
    async def test_rejected_and_the_401_names_the_claim(self, auth_http_client, claims, claim):
        resp = await _oauth_initialize(auth_http_client, _jwt(**claims))
        assert resp.status_code == 401
        assert f"claim '{claim}'" in resp.json()["error_description"]
        challenge = resp.headers["www-authenticate"]
        assert 'error="invalid_token"' in challenge and f"claim '{claim}'" in challenge
        assert "resource_metadata=" in challenge

    @pytest.mark.parametrize("claim", ["exp", "nbf", "iat"])
    @pytest.mark.parametrize(
        "value",
        [10**400, -(10**400), float("nan"), float("inf"), -float("inf")],
        ids=["overflow", "negative-overflow", "nan", "inf", "negative-inf"],
    )
    async def test_invalid_numeric_date_is_claim_specific_401(self, auth_http_client, claim, value):
        resp = await _oauth_initialize(auth_http_client, _jwt(**{claim: value}))
        assert resp.status_code == 401
        assert f"claim '{claim}'" in resp.json()["error_description"]
        assert f"claim '{claim}'" in resp.headers["www-authenticate"]

    @pytest.mark.parametrize("claim", ["exp", "nbf", "iat"])
    @pytest.mark.parametrize("sign", ["", "-"], ids=["positive", "negative"])
    async def test_integer_beyond_the_digit_limit_is_claim_specific_401(
        self, auth_http_client, claim, sign
    ):
        """A 5001-digit NumericDate exceeds Python's 4300-digit int conversion limit, so a
        plain json.loads of the payload raises; the 401 must still name the claim."""
        resp = await _oauth_initialize(
            auth_http_client, _jwt_with_raw_claim(claim, sign + "9" * 5001)
        )
        assert resp.status_code == 401
        assert f"claim '{claim}'" in resp.json()["error_description"]
        assert f"claim '{claim}'" in resp.headers["www-authenticate"]

    @pytest.mark.parametrize("claim", ["nbf", "iat"])
    async def test_skew_within_the_leeway_is_accepted(self, auth_http_client, claim):
        resp = await _oauth_initialize(auth_http_client, _jwt(**{claim: int(time.time()) + 30}))
        assert resp.status_code == 200

    async def test_a_later_request_without_a_token_gets_the_plain_401(self, auth_http_client):
        """A claim rejection never leaks into the next request's answer."""
        with patch.object(JWTVerifier, "_fetch_jwks", new=AsyncMock(return_value=_jwks())):
            async with auth_http_client("oauth", env=_oauth_env()) as client:
                first = await post_initialize(client, authorization=f"Bearer {_jwt(exp=None)}")
                second = await post_initialize(client)
        assert first.status_code == 401
        assert second.status_code == 401
        assert "claim" not in second.text

    def test_problem_helper(self):
        from unifi_fabric.transport_security import jwt_time_claim_problem

        now = 1_000_000.0
        assert jwt_time_claim_problem({"exp": now + 10}, now) is None
        assert "exp" in (jwt_time_claim_problem({}, now) or "")
        assert "exp" in (jwt_time_claim_problem({"exp": True}, now) or "")
        assert "nbf" in (jwt_time_claim_problem({"exp": now + 10, "nbf": now + 61}, now) or "")
        assert jwt_time_claim_problem({"exp": now + 10, "nbf": now + 60}, now) is None


# ============================================================== JWKS download cap


def _mock_transport(body: bytes, *, declare: bool):
    import httpx2

    def handler(request):
        headers = {"content-type": "application/json"}
        if declare:
            return httpx2.Response(200, headers=headers, content=body)

        async def chunks():
            for i in range(0, len(body), 65536):
                yield body[i : i + 65536]

        return httpx2.Response(200, headers=headers, content=chunks())

    return httpx2.MockTransport(handler)


class TestJWKSCap:
    def _verifier(self, body: bytes, *, declare: bool):
        from unifi_fabric.transport_security import StrictJWTVerifier, capped_jwks_client

        return StrictJWTVerifier(
            jwks_uri="https://idp.test/jwks",
            issuer=_ISSUER,
            audience=_AUDIENCE,
            http_client=capped_jwks_client(_mock_transport(body, declare=declare)),
        )

    @pytest.mark.parametrize("declare", [True, False], ids=["content-length", "chunked"])
    async def test_a_jwks_over_1_mib_is_refused(self, declare):
        doc = dict(_jwks(), pad="x" * (1024 * 1024))
        verifier = self._verifier(json.dumps(doc).encode(), declare=declare)
        assert await verifier.verify_token(_jwt()) is None

    @pytest.mark.parametrize("declare", [True, False], ids=["content-length", "chunked"])
    async def test_a_normal_jwks_verifies(self, declare):
        verifier = self._verifier(json.dumps(_jwks()).encode(), declare=declare)
        assert await verifier.verify_token(_jwt()) is not None

    @pytest.mark.parametrize("encoding", ["gzip", "deflate", "br"])
    @pytest.mark.parametrize("extra", [0, 1], ids=["exact-limit", "over-limit"])
    async def test_compressed_decoded_size_is_capped(self, monkeypatch, encoding, extra):
        import gzip
        import zlib

        import httpx2

        import unifi_fabric.transport_security as security

        # An 8 KiB decoded document exercises the same boundary without large fixtures.
        limit = 8192
        monkeypatch.setattr(security, "JWKS_MAX_BYTES", limit)
        base = json.dumps(_jwks()).encode()
        body = base + b" " * (limit + extra - len(base))
        if encoding == "br":
            import brotli  # a dev dependency, so the br case always runs

            wire = brotli.compress(body)
        else:
            wire = {"gzip": gzip.compress, "deflate": zlib.compress}[encoding](body)
        assert len(wire) < limit
        consumed = []
        closed = []

        class WireStream(httpx2.AsyncByteStream):
            async def __aiter__(self):
                consumed.append("body")
                yield wire
                # If the oversized first chunk is decoded/buffered, do not read ahead.
                consumed.append("tail")
                yield b""

            async def aclose(self):
                closed.append(True)

        def handler(request):
            return httpx2.Response(
                200,
                headers={"content-encoding": encoding, "content-length": str(len(wire))},
                stream=WireStream(),
            )

        async with security.capped_jwks_client(httpx2.MockTransport(handler)) as client:
            if extra:
                with pytest.raises(httpx2.ReadError, match="JWKS.*exceeds"):
                    await client.get("https://idp.test/jwks")
                assert consumed == ["body"]
            else:
                resp = await client.get("https://idp.test/jwks")
                assert resp.content == body
                assert resp.json() == _jwks()
        assert closed == [True]

    @pytest.mark.parametrize("encoding", ["gzip", "deflate", "br"])
    async def test_decoders_yield_bounded_chunks(self, monkeypatch, encoding):
        """The decoded-size cap relies on httpx2 decoding a compressed body in bounded
        chunks (httpx2 >= 2.12, the floor pyproject.toml declares): a 32 MiB body arriving
        as one small wire chunk must reach the cap check in pieces of at most 1 MiB, never
        as one 32 MiB buffer."""
        import gzip
        import zlib

        import brotli
        import httpx2

        import unifi_fabric.transport_security as security

        decoded = 32 * 1024 * 1024
        monkeypatch.setattr(security, "JWKS_MAX_BYTES", decoded)
        body = b"\0" * decoded
        compress = {"gzip": gzip.compress, "deflate": zlib.compress, "br": brotli.compress}
        wire = compress[encoding](body)
        assert len(wire) < 1024 * 1024

        async def one_chunk():
            yield wire

        def handler(request):
            return httpx2.Response(200, headers={"content-encoding": encoding}, content=one_chunk())

        sizes = []
        async with security.capped_jwks_client(httpx2.MockTransport(handler)) as client:
            async with client.stream("GET", "https://idp.test/jwks") as response:
                async for chunk in response.aiter_raw():
                    sizes.append(len(chunk))
        assert sum(sizes) == decoded
        assert max(sizes) <= 1024 * 1024, max(sizes)

    def test_pyproject_floors_httpx2_at_the_bounded_decoders(self):
        """httpx2 is imported directly and its bounded decoders arrived in 2.12; fastmcp
        alone admits httpx2 2.5, whose decoders return a whole decompressed chunk."""
        import tomllib
        from pathlib import Path

        from packaging.requirements import Requirement
        from packaging.version import Version

        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        deps = tomllib.loads(pyproject.read_text())["project"]["dependencies"]
        reqs = [Requirement(d) for d in deps if Requirement(d).name == "httpx2"]
        assert reqs, "httpx2 is not a declared dependency"
        floor = [Version(s.version) for s in reqs[0].specifier if s.operator == ">="]
        assert floor and floor[0] >= Version("2.12.0"), reqs[0]

    async def test_wire_overhead_does_not_reject_exact_decoded_limit(self, monkeypatch):
        import gzip

        import httpx2

        import unifi_fabric.transport_security as security

        monkeypatch.setattr(security, "JWKS_MAX_BYTES", 8192)
        body = b" " * 8192
        wire = gzip.compress(body, compresslevel=0)
        assert len(wire) > security.JWKS_MAX_BYTES

        async def chunks():
            yield wire

        def handler(request):
            return httpx2.Response(
                200,
                headers={"content-encoding": "gzip", "content-length": str(len(wire))},
                content=chunks(),
            )

        async with security.capped_jwks_client(httpx2.MockTransport(handler)) as client:
            response = await client.get("https://idp.test/jwks")
            assert response.content == body

    def test_build_auth_wires_the_capped_strict_verifier(self, monkeypatch):
        from unifi_fabric.server import build_auth
        from unifi_fabric.transport_security import (
            StrictJWTVerifier,
            StrictRemoteAuthProvider,
            _CappedTransport,
        )

        cfg = _settings(monkeypatch, MCP_AUTH_MODE="oauth", **_oauth_env())
        auth = build_auth(cfg)
        assert isinstance(auth, StrictRemoteAuthProvider)
        verifier = auth.token_verifier
        assert isinstance(verifier, StrictJWTVerifier)
        assert isinstance(verifier._http_client._transport, _CappedTransport)


# ========================================== hostile token and header input (no 500s)


def _b64(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


_GOOD_HEADER = _b64(json.dumps({"alg": "RS256", "kid": "k1"}).encode())


def _nested_tokens(depth: int) -> dict[str, str]:
    """Tokens whose header or payload nests ``depth`` arrays: unsigned, signed by the
    trusted key (so signature checks pass and the payload is decoded), and a nested
    header that the key lookup decodes first."""
    nested = b"[" * depth
    claims = _b64(json.dumps({"iss": _ISSUER, "exp": int(time.time()) + 600}).encode())
    return {
        "payload-unsigned": f"{_GOOD_HEADER}.{_b64(nested)}.{_b64(b'sig')}",
        "payload-signed": jws.serialize_compact({"alg": "RS256", "kid": "k1"}, nested, _KEY),
        "header": f"{_b64(nested)}.{claims}.{_b64(b'sig')}",
    }


def _assert_token_rejection(response):
    from unifi_fabric.access_log import B_HEADERS

    header_bytes = 2 + sum(
        len(name) + len(value) + 4 for name, value in response.request.headers.raw
    )
    if header_bytes > B_HEADERS:
        # The transport boundary rejects oversized fields before JWT decoding.
        assert response.status_code == 431
        assert response.content == b"Request headers too large\n"
        assert "www-authenticate" not in response.headers
    else:
        assert response.status_code == 401
        assert 'error="invalid_token"' in response.headers["www-authenticate"]


class TestHostileTokens:
    @pytest.mark.parametrize("depth", [10000, 40000])
    @pytest.mark.parametrize("where", ["payload-unsigned", "payload-signed", "header"])
    async def test_deeply_nested_token_is_rejected_before_or_during_auth(
        self, auth_http_client, depth, where
    ):
        """json's scanner raises RecursionError past the recursion limit; the verifier
        must answer invalid-token 401 within the header bound, or transport 431
        above it, never let it escape as a 500."""
        resp = await _oauth_initialize(auth_http_client, _nested_tokens(depth)[where])
        _assert_token_rejection(resp)

    @pytest.mark.parametrize(
        "token",
        [
            "no-dots-at-all",
            f"{_GOOD_HEADER}.{_b64(bytes([0xFF, 0xFE, 0x80]))}.sig",
            f"{_GOOD_HEADER}.!!!!.sig",
            f"{_GOOD_HEADER}.{_b64(b'{' * 10000)}.sig",
            f"{_GOOD_HEADER}.{_b64(b'[' * 10000 + b']' * 10000)}.sig",
        ],
        ids=["one-segment", "bad-utf8", "bad-base64", "open-braces", "balanced"],
    )
    async def test_malformed_token_is_rejected_before_or_during_auth(self, auth_http_client, token):
        resp = await _oauth_initialize(auth_http_client, token)
        _assert_token_rejection(resp)

    async def test_non_ascii_payload_is_rejected_without_raising(self):
        """HTTP clients cannot send it, but an ASGI server may decode one as latin-1."""
        from unifi_fabric.transport_security import StrictJWTVerifier

        verifier = StrictJWTVerifier(jwks_uri="https://idp.test/jwks", issuer=_ISSUER)
        with patch.object(JWTVerifier, "_fetch_jwks", new=AsyncMock(return_value=_jwks())):
            assert await verifier.load_access_token(f"{_GOOD_HEADER}.\u00e9\u00e9.sig") is None

    @pytest.mark.parametrize("error_type", [RecursionError, IndexError])
    async def test_decoder_bug_warns_without_token_content(
        self, auth_http_client, caplog, error_type
    ):
        import logging

        token = f"{_GOOD_HEADER}.{_b64(b'{}')}.synthetic-private-signature"
        logger = logging.getLogger("unifi_fabric.transport_security")
        # Server setup replaces root handlers; capture on the module logger instead.
        logger.addHandler(caplog.handler)
        try:
            with (
                caplog.at_level(logging.WARNING, logger=logger.name),
                patch.object(
                    JWTVerifier,
                    "load_access_token",
                    new=AsyncMock(side_effect=error_type(token)),
                ),
            ):
                response = await _oauth_initialize(auth_http_client, token)
        finally:
            logger.removeHandler(caplog.handler)
        assert response.status_code == 401
        assert 'error="invalid_token"' in response.headers["www-authenticate"]
        records = [r for r in caplog.records if r.name == "unifi_fabric.transport_security"]
        assert len(records) == 1
        assert records[0].levelno == logging.WARNING
        assert (
            records[0].getMessage() == "Bearer token rejected: a token segment could not be parsed"
        )
        assert records[0].exc_info is None
        assert token not in caplog.text
        assert "synthetic-private-signature" not in caplog.text

    @pytest.mark.parametrize("depth", [10000, 40000])
    async def test_verifier_returns_none_without_raising(self, depth):
        from unifi_fabric.transport_security import StrictJWTVerifier

        verifier = StrictJWTVerifier(jwks_uri="https://idp.test/jwks", issuer=_ISSUER)
        with patch.object(JWTVerifier, "_fetch_jwks", new=AsyncMock(return_value=_jwks())):
            for token in _nested_tokens(depth).values():
                assert await verifier.load_access_token(token) is None


class TestContentLengthParsing:
    @pytest.mark.parametrize(
        "value, expected",
        [
            ("123", "123"),
            (b"123", "123"),
            ("000", "0"),
            ("0042", "42"),
            ("9" * 5000, "9" * 5000),
            ("", None),
            (" 12", None),
            ("+5", None),
            ("1_000", None),
            ("-1", None),
            ("\u00b2", None),
            ("\uff11\uff12", None),
            (b"\xb2", None),
        ],
    )
    def test_length_digits(self, value, expected):
        from unifi_fabric.transport_security import length_digits

        assert length_digits(value) == expected

    @staticmethod
    def _declaring(value: bytes, body: bytes):
        import httpx2

        closed: list[bool] = []

        class Body(httpx2.AsyncByteStream):
            async def __aiter__(self):
                yield body

            async def aclose(self) -> None:
                closed.append(True)

        def handler(request):
            return httpx2.Response(
                200,
                headers=[(b"content-type", b"application/json"), (b"content-length", value)],
                stream=Body(),
            )

        return httpx2.MockTransport(handler), closed

    @pytest.mark.parametrize(
        "value",
        [b"9" * 5000, b"9" * 19, b"1048577", b"0" * 4000 + b"1048577"],
        ids=["5000-digits", "19-digits", "cap-plus-one", "zero-padded"],
    )
    async def test_oversized_declaration_is_the_cap_error(self, value):
        import httpx2

        from unifi_fabric.transport_security import capped_jwks_client

        transport, closed = self._declaring(value, b"{}")
        async with capped_jwks_client(transport) as client:
            with pytest.raises(httpx2.ReadError, match="byte cap") as info:
                await client.get("https://idp.test/jwks")
        assert closed == [True]
        assert len(str(info.value)) < 300
        digits = value.decode().lstrip("0")
        declared = f"{digits} bytes" if len(digits) <= 18 else f"a {len(digits)}-digit length"
        assert str(info.value) == (
            f"JWKS response from MCP_OAUTH_JWKS_URI declares {declared}, over the 1048576-byte cap"
        )

    @pytest.mark.parametrize(
        "value",
        [b"\xb2", b"1_0", b"+2", b"0" * 5000],
        ids=["superscript", "underscore", "plus", "zeros"],
    )
    async def test_unparseable_declaration_falls_back_to_the_streaming_cap(self, value):
        """A declaration that is not plain ASCII digits is not a length; the decoded
        stream is still capped, so a normal JWKS is read normally."""
        from unifi_fabric.transport_security import capped_jwks_client

        body = json.dumps(_jwks()).encode()
        transport, _ = self._declaring(value, body)
        async with capped_jwks_client(transport) as client:
            response = await client.get("https://idp.test/jwks")
        assert response.content == body

    @pytest.mark.parametrize(
        "value",
        [b"9" * 5000, b"\xb2", b"12x", b""],
        ids=["5000-digits", "superscript", "junk", "empty"],
    )
    async def test_host_hint_drops_an_unparseable_content_length(self, monkeypatch, value):
        import unifi_fabric.transport_security as security

        class FakeGuard:
            def __init__(self, app, **options):
                pass

            async def __call__(self, scope, receive, send):
                await send(
                    {
                        "type": "http.response.start",
                        "status": 421,
                        "headers": [(b"content-length", value), (b"x-kept", b"1")],
                    }
                )
                await send({"type": "http.response.body", "body": b"Misdirected"})

        monkeypatch.setattr(security, "HostOriginGuardMiddleware", FakeGuard)
        messages: list[dict[str, Any]] = []

        async def send(message):
            messages.append(message)

        guard = security.HostRefusalHintMiddleware(lambda *a: None)
        await guard({"type": "http", "headers": []}, AsyncMock(), send)
        headers = messages[0]["headers"]
        assert headers == [(b"x-kept", b"1")]
        assert b"MCP_ALLOWED_HOSTS" in messages[1]["body"]

    async def test_host_hint_is_appended_once_to_streamed_refusal(self, monkeypatch):
        import unifi_fabric.transport_security as security

        class FakeGuard:
            def __init__(self, app, **options):
                pass

            async def __call__(self, scope, receive, send):
                await send(
                    {
                        "type": "http.response.start",
                        "status": 421,
                        "headers": [(b"content-length", b"11")],
                    }
                )
                await send({"type": "http.response.body", "body": b"Mis", "more_body": True})
                await send({"type": "http.response.body", "body": b"directed", "more_body": False})

        monkeypatch.setattr(security, "HostOriginGuardMiddleware", FakeGuard)
        messages = []

        async def send(message):
            messages.append(message)

        guard = security.HostRefusalHintMiddleware(lambda *a: None)
        await guard({"type": "http", "headers": []}, AsyncMock(), send)
        body = b"".join(m["body"] for m in messages[1:])
        assert messages[1]["body"] == b"Mis"
        assert body.count(b"MCP_ALLOWED_HOSTS") == 1
        assert int(dict(messages[0]["headers"])[b"content-length"]) == len(body)

    async def test_host_hint_grows_a_zero_padded_content_length(self, monkeypatch):
        import unifi_fabric.transport_security as security

        assert security._lengthened([(b"Content-Length", b"0011")], 5) == [
            (b"Content-Length", b"16")
        ]


# ================================================================ F4: write scope


class _Ctx:
    def __init__(self, name: str) -> None:
        self.message = type("M", (), {"name": name})()


class TestWriteScope:
    async def _run(self, monkeypatch, tool: str, scopes: list[str] | None, write_scope="w"):
        from fastmcp.server.auth import AccessToken

        import unifi_fabric.server as srv
        from unifi_fabric.transport_security import WriteScopeMiddleware

        token = None
        if scopes is not None:
            token = AccessToken(token="t", client_id="c", scopes=scopes, expires_at=None)
        monkeypatch.setattr("fastmcp.server.dependencies.get_access_token", lambda: token)
        audit: list[tuple[str, str]] = []
        mw = WriteScopeMiddleware(
            srv.mcp, lambda: write_scope, audit=lambda t, r: audit.append((t, r))
        )
        call_next = AsyncMock(return_value="ran")
        return mw, call_next, audit, await self._call(mw, tool, call_next)

    async def _call(self, mw, tool, call_next):
        from fastmcp.exceptions import ToolError

        try:
            return await mw.on_call_tool(_Ctx(tool), call_next)
        except ToolError as exc:
            return exc

    async def test_write_tool_without_the_scope_is_refused_and_audited(self, monkeypatch):
        _, call_next, audit, out = await self._run(monkeypatch, "fabric_connector_delete", ["r"])
        assert "MCP_OAUTH_WRITE_SCOPE" in str(out) and "'w'" in str(out)
        call_next.assert_not_awaited()
        assert audit == [("fabric_connector_delete", "MCP_OAUTH_WRITE_SCOPE")]

    async def test_write_tool_with_the_scope_runs(self, monkeypatch):
        _, call_next, _, out = await self._run(monkeypatch, "fabric_connector_delete", ["r", "w"])
        assert out == "ran"

    async def test_read_tool_needs_no_write_scope(self, monkeypatch):
        _, _, _, out = await self._run(monkeypatch, "list_hosts", ["r"])
        assert out == "ran"

    async def test_unset_write_scope_keeps_every_tool_open(self, monkeypatch):
        _, _, _, out = await self._run(
            monkeypatch, "fabric_connector_delete", ["r"], write_scope=""
        )
        assert out == "ran"

    async def test_on_the_oauth_request_path_no_upstream_call_happens(
        self, auth_http_client, monkeypatch
    ):
        import fastmcp

        monkeypatch.setattr(fastmcp.settings, "stateless_http", True)
        call = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "fabric_connector_delete",
                "arguments": {"host": "h", "path": "network/api/s/default/rest/user/x"},
            },
        }
        hdrs = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {_jwt()}",
        }
        sent = AsyncMock(side_effect=AssertionError("no upstream request may be sent"))
        with (
            patch.object(JWTVerifier, "_fetch_jwks", new=AsyncMock(return_value=_jwks())),
            patch("unifi_fabric.client.UniFiClient.request", new=sent),
        ):
            env = _oauth_env(MCP_OAUTH_WRITE_SCOPE="unifi.write")
            async with auth_http_client("oauth", env=env) as client:
                resp = await client.post("/mcp", json=call, headers=hdrs)
        assert resp.status_code == 200
        assert "MCP_OAUTH_WRITE_SCOPE" in resp.text
        sent.assert_not_awaited()

    def test_write_scope_outside_oauth_is_a_config_error(self, monkeypatch):
        with pytest.raises(ValueError, match="MCP_OAUTH_WRITE_SCOPE applies only"):
            _settings(monkeypatch, MCP_BEARER_TOKEN=_TOKEN, MCP_OAUTH_WRITE_SCOPE="w")

    def test_write_scope_must_be_one_scope_token(self, monkeypatch):
        with pytest.raises(ValueError, match="MCP_OAUTH_WRITE_SCOPE"):
            _settings(monkeypatch, MCP_AUTH_MODE="oauth", **_oauth_env(MCP_OAUTH_WRITE_SCOPE="a b"))


# ====================================================== F7: constant-time bearer check


class TestConstantTimeBearer:
    async def test_accepts_only_the_exact_token(self):
        from unifi_fabric.transport_security import ConstantTimeTokenVerifier

        verifier = ConstantTimeTokenVerifier(_TOKEN)
        assert (await verifier.verify_token(_TOKEN)).client_id == "mcp"
        for wrong in ("", _TOKEN[:-1], _TOKEN + "f", "g" * 64):
            assert await verifier.verify_token(wrong) is None

    async def test_uses_hmac_compare_digest(self, monkeypatch):
        import hmac

        from unifi_fabric import transport_security
        from unifi_fabric.transport_security import ConstantTimeTokenVerifier

        calls: list[tuple[bytes, bytes]] = []
        real = hmac.compare_digest

        def spy(a, b):
            calls.append((a, b))
            return real(a, b)

        monkeypatch.setattr(transport_security.hmac, "compare_digest", spy)
        await ConstantTimeTokenVerifier(_TOKEN).verify_token("guess")
        assert calls == [(b"guess", _TOKEN.encode())]

    def test_build_auth_uses_it(self, monkeypatch):
        from unifi_fabric.server import build_auth
        from unifi_fabric.transport_security import ConstantTimeTokenVerifier

        assert isinstance(
            build_auth(_settings(monkeypatch, MCP_BEARER_TOKEN=_TOKEN)), ConstantTimeTokenVerifier
        )
