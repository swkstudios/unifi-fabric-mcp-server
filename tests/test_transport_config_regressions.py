"""Config and local Host-error regressions; no upstream calls."""

import re
from pathlib import Path

import pytest

from tests.test_auth_http import post_initialize
from unifi_fabric.config import MCPTransportSettings, Settings, api_base_url_problem


@pytest.mark.parametrize("char", [chr(i) for i in range(0x80, 0xA0)])
@pytest.mark.parametrize("part", ["host", "path", "query"])
def test_url_validation_rejects_every_c1_control(char, part):
    urls = {
        "host": f"https://ho{char}st.example",
        "path": f"https://host.example/a{char}b",
        "query": f"https://host.example/jwks?k=a{char}b",
    }
    assert api_base_url_problem(urls[part], allow_query=True) == (
        "contains whitespace or a control character"
    )


@pytest.mark.parametrize(
    "scopes", [[""], ["read", ""], ["", "write"], "read,,write", "read,", ",write"]
)
def test_required_scope_list_rejects_empty_tokens(scopes):
    with pytest.raises(ValueError, match="MCP_OAUTH_REQUIRED_SCOPES"):
        MCPTransportSettings(oauth_required_scopes=scopes)


@pytest.mark.parametrize("audience", [" audience", "audience ", " audience ", "two words"])
def test_oauth_audience_preserves_opaque_whitespace(audience):
    assert MCPTransportSettings(oauth_audience=audience).oauth_audience == audience


def test_settings_reference_documents_every_field():
    root = Path(__file__).resolve().parents[1]
    docs = "\n".join(
        (root / "docs" / name).read_text()
        for name in ("CONFIGURATION.md", "AUTH-TLS.md", "AUTH-OAUTH.md")
    )
    names = set(re.findall(r"^\| `([A-Z_]+)` \|", docs, re.M))
    expected = {
        str(field.validation_alias or f"{prefix}{name.upper()}")
        for model, prefix in ((Settings, "UNIFI_"), (MCPTransportSettings, "MCP_"))
        for name, field in model.model_fields.items()
    }
    assert expected <= names, sorted(expected - names)


async def test_rejected_host_error_names_the_allowlist(auth_http_client):
    async with auth_http_client("none", env={"MCP_ALLOWED_HOSTS": "mcp.example.test"}) as client:
        rejected = await post_initialize_with_host(client, "evil.example.test")
        accepted = await post_initialize_with_host(client, "mcp.example.test")
    assert rejected.status_code == 421
    assert "Misdirected Request" in rejected.text
    assert "MCP_ALLOWED_HOSTS" in rejected.text
    assert accepted.status_code == 200


async def post_initialize_with_host(client, host):
    # Reuse the established initialize request without adding a second harness.
    original = client.headers.get("Host")
    client.headers["Host"] = host
    try:
        return await post_initialize(client)
    finally:
        if original is None:
            del client.headers["Host"]
        else:
            client.headers["Host"] = original


async def test_downstream_421_body_and_headers_are_unchanged():
    from unifi_fabric.transport_security import HostRefusalHintMiddleware

    messages = []
    body = b"Misdirected Request from upstream"
    start = {
        "type": "http.response.start",
        "status": 421,
        "headers": [(b"content-length", str(len(body)).encode()), (b"x-upstream", b"yes")],
    }

    async def app(scope, receive, send):
        await send(start)
        await send({"type": "http.response.body", "body": body})

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        messages.append(message)

    guard = HostRefusalHintMiddleware(app, allowed_hosts=["mcp.example.test"], mode="auto")
    await guard({"type": "http", "headers": [(b"host", b"mcp.example.test")]}, receive, send)
    assert messages == [start, {"type": "http.response.body", "body": body}]


@pytest.mark.parametrize("mode", ["auto", "strict"])
async def test_local_host_hint_has_correct_content_length(mode):
    from unifi_fabric.transport_security import HostRefusalHintMiddleware

    messages = []

    async def app(scope, receive, send):
        pytest.fail("rejected Host reached the application")

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        messages.append(message)

    guard = HostRefusalHintMiddleware(app, allowed_hosts=["mcp.example.test"], mode=mode)
    await guard({"type": "http", "headers": [(b"host", b"evil.example.test")]}, receive, send)
    assert messages[0]["status"] == 421
    body = b"".join(m["body"] for m in messages if m["type"] == "http.response.body")
    assert b"MCP_ALLOWED_HOSTS" in body
    assert int(dict(messages[0]["headers"])[b"content-length"]) == len(body)
