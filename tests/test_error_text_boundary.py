"""The final tool-error boundary handles upstream values after arbitrary formatting."""

import json
from types import SimpleNamespace

import pytest
from fastmcp.exceptions import ToolError

from unifi_fabric import server
from unifi_fabric.redaction import REDACTION_MASK, mask_error_text, write_redaction_scope

MARKER = "synthetic-error-boundary-marker"


def forms(value):
    payload = {"password": value, "id": "console-id", "reason": "upstream refusal"}
    encoded = json.dumps(payload)
    return (
        str(payload),
        repr(payload),
        encoded,
        repr(encoded),
        json.dumps(encoded),
        json.dumps(json.dumps(encoded)),
        f"password={value}" if value[0] not in "\"'" else f"password={value!r}",
        f"password={value!r}",
        f"label / {encoded} / other label",
    )


@pytest.mark.parametrize("prefix", ["", "it's", 'a"b', "\\", "'\""])
def test_mask_formatted_upstream_fields(prefix):
    for rendered in forms(prefix + MARKER):
        text = "GET /v1/sites: " + rendered + "; retry with a read"
        masked = mask_error_text(text)
        assert MARKER not in masked, rendered
        assert REDACTION_MASK in masked
        assert masked.startswith("GET /v1/sites: ")
        if rendered.startswith("password="):
            assert masked == "GET /v1/sites: " + REDACTION_MASK
        else:
            assert masked.endswith("; retry with a read")
        assert mask_error_text(masked) == masked


@pytest.mark.parametrize("enabled", [False, True])
async def test_final_tool_error_boundary(enabled):
    context = SimpleNamespace(message=SimpleNamespace(name="list_sites", arguments={}))

    async def fail(_):
        error = ValueError("Site lookup failed")
        error.add_note(repr(json.dumps({"password": "it's" + MARKER, "id": "console-id"})))
        raise error

    with write_redaction_scope(enabled), pytest.raises((ValueError, ToolError)) as caught:
        await server.SecretScrubMiddleware().on_call_tool(context, fail)
    text = str(caught.value)
    assert (MARKER not in text) if enabled else (MARKER in text)
    assert "Site lookup failed" in text
    assert "console-id" in text


async def test_successful_tool_response_is_unchanged():
    context = SimpleNamespace(message=SimpleNamespace(name="list_sites", arguments={}))
    response = {"password": MARKER}

    async def succeed(_):
        return response

    with write_redaction_scope(True):
        assert await server.SecretScrubMiddleware().on_call_tool(context, succeed) is response


@pytest.mark.parametrize(
    "text",
    [
        "plain failure for console-id",
        '{"password": null, "secret": "", "id": "console-id"}',
        "cursor=opaque-page-value; page_token=opaque-token",
    ],
)
def test_mask_error_text_preserves_noncredentials(text):
    assert mask_error_text(text) == text


@pytest.mark.parametrize("text", ["password policy requires 12 characters", "password is wrong"])
def test_separator_free_credential_prose_is_preserved(text):
    assert mask_error_text(text) == text


@pytest.mark.parametrize("separator", ["=", ":"])
def test_unstructured_credential_token_discards_suffix(separator):
    assert mask_error_text(f"password{separator}{MARKER}; id=KEEP_ID") == REDACTION_MASK
